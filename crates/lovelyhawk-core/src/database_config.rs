//! Static catalog of database products and configuration artifacts.
//!
//! The catalog deliberately keeps three independent axes: wire/admin protocol,
//! database product, and configuration artifact dialect. Compatibility on one
//! axis never implies compatibility on another. All metadata is compile-time
//! static and contains no credentials or runtime parameter values.

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DatabaseConfigProtocol {
    MySql,
    PostgreSql,
    OracleCompatible,
    InformixCompatible,
    DmNative,
    SequoiaDbNative,
    VendorNative,
    CloudControlPlane,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DatabaseConfigProduct {
    MySql,
    MariaDb,
    PostgreSql,
    OpenGauss,
    MogDb,
    Vastbase,
    KingbaseEs,
    Dm,
    TiDb,
    OceanBase,
    GBase8a,
    GBase8s,
    GBase8c,
    TdsqlMysqlPrivate,
    TdsqlMysqlManaged,
    TdsqlPostgresqlPrivate,
    TdsqlPostgresqlManaged,
    GoldenDb,
    PolarDbX,
    PolarDbManagedMySql,
    PolarDbManagedPostgresql,
    PolarDbManagedOracle,
    SequoiaDb,
    GreatSql,
    GreatDb,
    KunDb,
    AntDb,
    HighGo,
    OpenTenBase,
    ShenTongNative,
    ShenTongMpp,
    ShenTongOpenGauss,
    Yashan,
}

impl DatabaseConfigProduct {
    pub const ALL: [Self; 33] = [
        Self::MySql,
        Self::MariaDb,
        Self::PostgreSql,
        Self::OpenGauss,
        Self::MogDb,
        Self::Vastbase,
        Self::KingbaseEs,
        Self::Dm,
        Self::TiDb,
        Self::OceanBase,
        Self::GBase8a,
        Self::GBase8s,
        Self::GBase8c,
        Self::TdsqlMysqlPrivate,
        Self::TdsqlMysqlManaged,
        Self::TdsqlPostgresqlPrivate,
        Self::TdsqlPostgresqlManaged,
        Self::GoldenDb,
        Self::PolarDbX,
        Self::PolarDbManagedMySql,
        Self::PolarDbManagedPostgresql,
        Self::PolarDbManagedOracle,
        Self::SequoiaDb,
        Self::GreatSql,
        Self::GreatDb,
        Self::KunDb,
        Self::AntDb,
        Self::HighGo,
        Self::OpenTenBase,
        Self::ShenTongNative,
        Self::ShenTongMpp,
        Self::ShenTongOpenGauss,
        Self::Yashan,
    ];
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DatabaseConfigComponent {
    Server,
    AccessControl,
    IdentityMapping,
    ReplicationIdentity,
    PluginRegistry,
    ComponentRegistry,
    RuntimeParameters,
    Persistence,
    PasswordStore,
    Cluster,
    GNode,
    GCluster,
    Gcware,
    CmServer,
    CmAgent,
    Proxy,
    Deployment,
    Ptk,
    Client,
    ConnectionManager,
    CommunicationSupport,
    Environment,
    ArchiveChecker,
    StorageManager,
    HighPerformanceLoader,
    MaxConnect,
    DmAp,
    CloudService,
    TiDb,
    TiKv,
    Pd,
    TiFlash,
    TiFlashLearner,
    TiProxy,
    TiCdc,
    TiCdcChangefeed,
    TiDbLightning,
    TiUp,
    OceanBaseObserver,
    OceanBaseTenant,
    ObProxy,
    Obd,
    BackupRecovery,
    PolarDbCn,
    PolarDbDn,
    PolarDbCdc,
    PolarDbGms,
    Operator,
    SequoiaStandalone,
    SequoiaCoordinator,
    SequoiaCatalog,
    SequoiaData,
    SequoiaSqlMySql,
    SequoiaSqlMariaDb,
    SequoiaSqlPostgreSql,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DatabaseConfigSurface {
    File,
    RuntimeSql,
    CloudApi,
    GeneratedReadOnly,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DatabaseConfigDialect {
    MySqlOptionFile,
    MySqlPersistedVariablesJson,
    PostgreSqlConf,
    PgHbaConf,
    PgIdentConf,
    PostgreSqlAutoConf,
    Ini,
    Toml,
    Yaml,
    Json,
    Xml,
    JavaProperties,
    KeyValue,
    GcwareConf,
    SequoiaQuickDeployClusterCsv,
    SequoiaQuickDeploySqlInstanceCsv,
    VendorText,
    VendorBinary,
    RuntimeSql,
    CloudApi,
    VendorSchema,
}

impl DatabaseConfigDialect {
    pub const fn is_binary(self) -> bool {
        matches!(self, Self::VendorBinary)
    }

    pub const fn is_generated(self) -> bool {
        matches!(
            self,
            Self::MySqlPersistedVariablesJson | Self::PostgreSqlAutoConf | Self::VendorBinary
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DatabaseConfigSupportLevel {
    VisualSyntax,
    RuntimeParameters,
    CloudProviderSchema,
    ReadOnlyDiscovery,
    VendorSchemaRequired,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DatabaseConfigEditPolicy {
    /// Allows bounded, lossless mutation of a local draft only.
    ///
    /// This policy does not prove target compatibility and never authorizes
    /// validated generation, remote application, activation, or deployment.
    LosslessLocalDraft,
    ReadOnly,
    VendorSchemaRequired,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DatabaseConfigLocalDraftAuthority {
    LosslessLocalDraft,
    ReadOnly,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DatabaseConfigReadOnlyReason {
    GeneratedArtifact,
    VendorSchemaRequired,
    ReadOnlyPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatabaseConfigReadOnlyStatus {
    pub authority: DatabaseConfigLocalDraftAuthority,
    pub reason: DatabaseConfigReadOnlyReason,
    pub notice: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DatabaseConfigValidator {
    SyntaxOnly,
    ServerConfigTest,
    RuntimeReadBack,
    CloudProvider,
    VendorTool,
    VendorSchemaRequired,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DatabaseConfigActivation {
    ReloadOrRestart,
    Restart,
    RollingRestart,
    RuntimeDependent,
    CloudManaged,
    VendorProcedure,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatabaseConfigProductDefinition {
    pub product: DatabaseConfigProduct,
    pub key: &'static str,
    pub label: &'static str,
    pub protocols: &'static [DatabaseConfigProtocol],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatabaseConfigArtifactDefinition {
    pub key: &'static str,
    pub product: DatabaseConfigProduct,
    pub component: DatabaseConfigComponent,
    pub surface: DatabaseConfigSurface,
    pub dialect: DatabaseConfigDialect,
    pub support: DatabaseConfigSupportLevel,
    pub edit_policy: DatabaseConfigEditPolicy,
    pub default_file_name: Option<&'static str>,
    pub validator: DatabaseConfigValidator,
    pub validation_note: &'static str,
    pub activation: DatabaseConfigActivation,
    pub activation_note: &'static str,
}

impl DatabaseConfigArtifactDefinition {
    /// Whether this catalog row describes a non-binary local file whose raw
    /// bytes may be read for bounded inspection.
    ///
    /// This does not prove that LovelyHawk has a source-backed visual parser;
    /// use [`Self::has_source_backed_visual_parser`] for that narrower claim.
    pub const fn is_file_visual_readable(self) -> bool {
        matches!(
            self.surface,
            DatabaseConfigSurface::File | DatabaseConfigSurface::GeneratedReadOnly
        ) && !self.dialect.is_binary()
    }

    /// Whether the artifact has a source-backed parser that the visual page may
    /// select without inventing a vendor grammar.
    pub const fn has_source_backed_visual_parser(self) -> bool {
        if !self.is_file_visual_readable() {
            return false;
        }

        let known_dialect = matches!(
            self.dialect,
            DatabaseConfigDialect::MySqlOptionFile
                | DatabaseConfigDialect::MySqlPersistedVariablesJson
                | DatabaseConfigDialect::PostgreSqlConf
                | DatabaseConfigDialect::PgHbaConf
                | DatabaseConfigDialect::PgIdentConf
                | DatabaseConfigDialect::PostgreSqlAutoConf
                | DatabaseConfigDialect::Ini
                | DatabaseConfigDialect::Toml
                | DatabaseConfigDialect::Yaml
                | DatabaseConfigDialect::Json
                | DatabaseConfigDialect::Xml
                | DatabaseConfigDialect::JavaProperties
                | DatabaseConfigDialect::KeyValue
                | DatabaseConfigDialect::GcwareConf
                | DatabaseConfigDialect::SequoiaQuickDeployClusterCsv
                | DatabaseConfigDialect::SequoiaQuickDeploySqlInstanceCsv
        );

        match self.support {
            DatabaseConfigSupportLevel::VisualSyntax => {
                known_dialect || matches!(self.dialect, DatabaseConfigDialect::VendorText)
            }
            DatabaseConfigSupportLevel::ReadOnlyDiscovery => known_dialect,
            DatabaseConfigSupportLevel::RuntimeParameters
            | DatabaseConfigSupportLevel::CloudProviderSchema
            | DatabaseConfigSupportLevel::VendorSchemaRequired => false,
        }
    }

    /// Returns the artifact-owned local draft authority.
    ///
    /// Schema metadata is deliberately not accepted here: selecting either a
    /// partial or complete schema can validate values but cannot grant or
    /// revoke local draft permission.
    pub const fn local_draft_authority(self) -> DatabaseConfigLocalDraftAuthority {
        if matches!(
            self.edit_policy,
            DatabaseConfigEditPolicy::LosslessLocalDraft
        ) && matches!(self.surface, DatabaseConfigSurface::File)
            && !self.dialect.is_generated()
        {
            DatabaseConfigLocalDraftAuthority::LosslessLocalDraft
        } else {
            DatabaseConfigLocalDraftAuthority::ReadOnly
        }
    }

    /// Whether the local file visualizer may mutate a bounded, lossless draft.
    ///
    /// This artifact-only decision grants no target validation, generation,
    /// application, activation, or deployment authority. Generated and binary
    /// artifacts fail closed even if a future catalog entry accidentally marks
    /// them as a local draft.
    pub const fn allows_lossless_local_draft(self) -> bool {
        matches!(
            self.local_draft_authority(),
            DatabaseConfigLocalDraftAuthority::LosslessLocalDraft
        )
    }

    /// Returns the finite reason and fixed renderer-safe notice for artifacts
    /// that do not grant local mutation authority.
    pub const fn read_only_status(self) -> Option<DatabaseConfigReadOnlyStatus> {
        if self.allows_lossless_local_draft() {
            return None;
        }

        let reason = if matches!(
            self.edit_policy,
            DatabaseConfigEditPolicy::VendorSchemaRequired
        ) {
            DatabaseConfigReadOnlyReason::VendorSchemaRequired
        } else if matches!(self.surface, DatabaseConfigSurface::GeneratedReadOnly) {
            DatabaseConfigReadOnlyReason::GeneratedArtifact
        } else {
            DatabaseConfigReadOnlyReason::ReadOnlyPolicy
        };
        let notice = match reason {
            DatabaseConfigReadOnlyReason::GeneratedArtifact => {
                "只读展示：该工件由服务器或厂商工具生成；当前仅允许预览，所有结构修改均已禁用，不能应用/部署。"
            }
            DatabaseConfigReadOnlyReason::VendorSchemaRequired => {
                "只读展示：该工件策略要求匹配产品/版本的厂商 schema；选择静态 schema 也不会解锁本地结构修改。当前仅允许预览，未经过目标校验，不能应用/部署。"
            }
            DatabaseConfigReadOnlyReason::ReadOnlyPolicy => {
                "只读展示：该工件的目录策略不授予本地结构修改权限，不能应用/部署。"
            }
        };

        Some(DatabaseConfigReadOnlyStatus {
            authority: DatabaseConfigLocalDraftAuthority::ReadOnly,
            reason,
            notice,
        })
    }
}

pub const DATABASE_CONFIG_PRODUCTS: &[DatabaseConfigProductDefinition] = &[
    product(
        DatabaseConfigProduct::MySql,
        "mysql",
        "MySQL",
        &[DatabaseConfigProtocol::MySql],
    ),
    product(
        DatabaseConfigProduct::MariaDb,
        "mariadb",
        "MariaDB",
        &[DatabaseConfigProtocol::MySql],
    ),
    product(
        DatabaseConfigProduct::PostgreSql,
        "postgresql",
        "PostgreSQL",
        &[DatabaseConfigProtocol::PostgreSql],
    ),
    product(
        DatabaseConfigProduct::OpenGauss,
        "opengauss",
        "openGauss",
        &[DatabaseConfigProtocol::PostgreSql],
    ),
    product(
        DatabaseConfigProduct::MogDb,
        "mogdb",
        "MogDB",
        &[DatabaseConfigProtocol::PostgreSql],
    ),
    product(
        DatabaseConfigProduct::Vastbase,
        "vastbase",
        "Vastbase",
        &[DatabaseConfigProtocol::PostgreSql],
    ),
    product(
        DatabaseConfigProduct::KingbaseEs,
        "kingbase-es",
        "KingbaseES",
        &[
            DatabaseConfigProtocol::PostgreSql,
            DatabaseConfigProtocol::OracleCompatible,
        ],
    ),
    product(
        DatabaseConfigProduct::Dm,
        "dm",
        "DM / 达梦",
        &[
            DatabaseConfigProtocol::DmNative,
            DatabaseConfigProtocol::OracleCompatible,
        ],
    ),
    product(
        DatabaseConfigProduct::TiDb,
        "tidb",
        "TiDB",
        &[DatabaseConfigProtocol::MySql],
    ),
    product(
        DatabaseConfigProduct::OceanBase,
        "oceanbase",
        "OceanBase",
        &[
            DatabaseConfigProtocol::MySql,
            DatabaseConfigProtocol::OracleCompatible,
        ],
    ),
    product(
        DatabaseConfigProduct::GBase8a,
        "gbase-8a",
        "GBase 8a",
        &[
            DatabaseConfigProtocol::MySql,
            DatabaseConfigProtocol::VendorNative,
        ],
    ),
    product(
        DatabaseConfigProduct::GBase8s,
        "gbase-8s",
        "GBase 8s",
        &[
            DatabaseConfigProtocol::InformixCompatible,
            DatabaseConfigProtocol::VendorNative,
        ],
    ),
    product(
        DatabaseConfigProduct::GBase8c,
        "gbase-8c",
        "GBase 8c",
        &[DatabaseConfigProtocol::PostgreSql],
    ),
    product(
        DatabaseConfigProduct::TdsqlMysqlPrivate,
        "tdsql-mysql-private",
        "TDSQL MySQL 私有化版",
        &[DatabaseConfigProtocol::MySql],
    ),
    product(
        DatabaseConfigProduct::TdsqlMysqlManaged,
        "tdsql-mysql-managed",
        "TDSQL MySQL 托管版",
        &[
            DatabaseConfigProtocol::MySql,
            DatabaseConfigProtocol::CloudControlPlane,
        ],
    ),
    product(
        DatabaseConfigProduct::TdsqlPostgresqlPrivate,
        "tdsql-postgresql-private",
        "TDSQL PostgreSQL 私有化版",
        &[DatabaseConfigProtocol::PostgreSql],
    ),
    product(
        DatabaseConfigProduct::TdsqlPostgresqlManaged,
        "tdsql-postgresql-managed",
        "TDSQL PostgreSQL 托管版",
        &[
            DatabaseConfigProtocol::PostgreSql,
            DatabaseConfigProtocol::CloudControlPlane,
        ],
    ),
    product(
        DatabaseConfigProduct::GoldenDb,
        "goldendb",
        "GoldenDB",
        &[
            DatabaseConfigProtocol::MySql,
            DatabaseConfigProtocol::VendorNative,
        ],
    ),
    product(
        DatabaseConfigProduct::PolarDbX,
        "polardb-x",
        "PolarDB-X",
        &[DatabaseConfigProtocol::MySql],
    ),
    product(
        DatabaseConfigProduct::PolarDbManagedMySql,
        "polardb-managed-mysql",
        "PolarDB MySQL 托管版",
        &[
            DatabaseConfigProtocol::MySql,
            DatabaseConfigProtocol::CloudControlPlane,
        ],
    ),
    product(
        DatabaseConfigProduct::PolarDbManagedPostgresql,
        "polardb-managed-postgresql",
        "PolarDB PostgreSQL 托管版",
        &[
            DatabaseConfigProtocol::PostgreSql,
            DatabaseConfigProtocol::CloudControlPlane,
        ],
    ),
    product(
        DatabaseConfigProduct::PolarDbManagedOracle,
        "polardb-managed-oracle",
        "PolarDB Oracle 兼容托管版",
        &[
            DatabaseConfigProtocol::OracleCompatible,
            DatabaseConfigProtocol::CloudControlPlane,
        ],
    ),
    product(
        DatabaseConfigProduct::SequoiaDb,
        "sequoiadb",
        "SequoiaDB",
        &[DatabaseConfigProtocol::SequoiaDbNative],
    ),
    product(
        DatabaseConfigProduct::GreatSql,
        "greatsql",
        "GreatSQL",
        &[DatabaseConfigProtocol::MySql],
    ),
    product(
        DatabaseConfigProduct::GreatDb,
        "greatdb",
        "GreatDB",
        &[DatabaseConfigProtocol::MySql],
    ),
    product(
        DatabaseConfigProduct::KunDb,
        "kundb",
        "KunDB",
        &[DatabaseConfigProtocol::MySql],
    ),
    product(
        DatabaseConfigProduct::AntDb,
        "antdb",
        "AntDB",
        &[DatabaseConfigProtocol::PostgreSql],
    ),
    product(
        DatabaseConfigProduct::HighGo,
        "highgo",
        "瀚高 HighGo",
        &[DatabaseConfigProtocol::PostgreSql],
    ),
    product(
        DatabaseConfigProduct::OpenTenBase,
        "opentenbase",
        "OpenTenBase",
        &[DatabaseConfigProtocol::PostgreSql],
    ),
    // Official product pages distinguish the native, MPP, and openGauss families.
    // A shared marketing name or wire compatibility is not evidence of a shared
    // configuration artifact or grammar:
    // https://shentongdata.com/index.php/product/list-4
    // https://shentongdata.com/index.php/product/view-37
    // https://shentongdata.com/index.php/product/view-106
    // https://shentongdata.com/index.php/product/view-355
    product(
        DatabaseConfigProduct::ShenTongNative,
        "shentong-native",
        "神通数据库（自研内核）",
        &[DatabaseConfigProtocol::VendorNative],
    ),
    product(
        DatabaseConfigProduct::ShenTongMpp,
        "shentong-mpp",
        "神通数据库（MPP 集群版）",
        &[DatabaseConfigProtocol::VendorNative],
    ),
    product(
        DatabaseConfigProduct::ShenTongOpenGauss,
        "shentong-opengauss",
        "神通数据库（openGauss 版）",
        &[DatabaseConfigProtocol::VendorNative],
    ),
    product(
        DatabaseConfigProduct::Yashan,
        "yashandb",
        "崖山数据库",
        &[DatabaseConfigProtocol::VendorNative],
    ),
];

const fn product(
    product: DatabaseConfigProduct,
    key: &'static str,
    label: &'static str,
    protocols: &'static [DatabaseConfigProtocol],
) -> DatabaseConfigProductDefinition {
    DatabaseConfigProductDefinition {
        product,
        key,
        label,
        protocols,
    }
}

const MYSQL_FILE_MYSQL_VALIDATION: &str = "默认文件名保留 Unix 常见 my.cnf；实际路径必须按目标实例与平台发现，Windows 可为 my.ini 或 my.cnf。catalog 不含目标补丁版本，因此仅声明语法校验：MySQL 8.0.11–8.0.15 不支持 --validate-config；MySQL 8.0.16 及之后的 8.0.x 与 8.4.x 可在隔离环境使用 mysqld --validate-config，但该原生校验不初始化存储引擎、插件或组件，不能据此确认相关选项。";
const MARIADB_FILE_VALIDATION: &str = "默认文件名保留 Unix 常见 my.cnf；实际路径必须按目标实例与平台发现，Windows 可为 my.ini 或 my.cnf。MariaDB 10.11/11.4 不支持服务端专用 validate-config；validate_config 到 MariaDB 13.0 才引入。--print-defaults 只能发现和展开已读取选项，不是服务端配置验证，因此仅声明语法校验。";
const MYSQL_FILE_ACTIVATION: &str = "先区分动态变量与启动期变量；文件变更仅通过受控滚动重启生效。";
const MYSQL_RUNTIME_VALIDATION: &str =
    "写入后从同一实例的变量视图独立回读，并区分会话、全局与持久化作用域。";
const MYSQL_RUNTIME_ACTIVATION: &str =
    "动态变量可立即生效；只读或启动期变量必须转为文件计划并受控重启。";
const POSTGRES_FILE_VALIDATION: &str =
    "由同产品、同版本服务端解析，并结合参数/配置错误视图回读；通用语法解析不能替代厂商语义校验。";
const POSTGRES_FILE_ACTIVATION: &str =
    "按参数 context 判定重载或重启；认证文件通常重载，postmaster 级参数需要受控重启。";
const POSTGRES_RUNTIME_VALIDATION: &str =
    "执行后从参数视图独立回读 effective、source 与 pending-restart 状态。";
const POSTGRES_RUNTIME_ACTIVATION: &str =
    "会话级参数立即生效；系统级参数按 context 重载或受控重启。";
const TOML_VALIDATION: &str =
    "严格 TOML 解析只验证结构；仍须交给同版本组件的配置检查或隔离启动检查。";
const COMPONENT_RESTART: &str = "按组件滚动重启并做集群健康回读；不得同时重启破坏仲裁的节点集合。";
const VENDOR_FILE_VALIDATION: &str =
    "使用匹配产品与版本的厂商配置检查工具；没有匹配 schema 时仅允许只读发现。";
const VENDOR_FILE_ACTIVATION: &str =
    "按厂商运维手册生成变更计划，并在独立验证后执行滚动或受控重启。";
const VENDOR_SCHEMA_VALIDATION: &str =
    "必须先取得匹配产品、组件和版本的厂商 schema/配置说明，未知字段不得推断。";
const VENDOR_SCHEMA_ACTIVATION: &str = "必须由匹配版本的厂商工具决定激活方式并完成健康回读。";
const TIDB_COMPONENT_SCHEMA_VALIDATION: &str = "仅做严格 TOML 结构解析；必须取得与具体组件自身版本匹配的 PingCAP 配置说明，不能用 TiDB Server 版本推断字段语义。";
const TIDB_COMPONENT_ACTIVATION: &str =
    "仅通过匹配组件版本的 PingCAP 运维流程变更；由该组件决定热加载或滚动重启，并完成组件健康回读。";
const TICDC_CHANGEFEED_ACTIVATION: &str = "使用匹配版本的 TiCDC 工具暂停 changefeed、更新配置、恢复任务，并独立查询任务状态与 checkpoint；不得直接部署文件。";
const TIDB_LIGHTNING_ACTIVATION: &str = "仅由匹配版本的 tidb-lightning 在隔离导入计划中读取；启动任务前必须校验目标、数据源、凭据与 checkpoint 策略。";
const CM_FILE_VALIDATION: &str = "使用匹配产品与版本的 CM 参数工具检查；目录没有内置 CM 字段 schema，不得把通用文本解析当作厂商语义校验。";
const CM_FILE_ACTIVATION: &str =
    "仅通过匹配版本的 CM 参数工具或部署流程变更，并按参数属性执行重载或受控重启后回读集群状态。";
const DM_INI_ACTIVATION: &str =
    "本地草稿不授权应用；仅由匹配版本中该文件对应的 DM 程序或工具消费，并按厂商流程独立验证结果。";
const DM_THREAD_VALIDATION: &str = "dmthrd.ini 仅在 dm.ini 的 DMTHRD_INI=1 时使用；catalog 未验证目标的精确 DM build 与 CPU 上下文，因此只允许 INI 语法可视化和本地无损草稿，必须由匹配 build 的厂商工具独立验证。";
const DM_THREAD_ACTIVATION: &str = "本地草稿不能自动部署或激活；仅在 dm.ini 的 DMTHRD_INI=1 时由匹配 build 的 DMServer 消费，应用前必须独立确认目标 CPU 上下文并遵循厂商流程。";

// Each catalog row keeps support, mutation, validation, and activation policy
// explicit so a new product cannot inherit a permissive default by accident.
#[allow(clippy::too_many_arguments)]
const fn file_artifact(
    key: &'static str,
    product: DatabaseConfigProduct,
    component: DatabaseConfigComponent,
    dialect: DatabaseConfigDialect,
    support: DatabaseConfigSupportLevel,
    edit_policy: DatabaseConfigEditPolicy,
    default_file_name: &'static str,
    validator: DatabaseConfigValidator,
    validation_note: &'static str,
    activation: DatabaseConfigActivation,
    activation_note: &'static str,
) -> DatabaseConfigArtifactDefinition {
    DatabaseConfigArtifactDefinition {
        key,
        product,
        component,
        surface: DatabaseConfigSurface::File,
        dialect,
        support,
        edit_policy,
        default_file_name: Some(default_file_name),
        validator,
        validation_note,
        activation,
        activation_note,
    }
}

const fn mysql_file(
    key: &'static str,
    product: DatabaseConfigProduct,
    default_file_name: &'static str,
) -> DatabaseConfigArtifactDefinition {
    file_artifact(
        key,
        product,
        DatabaseConfigComponent::Server,
        DatabaseConfigDialect::MySqlOptionFile,
        DatabaseConfigSupportLevel::VisualSyntax,
        DatabaseConfigEditPolicy::LosslessLocalDraft,
        default_file_name,
        DatabaseConfigValidator::SyntaxOnly,
        match product {
            DatabaseConfigProduct::MySql => MYSQL_FILE_MYSQL_VALIDATION,
            DatabaseConfigProduct::MariaDb => MARIADB_FILE_VALIDATION,
            _ => {
                "catalog 未覆盖该产品的目标版本与平台语义；仅声明语法校验，不得宣称存在原生服务端配置验证。"
            }
        },
        DatabaseConfigActivation::Restart,
        MYSQL_FILE_ACTIVATION,
    )
}

const fn mysql_runtime(
    key: &'static str,
    product: DatabaseConfigProduct,
    component: DatabaseConfigComponent,
) -> DatabaseConfigArtifactDefinition {
    runtime_artifact(
        key,
        product,
        component,
        MYSQL_RUNTIME_VALIDATION,
        MYSQL_RUNTIME_ACTIVATION,
    )
}

const fn postgres_file(
    key: &'static str,
    product: DatabaseConfigProduct,
    component: DatabaseConfigComponent,
    dialect: DatabaseConfigDialect,
    default_file_name: &'static str,
) -> DatabaseConfigArtifactDefinition {
    file_artifact(
        key,
        product,
        component,
        dialect,
        DatabaseConfigSupportLevel::VisualSyntax,
        DatabaseConfigEditPolicy::LosslessLocalDraft,
        default_file_name,
        DatabaseConfigValidator::ServerConfigTest,
        POSTGRES_FILE_VALIDATION,
        DatabaseConfigActivation::ReloadOrRestart,
        POSTGRES_FILE_ACTIVATION,
    )
}

const fn postgres_runtime(
    key: &'static str,
    product: DatabaseConfigProduct,
) -> DatabaseConfigArtifactDefinition {
    runtime_artifact(
        key,
        product,
        DatabaseConfigComponent::RuntimeParameters,
        POSTGRES_RUNTIME_VALIDATION,
        POSTGRES_RUNTIME_ACTIVATION,
    )
}

const fn runtime_artifact(
    key: &'static str,
    product: DatabaseConfigProduct,
    component: DatabaseConfigComponent,
    validation_note: &'static str,
    activation_note: &'static str,
) -> DatabaseConfigArtifactDefinition {
    DatabaseConfigArtifactDefinition {
        key,
        product,
        component,
        surface: DatabaseConfigSurface::RuntimeSql,
        dialect: DatabaseConfigDialect::RuntimeSql,
        support: DatabaseConfigSupportLevel::RuntimeParameters,
        edit_policy: DatabaseConfigEditPolicy::VendorSchemaRequired,
        default_file_name: None,
        validator: DatabaseConfigValidator::RuntimeReadBack,
        validation_note,
        activation: DatabaseConfigActivation::RuntimeDependent,
        activation_note,
    }
}

const fn generated_artifact(
    key: &'static str,
    product: DatabaseConfigProduct,
    component: DatabaseConfigComponent,
    dialect: DatabaseConfigDialect,
    default_file_name: &'static str,
    note: &'static str,
) -> DatabaseConfigArtifactDefinition {
    DatabaseConfigArtifactDefinition {
        key,
        product,
        component,
        surface: DatabaseConfigSurface::GeneratedReadOnly,
        dialect,
        support: DatabaseConfigSupportLevel::ReadOnlyDiscovery,
        edit_policy: DatabaseConfigEditPolicy::ReadOnly,
        default_file_name: Some(default_file_name),
        validator: DatabaseConfigValidator::NotApplicable,
        validation_note: note,
        activation: DatabaseConfigActivation::NotApplicable,
        activation_note: "该工件由服务器或配套运维工具生成；只能通过对应运行时、厂商工具或控制面接口变更。",
    }
}

const fn structured_vendor_file(
    key: &'static str,
    product: DatabaseConfigProduct,
    component: DatabaseConfigComponent,
    dialect: DatabaseConfigDialect,
    default_file_name: Option<&'static str>,
) -> DatabaseConfigArtifactDefinition {
    DatabaseConfigArtifactDefinition {
        key,
        product,
        component,
        surface: DatabaseConfigSurface::File,
        dialect,
        support: DatabaseConfigSupportLevel::VisualSyntax,
        edit_policy: DatabaseConfigEditPolicy::VendorSchemaRequired,
        default_file_name,
        validator: DatabaseConfigValidator::VendorSchemaRequired,
        validation_note: VENDOR_SCHEMA_VALIDATION,
        activation: DatabaseConfigActivation::VendorProcedure,
        activation_note: VENDOR_SCHEMA_ACTIVATION,
    }
}

const fn vendor_schema_file(
    key: &'static str,
    product: DatabaseConfigProduct,
    component: DatabaseConfigComponent,
    dialect: DatabaseConfigDialect,
    default_file_name: Option<&'static str>,
) -> DatabaseConfigArtifactDefinition {
    DatabaseConfigArtifactDefinition {
        key,
        product,
        component,
        surface: DatabaseConfigSurface::File,
        dialect,
        support: DatabaseConfigSupportLevel::VendorSchemaRequired,
        edit_policy: DatabaseConfigEditPolicy::VendorSchemaRequired,
        default_file_name,
        validator: DatabaseConfigValidator::VendorSchemaRequired,
        validation_note: VENDOR_SCHEMA_VALIDATION,
        activation: DatabaseConfigActivation::VendorProcedure,
        activation_note: VENDOR_SCHEMA_ACTIVATION,
    }
}

const fn gbase_8s_vendor_text_file(
    key: &'static str,
    component: DatabaseConfigComponent,
    default_file_name: &'static str,
    validation_note: &'static str,
) -> DatabaseConfigArtifactDefinition {
    file_artifact(
        key,
        DatabaseConfigProduct::GBase8s,
        component,
        DatabaseConfigDialect::VendorText,
        DatabaseConfigSupportLevel::VendorSchemaRequired,
        DatabaseConfigEditPolicy::VendorSchemaRequired,
        default_file_name,
        DatabaseConfigValidator::VendorSchemaRequired,
        validation_note,
        DatabaseConfigActivation::VendorProcedure,
        VENDOR_SCHEMA_ACTIVATION,
    )
}

const fn gbase_8s_visual_text_file(
    key: &'static str,
    component: DatabaseConfigComponent,
    default_file_name: &'static str,
    validation_note: &'static str,
) -> DatabaseConfigArtifactDefinition {
    file_artifact(
        key,
        DatabaseConfigProduct::GBase8s,
        component,
        DatabaseConfigDialect::VendorText,
        DatabaseConfigSupportLevel::VisualSyntax,
        DatabaseConfigEditPolicy::VendorSchemaRequired,
        default_file_name,
        DatabaseConfigValidator::VendorSchemaRequired,
        validation_note,
        DatabaseConfigActivation::VendorProcedure,
        VENDOR_SCHEMA_ACTIVATION,
    )
}

const fn cm_file(
    key: &'static str,
    product: DatabaseConfigProduct,
    component: DatabaseConfigComponent,
    default_file_name: &'static str,
) -> DatabaseConfigArtifactDefinition {
    file_artifact(
        key,
        product,
        component,
        DatabaseConfigDialect::VendorText,
        DatabaseConfigSupportLevel::VendorSchemaRequired,
        DatabaseConfigEditPolicy::VendorSchemaRequired,
        default_file_name,
        DatabaseConfigValidator::VendorTool,
        CM_FILE_VALIDATION,
        DatabaseConfigActivation::VendorProcedure,
        CM_FILE_ACTIVATION,
    )
}

const fn dm_ini_file(
    key: &'static str,
    component: DatabaseConfigComponent,
    default_file_name: &'static str,
) -> DatabaseConfigArtifactDefinition {
    file_artifact(
        key,
        DatabaseConfigProduct::Dm,
        component,
        DatabaseConfigDialect::Ini,
        DatabaseConfigSupportLevel::VisualSyntax,
        DatabaseConfigEditPolicy::LosslessLocalDraft,
        default_file_name,
        DatabaseConfigValidator::VendorTool,
        VENDOR_FILE_VALIDATION,
        DatabaseConfigActivation::VendorProcedure,
        DM_INI_ACTIVATION,
    )
}

const fn dm_thread_ini_file() -> DatabaseConfigArtifactDefinition {
    // Official DM physical-storage documentation makes this file conditional
    // on DMTHRD_INI=1; CPU binding still depends on the exact target host.
    // https://eco.dameng.com/document/dm/zh-cn/pm/physical-storage
    DatabaseConfigArtifactDefinition {
        validation_note: DM_THREAD_VALIDATION,
        activation_note: DM_THREAD_ACTIVATION,
        ..dm_ini_file("dm-thread", DatabaseConfigComponent::Server, "dmthrd.ini")
    }
}

pub const DATABASE_CONFIG_ARTIFACTS: &[DatabaseConfigArtifactDefinition] = &[
    // MySQL and MariaDB keep server-owned identity and persisted state separate from
    // user-managed option files. Plugin/component inventory is runtime metadata only.
    // https://dev.mysql.com/doc/refman/8.0/en/replication-options.html
    // https://dev.mysql.com/doc/refman/8.4/en/replication-options.html
    // https://dev.mysql.com/doc/refman/8.4/en/information-schema-plugins-table.html
    // https://dev.mysql.com/doc/refman/8.4/en/obtaining-component-information.html
    // https://mariadb.com/docs/server/reference/plugins/plugin-overview
    mysql_file("mysql-option-file", DatabaseConfigProduct::MySql, "my.cnf"),
    mysql_runtime(
        "mysql-runtime-variables",
        DatabaseConfigProduct::MySql,
        DatabaseConfigComponent::RuntimeParameters,
    ),
    runtime_artifact(
        "mysql-plugin-registry",
        DatabaseConfigProduct::MySql,
        DatabaseConfigComponent::PluginRegistry,
        "仅只读盘点 INFORMATION_SCHEMA.PLUGINS；mysql.plugin 只补充由 INSTALL PLUGIN 注册的持久插件，不能代表通过启动选项加载的全部插件，也不得读取其他 mysql 系统表或秘密。",
        "当前 P0 仅提供只读 inventory，不提供 mutation 或 activation，也不授权 INSTALL/UNINSTALL PLUGIN；catalog 行不表示 runtime provider 已接入。",
    ),
    runtime_artifact(
        "mysql-component-registry",
        DatabaseConfigProduct::MySql,
        DatabaseConfigComponent::ComponentRegistry,
        "仅只读盘点 mysql.component 的 component_urn；该 URN 是 INSTALL COMPONENT 与 UNINSTALL COMPONENT 使用的组件标识，不读取其他 mysql 系统表或秘密。",
        "当前 P0 仅提供只读 inventory，不提供 mutation 或 activation，也不授权 INSTALL/UNINSTALL COMPONENT；catalog 行不表示 runtime provider 已接入。",
    ),
    generated_artifact(
        "mysql-server-uuid",
        DatabaseConfigProduct::MySql,
        DatabaseConfigComponent::ReplicationIdentity,
        DatabaseConfigDialect::MySqlOptionFile,
        "auto.cnf",
        "auto.cnf 由 MySQL 服务端自动生成，仅含 `[auto]` 下的 `server_uuid` 身份状态；禁止写入或修改，未来只读发现必须与同一实例的 @@server_uuid 交叉回读。",
    ),
    generated_artifact(
        "mysql-persisted-variables",
        DatabaseConfigProduct::MySql,
        DatabaseConfigComponent::Persistence,
        DatabaseConfigDialect::MySqlPersistedVariablesJson,
        "mysqld-auto.cnf",
        "mysqld-auto.cnf 由 SET PERSIST 管理，直接编辑可能破坏服务端持久化状态。",
    ),
    mysql_file(
        "mariadb-option-file",
        DatabaseConfigProduct::MariaDb,
        "my.cnf",
    ),
    mysql_runtime(
        "mariadb-runtime-variables",
        DatabaseConfigProduct::MariaDb,
        DatabaseConfigComponent::RuntimeParameters,
    ),
    runtime_artifact(
        "mariadb-plugin-registry",
        DatabaseConfigProduct::MariaDb,
        DatabaseConfigComponent::PluginRegistry,
        "仅只读盘点 INFORMATION_SCHEMA.PLUGINS；mysql.plugin 只补充由 INSTALL PLUGIN、INSTALL SONAME 或 mariadb-plugin 注册的持久插件，不能代表通过启动选项加载的全部插件，也不得读取其他 mysql 系统表或秘密。",
        "当前 P0 仅提供只读 inventory，不提供 mutation 或 activation，也不授权安装、卸载或启停插件；catalog 行不表示 runtime provider 已接入。",
    ),
    // PostgreSQL: upstream files, runtime settings, and server-generated ALTER SYSTEM state.
    postgres_file(
        "postgresql-main",
        DatabaseConfigProduct::PostgreSql,
        DatabaseConfigComponent::Server,
        DatabaseConfigDialect::PostgreSqlConf,
        "postgresql.conf",
    ),
    postgres_file(
        "postgresql-hba",
        DatabaseConfigProduct::PostgreSql,
        DatabaseConfigComponent::AccessControl,
        DatabaseConfigDialect::PgHbaConf,
        "pg_hba.conf",
    ),
    postgres_file(
        "postgresql-ident",
        DatabaseConfigProduct::PostgreSql,
        DatabaseConfigComponent::IdentityMapping,
        DatabaseConfigDialect::PgIdentConf,
        "pg_ident.conf",
    ),
    postgres_runtime(
        "postgresql-runtime-parameters",
        DatabaseConfigProduct::PostgreSql,
    ),
    generated_artifact(
        "postgresql-auto-conf",
        DatabaseConfigProduct::PostgreSql,
        DatabaseConfigComponent::Persistence,
        DatabaseConfigDialect::PostgreSqlAutoConf,
        "postgresql.auto.conf",
        "postgresql.auto.conf 由 ALTER SYSTEM 生成，直接编辑会绕过服务端并发与语义检查。",
    ),
    // openGauss family.
    postgres_file(
        "opengauss-main",
        DatabaseConfigProduct::OpenGauss,
        DatabaseConfigComponent::Server,
        DatabaseConfigDialect::PostgreSqlConf,
        "postgresql.conf",
    ),
    postgres_file(
        "opengauss-hba",
        DatabaseConfigProduct::OpenGauss,
        DatabaseConfigComponent::AccessControl,
        DatabaseConfigDialect::PgHbaConf,
        "pg_hba.conf",
    ),
    postgres_file(
        "opengauss-ident",
        DatabaseConfigProduct::OpenGauss,
        DatabaseConfigComponent::IdentityMapping,
        DatabaseConfigDialect::PgIdentConf,
        "pg_ident.conf",
    ),
    postgres_runtime(
        "opengauss-runtime-parameters",
        DatabaseConfigProduct::OpenGauss,
    ),
    structured_vendor_file(
        "opengauss-om-cluster-xml",
        DatabaseConfigProduct::OpenGauss,
        DatabaseConfigComponent::Deployment,
        DatabaseConfigDialect::Xml,
        None,
    ),
    cm_file(
        "opengauss-cm-server",
        DatabaseConfigProduct::OpenGauss,
        DatabaseConfigComponent::CmServer,
        "cm_server.conf",
    ),
    cm_file(
        "opengauss-cm-agent",
        DatabaseConfigProduct::OpenGauss,
        DatabaseConfigComponent::CmAgent,
        "cm_agent.conf",
    ),
    generated_artifact(
        "opengauss-cluster-static-config",
        DatabaseConfigProduct::OpenGauss,
        DatabaseConfigComponent::Cluster,
        DatabaseConfigDialect::VendorBinary,
        "cluster_static_config",
        "cluster_static_config 由 gs_om 根据部署 XML 生成，是禁止文本读取或修改的二进制集群状态。",
    ),
    postgres_file(
        "mogdb-main",
        DatabaseConfigProduct::MogDb,
        DatabaseConfigComponent::Server,
        DatabaseConfigDialect::PostgreSqlConf,
        "postgresql.conf",
    ),
    postgres_file(
        "mogdb-hba",
        DatabaseConfigProduct::MogDb,
        DatabaseConfigComponent::AccessControl,
        DatabaseConfigDialect::PgHbaConf,
        "pg_hba.conf",
    ),
    postgres_file(
        "mogdb-ident",
        DatabaseConfigProduct::MogDb,
        DatabaseConfigComponent::IdentityMapping,
        DatabaseConfigDialect::PgIdentConf,
        "pg_ident.conf",
    ),
    postgres_runtime("mogdb-runtime-parameters", DatabaseConfigProduct::MogDb),
    structured_vendor_file(
        "mogdb-om-cluster-xml",
        DatabaseConfigProduct::MogDb,
        DatabaseConfigComponent::Deployment,
        DatabaseConfigDialect::Xml,
        None,
    ),
    cm_file(
        "mogdb-cm-server",
        DatabaseConfigProduct::MogDb,
        DatabaseConfigComponent::CmServer,
        "cm_server.conf",
    ),
    cm_file(
        "mogdb-cm-agent",
        DatabaseConfigProduct::MogDb,
        DatabaseConfigComponent::CmAgent,
        "cm_agent.conf",
    ),
    structured_vendor_file(
        "mogdb-ptk-deployment",
        DatabaseConfigProduct::MogDb,
        DatabaseConfigComponent::Ptk,
        DatabaseConfigDialect::Yaml,
        Some("config.yaml"),
    ),
    generated_artifact(
        "mogdb-cluster-static-config",
        DatabaseConfigProduct::MogDb,
        DatabaseConfigComponent::Cluster,
        DatabaseConfigDialect::VendorBinary,
        "cluster_static_config",
        "cluster_static_config 由 MogDB 运维工具根据部署配置生成，是禁止文本读取或修改的二进制集群状态。",
    ),
    postgres_file(
        "vastbase-main",
        DatabaseConfigProduct::Vastbase,
        DatabaseConfigComponent::Server,
        DatabaseConfigDialect::PostgreSqlConf,
        "postgresql.conf",
    ),
    postgres_file(
        "vastbase-hba",
        DatabaseConfigProduct::Vastbase,
        DatabaseConfigComponent::AccessControl,
        DatabaseConfigDialect::PgHbaConf,
        "pg_hba.conf",
    ),
    postgres_file(
        "vastbase-ident",
        DatabaseConfigProduct::Vastbase,
        DatabaseConfigComponent::IdentityMapping,
        DatabaseConfigDialect::PgIdentConf,
        "pg_ident.conf",
    ),
    postgres_runtime(
        "vastbase-runtime-parameters",
        DatabaseConfigProduct::Vastbase,
    ),
    structured_vendor_file(
        "vastbase-om-cluster-xml",
        DatabaseConfigProduct::Vastbase,
        DatabaseConfigComponent::Deployment,
        DatabaseConfigDialect::Xml,
        None,
    ),
    postgres_file(
        "kingbase-es-main",
        DatabaseConfigProduct::KingbaseEs,
        DatabaseConfigComponent::Server,
        DatabaseConfigDialect::PostgreSqlConf,
        "kingbase.conf",
    ),
    postgres_file(
        "kingbase-es-hba",
        DatabaseConfigProduct::KingbaseEs,
        DatabaseConfigComponent::AccessControl,
        DatabaseConfigDialect::PgHbaConf,
        "sys_hba.conf",
    ),
    postgres_file(
        "kingbase-es-ident",
        DatabaseConfigProduct::KingbaseEs,
        DatabaseConfigComponent::IdentityMapping,
        DatabaseConfigDialect::PgIdentConf,
        "sys_ident.conf",
    ),
    postgres_runtime(
        "kingbase-es-runtime-parameters",
        DatabaseConfigProduct::KingbaseEs,
    ),
    vendor_schema_file(
        "kingbase-es-repmgr",
        DatabaseConfigProduct::KingbaseEs,
        DatabaseConfigComponent::Cluster,
        DatabaseConfigDialect::VendorText,
        Some("repmgr.conf"),
    ),
    structured_vendor_file(
        "kingbase-es-replication",
        DatabaseConfigProduct::KingbaseEs,
        DatabaseConfigComponent::Cluster,
        DatabaseConfigDialect::PostgreSqlConf,
        Some("es_rep.conf"),
    ),
    generated_artifact(
        "kingbase-es-auto-conf",
        DatabaseConfigProduct::KingbaseEs,
        DatabaseConfigComponent::Persistence,
        DatabaseConfigDialect::PostgreSqlAutoConf,
        "kingbase.auto.conf",
        "kingbase.auto.conf 由服务端运行时参数接口生成，禁止绕过服务端直接编辑。",
    ),
    // DM has multiple independent INI roles; they must not be collapsed into dm.ini.
    file_artifact(
        "dm-main",
        DatabaseConfigProduct::Dm,
        DatabaseConfigComponent::Server,
        DatabaseConfigDialect::Ini,
        DatabaseConfigSupportLevel::VisualSyntax,
        DatabaseConfigEditPolicy::LosslessLocalDraft,
        "dm.ini",
        DatabaseConfigValidator::VendorTool,
        VENDOR_FILE_VALIDATION,
        DatabaseConfigActivation::VendorProcedure,
        VENDOR_FILE_ACTIVATION,
    ),
    dm_ini_file("dm-ap", DatabaseConfigComponent::DmAp, "dmap.ini"),
    dm_ini_file("dm-init", DatabaseConfigComponent::Deployment, "dminit.ini"),
    // dmdcr_cfg.ini uses repeated [GRP] sections whose following CSS/ASM
    // members form one ordered vendor-owned unit; generic INI edits can detach it.
    vendor_schema_file(
        "dm-dcr-config",
        DatabaseConfigProduct::Dm,
        DatabaseConfigComponent::Deployment,
        DatabaseConfigDialect::VendorText,
        Some("dmdcr_cfg.ini"),
    ),
    // DMDCR_*_STARTUP_CMD values are command payloads, not ordinary INI values.
    vendor_schema_file(
        "dm-dcr-node",
        DatabaseConfigProduct::Dm,
        DatabaseConfigComponent::Cluster,
        DatabaseConfigDialect::VendorText,
        Some("dmdcr.ini"),
    ),
    dm_ini_file(
        "dm-css-monitor",
        DatabaseConfigComponent::Cluster,
        "dmcssm.ini",
    ),
    dm_ini_file(
        "dm-asm-mal",
        DatabaseConfigComponent::Cluster,
        "dmasvrmal.ini",
    ),
    vendor_schema_file(
        "dm-client-service",
        DatabaseConfigProduct::Dm,
        DatabaseConfigComponent::Client,
        DatabaseConfigDialect::VendorText,
        Some("dm_svc.conf"),
    ),
    dm_ini_file("dm-mp", DatabaseConfigComponent::Cluster, "mp.ini"),
    dm_thread_ini_file(),
    file_artifact(
        "dm-archive",
        DatabaseConfigProduct::Dm,
        DatabaseConfigComponent::Persistence,
        DatabaseConfigDialect::Ini,
        DatabaseConfigSupportLevel::VisualSyntax,
        DatabaseConfigEditPolicy::LosslessLocalDraft,
        "dmarch.ini",
        DatabaseConfigValidator::VendorTool,
        VENDOR_FILE_VALIDATION,
        DatabaseConfigActivation::VendorProcedure,
        VENDOR_FILE_ACTIVATION,
    ),
    file_artifact(
        "dm-mal",
        DatabaseConfigProduct::Dm,
        DatabaseConfigComponent::Cluster,
        DatabaseConfigDialect::Ini,
        DatabaseConfigSupportLevel::VisualSyntax,
        DatabaseConfigEditPolicy::LosslessLocalDraft,
        "dmmal.ini",
        DatabaseConfigValidator::VendorTool,
        VENDOR_FILE_VALIDATION,
        DatabaseConfigActivation::VendorProcedure,
        VENDOR_FILE_ACTIVATION,
    ),
    file_artifact(
        "dm-watcher",
        DatabaseConfigProduct::Dm,
        DatabaseConfigComponent::Cluster,
        DatabaseConfigDialect::Ini,
        DatabaseConfigSupportLevel::VisualSyntax,
        DatabaseConfigEditPolicy::LosslessLocalDraft,
        "dmwatcher.ini",
        DatabaseConfigValidator::VendorTool,
        VENDOR_FILE_VALIDATION,
        DatabaseConfigActivation::VendorProcedure,
        VENDOR_FILE_ACTIVATION,
    ),
    file_artifact(
        "dm-monitor",
        DatabaseConfigProduct::Dm,
        DatabaseConfigComponent::Cluster,
        DatabaseConfigDialect::Ini,
        DatabaseConfigSupportLevel::VisualSyntax,
        DatabaseConfigEditPolicy::LosslessLocalDraft,
        "dmmonitor.ini",
        DatabaseConfigValidator::VendorTool,
        VENDOR_FILE_VALIDATION,
        DatabaseConfigActivation::VendorProcedure,
        VENDOR_FILE_ACTIVATION,
    ),
    file_artifact(
        "dm-timer",
        DatabaseConfigProduct::Dm,
        DatabaseConfigComponent::Cluster,
        DatabaseConfigDialect::Ini,
        DatabaseConfigSupportLevel::VisualSyntax,
        DatabaseConfigEditPolicy::LosslessLocalDraft,
        "dmtimer.ini",
        DatabaseConfigValidator::VendorTool,
        VENDOR_FILE_VALIDATION,
        DatabaseConfigActivation::VendorProcedure,
        VENDOR_FILE_ACTIVATION,
    ),
    file_artifact(
        "dm-sql-log",
        DatabaseConfigProduct::Dm,
        DatabaseConfigComponent::Server,
        DatabaseConfigDialect::Ini,
        DatabaseConfigSupportLevel::VisualSyntax,
        DatabaseConfigEditPolicy::LosslessLocalDraft,
        "sqllog.ini",
        DatabaseConfigValidator::VendorTool,
        VENDOR_FILE_VALIDATION,
        DatabaseConfigActivation::VendorProcedure,
        VENDOR_FILE_ACTIVATION,
    ),
    runtime_artifact(
        "dm-runtime-parameters",
        DatabaseConfigProduct::Dm,
        DatabaseConfigComponent::RuntimeParameters,
        "通过匹配版本的 DM 参数接口写入并从动态参数视图独立回读。",
        "是否即时生效或需要重启由参数属性和 DM 版本决定。",
    ),
    // TiDB: every process has an independent TOML artifact.
    file_artifact(
        "tidb-server-toml",
        DatabaseConfigProduct::TiDb,
        DatabaseConfigComponent::TiDb,
        DatabaseConfigDialect::Toml,
        DatabaseConfigSupportLevel::VisualSyntax,
        DatabaseConfigEditPolicy::LosslessLocalDraft,
        "tidb.toml",
        DatabaseConfigValidator::SyntaxOnly,
        TOML_VALIDATION,
        DatabaseConfigActivation::RollingRestart,
        COMPONENT_RESTART,
    ),
    file_artifact(
        "tidb-tikv-toml",
        DatabaseConfigProduct::TiDb,
        DatabaseConfigComponent::TiKv,
        DatabaseConfigDialect::Toml,
        DatabaseConfigSupportLevel::VisualSyntax,
        DatabaseConfigEditPolicy::LosslessLocalDraft,
        "tikv.toml",
        DatabaseConfigValidator::SyntaxOnly,
        TOML_VALIDATION,
        DatabaseConfigActivation::RollingRestart,
        COMPONENT_RESTART,
    ),
    file_artifact(
        "tidb-pd-toml",
        DatabaseConfigProduct::TiDb,
        DatabaseConfigComponent::Pd,
        DatabaseConfigDialect::Toml,
        DatabaseConfigSupportLevel::VisualSyntax,
        DatabaseConfigEditPolicy::LosslessLocalDraft,
        "pd.toml",
        DatabaseConfigValidator::SyntaxOnly,
        TOML_VALIDATION,
        DatabaseConfigActivation::RollingRestart,
        COMPONENT_RESTART,
    ),
    structured_vendor_file(
        "tidb-tiflash-toml",
        DatabaseConfigProduct::TiDb,
        DatabaseConfigComponent::TiFlash,
        DatabaseConfigDialect::Toml,
        Some("tiflash.toml"),
    ),
    structured_vendor_file(
        "tidb-tiflash-learner-toml",
        DatabaseConfigProduct::TiDb,
        DatabaseConfigComponent::TiFlashLearner,
        DatabaseConfigDialect::Toml,
        Some("tiflash-learner.toml"),
    ),
    file_artifact(
        "tidb-tiproxy-toml",
        DatabaseConfigProduct::TiDb,
        DatabaseConfigComponent::TiProxy,
        DatabaseConfigDialect::Toml,
        DatabaseConfigSupportLevel::VisualSyntax,
        DatabaseConfigEditPolicy::VendorSchemaRequired,
        "tiproxy.toml",
        DatabaseConfigValidator::VendorSchemaRequired,
        TIDB_COMPONENT_SCHEMA_VALIDATION,
        DatabaseConfigActivation::VendorProcedure,
        TIDB_COMPONENT_ACTIVATION,
    ),
    file_artifact(
        "tidb-ticdc-toml",
        DatabaseConfigProduct::TiDb,
        DatabaseConfigComponent::TiCdc,
        DatabaseConfigDialect::Toml,
        DatabaseConfigSupportLevel::VisualSyntax,
        DatabaseConfigEditPolicy::VendorSchemaRequired,
        "ticdc.toml",
        DatabaseConfigValidator::VendorSchemaRequired,
        TIDB_COMPONENT_SCHEMA_VALIDATION,
        DatabaseConfigActivation::VendorProcedure,
        TIDB_COMPONENT_ACTIVATION,
    ),
    file_artifact(
        "tidb-ticdc-changefeed-toml",
        DatabaseConfigProduct::TiDb,
        DatabaseConfigComponent::TiCdcChangefeed,
        DatabaseConfigDialect::Toml,
        DatabaseConfigSupportLevel::VisualSyntax,
        DatabaseConfigEditPolicy::VendorSchemaRequired,
        "changefeed.toml",
        DatabaseConfigValidator::VendorSchemaRequired,
        TIDB_COMPONENT_SCHEMA_VALIDATION,
        DatabaseConfigActivation::VendorProcedure,
        TICDC_CHANGEFEED_ACTIVATION,
    ),
    file_artifact(
        "tidb-lightning-toml",
        DatabaseConfigProduct::TiDb,
        DatabaseConfigComponent::TiDbLightning,
        DatabaseConfigDialect::Toml,
        DatabaseConfigSupportLevel::VisualSyntax,
        DatabaseConfigEditPolicy::VendorSchemaRequired,
        "tidb-lightning.toml",
        DatabaseConfigValidator::VendorSchemaRequired,
        TIDB_COMPONENT_SCHEMA_VALIDATION,
        DatabaseConfigActivation::VendorProcedure,
        TIDB_LIGHTNING_ACTIVATION,
    ),
    structured_vendor_file(
        "tidb-tiup-topology",
        DatabaseConfigProduct::TiDb,
        DatabaseConfigComponent::TiUp,
        DatabaseConfigDialect::Yaml,
        None,
    ),
    structured_vendor_file(
        "tidb-operator-cluster-cr",
        DatabaseConfigProduct::TiDb,
        DatabaseConfigComponent::Operator,
        DatabaseConfigDialect::Yaml,
        None,
    ),
    // OceanBase: observer.conf.bin is never a text-edit surface.
    generated_artifact(
        "oceanbase-observer-binary",
        DatabaseConfigProduct::OceanBase,
        DatabaseConfigComponent::OceanBaseObserver,
        DatabaseConfigDialect::VendorBinary,
        "observer.conf.bin",
        "observer.conf.bin 是 observer 生成的二进制状态，不能按文本读取或修改。",
    ),
    runtime_artifact(
        "oceanbase-observer-runtime",
        DatabaseConfigProduct::OceanBase,
        DatabaseConfigComponent::OceanBaseObserver,
        "仅执行只读 SHOW PARAMETERS 与 GV$OB_PARAMETERS inventory；同名参数的多节点、zone、server 与 scope 行必须分别保留，不得按参数名折叠。",
        "当前 P0 仅提供只读 inventory，不提供 mutation 或 activation，也不授权任何参数写入。",
    ),
    runtime_artifact(
        "oceanbase-obproxy-runtime",
        DatabaseConfigProduct::OceanBase,
        DatabaseConfigComponent::ObProxy,
        "仅以 root@proxysys 执行只读 SHOW PROXYCONFIG inventory；必须匹配 OBProxy 版本目录并对 secret 与凭据值脱敏。",
        "当前 P0 仅提供只读 inventory，不提供 mutation 或 activation，也不授权写入代理配置。",
    ),
    runtime_artifact(
        "oceanbase-tenant-variables",
        DatabaseConfigProduct::OceanBase,
        DatabaseConfigComponent::OceanBaseTenant,
        "仅支持 OceanBase CE 4.x MySQL mode tenant 的只读 SHOW GLOBAL VARIABLES 与 SHOW SESSION VARIABLES inventory；需要匹配版本的 vendor schema，不支持 Oracle mode。",
        "当前 P0 仅提供只读 inventory，不提供 mutation 或 activation；GLOBAL 变量语义仅面向新连接，现有 session 不变。",
    ),
    runtime_artifact(
        "oceanbase-backup-archive-state",
        DatabaseConfigProduct::OceanBase,
        DatabaseConfigComponent::BackupRecovery,
        "仅只读盘点 DBA_OB_BACKUP_PARAMETER、DBA_OB_ARCHIVE_DEST 及相关 jobs/history 视图；URI 中的 credentials 与 secret 必须脱敏。",
        "当前 P0 仅提供只读 inventory，不提供 mutation 或 activation，也不授权启动、停止或恢复备份与归档作业。",
    ),
    structured_vendor_file(
        "oceanbase-obd-deployment",
        DatabaseConfigProduct::OceanBase,
        DatabaseConfigComponent::Obd,
        DatabaseConfigDialect::Yaml,
        None,
    ),
    generated_artifact(
        "oceanbase-obd-registered-config",
        DatabaseConfigProduct::OceanBase,
        DatabaseConfigComponent::Obd,
        DatabaseConfigDialect::Yaml,
        "config.yaml",
        "部署注册后的 config.yaml 由 OBD 托管且可能包含工具生成的敏感值，只能脱敏只读发现。",
    ),
    structured_vendor_file(
        "oceanbase-operator-cluster-cr",
        DatabaseConfigProduct::OceanBase,
        DatabaseConfigComponent::Operator,
        DatabaseConfigDialect::Yaml,
        None,
    ),
    // GBase editions are different products and retain their native artifact families.
    file_artifact(
        "gbase-8a-gbase-options",
        DatabaseConfigProduct::GBase8a,
        DatabaseConfigComponent::GNode,
        DatabaseConfigDialect::MySqlOptionFile,
        DatabaseConfigSupportLevel::VisualSyntax,
        DatabaseConfigEditPolicy::LosslessLocalDraft,
        "gbase_8a_gbase.cnf",
        DatabaseConfigValidator::VendorTool,
        VENDOR_FILE_VALIDATION,
        DatabaseConfigActivation::RollingRestart,
        VENDOR_FILE_ACTIVATION,
    ),
    file_artifact(
        "gbase-8a-gcluster-options",
        DatabaseConfigProduct::GBase8a,
        DatabaseConfigComponent::GCluster,
        DatabaseConfigDialect::MySqlOptionFile,
        DatabaseConfigSupportLevel::VisualSyntax,
        DatabaseConfigEditPolicy::LosslessLocalDraft,
        "gbase_8a_gcluster.cnf",
        DatabaseConfigValidator::VendorTool,
        VENDOR_FILE_VALIDATION,
        DatabaseConfigActivation::RollingRestart,
        VENDOR_FILE_ACTIVATION,
    ),
    generated_artifact(
        "gbase-8a-gnode-cluster-common",
        DatabaseConfigProduct::GBase8a,
        DatabaseConfigComponent::GNode,
        DatabaseConfigDialect::Json,
        "cluster_common.cnf",
        "GBase 8a V9.5.3 的 $GBASE_BASE/config/cluster_common.cnf 是 GNode 厂商生成的 JSON 集群元数据；仅允许结构化查看。",
    ),
    generated_artifact(
        "gbase-8a-gcluster-cluster-common",
        DatabaseConfigProduct::GBase8a,
        DatabaseConfigComponent::GCluster,
        DatabaseConfigDialect::Json,
        "cluster_common.cnf",
        "GBase 8a V9.5.3 的 $GCLUSTER_BASE/config/cluster_common.cnf 是 GCluster 厂商生成的 JSON 集群元数据；仅允许结构化查看。",
    ),
    structured_vendor_file(
        "gbase-8a-distribution-xml",
        DatabaseConfigProduct::GBase8a,
        DatabaseConfigComponent::Cluster,
        DatabaseConfigDialect::Xml,
        None,
    ),
    structured_vendor_file(
        "gbase-8a-gcware-config",
        DatabaseConfigProduct::GBase8a,
        DatabaseConfigComponent::Gcware,
        DatabaseConfigDialect::GcwareConf,
        Some("gcware.conf"),
    ),
    gbase_8s_visual_text_file(
        "gbase-8s-onconfig",
        DatabaseConfigComponent::Server,
        "onconfig",
        "GBase 8s 服务器配置由 ONCONFIG 标识；未设置时缺省为 $GBASEDBTDIR/etc/onconfig，官方建议多实例使用 onconfig.<server_name>。没有匹配版本字段 schema 时不得推断语义。",
    ),
    gbase_8s_visual_text_file(
        "gbase-8s-sqlhosts",
        DatabaseConfigComponent::Client,
        "sqlhosts",
        "GBase 8s 连接信息缺省位于 $GBASEDBTDIR/etc/sqlhosts；GBASEDBTSQLHOSTS 可指定完整路径或实例专用文件。五列及 options 语义必须由匹配版本说明校验。",
    ),
    gbase_8s_vendor_text_file(
        "gbase-8s-connection-manager-config",
        DatabaseConfigComponent::ConnectionManager,
        "cmsm.cfg",
        "GBase 8s Connection Manager 缺省读取 $GBASEDBTDIR/etc/cmsm.cfg，CMCONFIG 可覆盖完整路径；文件含连接单元、SLA、宏和块结构，不能按通用空白键值语法推断。",
    ),
    gbase_8s_vendor_text_file(
        "gbase-8s-communication-support-config",
        DatabaseConfigComponent::CommunicationSupport,
        "concsm.cfg",
        "GBase 8s 通信支持模块缺省配置位于 $GBASEDBTDIR/etc/concsm.cfg，GBASEDBTCONCSMCFG 可覆盖路径或文件名；其中可能含认证与加密模块设置，只登记源文本。",
    ),
    gbase_8s_vendor_text_file(
        "gbase-8s-shared-environment",
        DatabaseConfigComponent::Environment,
        "gbasedbt.rc",
        "GBase 8s 共享环境配置位于 $GBASEDBTDIR/etc/gbasedbt.rc，由数据库管理员为所有服务器用户维护；它不是 shell 启动脚本，未知变量不得推断。",
    ),
    gbase_8s_vendor_text_file(
        "gbase-8s-user-environment",
        DatabaseConfigComponent::Environment,
        ".gbasedbt",
        "GBase 8s 用户私有环境覆盖文件位于 ~/.gbasedbt，由对应用户拥有并覆盖共享设置；内容可能含用户级路径或敏感环境值，只登记源文本。",
    ),
    file_artifact(
        "gbase-8s-archecker-template",
        DatabaseConfigProduct::GBase8s,
        DatabaseConfigComponent::ArchiveChecker,
        DatabaseConfigDialect::VendorText,
        DatabaseConfigSupportLevel::ReadOnlyDiscovery,
        DatabaseConfigEditPolicy::ReadOnly,
        "ac_config.std",
        DatabaseConfigValidator::NotApplicable,
        "$GBASEDBTDIR/etc/ac_config.std 是 archecker 参数模板；官方要求复制到另一文件后再修改，因此模板本身只读。",
        DatabaseConfigActivation::NotApplicable,
        "模板本身不激活；实际 archecker 配置必须通过 AC_CONFIG 指向经匹配版本检查的副本。",
    ),
    gbase_8s_vendor_text_file(
        "gbase-8s-storage-manager-definitions",
        DatabaseConfigComponent::StorageManager,
        "sm_versions",
        "$GBASEDBTDIR/etc/sm_versions 标识第三方存储管理器及版本；GBase 8s Primary Storage Manager 不使用 sm_versions.std，条目必须按实际 XBSA 厂商说明校验。",
    ),
    gbase_8s_vendor_text_file(
        "gbase-8s-high-performance-loader-config",
        DatabaseConfigComponent::HighPerformanceLoader,
        "plconfig",
        "High-Performance Loader 缺省读取 $GBASEDBTDIR/etc/plconfig；PLCONFIG 只能指定该目录中的简单文件名，复杂 HPL 参数语义需要匹配版本手册。",
    ),
    gbase_8s_vendor_text_file(
        "gbase-8s-maxconnect-config",
        DatabaseConfigComponent::MaxConnect,
        "IMCconfig",
        "GBase 8s MaxConnect 缺省读取 $GBASEDBTDIR/etc/IMCconfig；IMCCONFIG 可指定完整路径或实例文件名（如 IMCconfig.<instance>），字段语义需要匹配版本手册。",
    ),
    // ixbar.<servernum>, oncfg_<servername>.<servernum>, and the PSM catalog
    // are generated recovery state, not ordinary configuration text. The
    // catalog needs an opaque-state/directory surface before they can be
    // registered without misrepresenting them as editable or textual files.
    structured_vendor_file(
        "gbase-8s-om-cluster-xml",
        DatabaseConfigProduct::GBase8s,
        DatabaseConfigComponent::Deployment,
        DatabaseConfigDialect::Xml,
        None,
    ),
    postgres_file(
        "gbase-8c-main",
        DatabaseConfigProduct::GBase8c,
        DatabaseConfigComponent::Server,
        DatabaseConfigDialect::PostgreSqlConf,
        "postgresql.conf",
    ),
    postgres_file(
        "gbase-8c-hba",
        DatabaseConfigProduct::GBase8c,
        DatabaseConfigComponent::AccessControl,
        DatabaseConfigDialect::PgHbaConf,
        "pg_hba.conf",
    ),
    postgres_file(
        "gbase-8c-ident",
        DatabaseConfigProduct::GBase8c,
        DatabaseConfigComponent::IdentityMapping,
        DatabaseConfigDialect::PgIdentConf,
        "pg_ident.conf",
    ),
    postgres_runtime(
        "gbase-8c-runtime-parameters",
        DatabaseConfigProduct::GBase8c,
    ),
    generated_artifact(
        "gbase-8c-auto-conf",
        DatabaseConfigProduct::GBase8c,
        DatabaseConfigComponent::Persistence,
        DatabaseConfigDialect::PostgreSqlAutoConf,
        "postgresql.auto.conf",
        "postgresql.auto.conf 由 GBase 8c 运行时参数接口维护，禁止绕过服务端直接编辑。",
    ),
    structured_vendor_file(
        "gbase-8c-om-cluster-xml",
        DatabaseConfigProduct::GBase8c,
        DatabaseConfigComponent::Deployment,
        DatabaseConfigDialect::Xml,
        None,
    ),
    // TDSQL protocol families and deployment surfaces remain separate. Managed
    // instances expose a provider parameter plane, not these private-deployment files.
    mysql_file(
        "tdsql-mysql-option-file",
        DatabaseConfigProduct::TdsqlMysqlPrivate,
        "my.cnf",
    ),
    mysql_runtime(
        "tdsql-mysql-runtime-parameters",
        DatabaseConfigProduct::TdsqlMysqlPrivate,
        DatabaseConfigComponent::RuntimeParameters,
    ),
    DatabaseConfigArtifactDefinition {
        key: "tdsql-mysql-managed-parameter-api",
        product: DatabaseConfigProduct::TdsqlMysqlManaged,
        component: DatabaseConfigComponent::CloudService,
        surface: DatabaseConfigSurface::CloudApi,
        dialect: DatabaseConfigDialect::CloudApi,
        support: DatabaseConfigSupportLevel::CloudProviderSchema,
        edit_policy: DatabaseConfigEditPolicy::VendorSchemaRequired,
        default_file_name: None,
        validator: DatabaseConfigValidator::CloudProvider,
        validation_note: "必须绑定真实实例的引擎、版本和参数模板 schema；托管实例不得推断底层 my.cnf。",
        activation: DatabaseConfigActivation::CloudManaged,
        activation_note: "以云控制面返回的动态生效或重启语义为准，并在提交后独立回读。",
    },
    postgres_file(
        "tdsql-postgresql-main",
        DatabaseConfigProduct::TdsqlPostgresqlPrivate,
        DatabaseConfigComponent::Server,
        DatabaseConfigDialect::PostgreSqlConf,
        "postgresql.conf",
    ),
    postgres_file(
        "tdsql-postgresql-hba",
        DatabaseConfigProduct::TdsqlPostgresqlPrivate,
        DatabaseConfigComponent::AccessControl,
        DatabaseConfigDialect::PgHbaConf,
        "pg_hba.conf",
    ),
    postgres_file(
        "tdsql-postgresql-ident",
        DatabaseConfigProduct::TdsqlPostgresqlPrivate,
        DatabaseConfigComponent::IdentityMapping,
        DatabaseConfigDialect::PgIdentConf,
        "pg_ident.conf",
    ),
    postgres_runtime(
        "tdsql-postgresql-runtime-parameters",
        DatabaseConfigProduct::TdsqlPostgresqlPrivate,
    ),
    DatabaseConfigArtifactDefinition {
        key: "tdsql-postgresql-managed-parameter-api",
        product: DatabaseConfigProduct::TdsqlPostgresqlManaged,
        component: DatabaseConfigComponent::CloudService,
        surface: DatabaseConfigSurface::CloudApi,
        dialect: DatabaseConfigDialect::CloudApi,
        support: DatabaseConfigSupportLevel::CloudProviderSchema,
        edit_policy: DatabaseConfigEditPolicy::VendorSchemaRequired,
        default_file_name: None,
        validator: DatabaseConfigValidator::CloudProvider,
        validation_note: "必须绑定真实实例的 PostgreSQL 兼容版本和参数模板 schema；托管实例不得展示本地配置文件编辑。",
        activation: DatabaseConfigActivation::CloudManaged,
        activation_note: "以云控制面返回的动态生效或重启语义为准，并在提交后独立回读。",
    },
    // Distributed MySQL-compatible products keep vendor orchestration separate.
    vendor_schema_file(
        "goldendb-cluster-config",
        DatabaseConfigProduct::GoldenDb,
        DatabaseConfigComponent::Cluster,
        DatabaseConfigDialect::VendorSchema,
        None,
    ),
    // GoldenDB's compute-node proxy.ini is key/value text, but local draft
    // mutation stays disabled until a matching vendor schema is available.
    structured_vendor_file(
        "goldendb-proxy-ini",
        DatabaseConfigProduct::GoldenDb,
        DatabaseConfigComponent::Proxy,
        DatabaseConfigDialect::Ini,
        Some("proxy.ini"),
    ),
    mysql_runtime(
        "goldendb-runtime-parameters",
        DatabaseConfigProduct::GoldenDb,
        DatabaseConfigComponent::RuntimeParameters,
    ),
    file_artifact(
        "polardb-x-cn-properties",
        DatabaseConfigProduct::PolarDbX,
        DatabaseConfigComponent::PolarDbCn,
        DatabaseConfigDialect::JavaProperties,
        DatabaseConfigSupportLevel::VisualSyntax,
        DatabaseConfigEditPolicy::LosslessLocalDraft,
        "server.properties",
        DatabaseConfigValidator::VendorTool,
        VENDOR_FILE_VALIDATION,
        DatabaseConfigActivation::RollingRestart,
        VENDOR_FILE_ACTIVATION,
    ),
    file_artifact(
        "polardb-x-dn-option-file",
        DatabaseConfigProduct::PolarDbX,
        DatabaseConfigComponent::PolarDbDn,
        DatabaseConfigDialect::MySqlOptionFile,
        DatabaseConfigSupportLevel::VisualSyntax,
        DatabaseConfigEditPolicy::LosslessLocalDraft,
        "my.cnf",
        DatabaseConfigValidator::VendorTool,
        VENDOR_FILE_VALIDATION,
        DatabaseConfigActivation::RollingRestart,
        VENDOR_FILE_ACTIVATION,
    ),
    file_artifact(
        "polardb-x-cdc-properties",
        DatabaseConfigProduct::PolarDbX,
        DatabaseConfigComponent::PolarDbCdc,
        DatabaseConfigDialect::JavaProperties,
        DatabaseConfigSupportLevel::VisualSyntax,
        DatabaseConfigEditPolicy::LosslessLocalDraft,
        "config.properties",
        DatabaseConfigValidator::VendorTool,
        VENDOR_FILE_VALIDATION,
        DatabaseConfigActivation::RollingRestart,
        VENDOR_FILE_ACTIVATION,
    ),
    vendor_schema_file(
        "polardb-x-gms-config",
        DatabaseConfigProduct::PolarDbX,
        DatabaseConfigComponent::PolarDbGms,
        DatabaseConfigDialect::VendorSchema,
        None,
    ),
    structured_vendor_file(
        "polardb-x-operator-cr",
        DatabaseConfigProduct::PolarDbX,
        DatabaseConfigComponent::Operator,
        DatabaseConfigDialect::Yaml,
        None,
    ),
    mysql_runtime(
        "polardb-x-runtime-parameters",
        DatabaseConfigProduct::PolarDbX,
        DatabaseConfigComponent::RuntimeParameters,
    ),
    DatabaseConfigArtifactDefinition {
        key: "polardb-managed-mysql-parameter-api",
        product: DatabaseConfigProduct::PolarDbManagedMySql,
        component: DatabaseConfigComponent::CloudService,
        surface: DatabaseConfigSurface::CloudApi,
        dialect: DatabaseConfigDialect::CloudApi,
        support: DatabaseConfigSupportLevel::CloudProviderSchema,
        edit_policy: DatabaseConfigEditPolicy::VendorSchemaRequired,
        default_file_name: None,
        validator: DatabaseConfigValidator::CloudProvider,
        validation_note: "必须读取实例引擎、版本和参数模板 schema，并在提交后通过云控制面回读。",
        activation: DatabaseConfigActivation::CloudManaged,
        activation_note: "以云控制面返回的 immediate/reboot 语义为准，不假设底层文件或服务动作。",
    },
    DatabaseConfigArtifactDefinition {
        key: "polardb-managed-postgresql-parameter-api",
        product: DatabaseConfigProduct::PolarDbManagedPostgresql,
        component: DatabaseConfigComponent::CloudService,
        surface: DatabaseConfigSurface::CloudApi,
        dialect: DatabaseConfigDialect::CloudApi,
        support: DatabaseConfigSupportLevel::CloudProviderSchema,
        edit_policy: DatabaseConfigEditPolicy::VendorSchemaRequired,
        default_file_name: None,
        validator: DatabaseConfigValidator::CloudProvider,
        validation_note: "必须读取 PostgreSQL 引擎版本和参数模板 schema，并在提交后通过云控制面回读。",
        activation: DatabaseConfigActivation::CloudManaged,
        activation_note: "以云控制面返回的 immediate/reboot 语义为准，不假设底层文件或服务动作。",
    },
    DatabaseConfigArtifactDefinition {
        key: "polardb-managed-oracle-parameter-api",
        product: DatabaseConfigProduct::PolarDbManagedOracle,
        component: DatabaseConfigComponent::CloudService,
        surface: DatabaseConfigSurface::CloudApi,
        dialect: DatabaseConfigDialect::CloudApi,
        support: DatabaseConfigSupportLevel::CloudProviderSchema,
        edit_policy: DatabaseConfigEditPolicy::VendorSchemaRequired,
        default_file_name: None,
        validator: DatabaseConfigValidator::CloudProvider,
        validation_note: "必须读取 Oracle 兼容引擎版本和参数模板 schema，并在提交后通过云控制面回读。",
        activation: DatabaseConfigActivation::CloudManaged,
        activation_note: "以云控制面返回的 immediate/reboot 语义为准，不假设底层文件或服务动作。",
    },
    // SequoiaDB uses the same logical filename for standalone and role-specific instances.
    file_artifact(
        "sequoiadb-standalone-config",
        DatabaseConfigProduct::SequoiaDb,
        DatabaseConfigComponent::SequoiaStandalone,
        DatabaseConfigDialect::KeyValue,
        DatabaseConfigSupportLevel::VisualSyntax,
        DatabaseConfigEditPolicy::LosslessLocalDraft,
        "sdb.conf",
        DatabaseConfigValidator::VendorTool,
        VENDOR_FILE_VALIDATION,
        DatabaseConfigActivation::RollingRestart,
        COMPONENT_RESTART,
    ),
    file_artifact(
        "sequoiadb-coordinator-config",
        DatabaseConfigProduct::SequoiaDb,
        DatabaseConfigComponent::SequoiaCoordinator,
        DatabaseConfigDialect::KeyValue,
        DatabaseConfigSupportLevel::VisualSyntax,
        DatabaseConfigEditPolicy::LosslessLocalDraft,
        "sdb.conf",
        DatabaseConfigValidator::VendorTool,
        VENDOR_FILE_VALIDATION,
        DatabaseConfigActivation::RollingRestart,
        COMPONENT_RESTART,
    ),
    file_artifact(
        "sequoiadb-catalog-config",
        DatabaseConfigProduct::SequoiaDb,
        DatabaseConfigComponent::SequoiaCatalog,
        DatabaseConfigDialect::KeyValue,
        DatabaseConfigSupportLevel::VisualSyntax,
        DatabaseConfigEditPolicy::LosslessLocalDraft,
        "sdb.conf",
        DatabaseConfigValidator::VendorTool,
        VENDOR_FILE_VALIDATION,
        DatabaseConfigActivation::RollingRestart,
        COMPONENT_RESTART,
    ),
    file_artifact(
        "sequoiadb-data-config",
        DatabaseConfigProduct::SequoiaDb,
        DatabaseConfigComponent::SequoiaData,
        DatabaseConfigDialect::KeyValue,
        DatabaseConfigSupportLevel::VisualSyntax,
        DatabaseConfigEditPolicy::LosslessLocalDraft,
        "sdb.conf",
        DatabaseConfigValidator::VendorTool,
        VENDOR_FILE_VALIDATION,
        DatabaseConfigActivation::RollingRestart,
        COMPONENT_RESTART,
    ),
    structured_vendor_file(
        "sequoiadb-quick-deploy-cluster",
        DatabaseConfigProduct::SequoiaDb,
        DatabaseConfigComponent::Deployment,
        DatabaseConfigDialect::SequoiaQuickDeployClusterCsv,
        Some("sequoiadb.conf"),
    ),
    structured_vendor_file(
        "sequoiadb-quick-deploy-mysql",
        DatabaseConfigProduct::SequoiaDb,
        DatabaseConfigComponent::SequoiaSqlMySql,
        DatabaseConfigDialect::SequoiaQuickDeploySqlInstanceCsv,
        Some("mysql.conf"),
    ),
    structured_vendor_file(
        "sequoiadb-quick-deploy-mariadb",
        DatabaseConfigProduct::SequoiaDb,
        DatabaseConfigComponent::SequoiaSqlMariaDb,
        DatabaseConfigDialect::SequoiaQuickDeploySqlInstanceCsv,
        Some("mariadb.conf"),
    ),
    structured_vendor_file(
        "sequoiadb-quick-deploy-postgresql",
        DatabaseConfigProduct::SequoiaDb,
        DatabaseConfigComponent::SequoiaSqlPostgreSql,
        DatabaseConfigDialect::SequoiaQuickDeploySqlInstanceCsv,
        Some("postgresql.conf"),
    ),
    mysql_file(
        "greatsql-option-file",
        DatabaseConfigProduct::GreatSql,
        "my.cnf",
    ),
    mysql_runtime(
        "greatsql-runtime-parameters",
        DatabaseConfigProduct::GreatSql,
        DatabaseConfigComponent::RuntimeParameters,
    ),
    generated_artifact(
        "greatsql-persisted-variables",
        DatabaseConfigProduct::GreatSql,
        DatabaseConfigComponent::Persistence,
        DatabaseConfigDialect::MySqlPersistedVariablesJson,
        "mysqld-auto.cnf",
        "mysqld-auto.cnf 由 SET PERSIST/PERSIST_ONLY 管理，禁止绕过服务端直接编辑。",
    ),
    mysql_file(
        "greatdb-option-file",
        DatabaseConfigProduct::GreatDb,
        "my.cnf",
    ),
    mysql_runtime(
        "greatdb-runtime-parameters",
        DatabaseConfigProduct::GreatDb,
        DatabaseConfigComponent::RuntimeParameters,
    ),
    mysql_file("kundb-option-file", DatabaseConfigProduct::KunDb, "my.cnf"),
    mysql_runtime(
        "kundb-runtime-parameters",
        DatabaseConfigProduct::KunDb,
        DatabaseConfigComponent::RuntimeParameters,
    ),
    // PostgreSQL-compatible domestic products retain all three standard files.
    postgres_file(
        "antdb-main",
        DatabaseConfigProduct::AntDb,
        DatabaseConfigComponent::Server,
        DatabaseConfigDialect::PostgreSqlConf,
        "postgresql.conf",
    ),
    postgres_file(
        "antdb-hba",
        DatabaseConfigProduct::AntDb,
        DatabaseConfigComponent::AccessControl,
        DatabaseConfigDialect::PgHbaConf,
        "pg_hba.conf",
    ),
    postgres_file(
        "antdb-ident",
        DatabaseConfigProduct::AntDb,
        DatabaseConfigComponent::IdentityMapping,
        DatabaseConfigDialect::PgIdentConf,
        "pg_ident.conf",
    ),
    postgres_runtime("antdb-runtime-parameters", DatabaseConfigProduct::AntDb),
    postgres_file(
        "highgo-main",
        DatabaseConfigProduct::HighGo,
        DatabaseConfigComponent::Server,
        DatabaseConfigDialect::PostgreSqlConf,
        "postgresql.conf",
    ),
    postgres_file(
        "highgo-hba",
        DatabaseConfigProduct::HighGo,
        DatabaseConfigComponent::AccessControl,
        DatabaseConfigDialect::PgHbaConf,
        "pg_hba.conf",
    ),
    postgres_file(
        "highgo-ident",
        DatabaseConfigProduct::HighGo,
        DatabaseConfigComponent::IdentityMapping,
        DatabaseConfigDialect::PgIdentConf,
        "pg_ident.conf",
    ),
    postgres_runtime("highgo-runtime-parameters", DatabaseConfigProduct::HighGo),
    generated_artifact(
        "highgo-auto-conf",
        DatabaseConfigProduct::HighGo,
        DatabaseConfigComponent::Persistence,
        DatabaseConfigDialect::PostgreSqlAutoConf,
        "postgresql.auto.conf",
        "postgresql.auto.conf 由 ALTER SYSTEM 自动维护，直接编辑可能与运行时变更冲突。",
    ),
    structured_vendor_file(
        "highgo-ha-config",
        DatabaseConfigProduct::HighGo,
        DatabaseConfigComponent::Cluster,
        DatabaseConfigDialect::Yaml,
        Some("hghac.yml"),
    ),
    postgres_file(
        "opentenbase-main",
        DatabaseConfigProduct::OpenTenBase,
        DatabaseConfigComponent::Server,
        DatabaseConfigDialect::PostgreSqlConf,
        "postgresql.conf",
    ),
    postgres_file(
        "opentenbase-hba",
        DatabaseConfigProduct::OpenTenBase,
        DatabaseConfigComponent::AccessControl,
        DatabaseConfigDialect::PgHbaConf,
        "pg_hba.conf",
    ),
    postgres_file(
        "opentenbase-ident",
        DatabaseConfigProduct::OpenTenBase,
        DatabaseConfigComponent::IdentityMapping,
        DatabaseConfigDialect::PgIdentConf,
        "pg_ident.conf",
    ),
    postgres_runtime(
        "opentenbase-runtime-parameters",
        DatabaseConfigProduct::OpenTenBase,
    ),
    file_artifact(
        "yashandb-yasdb-ini",
        DatabaseConfigProduct::Yashan,
        DatabaseConfigComponent::Server,
        DatabaseConfigDialect::KeyValue,
        DatabaseConfigSupportLevel::VisualSyntax,
        DatabaseConfigEditPolicy::VendorSchemaRequired,
        "yasdb.ini",
        DatabaseConfigValidator::VendorSchemaRequired,
        "YashanDB 23.5 将 yasdb.ini 定义为 KEY=VALUE 参数文件并禁止直接编辑；没有匹配版本的厂商 schema 与变更过程时仅可只读检查源文本。",
        DatabaseConfigActivation::VendorProcedure,
        "不得直接写入 yasdb.ini；参数变更必须交给匹配版本的厂商过程，并独立回读实际生效值。",
    ),
    generated_artifact(
        "yashandb-spfile",
        DatabaseConfigProduct::Yashan,
        DatabaseConfigComponent::Persistence,
        DatabaseConfigDialect::VendorBinary,
        "yasdb.spfile",
        "yasdb.spfile 是由 ALTER SYSTEM 管理的二进制参数文件，不得作为文本读取、生成或直接编辑。",
    ),
    generated_artifact(
        "yashandb-password-file",
        DatabaseConfigProduct::Yashan,
        DatabaseConfigComponent::PasswordStore,
        DatabaseConfigDialect::VendorBinary,
        "yasdb.pwd",
        "yasdb.pwd 是由 yaspwd 管理的加密口令文件，不得作为文本读取、生成或直接编辑。",
    ),
    structured_vendor_file(
        "yashandb-yasboot-hosts",
        DatabaseConfigProduct::Yashan,
        DatabaseConfigComponent::Deployment,
        DatabaseConfigDialect::Toml,
        Some("hosts.toml"),
    ),
    structured_vendor_file(
        "yashandb-yasboot-cluster",
        DatabaseConfigProduct::Yashan,
        DatabaseConfigComponent::Cluster,
        DatabaseConfigDialect::Toml,
        None,
    ),
];

pub const MAX_DATABASE_CONFIG_PRODUCTS: usize = 64;
pub const MAX_DATABASE_CONFIG_ARTIFACTS: usize = 256;

const _: () = assert!(DATABASE_CONFIG_PRODUCTS.len() <= MAX_DATABASE_CONFIG_PRODUCTS);
const _: () = assert!(DATABASE_CONFIG_ARTIFACTS.len() <= MAX_DATABASE_CONFIG_ARTIFACTS);

pub fn artifacts_for(
    product: DatabaseConfigProduct,
) -> impl Iterator<Item = &'static DatabaseConfigArtifactDefinition> {
    DATABASE_CONFIG_ARTIFACTS
        .iter()
        .filter(move |artifact| artifact.product == product)
}

pub fn artifact_by_key(key: &str) -> Option<&'static DatabaseConfigArtifactDefinition> {
    DATABASE_CONFIG_ARTIFACTS
        .iter()
        .find(|artifact| artifact.key == key)
}

/// Returns a bounded, reviewed starting point for a lossless local draft.
///
/// A starter is only syntax input for the local visual parser. It does not
/// authorize target validation, generation, application, or deployment. Rows
/// without local-draft authority fail closed to an empty source. Compatible
/// products without a reviewed product-level starter receive comment-only
/// import guidance, never defaults copied from the upstream dialect.
pub fn database_starter_contents(artifact: &DatabaseConfigArtifactDefinition) -> &'static str {
    if !artifact.allows_lossless_local_draft() {
        return "";
    }

    match (artifact.product, artifact.dialect) {
        (
            DatabaseConfigProduct::MySql | DatabaseConfigProduct::MariaDb,
            DatabaseConfigDialect::MySqlOptionFile,
        ) => {
            "# LovelyHawk MySQL/MariaDB 应急响应比赛起始配置；部署前必须按所选产品与精确版本使用官方校验器复核。\n[mysqld]\nbind-address = 127.0.0.1\nport = 3306\nlocal-infile = 0\nskip-symbolic-links\n\n[client]\nport = 3306\n"
        }
        (DatabaseConfigProduct::PostgreSql, DatabaseConfigDialect::PostgreSqlConf) => {
            "# LovelyHawk 应急响应比赛起始配置；部署前以目标产品/版本校验。\nlisten_addresses = 'localhost'\nport = 5432\npassword_encryption = 'scram-sha-256'\nlogging_collector = on\nlog_connections = on\nlog_disconnections = on\n"
        }
        (DatabaseConfigProduct::PostgreSql, DatabaseConfigDialect::PgHbaConf) => {
            "# TYPE  DATABASE  USER  ADDRESS  METHOD\nlocal   all       all            peer\nhost    all       all   127.0.0.1/32   scram-sha-256\nhost    all       all   ::1/128        scram-sha-256\n"
        }
        (DatabaseConfigProduct::PostgreSql, DatabaseConfigDialect::PgIdentConf) => {
            "# MAPNAME  SYSTEM-USERNAME  DATABASE-USERNAME\n"
        }
        (_, DatabaseConfigDialect::MySqlOptionFile) => {
            "# 当前工件没有经审查的产品级 starter；请导入目标实例原文件，本页不会依据 MySQL 兼容方言猜测参数或端口。\n"
        }
        (
            _,
            DatabaseConfigDialect::PostgreSqlConf
            | DatabaseConfigDialect::PgHbaConf
            | DatabaseConfigDialect::PgIdentConf,
        ) => {
            "# 当前工件没有经审查的产品级 starter；请导入目标实例原文件，本页不会依据 PostgreSQL 兼容方言猜测参数或端口。\n"
        }
        (DatabaseConfigProduct::Dm, DatabaseConfigDialect::Ini) if artifact.key == "dm-main" => {
            "# LovelyHawk DM 本地 inspect 起始配置；仅供检查，参数动态级别与范围必须由目标 DM 精确版本回读，不得据此直接应用。\nINSTANCE_NAME = DMSERVER\nPORT_NUM = 5236\n"
        }
        (_, DatabaseConfigDialect::Ini) => {
            "# LovelyHawk INI 起始配置；按当前组件和目标版本添加 section/参数。\n"
        }
        (_, DatabaseConfigDialect::Toml) => {
            "# LovelyHawk TOML 起始配置；组件参数随版本变化，请导入目标机原文件后编辑。\n"
        }
        (_, DatabaseConfigDialect::JavaProperties) => {
            "# LovelyHawk Java properties 起始配置；请导入匹配组件版本的原文件。\n"
        }
        (_, DatabaseConfigDialect::KeyValue | DatabaseConfigDialect::VendorText) => {
            "# LovelyHawk 起始配置；请导入目标实例原文件以保留厂商扩展。\n"
        }
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::line_config_visual::{
        LineConfigDialect, LineConfigNodeKind, LineConfigVisualDocument,
    };

    #[test]
    fn read_only_status_distinguishes_generated_and_vendor_schema_artifacts() {
        let generated = artifact_by_key("mysql-persisted-variables")
            .expect("registered generated MySQL artifact");
        let generated_status = generated
            .read_only_status()
            .expect("generated artifacts are read-only");
        assert_eq!(
            generated_status.reason,
            DatabaseConfigReadOnlyReason::GeneratedArtifact
        );
        assert!(generated_status.notice.contains("只读展示"));
        assert!(generated_status.notice.contains("生成"));
        assert!(!generated.allows_lossless_local_draft());

        let vendor =
            artifact_by_key("opengauss-om-cluster-xml").expect("registered vendor-schema artifact");
        let vendor_status = vendor
            .read_only_status()
            .expect("vendor-schema artifacts are read-only");
        assert_eq!(
            vendor_status.reason,
            DatabaseConfigReadOnlyReason::VendorSchemaRequired
        );
        assert!(vendor_status.notice.contains("只读展示"));
        assert!(vendor_status.notice.contains("schema"));
        assert!(vendor_status.notice.contains("版本"));
        assert!(!vendor.allows_lossless_local_draft());

        assert_eq!(
            artifact_by_key("mysql-option-file")
                .expect("registered mutable local draft")
                .read_only_status(),
            None
        );
    }

    #[test]
    fn gbase_8s_known_text_grammars_are_readable_byte_exact_and_read_only() {
        for (key, source) in [
            ("gbase-8s-onconfig", "ROOTNAME rootdbs\r\nSERVERNUM 0\r\n"),
            (
                "gbase-8s-sqlhosts",
                "# dbserver nettype hostname service options\r\ngbaseserver onsoctcp 192.0.2.10 9088 g=g_cluster_1\r\n",
            ),
        ] {
            let artifact = artifact_by_key(key).expect("registered GBase 8s artifact");
            assert_eq!(artifact.product, DatabaseConfigProduct::GBase8s, "{key}");
            assert_eq!(artifact.dialect, DatabaseConfigDialect::VendorText, "{key}");
            assert_eq!(
                artifact.support,
                DatabaseConfigSupportLevel::VisualSyntax,
                "{key}"
            );
            assert!(artifact.is_file_visual_readable(), "{key}");
            assert!(!artifact.allows_lossless_local_draft(), "{key}");

            let document = LineConfigVisualDocument::parse(LineConfigDialect::Whitespace, source)
                .expect("reviewed GBase 8s text grammar");
            assert!(document.is_structured(), "{key}");
            assert!(!document.rows().is_empty(), "{key}");
            assert_eq!(document.raw_bytes(), source.as_bytes(), "{key}");
            assert_eq!(document.output().bytes(), source.as_bytes(), "{key}");
        }

        let first = artifacts_for(DatabaseConfigProduct::GBase8s)
            .find(|artifact| {
                artifact.support == DatabaseConfigSupportLevel::VisualSyntax
                    && artifact.dialect == DatabaseConfigDialect::VendorText
            })
            .map(|artifact| artifact.key);
        assert_eq!(first, Some("gbase-8s-onconfig"));
    }

    #[test]
    fn gbase_8s_visual_text_authkey_is_redacted_and_blocks_whole_document_copy() {
        const SOURCE: &str = "AUTHKEY K9z7Q2\n";
        const SENTINEL: &str = "K9z7Q2";

        for key in ["gbase-8s-onconfig", "gbase-8s-sqlhosts"] {
            let artifact = artifact_by_key(key).expect("registered GBase 8s visual text artifact");
            assert_eq!(artifact.product, DatabaseConfigProduct::GBase8s, "{key}");
            assert_eq!(artifact.dialect, DatabaseConfigDialect::VendorText, "{key}");
            assert_eq!(
                artifact.support,
                DatabaseConfigSupportLevel::VisualSyntax,
                "{key}"
            );
            assert!(artifact.has_source_backed_visual_parser(), "{key}");
            assert_eq!(
                artifact.local_draft_authority(),
                DatabaseConfigLocalDraftAuthority::ReadOnly,
                "{key}"
            );
            assert_eq!(
                artifact
                    .read_only_status()
                    .expect("GBase 8s text artifact remains read-only")
                    .authority,
                DatabaseConfigLocalDraftAuthority::ReadOnly,
                "{key}"
            );

            let document = LineConfigVisualDocument::parse(LineConfigDialect::Whitespace, SOURCE)
                .expect("GBase 8s AUTHKEY fixture");
            assert!(document.is_structured(), "{key}");
            assert!(document.contains_sensitive_values(), "{key}");
            assert_eq!(document.raw_bytes(), SOURCE.as_bytes(), "{key}");
            assert_eq!(document.output().bytes(), SOURCE.as_bytes(), "{key}");

            let rows = document.rows();
            let authkey = rows
                .iter()
                .find(|row| row.name() == Some("AUTHKEY"))
                .unwrap_or_else(|| panic!("{key} lost the AUTHKEY row"));
            assert!(authkey.sensitive(), "{key}");
            assert_eq!(authkey.value(), None, "{key}");
            assert_eq!(authkey.preview(), "[sensitive value redacted]", "{key}");
            assert!(!authkey.editable(), "{key}");
            assert!(
                rows.iter().all(|row| {
                    row.value() != Some(SENTINEL) && !row.preview().contains(SENTINEL)
                }),
                "{key} exposed the AUTHKEY value through a visual row"
            );
            for public_debug in [
                format!("{artifact:?}"),
                format!("{document:?}"),
                format!("{:?}", document.output()),
                format!("{rows:?}"),
            ] {
                assert!(!public_debug.contains(SENTINEL), "{key}");
            }
        }
    }

    #[test]
    fn supported_database_starters_are_core_owned_and_structured() {
        for (key, database_dialect, visual_dialect) in [
            (
                "mysql-option-file",
                DatabaseConfigDialect::MySqlOptionFile,
                LineConfigDialect::MySqlOption,
            ),
            (
                "postgresql-main",
                DatabaseConfigDialect::PostgreSqlConf,
                LineConfigDialect::PostgresConf,
            ),
            (
                "postgresql-hba",
                DatabaseConfigDialect::PgHbaConf,
                LineConfigDialect::PgHba,
            ),
            (
                "dm-main",
                DatabaseConfigDialect::Ini,
                LineConfigDialect::Ini,
            ),
            (
                "tidb-server-toml",
                DatabaseConfigDialect::Toml,
                LineConfigDialect::Toml,
            ),
            (
                "sequoiadb-standalone-config",
                DatabaseConfigDialect::KeyValue,
                LineConfigDialect::FlatKeyValue,
            ),
        ] {
            let artifact = artifact_by_key(key).expect("registered database starter artifact");
            assert_eq!(artifact.key, key);
            assert_eq!(artifact.dialect, database_dialect, "{key}");
            assert!(artifact.has_source_backed_visual_parser(), "{key}");
            assert!(artifact.allows_lossless_local_draft(), "{key}");

            let source = database_starter_contents(artifact);
            assert!(!source.is_empty(), "{key} has no reviewed starter");
            let document = LineConfigVisualDocument::parse(visual_dialect, source)
                .expect("reviewed database starter must parse");
            assert!(document.is_structured(), "starter {key} became opaque");
            assert!(!document.rows().is_empty(), "starter {key} has no rows");
            assert_eq!(document.raw_bytes(), source.as_bytes(), "{key}");
            assert_eq!(document.output().bytes(), source.as_bytes(), "{key}");
        }

        assert_eq!(
            database_starter_contents(
                artifact_by_key("mysql-server-uuid").expect("registered read-only artifact")
            ),
            ""
        );
    }

    #[test]
    fn compatible_and_domestic_starters_do_not_guess_upstream_defaults() {
        for key in ["kingbase-es-main", "gbase-8c-main", "tidb-server-toml"] {
            let artifact = artifact_by_key(key).expect("registered compatible database artifact");
            assert!(artifact.allows_lossless_local_draft(), "{key}");

            let starter = database_starter_contents(artifact);
            assert!(
                starter.contains("导入"),
                "{key} must request an original file"
            );
            assert!(
                starter
                    .lines()
                    .all(|line| line.is_empty() || line.starts_with('#')),
                "{key} starter guidance must remain comment-only"
            );
            for guessed_default in [
                "port = 5432",
                "port = 3306",
                "PORT_NUM = 5432",
                "password_encryption",
                "scram-sha-256",
                "bind-address",
            ] {
                assert!(
                    !starter.contains(guessed_default),
                    "{key} inherited guessed default {guessed_default}"
                );
            }
        }

        assert!(
            database_starter_contents(
                artifact_by_key("mysql-option-file").expect("reviewed MySQL starter")
            )
            .contains("3306")
        );
        assert!(
            database_starter_contents(
                artifact_by_key("postgresql-main").expect("reviewed PostgreSQL starter")
            )
            .contains("5432")
        );
        assert!(
            database_starter_contents(artifact_by_key("dm-main").expect("reviewed DM starter"))
                .contains("inspect")
        );
        assert_eq!(
            database_starter_contents(
                artifact_by_key("kingbase-es-auto-conf").expect("generated KingbaseES artifact")
            ),
            ""
        );
    }

    #[test]
    fn mysql_auto_cnf_core_fixture_is_byte_exact_structured_and_non_secret() {
        const SOURCE: &str = "[auto]\nserver-uuid=8a94f357-aab4-11df-86ab-c80aa9429562\n";

        let artifact = artifact_by_key("mysql-server-uuid").expect("registered auto.cnf artifact");
        assert_eq!(artifact.dialect, DatabaseConfigDialect::MySqlOptionFile);
        assert!(artifact.has_source_backed_visual_parser());
        assert!(!artifact.allows_lossless_local_draft());
        assert_eq!(database_starter_contents(artifact), "");

        let document = LineConfigVisualDocument::parse(LineConfigDialect::MySqlOption, SOURCE)
            .expect("representative auto.cnf fixture");
        assert!(document.is_structured());
        assert_eq!(document.raw_bytes(), SOURCE.as_bytes());
        assert_eq!(document.output().bytes(), SOURCE.as_bytes());
        assert!(!document.contains_sensitive_values());
        let rows = document.rows();
        assert!(rows.iter().all(|row| !row.sensitive()));
        assert!(rows.iter().any(|row| {
            row.kind() == LineConfigNodeKind::Section && row.name() == Some("auto")
        }));
        let identity = rows
            .iter()
            .find(|row| row.name() == Some("server-uuid"))
            .expect("auto.cnf server UUID row");
        assert_eq!(identity.kind(), LineConfigNodeKind::Entry);
        assert_eq!(
            identity.value(),
            Some("8a94f357-aab4-11df-86ab-c80aa9429562")
        );

        let secret = LineConfigVisualDocument::parse(
            LineConfigDialect::MySqlOption,
            "[auto]\npassword=NeverShow\n",
        )
        .expect("MySQL option secret boundary fixture");
        let secret_rows = secret.rows();
        let password = secret_rows
            .iter()
            .find(|row| row.name() == Some("password"))
            .expect("password row");
        assert!(secret.contains_sensitive_values());
        assert!(password.sensitive());
        assert_eq!(password.value(), None);
        assert!(!format!("{secret:?}{secret_rows:?}").contains("NeverShow"));
    }

    #[test]
    fn tidb_auxiliary_toml_core_fixtures_are_byte_exact_structured_and_non_secret() {
        for (key, component, default_file_name, source) in [
            (
                "tidb-tiflash-toml",
                DatabaseConfigComponent::TiFlash,
                "tiflash.toml",
                "[flash]\r\nservice_addr = \"127.0.0.1:3930\"",
            ),
            (
                "tidb-tiflash-learner-toml",
                DatabaseConfigComponent::TiFlashLearner,
                "tiflash-learner.toml",
                "[raftstore]\r\nstore-pool-size = 2",
            ),
            (
                "tidb-tiproxy-toml",
                DatabaseConfigComponent::TiProxy,
                "tiproxy.toml",
                "[proxy]\r\naddr = \"0.0.0.0:6000\"",
            ),
            (
                "tidb-ticdc-toml",
                DatabaseConfigComponent::TiCdc,
                "ticdc.toml",
                "[log]\r\nlevel = \"info\"",
            ),
            (
                "tidb-ticdc-changefeed-toml",
                DatabaseConfigComponent::TiCdcChangefeed,
                "changefeed.toml",
                "case-sensitive = false\r\nforce-replicate = false",
            ),
            (
                "tidb-lightning-toml",
                DatabaseConfigComponent::TiDbLightning,
                "tidb-lightning.toml",
                "[lightning]\r\nlevel = \"info\"",
            ),
        ] {
            let artifact = artifact_by_key(key).expect("registered TiDB auxiliary artifact");
            assert_eq!(artifact.product, DatabaseConfigProduct::TiDb, "{key}");
            assert_eq!(artifact.component, component, "{key}");
            assert_eq!(artifact.dialect, DatabaseConfigDialect::Toml, "{key}");
            assert_eq!(artifact.default_file_name, Some(default_file_name), "{key}");
            assert!(artifact.has_source_backed_visual_parser(), "{key}");
            assert!(!artifact.allows_lossless_local_draft(), "{key}");
            assert_eq!(database_starter_contents(artifact), "", "{key}");

            let document = LineConfigVisualDocument::parse(LineConfigDialect::Toml, source)
                .expect("representative TiDB auxiliary TOML fixture");
            assert!(document.is_structured(), "{key}");
            assert!(!document.rows().is_empty(), "{key}");
            assert_eq!(document.raw_bytes(), source.as_bytes(), "{key}");
            assert_eq!(document.output().bytes(), source.as_bytes(), "{key}");
            assert!(!document.contains_sensitive_values(), "{key}");
            assert!(document.rows().iter().all(|row| !row.sensitive()), "{key}");
        }

        let secret = LineConfigVisualDocument::parse(
            LineConfigDialect::Toml,
            "[security]\npassword = \"NeverShow\"",
        )
        .expect("TOML secret boundary fixture");
        let secret_rows = secret.rows();
        let password = secret_rows
            .iter()
            .find(|row| row.name() == Some("password"))
            .expect("password row");
        assert!(secret.contains_sensitive_values());
        assert!(password.sensitive());
        assert_eq!(password.value(), None);
        assert!(!format!("{secret:?}{secret_rows:?}").contains("NeverShow"));
    }

    #[test]
    fn yashandb_23_5_yasdb_ini_core_fixture_is_byte_exact_structured_and_non_secret() {
        const SOURCE: &str = "LISTENER_ADDR=127.0.0.1\r\nMAX_SESSIONS=1024\r\nUNKNOWN_23_5_KEY=preserve-this-byte-exact";

        let artifact =
            artifact_by_key("yashandb-yasdb-ini").expect("registered YashanDB yasdb.ini artifact");
        assert_eq!(artifact.product, DatabaseConfigProduct::Yashan);
        assert_eq!(artifact.dialect, DatabaseConfigDialect::KeyValue);
        assert_eq!(artifact.default_file_name, Some("yasdb.ini"));
        assert!(artifact.has_source_backed_visual_parser());
        assert!(!artifact.allows_lossless_local_draft());
        assert_eq!(database_starter_contents(artifact), "");

        let document = LineConfigVisualDocument::parse(LineConfigDialect::FlatKeyValue, SOURCE)
            .expect("representative YashanDB yasdb.ini fixture");
        assert!(document.is_structured());
        assert_eq!(document.raw_bytes(), SOURCE.as_bytes());
        assert_eq!(document.output().bytes(), SOURCE.as_bytes());
        assert!(!document.contains_sensitive_values());
        let rows = document.rows();
        assert!(rows.iter().all(|row| !row.sensitive()));
        for (key, value) in [
            ("LISTENER_ADDR", "127.0.0.1"),
            ("MAX_SESSIONS", "1024"),
            ("UNKNOWN_23_5_KEY", "preserve-this-byte-exact"),
        ] {
            assert_eq!(
                rows.iter()
                    .find(|row| row.name() == Some(key))
                    .and_then(|row| row.value()),
                Some(value),
                "{key}"
            );
        }

        let secret =
            LineConfigVisualDocument::parse(LineConfigDialect::FlatKeyValue, "PASSWORD=NeverShow")
                .expect("flat key/value secret boundary fixture");
        let secret_rows = secret.rows();
        let password = secret_rows
            .iter()
            .find(|row| row.name() == Some("PASSWORD"))
            .expect("password row");
        assert!(secret.contains_sensitive_values());
        assert!(password.sensitive());
        assert_eq!(password.value(), None);
        assert!(!format!("{secret:?}{secret_rows:?}").contains("NeverShow"));
    }

    #[test]
    fn only_evidence_blocked_shentong_products_have_no_artifacts() {
        let evidence_blocked = BTreeSet::from([
            DatabaseConfigProduct::ShenTongNative,
            DatabaseConfigProduct::ShenTongMpp,
            DatabaseConfigProduct::ShenTongOpenGauss,
        ]);

        for product in DatabaseConfigProduct::ALL {
            assert_eq!(
                artifacts_for(product).next().is_none(),
                evidence_blocked.contains(&product),
                "unexpected artifact coverage for {product:?}"
            );
        }
    }

    #[test]
    fn product_and_artifact_keys_are_unique_and_non_empty() {
        let mut product_keys = BTreeSet::new();
        let mut products = BTreeSet::new();
        for product in DATABASE_CONFIG_PRODUCTS {
            assert!(!product.key.is_empty());
            assert!(
                product_keys.insert(product.key),
                "duplicate {}",
                product.key
            );
            assert!(
                products.insert(product.product),
                "duplicate {:?}",
                product.product
            );
        }
        assert_eq!(products, DatabaseConfigProduct::ALL.into_iter().collect());

        let mut artifact_keys = BTreeSet::new();
        let mut named_artifact_identities = BTreeSet::new();
        for artifact in DATABASE_CONFIG_ARTIFACTS {
            assert!(!artifact.key.is_empty());
            assert!(
                artifact_keys.insert(artifact.key),
                "duplicate {}",
                artifact.key
            );
            if let Some(default_file_name) = artifact.default_file_name {
                assert!(
                    named_artifact_identities.insert((
                        artifact.product,
                        artifact.component,
                        default_file_name,
                    )),
                    "duplicate named artifact identity for {}",
                    artifact.key
                );
            }
        }
    }

    #[test]
    fn generated_and_binary_artifacts_never_allow_lossless_local_drafts() {
        for artifact in DATABASE_CONFIG_ARTIFACTS {
            if artifact.surface == DatabaseConfigSurface::GeneratedReadOnly
                || artifact.dialect.is_generated()
                || artifact.dialect.is_binary()
            {
                assert!(
                    !artifact.allows_lossless_local_draft(),
                    "{} must not allow a local draft",
                    artifact.key
                );
            }
        }

        let mysql_auto = artifact_by_key("mysql-persisted-variables").unwrap();
        assert_eq!(mysql_auto.default_file_name, Some("mysqld-auto.cnf"));
        assert_eq!(mysql_auto.surface, DatabaseConfigSurface::GeneratedReadOnly);
        assert!(!mysql_auto.allows_lossless_local_draft());
    }

    #[test]
    fn artifact_policy_only_authorizes_lossless_local_drafts() {
        for artifact in DATABASE_CONFIG_ARTIFACTS {
            let expected = artifact.edit_policy == DatabaseConfigEditPolicy::LosslessLocalDraft
                && artifact.surface == DatabaseConfigSurface::File
                && !artifact.dialect.is_generated();
            assert_eq!(
                artifact.allows_lossless_local_draft(),
                expected,
                "{} local draft authority drifted",
                artifact.key
            );
        }

        let locally_mutable = artifact_by_key("mysql-option-file").unwrap();
        assert_eq!(
            locally_mutable.edit_policy,
            DatabaseConfigEditPolicy::LosslessLocalDraft
        );
        assert!(locally_mutable.allows_lossless_local_draft());
        assert_eq!(
            locally_mutable.validator,
            DatabaseConfigValidator::SyntaxOnly
        );
        assert!(locally_mutable.validation_note.contains("8.0.16"));

        let mariadb = artifact_by_key("mariadb-option-file").unwrap();
        assert_eq!(mariadb.validator, DatabaseConfigValidator::SyntaxOnly);
        assert!(mariadb.validation_note.contains("13.0"));

        for key in [
            "opengauss-om-cluster-xml",
            "mysql-persisted-variables",
            "mysql-server-uuid",
        ] {
            assert!(!artifact_by_key(key).unwrap().allows_lossless_local_draft());
        }
    }

    #[test]
    fn mysql_and_mariadb_p0_c_inventory_rows_are_typed_and_read_only() {
        assert_eq!(
            DATABASE_CONFIG_ARTIFACTS
                .iter()
                .filter(|artifact| artifact.key == "mysql-server-uuid")
                .count(),
            1,
            "mysql-server-uuid must remain unique"
        );
        let server_uuid = artifact_by_key("mysql-server-uuid").unwrap();
        assert_eq!(server_uuid.product, DatabaseConfigProduct::MySql);
        assert_eq!(
            server_uuid.component,
            DatabaseConfigComponent::ReplicationIdentity
        );
        assert_eq!(
            server_uuid.surface,
            DatabaseConfigSurface::GeneratedReadOnly
        );
        assert_eq!(server_uuid.dialect, DatabaseConfigDialect::MySqlOptionFile);
        assert_eq!(
            server_uuid.support,
            DatabaseConfigSupportLevel::ReadOnlyDiscovery
        );
        assert_eq!(server_uuid.edit_policy, DatabaseConfigEditPolicy::ReadOnly);
        assert_eq!(server_uuid.default_file_name, Some("auto.cnf"));
        assert_eq!(
            server_uuid.validator,
            DatabaseConfigValidator::NotApplicable
        );
        assert_eq!(
            server_uuid.activation,
            DatabaseConfigActivation::NotApplicable
        );
        for expected_note in [
            "服务端自动生成",
            "[auto]",
            "server_uuid",
            "禁止写入或修改",
            "@@server_uuid",
        ] {
            assert!(
                server_uuid.validation_note.contains(expected_note),
                "auto.cnf note lost {expected_note}"
            );
        }
        assert!(server_uuid.has_source_backed_visual_parser());
        assert!(!server_uuid.allows_lossless_local_draft());

        for (key, product, component, inventory_source) in [
            (
                "mysql-plugin-registry",
                DatabaseConfigProduct::MySql,
                DatabaseConfigComponent::PluginRegistry,
                "INFORMATION_SCHEMA.PLUGINS",
            ),
            (
                "mysql-component-registry",
                DatabaseConfigProduct::MySql,
                DatabaseConfigComponent::ComponentRegistry,
                "mysql.component",
            ),
            (
                "mariadb-plugin-registry",
                DatabaseConfigProduct::MariaDb,
                DatabaseConfigComponent::PluginRegistry,
                "INFORMATION_SCHEMA.PLUGINS",
            ),
        ] {
            assert_eq!(
                DATABASE_CONFIG_ARTIFACTS
                    .iter()
                    .filter(|artifact| artifact.key == key)
                    .count(),
                1,
                "{key} must remain unique"
            );
            let artifact = artifact_by_key(key).unwrap();
            assert_eq!(artifact.product, product, "{key}");
            assert_eq!(artifact.component, component, "{key}");
            assert_eq!(artifact.surface, DatabaseConfigSurface::RuntimeSql, "{key}");
            assert_eq!(artifact.dialect, DatabaseConfigDialect::RuntimeSql, "{key}");
            assert_eq!(
                artifact.support,
                DatabaseConfigSupportLevel::RuntimeParameters,
                "{key}"
            );
            assert_eq!(
                artifact.edit_policy,
                DatabaseConfigEditPolicy::VendorSchemaRequired,
                "{key}"
            );
            assert_eq!(artifact.default_file_name, None, "{key}");
            assert_eq!(
                artifact.validator,
                DatabaseConfigValidator::RuntimeReadBack,
                "{key}"
            );
            assert_eq!(
                artifact.activation,
                DatabaseConfigActivation::RuntimeDependent,
                "{key}"
            );
            assert!(artifact.validation_note.contains(inventory_source), "{key}");
            assert!(artifact.activation_note.contains("只读 inventory"), "{key}");
            assert!(
                artifact.activation_note.contains("runtime provider 已接入"),
                "{key}"
            );
            assert!(!artifact.is_file_visual_readable(), "{key}");
            assert!(!artifact.has_source_backed_visual_parser(), "{key}");
            assert!(!artifact.allows_lossless_local_draft(), "{key}");
        }

        assert!(
            artifact_by_key("mysql-plugin-registry")
                .unwrap()
                .validation_note
                .contains("mysql.plugin")
        );
        assert!(
            artifact_by_key("mariadb-plugin-registry")
                .unwrap()
                .validation_note
                .contains("mysql.plugin")
        );
        assert!(
            artifact_by_key("mysql-component-registry")
                .unwrap()
                .validation_note
                .contains("component_urn")
        );
        assert!(
            artifacts_for(DatabaseConfigProduct::MariaDb).all(|artifact| {
                artifact.key != "mysql-server-uuid"
                    && artifact.component != DatabaseConfigComponent::ComponentRegistry
            })
        );
        assert!(artifact_by_key("mariadb-component-registry").is_none());
    }

    #[test]
    fn source_backed_visual_parser_capability_is_separate_from_raw_file_readability() {
        for key in [
            "gbase-8s-onconfig",
            "gbase-8s-sqlhosts",
            "goldendb-proxy-ini",
            "kingbase-es-replication",
            "mysql-server-uuid",
            "mysql-persisted-variables",
            "postgresql-auto-conf",
            "oceanbase-obd-registered-config",
            "gbase-8a-gnode-cluster-common",
        ] {
            let artifact = artifact_by_key(key).unwrap();
            assert!(artifact.is_file_visual_readable(), "{key}");
            assert!(artifact.has_source_backed_visual_parser(), "{key}");
        }

        for key in [
            "kingbase-es-repmgr",
            "dm-client-service",
            "opengauss-cm-server",
            "opengauss-cm-agent",
            "mogdb-cm-server",
            "mogdb-cm-agent",
            "gbase-8s-connection-manager-config",
            "gbase-8s-communication-support-config",
            "gbase-8s-shared-environment",
            "gbase-8s-user-environment",
            "gbase-8s-archecker-template",
            "gbase-8s-storage-manager-definitions",
            "gbase-8s-high-performance-loader-config",
            "gbase-8s-maxconnect-config",
        ] {
            let artifact = artifact_by_key(key).unwrap();
            assert!(artifact.is_file_visual_readable(), "{key}");
            assert!(!artifact.has_source_backed_visual_parser(), "{key}");
        }

        for key in [
            "mysql-runtime-variables",
            "tdsql-mysql-managed-parameter-api",
            "opengauss-cluster-static-config",
        ] {
            assert!(
                !artifact_by_key(key)
                    .unwrap()
                    .has_source_backed_visual_parser(),
                "{key}"
            );
        }

        let mut synthetic = *artifact_by_key("mysql-persisted-variables").unwrap();
        synthetic.dialect = DatabaseConfigDialect::VendorText;
        assert!(synthetic.is_file_visual_readable());
        assert!(!synthetic.has_source_backed_visual_parser());
        synthetic.dialect = DatabaseConfigDialect::VendorSchema;
        assert!(!synthetic.has_source_backed_visual_parser());
        synthetic.dialect = DatabaseConfigDialect::Json;
        assert!(synthetic.has_source_backed_visual_parser());
        synthetic.support = DatabaseConfigSupportLevel::VendorSchemaRequired;
        assert!(!synthetic.has_source_backed_visual_parser());
        synthetic.support = DatabaseConfigSupportLevel::RuntimeParameters;
        assert!(!synthetic.has_source_backed_visual_parser());
        synthetic.support = DatabaseConfigSupportLevel::CloudProviderSchema;
        assert!(!synthetic.has_source_backed_visual_parser());
    }

    #[test]
    fn local_visual_selection_hides_managed_runtime_cloud_binary_and_unparsed_artifacts() {
        for product in [
            DatabaseConfigProduct::TdsqlMysqlManaged,
            DatabaseConfigProduct::TdsqlPostgresqlManaged,
            DatabaseConfigProduct::PolarDbManagedMySql,
            DatabaseConfigProduct::PolarDbManagedPostgresql,
            DatabaseConfigProduct::PolarDbManagedOracle,
        ] {
            assert!(
                artifacts_for(product).all(|artifact| !artifact.has_source_backed_visual_parser()),
                "{product:?} entered the local visual selection"
            );
            assert!(
                !artifacts_for(product).any(|artifact| artifact.has_source_backed_visual_parser()),
                "{product:?} gained a first visual artifact"
            );
        }

        for key in [
            "mysql-runtime-variables",
            "postgresql-runtime-parameters",
            "tdsql-mysql-managed-parameter-api",
            "tdsql-postgresql-managed-parameter-api",
            "polardb-managed-mysql-parameter-api",
            "oceanbase-observer-binary",
            "opengauss-cluster-static-config",
            "goldendb-cluster-config",
            "yashandb-spfile",
            "yashandb-password-file",
            "kingbase-es-repmgr",
            "dm-client-service",
            "dm-dcr-config",
            "dm-dcr-node",
            "opengauss-cm-server",
            "opengauss-cm-agent",
            "mogdb-cm-server",
            "mogdb-cm-agent",
            "gbase-8s-connection-manager-config",
            "gbase-8s-communication-support-config",
            "gbase-8s-shared-environment",
            "gbase-8s-user-environment",
            "gbase-8s-archecker-template",
            "gbase-8s-storage-manager-definitions",
            "gbase-8s-high-performance-loader-config",
            "gbase-8s-maxconnect-config",
        ] {
            let artifact = artifact_by_key(key).expect("registered non-visual artifact");
            assert!(
                !artifact.has_source_backed_visual_parser(),
                "{key} entered the local visual selection"
            );
            assert_eq!(
                artifact.local_draft_authority(),
                DatabaseConfigLocalDraftAuthority::ReadOnly,
                "{key} gained local draft authority"
            );
            assert!(!artifact.allows_lossless_local_draft(), "{key}");
            assert_eq!(database_starter_contents(artifact), "", "{key}");
        }

        let reviewed = artifact_by_key("mysql-option-file").expect("reviewed visual artifact");
        assert!(reviewed.has_source_backed_visual_parser());
        assert!(reviewed.allows_lossless_local_draft());
    }

    #[test]
    fn unparsed_vendor_text_never_reaches_visual_rows_or_copy_boundaries() {
        const HOSTILE_PAYLOAD: &str =
            "<script>globalThis.vendorTextExecuted=true</script>\nAUTHKEY K9z7Q2\n";

        for key in [
            "kingbase-es-repmgr",
            "dm-client-service",
            "dm-dcr-config",
            "dm-dcr-node",
            "opengauss-cm-server",
            "opengauss-cm-agent",
            "mogdb-cm-server",
            "mogdb-cm-agent",
            "gbase-8s-connection-manager-config",
            "gbase-8s-communication-support-config",
            "gbase-8s-shared-environment",
            "gbase-8s-user-environment",
            "gbase-8s-archecker-template",
            "gbase-8s-storage-manager-definitions",
            "gbase-8s-high-performance-loader-config",
            "gbase-8s-maxconnect-config",
        ] {
            let artifact = artifact_by_key(key).expect("registered unparsed vendor artifact");
            assert!(artifact.is_file_visual_readable(), "{key}");
            assert!(
                !artifact.has_source_backed_visual_parser(),
                "{key} exposed visual rows"
            );
            assert_eq!(
                artifact.local_draft_authority(),
                DatabaseConfigLocalDraftAuthority::ReadOnly,
                "{key} exposed a copyable local draft"
            );
            assert_eq!(database_starter_contents(artifact), "", "{key}");

            let status = artifact
                .read_only_status()
                .expect("unparsed vendor artifact remains metadata-only");
            assert!(status.notice.len() <= 8_192, "{key}");
            let public_debug = format!("{artifact:?}{status:?}");
            for rejected in [HOSTILE_PAYLOAD, "vendorTextExecuted", "K9z7Q2"] {
                assert!(
                    !public_debug.contains(rejected),
                    "{key} leaked rejected vendor text"
                );
            }
        }
    }

    #[test]
    fn oceanbase_binary_state_and_read_only_runtime_inventory_are_separate() {
        let binary = artifact_by_key("oceanbase-observer-binary").unwrap();
        assert_eq!(binary.product, DatabaseConfigProduct::OceanBase);
        assert_eq!(binary.component, DatabaseConfigComponent::OceanBaseObserver);
        assert_eq!(binary.surface, DatabaseConfigSurface::GeneratedReadOnly);
        assert_eq!(binary.default_file_name, Some("observer.conf.bin"));
        assert_eq!(binary.dialect, DatabaseConfigDialect::VendorBinary);
        assert_eq!(binary.edit_policy, DatabaseConfigEditPolicy::ReadOnly);
        assert_eq!(binary.validator, DatabaseConfigValidator::NotApplicable);
        assert!(!binary.allows_lossless_local_draft());

        let expected_runtime = [
            (
                "oceanbase-observer-runtime",
                DatabaseConfigComponent::OceanBaseObserver,
                "仅执行只读 SHOW PARAMETERS 与 GV$OB_PARAMETERS inventory；同名参数的多节点、zone、server 与 scope 行必须分别保留，不得按参数名折叠。",
                "当前 P0 仅提供只读 inventory，不提供 mutation 或 activation，也不授权任何参数写入。",
            ),
            (
                "oceanbase-obproxy-runtime",
                DatabaseConfigComponent::ObProxy,
                "仅以 root@proxysys 执行只读 SHOW PROXYCONFIG inventory；必须匹配 OBProxy 版本目录并对 secret 与凭据值脱敏。",
                "当前 P0 仅提供只读 inventory，不提供 mutation 或 activation，也不授权写入代理配置。",
            ),
            (
                "oceanbase-tenant-variables",
                DatabaseConfigComponent::OceanBaseTenant,
                "仅支持 OceanBase CE 4.x MySQL mode tenant 的只读 SHOW GLOBAL VARIABLES 与 SHOW SESSION VARIABLES inventory；需要匹配版本的 vendor schema，不支持 Oracle mode。",
                "当前 P0 仅提供只读 inventory，不提供 mutation 或 activation；GLOBAL 变量语义仅面向新连接，现有 session 不变。",
            ),
            (
                "oceanbase-backup-archive-state",
                DatabaseConfigComponent::BackupRecovery,
                "仅只读盘点 DBA_OB_BACKUP_PARAMETER、DBA_OB_ARCHIVE_DEST 及相关 jobs/history 视图；URI 中的 credentials 与 secret 必须脱敏。",
                "当前 P0 仅提供只读 inventory，不提供 mutation 或 activation，也不授权启动、停止或恢复备份与归档作业。",
            ),
        ];
        let runtime_rows: Vec<_> = artifacts_for(DatabaseConfigProduct::OceanBase)
            .filter(|artifact| artifact.surface == DatabaseConfigSurface::RuntimeSql)
            .collect();
        assert_eq!(runtime_rows.len(), expected_runtime.len());

        for (key, component, validation_note, activation_note) in expected_runtime {
            let runtime = artifact_by_key(key).unwrap();
            assert_eq!(runtime.product, DatabaseConfigProduct::OceanBase, "{key}");
            assert_eq!(runtime.component, component, "{key}");
            assert_eq!(runtime.surface, DatabaseConfigSurface::RuntimeSql, "{key}");
            assert_eq!(runtime.dialect, DatabaseConfigDialect::RuntimeSql, "{key}");
            assert_eq!(
                runtime.edit_policy,
                DatabaseConfigEditPolicy::VendorSchemaRequired,
                "{key}"
            );
            assert_eq!(
                runtime.validator,
                DatabaseConfigValidator::RuntimeReadBack,
                "{key}"
            );
            assert_eq!(runtime.validation_note, validation_note, "{key}");
            assert_eq!(runtime.activation_note, activation_note, "{key}");
            assert!(!runtime.allows_lossless_local_draft(), "{key}");
            assert_ne!(runtime.key, binary.key, "{key}");
        }
    }

    #[test]
    fn gbase_and_tdsql_editions_are_not_collapsed() {
        let gbase_products: BTreeSet<_> = DATABASE_CONFIG_ARTIFACTS
            .iter()
            .filter_map(|artifact| {
                matches!(
                    artifact.product,
                    DatabaseConfigProduct::GBase8a
                        | DatabaseConfigProduct::GBase8s
                        | DatabaseConfigProduct::GBase8c
                )
                .then_some(artifact.product)
            })
            .collect();
        assert_eq!(
            gbase_products,
            BTreeSet::from([
                DatabaseConfigProduct::GBase8a,
                DatabaseConfigProduct::GBase8s,
                DatabaseConfigProduct::GBase8c,
            ])
        );

        assert!(
            artifacts_for(DatabaseConfigProduct::TdsqlMysqlPrivate)
                .any(|artifact| { artifact.dialect == DatabaseConfigDialect::MySqlOptionFile })
        );
        assert!(
            artifacts_for(DatabaseConfigProduct::TdsqlPostgresqlPrivate)
                .any(|artifact| artifact.dialect == DatabaseConfigDialect::PostgreSqlConf)
        );
        for managed in [
            DatabaseConfigProduct::TdsqlMysqlManaged,
            DatabaseConfigProduct::TdsqlPostgresqlManaged,
        ] {
            let artifacts: Vec<_> = artifacts_for(managed).collect();
            assert_eq!(artifacts.len(), 1);
            assert_eq!(artifacts[0].surface, DatabaseConfigSurface::CloudApi);
            assert!(!artifacts[0].allows_lossless_local_draft());
            assert_eq!(
                artifacts[0].edit_policy,
                DatabaseConfigEditPolicy::VendorSchemaRequired
            );
        }
        assert_ne!(
            DatabaseConfigProduct::TdsqlMysqlPrivate,
            DatabaseConfigProduct::TdsqlPostgresqlPrivate
        );

        let sqlhosts = artifact_by_key("gbase-8s-sqlhosts").unwrap();
        assert_eq!(sqlhosts.product, DatabaseConfigProduct::GBase8s);
        assert_eq!(sqlhosts.component, DatabaseConfigComponent::Client);
        assert_eq!(sqlhosts.dialect, DatabaseConfigDialect::VendorText);
        assert_eq!(sqlhosts.support, DatabaseConfigSupportLevel::VisualSyntax);
        assert_eq!(sqlhosts.default_file_name, Some("sqlhosts"));
        assert_eq!(
            sqlhosts.edit_policy,
            DatabaseConfigEditPolicy::VendorSchemaRequired
        );
        assert_eq!(
            sqlhosts.validator,
            DatabaseConfigValidator::VendorSchemaRequired
        );
        assert_eq!(
            sqlhosts.activation,
            DatabaseConfigActivation::VendorProcedure
        );
        assert!(sqlhosts.is_file_visual_readable());
        assert!(!sqlhosts.allows_lossless_local_draft());
    }

    #[test]
    fn gbase_8s_extended_files_keep_exact_owners_and_fail_closed_policies() {
        let expected = [
            (
                "gbase-8s-connection-manager-config",
                DatabaseConfigComponent::ConnectionManager,
                "cmsm.cfg",
                "$GBASEDBTDIR/etc/cmsm.cfg",
            ),
            (
                "gbase-8s-communication-support-config",
                DatabaseConfigComponent::CommunicationSupport,
                "concsm.cfg",
                "$GBASEDBTDIR/etc/concsm.cfg",
            ),
            (
                "gbase-8s-shared-environment",
                DatabaseConfigComponent::Environment,
                "gbasedbt.rc",
                "$GBASEDBTDIR/etc/gbasedbt.rc",
            ),
            (
                "gbase-8s-user-environment",
                DatabaseConfigComponent::Environment,
                ".gbasedbt",
                "~/.gbasedbt",
            ),
            (
                "gbase-8s-archecker-template",
                DatabaseConfigComponent::ArchiveChecker,
                "ac_config.std",
                "$GBASEDBTDIR/etc/ac_config.std",
            ),
            (
                "gbase-8s-storage-manager-definitions",
                DatabaseConfigComponent::StorageManager,
                "sm_versions",
                "$GBASEDBTDIR/etc/sm_versions",
            ),
            (
                "gbase-8s-high-performance-loader-config",
                DatabaseConfigComponent::HighPerformanceLoader,
                "plconfig",
                "$GBASEDBTDIR/etc/plconfig",
            ),
            (
                "gbase-8s-maxconnect-config",
                DatabaseConfigComponent::MaxConnect,
                "IMCconfig",
                "$GBASEDBTDIR/etc/IMCconfig",
            ),
        ];
        let mut identities = BTreeSet::new();

        for (key, component, file_name, documented_path) in expected {
            let artifact = artifact_by_key(key).unwrap();
            assert_eq!(artifact.product, DatabaseConfigProduct::GBase8s, "{key}");
            assert_eq!(artifact.component, component, "{key}");
            assert_eq!(artifact.surface, DatabaseConfigSurface::File, "{key}");
            assert_eq!(artifact.dialect, DatabaseConfigDialect::VendorText, "{key}");
            assert_ne!(
                artifact.support,
                DatabaseConfigSupportLevel::VisualSyntax,
                "{key} must not claim a structured visual syntax"
            );
            assert_eq!(artifact.default_file_name, Some(file_name), "{key}");
            assert!(artifact.validation_note.contains(documented_path), "{key}");
            assert!(artifact.is_file_visual_readable(), "{key}");
            assert!(!artifact.allows_lossless_local_draft(), "{key}");
            assert!(identities.insert((component, file_name)), "{key}");

            if key == "gbase-8s-archecker-template" {
                assert_eq!(
                    artifact.support,
                    DatabaseConfigSupportLevel::ReadOnlyDiscovery
                );
                assert_eq!(artifact.edit_policy, DatabaseConfigEditPolicy::ReadOnly);
                assert_eq!(artifact.validator, DatabaseConfigValidator::NotApplicable);
                assert_eq!(artifact.activation, DatabaseConfigActivation::NotApplicable);
            } else {
                assert_eq!(
                    artifact.support,
                    DatabaseConfigSupportLevel::VendorSchemaRequired
                );
                assert_eq!(
                    artifact.edit_policy,
                    DatabaseConfigEditPolicy::VendorSchemaRequired
                );
                assert_eq!(
                    artifact.validator,
                    DatabaseConfigValidator::VendorSchemaRequired
                );
                assert_eq!(
                    artifact.activation,
                    DatabaseConfigActivation::VendorProcedure
                );
            }
        }

        assert_eq!(identities.len(), expected.len());
    }

    #[test]
    fn gbase_8s_dynamic_names_and_generated_state_are_not_invented_as_defaults() {
        let onconfig = artifact_by_key("gbase-8s-onconfig").unwrap();
        assert_eq!(onconfig.default_file_name, Some("onconfig"));
        assert!(onconfig.validation_note.contains("onconfig.<server_name>"));

        let sqlhosts = artifact_by_key("gbase-8s-sqlhosts").unwrap();
        assert_eq!(sqlhosts.default_file_name, Some("sqlhosts"));
        assert!(sqlhosts.validation_note.contains("GBASEDBTSQLHOSTS"));

        let maxconnect = artifact_by_key("gbase-8s-maxconnect-config").unwrap();
        assert_eq!(maxconnect.default_file_name, Some("IMCconfig"));
        assert!(maxconnect.validation_note.contains("IMCconfig.<instance>"));

        assert!(
            artifacts_for(DatabaseConfigProduct::GBase8s).all(|artifact| {
                !matches!(
                    artifact.default_file_name,
                    Some(file_name) if file_name.starts_with("ixbar") || file_name == "psm"
                )
            })
        );
    }

    #[test]
    fn goldendb_proxy_ini_is_a_distinct_fail_closed_file_artifact() {
        let proxy = artifact_by_key("goldendb-proxy-ini").unwrap();
        assert_eq!(proxy.product, DatabaseConfigProduct::GoldenDb);
        assert_eq!(proxy.component, DatabaseConfigComponent::Proxy);
        assert_eq!(proxy.surface, DatabaseConfigSurface::File);
        assert_eq!(proxy.dialect, DatabaseConfigDialect::Ini);
        assert_eq!(proxy.support, DatabaseConfigSupportLevel::VisualSyntax);
        assert_eq!(
            proxy.edit_policy,
            DatabaseConfigEditPolicy::VendorSchemaRequired
        );
        assert_eq!(proxy.default_file_name, Some("proxy.ini"));
        assert_eq!(
            proxy.validator,
            DatabaseConfigValidator::VendorSchemaRequired
        );
        assert_eq!(proxy.activation, DatabaseConfigActivation::VendorProcedure);
        assert!(proxy.is_file_visual_readable());
        assert!(!proxy.allows_lossless_local_draft());

        let cluster = artifact_by_key("goldendb-cluster-config").unwrap();
        assert_ne!(proxy.component, cluster.component);
        assert_ne!(proxy.dialect, cluster.dialect);
    }

    #[test]
    fn gbase_gcware_conf_is_structured_but_never_a_local_draft() {
        let artifact = artifact_by_key("gbase-8a-gcware-config").unwrap();
        assert_eq!(artifact.product, DatabaseConfigProduct::GBase8a);
        assert_eq!(artifact.component, DatabaseConfigComponent::Gcware);
        assert_eq!(artifact.surface, DatabaseConfigSurface::File);
        assert_eq!(artifact.dialect, DatabaseConfigDialect::GcwareConf);
        assert_eq!(artifact.support, DatabaseConfigSupportLevel::VisualSyntax);
        assert_eq!(
            artifact.edit_policy,
            DatabaseConfigEditPolicy::VendorSchemaRequired
        );
        assert_eq!(artifact.default_file_name, Some("gcware.conf"));
        assert_eq!(
            artifact.validator,
            DatabaseConfigValidator::VendorSchemaRequired
        );
        assert_eq!(
            artifact.activation,
            DatabaseConfigActivation::VendorProcedure
        );
        assert!(artifact.is_file_visual_readable());
        assert!(!artifact.allows_lossless_local_draft());
    }

    #[test]
    fn gbase_8a_gnode_and_gcluster_artifacts_keep_distinct_component_identity() {
        let gnode_options = artifact_by_key("gbase-8a-gbase-options").unwrap();
        let gcluster_options = artifact_by_key("gbase-8a-gcluster-options").unwrap();
        assert_eq!(gnode_options.component, DatabaseConfigComponent::GNode);
        assert_eq!(
            gcluster_options.component,
            DatabaseConfigComponent::GCluster
        );
        assert_ne!(gnode_options.component, gcluster_options.component);

        let expected = [
            (
                "gbase-8a-gnode-cluster-common",
                DatabaseConfigComponent::GNode,
                "$GBASE_BASE/config/cluster_common.cnf",
            ),
            (
                "gbase-8a-gcluster-cluster-common",
                DatabaseConfigComponent::GCluster,
                "$GCLUSTER_BASE/config/cluster_common.cnf",
            ),
        ];
        for (key, component, documented_path) in expected {
            let artifact = artifact_by_key(key).unwrap();
            assert_eq!(artifact.product, DatabaseConfigProduct::GBase8a, "{key}");
            assert_eq!(artifact.component, component, "{key}");
            assert_eq!(
                artifact.surface,
                DatabaseConfigSurface::GeneratedReadOnly,
                "{key}"
            );
            assert_eq!(artifact.dialect, DatabaseConfigDialect::Json, "{key}");
            assert_eq!(
                artifact.support,
                DatabaseConfigSupportLevel::ReadOnlyDiscovery,
                "{key}"
            );
            assert_eq!(
                artifact.edit_policy,
                DatabaseConfigEditPolicy::ReadOnly,
                "{key}"
            );
            assert_eq!(
                artifact.default_file_name,
                Some("cluster_common.cnf"),
                "{key}"
            );
            assert!(artifact.validation_note.contains(documented_path), "{key}");
            assert!(artifact.is_file_visual_readable(), "{key}");
            assert!(!artifact.allows_lossless_local_draft(), "{key}");
        }

        let same_name_components: BTreeSet<_> = artifacts_for(DatabaseConfigProduct::GBase8a)
            .filter(|artifact| artifact.default_file_name == Some("cluster_common.cnf"))
            .map(|artifact| artifact.component)
            .collect();
        assert_eq!(
            same_name_components,
            BTreeSet::from([
                DatabaseConfigComponent::GNode,
                DatabaseConfigComponent::GCluster,
            ])
        );
        assert!(
            artifacts_for(DatabaseConfigProduct::GBase8a)
                .all(|artifact| artifact.default_file_name != Some("gnode.cnf"))
        );
    }

    #[test]
    fn sequoiadb_sdb_conf_roles_are_unique_and_keep_safe_policies() {
        let expected_components = BTreeSet::from([
            DatabaseConfigComponent::SequoiaStandalone,
            DatabaseConfigComponent::SequoiaCoordinator,
            DatabaseConfigComponent::SequoiaCatalog,
            DatabaseConfigComponent::SequoiaData,
        ]);
        let actual_components: BTreeSet<_> = artifacts_for(DatabaseConfigProduct::SequoiaDb)
            .filter(|artifact| artifact.default_file_name == Some("sdb.conf"))
            .map(|artifact| artifact.component)
            .collect();
        assert_eq!(actual_components, expected_components);

        for (key, component) in [
            (
                "sequoiadb-standalone-config",
                DatabaseConfigComponent::SequoiaStandalone,
            ),
            (
                "sequoiadb-coordinator-config",
                DatabaseConfigComponent::SequoiaCoordinator,
            ),
            (
                "sequoiadb-catalog-config",
                DatabaseConfigComponent::SequoiaCatalog,
            ),
            (
                "sequoiadb-data-config",
                DatabaseConfigComponent::SequoiaData,
            ),
        ] {
            let artifact = artifact_by_key(key).unwrap();
            assert_eq!(artifact.product, DatabaseConfigProduct::SequoiaDb, "{key}");
            assert_eq!(artifact.component, component, "{key}");
            assert_eq!(artifact.surface, DatabaseConfigSurface::File, "{key}");
            assert_eq!(artifact.dialect, DatabaseConfigDialect::KeyValue, "{key}");
            assert_eq!(
                artifact.support,
                DatabaseConfigSupportLevel::VisualSyntax,
                "{key}"
            );
            assert_eq!(
                artifact.edit_policy,
                DatabaseConfigEditPolicy::LosslessLocalDraft,
                "{key}"
            );
            assert_eq!(artifact.default_file_name, Some("sdb.conf"), "{key}");
            assert_eq!(
                artifact.validator,
                DatabaseConfigValidator::VendorTool,
                "{key}"
            );
            assert_eq!(
                artifact.activation,
                DatabaseConfigActivation::RollingRestart,
                "{key}"
            );
            assert!(artifact.is_file_visual_readable(), "{key}");
            assert!(artifact.allows_lossless_local_draft(), "{key}");
        }
    }

    #[test]
    fn sequoiadb_quick_deploy_tables_are_unique_read_only_inputs() {
        let expected = [
            (
                "sequoiadb-quick-deploy-cluster",
                DatabaseConfigComponent::Deployment,
                DatabaseConfigDialect::SequoiaQuickDeployClusterCsv,
                "sequoiadb.conf",
            ),
            (
                "sequoiadb-quick-deploy-mysql",
                DatabaseConfigComponent::SequoiaSqlMySql,
                DatabaseConfigDialect::SequoiaQuickDeploySqlInstanceCsv,
                "mysql.conf",
            ),
            (
                "sequoiadb-quick-deploy-mariadb",
                DatabaseConfigComponent::SequoiaSqlMariaDb,
                DatabaseConfigDialect::SequoiaQuickDeploySqlInstanceCsv,
                "mariadb.conf",
            ),
            (
                "sequoiadb-quick-deploy-postgresql",
                DatabaseConfigComponent::SequoiaSqlPostgreSql,
                DatabaseConfigDialect::SequoiaQuickDeploySqlInstanceCsv,
                "postgresql.conf",
            ),
        ];
        let mut identities = BTreeSet::new();
        for (key, component, dialect, default_file_name) in expected {
            let artifact = artifact_by_key(key).unwrap();
            assert_eq!(artifact.product, DatabaseConfigProduct::SequoiaDb, "{key}");
            assert_eq!(artifact.component, component, "{key}");
            assert_eq!(artifact.surface, DatabaseConfigSurface::File, "{key}");
            assert_eq!(artifact.dialect, dialect, "{key}");
            assert_eq!(
                artifact.support,
                DatabaseConfigSupportLevel::VisualSyntax,
                "{key}"
            );
            assert_eq!(
                artifact.edit_policy,
                DatabaseConfigEditPolicy::VendorSchemaRequired,
                "{key}"
            );
            assert_eq!(artifact.default_file_name, Some(default_file_name), "{key}");
            assert_eq!(
                artifact.validator,
                DatabaseConfigValidator::VendorSchemaRequired,
                "{key}"
            );
            assert_eq!(
                artifact.activation,
                DatabaseConfigActivation::VendorProcedure,
                "{key}"
            );
            assert!(artifact.is_file_visual_readable(), "{key}");
            assert!(!artifact.dialect.is_generated(), "{key}");
            assert!(!artifact.allows_lossless_local_draft(), "{key}");
            assert!(identities.insert((component, default_file_name)), "{key}");
        }

        let node = artifact_by_key("sequoiadb-standalone-config").unwrap();
        let deployment = artifact_by_key("sequoiadb-quick-deploy-cluster").unwrap();
        let sql = artifact_by_key("sequoiadb-quick-deploy-mysql").unwrap();
        assert_eq!(node.default_file_name, Some("sdb.conf"));
        assert_eq!(deployment.default_file_name, Some("sequoiadb.conf"));
        assert_ne!(node.component, deployment.component);
        assert_ne!(node.dialect, deployment.dialect);
        assert_ne!(deployment.dialect, sql.dialect);
    }

    #[test]
    fn dm_and_tidb_component_sets_are_complete() {
        let dm_files: BTreeSet<_> = artifacts_for(DatabaseConfigProduct::Dm)
            .filter_map(|artifact| artifact.default_file_name)
            .collect();
        for required in [
            "dm.ini",
            "dmap.ini",
            "dminit.ini",
            "dmdcr_cfg.ini",
            "dmdcr.ini",
            "dmcssm.ini",
            "dmasvrmal.ini",
            "dm_svc.conf",
            "mp.ini",
            "dmthrd.ini",
            "dmarch.ini",
            "dmmal.ini",
            "dmwatcher.ini",
            "dmmonitor.ini",
            "dmtimer.ini",
            "sqllog.ini",
        ] {
            assert!(dm_files.contains(required), "missing {required}");
        }

        let tidb_components: BTreeSet<_> = artifacts_for(DatabaseConfigProduct::TiDb)
            .map(|artifact| artifact.component)
            .collect();
        for required in [
            DatabaseConfigComponent::TiDb,
            DatabaseConfigComponent::TiKv,
            DatabaseConfigComponent::Pd,
            DatabaseConfigComponent::TiFlash,
            DatabaseConfigComponent::TiFlashLearner,
            DatabaseConfigComponent::TiProxy,
            DatabaseConfigComponent::TiCdc,
            DatabaseConfigComponent::TiCdcChangefeed,
            DatabaseConfigComponent::TiDbLightning,
            DatabaseConfigComponent::TiUp,
        ] {
            assert!(tidb_components.contains(&required), "missing {required:?}");
        }
    }

    #[test]
    fn dm_extended_family_preserves_confirmed_syntax_and_roles() {
        for (key, component, file_name) in [
            ("dm-ap", DatabaseConfigComponent::DmAp, "dmap.ini"),
            ("dm-init", DatabaseConfigComponent::Deployment, "dminit.ini"),
            (
                "dm-css-monitor",
                DatabaseConfigComponent::Cluster,
                "dmcssm.ini",
            ),
            (
                "dm-asm-mal",
                DatabaseConfigComponent::Cluster,
                "dmasvrmal.ini",
            ),
            ("dm-mp", DatabaseConfigComponent::Cluster, "mp.ini"),
            ("dm-thread", DatabaseConfigComponent::Server, "dmthrd.ini"),
        ] {
            let artifact = artifact_by_key(key).unwrap();
            assert_eq!(artifact.product, DatabaseConfigProduct::Dm, "{key}");
            assert_eq!(artifact.component, component, "{key}");
            assert_eq!(artifact.default_file_name, Some(file_name), "{key}");
            assert_eq!(artifact.surface, DatabaseConfigSurface::File, "{key}");
            assert_eq!(artifact.dialect, DatabaseConfigDialect::Ini, "{key}");
            assert_eq!(
                artifact.edit_policy,
                DatabaseConfigEditPolicy::LosslessLocalDraft,
                "{key}"
            );
            assert_eq!(artifact.validator, DatabaseConfigValidator::VendorTool);
            assert!(artifact.is_file_visual_readable(), "{key}");
            assert!(artifact.allows_lossless_local_draft(), "{key}");
        }

        let thread = artifact_by_key("dm-thread").unwrap();
        assert_eq!(thread.support, DatabaseConfigSupportLevel::VisualSyntax);
        assert_eq!(thread.activation, DatabaseConfigActivation::VendorProcedure);
        assert!(
            thread
                .validation_note
                .contains("仅在 dm.ini 的 DMTHRD_INI=1 时使用")
        );
        assert!(
            thread
                .validation_note
                .contains("未验证目标的精确 DM build 与 CPU 上下文")
        );
        assert!(thread.activation_note.contains("不能自动部署"));

        let client = artifact_by_key("dm-client-service").unwrap();
        assert_eq!(client.product, DatabaseConfigProduct::Dm);
        assert_eq!(client.component, DatabaseConfigComponent::Client);
        assert_eq!(client.default_file_name, Some("dm_svc.conf"));
        assert_eq!(client.surface, DatabaseConfigSurface::File);
        assert_eq!(client.dialect, DatabaseConfigDialect::VendorText);
        assert_eq!(
            client.edit_policy,
            DatabaseConfigEditPolicy::VendorSchemaRequired
        );
        assert!(client.is_file_visual_readable());
        assert!(!client.allows_lossless_local_draft());
    }

    #[test]
    fn dm_init_password_is_redacted_non_copyable_and_rejects_ordinary_updates() {
        const SECRET: &str = "NeverShow42";
        const HOSTILE_REPLACEMENT: &str =
            "<script>globalThis.dmInitExecuted=true</script> password=EchoMe";
        const SOURCE: &str = concat!(
            "[DAMENG]\r\n",
            "SYSDBA_PWD=NeverShow42\r\n",
            "LOG_PATH=/var/log/dm/primary\r\n",
            "LOG_PATH=/var/log/dm/archive\r\n",
        );

        let artifact = artifact_by_key("dm-init").expect("registered DM init artifact");
        assert_eq!(artifact.product, DatabaseConfigProduct::Dm);
        assert_eq!(artifact.dialect, DatabaseConfigDialect::Ini);
        assert_eq!(
            artifact.local_draft_authority(),
            DatabaseConfigLocalDraftAuthority::LosslessLocalDraft
        );
        assert!(artifact.has_source_backed_visual_parser());

        let mut document = LineConfigVisualDocument::parse(LineConfigDialect::Ini, SOURCE)
            .expect("representative dminit.ini fixture");
        assert!(document.is_structured());
        assert!(document.contains_sensitive_values());

        let rows = document.rows();
        let dameng = rows
            .iter()
            .find(|row| row.kind() == LineConfigNodeKind::Section && row.name() == Some("DAMENG"))
            .expect("DAMENG section");
        assert_eq!(dameng.child_count(), 3);
        let password = rows
            .iter()
            .find(|row| row.name() == Some("SYSDBA_PWD"))
            .expect("SYSDBA password row");
        assert_eq!(password.parent(), Some(dameng.id()));
        assert!(password.sensitive());
        assert_eq!(password.value(), None);
        assert_eq!(password.preview(), "[sensitive value redacted]");
        assert!(!password.editable());
        assert_eq!(
            rows.iter()
                .filter(|row| row.name() == Some("LOG_PATH"))
                .map(|row| row.value())
                .collect::<Vec<_>>(),
            [Some("/var/log/dm/primary"), Some("/var/log/dm/archive")]
        );

        for public_debug in [
            format!("{document:?}"),
            format!("{:?}", document.output()),
            format!("{rows:?}"),
        ] {
            assert!(!public_debug.contains(SECRET));
            assert!(!public_debug.contains("dmInitExecuted"));
            assert!(!public_debug.contains("EchoMe"));
        }

        let password_id = password.id();
        let before = document.raw_bytes().to_vec();
        for replacement in ["replacement", HOSTILE_REPLACEMENT] {
            let error = document
                .update_entry(password_id, "SYSDBA_PWD", Some(replacement))
                .expect_err("ordinary visual updates must reject the secret row");
            let public_error = error.to_string();
            assert!(public_error.contains("dedicated secret input flow"));
            assert!(!public_error.contains(replacement));
            assert!(!public_error.contains(SECRET));
            assert_eq!(document.raw_bytes(), before);
        }
    }

    #[test]
    fn dm_dcr_files_fail_closed_until_the_vendor_grammar_is_modeled() {
        for (key, component, file_name) in [
            (
                "dm-dcr-config",
                DatabaseConfigComponent::Deployment,
                "dmdcr_cfg.ini",
            ),
            ("dm-dcr-node", DatabaseConfigComponent::Cluster, "dmdcr.ini"),
        ] {
            let artifact = artifact_by_key(key).unwrap();
            assert_eq!(artifact.product, DatabaseConfigProduct::Dm, "{key}");
            assert_eq!(artifact.component, component, "{key}");
            assert_eq!(artifact.default_file_name, Some(file_name), "{key}");
            assert_eq!(artifact.surface, DatabaseConfigSurface::File, "{key}");
            assert_eq!(artifact.dialect, DatabaseConfigDialect::VendorText, "{key}");
            assert_eq!(
                artifact.support,
                DatabaseConfigSupportLevel::VendorSchemaRequired,
                "{key}"
            );
            assert_eq!(
                artifact.edit_policy,
                DatabaseConfigEditPolicy::VendorSchemaRequired,
                "{key}"
            );
            assert_eq!(
                artifact.validator,
                DatabaseConfigValidator::VendorSchemaRequired,
                "{key}"
            );
            assert_eq!(
                artifact.activation,
                DatabaseConfigActivation::VendorProcedure,
                "{key}"
            );
            assert!(artifact.is_file_visual_readable(), "{key}");
            assert!(!artifact.has_source_backed_visual_parser(), "{key}");
            assert!(!artifact.allows_lossless_local_draft(), "{key}");
        }
    }

    #[test]
    fn dm_dcr_array_and_startup_command_payloads_never_reach_the_generic_ini_editor() {
        const DCR_CONFIG: &str = concat!(
            "// ordered vendor-owned groups\n",
            "[GRP]\nDCR_GRP_NAME=CSS_GRP\nDCR_GRP_TYPE=CSS\n",
            "[CSS]\nDCR_EP_NAME=CSS0\n",
            "[CSS]\nDCR_EP_NAME=CSS1\n",
            "<script>globalThis.dcrExecuted=true</script>\n",
        );
        const DCR_NODE: &str = concat!(
            "DMDCR_PATH=/dmdata/dmdcr_cfg.ini\n",
            "DMDCR_DB_STARTUP_CMD=/opt/dmdbms/bin/dmserver path=/dmdata/DAMENG/dm.ini password=NeverShow42\n",
        );

        for (key, payload) in [("dm-dcr-config", DCR_CONFIG), ("dm-dcr-node", DCR_NODE)] {
            let artifact = artifact_by_key(key).expect("registered DM DCR artifact");
            assert_eq!(artifact.product, DatabaseConfigProduct::Dm, "{key}");
            assert_eq!(artifact.surface, DatabaseConfigSurface::File, "{key}");
            assert_eq!(artifact.dialect, DatabaseConfigDialect::VendorText, "{key}");
            assert_ne!(artifact.dialect, DatabaseConfigDialect::Ini, "{key}");
            assert_eq!(
                artifact.support,
                DatabaseConfigSupportLevel::VendorSchemaRequired,
                "{key}"
            );
            assert!(artifact.is_file_visual_readable(), "{key}");
            assert!(
                !artifact.has_source_backed_visual_parser(),
                "{key} reached the generic INI editor"
            );
            assert_eq!(
                artifact.local_draft_authority(),
                DatabaseConfigLocalDraftAuthority::ReadOnly,
                "{key} gained draft authority"
            );
            assert_eq!(database_starter_contents(artifact), "", "{key}");

            let status = artifact
                .read_only_status()
                .expect("DM DCR artifact remains fixed metadata only");
            let public_debug = format!("{artifact:?}{status:?}");
            for rejected in [
                payload,
                "DCR_GRP_NAME",
                "DMDCR_DB_STARTUP_CMD",
                "dmserver",
                "dcrExecuted",
                "NeverShow42",
            ] {
                assert!(!public_debug.contains(rejected), "{key} leaked {rejected}");
            }
        }
    }

    #[test]
    fn ha_cm_and_ptk_artifacts_keep_vendor_roles_separate() {
        for (key, product, component, file_name) in [
            (
                "opengauss-cm-server",
                DatabaseConfigProduct::OpenGauss,
                DatabaseConfigComponent::CmServer,
                "cm_server.conf",
            ),
            (
                "opengauss-cm-agent",
                DatabaseConfigProduct::OpenGauss,
                DatabaseConfigComponent::CmAgent,
                "cm_agent.conf",
            ),
            (
                "mogdb-cm-server",
                DatabaseConfigProduct::MogDb,
                DatabaseConfigComponent::CmServer,
                "cm_server.conf",
            ),
            (
                "mogdb-cm-agent",
                DatabaseConfigProduct::MogDb,
                DatabaseConfigComponent::CmAgent,
                "cm_agent.conf",
            ),
        ] {
            let artifact = artifact_by_key(key).unwrap();
            assert_eq!(artifact.product, product, "{key}");
            assert_eq!(artifact.component, component, "{key}");
            assert_eq!(artifact.default_file_name, Some(file_name), "{key}");
            assert_eq!(artifact.surface, DatabaseConfigSurface::File, "{key}");
            assert_eq!(artifact.dialect, DatabaseConfigDialect::VendorText, "{key}");
            assert_eq!(
                artifact.edit_policy,
                DatabaseConfigEditPolicy::VendorSchemaRequired,
                "{key}"
            );
            assert_eq!(artifact.validator, DatabaseConfigValidator::VendorTool);
            assert!(artifact.is_file_visual_readable(), "{key}");
            assert!(!artifact.allows_lossless_local_draft(), "{key}");
        }

        let ptk = artifact_by_key("mogdb-ptk-deployment").unwrap();
        assert_eq!(ptk.product, DatabaseConfigProduct::MogDb);
        assert_eq!(ptk.component, DatabaseConfigComponent::Ptk);
        assert_eq!(ptk.default_file_name, Some("config.yaml"));
        assert_eq!(ptk.surface, DatabaseConfigSurface::File);
        assert_eq!(ptk.dialect, DatabaseConfigDialect::Yaml);
        assert_eq!(
            ptk.edit_policy,
            DatabaseConfigEditPolicy::VendorSchemaRequired
        );

        for (key, product, dialect, support, file_name) in [
            (
                "kingbase-es-repmgr",
                DatabaseConfigProduct::KingbaseEs,
                DatabaseConfigDialect::VendorText,
                DatabaseConfigSupportLevel::VendorSchemaRequired,
                "repmgr.conf",
            ),
            (
                "kingbase-es-replication",
                DatabaseConfigProduct::KingbaseEs,
                DatabaseConfigDialect::PostgreSqlConf,
                DatabaseConfigSupportLevel::VisualSyntax,
                "es_rep.conf",
            ),
        ] {
            let artifact = artifact_by_key(key).unwrap();
            assert_eq!(artifact.product, product, "{key}");
            assert_eq!(
                artifact.component,
                DatabaseConfigComponent::Cluster,
                "{key}"
            );
            assert_eq!(artifact.default_file_name, Some(file_name), "{key}");
            assert_eq!(artifact.surface, DatabaseConfigSurface::File, "{key}");
            assert_eq!(artifact.dialect, dialect, "{key}");
            assert_eq!(artifact.support, support, "{key}");
            assert_eq!(
                artifact.edit_policy,
                DatabaseConfigEditPolicy::VendorSchemaRequired,
                "{key}"
            );
            assert_eq!(
                artifact.validator,
                DatabaseConfigValidator::VendorSchemaRequired,
                "{key}"
            );
            assert!(artifact.is_file_visual_readable(), "{key}");
            assert!(!artifact.allows_lossless_local_draft(), "{key}");
        }

        for (key, product) in [
            (
                "opengauss-cluster-static-config",
                DatabaseConfigProduct::OpenGauss,
            ),
            ("mogdb-cluster-static-config", DatabaseConfigProduct::MogDb),
        ] {
            let artifact = artifact_by_key(key).unwrap();
            assert_eq!(artifact.product, product, "{key}");
            assert_eq!(
                artifact.component,
                DatabaseConfigComponent::Cluster,
                "{key}"
            );
            assert_eq!(
                artifact.surface,
                DatabaseConfigSurface::GeneratedReadOnly,
                "{key}"
            );
            assert_eq!(artifact.dialect, DatabaseConfigDialect::VendorBinary);
            assert_eq!(artifact.edit_policy, DatabaseConfigEditPolicy::ReadOnly);
            assert!(!artifact.is_file_visual_readable(), "{key}");
            assert!(!artifact.allows_lossless_local_draft(), "{key}");
        }
    }

    #[test]
    fn tidb_auxiliary_toml_artifacts_preserve_official_roles_and_fail_closed() {
        let mut identities = BTreeSet::new();
        for (key, component, default_file_name) in [
            (
                "tidb-tiflash-toml",
                DatabaseConfigComponent::TiFlash,
                "tiflash.toml",
            ),
            (
                "tidb-tiflash-learner-toml",
                DatabaseConfigComponent::TiFlashLearner,
                "tiflash-learner.toml",
            ),
            (
                "tidb-tiproxy-toml",
                DatabaseConfigComponent::TiProxy,
                "tiproxy.toml",
            ),
            (
                "tidb-ticdc-toml",
                DatabaseConfigComponent::TiCdc,
                "ticdc.toml",
            ),
            (
                "tidb-ticdc-changefeed-toml",
                DatabaseConfigComponent::TiCdcChangefeed,
                "changefeed.toml",
            ),
            (
                "tidb-lightning-toml",
                DatabaseConfigComponent::TiDbLightning,
                "tidb-lightning.toml",
            ),
        ] {
            let artifact = artifact_by_key(key).unwrap();
            assert_eq!(artifact.product, DatabaseConfigProduct::TiDb, "{key}");
            assert_eq!(artifact.component, component, "{key}");
            assert_eq!(artifact.default_file_name, Some(default_file_name), "{key}");
            assert_eq!(artifact.surface, DatabaseConfigSurface::File, "{key}");
            assert_eq!(artifact.dialect, DatabaseConfigDialect::Toml, "{key}");
            assert_eq!(
                artifact.support,
                DatabaseConfigSupportLevel::VisualSyntax,
                "{key}"
            );
            assert_eq!(
                artifact.edit_policy,
                DatabaseConfigEditPolicy::VendorSchemaRequired,
                "{key}"
            );
            assert_eq!(
                artifact.validator,
                DatabaseConfigValidator::VendorSchemaRequired,
                "{key}"
            );
            assert_eq!(
                artifact.activation,
                DatabaseConfigActivation::VendorProcedure,
                "{key}"
            );
            assert!(artifact.is_file_visual_readable(), "{key}");
            assert!(!artifact.dialect.is_generated(), "{key}");
            assert!(!artifact.dialect.is_binary(), "{key}");
            assert!(!artifact.allows_lossless_local_draft(), "{key}");
            assert!(identities.insert((component, default_file_name)), "{key}");
        }

        assert_ne!(
            artifact_by_key("tidb-tiflash-toml").unwrap().component,
            artifact_by_key("tidb-tiflash-learner-toml")
                .unwrap()
                .component
        );
        assert_ne!(
            artifact_by_key("tidb-ticdc-toml").unwrap().component,
            artifact_by_key("tidb-ticdc-changefeed-toml")
                .unwrap()
                .component
        );
    }

    #[test]
    fn postgresql_family_exposes_its_main_hba_and_ident_files() {
        for product in [
            DatabaseConfigProduct::PostgreSql,
            DatabaseConfigProduct::OpenGauss,
            DatabaseConfigProduct::MogDb,
            DatabaseConfigProduct::Vastbase,
            DatabaseConfigProduct::GBase8c,
            DatabaseConfigProduct::TdsqlPostgresqlPrivate,
            DatabaseConfigProduct::AntDb,
            DatabaseConfigProduct::HighGo,
            DatabaseConfigProduct::OpenTenBase,
        ] {
            let files: BTreeSet<_> = artifacts_for(product)
                .filter_map(|artifact| artifact.default_file_name)
                .collect();
            for required in ["postgresql.conf", "pg_hba.conf", "pg_ident.conf"] {
                assert!(files.contains(required), "{product:?} missing {required}");
            }
        }

        let kingbase_files: BTreeSet<_> = artifacts_for(DatabaseConfigProduct::KingbaseEs)
            .filter_map(|artifact| artifact.default_file_name)
            .collect();
        for required in [
            "kingbase.conf",
            "sys_hba.conf",
            "sys_ident.conf",
            "repmgr.conf",
            "es_rep.conf",
        ] {
            assert!(
                kingbase_files.contains(required),
                "KingbaseES missing {required}"
            );
        }
        let auto = artifact_by_key("kingbase-es-auto-conf").unwrap();
        assert_eq!(auto.default_file_name, Some("kingbase.auto.conf"));
        assert_eq!(auto.surface, DatabaseConfigSurface::GeneratedReadOnly);
        assert!(!auto.allows_lossless_local_draft());
    }

    #[test]
    fn surfaces_and_policies_fail_closed() {
        for artifact in DATABASE_CONFIG_ARTIFACTS {
            assert!(!artifact.validation_note.is_empty());
            assert!(!artifact.activation_note.is_empty());

            match artifact.surface {
                DatabaseConfigSurface::File => {
                    assert_eq!(
                        artifact.is_file_visual_readable(),
                        !artifact.dialect.is_binary()
                    );
                    if artifact.edit_policy == DatabaseConfigEditPolicy::LosslessLocalDraft {
                        assert!(
                            artifact.default_file_name.is_some(),
                            "local draft artifact {} lacks a default filename",
                            artifact.key
                        );
                    }
                }
                DatabaseConfigSurface::RuntimeSql => {
                    assert_eq!(artifact.dialect, DatabaseConfigDialect::RuntimeSql);
                    assert_eq!(artifact.default_file_name, None);
                    assert!(!artifact.is_file_visual_readable());
                    assert!(!artifact.allows_lossless_local_draft());
                }
                DatabaseConfigSurface::CloudApi => {
                    assert_eq!(artifact.dialect, DatabaseConfigDialect::CloudApi);
                    assert_eq!(artifact.default_file_name, None);
                    assert!(!artifact.is_file_visual_readable());
                }
                DatabaseConfigSurface::GeneratedReadOnly => {
                    assert_eq!(artifact.edit_policy, DatabaseConfigEditPolicy::ReadOnly);
                    assert_eq!(
                        artifact.support,
                        DatabaseConfigSupportLevel::ReadOnlyDiscovery
                    );
                    assert_eq!(
                        artifact.is_file_visual_readable(),
                        !artifact.dialect.is_binary()
                    );
                }
            }

            if artifact.edit_policy != DatabaseConfigEditPolicy::LosslessLocalDraft {
                assert!(!artifact.allows_lossless_local_draft());
            }
        }

        let persisted = artifact_by_key("mysql-persisted-variables").unwrap();
        assert!(persisted.is_file_visual_readable());
        assert!(!persisted.allows_lossless_local_draft());
        let topology = artifact_by_key("tidb-tiup-topology").unwrap();
        assert!(topology.is_file_visual_readable());
        assert!(!topology.allows_lossless_local_draft());
        let observer = artifact_by_key("oceanbase-observer-binary").unwrap();
        assert!(!observer.is_file_visual_readable());
    }

    #[test]
    fn structured_read_only_visibility_is_independent_from_mutation() {
        for key in [
            "mysql-persisted-variables",
            "postgresql-auto-conf",
            "kingbase-es-auto-conf",
            "greatsql-persisted-variables",
            "highgo-auto-conf",
            "gbase-8c-auto-conf",
            "oceanbase-obd-registered-config",
            "tidb-tiup-topology",
            "opengauss-om-cluster-xml",
            "polardb-x-operator-cr",
        ] {
            let artifact = artifact_by_key(key).unwrap();
            assert!(
                artifact.is_file_visual_readable(),
                "{key} must remain visible"
            );
            assert!(
                !artifact.allows_lossless_local_draft(),
                "{key} must remain read-only"
            );
        }

        for key in [
            "oceanbase-observer-binary",
            "opengauss-cluster-static-config",
            "mogdb-cluster-static-config",
        ] {
            let artifact = artifact_by_key(key).unwrap();
            assert!(!artifact.is_file_visual_readable(), "{key} is binary");
            assert!(!artifact.allows_lossless_local_draft(), "{key} is binary");
        }
    }

    #[test]
    fn known_generated_artifacts_fail_closed() {
        let expected = BTreeSet::from([
            "mysql-server-uuid",
            "mysql-persisted-variables",
            "postgresql-auto-conf",
            "opengauss-cluster-static-config",
            "mogdb-cluster-static-config",
            "kingbase-es-auto-conf",
            "oceanbase-observer-binary",
            "oceanbase-obd-registered-config",
            "gbase-8a-gnode-cluster-common",
            "gbase-8a-gcluster-cluster-common",
            "gbase-8c-auto-conf",
            "greatsql-persisted-variables",
            "highgo-auto-conf",
            "yashandb-spfile",
            "yashandb-password-file",
        ]);
        let actual: BTreeSet<_> = DATABASE_CONFIG_ARTIFACTS
            .iter()
            .filter(|artifact| artifact.surface == DatabaseConfigSurface::GeneratedReadOnly)
            .map(|artifact| artifact.key)
            .collect();
        assert_eq!(actual, expected);

        for key in actual {
            let artifact = artifact_by_key(key).unwrap();
            assert_eq!(
                artifact.support,
                DatabaseConfigSupportLevel::ReadOnlyDiscovery
            );
            assert_eq!(artifact.edit_policy, DatabaseConfigEditPolicy::ReadOnly);
            assert_eq!(artifact.validator, DatabaseConfigValidator::NotApplicable);
            assert_eq!(artifact.activation, DatabaseConfigActivation::NotApplicable);
            assert!(!artifact.allows_lossless_local_draft());
        }
    }

    #[test]
    fn obd_input_and_registered_state_are_distinct() {
        let input = artifact_by_key("oceanbase-obd-deployment").unwrap();
        assert_eq!(input.product, DatabaseConfigProduct::OceanBase);
        assert_eq!(input.component, DatabaseConfigComponent::Obd);
        assert_eq!(input.surface, DatabaseConfigSurface::File);
        assert_eq!(input.dialect, DatabaseConfigDialect::Yaml);
        assert_eq!(input.support, DatabaseConfigSupportLevel::VisualSyntax);
        assert_eq!(
            input.edit_policy,
            DatabaseConfigEditPolicy::VendorSchemaRequired
        );
        assert_eq!(input.default_file_name, None);

        let registered = artifact_by_key("oceanbase-obd-registered-config").unwrap();
        assert_eq!(registered.product, DatabaseConfigProduct::OceanBase);
        assert_eq!(registered.component, DatabaseConfigComponent::Obd);
        assert_eq!(registered.surface, DatabaseConfigSurface::GeneratedReadOnly);
        assert_eq!(registered.dialect, DatabaseConfigDialect::Yaml);
        assert_eq!(registered.edit_policy, DatabaseConfigEditPolicy::ReadOnly);
        assert_eq!(registered.default_file_name, Some("config.yaml"));
    }

    #[test]
    fn domestic_deployment_manifests_are_not_collapsed() {
        for (key, product, component, dialect) in [
            (
                "opengauss-om-cluster-xml",
                DatabaseConfigProduct::OpenGauss,
                DatabaseConfigComponent::Deployment,
                DatabaseConfigDialect::Xml,
            ),
            (
                "mogdb-om-cluster-xml",
                DatabaseConfigProduct::MogDb,
                DatabaseConfigComponent::Deployment,
                DatabaseConfigDialect::Xml,
            ),
            (
                "mogdb-ptk-deployment",
                DatabaseConfigProduct::MogDb,
                DatabaseConfigComponent::Ptk,
                DatabaseConfigDialect::Yaml,
            ),
            (
                "vastbase-om-cluster-xml",
                DatabaseConfigProduct::Vastbase,
                DatabaseConfigComponent::Deployment,
                DatabaseConfigDialect::Xml,
            ),
            (
                "gbase-8a-distribution-xml",
                DatabaseConfigProduct::GBase8a,
                DatabaseConfigComponent::Cluster,
                DatabaseConfigDialect::Xml,
            ),
            (
                "gbase-8s-om-cluster-xml",
                DatabaseConfigProduct::GBase8s,
                DatabaseConfigComponent::Deployment,
                DatabaseConfigDialect::Xml,
            ),
            (
                "gbase-8c-om-cluster-xml",
                DatabaseConfigProduct::GBase8c,
                DatabaseConfigComponent::Deployment,
                DatabaseConfigDialect::Xml,
            ),
            (
                "tidb-tiup-topology",
                DatabaseConfigProduct::TiDb,
                DatabaseConfigComponent::TiUp,
                DatabaseConfigDialect::Yaml,
            ),
            (
                "tidb-operator-cluster-cr",
                DatabaseConfigProduct::TiDb,
                DatabaseConfigComponent::Operator,
                DatabaseConfigDialect::Yaml,
            ),
            (
                "oceanbase-obd-deployment",
                DatabaseConfigProduct::OceanBase,
                DatabaseConfigComponent::Obd,
                DatabaseConfigDialect::Yaml,
            ),
            (
                "oceanbase-operator-cluster-cr",
                DatabaseConfigProduct::OceanBase,
                DatabaseConfigComponent::Operator,
                DatabaseConfigDialect::Yaml,
            ),
            (
                "polardb-x-operator-cr",
                DatabaseConfigProduct::PolarDbX,
                DatabaseConfigComponent::Operator,
                DatabaseConfigDialect::Yaml,
            ),
            (
                "highgo-ha-config",
                DatabaseConfigProduct::HighGo,
                DatabaseConfigComponent::Cluster,
                DatabaseConfigDialect::Yaml,
            ),
        ] {
            let artifact = artifact_by_key(key).unwrap();
            assert_eq!(artifact.product, product, "{key}");
            assert_eq!(artifact.component, component, "{key}");
            assert_eq!(artifact.dialect, dialect, "{key}");
            assert_eq!(artifact.surface, DatabaseConfigSurface::File, "{key}");
            assert_eq!(
                artifact.support,
                DatabaseConfigSupportLevel::VisualSyntax,
                "{key}"
            );
            assert_eq!(
                artifact.edit_policy,
                DatabaseConfigEditPolicy::VendorSchemaRequired,
                "{key}"
            );
            assert_eq!(
                artifact.validator,
                DatabaseConfigValidator::VendorSchemaRequired,
                "{key}"
            );
        }
    }

    #[test]
    fn generated_runtime_pairs_are_separate() {
        for (product, generated_key, runtime_key) in [
            (
                DatabaseConfigProduct::GreatSql,
                "greatsql-persisted-variables",
                "greatsql-runtime-parameters",
            ),
            (
                DatabaseConfigProduct::HighGo,
                "highgo-auto-conf",
                "highgo-runtime-parameters",
            ),
            (
                DatabaseConfigProduct::GBase8c,
                "gbase-8c-auto-conf",
                "gbase-8c-runtime-parameters",
            ),
        ] {
            let generated = artifact_by_key(generated_key).unwrap();
            let runtime = artifact_by_key(runtime_key).unwrap();
            assert_eq!(generated.product, product);
            assert_eq!(runtime.product, product);
            assert_eq!(generated.surface, DatabaseConfigSurface::GeneratedReadOnly);
            assert_eq!(runtime.surface, DatabaseConfigSurface::RuntimeSql);
            assert_ne!(generated.component, runtime.component);
        }
    }

    #[test]
    fn arbitrary_path_inputs_do_not_invent_default_names() {
        for key in [
            "opengauss-om-cluster-xml",
            "mogdb-om-cluster-xml",
            "vastbase-om-cluster-xml",
            "gbase-8a-distribution-xml",
            "gbase-8s-om-cluster-xml",
            "gbase-8c-om-cluster-xml",
            "tidb-tiup-topology",
            "tidb-operator-cluster-cr",
            "oceanbase-obd-deployment",
            "oceanbase-operator-cluster-cr",
            "polardb-x-operator-cr",
            "yashandb-yasboot-cluster",
        ] {
            assert_eq!(
                artifact_by_key(key).unwrap().default_file_name,
                None,
                "{key} accepts an arbitrary path"
            );
        }

        assert_eq!(
            artifact_by_key("mogdb-ptk-deployment")
                .unwrap()
                .default_file_name,
            Some("config.yaml")
        );
        assert_eq!(
            artifact_by_key("highgo-ha-config")
                .unwrap()
                .default_file_name,
            Some("hghac.yml")
        );
        assert_eq!(
            artifact_by_key("yashandb-yasboot-hosts")
                .unwrap()
                .default_file_name,
            Some("hosts.toml")
        );
    }

    #[test]
    fn structured_vendor_rows_never_allow_lossless_local_drafts() {
        let rows: Vec<_> = DATABASE_CONFIG_ARTIFACTS
            .iter()
            .filter(|artifact| {
                artifact.surface == DatabaseConfigSurface::File
                    && artifact.support == DatabaseConfigSupportLevel::VisualSyntax
                    && artifact.edit_policy == DatabaseConfigEditPolicy::VendorSchemaRequired
            })
            .collect();
        assert!(!rows.is_empty());

        for artifact in rows {
            assert!(matches!(
                artifact.dialect,
                DatabaseConfigDialect::Toml
                    | DatabaseConfigDialect::PostgreSqlConf
                    | DatabaseConfigDialect::Ini
                    | DatabaseConfigDialect::Yaml
                    | DatabaseConfigDialect::Json
                    | DatabaseConfigDialect::Xml
                    | DatabaseConfigDialect::KeyValue
                    | DatabaseConfigDialect::GcwareConf
                    | DatabaseConfigDialect::SequoiaQuickDeployClusterCsv
                    | DatabaseConfigDialect::SequoiaQuickDeploySqlInstanceCsv
                    | DatabaseConfigDialect::VendorText
            ));
            assert_eq!(
                artifact.validator,
                DatabaseConfigValidator::VendorSchemaRequired
            );
            assert_eq!(
                artifact.activation,
                DatabaseConfigActivation::VendorProcedure
            );
            assert!(!artifact.allows_lossless_local_draft());
        }
    }

    #[test]
    fn yashan_23_5_keeps_text_source_and_vendor_owned_binary_state_separate() {
        assert!(artifact_by_key("yashandb-server-config").is_none());

        let yasdb_ini = artifact_by_key("yashandb-yasdb-ini").unwrap();
        assert_eq!(yasdb_ini.product, DatabaseConfigProduct::Yashan);
        assert_eq!(yasdb_ini.component, DatabaseConfigComponent::Server);
        assert_eq!(yasdb_ini.surface, DatabaseConfigSurface::File);
        assert_eq!(yasdb_ini.dialect, DatabaseConfigDialect::KeyValue);
        assert_eq!(yasdb_ini.support, DatabaseConfigSupportLevel::VisualSyntax);
        assert_eq!(
            yasdb_ini.edit_policy,
            DatabaseConfigEditPolicy::VendorSchemaRequired
        );
        assert_eq!(yasdb_ini.default_file_name, Some("yasdb.ini"));
        assert_eq!(
            yasdb_ini.validator,
            DatabaseConfigValidator::VendorSchemaRequired
        );
        assert_eq!(
            yasdb_ini.activation,
            DatabaseConfigActivation::VendorProcedure
        );
        assert!(yasdb_ini.is_file_visual_readable());
        assert!(!yasdb_ini.allows_lossless_local_draft());
        assert!(!yasdb_ini.dialect.is_generated());

        for (key, component, default_file_name) in [
            (
                "yashandb-spfile",
                DatabaseConfigComponent::Persistence,
                "yasdb.spfile",
            ),
            (
                "yashandb-password-file",
                DatabaseConfigComponent::PasswordStore,
                "yasdb.pwd",
            ),
        ] {
            let artifact = artifact_by_key(key).unwrap();
            assert_eq!(artifact.product, DatabaseConfigProduct::Yashan);
            assert_eq!(artifact.component, component);
            assert_eq!(artifact.surface, DatabaseConfigSurface::GeneratedReadOnly);
            assert_eq!(artifact.dialect, DatabaseConfigDialect::VendorBinary);
            assert_eq!(
                artifact.support,
                DatabaseConfigSupportLevel::ReadOnlyDiscovery
            );
            assert_eq!(artifact.edit_policy, DatabaseConfigEditPolicy::ReadOnly);
            assert_eq!(artifact.default_file_name, Some(default_file_name));
            assert_eq!(artifact.validator, DatabaseConfigValidator::NotApplicable);
            assert_eq!(artifact.activation, DatabaseConfigActivation::NotApplicable);
            assert!(artifact.dialect.is_binary());
            assert!(artifact.dialect.is_generated());
            assert!(!artifact.is_file_visual_readable());
            assert!(!artifact.allows_lossless_local_draft());
        }
    }

    #[test]
    fn yashan_yasboot_templates_remain_vendor_validated_inputs() {
        for (key, component, default_file_name) in [
            (
                "yashandb-yasboot-hosts",
                DatabaseConfigComponent::Deployment,
                Some("hosts.toml"),
            ),
            (
                "yashandb-yasboot-cluster",
                DatabaseConfigComponent::Cluster,
                None,
            ),
        ] {
            let artifact = artifact_by_key(key).unwrap();
            assert_eq!(artifact.product, DatabaseConfigProduct::Yashan);
            assert_eq!(artifact.component, component);
            assert_eq!(artifact.surface, DatabaseConfigSurface::File);
            assert_eq!(artifact.dialect, DatabaseConfigDialect::Toml);
            assert_eq!(artifact.default_file_name, default_file_name);
            assert_eq!(
                artifact.edit_policy,
                DatabaseConfigEditPolicy::VendorSchemaRequired
            );
            assert!(!artifact.allows_lossless_local_draft());
        }
    }

    #[test]
    fn shentong_families_are_distinct_and_do_not_infer_configuration() {
        let families = [
            DatabaseConfigProduct::ShenTongNative,
            DatabaseConfigProduct::ShenTongMpp,
            DatabaseConfigProduct::ShenTongOpenGauss,
        ];
        assert_eq!(families.into_iter().collect::<BTreeSet<_>>().len(), 3);

        for product in families {
            let definition = DATABASE_CONFIG_PRODUCTS
                .iter()
                .find(|definition| definition.product == product)
                .unwrap();
            assert_eq!(
                definition.protocols,
                &[DatabaseConfigProtocol::VendorNative]
            );
            assert!(
                !definition
                    .protocols
                    .contains(&DatabaseConfigProtocol::PostgreSql)
            );
            assert!(artifacts_for(product).next().is_none());
        }

        assert!(artifact_by_key("shentong-server-config").is_none());
        for guessed_file_name in ["oscar.conf", "OSRDB.conf"] {
            assert!(DATABASE_CONFIG_ARTIFACTS.iter().all(|artifact| {
                artifact
                    .default_file_name
                    .is_none_or(|name| !name.eq_ignore_ascii_case(guessed_file_name))
            }));
        }
    }

    #[test]
    fn yashan_text_mutations_require_versioned_vendor_schemas() {
        for artifact in artifacts_for(DatabaseConfigProduct::Yashan)
            .filter(|artifact| artifact.surface == DatabaseConfigSurface::File)
        {
            assert_eq!(
                artifact.edit_policy,
                DatabaseConfigEditPolicy::VendorSchemaRequired
            );
            assert_eq!(
                artifact.validator,
                DatabaseConfigValidator::VendorSchemaRequired
            );
            assert!(!artifact.allows_lossless_local_draft());
        }

        for key in [
            "yashandb-yasdb-ini",
            "yashandb-yasboot-hosts",
            "yashandb-yasboot-cluster",
        ] {
            assert_eq!(
                artifact_by_key(key).unwrap().support,
                DatabaseConfigSupportLevel::VisualSyntax
            );
        }
    }

    #[test]
    fn polardb_x_components_are_not_collapsed_into_one_properties_file() {
        let artifacts: BTreeSet<_> = artifacts_for(DatabaseConfigProduct::PolarDbX)
            .map(|artifact| (artifact.component, artifact.default_file_name))
            .collect();
        for required in [
            (
                DatabaseConfigComponent::PolarDbCn,
                Some("server.properties"),
            ),
            (DatabaseConfigComponent::PolarDbDn, Some("my.cnf")),
            (
                DatabaseConfigComponent::PolarDbCdc,
                Some("config.properties"),
            ),
            (DatabaseConfigComponent::PolarDbGms, None),
            (DatabaseConfigComponent::Operator, None),
        ] {
            assert!(artifacts.contains(&required), "missing {required:?}");
        }
    }
}
