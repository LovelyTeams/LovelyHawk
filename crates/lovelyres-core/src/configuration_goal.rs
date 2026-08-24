//! Reviewed, product-bound configuration goals.
//!
//! Search results are closed typed recipes, reviewed multi-step database goals,
//! catalogued artifact workspaces, or read-only guidance projected from one
//! reviewed database schema parameter. Search never inspects current values,
//! remote output, comments, or opaque source text.

use std::fmt;

use zeroize::Zeroizing;

use crate::{
    CoreError, CoreResult,
    apache_visual::{ApacheVisualDocument, ApacheVisualNodeKind},
    database_config::{
        DATABASE_CONFIG_ARTIFACTS, DATABASE_CONFIG_PRODUCTS, DatabaseConfigArtifactDefinition,
        DatabaseConfigDialect, DatabaseConfigProduct, DatabaseConfigProductDefinition,
        DatabaseConfigSupportLevel, DatabaseConfigSurface, artifact_by_key, artifacts_for,
    },
    database_config_schema::{
        DATABASE_CONFIG_SCHEMAS, DatabaseConfigParameterLocator, DatabaseConfigParameterSchema,
        DatabaseConfigSchema, DatabaseConfigSchemaSensitivity,
        DatabaseConfigSchemaValidationStatus, DatabaseConfigSchemaValueError,
        DatabaseConfigSchemaValueKind, DatabaseConfigVersion, DatabaseConfigVersionSelector,
    },
    middleware::MiddlewareProduct,
    nginx_config::NginxForbiddenPath,
};

pub const MAX_CONFIGURATION_GOAL_QUERY_CHARS: usize = 128;
pub const MAX_CONFIGURATION_GOAL_MATCHES: usize = 64;
pub const MAX_DATABASE_PARAMETER_ASSIGNMENT_CANDIDATES: usize = 64;

const NGINX_FORBIDDEN_PATH_ALIASES: &[&str] = &[
    "403",
    "禁止访问",
    "拒绝访问",
    "封禁",
    "禁止路径",
    "外部访问",
    "访问控制",
    "admin",
    "forbidden",
    "deny",
];
const NGINX_STATIC_SITE_ALIASES: &[&str] = &[
    "静态站点",
    "静态网站",
    "静态目录",
    "网站根目录",
    "static site",
    "document root",
];
const NGINX_REVERSE_PROXY_ALIASES: &[&str] = &[
    "反向代理",
    "代理到后端",
    "转发到后端",
    "proxy_pass",
    "reverse proxy",
    "upstream",
];
const APACHE_FORBIDDEN_PATH_ALIASES: &[&str] = &[
    "HTTP 403",
    "禁止访问路径",
    "拒绝访问路径",
    "路径封禁",
    "httpd forbidden path",
    "Require all denied",
];
const APACHE_DISABLE_TRACE_ALIASES: &[&str] = &[
    "Apache 禁用 TRACE",
    "httpd 关闭 trace",
    "Apache TRACE 405",
    "禁止 TRACE 请求",
    "关闭 HTTP TRACE",
];
const APACHE_REDUCE_VERSION_DISCLOSURE_ALIASES: &[&str] = &[
    "Apache 隐藏版本",
    "httpd 隐藏版本号",
    "Apache ServerTokens Prod",
    "关闭 ServerSignature",
    "隐藏 Apache 错误页签名",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DatabaseParameterGoalAliasGroup {
    canonical_keys: &'static [&'static str],
    aliases: &'static [&'static str],
}

/// Reviewed intent vocabulary for parameters whose vendor names do not describe
/// an operator's goal. Each entry only improves discovery; the exact schema
/// validator and artifact policy still decide whether a local draft is allowed.
const DATABASE_PARAMETER_GOAL_ALIAS_GROUPS: &[DatabaseParameterGoalAliasGroup] = &[
    DatabaseParameterGoalAliasGroup {
        canonical_keys: &["max_connections"],
        aliases: &[
            "提高最大连接数",
            "调整数据库连接上限",
            "增加并发连接",
            "connection limit",
        ],
    },
    DatabaseParameterGoalAliasGroup {
        canonical_keys: &[
            "slow_query_log",
            "log_slow_query",
            "log_min_duration_statement",
        ],
        aliases: &[
            "开启慢查询日志",
            "记录慢查询",
            "设置慢 SQL 阈值",
            "slow query",
        ],
    },
    DatabaseParameterGoalAliasGroup {
        canonical_keys: &["bind_address", "listen_addresses"],
        aliases: &[
            "调整数据库监听地址",
            "允许数据库远程连接",
            "数据库外部访问",
            "listen address",
        ],
    },
    DatabaseParameterGoalAliasGroup {
        canonical_keys: &["ssl", "SSL_ENABLE", "DIN_SSL_ENABLE", "HA_SSL_ENABLE"],
        aliases: &[
            "开启数据库 TLS",
            "启用 SSL 加密连接",
            "加密数据库连接",
            "enable tls",
        ],
    },
    DatabaseParameterGoalAliasGroup {
        canonical_keys: &[
            "audit_enabled",
            "audit_log_disable",
            "server_audit_logging",
            "sysaudit.enable",
            "UNIFIED_AUDITING",
            "ENABLE_AUDIT",
        ],
        aliases: &[
            "开启数据库审计",
            "保留审计记录",
            "启用审计日志",
            "enable audit",
        ],
    },
    DatabaseParameterGoalAliasGroup {
        canonical_keys: &[
            "AUDIT_LOG_FILE_COUNT",
            "AUDIT_KEEP_DAYS",
            "AUDIT_SPACE_LIMIT",
            "AUDIT_MAX_FILE_SIZE",
        ],
        aliases: &[
            "调整审计日志保留",
            "审计日志空间上限",
            "审计日志文件数量",
            "audit retention",
        ],
    },
    DatabaseParameterGoalAliasGroup {
        canonical_keys: &["statement_timeout"],
        aliases: &[
            "限制 SQL 执行时间",
            "设置查询超时",
            "终止超时语句",
            "query timeout",
        ],
    },
    DatabaseParameterGoalAliasGroup {
        canonical_keys: &["work_mem"],
        aliases: &[
            "调整查询工作内存",
            "排序哈希内存",
            "查询内存限制",
            "query memory",
        ],
    },
    DatabaseParameterGoalAliasGroup {
        canonical_keys: &[
            "sync_binlog",
            "innodb_flush_log_at_trx_commit",
            "synchronous_commit",
            "REDOFILE_IO_MODE",
        ],
        aliases: &[
            "提高事务持久性",
            "避免宕机丢数据",
            "调整日志刷盘策略",
            "transaction durability",
        ],
    },
    DatabaseParameterGoalAliasGroup {
        canonical_keys: &["password_encryption"],
        aliases: &[
            "设置密码哈希算法",
            "加强密码存储",
            "密码加密方式",
            "password hashing",
        ],
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatabaseGoalStepDefinition {
    pub title: &'static str,
    pub explanation: &'static str,
    pub products: &'static [DatabaseConfigProduct],
    pub canonical_keys: &'static [&'static str],
    pub required: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatabaseGoalDefinition {
    pub key: &'static str,
    pub title: &'static str,
    pub summary: &'static str,
    pub aliases: &'static [&'static str],
    pub steps: &'static [DatabaseGoalStepDefinition],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatabaseGoalVersionRequest {
    components: [u16; 4],
    component_count: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DatabaseGoalVersionSelection {
    Unspecified,
    Valid(DatabaseGoalVersionRequest),
    Invalid,
}

impl DatabaseGoalVersionSelection {
    const fn valid(self) -> Option<DatabaseGoalVersionRequest> {
        match self {
            Self::Valid(version) => Some(version),
            Self::Unspecified | Self::Invalid => None,
        }
    }
}

impl DatabaseGoalVersionRequest {
    pub fn label(self) -> String {
        self.components[..usize::from(self.component_count)]
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(".")
    }

    pub fn matches(self, selector: DatabaseConfigVersionSelector) -> bool {
        if self.component_count == 4 {
            return selector.contains(DatabaseConfigVersion::new_with_revision(
                self.components[0],
                self.components[1],
                self.components[2],
                self.components[3],
            ));
        }
        let lower = DatabaseConfigVersion::new_with_revision(
            self.components[0],
            self.components[1],
            self.components[2],
            self.components[3],
        );
        let upper = self.upper_exclusive();
        match selector {
            DatabaseConfigVersionSelector::Exact(version) => {
                version >= lower && upper.is_none_or(|upper| version < upper)
            }
            DatabaseConfigVersionSelector::HalfOpen {
                minimum_inclusive,
                maximum_exclusive,
            } => lower < maximum_exclusive && upper.is_none_or(|upper| minimum_inclusive < upper),
        }
    }

    fn upper_exclusive(self) -> Option<DatabaseConfigVersion> {
        let mut components = self.components;
        let index = usize::from(self.component_count.checked_sub(1)?);
        components[index] = components[index].checked_add(1)?;
        components[index + 1..].fill(0);
        Some(DatabaseConfigVersion::new_with_revision(
            components[0],
            components[1],
            components[2],
            components[3],
        ))
    }
}

const MYSQL_FAMILY: &[DatabaseConfigProduct] =
    &[DatabaseConfigProduct::MySql, DatabaseConfigProduct::MariaDb];
const POSTGRES_FAMILY: &[DatabaseConfigProduct] = &[
    DatabaseConfigProduct::PostgreSql,
    DatabaseConfigProduct::OpenGauss,
    DatabaseConfigProduct::KingbaseEs,
];
const REVIEWED_LISTENER_PRODUCTS: &[DatabaseConfigProduct] = &[
    DatabaseConfigProduct::MySql,
    DatabaseConfigProduct::MariaDb,
    DatabaseConfigProduct::PostgreSql,
    DatabaseConfigProduct::OpenGauss,
    DatabaseConfigProduct::KingbaseEs,
    DatabaseConfigProduct::TiDb,
    DatabaseConfigProduct::Dm,
];
const REVIEWED_TLS_PRODUCTS: &[DatabaseConfigProduct] = &[
    DatabaseConfigProduct::MySql,
    DatabaseConfigProduct::MariaDb,
    DatabaseConfigProduct::PostgreSql,
    DatabaseConfigProduct::OpenGauss,
    DatabaseConfigProduct::KingbaseEs,
    DatabaseConfigProduct::TiDb,
    DatabaseConfigProduct::Dm,
    DatabaseConfigProduct::Yashan,
];
const REVIEWED_AUDIT_PRODUCTS: &[DatabaseConfigProduct] = &[
    DatabaseConfigProduct::MySql,
    DatabaseConfigProduct::MariaDb,
    DatabaseConfigProduct::OpenGauss,
    DatabaseConfigProduct::KingbaseEs,
    DatabaseConfigProduct::Dm,
    DatabaseConfigProduct::Yashan,
];
const REVIEWED_CONNECTION_PRODUCTS: &[DatabaseConfigProduct] = &[
    DatabaseConfigProduct::MySql,
    DatabaseConfigProduct::MariaDb,
    DatabaseConfigProduct::PostgreSql,
    DatabaseConfigProduct::OpenGauss,
    DatabaseConfigProduct::KingbaseEs,
    DatabaseConfigProduct::TiDb,
    DatabaseConfigProduct::Dm,
];

pub static DATABASE_CONFIGURATION_GOALS: &[DatabaseGoalDefinition] = &[
    DatabaseGoalDefinition {
        key: "database.remote-access",
        title: "允许数据库从远端安全访问",
        summary: "检查监听端点、数据库访问控制与网络边界；只改监听地址并不能完成远程访问。",
        aliases: &[
            "允许数据库远程连接",
            "远程连接数据库",
            "数据库外部访问",
            "开放数据库端口",
            "remote access",
        ],
        steps: &[
            DatabaseGoalStepDefinition {
                title: "监听地址",
                explanation: "决定服务绑定在哪些网络接口；通配地址会扩大暴露面。",
                products: REVIEWED_LISTENER_PRODUCTS,
                canonical_keys: &["bind_address", "listen_addresses", "host", "LISTEN_IP"],
                required: true,
            },
            DatabaseGoalStepDefinition {
                title: "监听端口",
                explanation: "端口是目标实例身份的一部分，必须与防火墙和客户端配置一致。",
                products: REVIEWED_LISTENER_PRODUCTS,
                canonical_keys: &["port"],
                required: false,
            },
            DatabaseGoalStepDefinition {
                title: "数据库访问控制",
                explanation: "还需要账号/授权或 HBA 等独立访问策略；当前主配置 schema 不能替代它。",
                products: REVIEWED_LISTENER_PRODUCTS,
                canonical_keys: &[],
                required: true,
            },
            DatabaseGoalStepDefinition {
                title: "网络与真实连接验证",
                explanation: "还需目标防火墙、路由、TLS 和真实客户端连通性验证。",
                products: REVIEWED_LISTENER_PRODUCTS,
                canonical_keys: &[],
                required: true,
            },
        ],
    },
    DatabaseGoalDefinition {
        key: "database.slow-query-observability",
        title: "开启并校准慢查询记录",
        summary: "组合启用开关、阈值、输出位置与轮转权限，避免只有开关没有可用证据。",
        aliases: &[
            "开启慢查询",
            "记录慢 SQL",
            "慢查询日志",
            "slow query logging",
        ],
        steps: &[
            DatabaseGoalStepDefinition {
                title: "启用慢查询记录",
                explanation: "启用对应产品的慢查询采集路径。",
                products: &[
                    DatabaseConfigProduct::MySql,
                    DatabaseConfigProduct::MariaDb,
                    DatabaseConfigProduct::TiDb,
                ],
                canonical_keys: &["slow_query_log", "log_slow_query", "tidb_enable_slow_log"],
                required: true,
            },
            DatabaseGoalStepDefinition {
                title: "慢查询阈值",
                explanation: "阈值过高会漏掉问题，过低会产生大量日志；必须结合负载确定。",
                products: &[
                    DatabaseConfigProduct::MySql,
                    DatabaseConfigProduct::MariaDb,
                    DatabaseConfigProduct::PostgreSql,
                    DatabaseConfigProduct::TiDb,
                ],
                canonical_keys: &[
                    "long_query_time",
                    "log_min_duration_statement",
                    "tidb_slow_log_threshold",
                ],
                required: true,
            },
            DatabaseGoalStepDefinition {
                title: "日志输出位置",
                explanation: "输出文件需要受控路径、权限、空间和轮转策略。",
                products: MYSQL_FAMILY,
                canonical_keys: &["slow_query_log_file", "log_slow_query_file"],
                required: false,
            },
            DatabaseGoalStepDefinition {
                title: "轮转、权限与回读",
                explanation: "必须验证日志实际产生、可读取且不会因磁盘耗尽影响服务。",
                products: &[
                    DatabaseConfigProduct::MySql,
                    DatabaseConfigProduct::MariaDb,
                    DatabaseConfigProduct::PostgreSql,
                    DatabaseConfigProduct::TiDb,
                ],
                canonical_keys: &[],
                required: true,
            },
        ],
    },
    DatabaseGoalDefinition {
        key: "database.tls-transport",
        title: "启用数据库传输加密",
        summary: "组合强制加密、证书链、私钥引用、最低协议版本与客户端验证。",
        aliases: &[
            "开启数据库 TLS",
            "启用 SSL",
            "加密数据库连接",
            "transport encryption",
        ],
        steps: &[
            DatabaseGoalStepDefinition {
                title: "启用或强制加密",
                explanation: "仅配置证书不等于所有客户端都被强制使用加密连接。",
                products: REVIEWED_TLS_PRODUCTS,
                canonical_keys: &[
                    "require_secure_transport",
                    "ssl",
                    "SSL_ENABLE",
                    "ENABLE_ENCRYPT",
                ],
                required: true,
            },
            DatabaseGoalStepDefinition {
                title: "CA 与服务端证书",
                explanation: "证书、CA 和主机身份必须匹配并由目标进程可读取。",
                products: REVIEWED_TLS_PRODUCTS,
                canonical_keys: &[
                    "ssl_ca",
                    "ssl_ca_file",
                    "ssl-ca",
                    "ssl_cert",
                    "ssl_cert_file",
                    "ssl-cert",
                ],
                required: true,
            },
            DatabaseGoalStepDefinition {
                title: "私钥引用",
                explanation: "私钥路径属于非公开元数据；目标配方只说明，不读取或复制秘密。",
                products: REVIEWED_TLS_PRODUCTS,
                canonical_keys: &["ssl_key", "ssl_key_file", "ssl-key"],
                required: true,
            },
            DatabaseGoalStepDefinition {
                title: "最低协议版本",
                explanation: "禁用过时协议，同时确认目标二进制实际支持所选版本。",
                products: REVIEWED_TLS_PRODUCTS,
                canonical_keys: &[
                    "tls_version",
                    "tls-version",
                    "ssl_min_protocol_version",
                    "MIN_SSL_VERSION",
                ],
                required: false,
            },
            DatabaseGoalStepDefinition {
                title: "客户端策略与握手验证",
                explanation: "还需访问规则、客户端证书策略和真实 TLS 握手回读。",
                products: REVIEWED_TLS_PRODUCTS,
                canonical_keys: &[],
                required: true,
            },
        ],
    },
    DatabaseGoalDefinition {
        key: "database.auditing",
        title: "启用并保全数据库审计",
        summary: "核对审计能力、启停、事件范围、输出和保留策略，避免只有开关没有证据。",
        aliases: &[
            "开启数据库审计",
            "保留审计日志",
            "数据库操作留痕",
            "database auditing",
        ],
        steps: &[
            DatabaseGoalStepDefinition {
                title: "审计能力与启停",
                explanation: "插件、预加载或版本能力必须先被目标回读证明。",
                products: REVIEWED_AUDIT_PRODUCTS,
                canonical_keys: &[
                    "audit_enabled",
                    "audit_log_disable",
                    "server_audit_logging",
                    "sysaudit.enable",
                    "UNIFIED_AUDITING",
                    "ENABLE_AUDIT",
                ],
                required: true,
            },
            DatabaseGoalStepDefinition {
                title: "事件范围",
                explanation: "登录、权限违规、对象操作等事件范围必须符合审计目标。",
                products: REVIEWED_AUDIT_PRODUCTS,
                canonical_keys: &[
                    "audit_login_logout",
                    "audit_user_violation",
                    "audit_system_object",
                    "server_audit_events",
                ],
                required: false,
            },
            DatabaseGoalStepDefinition {
                title: "输出与保留",
                explanation: "输出位置、数量、空间和满盘行为决定证据是否可持续保存。",
                products: REVIEWED_AUDIT_PRODUCTS,
                canonical_keys: &[
                    "audit_directory",
                    "AUDIT_LOG_FILE_COUNT",
                    "AUDIT_KEEP_DAYS",
                    "AUDIT_SPACE_LIMIT",
                    "AUDIT_MAX_FILE_SIZE",
                ],
                required: false,
            },
            DatabaseGoalStepDefinition {
                title: "实际事件回读",
                explanation: "需要在目标上产生受控测试事件并确认审计记录可检索。",
                products: REVIEWED_AUDIT_PRODUCTS,
                canonical_keys: &[],
                required: true,
            },
        ],
    },
    DatabaseGoalDefinition {
        key: "database.connection-capacity",
        title: "调整数据库连接容量",
        summary: "设置连接上限并核算每连接内存、保留连接、线程和操作系统资源。",
        aliases: &[
            "提高最大连接数",
            "增加并发连接",
            "连接数不够",
            "connection capacity",
        ],
        steps: &[
            DatabaseGoalStepDefinition {
                title: "最大连接或会话数",
                explanation: "这是容量上限，不是孤立的性能开关。",
                products: REVIEWED_CONNECTION_PRODUCTS,
                canonical_keys: &["max_connections", "MAX_SESSIONS"],
                required: true,
            },
            DatabaseGoalStepDefinition {
                title: "保留连接",
                explanation: "保留管理员连接可以避免连接耗尽时完全失去处置入口。",
                products: POSTGRES_FAMILY,
                canonical_keys: &["superuser_reserved_connections", "reserved_connections"],
                required: false,
            },
            DatabaseGoalStepDefinition {
                title: "内存、线程与系统限制核算",
                explanation: "还需按单连接内存、线程模型、文件描述符和许可证计算安全上限。",
                products: REVIEWED_CONNECTION_PRODUCTS,
                canonical_keys: &[],
                required: true,
            },
            DatabaseGoalStepDefinition {
                title: "压力与拒绝服务验证",
                explanation: "目标值需要通过受控并发测试和资源回读验证。",
                products: REVIEWED_CONNECTION_PRODUCTS,
                canonical_keys: &[],
                required: true,
            },
        ],
    },
    DatabaseGoalDefinition {
        key: "database.query-timeout",
        title: "限制单条 SQL 的执行时间",
        summary: "设置语句超时，并明确它是默认值、会话值还是特定角色策略。",
        aliases: &[
            "SQL 执行超时",
            "终止长时间查询",
            "查询超时",
            "statement timeout",
        ],
        steps: &[
            DatabaseGoalStepDefinition {
                title: "语句超时",
                explanation: "限制单条语句运行时间；零值通常有禁用含义，必须按 schema 校验。",
                products: &[DatabaseConfigProduct::PostgreSql],
                canonical_keys: &["statement_timeout"],
                required: true,
            },
            DatabaseGoalStepDefinition {
                title: "角色/会话覆盖关系",
                explanation: "配置文件默认值可能被角色、数据库或会话设置覆盖。",
                products: &[DatabaseConfigProduct::PostgreSql],
                canonical_keys: &[],
                required: true,
            },
        ],
    },
    DatabaseGoalDefinition {
        key: "database.transaction-durability",
        title: "提高事务提交持久性",
        summary: "核对提交确认与日志 I/O 模式，并用故障恢复测试验证数据丢失边界。",
        aliases: &[
            "避免宕机丢数据",
            "提高事务持久性",
            "日志刷盘",
            "transaction durability",
        ],
        steps: &[
            DatabaseGoalStepDefinition {
                title: "提交确认策略",
                explanation: "同步提交级别决定客户端何时收到成功以及故障时可能丢失的范围。",
                products: &[
                    DatabaseConfigProduct::PostgreSql,
                    DatabaseConfigProduct::OpenGauss,
                ],
                canonical_keys: &["synchronous_commit"],
                required: true,
            },
            DatabaseGoalStepDefinition {
                title: "Redo I/O 模式",
                explanation: "缓存和同步写模式改变掉电后的持久性保证。",
                products: &[DatabaseConfigProduct::Yashan],
                canonical_keys: &["REDOFILE_IO_MODE"],
                required: true,
            },
            DatabaseGoalStepDefinition {
                title: "复制与存储故障验证",
                explanation: "还需匹配复制拓扑、存储语义并执行受控崩溃恢复测试。",
                products: &[
                    DatabaseConfigProduct::PostgreSql,
                    DatabaseConfigProduct::OpenGauss,
                    DatabaseConfigProduct::Yashan,
                ],
                canonical_keys: &[],
                required: true,
            },
        ],
    },
    DatabaseGoalDefinition {
        key: "database.password-storage",
        title: "加强数据库密码存储算法",
        summary: "选择已审密码哈希设置，并规划已有凭据迁移与重新设密。",
        aliases: &[
            "加强密码哈希",
            "密码加密方式",
            "升级密码算法",
            "password hashing",
        ],
        steps: &[
            DatabaseGoalStepDefinition {
                title: "密码存储算法",
                explanation: "通常只影响之后创建或修改的密码，不会自动重写已有凭据。",
                products: POSTGRES_FAMILY,
                canonical_keys: &["password_encryption", "password_encryption_type"],
                required: true,
            },
            DatabaseGoalStepDefinition {
                title: "已有凭据迁移",
                explanation: "必须盘点角色并通过受控重设密码完成迁移，不能从配置值推断已完成。",
                products: POSTGRES_FAMILY,
                canonical_keys: &[],
                required: true,
            },
        ],
    },
    DatabaseGoalDefinition {
        key: "database.connection-admission-guardrails",
        title: "限制连接建立阶段的资源占用",
        summary: "组合连接握手/认证超时与错误连接阈值，并把连接池重试预算和真实连接验证列为必需步骤。",
        aliases: &[
            "防止慢连接耗尽数据库",
            "设置数据库连接超时",
            "限制认证等待时间",
            "connection admission timeout",
        ],
        steps: &[
            DatabaseGoalStepDefinition {
                title: "连接握手超时",
                explanation: "限制客户端完成连接握手可占用服务端资源的时间。",
                products: MYSQL_FAMILY,
                canonical_keys: &["connect_timeout"],
                required: true,
            },
            DatabaseGoalStepDefinition {
                title: "认证超时",
                explanation: "限制 PostgreSQL 客户端完成认证可占用后端进程的时间。",
                products: &[DatabaseConfigProduct::PostgreSql],
                canonical_keys: &["authentication_timeout"],
                required: true,
            },
            DatabaseGoalStepDefinition {
                title: "错误连接阈值",
                explanation: "阈值过低会阻断响应人员，过高会减弱错误连接抑制。",
                products: MYSQL_FAMILY,
                canonical_keys: &["max_connect_errors"],
                required: false,
            },
            DatabaseGoalStepDefinition {
                title: "连接池预算、受控连接与运行时回读",
                explanation: "还必须核对客户端/连接池重试预算，并用成功与失败连接验证目标实际值；本地草稿不能证明完成。",
                products: &[
                    DatabaseConfigProduct::MySql,
                    DatabaseConfigProduct::MariaDb,
                    DatabaseConfigProduct::PostgreSql,
                ],
                canonical_keys: &[],
                required: true,
            },
        ],
    },
    DatabaseGoalDefinition {
        key: "database.idle-session-protection",
        title: "回收空闲或持锁的数据库会话",
        summary: "配置空闲会话边界，同时把连接池 keepalive、交互会话差异和持锁会话验证列为必需步骤。",
        aliases: &[
            "清理数据库空闲连接",
            "限制空闲事务会话",
            "防止连接池空闲会话耗尽",
            "idle session timeout",
        ],
        steps: &[
            DatabaseGoalStepDefinition {
                title: "非交互空闲会话超时",
                explanation: "限制 MySQL/MariaDB 非交互连接空闲占用连接槽的时间。",
                products: MYSQL_FAMILY,
                canonical_keys: &["wait_timeout"],
                required: true,
            },
            DatabaseGoalStepDefinition {
                title: "空闲事务超时",
                explanation: "限制 PostgreSQL 已开启事务但长期空闲、可能继续持锁的会话。",
                products: &[DatabaseConfigProduct::PostgreSql],
                canonical_keys: &["idle_in_transaction_session_timeout"],
                required: true,
            },
            DatabaseGoalStepDefinition {
                title: "连接池与真实会话验证",
                explanation: "还必须区分交互/非交互连接、核对连接池 keepalive，并验证持锁和普通空闲会话的真实行为。",
                products: &[
                    DatabaseConfigProduct::MySql,
                    DatabaseConfigProduct::MariaDb,
                    DatabaseConfigProduct::PostgreSql,
                ],
                canonical_keys: &[],
                required: true,
            },
        ],
    },
    DatabaseGoalDefinition {
        key: "database.connection-event-logging",
        title: "记录数据库连接与断开事件",
        summary: "组合日志采集器、输出目标和连接事件开关，并要求验证实际日志、权限、磁盘与轮转。",
        aliases: &[
            "记录数据库登录日志",
            "记录连接和断开事件",
            "开启连接审计日志",
            "connection event logging",
        ],
        steps: &[
            DatabaseGoalStepDefinition {
                title: "启动日志采集器",
                explanation: "确认 stderr/csvlog/jsonlog 等目标由采集器接管，而不是只设置事件开关。",
                products: &[
                    DatabaseConfigProduct::PostgreSql,
                    DatabaseConfigProduct::KingbaseEs,
                ],
                canonical_keys: &["logging_collector"],
                required: true,
            },
            DatabaseGoalStepDefinition {
                title: "日志输出格式",
                explanation: "选择与现有采集和解析链兼容的日志输出目标。",
                products: &[
                    DatabaseConfigProduct::PostgreSql,
                    DatabaseConfigProduct::KingbaseEs,
                ],
                canonical_keys: &["log_destination"],
                required: true,
            },
            DatabaseGoalStepDefinition {
                title: "记录连接事件",
                explanation: "启用连接建立记录，并可选记录断开事件。",
                products: &[
                    DatabaseConfigProduct::PostgreSql,
                    DatabaseConfigProduct::KingbaseEs,
                ],
                canonical_keys: &["log_connections"],
                required: true,
            },
            DatabaseGoalStepDefinition {
                title: "记录断开事件",
                explanation: "记录会话断开，便于建立连接生命周期证据。",
                products: &[DatabaseConfigProduct::PostgreSql],
                canonical_keys: &["log_disconnections"],
                required: false,
            },
            DatabaseGoalStepDefinition {
                title: "受控登录、落盘、权限与轮转验证",
                explanation: "还必须执行受控登录/断开并读取真实日志，同时核对权限、磁盘预算和轮转；本地草稿不能证明完成。",
                products: &[
                    DatabaseConfigProduct::PostgreSql,
                    DatabaseConfigProduct::KingbaseEs,
                ],
                canonical_keys: &[],
                required: true,
            },
        ],
    },
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedDatabaseGoalStep {
    definition: &'static DatabaseGoalStepDefinition,
    parameter_indices: Vec<usize>,
}

impl ResolvedDatabaseGoalStep {
    pub const fn definition(&self) -> &'static DatabaseGoalStepDefinition {
        self.definition
    }

    pub fn parameter_indices(&self) -> &[usize] {
        &self.parameter_indices
    }

    pub fn is_missing_required(&self) -> bool {
        self.definition.required && self.parameter_indices.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DatabaseGoalResolution {
    schema: &'static DatabaseConfigSchema,
    steps: Vec<ResolvedDatabaseGoalStep>,
}

impl DatabaseGoalResolution {
    pub const fn schema(&self) -> &'static DatabaseConfigSchema {
        self.schema
    }

    pub fn steps(&self) -> &[ResolvedDatabaseGoalStep] {
        &self.steps
    }

    pub fn reviewed_parameter_count(&self) -> usize {
        self.steps
            .iter()
            .map(|step| step.parameter_indices.len())
            .sum()
    }

    pub fn missing_required_count(&self) -> usize {
        self.steps
            .iter()
            .filter(|step| step.is_missing_required())
            .count()
    }
}

pub fn database_goal_resolutions(
    goal: &'static DatabaseGoalDefinition,
    product: DatabaseConfigProduct,
) -> Vec<DatabaseGoalResolution> {
    database_goal_resolutions_for_version(goal, product, None)
}

pub fn database_goal_resolutions_for_version(
    goal: &'static DatabaseGoalDefinition,
    product: DatabaseConfigProduct,
    version: Option<DatabaseGoalVersionRequest>,
) -> Vec<DatabaseGoalResolution> {
    DATABASE_CONFIG_SCHEMAS
        .iter()
        .filter(|schema| schema.binding.product == product)
        .filter(|schema| version.is_none_or(|version| version.matches(schema.binding.versions)))
        .filter_map(|schema| resolve_database_goal_for_schema(goal, schema))
        .collect()
}

fn resolve_database_goal_for_schema(
    goal: &'static DatabaseGoalDefinition,
    schema: &'static DatabaseConfigSchema,
) -> Option<DatabaseGoalResolution> {
    let steps = goal
        .steps
        .iter()
        .filter(|step| step.products.contains(&schema.binding.product))
        .map(|step| ResolvedDatabaseGoalStep {
            definition: step,
            parameter_indices: schema
                .parameters
                .iter()
                .enumerate()
                .filter_map(|(index, parameter)| {
                    step.canonical_keys
                        .contains(&parameter.canonical_key)
                        .then_some(index)
                })
                .collect(),
        })
        .collect::<Vec<_>>();
    let reviewed_parameter_count = steps
        .iter()
        .map(|step| step.parameter_indices.len())
        .sum::<usize>();
    (!steps.is_empty() && reviewed_parameter_count > 0)
        .then_some(DatabaseGoalResolution { schema, steps })
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ConfigurationGoalSubject {
    Middleware(MiddlewareProduct),
    Database(DatabaseConfigProduct),
}

impl ConfigurationGoalSubject {
    pub fn label(self) -> &'static str {
        match self {
            Self::Middleware(product) => product.label(),
            Self::Database(product) => database_product(product)
                .map_or("未知数据库产品", |definition| definition.label),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationGoalAvailability {
    /// A closed typed recipe can produce a local draft.
    LocalDraftRecipe,
    /// Reviewed metadata can explain the goal, but cannot produce a value.
    CatalogGuidance,
    /// The product is catalogued but has no reviewed goal semantics yet.
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationGoalSupportGap {
    MissingReviewedIntent,
    MissingReviewedRecipe,
    MissingExactSchema,
    MissingVersion,
    MissingEditableArtifact,
    MissingTypedValidator,
    MissingRuntimeCapability,
    MissingExternalEvidence,
    SensitiveValue,
}

impl ConfigurationGoalSupportGap {
    pub const fn label(self) -> &'static str {
        match self {
            Self::MissingReviewedIntent => "当前目标尚未收录",
            Self::MissingReviewedRecipe => "缺少经过审查的目标配方",
            Self::MissingExactSchema => "缺少精确版本 Schema",
            Self::MissingVersion => "请求的版本尚未登记",
            Self::MissingEditableArtifact => "缺少可安全生成的配置工件",
            Self::MissingTypedValidator => "缺少类型化值校验器",
            Self::MissingRuntimeCapability => "缺少目标运行时能力证据",
            Self::MissingExternalEvidence => "还缺目标外部步骤与回读证据",
            Self::SensitiveValue => "敏感值不能进入界面草稿",
        }
    }

    pub const fn explanation(self) -> &'static str {
        match self {
            Self::MissingReviewedIntent => {
                "产品已有部分目标或参数依据，但本次自然语言意图没有闭合匹配；不会拿相邻配方猜测。"
            }
            Self::MissingReviewedRecipe => {
                "当前只有产品或语法层登记，没有能把该目标转换成受控字段的类型化配方。"
            }
            Self::MissingExactSchema => {
                "已经知道配置工件，但没有与精确产品版本和 edition 绑定的参数语义。"
            }
            Self::MissingVersion => {
                "查询指定了产品版本，但当前注册表没有覆盖该版本；不会借用相邻版本的配置语义。"
            }
            Self::MissingEditableArtifact => {
                "参数依据存在，但对应工件只读、方言未建模，或不能保持本地无损草稿语义。"
            }
            Self::MissingTypedValidator => {
                "字段名称可见，但合法值、范围、单位或规范化规则尚未形成闭合校验器。"
            }
            Self::MissingRuntimeCapability => {
                "该配置依赖插件、模块或目标能力，当前没有与目标身份绑定的可靠探测结果。"
            }
            Self::MissingExternalEvidence => {
                "主配置只能完成目标的一部分；访问控制、网络、重载或实际回读仍需独立证明。"
            }
            Self::SensitiveValue => {
                "该字段可能包含凭据、私钥或其他秘密，界面不会保存、回显或复制其明文。"
            }
        }
    }

    pub const fn acceptance(self) -> &'static str {
        match self {
            Self::MissingReviewedIntent => "补充该产品的闭合目标定义、边界测试与明确完成条件。",
            Self::MissingReviewedRecipe => "新增 core 类型化配方、注入边界测试和本地草稿验收。",
            Self::MissingExactSchema => "绑定精确版本/edition、官方字段语义和值域后才能开放。",
            Self::MissingVersion => "新增该精确版本的官方 Schema 绑定和边界测试后才能开放。",
            Self::MissingEditableArtifact => "先证明工件、方言与无损写入策略，再开放本地生成。",
            Self::MissingTypedValidator => "补齐精确值域、单位、别名和边界测试后才能生成。",
            Self::MissingRuntimeCapability => "采集同一 TargetGuard 下的能力证据并在使用前复核。",
            Self::MissingExternalEvidence => "补齐外部步骤、目标校验、回读和真实请求/连接验证。",
            Self::SensitiveValue => "改用 core 凭据类型和不回显的目标侧安全写入流程。",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationGoalRecipeAction {
    NginxStaticSite,
    NginxReverseProxy,
    NginxForbiddenPath403,
    ApacheForbiddenPath403,
    ApacheDisableTrace,
    ApacheReduceVersionDisclosure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigurationGoalRecipe {
    pub key: &'static str,
    pub subject: ConfigurationGoalSubject,
    pub title: &'static str,
    pub summary: &'static str,
    pub expected_effect: &'static str,
    pub aliases: &'static [&'static str],
    pub action: ConfigurationGoalRecipeAction,
    pub availability: ConfigurationGoalAvailability,
}

pub static CONFIGURATION_GOAL_RECIPES: &[ConfigurationGoalRecipe] = &[
    ConfigurationGoalRecipe {
        key: "nginx.static-site",
        subject: ConfigurationGoalSubject::Middleware(MiddlewareProduct::Nginx),
        title: "用指定目录提供静态站点",
        summary: "填写域名、监听端口与本地站点目录，生成 Nginx 静态站点本地草稿。",
        expected_effect: "匹配该 server 的请求从指定 root 目录提供文件；部署前仍需 nginx -t。",
        aliases: NGINX_STATIC_SITE_ALIASES,
        action: ConfigurationGoalRecipeAction::NginxStaticSite,
        availability: ConfigurationGoalAvailability::LocalDraftRecipe,
    },
    ConfigurationGoalRecipe {
        key: "nginx.reverse-proxy",
        subject: ConfigurationGoalSubject::Middleware(MiddlewareProduct::Nginx),
        title: "把站点请求转发到后端服务",
        summary: "填写域名、监听端口与经过校验的 HTTP(S) upstream，生成反向代理本地草稿。",
        expected_effect: "匹配该 server 的请求转发到指定后端，并附带已审查的代理请求头。",
        aliases: NGINX_REVERSE_PROXY_ALIASES,
        action: ConfigurationGoalRecipeAction::NginxReverseProxy,
        availability: ConfigurationGoalAvailability::LocalDraftRecipe,
    },
    ConfigurationGoalRecipe {
        key: "nginx.forbidden-path-403",
        subject: ConfigurationGoalSubject::Middleware(MiddlewareProduct::Nginx),
        title: "禁止指定路径（HTTP 403）",
        summary: "按规范 URI 路径拒绝访问，可选择仅精确路径或同时覆盖其子路径。",
        expected_effect: "/admin、/admin/ 与 /admin/users 可返回 403；/administrator 不受影响。",
        aliases: NGINX_FORBIDDEN_PATH_ALIASES,
        action: ConfigurationGoalRecipeAction::NginxForbiddenPath403,
        availability: ConfigurationGoalAvailability::LocalDraftRecipe,
    },
    ConfigurationGoalRecipe {
        key: "apache.forbidden-path-403",
        subject: ConfigurationGoalSubject::Middleware(MiddlewareProduct::ApacheHttpd),
        title: "禁止指定路径及其子路径（HTTP 403）",
        summary: "为规范 URI 路径生成边界明确的 LocationMatch 与 Require all denied 本地草稿。",
        expected_effect: "/admin、/admin/ 与 /admin/users 对所有来源（含本机）返回 403，/administrator 不受影响；仍需核验 mod_authz_core、配置合并顺序、httpd -t 与真实请求。",
        aliases: APACHE_FORBIDDEN_PATH_ALIASES,
        action: ConfigurationGoalRecipeAction::ApacheForbiddenPath403,
        availability: ConfigurationGoalAvailability::LocalDraftRecipe,
    },
    ConfigurationGoalRecipe {
        key: "apache.disable-trace",
        subject: ConfigurationGoalSubject::Middleware(MiddlewareProduct::ApacheHttpd),
        title: "Apache 禁用 TRACE 方法",
        summary: "生成只包含 Apache core TraceEnable Off 的 server-config 本地草稿。",
        expected_effect: "Apache core 与 mod_proxy 对 TRACE 请求返回 405；这是一项方法策略，不代表 TRACE 本身是漏洞。",
        aliases: APACHE_DISABLE_TRACE_ALIASES,
        action: ConfigurationGoalRecipeAction::ApacheDisableTrace,
        availability: ConfigurationGoalAvailability::LocalDraftRecipe,
    },
    ConfigurationGoalRecipe {
        key: "apache.reduce-version-disclosure",
        subject: ConfigurationGoalSubject::Middleware(MiddlewareProduct::ApacheHttpd),
        title: "Apache 减少版本信息暴露",
        summary: "生成 ServerTokens Prod 与 ServerSignature Off 的全局 server-config 本地草稿。",
        expected_effect: "仍会标识 Apache，但不再披露版本、操作系统和模块细节，并关闭服务器生成页面的页脚签名。",
        aliases: APACHE_REDUCE_VERSION_DISCLOSURE_ALIASES,
        action: ConfigurationGoalRecipeAction::ApacheReduceVersionDisclosure,
        availability: ConfigurationGoalAvailability::LocalDraftRecipe,
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationGoalMatch {
    Recipe(&'static ConfigurationGoalRecipe),
    DatabaseArtifact {
        artifact: &'static DatabaseConfigArtifactDefinition,
    },
    DatabaseGoal {
        goal: &'static DatabaseGoalDefinition,
        product: DatabaseConfigProduct,
        version: Option<DatabaseGoalVersionRequest>,
    },
    DatabaseParameter {
        schema: &'static DatabaseConfigSchema,
        parameter_index: usize,
    },
    UnavailableSubject {
        coverage: ConfigurationGoalCoverage,
        gap: ConfigurationGoalSupportGap,
    },
}

impl ConfigurationGoalMatch {
    pub fn availability(self) -> ConfigurationGoalAvailability {
        match self {
            Self::Recipe(recipe) => recipe.availability,
            Self::DatabaseArtifact { artifact } => database_artifact_goal_availability(artifact),
            Self::DatabaseGoal { .. } => ConfigurationGoalAvailability::CatalogGuidance,
            Self::DatabaseParameter {
                schema,
                parameter_index,
            } => database_parameter_goal_availability(schema, parameter_index),
            Self::UnavailableSubject { .. } => ConfigurationGoalAvailability::Unavailable,
        }
    }

    pub fn subject(self) -> ConfigurationGoalSubject {
        match self {
            Self::Recipe(recipe) => recipe.subject,
            Self::DatabaseArtifact { artifact } => {
                ConfigurationGoalSubject::Database(artifact.product)
            }
            Self::DatabaseGoal { product, .. } => ConfigurationGoalSubject::Database(product),
            Self::DatabaseParameter { schema, .. } => {
                ConfigurationGoalSubject::Database(schema.binding.product)
            }
            Self::UnavailableSubject { coverage, .. } => coverage.subject,
        }
    }

    pub fn database_parameter(self) -> Option<&'static DatabaseConfigParameterSchema> {
        match self {
            Self::Recipe(_) => None,
            Self::DatabaseArtifact { .. } => None,
            Self::DatabaseGoal { .. } => None,
            Self::UnavailableSubject { .. } => None,
            Self::DatabaseParameter {
                schema,
                parameter_index,
            } => schema.parameters.get(parameter_index),
        }
    }

    pub fn support_gap(self) -> Option<ConfigurationGoalSupportGap> {
        match self {
            Self::Recipe(_) => None,
            Self::DatabaseArtifact { artifact } => database_artifact_goal_support_gap(artifact),
            Self::DatabaseGoal {
                goal,
                product,
                version,
            } => {
                let resolutions = database_goal_resolutions_for_version(goal, product, version);
                if resolutions.iter().any(|resolution| {
                    resolution.steps().iter().any(|step| {
                        step.is_missing_required() && !step.definition().canonical_keys.is_empty()
                    })
                }) {
                    Some(ConfigurationGoalSupportGap::MissingEditableArtifact)
                } else if resolutions
                    .iter()
                    .any(|resolution| resolution.missing_required_count() > 0)
                {
                    Some(ConfigurationGoalSupportGap::MissingExternalEvidence)
                } else {
                    None
                }
            }
            Self::DatabaseParameter {
                schema,
                parameter_index,
            } => database_parameter_goal_support(schema, parameter_index)
                .err()
                .map(database_parameter_support_gap),
            Self::UnavailableSubject { gap, .. } => Some(gap),
        }
    }
}

pub const fn database_artifact_goal_availability(
    artifact: &DatabaseConfigArtifactDefinition,
) -> ConfigurationGoalAvailability {
    if artifact.has_source_backed_visual_parser() {
        // An artifact parser opens a byte-preserving workspace; it is not a
        // reviewed operator-intent recipe and must not be presented as one.
        ConfigurationGoalAvailability::CatalogGuidance
    } else {
        ConfigurationGoalAvailability::Unavailable
    }
}

pub const fn database_artifact_goal_support_gap(
    artifact: &DatabaseConfigArtifactDefinition,
) -> Option<ConfigurationGoalSupportGap> {
    if artifact.has_source_backed_visual_parser() {
        return if !artifact.allows_lossless_local_draft() {
            Some(ConfigurationGoalSupportGap::MissingEditableArtifact)
        } else {
            None
        };
    }

    Some(match artifact.surface {
        DatabaseConfigSurface::RuntimeSql => ConfigurationGoalSupportGap::MissingRuntimeCapability,
        DatabaseConfigSurface::CloudApi => ConfigurationGoalSupportGap::MissingExternalEvidence,
        DatabaseConfigSurface::File | DatabaseConfigSurface::GeneratedReadOnly => {
            if matches!(
                artifact.support,
                DatabaseConfigSupportLevel::VendorSchemaRequired
            ) {
                ConfigurationGoalSupportGap::MissingExactSchema
            } else {
                ConfigurationGoalSupportGap::MissingTypedValidator
            }
        }
    })
}

fn database_parameter_support_gap(
    error: DatabaseParameterGoalDraftError,
) -> ConfigurationGoalSupportGap {
    match error {
        DatabaseParameterGoalDraftError::SchemaUnavailable
        | DatabaseParameterGoalDraftError::UnknownParameter => {
            ConfigurationGoalSupportGap::MissingExactSchema
        }
        DatabaseParameterGoalDraftError::ArtifactUnavailable
        | DatabaseParameterGoalDraftError::ArtifactBindingMismatch
        | DatabaseParameterGoalDraftError::ReadOnlyArtifact
        | DatabaseParameterGoalDraftError::UnsupportedDialect => {
            ConfigurationGoalSupportGap::MissingEditableArtifact
        }
        DatabaseParameterGoalDraftError::NonPublicParameter => {
            ConfigurationGoalSupportGap::SensitiveValue
        }
        DatabaseParameterGoalDraftError::RequiredCapability => {
            ConfigurationGoalSupportGap::MissingRuntimeCapability
        }
        DatabaseParameterGoalDraftError::VisibleUnvalidated
        | DatabaseParameterGoalDraftError::InvalidValue(_)
        | DatabaseParameterGoalDraftError::UnsafeValue
        | DatabaseParameterGoalDraftError::EmptyValueUnsupported => {
            ConfigurationGoalSupportGap::MissingTypedValidator
        }
    }
}

/// Why a reviewed database parameter cannot currently become a local draft.
///
/// This is deliberately separate from target validation: even a locally
/// draftable parameter remains unverified for any concrete server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseParameterGoalDraftError {
    SchemaUnavailable,
    UnknownParameter,
    ArtifactUnavailable,
    ArtifactBindingMismatch,
    ReadOnlyArtifact,
    UnsupportedDialect,
    NonPublicParameter,
    RequiredCapability,
    VisibleUnvalidated,
    InvalidValue(DatabaseConfigSchemaValueError),
    UnsafeValue,
    EmptyValueUnsupported,
}

#[derive(Clone)]
pub struct DatabaseParameterGoalDraft {
    container_path: Option<&'static str>,
    canonical_key: &'static str,
    normalized_value: String,
}

impl fmt::Debug for DatabaseParameterGoalDraft {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatabaseParameterGoalDraft")
            .field("container_path", &self.container_path)
            .field("canonical_key", &self.canonical_key)
            .field("normalized_value_bytes", &self.normalized_value.len())
            .finish()
    }
}

impl DatabaseParameterGoalDraft {
    pub const fn container_path(&self) -> Option<&'static str> {
        self.container_path
    }

    pub const fn canonical_key(&self) -> &'static str {
        self.canonical_key
    }

    pub fn normalized_value(&self) -> &str {
        &self.normalized_value
    }
}

/// One exact, registry-owned parameter identity selected by an assignment.
///
/// Equality deliberately uses schema identity rather than structural equality:
/// callers may only select a candidate returned by this module from the live
/// static registry.
#[derive(Clone, Copy)]
pub struct DatabaseParameterAssignmentTarget {
    schema: &'static DatabaseConfigSchema,
    parameter_index: usize,
}

impl PartialEq for DatabaseParameterAssignmentTarget {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self.schema, other.schema) && self.parameter_index == other.parameter_index
    }
}

impl Eq for DatabaseParameterAssignmentTarget {}

impl fmt::Debug for DatabaseParameterAssignmentTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let parameter = self.parameter();
        formatter
            .debug_struct("DatabaseParameterAssignmentTarget")
            .field("product", &self.schema.binding.product)
            .field("version_label", &self.schema.version_label)
            .field("artifact_key", &self.schema.binding.artifact_key)
            .field("container_path", &parameter.container_path)
            .field("canonical_key", &parameter.canonical_key)
            .finish()
    }
}

impl DatabaseParameterAssignmentTarget {
    pub const fn schema(&self) -> &'static DatabaseConfigSchema {
        self.schema
    }

    pub const fn parameter_index(&self) -> usize {
        self.parameter_index
    }

    pub fn parameter(&self) -> &'static DatabaseConfigParameterSchema {
        &self.schema.parameters[self.parameter_index]
    }
}

/// A uniquely resolved, schema-normalized local-draft assignment.
///
/// This object contains no target compatibility, capability, activation, or
/// deployment evidence. Consumers must revalidate it immediately before using
/// the draft in a local document mutation.
#[derive(Clone)]
pub struct DatabaseParameterAssignment {
    target: DatabaseParameterAssignmentTarget,
    draft: DatabaseParameterGoalDraft,
}

impl fmt::Debug for DatabaseParameterAssignment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatabaseParameterAssignment")
            .field("target", &self.target)
            .field("draft", &self.draft)
            .finish()
    }
}

impl DatabaseParameterAssignment {
    pub const fn target(&self) -> DatabaseParameterAssignmentTarget {
        self.target
    }

    pub const fn schema(&self) -> &'static DatabaseConfigSchema {
        self.target.schema
    }

    pub const fn parameter_index(&self) -> usize {
        self.target.parameter_index
    }

    pub const fn draft(&self) -> &DatabaseParameterGoalDraft {
        &self.draft
    }
}

/// Bounded candidate set for an assignment whose schema/container identity is
/// not unique. The unnormalized value remains core-owned and zeroized; callers
/// select one returned target and never receive the pending value itself.
pub struct DatabaseParameterAssignmentAmbiguity {
    candidates: Vec<DatabaseParameterAssignmentTarget>,
    pending_value: Zeroizing<String>,
}

impl fmt::Debug for DatabaseParameterAssignmentAmbiguity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatabaseParameterAssignmentAmbiguity")
            .field("candidates", &self.candidates)
            .finish()
    }
}

impl DatabaseParameterAssignmentAmbiguity {
    pub fn candidates(&self) -> &[DatabaseParameterAssignmentTarget] {
        &self.candidates
    }
}

/// A typed assignment failure. No variant contains the submitted value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseParameterAssignmentError {
    QueryTooLong,
    InvalidQuery,
    UnsupportedOperator,
    MissingTarget,
    MissingValue,
    MultipleOperators,
    MissingProduct,
    AmbiguousProduct,
    InvalidVersion,
    MissingVersion,
    MissingExactSchema,
    MissingParameter,
    InvalidQualifier,
    UnknownArtifact,
    ArtifactProductMismatch,
    UnknownContainer,
    UnknownParameter,
    UnknownCandidate,
    TooManyCandidates,
    Draft(DatabaseParameterGoalDraftError),
}

impl From<DatabaseParameterGoalDraftError> for DatabaseParameterAssignmentError {
    fn from(error: DatabaseParameterGoalDraftError) -> Self {
        Self::Draft(error)
    }
}

/// Result of recognizing the closed database assignment grammar.
///
/// `NotAssignment` is returned only when no supported or assignment-like
/// operator is present. Once an assignment shape is recognized, every failure
/// remains typed here so callers cannot silently fall back to fuzzy goal search.
#[derive(Debug)]
pub enum DatabaseParameterAssignmentResolution {
    NotAssignment,
    Ready(DatabaseParameterAssignment),
    Ambiguous(DatabaseParameterAssignmentAmbiguity),
    Rejected(DatabaseParameterAssignmentError),
}

pub fn database_parameter_goal_availability(
    schema: &'static DatabaseConfigSchema,
    parameter_index: usize,
) -> ConfigurationGoalAvailability {
    database_parameter_goal_support(schema, parameter_index)
        .map_or(ConfigurationGoalAvailability::CatalogGuidance, |()| {
            ConfigurationGoalAvailability::LocalDraftRecipe
        })
}

/// Validates one projected database parameter and returns only its canonical,
/// public value. This creates local-draft input, not target compatibility,
/// capability, activation, or deployment evidence.
pub fn validate_database_parameter_goal_value(
    schema: &'static DatabaseConfigSchema,
    parameter_index: usize,
    raw_value: &str,
) -> Result<DatabaseParameterGoalDraft, DatabaseParameterGoalDraftError> {
    database_parameter_goal_support(schema, parameter_index)?;
    let parameter = &schema.parameters[parameter_index];
    let validation = schema.validate_normalized_value(
        DatabaseConfigParameterLocator {
            container_path: parameter.container_path,
            key: parameter.canonical_key,
        },
        raw_value,
    );
    match validation.status() {
        DatabaseConfigSchemaValidationStatus::SyntaxValid => {}
        DatabaseConfigSchemaValidationStatus::Invalid(error) => {
            return Err(DatabaseParameterGoalDraftError::InvalidValue(error));
        }
        DatabaseConfigSchemaValidationStatus::VisibleUnvalidated => {
            return Err(DatabaseParameterGoalDraftError::VisibleUnvalidated);
        }
    }
    let normalized_value = validation
        .normalized_value()
        .ok_or(DatabaseParameterGoalDraftError::NonPublicParameter)?;
    if normalized_value.chars().any(|character| {
        character.is_control()
            || matches!(
                character,
                '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{200e}' | '\u{200f}'
            )
    }) {
        return Err(DatabaseParameterGoalDraftError::UnsafeValue);
    }
    if normalized_value.is_empty() {
        // The existing lossless line writers distinguish a valueless option
        // from an explicit empty assignment only when parsing source. Until the
        // typed writer can preserve that distinction, projected generation must
        // fail closed instead of silently changing semantics.
        return Err(DatabaseParameterGoalDraftError::EmptyValueUnsupported);
    }
    Ok(DatabaseParameterGoalDraft {
        container_path: parameter.container_path,
        canonical_key: parameter.canonical_key,
        normalized_value: normalized_value.to_owned(),
    })
}

/// Revalidates the current normalized value against the live static registry.
pub fn revalidate_database_parameter_assignment(
    assignment: &DatabaseParameterAssignment,
) -> Result<DatabaseParameterAssignment, DatabaseParameterAssignmentError> {
    revalidate_database_parameter_assignment_value(
        assignment,
        assignment.draft().normalized_value(),
    )
}

/// Revalidates a replacement value for an already resolved exact target.
///
/// This deliberately does not parse a query again, so editing the value cannot
/// change product, version, artifact, container, or key identity.
pub fn revalidate_database_parameter_assignment_value(
    assignment: &DatabaseParameterAssignment,
    raw_value: &str,
) -> Result<DatabaseParameterAssignment, DatabaseParameterAssignmentError> {
    validate_database_parameter_assignment_target(assignment.target, raw_value)
}

/// Resolves one candidate returned by an ambiguous assignment without exposing
/// the pending unnormalized value outside core.
pub fn select_database_parameter_assignment_candidate(
    ambiguity: &DatabaseParameterAssignmentAmbiguity,
    target: DatabaseParameterAssignmentTarget,
) -> Result<DatabaseParameterAssignment, DatabaseParameterAssignmentError> {
    if !ambiguity.candidates.contains(&target) {
        return Err(DatabaseParameterAssignmentError::UnknownCandidate);
    }
    validate_database_parameter_assignment_target(target, ambiguity.pending_value.as_str())
}

fn validate_database_parameter_assignment_target(
    target: DatabaseParameterAssignmentTarget,
    raw_value: &str,
) -> Result<DatabaseParameterAssignment, DatabaseParameterAssignmentError> {
    let draft =
        validate_database_parameter_goal_value(target.schema, target.parameter_index, raw_value)?;
    Ok(DatabaseParameterAssignment { target, draft })
}

fn database_parameter_goal_support(
    schema: &'static DatabaseConfigSchema,
    parameter_index: usize,
) -> Result<(), DatabaseParameterGoalDraftError> {
    if !DATABASE_CONFIG_SCHEMAS
        .iter()
        .any(|candidate| std::ptr::eq(candidate, schema))
    {
        return Err(DatabaseParameterGoalDraftError::SchemaUnavailable);
    }
    let parameter = schema
        .parameters
        .get(parameter_index)
        .ok_or(DatabaseParameterGoalDraftError::UnknownParameter)?;
    let artifact = artifact_by_key(schema.binding.artifact_key)
        .ok_or(DatabaseParameterGoalDraftError::ArtifactUnavailable)?;
    if artifact.product != schema.binding.product || artifact.component != schema.binding.component
    {
        return Err(DatabaseParameterGoalDraftError::ArtifactBindingMismatch);
    }
    if !artifact.allows_lossless_local_draft() {
        return Err(DatabaseParameterGoalDraftError::ReadOnlyArtifact);
    }
    if !matches!(
        artifact.dialect,
        DatabaseConfigDialect::MySqlOptionFile
            | DatabaseConfigDialect::PostgreSqlConf
            | DatabaseConfigDialect::Ini
            | DatabaseConfigDialect::Toml
            | DatabaseConfigDialect::JavaProperties
            | DatabaseConfigDialect::KeyValue
    ) {
        return Err(DatabaseParameterGoalDraftError::UnsupportedDialect);
    }
    if parameter.sensitivity != DatabaseConfigSchemaSensitivity::Public {
        return Err(DatabaseParameterGoalDraftError::NonPublicParameter);
    }
    if parameter.required_capability.is_some() {
        return Err(DatabaseParameterGoalDraftError::RequiredCapability);
    }
    if matches!(
        parameter.value_kind,
        DatabaseConfigSchemaValueKind::Text {
            maximum_bytes: 0,
            ..
        }
    ) {
        return Err(DatabaseParameterGoalDraftError::EmptyValueUnsupported);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigurationGoalSearchResults {
    matches: Vec<ConfigurationGoalMatch>,
    truncated: bool,
}

impl ConfigurationGoalSearchResults {
    pub fn matches(&self) -> &[ConfigurationGoalMatch] {
        &self.matches
    }

    pub const fn truncated(&self) -> bool {
        self.truncated
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigurationGoalCoverage {
    pub subject: ConfigurationGoalSubject,
    pub reviewed_recipes: usize,
    pub reviewed_parameters: usize,
}

impl ConfigurationGoalCoverage {
    pub const fn availability(self) -> ConfigurationGoalAvailability {
        if self.reviewed_recipes > 0 {
            ConfigurationGoalAvailability::LocalDraftRecipe
        } else if self.reviewed_parameters > 0 {
            ConfigurationGoalAvailability::CatalogGuidance
        } else {
            ConfigurationGoalAvailability::Unavailable
        }
    }

    /// Summarizes the reviewed evidence already available for this product.
    ///
    /// This deliberately describes inventory rather than implying that an
    /// unavailable natural-language goal can be generated or deployed.
    pub fn evidence_summary(self) -> String {
        match self.subject {
            ConfigurationGoalSubject::Middleware(MiddlewareProduct::Nginx) => format!(
                "已登记 {} 个受审本地配方，并具备 Nginx 无损语法树；其他目标仍需独立 typed 配方。",
                self.reviewed_recipes
            ),
            ConfigurationGoalSubject::Middleware(MiddlewareProduct::ApacheHttpd) => format!(
                "已登记 {} 个 Apache 2.4 受审本地配方，并具备 Apache 无损语法树；其他目标仍需指令级语义和模块证据。",
                self.reviewed_recipes
            ),
            ConfigurationGoalSubject::Middleware(MiddlewareProduct::Redis) => {
                "已登记 redis.conf 的只读结构解析；尚无受审的指令值模型、版本化校验器和本地草稿写回。".to_owned()
            }
            ConfigurationGoalSubject::Middleware(MiddlewareProduct::Tomcat) => {
                "已登记 server.xml、web.xml、context.xml 的只读结构；尚无按工件区分的 typed schema 与本地草稿写回。".to_owned()
            }
            ConfigurationGoalSubject::Database(_) if self.reviewed_parameters > 0 => {
                format!(
                    "已登记 {} 项精确版本参数语义；只有具备 typed validator 且工件允许本地无损草稿的参数可以生成。",
                    self.reviewed_parameters
                )
            }
            ConfigurationGoalSubject::Database(product) => {
                let artifact_count = artifacts_for(product).count();
                if artifact_count > 0 {
                    format!(
                        "已登记 {artifact_count} 个配置工件，但尚无与精确版本/edition 绑定的参数 Schema。"
                    )
                } else {
                    "当前只有产品身份登记，尚无经过证明的配置工件、参数 Schema 或本地草稿写回。".to_owned()
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationGoalSearchError {
    QueryTooLong,
    InvalidQuery,
}

/// Resolves the closed grammar
/// `PRODUCT [VERSION] [@ARTIFACT_KEY] [[CONTAINER]] CANONICAL_OR_EXACT_ALIAS
/// (设置为|设为|=) VALUE`.
///
/// Only the operator's left side participates in product/version/parameter
/// selection. Product names or version-like text in the value can therefore
/// never retarget the assignment. Artifact keys are exact. Container paths are
/// exact except for the documented ASCII case-insensitive MySQL option groups.
pub fn resolve_database_parameter_assignment(
    raw_query: &str,
) -> DatabaseParameterAssignmentResolution {
    let split = match split_database_parameter_assignment(raw_query) {
        Ok(Some(split)) => split,
        Ok(None) => return DatabaseParameterAssignmentResolution::NotAssignment,
        Err(error) => {
            if let Err(query_error) = validate_configuration_goal_query_text(raw_query) {
                return DatabaseParameterAssignmentResolution::Rejected(
                    database_assignment_query_error(query_error),
                );
            }
            return DatabaseParameterAssignmentResolution::Rejected(error);
        }
    };
    if let Err(query_error) = validate_configuration_goal_query_text(raw_query) {
        return DatabaseParameterAssignmentResolution::Rejected(database_assignment_query_error(
            query_error,
        ));
    }
    let left = match ConfigurationGoalQuery::parse(split.left) {
        Ok(left) => left,
        Err(query_error) => {
            return DatabaseParameterAssignmentResolution::Rejected(
                database_assignment_query_error(query_error),
            );
        }
    };
    let mentions = explicit_configuration_goal_subjects(&left);
    if mentions.is_empty() {
        return DatabaseParameterAssignmentResolution::Rejected(
            DatabaseParameterAssignmentError::MissingProduct,
        );
    }
    let leading_subjects = mentions
        .iter()
        .filter(|mention| mention.start == 0)
        .filter_map(|mention| match mention.subject {
            ConfigurationGoalSubject::Database(product) => Some(product),
            ConfigurationGoalSubject::Middleware(_) => None,
        })
        .collect::<Vec<_>>();
    let Some(product) = leading_subjects.first().copied() else {
        return DatabaseParameterAssignmentResolution::Rejected(
            DatabaseParameterAssignmentError::MissingTarget,
        );
    };
    if leading_subjects
        .iter()
        .any(|candidate| *candidate != product)
        || mentions
            .iter()
            .any(|mention| mention.subject != ConfigurationGoalSubject::Database(product))
    {
        return DatabaseParameterAssignmentResolution::Rejected(
            DatabaseParameterAssignmentError::AmbiguousProduct,
        );
    }
    let mention = *mentions
        .iter()
        .find(|mention| {
            mention.start == 0 && mention.subject == ConfigurationGoalSubject::Database(product)
        })
        .expect("a leading database subject was selected above");
    let Some(raw_tail) = left.as_str().get(mention.end..) else {
        return DatabaseParameterAssignmentResolution::Rejected(
            DatabaseParameterAssignmentError::MissingTarget,
        );
    };
    let (version_selection, raw_selector) = database_version_and_tail(raw_tail);
    if version_selection == DatabaseGoalVersionSelection::Invalid {
        return DatabaseParameterAssignmentResolution::Rejected(
            DatabaseParameterAssignmentError::InvalidVersion,
        );
    }
    let selector = match parse_database_assignment_selector(raw_selector) {
        Ok(selector) => selector,
        Err(error) => return DatabaseParameterAssignmentResolution::Rejected(error),
    };
    if let Some(artifact_key) = selector.artifact_key {
        let Some(artifact) = artifact_by_key(artifact_key) else {
            return DatabaseParameterAssignmentResolution::Rejected(
                DatabaseParameterAssignmentError::UnknownArtifact,
            );
        };
        if artifact.product != product {
            return DatabaseParameterAssignmentResolution::Rejected(
                DatabaseParameterAssignmentError::ArtifactProductMismatch,
            );
        }
    }

    let product_schemas = DATABASE_CONFIG_SCHEMAS
        .iter()
        .filter(|schema| schema.binding.product == product)
        .collect::<Vec<_>>();
    if product_schemas.is_empty() {
        return DatabaseParameterAssignmentResolution::Rejected(
            DatabaseParameterAssignmentError::MissingExactSchema,
        );
    }
    let product_schemas = product_schemas
        .into_iter()
        .filter(|schema| {
            selector
                .artifact_key
                .is_none_or(|artifact_key| schema.binding.artifact_key == artifact_key)
        })
        .collect::<Vec<_>>();
    if product_schemas.is_empty() {
        return DatabaseParameterAssignmentResolution::Rejected(
            DatabaseParameterAssignmentError::MissingExactSchema,
        );
    }
    let requested_version = version_selection.valid();
    let matching_schemas = product_schemas
        .into_iter()
        .filter(|schema| {
            requested_version.is_none_or(|version| version.matches(schema.binding.versions))
        })
        .collect::<Vec<_>>();
    if matching_schemas.is_empty() {
        return DatabaseParameterAssignmentResolution::Rejected(
            DatabaseParameterAssignmentError::MissingVersion,
        );
    }

    let mut candidates = Vec::new();
    let mut key_candidate_count = 0usize;
    for schema in matching_schemas {
        for (parameter_index, parameter) in schema.parameters.iter().enumerate() {
            if parameter.canonical_key != selector.canonical_or_alias
                && !parameter
                    .exact_aliases
                    .contains(&selector.canonical_or_alias)
            {
                continue;
            }
            key_candidate_count += 1;
            if selector.container_path.is_some_and(|container| {
                !database_assignment_container_matches(schema, parameter, container)
            }) {
                continue;
            }
            let target = DatabaseParameterAssignmentTarget {
                schema,
                parameter_index,
            };
            if candidates.contains(&target) {
                continue;
            }
            if candidates.len() == MAX_DATABASE_PARAMETER_ASSIGNMENT_CANDIDATES {
                return DatabaseParameterAssignmentResolution::Rejected(
                    DatabaseParameterAssignmentError::TooManyCandidates,
                );
            }
            candidates.push(target);
        }
    }
    if candidates.is_empty() {
        return DatabaseParameterAssignmentResolution::Rejected(
            if key_candidate_count > 0 && selector.container_path.is_some() {
                DatabaseParameterAssignmentError::UnknownContainer
            } else {
                DatabaseParameterAssignmentError::UnknownParameter
            },
        );
    }
    if candidates.len() > 1 {
        return DatabaseParameterAssignmentResolution::Ambiguous(
            DatabaseParameterAssignmentAmbiguity {
                candidates,
                pending_value: Zeroizing::new(split.value.to_owned()),
            },
        );
    }

    match validate_database_parameter_assignment_target(candidates[0], split.value) {
        Ok(assignment) => DatabaseParameterAssignmentResolution::Ready(assignment),
        Err(error) => DatabaseParameterAssignmentResolution::Rejected(error),
    }
}

#[derive(Clone, Copy)]
struct DatabaseParameterAssignmentSplit<'a> {
    left: &'a str,
    value: &'a str,
}

fn split_database_parameter_assignment(
    raw_query: &str,
) -> Result<Option<DatabaseParameterAssignmentSplit<'_>>, DatabaseParameterAssignmentError> {
    const SUPPORTED: &[&str] = &["设置为", "设为", "="];
    const UNSUPPORTED_ASSIGNMENT_LIKE: &[&str] = &[
        "改成",
        "修改为",
        "调整为",
        "改为",
        "更改为",
        "变更为",
        "设置成",
        "调整成",
        "配置为",
        "置为",
        "赋值为",
        "更新为",
    ];

    let supported = SUPPORTED
        .iter()
        .filter_map(|operator| raw_query.find(operator).map(|start| (start, *operator)))
        .min_by_key(|(start, _)| *start);
    let unsupported_start = UNSUPPORTED_ASSIGNMENT_LIKE
        .iter()
        .filter_map(|operator| raw_query.find(operator))
        .min();
    let Some((start, operator)) = supported else {
        return if unsupported_start.is_some() {
            Err(DatabaseParameterAssignmentError::UnsupportedOperator)
        } else {
            Ok(None)
        };
    };
    if unsupported_start.is_some_and(|unsupported| unsupported < start) {
        return Err(DatabaseParameterAssignmentError::UnsupportedOperator);
    }

    let left = raw_query[..start].trim();
    let value = raw_query[start + operator.len()..].trim();
    if left.is_empty() {
        return Err(DatabaseParameterAssignmentError::MissingTarget);
    }
    if value.is_empty() {
        return Err(DatabaseParameterAssignmentError::MissingValue);
    }
    if value.starts_with('=') || value.contains("设置为") || value.contains("设为") {
        return Err(DatabaseParameterAssignmentError::MultipleOperators);
    }
    Ok(Some(DatabaseParameterAssignmentSplit { left, value }))
}

fn database_assignment_query_error(
    error: ConfigurationGoalSearchError,
) -> DatabaseParameterAssignmentError {
    match error {
        ConfigurationGoalSearchError::QueryTooLong => {
            DatabaseParameterAssignmentError::QueryTooLong
        }
        ConfigurationGoalSearchError::InvalidQuery => {
            DatabaseParameterAssignmentError::InvalidQuery
        }
    }
}

#[derive(Clone, Copy)]
struct DatabaseParameterAssignmentSelector<'a> {
    artifact_key: Option<&'a str>,
    container_path: Option<&'a str>,
    canonical_or_alias: &'a str,
}

fn parse_database_assignment_selector(
    raw: &str,
) -> Result<DatabaseParameterAssignmentSelector<'_>, DatabaseParameterAssignmentError> {
    let mut tail = raw
        .trim_start()
        .trim_start_matches([':', '：'])
        .trim_start();
    if tail.is_empty() {
        return Err(DatabaseParameterAssignmentError::MissingParameter);
    }

    let artifact_key = if let Some(qualified) = tail.strip_prefix('@') {
        let end = qualified
            .char_indices()
            .find(|(_, character)| character.is_whitespace())
            .map_or(qualified.len(), |(index, _)| index);
        let artifact_key = &qualified[..end];
        if artifact_key.is_empty()
            || !artifact_key.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
            })
        {
            return Err(DatabaseParameterAssignmentError::InvalidQualifier);
        }
        tail = qualified[end..].trim_start();
        Some(artifact_key)
    } else {
        None
    };

    let container_path = if let Some(qualified) = tail.strip_prefix('[') {
        let Some(end) = qualified.find(']') else {
            return Err(DatabaseParameterAssignmentError::InvalidQualifier);
        };
        let container_path = &qualified[..end];
        if container_path.is_empty() {
            return Err(DatabaseParameterAssignmentError::InvalidQualifier);
        }
        let remainder = &qualified[end + 1..];
        if !remainder.is_empty() && !remainder.chars().next().is_some_and(char::is_whitespace) {
            return Err(DatabaseParameterAssignmentError::InvalidQualifier);
        }
        tail = remainder.trim_start();
        Some(container_path)
    } else {
        None
    };

    let canonical_or_alias = tail.trim();
    if canonical_or_alias.is_empty() {
        return Err(DatabaseParameterAssignmentError::MissingParameter);
    }
    if canonical_or_alias.chars().any(char::is_whitespace)
        || canonical_or_alias
            .chars()
            .any(|character| matches!(character, '@' | '[' | ']'))
    {
        return Err(DatabaseParameterAssignmentError::InvalidQualifier);
    }
    Ok(DatabaseParameterAssignmentSelector {
        artifact_key,
        container_path,
        canonical_or_alias,
    })
}

fn database_assignment_container_matches(
    schema: &DatabaseConfigSchema,
    parameter: &DatabaseConfigParameterSchema,
    qualifier: &str,
) -> bool {
    let Some(container_path) = parameter.container_path else {
        return false;
    };
    if artifact_by_key(schema.binding.artifact_key)
        .is_some_and(|artifact| artifact.dialect == DatabaseConfigDialect::MySqlOptionFile)
    {
        container_path.eq_ignore_ascii_case(qualifier)
    } else {
        container_path == qualifier
    }
}

pub fn search_configuration_goals(
    raw_query: &str,
) -> Result<ConfigurationGoalSearchResults, ConfigurationGoalSearchError> {
    let query = ConfigurationGoalQuery::parse(raw_query)?;
    let subject_mentions = explicit_configuration_goal_subjects(&query);
    let intent_query = query.without_subject_mentions(&subject_mentions);
    let mut ranked = Vec::new();
    let mut order = 0usize;

    for recipe in CONFIGURATION_GOAL_RECIPES {
        if subject_is_allowed(recipe.subject, &subject_mentions)
            && let Some(score) = recipe_score(recipe, &intent_query)
        {
            ranked.push((score, order, ConfigurationGoalMatch::Recipe(recipe)));
        }
        order += 1;
    }

    if !query.is_empty() {
        for product in DatabaseConfigProduct::ALL {
            let subject = ConfigurationGoalSubject::Database(product);
            if !subject_is_allowed(subject, &subject_mentions) {
                continue;
            }
            let version_selection = requested_database_version(&query, product, &subject_mentions);
            if version_selection == DatabaseGoalVersionSelection::Invalid {
                continue;
            }
            let version = version_selection.valid();
            for goal in DATABASE_CONFIGURATION_GOALS {
                if database_goal_resolutions_for_version(goal, product, version).is_empty() {
                    order += 1;
                    continue;
                }
                if let Some(score) = database_goal_score(goal, product, &intent_query) {
                    ranked.push((
                        score,
                        order,
                        ConfigurationGoalMatch::DatabaseGoal {
                            goal,
                            product,
                            version,
                        },
                    ));
                }
                order += 1;
            }
        }
    }

    if !query.is_empty() {
        for artifact in DATABASE_CONFIG_ARTIFACTS {
            let subject = ConfigurationGoalSubject::Database(artifact.product);
            if !subject_is_allowed(subject, &subject_mentions) {
                continue;
            }
            let version_selection =
                requested_database_version(&query, artifact.product, &subject_mentions);
            if version_selection == DatabaseGoalVersionSelection::Invalid {
                continue;
            }
            if let Some(score) = database_artifact_score(artifact, &intent_query) {
                ranked.push((
                    score,
                    order,
                    ConfigurationGoalMatch::DatabaseArtifact { artifact },
                ));
            }
            order += 1;
        }
    }

    if !query.is_empty() {
        for schema in DATABASE_CONFIG_SCHEMAS {
            let subject = ConfigurationGoalSubject::Database(schema.binding.product);
            if !subject_is_allowed(subject, &subject_mentions) {
                continue;
            }
            let version_selection =
                requested_database_version(&query, schema.binding.product, &subject_mentions);
            if version_selection == DatabaseGoalVersionSelection::Invalid {
                continue;
            }
            let version = version_selection.valid();
            if version.is_some_and(|version| !version.matches(schema.binding.versions)) {
                continue;
            }
            for (parameter_index, parameter) in schema.parameters.iter().enumerate() {
                if let Some(score) = database_parameter_score(schema, parameter, &intent_query) {
                    ranked.push((
                        score,
                        order,
                        ConfigurationGoalMatch::DatabaseParameter {
                            schema,
                            parameter_index,
                        },
                    ));
                }
                order += 1;
            }
        }

        for product in MiddlewareProduct::ALL {
            let subject = ConfigurationGoalSubject::Middleware(product);
            let coverage = configuration_goal_coverage(subject);
            let already_matched = ranked
                .iter()
                .any(|(_, _, matched)| matched.subject() == subject);
            if !already_matched
                && subject_mentions
                    .iter()
                    .any(|mention| mention.subject == subject)
            {
                ranked.push((
                    20,
                    order,
                    ConfigurationGoalMatch::UnavailableSubject {
                        coverage,
                        gap: unsupported_subject_gap(
                            coverage,
                            DatabaseGoalVersionSelection::Unspecified,
                        ),
                    },
                ));
            }
            order += 1;
        }
        for definition in DATABASE_CONFIG_PRODUCTS {
            let subject = ConfigurationGoalSubject::Database(definition.product);
            let coverage = configuration_goal_coverage(subject);
            let already_matched = ranked
                .iter()
                .any(|(_, _, matched)| matched.subject() == subject);
            if !already_matched
                && subject_mentions
                    .iter()
                    .any(|mention| mention.subject == subject)
            {
                let version =
                    requested_database_version(&query, definition.product, &subject_mentions);
                ranked.push((
                    20,
                    order,
                    ConfigurationGoalMatch::UnavailableSubject {
                        coverage,
                        gap: unsupported_subject_gap(coverage, version),
                    },
                ));
            }
            order += 1;
        }
    }

    ranked.sort_by(|left, right| right.0.cmp(&left.0).then(left.1.cmp(&right.1)));
    let truncated = ranked.len() > MAX_CONFIGURATION_GOAL_MATCHES;
    let matches = ranked
        .into_iter()
        .take(MAX_CONFIGURATION_GOAL_MATCHES)
        .map(|(_, _, goal)| goal)
        .collect();
    Ok(ConfigurationGoalSearchResults { matches, truncated })
}

pub fn configuration_goal_coverage(subject: ConfigurationGoalSubject) -> ConfigurationGoalCoverage {
    let reviewed_recipes = CONFIGURATION_GOAL_RECIPES
        .iter()
        .filter(|recipe| recipe.subject == subject)
        .count();
    let reviewed_parameters = match subject {
        ConfigurationGoalSubject::Middleware(_) => 0,
        ConfigurationGoalSubject::Database(product) => DATABASE_CONFIG_SCHEMAS
            .iter()
            .filter(|schema| schema.binding.product == product)
            .map(|schema| schema.parameters.len())
            .sum(),
    };
    ConfigurationGoalCoverage {
        subject,
        reviewed_recipes,
        reviewed_parameters,
    }
}

pub fn nginx_forbidden_path_from_goal_query(raw_query: &str) -> Option<NginxForbiddenPath> {
    let query = ConfigurationGoalQuery::parse(raw_query).ok()?;
    for (start, character) in query.as_str().char_indices() {
        if character != '/' {
            continue;
        }
        let has_safe_start = query.as_str()[..start]
            .chars()
            .next_back()
            .is_none_or(goal_path_boundary);
        if !has_safe_start {
            continue;
        }
        let tail = &query.as_str()[start..];
        let end = tail
            .char_indices()
            .take_while(|(_, character)| {
                character.is_ascii_alphanumeric()
                    || matches!(character, '/' | '-' | '_' | '.' | '~')
            })
            .last()
            .map_or(1, |(index, character)| index + character.len_utf8());
        let candidate = &tail[..end];
        let has_safe_end = tail[end..].chars().next().is_none_or(goal_path_boundary);
        if has_safe_end && let Ok(path) = NginxForbiddenPath::parse(candidate) {
            return Some(path);
        }
    }
    None
}

/// Builds one local Apache 2.4 draft for a canonical URI path and its descendants.
///
/// This proves only that the generated bytes fit the reviewed Apache syntax. It
/// does not prove that `mod_authz_core` is loaded or that a concrete target uses
/// this configuration graph.
pub fn apache_forbidden_path_draft_from_goal_query(
    raw_query: &str,
) -> CoreResult<Option<ApacheVisualDocument>> {
    let Some(path) = nginx_forbidden_path_from_goal_query(raw_query) else {
        return Ok(None);
    };
    let mut expression = String::with_capacity(path.as_str().len() + 16);
    expression.push('^');
    for character in path.as_str().chars() {
        if character == '.' {
            expression.push_str("\\.");
        } else {
            expression.push(character);
        }
    }
    expression.push_str("(?:/.*)?$");
    let source =
        format!("<LocationMatch \"{expression}\">\n    Require all denied\n</LocationMatch>\n");
    let document = ApacheVisualDocument::parse(&source)?;
    if !document.is_structured()
        || document.has_opaque_regions()
        || document.contains_sensitive_values()
        || document.raw_bytes() != source.as_bytes()
    {
        return Err(CoreError::validation(
            "Apache forbidden-path goal",
            "generated draft did not round-trip as one safe structured document",
        ));
    }
    Ok(Some(document))
}

pub fn apache_disable_trace_draft() -> CoreResult<ApacheVisualDocument> {
    apache_fixed_directive_draft(
        "Apache disable-TRACE goal",
        "TraceEnable Off\n",
        &[("TraceEnable", "Off")],
    )
}

pub fn apache_reduce_version_disclosure_draft() -> CoreResult<ApacheVisualDocument> {
    apache_fixed_directive_draft(
        "Apache reduce-version-disclosure goal",
        "ServerTokens Prod\nServerSignature Off\n",
        &[("ServerTokens", "Prod"), ("ServerSignature", "Off")],
    )
}

fn apache_fixed_directive_draft(
    context: &'static str,
    source: &'static str,
    expected: &[(&str, &str)],
) -> CoreResult<ApacheVisualDocument> {
    let document = ApacheVisualDocument::parse(source)?;
    if !document.is_structured()
        || document.has_opaque_regions()
        || document.contains_sensitive_values()
        || document.raw_bytes() != source.as_bytes()
    {
        return Err(CoreError::validation(
            context,
            "reviewed fragment did not round-trip as one safe structured document",
        ));
    }
    let rows = document.rows();
    if rows.len() != expected.len()
        || !rows.iter().zip(expected).all(|(row, (name, arguments))| {
            row.kind() == ApacheVisualNodeKind::Directive
                && row.parent().is_none()
                && row.depth() == 0
                && row.name() == Some(*name)
                && row.arguments() == Some(*arguments)
                && !row.sensitive()
        })
    {
        return Err(CoreError::validation(
            context,
            "reviewed fragment did not produce the exact closed directive sequence",
        ));
    }
    let output = document.output();
    let reparsed = ApacheVisualDocument::parse(output.text()?)?;
    if reparsed.raw_bytes() != source.as_bytes() || reparsed.rows().len() != expected.len() {
        return Err(CoreError::validation(
            context,
            "reviewed fragment changed across render and reparse",
        ));
    }
    Ok(document)
}

fn goal_path_boundary(character: char) -> bool {
    character.is_whitespace() || matches!(character, ',' | '，' | '。' | '、' | ':' | '：')
}

fn database_product(
    product: DatabaseConfigProduct,
) -> Option<&'static DatabaseConfigProductDefinition> {
    DATABASE_CONFIG_PRODUCTS
        .iter()
        .find(|definition| definition.product == product)
}

pub fn database_goal_available_version_labels(product: DatabaseConfigProduct) -> Vec<&'static str> {
    let mut labels = Vec::new();
    for schema in DATABASE_CONFIG_SCHEMAS
        .iter()
        .filter(|schema| schema.binding.product == product)
    {
        if !labels.contains(&schema.version_label) {
            labels.push(schema.version_label);
        }
    }
    labels
}

fn requested_database_version(
    query: &ConfigurationGoalQuery,
    product: DatabaseConfigProduct,
    subject_mentions: &[ConfigurationGoalSubjectMention],
) -> DatabaseGoalVersionSelection {
    let subject = ConfigurationGoalSubject::Database(product);
    let mut selected = DatabaseGoalVersionSelection::Unspecified;
    for mention in subject_mentions
        .iter()
        .filter(|mention| mention.subject == subject)
    {
        let Some(raw_tail) = query.as_str().get(mention.end..) else {
            return DatabaseGoalVersionSelection::Invalid;
        };
        match database_version_from_subject_tail(raw_tail) {
            DatabaseGoalVersionSelection::Unspecified => {}
            DatabaseGoalVersionSelection::Invalid => {
                return DatabaseGoalVersionSelection::Invalid;
            }
            DatabaseGoalVersionSelection::Valid(version) => match selected {
                DatabaseGoalVersionSelection::Unspecified => {
                    selected = DatabaseGoalVersionSelection::Valid(version);
                }
                DatabaseGoalVersionSelection::Valid(existing) if existing == version => {}
                DatabaseGoalVersionSelection::Valid(_) | DatabaseGoalVersionSelection::Invalid => {
                    return DatabaseGoalVersionSelection::Invalid;
                }
            },
        }
    }
    selected
}

fn database_version_from_subject_tail(raw_tail: &str) -> DatabaseGoalVersionSelection {
    database_version_and_tail(raw_tail).0
}

fn database_version_and_tail(raw_tail: &str) -> (DatabaseGoalVersionSelection, &str) {
    let mut tail = raw_tail.trim_start();
    tail = tail.trim_start_matches([':', '：']);
    tail = tail.trim_start();
    let mut explicitly_versioned = false;
    if let Some(rest) = tail.strip_prefix("版本") {
        explicitly_versioned = true;
        tail = rest.trim_start();
    }
    if let Some(rest) = tail.strip_prefix(['v', 'V']) {
        let looks_like_version = rest.chars().next().is_none_or(|character| {
            character.is_ascii_digit() || character.is_whitespace() || character == '.'
        });
        if looks_like_version {
            explicitly_versioned = true;
            tail = rest;
        }
    }
    if tail
        .chars()
        .next()
        .is_none_or(|character| !character.is_ascii_digit())
    {
        return if explicitly_versioned {
            (DatabaseGoalVersionSelection::Invalid, tail)
        } else {
            (DatabaseGoalVersionSelection::Unspecified, tail)
        };
    }
    let Some(end) = tail
        .char_indices()
        .take_while(|(_, character)| character.is_ascii_digit() || *character == '.')
        .last()
        .map(|(index, character)| index + character.len_utf8())
    else {
        return (DatabaseGoalVersionSelection::Invalid, tail);
    };
    let token = &tail[..end];
    if tail[end..]
        .chars()
        .next()
        .is_some_and(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        return (DatabaseGoalVersionSelection::Invalid, tail);
    }
    let Ok(parts) = token
        .split('.')
        .map(str::parse::<u16>)
        .collect::<Result<Vec<_>, _>>()
    else {
        return (DatabaseGoalVersionSelection::Invalid, tail);
    };
    if parts.is_empty() || parts.len() > 4 {
        return (DatabaseGoalVersionSelection::Invalid, tail);
    }
    let mut components = [0; 4];
    components[..parts.len()].copy_from_slice(&parts);
    (
        DatabaseGoalVersionSelection::Valid(DatabaseGoalVersionRequest {
            components,
            component_count: parts.len() as u8,
        }),
        &tail[end..],
    )
}

fn unsupported_subject_gap(
    coverage: ConfigurationGoalCoverage,
    requested_version: DatabaseGoalVersionSelection,
) -> ConfigurationGoalSupportGap {
    if requested_version == DatabaseGoalVersionSelection::Invalid {
        return ConfigurationGoalSupportGap::MissingVersion;
    }
    if let (ConfigurationGoalSubject::Database(product), Some(version)) =
        (coverage.subject, requested_version.valid())
        && DATABASE_CONFIG_SCHEMAS
            .iter()
            .any(|schema| schema.binding.product == product)
        && !DATABASE_CONFIG_SCHEMAS.iter().any(|schema| {
            schema.binding.product == product && version.matches(schema.binding.versions)
        })
    {
        return ConfigurationGoalSupportGap::MissingVersion;
    }
    if coverage.reviewed_recipes > 0 || coverage.reviewed_parameters > 0 {
        return ConfigurationGoalSupportGap::MissingReviewedIntent;
    }
    match coverage.subject {
        ConfigurationGoalSubject::Middleware(_) => {
            ConfigurationGoalSupportGap::MissingReviewedRecipe
        }
        ConfigurationGoalSubject::Database(product) if artifacts_for(product).next().is_some() => {
            ConfigurationGoalSupportGap::MissingExactSchema
        }
        ConfigurationGoalSubject::Database(_) => {
            ConfigurationGoalSupportGap::MissingEditableArtifact
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ConfigurationGoalSubjectMention {
    subject: ConfigurationGoalSubject,
    start: usize,
    end: usize,
}

#[derive(Debug)]
struct ConfigurationGoalQuery {
    text: String,
    tokens: Vec<String>,
}

impl ConfigurationGoalQuery {
    fn parse(raw: &str) -> Result<Self, ConfigurationGoalSearchError> {
        validate_configuration_goal_query_text(raw)?;
        let text = raw.trim().to_owned();
        let tokens = text
            .split(|character: char| {
                character.is_whitespace()
                    || matches!(
                        character,
                        ',' | '，' | '。' | '、' | ':' | '：' | ';' | '；'
                    )
            })
            .filter(|token| token.chars().count() >= 2)
            .map(ToOwned::to_owned)
            .collect();
        Ok(Self { text, tokens })
    }

    fn as_str(&self) -> &str {
        &self.text
    }

    fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    fn without_subject_mentions(&self, mentions: &[ConfigurationGoalSubjectMention]) -> Self {
        if mentions.is_empty() {
            return Self {
                text: self.text.clone(),
                tokens: self.tokens.clone(),
            };
        }
        let mut ranges = mentions
            .iter()
            .map(|mention| (mention.start, mention.end))
            .collect::<Vec<_>>();
        ranges.sort_unstable();
        let mut text = String::with_capacity(self.text.len());
        let mut cursor = 0usize;
        for (start, end) in ranges {
            if start > cursor {
                text.push_str(&self.text[cursor..start]);
            }
            text.push(' ');
            cursor = cursor.max(end);
        }
        if cursor < self.text.len() {
            text.push_str(&self.text[cursor..]);
        }
        Self::parse(text.trim()).expect("a validated query remains valid after removing subjects")
    }
}

fn validate_configuration_goal_query_text(raw: &str) -> Result<(), ConfigurationGoalSearchError> {
    if raw.chars().count() > MAX_CONFIGURATION_GOAL_QUERY_CHARS {
        return Err(ConfigurationGoalSearchError::QueryTooLong);
    }
    if raw.chars().any(|character| {
        character.is_control()
            || matches!(
                character,
                '\u{202a}'
                    ..='\u{202e}' | '\u{2066}'
                    ..='\u{2069}' | '\u{200e}' | '\u{200f}'
            )
    }) {
        return Err(ConfigurationGoalSearchError::InvalidQuery);
    }
    Ok(())
}

fn explicit_configuration_goal_subjects(
    query: &ConfigurationGoalQuery,
) -> Vec<ConfigurationGoalSubjectMention> {
    let lowered = query.as_str().to_ascii_lowercase();
    let mut mentions = Vec::new();
    let mut artifact_identifier_ranges = Vec::new();
    for product in MiddlewareProduct::ALL {
        for candidate in middleware_subject_names(product) {
            collect_subject_mentions(
                ConfigurationGoalSubject::Middleware(product),
                candidate,
                query.as_str(),
                &lowered,
                &mut mentions,
            );
        }
    }
    for definition in DATABASE_CONFIG_PRODUCTS {
        let subject = ConfigurationGoalSubject::Database(definition.product);
        for candidate in [definition.label, definition.key]
            .into_iter()
            .chain(database_subject_aliases(definition.product).iter().copied())
        {
            collect_subject_mentions(subject, candidate, query.as_str(), &lowered, &mut mentions);
        }
    }
    for artifact in DATABASE_CONFIG_ARTIFACTS {
        for identifier in [Some(artifact.key), artifact.default_file_name]
            .into_iter()
            .flatten()
        {
            let lowered_identifier = identifier.to_ascii_lowercase();
            for (start, _) in lowered.match_indices(&lowered_identifier) {
                let end = start + lowered_identifier.len();
                let safe_start = query.as_str()[..start]
                    .chars()
                    .next_back()
                    .is_none_or(subject_name_boundary);
                let safe_end = query.as_str()[end..]
                    .chars()
                    .next()
                    .is_none_or(subject_name_boundary);
                if safe_start && safe_end {
                    artifact_identifier_ranges.push((start, end));
                }
            }
        }
    }
    let complete = mentions.clone();
    mentions.retain(|mention| {
        !complete.iter().any(|other| {
            other.start <= mention.start
                && other.end >= mention.end
                && other.end - other.start > mention.end - mention.start
        })
    });
    mentions.retain(|mention| {
        !artifact_identifier_ranges
            .iter()
            .any(|(start, end)| *start <= mention.start && *end >= mention.end)
    });
    mentions.sort_unstable_by_key(|mention| (mention.start, mention.end, mention.subject));
    mentions.dedup();
    mentions
}

fn middleware_subject_names(product: MiddlewareProduct) -> &'static [&'static str] {
    match product {
        MiddlewareProduct::Nginx => &["Nginx"],
        MiddlewareProduct::ApacheHttpd => &["Apache HTTPD", "Apache", "httpd"],
        MiddlewareProduct::Redis => &["Redis"],
        MiddlewareProduct::Tomcat => &["Tomcat"],
    }
}

fn database_subject_aliases(product: DatabaseConfigProduct) -> &'static [&'static str] {
    match product {
        DatabaseConfigProduct::HighGo => &["瀚高"],
        DatabaseConfigProduct::ShenTongNative
        | DatabaseConfigProduct::ShenTongMpp
        | DatabaseConfigProduct::ShenTongOpenGauss => &["神通数据库", "神通"],
        _ => &[],
    }
}

fn collect_subject_mentions(
    subject: ConfigurationGoalSubject,
    candidate: &str,
    query: &str,
    lowered_query: &str,
    mentions: &mut Vec<ConfigurationGoalSubjectMention>,
) {
    let lowered_candidate = candidate.to_ascii_lowercase();
    for (start, _) in lowered_query.match_indices(&lowered_candidate) {
        let end = start + lowered_candidate.len();
        let safe_start = query[..start]
            .chars()
            .next_back()
            .is_none_or(subject_name_boundary);
        let safe_end = query[end..]
            .chars()
            .next()
            .is_none_or(subject_name_boundary)
            || subject_version_suffix_is_safe(&query[end..]);
        if safe_start && safe_end {
            mentions.push(ConfigurationGoalSubjectMention {
                subject,
                start,
                end,
            });
        }
    }
}

fn subject_name_boundary(character: char) -> bool {
    !character.is_ascii_alphanumeric() && character != '_'
}

fn subject_version_suffix_is_safe(tail: &str) -> bool {
    let (tail, had_prefix) =
        if let Some(tail) = tail.strip_prefix('v').or_else(|| tail.strip_prefix('V')) {
            (tail, true)
        } else {
            (tail, false)
        };
    let end = tail
        .char_indices()
        .take_while(|(_, character)| character.is_ascii_digit() || *character == '.')
        .last()
        .map_or(0, |(index, character)| index + character.len_utf8());
    if end == 0 {
        return had_prefix && tail.chars().next().is_none_or(subject_name_boundary);
    }
    tail[end..].chars().next().is_none_or(subject_name_boundary)
}

fn subject_is_allowed(
    subject: ConfigurationGoalSubject,
    mentions: &[ConfigurationGoalSubjectMention],
) -> bool {
    mentions.is_empty() || mentions.iter().any(|mention| mention.subject == subject)
}

fn recipe_score(recipe: &ConfigurationGoalRecipe, query: &ConfigurationGoalQuery) -> Option<u16> {
    if query.is_empty() {
        return Some(1);
    }
    let mut intent_score = 0;
    intent_score += match_score(recipe.title, query, 40);
    intent_score += match_score(recipe.summary, query, 16);
    intent_score += match_score(recipe.expected_effect, query, 16);
    intent_score += recipe
        .aliases
        .iter()
        .map(|alias| match_score(alias, query, 50))
        .max()
        .unwrap_or(0);
    let subject_only = contains_case_insensitive(recipe.subject.label(), query.as_str());
    if intent_score == 0 && !subject_only {
        return None;
    }
    Some(intent_score + match_score(recipe.subject.label(), query, 12))
}

fn database_goal_score(
    goal: &DatabaseGoalDefinition,
    product: DatabaseConfigProduct,
    query: &ConfigurationGoalQuery,
) -> Option<u16> {
    let mut intent_score = match_score(goal.title, query, 56);
    intent_score += match_score(goal.summary, query, 20);
    intent_score += goal
        .aliases
        .iter()
        .map(|alias| match_score(alias, query, 64))
        .max()
        .unwrap_or(0);
    if intent_score == 0 {
        return None;
    }
    let product_score = match_score(
        ConfigurationGoalSubject::Database(product).label(),
        query,
        24,
    );
    Some(intent_score + product_score)
}

fn database_artifact_score(
    artifact: &DatabaseConfigArtifactDefinition,
    query: &ConfigurationGoalQuery,
) -> Option<u16> {
    if query.is_empty() {
        return Some(1);
    }

    let mut intent_score = match_score(artifact.key, query, 72);
    intent_score += artifact
        .default_file_name
        .map_or(0, |file_name| match_score(file_name, query, 80));
    if intent_score == 0 {
        return None;
    }
    Some(
        intent_score
            + match_score(
                ConfigurationGoalSubject::Database(artifact.product).label(),
                query,
                16,
            ),
    )
}

fn database_parameter_score(
    schema: &DatabaseConfigSchema,
    parameter: &DatabaseConfigParameterSchema,
    query: &ConfigurationGoalQuery,
) -> Option<u16> {
    let mut intent_score = 0;
    intent_score += match_score(parameter.canonical_key, query, 60);
    intent_score += parameter
        .exact_aliases
        .iter()
        .map(|alias| match_score(alias, query, 50))
        .max()
        .unwrap_or(0);
    intent_score += parameter
        .container_path
        .map_or(0, |container| match_score(container, query, 20));
    intent_score += match_score(parameter.risk_rationale, query, 14);
    intent_score += match_score(parameter.competition_rationale, query, 14);
    intent_score += parameter
        .required_capability
        .map_or(0, |capability| match_score(capability, query, 12));
    intent_score += database_parameter_goal_alias_score(parameter.canonical_key, query);
    intent_score += match parameter.value_kind {
        DatabaseConfigSchemaValueKind::Boolean {
            true_literal,
            false_literal,
        } => match_score(true_literal, query, 4) + match_score(false_literal, query, 4),
        DatabaseConfigSchemaValueKind::Enumeration { values } => values
            .iter()
            .map(|value| match_score(value, query, 5))
            .max()
            .unwrap_or(0),
        DatabaseConfigSchemaValueKind::Integer { .. }
        | DatabaseConfigSchemaValueKind::Text { .. } => 0,
    };
    let subject = ConfigurationGoalSubject::Database(schema.binding.product);
    let product_only = contains_case_insensitive(subject.label(), query.as_str())
        || database_product(schema.binding.product)
            .is_some_and(|definition| contains_case_insensitive(definition.key, query.as_str()));
    let schema_only = contains_case_insensitive(schema.display_label, query.as_str())
        || contains_case_insensitive(schema.version_label, query.as_str());
    if intent_score == 0 && !product_only && !schema_only {
        return None;
    }
    Some(
        intent_score
            + match_score(schema.display_label, query, 12)
            + match_score(schema.version_label, query, 8)
            + match_score(subject.label(), query, 16),
    )
}

fn database_parameter_goal_alias_score(canonical_key: &str, query: &ConfigurationGoalQuery) -> u16 {
    DATABASE_PARAMETER_GOAL_ALIAS_GROUPS
        .iter()
        .filter(|group| group.canonical_keys.contains(&canonical_key))
        .flat_map(|group| group.aliases)
        .map(|alias| match_score(alias, query, 48))
        .max()
        .unwrap_or(0)
}

fn match_score(candidate: &str, query: &ConfigurationGoalQuery, weight: u16) -> u16 {
    if contains_case_insensitive(candidate, query.as_str()) {
        return weight;
    }
    if candidate.chars().count() >= 4 && contains_case_insensitive(query.as_str(), candidate) {
        return weight;
    }
    query
        .tokens
        .iter()
        .filter(|token| contains_case_insensitive(candidate, token))
        .count()
        .min(3) as u16
        * (weight / 4).max(1)
}

fn contains_case_insensitive(candidate: &str, query: &str) -> bool {
    if query.is_empty() {
        return true;
    }
    candidate.contains(query)
        || candidate
            .as_bytes()
            .windows(query.len())
            .any(|window| window.eq_ignore_ascii_case(query.as_bytes()))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    fn valid_projected_value(parameter: &DatabaseConfigParameterSchema) -> String {
        match parameter.value_kind {
            DatabaseConfigSchemaValueKind::Boolean { true_literal, .. } => true_literal.to_owned(),
            DatabaseConfigSchemaValueKind::Integer {
                minimum_inclusive, ..
            } => minimum_inclusive.to_string(),
            DatabaseConfigSchemaValueKind::Enumeration { values } => values[0].to_owned(),
            DatabaseConfigSchemaValueKind::Text {
                minimum_bytes,
                maximum_bytes,
                ..
            } => "x".repeat(minimum_bytes.max(1).min(maximum_bytes)),
        }
    }

    fn ready_assignment(query: &str) -> DatabaseParameterAssignment {
        match resolve_database_parameter_assignment(query) {
            DatabaseParameterAssignmentResolution::Ready(assignment) => assignment,
            other => panic!("expected ready assignment for {query:?}, got {other:?}"),
        }
    }

    fn rejected_assignment(query: &str) -> DatabaseParameterAssignmentError {
        match resolve_database_parameter_assignment(query) {
            DatabaseParameterAssignmentResolution::Rejected(error) => error,
            other => panic!("expected rejected assignment for {query:?}, got {other:?}"),
        }
    }

    #[test]
    fn empty_search_exposes_only_reviewed_high_level_recipes() {
        let results = search_configuration_goals("").unwrap();
        assert_eq!(results.matches().len(), CONFIGURATION_GOAL_RECIPES.len());
        assert!(
            results
                .matches()
                .iter()
                .zip(CONFIGURATION_GOAL_RECIPES)
                .all(|(goal, recipe)| matches!(
                    goal,
                    ConfigurationGoalMatch::Recipe(candidate)
                        if std::ptr::eq(*candidate, recipe)
                ))
        );
        assert!(!results.truncated());
    }

    #[test]
    fn natural_goal_search_finds_recipe_and_schema_parameter_guidance() {
        let nginx = search_configuration_goals("让 /admin 从外部访问全部返回 403").unwrap();
        assert!(matches!(
            nginx.matches().first(),
            Some(ConfigurationGoalMatch::Recipe(recipe))
                if recipe.action == ConfigurationGoalRecipeAction::NginxForbiddenPath403
        ));
        for (query, action) in [
            (
                "Nginx 静态站点目录",
                ConfigurationGoalRecipeAction::NginxStaticSite,
            ),
            (
                "Nginx 反向代理到后端",
                ConfigurationGoalRecipeAction::NginxReverseProxy,
            ),
        ] {
            assert!(
                search_configuration_goals(query)
                    .unwrap()
                    .matches()
                    .iter()
                    .any(|goal| matches!(
                        goal,
                        ConfigurationGoalMatch::Recipe(recipe) if recipe.action == action
                    ))
            );
        }

        let database = search_configuration_goals("PostgreSQL max_connections").unwrap();
        assert!(database.matches().iter().any(|goal| {
            matches!(
                goal,
                ConfigurationGoalMatch::DatabaseParameter { schema, parameter_index }
                    if schema.binding.product == DatabaseConfigProduct::PostgreSql
                        && schema.parameters[*parameter_index].canonical_key == "max_connections"
            )
        }));
        assert!(database.matches().iter().all(|goal| {
            goal.database_parameter().is_none_or(|parameter| {
                !parameter.canonical_key.is_empty()
                    && matches!(
                        goal.availability(),
                        ConfigurationGoalAvailability::LocalDraftRecipe
                            | ConfigurationGoalAvailability::CatalogGuidance
                    )
            })
        }));

        for (query, product, canonical_key) in [
            (
                "MySQL 开启慢查询日志",
                DatabaseConfigProduct::MySql,
                "slow_query_log",
            ),
            (
                "PostgreSQL 提高最大连接数",
                DatabaseConfigProduct::PostgreSql,
                "max_connections",
            ),
            (
                "PostgreSQL 限制 SQL 执行时间",
                DatabaseConfigProduct::PostgreSql,
                "statement_timeout",
            ),
            (
                "openGauss 开启数据库审计",
                DatabaseConfigProduct::OpenGauss,
                "audit_enabled",
            ),
            (
                "YashanDB 开启数据库审计",
                DatabaseConfigProduct::Yashan,
                "UNIFIED_AUDITING",
            ),
        ] {
            let results = search_configuration_goals(query).unwrap();
            assert!(
                results.matches().iter().any(|goal| matches!(
                    goal,
                    ConfigurationGoalMatch::DatabaseParameter {
                        schema,
                        parameter_index,
                    } if schema.binding.product == product
                        && schema.parameters[*parameter_index].canonical_key == canonical_key
                )),
                "{query:?} did not find {product:?}.{canonical_key}"
            );
        }

        let apache = search_configuration_goals("Apache HTTPD").unwrap();
        assert!(apache.matches().iter().any(|matched| matches!(
            matched,
            ConfigurationGoalMatch::Recipe(recipe)
                if recipe.action == ConfigurationGoalRecipeAction::ApacheForbiddenPath403
        )));

        let unavailable = search_configuration_goals("MogDB").unwrap();
        assert!(unavailable.matches().iter().any(|matched| matches!(
            matched,
            ConfigurationGoalMatch::DatabaseArtifact { artifact }
                if artifact.product == DatabaseConfigProduct::MogDb
        )));
        assert!(unavailable.matches().iter().all(|matched| {
            matched.subject() == ConfigurationGoalSubject::Database(DatabaseConfigProduct::MogDb)
        }));
    }

    #[test]
    fn database_goal_search_builds_versioned_checklists_without_claiming_completion() {
        let results = search_configuration_goals("PostgreSQL 允许数据库远程连接").unwrap();
        let (goal, product) = results
            .matches()
            .iter()
            .find_map(|matched| match matched {
                ConfigurationGoalMatch::DatabaseGoal { goal, product, .. }
                    if goal.key == "database.remote-access"
                        && *product == DatabaseConfigProduct::PostgreSql =>
                {
                    Some((*goal, *product))
                }
                _ => None,
            })
            .expect("reviewed PostgreSQL remote-access goal");
        let resolutions = database_goal_resolutions(goal, product);
        assert_eq!(resolutions.len(), 3, "PostgreSQL 16/17/18 stay distinct");
        for resolution in resolutions {
            assert_eq!(resolution.schema().binding.product, product);
            assert!(resolution.reviewed_parameter_count() > 0);
            assert!(resolution.missing_required_count() >= 2);
            assert!(resolution.steps().iter().any(|step| {
                step.parameter_indices().iter().any(|index| {
                    resolution.schema().parameters[*index].canonical_key == "listen_addresses"
                })
            }));
        }

        let slow = search_configuration_goals("TiDB 开启慢查询").unwrap();
        let goal = slow
            .matches()
            .iter()
            .find_map(|matched| match matched {
                ConfigurationGoalMatch::DatabaseGoal { goal, product, .. }
                    if goal.key == "database.slow-query-observability"
                        && *product == DatabaseConfigProduct::TiDb =>
                {
                    Some(*goal)
                }
                _ => None,
            })
            .expect("reviewed TiDB slow-query goal");
        let resolution = database_goal_resolutions(goal, DatabaseConfigProduct::TiDb)
            .into_iter()
            .find(|resolution| resolution.schema().binding.artifact_key == "tidb-server-toml")
            .expect("TiDB server schema resolution");
        for key in ["tidb_enable_slow_log", "tidb_slow_log_threshold"] {
            assert!(resolution.steps().iter().any(|step| {
                step.parameter_indices()
                    .iter()
                    .any(|index| resolution.schema().parameters[*index].canonical_key == key)
            }));
        }

        let unavailable = search_configuration_goals("MogDB 允许数据库远程连接").unwrap();
        assert!(!unavailable.matches().iter().any(|matched| matches!(
            matched,
            ConfigurationGoalMatch::DatabaseGoal {
                product: DatabaseConfigProduct::MogDb,
                ..
            }
        )));
        assert!(unavailable.matches().iter().any(|matched| matches!(
            matched,
            ConfigurationGoalMatch::UnavailableSubject { coverage, .. }
                if coverage.subject
                    == ConfigurationGoalSubject::Database(DatabaseConfigProduct::MogDb)
        )));
    }

    #[test]
    fn operational_guardrail_goals_bind_exact_parameters_and_keep_external_verification() {
        for (query, goal_key, product, canonical_key) in [
            (
                "PostgreSQL 16 限制认证等待时间",
                "database.connection-admission-guardrails",
                DatabaseConfigProduct::PostgreSql,
                "authentication_timeout",
            ),
            (
                "MySQL 8.4 清理数据库空闲连接",
                "database.idle-session-protection",
                DatabaseConfigProduct::MySql,
                "wait_timeout",
            ),
            (
                "PostgreSQL 17 记录连接和断开事件",
                "database.connection-event-logging",
                DatabaseConfigProduct::PostgreSql,
                "log_connections",
            ),
        ] {
            let results = search_configuration_goals(query).unwrap();
            let matched = results
                .matches()
                .iter()
                .copied()
                .find(|matched| {
                    matches!(
                        matched,
                        ConfigurationGoalMatch::DatabaseGoal { goal, product: found, .. }
                            if goal.key == goal_key && *found == product
                    )
                })
                .unwrap_or_else(|| panic!("{query:?} did not find {goal_key}"));
            assert_eq!(
                matched.availability(),
                ConfigurationGoalAvailability::CatalogGuidance
            );
            assert_eq!(
                matched.support_gap(),
                Some(ConfigurationGoalSupportGap::MissingExternalEvidence)
            );
            let ConfigurationGoalMatch::DatabaseGoal {
                goal,
                product,
                version,
            } = matched
            else {
                unreachable!()
            };
            let resolutions = database_goal_resolutions_for_version(goal, product, version);
            assert!(!resolutions.is_empty());
            assert!(resolutions.iter().any(|resolution| {
                resolution.steps().iter().any(|step| {
                    step.parameter_indices().iter().any(|index| {
                        resolution.schema().parameters[*index].canonical_key == canonical_key
                    })
                })
            }));
            assert!(resolutions.iter().all(|resolution| {
                resolution.steps().iter().any(|step| {
                    step.definition().required && step.definition().canonical_keys.is_empty()
                })
            }));
        }
    }

    #[test]
    fn operational_guardrail_goal_matrix_keeps_versions_containers_and_required_steps() {
        let goal = |key| {
            DATABASE_CONFIGURATION_GOALS
                .iter()
                .find(|goal| goal.key == key)
                .expect("reviewed database goal")
        };

        let admission = goal("database.connection-admission-guardrails");
        let maria_admission = database_goal_resolutions(admission, DatabaseConfigProduct::MariaDb);
        assert_eq!(maria_admission.len(), 2);
        for resolution in &maria_admission {
            for (key, required) in [("connect_timeout", true), ("max_connect_errors", false)] {
                let step = resolution
                    .steps()
                    .iter()
                    .find(|step| step.definition().canonical_keys.contains(&key))
                    .expect("reviewed MariaDB admission step");
                assert_eq!(step.definition().required, required);
                assert_eq!(step.parameter_indices().len(), 9);
                let containers = step
                    .parameter_indices()
                    .iter()
                    .map(|index| resolution.schema().parameters[*index].container_path)
                    .collect::<HashSet<_>>();
                assert_eq!(containers.len(), 9);
            }
        }
        let postgres_admission =
            database_goal_resolutions(admission, DatabaseConfigProduct::PostgreSql);
        assert_eq!(postgres_admission.len(), 3);
        assert!(postgres_admission.iter().all(|resolution| {
            resolution.steps().iter().any(|step| {
                step.definition().required
                    && step
                        .definition()
                        .canonical_keys
                        .contains(&"authentication_timeout")
                    && step.parameter_indices().len() == 1
            })
        }));

        let idle = goal("database.idle-session-protection");
        let maria_idle = database_goal_resolutions(idle, DatabaseConfigProduct::MariaDb);
        assert_eq!(maria_idle.len(), 2);
        assert!(maria_idle.iter().all(|resolution| {
            resolution.steps().iter().any(|step| {
                step.definition().required
                    && step.definition().canonical_keys.contains(&"wait_timeout")
                    && step.parameter_indices().len() == 9
            })
        }));
        let postgres_idle = database_goal_resolutions(idle, DatabaseConfigProduct::PostgreSql);
        assert_eq!(postgres_idle.len(), 3);

        let logging = goal("database.connection-event-logging");
        let postgres_logging =
            database_goal_resolutions(logging, DatabaseConfigProduct::PostgreSql);
        assert_eq!(postgres_logging.len(), 3);
        for resolution in &postgres_logging {
            for key in ["logging_collector", "log_destination", "log_connections"] {
                assert!(resolution.steps().iter().any(|step| {
                    step.definition().required
                        && step.definition().canonical_keys.contains(&key)
                        && step.parameter_indices().len() == 1
                }));
            }
            assert!(resolution.steps().iter().any(|step| {
                !step.definition().required
                    && step
                        .definition()
                        .canonical_keys
                        .contains(&"log_disconnections")
                    && step.parameter_indices().len() == 1
            }));
        }
        let kingbase_logging =
            database_goal_resolutions(logging, DatabaseConfigProduct::KingbaseEs);
        assert_eq!(kingbase_logging.len(), 1);
        for key in ["logging_collector", "log_destination", "log_connections"] {
            assert!(kingbase_logging[0].steps().iter().any(|step| {
                step.definition().required
                    && step.definition().canonical_keys.contains(&key)
                    && step.parameter_indices().len() == 1
            }));
        }
    }

    #[test]
    fn database_goal_catalog_is_closed_unique_and_every_resolution_is_bounded() {
        let mut keys = HashSet::new();
        for goal in DATABASE_CONFIGURATION_GOALS {
            assert!(keys.insert(goal.key));
            assert!(!goal.title.is_empty());
            assert!(!goal.summary.is_empty());
            assert!(!goal.aliases.is_empty());
            assert!(!goal.steps.is_empty());
            for step in goal.steps {
                assert!(!step.title.is_empty());
                assert!(!step.explanation.is_empty());
                assert!(!step.products.is_empty());
            }
            for product in DatabaseConfigProduct::ALL {
                for resolution in database_goal_resolutions(goal, product) {
                    assert_eq!(resolution.schema().binding.product, product);
                    assert!(resolution.reviewed_parameter_count() > 0);
                    assert!(resolution.steps().len() <= goal.steps.len());
                    for step in resolution.steps() {
                        assert!(step.definition().products.contains(&product));
                        assert!(step.parameter_indices().iter().all(|index| {
                            resolution
                                .schema()
                                .parameters
                                .get(*index)
                                .is_some_and(|parameter| {
                                    step.definition()
                                        .canonical_keys
                                        .contains(&parameter.canonical_key)
                                })
                        }));
                    }
                }
            }
        }
    }

    #[test]
    fn every_database_artifact_is_searchable_and_reports_its_real_local_capability() {
        for artifact in DATABASE_CONFIG_ARTIFACTS {
            let query = format!(
                "{} {}",
                ConfigurationGoalSubject::Database(artifact.product).label(),
                artifact.key
            );
            let results = search_configuration_goals(&query).unwrap();
            assert!(
                results.matches().iter().any(|matched| matches!(
                    matched,
                    ConfigurationGoalMatch::DatabaseArtifact { artifact: found }
                        if found.key == artifact.key && found.product == artifact.product
                )),
                "artifact {query:?} was not discoverable: {:?}",
                results.matches()
            );
            assert!(results.matches().iter().all(|matched| {
                matched.subject() == ConfigurationGoalSubject::Database(artifact.product)
            }));
        }

        let embedded_product_name = search_configuration_goals("SequoiaDB mariadb.conf").unwrap();
        assert!(
            embedded_product_name
                .matches()
                .iter()
                .any(|matched| matches!(
                    matched,
                    ConfigurationGoalMatch::DatabaseArtifact { artifact }
                        if artifact.key == "sequoiadb-quick-deploy-mariadb"
                ))
        );
        assert!(embedded_product_name.matches().iter().all(|matched| {
            matched.subject()
                == ConfigurationGoalSubject::Database(DatabaseConfigProduct::SequoiaDb)
        }));

        let local = artifact_by_key("mysql-option-file").unwrap();
        assert_eq!(
            database_artifact_goal_availability(local),
            ConfigurationGoalAvailability::CatalogGuidance
        );
        assert_eq!(database_artifact_goal_support_gap(local), None);

        let generated = artifact_by_key("mysql-persisted-variables").unwrap();
        assert_eq!(
            database_artifact_goal_availability(generated),
            ConfigurationGoalAvailability::CatalogGuidance
        );
        assert_eq!(
            database_artifact_goal_support_gap(generated),
            Some(ConfigurationGoalSupportGap::MissingEditableArtifact)
        );

        let runtime = artifact_by_key("mysql-runtime-variables").unwrap();
        assert_eq!(
            database_artifact_goal_availability(runtime),
            ConfigurationGoalAvailability::Unavailable
        );
        assert_eq!(
            database_artifact_goal_support_gap(runtime),
            Some(ConfigurationGoalSupportGap::MissingRuntimeCapability)
        );

        let no_parser = DATABASE_CONFIG_ARTIFACTS
            .iter()
            .find(|artifact| {
                artifact.surface == DatabaseConfigSurface::File
                    && !artifact.has_source_backed_visual_parser()
                    && artifact.support != DatabaseConfigSupportLevel::VendorSchemaRequired
            })
            .expect("a catalogued file without a visual parser");
        assert_eq!(
            database_artifact_goal_support_gap(no_parser),
            Some(ConfigurationGoalSupportGap::MissingTypedValidator)
        );
    }

    #[test]
    fn goal_query_and_path_extraction_fail_closed() {
        assert_eq!(
            nginx_forbidden_path_from_goal_query("禁止 /admin 及子路径")
                .as_ref()
                .map(NginxForbiddenPath::as_str),
            Some("/admin")
        );
        for invalid in [
            "//admin",
            "/admin//users",
            "https://host/admin",
            "/admin;return 200",
            "/admin%2Fusers",
            "/admin{ return 200; }",
        ] {
            assert!(
                nginx_forbidden_path_from_goal_query(invalid).is_none(),
                "{invalid:?}"
            );
        }
        assert_eq!(
            search_configuration_goals(&"x".repeat(MAX_CONFIGURATION_GOAL_QUERY_CHARS + 1)),
            Err(ConfigurationGoalSearchError::QueryTooLong)
        );
        assert_eq!(
            search_configuration_goals("max_connections\npassword"),
            Err(ConfigurationGoalSearchError::InvalidQuery)
        );
    }

    #[test]
    fn apache_forbidden_path_goal_is_typed_segment_safe_and_structured() {
        let query = "Apache block /admin.v1 with 403";
        let matches = search_configuration_goals(query).unwrap();
        assert!(matches.matches().iter().any(|matched| matches!(
            matched,
            ConfigurationGoalMatch::Recipe(recipe)
                if recipe.action == ConfigurationGoalRecipeAction::ApacheForbiddenPath403
        )));

        let document = apache_forbidden_path_draft_from_goal_query(query)
            .unwrap()
            .expect("canonical path");
        assert!(document.is_structured());
        assert!(!document.has_opaque_regions());
        assert_eq!(
            document.raw_bytes(),
            b"<LocationMatch \"^/admin\\.v1(?:/.*)?$\">\n    Require all denied\n</LocationMatch>\n"
        );

        for invalid in [
            "Apache 403 //admin",
            "Apache 403 /admin//users",
            "Apache 403 https://host/admin",
            "Apache 403 /admin;Require all granted",
            "Apache 403 /admin%2Fusers",
            "Apache 403 /admin{Require all granted}",
        ] {
            assert!(
                apache_forbidden_path_draft_from_goal_query(invalid)
                    .unwrap()
                    .is_none(),
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn apache_fixed_goals_are_closed_root_directive_sequences() {
        for (query, action) in [
            (
                "Apache 禁用 TRACE",
                ConfigurationGoalRecipeAction::ApacheDisableTrace,
            ),
            (
                "httpd 隐藏版本号",
                ConfigurationGoalRecipeAction::ApacheReduceVersionDisclosure,
            ),
        ] {
            let results = search_configuration_goals(query).unwrap();
            assert!(results.matches().iter().any(|matched| matches!(
                matched,
                ConfigurationGoalMatch::Recipe(recipe) if recipe.action == action
            )));
            assert!(results.matches().iter().all(|matched| {
                matched.subject()
                    == ConfigurationGoalSubject::Middleware(MiddlewareProduct::ApacheHttpd)
            }));
        }

        let trace = apache_disable_trace_draft().unwrap();
        assert_eq!(trace.raw_bytes(), b"TraceEnable Off\n");
        let trace_rows = trace.rows();
        assert_eq!(trace_rows.len(), 1);
        assert_eq!(trace_rows[0].name(), Some("TraceEnable"));
        assert_eq!(trace_rows[0].arguments(), Some("Off"));

        let disclosure = apache_reduce_version_disclosure_draft().unwrap();
        assert_eq!(
            disclosure.raw_bytes(),
            b"ServerTokens Prod\nServerSignature Off\n"
        );
        let disclosure_rows = disclosure.rows();
        assert_eq!(disclosure_rows.len(), 2);
        assert_eq!(disclosure_rows[0].name(), Some("ServerTokens"));
        assert_eq!(disclosure_rows[0].arguments(), Some("Prod"));
        assert_eq!(disclosure_rows[1].name(), Some("ServerSignature"));
        assert_eq!(disclosure_rows[1].arguments(), Some("Off"));
        assert!(
            !disclosure
                .output()
                .text()
                .unwrap()
                .contains("ServerTokens Off")
        );

        let hostile =
            search_configuration_goals("Apache 禁用 TRACE ; Header set X-Evil yes").unwrap();
        assert!(hostile.matches().iter().any(|matched| matches!(
            matched,
            ConfigurationGoalMatch::Recipe(recipe)
                if recipe.action == ConfigurationGoalRecipeAction::ApacheDisableTrace
        )));
        assert_eq!(
            apache_disable_trace_draft().unwrap().raw_bytes(),
            b"TraceEnable Off\n"
        );

        let redis = search_configuration_goals("Redis 禁用 TRACE").unwrap();
        assert!(!redis.matches().iter().any(|matched| matches!(
            matched,
            ConfigurationGoalMatch::Recipe(recipe)
                if matches!(
                    recipe.action,
                    ConfigurationGoalRecipeAction::ApacheDisableTrace
                        | ConfigurationGoalRecipeAction::ApacheReduceVersionDisclosure
                )
        )));
    }

    #[test]
    fn product_names_rank_only_matching_intents_and_report_typed_gaps() {
        let apache_tls = search_configuration_goals("Apache TLS").unwrap();
        assert!(!apache_tls.matches().iter().any(|matched| matches!(
            matched,
            ConfigurationGoalMatch::Recipe(recipe)
                if recipe.action == ConfigurationGoalRecipeAction::ApacheForbiddenPath403
        )));
        let apache_gap = apache_tls
            .matches()
            .iter()
            .find(|matched| {
                matched.subject()
                    == ConfigurationGoalSubject::Middleware(MiddlewareProduct::ApacheHttpd)
            })
            .and_then(|matched| matched.support_gap());
        assert_eq!(
            apache_gap,
            Some(ConfigurationGoalSupportGap::MissingReviewedIntent)
        );

        let redis = search_configuration_goals("Redis 限制内存").unwrap();
        let redis_gap = redis
            .matches()
            .iter()
            .find(|matched| {
                matched.subject() == ConfigurationGoalSubject::Middleware(MiddlewareProduct::Redis)
            })
            .and_then(|matched| matched.support_gap());
        assert_eq!(
            redis_gap,
            Some(ConfigurationGoalSupportGap::MissingReviewedRecipe)
        );

        let postgres_tls = search_configuration_goals("PostgreSQL TLS").unwrap();
        assert!(!postgres_tls.matches().iter().any(|matched| matches!(
            matched,
            ConfigurationGoalMatch::DatabaseParameter {
                schema,
                parameter_index,
            } if schema.binding.product == DatabaseConfigProduct::PostgreSql
                && schema.parameters[*parameter_index].canonical_key == "max_connections"
        )));
        assert!(postgres_tls.matches().iter().any(|matched| matches!(
            matched,
            ConfigurationGoalMatch::DatabaseGoal { goal, product, .. }
                if goal.key == "database.tls-transport"
                    && *product == DatabaseConfigProduct::PostgreSql
        )));

        let postgres_16 = search_configuration_goals("PostgreSQL 16 max_connections").unwrap();
        let versions = postgres_16
            .matches()
            .iter()
            .filter_map(|matched| match matched {
                ConfigurationGoalMatch::DatabaseParameter {
                    schema,
                    parameter_index,
                } if schema.binding.product == DatabaseConfigProduct::PostgreSql
                    && schema.parameters[*parameter_index].canonical_key == "max_connections" =>
                {
                    Some(schema.version_label)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(versions, vec![">=16.0.0, <17.0.0"]);

        let postgres_15 = search_configuration_goals("PostgreSQL 15 max_connections").unwrap();
        assert!(!postgres_15.matches().iter().any(|matched| matches!(
            matched,
            ConfigurationGoalMatch::DatabaseParameter { schema, .. }
                if schema.binding.product == DatabaseConfigProduct::PostgreSql
        )));
        assert!(postgres_15.matches().iter().any(|matched| matches!(
            matched,
            ConfigurationGoalMatch::UnavailableSubject {
                coverage,
                gap: ConfigurationGoalSupportGap::MissingVersion,
            } if coverage.subject
                == ConfigurationGoalSubject::Database(DatabaseConfigProduct::PostgreSql)
        )));
        assert_eq!(
            database_goal_available_version_labels(DatabaseConfigProduct::PostgreSql),
            vec![
                ">=16.0.0, <17.0.0",
                ">=17.0.0, <18.0.0",
                ">=18.0.0, <19.0.0",
            ]
        );

        for (query, subject) in [
            (
                "TDSQL MySQL 私有化版 提高最大连接数",
                ConfigurationGoalSubject::Database(DatabaseConfigProduct::TdsqlMysqlPrivate),
            ),
            (
                "TDSQL MySQL 托管版 提高最大连接数",
                ConfigurationGoalSubject::Database(DatabaseConfigProduct::TdsqlMysqlManaged),
            ),
            (
                "TDSQL PostgreSQL 私有化版 提高最大连接数",
                ConfigurationGoalSubject::Database(DatabaseConfigProduct::TdsqlPostgresqlPrivate),
            ),
            (
                "PolarDB MySQL 托管版 提高最大连接数",
                ConfigurationGoalSubject::Database(DatabaseConfigProduct::PolarDbManagedMySql),
            ),
            (
                "PolarDB PostgreSQL 托管版 提高最大连接数",
                ConfigurationGoalSubject::Database(DatabaseConfigProduct::PolarDbManagedPostgresql),
            ),
            (
                "MogDB 允许数据库远程连接",
                ConfigurationGoalSubject::Database(DatabaseConfigProduct::MogDb),
            ),
        ] {
            let results = search_configuration_goals(query).unwrap();
            assert!(!results.matches().is_empty(), "{query:?}");
            assert!(!results.truncated(), "{query:?}");
            assert!(
                results
                    .matches()
                    .iter()
                    .all(|matched| matched.subject() == subject),
                "{query:?}: {:?}",
                results.matches()
            );
            assert!(matches!(
                results.matches().first(),
                Some(ConfigurationGoalMatch::UnavailableSubject { .. })
            ));
        }

        let postgres_tls = search_configuration_goals("PostgreSQL TLS").unwrap();
        assert!(postgres_tls.matches().iter().all(|matched| {
            matched.subject()
                == ConfigurationGoalSubject::Database(DatabaseConfigProduct::PostgreSql)
        }));

        let nginx_tls = search_configuration_goals("Nginx TLS").unwrap();
        assert!(matches!(
            nginx_tls.matches(),
            [ConfigurationGoalMatch::UnavailableSubject {
                coverage,
                gap: ConfigurationGoalSupportGap::MissingReviewedIntent,
            }] if coverage.subject
                == ConfigurationGoalSubject::Middleware(MiddlewareProduct::Nginx)
        ));

        for (query, subject) in [
            (
                "MySQL8.4 max_connections",
                ConfigurationGoalSubject::Database(DatabaseConfigProduct::MySql),
            ),
            (
                "PostgreSQL16 max_connections",
                ConfigurationGoalSubject::Database(DatabaseConfigProduct::PostgreSql),
            ),
            (
                "PostgreSQLv16 max_connections",
                ConfigurationGoalSubject::Database(DatabaseConfigProduct::PostgreSql),
            ),
            (
                "openGauss6.0 max_connections",
                ConfigurationGoalSubject::Database(DatabaseConfigProduct::OpenGauss),
            ),
            (
                "TDSQL MySQL 私有化版15 max_connections",
                ConfigurationGoalSubject::Database(DatabaseConfigProduct::TdsqlMysqlPrivate),
            ),
        ] {
            let results = search_configuration_goals(query).unwrap();
            assert!(!results.matches().is_empty(), "{query:?}");
            assert!(
                results
                    .matches()
                    .iter()
                    .all(|matched| matched.subject() == subject),
                "{query:?}: {:?}",
                results.matches()
            );
        }
        let embedded = ConfigurationGoalQuery::parse("mysqlish max_connections").unwrap();
        assert!(
            explicit_configuration_goal_subjects(&embedded).is_empty(),
            "an embedded product fragment must not become an explicit product scope"
        );

        for query in [
            "PostgreSQL 65536 max_connections",
            "PostgreSQL 16.1.2.3.4 max_connections",
            "PostgreSQL v max_connections",
            "PostgreSQL65536 max_connections",
        ] {
            let results = search_configuration_goals(query).unwrap();
            assert!(
                matches!(
                    results.matches(),
                    [ConfigurationGoalMatch::UnavailableSubject {
                        coverage,
                        gap: ConfigurationGoalSupportGap::MissingVersion,
                    }] if coverage.subject
                        == ConfigurationGoalSubject::Database(DatabaseConfigProduct::PostgreSql)
                ),
                "{query:?}: {:?}",
                results.matches()
            );
        }

        let highgo = search_configuration_goals("瀚高 max_connections").unwrap();
        assert!(!highgo.matches().is_empty());
        assert!(highgo.matches().iter().all(|matched| {
            matched.subject() == ConfigurationGoalSubject::Database(DatabaseConfigProduct::HighGo)
        }));

        let shentong = search_configuration_goals("神通数据库 TLS").unwrap();
        let shentong_subjects = shentong
            .matches()
            .iter()
            .map(|matched| matched.subject())
            .collect::<HashSet<_>>();
        assert_eq!(
            shentong_subjects,
            HashSet::from([
                ConfigurationGoalSubject::Database(DatabaseConfigProduct::ShenTongNative),
                ConfigurationGoalSubject::Database(DatabaseConfigProduct::ShenTongMpp),
                ConfigurationGoalSubject::Database(DatabaseConfigProduct::ShenTongOpenGauss),
            ])
        );

        for query in [
            "postgresqlish PostgreSQL 16 max_connections",
            "postgresqlish PostgreSQLv16 max_connections",
        ] {
            let results = search_configuration_goals(query).unwrap();
            let schemas = results
                .matches()
                .iter()
                .filter_map(|matched| match matched {
                    ConfigurationGoalMatch::DatabaseParameter { schema, .. } => Some(*schema),
                    _ => None,
                })
                .collect::<Vec<_>>();
            assert!(!schemas.is_empty(), "{query:?}");
            let requested = DatabaseGoalVersionRequest {
                components: [16, 0, 0, 0],
                component_count: 1,
            };
            assert!(
                schemas
                    .iter()
                    .all(|schema| requested.matches(schema.binding.versions)),
                "{query:?}"
            );
        }

        let mysql = search_configuration_goals("mysqlish MySQL8.4 max_connections").unwrap();
        let mysql_schemas = mysql
            .matches()
            .iter()
            .filter_map(|matched| match matched {
                ConfigurationGoalMatch::DatabaseParameter { schema, .. } => Some(*schema),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(!mysql_schemas.is_empty());
        let requested = DatabaseGoalVersionRequest {
            components: [8, 4, 0, 0],
            component_count: 2,
        };
        assert!(
            mysql_schemas
                .iter()
                .all(|schema| requested.matches(schema.binding.versions))
        );

        let conflicting =
            search_configuration_goals("PostgreSQL16 PostgreSQL17 max_connections").unwrap();
        assert!(matches!(
            conflicting.matches(),
            [ConfigurationGoalMatch::UnavailableSubject {
                coverage,
                gap: ConfigurationGoalSupportGap::MissingVersion,
            }] if coverage.subject
                == ConfigurationGoalSubject::Database(DatabaseConfigProduct::PostgreSql)
        ));
    }

    #[test]
    fn coverage_is_total_for_every_catalogued_product() {
        for product in MiddlewareProduct::ALL {
            let coverage =
                configuration_goal_coverage(ConfigurationGoalSubject::Middleware(product));
            assert_eq!(
                coverage.subject,
                ConfigurationGoalSubject::Middleware(product)
            );
            assert!(!coverage.evidence_summary().is_empty(), "{product:?}");
        }
        for product in DatabaseConfigProduct::ALL {
            let coverage = configuration_goal_coverage(ConfigurationGoalSubject::Database(product));
            assert_eq!(
                coverage.subject,
                ConfigurationGoalSubject::Database(product)
            );
            assert!(!coverage.evidence_summary().is_empty(), "{product:?}");
        }
        assert!(
            configuration_goal_coverage(ConfigurationGoalSubject::Middleware(
                MiddlewareProduct::Redis
            ))
            .evidence_summary()
            .contains("redis.conf")
        );
        assert!(
            configuration_goal_coverage(ConfigurationGoalSubject::Middleware(
                MiddlewareProduct::Tomcat
            ))
            .evidence_summary()
            .contains("server.xml、web.xml、context.xml")
        );
        assert_eq!(
            configuration_goal_coverage(ConfigurationGoalSubject::Middleware(
                MiddlewareProduct::Nginx
            ))
            .availability(),
            ConfigurationGoalAvailability::LocalDraftRecipe
        );
        assert_eq!(
            configuration_goal_coverage(ConfigurationGoalSubject::Database(
                DatabaseConfigProduct::PostgreSql
            ))
            .availability(),
            ConfigurationGoalAvailability::CatalogGuidance
        );
        assert_eq!(
            configuration_goal_coverage(ConfigurationGoalSubject::Database(
                DatabaseConfigProduct::ShenTongNative
            ))
            .availability(),
            ConfigurationGoalAvailability::Unavailable
        );
    }

    #[test]
    fn database_parameter_assignment_operators_validate_normalize_and_revalidate() {
        for operator in ["设置为", "设为", "="] {
            let query = format!("PostgreSQL 16 max_connections {operator} 300");
            let assignment = ready_assignment(&query);
            assert_eq!(
                assignment.schema().binding.product,
                DatabaseConfigProduct::PostgreSql
            );
            assert_eq!(assignment.draft().container_path(), None);
            assert_eq!(assignment.draft().canonical_key(), "max_connections");
            assert_eq!(assignment.draft().normalized_value(), "300");
            assert!(!format!("{assignment:?}").contains("300"));
            let cloned = assignment.clone();
            assert_eq!(cloned.target(), assignment.target());
        }

        let assignment = ready_assignment("PostgreSQL 16 max_connections = 300");
        let revised = revalidate_database_parameter_assignment_value(&assignment, "301").unwrap();
        assert_eq!(revised.target(), assignment.target());
        assert_eq!(revised.draft().normalized_value(), "301");
        let same = revalidate_database_parameter_assignment(&assignment).unwrap();
        assert_eq!(same.target(), assignment.target());
        assert_eq!(same.draft().normalized_value(), "300");
        let invalid_revalidation =
            revalidate_database_parameter_assignment_value(&assignment, &"x".repeat(33))
                .unwrap_err();
        assert!(
            matches!(
                invalid_revalidation,
                DatabaseParameterAssignmentError::Draft(
                    DatabaseParameterGoalDraftError::InvalidValue(_)
                )
            ),
            "{invalid_revalidation:?}"
        );

        let (schema, parameter_index, parameter) = DATABASE_CONFIG_SCHEMAS
            .iter()
            .filter(|schema| schema.binding.product == DatabaseConfigProduct::PostgreSql)
            .filter(|schema| {
                schema
                    .binding
                    .versions
                    .contains(DatabaseConfigVersion::new(16, 0, 0))
            })
            .find_map(|schema| {
                schema
                    .parameters
                    .iter()
                    .enumerate()
                    .find(|(index, parameter)| {
                        parameter.container_path.is_none()
                            && matches!(
                                parameter.value_kind,
                                DatabaseConfigSchemaValueKind::Text {
                                    minimum_bytes,
                                    maximum_bytes,
                                    ..
                                } if minimum_bytes <= 9 && maximum_bytes >= 9
                            )
                            && database_parameter_goal_availability(schema, *index)
                                == ConfigurationGoalAvailability::LocalDraftRecipe
                    })
                    .map(|(index, parameter)| (schema, index, parameter))
            })
            .expect("PostgreSQL 16 has one public draftable text parameter");
        let query = format!(
            "PostgreSQL 16 @{} {} = mysql=v16",
            schema.binding.artifact_key, parameter.canonical_key
        );
        let text = ready_assignment(&query);
        assert_eq!(text.schema(), schema);
        assert_eq!(text.parameter_index(), parameter_index);
        assert_eq!(text.draft().normalized_value(), "mysql=v16");
        assert!(!format!("{text:?}").contains("mysql=v16"));
    }

    #[test]
    fn database_parameter_assignment_qualifiers_resolve_schema_artifact_and_container() {
        let ambiguity =
            match resolve_database_parameter_assignment("MariaDB 11.4 wait_timeout = 60") {
                DatabaseParameterAssignmentResolution::Ambiguous(ambiguity) => ambiguity,
                other => panic!("expected MariaDB container ambiguity, got {other:?}"),
            };
        assert_eq!(ambiguity.candidates().len(), 9);
        assert!(ambiguity.candidates().iter().all(|target| {
            target.schema().binding.artifact_key == "mariadb-option-file"
                && target.parameter().canonical_key == "wait_timeout"
        }));
        assert!(!format!("{ambiguity:?}").contains("60"));
        let mysqld = ambiguity
            .candidates()
            .iter()
            .copied()
            .find(|target| target.parameter().container_path == Some("mysqld"))
            .expect("reviewed mysqld group");
        let selected = select_database_parameter_assignment_candidate(&ambiguity, mysqld).unwrap();
        assert_eq!(selected.target(), mysqld);
        assert_eq!(selected.draft().normalized_value(), "60");

        for query in [
            "MariaDB 11.4 @mariadb-option-file [mysqld] wait_timeout = 60",
            "MariaDB 11.4 @mariadb-option-file [MYSQLD] wait-timeout 设为 60",
            "MariaDB 11.4 [mysqld] wait_timeout 设置为 60",
        ] {
            let assignment = ready_assignment(query);
            assert_eq!(assignment.draft().container_path(), Some("mysqld"));
            assert_eq!(assignment.draft().canonical_key(), "wait_timeout");
            assert_eq!(assignment.draft().normalized_value(), "60");
        }

        assert!(matches!(
            resolve_database_parameter_assignment("TiDB 8.5.7 level = info"),
            DatabaseParameterAssignmentResolution::Ambiguous(_)
        ));
        let tidb = ready_assignment("TiDB 8.5.7 @tidb-server-toml [log] level = info");
        assert_eq!(tidb.schema().binding.artifact_key, "tidb-server-toml");
        assert_eq!(tidb.draft().container_path(), Some("log"));

        assert_eq!(
            rejected_assignment("MariaDB 11.4 @mysql-option-file [mysqld] wait_timeout = 60"),
            DatabaseParameterAssignmentError::ArtifactProductMismatch
        );
        assert_eq!(
            rejected_assignment("MariaDB 11.4 @not-a-real-artifact [mysqld] wait_timeout = 60"),
            DatabaseParameterAssignmentError::UnknownArtifact
        );
        assert_eq!(
            rejected_assignment(
                "MariaDB 11.4 @mariadb-option-file [not-a-group] wait_timeout = 60"
            ),
            DatabaseParameterAssignmentError::UnknownContainer
        );
        assert_eq!(
            rejected_assignment("MariaDB 11.4 @mariadb-option-file [mysqld wait_timeout = 60"),
            DatabaseParameterAssignmentError::InvalidQualifier
        );
    }

    #[test]
    fn assignment_shaped_failures_never_fall_back_to_goal_search() {
        assert!(matches!(
            resolve_database_parameter_assignment("PostgreSQL 16 max_connections"),
            DatabaseParameterAssignmentResolution::NotAssignment
        ));
        for operator in [
            "改成",
            "修改为",
            "调整为",
            "改为",
            "更改为",
            "变更为",
            "设置成",
            "调整成",
            "配置为",
            "置为",
            "赋值为",
            "更新为",
        ] {
            let query = format!("PostgreSQL 16 max_connections {operator} 300");
            assert_eq!(
                rejected_assignment(&query),
                DatabaseParameterAssignmentError::UnsupportedOperator,
                "{query:?}"
            );
        }
        for (query, expected) in [
            ("= 300", DatabaseParameterAssignmentError::MissingTarget),
            (
                "PostgreSQL 16 max_connections = ",
                DatabaseParameterAssignmentError::MissingValue,
            ),
            (
                "PostgreSQL 16 max_connections == 300",
                DatabaseParameterAssignmentError::MultipleOperators,
            ),
            (
                "PostgreSQL 16 max_connections 设置为 300 设为 400",
                DatabaseParameterAssignmentError::MultipleOperators,
            ),
            (
                "max_connections = 300",
                DatabaseParameterAssignmentError::MissingProduct,
            ),
            (
                "MySQL PostgreSQL 16 max_connections = 300",
                DatabaseParameterAssignmentError::AmbiguousProduct,
            ),
            (
                "PostgreSQL 65536 max_connections = 300",
                DatabaseParameterAssignmentError::InvalidVersion,
            ),
            (
                "PostgreSQL 19 max_connections = 300",
                DatabaseParameterAssignmentError::MissingVersion,
            ),
            (
                "PostgreSQL 16 max_connection = 300",
                DatabaseParameterAssignmentError::UnknownParameter,
            ),
        ] {
            assert_eq!(rejected_assignment(query), expected, "{query:?}");
        }
        let too_long = format!(
            "PostgreSQL 16 max_connections = {}",
            "9".repeat(MAX_CONFIGURATION_GOAL_QUERY_CHARS)
        );
        assert_eq!(
            rejected_assignment(&too_long),
            DatabaseParameterAssignmentError::QueryTooLong
        );
        assert_eq!(
            rejected_assignment("PostgreSQL 16 max_connections = 3\n00"),
            DatabaseParameterAssignmentError::InvalidQuery
        );
        assert!(matches!(
            resolve_database_parameter_assignment("PostgreSQL max_connections = 300"),
            DatabaseParameterAssignmentResolution::Ambiguous(_)
        ));
    }

    #[test]
    fn assignment_sensitive_read_only_and_capability_values_fail_closed_without_echo() {
        let sentinel = "NeverEchoAssignment92731";
        let sensitive_query = format!("PostgreSQL 16 ssl_key_file = {sentinel}");
        let sensitive = resolve_database_parameter_assignment(&sensitive_query);
        assert!(matches!(
            sensitive,
            DatabaseParameterAssignmentResolution::Rejected(
                DatabaseParameterAssignmentError::Draft(
                    DatabaseParameterGoalDraftError::NonPublicParameter
                )
            )
        ));
        assert!(!format!("{sensitive:?}").contains(sentinel));

        assert_eq!(
            rejected_assignment("MySQL 8.4 @mysql-option-file [mysqld] audit_log_disable = ON"),
            DatabaseParameterAssignmentError::Draft(
                DatabaseParameterGoalDraftError::RequiredCapability
            )
        );
        assert_eq!(
            rejected_assignment("GoldenDB 6.1.3.10 @goldendb-proxy-ini [SQLEXEC] update_grade = 0"),
            DatabaseParameterAssignmentError::Draft(
                DatabaseParameterGoalDraftError::ReadOnlyArtifact
            )
        );
        let invalid_value = "DontEchoInvalid92731DontEchoInvalid92731";
        let invalid = resolve_database_parameter_assignment(&format!(
            "PostgreSQL 16 max_connections = {invalid_value}"
        ));
        assert!(matches!(
            invalid,
            DatabaseParameterAssignmentResolution::Rejected(
                DatabaseParameterAssignmentError::Draft(
                    DatabaseParameterGoalDraftError::InvalidValue(_)
                )
            )
        ));
        assert!(!format!("{invalid:?}").contains(invalid_value));

        let ambiguity = match resolve_database_parameter_assignment(
            "MariaDB 11.4 wait_timeout = DontEchoAmbiguous92731",
        ) {
            DatabaseParameterAssignmentResolution::Ambiguous(ambiguity) => ambiguity,
            other => panic!("expected ambiguity, got {other:?}"),
        };
        assert!(!format!("{ambiguity:?}").contains("DontEchoAmbiguous92731"));
        let candidate = ambiguity.candidates()[0];
        let error = select_database_parameter_assignment_candidate(&ambiguity, candidate)
            .expect_err("the selected integer value is invalid");
        assert!(matches!(
            error,
            DatabaseParameterAssignmentError::Draft(DatabaseParameterGoalDraftError::InvalidValue(
                _
            ))
        ));
        assert!(!format!("{error:?}").contains("DontEchoAmbiguous92731"));

        let unrelated = ready_assignment("PostgreSQL 16 max_connections = 300").target();
        assert_eq!(
            select_database_parameter_assignment_candidate(&ambiguity, unrelated).unwrap_err(),
            DatabaseParameterAssignmentError::UnknownCandidate
        );
    }

    #[test]
    fn every_actionable_exact_alias_resolves_to_its_canonical_static_target() {
        let mut covered = 0usize;
        for schema in DATABASE_CONFIG_SCHEMAS {
            let version = match schema.binding.versions {
                DatabaseConfigVersionSelector::Exact(version)
                | DatabaseConfigVersionSelector::HalfOpen {
                    minimum_inclusive: version,
                    ..
                } => version,
            };
            for (parameter_index, parameter) in schema.parameters.iter().enumerate() {
                if database_parameter_goal_availability(schema, parameter_index)
                    != ConfigurationGoalAvailability::LocalDraftRecipe
                {
                    continue;
                }
                for alias in parameter.exact_aliases {
                    covered += 1;
                    let container = parameter
                        .container_path
                        .map_or_else(String::new, |container| format!(" [{container}]"));
                    let query = format!(
                        "{} {}.{}.{}.{} @{}{} {} = {}",
                        ConfigurationGoalSubject::Database(schema.binding.product).label(),
                        version.major(),
                        version.minor(),
                        version.patch(),
                        version.revision(),
                        schema.binding.artifact_key,
                        container,
                        alias,
                        valid_projected_value(parameter),
                    );
                    let assignment = ready_assignment(&query);
                    assert!(std::ptr::eq(assignment.schema(), schema), "{query:?}");
                    assert_eq!(assignment.parameter_index(), parameter_index, "{query:?}");
                    assert_eq!(
                        assignment.draft().canonical_key(),
                        parameter.canonical_key,
                        "{query:?}"
                    );
                }
            }
        }
        assert_eq!(covered, 579, "actionable alias inventory changed");
    }

    #[test]
    fn actionable_database_parameter_goals_are_unique_and_canonical() {
        let mut identities = HashSet::new();
        let mut actionable = 0usize;
        for schema in DATABASE_CONFIG_SCHEMAS {
            for (parameter_index, parameter) in schema.parameters.iter().enumerate() {
                if database_parameter_goal_availability(schema, parameter_index)
                    != ConfigurationGoalAvailability::LocalDraftRecipe
                {
                    continue;
                }
                actionable += 1;
                assert!(identities.insert((
                    schema.binding.product,
                    schema.version_label,
                    schema.binding.artifact_key,
                    parameter.container_path,
                    parameter.canonical_key,
                )));
                let raw = valid_projected_value(parameter);
                let draft =
                    validate_database_parameter_goal_value(schema, parameter_index, &raw).unwrap();
                assert_eq!(draft.container_path(), parameter.container_path);
                assert_eq!(draft.canonical_key(), parameter.canonical_key);
                assert!(!draft.normalized_value().is_empty());
            }
        }
        assert!(actionable > 0);

        let (schema, parameter_index, parameter) = DATABASE_CONFIG_SCHEMAS
            .iter()
            .flat_map(|schema| {
                schema
                    .parameters
                    .iter()
                    .enumerate()
                    .map(move |(index, parameter)| (schema, index, parameter))
            })
            .find(|(schema, index, parameter)| {
                !parameter.exact_aliases.is_empty()
                    && database_parameter_goal_availability(schema, *index)
                        == ConfigurationGoalAvailability::LocalDraftRecipe
            })
            .expect("at least one actionable reviewed alias");
        let draft = validate_database_parameter_goal_value(
            schema,
            parameter_index,
            &valid_projected_value(parameter),
        )
        .unwrap();
        assert_eq!(draft.canonical_key(), parameter.canonical_key);
        assert_ne!(draft.canonical_key(), parameter.exact_aliases[0]);

        let (schema, parameter_index) = DATABASE_CONFIG_SCHEMAS
            .iter()
            .find_map(|schema| {
                schema
                    .parameters
                    .iter()
                    .enumerate()
                    .find(|(index, parameter)| {
                        matches!(
                            parameter.value_kind,
                            DatabaseConfigSchemaValueKind::Text {
                                minimum_bytes,
                                maximum_bytes,
                                ..
                            } if minimum_bytes <= 24 && maximum_bytes >= 24
                        ) && database_parameter_goal_availability(schema, *index)
                            == ConfigurationGoalAvailability::LocalDraftRecipe
                    })
                    .map(|(index, _)| (schema, index))
            })
            .expect("actionable text projection");
        let raw = "UniquePublicDraft92731";
        let draft = validate_database_parameter_goal_value(schema, parameter_index, raw).unwrap();
        assert_eq!(draft.normalized_value(), raw);
        assert!(!format!("{draft:?}").contains(raw));
    }

    #[test]
    fn projected_value_kinds_validate_and_fail_closed() {
        let mut covered = HashSet::new();
        for schema in DATABASE_CONFIG_SCHEMAS {
            for (parameter_index, parameter) in schema.parameters.iter().enumerate() {
                if database_parameter_goal_availability(schema, parameter_index)
                    != ConfigurationGoalAvailability::LocalDraftRecipe
                {
                    continue;
                }
                let (kind, invalid) = match parameter.value_kind {
                    DatabaseConfigSchemaValueKind::Boolean { .. } => {
                        ("boolean", "not-a-boolean".to_owned())
                    }
                    DatabaseConfigSchemaValueKind::Integer { .. } => {
                        ("integer", "not-an-integer".to_owned())
                    }
                    DatabaseConfigSchemaValueKind::Enumeration { .. } => {
                        ("enumeration", "not-a-reviewed-choice".to_owned())
                    }
                    DatabaseConfigSchemaValueKind::Text { maximum_bytes, .. } => {
                        ("text", "x".repeat(maximum_bytes + 1))
                    }
                };
                if !covered.insert(kind) {
                    continue;
                }
                assert!(
                    validate_database_parameter_goal_value(
                        schema,
                        parameter_index,
                        &valid_projected_value(parameter)
                    )
                    .is_ok()
                );
                assert!(matches!(
                    validate_database_parameter_goal_value(schema, parameter_index, &invalid),
                    Err(DatabaseParameterGoalDraftError::InvalidValue(_))
                ));
            }
        }
        assert_eq!(
            covered,
            HashSet::from(["boolean", "integer", "enumeration", "text"])
        );

        let (schema, parameter_index) = DATABASE_CONFIG_SCHEMAS
            .iter()
            .find_map(|schema| {
                schema
                    .parameters
                    .iter()
                    .enumerate()
                    .find(|(index, parameter)| {
                        matches!(
                            parameter.value_kind,
                            DatabaseConfigSchemaValueKind::Text {
                                minimum_bytes,
                                maximum_bytes,
                                ..
                            } if minimum_bytes <= 12 && maximum_bytes >= 12
                        ) && database_parameter_goal_availability(schema, *index)
                            == ConfigurationGoalAvailability::LocalDraftRecipe
                    })
                    .map(|(index, _)| (schema, index))
            })
            .expect("actionable text projection for control-character boundary");
        assert_eq!(
            validate_database_parameter_goal_value(schema, parameter_index, "safe\ninjectx")
                .unwrap_err(),
            DatabaseParameterGoalDraftError::UnsafeValue
        );
    }

    #[test]
    fn sensitive_capability_and_read_only_parameters_remain_guidance_only() {
        let sensitive = DATABASE_CONFIG_SCHEMAS
            .iter()
            .flat_map(|schema| {
                schema
                    .parameters
                    .iter()
                    .enumerate()
                    .map(move |(index, parameter)| (schema, index, parameter))
            })
            .find(|(_, _, parameter)| {
                parameter.sensitivity != DatabaseConfigSchemaSensitivity::Public
            })
            .expect("reviewed non-public parameter");
        assert_eq!(
            database_parameter_goal_availability(sensitive.0, sensitive.1),
            ConfigurationGoalAvailability::CatalogGuidance
        );
        assert_eq!(
            validate_database_parameter_goal_value(sensitive.0, sensitive.1, "NeverExpose")
                .unwrap_err(),
            DatabaseParameterGoalDraftError::NonPublicParameter
        );

        let capability = DATABASE_CONFIG_SCHEMAS
            .iter()
            .flat_map(|schema| {
                schema
                    .parameters
                    .iter()
                    .enumerate()
                    .map(move |(index, parameter)| (schema, index, parameter))
            })
            .find(|(schema, _, parameter)| {
                parameter.required_capability.is_some()
                    && parameter.sensitivity == DatabaseConfigSchemaSensitivity::Public
                    && artifact_by_key(schema.binding.artifact_key)
                        .is_some_and(|artifact| artifact.allows_lossless_local_draft())
            })
            .expect("reviewed capability-bound parameter");
        assert_eq!(
            validate_database_parameter_goal_value(
                capability.0,
                capability.1,
                &valid_projected_value(capability.2),
            )
            .unwrap_err(),
            DatabaseParameterGoalDraftError::RequiredCapability
        );

        let readonly = DATABASE_CONFIG_SCHEMAS
            .iter()
            .find_map(|schema| {
                schema
                    .parameters
                    .iter()
                    .enumerate()
                    .find(|(_, parameter)| {
                        parameter.sensitivity == DatabaseConfigSchemaSensitivity::Public
                            && parameter.required_capability.is_none()
                            && artifact_by_key(schema.binding.artifact_key)
                                .is_some_and(|artifact| !artifact.allows_lossless_local_draft())
                    })
                    .map(|(index, parameter)| (schema, index, parameter))
            })
            .expect("reviewed read-only parameter");
        assert!(matches!(
            validate_database_parameter_goal_value(
                readonly.0,
                readonly.1,
                &valid_projected_value(readonly.2),
            ),
            Err(DatabaseParameterGoalDraftError::ReadOnlyArtifact)
        ));
    }
}
