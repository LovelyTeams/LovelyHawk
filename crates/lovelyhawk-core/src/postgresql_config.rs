//! Deterministic, bounded PostgreSQL configuration fragments for newly
//! initialized, empty clusters.
//!
//! This module supports only PostgreSQL major versions that are still
//! supported on 2026-08-24: 14, 15, 16, 17, and 18. It emits one incomplete
//! `postgresql.conf` include fragment; it does not add an `include` directive,
//! initialize a cluster, discover precedence, deploy, overwrite, reload, or
//! restart PostgreSQL. Existing or data-bearing clusters require a separate
//! inventory, migration, backup, rollback, and target read-back workflow.
//!
//! Official references used by the closed model:
//! - <https://www.postgresql.org/support/versioning/>
//! - <https://www.postgresql.org/docs/18/config-setting.html>
//! - <https://www.postgresql.org/docs/18/runtime-config-connection.html>
//! - <https://www.postgresql.org/docs/18/runtime-config-wal.html>
//! - <https://www.postgresql.org/docs/18/runtime-config-vacuum.html>
//! - <https://www.postgresql.org/docs/18/runtime-config-resource.html>
//! - <https://www.postgresql.org/docs/18/runtime-config-client.html>
//! - <https://www.postgresql.org/docs/18/runtime-config-logging.html>
//! - <https://www.postgresql.org/docs/18/runtime-config-locks.html>
//! - <https://www.postgresql.org/docs/18/runtime-config-statistics.html>

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Component, Path, PathBuf},
};

use crate::{
    CoreError, CoreResult,
    line_config_visual::{LineConfigDialect, LineConfigNodeKind, LineConfigVisualDocument},
};

pub const MAX_GENERATED_POSTGRESQL_CONFIG_BYTES: usize = 16 * 1024;
pub const POSTGRESQL_VERSIONING_REFERENCE: &str = "https://www.postgresql.org/support/versioning/";
pub const POSTGRESQL_CONFIGURATION_REFERENCE: &str =
    "https://www.postgresql.org/docs/18/config-setting.html";
pub const POSTGRESQL_CONNECTION_REFERENCE: &str =
    "https://www.postgresql.org/docs/18/runtime-config-connection.html";
pub const POSTGRESQL_WAL_REFERENCE: &str =
    "https://www.postgresql.org/docs/18/runtime-config-wal.html";
pub const POSTGRESQL_AUTOVACUUM_REFERENCE: &str =
    "https://www.postgresql.org/docs/18/runtime-config-vacuum.html";
pub const POSTGRESQL_RESOURCE_REFERENCE: &str =
    "https://www.postgresql.org/docs/18/runtime-config-resource.html";
pub const POSTGRESQL_CLIENT_REFERENCE: &str =
    "https://www.postgresql.org/docs/18/runtime-config-client.html";
pub const POSTGRESQL_LOGGING_REFERENCE: &str =
    "https://www.postgresql.org/docs/18/runtime-config-logging.html";
pub const POSTGRESQL_LOCKS_REFERENCE: &str =
    "https://www.postgresql.org/docs/18/runtime-config-locks.html";
pub const POSTGRESQL_STATISTICS_REFERENCE: &str =
    "https://www.postgresql.org/docs/18/runtime-config-statistics.html";
pub const POSTGRESQL_17_LOGGING_REFERENCE: &str =
    "https://www.postgresql.org/docs/17/runtime-config-logging.html";
pub const POSTGRESQL_16_RELEASE_REFERENCE: &str =
    "https://www.postgresql.org/docs/16/release-16.html";
pub const POSTGRESQL_HBA_REFERENCE: &str =
    "https://www.postgresql.org/docs/18/auth-pg-hba-conf.html";
pub const POSTGRESQL_TLS_REFERENCE: &str = "https://www.postgresql.org/docs/18/ssl-tcp.html";
pub const POSTGRESQL_INITDB_REFERENCE: &str = "https://www.postgresql.org/docs/18/app-initdb.html";

pub const POSTGRESQL_OFFICIAL_REFERENCES: &[&str] = &[
    POSTGRESQL_VERSIONING_REFERENCE,
    POSTGRESQL_CONFIGURATION_REFERENCE,
    POSTGRESQL_CONNECTION_REFERENCE,
    POSTGRESQL_WAL_REFERENCE,
    POSTGRESQL_AUTOVACUUM_REFERENCE,
    POSTGRESQL_RESOURCE_REFERENCE,
    POSTGRESQL_CLIENT_REFERENCE,
    POSTGRESQL_LOGGING_REFERENCE,
    POSTGRESQL_LOCKS_REFERENCE,
    POSTGRESQL_STATISTICS_REFERENCE,
    POSTGRESQL_17_LOGGING_REFERENCE,
    POSTGRESQL_16_RELEASE_REFERENCE,
    POSTGRESQL_HBA_REFERENCE,
    POSTGRESQL_TLS_REFERENCE,
    POSTGRESQL_INITDB_REFERENCE,
];

pub const POSTGRESQL_HBA_IDENT_DEFERRED_REASON: &str = "pg_hba.conf 与 pg_ident.conf 决定真实连接准入和身份映射；当前片段不生成、不引用也不修改它们，必须在精确目标上独立审阅并验证。";
pub const POSTGRESQL_AUTO_CONF_DEFERRED_REASON: &str =
    "postgresql.auto.conf 是 ALTER SYSTEM 管理的高优先级生成态；当前模块不读取、不生成也不覆盖它。";
pub const POSTGRESQL_TLS_SECRET_ROLE_DEFERRED_REASON: &str = "TLS 证书与私钥、密码/secret、角色及其授权需要 core-owned 凭据和权限验证边界；当前模块明确不生成。";
pub const POSTGRESQL_ARCHIVE_PRELOAD_DEFERRED_REASON: &str = "archive_command、归档/恢复命令和 shared_preload_libraries 会执行外部程序或装载代码；当前模块明确不生成。";
pub const POSTGRESQL_RESOURCE_TUNING_DEFERRED_REASON: &str = "shared_buffers、work_mem 等资源参数必须结合目标内存、并发、工作负载与 build 约束进行 sizing；当前模块不伪造通用值。";
pub const POSTGRESQL_STATEMENT_LOG_TEXT_DEFERRED_REASON: &str = "全局 statement_timeout、lock_timeout 与 SQL/参数文本日志会改变应用行为或泄露敏感数据；当前模块不生成这些全局超时、log_statement 或 duration/query-text 日志。";
pub const POSTGRESQL_EXISTING_CLUSTER_DEFERRED_REASON: &str = "既有或含数据集群不能通过静态片段安全迁移；必须先盘点完整来源与优先级，并提供备份、回滚、重启和数据/行为回读。";
pub const POSTGRESQL_REMOTE_LISTENING_DEFERRED_REASON: &str = "非回环监听必须与 HBA、TLS、主机防火墙和真实客户端验证形成闭环；当前模块固定 listen_addresses 为 localhost。";

const MAX_POSTGRESQL_CONNECTIONS: u64 = 10_000;
const MAX_AUTHENTICATION_TIMEOUT_SECONDS: u64 = 3_600;
const MAX_IDLE_IN_TRANSACTION_TIMEOUT_SECONDS: u64 = 604_800;
const MAX_IDLE_SESSION_TIMEOUT_SECONDS: u64 = 604_800;
const MAX_TEMPORARY_FILE_LIMIT_MEBIBYTES: u64 = 1_048_576;
const MAX_DEADLOCK_TIMEOUT_MILLISECONDS: u64 = 3_600_000;
const MAX_AUTOVACUUM_LOG_THRESHOLD_MILLISECONDS: u64 = 86_400_000;
const MAX_TEMPORARY_FILE_LOG_THRESHOLD_KILOBYTES: u64 = 1_073_741_824;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PostgreSqlVersion {
    V14,
    V15,
    V16,
    V17,
    V18,
}

impl PostgreSqlVersion {
    pub const ALL: [Self; 5] = [Self::V14, Self::V15, Self::V16, Self::V17, Self::V18];

    pub const fn major(self) -> u16 {
        match self {
            Self::V14 => 14,
            Self::V15 => 15,
            Self::V16 => 16,
            Self::V17 => 17,
            Self::V18 => 18,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::V14 => "14",
            Self::V15 => "15",
            Self::V16 => "16",
            Self::V17 => "17",
            Self::V18 => "18",
        }
    }

    pub fn parse(value: &str) -> CoreResult<Self> {
        let major = parse_decimal(value, 14, 18, "PostgreSQL major version")?;
        Self::try_from(major as u16)
    }

    pub const fn supports_reserved_connections(self) -> bool {
        matches!(self, Self::V16 | Self::V17 | Self::V18)
    }

    pub const fn connection_logging_value(self) -> &'static str {
        match self {
            Self::V14 | Self::V15 | Self::V16 | Self::V17 => "on",
            Self::V18 => "'receipt,authentication,authorization'",
        }
    }

    pub const fn official_documentation(self) -> &'static str {
        match self {
            Self::V14 => "https://www.postgresql.org/docs/14/",
            Self::V15 => "https://www.postgresql.org/docs/15/",
            Self::V16 => "https://www.postgresql.org/docs/16/",
            Self::V17 => "https://www.postgresql.org/docs/17/",
            Self::V18 => "https://www.postgresql.org/docs/18/",
        }
    }

    pub const fn support_notice(self) -> &'static str {
        match self {
            Self::V14 => {
                "PostgreSQL 14 的官方支持将于 2026-11-12 结束；使用前必须重新确认支持状态并升级到最新 14.x 小版本。"
            }
            Self::V15 => {
                "PostgreSQL 15 的官方支持计划于 2027-11-11 结束；使用精确目标 major 的最新小版本。"
            }
            Self::V16 => {
                "PostgreSQL 16 的官方支持计划于 2028-11-09 结束；使用精确目标 major 的最新小版本。"
            }
            Self::V17 => {
                "PostgreSQL 17 的官方支持计划于 2029-11-08 结束；使用精确目标 major 的最新小版本。"
            }
            Self::V18 => {
                "PostgreSQL 18 的官方支持计划于 2030-11-14 结束；使用精确目标 major 的最新小版本。"
            }
        }
    }

    pub const fn risk(self) -> &'static str {
        match self {
            Self::V14 => {
                "该 major 已临近 EOL；EOL 后继续新建实例会失去社区安全修复，不能把此生成器当成延长支持。"
            }
            Self::V15 | Self::V16 | Self::V17 | Self::V18 => {
                "跨 major 的参数、默认值和数据目录不保证兼容；片段必须由完全相同 major 的目标验证。"
            }
        }
    }
}

impl TryFrom<u16> for PostgreSqlVersion {
    type Error = CoreError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            14 => Ok(Self::V14),
            15 => Ok(Self::V15),
            16 => Ok(Self::V16),
            17 => Ok(Self::V17),
            18 => Ok(Self::V18),
            _ => Err(CoreError::validation(
                "PostgreSQL major version",
                "must be one currently supported major: 14, 15, 16, 17, or 18",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PostgreSqlConfigFeature {
    ConnectionCapacity,
    AuthenticationTimeout,
    IdleInTransactionGuard,
    IdleSessionGuard,
    TemporaryFileLimit,
    ConnectionLifecycleLogging,
    LockWaitLogging,
    CheckpointLogging,
    AutovacuumLogging,
    TemporaryFileLogging,
    IoTiming,
    WalCompression,
    QueryIdentifier,
}

impl PostgreSqlConfigFeature {
    pub const ALL: [Self; 13] = [
        Self::ConnectionCapacity,
        Self::AuthenticationTimeout,
        Self::IdleInTransactionGuard,
        Self::IdleSessionGuard,
        Self::TemporaryFileLimit,
        Self::ConnectionLifecycleLogging,
        Self::LockWaitLogging,
        Self::CheckpointLogging,
        Self::AutovacuumLogging,
        Self::TemporaryFileLogging,
        Self::IoTiming,
        Self::WalCompression,
        Self::QueryIdentifier,
    ];

    pub const fn key(self) -> &'static str {
        match self {
            Self::ConnectionCapacity => "connection-capacity",
            Self::AuthenticationTimeout => "authentication-timeout",
            Self::IdleInTransactionGuard => "idle-in-transaction-guard",
            Self::IdleSessionGuard => "idle-session-guard",
            Self::TemporaryFileLimit => "temporary-file-limit",
            Self::ConnectionLifecycleLogging => "connection-lifecycle-logging",
            Self::LockWaitLogging => "lock-wait-logging",
            Self::CheckpointLogging => "checkpoint-logging",
            Self::AutovacuumLogging => "autovacuum-logging",
            Self::TemporaryFileLogging => "temporary-file-logging",
            Self::IoTiming => "io-timing",
            Self::WalCompression => "wal-compression",
            Self::QueryIdentifier => "query-identifier",
        }
    }

    pub const fn title(self) -> &'static str {
        match self {
            Self::ConnectionCapacity => "设置连接容量与应急保留槽",
            Self::AuthenticationTimeout => "限制认证握手时间",
            Self::IdleInTransactionGuard => "终止事务内长期空闲会话",
            Self::IdleSessionGuard => "终止事务外长期空闲会话",
            Self::TemporaryFileLimit => "限制单进程临时文件空间",
            Self::ConnectionLifecycleLogging => "记录连接与断开生命周期",
            Self::LockWaitLogging => "按明确阈值记录锁等待",
            Self::CheckpointLogging => "记录 checkpoint 与 restartpoint",
            Self::AutovacuumLogging => "按耗时阈值记录 autovacuum",
            Self::TemporaryFileLogging => "按大小阈值记录临时文件",
            Self::IoTiming => "采集数据文件与 WAL I/O 计时",
            Self::WalCompression => "使用内建 pglz 压缩 WAL 全页镜像",
            Self::QueryIdentifier => "启用内核查询标识符计算",
        }
    }

    pub const fn summary(self) -> &'static str {
        match self {
            Self::ConnectionCapacity => {
                "显式设置 max_connections 与超级用户保留槽；PostgreSQL 16+ 还设置普通保留角色槽。"
            }
            Self::AuthenticationTimeout => "限制未完成认证的客户端占用连接资源的时间。",
            Self::IdleInTransactionGuard => {
                "终止事务中长期空闲的会话，降低锁与旧快照长期保留风险。"
            }
            Self::IdleSessionGuard => {
                "终止事务外长期空闲会话；主要用于明确知道客户端连接生命周期的场景。"
            }
            Self::TemporaryFileLimit => {
                "限制每个 PostgreSQL 进程用于排序、哈希等操作的临时文件总量。"
            }
            Self::ConnectionLifecycleLogging => {
                "记录连接接收、认证/授权完成和会话断开，不开启 SQL 文本日志。"
            }
            Self::LockWaitLogging => {
                "成组设置 deadlock_timeout 与 log_lock_waits，让日志阈值明确且可验证。"
            }
            Self::CheckpointLogging => {
                "记录 checkpoint/restartpoint 的缓冲区写入数量与耗时等统计。"
            }
            Self::AutovacuumLogging => {
                "记录达到阈值的自动 VACUUM/ANALYZE，并记录因锁冲突等原因跳过的动作。"
            }
            Self::TemporaryFileLogging => {
                "临时文件删除时记录达到大小阈值的文件名与字节数，用于发现磁盘型排序/哈希。"
            }
            Self::IoTiming => {
                "同时启用 track_io_timing 与 track_wal_io_timing，补充数据文件和 WAL I/O 耗时。"
            }
            Self::WalCompression => {
                "压缩 WAL 中的全页镜像；14 使用 on，15–18 使用语义相同的 pglz。"
            }
            Self::QueryIdentifier => {
                "设置 compute_query_id=on，供 pg_stat_activity、EXPLAIN 与兼容扩展关联查询。"
            }
        }
    }

    pub const fn aliases(self) -> &'static [&'static str] {
        match self {
            Self::ConnectionCapacity => &[
                "max_connections",
                "reserved_connections",
                "superuser_reserved_connections",
                "连接数",
                "保留连接",
            ],
            Self::AuthenticationTimeout => &["authentication_timeout", "认证超时", "握手超时"],
            Self::IdleInTransactionGuard => &[
                "idle_in_transaction_session_timeout",
                "空闲事务",
                "idle transaction",
            ],
            Self::IdleSessionGuard => {
                &["idle_session_timeout", "空闲连接", "连接池", "idle session"]
            }
            Self::TemporaryFileLimit => &["temp_file_limit", "临时文件", "磁盘保护"],
            Self::ConnectionLifecycleLogging => {
                &["log_connections", "log_disconnections", "连接日志"]
            }
            Self::LockWaitLogging => &["log_lock_waits", "锁等待", "deadlock_timeout"],
            Self::CheckpointLogging => &["log_checkpoints", "checkpoint", "检查点日志"],
            Self::AutovacuumLogging => {
                &["log_autovacuum_min_duration", "autovacuum", "自动清理日志"]
            }
            Self::TemporaryFileLogging => {
                &["log_temp_files", "temp files", "临时文件日志", "排序落盘"]
            }
            Self::IoTiming => &[
                "track_io_timing",
                "track_wal_io_timing",
                "I/O timing",
                "IO 耗时",
            ],
            Self::WalCompression => &["wal_compression", "pglz", "WAL 压缩"],
            Self::QueryIdentifier => &[
                "compute_query_id",
                "query id",
                "查询标识符",
                "pg_stat_statements",
            ],
        }
    }

    pub const fn scope(self) -> &'static str {
        match self {
            Self::ConnectionCapacity => "集群/连接",
            Self::AuthenticationTimeout => "集群/认证",
            Self::IdleInTransactionGuard | Self::IdleSessionGuard | Self::TemporaryFileLimit => {
                "集群默认/会话行为"
            }
            Self::ConnectionLifecycleLogging
            | Self::LockWaitLogging
            | Self::CheckpointLogging
            | Self::AutovacuumLogging
            | Self::TemporaryFileLogging => "日志/可观测性",
            Self::IoTiming | Self::QueryIdentifier => "统计/可观测性",
            Self::WalCompression => "WAL/存储",
        }
    }

    pub const fn risk(self) -> &'static str {
        match self {
            Self::ConnectionCapacity => {
                "提高连接上限会增加共享内存和后端资源占用；保留槽过少会失去应急入口，过多会挤压普通连接。"
            }
            Self::AuthenticationTimeout => "阈值过短会拒绝高延迟或外部认证较慢的合法客户端。",
            Self::IdleInTransactionGuard => {
                "超时会主动断开会话并回滚其未提交事务，应用必须能正确处理。"
            }
            Self::IdleSessionGuard => {
                "事务外空闲通常成本很低；连接池或中间件可能无法正确处理服务端意外断连，启用前必须验证。"
            }
            Self::TemporaryFileLimit => {
                "限制按进程计算且不覆盖显式临时表；过低会让合法大查询失败，多个进程仍可并行消耗磁盘。"
            }
            Self::ConnectionLifecycleLogging => {
                "会增加日志量，并可能记录数据库名、用户名、应用名和远端地址等运行元数据。"
            }
            Self::LockWaitLogging => {
                "deadlock_timeout 也控制昂贵的死锁检查；阈值过低会增加检查开销并在繁忙系统产生大量日志。"
            }
            Self::CheckpointLogging => {
                "会增加少量日志；频繁 checkpoint 通常提示 WAL sizing 或负载问题。"
            }
            Self::AutovacuumLogging => {
                "阈值过低会产生大量日志，且日志包含表/索引名称与运行统计等数据库元数据。"
            }
            Self::TemporaryFileLogging => {
                "阈值为零会记录所有临时文件；高并发查询可能产生大量含文件路径和大小的日志。"
            }
            Self::IoTiming => {
                "会反复读取操作系统时钟，在部分平台有显著开销；应先用 pg_test_timing 验证目标。"
            }
            Self::WalCompression => {
                "减少 WAL 体积但消耗压缩/回放 CPU；当前仅开放所有目标都具备的内建 pglz。"
            }
            Self::QueryIdentifier => {
                "外部模块也可能计算 query id；必须保证只有一个提供者，且标识符不能跨 major 视为稳定。"
            }
        }
    }

    pub const fn activation(self) -> &'static str {
        match self {
            Self::ConnectionCapacity => "需要重启",
            Self::AuthenticationTimeout => "重载配置",
            Self::IdleInTransactionGuard | Self::IdleSessionGuard | Self::TemporaryFileLimit => {
                "重载后影响新会话"
            }
            Self::ConnectionLifecycleLogging => "重载后影响新连接",
            Self::LockWaitLogging
            | Self::CheckpointLogging
            | Self::AutovacuumLogging
            | Self::TemporaryFileLogging
            | Self::IoTiming
            | Self::WalCompression
            | Self::QueryIdentifier => "重载配置",
        }
    }

    pub const fn default_enabled(self) -> bool {
        false
    }

    pub const fn supports_version(self, _version: PostgreSqlVersion) -> bool {
        true
    }

    pub const fn official_reference(self) -> &'static str {
        match self {
            Self::ConnectionCapacity | Self::AuthenticationTimeout => {
                POSTGRESQL_CONNECTION_REFERENCE
            }
            Self::IdleInTransactionGuard | Self::IdleSessionGuard => POSTGRESQL_CLIENT_REFERENCE,
            Self::TemporaryFileLimit => POSTGRESQL_RESOURCE_REFERENCE,
            Self::ConnectionLifecycleLogging
            | Self::CheckpointLogging
            | Self::AutovacuumLogging
            | Self::TemporaryFileLogging => POSTGRESQL_LOGGING_REFERENCE,
            Self::LockWaitLogging => POSTGRESQL_LOCKS_REFERENCE,
            Self::IoTiming | Self::QueryIdentifier => POSTGRESQL_STATISTICS_REFERENCE,
            Self::WalCompression => POSTGRESQL_WAL_REFERENCE,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PostgreSqlPort(u16);

impl PostgreSqlPort {
    pub fn parse(value: &str) -> CoreResult<Self> {
        Ok(Self(
            parse_decimal(value, 1, 65_535, "PostgreSQL port")? as u16
        ))
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PostgreSqlConnectionCapacity {
    max_connections: u32,
    superuser_reserved_connections: u32,
    reserved_connections: u32,
}

impl PostgreSqlConnectionCapacity {
    pub fn new(
        max_connections: u32,
        superuser_reserved_connections: u32,
        reserved_connections: u32,
    ) -> CoreResult<Self> {
        if max_connections == 0 || u64::from(max_connections) > MAX_POSTGRESQL_CONNECTIONS {
            return Err(CoreError::validation(
                "PostgreSQL max_connections",
                format!("must be in 1..={MAX_POSTGRESQL_CONNECTIONS} under this generator policy"),
            ));
        }
        if u64::from(superuser_reserved_connections) > MAX_POSTGRESQL_CONNECTIONS
            || u64::from(reserved_connections) > MAX_POSTGRESQL_CONNECTIONS
        {
            return Err(CoreError::validation(
                "PostgreSQL reserved connection slots",
                format!("each value must be in 0..={MAX_POSTGRESQL_CONNECTIONS}"),
            ));
        }
        if superuser_reserved_connections + reserved_connections >= max_connections {
            return Err(CoreError::validation(
                "PostgreSQL connection capacity",
                "superuser_reserved_connections + reserved_connections must be less than max_connections",
            ));
        }
        Ok(Self {
            max_connections,
            superuser_reserved_connections,
            reserved_connections,
        })
    }

    pub fn parse(
        max_connections: &str,
        superuser_reserved_connections: &str,
        reserved_connections: &str,
    ) -> CoreResult<Self> {
        let maximum = parse_decimal(
            max_connections,
            1,
            MAX_POSTGRESQL_CONNECTIONS,
            "PostgreSQL max_connections",
        )? as u32;
        let superuser = parse_decimal(
            superuser_reserved_connections,
            0,
            MAX_POSTGRESQL_CONNECTIONS,
            "PostgreSQL superuser_reserved_connections",
        )? as u32;
        let reserved = parse_decimal(
            reserved_connections,
            0,
            MAX_POSTGRESQL_CONNECTIONS,
            "PostgreSQL reserved_connections",
        )? as u32;
        Self::new(maximum, superuser, reserved)
    }

    pub const fn lovelyres_suggestion() -> Self {
        Self {
            max_connections: 100,
            superuser_reserved_connections: 3,
            reserved_connections: 0,
        }
    }

    pub const fn max_connections(self) -> u32 {
        self.max_connections
    }

    pub const fn superuser_reserved_connections(self) -> u32 {
        self.superuser_reserved_connections
    }

    pub const fn reserved_connections(self) -> u32 {
        self.reserved_connections
    }

    fn validate_for_version(self, version: PostgreSqlVersion) -> CoreResult<()> {
        if !version.supports_reserved_connections() && self.reserved_connections != 0 {
            return Err(CoreError::validation(
                "PostgreSQL reserved_connections",
                format!(
                    "is unavailable in PostgreSQL {}; use zero or select PostgreSQL 16 or newer",
                    version.label()
                ),
            ));
        }
        Self::new(
            self.max_connections,
            self.superuser_reserved_connections,
            self.reserved_connections,
        )
        .map(|_| ())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PostgreSqlAuthenticationTimeoutSeconds(u32);

impl PostgreSqlAuthenticationTimeoutSeconds {
    pub fn parse(value: &str) -> CoreResult<Self> {
        Ok(Self(parse_decimal(
            value,
            1,
            MAX_AUTHENTICATION_TIMEOUT_SECONDS,
            "PostgreSQL authentication timeout",
        )? as u32))
    }

    pub const fn lovelyres_suggestion() -> Self {
        Self(60)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PostgreSqlIdleInTransactionTimeoutSeconds(u32);

impl PostgreSqlIdleInTransactionTimeoutSeconds {
    pub fn parse(value: &str) -> CoreResult<Self> {
        Ok(Self(parse_decimal(
            value,
            1,
            MAX_IDLE_IN_TRANSACTION_TIMEOUT_SECONDS,
            "PostgreSQL idle-in-transaction timeout",
        )? as u32))
    }

    pub const fn lovelyres_suggestion() -> Self {
        Self(300)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PostgreSqlIdleSessionTimeoutSeconds(u32);

impl PostgreSqlIdleSessionTimeoutSeconds {
    pub fn parse(value: &str) -> CoreResult<Self> {
        Ok(Self(parse_decimal(
            value,
            1,
            MAX_IDLE_SESSION_TIMEOUT_SECONDS,
            "PostgreSQL idle-session timeout",
        )? as u32))
    }

    pub const fn lovelyres_suggestion() -> Self {
        Self(1_800)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PostgreSqlTemporaryFileLimitMebibytes(u32);

impl PostgreSqlTemporaryFileLimitMebibytes {
    pub fn parse(value: &str) -> CoreResult<Self> {
        Ok(Self(parse_decimal(
            value,
            1,
            MAX_TEMPORARY_FILE_LIMIT_MEBIBYTES,
            "PostgreSQL temporary-file limit",
        )? as u32))
    }

    pub const fn lovelyres_suggestion() -> Self {
        Self(1_024)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PostgreSqlLockWaitThresholdMilliseconds(u32);

impl PostgreSqlLockWaitThresholdMilliseconds {
    pub fn parse(value: &str) -> CoreResult<Self> {
        Ok(Self(parse_decimal(
            value,
            1,
            MAX_DEADLOCK_TIMEOUT_MILLISECONDS,
            "PostgreSQL lock-wait logging threshold",
        )? as u32))
    }

    pub const fn lovelyres_suggestion() -> Self {
        Self(1_000)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PostgreSqlAutovacuumLogThresholdMilliseconds(u32);

impl PostgreSqlAutovacuumLogThresholdMilliseconds {
    pub fn parse(value: &str) -> CoreResult<Self> {
        Ok(Self(parse_decimal(
            value,
            0,
            MAX_AUTOVACUUM_LOG_THRESHOLD_MILLISECONDS,
            "PostgreSQL autovacuum log threshold",
        )? as u32))
    }

    pub const fn lovelyres_suggestion() -> Self {
        Self(1_000)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PostgreSqlTemporaryFileLogThresholdKilobytes(u32);

impl PostgreSqlTemporaryFileLogThresholdKilobytes {
    pub fn parse(value: &str) -> CoreResult<Self> {
        Ok(Self(parse_decimal(
            value,
            0,
            MAX_TEMPORARY_FILE_LOG_THRESHOLD_KILOBYTES,
            "PostgreSQL temporary-file log threshold",
        )? as u32))
    }

    pub const fn lovelyres_suggestion() -> Self {
        Self(10_240)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostgreSqlWalCompression {
    Pglz,
}

impl PostgreSqlWalCompression {
    pub const ALL: [Self; 1] = [Self::Pglz];

    pub fn parse(value: &str) -> CoreResult<Self> {
        match value {
            "pglz" => Ok(Self::Pglz),
            _ => Err(CoreError::validation(
                "PostgreSQL WAL compression",
                "must be pglz; lz4 and zstd require target build-capability inventory",
            )),
        }
    }

    pub const fn lovelyres_suggestion() -> Self {
        Self::Pglz
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Pglz => "pglz",
        }
    }

    pub const fn config_value(self, version: PostgreSqlVersion) -> &'static str {
        match (self, version) {
            (Self::Pglz, PostgreSqlVersion::V14) => "on",
            (
                Self::Pglz,
                PostgreSqlVersion::V15
                | PostgreSqlVersion::V16
                | PostgreSqlVersion::V17
                | PostgreSqlVersion::V18,
            ) => "pglz",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostgreSqlConfig {
    version: PostgreSqlVersion,
    port: PostgreSqlPort,
    features: BTreeSet<PostgreSqlConfigFeature>,
    connection_capacity: PostgreSqlConnectionCapacity,
    authentication_timeout: PostgreSqlAuthenticationTimeoutSeconds,
    idle_in_transaction_timeout: PostgreSqlIdleInTransactionTimeoutSeconds,
    idle_session_timeout: PostgreSqlIdleSessionTimeoutSeconds,
    temporary_file_limit: PostgreSqlTemporaryFileLimitMebibytes,
    lock_wait_threshold: PostgreSqlLockWaitThresholdMilliseconds,
    autovacuum_log_threshold: PostgreSqlAutovacuumLogThresholdMilliseconds,
    temporary_file_log_threshold: PostgreSqlTemporaryFileLogThresholdKilobytes,
    wal_compression: PostgreSqlWalCompression,
}

impl PostgreSqlConfig {
    pub fn baseline(version: PostgreSqlVersion) -> Self {
        Self {
            version,
            port: PostgreSqlPort(5_432),
            features: BTreeSet::new(),
            connection_capacity: PostgreSqlConnectionCapacity::lovelyres_suggestion(),
            authentication_timeout: PostgreSqlAuthenticationTimeoutSeconds::lovelyres_suggestion(),
            idle_in_transaction_timeout:
                PostgreSqlIdleInTransactionTimeoutSeconds::lovelyres_suggestion(),
            idle_session_timeout: PostgreSqlIdleSessionTimeoutSeconds::lovelyres_suggestion(),
            temporary_file_limit: PostgreSqlTemporaryFileLimitMebibytes::lovelyres_suggestion(),
            lock_wait_threshold: PostgreSqlLockWaitThresholdMilliseconds::lovelyres_suggestion(),
            autovacuum_log_threshold:
                PostgreSqlAutovacuumLogThresholdMilliseconds::lovelyres_suggestion(),
            temporary_file_log_threshold:
                PostgreSqlTemporaryFileLogThresholdKilobytes::lovelyres_suggestion(),
            wal_compression: PostgreSqlWalCompression::lovelyres_suggestion(),
        }
    }

    pub const fn version(&self) -> PostgreSqlVersion {
        self.version
    }

    pub const fn port(&self) -> PostgreSqlPort {
        self.port
    }

    pub fn features(&self) -> &BTreeSet<PostgreSqlConfigFeature> {
        &self.features
    }

    pub fn feature_enabled(&self, feature: PostgreSqlConfigFeature) -> bool {
        self.features.contains(&feature)
    }

    pub const fn connection_capacity(&self) -> PostgreSqlConnectionCapacity {
        self.connection_capacity
    }

    pub const fn authentication_timeout(&self) -> PostgreSqlAuthenticationTimeoutSeconds {
        self.authentication_timeout
    }

    pub const fn idle_in_transaction_timeout(&self) -> PostgreSqlIdleInTransactionTimeoutSeconds {
        self.idle_in_transaction_timeout
    }

    pub const fn idle_session_timeout(&self) -> PostgreSqlIdleSessionTimeoutSeconds {
        self.idle_session_timeout
    }

    pub const fn temporary_file_limit(&self) -> PostgreSqlTemporaryFileLimitMebibytes {
        self.temporary_file_limit
    }

    pub const fn lock_wait_threshold(&self) -> PostgreSqlLockWaitThresholdMilliseconds {
        self.lock_wait_threshold
    }

    pub const fn autovacuum_log_threshold(&self) -> PostgreSqlAutovacuumLogThresholdMilliseconds {
        self.autovacuum_log_threshold
    }

    pub const fn temporary_file_log_threshold(
        &self,
    ) -> PostgreSqlTemporaryFileLogThresholdKilobytes {
        self.temporary_file_log_threshold
    }

    pub const fn wal_compression(&self) -> PostgreSqlWalCompression {
        self.wal_compression
    }

    pub fn with_port(mut self, port: PostgreSqlPort) -> Self {
        self.port = port;
        self
    }

    pub fn with_feature(
        mut self,
        feature: PostgreSqlConfigFeature,
        enabled: bool,
    ) -> CoreResult<Self> {
        if enabled {
            self.features.insert(feature);
        } else {
            self.features.remove(&feature);
        }
        self.validate()?;
        Ok(self)
    }

    pub fn with_connection_capacity(
        mut self,
        value: PostgreSqlConnectionCapacity,
    ) -> CoreResult<Self> {
        self.connection_capacity = value;
        self.features
            .insert(PostgreSqlConfigFeature::ConnectionCapacity);
        self.validate()?;
        Ok(self)
    }

    pub fn with_authentication_timeout(
        mut self,
        value: PostgreSqlAuthenticationTimeoutSeconds,
    ) -> CoreResult<Self> {
        self.authentication_timeout = value;
        self.features
            .insert(PostgreSqlConfigFeature::AuthenticationTimeout);
        self.validate()?;
        Ok(self)
    }

    pub fn with_idle_in_transaction_timeout(
        mut self,
        value: PostgreSqlIdleInTransactionTimeoutSeconds,
    ) -> CoreResult<Self> {
        self.idle_in_transaction_timeout = value;
        self.features
            .insert(PostgreSqlConfigFeature::IdleInTransactionGuard);
        self.validate()?;
        Ok(self)
    }

    pub fn with_idle_session_timeout(
        mut self,
        value: PostgreSqlIdleSessionTimeoutSeconds,
    ) -> CoreResult<Self> {
        self.idle_session_timeout = value;
        self.features
            .insert(PostgreSqlConfigFeature::IdleSessionGuard);
        self.validate()?;
        Ok(self)
    }

    pub fn with_temporary_file_limit(
        mut self,
        value: PostgreSqlTemporaryFileLimitMebibytes,
    ) -> CoreResult<Self> {
        self.temporary_file_limit = value;
        self.features
            .insert(PostgreSqlConfigFeature::TemporaryFileLimit);
        self.validate()?;
        Ok(self)
    }

    pub fn with_lock_wait_logging_threshold(
        mut self,
        value: PostgreSqlLockWaitThresholdMilliseconds,
    ) -> CoreResult<Self> {
        self.lock_wait_threshold = value;
        self.features
            .insert(PostgreSqlConfigFeature::LockWaitLogging);
        self.validate()?;
        Ok(self)
    }

    pub fn with_autovacuum_logging_threshold(
        mut self,
        value: PostgreSqlAutovacuumLogThresholdMilliseconds,
    ) -> CoreResult<Self> {
        self.autovacuum_log_threshold = value;
        self.features
            .insert(PostgreSqlConfigFeature::AutovacuumLogging);
        self.validate()?;
        Ok(self)
    }

    pub fn with_temporary_file_logging_threshold(
        mut self,
        value: PostgreSqlTemporaryFileLogThresholdKilobytes,
    ) -> CoreResult<Self> {
        self.temporary_file_log_threshold = value;
        self.features
            .insert(PostgreSqlConfigFeature::TemporaryFileLogging);
        self.validate()?;
        Ok(self)
    }

    pub fn with_wal_compression(mut self, value: PostgreSqlWalCompression) -> CoreResult<Self> {
        self.wal_compression = value;
        self.features
            .insert(PostgreSqlConfigFeature::WalCompression);
        self.validate()?;
        Ok(self)
    }

    pub fn reset_to_baseline(&mut self) {
        *self = Self::baseline(self.version);
    }

    pub fn generate(&self) -> CoreResult<GeneratedPostgreSqlConfig> {
        self.validate()?;

        let mut contents = String::with_capacity(2_048);
        contents.push_str("# LovelyHawk PostgreSQL ");
        contents.push_str(self.version.label());
        contents.push_str(" new empty-cluster include fragment\n");
        contents.push_str(
            "# NEW EMPTY CLUSTER ONLY — DO NOT APPLY TO AN EXISTING OR DATA-BEARING CLUSTER.\n",
        );
        contents.push_str("# INCOMPLETE FRAGMENT ONLY — LovelyHawk does not include, install, deploy, overwrite, reload, or restart PostgreSQL.\n");
        contents.push_str("# Validate with the exact same-major target PostgreSQL before manually including or activating this file.\n");
        contents.push_str("# Later include files, postgresql.auto.conf, command-line -c, database, role, and session settings can override this preview.\n");
        contents.push_str("# DEFERRED: pg_hba.conf, pg_ident.conf, postgresql.auto.conf, TLS/private keys, passwords/secrets/roles, archive and restore commands, shared_preload_libraries, target-sized resource tuning, global statement/lock timeout, SQL/query-text logging, existing-cluster migration, and non-loopback listening.\n");
        contents.push_str("# Loopback listening is not authentication: local processes and Unix-domain socket clients still require separately reviewed access controls.\n");
        contents.push_str("# initdb authentication, locale, encoding, checksums, and WAL-segment choices are outside this fragment.\n");
        contents.push_str("# password_encryption affects passwords created or changed afterwards; it does not rewrite existing verifiers or HBA rules.\n");
        contents.push_str("# Optional numeric values below are LovelyHawk suggestions, not detected target values or universal PostgreSQL defaults.\n\n");

        contents.push_str("listen_addresses = 'localhost'\nport = ");
        contents.push_str(&self.port.get().to_string());
        contents.push_str("\npassword_encryption = 'scram-sha-256'\nfsync = on\nfull_page_writes = on\nsynchronous_commit = on\ntrack_counts = on\nautovacuum = on\n");

        if self.feature_enabled(PostgreSqlConfigFeature::ConnectionCapacity) {
            contents.push_str("\n# LovelyHawk suggestion: size connection limits against target memory, kernel limits, pooling, and standby topology.\nmax_connections = ");
            contents.push_str(&self.connection_capacity.max_connections().to_string());
            contents.push('\n');
            if self.version.supports_reserved_connections() {
                contents.push_str("reserved_connections = ");
                contents.push_str(&self.connection_capacity.reserved_connections().to_string());
                contents.push('\n');
            }
            contents.push_str("superuser_reserved_connections = ");
            contents.push_str(
                &self
                    .connection_capacity
                    .superuser_reserved_connections()
                    .to_string(),
            );
            contents.push('\n');
        }

        if self.feature_enabled(PostgreSqlConfigFeature::AuthenticationTimeout) {
            contents.push_str("\nauthentication_timeout = ");
            contents.push_str(&self.authentication_timeout.get().to_string());
            contents.push_str("s\n");
        }
        if self.feature_enabled(PostgreSqlConfigFeature::IdleInTransactionGuard) {
            contents.push_str("\nidle_in_transaction_session_timeout = ");
            contents.push_str(&self.idle_in_transaction_timeout.get().to_string());
            contents.push_str("s\n");
        }
        if self.feature_enabled(PostgreSqlConfigFeature::IdleSessionGuard) {
            contents.push_str("\n# Connection pools and middleware must be verified against unexpected server-side idle disconnects.\nidle_session_timeout = ");
            contents.push_str(&self.idle_session_timeout.get().to_string());
            contents.push_str("s\n");
        }
        if self.feature_enabled(PostgreSqlConfigFeature::TemporaryFileLimit) {
            contents.push_str("\n# Per PostgreSQL process; explicit temporary tables are outside temp_file_limit accounting.\ntemp_file_limit = ");
            contents.push_str(&self.temporary_file_limit.get().to_string());
            contents.push_str("MB\n");
        }
        if self.feature_enabled(PostgreSqlConfigFeature::ConnectionLifecycleLogging) {
            contents.push_str("\nlog_connections = ");
            contents.push_str(self.version.connection_logging_value());
            contents.push_str("\nlog_disconnections = on\n");
        }
        if self.feature_enabled(PostgreSqlConfigFeature::LockWaitLogging) {
            contents.push_str("\n# deadlock_timeout controls both lock-wait logging and the cost/frequency of deadlock checks.\ndeadlock_timeout = ");
            contents.push_str(&self.lock_wait_threshold.get().to_string());
            contents.push_str("ms\nlog_lock_waits = on\n");
        }
        if self.feature_enabled(PostgreSqlConfigFeature::CheckpointLogging) {
            contents.push_str("\nlog_checkpoints = on\n");
        }
        if self.feature_enabled(PostgreSqlConfigFeature::AutovacuumLogging) {
            contents.push_str("\nlog_autovacuum_min_duration = ");
            contents.push_str(&self.autovacuum_log_threshold.get().to_string());
            contents.push_str("ms\n");
        }
        if self.feature_enabled(PostgreSqlConfigFeature::TemporaryFileLogging) {
            contents.push_str("\n# Logs each qualifying temporary file when PostgreSQL deletes it.\nlog_temp_files = ");
            contents.push_str(&self.temporary_file_log_threshold.get().to_string());
            contents.push_str("kB\n");
        }
        if self.feature_enabled(PostgreSqlConfigFeature::IoTiming) {
            contents.push_str("\n# Verify operating-system clock-read overhead with pg_test_timing on the exact target.\ntrack_io_timing = on\ntrack_wal_io_timing = on\n");
        }
        if self.feature_enabled(PostgreSqlConfigFeature::WalCompression) {
            contents.push_str("\n# Closed to built-in pglz; optional lz4/zstd require target build-capability inventory.\nwal_compression = ");
            contents.push_str(self.wal_compression.config_value(self.version));
            contents.push('\n');
        }
        if self.feature_enabled(PostgreSqlConfigFeature::QueryIdentifier) {
            contents.push_str("\n# Ensure no external module also computes query identifiers.\ncompute_query_id = on\n");
        }

        validate_generated_document(&contents, self.version)?;
        Ok(GeneratedPostgreSqlConfig {
            version: self.version,
            contents,
        })
    }

    fn validate(&self) -> CoreResult<()> {
        for feature in &self.features {
            if !feature.supports_version(self.version) {
                return Err(CoreError::validation(
                    "PostgreSQL configuration feature",
                    format!(
                        "{} is not supported by PostgreSQL {}",
                        feature.title(),
                        self.version.label()
                    ),
                ));
            }
        }
        if self.feature_enabled(PostgreSqlConfigFeature::ConnectionCapacity) {
            self.connection_capacity
                .validate_for_version(self.version)?;
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GeneratedPostgreSqlConfig {
    version: PostgreSqlVersion,
    contents: String,
}

impl fmt::Debug for GeneratedPostgreSqlConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GeneratedPostgreSqlConfig")
            .field("version", &self.version)
            .field("bytes", &self.contents.len())
            .finish()
    }
}

impl GeneratedPostgreSqlConfig {
    pub fn contents(&self) -> &str {
        &self.contents
    }

    pub const fn version(&self) -> PostgreSqlVersion {
        self.version
    }

    pub fn suggested_file_name(&self) -> String {
        format!(
            "lovelyhawk-postgresql-{}-new-empty-cluster.conf",
            self.version.label()
        )
    }

    /// Writes a new local fragment and never replaces an existing path.
    ///
    /// A failure after `create_new` triggers a best-effort removal. If that
    /// cleanup also fails, one composite error exposes the exact path that may
    /// still contain a partial fragment.
    pub fn write_new(&self, destination: &Path) -> CoreResult<PathBuf> {
        validate_export_destination(destination)?;
        validate_generated_document(&self.contents, self.version)?;

        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(destination)
            .map_err(|source| {
                CoreError::io(
                    "create generated PostgreSQL configuration fragment",
                    destination,
                    source,
                )
            })?;
        let write_result = (|| {
            file.write_all(self.contents.as_bytes()).map_err(|source| {
                CoreError::io(
                    "write generated PostgreSQL configuration fragment",
                    destination,
                    source,
                )
            })?;
            file.flush().map_err(|source| {
                CoreError::io(
                    "flush generated PostgreSQL configuration fragment",
                    destination,
                    source,
                )
            })?;
            file.sync_all().map_err(|source| {
                CoreError::io(
                    "sync generated PostgreSQL configuration fragment",
                    destination,
                    source,
                )
            })
        })();
        drop(file);

        if let Err(write_error) = write_result {
            return Err(combine_write_and_cleanup_result(
                destination,
                write_error,
                fs::remove_file(destination),
            ));
        }
        Ok(destination.to_path_buf())
    }
}

fn combine_write_and_cleanup_result(
    destination: &Path,
    write_error: CoreError,
    cleanup_result: std::io::Result<()>,
) -> CoreError {
    match cleanup_result {
        Ok(()) => write_error,
        Err(cleanup_error) => CoreError::PartialCleanup {
            operation: "write generated PostgreSQL configuration fragment",
            path: destination.to_path_buf(),
            primary: Box::new(write_error),
            cleanup_failures: format!(
                "removing the possible partial file failed: {cleanup_error}; inspect and remove this exact path manually"
            ),
        },
    }
}

fn parse_decimal(
    value: &str,
    minimum: u64,
    maximum: u64,
    subject: &'static str,
) -> CoreResult<u64> {
    if value.is_empty()
        || value != value.trim()
        || value.len() > 20
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(CoreError::validation(
            subject,
            format!("must contain only decimal digits in {minimum}..={maximum}"),
        ));
    }
    let parsed = value
        .parse::<u64>()
        .map_err(|_| CoreError::validation(subject, format!("must be in {minimum}..={maximum}")))?;
    if !(minimum..=maximum).contains(&parsed) {
        return Err(CoreError::validation(
            subject,
            format!("must be in {minimum}..={maximum}"),
        ));
    }
    Ok(parsed)
}

fn validate_generated_document(contents: &str, version: PostgreSqlVersion) -> CoreResult<()> {
    if contents.is_empty()
        || contents.len() > MAX_GENERATED_POSTGRESQL_CONFIG_BYTES
        || contents.contains('\0')
        || contents.contains('\r')
        || !contents.ends_with('\n')
    {
        return Err(CoreError::validation(
            "generated PostgreSQL configuration fragment",
            format!(
                "must be non-empty LF-only UTF-8 with a terminal newline and at most {MAX_GENERATED_POSTGRESQL_CONFIG_BYTES} bytes"
            ),
        ));
    }

    let required_header = format!(
        "# LovelyHawk PostgreSQL {} new empty-cluster include fragment\n# NEW EMPTY CLUSTER ONLY — DO NOT APPLY TO AN EXISTING OR DATA-BEARING CLUSTER.\n",
        version.label()
    );
    if !contents.starts_with(&required_header) {
        return Err(CoreError::validation(
            "generated PostgreSQL configuration fragment",
            "must retain the matching major version and prominent new-empty-cluster-only warning",
        ));
    }

    let document = LineConfigVisualDocument::parse(LineConfigDialect::PostgresConf, contents)
        .map_err(|error| {
            CoreError::validation(
                "generated PostgreSQL configuration fragment",
                error.to_string(),
            )
        })?;
    if !document.is_structured()
        || document.raw_bytes() != contents.as_bytes()
        || document.output().bytes() != contents.as_bytes()
    {
        return Err(CoreError::validation(
            "generated PostgreSQL configuration fragment",
            "closed template must parse structurally and round-trip byte-exactly through PostgresConf",
        ));
    }

    let rows = document.rows();
    if rows.iter().any(|row| {
        !matches!(
            row.kind(),
            LineConfigNodeKind::Comment | LineConfigNodeKind::Entry
        )
    }) {
        return Err(CoreError::validation(
            "generated PostgreSQL configuration fragment",
            "closed template must contain only comments and assignments; includes and opaque nodes are forbidden",
        ));
    }

    const ALLOWED_DIRECTIVES: &[&str] = &[
        "listen_addresses",
        "port",
        "password_encryption",
        "fsync",
        "full_page_writes",
        "synchronous_commit",
        "track_counts",
        "autovacuum",
        "max_connections",
        "reserved_connections",
        "superuser_reserved_connections",
        "authentication_timeout",
        "idle_in_transaction_session_timeout",
        "idle_session_timeout",
        "temp_file_limit",
        "log_connections",
        "log_disconnections",
        "deadlock_timeout",
        "log_lock_waits",
        "log_checkpoints",
        "log_autovacuum_min_duration",
        "log_temp_files",
        "track_io_timing",
        "track_wal_io_timing",
        "wal_compression",
        "compute_query_id",
    ];

    let mut directives = BTreeMap::<String, String>::new();
    for line in contents.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line != line.trim() {
            return Err(CoreError::validation(
                "generated PostgreSQL configuration fragment",
                "assignment lines must not contain leading or trailing whitespace",
            ));
        }
        let (name, value) = line.split_once('=').ok_or_else(|| {
            CoreError::validation(
                "generated PostgreSQL configuration fragment",
                "assignment is missing one equals separator",
            )
        })?;
        if value.contains('=') {
            return Err(CoreError::validation(
                "generated PostgreSQL configuration fragment",
                "assignment contains more than one equals separator",
            ));
        }
        let name = name.trim();
        let value = value.trim();
        if !ALLOWED_DIRECTIVES.contains(&name) {
            return Err(CoreError::validation(
                "generated PostgreSQL configuration fragment",
                format!("directive {name} is outside the closed generator allowlist"),
            ));
        }
        if value.is_empty() {
            return Err(CoreError::validation(
                "generated PostgreSQL configuration fragment",
                format!("directive {name} is missing its typed value"),
            ));
        }
        if directives
            .insert(name.to_owned(), value.to_owned())
            .is_some()
        {
            return Err(CoreError::validation(
                "generated PostgreSQL configuration fragment",
                format!("directive {name} must occur exactly once"),
            ));
        }
    }

    let parsed_entry_names = rows
        .iter()
        .filter(|row| row.kind() == LineConfigNodeKind::Entry)
        .map(|row| row.name())
        .collect::<Vec<_>>();
    if parsed_entry_names.len() != directives.len()
        || parsed_entry_names
            .iter()
            .any(|name| name.is_none_or(|name| !directives.contains_key(name)))
    {
        return Err(CoreError::validation(
            "generated PostgreSQL configuration fragment",
            "manual closed-value validation disagrees with the lossless PostgresConf parse",
        ));
    }

    let one = |name: &str| -> CoreResult<&str> {
        directives.get(name).map(String::as_str).ok_or_else(|| {
            CoreError::validation(
                "generated PostgreSQL configuration fragment",
                format!("required baseline directive {name} is missing"),
            )
        })
    };

    for (name, expected) in [
        ("listen_addresses", "'localhost'"),
        ("password_encryption", "'scram-sha-256'"),
        ("fsync", "on"),
        ("full_page_writes", "on"),
        ("synchronous_commit", "on"),
        ("track_counts", "on"),
        ("autovacuum", "on"),
    ] {
        if one(name)? != expected {
            return Err(CoreError::validation(
                "generated PostgreSQL configuration fragment",
                format!("baseline directive {name} must remain {expected}"),
            ));
        }
    }
    PostgreSqlPort::parse(one("port")?)?;

    match (
        directives.get("max_connections"),
        directives.get("superuser_reserved_connections"),
        directives.get("reserved_connections"),
    ) {
        (None, None, None) => {}
        (Some(maximum), Some(superuser), reserved) => {
            let reserved = if version.supports_reserved_connections() {
                reserved.ok_or_else(|| {
                    CoreError::validation(
                        "generated PostgreSQL configuration fragment",
                        "PostgreSQL 16+ connection capacity must include reserved_connections",
                    )
                })?
            } else {
                if reserved.is_some() {
                    return Err(CoreError::validation(
                        "generated PostgreSQL configuration fragment",
                        format!(
                            "PostgreSQL {} must not emit reserved_connections",
                            version.label()
                        ),
                    ));
                }
                "0"
            };
            PostgreSqlConnectionCapacity::parse(maximum, superuser, reserved)?
                .validate_for_version(version)?;
        }
        _ => {
            return Err(CoreError::validation(
                "generated PostgreSQL configuration fragment",
                "connection-capacity directives must be emitted as one version-correct group",
            ));
        }
    }

    if let Some(value) = directives.get("authentication_timeout") {
        PostgreSqlAuthenticationTimeoutSeconds::parse(strip_unit(value, "s")?)?;
    }
    if let Some(value) = directives.get("idle_in_transaction_session_timeout") {
        PostgreSqlIdleInTransactionTimeoutSeconds::parse(strip_unit(value, "s")?)?;
    }
    if let Some(value) = directives.get("idle_session_timeout") {
        PostgreSqlIdleSessionTimeoutSeconds::parse(strip_unit(value, "s")?)?;
    }
    if let Some(value) = directives.get("temp_file_limit") {
        PostgreSqlTemporaryFileLimitMebibytes::parse(strip_unit(value, "MB")?)?;
    }
    if let Some(value) = directives.get("log_autovacuum_min_duration") {
        PostgreSqlAutovacuumLogThresholdMilliseconds::parse(strip_unit(value, "ms")?)?;
    }
    if let Some(value) = directives.get("log_temp_files") {
        PostgreSqlTemporaryFileLogThresholdKilobytes::parse(strip_unit(value, "kB")?)?;
    }

    match (
        directives.get("log_connections"),
        directives.get("log_disconnections"),
    ) {
        (None, None) => {}
        (Some(connections), Some(disconnections))
            if connections == version.connection_logging_value() && disconnections == "on" => {}
        (Some(_), Some(_)) => {
            return Err(CoreError::validation(
                "generated PostgreSQL configuration fragment",
                format!(
                    "PostgreSQL {} connection lifecycle logging must use the reviewed version-specific values",
                    version.label()
                ),
            ));
        }
        _ => {
            return Err(CoreError::validation(
                "generated PostgreSQL configuration fragment",
                "log_connections and log_disconnections must be enabled as one feature",
            ));
        }
    }
    match (
        directives.get("deadlock_timeout"),
        directives.get("log_lock_waits"),
    ) {
        (None, None) => {}
        (Some(threshold), Some(enabled)) if enabled == "on" => {
            PostgreSqlLockWaitThresholdMilliseconds::parse(strip_unit(threshold, "ms")?)?;
        }
        (Some(_), Some(_)) => {
            return Err(CoreError::validation(
                "generated PostgreSQL configuration fragment",
                "log_lock_waits must be the closed value on",
            ));
        }
        _ => {
            return Err(CoreError::validation(
                "generated PostgreSQL configuration fragment",
                "deadlock_timeout and log_lock_waits must be emitted as one typed feature group",
            ));
        }
    }

    for directive in ["log_checkpoints", "compute_query_id"] {
        if directives.get(directive).is_some_and(|value| value != "on") {
            return Err(CoreError::validation(
                "generated PostgreSQL configuration fragment",
                format!("{directive} must be the closed value on"),
            ));
        }
    }

    match (
        directives.get("track_io_timing"),
        directives.get("track_wal_io_timing"),
    ) {
        (None, None) => {}
        (Some(io), Some(wal)) if io == "on" && wal == "on" => {}
        (Some(_), Some(_)) => {
            return Err(CoreError::validation(
                "generated PostgreSQL configuration fragment",
                "track_io_timing and track_wal_io_timing must both use the closed value on",
            ));
        }
        _ => {
            return Err(CoreError::validation(
                "generated PostgreSQL configuration fragment",
                "track_io_timing and track_wal_io_timing must be emitted as one feature group",
            ));
        }
    }

    if let Some(value) = directives.get("wal_compression") {
        let expected = PostgreSqlWalCompression::Pglz.config_value(version);
        if value != expected {
            return Err(CoreError::validation(
                "generated PostgreSQL configuration fragment",
                format!(
                    "PostgreSQL {} wal_compression must use the reviewed built-in pglz spelling {expected}",
                    version.label()
                ),
            ));
        }
    }
    Ok(())
}

fn strip_unit<'a>(value: &'a str, unit: &str) -> CoreResult<&'a str> {
    value.strip_suffix(unit).ok_or_else(|| {
        CoreError::validation(
            "generated PostgreSQL configuration fragment",
            format!("typed numeric value must include the explicit {unit} unit"),
        )
    })
}

fn validate_export_destination(destination: &Path) -> CoreResult<()> {
    if !destination.is_absolute() {
        return Err(CoreError::validation(
            "generated PostgreSQL configuration destination",
            "must be an absolute path selected by the native save dialog",
        ));
    }
    if destination
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(CoreError::validation(
            "generated PostgreSQL configuration destination",
            "must not contain current-directory or parent-directory components",
        ));
    }
    if !destination
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("conf"))
    {
        return Err(CoreError::validation(
            "generated PostgreSQL configuration destination",
            "must use the .conf extension",
        ));
    }
    let parent = destination.parent().ok_or_else(|| {
        CoreError::validation(
            "generated PostgreSQL configuration destination",
            "path has no parent directory",
        )
    })?;
    if !parent.is_dir() {
        return Err(CoreError::validation(
            "generated PostgreSQL configuration destination",
            "parent directory does not exist",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, fs};

    use uuid::Uuid;

    use crate::mariadb_config::{
        MariaDbBinaryLogRetentionSeconds, MariaDbConfig, MariaDbConfigFeature, MariaDbServerId,
        MariaDbVersion,
    };

    use super::*;

    #[derive(Debug)]
    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir()
                .join(format!("lovelyres-postgresql-config-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn entry_names(contents: &str) -> BTreeSet<String> {
        LineConfigVisualDocument::parse(LineConfigDialect::PostgresConf, contents)
            .unwrap()
            .rows()
            .into_iter()
            .filter(|row| row.kind() == LineConfigNodeKind::Entry)
            .map(|row| row.name().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn supported_versions_and_feature_metadata_are_closed_and_explained() {
        assert_eq!(
            PostgreSqlVersion::ALL
                .into_iter()
                .map(PostgreSqlVersion::label)
                .collect::<Vec<_>>(),
            ["14", "15", "16", "17", "18"]
        );
        for version in PostgreSqlVersion::ALL {
            assert_eq!(PostgreSqlVersion::parse(version.label()).unwrap(), version);
            assert_eq!(
                PostgreSqlVersion::try_from(version.major()).unwrap(),
                version
            );
            assert!(
                version
                    .official_documentation()
                    .starts_with("https://www.postgresql.org/docs/")
            );
            assert!(!version.support_notice().is_empty());
            assert!(!version.risk().is_empty());
        }
        assert!(
            PostgreSqlVersion::V14
                .support_notice()
                .contains("2026-11-12")
        );
        assert!(PostgreSqlVersion::V14.risk().contains("EOL"));
        for unsupported in [0_u16, 13, 19, u16::MAX] {
            assert!(PostgreSqlVersion::try_from(unsupported).is_err());
        }
        for unsupported in ["", "13", "19", "18.1", " 18", "+18"] {
            assert!(
                PostgreSqlVersion::parse(unsupported).is_err(),
                "{unsupported:?}"
            );
        }

        let keys = PostgreSqlConfigFeature::ALL
            .into_iter()
            .map(PostgreSqlConfigFeature::key)
            .collect::<HashSet<_>>();
        assert_eq!(PostgreSqlConfigFeature::ALL.len(), 13);
        assert_eq!(
            PostgreSqlConfigFeature::ALL,
            [
                PostgreSqlConfigFeature::ConnectionCapacity,
                PostgreSqlConfigFeature::AuthenticationTimeout,
                PostgreSqlConfigFeature::IdleInTransactionGuard,
                PostgreSqlConfigFeature::IdleSessionGuard,
                PostgreSqlConfigFeature::TemporaryFileLimit,
                PostgreSqlConfigFeature::ConnectionLifecycleLogging,
                PostgreSqlConfigFeature::LockWaitLogging,
                PostgreSqlConfigFeature::CheckpointLogging,
                PostgreSqlConfigFeature::AutovacuumLogging,
                PostgreSqlConfigFeature::TemporaryFileLogging,
                PostgreSqlConfigFeature::IoTiming,
                PostgreSqlConfigFeature::WalCompression,
                PostgreSqlConfigFeature::QueryIdentifier,
            ]
        );
        assert_eq!(keys.len(), PostgreSqlConfigFeature::ALL.len());
        assert!(PostgreSqlConfigFeature::ALL.into_iter().all(|feature| {
            !feature.key().is_empty()
                && !feature.title().is_empty()
                && !feature.summary().is_empty()
                && !feature.aliases().is_empty()
                && !feature.scope().is_empty()
                && !feature.risk().is_empty()
                && !feature.activation().is_empty()
                && !feature.default_enabled()
                && feature
                    .official_reference()
                    .starts_with("https://www.postgresql.org/")
                && PostgreSqlVersion::ALL
                    .into_iter()
                    .all(|version| feature.supports_version(version))
        }));
        assert!(
            POSTGRESQL_OFFICIAL_REFERENCES
                .iter()
                .all(|reference| { reference.starts_with("https://www.postgresql.org/") })
        );
    }

    #[test]
    fn postgresql_and_mariadb_catalog_versions_search_and_inline_editor_prerequisites_are_typed() {
        assert_eq!(
            PostgreSqlVersion::ALL
                .into_iter()
                .map(PostgreSqlVersion::label)
                .collect::<Vec<_>>(),
            ["14", "15", "16", "17", "18"]
        );
        assert_eq!(
            MariaDbVersion::ALL
                .into_iter()
                .map(MariaDbVersion::label)
                .collect::<Vec<_>>(),
            ["10.11", "11.4", "11.8", "12.3"]
        );

        let lock_wait = PostgreSqlConfigFeature::LockWaitLogging;
        assert_eq!(lock_wait.key(), "lock-wait-logging");
        assert_eq!(lock_wait.title(), "按明确阈值记录锁等待");
        assert_eq!(
            lock_wait.aliases(),
            &["log_lock_waits", "锁等待", "deadlock_timeout"]
        );
        let postgresql_baseline = PostgreSqlConfig::baseline(PostgreSqlVersion::V18)
            .generate()
            .unwrap();
        let postgresql_selected = PostgreSqlConfig::baseline(PostgreSqlVersion::V18)
            .with_lock_wait_logging_threshold(
                PostgreSqlLockWaitThresholdMilliseconds::parse("1500").unwrap(),
            )
            .unwrap();
        let postgresql_output = postgresql_selected.generate().unwrap();
        assert!(
            postgresql_output
                .contents()
                .contains("deadlock_timeout = 1500ms\n")
        );
        assert!(
            postgresql_output
                .contents()
                .contains("log_lock_waits = on\n")
        );
        assert_eq!(
            postgresql_selected
                .with_feature(lock_wait, false)
                .unwrap()
                .generate()
                .unwrap(),
            postgresql_baseline
        );

        let retention = MariaDbConfigFeature::BinaryLogRetention;
        assert_eq!(retention.key(), "binary-log-retention");
        assert_eq!(retention.title(), "设置二进制日志保留时间");
        assert_eq!(
            retention.aliases(),
            &["binlog_expire_logs_seconds", "日志保留", "自动清理"]
        );
        assert_eq!(
            retention.required_feature(),
            Some(MariaDbConfigFeature::BinaryLogging)
        );
        let mariadb_selected = MariaDbConfig::baseline(MariaDbVersion::V12_3)
            .with_server_id(MariaDbServerId::parse("42").unwrap())
            .unwrap()
            .with_binary_log_retention(MariaDbBinaryLogRetentionSeconds::parse("86400").unwrap())
            .unwrap()
            .generate()
            .unwrap();
        for directive in [
            "log_bin = mariadb-bin\n",
            "server_id = 42\n",
            "binlog_expire_logs_seconds = 86400\n",
        ] {
            assert!(
                mariadb_selected.contents().contains(directive),
                "{directive}"
            );
        }

        assert!(PostgreSqlLockWaitThresholdMilliseconds::parse("0").is_err());
        assert!(PostgreSqlLockWaitThresholdMilliseconds::parse("3600001").is_err());
        assert!(MariaDbBinaryLogRetentionSeconds::parse("0").is_err());
        assert!(MariaDbBinaryLogRetentionSeconds::parse("8553601").is_err());
    }

    #[test]
    fn baseline_contains_only_the_eight_reviewed_directives() {
        let expected = BTreeSet::from([
            "listen_addresses".to_owned(),
            "port".to_owned(),
            "password_encryption".to_owned(),
            "fsync".to_owned(),
            "full_page_writes".to_owned(),
            "synchronous_commit".to_owned(),
            "track_counts".to_owned(),
            "autovacuum".to_owned(),
        ]);

        for version in PostgreSqlVersion::ALL {
            let config = PostgreSqlConfig::baseline(version);
            assert!(config.features().is_empty());
            let generated = config.generate().unwrap();
            assert_eq!(generated.version(), version);
            assert_eq!(
                generated.suggested_file_name(),
                format!(
                    "lovelyhawk-postgresql-{}-new-empty-cluster.conf",
                    version.label()
                )
            );
            assert_eq!(entry_names(generated.contents()), expected);
            assert!(
                generated
                    .contents()
                    .contains("listen_addresses = 'localhost'\n")
            );
            assert!(generated.contents().contains("port = 5432\n"));
            assert!(
                generated
                    .contents()
                    .contains("password_encryption = 'scram-sha-256'\n")
            );
            for durable in [
                "fsync = on\n",
                "full_page_writes = on\n",
                "synchronous_commit = on\n",
                "track_counts = on\n",
                "autovacuum = on\n",
            ] {
                assert!(generated.contents().contains(durable), "{durable}");
            }
            assert!(generated.contents().contains("NEW EMPTY CLUSTER ONLY"));
            assert!(generated.contents().contains("INCOMPLETE FRAGMENT ONLY"));
            assert!(
                generated
                    .contents()
                    .contains("does not include, install, deploy, overwrite, reload, or restart")
            );
            assert!(
                generated
                    .contents()
                    .contains("Loopback listening is not authentication")
            );
            assert!(generated.contents().contains("postgresql.auto.conf"));
            assert!(generated.contents().contains("DEFERRED:"));
            assert!(generated.contents().len() <= MAX_GENERATED_POSTGRESQL_CONFIG_BYTES);
            validate_generated_document(generated.contents(), version).unwrap();
        }
    }

    #[test]
    fn typed_values_reject_out_of_bounds_whitespace_and_injection() {
        assert_eq!(PostgreSqlPort::parse("1").unwrap().get(), 1);
        assert_eq!(PostgreSqlPort::parse("65535").unwrap().get(), 65_535);
        for invalid in ["", "0", "65536", " 5432", "+5432", "5432\nfsync=off"] {
            assert!(PostgreSqlPort::parse(invalid).is_err(), "{invalid:?}");
        }

        let capacity = PostgreSqlConnectionCapacity::parse("100", "3", "2").unwrap();
        assert_eq!(capacity.max_connections(), 100);
        assert_eq!(capacity.superuser_reserved_connections(), 3);
        assert_eq!(capacity.reserved_connections(), 2);
        for invalid in [
            ("0", "0", "0"),
            ("10001", "0", "0"),
            ("10", "5", "5"),
            ("100", " 3", "0"),
            ("100", "3", "0 # injected"),
        ] {
            assert!(
                PostgreSqlConnectionCapacity::parse(invalid.0, invalid.1, invalid.2).is_err(),
                "{invalid:?}"
            );
        }

        assert_eq!(
            PostgreSqlAuthenticationTimeoutSeconds::parse("1")
                .unwrap()
                .get(),
            1
        );
        assert_eq!(
            PostgreSqlAuthenticationTimeoutSeconds::parse("3600")
                .unwrap()
                .get(),
            3_600
        );
        assert!(PostgreSqlAuthenticationTimeoutSeconds::parse("0").is_err());
        assert!(PostgreSqlAuthenticationTimeoutSeconds::parse("3601").is_err());
        assert!(PostgreSqlIdleInTransactionTimeoutSeconds::parse("604801").is_err());
        assert!(PostgreSqlTemporaryFileLimitMebibytes::parse("1048577").is_err());
        assert!(PostgreSqlTemporaryFileLimitMebibytes::parse("1024MB").is_err());

        assert_eq!(
            PostgreSqlIdleSessionTimeoutSeconds::parse("1800")
                .unwrap()
                .get(),
            1_800
        );
        assert!(PostgreSqlIdleSessionTimeoutSeconds::parse("0").is_err());
        assert!(PostgreSqlIdleSessionTimeoutSeconds::parse("604801").is_err());
        assert!(PostgreSqlIdleSessionTimeoutSeconds::parse("1800s").is_err());

        assert_eq!(
            PostgreSqlLockWaitThresholdMilliseconds::parse("1000")
                .unwrap()
                .get(),
            1_000
        );
        assert!(PostgreSqlLockWaitThresholdMilliseconds::parse("0").is_err());
        assert!(PostgreSqlLockWaitThresholdMilliseconds::parse("3600001").is_err());

        assert_eq!(
            PostgreSqlAutovacuumLogThresholdMilliseconds::parse("0")
                .unwrap()
                .get(),
            0
        );
        assert!(PostgreSqlAutovacuumLogThresholdMilliseconds::parse("86400001").is_err());
        assert_eq!(
            PostgreSqlTemporaryFileLogThresholdKilobytes::parse("10240")
                .unwrap()
                .get(),
            10_240
        );
        assert!(PostgreSqlTemporaryFileLogThresholdKilobytes::parse("1073741825").is_err());

        assert_eq!(
            PostgreSqlWalCompression::parse("pglz").unwrap(),
            PostgreSqlWalCompression::Pglz
        );
        for invalid in ["", "on", "off", "lz4", "zstd", "pglz # injected"] {
            assert!(
                PostgreSqlWalCompression::parse(invalid).is_err(),
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn connection_capacity_tracks_the_reserved_connections_version_boundary() {
        for version in [PostgreSqlVersion::V14, PostgreSqlVersion::V15] {
            let generated = PostgreSqlConfig::baseline(version)
                .with_feature(PostgreSqlConfigFeature::ConnectionCapacity, true)
                .unwrap()
                .generate()
                .unwrap();
            assert!(generated.contents().contains("max_connections = 100\n"));
            assert!(
                generated
                    .contents()
                    .contains("superuser_reserved_connections = 3\n")
            );
            assert!(!entry_names(generated.contents()).contains("reserved_connections"));
        }

        for version in [
            PostgreSqlVersion::V16,
            PostgreSqlVersion::V17,
            PostgreSqlVersion::V18,
        ] {
            let generated = PostgreSqlConfig::baseline(version)
                .with_connection_capacity(PostgreSqlConnectionCapacity::new(200, 4, 2).unwrap())
                .unwrap()
                .generate()
                .unwrap();
            assert!(generated.contents().contains("max_connections = 200\n"));
            assert!(generated.contents().contains("reserved_connections = 2\n"));
            assert!(
                generated
                    .contents()
                    .contains("superuser_reserved_connections = 4\n")
            );
        }

        let unavailable = PostgreSqlConfig::baseline(PostgreSqlVersion::V15)
            .with_connection_capacity(PostgreSqlConnectionCapacity::new(100, 3, 1).unwrap());
        assert!(unavailable.is_err());
        assert!(!PostgreSqlVersion::V15.supports_reserved_connections());
        assert!(PostgreSqlVersion::V16.supports_reserved_connections());
    }

    #[test]
    fn postgresql_18_uses_current_connection_logging_enum_semantics() {
        for version in [
            PostgreSqlVersion::V14,
            PostgreSqlVersion::V15,
            PostgreSqlVersion::V16,
            PostgreSqlVersion::V17,
        ] {
            let generated = PostgreSqlConfig::baseline(version)
                .with_feature(PostgreSqlConfigFeature::ConnectionLifecycleLogging, true)
                .unwrap()
                .generate()
                .unwrap();
            assert!(generated.contents().contains("log_connections = on\n"));
            assert!(generated.contents().contains("log_disconnections = on\n"));
        }

        let generated = PostgreSqlConfig::baseline(PostgreSqlVersion::V18)
            .with_feature(PostgreSqlConfigFeature::ConnectionLifecycleLogging, true)
            .unwrap()
            .generate()
            .unwrap();
        assert!(
            generated
                .contents()
                .contains("log_connections = 'receipt,authentication,authorization'\n")
        );
        assert!(!generated.contents().contains("setup_durations"));
        assert!(!generated.contents().contains("log_connections = on\n"));
    }

    #[test]
    fn features_stack_deterministically_remove_independently_and_reset() {
        let capacity = PostgreSqlConnectionCapacity::new(250, 5, 2).unwrap();
        let first = PostgreSqlConfig::baseline(PostgreSqlVersion::V18)
            .with_connection_capacity(capacity)
            .unwrap()
            .with_feature(PostgreSqlConfigFeature::LockWaitLogging, true)
            .unwrap()
            .with_authentication_timeout(
                PostgreSqlAuthenticationTimeoutSeconds::parse("45").unwrap(),
            )
            .unwrap();
        let second = PostgreSqlConfig::baseline(PostgreSqlVersion::V18)
            .with_authentication_timeout(
                PostgreSqlAuthenticationTimeoutSeconds::parse("45").unwrap(),
            )
            .unwrap()
            .with_feature(PostgreSqlConfigFeature::LockWaitLogging, true)
            .unwrap()
            .with_connection_capacity(capacity)
            .unwrap();
        assert_eq!(
            first.generate().unwrap().contents(),
            second.generate().unwrap().contents()
        );

        let removed = first
            .clone()
            .with_feature(PostgreSqlConfigFeature::AuthenticationTimeout, false)
            .unwrap()
            .generate()
            .unwrap();
        assert!(!entry_names(removed.contents()).contains("authentication_timeout"));
        assert!(entry_names(removed.contents()).contains("max_connections"));
        assert!(entry_names(removed.contents()).contains("log_lock_waits"));

        let mut reset = first;
        reset.reset_to_baseline();
        assert_eq!(reset, PostgreSqlConfig::baseline(PostgreSqlVersion::V18));
        assert_eq!(
            reset.generate().unwrap().contents(),
            PostgreSqlConfig::baseline(PostgreSqlVersion::V18)
                .generate()
                .unwrap()
                .contents()
        );
    }

    #[test]
    fn postgresql_quick_version_stack_remove_reset_and_save_prerequisite_is_byte_exact() {
        let baseline = PostgreSqlConfig::baseline(PostgreSqlVersion::V18)
            .generate()
            .unwrap();
        assert!(
            baseline
                .contents()
                .contains("PostgreSQL 18 new empty-cluster")
        );
        assert!(
            baseline
                .contents()
                .contains("listen_addresses = 'localhost'\n")
        );
        assert!(baseline.contents().contains("port = 5432\n"));

        let stacked = PostgreSqlConfig::baseline(PostgreSqlVersion::V18)
            .with_connection_capacity(PostgreSqlConnectionCapacity::new(240, 3, 2).unwrap())
            .unwrap()
            .with_feature(PostgreSqlConfigFeature::ConnectionLifecycleLogging, true)
            .unwrap();
        let stacked_document = stacked.generate().unwrap();
        for directive in [
            "max_connections = 240\n",
            "reserved_connections = 2\n",
            "log_connections = 'receipt,authentication,authorization'\n",
            "log_disconnections = on\n",
        ] {
            assert!(
                stacked_document.contents().contains(directive),
                "{directive}"
            );
        }

        let version_15 = PostgreSqlConfig::baseline(PostgreSqlVersion::V15)
            .with_connection_capacity(PostgreSqlConnectionCapacity::new(240, 3, 0).unwrap())
            .unwrap()
            .with_feature(PostgreSqlConfigFeature::ConnectionLifecycleLogging, true)
            .unwrap();
        let version_15_document = version_15.generate().unwrap();
        assert!(
            version_15_document
                .contents()
                .contains("PostgreSQL 15 new empty-cluster")
        );
        assert!(
            version_15_document
                .contents()
                .contains("max_connections = 240\n")
        );
        assert!(
            !version_15_document
                .contents()
                .contains("\nreserved_connections =")
        );
        assert!(
            version_15_document
                .contents()
                .contains("log_connections = on\n")
        );

        let remaining = version_15
            .with_feature(PostgreSqlConfigFeature::ConnectionCapacity, false)
            .unwrap()
            .generate()
            .unwrap();
        assert!(!remaining.contents().contains("max_connections = 240\n"));
        assert!(remaining.contents().contains("log_connections = on\n"));

        let mut reset = stacked;
        reset.reset_to_baseline();
        let reset_document = reset.generate().unwrap();
        assert_eq!(reset_document.contents(), baseline.contents());
        assert_eq!(
            reset_document.suggested_file_name(),
            "lovelyhawk-postgresql-18-new-empty-cluster.conf"
        );

        let root = TestRoot::new();
        let destination = root.0.join("postgresql-quick.conf");
        assert_eq!(reset_document.write_new(&destination).unwrap(), destination);
        assert_eq!(
            fs::read(&destination).unwrap(),
            baseline.contents().as_bytes()
        );
        assert!(reset_document.write_new(&destination).is_err());
        assert_eq!(
            fs::read(&destination).unwrap(),
            baseline.contents().as_bytes()
        );

        let visual = LineConfigVisualDocument::parse(
            LineConfigDialect::PostgresConf,
            reset_document.contents(),
        )
        .unwrap();
        assert!(visual.is_structured());
        assert_eq!(visual.raw_bytes(), baseline.contents().as_bytes());
        assert_eq!(visual.output().bytes(), baseline.contents().as_bytes());
    }

    #[test]
    fn every_optional_feature_emits_only_its_closed_directives() {
        let config = PostgreSqlConfig::baseline(PostgreSqlVersion::V18)
            .with_feature(PostgreSqlConfigFeature::ConnectionCapacity, true)
            .unwrap()
            .with_authentication_timeout(
                PostgreSqlAuthenticationTimeoutSeconds::parse("30").unwrap(),
            )
            .unwrap()
            .with_idle_in_transaction_timeout(
                PostgreSqlIdleInTransactionTimeoutSeconds::parse("600").unwrap(),
            )
            .unwrap()
            .with_idle_session_timeout(PostgreSqlIdleSessionTimeoutSeconds::parse("1800").unwrap())
            .unwrap()
            .with_temporary_file_limit(
                PostgreSqlTemporaryFileLimitMebibytes::parse("2048").unwrap(),
            )
            .unwrap()
            .with_feature(PostgreSqlConfigFeature::ConnectionLifecycleLogging, true)
            .unwrap()
            .with_lock_wait_logging_threshold(
                PostgreSqlLockWaitThresholdMilliseconds::parse("1500").unwrap(),
            )
            .unwrap()
            .with_feature(PostgreSqlConfigFeature::CheckpointLogging, true)
            .unwrap()
            .with_autovacuum_logging_threshold(
                PostgreSqlAutovacuumLogThresholdMilliseconds::parse("2000").unwrap(),
            )
            .unwrap()
            .with_temporary_file_logging_threshold(
                PostgreSqlTemporaryFileLogThresholdKilobytes::parse("8192").unwrap(),
            )
            .unwrap()
            .with_feature(PostgreSqlConfigFeature::IoTiming, true)
            .unwrap()
            .with_wal_compression(PostgreSqlWalCompression::Pglz)
            .unwrap()
            .with_feature(PostgreSqlConfigFeature::QueryIdentifier, true)
            .unwrap();
        let generated = config.generate().unwrap();
        assert!(
            generated
                .contents()
                .contains("authentication_timeout = 30s\n")
        );
        assert!(
            generated
                .contents()
                .contains("idle_in_transaction_session_timeout = 600s\n")
        );
        assert!(
            generated
                .contents()
                .contains("idle_session_timeout = 1800s\n")
        );
        assert!(generated.contents().contains("temp_file_limit = 2048MB\n"));
        assert!(generated.contents().contains("deadlock_timeout = 1500ms\n"));
        assert!(generated.contents().contains("log_lock_waits = on\n"));
        assert!(generated.contents().contains("log_checkpoints = on\n"));
        assert!(
            generated
                .contents()
                .contains("log_autovacuum_min_duration = 2000ms\n")
        );
        assert!(generated.contents().contains("log_temp_files = 8192kB\n"));
        assert!(generated.contents().contains("track_io_timing = on\n"));
        assert!(generated.contents().contains("track_wal_io_timing = on\n"));
        assert!(generated.contents().contains("wal_compression = pglz\n"));
        assert!(generated.contents().contains("compute_query_id = on\n"));
        validate_generated_document(generated.contents(), PostgreSqlVersion::V18).unwrap();

        let removed_io_timing = config
            .with_feature(PostgreSqlConfigFeature::IoTiming, false)
            .unwrap()
            .generate()
            .unwrap();
        assert!(!entry_names(removed_io_timing.contents()).contains("track_io_timing"));
        assert!(!entry_names(removed_io_timing.contents()).contains("track_wal_io_timing"));
        assert!(entry_names(removed_io_timing.contents()).contains("log_temp_files"));
        assert!(entry_names(removed_io_timing.contents()).contains("wal_compression"));
    }

    #[test]
    fn wal_compression_uses_the_reviewed_version_specific_pglz_spelling() {
        let postgres_14 = PostgreSqlConfig::baseline(PostgreSqlVersion::V14)
            .with_wal_compression(PostgreSqlWalCompression::Pglz)
            .unwrap()
            .generate()
            .unwrap();
        assert!(postgres_14.contents().contains("wal_compression = on\n"));
        assert!(!postgres_14.contents().contains("wal_compression = pglz\n"));

        for version in [
            PostgreSqlVersion::V15,
            PostgreSqlVersion::V16,
            PostgreSqlVersion::V17,
            PostgreSqlVersion::V18,
        ] {
            let generated = PostgreSqlConfig::baseline(version)
                .with_wal_compression(PostgreSqlWalCompression::Pglz)
                .unwrap()
                .generate()
                .unwrap();
            assert!(generated.contents().contains("wal_compression = pglz\n"));
            validate_generated_document(generated.contents(), version).unwrap();
        }
    }

    #[test]
    fn generated_validator_rejects_unknown_include_duplicate_and_invalid_groups() {
        let baseline = PostgreSqlConfig::baseline(PostgreSqlVersion::V18)
            .generate()
            .unwrap();

        let mut unknown = baseline.contents().to_owned();
        unknown.push_str("work_mem = 64MB\n");
        assert!(validate_generated_document(&unknown, PostgreSqlVersion::V18).is_err());

        let mut include = baseline.contents().to_owned();
        include.push_str("include = 'other.conf'\n");
        assert!(validate_generated_document(&include, PostgreSqlVersion::V18).is_err());

        let mut duplicate = baseline.contents().to_owned();
        duplicate.push_str("port = 5433\n");
        assert!(validate_generated_document(&duplicate, PostgreSqlVersion::V18).is_err());

        let capacity = PostgreSqlConfig::baseline(PostgreSqlVersion::V18)
            .with_feature(PostgreSqlConfigFeature::ConnectionCapacity, true)
            .unwrap()
            .generate()
            .unwrap();
        let missing_group_member = capacity
            .contents()
            .replace("reserved_connections = 0\n", "");
        assert!(
            validate_generated_document(&missing_group_member, PostgreSqlVersion::V18).is_err()
        );

        let bad_log = PostgreSqlConfig::baseline(PostgreSqlVersion::V18)
            .with_feature(PostgreSqlConfigFeature::ConnectionLifecycleLogging, true)
            .unwrap()
            .generate()
            .unwrap()
            .contents()
            .replace(
                "'receipt,authentication,authorization'",
                "'all,setup_durations'",
            );
        assert!(validate_generated_document(&bad_log, PostgreSqlVersion::V18).is_err());

        let lock_wait = PostgreSqlConfig::baseline(PostgreSqlVersion::V18)
            .with_feature(PostgreSqlConfigFeature::LockWaitLogging, true)
            .unwrap()
            .generate()
            .unwrap();
        let missing_deadlock_timeout = lock_wait
            .contents()
            .replace("deadlock_timeout = 1000ms\n", "");
        assert!(
            validate_generated_document(&missing_deadlock_timeout, PostgreSqlVersion::V18).is_err()
        );

        let io_timing = PostgreSqlConfig::baseline(PostgreSqlVersion::V18)
            .with_feature(PostgreSqlConfigFeature::IoTiming, true)
            .unwrap()
            .generate()
            .unwrap();
        let missing_wal_timing = io_timing
            .contents()
            .replace("track_wal_io_timing = on\n", "");
        assert!(validate_generated_document(&missing_wal_timing, PostgreSqlVersion::V18).is_err());

        let wrong_wal_spelling = PostgreSqlConfig::baseline(PostgreSqlVersion::V14)
            .with_wal_compression(PostgreSqlWalCompression::Pglz)
            .unwrap()
            .generate()
            .unwrap()
            .contents()
            .replace("wal_compression = on", "wal_compression = pglz");
        assert!(validate_generated_document(&wrong_wal_spelling, PostgreSqlVersion::V14).is_err());
    }

    #[test]
    fn write_new_round_trips_and_never_overwrites() {
        let root = TestRoot::new();
        let generated = PostgreSqlConfig::baseline(PostgreSqlVersion::V18)
            .generate()
            .unwrap();
        let destination = root.0.join(generated.suggested_file_name());
        assert_eq!(generated.write_new(&destination).unwrap(), destination);
        assert_eq!(
            fs::read_to_string(&destination).unwrap(),
            generated.contents()
        );
        assert!(generated.write_new(&destination).is_err());
        assert_eq!(
            fs::read_to_string(&destination).unwrap(),
            generated.contents()
        );

        assert!(generated.write_new(Path::new("relative.conf")).is_err());
        assert!(generated.write_new(&root.0.join("fragment.txt")).is_err());
        assert!(
            generated
                .write_new(&root.0.join("missing").join("fragment.conf"))
                .is_err()
        );
    }

    #[test]
    fn cleanup_failure_reports_the_possible_partial_file_exactly() {
        let destination = PathBuf::from("C:\\tmp\\lovelyres-postgresql-partial.conf");
        let write_error = CoreError::validation(
            "generated PostgreSQL configuration write",
            "simulated write failure",
        );
        let error = combine_write_and_cleanup_result(
            &destination,
            write_error,
            Err(std::io::Error::other("simulated cleanup failure")),
        );
        let message = error.to_string();
        assert!(matches!(error, CoreError::PartialCleanup { .. }));
        assert!(message.contains(destination.to_string_lossy().as_ref()));
        assert!(message.contains("simulated write failure"));
        assert!(message.contains("simulated cleanup failure"));
        assert!(message.contains("inspect and remove this exact path manually"));
    }

    #[test]
    fn debug_output_does_not_expose_generated_contents() {
        let generated = PostgreSqlConfig::baseline(PostgreSqlVersion::V18)
            .generate()
            .unwrap();
        let debug = format!("{generated:?}");
        assert!(debug.contains("bytes"));
        assert!(!debug.contains("listen_addresses"));
        assert!(!debug.contains("scram-sha-256"));
    }

    #[test]
    fn deferred_boundaries_are_explicit_and_not_emitted_as_directives() {
        for reason in [
            POSTGRESQL_HBA_IDENT_DEFERRED_REASON,
            POSTGRESQL_AUTO_CONF_DEFERRED_REASON,
            POSTGRESQL_TLS_SECRET_ROLE_DEFERRED_REASON,
            POSTGRESQL_ARCHIVE_PRELOAD_DEFERRED_REASON,
            POSTGRESQL_RESOURCE_TUNING_DEFERRED_REASON,
            POSTGRESQL_STATEMENT_LOG_TEXT_DEFERRED_REASON,
            POSTGRESQL_EXISTING_CLUSTER_DEFERRED_REASON,
            POSTGRESQL_REMOTE_LISTENING_DEFERRED_REASON,
        ] {
            assert!(!reason.is_empty());
        }

        let generated = PostgreSqlConfig::baseline(PostgreSqlVersion::V18)
            .generate()
            .unwrap();
        let names = entry_names(generated.contents());
        for forbidden in [
            "include",
            "hba_file",
            "ident_file",
            "ssl",
            "ssl_key_file",
            "archive_command",
            "restore_command",
            "shared_preload_libraries",
            "shared_buffers",
            "work_mem",
            "statement_timeout",
            "lock_timeout",
            "log_statement",
            "log_min_duration_statement",
        ] {
            assert!(!names.contains(forbidden), "{forbidden}");
        }
    }
}
