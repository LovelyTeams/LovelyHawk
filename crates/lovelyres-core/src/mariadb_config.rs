//! Deterministic, bounded MariaDB option-file fragments for newly initialized,
//! empty standalone instances.
//!
//! The closed version set follows the MariaDB Foundation Community LTS table
//! as observed on 2026-08-24: 10.11, 11.4, 11.8, and 12.3. MariaDB 10.6 is
//! already EOL, while rolling and preview series are intentionally excluded.
//! The generator emits one review-only `[mariadb]` fragment; it does not add an
//! include directive, initialize an instance, deploy, overwrite, restart, or
//! inspect effective option precedence.
//!
//! Official references:
//! - <https://mariadb.org/about/#maintenance-policy>
//! - <https://mariadb.com/docs/server/server-management/install-and-upgrade-mariadb/configuring-mariadb/configuring-mariadb-with-option-files>
//! - <https://mariadb.com/docs/server/server-management/variables-and-modes/server-system-variables>
//! - <https://mariadb.com/docs/server/server-management/server-monitoring-logs/slow-query-log/slow-query-log-overview>
//! - <https://mariadb.com/docs/server/server-management/server-monitoring-logs/error-log>
//! - <https://mariadb.com/docs/server/ha-and-performance/standard-replication/replication-and-binary-log-system-variables>
//! - <https://mariadb.com/docs/server/reference/data-types/string-data-types/character-sets/setting-character-sets-and-collations>
//! - <https://mariadb.com/docs/server/server-usage/storage-engines/innodb/innodb-system-variables>

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

pub const MAX_GENERATED_MARIADB_CONFIG_BYTES: usize = 24 * 1024;
pub const MARIADB_LIFECYCLE_REFERENCE: &str = "https://mariadb.org/about/#maintenance-policy";
pub const MARIADB_OPTION_FILE_REFERENCE: &str = "https://mariadb.com/docs/server/server-management/install-and-upgrade-mariadb/configuring-mariadb/configuring-mariadb-with-option-files";
pub const MARIADB_SERVER_VARIABLES_REFERENCE: &str =
    "https://mariadb.com/docs/server/server-management/variables-and-modes/server-system-variables";
pub const MARIADB_SLOW_LOG_REFERENCE: &str = "https://mariadb.com/docs/server/server-management/server-monitoring-logs/slow-query-log/slow-query-log-overview";
pub const MARIADB_ERROR_LOG_REFERENCE: &str =
    "https://mariadb.com/docs/server/server-management/server-monitoring-logs/error-log";
pub const MARIADB_BINARY_LOG_REFERENCE: &str = "https://mariadb.com/docs/server/ha-and-performance/standard-replication/replication-and-binary-log-system-variables";
pub const MARIADB_BINARY_LOG_MAINTENANCE_REFERENCE: &str = "https://mariadb.com/docs/server/server-management/server-monitoring-logs/binary-log/using-and-maintaining-the-binary-log";
pub const MARIADB_CHARACTER_SET_REFERENCE: &str = "https://mariadb.com/docs/server/reference/data-types/string-data-types/character-sets/setting-character-sets-and-collations";
pub const MARIADB_SUPPORTED_COLLATIONS_REFERENCE: &str = "https://mariadb.com/docs/server/reference/data-types/string-data-types/character-sets/supported-character-sets-and-collations";
pub const MARIADB_INNODB_REFERENCE: &str =
    "https://mariadb.com/docs/server/server-usage/storage-engines/innodb/innodb-system-variables";
pub const MARIADB_LOCAL_INFILE_REFERENCE: &str = "https://mariadb.com/docs/server/reference/sql-statements/data-manipulation/inserting-loading-data/load-data-into-tables-or-index/load-data-infile";

pub const MARIADB_OFFICIAL_REFERENCES: &[&str] = &[
    MARIADB_LIFECYCLE_REFERENCE,
    MARIADB_OPTION_FILE_REFERENCE,
    MARIADB_SERVER_VARIABLES_REFERENCE,
    MARIADB_SLOW_LOG_REFERENCE,
    MARIADB_ERROR_LOG_REFERENCE,
    MARIADB_BINARY_LOG_REFERENCE,
    MARIADB_BINARY_LOG_MAINTENANCE_REFERENCE,
    MARIADB_CHARACTER_SET_REFERENCE,
    MARIADB_SUPPORTED_COLLATIONS_REFERENCE,
    MARIADB_INNODB_REFERENCE,
    MARIADB_LOCAL_INFILE_REFERENCE,
];

pub const MARIADB_TLS_CREDENTIALS_GRANTS_DEFERRED_REASON: &str = "TLS 证书/私钥、用户密码、认证插件、Host 匹配和 GRANT 权限需要 core-owned 凭据与目标权限验证边界；当前片段明确不生成。";
pub const MARIADB_EXISTING_INSTANCE_MIGRATION_DEFERRED_REASON: &str = "既有或含数据实例不能通过静态 option file 安全迁移；必须先盘点完整 option 来源、运行值、数据与复制状态，并提供备份、回滚、重启和数据/行为回读。";
pub const MARIADB_REMOTE_LISTENING_DEFERRED_REASON: &str = "非回环监听必须与 TLS、用户 Host/授权、主机防火墙和真实客户端验证形成闭环；当前 Baseline 固定 127.0.0.1。";
pub const MARIADB_HARDWARE_TUNING_DEFERRED_REASON: &str = "buffer pool、redo log、thread/cache 与 I/O 参数必须结合目标内存、存储、CPU 和工作负载 sizing；当前模块不伪造硬件默认值。";
pub const MARIADB_12_3_INNODB_BINLOG_DEFERRED_REASON: &str = "MariaDB 12.3 新增 InnoDB-based binary log；当前模块保留传统文件式 log_bin，不生成 binlog_storage_engine，待恢复、复制与工具兼容矩阵完成后再建模。";

const MAX_CONNECTIONS: u64 = 100_000;
const MAX_SECONDS_PER_YEAR: u64 = 31_536_000;
const MAX_SESSION_TIMEOUT_SECONDS: u64 = 31_536_000;
const MAX_SLOW_QUERY_SECONDS: u64 = 3_600;
const MAX_BINLOG_RETENTION_SECONDS: u64 = 8_553_600;
const MAX_ALLOWED_PACKET_MEBIBYTES: u64 = 1_024;
const MAX_INNODB_LOCK_WAIT_SECONDS: u64 = 3_600;
const ERROR_LOG_FILE_NAME: &str = "mariadb-error.log";
const SLOW_LOG_FILE_NAME: &str = "mariadb-slow.log";
const BINARY_LOG_BASENAME: &str = "mariadb-bin";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MariaDbVersion {
    V10_11,
    V11_4,
    V11_8,
    V12_3,
}

impl MariaDbVersion {
    pub const ALL: [Self; 4] = [Self::V10_11, Self::V11_4, Self::V11_8, Self::V12_3];

    pub const fn label(self) -> &'static str {
        match self {
            Self::V10_11 => "10.11",
            Self::V11_4 => "11.4",
            Self::V11_8 => "11.8",
            Self::V12_3 => "12.3",
        }
    }

    pub fn parse(value: &str) -> CoreResult<Self> {
        match value {
            "10.11" => Ok(Self::V10_11),
            "11.4" => Ok(Self::V11_4),
            "11.8" => Ok(Self::V11_8),
            "12.3" => Ok(Self::V12_3),
            _ => Err(CoreError::validation(
                "MariaDB Community LTS series",
                "must be one explicitly selected supported LTS series: 10.11, 11.4, 11.8, or 12.3",
            )),
        }
    }

    pub const fn support_notice(self) -> &'static str {
        match self {
            Self::V10_11 => {
                "MariaDB 10.11 Community LTS maintenance is scheduled through 2028-02-16."
            }
            Self::V11_4 => {
                "MariaDB 11.4 Community LTS maintenance is scheduled through 2029-05-29."
            }
            Self::V11_8 => {
                "MariaDB 11.8 Community LTS maintenance is scheduled through 2028-06-04."
            }
            Self::V12_3 => {
                "MariaDB 12.3 Community LTS maintenance is scheduled through 2029-06-12."
            }
        }
    }

    pub const fn risk(self) -> &'static str {
        match self {
            Self::V10_11 | Self::V11_4 => {
                "该系列早于 MariaDB 11.6 的默认字符集变化；不得把旧发行包默认值当成新系列默认值。"
            }
            Self::V11_8 => {
                "该系列晚于 MariaDB 11.6 的默认字符集变化；升级应用必须复核排序和比较语义。"
            }
            Self::V12_3 => {
                "该系列新增 InnoDB-based binary log 等能力；本生成器不会根据新能力猜测迁移或恢复设置。"
            }
        }
    }

    pub const fn uses_pre_11_6_character_defaults(self) -> bool {
        matches!(self, Self::V10_11 | Self::V11_4)
    }

    pub const fn supports_innodb_binary_log(self) -> bool {
        matches!(self, Self::V12_3)
    }

    pub const fn official_series_reference(self) -> &'static str {
        match self {
            Self::V10_11 => "https://mariadb.com/docs/release-notes/community-server/10.11",
            Self::V11_4 => "https://mariadb.com/docs/release-notes/community-server/11.4",
            Self::V11_8 => "https://mariadb.com/docs/release-notes/community-server/11.8",
            Self::V12_3 => "https://mariadb.com/docs/release-notes/community-server/12.3",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MariaDbConfigFeature {
    SkipNameResolve,
    ConnectionCapacity,
    HandshakeTimeout,
    SessionIdleTimeouts,
    HostErrorThreshold,
    MaximumPacketSize,
    SlowQueryLog,
    ErrorLogFile,
    BinaryLogging,
    BinaryLogRetention,
    BinaryLogDurability,
    CharacterSetAndCollation,
    InnoDbDurability,
    InnoDbLockWaitTimeout,
    InnoDbDeadlockLogging,
}

impl MariaDbConfigFeature {
    pub const ALL: [Self; 15] = [
        Self::SkipNameResolve,
        Self::ConnectionCapacity,
        Self::HandshakeTimeout,
        Self::SessionIdleTimeouts,
        Self::HostErrorThreshold,
        Self::MaximumPacketSize,
        Self::SlowQueryLog,
        Self::ErrorLogFile,
        Self::BinaryLogging,
        Self::BinaryLogRetention,
        Self::BinaryLogDurability,
        Self::CharacterSetAndCollation,
        Self::InnoDbDurability,
        Self::InnoDbLockWaitTimeout,
        Self::InnoDbDeadlockLogging,
    ];

    pub const fn key(self) -> &'static str {
        match self {
            Self::SkipNameResolve => "skip-name-resolve",
            Self::ConnectionCapacity => "connection-capacity",
            Self::HandshakeTimeout => "handshake-timeout",
            Self::SessionIdleTimeouts => "session-idle-timeouts",
            Self::HostErrorThreshold => "host-error-threshold",
            Self::MaximumPacketSize => "maximum-packet-size",
            Self::SlowQueryLog => "slow-query-log",
            Self::ErrorLogFile => "error-log-file",
            Self::BinaryLogging => "binary-logging",
            Self::BinaryLogRetention => "binary-log-retention",
            Self::BinaryLogDurability => "binary-log-durability",
            Self::CharacterSetAndCollation => "character-set-and-collation",
            Self::InnoDbDurability => "innodb-durability",
            Self::InnoDbLockWaitTimeout => "innodb-lock-wait-timeout",
            Self::InnoDbDeadlockLogging => "innodb-deadlock-logging",
        }
    }

    pub const fn title(self) -> &'static str {
        match self {
            Self::SkipNameResolve => "关闭客户端主机名解析",
            Self::ConnectionCapacity => "设置连接容量",
            Self::HandshakeTimeout => "限制客户端握手时间",
            Self::SessionIdleTimeouts => "限制会话空闲时间",
            Self::HostErrorThreshold => "设置主机连接错误阈值",
            Self::MaximumPacketSize => "限制最大协议包",
            Self::SlowQueryLog => "启用文件式慢查询日志",
            Self::ErrorLogFile => "固定错误日志文件",
            Self::BinaryLogging => "启用传统文件式二进制日志",
            Self::BinaryLogRetention => "设置二进制日志保留时间",
            Self::BinaryLogDurability => "每次提交同步二进制日志",
            Self::CharacterSetAndCollation => "固定字符集与排序规则",
            Self::InnoDbDurability => "显式启用 InnoDB 完整耐久性",
            Self::InnoDbLockWaitTimeout => "限制 InnoDB 锁等待",
            Self::InnoDbDeadlockLogging => "记录全部 InnoDB 死锁",
        }
    }

    pub const fn summary(self) -> &'static str {
        match self {
            Self::SkipNameResolve => {
                "连接授权检查只使用 IP/localhost，不等待反向 DNS；现有基于主机名的账户会失配。"
            }
            Self::ConnectionCapacity => {
                "显式限制同时客户端连接数；不包含线程池或 OS 文件描述符 sizing。"
            }
            Self::HandshakeTimeout => "限制服务器等待客户端完成初始握手的秒数。",
            Self::SessionIdleTimeouts => "分别限制非交互与交互连接的空闲秒数。",
            Self::HostErrorThreshold => {
                "单个主机连续连接错误达到阈值后会被 host cache 阻止，恢复可能需要 FLUSH HOSTS。"
            }
            Self::MaximumPacketSize => "限制单个通信包与部分中间缓冲的最大尺寸。",
            Self::SlowQueryLog => {
                "使用 MariaDB 10.11+ 的 log_slow_query 命名，固定 FILE 输出和相对 datadir 文件名。"
            }
            Self::ErrorLogFile => {
                "将错误日志固定到 datadir 相对文件 mariadb-error.log；不覆盖 systemd/journal 设计。"
            }
            Self::BinaryLogging => {
                "启用传统文件式 log_bin 与非零 server_id；不配置复制、GTID、格式或 12.3 InnoDB-based binlog。"
            }
            Self::BinaryLogRetention => {
                "使用非零 binlog_expire_logs_seconds 自动清理传统二进制日志，依赖 BinaryLogging。"
            }
            Self::BinaryLogDurability => {
                "设置 sync_binlog=1，让传统文件式 binlog 每次事务提交后请求同步，依赖 BinaryLogging。"
            }
            Self::CharacterSetAndCollation => {
                "显式固定 utf8mb4 与闭合排序规则，跨过 MariaDB 11.6 默认字符集变化时不依赖发行包默认。"
            }
            Self::InnoDbDurability => {
                "固定 innodb_flush_log_at_trx_commit=1 与 innodb_doublewrite=ON。"
            }
            Self::InnoDbLockWaitTimeout => "限制 InnoDB 事务等待行锁的秒数，超时会让语句失败。",
            Self::InnoDbDeadlockLogging => "将所有 InnoDB 死锁写入错误日志，而非只保留最近一次。",
        }
    }

    pub const fn aliases(self) -> &'static [&'static str] {
        match self {
            Self::SkipNameResolve => &["skip_name_resolve", "DNS", "主机名解析"],
            Self::ConnectionCapacity => &["max_connections", "连接数", "并发连接"],
            Self::HandshakeTimeout => &["connect_timeout", "握手超时", "连接超时"],
            Self::SessionIdleTimeouts => &["wait_timeout", "interactive_timeout", "空闲会话"],
            Self::HostErrorThreshold => &["max_connect_errors", "host cache", "连接错误"],
            Self::MaximumPacketSize => &["max_allowed_packet", "协议包", "packet"],
            Self::SlowQueryLog => &[
                "log_slow_query",
                "slow_query_log",
                "log_slow_query_time",
                "慢 SQL",
            ],
            Self::ErrorLogFile => &["log_error", "错误日志", "mariadb-error.log"],
            Self::BinaryLogging => &["log_bin", "server_id", "binlog", "复制日志"],
            Self::BinaryLogRetention => &["binlog_expire_logs_seconds", "日志保留", "自动清理"],
            Self::BinaryLogDurability => &["sync_binlog", "binlog fsync", "日志耐久性"],
            Self::CharacterSetAndCollation => &[
                "character_set_server",
                "collation_server",
                "utf8mb4",
                "排序规则",
            ],
            Self::InnoDbDurability => &[
                "innodb_flush_log_at_trx_commit",
                "innodb_doublewrite",
                "ACID",
            ],
            Self::InnoDbLockWaitTimeout => &["innodb_lock_wait_timeout", "锁等待", "行锁"],
            Self::InnoDbDeadlockLogging => &["innodb_print_all_deadlocks", "死锁日志", "deadlock"],
        }
    }

    pub const fn scope(self) -> &'static str {
        match self {
            Self::SkipNameResolve => "网络/授权前置条件",
            Self::ConnectionCapacity
            | Self::HandshakeTimeout
            | Self::SessionIdleTimeouts
            | Self::HostErrorThreshold
            | Self::MaximumPacketSize => "连接",
            Self::SlowQueryLog | Self::ErrorLogFile => "日志",
            Self::BinaryLogging | Self::BinaryLogRetention | Self::BinaryLogDurability => {
                "二进制日志"
            }
            Self::CharacterSetAndCollation => "新建对象默认/文本语义",
            Self::InnoDbDurability | Self::InnoDbLockWaitTimeout | Self::InnoDbDeadlockLogging => {
                "InnoDB"
            }
        }
    }

    pub const fn risk(self) -> &'static str {
        match self {
            Self::SkipNameResolve => {
                "基于 DNS 主机名的账户将无法匹配，启用前必须审阅全部账号 Host。"
            }
            Self::ConnectionCapacity => {
                "上限过高会耗尽内存、线程和文件描述符，过低会阻断应用及应急登录。"
            }
            Self::HandshakeTimeout => "阈值过短会拒绝高延迟或认证较慢的合法客户端。",
            Self::SessionIdleTimeouts => "空闲连接会被主动断开，连接池必须能检测并重建连接。",
            Self::HostErrorThreshold => "阈值过低可被攻击者利用来阻断合法来源地址。",
            Self::MaximumPacketSize => {
                "过低会让合法大行、BLOB 或复制事件失败；上限也会增加按需内存压力。"
            }
            Self::SlowQueryLog => "日志可能包含 SQL、字面量和敏感数据，并增加磁盘 I/O 与容量压力。",
            Self::ErrorLogFile => {
                "文件必须具有正确 datadir 权限、轮转和容量策略，否则可能启动失败或占满磁盘。"
            }
            Self::BinaryLogging => "会增加磁盘和恢复复杂度；server_id 必须在复制拓扑中唯一。",
            Self::BinaryLogRetention => "保留时间短于最大副本延迟或恢复窗口会破坏复制/时间点恢复。",
            Self::BinaryLogDurability => {
                "每提交同步可显著增加写延迟；存储栈仍可能不兑现持久化保证。"
            }
            Self::CharacterSetAndCollation => {
                "改变排序、比较和唯一约束语义；只影响随后创建且未显式指定的对象。"
            }
            Self::InnoDbDurability => {
                "完整刷盘与 doublewrite 会增加写 I/O；不能替代可靠存储和备份。"
            }
            Self::InnoDbLockWaitTimeout => "超时只让等待语句失败，应用必须正确回滚或重试事务。",
            Self::InnoDbDeadlockLogging => "高冲突工作负载可能产生大量错误日志。",
        }
    }

    pub const fn activation(self) -> &'static str {
        "下次启动/重启读取 option file（本模块不执行）"
    }

    pub const fn default_enabled(self) -> bool {
        false
    }

    pub const fn supports_version(self, _version: MariaDbVersion) -> bool {
        true
    }

    pub const fn required_feature(self) -> Option<Self> {
        match self {
            Self::BinaryLogRetention | Self::BinaryLogDurability => Some(Self::BinaryLogging),
            _ => None,
        }
    }

    pub const fn owned_keys(self) -> &'static [&'static str] {
        match self {
            Self::SkipNameResolve => &["skip_name_resolve"],
            Self::ConnectionCapacity => &["max_connections"],
            Self::HandshakeTimeout => &["connect_timeout"],
            Self::SessionIdleTimeouts => &["wait_timeout", "interactive_timeout"],
            Self::HostErrorThreshold => &["max_connect_errors"],
            Self::MaximumPacketSize => &["max_allowed_packet"],
            Self::SlowQueryLog => &[
                "log_output",
                "log_slow_query",
                "log_slow_query_time",
                "log_slow_query_file",
            ],
            Self::ErrorLogFile => &["log_error"],
            Self::BinaryLogging => &["log_bin", "server_id"],
            Self::BinaryLogRetention => &["binlog_expire_logs_seconds"],
            Self::BinaryLogDurability => &["sync_binlog"],
            Self::CharacterSetAndCollation => &["character_set_server", "collation_server"],
            Self::InnoDbDurability => &["innodb_flush_log_at_trx_commit", "innodb_doublewrite"],
            Self::InnoDbLockWaitTimeout => &["innodb_lock_wait_timeout"],
            Self::InnoDbDeadlockLogging => &["innodb_print_all_deadlocks"],
        }
    }

    pub const fn official_reference(self) -> &'static str {
        match self {
            Self::SkipNameResolve
            | Self::ConnectionCapacity
            | Self::HandshakeTimeout
            | Self::SessionIdleTimeouts
            | Self::HostErrorThreshold
            | Self::MaximumPacketSize => MARIADB_SERVER_VARIABLES_REFERENCE,
            Self::SlowQueryLog => MARIADB_SLOW_LOG_REFERENCE,
            Self::ErrorLogFile => MARIADB_ERROR_LOG_REFERENCE,
            Self::BinaryLogging | Self::BinaryLogRetention | Self::BinaryLogDurability => {
                MARIADB_BINARY_LOG_REFERENCE
            }
            Self::CharacterSetAndCollation => MARIADB_CHARACTER_SET_REFERENCE,
            Self::InnoDbDurability | Self::InnoDbLockWaitTimeout | Self::InnoDbDeadlockLogging => {
                MARIADB_INNODB_REFERENCE
            }
        }
    }

    pub const fn version_notice(self, version: MariaDbVersion) -> &'static str {
        match (self, version.uses_pre_11_6_character_defaults()) {
            (Self::CharacterSetAndCollation, true) => {
                "该系列早于 11.6，MariaDB 官方默认通常仍为 latin1；选择本功能会显式改为 utf8mb4。"
            }
            (Self::CharacterSetAndCollation, false) => {
                "MariaDB 11.6 起官方默认改为 utf8mb4；本功能仍显式固定字符集与排序规则，避免发行包差异。"
            }
            (Self::SlowQueryLog, _) => {
                "所有支持系列均从 10.11 起使用 log_slow_query 命名；旧 slow_query_log 仅是兼容别名。"
            }
            (Self::BinaryLogging, _) if version.supports_innodb_binary_log() => {
                MARIADB_12_3_INNODB_BINLOG_DEFERRED_REASON
            }
            _ => "该功能使用全部受支持 LTS 系列共有的闭合参数语义。",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MariaDbPort(u16);

impl MariaDbPort {
    pub fn parse(value: &str) -> CoreResult<Self> {
        Ok(Self(parse_decimal(value, 1, 65_535, "MariaDB port")? as u16))
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

macro_rules! bounded_u32 {
    ($name:ident, $subject:literal, $minimum:expr, $maximum:expr, $suggestion:expr) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub struct $name(u32);

        impl $name {
            pub fn parse(value: &str) -> CoreResult<Self> {
                Ok(Self(
                    parse_decimal(value, $minimum, $maximum, $subject)? as u32
                ))
            }

            pub const fn lovelyres_suggestion() -> Self {
                Self($suggestion)
            }

            pub const fn get(self) -> u32 {
                self.0
            }
        }
    };
}

bounded_u32!(
    MariaDbMaxConnections,
    "MariaDB max_connections",
    10,
    MAX_CONNECTIONS,
    200
);
bounded_u32!(
    MariaDbConnectTimeoutSeconds,
    "MariaDB connect_timeout",
    2,
    MAX_SECONDS_PER_YEAR,
    10
);
bounded_u32!(
    MariaDbMaxConnectErrors,
    "MariaDB max_connect_errors",
    1,
    u32::MAX as u64,
    100
);
bounded_u32!(
    MariaDbMaxAllowedPacketMebibytes,
    "MariaDB max_allowed_packet",
    1,
    MAX_ALLOWED_PACKET_MEBIBYTES,
    64
);
bounded_u32!(
    MariaDbSlowQueryTimeSeconds,
    "MariaDB slow-query time",
    1,
    MAX_SLOW_QUERY_SECONDS,
    2
);
bounded_u32!(MariaDbServerId, "MariaDB server_id", 1, u32::MAX as u64, 1);
bounded_u32!(
    MariaDbBinaryLogRetentionSeconds,
    "MariaDB binary-log retention",
    1,
    MAX_BINLOG_RETENTION_SECONDS,
    604_800
);
bounded_u32!(
    MariaDbInnoDbLockWaitTimeoutSeconds,
    "MariaDB InnoDB lock-wait timeout",
    1,
    MAX_INNODB_LOCK_WAIT_SECONDS,
    50
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MariaDbSessionIdleTimeouts {
    wait_timeout_seconds: u32,
    interactive_timeout_seconds: u32,
}

impl MariaDbSessionIdleTimeouts {
    pub fn parse(wait_timeout: &str, interactive_timeout: &str) -> CoreResult<Self> {
        Ok(Self {
            wait_timeout_seconds: parse_decimal(
                wait_timeout,
                1,
                MAX_SESSION_TIMEOUT_SECONDS,
                "MariaDB wait_timeout",
            )? as u32,
            interactive_timeout_seconds: parse_decimal(
                interactive_timeout,
                1,
                MAX_SESSION_TIMEOUT_SECONDS,
                "MariaDB interactive_timeout",
            )? as u32,
        })
    }

    pub const fn lovelyres_suggestion() -> Self {
        Self {
            wait_timeout_seconds: 600,
            interactive_timeout_seconds: 600,
        }
    }

    pub const fn wait_timeout_seconds(self) -> u32 {
        self.wait_timeout_seconds
    }

    pub const fn interactive_timeout_seconds(self) -> u32 {
        self.interactive_timeout_seconds
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MariaDbCharacterProfile {
    UnicodeCaseInsensitive,
    UnicodeBinary,
}

impl MariaDbCharacterProfile {
    pub const ALL: [Self; 2] = [Self::UnicodeCaseInsensitive, Self::UnicodeBinary];

    pub const fn label(self) -> &'static str {
        match self {
            Self::UnicodeCaseInsensitive => "utf8mb4 / UCA 14 不区分大小写",
            Self::UnicodeBinary => "utf8mb4 / 二进制排序",
        }
    }

    pub const fn summary(self) -> &'static str {
        match self {
            Self::UnicodeCaseInsensitive => {
                "使用 utf8mb4_uca1400_ai_ci，按 UCA 14.0 进行不区分重音与大小写比较。"
            }
            Self::UnicodeBinary => "使用 utf8mb4_bin，按编码字节进行区分大小写的二进制比较。",
        }
    }

    pub const fn risk(self) -> &'static str {
        match self {
            Self::UnicodeCaseInsensitive => {
                "视觉不同的字符串可能比较相等，影响唯一索引、排序和应用标识符。"
            }
            Self::UnicodeBinary => "用户可见文本排序不符合自然语言规则，大小写差异会影响匹配。",
        }
    }

    const fn character_set(self) -> &'static str {
        "utf8mb4"
    }

    const fn collation(self) -> &'static str {
        match self {
            Self::UnicodeCaseInsensitive => "utf8mb4_uca1400_ai_ci",
            Self::UnicodeBinary => "utf8mb4_bin",
        }
    }

    fn parse(character_set: &str, collation: &str) -> CoreResult<Self> {
        Self::ALL
            .into_iter()
            .find(|profile| {
                profile.character_set() == character_set && profile.collation() == collation
            })
            .ok_or_else(|| {
                CoreError::validation(
                    "MariaDB character-set profile",
                    "must be one reviewed utf8mb4 character-set/collation pair",
                )
            })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MariaDbConfig {
    version: MariaDbVersion,
    port: MariaDbPort,
    features: BTreeSet<MariaDbConfigFeature>,
    max_connections: MariaDbMaxConnections,
    connect_timeout: MariaDbConnectTimeoutSeconds,
    session_idle_timeouts: MariaDbSessionIdleTimeouts,
    max_connect_errors: MariaDbMaxConnectErrors,
    max_allowed_packet: MariaDbMaxAllowedPacketMebibytes,
    slow_query_time: MariaDbSlowQueryTimeSeconds,
    server_id: MariaDbServerId,
    binary_log_retention: MariaDbBinaryLogRetentionSeconds,
    character_profile: MariaDbCharacterProfile,
    innodb_lock_wait_timeout: MariaDbInnoDbLockWaitTimeoutSeconds,
}

impl MariaDbConfig {
    pub fn baseline(version: MariaDbVersion) -> Self {
        Self {
            version,
            port: MariaDbPort(3_306),
            features: BTreeSet::new(),
            max_connections: MariaDbMaxConnections::lovelyres_suggestion(),
            connect_timeout: MariaDbConnectTimeoutSeconds::lovelyres_suggestion(),
            session_idle_timeouts: MariaDbSessionIdleTimeouts::lovelyres_suggestion(),
            max_connect_errors: MariaDbMaxConnectErrors::lovelyres_suggestion(),
            max_allowed_packet: MariaDbMaxAllowedPacketMebibytes::lovelyres_suggestion(),
            slow_query_time: MariaDbSlowQueryTimeSeconds::lovelyres_suggestion(),
            server_id: MariaDbServerId::lovelyres_suggestion(),
            binary_log_retention: MariaDbBinaryLogRetentionSeconds::lovelyres_suggestion(),
            character_profile: MariaDbCharacterProfile::UnicodeCaseInsensitive,
            innodb_lock_wait_timeout: MariaDbInnoDbLockWaitTimeoutSeconds::lovelyres_suggestion(),
        }
    }

    pub const fn version(&self) -> MariaDbVersion {
        self.version
    }

    pub const fn port(&self) -> MariaDbPort {
        self.port
    }

    pub fn features(&self) -> &BTreeSet<MariaDbConfigFeature> {
        &self.features
    }

    pub fn feature_enabled(&self, feature: MariaDbConfigFeature) -> bool {
        self.features.contains(&feature)
    }

    pub const fn max_connections(&self) -> MariaDbMaxConnections {
        self.max_connections
    }

    pub const fn connect_timeout(&self) -> MariaDbConnectTimeoutSeconds {
        self.connect_timeout
    }

    pub const fn session_idle_timeouts(&self) -> MariaDbSessionIdleTimeouts {
        self.session_idle_timeouts
    }

    pub const fn max_connect_errors(&self) -> MariaDbMaxConnectErrors {
        self.max_connect_errors
    }

    pub const fn max_allowed_packet(&self) -> MariaDbMaxAllowedPacketMebibytes {
        self.max_allowed_packet
    }

    pub const fn slow_query_time(&self) -> MariaDbSlowQueryTimeSeconds {
        self.slow_query_time
    }

    pub const fn server_id(&self) -> MariaDbServerId {
        self.server_id
    }

    pub const fn binary_log_retention(&self) -> MariaDbBinaryLogRetentionSeconds {
        self.binary_log_retention
    }

    pub const fn character_profile(&self) -> MariaDbCharacterProfile {
        self.character_profile
    }

    pub const fn innodb_lock_wait_timeout(&self) -> MariaDbInnoDbLockWaitTimeoutSeconds {
        self.innodb_lock_wait_timeout
    }

    pub fn with_port(mut self, port: MariaDbPort) -> Self {
        self.port = port;
        self
    }

    pub fn with_feature(
        mut self,
        feature: MariaDbConfigFeature,
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

    pub fn with_max_connections(mut self, value: MariaDbMaxConnections) -> CoreResult<Self> {
        self.max_connections = value;
        self.features
            .insert(MariaDbConfigFeature::ConnectionCapacity);
        self.validate()?;
        Ok(self)
    }

    pub fn with_connect_timeout(mut self, value: MariaDbConnectTimeoutSeconds) -> CoreResult<Self> {
        self.connect_timeout = value;
        self.features.insert(MariaDbConfigFeature::HandshakeTimeout);
        self.validate()?;
        Ok(self)
    }

    pub fn with_session_idle_timeouts(
        mut self,
        value: MariaDbSessionIdleTimeouts,
    ) -> CoreResult<Self> {
        self.session_idle_timeouts = value;
        self.features
            .insert(MariaDbConfigFeature::SessionIdleTimeouts);
        self.validate()?;
        Ok(self)
    }

    pub fn with_max_connect_errors(mut self, value: MariaDbMaxConnectErrors) -> CoreResult<Self> {
        self.max_connect_errors = value;
        self.features
            .insert(MariaDbConfigFeature::HostErrorThreshold);
        self.validate()?;
        Ok(self)
    }

    pub fn with_max_allowed_packet(
        mut self,
        value: MariaDbMaxAllowedPacketMebibytes,
    ) -> CoreResult<Self> {
        self.max_allowed_packet = value;
        self.features
            .insert(MariaDbConfigFeature::MaximumPacketSize);
        self.validate()?;
        Ok(self)
    }

    pub fn with_slow_query_time(mut self, value: MariaDbSlowQueryTimeSeconds) -> CoreResult<Self> {
        self.slow_query_time = value;
        self.features.insert(MariaDbConfigFeature::SlowQueryLog);
        self.validate()?;
        Ok(self)
    }

    pub fn with_server_id(mut self, value: MariaDbServerId) -> CoreResult<Self> {
        self.server_id = value;
        self.features.insert(MariaDbConfigFeature::BinaryLogging);
        self.validate()?;
        Ok(self)
    }

    pub fn with_binary_log_retention(
        mut self,
        value: MariaDbBinaryLogRetentionSeconds,
    ) -> CoreResult<Self> {
        self.binary_log_retention = value;
        self.features
            .insert(MariaDbConfigFeature::BinaryLogRetention);
        self.validate()?;
        Ok(self)
    }

    pub fn with_character_profile(mut self, value: MariaDbCharacterProfile) -> CoreResult<Self> {
        self.character_profile = value;
        self.features
            .insert(MariaDbConfigFeature::CharacterSetAndCollation);
        self.validate()?;
        Ok(self)
    }

    pub fn with_innodb_lock_wait_timeout(
        mut self,
        value: MariaDbInnoDbLockWaitTimeoutSeconds,
    ) -> CoreResult<Self> {
        self.innodb_lock_wait_timeout = value;
        self.features
            .insert(MariaDbConfigFeature::InnoDbLockWaitTimeout);
        self.validate()?;
        Ok(self)
    }

    pub fn reset_to_baseline(&mut self) {
        *self = Self::baseline(self.version);
    }

    pub fn generate(&self) -> CoreResult<GeneratedMariaDbConfig> {
        self.validate()?;

        let mut contents = String::with_capacity(3_000);
        contents.push_str("# LovelyRes MariaDB ");
        contents.push_str(self.version.label());
        contents.push_str(" LTS new empty-instance review-only option fragment\n");
        contents.push_str(
            "# NEW EMPTY INSTANCE ONLY — DO NOT APPLY TO AN EXISTING OR DATA-BEARING INSTANCE.\n",
        );
        contents.push_str("# INCOMPLETE REVIEW FRAGMENT ONLY — LovelyRes does not include, initialize, install, deploy, overwrite, restart, or validate a target service.\n");
        contents.push_str("# Validate with the exact selected LTS series and current patch before manually including or activating this file.\n");
        contents.push_str("# Later option files, command-line arguments, environment/service-manager state, and SET GLOBAL can override this preview.\n");
        contents.push_str("# DEFERRED: TLS/private keys, users/passwords/auth plugins/GRANTs, non-loopback listening, replication/GTID topology, arbitrary paths/options, hardware-sized buffers, plugins, encryption keys, and existing-instance migration.\n");
        contents.push_str("# Loopback binding is not authentication: local processes and socket clients still require separately reviewed accounts and grants.\n");
        contents.push_str("# Fixed log names are relative to datadir; verify ownership, permissions, rotation, capacity, backup, and disclosure controls before startup.\n");
        contents.push_str("# Optional numeric values are LovelyRes suggestions, not detected target values or universal MariaDB defaults.\n");
        if self.version.supports_innodb_binary_log() {
            contents.push_str("# MariaDB 12.3 InnoDB-based binary log is intentionally deferred; this fragment never sets binlog_storage_engine.\n");
        }
        contents.push_str("\n[mariadb]\nbind_address = 127.0.0.1\nport = ");
        contents.push_str(&self.port.get().to_string());
        contents.push_str("\nlocal_infile = OFF\n");

        if self.feature_enabled(MariaDbConfigFeature::SkipNameResolve) {
            contents.push_str("\nskip_name_resolve = ON\n");
        }
        if self.feature_enabled(MariaDbConfigFeature::ConnectionCapacity) {
            contents.push_str("\n# LovelyRes suggestion: size against target memory, threads, file descriptors, pooling, and emergency access.\nmax_connections = ");
            contents.push_str(&self.max_connections.get().to_string());
            contents.push('\n');
        }
        if self.feature_enabled(MariaDbConfigFeature::HandshakeTimeout) {
            contents.push_str("\nconnect_timeout = ");
            contents.push_str(&self.connect_timeout.get().to_string());
            contents.push('\n');
        }
        if self.feature_enabled(MariaDbConfigFeature::SessionIdleTimeouts) {
            contents.push_str("\nwait_timeout = ");
            contents.push_str(
                &self
                    .session_idle_timeouts
                    .wait_timeout_seconds()
                    .to_string(),
            );
            contents.push_str("\ninteractive_timeout = ");
            contents.push_str(
                &self
                    .session_idle_timeouts
                    .interactive_timeout_seconds()
                    .to_string(),
            );
            contents.push('\n');
        }
        if self.feature_enabled(MariaDbConfigFeature::HostErrorThreshold) {
            contents.push_str("\nmax_connect_errors = ");
            contents.push_str(&self.max_connect_errors.get().to_string());
            contents.push('\n');
        }
        if self.feature_enabled(MariaDbConfigFeature::MaximumPacketSize) {
            contents.push_str("\nmax_allowed_packet = ");
            contents.push_str(&self.max_allowed_packet.get().to_string());
            contents.push_str("M\n");
        }
        if self.feature_enabled(MariaDbConfigFeature::SlowQueryLog) {
            contents.push_str("\n# Slow logs may contain SQL and sensitive literals.\nlog_output = FILE\nlog_slow_query = ON\nlog_slow_query_time = ");
            contents.push_str(&self.slow_query_time.get().to_string());
            contents.push_str("\nlog_slow_query_file = ");
            contents.push_str(SLOW_LOG_FILE_NAME);
            contents.push('\n');
        }
        if self.feature_enabled(MariaDbConfigFeature::ErrorLogFile) {
            contents.push_str("\nlog_error = ");
            contents.push_str(ERROR_LOG_FILE_NAME);
            contents.push('\n');
        }
        if self.feature_enabled(MariaDbConfigFeature::BinaryLogging) {
            contents.push_str("\n# Traditional file-based binlog only; replication and GTID remain deferred.\nlog_bin = ");
            contents.push_str(BINARY_LOG_BASENAME);
            contents.push_str("\nserver_id = ");
            contents.push_str(&self.server_id.get().to_string());
            contents.push('\n');
        }
        if self.feature_enabled(MariaDbConfigFeature::BinaryLogRetention) {
            contents.push_str("\nbinlog_expire_logs_seconds = ");
            contents.push_str(&self.binary_log_retention.get().to_string());
            contents.push('\n');
        }
        if self.feature_enabled(MariaDbConfigFeature::BinaryLogDurability) {
            contents.push_str("\nsync_binlog = 1\n");
        }
        if self.feature_enabled(MariaDbConfigFeature::CharacterSetAndCollation) {
            contents.push_str("\n# Explicit across the MariaDB 11.6 default-character-set transition.\ncharacter_set_server = ");
            contents.push_str(self.character_profile.character_set());
            contents.push_str("\ncollation_server = ");
            contents.push_str(self.character_profile.collation());
            contents.push('\n');
        }
        if self.feature_enabled(MariaDbConfigFeature::InnoDbDurability) {
            contents.push_str("\ninnodb_flush_log_at_trx_commit = 1\ninnodb_doublewrite = ON\n");
        }
        if self.feature_enabled(MariaDbConfigFeature::InnoDbLockWaitTimeout) {
            contents.push_str("\ninnodb_lock_wait_timeout = ");
            contents.push_str(&self.innodb_lock_wait_timeout.get().to_string());
            contents.push('\n');
        }
        if self.feature_enabled(MariaDbConfigFeature::InnoDbDeadlockLogging) {
            contents.push_str("\ninnodb_print_all_deadlocks = ON\n");
        }

        validate_generated_document(&contents, self.version)?;
        Ok(GeneratedMariaDbConfig {
            version: self.version,
            contents,
        })
    }

    fn validate(&self) -> CoreResult<()> {
        for feature in &self.features {
            if !feature.supports_version(self.version) {
                return Err(CoreError::validation(
                    "MariaDB configuration feature",
                    format!(
                        "{} is not supported by MariaDB {}",
                        feature.title(),
                        self.version.label()
                    ),
                ));
            }
            if let Some(required) = feature.required_feature()
                && !self.feature_enabled(required)
            {
                return Err(CoreError::validation(
                    "MariaDB configuration feature dependency",
                    format!("{} requires {}", feature.title(), required.title()),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GeneratedMariaDbConfig {
    version: MariaDbVersion,
    contents: String,
}

impl fmt::Debug for GeneratedMariaDbConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GeneratedMariaDbConfig")
            .field("version", &self.version)
            .field("bytes", &self.contents.len())
            .finish()
    }
}

impl GeneratedMariaDbConfig {
    pub const fn version(&self) -> MariaDbVersion {
        self.version
    }

    pub fn contents(&self) -> &str {
        &self.contents
    }

    pub fn suggested_file_name(&self) -> String {
        format!(
            "lovelyres-mariadb-{}-new-empty-instance.cnf",
            self.version.label()
        )
    }

    /// Writes one new local review fragment and never replaces an existing path.
    pub fn write_new(&self, destination: &Path) -> CoreResult<PathBuf> {
        validate_export_destination(destination)?;
        validate_generated_document(&self.contents, self.version)?;

        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(destination)
            .map_err(|source| {
                CoreError::io(
                    "create generated MariaDB review fragment",
                    destination,
                    source,
                )
            })?;
        let write_result = (|| {
            file.write_all(self.contents.as_bytes()).map_err(|source| {
                CoreError::io(
                    "write generated MariaDB review fragment",
                    destination,
                    source,
                )
            })?;
            file.flush().map_err(|source| {
                CoreError::io(
                    "flush generated MariaDB review fragment",
                    destination,
                    source,
                )
            })?;
            file.sync_all().map_err(|source| {
                CoreError::io(
                    "sync generated MariaDB review fragment",
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
            operation: "write generated MariaDB review fragment",
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

fn validate_generated_document(contents: &str, version: MariaDbVersion) -> CoreResult<()> {
    if contents.is_empty()
        || contents.len() > MAX_GENERATED_MARIADB_CONFIG_BYTES
        || contents.contains('\0')
        || contents.contains('\r')
        || !contents.ends_with('\n')
    {
        return Err(CoreError::validation(
            "generated MariaDB review fragment",
            format!(
                "must be non-empty LF-only UTF-8 with a terminal newline and at most {MAX_GENERATED_MARIADB_CONFIG_BYTES} bytes"
            ),
        ));
    }
    let required_header = format!(
        "# LovelyRes MariaDB {} LTS new empty-instance review-only option fragment\n# NEW EMPTY INSTANCE ONLY — DO NOT APPLY TO AN EXISTING OR DATA-BEARING INSTANCE.\n",
        version.label()
    );
    if !contents.starts_with(&required_header) {
        return Err(CoreError::validation(
            "generated MariaDB review fragment",
            "must retain the matching LTS series and prominent new-empty-instance-only warning",
        ));
    }

    let document = LineConfigVisualDocument::parse(LineConfigDialect::MySqlOption, contents)
        .map_err(|error| {
            CoreError::validation("generated MariaDB review fragment", error.to_string())
        })?;
    if !document.is_structured()
        || document.raw_bytes() != contents.as_bytes()
        || document.output().bytes() != contents.as_bytes()
    {
        return Err(CoreError::validation(
            "generated MariaDB review fragment",
            "closed template must parse structurally and round-trip byte-exactly through MySqlOption",
        ));
    }
    let rows = document.rows();
    if rows.iter().any(|row| {
        !matches!(
            row.kind(),
            LineConfigNodeKind::Comment | LineConfigNodeKind::Section | LineConfigNodeKind::Entry
        )
    }) {
        return Err(CoreError::validation(
            "generated MariaDB review fragment",
            "closed template must contain only comments, one section, and assignments; includes and opaque nodes are forbidden",
        ));
    }
    let sections = rows
        .iter()
        .filter(|row| row.kind() == LineConfigNodeKind::Section)
        .collect::<Vec<_>>();
    if sections.len() != 1 || sections[0].name() != Some("mariadb") {
        return Err(CoreError::validation(
            "generated MariaDB review fragment",
            "must contain exactly one [mariadb] section",
        ));
    }
    let section_id = sections[0].id();
    if rows
        .iter()
        .filter(|row| row.kind() == LineConfigNodeKind::Entry)
        .any(|row| row.parent() != Some(section_id))
    {
        return Err(CoreError::validation(
            "generated MariaDB review fragment",
            "every assignment must belong directly to [mariadb]",
        ));
    }

    const ALLOWED_DIRECTIVES: &[&str] = &[
        "bind_address",
        "port",
        "local_infile",
        "skip_name_resolve",
        "max_connections",
        "connect_timeout",
        "wait_timeout",
        "interactive_timeout",
        "max_connect_errors",
        "max_allowed_packet",
        "log_output",
        "log_slow_query",
        "log_slow_query_time",
        "log_slow_query_file",
        "log_error",
        "log_bin",
        "server_id",
        "binlog_expire_logs_seconds",
        "sync_binlog",
        "character_set_server",
        "collation_server",
        "innodb_flush_log_at_trx_commit",
        "innodb_doublewrite",
        "innodb_lock_wait_timeout",
        "innodb_print_all_deadlocks",
    ];

    let mut in_section = false;
    let mut section_count = 0_usize;
    let mut directives = BTreeMap::<String, String>::new();
    for line in contents.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[mariadb]" {
            section_count += 1;
            in_section = true;
            continue;
        }
        if line.starts_with('[') || line.ends_with(']') || !in_section {
            return Err(CoreError::validation(
                "generated MariaDB review fragment",
                "only one [mariadb] section is allowed and assignments must follow it",
            ));
        }
        if line.matches('=').count() != 1 {
            return Err(CoreError::validation(
                "generated MariaDB review fragment",
                "assignments must contain exactly one equals separator",
            ));
        }
        let (raw_name, raw_value) = line.split_once('=').expect("equals count checked");
        let name = raw_name.trim();
        let value = raw_value.trim();
        if line != format!("{name} = {value}") {
            return Err(CoreError::validation(
                "generated MariaDB review fragment",
                "assignments must use canonical `key = value` formatting",
            ));
        }
        if !ALLOWED_DIRECTIVES.contains(&name) {
            return Err(CoreError::validation(
                "generated MariaDB review fragment",
                format!("directive {name} is outside the closed generator allowlist"),
            ));
        }
        if value.is_empty()
            || directives
                .insert(name.to_owned(), value.to_owned())
                .is_some()
        {
            return Err(CoreError::validation(
                "generated MariaDB review fragment",
                format!("directive {name} must have one non-empty value and occur exactly once"),
            ));
        }
    }
    if section_count != 1 {
        return Err(CoreError::validation(
            "generated MariaDB review fragment",
            "must contain exactly one [mariadb] section",
        ));
    }

    let parsed_names = rows
        .iter()
        .filter(|row| row.kind() == LineConfigNodeKind::Entry)
        .map(|row| row.name())
        .collect::<Vec<_>>();
    if parsed_names.len() != directives.len()
        || parsed_names
            .iter()
            .any(|name| name.is_none_or(|name| !directives.contains_key(name)))
    {
        return Err(CoreError::validation(
            "generated MariaDB review fragment",
            "manual closed-value validation disagrees with the lossless MySqlOption parse",
        ));
    }

    let one = |name: &str| -> CoreResult<&str> {
        directives.get(name).map(String::as_str).ok_or_else(|| {
            CoreError::validation(
                "generated MariaDB review fragment",
                format!("required baseline directive {name} is missing"),
            )
        })
    };
    if one("bind_address")? != "127.0.0.1" {
        return Err(CoreError::validation(
            "generated MariaDB review fragment",
            MARIADB_REMOTE_LISTENING_DEFERRED_REASON,
        ));
    }
    MariaDbPort::parse(one("port")?)?;
    if one("local_infile")? != "OFF" {
        return Err(CoreError::validation(
            "generated MariaDB review fragment",
            "local_infile must remain disabled in the immutable Baseline",
        ));
    }

    validate_optional_on(&directives, "skip_name_resolve")?;
    if let Some(value) = directives.get("max_connections") {
        MariaDbMaxConnections::parse(value)?;
    }
    if let Some(value) = directives.get("connect_timeout") {
        MariaDbConnectTimeoutSeconds::parse(value)?;
    }
    match (
        directives.get("wait_timeout"),
        directives.get("interactive_timeout"),
    ) {
        (None, None) => {}
        (Some(wait), Some(interactive)) => {
            MariaDbSessionIdleTimeouts::parse(wait, interactive)?;
        }
        _ => {
            return Err(CoreError::validation(
                "generated MariaDB review fragment",
                "wait_timeout and interactive_timeout must be emitted as one feature",
            ));
        }
    }
    if let Some(value) = directives.get("max_connect_errors") {
        MariaDbMaxConnectErrors::parse(value)?;
    }
    if let Some(value) = directives.get("max_allowed_packet") {
        MariaDbMaxAllowedPacketMebibytes::parse(strip_unit(value, "M")?)?;
    }

    match (
        directives.get("log_output"),
        directives.get("log_slow_query"),
        directives.get("log_slow_query_time"),
        directives.get("log_slow_query_file"),
    ) {
        (None, None, None, None) => {}
        (Some(output), Some(enabled), Some(seconds), Some(file))
            if output == "FILE" && enabled == "ON" && file == SLOW_LOG_FILE_NAME =>
        {
            MariaDbSlowQueryTimeSeconds::parse(seconds)?;
        }
        _ => {
            return Err(CoreError::validation(
                "generated MariaDB review fragment",
                "slow-query logging must use the complete reviewed 10.11+ canonical group",
            ));
        }
    }
    if directives
        .get("log_error")
        .is_some_and(|value| value != ERROR_LOG_FILE_NAME)
    {
        return Err(CoreError::validation(
            "generated MariaDB review fragment",
            "log_error must use the fixed datadir-relative review filename",
        ));
    }

    let binary_logging_enabled = match (directives.get("log_bin"), directives.get("server_id")) {
        (None, None) => false,
        (Some(basename), Some(server_id)) if basename == BINARY_LOG_BASENAME => {
            MariaDbServerId::parse(server_id)?;
            true
        }
        _ => {
            return Err(CoreError::validation(
                "generated MariaDB review fragment",
                "traditional binary logging must use one fixed basename and one typed server_id",
            ));
        }
    };
    if let Some(value) = directives.get("binlog_expire_logs_seconds") {
        if !binary_logging_enabled {
            return Err(CoreError::validation(
                "generated MariaDB review fragment",
                "binary-log retention requires BinaryLogging",
            ));
        }
        MariaDbBinaryLogRetentionSeconds::parse(value)?;
    }
    if let Some(value) = directives.get("sync_binlog")
        && (!binary_logging_enabled || value != "1")
    {
        return Err(CoreError::validation(
            "generated MariaDB review fragment",
            "sync_binlog must be 1 and requires BinaryLogging",
        ));
    }

    match (
        directives.get("character_set_server"),
        directives.get("collation_server"),
    ) {
        (None, None) => {}
        (Some(character_set), Some(collation)) => {
            MariaDbCharacterProfile::parse(character_set, collation)?;
        }
        _ => {
            return Err(CoreError::validation(
                "generated MariaDB review fragment",
                "character_set_server and collation_server must be emitted as one reviewed profile",
            ));
        }
    }

    match (
        directives.get("innodb_flush_log_at_trx_commit"),
        directives.get("innodb_doublewrite"),
    ) {
        (None, None) => {}
        (Some(flush), Some(doublewrite)) if flush == "1" && doublewrite == "ON" => {}
        _ => {
            return Err(CoreError::validation(
                "generated MariaDB review fragment",
                "InnoDB durability must use flush-at-commit 1 and doublewrite ON together",
            ));
        }
    }
    if let Some(value) = directives.get("innodb_lock_wait_timeout") {
        MariaDbInnoDbLockWaitTimeoutSeconds::parse(value)?;
    }
    validate_optional_on(&directives, "innodb_print_all_deadlocks")?;

    if version.supports_innodb_binary_log() && directives.contains_key("binlog_storage_engine") {
        return Err(CoreError::validation(
            "generated MariaDB review fragment",
            MARIADB_12_3_INNODB_BINLOG_DEFERRED_REASON,
        ));
    }
    Ok(())
}

fn validate_optional_on(directives: &BTreeMap<String, String>, name: &str) -> CoreResult<()> {
    if directives.get(name).is_some_and(|value| value != "ON") {
        return Err(CoreError::validation(
            "generated MariaDB review fragment",
            format!("directive {name} must use the closed value ON"),
        ));
    }
    Ok(())
}

fn strip_unit<'a>(value: &'a str, unit: &str) -> CoreResult<&'a str> {
    value.strip_suffix(unit).ok_or_else(|| {
        CoreError::validation(
            "generated MariaDB review fragment",
            format!("typed numeric value must include the explicit {unit} unit"),
        )
    })
}

fn validate_export_destination(destination: &Path) -> CoreResult<()> {
    if !destination.is_absolute() {
        return Err(CoreError::validation(
            "generated MariaDB review destination",
            "must be an absolute path selected by the native save dialog",
        ));
    }
    if destination
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(CoreError::validation(
            "generated MariaDB review destination",
            "must not contain current-directory or parent-directory components",
        ));
    }
    if !destination
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("cnf"))
    {
        return Err(CoreError::validation(
            "generated MariaDB review destination",
            "must use the .cnf extension",
        ));
    }
    let parent = destination.parent().ok_or_else(|| {
        CoreError::validation(
            "generated MariaDB review destination",
            "path has no parent directory",
        )
    })?;
    if !parent.is_dir() {
        return Err(CoreError::validation(
            "generated MariaDB review destination",
            "parent directory does not exist",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, fs};

    use uuid::Uuid;

    use super::*;

    #[derive(Debug)]
    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("lovelyres-mariadb-config-{}", Uuid::new_v4()));
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
        LineConfigVisualDocument::parse(LineConfigDialect::MySqlOption, contents)
            .unwrap()
            .rows()
            .into_iter()
            .filter(|row| row.kind() == LineConfigNodeKind::Entry)
            .map(|row| row.name().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn supported_lts_series_are_explicit_and_eol_or_rolling_series_are_rejected() {
        assert_eq!(
            MariaDbVersion::ALL
                .into_iter()
                .map(MariaDbVersion::label)
                .collect::<Vec<_>>(),
            ["10.11", "11.4", "11.8", "12.3"]
        );
        for version in MariaDbVersion::ALL {
            assert_eq!(MariaDbVersion::parse(version.label()).unwrap(), version);
            assert!(!version.support_notice().is_empty());
            assert!(!version.risk().is_empty());
            assert!(
                version
                    .official_series_reference()
                    .starts_with("https://mariadb.com/")
            );
        }
        for unsupported in ["", "10.6", "10.11.18", "11.7", "12.2", "13.0", " 11.8"] {
            assert!(
                MariaDbVersion::parse(unsupported).is_err(),
                "{unsupported:?}"
            );
        }
        assert!(
            MariaDbVersion::V10_11
                .support_notice()
                .contains("2028-02-16")
        );
        assert!(
            MariaDbVersion::V12_3
                .support_notice()
                .contains("2029-06-12")
        );
        assert!(MariaDbVersion::V12_3.supports_innodb_binary_log());
        assert!(!MariaDbVersion::V11_8.supports_innodb_binary_log());
    }

    #[test]
    fn feature_catalog_is_closed_unique_explained_and_version_aware() {
        assert_eq!(MariaDbConfigFeature::ALL.len(), 15);
        let keys = MariaDbConfigFeature::ALL
            .into_iter()
            .map(MariaDbConfigFeature::key)
            .collect::<HashSet<_>>();
        assert_eq!(keys.len(), MariaDbConfigFeature::ALL.len());
        let mut owned_keys = HashSet::new();
        for feature in MariaDbConfigFeature::ALL {
            assert!(!feature.key().is_empty());
            assert!(!feature.title().is_empty());
            assert!(!feature.summary().is_empty());
            assert!(!feature.aliases().is_empty());
            assert!(!feature.scope().is_empty());
            assert!(!feature.risk().is_empty());
            assert!(!feature.activation().is_empty());
            assert!(!feature.default_enabled());
            assert!(
                feature
                    .official_reference()
                    .starts_with("https://mariadb.com/")
            );
            assert!(
                MariaDbVersion::ALL
                    .into_iter()
                    .all(|version| feature.supports_version(version))
            );
            for key in feature.owned_keys() {
                assert!(owned_keys.insert(*key), "duplicate owner for {key}");
            }
        }
        assert_eq!(
            MariaDbConfigFeature::BinaryLogRetention.required_feature(),
            Some(MariaDbConfigFeature::BinaryLogging)
        );
        assert_eq!(
            MariaDbConfigFeature::BinaryLogDurability.required_feature(),
            Some(MariaDbConfigFeature::BinaryLogging)
        );
        assert!(
            MariaDbConfigFeature::CharacterSetAndCollation
                .version_notice(MariaDbVersion::V11_4)
                .contains("早于 11.6")
        );
        assert!(
            MariaDbConfigFeature::CharacterSetAndCollation
                .version_notice(MariaDbVersion::V11_8)
                .contains("11.6 起")
        );
        assert!(
            MariaDbConfigFeature::SlowQueryLog
                .version_notice(MariaDbVersion::V10_11)
                .contains("log_slow_query")
        );
        assert!(MARIADB_OFFICIAL_REFERENCES.iter().all(|reference| {
            reference.starts_with("https://mariadb.org/")
                || reference.starts_with("https://mariadb.com/")
        }));
    }

    #[test]
    fn baseline_is_loopback_only_and_contains_only_three_immutable_settings() {
        let expected = BTreeSet::from([
            "bind_address".to_owned(),
            "port".to_owned(),
            "local_infile".to_owned(),
        ]);
        for version in MariaDbVersion::ALL {
            let config = MariaDbConfig::baseline(version);
            assert!(config.features().is_empty());
            let generated = config.generate().unwrap();
            assert_eq!(entry_names(generated.contents()), expected);
            assert!(generated.contents().contains("[mariadb]\n"));
            assert!(generated.contents().contains("bind_address = 127.0.0.1\n"));
            assert!(generated.contents().contains("port = 3306\n"));
            assert!(generated.contents().contains("local_infile = OFF\n"));
            assert!(generated.contents().contains("NEW EMPTY INSTANCE ONLY"));
            assert!(
                generated
                    .contents()
                    .contains("INCOMPLETE REVIEW FRAGMENT ONLY")
            );
            assert!(
                generated
                    .contents()
                    .contains("Loopback binding is not authentication")
            );
            assert_eq!(
                generated.suggested_file_name(),
                format!(
                    "lovelyres-mariadb-{}-new-empty-instance.cnf",
                    version.label()
                )
            );
            validate_generated_document(generated.contents(), version).unwrap();
        }
    }

    #[test]
    fn typed_numeric_boundaries_reject_whitespace_signs_and_injection() {
        assert_eq!(MariaDbPort::parse("1").unwrap().get(), 1);
        assert_eq!(MariaDbPort::parse("65535").unwrap().get(), 65_535);
        assert_eq!(MariaDbMaxConnections::parse("10").unwrap().get(), 10);
        assert_eq!(
            MariaDbMaxConnections::parse("100000").unwrap().get(),
            100_000
        );
        assert_eq!(MariaDbConnectTimeoutSeconds::parse("2").unwrap().get(), 2);
        assert_eq!(
            MariaDbBinaryLogRetentionSeconds::parse("8553600")
                .unwrap()
                .get(),
            8_553_600
        );
        assert_eq!(
            MariaDbSessionIdleTimeouts::parse("60", "120")
                .unwrap()
                .interactive_timeout_seconds(),
            120
        );

        for invalid in ["", "0", "65536", " 3306", "+3306", "3306\nssl=ON"] {
            assert!(MariaDbPort::parse(invalid).is_err(), "{invalid:?}");
        }
        for invalid in ["9", "100001", "200 # comment", "200M"] {
            assert!(
                MariaDbMaxConnections::parse(invalid).is_err(),
                "{invalid:?}"
            );
        }
        assert!(MariaDbConnectTimeoutSeconds::parse("1").is_err());
        assert!(MariaDbConnectTimeoutSeconds::parse("31536001").is_err());
        assert!(MariaDbSessionIdleTimeouts::parse("0", "60").is_err());
        assert!(MariaDbMaxAllowedPacketMebibytes::parse("1025").is_err());
        assert!(MariaDbSlowQueryTimeSeconds::parse("2.5").is_err());
        assert!(MariaDbServerId::parse("0").is_err());
        assert!(MariaDbBinaryLogRetentionSeconds::parse("8553601").is_err());
        assert!(MariaDbInnoDbLockWaitTimeoutSeconds::parse("3601").is_err());
    }

    #[test]
    fn all_features_render_the_closed_reviewed_values() {
        let mut config = MariaDbConfig::baseline(MariaDbVersion::V12_3)
            .with_feature(MariaDbConfigFeature::BinaryLogging, true)
            .unwrap();
        for feature in MariaDbConfigFeature::ALL {
            config = config.with_feature(feature, true).unwrap();
        }
        let generated = config.generate().unwrap();
        for line in [
            "skip_name_resolve = ON\n",
            "max_connections = 200\n",
            "connect_timeout = 10\n",
            "wait_timeout = 600\n",
            "interactive_timeout = 600\n",
            "max_connect_errors = 100\n",
            "max_allowed_packet = 64M\n",
            "log_output = FILE\n",
            "log_slow_query = ON\n",
            "log_slow_query_time = 2\n",
            "log_slow_query_file = mariadb-slow.log\n",
            "log_error = mariadb-error.log\n",
            "log_bin = mariadb-bin\n",
            "server_id = 1\n",
            "binlog_expire_logs_seconds = 604800\n",
            "sync_binlog = 1\n",
            "character_set_server = utf8mb4\n",
            "collation_server = utf8mb4_uca1400_ai_ci\n",
            "innodb_flush_log_at_trx_commit = 1\n",
            "innodb_doublewrite = ON\n",
            "innodb_lock_wait_timeout = 50\n",
            "innodb_print_all_deadlocks = ON\n",
        ] {
            assert!(generated.contents().contains(line), "{line}");
        }
        validate_generated_document(generated.contents(), MariaDbVersion::V12_3).unwrap();
    }

    #[test]
    fn stacking_is_deterministic_removal_is_local_and_reset_restores_baseline() {
        let first = MariaDbConfig::baseline(MariaDbVersion::V11_8)
            .with_max_connections(MariaDbMaxConnections::parse("500").unwrap())
            .unwrap()
            .with_connect_timeout(MariaDbConnectTimeoutSeconds::parse("15").unwrap())
            .unwrap()
            .with_character_profile(MariaDbCharacterProfile::UnicodeBinary)
            .unwrap();
        let second = MariaDbConfig::baseline(MariaDbVersion::V11_8)
            .with_character_profile(MariaDbCharacterProfile::UnicodeBinary)
            .unwrap()
            .with_connect_timeout(MariaDbConnectTimeoutSeconds::parse("15").unwrap())
            .unwrap()
            .with_max_connections(MariaDbMaxConnections::parse("500").unwrap())
            .unwrap();
        assert_eq!(
            first.generate().unwrap().contents(),
            second.generate().unwrap().contents()
        );

        let removed = first
            .clone()
            .with_feature(MariaDbConfigFeature::HandshakeTimeout, false)
            .unwrap()
            .generate()
            .unwrap();
        let names = entry_names(removed.contents());
        assert!(!names.contains("connect_timeout"));
        assert!(names.contains("max_connections"));
        assert!(names.contains("character_set_server"));

        let mut reset = first;
        reset.reset_to_baseline();
        assert_eq!(reset, MariaDbConfig::baseline(MariaDbVersion::V11_8));
    }

    #[test]
    fn binary_retention_and_durability_require_binary_logging() {
        assert!(
            MariaDbConfig::baseline(MariaDbVersion::V11_8)
                .with_feature(MariaDbConfigFeature::BinaryLogRetention, true)
                .is_err()
        );
        assert!(
            MariaDbConfig::baseline(MariaDbVersion::V11_8)
                .with_feature(MariaDbConfigFeature::BinaryLogDurability, true)
                .is_err()
        );
        let configured = MariaDbConfig::baseline(MariaDbVersion::V11_8)
            .with_feature(MariaDbConfigFeature::BinaryLogging, true)
            .unwrap()
            .with_binary_log_retention(MariaDbBinaryLogRetentionSeconds::parse("86400").unwrap())
            .unwrap()
            .with_feature(MariaDbConfigFeature::BinaryLogDurability, true)
            .unwrap();
        assert!(
            configured
                .clone()
                .with_feature(MariaDbConfigFeature::BinaryLogging, false)
                .is_err()
        );
        let generated = configured.generate().unwrap();
        assert!(
            generated
                .contents()
                .contains("binlog_expire_logs_seconds = 86400\n")
        );
        assert!(generated.contents().contains("sync_binlog = 1\n"));
    }

    #[test]
    fn mariadb_quick_dependency_stack_remove_reset_save_and_visual_prerequisite_are_byte_exact() {
        let baseline = MariaDbConfig::baseline(MariaDbVersion::V12_3)
            .generate()
            .unwrap();
        assert!(baseline.contents().contains("MariaDB 12.3 LTS"));
        assert!(baseline.contents().contains("bind_address = 127.0.0.1\n"));
        assert!(baseline.contents().contains("port = 3306\n"));

        for dependent in [
            MariaDbConfigFeature::BinaryLogRetention,
            MariaDbConfigFeature::BinaryLogDurability,
        ] {
            assert!(
                MariaDbConfig::baseline(MariaDbVersion::V12_3)
                    .with_feature(dependent, true)
                    .is_err()
            );
        }
        let stacked = MariaDbConfig::baseline(MariaDbVersion::V12_3)
            .with_server_id(MariaDbServerId::parse("42").unwrap())
            .unwrap()
            .with_binary_log_retention(MariaDbBinaryLogRetentionSeconds::parse("86400").unwrap())
            .unwrap()
            .with_feature(MariaDbConfigFeature::BinaryLogDurability, true)
            .unwrap();
        let stacked_document = stacked.generate().unwrap();
        for directive in [
            "log_bin = mariadb-bin\n",
            "server_id = 42\n",
            "binlog_expire_logs_seconds = 86400\n",
            "sync_binlog = 1\n",
        ] {
            assert!(
                stacked_document.contents().contains(directive),
                "{directive}"
            );
        }

        let without_binary_log = stacked
            .clone()
            .with_feature(MariaDbConfigFeature::BinaryLogDurability, false)
            .unwrap()
            .with_feature(MariaDbConfigFeature::BinaryLogRetention, false)
            .unwrap()
            .with_feature(MariaDbConfigFeature::BinaryLogging, false)
            .unwrap()
            .generate()
            .unwrap();
        for removed in [
            "log_bin = mariadb-bin\n",
            "server_id = 42\n",
            "binlog_expire_logs_seconds = 86400\n",
            "sync_binlog = 1\n",
        ] {
            assert!(
                !without_binary_log.contents().contains(removed),
                "{removed}"
            );
        }

        let maria_10_11 = MariaDbConfig::baseline(MariaDbVersion::V10_11)
            .with_slow_query_time(MariaDbSlowQueryTimeSeconds::parse("2").unwrap())
            .unwrap()
            .generate()
            .unwrap();
        assert!(maria_10_11.contents().contains("MariaDB 10.11 LTS"));
        assert!(maria_10_11.contents().contains("log_slow_query = ON\n"));
        assert_eq!(
            maria_10_11.suggested_file_name(),
            "lovelyres-mariadb-10.11-new-empty-instance.cnf"
        );

        let mut reset = stacked;
        reset.reset_to_baseline();
        assert_eq!(reset.generate().unwrap().contents(), baseline.contents());

        let root = TestRoot::new();
        let destination = root.0.join("mariadb-quick.cnf");
        assert_eq!(maria_10_11.write_new(&destination).unwrap(), destination);
        assert_eq!(
            fs::read(&destination).unwrap(),
            maria_10_11.contents().as_bytes()
        );
        assert!(maria_10_11.write_new(&destination).is_err());
        assert_eq!(
            fs::read(&destination).unwrap(),
            maria_10_11.contents().as_bytes()
        );

        let visual =
            LineConfigVisualDocument::parse(LineConfigDialect::MySqlOption, maria_10_11.contents())
                .unwrap();
        assert!(visual.is_structured());
        assert_eq!(visual.raw_bytes(), maria_10_11.contents().as_bytes());
        assert_eq!(visual.output().bytes(), maria_10_11.contents().as_bytes());
    }

    #[test]
    fn slow_log_uses_mariadb_10_11_canonical_names_not_legacy_aliases() {
        for version in MariaDbVersion::ALL {
            let generated = MariaDbConfig::baseline(version)
                .with_slow_query_time(MariaDbSlowQueryTimeSeconds::parse("3").unwrap())
                .unwrap()
                .generate()
                .unwrap();
            let names = entry_names(generated.contents());
            for canonical in [
                "log_output",
                "log_slow_query",
                "log_slow_query_time",
                "log_slow_query_file",
            ] {
                assert!(names.contains(canonical));
            }
            for legacy in ["slow_query_log", "long_query_time", "slow_query_log_file"] {
                assert!(!names.contains(legacy));
            }
        }
    }

    #[test]
    fn character_profile_is_explicit_across_the_11_6_default_transition() {
        for version in MariaDbVersion::ALL {
            let generated = MariaDbConfig::baseline(version)
                .with_character_profile(MariaDbCharacterProfile::UnicodeCaseInsensitive)
                .unwrap()
                .generate()
                .unwrap();
            assert!(
                generated
                    .contents()
                    .contains("character_set_server = utf8mb4\n")
            );
            assert!(
                generated
                    .contents()
                    .contains("collation_server = utf8mb4_uca1400_ai_ci\n")
            );
        }
        assert!(MariaDbVersion::V11_4.uses_pre_11_6_character_defaults());
        assert!(!MariaDbVersion::V11_8.uses_pre_11_6_character_defaults());
        for profile in MariaDbCharacterProfile::ALL {
            assert!(!profile.label().is_empty());
            assert!(!profile.summary().is_empty());
            assert!(!profile.risk().is_empty());
            assert_eq!(
                MariaDbCharacterProfile::parse(profile.character_set(), profile.collation())
                    .unwrap(),
                profile
            );
        }
    }

    #[test]
    fn mariadb_12_3_innodb_binary_log_remains_explicitly_deferred() {
        let generated = MariaDbConfig::baseline(MariaDbVersion::V12_3)
            .with_feature(MariaDbConfigFeature::BinaryLogging, true)
            .unwrap()
            .generate()
            .unwrap();
        assert!(
            generated
                .contents()
                .contains("InnoDB-based binary log is intentionally deferred")
        );
        assert!(!entry_names(generated.contents()).contains("binlog_storage_engine"));
        assert!(MARIADB_12_3_INNODB_BINLOG_DEFERRED_REASON.contains("12.3"));
    }

    #[test]
    fn validator_rejects_unknown_include_duplicate_extra_section_and_bad_groups() {
        let baseline = MariaDbConfig::baseline(MariaDbVersion::V11_8)
            .generate()
            .unwrap();

        let mut unknown = baseline.contents().to_owned();
        unknown.push_str("innodb_buffer_pool_size = 4G\n");
        assert!(validate_generated_document(&unknown, MariaDbVersion::V11_8).is_err());

        let mut include = baseline.contents().to_owned();
        include.push_str("!include /etc/mysql/secret.cnf\n");
        assert!(validate_generated_document(&include, MariaDbVersion::V11_8).is_err());

        let mut duplicate = baseline.contents().to_owned();
        duplicate.push_str("port = 3307\n");
        assert!(validate_generated_document(&duplicate, MariaDbVersion::V11_8).is_err());

        let mut extra_section = baseline.contents().to_owned();
        extra_section.push_str("[mysqld]\nmax_connections = 100\n");
        assert!(validate_generated_document(&extra_section, MariaDbVersion::V11_8).is_err());

        let mut retention_without_binlog = baseline.contents().to_owned();
        retention_without_binlog.push_str("binlog_expire_logs_seconds = 86400\n");
        assert!(
            validate_generated_document(&retention_without_binlog, MariaDbVersion::V11_8).is_err()
        );

        let slow = MariaDbConfig::baseline(MariaDbVersion::V11_8)
            .with_feature(MariaDbConfigFeature::SlowQueryLog, true)
            .unwrap()
            .generate()
            .unwrap()
            .contents()
            .replace("log_output = FILE\n", "");
        assert!(validate_generated_document(&slow, MariaDbVersion::V11_8).is_err());
    }

    #[test]
    fn deferred_security_and_migration_boundaries_never_become_directives() {
        for reason in [
            MARIADB_TLS_CREDENTIALS_GRANTS_DEFERRED_REASON,
            MARIADB_EXISTING_INSTANCE_MIGRATION_DEFERRED_REASON,
            MARIADB_REMOTE_LISTENING_DEFERRED_REASON,
            MARIADB_HARDWARE_TUNING_DEFERRED_REASON,
            MARIADB_12_3_INNODB_BINLOG_DEFERRED_REASON,
        ] {
            assert!(!reason.is_empty());
        }
        let generated = MariaDbConfig::baseline(MariaDbVersion::V12_3)
            .generate()
            .unwrap();
        let names = entry_names(generated.contents());
        for forbidden in [
            "include",
            "bind_address_all",
            "ssl",
            "ssl_key",
            "require_secure_transport",
            "init_file",
            "skip_grant_tables",
            "user",
            "password",
            "innodb_buffer_pool_size",
            "innodb_log_file_size",
            "thread_cache_size",
            "binlog_storage_engine",
        ] {
            assert!(!names.contains(forbidden), "{forbidden}");
        }
    }

    #[test]
    fn write_new_round_trips_and_never_overwrites() {
        let root = TestRoot::new();
        let generated = MariaDbConfig::baseline(MariaDbVersion::V11_8)
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
        assert!(generated.write_new(Path::new("relative.cnf")).is_err());
        assert!(generated.write_new(&root.0.join("fragment.ini")).is_err());
        assert!(
            generated
                .write_new(&root.0.join("missing").join("fragment.cnf"))
                .is_err()
        );
    }

    #[test]
    fn cleanup_failure_reports_the_possible_partial_file_exactly() {
        let destination = PathBuf::from("C:\\tmp\\lovelyres-mariadb-partial.cnf");
        let write_error =
            CoreError::validation("generated MariaDB review write", "simulated write failure");
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
        let generated = MariaDbConfig::baseline(MariaDbVersion::V11_8)
            .generate()
            .unwrap();
        let debug = format!("{generated:?}");
        assert!(debug.contains("bytes"));
        assert!(!debug.contains("bind_address"));
        assert!(!debug.contains("local_infile"));
    }
}
