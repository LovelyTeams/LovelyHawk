//! Deterministic, bounded MongoDB configuration drafts for a new local
//! standalone `mongod` only.
//!
//! As of 2026-08-24, the closed version model accepts the supported
//! self-managed MongoDB Server series 7.0, 8.0, and 8.3. MongoDB 8.2 reached
//! end of life on 2026-07-31 and is deliberately rejected. This module emits
//! one incomplete local YAML file; it does not discover precedence, create
//! users or secrets, initialize a replica set, deploy, overwrite, start,
//! reload, restart, or verify a server. Existing or data-bearing deployments
//! require inventory, backup, rollback, and target read-back workflows.
//!
//! The parser below intentionally accepts only the tiny mapping-and-scalar
//! YAML subset emitted by this module. It is not a general-purpose YAML
//! parser: aliases, anchors, tags, sequences, flow collections, quoted or
//! multiline scalars, directives, merge keys, and inline comments are all
//! rejected before the closed key/value validator runs.
//!
//! Official references used by the closed model:
//! - <https://www.mongodb.com/legal/support-policy/lifecycles>
//! - <https://www.mongodb.com/docs/manual/reference/configuration-options/>
//! - <https://www.mongodb.com/docs/v8.0/reference/configuration-options/>
//! - <https://www.mongodb.com/docs/v7.0/reference/configuration-options/>
//! - <https://www.mongodb.com/docs/manual/tutorial/manage-the-database-profiler/>
//! - <https://www.mongodb.com/docs/manual/core/wiredtiger/>
//! - <https://www.mongodb.com/docs/manual/core/security-mongodb-configuration/>

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Component, Path, PathBuf},
};

use crate::{CoreError, CoreResult};

pub const MAX_GENERATED_MONGODB_CONFIG_BYTES: usize = 24 * 1024;
pub const MONGODB_LIFECYCLE_REFERENCE: &str =
    "https://www.mongodb.com/legal/support-policy/lifecycles";
pub const MONGODB_CONFIGURATION_REFERENCE: &str =
    "https://www.mongodb.com/docs/manual/reference/configuration-options/";
pub const MONGODB_8_CONFIGURATION_REFERENCE: &str =
    "https://www.mongodb.com/docs/v8.0/reference/configuration-options/";
pub const MONGODB_7_CONFIGURATION_REFERENCE: &str =
    "https://www.mongodb.com/docs/v7.0/reference/configuration-options/";
pub const MONGODB_8_3_RELEASE_REFERENCE: &str =
    "https://www.mongodb.com/docs/manual/release-notes/8.3/";
pub const MONGODB_PROFILER_REFERENCE: &str =
    "https://www.mongodb.com/docs/manual/tutorial/manage-the-database-profiler/";
pub const MONGODB_WIRED_TIGER_REFERENCE: &str =
    "https://www.mongodb.com/docs/manual/core/wiredtiger/";
pub const MONGODB_SECURITY_REFERENCE: &str =
    "https://www.mongodb.com/docs/manual/core/security-mongodb-configuration/";

pub const MONGODB_OFFICIAL_REFERENCES: &[&str] = &[
    MONGODB_LIFECYCLE_REFERENCE,
    MONGODB_CONFIGURATION_REFERENCE,
    MONGODB_8_CONFIGURATION_REFERENCE,
    MONGODB_7_CONFIGURATION_REFERENCE,
    MONGODB_8_3_RELEASE_REFERENCE,
    MONGODB_PROFILER_REFERENCE,
    MONGODB_WIRED_TIGER_REFERENCE,
    MONGODB_SECURITY_REFERENCE,
];

pub const MONGODB_AUTHENTICATION_DEFERRED_REASON: &str = "authorization 固定启用，但用户、角色、密码和 SCRAM 凭据必须由 core-owned 凭据流程在精确目标上创建并验证；本模块不生成任何认证秘密。";
pub const MONGODB_TLS_DEFERRED_REASON: &str = "TLS 证书、私钥、CA、密码及文件权限必须来自显式凭据与目标盘点；本模块不猜测路径、不生成密钥，也不输出 net.tls。";
pub const MONGODB_ENTERPRISE_DEFERRED_REASON: &str = "auditLog、security.redactClientLogData、静态加密、LDAP/KMIP 与其他 Enterprise/Atlas 专属能力不属于 Community-compatible 闭合模型，当前明确不提供。";
pub const MONGODB_REPLICA_SET_DEFERRED_REASON: &str = "仅写 replication.replSetName 不能初始化成员、验证多数派语义或完成内部认证；复制集、oplog 与分片配置当前明确不生成。";
pub const MONGODB_REMOTE_LISTENING_DEFERRED_REASON: &str = "非回环监听必须与 TLS、认证用户、主机防火墙、客户端来源和真实连接验证闭环；当前固定 bindIp 为 127.0.0.1。";
pub const MONGODB_EXISTING_DEPLOYMENT_DEFERRED_REASON: &str = "既有或含数据部署不能用静态草稿安全迁移；WiredTiger 压缩只影响新集合，缓存与启动参数还会受现有配置源和目标资源约束。";
pub const MONGODB_PATH_AND_SERVICE_DEFERRED_REASON: &str = "dbPath、PID、服务用户、套接字、包管理器布局与启动方式依赖目标；除用户显式提供的日志文件外，本模块不猜测路径，也不输出部署命令。";

const MAX_MONGODB_CONNECTIONS: u64 = 1_000_000;
const MAX_SLOW_OPERATION_THRESHOLD_MILLISECONDS: u64 = 86_400_000;
const MAX_LOG_PATH_BYTES: usize = 1_024;
const MIN_CACHE_THOUSANDTHS_GB: u64 = 256;
const MAX_CACHE_THOUSANDTHS_GB: u64 = 10_000_000;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MongoDbVersion {
    V7_0,
    V8_0,
    V8_3,
}

impl MongoDbVersion {
    pub const ALL: [Self; 3] = [Self::V7_0, Self::V8_0, Self::V8_3];

    pub const fn major(self) -> u16 {
        match self {
            Self::V7_0 => 7,
            Self::V8_0 | Self::V8_3 => 8,
        }
    }

    pub const fn minor(self) -> u16 {
        match self {
            Self::V7_0 | Self::V8_0 => 0,
            Self::V8_3 => 3,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::V7_0 => "7.0",
            Self::V8_0 => "8.0",
            Self::V8_3 => "8.3",
        }
    }

    pub fn parse(value: &str) -> CoreResult<Self> {
        if value != value.trim() || value.len() != 3 {
            return Err(unsupported_mongodb_version());
        }
        match value {
            "7.0" => Ok(Self::V7_0),
            "8.0" => Ok(Self::V8_0),
            "8.3" => Ok(Self::V8_3),
            _ => Err(unsupported_mongodb_version()),
        }
    }

    pub const fn supports_slow_in_progress_threshold(self) -> bool {
        matches!(self, Self::V8_3)
    }

    pub const fn official_documentation(self) -> &'static str {
        match self {
            Self::V7_0 => MONGODB_7_CONFIGURATION_REFERENCE,
            Self::V8_0 => MONGODB_8_CONFIGURATION_REFERENCE,
            Self::V8_3 => MONGODB_CONFIGURATION_REFERENCE,
        }
    }

    pub const fn support_notice(self) -> &'static str {
        match self {
            Self::V7_0 => {
                "MongoDB 7.0 的官方生命周期计划于 2027-08-31 结束；使用前必须重新确认状态并采用最新 7.0.x 安全补丁。"
            }
            Self::V8_0 => {
                "MongoDB 8.0 的官方生命周期计划于 2029-10-31 结束；使用精确 8.0 系列的最新补丁版本。"
            }
            Self::V8_3 => {
                "MongoDB 8.3 的官方生命周期计划于 2029-10-31 结束；使用精确 8.3 系列的最新补丁版本。"
            }
        }
    }

    pub const fn risk(self) -> &'static str {
        match self {
            Self::V7_0 => {
                "7.0 较早且支持窗口更短；不能把新草稿当作跳过补丁、升级路径或 FCV 检查的依据。"
            }
            Self::V8_0 => {
                "8.0 是长期支持的 major 系列，但参数默认值、FCV 和数据文件仍须由同系列目标验证。"
            }
            Self::V8_3 => {
                "8.3 是受支持的 minor 系列；部分部署能力与 8.0 不同，降级或迁移必须遵循官方相邻版本路径。"
            }
        }
    }
}

impl TryFrom<(u16, u16)> for MongoDbVersion {
    type Error = CoreError;

    fn try_from(value: (u16, u16)) -> Result<Self, Self::Error> {
        match value {
            (7, 0) => Ok(Self::V7_0),
            (8, 0) => Ok(Self::V8_0),
            (8, 3) => Ok(Self::V8_3),
            _ => Err(unsupported_mongodb_version()),
        }
    }
}

fn unsupported_mongodb_version() -> CoreError {
    CoreError::validation(
        "MongoDB server series",
        "must be one supported self-managed series as of 2026-08-24: 7.0, 8.0, or 8.3; 8.2 reached EOL on 2026-07-31",
    )
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MongoDbConfigFeature {
    ConnectionLimit,
    SlowOperationLogging,
    OperationProfiler,
    SlowInProgressLogging,
    LogRotation,
    WiredTigerCache,
    WiredTigerCompression,
}

impl MongoDbConfigFeature {
    pub const ALL: [Self; 7] = [
        Self::ConnectionLimit,
        Self::SlowOperationLogging,
        Self::OperationProfiler,
        Self::SlowInProgressLogging,
        Self::LogRotation,
        Self::WiredTigerCache,
        Self::WiredTigerCompression,
    ];

    pub const fn key(self) -> &'static str {
        match self {
            Self::ConnectionLimit => "connection-limit",
            Self::SlowOperationLogging => "slow-operation-logging",
            Self::OperationProfiler => "operation-profiler",
            Self::SlowInProgressLogging => "slow-in-progress-logging",
            Self::LogRotation => "log-rotation",
            Self::WiredTigerCache => "wiredtiger-cache",
            Self::WiredTigerCompression => "wiredtiger-compression",
        }
    }

    pub const fn title(self) -> &'static str {
        match self {
            Self::ConnectionLimit => "限制入站连接总量",
            Self::SlowOperationLogging => "设置慢操作日志阈值与采样率",
            Self::OperationProfiler => "启用慢操作数据库分析器",
            Self::SlowInProgressLogging => "记录仍在执行的长耗时查询",
            Self::LogRotation => "配置显式文件日志轮转语义",
            Self::WiredTigerCache => "限制 WiredTiger 内部缓存",
            Self::WiredTigerCompression => "选择新集合与 journal 压缩算法",
        }
    }

    pub const fn summary(self) -> &'static str {
        match self {
            Self::ConnectionLimit => {
                "设置 net.maxIncomingConnections；仍受 RLIMIT_NOFILE、内核和平台上限约束。"
            }
            Self::SlowOperationLogging => {
                "设置 slowOpThresholdMs 与 slowOpSampleRate；分析器保持关闭时仍影响诊断慢日志。"
            }
            Self::OperationProfiler => {
                "只开放 mode: slowOp，不开放会采集全部操作的 mode: all 或表达式 filter。"
            }
            Self::SlowInProgressLogging => "MongoDB 8.3+ 在查询跨过阈值时记录仍在执行的慢查询。",
            Self::LogRotation => {
                "使用调用方提供的绝对 POSIX 日志路径，闭合 destination/path/logAppend/logRotate。"
            }
            Self::WiredTigerCache => {
                "设置 cacheSizeGB；值必须基于容器/主机内存和其他进程，而非通用默认猜测。"
            }
            Self::WiredTigerCompression => {
                "同时设置新集合 blockCompressor 与 WiredTiger journalCompressor。"
            }
        }
    }

    pub const fn aliases(self) -> &'static [&'static str] {
        match self {
            Self::ConnectionLimit => &[
                "maxIncomingConnections",
                "maxConns",
                "最大连接数",
                "连接上限",
            ],
            Self::SlowOperationLogging => &[
                "slowOpThresholdMs",
                "slowOpSampleRate",
                "slowms",
                "慢查询日志",
            ],
            Self::OperationProfiler => &[
                "operationProfiling.mode",
                "profile slowOp",
                "数据库分析器",
                "操作分析",
            ],
            Self::SlowInProgressLogging => &[
                "slowOpInProgressThresholdMs",
                "defaultSlowInProgMS",
                "运行中慢查询",
            ],
            Self::LogRotation => &["systemLog.logRotate", "logAppend", "reopen", "日志轮转"],
            Self::WiredTigerCache => &[
                "cacheSizeGB",
                "wiredTigerCacheSizeGB",
                "WT cache",
                "缓存大小",
            ],
            Self::WiredTigerCompression => &[
                "blockCompressor",
                "journalCompressor",
                "snappy",
                "zstd",
                "压缩",
            ],
        }
    }

    pub const fn scope(self) -> &'static str {
        match self {
            Self::ConnectionLimit => "实例/网络",
            Self::SlowOperationLogging | Self::OperationProfiler | Self::SlowInProgressLogging => {
                "实例/可观测性"
            }
            Self::LogRotation => "实例/文件日志",
            Self::WiredTigerCache => "实例/内存与存储",
            Self::WiredTigerCompression => "新集合与 journal/存储",
        }
    }

    pub const fn risk(self) -> &'static str {
        match self {
            Self::ConnectionLimit => {
                "过低会拒绝合法连接，过高不会突破 OS 限制且会扩大连接相关内存与调度压力。"
            }
            Self::SlowOperationLogging => {
                "更低阈值或更高采样率会显著增加日志量，并可能把查询形状和运行元数据写入日志。"
            }
            Self::OperationProfiler => {
                "分析器有性能开销，system.profile 可能保存未加密的查询数据；必须控制读取权限和保留策略。"
            }
            Self::SlowInProgressLogging => {
                "阈值过低会重复暴露长查询运行元数据并放大日志量；该键在 8.3 之前不可用。"
            }
            Self::LogRotation => {
                "路径、目录权限和外部轮转器必须先验证；reopen 需要外部 rename/create 协作，rename 仍需触发轮转。"
            }
            Self::WiredTigerCache => {
                "过大会挤压文件系统缓存和其他进程，过小会增加 eviction；索引构建内存不计入此缓存。"
            }
            Self::WiredTigerCompression => {
                "压缩率与 CPU 成本取决于工作负载；集合选项只影响随后创建的新集合，不会重写既有数据。"
            }
        }
    }

    pub const fn activation(self) -> &'static str {
        match self {
            Self::LogRotation => "受控重启后生效；实际轮转仍需独立触发并验证",
            Self::WiredTigerCompression => "受控重启后成为新集合/journal 默认值；既有集合不变",
            _ => "受控重启后生效；本模块不执行启动或重启",
        }
    }

    pub const fn default_enabled(self) -> bool {
        false
    }

    pub const fn supports_version(self, version: MongoDbVersion) -> bool {
        !matches!(self, Self::SlowInProgressLogging)
            || version.supports_slow_in_progress_threshold()
    }

    pub const fn official_reference(self) -> &'static str {
        match self {
            Self::ConnectionLimit | Self::LogRotation => MONGODB_CONFIGURATION_REFERENCE,
            Self::SlowOperationLogging | Self::OperationProfiler | Self::SlowInProgressLogging => {
                MONGODB_PROFILER_REFERENCE
            }
            Self::WiredTigerCache | Self::WiredTigerCompression => MONGODB_WIRED_TIGER_REFERENCE,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MongoDbPort(u16);

impl MongoDbPort {
    pub fn parse(value: &str) -> CoreResult<Self> {
        Ok(Self(
            parse_decimal(value, 1, 65_535, "MongoDB TCP port")? as u16
        ))
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MongoDbConnectionLimit(u32);

impl MongoDbConnectionLimit {
    pub fn parse(value: &str) -> CoreResult<Self> {
        Ok(Self(parse_decimal(
            value,
            1,
            MAX_MONGODB_CONNECTIONS,
            "MongoDB maximum incoming connections",
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
pub struct MongoDbSlowOperationSettings {
    threshold_milliseconds: u32,
    sample_rate_ten_thousandths: u16,
}

impl MongoDbSlowOperationSettings {
    pub fn new(threshold_milliseconds: u32, sample_rate_ten_thousandths: u16) -> CoreResult<Self> {
        if threshold_milliseconds == 0
            || u64::from(threshold_milliseconds) > MAX_SLOW_OPERATION_THRESHOLD_MILLISECONDS
        {
            return Err(CoreError::validation(
                "MongoDB slow-operation threshold",
                format!(
                    "must be in 1..={MAX_SLOW_OPERATION_THRESHOLD_MILLISECONDS} milliseconds under this generator policy"
                ),
            ));
        }
        if sample_rate_ten_thousandths > 10_000 {
            return Err(CoreError::validation(
                "MongoDB slow-operation sample rate",
                "must be in 0..=10000 ten-thousandths (0.0..=1.0)",
            ));
        }
        Ok(Self {
            threshold_milliseconds,
            sample_rate_ten_thousandths,
        })
    }

    pub fn parse(threshold_milliseconds: &str, sample_rate: &str) -> CoreResult<Self> {
        let threshold = parse_decimal(
            threshold_milliseconds,
            1,
            MAX_SLOW_OPERATION_THRESHOLD_MILLISECONDS,
            "MongoDB slow-operation threshold",
        )? as u32;
        let sample_rate = parse_unit_interval(sample_rate)?;
        Self::new(threshold, sample_rate)
    }

    pub const fn lovelyres_suggestion() -> Self {
        Self {
            threshold_milliseconds: 100,
            sample_rate_ten_thousandths: 10_000,
        }
    }

    pub const fn threshold_milliseconds(self) -> u32 {
        self.threshold_milliseconds
    }

    pub const fn sample_rate_ten_thousandths(self) -> u16 {
        self.sample_rate_ten_thousandths
    }

    fn rendered_sample_rate(self) -> String {
        render_unit_interval(self.sample_rate_ten_thousandths)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MongoDbSlowInProgressThreshold(u32);

impl MongoDbSlowInProgressThreshold {
    pub fn parse(value: &str) -> CoreResult<Self> {
        Ok(Self(parse_decimal(
            value,
            1,
            MAX_SLOW_OPERATION_THRESHOLD_MILLISECONDS,
            "MongoDB slow-in-progress threshold",
        )? as u32))
    }

    pub const fn lovelyres_suggestion() -> Self {
        Self(5_000)
    }

    pub const fn milliseconds(self) -> u32 {
        self.0
    }
}

/// A decimal `cacheSizeGB` value stored as thousandths of one documented GB.
///
/// Integer storage avoids floating-point formatting differences and makes
/// deterministic output possible while retaining the official 0.256 GB lower
/// boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MongoDbWiredTigerCacheSize(u64);

impl MongoDbWiredTigerCacheSize {
    pub fn parse_gigabytes(value: &str) -> CoreResult<Self> {
        let thousandths = parse_fixed_decimal_thousandths(value, "MongoDB WiredTiger cache size")?;
        if !(MIN_CACHE_THOUSANDTHS_GB..=MAX_CACHE_THOUSANDTHS_GB).contains(&thousandths) {
            return Err(CoreError::validation(
                "MongoDB WiredTiger cache size",
                "must be in 0.256..=10000 GB with at most three fractional digits",
            ));
        }
        Ok(Self(thousandths))
    }

    pub const fn thousandths_of_gigabyte(self) -> u64 {
        self.0
    }

    fn rendered_gigabytes(self) -> String {
        render_fixed_decimal_thousandths(self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MongoDbCompressor {
    None,
    Snappy,
    Zlib,
    Zstd,
}

impl MongoDbCompressor {
    pub const ALL: [Self; 4] = [Self::None, Self::Snappy, Self::Zlib, Self::Zstd];

    pub fn parse(value: &str) -> CoreResult<Self> {
        match value {
            "none" => Ok(Self::None),
            "snappy" => Ok(Self::Snappy),
            "zlib" => Ok(Self::Zlib),
            "zstd" => Ok(Self::Zstd),
            _ => Err(CoreError::validation(
                "MongoDB WiredTiger compressor",
                "must be one closed value: none, snappy, zlib, or zstd",
            )),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Snappy => "snappy",
            Self::Zlib => "zlib",
            Self::Zstd => "zstd",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MongoDbCompression {
    collection: MongoDbCompressor,
    journal: MongoDbCompressor,
}

impl MongoDbCompression {
    pub const fn new(collection: MongoDbCompressor, journal: MongoDbCompressor) -> Self {
        Self {
            collection,
            journal,
        }
    }

    pub const fn collection(self) -> MongoDbCompressor {
        self.collection
    }

    pub const fn journal(self) -> MongoDbCompressor {
        self.journal
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MongoDbLogRotationMode {
    Rename,
    Reopen,
}

impl MongoDbLogRotationMode {
    pub fn parse(value: &str) -> CoreResult<Self> {
        match value {
            "rename" => Ok(Self::Rename),
            "reopen" => Ok(Self::Reopen),
            _ => Err(CoreError::validation(
                "MongoDB log rotation mode",
                "must be rename or reopen",
            )),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rename => "rename",
            Self::Reopen => "reopen",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MongoDbLogPath(String);

impl MongoDbLogPath {
    pub fn parse(value: &str) -> CoreResult<Self> {
        if value.is_empty()
            || value.len() > MAX_LOG_PATH_BYTES
            || value != value.trim()
            || !value.starts_with('/')
            || value.ends_with('/')
            || value.contains("//")
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'-' | b'.')
            })
        {
            return Err(invalid_log_path());
        }
        let mut components = value.split('/');
        if components.next() != Some("")
            || components
                .clone()
                .any(|component| component.is_empty() || matches!(component, "." | ".."))
        {
            return Err(invalid_log_path());
        }
        let file_name = components.next_back().ok_or_else(invalid_log_path)?;
        if !file_name.rsplit_once('.').is_some_and(|(stem, extension)| {
            !stem.is_empty() && extension.eq_ignore_ascii_case("log")
        }) {
            return Err(CoreError::validation(
                "MongoDB diagnostic log path",
                "must end in a non-empty .log file name",
            ));
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn invalid_log_path() -> CoreError {
    CoreError::validation(
        "MongoDB diagnostic log path",
        format!(
            "must be an absolute POSIX .log path of at most {MAX_LOG_PATH_BYTES} ASCII bytes, using only letters, digits, slash, dot, underscore, and hyphen, without empty, current, or parent components"
        ),
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MongoDbLogRotation {
    path: MongoDbLogPath,
    mode: MongoDbLogRotationMode,
}

impl MongoDbLogRotation {
    pub const fn new(path: MongoDbLogPath, mode: MongoDbLogRotationMode) -> Self {
        Self { path, mode }
    }

    pub fn path(&self) -> &MongoDbLogPath {
        &self.path
    }

    pub const fn mode(&self) -> MongoDbLogRotationMode {
        self.mode
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MongoDbConfig {
    version: MongoDbVersion,
    port: MongoDbPort,
    features: BTreeSet<MongoDbConfigFeature>,
    connection_limit: MongoDbConnectionLimit,
    slow_operations: MongoDbSlowOperationSettings,
    slow_in_progress: MongoDbSlowInProgressThreshold,
    log_rotation: Option<MongoDbLogRotation>,
    wired_tiger_cache: Option<MongoDbWiredTigerCacheSize>,
    compression: Option<MongoDbCompression>,
}

impl MongoDbConfig {
    pub fn baseline(version: MongoDbVersion) -> Self {
        Self {
            version,
            port: MongoDbPort(27_017),
            features: BTreeSet::new(),
            connection_limit: MongoDbConnectionLimit::lovelyres_suggestion(),
            slow_operations: MongoDbSlowOperationSettings::lovelyres_suggestion(),
            slow_in_progress: MongoDbSlowInProgressThreshold::lovelyres_suggestion(),
            log_rotation: None,
            wired_tiger_cache: None,
            compression: None,
        }
    }

    pub const fn version(&self) -> MongoDbVersion {
        self.version
    }

    pub const fn port(&self) -> MongoDbPort {
        self.port
    }

    pub fn features(&self) -> &BTreeSet<MongoDbConfigFeature> {
        &self.features
    }

    pub fn feature_enabled(&self, feature: MongoDbConfigFeature) -> bool {
        self.features.contains(&feature)
    }

    pub const fn connection_limit(&self) -> MongoDbConnectionLimit {
        self.connection_limit
    }

    pub const fn slow_operations(&self) -> MongoDbSlowOperationSettings {
        self.slow_operations
    }

    pub const fn slow_in_progress(&self) -> MongoDbSlowInProgressThreshold {
        self.slow_in_progress
    }

    pub fn log_rotation(&self) -> Option<&MongoDbLogRotation> {
        self.log_rotation.as_ref()
    }

    pub const fn wired_tiger_cache(&self) -> Option<MongoDbWiredTigerCacheSize> {
        self.wired_tiger_cache
    }

    pub const fn compression(&self) -> Option<MongoDbCompression> {
        self.compression
    }

    pub fn with_port(mut self, port: MongoDbPort) -> Self {
        self.port = port;
        self
    }

    pub fn with_feature(
        mut self,
        feature: MongoDbConfigFeature,
        enabled: bool,
    ) -> CoreResult<Self> {
        if enabled {
            if !feature.supports_version(self.version) {
                return Err(unsupported_feature_for_version(feature, self.version));
            }
            match feature {
                MongoDbConfigFeature::LogRotation if self.log_rotation.is_none() => {
                    return Err(CoreError::validation(
                        "MongoDB log rotation feature",
                        "requires an explicit typed path and mode through with_log_rotation; LovelyHawk does not guess log paths",
                    ));
                }
                MongoDbConfigFeature::WiredTigerCache if self.wired_tiger_cache.is_none() => {
                    return Err(CoreError::validation(
                        "MongoDB WiredTiger cache feature",
                        "requires an explicit target-sized value through with_wired_tiger_cache",
                    ));
                }
                MongoDbConfigFeature::WiredTigerCompression if self.compression.is_none() => {
                    return Err(CoreError::validation(
                        "MongoDB WiredTiger compression feature",
                        "requires explicit collection and journal compressors through with_compression",
                    ));
                }
                _ => {}
            }
            self.features.insert(feature);
        } else {
            self.features.remove(&feature);
        }
        self.validate()?;
        Ok(self)
    }

    pub fn with_connection_limit(mut self, value: MongoDbConnectionLimit) -> CoreResult<Self> {
        self.connection_limit = value;
        self.features.insert(MongoDbConfigFeature::ConnectionLimit);
        self.validate()?;
        Ok(self)
    }

    pub fn with_slow_operation_logging(
        mut self,
        value: MongoDbSlowOperationSettings,
    ) -> CoreResult<Self> {
        self.slow_operations = value;
        self.features
            .insert(MongoDbConfigFeature::SlowOperationLogging);
        self.validate()?;
        Ok(self)
    }

    pub fn with_slow_in_progress_logging(
        mut self,
        value: MongoDbSlowInProgressThreshold,
    ) -> CoreResult<Self> {
        if !self.version.supports_slow_in_progress_threshold() {
            return Err(unsupported_feature_for_version(
                MongoDbConfigFeature::SlowInProgressLogging,
                self.version,
            ));
        }
        self.slow_in_progress = value;
        self.features
            .insert(MongoDbConfigFeature::SlowInProgressLogging);
        self.validate()?;
        Ok(self)
    }

    pub fn with_log_rotation(mut self, value: MongoDbLogRotation) -> CoreResult<Self> {
        self.log_rotation = Some(value);
        self.features.insert(MongoDbConfigFeature::LogRotation);
        self.validate()?;
        Ok(self)
    }

    pub fn with_wired_tiger_cache(mut self, value: MongoDbWiredTigerCacheSize) -> CoreResult<Self> {
        self.wired_tiger_cache = Some(value);
        self.features.insert(MongoDbConfigFeature::WiredTigerCache);
        self.validate()?;
        Ok(self)
    }

    pub fn with_compression(mut self, value: MongoDbCompression) -> CoreResult<Self> {
        self.compression = Some(value);
        self.features
            .insert(MongoDbConfigFeature::WiredTigerCompression);
        self.validate()?;
        Ok(self)
    }

    pub fn reset_to_baseline(&mut self) {
        *self = Self::baseline(self.version);
    }

    pub fn generate(&self) -> CoreResult<GeneratedMongoDbConfig> {
        self.validate()?;

        let mut contents = String::with_capacity(3_072);
        contents.push_str("# LovelyHawk MongoDB ");
        contents.push_str(self.version.label());
        contents.push_str(" new local standalone mongod.conf draft\n");
        contents.push_str(
            "# NEW EMPTY LOCAL STANDALONE ONLY — DO NOT APPLY TO AN EXISTING OR DATA-BEARING DEPLOYMENT.\n",
        );
        contents.push_str("# INCOMPLETE LOCAL FILE ONLY — LovelyHawk does not deploy, overwrite, initialize, start, reload, restart, or verify mongod.\n");
        contents.push_str("# Validate this exact file with the exact target series before manual activation; other config files, environment expansion, and command-line values are outside this preview.\n");
        contents.push_str("# Loopback binding is not authorization: authorization is enabled, but the first user/role and all credentials must be created and verified separately through the documented localhost bootstrap boundary.\n");
        contents.push_str("# DEFERRED/UNAVAILABLE: passwords and SCRAM secrets; TLS/CA/private-key material; auditLog, log redaction, encryption, LDAP/KMIP and other Enterprise-only features; replica sets, oplog and sharding; dbPath/PID/service layout; existing-deployment migration; remote listening; deployment commands.\n");
        contents.push_str("# No dbPath or default log path is guessed. File logging appears only when the caller supplies a validated absolute POSIX .log path.\n");
        contents.push_str("# The emitted YAML is a strict LovelyHawk subset: mappings plus reviewed bare scalars only; YAML expansion, anchors, aliases, tags, includes, sequences and multiline values are forbidden.\n\n");

        contents.push_str("net:\n  bindIp: 127.0.0.1\n  port: ");
        contents.push_str(&self.port.get().to_string());
        contents.push('\n');
        if self.feature_enabled(MongoDbConfigFeature::ConnectionLimit) {
            contents.push_str("  maxIncomingConnections: ");
            contents.push_str(&self.connection_limit.get().to_string());
            contents.push('\n');
        }

        contents.push_str("security:\n  authorization: enabled\n  javascriptEnabled: false\n");

        let has_operation_profiling = self.features.iter().any(|feature| {
            matches!(
                feature,
                MongoDbConfigFeature::SlowOperationLogging
                    | MongoDbConfigFeature::OperationProfiler
                    | MongoDbConfigFeature::SlowInProgressLogging
            )
        });
        if has_operation_profiling {
            contents.push_str("operationProfiling:\n");
            if self.feature_enabled(MongoDbConfigFeature::OperationProfiler) {
                contents.push_str("  mode: slowOp\n");
            }
            if self.feature_enabled(MongoDbConfigFeature::SlowOperationLogging) {
                contents.push_str("  slowOpThresholdMs: ");
                contents.push_str(&self.slow_operations.threshold_milliseconds().to_string());
                contents.push_str("\n  slowOpSampleRate: ");
                contents.push_str(&self.slow_operations.rendered_sample_rate());
                contents.push('\n');
            }
            if self.feature_enabled(MongoDbConfigFeature::SlowInProgressLogging) {
                contents.push_str("  slowOpInProgressThresholdMs: ");
                contents.push_str(&self.slow_in_progress.milliseconds().to_string());
                contents.push('\n');
            }
        }

        if self.feature_enabled(MongoDbConfigFeature::LogRotation) {
            let rotation = self.log_rotation.as_ref().ok_or_else(|| {
                CoreError::validation(
                    "MongoDB log rotation feature",
                    "enabled feature is missing its typed path and mode",
                )
            })?;
            contents.push_str("systemLog:\n  destination: file\n  path: ");
            contents.push_str(rotation.path().as_str());
            contents.push_str("\n  logAppend: true\n  logRotate: ");
            contents.push_str(rotation.mode().as_str());
            contents.push_str("\n  timeStampFormat: iso8601-utc\n");
        }

        contents.push_str("storage:\n  engine: wiredTiger\n");
        let emit_cache = self.feature_enabled(MongoDbConfigFeature::WiredTigerCache);
        let emit_compression = self.feature_enabled(MongoDbConfigFeature::WiredTigerCompression);
        if emit_cache || emit_compression {
            contents.push_str("  wiredTiger:\n");
            contents.push_str("    engineConfig:\n");
            if emit_cache {
                let cache = self.wired_tiger_cache.ok_or_else(|| {
                    CoreError::validation(
                        "MongoDB WiredTiger cache feature",
                        "enabled feature is missing its typed cache size",
                    )
                })?;
                contents.push_str("      cacheSizeGB: ");
                contents.push_str(&cache.rendered_gigabytes());
                contents.push('\n');
            }
            if emit_compression {
                let compression = self.compression.ok_or_else(|| {
                    CoreError::validation(
                        "MongoDB WiredTiger compression feature",
                        "enabled feature is missing its typed compressors",
                    )
                })?;
                contents.push_str("      journalCompressor: ");
                contents.push_str(compression.journal().as_str());
                contents.push_str("\n    collectionConfig:\n      blockCompressor: ");
                contents.push_str(compression.collection().as_str());
                contents.push('\n');
            }
        }

        validate_generated_document(&contents, self.version)?;
        Ok(GeneratedMongoDbConfig {
            version: self.version,
            contents,
        })
    }

    fn validate(&self) -> CoreResult<()> {
        for feature in &self.features {
            if !feature.supports_version(self.version) {
                return Err(unsupported_feature_for_version(*feature, self.version));
            }
        }
        if self.feature_enabled(MongoDbConfigFeature::LogRotation) && self.log_rotation.is_none() {
            return Err(CoreError::validation(
                "MongoDB log rotation feature",
                "enabled feature is missing its typed path and mode",
            ));
        }
        if self.feature_enabled(MongoDbConfigFeature::WiredTigerCache)
            && self.wired_tiger_cache.is_none()
        {
            return Err(CoreError::validation(
                "MongoDB WiredTiger cache feature",
                "enabled feature is missing its target-sized typed value",
            ));
        }
        if self.feature_enabled(MongoDbConfigFeature::WiredTigerCompression)
            && self.compression.is_none()
        {
            return Err(CoreError::validation(
                "MongoDB WiredTiger compression feature",
                "enabled feature is missing its typed compressor pair",
            ));
        }
        Ok(())
    }
}

fn unsupported_feature_for_version(
    feature: MongoDbConfigFeature,
    version: MongoDbVersion,
) -> CoreError {
    CoreError::validation(
        "MongoDB configuration feature",
        format!(
            "{} is unavailable in MongoDB {}; slow-in-progress logging requires MongoDB 8.3 or newer",
            feature.title(),
            version.label()
        ),
    )
}

#[derive(Clone, Eq, PartialEq)]
pub struct GeneratedMongoDbConfig {
    version: MongoDbVersion,
    contents: String,
}

impl fmt::Debug for GeneratedMongoDbConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GeneratedMongoDbConfig")
            .field("version", &self.version)
            .field("bytes", &self.contents.len())
            .finish()
    }
}

impl GeneratedMongoDbConfig {
    pub fn contents(&self) -> &str {
        &self.contents
    }

    pub const fn version(&self) -> MongoDbVersion {
        self.version
    }

    pub fn suggested_file_name(&self) -> String {
        format!(
            "lovelyres-mongodb-{}-new-local-standalone-mongod.conf",
            self.version.label()
        )
    }

    /// Writes a new local draft and never replaces an existing path.
    ///
    /// A failure after `create_new` triggers a best-effort removal. If that
    /// cleanup also fails, one composite error exposes the exact path that may
    /// still contain a partial draft.
    pub fn write_new(&self, destination: &Path) -> CoreResult<PathBuf> {
        validate_export_destination(destination)?;
        validate_generated_document(&self.contents, self.version)?;

        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(destination)
            .map_err(|source| {
                CoreError::io(
                    "create generated MongoDB configuration draft",
                    destination,
                    source,
                )
            })?;
        let write_result = (|| {
            file.write_all(self.contents.as_bytes()).map_err(|source| {
                CoreError::io(
                    "write generated MongoDB configuration draft",
                    destination,
                    source,
                )
            })?;
            file.flush().map_err(|source| {
                CoreError::io(
                    "flush generated MongoDB configuration draft",
                    destination,
                    source,
                )
            })?;
            file.sync_all().map_err(|source| {
                CoreError::io(
                    "sync generated MongoDB configuration draft",
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
            operation: "write generated MongoDB configuration draft",
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

fn parse_unit_interval(value: &str) -> CoreResult<u16> {
    let invalid = || {
        CoreError::validation(
            "MongoDB slow-operation sample rate",
            "must be a plain decimal in 0.0..=1.0 with at most four fractional digits",
        )
    };
    if value.is_empty() || value != value.trim() || value.len() > 6 {
        return Err(invalid());
    }
    let (whole, fraction) = match value.split_once('.') {
        Some((whole, fraction)) => {
            if fraction.is_empty() || fraction.len() > 4 || fraction.contains('.') {
                return Err(invalid());
            }
            (whole, fraction)
        }
        None => (value, ""),
    };
    if !matches!(whole, "0" | "1")
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        || (whole == "1" && fraction.bytes().any(|byte| byte != b'0'))
    {
        return Err(invalid());
    }
    if whole == "1" {
        return Ok(10_000);
    }
    let mut padded = fraction.to_owned();
    while padded.len() < 4 {
        padded.push('0');
    }
    if padded.is_empty() {
        Ok(0)
    } else {
        padded.parse::<u16>().map_err(|_| invalid())
    }
}

fn render_unit_interval(value: u16) -> String {
    if value == 0 {
        return "0.0".to_owned();
    }
    if value == 10_000 {
        return "1.0".to_owned();
    }
    let mut fraction = format!("{value:04}");
    while fraction.ends_with('0') {
        fraction.pop();
    }
    format!("0.{fraction}")
}

fn parse_fixed_decimal_thousandths(value: &str, subject: &'static str) -> CoreResult<u64> {
    let invalid = || {
        CoreError::validation(
            subject,
            "must be a non-negative plain decimal with at most three fractional digits",
        )
    };
    if value.is_empty() || value != value.trim() || value.len() > 9 {
        return Err(invalid());
    }
    let (whole, fraction) = match value.split_once('.') {
        Some((whole, fraction)) => {
            if fraction.is_empty() || fraction.len() > 3 || fraction.contains('.') {
                return Err(invalid());
            }
            (whole, fraction)
        }
        None => (value, ""),
    };
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(invalid());
    }
    let whole = whole.parse::<u64>().map_err(|_| invalid())?;
    let mut padded = fraction.to_owned();
    while padded.len() < 3 {
        padded.push('0');
    }
    let fractional = if padded.is_empty() {
        0
    } else {
        padded.parse::<u64>().map_err(|_| invalid())?
    };
    whole
        .checked_mul(1_000)
        .and_then(|value| value.checked_add(fractional))
        .ok_or_else(invalid)
}

fn render_fixed_decimal_thousandths(value: u64) -> String {
    let whole = value / 1_000;
    let mut fraction = format!("{:03}", value % 1_000);
    while fraction.ends_with('0') {
        fraction.pop();
    }
    if fraction.is_empty() {
        format!("{whole}.0")
    } else {
        format!("{whole}.{fraction}")
    }
}

#[derive(Debug, Eq, PartialEq)]
struct MongoDbYamlSubset {
    containers: BTreeSet<String>,
    values: BTreeMap<String, String>,
}

impl MongoDbYamlSubset {
    fn parse(contents: &str) -> CoreResult<Self> {
        if contents.is_empty()
            || contents.len() > MAX_GENERATED_MONGODB_CONFIG_BYTES
            || contents.contains('\0')
            || contents.contains('\r')
            || !contents.ends_with('\n')
        {
            return Err(CoreError::validation(
                "MongoDB YAML subset",
                format!(
                    "must be non-empty LF-only UTF-8 with a terminal newline and at most {MAX_GENERATED_MONGODB_CONFIG_BYTES} bytes"
                ),
            ));
        }

        let mut parents = Vec::<String>::new();
        let mut seen_paths = BTreeSet::<String>::new();
        let mut containers = BTreeSet::<String>::new();
        let mut values = BTreeMap::<String, String>::new();

        for (line_index, line) in contents.lines().enumerate() {
            let line_number = line_index + 1;
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.trim_start().starts_with('#') {
                return Err(yaml_line_error(
                    line_number,
                    "comments must begin in column one",
                ));
            }
            if line.contains('\t') || line != line.trim_end() {
                return Err(yaml_line_error(
                    line_number,
                    "tabs and trailing whitespace are forbidden",
                ));
            }
            let indent = line.bytes().take_while(|byte| *byte == b' ').count();
            if indent % 2 != 0 || indent > 6 {
                return Err(yaml_line_error(
                    line_number,
                    "indentation must use exactly two spaces per level with depth at most three",
                ));
            }
            let level = indent / 2;
            if level > parents.len() {
                return Err(yaml_line_error(
                    line_number,
                    "indentation may descend only below the immediately preceding mapping",
                ));
            }
            parents.truncate(level);

            let body = &line[indent..];
            if body.matches(':').count() != 1 {
                return Err(yaml_line_error(
                    line_number,
                    "each mapping line must contain exactly one colon",
                ));
            }
            let (key, remainder) = body
                .split_once(':')
                .ok_or_else(|| yaml_line_error(line_number, "mapping line is missing its colon"))?;
            if key.is_empty()
                || !key.bytes().enumerate().all(|(index, byte)| {
                    byte.is_ascii_alphabetic() || (index > 0 && byte.is_ascii_digit())
                })
            {
                return Err(yaml_line_error(
                    line_number,
                    "keys must be non-empty ASCII alphanumeric names beginning with a letter",
                ));
            }

            let mut path_components = parents.clone();
            path_components.push(key.to_owned());
            let path = path_components.join(".");
            if !seen_paths.insert(path.clone()) {
                return Err(yaml_line_error(
                    line_number,
                    format!("duplicate mapping path {path}"),
                ));
            }

            if remainder.is_empty() {
                if level == 3 {
                    return Err(yaml_line_error(
                        line_number,
                        "a mapping at maximum depth cannot contain reviewed leaves",
                    ));
                }
                containers.insert(path);
                parents.push(key.to_owned());
                continue;
            }

            let value = remainder.strip_prefix(' ').ok_or_else(|| {
                yaml_line_error(
                    line_number,
                    "a scalar must follow the colon with exactly one space",
                )
            })?;
            if value.is_empty()
                || value.starts_with(' ')
                || !value.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/' | b'_' | b'-')
                })
            {
                return Err(yaml_line_error(
                    line_number,
                    "only reviewed non-empty bare ASCII scalars are accepted; quoting, comments, collections, tags, anchors, aliases and multiline syntax are forbidden",
                ));
            }
            values.insert(path, value.to_owned());
        }

        for container in &containers {
            let prefix = format!("{container}.");
            if !values.keys().any(|path| path.starts_with(&prefix)) {
                return Err(CoreError::validation(
                    "MongoDB YAML subset",
                    format!("mapping {container} must not be empty"),
                ));
            }
        }
        if values.is_empty() {
            return Err(CoreError::validation(
                "MongoDB YAML subset",
                "must contain at least one reviewed scalar",
            ));
        }
        Ok(Self { containers, values })
    }
}

fn yaml_line_error(line_number: usize, message: impl Into<String>) -> CoreError {
    CoreError::validation(
        "MongoDB YAML subset",
        format!("line {line_number}: {}", message.into()),
    )
}

fn validate_generated_document(contents: &str, version: MongoDbVersion) -> CoreResult<()> {
    let required_header = format!(
        "# LovelyHawk MongoDB {} new local standalone mongod.conf draft\n# NEW EMPTY LOCAL STANDALONE ONLY — DO NOT APPLY TO AN EXISTING OR DATA-BEARING DEPLOYMENT.\n",
        version.label()
    );
    if !contents.starts_with(&required_header) {
        return Err(CoreError::validation(
            "generated MongoDB configuration draft",
            "must retain the matching series and prominent new-empty-local-standalone-only warning",
        ));
    }

    let document = MongoDbYamlSubset::parse(contents).map_err(|error| {
        CoreError::validation("generated MongoDB configuration draft", error.to_string())
    })?;

    const ALLOWED_CONTAINERS: &[&str] = &[
        "net",
        "security",
        "operationProfiling",
        "systemLog",
        "storage",
        "storage.wiredTiger",
        "storage.wiredTiger.engineConfig",
        "storage.wiredTiger.collectionConfig",
    ];
    const ALLOWED_VALUES: &[&str] = &[
        "net.bindIp",
        "net.port",
        "net.maxIncomingConnections",
        "security.authorization",
        "security.javascriptEnabled",
        "operationProfiling.mode",
        "operationProfiling.slowOpThresholdMs",
        "operationProfiling.slowOpSampleRate",
        "operationProfiling.slowOpInProgressThresholdMs",
        "systemLog.destination",
        "systemLog.path",
        "systemLog.logAppend",
        "systemLog.logRotate",
        "systemLog.timeStampFormat",
        "storage.engine",
        "storage.wiredTiger.engineConfig.cacheSizeGB",
        "storage.wiredTiger.engineConfig.journalCompressor",
        "storage.wiredTiger.collectionConfig.blockCompressor",
    ];

    for container in &document.containers {
        if !ALLOWED_CONTAINERS.contains(&container.as_str()) {
            return Err(CoreError::validation(
                "generated MongoDB configuration draft",
                format!("mapping {container} is outside the closed generator allowlist"),
            ));
        }
    }
    for path in document.values.keys() {
        if !ALLOWED_VALUES.contains(&path.as_str()) {
            return Err(CoreError::validation(
                "generated MongoDB configuration draft",
                format!("setting {path} is outside the closed generator allowlist"),
            ));
        }
    }

    let required = |path: &str| -> CoreResult<&str> {
        document
            .values
            .get(path)
            .map(String::as_str)
            .ok_or_else(|| {
                CoreError::validation(
                    "generated MongoDB configuration draft",
                    format!("required baseline setting {path} is missing"),
                )
            })
    };

    for (path, expected) in [
        ("net.bindIp", "127.0.0.1"),
        ("security.authorization", "enabled"),
        ("security.javascriptEnabled", "false"),
        ("storage.engine", "wiredTiger"),
    ] {
        if required(path)? != expected {
            return Err(CoreError::validation(
                "generated MongoDB configuration draft",
                format!("baseline setting {path} must remain {expected}"),
            ));
        }
    }
    MongoDbPort::parse(required("net.port")?)?;

    if let Some(value) = document.values.get("net.maxIncomingConnections") {
        MongoDbConnectionLimit::parse(value)?;
    }

    if document
        .values
        .get("operationProfiling.mode")
        .is_some_and(|value| value != "slowOp")
    {
        return Err(CoreError::validation(
            "generated MongoDB configuration draft",
            "operationProfiling.mode must be the closed value slowOp; mode all and filters are forbidden",
        ));
    }
    match (
        document.values.get("operationProfiling.slowOpThresholdMs"),
        document.values.get("operationProfiling.slowOpSampleRate"),
    ) {
        (None, None) => {}
        (Some(threshold), Some(sample_rate)) => {
            MongoDbSlowOperationSettings::parse(threshold, sample_rate)?;
        }
        _ => {
            return Err(CoreError::validation(
                "generated MongoDB configuration draft",
                "slowOpThresholdMs and slowOpSampleRate must be emitted as one typed feature group",
            ));
        }
    }
    if let Some(value) = document
        .values
        .get("operationProfiling.slowOpInProgressThresholdMs")
    {
        if !version.supports_slow_in_progress_threshold() {
            return Err(CoreError::validation(
                "generated MongoDB configuration draft",
                format!(
                    "slowOpInProgressThresholdMs is unavailable in MongoDB {}",
                    version.label()
                ),
            ));
        }
        MongoDbSlowInProgressThreshold::parse(value)?;
    }

    let system_log_paths = [
        "systemLog.destination",
        "systemLog.path",
        "systemLog.logAppend",
        "systemLog.logRotate",
        "systemLog.timeStampFormat",
    ];
    let present_system_log_values = system_log_paths
        .iter()
        .filter(|path| document.values.contains_key(**path))
        .count();
    if present_system_log_values != 0 {
        if present_system_log_values != system_log_paths.len() {
            return Err(CoreError::validation(
                "generated MongoDB configuration draft",
                "file logging must contain destination, path, logAppend, logRotate, and timeStampFormat as one closed group",
            ));
        }
        if required("systemLog.destination")? != "file"
            || required("systemLog.logAppend")? != "true"
            || required("systemLog.timeStampFormat")? != "iso8601-utc"
        {
            return Err(CoreError::validation(
                "generated MongoDB configuration draft",
                "file logging must retain destination=file, logAppend=true, and timeStampFormat=iso8601-utc",
            ));
        }
        MongoDbLogPath::parse(required("systemLog.path")?)?;
        MongoDbLogRotationMode::parse(required("systemLog.logRotate")?)?;
    }

    if let Some(value) = document
        .values
        .get("storage.wiredTiger.engineConfig.cacheSizeGB")
    {
        MongoDbWiredTigerCacheSize::parse_gigabytes(value)?;
    }
    match (
        document
            .values
            .get("storage.wiredTiger.engineConfig.journalCompressor"),
        document
            .values
            .get("storage.wiredTiger.collectionConfig.blockCompressor"),
    ) {
        (None, None) => {}
        (Some(journal), Some(collection)) => {
            MongoDbCompressor::parse(journal)?;
            MongoDbCompressor::parse(collection)?;
        }
        _ => {
            return Err(CoreError::validation(
                "generated MongoDB configuration draft",
                "journalCompressor and blockCompressor must be emitted as one closed compression group",
            ));
        }
    }
    Ok(())
}

fn validate_export_destination(destination: &Path) -> CoreResult<()> {
    if !destination.is_absolute() {
        return Err(CoreError::validation(
            "generated MongoDB configuration destination",
            "must be an absolute path selected by the native save dialog",
        ));
    }
    if destination
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(CoreError::validation(
            "generated MongoDB configuration destination",
            "must not contain current-directory or parent-directory components",
        ));
    }
    if !destination
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("conf"))
    {
        return Err(CoreError::validation(
            "generated MongoDB configuration destination",
            "must use the .conf extension",
        ));
    }
    let parent = destination.parent().ok_or_else(|| {
        CoreError::validation(
            "generated MongoDB configuration destination",
            "path has no parent directory",
        )
    })?;
    if !parent.is_dir() {
        return Err(CoreError::validation(
            "generated MongoDB configuration destination",
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
                std::env::temp_dir().join(format!("lovelyres-mongodb-config-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn parsed(contents: &str) -> MongoDbYamlSubset {
        MongoDbYamlSubset::parse(contents).unwrap()
    }

    #[test]
    fn supported_versions_follow_the_current_official_lifecycle() {
        assert_eq!(
            MongoDbVersion::ALL
                .into_iter()
                .map(MongoDbVersion::label)
                .collect::<Vec<_>>(),
            ["7.0", "8.0", "8.3"]
        );
        for version in MongoDbVersion::ALL {
            assert_eq!(MongoDbVersion::parse(version.label()).unwrap(), version);
            assert_eq!(
                MongoDbVersion::try_from((version.major(), version.minor())).unwrap(),
                version
            );
            assert!(
                version
                    .official_documentation()
                    .starts_with("https://www.mongodb.com/")
            );
            assert!(!version.support_notice().is_empty());
            assert!(!version.risk().is_empty());
        }
        assert!(MongoDbVersion::V7_0.support_notice().contains("2027-08-31"));
        assert!(MongoDbVersion::V8_0.support_notice().contains("2029-10-31"));
        assert!(MongoDbVersion::V8_3.support_notice().contains("2029-10-31"));
        for unsupported in [
            "", "6.0", "7", "7.1", "8.1", "8.2", "8.4", " 8.3", "8.3 ", "8.3.0",
        ] {
            assert!(
                MongoDbVersion::parse(unsupported).is_err(),
                "{unsupported:?}"
            );
        }
        for unsupported in [(0, 0), (6, 0), (7, 1), (8, 1), (8, 2), (8, 4)] {
            assert!(MongoDbVersion::try_from(unsupported).is_err());
        }
    }

    #[test]
    fn feature_metadata_is_unique_searchable_and_version_explicit() {
        let keys = MongoDbConfigFeature::ALL
            .into_iter()
            .map(MongoDbConfigFeature::key)
            .collect::<HashSet<_>>();
        assert_eq!(keys.len(), MongoDbConfigFeature::ALL.len());
        for feature in MongoDbConfigFeature::ALL {
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
                    .starts_with("https://www.mongodb.com/")
            );
        }
        assert!(
            !MongoDbConfigFeature::SlowInProgressLogging.supports_version(MongoDbVersion::V7_0)
        );
        assert!(
            !MongoDbConfigFeature::SlowInProgressLogging.supports_version(MongoDbVersion::V8_0)
        );
        assert!(MongoDbConfigFeature::SlowInProgressLogging.supports_version(MongoDbVersion::V8_3));
        assert!(MongoDbConfigFeature::ALL.into_iter().all(|feature| {
            feature == MongoDbConfigFeature::SlowInProgressLogging
                || MongoDbVersion::ALL
                    .into_iter()
                    .all(|version| feature.supports_version(version))
        }));
        assert!(
            MONGODB_OFFICIAL_REFERENCES
                .iter()
                .all(|reference| reference.starts_with("https://www.mongodb.com/"))
        );
    }

    #[test]
    fn baseline_is_loopback_authorized_standalone_and_closed() {
        let expected_values = BTreeSet::from([
            "net.bindIp".to_owned(),
            "net.port".to_owned(),
            "security.authorization".to_owned(),
            "security.javascriptEnabled".to_owned(),
            "storage.engine".to_owned(),
        ]);
        let expected_containers = BTreeSet::from([
            "net".to_owned(),
            "security".to_owned(),
            "storage".to_owned(),
        ]);

        for version in MongoDbVersion::ALL {
            let config = MongoDbConfig::baseline(version);
            assert!(config.features().is_empty());
            let generated = config.generate().unwrap();
            assert_eq!(generated.version(), version);
            assert_eq!(
                generated.suggested_file_name(),
                format!(
                    "lovelyres-mongodb-{}-new-local-standalone-mongod.conf",
                    version.label()
                )
            );
            let document = parsed(generated.contents());
            assert_eq!(
                document.values.keys().cloned().collect::<BTreeSet<_>>(),
                expected_values
            );
            assert_eq!(document.containers, expected_containers);
            assert_eq!(document.values["net.bindIp"], "127.0.0.1");
            assert_eq!(document.values["net.port"], "27017");
            assert_eq!(document.values["security.authorization"], "enabled");
            assert_eq!(document.values["security.javascriptEnabled"], "false");
            assert_eq!(document.values["storage.engine"], "wiredTiger");
            assert!(
                generated
                    .contents()
                    .contains("NEW EMPTY LOCAL STANDALONE ONLY")
            );
            assert!(generated.contents().contains("INCOMPLETE LOCAL FILE ONLY"));
            assert!(generated.contents().contains("does not deploy, overwrite"));
            assert!(
                generated
                    .contents()
                    .contains("No dbPath or default log path is guessed")
            );
            assert!(generated.contents().contains("DEFERRED/UNAVAILABLE:"));
            assert!(generated.contents().len() <= MAX_GENERATED_MONGODB_CONFIG_BYTES);
            validate_generated_document(generated.contents(), version).unwrap();
        }
    }

    #[test]
    fn integer_typed_values_reject_bounds_whitespace_and_injection() {
        assert_eq!(MongoDbPort::parse("1").unwrap().get(), 1);
        assert_eq!(MongoDbPort::parse("65535").unwrap().get(), 65_535);
        for invalid in ["", "0", "65536", " 27017", "+27017", "27017\nnet:"] {
            assert!(MongoDbPort::parse(invalid).is_err(), "{invalid:?}");
        }

        assert_eq!(MongoDbConnectionLimit::parse("1").unwrap().get(), 1);
        assert_eq!(
            MongoDbConnectionLimit::parse("1000000").unwrap().get(),
            1_000_000
        );
        for invalid in [
            "0",
            "1000001",
            "1e3",
            "1000 # comment",
            "1000\n  bindIpAll: true",
        ] {
            assert!(
                MongoDbConnectionLimit::parse(invalid).is_err(),
                "{invalid:?}"
            );
        }

        assert_eq!(
            MongoDbSlowInProgressThreshold::parse("5000")
                .unwrap()
                .milliseconds(),
            5_000
        );
        for invalid in ["0", "86400001", "5000ms", "5000\nmode: all"] {
            assert!(MongoDbSlowInProgressThreshold::parse(invalid).is_err());
        }
    }

    #[test]
    fn fixed_decimal_values_are_bounded_and_render_deterministically() {
        for (text, expected, rendered) in [
            ("0.256", 256, "0.256"),
            ("0.5", 500, "0.5"),
            ("1", 1_000, "1.0"),
            ("12.340", 12_340, "12.34"),
            ("10000", 10_000_000, "10000.0"),
        ] {
            let parsed = MongoDbWiredTigerCacheSize::parse_gigabytes(text).unwrap();
            assert_eq!(parsed.thousandths_of_gigabyte(), expected);
            assert_eq!(parsed.rendered_gigabytes(), rendered);
        }
        for invalid in [
            "",
            "0.255",
            "10000.001",
            "1.0000",
            " 1.0",
            "+1.0",
            "NaN",
            "1e3",
            "1.0\nsecurity:",
        ] {
            assert!(
                MongoDbWiredTigerCacheSize::parse_gigabytes(invalid).is_err(),
                "{invalid:?}"
            );
        }

        for (text, expected, rendered) in [
            ("0", 0, "0.0"),
            ("0.0001", 1, "0.0001"),
            ("0.1", 1_000, "0.1"),
            ("0.2500", 2_500, "0.25"),
            ("1", 10_000, "1.0"),
            ("1.0000", 10_000, "1.0"),
        ] {
            let settings = MongoDbSlowOperationSettings::parse("100", text).unwrap();
            assert_eq!(settings.sample_rate_ten_thousandths(), expected);
            assert_eq!(settings.rendered_sample_rate(), rendered);
        }
        for invalid in [
            "", ".5", "00.5", "1.0001", "0.00001", "-0.1", "NaN", "0.5 #",
        ] {
            assert!(
                MongoDbSlowOperationSettings::parse("100", invalid).is_err(),
                "{invalid:?}"
            );
        }
        assert!(MongoDbSlowOperationSettings::new(100, 10_001).is_err());
        assert!(MongoDbSlowOperationSettings::parse("0", "1.0").is_err());
    }

    #[test]
    fn log_path_and_closed_enums_reject_yaml_and_path_injection() {
        let path = MongoDbLogPath::parse("/var/log/mongodb/mongod-1.log").unwrap();
        assert_eq!(path.as_str(), "/var/log/mongodb/mongod-1.log");
        for invalid in [
            "",
            "relative/mongod.log",
            "/var/log/mongodb/",
            "/var//mongodb/mongod.log",
            "/var/./mongodb/mongod.log",
            "/var/../mongodb/mongod.log",
            "/var/log/mongod.txt",
            "/var/log/mongo db.log",
            "/var/log/mongod.log # injected",
            "/var/log/mongod.log\nsecurity:",
            "C:\\MongoDB\\mongod.log",
            "//server/share/mongod.log",
        ] {
            assert!(MongoDbLogPath::parse(invalid).is_err(), "{invalid:?}");
        }
        for compressor in MongoDbCompressor::ALL {
            assert_eq!(
                MongoDbCompressor::parse(compressor.as_str()).unwrap(),
                compressor
            );
        }
        for invalid in ["", "lz4", "SNAPPY", "zstd #", "zstd\nsecurity:"] {
            assert!(MongoDbCompressor::parse(invalid).is_err());
        }
        assert_eq!(
            MongoDbLogRotationMode::parse("rename").unwrap(),
            MongoDbLogRotationMode::Rename
        );
        assert_eq!(
            MongoDbLogRotationMode::parse("reopen").unwrap(),
            MongoDbLogRotationMode::Reopen
        );
        assert!(MongoDbLogRotationMode::parse("truncate").is_err());
    }

    #[test]
    fn slow_in_progress_setting_obeys_the_8_3_boundary() {
        for version in [MongoDbVersion::V7_0, MongoDbVersion::V8_0] {
            assert!(
                MongoDbConfig::baseline(version)
                    .with_slow_in_progress_logging(
                        MongoDbSlowInProgressThreshold::parse("5000").unwrap()
                    )
                    .is_err()
            );
            assert!(
                MongoDbConfig::baseline(version)
                    .with_feature(MongoDbConfigFeature::SlowInProgressLogging, true)
                    .is_err()
            );
        }

        let generated = MongoDbConfig::baseline(MongoDbVersion::V8_3)
            .with_slow_in_progress_logging(MongoDbSlowInProgressThreshold::parse("2500").unwrap())
            .unwrap()
            .generate()
            .unwrap();
        assert!(
            generated
                .contents()
                .contains("slowOpInProgressThresholdMs: 2500\n")
        );

        let wrong_version = generated.contents().replace("MongoDB 8.3", "MongoDB 8.0");
        assert!(validate_generated_document(&wrong_version, MongoDbVersion::V8_0).is_err());
    }

    #[test]
    fn parameterized_features_require_explicit_typed_values() {
        for feature in [
            MongoDbConfigFeature::LogRotation,
            MongoDbConfigFeature::WiredTigerCache,
            MongoDbConfigFeature::WiredTigerCompression,
        ] {
            assert!(
                MongoDbConfig::baseline(MongoDbVersion::V8_3)
                    .with_feature(feature, true)
                    .is_err(),
                "{feature:?}"
            );
        }
        for feature in [
            MongoDbConfigFeature::ConnectionLimit,
            MongoDbConfigFeature::SlowOperationLogging,
            MongoDbConfigFeature::OperationProfiler,
            MongoDbConfigFeature::SlowInProgressLogging,
        ] {
            assert!(
                MongoDbConfig::baseline(MongoDbVersion::V8_3)
                    .with_feature(feature, true)
                    .is_ok(),
                "{feature:?}"
            );
        }
    }

    fn full_config_in_forward_order() -> MongoDbConfig {
        MongoDbConfig::baseline(MongoDbVersion::V8_3)
            .with_connection_limit(MongoDbConnectionLimit::parse("2500").unwrap())
            .unwrap()
            .with_slow_operation_logging(
                MongoDbSlowOperationSettings::parse("250", "0.25").unwrap(),
            )
            .unwrap()
            .with_feature(MongoDbConfigFeature::OperationProfiler, true)
            .unwrap()
            .with_slow_in_progress_logging(MongoDbSlowInProgressThreshold::parse("7500").unwrap())
            .unwrap()
            .with_log_rotation(MongoDbLogRotation::new(
                MongoDbLogPath::parse("/srv/mongodb/log/mongod.log").unwrap(),
                MongoDbLogRotationMode::Reopen,
            ))
            .unwrap()
            .with_wired_tiger_cache(MongoDbWiredTigerCacheSize::parse_gigabytes("2.5").unwrap())
            .unwrap()
            .with_compression(MongoDbCompression::new(
                MongoDbCompressor::Zstd,
                MongoDbCompressor::Snappy,
            ))
            .unwrap()
    }

    fn full_config_in_reverse_order() -> MongoDbConfig {
        MongoDbConfig::baseline(MongoDbVersion::V8_3)
            .with_compression(MongoDbCompression::new(
                MongoDbCompressor::Zstd,
                MongoDbCompressor::Snappy,
            ))
            .unwrap()
            .with_wired_tiger_cache(MongoDbWiredTigerCacheSize::parse_gigabytes("2.5").unwrap())
            .unwrap()
            .with_log_rotation(MongoDbLogRotation::new(
                MongoDbLogPath::parse("/srv/mongodb/log/mongod.log").unwrap(),
                MongoDbLogRotationMode::Reopen,
            ))
            .unwrap()
            .with_slow_in_progress_logging(MongoDbSlowInProgressThreshold::parse("7500").unwrap())
            .unwrap()
            .with_feature(MongoDbConfigFeature::OperationProfiler, true)
            .unwrap()
            .with_slow_operation_logging(
                MongoDbSlowOperationSettings::parse("250", "0.25").unwrap(),
            )
            .unwrap()
            .with_connection_limit(MongoDbConnectionLimit::parse("2500").unwrap())
            .unwrap()
    }

    #[test]
    fn features_stack_deterministically_remove_independently_and_reset() {
        let first = full_config_in_forward_order();
        let second = full_config_in_reverse_order();
        assert_eq!(
            first.generate().unwrap().contents(),
            second.generate().unwrap().contents()
        );

        let removed_logging = first
            .clone()
            .with_feature(MongoDbConfigFeature::SlowOperationLogging, false)
            .unwrap()
            .generate()
            .unwrap();
        let document = parsed(removed_logging.contents());
        assert!(
            !document
                .values
                .contains_key("operationProfiling.slowOpThresholdMs")
        );
        assert!(
            !document
                .values
                .contains_key("operationProfiling.slowOpSampleRate")
        );
        assert_eq!(document.values["operationProfiling.mode"], "slowOp");
        assert_eq!(
            document.values["operationProfiling.slowOpInProgressThresholdMs"],
            "7500"
        );
        assert!(document.values.contains_key("systemLog.path"));
        assert!(
            document
                .values
                .contains_key("storage.wiredTiger.engineConfig.cacheSizeGB")
        );

        let removed_rotation = first
            .clone()
            .with_feature(MongoDbConfigFeature::LogRotation, false)
            .unwrap()
            .generate()
            .unwrap();
        assert!(
            parsed(removed_rotation.contents())
                .values
                .keys()
                .all(|path| !path.starts_with("systemLog."))
        );

        let mut reset = first;
        reset.reset_to_baseline();
        assert_eq!(reset, MongoDbConfig::baseline(MongoDbVersion::V8_3));
        assert_eq!(
            reset.generate().unwrap().contents(),
            MongoDbConfig::baseline(MongoDbVersion::V8_3)
                .generate()
                .unwrap()
                .contents()
        );
    }

    #[test]
    fn every_optional_feature_emits_one_closed_composable_tree() {
        let generated = full_config_in_forward_order().generate().unwrap();
        let document = parsed(generated.contents());
        for (path, expected) in [
            ("net.maxIncomingConnections", "2500"),
            ("operationProfiling.mode", "slowOp"),
            ("operationProfiling.slowOpThresholdMs", "250"),
            ("operationProfiling.slowOpSampleRate", "0.25"),
            ("operationProfiling.slowOpInProgressThresholdMs", "7500"),
            ("systemLog.destination", "file"),
            ("systemLog.path", "/srv/mongodb/log/mongod.log"),
            ("systemLog.logAppend", "true"),
            ("systemLog.logRotate", "reopen"),
            ("systemLog.timeStampFormat", "iso8601-utc"),
            ("storage.wiredTiger.engineConfig.cacheSizeGB", "2.5"),
            (
                "storage.wiredTiger.engineConfig.journalCompressor",
                "snappy",
            ),
            (
                "storage.wiredTiger.collectionConfig.blockCompressor",
                "zstd",
            ),
        ] {
            assert_eq!(document.values[path], expected, "{path}");
        }
        assert_eq!(
            generated
                .contents()
                .matches("operationProfiling:\n")
                .count(),
            1
        );
        assert_eq!(generated.contents().matches("storage:\n").count(), 1);
        assert_eq!(generated.contents().matches("  wiredTiger:\n").count(), 1);
        validate_generated_document(generated.contents(), MongoDbVersion::V8_3).unwrap();
    }

    #[test]
    fn strict_yaml_subset_rejects_yaml_features_and_malformed_indentation() {
        let cases = [
            "net:\n\tport: 27017\n",
            "net:\n port: 27017\n",
            "net:\n    port: 27017\n",
            " net:\n  port: 27017\n",
            "net: &defaults\n  port: 27017\n",
            "net: *defaults\n",
            "net: !tag value\n",
            "net: { port: 27017 }\n",
            "net:\n  bindIp: [127.0.0.1]\n",
            "net:\n  bindIp: \"127.0.0.1\"\n",
            "net:\n  bindIp: 127.0.0.1 # comment\n",
            "net:\n  value: |\n    text: bad\n",
            "---\nnet:\n  port: 27017\n",
            "%YAML 1.2\nnet:\n  port: 27017\n",
            "net:\n  port: 27017 \n",
            "net:\n",
            "# comment only\n",
            "net:\n  port: 27017\nnet:\n  bindIp: 127.0.0.1\n",
            "net:\n  port: 27017\n  port: 27018\n",
            "  # indented comment\nnet:\n  port: 27017\n",
        ];
        for contents in cases {
            assert!(MongoDbYamlSubset::parse(contents).is_err(), "{contents:?}");
        }
        assert!(MongoDbYamlSubset::parse("net:\r\n  port: 27017\r\n").is_err());
        assert!(MongoDbYamlSubset::parse("net:\n  port: 27017\0\n").is_err());
        assert!(MongoDbYamlSubset::parse("net:\n  port: 27017").is_err());
    }

    #[test]
    fn generated_validator_rejects_unknown_duplicate_remote_and_unsafe_values() {
        let baseline = MongoDbConfig::baseline(MongoDbVersion::V8_3)
            .generate()
            .unwrap();

        let unknown = baseline
            .contents()
            .replace("  port: 27017\n", "  port: 27017\n  bindIpAll: true\n");
        assert!(validate_generated_document(&unknown, MongoDbVersion::V8_3).is_err());

        let duplicate = baseline
            .contents()
            .replace("  port: 27017\n", "  port: 27017\n  port: 27018\n");
        assert!(validate_generated_document(&duplicate, MongoDbVersion::V8_3).is_err());

        let remote = baseline.contents().replace("127.0.0.1", "0.0.0.0");
        assert!(validate_generated_document(&remote, MongoDbVersion::V8_3).is_err());

        let disabled_auth = baseline
            .contents()
            .replace("authorization: enabled", "authorization: disabled");
        assert!(validate_generated_document(&disabled_auth, MongoDbVersion::V8_3).is_err());

        let javascript = baseline
            .contents()
            .replace("javascriptEnabled: false", "javascriptEnabled: true");
        assert!(validate_generated_document(&javascript, MongoDbVersion::V8_3).is_err());

        let injected_tls = baseline.contents().replace(
            "  bindIp: 127.0.0.1\n",
            "  bindIp: 127.0.0.1\n  tls:\n    mode: requireTLS\n",
        );
        assert!(validate_generated_document(&injected_tls, MongoDbVersion::V8_3).is_err());

        let injected_audit = format!("{}auditLog:\n  destination: console\n", baseline.contents());
        assert!(validate_generated_document(&injected_audit, MongoDbVersion::V8_3).is_err());

        let injected_replication =
            format!("{}replication:\n  replSetName: rs0\n", baseline.contents());
        assert!(validate_generated_document(&injected_replication, MongoDbVersion::V8_3).is_err());
    }

    #[test]
    fn validator_rejects_partial_feature_groups_and_unreviewed_profiler_modes() {
        let full = full_config_in_forward_order().generate().unwrap();

        let missing_sample = full.contents().replace("  slowOpSampleRate: 0.25\n", "");
        assert!(validate_generated_document(&missing_sample, MongoDbVersion::V8_3).is_err());

        let all_profiler = full.contents().replace("mode: slowOp", "mode: all");
        assert!(validate_generated_document(&all_profiler, MongoDbVersion::V8_3).is_err());

        let missing_log_append = full.contents().replace("  logAppend: true\n", "");
        assert!(validate_generated_document(&missing_log_append, MongoDbVersion::V8_3).is_err());

        let bad_log_path = full
            .contents()
            .replace("/srv/mongodb/log/mongod.log", "relative.log");
        assert!(validate_generated_document(&bad_log_path, MongoDbVersion::V8_3).is_err());

        let missing_collection_compressor = full
            .contents()
            .replace("    collectionConfig:\n      blockCompressor: zstd\n", "");
        assert!(
            validate_generated_document(&missing_collection_compressor, MongoDbVersion::V8_3)
                .is_err()
        );

        let bad_cache = full
            .contents()
            .replace("cacheSizeGB: 2.5", "cacheSizeGB: 0.1");
        assert!(validate_generated_document(&bad_cache, MongoDbVersion::V8_3).is_err());
    }

    #[test]
    fn write_new_round_trips_and_never_overwrites() {
        let root = TestRoot::new();
        let generated = full_config_in_forward_order().generate().unwrap();
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
        assert!(generated.write_new(&root.0.join("mongod.yaml")).is_err());
        assert!(
            generated
                .write_new(&root.0.join("missing").join("mongod.conf"))
                .is_err()
        );
    }

    #[test]
    fn cleanup_failure_reports_the_possible_partial_file_exactly() {
        let destination = PathBuf::from("C:\\tmp\\lovelyres-mongodb-partial.conf");
        let write_error = CoreError::validation(
            "generated MongoDB configuration write",
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
    fn debug_output_does_not_expose_generated_contents_or_log_path() {
        let generated = full_config_in_forward_order().generate().unwrap();
        let debug = format!("{generated:?}");
        assert!(debug.contains("bytes"));
        assert!(!debug.contains("authorization"));
        assert!(!debug.contains("/srv/mongodb"));
        assert!(!debug.contains("slowOp"));
    }

    #[test]
    fn deferred_boundaries_are_explicit_and_forbidden_from_output() {
        for reason in [
            MONGODB_AUTHENTICATION_DEFERRED_REASON,
            MONGODB_TLS_DEFERRED_REASON,
            MONGODB_ENTERPRISE_DEFERRED_REASON,
            MONGODB_REPLICA_SET_DEFERRED_REASON,
            MONGODB_REMOTE_LISTENING_DEFERRED_REASON,
            MONGODB_EXISTING_DEPLOYMENT_DEFERRED_REASON,
            MONGODB_PATH_AND_SERVICE_DEFERRED_REASON,
        ] {
            assert!(!reason.is_empty());
        }

        let generated = full_config_in_forward_order().generate().unwrap();
        let document = parsed(generated.contents());
        for forbidden_prefix in [
            "net.tls",
            "security.keyFile",
            "security.redactClientLogData",
            "auditLog",
            "replication",
            "sharding",
            "storage.dbPath",
            "processManagement",
        ] {
            assert!(
                document
                    .values
                    .keys()
                    .all(|path| !path.starts_with(forbidden_prefix)),
                "{forbidden_prefix}"
            );
        }
        for forbidden_text in [
            "certificateKeyFile:",
            "keyFile:",
            "replSetName:",
            "bindIpAll:",
            "0.0.0.0",
            "--config",
            "systemctl",
            "mongod --",
        ] {
            assert!(
                !generated.contents().contains(forbidden_text),
                "{forbidden_text}"
            );
        }
    }
}
