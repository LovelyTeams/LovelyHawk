//! Deterministic generation of bounded Redis Open Source `redis.conf` drafts
//! for new, empty standalone instances.
//!
//! The first version deliberately supports only the Redis 6.2, 7.2, 7.4,
//! 8.0, 8.2, 8.4, 8.6, 8.8, and 8.10 configuration lines documented by the Redis
//! project. Every emitted directive is selected from a closed enum or crosses
//! a typed numeric boundary. Authentication, ACLs, TLS, replication, Cluster,
//! Sentinel, modules, arbitrary directives, and non-loopback network exposure
//! remain outside this generator until their secret and runtime-capability
//! contracts are implemented. These drafts must never be applied as a static
//! AOF/RDB migration for an existing data-bearing instance.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Component, Path, PathBuf},
};

use crate::{
    CoreError, CoreResult,
    middleware_document::{
        MiddlewareDocument, MiddlewareDocumentNodeKind, MiddlewareDocumentSyntax,
    },
    sftp::RemotePath,
};

pub const MAX_GENERATED_REDIS_CONFIG_BYTES: usize = 16 * 1024;
pub const REDIS_AUTHENTICATION_ACL_DEFERRED_REASON: &str = "认证口令、ACL 用户和 ACL 文件可能包含秘密；当前生成器没有 core-owned 不回显凭据输入与目标侧验证边界，因此明确不生成 requirepass、masterauth、user 或 aclfile。";
pub const REDIS_REMOTE_BINDING_DEFERRED_REASON: &str = "当前生成器只允许回环地址；在认证/ACL、主机防火墙和真实客户端验证形成闭环前，不生成局域网或全网监听。";
pub const REDIS_EXISTING_INSTANCE_MIGRATION_DEFERRED_REASON: &str = "既有含数据 Redis 实例不能通过静态改写 appendonly/save 安全迁移；必须先检查当前持久化文件与运行状态，在实时实例上按官方转换流程操作，并具备备份、回滚和重启后数据验证。当前模块只生成新建空实例配置。";

const SUGGESTED_FILE_NAME: &str = "redis-new-empty-instance.conf";
const DEFAULT_REDIS_DATA_DIRECTORY: &str = "/var/lib/redis";
const REDIS_RDB_FILE_NAME: &str = "dump.rdb";
const REDIS_AOF_FILE_NAME: &str = "appendonly.aof";
const REDIS_AOF_DIRECTORY_NAME: &str = "appendonlydir";
const DEFAULT_MAXMEMORY_MEBIBYTES: u64 = 512;
const MAX_REDIS_DATA_DIRECTORY_BYTES: usize = 1_024;
const MEBIBYTE_BYTES: u64 = 1024 * 1024;
const MAX_MEMORY_MEBIBYTES: u64 = 16 * 1024 * 1024;
const MAX_CLIENTS: u64 = 1_000_000;
const MAX_IDLE_TIMEOUT_SECONDS: u64 = 31_536_000;
const MAX_TCP_KEEPALIVE_SECONDS: u64 = 86_400;
const MAX_SLOWLOG_THRESHOLD_MICROSECONDS: u64 = 86_400_000_000;
const MAX_SLOWLOG_LENGTH: u64 = 1_000_000;
const MAX_LATENCY_THRESHOLD_MILLISECONDS: u64 = 60_000;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RedisVersion {
    V6_2,
    V7_2,
    V7_4,
    V8_0,
    V8_2,
    V8_4,
    V8_6,
    V8_8,
    V8_10,
}

impl RedisVersion {
    pub const ALL: [Self; 9] = [
        Self::V6_2,
        Self::V7_2,
        Self::V7_4,
        Self::V8_0,
        Self::V8_2,
        Self::V8_4,
        Self::V8_6,
        Self::V8_8,
        Self::V8_10,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::V6_2 => "6.2",
            Self::V7_2 => "7.2",
            Self::V7_4 => "7.4",
            Self::V8_0 => "8.0",
            Self::V8_2 => "8.2",
            Self::V8_4 => "8.4",
            Self::V8_6 => "8.6",
            Self::V8_8 => "8.8",
            Self::V8_10 => "8.10",
        }
    }

    /// Redis 7 and newer store AOF base, incremental, and manifest files in a
    /// dedicated `appenddirname`; Redis 6.2 uses one AOF file directly in `dir`.
    pub const fn uses_multi_part_aof(self) -> bool {
        !matches!(self, Self::V6_2)
    }

    pub fn parse(value: &str) -> CoreResult<Self> {
        match value {
            "6.2" => Ok(Self::V6_2),
            "7.2" => Ok(Self::V7_2),
            "7.4" => Ok(Self::V7_4),
            "8.0" => Ok(Self::V8_0),
            "8.2" => Ok(Self::V8_2),
            "8.4" => Ok(Self::V8_4),
            "8.6" => Ok(Self::V8_6),
            "8.8" => Ok(Self::V8_8),
            "8.10" => Ok(Self::V8_10),
            _ => Err(CoreError::validation(
                "Redis version",
                "must be one explicitly supported minor line: 6.2, 7.2, 7.4, 8.0, 8.2, 8.4, 8.6, 8.8, or 8.10",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RedisConfigFeature {
    MaxClients,
    IdleClientTimeout,
    TcpKeepalive,
    MemoryLimit,
    EvictionPolicy,
    AofPersistence,
    RdbPersistence,
    SlowLog,
    LatencyMonitor,
}

impl RedisConfigFeature {
    pub const ALL: [Self; 9] = [
        Self::MaxClients,
        Self::IdleClientTimeout,
        Self::TcpKeepalive,
        Self::MemoryLimit,
        Self::EvictionPolicy,
        Self::AofPersistence,
        Self::RdbPersistence,
        Self::SlowLog,
        Self::LatencyMonitor,
    ];

    pub const fn key(self) -> &'static str {
        match self {
            Self::MaxClients => "max-clients",
            Self::IdleClientTimeout => "idle-client-timeout",
            Self::TcpKeepalive => "tcp-keepalive",
            Self::MemoryLimit => "memory-limit",
            Self::EvictionPolicy => "eviction-policy",
            Self::AofPersistence => "aof-persistence",
            Self::RdbPersistence => "rdb-persistence",
            Self::SlowLog => "slow-log",
            Self::LatencyMonitor => "latency-monitor",
        }
    }

    pub const fn title(self) -> &'static str {
        match self {
            Self::MaxClients => "限制客户端连接数",
            Self::IdleClientTimeout => "关闭长期空闲客户端",
            Self::TcpKeepalive => "启用 TCP Keepalive",
            Self::MemoryLimit => "设置最大内存",
            Self::EvictionPolicy => "配置内存淘汰策略",
            Self::AofPersistence => "启用 AOF 持久化",
            Self::RdbPersistence => "启用 RDB 快照",
            Self::SlowLog => "记录慢命令",
            Self::LatencyMonitor => "启用延迟事件监控",
        }
    }

    pub const fn summary(self) -> &'static str {
        match self {
            Self::MaxClients => "显式限制普通客户端与内部连接共享的连接预算。",
            Self::IdleClientTimeout => {
                "超过固定空闲秒数后关闭普通客户端连接；订阅等连接仍遵循 Redis 自身语义。"
            }
            Self::TcpKeepalive => "用有界秒数探测失联客户端并维持中间网络设备状态。",
            Self::MemoryLimit => "设置非零 maxmemory；仍需为复制、持久化和系统保留额外内存。",
            Self::EvictionPolicy => "达到 maxmemory 后按闭合策略选择键；必须先设置非零内存上限。",
            Self::AofPersistence => {
                "仅为新建空实例启用 appendonly，并从闭合 fsync 策略中选择持久性与性能权衡。"
            }
            Self::RdbPersistence => {
                "仅为新建空实例使用 Redis 官方示例的三档 save 计划及 RDB 完整性选项。"
            }
            Self::SlowLog => "用类型化微秒阈值和有界队列记录慢命令；不记录命令执行时间之外的 I/O。",
            Self::LatencyMonitor => "记录超过类型化毫秒阈值的 Redis 内部延迟事件。",
        }
    }

    pub const fn scope(self) -> &'static str {
        match self {
            Self::MaxClients | Self::IdleClientTimeout | Self::TcpKeepalive => "连接",
            Self::MemoryLimit | Self::EvictionPolicy => "内存",
            Self::AofPersistence | Self::RdbPersistence => "持久化",
            Self::SlowLog | Self::LatencyMonitor => "可观测性",
        }
    }

    pub const fn default_enabled(self) -> bool {
        matches!(
            self,
            Self::MaxClients
                | Self::TcpKeepalive
                | Self::MemoryLimit
                | Self::AofPersistence
                | Self::RdbPersistence
                | Self::SlowLog
        )
    }

    pub const fn aliases(self) -> &'static [&'static str] {
        match self {
            Self::MaxClients => &["maxclients", "客户端上限", "连接数"],
            Self::IdleClientTimeout => &["timeout", "空闲连接", "idle client"],
            Self::TcpKeepalive => &["tcp-keepalive", "Keepalive", "死连接"],
            Self::MemoryLimit => &["maxmemory", "内存上限", "OOM"],
            Self::EvictionPolicy => &["maxmemory-policy", "淘汰策略", "LRU", "LFU"],
            Self::AofPersistence => &["appendonly", "appendfsync", "AOF"],
            Self::RdbPersistence => &["save", "RDB", "快照"],
            Self::SlowLog => &["slowlog", "慢命令", "慢日志"],
            Self::LatencyMonitor => &["latency-monitor-threshold", "延迟监控", "LATENCY"],
        }
    }

    pub const fn supports_version(self, _version: RedisVersion) -> bool {
        true
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedisBindProfile {
    Ipv4Loopback,
    DualStackLoopback,
}

impl RedisBindProfile {
    pub const ALL: [Self; 2] = [Self::Ipv4Loopback, Self::DualStackLoopback];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Ipv4Loopback => "仅 IPv4 回环",
            Self::DualStackLoopback => "IPv4 回环 + 可选 IPv6 回环",
        }
    }

    const fn directive_value(self) -> &'static str {
        match self {
            Self::Ipv4Loopback => "127.0.0.1",
            Self::DualStackLoopback => "127.0.0.1 -::1",
        }
    }
}

/// An absolute, bounded POSIX directory safe to emit as one unquoted Redis
/// configuration argument.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedisDataDirectory(RemotePath);

impl RedisDataDirectory {
    pub fn parse(value: &str) -> CoreResult<Self> {
        if value.is_empty()
            || value.len() > MAX_REDIS_DATA_DIRECTORY_BYTES
            || value != value.trim()
            || !value.is_ascii()
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-')
            })
        {
            return Err(CoreError::validation(
                "Redis data directory",
                format!(
                    "must be a non-empty absolute POSIX path of at most {MAX_REDIS_DATA_DIRECTORY_BYTES} ASCII bytes using only letters, digits, '/', '.', '_', or '-'"
                ),
            ));
        }
        let path = RemotePath::new(value.to_owned())
            .map_err(|error| CoreError::validation("Redis data directory", error.to_string()))?;
        if path.as_str() == "/" {
            return Err(CoreError::validation(
                "Redis data directory",
                "filesystem root is too broad; select a dedicated Redis data directory",
            ));
        }
        Ok(Self(path))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn as_remote_path(&self) -> &RemotePath {
        &self.0
    }

    fn validate(&self) -> CoreResult<()> {
        let reparsed = Self::parse(self.as_str())?;
        if reparsed != *self {
            return Err(CoreError::validation(
                "Redis data directory",
                "stored path is not canonical",
            ));
        }
        Ok(())
    }
}

impl Default for RedisDataDirectory {
    fn default() -> Self {
        Self::parse(DEFAULT_REDIS_DATA_DIRECTORY)
            .expect("the built-in Redis data directory must remain valid")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RedisPort(u16);

impl RedisPort {
    pub fn parse(value: &str) -> CoreResult<Self> {
        let port = parse_decimal(value, 1, u16::MAX as u64, "Redis TCP port")?;
        Ok(Self(port as u16))
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RedisMaxClients(u32);

impl RedisMaxClients {
    pub fn parse(value: &str) -> CoreResult<Self> {
        let clients = parse_decimal(value, 1, MAX_CLIENTS, "Redis maxclients")?;
        Ok(Self(clients as u32))
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RedisIdleTimeoutSeconds(u32);

impl RedisIdleTimeoutSeconds {
    pub fn parse(value: &str) -> CoreResult<Self> {
        let seconds = parse_decimal(
            value,
            1,
            MAX_IDLE_TIMEOUT_SECONDS,
            "Redis idle client timeout",
        )?;
        Ok(Self(seconds as u32))
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RedisTcpKeepaliveSeconds(u32);

impl RedisTcpKeepaliveSeconds {
    pub fn parse(value: &str) -> CoreResult<Self> {
        let seconds = parse_decimal(value, 1, MAX_TCP_KEEPALIVE_SECONDS, "Redis TCP keepalive")?;
        Ok(Self(seconds as u32))
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RedisMaxmemory {
    mebibytes: u64,
}

impl RedisMaxmemory {
    pub fn parse_mebibytes(value: &str) -> CoreResult<Self> {
        let mebibytes = parse_decimal(value, 1, MAX_MEMORY_MEBIBYTES, "Redis maxmemory MiB")?;
        Ok(Self { mebibytes })
    }

    pub fn from_mebibytes(mebibytes: u64) -> CoreResult<Self> {
        Self::parse_mebibytes(&mebibytes.to_string())
    }

    pub const fn mebibytes(self) -> u64 {
        self.mebibytes
    }

    pub const fn bytes(self) -> u64 {
        self.mebibytes * MEBIBYTE_BYTES
    }

    fn from_bytes(bytes: u64) -> CoreResult<Self> {
        if bytes == 0 || !bytes.is_multiple_of(MEBIBYTE_BYTES) {
            return Err(CoreError::validation(
                "Redis maxmemory",
                "must be a non-zero whole number of MiB",
            ));
        }
        Self::from_mebibytes(bytes / MEBIBYTE_BYTES)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedisEvictionPolicy {
    NoEviction,
    AllKeysLru,
    AllKeysLfu,
    AllKeysRandom,
    VolatileLru,
    VolatileLfu,
    VolatileRandom,
    VolatileTtl,
}

impl RedisEvictionPolicy {
    pub const ALL: [Self; 8] = [
        Self::NoEviction,
        Self::AllKeysLru,
        Self::AllKeysLfu,
        Self::AllKeysRandom,
        Self::VolatileLru,
        Self::VolatileLfu,
        Self::VolatileRandom,
        Self::VolatileTtl,
    ];

    pub const fn directive_value(self) -> &'static str {
        match self {
            Self::NoEviction => "noeviction",
            Self::AllKeysLru => "allkeys-lru",
            Self::AllKeysLfu => "allkeys-lfu",
            Self::AllKeysRandom => "allkeys-random",
            Self::VolatileLru => "volatile-lru",
            Self::VolatileLfu => "volatile-lfu",
            Self::VolatileRandom => "volatile-random",
            Self::VolatileTtl => "volatile-ttl",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::NoEviction => "不淘汰（写入返回错误）",
            Self::AllKeysLru => "所有键：近似 LRU",
            Self::AllKeysLfu => "所有键：近似 LFU",
            Self::AllKeysRandom => "所有键：随机淘汰",
            Self::VolatileLru => "仅有过期时间的键：近似 LRU",
            Self::VolatileLfu => "仅有过期时间的键：近似 LFU",
            Self::VolatileRandom => "仅有过期时间的键：随机淘汰",
            Self::VolatileTtl => "仅有过期时间的键：优先较短 TTL",
        }
    }

    pub const fn summary(self) -> &'static str {
        match self {
            Self::NoEviction => "达到 maxmemory 后保留现有键，不主动删除数据。",
            Self::AllKeysLru => "从全部键中近似淘汰最久未使用的键。",
            Self::AllKeysLfu => "从全部键中近似淘汰访问频率最低的键。",
            Self::AllKeysRandom => "从全部键中随机选择键淘汰。",
            Self::VolatileLru => "仅从设置了过期时间的键中近似淘汰最久未使用的键。",
            Self::VolatileLfu => "仅从设置了过期时间的键中近似淘汰访问频率最低的键。",
            Self::VolatileRandom => "仅从设置了过期时间的键中随机选择键淘汰。",
            Self::VolatileTtl => "仅从设置了过期时间的键中优先淘汰剩余 TTL 较短的键。",
        }
    }

    pub const fn risk(self) -> &'static str {
        match self {
            Self::NoEviction => {
                "达到 maxmemory 后，需要新增内存的写命令会返回 OOM 错误；应用必须处理写入失败。"
            }
            Self::AllKeysLru => "可能淘汰任何键，包括仍有业务价值但近期未访问的键。",
            Self::AllKeysLfu => "可能淘汰任何键；新写入或阶段性低频的重要键也可能被选中。",
            Self::AllKeysRandom => "淘汰对象不可预测，不适合不同键价值差异明显的数据集。",
            Self::VolatileLru | Self::VolatileLfu | Self::VolatileRandom | Self::VolatileTtl => {
                "没有设置过期时间的可淘汰键时，会退化为 noeviction，并让需要新增内存的写命令返回 OOM 错误。"
            }
        }
    }

    pub fn parse(value: &str) -> CoreResult<Self> {
        Self::ALL
            .into_iter()
            .find(|policy| policy.directive_value() == value)
            .ok_or_else(|| {
                CoreError::validation(
                    "Redis eviction policy",
                    "must be a policy supported by every declared Redis version",
                )
            })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedisAppendFsync {
    Always,
    EverySecond,
    OperatingSystem,
}

impl RedisAppendFsync {
    pub const ALL: [Self; 3] = [Self::Always, Self::EverySecond, Self::OperatingSystem];

    pub const fn directive_value(self) -> &'static str {
        match self {
            Self::Always => "always",
            Self::EverySecond => "everysec",
            Self::OperatingSystem => "no",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Always => "每次写入同步（always）",
            Self::EverySecond => "每秒同步（everysec）",
            Self::OperatingSystem => "交给操作系统（no）",
        }
    }

    pub const fn summary(self) -> &'static str {
        match self {
            Self::Always => "每次 AOF 写入后请求 fsync，优先耐久性。",
            Self::EverySecond => "通常每秒请求一次 fsync，在耐久性与性能之间折中。",
            Self::OperatingSystem => "Redis 不主动 fsync，由操作系统决定何时落盘。",
        }
    }

    pub const fn risk(self) -> &'static str {
        match self {
            Self::Always => "同步 I/O 可能显著增加写延迟并降低吞吐量。",
            Self::EverySecond => "灾难性故障时可能丢失大约一秒内尚未落盘的写入。",
            Self::OperatingSystem => {
                "耐久性窗口取决于操作系统刷新策略，可能比 everysec 丢失更多写入。"
            }
        }
    }

    fn parse(value: &str) -> CoreResult<Self> {
        Self::ALL
            .into_iter()
            .find(|policy| policy.directive_value() == value)
            .ok_or_else(|| {
                CoreError::validation(
                    "Redis appendfsync policy",
                    "must be always, everysec, or no",
                )
            })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RedisSlowLogConfig {
    threshold_microseconds: u64,
    maximum_entries: u32,
}

impl RedisSlowLogConfig {
    pub fn new(threshold_microseconds: u64, maximum_entries: u32) -> CoreResult<Self> {
        if threshold_microseconds > MAX_SLOWLOG_THRESHOLD_MICROSECONDS {
            return Err(CoreError::validation(
                "Redis slowlog threshold",
                format!("must be in 0..={MAX_SLOWLOG_THRESHOLD_MICROSECONDS} microseconds"),
            ));
        }
        if maximum_entries == 0 || u64::from(maximum_entries) > MAX_SLOWLOG_LENGTH {
            return Err(CoreError::validation(
                "Redis slowlog maximum length",
                format!("must be in 1..={MAX_SLOWLOG_LENGTH}"),
            ));
        }
        Ok(Self {
            threshold_microseconds,
            maximum_entries,
        })
    }

    pub const fn threshold_microseconds(self) -> u64 {
        self.threshold_microseconds
    }

    pub const fn maximum_entries(self) -> u32 {
        self.maximum_entries
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RedisLatencyThresholdMilliseconds(u32);

impl RedisLatencyThresholdMilliseconds {
    pub fn parse(value: &str) -> CoreResult<Self> {
        let milliseconds = parse_decimal(
            value,
            1,
            MAX_LATENCY_THRESHOLD_MILLISECONDS,
            "Redis latency monitor threshold",
        )?;
        Ok(Self(milliseconds as u32))
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedisConfig {
    version: RedisVersion,
    bind_profile: RedisBindProfile,
    port: RedisPort,
    data_directory: RedisDataDirectory,
    features: BTreeSet<RedisConfigFeature>,
    max_clients: RedisMaxClients,
    idle_timeout: RedisIdleTimeoutSeconds,
    tcp_keepalive: RedisTcpKeepaliveSeconds,
    maxmemory: RedisMaxmemory,
    eviction_policy: Option<RedisEvictionPolicy>,
    append_fsync: RedisAppendFsync,
    slow_log: RedisSlowLogConfig,
    latency_threshold: Option<RedisLatencyThresholdMilliseconds>,
}

impl RedisConfig {
    pub fn baseline(version: RedisVersion) -> Self {
        Self {
            version,
            bind_profile: RedisBindProfile::DualStackLoopback,
            port: RedisPort(6379),
            data_directory: RedisDataDirectory::default(),
            features: RedisConfigFeature::ALL
                .into_iter()
                .filter(|feature| feature.default_enabled())
                .collect(),
            max_clients: RedisMaxClients(10_000),
            idle_timeout: RedisIdleTimeoutSeconds(300),
            tcp_keepalive: RedisTcpKeepaliveSeconds(300),
            maxmemory: RedisMaxmemory {
                mebibytes: DEFAULT_MAXMEMORY_MEBIBYTES,
            },
            eviction_policy: None,
            append_fsync: RedisAppendFsync::EverySecond,
            slow_log: RedisSlowLogConfig {
                threshold_microseconds: 10_000,
                maximum_entries: 128,
            },
            latency_threshold: None,
        }
    }

    pub const fn version(&self) -> RedisVersion {
        self.version
    }

    pub const fn bind_profile(&self) -> RedisBindProfile {
        self.bind_profile
    }

    pub const fn port(&self) -> RedisPort {
        self.port
    }

    pub fn data_directory(&self) -> &RedisDataDirectory {
        &self.data_directory
    }

    pub fn features(&self) -> &BTreeSet<RedisConfigFeature> {
        &self.features
    }

    pub fn feature_enabled(&self, feature: RedisConfigFeature) -> bool {
        self.features.contains(&feature)
    }

    pub fn with_bind_profile(mut self, profile: RedisBindProfile) -> Self {
        self.bind_profile = profile;
        self
    }

    pub fn with_port(mut self, port: RedisPort) -> Self {
        self.port = port;
        self
    }

    pub fn with_data_directory(mut self, directory: RedisDataDirectory) -> CoreResult<Self> {
        directory.validate()?;
        self.data_directory = directory;
        self.validate_feature_compatibility()?;
        Ok(self)
    }

    pub fn with_feature(mut self, feature: RedisConfigFeature, enabled: bool) -> CoreResult<Self> {
        if enabled {
            self.features.insert(feature);
        } else {
            self.features.remove(&feature);
        }
        self.validate_feature_compatibility()?;
        Ok(self)
    }

    pub fn with_max_clients(mut self, value: RedisMaxClients) -> CoreResult<Self> {
        self.max_clients = value;
        self.features.insert(RedisConfigFeature::MaxClients);
        self.validate_feature_compatibility()?;
        Ok(self)
    }

    pub fn with_idle_timeout(mut self, value: RedisIdleTimeoutSeconds) -> CoreResult<Self> {
        self.idle_timeout = value;
        self.features.insert(RedisConfigFeature::IdleClientTimeout);
        self.validate_feature_compatibility()?;
        Ok(self)
    }

    pub fn with_tcp_keepalive(mut self, value: RedisTcpKeepaliveSeconds) -> CoreResult<Self> {
        self.tcp_keepalive = value;
        self.features.insert(RedisConfigFeature::TcpKeepalive);
        self.validate_feature_compatibility()?;
        Ok(self)
    }

    pub fn with_memory_limit(mut self, value: RedisMaxmemory) -> CoreResult<Self> {
        self.maxmemory = value;
        self.features.insert(RedisConfigFeature::MemoryLimit);
        self.validate_feature_compatibility()?;
        Ok(self)
    }

    pub fn with_eviction_policy(mut self, policy: RedisEvictionPolicy) -> CoreResult<Self> {
        self.eviction_policy = Some(policy);
        self.features.insert(RedisConfigFeature::EvictionPolicy);
        self.validate_feature_compatibility()?;
        Ok(self)
    }

    pub fn with_append_fsync(mut self, policy: RedisAppendFsync) -> CoreResult<Self> {
        self.append_fsync = policy;
        self.features.insert(RedisConfigFeature::AofPersistence);
        self.validate_feature_compatibility()?;
        Ok(self)
    }

    pub fn with_slow_log(mut self, value: RedisSlowLogConfig) -> CoreResult<Self> {
        self.slow_log = value;
        self.features.insert(RedisConfigFeature::SlowLog);
        self.validate_feature_compatibility()?;
        Ok(self)
    }

    pub fn with_latency_threshold(
        mut self,
        value: RedisLatencyThresholdMilliseconds,
    ) -> CoreResult<Self> {
        self.latency_threshold = Some(value);
        self.features.insert(RedisConfigFeature::LatencyMonitor);
        self.validate_feature_compatibility()?;
        Ok(self)
    }

    pub fn generate(&self) -> CoreResult<GeneratedRedisConfig> {
        self.validate_feature_compatibility()?;

        let mut contents = String::with_capacity(1_024);
        contents.push_str("# LovelyRes Redis Open Source ");
        contents.push_str(self.version.label());
        contents.push_str(" standalone new empty-instance baseline\n");
        contents.push_str(
            "# EMPTY INSTANCE ONLY — DO NOT APPLY TO AN EXISTING DATA-BEARING REDIS INSTANCE.\n",
        );
        contents.push_str(
            "# Existing-instance AOF/RDB changes require a separate live migration, backup, rollback, and data verification workflow.\n",
        );
        contents.push_str(
            "# Local draft only: validate with the exact target redis-server before activation.\n",
        );
        contents.push_str(
            "# Authentication/ACL and non-loopback exposure are intentionally deferred.\n",
        );
        contents.push_str(
            "# Loopback binding is not authentication: any local process able to reach this port may access Redis.\n",
        );
        contents.push_str(
            "# maxclients is an application limit and remains constrained by the target OS file-descriptor limit and Redis reserved descriptors.\n",
        );
        contents.push_str("# Verify the data directory exists with correct ownership, permissions, capacity, and backup policy before first startup.\n");
        contents.push_str("# The 512 MiB maxmemory baseline is a conservative placeholder; size it for the target and reserve memory for Redis overhead, persistence, and the OS.\n\n");

        contents.push_str("bind ");
        contents.push_str(self.bind_profile.directive_value());
        contents.push_str("\nprotected-mode yes\nport ");
        contents.push_str(&self.port.get().to_string());
        contents.push_str("\n\n");

        contents.push_str("dir ");
        contents.push_str(self.data_directory.as_str());
        contents.push_str("\ndbfilename ");
        contents.push_str(REDIS_RDB_FILE_NAME);
        contents.push_str("\nappendfilename \"");
        contents.push_str(REDIS_AOF_FILE_NAME);
        contents.push_str("\"\n");
        if self.version.uses_multi_part_aof() {
            contents.push_str("appenddirname \"");
            contents.push_str(REDIS_AOF_DIRECTORY_NAME);
            contents.push_str("\"\n");
        }
        contents.push('\n');

        if self.feature_enabled(RedisConfigFeature::MaxClients) {
            contents.push_str("maxclients ");
            contents.push_str(&self.max_clients.get().to_string());
            contents.push('\n');
        }
        let idle_timeout = if self.feature_enabled(RedisConfigFeature::IdleClientTimeout) {
            self.idle_timeout.get()
        } else {
            0
        };
        contents.push_str("timeout ");
        contents.push_str(&idle_timeout.to_string());
        let tcp_keepalive = if self.feature_enabled(RedisConfigFeature::TcpKeepalive) {
            self.tcp_keepalive.get()
        } else {
            0
        };
        contents.push_str("\ntcp-keepalive ");
        contents.push_str(&tcp_keepalive.to_string());
        contents.push_str("\n\n");

        contents.push_str("maxmemory ");
        contents.push_str(&self.maxmemory.bytes().to_string());
        let eviction_policy = match (
            self.feature_enabled(RedisConfigFeature::EvictionPolicy),
            self.eviction_policy,
        ) {
            (true, Some(policy)) => policy,
            (false, _) | (true, None) => RedisEvictionPolicy::NoEviction,
        };
        contents.push_str("\nmaxmemory-policy ");
        contents.push_str(eviction_policy.directive_value());
        contents.push_str("\n\n");

        if self.feature_enabled(RedisConfigFeature::AofPersistence) {
            contents.push_str("appendonly yes\nappendfsync ");
            contents.push_str(self.append_fsync.directive_value());
            contents.push('\n');
        } else {
            contents.push_str("appendonly no\n");
        }

        if self.feature_enabled(RedisConfigFeature::RdbPersistence) {
            contents.push_str(
                "save 3600 1\nsave 300 100\nsave 60 10000\nstop-writes-on-bgsave-error yes\nrdbcompression yes\nrdbchecksum yes\n",
            );
        } else {
            contents.push_str("save \"\"\n");
        }
        contents.push('\n');

        if self.feature_enabled(RedisConfigFeature::SlowLog) {
            contents.push_str("slowlog-log-slower-than ");
            contents.push_str(&self.slow_log.threshold_microseconds().to_string());
            contents.push_str("\nslowlog-max-len ");
            contents.push_str(&self.slow_log.maximum_entries().to_string());
            contents.push('\n');
        } else {
            contents.push_str("slowlog-log-slower-than -1\n");
        }
        let latency_threshold = match (
            self.feature_enabled(RedisConfigFeature::LatencyMonitor),
            self.latency_threshold,
        ) {
            (true, Some(value)) => value.get(),
            (false, _) | (true, None) => 0,
        };
        contents.push_str("latency-monitor-threshold ");
        contents.push_str(&latency_threshold.to_string());
        contents.push('\n');

        validate_generated_document(&contents, self.version)?;
        Ok(GeneratedRedisConfig {
            version: self.version,
            contents,
        })
    }

    fn validate_feature_compatibility(&self) -> CoreResult<()> {
        for feature in &self.features {
            if !feature.supports_version(self.version) {
                return Err(CoreError::validation(
                    "Redis configuration feature",
                    format!(
                        "{} is not supported by Redis {}",
                        feature.title(),
                        self.version.label()
                    ),
                ));
            }
        }

        self.data_directory.validate()?;

        let memory_enabled = self.feature_enabled(RedisConfigFeature::MemoryLimit);
        let eviction_enabled = self.feature_enabled(RedisConfigFeature::EvictionPolicy);
        if !memory_enabled {
            return Err(CoreError::validation(
                "Redis memory limit",
                "the new-instance baseline requires a typed non-zero maxmemory; choose a target-sized limit instead of disabling it",
            ));
        }
        if eviction_enabled && self.eviction_policy.is_none() {
            return Err(CoreError::validation(
                "Redis eviction policy",
                "the eviction-policy feature requires a typed policy and an enabled non-zero memory limit",
            ));
        }

        if self.feature_enabled(RedisConfigFeature::LatencyMonitor)
            && self.latency_threshold.is_none()
        {
            return Err(CoreError::validation(
                "Redis latency monitor",
                "the latency-monitor feature requires a typed positive millisecond threshold",
            ));
        }

        if !self.feature_enabled(RedisConfigFeature::AofPersistence)
            && !self.feature_enabled(RedisConfigFeature::RdbPersistence)
        {
            return Err(CoreError::validation(
                "Redis persistence",
                "refuses to disable both AOF and RDB in this first baseline; enable AOF before removing RDB",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GeneratedRedisConfig {
    version: RedisVersion,
    contents: String,
}

impl fmt::Debug for GeneratedRedisConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GeneratedRedisConfig")
            .field("version", &self.version)
            .field("bytes", &self.contents.len())
            .finish()
    }
}

impl GeneratedRedisConfig {
    pub fn contents(&self) -> &str {
        &self.contents
    }

    pub const fn version(&self) -> RedisVersion {
        self.version
    }

    pub const fn suggested_file_name(&self) -> &'static str {
        SUGGESTED_FILE_NAME
    }

    /// Writes one new empty-instance `redis.conf` without replacing an existing file.
    pub fn write_new(&self, destination: &Path) -> CoreResult<PathBuf> {
        validate_export_destination(destination)?;
        validate_generated_document(&self.contents, self.version)?;

        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(destination)
            .map_err(|source| {
                CoreError::io("create generated Redis configuration", destination, source)
            })?;
        let write_result = (|| {
            file.write_all(self.contents.as_bytes()).map_err(|source| {
                CoreError::io("write generated Redis configuration", destination, source)
            })?;
            file.flush().map_err(|source| {
                CoreError::io("flush generated Redis configuration", destination, source)
            })?;
            file.sync_all().map_err(|source| {
                CoreError::io("sync generated Redis configuration", destination, source)
            })
        })();
        drop(file);

        if let Err(error) = write_result {
            return Err(combine_write_and_cleanup_result(
                destination,
                error,
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
        Err(cleanup_error) => CoreError::validation(
            "generated Redis configuration write and cleanup",
            format!(
                "write failed ({write_error}); removing the partial file at {} also failed ({cleanup_error}); inspect and remove the possible partial file manually",
                destination.display()
            ),
        ),
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

fn validate_generated_document(contents: &str, version: RedisVersion) -> CoreResult<()> {
    if contents.is_empty()
        || contents.len() > MAX_GENERATED_REDIS_CONFIG_BYTES
        || contents.contains('\0')
        || contents.contains('\r')
        || !contents.ends_with('\n')
    {
        return Err(CoreError::validation(
            "generated Redis configuration",
            format!(
                "must be non-empty LF-only UTF-8 with a terminal newline and at most {MAX_GENERATED_REDIS_CONFIG_BYTES} bytes"
            ),
        ));
    }

    let required_header = format!(
        "# LovelyRes Redis Open Source {} standalone new empty-instance baseline\n# EMPTY INSTANCE ONLY — DO NOT APPLY TO AN EXISTING DATA-BEARING REDIS INSTANCE.\n",
        version.label()
    );
    if !contents.starts_with(&required_header) {
        return Err(CoreError::validation(
            "generated Redis configuration",
            "must retain the matching Redis version and prominent new-empty-instance-only warning",
        ));
    }

    let document = MiddlewareDocument::parse(
        MiddlewareDocumentSyntax::Redis,
        contents.as_bytes().to_vec(),
    )
    .map_err(|error| CoreError::validation("generated Redis configuration", error.to_string()))?;
    if document.raw_bytes() != contents.as_bytes() {
        return Err(CoreError::validation(
            "generated Redis configuration",
            "closed template did not round-trip byte-exactly",
        ));
    }

    const ALLOWED_DIRECTIVES: &[&str] = &[
        "bind",
        "protected-mode",
        "port",
        "dir",
        "dbfilename",
        "maxclients",
        "timeout",
        "tcp-keepalive",
        "maxmemory",
        "maxmemory-policy",
        "appendonly",
        "appendfilename",
        "appenddirname",
        "appendfsync",
        "save",
        "stop-writes-on-bgsave-error",
        "rdbcompression",
        "rdbchecksum",
        "slowlog-log-slower-than",
        "slowlog-max-len",
        "latency-monitor-threshold",
    ];

    let mut directives = BTreeMap::<String, Vec<String>>::new();
    for node in document.nodes() {
        match node.kind {
            MiddlewareDocumentNodeKind::Preamble
            | MiddlewareDocumentNodeKind::Whitespace
            | MiddlewareDocumentNodeKind::Comment => {}
            MiddlewareDocumentNodeKind::Directive => {
                let name = node.name.as_deref().ok_or_else(|| {
                    CoreError::validation(
                        "generated Redis configuration",
                        "directive is missing its closed name",
                    )
                })?;
                if !ALLOWED_DIRECTIVES.contains(&name) {
                    return Err(CoreError::validation(
                        "generated Redis configuration",
                        format!("directive {name} is outside the closed generator allowlist"),
                    ));
                }
                let span = node.editable_value.ok_or_else(|| {
                    CoreError::validation(
                        "generated Redis configuration",
                        format!("directive {name} is missing its typed value"),
                    )
                })?;
                let value = std::str::from_utf8(&document.raw_bytes()[span.start()..span.end()])
                    .map_err(|_| {
                        CoreError::validation(
                            "generated Redis configuration",
                            "directive value is not UTF-8",
                        )
                    })?;
                directives
                    .entry(name.to_owned())
                    .or_default()
                    .push(value.to_owned());
            }
            MiddlewareDocumentNodeKind::BlockStart
            | MiddlewareDocumentNodeKind::BlockEnd
            | MiddlewareDocumentNodeKind::ElementStart
            | MiddlewareDocumentNodeKind::ElementEnd
            | MiddlewareDocumentNodeKind::Attribute
            | MiddlewareDocumentNodeKind::Text
            | MiddlewareDocumentNodeKind::Cdata
            | MiddlewareDocumentNodeKind::ProcessingInstruction
            | MiddlewareDocumentNodeKind::Declaration
            | MiddlewareDocumentNodeKind::Opaque => {
                return Err(CoreError::validation(
                    "generated Redis configuration",
                    "closed template produced a non-directive or opaque structure",
                ));
            }
        }
    }

    for (name, values) in &directives {
        if name != "save" && values.len() != 1 {
            return Err(CoreError::validation(
                "generated Redis configuration",
                format!("directive {name} must occur exactly once"),
            ));
        }
    }
    for required in [
        "bind",
        "protected-mode",
        "port",
        "dir",
        "dbfilename",
        "timeout",
        "tcp-keepalive",
        "maxmemory",
        "maxmemory-policy",
        "appendonly",
        "appendfilename",
        "save",
        "slowlog-log-slower-than",
        "latency-monitor-threshold",
    ] {
        if !directives.contains_key(required) {
            return Err(CoreError::validation(
                "generated Redis configuration",
                format!("required baseline directive {required} is missing"),
            ));
        }
    }

    let one = |name: &str| -> CoreResult<&str> {
        directives
            .get(name)
            .and_then(|values| values.first())
            .map(String::as_str)
            .ok_or_else(|| {
                CoreError::validation(
                    "generated Redis configuration",
                    format!("directive {name} is missing"),
                )
            })
    };

    if !RedisBindProfile::ALL
        .into_iter()
        .any(|profile| profile.directive_value() == one("bind").unwrap_or_default())
    {
        return Err(CoreError::validation(
            "generated Redis configuration",
            REDIS_REMOTE_BINDING_DEFERRED_REASON,
        ));
    }
    if one("protected-mode")? != "yes" {
        return Err(CoreError::validation(
            "generated Redis configuration",
            "protected-mode must remain enabled",
        ));
    }
    RedisPort::parse(one("port")?)?;
    RedisDataDirectory::parse(one("dir")?)?;
    if one("dbfilename")? != REDIS_RDB_FILE_NAME {
        return Err(CoreError::validation(
            "generated Redis configuration",
            format!("dbfilename must remain fixed at {REDIS_RDB_FILE_NAME}"),
        ));
    }
    if one("appendfilename")? != format!("\"{REDIS_AOF_FILE_NAME}\"") {
        return Err(CoreError::validation(
            "generated Redis configuration",
            format!("appendfilename must remain fixed at {REDIS_AOF_FILE_NAME}"),
        ));
    }
    if version.uses_multi_part_aof() {
        if one("appenddirname")? != format!("\"{REDIS_AOF_DIRECTORY_NAME}\"") {
            return Err(CoreError::validation(
                "generated Redis configuration",
                format!(
                    "Redis {} multi-part AOF must use the fixed appenddirname {REDIS_AOF_DIRECTORY_NAME}",
                    version.label()
                ),
            ));
        }
    } else if directives.contains_key("appenddirname") {
        return Err(CoreError::validation(
            "generated Redis configuration",
            "Redis 6.2 uses a single AOF file in dir and must not receive the Redis 7+ appenddirname directive",
        ));
    }
    if let Some(value) = directives
        .get("maxclients")
        .and_then(|values| values.first())
    {
        RedisMaxClients::parse(value)?;
    }

    validate_zero_or_typed_seconds(
        one("timeout")?,
        RedisIdleTimeoutSeconds::parse,
        "Redis idle client timeout",
    )?;
    validate_zero_or_typed_seconds(
        one("tcp-keepalive")?,
        RedisTcpKeepaliveSeconds::parse,
        "Redis TCP keepalive",
    )?;

    let bytes = parse_decimal(
        one("maxmemory")?,
        MEBIBYTE_BYTES,
        MAX_MEMORY_MEBIBYTES * MEBIBYTE_BYTES,
        "Redis maxmemory",
    )?;
    RedisMaxmemory::from_bytes(bytes)?;
    RedisEvictionPolicy::parse(one("maxmemory-policy")?)?;

    let aof_enabled = match one("appendonly")? {
        "yes" => {
            RedisAppendFsync::parse(one("appendfsync")?)?;
            true
        }
        "no" if !directives.contains_key("appendfsync") => false,
        _ => {
            return Err(CoreError::validation(
                "generated Redis configuration",
                "appendonly must be yes with one appendfsync policy, or no without appendfsync",
            ));
        }
    };

    let save_values = directives.get("save").expect("required save checked above");
    if save_values.as_slice() == ["\"\""] {
        if !aof_enabled {
            return Err(CoreError::validation(
                "generated Redis configuration",
                "refuses a configuration that jointly disables both AOF and RDB persistence",
            ));
        }
        for directive in [
            "stop-writes-on-bgsave-error",
            "rdbcompression",
            "rdbchecksum",
        ] {
            if directives.contains_key(directive) {
                return Err(CoreError::validation(
                    "generated Redis configuration",
                    "disabled RDB must not retain active RDB options",
                ));
            }
        }
    } else if save_values.as_slice() == ["3600 1", "300 100", "60 10000"] {
        for directive in [
            "stop-writes-on-bgsave-error",
            "rdbcompression",
            "rdbchecksum",
        ] {
            if one(directive)? != "yes" {
                return Err(CoreError::validation(
                    "generated Redis configuration",
                    format!("RDB safety directive {directive} must be yes"),
                ));
            }
        }
    } else {
        return Err(CoreError::validation(
            "generated Redis configuration",
            "save directives must be the reviewed RDB schedule or one explicit disable",
        ));
    }

    let slowlog_threshold = one("slowlog-log-slower-than")?;
    if slowlog_threshold == "-1" {
        if directives.contains_key("slowlog-max-len") {
            return Err(CoreError::validation(
                "generated Redis configuration",
                "disabled slowlog must not retain a queue length",
            ));
        }
    } else {
        let threshold = parse_decimal(
            slowlog_threshold,
            0,
            MAX_SLOWLOG_THRESHOLD_MICROSECONDS,
            "Redis slowlog threshold",
        )?;
        let maximum_entries = parse_decimal(
            one("slowlog-max-len")?,
            1,
            MAX_SLOWLOG_LENGTH,
            "Redis slowlog maximum length",
        )?;
        RedisSlowLogConfig::new(threshold, maximum_entries as u32)?;
    }

    let latency = one("latency-monitor-threshold")?;
    if latency != "0" {
        RedisLatencyThresholdMilliseconds::parse(latency)?;
    }
    Ok(())
}

fn validate_zero_or_typed_seconds<T>(
    value: &str,
    parse: impl FnOnce(&str) -> CoreResult<T>,
    subject: &'static str,
) -> CoreResult<()> {
    if value == "0" {
        return Ok(());
    }
    parse(value)
        .map(|_| ())
        .map_err(|error| CoreError::validation(subject, error.to_string()))
}

fn validate_export_destination(destination: &Path) -> CoreResult<()> {
    if !destination.is_absolute() {
        return Err(CoreError::validation(
            "generated Redis configuration destination",
            "must be an absolute path selected by the native save dialog",
        ));
    }
    if destination
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(CoreError::validation(
            "generated Redis configuration destination",
            "must not contain current-directory or parent-directory components",
        ));
    }
    if !destination
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("conf"))
    {
        return Err(CoreError::validation(
            "generated Redis configuration destination",
            "must use the .conf extension",
        ));
    }
    let parent = destination.parent().ok_or_else(|| {
        CoreError::validation(
            "generated Redis configuration destination",
            "path has no parent directory",
        )
    })?;
    if !parent.is_dir() {
        return Err(CoreError::validation(
            "generated Redis configuration destination",
            "parent directory does not exist",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use uuid::Uuid;

    use super::*;

    #[derive(Debug)]
    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("lovelyres-redis-config-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn version_lines_and_feature_metadata_are_closed_and_unique() {
        assert_eq!(
            RedisVersion::ALL
                .into_iter()
                .map(RedisVersion::label)
                .collect::<Vec<_>>(),
            [
                "6.2", "7.2", "7.4", "8.0", "8.2", "8.4", "8.6", "8.8", "8.10",
            ]
        );
        for version in RedisVersion::ALL {
            assert_eq!(RedisVersion::parse(version.label()).unwrap(), version);
        }
        for unsupported in ["", "6.0", "7.0", "8", "8.8.1", "8.10.1", "9.0", " 8.8"] {
            assert!(RedisVersion::parse(unsupported).is_err(), "{unsupported:?}");
        }

        let keys = RedisConfigFeature::ALL
            .into_iter()
            .map(RedisConfigFeature::key)
            .collect::<HashSet<_>>();
        assert_eq!(keys.len(), RedisConfigFeature::ALL.len());
        assert!(RedisConfigFeature::ALL.into_iter().all(|feature| {
            !feature.key().is_empty()
                && !feature.title().is_empty()
                && !feature.summary().is_empty()
                && !feature.scope().is_empty()
                && !feature.aliases().is_empty()
                && RedisVersion::ALL
                    .into_iter()
                    .all(|version| feature.supports_version(version))
        }));
        assert_eq!(
            RedisConfigFeature::ALL
                .into_iter()
                .filter(|feature| feature.default_enabled())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                RedisConfigFeature::MaxClients,
                RedisConfigFeature::TcpKeepalive,
                RedisConfigFeature::MemoryLimit,
                RedisConfigFeature::AofPersistence,
                RedisConfigFeature::RdbPersistence,
                RedisConfigFeature::SlowLog,
            ])
        );
        assert!(!RedisVersion::V6_2.uses_multi_part_aof());
        assert!(
            RedisVersion::ALL
                .into_iter()
                .filter(|version| *version != RedisVersion::V6_2)
                .all(RedisVersion::uses_multi_part_aof)
        );

        let eviction_values = RedisEvictionPolicy::ALL
            .into_iter()
            .map(RedisEvictionPolicy::directive_value)
            .collect::<HashSet<_>>();
        assert_eq!(eviction_values.len(), RedisEvictionPolicy::ALL.len());
        assert!(RedisEvictionPolicy::ALL.into_iter().all(|policy| {
            !policy.label().is_empty() && !policy.summary().is_empty() && !policy.risk().is_empty()
        }));
        assert!(RedisEvictionPolicy::NoEviction.risk().contains("OOM"));
        for volatile in [
            RedisEvictionPolicy::VolatileLru,
            RedisEvictionPolicy::VolatileLfu,
            RedisEvictionPolicy::VolatileRandom,
            RedisEvictionPolicy::VolatileTtl,
        ] {
            assert!(volatile.risk().contains("没有设置过期时间"));
            assert!(volatile.risk().contains("OOM"));
        }

        let fsync_values = RedisAppendFsync::ALL
            .into_iter()
            .map(RedisAppendFsync::directive_value)
            .collect::<HashSet<_>>();
        assert_eq!(fsync_values.len(), RedisAppendFsync::ALL.len());
        assert!(RedisAppendFsync::ALL.into_iter().all(|policy| {
            !policy.label().is_empty() && !policy.summary().is_empty() && !policy.risk().is_empty()
        }));
        assert!(RedisAppendFsync::Always.risk().contains("写延迟"));
        assert!(RedisAppendFsync::EverySecond.risk().contains("一秒"));
        assert!(
            RedisAppendFsync::OperatingSystem
                .risk()
                .contains("更多写入")
        );
    }

    #[test]
    fn baseline_is_explicitly_for_empty_instances_and_has_bounded_dual_persistence() {
        for version in RedisVersion::ALL {
            let generated = RedisConfig::baseline(version).generate().unwrap();
            assert_eq!(generated.version(), version);
            assert!(generated.contents().contains(&format!(
                "Redis Open Source {} standalone new empty-instance baseline",
                version.label()
            )));
            assert!(generated.contents().contains(
                "EMPTY INSTANCE ONLY — DO NOT APPLY TO AN EXISTING DATA-BEARING REDIS INSTANCE"
            ));
            assert!(
                generated
                    .contents()
                    .contains("Loopback binding is not authentication")
            );
            assert!(generated.contents().contains("OS file-descriptor limit"));
            assert!(generated.contents().contains("bind 127.0.0.1 -::1\n"));
            assert!(generated.contents().contains("protected-mode yes\n"));
            assert!(generated.contents().contains("port 6379\n"));
            assert!(generated.contents().contains("dir /var/lib/redis\n"));
            assert!(generated.contents().contains("dbfilename dump.rdb\n"));
            assert!(
                generated
                    .contents()
                    .contains("appendfilename \"appendonly.aof\"\n")
            );
            assert_eq!(
                generated
                    .contents()
                    .contains("appenddirname \"appendonlydir\"\n"),
                version.uses_multi_part_aof()
            );
            assert!(generated.contents().contains("maxclients 10000\n"));
            assert!(generated.contents().contains("tcp-keepalive 300\n"));
            assert!(generated.contents().contains("maxmemory 536870912\n"));
            assert!(
                generated
                    .contents()
                    .contains("maxmemory-policy noeviction\n")
            );
            assert!(
                generated
                    .contents()
                    .contains("appendonly yes\nappendfsync everysec\n")
            );
            assert_eq!(generated.contents().matches("save ").count(), 3);
            for forbidden in [
                "requirepass",
                "masterauth",
                "aclfile",
                "user default",
                "tls-key-file",
                "replicaof",
                "loadmodule",
            ] {
                assert!(!generated.contents().contains(forbidden), "{forbidden}");
            }
            validate_generated_document(generated.contents(), version).unwrap();
            assert!(generated.contents().len() <= MAX_GENERATED_REDIS_CONFIG_BYTES);
        }
        assert!(REDIS_EXISTING_INSTANCE_MIGRATION_DEFERRED_REASON.contains("静态改写"));
        assert!(REDIS_EXISTING_INSTANCE_MIGRATION_DEFERRED_REASON.contains("备份"));
    }

    #[test]
    fn closed_bind_profiles_never_expose_non_loopback_interfaces() {
        for profile in RedisBindProfile::ALL {
            let generated = RedisConfig::baseline(RedisVersion::V8_8)
                .with_bind_profile(profile)
                .generate()
                .unwrap();
            assert!(generated.contents().contains("bind 127.0.0.1"));
            assert!(!generated.contents().contains("0.0.0.0"));
            assert!(!generated.contents().contains("bind *"));
        }
        assert!(REDIS_REMOTE_BINDING_DEFERRED_REASON.contains("回环"));
        assert!(REDIS_AUTHENTICATION_ACL_DEFERRED_REASON.contains("不回显"));
    }

    #[test]
    fn typed_numeric_boundaries_reject_whitespace_signs_overflow_and_injection() {
        assert_eq!(
            RedisDataDirectory::parse("/srv/redis-8_8/data")
                .unwrap()
                .as_str(),
            "/srv/redis-8_8/data"
        );
        assert_eq!(RedisPort::parse("6380").unwrap().get(), 6380);
        assert_eq!(RedisMaxClients::parse("25000").unwrap().get(), 25_000);
        assert_eq!(RedisIdleTimeoutSeconds::parse("600").unwrap().get(), 600);
        assert_eq!(RedisTcpKeepaliveSeconds::parse("120").unwrap().get(), 120);
        assert_eq!(
            RedisMaxmemory::parse_mebibytes("512").unwrap().bytes(),
            512 * MEBIBYTE_BYTES
        );
        assert_eq!(
            RedisLatencyThresholdMilliseconds::parse("100")
                .unwrap()
                .get(),
            100
        );

        for invalid in ["", "0", "65536", " 6379", "6379 ", "+6379", "6379\nuser x"] {
            assert!(RedisPort::parse(invalid).is_err(), "{invalid:?}");
        }
        for invalid in ["", "0", "1000001", "10000 # comment", "-1"] {
            assert!(RedisMaxClients::parse(invalid).is_err(), "{invalid:?}");
        }
        for invalid in ["0", "31536001", "60 timeout 0"] {
            assert!(
                RedisIdleTimeoutSeconds::parse(invalid).is_err(),
                "{invalid:?}"
            );
        }
        for invalid in ["0", "86401", "300\r\nrequirepass x"] {
            assert!(
                RedisTcpKeepaliveSeconds::parse(invalid).is_err(),
                "{invalid:?}"
            );
        }
        for invalid in ["0", "16777217", "512mb", "512 maxmemory-policy allkeys-lru"] {
            assert!(
                RedisMaxmemory::parse_mebibytes(invalid).is_err(),
                "{invalid:?}"
            );
        }
        for invalid in ["0", "60001", "100 # comment"] {
            assert!(
                RedisLatencyThresholdMilliseconds::parse(invalid).is_err(),
                "{invalid:?}"
            );
        }
        for invalid in [
            "",
            "/",
            "var/lib/redis",
            "/var/lib/redis/",
            "/var/../redis",
            "/var/lib/redis data",
            "/var/lib/redis#comment",
            "/var/lib/redis\nrequirepass secret",
            " /var/lib/redis",
        ] {
            assert!(RedisDataDirectory::parse(invalid).is_err(), "{invalid:?}");
        }
        assert!(RedisSlowLogConfig::new(MAX_SLOWLOG_THRESHOLD_MICROSECONDS + 1, 128).is_err());
        assert!(RedisSlowLogConfig::new(10_000, 0).is_err());
        assert!(RedisSlowLogConfig::new(10_000, 1_000_001).is_err());
    }

    #[test]
    fn additive_features_are_order_independent_and_removal_restores_baseline() {
        let baseline = RedisConfig::baseline(RedisVersion::V7_4)
            .generate()
            .unwrap();
        let memory = RedisMaxmemory::from_mebibytes(1024).unwrap();
        let latency = RedisLatencyThresholdMilliseconds::parse("100").unwrap();

        let first = RedisConfig::baseline(RedisVersion::V7_4)
            .with_memory_limit(memory)
            .unwrap()
            .with_latency_threshold(latency)
            .unwrap()
            .generate()
            .unwrap();
        let second = RedisConfig::baseline(RedisVersion::V7_4)
            .with_latency_threshold(latency)
            .unwrap()
            .with_memory_limit(memory)
            .unwrap()
            .generate()
            .unwrap();
        assert_eq!(first, second);
        assert!(first.contents().contains("maxmemory 1073741824"));
        assert!(first.contents().contains("latency-monitor-threshold 100"));

        let restored = RedisConfig::baseline(RedisVersion::V7_4)
            .with_latency_threshold(latency)
            .unwrap()
            .with_feature(RedisConfigFeature::LatencyMonitor, false)
            .unwrap()
            .generate()
            .unwrap();
        assert_eq!(restored, baseline);
    }

    #[test]
    fn bounded_memory_is_mandatory_and_eviction_removal_preserves_it() {
        assert!(
            RedisConfig::baseline(RedisVersion::V8_0)
                .with_feature(RedisConfigFeature::MemoryLimit, false)
                .is_err()
        );
        assert!(
            RedisConfig::baseline(RedisVersion::V8_0)
                .with_feature(RedisConfigFeature::EvictionPolicy, true)
                .is_err()
        );

        let configured = RedisConfig::baseline(RedisVersion::V8_0)
            .with_memory_limit(RedisMaxmemory::from_mebibytes(1024).unwrap())
            .unwrap()
            .with_eviction_policy(RedisEvictionPolicy::AllKeysLfu)
            .unwrap();
        let generated = configured.generate().unwrap();
        assert!(generated.contents().contains("maxmemory 1073741824\n"));
        assert!(
            generated
                .contents()
                .contains("maxmemory-policy allkeys-lfu\n")
        );
        assert!(
            configured
                .clone()
                .with_feature(RedisConfigFeature::MemoryLimit, false)
                .is_err()
        );

        let without_eviction = configured
            .with_feature(RedisConfigFeature::EvictionPolicy, false)
            .unwrap()
            .generate()
            .unwrap();
        assert!(
            without_eviction
                .contents()
                .contains("maxmemory 1073741824\n")
        );
        assert!(
            without_eviction
                .contents()
                .contains("maxmemory-policy noeviction\n")
        );
    }

    #[test]
    fn aof_and_rdb_compose_but_at_least_one_persistence_mode_remains() {
        let aof_and_rdb = RedisConfig::baseline(RedisVersion::V6_2)
            .with_append_fsync(RedisAppendFsync::Always)
            .unwrap();
        let both = aof_and_rdb.generate().unwrap();
        assert!(
            both.contents()
                .contains("appendonly yes\nappendfsync always\n")
        );
        assert_eq!(both.contents().matches("save ").count(), 3);

        let aof_only = aof_and_rdb
            .with_feature(RedisConfigFeature::RdbPersistence, false)
            .unwrap();
        let generated = aof_only.generate().unwrap();
        assert!(generated.contents().contains("appendonly yes\n"));
        assert!(generated.contents().contains("save \"\"\n"));
        assert!(!generated.contents().contains("rdbcompression"));
        assert!(
            aof_only
                .with_feature(RedisConfigFeature::AofPersistence, false)
                .is_err()
        );

        let rdb_only = RedisConfig::baseline(RedisVersion::V6_2)
            .with_feature(RedisConfigFeature::AofPersistence, false)
            .unwrap()
            .generate()
            .unwrap();
        assert!(rdb_only.contents().contains("appendonly no\n"));
        assert!(!rdb_only.contents().contains("appendfsync"));
        assert_eq!(rdb_only.contents().matches("save ").count(), 3);
    }

    #[test]
    fn redis_6_2_and_7_plus_render_and_validate_different_aof_layouts() {
        let legacy = RedisConfig::baseline(RedisVersion::V6_2)
            .generate()
            .unwrap();
        assert!(
            legacy
                .contents()
                .contains("appendfilename \"appendonly.aof\"\n")
        );
        assert!(!legacy.contents().contains("appenddirname"));

        let invalid_legacy = legacy.contents().replace(
            "appendfilename \"appendonly.aof\"\n",
            "appendfilename \"appendonly.aof\"\nappenddirname \"appendonlydir\"\n",
        );
        assert!(validate_generated_document(&invalid_legacy, RedisVersion::V6_2).is_err());

        for version in RedisVersion::ALL
            .into_iter()
            .filter(|version| *version != RedisVersion::V6_2)
        {
            let generated = RedisConfig::baseline(version).generate().unwrap();
            assert!(
                generated
                    .contents()
                    .contains("appenddirname \"appendonlydir\"\n")
            );
            let missing_directory = generated
                .contents()
                .replace("appenddirname \"appendonlydir\"\n", "");
            assert!(validate_generated_document(&missing_directory, version).is_err());
        }
    }

    #[test]
    fn connection_slowlog_and_latency_tuning_render_only_typed_values() {
        let generated = RedisConfig::baseline(RedisVersion::V8_2)
            .with_port(RedisPort::parse("6380").unwrap())
            .with_data_directory(RedisDataDirectory::parse("/srv/redis/data").unwrap())
            .unwrap()
            .with_max_clients(RedisMaxClients::parse("25000").unwrap())
            .unwrap()
            .with_idle_timeout(RedisIdleTimeoutSeconds::parse("600").unwrap())
            .unwrap()
            .with_tcp_keepalive(RedisTcpKeepaliveSeconds::parse("120").unwrap())
            .unwrap()
            .with_slow_log(RedisSlowLogConfig::new(25_000, 256).unwrap())
            .unwrap()
            .with_latency_threshold(RedisLatencyThresholdMilliseconds::parse("50").unwrap())
            .unwrap()
            .generate()
            .unwrap();
        for expected in [
            "port 6380",
            "dir /srv/redis/data",
            "maxclients 25000",
            "timeout 600",
            "tcp-keepalive 120",
            "slowlog-log-slower-than 25000",
            "slowlog-max-len 256",
            "latency-monitor-threshold 50",
        ] {
            assert!(generated.contents().contains(expected), "{expected}");
        }
    }

    #[test]
    fn every_compatible_feature_composes_for_every_supported_version() {
        for version in RedisVersion::ALL {
            let mut config = RedisConfig::baseline(version)
                .with_memory_limit(RedisMaxmemory::from_mebibytes(256).unwrap())
                .unwrap()
                .with_eviction_policy(RedisEvictionPolicy::VolatileTtl)
                .unwrap()
                .with_append_fsync(RedisAppendFsync::EverySecond)
                .unwrap()
                .with_latency_threshold(RedisLatencyThresholdMilliseconds::parse("100").unwrap())
                .unwrap();
            for feature in RedisConfigFeature::ALL {
                if !matches!(
                    feature,
                    RedisConfigFeature::MemoryLimit
                        | RedisConfigFeature::EvictionPolicy
                        | RedisConfigFeature::LatencyMonitor
                ) {
                    config = config.with_feature(feature, true).unwrap();
                }
            }
            let generated = config.generate().unwrap();
            validate_generated_document(generated.contents(), version).unwrap();
            assert!(generated.contents().len() <= MAX_GENERATED_REDIS_CONFIG_BYTES);
        }
    }

    #[test]
    fn generated_validator_rejects_unknown_sensitive_and_unsafe_network_directives() {
        let baseline = RedisConfig::baseline(RedisVersion::V8_8)
            .generate()
            .unwrap()
            .contents()
            .to_owned();
        for injected in [
            "requirepass exposed-secret\n",
            "aclfile /tmp/users.acl\n",
            "user default on >secret ~* +@all\n",
            "rename-command CONFIG hidden\n",
        ] {
            let mut malicious = baseline.clone();
            malicious.push_str(injected);
            assert!(
                validate_generated_document(&malicious, RedisVersion::V8_8).is_err(),
                "{injected:?}"
            );
        }

        let exposed = baseline.replace("bind 127.0.0.1 -::1", "bind 0.0.0.0 ::");
        assert!(validate_generated_document(&exposed, RedisVersion::V8_8).is_err());
        let unprotected = baseline.replace("protected-mode yes", "protected-mode no");
        assert!(validate_generated_document(&unprotected, RedisVersion::V8_8).is_err());

        let no_persistence = baseline
            .replace("appendonly yes\nappendfsync everysec\n", "appendonly no\n")
            .replace(
                "save 3600 1\nsave 300 100\nsave 60 10000\nstop-writes-on-bgsave-error yes\nrdbcompression yes\nrdbchecksum yes\n",
                "save \"\"\n",
            );
        assert!(validate_generated_document(&no_persistence, RedisVersion::V8_8).is_err());

        let missing_scope_warning = baseline.replace(
            "# EMPTY INSTANCE ONLY — DO NOT APPLY TO AN EXISTING DATA-BEARING REDIS INSTANCE.\n",
            "",
        );
        assert!(validate_generated_document(&missing_scope_warning, RedisVersion::V8_8).is_err());
    }

    #[test]
    fn redis_catalog_inline_editor_and_preview_prerequisites_are_typed_and_byte_exact() {
        let feature = RedisConfigFeature::SlowLog;
        assert_eq!(feature.key(), "slow-log");
        assert_eq!(feature.title(), "记录慢命令");
        assert_eq!(
            feature.summary(),
            "用类型化微秒阈值和有界队列记录慢命令；不记录命令执行时间之外的 I/O。"
        );
        assert_eq!(feature.scope(), "可观测性");
        assert_eq!(feature.aliases(), ["slowlog", "慢命令", "慢日志"]);
        assert!(feature.default_enabled());
        assert!(
            RedisVersion::ALL
                .into_iter()
                .all(|version| feature.supports_version(version))
        );

        let selected = RedisSlowLogConfig::new(25_000, 256).unwrap();
        assert_eq!(selected.threshold_microseconds(), 25_000);
        assert_eq!(selected.maximum_entries(), 256);
        let baseline = RedisConfig::baseline(RedisVersion::V8_10)
            .generate()
            .unwrap();
        let generated = RedisConfig::baseline(RedisVersion::V8_10)
            .with_slow_log(selected)
            .unwrap()
            .generate()
            .unwrap();
        assert_eq!(
            generated.contents(),
            baseline.contents().replace(
                "slowlog-log-slower-than 10000\nslowlog-max-len 128\n",
                "slowlog-log-slower-than 25000\nslowlog-max-len 256\n",
            )
        );
        assert_eq!(
            generated
                .contents()
                .lines()
                .filter(|line| line.starts_with("slowlog-"))
                .collect::<Vec<_>>(),
            ["slowlog-log-slower-than 25000", "slowlog-max-len 256",]
        );

        let removed = RedisConfig::baseline(RedisVersion::V8_10)
            .with_feature(RedisConfigFeature::SlowLog, false)
            .unwrap()
            .generate()
            .unwrap();
        assert_eq!(
            removed.contents(),
            baseline.contents().replace(
                "slowlog-log-slower-than 10000\nslowlog-max-len 128\n",
                "slowlog-log-slower-than -1\n",
            )
        );
        assert_eq!(
            removed
                .contents()
                .lines()
                .filter(|line| line.starts_with("slowlog-"))
                .collect::<Vec<_>>(),
            ["slowlog-log-slower-than -1"]
        );

        assert!(RedisSlowLogConfig::new(0, 1).is_ok());
        assert!(
            RedisSlowLogConfig::new(
                MAX_SLOWLOG_THRESHOLD_MICROSECONDS,
                MAX_SLOWLOG_LENGTH as u32,
            )
            .is_ok()
        );
        assert!(RedisSlowLogConfig::new(MAX_SLOWLOG_THRESHOLD_MICROSECONDS + 1, 128).is_err());
        assert!(RedisSlowLogConfig::new(10_000, 0).is_err());
        assert!(RedisSlowLogConfig::new(10_000, MAX_SLOWLOG_LENGTH as u32 + 1).is_err());
    }

    #[test]
    fn redis_quick_stack_remove_reset_and_save_prerequisite_is_byte_exact() {
        let baseline_config = RedisConfig::baseline(RedisVersion::V8_10);
        let baseline = baseline_config.generate().unwrap();
        for expected in [
            "Redis Open Source 8.10",
            "EMPTY INSTANCE ONLY",
            "bind 127.0.0.1 -::1",
            "protected-mode yes",
            "port 6379",
            "dir /var/lib/redis",
            "maxclients 10000",
            "maxmemory 536870912",
            "appendonly yes",
            "appendfsync everysec",
            "save 3600 1",
            "slowlog-log-slower-than 10000",
        ] {
            assert!(baseline.contents().contains(expected), "{expected}");
        }

        let stacked_config = baseline_config
            .clone()
            .with_idle_timeout(RedisIdleTimeoutSeconds::parse("600").unwrap())
            .unwrap()
            .with_latency_threshold(RedisLatencyThresholdMilliseconds::parse("50").unwrap())
            .unwrap()
            .with_eviction_policy(RedisEvictionPolicy::AllKeysLru)
            .unwrap();
        let stacked = stacked_config.generate().unwrap();
        for expected in [
            "timeout 600\n",
            "latency-monitor-threshold 50\n",
            "maxmemory-policy allkeys-lru\n",
        ] {
            assert!(stacked.contents().contains(expected), "{expected}");
        }

        let remaining_config = stacked_config
            .with_feature(RedisConfigFeature::IdleClientTimeout, false)
            .unwrap();
        let remaining = remaining_config.generate().unwrap();
        assert!(remaining.contents().contains("timeout 0\n"));
        assert!(
            remaining
                .contents()
                .contains("latency-monitor-threshold 50\n")
        );
        assert!(
            remaining
                .contents()
                .contains("maxmemory-policy allkeys-lru\n")
        );
        assert!(
            remaining_config
                .clone()
                .with_feature(RedisConfigFeature::MemoryLimit, false)
                .is_err()
        );
        assert_eq!(remaining_config.generate().unwrap(), remaining);

        let rdb_only_config = remaining_config
            .with_feature(RedisConfigFeature::AofPersistence, false)
            .unwrap();
        let rdb_only = rdb_only_config.generate().unwrap();
        assert!(rdb_only.contents().contains("appendonly no\n"));
        assert!(rdb_only.contents().contains("save 3600 1\n"));
        assert!(
            rdb_only_config
                .clone()
                .with_feature(RedisConfigFeature::RdbPersistence, false)
                .is_err()
        );
        assert_eq!(rdb_only_config.generate().unwrap(), rdb_only);

        let reset = RedisConfig::baseline(RedisVersion::V8_10)
            .generate()
            .unwrap();
        assert_eq!(reset, baseline);
        assert_eq!(reset.suggested_file_name(), "redis-new-empty-instance.conf");

        let root = TestRoot::new();
        let destination = root.0.join(reset.suggested_file_name());
        assert_eq!(reset.write_new(&destination).unwrap(), destination);
        assert_eq!(
            fs::read(&destination).unwrap(),
            baseline.contents().as_bytes()
        );
        assert!(reset.write_new(&destination).is_err());
        assert_eq!(
            fs::read(&destination).unwrap(),
            baseline.contents().as_bytes()
        );
    }

    #[test]
    fn generated_output_is_exclusively_created_and_never_overwrites() {
        let root = TestRoot::new();
        let destination = root.0.join("redis.conf");
        let generated = RedisConfig::baseline(RedisVersion::V8_8)
            .generate()
            .unwrap();
        assert_eq!(
            generated.suggested_file_name(),
            "redis-new-empty-instance.conf"
        );
        assert_eq!(generated.write_new(&destination).unwrap(), destination);
        assert_eq!(
            fs::read_to_string(&destination).unwrap(),
            generated.contents()
        );

        fs::write(&destination, "owned-by-user\n").unwrap();
        assert!(generated.write_new(&destination).is_err());
        assert_eq!(fs::read_to_string(&destination).unwrap(), "owned-by-user\n");
    }

    #[test]
    fn write_and_cleanup_failures_are_both_visible_to_the_caller() {
        let root = TestRoot::new();
        let destination = root.0.join("partial.conf");
        let write_error = CoreError::validation("test Redis write", "disk full");
        let combined = combine_write_and_cleanup_result(
            &destination,
            write_error,
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "cleanup denied",
            )),
        );
        let message = combined.to_string();
        assert!(message.contains("disk full"));
        assert!(message.contains("cleanup denied"));
        assert!(message.contains("partial.conf"));

        let original = combine_write_and_cleanup_result(
            &destination,
            CoreError::validation("test Redis write", "short write"),
            Ok(()),
        );
        assert!(original.to_string().contains("short write"));
    }

    #[test]
    fn export_destination_requires_existing_absolute_parent_and_conf_extension() {
        let root = TestRoot::new();
        let generated = RedisConfig::baseline(RedisVersion::V7_2)
            .generate()
            .unwrap();
        assert!(generated.write_new(Path::new("redis.conf")).is_err());
        assert!(generated.write_new(&root.0.join("redis.txt")).is_err());
        assert!(
            generated
                .write_new(&root.0.join("missing").join("redis.conf"))
                .is_err()
        );
        assert!(
            generated
                .write_new(&root.0.join("child").join("..").join("redis.conf"))
                .is_err()
        );
    }
}
