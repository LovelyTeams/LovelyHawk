//! Deterministic generation of a closed MySQL 8.4 `[mysqld]` configuration.
//!
//! The supported settings and ranges are intentionally narrower than the
//! server's complete option surface. They are based on the MySQL 8.4 Reference
//! Manual sections for [server system variables], [binary logging options], and
//! [replication options]. TLS, Enterprise Audit, plugin configuration, arbitrary
//! paths, and arbitrary key/value parameters are deliberately not represented.
//!
//! [server system variables]: https://dev.mysql.com/doc/refman/8.4/en/server-system-variables.html
//! [binary logging options]: https://dev.mysql.com/doc/refman/8.4/en/replication-options-binary-log.html
//! [replication options]: https://dev.mysql.com/doc/refman/8.4/en/replication-options.html
//! [configuration validation]: https://dev.mysql.com/doc/refman/8.4/en/server-options.html#option_mysqld_validate-config

use std::{
    collections::{BTreeSet, HashSet},
    error::Error,
    fmt,
    fs::{self, OpenOptions},
    io::{self, Write},
    net::IpAddr,
    path::{Component, Path, PathBuf},
};

pub const MAX_GENERATED_MYSQL_CONFIG_BYTES: usize = 16 * 1024;
const SUGGESTED_FILE_NAME: &str = "my.cnf";
const MYSQL_MAJOR: u16 = 8;
const MYSQL_MINOR: u16 = 4;
const MAX_SECONDS_PER_YEAR: u32 = 31_536_000;
const MAX_PORTABLE_WAIT_TIMEOUT_SECONDS: u32 = 2_147_483;
const DEFAULT_BINLOG_RETENTION_SECONDS: u32 = 2_592_000;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MySqlConfigVersion {
    major: u16,
    minor: u16,
    patch: u16,
}

impl MySqlConfigVersion {
    /// Construct a version in the only supported family: MySQL 8.4.x.
    pub fn new(major: u16, minor: u16, patch: u16) -> Result<Self, MySqlConfigError> {
        if major != MYSQL_MAJOR || minor != MYSQL_MINOR {
            return Err(MySqlConfigError::UnsupportedVersion {
                major,
                minor,
                patch,
            });
        }
        Ok(Self {
            major,
            minor,
            patch,
        })
    }

    pub const fn major(self) -> u16 {
        self.major
    }

    pub const fn minor(self) -> u16 {
        self.minor
    }

    pub const fn patch(self) -> u16 {
        self.patch
    }
}

impl fmt::Display for MySqlConfigVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MySqlConfigFeature {
    RemoteListener,
    DisableTcp,
    SkipNameResolve,
    MaxConnections,
    ConnectTimeout,
    MaxConnectErrors,
    SessionTimeouts,
    SlowQueryLog,
    GeneralLog,
    LogErrorVerbosity,
    DisableFileImportExport,
    ReadOnlyReplica,
    BinaryLogging,
    BinaryLogRetention,
    EnableLocalInfile,
}

impl MySqlConfigFeature {
    pub const ALL: [Self; 15] = [
        Self::RemoteListener,
        Self::DisableTcp,
        Self::SkipNameResolve,
        Self::MaxConnections,
        Self::ConnectTimeout,
        Self::MaxConnectErrors,
        Self::SessionTimeouts,
        Self::SlowQueryLog,
        Self::GeneralLog,
        Self::LogErrorVerbosity,
        Self::DisableFileImportExport,
        Self::ReadOnlyReplica,
        Self::BinaryLogging,
        Self::BinaryLogRetention,
        Self::EnableLocalInfile,
    ];

    pub const fn key(self) -> &'static str {
        match self {
            Self::RemoteListener => "remote-listener",
            Self::DisableTcp => "disable-tcp",
            Self::SkipNameResolve => "skip-name-resolve",
            Self::MaxConnections => "max-connections",
            Self::ConnectTimeout => "connect-timeout",
            Self::MaxConnectErrors => "max-connect-errors",
            Self::SessionTimeouts => "session-timeouts",
            Self::SlowQueryLog => "slow-query-log",
            Self::GeneralLog => "general-log",
            Self::LogErrorVerbosity => "log-error-verbosity",
            Self::DisableFileImportExport => "disable-file-import-export",
            Self::ReadOnlyReplica => "read-only-replica",
            Self::BinaryLogging => "binary-logging",
            Self::BinaryLogRetention => "binary-log-retention",
            Self::EnableLocalInfile => "enable-local-infile",
        }
    }

    pub const fn title(self) -> &'static str {
        match self {
            Self::RemoteListener => "允许远程经典协议监听",
            Self::DisableTcp => "关闭 TCP 连接",
            Self::SkipNameResolve => "关闭客户端主机名解析",
            Self::MaxConnections => "限制最大连接数",
            Self::ConnectTimeout => "配置握手超时",
            Self::MaxConnectErrors => "配置主机连接错误阈值",
            Self::SessionTimeouts => "配置会话空闲超时",
            Self::SlowQueryLog => "启用慢查询日志",
            Self::GeneralLog => "启用通用查询日志",
            Self::LogErrorVerbosity => "配置错误日志详细级别",
            Self::DisableFileImportExport => "禁止服务端文件导入导出",
            Self::ReadOnlyReplica => "启用只读副本保护",
            Self::BinaryLogging => "配置二进制日志标识",
            Self::BinaryLogRetention => "配置二进制日志保留时间",
            Self::EnableLocalInfile => "允许 LOCAL 数据导入",
        }
    }

    pub const fn summary(self) -> &'static str {
        match self {
            Self::RemoteListener => {
                "将经典 MySQL 协议的 bind_address 从本机回环地址改为一个规范 IP；X Plugin 仍关闭，且不会代替账号 Host、TLS 或主机防火墙配置。"
            }
            Self::DisableTcp => "设置 skip_networking，拒绝 TCP/IP 客户端连接。",
            Self::SkipNameResolve => "连接检查仅使用 IP；授权表中的 Host 应使用 IP 或 localhost。",
            Self::MaxConnections => "设置服务器可同时接受的客户端连接数量上限。",
            Self::ConnectTimeout => "限制服务器等待客户端完成初始握手的秒数。",
            Self::MaxConnectErrors => "主机连续连接失败达到阈值后阻止其继续连接。",
            Self::SessionTimeouts => "分别设置非交互和交互连接的空闲关闭时间。",
            Self::SlowQueryLog => "写入 FILE 慢查询日志，并设置整秒 long_query_time。",
            Self::GeneralLog => "将已建立连接和收到的语句写入 FILE 通用查询日志。",
            Self::LogErrorVerbosity => "设置错误日志包含错误、警告及信息消息的级别。",
            Self::DisableFileImportExport => {
                "将 secure_file_priv 固定为 NULL，禁止服务端导入导出操作。"
            }
            Self::ReadOnlyReplica => {
                "同时启用 read_only 与 super_read_only；文档规定的管理例外仍存在。"
            }
            Self::BinaryLogging => {
                "使用固定 basename binlog 和非零 server_id；MySQL 8.4 默认使用 ROW，本模块不写入已弃用的 binlog_format。"
            }
            Self::BinaryLogRetention => "设置自动清理二进制日志的保留秒数；依赖二进制日志配置。",
            Self::EnableLocalInfile => "将 Baseline 的 local_infile=OFF 显式改为 ON。",
        }
    }

    pub const fn scope(self) -> &'static str {
        match self {
            Self::RemoteListener | Self::DisableTcp | Self::SkipNameResolve => "网络",
            Self::MaxConnections
            | Self::ConnectTimeout
            | Self::MaxConnectErrors
            | Self::SessionTimeouts => "连接",
            Self::SlowQueryLog | Self::GeneralLog | Self::LogErrorVerbosity => "日志",
            Self::DisableFileImportExport | Self::EnableLocalInfile => "文件导入",
            Self::ReadOnlyReplica => "副本保护",
            Self::BinaryLogging | Self::BinaryLogRetention => "二进制日志",
        }
    }

    /// Baseline settings are rendered independently and cannot be removed.
    /// Every optional catalog feature therefore starts disabled.
    pub const fn default_enabled(self) -> bool {
        false
    }

    pub const fn aliases(self) -> &'static [&'static str] {
        match self {
            Self::RemoteListener => &["远程访问", "bind_address", "0.0.0.0", "监听地址"],
            Self::DisableTcp => &["关闭 TCP", "skip_networking", "socket only"],
            Self::SkipNameResolve => &["DNS", "skip_name_resolve", "主机名解析"],
            Self::MaxConnections => &["max_connections", "最大连接", "并发连接"],
            Self::ConnectTimeout => &["connect_timeout", "握手超时", "连接超时"],
            Self::MaxConnectErrors => &["max_connect_errors", "连接错误", "host cache"],
            Self::SessionTimeouts => &[
                "wait_timeout",
                "interactive_timeout",
                "空闲超时",
                "会话超时",
            ],
            Self::SlowQueryLog => &["slow_query_log", "long_query_time", "慢 SQL"],
            Self::GeneralLog => &["general_log", "通用日志", "查询日志"],
            Self::LogErrorVerbosity => &["log_error_verbosity", "错误日志", "日志级别"],
            Self::DisableFileImportExport => &[
                "secure_file_priv",
                "LOAD DATA",
                "SELECT INTO OUTFILE",
                "禁止导入导出",
            ],
            Self::ReadOnlyReplica => &["read_only", "super_read_only", "只读", "副本"],
            Self::BinaryLogging => &["log_bin", "server_id", "ROW", "binlog", "复制"],
            Self::BinaryLogRetention => &["binlog_expire_logs_seconds", "binlog 保留", "自动清理"],
            Self::EnableLocalInfile => &["local_infile", "LOAD DATA LOCAL", "本地导入"],
        }
    }

    pub const fn owned_keys(self) -> &'static [&'static str] {
        match self {
            Self::RemoteListener => &["bind_address"],
            Self::DisableTcp => &["skip_networking"],
            Self::SkipNameResolve => &["skip_name_resolve"],
            Self::MaxConnections => &["max_connections"],
            Self::ConnectTimeout => &["connect_timeout"],
            Self::MaxConnectErrors => &["max_connect_errors"],
            Self::SessionTimeouts => &["wait_timeout", "interactive_timeout"],
            Self::SlowQueryLog => &["slow_query_log", "long_query_time"],
            Self::GeneralLog => &["general_log"],
            Self::LogErrorVerbosity => &["log_error_verbosity"],
            Self::DisableFileImportExport => &["secure_file_priv"],
            Self::ReadOnlyReplica => &["read_only", "super_read_only"],
            Self::BinaryLogging => &["log_bin", "server_id"],
            Self::BinaryLogRetention => &["binlog_expire_logs_seconds"],
            Self::EnableLocalInfile => &["local_infile"],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MySqlSettingOwner {
    Baseline,
    Feature(MySqlConfigFeature),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MySqlOwnedSetting {
    key: &'static str,
    value: String,
    owner: MySqlSettingOwner,
}

impl MySqlOwnedSetting {
    pub const fn key(&self) -> &'static str {
        self.key
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    pub const fn owner(&self) -> MySqlSettingOwner {
        self.owner
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MySqlConfig {
    version: MySqlConfigVersion,
    features: BTreeSet<MySqlConfigFeature>,
    remote_listener: Option<IpAddr>,
    max_connections: u32,
    connect_timeout_seconds: u32,
    max_connect_errors: u64,
    wait_timeout_seconds: u32,
    interactive_timeout_seconds: u32,
    long_query_time_seconds: u32,
    log_error_verbosity: u8,
    server_id: u32,
    binlog_expire_logs_seconds: u32,
}

impl MySqlConfig {
    /// Create the immutable safe Baseline and no optional features.
    ///
    /// The Baseline binds to `127.0.0.1`, listens on port 3306, writes selected
    /// logs to files, and fixes `local_infile` to `OFF`. Optional features are
    /// recomposed over those values rather than editing arbitrary text.
    pub fn baseline(version: MySqlConfigVersion) -> Self {
        Self {
            version,
            features: BTreeSet::new(),
            remote_listener: None,
            max_connections: 151,
            connect_timeout_seconds: 10,
            max_connect_errors: 100,
            wait_timeout_seconds: 28_800,
            interactive_timeout_seconds: 28_800,
            long_query_time_seconds: 10,
            log_error_verbosity: 2,
            server_id: 1,
            binlog_expire_logs_seconds: DEFAULT_BINLOG_RETENTION_SECONDS,
        }
    }

    pub const fn version(&self) -> MySqlConfigVersion {
        self.version
    }

    pub fn enabled_features(&self) -> &BTreeSet<MySqlConfigFeature> {
        &self.features
    }

    pub fn feature_enabled(&self, feature: MySqlConfigFeature) -> bool {
        self.features.contains(&feature)
    }

    pub fn with_feature(
        mut self,
        feature: MySqlConfigFeature,
        enabled: bool,
    ) -> Result<Self, MySqlConfigError> {
        if feature == MySqlConfigFeature::RemoteListener {
            if enabled {
                return Err(MySqlConfigError::MissingRequiredValue {
                    feature,
                    field: "bind_address",
                });
            }
            self.remote_listener = None;
        }
        if enabled {
            self.features.insert(feature);
        } else {
            self.features.remove(&feature);
        }
        self.validate_feature_compatibility()?;
        Ok(self)
    }

    pub fn with_remote_listener(mut self, address: IpAddr) -> Result<Self, MySqlConfigError> {
        self.remote_listener = Some(address);
        self.features.insert(MySqlConfigFeature::RemoteListener);
        self.validate_feature_compatibility()?;
        Ok(self)
    }

    pub fn with_max_connections(mut self, value: u32) -> Result<Self, MySqlConfigError> {
        validate_range("max_connections", u64::from(value), 1, 100_000)?;
        self.max_connections = value;
        self.features.insert(MySqlConfigFeature::MaxConnections);
        Ok(self)
    }

    pub fn with_connect_timeout_seconds(mut self, value: u32) -> Result<Self, MySqlConfigError> {
        validate_range(
            "connect_timeout",
            u64::from(value),
            2,
            u64::from(MAX_SECONDS_PER_YEAR),
        )?;
        self.connect_timeout_seconds = value;
        self.features.insert(MySqlConfigFeature::ConnectTimeout);
        Ok(self)
    }

    pub fn with_max_connect_errors(mut self, value: u64) -> Result<Self, MySqlConfigError> {
        validate_range("max_connect_errors", value, 1, u64::from(u32::MAX))?;
        self.max_connect_errors = value;
        self.features.insert(MySqlConfigFeature::MaxConnectErrors);
        Ok(self)
    }

    pub fn with_session_timeouts_seconds(
        mut self,
        wait_timeout: u32,
        interactive_timeout: u32,
    ) -> Result<Self, MySqlConfigError> {
        validate_range(
            "wait_timeout",
            u64::from(wait_timeout),
            1,
            u64::from(MAX_PORTABLE_WAIT_TIMEOUT_SECONDS),
        )?;
        validate_range(
            "interactive_timeout",
            u64::from(interactive_timeout),
            1,
            u64::from(MAX_SECONDS_PER_YEAR),
        )?;
        self.wait_timeout_seconds = wait_timeout;
        self.interactive_timeout_seconds = interactive_timeout;
        self.features.insert(MySqlConfigFeature::SessionTimeouts);
        Ok(self)
    }

    pub fn with_slow_query_log_seconds(
        mut self,
        long_query_time: u32,
    ) -> Result<Self, MySqlConfigError> {
        validate_range(
            "long_query_time",
            u64::from(long_query_time),
            0,
            u64::from(MAX_SECONDS_PER_YEAR),
        )?;
        self.long_query_time_seconds = long_query_time;
        self.features.insert(MySqlConfigFeature::SlowQueryLog);
        Ok(self)
    }

    pub fn with_log_error_verbosity(mut self, value: u8) -> Result<Self, MySqlConfigError> {
        validate_range("log_error_verbosity", u64::from(value), 1, 3)?;
        self.log_error_verbosity = value;
        self.features.insert(MySqlConfigFeature::LogErrorVerbosity);
        Ok(self)
    }

    pub fn with_binary_logging(mut self, server_id: u32) -> Result<Self, MySqlConfigError> {
        validate_range("server_id", u64::from(server_id), 1, u64::from(u32::MAX))?;
        self.server_id = server_id;
        self.features.insert(MySqlConfigFeature::BinaryLogging);
        Ok(self)
    }

    pub fn with_binary_log_retention_seconds(
        mut self,
        value: u32,
    ) -> Result<Self, MySqlConfigError> {
        validate_range(
            "binlog_expire_logs_seconds",
            u64::from(value),
            1,
            u64::from(u32::MAX),
        )?;
        self.binlog_expire_logs_seconds = value;
        self.features.insert(MySqlConfigFeature::BinaryLogRetention);
        self.validate_feature_compatibility()?;
        Ok(self)
    }

    pub fn generate(&self) -> Result<GeneratedMySqlConfig, MySqlConfigError> {
        self.validate_values()?;
        self.validate_feature_compatibility()?;
        let settings = self.compose_settings()?;

        let mut contents = String::with_capacity(1_024);
        contents.push_str("# LovelyRes generated MySQL 8.4 configuration\n");
        contents.push_str("# Target version: MySQL ");
        contents.push_str(&self.version.to_string());
        contents.push_str(
            "\n# Validate with matching MySQL 8.4: mysqld --defaults-file=<path> --validate-config.\n",
        );
        contents.push_str("[mysqld]\n");
        for setting in &settings {
            contents.push_str(setting.key());
            contents.push_str(" = ");
            contents.push_str(setting.value());
            contents.push('\n');
        }

        validate_generated_mysql_config_document(&contents)?;
        Ok(GeneratedMySqlConfig {
            version: self.version,
            contents,
            settings,
        })
    }

    fn validate_values(&self) -> Result<(), MySqlConfigError> {
        validate_range(
            "max_connections",
            u64::from(self.max_connections),
            1,
            100_000,
        )?;
        validate_range(
            "connect_timeout",
            u64::from(self.connect_timeout_seconds),
            2,
            u64::from(MAX_SECONDS_PER_YEAR),
        )?;
        validate_range(
            "max_connect_errors",
            self.max_connect_errors,
            1,
            u64::from(u32::MAX),
        )?;
        validate_range(
            "wait_timeout",
            u64::from(self.wait_timeout_seconds),
            1,
            u64::from(MAX_PORTABLE_WAIT_TIMEOUT_SECONDS),
        )?;
        validate_range(
            "interactive_timeout",
            u64::from(self.interactive_timeout_seconds),
            1,
            u64::from(MAX_SECONDS_PER_YEAR),
        )?;
        validate_range(
            "long_query_time",
            u64::from(self.long_query_time_seconds),
            0,
            u64::from(MAX_SECONDS_PER_YEAR),
        )?;
        validate_range(
            "log_error_verbosity",
            u64::from(self.log_error_verbosity),
            1,
            3,
        )?;
        validate_range(
            "server_id",
            u64::from(self.server_id),
            1,
            u64::from(u32::MAX),
        )?;
        validate_range(
            "binlog_expire_logs_seconds",
            u64::from(self.binlog_expire_logs_seconds),
            1,
            u64::from(u32::MAX),
        )
    }

    fn validate_feature_compatibility(&self) -> Result<(), MySqlConfigError> {
        if self.feature_enabled(MySqlConfigFeature::RemoteListener)
            && self.remote_listener.is_none()
        {
            return Err(MySqlConfigError::MissingRequiredValue {
                feature: MySqlConfigFeature::RemoteListener,
                field: "bind_address",
            });
        }
        if self.feature_enabled(MySqlConfigFeature::RemoteListener)
            && self.feature_enabled(MySqlConfigFeature::DisableTcp)
        {
            return Err(MySqlConfigError::ConflictingFeatures {
                first: MySqlConfigFeature::RemoteListener,
                second: MySqlConfigFeature::DisableTcp,
            });
        }
        if self.feature_enabled(MySqlConfigFeature::BinaryLogRetention)
            && !self.feature_enabled(MySqlConfigFeature::BinaryLogging)
        {
            return Err(MySqlConfigError::MissingRequiredFeature {
                feature: MySqlConfigFeature::BinaryLogRetention,
                required: MySqlConfigFeature::BinaryLogging,
            });
        }
        Ok(())
    }

    fn compose_settings(&self) -> Result<Vec<MySqlOwnedSetting>, MySqlConfigError> {
        let mut settings = Vec::with_capacity(24);

        if self.feature_enabled(MySqlConfigFeature::RemoteListener) {
            let remote_listener =
                self.remote_listener
                    .ok_or(MySqlConfigError::MissingRequiredValue {
                        feature: MySqlConfigFeature::RemoteListener,
                        field: "bind_address",
                    })?;
            push_unique_setting(
                &mut settings,
                MySqlConfigFeature::RemoteListener,
                "bind_address",
                remote_listener.to_string(),
            )?;
        } else {
            push_unique_baseline_setting(&mut settings, "bind_address", "127.0.0.1")?;
        }
        push_unique_baseline_setting(&mut settings, "port", "3306")?;
        // MySQL 8.4 enables X Plugin by default and otherwise listens on all
        // interfaces via port 33060. This closed generator does not yet model
        // X Protocol, so the Baseline disables it explicitly instead of
        // leaving an unrepresented network listener open.
        push_unique_baseline_setting(&mut settings, "mysqlx", "OFF")?;
        if self.feature_enabled(MySqlConfigFeature::EnableLocalInfile) {
            push_unique_setting(
                &mut settings,
                MySqlConfigFeature::EnableLocalInfile,
                "local_infile",
                "ON",
            )?;
        } else {
            push_unique_baseline_setting(&mut settings, "local_infile", "OFF")?;
        }
        push_unique_baseline_setting(&mut settings, "log_output", "FILE")?;

        for feature in MySqlConfigFeature::ALL {
            if !self.feature_enabled(feature)
                || matches!(
                    feature,
                    MySqlConfigFeature::RemoteListener | MySqlConfigFeature::EnableLocalInfile
                )
            {
                continue;
            }
            match feature {
                MySqlConfigFeature::RemoteListener | MySqlConfigFeature::EnableLocalInfile => {}
                MySqlConfigFeature::DisableTcp => {
                    push_unique_setting(&mut settings, feature, "skip_networking", "ON")?;
                }
                MySqlConfigFeature::SkipNameResolve => {
                    push_unique_setting(&mut settings, feature, "skip_name_resolve", "ON")?;
                }
                MySqlConfigFeature::MaxConnections => push_unique_setting(
                    &mut settings,
                    feature,
                    "max_connections",
                    self.max_connections.to_string(),
                )?,
                MySqlConfigFeature::ConnectTimeout => push_unique_setting(
                    &mut settings,
                    feature,
                    "connect_timeout",
                    self.connect_timeout_seconds.to_string(),
                )?,
                MySqlConfigFeature::MaxConnectErrors => push_unique_setting(
                    &mut settings,
                    feature,
                    "max_connect_errors",
                    self.max_connect_errors.to_string(),
                )?,
                MySqlConfigFeature::SessionTimeouts => {
                    push_unique_setting(
                        &mut settings,
                        feature,
                        "wait_timeout",
                        self.wait_timeout_seconds.to_string(),
                    )?;
                    push_unique_setting(
                        &mut settings,
                        feature,
                        "interactive_timeout",
                        self.interactive_timeout_seconds.to_string(),
                    )?;
                }
                MySqlConfigFeature::SlowQueryLog => {
                    push_unique_setting(&mut settings, feature, "slow_query_log", "ON")?;
                    push_unique_setting(
                        &mut settings,
                        feature,
                        "long_query_time",
                        self.long_query_time_seconds.to_string(),
                    )?;
                }
                MySqlConfigFeature::GeneralLog => {
                    push_unique_setting(&mut settings, feature, "general_log", "ON")?;
                }
                MySqlConfigFeature::LogErrorVerbosity => push_unique_setting(
                    &mut settings,
                    feature,
                    "log_error_verbosity",
                    self.log_error_verbosity.to_string(),
                )?,
                MySqlConfigFeature::DisableFileImportExport => {
                    push_unique_setting(&mut settings, feature, "secure_file_priv", "NULL")?;
                }
                MySqlConfigFeature::ReadOnlyReplica => {
                    push_unique_setting(&mut settings, feature, "read_only", "ON")?;
                    push_unique_setting(&mut settings, feature, "super_read_only", "ON")?;
                }
                MySqlConfigFeature::BinaryLogging => {
                    push_unique_setting(&mut settings, feature, "log_bin", "binlog")?;
                    push_unique_setting(
                        &mut settings,
                        feature,
                        "server_id",
                        self.server_id.to_string(),
                    )?;
                }
                MySqlConfigFeature::BinaryLogRetention => push_unique_setting(
                    &mut settings,
                    feature,
                    "binlog_expire_logs_seconds",
                    self.binlog_expire_logs_seconds.to_string(),
                )?,
            }
        }
        validate_setting_ownership(&settings, &self.features)?;
        Ok(settings)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedMySqlConfig {
    version: MySqlConfigVersion,
    contents: String,
    settings: Vec<MySqlOwnedSetting>,
}

impl GeneratedMySqlConfig {
    pub const fn version(&self) -> MySqlConfigVersion {
        self.version
    }

    pub fn contents(&self) -> &str {
        &self.contents
    }

    pub fn settings(&self) -> &[MySqlOwnedSetting] {
        &self.settings
    }

    pub const fn suggested_file_name(&self) -> &'static str {
        SUGGESTED_FILE_NAME
    }

    /// Write a generated `.cnf` or `.ini` to a new native-dialog destination.
    /// Existing files are never replaced.
    pub fn write_new(&self, destination: &Path) -> Result<PathBuf, MySqlConfigError> {
        validate_export_destination(destination)?;
        validate_generated_mysql_config_document(&self.contents)?;

        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(destination)
            .map_err(|source| MySqlConfigError::Io {
                operation: "create generated MySQL configuration",
                path: destination.to_path_buf(),
                source,
            })?;
        let write_result = (|| {
            file.write_all(self.contents.as_bytes())
                .map_err(|source| MySqlConfigError::Io {
                    operation: "write generated MySQL configuration",
                    path: destination.to_path_buf(),
                    source,
                })?;
            file.flush().map_err(|source| MySqlConfigError::Io {
                operation: "flush generated MySQL configuration",
                path: destination.to_path_buf(),
                source,
            })?;
            file.sync_all().map_err(|source| MySqlConfigError::Io {
                operation: "sync generated MySQL configuration",
                path: destination.to_path_buf(),
                source,
            })
        })();
        drop(file);

        if let Err(write_error) = write_result {
            if let Err(source) = fs::remove_file(destination) {
                return Err(MySqlConfigError::PartialFileCleanup {
                    path: destination.to_path_buf(),
                    write_error: Box::new(write_error),
                    source,
                });
            }
            return Err(write_error);
        }
        Ok(destination.to_path_buf())
    }
}

#[derive(Debug)]
pub enum MySqlConfigError {
    UnsupportedVersion {
        major: u16,
        minor: u16,
        patch: u16,
    },
    ValueOutOfRange {
        field: &'static str,
        minimum: u64,
        maximum: u64,
        actual: u64,
    },
    ConflictingFeatures {
        first: MySqlConfigFeature,
        second: MySqlConfigFeature,
    },
    MissingRequiredFeature {
        feature: MySqlConfigFeature,
        required: MySqlConfigFeature,
    },
    MissingRequiredValue {
        feature: MySqlConfigFeature,
        field: &'static str,
    },
    DuplicateSetting {
        key: String,
    },
    InvalidFeatureOwnership {
        detail: String,
    },
    InvalidDocument {
        detail: String,
    },
    InvalidDestination {
        detail: String,
    },
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    PartialFileCleanup {
        path: PathBuf,
        write_error: Box<MySqlConfigError>,
        source: io::Error,
    },
}

impl fmt::Display for MySqlConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion {
                major,
                minor,
                patch,
            } => write!(
                formatter,
                "unsupported MySQL version {major}.{minor}.{patch}; only MySQL 8.4.x is supported"
            ),
            Self::ValueOutOfRange {
                field,
                minimum,
                maximum,
                actual,
            } => write!(
                formatter,
                "{field} must be in {minimum}..={maximum}, got {actual}"
            ),
            Self::ConflictingFeatures { first, second } => write!(
                formatter,
                "MySQL features {} and {} are mutually exclusive",
                first.key(),
                second.key()
            ),
            Self::MissingRequiredFeature { feature, required } => write!(
                formatter,
                "MySQL feature {} requires {}",
                feature.key(),
                required.key()
            ),
            Self::MissingRequiredValue { feature, field } => write!(
                formatter,
                "MySQL feature {} requires a typed value for {field}",
                feature.key()
            ),
            Self::DuplicateSetting { key } => {
                write!(formatter, "generated MySQL setting {key} is duplicated")
            }
            Self::InvalidFeatureOwnership { detail } => {
                write!(formatter, "invalid MySQL feature ownership: {detail}")
            }
            Self::InvalidDocument { detail } => {
                write!(formatter, "invalid generated MySQL configuration: {detail}")
            }
            Self::InvalidDestination { detail } => {
                write!(
                    formatter,
                    "invalid MySQL configuration destination: {detail}"
                )
            }
            Self::Io {
                operation,
                path,
                source,
            } => write!(formatter, "{operation} at {}: {source}", path.display()),
            Self::PartialFileCleanup {
                path,
                write_error,
                source,
            } => write!(
                formatter,
                "{write_error}; also failed to remove partial file {}: {source}",
                path.display()
            ),
        }
    }
}

impl Error for MySqlConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } | Self::PartialFileCleanup { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn validate_range(
    field: &'static str,
    actual: u64,
    minimum: u64,
    maximum: u64,
) -> Result<(), MySqlConfigError> {
    if !(minimum..=maximum).contains(&actual) {
        return Err(MySqlConfigError::ValueOutOfRange {
            field,
            minimum,
            maximum,
            actual,
        });
    }
    Ok(())
}

fn push_unique_baseline_setting(
    settings: &mut Vec<MySqlOwnedSetting>,
    key: &'static str,
    value: impl Into<String>,
) -> Result<(), MySqlConfigError> {
    push_owned_setting(settings, MySqlSettingOwner::Baseline, key, value)
}

fn push_unique_setting(
    settings: &mut Vec<MySqlOwnedSetting>,
    feature: MySqlConfigFeature,
    key: &'static str,
    value: impl Into<String>,
) -> Result<(), MySqlConfigError> {
    push_owned_setting(settings, MySqlSettingOwner::Feature(feature), key, value)
}

fn push_owned_setting(
    settings: &mut Vec<MySqlOwnedSetting>,
    owner: MySqlSettingOwner,
    key: &'static str,
    value: impl Into<String>,
) -> Result<(), MySqlConfigError> {
    if settings.iter().any(|setting| setting.key == key) {
        return Err(MySqlConfigError::DuplicateSetting {
            key: key.to_owned(),
        });
    }
    settings.push(MySqlOwnedSetting {
        key,
        value: value.into(),
        owner,
    });
    Ok(())
}

fn validate_setting_ownership(
    settings: &[MySqlOwnedSetting],
    enabled_features: &BTreeSet<MySqlConfigFeature>,
) -> Result<(), MySqlConfigError> {
    let mut keys = HashSet::with_capacity(settings.len());
    for setting in settings {
        if !keys.insert(setting.key()) {
            return Err(MySqlConfigError::DuplicateSetting {
                key: setting.key().to_owned(),
            });
        }
        if let MySqlSettingOwner::Feature(feature) = setting.owner()
            && !feature.owned_keys().contains(&setting.key())
        {
            return Err(MySqlConfigError::InvalidFeatureOwnership {
                detail: format!(
                    "feature {} does not declare ownership of {}",
                    feature.key(),
                    setting.key()
                ),
            });
        }
    }

    for feature in MySqlConfigFeature::ALL {
        for key in feature.owned_keys() {
            let owner = settings
                .iter()
                .find(|setting| setting.key() == *key)
                .map(MySqlOwnedSetting::owner);
            if enabled_features.contains(&feature) {
                if owner != Some(MySqlSettingOwner::Feature(feature)) {
                    return Err(MySqlConfigError::InvalidFeatureOwnership {
                        detail: format!(
                            "enabled feature {} does not exclusively own {}",
                            feature.key(),
                            key
                        ),
                    });
                }
            } else if owner == Some(MySqlSettingOwner::Feature(feature)) {
                return Err(MySqlConfigError::InvalidFeatureOwnership {
                    detail: format!("disabled feature {} still owns {}", feature.key(), key),
                });
            }
        }
    }
    Ok(())
}

/// Validate the closed document shape emitted by this module.
///
/// This is not a general MySQL parser. It deliberately rejects unknown keys,
/// non-canonical lines, duplicate assignments, extra sections, CR/control
/// characters, and documents above the configured byte bound.
pub fn validate_generated_mysql_config_document(contents: &str) -> Result<(), MySqlConfigError> {
    if contents.is_empty() {
        return Err(invalid_document("document is empty"));
    }
    if contents.len() > MAX_GENERATED_MYSQL_CONFIG_BYTES {
        return Err(invalid_document(format!(
            "document exceeds {MAX_GENERATED_MYSQL_CONFIG_BYTES} bytes"
        )));
    }
    if !contents.ends_with('\n') {
        return Err(invalid_document("document must end with an LF newline"));
    }
    if contents
        .chars()
        .any(|character| character != '\n' && character.is_control())
    {
        return Err(invalid_document(
            "document contains a control character other than LF",
        ));
    }

    let mut section_count = 0_usize;
    let mut inside_mysqld = false;
    let mut keys = HashSet::new();
    for line in contents.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[mysqld]" {
            section_count += 1;
            inside_mysqld = true;
            continue;
        }
        if line.starts_with('[') || line.ends_with(']') {
            return Err(invalid_document("only one [mysqld] section is allowed"));
        }
        if !inside_mysqld {
            return Err(invalid_document("a setting appears before [mysqld]"));
        }
        if line.matches('=').count() != 1 {
            return Err(invalid_document("settings must contain one equals sign"));
        }
        let (raw_key, raw_value) = line
            .split_once('=')
            .expect("the equals-sign count was checked");
        let key = raw_key.trim();
        let value = raw_value.trim();
        if line != format!("{key} = {value}") {
            return Err(invalid_document(
                "settings must use canonical `key = value` formatting",
            ));
        }
        if !keys.insert(key) {
            return Err(MySqlConfigError::DuplicateSetting {
                key: key.to_owned(),
            });
        }
        validate_known_setting(key, value)?;
    }
    if section_count != 1 {
        return Err(invalid_document(
            "document must contain exactly one [mysqld]",
        ));
    }
    if keys.is_empty() {
        return Err(invalid_document("[mysqld] must contain settings"));
    }
    Ok(())
}

fn validate_known_setting(key: &str, value: &str) -> Result<(), MySqlConfigError> {
    let valid = match key {
        "bind_address" => value.parse::<IpAddr>().is_ok(),
        "port" => value == "3306",
        "mysqlx" => value == "OFF",
        "local_infile" => matches!(value, "ON" | "OFF"),
        "log_output" => value == "FILE",
        "skip_networking" | "skip_name_resolve" | "slow_query_log" | "general_log"
        | "read_only" | "super_read_only" => value == "ON",
        "max_connections" => parse_in_range(value, 1, 100_000),
        "connect_timeout" => parse_in_range(value, 2, u64::from(MAX_SECONDS_PER_YEAR)),
        "max_connect_errors" => parse_in_range(value, 1, u64::from(u32::MAX)),
        "wait_timeout" => parse_in_range(value, 1, u64::from(MAX_PORTABLE_WAIT_TIMEOUT_SECONDS)),
        "interactive_timeout" | "long_query_time" => {
            let minimum = u64::from(key != "long_query_time");
            parse_in_range(value, minimum, u64::from(MAX_SECONDS_PER_YEAR))
        }
        "log_error_verbosity" => parse_in_range(value, 1, 3),
        "secure_file_priv" => value == "NULL",
        "log_bin" => value == "binlog",
        "server_id" | "binlog_expire_logs_seconds" => parse_in_range(value, 1, u64::from(u32::MAX)),
        _ => false,
    };
    if !valid {
        return Err(invalid_document(format!(
            "unknown setting or unsupported value: {key}"
        )));
    }
    Ok(())
}

fn parse_in_range(value: &str, minimum: u64, maximum: u64) -> bool {
    value
        .parse::<u64>()
        .is_ok_and(|number| (minimum..=maximum).contains(&number))
}

fn invalid_document(detail: impl Into<String>) -> MySqlConfigError {
    MySqlConfigError::InvalidDocument {
        detail: detail.into(),
    }
}

fn validate_export_destination(destination: &Path) -> Result<(), MySqlConfigError> {
    if !destination.is_absolute() {
        return Err(invalid_destination(
            "path must be absolute and selected by the native save dialog",
        ));
    }
    if destination
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(invalid_destination(
            "path must not contain current-directory or parent-directory components",
        ));
    }
    let valid_extension = destination
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("cnf") || extension.eq_ignore_ascii_case("ini")
        });
    if !valid_extension {
        return Err(invalid_destination("file extension must be .cnf or .ini"));
    }
    let parent = destination
        .parent()
        .ok_or_else(|| invalid_destination("path has no parent directory"))?;
    if !parent.is_dir() {
        return Err(invalid_destination("parent directory does not exist"));
    }
    Ok(())
}

fn invalid_destination(detail: impl Into<String>) -> MySqlConfigError {
    MySqlConfigError::InvalidDestination {
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;

    static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[derive(Debug)]
    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let sequence = TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "lovelyres-mysql-config-{}-{timestamp}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn version() -> MySqlConfigVersion {
        MySqlConfigVersion::new(8, 4, 3).unwrap()
    }

    fn baseline() -> MySqlConfig {
        MySqlConfig::baseline(version())
    }

    #[test]
    fn feature_catalog_is_complete_unique_and_closed() {
        assert_eq!(MySqlConfigFeature::ALL.len(), 15);
        let feature_keys = MySqlConfigFeature::ALL
            .into_iter()
            .map(MySqlConfigFeature::key)
            .collect::<HashSet<_>>();
        assert_eq!(feature_keys.len(), MySqlConfigFeature::ALL.len());

        let mut owned_keys = HashSet::new();
        for feature in MySqlConfigFeature::ALL {
            assert!(!feature.key().is_empty());
            assert!(!feature.title().is_empty());
            assert!(!feature.summary().is_empty());
            assert!(!feature.scope().is_empty());
            assert!(!feature.default_enabled());
            assert!(!feature.aliases().is_empty());
            assert!(!feature.owned_keys().is_empty());
            assert!(
                feature
                    .owned_keys()
                    .iter()
                    .all(|key| owned_keys.insert(*key))
            );
        }

        let searchable_text = MySqlConfigFeature::ALL
            .into_iter()
            .flat_map(|feature| {
                std::iter::once(feature.key()).chain(feature.aliases().iter().copied())
            })
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_lowercase();
        assert!(!searchable_text.contains("tls"));
        assert!(!searchable_text.contains("audit"));
        assert!(!owned_keys.contains("plugin_load"));
        assert!(!owned_keys.contains("ssl_ca"));
    }

    #[test]
    fn version_is_limited_to_mysql_8_4() {
        assert!(MySqlConfigVersion::new(8, 4, 0).is_ok());
        assert!(MySqlConfigVersion::new(8, 4, u16::MAX).is_ok());
        for (major, minor, patch) in [(8, 0, 40), (8, 3, 0), (8, 5, 0), (9, 0, 0)] {
            assert!(matches!(
                MySqlConfigVersion::new(major, minor, patch),
                Err(MySqlConfigError::UnsupportedVersion { .. })
            ));
        }
    }

    #[test]
    fn baseline_is_exact_immutable_and_deterministic() {
        let first = baseline().generate().unwrap();
        let second = baseline().generate().unwrap();
        assert_eq!(first, second);
        assert_eq!(first.version(), version());
        assert_eq!(first.suggested_file_name(), "my.cnf");
        assert_eq!(
            first.contents(),
            "# LovelyRes generated MySQL 8.4 configuration\n\
# Target version: MySQL 8.4.3\n\
# Validate with matching MySQL 8.4: mysqld --defaults-file=<path> --validate-config.\n\
[mysqld]\n\
bind_address = 127.0.0.1\n\
port = 3306\n\
mysqlx = OFF\n\
local_infile = OFF\n\
log_output = FILE\n"
        );
        assert!(
            first
                .settings()
                .iter()
                .all(|setting| setting.owner() == MySqlSettingOwner::Baseline)
        );
        assert!(baseline().enabled_features().is_empty());
    }

    #[test]
    fn compatible_features_compose_in_one_deterministic_document() {
        let config = baseline()
            .with_remote_listener("0.0.0.0".parse().unwrap())
            .unwrap()
            .with_feature(MySqlConfigFeature::SkipNameResolve, true)
            .unwrap()
            .with_max_connections(500)
            .unwrap()
            .with_connect_timeout_seconds(15)
            .unwrap()
            .with_max_connect_errors(1_000)
            .unwrap()
            .with_session_timeouts_seconds(600, 900)
            .unwrap()
            .with_slow_query_log_seconds(2)
            .unwrap()
            .with_feature(MySqlConfigFeature::GeneralLog, true)
            .unwrap()
            .with_log_error_verbosity(3)
            .unwrap()
            .with_feature(MySqlConfigFeature::DisableFileImportExport, true)
            .unwrap()
            .with_feature(MySqlConfigFeature::ReadOnlyReplica, true)
            .unwrap()
            .with_binary_logging(42)
            .unwrap()
            .with_binary_log_retention_seconds(86_400)
            .unwrap()
            .with_feature(MySqlConfigFeature::EnableLocalInfile, true)
            .unwrap();

        let generated = config.generate().unwrap();
        let expected_keys = [
            "bind_address",
            "port",
            "mysqlx",
            "local_infile",
            "log_output",
            "skip_name_resolve",
            "max_connections",
            "connect_timeout",
            "max_connect_errors",
            "wait_timeout",
            "interactive_timeout",
            "slow_query_log",
            "long_query_time",
            "general_log",
            "log_error_verbosity",
            "secure_file_priv",
            "read_only",
            "super_read_only",
            "log_bin",
            "server_id",
            "binlog_expire_logs_seconds",
        ];
        assert_eq!(
            generated
                .settings()
                .iter()
                .map(MySqlOwnedSetting::key)
                .collect::<Vec<_>>(),
            expected_keys
        );
        assert!(generated.contents().contains("bind_address = 0.0.0.0\n"));
        assert!(generated.contents().contains("local_infile = ON\n"));
        assert!(generated.contents().contains("secure_file_priv = NULL\n"));
        assert!(generated.contents().contains("log_bin = binlog\n"));
        assert!(!generated.contents().contains("binlog_format"));
        validate_generated_mysql_config_document(generated.contents()).unwrap();

        for feature in config.enabled_features() {
            for key in feature.owned_keys() {
                let setting = generated
                    .settings()
                    .iter()
                    .find(|setting| setting.key() == *key)
                    .unwrap();
                assert_eq!(setting.owner(), MySqlSettingOwner::Feature(*feature));
            }
        }
    }

    #[test]
    fn disabling_tcp_is_supported_but_conflicts_with_remote_listening() {
        let tcp_disabled = baseline()
            .with_feature(MySqlConfigFeature::DisableTcp, true)
            .unwrap()
            .generate()
            .unwrap();
        assert!(tcp_disabled.contents().contains("skip_networking = ON\n"));

        assert!(matches!(
            baseline()
                .with_feature(MySqlConfigFeature::DisableTcp, true)
                .unwrap()
                .with_remote_listener("0.0.0.0".parse().unwrap()),
            Err(MySqlConfigError::ConflictingFeatures { .. })
        ));
        assert!(matches!(
            baseline()
                .with_remote_listener("0.0.0.0".parse().unwrap())
                .unwrap()
                .with_feature(MySqlConfigFeature::DisableTcp, true),
            Err(MySqlConfigError::ConflictingFeatures { .. })
        ));
    }

    #[test]
    fn binary_log_retention_requires_explicit_binary_logging() {
        assert!(matches!(
            baseline().with_binary_log_retention_seconds(86_400),
            Err(MySqlConfigError::MissingRequiredFeature {
                feature: MySqlConfigFeature::BinaryLogRetention,
                required: MySqlConfigFeature::BinaryLogging,
            })
        ));
        let config = baseline()
            .with_binary_logging(7)
            .unwrap()
            .with_binary_log_retention_seconds(86_400)
            .unwrap();
        assert!(matches!(
            config.with_feature(MySqlConfigFeature::BinaryLogging, false),
            Err(MySqlConfigError::MissingRequiredFeature { .. })
        ));
    }

    #[test]
    fn numeric_inputs_enforce_mysql_8_4_and_portable_bounds() {
        assert!(baseline().with_max_connections(1).is_ok());
        assert!(baseline().with_max_connections(100_000).is_ok());
        assert!(baseline().with_max_connections(0).is_err());
        assert!(baseline().with_max_connections(100_001).is_err());

        assert!(baseline().with_connect_timeout_seconds(2).is_ok());
        assert!(
            baseline()
                .with_connect_timeout_seconds(MAX_SECONDS_PER_YEAR)
                .is_ok()
        );
        assert!(baseline().with_connect_timeout_seconds(1).is_err());

        assert!(baseline().with_max_connect_errors(1).is_ok());
        assert!(
            baseline()
                .with_max_connect_errors(u64::from(u32::MAX))
                .is_ok()
        );
        assert!(baseline().with_max_connect_errors(0).is_err());
        assert!(
            baseline()
                .with_max_connect_errors(u64::from(u32::MAX) + 1)
                .is_err()
        );

        assert!(baseline().with_session_timeouts_seconds(1, 1).is_ok());
        assert!(
            baseline()
                .with_session_timeouts_seconds(
                    MAX_PORTABLE_WAIT_TIMEOUT_SECONDS,
                    MAX_SECONDS_PER_YEAR
                )
                .is_ok()
        );
        assert!(baseline().with_session_timeouts_seconds(0, 1).is_err());
        assert!(
            baseline()
                .with_session_timeouts_seconds(MAX_PORTABLE_WAIT_TIMEOUT_SECONDS + 1, 1)
                .is_err()
        );
        assert!(baseline().with_session_timeouts_seconds(1, 0).is_err());

        assert!(baseline().with_slow_query_log_seconds(0).is_ok());
        assert!(
            baseline()
                .with_slow_query_log_seconds(MAX_SECONDS_PER_YEAR)
                .is_ok()
        );
        assert!(
            baseline()
                .with_slow_query_log_seconds(MAX_SECONDS_PER_YEAR + 1)
                .is_err()
        );

        assert!(baseline().with_log_error_verbosity(1).is_ok());
        assert!(baseline().with_log_error_verbosity(3).is_ok());
        assert!(baseline().with_log_error_verbosity(0).is_err());
        assert!(baseline().with_log_error_verbosity(4).is_err());
        assert!(baseline().with_binary_logging(0).is_err());
        assert!(baseline().with_binary_logging(u32::MAX).is_ok());

        let binary = baseline().with_binary_logging(1).unwrap();
        assert!(binary.clone().with_binary_log_retention_seconds(1).is_ok());
        assert!(
            binary
                .clone()
                .with_binary_log_retention_seconds(u32::MAX)
                .is_ok()
        );
        assert!(binary.with_binary_log_retention_seconds(0).is_err());
    }

    #[test]
    fn typed_ip_listener_cannot_inject_configuration_text() {
        let generated = baseline()
            .with_remote_listener("2001:db8::1".parse().unwrap())
            .unwrap()
            .generate()
            .unwrap();
        assert!(
            generated
                .contents()
                .contains("bind_address = 2001:db8::1\n")
        );
        assert_eq!(generated.contents().matches("[mysqld]").count(), 1);
        assert!(generated.contents().contains("mysqlx = OFF\n"));
    }

    #[test]
    fn remote_listener_requires_the_typed_ip_setter_and_never_opens_x_protocol() {
        assert!(matches!(
            baseline().with_feature(MySqlConfigFeature::RemoteListener, true),
            Err(MySqlConfigError::MissingRequiredValue {
                feature: MySqlConfigFeature::RemoteListener,
                field: "bind_address",
            })
        ));

        let removed = baseline()
            .with_remote_listener("0.0.0.0".parse().unwrap())
            .unwrap()
            .with_feature(MySqlConfigFeature::RemoteListener, false)
            .unwrap();
        assert!(matches!(
            removed.with_feature(MySqlConfigFeature::RemoteListener, true),
            Err(MySqlConfigError::MissingRequiredValue { .. })
        ));

        let generated = baseline()
            .with_remote_listener("0.0.0.0".parse().unwrap())
            .unwrap()
            .generate()
            .unwrap();
        assert!(generated.contents().contains("bind_address = 0.0.0.0\n"));
        assert!(generated.contents().contains("mysqlx = OFF\n"));
        assert!(!generated.contents().contains("mysqlx_bind_address"));
        assert!(!generated.contents().contains("mysqlx_port"));
    }

    #[test]
    fn removing_features_recomposes_baseline_and_only_owned_settings() {
        let reset_listener = baseline()
            .with_remote_listener("0.0.0.0".parse().unwrap())
            .unwrap()
            .with_feature(MySqlConfigFeature::RemoteListener, false)
            .unwrap()
            .generate()
            .unwrap();
        assert!(
            reset_listener
                .contents()
                .contains("bind_address = 127.0.0.1\n")
        );
        assert_eq!(
            reset_listener.settings()[0].owner(),
            MySqlSettingOwner::Baseline
        );

        let reset_local_infile = baseline()
            .with_feature(MySqlConfigFeature::EnableLocalInfile, true)
            .unwrap()
            .with_feature(MySqlConfigFeature::EnableLocalInfile, false)
            .unwrap()
            .generate()
            .unwrap();
        assert!(
            reset_local_infile
                .contents()
                .contains("local_infile = OFF\n")
        );
        assert_eq!(
            reset_local_infile
                .settings()
                .iter()
                .find(|setting| setting.key() == "local_infile")
                .unwrap()
                .owner(),
            MySqlSettingOwner::Baseline
        );
    }

    #[test]
    fn mysql_quick_stack_remove_reset_save_and_structured_visual_prerequisite_are_byte_exact() {
        let version = MySqlConfigVersion::new(8, 4, 0).unwrap();
        let baseline = MySqlConfig::baseline(version).generate().unwrap();
        assert!(
            baseline
                .contents()
                .contains("# Target version: MySQL 8.4.0\n")
        );
        assert!(baseline.contents().contains("[mysqld]\n"));
        assert!(baseline.contents().contains("bind_address = 127.0.0.1\n"));
        assert!(baseline.contents().contains("port = 3306\n"));
        assert!(baseline.contents().contains("mysqlx = OFF\n"));
        assert!(baseline.contents().contains("local_infile = OFF\n"));

        assert!(matches!(
            MySqlConfig::baseline(version)
                .with_binary_log_retention_seconds(DEFAULT_BINLOG_RETENTION_SECONDS),
            Err(MySqlConfigError::MissingRequiredFeature {
                feature: MySqlConfigFeature::BinaryLogRetention,
                required: MySqlConfigFeature::BinaryLogging,
            })
        ));
        let stacked = MySqlConfig::baseline(version)
            .with_max_connections(400)
            .unwrap()
            .with_slow_query_log_seconds(10)
            .unwrap()
            .with_binary_logging(1)
            .unwrap()
            .with_binary_log_retention_seconds(DEFAULT_BINLOG_RETENTION_SECONDS)
            .unwrap();
        assert!(stacked.feature_enabled(MySqlConfigFeature::BinaryLogging));
        let stacked_document = stacked.generate().unwrap();
        for directive in [
            "max_connections = 400\n",
            "slow_query_log = ON\n",
            "long_query_time = 10\n",
            "log_bin = binlog\n",
            "server_id = 1\n",
            "binlog_expire_logs_seconds = 2592000\n",
        ] {
            assert!(
                stacked_document.contents().contains(directive),
                "{directive}"
            );
        }

        let remaining = stacked
            .with_feature(MySqlConfigFeature::MaxConnections, false)
            .unwrap()
            .generate()
            .unwrap();
        assert!(!remaining.contents().contains("max_connections = 400\n"));
        assert!(remaining.contents().contains("slow_query_log = ON\n"));
        assert!(
            remaining
                .contents()
                .contains("binlog_expire_logs_seconds = 2592000\n")
        );

        let reset = MySqlConfig::baseline(version).generate().unwrap();
        assert_eq!(reset.contents(), baseline.contents());
        let root = TestRoot::new();
        let destination = root.0.join("mysql-quick.cnf");
        assert_eq!(reset.write_new(&destination).unwrap(), destination);
        assert_eq!(
            fs::read(&destination).unwrap(),
            baseline.contents().as_bytes()
        );
        assert!(matches!(
            reset.write_new(&destination),
            Err(MySqlConfigError::Io { .. })
        ));
        assert_eq!(
            fs::read(&destination).unwrap(),
            baseline.contents().as_bytes()
        );

        let visual = crate::line_config_visual::LineConfigVisualDocument::parse(
            crate::line_config_visual::LineConfigDialect::MySqlOption,
            reset.contents(),
        )
        .unwrap();
        assert!(visual.is_structured());
        assert!(!visual.rows().is_empty());
        assert_eq!(visual.raw_bytes(), baseline.contents().as_bytes());
        assert_eq!(visual.output().bytes(), baseline.contents().as_bytes());
    }

    #[test]
    fn mysql_catalog_inline_editor_and_preview_prerequisites_are_typed_and_byte_exact() {
        let feature = MySqlConfigFeature::MaxConnections;
        assert_eq!(feature.key(), "max-connections");
        assert_eq!(feature.title(), "限制最大连接数");
        assert_eq!(
            feature.summary(),
            "设置服务器可同时接受的客户端连接数量上限。"
        );
        assert_eq!(feature.scope(), "连接");
        assert_eq!(
            feature.aliases(),
            &["max_connections", "最大连接", "并发连接"]
        );
        assert_eq!(feature.owned_keys(), &["max_connections"]);
        assert!(!feature.default_enabled());

        let baseline = baseline().generate().unwrap();
        let selected = MySqlConfig::baseline(version())
            .with_max_connections(400)
            .unwrap();
        let selected_output = selected.generate().unwrap();
        const MAX_CONNECTIONS: &str = "max_connections = 400\n";
        assert_eq!(
            selected_output.contents().matches(MAX_CONNECTIONS).count(),
            1
        );
        assert_eq!(
            selected_output.contents().replace(MAX_CONNECTIONS, ""),
            baseline.contents()
        );

        let removed = selected
            .with_feature(feature, false)
            .unwrap()
            .generate()
            .unwrap();
        assert_eq!(removed, baseline);
        assert!(
            MySqlConfig::baseline(version())
                .with_max_connections(0)
                .is_err()
        );
        assert!(
            MySqlConfig::baseline(version())
                .with_max_connections(100_001)
                .is_err()
        );
    }

    #[test]
    fn document_validation_rejects_controls_duplicates_unknowns_and_extra_sections() {
        let baseline = baseline().generate().unwrap().contents().to_owned();
        assert!(validate_generated_mysql_config_document(&baseline).is_ok());

        let duplicate = baseline.replace("port = 3306\n", "port = 3306\nport = 3306\n");
        assert!(matches!(
            validate_generated_mysql_config_document(&duplicate),
            Err(MySqlConfigError::DuplicateSetting { .. })
        ));
        assert!(
            validate_generated_mysql_config_document(
                &baseline.replace("port = 3306", "port = 3306\r")
            )
            .is_err()
        );
        assert!(
            validate_generated_mysql_config_document(
                &baseline.replace("port = 3306", "port\t= 3306")
            )
            .is_err()
        );
        assert!(
            validate_generated_mysql_config_document(
                &baseline.replace("port = 3306", "arbitrary_option = ON")
            )
            .is_err()
        );
        assert!(
            validate_generated_mysql_config_document(&format!("{baseline}[client]\n")).is_err()
        );
        assert!(
            validate_generated_mysql_config_document(
                &baseline.replace("[mysqld]\n", "[mysqld]\n[mysqld]\n")
            )
            .is_err()
        );

        let oversized = format!(
            "#{}\n[mysqld]\nport = 3306\n",
            "x".repeat(MAX_GENERATED_MYSQL_CONFIG_BYTES)
        );
        assert!(validate_generated_mysql_config_document(&oversized).is_err());
    }

    #[test]
    fn duplicate_setting_and_invalid_ownership_are_rejected_independently() {
        let mut settings = Vec::new();
        push_unique_baseline_setting(&mut settings, "port", "3306").unwrap();
        assert!(matches!(
            push_unique_baseline_setting(&mut settings, "port", "3306"),
            Err(MySqlConfigError::DuplicateSetting { .. })
        ));

        let invalid = [MySqlOwnedSetting {
            key: "general_log",
            value: "ON".to_owned(),
            owner: MySqlSettingOwner::Feature(MySqlConfigFeature::SlowQueryLog),
        }];
        assert!(matches!(
            validate_setting_ownership(
                &invalid,
                &BTreeSet::from([MySqlConfigFeature::SlowQueryLog])
            ),
            Err(MySqlConfigError::InvalidFeatureOwnership { .. })
        ));
    }

    #[test]
    fn write_new_saves_exact_bytes_and_never_overwrites() {
        let root = TestRoot::new();
        let generated = baseline().generate().unwrap();
        let destination = root.0.join("my.cnf");

        assert_eq!(generated.write_new(&destination).unwrap(), destination);
        assert_eq!(
            fs::read_to_string(&destination).unwrap(),
            generated.contents()
        );
        assert!(matches!(
            generated.write_new(&destination),
            Err(MySqlConfigError::Io { .. })
        ));
        assert_eq!(
            fs::read_to_string(&destination).unwrap(),
            generated.contents()
        );

        let windows_destination = root.0.join("my.ini");
        generated.write_new(&windows_destination).unwrap();
        assert_eq!(
            fs::read_to_string(&windows_destination).unwrap(),
            generated.contents()
        );
    }

    #[test]
    fn write_new_rejects_untrusted_destination_shapes() {
        let root = TestRoot::new();
        let generated = baseline().generate().unwrap();
        assert!(matches!(
            generated.write_new(Path::new("relative.cnf")),
            Err(MySqlConfigError::InvalidDestination { .. })
        ));
        assert!(matches!(
            generated.write_new(&root.0.join("my.txt")),
            Err(MySqlConfigError::InvalidDestination { .. })
        ));
        assert!(matches!(
            generated.write_new(&root.0.join("missing").join("my.cnf")),
            Err(MySqlConfigError::InvalidDestination { .. })
        ));
    }
}
