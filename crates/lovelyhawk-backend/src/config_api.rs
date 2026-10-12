//! Stable, renderer-safe metadata for the typed configuration generators.
//!
//! The renderer receives only reviewed static labels and closed identifiers.
//! Generated documents and mutable drafts stay in Rust and are exposed through
//! separate capability handles; this catalog is never an arbitrary schema or
//! command execution boundary.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::fmt;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use lovelyhawk_core::{
    CoreError, CoreResult,
    apache_config::{
        ApacheAllowedSource, ApacheForbiddenPath, ApacheForbiddenPathRule,
        ApacheForbiddenPathScope, ApacheListenPort, ApacheServerName, ApacheSiteConfig,
        ApacheSiteFeature, ApacheSiteKind, ApacheSiteTarget, ApacheStaticRoot, ApacheUpstream,
    },
    database_config::{
        DATABASE_CONFIG_ARTIFACTS, DATABASE_CONFIG_PRODUCTS, DatabaseConfigLocalDraftAuthority,
        DatabaseConfigReadOnlyReason, MAX_DATABASE_CONFIG_ARTIFACTS,
    },
    database_config_schema::{
        DATABASE_CONFIG_SCHEMAS, DatabaseConfigSchemaCompleteness, DatabaseConfigVersionSelector,
    },
    haproxy_config::{
        HaProxyAllowedSource, HaProxyConfigFeature, HaProxyForbiddenPath, HaProxyForbiddenPathRule,
        HaProxyForbiddenPathScope, HaProxyHttpConfig, HaProxyListenAddress, HaProxyListenPort,
        HaProxyUpstream, HaProxyVersion,
    },
    mariadb_config::{
        MariaDbBinaryLogRetentionSeconds, MariaDbCharacterProfile, MariaDbConfig,
        MariaDbConfigFeature, MariaDbConnectTimeoutSeconds, MariaDbInnoDbLockWaitTimeoutSeconds,
        MariaDbMaxAllowedPacketMebibytes, MariaDbMaxConnectErrors, MariaDbMaxConnections,
        MariaDbPort, MariaDbServerId, MariaDbSessionIdleTimeouts, MariaDbSlowQueryTimeSeconds,
        MariaDbVersion,
    },
    mongodb_config::{
        MongoDbCompression, MongoDbCompressor, MongoDbConfig, MongoDbConfigFeature,
        MongoDbConnectionLimit, MongoDbLogPath, MongoDbLogRotation, MongoDbLogRotationMode,
        MongoDbPort, MongoDbSlowInProgressThreshold, MongoDbSlowOperationSettings, MongoDbVersion,
        MongoDbWiredTigerCacheSize,
    },
    mysql_config::{MySqlConfig, MySqlConfigFeature, MySqlConfigVersion},
    nginx_config::{
        NginxAllowedSource, NginxForbiddenPath, NginxForbiddenPathRule, NginxForbiddenPathScope,
        NginxListenPort, NginxServerNames, NginxSiteConfig, NginxSiteFeature, NginxSiteKind,
        NginxSiteTarget, NginxStaticRoot, NginxUpstream,
    },
    postgresql_config::{
        PostgreSqlAuthenticationTimeoutSeconds, PostgreSqlAutovacuumLogThresholdMilliseconds,
        PostgreSqlConfig, PostgreSqlConfigFeature, PostgreSqlConnectionCapacity,
        PostgreSqlIdleInTransactionTimeoutSeconds, PostgreSqlIdleSessionTimeoutSeconds,
        PostgreSqlLockWaitThresholdMilliseconds, PostgreSqlPort,
        PostgreSqlTemporaryFileLimitMebibytes, PostgreSqlTemporaryFileLogThresholdKilobytes,
        PostgreSqlVersion, PostgreSqlWalCompression,
    },
    redis_config::{
        RedisAppendFsync, RedisBindProfile, RedisConfig, RedisConfigFeature, RedisDataDirectory,
        RedisEvictionPolicy, RedisIdleTimeoutSeconds, RedisLatencyThresholdMilliseconds,
        RedisMaxClients, RedisMaxmemory, RedisPort, RedisSlowLogConfig, RedisTcpKeepaliveSeconds,
        RedisVersion,
    },
    tomcat_config::{
        GeneratedTomcatConfigBundle, TOMCAT_BUNDLE_SCOPE_NOTICE, TomcatAbortedUploadSwallowBytes,
        TomcatAcceptCount, TomcatApplicationName, TomcatArtifactKind, TomcatCompressionMinBytes,
        TomcatConfig, TomcatConfigFeature, TomcatConnectionTimeoutMillis, TomcatConnectorAddress,
        TomcatConnectorConfig, TomcatConnectorPort, TomcatFormParameterBytes, TomcatMaxConnections,
        TomcatMaxThreads, TomcatVersionFamily,
    },
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const CONFIG_PRODUCT_COUNT: usize = 9;
const CONFIG_FEATURE_COUNT: usize = 137;
const MAX_READ_ONLY_ARTIFACTS: usize = MAX_DATABASE_CONFIG_ARTIFACTS;
const MAX_DRAFTS: usize = 16;
const DRAFT_TTL: Duration = Duration::from_secs(10 * 60);
const MAX_DRAFT_BYTES: usize = 512 * 1024;
const MAX_REGISTRY_BYTES: usize = 4 * 1024 * 1024;
const MAX_PREVIEW_BYTES: usize = 32 * 1024;
const MAX_COPY_BYTES: usize = 256 * 1024;
const MAX_FEATURE_KEYS: usize = CONFIG_FEATURE_COUNT;
const MAX_HANDLE_BYTES: usize = 128;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigCatalog {
    schema: &'static str,
    products: Vec<ConfigProduct>,
    read_only_artifacts: Vec<ConfigReadOnlyArtifactStatus>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfigReadOnlyArtifactStatus {
    artifact_key: &'static str,
    product_key: &'static str,
    product_title: &'static str,
    title: &'static str,
    authority: &'static str,
    reason: &'static str,
    notice: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfigProduct {
    key: &'static str,
    title: &'static str,
    family: &'static str,
    choice_kind: &'static str,
    default_choice: &'static str,
    choices: Vec<ConfigChoice>,
    features: Vec<ConfigFeature>,
    artifacts: Vec<ConfigArtifact>,
    scope_notice: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfigChoice {
    key: String,
    label: String,
    detail: String,
    is_default: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfigFeature {
    key: String,
    title: String,
    summary: String,
    scope: String,
    default_enabled: bool,
    aliases: Vec<String>,
    supported_choices: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfigArtifact {
    key: String,
    relative_path: String,
    title: String,
}

pub fn config_catalog() -> ConfigCatalog {
    let products = vec![
        nginx_product(),
        apache_product(),
        haproxy_product(),
        mysql_product(),
        postgresql_product(),
        mariadb_product(),
        mongodb_product(),
        redis_product(),
        tomcat_product(),
    ];
    debug_assert_eq!(products.len(), CONFIG_PRODUCT_COUNT);
    debug_assert_eq!(
        products
            .iter()
            .map(|product| product.features.len())
            .sum::<usize>(),
        CONFIG_FEATURE_COUNT
    );
    let read_only_artifacts = DATABASE_CONFIG_ARTIFACTS
        .iter()
        .filter(|artifact| artifact.is_file_visual_readable())
        .filter_map(|artifact| {
            let status = artifact.read_only_status()?;
            let authority = match status.authority {
                DatabaseConfigLocalDraftAuthority::ReadOnly => "read-only",
                DatabaseConfigLocalDraftAuthority::LosslessLocalDraft => return None,
            };
            let product = DATABASE_CONFIG_PRODUCTS
                .iter()
                .find(|product| product.product == artifact.product)
                .expect("database artifact product must be registered");
            Some(ConfigReadOnlyArtifactStatus {
                artifact_key: artifact.key,
                product_key: product.key,
                product_title: product.label,
                title: artifact.default_file_name.unwrap_or(artifact.key),
                authority,
                reason: match status.reason {
                    DatabaseConfigReadOnlyReason::GeneratedArtifact => "generated-artifact",
                    DatabaseConfigReadOnlyReason::VendorSchemaRequired => "vendor-schema-required",
                    DatabaseConfigReadOnlyReason::ReadOnlyPolicy => "read-only-policy",
                },
                notice: read_only_artifact_notice(artifact.key, status.notice),
            })
        })
        .collect::<Vec<_>>();
    debug_assert!(read_only_artifacts.len() <= MAX_READ_ONLY_ARTIFACTS);
    ConfigCatalog {
        schema: "lovelyres-config-catalog/v2",
        products,
        read_only_artifacts,
    }
}

fn read_only_artifact_notice(artifact_key: &str, base_notice: &str) -> String {
    if artifact_key != "yashandb-yasdb-ini" {
        return base_notice.to_owned();
    }
    let mut schemas = DATABASE_CONFIG_SCHEMAS
        .iter()
        .filter(|schema| schema.binding.artifact_key == artifact_key);
    let Some(schema) = schemas.next() else {
        return base_notice.to_owned();
    };
    if schemas.next().is_some()
        || schema.completeness != DatabaseConfigSchemaCompleteness::Partial
        || schema.bound_artifact_local_draft_authority()
            != Some(DatabaseConfigLocalDraftAuthority::ReadOnly)
    {
        return base_notice.to_owned();
    }
    let DatabaseConfigVersionSelector::Exact(version) = schema.binding.versions else {
        return base_notice.to_owned();
    };
    let Some(document_family) = schema.binding.edition_key else {
        return base_notice.to_owned();
    };
    format!(
        "只读展示：仅公开 schema 元数据；精确 build {}.{}.{}.{}；文档族 {document_family}；完整性 Partial。该元数据只用于显示，绝不会写入目标内容、本地草稿或另存文件，也不授予修改权限。",
        version.major(),
        version.minor(),
        version.patch(),
        version.revision(),
    )
}

fn nginx_product() -> ConfigProduct {
    let choices = NginxSiteKind::ALL
        .into_iter()
        .map(|kind| {
            choice(
                nginx_kind_key(kind),
                kind.label(),
                "生成一个本地审阅用站点片段。",
                matches!(kind, NginxSiteKind::ReverseProxy),
            )
        })
        .collect::<Vec<_>>();
    let features = NginxSiteFeature::ALL
        .into_iter()
        .map(|item| {
            feature(
                item.key(),
                item.title(),
                item.summary(),
                item.scope(),
                item.default_enabled(),
                item.aliases(),
                NginxSiteKind::ALL
                    .into_iter()
                    .filter(|kind| item.supports_kind(*kind))
                    .map(nginx_kind_key),
            )
        })
        .collect();
    product(
        "nginx",
        "Nginx",
        "web",
        "mode",
        "reverse-proxy",
        choices,
        features,
        vec![artifact("site", "nginx-site.conf", "站点配置片段")],
        "仅生成本地草稿；部署前必须由目标 Nginx 版本、完整 include 图和 nginx -t 验证。",
    )
}

fn apache_product() -> ConfigProduct {
    let choices = ApacheSiteKind::ALL
        .into_iter()
        .map(|kind| {
            choice(
                apache_kind_key(kind),
                kind.label(),
                "生成一个顶层 server include，而不是 .htaccess。",
                matches!(kind, ApacheSiteKind::ReverseProxy),
            )
        })
        .collect::<Vec<_>>();
    let features = ApacheSiteFeature::ALL
        .into_iter()
        .map(|item| {
            feature(
                item.key(),
                item.title(),
                item.summary(),
                item.scope(),
                item.default_enabled(),
                item.aliases(),
                ApacheSiteKind::ALL
                    .into_iter()
                    .filter(|kind| item.supports_kind(*kind))
                    .map(apache_kind_key),
            )
        })
        .collect();
    product(
        "apache",
        "Apache HTTP Server",
        "web",
        "mode",
        "reverse-proxy",
        choices,
        features,
        vec![artifact("site", "apache-site.conf", "站点配置片段")],
        "仅生成本地草稿；部署前必须核对目标 httpd 模块、完整 include 图并运行目标 httpd -t。",
    )
}

fn haproxy_product() -> ConfigProduct {
    let choices = HaProxyVersion::ALL
        .into_iter()
        .map(|version| {
            choice(
                version.label(),
                version.label(),
                version.support_notice(),
                version.is_default_recommendation(),
            )
        })
        .collect::<Vec<_>>();
    let features = HaProxyConfigFeature::ALL
        .into_iter()
        .map(|item| {
            feature(
                item.key(),
                item.title(),
                item.summary(),
                item.scope(),
                item.default_enabled(),
                item.aliases(),
                HaProxyVersion::ALL
                    .into_iter()
                    .filter(|version| item.supports_version(*version))
                    .map(|version| version.label()),
            )
        })
        .collect();
    product(
        "haproxy",
        "HAProxy",
        "proxy",
        "version",
        "3.4",
        choices,
        features,
        vec![artifact("main", "haproxy.cfg", "HTTP 代理配置")],
        "TLS 前端、PROXY protocol 信任和真实目标校验保持关闭；草稿必须由目标 haproxy -c -f 验证。",
    )
}

fn mysql_product() -> ConfigProduct {
    let choices = vec![choice(
        "8.4.0",
        "MySQL 8.4.x",
        "闭合模型只接受 8.4 系列；补丁版本仍须与目标一致。",
        true,
    )];
    let features = MySqlConfigFeature::ALL
        .into_iter()
        .map(|item| {
            feature(
                item.key(),
                item.title(),
                item.summary(),
                item.scope(),
                item.default_enabled(),
                item.aliases(),
                ["8.4.0"],
            )
        })
        .collect();
    product(
        "mysql",
        "MySQL",
        "database",
        "version",
        "8.4.0",
        choices,
        features,
        vec![artifact("main", "my.cnf", "mysqld option file")],
        "远程监听不替代账号 Host、TLS 或防火墙；输出必须由同系列目标 mysqld --validate-config 验证。",
    )
}

fn postgresql_product() -> ConfigProduct {
    let choices = PostgreSqlVersion::ALL
        .into_iter()
        .map(|version| {
            choice(
                version.label(),
                version.label(),
                format!("{} {}", version.support_notice(), version.risk()),
                matches!(version, PostgreSqlVersion::V18),
            )
        })
        .collect::<Vec<_>>();
    let features = PostgreSqlConfigFeature::ALL
        .into_iter()
        .map(|item| {
            feature(
                item.key(),
                item.title(),
                item.summary(),
                item.scope(),
                item.default_enabled(),
                item.aliases(),
                PostgreSqlVersion::ALL
                    .into_iter()
                    .filter(|version| item.supports_version(*version))
                    .map(|version| version.label()),
            )
        })
        .collect();
    product(
        "postgresql",
        "PostgreSQL",
        "database",
        "version",
        "18",
        choices,
        features,
        vec![artifact("main", "postgresql.conf", "server configuration")],
        "输出不包含 pg_hba.conf、pg_ident.conf 或 TLS；必须由完全相同 major 的目标验证。",
    )
}

fn mariadb_product() -> ConfigProduct {
    let choices = MariaDbVersion::ALL
        .into_iter()
        .map(|version| {
            choice(
                version.label(),
                version.label(),
                format!("{} {}", version.support_notice(), version.risk()),
                matches!(version, MariaDbVersion::V12_3),
            )
        })
        .collect::<Vec<_>>();
    let features = MariaDbConfigFeature::ALL
        .into_iter()
        .map(|item| {
            feature(
                item.key(),
                item.title(),
                item.summary(),
                item.scope(),
                item.default_enabled(),
                item.aliases(),
                MariaDbVersion::ALL
                    .into_iter()
                    .filter(|version| item.supports_version(*version))
                    .map(|version| version.label()),
            )
        })
        .collect();
    product(
        "mariadb",
        "MariaDB",
        "database",
        "version",
        "12.3",
        choices,
        features,
        vec![artifact("main", "mariadb.cnf", "server option file")],
        "配置来源、发行包默认值与目标 option validator 必须独立核对；不会猜测既有实例迁移。",
    )
}

fn mongodb_product() -> ConfigProduct {
    let choices = MongoDbVersion::ALL
        .into_iter()
        .map(|version| {
            choice(
                version.label(),
                version.label(),
                format!("{} {}", version.support_notice(), version.risk()),
                matches!(version, MongoDbVersion::V8_3),
            )
        })
        .collect::<Vec<_>>();
    let features = MongoDbConfigFeature::ALL
        .into_iter()
        .map(|item| {
            feature(
                item.key(),
                item.title(),
                item.summary(),
                item.scope(),
                item.default_enabled(),
                item.aliases(),
                MongoDbVersion::ALL
                    .into_iter()
                    .filter(|version| item.supports_version(*version))
                    .map(|version| version.label()),
            )
        })
        .collect();
    product(
        "mongodb",
        "MongoDB",
        "database",
        "version",
        "8.3",
        choices,
        features,
        vec![artifact("main", "mongod.conf", "mongod YAML configuration")],
        "不猜测 dbPath、TLS、凭据、replica set 或既有数据迁移；输出仅为新部署的本地审阅草稿。",
    )
}

fn redis_product() -> ConfigProduct {
    let choices = RedisVersion::ALL
        .into_iter()
        .map(|version| {
            choice(
                version.label(),
                version.label(),
                "AOF 文件布局与版本能力由 Rust 核心按所选版本决定。",
                matches!(version, RedisVersion::V8_10),
            )
        })
        .collect::<Vec<_>>();
    let features = RedisConfigFeature::ALL
        .into_iter()
        .map(|item| {
            feature(
                item.key(),
                item.title(),
                item.summary(),
                item.scope(),
                item.default_enabled(),
                item.aliases(),
                RedisVersion::ALL
                    .into_iter()
                    .filter(|version| item.supports_version(*version))
                    .map(|version| version.label()),
            )
        })
        .collect();
    product(
        "redis",
        "Redis",
        "cache",
        "version",
        "8.10",
        choices,
        features,
        vec![artifact("main", "redis.conf", "Redis configuration")],
        "只面向全新空实例；认证、ACL、远程暴露、既有数据迁移和目标启动验证不由静态草稿替代。",
    )
}

fn tomcat_product() -> ConfigProduct {
    let choices = TomcatVersionFamily::ALL
        .into_iter()
        .map(|version| {
            choice(
                tomcat_version_key(version),
                version.label(),
                format!(
                    "{}；最低 Java {}。",
                    version.servlet_specification(),
                    version.minimum_java()
                ),
                matches!(version, TomcatVersionFamily::V11_0),
            )
        })
        .collect::<Vec<_>>();
    let features = TomcatConfigFeature::ALL
        .into_iter()
        .map(|item| {
            feature(
                item.key(),
                item.title(),
                item.summary(),
                item.scope(),
                item.default_enabled(),
                item.aliases(),
                TomcatVersionFamily::ALL
                    .into_iter()
                    .filter(|version| item.supports_version(*version))
                    .map(tomcat_version_key),
            )
        })
        .collect();
    let artifacts = TomcatArtifactKind::ALL
        .into_iter()
        .map(|kind| artifact(kind.file_name(), kind.relative_path(), kind.title()))
        .collect();
    product(
        "tomcat",
        "Apache Tomcat",
        "application-server",
        "version",
        "11.0",
        choices,
        features,
        artifacts,
        TOMCAT_BUNDLE_SCOPE_NOTICE,
    )
}

#[allow(clippy::too_many_arguments)]
fn product(
    key: &'static str,
    title: &'static str,
    family: &'static str,
    choice_kind: &'static str,
    default_choice: &'static str,
    choices: Vec<ConfigChoice>,
    features: Vec<ConfigFeature>,
    artifacts: Vec<ConfigArtifact>,
    scope_notice: &'static str,
) -> ConfigProduct {
    ConfigProduct {
        key,
        title,
        family,
        choice_kind,
        default_choice,
        choices,
        features,
        artifacts,
        scope_notice,
    }
}

fn choice(
    key: impl Into<String>,
    label: impl Into<String>,
    detail: impl Into<String>,
    is_default: bool,
) -> ConfigChoice {
    ConfigChoice {
        key: key.into(),
        label: label.into(),
        detail: detail.into(),
        is_default,
    }
}

fn feature<'a>(
    key: &str,
    title: &str,
    summary: &str,
    scope: &str,
    default_enabled: bool,
    aliases: &[&str],
    supported_choices: impl IntoIterator<Item = &'a str>,
) -> ConfigFeature {
    ConfigFeature {
        key: key.to_owned(),
        title: title.to_owned(),
        summary: summary.to_owned(),
        scope: scope.to_owned(),
        default_enabled,
        aliases: aliases.iter().map(|alias| (*alias).to_owned()).collect(),
        supported_choices: supported_choices.into_iter().map(str::to_owned).collect(),
    }
}

fn artifact(key: &str, relative_path: &str, title: &str) -> ConfigArtifact {
    ConfigArtifact {
        key: key.to_owned(),
        relative_path: relative_path.to_owned(),
        title: title.to_owned(),
    }
}

const fn nginx_kind_key(kind: NginxSiteKind) -> &'static str {
    match kind {
        NginxSiteKind::Static => "static",
        NginxSiteKind::ReverseProxy => "reverse-proxy",
    }
}

const fn apache_kind_key(kind: ApacheSiteKind) -> &'static str {
    match kind {
        ApacheSiteKind::Static => "static",
        ApacheSiteKind::ReverseProxy => "reverse-proxy",
    }
}

const fn tomcat_version_key(version: TomcatVersionFamily) -> &'static str {
    match version {
        TomcatVersionFamily::V9_0 => "9.0",
        TomcatVersionFamily::V10_1 => "10.1",
        TomcatVersionFamily::V11_0 => "11.0",
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "product", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ConfigGenerateInput {
    Nginx {
        #[serde(default = "default_reverse_proxy")]
        choice: String,
        #[serde(default)]
        features: Option<Vec<String>>,
        #[serde(default)]
        values: NginxValues,
    },
    Apache {
        #[serde(default = "default_reverse_proxy")]
        choice: String,
        #[serde(default)]
        features: Option<Vec<String>>,
        #[serde(default)]
        values: ApacheValues,
    },
    Haproxy {
        #[serde(default = "default_haproxy_version")]
        choice: String,
        #[serde(default)]
        features: Option<Vec<String>>,
        #[serde(default)]
        values: HaProxyValues,
    },
    Mysql {
        #[serde(default = "default_mysql_version")]
        choice: String,
        #[serde(default)]
        features: Option<Vec<String>>,
        #[serde(default)]
        values: MySqlValues,
    },
    Postgresql {
        #[serde(default = "default_postgresql_version")]
        choice: String,
        #[serde(default)]
        features: Option<Vec<String>>,
        #[serde(default)]
        values: PostgreSqlValues,
    },
    Mariadb {
        #[serde(default = "default_mariadb_version")]
        choice: String,
        #[serde(default)]
        features: Option<Vec<String>>,
        #[serde(default)]
        values: MariaDbValues,
    },
    Mongodb {
        #[serde(default = "default_mongodb_version")]
        choice: String,
        #[serde(default)]
        features: Option<Vec<String>>,
        #[serde(default)]
        values: MongoDbValues,
    },
    Redis {
        #[serde(default = "default_redis_version")]
        choice: String,
        #[serde(default)]
        features: Option<Vec<String>>,
        #[serde(default)]
        values: RedisValues,
    },
    Tomcat {
        #[serde(default = "default_tomcat_version")]
        choice: String,
        #[serde(default)]
        features: Option<Vec<String>>,
        #[serde(default)]
        values: TomcatValues,
    },
}

macro_rules! string_values {
    ($name:ident { $($field:ident : $default:literal),+ $(,)? }) => {
        #[derive(Debug, Deserialize)]
        #[serde(default, rename_all = "camelCase", deny_unknown_fields)]
        pub struct $name { $(pub $field: String),+ }

        impl Default for $name {
            fn default() -> Self {
                Self { $($field: $default.to_owned()),+ }
            }
        }
    };
}

string_values!(NginxValues {
    server_name: "example.com",
    listen_port: "80",
    static_root: "/var/www/html",
    upstream: "http://127.0.0.1:3000",
    forbidden_path: "/admin",
    forbidden_scope: "path-and-descendants",
    allowed_source: ""
});
string_values!(ApacheValues {
    server_name: "example.com",
    listen_port: "80",
    static_root: "/var/www/html",
    upstream: "http://127.0.0.1:3000",
    forbidden_path: "/admin",
    forbidden_scope: "path-and-descendants",
    allowed_source: ""
});
string_values!(HaProxyValues {
    listen_address: "127.0.0.1",
    listen_port: "80",
    upstream: "127.0.0.1:3000",
    forbidden_path: "/admin",
    forbidden_scope: "path-and-descendants",
    allowed_source: "127.0.0.1"
});
string_values!(MySqlValues {
    remote_listener: "0.0.0.0",
    max_connections: "151",
    connect_timeout: "10",
    max_connect_errors: "100",
    wait_timeout: "28800",
    interactive_timeout: "28800",
    long_query_time: "10",
    log_error_verbosity: "2",
    server_id: "1",
    binlog_retention: "2592000"
});
string_values!(PostgreSqlValues {
    port: "5432",
    max_connections: "100",
    superuser_reserved_connections: "3",
    reserved_connections: "0",
    authentication_timeout: "60",
    idle_in_transaction_timeout: "300",
    idle_session_timeout: "1800",
    temporary_file_limit: "1024",
    lock_wait_threshold: "1000",
    autovacuum_log_threshold: "1000",
    temporary_file_log_threshold: "10240",
    wal_compression: "pglz"
});
string_values!(MariaDbValues {
    port: "3306",
    max_connections: "200",
    connect_timeout: "10",
    wait_timeout: "600",
    interactive_timeout: "600",
    max_connect_errors: "100",
    max_allowed_packet: "64",
    slow_query_time: "2",
    server_id: "1",
    binlog_retention: "604800",
    innodb_lock_wait_timeout: "50",
    character_profile: "unicode-case-insensitive"
});
string_values!(MongoDbValues {
    port: "27017",
    max_connections: "10000",
    slow_operation_threshold: "100",
    slow_operation_sample_rate: "1.0",
    slow_in_progress_threshold: "1000",
    log_path: "/var/log/mongodb/mongod.log",
    log_rotation_mode: "rename",
    wired_tiger_cache_gib: "1",
    collection_compressor: "snappy",
    journal_compressor: "zstd"
});
string_values!(RedisValues {
    bind_profile: "dual-stack-loopback",
    data_directory: "/var/lib/redis",
    port: "6379",
    max_clients: "10000",
    idle_timeout: "300",
    tcp_keepalive: "300",
    maxmemory_mib: "512",
    eviction_policy: "noeviction",
    append_fsync: "everysec",
    slowlog_threshold: "10000",
    slowlog_length: "128",
    latency_threshold: "100"
});
string_values!(TomcatValues {
    connector_address: "ipv4-loopback",
    application_name: "LovelyHawk ROOT application",
    port: "8080",
    connection_timeout: "20000",
    max_threads: "200",
    accept_count: "100",
    max_connections: "8192",
    max_post_size: "2097152",
    max_swallow_size: "2097152",
    compression_min_size: "2048"
});

pub struct ConfigApi {
    drafts: Mutex<DraftRegistry>,
}

impl fmt::Debug for ConfigApi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (draft_count, total_bytes) = self
            .drafts
            .lock()
            .map(|registry| (registry.drafts.len(), registry.total_bytes))
            .unwrap_or_default();
        formatter
            .debug_struct("ConfigApi")
            .field("draft_count", &draft_count)
            .field("total_bytes", &total_bytes)
            .finish()
    }
}

impl Default for ConfigApi {
    fn default() -> Self {
        Self {
            drafts: Mutex::new(DraftRegistry::default()),
        }
    }
}

impl ConfigApi {
    pub fn generate(&self, input: ConfigGenerateInput) -> CoreResult<ConfigDraftDto> {
        let draft = build_draft(input)?;
        let mut registry = self.lock_registry()?;
        registry.remove_expired(Instant::now());
        let (handle, revision) = registry.insert(draft, Instant::now())?;
        registry.dto(&handle, revision)
    }

    pub fn revise(
        &self,
        handle: &str,
        revision: u64,
        input: ConfigGenerateInput,
    ) -> CoreResult<ConfigDraftDto> {
        validate_handle(handle)?;
        let draft = build_draft(input)?;
        let mut registry = self.lock_registry()?;
        registry.remove_expired(Instant::now());
        let next_revision = registry.replace(handle, revision, draft, Instant::now())?;
        registry.dto(handle, next_revision)
    }

    pub fn copy(&self, handle: &str, revision: u64) -> CoreResult<ConfigCopyDto> {
        validate_handle(handle)?;
        let mut registry = self.lock_registry()?;
        registry.remove_expired(Instant::now());
        registry.copy(handle, revision)
    }

    /// Writes every file of the current multi-file draft below a new directory
    /// in `parent`, named by the generator. Core's writer creates the directory
    /// and each file new, so an existing directory is refused untouched and a
    /// failure part-way removes only what this call created.
    pub fn export_bundle(
        &self,
        handle: &str,
        revision: u64,
        parent: &Path,
    ) -> CoreResult<ConfigBundleExportDto> {
        validate_handle(handle)?;
        let bundle = {
            let mut registry = self.lock_registry()?;
            registry.remove_expired(Instant::now());
            registry.bundle(handle, revision)?
        };
        let directory_name = bundle.0.suggested_directory_name();
        bundle.0.write_new(&parent.join(directory_name))?;
        Ok(ConfigBundleExportDto {
            directory_name: directory_name.to_owned(),
            file_count: bundle.0.artifacts().len(),
        })
    }

    pub fn close(&self, handle: &str, revision: u64) -> CoreResult<ConfigClosedDto> {
        validate_handle(handle)?;
        let mut registry = self.lock_registry()?;
        registry.remove_expired(Instant::now());
        registry.close(handle, revision)?;
        Ok(ConfigClosedDto { closed: true })
    }

    pub fn artifact(
        &self,
        handle: &str,
        revision: u64,
        artifact_key: &str,
    ) -> CoreResult<ConfigArtifactExportDto> {
        let artifact = self.artifact_bytes(handle, revision, artifact_key)?;
        let contents = String::from_utf8(artifact.bytes).map_err(|_| {
            invalid(
                "configuration artifact encoding",
                "generated artifacts must remain valid UTF-8 text",
            )
        })?;
        Ok(ConfigArtifactExportDto {
            suggested_name: artifact.suggested_name,
            contents,
        })
    }

    pub(crate) fn artifact_bytes(
        &self,
        handle: &str,
        revision: u64,
        artifact_key: &str,
    ) -> CoreResult<ConfigArtifactBytes> {
        validate_handle(handle)?;
        validate_artifact_key(artifact_key)?;
        let mut registry = self.lock_registry()?;
        registry.remove_expired(Instant::now());
        registry.artifact_bytes(handle, revision, artifact_key)
    }

    fn lock_registry(&self) -> CoreResult<MutexGuard<'_, DraftRegistry>> {
        self.drafts.lock().map_err(|_| {
            invalid(
                "configuration draft registry",
                "internal lock is unavailable",
            )
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigDraftDto {
    pub handle: String,
    pub revision: u64,
    pub product: &'static str,
    pub choice: String,
    pub suggested_name: String,
    pub total_bytes: usize,
    pub copy_allowed: bool,
    pub artifacts: Vec<ConfigDraftArtifactDto>,
    pub notices: Vec<&'static str>,
}

impl fmt::Debug for ConfigDraftDto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigDraftDto")
            .field("revision", &self.revision)
            .field("product", &self.product)
            .field("choice", &self.choice)
            .field("suggested_name", &self.suggested_name)
            .field("total_bytes", &self.total_bytes)
            .field("copy_allowed", &self.copy_allowed)
            .field("artifact_count", &self.artifacts.len())
            .field("notices", &self.notices)
            .finish()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigDraftArtifactDto {
    pub key: String,
    pub relative_path: String,
    pub media_type: &'static str,
    pub byte_length: usize,
    pub preview: String,
    pub preview_truncated: bool,
    pub copy_allowed: bool,
}

impl fmt::Debug for ConfigDraftArtifactDto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigDraftArtifactDto")
            .field("key", &self.key)
            .field("relative_path", &self.relative_path)
            .field("media_type", &self.media_type)
            .field("byte_length", &self.byte_length)
            .field("preview_truncated", &self.preview_truncated)
            .field("copy_allowed", &self.copy_allowed)
            .finish()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigCopyDto {
    pub revision: u64,
    pub artifacts: Vec<ConfigCopyArtifactDto>,
    /// What the clipboard receives: a single file as it is; several files each
    /// between `===== BEGIN <path> =====` and `===== END <path> =====` lines, so
    /// the pasted text still says which file every part belongs to.
    pub text: String,
}

impl fmt::Debug for ConfigCopyDto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigCopyDto")
            .field("revision", &self.revision)
            .field("artifacts", &self.artifacts)
            .field("text_bytes", &self.text.len())
            .finish()
    }
}

/// A whole multi-file draft written below one new directory.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigBundleExportDto {
    pub directory_name: String,
    pub file_count: usize,
}

/// The copy text for a draft's files, in order; see [`ConfigCopyDto::text`].
fn review_copy_text(artifacts: &[BuiltArtifact]) -> String {
    let as_text = |artifact: &BuiltArtifact| {
        String::from_utf8(artifact.bytes.clone()).expect("typed generators were validated as UTF-8")
    };
    if let [only] = artifacts {
        return as_text(only);
    }
    let mut text = String::new();
    for artifact in artifacts {
        let contents = as_text(artifact);
        text.push_str("===== BEGIN ");
        text.push_str(&artifact.relative_path);
        text.push_str(" =====\n");
        text.push_str(&contents);
        if !contents.ends_with('\n') {
            text.push('\n');
        }
        text.push_str("===== END ");
        text.push_str(&artifact.relative_path);
        text.push_str(" =====\n\n");
    }
    text
}

#[derive(Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConfigCopyArtifactDto {
    pub key: String,
    pub contents: String,
}

impl fmt::Debug for ConfigCopyArtifactDto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigCopyArtifactDto")
            .field("key", &self.key)
            .field("content_bytes", &self.contents.len())
            .finish()
    }
}

#[derive(Debug, Serialize)]
pub struct ConfigClosedDto {
    pub closed: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigArtifactExportDto {
    pub suggested_name: String,
    pub contents: String,
}

impl fmt::Debug for ConfigArtifactExportDto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigArtifactExportDto")
            .field("suggested_name", &self.suggested_name)
            .field("content_bytes", &self.contents.len())
            .finish()
    }
}

pub(crate) struct ConfigArtifactBytes {
    pub product: &'static str,
    pub suggested_name: String,
    pub bytes: Vec<u8>,
}

impl fmt::Debug for ConfigArtifactBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigArtifactBytes")
            .field("suggested_name", &self.suggested_name)
            .field("byte_length", &self.bytes.len())
            .finish()
    }
}

#[derive(Debug)]
struct BuiltDraft {
    product: &'static str,
    choice: String,
    suggested_name: String,
    artifacts: Vec<BuiltArtifact>,
    notices: Vec<&'static str>,
    /// The typed Tomcat bundle the artifacts came from, kept so the whole
    /// draft can be written by core's create-only directory writer.
    bundle: Option<DraftBundle>,
}

/// A generated multi-file bundle; its debug form names no contents.
#[derive(Clone)]
struct DraftBundle(GeneratedTomcatConfigBundle);

impl fmt::Debug for DraftBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DraftBundle")
            .field("files", &self.0.artifacts().len())
            .field("total_bytes", &self.0.total_bytes())
            .finish()
    }
}

#[derive(Clone)]
struct BuiltArtifact {
    key: String,
    relative_path: String,
    media_type: &'static str,
    bytes: Vec<u8>,
}

impl fmt::Debug for BuiltArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BuiltArtifact")
            .field("key", &self.key)
            .field("relative_path", &self.relative_path)
            .field("media_type", &self.media_type)
            .field("byte_length", &self.bytes.len())
            .finish()
    }
}

impl BuiltDraft {
    fn total_bytes(&self) -> usize {
        self.artifacts
            .iter()
            .map(|artifact| artifact.bytes.len())
            .sum()
    }

    fn validate(&self) -> CoreResult<()> {
        if self.artifacts.is_empty() || self.artifacts.len() > 3 {
            return Err(invalid(
                "generated configuration artifacts",
                "must contain between one and three closed artifacts",
            ));
        }
        let total = self.total_bytes();
        if total == 0 || total > MAX_DRAFT_BYTES {
            return Err(invalid(
                "generated configuration draft",
                "exceeds the bounded in-memory draft size",
            ));
        }
        let mut keys = BTreeSet::new();
        let mut paths = BTreeSet::new();
        for artifact in &self.artifacts {
            validate_artifact_key(&artifact.key)?;
            if !keys.insert(&artifact.key) || !paths.insert(&artifact.relative_path) {
                return Err(invalid(
                    "generated configuration artifacts",
                    "artifact keys and relative paths must be unique",
                ));
            }
            if artifact.relative_path.is_empty()
                || artifact.relative_path.len() > 256
                || artifact.relative_path.contains("..")
                || artifact.relative_path.starts_with(['/', '\\'])
                || artifact.relative_path.chars().any(char::is_control)
            {
                return Err(invalid(
                    "generated configuration artifact path",
                    "must be a bounded fixed relative path",
                ));
            }
            std::str::from_utf8(&artifact.bytes).map_err(|_| {
                invalid(
                    "generated configuration artifact",
                    "must be valid UTF-8 from a typed core generator",
                )
            })?;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct PendingDraft {
    revision: u64,
    expires_at: Instant,
    draft: BuiltDraft,
}

#[derive(Default, Debug)]
struct DraftRegistry {
    drafts: HashMap<String, PendingDraft>,
    order: VecDeque<String>,
    total_bytes: usize,
}

impl DraftRegistry {
    fn insert(&mut self, draft: BuiltDraft, now: Instant) -> CoreResult<(String, u64)> {
        draft.validate()?;
        while self.drafts.len() >= MAX_DRAFTS
            || self.total_bytes.saturating_add(draft.total_bytes()) > MAX_REGISTRY_BYTES
        {
            self.evict_oldest()?;
        }
        let handle = unique_handle(&self.drafts)?;
        self.total_bytes += draft.total_bytes();
        self.order.push_back(handle.clone());
        self.drafts.insert(
            handle.clone(),
            PendingDraft {
                revision: 1,
                expires_at: now + DRAFT_TTL,
                draft,
            },
        );
        Ok((handle, 1))
    }

    fn replace(
        &mut self,
        handle: &str,
        revision: u64,
        draft: BuiltDraft,
        now: Instant,
    ) -> CoreResult<u64> {
        draft.validate()?;
        let pending = self.current(handle, revision)?;
        let next_revision = pending
            .revision
            .checked_add(1)
            .ok_or_else(|| invalid("configuration draft revision", "revision exhausted"))?;
        let previous_bytes = pending.draft.total_bytes();
        let projected = self
            .total_bytes
            .saturating_sub(previous_bytes)
            .saturating_add(draft.total_bytes());
        if projected > MAX_REGISTRY_BYTES {
            return Err(invalid(
                "configuration draft registry",
                "the replacement exceeds the total registry byte limit",
            ));
        }
        let pending = self.drafts.get_mut(handle).expect("current checked handle");
        self.total_bytes = projected;
        pending.revision = next_revision;
        pending.expires_at = now + DRAFT_TTL;
        pending.draft = draft;
        Ok(next_revision)
    }

    fn dto(&self, handle: &str, revision: u64) -> CoreResult<ConfigDraftDto> {
        let pending = self.current(handle, revision)?;
        let total_bytes = pending.draft.total_bytes();
        let copy_allowed = total_bytes <= MAX_COPY_BYTES;
        let mut remaining_preview = MAX_PREVIEW_BYTES;
        let artifacts = pending
            .draft
            .artifacts
            .iter()
            .map(|artifact| {
                let (preview, truncated) = utf8_preview(&artifact.bytes, remaining_preview);
                remaining_preview = remaining_preview.saturating_sub(preview.len());
                ConfigDraftArtifactDto {
                    key: artifact.key.clone(),
                    relative_path: artifact.relative_path.clone(),
                    media_type: artifact.media_type,
                    byte_length: artifact.bytes.len(),
                    preview,
                    preview_truncated: truncated,
                    copy_allowed: copy_allowed && artifact.bytes.len() <= MAX_COPY_BYTES,
                }
            })
            .collect();
        Ok(ConfigDraftDto {
            handle: handle.to_owned(),
            revision,
            product: pending.draft.product,
            choice: pending.draft.choice.clone(),
            suggested_name: pending.draft.suggested_name.clone(),
            total_bytes,
            copy_allowed,
            artifacts,
            notices: pending.draft.notices.clone(),
        })
    }

    fn copy(&self, handle: &str, revision: u64) -> CoreResult<ConfigCopyDto> {
        let pending = self.current(handle, revision)?;
        if pending.draft.total_bytes() > MAX_COPY_BYTES {
            return Err(invalid(
                "configuration copy",
                "the complete draft is too large for the bounded copy channel",
            ));
        }
        let artifacts = pending
            .draft
            .artifacts
            .iter()
            .map(|artifact| ConfigCopyArtifactDto {
                key: artifact.key.clone(),
                contents: String::from_utf8(artifact.bytes.clone())
                    .expect("typed generators were validated as UTF-8"),
            })
            .collect();
        Ok(ConfigCopyDto {
            revision,
            artifacts,
            text: review_copy_text(&pending.draft.artifacts),
        })
    }

    fn bundle(&self, handle: &str, revision: u64) -> CoreResult<DraftBundle> {
        let pending = self.current(handle, revision)?;
        pending.draft.bundle.clone().ok_or_else(|| {
            invalid(
                "configuration bundle export",
                "only a multi-file draft is written as a directory",
            )
        })
    }

    fn artifact_bytes(
        &self,
        handle: &str,
        revision: u64,
        artifact_key: &str,
    ) -> CoreResult<ConfigArtifactBytes> {
        let pending = self.current(handle, revision)?;
        let artifact = pending
            .draft
            .artifacts
            .iter()
            .find(|artifact| artifact.key == artifact_key)
            .ok_or_else(draft_not_found)?;
        Ok(ConfigArtifactBytes {
            product: pending.draft.product,
            suggested_name: artifact.relative_path.clone(),
            bytes: artifact.bytes.clone(),
        })
    }

    fn close(&mut self, handle: &str, revision: u64) -> CoreResult<()> {
        self.current(handle, revision)?;
        let pending = self.drafts.remove(handle).expect("current checked handle");
        self.total_bytes = self.total_bytes.saturating_sub(pending.draft.total_bytes());
        self.order.retain(|existing| existing != handle);
        Ok(())
    }

    fn current(&self, handle: &str, revision: u64) -> CoreResult<&PendingDraft> {
        let pending = self.drafts.get(handle).ok_or_else(draft_not_found)?;
        if revision == 0 || pending.revision != revision {
            return Err(invalid(
                "configuration draft revision",
                "the draft revision is stale",
            ));
        }
        Ok(pending)
    }

    fn remove_expired(&mut self, now: Instant) {
        let expired = self
            .drafts
            .iter()
            .filter_map(|(handle, pending)| (pending.expires_at <= now).then_some(handle.clone()))
            .collect::<Vec<_>>();
        for handle in expired {
            if let Some(pending) = self.drafts.remove(&handle) {
                self.total_bytes = self.total_bytes.saturating_sub(pending.draft.total_bytes());
            }
        }
        self.order.retain(|handle| self.drafts.contains_key(handle));
    }

    fn evict_oldest(&mut self) -> CoreResult<()> {
        let handle = self.order.pop_front().ok_or_else(|| {
            invalid(
                "configuration draft registry",
                "cannot satisfy the bounded registry capacity",
            )
        })?;
        if let Some(pending) = self.drafts.remove(&handle) {
            self.total_bytes = self.total_bytes.saturating_sub(pending.draft.total_bytes());
        }
        Ok(())
    }
}

fn build_draft(input: ConfigGenerateInput) -> CoreResult<BuiltDraft> {
    let draft = match input {
        ConfigGenerateInput::Nginx {
            choice,
            features,
            values,
        } => build_nginx(choice, features, values)?,
        ConfigGenerateInput::Apache {
            choice,
            features,
            values,
        } => build_apache(choice, features, values)?,
        ConfigGenerateInput::Haproxy {
            choice,
            features,
            values,
        } => build_haproxy(choice, features, values)?,
        ConfigGenerateInput::Mysql {
            choice,
            features,
            values,
        } => build_mysql(choice, features, values)?,
        ConfigGenerateInput::Postgresql {
            choice,
            features,
            values,
        } => build_postgresql(choice, features, values)?,
        ConfigGenerateInput::Mariadb {
            choice,
            features,
            values,
        } => build_mariadb(choice, features, values)?,
        ConfigGenerateInput::Mongodb {
            choice,
            features,
            values,
        } => build_mongodb(choice, features, values)?,
        ConfigGenerateInput::Redis {
            choice,
            features,
            values,
        } => build_redis(choice, features, values)?,
        ConfigGenerateInput::Tomcat {
            choice,
            features,
            values,
        } => build_tomcat(choice, features, values)?,
    };
    draft.validate()?;
    Ok(draft)
}

fn build_nginx(
    choice: String,
    requested: Option<Vec<String>>,
    values: NginxValues,
) -> CoreResult<BuiltDraft> {
    let kind = parse_nginx_kind(&choice)?;
    let features = select_features(
        requested,
        &NginxSiteFeature::ALL,
        NginxSiteFeature::key,
        NginxSiteFeature::default_enabled,
        |feature| feature.supports_kind(kind),
        "Nginx feature",
    )?;
    let target = match kind {
        NginxSiteKind::Static => {
            NginxSiteTarget::Static(NginxStaticRoot::parse(&values.static_root)?)
        }
        NginxSiteKind::ReverseProxy => {
            NginxSiteTarget::ReverseProxy(NginxUpstream::parse(&values.upstream)?)
        }
    };
    let mut config = NginxSiteConfig::new(
        NginxServerNames::parse(&values.server_name)?,
        NginxListenPort::parse(&values.listen_port)?,
        target,
        false,
    )?;
    for feature in NginxSiteFeature::ALL {
        config = config.with_feature(feature, features.contains(&feature))?;
    }
    if features.contains(&NginxSiteFeature::ForbiddenPath403) {
        config = config.with_forbidden_path_rule(NginxForbiddenPathRule::new(
            NginxForbiddenPath::parse(&values.forbidden_path)?,
            parse_nginx_scope(&values.forbidden_scope)?,
        )?)?;
    }
    if features.contains(&NginxSiteFeature::RestrictSourceIp) {
        config =
            config.with_allowed_source_rule(NginxAllowedSource::parse(&values.allowed_source)?)?;
    }
    let generated = config.generate()?;
    Ok(single_draft(
        "nginx",
        choice,
        generated.suggested_file_name(),
        "site",
        "nginx-site.conf",
        "text/plain",
        generated.contents(),
        "仅生成本地草稿；部署前必须由目标 Nginx 版本、完整 include 图和 nginx -t 验证。",
    ))
}

fn build_apache(
    choice: String,
    requested: Option<Vec<String>>,
    values: ApacheValues,
) -> CoreResult<BuiltDraft> {
    let kind = parse_apache_kind(&choice)?;
    let features = select_features(
        requested,
        &ApacheSiteFeature::ALL,
        ApacheSiteFeature::key,
        ApacheSiteFeature::default_enabled,
        |feature| feature.supports_kind(kind),
        "Apache feature",
    )?;
    let target = match kind {
        ApacheSiteKind::Static => {
            ApacheSiteTarget::Static(ApacheStaticRoot::parse(&values.static_root)?)
        }
        ApacheSiteKind::ReverseProxy => {
            ApacheSiteTarget::ReverseProxy(ApacheUpstream::parse(&values.upstream)?)
        }
    };
    let mut config = ApacheSiteConfig::new(
        ApacheServerName::parse(&values.server_name)?,
        ApacheListenPort::parse(&values.listen_port)?,
        target,
        false,
    )?;
    for feature in ApacheSiteFeature::ALL {
        config = config.with_feature(feature, features.contains(&feature))?;
    }
    if features.contains(&ApacheSiteFeature::ForbiddenPath403) {
        config = config.with_forbidden_path_rule(ApacheForbiddenPathRule::new(
            ApacheForbiddenPath::parse(&values.forbidden_path)?,
            parse_apache_scope(&values.forbidden_scope)?,
        )?)?;
    }
    if features.contains(&ApacheSiteFeature::RestrictSourceIp) {
        config =
            config.with_allowed_source_rule(ApacheAllowedSource::parse(&values.allowed_source)?)?;
    }
    let generated = config.generate()?;
    Ok(single_draft(
        "apache",
        choice,
        generated.suggested_file_name(),
        "site",
        "apache-site.conf",
        "text/plain",
        generated.contents(),
        "仅生成本地草稿；部署前必须核对目标 httpd 模块、完整 include 图并运行目标 httpd -t。",
    ))
}

fn build_haproxy(
    choice: String,
    requested: Option<Vec<String>>,
    values: HaProxyValues,
) -> CoreResult<BuiltDraft> {
    let version = HaProxyVersion::parse(&choice)?;
    let features = select_features(
        requested,
        &HaProxyConfigFeature::ALL,
        HaProxyConfigFeature::key,
        HaProxyConfigFeature::default_enabled,
        |feature| feature.supports_version(version),
        "HAProxy feature",
    )?;
    let mut config = HaProxyHttpConfig::baseline(
        version,
        HaProxyListenAddress::parse(&values.listen_address)?,
        HaProxyListenPort::parse(&values.listen_port)?,
        HaProxyUpstream::parse(&values.upstream)?,
    )?;
    for feature in HaProxyConfigFeature::ALL {
        if features.contains(&feature)
            && matches!(
                feature,
                HaProxyConfigFeature::ForbiddenPath403 | HaProxyConfigFeature::RestrictSourceIp
            )
        {
            continue;
        }
        config = config.with_feature(feature, features.contains(&feature))?;
    }
    if features.contains(&HaProxyConfigFeature::ForbiddenPath403) {
        config = config.with_forbidden_path_rule(HaProxyForbiddenPathRule::new(
            HaProxyForbiddenPath::parse(&values.forbidden_path)?,
            parse_haproxy_scope(&values.forbidden_scope)?,
        )?)?;
    }
    if features.contains(&HaProxyConfigFeature::RestrictSourceIp) {
        config =
            config.with_allowed_source(HaProxyAllowedSource::parse(&values.allowed_source)?)?;
    }
    let generated = config.generate()?;
    Ok(single_draft(
        "haproxy",
        choice,
        generated.suggested_file_name(),
        "main",
        "haproxy.cfg",
        "text/plain",
        generated.contents(),
        "TLS 前端保持关闭；草稿必须由目标 haproxy -c -f 验证。",
    ))
}

fn build_mysql(
    choice: String,
    requested: Option<Vec<String>>,
    values: MySqlValues,
) -> CoreResult<BuiltDraft> {
    if choice != "8.4.0" {
        return Err(invalid("MySQL version", "must be exactly 8.4.0"));
    }
    let features = select_features(
        requested,
        &MySqlConfigFeature::ALL,
        MySqlConfigFeature::key,
        MySqlConfigFeature::default_enabled,
        |_| true,
        "MySQL feature",
    )?;
    let version =
        MySqlConfigVersion::new(8, 4, 0).map_err(|error| display_error("MySQL version", error))?;
    let mut config = MySqlConfig::baseline(version);
    for feature in MySqlConfigFeature::ALL {
        if !features.contains(&feature) {
            continue;
        }
        config = match feature {
            MySqlConfigFeature::RemoteListener => config
                .with_remote_listener(parse_number("MySQL bind_address", &values.remote_listener)?),
            MySqlConfigFeature::MaxConnections => config.with_max_connections(parse_number(
                "MySQL max_connections",
                &values.max_connections,
            )?),
            MySqlConfigFeature::ConnectTimeout => config.with_connect_timeout_seconds(
                parse_number("MySQL connect_timeout", &values.connect_timeout)?,
            ),
            MySqlConfigFeature::MaxConnectErrors => config.with_max_connect_errors(parse_number(
                "MySQL max_connect_errors",
                &values.max_connect_errors,
            )?),
            MySqlConfigFeature::SessionTimeouts => config.with_session_timeouts_seconds(
                parse_number("MySQL wait_timeout", &values.wait_timeout)?,
                parse_number("MySQL interactive_timeout", &values.interactive_timeout)?,
            ),
            MySqlConfigFeature::SlowQueryLog => config.with_slow_query_log_seconds(parse_number(
                "MySQL long_query_time",
                &values.long_query_time,
            )?),
            MySqlConfigFeature::LogErrorVerbosity => config.with_log_error_verbosity(parse_number(
                "MySQL log_error_verbosity",
                &values.log_error_verbosity,
            )?),
            MySqlConfigFeature::BinaryLogging => {
                config.with_binary_logging(parse_number("MySQL server_id", &values.server_id)?)
            }
            MySqlConfigFeature::BinaryLogRetention => config.with_binary_log_retention_seconds(
                parse_number("MySQL binlog retention", &values.binlog_retention)?,
            ),
            _ => config.with_feature(feature, true),
        }
        .map_err(|error| display_error("MySQL configuration", error))?;
    }
    let generated = config
        .generate()
        .map_err(|error| display_error("MySQL configuration", error))?;
    Ok(single_draft(
        "mysql",
        choice,
        generated.suggested_file_name(),
        "main",
        "my.cnf",
        "text/plain",
        generated.contents(),
        "远程监听不替代账号 Host、TLS 或防火墙；输出必须由同系列目标 mysqld --validate-config 验证。",
    ))
}

fn build_postgresql(
    choice: String,
    requested: Option<Vec<String>>,
    values: PostgreSqlValues,
) -> CoreResult<BuiltDraft> {
    let version = PostgreSqlVersion::parse(&choice)?;
    let features = select_features(
        requested,
        &PostgreSqlConfigFeature::ALL,
        PostgreSqlConfigFeature::key,
        PostgreSqlConfigFeature::default_enabled,
        |feature| feature.supports_version(version),
        "PostgreSQL feature",
    )?;
    let mut config =
        PostgreSqlConfig::baseline(version).with_port(PostgreSqlPort::parse(&values.port)?);
    for feature in PostgreSqlConfigFeature::ALL {
        if !features.contains(&feature) {
            continue;
        }
        config = match feature {
            PostgreSqlConfigFeature::ConnectionCapacity => {
                config.with_connection_capacity(PostgreSqlConnectionCapacity::parse(
                    &values.max_connections,
                    &values.superuser_reserved_connections,
                    &values.reserved_connections,
                )?)
            }
            PostgreSqlConfigFeature::AuthenticationTimeout => config.with_authentication_timeout(
                PostgreSqlAuthenticationTimeoutSeconds::parse(&values.authentication_timeout)?,
            ),
            PostgreSqlConfigFeature::IdleInTransactionGuard => config
                .with_idle_in_transaction_timeout(
                    PostgreSqlIdleInTransactionTimeoutSeconds::parse(
                        &values.idle_in_transaction_timeout,
                    )?,
                ),
            PostgreSqlConfigFeature::IdleSessionGuard => config.with_idle_session_timeout(
                PostgreSqlIdleSessionTimeoutSeconds::parse(&values.idle_session_timeout)?,
            ),
            PostgreSqlConfigFeature::TemporaryFileLimit => config.with_temporary_file_limit(
                PostgreSqlTemporaryFileLimitMebibytes::parse(&values.temporary_file_limit)?,
            ),
            PostgreSqlConfigFeature::LockWaitLogging => config.with_lock_wait_logging_threshold(
                PostgreSqlLockWaitThresholdMilliseconds::parse(&values.lock_wait_threshold)?,
            ),
            PostgreSqlConfigFeature::AutovacuumLogging => config.with_autovacuum_logging_threshold(
                PostgreSqlAutovacuumLogThresholdMilliseconds::parse(
                    &values.autovacuum_log_threshold,
                )?,
            ),
            PostgreSqlConfigFeature::TemporaryFileLogging => config
                .with_temporary_file_logging_threshold(
                    PostgreSqlTemporaryFileLogThresholdKilobytes::parse(
                        &values.temporary_file_log_threshold,
                    )?,
                ),
            PostgreSqlConfigFeature::WalCompression => config
                .with_wal_compression(PostgreSqlWalCompression::parse(&values.wal_compression)?),
            _ => config.with_feature(feature, true),
        }?;
    }
    let generated = config.generate()?;
    Ok(single_draft(
        "postgresql",
        choice,
        generated.suggested_file_name(),
        "main",
        "postgresql.conf",
        "text/plain",
        generated.contents(),
        "输出不包含 pg_hba.conf、pg_ident.conf 或 TLS；必须由完全相同 major 的目标验证。",
    ))
}

fn build_mariadb(
    choice: String,
    requested: Option<Vec<String>>,
    values: MariaDbValues,
) -> CoreResult<BuiltDraft> {
    let version = MariaDbVersion::parse(&choice)?;
    let features = select_features(
        requested,
        &MariaDbConfigFeature::ALL,
        MariaDbConfigFeature::key,
        MariaDbConfigFeature::default_enabled,
        |feature| feature.supports_version(version),
        "MariaDB feature",
    )?;
    let character_profile = match values.character_profile.as_str() {
        "unicode-case-insensitive" => MariaDbCharacterProfile::UnicodeCaseInsensitive,
        "unicode-binary" => MariaDbCharacterProfile::UnicodeBinary,
        _ => {
            return Err(invalid(
                "MariaDB character profile",
                "must be unicode-case-insensitive or unicode-binary",
            ));
        }
    };
    let mut config = MariaDbConfig::baseline(version).with_port(MariaDbPort::parse(&values.port)?);
    for feature in MariaDbConfigFeature::ALL {
        if !features.contains(&feature) {
            continue;
        }
        config = match feature {
            MariaDbConfigFeature::ConnectionCapacity => {
                config.with_max_connections(MariaDbMaxConnections::parse(&values.max_connections)?)
            }
            MariaDbConfigFeature::HandshakeTimeout => config.with_connect_timeout(
                MariaDbConnectTimeoutSeconds::parse(&values.connect_timeout)?,
            ),
            MariaDbConfigFeature::SessionIdleTimeouts => {
                config.with_session_idle_timeouts(MariaDbSessionIdleTimeouts::parse(
                    &values.wait_timeout,
                    &values.interactive_timeout,
                )?)
            }
            MariaDbConfigFeature::HostErrorThreshold => config.with_max_connect_errors(
                MariaDbMaxConnectErrors::parse(&values.max_connect_errors)?,
            ),
            MariaDbConfigFeature::MaximumPacketSize => config.with_max_allowed_packet(
                MariaDbMaxAllowedPacketMebibytes::parse(&values.max_allowed_packet)?,
            ),
            MariaDbConfigFeature::SlowQueryLog => config
                .with_slow_query_time(MariaDbSlowQueryTimeSeconds::parse(&values.slow_query_time)?),
            MariaDbConfigFeature::BinaryLogging => {
                config.with_server_id(MariaDbServerId::parse(&values.server_id)?)
            }
            MariaDbConfigFeature::BinaryLogRetention => config.with_binary_log_retention(
                MariaDbBinaryLogRetentionSeconds::parse(&values.binlog_retention)?,
            ),
            MariaDbConfigFeature::CharacterSetAndCollation => {
                config.with_character_profile(character_profile)
            }
            MariaDbConfigFeature::InnoDbLockWaitTimeout => config.with_innodb_lock_wait_timeout(
                MariaDbInnoDbLockWaitTimeoutSeconds::parse(&values.innodb_lock_wait_timeout)?,
            ),
            _ => config.with_feature(feature, true),
        }?;
    }
    let generated = config.generate()?;
    Ok(single_draft(
        "mariadb",
        choice,
        generated.suggested_file_name(),
        "main",
        "mariadb.cnf",
        "text/plain",
        generated.contents(),
        "配置来源、发行包默认值与目标 option validator 必须独立核对；不会猜测既有实例迁移。",
    ))
}

fn build_mongodb(
    choice: String,
    requested: Option<Vec<String>>,
    values: MongoDbValues,
) -> CoreResult<BuiltDraft> {
    let version = MongoDbVersion::parse(&choice)?;
    let features = select_features(
        requested,
        &MongoDbConfigFeature::ALL,
        MongoDbConfigFeature::key,
        MongoDbConfigFeature::default_enabled,
        |feature| feature.supports_version(version),
        "MongoDB feature",
    )?;
    let mut config = MongoDbConfig::baseline(version).with_port(MongoDbPort::parse(&values.port)?);
    for feature in MongoDbConfigFeature::ALL {
        if !features.contains(&feature) {
            continue;
        }
        config = match feature {
            MongoDbConfigFeature::ConnectionLimit => config
                .with_connection_limit(MongoDbConnectionLimit::parse(&values.max_connections)?),
            MongoDbConfigFeature::SlowOperationLogging => {
                config.with_slow_operation_logging(MongoDbSlowOperationSettings::parse(
                    &values.slow_operation_threshold,
                    &values.slow_operation_sample_rate,
                )?)
            }
            MongoDbConfigFeature::SlowInProgressLogging => config.with_slow_in_progress_logging(
                MongoDbSlowInProgressThreshold::parse(&values.slow_in_progress_threshold)?,
            ),
            MongoDbConfigFeature::LogRotation => config.with_log_rotation(MongoDbLogRotation::new(
                MongoDbLogPath::parse(&values.log_path)?,
                MongoDbLogRotationMode::parse(&values.log_rotation_mode)?,
            )),
            MongoDbConfigFeature::WiredTigerCache => config.with_wired_tiger_cache(
                MongoDbWiredTigerCacheSize::parse_gigabytes(&values.wired_tiger_cache_gib)?,
            ),
            MongoDbConfigFeature::WiredTigerCompression => {
                config.with_compression(MongoDbCompression::new(
                    MongoDbCompressor::parse(&values.collection_compressor)?,
                    MongoDbCompressor::parse(&values.journal_compressor)?,
                ))
            }
            _ => config.with_feature(feature, true),
        }?;
    }
    let generated = config.generate()?;
    Ok(single_draft(
        "mongodb",
        choice,
        generated.suggested_file_name(),
        "main",
        "mongod.conf",
        "application/yaml",
        generated.contents(),
        "不猜测 dbPath、TLS、凭据、replica set 或既有数据迁移；输出仅为新部署的本地审阅草稿。",
    ))
}

fn build_redis(
    choice: String,
    requested: Option<Vec<String>>,
    values: RedisValues,
) -> CoreResult<BuiltDraft> {
    let version = RedisVersion::parse(&choice)?;
    let features = select_features(
        requested,
        &RedisConfigFeature::ALL,
        RedisConfigFeature::key,
        RedisConfigFeature::default_enabled,
        |feature| feature.supports_version(version),
        "Redis feature",
    )?;
    let bind_profile = match values.bind_profile.as_str() {
        "ipv4-loopback" => RedisBindProfile::Ipv4Loopback,
        "dual-stack-loopback" => RedisBindProfile::DualStackLoopback,
        _ => {
            return Err(invalid(
                "Redis bind profile",
                "must be ipv4-loopback or dual-stack-loopback",
            ));
        }
    };
    let eviction_policy = RedisEvictionPolicy::ALL
        .into_iter()
        .find(|policy| policy.directive_value() == values.eviction_policy)
        .ok_or_else(|| invalid("Redis eviction policy", "must be one closed catalog policy"))?;
    let append_fsync = RedisAppendFsync::ALL
        .into_iter()
        .find(|policy| policy.directive_value() == values.append_fsync)
        .ok_or_else(|| invalid("Redis appendfsync", "must be always, everysec, or no"))?;
    let mut config = RedisConfig::baseline(version)
        .with_bind_profile(bind_profile)
        .with_port(RedisPort::parse(&values.port)?)
        .with_data_directory(RedisDataDirectory::parse(&values.data_directory)?)?;
    for feature in RedisConfigFeature::ALL {
        config = if features.contains(&feature) {
            match feature {
                RedisConfigFeature::MaxClients => {
                    config.with_max_clients(RedisMaxClients::parse(&values.max_clients)?)
                }
                RedisConfigFeature::IdleClientTimeout => {
                    config.with_idle_timeout(RedisIdleTimeoutSeconds::parse(&values.idle_timeout)?)
                }
                RedisConfigFeature::TcpKeepalive => config
                    .with_tcp_keepalive(RedisTcpKeepaliveSeconds::parse(&values.tcp_keepalive)?),
                RedisConfigFeature::MemoryLimit => config
                    .with_memory_limit(RedisMaxmemory::parse_mebibytes(&values.maxmemory_mib)?),
                RedisConfigFeature::EvictionPolicy => config.with_eviction_policy(eviction_policy),
                RedisConfigFeature::AofPersistence => config.with_append_fsync(append_fsync),
                RedisConfigFeature::RdbPersistence => config.with_feature(feature, true),
                RedisConfigFeature::SlowLog => config.with_slow_log(RedisSlowLogConfig::new(
                    parse_number("Redis slowlog threshold", &values.slowlog_threshold)?,
                    parse_number("Redis slowlog length", &values.slowlog_length)?,
                )?),
                RedisConfigFeature::LatencyMonitor => config.with_latency_threshold(
                    RedisLatencyThresholdMilliseconds::parse(&values.latency_threshold)?,
                ),
            }
        } else {
            config.with_feature(feature, false)
        }?;
    }
    let generated = config.generate()?;
    Ok(single_draft(
        "redis",
        choice,
        generated.suggested_file_name(),
        "main",
        "redis.conf",
        "text/plain",
        generated.contents(),
        "只面向全新空实例；认证、ACL、远程暴露、既有数据迁移和目标启动验证不由静态草稿替代。",
    ))
}

fn build_tomcat(
    choice: String,
    requested: Option<Vec<String>>,
    values: TomcatValues,
) -> CoreResult<BuiltDraft> {
    let version = parse_tomcat_version(&choice)?;
    let features = select_features(
        requested,
        &TomcatConfigFeature::ALL,
        TomcatConfigFeature::key,
        TomcatConfigFeature::default_enabled,
        |feature| feature.supports_version(version),
        "Tomcat feature",
    )?;
    let address = match values.connector_address.as_str() {
        "ipv4-loopback" => TomcatConnectorAddress::Ipv4Loopback,
        "ipv6-loopback" => TomcatConnectorAddress::Ipv6Loopback,
        _ => {
            return Err(invalid(
                "Tomcat connector address",
                "must be ipv4-loopback or ipv6-loopback",
            ));
        }
    };
    let connector = TomcatConnectorConfig::new(
        address,
        TomcatConnectorPort::parse(&values.port)?,
        TomcatConnectionTimeoutMillis::parse(&values.connection_timeout)?,
        TomcatMaxThreads::parse(&values.max_threads)?,
        TomcatAcceptCount::parse(&values.accept_count)?,
        TomcatMaxConnections::parse(&values.max_connections)?,
        TomcatFormParameterBytes::parse(&values.max_post_size)?,
        TomcatAbortedUploadSwallowBytes::parse(&values.max_swallow_size)?,
    )?;
    let mut config = TomcatConfig::baseline(version)
        .with_application_name(TomcatApplicationName::parse(&values.application_name)?)
        .with_connector(connector)?;
    for feature in TomcatConfigFeature::ALL {
        config = config.with_feature(feature, features.contains(&feature))?;
    }
    if features.contains(&TomcatConfigFeature::ResponseCompression) {
        config = config.with_compression_min_size(TomcatCompressionMinBytes::parse(
            &values.compression_min_size,
        )?);
    }
    let generated = config.generate()?;
    let artifacts = generated
        .artifacts()
        .iter()
        .map(|artifact| BuiltArtifact {
            key: artifact.file_name().to_owned(),
            relative_path: artifact.relative_path().to_owned(),
            media_type: "application/xml",
            bytes: artifact.contents().as_bytes().to_vec(),
        })
        .collect();
    Ok(BuiltDraft {
        product: "tomcat",
        choice,
        suggested_name: generated.suggested_directory_name().to_owned(),
        artifacts,
        notices: vec![TOMCAT_BUNDLE_SCOPE_NOTICE],
        bundle: Some(DraftBundle(generated)),
    })
}

#[allow(clippy::too_many_arguments)]
fn single_draft(
    product: &'static str,
    choice: String,
    suggested_name: impl Into<String>,
    key: &str,
    relative_path: &str,
    media_type: &'static str,
    contents: &str,
    notice: &'static str,
) -> BuiltDraft {
    BuiltDraft {
        product,
        choice,
        suggested_name: suggested_name.into(),
        artifacts: vec![BuiltArtifact {
            key: key.to_owned(),
            relative_path: relative_path.to_owned(),
            media_type,
            bytes: contents.as_bytes().to_vec(),
        }],
        notices: vec![notice],
        bundle: None,
    }
}

fn select_features<T: Copy + Ord>(
    requested: Option<Vec<String>>,
    all: &[T],
    key: impl Fn(T) -> &'static str,
    default_enabled: impl Fn(T) -> bool,
    supported: impl Fn(T) -> bool,
    subject: &'static str,
) -> CoreResult<BTreeSet<T>> {
    let Some(requested) = requested else {
        return Ok(all
            .iter()
            .copied()
            .filter(|feature| default_enabled(*feature) && supported(*feature))
            .collect());
    };
    if requested.len() > all.len() || requested.len() > MAX_FEATURE_KEYS {
        return Err(invalid(subject, "contains too many feature keys"));
    }
    let mut selected = BTreeSet::new();
    for requested_key in requested {
        if requested_key.is_empty()
            || requested_key.len() > 128
            || requested_key.chars().any(char::is_control)
        {
            return Err(invalid(subject, "contains an invalid feature key"));
        }
        let feature = all
            .iter()
            .copied()
            .find(|feature| key(*feature) == requested_key)
            .ok_or_else(|| invalid(subject, "contains an unknown canonical feature key"))?;
        if !supported(feature) {
            return Err(invalid(
                subject,
                "contains a feature unsupported by the selected choice",
            ));
        }
        if !selected.insert(feature) {
            return Err(invalid(subject, "contains a duplicate feature key"));
        }
    }
    Ok(selected)
}

fn parse_nginx_kind(value: &str) -> CoreResult<NginxSiteKind> {
    match value {
        "static" => Ok(NginxSiteKind::Static),
        "reverse-proxy" => Ok(NginxSiteKind::ReverseProxy),
        _ => Err(invalid("Nginx mode", "must be static or reverse-proxy")),
    }
}

fn parse_apache_kind(value: &str) -> CoreResult<ApacheSiteKind> {
    match value {
        "static" => Ok(ApacheSiteKind::Static),
        "reverse-proxy" => Ok(ApacheSiteKind::ReverseProxy),
        _ => Err(invalid("Apache mode", "must be static or reverse-proxy")),
    }
}

fn parse_nginx_scope(value: &str) -> CoreResult<NginxForbiddenPathScope> {
    match value {
        "exact" => Ok(NginxForbiddenPathScope::Exact),
        "path-and-descendants" => Ok(NginxForbiddenPathScope::PathAndDescendants),
        _ => Err(invalid("Nginx forbidden-path scope", "is not supported")),
    }
}

fn parse_apache_scope(value: &str) -> CoreResult<ApacheForbiddenPathScope> {
    match value {
        "exact" => Ok(ApacheForbiddenPathScope::Exact),
        "path-and-descendants" => Ok(ApacheForbiddenPathScope::PathAndDescendants),
        _ => Err(invalid("Apache forbidden-path scope", "is not supported")),
    }
}

fn parse_haproxy_scope(value: &str) -> CoreResult<HaProxyForbiddenPathScope> {
    match value {
        "exact" => Ok(HaProxyForbiddenPathScope::Exact),
        "path-and-descendants" => Ok(HaProxyForbiddenPathScope::PathAndDescendants),
        _ => Err(invalid("HAProxy forbidden-path scope", "is not supported")),
    }
}

fn parse_tomcat_version(value: &str) -> CoreResult<TomcatVersionFamily> {
    match value {
        "9.0" => Ok(TomcatVersionFamily::V9_0),
        "10.1" => Ok(TomcatVersionFamily::V10_1),
        "11.0" => Ok(TomcatVersionFamily::V11_0),
        _ => Err(invalid("Tomcat version", "must be 9.0, 10.1, or 11.0")),
    }
}

fn parse_number<T>(subject: &'static str, value: &str) -> CoreResult<T>
where
    T: std::str::FromStr,
    T::Err: fmt::Display,
{
    value
        .trim()
        .parse()
        .map_err(|error| display_error(subject, error))
}

fn display_error(subject: &'static str, error: impl fmt::Display) -> CoreError {
    invalid(subject, error.to_string())
}

fn utf8_preview(bytes: &[u8], maximum: usize) -> (String, bool) {
    if bytes.len() <= maximum {
        return (
            String::from_utf8(bytes.to_vec()).expect("typed generated artifacts are UTF-8"),
            false,
        );
    }
    let mut end = maximum.min(bytes.len());
    while end > 0 && std::str::from_utf8(&bytes[..end]).is_err() {
        end -= 1;
    }
    (
        String::from_utf8(bytes[..end].to_vec()).expect("preview ends on a UTF-8 boundary"),
        true,
    )
}

fn unique_handle<T>(existing: &HashMap<String, T>) -> CoreResult<String> {
    for _ in 0..8 {
        let handle = Uuid::new_v4().to_string();
        if !existing.contains_key(&handle) {
            return Ok(handle);
        }
    }
    Err(invalid(
        "configuration draft handle",
        "could not allocate a unique opaque capability",
    ))
}

fn validate_handle(value: &str) -> CoreResult<()> {
    if value.is_empty()
        || value.len() > MAX_HANDLE_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(invalid(
            "configuration draft handle",
            "must be a bounded opaque identifier",
        ));
    }
    Ok(())
}

fn validate_artifact_key(value: &str) -> CoreResult<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(invalid(
            "configuration artifact key",
            "must be a bounded closed identifier",
        ));
    }
    Ok(())
}

fn draft_not_found() -> CoreError {
    CoreError::NotFound {
        entity: "configuration draft capability",
        id: "[opaque]".to_owned(),
    }
}

fn invalid(subject: &'static str, message: impl Into<String>) -> CoreError {
    CoreError::Validation {
        subject,
        message: message.into(),
    }
}

fn default_reverse_proxy() -> String {
    "reverse-proxy".to_owned()
}
fn default_haproxy_version() -> String {
    "3.4".to_owned()
}
fn default_mysql_version() -> String {
    "8.4.0".to_owned()
}
fn default_postgresql_version() -> String {
    "18".to_owned()
}
fn default_mariadb_version() -> String {
    "12.3".to_owned()
}
fn default_mongodb_version() -> String {
    "8.3".to_owned()
}
fn default_redis_version() -> String {
    "8.10".to_owned()
}
fn default_tomcat_version() -> String {
    "11.0".to_owned()
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use serde_json::{Value, json};

    use super::*;

    #[test]
    fn catalog_covers_nine_unique_products_and_every_typed_feature() {
        let catalog = config_catalog();
        assert_eq!(catalog.products.len(), CONFIG_PRODUCT_COUNT);
        assert_eq!(
            catalog
                .products
                .iter()
                .map(|product| product.features.len())
                .sum::<usize>(),
            CONFIG_FEATURE_COUNT
        );
        let keys = catalog
            .products
            .iter()
            .map(|product| product.key)
            .collect::<HashSet<_>>();
        assert_eq!(keys.len(), CONFIG_PRODUCT_COUNT);
        assert!(keys.contains("haproxy"));
        assert!(keys.contains("mongodb"));
    }

    #[test]
    fn catalog_projects_finite_read_only_reasons_without_mutation_authority() {
        let catalog = config_catalog();
        assert!(!catalog.read_only_artifacts.is_empty());
        assert!(catalog.read_only_artifacts.len() <= MAX_READ_ONLY_ARTIFACTS);
        assert!(
            catalog
                .read_only_artifacts
                .iter()
                .all(|artifact| artifact.authority == "read-only")
        );
        assert_eq!(
            catalog
                .read_only_artifacts
                .iter()
                .map(|artifact| artifact.artifact_key)
                .collect::<HashSet<_>>()
                .len(),
            catalog.read_only_artifacts.len()
        );

        let generated = catalog
            .read_only_artifacts
            .iter()
            .find(|artifact| artifact.artifact_key == "mysql-persisted-variables")
            .expect("generated MySQL artifact is renderer-visible");
        assert_eq!(generated.product_key, "mysql");
        assert_eq!(generated.product_title, "MySQL");
        assert_eq!(generated.title, "mysqld-auto.cnf");
        assert_eq!(generated.reason, "generated-artifact");
        assert!(generated.notice.contains("只读展示"));
        assert!(generated.notice.contains("生成"));

        let vendor = catalog
            .read_only_artifacts
            .iter()
            .find(|artifact| artifact.artifact_key == "opengauss-om-cluster-xml")
            .expect("vendor-schema openGauss artifact is renderer-visible");
        assert_eq!(vendor.product_key, "opengauss");
        assert_eq!(vendor.product_title, "openGauss");
        assert_eq!(vendor.reason, "vendor-schema-required");
        assert!(vendor.notice.contains("schema"));
        assert!(vendor.notice.contains("版本"));

        let public = serde_json::to_value(&catalog).expect("serialize renderer catalog");
        let public_rows = public
            .get("readOnlyArtifacts")
            .and_then(Value::as_array)
            .expect("camel-case read-only artifact array");
        let public_generated = public_rows
            .iter()
            .find(|artifact| {
                artifact.get("artifactKey")
                    == Some(&Value::String("mysql-persisted-variables".to_owned()))
            })
            .expect("serialized generated artifact");
        assert_eq!(
            public_generated.get("authority"),
            Some(&Value::String("read-only".to_owned()))
        );
        assert_eq!(
            public_generated.get("reason"),
            Some(&Value::String("generated-artifact".to_owned()))
        );
        assert_eq!(
            public_generated.as_object().map(|object| object.len()),
            Some(7)
        );
        assert!(public_generated.get("mutationAllowed").is_none());
        assert!(public_generated.get("editPolicy").is_none());
    }

    #[test]
    fn schema_metadata_never_changes_typed_catalog_local_draft_authority() {
        let catalog = config_catalog();
        let public = serde_json::to_value(&catalog).expect("serialize renderer catalog");
        let public_rows = public
            .get("readOnlyArtifacts")
            .and_then(Value::as_array)
            .expect("camel-case read-only artifact array");

        for (artifact_key, expected_reason) in [
            ("opengauss-om-cluster-xml", "vendor-schema-required"),
            ("mysql-persisted-variables", "generated-artifact"),
        ] {
            let artifact = lovelyhawk_core::database_config::artifact_by_key(artifact_key)
                .expect("registered database artifact");
            let status = artifact
                .read_only_status()
                .expect("fixture artifact remains read-only");
            assert_eq!(
                status.authority,
                DatabaseConfigLocalDraftAuthority::ReadOnly
            );

            let projected = catalog
                .read_only_artifacts
                .iter()
                .find(|candidate| candidate.artifact_key == artifact_key)
                .expect("artifact authority must reach the renderer catalog");
            assert_eq!(projected.authority, "read-only");
            assert_eq!(projected.reason, expected_reason);

            let serialized = public_rows
                .iter()
                .find(|candidate| {
                    candidate.get("artifactKey") == Some(&Value::String(artifact_key.to_owned()))
                })
                .expect("serialized read-only artifact");
            assert_eq!(
                serialized.get("authority"),
                Some(&Value::String("read-only".to_owned()))
            );
            assert_eq!(serialized.as_object().map(|object| object.len()), Some(7));
            for forbidden in [
                "schemaAuthority",
                "schemaCompleteness",
                "localDraftAllowed",
                "mutationAllowed",
                "editPolicy",
            ] {
                assert!(
                    serialized.get(forbidden).is_none(),
                    "schema-derived field leaked: {forbidden}"
                );
            }
        }
    }

    #[test]
    fn compatible_and_domestic_starters_do_not_guess_upstream_defaults() {
        let catalog = config_catalog();
        let public = serde_json::to_value(&catalog).expect("serialize renderer catalog");
        let public_object = public.as_object().expect("catalog object");
        assert_eq!(public_object.len(), 3);
        for forbidden_field in ["databaseStarters", "starterContents", "upstreamDefaults"] {
            assert!(
                public_object.get(forbidden_field).is_none(),
                "catalog leaked {forbidden_field}"
            );
        }

        let public_rows = public
            .get("readOnlyArtifacts")
            .and_then(Value::as_array)
            .expect("camel-case read-only artifact array");
        for key in ["kingbase-es-main", "gbase-8c-main", "tidb-server-toml"] {
            let artifact = lovelyhawk_core::database_config::artifact_by_key(key)
                .expect("registered compatible database artifact");
            let starter = lovelyhawk_core::database_config::database_starter_contents(artifact);
            assert!(starter.contains("导入"), "{key}");
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
                    "{key}: {guessed_default}"
                );
            }
            assert!(
                public_rows
                    .iter()
                    .all(|row| { row.get("artifactKey") != Some(&Value::String(key.to_owned())) }),
                "starter bytes for {key} must stay behind the Rust boundary"
            );
        }
    }

    #[test]
    fn local_visual_selection_hides_managed_runtime_cloud_binary_and_unparsed_artifacts() {
        let catalog = config_catalog();
        for managed_product in [
            "tdsql-mysql-managed",
            "tdsql-postgresql-managed",
            "polardb-managed-mysql",
            "polardb-managed-postgresql",
            "polardb-managed-oracle",
        ] {
            assert!(
                catalog
                    .products
                    .iter()
                    .all(|product| product.key != managed_product),
                "{managed_product} entered the finite local generator catalog"
            );
        }

        let public = serde_json::to_value(&catalog).expect("serialize renderer catalog");
        let public_rows = public
            .get("readOnlyArtifacts")
            .and_then(Value::as_array)
            .expect("camel-case read-only artifact array");
        let api = ConfigApi::default();
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
            let artifact = lovelyhawk_core::database_config::artifact_by_key(key)
                .expect("registered non-visual artifact");
            assert!(!artifact.has_source_backed_visual_parser(), "{key}");
            assert_eq!(
                artifact.local_draft_authority(),
                DatabaseConfigLocalDraftAuthority::ReadOnly,
                "{key} gained local draft authority"
            );

            let projected = catalog
                .read_only_artifacts
                .iter()
                .find(|candidate| candidate.artifact_key == key);
            let serialized = public_rows.iter().find(|candidate| {
                candidate.get("artifactKey") == Some(&Value::String(key.to_owned()))
            });
            assert_eq!(projected.is_some(), serialized.is_some(), "{key}");
            if !artifact.is_file_visual_readable() {
                assert!(projected.is_none(), "{key} entered renderer metadata");
            }
            if let Some(row) = serialized {
                assert_eq!(
                    row.get("authority"),
                    Some(&Value::String("read-only".to_owned())),
                    "{key}"
                );
                assert_eq!(row.as_object().map(|object| object.len()), Some(7), "{key}");
                for forbidden in [
                    "contents",
                    "preview",
                    "draft",
                    "handle",
                    "revision",
                    "copyAllowed",
                    "saveAllowed",
                    "mutationAllowed",
                    "path",
                ] {
                    assert!(row.get(forbidden).is_none(), "{key} leaked {forbidden}");
                }
            }

            assert!(api.copy(key, 1).is_err(), "{key}");
            assert!(api.artifact(key, 1, key).is_err(), "{key}");
            assert!(api.close(key, 1).is_err(), "{key}");
        }
    }

    #[test]
    fn unparsed_vendor_text_never_reaches_visual_rows_or_copy_boundaries() {
        const HOSTILE_PAYLOAD: &str =
            "<script>globalThis.vendorTextExecuted=true</script>\nAUTHKEY K9z7Q2\n";
        let catalog = config_catalog();
        let public = serde_json::to_value(&catalog).expect("serialize renderer catalog");
        let public_rows = public
            .get("readOnlyArtifacts")
            .and_then(Value::as_array)
            .expect("camel-case read-only artifact array");

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
            let artifact = lovelyhawk_core::database_config::artifact_by_key(key)
                .expect("registered unparsed vendor artifact");
            assert!(!artifact.has_source_backed_visual_parser(), "{key}");
            assert_eq!(
                artifact.local_draft_authority(),
                DatabaseConfigLocalDraftAuthority::ReadOnly,
                "{key}"
            );

            let projected = catalog
                .read_only_artifacts
                .iter()
                .find(|candidate| candidate.artifact_key == key)
                .expect("unparsed artifact projects only bounded metadata");
            assert_eq!(projected.authority, "read-only", "{key}");
            assert!(projected.notice.len() <= 8_192, "{key}");
            let serialized = public_rows
                .iter()
                .find(|candidate| {
                    candidate.get("artifactKey") == Some(&Value::String(key.to_owned()))
                })
                .expect("serialized unparsed artifact metadata");
            assert_eq!(serialized.as_object().map(|object| object.len()), Some(7));
            for forbidden in [
                "rawText",
                "contents",
                "rows",
                "preview",
                "draft",
                "handle",
                "revision",
                "copyAllowed",
                "saveAllowed",
                "mutationAllowed",
                "exportPayload",
            ] {
                assert!(serialized.get(forbidden).is_none(), "{key}: {forbidden}");
            }
            let serialized_text = serde_json::to_string(serialized).unwrap();
            for rejected in [HOSTILE_PAYLOAD, "vendorTextExecuted", "K9z7Q2"] {
                assert!(!serialized_text.contains(rejected), "{key} leaked raw text");
            }
        }

        let api = ConfigApi::default();
        let rejected = format!(
            "{:?}{:?}{:?}{:?}",
            api.copy(HOSTILE_PAYLOAD, 1).err(),
            api.artifact(HOSTILE_PAYLOAD, 1, "kingbase-es-repmgr").err(),
            api.revise(HOSTILE_PAYLOAD, 1, input("mysql")).err(),
            api.close(HOSTILE_PAYLOAD, 1).err()
        );
        assert!(!rejected.contains("vendorTextExecuted"));
        assert!(!rejected.contains("K9z7Q2"));
    }

    #[test]
    fn gbase_8s_visual_text_authkey_is_redacted_and_blocks_whole_document_copy() {
        const SOURCE: &str = "AUTHKEY K9z7Q2\n";
        const SENTINEL: &str = "K9z7Q2";
        const HOSTILE_HANDLE: &str =
            "<script>globalThis.gbaseAuthkeyExecuted=true</script> AUTHKEY K9z7Q2";

        let catalog = config_catalog();
        assert!(
            catalog
                .products
                .iter()
                .all(|product| product.key != "gbase-8s")
        );
        let public = serde_json::to_value(&catalog).expect("serialize renderer catalog");
        let public_rows = public
            .get("readOnlyArtifacts")
            .and_then(Value::as_array)
            .expect("camel-case read-only artifact array");
        let api = ConfigApi::default();

        for key in ["gbase-8s-onconfig", "gbase-8s-sqlhosts"] {
            let artifact = lovelyhawk_core::database_config::artifact_by_key(key)
                .expect("registered GBase 8s visual text artifact");
            assert!(artifact.has_source_backed_visual_parser(), "{key}");
            assert_eq!(
                artifact.local_draft_authority(),
                DatabaseConfigLocalDraftAuthority::ReadOnly,
                "{key}"
            );

            let projected = catalog
                .read_only_artifacts
                .iter()
                .find(|candidate| candidate.artifact_key == key)
                .expect("GBase 8s artifact projects bounded metadata only");
            assert_eq!(projected.product_key, "gbase-8s", "{key}");
            assert_eq!(projected.authority, "read-only", "{key}");
            assert_eq!(projected.reason, "vendor-schema-required", "{key}");

            let serialized = public_rows
                .iter()
                .find(|candidate| {
                    candidate.get("artifactKey") == Some(&Value::String(key.to_owned()))
                })
                .expect("serialized GBase 8s metadata");
            assert_eq!(serialized.as_object().map(|object| object.len()), Some(7));
            for forbidden in [
                "AUTHKEY",
                "rawText",
                "contents",
                "rows",
                "preview",
                "draft",
                "handle",
                "revision",
                "copyPayload",
                "exportPayload",
                "savePayload",
                "copyAllowed",
                "saveAllowed",
                "mutationAllowed",
            ] {
                assert!(serialized.get(forbidden).is_none(), "{key}: {forbidden}");
            }
            let serialized_text = serde_json::to_string(serialized).unwrap();
            assert!(!serialized_text.contains(SOURCE), "{key}");
            assert!(!serialized_text.contains(SENTINEL), "{key}");

            let errors = format!(
                "{:?}{:?}{:?}{:?}",
                api.copy(key, 1).err(),
                api.artifact(key, 1, key).err(),
                api.revise(key, 1, input("mysql")).err(),
                api.close(key, 1).err()
            );
            assert!(!errors.contains(SENTINEL), "{key}");
            assert!(!errors.contains("AUTHKEY"), "{key}");
        }

        let hostile_errors = format!(
            "{:?}{:?}{:?}{:?}",
            api.copy(HOSTILE_HANDLE, 1).err(),
            api.artifact(HOSTILE_HANDLE, 1, "gbase-8s-onconfig").err(),
            api.revise(HOSTILE_HANDLE, 1, input("mysql")).err(),
            api.close(HOSTILE_HANDLE, 1).err()
        );
        for rejected in ["gbaseAuthkeyExecuted", "AUTHKEY", SENTINEL] {
            assert!(!hostile_errors.contains(rejected));
        }

        let input_error = serde_json::from_value::<ConfigGenerateInput>(json!({
            "product": "gbase-8s",
            "choice": "onconfig",
            "features": [],
            "values": { "AUTHKEY": SENTINEL }
        }))
        .expect_err("GBase 8s AUTHKEY never enters the finite generator input");
        assert!(!input_error.to_string().contains(SENTINEL));
    }

    #[test]
    fn dm_dcr_array_and_startup_command_payloads_never_reach_the_generic_ini_editor() {
        const DCR_CONFIG: &str = concat!(
            "[GRP]\nDCR_GRP_NAME=CSS_GRP\nDCR_GRP_TYPE=CSS\n",
            "[CSS]\nDCR_EP_NAME=CSS0\n",
            "<script>globalThis.dcrExecuted=true</script>\n",
        );
        const DCR_NODE: &str = concat!(
            "DMDCR_PATH=/dmdata/dmdcr_cfg.ini\n",
            "DMDCR_DB_STARTUP_CMD=/opt/dmdbms/bin/dmserver path=/dmdata/DAMENG/dm.ini password=NeverShow42\n",
        );
        let catalog = config_catalog();
        assert!(catalog.products.iter().all(|product| product.key != "dm"));
        let public = serde_json::to_value(&catalog).expect("serialize renderer catalog");
        let public_rows = public
            .get("readOnlyArtifacts")
            .and_then(Value::as_array)
            .expect("camel-case read-only artifact array");
        let api = ConfigApi::default();

        for (key, payload) in [("dm-dcr-config", DCR_CONFIG), ("dm-dcr-node", DCR_NODE)] {
            let artifact = lovelyhawk_core::database_config::artifact_by_key(key)
                .expect("registered DM DCR artifact");
            assert_eq!(
                artifact.dialect,
                lovelyhawk_core::database_config::DatabaseConfigDialect::VendorText,
                "{key}"
            );
            assert!(!artifact.has_source_backed_visual_parser(), "{key}");
            assert_eq!(
                artifact.local_draft_authority(),
                DatabaseConfigLocalDraftAuthority::ReadOnly,
                "{key}"
            );

            let projected = catalog
                .read_only_artifacts
                .iter()
                .find(|candidate| candidate.artifact_key == key)
                .expect("DM DCR artifact projects fixed metadata only");
            assert_eq!(projected.authority, "read-only");
            let serialized = public_rows
                .iter()
                .find(|candidate| {
                    candidate.get("artifactKey") == Some(&Value::String(key.to_owned()))
                })
                .expect("serialized DM DCR metadata");
            assert_eq!(serialized.as_object().map(|object| object.len()), Some(7));
            for forbidden in [
                "iniRows",
                "groups",
                "members",
                "startupCommand",
                "command",
                "shell",
                "rawText",
                "contents",
                "preview",
                "draft",
                "handle",
                "copyAllowed",
                "saveAllowed",
                "mutationAllowed",
                "exportPayload",
            ] {
                assert!(serialized.get(forbidden).is_none(), "{key}: {forbidden}");
            }
            let serialized_text = serde_json::to_string(serialized).unwrap();
            for rejected in [
                payload,
                "DCR_GRP_NAME",
                "DMDCR_DB_STARTUP_CMD",
                "dmserver",
                "dcrExecuted",
                "NeverShow42",
            ] {
                assert!(!serialized_text.contains(rejected), "{key}: {rejected}");
            }

            assert!(api.copy(key, 1).is_err(), "{key}");
            assert!(api.artifact(key, 1, key).is_err(), "{key}");
            assert!(api.revise(key, 1, input("mysql")).is_err(), "{key}");
            assert!(api.close(key, 1).is_err(), "{key}");

            let public_errors = format!(
                "{:?}{:?}{:?}{:?}",
                api.copy(payload, 1).err(),
                api.artifact(payload, 1, key).err(),
                api.revise(payload, 1, input("mysql")).err(),
                api.close(payload, 1).err()
            );
            assert!(!public_errors.contains("dcrExecuted"), "{key}");
            assert!(!public_errors.contains("NeverShow42"), "{key}");
        }
    }

    #[test]
    fn dm_init_password_is_redacted_non_copyable_and_rejects_ordinary_updates() {
        const SECRET: &str = "NeverShow42";
        const HOSTILE_INPUT: &str =
            "<script>globalThis.dmInitExecuted=true</script> password=EchoMe";
        const DM_INIT_SOURCE: &str =
            "[DAMENG]\nSYSDBA_PWD=NeverShow42\nLOG_PATH=/var/log/dm/primary\n";

        let artifact = lovelyhawk_core::database_config::artifact_by_key("dm-init")
            .expect("registered DM init artifact");
        assert_eq!(
            artifact.local_draft_authority(),
            DatabaseConfigLocalDraftAuthority::LosslessLocalDraft
        );
        assert!(artifact.has_source_backed_visual_parser());
        assert_eq!(artifact.read_only_status(), None);

        let catalog = config_catalog();
        assert!(catalog.products.iter().all(|product| product.key != "dm"));
        assert!(
            catalog
                .read_only_artifacts
                .iter()
                .all(|candidate| candidate.artifact_key != "dm-init")
        );
        let public = serde_json::to_value(&catalog).expect("serialize renderer catalog");
        let public_text = serde_json::to_string(&public).expect("encode renderer catalog");
        for rejected in [
            "dm-init",
            "SYSDBA_PWD",
            SECRET,
            "dmInitExecuted",
            "EchoMe",
            DM_INIT_SOURCE,
        ] {
            assert!(!public_text.contains(rejected), "catalog leaked {rejected}");
        }

        let api = ConfigApi::default();
        let ordinary_update_errors = format!(
            "{:?}{:?}{:?}{:?}",
            api.revise("dm-init", 1, input("mysql")).err(),
            api.copy("dm-init", 1).err(),
            api.artifact("dm-init", 1, "dm-init").err(),
            api.close("dm-init", 1).err()
        );
        assert!(!ordinary_update_errors.contains("dm-init"));
        assert!(!ordinary_update_errors.contains(SECRET));

        let hostile_errors = format!(
            "{:?}{:?}{:?}{:?}",
            api.revise(HOSTILE_INPUT, 1, input("mysql")).err(),
            api.copy(HOSTILE_INPUT, 1).err(),
            api.artifact(HOSTILE_INPUT, 1, HOSTILE_INPUT).err(),
            api.close(HOSTILE_INPUT, 1).err()
        );
        for rejected in ["dmInitExecuted", "EchoMe", SECRET] {
            assert!(!hostile_errors.contains(rejected));
        }

        for rejected_input in [
            json!({
                "product": "dm",
                "choice": "dminit",
                "features": [],
                "values": { "SYSDBA_PWD": SECRET }
            }),
            json!({
                "product": "mysql",
                "values": { "SYSDBA_PWD": HOSTILE_INPUT }
            }),
        ] {
            let error = serde_json::from_value::<ConfigGenerateInput>(rejected_input)
                .expect_err("DM credentials never enter the finite generator input");
            let public_error = error.to_string();
            assert!(!public_error.contains(SECRET));
            assert!(!public_error.contains("dmInitExecuted"));
            assert!(!public_error.contains("EchoMe"));
        }
    }

    #[test]
    fn catalog_exposes_mysql_auto_cnf_metadata_without_a_content_capability() {
        let catalog = config_catalog();
        let auto_cnf = catalog
            .read_only_artifacts
            .iter()
            .find(|artifact| artifact.artifact_key == "mysql-server-uuid")
            .expect("registered auto.cnf selector row");
        assert_eq!(auto_cnf.product_key, "mysql");
        assert_eq!(auto_cnf.product_title, "MySQL");
        assert_eq!(auto_cnf.title, "auto.cnf");
        assert_eq!(auto_cnf.authority, "read-only");
        assert_eq!(auto_cnf.reason, "generated-artifact");
        assert!(auto_cnf.notice.contains("只读展示"));
        assert!(auto_cnf.notice.contains("生成"));

        let public = serde_json::to_value(catalog).expect("serialize renderer catalog");
        let public_auto_cnf = public
            .get("readOnlyArtifacts")
            .and_then(Value::as_array)
            .and_then(|artifacts| {
                artifacts.iter().find(|artifact| {
                    artifact.get("artifactKey")
                        == Some(&Value::String("mysql-server-uuid".to_owned()))
                })
            })
            .expect("serialized auto.cnf selector row");
        assert_eq!(
            public_auto_cnf.as_object().map(|object| object.len()),
            Some(7)
        );
        for forbidden in [
            "contents",
            "preview",
            "handle",
            "revision",
            "copyAllowed",
            "saveAllowed",
            "mutationAllowed",
            "path",
        ] {
            assert!(
                public_auto_cnf.get(forbidden).is_none(),
                "catalog leaked {forbidden}"
            );
        }
    }

    #[test]
    fn catalog_projects_yashandb_exact_schema_as_read_only_metadata_only() {
        let catalog = config_catalog();
        let yashan = catalog
            .read_only_artifacts
            .iter()
            .find(|artifact| artifact.artifact_key == "yashandb-yasdb-ini")
            .expect("registered YashanDB selector row");
        assert_eq!(yashan.product_key, "yashandb");
        assert_eq!(yashan.product_title, "崖山数据库");
        assert_eq!(yashan.title, "yasdb.ini");
        assert_eq!(yashan.authority, "read-only");
        assert_eq!(yashan.reason, "vendor-schema-required");
        for expected in [
            "只读展示",
            "23.5.4.100",
            "official-doc-family-23.5.4.100",
            "Partial",
            "只用于显示",
            "绝不会写入目标内容、本地草稿或另存文件",
        ] {
            assert!(yashan.notice.contains(expected), "missing {expected}");
        }
        assert!(yashan.notice.len() <= 8_192);
        assert!(!yashan.notice.contains("当前仅允许预览"));

        let public = serde_json::to_value(&catalog).expect("serialize renderer catalog");
        let public_yashan = public
            .get("readOnlyArtifacts")
            .and_then(Value::as_array)
            .and_then(|artifacts| {
                artifacts.iter().find(|artifact| {
                    artifact.get("artifactKey")
                        == Some(&Value::String("yashandb-yasdb-ini".to_owned()))
                })
            })
            .expect("serialized YashanDB selector row");
        assert_eq!(
            public_yashan.as_object().map(|object| object.len()),
            Some(7)
        );
        for forbidden in [
            "schema",
            "parameters",
            "documentedDefaults",
            "contents",
            "draft",
            "savePayload",
            "mutationAllowed",
            "path",
        ] {
            assert!(
                public_yashan.get(forbidden).is_none(),
                "catalog leaked {forbidden}"
            );
        }
        let serialized_yashan = serde_json::to_string(public_yashan).unwrap();
        assert!(!serialized_yashan.contains("RUN_LOG_LEVEL"));
        assert!(!serialized_yashan.contains("INFO"));

        let api = ConfigApi::default();
        assert!(api.revise("yashandb-yasdb-ini", 1, input("mysql")).is_err());
        assert!(api.copy("yashandb-yasdb-ini", 1).is_err());
        assert!(
            api.artifact("yashandb-yasdb-ini", 1, "yashandb-yasdb-ini")
                .is_err()
        );
        assert!(api.close("yashandb-yasdb-ini", 1).is_err());
        assert!(
            serde_json::from_value::<ConfigGenerateInput>(json!({
                "product": "yashandb"
            }))
            .is_err()
        );
    }

    #[test]
    fn catalog_is_safe_static_metadata_without_generated_text_or_secrets() {
        let value = serde_json::to_value(config_catalog()).unwrap();
        let encoded = serde_json::to_string(&value).unwrap();
        assert!(encoded.len() < 256 * 1024);
        assert!(!encoded.contains("password"));
        assert!(!encoded.contains("privateKey"));
        assert!(!encoded.contains("BEGIN "));
        assert_eq!(
            value.get("schema"),
            Some(&Value::String("lovelyres-config-catalog/v2".to_owned()))
        );
    }

    #[test]
    fn every_feature_has_a_supported_choice_and_unique_key_per_product() {
        for product in config_catalog().products {
            let choice_keys = product
                .choices
                .iter()
                .map(|choice| choice.key.as_str())
                .collect::<HashSet<_>>();
            assert!(choice_keys.contains(product.default_choice));
            let mut feature_keys = HashSet::new();
            for feature in product.features {
                assert!(feature_keys.insert(feature.key.clone()));
                assert!(!feature.supported_choices.is_empty());
                assert!(
                    feature
                        .supported_choices
                        .iter()
                        .all(|choice| choice_keys.contains(choice.as_str()))
                );
            }
        }
    }

    fn input(product: &str) -> ConfigGenerateInput {
        serde_json::from_value(json!({ "product": product })).unwrap()
    }

    #[test]
    fn copy_text_keeps_one_file_as_is_and_labels_every_file_of_a_bundle() {
        let api = ConfigApi::default();
        let redis = api.generate(input("redis")).unwrap();
        let copy = api.copy(&redis.handle, redis.revision).unwrap();
        assert_eq!(copy.text, copy.artifacts[0].contents);
        assert!(!copy.text.contains("===== BEGIN"));

        let tomcat = api.generate(input("tomcat")).unwrap();
        let copy = api.copy(&tomcat.handle, tomcat.revision).unwrap();
        let mut expected = String::new();
        for (artifact, copied) in tomcat.artifacts.iter().zip(&copy.artifacts) {
            assert_eq!(artifact.key, copied.key);
            expected.push_str(&format!(
                "===== BEGIN {path} =====\n{contents}{newline}===== END {path} =====\n\n",
                path = artifact.relative_path,
                contents = copied.contents,
                newline = if copied.contents.ends_with('\n') {
                    ""
                } else {
                    "\n"
                },
            ));
        }
        assert_eq!(copy.text, expected);
        assert_eq!(
            tomcat
                .artifacts
                .iter()
                .map(|artifact| artifact.relative_path.as_str())
                .collect::<Vec<_>>(),
            [
                "conf/server.xml",
                "webapps/ROOT/META-INF/context.xml",
                "webapps/ROOT/WEB-INF/web.xml"
            ]
        );
        // The debug form names sizes, never the text.
        let debug = format!("{copy:?}");
        assert!(debug.contains("text_bytes") && !debug.contains("<Server"));
    }

    #[test]
    fn tomcat_bundle_exports_every_file_new_and_never_overwrites() {
        let parent =
            std::env::temp_dir().join(format!("lovelyhawk-config-bundle-{}", Uuid::new_v4()));
        std::fs::create_dir(&parent).unwrap();
        let api = ConfigApi::default();
        let tomcat = api.generate(input("tomcat")).unwrap();
        let copy = api.copy(&tomcat.handle, tomcat.revision).unwrap();

        let exported = api
            .export_bundle(&tomcat.handle, tomcat.revision, &parent)
            .unwrap();
        assert_eq!(
            exported.directory_name,
            "lovelyhawk-tomcat-new-empty-review-bundle"
        );
        assert_eq!(exported.file_count, 3);
        let directory = parent.join(&exported.directory_name);
        let read_all = || {
            tomcat
                .artifacts
                .iter()
                .map(|artifact| std::fs::read(directory.join(&artifact.relative_path)).unwrap())
                .collect::<Vec<_>>()
        };
        let written = read_all();
        for (bytes, copied) in written.iter().zip(&copy.artifacts) {
            assert_eq!(bytes, copied.contents.as_bytes());
        }

        // A second export into the same folder is refused as already existing
        // and leaves every file exactly as the first one wrote it.
        let error = api
            .export_bundle(&tomcat.handle, tomcat.revision, &parent)
            .unwrap_err();
        assert!(
            matches!(&error, CoreError::Io { source, .. } if source.kind() == std::io::ErrorKind::AlreadyExists),
            "{error:?}"
        );
        assert_eq!(read_all(), written);

        // A stale revision, a single-file draft and a relative folder are all refused.
        let revised = api
            .revise(&tomcat.handle, tomcat.revision, input("tomcat"))
            .unwrap();
        assert!(
            api.export_bundle(&tomcat.handle, tomcat.revision, &parent)
                .is_err()
        );
        let fresh =
            std::env::temp_dir().join(format!("lovelyhawk-config-bundle-{}", Uuid::new_v4()));
        std::fs::create_dir(&fresh).unwrap();
        let redis = api.generate(input("redis")).unwrap();
        assert!(matches!(
            api.export_bundle(&redis.handle, redis.revision, &fresh),
            Err(CoreError::Validation { .. })
        ));
        assert!(
            api.export_bundle(&revised.handle, revised.revision, Path::new("relative"))
                .is_err()
        );
        assert_eq!(std::fs::read_dir(&fresh).unwrap().count(), 0);

        std::fs::remove_dir_all(&parent).unwrap();
        std::fs::remove_dir(&fresh).unwrap();
    }

    #[test]
    fn default_quick_inputs_generate_all_nine_products_through_core() {
        let products = [
            "nginx",
            "apache",
            "haproxy",
            "mysql",
            "postgresql",
            "mariadb",
            "mongodb",
            "redis",
            "tomcat",
        ];
        for product in products {
            let draft = build_draft(input(product)).unwrap_or_else(|error| {
                panic!("default {product} quick input must generate: {error}")
            });
            assert_eq!(draft.product, product);
            assert!(draft.total_bytes() > 0);
            assert!(draft.total_bytes() <= MAX_DRAFT_BYTES);
        }
    }

    #[test]
    fn canonical_feature_mapping_covers_all_137_keys_and_rejects_aliases_and_duplicates() {
        let catalog = config_catalog();
        let mut count = 0;
        for product in catalog.products {
            let mut keys = HashSet::new();
            for feature in product.features {
                count += 1;
                assert!(keys.insert(feature.key.clone()));
            }
        }
        assert_eq!(count, CONFIG_FEATURE_COUNT);

        fn assert_every_key_maps<T: Copy + Ord>(
            all: &[T],
            key: impl Fn(T) -> &'static str + Copy,
            default_enabled: impl Fn(T) -> bool + Copy,
        ) -> usize {
            for feature in all {
                let selected = select_features(
                    Some(vec![key(*feature).to_owned()]),
                    all,
                    key,
                    default_enabled,
                    |_| true,
                    "test feature",
                )
                .unwrap();
                assert_eq!(selected.len(), 1);
                assert!(selected.contains(feature));
            }
            all.len()
        }
        let mapped = assert_every_key_maps(
            &NginxSiteFeature::ALL,
            NginxSiteFeature::key,
            NginxSiteFeature::default_enabled,
        ) + assert_every_key_maps(
            &ApacheSiteFeature::ALL,
            ApacheSiteFeature::key,
            ApacheSiteFeature::default_enabled,
        ) + assert_every_key_maps(
            &HaProxyConfigFeature::ALL,
            HaProxyConfigFeature::key,
            HaProxyConfigFeature::default_enabled,
        ) + assert_every_key_maps(
            &MySqlConfigFeature::ALL,
            MySqlConfigFeature::key,
            MySqlConfigFeature::default_enabled,
        ) + assert_every_key_maps(
            &PostgreSqlConfigFeature::ALL,
            PostgreSqlConfigFeature::key,
            PostgreSqlConfigFeature::default_enabled,
        ) + assert_every_key_maps(
            &MariaDbConfigFeature::ALL,
            MariaDbConfigFeature::key,
            MariaDbConfigFeature::default_enabled,
        ) + assert_every_key_maps(
            &MongoDbConfigFeature::ALL,
            MongoDbConfigFeature::key,
            MongoDbConfigFeature::default_enabled,
        ) + assert_every_key_maps(
            &RedisConfigFeature::ALL,
            RedisConfigFeature::key,
            RedisConfigFeature::default_enabled,
        ) + assert_every_key_maps(
            &TomcatConfigFeature::ALL,
            TomcatConfigFeature::key,
            TomcatConfigFeature::default_enabled,
        );
        assert_eq!(mapped, CONFIG_FEATURE_COUNT);

        assert!(
            select_features(
                Some(vec!["安全响应头".to_owned()]),
                &NginxSiteFeature::ALL,
                NginxSiteFeature::key,
                NginxSiteFeature::default_enabled,
                |_| true,
                "Nginx feature",
            )
            .is_err()
        );
        assert!(
            select_features(
                Some(vec![
                    "security-headers".to_owned(),
                    "security-headers".to_owned(),
                ]),
                &NginxSiteFeature::ALL,
                NginxSiteFeature::key,
                NginxSiteFeature::default_enabled,
                |_| true,
                "Nginx feature",
            )
            .is_err()
        );
    }

    #[test]
    fn nginx_feature_removal_revises_preview_and_invalidates_stale_capabilities() {
        const SECURITY_DIRECTIVE: &str = "add_header X-Content-Type-Options";
        const HOSTILE_FEATURE: &str =
            "<script>globalThis.nginxRemoveExecuted=true</script> credential=NeverShow42";

        let api = ConfigApi::default();
        let enabled: ConfigGenerateInput = serde_json::from_value(json!({
            "product": "nginx",
            "choice": "reverse-proxy",
            "features": ["security-headers"]
        }))
        .unwrap();
        let generated = api.generate(enabled).unwrap();
        assert!(generated.artifacts[0].preview.contains(SECURITY_DIRECTIVE));

        let removed: ConfigGenerateInput = serde_json::from_value(json!({
            "product": "nginx",
            "choice": "reverse-proxy",
            "features": []
        }))
        .unwrap();
        let revised = api
            .revise(&generated.handle, generated.revision, removed)
            .unwrap();
        assert_eq!(revised.handle, generated.handle);
        assert_eq!(revised.revision, generated.revision + 1);
        assert!(!revised.artifacts[0].preview.contains(SECURITY_DIRECTIVE));
        assert!(revised.artifacts[0].preview.contains("proxy_pass"));

        assert!(api.copy(&generated.handle, generated.revision).is_err());
        assert!(
            api.artifact(&generated.handle, generated.revision, "site")
                .is_err()
        );
        assert!(api.close(&generated.handle, generated.revision).is_err());

        let current_copy = api.copy(&revised.handle, revised.revision).unwrap();
        let current_export = api
            .artifact(&revised.handle, revised.revision, "site")
            .unwrap();
        assert!(
            !current_copy.artifacts[0]
                .contents
                .contains(SECURITY_DIRECTIVE)
        );
        assert!(!current_export.contents.contains(SECURITY_DIRECTIVE));

        let hostile: ConfigGenerateInput = serde_json::from_value(json!({
            "product": "nginx",
            "choice": "reverse-proxy",
            "features": [HOSTILE_FEATURE]
        }))
        .unwrap();
        let public_error = api
            .revise(&revised.handle, revised.revision, hostile)
            .expect_err("unknown hostile feature must fail closed")
            .to_string();
        for rejected in ["nginxRemoveExecuted", "NeverShow42", HOSTILE_FEATURE] {
            assert!(!public_error.contains(rejected));
        }

        let after_rejection = api.copy(&revised.handle, revised.revision).unwrap();
        assert_eq!(
            after_rejection.artifacts[0].contents,
            current_copy.artifacts[0].contents
        );
        for rejected in [SECURITY_DIRECTIVE, "nginxRemoveExecuted", "NeverShow42"] {
            assert!(!after_rejection.artifacts[0].contents.contains(rejected));
            assert!(!current_export.contents.contains(rejected));
        }
    }

    #[test]
    fn apache_catalog_inline_editor_and_preview_prerequisites_are_current_and_fail_closed() {
        const BODY_DIRECTIVE: &str = "LimitRequestBody 10485760";
        const HOSTILE_FEATURE: &str =
            "<script>globalThis.apacheInlineExecuted=true</script> credential=NeverShow42";

        fn apache_features(features: &[&str]) -> ConfigGenerateInput {
            serde_json::from_value(json!({
                "product": "apache",
                "choice": "reverse-proxy",
                "features": features
            }))
            .unwrap()
        }

        let catalog = config_catalog();
        let apache = catalog
            .products
            .iter()
            .find(|product| product.key == "apache")
            .expect("Apache catalog product");
        let matches = apache
            .features
            .iter()
            .filter(|feature| feature.key == "client-body-limit")
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 1);
        let feature = matches[0];
        assert_eq!(feature.title, "限制请求体大小");
        assert_eq!(feature.summary, "将客户端请求体上限固定为 10 MiB。");
        assert_eq!(feature.scope, "虚拟主机");
        assert!(!feature.default_enabled);
        assert_eq!(
            feature.aliases,
            ["请求体", "上传大小", "LimitRequestBody", "10 MiB"]
        );
        assert_eq!(feature.supported_choices, ["static", "reverse-proxy"]);

        let api = ConfigApi::default();
        let baseline = api.generate(input("apache")).unwrap();
        assert!(!baseline.artifacts[0].preview.contains(BODY_DIRECTIVE));

        let selected = api
            .revise(
                &baseline.handle,
                baseline.revision,
                apache_features(&[
                    "security-headers",
                    "reduce-version-disclosure",
                    "disable-trace",
                    "client-body-limit",
                ]),
            )
            .unwrap();
        assert_eq!(selected.handle, baseline.handle);
        assert_eq!(selected.revision, baseline.revision + 1);
        assert_eq!(selected.artifacts.len(), 1);
        assert_eq!(selected.artifacts[0].key, "site");
        assert!(selected.artifacts[0].preview.contains(BODY_DIRECTIVE));
        assert!(api.copy(&baseline.handle, baseline.revision).is_err());
        let selected_copy = api.copy(&selected.handle, selected.revision).unwrap();
        assert_eq!(
            selected_copy.artifacts[0].contents,
            selected.artifacts[0].preview
        );

        let removed = api
            .revise(
                &selected.handle,
                selected.revision,
                apache_features(&[
                    "security-headers",
                    "reduce-version-disclosure",
                    "disable-trace",
                ]),
            )
            .unwrap();
        assert!(!removed.artifacts[0].preview.contains(BODY_DIRECTIVE));
        assert!(api.copy(&selected.handle, selected.revision).is_err());

        let public_error = api
            .revise(
                &removed.handle,
                removed.revision,
                apache_features(&[HOSTILE_FEATURE]),
            )
            .expect_err("hostile catalog feature must fail closed")
            .to_string();
        for rejected in ["apacheInlineExecuted", "NeverShow42", HOSTILE_FEATURE] {
            assert!(!public_error.contains(rejected));
        }
        let after_rejection = api.copy(&removed.handle, removed.revision).unwrap();
        assert_eq!(
            after_rejection.artifacts[0].contents,
            removed.artifacts[0].preview
        );
        assert!(
            !after_rejection.artifacts[0]
                .contents
                .contains(BODY_DIRECTIVE)
        );
    }

    #[test]
    fn apache_stack_remove_reset_revisions_are_consistent_and_fail_closed() {
        const METHOD_DIRECTIVE: &str = "Require method GET HEAD";
        const BODY_DIRECTIVE: &str = "LimitRequestBody 10485760";
        const HOSTILE_FEATURE: &str =
            "<script>globalThis.apacheStackExecuted=true</script> password=NeverShow42";

        fn apache_features(features: &[&str]) -> ConfigGenerateInput {
            serde_json::from_value(json!({
                "product": "apache",
                "choice": "reverse-proxy",
                "features": features
            }))
            .unwrap()
        }

        let api = ConfigApi::default();
        let baseline = api.generate(input("apache")).unwrap();
        let baseline_copy = api.copy(&baseline.handle, baseline.revision).unwrap();
        assert!(baseline.artifacts[0].preview.contains("ProxyPass"));
        assert!(!baseline.artifacts[0].preview.contains(METHOD_DIRECTIVE));
        assert!(!baseline.artifacts[0].preview.contains(BODY_DIRECTIVE));

        let stacked = api
            .revise(
                &baseline.handle,
                baseline.revision,
                apache_features(&[
                    "security-headers",
                    "reduce-version-disclosure",
                    "disable-trace",
                    "restrict-request-methods",
                    "client-body-limit",
                ]),
            )
            .unwrap();
        assert!(stacked.artifacts[0].preview.contains(METHOD_DIRECTIVE));
        assert!(stacked.artifacts[0].preview.contains(BODY_DIRECTIVE));
        assert!(stacked.artifacts[0].preview.contains("ProxyPass"));
        assert!(api.copy(&baseline.handle, baseline.revision).is_err());

        let trace_removed = api
            .revise(
                &stacked.handle,
                stacked.revision,
                apache_features(&[
                    "security-headers",
                    "reduce-version-disclosure",
                    "client-body-limit",
                ]),
            )
            .unwrap();
        assert!(
            !trace_removed.artifacts[0]
                .preview
                .contains(METHOD_DIRECTIVE)
        );
        assert!(
            !trace_removed.artifacts[0]
                .preview
                .contains("TraceEnable Off")
        );
        assert!(trace_removed.artifacts[0].preview.contains(BODY_DIRECTIVE));
        assert!(api.copy(&stacked.handle, stacked.revision).is_err());

        let reopened = api
            .revise(
                &trace_removed.handle,
                trace_removed.revision,
                apache_features(&[
                    "security-headers",
                    "reduce-version-disclosure",
                    "disable-trace",
                    "restrict-request-methods",
                    "client-body-limit",
                ]),
            )
            .unwrap();
        assert!(reopened.artifacts[0].preview.contains(METHOD_DIRECTIVE));
        assert!(reopened.artifacts[0].preview.contains("TraceEnable Off"));

        let method_removed = api
            .revise(
                &reopened.handle,
                reopened.revision,
                apache_features(&[
                    "security-headers",
                    "reduce-version-disclosure",
                    "disable-trace",
                    "client-body-limit",
                ]),
            )
            .unwrap();
        assert!(
            !method_removed.artifacts[0]
                .preview
                .contains(METHOD_DIRECTIVE)
        );
        assert!(
            method_removed.artifacts[0]
                .preview
                .contains("TraceEnable Off")
        );
        assert!(method_removed.artifacts[0].preview.contains(BODY_DIRECTIVE));

        let reset = api
            .revise(
                &method_removed.handle,
                method_removed.revision,
                input("apache"),
            )
            .unwrap();
        assert_eq!(reset.artifacts[0].preview, baseline.artifacts[0].preview);
        let reset_copy = api.copy(&reset.handle, reset.revision).unwrap();
        assert_eq!(
            reset_copy.artifacts[0].contents,
            baseline_copy.artifacts[0].contents
        );
        let reset_export = api.artifact(&reset.handle, reset.revision, "site").unwrap();
        let visual =
            lovelyhawk_core::apache_visual::ApacheVisualDocument::parse(&reset_export.contents)
                .unwrap();
        assert!(visual.is_structured());
        assert_eq!(visual.raw_bytes(), reset_export.contents.as_bytes());

        let hostile = apache_features(&[HOSTILE_FEATURE]);
        let public_error = api
            .revise(&reset.handle, reset.revision, hostile)
            .expect_err("hostile Apache feature text must fail closed")
            .to_string();
        for rejected in ["apacheStackExecuted", "NeverShow42", HOSTILE_FEATURE] {
            assert!(!public_error.contains(rejected));
        }
        let after_rejection = api.copy(&reset.handle, reset.revision).unwrap();
        assert_eq!(
            after_rejection.artifacts[0].contents,
            baseline_copy.artifacts[0].contents
        );
        assert!(
            !after_rejection.artifacts[0]
                .contents
                .contains("apacheStackExecuted")
        );
        assert!(
            !after_rejection.artifacts[0]
                .contents
                .contains("NeverShow42")
        );
    }

    #[test]
    fn mysql_catalog_inline_editor_and_preview_prerequisites_are_current_and_fail_closed() {
        const MAX_400: &str = "max_connections = 400\n";
        const MAX_500: &str = "max_connections = 500\n";
        const HOSTILE_VALUE: &str =
            "<script>globalThis.mysqlInlineExecuted=true</script> credential=NeverShow42";

        fn mysql_max_connections(value: &str, enabled: bool) -> ConfigGenerateInput {
            serde_json::from_value(json!({
                "product": "mysql",
                "choice": "8.4.0",
                "features": if enabled { vec!["max-connections"] } else { vec![] },
                "values": { "maxConnections": value }
            }))
            .unwrap()
        }

        let catalog = config_catalog();
        let mysql = catalog
            .products
            .iter()
            .find(|product| product.key == "mysql")
            .expect("MySQL catalog product");
        let matches = mysql
            .features
            .iter()
            .filter(|feature| feature.key == "max-connections")
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 1);
        let feature = matches[0];
        assert_eq!(feature.title, "限制最大连接数");
        assert_eq!(
            feature.summary,
            "设置服务器可同时接受的客户端连接数量上限。"
        );
        assert_eq!(feature.scope, "连接");
        assert_eq!(feature.aliases, ["max_connections", "最大连接", "并发连接"]);
        assert_eq!(feature.supported_choices, ["8.4.0"]);
        assert!(!feature.default_enabled);

        let api = ConfigApi::default();
        let baseline = api.generate(input("mysql")).unwrap();
        assert!(!baseline.artifacts[0].preview.contains("max_connections"));

        let selected = api
            .revise(
                &baseline.handle,
                baseline.revision,
                mysql_max_connections("400", true),
            )
            .unwrap();
        assert_eq!(selected.handle, baseline.handle);
        assert_eq!(selected.revision, baseline.revision + 1);
        assert!(selected.artifacts[0].preview.contains(MAX_400));
        assert!(api.copy(&baseline.handle, baseline.revision).is_err());

        let changed = api
            .revise(
                &selected.handle,
                selected.revision,
                mysql_max_connections("500", true),
            )
            .unwrap();
        assert!(changed.artifacts[0].preview.contains(MAX_500));
        assert!(!changed.artifacts[0].preview.contains(MAX_400));
        assert!(api.copy(&selected.handle, selected.revision).is_err());
        let current_copy = api.copy(&changed.handle, changed.revision).unwrap();
        assert_eq!(
            current_copy.artifacts[0].contents,
            changed.artifacts[0].preview
        );

        let public_error = api
            .revise(
                &changed.handle,
                changed.revision,
                mysql_max_connections(HOSTILE_VALUE, true),
            )
            .expect_err("hostile max_connections must fail closed")
            .to_string();
        for rejected in ["mysqlInlineExecuted", "NeverShow42", HOSTILE_VALUE] {
            assert!(!public_error.contains(rejected));
        }
        let after_rejection = api.copy(&changed.handle, changed.revision).unwrap();
        assert_eq!(
            after_rejection.artifacts[0].contents,
            current_copy.artifacts[0].contents
        );

        let removed = api
            .revise(
                &changed.handle,
                changed.revision,
                mysql_max_connections("151", false),
            )
            .unwrap();
        assert_eq!(removed.artifacts[0].preview, baseline.artifacts[0].preview);
        assert!(api.copy(&changed.handle, changed.revision).is_err());
    }

    #[test]
    fn mysql_quick_stack_remove_reset_preview_and_save_prerequisites_fail_closed() {
        const MAX_CONNECTIONS: &str = "max_connections = 400\n";
        const SLOW_QUERY_LOG: &str = "slow_query_log = ON\n";
        const BINLOG_RETENTION: &str = "binlog_expire_logs_seconds = 2592000\n";
        const HOSTILE_FEATURE: &str =
            "<script>globalThis.mysqlStackExecuted=true</script> password=NeverShow42";

        fn mysql_features(features: &[&str], max_connections: &str) -> ConfigGenerateInput {
            serde_json::from_value(json!({
                "product": "mysql",
                "choice": "8.4.0",
                "features": features,
                "values": { "maxConnections": max_connections }
            }))
            .unwrap()
        }

        let api = ConfigApi::default();
        let baseline = api.generate(input("mysql")).unwrap();
        let baseline_copy = api.copy(&baseline.handle, baseline.revision).unwrap();
        assert_eq!(baseline.suggested_name, "my.cnf");
        assert!(baseline.artifacts[0].preview.contains("[mysqld]\n"));
        assert!(!baseline.artifacts[0].preview.contains(MAX_CONNECTIONS));

        let stacked = api
            .revise(
                &baseline.handle,
                baseline.revision,
                mysql_features(
                    &[
                        "max-connections",
                        "slow-query-log",
                        "binary-logging",
                        "binary-log-retention",
                    ],
                    "400",
                ),
            )
            .unwrap();
        for directive in [
            MAX_CONNECTIONS,
            SLOW_QUERY_LOG,
            "long_query_time = 10\n",
            "log_bin = binlog\n",
            "server_id = 1\n",
            BINLOG_RETENTION,
        ] {
            assert!(
                stacked.artifacts[0].preview.contains(directive),
                "{directive}"
            );
        }
        assert!(api.copy(&baseline.handle, baseline.revision).is_err());
        assert!(
            api.artifact(&baseline.handle, baseline.revision, "main")
                .is_err()
        );

        let remaining = api
            .revise(
                &stacked.handle,
                stacked.revision,
                mysql_features(
                    &["slow-query-log", "binary-logging", "binary-log-retention"],
                    "400",
                ),
            )
            .unwrap();
        assert!(!remaining.artifacts[0].preview.contains(MAX_CONNECTIONS));
        assert!(remaining.artifacts[0].preview.contains(SLOW_QUERY_LOG));
        assert!(remaining.artifacts[0].preview.contains(BINLOG_RETENTION));
        assert!(api.copy(&stacked.handle, stacked.revision).is_err());

        let reset = api
            .revise(&remaining.handle, remaining.revision, input("mysql"))
            .unwrap();
        assert_eq!(reset.artifacts[0].preview, baseline.artifacts[0].preview);
        let reset_copy = api.copy(&reset.handle, reset.revision).unwrap();
        assert_eq!(
            reset_copy.artifacts[0].contents,
            baseline_copy.artifacts[0].contents
        );
        let reset_export = api.artifact(&reset.handle, reset.revision, "main").unwrap();
        assert_eq!(reset_export.suggested_name, "my.cnf");
        assert_eq!(reset_export.contents, baseline_copy.artifacts[0].contents);
        let visual = lovelyhawk_core::line_config_visual::LineConfigVisualDocument::parse(
            lovelyhawk_core::line_config_visual::LineConfigDialect::MySqlOption,
            &reset_export.contents,
        )
        .unwrap();
        assert!(visual.is_structured());
        assert_eq!(visual.raw_bytes(), reset_export.contents.as_bytes());

        let missing_dependency = mysql_features(&["binary-log-retention"], "151");
        let dependency_error = api
            .revise(&reset.handle, reset.revision, missing_dependency)
            .expect_err("binlog retention without binary logging must fail closed")
            .to_string();
        assert!(!dependency_error.contains("NeverShow42"));

        let hostile = mysql_features(&[HOSTILE_FEATURE], "151");
        let public_error = api
            .revise(&reset.handle, reset.revision, hostile)
            .expect_err("hostile MySQL feature text must fail closed")
            .to_string();
        for rejected in ["mysqlStackExecuted", "NeverShow42", HOSTILE_FEATURE] {
            assert!(!public_error.contains(rejected));
        }
        let after_rejection = api.copy(&reset.handle, reset.revision).unwrap();
        assert_eq!(
            after_rejection.artifacts[0].contents,
            baseline_copy.artifacts[0].contents
        );
        for rejected in [MAX_CONNECTIONS, "mysqlStackExecuted", "NeverShow42"] {
            assert!(!after_rejection.artifacts[0].contents.contains(rejected));
            assert!(!reset_export.contents.contains(rejected));
        }
    }

    #[test]
    fn postgresql_and_mariadb_catalog_versions_search_and_inline_editor_prerequisites_are_current()
    {
        const HOSTILE_VALUE: &str =
            "<script>globalThis.databaseInlineExecuted=true</script> credential=NeverShow42";

        fn postgresql_lock_wait(value: &str) -> ConfigGenerateInput {
            serde_json::from_value(json!({
                "product": "postgresql",
                "choice": "18",
                "features": ["lock-wait-logging"],
                "values": { "lockWaitThreshold": value }
            }))
            .unwrap()
        }

        fn mariadb_retention(value: &str) -> ConfigGenerateInput {
            serde_json::from_value(json!({
                "product": "mariadb",
                "choice": "12.3",
                "features": ["binary-logging", "binary-log-retention"],
                "values": { "serverId": "42", "binlogRetention": value }
            }))
            .unwrap()
        }

        let catalog = config_catalog();
        let postgresql = catalog
            .products
            .iter()
            .find(|product| product.key == "postgresql")
            .expect("PostgreSQL catalog product");
        assert_eq!(
            postgresql
                .choices
                .iter()
                .map(|choice| choice.key.as_str())
                .collect::<Vec<_>>(),
            ["14", "15", "16", "17", "18"]
        );
        let lock_wait = postgresql
            .features
            .iter()
            .find(|feature| feature.key == "lock-wait-logging")
            .expect("PostgreSQL lock-wait catalog feature");
        assert_eq!(lock_wait.title, "按明确阈值记录锁等待");
        assert_eq!(
            lock_wait.aliases,
            ["log_lock_waits", "锁等待", "deadlock_timeout"]
        );
        assert_eq!(lock_wait.supported_choices, ["14", "15", "16", "17", "18"]);

        let mariadb = catalog
            .products
            .iter()
            .find(|product| product.key == "mariadb")
            .expect("MariaDB catalog product");
        assert_eq!(
            mariadb
                .choices
                .iter()
                .map(|choice| choice.key.as_str())
                .collect::<Vec<_>>(),
            ["10.11", "11.4", "11.8", "12.3"]
        );
        let retention = mariadb
            .features
            .iter()
            .find(|feature| feature.key == "binary-log-retention")
            .expect("MariaDB retention catalog feature");
        assert_eq!(retention.title, "设置二进制日志保留时间");
        assert_eq!(
            retention.aliases,
            ["binlog_expire_logs_seconds", "日志保留", "自动清理"]
        );
        assert_eq!(
            retention.supported_choices,
            ["10.11", "11.4", "11.8", "12.3"]
        );

        let api = ConfigApi::default();
        let postgresql_baseline = api.generate(input("postgresql")).unwrap();
        let postgresql_selected = api
            .revise(
                &postgresql_baseline.handle,
                postgresql_baseline.revision,
                postgresql_lock_wait("1500"),
            )
            .unwrap();
        for directive in ["deadlock_timeout = 1500ms\n", "log_lock_waits = on\n"] {
            assert!(
                postgresql_selected.artifacts[0].preview.contains(directive),
                "{directive}"
            );
        }
        assert!(
            api.copy(&postgresql_baseline.handle, postgresql_baseline.revision)
                .is_err()
        );
        let postgresql_copy = api
            .copy(&postgresql_selected.handle, postgresql_selected.revision)
            .unwrap();
        assert_eq!(
            postgresql_copy.artifacts[0].contents,
            postgresql_selected.artifacts[0].preview
        );

        let postgresql_error = api
            .revise(
                &postgresql_selected.handle,
                postgresql_selected.revision,
                postgresql_lock_wait(HOSTILE_VALUE),
            )
            .expect_err("hostile PostgreSQL inline value must fail closed")
            .to_string();
        for rejected in ["databaseInlineExecuted", "NeverShow42", HOSTILE_VALUE] {
            assert!(!postgresql_error.contains(rejected));
        }
        assert_eq!(
            api.copy(&postgresql_selected.handle, postgresql_selected.revision)
                .unwrap()
                .artifacts[0]
                .contents,
            postgresql_copy.artifacts[0].contents
        );

        let mariadb_baseline = api.generate(input("mariadb")).unwrap();
        let mariadb_selected = api
            .revise(
                &mariadb_baseline.handle,
                mariadb_baseline.revision,
                mariadb_retention("86400"),
            )
            .unwrap();
        for directive in [
            "log_bin = mariadb-bin\n",
            "server_id = 42\n",
            "binlog_expire_logs_seconds = 86400\n",
        ] {
            assert!(
                mariadb_selected.artifacts[0].preview.contains(directive),
                "{directive}"
            );
        }
        assert!(
            api.copy(&mariadb_baseline.handle, mariadb_baseline.revision)
                .is_err()
        );
        let mariadb_copy = api
            .copy(&mariadb_selected.handle, mariadb_selected.revision)
            .unwrap();
        assert_eq!(
            mariadb_copy.artifacts[0].contents,
            mariadb_selected.artifacts[0].preview
        );

        let mariadb_error = api
            .revise(
                &mariadb_selected.handle,
                mariadb_selected.revision,
                mariadb_retention(HOSTILE_VALUE),
            )
            .expect_err("hostile MariaDB inline value must fail closed")
            .to_string();
        for rejected in ["databaseInlineExecuted", "NeverShow42", HOSTILE_VALUE] {
            assert!(!mariadb_error.contains(rejected));
        }
        assert_eq!(
            api.copy(&mariadb_selected.handle, mariadb_selected.revision)
                .unwrap()
                .artifacts[0]
                .contents,
            mariadb_copy.artifacts[0].contents
        );
    }

    #[test]
    fn postgresql_and_mariadb_quick_interactions_are_isolated_and_save_prerequisites_are_current() {
        const HOSTILE_FEATURE: &str =
            "<script>globalThis.databaseIsolationExecuted=true</script> password=NeverShow42";

        fn postgresql_input(
            choice: &str,
            features: &[&str],
            max_connections: &str,
            reserved_connections: &str,
        ) -> ConfigGenerateInput {
            serde_json::from_value(json!({
                "product": "postgresql",
                "choice": choice,
                "features": features,
                "values": {
                    "maxConnections": max_connections,
                    "reservedConnections": reserved_connections
                }
            }))
            .unwrap()
        }

        fn mariadb_input(
            choice: &str,
            features: &[&str],
            server_id: &str,
            binlog_retention: &str,
        ) -> ConfigGenerateInput {
            serde_json::from_value(json!({
                "product": "mariadb",
                "choice": choice,
                "features": features,
                "values": {
                    "serverId": server_id,
                    "binlogRetention": binlog_retention
                }
            }))
            .unwrap()
        }

        let api = ConfigApi::default();
        let postgresql_baseline = api.generate(input("postgresql")).unwrap();
        let postgresql_baseline_copy = api
            .copy(&postgresql_baseline.handle, postgresql_baseline.revision)
            .unwrap();
        assert_eq!(
            postgresql_baseline.suggested_name,
            "lovelyhawk-postgresql-18-new-empty-cluster.conf"
        );
        assert!(
            postgresql_baseline.artifacts[0]
                .preview
                .contains("listen_addresses = 'localhost'\n")
        );

        let postgresql_stacked = api
            .revise(
                &postgresql_baseline.handle,
                postgresql_baseline.revision,
                postgresql_input(
                    "18",
                    &["connection-capacity", "connection-lifecycle-logging"],
                    "240",
                    "2",
                ),
            )
            .unwrap();
        for directive in [
            "max_connections = 240\n",
            "reserved_connections = 2\n",
            "log_connections = 'receipt,authentication,authorization'\n",
        ] {
            assert!(
                postgresql_stacked.artifacts[0].preview.contains(directive),
                "{directive}"
            );
        }
        assert!(
            api.copy(&postgresql_baseline.handle, postgresql_baseline.revision)
                .is_err()
        );

        assert!(
            api.revise(
                &postgresql_stacked.handle,
                postgresql_stacked.revision,
                postgresql_input(
                    "15",
                    &["connection-capacity", "connection-lifecycle-logging"],
                    "240",
                    "2",
                ),
            )
            .is_err(),
            "PostgreSQL 15 must reject the PostgreSQL 18 reserved-connections value"
        );
        let postgresql_15 = api
            .revise(
                &postgresql_stacked.handle,
                postgresql_stacked.revision,
                postgresql_input(
                    "15",
                    &["connection-capacity", "connection-lifecycle-logging"],
                    "240",
                    "0",
                ),
            )
            .unwrap();
        assert!(postgresql_15.artifacts[0].preview.contains("PostgreSQL 15"));
        assert!(
            !postgresql_15.artifacts[0]
                .preview
                .contains("\nreserved_connections =")
        );
        assert!(
            postgresql_15.artifacts[0]
                .preview
                .contains("log_connections = on\n")
        );

        let postgresql_remaining = api
            .revise(
                &postgresql_15.handle,
                postgresql_15.revision,
                postgresql_input("15", &["connection-lifecycle-logging"], "240", "0"),
            )
            .unwrap();
        assert!(
            !postgresql_remaining.artifacts[0]
                .preview
                .contains("max_connections = 240\n")
        );
        assert!(
            postgresql_remaining.artifacts[0]
                .preview
                .contains("log_connections = on\n")
        );

        let mariadb_stacked = api
            .revise(
                &postgresql_remaining.handle,
                postgresql_remaining.revision,
                mariadb_input(
                    "12.3",
                    &[
                        "binary-logging",
                        "binary-log-retention",
                        "binary-log-durability",
                    ],
                    "42",
                    "86400",
                ),
            )
            .unwrap();
        assert_eq!(mariadb_stacked.product, "mariadb");
        for directive in [
            "server_id = 42\n",
            "binlog_expire_logs_seconds = 86400\n",
            "sync_binlog = 1\n",
        ] {
            assert!(mariadb_stacked.artifacts[0].preview.contains(directive));
        }
        assert!(
            !mariadb_stacked.artifacts[0]
                .preview
                .contains("listen_addresses")
        );
        assert!(
            api.copy(&postgresql_remaining.handle, postgresql_remaining.revision)
                .is_err()
        );

        let mariadb_without_binlog = api
            .revise(
                &mariadb_stacked.handle,
                mariadb_stacked.revision,
                mariadb_input("12.3", &[], "42", "86400"),
            )
            .unwrap();
        for removed in [
            "log_bin = mariadb-bin\n",
            "binlog_expire_logs_seconds = 86400\n",
            "sync_binlog = 1\n",
        ] {
            assert!(
                !mariadb_without_binlog.artifacts[0]
                    .preview
                    .contains(removed)
            );
        }

        let mariadb_10_11 = api
            .revise(
                &mariadb_without_binlog.handle,
                mariadb_without_binlog.revision,
                mariadb_input("10.11", &["slow-query-log"], "42", "86400"),
            )
            .unwrap();
        let mariadb_10_11_copy = api
            .copy(&mariadb_10_11.handle, mariadb_10_11.revision)
            .unwrap();
        assert!(
            mariadb_10_11.artifacts[0]
                .preview
                .contains("MariaDB 10.11 LTS")
        );
        assert!(
            mariadb_10_11.artifacts[0]
                .preview
                .contains("log_slow_query = ON\n")
        );

        let postgresql_reset = api
            .revise(
                &mariadb_10_11.handle,
                mariadb_10_11.revision,
                input("postgresql"),
            )
            .unwrap();
        assert_eq!(postgresql_reset.product, "postgresql");
        assert_eq!(
            postgresql_reset.artifacts[0].preview,
            postgresql_baseline.artifacts[0].preview
        );
        let postgresql_export = api
            .artifact(&postgresql_reset.handle, postgresql_reset.revision, "main")
            .unwrap();
        assert_eq!(postgresql_export.suggested_name, "postgresql.conf");
        assert_eq!(
            postgresql_export.contents,
            postgresql_baseline_copy.artifacts[0].contents
        );
        assert!(
            api.copy(&mariadb_10_11.handle, mariadb_10_11.revision)
                .is_err()
        );

        let mariadb_restored = api
            .revise(
                &postgresql_reset.handle,
                postgresql_reset.revision,
                mariadb_input("10.11", &["slow-query-log"], "42", "86400"),
            )
            .unwrap();
        assert_eq!(
            mariadb_restored.artifacts[0].preview,
            mariadb_10_11.artifacts[0].preview
        );
        assert_eq!(
            mariadb_restored.suggested_name,
            "lovelyhawk-mariadb-10.11-new-empty-instance.cnf"
        );
        let mariadb_export = api
            .artifact(&mariadb_restored.handle, mariadb_restored.revision, "main")
            .unwrap();
        assert_eq!(mariadb_export.suggested_name, "mariadb.cnf");
        assert_eq!(
            mariadb_export.contents,
            mariadb_10_11_copy.artifacts[0].contents
        );
        let visual = lovelyhawk_core::line_config_visual::LineConfigVisualDocument::parse(
            lovelyhawk_core::line_config_visual::LineConfigDialect::MySqlOption,
            &mariadb_export.contents,
        )
        .unwrap();
        assert!(visual.is_structured());
        assert_eq!(visual.raw_bytes(), mariadb_export.contents.as_bytes());

        for rejected_input in [
            mariadb_input("10.11", &["binary-log-retention"], "42", "86400"),
            mariadb_input("10.11", &[HOSTILE_FEATURE], "42", "86400"),
        ] {
            let public_error = api
                .revise(
                    &mariadb_restored.handle,
                    mariadb_restored.revision,
                    rejected_input,
                )
                .expect_err("invalid MariaDB request must fail without mutation")
                .to_string();
            for rejected in ["databaseIsolationExecuted", "NeverShow42", HOSTILE_FEATURE] {
                assert!(!public_error.contains(rejected));
            }
        }
        let after_rejection = api
            .copy(&mariadb_restored.handle, mariadb_restored.revision)
            .unwrap();
        assert_eq!(
            after_rejection.artifacts[0].contents,
            mariadb_10_11_copy.artifacts[0].contents
        );
    }

    #[test]
    fn redis_catalog_inline_editor_and_preview_prerequisites_are_current_and_fail_closed() {
        const HOSTILE_VALUE: &str =
            "<script>globalThis.redisInlineExecuted=true</script> password=NeverShow42";
        const DEFAULT_FEATURES: [&str; 6] = [
            "max-clients",
            "tcp-keepalive",
            "memory-limit",
            "aof-persistence",
            "rdb-persistence",
            "slow-log",
        ];

        fn slow_log_input(features: &[&str], threshold: &str, length: &str) -> ConfigGenerateInput {
            serde_json::from_value(json!({
                "product": "redis",
                "choice": "8.10",
                "features": features,
                "values": {
                    "slowlogThreshold": threshold,
                    "slowlogLength": length
                }
            }))
            .unwrap()
        }

        let catalog = config_catalog();
        let redis = catalog
            .products
            .iter()
            .find(|product| product.key == "redis")
            .unwrap();
        assert_eq!(
            redis
                .choices
                .iter()
                .map(|choice| choice.key.as_str())
                .collect::<Vec<_>>(),
            [
                "6.2", "7.2", "7.4", "8.0", "8.2", "8.4", "8.6", "8.8", "8.10"
            ]
        );
        let slow_log = redis
            .features
            .iter()
            .find(|feature| feature.key == "slow-log")
            .unwrap();
        assert_eq!(slow_log.title, "记录慢命令");
        assert_eq!(slow_log.scope, "可观测性");
        assert_eq!(slow_log.aliases, ["slowlog", "慢命令", "慢日志"]);
        assert!(slow_log.default_enabled);
        assert_eq!(
            slow_log.supported_choices,
            [
                "6.2", "7.2", "7.4", "8.0", "8.2", "8.4", "8.6", "8.8", "8.10"
            ]
        );

        let api = ConfigApi::default();
        let selected = api
            .generate(slow_log_input(&DEFAULT_FEATURES, "25000", "256"))
            .unwrap();
        for directive in ["slowlog-log-slower-than 25000\n", "slowlog-max-len 256\n"] {
            assert!(
                selected.artifacts[0].preview.contains(directive),
                "{directive}"
            );
        }
        let selected_copy = api.copy(&selected.handle, selected.revision).unwrap();
        assert_eq!(
            selected_copy.artifacts[0].contents,
            selected.artifacts[0].preview
        );

        let revised = api
            .revise(
                &selected.handle,
                selected.revision,
                slow_log_input(&DEFAULT_FEATURES, "50000", "512"),
            )
            .unwrap();
        assert!(
            revised.artifacts[0]
                .preview
                .contains("slowlog-log-slower-than 50000\n")
        );
        assert!(
            revised.artifacts[0]
                .preview
                .contains("slowlog-max-len 512\n")
        );
        assert!(api.copy(&selected.handle, selected.revision).is_err());

        let without_slow_log = DEFAULT_FEATURES
            .into_iter()
            .filter(|feature| *feature != "slow-log")
            .collect::<Vec<_>>();
        let removed = api
            .revise(
                &revised.handle,
                revised.revision,
                slow_log_input(&without_slow_log, "50000", "512"),
            )
            .unwrap();
        assert!(
            removed.artifacts[0]
                .preview
                .contains("slowlog-log-slower-than -1\n")
        );
        assert!(!removed.artifacts[0].preview.contains("slowlog-max-len"));
        assert!(api.copy(&revised.handle, revised.revision).is_err());
        let removed_copy = api.copy(&removed.handle, removed.revision).unwrap();
        assert_eq!(
            removed_copy.artifacts[0].contents,
            removed.artifacts[0].preview
        );

        let public_error = api
            .revise(
                &removed.handle,
                removed.revision,
                slow_log_input(&DEFAULT_FEATURES, HOSTILE_VALUE, "512"),
            )
            .expect_err("hostile Redis slowlog value must fail without mutation")
            .to_string();
        for rejected in ["redisInlineExecuted", "NeverShow42", HOSTILE_VALUE] {
            assert!(!public_error.contains(rejected));
        }
        let after_rejection = api.copy(&removed.handle, removed.revision).unwrap();
        assert_eq!(
            after_rejection.artifacts[0].contents,
            removed_copy.artifacts[0].contents
        );
        assert!(
            !after_rejection.artifacts[0]
                .contents
                .contains("redisInlineExecuted")
        );
        assert!(
            !after_rejection.artifacts[0]
                .contents
                .contains("NeverShow42")
        );
    }

    #[test]
    fn redis_quick_stack_remove_reset_preview_and_save_prerequisites_are_current() {
        const HOSTILE_FEATURE: &str =
            "<script>globalThis.redisStackExecuted=true</script> password=NeverShow42";

        fn redis_input(
            features: &[&str],
            idle_timeout: &str,
            latency_threshold: &str,
            eviction_policy: &str,
        ) -> ConfigGenerateInput {
            serde_json::from_value(json!({
                "product": "redis",
                "choice": "8.10",
                "features": features,
                "values": {
                    "idleTimeout": idle_timeout,
                    "latencyThreshold": latency_threshold,
                    "evictionPolicy": eviction_policy
                }
            }))
            .unwrap()
        }

        let stacked_features = [
            "max-clients",
            "idle-client-timeout",
            "tcp-keepalive",
            "memory-limit",
            "eviction-policy",
            "aof-persistence",
            "rdb-persistence",
            "slow-log",
            "latency-monitor",
        ];
        let api = ConfigApi::default();
        let baseline = api.generate(input("redis")).unwrap();
        let baseline_copy = api.copy(&baseline.handle, baseline.revision).unwrap();
        assert_eq!(baseline.suggested_name, "redis-new-empty-instance.conf");
        for expected in [
            "Redis Open Source 8.10",
            "maxmemory 536870912\n",
            "appendonly yes\n",
            "save 3600 1\n",
        ] {
            assert!(
                baseline.artifacts[0].preview.contains(expected),
                "{expected}"
            );
        }

        let stacked = api
            .revise(
                &baseline.handle,
                baseline.revision,
                redis_input(&stacked_features, "600", "50", "allkeys-lru"),
            )
            .unwrap();
        for expected in [
            "timeout 600\n",
            "latency-monitor-threshold 50\n",
            "maxmemory-policy allkeys-lru\n",
        ] {
            assert!(
                stacked.artifacts[0].preview.contains(expected),
                "{expected}"
            );
        }
        assert!(api.copy(&baseline.handle, baseline.revision).is_err());
        assert!(
            api.artifact(&baseline.handle, baseline.revision, "main")
                .is_err()
        );

        let remaining_features = stacked_features
            .iter()
            .copied()
            .filter(|feature| *feature != "idle-client-timeout")
            .collect::<Vec<_>>();
        let remaining = api
            .revise(
                &stacked.handle,
                stacked.revision,
                redis_input(&remaining_features, "600", "50", "allkeys-lru"),
            )
            .unwrap();
        assert!(remaining.artifacts[0].preview.contains("timeout 0\n"));
        assert!(
            remaining.artifacts[0]
                .preview
                .contains("latency-monitor-threshold 50\n")
        );
        assert!(
            remaining.artifacts[0]
                .preview
                .contains("maxmemory-policy allkeys-lru\n")
        );

        let without_memory = remaining_features
            .iter()
            .copied()
            .filter(|feature| *feature != "memory-limit")
            .collect::<Vec<_>>();
        assert!(
            api.revise(
                &remaining.handle,
                remaining.revision,
                redis_input(&without_memory, "600", "50", "allkeys-lru"),
            )
            .is_err()
        );

        let rdb_only_features = remaining_features
            .iter()
            .copied()
            .filter(|feature| *feature != "aof-persistence")
            .collect::<Vec<_>>();
        let rdb_only = api
            .revise(
                &remaining.handle,
                remaining.revision,
                redis_input(&rdb_only_features, "600", "50", "allkeys-lru"),
            )
            .unwrap();
        assert!(rdb_only.artifacts[0].preview.contains("appendonly no\n"));
        assert!(rdb_only.artifacts[0].preview.contains("save 3600 1\n"));
        assert!(api.copy(&remaining.handle, remaining.revision).is_err());

        let without_persistence = rdb_only_features
            .iter()
            .copied()
            .filter(|feature| *feature != "rdb-persistence")
            .collect::<Vec<_>>();
        assert!(
            api.revise(
                &rdb_only.handle,
                rdb_only.revision,
                redis_input(&without_persistence, "600", "50", "allkeys-lru"),
            )
            .is_err()
        );
        let after_rejection = api.copy(&rdb_only.handle, rdb_only.revision).unwrap();
        assert_eq!(
            after_rejection.artifacts[0].contents,
            rdb_only.artifacts[0].preview
        );

        let reset = api
            .revise(&rdb_only.handle, rdb_only.revision, input("redis"))
            .unwrap();
        assert_eq!(reset.artifacts[0].preview, baseline.artifacts[0].preview);
        let reset_copy = api.copy(&reset.handle, reset.revision).unwrap();
        assert_eq!(
            reset_copy.artifacts[0].contents,
            baseline_copy.artifacts[0].contents
        );
        let reset_export = api.artifact(&reset.handle, reset.revision, "main").unwrap();
        assert_eq!(reset_export.suggested_name, "redis.conf");
        assert_eq!(reset_export.contents, baseline_copy.artifacts[0].contents);

        for rejected_input in [
            redis_input(&without_memory, "600", "50", "allkeys-lru"),
            redis_input(&without_persistence, "600", "50", "allkeys-lru"),
            redis_input(&[HOSTILE_FEATURE], "600", "50", "allkeys-lru"),
        ] {
            let public_error = api
                .revise(&reset.handle, reset.revision, rejected_input)
                .expect_err("invalid Redis request must fail without mutation")
                .to_string();
            for rejected in ["redisStackExecuted", "NeverShow42", HOSTILE_FEATURE] {
                assert!(!public_error.contains(rejected));
            }
        }
        let current = api.copy(&reset.handle, reset.revision).unwrap();
        assert_eq!(
            current.artifacts[0].contents,
            baseline_copy.artifacts[0].contents
        );
        assert!(!current.artifacts[0].contents.contains("redisStackExecuted"));
        assert!(!current.artifacts[0].contents.contains("NeverShow42"));
    }

    #[test]
    fn tomcat_catalog_inline_editor_and_preview_prerequisites_are_current_and_fail_closed() {
        const HOSTILE_VALUE: &str =
            "<script>globalThis.tomcatInlineExecuted=true</script> password=NeverShow42";
        const DEFAULT_FEATURES: [&str; 3] = [
            "connector-limits",
            "http-only-session-cookies",
            "header-security-filter",
        ];

        fn connector_input(
            features: &[&str],
            max_threads: &str,
            accept_count: &str,
            max_connections: &str,
            max_post_size: &str,
            max_swallow_size: &str,
        ) -> ConfigGenerateInput {
            serde_json::from_value(json!({
                "product": "tomcat",
                "choice": "11.0",
                "features": features,
                "values": {
                    "maxThreads": max_threads,
                    "acceptCount": accept_count,
                    "maxConnections": max_connections,
                    "maxPostSize": max_post_size,
                    "maxSwallowSize": max_swallow_size
                }
            }))
            .unwrap()
        }

        fn artifact<'a>(draft: &'a ConfigDraftDto, key: &str) -> &'a str {
            draft
                .artifacts
                .iter()
                .find(|artifact| artifact.key == key)
                .expect("Tomcat draft must retain every fixed artifact")
                .preview
                .as_str()
        }

        let catalog = config_catalog();
        let tomcat = catalog
            .products
            .iter()
            .find(|product| product.key == "tomcat")
            .unwrap();
        assert_eq!(
            tomcat
                .choices
                .iter()
                .map(|choice| choice.key.as_str())
                .collect::<Vec<_>>(),
            ["9.0", "10.1", "11.0"]
        );
        assert_eq!(
            tomcat
                .artifacts
                .iter()
                .map(|artifact| artifact.key.as_str())
                .collect::<Vec<_>>(),
            ["server.xml", "context.xml", "web.xml"]
        );
        let connector_limits = tomcat
            .features
            .iter()
            .find(|feature| feature.key == "connector-limits")
            .unwrap();
        assert_eq!(
            connector_limits.title,
            "限制 Connector 容量、参数转换与中止上传吞咽量"
        );
        assert_eq!(connector_limits.scope, "Connector / server.xml");
        assert_eq!(
            connector_limits.aliases,
            [
                "maxThreads",
                "acceptCount",
                "maxConnections",
                "maxPostSize",
                "maxSwallowSize",
                "连接数",
                "表单参数",
                "参数转换",
                "中止上传吞咽",
            ]
        );
        assert_eq!(connector_limits.supported_choices, ["9.0", "10.1", "11.0"]);
        assert!(connector_limits.default_enabled);

        let api = ConfigApi::default();
        let selected = api
            .generate(connector_input(
                &DEFAULT_FEATURES,
                "320",
                "400",
                "12000",
                "3000000",
                "4000000",
            ))
            .unwrap();
        for attribute in [
            "maxThreads=\"320\"",
            "acceptCount=\"400\"",
            "maxConnections=\"12000\"",
            "maxPostSize=\"3000000\"",
            "maxSwallowSize=\"4000000\"",
        ] {
            assert!(
                artifact(&selected, "server.xml").contains(attribute),
                "{attribute}"
            );
        }
        let selected_copy = api.copy(&selected.handle, selected.revision).unwrap();
        for selected_artifact in &selected.artifacts {
            let copied = selected_copy
                .artifacts
                .iter()
                .find(|item| item.key == selected_artifact.key)
                .unwrap();
            assert_eq!(copied.contents, selected_artifact.preview);
        }

        let revised = api
            .revise(
                &selected.handle,
                selected.revision,
                connector_input(
                    &DEFAULT_FEATURES,
                    "640",
                    "800",
                    "24000",
                    "6000000",
                    "8000000",
                ),
            )
            .unwrap();
        for attribute in [
            "maxThreads=\"640\"",
            "acceptCount=\"800\"",
            "maxConnections=\"24000\"",
            "maxPostSize=\"6000000\"",
            "maxSwallowSize=\"8000000\"",
        ] {
            assert!(
                artifact(&revised, "server.xml").contains(attribute),
                "{attribute}"
            );
        }
        assert!(api.copy(&selected.handle, selected.revision).is_err());

        let without_connector_limits = DEFAULT_FEATURES
            .into_iter()
            .filter(|feature| *feature != "connector-limits")
            .collect::<Vec<_>>();
        let removed = api
            .revise(
                &revised.handle,
                revised.revision,
                connector_input(
                    &without_connector_limits,
                    "640",
                    "800",
                    "24000",
                    "6000000",
                    "8000000",
                ),
            )
            .unwrap();
        for attribute in [
            "maxThreads=",
            "acceptCount=",
            "maxConnections=",
            "maxPostSize=",
            "maxSwallowSize=",
        ] {
            assert!(
                !artifact(&removed, "server.xml").contains(attribute),
                "{attribute}"
            );
        }
        assert_eq!(
            artifact(&removed, "context.xml"),
            artifact(&revised, "context.xml")
        );
        assert_eq!(artifact(&removed, "web.xml"), artifact(&revised, "web.xml"));
        assert!(api.copy(&revised.handle, revised.revision).is_err());
        let removed_copy = api.copy(&removed.handle, removed.revision).unwrap();

        for rejected_input in [
            connector_input(
                &DEFAULT_FEATURES,
                HOSTILE_VALUE,
                "800",
                "24000",
                "6000000",
                "8000000",
            ),
            connector_input(&DEFAULT_FEATURES, "500", "800", "400", "6000000", "8000000"),
        ] {
            let public_error = api
                .revise(&removed.handle, removed.revision, rejected_input)
                .expect_err("invalid Tomcat connector values must fail without mutation")
                .to_string();
            for rejected in ["tomcatInlineExecuted", "NeverShow42", HOSTILE_VALUE] {
                assert!(!public_error.contains(rejected));
            }
        }
        let after_rejection = api.copy(&removed.handle, removed.revision).unwrap();
        assert_eq!(after_rejection.artifacts, removed_copy.artifacts);
        assert!(after_rejection.artifacts.iter().all(|artifact| {
            !artifact.contents.contains("tomcatInlineExecuted")
                && !artifact.contents.contains("NeverShow42")
        }));
    }

    #[test]
    fn tomcat_quick_bundle_stack_exclude_remove_reset_copy_and_save_prerequisites_are_current() {
        const HOSTILE_FEATURE: &str =
            "<script>globalThis.tomcatBundleExecuted=true</script> password=NeverShow42";

        fn tomcat_input(choice: &str, features: &[&str]) -> ConfigGenerateInput {
            serde_json::from_value(json!({
                "product": "tomcat",
                "choice": choice,
                "features": features,
                "values": {
                    "connectorAddress": "ipv6-loopback",
                    "applicationName": "Operations ROOT",
                    "port": "8181",
                    "connectionTimeout": "25000",
                    "maxThreads": "320",
                    "acceptCount": "400",
                    "maxConnections": "12000",
                    "maxPostSize": "3000000",
                    "maxSwallowSize": "4000000",
                    "compressionMinSize": "1024"
                }
            }))
            .unwrap()
        }

        fn preview<'a>(draft: &'a ConfigDraftDto, key: &str) -> &'a str {
            draft
                .artifacts
                .iter()
                .find(|artifact| artifact.key == key)
                .expect("Tomcat draft must retain every fixed artifact")
                .preview
                .as_str()
        }

        fn copied<'a>(copy: &'a ConfigCopyDto, key: &str) -> &'a str {
            copy.artifacts
                .iter()
                .find(|artifact| artifact.key == key)
                .expect("Tomcat copy must retain every fixed artifact")
                .contents
                .as_str()
        }

        fn assert_copy_eq(actual: &ConfigCopyDto, expected: &ConfigCopyDto) {
            assert_eq!(actual.artifacts.len(), expected.artifacts.len());
            for artifact in &actual.artifacts {
                assert_eq!(artifact.contents, copied(expected, &artifact.key));
            }
        }

        let stacked_features = [
            "connector-limits",
            "response-compression",
            "host-auto-deploy",
            "http-only-session-cookies",
            "header-security-filter",
            "allow-safe-methods-only",
        ];
        let api = ConfigApi::default();
        let baseline = api.generate(input("tomcat")).unwrap();
        let baseline_copy = api.copy(&baseline.handle, baseline.revision).unwrap();
        assert_eq!(
            baseline.suggested_name,
            "lovelyhawk-tomcat-new-empty-review-bundle"
        );
        assert_eq!(
            baseline
                .artifacts
                .iter()
                .map(|artifact| (artifact.key.as_str(), artifact.relative_path.as_str()))
                .collect::<Vec<_>>(),
            [
                ("server.xml", "conf/server.xml"),
                ("context.xml", "webapps/ROOT/META-INF/context.xml"),
                ("web.xml", "webapps/ROOT/WEB-INF/web.xml"),
            ]
        );
        assert_eq!(
            baseline_copy
                .artifacts
                .iter()
                .map(|artifact| artifact.key.as_str())
                .collect::<Vec<_>>(),
            ["server.xml", "context.xml", "web.xml"]
        );
        assert!(preview(&baseline, "server.xml").contains("address=\"127.0.0.1\""));
        assert!(preview(&baseline, "web.xml").contains("web-app_6_1.xsd"));

        let stacked = api
            .revise(
                &baseline.handle,
                baseline.revision,
                tomcat_input("10.1", &stacked_features),
            )
            .unwrap();
        for expected in [
            "address=\"::1\"",
            "port=\"8181\"",
            "connectionTimeout=\"25000\"",
            "maxThreads=\"320\"",
            "acceptCount=\"400\"",
            "maxConnections=\"12000\"",
            "maxPostSize=\"3000000\"",
            "maxSwallowSize=\"4000000\"",
            "compressionMinSize=\"1024\"",
            "autoDeploy=\"true\"",
        ] {
            assert!(
                preview(&stacked, "server.xml").contains(expected),
                "{expected}"
            );
        }
        assert!(preview(&stacked, "web.xml").contains("web-app_6_0.xsd"));
        assert!(preview(&stacked, "web.xml").contains("<http-method>GET</http-method>"));
        assert!(preview(&stacked, "web.xml").contains("<deny-uncovered-http-methods />"));
        assert_eq!(
            preview(&stacked, "context.xml"),
            preview(&baseline, "context.xml")
        );
        assert!(api.copy(&baseline.handle, baseline.revision).is_err());
        let stacked_copy = api.copy(&stacked.handle, stacked.revision).unwrap();

        let conflicting_features = [
            "connector-limits",
            "response-compression",
            "host-auto-deploy",
            "http-only-session-cookies",
            "header-security-filter",
            "allow-safe-methods-only",
            "deny-all-requests",
        ];
        assert!(
            api.revise(
                &stacked.handle,
                stacked.revision,
                tomcat_input("10.1", &conflicting_features),
            )
            .is_err()
        );
        assert_copy_eq(
            &api.copy(&stacked.handle, stacked.revision).unwrap(),
            &stacked_copy,
        );

        let deny_features = [
            "connector-limits",
            "response-compression",
            "host-auto-deploy",
            "http-only-session-cookies",
            "header-security-filter",
            "deny-all-requests",
        ];
        let deny_all = api
            .revise(
                &stacked.handle,
                stacked.revision,
                tomcat_input("10.1", &deny_features),
            )
            .unwrap();
        assert_eq!(
            preview(&deny_all, "server.xml"),
            copied(&stacked_copy, "server.xml")
        );
        assert_eq!(
            preview(&deny_all, "context.xml"),
            copied(&stacked_copy, "context.xml")
        );
        assert!(!preview(&deny_all, "web.xml").contains("<http-method>GET</http-method>"));
        assert!(
            preview(&deny_all, "web.xml")
                .contains("<web-resource-name>LovelyHawk deny all</web-resource-name>")
        );
        assert!(preview(&deny_all, "web.xml").contains("<auth-constraint />"));

        let without_deny_features = [
            "connector-limits",
            "response-compression",
            "host-auto-deploy",
            "http-only-session-cookies",
            "header-security-filter",
        ];
        let without_deny = api
            .revise(
                &deny_all.handle,
                deny_all.revision,
                tomcat_input("10.1", &without_deny_features),
            )
            .unwrap();
        let without_deny_copy = api
            .copy(&without_deny.handle, without_deny.revision)
            .unwrap();
        assert!(!preview(&without_deny, "web.xml").contains("LovelyHawk deny all"));

        let without_compression_features = [
            "connector-limits",
            "host-auto-deploy",
            "http-only-session-cookies",
            "header-security-filter",
        ];
        let without_compression = api
            .revise(
                &without_deny.handle,
                without_deny.revision,
                tomcat_input("10.1", &without_compression_features),
            )
            .unwrap();
        assert!(!preview(&without_compression, "server.xml").contains("compressionMinSize"));
        assert!(preview(&without_compression, "server.xml").contains("autoDeploy=\"true\""));
        assert_eq!(
            preview(&without_compression, "context.xml"),
            copied(&without_deny_copy, "context.xml")
        );
        assert_eq!(
            preview(&without_compression, "web.xml"),
            copied(&without_deny_copy, "web.xml")
        );

        let reset = api
            .revise(
                &without_compression.handle,
                without_compression.revision,
                input("tomcat"),
            )
            .unwrap();
        let reset_copy = api.copy(&reset.handle, reset.revision).unwrap();
        assert_copy_eq(&reset_copy, &baseline_copy);
        for (key, relative_path) in [
            ("server.xml", "conf/server.xml"),
            ("context.xml", "webapps/ROOT/META-INF/context.xml"),
            ("web.xml", "webapps/ROOT/WEB-INF/web.xml"),
        ] {
            let export = api.artifact(&reset.handle, reset.revision, key).unwrap();
            assert_eq!(export.suggested_name, relative_path);
            assert_eq!(export.contents, copied(&baseline_copy, key));
        }
        assert!(
            api.artifact(
                &without_compression.handle,
                without_compression.revision,
                "server.xml"
            )
            .is_err()
        );
        assert!(
            api.artifact(&reset.handle, reset.revision, "foreign.xml")
                .is_err()
        );

        for rejected_input in [
            tomcat_input("10.1", &conflicting_features),
            tomcat_input("10.1", &[HOSTILE_FEATURE]),
        ] {
            let public_error = api
                .revise(&reset.handle, reset.revision, rejected_input)
                .expect_err("invalid Tomcat request must fail without mutation")
                .to_string();
            for rejected in ["tomcatBundleExecuted", "NeverShow42", HOSTILE_FEATURE] {
                assert!(!public_error.contains(rejected));
            }
        }
        assert_copy_eq(
            &api.copy(&reset.handle, reset.revision).unwrap(),
            &baseline_copy,
        );
    }

    #[test]
    fn haproxy_and_mongodb_have_real_closed_generation_entries() {
        let haproxy: ConfigGenerateInput = serde_json::from_value(json!({
            "product": "haproxy",
            "features": [
                "health-check",
                "request-id",
                "forbidden-path-403",
                "restrict-source-ip"
            ]
        }))
        .unwrap();
        let generated = build_draft(haproxy).unwrap();
        assert_eq!(generated.product, "haproxy");
        assert!(
            std::str::from_utf8(&generated.artifacts[0].bytes)
                .unwrap()
                .contains("http-check")
        );

        let mongodb: ConfigGenerateInput = serde_json::from_value(json!({
            "product": "mongodb",
            "features": ["connection-limit", "log-rotation"]
        }))
        .unwrap();
        let generated = build_draft(mongodb).unwrap();
        assert_eq!(generated.product, "mongodb");
        assert!(
            std::str::from_utf8(&generated.artifacts[0].bytes)
                .unwrap()
                .contains("mongod.conf")
        );
    }

    #[test]
    fn serde_and_core_reject_unknown_fields_injection_and_unsupported_combinations() {
        assert!(
            serde_json::from_value::<ConfigGenerateInput>(json!({
                "product": "nginx",
                "command": "include /tmp/hostile.conf"
            }))
            .is_err()
        );
        let injected: ConfigGenerateInput = serde_json::from_value(json!({
            "product": "nginx",
            "values": { "serverName": "example.com; include /tmp/x;" }
        }))
        .unwrap();
        assert!(build_draft(injected).is_err());

        let static_websocket: ConfigGenerateInput = serde_json::from_value(json!({
            "product": "nginx",
            "choice": "static",
            "features": ["websocket-proxy"]
        }))
        .unwrap();
        assert!(build_draft(static_websocket).is_err());

        let deferred_tls: ConfigGenerateInput = serde_json::from_value(json!({
            "product": "haproxy",
            "features": ["tls-frontend"]
        }))
        .unwrap();
        assert!(build_draft(deferred_tls).is_err());
    }

    fn synthetic_draft(size: usize) -> BuiltDraft {
        BuiltDraft {
            product: "nginx",
            choice: "reverse-proxy".to_owned(),
            suggested_name: "nginx-site.conf".to_owned(),
            artifacts: vec![BuiltArtifact {
                key: "site".to_owned(),
                relative_path: "nginx-site.conf".to_owned(),
                media_type: "text/plain",
                bytes: vec![b'x'; size],
            }],
            notices: vec!["review only"],
            bundle: None,
        }
    }

    #[test]
    fn registry_enforces_cap_ttl_revision_and_stale_close() {
        let mut registry = DraftRegistry::default();
        let now = Instant::now();
        let (first, _) = registry.insert(synthetic_draft(32), now).unwrap();
        for _ in 1..=MAX_DRAFTS {
            registry.insert(synthetic_draft(32), now).unwrap();
        }
        assert_eq!(registry.drafts.len(), MAX_DRAFTS);
        assert!(!registry.drafts.contains_key(&first));

        let handle = registry.order.back().unwrap().clone();
        let next = registry
            .replace(&handle, 1, synthetic_draft(64), now)
            .unwrap();
        assert_eq!(next, 2);
        assert!(registry.copy(&handle, 1).is_err());
        assert!(registry.close(&handle, 1).is_err());

        registry.drafts.get_mut(&handle).unwrap().expires_at = now;
        registry.remove_expired(now);
        assert!(registry.copy(&handle, 2).is_err());
        assert!(registry.total_bytes <= MAX_REGISTRY_BYTES);
    }

    #[test]
    fn previews_are_globally_bounded_and_copy_requires_current_revision() {
        let mut registry = DraftRegistry::default();
        let (handle, revision) = registry
            .insert(synthetic_draft(MAX_PREVIEW_BYTES + 100), Instant::now())
            .unwrap();
        let dto = registry.dto(&handle, revision).unwrap();
        assert!(dto.artifacts[0].preview.len() <= MAX_PREVIEW_BYTES);
        assert!(dto.artifacts[0].preview_truncated);
        let copy = registry.copy(&handle, revision).unwrap();
        assert_eq!(copy.artifacts[0].contents.len(), MAX_PREVIEW_BYTES + 100);
        assert!(!format!("{copy:?}").contains(&copy.artifacts[0].contents));

        let api = ConfigApi::default();
        let generated = api.generate(input("nginx")).unwrap();
        assert!(!format!("{generated:?}").contains(&generated.handle));
        let artifact = api
            .artifact_bytes(&generated.handle, generated.revision, "site")
            .unwrap();
        assert!(!artifact.bytes.is_empty());
        assert!(!artifact.suggested_name.is_empty());
        let exported = api
            .artifact(&generated.handle, generated.revision, "site")
            .unwrap();
        assert!(!exported.contents.is_empty());
        assert!(!exported.suggested_name.is_empty());
        assert!(!format!("{exported:?}").contains(&exported.contents));
        let revised = api
            .revise(&generated.handle, generated.revision, input("apache"))
            .unwrap();
        assert_eq!(revised.revision, generated.revision + 1);
        assert_eq!(revised.product, "apache");
        assert!(api.copy(&generated.handle, generated.revision).is_err());
        assert!(api.close(&generated.handle, generated.revision).is_err());
        assert!(api.close(&revised.handle, revised.revision).unwrap().closed);
        assert!(api.copy(&revised.handle, revised.revision).is_err());
    }

    #[test]
    fn tomcat_is_a_three_artifact_bundle_with_fixed_safe_paths() {
        let api = ConfigApi::default();
        let generated = api.generate(input("tomcat")).unwrap();
        assert_eq!(generated.artifacts.len(), 3);
        let paths = generated
            .artifacts
            .iter()
            .map(|artifact| artifact.relative_path.as_str())
            .collect::<HashSet<_>>();
        assert_eq!(paths.len(), 3);
        assert!(paths.contains("conf/server.xml"));
        assert!(paths.contains("webapps/ROOT/META-INF/context.xml"));
        assert!(paths.contains("webapps/ROOT/WEB-INF/web.xml"));
        let copied = api.copy(&generated.handle, generated.revision).unwrap();
        assert_eq!(copied.artifacts.len(), 3);
    }
}
