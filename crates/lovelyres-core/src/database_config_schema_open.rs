//! Reviewed partial schemas for upstream database server configuration files.
//!
//! These schemas describe the effect of editing files, not the separate SQL
//! runtime-variable surfaces. Consequently, a MySQL or MariaDB option-file
//! change remains `Restart` even when the corresponding runtime variable is
//! dynamic. PostgreSQL parameters that are backend-start scoped are `Reload`;
//! their rationale states that only connections created after the reload see
//! the new file default.

use crate::database_config::{DatabaseConfigComponent, DatabaseConfigProduct};
use crate::database_config_schema::{
    DatabaseConfigParameterSchema, DatabaseConfigSchema, DatabaseConfigSchemaActivation,
    DatabaseConfigSchemaBinding, DatabaseConfigSchemaCompleteness, DatabaseConfigSchemaReference,
    DatabaseConfigSchemaRisk, DatabaseConfigSchemaScope, DatabaseConfigSchemaSensitivity,
    DatabaseConfigSchemaValueKind, DatabaseConfigTextNormalization, DatabaseConfigVersion,
    DatabaseConfigVersionSelector,
};

pub const MYSQL_ENTERPRISE_AUDIT_CAPABILITY: &str = "mysql.enterprise_audit";
pub const MARIADB_AUDIT_PLUGIN_CAPABILITY: &str = "mariadb.audit_plugin";
pub const MARIADB_GALERA_CAPABILITY: &str = "mariadb.galera";
pub const POSTGRESQL_OAUTH_CAPABILITY: &str = "postgresql.oauth";

const PUBLIC: DatabaseConfigSchemaSensitivity = DatabaseConfigSchemaSensitivity::Public;
const METADATA: DatabaseConfigSchemaSensitivity =
    DatabaseConfigSchemaSensitivity::OperationalMetadata;
const SECRET: DatabaseConfigSchemaSensitivity = DatabaseConfigSchemaSensitivity::MayContainSecrets;
const PRIVATE_KEY: DatabaseConfigSchemaSensitivity =
    DatabaseConfigSchemaSensitivity::PrivateKeyReference;

const GLOBAL: DatabaseConfigSchemaScope = DatabaseConfigSchemaScope::Global;
const SESSION: DatabaseConfigSchemaScope = DatabaseConfigSchemaScope::Session;
const CLUSTER: DatabaseConfigSchemaScope = DatabaseConfigSchemaScope::Cluster;

const RESTART: DatabaseConfigSchemaActivation = DatabaseConfigSchemaActivation::Restart;
const RELOAD: DatabaseConfigSchemaActivation = DatabaseConfigSchemaActivation::Reload;

const MEDIUM: DatabaseConfigSchemaRisk = DatabaseConfigSchemaRisk::Medium;
const HIGH: DatabaseConfigSchemaRisk = DatabaseConfigSchemaRisk::High;
const CRITICAL: DatabaseConfigSchemaRisk = DatabaseConfigSchemaRisk::Critical;

const BOOL_ON_OFF: DatabaseConfigSchemaValueKind = DatabaseConfigSchemaValueKind::Boolean {
    true_literal: "ON",
    false_literal: "OFF",
};
const BOOL_ON_OFF_LOWER: DatabaseConfigSchemaValueKind = DatabaseConfigSchemaValueKind::Boolean {
    true_literal: "on",
    false_literal: "off",
};

const fn text(maximum_bytes: usize) -> DatabaseConfigSchemaValueKind {
    DatabaseConfigSchemaValueKind::Text {
        minimum_bytes: 0,
        maximum_bytes,
        normalization: DatabaseConfigTextNormalization::Preserve,
    }
}

const fn trimmed_text(minimum_bytes: usize, maximum_bytes: usize) -> DatabaseConfigSchemaValueKind {
    DatabaseConfigSchemaValueKind::Text {
        minimum_bytes,
        maximum_bytes,
        normalization: DatabaseConfigTextNormalization::TrimAsciiWhitespace,
    }
}

#[allow(clippy::too_many_arguments)]
const fn parameter(
    container_path: Option<&'static str>,
    canonical_key: &'static str,
    exact_aliases: &'static [&'static str],
    value_kind: DatabaseConfigSchemaValueKind,
    scope: DatabaseConfigSchemaScope,
    sensitivity: DatabaseConfigSchemaSensitivity,
    activation: DatabaseConfigSchemaActivation,
    risk: DatabaseConfigSchemaRisk,
    risk_rationale: &'static str,
    competition_rationale: &'static str,
    official_reference_id: &'static str,
    required_capability: Option<&'static str>,
) -> DatabaseConfigParameterSchema {
    DatabaseConfigParameterSchema {
        container_path,
        canonical_key,
        exact_aliases,
        value_kind,
        documented_default: None,
        scope,
        sensitivity,
        activation,
        risk,
        risk_rationale,
        competition_rationale,
        official_reference_id,
        required_capability,
    }
}

/// Expands reviewed parameters into named option-file groups without changing
/// key matching semantics. The schema layer applies the vendor-documented
/// ASCII case-insensitive semantics to these explicit group names only.
const fn parameters_for_containers<const OUTPUT: usize>(
    base: &[DatabaseConfigParameterSchema],
    containers: &[&'static str],
) -> [DatabaseConfigParameterSchema; OUTPUT] {
    assert!(!base.is_empty());
    assert!(OUTPUT == base.len() * containers.len());

    let mut expanded = [base[0]; OUTPUT];
    let mut output_index = 0;
    let mut container_index = 0;
    while container_index < containers.len() {
        let mut parameter_index = 0;
        while parameter_index < base.len() {
            let mut parameter = base[parameter_index];
            parameter.container_path = Some(containers[container_index]);
            expanded[output_index] = parameter;
            output_index += 1;
            parameter_index += 1;
        }
        container_index += 1;
    }
    expanded
}

const MYSQL_8_0_REFERENCES: &[DatabaseConfigSchemaReference] = &[
    DatabaseConfigSchemaReference {
        id: "mysql:system-variables",
        title: "MySQL 8.0 Reference Manual - Server System Variables",
        url: "https://dev.mysql.com/doc/refman/8.0/en/server-system-variables.html",
    },
    DatabaseConfigSchemaReference {
        id: "mysql:server-options",
        title: "MySQL 8.0 Reference Manual - Server Command Options",
        url: "https://dev.mysql.com/doc/refman/8.0/en/server-options.html",
    },
    DatabaseConfigSchemaReference {
        id: "mysql:tls",
        title: "MySQL 8.0 Reference Manual - Configuring Encrypted Connections",
        url: "https://dev.mysql.com/doc/refman/8.0/en/using-encrypted-connections.html",
    },
    DatabaseConfigSchemaReference {
        id: "mysql:replication",
        title: "MySQL 8.0 Reference Manual - Replication and Binary Logging Options",
        url: "https://dev.mysql.com/doc/refman/8.0/en/replication-options-binary-log.html",
    },
];

const MYSQL_8_4_REFERENCES: &[DatabaseConfigSchemaReference] = &[
    DatabaseConfigSchemaReference {
        id: "mysql:system-variables",
        title: "MySQL 8.4 Reference Manual - Server System Variables",
        url: "https://dev.mysql.com/doc/refman/8.4/en/server-system-variables.html",
    },
    DatabaseConfigSchemaReference {
        id: "mysql:server-options",
        title: "MySQL 8.4 Reference Manual - Server Command Options",
        url: "https://dev.mysql.com/doc/refman/8.4/en/server-options.html",
    },
    DatabaseConfigSchemaReference {
        id: "mysql:tls",
        title: "MySQL 8.4 Reference Manual - Configuring Encrypted Connections",
        url: "https://dev.mysql.com/doc/refman/8.4/en/using-encrypted-connections.html",
    },
    DatabaseConfigSchemaReference {
        id: "mysql:replication",
        title: "MySQL 8.4 Reference Manual - Replication and Binary Logging Options",
        url: "https://dev.mysql.com/doc/refman/8.4/en/replication-options-binary-log.html",
    },
    DatabaseConfigSchemaReference {
        id: "mysql:native-auth",
        title: "MySQL 8.4 Reference Manual - Native Pluggable Authentication",
        url: "https://dev.mysql.com/doc/refman/8.4/en/native-pluggable-authentication.html",
    },
    DatabaseConfigSchemaReference {
        id: "mysql:enterprise-audit",
        title: "MySQL 8.4 Reference Manual - Enterprise Audit Log Reference",
        url: "https://dev.mysql.com/doc/refman/8.4/en/audit-log-reference.html",
    },
];

const MARIADB_REFERENCES: &[DatabaseConfigSchemaReference] = &[
    DatabaseConfigSchemaReference {
        id: "mariadb:system-variables",
        title: "MariaDB Server Documentation - Server System Variables",
        url: "https://mariadb.com/docs/server/server-management/variables-and-modes/server-system-variables",
    },
    DatabaseConfigSchemaReference {
        id: "mariadb:tls",
        title: "MariaDB Server Documentation - SSL/TLS System Variables",
        url: "https://mariadb.com/docs/server/security/encryption/data-in-transit-encryption/ssltls-system-variables",
    },
    DatabaseConfigSchemaReference {
        id: "mariadb:replication",
        title: "MariaDB Server Documentation - Replication and Binary Log System Variables",
        url: "https://mariadb.com/docs/server/ha-and-performance/standard-replication/replication-and-binary-log-system-variables",
    },
    DatabaseConfigSchemaReference {
        id: "mariadb:audit",
        title: "MariaDB Server Documentation - Audit Plugin Options and System Variables",
        url: "https://mariadb.com/docs/server/reference/plugins/mariadb-audit-plugin/mariadb-audit-plugin-options-and-system-variables",
    },
    DatabaseConfigSchemaReference {
        id: "mariadb:server-options",
        title: "MariaDB Server Documentation - mariadbd Options",
        url: "https://mariadb.com/docs/server/server-management/starting-and-stopping-mariadb/mariadbd-options",
    },
    DatabaseConfigSchemaReference {
        id: "mariadb:option-files",
        title: "MariaDB Server Documentation - Configuring MariaDB with Option Files",
        url: "https://mariadb.com/docs/server/server-management/install-and-upgrade-mariadb/configuring-mariadb/configuring-mariadb-with-option-files",
    },
    DatabaseConfigSchemaReference {
        id: "mariadb:galera-sst",
        title: "MariaDB Galera Cluster Documentation - mariadb-backup SST Method",
        url: "https://mariadb.com/docs/galera-cluster/high-availability/state-snapshot-transfers-ssts-in-galera-cluster/mariadb-backup-sst-method",
    },
];

macro_rules! postgresql_references {
    ($name:ident, $version:literal) => {
        const $name: &[DatabaseConfigSchemaReference] = &[
            DatabaseConfigSchemaReference {
                id: "postgresql:connection",
                title: concat!("PostgreSQL ", $version, " - Connections and Authentication"),
                url: concat!(
                    "https://www.postgresql.org/docs/",
                    $version,
                    "/runtime-config-connection.html"
                ),
            },
            DatabaseConfigSchemaReference {
                id: "postgresql:logging",
                title: concat!("PostgreSQL ", $version, " - Error Reporting and Logging"),
                url: concat!(
                    "https://www.postgresql.org/docs/",
                    $version,
                    "/runtime-config-logging.html"
                ),
            },
            DatabaseConfigSchemaReference {
                id: "postgresql:resources",
                title: concat!("PostgreSQL ", $version, " - Resource Consumption"),
                url: concat!(
                    "https://www.postgresql.org/docs/",
                    $version,
                    "/runtime-config-resource.html"
                ),
            },
            DatabaseConfigSchemaReference {
                id: "postgresql:file-locations",
                title: concat!("PostgreSQL ", $version, " - File Locations"),
                url: concat!(
                    "https://www.postgresql.org/docs/",
                    $version,
                    "/runtime-config-file-locations.html"
                ),
            },
            DatabaseConfigSchemaReference {
                id: "postgresql:replication",
                title: concat!("PostgreSQL ", $version, " - Replication"),
                url: concat!(
                    "https://www.postgresql.org/docs/",
                    $version,
                    "/runtime-config-replication.html"
                ),
            },
            DatabaseConfigSchemaReference {
                id: "postgresql:wal",
                title: concat!("PostgreSQL ", $version, " - Write Ahead Log"),
                url: concat!(
                    "https://www.postgresql.org/docs/",
                    $version,
                    "/runtime-config-wal.html"
                ),
            },
            DatabaseConfigSchemaReference {
                id: "postgresql:client",
                title: concat!("PostgreSQL ", $version, " - Client Connection Defaults"),
                url: concat!(
                    "https://www.postgresql.org/docs/",
                    $version,
                    "/runtime-config-client.html"
                ),
            },
            DatabaseConfigSchemaReference {
                id: "postgresql:developer",
                title: concat!("PostgreSQL ", $version, " - Developer Options"),
                url: concat!(
                    "https://www.postgresql.org/docs/",
                    $version,
                    "/runtime-config-developer.html"
                ),
            },
        ];
    };
}

postgresql_references!(POSTGRESQL_16_REFERENCES, "16");
postgresql_references!(POSTGRESQL_17_REFERENCES, "17");
postgresql_references!(POSTGRESQL_18_REFERENCES, "18");

macro_rules! define_mysql_parameters {
    ($name:ident, $version_group:literal; $($extra:expr),* $(,)?) => {
        const $name: &[DatabaseConfigParameterSchema] = &{
            const BASE: &[DatabaseConfigParameterSchema] = &[
            parameter(
                Some("mysqld"),
                "bind_address",
                &["bind-address"],
                text(4_096),
                GLOBAL,
                METADATA,
                RESTART,
                HIGH,
                "Wildcard or broad listener addresses expose MySQL on additional interfaces.",
                "Listener scope is a first-pass incident-response exposure check.",
                "mysql:system-variables",
                None,
            ),
            parameter(
                Some("mysqld"),
                "port",
                &[],
                DatabaseConfigSchemaValueKind::Integer {
                    minimum_inclusive: 0,
                    maximum_inclusive: 65_535,
                },
                GLOBAL,
                PUBLIC,
                RESTART,
                MEDIUM,
                "The TCP port changes the reachable service endpoint.",
                "Competitors need exact endpoint visibility without assuming port 3306.",
                "mysql:system-variables",
                None,
            ),
            parameter(
                Some("mysqld"),
                "skip_networking",
                &["skip-networking"],
                BOOL_ON_OFF,
                GLOBAL,
                PUBLIC,
                RESTART,
                HIGH,
                "Enabling this disables TCP and leaves only local transports.",
                "A mistaken value can either expose TCP or cut off remote response access.",
                "mysql:system-variables",
                None,
            ),
            parameter(
                Some("mysqld"),
                "skip_name_resolve",
                &["skip-name-resolve"],
                BOOL_ON_OFF,
                GLOBAL,
                PUBLIC,
                RESTART,
                HIGH,
                "Host grants that depend on DNS names stop matching when this is enabled.",
                "The UI must warn before a hardening change locks out responder accounts.",
                "mysql:system-variables",
                None,
            ),
            parameter(
                Some("mysqld"),
                "require_secure_transport",
                &["require-secure-transport"],
                BOOL_ON_OFF,
                GLOBAL,
                PUBLIC,
                RESTART,
                HIGH,
                "OFF permits unencrypted TCP connections.",
                "Transport enforcement is a high-value containment control.",
                "mysql:system-variables",
                None,
            ),
            parameter(
                Some("mysqld"),
                "tls_version",
                &["tls-version"],
                trimmed_text(0, 128),
                GLOBAL,
                PUBLIC,
                RESTART,
                HIGH,
                "An empty or weak protocol set can disable or weaken encrypted connections.",
                "The accepted protocol set varies across MySQL 8.0 patch levels, so it remains bounded text.",
                "mysql:tls",
                None,
            ),
            parameter(
                Some("mysqld"),
                "ssl_ca",
                &["ssl-ca"],
                text(4_096),
                GLOBAL,
                METADATA,
                RESTART,
                HIGH,
                "The CA path defines the trust root used for encrypted connections.",
                "Missing or replaced trust material is important attack evidence.",
                "mysql:tls",
                None,
            ),
            parameter(
                Some("mysqld"),
                "ssl_cert",
                &["ssl-cert"],
                text(4_096),
                GLOBAL,
                METADATA,
                RESTART,
                HIGH,
                "The certificate path selects the server identity presented to clients.",
                "Certificate replacement is relevant during active interception response.",
                "mysql:tls",
                None,
            ),
            parameter(
                Some("mysqld"),
                "ssl_key",
                &["ssl-key"],
                text(4_096),
                GLOBAL,
                PRIVATE_KEY,
                RESTART,
                CRITICAL,
                "The value identifies private-key material and must not be exposed in previews.",
                "Private-key references require redaction and strict file-permission review.",
                "mysql:tls",
                None,
            ),
            parameter(
                Some("mysqld"),
                "max_connections",
                &["max-connections"],
                DatabaseConfigSchemaValueKind::Integer {
                    minimum_inclusive: 1,
                    maximum_inclusive: 100_000,
                },
                GLOBAL,
                PUBLIC,
                RESTART,
                HIGH,
                "Excessive connection limits can exhaust memory, threads, and file descriptors.",
                "Responders also need enough capacity to retain an emergency login path.",
                "mysql:system-variables",
                None,
            ),
            parameter(
                Some("mysqld"),
                "max_connect_errors",
                &["max-connect-errors"],
                trimmed_text(1, 20),
                GLOBAL,
                PUBLIC,
                RESTART,
                MEDIUM,
                "The documented maximum is platform dependent.",
                "A low limit can block responders while an excessive limit weakens abuse throttling.",
                "mysql:system-variables",
                None,
            ),
            parameter(
                Some("mysqld"),
                "connect_timeout",
                &["connect-timeout"],
                DatabaseConfigSchemaValueKind::Integer {
                    minimum_inclusive: 2,
                    maximum_inclusive: 31_536_000,
                },
                GLOBAL,
                PUBLIC,
                RESTART,
                MEDIUM,
                "Long authentication waits consume connection slots.",
                "The bound helps identify resource-exhaustion configurations.",
                "mysql:system-variables",
                None,
            ),
            parameter(
                Some("mysqld"),
                "wait_timeout",
                &["wait-timeout"],
                trimmed_text(1, 20),
                GLOBAL,
                PUBLIC,
                RESTART,
                MEDIUM,
                "The documented upper bound differs by platform.",
                "Very long idle sessions can consume response capacity.",
                "mysql:system-variables",
                None,
            ),
            parameter(
                Some("mysqld"),
                "general_log",
                &["general-log"],
                BOOL_ON_OFF,
                GLOBAL,
                PUBLIC,
                RESTART,
                HIGH,
                "The general log can contain sensitive SQL and adds substantial I/O.",
                "It is useful evidence only when destination, permissions, and retention are controlled.",
                "mysql:system-variables",
                None,
            ),
            parameter(
                Some("mysqld"),
                "general_log_file",
                &["general-log-file"],
                text(4_096),
                GLOBAL,
                METADATA,
                RESTART,
                HIGH,
                "The destination can expose or overwrite sensitive query evidence.",
                "Responders must verify the exact protected log path.",
                "mysql:system-variables",
                None,
            ),
            parameter(
                Some("mysqld"),
                "slow_query_log",
                &["slow-query-log"],
                BOOL_ON_OFF,
                GLOBAL,
                PUBLIC,
                RESTART,
                MEDIUM,
                "Slow-query logging can disclose SQL and consume disk.",
                "Controlled activation can preserve useful performance and attack traces.",
                "mysql:system-variables",
                None,
            ),
            parameter(
                Some("mysqld"),
                "slow_query_log_file",
                &["slow-query-log-file"],
                text(4_096),
                GLOBAL,
                METADATA,
                RESTART,
                HIGH,
                "The file path controls where sensitive slow SQL is retained.",
                "Path and permissions are part of evidence integrity.",
                "mysql:system-variables",
                None,
            ),
            parameter(
                Some("mysqld"),
                "log_output",
                &["log-output"],
                DatabaseConfigSchemaValueKind::Enumeration {
                    values: &["FILE", "TABLE", "FILE,TABLE", "TABLE,FILE", "NONE"],
                },
                GLOBAL,
                PUBLIC,
                RESTART,
                HIGH,
                "NONE suppresses general and slow log output even when their switches are enabled.",
                "A visually enabled log with no destination is a common evidence gap.",
                "mysql:system-variables",
                None,
            ),
            parameter(
                Some("mysqld"),
                "log_error",
                &["log-error"],
                text(4_096),
                GLOBAL,
                METADATA,
                RESTART,
                HIGH,
                "An inaccessible error-log path removes critical diagnostics.",
                "Error logs are primary incident-response evidence.",
                "mysql:system-variables",
                None,
            ),
            parameter(
                Some("mysqld"),
                "log_error_verbosity",
                &["log-error-verbosity"],
                DatabaseConfigSchemaValueKind::Integer {
                    minimum_inclusive: 1,
                    maximum_inclusive: 3,
                },
                GLOBAL,
                PUBLIC,
                RESTART,
                MEDIUM,
                "Low verbosity can suppress warnings while high verbosity increases disclosure.",
                "The setting changes the evidence available during a competition.",
                "mysql:system-variables",
                None,
            ),
            parameter(
                Some("mysqld"),
                "log_error_services",
                &["log-error-services"],
                text(4_096),
                GLOBAL,
                PUBLIC,
                RESTART,
                CRITICAL,
                "Named nonbuilt-in components can be implicitly loaded into the server.",
                "This is both an evidence-routing and native-code loading boundary.",
                "mysql:system-variables",
                None,
            ),
            parameter(
                Some("mysqld"),
                "log_raw",
                &["log-raw"],
                BOOL_ON_OFF,
                GLOBAL,
                PUBLIC,
                RESTART,
                CRITICAL,
                "Raw logging can record passwords before query rewriting masks them.",
                "The setting must be prominently flagged to prevent credential disclosure.",
                "mysql:server-options",
                None,
            ),
            parameter(
                Some("mysqld"),
                "local_infile",
                &["local-infile"],
                BOOL_ON_OFF,
                GLOBAL,
                PUBLIC,
                RESTART,
                HIGH,
                "Enabling local file loading expands client-file attack surface.",
                "Unexpected enablement is a useful compromise indicator.",
                "mysql:system-variables",
                None,
            ),
            parameter(
                Some("mysqld"),
                "secure_file_priv",
                &["secure-file-priv"],
                text(4_096),
                GLOBAL,
                METADATA,
                RESTART,
                CRITICAL,
                "An empty value permits import and export in any server-accessible directory; NULL disables it.",
                "The exact path bounds FILE-based exfiltration and plugin-dropping attacks.",
                "mysql:system-variables",
                None,
            ),
            parameter(
                Some("mysqld"),
                "init_file",
                &["init-file"],
                text(4_096),
                GLOBAL,
                METADATA,
                RESTART,
                CRITICAL,
                "The referenced file executes SQL during server startup.",
                "It is a direct privileged persistence location.",
                "mysql:system-variables",
                None,
            ),
            parameter(
                Some("mysqld"),
                "plugin_dir",
                &["plugin-dir"],
                text(4_096),
                GLOBAL,
                METADATA,
                RESTART,
                CRITICAL,
                "A server-writable plugin directory can turn file writes into native-code execution.",
                "The directory is a critical persistence and execution boundary.",
                "mysql:system-variables",
                None,
            ),
            parameter(
                Some("mysqld"),
                "skip_grant_tables",
                &["skip-grant-tables"],
                text(16),
                GLOBAL,
                PUBLIC,
                RESTART,
                CRITICAL,
                "This startup option bypasses the privilege system.",
                "Any configured occurrence requires immediate critical review, including valueless option syntax.",
                "mysql:server-options",
                None,
            ),
            parameter(
                Some("mysqld"),
                "read_only",
                &["read-only"],
                BOOL_ON_OFF,
                GLOBAL,
                PUBLIC,
                RESTART,
                HIGH,
                "Privileged users and replication activity retain documented write exceptions.",
                "The UI must not present this as an absolute integrity boundary.",
                "mysql:system-variables",
                None,
            ),
            parameter(
                Some("mysqld"),
                "super_read_only",
                &["super-read-only"],
                BOOL_ON_OFF,
                GLOBAL,
                PUBLIC,
                RESTART,
                HIGH,
                "Disabling stronger read-only protection permits privileged client writes.",
                "Replica containment depends on the stronger setting during response.",
                "mysql:system-variables",
                None,
            ),
            parameter(
                Some("mysqld"),
                "log_bin",
                &["log-bin"],
                text(4_096),
                GLOBAL,
                METADATA,
                RESTART,
                HIGH,
                "The option enables binary logging and may carry an optional log basename; it is not the read-only runtime Boolean.",
                "Option-file and runtime meanings remain separate while binary-log continuity supports reconstruction.",
                "mysql:replication",
                None,
            ),
            parameter(
                Some("mysqld"),
                "server_id",
                &["server-id"],
                DatabaseConfigSchemaValueKind::Integer {
                    minimum_inclusive: 1,
                    maximum_inclusive: 4_294_967_295,
                },
                GLOBAL,
                PUBLIC,
                RESTART,
                HIGH,
                "Duplicate identifiers break replication topology identity.",
                "Exact server identity helps detect a redirected or cloned replica.",
                "mysql:replication",
                None,
            ),
            parameter(
                Some("mysqld"),
                "binlog_format",
                &["binlog-format"],
                DatabaseConfigSchemaValueKind::Enumeration {
                    values: &["ROW", "MIXED", "STATEMENT"],
                },
                GLOBAL,
                PUBLIC,
                RESTART,
                HIGH,
                "Statement logging can reproduce nondeterministic changes differently on replicas.",
                "Format changes during replication require explicit topology review.",
                "mysql:replication",
                None,
            ),
            parameter(
                Some("mysqld"),
                "binlog_expire_logs_seconds",
                &["binlog-expire-logs-seconds"],
                DatabaseConfigSchemaValueKind::Integer {
                    minimum_inclusive: 0,
                    maximum_inclusive: 4_294_967_295,
                },
                GLOBAL,
                PUBLIC,
                RESTART,
                HIGH,
                "Zero can exhaust disk; a short window destroys recovery history and strands lagging replicas.",
                "Retention must cover the competition recovery horizon.",
                "mysql:replication",
                None,
            ),
            $(
                $extra,
            )*
            ];
            parameters_for_containers::<{ BASE.len() * 3 }>(
                BASE,
                &["mysqld", "server", $version_group],
            )
        };
    };
}

define_mysql_parameters!(MYSQL_8_0_PARAMETERS, "mysqld-8.0";
    parameter(
        Some("mysqld"),
        "default_authentication_plugin",
        &["default-authentication-plugin"],
        DatabaseConfigSchemaValueKind::Enumeration {
            values: &[
                "caching_sha2_password",
                "sha256_password",
                "mysql_native_password",
            ],
        },
        GLOBAL,
        PUBLIC,
        RESTART,
        HIGH,
        "The selected default affects credentials created or changed afterwards and is removed in MySQL 8.4.",
        "The versioned schema prevents generating this removed option for 8.4.",
        "mysql:system-variables",
        None,
    )
);

define_mysql_parameters!(MYSQL_8_4_PARAMETERS, "mysqld-8.4";
    parameter(
        Some("mysqld"),
        "authentication_policy",
        &["authentication-policy"],
        trimmed_text(1, 4_096),
        GLOBAL,
        PUBLIC,
        RESTART,
        HIGH,
        "The policy constrains new or altered accounts but does not retrofit existing accounts.",
        "Responders must distinguish future account policy from current credential state.",
        "mysql:system-variables",
        None,
    ),
    parameter(
        Some("mysqld"),
        "mysql_native_password",
        &["mysql-native-password"],
        BOOL_ON_OFF,
        GLOBAL,
        PUBLIC,
        RESTART,
        CRITICAL,
        "This enables the deprecated native password plugin that is disabled by default in 8.4.",
        "Legacy authentication enablement is a high-priority downgrade finding.",
        "mysql:native-auth",
        None,
    ),
    parameter(
        Some("mysqld"),
        "binlog_encryption",
        &["binlog-encryption"],
        BOOL_ON_OFF,
        GLOBAL,
        PUBLIC,
        RESTART,
        HIGH,
        "OFF leaves binary and relay log contents readable to unauthorized filesystem access.",
        "At-rest protection matters because logs often contain sensitive row data.",
        "mysql:replication",
        None,
    ),
    parameter(
        Some("mysqld"),
        "audit_log_file",
        &["audit-log-file"],
        text(4_096),
        GLOBAL,
        METADATA,
        RESTART,
        HIGH,
        "Audit logs can contain sensitive SQL and require a protected destination.",
        "This optional parameter is valid only when Enterprise Audit is installed.",
        "mysql:enterprise-audit",
        Some(MYSQL_ENTERPRISE_AUDIT_CAPABILITY),
    ),
    parameter(
        Some("mysqld"),
        "audit_log_format",
        &["audit-log-format"],
        DatabaseConfigSchemaValueKind::Enumeration {
            values: &["OLD", "NEW", "JSON"],
        },
        GLOBAL,
        PUBLIC,
        RESTART,
        MEDIUM,
        "The selected format changes downstream parsing and evidence handling.",
        "This optional parameter is valid only when Enterprise Audit is installed.",
        "mysql:enterprise-audit",
        Some(MYSQL_ENTERPRISE_AUDIT_CAPABILITY),
    ),
    parameter(
        Some("mysqld"),
        "audit_log_disable",
        &["audit-log-disable"],
        BOOL_ON_OFF,
        GLOBAL,
        PUBLIC,
        RESTART,
        CRITICAL,
        "ON disables auditing for current and future sessions.",
        "Disabling the audit stream is a critical anti-forensics indicator.",
        "mysql:enterprise-audit",
        Some(MYSQL_ENTERPRISE_AUDIT_CAPABILITY),
    )
);

macro_rules! define_grouped_mariadb_parameters {
    (
        $name:ident,
        $mysqld_version_group:literal,
        $mariadb_version_group:literal,
        $mariadbd_version_group:literal;
        $(
            (
                $key:literal,
                $aliases:expr,
                $value_kind:expr,
                $scope:expr,
                $sensitivity:expr,
                $risk:expr,
                $risk_rationale:literal,
                $competition_rationale:literal,
                $reference:literal,
                $capability:expr
            )
        ),+ $(,)?
    ) => {
        const $name: &[DatabaseConfigParameterSchema] = &{
            const BASE: &[DatabaseConfigParameterSchema] = &[
                $(
                    parameter(
                    Some("server"),
                    $key,
                    $aliases,
                    $value_kind,
                    $scope,
                    $sensitivity,
                    RESTART,
                    $risk,
                    $risk_rationale,
                    $competition_rationale,
                    $reference,
                    $capability,
                ),
                )+
            ];
            parameters_for_containers::<{ BASE.len() * 9 }>(
                BASE,
                &[
                    "client-server",
                    "server",
                    "mysqld",
                    $mysqld_version_group,
                    "mariadb",
                    $mariadb_version_group,
                    "mariadbd",
                    $mariadbd_version_group,
                    "galera",
                ],
            )
        };
    };
}

macro_rules! define_mariadb_parameters {
    (
        $name:ident,
        $mysqld_version_group:literal,
        $mariadb_version_group:literal,
        $mariadbd_version_group:literal,
        $row_image_values:expr;
        $($extra:tt),* $(,)?
    ) => {
        define_grouped_mariadb_parameters!(
            $name,
            $mysqld_version_group,
            $mariadb_version_group,
            $mariadbd_version_group;
            (
                "bind_address",
                &["bind-address"],
                text(4_096),
                GLOBAL,
                METADATA,
                HIGH,
                "Empty or broad listener addresses expose MariaDB on additional interfaces.",
                "MariaDB 10.11 and later support exact comma-separated listener lists.",
                "mariadb:system-variables",
                None
            ),
            (
                "port",
                &[],
                DatabaseConfigSchemaValueKind::Integer {
                    minimum_inclusive: 0,
                    maximum_inclusive: 65_535,
                },
                GLOBAL,
                PUBLIC,
                MEDIUM,
                "The port changes the reachable service endpoint.",
                "Responders must see the exact endpoint rather than assume port 3306.",
                "mariadb:system-variables",
                None
            ),
            (
                "skip_networking",
                &["skip-networking"],
                BOOL_ON_OFF,
                GLOBAL,
                PUBLIC,
                HIGH,
                "ON disables TCP and leaves only local transports.",
                "A mistaken value can either expose TCP or cut off remote response access.",
                "mariadb:system-variables",
                None
            ),
            (
                "skip_name_resolve",
                &["skip-name-resolve"],
                BOOL_ON_OFF,
                GLOBAL,
                PUBLIC,
                HIGH,
                "Host grants that use DNS names stop matching when this is enabled.",
                "The hardening switch must not silently lock out responder accounts.",
                "mariadb:system-variables",
                None
            ),
            (
                "require_secure_transport",
                &["require-secure-transport"],
                BOOL_ON_OFF,
                GLOBAL,
                PUBLIC,
                HIGH,
                "OFF permits insecure client transport.",
                "Transport enforcement is a high-value containment control.",
                "mariadb:system-variables",
                None
            ),
            (
                "ssl_ca",
                &["ssl-ca"],
                text(4_096),
                GLOBAL,
                METADATA,
                HIGH,
                "The CA path defines the trust root for encrypted connections.",
                "MariaDB TLS file settings require a server restart when edited in an option file.",
                "mariadb:tls",
                None
            ),
            (
                "ssl_cert",
                &["ssl-cert"],
                text(4_096),
                GLOBAL,
                METADATA,
                HIGH,
                "The certificate path selects the server identity.",
                "Certificate replacement is relevant to interception response.",
                "mariadb:tls",
                None
            ),
            (
                "ssl_key",
                &["ssl-key"],
                text(4_096),
                GLOBAL,
                PRIVATE_KEY,
                CRITICAL,
                "The path identifies private-key material and must not be exposed in previews.",
                "Private-key references require redaction and permission review.",
                "mariadb:tls",
                None
            ),
            (
                "tls_version",
                &["tls-version"],
                trimmed_text(0, 128),
                GLOBAL,
                PUBLIC,
                HIGH,
                "An empty or weak protocol set can disable or weaken TLS.",
                "Available protocols depend on the compiled TLS library, so this is bounded text.",
                "mariadb:tls",
                None
            ),
            (
                "max_connections",
                &["max-connections"],
                DatabaseConfigSchemaValueKind::Integer {
                    minimum_inclusive: 10,
                    maximum_inclusive: 100_000,
                },
                GLOBAL,
                PUBLIC,
                HIGH,
                "Excessive limits can exhaust memory, threads, and file descriptors.",
                "Capacity must preserve an emergency responder login path.",
                "mariadb:system-variables",
                None
            ),
            (
                "max_connect_errors",
                &["max-connect-errors"],
                DatabaseConfigSchemaValueKind::Integer {
                    minimum_inclusive: 1,
                    maximum_inclusive: 4_294_967_295,
                },
                GLOBAL,
                PUBLIC,
                MEDIUM,
                "A low limit can block responders while an excessive limit weakens abuse throttling.",
                "Host blocking is both an availability and brute-force control.",
                "mariadb:system-variables",
                None
            ),
            (
                "connect_timeout",
                &["connect-timeout"],
                DatabaseConfigSchemaValueKind::Integer {
                    minimum_inclusive: 2,
                    maximum_inclusive: 31_536_000,
                },
                GLOBAL,
                PUBLIC,
                MEDIUM,
                "Long authentication waits consume connection slots.",
                "The bound helps identify resource-exhaustion configurations.",
                "mariadb:system-variables",
                None
            ),
            (
                "wait_timeout",
                &["wait-timeout"],
                trimmed_text(1, 20),
                GLOBAL,
                PUBLIC,
                MEDIUM,
                "The documented maximum differs by platform.",
                "Very long idle sessions consume response capacity.",
                "mariadb:system-variables",
                None
            ),
            (
                "max_user_connections",
                &["max-user-connections"],
                DatabaseConfigSchemaValueKind::Integer {
                    minimum_inclusive: -1,
                    maximum_inclusive: 4_294_967_295,
                },
                GLOBAL,
                PUBLIC,
                HIGH,
                "Zero and minus one have special global semantics while low limits can block response accounts.",
                "Per-user limits are important during connection-exhaustion attacks.",
                "mariadb:system-variables",
                None
            ),
            (
                "general_log",
                &["general-log"],
                BOOL_ON_OFF,
                GLOBAL,
                PUBLIC,
                HIGH,
                "The general log can contain sensitive SQL and adds substantial I/O.",
                "It is useful evidence only with a protected destination and retention policy.",
                "mariadb:system-variables",
                None
            ),
            (
                "general_log_file",
                &["general-log-file"],
                text(4_096),
                GLOBAL,
                METADATA,
                HIGH,
                "The destination can expose or overwrite sensitive query evidence.",
                "The exact protected path is part of evidence integrity.",
                "mariadb:system-variables",
                None
            ),
            (
                "log_output",
                &["log-output"],
                DatabaseConfigSchemaValueKind::Enumeration {
                    values: &["FILE", "TABLE", "FILE,TABLE", "TABLE,FILE", "NONE"],
                },
                GLOBAL,
                PUBLIC,
                HIGH,
                "NONE suppresses general and slow logs even when their switches are enabled.",
                "A visually enabled log with no output is a common evidence gap.",
                "mariadb:system-variables",
                None
            ),
            (
                "log_slow_query",
                &["log-slow-query", "slow_query_log", "slow-query-log"],
                BOOL_ON_OFF,
                GLOBAL,
                PUBLIC,
                MEDIUM,
                "Slow-query logging can disclose SQL and consume disk.",
                "The reviewed aliases are explicit; no fuzzy spelling is accepted.",
                "mariadb:system-variables",
                None
            ),
            (
                "log_slow_query_file",
                &[
                    "log-slow-query-file",
                    "slow_query_log_file",
                    "slow-query-log-file",
                ],
                text(4_096),
                GLOBAL,
                METADATA,
                HIGH,
                "The file can contain sensitive SQL and requires protected permissions.",
                "The reviewed compatibility aliases are exact and container scoped.",
                "mariadb:system-variables",
                None
            ),
            (
                "log_error",
                &["log-error"],
                text(4_096),
                GLOBAL,
                METADATA,
                HIGH,
                "An inaccessible error-log path removes critical diagnostics.",
                "Error logs are primary incident-response evidence.",
                "mariadb:system-variables",
                None
            ),
            (
                "local_infile",
                &["local-infile"],
                BOOL_ON_OFF,
                GLOBAL,
                PUBLIC,
                HIGH,
                "MariaDB defaults this file-loading capability to ON.",
                "Unexpected enablement expands the client-file attack surface.",
                "mariadb:system-variables",
                None
            ),
            (
                "secure_file_priv",
                &["secure-file-priv"],
                text(4_096),
                GLOBAL,
                METADATA,
                CRITICAL,
                "An empty or unset value permits access to any server-accessible path.",
                "MariaDB semantics differ from MySQL NULL handling and must stay product specific.",
                "mariadb:system-variables",
                None
            ),
            (
                "init_file",
                &["init-file"],
                text(4_096),
                GLOBAL,
                METADATA,
                CRITICAL,
                "The referenced file executes SQL during startup.",
                "It is a direct privileged persistence location.",
                "mariadb:system-variables",
                None
            ),
            (
                "plugin_dir",
                &["plugin-dir"],
                text(4_096),
                GLOBAL,
                METADATA,
                CRITICAL,
                "A server-writable plugin directory can lead to native-code execution.",
                "The directory is a critical persistence and execution boundary.",
                "mariadb:system-variables",
                None
            ),
            (
                "skip_grant_tables",
                &["skip-grant-tables"],
                text(16),
                GLOBAL,
                PUBLIC,
                CRITICAL,
                "This startup option bypasses the privilege system.",
                "Any occurrence requires immediate review, including valueless option syntax.",
                "mariadb:server-options",
                None
            ),
            (
                "read_only",
                &["read-only"],
                BOOL_ON_OFF,
                GLOBAL,
                PUBLIC,
                HIGH,
                "Privileged users and replication activity retain documented write exceptions.",
                "The UI must not present this as an absolute integrity boundary.",
                "mariadb:system-variables",
                None
            ),
            (
                "log_bin",
                &["log-bin"],
                text(4_096),
                GLOBAL,
                METADATA,
                HIGH,
                "The option enables binary logging and may carry an optional log basename; it is not the read-only runtime Boolean.",
                "Option-file and runtime meanings remain separate while binary-log continuity supports reconstruction.",
                "mariadb:replication",
                None
            ),
            (
                "binlog_format",
                &["binlog-format"],
                DatabaseConfigSchemaValueKind::Enumeration {
                    values: &["ROW", "MIXED", "STATEMENT"],
                },
                GLOBAL,
                PUBLIC,
                HIGH,
                "Statement logging can reproduce nondeterministic changes differently on replicas.",
                "Format changes require explicit topology review.",
                "mariadb:replication",
                None
            ),
            (
                "binlog_row_image",
                &["binlog-row-image"],
                DatabaseConfigSchemaValueKind::Enumeration {
                    values: $row_image_values,
                },
                GLOBAL,
                PUBLIC,
                HIGH,
                "Reduced row images require identical key and column definitions to avoid divergence.",
                "The 11.4-only FULL_NODUP value is version gated by separate schemas.",
                "mariadb:replication",
                None
            ),
            (
                "binlog_expire_logs_seconds",
                &["binlog-expire-logs-seconds"],
                DatabaseConfigSchemaValueKind::Integer {
                    minimum_inclusive: 0,
                    maximum_inclusive: 8_553_600,
                },
                GLOBAL,
                PUBLIC,
                HIGH,
                "Zero can exhaust disk; a short window destroys recovery history and strands lagging replicas.",
                "Retention must cover the competition recovery horizon.",
                "mariadb:replication",
                None
            ),
            (
                "encrypt_binlog",
                &["encrypt-binlog"],
                BOOL_ON_OFF,
                GLOBAL,
                PUBLIC,
                HIGH,
                "OFF leaves binary and relay logs readable to unauthorized filesystem access.",
                "At-rest protection matters because logs often contain sensitive row data.",
                "mariadb:replication",
                None
            ),
            (
                "wsrep_sst_auth",
                &["wsrep-sst-auth"],
                text(4_096),
                GLOBAL,
                SECRET,
                CRITICAL,
                "The value carries Galera SST authentication material in user:password form.",
                "Plain-text SST credentials must never appear in previews, copies, or exports.",
                "mariadb:galera-sst",
                Some(MARIADB_GALERA_CAPABILITY)
            ),
            (
                "server_id",
                &["server-id"],
                DatabaseConfigSchemaValueKind::Integer {
                    minimum_inclusive: 1,
                    maximum_inclusive: 4_294_967_295,
                },
                GLOBAL,
                PUBLIC,
                HIGH,
                "Duplicate identifiers break replication topology identity.",
                "Exact server identity helps detect a redirected or cloned replica.",
                "mariadb:replication",
                None
            ),
            (
                "gtid_strict_mode",
                &["gtid-strict-mode"],
                BOOL_ON_OFF,
                GLOBAL,
                PUBLIC,
                HIGH,
                "Strict mode stops replication on missing or out-of-order GTIDs instead of hiding divergence.",
                "The mode changes whether topology inconsistencies fail visibly.",
                "mariadb:replication",
                None
            ),
            (
                "replication_ssl_verify_server_cert",
                &["replication-ssl-verify-server-cert"],
                BOOL_ON_OFF,
                GLOBAL,
                PUBLIC,
                CRITICAL,
                "OFF permits replication TLS without verifying the source certificate.",
                "A forged source can inject or observe replicated data.",
                "mariadb:replication",
                None
            ),
            (
                "server_audit",
                &["server-audit"],
                DatabaseConfigSchemaValueKind::Enumeration {
                    values: &["OFF", "ON", "FORCE", "FORCE_PLUS_PERMANENT"],
                },
                GLOBAL,
                PUBLIC,
                CRITICAL,
                "OFF disables the plugin while FORCE variants can require successful startup loading.",
                "The option is valid only when the MariaDB Audit Plugin is installed.",
                "mariadb:audit",
                Some(MARIADB_AUDIT_PLUGIN_CAPABILITY)
            ),
            (
                "server_audit_logging",
                &["server-audit-logging"],
                BOOL_ON_OFF,
                GLOBAL,
                PUBLIC,
                CRITICAL,
                "OFF stops audit record generation.",
                "Audit disablement is a critical anti-forensics indicator.",
                "mariadb:audit",
                Some(MARIADB_AUDIT_PLUGIN_CAPABILITY)
            ),
            (
                "server_audit_events",
                &["server-audit-events"],
                text(1_024),
                GLOBAL,
                PUBLIC,
                HIGH,
                "An incorrect event filter can omit relevant evidence.",
                "The empty value means all events and combinations are therefore kept as bounded text.",
                "mariadb:audit",
                Some(MARIADB_AUDIT_PLUGIN_CAPABILITY)
            ),
            (
                "server_audit_output_type",
                &["server-audit-output-type"],
                DatabaseConfigSchemaValueKind::Enumeration {
                    values: &["FILE", "SYSLOG"],
                },
                GLOBAL,
                PUBLIC,
                HIGH,
                "SYSLOG relies on the operating-system daemon being configured to retain records.",
                "The destination type controls where responders must collect evidence.",
                "mariadb:audit",
                Some(MARIADB_AUDIT_PLUGIN_CAPABILITY)
            ),
            (
                "server_audit_file_path",
                &["server-audit-file-path"],
                text(4_096),
                GLOBAL,
                METADATA,
                HIGH,
                "The audit path contains sensitive SQL and requires strict permissions.",
                "Responders must locate and preserve the exact audit file.",
                "mariadb:audit",
                Some(MARIADB_AUDIT_PLUGIN_CAPABILITY)
            ),
            $($extra),*
        );
    };
}

define_mariadb_parameters!(
    MARIADB_10_11_PARAMETERS,
    "mysqld-10.11",
    "mariadb-10.11",
    "mariadbd-10.11",
    &["FULL", "NOBLOB", "MINIMAL"];
);

define_mariadb_parameters!(
    MARIADB_11_4_PARAMETERS,
    "mysqld-11.4",
    "mariadb-11.4",
    "mariadbd-11.4",
    &["FULL", "NOBLOB", "MINIMAL", "FULL_NODUP"];
    (
        "redirect_url",
        &["redirect-url"],
        text(4_096),
        GLOBAL,
        METADATA,
        CRITICAL,
        "A malicious redirect can send compatible clients to an attacker-controlled server.",
        "This parameter is available in the requested 11.4 line but not the 10.11 schema.",
        "mariadb:system-variables",
        None
    ),
    (
        "binlog_ignore_db",
        &["binlog-ignore-db"],
        trimmed_text(1, 512),
        GLOBAL,
        METADATA,
        CRITICAL,
        "Filtered transactions never enter the binary log and cannot reach replicas or PITR.",
        "The option is repeatable; a single comma-separated value is not treated as equivalent.",
        "mariadb:replication",
        None
    ),
    (
        "binlog_gtid_index",
        &["binlog-gtid-index"],
        BOOL_ON_OFF,
        GLOBAL,
        PUBLIC,
        MEDIUM,
        "Disabling the 11.4 GTID index can slow GTID lookup during recovery.",
        "This parameter is version gated to the 11.4 schema.",
        "mariadb:replication",
        None
    )
);

macro_rules! define_postgresql_parameters {
    (
        $name:ident,
        $log_connections_kind:expr,
        $ssl_group_key:literal,
        $ssl_group_rationale:literal;
        $($extra:expr),* $(,)?
    ) => {
        const $name: &[DatabaseConfigParameterSchema] = &[
            parameter(
                None,
                "listen_addresses",
                &[],
                text(4_096),
                CLUSTER,
                METADATA,
                RESTART,
                HIGH,
                "A wildcard or broad list exposes PostgreSQL on additional interfaces.",
                "Listener scope is a first-pass incident-response exposure check.",
                "postgresql:connection",
                None,
            ),
            parameter(
                None,
                "port",
                &[],
                DatabaseConfigSchemaValueKind::Integer {
                    minimum_inclusive: 1,
                    maximum_inclusive: 65_535,
                },
                CLUSTER,
                PUBLIC,
                RESTART,
                MEDIUM,
                "The port changes the reachable server endpoint.",
                "Responders need exact endpoint visibility without assuming port 5432.",
                "postgresql:connection",
                None,
            ),
            parameter(
                None,
                "unix_socket_directories",
                &[],
                text(4_096),
                CLUSTER,
                METADATA,
                RESTART,
                HIGH,
                "Socket placement and directory permissions control local connection exposure.",
                "An empty value removes the local socket response path.",
                "postgresql:connection",
                None,
            ),
            parameter(
                None,
                "max_connections",
                &[],
                trimmed_text(1, 32),
                CLUSTER,
                PUBLIC,
                RESTART,
                HIGH,
                "Increasing the limit increases shared-memory and backend resource demand.",
                "Build-specific bounds are read from pg_settings rather than guessed statically.",
                "postgresql:connection",
                None,
            ),
            parameter(
                None,
                "reserved_connections",
                &[],
                trimmed_text(1, 32),
                CLUSTER,
                PUBLIC,
                RESTART,
                HIGH,
                "The value is relationally bounded by max_connections and superuser reservations.",
                "A dedicated responder role can retain access during connection exhaustion.",
                "postgresql:connection",
                None,
            ),
            parameter(
                None,
                "superuser_reserved_connections",
                &[],
                trimmed_text(1, 32),
                CLUSTER,
                PUBLIC,
                RESTART,
                HIGH,
                "Too few slots remove emergency access while too many starve normal clients.",
                "The relational bound is intentionally deferred to target pg_settings and cross-field validation.",
                "postgresql:connection",
                None,
            ),
            parameter(
                None,
                "authentication_timeout",
                &[],
                trimmed_text(1, 64),
                CLUSTER,
                PUBLIC,
                RELOAD,
                MEDIUM,
                "Long authentication waits permit incomplete clients to hold connection resources.",
                "PostgreSQL time-unit grammar is retained as bounded text for server validation.",
                "postgresql:connection",
                None,
            ),
            parameter(
                None,
                "password_encryption",
                &[],
                DatabaseConfigSchemaValueKind::Enumeration {
                    values: &["scram-sha-256", "md5"],
                },
                SESSION,
                PUBLIC,
                RELOAD,
                HIGH,
                "MD5 password storage is weaker and deprecated in PostgreSQL 18.",
                "The setting affects passwords created or changed afterwards, not existing verifiers.",
                "postgresql:connection",
                None,
            ),
            parameter(
                None,
                "ssl",
                &[],
                BOOL_ON_OFF_LOWER,
                CLUSTER,
                PUBLIC,
                RELOAD,
                HIGH,
                "OFF disables TLS and makes hostssl access rules unusable.",
                "Transport encryption is a primary containment control.",
                "postgresql:connection",
                None,
            ),
            parameter(
                None,
                "ssl_ca_file",
                &[],
                text(4_096),
                CLUSTER,
                METADATA,
                RELOAD,
                HIGH,
                "An empty CA setting prevents client-certificate authority validation.",
                "Trust-root replacement is important response evidence.",
                "postgresql:connection",
                None,
            ),
            parameter(
                None,
                "ssl_cert_file",
                &[],
                text(4_096),
                CLUSTER,
                METADATA,
                RELOAD,
                HIGH,
                "The certificate path selects the identity presented to clients.",
                "Certificate replacement is relevant during interception response.",
                "postgresql:connection",
                None,
            ),
            parameter(
                None,
                "ssl_key_file",
                &[],
                text(4_096),
                CLUSTER,
                PRIVATE_KEY,
                RELOAD,
                CRITICAL,
                "The value identifies private-key material and must not be exposed in previews.",
                "Private-key references require redaction and strict permission review.",
                "postgresql:connection",
                None,
            ),
            parameter(
                None,
                "ssl_crl_file",
                &[],
                text(4_096),
                CLUSTER,
                METADATA,
                RELOAD,
                HIGH,
                "Without a CRL file or directory, revoked client certificates are not rejected from that source.",
                "Revocation state is important during certificate compromise response.",
                "postgresql:connection",
                None,
            ),
            parameter(
                None,
                "ssl_min_protocol_version",
                &[],
                DatabaseConfigSchemaValueKind::Enumeration {
                    values: &["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"],
                },
                CLUSTER,
                PUBLIC,
                RELOAD,
                HIGH,
                "TLSv1 and TLSv1.1 permit obsolete protocol versions.",
                "The minimum is a direct transport-hardening signal.",
                "postgresql:connection",
                None,
            ),
            parameter(
                None,
                "ssl_max_protocol_version",
                &[],
                trimmed_text(0, 16),
                CLUSTER,
                PUBLIC,
                RELOAD,
                MEDIUM,
                "An unnecessarily low maximum disables newer TLS protocols.",
                "The empty value intentionally means no configured maximum.",
                "postgresql:connection",
                None,
            ),
            parameter(
                None,
                $ssl_group_key,
                &[],
                trimmed_text(1, 4_096),
                CLUSTER,
                PUBLIC,
                RELOAD,
                HIGH,
                "Unsupported or weak key-exchange groups can break or weaken TLS negotiation.",
                $ssl_group_rationale,
                "postgresql:connection",
                None,
            ),
            parameter(
                None,
                "logging_collector",
                &[],
                BOOL_ON_OFF_LOWER,
                CLUSTER,
                PUBLIC,
                RESTART,
                HIGH,
                "OFF requires an external stderr collector to preserve server evidence.",
                "The UI must show whether PostgreSQL itself owns file collection.",
                "postgresql:logging",
                None,
            ),
            parameter(
                None,
                "log_destination",
                &[],
                trimmed_text(1, 512),
                CLUSTER,
                PUBLIC,
                RELOAD,
                HIGH,
                "Destinations such as syslog and eventlog require correct operating-system retention.",
                "Comma combinations and platform availability remain bounded text.",
                "postgresql:logging",
                None,
            ),
            parameter(
                None,
                "log_directory",
                &[],
                text(4_096),
                CLUSTER,
                METADATA,
                RELOAD,
                HIGH,
                "The directory controls log permissions, evidence location, and disk pressure.",
                "Responders must locate and preserve the exact directory.",
                "postgresql:logging",
                None,
            ),
            parameter(
                None,
                "log_filename",
                &[],
                text(4_096),
                CLUSTER,
                METADATA,
                RELOAD,
                HIGH,
                "A filename pattern interacts with rotation and can overwrite prior evidence.",
                "The pattern is operational metadata and is not interpreted as a path action.",
                "postgresql:logging",
                None,
            ),
            parameter(
                None,
                "log_connections",
                &[],
                $log_connections_kind,
                SESSION,
                PUBLIC,
                RELOAD,
                MEDIUM,
                "Disabled connection logging reduces authentication timeline evidence.",
                "After a file reload this backend-start parameter affects only new connections.",
                "postgresql:logging",
                None,
            ),
            parameter(
                None,
                "log_disconnections",
                &[],
                BOOL_ON_OFF_LOWER,
                SESSION,
                PUBLIC,
                RELOAD,
                MEDIUM,
                "Disabled disconnection logging leaves connection lifetimes incomplete.",
                "After a file reload this backend-start parameter affects only new connections.",
                "postgresql:logging",
                None,
            ),
            parameter(
                None,
                "log_statement",
                &[],
                DatabaseConfigSchemaValueKind::Enumeration {
                    values: &["none", "ddl", "mod", "all"],
                },
                SESSION,
                PUBLIC,
                RELOAD,
                CRITICAL,
                "PostgreSQL documents that logged statements can contain plaintext passwords and sensitive data.",
                "Evidence value must be balanced against credential disclosure and I/O load.",
                "postgresql:logging",
                None,
            ),
            parameter(
                None,
                "log_min_duration_statement",
                &[],
                DatabaseConfigSchemaValueKind::Integer {
                    minimum_inclusive: -1,
                    maximum_inclusive: 2_147_483_647,
                },
                SESSION,
                PUBLIC,
                RELOAD,
                HIGH,
                "Zero logs every completed statement while minus one disables duration logging.",
                "Aggressive logging can disclose SQL and exhaust disk during an attack.",
                "postgresql:logging",
                None,
            ),
            parameter(
                None,
                "log_parameter_max_length",
                &[],
                DatabaseConfigSchemaValueKind::Integer {
                    minimum_inclusive: -1,
                    maximum_inclusive: 2_147_483_647,
                },
                SESSION,
                PUBLIC,
                RELOAD,
                CRITICAL,
                "Minus one allows complete bind-parameter values to enter statement logs.",
                "Credentials and tokens can otherwise be copied into evidence files.",
                "postgresql:logging",
                None,
            ),
            parameter(
                None,
                "log_parameter_max_length_on_error",
                &[],
                DatabaseConfigSchemaValueKind::Integer {
                    minimum_inclusive: -1,
                    maximum_inclusive: 2_147_483_647,
                },
                SESSION,
                PUBLIC,
                RELOAD,
                CRITICAL,
                "Nonzero values include bind parameters in error paths; minus one permits complete values.",
                "Error-triggering attacks can deliberately push secrets into logs.",
                "postgresql:logging",
                None,
            ),
            parameter(
                None,
                "shared_buffers",
                &[],
                trimmed_text(1, 64),
                CLUSTER,
                PUBLIC,
                RESTART,
                HIGH,
                "An excessive allocation can starve the operating system and response tooling.",
                "Units and build-specific maximums are validated against target pg_settings.",
                "postgresql:resources",
                None,
            ),
            parameter(
                None,
                "work_mem",
                &[],
                trimmed_text(1, 64),
                SESSION,
                PUBLIC,
                RELOAD,
                HIGH,
                "This memory can be allocated repeatedly per sort or hash operation, not merely per connection.",
                "Units and build-specific maximums are validated against target pg_settings.",
                "postgresql:resources",
                None,
            ),
            parameter(
                None,
                "temp_file_limit",
                &[],
                trimmed_text(1, 64),
                SESSION,
                PUBLIC,
                RELOAD,
                HIGH,
                "Minus one permits a process to consume unbounded temporary-file space.",
                "Unit grammar and target bounds remain server validated.",
                "postgresql:resources",
                None,
            ),
            parameter(
                None,
                "statement_timeout",
                &[],
                trimmed_text(1, 64),
                SESSION,
                PUBLIC,
                RELOAD,
                MEDIUM,
                "Zero permits statements to run without a configured time limit.",
                "PostgreSQL unit syntax is retained so values such as 5min remain valid.",
                "postgresql:client",
                None,
            ),
            parameter(
                None,
                "idle_in_transaction_session_timeout",
                &[],
                trimmed_text(1, 64),
                SESSION,
                PUBLIC,
                RELOAD,
                HIGH,
                "Zero permits idle transactions to retain locks and block vacuum indefinitely.",
                "PostgreSQL unit syntax is retained as bounded text.",
                "postgresql:client",
                None,
            ),
            parameter(
                None,
                "data_directory",
                &[],
                text(4_096),
                CLUSTER,
                METADATA,
                RESTART,
                CRITICAL,
                "A changed path can start a different data cluster.",
                "The data root is a critical identity and recovery boundary.",
                "postgresql:file-locations",
                None,
            ),
            parameter(
                None,
                "hba_file",
                &[],
                text(4_096),
                CLUSTER,
                METADATA,
                RESTART,
                CRITICAL,
                "A changed path can silently select a different authentication policy.",
                "Authentication review must follow the exact referenced file.",
                "postgresql:file-locations",
                None,
            ),
            parameter(
                None,
                "ident_file",
                &[],
                text(4_096),
                CLUSTER,
                METADATA,
                RESTART,
                HIGH,
                "A changed path can select unexpected external-to-database identity mappings.",
                "Identity-map review must follow the exact referenced file.",
                "postgresql:file-locations",
                None,
            ),
            parameter(
                None,
                "wal_level",
                &[],
                DatabaseConfigSchemaValueKind::Enumeration {
                    values: &["minimal", "replica", "logical"],
                },
                CLUSTER,
                PUBLIC,
                RESTART,
                CRITICAL,
                "minimal removes information required for archive recovery and standby operation.",
                "WAL capability determines which recovery and replication evidence exists.",
                "postgresql:wal",
                None,
            ),
            parameter(
                None,
                "max_wal_senders",
                &[],
                trimmed_text(1, 32),
                CLUSTER,
                PUBLIC,
                RESTART,
                HIGH,
                "Zero disables WAL streaming while high values reserve additional connection resources.",
                "Build-specific bounds are read from target pg_settings.",
                "postgresql:replication",
                None,
            ),
            parameter(
                None,
                "max_replication_slots",
                &[],
                trimmed_text(1, 32),
                CLUSTER,
                PUBLIC,
                RESTART,
                HIGH,
                "Abandoned slots can retain WAL until the filesystem is exhausted.",
                "Build-specific bounds and live slot use require target inspection.",
                "postgresql:replication",
                None,
            ),
            parameter(
                None,
                "primary_conninfo",
                &[],
                text(16_384),
                CLUSTER,
                SECRET,
                RELOAD,
                CRITICAL,
                "The connection string can embed a password and redirect a standby to a hostile primary.",
                "The entire value stays redacted rather than attempting partial secret parsing.",
                "postgresql:replication",
                None,
            ),
            parameter(
                None,
                "primary_slot_name",
                &[],
                text(512),
                CLUSTER,
                METADATA,
                RELOAD,
                HIGH,
                "A wrong or abandoned slot can cause a WAL gap or unbounded retention.",
                "Slot identity is topology metadata that must be correlated with the primary.",
                "postgresql:replication",
                None,
            ),
            parameter(
                None,
                "synchronous_standby_names",
                &[],
                text(4_096),
                CLUSTER,
                METADATA,
                RELOAD,
                HIGH,
                "A wrong quorum can block every commit or silently remove synchronous durability.",
                "The grammar is kept as bounded text for server validation.",
                "postgresql:replication",
                None,
            ),
            parameter(
                None,
                "archive_mode",
                &[],
                DatabaseConfigSchemaValueKind::Enumeration {
                    values: &["off", "on", "always"],
                },
                CLUSTER,
                PUBLIC,
                RESTART,
                HIGH,
                "off disables WAL archiving and point-in-time recovery continuity.",
                "always also archives during standby recovery and requires deliberate topology design.",
                "postgresql:wal",
                None,
            ),
            parameter(
                None,
                "archive_command",
                &[],
                text(65_536),
                CLUSTER,
                SECRET,
                RELOAD,
                CRITICAL,
                "PostgreSQL executes this shell command as the database operating-system account.",
                "It is a direct command-execution boundary and can also contain remote credentials.",
                "postgresql:wal",
                None,
            ),
            parameter(
                None,
                "archive_library",
                &[],
                text(4_096),
                CLUSTER,
                METADATA,
                RELOAD,
                CRITICAL,
                "The value selects native code loaded into the server for WAL archiving.",
                "It is mutually exclusive with archive_command and forms a code-loading boundary.",
                "postgresql:wal",
                None,
            ),
            parameter(
                None,
                "fsync",
                &[],
                BOOL_ON_OFF_LOWER,
                CLUSTER,
                PUBLIC,
                RELOAD,
                CRITICAL,
                "OFF can cause irrecoverable corruption after an operating-system or hardware crash.",
                "The setting requires the strongest integrity warning.",
                "postgresql:wal",
                None,
            ),
            parameter(
                None,
                "full_page_writes",
                &[],
                BOOL_ON_OFF_LOWER,
                CLUSTER,
                PUBLIC,
                RELOAD,
                CRITICAL,
                "OFF increases the risk of unrecoverable partial-page corruption after a crash.",
                "The setting directly affects WAL recovery safety.",
                "postgresql:wal",
                None,
            ),
            parameter(
                None,
                "synchronous_commit",
                &[],
                DatabaseConfigSchemaValueKind::Enumeration {
                    values: &["remote_apply", "on", "remote_write", "local", "off"],
                },
                SESSION,
                PUBLIC,
                RELOAD,
                HIGH,
                "off can lose recently acknowledged transactions after a crash.",
                "The durability tradeoff must remain visible during containment.",
                "postgresql:wal",
                None,
            ),
            parameter(
                None,
                "shared_preload_libraries",
                &[],
                text(16_384),
                CLUSTER,
                METADATA,
                RESTART,
                CRITICAL,
                "Listed native libraries load at server startup and can execute arbitrary extension code.",
                "This is a primary native-code persistence location.",
                "postgresql:client",
                None,
            ),
            parameter(
                None,
                "dynamic_library_path",
                &[],
                text(16_384),
                SESSION,
                METADATA,
                RELOAD,
                CRITICAL,
                "The path changes where LOAD and C-language functions search for native libraries.",
                "Unexpected directories can redirect trusted names to hostile code.",
                "postgresql:client",
                None,
            ),
            parameter(
                None,
                "session_replication_role",
                &[],
                DatabaseConfigSchemaValueKind::Enumeration {
                    values: &["origin", "replica", "local"],
                },
                SESSION,
                PUBLIC,
                RELOAD,
                CRITICAL,
                "replica suppresses ordinary triggers and rules, including foreign-key checks.",
                "A global file default can silently permit inconsistent writes in new or reloaded sessions.",
                "postgresql:client",
                None,
            ),
            parameter(
                None,
                "allow_system_table_mods",
                &[],
                BOOL_ON_OFF_LOWER,
                CLUSTER,
                PUBLIC,
                RESTART,
                CRITICAL,
                "ON permits risky system-catalog structure changes and can cause irretrievable data loss.",
                "This developer switch should be exceptional on a competition server.",
                "postgresql:developer",
                None,
            ),
            parameter(
                None,
                "zero_damaged_pages",
                &[],
                BOOL_ON_OFF_LOWER,
                SESSION,
                PUBLIC,
                RELOAD,
                CRITICAL,
                "ON zeros damaged pages in memory and destroys every row on those pages.",
                "It is an explicit last-resort recovery control, never a routine repair switch.",
                "postgresql:developer",
                None,
            ),
            $(
                $extra,
            )*
        ];
    };
}

define_postgresql_parameters!(
    POSTGRESQL_16_17_PARAMETERS,
    BOOL_ON_OFF_LOWER,
    "ssl_ecdh_curve",
    "PostgreSQL 16 and 17 accept one curve name; PostgreSQL 18 replaces it with ssl_groups.";
);

define_postgresql_parameters!(
    POSTGRESQL_18_PARAMETERS,
    text(1_024),
    "ssl_groups",
    "PostgreSQL 18 accepts a colon-separated group list and no longer uses ssl_ecdh_curve.";
    parameter(
        None,
        "oauth_validator_libraries",
        &[],
        text(16_384),
        CLUSTER,
        METADATA,
        RELOAD,
        CRITICAL,
        "PostgreSQL loads listed third-party OAuth validator libraries on demand during login.",
        "The PostgreSQL 18-only parameter requires OAuth build support and trusted validator code.",
        "postgresql:connection",
        Some(POSTGRESQL_OAUTH_CAPABILITY),
    )
);

pub const MYSQL_OPTION_FILE_8_0_SCHEMA: DatabaseConfigSchema = DatabaseConfigSchema {
    display_label: "MySQL option file 8.0 partial security schema",
    version_label: ">=8.0.11, <8.1.0",
    binding: DatabaseConfigSchemaBinding {
        product: DatabaseConfigProduct::MySql,
        versions: DatabaseConfigVersionSelector::HalfOpen {
            minimum_inclusive: DatabaseConfigVersion::new(8, 0, 11),
            maximum_exclusive: DatabaseConfigVersion::new(8, 1, 0),
        },
        edition_key: None,
        component: DatabaseConfigComponent::Server,
        artifact_key: "mysql-option-file",
    },
    completeness: DatabaseConfigSchemaCompleteness::Partial,
    parameters: MYSQL_8_0_PARAMETERS,
    references: MYSQL_8_0_REFERENCES,
};

pub const MYSQL_OPTION_FILE_8_4_SCHEMA: DatabaseConfigSchema = DatabaseConfigSchema {
    display_label: "MySQL option file 8.4 partial security schema",
    version_label: ">=8.4.0, <8.5.0",
    binding: DatabaseConfigSchemaBinding {
        product: DatabaseConfigProduct::MySql,
        versions: DatabaseConfigVersionSelector::HalfOpen {
            minimum_inclusive: DatabaseConfigVersion::new(8, 4, 0),
            maximum_exclusive: DatabaseConfigVersion::new(8, 5, 0),
        },
        edition_key: None,
        component: DatabaseConfigComponent::Server,
        artifact_key: "mysql-option-file",
    },
    completeness: DatabaseConfigSchemaCompleteness::Partial,
    parameters: MYSQL_8_4_PARAMETERS,
    references: MYSQL_8_4_REFERENCES,
};

pub const MARIADB_OPTION_FILE_10_11_SCHEMA: DatabaseConfigSchema = DatabaseConfigSchema {
    display_label: "MariaDB option file 10.11 partial security schema",
    version_label: ">=10.11.0, <10.12.0",
    binding: DatabaseConfigSchemaBinding {
        product: DatabaseConfigProduct::MariaDb,
        versions: DatabaseConfigVersionSelector::HalfOpen {
            minimum_inclusive: DatabaseConfigVersion::new(10, 11, 0),
            maximum_exclusive: DatabaseConfigVersion::new(10, 12, 0),
        },
        edition_key: None,
        component: DatabaseConfigComponent::Server,
        artifact_key: "mariadb-option-file",
    },
    completeness: DatabaseConfigSchemaCompleteness::Partial,
    parameters: MARIADB_10_11_PARAMETERS,
    references: MARIADB_REFERENCES,
};

pub const MARIADB_OPTION_FILE_11_4_SCHEMA: DatabaseConfigSchema = DatabaseConfigSchema {
    display_label: "MariaDB option file 11.4 partial security schema",
    version_label: ">=11.4.0, <11.5.0",
    binding: DatabaseConfigSchemaBinding {
        product: DatabaseConfigProduct::MariaDb,
        versions: DatabaseConfigVersionSelector::HalfOpen {
            minimum_inclusive: DatabaseConfigVersion::new(11, 4, 0),
            maximum_exclusive: DatabaseConfigVersion::new(11, 5, 0),
        },
        edition_key: None,
        component: DatabaseConfigComponent::Server,
        artifact_key: "mariadb-option-file",
    },
    completeness: DatabaseConfigSchemaCompleteness::Partial,
    parameters: MARIADB_11_4_PARAMETERS,
    references: MARIADB_REFERENCES,
};

pub const POSTGRESQL_MAIN_16_SCHEMA: DatabaseConfigSchema = DatabaseConfigSchema {
    display_label: "PostgreSQL main configuration 16 partial security schema",
    version_label: ">=16.0.0, <17.0.0",
    binding: DatabaseConfigSchemaBinding {
        product: DatabaseConfigProduct::PostgreSql,
        versions: DatabaseConfigVersionSelector::HalfOpen {
            minimum_inclusive: DatabaseConfigVersion::new(16, 0, 0),
            maximum_exclusive: DatabaseConfigVersion::new(17, 0, 0),
        },
        edition_key: None,
        component: DatabaseConfigComponent::Server,
        artifact_key: "postgresql-main",
    },
    completeness: DatabaseConfigSchemaCompleteness::Partial,
    parameters: POSTGRESQL_16_17_PARAMETERS,
    references: POSTGRESQL_16_REFERENCES,
};

pub const POSTGRESQL_MAIN_17_SCHEMA: DatabaseConfigSchema = DatabaseConfigSchema {
    display_label: "PostgreSQL main configuration 17 partial security schema",
    version_label: ">=17.0.0, <18.0.0",
    binding: DatabaseConfigSchemaBinding {
        product: DatabaseConfigProduct::PostgreSql,
        versions: DatabaseConfigVersionSelector::HalfOpen {
            minimum_inclusive: DatabaseConfigVersion::new(17, 0, 0),
            maximum_exclusive: DatabaseConfigVersion::new(18, 0, 0),
        },
        edition_key: None,
        component: DatabaseConfigComponent::Server,
        artifact_key: "postgresql-main",
    },
    completeness: DatabaseConfigSchemaCompleteness::Partial,
    parameters: POSTGRESQL_16_17_PARAMETERS,
    references: POSTGRESQL_17_REFERENCES,
};

pub const POSTGRESQL_MAIN_18_SCHEMA: DatabaseConfigSchema = DatabaseConfigSchema {
    display_label: "PostgreSQL main configuration 18 partial security schema",
    version_label: ">=18.0.0, <19.0.0",
    binding: DatabaseConfigSchemaBinding {
        product: DatabaseConfigProduct::PostgreSql,
        versions: DatabaseConfigVersionSelector::HalfOpen {
            minimum_inclusive: DatabaseConfigVersion::new(18, 0, 0),
            maximum_exclusive: DatabaseConfigVersion::new(19, 0, 0),
        },
        edition_key: None,
        component: DatabaseConfigComponent::Server,
        artifact_key: "postgresql-main",
    },
    completeness: DatabaseConfigSchemaCompleteness::Partial,
    parameters: POSTGRESQL_18_PARAMETERS,
    references: POSTGRESQL_18_REFERENCES,
};

#[cfg(test)]
const OPEN_DATABASE_CONFIG_SCHEMAS: &[DatabaseConfigSchema] = &[
    MYSQL_OPTION_FILE_8_0_SCHEMA,
    MYSQL_OPTION_FILE_8_4_SCHEMA,
    MARIADB_OPTION_FILE_10_11_SCHEMA,
    MARIADB_OPTION_FILE_11_4_SCHEMA,
    POSTGRESQL_MAIN_16_SCHEMA,
    POSTGRESQL_MAIN_17_SCHEMA,
    POSTGRESQL_MAIN_18_SCHEMA,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database_config_schema::{
        DatabaseConfigParameterLocator, DatabaseConfigSchemaCatalog,
        DatabaseConfigSchemaLookupError, DatabaseConfigSchemaTarget,
    };

    fn target(
        product: DatabaseConfigProduct,
        version: DatabaseConfigVersion,
        artifact_key: &'static str,
    ) -> DatabaseConfigSchemaTarget<'static> {
        DatabaseConfigSchemaTarget {
            product,
            version,
            edition_key: None,
            component: DatabaseConfigComponent::Server,
            artifact_key,
        }
    }

    const fn locator(
        container_path: Option<&'static str>,
        key: &'static str,
    ) -> DatabaseConfigParameterLocator<'static> {
        DatabaseConfigParameterLocator {
            container_path,
            key,
        }
    }

    #[test]
    fn reviewed_catalog_constructs_and_every_pack_stays_partial() {
        let catalog = DatabaseConfigSchemaCatalog::new(OPEN_DATABASE_CONFIG_SCHEMAS).unwrap();
        assert_eq!(catalog.schemas().len(), 7);
        assert!(
            catalog
                .schemas()
                .iter()
                .all(|schema| !schema.has_complete_artifact_coverage())
        );
        assert!(catalog.schemas().iter().all(|schema| {
            schema
                .references
                .iter()
                .all(|reference| reference.url.starts_with("https://"))
        }));
    }

    #[test]
    fn half_open_product_versions_do_not_bleed_across_boundaries() {
        let catalog = DatabaseConfigSchemaCatalog::new(OPEN_DATABASE_CONFIG_SCHEMAS).unwrap();

        for version in [
            DatabaseConfigVersion::new(8, 0, 11),
            DatabaseConfigVersion::new(8, 0, 99),
        ] {
            let mysql_80 = catalog
                .lookup(target(
                    DatabaseConfigProduct::MySql,
                    version,
                    "mysql-option-file",
                ))
                .unwrap();
            assert_eq!(mysql_80.version_label, ">=8.0.11, <8.1.0");
        }
        assert_eq!(
            catalog.lookup(target(
                DatabaseConfigProduct::MySql,
                DatabaseConfigVersion::new(8, 0, 10),
                "mysql-option-file",
            )),
            Err(DatabaseConfigSchemaLookupError::VersionMismatch)
        );
        for version in [
            DatabaseConfigVersion::new(8, 1, 0),
            DatabaseConfigVersion::new(8, 2, 7),
            DatabaseConfigVersion::new(8, 3, 99),
        ] {
            assert_eq!(
                catalog.lookup(target(
                    DatabaseConfigProduct::MySql,
                    version,
                    "mysql-option-file",
                )),
                Err(DatabaseConfigSchemaLookupError::VersionMismatch)
            );
        }
        let mysql_84 = catalog
            .lookup(target(
                DatabaseConfigProduct::MySql,
                DatabaseConfigVersion::new(8, 4, 0),
                "mysql-option-file",
            ))
            .unwrap();
        assert_eq!(mysql_84.version_label, ">=8.4.0, <8.5.0");
        assert_eq!(
            catalog.lookup(target(
                DatabaseConfigProduct::MySql,
                DatabaseConfigVersion::new(8, 5, 0),
                "mysql-option-file",
            )),
            Err(DatabaseConfigSchemaLookupError::VersionMismatch)
        );

        assert!(
            catalog
                .lookup(target(
                    DatabaseConfigProduct::MariaDb,
                    DatabaseConfigVersion::new(10, 11, 9),
                    "mariadb-option-file",
                ))
                .is_ok()
        );
        assert_eq!(
            catalog.lookup(target(
                DatabaseConfigProduct::MariaDb,
                DatabaseConfigVersion::new(10, 12, 0),
                "mariadb-option-file",
            )),
            Err(DatabaseConfigSchemaLookupError::VersionMismatch)
        );
        assert!(
            catalog
                .lookup(target(
                    DatabaseConfigProduct::PostgreSql,
                    DatabaseConfigVersion::new(18, 9, 0),
                    "postgresql-main",
                ))
                .is_ok()
        );
        assert_eq!(
            catalog.lookup(target(
                DatabaseConfigProduct::PostgreSql,
                DatabaseConfigVersion::new(19, 0, 0),
                "postgresql-main",
            )),
            Err(DatabaseConfigSchemaLookupError::VersionMismatch)
        );
    }

    #[test]
    fn aliases_and_vendor_container_paths_are_isolated() {
        let mysql = &MYSQL_OPTION_FILE_8_4_SCHEMA;
        for container in ["mysqld", "server", "mysqld-8.4"] {
            assert_eq!(
                mysql
                    .parameter(locator(Some(container), "bind-address"))
                    .unwrap()
                    .canonical_key,
                "bind_address"
            );
            assert_eq!(
                mysql
                    .parameter(locator(Some(container), "skip_grant_tables"))
                    .unwrap()
                    .risk,
                CRITICAL
            );
        }
        for rejected in [
            locator(None, "bind_address"),
            locator(Some("mysqld-8.0"), "bind_address"),
            locator(Some("mysqld"), "Bind-Address"),
            locator(Some("mysqld"), "bind__address"),
        ] {
            assert!(mysql.parameter(rejected).is_none());
        }
        assert!(
            mysql
                .parameter(locator(Some("MYSQLD"), "bind_address"))
                .is_some()
        );

        let mariadb = &MARIADB_OPTION_FILE_11_4_SCHEMA;
        for container in [
            "server",
            "client-server",
            "mysqld",
            "mysqld-11.4",
            "mariadb",
            "mariadb-11.4",
            "mariadbd",
            "mariadbd-11.4",
            "galera",
        ] {
            assert!(
                mariadb
                    .parameter(locator(Some(container), "slow-query-log"))
                    .is_some()
            );
        }
        assert!(
            mariadb
                .parameter(locator(Some("MARIADBD-11.4"), "slow-query-log"))
                .is_some()
        );
        assert!(
            mariadb
                .parameter(locator(Some("mariadb-10.11"), "log_slow_query"))
                .is_none()
        );
        assert!(
            mariadb
                .parameter(locator(Some("mariadbd-10.11"), "log_slow_query"))
                .is_none()
        );

        assert!(
            POSTGRESQL_MAIN_18_SCHEMA
                .parameter(locator(None, "port"))
                .is_some()
        );
        assert!(
            POSTGRESQL_MAIN_18_SCHEMA
                .parameter(locator(Some("postgresql"), "port"))
                .is_none()
        );
    }

    #[test]
    fn high_risk_and_optional_plugin_metadata_fail_visible() {
        let mysql_skip = MYSQL_OPTION_FILE_8_4_SCHEMA
            .parameter(locator(Some("mysqld"), "skip_grant_tables"))
            .unwrap();
        assert_eq!(mysql_skip.risk, CRITICAL);
        assert_eq!(mysql_skip.activation, RESTART);

        let mysql_audit = MYSQL_OPTION_FILE_8_4_SCHEMA
            .parameter(locator(Some("mysqld"), "audit_log_file"))
            .unwrap();
        assert_eq!(
            mysql_audit.required_capability,
            Some(MYSQL_ENTERPRISE_AUDIT_CAPABILITY)
        );
        assert_eq!(mysql_audit.sensitivity, METADATA);

        let mariadb_audit = MARIADB_OPTION_FILE_10_11_SCHEMA
            .parameter(locator(Some("mariadb-10.11"), "server_audit_logging"))
            .unwrap();
        assert_eq!(
            mariadb_audit.required_capability,
            Some(MARIADB_AUDIT_PLUGIN_CAPABILITY)
        );
        assert_eq!(mariadb_audit.risk, CRITICAL);

        let primary_conninfo = POSTGRESQL_MAIN_18_SCHEMA
            .parameter(locator(None, "primary_conninfo"))
            .unwrap();
        assert_eq!(primary_conninfo.sensitivity, SECRET);
        let ssl_key = POSTGRESQL_MAIN_18_SCHEMA
            .parameter(locator(None, "ssl_key_file"))
            .unwrap();
        assert_eq!(ssl_key.sensitivity, PRIVATE_KEY);
    }

    #[test]
    fn galera_sst_credentials_are_secret_in_every_reviewed_server_group() {
        for (schema, version_groups) in [
            (
                &MARIADB_OPTION_FILE_10_11_SCHEMA,
                ["mysqld-10.11", "mariadb-10.11", "mariadbd-10.11"],
            ),
            (
                &MARIADB_OPTION_FILE_11_4_SCHEMA,
                ["mysqld-11.4", "mariadb-11.4", "mariadbd-11.4"],
            ),
        ] {
            for container in [
                "client-server",
                "server",
                "mysqld",
                "mariadb",
                "mariadbd",
                "galera",
            ]
            .into_iter()
            .chain(version_groups)
            {
                for key in ["wsrep_sst_auth", "wsrep-sst-auth"] {
                    let parameter = schema
                        .parameter(locator(Some(container), key))
                        .expect("reviewed Galera SST credential must be recognized");
                    assert_eq!(parameter.sensitivity, SECRET);
                    assert_eq!(parameter.activation, RESTART);
                    assert_eq!(parameter.risk, CRITICAL);
                    assert_eq!(
                        parameter.required_capability,
                        Some(MARIADB_GALERA_CAPABILITY)
                    );
                    assert_eq!(parameter.official_reference_id, "mariadb:galera-sst");
                }
            }
            assert!(schema.references.iter().any(|reference| {
                reference.id == "mariadb:galera-sst"
                    && reference.url
                        == "https://mariadb.com/docs/galera-cluster/high-availability/state-snapshot-transfers-ssts-in-galera-cluster/mariadb-backup-sst-method"
            }));
        }
    }

    #[test]
    fn file_activation_never_claims_runtime_dynamic_application() {
        for (schema, container, key) in [
            (&MYSQL_OPTION_FILE_8_4_SCHEMA, Some("mysqld"), "general_log"),
            (
                &MARIADB_OPTION_FILE_11_4_SCHEMA,
                Some("mariadb"),
                "require_secure_transport",
            ),
        ] {
            assert_eq!(
                schema
                    .parameter(locator(container, key))
                    .unwrap()
                    .activation,
                RESTART
            );
        }

        let new_backend = POSTGRESQL_MAIN_18_SCHEMA
            .parameter(locator(None, "log_connections"))
            .unwrap();
        assert_eq!(new_backend.activation, RELOAD);
        assert!(
            new_backend
                .competition_rationale
                .contains("new connections")
        );
        assert_eq!(
            POSTGRESQL_MAIN_18_SCHEMA
                .parameter(locator(None, "listen_addresses"))
                .unwrap()
                .activation,
            RESTART
        );
    }

    #[test]
    fn postgresql_18_differences_are_version_scoped() {
        let pg17 = &POSTGRESQL_MAIN_17_SCHEMA;
        let pg18 = &POSTGRESQL_MAIN_18_SCHEMA;

        assert!(pg17.parameter(locator(None, "ssl_ecdh_curve")).is_some());
        assert!(pg17.parameter(locator(None, "ssl_groups")).is_none());
        assert!(pg18.parameter(locator(None, "ssl_ecdh_curve")).is_none());
        assert!(pg18.parameter(locator(None, "ssl_groups")).is_some());
        assert!(matches!(
            pg17.parameter(locator(None, "log_connections"))
                .unwrap()
                .value_kind,
            DatabaseConfigSchemaValueKind::Boolean { .. }
        ));
        assert!(matches!(
            pg18.parameter(locator(None, "log_connections"))
                .unwrap()
                .value_kind,
            DatabaseConfigSchemaValueKind::Text { .. }
        ));
        let oauth = pg18
            .parameter(locator(None, "oauth_validator_libraries"))
            .unwrap();
        assert_eq!(oauth.required_capability, Some(POSTGRESQL_OAUTH_CAPABILITY));
        assert!(
            POSTGRESQL_MAIN_17_SCHEMA
                .parameter(locator(None, "oauth_validator_libraries"))
                .is_none()
        );
    }
}
