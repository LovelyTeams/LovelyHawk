//! Reviewed, partial schemas for domestic and competition-relevant databases.
//!
//! These packs only annotate keys proven by the linked official references.
//! `Partial` deliberately leaves every unlisted key visible and unvalidated.
//! In particular, the DM8 manuals linked here are not pinned to an exact build:
//! their packs are inspect/annotate-only metadata and must never authorize
//! generation or automatic application without the per-parameter capability.
//! DM archive, MAL, watcher, and monitor files are omitted because their safety
//! depends on whole-cluster graph invariants that a scalar schema cannot prove.

use crate::database_config::{DatabaseConfigComponent, DatabaseConfigProduct};
use crate::database_config_schema::{
    DatabaseConfigDocumentedDefault, DatabaseConfigParameterSchema, DatabaseConfigSchema,
    DatabaseConfigSchemaActivation, DatabaseConfigSchemaBinding, DatabaseConfigSchemaCompleteness,
    DatabaseConfigSchemaReference, DatabaseConfigSchemaRisk, DatabaseConfigSchemaScope,
    DatabaseConfigSchemaSensitivity, DatabaseConfigSchemaValueKind,
    DatabaseConfigTextNormalization, DatabaseConfigVersion, DatabaseConfigVersionSelector,
};

const fn text(
    minimum_bytes: usize,
    maximum_bytes: usize,
    normalization: DatabaseConfigTextNormalization,
) -> DatabaseConfigSchemaValueKind {
    DatabaseConfigSchemaValueKind::Text {
        minimum_bytes,
        maximum_bytes,
        normalization,
    }
}

macro_rules! parameter {
    (
        $container:expr,
        $key:literal,
        $kind:expr,
        $scope:ident,
        $sensitivity:ident,
        $activation:ident,
        $risk:ident,
        $risk_rationale:literal,
        $competition_rationale:literal,
        $reference:literal,
        $capability:expr
    ) => {
        parameter!(
            $container,
            $key,
            $kind,
            $scope,
            $sensitivity,
            $activation,
            $risk,
            $risk_rationale,
            $competition_rationale,
            $reference,
            $capability,
            None
        )
    };
    (
        $container:expr,
        $key:literal,
        $kind:expr,
        $scope:ident,
        $sensitivity:ident,
        $activation:ident,
        $risk:ident,
        $risk_rationale:literal,
        $competition_rationale:literal,
        $reference:literal,
        $capability:expr,
        $documented_default:expr
    ) => {
        DatabaseConfigParameterSchema {
            container_path: $container,
            canonical_key: $key,
            exact_aliases: &[],
            value_kind: $kind,
            documented_default: $documented_default,
            scope: DatabaseConfigSchemaScope::$scope,
            sensitivity: DatabaseConfigSchemaSensitivity::$sensitivity,
            activation: DatabaseConfigSchemaActivation::$activation,
            risk: DatabaseConfigSchemaRisk::$risk,
            risk_rationale: $risk_rationale,
            competition_rationale: $competition_rationale,
            official_reference_id: $reference,
            required_capability: $capability,
        }
    };
}

const TIDB_REFERENCES: &[DatabaseConfigSchemaReference] = &[
    DatabaseConfigSchemaReference {
        id: "pingcap:tidb-8.5-config",
        title: "TiDB 8.5 configuration file",
        url: "https://docs.pingcap.com/tidb/v8.5/tidb-configuration-file/",
    },
    DatabaseConfigSchemaReference {
        id: "pingcap:tidb-8.5.7-release",
        title: "TiDB 8.5.7 release notes",
        url: "https://docs.pingcap.com/tidb/stable/release-8.5.7/",
    },
    DatabaseConfigSchemaReference {
        id: "pingcap:tidb-8.5.7-config-tag",
        title: "TiDB 8.5.7 tagged configuration template",
        url: "https://github.com/pingcap/tidb/blob/v8.5.7/pkg/config/config.toml.example",
    },
];

const TIKV_REFERENCES: &[DatabaseConfigSchemaReference] = &[
    DatabaseConfigSchemaReference {
        id: "pingcap:tikv-8.5-config",
        title: "TiKV 8.5 configuration file",
        url: "https://docs.pingcap.com/tidb/v8.5/tikv-configuration-file/",
    },
    DatabaseConfigSchemaReference {
        id: "pingcap:tidb-8.5.7-release",
        title: "TiDB 8.5.7 release notes",
        url: "https://docs.pingcap.com/tidb/stable/release-8.5.7/",
    },
    DatabaseConfigSchemaReference {
        id: "pingcap:tikv-8.5.7-config-tag",
        title: "TiKV 8.5.7 tagged configuration template",
        url: "https://github.com/tikv/tikv/blob/v8.5.7/etc/config-template.toml",
    },
];

const PD_REFERENCES: &[DatabaseConfigSchemaReference] = &[
    DatabaseConfigSchemaReference {
        id: "pingcap:pd-8.5-config",
        title: "PD 8.5 configuration file",
        url: "https://docs.pingcap.com/tidb/v8.5/pd-configuration-file/",
    },
    DatabaseConfigSchemaReference {
        id: "pingcap:tidb-8.5.7-release",
        title: "TiDB 8.5.7 release notes",
        url: "https://docs.pingcap.com/tidb/stable/release-8.5.7/",
    },
    DatabaseConfigSchemaReference {
        id: "pingcap:pd-8.5.7-config-tag",
        title: "PD 8.5.7 tagged configuration",
        url: "https://github.com/tikv/pd/blob/v8.5.7/conf/config.toml",
    },
];

const TIDB_8_5_7_PARAMETERS: &[DatabaseConfigParameterSchema] = &[
    parameter!(
        None,
        "host",
        text(1, 255, DatabaseConfigTextNormalization::TrimAsciiWhitespace),
        Instance,
        OperationalMetadata,
        RollingRestart,
        High,
        "A wildcard address exposes the SQL listener on every interface.",
        "Listener exposure is a first-line incident-response check.",
        "pingcap:tidb-8.5-config",
        None
    ),
    parameter!(
        None,
        "port",
        DatabaseConfigSchemaValueKind::Integer {
            minimum_inclusive: 1,
            maximum_inclusive: 65_535,
        },
        Instance,
        OperationalMetadata,
        RollingRestart,
        Medium,
        "Changing the SQL port changes the reachable service endpoint.",
        "The exact listener port is required during containment and recovery.",
        "pingcap:tidb-8.5-config",
        None
    ),
    parameter!(
        Some("status"),
        "status-host",
        text(1, 255, DatabaseConfigTextNormalization::TrimAsciiWhitespace),
        Instance,
        OperationalMetadata,
        RollingRestart,
        High,
        "A wildcard status address exposes diagnostics and profiling endpoints.",
        "Status-plane exposure commonly reveals operational evidence.",
        "pingcap:tidb-8.5-config",
        None
    ),
    parameter!(
        Some("status"),
        "status-port",
        DatabaseConfigSchemaValueKind::Integer {
            minimum_inclusive: 1,
            maximum_inclusive: 65_535,
        },
        Instance,
        OperationalMetadata,
        RollingRestart,
        Medium,
        "Changing the status port changes the diagnostic endpoint.",
        "The status endpoint must be distinguished from the SQL listener.",
        "pingcap:tidb-8.5-config",
        None
    ),
    parameter!(
        Some("security"),
        "ssl-ca",
        text(0, 4_096, DatabaseConfigTextNormalization::Preserve),
        Instance,
        OperationalMetadata,
        RollingRestart,
        High,
        "An empty or wrong CA path can leave client TLS unavailable or untrusted.",
        "Certificate-chain state is central to transport incident triage.",
        "pingcap:tidb-8.5-config",
        None
    ),
    parameter!(
        Some("security"),
        "ssl-cert",
        text(0, 4_096, DatabaseConfigTextNormalization::Preserve),
        Instance,
        OperationalMetadata,
        RollingRestart,
        High,
        "A wrong certificate path can disable secure client connections.",
        "The certificate reference must remain paired with its key and CA.",
        "pingcap:tidb-8.5-config",
        None
    ),
    parameter!(
        Some("security"),
        "ssl-key",
        text(0, 4_096, DatabaseConfigTextNormalization::Preserve),
        Instance,
        PrivateKeyReference,
        RollingRestart,
        Critical,
        "The value identifies private-key material and must not be exposed.",
        "Private-key references require redacted review during competition.",
        "pingcap:tidb-8.5-config",
        None
    ),
    parameter!(
        Some("security"),
        "cluster-ssl-ca",
        text(0, 4_096, DatabaseConfigTextNormalization::Preserve),
        Cluster,
        OperationalMetadata,
        RollingRestart,
        High,
        "Internal TLS changes must be coordinated across every TiDB component.",
        "Partial internal TLS deployment can break the control and data planes.",
        "pingcap:tidb-8.5-config",
        None
    ),
    parameter!(
        Some("security"),
        "cluster-ssl-cert",
        text(0, 4_096, DatabaseConfigTextNormalization::Preserve),
        Cluster,
        OperationalMetadata,
        RollingRestart,
        High,
        "Internal certificates must match the cluster CA and peer identities.",
        "Component-to-component trust must be reviewed as a coordinated set.",
        "pingcap:tidb-8.5-config",
        None
    ),
    parameter!(
        Some("security"),
        "cluster-ssl-key",
        text(0, 4_096, DatabaseConfigTextNormalization::Preserve),
        Cluster,
        PrivateKeyReference,
        RollingRestart,
        Critical,
        "The value identifies internal cluster private-key material.",
        "Internal private-key references must never enter previews or logs.",
        "pingcap:tidb-8.5-config",
        None
    ),
    parameter!(
        Some("security"),
        "tls-version",
        text(0, 32, DatabaseConfigTextNormalization::TrimAsciiWhitespace),
        Instance,
        Public,
        RollingRestart,
        High,
        "The selected minimum TLS version controls protocol downgrade exposure; empty has a documented meaning.",
        "Text preserves the valid empty form because the common enum contract rejects empty literals.",
        "pingcap:tidb-8.5-config",
        None
    ),
    parameter!(
        Some("security"),
        "enable-sem",
        DatabaseConfigSchemaValueKind::Boolean {
            true_literal: "true",
            false_literal: "false",
        },
        Instance,
        Public,
        RollingRestart,
        High,
        "Disabling SEM removes its enhanced security restrictions.",
        "The switch is a direct security-posture signal.",
        "pingcap:tidb-8.5-config",
        None
    ),
    parameter!(
        Some("security"),
        "spilled-file-encryption-method",
        DatabaseConfigSchemaValueKind::Enumeration {
            values: &["plaintext", "aes128-ctr"],
        },
        Instance,
        Public,
        RollingRestart,
        High,
        "Plaintext leaves spilled query data readable at rest.",
        "Temporary spill files can retain evidence and sensitive values.",
        "pingcap:tidb-8.5-config",
        None
    ),
    parameter!(
        Some("instance"),
        "max_connections",
        DatabaseConfigSchemaValueKind::Integer {
            minimum_inclusive: 0,
            maximum_inclusive: 100_000,
        },
        Instance,
        Public,
        RollingRestart,
        High,
        "Zero means no configured connection limit and can permit exhaustion.",
        "Connection ceilings matter during denial-of-service containment.",
        "pingcap:tidb-8.5-config",
        None
    ),
    parameter!(
        Some("instance"),
        "tidb_enable_slow_log",
        DatabaseConfigSchemaValueKind::Boolean {
            true_literal: "true",
            false_literal: "false",
        },
        Instance,
        Public,
        RollingRestart,
        Medium,
        "Disabling slow logging removes useful query evidence.",
        "Slow-query evidence is frequently needed in response exercises.",
        "pingcap:tidb-8.5-config",
        None
    ),
    parameter!(
        Some("instance"),
        "tidb_slow_log_threshold",
        DatabaseConfigSchemaValueKind::Integer {
            minimum_inclusive: -1,
            maximum_inclusive: i64::MAX,
        },
        Instance,
        Public,
        RollingRestart,
        Medium,
        "A disabled or excessive threshold suppresses useful slow-query evidence.",
        "The threshold explains gaps in incident timelines.",
        "pingcap:tidb-8.5-config",
        None
    ),
    parameter!(
        Some("log"),
        "level",
        DatabaseConfigSchemaValueKind::Enumeration {
            values: &["debug", "info", "warn", "error", "fatal"],
        },
        Instance,
        Public,
        RollingRestart,
        Medium,
        "Debug logging increases sensitive-query and disk exposure.",
        "Log level explains both available evidence and leakage risk.",
        "pingcap:tidb-8.5-config",
        None
    ),
    parameter!(
        Some("log.file"),
        "max-size",
        DatabaseConfigSchemaValueKind::Integer {
            minimum_inclusive: 1,
            maximum_inclusive: 4_096,
        },
        Instance,
        Public,
        RollingRestart,
        Medium,
        "Large files or unconstrained retention can exhaust local storage.",
        "Log capacity affects evidence preservation and service availability.",
        "pingcap:tidb-8.5-config",
        None
    ),
    parameter!(
        Some("log.file"),
        "max-days",
        DatabaseConfigSchemaValueKind::Integer {
            minimum_inclusive: 0,
            maximum_inclusive: i64::MAX,
        },
        Instance,
        Public,
        RollingRestart,
        Medium,
        "Zero keeps files without an age limit and can exhaust storage.",
        "Retention directly affects forensic coverage.",
        "pingcap:tidb-8.5-config",
        None
    ),
    parameter!(
        Some("log.file"),
        "max-backups",
        DatabaseConfigSchemaValueKind::Integer {
            minimum_inclusive: 0,
            maximum_inclusive: i64::MAX,
        },
        Instance,
        Public,
        RollingRestart,
        Medium,
        "Zero retains all backups and can exhaust storage.",
        "Backup count controls the available incident history.",
        "pingcap:tidb-8.5-config",
        None
    ),
];

/// Exact TiDB server TOML pack for the current 8.5 LTS patch reviewed here.
pub const TIDB_8_5_7_SERVER_TOML_SCHEMA: DatabaseConfigSchema = DatabaseConfigSchema {
    display_label: "TiDB server TOML (reviewed partial)",
    version_label: "8.5.7 exact",
    binding: DatabaseConfigSchemaBinding {
        product: DatabaseConfigProduct::TiDb,
        versions: DatabaseConfigVersionSelector::Exact(DatabaseConfigVersion::new(8, 5, 7)),
        edition_key: None,
        component: DatabaseConfigComponent::TiDb,
        artifact_key: "tidb-server-toml",
    },
    completeness: DatabaseConfigSchemaCompleteness::Partial,
    parameters: TIDB_8_5_7_PARAMETERS,
    references: TIDB_REFERENCES,
};

const TIKV_8_5_7_PARAMETERS: &[DatabaseConfigParameterSchema] = &[
    parameter!(
        Some("server"),
        "addr",
        text(1, 512, DatabaseConfigTextNormalization::TrimAsciiWhitespace),
        Instance,
        OperationalMetadata,
        RollingRestart,
        High,
        "A broadly bound service address expands the TiKV attack surface.",
        "The storage listener is distinct from status and advertised addresses.",
        "pingcap:tikv-8.5-config",
        None
    ),
    parameter!(
        Some("server"),
        "advertise-addr",
        text(0, 512, DatabaseConfigTextNormalization::TrimAsciiWhitespace),
        Cluster,
        OperationalMetadata,
        RollingRestart,
        High,
        "A wrong advertised address can partition or redirect cluster traffic.",
        "Advertised topology is central to cluster compromise triage.",
        "pingcap:tikv-8.5-config",
        None
    ),
    parameter!(
        Some("server"),
        "status-addr",
        text(0, 512, DatabaseConfigTextNormalization::TrimAsciiWhitespace),
        Instance,
        OperationalMetadata,
        RollingRestart,
        High,
        "A public status address exposes operational diagnostics.",
        "Status endpoints frequently reveal high-value response evidence.",
        "pingcap:tikv-8.5-config",
        None
    ),
    parameter!(
        Some("security"),
        "ca-path",
        text(0, 4_096, DatabaseConfigTextNormalization::Preserve),
        Cluster,
        OperationalMetadata,
        RollingRestart,
        High,
        "The CA must be coordinated with every mutually authenticated component.",
        "Internal trust failures can isolate the storage layer.",
        "pingcap:tikv-8.5-config",
        None
    ),
    parameter!(
        Some("security"),
        "cert-path",
        text(0, 4_096, DatabaseConfigTextNormalization::Preserve),
        Cluster,
        OperationalMetadata,
        RollingRestart,
        High,
        "The certificate must match the configured CA and peer identity.",
        "Certificate state is required for internal-channel triage.",
        "pingcap:tikv-8.5-config",
        None
    ),
    parameter!(
        Some("security"),
        "key-path",
        text(0, 4_096, DatabaseConfigTextNormalization::Preserve),
        Cluster,
        PrivateKeyReference,
        RollingRestart,
        Critical,
        "The value identifies TiKV private-key material.",
        "Private-key references must be redacted in the competition UI.",
        "pingcap:tikv-8.5-config",
        None
    ),
    parameter!(
        Some("security"),
        "redact-info-log",
        DatabaseConfigSchemaValueKind::Enumeration {
            values: &["false", "true", "off", "on", "marker"],
        },
        Instance,
        Public,
        RollingRestart,
        High,
        "Disabled redaction can expose values in TiKV logs.",
        "Redaction state determines whether log previews are safe.",
        "pingcap:tikv-8.5-config",
        None
    ),
    parameter!(
        Some("security.encryption"),
        "data-encryption-method",
        DatabaseConfigSchemaValueKind::Enumeration {
            values: &[
                "plaintext",
                "aes128-ctr",
                "aes192-ctr",
                "aes256-ctr",
                "sm4-ctr",
            ],
        },
        Instance,
        Public,
        VendorProcedure,
        Critical,
        "Plaintext leaves TiKV data files unencrypted at rest.",
        "Encryption state is a primary data-exposure control.",
        "pingcap:tikv-8.5-config",
        None
    ),
    parameter!(
        None,
        "memory-usage-limit",
        text(1, 128, DatabaseConfigTextNormalization::TrimAsciiWhitespace),
        Instance,
        Public,
        RollingRestart,
        High,
        "An unsafe limit can cause OOM or severe throttling.",
        "Resource exhaustion is common in response competitions.",
        "pingcap:tikv-8.5-config",
        None
    ),
    parameter!(
        Some("storage.block-cache"),
        "capacity",
        text(1, 128, DatabaseConfigTextNormalization::TrimAsciiWhitespace),
        Instance,
        Public,
        RollingRestart,
        High,
        "An unsafe cache capacity can exhaust memory or collapse performance.",
        "Runtime changes must also be reconciled with deployment configuration.",
        "pingcap:tikv-8.5-config",
        None
    ),
    parameter!(
        Some("server"),
        "grpc-memory-pool-quota",
        text(1, 128, DatabaseConfigTextNormalization::TrimAsciiWhitespace),
        Instance,
        Public,
        RollingRestart,
        High,
        "A value that is too low can stall gRPC work; an unlimited pool can exhaust memory.",
        "The quota helps explain storage service stalls.",
        "pingcap:tikv-8.5-config",
        None
    ),
    parameter!(
        Some("raftstore"),
        "raft-entry-max-size",
        text(1, 128, DatabaseConfigTextNormalization::TrimAsciiWhitespace),
        Cluster,
        Public,
        RollingRestart,
        High,
        "Incompatible values can reject transactions or Raft entries.",
        "The limit must be evaluated across the transaction and Raft path.",
        "pingcap:tikv-8.5-config",
        None
    ),
    parameter!(
        Some("log"),
        "level",
        DatabaseConfigSchemaValueKind::Enumeration {
            values: &["debug", "info", "warn", "error", "fatal"],
        },
        Instance,
        Public,
        RollingRestart,
        Medium,
        "Debug logging increases data exposure and disk pressure.",
        "The log level explains evidence volume and leakage risk.",
        "pingcap:tikv-8.5-config",
        None
    ),
    parameter!(
        Some("log.file"),
        "max-size",
        DatabaseConfigSchemaValueKind::Integer {
            minimum_inclusive: 1,
            maximum_inclusive: 4_096,
        },
        Instance,
        Public,
        RollingRestart,
        Medium,
        "Large log files increase local disk pressure.",
        "Rotation limits affect both evidence and availability.",
        "pingcap:tikv-8.5-config",
        None
    ),
];

/// Exact TiKV TOML pack for the current 8.5 LTS patch reviewed here.
pub const TIKV_8_5_7_TOML_SCHEMA: DatabaseConfigSchema = DatabaseConfigSchema {
    display_label: "TiKV TOML (reviewed partial)",
    version_label: "8.5.7 exact",
    binding: DatabaseConfigSchemaBinding {
        product: DatabaseConfigProduct::TiDb,
        versions: DatabaseConfigVersionSelector::Exact(DatabaseConfigVersion::new(8, 5, 7)),
        edition_key: None,
        component: DatabaseConfigComponent::TiKv,
        artifact_key: "tidb-tikv-toml",
    },
    completeness: DatabaseConfigSchemaCompleteness::Partial,
    parameters: TIKV_8_5_7_PARAMETERS,
    references: TIKV_REFERENCES,
};

const PD_8_5_7_PARAMETERS: &[DatabaseConfigParameterSchema] = &[
    parameter!(
        None,
        "client-urls",
        text(1, 4_096, DatabaseConfigTextNormalization::Preserve),
        Instance,
        OperationalMetadata,
        RollingRestart,
        Critical,
        "A broadly bound client URL exposes the PD control plane.",
        "PD client endpoints are critical containment targets.",
        "pingcap:pd-8.5-config",
        None
    ),
    parameter!(
        None,
        "advertise-client-urls",
        text(1, 4_096, DatabaseConfigTextNormalization::Preserve),
        Cluster,
        OperationalMetadata,
        RollingRestart,
        High,
        "Incorrect advertised client URLs can redirect or partition control traffic.",
        "Advertised endpoints establish the trusted cluster topology.",
        "pingcap:pd-8.5-config",
        None
    ),
    parameter!(
        None,
        "peer-urls",
        text(1, 4_096, DatabaseConfigTextNormalization::Preserve),
        Instance,
        OperationalMetadata,
        RollingRestart,
        Critical,
        "A broadly bound peer URL exposes the PD consensus plane.",
        "Consensus endpoints are high-value incident-response evidence.",
        "pingcap:pd-8.5-config",
        None
    ),
    parameter!(
        None,
        "advertise-peer-urls",
        text(1, 4_096, DatabaseConfigTextNormalization::Preserve),
        Cluster,
        OperationalMetadata,
        RollingRestart,
        High,
        "Incorrect advertised peer URLs can partition PD consensus.",
        "The exact peer topology must be preserved during recovery.",
        "pingcap:pd-8.5-config",
        None
    ),
    parameter!(
        None,
        "initial-cluster",
        text(1, 8_192, DatabaseConfigTextNormalization::Preserve),
        Cluster,
        OperationalMetadata,
        VendorProcedure,
        Critical,
        "Changing the bootstrap member map can create a conflicting cluster.",
        "Bootstrap topology is inspect-only after cluster creation.",
        "pingcap:pd-8.5-config",
        None
    ),
    parameter!(
        None,
        "force-new-cluster",
        DatabaseConfigSchemaValueKind::Boolean {
            true_literal: "true",
            false_literal: "false",
        },
        Cluster,
        Public,
        VendorProcedure,
        Critical,
        "Forcing a new cluster can violate consensus and lose data.",
        "This recovery-only switch must never be emitted by a normal template.",
        "pingcap:pd-8.5-config",
        None
    ),
    parameter!(
        Some("security"),
        "cacert-path",
        text(0, 4_096, DatabaseConfigTextNormalization::Preserve),
        Cluster,
        OperationalMetadata,
        RollingRestart,
        High,
        "The CA reference must be coordinated across all TiDB components.",
        "Control-plane trust is central to incident containment.",
        "pingcap:pd-8.5-config",
        None
    ),
    parameter!(
        Some("security"),
        "cert-path",
        text(0, 4_096, DatabaseConfigTextNormalization::Preserve),
        Cluster,
        OperationalMetadata,
        RollingRestart,
        High,
        "The certificate must match the PD identity and configured CA.",
        "Certificate state must be reviewed with the whole cluster.",
        "pingcap:pd-8.5-config",
        None
    ),
    parameter!(
        Some("security"),
        "key-path",
        text(0, 4_096, DatabaseConfigTextNormalization::Preserve),
        Cluster,
        PrivateKeyReference,
        RollingRestart,
        Critical,
        "The value identifies PD private-key material.",
        "Private-key references must never be retained in previews.",
        "pingcap:pd-8.5-config",
        None
    ),
    parameter!(
        Some("security"),
        "redact-info-log",
        DatabaseConfigSchemaValueKind::Enumeration {
            values: &["false", "true", "marker"],
        },
        Cluster,
        Public,
        RollingRestart,
        High,
        "Disabled redaction can expose values in PD logs.",
        "The redaction mode determines whether logs are safe to display.",
        "pingcap:pd-8.5-config",
        None
    ),
    parameter!(
        Some("replication"),
        "max-replicas",
        DatabaseConfigSchemaValueKind::Integer {
            minimum_inclusive: 1,
            maximum_inclusive: i64::MAX,
        },
        Cluster,
        Public,
        VendorProcedure,
        Critical,
        "Reducing replica count weakens data durability.",
        "Replica policy is a primary resilience control.",
        "pingcap:pd-8.5-config",
        None
    ),
    parameter!(
        Some("replication"),
        "isolation-level",
        text(0, 512, DatabaseConfigTextNormalization::TrimAsciiWhitespace),
        Cluster,
        OperationalMetadata,
        VendorProcedure,
        High,
        "A weak or missing isolation level reduces failure-domain guarantees.",
        "Isolation policy explains replica placement during incidents.",
        "pingcap:pd-8.5-config",
        None
    ),
    parameter!(
        Some("replication"),
        "strictly-match-label",
        DatabaseConfigSchemaValueKind::Boolean {
            true_literal: "true",
            false_literal: "false",
        },
        Cluster,
        Public,
        VendorProcedure,
        High,
        "Non-strict label matching can admit stores with unexpected labels.",
        "Strictness affects whether topology mistakes are rejected.",
        "pingcap:pd-8.5-config",
        None
    ),
    parameter!(
        Some("replication"),
        "enable-placement-rules",
        DatabaseConfigSchemaValueKind::Boolean {
            true_literal: "true",
            false_literal: "false",
        },
        Cluster,
        Public,
        VendorProcedure,
        Critical,
        "Disabling placement rules can invalidate intended replica policy.",
        "Placement controls are critical to cluster resilience.",
        "pingcap:pd-8.5-config",
        None
    ),
    parameter!(
        Some("schedule"),
        "max-store-down-time",
        text(1, 128, DatabaseConfigTextNormalization::TrimAsciiWhitespace),
        Cluster,
        Public,
        VendorProcedure,
        High,
        "Too short triggers unnecessary rebuilds; too long delays protection.",
        "The threshold explains replica movement after a store outage.",
        "pingcap:pd-8.5-config",
        None
    ),
    parameter!(
        Some("log"),
        "level",
        DatabaseConfigSchemaValueKind::Enumeration {
            values: &["debug", "info", "warn", "error", "fatal"],
        },
        Cluster,
        Public,
        RollingRestart,
        Medium,
        "Debug logging increases data exposure and disk pressure.",
        "PD logs are primary control-plane evidence.",
        "pingcap:pd-8.5-config",
        None
    ),
];

/// Exact PD TOML pack for the current 8.5 LTS patch reviewed here.
pub const PD_8_5_7_TOML_SCHEMA: DatabaseConfigSchema = DatabaseConfigSchema {
    display_label: "PD TOML (reviewed partial)",
    version_label: "8.5.7 exact",
    binding: DatabaseConfigSchemaBinding {
        product: DatabaseConfigProduct::TiDb,
        versions: DatabaseConfigVersionSelector::Exact(DatabaseConfigVersion::new(8, 5, 7)),
        edition_key: None,
        component: DatabaseConfigComponent::Pd,
        artifact_key: "tidb-pd-toml",
    },
    completeness: DatabaseConfigSchemaCompleteness::Partial,
    parameters: PD_8_5_7_PARAMETERS,
    references: PD_REFERENCES,
};

const OPENGAUSS_5_REFERENCES: &[DatabaseConfigSchemaReference] = &[
    DatabaseConfigSchemaReference {
        id: "opengauss:5.0.0-enterprise-edition",
        title: "openGauss 5.0.0 Enterprise edition installation process",
        url: "https://docs.opengauss.org/en/docs/5.0.0/docs/InstallationGuide/enterprise-edition-installation-process.html",
    },
    DatabaseConfigSchemaReference {
        id: "opengauss:5.0.0-connection-settings",
        title: "openGauss 5.0.0 connection settings",
        url: "https://docs.opengauss.org/en/docs/5.0.0/docs/DatabaseReference/connection-settings.html",
    },
    DatabaseConfigSchemaReference {
        id: "opengauss:5.0.0-password-policy",
        title: "openGauss 5.0.0 password security policies",
        url: "https://docs.opengauss.org/en/docs/5.0.0/docs/DatabaseAdministrationGuide/setting-password-security-policies.html",
    },
];

const OPENGAUSS_5_0_0_STANDARD_PARAMETERS: &[DatabaseConfigParameterSchema] = &[
    parameter!(
        None,
        "listen_addresses",
        text(1, 4_096, DatabaseConfigTextNormalization::Preserve),
        Instance,
        OperationalMetadata,
        Restart,
        Critical,
        "Wildcard or public listener addresses expose the database service.",
        "Listener scope is a primary containment check.",
        "opengauss:5.0.0-connection-settings",
        None
    ),
    parameter!(
        None,
        "port",
        DatabaseConfigSchemaValueKind::Integer {
            minimum_inclusive: 1,
            maximum_inclusive: 65_535,
        },
        Instance,
        OperationalMetadata,
        Restart,
        Medium,
        "Changing the port changes the reachable service endpoint.",
        "The exact port is necessary for response and restoration.",
        "opengauss:5.0.0-connection-settings",
        None
    ),
    parameter!(
        None,
        "max_connections",
        DatabaseConfigSchemaValueKind::Integer {
            minimum_inclusive: 10,
            maximum_inclusive: 262_143,
        },
        Instance,
        Public,
        Restart,
        High,
        "An excessive value can exhaust resources; a standby must not be lower than its primary.",
        "Connection exhaustion and HA mismatches are common competition failures.",
        "opengauss:5.0.0-connection-settings",
        None
    ),
    parameter!(
        None,
        "password_encryption_type",
        DatabaseConfigSchemaValueKind::Enumeration {
            values: &["0", "1", "2", "3"],
        },
        Cluster,
        Public,
        Reload,
        Critical,
        "Modes 0 and 1 retain MD5-derived password material; changes affect new password updates only.",
        "The value explains credential-hash strength without exposing credentials.",
        "opengauss:5.0.0-password-policy",
        None
    ),
];

/// Exact openGauss 5.0.0 Enterprise-edition main configuration pack.
pub const OPENGAUSS_5_0_0_STANDARD_MAIN_SCHEMA: DatabaseConfigSchema = DatabaseConfigSchema {
    display_label: "openGauss main configuration (Enterprise, reviewed partial)",
    version_label: "5.0.0 exact",
    binding: DatabaseConfigSchemaBinding {
        product: DatabaseConfigProduct::OpenGauss,
        versions: DatabaseConfigVersionSelector::Exact(DatabaseConfigVersion::new(5, 0, 0)),
        edition_key: Some("enterprise"),
        component: DatabaseConfigComponent::Server,
        artifact_key: "opengauss-main",
    },
    completeness: DatabaseConfigSchemaCompleteness::Partial,
    parameters: OPENGAUSS_5_0_0_STANDARD_PARAMETERS,
    references: OPENGAUSS_5_REFERENCES,
};

const OPENGAUSS_6_LITE_REFERENCES: &[DatabaseConfigSchemaReference] = &[
    DatabaseConfigSchemaReference {
        id: "opengauss:6.0.0-lite-settings",
        title: "openGauss 6.0.0 Lite settings",
        url: "https://docs.opengauss.org/en/docs/6.0.0-lite/docs/DataBaseReference/settings.html",
    },
    DatabaseConfigSchemaReference {
        id: "opengauss:6.0.0-lite-primary",
        title: "openGauss 6.0.0 Lite primary server settings",
        url: "https://docs.opengauss.org/en/docs/6.0.0-lite/docs/DataBaseReference/primary-server.html",
    },
    DatabaseConfigSchemaReference {
        id: "opengauss:6.0.0-lite-audit",
        title: "openGauss 6.0.0 Lite database audit",
        url: "https://docs.opengauss.org/en/docs/6.0.0-lite/docs/DatabaseAdministrationGuide/overview-database-audit.html",
    },
];

const fn opengauss_replconninfo(key: &'static str) -> DatabaseConfigParameterSchema {
    DatabaseConfigParameterSchema {
        container_path: None,
        canonical_key: key,
        exact_aliases: &[],
        value_kind: text(1, 8_192, DatabaseConfigTextNormalization::Preserve),
        documented_default: None,
        scope: DatabaseConfigSchemaScope::Cluster,
        sensitivity: DatabaseConfigSchemaSensitivity::OperationalMetadata,
        activation: DatabaseConfigSchemaActivation::Reload,
        risk: DatabaseConfigSchemaRisk::Critical,
        risk_rationale: "The structured replication endpoint controls primary/standby connectivity and TLS mode.",
        competition_rationale: "Replication endpoints must be parsed as a whole and never edited as free-form fragments.",
        official_reference_id: "opengauss:6.0.0-lite-primary",
        required_capability: None,
    }
}

const OPENGAUSS_6_0_0_LITE_PARAMETERS: &[DatabaseConfigParameterSchema] = &[
    parameter!(
        None,
        "wal_level",
        DatabaseConfigSchemaValueKind::Enumeration {
            values: &["minimal", "archive", "hot_standby", "logical"],
        },
        Cluster,
        Public,
        Restart,
        Critical,
        "Minimal WAL can make archiving and standby recovery unavailable.",
        "WAL posture is central to recovery scoring.",
        "opengauss:6.0.0-lite-settings",
        None
    ),
    parameter!(
        None,
        "fsync",
        DatabaseConfigSchemaValueKind::Boolean {
            true_literal: "on",
            false_literal: "off",
        },
        Instance,
        Public,
        Reload,
        Critical,
        "Disabling fsync can cause unrecoverable corruption after a crash.",
        "The switch is a direct durability control.",
        "opengauss:6.0.0-lite-settings",
        None
    ),
    parameter!(
        None,
        "synchronous_commit",
        DatabaseConfigSchemaValueKind::Enumeration {
            values: &[
                "on",
                "off",
                "local",
                "remote_write",
                "remote_receive",
                "remote_apply",
                "true",
                "false",
                "yes",
                "no",
                "1",
                "0",
                "2",
            ],
        },
        Session,
        Public,
        Reload,
        High,
        "Off or local modes weaken commit durability guarantees.",
        "A file reload changes the default for new sessions; existing sessions retain their current durability setting.",
        "opengauss:6.0.0-lite-settings",
        None
    ),
    parameter!(
        None,
        "synchronous_standby_names",
        text(0, 8_192, DatabaseConfigTextNormalization::Preserve),
        Cluster,
        OperationalMetadata,
        Reload,
        Critical,
        "A wrong ANY, FIRST, or member expression can block commits or weaken synchronization.",
        "Standby selection must remain visible as topology-aware text.",
        "opengauss:6.0.0-lite-primary",
        None
    ),
    opengauss_replconninfo("replconninfo1"),
    opengauss_replconninfo("replconninfo2"),
    opengauss_replconninfo("replconninfo3"),
    opengauss_replconninfo("replconninfo4"),
    opengauss_replconninfo("replconninfo5"),
    opengauss_replconninfo("replconninfo6"),
    opengauss_replconninfo("replconninfo7"),
    opengauss_replconninfo("replconninfo8"),
    opengauss_replconninfo("replconninfo9"),
    opengauss_replconninfo("replconninfo10"),
    opengauss_replconninfo("replconninfo11"),
    opengauss_replconninfo("replconninfo12"),
    opengauss_replconninfo("replconninfo13"),
    opengauss_replconninfo("replconninfo14"),
    opengauss_replconninfo("replconninfo15"),
    opengauss_replconninfo("replconninfo16"),
    opengauss_replconninfo("replconninfo17"),
    opengauss_replconninfo("replconninfo18"),
    parameter!(
        None,
        "enable_stream_replication",
        DatabaseConfigSchemaValueKind::Boolean {
            true_literal: "on",
            false_literal: "off",
        },
        Cluster,
        Public,
        Reload,
        Critical,
        "Disabling stream replication breaks normal HA data synchronization.",
        "The switch is a direct HA integrity signal.",
        "opengauss:6.0.0-lite-primary",
        None
    ),
    parameter!(
        None,
        "shared_buffers",
        text(1, 128, DatabaseConfigTextNormalization::TrimAsciiWhitespace),
        Instance,
        Public,
        Restart,
        High,
        "An unsafe buffer allocation can exhaust memory or severely impair service; values may carry units.",
        "Text avoids rejecting documented unit-bearing forms that the scalar model cannot normalize.",
        "opengauss:6.0.0-lite-settings",
        None
    ),
    parameter!(
        None,
        "audit_enabled",
        DatabaseConfigSchemaValueKind::Boolean {
            true_literal: "on",
            false_literal: "off",
        },
        Instance,
        Public,
        Reload,
        Critical,
        "Disabling auditing removes core response evidence.",
        "Audit availability is a primary competition control.",
        "opengauss:6.0.0-lite-audit",
        None
    ),
    parameter!(
        None,
        "audit_login_logout",
        text(1, 64, DatabaseConfigTextNormalization::TrimAsciiWhitespace),
        Instance,
        Public,
        Reload,
        High,
        "A zero or reduced mask can omit login and logout evidence.",
        "The official page proves the key but the scalar schema does not guess undocumented masks.",
        "opengauss:6.0.0-lite-audit",
        None
    ),
    parameter!(
        None,
        "audit_user_violation",
        text(1, 64, DatabaseConfigTextNormalization::TrimAsciiWhitespace),
        Instance,
        Public,
        Reload,
        High,
        "Disabled violation auditing hides unauthorized-access evidence.",
        "The mask remains inspectable without inferring unsupported bit ranges.",
        "opengauss:6.0.0-lite-audit",
        None
    ),
    parameter!(
        None,
        "audit_system_object",
        text(1, 64, DatabaseConfigTextNormalization::TrimAsciiWhitespace),
        Instance,
        Public,
        Reload,
        High,
        "A reduced mask can omit changes to important system objects.",
        "Bitmask meaning must remain tied to the exact Lite manual.",
        "opengauss:6.0.0-lite-audit",
        None
    ),
    parameter!(
        None,
        "audit_directory",
        text(1, 4_096, DatabaseConfigTextNormalization::Preserve),
        Instance,
        OperationalMetadata,
        Restart,
        High,
        "A wrong or unprotected directory can lose or expose audit evidence.",
        "The audit path is operational metadata and must not be treated as a secret value.",
        "opengauss:6.0.0-lite-audit",
        None
    ),
];

/// Exact openGauss 6.0.0 Lite main configuration pack.
pub const OPENGAUSS_6_0_0_LITE_MAIN_SCHEMA: DatabaseConfigSchema = DatabaseConfigSchema {
    display_label: "openGauss main configuration (Lite, reviewed partial)",
    version_label: "6.0.0 Lite exact",
    binding: DatabaseConfigSchemaBinding {
        product: DatabaseConfigProduct::OpenGauss,
        versions: DatabaseConfigVersionSelector::Exact(DatabaseConfigVersion::new(6, 0, 0)),
        edition_key: Some("lite"),
        component: DatabaseConfigComponent::Server,
        artifact_key: "opengauss-main",
    },
    completeness: DatabaseConfigSchemaCompleteness::Partial,
    parameters: OPENGAUSS_6_0_0_LITE_PARAMETERS,
    references: OPENGAUSS_6_LITE_REFERENCES,
};

const KINGBASE_V8_REFERENCES: &[DatabaseConfigSchemaReference] = &[DatabaseConfigSchemaReference {
    id: "kingbase:v8.6.7.12-connection",
    title: "KingbaseES V8.6.7.12 connection settings",
    url: "https://help.kingbase.com.cn/v8.6.7.12/admin/reference/ref-database-parameter/type-of-parameters/runtime-config-connection.html",
}];

const KINGBASE_V8_6_7_12_PARAMETERS: &[DatabaseConfigParameterSchema] = &[
    parameter!(
        None,
        "listen_addresses",
        text(1, 4_096, DatabaseConfigTextNormalization::Preserve),
        Instance,
        OperationalMetadata,
        Restart,
        Critical,
        "The exact manual contradicts itself about the default, so only the observed value is safe to annotate.",
        "Wildcard listeners are high-priority response findings.",
        "kingbase:v8.6.7.12-connection",
        None
    ),
    parameter!(
        None,
        "port",
        text(1, 32, DatabaseConfigTextNormalization::TrimAsciiWhitespace),
        Instance,
        OperationalMetadata,
        Restart,
        Medium,
        "The exact page proves the key and default but does not justify a generated range here.",
        "Unknown vendor ranges stay textual and inspect-first.",
        "kingbase:v8.6.7.12-connection",
        None
    ),
    parameter!(
        None,
        "max_connections",
        text(1, 32, DatabaseConfigTextNormalization::TrimAsciiWhitespace),
        Instance,
        Public,
        Restart,
        High,
        "An excessive value can exhaust resources and standby values must cover primary demand.",
        "The vendor range is not inferred from PostgreSQL compatibility.",
        "kingbase:v8.6.7.12-connection",
        None
    ),
    parameter!(
        None,
        "password_encryption",
        DatabaseConfigSchemaValueKind::Enumeration {
            values: &["md5", "scram-sha-256", "on"],
        },
        Session,
        Public,
        Reload,
        Critical,
        "MD5 stores weaker password verifiers and changes only affect subsequently set passwords.",
        "Reload changes the default for new sessions; existing verifiers are unchanged and only subsequently set passwords use the selected method.",
        "kingbase:v8.6.7.12-connection",
        None
    ),
    parameter!(
        None,
        "ssl",
        DatabaseConfigSchemaValueKind::Boolean {
            true_literal: "on",
            false_literal: "off",
        },
        Instance,
        Public,
        Reload,
        Critical,
        "Disabling SSL permits unencrypted connections when access rules allow them.",
        "Reloaded TLS settings apply to new connections; existing connections are unaffected.",
        "kingbase:v8.6.7.12-connection",
        None
    ),
    parameter!(
        None,
        "ssl_ca_file",
        text(0, 4_096, DatabaseConfigTextNormalization::Preserve),
        Instance,
        OperationalMetadata,
        Reload,
        High,
        "A wrong CA reference can break or weaken peer verification.",
        "The CA, certificate, and key must be reviewed together; reload affects new connections only.",
        "kingbase:v8.6.7.12-connection",
        None
    ),
    parameter!(
        None,
        "ssl_cert_file",
        text(0, 4_096, DatabaseConfigTextNormalization::Preserve),
        Instance,
        OperationalMetadata,
        Reload,
        High,
        "A wrong certificate reference can prevent secure service startup.",
        "Certificate configuration is critical response metadata; reload affects new connections only.",
        "kingbase:v8.6.7.12-connection",
        None
    ),
    parameter!(
        None,
        "ssl_key_file",
        text(0, 4_096, DatabaseConfigTextNormalization::Preserve),
        Instance,
        PrivateKeyReference,
        Reload,
        Critical,
        "The value identifies KingbaseES private-key material.",
        "Private-key references must be redacted; reload affects new connections only.",
        "kingbase:v8.6.7.12-connection",
        None
    ),
    parameter!(
        None,
        "ssl_ciphers",
        text(1, 8_192, DatabaseConfigTextNormalization::Preserve),
        Instance,
        Public,
        Reload,
        High,
        "Legacy or anonymous cipher selections weaken transport security.",
        "Cipher compatibility is vendor and crypto-library specific; reload affects new connections only.",
        "kingbase:v8.6.7.12-connection",
        None
    ),
    parameter!(
        None,
        "ssl_min_protocol_version",
        DatabaseConfigSchemaValueKind::Enumeration {
            values: &["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"],
        },
        Instance,
        Public,
        Reload,
        Critical,
        "TLSv1 and TLSv1.1 permit obsolete protocol versions.",
        "The minimum protocol is a direct hardening control; reload affects new connections only.",
        "kingbase:v8.6.7.12-connection",
        None
    ),
];

/// Exact V8.6.7.12 official-document-family pack; no other V8 build inherits it.
pub const KINGBASE_ES_V8_6_7_12_MAIN_SCHEMA: DatabaseConfigSchema = DatabaseConfigSchema {
    display_label: "KingbaseES main configuration (V8 document family, reviewed partial)",
    version_label: "V8.6.7.12 exact four-part version",
    binding: DatabaseConfigSchemaBinding {
        product: DatabaseConfigProduct::KingbaseEs,
        versions: DatabaseConfigVersionSelector::Exact(DatabaseConfigVersion::new_with_revision(
            8, 6, 7, 12,
        )),
        edition_key: Some("official-doc-family-v8.6.7.12"),
        component: DatabaseConfigComponent::Server,
        artifact_key: "kingbase-es-main",
    },
    completeness: DatabaseConfigSchemaCompleteness::Partial,
    parameters: KINGBASE_V8_6_7_12_PARAMETERS,
    references: KINGBASE_V8_REFERENCES,
};

const KINGBASE_V9_REFERENCES: &[DatabaseConfigSchemaReference] = &[
    DatabaseConfigSchemaReference {
        id: "kingbase:v9.3.11-reference-manual",
        title: "KingbaseES V9.3.11 database reference manual",
        url: "https://help.kingbase.com.cn/v9.3.11/PDF/KingbaseES%E6%95%B0%E6%8D%AE%E5%BA%93%E5%8F%82%E8%80%83%E6%89%8B%E5%86%8C.pdf",
    },
    DatabaseConfigSchemaReference {
        id: "kingbase:v9.3.11-security-guide",
        title: "KingbaseES V9.3.11 security guide",
        url: "https://help.kingbase.com.cn/v9.3.11/PDF/KingbaseES%E5%AE%89%E5%85%A8%E6%8C%87%E5%8D%97.pdf",
    },
    DatabaseConfigSchemaReference {
        id: "kingbase:v9.3.11-family-index",
        title: "KingbaseES V9.3.11 parameter manual family index",
        url: "https://help.kingbase.com.cn/v9.3.11/admin/reference/ref-database-parameter/index.html",
    },
];

const KINGBASE_V9_3_11_PARAMETERS: &[DatabaseConfigParameterSchema] = &[
    parameter!(
        None,
        "ssl_min_protocol_version",
        DatabaseConfigSchemaValueKind::Enumeration {
            values: &["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"],
        },
        Instance,
        Public,
        Reload,
        Critical,
        "TLSv1 and TLSv1.1 permit obsolete protocol versions.",
        "The exact reference manual marks this reloadable; the new minimum applies to new connections while existing connections are unaffected.",
        "kingbase:v9.3.11-reference-manual",
        None
    ),
    parameter!(
        None,
        "logging_collector",
        DatabaseConfigSchemaValueKind::Boolean {
            true_literal: "on",
            false_literal: "off",
        },
        Instance,
        Public,
        Restart,
        High,
        "Disabling the collector can remove expected local log evidence.",
        "Collector state explains missing files during triage.",
        "kingbase:v9.3.11-reference-manual",
        None
    ),
    parameter!(
        None,
        "log_destination",
        text(1, 512, DatabaseConfigTextNormalization::Preserve),
        Instance,
        Public,
        Reload,
        Medium,
        "A destination list can redirect or omit expected evidence.",
        "The list remains textual because platform-specific combinations are not inferred.",
        "kingbase:v9.3.11-reference-manual",
        None
    ),
    parameter!(
        None,
        "log_connections",
        DatabaseConfigSchemaValueKind::Boolean {
            true_literal: "on",
            false_literal: "off",
        },
        Instance,
        Public,
        Reload,
        High,
        "Disabled connection logging reduces authentication evidence.",
        "Login timelines are common competition evidence.",
        "kingbase:v9.3.11-reference-manual",
        None
    ),
    parameter!(
        None,
        "sysaudit.enable",
        DatabaseConfigSchemaValueKind::Boolean {
            true_literal: "on",
            false_literal: "off",
        },
        Instance,
        Public,
        Reload,
        Critical,
        "Disabling sysaudit removes vendor audit coverage.",
        "The setting is usable only after the sysaudit preload prerequisite is proven.",
        "kingbase:v9.3.11-security-guide",
        Some("kingbase.sysaudit-preloaded")
    ),
    parameter!(
        None,
        "sysaudit.audit_table_password",
        text(0, 4_096, DatabaseConfigTextNormalization::Preserve),
        VendorDefined,
        MayContainSecrets,
        VendorProcedure,
        Critical,
        "The parameter contains an audit credential and must never be displayed.",
        "Credential values remain redacted even during syntax validation.",
        "kingbase:v9.3.11-security-guide",
        Some("kingbase.sysaudit-preloaded")
    ),
    parameter!(
        None,
        "sysaudit.local_sao_password",
        text(0, 4_096, DatabaseConfigTextNormalization::Preserve),
        VendorDefined,
        MayContainSecrets,
        VendorProcedure,
        Critical,
        "The parameter contains a security-administrator credential.",
        "The UI must never retain, preview, or export this value.",
        "kingbase:v9.3.11-security-guide",
        Some("kingbase.sysaudit-preloaded")
    ),
];

/// Exact V9.3.11 official-document-family pack, separate from compatibility editions.
pub const KINGBASE_ES_V9_3_11_MAIN_SCHEMA: DatabaseConfigSchema = DatabaseConfigSchema {
    display_label: "KingbaseES main configuration (V9 document family, reviewed partial)",
    version_label: "V9.3.11 exact document family",
    binding: DatabaseConfigSchemaBinding {
        product: DatabaseConfigProduct::KingbaseEs,
        versions: DatabaseConfigVersionSelector::Exact(DatabaseConfigVersion::new(9, 3, 11)),
        edition_key: Some("official-doc-family-v9.3.11"),
        component: DatabaseConfigComponent::Server,
        artifact_key: "kingbase-es-main",
    },
    completeness: DatabaseConfigSchemaCompleteness::Partial,
    parameters: KINGBASE_V9_3_11_PARAMETERS,
    references: KINGBASE_V9_REFERENCES,
};

const GOLDENDB_V6_1_03_10_REFERENCES: &[DatabaseConfigSchemaReference] = &[
    DatabaseConfigSchemaReference {
        id: "goldendb:6.1.03.10-version-api",
        title: "GoldenDB documentation version API",
        url: "https://www.goldendb.com/document/center/getVersion/1",
    },
    DatabaseConfigSchemaReference {
        id: "goldendb:6.1.03.10-faq-sql",
        title: "GoldenDB v6.1.03.10 SQL FAQ",
        url: "https://www.goldendb.com/docsCenter/GoldenDB/61310/html/FAQ_SQL.html",
    },
    DatabaseConfigSchemaReference {
        id: "goldendb:6.1.03.10-sql-standard",
        title: "GoldenDB v6.1.03.10 SQL development support",
        url: "https://www.goldendb.com/docsCenter/GoldenDB/61310/html/developmentSupport_SQLStandard.html",
    },
    DatabaseConfigSchemaReference {
        id: "goldendb:6.1.03.10-dbtool",
        title: "GoldenDB v6.1.03.10 DBTool operations",
        url: "https://www.goldendb.com/docsCenter/GoldenDB/61310/html/operationManagement_dbtool.html",
    },
];

const GOLDENDB_V6_1_03_10_PROXY_PARAMETERS: &[DatabaseConfigParameterSchema] = &[
    parameter!(
        Some("SQLEXEC"),
        "update_grade",
        DatabaseConfigSchemaValueKind::Enumeration {
            values: &["0", "1", "2"],
        },
        Component,
        Public,
        Dynamic,
        Critical,
        "The value selects no CN override, SW, or CW write isolation and can materially change transaction consistency.",
        "Official default is 0; it is read-only metadata, not an automatic-fill, normalization, mutation, or deployment grant.",
        "goldendb:6.1.03.10-faq-sql",
        None,
        Some(DatabaseConfigDocumentedDefault::Enumeration("0"))
    ),
    parameter!(
        Some("SQLEXEC"),
        "select_grade",
        DatabaseConfigSchemaValueKind::Enumeration {
            values: &["0", "1", "2", "3", "4"],
        },
        Component,
        Public,
        Dynamic,
        Critical,
        "The value selects no CN override, UR, SEMI-CR, CR, or MVCC_RC read isolation and can change transaction visibility.",
        "Official default is 0; it is read-only metadata, not an automatic-fill, normalization, mutation, or deployment grant.",
        "goldendb:6.1.03.10-faq-sql",
        None,
        Some(DatabaseConfigDocumentedDefault::Enumeration("0"))
    ),
    parameter!(
        Some("SQLEXEC"),
        "mvcc_grade",
        DatabaseConfigSchemaValueKind::Enumeration {
            values: &["0", "1"],
        },
        Component,
        Public,
        Dynamic,
        High,
        "The value applies MVCC to all SELECT statements or only aggregate functions and can alter visibility and performance.",
        "Official default is 0; it is read-only metadata, not an automatic-fill, normalization, mutation, or deployment grant.",
        "goldendb:6.1.03.10-faq-sql",
        None,
        Some(DatabaseConfigDocumentedDefault::Enumeration("0"))
    ),
    parameter!(
        Some("GENERAL"),
        "switch_insert_value_on_duplicate_key_update_sw",
        DatabaseConfigSchemaValueKind::Enumeration {
            values: &["0", "1"],
        },
        Component,
        Public,
        Dynamic,
        Critical,
        "One requires SW writes for INSERT VALUES ON DUPLICATE KEY UPDATE while zero permits CW, changing distributed write-consistency behavior.",
        "Official default is 1; it is read-only metadata, not an automatic-fill, normalization, mutation, or deployment grant.",
        "goldendb:6.1.03.10-sql-standard",
        None,
        Some(DatabaseConfigDocumentedDefault::Enumeration("1"))
    ),
    parameter!(
        Some("GENERAL"),
        "insert_value_on_duplicate_key_update_usage_level",
        DatabaseConfigSchemaValueKind::Enumeration {
            values: &["0", "1"],
        },
        Component,
        Public,
        Dynamic,
        Critical,
        "Zero requires primary and unique indexes to include the distribution key; one limits the feature to each shard and does not provide cross-shard uniqueness.",
        "Official default is 0; it is read-only metadata, not an automatic-fill, normalization, mutation, or deployment grant.",
        "goldendb:6.1.03.10-sql-standard",
        None,
        Some(DatabaseConfigDocumentedDefault::Enumeration("0"))
    ),
];

/// Exact GoldenDB v6.1.03.10 compute-node proxy.ini metadata.
///
/// The documented dynamic behavior does not grant remote mutation authority;
/// the artifact remains vendor-schema-gated and requires independent readback.
pub const GOLDENDB_V6_1_03_10_PROXY_INI_SCHEMA: DatabaseConfigSchema = DatabaseConfigSchema {
    display_label: "GoldenDB compute-node proxy.ini (reviewed partial)",
    version_label: "v6.1.03.10 exact",
    binding: DatabaseConfigSchemaBinding {
        product: DatabaseConfigProduct::GoldenDb,
        versions: DatabaseConfigVersionSelector::Exact(DatabaseConfigVersion::new_with_revision(
            6, 1, 3, 10,
        )),
        edition_key: None,
        component: DatabaseConfigComponent::Proxy,
        artifact_key: "goldendb-proxy-ini",
    },
    completeness: DatabaseConfigSchemaCompleteness::Partial,
    parameters: GOLDENDB_V6_1_03_10_PROXY_PARAMETERS,
    references: GOLDENDB_V6_1_03_10_REFERENCES,
};

const YASHANDB_23_5_4_100_REFERENCES: &[DatabaseConfigSchemaReference] = &[
    DatabaseConfigSchemaReference {
        id: "yashandb:23.5.4.100-configuration-parameters",
        title: "YashanDB 23.5.4 configuration parameters",
        url: "https://doc.yashandb.com/yashandb/23.5.4/zh/All-Manuals/Reference-Manual/Configuration-Parameters.html",
    },
    DatabaseConfigSchemaReference {
        id: "yashandb:23.5.4.100-release",
        title: "YashanDB v23.5.4.100 release notes",
        url: "https://doc.yashandb.com/yashandb/23.5/zh/All-Manuals/Product-Overview/Release-Notes/23.5.4.html",
    },
    DatabaseConfigSchemaReference {
        id: "yashandb:23.5-configuration-file-management",
        title: "YashanDB 23.5 configuration parameter file management",
        url: "https://doc.yashandb.com/yashandb/23.5/zh/All-Manuals/Database-Administration/Storage-Management/Database-File-Management/Configuration-Parameter-File-and-Password-File-Management.html",
    },
    DatabaseConfigSchemaReference {
        id: "yashandb:23.5-alter-system",
        title: "YashanDB 23.5 ALTER SYSTEM",
        url: "https://doc.yashandb.com/yashandb/23.5/zh/SQL-Guide/SQL-Statements/ALTER-SYSTEM.html",
    },
    DatabaseConfigSchemaReference {
        id: "yashandb:23.5-global-parameter-configuration",
        title: "YashanDB 23.5 global parameter configuration",
        url: "https://doc.yashandb.com/yashandb/23.5/zh/All-Manuals/Database-Administration/%E2%80%8B%E2%80%8BMultitenant-Management/Global-Parameter-Configuration.html",
    },
];

const YASHANDB_23_5_4_100_YASDB_INI_PARAMETERS: &[DatabaseConfigParameterSchema] = &[
    parameter!(
        None,
        "ARCH_CLEAN_IGNORE_MODE",
        DatabaseConfigSchemaValueKind::Enumeration {
            values: &["NONE", "BACKUP", "STANDBY", "BOTH"],
        },
        VendorDefined,
        Public,
        Dynamic,
        Critical,
        "BACKUP, STANDBY, and BOTH relax archive-cleaning gates; the vendor warns that STANDBY can leave a standby needing repair.",
        "Officially introduced in v22.1. YashanDB forbids direct yasdb.ini edits; this is read-only metadata and never authorizes a change.",
        "yashandb:23.5.4.100-configuration-parameters",
        None,
        Some(DatabaseConfigDocumentedDefault::Enumeration("NONE"))
    ),
    parameter!(
        None,
        "AUDIT_LOG_FILE_COUNT",
        DatabaseConfigSchemaValueKind::Integer {
            minimum_inclusive: 2,
            maximum_inclusive: 10_000,
        },
        VendorDefined,
        Public,
        Dynamic,
        High,
        "Files older than the configured count are deleted, so a small value can remove incident evidence.",
        "Officially introduced in v22.4. YashanDB forbids direct yasdb.ini edits; this is read-only metadata and never authorizes a change.",
        "yashandb:23.5.4.100-configuration-parameters",
        None,
        Some(DatabaseConfigDocumentedDefault::Integer(200))
    ),
    parameter!(
        None,
        "AUDIT_QUEUE_WRITE",
        DatabaseConfigSchemaValueKind::Boolean {
            true_literal: "TRUE",
            false_literal: "FALSE",
        },
        VendorDefined,
        Public,
        Dynamic,
        High,
        "The value selects asynchronous queued audit writes or direct writes and changes the audit durability and performance path.",
        "Officially introduced in v22.2. YashanDB forbids direct yasdb.ini edits; this is read-only metadata and never authorizes a change.",
        "yashandb:23.5.4.100-configuration-parameters",
        None,
        Some(DatabaseConfigDocumentedDefault::Boolean(true))
    ),
    parameter!(
        None,
        "AUDIT_RECORD_TABLE",
        DatabaseConfigSchemaValueKind::Boolean {
            true_literal: "TRUE",
            false_literal: "FALSE",
        },
        VendorDefined,
        Public,
        Dynamic,
        High,
        "TRUE consumes SYSAUX space while FALSE redirects audit records to files controlled by a separate path parameter.",
        "Officially introduced in v23.4. YashanDB forbids direct yasdb.ini edits; this is read-only metadata and never authorizes a change.",
        "yashandb:23.5.4.100-configuration-parameters",
        None,
        Some(DatabaseConfigDocumentedDefault::Boolean(true))
    ),
    parameter!(
        None,
        "DIN_SSL_ENABLE",
        DatabaseConfigSchemaValueKind::Boolean {
            true_literal: "ON",
            false_literal: "OFF",
        },
        VendorDefined,
        Public,
        Restart,
        Critical,
        "OFF leaves distributed-node internal network traffic outside the documented SSL trusted channel.",
        "Officially introduced in v23.3. YashanDB forbids direct yasdb.ini edits; this is read-only metadata and never authorizes a change.",
        "yashandb:23.5.4.100-configuration-parameters",
        None,
        Some(DatabaseConfigDocumentedDefault::Boolean(false))
    ),
    parameter!(
        None,
        "ENABLE_SEPARATE_DUTY",
        DatabaseConfigSchemaValueKind::Boolean {
            true_literal: "TRUE",
            false_literal: "FALSE",
        },
        VendorDefined,
        Public,
        Restart,
        Critical,
        "FALSE disables the documented separation-of-duties security mode.",
        "Officially introduced in v22.2. YashanDB forbids direct yasdb.ini edits; this is read-only metadata and never authorizes a change.",
        "yashandb:23.5.4.100-configuration-parameters",
        None,
        Some(DatabaseConfigDocumentedDefault::Boolean(false))
    ),
    parameter!(
        None,
        "ENCRYPT_TYPE",
        DatabaseConfigSchemaValueKind::Enumeration {
            values: &["SSL", "TLCP"],
        },
        VendorDefined,
        Public,
        Restart,
        Critical,
        "The trusted-channel protocol must remain compatible with the target's certificate and key material.",
        "Officially introduced in v23.2. YashanDB forbids direct yasdb.ini edits; this is read-only metadata and never authorizes a change.",
        "yashandb:23.5.4.100-configuration-parameters",
        None,
        Some(DatabaseConfigDocumentedDefault::Enumeration("SSL"))
    ),
    parameter!(
        None,
        "HA_ELECTION_TIMEOUT",
        DatabaseConfigSchemaValueKind::Integer {
            minimum_inclusive: 1,
            maximum_inclusive: 1_000,
        },
        VendorDefined,
        Public,
        Dynamic,
        Critical,
        "The node group must use one value, and the vendor warns that too small a timeout can trigger failover during a transient network interruption.",
        "Officially introduced in v22.2. YashanDB forbids direct yasdb.ini edits; this is read-only metadata and never authorizes a change.",
        "yashandb:23.5.4.100-configuration-parameters",
        None,
        Some(DatabaseConfigDocumentedDefault::Integer(9))
    ),
    parameter!(
        None,
        "HA_SSL_ENABLE",
        DatabaseConfigSchemaValueKind::Boolean {
            true_literal: "ON",
            false_literal: "OFF",
        },
        VendorDefined,
        Public,
        Restart,
        Critical,
        "OFF leaves the dedicated HA internal link outside the documented SSL trusted channel.",
        "Officially introduced in v22.2. YashanDB forbids direct yasdb.ini edits; this is read-only metadata and never authorizes a change.",
        "yashandb:23.5.4.100-configuration-parameters",
        None,
        Some(DatabaseConfigDocumentedDefault::Boolean(false))
    ),
    parameter!(
        None,
        "LISTENER_LOG_ENABLED",
        DatabaseConfigSchemaValueKind::Boolean {
            true_literal: "TRUE",
            false_literal: "FALSE",
        },
        VendorDefined,
        Public,
        Dynamic,
        Medium,
        "This is the listener-log automatic-cleanup switch, not the listener recording switch; either cleanup or unbounded growth affects evidence handling.",
        "Officially introduced in v23.4. YashanDB forbids direct yasdb.ini edits; this is read-only metadata and never authorizes a change.",
        "yashandb:23.5.4.100-configuration-parameters",
        None,
        Some(DatabaseConfigDocumentedDefault::Boolean(false))
    ),
    parameter!(
        None,
        "MAX_LOGIN_WORKERS",
        DatabaseConfigSchemaValueKind::Integer {
            minimum_inclusive: 1,
            maximum_inclusive: 16,
        },
        VendorDefined,
        Public,
        Restart,
        High,
        "When the thread pool is enabled, this value bounds login workers and therefore affects authentication-plane capacity.",
        "Officially introduced in v23.4.4. YashanDB forbids direct yasdb.ini edits; this is read-only metadata and never authorizes a change.",
        "yashandb:23.5.4.100-configuration-parameters",
        None,
        Some(DatabaseConfigDocumentedDefault::Integer(1))
    ),
    parameter!(
        None,
        "REDOFILE_IO_MODE",
        DatabaseConfigSchemaValueKind::Enumeration {
            values: &["DSYNC", "SYNC", "DIRECT", "DEFAULT"],
        },
        VendorDefined,
        Public,
        Restart,
        Critical,
        "The vendor warns that DEFAULT only writes redo to the system cache and can lose data after power failure; the other documented modes preserve durability.",
        "Officially introduced in v22.2. YashanDB forbids direct yasdb.ini edits; this is read-only metadata and never authorizes a change.",
        "yashandb:23.5.4.100-configuration-parameters",
        None,
        Some(DatabaseConfigDocumentedDefault::Enumeration("DSYNC"))
    ),
    parameter!(
        None,
        "RUN_LOG_LEVEL",
        DatabaseConfigSchemaValueKind::Enumeration {
            values: &[
                "OFF", "FATAL", "ERROR", "WARN", "INFO", "DEBUG", "TRACE", "ALL",
            ],
        },
        VendorDefined,
        Public,
        Dynamic,
        High,
        "OFF removes runtime evidence while verbose modes increase disk use and the amount of operational detail recorded.",
        "Officially introduced in v22.2. YashanDB forbids direct yasdb.ini edits; this is read-only metadata and never authorizes a change.",
        "yashandb:23.5.4.100-configuration-parameters",
        None,
        Some(DatabaseConfigDocumentedDefault::Enumeration("INFO"))
    ),
    parameter!(
        None,
        "SSL_ENABLE",
        DatabaseConfigSchemaValueKind::Boolean {
            true_literal: "ON",
            false_literal: "OFF",
        },
        VendorDefined,
        Public,
        Restart,
        Critical,
        "OFF leaves database client/server traffic outside the documented SSL trusted channel.",
        "Officially introduced in v22.2. YashanDB forbids direct yasdb.ini edits; this is read-only metadata and never authorizes a change.",
        "yashandb:23.5.4.100-configuration-parameters",
        None,
        Some(DatabaseConfigDocumentedDefault::Boolean(false))
    ),
    parameter!(
        None,
        "UNIFIED_AUDITING",
        DatabaseConfigSchemaValueKind::Enumeration {
            values: &["TRUE", "FALSE"],
        },
        VendorDefined,
        Public,
        Dynamic,
        Critical,
        "FALSE disables unified auditing; standby databases do not audit regardless of this value.",
        "Officially introduced in v22.2. YashanDB forbids direct yasdb.ini edits; this is read-only metadata and never authorizes a change.",
        "yashandb:23.5.4.100-configuration-parameters",
        None,
        Some(DatabaseConfigDocumentedDefault::Enumeration("FALSE"))
    ),
];

/// Exact YashanDB v23.5.4.100 yasdb.ini metadata reviewed from the official
/// documentation family. The `edition_key` is an evidence-family guard, not a
/// claim about the target's commercial edition: the release is called AI
/// Edition while operational examples still show Enterprise Edition banners.
/// YashanDB forbids direct edits to this file, so a match only annotates source
/// text and never authorizes generation, mutation, application, or deployment.
pub const YASHANDB_23_5_4_100_YASDB_INI_SCHEMA: DatabaseConfigSchema = DatabaseConfigSchema {
    display_label: "YashanDB yasdb.ini (reviewed partial)",
    version_label: "v23.5.4.100 exact official document family",
    binding: DatabaseConfigSchemaBinding {
        product: DatabaseConfigProduct::Yashan,
        versions: DatabaseConfigVersionSelector::Exact(DatabaseConfigVersion::new_with_revision(
            23, 5, 4, 100,
        )),
        edition_key: Some("official-doc-family-23.5.4.100"),
        component: DatabaseConfigComponent::Server,
        artifact_key: "yashandb-yasdb-ini",
    },
    completeness: DatabaseConfigSchemaCompleteness::Partial,
    parameters: YASHANDB_23_5_4_100_YASDB_INI_PARAMETERS,
    references: YASHANDB_23_5_4_100_REFERENCES,
};

const DM8_REQUIRED_CAPABILITY: Option<&str> = Some("dm8.exact-build-schema-confirmed");

const DM8_REFERENCES: &[DatabaseConfigSchemaReference] = &[
    DatabaseConfigSchemaReference {
        id: "dm:dm8-ini-parameters",
        title: "DM8 administrator manual configuration-file parameters",
        url: "https://eco.dameng.com/document/dm/zh-cn/pm/physical-storage.html",
    },
    DatabaseConfigSchemaReference {
        id: "dm:dm8-parameter-activation",
        title: "DM8 configuration parameter activation FAQ",
        url: "https://eco.dameng.com/document/dm/zh-cn/faq/FAQ_CONFIGURE.html",
    },
    DatabaseConfigSchemaReference {
        id: "dm:dm8-transport-encryption",
        title: "DM8 communication encryption",
        url: "https://eco.dameng.com/document/dm/zh-cn/pm/communication-encryption.html",
    },
];

const DM8_MAIN_PARAMETERS: &[DatabaseConfigParameterSchema] = &[
    parameter!(
        None,
        "PORT_NUM",
        DatabaseConfigSchemaValueKind::Integer {
            minimum_inclusive: 1_024,
            maximum_inclusive: 65_534,
        },
        Instance,
        OperationalMetadata,
        Restart,
        High,
        "The listener port changes the reachable DM service endpoint.",
        "The unpinned manual cannot authorize use until the exact build is confirmed.",
        "dm:dm8-ini-parameters",
        DM8_REQUIRED_CAPABILITY
    ),
    parameter!(
        None,
        "LISTEN_IP",
        text(0, 1_024, DatabaseConfigTextNormalization::Preserve),
        Instance,
        OperationalMetadata,
        Restart,
        Critical,
        "A broad listener expands exposure; a wrong IP can prevent all connections.",
        "The observed address is annotated without inferring vendor defaults.",
        "dm:dm8-ini-parameters",
        DM8_REQUIRED_CAPABILITY
    ),
    parameter!(
        None,
        "MAX_SESSIONS",
        DatabaseConfigSchemaValueKind::Integer {
            minimum_inclusive: 1,
            maximum_inclusive: 150_000,
        },
        Instance,
        Public,
        Restart,
        High,
        "An excessive value can exhaust resources and the license can impose a lower limit.",
        "Connection exhaustion is a common incident symptom.",
        "dm:dm8-ini-parameters",
        DM8_REQUIRED_CAPABILITY
    ),
    parameter!(
        None,
        "MAX_SESSION_MEMORY",
        DatabaseConfigSchemaValueKind::Integer {
            minimum_inclusive: 0,
            maximum_inclusive: 262_144,
        },
        Instance,
        Public,
        VendorProcedure,
        High,
        "Zero means no per-session memory limit and can amplify exhaustion.",
        "Per-session memory explains pressure caused by hostile queries.",
        "dm:dm8-ini-parameters",
        DM8_REQUIRED_CAPABILITY
    ),
    parameter!(
        None,
        "ENABLE_ENCRYPT",
        DatabaseConfigSchemaValueKind::Enumeration {
            values: &["0", "1", "2", "4", "5", "6"],
        },
        Instance,
        Public,
        Restart,
        Critical,
        "Zero disables SSL; nonzero modes require matching server and client cryptographic environments.",
        "A mismatched mode can either expose traffic or prevent service startup and access.",
        "dm:dm8-transport-encryption",
        DM8_REQUIRED_CAPABILITY
    ),
    parameter!(
        None,
        "MIN_SSL_VERSION",
        text(1, 32, DatabaseConfigTextNormalization::TrimAsciiWhitespace),
        Instance,
        Public,
        Restart,
        Critical,
        "Zero permits all supported versions; the manual shows hexadecimal and decimal representations.",
        "Text avoids inventing which lexical forms an unconfirmed build accepts.",
        "dm:dm8-transport-encryption",
        DM8_REQUIRED_CAPABILITY
    ),
    parameter!(
        None,
        "COMM_ENCRYPT_NAME",
        text(0, 512, DatabaseConfigTextNormalization::TrimAsciiWhitespace),
        Instance,
        Public,
        Restart,
        Critical,
        "An empty value disables application-layer encryption and an invalid name can silently fall back.",
        "Accepted algorithms must come from the exact build's V$CIPHERS view.",
        "dm:dm8-ini-parameters",
        DM8_REQUIRED_CAPABILITY
    ),
    parameter!(
        None,
        "COMM_VALIDATE",
        DatabaseConfigSchemaValueKind::Enumeration {
            values: &["0", "1", "2"],
        },
        Global,
        Public,
        VendorProcedure,
        High,
        "Zero disables message validation; mode 2 records error contents that may be sensitive.",
        "The mode affects both integrity checking and log exposure.",
        "dm:dm8-ini-parameters",
        DM8_REQUIRED_CAPABILITY
    ),
    parameter!(
        None,
        "MESSAGE_CHECK",
        DatabaseConfigSchemaValueKind::Boolean {
            true_literal: "1",
            false_literal: "0",
        },
        Global,
        Public,
        VendorProcedure,
        High,
        "Message-body validation works only when both endpoints enable it.",
        "A local toggle alone does not prove protected communication.",
        "dm:dm8-ini-parameters",
        DM8_REQUIRED_CAPABILITY
    ),
    parameter!(
        None,
        "INVITED_IP",
        text(0, 8_192, DatabaseConfigTextNormalization::Preserve),
        Global,
        OperationalMetadata,
        VendorProcedure,
        Critical,
        "An empty or overly broad CIDR allowlist expands database access.",
        "The allowlist is operational topology and must retain exact order and bytes.",
        "dm:dm8-ini-parameters",
        DM8_REQUIRED_CAPABILITY
    ),
    parameter!(
        None,
        "AUTH_ENCRYPT_NAME",
        text(0, 512, DatabaseConfigTextNormalization::TrimAsciiWhitespace),
        Global,
        Public,
        Restart,
        Critical,
        "The password hashing algorithm is build-dependent and an empty value delegates selection.",
        "Accepted names must be confirmed from the exact build rather than inferred.",
        "dm:dm8-ini-parameters",
        DM8_REQUIRED_CAPABILITY
    ),
    parameter!(
        None,
        "AUDIT_FILE_FULL_MODE",
        DatabaseConfigSchemaValueKind::Enumeration {
            values: &["1", "2", "3"],
        },
        Instance,
        Public,
        Restart,
        Critical,
        "The mode can block work, stop auditing, or delete older evidence when space is exhausted.",
        "Audit-full behavior is critical during disk-pressure incidents.",
        "dm:dm8-ini-parameters",
        DM8_REQUIRED_CAPABILITY
    ),
    parameter!(
        None,
        "AUDIT_FLUSH_LEVEL",
        DatabaseConfigSchemaValueKind::Enumeration {
            values: &["0", "1", "2"],
        },
        Global,
        Public,
        VendorProcedure,
        High,
        "Delayed flush increases the evidence-loss window during abrupt failure.",
        "Flush timing explains gaps between activity and durable audit records.",
        "dm:dm8-ini-parameters",
        DM8_REQUIRED_CAPABILITY
    ),
    parameter!(
        None,
        "AUDIT_KEEP_DAYS",
        DatabaseConfigSchemaValueKind::Integer {
            minimum_inclusive: 0,
            maximum_inclusive: 3_660,
        },
        Instance,
        Public,
        Restart,
        High,
        "A short retention period can remove incident evidence.",
        "Retention must be reviewed together with space and full-mode settings.",
        "dm:dm8-ini-parameters",
        DM8_REQUIRED_CAPABILITY
    ),
    parameter!(
        None,
        "AUDIT_SPACE_LIMIT",
        text(1, 32, DatabaseConfigTextNormalization::TrimAsciiWhitespace),
        Instance,
        Public,
        Restart,
        High,
        "Zero is unlimited while nonzero values use a disjoint documented range.",
        "Text preserves the value because the scalar model cannot express zero-or-range safely.",
        "dm:dm8-ini-parameters",
        DM8_REQUIRED_CAPABILITY
    ),
    parameter!(
        None,
        "AUDIT_MAX_FILE_SIZE",
        DatabaseConfigSchemaValueKind::Integer {
            minimum_inclusive: 8,
            maximum_inclusive: 4_096,
        },
        Global,
        Public,
        VendorProcedure,
        Medium,
        "Unsafe file sizing can increase rotation churn or disk pressure.",
        "File sizing affects evidence collection and transport.",
        "dm:dm8-ini-parameters",
        DM8_REQUIRED_CAPABILITY
    ),
    parameter!(
        None,
        "ENABLE_AUDIT",
        DatabaseConfigSchemaValueKind::Enumeration {
            values: &["0", "1", "2"],
        },
        VendorDefined,
        Public,
        VendorProcedure,
        Critical,
        "Zero disables auditing; this manual parameter is not dynamically mutable.",
        "The exact build and vendor procedure must be confirmed before any change.",
        "dm:dm8-ini-parameters",
        DM8_REQUIRED_CAPABILITY
    ),
    parameter!(
        None,
        "SVR_LOG",
        DatabaseConfigSchemaValueKind::Enumeration {
            values: &["0", "1", "2", "3"],
        },
        Global,
        Public,
        VendorProcedure,
        High,
        "SQL logging can expose statements and parameters or, when off, remove response evidence.",
        "The selected mode must be balanced against leakage, disk, and performance impact.",
        "dm:dm8-ini-parameters",
        DM8_REQUIRED_CAPABILITY
    ),
];

/// DM8 family metadata for dm.ini. It is never an automatic-generation grant.
pub const DM8_MAIN_INSPECT_ONLY_SCHEMA: DatabaseConfigSchema = DatabaseConfigSchema {
    display_label: "DM8 dm.ini (manual-unpinned inspect-only partial)",
    version_label: "DM8 family; exact build capability required",
    binding: DatabaseConfigSchemaBinding {
        product: DatabaseConfigProduct::Dm,
        versions: DatabaseConfigVersionSelector::HalfOpen {
            minimum_inclusive: DatabaseConfigVersion::new(8, 0, 0),
            maximum_exclusive: DatabaseConfigVersion::new(9, 0, 0),
        },
        edition_key: Some("manual-unpinned-inspect-only"),
        component: DatabaseConfigComponent::Server,
        artifact_key: "dm-main",
    },
    completeness: DatabaseConfigSchemaCompleteness::Partial,
    parameters: DM8_MAIN_PARAMETERS,
    references: DM8_REFERENCES,
};

const DM8_SQL_LOG_PARAMETERS: &[DatabaseConfigParameterSchema] = &[
    parameter!(
        None,
        "SQL_TRACE_MASK",
        text(
            1,
            1_024,
            DatabaseConfigTextNormalization::TrimAsciiWhitespace
        ),
        VendorDefined,
        Public,
        VendorProcedure,
        Critical,
        "Masks can record raw statements and bit 28 records parameter types and values.",
        "The colon-separated expression is retained without inventing a partial grammar.",
        "dm:dm8-ini-parameters",
        DM8_REQUIRED_CAPABILITY
    ),
    parameter!(
        None,
        "FILE_PATH",
        text(1, 4_096, DatabaseConfigTextNormalization::Preserve),
        VendorDefined,
        OperationalMetadata,
        VendorProcedure,
        High,
        "An unsafe path can expose logs or exhaust the wrong filesystem.",
        "Log storage is response metadata and requires vendor refresh after change.",
        "dm:dm8-ini-parameters",
        DM8_REQUIRED_CAPABILITY
    ),
    parameter!(
        None,
        "FILE_NUM",
        DatabaseConfigSchemaValueKind::Integer {
            minimum_inclusive: 2,
            maximum_inclusive: 1_024,
        },
        VendorDefined,
        Public,
        VendorProcedure,
        High,
        "A low count destroys older evidence; a high count increases disk use.",
        "The value must be considered with file size and switch mode.",
        "dm:dm8-ini-parameters",
        DM8_REQUIRED_CAPABILITY
    ),
    parameter!(
        None,
        "SWITCH_MODE",
        DatabaseConfigSchemaValueKind::Enumeration {
            values: &["0", "1", "2", "3"],
        },
        VendorDefined,
        Public,
        VendorProcedure,
        High,
        "Mode zero disables switching and can create an unbounded active file.",
        "Switch mode changes the unit and valid range of SWITCH_LIMIT.",
        "dm:dm8-ini-parameters",
        DM8_REQUIRED_CAPABILITY
    ),
    parameter!(
        None,
        "SWITCH_LIMIT",
        text(1, 64, DatabaseConfigTextNormalization::TrimAsciiWhitespace),
        VendorDefined,
        Public,
        VendorProcedure,
        High,
        "The range and unit depend on SWITCH_MODE and cannot be validated independently.",
        "Text prevents the scalar pack from falsely proving a cross-field constraint.",
        "dm:dm8-ini-parameters",
        DM8_REQUIRED_CAPABILITY
    ),
];

/// DM8 family metadata for the global sqllog.ini section only.
///
/// Named modes are user-defined. Without wildcard container semantics, their
/// keys deliberately remain visible and unvalidated rather than pretending
/// that every installation uses the example `SLOG_ALL` section.
pub const DM8_SQL_LOG_INSPECT_ONLY_SCHEMA: DatabaseConfigSchema = DatabaseConfigSchema {
    display_label: "DM8 sqllog.ini global section (manual-unpinned inspect-only partial)",
    version_label: "DM8 family; exact build capability required",
    binding: DatabaseConfigSchemaBinding {
        product: DatabaseConfigProduct::Dm,
        versions: DatabaseConfigVersionSelector::HalfOpen {
            minimum_inclusive: DatabaseConfigVersion::new(8, 0, 0),
            maximum_exclusive: DatabaseConfigVersion::new(9, 0, 0),
        },
        edition_key: Some("manual-unpinned-inspect-only"),
        component: DatabaseConfigComponent::Server,
        artifact_key: "dm-sql-log",
    },
    completeness: DatabaseConfigSchemaCompleteness::Partial,
    parameters: DM8_SQL_LOG_PARAMETERS,
    references: DM8_REFERENCES,
};

/// Candidate domestic packs for explicit composition by the registry owner.
/// This module does not register or activate them on its own.
#[cfg(test)]
const DOMESTIC_DATABASE_CONFIG_SCHEMAS: &[DatabaseConfigSchema] = &[
    TIDB_8_5_7_SERVER_TOML_SCHEMA,
    TIKV_8_5_7_TOML_SCHEMA,
    PD_8_5_7_TOML_SCHEMA,
    OPENGAUSS_5_0_0_STANDARD_MAIN_SCHEMA,
    OPENGAUSS_6_0_0_LITE_MAIN_SCHEMA,
    KINGBASE_ES_V8_6_7_12_MAIN_SCHEMA,
    KINGBASE_ES_V9_3_11_MAIN_SCHEMA,
    GOLDENDB_V6_1_03_10_PROXY_INI_SCHEMA,
    DM8_MAIN_INSPECT_ONLY_SCHEMA,
    DM8_SQL_LOG_INSPECT_ONLY_SCHEMA,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database_config::{artifact_by_key, database_starter_contents};
    use crate::database_config_schema::{
        DatabaseConfigParameterLocator, DatabaseConfigSchemaCatalog,
        DatabaseConfigSchemaCatalogError, DatabaseConfigSchemaLookupError,
        DatabaseConfigSchemaTarget, DatabaseConfigSchemaValidationStatus,
    };
    use crate::line_config_visual::{LineConfigDialect, LineConfigVisualDocument};

    const YASHANDB_TEST_SCHEMAS: &[DatabaseConfigSchema] = &[YASHANDB_23_5_4_100_YASDB_INI_SCHEMA];

    fn target(
        product: DatabaseConfigProduct,
        version: DatabaseConfigVersion,
        edition_key: Option<&'static str>,
        component: DatabaseConfigComponent,
        artifact_key: &'static str,
    ) -> DatabaseConfigSchemaTarget<'static> {
        DatabaseConfigSchemaTarget {
            product,
            version,
            edition_key,
            component,
            artifact_key,
        }
    }

    fn activation(
        schema: &DatabaseConfigSchema,
        container_path: Option<&str>,
        key: &str,
    ) -> DatabaseConfigSchemaActivation {
        schema
            .parameter(DatabaseConfigParameterLocator {
                container_path,
                key,
            })
            .unwrap()
            .activation
    }

    #[test]
    fn domestic_catalog_constructs_and_every_pack_is_partial() {
        let catalog = DatabaseConfigSchemaCatalog::new(DOMESTIC_DATABASE_CONFIG_SCHEMAS).unwrap();
        assert_eq!(catalog.schemas().len(), 10);
        assert!(
            catalog
                .schemas()
                .iter()
                .all(|schema| !schema.has_complete_artifact_coverage())
        );
        assert!(
            catalog
                .schemas()
                .iter()
                .flat_map(|schema| schema.references)
                .all(|reference| reference.url.starts_with("https://"))
        );
    }

    #[test]
    fn yashandb_schema_requires_the_exact_build_and_document_family() {
        let catalog = DatabaseConfigSchemaCatalog::new(YASHANDB_TEST_SCHEMAS).unwrap();
        let exact = target(
            DatabaseConfigProduct::Yashan,
            DatabaseConfigVersion::new_with_revision(23, 5, 4, 100),
            Some("official-doc-family-23.5.4.100"),
            DatabaseConfigComponent::Server,
            "yashandb-yasdb-ini",
        );
        let schema = catalog.lookup(exact).unwrap();
        assert_eq!(schema.parameters.len(), 15);
        assert!(!schema.has_complete_artifact_coverage());
        assert!(schema.version_label.contains("official document family"));

        for version in [
            DatabaseConfigVersion::new(23, 5, 4),
            DatabaseConfigVersion::new_with_revision(23, 5, 2, 100),
            DatabaseConfigVersion::new_with_revision(23, 5, 4, 99),
            DatabaseConfigVersion::new_with_revision(23, 5, 4, 101),
        ] {
            let mut unavailable = exact;
            unavailable.version = version;
            assert_eq!(
                catalog.lookup(unavailable),
                Err(DatabaseConfigSchemaLookupError::VersionMismatch)
            );
        }

        for edition_key in [None, Some("enterprise"), Some("ai-edition")] {
            let mut unavailable = exact;
            unavailable.edition_key = edition_key;
            assert_eq!(
                catalog.lookup(unavailable),
                Err(DatabaseConfigSchemaLookupError::EditionMismatch)
            );
        }

        assert!(schema.references.iter().any(|reference| {
            reference.id == "yashandb:23.5.4.100-release"
                && reference.url.ends_with("/Release-Notes/23.5.4.html")
        }));
        assert!(schema.references.iter().any(|reference| {
            reference.id == "yashandb:23.5-configuration-file-management"
                && reference.url.contains("Configuration-Parameter-File")
        }));

        let artifact = crate::database_config::artifact_by_key("yashandb-yasdb-ini").unwrap();
        assert!(artifact.is_file_visual_readable());
        assert!(!artifact.allows_lossless_local_draft());
        assert!(!artifact.dialect.is_generated());
    }

    #[test]
    fn yashandb_23_5_4_100_schema_is_exact_read_only_metadata_and_never_serialized() {
        const SOURCE: &str = "RUN_LOG_LEVEL=DEBUG\r\nCUSTOM_KEEP=literal";
        let catalog = DatabaseConfigSchemaCatalog::new(YASHANDB_TEST_SCHEMAS).unwrap();
        let schema = catalog
            .lookup(target(
                DatabaseConfigProduct::Yashan,
                DatabaseConfigVersion::new_with_revision(23, 5, 4, 100),
                Some("official-doc-family-23.5.4.100"),
                DatabaseConfigComponent::Server,
                "yashandb-yasdb-ini",
            ))
            .unwrap();
        assert_eq!(schema.parameters.len(), 15);
        assert_eq!(
            schema.completeness,
            DatabaseConfigSchemaCompleteness::Partial
        );
        assert_eq!(
            schema.binding.versions,
            DatabaseConfigVersionSelector::Exact(DatabaseConfigVersion::new_with_revision(
                23, 5, 4, 100
            ))
        );
        assert_eq!(
            schema.binding.edition_key,
            Some("official-doc-family-23.5.4.100")
        );

        let artifact = artifact_by_key("yashandb-yasdb-ini").unwrap();
        assert_eq!(artifact.default_file_name, Some("yasdb.ini"));
        assert!(!artifact.allows_lossless_local_draft());
        assert_eq!(database_starter_contents(artifact), "");
        let document = LineConfigVisualDocument::parse(LineConfigDialect::FlatKeyValue, SOURCE)
            .expect("representative YashanDB source");
        let raw_before = document.raw_bytes().to_vec();
        let output_before = document.output().bytes().to_vec();
        let rows = document.rows();
        let run_log = rows
            .iter()
            .find(|row| row.name() == Some("RUN_LOG_LEVEL"))
            .expect("reviewed schema row");
        let validation = schema.validate_normalized_value(
            DatabaseConfigParameterLocator {
                container_path: None,
                key: "RUN_LOG_LEVEL",
            },
            run_log.value().expect("public row value"),
        );
        assert_eq!(
            validation.status(),
            DatabaseConfigSchemaValidationStatus::SyntaxValid
        );
        assert_eq!(validation.normalized_value(), Some("DEBUG"));
        assert_eq!(
            schema
                .parameter(DatabaseConfigParameterLocator {
                    container_path: None,
                    key: "RUN_LOG_LEVEL",
                })
                .and_then(|parameter| parameter.documented_default_for_display())
                .as_deref(),
            Some("INFO")
        );

        assert_eq!(document.raw_bytes(), raw_before);
        assert_eq!(document.output().bytes(), output_before);
        assert_eq!(document.output().bytes(), SOURCE.as_bytes());
        let save_output = document.output();
        let saved = save_output.text().expect("valid UTF-8 save payload");
        assert!(!saved.contains("INFO"));
        assert!(!saved.contains("23.5.4.100"));
        assert!(!saved.contains("official-doc-family"));
        assert!(!saved.contains("Partial"));
    }

    #[test]
    fn yashandb_schema_metadata_is_exact_and_never_implies_file_mutation() {
        let cases = [
            (
                "ARCH_CLEAN_IGNORE_MODE",
                DatabaseConfigSchemaValueKind::Enumeration {
                    values: &["NONE", "BACKUP", "STANDBY", "BOTH"],
                },
                DatabaseConfigDocumentedDefault::Enumeration("NONE"),
                DatabaseConfigSchemaActivation::Dynamic,
                DatabaseConfigSchemaRisk::Critical,
                "v22.1",
            ),
            (
                "AUDIT_LOG_FILE_COUNT",
                DatabaseConfigSchemaValueKind::Integer {
                    minimum_inclusive: 2,
                    maximum_inclusive: 10_000,
                },
                DatabaseConfigDocumentedDefault::Integer(200),
                DatabaseConfigSchemaActivation::Dynamic,
                DatabaseConfigSchemaRisk::High,
                "v22.4",
            ),
            (
                "AUDIT_QUEUE_WRITE",
                DatabaseConfigSchemaValueKind::Boolean {
                    true_literal: "TRUE",
                    false_literal: "FALSE",
                },
                DatabaseConfigDocumentedDefault::Boolean(true),
                DatabaseConfigSchemaActivation::Dynamic,
                DatabaseConfigSchemaRisk::High,
                "v22.2",
            ),
            (
                "AUDIT_RECORD_TABLE",
                DatabaseConfigSchemaValueKind::Boolean {
                    true_literal: "TRUE",
                    false_literal: "FALSE",
                },
                DatabaseConfigDocumentedDefault::Boolean(true),
                DatabaseConfigSchemaActivation::Dynamic,
                DatabaseConfigSchemaRisk::High,
                "v23.4",
            ),
            (
                "DIN_SSL_ENABLE",
                DatabaseConfigSchemaValueKind::Boolean {
                    true_literal: "ON",
                    false_literal: "OFF",
                },
                DatabaseConfigDocumentedDefault::Boolean(false),
                DatabaseConfigSchemaActivation::Restart,
                DatabaseConfigSchemaRisk::Critical,
                "v23.3",
            ),
            (
                "ENABLE_SEPARATE_DUTY",
                DatabaseConfigSchemaValueKind::Boolean {
                    true_literal: "TRUE",
                    false_literal: "FALSE",
                },
                DatabaseConfigDocumentedDefault::Boolean(false),
                DatabaseConfigSchemaActivation::Restart,
                DatabaseConfigSchemaRisk::Critical,
                "v22.2",
            ),
            (
                "ENCRYPT_TYPE",
                DatabaseConfigSchemaValueKind::Enumeration {
                    values: &["SSL", "TLCP"],
                },
                DatabaseConfigDocumentedDefault::Enumeration("SSL"),
                DatabaseConfigSchemaActivation::Restart,
                DatabaseConfigSchemaRisk::Critical,
                "v23.2",
            ),
            (
                "HA_ELECTION_TIMEOUT",
                DatabaseConfigSchemaValueKind::Integer {
                    minimum_inclusive: 1,
                    maximum_inclusive: 1_000,
                },
                DatabaseConfigDocumentedDefault::Integer(9),
                DatabaseConfigSchemaActivation::Dynamic,
                DatabaseConfigSchemaRisk::Critical,
                "v22.2",
            ),
            (
                "HA_SSL_ENABLE",
                DatabaseConfigSchemaValueKind::Boolean {
                    true_literal: "ON",
                    false_literal: "OFF",
                },
                DatabaseConfigDocumentedDefault::Boolean(false),
                DatabaseConfigSchemaActivation::Restart,
                DatabaseConfigSchemaRisk::Critical,
                "v22.2",
            ),
            (
                "LISTENER_LOG_ENABLED",
                DatabaseConfigSchemaValueKind::Boolean {
                    true_literal: "TRUE",
                    false_literal: "FALSE",
                },
                DatabaseConfigDocumentedDefault::Boolean(false),
                DatabaseConfigSchemaActivation::Dynamic,
                DatabaseConfigSchemaRisk::Medium,
                "v23.4",
            ),
            (
                "MAX_LOGIN_WORKERS",
                DatabaseConfigSchemaValueKind::Integer {
                    minimum_inclusive: 1,
                    maximum_inclusive: 16,
                },
                DatabaseConfigDocumentedDefault::Integer(1),
                DatabaseConfigSchemaActivation::Restart,
                DatabaseConfigSchemaRisk::High,
                "v23.4.4",
            ),
            (
                "REDOFILE_IO_MODE",
                DatabaseConfigSchemaValueKind::Enumeration {
                    values: &["DSYNC", "SYNC", "DIRECT", "DEFAULT"],
                },
                DatabaseConfigDocumentedDefault::Enumeration("DSYNC"),
                DatabaseConfigSchemaActivation::Restart,
                DatabaseConfigSchemaRisk::Critical,
                "v22.2",
            ),
            (
                "RUN_LOG_LEVEL",
                DatabaseConfigSchemaValueKind::Enumeration {
                    values: &[
                        "OFF", "FATAL", "ERROR", "WARN", "INFO", "DEBUG", "TRACE", "ALL",
                    ],
                },
                DatabaseConfigDocumentedDefault::Enumeration("INFO"),
                DatabaseConfigSchemaActivation::Dynamic,
                DatabaseConfigSchemaRisk::High,
                "v22.2",
            ),
            (
                "SSL_ENABLE",
                DatabaseConfigSchemaValueKind::Boolean {
                    true_literal: "ON",
                    false_literal: "OFF",
                },
                DatabaseConfigDocumentedDefault::Boolean(false),
                DatabaseConfigSchemaActivation::Restart,
                DatabaseConfigSchemaRisk::Critical,
                "v22.2",
            ),
            (
                "UNIFIED_AUDITING",
                DatabaseConfigSchemaValueKind::Enumeration {
                    values: &["TRUE", "FALSE"],
                },
                DatabaseConfigDocumentedDefault::Enumeration("FALSE"),
                DatabaseConfigSchemaActivation::Dynamic,
                DatabaseConfigSchemaRisk::Critical,
                "v22.2",
            ),
        ];

        assert_eq!(
            YASHANDB_23_5_4_100_YASDB_INI_SCHEMA.parameters.len(),
            cases.len()
        );
        for (key, kind, default, activation, risk, introduced) in cases {
            let parameter = YASHANDB_23_5_4_100_YASDB_INI_SCHEMA
                .parameter(DatabaseConfigParameterLocator {
                    container_path: None,
                    key,
                })
                .unwrap();
            assert_eq!(parameter.container_path, None);
            assert_eq!(parameter.canonical_key, key);
            assert!(parameter.exact_aliases.is_empty());
            assert_eq!(parameter.value_kind, kind);
            assert_eq!(parameter.documented_default, Some(default));
            assert_eq!(parameter.scope, DatabaseConfigSchemaScope::VendorDefined);
            assert_eq!(
                parameter.sensitivity,
                DatabaseConfigSchemaSensitivity::Public
            );
            assert_eq!(parameter.activation, activation);
            assert_eq!(parameter.risk, risk);
            assert_eq!(
                parameter.official_reference_id,
                "yashandb:23.5.4.100-configuration-parameters"
            );
            assert_eq!(parameter.required_capability, None);
            assert!(parameter.competition_rationale.contains(introduced));
            assert!(
                parameter
                    .competition_rationale
                    .contains("forbids direct yasdb.ini edits")
            );
            assert!(parameter.documented_default_for_display().is_some());
        }
    }

    #[test]
    fn yashandb_schema_validates_only_reviewed_exact_literals_and_ranges() {
        let schema = &YASHANDB_23_5_4_100_YASDB_INI_SCHEMA;
        for (key, accepted, rejected) in [
            (
                "ARCH_CLEAN_IGNORE_MODE",
                &["NONE", "BACKUP", "STANDBY", "BOTH"][..],
                &["none", "ALL", ""][..],
            ),
            (
                "AUDIT_QUEUE_WRITE",
                &["TRUE", "FALSE"][..],
                &["true", "ON", "1"][..],
            ),
            (
                "AUDIT_RECORD_TABLE",
                &["TRUE", "FALSE"][..],
                &["true", "ON", "1"][..],
            ),
            (
                "DIN_SSL_ENABLE",
                &["ON", "OFF"][..],
                &["on", "TRUE", "1"][..],
            ),
            (
                "ENABLE_SEPARATE_DUTY",
                &["TRUE", "FALSE"][..],
                &["true", "ON", "1"][..],
            ),
            (
                "ENCRYPT_TYPE",
                &["SSL", "TLCP"][..],
                &["ssl", "GMSSL", ""][..],
            ),
            (
                "HA_SSL_ENABLE",
                &["ON", "OFF"][..],
                &["on", "TRUE", "1"][..],
            ),
            (
                "LISTENER_LOG_ENABLED",
                &["TRUE", "FALSE"][..],
                &["true", "ON", "1"][..],
            ),
            (
                "REDOFILE_IO_MODE",
                &["DSYNC", "SYNC", "DIRECT", "DEFAULT"][..],
                &["dsync", "ASYNC", ""][..],
            ),
            (
                "RUN_LOG_LEVEL",
                &[
                    "OFF", "FATAL", "ERROR", "WARN", "INFO", "DEBUG", "TRACE", "ALL",
                ][..],
                &["off", "NOTICE", ""][..],
            ),
            ("SSL_ENABLE", &["ON", "OFF"][..], &["on", "TRUE", "1"][..]),
            (
                "UNIFIED_AUDITING",
                &["TRUE", "FALSE"][..],
                &["true", "ON", "1"][..],
            ),
        ] {
            let locator = DatabaseConfigParameterLocator {
                container_path: None,
                key,
            };
            for value in accepted {
                assert_eq!(
                    schema.validate_normalized_value(locator, value).status(),
                    DatabaseConfigSchemaValidationStatus::SyntaxValid,
                    "{key} rejected {value}"
                );
            }
            for value in rejected {
                assert!(
                    matches!(
                        schema.validate_normalized_value(locator, value).status(),
                        DatabaseConfigSchemaValidationStatus::Invalid(_)
                    ),
                    "{key} accepted {value}"
                );
            }
        }

        for (key, minimum, maximum) in [
            ("AUDIT_LOG_FILE_COUNT", 2_i64, 10_000_i64),
            ("HA_ELECTION_TIMEOUT", 1, 1_000),
            ("MAX_LOGIN_WORKERS", 1, 16),
        ] {
            let locator = DatabaseConfigParameterLocator {
                container_path: None,
                key,
            };
            for value in [minimum, maximum] {
                assert_eq!(
                    schema
                        .validate_normalized_value(locator, &value.to_string())
                        .status(),
                    DatabaseConfigSchemaValidationStatus::SyntaxValid
                );
            }
            for value in [minimum - 1, maximum + 1] {
                assert!(matches!(
                    schema
                        .validate_normalized_value(locator, &value.to_string())
                        .status(),
                    DatabaseConfigSchemaValidationStatus::Invalid(_)
                ));
            }
        }
    }

    #[test]
    fn yashandb_unreviewed_and_noncanonical_keys_remain_visible_unvalidated() {
        let catalog = DatabaseConfigSchemaCatalog::new(YASHANDB_TEST_SCHEMAS).unwrap();
        let schema = catalog
            .lookup(target(
                DatabaseConfigProduct::Yashan,
                DatabaseConfigVersion::new_with_revision(23, 5, 4, 100),
                Some("official-doc-family-23.5.4.100"),
                DatabaseConfigComponent::Server,
                "yashandb-yasdb-ini",
            ))
            .unwrap();

        for locator in [
            DatabaseConfigParameterLocator {
                container_path: None,
                key: "ssl_enable",
            },
            DatabaseConfigParameterLocator {
                container_path: Some("ROOT"),
                key: "SSL_ENABLE",
            },
            DatabaseConfigParameterLocator {
                container_path: None,
                key: "LISTEN_ADDR",
            },
            DatabaseConfigParameterLocator {
                container_path: None,
                key: "DIN_ADDR",
            },
            DatabaseConfigParameterLocator {
                container_path: None,
                key: "REPLICATION_ADDR",
            },
            DatabaseConfigParameterLocator {
                container_path: None,
                key: "SSL_CERT_FILE",
            },
            DatabaseConfigParameterLocator {
                container_path: None,
                key: "SSL_KEY_FILE",
            },
            DatabaseConfigParameterLocator {
                container_path: None,
                key: "SSL_DH_PARAM_FILE",
            },
            DatabaseConfigParameterLocator {
                container_path: None,
                key: "PASSWORD_FILE",
            },
            DatabaseConfigParameterLocator {
                container_path: None,
                key: "SECURE_FILE_PRIV",
            },
            DatabaseConfigParameterLocator {
                container_path: None,
                key: "WALLET_ROOT",
            },
            DatabaseConfigParameterLocator {
                container_path: None,
                key: "ARCHIVE_DEST_1",
            },
            DatabaseConfigParameterLocator {
                container_path: None,
                key: "REQUIRED_SYNC_STANDBYS",
            },
            DatabaseConfigParameterLocator {
                container_path: None,
                key: "QUORUM_SYNC_STANDBYS",
            },
            DatabaseConfigParameterLocator {
                container_path: None,
                key: "DATA_BUFFER_SIZE",
            },
            DatabaseConfigParameterLocator {
                container_path: None,
                key: "MAX_SESSIONS",
            },
            DatabaseConfigParameterLocator {
                container_path: None,
                key: "MAX_PARALLEL_WORKERS",
            },
            DatabaseConfigParameterLocator {
                container_path: None,
                key: "MAX_IOPS",
            },
        ] {
            assert_eq!(
                schema
                    .validate_normalized_value(locator, "attacker-controlled")
                    .status(),
                DatabaseConfigSchemaValidationStatus::VisibleUnvalidated,
                "unexpectedly validated {locator:?}"
            );
        }
    }

    #[test]
    fn tidb_packs_require_the_exact_patch_and_exact_table_path() {
        let catalog = DatabaseConfigSchemaCatalog::new(DOMESTIC_DATABASE_CONFIG_SCHEMAS).unwrap();
        let server_target = target(
            DatabaseConfigProduct::TiDb,
            DatabaseConfigVersion::new(8, 5, 7),
            None,
            DatabaseConfigComponent::TiDb,
            "tidb-server-toml",
        );
        let server = catalog.lookup(server_target).unwrap();
        assert!(
            server
                .parameter(DatabaseConfigParameterLocator {
                    container_path: Some("security"),
                    key: "ssl-key",
                })
                .is_some()
        );
        assert!(
            server
                .parameter(DatabaseConfigParameterLocator {
                    container_path: None,
                    key: "ssl-key",
                })
                .is_none()
        );

        let mut older_patch = server_target;
        older_patch.version = DatabaseConfigVersion::new(8, 5, 6);
        assert_eq!(
            catalog.lookup(older_patch),
            Err(DatabaseConfigSchemaLookupError::VersionMismatch)
        );

        assert!(
            catalog
                .lookup(target(
                    DatabaseConfigProduct::TiDb,
                    DatabaseConfigVersion::new(8, 5, 7),
                    None,
                    DatabaseConfigComponent::TiKv,
                    "tidb-tikv-toml",
                ))
                .unwrap()
                .parameter(DatabaseConfigParameterLocator {
                    container_path: Some("security.encryption"),
                    key: "data-encryption-method",
                })
                .is_some()
        );
        assert!(
            catalog
                .lookup(target(
                    DatabaseConfigProduct::TiDb,
                    DatabaseConfigVersion::new(8, 5, 7),
                    None,
                    DatabaseConfigComponent::Pd,
                    "tidb-pd-toml",
                ))
                .is_ok()
        );
    }

    #[test]
    fn edition_keys_fail_closed() {
        let catalog = DatabaseConfigSchemaCatalog::new(DOMESTIC_DATABASE_CONFIG_SCHEMAS).unwrap();
        assert!(
            catalog
                .lookup(target(
                    DatabaseConfigProduct::OpenGauss,
                    DatabaseConfigVersion::new(5, 0, 0),
                    Some("enterprise"),
                    DatabaseConfigComponent::Server,
                    "opengauss-main",
                ))
                .is_ok()
        );
        assert_eq!(
            catalog.lookup(target(
                DatabaseConfigProduct::OpenGauss,
                DatabaseConfigVersion::new(5, 0, 0),
                Some("standard"),
                DatabaseConfigComponent::Server,
                "opengauss-main",
            )),
            Err(DatabaseConfigSchemaLookupError::EditionMismatch)
        );
        assert_eq!(
            catalog.lookup(target(
                DatabaseConfigProduct::KingbaseEs,
                DatabaseConfigVersion::new(9, 3, 11),
                Some("oracle-compatible"),
                DatabaseConfigComponent::Server,
                "kingbase-es-main",
            )),
            Err(DatabaseConfigSchemaLookupError::EditionMismatch)
        );
    }

    #[test]
    fn kingbase_v8_requires_all_four_version_segments() {
        let catalog = DatabaseConfigSchemaCatalog::new(DOMESTIC_DATABASE_CONFIG_SCHEMAS).unwrap();
        let exact = target(
            DatabaseConfigProduct::KingbaseEs,
            DatabaseConfigVersion::new_with_revision(8, 6, 7, 12),
            Some("official-doc-family-v8.6.7.12"),
            DatabaseConfigComponent::Server,
            "kingbase-es-main",
        );
        assert!(catalog.lookup(exact).is_ok());

        let mut wrong_revision = exact;
        wrong_revision.version = DatabaseConfigVersion::new_with_revision(8, 6, 7, 11);
        assert_eq!(
            catalog.lookup(wrong_revision),
            Err(DatabaseConfigSchemaLookupError::VersionMismatch)
        );
        assert!(
            catalog
                .lookup(target(
                    DatabaseConfigProduct::KingbaseEs,
                    DatabaseConfigVersion::new(9, 3, 11),
                    Some("official-doc-family-v9.3.11"),
                    DatabaseConfigComponent::Server,
                    "kingbase-es-main",
                ))
                .is_ok()
        );
    }

    #[test]
    fn goldendb_proxy_schema_requires_the_exact_four_part_version_and_no_edition() {
        let catalog = DatabaseConfigSchemaCatalog::new(DOMESTIC_DATABASE_CONFIG_SCHEMAS).unwrap();
        let exact = target(
            DatabaseConfigProduct::GoldenDb,
            DatabaseConfigVersion::new_with_revision(6, 1, 3, 10),
            None,
            DatabaseConfigComponent::Proxy,
            "goldendb-proxy-ini",
        );
        assert_eq!(
            catalog.lookup(exact).unwrap().display_label,
            "GoldenDB compute-node proxy.ini (reviewed partial)"
        );

        for version in [
            DatabaseConfigVersion::new_with_revision(6, 1, 3, 9),
            DatabaseConfigVersion::new_with_revision(6, 1, 3, 11),
            DatabaseConfigVersion::new(6, 1, 3),
        ] {
            let mut unavailable = exact;
            unavailable.version = version;
            assert_eq!(
                catalog.lookup(unavailable),
                Err(DatabaseConfigSchemaLookupError::VersionMismatch)
            );
        }

        let mut wrong_edition = exact;
        wrong_edition.edition_key = Some("61310");
        assert_eq!(
            catalog.lookup(wrong_edition),
            Err(DatabaseConfigSchemaLookupError::EditionMismatch)
        );

        static OVERLAPPING: &[DatabaseConfigSchema] = &[
            GOLDENDB_V6_1_03_10_PROXY_INI_SCHEMA,
            GOLDENDB_V6_1_03_10_PROXY_INI_SCHEMA,
        ];
        assert!(matches!(
            DatabaseConfigSchemaCatalog::new(OVERLAPPING),
            Err(DatabaseConfigSchemaCatalogError::OverlappingSchemas { .. })
        ));
    }

    #[test]
    fn goldendb_proxy_locators_values_and_safety_metadata_are_exact() {
        let cases: &[(&str, &str, &[&str], DatabaseConfigSchemaRisk, &str)] = &[
            (
                "SQLEXEC",
                "update_grade",
                &["0", "1", "2"],
                DatabaseConfigSchemaRisk::Critical,
                "0",
            ),
            (
                "SQLEXEC",
                "select_grade",
                &["0", "1", "2", "3", "4"],
                DatabaseConfigSchemaRisk::Critical,
                "0",
            ),
            (
                "SQLEXEC",
                "mvcc_grade",
                &["0", "1"],
                DatabaseConfigSchemaRisk::High,
                "0",
            ),
            (
                "GENERAL",
                "switch_insert_value_on_duplicate_key_update_sw",
                &["0", "1"],
                DatabaseConfigSchemaRisk::Critical,
                "1",
            ),
            (
                "GENERAL",
                "insert_value_on_duplicate_key_update_usage_level",
                &["0", "1"],
                DatabaseConfigSchemaRisk::Critical,
                "0",
            ),
        ];

        assert_eq!(GOLDENDB_V6_1_03_10_PROXY_INI_SCHEMA.parameters.len(), 5);
        for (container_path, key, expected_values, expected_risk, documented_default) in cases {
            let locator = DatabaseConfigParameterLocator {
                container_path: Some(container_path),
                key,
            };
            let parameter = GOLDENDB_V6_1_03_10_PROXY_INI_SCHEMA
                .parameter(locator)
                .unwrap();
            assert!(parameter.exact_aliases.is_empty());
            assert_eq!(
                parameter.value_kind,
                DatabaseConfigSchemaValueKind::Enumeration {
                    values: expected_values,
                }
            );
            assert_eq!(parameter.scope, DatabaseConfigSchemaScope::Component);
            assert_eq!(
                parameter.sensitivity,
                DatabaseConfigSchemaSensitivity::Public
            );
            assert_eq!(
                parameter.activation,
                DatabaseConfigSchemaActivation::Dynamic
            );
            assert_eq!(parameter.risk, *expected_risk);
            assert_eq!(
                parameter.documented_default,
                Some(DatabaseConfigDocumentedDefault::Enumeration(
                    documented_default
                ))
            );
            assert_eq!(
                parameter.documented_default_for_display().as_deref(),
                Some(*documented_default)
            );
            assert!(
                parameter
                    .competition_rationale
                    .contains(&format!("Official default is {documented_default}"))
            );
            assert!(
                parameter
                    .competition_rationale
                    .contains("not an automatic-fill")
            );

            for value in *expected_values {
                let validation =
                    GOLDENDB_V6_1_03_10_PROXY_INI_SCHEMA.validate_normalized_value(locator, value);
                assert_eq!(
                    validation.status(),
                    DatabaseConfigSchemaValidationStatus::SyntaxValid
                );
                assert_eq!(validation.normalized_value(), Some(*value));
            }
            assert_eq!(
                GOLDENDB_V6_1_03_10_PROXY_INI_SCHEMA
                    .validate_normalized_value(locator, "unsupported")
                    .status(),
                DatabaseConfigSchemaValidationStatus::Invalid(
                    crate::database_config_schema::DatabaseConfigSchemaValueError::UnknownEnumerationValue
                )
            );
        }

        for locator in [
            DatabaseConfigParameterLocator {
                container_path: Some("sqlexec"),
                key: "update_grade",
            },
            DatabaseConfigParameterLocator {
                container_path: Some("SQLEXEC"),
                key: "UPDATE_GRADE",
            },
            DatabaseConfigParameterLocator {
                container_path: Some("GENERAL"),
                key: "parse_mode",
            },
        ] {
            assert_eq!(
                GOLDENDB_V6_1_03_10_PROXY_INI_SCHEMA
                    .validate_normalized_value(locator, "0")
                    .status(),
                DatabaseConfigSchemaValidationStatus::VisibleUnvalidated
            );
        }
    }

    #[test]
    fn goldendb_proxy_references_are_version_pinned_and_field_bound() {
        assert_eq!(GOLDENDB_V6_1_03_10_PROXY_INI_SCHEMA.references.len(), 4);
        for (id, url) in [
            (
                "goldendb:6.1.03.10-version-api",
                "https://www.goldendb.com/document/center/getVersion/1",
            ),
            (
                "goldendb:6.1.03.10-faq-sql",
                "https://www.goldendb.com/docsCenter/GoldenDB/61310/html/FAQ_SQL.html",
            ),
            (
                "goldendb:6.1.03.10-sql-standard",
                "https://www.goldendb.com/docsCenter/GoldenDB/61310/html/developmentSupport_SQLStandard.html",
            ),
            (
                "goldendb:6.1.03.10-dbtool",
                "https://www.goldendb.com/docsCenter/GoldenDB/61310/html/operationManagement_dbtool.html",
            ),
        ] {
            assert!(
                GOLDENDB_V6_1_03_10_PROXY_INI_SCHEMA
                    .references
                    .iter()
                    .any(|reference| reference.id == id && reference.url == url)
            );
        }
        assert!(
            GOLDENDB_V6_1_03_10_PROXY_INI_SCHEMA
                .parameters
                .iter()
                .all(|parameter| matches!(
                    parameter.official_reference_id,
                    "goldendb:6.1.03.10-faq-sql" | "goldendb:6.1.03.10-sql-standard"
                ))
        );
    }

    #[test]
    fn dm8_is_range_visible_but_every_parameter_requires_exact_build_capability() {
        let catalog = DatabaseConfigSchemaCatalog::new(DOMESTIC_DATABASE_CONFIG_SCHEMAS).unwrap();
        for schema in [
            &DM8_MAIN_INSPECT_ONLY_SCHEMA,
            &DM8_SQL_LOG_INSPECT_ONLY_SCHEMA,
        ] {
            assert_eq!(
                schema.binding.edition_key,
                Some("manual-unpinned-inspect-only")
            );
            assert!(schema.parameters.iter().all(|parameter| {
                parameter.required_capability == Some("dm8.exact-build-schema-confirmed")
            }));
        }
        assert!(
            catalog
                .lookup(target(
                    DatabaseConfigProduct::Dm,
                    DatabaseConfigVersion::new_with_revision(8, 99, 99, 99),
                    Some("manual-unpinned-inspect-only"),
                    DatabaseConfigComponent::Server,
                    "dm-main",
                ))
                .is_ok()
        );
        assert_eq!(
            catalog.lookup(target(
                DatabaseConfigProduct::Dm,
                DatabaseConfigVersion::new(8, 1, 0),
                None,
                DatabaseConfigComponent::Server,
                "dm-main",
            )),
            Err(DatabaseConfigSchemaLookupError::EditionMismatch)
        );
    }

    #[test]
    fn exact_tidb_patch_packs_link_immutable_release_and_tag_evidence() {
        for (schema, tagged_configuration_url) in [
            (
                &TIDB_8_5_7_SERVER_TOML_SCHEMA,
                "https://github.com/pingcap/tidb/blob/v8.5.7/pkg/config/config.toml.example",
            ),
            (
                &TIKV_8_5_7_TOML_SCHEMA,
                "https://github.com/tikv/tikv/blob/v8.5.7/etc/config-template.toml",
            ),
            (
                &PD_8_5_7_TOML_SCHEMA,
                "https://github.com/tikv/pd/blob/v8.5.7/conf/config.toml",
            ),
        ] {
            assert!(schema.references.iter().any(|reference| {
                reference.id == "pingcap:tidb-8.5.7-release"
                    && reference.url == "https://docs.pingcap.com/tidb/stable/release-8.5.7/"
            }));
            assert!(
                schema
                    .references
                    .iter()
                    .any(|reference| reference.url == tagged_configuration_url)
            );
        }
    }

    #[test]
    fn file_schema_activation_matches_reviewed_runtime_effects() {
        assert!(
            DOMESTIC_DATABASE_CONFIG_SCHEMAS
                .iter()
                .filter(|schema| schema.binding.artifact_key != "goldendb-proxy-ini")
                .flat_map(|schema| schema.parameters)
                .all(|parameter| parameter.activation != DatabaseConfigSchemaActivation::Dynamic)
        );
        assert!(
            GOLDENDB_V6_1_03_10_PROXY_INI_SCHEMA
                .parameters
                .iter()
                .all(|parameter| parameter.activation == DatabaseConfigSchemaActivation::Dynamic)
        );

        for key in [
            "max_connections",
            "tidb_enable_slow_log",
            "tidb_slow_log_threshold",
        ] {
            assert_eq!(
                activation(&TIDB_8_5_7_SERVER_TOML_SCHEMA, Some("instance"), key),
                DatabaseConfigSchemaActivation::RollingRestart
            );
        }
        for (container_path, key) in [
            (Some("storage.block-cache"), "capacity"),
            (Some("server"), "grpc-memory-pool-quota"),
            (Some("raftstore"), "raft-entry-max-size"),
            (Some("log"), "level"),
        ] {
            assert_eq!(
                activation(&TIKV_8_5_7_TOML_SCHEMA, container_path, key),
                DatabaseConfigSchemaActivation::RollingRestart
            );
        }
        for (container_path, key) in [
            (Some("replication"), "max-replicas"),
            (Some("replication"), "isolation-level"),
            (Some("replication"), "strictly-match-label"),
            (Some("replication"), "enable-placement-rules"),
            (Some("schedule"), "max-store-down-time"),
        ] {
            assert_eq!(
                activation(&PD_8_5_7_TOML_SCHEMA, container_path, key),
                DatabaseConfigSchemaActivation::VendorProcedure
            );
        }
        assert_eq!(
            activation(&PD_8_5_7_TOML_SCHEMA, Some("log"), "level"),
            DatabaseConfigSchemaActivation::RollingRestart
        );

        for key in [
            "synchronous_commit",
            "audit_enabled",
            "audit_login_logout",
            "audit_user_violation",
            "audit_system_object",
        ] {
            assert_eq!(
                activation(&OPENGAUSS_6_0_0_LITE_MAIN_SCHEMA, None, key),
                DatabaseConfigSchemaActivation::Reload
            );
        }
        for key in [
            "MAX_SESSION_MEMORY",
            "COMM_VALIDATE",
            "MESSAGE_CHECK",
            "INVITED_IP",
            "AUDIT_FLUSH_LEVEL",
            "AUDIT_MAX_FILE_SIZE",
            "SVR_LOG",
        ] {
            assert_eq!(
                activation(&DM8_MAIN_INSPECT_ONLY_SCHEMA, None, key),
                DatabaseConfigSchemaActivation::VendorProcedure
            );
        }
    }

    #[test]
    fn unsupported_array_parameters_stay_visible_and_unvalidated() {
        for (schema, container_path, key) in [
            (
                &TIDB_8_5_7_SERVER_TOML_SCHEMA,
                Some("security"),
                "cluster-verify-cn",
            ),
            (&TIKV_8_5_7_TOML_SCHEMA, Some("security"), "cert-allowed-cn"),
            (
                &PD_8_5_7_TOML_SCHEMA,
                Some("replication"),
                "location-labels",
            ),
        ] {
            let validation = schema.validate_normalized_value(
                DatabaseConfigParameterLocator {
                    container_path,
                    key,
                },
                "[]",
            );
            assert_eq!(
                validation.status(),
                DatabaseConfigSchemaValidationStatus::VisibleUnvalidated
            );
        }
    }

    #[test]
    fn session_value_aliases_and_reload_semantics_are_exact() {
        let synchronous_commit = OPENGAUSS_6_0_0_LITE_MAIN_SCHEMA
            .parameter(DatabaseConfigParameterLocator {
                container_path: None,
                key: "synchronous_commit",
            })
            .unwrap();
        assert_eq!(synchronous_commit.scope, DatabaseConfigSchemaScope::Session);
        assert_eq!(
            synchronous_commit.activation,
            DatabaseConfigSchemaActivation::Reload
        );
        assert!(
            synchronous_commit
                .competition_rationale
                .contains("new sessions")
        );
        for alias in ["true", "false", "yes", "no", "1", "0", "2"] {
            assert_eq!(
                OPENGAUSS_6_0_0_LITE_MAIN_SCHEMA
                    .validate_normalized_value(
                        DatabaseConfigParameterLocator {
                            container_path: None,
                            key: "synchronous_commit",
                        },
                        alias,
                    )
                    .status(),
                DatabaseConfigSchemaValidationStatus::SyntaxValid
            );
        }

        let password_encryption = KINGBASE_ES_V8_6_7_12_MAIN_SCHEMA
            .parameter(DatabaseConfigParameterLocator {
                container_path: None,
                key: "password_encryption",
            })
            .unwrap();
        assert_eq!(
            password_encryption.scope,
            DatabaseConfigSchemaScope::Session
        );
        assert_eq!(
            password_encryption.activation,
            DatabaseConfigSchemaActivation::Reload
        );
        assert!(
            password_encryption
                .competition_rationale
                .contains("new sessions")
        );
        assert_eq!(
            KINGBASE_ES_V8_6_7_12_MAIN_SCHEMA
                .validate_normalized_value(
                    DatabaseConfigParameterLocator {
                        container_path: None,
                        key: "password_encryption",
                    },
                    "on",
                )
                .status(),
            DatabaseConfigSchemaValidationStatus::SyntaxValid
        );
    }

    #[test]
    fn kingbase_tls_reload_only_affects_new_connections() {
        for key in [
            "ssl",
            "ssl_ca_file",
            "ssl_cert_file",
            "ssl_key_file",
            "ssl_ciphers",
            "ssl_min_protocol_version",
        ] {
            let parameter = KINGBASE_ES_V8_6_7_12_MAIN_SCHEMA
                .parameter(DatabaseConfigParameterLocator {
                    container_path: None,
                    key,
                })
                .unwrap();
            assert_eq!(parameter.activation, DatabaseConfigSchemaActivation::Reload);
            assert!(parameter.competition_rationale.contains("new connections"));
        }

        let v9_minimum = KINGBASE_ES_V9_3_11_MAIN_SCHEMA
            .parameter(DatabaseConfigParameterLocator {
                container_path: None,
                key: "ssl_min_protocol_version",
            })
            .unwrap();
        assert_eq!(
            v9_minimum.activation,
            DatabaseConfigSchemaActivation::Reload
        );
        assert!(v9_minimum.competition_rationale.contains("new connections"));
    }

    #[test]
    fn all_four_sensitivity_states_are_exercised() {
        let parameters = DOMESTIC_DATABASE_CONFIG_SCHEMAS
            .iter()
            .flat_map(|schema| schema.parameters);
        let all: Vec<_> = parameters.map(|parameter| parameter.sensitivity).collect();
        for expected in [
            DatabaseConfigSchemaSensitivity::Public,
            DatabaseConfigSchemaSensitivity::OperationalMetadata,
            DatabaseConfigSchemaSensitivity::MayContainSecrets,
            DatabaseConfigSchemaSensitivity::PrivateKeyReference,
        ] {
            assert!(all.contains(&expected), "missing sensitivity {expected:?}");
        }
    }

    #[test]
    fn unknown_or_cross_field_ranges_remain_text() {
        for (schema, key) in [
            (&KINGBASE_ES_V8_6_7_12_MAIN_SCHEMA, "port"),
            (&DM8_MAIN_INSPECT_ONLY_SCHEMA, "MIN_SSL_VERSION"),
            (&DM8_MAIN_INSPECT_ONLY_SCHEMA, "AUDIT_SPACE_LIMIT"),
            (&DM8_SQL_LOG_INSPECT_ONLY_SCHEMA, "SWITCH_LIMIT"),
        ] {
            let parameter = schema
                .parameter(DatabaseConfigParameterLocator {
                    container_path: None,
                    key,
                })
                .unwrap();
            assert!(matches!(
                parameter.value_kind,
                DatabaseConfigSchemaValueKind::Text { .. }
            ));
        }
    }
}
