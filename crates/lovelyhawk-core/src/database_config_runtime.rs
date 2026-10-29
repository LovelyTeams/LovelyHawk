//! Closed, read-only discovery plans for database runtime parameters.
//!
//! This module does not connect to a database and never executes SQL. Callers
//! may only select one of the reviewed, static `SELECT` plans below, execute it
//! through a separately owned transport, and feed the headerless hex-TSV
//! result back to the matching plan. Wire-protocol compatibility never grants
//! a plan for another database product.

use std::{fmt, str};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::database_config::{
    DatabaseConfigComponent, DatabaseConfigDialect, DatabaseConfigProduct, DatabaseConfigSurface,
    artifact_by_key,
};
use crate::database_config_schema::{DatabaseConfigVersion, DatabaseConfigVersionSelector};

const RUNTIME_TSV_COLUMNS: usize = 9;
pub const MAX_DATABASE_CONFIG_RUNTIME_TSV_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_DATABASE_CONFIG_RUNTIME_ROWS: usize = 16_384;
pub const MAX_DATABASE_CONFIG_RUNTIME_CELLS: usize =
    MAX_DATABASE_CONFIG_RUNTIME_ROWS * RUNTIME_TSV_COLUMNS;
pub const MAX_DATABASE_CONFIG_RUNTIME_DEPTH: usize = 8;
pub const MAX_DATABASE_CONFIG_RUNTIME_NAME_BYTES: usize = 512;
pub const MAX_DATABASE_CONFIG_RUNTIME_VALUE_BYTES: usize = 64 * 1024;
pub const MAX_DATABASE_CONFIG_RUNTIME_ESCAPED_VALUE_BYTES: usize =
    MAX_DATABASE_CONFIG_RUNTIME_VALUE_BYTES * 6;
pub const MAX_DATABASE_CONFIG_RUNTIME_METADATA_BYTES: usize = 8 * 1024;
pub const MAX_DATABASE_CONFIG_RUNTIME_ENUM_VALUES: usize = 1_024;
pub const MAX_DATABASE_CONFIG_RUNTIME_ENUM_VALUE_BYTES: usize = 4 * 1024;
pub const MAX_DATABASE_CONFIG_RUNTIME_EDITION_KEY_BYTES: usize = 128;
pub const MAX_DATABASE_CONFIG_RUNTIME_IDENTITY_TSV_BYTES: usize = 4 * 1024;

const COMMUNITY_EDITION_KEY: &str = "community";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DatabaseConfigRuntimeSqlProvider {
    /// MySQL's reviewed `performance_schema.variables_info` contract.
    MySqlPerformanceSchema,
    /// MariaDB's reviewed `information_schema.SYSTEM_VARIABLES` contract.
    MariaDbInformationSchema,
    /// PostgreSQL's reviewed `pg_catalog.pg_settings` contract.
    PostgreSqlPgSettings,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseConfigRuntimeWireFormat {
    /// Nine headerless TSV cells per row. Every non-null cell is UTF-8 bytes
    /// encoded as hexadecimal; `-` is the only null sentinel.
    HeaderlessHexTsvV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatabaseConfigRuntimeReference {
    pub id: &'static str,
    pub title: &'static str,
    pub url: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatabaseConfigRuntimeBinding {
    pub product: DatabaseConfigProduct,
    pub versions: DatabaseConfigVersionSelector,
    /// Exact edition key. `None` matches only a target with no edition key.
    pub edition_key: Option<&'static str>,
    pub component: DatabaseConfigComponent,
    /// Exact key from `DATABASE_CONFIG_ARTIFACTS`.
    pub artifact_key: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeEnumEncoding {
    None,
    MariaDbCommaList,
    PostgreSqlJsonArray,
}

#[derive(Debug, Eq, PartialEq)]
pub struct DatabaseConfigRuntimeQueryPlan {
    id: &'static str,
    provider: DatabaseConfigRuntimeSqlProvider,
    binding: DatabaseConfigRuntimeBinding,
    wire_format: DatabaseConfigRuntimeWireFormat,
    reference: DatabaseConfigRuntimeReference,
    query: &'static str,
    enum_encoding: RuntimeEnumEncoding,
}

impl DatabaseConfigRuntimeQueryPlan {
    pub const fn id(&self) -> &'static str {
        self.id
    }

    pub const fn provider(&self) -> DatabaseConfigRuntimeSqlProvider {
        self.provider
    }

    pub const fn binding(&self) -> DatabaseConfigRuntimeBinding {
        self.binding
    }

    pub const fn wire_format(&self) -> DatabaseConfigRuntimeWireFormat {
        self.wire_format
    }

    pub const fn reference(&self) -> DatabaseConfigRuntimeReference {
        self.reference
    }

    /// Returns a reviewed, immutable read-only query. There is deliberately no
    /// parameter or string-building API at this boundary.
    pub const fn query(&self) -> &'static str {
        self.query
    }

    /// Consumes an owned zeroizing buffer. The raw hex wire output is wiped on
    /// both success and error; callers must not retain an unprotected clone.
    pub fn parse_tsv(
        &'static self,
        bytes: Zeroizing<Vec<u8>>,
    ) -> Result<DatabaseConfigRuntimeDocument, DatabaseConfigRuntimeParseError> {
        parse_runtime_tsv(self, &bytes, RuntimeValueDisclosure::Protected)
    }

    /// Only the native, identity-checked PostgreSQL connection calls this. The
    /// remote-client entry point above retains its fully protected value policy.
    pub(crate) fn parse_native_postgresql_tsv(
        &'static self,
        bytes: Zeroizing<Vec<u8>>,
    ) -> Result<DatabaseConfigRuntimeDocument, DatabaseConfigRuntimeParseError> {
        if self.provider != DatabaseConfigRuntimeSqlProvider::PostgreSqlPgSettings
            || self.binding.product != DatabaseConfigProduct::PostgreSql
        {
            return Err(DatabaseConfigRuntimeParseError::InvalidNativeProvider);
        }
        parse_runtime_tsv(self, &bytes, RuntimeValueDisclosure::NativePostgresql)
    }
}

#[derive(Clone, Copy)]
enum RuntimeValueDisclosure {
    Protected,
    NativePostgresql,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatabaseConfigRuntimeTarget<'a> {
    pub provider: DatabaseConfigRuntimeSqlProvider,
    pub product: DatabaseConfigProduct,
    pub version: DatabaseConfigVersion,
    pub edition_key: Option<&'a str>,
    pub component: DatabaseConfigComponent,
    pub artifact_key: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DatabaseConfigRuntimeLookupError {
    #[error("the runtime artifact key is not registered")]
    ArtifactUnknown,
    #[error("the runtime artifact belongs to another product")]
    ProductMismatch,
    #[error("the runtime artifact belongs to another component")]
    ComponentMismatch,
    #[error("the runtime edition key is invalid")]
    InvalidEditionKey,
    #[error("the runtime plan does not cover the exact edition")]
    EditionMismatch,
    #[error("the runtime plan does not cover the exact typed version")]
    VersionMismatch,
    #[error("the artifact is not a supported RuntimeSql discovery surface")]
    Unsupported,
    #[error("the selected provider does not own the exact runtime binding")]
    ProviderMismatch,
    #[error("this exact product/runtime artifact requires a reviewed vendor schema")]
    VendorSchemaRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseConfigRuntimeEdition {
    Community,
}

impl DatabaseConfigRuntimeEdition {
    pub const fn key(self) -> &'static str {
        match self {
            Self::Community => COMMUNITY_EDITION_KEY,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct DatabaseConfigRuntimeIdentityPlan {
    id: &'static str,
    declared_product: DatabaseConfigProduct,
    wire_format: DatabaseConfigRuntimeWireFormat,
    expected_columns: usize,
    query: &'static str,
}

impl DatabaseConfigRuntimeIdentityPlan {
    pub const fn id(&self) -> &'static str {
        self.id
    }

    pub const fn declared_product(&self) -> DatabaseConfigProduct {
        self.declared_product
    }

    pub const fn wire_format(&self) -> DatabaseConfigRuntimeWireFormat {
        self.wire_format
    }

    pub const fn expected_columns(&self) -> usize {
        self.expected_columns
    }

    /// Returns a closed, immutable identity query. There is no parameter or
    /// string-building API at this boundary.
    pub const fn query(&self) -> &'static str {
        self.query
    }

    /// Consumes and wipes the complete identity wire output on every path.
    pub fn parse_tsv(
        &'static self,
        bytes: Zeroizing<Vec<u8>>,
    ) -> Result<DatabaseConfigRuntimeIdentity, DatabaseConfigRuntimeIdentityParseError> {
        parse_runtime_identity_tsv(self, &bytes)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DatabaseConfigRuntimeIdentity {
    product: DatabaseConfigProduct,
    version: DatabaseConfigVersion,
    edition: DatabaseConfigRuntimeEdition,
}

impl fmt::Debug for DatabaseConfigRuntimeIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatabaseConfigRuntimeIdentity")
            .field("product", &self.product)
            .field("version", &self.version)
            .field("edition", &self.edition)
            .finish()
    }
}

impl DatabaseConfigRuntimeIdentity {
    pub const fn product(self) -> DatabaseConfigProduct {
        self.product
    }

    pub const fn version(self) -> DatabaseConfigVersion {
        self.version
    }

    pub const fn edition(self) -> DatabaseConfigRuntimeEdition {
        self.edition
    }

    /// Builds the only runtime target authorized by this verified identity.
    /// Provider, component, artifact, and edition are all core-owned constants.
    pub const fn runtime_target(self) -> DatabaseConfigRuntimeTarget<'static> {
        let (provider, artifact_key) = match self.product {
            DatabaseConfigProduct::MySql => (
                DatabaseConfigRuntimeSqlProvider::MySqlPerformanceSchema,
                "mysql-runtime-variables",
            ),
            DatabaseConfigProduct::MariaDb => (
                DatabaseConfigRuntimeSqlProvider::MariaDbInformationSchema,
                "mariadb-runtime-variables",
            ),
            DatabaseConfigProduct::PostgreSql => (
                DatabaseConfigRuntimeSqlProvider::PostgreSqlPgSettings,
                "postgresql-runtime-parameters",
            ),
            _ => unreachable!(),
        };
        DatabaseConfigRuntimeTarget {
            provider,
            product: self.product,
            version: self.version,
            edition_key: Some(self.edition.key()),
            component: DatabaseConfigComponent::RuntimeParameters,
            artifact_key,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DatabaseConfigRuntimeIdentityLookupError {
    #[error("the declared product has no reviewed native runtime identity plan")]
    UnsupportedDeclaredProduct,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DatabaseConfigRuntimeIdentityParseError {
    #[error("runtime identity TSV exceeds the byte limit")]
    InputTooLarge,
    #[error("runtime identity TSV must contain exactly one row")]
    InvalidRowCount,
    #[error("runtime identity TSV has {actual} columns; expected {expected}")]
    InvalidColumnCount { expected: usize, actual: usize },
    #[error("runtime identity TSV contains an invalid wire byte at offset {offset}")]
    InvalidWireByte { offset: usize },
    #[error("runtime identity TSV contains a forbidden control byte at offset {offset}")]
    ControlCharacter { offset: usize },
    #[error("runtime identity column {column} is null")]
    RequiredCellMissing { column: usize },
    #[error("runtime identity column {column} is not hexadecimal")]
    InvalidHex { column: usize },
    #[error("runtime identity column {column} is not UTF-8")]
    InvalidUtf8 { column: usize },
    #[error("runtime identity column {column} contains a forbidden display character")]
    DecodedControlCharacter { column: usize },
    #[error("runtime identity does not match the declared database product")]
    DeclaredProductMismatch,
    #[error("runtime identity has no reviewed community/upstream signature")]
    UntrustedIdentity,
    #[error("runtime identity reports an enterprise, managed, or unknown edition")]
    UntrustedEdition,
    #[error("runtime identity contains an invalid version")]
    InvalidVersion,
    #[error("pre-release or development database versions are not supported")]
    PreReleaseOrDevelopment,
    #[error("runtime identity version sources disagree")]
    InconsistentVersionSources,
    #[error("runtime identity version is outside the reviewed range")]
    UnsupportedVersion,
}

pub fn database_config_runtime_identity_plan(
    declared_product: DatabaseConfigProduct,
) -> Result<&'static DatabaseConfigRuntimeIdentityPlan, DatabaseConfigRuntimeIdentityLookupError> {
    DATABASE_CONFIG_RUNTIME_IDENTITY_PLANS
        .iter()
        .find(|plan| plan.declared_product == declared_product)
        .ok_or(DatabaseConfigRuntimeIdentityLookupError::UnsupportedDeclaredProduct)
}

/// Selects a plan only when provider, product, component, and artifact all
/// match exactly. A MySQL/PostgreSQL-compatible protocol is never considered.
pub fn database_config_runtime_query_plan(
    target: DatabaseConfigRuntimeTarget<'_>,
) -> Result<&'static DatabaseConfigRuntimeQueryPlan, DatabaseConfigRuntimeLookupError> {
    if target.edition_key.is_some_and(|edition| {
        edition.is_empty()
            || edition.len() > MAX_DATABASE_CONFIG_RUNTIME_EDITION_KEY_BYTES
            || edition.chars().any(is_unsafe_display_character)
    }) {
        return Err(DatabaseConfigRuntimeLookupError::InvalidEditionKey);
    }
    let artifact = artifact_by_key(target.artifact_key)
        .ok_or(DatabaseConfigRuntimeLookupError::ArtifactUnknown)?;
    if artifact.product != target.product {
        return Err(DatabaseConfigRuntimeLookupError::ProductMismatch);
    }
    if artifact.component != target.component {
        return Err(DatabaseConfigRuntimeLookupError::ComponentMismatch);
    }
    if artifact.surface != DatabaseConfigSurface::RuntimeSql
        || artifact.dialect != DatabaseConfigDialect::RuntimeSql
    {
        return Err(DatabaseConfigRuntimeLookupError::Unsupported);
    }

    let mut binding_found = false;
    let mut edition_found = false;
    let mut version_found = false;
    for plan in DATABASE_CONFIG_RUNTIME_QUERY_PLANS {
        if plan.binding.product != target.product
            || plan.binding.component != target.component
            || plan.binding.artifact_key != target.artifact_key
        {
            continue;
        }
        binding_found = true;
        if plan.binding.edition_key != target.edition_key {
            continue;
        }
        edition_found = true;
        if !plan.binding.versions.contains(target.version) {
            continue;
        }
        version_found = true;
        if plan.provider == target.provider {
            return Ok(plan);
        }
    }
    if !binding_found {
        return Err(DatabaseConfigRuntimeLookupError::VendorSchemaRequired);
    }
    if !edition_found {
        return Err(DatabaseConfigRuntimeLookupError::EditionMismatch);
    }
    if !version_found {
        return Err(DatabaseConfigRuntimeLookupError::VersionMismatch);
    }
    Err(DatabaseConfigRuntimeLookupError::ProviderMismatch)
}

const MYSQL_IDENTITY_QUERY: &str = r#"SELECT
  HEX(CONVERT(@@version USING utf8mb4)),
  HEX(CONVERT(@@version_comment USING utf8mb4))"#;

const MARIADB_IDENTITY_QUERY: &str = r#"SELECT
  HEX(CONVERT(@@version USING utf8mb4))"#;

const POSTGRESQL_IDENTITY_QUERY: &str = r#"SELECT
  pg_catalog.encode(pg_catalog.convert_to(pg_catalog.current_setting('server_version_num'), 'UTF8'), 'hex'),
  pg_catalog.encode(pg_catalog.convert_to(pg_catalog.current_setting('server_version'), 'UTF8'), 'hex'),
  pg_catalog.encode(pg_catalog.convert_to(pg_catalog.version(), 'UTF8'), 'hex')"#;

const DATABASE_CONFIG_RUNTIME_IDENTITY_PLANS: &[DatabaseConfigRuntimeIdentityPlan] = &[
    DatabaseConfigRuntimeIdentityPlan {
        id: "mysql-native-community-identity-v1",
        declared_product: DatabaseConfigProduct::MySql,
        wire_format: DatabaseConfigRuntimeWireFormat::HeaderlessHexTsvV1,
        expected_columns: 2,
        query: MYSQL_IDENTITY_QUERY,
    },
    DatabaseConfigRuntimeIdentityPlan {
        id: "mariadb-native-community-identity-v1",
        declared_product: DatabaseConfigProduct::MariaDb,
        wire_format: DatabaseConfigRuntimeWireFormat::HeaderlessHexTsvV1,
        expected_columns: 1,
        query: MARIADB_IDENTITY_QUERY,
    },
    DatabaseConfigRuntimeIdentityPlan {
        id: "postgresql-native-community-identity-v1",
        declared_product: DatabaseConfigProduct::PostgreSql,
        wire_format: DatabaseConfigRuntimeWireFormat::HeaderlessHexTsvV1,
        expected_columns: 3,
        query: POSTGRESQL_IDENTITY_QUERY,
    },
];

const MYSQL_REFERENCE: DatabaseConfigRuntimeReference = DatabaseConfigRuntimeReference {
    id: "mysql-8-performance-schema-variables-info",
    title: "MySQL Reference Manual: Performance Schema variables_info Table",
    url: "https://dev.mysql.com/doc/refman/8.0/en/performance-schema-variables-info-table.html",
};

const MYSQL_84_REFERENCE: DatabaseConfigRuntimeReference = DatabaseConfigRuntimeReference {
    id: "mysql-8.4-performance-schema-variables-info",
    title: "MySQL 8.4 Reference Manual: Performance Schema variables_info Table",
    url: "https://dev.mysql.com/doc/refman/8.4/en/performance-schema-variables-info-table.html",
};

const MARIADB_1011_REFERENCE: DatabaseConfigRuntimeReference = DatabaseConfigRuntimeReference {
    id: "mariadb-10.11-information-schema-system-variables",
    title: "MariaDB 10.11 Documentation: Information Schema SYSTEM_VARIABLES Table",
    url: "https://mariadb.com/docs/server/reference/system-tables/information-schema/information-schema-tables/information-schema-system_variables-table",
};

const MARIADB_114_REFERENCE: DatabaseConfigRuntimeReference = DatabaseConfigRuntimeReference {
    id: "mariadb-11.4-information-schema-system-variables",
    title: "MariaDB 11.4 Documentation: Information Schema SYSTEM_VARIABLES Table",
    url: "https://mariadb.com/docs/server/reference/system-tables/information-schema/information-schema-tables/information-schema-system_variables-table",
};

const POSTGRESQL_16_REFERENCE: DatabaseConfigRuntimeReference = DatabaseConfigRuntimeReference {
    id: "postgresql-16-pg-settings",
    title: "PostgreSQL 16 Documentation: pg_settings",
    url: "https://www.postgresql.org/docs/16/view-pg-settings.html",
};

const POSTGRESQL_17_REFERENCE: DatabaseConfigRuntimeReference = DatabaseConfigRuntimeReference {
    id: "postgresql-17-pg-settings",
    title: "PostgreSQL 17 Documentation: pg_settings",
    url: "https://www.postgresql.org/docs/17/view-pg-settings.html",
};

const POSTGRESQL_18_REFERENCE: DatabaseConfigRuntimeReference = DatabaseConfigRuntimeReference {
    id: "postgresql-18-pg-settings",
    title: "PostgreSQL 18 Documentation: pg_settings",
    url: "https://www.postgresql.org/docs/18/view-pg-settings.html",
};

// These statements return the exact nine-cell wire layout documented by
// `HeaderlessHexTsvV1`: name, current value, scope, apply/context, source,
// pending_restart, minimum, maximum, and enum metadata. The transport must
// disable column headers and must not reinterpret the returned cells.
const MYSQL_RUNTIME_QUERY: &str = r#"SELECT
  HEX(CONVERT(vi.VARIABLE_NAME USING utf8mb4)),
  CASE WHEN gv.VARIABLE_VALUE IS NULL THEN '-' ELSE HEX(CONVERT(gv.VARIABLE_VALUE USING utf8mb4)) END,
  HEX('global'),
  HEX('vendor-defined'),
  CASE WHEN vi.VARIABLE_SOURCE IS NULL THEN '-' ELSE HEX(CONVERT(vi.VARIABLE_SOURCE USING utf8mb4)) END,
  '-',
  CASE WHEN vi.MIN_VALUE IS NULL THEN '-' ELSE HEX(CONVERT(vi.MIN_VALUE USING utf8mb4)) END,
  CASE WHEN vi.MAX_VALUE IS NULL THEN '-' ELSE HEX(CONVERT(vi.MAX_VALUE USING utf8mb4)) END,
  '-'
FROM performance_schema.variables_info AS vi
INNER JOIN performance_schema.global_variables AS gv USING (VARIABLE_NAME)
ORDER BY vi.VARIABLE_NAME"#;

const MARIADB_RUNTIME_QUERY: &str = r#"SELECT
  HEX(CONVERT(VARIABLE_NAME USING utf8mb4)),
  CASE WHEN COALESCE(GLOBAL_VALUE, SESSION_VALUE) IS NULL THEN '-' ELSE HEX(CONVERT(COALESCE(GLOBAL_VALUE, SESSION_VALUE) USING utf8mb4)) END,
  HEX(CONVERT(VARIABLE_SCOPE USING utf8mb4)),
  HEX(CASE WHEN READ_ONLY = 'YES' THEN 'read-only' ELSE 'dynamic' END),
  CASE WHEN GLOBAL_VALUE_ORIGIN IS NULL THEN '-' ELSE HEX(CONVERT(GLOBAL_VALUE_ORIGIN USING utf8mb4)) END,
  '-',
  CASE WHEN NUMERIC_MIN_VALUE IS NULL THEN '-' ELSE HEX(CONVERT(NUMERIC_MIN_VALUE USING utf8mb4)) END,
  CASE WHEN NUMERIC_MAX_VALUE IS NULL THEN '-' ELSE HEX(CONVERT(NUMERIC_MAX_VALUE USING utf8mb4)) END,
  CASE WHEN ENUM_VALUE_LIST IS NULL THEN '-' ELSE HEX(CONVERT(ENUM_VALUE_LIST USING utf8mb4)) END
FROM information_schema.SYSTEM_VARIABLES
ORDER BY VARIABLE_NAME"#;

const POSTGRESQL_RUNTIME_QUERY: &str = r#"SELECT
  pg_catalog.encode(pg_catalog.convert_to(name, 'UTF8'), 'hex'),
  CASE WHEN setting IS NULL THEN '-' ELSE pg_catalog.encode(pg_catalog.convert_to(setting, 'UTF8'), 'hex') END,
  pg_catalog.encode(pg_catalog.convert_to('server-or-session', 'UTF8'), 'hex'),
  pg_catalog.encode(pg_catalog.convert_to(context, 'UTF8'), 'hex'),
  CASE WHEN source IS NULL THEN '-' ELSE pg_catalog.encode(pg_catalog.convert_to(source, 'UTF8'), 'hex') END,
  pg_catalog.encode(pg_catalog.convert_to(pending_restart::pg_catalog.text, 'UTF8'), 'hex'),
  CASE WHEN min_val IS NULL THEN '-' ELSE pg_catalog.encode(pg_catalog.convert_to(min_val, 'UTF8'), 'hex') END,
  CASE WHEN max_val IS NULL THEN '-' ELSE pg_catalog.encode(pg_catalog.convert_to(max_val, 'UTF8'), 'hex') END,
  CASE WHEN enumvals IS NULL THEN '-' ELSE pg_catalog.encode(pg_catalog.convert_to(pg_catalog.array_to_json(enumvals)::pg_catalog.text, 'UTF8'), 'hex') END
FROM pg_catalog.pg_settings
ORDER BY name"#;

const DATABASE_CONFIG_RUNTIME_QUERY_PLANS: &[DatabaseConfigRuntimeQueryPlan] = &[
    DatabaseConfigRuntimeQueryPlan {
        id: "mysql-8.0-runtime-read-only-v1",
        provider: DatabaseConfigRuntimeSqlProvider::MySqlPerformanceSchema,
        binding: DatabaseConfigRuntimeBinding {
            product: DatabaseConfigProduct::MySql,
            versions: DatabaseConfigVersionSelector::HalfOpen {
                minimum_inclusive: DatabaseConfigVersion::new(8, 0, 11),
                maximum_exclusive: DatabaseConfigVersion::new(8, 1, 0),
            },
            edition_key: Some(COMMUNITY_EDITION_KEY),
            component: DatabaseConfigComponent::RuntimeParameters,
            artifact_key: "mysql-runtime-variables",
        },
        wire_format: DatabaseConfigRuntimeWireFormat::HeaderlessHexTsvV1,
        reference: MYSQL_REFERENCE,
        query: MYSQL_RUNTIME_QUERY,
        enum_encoding: RuntimeEnumEncoding::None,
    },
    DatabaseConfigRuntimeQueryPlan {
        id: "mysql-8.4-runtime-read-only-v1",
        provider: DatabaseConfigRuntimeSqlProvider::MySqlPerformanceSchema,
        binding: DatabaseConfigRuntimeBinding {
            product: DatabaseConfigProduct::MySql,
            versions: DatabaseConfigVersionSelector::HalfOpen {
                minimum_inclusive: DatabaseConfigVersion::new(8, 4, 0),
                maximum_exclusive: DatabaseConfigVersion::new(8, 5, 0),
            },
            edition_key: Some(COMMUNITY_EDITION_KEY),
            component: DatabaseConfigComponent::RuntimeParameters,
            artifact_key: "mysql-runtime-variables",
        },
        wire_format: DatabaseConfigRuntimeWireFormat::HeaderlessHexTsvV1,
        reference: MYSQL_84_REFERENCE,
        query: MYSQL_RUNTIME_QUERY,
        enum_encoding: RuntimeEnumEncoding::None,
    },
    DatabaseConfigRuntimeQueryPlan {
        id: "mariadb-10.11-runtime-read-only-v1",
        provider: DatabaseConfigRuntimeSqlProvider::MariaDbInformationSchema,
        binding: DatabaseConfigRuntimeBinding {
            product: DatabaseConfigProduct::MariaDb,
            versions: DatabaseConfigVersionSelector::HalfOpen {
                minimum_inclusive: DatabaseConfigVersion::new(10, 11, 0),
                maximum_exclusive: DatabaseConfigVersion::new(10, 12, 0),
            },
            edition_key: Some(COMMUNITY_EDITION_KEY),
            component: DatabaseConfigComponent::RuntimeParameters,
            artifact_key: "mariadb-runtime-variables",
        },
        wire_format: DatabaseConfigRuntimeWireFormat::HeaderlessHexTsvV1,
        reference: MARIADB_1011_REFERENCE,
        query: MARIADB_RUNTIME_QUERY,
        enum_encoding: RuntimeEnumEncoding::MariaDbCommaList,
    },
    DatabaseConfigRuntimeQueryPlan {
        id: "mariadb-11.4-runtime-read-only-v1",
        provider: DatabaseConfigRuntimeSqlProvider::MariaDbInformationSchema,
        binding: DatabaseConfigRuntimeBinding {
            product: DatabaseConfigProduct::MariaDb,
            versions: DatabaseConfigVersionSelector::HalfOpen {
                minimum_inclusive: DatabaseConfigVersion::new(11, 4, 0),
                maximum_exclusive: DatabaseConfigVersion::new(11, 5, 0),
            },
            edition_key: Some(COMMUNITY_EDITION_KEY),
            component: DatabaseConfigComponent::RuntimeParameters,
            artifact_key: "mariadb-runtime-variables",
        },
        wire_format: DatabaseConfigRuntimeWireFormat::HeaderlessHexTsvV1,
        reference: MARIADB_114_REFERENCE,
        query: MARIADB_RUNTIME_QUERY,
        enum_encoding: RuntimeEnumEncoding::MariaDbCommaList,
    },
    DatabaseConfigRuntimeQueryPlan {
        id: "postgresql-16-runtime-read-only-v1",
        provider: DatabaseConfigRuntimeSqlProvider::PostgreSqlPgSettings,
        binding: DatabaseConfigRuntimeBinding {
            product: DatabaseConfigProduct::PostgreSql,
            versions: DatabaseConfigVersionSelector::HalfOpen {
                minimum_inclusive: DatabaseConfigVersion::new(16, 0, 0),
                maximum_exclusive: DatabaseConfigVersion::new(17, 0, 0),
            },
            edition_key: Some(COMMUNITY_EDITION_KEY),
            component: DatabaseConfigComponent::RuntimeParameters,
            artifact_key: "postgresql-runtime-parameters",
        },
        wire_format: DatabaseConfigRuntimeWireFormat::HeaderlessHexTsvV1,
        reference: POSTGRESQL_16_REFERENCE,
        query: POSTGRESQL_RUNTIME_QUERY,
        enum_encoding: RuntimeEnumEncoding::PostgreSqlJsonArray,
    },
    DatabaseConfigRuntimeQueryPlan {
        id: "postgresql-17-runtime-read-only-v1",
        provider: DatabaseConfigRuntimeSqlProvider::PostgreSqlPgSettings,
        binding: DatabaseConfigRuntimeBinding {
            product: DatabaseConfigProduct::PostgreSql,
            versions: DatabaseConfigVersionSelector::HalfOpen {
                minimum_inclusive: DatabaseConfigVersion::new(17, 0, 0),
                maximum_exclusive: DatabaseConfigVersion::new(18, 0, 0),
            },
            edition_key: Some(COMMUNITY_EDITION_KEY),
            component: DatabaseConfigComponent::RuntimeParameters,
            artifact_key: "postgresql-runtime-parameters",
        },
        wire_format: DatabaseConfigRuntimeWireFormat::HeaderlessHexTsvV1,
        reference: POSTGRESQL_17_REFERENCE,
        query: POSTGRESQL_RUNTIME_QUERY,
        enum_encoding: RuntimeEnumEncoding::PostgreSqlJsonArray,
    },
    DatabaseConfigRuntimeQueryPlan {
        id: "postgresql-18-runtime-read-only-v1",
        provider: DatabaseConfigRuntimeSqlProvider::PostgreSqlPgSettings,
        binding: DatabaseConfigRuntimeBinding {
            product: DatabaseConfigProduct::PostgreSql,
            versions: DatabaseConfigVersionSelector::HalfOpen {
                minimum_inclusive: DatabaseConfigVersion::new(18, 0, 0),
                maximum_exclusive: DatabaseConfigVersion::new(19, 0, 0),
            },
            edition_key: Some(COMMUNITY_EDITION_KEY),
            component: DatabaseConfigComponent::RuntimeParameters,
            artifact_key: "postgresql-runtime-parameters",
        },
        wire_format: DatabaseConfigRuntimeWireFormat::HeaderlessHexTsvV1,
        reference: POSTGRESQL_18_REFERENCE,
        query: POSTGRESQL_RUNTIME_QUERY,
        enum_encoding: RuntimeEnumEncoding::PostgreSqlJsonArray,
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseConfigRuntimeScope {
    Global,
    GlobalAndSession,
    SessionOnly,
    ServerOrSession,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostgreSqlRuntimeContext {
    Internal,
    Postmaster,
    Sighup,
    SuperuserBackend,
    Backend,
    Superuser,
    User,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseConfigRuntimeApply {
    VendorDefined,
    Dynamic,
    ReadOnly,
    PostgreSql(PostgreSqlRuntimeContext),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseConfigRuntimeSensitivity {
    Public,
    MayContainSecrets,
    PrivateKeyReference,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseConfigRuntimeValuePresence {
    Null,
    Empty,
    Present,
}

#[derive(Clone)]
pub struct DatabaseConfigRuntimeValue {
    sensitivity: DatabaseConfigRuntimeSensitivity,
    presence: DatabaseConfigRuntimeValuePresence,
    public_value: Option<String>,
    public_value_was_escaped: bool,
    sensitive_sha256: Option<[u8; 32]>,
}

impl fmt::Debug for DatabaseConfigRuntimeValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("DatabaseConfigRuntimeValue");
        debug
            .field("sensitivity", &self.sensitivity)
            .field("presence", &self.presence)
            .field(
                "display_bytes",
                &self.public_value.as_ref().map(String::len),
            )
            .field("escaped", &self.public_value_was_escaped)
            .field("value", &"<omitted>");
        debug.finish()
    }
}

impl DatabaseConfigRuntimeValue {
    pub const fn sensitivity(&self) -> DatabaseConfigRuntimeSensitivity {
        self.sensitivity
    }

    pub const fn presence(&self) -> DatabaseConfigRuntimeValuePresence {
        self.presence
    }

    /// Returns a bounded, display-safe value only for parameters classified as
    /// public. Unsafe display/control characters are represented as escapes.
    pub fn public_value(&self) -> Option<&str> {
        (self.sensitivity == DatabaseConfigRuntimeSensitivity::Public)
            .then_some(self.public_value.as_deref())
            .flatten()
    }

    pub const fn public_value_was_escaped(&self) -> bool {
        self.public_value_was_escaped
    }

    /// Reports whether an internal comparison fingerprint was retained without
    /// exposing the digest as a public low-entropy guessing oracle.
    pub const fn has_redacted_fingerprint(&self) -> bool {
        self.sensitive_sha256.is_some()
    }
}

#[derive(Clone)]
pub struct DatabaseConfigRuntimeRow {
    name: String,
    value: DatabaseConfigRuntimeValue,
    scope: DatabaseConfigRuntimeScope,
    apply: DatabaseConfigRuntimeApply,
    source: Option<String>,
    pending_restart: Option<bool>,
    minimum: Option<String>,
    maximum: Option<String>,
    enum_values: Vec<String>,
}

impl fmt::Debug for DatabaseConfigRuntimeRow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatabaseConfigRuntimeRow")
            .field("name_bytes", &self.name.len())
            .field("value", &self.value)
            .field("scope", &self.scope)
            .field("apply", &self.apply)
            .field("source_present", &self.source.is_some())
            .field("pending_restart", &self.pending_restart)
            .field("minimum_present", &self.minimum.is_some())
            .field("maximum_present", &self.maximum.is_some())
            .field("enum_value_count", &self.enum_values.len())
            .finish()
    }
}

impl DatabaseConfigRuntimeRow {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn value(&self) -> &DatabaseConfigRuntimeValue {
        &self.value
    }

    pub const fn scope(&self) -> DatabaseConfigRuntimeScope {
        self.scope
    }

    pub const fn apply(&self) -> DatabaseConfigRuntimeApply {
        self.apply
    }

    pub fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    pub const fn pending_restart(&self) -> Option<bool> {
        self.pending_restart
    }

    pub fn minimum(&self) -> Option<&str> {
        self.minimum.as_deref()
    }

    pub fn maximum(&self) -> Option<&str> {
        self.maximum.as_deref()
    }

    pub fn enum_values(&self) -> &[String] {
        &self.enum_values
    }
}

#[derive(Clone)]
pub struct DatabaseConfigRuntimeDocument {
    provider: DatabaseConfigRuntimeSqlProvider,
    binding: DatabaseConfigRuntimeBinding,
    rows: Vec<DatabaseConfigRuntimeRow>,
}

impl fmt::Debug for DatabaseConfigRuntimeDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatabaseConfigRuntimeDocument")
            .field("provider", &self.provider)
            .field("binding", &self.binding)
            .field("row_count", &self.rows.len())
            .field("rows", &"<omitted>")
            .finish()
    }
}

impl DatabaseConfigRuntimeDocument {
    pub const fn provider(&self) -> DatabaseConfigRuntimeSqlProvider {
        self.provider
    }

    pub const fn binding(&self) -> DatabaseConfigRuntimeBinding {
        self.binding
    }

    /// Rows remain in server result order and duplicate names remain distinct.
    pub fn rows(&self) -> &[DatabaseConfigRuntimeRow] {
        &self.rows
    }

    pub fn into_rows(self) -> Vec<DatabaseConfigRuntimeRow> {
        self.rows
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DatabaseConfigRuntimeParseError {
    #[error("native runtime values require a reviewed PostgreSQL provider")]
    InvalidNativeProvider,
    #[error("runtime TSV exceeds the byte limit")]
    InputTooLarge,
    #[error("runtime TSV exceeds the row limit")]
    TooManyRows,
    #[error("runtime TSV exceeds the cell limit")]
    TooManyCells,
    #[error("runtime TSV contains an invalid wire byte at offset {offset}")]
    InvalidWireByte { offset: usize },
    #[error("runtime TSV contains a forbidden control byte at offset {offset}")]
    ControlCharacter { offset: usize },
    #[error("runtime TSV row {row} has {actual} columns; expected {expected}")]
    InvalidColumnCount {
        row: usize,
        expected: usize,
        actual: usize,
    },
    #[error("runtime TSV cell {column} on row {row} exceeds its limit")]
    CellTooLarge { row: usize, column: usize },
    #[error("runtime TSV cell {column} on row {row} is not hexadecimal")]
    InvalidHex { row: usize, column: usize },
    #[error("runtime TSV cell {column} on row {row} is not UTF-8")]
    InvalidUtf8 { row: usize, column: usize },
    #[error("runtime TSV cell {column} on row {row} contains a control character")]
    DecodedControlCharacter { row: usize, column: usize },
    #[error("runtime parameter name on row {row} is invalid")]
    InvalidName { row: usize },
    #[error("required runtime TSV cell {column} on row {row} is null")]
    RequiredCellMissing { row: usize, column: usize },
    #[error("runtime scope on row {row} does not match the provider contract")]
    InvalidScope { row: usize },
    #[error("runtime apply/context on row {row} does not match the provider contract")]
    InvalidApply { row: usize },
    #[error("pending_restart on row {row} does not match the provider contract")]
    InvalidPendingRestart { row: usize },
    #[error("enum metadata on row {row} is invalid")]
    InvalidEnumMetadata { row: usize },
    #[error("enum metadata on row {row} exceeds the depth limit")]
    MetadataDepthExceeded { row: usize },
    #[error("enum metadata on row {row} exceeds the value-count limit")]
    TooManyEnumValues { row: usize },
}

fn parse_runtime_identity_tsv(
    plan: &'static DatabaseConfigRuntimeIdentityPlan,
    bytes: &[u8],
) -> Result<DatabaseConfigRuntimeIdentity, DatabaseConfigRuntimeIdentityParseError> {
    let cells = runtime_identity_wire_cells(bytes, plan.expected_columns)?;
    let decoded = cells
        .iter()
        .enumerate()
        .map(|(column, cell)| decode_runtime_identity_cell(cell, column))
        .collect::<Result<Vec<_>, _>>()?;

    let version = match plan.declared_product {
        DatabaseConfigProduct::MySql => parse_mysql_runtime_identity(&decoded)?,
        DatabaseConfigProduct::MariaDb => parse_mariadb_runtime_identity(&decoded)?,
        DatabaseConfigProduct::PostgreSql => parse_postgresql_runtime_identity(&decoded)?,
        _ => return Err(DatabaseConfigRuntimeIdentityParseError::UntrustedIdentity),
    };
    Ok(DatabaseConfigRuntimeIdentity {
        product: plan.declared_product,
        version,
        edition: DatabaseConfigRuntimeEdition::Community,
    })
}

fn runtime_identity_wire_cells(
    bytes: &[u8],
    expected_columns: usize,
) -> Result<Vec<&[u8]>, DatabaseConfigRuntimeIdentityParseError> {
    if bytes.len() > MAX_DATABASE_CONFIG_RUNTIME_IDENTITY_TSV_BYTES {
        return Err(DatabaseConfigRuntimeIdentityParseError::InputTooLarge);
    }
    let row = bytes
        .strip_suffix(b"\r\n")
        .or_else(|| bytes.strip_suffix(b"\n"))
        .unwrap_or(bytes);
    if row.is_empty() || row.iter().any(|byte| matches!(byte, b'\r' | b'\n')) {
        return Err(DatabaseConfigRuntimeIdentityParseError::InvalidRowCount);
    }
    for (offset, byte) in row.iter().copied().enumerate() {
        match byte {
            b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' | b'-' | b'\t' => {}
            byte if byte.is_ascii_control() => {
                return Err(DatabaseConfigRuntimeIdentityParseError::ControlCharacter { offset });
            }
            _ => {
                return Err(DatabaseConfigRuntimeIdentityParseError::InvalidWireByte { offset });
            }
        }
    }
    let cells = row.split(|byte| *byte == b'\t').collect::<Vec<_>>();
    if cells.len() != expected_columns {
        return Err(
            DatabaseConfigRuntimeIdentityParseError::InvalidColumnCount {
                expected: expected_columns,
                actual: cells.len(),
            },
        );
    }
    Ok(cells)
}

fn decode_runtime_identity_cell(
    cell: &[u8],
    column: usize,
) -> Result<Zeroizing<String>, DatabaseConfigRuntimeIdentityParseError> {
    if cell == b"-" {
        return Err(DatabaseConfigRuntimeIdentityParseError::RequiredCellMissing { column });
    }
    if !cell.len().is_multiple_of(2) {
        return Err(DatabaseConfigRuntimeIdentityParseError::InvalidHex { column });
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(cell.len() / 2));
    for pair in cell.as_chunks::<2>().0 {
        let high = hex_nibble(pair[0])
            .ok_or(DatabaseConfigRuntimeIdentityParseError::InvalidHex { column })?;
        let low = hex_nibble(pair[1])
            .ok_or(DatabaseConfigRuntimeIdentityParseError::InvalidHex { column })?;
        bytes.push((high << 4) | low);
    }
    let value = str::from_utf8(&bytes)
        .map_err(|_| DatabaseConfigRuntimeIdentityParseError::InvalidUtf8 { column })?;
    if value.chars().any(is_unsafe_display_character) {
        return Err(DatabaseConfigRuntimeIdentityParseError::DecodedControlCharacter { column });
    }
    let mut output = Zeroizing::new(String::with_capacity(value.len()));
    output.push_str(value);
    Ok(output)
}

fn parse_mysql_runtime_identity(
    cells: &[Zeroizing<String>],
) -> Result<DatabaseConfigVersion, DatabaseConfigRuntimeIdentityParseError> {
    let version_text = cells[0].as_str();
    let version_comment = cells[1].as_str();
    if contains_ascii_case_insensitive(version_text.as_bytes(), b"mariadb")
        || contains_ascii_case_insensitive(version_comment.as_bytes(), b"mariadb")
    {
        return Err(DatabaseConfigRuntimeIdentityParseError::DeclaredProductMismatch);
    }
    if contains_prerelease_marker(version_text.as_bytes()) {
        return Err(DatabaseConfigRuntimeIdentityParseError::PreReleaseOrDevelopment);
    }
    if version_comment != "MySQL Community Server - GPL" {
        return Err(DatabaseConfigRuntimeIdentityParseError::UntrustedEdition);
    }
    let version = parse_three_part_version(version_text)?;
    if !matches_reviewed_runtime_version(DatabaseConfigProduct::MySql, version) {
        return Err(DatabaseConfigRuntimeIdentityParseError::UnsupportedVersion);
    }
    Ok(version)
}

fn parse_mariadb_runtime_identity(
    cells: &[Zeroizing<String>],
) -> Result<DatabaseConfigVersion, DatabaseConfigRuntimeIdentityParseError> {
    let identity = cells[0].as_str();
    if contains_prerelease_marker(identity.as_bytes()) {
        return Err(DatabaseConfigRuntimeIdentityParseError::PreReleaseOrDevelopment);
    }
    let Some((version_text, suffix)) = identity.split_once("-MariaDB") else {
        if contains_ascii_case_insensitive(identity.as_bytes(), b"mariadb") {
            return Err(DatabaseConfigRuntimeIdentityParseError::UntrustedEdition);
        }
        if parse_three_part_version(identity).is_ok() {
            return Err(DatabaseConfigRuntimeIdentityParseError::DeclaredProductMismatch);
        }
        return Err(DatabaseConfigRuntimeIdentityParseError::UntrustedIdentity);
    };
    if !mariadb_community_suffix_is_reviewed(suffix) {
        return Err(DatabaseConfigRuntimeIdentityParseError::UntrustedEdition);
    }
    let version = parse_three_part_version(version_text)?;
    if !matches_reviewed_runtime_version(DatabaseConfigProduct::MariaDb, version) {
        return Err(DatabaseConfigRuntimeIdentityParseError::UnsupportedVersion);
    }
    Ok(version)
}

fn mariadb_community_suffix_is_reviewed(suffix: &str) -> bool {
    suffix.is_empty()
        || suffix.strip_prefix('-').is_some_and(|suffixes| {
            !suffixes.is_empty()
                && suffixes
                    .split('-')
                    .all(|suffix| matches!(suffix, "embedded" | "log" | "debug" | "valgrind"))
        })
}

fn parse_postgresql_runtime_identity(
    cells: &[Zeroizing<String>],
) -> Result<DatabaseConfigVersion, DatabaseConfigRuntimeIdentityParseError> {
    let version_number = cells[0].as_str();
    let server_version = cells[1].as_str();
    let banner = cells[2].as_str();
    if [version_number, server_version, banner]
        .iter()
        .any(|value| contains_prerelease_marker(value.as_bytes()))
    {
        return Err(DatabaseConfigRuntimeIdentityParseError::PreReleaseOrDevelopment);
    }
    if postgres_banner_has_untrusted_vendor(banner)
        || postgres_banner_has_untrusted_vendor(server_version)
    {
        return Err(DatabaseConfigRuntimeIdentityParseError::UntrustedEdition);
    }
    if !banner.starts_with("PostgreSQL ") {
        if contains_ascii_case_insensitive(banner.as_bytes(), b"mysql")
            || contains_ascii_case_insensitive(banner.as_bytes(), b"mariadb")
        {
            return Err(DatabaseConfigRuntimeIdentityParseError::DeclaredProductMismatch);
        }
        return Err(DatabaseConfigRuntimeIdentityParseError::UntrustedIdentity);
    }

    let numeric_version = parse_postgresql_version_number(version_number)?;
    let display_version = parse_postgresql_display_version(server_version)?;
    let banner_version = parse_postgresql_banner_version(banner)?;
    if numeric_version != display_version || display_version != banner_version {
        return Err(DatabaseConfigRuntimeIdentityParseError::InconsistentVersionSources);
    }
    if !matches_reviewed_runtime_version(DatabaseConfigProduct::PostgreSql, numeric_version) {
        return Err(DatabaseConfigRuntimeIdentityParseError::UnsupportedVersion);
    }
    Ok(numeric_version)
}

fn parse_three_part_version(
    value: &str,
) -> Result<DatabaseConfigVersion, DatabaseConfigRuntimeIdentityParseError> {
    let mut parts = value.split('.');
    let major = parse_version_part(parts.next())?;
    let minor = parse_version_part(parts.next())?;
    let patch = parse_version_part(parts.next())?;
    if parts.next().is_some() {
        return Err(DatabaseConfigRuntimeIdentityParseError::InvalidVersion);
    }
    Ok(DatabaseConfigVersion::new(major, minor, patch))
}

fn parse_two_part_version(
    value: &str,
) -> Result<DatabaseConfigVersion, DatabaseConfigRuntimeIdentityParseError> {
    let mut parts = value.split('.');
    let major = parse_version_part(parts.next())?;
    let minor = parse_version_part(parts.next())?;
    if parts.next().is_some() {
        return Err(DatabaseConfigRuntimeIdentityParseError::InvalidVersion);
    }
    Ok(DatabaseConfigVersion::new(major, minor, 0))
}

fn parse_version_part(value: Option<&str>) -> Result<u16, DatabaseConfigRuntimeIdentityParseError> {
    let value = value.ok_or(DatabaseConfigRuntimeIdentityParseError::InvalidVersion)?;
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(DatabaseConfigRuntimeIdentityParseError::InvalidVersion);
    }
    value
        .parse::<u16>()
        .map_err(|_| DatabaseConfigRuntimeIdentityParseError::InvalidVersion)
}

fn parse_postgresql_version_number(
    value: &str,
) -> Result<DatabaseConfigVersion, DatabaseConfigRuntimeIdentityParseError> {
    if value.len() != 6 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(DatabaseConfigRuntimeIdentityParseError::InvalidVersion);
    }
    let number = value
        .parse::<u32>()
        .map_err(|_| DatabaseConfigRuntimeIdentityParseError::InvalidVersion)?;
    let major = u16::try_from(number / 10_000)
        .map_err(|_| DatabaseConfigRuntimeIdentityParseError::InvalidVersion)?;
    let minor = u16::try_from(number % 10_000)
        .map_err(|_| DatabaseConfigRuntimeIdentityParseError::InvalidVersion)?;
    Ok(DatabaseConfigVersion::new(major, minor, 0))
}

fn parse_postgresql_banner_version(
    banner: &str,
) -> Result<DatabaseConfigVersion, DatabaseConfigRuntimeIdentityParseError> {
    let remainder = banner
        .strip_prefix("PostgreSQL ")
        .ok_or(DatabaseConfigRuntimeIdentityParseError::UntrustedIdentity)?;
    let version_end = remainder
        .bytes()
        .position(|byte| matches!(byte, b' ' | b','))
        .ok_or(DatabaseConfigRuntimeIdentityParseError::UntrustedIdentity)?;
    let version_text = &remainder[..version_end];
    let version = parse_two_part_version(version_text)?;
    let signature = strip_postgresql_package_suffix(&remainder[version_end..], version_text)?;
    let unix_signature = signature.starts_with(" on ")
        && contains_ascii_case_insensitive(signature.as_bytes(), b", compiled by ");
    let windows_signature = signature.starts_with(", compiled by ");
    if !(unix_signature || windows_signature) || !signature.ends_with("-bit") {
        return Err(DatabaseConfigRuntimeIdentityParseError::UntrustedIdentity);
    }
    Ok(version)
}

fn parse_postgresql_display_version(
    value: &str,
) -> Result<DatabaseConfigVersion, DatabaseConfigRuntimeIdentityParseError> {
    let end = value.find(' ').unwrap_or(value.len());
    let version_text = &value[..end];
    let version = parse_two_part_version(version_text)?;
    if !strip_postgresql_package_suffix(&value[end..], version_text)?.is_empty() {
        return Err(DatabaseConfigRuntimeIdentityParseError::InvalidVersion);
    }
    Ok(version)
}

/// Native Debian/Ubuntu builds put a package label in both server_version and
/// version(). Accept that closed packaging shape, retaining the independent
/// numeric version check and known-fork refusals. It is not proof of provenance.
fn strip_postgresql_package_suffix<'a>(
    suffix: &'a str,
    upstream: &str,
) -> Result<&'a str, DatabaseConfigRuntimeIdentityParseError> {
    if !suffix.starts_with(" (") {
        return Ok(suffix);
    }
    let end = suffix
        .find(')')
        .ok_or(DatabaseConfigRuntimeIdentityParseError::UntrustedIdentity)?;
    let package = &suffix[2..end];
    let revision = package
        .strip_prefix("Debian ")
        .or_else(|| package.strip_prefix("Ubuntu "))
        .and_then(|value| value.strip_prefix(upstream))
        .and_then(|value| value.strip_prefix('-'))
        .ok_or(DatabaseConfigRuntimeIdentityParseError::UntrustedIdentity)?;
    if revision.is_empty()
        || revision.len() > 96
        || !revision
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'~' | b'-'))
    {
        return Err(DatabaseConfigRuntimeIdentityParseError::UntrustedIdentity);
    }
    Ok(&suffix[end + 1..])
}

fn postgres_banner_has_untrusted_vendor(banner: &str) -> bool {
    [
        b"enterprise".as_slice(),
        b"enterprisedb".as_slice(),
        b" edb".as_slice(),
        b"aurora".as_slice(),
        b"alloydb".as_slice(),
        b"cloud sql".as_slice(),
        b"amazon rds".as_slice(),
        b"yugabyte".as_slice(),
        b"cockroach".as_slice(),
        b"greenplum".as_slice(),
        b"redshift".as_slice(),
        b"opengauss".as_slice(),
        b"gaussdb".as_slice(),
        b"kingbase".as_slice(),
        b"highgo".as_slice(),
        b"tdsql".as_slice(),
        b"opentenbase".as_slice(),
    ]
    .iter()
    .any(|marker| contains_ascii_case_insensitive(banner.as_bytes(), marker))
}

fn contains_prerelease_marker(value: &[u8]) -> bool {
    [
        b"alpha".as_slice(),
        b"beta".as_slice(),
        b"preview".as_slice(),
        b"devel".as_slice(),
        b"-rc".as_slice(),
        b" rc".as_slice(),
    ]
    .iter()
    .any(|marker| contains_ascii_case_insensitive(value, marker))
        || value.windows(2).enumerate().any(|(offset, pair)| {
            pair.eq_ignore_ascii_case(b"rc") && offset > 0 && value[offset - 1].is_ascii_digit()
        })
}

fn matches_reviewed_runtime_version(
    product: DatabaseConfigProduct,
    version: DatabaseConfigVersion,
) -> bool {
    match product {
        DatabaseConfigProduct::MySql => {
            DatabaseConfigVersionSelector::HalfOpen {
                minimum_inclusive: DatabaseConfigVersion::new(8, 0, 11),
                maximum_exclusive: DatabaseConfigVersion::new(8, 1, 0),
            }
            .contains(version)
                || DatabaseConfigVersionSelector::HalfOpen {
                    minimum_inclusive: DatabaseConfigVersion::new(8, 4, 0),
                    maximum_exclusive: DatabaseConfigVersion::new(8, 5, 0),
                }
                .contains(version)
        }
        DatabaseConfigProduct::MariaDb => {
            DatabaseConfigVersionSelector::HalfOpen {
                minimum_inclusive: DatabaseConfigVersion::new(10, 11, 0),
                maximum_exclusive: DatabaseConfigVersion::new(10, 12, 0),
            }
            .contains(version)
                || DatabaseConfigVersionSelector::HalfOpen {
                    minimum_inclusive: DatabaseConfigVersion::new(11, 4, 0),
                    maximum_exclusive: DatabaseConfigVersion::new(11, 5, 0),
                }
                .contains(version)
        }
        DatabaseConfigProduct::PostgreSql => (16..=18).contains(&version.major()),
        _ => false,
    }
}

fn parse_runtime_tsv(
    plan: &'static DatabaseConfigRuntimeQueryPlan,
    bytes: &[u8],
    disclosure: RuntimeValueDisclosure,
) -> Result<DatabaseConfigRuntimeDocument, DatabaseConfigRuntimeParseError> {
    validate_wire_shape(bytes)?;
    let mut rows = Vec::new();
    let mut raw_rows = bytes.split(|byte| *byte == b'\n').peekable();
    let mut row_index = 0usize;
    while let Some(raw_row) = raw_rows.next() {
        if raw_row.is_empty() && row_index > 0 && raw_rows.peek().is_none() {
            break;
        }
        if raw_row.is_empty() && bytes.is_empty() {
            break;
        }
        let raw_row = raw_row.strip_suffix(b"\r").unwrap_or(raw_row);
        let cells = raw_row.split(|byte| *byte == b'\t').collect::<Vec<_>>();
        if cells.len() != RUNTIME_TSV_COLUMNS {
            return Err(DatabaseConfigRuntimeParseError::InvalidColumnCount {
                row: row_index,
                expected: RUNTIME_TSV_COLUMNS,
                actual: cells.len(),
            });
        }
        rows.push(parse_runtime_row(plan, row_index, &cells, disclosure)?);
        row_index += 1;
    }

    Ok(DatabaseConfigRuntimeDocument {
        provider: plan.provider,
        binding: plan.binding,
        rows,
    })
}

fn validate_wire_shape(bytes: &[u8]) -> Result<(), DatabaseConfigRuntimeParseError> {
    if bytes.len() > MAX_DATABASE_CONFIG_RUNTIME_TSV_BYTES {
        return Err(DatabaseConfigRuntimeParseError::InputTooLarge);
    }

    let mut rows = usize::from(!bytes.is_empty());
    let mut cells = usize::from(!bytes.is_empty());
    for (offset, byte) in bytes.iter().copied().enumerate() {
        match byte {
            b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' | b'-' => {}
            b'\t' => cells = cells.saturating_add(1),
            b'\n' => {
                if offset + 1 < bytes.len() {
                    rows = rows.saturating_add(1);
                    cells = cells.saturating_add(1);
                }
            }
            b'\r' if bytes.get(offset + 1) == Some(&b'\n') => {}
            byte if byte.is_ascii_control() => {
                return Err(DatabaseConfigRuntimeParseError::ControlCharacter { offset });
            }
            _ => return Err(DatabaseConfigRuntimeParseError::InvalidWireByte { offset }),
        }
        if rows > MAX_DATABASE_CONFIG_RUNTIME_ROWS {
            return Err(DatabaseConfigRuntimeParseError::TooManyRows);
        }
        if cells > MAX_DATABASE_CONFIG_RUNTIME_CELLS {
            return Err(DatabaseConfigRuntimeParseError::TooManyCells);
        }
    }
    Ok(())
}

fn parse_runtime_row(
    plan: &DatabaseConfigRuntimeQueryPlan,
    row: usize,
    cells: &[&[u8]],
    disclosure: RuntimeValueDisclosure,
) -> Result<DatabaseConfigRuntimeRow, DatabaseConfigRuntimeParseError> {
    let name = required_text_cell(cells[0], row, 0, MAX_DATABASE_CONFIG_RUNTIME_NAME_BYTES)?;
    if !valid_runtime_name(plan.provider, &name) {
        return Err(DatabaseConfigRuntimeParseError::InvalidName { row });
    }
    let native_name =
        matches!(disclosure, RuntimeValueDisclosure::NativePostgresql).then_some(name.as_str());
    let value = parse_runtime_value(cells[1], row, classify_runtime_name(&name), native_name)?;

    let scope_text =
        required_text_cell(cells[2], row, 2, MAX_DATABASE_CONFIG_RUNTIME_METADATA_BYTES)?;
    let scope = parse_scope(plan.provider, &scope_text)
        .ok_or(DatabaseConfigRuntimeParseError::InvalidScope { row })?;

    let apply_text =
        required_text_cell(cells[3], row, 3, MAX_DATABASE_CONFIG_RUNTIME_METADATA_BYTES)?;
    let apply = parse_apply(plan.provider, &apply_text)
        .ok_or(DatabaseConfigRuntimeParseError::InvalidApply { row })?;

    let source = optional_text_cell(cells[4], row, 4, MAX_DATABASE_CONFIG_RUNTIME_METADATA_BYTES)?;
    let pending_restart = parse_pending_restart(plan.provider, cells[5], row)?;
    let minimum = optional_text_cell(cells[6], row, 6, MAX_DATABASE_CONFIG_RUNTIME_METADATA_BYTES)?;
    let maximum = optional_text_cell(cells[7], row, 7, MAX_DATABASE_CONFIG_RUNTIME_METADATA_BYTES)?;
    let enum_values = parse_enum_values(plan.enum_encoding, cells[8], row)?;

    Ok(DatabaseConfigRuntimeRow {
        name,
        value,
        scope,
        apply,
        source,
        pending_restart,
        minimum,
        maximum,
        enum_values,
    })
}

fn parse_runtime_value(
    cell: &[u8],
    row: usize,
    sensitivity: DatabaseConfigRuntimeSensitivity,
    native_name: Option<&str>,
) -> Result<DatabaseConfigRuntimeValue, DatabaseConfigRuntimeParseError> {
    let decoded =
        optional_zeroizing_bytes_cell(cell, row, 1, MAX_DATABASE_CONFIG_RUNTIME_VALUE_BYTES)?;
    let presence = value_presence(decoded.as_deref().map(|bytes| bytes.as_slice()));
    let decoded_text = decoded
        .as_deref()
        .map(|bytes| {
            str::from_utf8(bytes)
                .map_err(|_| DatabaseConfigRuntimeParseError::InvalidUtf8 { row, column: 1 })
        })
        .transpose()?;

    let sensitivity = if native_name
        .zip(decoded_text)
        .is_some_and(|(name, value)| public_postgresql_scalar(name, value))
    {
        DatabaseConfigRuntimeSensitivity::Public
    } else {
        sensitivity
    };
    let sensitivity = merge_runtime_sensitivity(
        sensitivity,
        decoded
            .as_deref()
            .and_then(|bytes| classify_runtime_carrier(bytes)),
    );
    let (public_value, public_value_was_escaped) =
        if sensitivity == DatabaseConfigRuntimeSensitivity::Public {
            match decoded_text {
                Some(value) => {
                    let (value, escaped) = escape_public_value(value);
                    (Some(value), escaped)
                }
                None => (None, false),
            }
        } else {
            (None, false)
        };
    let sensitive_sha256 = if sensitivity == DatabaseConfigRuntimeSensitivity::Public {
        None
    } else {
        decoded
            .as_deref()
            .map(|bytes| <[u8; 32]>::from(Sha256::digest(bytes)))
    };
    Ok(DatabaseConfigRuntimeValue {
        sensitivity,
        presence,
        public_value,
        public_value_was_escaped,
        sensitive_sha256,
    })
}

/// Finite PostgreSQL 16/17/18 scalar vocabularies; never trust a server-supplied
/// name, type declaration or enum list to authorize arbitrary text disclosure.
fn public_postgresql_scalar(name: &str, value: &str) -> bool {
    match name {
        "ssl"
        | "logging_collector"
        | "log_connections"
        | "log_disconnections"
        | "default_transaction_read_only" => matches!(value, "on" | "off"),
        "password_encryption" => matches!(value, "md5" | "scram-sha-256"),
        "log_statement" => matches!(value, "none" | "ddl" | "mod" | "all"),
        "listen_addresses" => matches!(value, "" | "*" | "localhost" | "127.0.0.1" | "::1"),
        "ssl_min_protocol_version" => matches!(value, "TLSv1" | "TLSv1.1" | "TLSv1.2" | "TLSv1.3"),
        "ssl_max_protocol_version" => {
            matches!(value, "" | "TLSv1" | "TLSv1.1" | "TLSv1.2" | "TLSv1.3")
        }
        _ => false,
    }
}

fn merge_runtime_sensitivity(
    name: DatabaseConfigRuntimeSensitivity,
    carrier: Option<DatabaseConfigRuntimeSensitivity>,
) -> DatabaseConfigRuntimeSensitivity {
    match (name, carrier) {
        (DatabaseConfigRuntimeSensitivity::PrivateKeyReference, _)
        | (_, Some(DatabaseConfigRuntimeSensitivity::PrivateKeyReference)) => {
            DatabaseConfigRuntimeSensitivity::PrivateKeyReference
        }
        (DatabaseConfigRuntimeSensitivity::MayContainSecrets, _)
        | (_, Some(DatabaseConfigRuntimeSensitivity::MayContainSecrets)) => {
            DatabaseConfigRuntimeSensitivity::MayContainSecrets
        }
        (DatabaseConfigRuntimeSensitivity::Public, None)
        | (
            DatabaseConfigRuntimeSensitivity::Public,
            Some(DatabaseConfigRuntimeSensitivity::Public),
        ) => DatabaseConfigRuntimeSensitivity::Public,
    }
}

fn escape_public_value(value: &str) -> (String, bool) {
    let mut escaped = false;
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        if is_unsafe_display_character(character) {
            escaped = true;
            output.extend(character.escape_default());
        } else {
            output.push(character);
        }
    }
    debug_assert!(output.len() <= MAX_DATABASE_CONFIG_RUNTIME_ESCAPED_VALUE_BYTES);
    (output, escaped)
}

fn value_presence(value: Option<&[u8]>) -> DatabaseConfigRuntimeValuePresence {
    match value {
        None => DatabaseConfigRuntimeValuePresence::Null,
        Some([]) => DatabaseConfigRuntimeValuePresence::Empty,
        Some(_) => DatabaseConfigRuntimeValuePresence::Present,
    }
}

fn parse_scope(
    provider: DatabaseConfigRuntimeSqlProvider,
    value: &str,
) -> Option<DatabaseConfigRuntimeScope> {
    match (provider, value) {
        (DatabaseConfigRuntimeSqlProvider::MySqlPerformanceSchema, "global") => {
            Some(DatabaseConfigRuntimeScope::Global)
        }
        (DatabaseConfigRuntimeSqlProvider::MariaDbInformationSchema, "GLOBAL") => {
            Some(DatabaseConfigRuntimeScope::Global)
        }
        (DatabaseConfigRuntimeSqlProvider::MariaDbInformationSchema, "SESSION") => {
            Some(DatabaseConfigRuntimeScope::GlobalAndSession)
        }
        (DatabaseConfigRuntimeSqlProvider::MariaDbInformationSchema, "SESSION ONLY") => {
            Some(DatabaseConfigRuntimeScope::SessionOnly)
        }
        (
            DatabaseConfigRuntimeSqlProvider::MariaDbInformationSchema,
            "GLOBAL,SESSION" | "GLOBAL AND SESSION",
        ) => Some(DatabaseConfigRuntimeScope::GlobalAndSession),
        (DatabaseConfigRuntimeSqlProvider::PostgreSqlPgSettings, "server-or-session") => {
            Some(DatabaseConfigRuntimeScope::ServerOrSession)
        }
        _ => None,
    }
}

fn parse_apply(
    provider: DatabaseConfigRuntimeSqlProvider,
    value: &str,
) -> Option<DatabaseConfigRuntimeApply> {
    match (provider, value) {
        (DatabaseConfigRuntimeSqlProvider::MySqlPerformanceSchema, "vendor-defined") => {
            Some(DatabaseConfigRuntimeApply::VendorDefined)
        }
        (DatabaseConfigRuntimeSqlProvider::MariaDbInformationSchema, "dynamic") => {
            Some(DatabaseConfigRuntimeApply::Dynamic)
        }
        (DatabaseConfigRuntimeSqlProvider::MariaDbInformationSchema, "read-only") => {
            Some(DatabaseConfigRuntimeApply::ReadOnly)
        }
        (DatabaseConfigRuntimeSqlProvider::PostgreSqlPgSettings, "internal") => Some(
            DatabaseConfigRuntimeApply::PostgreSql(PostgreSqlRuntimeContext::Internal),
        ),
        (DatabaseConfigRuntimeSqlProvider::PostgreSqlPgSettings, "postmaster") => Some(
            DatabaseConfigRuntimeApply::PostgreSql(PostgreSqlRuntimeContext::Postmaster),
        ),
        (DatabaseConfigRuntimeSqlProvider::PostgreSqlPgSettings, "sighup") => Some(
            DatabaseConfigRuntimeApply::PostgreSql(PostgreSqlRuntimeContext::Sighup),
        ),
        (DatabaseConfigRuntimeSqlProvider::PostgreSqlPgSettings, "superuser-backend") => Some(
            DatabaseConfigRuntimeApply::PostgreSql(PostgreSqlRuntimeContext::SuperuserBackend),
        ),
        (DatabaseConfigRuntimeSqlProvider::PostgreSqlPgSettings, "backend") => Some(
            DatabaseConfigRuntimeApply::PostgreSql(PostgreSqlRuntimeContext::Backend),
        ),
        (DatabaseConfigRuntimeSqlProvider::PostgreSqlPgSettings, "superuser") => Some(
            DatabaseConfigRuntimeApply::PostgreSql(PostgreSqlRuntimeContext::Superuser),
        ),
        (DatabaseConfigRuntimeSqlProvider::PostgreSqlPgSettings, "user") => Some(
            DatabaseConfigRuntimeApply::PostgreSql(PostgreSqlRuntimeContext::User),
        ),
        _ => None,
    }
}

fn parse_pending_restart(
    provider: DatabaseConfigRuntimeSqlProvider,
    cell: &[u8],
    row: usize,
) -> Result<Option<bool>, DatabaseConfigRuntimeParseError> {
    let value = optional_text_cell(cell, row, 5, 5)?;
    match (provider, value.as_deref()) {
        (DatabaseConfigRuntimeSqlProvider::PostgreSqlPgSettings, Some("true")) => Ok(Some(true)),
        (DatabaseConfigRuntimeSqlProvider::PostgreSqlPgSettings, Some("false")) => Ok(Some(false)),
        (DatabaseConfigRuntimeSqlProvider::PostgreSqlPgSettings, _) => {
            Err(DatabaseConfigRuntimeParseError::InvalidPendingRestart { row })
        }
        (_, None) => Ok(None),
        _ => Err(DatabaseConfigRuntimeParseError::InvalidPendingRestart { row }),
    }
}

fn parse_enum_values(
    encoding: RuntimeEnumEncoding,
    cell: &[u8],
    row: usize,
) -> Result<Vec<String>, DatabaseConfigRuntimeParseError> {
    let value = optional_text_cell(cell, row, 8, MAX_DATABASE_CONFIG_RUNTIME_METADATA_BYTES)?;
    match (encoding, value) {
        (RuntimeEnumEncoding::None, None) => Ok(Vec::new()),
        (RuntimeEnumEncoding::None, Some(_)) => {
            Err(DatabaseConfigRuntimeParseError::InvalidEnumMetadata { row })
        }
        (RuntimeEnumEncoding::MariaDbCommaList, None) => Ok(Vec::new()),
        (RuntimeEnumEncoding::MariaDbCommaList, Some(value)) => {
            if value.is_empty() {
                return Ok(Vec::new());
            }
            let values = value
                .split(',')
                .map(str::trim)
                .map(str::to_owned)
                .collect::<Vec<_>>();
            validate_enum_values(values, row, encoding)
        }
        (RuntimeEnumEncoding::PostgreSqlJsonArray, None) => Ok(Vec::new()),
        (RuntimeEnumEncoding::PostgreSqlJsonArray, Some(value)) => {
            validate_json_depth(&value, row)?;
            let values = serde_json::from_str::<Vec<String>>(&value)
                .map_err(|_| DatabaseConfigRuntimeParseError::InvalidEnumMetadata { row })?;
            validate_enum_values(values, row, encoding)
        }
    }
}

fn validate_enum_values(
    values: Vec<String>,
    row: usize,
    encoding: RuntimeEnumEncoding,
) -> Result<Vec<String>, DatabaseConfigRuntimeParseError> {
    if values.len() > MAX_DATABASE_CONFIG_RUNTIME_ENUM_VALUES {
        return Err(DatabaseConfigRuntimeParseError::TooManyEnumValues { row });
    }
    for value in &values {
        // PostgreSQL includes an empty enum option for settings such as
        // ssl_max_protocol_version. JSON distinguishes it from a missing item;
        // a hole in MariaDB's comma-separated list remains invalid.
        if (value.is_empty() && !matches!(encoding, RuntimeEnumEncoding::PostgreSqlJsonArray))
            || value.len() > MAX_DATABASE_CONFIG_RUNTIME_ENUM_VALUE_BYTES
            || value.chars().any(is_unsafe_display_character)
        {
            return Err(DatabaseConfigRuntimeParseError::InvalidEnumMetadata { row });
        }
    }
    Ok(values)
}

fn validate_json_depth(value: &str, row: usize) -> Result<(), DatabaseConfigRuntimeParseError> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for character in value.chars() {
        if in_string {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
            continue;
        }
        match character {
            '"' => in_string = true,
            '[' | '{' => {
                depth = depth.saturating_add(1);
                if depth > MAX_DATABASE_CONFIG_RUNTIME_DEPTH {
                    return Err(DatabaseConfigRuntimeParseError::MetadataDepthExceeded { row });
                }
            }
            ']' | '}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Ok(())
}

fn required_text_cell(
    cell: &[u8],
    row: usize,
    column: usize,
    maximum_bytes: usize,
) -> Result<String, DatabaseConfigRuntimeParseError> {
    optional_text_cell(cell, row, column, maximum_bytes)?
        .ok_or(DatabaseConfigRuntimeParseError::RequiredCellMissing { row, column })
}

fn optional_text_cell(
    cell: &[u8],
    row: usize,
    column: usize,
    maximum_bytes: usize,
) -> Result<Option<String>, DatabaseConfigRuntimeParseError> {
    optional_bytes_cell(cell, row, column, maximum_bytes)?
        .map(|bytes| checked_utf8(bytes, row, column))
        .transpose()
}

fn optional_bytes_cell(
    cell: &[u8],
    row: usize,
    column: usize,
    maximum_bytes: usize,
) -> Result<Option<Vec<u8>>, DatabaseConfigRuntimeParseError> {
    if cell == b"-" {
        return Ok(None);
    }
    if cell.len() > maximum_bytes.saturating_mul(2) {
        return Err(DatabaseConfigRuntimeParseError::CellTooLarge { row, column });
    }
    if !cell.len().is_multiple_of(2) {
        return Err(DatabaseConfigRuntimeParseError::InvalidHex { row, column });
    }
    let mut decoded = Vec::with_capacity(cell.len() / 2);
    for pair in cell.as_chunks::<2>().0 {
        let high = hex_nibble(pair[0])
            .ok_or(DatabaseConfigRuntimeParseError::InvalidHex { row, column })?;
        let low = hex_nibble(pair[1])
            .ok_or(DatabaseConfigRuntimeParseError::InvalidHex { row, column })?;
        decoded.push((high << 4) | low);
    }
    Ok(Some(decoded))
}

fn optional_zeroizing_bytes_cell(
    cell: &[u8],
    row: usize,
    column: usize,
    maximum_bytes: usize,
) -> Result<Option<Zeroizing<Vec<u8>>>, DatabaseConfigRuntimeParseError> {
    if cell == b"-" {
        return Ok(None);
    }
    if cell.len() > maximum_bytes.saturating_mul(2) {
        return Err(DatabaseConfigRuntimeParseError::CellTooLarge { row, column });
    }
    if !cell.len().is_multiple_of(2) {
        return Err(DatabaseConfigRuntimeParseError::InvalidHex { row, column });
    }
    let mut decoded = Zeroizing::new(Vec::with_capacity(cell.len() / 2));
    for pair in cell.as_chunks::<2>().0 {
        let high = hex_nibble(pair[0])
            .ok_or(DatabaseConfigRuntimeParseError::InvalidHex { row, column })?;
        let low = hex_nibble(pair[1])
            .ok_or(DatabaseConfigRuntimeParseError::InvalidHex { row, column })?;
        decoded.push((high << 4) | low);
    }
    Ok(Some(decoded))
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn checked_utf8(
    bytes: Vec<u8>,
    row: usize,
    column: usize,
) -> Result<String, DatabaseConfigRuntimeParseError> {
    let value = String::from_utf8(bytes)
        .map_err(|_| DatabaseConfigRuntimeParseError::InvalidUtf8 { row, column })?;
    if value.chars().any(is_unsafe_display_character) {
        return Err(DatabaseConfigRuntimeParseError::DecodedControlCharacter { row, column });
    }
    Ok(value)
}

fn is_unsafe_display_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{00ad}'
                | '\u{034f}'
                | '\u{061c}'
                | '\u{115f}'..='\u{1160}'
                | '\u{17b4}'..='\u{17b5}'
                | '\u{180b}'..='\u{180f}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}'
                | '\u{3164}'
                | '\u{fe00}'..='\u{fe0f}'
                | '\u{feff}'
                | '\u{ffa0}'
                | '\u{fff9}'..='\u{fffb}'
                | '\u{1bca0}'..='\u{1bca3}'
                | '\u{1d173}'..='\u{1d17a}'
                | '\u{e0000}'..='\u{e0fff}'
        )
}

fn valid_runtime_name(provider: DatabaseConfigRuntimeSqlProvider, name: &str) -> bool {
    if name.is_empty()
        || name.len() > MAX_DATABASE_CONFIG_RUNTIME_NAME_BYTES
        || name.chars().any(is_unsafe_display_character)
    {
        return false;
    }
    match provider {
        DatabaseConfigRuntimeSqlProvider::MySqlPerformanceSchema
        | DatabaseConfigRuntimeSqlProvider::MariaDbInformationSchema => name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')),
        DatabaseConfigRuntimeSqlProvider::PostgreSqlPgSettings => {
            name.split('.').all(valid_postgresql_identifier_segment)
        }
    }
}

fn valid_postgresql_identifier_segment(segment: &str) -> bool {
    let mut bytes = segment.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == b'_' || !first.is_ascii()) {
        return false;
    }
    bytes
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$') || !byte.is_ascii())
}

fn classify_runtime_name(name: &str) -> DatabaseConfigRuntimeSensitivity {
    let compact = name
        .bytes()
        .filter(u8::is_ascii_alphanumeric)
        .map(|byte| byte.to_ascii_lowercase() as char)
        .collect::<String>();
    let tokens = name
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();

    if ["privatekey", "sslkey", "tlskey", "keyfile", "keypath"]
        .iter()
        .any(|needle| compact.contains(needle))
    {
        return DatabaseConfigRuntimeSensitivity::PrivateKeyReference;
    }
    if [
        "password",
        "passwd",
        "secret",
        "credential",
        "passphrase",
        "authorization",
        "authenticationstring",
        "apikey",
        "accesskey",
        "encryptionkey",
        "masterkey",
    ]
    .iter()
    .any(|needle| compact.contains(needle))
        || tokens.iter().any(|token| token == "token")
        || tokens.iter().any(|token| token == "pwd")
        || tokens.iter().any(|token| token == "auth")
        || tokens
            .iter()
            .any(|token| matches!(token.as_str(), "uri" | "url" | "dsn" | "conninfo"))
        || compact.contains("connectionstring")
        || compact.ends_with("command")
    {
        return DatabaseConfigRuntimeSensitivity::MayContainSecrets;
    }
    // Runtime clients and the target are both attacker-controlled. Unknown
    // values must not become public merely because their name lacks a known
    // secret marker: a replaced mysql/psql binary could echo the credential
    // under any benign-looking parameter name. A future public value path
    // must be granted by an exact product/version schema and type validation.
    DatabaseConfigRuntimeSensitivity::MayContainSecrets
}

fn classify_runtime_carrier(bytes: &[u8]) -> Option<DatabaseConfigRuntimeSensitivity> {
    if contains_private_key_pem_header(bytes) {
        return Some(DatabaseConfigRuntimeSensitivity::PrivateKeyReference);
    }
    if contains_credential_assignment(bytes)
        || contains_ascii_case_insensitive(bytes, b"bearer ")
        || uri_contains_userinfo(bytes)
    {
        return Some(DatabaseConfigRuntimeSensitivity::MayContainSecrets);
    }
    None
}

fn contains_private_key_pem_header(bytes: &[u8]) -> bool {
    let begin = b"-----BEGIN ";
    if bytes.len() < begin.len() {
        return false;
    }
    for offset in 0..=bytes.len() - begin.len() {
        if !bytes[offset..offset + begin.len()].eq_ignore_ascii_case(begin) {
            continue;
        }
        let header = &bytes[offset..bytes.len().min(offset + 128)];
        let header_end = header
            .iter()
            .position(|byte| matches!(byte, b'\r' | b'\n'))
            .unwrap_or(header.len());
        if contains_ascii_case_insensitive(&header[..header_end], b"PRIVATE KEY") {
            return true;
        }
    }
    false
}

fn contains_credential_assignment(bytes: &[u8]) -> bool {
    for key in [
        b"password".as_slice(),
        b"passwd".as_slice(),
        b"pwd".as_slice(),
        b"passphrase".as_slice(),
        b"secret".as_slice(),
        b"token".as_slice(),
        b"api_key".as_slice(),
        b"apikey".as_slice(),
        b"access_key".as_slice(),
        b"authorization".as_slice(),
    ] {
        if bytes.len() < key.len() {
            continue;
        }
        for offset in 0..=bytes.len() - key.len() {
            if !bytes[offset..offset + key.len()].eq_ignore_ascii_case(key) {
                continue;
            }
            let mut remainder = &bytes[offset + key.len()..];
            if offset > 0
                && bytes[offset - 1] == b'-'
                && remainder.first().is_some_and(u8::is_ascii_whitespace)
                && !trim_ascii_space_start(remainder).is_empty()
            {
                return true;
            }
            remainder = trim_ascii_space_start(remainder);
            if remainder
                .first()
                .is_some_and(|byte| matches!(byte, b'\'' | b'"'))
            {
                remainder = trim_ascii_space_start(&remainder[1..]);
            }
            if remainder
                .first()
                .is_some_and(|byte| matches!(byte, b':' | b'='))
            {
                return true;
            }
        }
    }
    false
}

fn trim_ascii_space_start(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(|byte| byte.is_ascii_whitespace()) {
        bytes = &bytes[1..];
    }
    bytes
}

fn contains_ascii_case_insensitive(bytes: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && bytes
            .windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle))
}

fn uri_contains_userinfo(bytes: &[u8]) -> bool {
    for (scheme_end, separator) in bytes.windows(3).enumerate() {
        if separator != b"://" {
            continue;
        }
        let authority = &bytes[scheme_end + 3..];
        let authority_end = authority
            .iter()
            .position(|byte| matches!(byte, b'/' | b'?' | b'#') || byte.is_ascii_whitespace())
            .unwrap_or(authority.len());
        if authority[..authority_end]
            .iter()
            .position(|byte| *byte == b'@')
            .is_some_and(|position| position > 0)
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(
        provider: DatabaseConfigRuntimeSqlProvider,
        product: DatabaseConfigProduct,
        artifact_key: &'static str,
    ) -> DatabaseConfigRuntimeTarget<'static> {
        let version = match product {
            DatabaseConfigProduct::MySql => DatabaseConfigVersion::new(8, 0, 43),
            DatabaseConfigProduct::MariaDb => DatabaseConfigVersion::new(10, 11, 0),
            DatabaseConfigProduct::PostgreSql => DatabaseConfigVersion::new(18, 0, 0),
            _ => DatabaseConfigVersion::new(1, 0, 0),
        };
        DatabaseConfigRuntimeTarget {
            provider,
            product,
            version,
            edition_key: Some(COMMUNITY_EDITION_KEY),
            component: DatabaseConfigComponent::RuntimeParameters,
            artifact_key,
        }
    }

    fn parse(
        plan: &'static DatabaseConfigRuntimeQueryPlan,
        bytes: Vec<u8>,
    ) -> Result<DatabaseConfigRuntimeDocument, DatabaseConfigRuntimeParseError> {
        plan.parse_tsv(Zeroizing::new(bytes))
    }

    fn parse_error(
        plan: &'static DatabaseConfigRuntimeQueryPlan,
        bytes: Vec<u8>,
    ) -> DatabaseConfigRuntimeParseError {
        parse(plan, bytes).unwrap_err()
    }

    fn identity_plan(product: DatabaseConfigProduct) -> &'static DatabaseConfigRuntimeIdentityPlan {
        database_config_runtime_identity_plan(product).unwrap()
    }

    fn identity_wire(cells: &[&str]) -> Vec<u8> {
        cells
            .iter()
            .map(|value| hex(value))
            .collect::<Vec<_>>()
            .join("\t")
            .into_bytes()
    }

    fn parse_identity(
        product: DatabaseConfigProduct,
        cells: &[&str],
    ) -> Result<DatabaseConfigRuntimeIdentity, DatabaseConfigRuntimeIdentityParseError> {
        identity_plan(product).parse_tsv(Zeroizing::new(identity_wire(cells)))
    }

    fn identity_error(
        product: DatabaseConfigProduct,
        cells: &[&str],
    ) -> DatabaseConfigRuntimeIdentityParseError {
        parse_identity(product, cells).unwrap_err()
    }

    fn mysql_plan() -> &'static DatabaseConfigRuntimeQueryPlan {
        database_config_runtime_query_plan(target(
            DatabaseConfigRuntimeSqlProvider::MySqlPerformanceSchema,
            DatabaseConfigProduct::MySql,
            "mysql-runtime-variables",
        ))
        .unwrap()
    }

    fn postgresql_plan() -> &'static DatabaseConfigRuntimeQueryPlan {
        database_config_runtime_query_plan(target(
            DatabaseConfigRuntimeSqlProvider::PostgreSqlPgSettings,
            DatabaseConfigProduct::PostgreSql,
            "postgresql-runtime-parameters",
        ))
        .unwrap()
    }

    fn hex(value: &str) -> String {
        value
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect()
    }

    fn wire_row(cells: [&str; RUNTIME_TSV_COLUMNS]) -> String {
        cells.join("\t")
    }

    fn mysql_row(name: &str, value: Option<&str>) -> String {
        wire_row([
            &hex(name),
            &value.map(hex).unwrap_or_else(|| "-".to_owned()),
            &hex("global"),
            &hex("vendor-defined"),
            &hex("COMPILED"),
            "-",
            "-",
            "-",
            "-",
        ])
    }

    #[test]
    fn query_catalog_contains_only_closed_read_only_selects() {
        assert_eq!(DATABASE_CONFIG_RUNTIME_QUERY_PLANS.len(), 7);
        for (index, plan) in DATABASE_CONFIG_RUNTIME_QUERY_PLANS.iter().enumerate() {
            assert!(plan.query().trim_start().starts_with("SELECT"));
            assert!(!plan.query().contains(';'));
            assert!(plan.reference().url.starts_with("https://"));
            assert!(!plan.reference().id.is_empty());
            for forbidden in [
                "INSERT", "UPDATE", "DELETE", "ALTER", "DROP", "TRUNCATE", "CALL",
            ] {
                assert!(
                    !plan
                        .query()
                        .split(|character: char| !character.is_ascii_alphanumeric())
                        .any(|token| token.eq_ignore_ascii_case(forbidden)),
                    "{} unexpectedly contains {forbidden}",
                    plan.id()
                );
            }
            assert!(
                DATABASE_CONFIG_RUNTIME_QUERY_PLANS[..index]
                    .iter()
                    .all(|previous| previous.id() != plan.id())
            );
        }
    }

    #[test]
    fn identity_catalog_is_closed_and_accepts_only_native_declared_products() {
        assert_eq!(DATABASE_CONFIG_RUNTIME_IDENTITY_PLANS.len(), 3);
        for (index, plan) in DATABASE_CONFIG_RUNTIME_IDENTITY_PLANS.iter().enumerate() {
            assert!(plan.query().trim_start().starts_with("SELECT"));
            assert!(!plan.query().contains(';'));
            assert_eq!(
                plan.wire_format(),
                DatabaseConfigRuntimeWireFormat::HeaderlessHexTsvV1
            );
            assert!((1..=3).contains(&plan.expected_columns()));
            for forbidden in [
                "INSERT", "UPDATE", "DELETE", "ALTER", "DROP", "TRUNCATE", "CALL",
            ] {
                assert!(
                    !plan
                        .query()
                        .split(|character: char| !character.is_ascii_alphanumeric())
                        .any(|token| token.eq_ignore_ascii_case(forbidden)),
                    "{} unexpectedly contains {forbidden}",
                    plan.id()
                );
            }
            assert!(
                DATABASE_CONFIG_RUNTIME_IDENTITY_PLANS[..index]
                    .iter()
                    .all(|previous| previous.id() != plan.id())
            );
        }
        assert_eq!(
            database_config_runtime_identity_plan(DatabaseConfigProduct::TiDb),
            Err(DatabaseConfigRuntimeIdentityLookupError::UnsupportedDeclaredProduct)
        );
        assert_eq!(
            database_config_runtime_identity_plan(DatabaseConfigProduct::OpenGauss),
            Err(DatabaseConfigRuntimeIdentityLookupError::UnsupportedDeclaredProduct)
        );
    }

    #[test]
    fn mysql_identity_enforces_community_signature_and_reviewed_boundaries() {
        let community = "MySQL Community Server - GPL";
        for version in ["8.0.11", "8.0.43", "8.4.0", "8.4.99"] {
            let identity =
                parse_identity(DatabaseConfigProduct::MySql, &[version, community]).unwrap();
            assert_eq!(identity.product(), DatabaseConfigProduct::MySql);
            assert_eq!(identity.edition(), DatabaseConfigRuntimeEdition::Community);
            let target = identity.runtime_target();
            assert_eq!(
                target.provider,
                DatabaseConfigRuntimeSqlProvider::MySqlPerformanceSchema
            );
            assert_eq!(target.product, DatabaseConfigProduct::MySql);
            assert_eq!(target.edition_key, Some(COMMUNITY_EDITION_KEY));
            assert_eq!(target.component, DatabaseConfigComponent::RuntimeParameters);
            assert_eq!(target.artifact_key, "mysql-runtime-variables");
            assert!(database_config_runtime_query_plan(target).is_ok());
        }
        for version in ["8.0.10", "8.1.0", "8.3.99", "8.5.0", "9.0.0"] {
            assert_eq!(
                identity_error(DatabaseConfigProduct::MySql, &[version, community]),
                DatabaseConfigRuntimeIdentityParseError::UnsupportedVersion
            );
        }
        assert_eq!(
            identity_error(
                DatabaseConfigProduct::MySql,
                &["8.4.1", "MySQL Enterprise Server - Commercial"]
            ),
            DatabaseConfigRuntimeIdentityParseError::UntrustedEdition
        );
        assert_eq!(
            identity_error(
                DatabaseConfigProduct::MySql,
                &["8.4.1", "Google Cloud SQL for MySQL"]
            ),
            DatabaseConfigRuntimeIdentityParseError::UntrustedEdition
        );
        assert_eq!(
            identity_error(
                DatabaseConfigProduct::MySql,
                &["10.11.8-MariaDB", "mariadb.org binary distribution"]
            ),
            DatabaseConfigRuntimeIdentityParseError::DeclaredProductMismatch
        );
    }

    #[test]
    fn mariadb_identity_requires_exact_community_suffix_and_minor_families() {
        for version in [
            "10.11.0-MariaDB",
            "10.11.99-MariaDB",
            "10.11.99-MariaDB-log",
            "11.4.0-MariaDB",
            "11.4.99-MariaDB",
        ] {
            let identity = parse_identity(DatabaseConfigProduct::MariaDb, &[version]).unwrap();
            let target = identity.runtime_target();
            assert_eq!(identity.product(), DatabaseConfigProduct::MariaDb);
            assert_eq!(
                target.provider,
                DatabaseConfigRuntimeSqlProvider::MariaDbInformationSchema
            );
            assert_eq!(target.edition_key, Some(COMMUNITY_EDITION_KEY));
            assert_eq!(target.artifact_key, "mariadb-runtime-variables");
            assert!(database_config_runtime_query_plan(target).is_ok());
        }
        for version in [
            "10.10.99-MariaDB",
            "10.12.0-MariaDB",
            "11.3.99-MariaDB",
            "11.5.0-MariaDB",
        ] {
            assert_eq!(
                identity_error(DatabaseConfigProduct::MariaDb, &[version]),
                DatabaseConfigRuntimeIdentityParseError::UnsupportedVersion
            );
        }
        assert_eq!(
            identity_error(
                DatabaseConfigProduct::MariaDb,
                &["11.4.3-MariaDB-enterprise"]
            ),
            DatabaseConfigRuntimeIdentityParseError::UntrustedEdition
        );
        assert_eq!(
            identity_error(DatabaseConfigProduct::MariaDb, &["8.0.43"]),
            DatabaseConfigRuntimeIdentityParseError::DeclaredProductMismatch
        );
    }

    #[test]
    fn postgresql_packaging_labels_preserve_three_way_version_checks() {
        for display in [
            "16.15 (Debian 16.15-1.pgdg13+2)",
            "16.15 (Ubuntu 16.15-0ubuntu0.24.04.1)",
        ] {
            let banner = format!(
                "PostgreSQL {display} on x86_64-pc-linux-gnu, compiled by gcc (Debian 14.2.0-19) 14.2.0, 64-bit"
            );
            let identity = parse_identity(
                DatabaseConfigProduct::PostgreSql,
                &["160015", display, &banner],
            )
            .unwrap();
            assert_eq!(identity.version(), DatabaseConfigVersion::new(16, 15, 0));
            assert_eq!(
                identity_error(
                    DatabaseConfigProduct::PostgreSql,
                    &["160014", display, &banner]
                ),
                DatabaseConfigRuntimeIdentityParseError::InconsistentVersionSources
            );
        }
        for display in [
            "16.15 (Acme 16.15-1)",
            "16.15 (Debian 16.14-1)",
            "16.15 (Debian 16.15-)",
            "16.15 (Debian 16.15-1) ignored",
            "16.15 (Debian 16.15-1 openGauss)",
            "16.15 (Debian 16.15-openGauss)",
            "16.15 (Debian 16.15-1",
            "16.15 (Debian 16.15-1) (Debian 16.15-1)",
        ] {
            let banner =
                format!("PostgreSQL {display} on x86_64-pc-linux-gnu, compiled by gcc, 64-bit");
            assert!(
                parse_identity(
                    DatabaseConfigProduct::PostgreSql,
                    &["160015", display, &banner]
                )
                .is_err()
            );
        }
    }

    #[test]
    fn postgresql_identity_requires_three_consistent_stable_upstream_sources() {
        for (number, version) in [("160002", "16.2"), ("170006", "17.6"), ("180000", "18.0")] {
            let banner =
                format!("PostgreSQL {version} on x86_64-pc-linux-gnu, compiled by gcc, 64-bit");
            let identity = parse_identity(
                DatabaseConfigProduct::PostgreSql,
                &[number, version, &banner],
            )
            .unwrap();
            let target = identity.runtime_target();
            assert_eq!(
                identity.version().major(),
                number[..2].parse::<u16>().unwrap()
            );
            assert_eq!(
                target.provider,
                DatabaseConfigRuntimeSqlProvider::PostgreSqlPgSettings
            );
            assert_eq!(target.edition_key, Some(COMMUNITY_EDITION_KEY));
            assert_eq!(target.artifact_key, "postgresql-runtime-parameters");
            assert!(database_config_runtime_query_plan(target).is_ok());
        }
        assert_eq!(
            identity_error(
                DatabaseConfigProduct::PostgreSql,
                &[
                    "160002",
                    "16.3",
                    "PostgreSQL 16.3 on x86_64-pc-linux-gnu, compiled by gcc, 64-bit",
                ]
            ),
            DatabaseConfigRuntimeIdentityParseError::InconsistentVersionSources
        );
        for prerelease in ["18beta1", "18rc1", "18devel"] {
            let banner =
                format!("PostgreSQL {prerelease} on x86_64-pc-linux-gnu, compiled by gcc, 64-bit");
            assert_eq!(
                identity_error(
                    DatabaseConfigProduct::PostgreSql,
                    &["180000", prerelease, &banner]
                ),
                DatabaseConfigRuntimeIdentityParseError::PreReleaseOrDevelopment
            );
        }
        assert_eq!(
            identity_error(
                DatabaseConfigProduct::PostgreSql,
                &[
                    "160002",
                    "16.2",
                    "EnterpriseDB 16.2 on x86_64-pc-linux-gnu, compiled by gcc, 64-bit",
                ]
            ),
            DatabaseConfigRuntimeIdentityParseError::UntrustedEdition
        );
        for banner in [
            "PostgreSQL 16.2 on Aurora, compiled by gcc, 64-bit",
            "PostgreSQL 16.2 on openGauss, compiled by gcc, 64-bit",
        ] {
            assert_eq!(
                identity_error(
                    DatabaseConfigProduct::PostgreSql,
                    &["160002", "16.2", banner]
                ),
                DatabaseConfigRuntimeIdentityParseError::UntrustedEdition
            );
        }
        assert_eq!(
            identity_error(
                DatabaseConfigProduct::PostgreSql,
                &["160002", "16.2", "PostgreSQL 16.2 Acme Commercial 64-bit"]
            ),
            DatabaseConfigRuntimeIdentityParseError::UntrustedIdentity
        );
        assert_eq!(
            identity_error(
                DatabaseConfigProduct::PostgreSql,
                &[
                    "160002",
                    "16.2",
                    "MySQL 8.0.43 on x86_64-pc-linux-gnu, compiled by gcc, 64-bit",
                ]
            ),
            DatabaseConfigRuntimeIdentityParseError::DeclaredProductMismatch
        );
        assert_eq!(
            identity_error(
                DatabaseConfigProduct::PostgreSql,
                &[
                    "190000",
                    "19.0",
                    "PostgreSQL 19.0 on x86_64-pc-linux-gnu, compiled by gcc, 64-bit",
                ]
            ),
            DatabaseConfigRuntimeIdentityParseError::UnsupportedVersion
        );
    }

    #[test]
    fn identity_wire_is_single_row_exact_shape_bounded_and_non_echoing() {
        let mysql = identity_plan(DatabaseConfigProduct::MySql);
        assert_eq!(
            mysql
                .parse_tsv(Zeroizing::new(
                    format!("{}\n{}", hex("8.0.43"), hex("second-row")).into_bytes()
                ))
                .unwrap_err(),
            DatabaseConfigRuntimeIdentityParseError::InvalidRowCount
        );
        assert_eq!(
            mysql
                .parse_tsv(Zeroizing::new(identity_wire(&["8.0.43"])))
                .unwrap_err(),
            DatabaseConfigRuntimeIdentityParseError::InvalidColumnCount {
                expected: 2,
                actual: 1,
            }
        );
        assert_eq!(
            mysql
                .parse_tsv(Zeroizing::new(identity_wire(&[
                    "8.0.43",
                    "MySQL Community Server - GPL",
                    "extra",
                ])))
                .unwrap_err(),
            DatabaseConfigRuntimeIdentityParseError::InvalidColumnCount {
                expected: 2,
                actual: 3,
            }
        );
        assert_eq!(
            mysql
                .parse_tsv(Zeroizing::new(b"1\t32".to_vec()))
                .unwrap_err(),
            DatabaseConfigRuntimeIdentityParseError::InvalidHex { column: 0 }
        );
        assert!(matches!(
            mysql
                .parse_tsv(Zeroizing::new(b"31\x01\t32".to_vec()))
                .unwrap_err(),
            DatabaseConfigRuntimeIdentityParseError::ControlCharacter { .. }
        ));
        let decoded_control = format!("{}\t{}", hex("8.0.43\nDontLeak"), hex("community"));
        let error = mysql
            .parse_tsv(Zeroizing::new(decoded_control.into_bytes()))
            .unwrap_err();
        assert_eq!(
            error,
            DatabaseConfigRuntimeIdentityParseError::DecodedControlCharacter { column: 0 }
        );
        assert!(!format!("{error:?}").contains("DontLeak"));
        assert_eq!(
            mysql
                .parse_tsv(Zeroizing::new(vec![
                    b'0';
                    MAX_DATABASE_CONFIG_RUNTIME_IDENTITY_TSV_BYTES
                        + 1
                ]))
                .unwrap_err(),
            DatabaseConfigRuntimeIdentityParseError::InputTooLarge
        );

        let valid_crlf = format!(
            "{}\t{}\r\n",
            hex("8.0.43"),
            hex("MySQL Community Server - GPL")
        );
        assert!(
            mysql
                .parse_tsv(Zeroizing::new(valid_crlf.into_bytes()))
                .is_ok()
        );
    }

    fn postgres_row(
        name: &str,
        value: &str,
        context: &str,
        pending_restart: bool,
        enum_json: Option<&str>,
    ) -> String {
        wire_row([
            &hex(name),
            &hex(value),
            &hex("server-or-session"),
            &hex(context),
            &hex("configuration file"),
            &hex(if pending_restart { "true" } else { "false" }),
            &hex("1"),
            &hex("100"),
            &enum_json.map(hex).unwrap_or_else(|| "-".to_owned()),
        ])
    }

    #[test]
    fn lookup_requires_exact_provider_product_component_and_runtime_artifact() {
        let mysql = database_config_runtime_query_plan(target(
            DatabaseConfigRuntimeSqlProvider::MySqlPerformanceSchema,
            DatabaseConfigProduct::MySql,
            "mysql-runtime-variables",
        ))
        .unwrap();
        assert_eq!(mysql.id(), "mysql-8.0-runtime-read-only-v1");
        assert!(mysql.query().trim_start().starts_with("SELECT"));
        assert!(
            mysql
                .query()
                .contains("INNER JOIN performance_schema.global_variables")
        );

        assert_eq!(
            database_config_runtime_query_plan(target(
                DatabaseConfigRuntimeSqlProvider::MariaDbInformationSchema,
                DatabaseConfigProduct::MySql,
                "mysql-runtime-variables",
            )),
            Err(DatabaseConfigRuntimeLookupError::ProviderMismatch)
        );
        assert_eq!(
            database_config_runtime_query_plan(target(
                DatabaseConfigRuntimeSqlProvider::MySqlPerformanceSchema,
                DatabaseConfigProduct::MariaDb,
                "mysql-runtime-variables",
            )),
            Err(DatabaseConfigRuntimeLookupError::ProductMismatch)
        );
        assert_eq!(
            database_config_runtime_query_plan(DatabaseConfigRuntimeTarget {
                provider: DatabaseConfigRuntimeSqlProvider::MySqlPerformanceSchema,
                product: DatabaseConfigProduct::MySql,
                version: DatabaseConfigVersion::new(8, 0, 43),
                edition_key: Some(COMMUNITY_EDITION_KEY),
                component: DatabaseConfigComponent::Server,
                artifact_key: "mysql-runtime-variables",
            }),
            Err(DatabaseConfigRuntimeLookupError::ComponentMismatch)
        );
        assert_eq!(
            database_config_runtime_query_plan(DatabaseConfigRuntimeTarget {
                provider: DatabaseConfigRuntimeSqlProvider::MySqlPerformanceSchema,
                product: DatabaseConfigProduct::MySql,
                version: DatabaseConfigVersion::new(8, 0, 43),
                edition_key: Some(COMMUNITY_EDITION_KEY),
                component: DatabaseConfigComponent::Server,
                artifact_key: "mysql-option-file",
            }),
            Err(DatabaseConfigRuntimeLookupError::Unsupported)
        );
        assert_eq!(
            database_config_runtime_query_plan(target(
                DatabaseConfigRuntimeSqlProvider::MySqlPerformanceSchema,
                DatabaseConfigProduct::MySql,
                "mysql-option-file",
            )),
            Err(DatabaseConfigRuntimeLookupError::ComponentMismatch)
        );
        assert_eq!(
            database_config_runtime_query_plan(target(
                DatabaseConfigRuntimeSqlProvider::PostgreSqlPgSettings,
                DatabaseConfigProduct::Dm,
                "dm-runtime-parameters",
            )),
            Err(DatabaseConfigRuntimeLookupError::VendorSchemaRequired)
        );
        assert_eq!(
            database_config_runtime_query_plan(target(
                DatabaseConfigRuntimeSqlProvider::PostgreSqlPgSettings,
                DatabaseConfigProduct::PostgreSql,
                "missing-runtime-artifact",
            )),
            Err(DatabaseConfigRuntimeLookupError::ArtifactUnknown)
        );
    }

    #[test]
    fn lookup_enforces_reviewed_version_and_edition_boundaries() {
        let mut mysql = target(
            DatabaseConfigRuntimeSqlProvider::MySqlPerformanceSchema,
            DatabaseConfigProduct::MySql,
            "mysql-runtime-variables",
        );
        mysql.version = DatabaseConfigVersion::new(8, 0, 10);
        assert_eq!(
            database_config_runtime_query_plan(mysql),
            Err(DatabaseConfigRuntimeLookupError::VersionMismatch)
        );
        mysql.version = DatabaseConfigVersion::new(8, 0, 11);
        assert_eq!(
            database_config_runtime_query_plan(mysql).unwrap().id(),
            "mysql-8.0-runtime-read-only-v1"
        );
        mysql.version = DatabaseConfigVersion::new(8, 1, 0);
        assert_eq!(
            database_config_runtime_query_plan(mysql),
            Err(DatabaseConfigRuntimeLookupError::VersionMismatch)
        );
        mysql.version = DatabaseConfigVersion::new(8, 4, 0);
        assert_eq!(
            database_config_runtime_query_plan(mysql).unwrap().id(),
            "mysql-8.4-runtime-read-only-v1"
        );
        mysql.version = DatabaseConfigVersion::new(8, 5, 0);
        assert_eq!(
            database_config_runtime_query_plan(mysql),
            Err(DatabaseConfigRuntimeLookupError::VersionMismatch)
        );
        mysql.version = DatabaseConfigVersion::new(8, 4, 0);
        mysql.edition_key = None;
        assert_eq!(
            database_config_runtime_query_plan(mysql),
            Err(DatabaseConfigRuntimeLookupError::EditionMismatch)
        );
        mysql.edition_key = Some("enterprise");
        assert_eq!(
            database_config_runtime_query_plan(mysql),
            Err(DatabaseConfigRuntimeLookupError::EditionMismatch)
        );
        mysql.edition_key = Some("bad\nkey");
        assert_eq!(
            database_config_runtime_query_plan(mysql),
            Err(DatabaseConfigRuntimeLookupError::InvalidEditionKey)
        );

        let mut mariadb = target(
            DatabaseConfigRuntimeSqlProvider::MariaDbInformationSchema,
            DatabaseConfigProduct::MariaDb,
            "mariadb-runtime-variables",
        );
        mariadb.version = DatabaseConfigVersion::new(10, 10, 99);
        assert_eq!(
            database_config_runtime_query_plan(mariadb),
            Err(DatabaseConfigRuntimeLookupError::VersionMismatch)
        );
        mariadb.version = DatabaseConfigVersion::new(10, 11, 0);
        assert_eq!(
            database_config_runtime_query_plan(mariadb).unwrap().id(),
            "mariadb-10.11-runtime-read-only-v1"
        );
        mariadb.version = DatabaseConfigVersion::new(10, 12, 0);
        assert_eq!(
            database_config_runtime_query_plan(mariadb),
            Err(DatabaseConfigRuntimeLookupError::VersionMismatch)
        );
        mariadb.version = DatabaseConfigVersion::new(11, 4, 0);
        assert_eq!(
            database_config_runtime_query_plan(mariadb).unwrap().id(),
            "mariadb-11.4-runtime-read-only-v1"
        );
        mariadb.version = DatabaseConfigVersion::new(11, 5, 0);
        assert_eq!(
            database_config_runtime_query_plan(mariadb),
            Err(DatabaseConfigRuntimeLookupError::VersionMismatch)
        );

        let mut postgres = target(
            DatabaseConfigRuntimeSqlProvider::PostgreSqlPgSettings,
            DatabaseConfigProduct::PostgreSql,
            "postgresql-runtime-parameters",
        );
        postgres.version = DatabaseConfigVersion::new(15, 99, 0);
        assert_eq!(
            database_config_runtime_query_plan(postgres),
            Err(DatabaseConfigRuntimeLookupError::VersionMismatch)
        );
        for major in 16..=18 {
            postgres.version = DatabaseConfigVersion::new(major, 0, 0);
            assert_eq!(
                database_config_runtime_query_plan(postgres).unwrap().id(),
                match major {
                    16 => "postgresql-16-runtime-read-only-v1",
                    17 => "postgresql-17-runtime-read-only-v1",
                    _ => "postgresql-18-runtime-read-only-v1",
                }
            );
        }
        postgres.version = DatabaseConfigVersion::new(19, 0, 0);
        assert_eq!(
            database_config_runtime_query_plan(postgres),
            Err(DatabaseConfigRuntimeLookupError::VersionMismatch)
        );
    }

    #[test]
    fn parser_preserves_duplicate_names_and_order_but_redacts_unknown_values() {
        let plan = mysql_plan();
        let injection = "'; DROP TABLE runtime_settings; --";
        let input = [
            mysql_row("duplicate_name", Some(injection)),
            mysql_row("duplicate_name", Some("second")),
            mysql_row("last_name", Some("third")),
        ]
        .join("\n");
        let document = parse(plan, input.into_bytes()).unwrap();

        assert_eq!(document.rows().len(), 3);
        assert_eq!(document.rows()[0].name(), "duplicate_name");
        assert_eq!(document.rows()[0].value().public_value(), None);
        assert_eq!(document.rows()[1].name(), "duplicate_name");
        assert_eq!(document.rows()[1].value().public_value(), None);
        assert_eq!(document.rows()[2].name(), "last_name");
        assert!(!plan.query().contains(injection));
        assert!(!format!("{document:?}").contains(injection));
        assert!(!format!("{document:?}").contains("second"));
    }

    #[test]
    fn sensitive_names_and_carriers_discard_plaintext_before_storage() {
        let plan = mysql_plan();
        let secret = "DontLeak-credential";
        let input = [
            mysql_row("admin_password", Some(secret)),
            mysql_row("ssl_private_key_file", Some("/private/server.key")),
            mysql_row("upstream_dsn", Some("mysql://user:password@host/db")),
            mysql_row("archive_command", Some("uploader --token DontLeak")),
            mysql_row("wsrep_sst_auth", Some("sst-user:DontLeak")),
            mysql_row("benign_setting", Some("mysql://user:DontLeak@host/db")),
            mysql_row(
                "benign_pem",
                Some("-----BEGIN DSA PRIVATE KEY-----\nDontLeak\n-----END DSA PRIVATE KEY-----"),
            ),
            mysql_row("benign_json", Some(r#"{"password":"DontLeak"}"#)),
            mysql_row("benign_assignment", Some("password = DontLeak")),
            mysql_row("benign_cli", Some("uploader --token DontLeak")),
            mysql_row("api_token", None),
        ]
        .join("\n");
        let document = parse(plan, input.into_bytes()).unwrap();
        let cloned = document.clone();

        let password = document.rows()[0].value();
        assert_eq!(
            password.sensitivity(),
            DatabaseConfigRuntimeSensitivity::MayContainSecrets
        );
        assert_eq!(
            password.presence(),
            DatabaseConfigRuntimeValuePresence::Present
        );
        assert_eq!(password.public_value(), None);
        assert_eq!(
            password.sensitive_sha256.as_ref(),
            Some(&Sha256::digest(secret.as_bytes()).into())
        );
        assert!(password.has_redacted_fingerprint());
        assert_eq!(
            document.rows()[1].value().sensitivity(),
            DatabaseConfigRuntimeSensitivity::PrivateKeyReference
        );
        assert_eq!(
            document.rows()[2].value().sensitivity(),
            DatabaseConfigRuntimeSensitivity::MayContainSecrets
        );
        assert_eq!(
            document.rows()[3].value().presence(),
            DatabaseConfigRuntimeValuePresence::Present
        );
        assert_eq!(
            document.rows()[3].value().sensitivity(),
            DatabaseConfigRuntimeSensitivity::MayContainSecrets
        );
        assert_eq!(
            document.rows()[4].value().sensitivity(),
            DatabaseConfigRuntimeSensitivity::MayContainSecrets
        );
        assert_eq!(
            document.rows()[5].value().sensitivity(),
            DatabaseConfigRuntimeSensitivity::MayContainSecrets
        );
        assert_eq!(document.rows()[5].value().public_value(), None);
        assert_eq!(
            document.rows()[6].value().sensitivity(),
            DatabaseConfigRuntimeSensitivity::PrivateKeyReference
        );
        assert_eq!(document.rows()[6].value().public_value(), None);
        for row in &document.rows()[7..=9] {
            assert_eq!(
                row.value().sensitivity(),
                DatabaseConfigRuntimeSensitivity::MayContainSecrets
            );
            assert_eq!(row.value().public_value(), None);
        }
        assert_eq!(
            document.rows()[10].value().presence(),
            DatabaseConfigRuntimeValuePresence::Null
        );
        assert_eq!(document.rows()[10].value().sensitive_sha256, None);
        assert!(!format!("{document:?}").contains(secret));
        assert!(!format!("{cloned:?}").contains(secret));
        assert!(!format!("{document:?}").contains("DontLeak"));
        assert!(!format!("{cloned:?}").contains("DontLeak"));
        assert!(!format!("{:?}", document.rows()[1]).contains("/private/server.key"));
    }

    #[test]
    fn native_postgresql_discloses_only_reviewed_scalar_values() {
        let samples = [
            ("ssl", "on", Some("on")),
            ("ssl", "NativeScalarSecretCanary", None),
            ("ssl", "ON", None),
            (
                "password_encryption",
                "scram-sha-256",
                Some("scram-sha-256"),
            ),
            ("password_encryption", "NativeScalarSecretCanary", None),
            ("log_statement", "ddl", Some("ddl")),
            ("listen_addresses", "*", Some("*")),
            ("listen_addresses", "private-db.internal", None),
            ("ssl_max_protocol_version", "", Some("")),
            ("extension.ssl", "on", None),
            (
                "primary_conninfo",
                "password=NativeScalarSecretCanary",
                None,
            ),
        ];
        let input = samples
            .iter()
            .map(|(name, value, _)| postgres_row(name, value, "sighup", false, None))
            .collect::<Vec<_>>()
            .join("\n");
        let plan = postgresql_plan();
        let protected = plan
            .parse_tsv(Zeroizing::new(input.as_bytes().to_vec()))
            .unwrap();
        assert!(
            protected
                .rows()
                .iter()
                .all(|row| row.value().public_value().is_none())
        );
        let document = plan
            .parse_native_postgresql_tsv(Zeroizing::new(input.into_bytes()))
            .unwrap();
        for (row, (_, _, expected)) in document.rows().iter().zip(samples) {
            assert_eq!(row.value().public_value(), expected);
            if expected.is_none() {
                assert!(row.value().has_redacted_fingerprint());
            }
        }
        assert!(!format!("{document:?}").contains("NativeScalarSecretCanary"));
        assert!(
            mysql_plan()
                .parse_native_postgresql_tsv(Zeroizing::new(Vec::new()))
                .is_err()
        );
        let enum_input = postgres_row(
            "ssl_max_protocol_version",
            "",
            "sighup",
            false,
            Some(r#"["","TLSv1.2","TLSv1.3"]"#),
        );
        let document = plan
            .parse_native_postgresql_tsv(Zeroizing::new(enum_input.into_bytes()))
            .unwrap();
        assert_eq!(document.rows()[0].enum_values(), ["", "TLSv1.2", "TLSv1.3"]);
    }

    #[test]
    fn postgresql_empty_enum_choice_is_preserved_without_allowing_comma_list_holes() {
        let values = vec![String::new(), "TLSv1.2".to_owned(), "TLSv1.3".to_owned()];
        assert_eq!(
            validate_enum_values(values.clone(), 0, RuntimeEnumEncoding::PostgreSqlJsonArray)
                .unwrap(),
            values
        );
        assert!(validate_enum_values(values, 0, RuntimeEnumEncoding::MariaDbCommaList).is_err());
        assert!(
            validate_enum_values(
                vec!["\n".to_owned()],
                0,
                RuntimeEnumEncoding::PostgreSqlJsonArray
            )
            .is_err()
        );
    }

    #[test]
    fn postgresql_context_pending_restart_and_enum_metadata_are_typed() {
        let plan = postgresql_plan();
        let input = [
            postgres_row(
                "wal_level",
                "replica",
                "postmaster",
                true,
                Some(r#"["minimal","replica","logical"]"#),
            ),
            postgres_row("扩展.param$1", "safe", "user", false, None),
            postgres_row("ext.e\u{301}", "safe", "user", false, None),
        ]
        .join("\n");
        let document = parse(plan, input.into_bytes()).unwrap();
        let row = &document.rows()[0];

        assert_eq!(row.scope(), DatabaseConfigRuntimeScope::ServerOrSession);
        assert_eq!(
            row.apply(),
            DatabaseConfigRuntimeApply::PostgreSql(PostgreSqlRuntimeContext::Postmaster)
        );
        assert_eq!(row.pending_restart(), Some(true));
        assert_eq!(row.source(), Some("configuration file"));
        assert_eq!(row.minimum(), Some("1"));
        assert_eq!(row.maximum(), Some("100"));
        assert_eq!(row.enum_values(), ["minimal", "replica", "logical"]);
        assert_eq!(document.rows()[1].name(), "扩展.param$1");
        assert_eq!(document.rows()[2].name(), "ext.e\u{301}");
        let debug = format!("{document:?}");
        for remote_text in [
            "wal_level",
            "configuration file",
            "minimal",
            "replica",
            "logical",
            "扩展.param$1",
        ] {
            assert!(!debug.contains(remote_text));
        }
    }

    #[test]
    fn parser_rejects_bytes_rows_cells_depth_and_control_characters() {
        let plan = mysql_plan();
        assert_eq!(
            parse_error(plan, vec![b'0'; MAX_DATABASE_CONFIG_RUNTIME_TSV_BYTES + 1]),
            DatabaseConfigRuntimeParseError::InputTooLarge
        );

        let too_many_rows = "\n".repeat(MAX_DATABASE_CONFIG_RUNTIME_ROWS + 1);
        assert_eq!(
            parse_error(plan, too_many_rows.into_bytes()),
            DatabaseConfigRuntimeParseError::TooManyRows
        );

        let too_many_cells = "\t".repeat(MAX_DATABASE_CONFIG_RUNTIME_CELLS);
        assert_eq!(
            parse_error(plan, too_many_cells.into_bytes()),
            DatabaseConfigRuntimeParseError::TooManyCells
        );

        let mut raw_control = mysql_row("safe_name", Some("safe")).into_bytes();
        raw_control[0] = 0x01;
        assert!(matches!(
            parse_error(plan, raw_control),
            DatabaseConfigRuntimeParseError::ControlCharacter { .. }
        ));

        for (value, expected) in [
            ("line\nbreak", "line\\nbreak"),
            ("ok\u{200f}txt", "ok\\u{200f}txt"),
            ("ok\u{206a}txt", "ok\\u{206a}txt"),
        ] {
            let row = mysql_row("safe_name", Some(value));
            let document = parse(plan, row.into_bytes()).unwrap();
            assert_eq!(document.rows()[0].value().public_value(), None);
            assert_eq!(
                document.rows()[0].value().sensitivity(),
                DatabaseConfigRuntimeSensitivity::MayContainSecrets
            );
            let (escaped, was_escaped) = escape_public_value(value);
            assert_eq!(escaped, expected);
            assert!(was_escaped);
        }

        let unsafe_metadata = wire_row([
            &hex("safe_name"),
            &hex("safe"),
            &hex("global"),
            &hex("vendor-defined"),
            &hex("COM\u{200f}PILED"),
            "-",
            "-",
            "-",
            "-",
        ]);
        assert_eq!(
            parse_error(plan, unsafe_metadata.into_bytes()),
            DatabaseConfigRuntimeParseError::DecodedControlCharacter { row: 0, column: 4 }
        );

        let postgres = postgresql_plan();
        let unsafe_postgres_name =
            postgres_row("myext.\u{200f}parameter", "safe", "user", false, None);
        assert_eq!(
            parse_error(postgres, unsafe_postgres_name.into_bytes()),
            DatabaseConfigRuntimeParseError::DecodedControlCharacter { row: 0, column: 0 }
        );
        for invalid_name in ["$bad", "1bad", ".bad", "a..b", "bad."] {
            let invalid_postgres_name = postgres_row(invalid_name, "safe", "user", false, None);
            assert_eq!(
                parse_error(postgres, invalid_postgres_name.into_bytes()),
                DatabaseConfigRuntimeParseError::InvalidName { row: 0 }
            );
        }
        let nested = "[".repeat(MAX_DATABASE_CONFIG_RUNTIME_DEPTH + 1)
            + &"]".repeat(MAX_DATABASE_CONFIG_RUNTIME_DEPTH + 1);
        let nested_row = postgres_row("enum_setting", "x", "user", false, Some(&nested));
        assert_eq!(
            parse_error(postgres, nested_row.into_bytes()),
            DatabaseConfigRuntimeParseError::MetadataDepthExceeded { row: 0 }
        );
    }

    #[test]
    fn valid_rows_reach_the_exact_row_and_cell_limit_and_accept_crlf() {
        let plan = mysql_plan();
        let row = mysql_row("a", Some(""));
        let at_limit = std::iter::repeat_n(row.as_str(), MAX_DATABASE_CONFIG_RUNTIME_ROWS)
            .collect::<Vec<_>>()
            .join("\n");
        let document = parse(plan, at_limit.into_bytes()).unwrap();
        assert_eq!(document.rows().len(), MAX_DATABASE_CONFIG_RUNTIME_ROWS);

        let over_limit = std::iter::repeat_n(row.as_str(), MAX_DATABASE_CONFIG_RUNTIME_ROWS + 1)
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            parse_error(plan, over_limit.into_bytes()),
            DatabaseConfigRuntimeParseError::TooManyRows
        );

        let crlf = format!(
            "{}\r\n{}\r\n",
            mysql_row("a", Some("1")),
            mysql_row("b", Some("2"))
        );
        let document = parse(plan, crlf.into_bytes()).unwrap();
        assert_eq!(document.rows().len(), 2);
    }

    #[test]
    fn public_values_and_cells_are_independently_bounded() {
        let plan = mysql_plan();
        let oversized_value = "v".repeat(MAX_DATABASE_CONFIG_RUNTIME_VALUE_BYTES + 1);
        let input = mysql_row("safe_name", Some(&oversized_value));
        assert_eq!(
            parse_error(plan, input.into_bytes()),
            DatabaseConfigRuntimeParseError::CellTooLarge { row: 0, column: 1 }
        );

        let invalid_name = mysql_row("name;drop", Some("value"));
        assert_eq!(
            parse_error(plan, invalid_name.into_bytes()),
            DatabaseConfigRuntimeParseError::InvalidName { row: 0 }
        );
    }
}
