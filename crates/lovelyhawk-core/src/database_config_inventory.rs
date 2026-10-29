//! Closed, read-only MySQL and MariaDB plugin/component inventory plans.
//!
//! Each immutable `SELECT` emits a leading native identity row, inventory rows,
//! and a completion row from one database connection. The parser binds the
//! exact reviewed identity to the typed document before either can escape. This
//! module does not own a transport, execute SQL, reconcile startup sources, or
//! authorize any mutation.
//! The final sentinel detects ordinary truncation at a row boundary; it is not
//! an authenticated transport envelope and a malicious server can forge it.

use std::{fmt, str};

use zeroize::Zeroizing;

use crate::database_config::{
    DatabaseConfigComponent, DatabaseConfigDialect, DatabaseConfigProduct, DatabaseConfigSurface,
    artifact_by_key,
};
use crate::database_config_runtime::{
    DatabaseConfigRuntimeIdentity, DatabaseConfigRuntimeIdentityParseError,
    database_config_runtime_identity_plan,
};
use crate::database_config_schema::{DatabaseConfigVersion, DatabaseConfigVersionSelector};

const PLUGIN_TSV_COLUMNS: usize = 7;
const COMPONENT_TSV_COLUMNS: usize = 3;
const COMMUNITY_EDITION_KEY: &str = "community";
const IDENTITY_BOUNDARY_CELL: &[u8] = b"6964656E746974795F7631";
const PLUGIN_COMPLETION_SENTINEL_ROW: &[u8] = b"636F6D706C6574655F7631\t-\t-\t-\t-\t-\t-";
const COMPONENT_COMPLETION_SENTINEL_ROW: &[u8] = b"-\t-\t636F6D706C6574655F7631";

pub const MAX_DATABASE_CONFIG_INVENTORY_TSV_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_DATABASE_CONFIG_INVENTORY_ROWS: usize = 16_384;
pub const MAX_DATABASE_CONFIG_INVENTORY_CELLS: usize =
    MAX_DATABASE_CONFIG_INVENTORY_ROWS * PLUGIN_TSV_COLUMNS;
pub const MAX_DATABASE_CONFIG_INVENTORY_SOURCE_BYTES: usize = 16;
pub const MAX_DATABASE_CONFIG_INVENTORY_NAME_BYTES: usize = 512;
pub const MAX_DATABASE_CONFIG_INVENTORY_TYPE_BYTES: usize = 512;
pub const MAX_DATABASE_CONFIG_INVENTORY_ENUM_BYTES: usize = 64;
pub const MAX_DATABASE_CONFIG_INVENTORY_LIBRARY_BYTES: usize = 8 * 1024;
pub const MAX_DATABASE_CONFIG_INVENTORY_URN_BYTES: usize = 8 * 1024;
pub const MAX_DATABASE_CONFIG_INVENTORY_DECIMAL_BYTES: usize = 20;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DatabaseConfigInventorySurface {
    PluginRegistry,
    ComponentRegistry,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum DatabaseConfigInventoryProvider {
    MySqlPluginTables,
    MySqlComponentTable,
    MariaDbPluginTables,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DatabaseConfigInventoryWireFormat {
    /// Headerless TSV whose non-null cells are UTF-8 encoded as hexadecimal.
    /// A single `-` is the only null sentinel.
    CompositeHeaderlessHexTsvV2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DatabaseConfigInventoryReference {
    pub id: &'static str,
    pub title: &'static str,
    pub url: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DatabaseConfigInventoryBinding {
    pub product: DatabaseConfigProduct,
    pub versions: &'static [DatabaseConfigVersionSelector],
    pub edition_key: &'static str,
    pub component: DatabaseConfigComponent,
    pub artifact_key: &'static str,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct DatabaseConfigInventoryQueryPlan {
    id: &'static str,
    identity_plan_id: &'static str,
    provider: DatabaseConfigInventoryProvider,
    binding: DatabaseConfigInventoryBinding,
    wire_format: DatabaseConfigInventoryWireFormat,
    expected_columns: usize,
    references: &'static [DatabaseConfigInventoryReference],
    query: &'static str,
}

impl DatabaseConfigInventoryQueryPlan {
    pub(crate) const fn id(&self) -> &'static str {
        self.id
    }

    pub(crate) const fn binding(&self) -> DatabaseConfigInventoryBinding {
        self.binding
    }

    pub(crate) const fn identity_plan_id(&self) -> &'static str {
        self.identity_plan_id
    }

    /// Returns the reviewed statement verbatim. There is intentionally no SQL
    /// parameter, fragment, table-name, or caller-selected provider boundary.
    pub(crate) const fn query(&self) -> &'static str {
        self.query
    }

    /// Consumes the complete wire buffer so it is zeroized on every exit path.
    pub(crate) fn parse_tsv(
        &'static self,
        bytes: Zeroizing<Vec<u8>>,
    ) -> Result<DatabaseConfigInventoryRead, DatabaseConfigInventoryParseError> {
        parse_inventory_tsv(self, &bytes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DatabaseConfigInventoryRead {
    identity: DatabaseConfigRuntimeIdentity,
    document: DatabaseConfigInventoryDocument,
}

impl DatabaseConfigInventoryRead {
    pub(crate) fn into_parts(
        self,
    ) -> (
        DatabaseConfigRuntimeIdentity,
        DatabaseConfigInventoryDocument,
    ) {
        (self.identity, self.document)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum DatabaseConfigInventoryLookupError {
    #[error("the verified database product has no reviewed inventory plan")]
    UnsupportedProduct,
    #[error("the requested inventory surface is unavailable for this database product")]
    UnsupportedSurface,
    #[error("the inventory artifact is missing from the core catalog")]
    ArtifactUnknown,
    #[error("the inventory artifact no longer matches its exact product or component")]
    ArtifactBindingMismatch,
    #[error("the inventory artifact is not a RuntimeSql artifact")]
    UnsupportedArtifact,
    #[error("the inventory plan has no complete reviewed official reference metadata")]
    InvalidPlanMetadata,
}

/// Selects one closed composite identity+inventory query from caller-owned enums.
/// The returned parser independently verifies exact product, edition, and version.
pub(crate) fn database_config_inventory_query_plan(
    product: DatabaseConfigProduct,
    surface: DatabaseConfigInventorySurface,
) -> Result<&'static DatabaseConfigInventoryQueryPlan, DatabaseConfigInventoryLookupError> {
    let (component, artifact_key) = match (product, surface) {
        (DatabaseConfigProduct::MySql, DatabaseConfigInventorySurface::PluginRegistry) => (
            DatabaseConfigComponent::PluginRegistry,
            "mysql-plugin-registry",
        ),
        (DatabaseConfigProduct::MySql, DatabaseConfigInventorySurface::ComponentRegistry) => (
            DatabaseConfigComponent::ComponentRegistry,
            "mysql-component-registry",
        ),
        (DatabaseConfigProduct::MariaDb, DatabaseConfigInventorySurface::PluginRegistry) => (
            DatabaseConfigComponent::PluginRegistry,
            "mariadb-plugin-registry",
        ),
        (DatabaseConfigProduct::MariaDb, DatabaseConfigInventorySurface::ComponentRegistry) => {
            return Err(DatabaseConfigInventoryLookupError::UnsupportedSurface);
        }
        _ => return Err(DatabaseConfigInventoryLookupError::UnsupportedProduct),
    };

    let artifact =
        artifact_by_key(artifact_key).ok_or(DatabaseConfigInventoryLookupError::ArtifactUnknown)?;
    if artifact.product != product || artifact.component != component {
        return Err(DatabaseConfigInventoryLookupError::ArtifactBindingMismatch);
    }
    if artifact.surface != DatabaseConfigSurface::RuntimeSql
        || artifact.dialect != DatabaseConfigDialect::RuntimeSql
    {
        return Err(DatabaseConfigInventoryLookupError::UnsupportedArtifact);
    }

    for plan in DATABASE_CONFIG_INVENTORY_QUERY_PLANS {
        if plan.binding.product != product
            || plan.binding.component != component
            || plan.binding.artifact_key != artifact_key
        {
            continue;
        }
        if plan.references.is_empty()
            || plan.references.iter().any(|reference| {
                reference.id.is_empty()
                    || reference.title.is_empty()
                    || !reference.url.starts_with("https://")
            })
        {
            return Err(DatabaseConfigInventoryLookupError::InvalidPlanMetadata);
        }
        return Ok(plan);
    }
    Err(DatabaseConfigInventoryLookupError::ArtifactBindingMismatch)
}

#[derive(Clone, Eq, PartialEq)]
pub struct DatabaseConfigInventoryText {
    public_value: Option<String>,
}

impl fmt::Debug for DatabaseConfigInventoryText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatabaseConfigInventoryText")
            .field("is_redacted", &self.public_value.is_none())
            .field(
                "public_value_bytes",
                &self.public_value.as_ref().map(String::len),
            )
            .finish()
    }
}

impl DatabaseConfigInventoryText {
    /// The only outward text channel. `None` means the transient raw value was
    /// discarded because it did not satisfy the field's public grammar.
    pub fn public_value(&self) -> Option<&str> {
        self.public_value.as_deref()
    }

    pub const fn is_redacted(&self) -> bool {
        self.public_value.is_none()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseConfigPluginStatus {
    Active,
    Inactive,
    Disabled,
    Deleting,
    Deleted,
    Unrecognized,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseConfigPluginLoadOption {
    Off,
    On,
    Force,
    ForcePlusPermanent,
    Unrecognized,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseConfigPluginMaturity {
    VendorUnknown,
    Experimental,
    Alpha,
    Beta,
    Gamma,
    Stable,
    Unrecognized,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DatabaseConfigLoadedPlugin {
    name: DatabaseConfigInventoryText,
    status: DatabaseConfigPluginStatus,
    plugin_type: DatabaseConfigInventoryText,
    library: Option<DatabaseConfigInventoryText>,
    load_option: DatabaseConfigPluginLoadOption,
    maturity: Option<DatabaseConfigPluginMaturity>,
}

impl DatabaseConfigLoadedPlugin {
    pub fn name(&self) -> &DatabaseConfigInventoryText {
        &self.name
    }

    pub const fn status(&self) -> DatabaseConfigPluginStatus {
        self.status
    }

    pub fn plugin_type(&self) -> &DatabaseConfigInventoryText {
        &self.plugin_type
    }

    pub fn library(&self) -> Option<&DatabaseConfigInventoryText> {
        self.library.as_ref()
    }

    pub const fn load_option(&self) -> DatabaseConfigPluginLoadOption {
        self.load_option
    }

    pub const fn maturity(&self) -> Option<DatabaseConfigPluginMaturity> {
        self.maturity
    }

    /// A null `PLUGIN_LIBRARY` proves only that the loaded row is built in. It
    /// does not prove a persisted or command-line startup source.
    pub const fn is_built_in(&self) -> bool {
        self.library.is_none()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DatabaseConfigRegisteredPlugin {
    name: DatabaseConfigInventoryText,
    library: DatabaseConfigInventoryText,
}

impl DatabaseConfigRegisteredPlugin {
    pub fn name(&self) -> &DatabaseConfigInventoryText {
        &self.name
    }

    pub fn library(&self) -> &DatabaseConfigInventoryText {
        &self.library
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DatabaseConfigPluginInventoryRow {
    Loaded(DatabaseConfigLoadedPlugin),
    Registered(DatabaseConfigRegisteredPlugin),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DatabaseConfigComponentRegistration {
    component_id: u64,
    component_group_id: u64,
    urn: DatabaseConfigInventoryText,
}

impl DatabaseConfigComponentRegistration {
    pub fn urn(&self) -> &DatabaseConfigInventoryText {
        &self.urn
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DatabaseConfigPluginInventory {
    rows: Vec<DatabaseConfigPluginInventoryRow>,
}

impl fmt::Debug for DatabaseConfigPluginInventory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatabaseConfigPluginInventory")
            .field("row_count", &self.rows.len())
            .finish_non_exhaustive()
    }
}

impl DatabaseConfigPluginInventory {
    pub fn rows(&self) -> &[DatabaseConfigPluginInventoryRow] {
        &self.rows
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DatabaseConfigComponentInventory {
    rows: Vec<DatabaseConfigComponentRegistration>,
}

impl fmt::Debug for DatabaseConfigComponentInventory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatabaseConfigComponentInventory")
            .field("row_count", &self.rows.len())
            .finish_non_exhaustive()
    }
}

impl DatabaseConfigComponentInventory {
    pub fn rows(&self) -> &[DatabaseConfigComponentRegistration] {
        &self.rows
    }
}

/// Unbound parsed payload. It is not evidence for an exact target by itself;
/// consumers must retain the `DatabaseConfigInventorySnapshot` returned by the
/// database service and validate that snapshot's `TargetGuard` before display.
#[derive(Clone, Eq, PartialEq)]
pub enum DatabaseConfigInventoryDocument {
    Plugins(DatabaseConfigPluginInventory),
    Components(DatabaseConfigComponentInventory),
}

impl fmt::Debug for DatabaseConfigInventoryDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plugins(inventory) => inventory.fmt(formatter),
            Self::Components(inventory) => inventory.fmt(formatter),
        }
    }
}

impl DatabaseConfigInventoryDocument {
    pub fn len(&self) -> usize {
        match self {
            Self::Plugins(inventory) => inventory.rows.len(),
            Self::Components(inventory) => inventory.rows.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn plugins(&self) -> Option<&DatabaseConfigPluginInventory> {
        match self {
            Self::Plugins(inventory) => Some(inventory),
            Self::Components(_) => None,
        }
    }

    pub fn components(&self) -> Option<&DatabaseConfigComponentInventory> {
        match self {
            Self::Components(inventory) => Some(inventory),
            Self::Plugins(_) => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum DatabaseConfigInventoryParseError {
    #[error("inventory TSV exceeds the byte limit")]
    InputTooLarge,
    #[error("inventory TSV exceeds the row limit")]
    TooManyRows,
    #[error("inventory TSV exceeds the cell limit")]
    TooManyCells,
    #[error("inventory TSV is incomplete because it has no final line feed")]
    MissingFinalLineFeed,
    #[error("inventory TSV is incomplete because it has no completion sentinel")]
    MissingCompletionSentinel,
    #[error("inventory completion sentinel at row {row} is not the final row")]
    CompletionSentinelNotLast { row: usize },
    #[error("inventory completion sentinel is duplicated at row {row}")]
    DuplicateCompletionSentinel { row: usize },
    #[error("inventory TSV has no leading identity boundary")]
    MissingIdentityBoundary,
    #[error("inventory identity boundary first appears at row {row}")]
    IdentityBoundaryNotFirst { row: usize },
    #[error("inventory identity boundary is duplicated at row {row}")]
    DuplicateIdentityBoundary { row: usize },
    #[error("inventory identity row violates the product-specific column contract")]
    InvalidIdentityRowShape,
    #[error("inventory runtime identity is invalid: {0}")]
    InvalidIdentity(DatabaseConfigRuntimeIdentityParseError),
    #[error("inventory runtime identity does not match the selected plan")]
    IdentityPlanMismatch,
    #[error("inventory TSV contains an invalid wire byte at offset {offset}")]
    InvalidWireByte { offset: usize },
    #[error("inventory TSV contains a forbidden control byte at offset {offset}")]
    ControlCharacter { offset: usize },
    #[error("inventory row {row} has {actual} columns; expected {expected}")]
    InvalidColumnCount {
        row: usize,
        expected: usize,
        actual: usize,
    },
    #[error("inventory row {row}, column {column} is null")]
    RequiredCellMissing { row: usize, column: usize },
    #[error("inventory row {row}, column {column} is empty")]
    RequiredCellEmpty { row: usize, column: usize },
    #[error("inventory row {row}, column {column} exceeds its field limit")]
    CellTooLarge { row: usize, column: usize },
    #[error("inventory row {row}, column {column} is not hexadecimal")]
    InvalidHex { row: usize, column: usize },
    #[error("inventory row {row}, column {column} is not UTF-8")]
    InvalidUtf8 { row: usize, column: usize },
    #[error("inventory row {row}, column {column} contains a decoded control character")]
    DecodedControlCharacter { row: usize, column: usize },
    #[error("inventory row {row} has an unknown row kind")]
    InvalidPluginRowKind { row: usize },
    #[error("inventory row {row} violates the loaded/registered column contract")]
    InvalidPluginRowShape { row: usize },
    #[error("inventory row {row}, column {column} is not canonical decimal u64")]
    InvalidDecimal { row: usize, column: usize },
}

const MYSQL_PLUGIN_QUERY: &str = r#"SELECT
  HEX(CONVERT(inventory_source USING utf8mb4)),
  CASE WHEN plugin_name IS NULL THEN '-' ELSE HEX(CONVERT(plugin_name USING utf8mb4)) END,
  CASE WHEN plugin_status IS NULL THEN '-' ELSE HEX(CONVERT(plugin_status USING utf8mb4)) END,
  CASE WHEN plugin_type IS NULL THEN '-' ELSE HEX(CONVERT(plugin_type USING utf8mb4)) END,
  CASE WHEN plugin_library IS NULL THEN '-' ELSE HEX(CONVERT(plugin_library USING utf8mb4)) END,
  CASE WHEN load_option IS NULL THEN '-' ELSE HEX(CONVERT(load_option USING utf8mb4)) END,
  '-'
FROM (
  SELECT
    -1 AS source_rank,
    'identity_v1' AS inventory_source,
    @@version AS plugin_name,
    @@version_comment AS plugin_status,
    NULL AS plugin_type,
    NULL AS plugin_library,
    NULL AS load_option
  UNION ALL
  SELECT
    0,
    'loaded' AS inventory_source,
    PLUGIN_NAME AS plugin_name,
    PLUGIN_STATUS AS plugin_status,
    PLUGIN_TYPE AS plugin_type,
    PLUGIN_LIBRARY AS plugin_library,
    LOAD_OPTION AS load_option
  FROM information_schema.PLUGINS
  UNION ALL
  SELECT
    1,
    'registered',
    name,
    NULL,
    NULL,
    dl,
    NULL
  FROM mysql.plugin
  UNION ALL
  SELECT
    2,
    'complete_v1',
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
) AS inventory
ORDER BY
  source_rank,
  BINARY plugin_name,
  BINARY plugin_library,
  BINARY plugin_status,
  BINARY plugin_type,
  BINARY load_option"#;

const MARIADB_PLUGIN_QUERY: &str = r#"SELECT
  HEX(CONVERT(inventory_source USING utf8mb4)),
  CASE WHEN plugin_name IS NULL THEN '-' ELSE HEX(CONVERT(plugin_name USING utf8mb4)) END,
  CASE WHEN plugin_status IS NULL THEN '-' ELSE HEX(CONVERT(plugin_status USING utf8mb4)) END,
  CASE WHEN plugin_type IS NULL THEN '-' ELSE HEX(CONVERT(plugin_type USING utf8mb4)) END,
  CASE WHEN plugin_library IS NULL THEN '-' ELSE HEX(CONVERT(plugin_library USING utf8mb4)) END,
  CASE WHEN load_option IS NULL THEN '-' ELSE HEX(CONVERT(load_option USING utf8mb4)) END,
  CASE WHEN maturity IS NULL THEN '-' ELSE HEX(CONVERT(maturity USING utf8mb4)) END
FROM (
  SELECT
    -1 AS source_rank,
    'identity_v1' AS inventory_source,
    @@version AS plugin_name,
    NULL AS plugin_status,
    NULL AS plugin_type,
    NULL AS plugin_library,
    NULL AS load_option,
    NULL AS maturity
  UNION ALL
  SELECT
    0,
    'loaded' AS inventory_source,
    PLUGIN_NAME AS plugin_name,
    PLUGIN_STATUS AS plugin_status,
    PLUGIN_TYPE AS plugin_type,
    PLUGIN_LIBRARY AS plugin_library,
    LOAD_OPTION AS load_option,
    PLUGIN_MATURITY AS maturity
  FROM information_schema.PLUGINS
  UNION ALL
  SELECT
    1,
    'registered',
    name,
    NULL,
    NULL,
    dl,
    NULL,
    NULL
  FROM mysql.plugin
  UNION ALL
  SELECT
    2,
    'complete_v1',
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
) AS inventory
ORDER BY
  source_rank,
  BINARY plugin_name,
  BINARY plugin_library,
  BINARY plugin_status,
  BINARY plugin_type,
  BINARY load_option,
  BINARY maturity"#;

const MYSQL_COMPONENT_QUERY: &str = r#"SELECT
  CASE WHEN component_id IS NULL THEN '-' ELSE HEX(CONVERT(component_id USING utf8mb4)) END,
  CASE WHEN component_group_id IS NULL THEN '-' ELSE HEX(CONVERT(component_group_id USING utf8mb4)) END,
  CASE WHEN component_urn IS NULL THEN '-' ELSE HEX(CONVERT(component_urn USING utf8mb4)) END
FROM (
  SELECT
    -1 AS source_rank,
    'identity_v1' AS component_id,
    @@version AS component_group_id,
    @@version_comment AS component_urn
  UNION ALL
  SELECT
    0,
    CAST(component_id AS CHAR CHARACTER SET utf8mb4),
    CAST(component_group_id AS CHAR CHARACTER SET utf8mb4),
    component_urn
  FROM mysql.component
  UNION ALL
  SELECT
    1,
    NULL,
    NULL,
    'complete_v1'
) AS inventory
ORDER BY source_rank, BINARY component_id, BINARY component_group_id, BINARY component_urn"#;

const MYSQL_PLUGIN_REFERENCES: &[DatabaseConfigInventoryReference] = &[
    DatabaseConfigInventoryReference {
        id: "mysql-8.4-information-schema-plugins",
        title: "MySQL 8.4 Reference Manual: Information Schema PLUGINS Table",
        url: "https://dev.mysql.com/doc/refman/8.4/en/information-schema-plugins-table.html",
    },
    DatabaseConfigInventoryReference {
        id: "mysql-8.4-obtaining-plugin-information",
        title: "MySQL 8.4 Reference Manual: Obtaining Server Plugin Information",
        url: "https://dev.mysql.com/doc/refman/8.4/en/obtaining-plugin-information.html",
    },
];

const MYSQL_COMPONENT_REFERENCES: &[DatabaseConfigInventoryReference] =
    &[DatabaseConfigInventoryReference {
        id: "mysql-8.4-obtaining-component-information",
        title: "MySQL 8.4 Reference Manual: Obtaining Component Information",
        url: "https://dev.mysql.com/doc/refman/8.4/en/obtaining-component-information.html",
    }];

const MARIADB_PLUGIN_REFERENCES: &[DatabaseConfigInventoryReference] = &[
    DatabaseConfigInventoryReference {
        id: "mariadb-information-schema-plugins",
        title: "MariaDB Documentation: Information Schema PLUGINS Table",
        url: "https://mariadb.com/docs/server/reference/system-tables/information-schema/information-schema-tables/plugins-table-information-schema",
    },
    DatabaseConfigInventoryReference {
        id: "mariadb-mysql-plugin",
        title: "MariaDB Documentation: mysql.plugin Table",
        url: "https://mariadb.com/docs/server/reference/system-tables/the-mysql-database-tables/mysql-plugin-table",
    },
];

const MYSQL_80_VERSIONS: DatabaseConfigVersionSelector = DatabaseConfigVersionSelector::HalfOpen {
    minimum_inclusive: DatabaseConfigVersion::new(8, 0, 11),
    maximum_exclusive: DatabaseConfigVersion::new(8, 1, 0),
};
const MYSQL_84_VERSIONS: DatabaseConfigVersionSelector = DatabaseConfigVersionSelector::HalfOpen {
    minimum_inclusive: DatabaseConfigVersion::new(8, 4, 0),
    maximum_exclusive: DatabaseConfigVersion::new(8, 5, 0),
};
const MARIADB_1011_VERSIONS: DatabaseConfigVersionSelector =
    DatabaseConfigVersionSelector::HalfOpen {
        minimum_inclusive: DatabaseConfigVersion::new(10, 11, 0),
        maximum_exclusive: DatabaseConfigVersion::new(10, 12, 0),
    };
const MARIADB_114_VERSIONS: DatabaseConfigVersionSelector =
    DatabaseConfigVersionSelector::HalfOpen {
        minimum_inclusive: DatabaseConfigVersion::new(11, 4, 0),
        maximum_exclusive: DatabaseConfigVersion::new(11, 5, 0),
    };
const MYSQL_INVENTORY_VERSIONS: &[DatabaseConfigVersionSelector] =
    &[MYSQL_80_VERSIONS, MYSQL_84_VERSIONS];
const MARIADB_INVENTORY_VERSIONS: &[DatabaseConfigVersionSelector] =
    &[MARIADB_1011_VERSIONS, MARIADB_114_VERSIONS];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InventoryPlanSpec {
    id: &'static str,
    identity_plan_id: &'static str,
    provider: DatabaseConfigInventoryProvider,
    product: DatabaseConfigProduct,
    versions: &'static [DatabaseConfigVersionSelector],
    component: DatabaseConfigComponent,
    artifact_key: &'static str,
    expected_columns: usize,
    references: &'static [DatabaseConfigInventoryReference],
    query: &'static str,
}

const fn inventory_plan(spec: InventoryPlanSpec) -> DatabaseConfigInventoryQueryPlan {
    DatabaseConfigInventoryQueryPlan {
        id: spec.id,
        identity_plan_id: spec.identity_plan_id,
        provider: spec.provider,
        binding: DatabaseConfigInventoryBinding {
            product: spec.product,
            versions: spec.versions,
            edition_key: COMMUNITY_EDITION_KEY,
            component: spec.component,
            artifact_key: spec.artifact_key,
        },
        wire_format: DatabaseConfigInventoryWireFormat::CompositeHeaderlessHexTsvV2,
        expected_columns: spec.expected_columns,
        references: spec.references,
        query: spec.query,
    }
}

const DATABASE_CONFIG_INVENTORY_QUERY_PLANS: &[DatabaseConfigInventoryQueryPlan] = &[
    inventory_plan(InventoryPlanSpec {
        id: "mysql-plugin-inventory-composite-read-only-v2",
        identity_plan_id: "mysql-native-community-identity-v1",
        provider: DatabaseConfigInventoryProvider::MySqlPluginTables,
        product: DatabaseConfigProduct::MySql,
        versions: MYSQL_INVENTORY_VERSIONS,
        component: DatabaseConfigComponent::PluginRegistry,
        artifact_key: "mysql-plugin-registry",
        expected_columns: PLUGIN_TSV_COLUMNS,
        references: MYSQL_PLUGIN_REFERENCES,
        query: MYSQL_PLUGIN_QUERY,
    }),
    inventory_plan(InventoryPlanSpec {
        id: "mysql-component-inventory-composite-read-only-v2",
        identity_plan_id: "mysql-native-community-identity-v1",
        provider: DatabaseConfigInventoryProvider::MySqlComponentTable,
        product: DatabaseConfigProduct::MySql,
        versions: MYSQL_INVENTORY_VERSIONS,
        component: DatabaseConfigComponent::ComponentRegistry,
        artifact_key: "mysql-component-registry",
        expected_columns: COMPONENT_TSV_COLUMNS,
        references: MYSQL_COMPONENT_REFERENCES,
        query: MYSQL_COMPONENT_QUERY,
    }),
    inventory_plan(InventoryPlanSpec {
        id: "mariadb-plugin-inventory-composite-read-only-v2",
        identity_plan_id: "mariadb-native-community-identity-v1",
        provider: DatabaseConfigInventoryProvider::MariaDbPluginTables,
        product: DatabaseConfigProduct::MariaDb,
        versions: MARIADB_INVENTORY_VERSIONS,
        component: DatabaseConfigComponent::PluginRegistry,
        artifact_key: "mariadb-plugin-registry",
        expected_columns: PLUGIN_TSV_COLUMNS,
        references: MARIADB_PLUGIN_REFERENCES,
        query: MARIADB_PLUGIN_QUERY,
    }),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublicTextRule {
    PluginName,
    PluginType,
    PluginLibrary,
    ComponentUrn,
}

fn parse_inventory_tsv(
    plan: &'static DatabaseConfigInventoryQueryPlan,
    bytes: &[u8],
) -> Result<DatabaseConfigInventoryRead, DatabaseConfigInventoryParseError> {
    validate_wire_shape(bytes)?;
    let raw_rows = completed_wire_rows(plan.provider, bytes)?;
    let Some((identity_row, inventory_rows)) = raw_rows.split_first() else {
        return Err(DatabaseConfigInventoryParseError::MissingIdentityBoundary);
    };
    if !is_identity_boundary_row(identity_row) {
        if let Some(row) = raw_rows
            .iter()
            .position(|row| is_identity_boundary_row(row))
        {
            return Err(DatabaseConfigInventoryParseError::IdentityBoundaryNotFirst { row });
        }
        return Err(DatabaseConfigInventoryParseError::MissingIdentityBoundary);
    }
    if let Some(row) = inventory_rows
        .iter()
        .position(|row| is_identity_boundary_row(row))
    {
        return Err(DatabaseConfigInventoryParseError::DuplicateIdentityBoundary { row: row + 1 });
    }

    let identity = parse_inventory_identity(plan, identity_row)?;
    let document = parse_inventory_rows(plan, inventory_rows)?;
    Ok(DatabaseConfigInventoryRead { identity, document })
}

fn is_identity_boundary_row(row: &[u8]) -> bool {
    row.split(|byte| *byte == b'\t')
        .next()
        .is_some_and(|cell| cell.eq_ignore_ascii_case(IDENTITY_BOUNDARY_CELL))
}

fn parse_inventory_identity(
    plan: &'static DatabaseConfigInventoryQueryPlan,
    raw_row: &[u8],
) -> Result<DatabaseConfigRuntimeIdentity, DatabaseConfigInventoryParseError> {
    let cells = raw_row.split(|byte| *byte == b'\t').collect::<Vec<_>>();
    if cells.len() != plan.expected_columns {
        return Err(DatabaseConfigInventoryParseError::InvalidColumnCount {
            row: 0,
            expected: plan.expected_columns,
            actual: cells.len(),
        });
    }
    let identity_columns: &[usize] = match plan.provider {
        DatabaseConfigInventoryProvider::MySqlPluginTables => {
            if cells[1..=2].iter().any(|cell| is_null_cell(cell))
                || cells[3..].iter().any(|cell| !is_null_cell(cell))
            {
                return Err(DatabaseConfigInventoryParseError::InvalidIdentityRowShape);
            }
            &[1, 2]
        }
        DatabaseConfigInventoryProvider::MariaDbPluginTables => {
            if is_null_cell(cells[1]) || cells[2..].iter().any(|cell| !is_null_cell(cell)) {
                return Err(DatabaseConfigInventoryParseError::InvalidIdentityRowShape);
            }
            &[1]
        }
        DatabaseConfigInventoryProvider::MySqlComponentTable => {
            if cells[1..].iter().any(|cell| is_null_cell(cell)) {
                return Err(DatabaseConfigInventoryParseError::InvalidIdentityRowShape);
            }
            &[1, 2]
        }
    };

    let mut identity_wire = Zeroizing::new(Vec::new());
    for (position, column) in identity_columns.iter().copied().enumerate() {
        if position > 0 {
            identity_wire.push(b'\t');
        }
        identity_wire.extend_from_slice(cells[column]);
    }
    let identity_plan = database_config_runtime_identity_plan(plan.binding.product)
        .map_err(|_| DatabaseConfigInventoryParseError::IdentityPlanMismatch)?;
    if identity_plan.id() != plan.identity_plan_id {
        return Err(DatabaseConfigInventoryParseError::IdentityPlanMismatch);
    }
    let identity = identity_plan
        .parse_tsv(identity_wire)
        .map_err(DatabaseConfigInventoryParseError::InvalidIdentity)?;
    if identity.product() != plan.binding.product
        || identity.edition().key() != plan.binding.edition_key
        || !plan
            .binding
            .versions
            .iter()
            .any(|versions| versions.contains(identity.version()))
    {
        return Err(DatabaseConfigInventoryParseError::IdentityPlanMismatch);
    }
    Ok(identity)
}

fn parse_inventory_rows(
    plan: &'static DatabaseConfigInventoryQueryPlan,
    raw_rows: &[&[u8]],
) -> Result<DatabaseConfigInventoryDocument, DatabaseConfigInventoryParseError> {
    match plan.provider {
        DatabaseConfigInventoryProvider::MySqlPluginTables
        | DatabaseConfigInventoryProvider::MariaDbPluginTables => {
            let mut rows = Vec::new();
            for_each_wire_row(raw_rows, plan.expected_columns, 0, |row, cells| {
                rows.push(parse_plugin_row(plan.provider, row, cells)?);
                Ok(())
            })?;
            Ok(DatabaseConfigInventoryDocument::Plugins(
                DatabaseConfigPluginInventory { rows },
            ))
        }
        DatabaseConfigInventoryProvider::MySqlComponentTable => {
            let mut rows = Vec::new();
            for_each_wire_row(raw_rows, plan.expected_columns, 0, |row, cells| {
                rows.push(parse_component_row(row, cells)?);
                Ok(())
            })?;
            Ok(DatabaseConfigInventoryDocument::Components(
                DatabaseConfigComponentInventory { rows },
            ))
        }
    }
}

fn completed_wire_rows(
    provider: DatabaseConfigInventoryProvider,
    bytes: &[u8],
) -> Result<Vec<&[u8]>, DatabaseConfigInventoryParseError> {
    let Some(without_lf) = bytes.strip_suffix(b"\n") else {
        return Err(DatabaseConfigInventoryParseError::MissingFinalLineFeed);
    };
    let payload = without_lf.strip_suffix(b"\r").unwrap_or(without_lf);
    let rows = payload
        .split(|byte| *byte == b'\n')
        .map(|row| row.strip_suffix(b"\r").unwrap_or(row))
        .collect::<Vec<_>>();
    let sentinel = match provider {
        DatabaseConfigInventoryProvider::MySqlPluginTables
        | DatabaseConfigInventoryProvider::MariaDbPluginTables => PLUGIN_COMPLETION_SENTINEL_ROW,
        DatabaseConfigInventoryProvider::MySqlComponentTable => COMPONENT_COMPLETION_SENTINEL_ROW,
    };

    let last = rows.len() - 1;
    if rows[last] != sentinel {
        if let Some(row) = rows.iter().position(|candidate| *candidate == sentinel) {
            return Err(DatabaseConfigInventoryParseError::CompletionSentinelNotLast { row });
        }
        return Err(DatabaseConfigInventoryParseError::MissingCompletionSentinel);
    }
    if let Some(row) = rows[..last]
        .iter()
        .position(|candidate| *candidate == sentinel)
    {
        return Err(DatabaseConfigInventoryParseError::DuplicateCompletionSentinel { row });
    }
    Ok(rows[..last].to_vec())
}

fn for_each_wire_row(
    raw_rows: &[&[u8]],
    expected_columns: usize,
    row_offset: usize,
    mut visit: impl FnMut(usize, &[&[u8]]) -> Result<(), DatabaseConfigInventoryParseError>,
) -> Result<(), DatabaseConfigInventoryParseError> {
    for (index, raw_row) in raw_rows.iter().copied().enumerate() {
        let row = index + row_offset;
        let cells = raw_row.split(|byte| *byte == b'\t').collect::<Vec<_>>();
        if cells.len() != expected_columns {
            return Err(DatabaseConfigInventoryParseError::InvalidColumnCount {
                row,
                expected: expected_columns,
                actual: cells.len(),
            });
        }
        visit(row, &cells)?;
    }
    Ok(())
}

fn validate_wire_shape(bytes: &[u8]) -> Result<(), DatabaseConfigInventoryParseError> {
    if bytes.len() > MAX_DATABASE_CONFIG_INVENTORY_TSV_BYTES {
        return Err(DatabaseConfigInventoryParseError::InputTooLarge);
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
                return Err(DatabaseConfigInventoryParseError::ControlCharacter { offset });
            }
            _ => return Err(DatabaseConfigInventoryParseError::InvalidWireByte { offset }),
        }
        if rows > MAX_DATABASE_CONFIG_INVENTORY_ROWS {
            return Err(DatabaseConfigInventoryParseError::TooManyRows);
        }
        if cells > MAX_DATABASE_CONFIG_INVENTORY_CELLS {
            return Err(DatabaseConfigInventoryParseError::TooManyCells);
        }
    }
    Ok(())
}

fn parse_plugin_row(
    provider: DatabaseConfigInventoryProvider,
    row: usize,
    cells: &[&[u8]],
) -> Result<DatabaseConfigPluginInventoryRow, DatabaseConfigInventoryParseError> {
    let source = required_text_cell(cells[0], row, 0, MAX_DATABASE_CONFIG_INVENTORY_SOURCE_BYTES)?;
    match source.as_str() {
        "loaded" => {
            parse_loaded_plugin(provider, row, cells).map(DatabaseConfigPluginInventoryRow::Loaded)
        }
        "registered" => {
            parse_registered_plugin(row, cells).map(DatabaseConfigPluginInventoryRow::Registered)
        }
        _ => Err(DatabaseConfigInventoryParseError::InvalidPluginRowKind { row }),
    }
}

fn parse_loaded_plugin(
    provider: DatabaseConfigInventoryProvider,
    row: usize,
    cells: &[&[u8]],
) -> Result<DatabaseConfigLoadedPlugin, DatabaseConfigInventoryParseError> {
    let required = [1usize, 2, 3, 5];
    let mysql_maturity_is_null =
        provider != DatabaseConfigInventoryProvider::MySqlPluginTables || is_null_cell(cells[6]);
    if required.iter().any(|column| is_null_cell(cells[*column])) || !mysql_maturity_is_null {
        return Err(DatabaseConfigInventoryParseError::InvalidPluginRowShape { row });
    }

    let name = public_text_cell(
        cells[1],
        row,
        1,
        MAX_DATABASE_CONFIG_INVENTORY_NAME_BYTES,
        PublicTextRule::PluginName,
    )?;
    let status = parse_plugin_status(required_text_cell(
        cells[2],
        row,
        2,
        MAX_DATABASE_CONFIG_INVENTORY_ENUM_BYTES,
    )?);
    let plugin_type = public_text_cell(
        cells[3],
        row,
        3,
        MAX_DATABASE_CONFIG_INVENTORY_TYPE_BYTES,
        PublicTextRule::PluginType,
    )?;
    let library = optional_public_text_cell(
        cells[4],
        row,
        4,
        MAX_DATABASE_CONFIG_INVENTORY_LIBRARY_BYTES,
        PublicTextRule::PluginLibrary,
    )?;
    let load_option = parse_plugin_load_option(required_text_cell(
        cells[5],
        row,
        5,
        MAX_DATABASE_CONFIG_INVENTORY_ENUM_BYTES,
    )?);
    let maturity = match provider {
        DatabaseConfigInventoryProvider::MariaDbPluginTables => {
            optional_text_cell(cells[6], row, 6, MAX_DATABASE_CONFIG_INVENTORY_ENUM_BYTES)?
                .map(parse_plugin_maturity)
        }
        DatabaseConfigInventoryProvider::MySqlPluginTables => None,
        DatabaseConfigInventoryProvider::MySqlComponentTable => unreachable!(),
    };

    Ok(DatabaseConfigLoadedPlugin {
        name,
        status,
        plugin_type,
        library,
        load_option,
        maturity,
    })
}

fn parse_registered_plugin(
    row: usize,
    cells: &[&[u8]],
) -> Result<DatabaseConfigRegisteredPlugin, DatabaseConfigInventoryParseError> {
    if is_null_cell(cells[1])
        || is_null_cell(cells[4])
        || [2usize, 3, 5, 6]
            .iter()
            .any(|column| !is_null_cell(cells[*column]))
    {
        return Err(DatabaseConfigInventoryParseError::InvalidPluginRowShape { row });
    }

    Ok(DatabaseConfigRegisteredPlugin {
        name: public_text_cell(
            cells[1],
            row,
            1,
            MAX_DATABASE_CONFIG_INVENTORY_NAME_BYTES,
            PublicTextRule::PluginName,
        )?,
        library: public_text_cell(
            cells[4],
            row,
            4,
            MAX_DATABASE_CONFIG_INVENTORY_LIBRARY_BYTES,
            PublicTextRule::PluginLibrary,
        )?,
    })
}

fn parse_component_row(
    row: usize,
    cells: &[&[u8]],
) -> Result<DatabaseConfigComponentRegistration, DatabaseConfigInventoryParseError> {
    Ok(DatabaseConfigComponentRegistration {
        component_id: decimal_u64_cell(cells[0], row, 0)?,
        component_group_id: decimal_u64_cell(cells[1], row, 1)?,
        urn: public_text_cell(
            cells[2],
            row,
            2,
            MAX_DATABASE_CONFIG_INVENTORY_URN_BYTES,
            PublicTextRule::ComponentUrn,
        )?,
    })
}

fn parse_plugin_status(value: Zeroizing<String>) -> DatabaseConfigPluginStatus {
    if value.eq_ignore_ascii_case("ACTIVE") {
        DatabaseConfigPluginStatus::Active
    } else if value.eq_ignore_ascii_case("INACTIVE") {
        DatabaseConfigPluginStatus::Inactive
    } else if value.eq_ignore_ascii_case("DISABLED") {
        DatabaseConfigPluginStatus::Disabled
    } else if value.eq_ignore_ascii_case("DELETING") {
        DatabaseConfigPluginStatus::Deleting
    } else if value.eq_ignore_ascii_case("DELETED") {
        DatabaseConfigPluginStatus::Deleted
    } else {
        DatabaseConfigPluginStatus::Unrecognized
    }
}

fn parse_plugin_load_option(value: Zeroizing<String>) -> DatabaseConfigPluginLoadOption {
    if value.eq_ignore_ascii_case("OFF") {
        DatabaseConfigPluginLoadOption::Off
    } else if value.eq_ignore_ascii_case("ON") {
        DatabaseConfigPluginLoadOption::On
    } else if value.eq_ignore_ascii_case("FORCE") {
        DatabaseConfigPluginLoadOption::Force
    } else if value.eq_ignore_ascii_case("FORCE_PLUS_PERMANENT") {
        DatabaseConfigPluginLoadOption::ForcePlusPermanent
    } else {
        DatabaseConfigPluginLoadOption::Unrecognized
    }
}

fn parse_plugin_maturity(value: Zeroizing<String>) -> DatabaseConfigPluginMaturity {
    if value.eq_ignore_ascii_case("UNKNOWN") {
        DatabaseConfigPluginMaturity::VendorUnknown
    } else if value.eq_ignore_ascii_case("EXPERIMENTAL") {
        DatabaseConfigPluginMaturity::Experimental
    } else if value.eq_ignore_ascii_case("ALPHA") {
        DatabaseConfigPluginMaturity::Alpha
    } else if value.eq_ignore_ascii_case("BETA") {
        DatabaseConfigPluginMaturity::Beta
    } else if value.eq_ignore_ascii_case("GAMMA") {
        DatabaseConfigPluginMaturity::Gamma
    } else if value.eq_ignore_ascii_case("STABLE") {
        DatabaseConfigPluginMaturity::Stable
    } else {
        DatabaseConfigPluginMaturity::Unrecognized
    }
}

fn decimal_u64_cell(
    cell: &[u8],
    row: usize,
    column: usize,
) -> Result<u64, DatabaseConfigInventoryParseError> {
    let value = required_text_cell(
        cell,
        row,
        column,
        MAX_DATABASE_CONFIG_INVENTORY_DECIMAL_BYTES,
    )?;
    let bytes = value.as_bytes();
    if !bytes.iter().all(u8::is_ascii_digit) || (bytes.len() > 1 && bytes.first() == Some(&b'0')) {
        return Err(DatabaseConfigInventoryParseError::InvalidDecimal { row, column });
    }
    value
        .parse::<u64>()
        .map_err(|_| DatabaseConfigInventoryParseError::InvalidDecimal { row, column })
}

fn public_text_cell(
    cell: &[u8],
    row: usize,
    column: usize,
    maximum_bytes: usize,
    rule: PublicTextRule,
) -> Result<DatabaseConfigInventoryText, DatabaseConfigInventoryParseError> {
    let value = required_text_cell(cell, row, column, maximum_bytes)?;
    Ok(public_text(value, rule))
}

fn optional_public_text_cell(
    cell: &[u8],
    row: usize,
    column: usize,
    maximum_bytes: usize,
    rule: PublicTextRule,
) -> Result<Option<DatabaseConfigInventoryText>, DatabaseConfigInventoryParseError> {
    optional_text_cell(cell, row, column, maximum_bytes)
        .map(|value| value.map(|value| public_text(value, rule)))
}

fn public_text(value: Zeroizing<String>, rule: PublicTextRule) -> DatabaseConfigInventoryText {
    let is_public = !has_sensitive_carrier(&value)
        && match rule {
            PublicTextRule::PluginName => valid_public_plugin_name(&value),
            PublicTextRule::PluginType => valid_public_plugin_type(&value),
            PublicTextRule::PluginLibrary => valid_public_library(&value),
            PublicTextRule::ComponentUrn => valid_public_component_urn(&value),
        };
    DatabaseConfigInventoryText {
        public_value: is_public.then(|| value.to_string()),
    }
}

fn required_text_cell(
    cell: &[u8],
    row: usize,
    column: usize,
    maximum_bytes: usize,
) -> Result<Zeroizing<String>, DatabaseConfigInventoryParseError> {
    optional_text_cell(cell, row, column, maximum_bytes)?
        .ok_or(DatabaseConfigInventoryParseError::RequiredCellMissing { row, column })
}

fn optional_text_cell(
    cell: &[u8],
    row: usize,
    column: usize,
    maximum_bytes: usize,
) -> Result<Option<Zeroizing<String>>, DatabaseConfigInventoryParseError> {
    let Some(decoded) = optional_bytes_cell(cell, row, column, maximum_bytes)? else {
        return Ok(None);
    };
    let value = str::from_utf8(&decoded)
        .map_err(|_| DatabaseConfigInventoryParseError::InvalidUtf8 { row, column })?;
    if value.is_empty() {
        return Err(DatabaseConfigInventoryParseError::RequiredCellEmpty { row, column });
    }
    if value.chars().any(char::is_control) {
        return Err(DatabaseConfigInventoryParseError::DecodedControlCharacter { row, column });
    }
    Ok(Some(Zeroizing::new(value.to_owned())))
}

fn optional_bytes_cell(
    cell: &[u8],
    row: usize,
    column: usize,
    maximum_bytes: usize,
) -> Result<Option<Zeroizing<Vec<u8>>>, DatabaseConfigInventoryParseError> {
    if is_null_cell(cell) {
        return Ok(None);
    }
    if cell.len() > maximum_bytes.saturating_mul(2) {
        return Err(DatabaseConfigInventoryParseError::CellTooLarge { row, column });
    }
    if !cell.len().is_multiple_of(2) {
        return Err(DatabaseConfigInventoryParseError::InvalidHex { row, column });
    }
    let mut decoded = Zeroizing::new(Vec::with_capacity(cell.len() / 2));
    for pair in cell.as_chunks::<2>().0 {
        let high = hex_nibble(pair[0])
            .ok_or(DatabaseConfigInventoryParseError::InvalidHex { row, column })?;
        let low = hex_nibble(pair[1])
            .ok_or(DatabaseConfigInventoryParseError::InvalidHex { row, column })?;
        decoded.push((high << 4) | low);
    }
    Ok(Some(decoded))
}

fn is_null_cell(cell: &[u8]) -> bool {
    cell == b"-"
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn has_sensitive_carrier(value: &str) -> bool {
    value.chars().any(is_unsafe_display_character)
        || contains_ascii_case_insensitive(value.as_bytes(), b"-----begin")
        || [
            b"password=".as_slice(),
            b"passwd=".as_slice(),
            b"secret=".as_slice(),
            b"token=".as_slice(),
            b"pwd=".as_slice(),
            b"authorization:".as_slice(),
            b"bearer ".as_slice(),
        ]
        .iter()
        .any(|needle| contains_ascii_case_insensitive(value.as_bytes(), needle))
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.windows(needle.len()).any(|window| {
            window
                .iter()
                .zip(needle)
                .all(|(left, right)| left.eq_ignore_ascii_case(right))
        })
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

fn valid_public_plugin_name(value: &str) -> bool {
    !value.is_empty()
        && !looks_like_path_or_uri(value)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'$' | b'.'))
}

fn valid_public_plugin_type(value: &str) -> bool {
    !value.is_empty()
        && !looks_like_path_or_uri(value)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'_' | b'-'))
}

fn valid_public_library(value: &str) -> bool {
    !value.is_empty()
        && !looks_like_path_or_uri(value)
        && !value.starts_with('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'+'))
}

fn valid_public_component_urn(value: &str) -> bool {
    let Some(component) = value.strip_prefix("file://") else {
        return false;
    };
    !component.is_empty()
        && !looks_like_path_or_uri(component)
        && !component.starts_with('.')
        && component
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'+'))
}

fn looks_like_path_or_uri(value: &str) -> bool {
    value.contains('/')
        || value.contains('\\')
        || value.contains("://")
        || value.contains("..")
        || value.as_bytes().get(1).is_some_and(|byte| *byte == b':')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(value: &str) -> String {
        value
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect()
    }

    fn wire_cell(value: Option<&str>) -> String {
        value.map(hex).unwrap_or_else(|| "-".to_owned())
    }

    fn wire_row(cells: &[Option<&str>]) -> String {
        cells
            .iter()
            .map(|value| wire_cell(*value))
            .collect::<Vec<_>>()
            .join("\t")
    }

    fn plan(
        product: DatabaseConfigProduct,
        surface: DatabaseConfigInventorySurface,
    ) -> &'static DatabaseConfigInventoryQueryPlan {
        database_config_inventory_query_plan(product, surface).unwrap()
    }

    fn mysql_plugin_plan() -> &'static DatabaseConfigInventoryQueryPlan {
        plan(
            DatabaseConfigProduct::MySql,
            DatabaseConfigInventorySurface::PluginRegistry,
        )
    }

    fn mariadb_plugin_plan() -> &'static DatabaseConfigInventoryQueryPlan {
        plan(
            DatabaseConfigProduct::MariaDb,
            DatabaseConfigInventorySurface::PluginRegistry,
        )
    }

    fn mysql_component_plan() -> &'static DatabaseConfigInventoryQueryPlan {
        plan(
            DatabaseConfigProduct::MySql,
            DatabaseConfigInventorySurface::ComponentRegistry,
        )
    }

    fn identity_row(plan: &'static DatabaseConfigInventoryQueryPlan, version: &str) -> String {
        match plan.provider {
            DatabaseConfigInventoryProvider::MySqlPluginTables => wire_row(&[
                Some("identity_v1"),
                Some(version),
                Some("MySQL Community Server - GPL"),
                None,
                None,
                None,
                None,
            ]),
            DatabaseConfigInventoryProvider::MariaDbPluginTables => wire_row(&[
                Some("identity_v1"),
                Some(version),
                None,
                None,
                None,
                None,
                None,
            ]),
            DatabaseConfigInventoryProvider::MySqlComponentTable => wire_row(&[
                Some("identity_v1"),
                Some(version),
                Some("MySQL Community Server - GPL"),
            ]),
        }
    }

    fn default_identity_row(plan: &'static DatabaseConfigInventoryQueryPlan) -> String {
        match plan.binding.product {
            DatabaseConfigProduct::MySql => identity_row(plan, "8.4.3"),
            DatabaseConfigProduct::MariaDb => identity_row(plan, "11.4.3-MariaDB"),
            _ => unreachable!(),
        }
    }

    fn parse(
        plan: &'static DatabaseConfigInventoryQueryPlan,
        wire: impl Into<Vec<u8>>,
    ) -> Result<DatabaseConfigInventoryDocument, DatabaseConfigInventoryParseError> {
        raw_parse(plan, complete_wire(plan, wire)).map(|read| read.into_parts().1)
    }

    fn raw_parse(
        plan: &'static DatabaseConfigInventoryQueryPlan,
        wire: impl Into<Vec<u8>>,
    ) -> Result<DatabaseConfigInventoryRead, DatabaseConfigInventoryParseError> {
        plan.parse_tsv(Zeroizing::new(wire.into()))
    }

    fn complete_wire(
        plan: &'static DatabaseConfigInventoryQueryPlan,
        wire: impl Into<Vec<u8>>,
    ) -> Vec<u8> {
        complete_wire_with_identity(plan, default_identity_row(plan), wire)
    }

    fn complete_wire_with_identity(
        plan: &'static DatabaseConfigInventoryQueryPlan,
        identity: impl Into<Vec<u8>>,
        wire: impl Into<Vec<u8>>,
    ) -> Vec<u8> {
        let inventory = wire.into();
        let needs_line_feed = !inventory.is_empty() && !inventory.ends_with(b"\n");
        let mut wire = identity.into();
        wire.push(b'\n');
        wire.extend_from_slice(&inventory);
        if needs_line_feed {
            wire.push(b'\n');
        }
        wire.extend_from_slice(match plan.provider {
            DatabaseConfigInventoryProvider::MySqlPluginTables
            | DatabaseConfigInventoryProvider::MariaDbPluginTables => {
                PLUGIN_COMPLETION_SENTINEL_ROW
            }
            DatabaseConfigInventoryProvider::MySqlComponentTable => {
                COMPONENT_COMPLETION_SENTINEL_ROW
            }
        });
        wire.push(b'\n');
        wire
    }

    fn prefix_identity(
        plan: &'static DatabaseConfigInventoryQueryPlan,
        tail: impl Into<Vec<u8>>,
    ) -> Vec<u8> {
        let mut wire = default_identity_row(plan).into_bytes();
        wire.push(b'\n');
        wire.extend_from_slice(&tail.into());
        wire
    }

    fn loaded_row(
        name: &str,
        status: &str,
        plugin_type: &str,
        library: Option<&str>,
        load_option: &str,
        maturity: Option<&str>,
    ) -> String {
        wire_row(&[
            Some("loaded"),
            Some(name),
            Some(status),
            Some(plugin_type),
            library,
            Some(load_option),
            maturity,
        ])
    }

    fn registered_row(name: &str, library: &str) -> String {
        wire_row(&[
            Some("registered"),
            Some(name),
            None,
            None,
            Some(library),
            None,
            None,
        ])
    }

    #[test]
    fn query_catalog_is_closed_unique_read_only_and_catalog_bound() {
        assert_eq!(DATABASE_CONFIG_INVENTORY_QUERY_PLANS.len(), 3);
        for (index, plan) in DATABASE_CONFIG_INVENTORY_QUERY_PLANS.iter().enumerate() {
            assert!(plan.query().trim_start().starts_with("SELECT"));
            assert!(!plan.query().contains(';'));
            assert!(!plan.query().contains("SELECT *"));
            assert!(!plan.references.is_empty());
            assert!(plan.references.iter().all(|reference| {
                !reference.id.is_empty()
                    && !reference.title.is_empty()
                    && reference.url.starts_with("https://")
            }));
            for forbidden in [
                "INSERT",
                "UPDATE",
                "DELETE",
                "ALTER",
                "DROP",
                "TRUNCATE",
                "CALL",
                "INSTALL",
                "UNINSTALL",
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
                DATABASE_CONFIG_INVENTORY_QUERY_PLANS[..index]
                    .iter()
                    .all(|previous| previous.id() != plan.id())
            );

            let artifact = artifact_by_key(plan.binding().artifact_key).unwrap();
            assert_eq!(artifact.product, plan.binding().product);
            assert_eq!(artifact.component, plan.binding().component);
            assert_eq!(artifact.surface, DatabaseConfigSurface::RuntimeSql);
            assert_eq!(artifact.dialect, DatabaseConfigDialect::RuntimeSql);
            assert_eq!(plan.binding().versions.len(), 2);
            assert_eq!(plan.query().matches("'identity_v1'").count(), 1);
            assert_eq!(plan.query().matches("'complete_v1'").count(), 1);
        }

        assert!(MYSQL_PLUGIN_QUERY.contains("FROM information_schema.PLUGINS"));
        assert!(MYSQL_PLUGIN_QUERY.contains("FROM mysql.plugin"));
        assert!(MYSQL_PLUGIN_QUERY.contains("UNION ALL"));
        assert!(MARIADB_PLUGIN_QUERY.contains("PLUGIN_MATURITY"));
        assert!(MYSQL_COMPONENT_QUERY.contains("FROM mysql.component"));
        assert!(MYSQL_COMPONENT_QUERY.contains("-1 AS source_rank"));
        for excluded in [
            "PLUGIN_AUTHOR",
            "PLUGIN_DESCRIPTION",
            "PLUGIN_LICENSE",
            "PLUGIN_VERSION",
            "AUTH_VERSION",
        ] {
            assert!(!MYSQL_PLUGIN_QUERY.contains(excluded));
            assert!(!MARIADB_PLUGIN_QUERY.contains(excluded));
        }
    }

    #[test]
    fn product_and_surface_derive_three_composite_plans_and_reject_other_surfaces() {
        let cases = [
            (
                DatabaseConfigProduct::MySql,
                DatabaseConfigInventorySurface::PluginRegistry,
                "mysql-plugin-inventory-composite-read-only-v2",
            ),
            (
                DatabaseConfigProduct::MySql,
                DatabaseConfigInventorySurface::ComponentRegistry,
                "mysql-component-inventory-composite-read-only-v2",
            ),
            (
                DatabaseConfigProduct::MariaDb,
                DatabaseConfigInventorySurface::PluginRegistry,
                "mariadb-plugin-inventory-composite-read-only-v2",
            ),
        ];
        for (product, surface, expected_id) in cases {
            assert_eq!(plan(product, surface).id(), expected_id);
        }

        assert_eq!(
            database_config_inventory_query_plan(
                DatabaseConfigProduct::MariaDb,
                DatabaseConfigInventorySurface::ComponentRegistry,
            ),
            Err(DatabaseConfigInventoryLookupError::UnsupportedSurface)
        );
        assert_eq!(
            database_config_inventory_query_plan(
                DatabaseConfigProduct::PostgreSql,
                DatabaseConfigInventorySurface::PluginRegistry,
            ),
            Err(DatabaseConfigInventoryLookupError::UnsupportedProduct)
        );
    }

    #[test]
    fn composite_wire_binds_each_reviewed_identity_to_its_document() {
        let cases = [
            (
                mysql_plugin_plan(),
                "8.0.11",
                DatabaseConfigProduct::MySql,
                DatabaseConfigVersion::new(8, 0, 11),
            ),
            (
                mysql_plugin_plan(),
                "8.4.99",
                DatabaseConfigProduct::MySql,
                DatabaseConfigVersion::new(8, 4, 99),
            ),
            (
                mysql_component_plan(),
                "8.0.43",
                DatabaseConfigProduct::MySql,
                DatabaseConfigVersion::new(8, 0, 43),
            ),
            (
                mysql_component_plan(),
                "8.4.0",
                DatabaseConfigProduct::MySql,
                DatabaseConfigVersion::new(8, 4, 0),
            ),
            (
                mariadb_plugin_plan(),
                "10.11.0-MariaDB",
                DatabaseConfigProduct::MariaDb,
                DatabaseConfigVersion::new(10, 11, 0),
            ),
            (
                mariadb_plugin_plan(),
                "11.4.99-MariaDB-log",
                DatabaseConfigProduct::MariaDb,
                DatabaseConfigVersion::new(11, 4, 99),
            ),
        ];
        for (plan, version_wire, product, version) in cases {
            let wire =
                complete_wire_with_identity(plan, identity_row(plan, version_wire), Vec::new());
            let (identity, document) = raw_parse(plan, wire).unwrap().into_parts();
            assert_eq!(identity.product(), product);
            assert_eq!(identity.version(), version);
            assert!(document.is_empty());
        }
    }

    #[test]
    fn composite_wire_rejects_truncation_boundary_confusion_and_identity_mismatch() {
        let plan = mysql_plugin_plan();
        let mut sentinel_only = PLUGIN_COMPLETION_SENTINEL_ROW.to_vec();
        sentinel_only.push(b'\n');
        assert_eq!(
            raw_parse(plan, sentinel_only).unwrap_err(),
            DatabaseConfigInventoryParseError::MissingIdentityBoundary
        );

        let ordinary = loaded_row("InnoDB", "ACTIVE", "STORAGE ENGINE", None, "ON", None);
        let mut boundary_late = ordinary.as_bytes().to_vec();
        boundary_late.push(b'\n');
        boundary_late.extend_from_slice(identity_row(plan, "8.4.3").as_bytes());
        boundary_late.push(b'\n');
        boundary_late.extend_from_slice(PLUGIN_COMPLETION_SENTINEL_ROW);
        boundary_late.push(b'\n');
        assert_eq!(
            raw_parse(plan, boundary_late).unwrap_err(),
            DatabaseConfigInventoryParseError::IdentityBoundaryNotFirst { row: 1 }
        );

        let duplicate = complete_wire_with_identity(
            plan,
            identity_row(plan, "8.4.3"),
            identity_row(plan, "8.4.3"),
        );
        assert_eq!(
            raw_parse(plan, duplicate).unwrap_err(),
            DatabaseConfigInventoryParseError::DuplicateIdentityBoundary { row: 1 }
        );

        let invalid_shape = wire_row(&[
            Some("identity_v1"),
            Some("8.4.3"),
            Some("MySQL Community Server - GPL"),
            Some("AUDIT"),
            None,
            None,
            None,
        ]);
        assert_eq!(
            raw_parse(
                plan,
                complete_wire_with_identity(plan, invalid_shape, Vec::new())
            )
            .unwrap_err(),
            DatabaseConfigInventoryParseError::InvalidIdentityRowShape
        );

        assert!(matches!(
            raw_parse(
                plan,
                complete_wire_with_identity(plan, identity_row(plan, "11.4.3-MariaDB"), Vec::new())
            ),
            Err(DatabaseConfigInventoryParseError::InvalidIdentity(
                DatabaseConfigRuntimeIdentityParseError::DeclaredProductMismatch
            ))
        ));
        assert!(matches!(
            raw_parse(
                plan,
                complete_wire_with_identity(plan, identity_row(plan, "8.1.0"), Vec::new())
            ),
            Err(DatabaseConfigInventoryParseError::InvalidIdentity(
                DatabaseConfigRuntimeIdentityParseError::UnsupportedVersion
            ))
        ));

        let mut truncated = prefix_identity(plan, ordinary.into_bytes());
        truncated.push(b'\n');
        assert_eq!(
            raw_parse(plan, truncated).unwrap_err(),
            DatabaseConfigInventoryParseError::MissingCompletionSentinel
        );
    }

    #[test]
    fn mysql_plugin_rows_remain_loaded_or_registered_in_wire_order() {
        let wire = [
            loaded_row("InnoDB", "ACTIVE", "STORAGE ENGINE", None, "ON", None),
            loaded_row(
                "audit_log",
                "DISABLED",
                "AUDIT",
                Some("audit_log.so"),
                "FORCE",
                None,
            ),
            registered_row("audit_log", "audit_log.so"),
            registered_row("audit_log", "audit_log.so"),
        ]
        .join("\n");
        let document = parse(mysql_plugin_plan(), wire.into_bytes()).unwrap();
        let rows = document.plugins().unwrap().rows();
        assert_eq!(rows.len(), 4);
        let DatabaseConfigPluginInventoryRow::Loaded(first) = &rows[0] else {
            panic!("first row changed kind")
        };
        assert_eq!(first.name().public_value(), Some("InnoDB"));
        assert_eq!(first.plugin_type().public_value(), Some("STORAGE ENGINE"));
        assert_eq!(first.status(), DatabaseConfigPluginStatus::Active);
        assert_eq!(first.load_option(), DatabaseConfigPluginLoadOption::On);
        assert!(first.is_built_in());
        assert_eq!(rows[2], rows[3]);
        assert!(matches!(
            &rows[2],
            DatabaseConfigPluginInventoryRow::Registered(_)
        ));
    }

    #[test]
    fn mariadb_maturity_is_typed_nullable_and_unknown_raw_is_discarded() {
        let secret = "PASSWORD=DoNotRetain";
        let wire = [
            loaded_row(
                "server_audit",
                secret,
                "AUDIT",
                Some("server_audit.so"),
                secret,
                Some("Unknown"),
            ),
            loaded_row(
                "metadata_lock_info",
                "ACTIVE",
                "INFORMATION SCHEMA",
                None,
                "ON",
                None,
            ),
            loaded_row(
                "future_plugin",
                "ACTIVE",
                "DAEMON",
                None,
                "ON",
                Some(secret),
            ),
        ]
        .join("\n");
        let document = parse(mariadb_plugin_plan(), wire.into_bytes()).unwrap();
        let rows = document.plugins().unwrap().rows();
        let DatabaseConfigPluginInventoryRow::Loaded(first) = &rows[0] else {
            panic!("expected loaded row")
        };
        assert_eq!(first.status(), DatabaseConfigPluginStatus::Unrecognized);
        assert_eq!(
            first.load_option(),
            DatabaseConfigPluginLoadOption::Unrecognized
        );
        assert_eq!(
            first.maturity(),
            Some(DatabaseConfigPluginMaturity::VendorUnknown)
        );
        let DatabaseConfigPluginInventoryRow::Loaded(second) = &rows[1] else {
            panic!("expected loaded row")
        };
        assert_eq!(second.maturity(), None);
        let DatabaseConfigPluginInventoryRow::Loaded(third) = &rows[2] else {
            panic!("expected loaded row")
        };
        assert_eq!(
            third.maturity(),
            Some(DatabaseConfigPluginMaturity::Unrecognized)
        );
        assert!(!format!("{document:?}").contains("DoNotRetain"));
        assert!(!format!("{:?}", document.clone()).contains("DoNotRetain"));
    }

    #[test]
    fn loaded_and_registered_shapes_fail_closed() {
        let mysql = mysql_plugin_plan();
        for cells in [
            [
                Some("loaded"),
                None,
                Some("ACTIVE"),
                Some("AUDIT"),
                None,
                Some("ON"),
                None,
            ],
            [
                Some("loaded"),
                Some("x"),
                None,
                Some("AUDIT"),
                None,
                Some("ON"),
                None,
            ],
            [
                Some("loaded"),
                Some("x"),
                Some("ACTIVE"),
                None,
                None,
                Some("ON"),
                None,
            ],
            [
                Some("loaded"),
                Some("x"),
                Some("ACTIVE"),
                Some("AUDIT"),
                None,
                None,
                None,
            ],
            [
                Some("loaded"),
                Some("x"),
                Some("ACTIVE"),
                Some("AUDIT"),
                None,
                Some("ON"),
                Some("STABLE"),
            ],
            [
                Some("registered"),
                Some("x"),
                Some("ACTIVE"),
                None,
                Some("x.so"),
                None,
                None,
            ],
            [
                Some("registered"),
                Some("x"),
                None,
                Some("AUDIT"),
                Some("x.so"),
                None,
                None,
            ],
            [Some("registered"), Some("x"), None, None, None, None, None],
            [
                Some("registered"),
                Some("x"),
                None,
                None,
                Some("x.so"),
                Some("ON"),
                None,
            ],
            [
                Some("registered"),
                Some("x"),
                None,
                None,
                Some("x.so"),
                None,
                Some("STABLE"),
            ],
        ] {
            assert!(matches!(
                parse(mysql, wire_row(&cells).into_bytes()),
                Err(DatabaseConfigInventoryParseError::InvalidPluginRowShape { row: 0 })
            ));
        }
    }

    #[test]
    fn hostile_text_has_only_a_one_way_redacted_representation() {
        let secret = "DontLeakThisValue";
        let wire = [
            loaded_row(
                &format!("safe\u{202e}{secret}"),
                "ACTIVE",
                &format!("-----BEGIN CERTIFICATE-----{secret}"),
                Some(&format!("/tmp/{secret}.so")),
                "ON",
                None,
            ),
            registered_row(
                &format!("password={secret}"),
                &format!("https://user:{secret}@host/plugin.so"),
            ),
            loaded_row(
                &format!("line\u{200b}{secret}"),
                "ACTIVE",
                "AUDIT",
                Some(&format!("C:\\plugins\\{secret}.dll")),
                "ON",
                None,
            ),
        ]
        .join("\n");
        let document = parse(mysql_plugin_plan(), wire.into_bytes()).unwrap();
        let rows = document.plugins().unwrap().rows();
        let DatabaseConfigPluginInventoryRow::Loaded(first) = &rows[0] else {
            panic!("expected loaded row")
        };
        assert!(first.name().is_redacted());
        assert!(first.plugin_type().is_redacted());
        assert!(first.library().unwrap().is_redacted());
        let DatabaseConfigPluginInventoryRow::Registered(second) = &rows[1] else {
            panic!("expected registered row")
        };
        assert!(second.name().is_redacted());
        assert!(second.library().is_redacted());
        let DatabaseConfigPluginInventoryRow::Loaded(third) = &rows[2] else {
            panic!("expected loaded row")
        };
        assert!(third.name().is_redacted());
        assert!(third.library().unwrap().is_redacted());

        let debug = format!("{rows:?}{:?}", rows.to_vec());
        assert!(!debug.contains(secret));
        assert!(!format!("{document:?}").contains(secret));
    }

    #[test]
    fn component_ids_are_internal_typed_values_and_urns_are_strict() {
        let wire = [
            wire_row(&[
                Some("1"),
                Some("1"),
                Some("file://component_validate_password"),
            ]),
            wire_row(&[Some("2"), Some("1"), Some("file:///etc/private")]),
            wire_row(&[
                Some("2"),
                Some("1"),
                Some("https://user:secret@host/component"),
            ]),
            wire_row(&[Some("2"), Some("1"), Some("-----BEGIN PRIVATE KEY-----")]),
        ]
        .join("\n");
        let document = parse(mysql_component_plan(), wire.into_bytes()).unwrap();
        let rows = document.components().unwrap().rows();
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[0].component_id, 1);
        assert_eq!(rows[0].component_group_id, 1);
        assert_eq!(
            rows[0].urn().public_value(),
            Some("file://component_validate_password")
        );
        assert!(rows[1].urn().is_redacted());
        assert!(rows[2].urn().is_redacted());
        assert!(rows[3].urn().is_redacted());
    }

    #[test]
    fn component_decimal_contract_is_required_canonical_and_bounded() {
        for invalid in [
            None,
            Some(""),
            Some("01"),
            Some("+1"),
            Some("-1"),
            Some("18446744073709551616"),
        ] {
            let wire = wire_row(&[invalid, Some("1"), Some("file://component_x")]);
            assert!(matches!(
                parse(mysql_component_plan(), wire.into_bytes()),
                Err(DatabaseConfigInventoryParseError::RequiredCellMissing { .. })
                    | Err(DatabaseConfigInventoryParseError::RequiredCellEmpty { .. })
                    | Err(DatabaseConfigInventoryParseError::InvalidDecimal { .. })
            ));
        }
        let group_null = wire_row(&[Some("1"), None, Some("file://component_x")]);
        assert!(matches!(
            parse(mysql_component_plan(), group_null.into_bytes()),
            Err(DatabaseConfigInventoryParseError::RequiredCellMissing { row: 0, column: 1 })
        ));
    }

    #[test]
    fn wire_shape_utf8_columns_and_field_limits_fail_closed_without_echo() {
        let plan = mysql_plugin_plan();
        assert!(matches!(
            parse(plan, b"GG".to_vec()),
            Err(DatabaseConfigInventoryParseError::InvalidWireByte { .. })
        ));
        assert!(matches!(
            parse(plan, b"6\t-\t-\t-\t-\t-\t-".to_vec()),
            Err(DatabaseConfigInventoryParseError::InvalidHex { .. })
        ));
        let invalid_utf8 = ["FF", "78", "-", "-", "78", "-", "-"].join("\t");
        assert!(matches!(
            parse(plan, invalid_utf8.into_bytes()),
            Err(DatabaseConfigInventoryParseError::InvalidUtf8 { row: 0, column: 0 })
        ));
        assert!(matches!(
            parse(plan, b"6C\x01\t-\t-\t-\t-\t-\t-".to_vec()),
            Err(DatabaseConfigInventoryParseError::ControlCharacter { .. })
        ));
        let decoded_control = loaded_row("line\nDontLeak", "ACTIVE", "AUDIT", None, "ON", None);
        let error = parse(plan, decoded_control.into_bytes()).unwrap_err();
        assert_eq!(
            error,
            DatabaseConfigInventoryParseError::DecodedControlCharacter { row: 0, column: 1 }
        );
        assert!(!format!("{error:?}").contains("DontLeak"));
        assert!(matches!(
            parse(plan, b"6C\t-".to_vec()),
            Err(DatabaseConfigInventoryParseError::InvalidColumnCount {
                expected: PLUGIN_TSV_COLUMNS,
                ..
            })
        ));

        let oversized_name = "x".repeat(MAX_DATABASE_CONFIG_INVENTORY_NAME_BYTES + 1);
        let error = parse(
            plan,
            loaded_row(&oversized_name, "ACTIVE", "AUDIT", None, "ON", None).into_bytes(),
        )
        .unwrap_err();
        assert_eq!(
            error,
            DatabaseConfigInventoryParseError::CellTooLarge { row: 0, column: 1 }
        );
        assert!(!format!("{error:?}").contains(&oversized_name));
    }

    #[test]
    fn global_byte_row_and_cell_caps_are_enforced_and_empty_is_valid() {
        assert!(parse(mysql_plugin_plan(), Vec::new()).unwrap().is_empty());
        assert_eq!(
            parse(
                mysql_plugin_plan(),
                vec![b'0'; MAX_DATABASE_CONFIG_INVENTORY_TSV_BYTES + 1],
            )
            .unwrap_err(),
            DatabaseConfigInventoryParseError::InputTooLarge
        );

        // The generated identity and completion rows consume two row slots.
        let too_many_rows = "-\t-\t-\n".repeat(MAX_DATABASE_CONFIG_INVENTORY_ROWS);
        assert_eq!(
            parse(mysql_component_plan(), too_many_rows.into_bytes()).unwrap_err(),
            DatabaseConfigInventoryParseError::TooManyRows
        );

        let mut too_many_cells = Vec::with_capacity(MAX_DATABASE_CONFIG_INVENTORY_CELLS * 2);
        // The three-cell component sentinel is included in the global cap.
        for index in 0..(MAX_DATABASE_CONFIG_INVENTORY_CELLS - 2) {
            if index > 0 {
                too_many_cells.push(b'\t');
            }
            too_many_cells.push(b'-');
        }
        assert_eq!(
            parse(mysql_plugin_plan(), too_many_cells).unwrap_err(),
            DatabaseConfigInventoryParseError::TooManyCells
        );
    }

    #[test]
    fn completion_sentinel_is_unique_final_and_line_feed_terminated() {
        for plan in [
            mysql_plugin_plan(),
            mariadb_plugin_plan(),
            mysql_component_plan(),
        ] {
            let sentinel = match plan.provider {
                DatabaseConfigInventoryProvider::MySqlPluginTables
                | DatabaseConfigInventoryProvider::MariaDbPluginTables => {
                    PLUGIN_COMPLETION_SENTINEL_ROW
                }
                DatabaseConfigInventoryProvider::MySqlComponentTable => {
                    COMPONENT_COMPLETION_SENTINEL_ROW
                }
            };

            let lf = complete_wire(plan, Vec::new());
            assert!(raw_parse(plan, lf).unwrap().into_parts().1.is_empty());

            let mut crlf = complete_wire(plan, Vec::new());
            crlf.pop();
            crlf.extend_from_slice(b"\r\n");
            assert!(raw_parse(plan, crlf).unwrap().into_parts().1.is_empty());

            assert_eq!(
                raw_parse(plan, Vec::new()).unwrap_err(),
                DatabaseConfigInventoryParseError::MissingFinalLineFeed
            );
            assert_eq!(
                raw_parse(plan, sentinel.to_vec()).unwrap_err(),
                DatabaseConfigInventoryParseError::MissingFinalLineFeed
            );

            let ordinary_row = match plan.provider {
                DatabaseConfigInventoryProvider::MySqlPluginTables => {
                    loaded_row("InnoDB", "ACTIVE", "STORAGE ENGINE", None, "ON", None)
                }
                DatabaseConfigInventoryProvider::MariaDbPluginTables => loaded_row(
                    "server_audit",
                    "ACTIVE",
                    "AUDIT",
                    None,
                    "ON",
                    Some("STABLE"),
                ),
                DatabaseConfigInventoryProvider::MySqlComponentTable => wire_row(&[
                    Some("1"),
                    Some("1"),
                    Some("file://component_validate_password"),
                ]),
            };
            assert_eq!(
                raw_parse(plan, format!("{ordinary_row}\n").into_bytes()).unwrap_err(),
                DatabaseConfigInventoryParseError::MissingCompletionSentinel
            );

            let mut sentinel_then_row = sentinel.to_vec();
            sentinel_then_row.push(b'\n');
            sentinel_then_row.extend_from_slice(ordinary_row.as_bytes());
            sentinel_then_row.push(b'\n');
            let sentinel_then_row = prefix_identity(plan, sentinel_then_row);
            assert_eq!(
                raw_parse(plan, sentinel_then_row).unwrap_err(),
                DatabaseConfigInventoryParseError::CompletionSentinelNotLast { row: 1 }
            );

            let mut intermediate = ordinary_row.as_bytes().to_vec();
            intermediate.push(b'\n');
            intermediate.extend_from_slice(sentinel);
            intermediate.push(b'\n');
            intermediate.extend_from_slice(ordinary_row.as_bytes());
            intermediate.push(b'\n');
            let intermediate = prefix_identity(plan, intermediate);
            assert_eq!(
                raw_parse(plan, intermediate).unwrap_err(),
                DatabaseConfigInventoryParseError::CompletionSentinelNotLast { row: 2 }
            );

            let mut duplicate = sentinel.to_vec();
            duplicate.push(b'\n');
            duplicate.extend_from_slice(sentinel);
            duplicate.push(b'\n');
            let duplicate = prefix_identity(plan, duplicate);
            assert_eq!(
                raw_parse(plan, duplicate).unwrap_err(),
                DatabaseConfigInventoryParseError::DuplicateCompletionSentinel { row: 1 }
            );

            let mut trailing_blank = sentinel.to_vec();
            trailing_blank.extend_from_slice(b"\n\n");
            let trailing_blank = prefix_identity(plan, trailing_blank);
            assert_eq!(
                raw_parse(plan, trailing_blank).unwrap_err(),
                DatabaseConfigInventoryParseError::CompletionSentinelNotLast { row: 1 }
            );

            let mut cut_after_sentinel = ordinary_row.into_bytes();
            cut_after_sentinel.push(b'\n');
            cut_after_sentinel.extend_from_slice(sentinel);
            let cut_after_sentinel = prefix_identity(plan, cut_after_sentinel);
            assert_eq!(
                raw_parse(plan, cut_after_sentinel).unwrap_err(),
                DatabaseConfigInventoryParseError::MissingFinalLineFeed
            );
        }
    }

    #[test]
    fn crlf_is_accepted_but_extra_blank_rows_and_unknown_kinds_are_not() {
        let valid = format!(
            "{}\r\n",
            loaded_row("InnoDB", "ACTIVE", "STORAGE ENGINE", None, "ON", None)
        );
        assert_eq!(
            parse(mysql_plugin_plan(), valid.into_bytes())
                .unwrap()
                .len(),
            1
        );

        let blank = format!(
            "{}\n\n{}",
            loaded_row("a", "ACTIVE", "AUDIT", None, "ON", None),
            loaded_row("b", "ACTIVE", "AUDIT", None, "ON", None)
        );
        assert!(matches!(
            parse(mysql_plugin_plan(), blank.into_bytes()),
            Err(DatabaseConfigInventoryParseError::InvalidColumnCount { row: 1, .. })
        ));
        let unknown = wire_row(&[
            Some("persisted"),
            Some("x"),
            None,
            None,
            Some("x.so"),
            None,
            None,
        ]);
        assert_eq!(
            parse(mysql_plugin_plan(), unknown.into_bytes()).unwrap_err(),
            DatabaseConfigInventoryParseError::InvalidPluginRowKind { row: 0 }
        );
    }
}
