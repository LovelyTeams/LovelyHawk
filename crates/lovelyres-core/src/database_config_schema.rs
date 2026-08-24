//! Versioned, artifact-bound database configuration schema contracts.
//!
//! This module is deliberately only a static metadata and value-validation
//! foundation. It performs no remote discovery, mutation, persistence, or UI
//! work. The production registry contains only partial packs reviewed against
//! official references; a match improves visibility but never grants mutation
//! or deployment authority and is never inferred from wire compatibility.

use std::{borrow::Cow, fmt};

use url::Url;
use zeroize::Zeroizing;

use crate::database_config::{
    DatabaseConfigComponent, DatabaseConfigDialect, DatabaseConfigProduct, artifact_by_key,
};
use crate::database_config_schema_domestic::{
    DM8_MAIN_INSPECT_ONLY_SCHEMA, DM8_SQL_LOG_INSPECT_ONLY_SCHEMA,
    GOLDENDB_V6_1_03_10_PROXY_INI_SCHEMA, KINGBASE_ES_V8_6_7_12_MAIN_SCHEMA,
    KINGBASE_ES_V9_3_11_MAIN_SCHEMA, OPENGAUSS_5_0_0_STANDARD_MAIN_SCHEMA,
    OPENGAUSS_6_0_0_LITE_MAIN_SCHEMA, PD_8_5_7_TOML_SCHEMA, TIDB_8_5_7_SERVER_TOML_SCHEMA,
    TIKV_8_5_7_TOML_SCHEMA, YASHANDB_23_5_4_100_YASDB_INI_SCHEMA,
};
use crate::database_config_schema_open::{
    MARIADB_OPTION_FILE_10_11_SCHEMA, MARIADB_OPTION_FILE_11_4_SCHEMA,
    MYSQL_OPTION_FILE_8_0_SCHEMA, MYSQL_OPTION_FILE_8_4_SCHEMA, POSTGRESQL_MAIN_16_SCHEMA,
    POSTGRESQL_MAIN_17_SCHEMA, POSTGRESQL_MAIN_18_SCHEMA,
};

pub const MAX_DATABASE_CONFIG_SCHEMA_INPUT_BYTES: usize = 64 * 1024;
pub const MAX_DATABASE_CONFIG_SCHEMA_KEY_BYTES: usize = 512;
pub const MAX_DATABASE_CONFIG_SCHEMA_ENUM_VALUES: usize = 1_024;
pub const MAX_DATABASE_CONFIG_SCHEMA_ALIASES_PER_PARAMETER: usize = 64;
pub const MAX_DATABASE_CONFIG_SCHEMA_LABEL_BYTES: usize = 512;
pub const MAX_DATABASE_CONFIG_SCHEMA_REFERENCES: usize = 256;
pub const MAX_DATABASE_CONFIG_SCHEMA_REFERENCE_ID_BYTES: usize = 512;
pub const MAX_DATABASE_CONFIG_SCHEMA_REFERENCE_TITLE_BYTES: usize = 1_024;
pub const MAX_DATABASE_CONFIG_SCHEMA_REFERENCE_URL_BYTES: usize = 4 * 1_024;
pub const MAX_DATABASE_CONFIG_SCHEMA_DOCUMENTED_DEFAULT_BYTES: usize = 4 * 1_024;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DatabaseConfigVersion {
    major: u16,
    minor: u16,
    patch: u16,
    revision: u16,
}

impl DatabaseConfigVersion {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self::new_with_revision(major, minor, patch, 0)
    }

    pub const fn new_with_revision(major: u16, minor: u16, patch: u16, revision: u16) -> Self {
        Self {
            major,
            minor,
            patch,
            revision,
        }
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

    pub const fn revision(self) -> u16 {
        self.revision
    }
}

/// A typed selector; no free-form version string or fuzzy matching is allowed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseConfigVersionSelector {
    Exact(DatabaseConfigVersion),
    HalfOpen {
        minimum_inclusive: DatabaseConfigVersion,
        maximum_exclusive: DatabaseConfigVersion,
    },
}

impl DatabaseConfigVersionSelector {
    pub fn contains(self, version: DatabaseConfigVersion) -> bool {
        match self {
            Self::Exact(expected) => version == expected,
            Self::HalfOpen {
                minimum_inclusive,
                maximum_exclusive,
            } => minimum_inclusive <= version && version < maximum_exclusive,
        }
    }

    fn is_valid(self) -> bool {
        match self {
            Self::Exact(_) => true,
            Self::HalfOpen {
                minimum_inclusive,
                maximum_exclusive,
            } => minimum_inclusive < maximum_exclusive,
        }
    }

    fn overlaps(self, other: Self) -> bool {
        match (self, other) {
            (Self::Exact(left), Self::Exact(right)) => left == right,
            (Self::Exact(version), range) | (range, Self::Exact(version)) => {
                range.contains(version)
            }
            (
                Self::HalfOpen {
                    minimum_inclusive: left_minimum,
                    maximum_exclusive: left_maximum,
                },
                Self::HalfOpen {
                    minimum_inclusive: right_minimum,
                    maximum_exclusive: right_maximum,
                },
            ) => left_minimum < right_maximum && right_minimum < left_maximum,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseConfigSchemaCompleteness {
    Partial,
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseConfigSchemaScope {
    Session,
    Instance,
    Component,
    Cluster,
    Global,
    VendorDefined,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseConfigSchemaSensitivity {
    Public,
    OperationalMetadata,
    MayContainSecrets,
    PrivateKeyReference,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseConfigSchemaActivation {
    Dynamic,
    Reload,
    Restart,
    RollingRestart,
    VendorProcedure,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DatabaseConfigSchemaRisk {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseConfigTextNormalization {
    Preserve,
    TrimAsciiWhitespace,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseConfigSchemaValueKind {
    Boolean {
        true_literal: &'static str,
        false_literal: &'static str,
    },
    Integer {
        minimum_inclusive: i64,
        maximum_inclusive: i64,
    },
    Enumeration {
        values: &'static [&'static str],
    },
    Text {
        minimum_bytes: usize,
        maximum_bytes: usize,
        normalization: DatabaseConfigTextNormalization,
    },
}

/// A fixed scalar default explicitly documented for one schema binding.
///
/// This is read-only evidence metadata. It is not the target's current value,
/// a recommendation, or authority to generate, mutate, or deploy a file. In
/// particular, an enumeration default is named explicitly and is never inferred
/// from the order of `DatabaseConfigSchemaValueKind::Enumeration::values`.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum DatabaseConfigDocumentedDefault {
    Boolean(bool),
    Integer(i64),
    Enumeration(&'static str),
    Text(&'static str),
}

impl fmt::Debug for DatabaseConfigDocumentedDefault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Boolean(_) => "Boolean(<documented>)",
            Self::Integer(_) => "Integer(<documented>)",
            Self::Enumeration(_) => "Enumeration(<documented>)",
            Self::Text(_) => "Text(<documented>)",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatabaseConfigParameterSchema {
    /// Exact section/table path. `None` means the artifact root; no prefix or
    /// fuzzy matching is performed. MySQL-option group names follow their
    /// documented ASCII case-insensitive semantics; keys remain exact aliases.
    pub container_path: Option<&'static str>,
    pub canonical_key: &'static str,
    /// Exact, reviewed spellings accepted in the same container. No alias is
    /// generated and no dash/underscore or other fuzzy matching occurs.
    pub exact_aliases: &'static [&'static str],
    pub value_kind: DatabaseConfigSchemaValueKind,
    /// A fixed scalar default proven by `official_reference_id` for this exact
    /// schema binding. `None` also covers contextual, computed, unreviewed, and
    /// version-dependent defaults; consumers must not infer one from `value_kind`.
    pub documented_default: Option<DatabaseConfigDocumentedDefault>,
    pub scope: DatabaseConfigSchemaScope,
    pub sensitivity: DatabaseConfigSchemaSensitivity,
    pub activation: DatabaseConfigSchemaActivation,
    pub risk: DatabaseConfigSchemaRisk,
    pub risk_rationale: &'static str,
    pub competition_rationale: &'static str,
    pub official_reference_id: &'static str,
    /// Stable edition/plugin capability key required by this parameter, when
    /// applicable. This module records the requirement but never probes it.
    pub required_capability: Option<&'static str>,
}

impl DatabaseConfigParameterSchema {
    /// Returns a canonical, bounded public representation for read-only UI
    /// metadata. Invalid or sensitive metadata fails closed as absent even if a
    /// caller bypasses catalog construction.
    pub fn documented_default_for_display(&self) -> Option<Cow<'static, str>> {
        validated_documented_default(self).ok().flatten()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatabaseConfigSchemaBinding {
    pub product: DatabaseConfigProduct,
    pub versions: DatabaseConfigVersionSelector,
    /// Exact edition/family key. `None` matches only a target with `None`.
    pub edition_key: Option<&'static str>,
    pub component: DatabaseConfigComponent,
    /// Exact key from `DATABASE_CONFIG_ARTIFACTS`.
    pub artifact_key: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatabaseConfigSchemaReference {
    pub id: &'static str,
    pub title: &'static str,
    pub url: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatabaseConfigSchema {
    /// Stable, static labels for selection. They are display metadata only and
    /// are never used for matching a target version.
    pub display_label: &'static str,
    pub version_label: &'static str,
    pub binding: DatabaseConfigSchemaBinding,
    pub completeness: DatabaseConfigSchemaCompleteness,
    pub parameters: &'static [DatabaseConfigParameterSchema],
    /// Bounded official evidence metadata. Catalog construction verifies that
    /// every parameter's `official_reference_id` resolves exactly once here.
    pub references: &'static [DatabaseConfigSchemaReference],
}

impl DatabaseConfigSchema {
    /// A successful lookup of a partial schema never grants artifact-wide
    /// coverage. Consumers must keep unknown keys visible and unvalidated.
    pub const fn has_complete_artifact_coverage(&self) -> bool {
        matches!(
            self.completeness,
            DatabaseConfigSchemaCompleteness::Complete
        )
    }

    pub fn parameter(
        &self,
        locator: DatabaseConfigParameterLocator<'_>,
    ) -> Option<&DatabaseConfigParameterSchema> {
        let case_insensitive_containers = artifact_by_key(self.binding.artifact_key)
            .is_some_and(|artifact| artifact.dialect == DatabaseConfigDialect::MySqlOptionFile);
        self.parameters.iter().find(|parameter| {
            container_paths_match(
                parameter.container_path,
                locator.container_path,
                case_insensitive_containers,
            ) && parameter_accepts_key(parameter, locator.key)
        })
    }

    /// Checks only the configured value syntax/range and returns a normalized
    /// public value when safe. `SyntaxValid` does not assert that a declared
    /// `required_capability` is installed or available on any target.
    pub fn validate_normalized_value(
        &self,
        locator: DatabaseConfigParameterLocator<'_>,
        raw_value: &str,
    ) -> DatabaseConfigSchemaValidation<'_> {
        let Some(parameter) = self.parameter(locator) else {
            return DatabaseConfigSchemaValidation {
                parameter: None,
                status: DatabaseConfigSchemaValidationStatus::VisibleUnvalidated,
                normalized_value: None,
            };
        };
        if raw_value.len() > MAX_DATABASE_CONFIG_SCHEMA_INPUT_BYTES {
            return DatabaseConfigSchemaValidation::invalid(
                parameter,
                DatabaseConfigSchemaValueError::InputTooLong,
            );
        }

        match normalize_value(parameter.value_kind, raw_value) {
            Ok(value) => {
                let value = Zeroizing::new(value);
                DatabaseConfigSchemaValidation {
                    parameter: Some(parameter),
                    status: DatabaseConfigSchemaValidationStatus::SyntaxValid,
                    normalized_value: matches!(
                        parameter.sensitivity,
                        DatabaseConfigSchemaSensitivity::Public
                    )
                    .then_some(value),
                }
            }
            Err(error) => DatabaseConfigSchemaValidation::invalid(parameter, error),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatabaseConfigParameterLocator<'a> {
    pub container_path: Option<&'a str>,
    pub key: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatabaseConfigSchemaTarget<'a> {
    pub product: DatabaseConfigProduct,
    pub version: DatabaseConfigVersion,
    pub edition_key: Option<&'a str>,
    pub component: DatabaseConfigComponent,
    pub artifact_key: &'a str,
}

#[derive(Clone, Copy, Debug)]
pub struct DatabaseConfigSchemaCatalog {
    schemas: &'static [DatabaseConfigSchema],
}

impl DatabaseConfigSchemaCatalog {
    pub fn new(
        schemas: &'static [DatabaseConfigSchema],
    ) -> Result<Self, DatabaseConfigSchemaCatalogError> {
        validate_catalog(schemas)?;
        Ok(Self { schemas })
    }

    pub const fn schemas(&self) -> &'static [DatabaseConfigSchema] {
        self.schemas
    }

    pub fn lookup(
        &self,
        target: DatabaseConfigSchemaTarget<'_>,
    ) -> Result<&'static DatabaseConfigSchema, DatabaseConfigSchemaLookupError> {
        if target.edition_key.is_some_and(|edition_key| {
            !valid_bounded_text(edition_key, MAX_DATABASE_CONFIG_SCHEMA_KEY_BYTES)
        }) {
            return Err(DatabaseConfigSchemaLookupError::InvalidEditionKey);
        }
        let artifact = artifact_by_key(target.artifact_key)
            .ok_or(DatabaseConfigSchemaLookupError::ArtifactUnknown)?;
        if artifact.product != target.product {
            return Err(DatabaseConfigSchemaLookupError::ProductMismatch);
        }
        if artifact.component != target.component {
            return Err(DatabaseConfigSchemaLookupError::ComponentMismatch);
        }

        let mut artifact_has_schema = false;
        let mut edition_has_schema = false;
        let mut matched = None;
        for schema in self.schemas {
            if schema.binding.artifact_key != target.artifact_key {
                continue;
            }
            artifact_has_schema = true;
            if schema.binding.edition_key != target.edition_key {
                continue;
            }
            edition_has_schema = true;
            if schema.binding.product == target.product
                && schema.binding.component == target.component
                && schema.binding.versions.contains(target.version)
            {
                if matched.is_some() {
                    return Err(DatabaseConfigSchemaLookupError::AmbiguousMatch);
                }
                matched = Some(schema);
            }
        }
        if !artifact_has_schema {
            return Err(DatabaseConfigSchemaLookupError::SchemaUnavailable);
        }
        if !edition_has_schema {
            return Err(DatabaseConfigSchemaLookupError::EditionMismatch);
        }
        matched.ok_or(DatabaseConfigSchemaLookupError::VersionMismatch)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseConfigSchemaCatalogError {
    InvalidSchemaMetadata {
        schema_index: usize,
    },
    EmptyArtifactKey {
        schema_index: usize,
    },
    UnknownArtifact {
        schema_index: usize,
    },
    ArtifactProductMismatch {
        schema_index: usize,
    },
    ArtifactComponentMismatch {
        schema_index: usize,
    },
    InvalidVersionSelector {
        schema_index: usize,
    },
    InvalidEditionKey {
        schema_index: usize,
    },
    EmptyParameterSet {
        schema_index: usize,
    },
    TooManyReferences {
        schema_index: usize,
    },
    InvalidReference {
        schema_index: usize,
        reference_index: usize,
    },
    DuplicateReference {
        schema_index: usize,
        first_reference_index: usize,
        duplicate_reference_index: usize,
    },
    InvalidParameter {
        schema_index: usize,
        parameter_index: usize,
    },
    InvalidDocumentedDefault {
        schema_index: usize,
        parameter_index: usize,
    },
    UnresolvedParameterReference {
        schema_index: usize,
        parameter_index: usize,
    },
    DuplicateParameter {
        schema_index: usize,
        first_parameter_index: usize,
        duplicate_parameter_index: usize,
    },
    OverlappingSchemas {
        first_schema_index: usize,
        second_schema_index: usize,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseConfigSchemaLookupError {
    InvalidEditionKey,
    ArtifactUnknown,
    ProductMismatch,
    ComponentMismatch,
    SchemaUnavailable,
    EditionMismatch,
    VersionMismatch,
    AmbiguousMatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseConfigSchemaValueError {
    InputTooLong,
    InvalidBoolean,
    InvalidInteger,
    BelowMinimum,
    AboveMaximum,
    UnknownEnumerationValue,
    TextTooShort,
    TextTooLong,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseConfigSchemaValidationStatus {
    SyntaxValid,
    Invalid(DatabaseConfigSchemaValueError),
    VisibleUnvalidated,
}

#[derive(Clone, Eq, PartialEq)]
pub struct DatabaseConfigSchemaValidation<'a> {
    parameter: Option<&'a DatabaseConfigParameterSchema>,
    status: DatabaseConfigSchemaValidationStatus,
    normalized_value: Option<Zeroizing<String>>,
}

impl fmt::Debug for DatabaseConfigSchemaValidation<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatabaseConfigSchemaValidation")
            .field(
                "canonical_key",
                &self.parameter.map(|parameter| parameter.canonical_key),
            )
            .field(
                "sensitivity",
                &self.parameter.map(|parameter| parameter.sensitivity),
            )
            .field("status", &self.status)
            .field(
                "normalized_value_bytes",
                &self.normalized_value.as_ref().map(|value| value.len()),
            )
            .finish()
    }
}

impl<'a> DatabaseConfigSchemaValidation<'a> {
    fn invalid(
        parameter: &'a DatabaseConfigParameterSchema,
        error: DatabaseConfigSchemaValueError,
    ) -> Self {
        Self {
            parameter: Some(parameter),
            status: DatabaseConfigSchemaValidationStatus::Invalid(error),
            normalized_value: None,
        }
    }

    pub const fn parameter(&self) -> Option<&DatabaseConfigParameterSchema> {
        self.parameter
    }

    pub const fn status(&self) -> DatabaseConfigSchemaValidationStatus {
        self.status
    }

    pub fn normalized_value(&self) -> Option<&str> {
        self.normalized_value.as_ref().map(|value| value.as_str())
    }

    pub const fn sensitivity(&self) -> Option<DatabaseConfigSchemaSensitivity> {
        match self.parameter {
            Some(parameter) => Some(parameter.sensitivity),
            None => None,
        }
    }
}

/// Reviewed schema packs. Every current pack is deliberately `Partial`; this
/// registry improves visibility and validation but never grants artifact-wide
/// mutation or deployment authority.
pub static DATABASE_CONFIG_SCHEMAS: &[DatabaseConfigSchema] = &[
    MYSQL_OPTION_FILE_8_0_SCHEMA,
    MYSQL_OPTION_FILE_8_4_SCHEMA,
    MARIADB_OPTION_FILE_10_11_SCHEMA,
    MARIADB_OPTION_FILE_11_4_SCHEMA,
    POSTGRESQL_MAIN_16_SCHEMA,
    POSTGRESQL_MAIN_17_SCHEMA,
    POSTGRESQL_MAIN_18_SCHEMA,
    TIDB_8_5_7_SERVER_TOML_SCHEMA,
    TIKV_8_5_7_TOML_SCHEMA,
    PD_8_5_7_TOML_SCHEMA,
    OPENGAUSS_5_0_0_STANDARD_MAIN_SCHEMA,
    OPENGAUSS_6_0_0_LITE_MAIN_SCHEMA,
    KINGBASE_ES_V8_6_7_12_MAIN_SCHEMA,
    KINGBASE_ES_V9_3_11_MAIN_SCHEMA,
    GOLDENDB_V6_1_03_10_PROXY_INI_SCHEMA,
    YASHANDB_23_5_4_100_YASDB_INI_SCHEMA,
    DM8_MAIN_INSPECT_ONLY_SCHEMA,
    DM8_SQL_LOG_INSPECT_ONLY_SCHEMA,
];

pub fn registered_database_config_schema_catalog()
-> Result<DatabaseConfigSchemaCatalog, DatabaseConfigSchemaCatalogError> {
    DatabaseConfigSchemaCatalog::new(DATABASE_CONFIG_SCHEMAS)
}

fn validate_catalog(
    schemas: &'static [DatabaseConfigSchema],
) -> Result<(), DatabaseConfigSchemaCatalogError> {
    for (schema_index, schema) in schemas.iter().enumerate() {
        if !valid_bounded_text(schema.display_label, MAX_DATABASE_CONFIG_SCHEMA_LABEL_BYTES)
            || !valid_bounded_text(schema.version_label, MAX_DATABASE_CONFIG_SCHEMA_LABEL_BYTES)
        {
            return Err(DatabaseConfigSchemaCatalogError::InvalidSchemaMetadata { schema_index });
        }
        if schema.binding.artifact_key.is_empty() {
            return Err(DatabaseConfigSchemaCatalogError::EmptyArtifactKey { schema_index });
        }
        let artifact = artifact_by_key(schema.binding.artifact_key)
            .ok_or(DatabaseConfigSchemaCatalogError::UnknownArtifact { schema_index })?;
        let case_insensitive_containers =
            artifact.dialect == DatabaseConfigDialect::MySqlOptionFile;
        if artifact.product != schema.binding.product {
            return Err(DatabaseConfigSchemaCatalogError::ArtifactProductMismatch { schema_index });
        }
        if artifact.component != schema.binding.component {
            return Err(
                DatabaseConfigSchemaCatalogError::ArtifactComponentMismatch { schema_index },
            );
        }
        if !schema.binding.versions.is_valid() {
            return Err(DatabaseConfigSchemaCatalogError::InvalidVersionSelector { schema_index });
        }
        if schema.binding.edition_key.is_some_and(|edition_key| {
            !valid_bounded_text(edition_key, MAX_DATABASE_CONFIG_SCHEMA_KEY_BYTES)
        }) {
            return Err(DatabaseConfigSchemaCatalogError::InvalidEditionKey { schema_index });
        }
        if schema.parameters.is_empty() {
            return Err(DatabaseConfigSchemaCatalogError::EmptyParameterSet { schema_index });
        }
        if schema.references.len() > MAX_DATABASE_CONFIG_SCHEMA_REFERENCES {
            return Err(DatabaseConfigSchemaCatalogError::TooManyReferences { schema_index });
        }
        for (reference_index, reference) in schema.references.iter().enumerate() {
            if !valid_reference(reference) {
                return Err(DatabaseConfigSchemaCatalogError::InvalidReference {
                    schema_index,
                    reference_index,
                });
            }
            if let Some(first_reference_index) = schema.references[..reference_index]
                .iter()
                .position(|candidate| candidate.id == reference.id)
            {
                return Err(DatabaseConfigSchemaCatalogError::DuplicateReference {
                    schema_index,
                    first_reference_index,
                    duplicate_reference_index: reference_index,
                });
            }
        }
        for (parameter_index, parameter) in schema.parameters.iter().enumerate() {
            if !valid_parameter(parameter) {
                return Err(DatabaseConfigSchemaCatalogError::InvalidParameter {
                    schema_index,
                    parameter_index,
                });
            }
            if validated_documented_default(parameter).is_err() {
                return Err(DatabaseConfigSchemaCatalogError::InvalidDocumentedDefault {
                    schema_index,
                    parameter_index,
                });
            }
            if !schema
                .references
                .iter()
                .any(|reference| reference.id == parameter.official_reference_id)
            {
                return Err(
                    DatabaseConfigSchemaCatalogError::UnresolvedParameterReference {
                        schema_index,
                        parameter_index,
                    },
                );
            }
            if let Some(first_parameter_index) = schema.parameters[..parameter_index]
                .iter()
                .position(|candidate| {
                    parameter_locators_overlap(case_insensitive_containers, candidate, parameter)
                })
            {
                return Err(DatabaseConfigSchemaCatalogError::DuplicateParameter {
                    schema_index,
                    first_parameter_index,
                    duplicate_parameter_index: parameter_index,
                });
            }
        }
    }

    for (second_schema_index, second) in schemas.iter().enumerate() {
        for (first_schema_index, first) in schemas[..second_schema_index].iter().enumerate() {
            if first.binding.product == second.binding.product
                && first.binding.component == second.binding.component
                && first.binding.artifact_key == second.binding.artifact_key
                && first.binding.edition_key == second.binding.edition_key
                && first.binding.versions.overlaps(second.binding.versions)
            {
                return Err(DatabaseConfigSchemaCatalogError::OverlappingSchemas {
                    first_schema_index,
                    second_schema_index,
                });
            }
        }
    }
    Ok(())
}

fn valid_bounded_text(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= maximum_bytes && !value.chars().any(char::is_control)
}

fn valid_reference(reference: &DatabaseConfigSchemaReference) -> bool {
    valid_bounded_text(reference.id, MAX_DATABASE_CONFIG_SCHEMA_REFERENCE_ID_BYTES)
        && valid_bounded_text(
            reference.title,
            MAX_DATABASE_CONFIG_SCHEMA_REFERENCE_TITLE_BYTES,
        )
        && valid_bounded_text(
            reference.url,
            MAX_DATABASE_CONFIG_SCHEMA_REFERENCE_URL_BYTES,
        )
        && Url::parse(reference.url).is_ok_and(|url| url.scheme() == "https" && url.has_host())
}

fn parameter_accepts_key(parameter: &DatabaseConfigParameterSchema, key: &str) -> bool {
    parameter.canonical_key == key || parameter.exact_aliases.contains(&key)
}

fn parameter_locators_overlap(
    case_insensitive_containers: bool,
    first: &DatabaseConfigParameterSchema,
    second: &DatabaseConfigParameterSchema,
) -> bool {
    container_paths_match(
        first.container_path,
        second.container_path,
        case_insensitive_containers,
    ) && (parameter_accepts_key(second, first.canonical_key)
        || first
            .exact_aliases
            .iter()
            .any(|alias| parameter_accepts_key(second, alias)))
}

fn container_paths_match(
    expected: Option<&str>,
    actual: Option<&str>,
    case_insensitive: bool,
) -> bool {
    match (expected, actual) {
        (None, None) => true,
        (Some(expected), Some(actual)) if case_insensitive => expected.eq_ignore_ascii_case(actual),
        _ => expected == actual,
    }
}

fn valid_parameter(parameter: &DatabaseConfigParameterSchema) -> bool {
    if parameter.container_path.is_some_and(|path| {
        path.is_empty()
            || path.len() > MAX_DATABASE_CONFIG_SCHEMA_KEY_BYTES
            || path.chars().any(char::is_control)
    }) || parameter.canonical_key.is_empty()
        || parameter.canonical_key.len() > MAX_DATABASE_CONFIG_SCHEMA_KEY_BYTES
        || parameter.canonical_key.chars().any(char::is_control)
        || parameter.exact_aliases.len() > MAX_DATABASE_CONFIG_SCHEMA_ALIASES_PER_PARAMETER
        || !parameter
            .exact_aliases
            .iter()
            .enumerate()
            .all(|(index, alias)| {
                valid_bounded_text(alias, MAX_DATABASE_CONFIG_SCHEMA_KEY_BYTES)
                    && *alias != parameter.canonical_key
                    && !parameter.exact_aliases[..index].contains(alias)
            })
        || parameter.risk_rationale.is_empty()
        || parameter.competition_rationale.is_empty()
        || parameter.official_reference_id.is_empty()
        || parameter.required_capability.is_some_and(|capability| {
            !valid_bounded_text(capability, MAX_DATABASE_CONFIG_SCHEMA_KEY_BYTES)
        })
    {
        return false;
    }
    match parameter.value_kind {
        DatabaseConfigSchemaValueKind::Boolean {
            true_literal,
            false_literal,
        } => {
            !true_literal.is_empty()
                && !false_literal.is_empty()
                && true_literal != false_literal
                && true_literal.len() <= MAX_DATABASE_CONFIG_SCHEMA_INPUT_BYTES
                && false_literal.len() <= MAX_DATABASE_CONFIG_SCHEMA_INPUT_BYTES
        }
        DatabaseConfigSchemaValueKind::Integer {
            minimum_inclusive,
            maximum_inclusive,
        } => minimum_inclusive <= maximum_inclusive,
        DatabaseConfigSchemaValueKind::Enumeration { values } => {
            !values.is_empty()
                && values.len() <= MAX_DATABASE_CONFIG_SCHEMA_ENUM_VALUES
                && values.iter().enumerate().all(|(index, value)| {
                    !value.is_empty()
                        && value.len() <= MAX_DATABASE_CONFIG_SCHEMA_INPUT_BYTES
                        && !values[..index].contains(value)
                })
        }
        DatabaseConfigSchemaValueKind::Text {
            minimum_bytes,
            maximum_bytes,
            ..
        } => {
            minimum_bytes <= maximum_bytes
                && maximum_bytes <= MAX_DATABASE_CONFIG_SCHEMA_INPUT_BYTES
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DatabaseConfigDocumentedDefaultError {
    SensitiveParameter,
    KindMismatch,
    InvalidValue,
}

fn validated_documented_default(
    parameter: &DatabaseConfigParameterSchema,
) -> Result<Option<Cow<'static, str>>, DatabaseConfigDocumentedDefaultError> {
    let Some(documented_default) = parameter.documented_default else {
        return Ok(None);
    };
    if matches!(
        parameter.sensitivity,
        DatabaseConfigSchemaSensitivity::MayContainSecrets
            | DatabaseConfigSchemaSensitivity::PrivateKeyReference
    ) {
        return Err(DatabaseConfigDocumentedDefaultError::SensitiveParameter);
    }

    let value = match (documented_default, parameter.value_kind) {
        (
            DatabaseConfigDocumentedDefault::Boolean(value),
            DatabaseConfigSchemaValueKind::Boolean {
                true_literal,
                false_literal,
            },
        ) => Cow::Borrowed(if value { true_literal } else { false_literal }),
        (
            DatabaseConfigDocumentedDefault::Integer(value),
            DatabaseConfigSchemaValueKind::Integer {
                minimum_inclusive,
                maximum_inclusive,
            },
        ) => {
            if value < minimum_inclusive || value > maximum_inclusive {
                return Err(DatabaseConfigDocumentedDefaultError::InvalidValue);
            }
            Cow::Owned(value.to_string())
        }
        (
            DatabaseConfigDocumentedDefault::Enumeration(value),
            DatabaseConfigSchemaValueKind::Enumeration { values },
        ) => {
            if !values.contains(&value) {
                return Err(DatabaseConfigDocumentedDefaultError::InvalidValue);
            }
            Cow::Borrowed(value)
        }
        (
            DatabaseConfigDocumentedDefault::Text(value),
            DatabaseConfigSchemaValueKind::Text {
                minimum_bytes,
                maximum_bytes,
                normalization,
            },
        ) => {
            if value.len() < minimum_bytes
                || value.len() > maximum_bytes
                || matches!(
                    normalization,
                    DatabaseConfigTextNormalization::TrimAsciiWhitespace
                ) && trim_ascii_whitespace(value) != value
            {
                return Err(DatabaseConfigDocumentedDefaultError::InvalidValue);
            }
            Cow::Borrowed(value)
        }
        _ => return Err(DatabaseConfigDocumentedDefaultError::KindMismatch),
    };

    if value.len() > MAX_DATABASE_CONFIG_SCHEMA_DOCUMENTED_DEFAULT_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(DatabaseConfigDocumentedDefaultError::InvalidValue);
    }
    Ok(Some(value))
}

fn normalize_value(
    kind: DatabaseConfigSchemaValueKind,
    raw_value: &str,
) -> Result<String, DatabaseConfigSchemaValueError> {
    match kind {
        DatabaseConfigSchemaValueKind::Boolean {
            true_literal,
            false_literal,
        } => {
            let value = trim_ascii_whitespace(raw_value);
            if value == true_literal {
                Ok(true_literal.to_owned())
            } else if value == false_literal {
                Ok(false_literal.to_owned())
            } else {
                Err(DatabaseConfigSchemaValueError::InvalidBoolean)
            }
        }
        DatabaseConfigSchemaValueKind::Integer {
            minimum_inclusive,
            maximum_inclusive,
        } => {
            let value = trim_ascii_whitespace(raw_value);
            let number = parse_strict_integer(value)
                .ok_or(DatabaseConfigSchemaValueError::InvalidInteger)?;
            if number < minimum_inclusive {
                Err(DatabaseConfigSchemaValueError::BelowMinimum)
            } else if number > maximum_inclusive {
                Err(DatabaseConfigSchemaValueError::AboveMaximum)
            } else {
                Ok(number.to_string())
            }
        }
        DatabaseConfigSchemaValueKind::Enumeration { values } => {
            let value = trim_ascii_whitespace(raw_value);
            values
                .iter()
                .find(|candidate| **candidate == value)
                .map(|canonical| (*canonical).to_owned())
                .ok_or(DatabaseConfigSchemaValueError::UnknownEnumerationValue)
        }
        DatabaseConfigSchemaValueKind::Text {
            minimum_bytes,
            maximum_bytes,
            normalization,
        } => {
            let value = match normalization {
                DatabaseConfigTextNormalization::Preserve => raw_value,
                DatabaseConfigTextNormalization::TrimAsciiWhitespace => {
                    trim_ascii_whitespace(raw_value)
                }
            };
            if value.len() < minimum_bytes {
                Err(DatabaseConfigSchemaValueError::TextTooShort)
            } else if value.len() > maximum_bytes {
                Err(DatabaseConfigSchemaValueError::TextTooLong)
            } else {
                Ok(value.to_owned())
            }
        }
    }
}

fn parse_strict_integer(value: &str) -> Option<i64> {
    let bytes = value.as_bytes();
    let digits = if bytes.first() == Some(&b'-') {
        &bytes[1..]
    } else {
        bytes
    };
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    value.parse().ok()
}

fn trim_ascii_whitespace(value: &str) -> &str {
    let bytes = value.as_bytes();
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |index| index + 1);
    &value[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_registry_is_valid_and_remains_partial() {
        let catalog = registered_database_config_schema_catalog().unwrap();

        assert_eq!(catalog.schemas().len(), 18);
        assert!(catalog.schemas().iter().all(|schema| {
            schema.completeness == DatabaseConfigSchemaCompleteness::Partial
                && !schema.parameters.is_empty()
                && !schema.references.is_empty()
        }));
        let documented_defaults = catalog
            .schemas()
            .iter()
            .flat_map(|schema| {
                schema.parameters.iter().filter_map(move |parameter| {
                    parameter.documented_default.map(|value| (schema, value))
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(documented_defaults.len(), 20);
        assert_eq!(
            documented_defaults
                .iter()
                .filter(|(schema, _)| schema.binding.artifact_key == "goldendb-proxy-ini")
                .count(),
            5
        );
        assert_eq!(
            documented_defaults
                .iter()
                .filter(|(schema, _)| schema.binding.artifact_key == "yashandb-yasdb-ini")
                .count(),
            15
        );
        assert!(documented_defaults.iter().all(|(schema, _)| {
            matches!(
                (
                    schema.binding.artifact_key,
                    schema.binding.versions,
                    schema.binding.edition_key,
                ),
                (
                    "goldendb-proxy-ini",
                    DatabaseConfigVersionSelector::Exact(DatabaseConfigVersion {
                        major: 6,
                        minor: 1,
                        patch: 3,
                        revision: 10,
                    }),
                    None,
                ) | (
                    "yashandb-yasdb-ini",
                    DatabaseConfigVersionSelector::Exact(DatabaseConfigVersion {
                        major: 23,
                        minor: 5,
                        patch: 4,
                        revision: 100,
                    }),
                    Some("official-doc-family-23.5.4.100"),
                )
            )
        }));
    }

    #[test]
    fn shentong_families_have_no_catalog_artifacts_or_schema_bindings() {
        let catalog = registered_database_config_schema_catalog().unwrap();
        let bound_products = catalog
            .schemas()
            .iter()
            .map(|schema| schema.binding.product)
            .collect::<std::collections::BTreeSet<_>>();
        let families = [
            DatabaseConfigProduct::ShenTongNative,
            DatabaseConfigProduct::ShenTongMpp,
            DatabaseConfigProduct::ShenTongOpenGauss,
        ];

        // Certification identifies a distinct product family; it does not bind
        // upstream openGauss configuration artifacts or schemas to that family:
        // https://opengauss.org/zh/certification/
        assert!(bound_products.contains(&DatabaseConfigProduct::OpenGauss));
        for product in families {
            assert!(
                crate::database_config::artifacts_for(product)
                    .next()
                    .is_none()
            );
            assert!(!bound_products.contains(&product));
        }
    }

    const FIXTURE_REFERENCES: &[DatabaseConfigSchemaReference] = &[
        DatabaseConfigSchemaReference {
            id: "test-fixture:integer",
            title: "Test-only bounded integer fixture",
            url: "https://example.invalid/lovelyres/schema-fixture/integer",
        },
        DatabaseConfigSchemaReference {
            id: "test-fixture:enum",
            title: "Test-only enumeration fixture",
            url: "https://example.invalid/lovelyres/schema-fixture/enum",
        },
        DatabaseConfigSchemaReference {
            id: "test-fixture:sensitive",
            title: "Test-only sensitive-value fixture",
            url: "https://example.invalid/lovelyres/schema-fixture/sensitive",
        },
    ];

    const FIXTURE_PARAMETERS: &[DatabaseConfigParameterSchema] = &[
        DatabaseConfigParameterSchema {
            container_path: Some("server"),
            canonical_key: "fixture_limit",
            exact_aliases: &[],
            value_kind: DatabaseConfigSchemaValueKind::Integer {
                minimum_inclusive: 1,
                maximum_inclusive: 10,
            },
            documented_default: None,
            scope: DatabaseConfigSchemaScope::Instance,
            sensitivity: DatabaseConfigSchemaSensitivity::Public,
            activation: DatabaseConfigSchemaActivation::Dynamic,
            risk: DatabaseConfigSchemaRisk::Low,
            risk_rationale: "Test-only bounded integer fixture.",
            competition_rationale: "Exercises normalized range validation only.",
            official_reference_id: "test-fixture:integer",
            required_capability: None,
        },
        DatabaseConfigParameterSchema {
            container_path: Some("client"),
            canonical_key: "fixture_limit",
            exact_aliases: &[],
            value_kind: DatabaseConfigSchemaValueKind::Integer {
                minimum_inclusive: 100,
                maximum_inclusive: 200,
            },
            documented_default: None,
            scope: DatabaseConfigSchemaScope::Session,
            sensitivity: DatabaseConfigSchemaSensitivity::Public,
            activation: DatabaseConfigSchemaActivation::VendorProcedure,
            risk: DatabaseConfigSchemaRisk::Informational,
            risk_rationale: "Test-only same-key, different-container fixture.",
            competition_rationale: "Exercises exact locator matching only.",
            official_reference_id: "test-fixture:integer",
            required_capability: None,
        },
        DatabaseConfigParameterSchema {
            container_path: Some("server"),
            canonical_key: "fixture-mode",
            exact_aliases: &["fixture_mode"],
            value_kind: DatabaseConfigSchemaValueKind::Enumeration {
                values: &["safe", "strict"],
            },
            documented_default: None,
            scope: DatabaseConfigSchemaScope::Component,
            sensitivity: DatabaseConfigSchemaSensitivity::Public,
            activation: DatabaseConfigSchemaActivation::Reload,
            risk: DatabaseConfigSchemaRisk::Medium,
            risk_rationale: "Test-only enumeration fixture.",
            competition_rationale: "Exercises exact canonical enum matching only.",
            official_reference_id: "test-fixture:enum",
            required_capability: None,
        },
        DatabaseConfigParameterSchema {
            container_path: Some("security"),
            canonical_key: "fixture_secret",
            exact_aliases: &[],
            value_kind: DatabaseConfigSchemaValueKind::Text {
                minimum_bytes: 1,
                maximum_bytes: 64,
                normalization: DatabaseConfigTextNormalization::Preserve,
            },
            documented_default: None,
            scope: DatabaseConfigSchemaScope::Instance,
            sensitivity: DatabaseConfigSchemaSensitivity::MayContainSecrets,
            activation: DatabaseConfigSchemaActivation::Restart,
            risk: DatabaseConfigSchemaRisk::High,
            risk_rationale: "Test-only sensitive-value fixture.",
            competition_rationale: "Exercises redacted diagnostics only.",
            official_reference_id: "test-fixture:sensitive",
            required_capability: Some("test.fixture.secret-provider"),
        },
    ];

    const FIXTURE_SCHEMAS: &[DatabaseConfigSchema] = &[DatabaseConfigSchema {
        display_label: "Test fixture schema",
        version_label: "8.x revision-aware test fixture",
        binding: DatabaseConfigSchemaBinding {
            product: DatabaseConfigProduct::MySql,
            versions: DatabaseConfigVersionSelector::HalfOpen {
                minimum_inclusive: DatabaseConfigVersion::new_with_revision(8, 0, 0, 12),
                maximum_exclusive: DatabaseConfigVersion::new(9, 0, 0),
            },
            edition_key: Some("test.fixture.standard"),
            component: DatabaseConfigComponent::Server,
            artifact_key: "mysql-option-file",
        },
        completeness: DatabaseConfigSchemaCompleteness::Partial,
        parameters: FIXTURE_PARAMETERS,
        references: FIXTURE_REFERENCES,
    }];

    fn target(version: DatabaseConfigVersion) -> DatabaseConfigSchemaTarget<'static> {
        DatabaseConfigSchemaTarget {
            product: DatabaseConfigProduct::MySql,
            version,
            edition_key: Some("test.fixture.standard"),
            component: DatabaseConfigComponent::Server,
            artifact_key: "mysql-option-file",
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
    fn typed_version_boundaries_are_inclusive_then_exclusive() {
        let catalog = DatabaseConfigSchemaCatalog::new(FIXTURE_SCHEMAS).unwrap();
        assert_eq!(catalog.schemas()[0].display_label, "Test fixture schema");
        assert_eq!(
            catalog.schemas()[0].version_label,
            "8.x revision-aware test fixture"
        );
        assert_eq!(DatabaseConfigVersion::new(8, 0, 0).revision(), 0);
        assert_eq!(
            catalog.lookup(target(DatabaseConfigVersion::new_with_revision(
                8, 0, 0, 11
            ))),
            Err(DatabaseConfigSchemaLookupError::VersionMismatch)
        );
        assert!(
            catalog
                .lookup(target(DatabaseConfigVersion::new_with_revision(
                    8, 0, 0, 12
                )))
                .is_ok()
        );
        assert!(
            catalog
                .lookup(target(DatabaseConfigVersion::new(8, 0, 1)))
                .is_ok()
        );
        assert_eq!(
            catalog.lookup(target(DatabaseConfigVersion::new(9, 0, 0))),
            Err(DatabaseConfigSchemaLookupError::VersionMismatch)
        );
    }

    #[test]
    fn newly_visible_artifacts_do_not_inherit_unrelated_schemas() {
        let catalog = registered_database_config_schema_catalog().unwrap();
        for (product, component, artifact_key) in [
            (
                DatabaseConfigProduct::MySql,
                DatabaseConfigComponent::ReplicationIdentity,
                "mysql-server-uuid",
            ),
            (
                DatabaseConfigProduct::MySql,
                DatabaseConfigComponent::PluginRegistry,
                "mysql-plugin-registry",
            ),
            (
                DatabaseConfigProduct::MySql,
                DatabaseConfigComponent::ComponentRegistry,
                "mysql-component-registry",
            ),
            (
                DatabaseConfigProduct::MariaDb,
                DatabaseConfigComponent::PluginRegistry,
                "mariadb-plugin-registry",
            ),
            (
                DatabaseConfigProduct::Dm,
                DatabaseConfigComponent::Server,
                "dm-thread",
            ),
            (
                DatabaseConfigProduct::GBase8s,
                DatabaseConfigComponent::Server,
                "gbase-8s-onconfig",
            ),
            (
                DatabaseConfigProduct::GBase8s,
                DatabaseConfigComponent::Client,
                "gbase-8s-sqlhosts",
            ),
            (
                DatabaseConfigProduct::GBase8s,
                DatabaseConfigComponent::ConnectionManager,
                "gbase-8s-connection-manager-config",
            ),
            (
                DatabaseConfigProduct::GBase8s,
                DatabaseConfigComponent::CommunicationSupport,
                "gbase-8s-communication-support-config",
            ),
            (
                DatabaseConfigProduct::GBase8s,
                DatabaseConfigComponent::Environment,
                "gbase-8s-shared-environment",
            ),
            (
                DatabaseConfigProduct::GBase8s,
                DatabaseConfigComponent::Environment,
                "gbase-8s-user-environment",
            ),
            (
                DatabaseConfigProduct::GBase8s,
                DatabaseConfigComponent::ArchiveChecker,
                "gbase-8s-archecker-template",
            ),
            (
                DatabaseConfigProduct::GBase8s,
                DatabaseConfigComponent::StorageManager,
                "gbase-8s-storage-manager-definitions",
            ),
            (
                DatabaseConfigProduct::GBase8s,
                DatabaseConfigComponent::HighPerformanceLoader,
                "gbase-8s-high-performance-loader-config",
            ),
            (
                DatabaseConfigProduct::GBase8s,
                DatabaseConfigComponent::MaxConnect,
                "gbase-8s-maxconnect-config",
            ),
            (
                DatabaseConfigProduct::GBase8a,
                DatabaseConfigComponent::Gcware,
                "gbase-8a-gcware-config",
            ),
            (
                DatabaseConfigProduct::GBase8a,
                DatabaseConfigComponent::GNode,
                "gbase-8a-gnode-cluster-common",
            ),
            (
                DatabaseConfigProduct::GBase8a,
                DatabaseConfigComponent::GCluster,
                "gbase-8a-gcluster-cluster-common",
            ),
            (
                DatabaseConfigProduct::SequoiaDb,
                DatabaseConfigComponent::SequoiaStandalone,
                "sequoiadb-standalone-config",
            ),
            (
                DatabaseConfigProduct::SequoiaDb,
                DatabaseConfigComponent::Deployment,
                "sequoiadb-quick-deploy-cluster",
            ),
            (
                DatabaseConfigProduct::SequoiaDb,
                DatabaseConfigComponent::SequoiaSqlMySql,
                "sequoiadb-quick-deploy-mysql",
            ),
            (
                DatabaseConfigProduct::SequoiaDb,
                DatabaseConfigComponent::SequoiaSqlMariaDb,
                "sequoiadb-quick-deploy-mariadb",
            ),
            (
                DatabaseConfigProduct::SequoiaDb,
                DatabaseConfigComponent::SequoiaSqlPostgreSql,
                "sequoiadb-quick-deploy-postgresql",
            ),
            (
                DatabaseConfigProduct::OceanBase,
                DatabaseConfigComponent::OceanBaseTenant,
                "oceanbase-tenant-variables",
            ),
            (
                DatabaseConfigProduct::OceanBase,
                DatabaseConfigComponent::BackupRecovery,
                "oceanbase-backup-archive-state",
            ),
        ] {
            assert_eq!(
                catalog.lookup(DatabaseConfigSchemaTarget {
                    product,
                    version: DatabaseConfigVersion::new(8, 8, 0),
                    edition_key: None,
                    component,
                    artifact_key,
                }),
                Err(DatabaseConfigSchemaLookupError::SchemaUnavailable),
                "{artifact_key} inherited an unrelated schema"
            );
        }
    }

    #[test]
    fn tidb_auxiliary_components_do_not_inherit_tidb_server_8_5_7_schema() {
        let catalog = registered_database_config_schema_catalog().unwrap();
        for (component, artifact_key) in [
            (DatabaseConfigComponent::TiFlash, "tidb-tiflash-toml"),
            (
                DatabaseConfigComponent::TiFlashLearner,
                "tidb-tiflash-learner-toml",
            ),
            (DatabaseConfigComponent::TiProxy, "tidb-tiproxy-toml"),
            (DatabaseConfigComponent::TiCdc, "tidb-ticdc-toml"),
            (
                DatabaseConfigComponent::TiCdcChangefeed,
                "tidb-ticdc-changefeed-toml",
            ),
            (
                DatabaseConfigComponent::TiDbLightning,
                "tidb-lightning-toml",
            ),
        ] {
            assert_eq!(
                catalog.lookup(DatabaseConfigSchemaTarget {
                    product: DatabaseConfigProduct::TiDb,
                    version: DatabaseConfigVersion::new_with_revision(8, 5, 7, 0),
                    edition_key: None,
                    component,
                    artifact_key,
                }),
                Err(DatabaseConfigSchemaLookupError::SchemaUnavailable),
                "{artifact_key} inherited the TiDB Server 8.5.7 schema"
            );
        }
    }

    #[test]
    fn duplicate_parameters_and_overlapping_bindings_are_rejected() {
        static DUPLICATE_PARAMETERS: &[DatabaseConfigParameterSchema] =
            &[FIXTURE_PARAMETERS[0], FIXTURE_PARAMETERS[0]];
        static DUPLICATE_SCHEMA: &[DatabaseConfigSchema] = &[DatabaseConfigSchema {
            parameters: DUPLICATE_PARAMETERS,
            ..FIXTURE_SCHEMAS[0]
        }];
        assert!(matches!(
            DatabaseConfigSchemaCatalog::new(DUPLICATE_SCHEMA),
            Err(DatabaseConfigSchemaCatalogError::DuplicateParameter { .. })
        ));

        static CASE_COLLISION_PARAMETERS: &[DatabaseConfigParameterSchema] = &[
            FIXTURE_PARAMETERS[0],
            DatabaseConfigParameterSchema {
                container_path: Some("SERVER"),
                ..FIXTURE_PARAMETERS[0]
            },
        ];
        static CASE_COLLISION_SCHEMA: &[DatabaseConfigSchema] = &[DatabaseConfigSchema {
            parameters: CASE_COLLISION_PARAMETERS,
            ..FIXTURE_SCHEMAS[0]
        }];
        assert!(matches!(
            DatabaseConfigSchemaCatalog::new(CASE_COLLISION_SCHEMA),
            Err(DatabaseConfigSchemaCatalogError::DuplicateParameter { .. })
        ));

        static ALIAS_COLLISION_PARAMETERS: &[DatabaseConfigParameterSchema] = &[
            FIXTURE_PARAMETERS[0],
            DatabaseConfigParameterSchema {
                canonical_key: "fixture-other",
                exact_aliases: &["fixture_limit"],
                ..FIXTURE_PARAMETERS[2]
            },
        ];
        static ALIAS_COLLISION_SCHEMA: &[DatabaseConfigSchema] = &[DatabaseConfigSchema {
            parameters: ALIAS_COLLISION_PARAMETERS,
            ..FIXTURE_SCHEMAS[0]
        }];
        assert!(matches!(
            DatabaseConfigSchemaCatalog::new(ALIAS_COLLISION_SCHEMA),
            Err(DatabaseConfigSchemaCatalogError::DuplicateParameter { .. })
        ));

        static SELF_COLLIDING_ALIAS_PARAMETERS: &[DatabaseConfigParameterSchema] =
            &[DatabaseConfigParameterSchema {
                exact_aliases: &["fixture_limit"],
                ..FIXTURE_PARAMETERS[0]
            }];
        static SELF_COLLIDING_ALIAS_SCHEMA: &[DatabaseConfigSchema] = &[DatabaseConfigSchema {
            parameters: SELF_COLLIDING_ALIAS_PARAMETERS,
            ..FIXTURE_SCHEMAS[0]
        }];
        assert!(matches!(
            DatabaseConfigSchemaCatalog::new(SELF_COLLIDING_ALIAS_SCHEMA),
            Err(DatabaseConfigSchemaCatalogError::InvalidParameter { .. })
        ));

        static INVALID_CAPABILITY_PARAMETERS: &[DatabaseConfigParameterSchema] =
            &[DatabaseConfigParameterSchema {
                required_capability: Some("test.fixture\ninvalid"),
                ..FIXTURE_PARAMETERS[0]
            }];
        static INVALID_CAPABILITY_SCHEMA: &[DatabaseConfigSchema] = &[DatabaseConfigSchema {
            parameters: INVALID_CAPABILITY_PARAMETERS,
            ..FIXTURE_SCHEMAS[0]
        }];
        assert!(matches!(
            DatabaseConfigSchemaCatalog::new(INVALID_CAPABILITY_SCHEMA),
            Err(DatabaseConfigSchemaCatalogError::InvalidParameter { .. })
        ));

        static OVERLAPPING: &[DatabaseConfigSchema] = &[
            FIXTURE_SCHEMAS[0],
            DatabaseConfigSchema {
                binding: DatabaseConfigSchemaBinding {
                    versions: DatabaseConfigVersionSelector::Exact(DatabaseConfigVersion::new(
                        8, 4, 0,
                    )),
                    ..FIXTURE_SCHEMAS[0].binding
                },
                ..FIXTURE_SCHEMAS[0]
            },
        ];
        assert!(matches!(
            DatabaseConfigSchemaCatalog::new(OVERLAPPING),
            Err(DatabaseConfigSchemaCatalogError::OverlappingSchemas { .. })
        ));

        static DISTINCT_EDITION: &[DatabaseConfigSchema] = &[
            FIXTURE_SCHEMAS[0],
            DatabaseConfigSchema {
                display_label: "Test fixture alternate edition schema",
                binding: DatabaseConfigSchemaBinding {
                    edition_key: Some("test.fixture.alternate"),
                    ..FIXTURE_SCHEMAS[0].binding
                },
                ..FIXTURE_SCHEMAS[0]
            },
        ];
        let distinct_editions = DatabaseConfigSchemaCatalog::new(DISTINCT_EDITION).unwrap();
        let mut alternate_target = target(DatabaseConfigVersion::new(8, 4, 0));
        alternate_target.edition_key = Some("test.fixture.alternate");
        assert_eq!(
            distinct_editions
                .lookup(alternate_target)
                .unwrap()
                .display_label,
            "Test fixture alternate edition schema"
        );

        static INVALID_EDITION_SCHEMA: &[DatabaseConfigSchema] = &[DatabaseConfigSchema {
            binding: DatabaseConfigSchemaBinding {
                edition_key: Some("test.fixture\ninvalid"),
                ..FIXTURE_SCHEMAS[0].binding
            },
            ..FIXTURE_SCHEMAS[0]
        }];
        assert!(matches!(
            DatabaseConfigSchemaCatalog::new(INVALID_EDITION_SCHEMA),
            Err(DatabaseConfigSchemaCatalogError::InvalidEditionKey { .. })
        ));
    }

    #[test]
    fn parameter_locators_are_exact_and_container_qualified() {
        let schema = DatabaseConfigSchemaCatalog::new(FIXTURE_SCHEMAS)
            .unwrap()
            .lookup(target(DatabaseConfigVersion::new(8, 1, 0)))
            .unwrap();

        let server =
            schema.validate_normalized_value(locator(Some("server"), "fixture_limit"), "7");
        assert_eq!(
            server.status(),
            DatabaseConfigSchemaValidationStatus::SyntaxValid
        );
        let client =
            schema.validate_normalized_value(locator(Some("client"), "fixture_limit"), "7");
        assert_eq!(
            client.status(),
            DatabaseConfigSchemaValidationStatus::Invalid(
                DatabaseConfigSchemaValueError::BelowMinimum
            )
        );

        let canonical = schema
            .parameter(locator(Some("server"), "fixture-mode"))
            .unwrap();
        let alias = schema
            .parameter(locator(Some("server"), "fixture_mode"))
            .unwrap();
        assert_eq!(canonical, alias);
        assert_eq!(alias.canonical_key, "fixture-mode");

        assert!(
            schema
                .parameter(locator(Some("SERVER"), "fixture_limit"))
                .is_some()
        );

        for locator in [
            locator(None, "fixture_limit"),
            locator(Some("server"), "Fixture_Limit"),
            locator(Some("server"), "fixture--mode"),
        ] {
            let result = schema.validate_normalized_value(locator, "7");
            assert_eq!(
                result.status(),
                DatabaseConfigSchemaValidationStatus::VisibleUnvalidated
            );
            assert!(result.parameter().is_none());
        }
    }

    #[test]
    fn documented_defaults_are_typed_canonical_and_not_inferred_from_enum_order() {
        static PARAMETERS: &[DatabaseConfigParameterSchema] = &[
            DatabaseConfigParameterSchema {
                canonical_key: "fixture_boolean_default",
                value_kind: DatabaseConfigSchemaValueKind::Boolean {
                    true_literal: "on",
                    false_literal: "off",
                },
                documented_default: Some(DatabaseConfigDocumentedDefault::Boolean(true)),
                ..FIXTURE_PARAMETERS[0]
            },
            DatabaseConfigParameterSchema {
                canonical_key: "fixture_integer_default",
                documented_default: Some(DatabaseConfigDocumentedDefault::Integer(7)),
                ..FIXTURE_PARAMETERS[0]
            },
            DatabaseConfigParameterSchema {
                documented_default: Some(DatabaseConfigDocumentedDefault::Enumeration("strict")),
                ..FIXTURE_PARAMETERS[2]
            },
            DatabaseConfigParameterSchema {
                canonical_key: "fixture_reordered_mode",
                exact_aliases: &[],
                value_kind: DatabaseConfigSchemaValueKind::Enumeration {
                    values: &["strict", "safe"],
                },
                documented_default: Some(DatabaseConfigDocumentedDefault::Enumeration("strict")),
                ..FIXTURE_PARAMETERS[2]
            },
            DatabaseConfigParameterSchema {
                container_path: Some("text"),
                canonical_key: "fixture_preserved_text",
                value_kind: DatabaseConfigSchemaValueKind::Text {
                    minimum_bytes: 0,
                    maximum_bytes: 64,
                    normalization: DatabaseConfigTextNormalization::Preserve,
                },
                documented_default: Some(DatabaseConfigDocumentedDefault::Text(" padded ")),
                sensitivity: DatabaseConfigSchemaSensitivity::Public,
                required_capability: None,
                ..FIXTURE_PARAMETERS[3]
            },
            DatabaseConfigParameterSchema {
                container_path: Some("text"),
                canonical_key: "fixture_trimmed_text",
                value_kind: DatabaseConfigSchemaValueKind::Text {
                    minimum_bytes: 0,
                    maximum_bytes: 64,
                    normalization: DatabaseConfigTextNormalization::TrimAsciiWhitespace,
                },
                documented_default: Some(DatabaseConfigDocumentedDefault::Text("trimmed")),
                sensitivity: DatabaseConfigSchemaSensitivity::OperationalMetadata,
                required_capability: None,
                ..FIXTURE_PARAMETERS[3]
            },
            DatabaseConfigParameterSchema {
                container_path: Some("text"),
                canonical_key: "fixture_empty_text",
                value_kind: DatabaseConfigSchemaValueKind::Text {
                    minimum_bytes: 0,
                    maximum_bytes: 64,
                    normalization: DatabaseConfigTextNormalization::Preserve,
                },
                documented_default: Some(DatabaseConfigDocumentedDefault::Text("")),
                sensitivity: DatabaseConfigSchemaSensitivity::Public,
                required_capability: None,
                ..FIXTURE_PARAMETERS[3]
            },
        ];
        static SCHEMAS: &[DatabaseConfigSchema] = &[DatabaseConfigSchema {
            parameters: PARAMETERS,
            ..FIXTURE_SCHEMAS[0]
        }];
        let schema = DatabaseConfigSchemaCatalog::new(SCHEMAS)
            .unwrap()
            .lookup(target(DatabaseConfigVersion::new(8, 1, 0)))
            .unwrap();

        for (container_path, key, expected) in [
            (Some("server"), "fixture_boolean_default", "on"),
            (Some("server"), "fixture_integer_default", "7"),
            (Some("server"), "fixture-mode", "strict"),
            (Some("server"), "fixture_mode", "strict"),
            (Some("SERVER"), "fixture_reordered_mode", "strict"),
            (Some("text"), "fixture_preserved_text", " padded "),
            (Some("text"), "fixture_trimmed_text", "trimmed"),
            (Some("text"), "fixture_empty_text", ""),
        ] {
            assert_eq!(
                schema
                    .parameter(locator(container_path, key))
                    .unwrap()
                    .documented_default_for_display()
                    .as_deref(),
                Some(expected),
                "{container_path:?}/{key}"
            );
        }
        assert_eq!(FIXTURE_PARAMETERS[2].documented_default, None);
        assert!(
            FIXTURE_PARAMETERS[2]
                .documented_default_for_display()
                .is_none()
        );
        let cloned = PARAMETERS[2].documented_default;
        assert_eq!(cloned, PARAMETERS[2].documented_default);
        assert!(!format!("{cloned:?}").contains("strict"));
    }

    #[test]
    fn invalid_or_sensitive_documented_defaults_fail_closed_without_value_output() {
        macro_rules! assert_invalid_default {
            ($parameter:expr) => {{
                static PARAMETERS: &[DatabaseConfigParameterSchema] = &[$parameter];
                static SCHEMAS: &[DatabaseConfigSchema] = &[DatabaseConfigSchema {
                    parameters: PARAMETERS,
                    ..FIXTURE_SCHEMAS[0]
                }];
                assert!(matches!(
                    DatabaseConfigSchemaCatalog::new(SCHEMAS),
                    Err(DatabaseConfigSchemaCatalogError::InvalidDocumentedDefault {
                        schema_index: 0,
                        parameter_index: 0,
                    })
                ));
                assert!(PARAMETERS[0].documented_default_for_display().is_none());
            }};
        }

        assert_invalid_default!(DatabaseConfigParameterSchema {
            documented_default: Some(DatabaseConfigDocumentedDefault::Enumeration("7")),
            ..FIXTURE_PARAMETERS[0]
        });
        assert_invalid_default!(DatabaseConfigParameterSchema {
            documented_default: Some(DatabaseConfigDocumentedDefault::Integer(11)),
            ..FIXTURE_PARAMETERS[0]
        });
        assert_invalid_default!(DatabaseConfigParameterSchema {
            documented_default: Some(DatabaseConfigDocumentedDefault::Enumeration("missing")),
            ..FIXTURE_PARAMETERS[2]
        });
        assert_invalid_default!(DatabaseConfigParameterSchema {
            value_kind: DatabaseConfigSchemaValueKind::Text {
                minimum_bytes: 0,
                maximum_bytes: 64,
                normalization: DatabaseConfigTextNormalization::TrimAsciiWhitespace,
            },
            documented_default: Some(DatabaseConfigDocumentedDefault::Text(" padded ")),
            sensitivity: DatabaseConfigSchemaSensitivity::Public,
            required_capability: None,
            ..FIXTURE_PARAMETERS[3]
        });
        assert_invalid_default!(DatabaseConfigParameterSchema {
            value_kind: DatabaseConfigSchemaValueKind::Text {
                minimum_bytes: 0,
                maximum_bytes: 64,
                normalization: DatabaseConfigTextNormalization::Preserve,
            },
            documented_default: Some(DatabaseConfigDocumentedDefault::Text("line\nbreak")),
            sensitivity: DatabaseConfigSchemaSensitivity::Public,
            required_capability: None,
            ..FIXTURE_PARAMETERS[3]
        });

        const SENTINEL: &str = "documented-default-must-not-leak";
        static SECRET_PARAMETERS: &[DatabaseConfigParameterSchema] =
            &[DatabaseConfigParameterSchema {
                documented_default: Some(DatabaseConfigDocumentedDefault::Text(SENTINEL)),
                ..FIXTURE_PARAMETERS[3]
            }];
        static SECRET_SCHEMAS: &[DatabaseConfigSchema] = &[DatabaseConfigSchema {
            parameters: SECRET_PARAMETERS,
            ..FIXTURE_SCHEMAS[0]
        }];
        let error = DatabaseConfigSchemaCatalog::new(SECRET_SCHEMAS).unwrap_err();
        assert_eq!(
            error,
            DatabaseConfigSchemaCatalogError::InvalidDocumentedDefault {
                schema_index: 0,
                parameter_index: 0,
            }
        );
        assert!(!format!("{error:?}").contains(SENTINEL));
        assert!(!format!("{:?}", SECRET_PARAMETERS[0]).contains(SENTINEL));
        assert!(
            SECRET_PARAMETERS[0]
                .documented_default_for_display()
                .is_none()
        );

        assert_invalid_default!(DatabaseConfigParameterSchema {
            sensitivity: DatabaseConfigSchemaSensitivity::PrivateKeyReference,
            documented_default: Some(DatabaseConfigDocumentedDefault::Text("private-key-path")),
            ..FIXTURE_PARAMETERS[3]
        });
    }

    #[test]
    fn documented_defaults_are_scoped_to_the_matched_version_pack() {
        static VERSION_ONE_PARAMETERS: &[DatabaseConfigParameterSchema] =
            &[DatabaseConfigParameterSchema {
                documented_default: Some(DatabaseConfigDocumentedDefault::Integer(3)),
                ..FIXTURE_PARAMETERS[0]
            }];
        static VERSION_TWO_PARAMETERS: &[DatabaseConfigParameterSchema] =
            &[DatabaseConfigParameterSchema {
                documented_default: Some(DatabaseConfigDocumentedDefault::Integer(7)),
                ..FIXTURE_PARAMETERS[0]
            }];
        static SCHEMAS: &[DatabaseConfigSchema] = &[
            DatabaseConfigSchema {
                binding: DatabaseConfigSchemaBinding {
                    versions: DatabaseConfigVersionSelector::Exact(DatabaseConfigVersion::new(
                        8, 1, 0,
                    )),
                    ..FIXTURE_SCHEMAS[0].binding
                },
                parameters: VERSION_ONE_PARAMETERS,
                ..FIXTURE_SCHEMAS[0]
            },
            DatabaseConfigSchema {
                display_label: "Test fixture second exact version schema",
                binding: DatabaseConfigSchemaBinding {
                    versions: DatabaseConfigVersionSelector::Exact(DatabaseConfigVersion::new(
                        8, 2, 0,
                    )),
                    ..FIXTURE_SCHEMAS[0].binding
                },
                parameters: VERSION_TWO_PARAMETERS,
                ..FIXTURE_SCHEMAS[0]
            },
        ];
        let catalog = DatabaseConfigSchemaCatalog::new(SCHEMAS).unwrap();

        for (version, expected) in [
            (DatabaseConfigVersion::new(8, 1, 0), "3"),
            (DatabaseConfigVersion::new(8, 2, 0), "7"),
        ] {
            let parameter = catalog
                .lookup(target(version))
                .unwrap()
                .parameter(locator(Some("server"), "fixture_limit"))
                .unwrap();
            assert_eq!(
                parameter.documented_default_for_display().as_deref(),
                Some(expected)
            );
        }
    }

    #[test]
    fn references_are_bounded_https_metadata_and_resolve_exactly_once() {
        static INVALID_URL_REFERENCES: &[DatabaseConfigSchemaReference] = &[
            DatabaseConfigSchemaReference {
                url: "http://example.invalid/not-official",
                ..FIXTURE_REFERENCES[0]
            },
            FIXTURE_REFERENCES[1],
            FIXTURE_REFERENCES[2],
        ];
        static INVALID_URL_SCHEMA: &[DatabaseConfigSchema] = &[DatabaseConfigSchema {
            references: INVALID_URL_REFERENCES,
            ..FIXTURE_SCHEMAS[0]
        }];
        assert!(matches!(
            DatabaseConfigSchemaCatalog::new(INVALID_URL_SCHEMA),
            Err(DatabaseConfigSchemaCatalogError::InvalidReference { .. })
        ));

        static DUPLICATE_REFERENCES: &[DatabaseConfigSchemaReference] = &[
            FIXTURE_REFERENCES[0],
            DatabaseConfigSchemaReference {
                title: "Second test fixture with a duplicate id",
                url: "https://example.invalid/lovelyres/schema-fixture/duplicate",
                ..FIXTURE_REFERENCES[0]
            },
            FIXTURE_REFERENCES[1],
            FIXTURE_REFERENCES[2],
        ];
        static DUPLICATE_REFERENCE_SCHEMA: &[DatabaseConfigSchema] = &[DatabaseConfigSchema {
            references: DUPLICATE_REFERENCES,
            ..FIXTURE_SCHEMAS[0]
        }];
        assert!(matches!(
            DatabaseConfigSchemaCatalog::new(DUPLICATE_REFERENCE_SCHEMA),
            Err(DatabaseConfigSchemaCatalogError::DuplicateReference { .. })
        ));

        static MISSING_REFERENCE_PARAMETERS: &[DatabaseConfigParameterSchema] =
            &[DatabaseConfigParameterSchema {
                official_reference_id: "test-fixture:missing",
                ..FIXTURE_PARAMETERS[0]
            }];
        static MISSING_REFERENCE_SCHEMA: &[DatabaseConfigSchema] = &[DatabaseConfigSchema {
            parameters: MISSING_REFERENCE_PARAMETERS,
            ..FIXTURE_SCHEMAS[0]
        }];
        assert!(matches!(
            DatabaseConfigSchemaCatalog::new(MISSING_REFERENCE_SCHEMA),
            Err(DatabaseConfigSchemaCatalogError::UnresolvedParameterReference { .. })
        ));
    }

    #[test]
    fn normalized_values_validate_without_sensitive_debug_output() {
        let schema = DatabaseConfigSchemaCatalog::new(FIXTURE_SCHEMAS)
            .unwrap()
            .lookup(target(DatabaseConfigVersion::new(8, 1, 0)))
            .unwrap();
        assert!(!schema.has_complete_artifact_coverage());

        let integer =
            schema.validate_normalized_value(locator(Some("server"), "fixture_limit"), " 007 ");
        assert_eq!(
            integer.status(),
            DatabaseConfigSchemaValidationStatus::SyntaxValid
        );
        assert_eq!(integer.normalized_value(), Some("7"));
        let too_large =
            schema.validate_normalized_value(locator(Some("server"), "fixture_limit"), "11");
        assert_eq!(
            too_large.status(),
            DatabaseConfigSchemaValidationStatus::Invalid(
                DatabaseConfigSchemaValueError::AboveMaximum
            )
        );

        let sensitive = schema
            .validate_normalized_value(locator(Some("security"), "fixture_secret"), "DontLeak");
        assert_eq!(sensitive.normalized_value(), None);
        assert_eq!(
            sensitive.status(),
            DatabaseConfigSchemaValidationStatus::SyntaxValid
        );
        assert_eq!(
            sensitive.sensitivity(),
            Some(DatabaseConfigSchemaSensitivity::MayContainSecrets)
        );
        assert_eq!(
            sensitive.parameter().unwrap().required_capability,
            Some("test.fixture.secret-provider")
        );
        let cloned = sensitive.clone();
        assert!(cloned.normalized_value().is_none());
        assert!(!format!("{sensitive:?}").contains("DontLeak"));
        assert!(!format!("{cloned:?}").contains("DontLeak"));
    }

    #[test]
    fn only_public_values_are_retained_after_syntax_validation() {
        static NON_PUBLIC_PARAMETERS: &[DatabaseConfigParameterSchema] = &[
            DatabaseConfigParameterSchema {
                container_path: Some("metadata"),
                canonical_key: "fixture_operational_metadata",
                sensitivity: DatabaseConfigSchemaSensitivity::OperationalMetadata,
                required_capability: None,
                ..FIXTURE_PARAMETERS[3]
            },
            DatabaseConfigParameterSchema {
                container_path: Some("credentials"),
                canonical_key: "fixture_may_contain_secrets",
                sensitivity: DatabaseConfigSchemaSensitivity::MayContainSecrets,
                required_capability: None,
                ..FIXTURE_PARAMETERS[3]
            },
            DatabaseConfigParameterSchema {
                container_path: Some("keys"),
                canonical_key: "fixture_private_key_reference",
                sensitivity: DatabaseConfigSchemaSensitivity::PrivateKeyReference,
                required_capability: None,
                ..FIXTURE_PARAMETERS[3]
            },
        ];
        static NON_PUBLIC_SCHEMA: &[DatabaseConfigSchema] = &[DatabaseConfigSchema {
            parameters: NON_PUBLIC_PARAMETERS,
            ..FIXTURE_SCHEMAS[0]
        }];
        let schema = DatabaseConfigSchemaCatalog::new(NON_PUBLIC_SCHEMA)
            .unwrap()
            .lookup(target(DatabaseConfigVersion::new(8, 1, 0)))
            .unwrap();

        for (container_path, key, sensitivity) in [
            (
                "metadata",
                "fixture_operational_metadata",
                DatabaseConfigSchemaSensitivity::OperationalMetadata,
            ),
            (
                "credentials",
                "fixture_may_contain_secrets",
                DatabaseConfigSchemaSensitivity::MayContainSecrets,
            ),
            (
                "keys",
                "fixture_private_key_reference",
                DatabaseConfigSchemaSensitivity::PrivateKeyReference,
            ),
        ] {
            let result =
                schema.validate_normalized_value(locator(Some(container_path), key), "NeverExpose");
            assert_eq!(
                result.status(),
                DatabaseConfigSchemaValidationStatus::SyntaxValid
            );
            assert_eq!(result.sensitivity(), Some(sensitivity));
            assert!(result.normalized_value().is_none());
            assert!(!format!("{result:?}").contains("NeverExpose"));
        }
    }

    #[test]
    fn unknown_keys_stay_visible_unvalidated_and_family_mismatches_fail_closed() {
        let catalog = DatabaseConfigSchemaCatalog::new(FIXTURE_SCHEMAS).unwrap();
        let schema = catalog
            .lookup(target(DatabaseConfigVersion::new(8, 0, 1)))
            .unwrap();
        let unknown = schema.validate_normalized_value(
            locator(Some("server"), "fixture_unknown"),
            "visible source value",
        );
        assert_eq!(
            unknown.status(),
            DatabaseConfigSchemaValidationStatus::VisibleUnvalidated
        );
        assert!(unknown.parameter().is_none());
        assert!(unknown.normalized_value().is_none());

        let mut wrong_product = target(DatabaseConfigVersion::new(8, 0, 1));
        wrong_product.product = DatabaseConfigProduct::MariaDb;
        assert_eq!(
            catalog.lookup(wrong_product),
            Err(DatabaseConfigSchemaLookupError::ProductMismatch)
        );

        let mut wrong_component = target(DatabaseConfigVersion::new(8, 0, 1));
        wrong_component.component = DatabaseConfigComponent::Proxy;
        assert_eq!(
            catalog.lookup(wrong_component),
            Err(DatabaseConfigSchemaLookupError::ComponentMismatch)
        );

        let mut missing_edition = target(DatabaseConfigVersion::new(8, 0, 1));
        missing_edition.edition_key = None;
        assert_eq!(
            catalog.lookup(missing_edition),
            Err(DatabaseConfigSchemaLookupError::EditionMismatch)
        );

        let mut wrong_edition = target(DatabaseConfigVersion::new(8, 0, 1));
        wrong_edition.edition_key = Some("test.fixture.alternate");
        assert_eq!(
            catalog.lookup(wrong_edition),
            Err(DatabaseConfigSchemaLookupError::EditionMismatch)
        );

        let mut invalid_edition = target(DatabaseConfigVersion::new(8, 0, 1));
        invalid_edition.edition_key = Some("test.fixture\ninvalid");
        assert_eq!(
            catalog.lookup(invalid_edition),
            Err(DatabaseConfigSchemaLookupError::InvalidEditionKey)
        );

        let mut unknown_artifact = target(DatabaseConfigVersion::new(8, 0, 1));
        unknown_artifact.artifact_key = "test-fixture-missing-artifact";
        assert_eq!(
            catalog.lookup(unknown_artifact),
            Err(DatabaseConfigSchemaLookupError::ArtifactUnknown)
        );
    }
}
