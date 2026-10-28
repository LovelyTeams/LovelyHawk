//! One row model over every visual configuration parser.
//!
//! Nginx, Apache httpd, the line-based database dialects and the structured
//! (JSON, YAML, XML and vendor) dialects each have their own document type.
//! This module puts them behind one document and one row so that read-only
//! policy, schema meaning, redaction and search are decided once, here, and
//! not again by whichever page shows the rows.
//!
//! A database file is always bound to the catalogued artifact it was opened
//! as. The artifact decides the parser and whether a local draft may change
//! at all; choosing a schema adds meaning to rows but never unlocks editing,
//! never validates a value against a target, and never fills in defaults.

use std::collections::HashMap;
use std::fmt;
use std::path::Path;

use crate::apache_visual::{
    ApacheVisualDocument, ApacheVisualNodeId, ApacheVisualNodeKind, ApacheVisualRow,
};
use crate::configuration_goal::{
    DatabaseParameterAssignment, DatabaseParameterGoalDraft, DatabaseParameterGoalDraftError,
    validate_database_parameter_goal_value,
};
use crate::database_config::{
    DATABASE_CONFIG_ARTIFACTS, DatabaseConfigArtifactDefinition, DatabaseConfigDialect,
    DatabaseConfigEditPolicy, DatabaseConfigProduct,
};
use crate::database_config_schema::{
    DATABASE_CONFIG_SCHEMAS, DatabaseConfigParameterLocator, DatabaseConfigParameterSchema,
    DatabaseConfigSchema, DatabaseConfigSchemaActivation, DatabaseConfigSchemaRisk,
    DatabaseConfigSchemaScope, DatabaseConfigSchemaSensitivity, DatabaseConfigSchemaValueKind,
    DatabaseConfigTextNormalization,
};
use crate::line_config_visual::{
    LineConfigDialect, LineConfigNodeId, LineConfigNodeKind, LineConfigRow,
    LineConfigVisualDocument,
};
use crate::nginx_visual::{
    NginxVisualDocument, NginxVisualNodeId, NginxVisualNodeKind, NginxVisualRow,
};
use crate::structured_config_visual::{
    StructuredConfigDialect, StructuredConfigNodeId, StructuredConfigNodeKind, StructuredConfigRow,
    StructuredConfigVisualDocument,
};
use crate::{CoreError, CoreResult};

/// A search query longer than this is cut to it before matching.
pub const MAX_VISUAL_SEARCH_CHARS: usize = 128;

/// What a row shows in place of a value the schema marks as secret.
pub const REDACTED_SCHEMA_VALUE: &str = "[sensitive value redacted]";

/// Which syntax a document is in and, for a database file, which catalogued
/// artifact it was opened as.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VisualDocumentKind {
    Nginx,
    Apache,
    Database(&'static DatabaseConfigArtifactDefinition),
}

/// Why a database file may be read and saved as a copy but never changed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VisualReadOnlyReason {
    /// The artifact needs the matching vendor schema; a static schema does
    /// not unlock structural changes.
    VendorSchemaRequired,
    /// The server or a vendor tool writes this file.
    Generated,
}

impl VisualDocumentKind {
    pub const fn allows_lossless_local_draft(self) -> bool {
        match self {
            Self::Nginx | Self::Apache => true,
            Self::Database(artifact) => artifact.allows_lossless_local_draft(),
        }
    }

    pub const fn read_only_reason(self) -> Option<VisualReadOnlyReason> {
        match self {
            Self::Database(artifact) if !artifact.allows_lossless_local_draft() => {
                Some(match artifact.edit_policy {
                    DatabaseConfigEditPolicy::VendorSchemaRequired => {
                        VisualReadOnlyReason::VendorSchemaRequired
                    }
                    _ => VisualReadOnlyReason::Generated,
                })
            }
            Self::Nginx | Self::Apache | Self::Database(_) => None,
        }
    }

    /// Whether the syntax has containers (blocks, sections, groups, tables).
    pub const fn supports_containers(self) -> bool {
        match self {
            Self::Nginx | Self::Apache => true,
            Self::Database(artifact) => matches!(
                artifact.dialect,
                DatabaseConfigDialect::MySqlOptionFile
                    | DatabaseConfigDialect::Ini
                    | DatabaseConfigDialect::Toml
            ),
        }
    }

    /// Whether a container may hold another container.
    pub const fn supports_nested_containers(self) -> bool {
        match self {
            Self::Nginx | Self::Apache => true,
            Self::Database(artifact) => matches!(artifact.dialect, DatabaseConfigDialect::Toml),
        }
    }

    /// The file this kind of document is, as a list names it.
    pub fn artifact_label(self) -> &'static str {
        match self {
            Self::Nginx => "nginx.conf",
            Self::Apache => "httpd.conf / apache2.conf",
            Self::Database(artifact) => database_artifact_display_label(artifact),
        }
    }

    /// Whether a statement is a whole record (pg_hba, pg_ident) rather than a
    /// name and a value.
    pub const fn statements_are_records(self) -> bool {
        match self {
            Self::Database(artifact) => matches!(
                artifact.dialect,
                DatabaseConfigDialect::PgHbaConf | DatabaseConfigDialect::PgIdentConf
            ),
            Self::Nginx | Self::Apache => false,
        }
    }
}

/// The four shapes a row takes, whatever the syntax.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VisualNodeKind {
    Statement,
    Container,
    Comment,
    Opaque,
}

impl VisualNodeKind {
    /// The kind's own word, for search; pages label kinds per product.
    pub const fn search_key(self) -> &'static str {
        match self {
            Self::Statement => "statement",
            Self::Container => "container",
            Self::Comment => "comment",
            Self::Opaque => "opaque",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Statement => "语句",
            Self::Container => "块",
            Self::Comment => "注释",
            Self::Opaque => "原文",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum VisualNodeId {
    Nginx(NginxVisualNodeId),
    Apache(ApacheVisualNodeId),
    Line(LineConfigNodeId),
    Structured(StructuredConfigNodeId),
}

impl VisualNodeId {
    pub const fn get(self) -> u128 {
        match self {
            Self::Nginx(id) => id.get(),
            Self::Apache(id) => id.get(),
            Self::Line(id) => id.get(),
            Self::Structured(id) => id.get(),
        }
    }
}

/// How a row relates to the selected schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseParameterMatch {
    /// Not an option row, or no schema applies.
    NotApplicable,
    /// An option the selected schema does not describe; shown as written.
    VisibleUnvalidated,
    /// An option the selected schema describes, by its exact place and name.
    Matched(&'static DatabaseConfigParameterSchema),
}

/// How much a row's meaning rests on: reviewed catalogue guidance (never a
/// check against the target), or its syntax alone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VisualMeaningLevel {
    CatalogGuidance,
    SyntaxOnly,
}

#[derive(Clone)]
pub struct VisualRow {
    id: VisualNodeId,
    parent: Option<VisualNodeId>,
    depth: usize,
    kind: VisualNodeKind,
    name: Option<String>,
    arguments: Option<String>,
    preview: String,
    child_count: usize,
    truncated: bool,
    allows_local_draft_mutation: bool,
    sensitive: bool,
    database_parameter: DatabaseParameterMatch,
}

impl fmt::Debug for VisualRow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VisualRow")
            .field("id", &self.id)
            .field("parent", &self.parent)
            .field("depth", &self.depth)
            .field("kind", &self.kind)
            .field("name_present", &self.name.is_some())
            .field("arguments_present", &self.arguments.is_some())
            .field("preview_bytes", &self.preview.len())
            .field("child_count", &self.child_count)
            .field("truncated", &self.truncated)
            .field(
                "allows_local_draft_mutation",
                &self.allows_local_draft_mutation,
            )
            .field("sensitive", &self.sensitive)
            .field("database_parameter", &self.database_parameter)
            .finish()
    }
}

impl VisualRow {
    pub const fn id(&self) -> VisualNodeId {
        self.id
    }

    pub const fn parent(&self) -> Option<VisualNodeId> {
        self.parent
    }

    pub const fn depth(&self) -> usize {
        self.depth
    }

    pub const fn kind(&self) -> VisualNodeKind {
        self.kind
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn arguments(&self) -> Option<&str> {
        self.arguments.as_deref()
    }

    pub fn preview(&self) -> &str {
        &self.preview
    }

    pub const fn child_count(&self) -> usize {
        self.child_count
    }

    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    pub const fn allows_local_draft_mutation(&self) -> bool {
        self.allows_local_draft_mutation
    }

    pub const fn sensitive(&self) -> bool {
        self.sensitive
    }

    pub const fn database_parameter(&self) -> DatabaseParameterMatch {
        self.database_parameter
    }

    pub const fn meaning_level(&self) -> VisualMeaningLevel {
        match self.database_parameter {
            DatabaseParameterMatch::Matched(_) => VisualMeaningLevel::CatalogGuidance,
            DatabaseParameterMatch::NotApplicable | DatabaseParameterMatch::VisibleUnvalidated => {
                VisualMeaningLevel::SyntaxOnly
            }
        }
    }

    fn with_local_draft_permission(mut self, allows_lossless_local_draft: bool) -> Self {
        self.allows_local_draft_mutation &= allows_lossless_local_draft;
        self
    }
}

impl From<NginxVisualRow> for VisualRow {
    fn from(row: NginxVisualRow) -> Self {
        let kind = match row.kind() {
            NginxVisualNodeKind::Directive => VisualNodeKind::Statement,
            NginxVisualNodeKind::Block => VisualNodeKind::Container,
            NginxVisualNodeKind::Comment => VisualNodeKind::Comment,
            NginxVisualNodeKind::Opaque => VisualNodeKind::Opaque,
        };
        Self {
            id: VisualNodeId::Nginx(row.id()),
            parent: row.parent().map(VisualNodeId::Nginx),
            depth: row.depth(),
            kind,
            name: row.name().map(ToOwned::to_owned),
            arguments: row.arguments().map(ToOwned::to_owned),
            preview: row.preview().to_owned(),
            child_count: row.child_count(),
            truncated: row.truncated(),
            allows_local_draft_mutation: row.editable(),
            sensitive: row.sensitive(),
            database_parameter: DatabaseParameterMatch::NotApplicable,
        }
    }
}

impl From<ApacheVisualRow> for VisualRow {
    fn from(row: ApacheVisualRow) -> Self {
        let kind = match row.kind() {
            ApacheVisualNodeKind::Directive => VisualNodeKind::Statement,
            ApacheVisualNodeKind::Section => VisualNodeKind::Container,
            ApacheVisualNodeKind::Comment => VisualNodeKind::Comment,
            ApacheVisualNodeKind::Opaque => VisualNodeKind::Opaque,
        };
        Self {
            id: VisualNodeId::Apache(row.id()),
            parent: row.parent().map(VisualNodeId::Apache),
            depth: row.depth(),
            kind,
            name: row.name().map(ToOwned::to_owned),
            arguments: row.arguments().map(ToOwned::to_owned),
            preview: row.preview().to_owned(),
            child_count: row.child_count(),
            truncated: row.truncated(),
            allows_local_draft_mutation: row.editable(),
            sensitive: row.sensitive(),
            database_parameter: DatabaseParameterMatch::NotApplicable,
        }
    }
}

impl From<StructuredConfigRow> for VisualRow {
    fn from(row: StructuredConfigRow) -> Self {
        let kind = match row.kind() {
            StructuredConfigNodeKind::Document
            | StructuredConfigNodeKind::Object
            | StructuredConfigNodeKind::Array
            | StructuredConfigNodeKind::Member => VisualNodeKind::Container,
            StructuredConfigNodeKind::Scalar => VisualNodeKind::Statement,
            StructuredConfigNodeKind::Comment => VisualNodeKind::Comment,
            StructuredConfigNodeKind::Opaque => VisualNodeKind::Opaque,
        };
        Self {
            id: VisualNodeId::Structured(row.id()),
            parent: row.parent().map(VisualNodeId::Structured),
            depth: row.depth(),
            kind,
            name: row.name().map(ToOwned::to_owned),
            arguments: row.value().map(ToOwned::to_owned),
            preview: row.preview().to_owned(),
            child_count: row.child_count(),
            truncated: row.truncated(),
            // Structured documents are read and saved as copies only.
            allows_local_draft_mutation: false,
            sensitive: row.sensitive(),
            database_parameter: DatabaseParameterMatch::NotApplicable,
        }
    }
}

fn visual_row_from_line(
    row: LineConfigRow,
    database_parameter: DatabaseParameterMatch,
) -> VisualRow {
    let kind = match row.kind() {
        LineConfigNodeKind::Section | LineConfigNodeKind::Table => VisualNodeKind::Container,
        LineConfigNodeKind::Entry | LineConfigNodeKind::Include | LineConfigNodeKind::Record => {
            VisualNodeKind::Statement
        }
        LineConfigNodeKind::Comment => VisualNodeKind::Comment,
        LineConfigNodeKind::Opaque => VisualNodeKind::Opaque,
    };
    // A value the schema marks as secret is redacted here, before any page,
    // search or copy can see it, even when the syntax did not flag it.
    let schema_sensitive = matches!(
        database_parameter,
        DatabaseParameterMatch::Matched(DatabaseConfigParameterSchema {
            sensitivity: DatabaseConfigSchemaSensitivity::MayContainSecrets
                | DatabaseConfigSchemaSensitivity::PrivateKeyReference,
            ..
        })
    );
    if schema_sensitive {
        return VisualRow {
            id: VisualNodeId::Line(row.id()),
            parent: row.parent().map(VisualNodeId::Line),
            depth: row.depth(),
            kind,
            name: row.name().map(ToOwned::to_owned),
            arguments: None,
            preview: REDACTED_SCHEMA_VALUE.to_owned(),
            child_count: row.child_count(),
            truncated: false,
            allows_local_draft_mutation: false,
            sensitive: true,
            database_parameter,
        };
    }
    VisualRow {
        id: VisualNodeId::Line(row.id()),
        parent: row.parent().map(VisualNodeId::Line),
        depth: row.depth(),
        kind,
        name: row.name().map(ToOwned::to_owned),
        arguments: row.value().map(ToOwned::to_owned),
        preview: row.preview().to_owned(),
        child_count: row.child_count(),
        truncated: row.truncated(),
        allows_local_draft_mutation: row.editable(),
        sensitive: row.sensitive(),
        database_parameter,
    }
}

/// Which parser a catalogued database file is read with.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseVisualParser {
    Line(LineConfigDialect),
    Structured(StructuredConfigDialect),
}

fn line_dialect(artifact: &DatabaseConfigArtifactDefinition) -> Option<LineConfigDialect> {
    if !artifact.has_source_backed_visual_parser() {
        return None;
    }
    match artifact.dialect {
        DatabaseConfigDialect::MySqlOptionFile => Some(LineConfigDialect::MySqlOption),
        DatabaseConfigDialect::PostgreSqlConf | DatabaseConfigDialect::PostgreSqlAutoConf => {
            Some(LineConfigDialect::PostgresConf)
        }
        DatabaseConfigDialect::PgHbaConf => Some(LineConfigDialect::PgHba),
        DatabaseConfigDialect::PgIdentConf => Some(LineConfigDialect::PgIdent),
        DatabaseConfigDialect::Ini => Some(LineConfigDialect::Ini),
        DatabaseConfigDialect::Toml => Some(LineConfigDialect::Toml),
        DatabaseConfigDialect::JavaProperties => Some(LineConfigDialect::JavaProperties),
        DatabaseConfigDialect::KeyValue => Some(LineConfigDialect::FlatKeyValue),
        DatabaseConfigDialect::VendorText => Some(LineConfigDialect::Whitespace),
        DatabaseConfigDialect::MySqlPersistedVariablesJson
        | DatabaseConfigDialect::Yaml
        | DatabaseConfigDialect::Json
        | DatabaseConfigDialect::Xml
        | DatabaseConfigDialect::GcwareConf
        | DatabaseConfigDialect::SequoiaQuickDeployClusterCsv
        | DatabaseConfigDialect::SequoiaQuickDeploySqlInstanceCsv
        | DatabaseConfigDialect::VendorBinary
        | DatabaseConfigDialect::RuntimeSql
        | DatabaseConfigDialect::CloudApi
        | DatabaseConfigDialect::VendorSchema => None,
    }
}

fn structured_dialect(
    artifact: &DatabaseConfigArtifactDefinition,
) -> Option<StructuredConfigDialect> {
    if !artifact.has_source_backed_visual_parser() {
        return None;
    }
    match artifact.dialect {
        DatabaseConfigDialect::MySqlPersistedVariablesJson | DatabaseConfigDialect::Json => {
            Some(StructuredConfigDialect::Json)
        }
        DatabaseConfigDialect::Yaml => Some(StructuredConfigDialect::Yaml),
        DatabaseConfigDialect::Xml => Some(StructuredConfigDialect::Xml),
        DatabaseConfigDialect::GcwareConf => Some(StructuredConfigDialect::Gcware),
        DatabaseConfigDialect::SequoiaQuickDeployClusterCsv => {
            Some(StructuredConfigDialect::SequoiaQuickDeployClusterCsv)
        }
        DatabaseConfigDialect::SequoiaQuickDeploySqlInstanceCsv => {
            Some(StructuredConfigDialect::SequoiaQuickDeploySqlInstanceCsv)
        }
        DatabaseConfigDialect::MySqlOptionFile
        | DatabaseConfigDialect::PostgreSqlConf
        | DatabaseConfigDialect::PgHbaConf
        | DatabaseConfigDialect::PgIdentConf
        | DatabaseConfigDialect::PostgreSqlAutoConf
        | DatabaseConfigDialect::Ini
        | DatabaseConfigDialect::Toml
        | DatabaseConfigDialect::JavaProperties
        | DatabaseConfigDialect::KeyValue
        | DatabaseConfigDialect::VendorText
        | DatabaseConfigDialect::VendorBinary
        | DatabaseConfigDialect::RuntimeSql
        | DatabaseConfigDialect::CloudApi
        | DatabaseConfigDialect::VendorSchema => None,
    }
}

/// The parser for a catalogued database file, or `None` when the file has no
/// source-backed parser here (binary, runtime-only, cloud and the like).
pub fn database_visual_parser(
    artifact: &DatabaseConfigArtifactDefinition,
) -> Option<DatabaseVisualParser> {
    line_dialect(artifact)
        .map(DatabaseVisualParser::Line)
        .or_else(|| structured_dialect(artifact).map(DatabaseVisualParser::Structured))
}

/// The catalogued files of a product that open in the visual editor.
pub fn database_visual_artifacts(
    product: DatabaseConfigProduct,
) -> impl Iterator<Item = &'static DatabaseConfigArtifactDefinition> {
    DATABASE_CONFIG_ARTIFACTS.iter().filter(move |artifact| {
        artifact.product == product && database_visual_parser(artifact).is_some()
    })
}

/// Whether a product has any file the visual editor can open.
pub fn database_product_has_visual_files(product: DatabaseConfigProduct) -> bool {
    database_visual_artifacts(product).next().is_some()
}

/// The file a product's list starts with.
pub fn first_database_visual_artifact(
    product: DatabaseConfigProduct,
) -> Option<&'static DatabaseConfigArtifactDefinition> {
    database_visual_artifacts(product).next()
}

/// A catalogued database file by its exact key.
pub fn database_artifact_by_key(key: &str) -> Option<&'static DatabaseConfigArtifactDefinition> {
    DATABASE_CONFIG_ARTIFACTS
        .iter()
        .find(|artifact| artifact.key == key)
}

/// The name a file goes by in a list, where the catalogue's own file name
/// would not tell two components apart.
pub fn database_artifact_display_label(
    artifact: &DatabaseConfigArtifactDefinition,
) -> &'static str {
    match artifact.key {
        "gbase-8a-gnode-cluster-common" => "cluster_common.cnf · GNode",
        "gbase-8a-gcluster-cluster-common" => "cluster_common.cnf · GCluster",
        _ => artifact.default_file_name.unwrap_or(artifact.key),
    }
}

/// What a new local draft of a file starts with: a short reviewed starting
/// point for the files that have one, otherwise a comment asking for the
/// target's own file, otherwise nothing.
pub fn database_starter_contents(artifact: &DatabaseConfigArtifactDefinition) -> &'static str {
    match (artifact.product, artifact.dialect) {
        (DatabaseConfigProduct::MySql, DatabaseConfigDialect::MySqlOptionFile)
            if artifact.key == "mysql-server-uuid" =>
        {
            ""
        }
        (
            DatabaseConfigProduct::MySql | DatabaseConfigProduct::MariaDb,
            DatabaseConfigDialect::MySqlOptionFile,
        ) => {
            "# LovelyHawk MySQL/MariaDB 应急响应比赛起始配置；部署前必须按所选产品与精确版本使用官方工具复核。\n[mysqld]\nbind-address = 127.0.0.1\nport = 3306\nlocal-infile = 0\nskip-symbolic-links\n\n[client]\nport = 3306\n"
        }
        // No line here may name a credential, even an algorithm such as
        // password_encryption: such a line is hidden, and with it the whole
        // text of a fresh draft.
        (DatabaseConfigProduct::PostgreSql, DatabaseConfigDialect::PostgreSqlConf) => {
            "# LovelyHawk 应急响应比赛起始配置；部署前以目标产品/版本校验。\nlisten_addresses = 'localhost'\nport = 5432\nlogging_collector = on\nlog_connections = on\nlog_disconnections = on\n"
        }
        (DatabaseConfigProduct::PostgreSql, DatabaseConfigDialect::PgHbaConf) => {
            "# TYPE  DATABASE  USER  ADDRESS  METHOD\nlocal   all       all            peer\nhost    all       all   127.0.0.1/32   scram-sha-256\nhost    all       all   ::1/128        scram-sha-256\n"
        }
        (DatabaseConfigProduct::PostgreSql, DatabaseConfigDialect::PgIdentConf) => {
            "# MAPNAME  SYSTEM-USERNAME  DATABASE-USERNAME\n"
        }
        (_, DatabaseConfigDialect::MySqlOptionFile) => {
            "# 当前文件没有经审查的产品级起始内容；请导入目标实例原文件，本页不会依据 MySQL 兼容语法猜测参数或端口。\n"
        }
        (
            _,
            DatabaseConfigDialect::PostgreSqlConf
            | DatabaseConfigDialect::PgHbaConf
            | DatabaseConfigDialect::PgIdentConf,
        ) => {
            "# 当前文件没有经审查的产品级起始内容；请导入目标实例原文件，本页不会依据 PostgreSQL 兼容语法猜测参数或端口。\n"
        }
        (DatabaseConfigProduct::Dm, DatabaseConfigDialect::Ini) if artifact.key == "dm-main" => {
            "# LovelyHawk DM 本地检查起始配置；仅供检查，参数动态级别与范围必须由目标 DM 精确版本回读，不得据此直接应用。\nINSTANCE_NAME = DMSERVER\nPORT_NUM = 5236\n"
        }
        (_, DatabaseConfigDialect::Ini) => {
            "# LovelyHawk INI 起始配置；按当前组件和目标版本添加分组与参数。\n"
        }
        (DatabaseConfigProduct::TiDb, DatabaseConfigDialect::Toml)
            if matches!(
                artifact.key,
                "tidb-tiflash-toml"
                    | "tidb-tiflash-learner-toml"
                    | "tidb-tiproxy-toml"
                    | "tidb-ticdc-toml"
                    | "tidb-ticdc-changefeed-toml"
                    | "tidb-lightning-toml"
            ) =>
        {
            ""
        }
        (_, DatabaseConfigDialect::Toml) => {
            "# LovelyHawk TOML 起始配置；组件参数随版本变化，请导入目标机原文件后编辑。\n"
        }
        (_, DatabaseConfigDialect::JavaProperties) => {
            "# LovelyHawk Java properties 起始配置；请导入匹配组件版本的原文件。\n"
        }
        (DatabaseConfigProduct::Yashan, DatabaseConfigDialect::KeyValue)
            if artifact.key == "yashandb-yasdb-ini" =>
        {
            ""
        }
        (_, DatabaseConfigDialect::KeyValue | DatabaseConfigDialect::VendorText) => {
            "# LovelyHawk 起始配置；请导入目标实例原文件以保留厂商扩展。\n"
        }
        (
            _,
            DatabaseConfigDialect::MySqlPersistedVariablesJson
            | DatabaseConfigDialect::PostgreSqlAutoConf
            | DatabaseConfigDialect::Yaml
            | DatabaseConfigDialect::Json
            | DatabaseConfigDialect::Xml
            | DatabaseConfigDialect::GcwareConf
            | DatabaseConfigDialect::SequoiaQuickDeployClusterCsv
            | DatabaseConfigDialect::SequoiaQuickDeploySqlInstanceCsv
            | DatabaseConfigDialect::VendorBinary
            | DatabaseConfigDialect::RuntimeSql
            | DatabaseConfigDialect::CloudApi
            | DatabaseConfigDialect::VendorSchema,
        ) => "",
    }
}

fn unsupported_visual_artifact() -> CoreError {
    CoreError::Validation {
        subject: "visual configuration artifact",
        message: "the selected artifact does not support this structural operation".to_owned(),
    }
}

fn read_only_visual_artifact(artifact: &DatabaseConfigArtifactDefinition) -> CoreError {
    let reason = if matches!(
        artifact.edit_policy,
        DatabaseConfigEditPolicy::VendorSchemaRequired
    ) {
        "the selected artifact policy forbids local draft mutation; selecting schema metadata does not unlock it"
    } else {
        "the selected generated artifact forbids local draft mutation"
    };
    CoreError::Validation {
        subject: "local lossless configuration draft mutation",
        message: reason.to_owned(),
    }
}

fn stale_visual_node() -> CoreError {
    CoreError::Validation {
        subject: "visual configuration edit",
        message: "selected node is stale".to_owned(),
    }
}

/// One editable or read-only configuration document, whatever its syntax.
#[derive(Clone, Debug)]
pub enum VisualDocument {
    Nginx(NginxVisualDocument),
    Apache(ApacheVisualDocument),
    Line {
        artifact: &'static DatabaseConfigArtifactDefinition,
        document: LineConfigVisualDocument,
    },
    Structured {
        artifact: &'static DatabaseConfigArtifactDefinition,
        document: StructuredConfigVisualDocument,
    },
}

impl VisualDocument {
    pub fn nginx_competition_skeleton() -> CoreResult<Self> {
        NginxVisualDocument::competition_skeleton().map(Self::Nginx)
    }

    pub fn apache_competition_skeleton() -> CoreResult<Self> {
        ApacheVisualDocument::competition_skeleton().map(Self::Apache)
    }

    /// The starting document a new draft of `kind` begins with; a read-only
    /// database file has none.
    pub fn competition_skeleton(kind: VisualDocumentKind) -> CoreResult<Self> {
        match kind {
            VisualDocumentKind::Nginx => Self::nginx_competition_skeleton(),
            VisualDocumentKind::Apache => Self::apache_competition_skeleton(),
            VisualDocumentKind::Database(artifact) => Self::database_starter(artifact),
        }
    }

    /// What selecting a kind shows before anything is imported: the starting
    /// document, or an empty read-only one for a file that is never drafted.
    pub fn selection_document(kind: VisualDocumentKind) -> CoreResult<Self> {
        match kind {
            VisualDocumentKind::Database(artifact) if !artifact.allows_lossless_local_draft() => {
                Self::parse_database(artifact, "")
            }
            VisualDocumentKind::Nginx
            | VisualDocumentKind::Apache
            | VisualDocumentKind::Database(_) => Self::competition_skeleton(kind),
        }
    }

    pub fn database_starter(
        artifact: &'static DatabaseConfigArtifactDefinition,
    ) -> CoreResult<Self> {
        if !artifact.allows_lossless_local_draft() {
            return Err(read_only_visual_artifact(artifact));
        }
        Self::parse_database(artifact, database_starter_contents(artifact))
    }

    pub fn parse_database(
        artifact: &'static DatabaseConfigArtifactDefinition,
        source: &str,
    ) -> CoreResult<Self> {
        Self::parse_database_bytes(artifact, source.as_bytes().to_vec())
    }

    pub fn parse_database_bytes(
        artifact: &'static DatabaseConfigArtifactDefinition,
        source: Vec<u8>,
    ) -> CoreResult<Self> {
        match database_visual_parser(artifact).ok_or_else(unsupported_visual_artifact)? {
            DatabaseVisualParser::Line(dialect) => {
                LineConfigVisualDocument::parse_bytes(dialect, source)
                    .map(|document| Self::Line { artifact, document })
            }
            DatabaseVisualParser::Structured(dialect) => {
                StructuredConfigVisualDocument::parse_bytes(dialect, source)
                    .map(|document| Self::Structured { artifact, document })
            }
        }
    }

    pub fn read_local(kind: VisualDocumentKind, path: &Path) -> CoreResult<Self> {
        match kind {
            VisualDocumentKind::Nginx => NginxVisualDocument::read_local(path).map(Self::Nginx),
            VisualDocumentKind::Apache => ApacheVisualDocument::read_local(path).map(Self::Apache),
            VisualDocumentKind::Database(artifact) => {
                match database_visual_parser(artifact).ok_or_else(unsupported_visual_artifact)? {
                    DatabaseVisualParser::Line(dialect) => {
                        LineConfigVisualDocument::read_local(dialect, path)
                            .map(|document| Self::Line { artifact, document })
                    }
                    DatabaseVisualParser::Structured(dialect) => {
                        StructuredConfigVisualDocument::read_local(dialect, path)
                            .map(|document| Self::Structured { artifact, document })
                    }
                }
            }
        }
    }

    pub const fn kind(&self) -> VisualDocumentKind {
        match self {
            Self::Nginx(_) => VisualDocumentKind::Nginx,
            Self::Apache(_) => VisualDocumentKind::Apache,
            Self::Line { artifact, .. } | Self::Structured { artifact, .. } => {
                VisualDocumentKind::Database(artifact)
            }
        }
    }

    pub const fn is_structured(&self) -> bool {
        match self {
            Self::Nginx(document) => document.is_structured(),
            Self::Apache(document) => document.is_structured(),
            Self::Line { document, .. } => document.is_structured(),
            Self::Structured { document, .. } => document.is_structured(),
        }
    }

    pub const fn contains_sensitive_values(&self) -> bool {
        match self {
            Self::Nginx(document) => document.contains_sensitive_values(),
            Self::Apache(document) => document.contains_sensitive_values(),
            Self::Line { document, .. } => document.contains_sensitive_values(),
            Self::Structured { document, .. } => document.contains_sensitive_values(),
        }
    }

    /// Whether the whole text may reach a clipboard or a page.
    pub const fn can_copy(&self) -> bool {
        !self.contains_sensitive_values()
    }

    pub fn raw_bytes(&self) -> &[u8] {
        match self {
            Self::Nginx(document) => document.raw_bytes(),
            Self::Apache(document) => document.raw_bytes(),
            Self::Line { document, .. } => document.raw_bytes(),
            Self::Structured { document, .. } => document.raw_bytes(),
        }
    }

    /// The bytes as text, when they are UTF-8.
    pub fn text(&self) -> Option<&str> {
        std::str::from_utf8(self.raw_bytes()).ok()
    }

    /// The file name a save suggests: the catalogue's for a database file.
    pub fn suggested_file_name(&self) -> &'static str {
        match self {
            Self::Nginx(document) => document.output().suggested_file_name(),
            Self::Apache(document) => document.output().suggested_file_name(),
            Self::Line { artifact, document } => artifact
                .default_file_name
                .unwrap_or_else(|| document.dialect().suggested_file_name()),
            Self::Structured { artifact, document } => artifact
                .default_file_name
                .unwrap_or_else(|| document.dialect().suggested_file_name()),
        }
    }

    /// Writes the document's bytes to a file that must not exist yet.
    pub fn write_new(&self, destination: &Path) -> CoreResult<std::path::PathBuf> {
        match self {
            Self::Nginx(document) => document.output().write_new(destination),
            Self::Apache(document) => document.output().write_new(destination),
            Self::Line { document, .. } => document.output().write_new(destination),
            Self::Structured { document, .. } => document.output().write_new(destination),
        }
    }

    pub fn rows(&self) -> Vec<VisualRow> {
        self.rows_with_database_schema(None)
    }

    /// The rows, with the schema's meaning attached where it applies. A
    /// schema for another file is ignored, never half-applied.
    pub fn rows_with_database_schema(
        &self,
        schema: Option<&'static DatabaseConfigSchema>,
    ) -> Vec<VisualRow> {
        match self {
            Self::Nginx(document) => document.rows().into_iter().map(Into::into).collect(),
            Self::Apache(document) => document.rows().into_iter().map(Into::into).collect(),
            Self::Line { artifact, document } => line_visual_rows(
                document,
                schema.filter(|schema| database_schema_matches_artifact(schema, artifact)),
            )
            .into_iter()
            .map(|row| row.with_local_draft_permission(artifact.allows_lossless_local_draft()))
            .collect(),
            Self::Structured { artifact, document } => document
                .rows()
                .into_iter()
                .map(VisualRow::from)
                .map(|row| row.with_local_draft_permission(artifact.allows_lossless_local_draft()))
                .collect(),
        }
    }

    pub fn add_statement(
        &mut self,
        parent: Option<VisualNodeId>,
        name: &str,
        arguments: &str,
    ) -> CoreResult<()> {
        self.ensure_lossless_local_draft()?;
        match self {
            Self::Nginx(document) => {
                document.add_directive(unwrap_nginx_parent(parent)?, name, arguments)
            }
            Self::Apache(document) => {
                document.add_directive(unwrap_apache_parent(parent)?, name, arguments)
            }
            Self::Line { document, .. } => {
                let parent = unwrap_line_parent(parent)?;
                match document.dialect() {
                    LineConfigDialect::PgHba | LineConfigDialect::PgIdent => {
                        document.add_record(parent, &join_visual_fields(name, arguments))
                    }
                    _ => document.add_entry(
                        parent,
                        name,
                        (!arguments.is_empty()).then_some(arguments),
                    ),
                }
            }
            Self::Structured { .. } => Err(unsupported_visual_artifact()),
        }
    }

    pub fn add_container(
        &mut self,
        parent: Option<VisualNodeId>,
        name: &str,
        arguments: &str,
    ) -> CoreResult<()> {
        self.ensure_lossless_local_draft()?;
        match self {
            Self::Nginx(document) => {
                document.add_block(unwrap_nginx_parent(parent)?, name, arguments)
            }
            Self::Apache(document) => {
                document.add_section(unwrap_apache_parent(parent)?, name, arguments)
            }
            Self::Line { document, .. } => match document.dialect() {
                LineConfigDialect::MySqlOption | LineConfigDialect::Ini => {
                    if parent.is_some() || !arguments.is_empty() {
                        return Err(unsupported_visual_artifact());
                    }
                    document.add_section(name)
                }
                LineConfigDialect::Toml => document.add_table(unwrap_line_parent(parent)?, name),
                _ => Err(unsupported_visual_artifact()),
            },
            Self::Structured { .. } => Err(unsupported_visual_artifact()),
        }
    }

    pub fn add_comment(&mut self, parent: Option<VisualNodeId>, text: &str) -> CoreResult<()> {
        self.ensure_lossless_local_draft()?;
        match self {
            Self::Nginx(document) => document.add_comment(unwrap_nginx_parent(parent)?, text),
            Self::Apache(document) => document.add_comment(unwrap_apache_parent(parent)?, text),
            Self::Line { document, .. } => document.add_comment(unwrap_line_parent(parent)?, text),
            Self::Structured { .. } => Err(unsupported_visual_artifact()),
        }
    }

    pub fn update_statement(
        &mut self,
        id: VisualNodeId,
        name: &str,
        arguments: &str,
    ) -> CoreResult<()> {
        self.ensure_lossless_local_draft()?;
        match (self, id) {
            (Self::Nginx(document), VisualNodeId::Nginx(id)) => {
                document.update_statement(id, name, arguments)
            }
            (Self::Apache(document), VisualNodeId::Apache(id)) => {
                document.update_statement(id, name, arguments)
            }
            (Self::Line { document, .. }, VisualNodeId::Line(id)) => {
                let row = document.row_by_id(id).ok_or_else(stale_visual_node)?;
                match row.kind() {
                    LineConfigNodeKind::Entry | LineConfigNodeKind::Include => document
                        .update_entry(id, name, (!arguments.is_empty()).then_some(arguments)),
                    LineConfigNodeKind::Record => {
                        document.update_record(id, &join_visual_fields(name, arguments))
                    }
                    LineConfigNodeKind::Section | LineConfigNodeKind::Table => {
                        if !arguments.is_empty() {
                            return Err(unsupported_visual_artifact());
                        }
                        document.update_container(id, name)
                    }
                    LineConfigNodeKind::Comment | LineConfigNodeKind::Opaque => {
                        Err(stale_visual_node())
                    }
                }
            }
            _ => Err(stale_visual_node()),
        }
    }

    pub fn update_comment(&mut self, id: VisualNodeId, text: &str) -> CoreResult<()> {
        self.ensure_lossless_local_draft()?;
        match (self, id) {
            (Self::Nginx(document), VisualNodeId::Nginx(id)) => document.update_comment(id, text),
            (Self::Apache(document), VisualNodeId::Apache(id)) => document.update_comment(id, text),
            (Self::Line { document, .. }, VisualNodeId::Line(id)) => {
                document.update_comment(id, text)
            }
            _ => Err(stale_visual_node()),
        }
    }

    pub fn remove(&mut self, id: VisualNodeId) -> CoreResult<()> {
        self.ensure_lossless_local_draft()?;
        match (self, id) {
            (Self::Nginx(document), VisualNodeId::Nginx(id)) => document.remove(id),
            (Self::Apache(document), VisualNodeId::Apache(id)) => document.remove(id),
            (Self::Line { document, .. }, VisualNodeId::Line(id)) => document.remove(id),
            _ => Err(stale_visual_node()),
        }
    }

    pub fn move_up(&mut self, id: VisualNodeId) -> CoreResult<()> {
        self.ensure_lossless_local_draft()?;
        match (self, id) {
            (Self::Nginx(document), VisualNodeId::Nginx(id)) => document.move_up(id),
            (Self::Apache(document), VisualNodeId::Apache(id)) => document.move_up(id),
            (Self::Line { document, .. }, VisualNodeId::Line(id)) => document.move_up(id),
            _ => Err(stale_visual_node()),
        }
    }

    pub fn move_down(&mut self, id: VisualNodeId) -> CoreResult<()> {
        self.ensure_lossless_local_draft()?;
        match (self, id) {
            (Self::Nginx(document), VisualNodeId::Nginx(id)) => document.move_down(id),
            (Self::Apache(document), VisualNodeId::Apache(id)) => document.move_down(id),
            (Self::Line { document, .. }, VisualNodeId::Line(id)) => document.move_down(id),
            _ => Err(stale_visual_node()),
        }
    }

    fn ensure_lossless_local_draft(&self) -> CoreResult<()> {
        match self.kind() {
            VisualDocumentKind::Database(artifact) if !artifact.allows_lossless_local_draft() => {
                Err(read_only_visual_artifact(artifact))
            }
            VisualDocumentKind::Nginx
            | VisualDocumentKind::Apache
            | VisualDocumentKind::Database(_) => Ok(()),
        }
    }
}

fn line_visual_rows(
    document: &LineConfigVisualDocument,
    schema: Option<&'static DatabaseConfigSchema>,
) -> Vec<VisualRow> {
    let rows = document.rows();
    let container_names = rows
        .iter()
        .filter(|row| {
            matches!(
                row.kind(),
                LineConfigNodeKind::Section | LineConfigNodeKind::Table
            )
        })
        .filter_map(|row| row.name().map(|name| (row.id(), name.to_owned())))
        .collect::<HashMap<_, _>>();
    rows.into_iter()
        .map(|row| {
            let parameter = line_database_parameter(schema, &row, &container_names);
            visual_row_from_line(row, parameter)
        })
        .collect()
}

fn line_database_parameter(
    schema: Option<&'static DatabaseConfigSchema>,
    row: &LineConfigRow,
    container_names: &HashMap<LineConfigNodeId, String>,
) -> DatabaseParameterMatch {
    let Some(schema) = schema else {
        return DatabaseParameterMatch::NotApplicable;
    };
    if row.kind() != LineConfigNodeKind::Entry {
        return DatabaseParameterMatch::NotApplicable;
    }
    let Some(key) = row.name() else {
        return DatabaseParameterMatch::VisibleUnvalidated;
    };
    let container_path = match row.parent() {
        None => None,
        Some(parent) => {
            let Some(name) = container_names.get(&parent) else {
                return DatabaseParameterMatch::VisibleUnvalidated;
            };
            Some(name.as_str())
        }
    };
    schema
        .parameter(DatabaseConfigParameterLocator {
            container_path,
            key,
        })
        .map_or(
            DatabaseParameterMatch::VisibleUnvalidated,
            DatabaseParameterMatch::Matched,
        )
}

fn unwrap_nginx_parent(parent: Option<VisualNodeId>) -> CoreResult<Option<NginxVisualNodeId>> {
    parent
        .map(|id| match id {
            VisualNodeId::Nginx(id) => Ok(id),
            _ => Err(stale_visual_node()),
        })
        .transpose()
}

fn unwrap_apache_parent(parent: Option<VisualNodeId>) -> CoreResult<Option<ApacheVisualNodeId>> {
    parent
        .map(|id| match id {
            VisualNodeId::Apache(id) => Ok(id),
            _ => Err(stale_visual_node()),
        })
        .transpose()
}

fn unwrap_line_parent(parent: Option<VisualNodeId>) -> CoreResult<Option<LineConfigNodeId>> {
    parent
        .map(|id| match id {
            VisualNodeId::Line(id) => Ok(id),
            _ => Err(stale_visual_node()),
        })
        .transpose()
}

fn join_visual_fields(name: &str, arguments: &str) -> String {
    if name.is_empty() {
        arguments.to_owned()
    } else if arguments.is_empty() {
        name.to_owned()
    } else {
        format!("{name} {arguments}")
    }
}

/// Whether a schema was written for exactly this file.
pub fn database_schema_matches_artifact(
    schema: &DatabaseConfigSchema,
    artifact: &DatabaseConfigArtifactDefinition,
) -> bool {
    schema.binding.product == artifact.product
        && schema.binding.component == artifact.component
        && schema.binding.artifact_key == artifact.key
}

/// The reviewed schemas written for a file, one per version range.
pub fn database_schemas_for_artifact(
    artifact: &'static DatabaseConfigArtifactDefinition,
) -> impl Iterator<Item = &'static DatabaseConfigSchema> {
    DATABASE_CONFIG_SCHEMAS
        .iter()
        .filter(move |schema| database_schema_matches_artifact(schema, artifact))
}

pub const fn schema_scope_terms(scope: DatabaseConfigSchemaScope) -> [&'static str; 2] {
    match scope {
        DatabaseConfigSchemaScope::Session => ["Session", "会话"],
        DatabaseConfigSchemaScope::Instance => ["Instance", "实例"],
        DatabaseConfigSchemaScope::Component => ["Component", "组件"],
        DatabaseConfigSchemaScope::Cluster => ["Cluster", "集群"],
        DatabaseConfigSchemaScope::Global => ["Global", "全局"],
        DatabaseConfigSchemaScope::VendorDefined => ["VendorDefined", "厂商定义"],
    }
}

pub const fn schema_activation_terms(
    activation: DatabaseConfigSchemaActivation,
) -> [&'static str; 2] {
    match activation {
        DatabaseConfigSchemaActivation::Dynamic => ["Dynamic", "立即生效"],
        DatabaseConfigSchemaActivation::Reload => ["Reload", "重新加载后生效"],
        DatabaseConfigSchemaActivation::Restart => ["Restart", "重启后生效"],
        DatabaseConfigSchemaActivation::RollingRestart => ["RollingRestart", "滚动重启后生效"],
        DatabaseConfigSchemaActivation::VendorProcedure => ["VendorProcedure", "按厂商步骤生效"],
    }
}

pub const fn schema_risk_terms(risk: DatabaseConfigSchemaRisk) -> [&'static str; 2] {
    match risk {
        DatabaseConfigSchemaRisk::Informational => ["Informational", "提示"],
        DatabaseConfigSchemaRisk::Low => ["Low", "低风险"],
        DatabaseConfigSchemaRisk::Medium => ["Medium", "中风险"],
        DatabaseConfigSchemaRisk::High => ["High", "高风险"],
        DatabaseConfigSchemaRisk::Critical => ["Critical", "严重风险"],
    }
}

pub const fn schema_sensitivity_terms(
    sensitivity: DatabaseConfigSchemaSensitivity,
) -> [&'static str; 2] {
    match sensitivity {
        DatabaseConfigSchemaSensitivity::Public => ["Public", "公开"],
        DatabaseConfigSchemaSensitivity::OperationalMetadata => ["OperationalMetadata", "运维信息"],
        DatabaseConfigSchemaSensitivity::MayContainSecrets => ["MayContainSecrets", "可能含秘密"],
        DatabaseConfigSchemaSensitivity::PrivateKeyReference => ["PrivateKeyReference", "私钥引用"],
    }
}

const fn schema_value_kind_terms(value_kind: DatabaseConfigSchemaValueKind) -> [&'static str; 2] {
    match value_kind {
        DatabaseConfigSchemaValueKind::Boolean { .. } => ["Boolean", "开关"],
        DatabaseConfigSchemaValueKind::Integer { .. } => ["Integer", "整数"],
        DatabaseConfigSchemaValueKind::Enumeration { .. } => ["Enumeration", "取值之一"],
        DatabaseConfigSchemaValueKind::Text { .. } => ["Text", "文本"],
    }
}

/// The values a parameter accepts, in words: the reviewed literals and bounds,
/// never a documented default or a value from a file.
pub fn schema_value_kind_description(value_kind: DatabaseConfigSchemaValueKind) -> String {
    match value_kind {
        DatabaseConfigSchemaValueKind::Boolean {
            true_literal,
            false_literal,
        } => format!("开关（开：{true_literal}；关：{false_literal}）"),
        DatabaseConfigSchemaValueKind::Integer {
            minimum_inclusive,
            maximum_inclusive,
        } => format!("整数（{minimum_inclusive} 到 {maximum_inclusive}）"),
        DatabaseConfigSchemaValueKind::Enumeration { values } => {
            format!("取值之一（{}）", values.join("、"))
        }
        DatabaseConfigSchemaValueKind::Text {
            minimum_bytes,
            maximum_bytes,
            normalization,
        } => format!(
            "文本（{minimum_bytes} 到 {maximum_bytes} 字节，{}）",
            match normalization {
                DatabaseConfigTextNormalization::Preserve => "按原样保留",
                DatabaseConfigTextNormalization::TrimAsciiWhitespace => "去掉首尾空白",
            }
        ),
    }
}

/// Whether a query names a value domain: its kind or one of its reviewed
/// literals. Integer bounds and text lengths are not words to search for.
pub fn schema_value_kind_matches_bounded_query(
    value_kind: DatabaseConfigSchemaValueKind,
    query: &str,
) -> bool {
    if schema_value_kind_terms(value_kind)
        .iter()
        .any(|term| ascii_case_insensitive_contains(term, query))
    {
        return true;
    }
    match value_kind {
        DatabaseConfigSchemaValueKind::Boolean {
            true_literal,
            false_literal,
        } => {
            ascii_case_insensitive_contains(true_literal, query)
                || ascii_case_insensitive_contains(false_literal, query)
        }
        DatabaseConfigSchemaValueKind::Enumeration { values } => values
            .iter()
            .any(|value| ascii_case_insensitive_contains(value, query)),
        DatabaseConfigSchemaValueKind::Integer { .. }
        | DatabaseConfigSchemaValueKind::Text { .. } => false,
    }
}

/// The query as matching uses it: at most [`MAX_VISUAL_SEARCH_CHARS`] characters.
pub fn bounded_visual_search_query(value: &str) -> String {
    value.chars().take(MAX_VISUAL_SEARCH_CHARS).collect()
}

/// ASCII letters match in any case; everything else matches exactly.
pub fn ascii_case_insensitive_contains(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|candidate| candidate.eq_ignore_ascii_case(needle.as_bytes()))
}

fn schema_contains_parameter(
    schema: &DatabaseConfigSchema,
    parameter: &DatabaseConfigParameterSchema,
) -> bool {
    schema
        .parameters
        .iter()
        .any(|candidate| std::ptr::eq(candidate, parameter))
}

/// The reviewed words a parameter can be found by: its names, place, value
/// domain, classification, rationale and reference. Never its documented
/// default, and never a value from any file.
pub fn schema_parameter_search_terms(
    schema: &DatabaseConfigSchema,
    parameter: &DatabaseConfigParameterSchema,
) -> Vec<&'static str> {
    let mut terms = vec![parameter.canonical_key];
    terms.extend(parameter.exact_aliases.iter().copied());
    terms.extend(parameter.container_path);
    terms.extend(schema_value_kind_terms(parameter.value_kind));
    match parameter.value_kind {
        DatabaseConfigSchemaValueKind::Boolean {
            true_literal,
            false_literal,
        } => terms.extend([true_literal, false_literal]),
        DatabaseConfigSchemaValueKind::Enumeration { values } => {
            terms.extend(values.iter().copied())
        }
        DatabaseConfigSchemaValueKind::Integer { .. }
        | DatabaseConfigSchemaValueKind::Text { .. } => {}
    }
    terms.extend(schema_scope_terms(parameter.scope));
    terms.extend(schema_activation_terms(parameter.activation));
    terms.extend(schema_risk_terms(parameter.risk));
    terms.extend(schema_sensitivity_terms(parameter.sensitivity));
    terms.extend(parameter.required_capability);
    terms.push(parameter.risk_rationale);
    terms.push(parameter.competition_rationale);
    for reference in schema.references {
        if reference.id == parameter.official_reference_id {
            terms.push(reference.id);
            terms.push(reference.title);
        }
    }
    terms
}

pub fn schema_parameter_matches_bounded_query(
    schema: &DatabaseConfigSchema,
    parameter: &DatabaseConfigParameterSchema,
    query: &str,
) -> bool {
    schema_parameter_search_terms(schema, parameter)
        .iter()
        .any(|term| ascii_case_insensitive_contains(term, query))
}

/// The words a row can be found by: its kind, the name of a statement or
/// container, and — for a row the selected schema describes — the reviewed
/// parameter words. Comment text, values, previews and raw text never are.
pub fn visual_row_search_terms(
    row: &VisualRow,
    schema: Option<&'static DatabaseConfigSchema>,
) -> Vec<String> {
    let mut terms = vec![
        row.kind().label().to_owned(),
        row.kind().search_key().to_owned(),
    ];
    if matches!(
        row.kind(),
        VisualNodeKind::Statement | VisualNodeKind::Container
    ) && let Some(name) = row.name()
    {
        terms.push(name.to_owned());
    }
    if let (Some(schema), DatabaseParameterMatch::Matched(parameter)) =
        (schema, row.database_parameter())
        && schema_contains_parameter(schema, parameter)
    {
        terms.extend(
            schema_parameter_search_terms(schema, parameter)
                .into_iter()
                .map(str::to_owned),
        );
    }
    terms
}

/// The rows a search keeps, in document order: every row whose search terms
/// contain the query, with each container it sits in. An empty query keeps
/// every row.
pub fn filtered_visual_row_indices(
    rows: &[VisualRow],
    schema: Option<&'static DatabaseConfigSchema>,
    query: &str,
) -> Vec<usize> {
    let query = bounded_visual_search_query(query);
    if query.is_empty() {
        return (0..rows.len()).collect();
    }
    let indices_by_id = rows
        .iter()
        .enumerate()
        .map(|(index, row)| (row.id(), index))
        .collect::<HashMap<_, _>>();
    let mut visible = vec![false; rows.len()];
    for (index, row) in rows.iter().enumerate() {
        let matched = visual_row_search_terms(row, schema)
            .iter()
            .any(|term| ascii_case_insensitive_contains(term, &query));
        if !matched {
            continue;
        }
        let mut current = Some(index);
        // The step bound makes a malformed parent cycle stop instead of loop.
        for _ in 0..rows.len() {
            let Some(current_index) = current else {
                break;
            };
            if visible[current_index] {
                break;
            }
            visible[current_index] = true;
            current = rows[current_index]
                .parent
                .and_then(|parent| indices_by_id.get(&parent).copied());
        }
    }
    visible
        .into_iter()
        .enumerate()
        .filter_map(|(index, visible)| visible.then_some(index))
        .collect()
}

/// The schema's parameters a search keeps, whether or not the file has them.
pub fn filtered_schema_parameter_indices(schema: &DatabaseConfigSchema, query: &str) -> Vec<usize> {
    let query = bounded_visual_search_query(query);
    schema
        .parameters
        .iter()
        .enumerate()
        .filter_map(|(index, parameter)| {
            (query.is_empty() || schema_parameter_matches_bounded_query(schema, parameter, &query))
                .then_some(index)
        })
        .collect()
}

/// A document open for editing, with the schema chosen for it and the
/// catalogue parameter chosen from that schema.
#[derive(Clone, Debug)]
pub struct VisualEditingSession {
    document: VisualDocument,
    schema: Option<&'static DatabaseConfigSchema>,
    selected_parameter: Option<usize>,
}

impl VisualEditingSession {
    pub fn new(document: VisualDocument) -> Self {
        Self {
            document,
            schema: None,
            selected_parameter: None,
        }
    }

    pub const fn document(&self) -> &VisualDocument {
        &self.document
    }

    /// The document for an edit. The chosen schema stays: an edit does not
    /// change which file this is.
    pub fn document_mut(&mut self) -> &mut VisualDocument {
        &mut self.document
    }

    /// Puts another document in place. A different file drops the schema and
    /// the parameter chosen for the old one.
    pub fn replace_document(&mut self, document: VisualDocument) {
        if document.kind() != self.document.kind() {
            self.schema = None;
            self.selected_parameter = None;
        }
        self.document = document;
    }

    pub const fn current_schema(&self) -> Option<&'static DatabaseConfigSchema> {
        self.schema
    }

    pub const fn selected_parameter(&self) -> Option<usize> {
        self.selected_parameter
    }

    /// Chooses a reviewed schema from the built-in registry.
    pub fn select_schema(&mut self, schema: &'static DatabaseConfigSchema) -> bool {
        self.select_schema_from_registry(schema, DATABASE_CONFIG_SCHEMAS)
    }

    /// Chooses `schema` when it is one of `registry` and was written for this
    /// very file; anything else leaves the current choice as it was.
    pub fn select_schema_from_registry(
        &mut self,
        schema: &'static DatabaseConfigSchema,
        registry: &'static [DatabaseConfigSchema],
    ) -> bool {
        let VisualDocumentKind::Database(artifact) = self.document.kind() else {
            return false;
        };
        let registered = registry
            .iter()
            .any(|candidate| std::ptr::eq(candidate, schema));
        if !registered || !database_schema_matches_artifact(schema, artifact) {
            return false;
        }
        if !self
            .schema
            .is_some_and(|current| std::ptr::eq(current, schema))
        {
            self.selected_parameter = None;
        }
        self.schema = Some(schema);
        true
    }

    pub fn clear_schema(&mut self) {
        self.schema = None;
        self.selected_parameter = None;
    }

    pub fn rows(&self) -> Vec<VisualRow> {
        self.document.rows_with_database_schema(self.schema)
    }

    /// Whether anything is hidden: a value the syntax flags, or one the
    /// chosen schema marks as secret although the syntax did not.
    pub fn contains_sensitive_values(&self) -> bool {
        self.document.contains_sensitive_values() || self.rows().iter().any(VisualRow::sensitive)
    }

    /// Whether the whole text may reach a clipboard or a page.
    pub fn can_copy(&self) -> bool {
        !self.contains_sensitive_values()
    }

    pub fn filtered_row_indices(&self, query: &str) -> Vec<usize> {
        filtered_visual_row_indices(&self.rows(), self.schema, query)
    }

    pub fn filtered_parameter_indices(&self, query: &str) -> Vec<usize> {
        self.schema
            .map(|schema| filtered_schema_parameter_indices(schema, query))
            .unwrap_or_default()
    }

    /// Chooses a catalogue parameter that the current search shows; one the
    /// search hides, or from another schema, is not chosen. The document is
    /// never touched.
    pub fn select_visible_parameter(
        &mut self,
        schema: &'static DatabaseConfigSchema,
        index: usize,
        query: &str,
    ) -> Option<&'static DatabaseConfigParameterSchema> {
        let current = self.schema?;
        if !std::ptr::eq(current, schema)
            || !self.filtered_parameter_indices(query).contains(&index)
        {
            return None;
        }
        let parameter = current.parameters.get(index)?;
        self.selected_parameter = Some(index);
        Some(parameter)
    }

    /// The document after setting parameter `parameter_index` of the chosen
    /// schema to `raw_value`, checked by the schema and read back; this
    /// session is not changed.
    pub fn stage_parameter_value(
        &self,
        parameter_index: usize,
        raw_value: &str,
    ) -> Result<VisualDocument, DatabaseParameterValueError> {
        let schema = self.schema.ok_or(DatabaseParameterValueError::NoSchema)?;
        let draft = validate_database_parameter_goal_value(schema, parameter_index, raw_value)
            .map_err(DatabaseParameterValueError::Draft)?;
        stage_database_parameter(&self.document, schema, parameter_index, &draft)
            .map_err(DatabaseParameterValueError::Stage)
    }

    /// Where a confirmed assignment would land, as a new session: this very
    /// document when it is the target file under the same schema, otherwise a
    /// new empty draft of the target file. Unsaved edits of another file, or
    /// of this file under another schema or version, are never set aside.
    pub fn stage_assignment(
        &self,
        assignment: &DatabaseParameterAssignment,
        unsaved: bool,
    ) -> Result<Self, DatabaseAssignmentPreflightError> {
        let schema = assignment.schema();
        let artifact = database_artifact_by_key(schema.binding.artifact_key)
            .filter(|artifact| database_schema_matches_artifact(schema, artifact))
            .ok_or(DatabaseAssignmentPreflightError::ArtifactMissing)?;
        let target_kind = VisualDocumentKind::Database(artifact);
        let same_file = self.document.kind() == target_kind;
        let same_schema = self
            .schema
            .is_some_and(|current| std::ptr::eq(current, schema));
        if unsaved && !same_file {
            return Err(DatabaseAssignmentPreflightError::OtherFileUnsaved);
        }
        if unsaved && !same_schema {
            return Err(DatabaseAssignmentPreflightError::OtherSchemaUnsaved);
        }
        let base = if same_file && same_schema {
            self.document.clone()
        } else {
            VisualDocument::parse_database(artifact, "").map_err(|_| {
                DatabaseAssignmentPreflightError::Stage(DatabaseParameterStageError::WriterRefused)
            })?
        };
        let staged = stage_database_parameter(
            &base,
            schema,
            assignment.parameter_index(),
            assignment.draft(),
        )
        .map_err(DatabaseAssignmentPreflightError::Stage)?;
        Ok(Self {
            document: staged,
            schema: Some(schema),
            selected_parameter: Some(assignment.parameter_index()),
        })
    }
}

/// Why a value typed for a catalogue parameter did not go into the draft.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseParameterValueError {
    /// No schema is chosen, so there is no catalogue to set from.
    NoSchema,
    /// The schema refuses this parameter or this value.
    Draft(DatabaseParameterGoalDraftError),
    /// The document could not take the value.
    Stage(DatabaseParameterStageError),
}

/// Why an assignment cannot go into the document open now.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseAssignmentPreflightError {
    /// The catalogue no longer has the file the schema was written for.
    ArtifactMissing,
    /// Another file has unsaved edits.
    OtherFileUnsaved,
    /// This file has unsaved edits under another schema or version.
    OtherSchemaUnsaved,
    Stage(DatabaseParameterStageError),
}

/// Why a reviewed parameter value could not be written into a local draft.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseParameterStageError {
    /// The schema no longer has this parameter.
    ParameterGone,
    /// The document is not a database file.
    NotDatabaseDocument,
    /// The value was checked for another file, group or name.
    TargetMismatch,
    /// The file is never changed here.
    ReadOnly,
    /// The parameter is written more than once; which line wins is the
    /// server's rule, so none is changed.
    Duplicate,
    /// The one existing line cannot be changed here (hidden or too long).
    LineLocked,
    /// More than one group carries the parameter's group name.
    AmbiguousGroup,
    /// The syntax writer refused the line.
    WriterRefused,
    /// After writing, the file did not read back with exactly this one line
    /// holding exactly this value.
    ReadBackFailed,
}

fn database_goal_container_name_matches(
    dialect: DatabaseConfigDialect,
    actual: &str,
    expected: &str,
) -> bool {
    if dialect == DatabaseConfigDialect::MySqlOptionFile {
        actual.eq_ignore_ascii_case(expected)
    } else {
        actual == expected
    }
}

fn exact_parameter_rows(
    document: &VisualDocument,
    schema: &'static DatabaseConfigSchema,
    parameter: &DatabaseConfigParameterSchema,
) -> Vec<VisualRow> {
    document
        .rows_with_database_schema(Some(schema))
        .into_iter()
        .filter(|row| {
            matches!(
                row.database_parameter(),
                DatabaseParameterMatch::Matched(candidate) if std::ptr::eq(candidate, parameter)
            )
        })
        .collect()
}

/// The document after writing one reviewed value: the single existing line is
/// changed, or the line is added (under its group, created when missing). The
/// result must read back as exactly one line holding exactly this value;
/// anything else leaves `document` as it was and says why.
pub fn stage_database_parameter(
    document: &VisualDocument,
    schema: &'static DatabaseConfigSchema,
    parameter_index: usize,
    draft: &DatabaseParameterGoalDraft,
) -> Result<VisualDocument, DatabaseParameterStageError> {
    let parameter = schema
        .parameters
        .get(parameter_index)
        .ok_or(DatabaseParameterStageError::ParameterGone)?;
    let VisualDocumentKind::Database(artifact) = document.kind() else {
        return Err(DatabaseParameterStageError::NotDatabaseDocument);
    };
    if !database_schema_matches_artifact(schema, artifact)
        || draft.container_path() != parameter.container_path
        || draft.canonical_key() != parameter.canonical_key
    {
        return Err(DatabaseParameterStageError::TargetMismatch);
    }
    if !artifact.allows_lossless_local_draft() {
        return Err(DatabaseParameterStageError::ReadOnly);
    }

    let mut staged = document.clone();
    let existing = exact_parameter_rows(&staged, schema, parameter);
    match existing.as_slice() {
        [] => add_database_parameter_statement(&mut staged, artifact, schema, draft)?,
        [row] => {
            if !row.allows_local_draft_mutation() {
                return Err(DatabaseParameterStageError::LineLocked);
            }
            staged
                .update_statement(row.id(), draft.canonical_key(), draft.normalized_value())
                .map_err(|_| DatabaseParameterStageError::WriterRefused)?;
        }
        _ => return Err(DatabaseParameterStageError::Duplicate),
    }

    let written = exact_parameter_rows(&staged, schema, parameter);
    match written.as_slice() {
        [row]
            if row.name() == Some(draft.canonical_key())
                && row.arguments() == Some(draft.normalized_value()) =>
        {
            Ok(staged)
        }
        _ => Err(DatabaseParameterStageError::ReadBackFailed),
    }
}

fn add_database_parameter_statement(
    document: &mut VisualDocument,
    artifact: &'static DatabaseConfigArtifactDefinition,
    schema: &'static DatabaseConfigSchema,
    draft: &DatabaseParameterGoalDraft,
) -> Result<(), DatabaseParameterStageError> {
    let groups_named = |document: &VisualDocument, path: &str| {
        document
            .rows_with_database_schema(Some(schema))
            .into_iter()
            .filter(|row| {
                row.kind() == VisualNodeKind::Container
                    && row.parent().is_none()
                    && row.name().is_some_and(|name| {
                        database_goal_container_name_matches(artifact.dialect, name, path)
                    })
            })
            .map(|row| row.id())
            .collect::<Vec<_>>()
    };
    let mut added_group = None;
    let parent = match draft.container_path() {
        None => None,
        Some(path) => match groups_named(document, path).as_slice() {
            [parent] => Some(*parent),
            [] => {
                document
                    .add_container(None, path, "")
                    .map_err(|_| DatabaseParameterStageError::WriterRefused)?;
                let created = groups_named(document, path);
                let [parent] = created.as_slice() else {
                    return Err(DatabaseParameterStageError::ReadBackFailed);
                };
                added_group = Some(*parent);
                Some(*parent)
            }
            _ => return Err(DatabaseParameterStageError::AmbiguousGroup),
        },
    };
    if document
        .add_statement(parent, draft.canonical_key(), draft.normalized_value())
        .is_err()
    {
        if let Some(group) = added_group {
            let _ = document.remove(group);
        }
        return Err(DatabaseParameterStageError::WriterRefused);
    }
    Ok(())
}

// Ported from the retired GPUI configuration page (docs/legacy/config-generator-baseline.rs.txt);
// each test keeps the legacy name it replaces (docs/CONFIG_GENERATOR_TEST_BACKLOG.md).
#[cfg(test)]
mod tests {
    use super::*;
    use crate::database_config::DatabaseConfigComponent;
    use crate::database_config_schema::{
        DatabaseConfigDocumentedDefault, DatabaseConfigSchemaBinding,
        DatabaseConfigSchemaCompleteness, DatabaseConfigSchemaReference, DatabaseConfigVersion,
        DatabaseConfigVersionSelector,
    };
    use crate::nginx_config::{
        NginxListenPort, NginxServerNames, NginxSiteConfig, NginxSiteTarget, NginxUpstream,
    };

    static TEST_SCHEMA_REFERENCES: &[DatabaseConfigSchemaReference] =
        &[DatabaseConfigSchemaReference {
            id: "test:config-generator-schema",
            title: "Config generator test-only schema reference",
            url: "https://example.invalid/config-generator-schema",
        }];

    static TEST_MYSQL_PARAMETERS: &[DatabaseConfigParameterSchema] = &[
        DatabaseConfigParameterSchema {
            container_path: Some("mysqld"),
            canonical_key: "fixture-payload",
            exact_aliases: &["fixture_payload"],
            value_kind: DatabaseConfigSchemaValueKind::Text {
                minimum_bytes: 1,
                maximum_bytes: 256,
                normalization: DatabaseConfigTextNormalization::Preserve,
            },
            documented_default: None,
            scope: DatabaseConfigSchemaScope::Instance,
            sensitivity: DatabaseConfigSchemaSensitivity::MayContainSecrets,
            activation: DatabaseConfigSchemaActivation::Restart,
            risk: DatabaseConfigSchemaRisk::High,
            risk_rationale: "Test-only sensitive row classification.",
            competition_rationale: "Proves that UI metadata redaction precedes value copying.",
            official_reference_id: "test:config-generator-schema",
            required_capability: Some("test.fixture.capability"),
        },
        DatabaseConfigParameterSchema {
            container_path: Some("client"),
            canonical_key: "fixture-host",
            exact_aliases: &[],
            value_kind: DatabaseConfigSchemaValueKind::Text {
                minimum_bytes: 1,
                maximum_bytes: 256,
                normalization: DatabaseConfigTextNormalization::Preserve,
            },
            documented_default: None,
            scope: DatabaseConfigSchemaScope::Session,
            sensitivity: DatabaseConfigSchemaSensitivity::OperationalMetadata,
            activation: DatabaseConfigSchemaActivation::Reload,
            risk: DatabaseConfigSchemaRisk::Low,
            risk_rationale: "Test-only operational metadata classification.",
            competition_rationale: "Proves that operational metadata remains visible.",
            official_reference_id: "test:config-generator-schema",
            required_capability: None,
        },
    ];

    const TEST_MYSQL_SCHEMA: DatabaseConfigSchema = DatabaseConfigSchema {
        display_label: "Test MySQL schema",
        version_label: "8.0 test fixture",
        binding: DatabaseConfigSchemaBinding {
            product: DatabaseConfigProduct::MySql,
            versions: DatabaseConfigVersionSelector::Exact(DatabaseConfigVersion::new(8, 0, 0)),
            edition_key: Some("test.standard"),
            component: DatabaseConfigComponent::Server,
            artifact_key: "mysql-option-file",
        },
        completeness: DatabaseConfigSchemaCompleteness::Partial,
        parameters: TEST_MYSQL_PARAMETERS,
        references: TEST_SCHEMA_REFERENCES,
    };

    static TEST_SCHEMA_REGISTRY: &[DatabaseConfigSchema] = &[
        TEST_MYSQL_SCHEMA,
        DatabaseConfigSchema {
            display_label: "Test PostgreSQL schema",
            version_label: "17 test fixture",
            binding: DatabaseConfigSchemaBinding {
                product: DatabaseConfigProduct::PostgreSql,
                versions: DatabaseConfigVersionSelector::Exact(DatabaseConfigVersion::new(
                    17, 0, 0,
                )),
                edition_key: None,
                component: DatabaseConfigComponent::Server,
                artifact_key: "postgresql-main",
            },
            ..TEST_MYSQL_SCHEMA
        },
    ];

    static TEST_DEFAULT_ONLY_SCHEMA: DatabaseConfigSchema = DatabaseConfigSchema {
        parameters: &[DatabaseConfigParameterSchema {
            container_path: Some("client"),
            canonical_key: "fixture-host",
            exact_aliases: &[],
            value_kind: DatabaseConfigSchemaValueKind::Text {
                minimum_bytes: 1,
                maximum_bytes: 256,
                normalization: DatabaseConfigTextNormalization::Preserve,
            },
            documented_default: Some(DatabaseConfigDocumentedDefault::Text(
                "default-only-search-sentinel",
            )),
            scope: DatabaseConfigSchemaScope::Session,
            sensitivity: DatabaseConfigSchemaSensitivity::OperationalMetadata,
            activation: DatabaseConfigSchemaActivation::Reload,
            risk: DatabaseConfigSchemaRisk::Low,
            risk_rationale: "Test-only operational metadata classification.",
            competition_rationale: "Proves that operational metadata remains visible.",
            official_reference_id: "test:config-generator-schema",
            required_capability: None,
        }],
        ..TEST_MYSQL_SCHEMA
    };

    fn database_artifact(key: &str) -> &'static DatabaseConfigArtifactDefinition {
        database_artifact_by_key(key)
            .unwrap_or_else(|| panic!("missing database configuration artifact {key}"))
    }

    fn mysql_session(source: &str) -> VisualEditingSession {
        VisualEditingSession::new(
            VisualDocument::parse_database(database_artifact("mysql-option-file"), source).unwrap(),
        )
    }

    fn filtered_row_names<'a>(rows: &'a [VisualRow], indices: &[usize]) -> Vec<&'a str> {
        indices
            .iter()
            .filter_map(|index| rows.get(*index).and_then(VisualRow::name))
            .collect()
    }

    pub(super) fn assert_local_draft_mutation_denied<T>(result: CoreResult<T>, key: &str) {
        let error = match result {
            Ok(_) => panic!("read-only artifact {key} accepted a local draft mutation"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("local draft mutation"),
            "unexpected {key} mutation error: {error}"
        );
    }

    #[test]
    fn visual_search_is_bounded_ascii_case_insensitive_and_keeps_only_parent_chains() {
        let source = concat!(
            "events {}\n",
            "http {\n",
            "    server {\n",
            "        target_match one;\n",
            "        unrelated first;\n",
            "    }\n",
            "    server {\n",
            "        target_match two;\n",
            "        unrelated second;\n",
            "    }\n",
            "    unrelated_root value;\n",
            "}\n",
        );
        let document = VisualDocument::Nginx(NginxVisualDocument::parse(source).unwrap());
        let rows = document.rows();

        assert_eq!(
            bounded_visual_search_query(&format!("{}ignored", "x".repeat(128))),
            "x".repeat(128)
        );
        assert_eq!(
            filtered_visual_row_indices(&rows, None, "").len(),
            rows.len()
        );

        let matches = filtered_visual_row_indices(&rows, None, "TaRgEt_MaTcH");
        assert!(matches.windows(2).all(|indices| indices[0] < indices[1]));
        assert_eq!(
            filtered_row_names(&rows, &matches),
            ["http", "server", "target_match", "server", "target_match"]
        );
        assert_eq!(
            matches
                .iter()
                .map(|index| rows[*index].depth())
                .collect::<Vec<_>>(),
            [0, 1, 2, 1, 2]
        );
        assert!(
            filtered_row_names(&rows, &matches)
                .iter()
                .all(|name| !name.starts_with("unrelated"))
        );
        // A value ("one", "first") is never a search word.
        assert!(filtered_visual_row_indices(&rows, None, "first").is_empty());
        assert!(filtered_visual_row_indices(&rows, None, "zero-match-X9").is_empty());
    }

    #[test]
    fn visual_search_uses_reviewed_schema_meaning_but_never_defaults_or_row_values() {
        const VALUE_SENTINEL: &str = "row-value-must-not-be-indexed-X9";
        let mut session = mysql_session(&format!(
            "[mysqld]\nfixture_payload = classified\nunknown_setting = {VALUE_SENTINEL}\n"
        ));
        let schema = &TEST_SCHEMA_REGISTRY[0];
        assert!(session.select_schema_from_registry(schema, TEST_SCHEMA_REGISTRY));
        let rows = session.rows();
        let matched_index = rows
            .iter()
            .position(|row| matches!(row.database_parameter(), DatabaseParameterMatch::Matched(_)))
            .unwrap();

        for query in [
            "FIXTURE-PAYLOAD",
            "FIXTURE_PAYLOAD",
            "MYSQLD",
            "INSTANCE",
            "RESTART",
            "HIGH",
            "MAYCONTAINSECRETS",
            "TEST.FIXTURE.CAPABILITY",
            "REDACTION PRECEDES",
            // The same classifications in the words the page shows.
            "实例",
            "重启后生效",
            "高风险",
            "可能含秘密",
        ] {
            assert!(
                session.filtered_row_indices(query).contains(&matched_index),
                "reviewed schema field did not match: {query}"
            );
            assert_eq!(
                session.filtered_parameter_indices(query),
                [0],
                "catalog field did not match: {query}"
            );
        }
        for query in [
            "TEST:CONFIG-GENERATOR-SCHEMA",
            "CONFIG GENERATOR TEST-ONLY SCHEMA REFERENCE",
        ] {
            assert!(session.filtered_row_indices(query).contains(&matched_index));
            assert_eq!(session.filtered_parameter_indices(query), [0, 1]);
        }

        assert!(session.filtered_row_indices(VALUE_SENTINEL).is_empty());
        assert!(session.filtered_row_indices("classified").is_empty());
        assert!(
            filtered_schema_parameter_indices(
                &TEST_DEFAULT_ONLY_SCHEMA,
                "default-only-search-sentinel"
            )
            .is_empty()
        );
        assert_eq!(session.filtered_parameter_indices(""), [0, 1]);
    }

    #[test]
    fn schema_value_domains_are_detailed_and_reviewed_literals_are_searchable() {
        let boolean = DatabaseConfigSchemaValueKind::Boolean {
            true_literal: "ENABLED_REVIEWED",
            false_literal: "DISABLED_REVIEWED",
        };
        let integer = DatabaseConfigSchemaValueKind::Integer {
            minimum_inclusive: -8,
            maximum_inclusive: 64,
        };
        let enumeration = DatabaseConfigSchemaValueKind::Enumeration {
            values: &["alpha", "ReviewedEnum-X9"],
        };
        let text = DatabaseConfigSchemaValueKind::Text {
            minimum_bytes: 1,
            maximum_bytes: 256,
            normalization: DatabaseConfigTextNormalization::TrimAsciiWhitespace,
        };

        assert!(schema_value_kind_matches_bounded_query(
            boolean,
            "enabled_reviewed"
        ));
        assert!(schema_value_kind_matches_bounded_query(
            enumeration,
            "reviewedenum-x9"
        ));
        assert!(schema_value_kind_matches_bounded_query(integer, "整数"));
        // Bounds and lengths are not search words.
        assert!(!schema_value_kind_matches_bounded_query(integer, "64"));
        assert!(!schema_value_kind_matches_bounded_query(text, "256"));
        assert_eq!(
            schema_value_kind_description(boolean),
            "开关（开：ENABLED_REVIEWED；关：DISABLED_REVIEWED）"
        );
        assert_eq!(schema_value_kind_description(integer), "整数（-8 到 64）");
        assert_eq!(
            schema_value_kind_description(enumeration),
            "取值之一（alpha、ReviewedEnum-X9）"
        );
        assert_eq!(
            schema_value_kind_description(text),
            "文本（1 到 256 字节，去掉首尾空白）"
        );
    }

    #[test]
    fn schema_catalog_covers_parameters_absent_from_the_document_without_mutation() {
        let mut session = mysql_session("");
        let schema = &TEST_SCHEMA_REGISTRY[0];
        let bytes_before = session.document().raw_bytes().to_vec();
        assert!(session.select_schema_from_registry(schema, TEST_SCHEMA_REGISTRY));
        assert!(session.rows().is_empty());
        assert_eq!(session.filtered_parameter_indices(""), [0, 1]);
        assert_eq!(session.filtered_parameter_indices("fixture-host"), [1]);

        // A parameter the current search hides is not chosen.
        assert!(
            session
                .select_visible_parameter(schema, 0, "fixture-host")
                .is_none()
        );
        let selected = session
            .select_visible_parameter(schema, 1, "fixture-host")
            .expect("visible catalog item");
        assert_eq!(selected.canonical_key, "fixture-host");
        assert_eq!(session.selected_parameter(), Some(1));
        assert_eq!(session.document().raw_bytes(), bytes_before);
    }

    #[test]
    fn search_never_indexes_sensitive_text_from_any_visual_document_source() {
        const SECRET: &str = "SensitiveSearchSentinel-X9";
        let nginx = VisualDocument::Nginx(
            NginxVisualDocument::parse(&format!("proxy_set_header Authorization {SECRET};\n"))
                .unwrap(),
        );
        let apache = VisualDocument::Apache(
            ApacheVisualDocument::parse(&format!("DBDParams \"password={SECRET}\"\n")).unwrap(),
        );
        let line = VisualDocument::parse_database(
            database_artifact("dm-init"),
            &format!("[DAMENG]\nSYSDBA_PWD={SECRET}\n"),
        )
        .unwrap();
        let structured = VisualDocument::parse_database(
            database_artifact("mysql-persisted-variables"),
            &format!("{{\"Version\":2,\"mysql_server\":{{\"password\":\"{SECRET}\"}}}}\n"),
        )
        .unwrap();

        for document in [nginx, apache, line, structured] {
            assert!(
                document
                    .raw_bytes()
                    .windows(SECRET.len())
                    .any(|bytes| bytes == SECRET.as_bytes())
            );
            assert!(document.contains_sensitive_values() && !document.can_copy());
            let rows = document.rows();
            assert!(rows.iter().any(VisualRow::sensitive));
            assert!(filtered_visual_row_indices(&rows, None, SECRET).is_empty());
            for row in rows.iter().filter(|row| row.sensitive()) {
                assert!(
                    visual_row_search_terms(row, None)
                        .iter()
                        .all(|term| !term.contains(SECRET))
                );
                assert!(!format!("{row:?}").contains(SECRET));
            }
        }
    }

    #[test]
    fn configuration_explanations_use_fail_closed_meaning_levels_without_values() {
        const SECRET: &str = "ExplanationSecret-X9";
        let mut session = mysql_session(&format!(
            "[mysqld]\nfixture_payload={SECRET}\nunknown_setting=visible\n"
        ));
        let schema = &TEST_SCHEMA_REGISTRY[0];
        assert!(session.select_schema_from_registry(schema, TEST_SCHEMA_REGISTRY));
        let rows = session.rows();
        let level_of = |wanted: fn(DatabaseParameterMatch) -> bool| {
            rows.iter()
                .find(|row| wanted(row.database_parameter()))
                .map(VisualRow::meaning_level)
                .unwrap()
        };
        // Only a row the reviewed catalogue describes rests on catalogue
        // guidance; nothing here is ever a check against the target.
        assert_eq!(
            level_of(|parameter| matches!(parameter, DatabaseParameterMatch::Matched(_))),
            VisualMeaningLevel::CatalogGuidance
        );
        assert_eq!(
            level_of(|parameter| matches!(parameter, DatabaseParameterMatch::VisibleUnvalidated)),
            VisualMeaningLevel::SyntaxOnly
        );
        assert_eq!(
            level_of(|parameter| matches!(parameter, DatabaseParameterMatch::NotApplicable)),
            VisualMeaningLevel::SyntaxOnly
        );
        let nginx = VisualDocument::nginx_competition_skeleton().unwrap();
        assert!(
            nginx
                .rows()
                .iter()
                .all(|row| row.meaning_level() == VisualMeaningLevel::SyntaxOnly)
        );

        // The matched row carries its classification but never its value.
        let matched = rows
            .iter()
            .find(|row| matches!(row.database_parameter(), DatabaseParameterMatch::Matched(_)))
            .unwrap();
        assert!(matched.sensitive() && matched.arguments().is_none());
        assert_eq!(matched.preview(), REDACTED_SCHEMA_VALUE);
        let terms = visual_row_search_terms(matched, Some(schema));
        assert!(terms.iter().any(|term| term == "Text"));
        assert!(terms.iter().all(|term| !term.contains(SECRET)));
        assert!(!format!("{rows:?}").contains(SECRET));
    }

    #[test]
    fn model_starts_with_independent_quick_and_competition_documents() {
        let generated = NginxSiteConfig::new(
            NginxServerNames::parse("example.com").unwrap(),
            NginxListenPort::parse("80").unwrap(),
            NginxSiteTarget::ReverseProxy(NginxUpstream::parse("http://127.0.0.1:3000").unwrap()),
            true,
        )
        .unwrap()
        .generate()
        .unwrap();
        let quick_contents = generated.contents().to_owned();
        let mut session =
            VisualEditingSession::new(VisualDocument::nginx_competition_skeleton().unwrap());

        assert!(session.document().is_structured());
        assert!(
            session
                .rows()
                .iter()
                .any(|row| row.name() == Some("events"))
        );
        assert!(session.rows().iter().any(|row| row.name() == Some("http")));

        session
            .document_mut()
            .add_statement(None, "third_party_directive", "competition value")
            .unwrap();
        assert!(session.rows().iter().any(|row| {
            row.kind() == VisualNodeKind::Statement && row.name() == Some("third_party_directive")
        }));
        // The visual draft is its own document: the quick draft is untouched.
        assert_eq!(generated.contents(), quick_contents);
    }

    #[test]
    fn schema_selection_rejects_cross_artifact_and_resets_when_artifact_changes() {
        let mut session = mysql_session("");
        let mysql_schema = &TEST_SCHEMA_REGISTRY[0];
        let postgresql_schema = &TEST_SCHEMA_REGISTRY[1];

        assert!(!session.select_schema_from_registry(postgresql_schema, TEST_SCHEMA_REGISTRY));
        assert!(session.current_schema().is_none());

        static UNREGISTERED_SCHEMA: DatabaseConfigSchema = DatabaseConfigSchema {
            display_label: "Unregistered test schema",
            ..TEST_MYSQL_SCHEMA
        };
        assert!(!session.select_schema_from_registry(&UNREGISTERED_SCHEMA, TEST_SCHEMA_REGISTRY));
        assert!(session.current_schema().is_none());

        assert!(session.select_schema_from_registry(mysql_schema, TEST_SCHEMA_REGISTRY));
        assert!(std::ptr::eq(
            session.current_schema().unwrap(),
            mysql_schema
        ));
        assert!(!session.select_schema_from_registry(postgresql_schema, TEST_SCHEMA_REGISTRY));
        assert!(std::ptr::eq(
            session.current_schema().unwrap(),
            mysql_schema
        ));

        session.replace_document(
            VisualDocument::parse_database(database_artifact("postgresql-main"), "port = 5433\n")
                .unwrap(),
        );
        assert!(session.current_schema().is_none());
        assert!(session.selected_parameter().is_none());

        // A schema is never chosen for a document that is not a database file.
        let mut nginx =
            VisualEditingSession::new(VisualDocument::nginx_competition_skeleton().unwrap());
        assert!(!nginx.select_schema_from_registry(mysql_schema, TEST_SCHEMA_REGISTRY));
    }

    #[test]
    fn partial_schema_is_metadata_only_and_preserves_local_draft_permission() {
        let mut session = mysql_session("[mysqld]\nunknown_local_draft_key = retained\n");
        let partial_schema = &TEST_SCHEMA_REGISTRY[0];
        let permission_before = session.document().kind().allows_lossless_local_draft();
        assert!(permission_before);
        assert_eq!(
            partial_schema.completeness,
            DatabaseConfigSchemaCompleteness::Partial
        );

        assert!(session.select_schema_from_registry(partial_schema, TEST_SCHEMA_REGISTRY));
        assert_eq!(
            session.document().kind().allows_lossless_local_draft(),
            permission_before
        );
        let rows = session.rows();
        let unknown = rows
            .iter()
            .find(|row| row.name() == Some("unknown_local_draft_key"))
            .unwrap();
        assert!(unknown.allows_local_draft_mutation());
        assert!(matches!(
            unknown.database_parameter(),
            DatabaseParameterMatch::VisibleUnvalidated
        ));
        assert_eq!(unknown.meaning_level(), VisualMeaningLevel::SyntaxOnly);
        // An edit still goes through, schema or not.
        let id = unknown.id();
        session
            .document_mut()
            .update_statement(id, "unknown_local_draft_key", "changed")
            .unwrap();
        assert!(std::ptr::eq(
            session.current_schema().unwrap(),
            partial_schema
        ));
    }

    #[test]
    fn schema_metadata_lookup_is_path_qualified_and_redacts_before_ui_copy() {
        let mut session = mysql_session("");
        let mysql_schema = &TEST_SCHEMA_REGISTRY[0];
        assert!(session.select_schema_from_registry(mysql_schema, TEST_SCHEMA_REGISTRY));

        let classified_value = "classified-value-X9";
        let source = format!(
            "[mysqld]\nfixture_payload = {classified_value}\n[client]\nfixture_payload = visible-client\nfixture-host = db01\nunknown_setting = visible-unknown\n"
        );
        let imported =
            VisualDocument::parse_database(database_artifact("mysql-option-file"), &source)
                .unwrap();
        // The syntax alone sees nothing secret here; the schema does.
        assert!(!imported.contains_sensitive_values());
        session.replace_document(imported);
        assert!(std::ptr::eq(
            session.current_schema().unwrap(),
            mysql_schema
        ));

        let rows = session.rows();
        let sensitive = rows
            .iter()
            .find(|row| {
                row.name() == Some("fixture_payload")
                    && matches!(row.database_parameter(), DatabaseParameterMatch::Matched(_))
            })
            .unwrap();
        assert!(sensitive.sensitive());
        assert!(!sensitive.allows_local_draft_mutation());
        assert!(sensitive.arguments().is_none());
        assert_eq!(sensitive.preview(), REDACTED_SCHEMA_VALUE);
        assert!(!format!("{sensitive:?}").contains(classified_value));
        assert!(!format!("{rows:?}").contains(classified_value));
        assert!(!session.can_copy());
        assert!(session.contains_sensitive_values());
        assert_eq!(session.document().raw_bytes(), source.as_bytes());

        // The same name in another group is not this parameter.
        let wrong_container = rows
            .iter()
            .find(|row| {
                row.name() == Some("fixture_payload")
                    && matches!(
                        row.database_parameter(),
                        DatabaseParameterMatch::VisibleUnvalidated
                    )
            })
            .unwrap();
        assert_eq!(wrong_container.arguments(), Some("visible-client"));
        assert!(!wrong_container.sensitive());

        let operational = rows
            .iter()
            .find(|row| row.name() == Some("fixture-host"))
            .unwrap();
        assert_eq!(operational.arguments(), Some("db01"));
        assert!(!operational.sensitive());

        let unknown = rows
            .iter()
            .find(|row| row.name() == Some("unknown_setting"))
            .unwrap();
        assert_eq!(unknown.arguments(), Some("visible-unknown"));
        assert!(matches!(
            unknown.database_parameter(),
            DatabaseParameterMatch::VisibleUnvalidated
        ));

        let DatabaseParameterMatch::Matched(parameter) = sensitive.database_parameter() else {
            unreachable!()
        };
        let terms = schema_parameter_search_terms(mysql_schema, parameter);
        for expected in [
            "test.fixture.capability",
            "Instance",
            "Restart",
            "High",
            "Config generator test-only schema reference",
        ] {
            assert!(terms.contains(&expected), "{expected}");
        }
        assert!(terms.iter().all(|term| !term.contains(classified_value)));
    }

    #[test]
    fn documented_defaults_show_for_five_goldendb_matches_without_changing_document() {
        let artifact = database_artifact("goldendb-proxy-ini");
        let schema = DATABASE_CONFIG_SCHEMAS
            .iter()
            .find(|schema| {
                database_schema_matches_artifact(schema, artifact)
                    && schema.version_label == "v6.1.03.10 exact"
            })
            .expect("registered GoldenDB v6.1.03.10 proxy.ini schema");
        assert_eq!(schema.parameters.len(), 5);
        assert!(
            database_schemas_for_artifact(artifact)
                .any(|candidate| std::ptr::eq(candidate, schema))
        );

        let source = "[SQLEXEC]\r\nupdate_grade = 2\r\nselect_grade = 4\r\nmvcc_grade = 1\r\n[GENERAL]\r\nswitch_insert_value_on_duplicate_key_update_sw = 0\r\ninsert_value_on_duplicate_key_update_usage_level = 1\r\nunknown_setting = retained\r\n";
        let mut session =
            VisualEditingSession::new(VisualDocument::parse_database(artifact, source).unwrap());
        let raw_before = session.document().raw_bytes().to_vec();
        let permission_before = session.document().kind().allows_lossless_local_draft();
        let row_permissions_before = session
            .rows()
            .iter()
            .map(VisualRow::allows_local_draft_mutation)
            .collect::<Vec<_>>();
        let can_copy_before = session.can_copy();
        let starter_before = database_starter_contents(artifact);

        assert!(!permission_before);
        assert_eq!(raw_before, source.as_bytes());
        assert_local_draft_mutation_denied(
            VisualDocument::database_starter(artifact),
            artifact.key,
        );

        assert!(session.select_schema(schema));
        let rows = session.rows();
        for (key, current_value, documented_default) in [
            ("update_grade", "2", "0"),
            ("select_grade", "4", "0"),
            ("mvcc_grade", "1", "0"),
            ("switch_insert_value_on_duplicate_key_update_sw", "0", "1"),
            ("insert_value_on_duplicate_key_update_usage_level", "1", "0"),
        ] {
            let row = rows
                .iter()
                .find(|row| row.name() == Some(key))
                .unwrap_or_else(|| panic!("missing GoldenDB row {key}"));
            assert_eq!(row.arguments(), Some(current_value), "{key}");
            let DatabaseParameterMatch::Matched(parameter) = row.database_parameter() else {
                panic!("{key} did not match its exact place");
            };
            assert_eq!(
                parameter.documented_default_for_display().as_deref(),
                Some(documented_default),
                "{key}"
            );
        }
        let unknown = rows
            .iter()
            .find(|row| row.name() == Some("unknown_setting"))
            .unwrap();
        assert!(matches!(
            unknown.database_parameter(),
            DatabaseParameterMatch::VisibleUnvalidated
        ));

        // Showing defaults changed nothing: bytes, permission, copy, starter.
        assert_eq!(session.document().raw_bytes(), raw_before);
        assert_eq!(
            session.document().kind().allows_lossless_local_draft(),
            permission_before
        );
        assert_eq!(
            rows.iter()
                .map(VisualRow::allows_local_draft_mutation)
                .collect::<Vec<_>>(),
            row_permissions_before
        );
        assert_eq!(session.can_copy(), can_copy_before);
        assert_eq!(database_starter_contents(artifact), starter_before);
        let id = rows
            .iter()
            .find(|row| row.name() == Some("update_grade"))
            .unwrap()
            .id();
        assert_local_draft_mutation_denied(
            session
                .document_mut()
                .update_statement(id, "update_grade", "9"),
            artifact.key,
        );
    }

    #[test]
    fn documented_defaults_render_empty_text_but_hide_invalid_sensitive_metadata() {
        const SECRET_DEFAULT: &str = "documented-default-must-not-reach-ui";
        static INVALID_REGISTRY: &[DatabaseConfigSchema] = &[DatabaseConfigSchema {
            parameters: &[DatabaseConfigParameterSchema {
                container_path: Some("mysqld"),
                canonical_key: "fixture-payload",
                exact_aliases: &["fixture_payload"],
                value_kind: DatabaseConfigSchemaValueKind::Text {
                    minimum_bytes: 1,
                    maximum_bytes: 256,
                    normalization: DatabaseConfigTextNormalization::Preserve,
                },
                documented_default: Some(DatabaseConfigDocumentedDefault::Text(SECRET_DEFAULT)),
                scope: DatabaseConfigSchemaScope::Instance,
                sensitivity: DatabaseConfigSchemaSensitivity::MayContainSecrets,
                activation: DatabaseConfigSchemaActivation::Restart,
                risk: DatabaseConfigSchemaRisk::High,
                risk_rationale: "Test-only sensitive row classification.",
                competition_rationale: "Proves that UI metadata redaction precedes value copying.",
                official_reference_id: "test:config-generator-schema",
                required_capability: Some("test.fixture.capability"),
            }],
            ..TEST_MYSQL_SCHEMA
        }];

        let source = "[mysqld]\nfixture_payload = current-sensitive-value\n";
        let mut session = mysql_session(source);
        let schema = &INVALID_REGISTRY[0];
        assert!(session.select_schema_from_registry(schema, INVALID_REGISTRY));
        let rows = session.rows();
        let row = rows
            .iter()
            .find(|row| row.name() == Some("fixture_payload"))
            .unwrap();
        let DatabaseParameterMatch::Matched(parameter) = row.database_parameter() else {
            panic!("invalid sensitive fixture did not match its exact path");
        };
        assert!(parameter.documented_default_for_display().is_none());
        assert!(
            visual_row_search_terms(row, Some(schema))
                .iter()
                .all(|term| !term.contains(SECRET_DEFAULT))
        );
        assert!(!format!("{row:?}{session:?}").contains(SECRET_DEFAULT));
        assert_eq!(session.document().raw_bytes(), source.as_bytes());

        static EMPTY_REGISTRY: &[DatabaseConfigSchema] = &[DatabaseConfigSchema {
            parameters: &[DatabaseConfigParameterSchema {
                container_path: Some("client"),
                canonical_key: "fixture-host",
                exact_aliases: &[],
                value_kind: DatabaseConfigSchemaValueKind::Text {
                    minimum_bytes: 0,
                    maximum_bytes: 256,
                    normalization: DatabaseConfigTextNormalization::Preserve,
                },
                documented_default: Some(DatabaseConfigDocumentedDefault::Text("")),
                scope: DatabaseConfigSchemaScope::Session,
                sensitivity: DatabaseConfigSchemaSensitivity::OperationalMetadata,
                activation: DatabaseConfigSchemaActivation::Reload,
                risk: DatabaseConfigSchemaRisk::Low,
                risk_rationale: "Test-only operational metadata classification.",
                competition_rationale: "Proves that operational metadata remains visible.",
                official_reference_id: "test:config-generator-schema",
                required_capability: None,
            }],
            ..TEST_MYSQL_SCHEMA
        }];
        let source = "[client]\nfixture-host = current-host\n";
        let mut session = mysql_session(source);
        let schema = &EMPTY_REGISTRY[0];
        assert!(session.select_schema_from_registry(schema, EMPTY_REGISTRY));
        let rows = session.rows();
        let row = rows
            .iter()
            .find(|row| row.name() == Some("fixture-host"))
            .unwrap();
        assert_eq!(row.arguments(), Some("current-host"));
        let DatabaseParameterMatch::Matched(parameter) = row.database_parameter() else {
            panic!("empty-default fixture did not match");
        };
        // An empty default is shown as empty, not hidden and not invented.
        assert_eq!(
            parameter.documented_default_for_display().as_deref(),
            Some("")
        );
        assert_eq!(session.document().raw_bytes(), source.as_bytes());
    }

    fn in_selector(artifact: &DatabaseConfigArtifactDefinition) -> bool {
        database_visual_artifacts(artifact.product).any(|candidate| candidate.key == artifact.key)
    }

    /// Every way of changing a read-only document is refused and leaves its
    /// bytes exactly as they were.
    fn assert_every_mutation_denied(document: &mut VisualDocument, id: VisualNodeId, key: &str) {
        let before = document.raw_bytes().to_vec();
        assert_local_draft_mutation_denied(
            document.add_statement(None, "new_key", "new_value"),
            key,
        );
        assert_eq!(document.raw_bytes(), before, "{key}");
        assert_local_draft_mutation_denied(document.add_container(None, "new_group", ""), key);
        assert_eq!(document.raw_bytes(), before, "{key}");
        assert_local_draft_mutation_denied(document.add_comment(None, "new comment"), key);
        assert_eq!(document.raw_bytes(), before, "{key}");
        assert_local_draft_mutation_denied(document.update_statement(id, "changed", "value"), key);
        assert_eq!(document.raw_bytes(), before, "{key}");
        assert_local_draft_mutation_denied(document.update_comment(id, "changed comment"), key);
        assert_eq!(document.raw_bytes(), before, "{key}");
        assert_local_draft_mutation_denied(document.remove(id), key);
        assert_eq!(document.raw_bytes(), before, "{key}");
        assert_local_draft_mutation_denied(document.move_up(id), key);
        assert_eq!(document.raw_bytes(), before, "{key}");
        assert_local_draft_mutation_denied(document.move_down(id), key);
        assert_eq!(document.raw_bytes(), before, "{key}");
    }

    /// A read-only file opens empty, names its own file, has no starter and
    /// says why it cannot be changed.
    fn assert_read_only_selection(
        artifact: &'static DatabaseConfigArtifactDefinition,
        file_name: &str,
    ) {
        let key = artifact.key;
        let kind = VisualDocumentKind::Database(artifact);
        let selection = VisualDocument::selection_document(kind).unwrap();
        assert_eq!(selection.kind(), kind, "{key}");
        assert_eq!(selection.text(), Some(""), "{key}");
        assert_eq!(selection.suggested_file_name(), file_name, "{key}");
        assert!(kind.read_only_reason().is_some(), "{key}");
        assert_eq!(database_starter_contents(artifact), "", "{key}");
        assert_local_draft_mutation_denied(VisualDocument::database_starter(artifact), key);
        assert_local_draft_mutation_denied(VisualDocument::competition_skeleton(kind), key);
    }

    #[test]
    fn readable_generated_json_pg_auto_yaml_and_xml_enter_the_selector() {
        for (key, parser) in [
            (
                "mysql-server-uuid",
                DatabaseVisualParser::Line(LineConfigDialect::MySqlOption),
            ),
            (
                "mysql-persisted-variables",
                DatabaseVisualParser::Structured(StructuredConfigDialect::Json),
            ),
            (
                "postgresql-auto-conf",
                DatabaseVisualParser::Line(LineConfigDialect::PostgresConf),
            ),
            (
                "oceanbase-obd-registered-config",
                DatabaseVisualParser::Structured(StructuredConfigDialect::Yaml),
            ),
            (
                "mogdb-ptk-deployment",
                DatabaseVisualParser::Structured(StructuredConfigDialect::Yaml),
            ),
            (
                "opengauss-om-cluster-xml",
                DatabaseVisualParser::Structured(StructuredConfigDialect::Xml),
            ),
            (
                "goldendb-proxy-ini",
                DatabaseVisualParser::Line(LineConfigDialect::Ini),
            ),
            (
                "kingbase-es-replication",
                DatabaseVisualParser::Line(LineConfigDialect::PostgresConf),
            ),
            (
                "gbase-8a-gcware-config",
                DatabaseVisualParser::Structured(StructuredConfigDialect::Gcware),
            ),
            (
                "gbase-8a-gnode-cluster-common",
                DatabaseVisualParser::Structured(StructuredConfigDialect::Json),
            ),
            (
                "gbase-8a-gcluster-cluster-common",
                DatabaseVisualParser::Structured(StructuredConfigDialect::Json),
            ),
            (
                "yashandb-yasdb-ini",
                DatabaseVisualParser::Line(LineConfigDialect::FlatKeyValue),
            ),
            (
                "tidb-tiflash-toml",
                DatabaseVisualParser::Line(LineConfigDialect::Toml),
            ),
            (
                "tidb-tiflash-learner-toml",
                DatabaseVisualParser::Line(LineConfigDialect::Toml),
            ),
            (
                "tidb-tiproxy-toml",
                DatabaseVisualParser::Line(LineConfigDialect::Toml),
            ),
            (
                "tidb-ticdc-toml",
                DatabaseVisualParser::Line(LineConfigDialect::Toml),
            ),
            (
                "tidb-ticdc-changefeed-toml",
                DatabaseVisualParser::Line(LineConfigDialect::Toml),
            ),
            (
                "tidb-lightning-toml",
                DatabaseVisualParser::Line(LineConfigDialect::Toml),
            ),
        ] {
            let artifact = database_artifact(key);
            assert!(
                artifact.is_file_visual_readable(),
                "{key} became unreadable"
            );
            assert!(artifact.has_source_backed_visual_parser(), "{key}");
            assert!(
                !artifact.allows_lossless_local_draft(),
                "{key} allowed a local draft"
            );
            assert_eq!(database_visual_parser(artifact), Some(parser), "{key}");
            assert!(in_selector(artifact), "{key} left the selector");
            assert!(database_product_has_visual_files(artifact.product), "{key}");
        }

        let mut plain_json = *database_artifact("mysql-persisted-variables");
        plain_json.dialect = DatabaseConfigDialect::Json;
        assert_eq!(
            structured_dialect(&plain_json),
            Some(StructuredConfigDialect::Json)
        );
    }

    #[test]
    fn mysql_auto_cnf_is_selectable_byte_exact_non_secret_and_fully_read_only() {
        const SOURCE: &str = "[auto]\nserver-uuid=8a94f357-aab4-11df-86ab-c80aa9429562\n";
        let artifact = database_artifact("mysql-server-uuid");
        assert_eq!(artifact.product, DatabaseConfigProduct::MySql);
        assert_eq!(
            artifact.component,
            DatabaseConfigComponent::ReplicationIdentity
        );
        assert_eq!(artifact.default_file_name, Some("auto.cnf"));
        assert_eq!(
            database_visual_parser(artifact),
            Some(DatabaseVisualParser::Line(LineConfigDialect::MySqlOption))
        );
        assert!(in_selector(artifact));
        assert!(!artifact.allows_lossless_local_draft());
        assert_read_only_selection(artifact, "auto.cnf");

        let mut document = VisualDocument::parse_database(artifact, SOURCE).unwrap();
        let rows = document.rows();
        let section = rows
            .iter()
            .find(|row| row.name() == Some("auto"))
            .expect("[auto] section");
        assert_eq!(section.kind(), VisualNodeKind::Container);
        let identity = rows
            .iter()
            .find(|row| row.name() == Some("server-uuid"))
            .expect("server-uuid");
        assert_eq!(identity.kind(), VisualNodeKind::Statement);
        assert_eq!(
            identity.arguments(),
            Some("8a94f357-aab4-11df-86ab-c80aa9429562")
        );
        assert!(!identity.sensitive());
        assert!(rows.iter().all(|row| !row.allows_local_draft_mutation()));
        assert!(document.is_structured());
        assert_eq!(document.raw_bytes(), SOURCE.as_bytes());
        assert_eq!(document.suggested_file_name(), "auto.cnf");
        assert!(!document.contains_sensitive_values() && document.can_copy());

        // Saved as a new local copy byte for byte; an existing file is not overwritten.
        let directory =
            std::env::temp_dir().join(format!("lovelyhawk-auto-cnf-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let destination = directory.join(document.suggested_file_name());
        document.write_new(&destination).unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), SOURCE.as_bytes());
        assert!(document.write_new(&destination).is_err());
        std::fs::remove_dir_all(&directory).unwrap();

        let id = identity.id();
        assert_every_mutation_denied(&mut document, id, artifact.key);

        for key in [
            "mysql-plugin-registry",
            "mysql-component-registry",
            "mariadb-plugin-registry",
        ] {
            let runtime = database_artifact(key);
            assert_eq!(database_visual_parser(runtime), None, "{key}");
            assert!(!in_selector(runtime), "{key}");
        }
        assert!(
            crate::database_config::artifacts_for(DatabaseConfigProduct::MariaDb).all(
                |candidate| {
                    candidate.default_file_name != Some("auto.cnf")
                        && candidate.component != DatabaseConfigComponent::ComponentRegistry
                }
            )
        );
    }

    #[test]
    fn readable_read_only_documents_preserve_bytes_and_reject_every_mutation() {
        for (key, source) in [
            (
                "mysql-persisted-variables",
                "{\"Version\": 2, \"mysql_server\": {\"max_connections\": 200}}\n",
            ),
            (
                "postgresql-auto-conf",
                "shared_buffers = '128MB'\nlog_connections = on\n",
            ),
            (
                "mogdb-ptk-deployment",
                "cluster_name: emergency\ninstances:\n  - host: db01\n",
            ),
            (
                "opengauss-om-cluster-xml",
                "<?xml version=\"1.0\"?><cluster><node name=\"db01\" /></cluster>\n",
            ),
            (
                "gbase-8s-sqlhosts",
                "# dbserver nettype hostname service options\ngbaseserver onsoctcp 192.0.2.10 9088 g=g_cluster_1\n",
            ),
            (
                "goldendb-proxy-ini",
                "conn_instance_for_mpp = 8880\ndefault_parallel_processing_mode = 1\n",
            ),
            (
                "kingbase-es-replication",
                "node_id = 1\nupstream_conninfo = 'host=192.0.2.10'\n",
            ),
            (
                "gbase-8a-gcware-config",
                "totem {\n  version: 2\n  interface {\n    member {\n      memberaddr: 10.0.0.1\n    }\n  }\n}\n",
            ),
            (
                "gbase-8a-gnode-cluster-common",
                "{\"role\":\"gnode\",\"host\":\"db01\"}\r\n",
            ),
            (
                "gbase-8a-gcluster-cluster-common",
                "{\"role\":\"gcluster\",\"host\":\"gc01\"}\r\n",
            ),
            (
                "tidb-tiflash-toml",
                "[flash]\r\nservice_addr = \"127.0.0.1:3930\"",
            ),
            (
                "tidb-tiflash-learner-toml",
                "[raftstore]\r\nstore-pool-size = 2",
            ),
            ("tidb-tiproxy-toml", "[proxy]\r\naddr = \"0.0.0.0:6000\""),
            ("tidb-ticdc-toml", "[log]\r\nlevel = \"info\""),
            (
                "tidb-ticdc-changefeed-toml",
                "case-sensitive = false\r\nforce-replicate = false",
            ),
            ("tidb-lightning-toml", "[lightning]\r\nlevel = \"info\""),
        ] {
            let artifact = database_artifact(key);
            let kind = VisualDocumentKind::Database(artifact);
            let mut document = VisualDocument::parse_database(artifact, source).unwrap();
            let id = document
                .rows()
                .first()
                .unwrap_or_else(|| panic!("readable artifact {key} has no visible row"))
                .id();
            assert_eq!(document.kind(), kind, "{key}");
            assert_eq!(document.text(), Some(source), "{key}");
            assert!(
                document
                    .rows()
                    .iter()
                    .all(|row| !row.allows_local_draft_mutation()),
                "{key}"
            );
            assert!(kind.read_only_reason().is_some(), "{key}");
            assert_local_draft_mutation_denied(VisualDocument::competition_skeleton(kind), key);
            assert_every_mutation_denied(&mut document, id, key);
        }
    }

    #[test]
    fn tidb_auxiliary_toml_catalog_is_byte_exact_read_only_and_schema_isolated() {
        let tidb_server = database_artifact("tidb-server-toml");
        assert!(
            DATABASE_CONFIG_SCHEMAS
                .iter()
                .any(|schema| database_schema_matches_artifact(schema, tidb_server)),
            "the isolation check requires the TiDB Server schema fixture"
        );
        for (key, component, default_file_name, source) in [
            (
                "tidb-tiflash-toml",
                DatabaseConfigComponent::TiFlash,
                "tiflash.toml",
                "[flash]\r\nservice_addr = \"127.0.0.1:3930\"",
            ),
            (
                "tidb-tiflash-learner-toml",
                DatabaseConfigComponent::TiFlashLearner,
                "tiflash-learner.toml",
                "[raftstore]\r\nstore-pool-size = 2",
            ),
            (
                "tidb-tiproxy-toml",
                DatabaseConfigComponent::TiProxy,
                "tiproxy.toml",
                "[proxy]\r\naddr = \"0.0.0.0:6000\"",
            ),
            (
                "tidb-ticdc-toml",
                DatabaseConfigComponent::TiCdc,
                "ticdc.toml",
                "[log]\r\nlevel = \"info\"",
            ),
            (
                "tidb-ticdc-changefeed-toml",
                DatabaseConfigComponent::TiCdcChangefeed,
                "changefeed.toml",
                "case-sensitive = false\r\nforce-replicate = false",
            ),
            (
                "tidb-lightning-toml",
                DatabaseConfigComponent::TiDbLightning,
                "tidb-lightning.toml",
                "[lightning]\r\nlevel = \"info\"",
            ),
        ] {
            let artifact = database_artifact(key);
            let kind = VisualDocumentKind::Database(artifact);
            assert_eq!(artifact.product, DatabaseConfigProduct::TiDb, "{key}");
            assert_eq!(artifact.component, component, "{key}");
            assert_ne!(artifact.component, DatabaseConfigComponent::TiDb, "{key}");
            assert_eq!(artifact.dialect, DatabaseConfigDialect::Toml, "{key}");
            assert_eq!(artifact.default_file_name, Some(default_file_name), "{key}");
            assert!(artifact.is_file_visual_readable(), "{key}");
            assert!(!artifact.allows_lossless_local_draft(), "{key}");
            assert_eq!(
                line_dialect(artifact),
                Some(LineConfigDialect::Toml),
                "{key}"
            );
            assert_eq!(structured_dialect(artifact), None, "{key}");
            assert!(in_selector(artifact), "{key}");
            // The TiDB Server schema never leaks onto another component's file.
            assert_eq!(database_schemas_for_artifact(artifact).count(), 0, "{key}");
            assert_read_only_selection(artifact, default_file_name);

            let mut document = VisualDocument::parse_database(artifact, source).unwrap();
            let mut session = VisualEditingSession::new(document.clone());
            for schema in DATABASE_CONFIG_SCHEMAS {
                assert!(
                    !session.select_schema(schema),
                    "{key} took {}",
                    schema.display_label
                );
            }
            let rows = document.rows();
            let id = rows
                .first()
                .unwrap_or_else(|| panic!("{key} has no visible TOML row"))
                .id();
            assert!(document.is_structured(), "{key}");
            assert_eq!(document.kind(), kind, "{key}");
            assert_eq!(document.raw_bytes(), source.as_bytes(), "{key}");
            assert_eq!(document.suggested_file_name(), default_file_name, "{key}");
            assert!(
                rows.iter().all(|row| !row.allows_local_draft_mutation()),
                "{key}"
            );
            assert_every_mutation_denied(&mut document, id, key);
        }
        let ticdc = database_artifact("tidb-ticdc-toml");
        assert_eq!(ticdc.default_file_name, Some("ticdc.toml"));
        assert_ne!(ticdc.default_file_name, Some("config.toml"));
        let tiproxy = database_artifact("tidb-tiproxy-toml");
        assert_eq!(tiproxy.component, DatabaseConfigComponent::TiProxy);
        assert_ne!(tiproxy.component, tidb_server.component);
    }

    #[test]
    fn gbase_8a_cluster_common_json_keeps_component_identity_and_read_only_boundaries() {
        let gnode_options = database_artifact("gbase-8a-gbase-options");
        let gcluster_options = database_artifact("gbase-8a-gcluster-options");
        assert_eq!(gnode_options.component, DatabaseConfigComponent::GNode);
        assert_eq!(
            gcluster_options.component,
            DatabaseConfigComponent::GCluster
        );
        assert!(
            crate::database_config::artifacts_for(DatabaseConfigProduct::GBase8a)
                .all(|artifact| artifact.default_file_name != Some("gnode.cnf")),
            "the catalogue must not invent gnode.cnf"
        );
        for (key, other_key, component, display_label, role, secret) in [
            (
                "gbase-8a-gnode-cluster-common",
                "gbase-8a-gcluster-cluster-common",
                DatabaseConfigComponent::GNode,
                "cluster_common.cnf · GNode",
                "gnode",
                "GNodeClusterSecret",
            ),
            (
                "gbase-8a-gcluster-cluster-common",
                "gbase-8a-gnode-cluster-common",
                DatabaseConfigComponent::GCluster,
                "cluster_common.cnf · GCluster",
                "gcluster",
                "GClusterClusterSecret",
            ),
        ] {
            let artifact = database_artifact(key);
            let other = database_artifact(other_key);
            let kind = VisualDocumentKind::Database(artifact);
            let source = format!(
                "{{\r\n  \"role\": \"{role}\",\r\n  \"host\": \"db01\",\r\n  \"password\": \"{secret}\"\r\n}}"
            );
            assert_eq!(artifact.product, DatabaseConfigProduct::GBase8a, "{key}");
            assert_eq!(artifact.component, component, "{key}");
            assert_ne!(artifact.component, other.component, "{key}");
            assert_eq!(
                database_artifact_display_label(artifact),
                display_label,
                "{key}"
            );
            assert_eq!(kind.artifact_label(), display_label, "{key}");
            assert_ne!(
                database_artifact_display_label(artifact),
                database_artifact_display_label(other),
                "{key}"
            );
            assert_eq!(artifact.dialect, DatabaseConfigDialect::Json, "{key}");
            assert!(!artifact.allows_lossless_local_draft(), "{key}");
            assert_eq!(line_dialect(artifact), None, "{key}");
            assert_eq!(
                database_visual_parser(artifact),
                Some(DatabaseVisualParser::Structured(
                    StructuredConfigDialect::Json
                )),
                "{key}"
            );
            assert!(in_selector(artifact), "{key}");
            assert_eq!(
                artifact.default_file_name,
                Some("cluster_common.cnf"),
                "{key}"
            );
            assert_read_only_selection(artifact, "cluster_common.cnf");
            assert_ne!(
                VisualDocument::selection_document(kind).unwrap().kind(),
                VisualDocumentKind::Database(other),
                "{key} selected the other role"
            );

            let mut document = VisualDocument::parse_database(artifact, &source).unwrap();
            let rows = document.rows();
            let id = rows
                .first()
                .unwrap_or_else(|| panic!("{key} has no structured row"))
                .id();
            let password = rows
                .iter()
                .find(|row| row.name() == Some("password"))
                .unwrap_or_else(|| panic!("{key} lost its password member"));
            assert!(document.is_structured(), "{key}");
            assert_ne!(
                document.kind(),
                VisualDocumentKind::Database(other),
                "{key}"
            );
            assert_eq!(document.raw_bytes(), source.as_bytes(), "{key}");
            assert_eq!(
                document.suggested_file_name(),
                "cluster_common.cnf",
                "{key}"
            );
            assert!(
                document.contains_sensitive_values() && !document.can_copy(),
                "{key}"
            );
            assert!(password.sensitive(), "{key}");
            assert_eq!(password.preview(), REDACTED_SCHEMA_VALUE, "{key}");
            assert!(password.arguments().is_none(), "{key}");
            assert!(!format!("{document:?}{rows:?}").contains(secret), "{key}");
            assert!(
                rows.iter().all(|row| !row.allows_local_draft_mutation()),
                "{key}"
            );
            assert_every_mutation_denied(&mut document, id, key);
        }
    }

    #[test]
    fn yashandb_23_5_yasdb_ini_is_selectable_byte_exact_and_fully_read_only() {
        let artifact = database_artifact("yashandb-yasdb-ini");
        let source = "LISTENER_ADDR=127.0.0.1\r\nMAX_SESSIONS=1024\r\nUNKNOWN_23_5_KEY=preserve-this-byte-exact";
        assert_eq!(artifact.product, DatabaseConfigProduct::Yashan);
        assert_eq!(artifact.dialect, DatabaseConfigDialect::KeyValue);
        assert!(artifact.is_file_visual_readable());
        assert!(!artifact.allows_lossless_local_draft());
        assert_eq!(
            line_dialect(artifact),
            Some(LineConfigDialect::FlatKeyValue)
        );
        assert_eq!(structured_dialect(artifact), None);
        assert!(in_selector(artifact));
        assert!(database_product_has_visual_files(
            DatabaseConfigProduct::Yashan
        ));
        assert_eq!(
            first_database_visual_artifact(DatabaseConfigProduct::Yashan)
                .map(|candidate| candidate.key),
            Some("yashandb-yasdb-ini")
        );
        assert_eq!(artifact.default_file_name, Some("yasdb.ini"));
        assert_eq!(
            database_schemas_for_artifact(artifact).count(),
            1,
            "yasdb.ini must expose exactly one reviewed fixed-version schema"
        );
        assert_read_only_selection(artifact, "yasdb.ini");

        let mut document = VisualDocument::parse_database(artifact, source).unwrap();
        let rows = document.rows();
        let id = rows.first().expect("yasdb.ini must expose a row").id();
        assert!(document.is_structured());
        assert_eq!(document.raw_bytes(), source.as_bytes());
        assert_eq!(document.suggested_file_name(), "yasdb.ini");
        assert!(rows.iter().all(|row| !row.allows_local_draft_mutation()));
        for key in ["LISTENER_ADDR", "MAX_SESSIONS", "UNKNOWN_23_5_KEY"] {
            assert!(
                rows.iter().any(|row| row.name() == Some(key)),
                "{key} was not visible"
            );
        }
        assert_every_mutation_denied(&mut document, id, artifact.key);
    }

    #[test]
    fn sequoia_quick_deploy_cross_role_imports_are_whole_sensitive_opaque_and_keep_catalog_name() {
        const CLUSTER: &str =
            "role,groupName,hostName,serviceName,dbPath\ndata,group1,localhost,11820,/srv/data\n";
        const SQL_INSTANCE: &str =
            "instanceName,port,databaseDir,coordAddr\nmyinst,3306,/srv/mysql,-\n";
        for (key, default_file_name, cross_role_source) in [
            (
                "sequoiadb-quick-deploy-cluster",
                "sequoiadb.conf",
                SQL_INSTANCE,
            ),
            ("sequoiadb-quick-deploy-mysql", "mysql.conf", CLUSTER),
            ("sequoiadb-quick-deploy-mariadb", "mariadb.conf", CLUSTER),
            (
                "sequoiadb-quick-deploy-postgresql",
                "postgresql.conf",
                CLUSTER,
            ),
        ] {
            let document =
                VisualDocument::parse_database(database_artifact(key), cross_role_source).unwrap();
            let rows = document.rows();
            assert!(
                !document.is_structured(),
                "{key} accepted a cross-role header"
            );
            assert!(
                document.contains_sensitive_values() && !document.can_copy(),
                "{key}"
            );
            assert_eq!(document.raw_bytes(), cross_role_source.as_bytes(), "{key}");
            assert_eq!(document.suggested_file_name(), default_file_name, "{key}");
            assert_eq!(rows.len(), 1, "{key} cross-role input was not whole opaque");
            assert_eq!(rows[0].kind(), VisualNodeKind::Opaque, "{key}");
            assert!(rows[0].sensitive(), "{key}");
            assert_eq!(rows[0].preview(), REDACTED_SCHEMA_VALUE, "{key}");
            assert!(
                rows.iter().all(|row| !row.allows_local_draft_mutation()),
                "{key}"
            );
        }
    }

    #[test]
    fn sequoia_quick_deploy_sensitive_and_local_opaque_rows_block_copy_but_keep_safe_sibling() {
        let secret = "ApiNeverShow";
        let odd_quote_secret = "OddNeverShow";
        let bad_bracket_secret = "BracketNeverShow";
        let source = format!(
            "instanceName,port,databaseDir,coordAddr\r\napi,6101,/srv/api_key={secret},-\r\nodd,6102,/srv/\"{odd_quote_secret},-\r\nbad-{bad_bracket_secret},6103,/srv,[host:1,host:2\r\nsafe,6104,/srv/plain,[host:1,host:2]\r\n"
        );
        let document = VisualDocument::parse_database(
            database_artifact("sequoiadb-quick-deploy-mariadb"),
            &source,
        )
        .unwrap();
        let rows = document.rows();
        let opaque = rows
            .iter()
            .filter(|row| row.kind() == VisualNodeKind::Opaque)
            .collect::<Vec<_>>();
        assert!(document.is_structured());
        assert!(document.contains_sensitive_values() && !document.can_copy());
        assert_eq!(document.raw_bytes(), source.as_bytes());
        assert_eq!(document.suggested_file_name(), "mariadb.conf");
        assert_eq!(opaque.len(), 2);
        assert!(
            opaque
                .iter()
                .all(|row| row.sensitive() && row.preview() == REDACTED_SCHEMA_VALUE)
        );
        assert!(rows.iter().any(|row| {
            row.kind() == VisualNodeKind::Statement
                && row.sensitive()
                && row.preview() == REDACTED_SCHEMA_VALUE
                && row.arguments().is_none()
        }));
        for safe_value in ["safe", "/srv/plain", "[host:1,host:2]"] {
            assert!(
                rows.iter().any(|row| row.arguments() == Some(safe_value)),
                "safe sibling field {safe_value} was hidden"
            );
        }
        let debug = format!("{document:?}{rows:?}");
        for hidden in [secret, odd_quote_secret, bad_bracket_secret] {
            assert!(!debug.contains(hidden));
            assert!(filtered_visual_row_indices(&rows, None, hidden).is_empty());
        }
    }

    #[test]
    fn sequoia_quick_deploy_opaque_rows_redact_and_all_mutation_starter_deploy_paths_stay_closed() {
        for (key, secret, source) in [
            (
                "sequoiadb-quick-deploy-cluster",
                "cluster-secret-token",
                "role,groupName,hostName,serviceName,dbPath\n\"cluster-secret-token\",group1,sdbserver1,11820,/srv/data\n",
            ),
            (
                "sequoiadb-quick-deploy-mysql",
                "mysql-secret-token",
                "instanceName,port,databaseDir,coordAddr\n\"mysql-secret-token\",3306,/srv/mysql,[localhost:50000,localhost:11810]\n",
            ),
            (
                "sequoiadb-quick-deploy-mariadb",
                "mariadb-secret-token",
                "instanceName,port,databaseDir,coordAddr\n\"mariadb-secret-token\",6101,/srv/mariadb,[localhost:50000,localhost:11810]\n",
            ),
            (
                "sequoiadb-quick-deploy-postgresql",
                "postgresql-secret-token",
                "instanceName,port,databaseDir,coordAddr\n\"postgresql-secret-token\",5432,/srv/postgresql,localhost:50000\n",
            ),
        ] {
            let artifact = database_artifact(key);
            let kind = VisualDocumentKind::Database(artifact);
            let mut document = VisualDocument::parse_database(artifact, source).unwrap();
            let rows = document.rows();
            let opaque = rows
                .iter()
                .find(|row| row.kind() == VisualNodeKind::Opaque)
                .unwrap_or_else(|| panic!("{key} did not preserve unknown quoting as opaque"));
            let opaque_id = opaque.id();
            assert!(document.is_structured(), "{key} hid safe sibling rows");
            assert!(
                document.contains_sensitive_values() && !document.can_copy(),
                "{key}"
            );
            assert!(opaque.sensitive(), "{key}");
            assert_eq!(opaque.preview(), REDACTED_SCHEMA_VALUE, "{key}");
            assert!(!format!("{document:?}{rows:?}").contains(secret), "{key}");
            assert_eq!(document.raw_bytes(), source.as_bytes(), "{key}");
            assert_eq!(database_starter_contents(artifact), "", "{key}");
            assert!(kind.read_only_reason().is_some(), "{key}");
            assert_local_draft_mutation_denied(VisualDocument::database_starter(artifact), key);
            assert_local_draft_mutation_denied(VisualDocument::competition_skeleton(kind), key);
            assert_every_mutation_denied(&mut document, opaque_id, key);
        }
    }

    fn postgresql_schema(version: &str) -> &'static DatabaseConfigSchema {
        DATABASE_CONFIG_SCHEMAS
            .iter()
            .find(|schema| {
                schema.binding.product == DatabaseConfigProduct::PostgreSql
                    && schema.version_label.contains(version)
                    && schema
                        .parameters
                        .iter()
                        .any(|parameter| parameter.canonical_key == "max_connections")
            })
            .unwrap_or_else(|| panic!("PostgreSQL {version} schema with max_connections"))
    }

    fn parameter_index(schema: &DatabaseConfigSchema, key: &str) -> usize {
        schema
            .parameters
            .iter()
            .position(|parameter| parameter.canonical_key == key)
            .unwrap()
    }

    fn assignment(query: &str) -> DatabaseParameterAssignment {
        match crate::configuration_goal::resolve_database_parameter_assignment(query) {
            crate::configuration_goal::DatabaseParameterAssignmentResolution::Ready(assignment) => {
                assignment
            }
            other => panic!("{query:?} did not resolve: {other:?}"),
        }
    }

    #[test]
    fn a_parameter_value_is_written_once_replaced_in_place_and_read_back() {
        let schema = postgresql_schema("16");
        let artifact = database_artifact(schema.binding.artifact_key);
        let index = parameter_index(schema, "max_connections");
        let mut session = VisualEditingSession::new(
            VisualDocument::parse_database(artifact, "port = 5432\n").unwrap(),
        );
        assert_eq!(
            session.stage_parameter_value(index, "250").unwrap_err(),
            DatabaseParameterValueError::NoSchema
        );
        assert!(session.select_schema(schema));

        let first = session.stage_parameter_value(index, "250").unwrap();
        assert_eq!(first.text(), Some("port = 5432\nmax_connections = 250\n"));
        session.replace_document(first);
        let second = session.stage_parameter_value(index, "300").unwrap();
        let text = second.text().unwrap();
        assert!(text.contains("max_connections = 300") && !text.contains("250"));
        assert_eq!(text.matches("max_connections").count(), 1);
        // Staging never changes the session's own document.
        assert!(
            session
                .document()
                .text()
                .unwrap()
                .contains("max_connections = 250")
        );

        // A value the schema refuses (this schema allows 1 to 32 bytes of
        // text) is reported, never written.
        for refused in ["x".repeat(33), "\u{202e}300".to_owned()] {
            assert!(
                matches!(
                    session.stage_parameter_value(index, &refused),
                    Err(DatabaseParameterValueError::Draft(_))
                ),
                "{refused:?}"
            );
        }
    }

    #[test]
    fn duplicate_read_only_and_hidden_parameters_are_refused_without_change() {
        let schema = postgresql_schema("16");
        let artifact = database_artifact(schema.binding.artifact_key);
        let index = parameter_index(schema, "max_connections");
        let draft = validate_database_parameter_goal_value(schema, index, "300").unwrap();

        let duplicate = VisualDocument::parse_database(
            artifact,
            "max_connections = 100\nmax_connections = 200\n",
        )
        .unwrap();
        assert_eq!(
            stage_database_parameter(&duplicate, schema, index, &draft).unwrap_err(),
            DatabaseParameterStageError::Duplicate
        );
        assert_eq!(
            duplicate.text(),
            Some("max_connections = 100\nmax_connections = 200\n")
        );

        let other_file =
            VisualDocument::parse_database(database_artifact("mysql-option-file"), "").unwrap();
        assert_eq!(
            stage_database_parameter(&other_file, schema, index, &draft).unwrap_err(),
            DatabaseParameterStageError::TargetMismatch
        );
        let nginx = VisualDocument::nginx_competition_skeleton().unwrap();
        assert_eq!(
            stage_database_parameter(&nginx, schema, index, &draft).unwrap_err(),
            DatabaseParameterStageError::NotDatabaseDocument
        );
        assert_eq!(
            stage_database_parameter(&duplicate, schema, schema.parameters.len(), &draft)
                .unwrap_err(),
            DatabaseParameterStageError::ParameterGone
        );
    }

    #[test]
    fn a_missing_option_group_is_created_for_the_parameter_and_an_existing_one_reused() {
        let (schema, index) = DATABASE_CONFIG_SCHEMAS
            .iter()
            .filter(|schema| schema.binding.artifact_key == "mysql-option-file")
            .find_map(|schema| {
                let index = schema.parameters.iter().position(|parameter| {
                    parameter.canonical_key == "max_connections"
                        && parameter.container_path == Some("mysqld")
                })?;
                validate_database_parameter_goal_value(schema, index, "400")
                    .ok()
                    .map(|_| (schema, index))
            })
            .expect("a MySQL schema with a draftable [mysqld] max_connections");
        let artifact = database_artifact("mysql-option-file");
        let draft = validate_database_parameter_goal_value(schema, index, "400").unwrap();

        let empty = VisualDocument::parse_database(artifact, "").unwrap();
        let staged = stage_database_parameter(&empty, schema, index, &draft).unwrap();
        assert_eq!(staged.text(), Some("[mysqld]\nmax_connections=400"));

        let grouped =
            VisualDocument::parse_database(artifact, "[MYSQLD]\nport=3306\n[client]\nport=3306\n")
                .unwrap();
        let staged = stage_database_parameter(&grouped, schema, index, &draft).unwrap();
        let text = staged.text().unwrap();
        assert_eq!(
            text.matches("[MYSQLD]").count() + text.matches("[mysqld]").count(),
            1
        );
        assert!(text.find("max_connections=400").unwrap() < text.find("[client]").unwrap());

        let two_groups =
            VisualDocument::parse_database(artifact, "[mysqld]\nport=3306\n[mysqld]\nuser=mysql\n")
                .unwrap();
        assert_eq!(
            stage_database_parameter(&two_groups, schema, index, &draft).unwrap_err(),
            DatabaseParameterStageError::AmbiguousGroup
        );
    }

    #[test]
    fn an_assignment_lands_in_the_open_draft_or_a_new_one_but_never_sets_unsaved_edits_aside() {
        let postgres_16 = postgresql_schema("16");
        let postgres_17 = DATABASE_CONFIG_SCHEMAS
            .iter()
            .find(|schema| {
                schema.binding.product == DatabaseConfigProduct::PostgreSql
                    && schema.version_label.starts_with(">=17.")
                    && schema.binding.artifact_key == postgres_16.binding.artifact_key
                    && schema
                        .parameters
                        .iter()
                        .any(|parameter| parameter.canonical_key == "max_connections")
            })
            .expect("PostgreSQL 17 same-file schema");
        let artifact = database_artifact(postgres_16.binding.artifact_key);
        let query = format!("PostgreSQL 16 @{} max_connections = 300", artifact.key);
        let ready = assignment(&query);

        // A clean document of another file is replaced by a new draft holding only the line.
        let nginx =
            VisualEditingSession::new(VisualDocument::nginx_competition_skeleton().unwrap());
        let staged = nginx.stage_assignment(&ready, false).unwrap();
        assert_eq!(
            staged.document().text().map(str::trim),
            Some("max_connections = 300")
        );
        assert!(std::ptr::eq(staged.current_schema().unwrap(), postgres_16));
        assert_eq!(staged.selected_parameter(), Some(ready.parameter_index()));
        assert!(nginx.document().text().unwrap().contains("events"));

        // Unsaved edits of another file are never set aside.
        assert_eq!(
            nginx.stage_assignment(&ready, true).unwrap_err(),
            DatabaseAssignmentPreflightError::OtherFileUnsaved
        );

        // The same file under the same schema takes the line in place.
        let mut same = VisualEditingSession::new(
            VisualDocument::parse_database(artifact, "shared_buffers = 128MB\n").unwrap(),
        );
        assert!(same.select_schema(postgres_16));
        let staged = same.stage_assignment(&ready, true).unwrap();
        assert_eq!(
            staged.document().text(),
            Some("shared_buffers = 128MB\nmax_connections = 300\n")
        );

        // Unsaved edits under another version of the same file are not mixed in.
        assert!(same.select_schema(postgres_17));
        assert_eq!(
            same.stage_assignment(&ready, true).unwrap_err(),
            DatabaseAssignmentPreflightError::OtherSchemaUnsaved
        );
        assert_eq!(same.document().text(), Some("shared_buffers = 128MB\n"));
        // Clean, it starts a new draft under the assignment's own version instead.
        let staged = same.stage_assignment(&ready, false).unwrap();
        assert!(std::ptr::eq(staged.current_schema().unwrap(), postgres_16));
        assert_eq!(
            staged.document().text().map(str::trim),
            Some("max_connections = 300")
        );
    }
}
