//! A configuration file edited as a tree — Nginx and Apache httpd. The
//! document lives here; the page holds only a handle, a revision and the rows
//! it was shown.
//!
//! Every edit goes through the core document, which rebuilds the text and
//! reparses it, so a field can never become two statements and an untouched
//! file stays byte for byte what it was. Rows that hold hidden values are
//! shown hidden and cannot be edited, removed, moved or built on. Reading a
//! local file and handing out the whole text are the host's alone: those two
//! actions carry a path or the contents and never come from the page.
use crate::config_api::ConfigApi;
use crate::config_goal_api::{
    ConfigGoalSearchDto, GoalAssignmentDto, GoalBinding, PendingGoal, PendingGoalState,
    goal_results, preflight_key, rejection_key, target_dto,
};
use lovelyhawk_core::{
    CoreError, CoreResult,
    apache_visual::{ApacheVisualDocument, ApacheVisualNodeKind},
    configuration_goal::{
        ConfigurationGoalAvailability, DatabaseParameterAssignment,
        DatabaseParameterAssignmentResolution, database_parameter_goal_availability,
        resolve_database_parameter_assignment, revalidate_database_parameter_assignment_value,
        select_database_parameter_assignment_candidate,
    },
    database_config::{
        DATABASE_CONFIG_PRODUCTS, DatabaseConfigArtifactDefinition, DatabaseConfigDialect,
        DatabaseConfigProduct, DatabaseConfigProductDefinition,
    },
    database_config_schema::{
        DATABASE_CONFIG_SCHEMAS, DatabaseConfigSchema, DatabaseConfigSchemaActivation,
        DatabaseConfigSchemaCompleteness, DatabaseConfigSchemaRisk, DatabaseConfigSchemaScope,
        DatabaseConfigSchemaSensitivity, DatabaseConfigSchemaValueKind, DatabaseConfigVersion,
        DatabaseConfigVersionSelector,
    },
    line_config_visual::{LineConfigDialect, LineConfigNodeKind, LineConfigVisualDocument},
    nginx_visual::{NginxVisualDocument, NginxVisualNodeKind},
    visual_document::{
        DatabaseAssignmentPreflightError, DatabaseParameterMatch, DatabaseParameterStageError,
        DatabaseParameterValueError, VisualDocument, VisualDocumentKind, VisualEditingSession,
        VisualMeaningLevel, VisualNodeId, VisualNodeKind, VisualReadOnlyReason,
        database_artifact_by_key, database_artifact_display_label,
        database_schema_matches_artifact, database_schemas_for_artifact, database_visual_artifacts,
        database_visual_parser, schema_parameter_search_terms, schema_value_kind_description,
        visual_row_search_terms,
    },
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const MAX_DOCUMENTS: usize = 8;
const MAX_SEARCH_TERMS: usize = 64;
const MAX_SCHEMAS: usize = 32;
const MAX_PARAMETERS: usize = 512;
/// Edits can take a while; a document unused this long is let go.
const IDLE_LIMIT: Duration = Duration::from_secs(4 * 60 * 60);
const MAX_ROWS: usize = 2_000;
const MAX_VIEW_ROW_BYTES: usize = 1_536 * 1024;
const MAX_ROW_ARGUMENT_BYTES: usize = 4 * 1024;
const MAX_TEXT_BYTES: usize = 128 * 1024;
const MAX_COPY_BYTES: usize = 256 * 1024;
const MAX_FIELD_BYTES: usize = 64 * 1024;
const MAX_HANDLE_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum VisualProduct {
    Nginx,
    Apache,
    Redis,
    Haproxy,
    Mysql,
    Mariadb,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum VisualTemplate {
    Blank,
    Competition,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum VisualAddKind {
    Directive,
    Block,
    Comment,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum VisualDirection {
    Up,
    Down,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum VisualExportPurpose {
    Copy,
    Save,
}

#[derive(Deserialize)]
#[serde(
    tag = "action",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum ConfigVisualRequest {
    New {
        product: VisualProduct,
        template: VisualTemplate,
    },
    OpenQuick {
        handle: String,
        revision: u64,
        artifact_key: String,
    },
    View {
        document_handle: String,
        revision: u64,
    },
    Add {
        document_handle: String,
        revision: u64,
        parent_id: Option<String>,
        kind: VisualAddKind,
        name: Option<String>,
        arguments: Option<String>,
        text: Option<String>,
        /// A comment written on the line above the new directive or block,
        /// in the same edit: both are added or neither is.
        note: Option<String>,
    },
    Update {
        document_handle: String,
        revision: u64,
        node_id: String,
        name: Option<String>,
        arguments: Option<String>,
        text: Option<String>,
    },
    Remove {
        document_handle: String,
        revision: u64,
        node_id: String,
    },
    Move {
        document_handle: String,
        revision: u64,
        node_id: String,
        direction: VisualDirection,
    },
    Close {
        document_handle: String,
        revision: u64,
    },
    /// Host only: the path comes from the system's open dialog.
    Import {
        product: VisualProduct,
        selected_path: PathBuf,
    },
    /// The catalogued database files the editor can open, by product.
    DatabaseCatalog,
    /// A catalogued database file: its reviewed starting content, or an
    /// empty read-only view for a file that is never drafted here.
    NewDatabase { artifact_key: String },
    /// Host only: a local copy of a catalogued database file.
    ImportDatabase {
        artifact_key: String,
        selected_path: PathBuf,
    },
    /// Chooses the reviewed schema (version) the rows are read against, or
    /// none. The file's bytes do not change.
    SelectSchema {
        document_handle: String,
        revision: u64,
        schema: Option<usize>,
    },
    /// Sets one parameter of the chosen schema, checked by it and read back.
    SetParameter {
        document_handle: String,
        revision: u64,
        parameter_index: usize,
        value: String,
    },
    /// Host only: the whole text, for the clipboard or a file the host writes.
    Export {
        document_handle: String,
        revision: u64,
        purpose: VisualExportPurpose,
    },
    /// The generator's search box: goals, parameters, files and gaps, or an
    /// assignment held for confirmation. `document` is the visual document
    /// the page has open, if any, which a confirmed value may land in.
    GoalSearch {
        query: String,
        document: Option<GoalDocument>,
    },
    /// Picks one exact candidate of an ambiguous assignment.
    GoalChoose {
        lease: String,
        candidate: usize,
        document: Option<GoalDocument>,
    },
    /// Writes the held assignment, with the value as the page now shows it,
    /// into the open document or a new one.
    GoalConfirm {
        lease: String,
        value: String,
        document: Option<GoalDocument>,
    },
}

/// The visual document the page has open, as it shows it.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GoalDocument {
    document_handle: String,
    revision: u64,
    /// Whether it holds edits not yet saved to a file.
    unsaved: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConfigVisualRowDto {
    id: String,
    parent_id: Option<String>,
    depth: usize,
    kind: &'static str,
    name: Option<String>,
    arguments: Option<String>,
    preview: String,
    child_count: usize,
    truncated: bool,
    editable: bool,
    sensitive: bool,
    /// A database file's row: what its meaning rests on ("catalog" for a
    /// parameter the chosen schema describes, else "syntax"); null otherwise.
    meaning: Option<&'static str>,
    /// The described parameter's place in the chosen schema's list.
    parameter_index: Option<usize>,
    /// What a database file's row can be found by, decided by core: kind,
    /// name and reviewed parameter words, never values. Empty otherwise.
    search_terms: Vec<String>,
}

/// What a database file is, what it is read against, and that schema's
/// reviewed parameters, present in the file or not.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConfigVisualDatabaseDto {
    product: &'static str,
    product_label: &'static str,
    artifact_key: &'static str,
    file_label: &'static str,
    syntax: &'static str,
    /// Why the file is read and saved as a copy only, or null.
    read_only: Option<&'static str>,
    schemas: Vec<ConfigVisualSchemaDto>,
    schema_index: Option<usize>,
    parameters: Vec<ConfigVisualParameterDto>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConfigVisualSchemaDto {
    index: usize,
    /// Product, versions and edition in words, e.g. "PostgreSQL 16.x".
    label: String,
    /// The exact range of versions, e.g. "16.0.0 及以上、低于 17.0.0".
    version: String,
    complete: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConfigVisualParameterDto {
    index: usize,
    key: &'static str,
    aliases: Vec<&'static str>,
    group: Option<&'static str>,
    value_kind: &'static str,
    value_domain: String,
    scope: &'static str,
    activation: &'static str,
    risk: &'static str,
    sensitivity: &'static str,
    rationale: &'static str,
    purpose: &'static str,
    reference: Option<&'static str>,
    capability: Option<&'static str>,
    documented_default: Option<String>,
    /// Whether a value can be set here: public, editable file, no extra capability.
    settable: bool,
    /// How many lines of the file are this parameter.
    occurrences: usize,
    search_terms: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConfigVisualDatabaseCatalogDto {
    products: Vec<ConfigVisualDatabaseProductDto>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConfigVisualDatabaseProductDto {
    product: &'static str,
    label: &'static str,
    files: Vec<ConfigVisualDatabaseFileDto>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConfigVisualDatabaseFileDto {
    key: &'static str,
    label: &'static str,
    syntax: &'static str,
    read_only: Option<&'static str>,
    schemas: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConfigVisualViewDto {
    document_handle: String,
    revision: u64,
    product: &'static str,
    source: &'static str,
    structured: bool,
    /// Parts kept as written because they are not this syntax (Apache <Perl>).
    partly_opaque: bool,
    contains_sensitive: bool,
    total_bytes: usize,
    suggested_name: &'static str,
    rows: Vec<ConfigVisualRowDto>,
    total_rows: usize,
    rows_truncated: bool,
    /// The whole text, when it is UTF-8, small enough and holds nothing hidden.
    text: Option<String>,
    text_truncated: bool,
    copy_allowed: bool,
    /// Set for a catalogued database file, null otherwise.
    database: Option<Box<ConfigVisualDatabaseDto>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConfigVisualClosedDto {
    closed: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConfigVisualExportDto {
    suggested_name: &'static str,
    contents: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub(crate) enum ConfigVisualResponse {
    View(ConfigVisualViewDto),
    Closed(ConfigVisualClosedDto),
    Export(ConfigVisualExportDto),
    DatabaseCatalog(ConfigVisualDatabaseCatalogDto),
    GoalSearch(Box<ConfigGoalSearchDto>),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ConfigVisualError {
    Invalid,
    Stale,
    Capacity,
    Unsupported,
    Sensitive,
    NotBlock,
    Rejected,
    ReadFailed,
    NotText,
    TooLarge,
    /// The database file is read and saved as a copy only.
    ReadOnly,
    /// A parameter value was asked for with no schema chosen.
    NoSchema,
    /// The chosen schema refuses this parameter or this value.
    ValueRefused,
    /// The parameter is written more than once; none is changed.
    ParameterDuplicate,
    /// The one line holding the parameter cannot be changed here.
    ParameterLocked,
    /// The search sentence is too long or carries control characters.
    GoalQueryRefused,
    /// The assignment is no longer the one shown, or the document moved on.
    GoalStale,
    /// The value typed into the confirmation is outside the parameter's rules.
    GoalValueRefused,
    /// Another document holds unsaved edits; it is not set aside.
    GoalOtherFileUnsaved,
    /// This file holds unsaved edits read against another version.
    GoalOtherVersionUnsaved,
}

/// The editable syntaxes, behind one set of operations. Cloned only to try a
/// two-step edit before keeping it.
#[derive(Clone)]
enum Document {
    Nginx(NginxVisualDocument),
    Apache(ApacheVisualDocument),
    /// redis.conf: flat lines, no blocks.
    Redis(LineConfigVisualDocument),
    /// haproxy.cfg: sections named by a keyword, each owning its lines.
    HaProxy(LineConfigVisualDocument),
    /// my.cnf for MySQL: [groups], each owning its options, and include lines.
    MySql(LineConfigVisualDocument),
    /// The same option-file syntax, read by a MariaDB server.
    MariaDb(LineConfigVisualDocument),
    /// A catalogued database file, with the schema chosen for it. Core owns
    /// its read-only policy, schema meaning and redaction.
    Database(Box<VisualEditingSession>),
}

/// A row as the page sees it, whichever syntax it came from.
struct Row {
    id: u128,
    parent: Option<u128>,
    depth: usize,
    kind: &'static str,
    name: Option<String>,
    arguments: Option<String>,
    preview: String,
    child_count: usize,
    truncated: bool,
    editable: bool,
    sensitive: bool,
    meaning: Option<&'static str>,
    parameter_index: Option<usize>,
    search_terms: Vec<String>,
}

/// Runs `$tree` with `$d` bound to an Nginx or Apache tree, and `$line` with
/// `$r` bound to a Redis or HAProxy line document, whose operations are named
/// for lines.
macro_rules! each {
    ($document:expr, $d:ident => $tree:expr, $r:ident => $line:expr, $s:ident => $database:expr) => {
        match $document {
            Document::Nginx($d) => $tree,
            Document::Apache($d) => $tree,
            Document::Redis($r)
            | Document::HaProxy($r)
            | Document::MySql($r)
            | Document::MariaDb($r) => $line,
            Document::Database($s) => $database,
        }
    };
}

/// The node a page named, in the database file's current revision.
fn database_node(
    session: &VisualEditingSession,
    id: u128,
) -> Result<VisualNodeId, ConfigVisualError> {
    session
        .rows()
        .into_iter()
        .find(|row| row.id().get() == id)
        .map(|row| row.id())
        .ok_or(ConfigVisualError::Stale)
}

/// An add that did not go in: a read-only file says so, anything else is a
/// refused edit.
fn refused_add(error: ConfigVisualError) -> ConfigVisualError {
    if error == ConfigVisualError::ReadOnly {
        error
    } else {
        ConfigVisualError::Rejected
    }
}

/// A read-only file says so; anything else core refused is a refused edit.
fn database_edit_error(error: CoreError) -> ConfigVisualError {
    match error {
        CoreError::Validation { subject, .. }
            if subject.contains("local lossless configuration draft") =>
        {
            ConfigVisualError::ReadOnly
        }
        _ => ConfigVisualError::Rejected,
    }
}

/// A HAProxy keyword may stand alone (`daemon`): no arguments, no value.
fn line_value(arguments: &str) -> Option<&str> {
    (!arguments.trim().is_empty()).then_some(arguments)
}

fn line_kind(kind: LineConfigNodeKind) -> &'static str {
    match kind {
        LineConfigNodeKind::Entry | LineConfigNodeKind::Include | LineConfigNodeKind::Record => {
            "directive"
        }
        LineConfigNodeKind::Section | LineConfigNodeKind::Table => "block",
        LineConfigNodeKind::Comment => "comment",
        LineConfigNodeKind::Opaque => "opaque",
    }
}

fn nginx_kind(kind: NginxVisualNodeKind) -> &'static str {
    match kind {
        NginxVisualNodeKind::Directive => "directive",
        NginxVisualNodeKind::Block => "block",
        NginxVisualNodeKind::Comment => "comment",
        NginxVisualNodeKind::Opaque => "opaque",
    }
}

fn apache_kind(kind: ApacheVisualNodeKind) -> &'static str {
    match kind {
        ApacheVisualNodeKind::Directive => "directive",
        ApacheVisualNodeKind::Section => "block",
        ApacheVisualNodeKind::Comment => "comment",
        ApacheVisualNodeKind::Opaque => "opaque",
    }
}

impl Document {
    fn new(product: VisualProduct, template: VisualTemplate) -> CoreResult<Self> {
        Ok(match (product, template) {
            (VisualProduct::Nginx, VisualTemplate::Blank) => {
                Self::Nginx(NginxVisualDocument::blank())
            }
            (VisualProduct::Nginx, VisualTemplate::Competition) => {
                Self::Nginx(NginxVisualDocument::competition_skeleton()?)
            }
            (VisualProduct::Apache, VisualTemplate::Blank) => {
                Self::Apache(ApacheVisualDocument::blank())
            }
            (VisualProduct::Apache, VisualTemplate::Competition) => {
                Self::Apache(ApacheVisualDocument::competition_skeleton()?)
            }
            (VisualProduct::Redis, VisualTemplate::Blank) => {
                Self::Redis(LineConfigVisualDocument::blank(LineConfigDialect::Redis))
            }
            (VisualProduct::Redis, VisualTemplate::Competition) => {
                Self::Redis(LineConfigVisualDocument::redis_competition_skeleton()?)
            }
            (VisualProduct::Haproxy, VisualTemplate::Blank) => {
                Self::HaProxy(LineConfigVisualDocument::blank(LineConfigDialect::HaProxy))
            }
            (VisualProduct::Haproxy, VisualTemplate::Competition) => {
                Self::HaProxy(LineConfigVisualDocument::haproxy_competition_skeleton()?)
            }
            (VisualProduct::Mysql, VisualTemplate::Blank) => Self::MySql(
                LineConfigVisualDocument::blank(LineConfigDialect::MySqlOption),
            ),
            (VisualProduct::Mysql, VisualTemplate::Competition) => {
                Self::MySql(LineConfigVisualDocument::mysql_competition_skeleton()?)
            }
            (VisualProduct::Mariadb, VisualTemplate::Blank) => Self::MariaDb(
                LineConfigVisualDocument::blank(LineConfigDialect::MySqlOption),
            ),
            (VisualProduct::Mariadb, VisualTemplate::Competition) => {
                Self::MariaDb(LineConfigVisualDocument::mariadb_competition_skeleton()?)
            }
        })
    }

    fn parse_bytes(product: VisualProduct, bytes: Vec<u8>) -> CoreResult<Self> {
        Ok(match product {
            VisualProduct::Nginx => Self::Nginx(NginxVisualDocument::parse_bytes(bytes)?),
            VisualProduct::Apache => Self::Apache(ApacheVisualDocument::parse_bytes(bytes)?),
            VisualProduct::Redis => Self::Redis(LineConfigVisualDocument::parse_bytes(
                LineConfigDialect::Redis,
                bytes,
            )?),
            VisualProduct::Haproxy => Self::HaProxy(LineConfigVisualDocument::parse_bytes(
                LineConfigDialect::HaProxy,
                bytes,
            )?),
            VisualProduct::Mysql => Self::MySql(LineConfigVisualDocument::parse_bytes(
                LineConfigDialect::MySqlOption,
                bytes,
            )?),
            VisualProduct::Mariadb => Self::MariaDb(LineConfigVisualDocument::parse_bytes(
                LineConfigDialect::MySqlOption,
                bytes,
            )?),
        })
    }

    fn read_local(product: VisualProduct, path: &Path) -> CoreResult<Self> {
        Ok(match product {
            VisualProduct::Nginx => Self::Nginx(NginxVisualDocument::read_local(path)?),
            VisualProduct::Apache => Self::Apache(ApacheVisualDocument::read_local(path)?),
            VisualProduct::Redis => Self::Redis(LineConfigVisualDocument::read_local(
                LineConfigDialect::Redis,
                path,
            )?),
            VisualProduct::Haproxy => Self::HaProxy(LineConfigVisualDocument::read_local(
                LineConfigDialect::HaProxy,
                path,
            )?),
            VisualProduct::Mysql => Self::MySql(LineConfigVisualDocument::read_local(
                LineConfigDialect::MySqlOption,
                path,
            )?),
            VisualProduct::Mariadb => Self::MariaDb(LineConfigVisualDocument::read_local(
                LineConfigDialect::MySqlOption,
                path,
            )?),
        })
    }

    fn product(&self) -> &'static str {
        match self {
            Self::Nginx(_) => "nginx",
            Self::Apache(_) => "apache",
            Self::Redis(_) => "redis",
            Self::HaProxy(_) => "haproxy",
            Self::MySql(_) => "mysql",
            Self::MariaDb(_) => "mariadb",
            Self::Database(_) => "database",
        }
    }

    /// Parts kept as written inside an otherwise readable file.
    fn partly_opaque(&self) -> bool {
        match self {
            Self::Nginx(_) => false,
            Self::Apache(document) => document.has_opaque_regions(),
            Self::Redis(document)
            | Self::HaProxy(document)
            | Self::MySql(document)
            | Self::MariaDb(document) => !document.is_structured() && !document.is_whole_opaque(),
            Self::Database(session) => {
                session.document().is_structured()
                    && session
                        .rows()
                        .iter()
                        .any(|row| row.kind() == VisualNodeKind::Opaque)
            }
        }
    }

    /// Whether the file reads as this syntax at all, so it can be edited.
    fn is_structured(&self) -> bool {
        match self {
            Self::Nginx(document) => document.is_structured(),
            Self::Apache(document) => document.is_structured(),
            Self::Redis(document)
            | Self::HaProxy(document)
            | Self::MySql(document)
            | Self::MariaDb(document) => !document.is_whole_opaque(),
            Self::Database(session) => session.document().is_structured(),
        }
    }

    fn rows(&self) -> Vec<Row> {
        match self {
            Self::Database(session) => {
                let schema = session.current_schema();
                session
                    .rows()
                    .iter()
                    .map(|row| Row {
                        id: row.id().get(),
                        parent: row.parent().map(|id| id.get()),
                        depth: row.depth(),
                        kind: match row.kind() {
                            VisualNodeKind::Statement => "directive",
                            VisualNodeKind::Container => "block",
                            VisualNodeKind::Comment => "comment",
                            VisualNodeKind::Opaque => "opaque",
                        },
                        name: row.name().map(str::to_owned),
                        arguments: row.arguments().map(str::to_owned),
                        preview: row.preview().to_owned(),
                        child_count: row.child_count(),
                        truncated: row.truncated(),
                        editable: row.allows_local_draft_mutation(),
                        sensitive: row.sensitive(),
                        meaning: Some(match row.meaning_level() {
                            VisualMeaningLevel::CatalogGuidance => "catalog",
                            VisualMeaningLevel::SyntaxOnly => "syntax",
                        }),
                        parameter_index: match (schema, row.database_parameter()) {
                            (Some(schema), DatabaseParameterMatch::Matched(parameter)) => schema
                                .parameters
                                .iter()
                                .position(|candidate| std::ptr::eq(candidate, parameter)),
                            _ => None,
                        },
                        search_terms: visual_row_search_terms(row, schema),
                    })
                    .collect()
            }
            Self::Nginx(document) => document
                .rows()
                .iter()
                .map(|row| Row {
                    id: row.id().get(),
                    parent: row.parent().map(|id| id.get()),
                    depth: row.depth(),
                    kind: nginx_kind(row.kind()),
                    name: row.name().map(str::to_owned),
                    arguments: row.arguments().map(str::to_owned),
                    preview: row.preview().to_owned(),
                    child_count: row.child_count(),
                    truncated: row.truncated(),
                    editable: row.editable(),
                    sensitive: row.sensitive(),
                    meaning: None,
                    parameter_index: None,
                    search_terms: Vec::new(),
                })
                .collect(),
            Self::Apache(document) => document
                .rows()
                .iter()
                .map(|row| Row {
                    id: row.id().get(),
                    parent: row.parent().map(|id| id.get()),
                    depth: row.depth(),
                    kind: apache_kind(row.kind()),
                    name: row.name().map(str::to_owned),
                    arguments: row.arguments().map(str::to_owned),
                    preview: row.preview().to_owned(),
                    child_count: row.child_count(),
                    truncated: row.truncated(),
                    editable: row.editable(),
                    sensitive: row.sensitive(),
                    meaning: None,
                    parameter_index: None,
                    search_terms: Vec::new(),
                })
                .collect(),
            Self::Redis(document)
            | Self::HaProxy(document)
            | Self::MySql(document)
            | Self::MariaDb(document) => document
                .rows()
                .iter()
                .map(|row| Row {
                    id: row.id().get(),
                    parent: row.parent().map(|id| id.get()),
                    depth: row.depth(),
                    kind: line_kind(row.kind()),
                    name: row.name().map(str::to_owned),
                    arguments: row.value().map(str::to_owned),
                    preview: row.preview().to_owned(),
                    child_count: row.child_count(),
                    truncated: row.truncated(),
                    editable: row.editable(),
                    sensitive: row.sensitive(),
                    meaning: None,
                    parameter_index: None,
                    search_terms: Vec::new(),
                })
                .collect(),
        }
    }

    /// The row a page named by the id it was shown, in this revision only.
    fn find(&self, id: &str) -> Result<Row, ConfigVisualError> {
        let wanted = parse_node_id(id)?;
        self.rows()
            .into_iter()
            .find(|row| row.id == wanted)
            .ok_or(ConfigVisualError::Stale)
    }

    fn add(
        &mut self,
        parent: Option<u128>,
        kind: VisualAddKind,
        name: &str,
        arguments: &str,
        text: &str,
    ) -> Result<(), ConfigVisualError> {
        each!(self, d => {
            // A parent that is not in this revision never turns into "the top level".
            let parent = match parent {
                None => None,
                Some(wanted) => Some(
                    d.rows()
                        .into_iter()
                        .find(|row| row.id().get() == wanted)
                        .map(|row| row.id())
                        .ok_or(ConfigVisualError::Stale)?,
                ),
            };
            match kind {
                VisualAddKind::Comment => d.add_comment(parent, text),
                VisualAddKind::Block => d.add_block(parent, name, arguments),
                VisualAddKind::Directive => d.add_directive(parent, name, arguments),
            }
            .map_err(|_| ConfigVisualError::Rejected)
        }, r => {
            if r.dialect() == LineConfigDialect::MySqlOption {
                let parent = match parent {
                    None => None,
                    Some(wanted) => Some(
                        r.rows()
                            .into_iter()
                            .find(|row| row.id().get() == wanted)
                            .map(|row| row.id())
                            .ok_or(ConfigVisualError::Stale)?,
                    ),
                };
                // [groups] only at the top and named by themselves; options
                // only inside a group; !include lines wherever core allows.
                return match kind {
                    VisualAddKind::Comment => r.add_comment(parent, text),
                    VisualAddKind::Block if parent.is_none() && arguments.trim().is_empty() => {
                        r.add_section(name)
                    }
                    VisualAddKind::Block => return Err(ConfigVisualError::Rejected),
                    VisualAddKind::Directive if name.trim_start().starts_with('!') => {
                        r.add_include(parent, name, arguments)
                    }
                    VisualAddKind::Directive => r.add_entry(parent, name, line_value(arguments)),
                }
                .map_err(|_| ConfigVisualError::Rejected);
            }
            if r.dialect() == LineConfigDialect::HaProxy {
                let parent = match parent {
                    None => None,
                    Some(wanted) => Some(
                        r.rows()
                            .into_iter()
                            .find(|row| row.id().get() == wanted)
                            .map(|row| row.id())
                            .ok_or(ConfigVisualError::Stale)?,
                    ),
                };
                // Sections only at the top; settings only inside a section.
                return match kind {
                    VisualAddKind::Comment => r.add_comment(parent, text),
                    VisualAddKind::Block if parent.is_none() => {
                        r.add_haproxy_section(name, arguments)
                    }
                    VisualAddKind::Block => return Err(ConfigVisualError::Rejected),
                    VisualAddKind::Directive => r.add_entry(parent, name, line_value(arguments)),
                }
                .map_err(|_| ConfigVisualError::Rejected);
            }
            // redis.conf has no blocks: everything sits at the top level.
            if parent.is_some() {
                return Err(ConfigVisualError::NotBlock);
            }
            match kind {
                VisualAddKind::Comment => r.add_comment(None, text),
                VisualAddKind::Block => return Err(ConfigVisualError::Rejected),
                VisualAddKind::Directive if name.trim().eq_ignore_ascii_case("include") => {
                    r.add_include(None, name, arguments)
                }
                VisualAddKind::Directive => r.add_entry(None, name, Some(arguments)),
            }
            .map_err(|_| ConfigVisualError::Rejected)
        }, s => {
            let parent = parent.map(|wanted| database_node(s, wanted)).transpose()?;
            let document = s.document_mut();
            match kind {
                VisualAddKind::Comment => document.add_comment(parent, text),
                VisualAddKind::Block => document.add_container(parent, name, arguments),
                VisualAddKind::Directive => document.add_statement(parent, name, arguments),
            }
            .map_err(database_edit_error)
        })
    }

    /// A comment line, then the directive or block right under it, in the
    /// same parent. Tried on a copy and kept only when both are accepted.
    fn add_with_note(
        &mut self,
        parent: Option<u128>,
        kind: VisualAddKind,
        name: &str,
        arguments: &str,
        note: &str,
    ) -> Result<(), ConfigVisualError> {
        let rows = self.rows();
        let parent_at = match parent {
            None => None,
            Some(id) => Some(
                rows.iter()
                    .position(|row| row.id == id)
                    .ok_or(ConfigVisualError::Stale)?,
            ),
        };
        let mut draft = self.clone();
        draft
            .add(parent, VisualAddKind::Comment, "", "", note)
            .map_err(refused_add)?;
        // Every edit hands out new ids. The comment went in after the
        // parent's own line, so the parent keeps its place in the list.
        let parent = match parent_at {
            None => None,
            Some(index) => {
                let before = &rows[index];
                let after = draft.rows().into_iter().nth(index).filter(|row| {
                    row.kind == before.kind && row.name == before.name && row.depth == before.depth
                });
                Some(after.ok_or(ConfigVisualError::Rejected)?.id)
            }
        };
        draft
            .add(parent, kind, name, arguments, "")
            .map_err(refused_add)?;
        *self = draft;
        Ok(())
    }

    fn update_statement(
        &mut self,
        id: u128,
        name: &str,
        arguments: &str,
    ) -> Result<(), ConfigVisualError> {
        each!(self, d => {
            let target = d.rows().into_iter().find(|row| row.id().get() == id).map(|row| row.id());
            let target = target.ok_or(ConfigVisualError::Stale)?;
            d.update_statement(target, name, arguments).map_err(|_| ConfigVisualError::Rejected)
        }, r => {
            let target = r.rows().into_iter().find(|row| row.id().get() == id);
            let target = target.ok_or(ConfigVisualError::Stale)?;
            let option_file = r.dialect() == LineConfigDialect::MySqlOption;
            if target.kind() == LineConfigNodeKind::Section && option_file {
                // A [group] header is its name alone.
                if !arguments.trim().is_empty() {
                    return Err(ConfigVisualError::Rejected);
                }
                return r
                    .update_container(target.id(), name)
                    .map_err(|_| ConfigVisualError::Rejected);
            }
            if target.kind() == LineConfigNodeKind::Section {
                return r
                    .update_haproxy_section(target.id(), name, arguments)
                    .map_err(|_| ConfigVisualError::Rejected);
            }
            // HAProxy keywords and option-file flags (skip-name-resolve) may
            // stand alone; a Redis line always has a value.
            let value = if r.dialect() == LineConfigDialect::HaProxy || option_file {
                line_value(arguments)
            } else {
                Some(arguments)
            };
            r.update_entry(target.id(), name, value).map_err(|_| ConfigVisualError::Rejected)
        }, s => {
            let target = database_node(s, id)?;
            s.document_mut().update_statement(target, name, arguments).map_err(database_edit_error)
        })
    }

    fn update_comment(&mut self, id: u128, text: &str) -> Result<(), ConfigVisualError> {
        each!(self, d => {
            let target = d.rows().into_iter().find(|row| row.id().get() == id).map(|row| row.id());
            let target = target.ok_or(ConfigVisualError::Stale)?;
            d.update_comment(target, text).map_err(|_| ConfigVisualError::Rejected)
        }, r => {
            let target = r.rows().into_iter().find(|row| row.id().get() == id).map(|row| row.id());
            let target = target.ok_or(ConfigVisualError::Stale)?;
            r.update_comment(target, text).map_err(|_| ConfigVisualError::Rejected)
        }, s => {
            let target = database_node(s, id)?;
            s.document_mut().update_comment(target, text).map_err(database_edit_error)
        })
    }

    fn remove(&mut self, id: u128) -> Result<(), ConfigVisualError> {
        each!(self, d => {
            let target = d.rows().into_iter().find(|row| row.id().get() == id).map(|row| row.id());
            let target = target.ok_or(ConfigVisualError::Stale)?;
            d.remove(target).map_err(|_| ConfigVisualError::Rejected)
        }, r => {
            let target = r.rows().into_iter().find(|row| row.id().get() == id).map(|row| row.id());
            let target = target.ok_or(ConfigVisualError::Stale)?;
            r.remove(target).map_err(|_| ConfigVisualError::Rejected)
        }, s => {
            let target = database_node(s, id)?;
            s.document_mut().remove(target).map_err(database_edit_error)
        })
    }

    fn move_row(&mut self, id: u128, direction: VisualDirection) -> Result<(), ConfigVisualError> {
        each!(self, d => {
            let target = d.rows().into_iter().find(|row| row.id().get() == id).map(|row| row.id());
            let target = target.ok_or(ConfigVisualError::Stale)?;
            match direction {
                VisualDirection::Up => d.move_up(target),
                VisualDirection::Down => d.move_down(target),
            }
            .map_err(|_| ConfigVisualError::Rejected)
        }, r => {
            let target = r.rows().into_iter().find(|row| row.id().get() == id).map(|row| row.id());
            let target = target.ok_or(ConfigVisualError::Stale)?;
            match direction {
                VisualDirection::Up => r.move_up(target),
                VisualDirection::Down => r.move_down(target),
            }
            .map_err(|_| ConfigVisualError::Rejected)
        }, s => {
            let target = database_node(s, id)?;
            let document = s.document_mut();
            match direction {
                VisualDirection::Up => document.move_up(target),
                VisualDirection::Down => document.move_down(target),
            }
            .map_err(database_edit_error)
        })
    }

    fn contains_sensitive_values(&self) -> bool {
        each!(self, d => d.contains_sensitive_values(), r => r.contains_sensitive_values(),
            s => s.contains_sensitive_values())
    }

    fn raw_bytes(&self) -> &[u8] {
        each!(self, d => d.raw_bytes(), r => r.raw_bytes(), s => s.document().raw_bytes())
    }

    fn suggested_name(&self) -> &'static str {
        each!(self, d => d.output().suggested_file_name(), r => r.output().suggested_file_name(),
            s => s.document().suggested_file_name())
    }

    fn text(&self) -> Option<&str> {
        std::str::from_utf8(self.raw_bytes()).ok()
    }
}

struct Held {
    document: Document,
    revision: u64,
    source: &'static str,
    touched: Instant,
}

#[derive(Default)]
pub(crate) struct ConfigVisualApi {
    documents: Mutex<HashMap<String, Held>>,
    /// The assignment held for confirmation. Locked before `documents`
    /// whenever both are needed.
    goal: Mutex<PendingGoal>,
}

impl std::fmt::Debug for ConfigVisualApi {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConfigVisualApi")
            .field("documents", &self.documents.lock().len())
            .finish()
    }
}

impl ConfigVisualApi {
    pub(crate) fn dispatch(
        &self,
        request: ConfigVisualRequest,
        quick: &ConfigApi,
    ) -> Result<ConfigVisualResponse, ConfigVisualError> {
        let now = Instant::now();
        self.documents
            .lock()
            .retain(|_, held| now.duration_since(held.touched) < IDLE_LIMIT);
        match request {
            ConfigVisualRequest::New { product, template } => {
                let document =
                    Document::new(product, template).map_err(|_| ConfigVisualError::Rejected)?;
                let source = match template {
                    VisualTemplate::Blank => "blank",
                    VisualTemplate::Competition => "competition",
                };
                self.insert(document, source, now)
                    .map(ConfigVisualResponse::View)
            }
            ConfigVisualRequest::OpenQuick {
                handle,
                revision,
                artifact_key,
            } => {
                if !valid_handle(&handle) || !valid_handle(&artifact_key) || revision == 0 {
                    return Err(ConfigVisualError::Invalid);
                }
                let artifact = quick
                    .artifact_bytes(&handle, revision, &artifact_key)
                    .map_err(|_| ConfigVisualError::Stale)?;
                let product = match artifact.product {
                    "nginx" => VisualProduct::Nginx,
                    "apache" => VisualProduct::Apache,
                    "redis" => VisualProduct::Redis,
                    "haproxy" => VisualProduct::Haproxy,
                    "mysql" => VisualProduct::Mysql,
                    "mariadb" => VisualProduct::Mariadb,
                    _ => return Err(ConfigVisualError::Unsupported),
                };
                let document = Document::parse_bytes(product, artifact.bytes)
                    .map_err(|_| ConfigVisualError::TooLarge)?;
                self.insert(document, "quick", now)
                    .map(ConfigVisualResponse::View)
            }
            ConfigVisualRequest::Import {
                product,
                selected_path,
            } => {
                if !selected_path.is_absolute() || selected_path.as_os_str().len() > 32_768 {
                    return Err(ConfigVisualError::Invalid);
                }
                let document =
                    Document::read_local(product, &selected_path).map_err(|error| match error {
                        CoreError::Validation { subject, .. } if subject.contains("size") => {
                            ConfigVisualError::TooLarge
                        }
                        _ => ConfigVisualError::ReadFailed,
                    })?;
                self.insert(document, "import", now)
                    .map(ConfigVisualResponse::View)
            }
            ConfigVisualRequest::DatabaseCatalog => {
                Ok(ConfigVisualResponse::DatabaseCatalog(database_catalog()))
            }
            ConfigVisualRequest::GoalSearch { query, document } => {
                self.goal_search(&query, document.as_ref())
            }
            ConfigVisualRequest::GoalChoose {
                lease,
                candidate,
                document,
            } => self.goal_choose(&lease, candidate, document.as_ref()),
            ConfigVisualRequest::GoalConfirm {
                lease,
                value,
                document,
            } => self.goal_confirm(&lease, &value, document.as_ref(), now),
            ConfigVisualRequest::NewDatabase { artifact_key } => {
                let artifact = visual_database_artifact(&artifact_key)?;
                let document =
                    VisualDocument::selection_document(VisualDocumentKind::Database(artifact))
                        .map_err(|_| ConfigVisualError::Rejected)?;
                // A file that is never drafted opens empty, for a local copy to be imported.
                let source = if artifact.allows_lossless_local_draft() {
                    "starter"
                } else {
                    "blank"
                };
                self.insert(
                    Document::Database(Box::new(VisualEditingSession::new(document))),
                    source,
                    now,
                )
                .map(ConfigVisualResponse::View)
            }
            ConfigVisualRequest::ImportDatabase {
                artifact_key,
                selected_path,
            } => {
                if !selected_path.is_absolute() || selected_path.as_os_str().len() > 32_768 {
                    return Err(ConfigVisualError::Invalid);
                }
                let artifact = visual_database_artifact(&artifact_key)?;
                let document = VisualDocument::read_local(
                    VisualDocumentKind::Database(artifact),
                    &selected_path,
                )
                .map_err(|error| match error {
                    CoreError::Validation { subject, .. } if subject.contains("size") => {
                        ConfigVisualError::TooLarge
                    }
                    _ => ConfigVisualError::ReadFailed,
                })?;
                self.insert(
                    Document::Database(Box::new(VisualEditingSession::new(document))),
                    "import",
                    now,
                )
                .map(ConfigVisualResponse::View)
            }
            ConfigVisualRequest::SelectSchema {
                document_handle,
                revision,
                schema,
            } => self
                .edit(&document_handle, revision, now, |document| {
                    let Document::Database(session) = document else {
                        return Err(ConfigVisualError::Unsupported);
                    };
                    match schema {
                        None => {
                            session.clear_schema();
                            Ok(())
                        }
                        Some(index) => {
                            let schema = DATABASE_CONFIG_SCHEMAS
                                .get(index)
                                .ok_or(ConfigVisualError::Invalid)?;
                            if session.select_schema(schema) {
                                Ok(())
                            } else {
                                Err(ConfigVisualError::Rejected)
                            }
                        }
                    }
                })
                .map(ConfigVisualResponse::View),
            ConfigVisualRequest::SetParameter {
                document_handle,
                revision,
                parameter_index,
                value,
            } => {
                field(Some(&value))?;
                self.edit(&document_handle, revision, now, |document| {
                    let Document::Database(session) = document else {
                        return Err(ConfigVisualError::Unsupported);
                    };
                    let staged = session
                        .stage_parameter_value(parameter_index, &value)
                        .map_err(|error| match error {
                            DatabaseParameterValueError::NoSchema => ConfigVisualError::NoSchema,
                            DatabaseParameterValueError::Draft(_) => {
                                ConfigVisualError::ValueRefused
                            }
                            DatabaseParameterValueError::Stage(
                                DatabaseParameterStageError::ReadOnly,
                            ) => ConfigVisualError::ReadOnly,
                            DatabaseParameterValueError::Stage(
                                DatabaseParameterStageError::Duplicate,
                            ) => ConfigVisualError::ParameterDuplicate,
                            DatabaseParameterValueError::Stage(
                                DatabaseParameterStageError::LineLocked,
                            ) => ConfigVisualError::ParameterLocked,
                            DatabaseParameterValueError::Stage(_) => ConfigVisualError::Rejected,
                        })?;
                    session.replace_document(staged);
                    Ok(())
                })
                .map(ConfigVisualResponse::View)
            }
            ConfigVisualRequest::View {
                document_handle,
                revision,
            } => self
                .with_document(&document_handle, revision, now)
                .map(ConfigVisualResponse::View),
            ConfigVisualRequest::Add {
                document_handle,
                revision,
                parent_id,
                kind,
                name,
                arguments,
                text,
                note,
            } => self
                .edit(&document_handle, revision, now, |document| {
                    let parent = match parent_id.as_deref() {
                        None => None,
                        Some(id) => {
                            let row = document.find(id)?;
                            if row.kind != "block" {
                                return Err(ConfigVisualError::NotBlock);
                            }
                            if row.sensitive {
                                return Err(ConfigVisualError::Sensitive);
                            }
                            Some(row.id)
                        }
                    };
                    let note = match (kind, note.as_deref()) {
                        (_, None) => None,
                        (VisualAddKind::Comment, Some(_)) => {
                            return Err(ConfigVisualError::Invalid);
                        }
                        (_, Some(note)) => Some(field(Some(note))?),
                    };
                    let (name, arguments, text) = match kind {
                        VisualAddKind::Comment => {
                            if name.is_some() || arguments.is_some() {
                                return Err(ConfigVisualError::Invalid);
                            }
                            ("", "", field(text.as_deref())?)
                        }
                        VisualAddKind::Directive | VisualAddKind::Block => {
                            if text.is_some() {
                                return Err(ConfigVisualError::Invalid);
                            }
                            (field(name.as_deref())?, field(arguments.as_deref())?, "")
                        }
                    };
                    let Some(note) = note else {
                        return document
                            .add(parent, kind, name, arguments, text)
                            .map_err(refused_add);
                    };
                    document.add_with_note(parent, kind, name, arguments, note)
                })
                .map(ConfigVisualResponse::View),
            ConfigVisualRequest::Update {
                document_handle,
                revision,
                node_id,
                name,
                arguments,
                text,
            } => self
                .edit(&document_handle, revision, now, |document| {
                    let row = document.find(&node_id)?;
                    if row.sensitive {
                        return Err(ConfigVisualError::Sensitive);
                    }
                    match row.kind {
                        "comment" => {
                            if name.is_some() || arguments.is_some() {
                                return Err(ConfigVisualError::Invalid);
                            }
                            document.update_comment(row.id, field(text.as_deref())?)
                        }
                        "directive" | "block" => {
                            if text.is_some() {
                                return Err(ConfigVisualError::Invalid);
                            }
                            document.update_statement(
                                row.id,
                                field(name.as_deref())?,
                                field(arguments.as_deref())?,
                            )
                        }
                        _ => Err(ConfigVisualError::Rejected),
                    }
                })
                .map(ConfigVisualResponse::View),
            ConfigVisualRequest::Remove {
                document_handle,
                revision,
                node_id,
            } => self
                .edit(&document_handle, revision, now, |document| {
                    let row = document.find(&node_id)?;
                    if row.sensitive {
                        return Err(ConfigVisualError::Sensitive);
                    }
                    document.remove(row.id)
                })
                .map(ConfigVisualResponse::View),
            ConfigVisualRequest::Move {
                document_handle,
                revision,
                node_id,
                direction,
            } => self
                .edit(&document_handle, revision, now, |document| {
                    let row = document.find(&node_id)?;
                    if row.sensitive {
                        return Err(ConfigVisualError::Sensitive);
                    }
                    document.move_row(row.id, direction)
                })
                .map(ConfigVisualResponse::View),
            ConfigVisualRequest::Close {
                document_handle,
                revision,
            } => {
                if !valid_handle(&document_handle) {
                    return Err(ConfigVisualError::Invalid);
                }
                let mut documents = self.documents.lock();
                match documents.get(&document_handle) {
                    Some(held) if held.revision == revision => {
                        documents.remove(&document_handle);
                        Ok(ConfigVisualResponse::Closed(ConfigVisualClosedDto {
                            closed: true,
                        }))
                    }
                    _ => Err(ConfigVisualError::Stale),
                }
            }
            ConfigVisualRequest::Export {
                document_handle,
                revision,
                purpose,
            } => {
                if !valid_handle(&document_handle) {
                    return Err(ConfigVisualError::Invalid);
                }
                let mut documents = self.documents.lock();
                let held = documents
                    .get_mut(&document_handle)
                    .filter(|held| held.revision == revision)
                    .ok_or(ConfigVisualError::Stale)?;
                held.touched = now;
                if purpose == VisualExportPurpose::Copy && held.document.contains_sensitive_values()
                {
                    return Err(ConfigVisualError::Sensitive);
                }
                let contents = held
                    .document
                    .text()
                    .ok_or(ConfigVisualError::NotText)?
                    .to_owned();
                if purpose == VisualExportPurpose::Copy && contents.len() > MAX_COPY_BYTES {
                    return Err(ConfigVisualError::TooLarge);
                }
                Ok(ConfigVisualResponse::Export(ConfigVisualExportDto {
                    suggested_name: held.document.suggested_name(),
                    contents,
                }))
            }
        }
    }

    fn insert(
        &self,
        document: Document,
        source: &'static str,
        now: Instant,
    ) -> Result<ConfigVisualViewDto, ConfigVisualError> {
        insert_into(&mut self.documents.lock(), document, source, now)
    }

    /// The open document a goal request names, checked against the revision
    /// the page shows. `None` when the page has none open.
    fn goal_binding(
        document: Option<&GoalDocument>,
    ) -> Result<Option<GoalBinding>, ConfigVisualError> {
        document
            .map(|document| {
                if !valid_handle(&document.document_handle) || document.revision == 0 {
                    return Err(ConfigVisualError::Invalid);
                }
                Ok(GoalBinding {
                    handle: document.document_handle.clone(),
                    revision: document.revision,
                })
            })
            .transpose()
    }

    /// Where a resolved assignment would land, or why it cannot, worked out
    /// on copies: nothing open changes.
    fn goal_preflight(
        &self,
        assignment: &DatabaseParameterAssignment,
        document: Option<&GoalDocument>,
    ) -> Result<(Option<&'static str>, Option<&'static str>), ConfigVisualError> {
        let documents = self.documents.lock();
        let open = match document {
            Some(document) => Some(
                documents
                    .get(&document.document_handle)
                    .filter(|held| held.revision == document.revision)
                    .ok_or(ConfigVisualError::Stale)?,
            ),
            None => None,
        };
        let unsaved = document.is_some_and(|document| document.unsaved);
        let staged = match open.map(|held| &held.document) {
            Some(Document::Database(session)) => session
                .stage_assignment(assignment, unsaved)
                .map(|staged| (staged, lands_in_open(session, assignment))),
            Some(_) if unsaved => Err(DatabaseAssignmentPreflightError::OtherFileUnsaved),
            _ => fresh_assignment_session(assignment)?
                .stage_assignment(assignment, false)
                .map(|staged| (staged, false)),
        };
        Ok(match staged {
            Ok((_, true)) => (Some("open-draft"), None),
            Ok((_, false)) => (Some("new-draft"), None),
            Err(error) => (None, Some(preflight_key(error))),
        })
    }

    fn goal_ready(
        &self,
        pending: &mut PendingGoal,
        assignment: DatabaseParameterAssignment,
        document: Option<&GoalDocument>,
    ) -> Result<ConfigVisualResponse, ConfigVisualError> {
        let binding = Self::goal_binding(document)?;
        let (landing, blocked) = self.goal_preflight(&assignment, document)?;
        let target = target_dto(assignment.schema(), assignment.parameter_index());
        let value = assignment.draft().normalized_value().to_owned();
        let lease = pending.hold(PendingGoalState::Ready {
            assignment,
            binding,
        });
        Ok(goal_answer(ConfigGoalSearchDto {
            assignment: Some(GoalAssignmentDto {
                lease: Some(lease),
                state: "ready",
                target: Some(target),
                value: Some(value),
                landing,
                blocked,
                candidates: Vec::new(),
                rejection: None,
            }),
            results: Vec::new(),
            truncated: false,
        }))
    }

    fn goal_rejected(pending: &mut PendingGoal, rejection: &'static str) -> ConfigVisualResponse {
        pending.clear();
        goal_answer(ConfigGoalSearchDto {
            assignment: Some(GoalAssignmentDto {
                lease: None,
                state: "rejected",
                target: None,
                value: None,
                landing: None,
                blocked: None,
                candidates: Vec::new(),
                rejection: Some(rejection),
            }),
            results: Vec::new(),
            truncated: false,
        })
    }

    fn goal_search(
        &self,
        query: &str,
        document: Option<&GoalDocument>,
    ) -> Result<ConfigVisualResponse, ConfigVisualError> {
        if query.len() > MAX_FIELD_BYTES || query.contains('\0') {
            return Err(ConfigVisualError::GoalQueryRefused);
        }
        Self::goal_binding(document)?;
        let mut pending = self.goal.lock();
        match resolve_database_parameter_assignment(query) {
            DatabaseParameterAssignmentResolution::NotAssignment => {
                pending.clear();
                let (results, truncated) =
                    goal_results(query).map_err(|_| ConfigVisualError::GoalQueryRefused)?;
                Ok(goal_answer(ConfigGoalSearchDto {
                    assignment: None,
                    results,
                    truncated,
                }))
            }
            DatabaseParameterAssignmentResolution::Ready(assignment) => {
                self.goal_ready(&mut pending, assignment, document)
            }
            DatabaseParameterAssignmentResolution::Ambiguous(ambiguity) => {
                let candidates = ambiguity
                    .candidates()
                    .iter()
                    .map(|target| target_dto(target.schema(), target.parameter_index()))
                    .collect();
                let lease = pending.hold(PendingGoalState::Ambiguous { ambiguity });
                Ok(goal_answer(ConfigGoalSearchDto {
                    assignment: Some(GoalAssignmentDto {
                        lease: Some(lease),
                        state: "ambiguous",
                        target: None,
                        value: None,
                        landing: None,
                        blocked: None,
                        candidates,
                        rejection: None,
                    }),
                    results: Vec::new(),
                    truncated: false,
                }))
            }
            DatabaseParameterAssignmentResolution::Rejected(error) => {
                Ok(Self::goal_rejected(&mut pending, rejection_key(error)))
            }
        }
    }

    fn goal_choose(
        &self,
        lease: &str,
        candidate: usize,
        document: Option<&GoalDocument>,
    ) -> Result<ConfigVisualResponse, ConfigVisualError> {
        let mut pending = self.goal.lock();
        if !pending.is_current(lease) {
            return Err(ConfigVisualError::GoalStale);
        }
        let PendingGoalState::Ambiguous { ambiguity } = &pending.state else {
            return Err(ConfigVisualError::GoalStale);
        };
        let target = *ambiguity
            .candidates()
            .get(candidate)
            .ok_or(ConfigVisualError::Invalid)?;
        match select_database_parameter_assignment_candidate(ambiguity, target) {
            Ok(assignment) => self.goal_ready(&mut pending, assignment, document),
            Err(error) => Ok(Self::goal_rejected(&mut pending, rejection_key(error))),
        }
    }

    /// Writes the held assignment once. Every refusal leaves every document
    /// and its revision as they were, and never repeats the value.
    fn goal_confirm(
        &self,
        lease: &str,
        value: &str,
        document: Option<&GoalDocument>,
        now: Instant,
    ) -> Result<ConfigVisualResponse, ConfigVisualError> {
        field(Some(value))?;
        let given = Self::goal_binding(document)?;
        let mut pending = self.goal.lock();
        if !pending.is_current(lease) {
            return Err(ConfigVisualError::GoalStale);
        }
        let PendingGoalState::Ready {
            assignment,
            binding,
        } = &pending.state
        else {
            return Err(ConfigVisualError::GoalStale);
        };
        // The preview was worked out against one document at one revision;
        // a schema choice or an edit since then makes it another question.
        if given != *binding {
            return Err(ConfigVisualError::GoalStale);
        }
        let revised = revalidate_database_parameter_assignment_value(assignment, value)
            .map_err(|_| ConfigVisualError::GoalValueRefused)?;
        let unsaved = document.is_some_and(|document| document.unsaved);
        let mut documents = self.documents.lock();
        let response = match &given {
            Some(binding) => {
                let held = documents
                    .get_mut(&binding.handle)
                    .filter(|held| held.revision == binding.revision)
                    .ok_or(ConfigVisualError::GoalStale)?;
                match &mut held.document {
                    Document::Database(session) => {
                        let in_place = lands_in_open(session, &revised);
                        let staged = session
                            .stage_assignment(&revised, unsaved)
                            .map_err(goal_preflight_error)?;
                        if in_place {
                            **session = staged;
                            held.revision = held.revision.saturating_add(1);
                            held.touched = now;
                            view(&binding.handle, held)
                        } else {
                            insert_into(
                                &mut documents,
                                Document::Database(Box::new(staged)),
                                "goal",
                                now,
                            )?
                        }
                    }
                    _ if unsaved => return Err(ConfigVisualError::GoalOtherFileUnsaved),
                    _ => insert_into(
                        &mut documents,
                        Document::Database(Box::new(staged_in_fresh(&revised)?)),
                        "goal",
                        now,
                    )?,
                }
            }
            None => insert_into(
                &mut documents,
                Document::Database(Box::new(staged_in_fresh(&revised)?)),
                "goal",
                now,
            )?,
        };
        pending.lease = None;
        pending.state = PendingGoalState::Consumed;
        Ok(ConfigVisualResponse::View(response))
    }
}

fn goal_answer(answer: ConfigGoalSearchDto) -> ConfigVisualResponse {
    ConfigVisualResponse::GoalSearch(Box::new(answer))
}

/// Whether a value would go into the open file itself: the same file, read
/// against the assignment's own version. Otherwise it starts a new draft.
fn lands_in_open(session: &VisualEditingSession, assignment: &DatabaseParameterAssignment) -> bool {
    let schema = assignment.schema();
    database_artifact_by_key(schema.binding.artifact_key).is_some_and(|artifact| {
        session.document().kind() == VisualDocumentKind::Database(artifact)
            && session
                .current_schema()
                .is_some_and(|current| std::ptr::eq(current, schema))
    })
}

/// An empty draft of the assignment's file, to stage a value into.
fn fresh_assignment_session(
    assignment: &DatabaseParameterAssignment,
) -> Result<VisualEditingSession, ConfigVisualError> {
    let artifact = database_artifact_by_key(assignment.schema().binding.artifact_key)
        .ok_or(ConfigVisualError::Unsupported)?;
    VisualDocument::parse_database(artifact, "")
        .map(VisualEditingSession::new)
        .map_err(|_| ConfigVisualError::Unsupported)
}

fn staged_in_fresh(
    assignment: &DatabaseParameterAssignment,
) -> Result<VisualEditingSession, ConfigVisualError> {
    fresh_assignment_session(assignment)?
        .stage_assignment(assignment, false)
        .map_err(goal_preflight_error)
}

fn goal_preflight_error(error: DatabaseAssignmentPreflightError) -> ConfigVisualError {
    match error {
        DatabaseAssignmentPreflightError::OtherFileUnsaved => {
            ConfigVisualError::GoalOtherFileUnsaved
        }
        DatabaseAssignmentPreflightError::OtherSchemaUnsaved => {
            ConfigVisualError::GoalOtherVersionUnsaved
        }
        DatabaseAssignmentPreflightError::ArtifactMissing
        | DatabaseAssignmentPreflightError::Stage(DatabaseParameterStageError::ReadOnly) => {
            ConfigVisualError::ReadOnly
        }
        DatabaseAssignmentPreflightError::Stage(DatabaseParameterStageError::Duplicate) => {
            ConfigVisualError::ParameterDuplicate
        }
        DatabaseAssignmentPreflightError::Stage(DatabaseParameterStageError::LineLocked) => {
            ConfigVisualError::ParameterLocked
        }
        DatabaseAssignmentPreflightError::Stage(_) => ConfigVisualError::Rejected,
    }
}

fn insert_into(
    documents: &mut HashMap<String, Held>,
    document: Document,
    source: &'static str,
    now: Instant,
) -> Result<ConfigVisualViewDto, ConfigVisualError> {
    // Never evict: a document may hold edits nobody has saved yet.
    if documents.len() >= MAX_DOCUMENTS {
        return Err(ConfigVisualError::Capacity);
    }
    let handle = uuid::Uuid::new_v4().to_string();
    let held = Held {
        document,
        revision: 1,
        source,
        touched: now,
    };
    let view = view(&handle, &held);
    documents.insert(handle, held);
    Ok(view)
}

impl ConfigVisualApi {
    fn with_document(
        &self,
        handle: &str,
        revision: u64,
        now: Instant,
    ) -> Result<ConfigVisualViewDto, ConfigVisualError> {
        if !valid_handle(handle) {
            return Err(ConfigVisualError::Invalid);
        }
        let mut documents = self.documents.lock();
        let held = documents
            .get_mut(handle)
            .filter(|held| held.revision == revision)
            .ok_or(ConfigVisualError::Stale)?;
        held.touched = now;
        Ok(view(handle, held))
    }

    /// One edit against the revision the page saw. A refused edit leaves the
    /// document and its revision as they were.
    fn edit(
        &self,
        handle: &str,
        revision: u64,
        now: Instant,
        apply: impl FnOnce(&mut Document) -> Result<(), ConfigVisualError>,
    ) -> Result<ConfigVisualViewDto, ConfigVisualError> {
        if !valid_handle(handle) {
            return Err(ConfigVisualError::Invalid);
        }
        let mut documents = self.documents.lock();
        let held = documents
            .get_mut(handle)
            .filter(|held| held.revision == revision)
            .ok_or(ConfigVisualError::Stale)?;
        held.touched = now;
        apply(&mut held.document)?;
        held.revision = held.revision.saturating_add(1);
        Ok(view(handle, held))
    }
}

fn field(value: Option<&str>) -> Result<&str, ConfigVisualError> {
    let value = value.unwrap_or("");
    if value.len() > MAX_FIELD_BYTES || value.contains('\0') {
        return Err(ConfigVisualError::Invalid);
    }
    Ok(value)
}

fn parse_node_id(id: &str) -> Result<u128, ConfigVisualError> {
    if id.is_empty() || id.len() > 40 || !id.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ConfigVisualError::Invalid);
    }
    id.parse::<u128>().map_err(|_| ConfigVisualError::Invalid)
}

fn view(handle: &str, held: &Held) -> ConfigVisualViewDto {
    let document = &held.document;
    let all = document.rows();
    let total_rows = all.len();
    let mut rows = Vec::new();
    let mut budget = 0usize;
    let mut rows_truncated = false;
    for row in all {
        if rows.len() >= MAX_ROWS {
            rows_truncated = true;
            break;
        }
        // A name or argument too long to show whole is not offered for
        // editing here; editing a cut-off value would silently drop its tail.
        let too_long = row
            .arguments
            .iter()
            .chain(row.name.iter())
            .any(|value| value.len() > MAX_ROW_ARGUMENT_BYTES);
        let cost = row.preview.len()
            + if too_long {
                0
            } else {
                row.name.as_ref().map_or(0, String::len)
                    + row.arguments.as_ref().map_or(0, String::len)
            }
            + 160;
        if budget + cost > MAX_VIEW_ROW_BYTES {
            rows_truncated = true;
            break;
        }
        budget += cost;
        rows.push(ConfigVisualRowDto {
            id: row.id.to_string(),
            parent_id: row.parent.map(|id| id.to_string()),
            depth: row.depth,
            kind: row.kind,
            name: if too_long { None } else { row.name },
            arguments: if too_long { None } else { row.arguments },
            preview: row.preview,
            child_count: row.child_count,
            truncated: row.truncated || too_long,
            editable: row.editable && !too_long,
            sensitive: row.sensitive,
            meaning: row.meaning,
            parameter_index: row.parameter_index,
            search_terms: row
                .search_terms
                .into_iter()
                .filter(|term| term.len() <= MAX_ROW_ARGUMENT_BYTES)
                .take(MAX_SEARCH_TERMS)
                .collect(),
        });
    }
    let contains_sensitive = document.contains_sensitive_values();
    let text = document.text();
    let (text, text_truncated) = match text {
        Some(_) if contains_sensitive => (None, false),
        Some(text) if text.len() > MAX_TEXT_BYTES => {
            let mut end = MAX_TEXT_BYTES;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            (Some(text[..end].to_owned()), true)
        }
        Some(text) => (Some(text.to_owned()), false),
        None => (None, false),
    };
    let copy_allowed = !contains_sensitive
        && document.text().is_some()
        && document.raw_bytes().len() <= MAX_COPY_BYTES;
    ConfigVisualViewDto {
        document_handle: handle.to_owned(),
        revision: held.revision,
        product: document.product(),
        source: held.source,
        structured: document.is_structured(),
        partly_opaque: document.partly_opaque(),
        contains_sensitive,
        total_bytes: document.raw_bytes().len(),
        suggested_name: document.suggested_name(),
        rows,
        total_rows,
        rows_truncated,
        text,
        text_truncated,
        copy_allowed,
        database: match document {
            Document::Database(session) => Some(Box::new(database_view(session))),
            _ => None,
        },
    }
}

/// A catalogued file the visual editor can open, by its exact key.
fn visual_database_artifact(
    key: &str,
) -> Result<&'static DatabaseConfigArtifactDefinition, ConfigVisualError> {
    if !valid_handle(key) {
        return Err(ConfigVisualError::Invalid);
    }
    let artifact = database_artifact_by_key(key).ok_or(ConfigVisualError::Invalid)?;
    if database_visual_parser(artifact).is_none() {
        return Err(ConfigVisualError::Unsupported);
    }
    Ok(artifact)
}

pub(crate) fn database_product_definition(
    product: DatabaseConfigProduct,
) -> Option<&'static DatabaseConfigProductDefinition> {
    DATABASE_CONFIG_PRODUCTS
        .iter()
        .find(|definition| definition.product == product)
}

/// The syntax a file is written in, as the page names it.
const fn syntax_key(dialect: DatabaseConfigDialect) -> &'static str {
    match dialect {
        DatabaseConfigDialect::MySqlOptionFile => "mysql-option",
        DatabaseConfigDialect::PostgreSqlConf | DatabaseConfigDialect::PostgreSqlAutoConf => {
            "postgresql-conf"
        }
        DatabaseConfigDialect::PgHbaConf => "pg-hba",
        DatabaseConfigDialect::PgIdentConf => "pg-ident",
        DatabaseConfigDialect::Ini => "ini",
        DatabaseConfigDialect::Toml => "toml",
        DatabaseConfigDialect::Yaml => "yaml",
        DatabaseConfigDialect::Json | DatabaseConfigDialect::MySqlPersistedVariablesJson => "json",
        DatabaseConfigDialect::Xml => "xml",
        DatabaseConfigDialect::JavaProperties => "java-properties",
        DatabaseConfigDialect::KeyValue => "key-value",
        DatabaseConfigDialect::VendorText => "vendor-text",
        DatabaseConfigDialect::GcwareConf => "gcware",
        DatabaseConfigDialect::SequoiaQuickDeployClusterCsv
        | DatabaseConfigDialect::SequoiaQuickDeploySqlInstanceCsv => "csv",
        DatabaseConfigDialect::VendorBinary
        | DatabaseConfigDialect::RuntimeSql
        | DatabaseConfigDialect::CloudApi
        | DatabaseConfigDialect::VendorSchema => "other",
    }
}

const fn read_only_key(kind: VisualDocumentKind) -> Option<&'static str> {
    match kind.read_only_reason() {
        Some(VisualReadOnlyReason::VendorSchemaRequired) => Some("vendor-schema"),
        Some(VisualReadOnlyReason::Generated) => Some("generated"),
        None => None,
    }
}

fn database_catalog() -> ConfigVisualDatabaseCatalogDto {
    ConfigVisualDatabaseCatalogDto {
        products: DATABASE_CONFIG_PRODUCTS
            .iter()
            .filter_map(|definition| {
                let files = database_visual_artifacts(definition.product)
                    .map(|artifact| ConfigVisualDatabaseFileDto {
                        key: artifact.key,
                        label: database_artifact_display_label(artifact),
                        syntax: syntax_key(artifact.dialect),
                        read_only: read_only_key(VisualDocumentKind::Database(artifact)),
                        schemas: database_schemas_for_artifact(artifact).count(),
                    })
                    .collect::<Vec<_>>();
                (!files.is_empty()).then_some(ConfigVisualDatabaseProductDto {
                    product: definition.key,
                    label: definition.label,
                    files,
                })
            })
            .collect(),
    }
}

const fn scope_key(scope: DatabaseConfigSchemaScope) -> &'static str {
    match scope {
        DatabaseConfigSchemaScope::Session => "session",
        DatabaseConfigSchemaScope::Instance => "instance",
        DatabaseConfigSchemaScope::Component => "component",
        DatabaseConfigSchemaScope::Cluster => "cluster",
        DatabaseConfigSchemaScope::Global => "global",
        DatabaseConfigSchemaScope::VendorDefined => "vendor-defined",
    }
}

pub(crate) const fn activation_key(activation: DatabaseConfigSchemaActivation) -> &'static str {
    match activation {
        DatabaseConfigSchemaActivation::Dynamic => "dynamic",
        DatabaseConfigSchemaActivation::Reload => "reload",
        DatabaseConfigSchemaActivation::Restart => "restart",
        DatabaseConfigSchemaActivation::RollingRestart => "rolling-restart",
        DatabaseConfigSchemaActivation::VendorProcedure => "vendor-procedure",
    }
}

pub(crate) const fn risk_key(risk: DatabaseConfigSchemaRisk) -> &'static str {
    match risk {
        DatabaseConfigSchemaRisk::Informational => "informational",
        DatabaseConfigSchemaRisk::Low => "low",
        DatabaseConfigSchemaRisk::Medium => "medium",
        DatabaseConfigSchemaRisk::High => "high",
        DatabaseConfigSchemaRisk::Critical => "critical",
    }
}

const fn sensitivity_key(sensitivity: DatabaseConfigSchemaSensitivity) -> &'static str {
    match sensitivity {
        DatabaseConfigSchemaSensitivity::Public => "public",
        DatabaseConfigSchemaSensitivity::OperationalMetadata => "operational-metadata",
        DatabaseConfigSchemaSensitivity::MayContainSecrets => "may-contain-secrets",
        DatabaseConfigSchemaSensitivity::PrivateKeyReference => "private-key-reference",
    }
}

/// A version as people write it: three parts, four when the fourth is used.
fn version_text(version: DatabaseConfigVersion) -> String {
    if version.revision() == 0 {
        format!(
            "{}.{}.{}",
            version.major(),
            version.minor(),
            version.patch()
        )
    } else {
        format!(
            "{}.{}.{}.{}",
            version.major(),
            version.minor(),
            version.patch(),
            version.revision()
        )
    }
}

/// The short name of the versions a schema covers ("16.x", "8.0.x"), and
/// the exact range in words. Built from the typed selector, not the
/// catalogue's English labels, so every schema reads the same way.
fn version_words(selector: DatabaseConfigVersionSelector) -> (String, String) {
    match selector {
        DatabaseConfigVersionSelector::Exact(version) => {
            let text = version_text(version);
            (text.clone(), format!("仅 {text}"))
        }
        DatabaseConfigVersionSelector::HalfOpen {
            minimum_inclusive: low,
            maximum_exclusive: high,
        } => {
            let range = format!("{} 及以上、低于 {}", version_text(low), version_text(high));
            let whole_major = low.minor() == 0
                && low.patch() == 0
                && low.revision() == 0
                && high == DatabaseConfigVersion::new(low.major().saturating_add(1), 0, 0);
            let whole_minor = low.patch() == 0
                && low.revision() == 0
                && high
                    == DatabaseConfigVersion::new(low.major(), low.minor().saturating_add(1), 0);
            let short = if whole_major {
                format!("{}.x", low.major())
            } else if whole_minor {
                format!("{}.{}.x", low.major(), low.minor())
            } else {
                range.clone()
            };
            (short, range)
        }
    }
}

/// An edition named in words; a documentation family adds nothing the
/// version does not already say.
fn edition_words(edition: Option<&str>) -> Option<String> {
    match edition? {
        "enterprise" => Some("企业版".to_owned()),
        "lite" => Some("轻量版".to_owned()),
        "standard" => Some("标准版".to_owned()),
        key if key.starts_with("official-doc-family") => None,
        key => Some(format!("版本线 {key}")),
    }
}

pub(crate) fn schema_dto(index: usize, schema: &DatabaseConfigSchema) -> ConfigVisualSchemaDto {
    let product = database_product_definition(schema.binding.product)
        .map_or("数据库", |definition| definition.label);
    let (short, range) = version_words(schema.binding.versions);
    let label = match edition_words(schema.binding.edition_key) {
        Some(edition) => format!("{product} {short} {edition}"),
        None => format!("{product} {short}"),
    };
    ConfigVisualSchemaDto {
        index,
        label,
        version: range,
        complete: schema.completeness == DatabaseConfigSchemaCompleteness::Complete,
    }
}

const fn value_kind_key(value_kind: DatabaseConfigSchemaValueKind) -> &'static str {
    match value_kind {
        DatabaseConfigSchemaValueKind::Boolean { .. } => "boolean",
        DatabaseConfigSchemaValueKind::Integer { .. } => "integer",
        DatabaseConfigSchemaValueKind::Enumeration { .. } => "enumeration",
        DatabaseConfigSchemaValueKind::Text { .. } => "text",
    }
}

fn database_view(session: &VisualEditingSession) -> ConfigVisualDatabaseDto {
    let VisualDocumentKind::Database(artifact) = session.document().kind() else {
        unreachable!("a database session always holds a database file");
    };
    let product = database_product_definition(artifact.product);
    let schemas = DATABASE_CONFIG_SCHEMAS
        .iter()
        .enumerate()
        .filter(|(_, schema)| database_schema_matches_artifact(schema, artifact))
        .map(|(index, schema)| schema_dto(index, schema))
        .take(MAX_SCHEMAS)
        .collect();
    let current = session.current_schema();
    let schema_index = current.and_then(|current| {
        DATABASE_CONFIG_SCHEMAS
            .iter()
            .position(|candidate| std::ptr::eq(candidate, current))
    });
    let rows = session.rows();
    let parameters = current
        .map(|schema| {
            schema
                .parameters
                .iter()
                .enumerate()
                .take(MAX_PARAMETERS)
                .map(|(index, parameter)| ConfigVisualParameterDto {
                    index,
                    key: parameter.canonical_key,
                    aliases: parameter.exact_aliases.to_vec(),
                    group: parameter.container_path,
                    value_kind: value_kind_key(parameter.value_kind),
                    value_domain: schema_value_kind_description(parameter.value_kind),
                    scope: scope_key(parameter.scope),
                    activation: activation_key(parameter.activation),
                    risk: risk_key(parameter.risk),
                    sensitivity: sensitivity_key(parameter.sensitivity),
                    rationale: parameter.risk_rationale,
                    purpose: parameter.competition_rationale,
                    reference: schema
                        .references
                        .iter()
                        .find(|reference| reference.id == parameter.official_reference_id)
                        .map(|reference| reference.title),
                    capability: parameter.required_capability,
                    documented_default: parameter
                        .documented_default_for_display()
                        .map(|value| value.into_owned()),
                    settable: database_parameter_goal_availability(schema, index)
                        == ConfigurationGoalAvailability::LocalDraftRecipe,
                    occurrences: rows
                        .iter()
                        .filter(|row| {
                            matches!(
                                row.database_parameter(),
                                DatabaseParameterMatch::Matched(candidate)
                                    if std::ptr::eq(candidate, parameter)
                            )
                        })
                        .count(),
                    search_terms: schema_parameter_search_terms(schema, parameter),
                })
                .collect()
        })
        .unwrap_or_default();
    ConfigVisualDatabaseDto {
        product: product.map_or("unknown", |definition| definition.key),
        product_label: product.map_or("数据库", |definition| definition.label),
        artifact_key: artifact.key,
        file_label: database_artifact_display_label(artifact),
        syntax: syntax_key(artifact.dialect),
        read_only: read_only_key(session.document().kind()),
        schemas,
        schema_index,
        parameters,
    }
}

fn valid_handle(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_HANDLE_BYTES
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn api() -> (ConfigVisualApi, ConfigApi) {
        (ConfigVisualApi::default(), ConfigApi::default())
    }

    fn view_of(response: ConfigVisualResponse) -> ConfigVisualViewDto {
        match response {
            ConfigVisualResponse::View(view) => view,
            other => panic!("expected a view, got {other:?}"),
        }
    }

    fn new_document(
        api: &ConfigVisualApi,
        quick: &ConfigApi,
        product: VisualProduct,
        template: VisualTemplate,
    ) -> ConfigVisualViewDto {
        view_of(
            api.dispatch(ConfigVisualRequest::New { product, template }, quick)
                .unwrap(),
        )
    }

    fn new_blank(api: &ConfigVisualApi, quick: &ConfigApi) -> ConfigVisualViewDto {
        new_document(api, quick, VisualProduct::Nginx, VisualTemplate::Blank)
    }

    fn add(
        api: &ConfigVisualApi,
        quick: &ConfigApi,
        view: &ConfigVisualViewDto,
        parent: Option<String>,
        kind: VisualAddKind,
        name: &str,
        arguments: &str,
    ) -> Result<ConfigVisualViewDto, ConfigVisualError> {
        add_noted(api, quick, view, parent, kind, name, arguments, None)
    }

    #[allow(clippy::too_many_arguments)]
    fn add_noted(
        api: &ConfigVisualApi,
        quick: &ConfigApi,
        view: &ConfigVisualViewDto,
        parent: Option<String>,
        kind: VisualAddKind,
        name: &str,
        arguments: &str,
        note: Option<&str>,
    ) -> Result<ConfigVisualViewDto, ConfigVisualError> {
        api.dispatch(
            ConfigVisualRequest::Add {
                document_handle: view.document_handle.clone(),
                revision: view.revision,
                parent_id: parent,
                kind,
                name: Some(name.into()),
                arguments: Some(arguments.into()),
                text: None,
                note: note.map(str::to_owned),
            },
            quick,
        )
        .map(view_of)
    }

    fn import(
        api: &ConfigVisualApi,
        quick: &ConfigApi,
        product: VisualProduct,
        source: &str,
    ) -> ConfigVisualViewDto {
        let path =
            std::env::temp_dir().join(format!("lovelyhawk-visual-{}.conf", uuid::Uuid::new_v4()));
        std::fs::write(&path, source).unwrap();
        let imported = view_of(
            api.dispatch(
                ConfigVisualRequest::Import {
                    product,
                    selected_path: path.clone(),
                },
                quick,
            )
            .unwrap(),
        );
        std::fs::remove_file(&path).unwrap();
        imported
    }

    #[test]
    fn edits_build_a_tree_and_every_edit_needs_the_revision_it_saw() {
        let (api, quick) = api();
        let blank = new_blank(&api, &quick);
        assert_eq!(blank.revision, 1);
        let handle = blank.document_handle.clone();
        let server = add(
            &api,
            &quick,
            &blank,
            None,
            VisualAddKind::Block,
            "server",
            "",
        )
        .unwrap();
        assert_eq!(server.revision, 2);
        let block = server
            .rows
            .iter()
            .find(|row| row.kind == "block")
            .unwrap()
            .id
            .clone();
        let with_listen = add(
            &api,
            &quick,
            &server,
            Some(block.clone()),
            VisualAddKind::Directive,
            "listen",
            "8080",
        )
        .unwrap();
        let text = with_listen.text.clone().unwrap();
        assert!(
            text.contains("server {") && text.contains("    listen 8080;"),
            "{text}"
        );
        let listen = with_listen
            .rows
            .iter()
            .find(|row| row.name.as_deref() == Some("listen"))
            .unwrap();
        assert_eq!(listen.depth, 1);
        assert!(listen.parent_id.is_some());
        // The page's older revision is refused and changes nothing.
        assert_eq!(
            api.dispatch(
                ConfigVisualRequest::Remove {
                    document_handle: handle.clone(),
                    revision: 2,
                    node_id: listen.id.clone(),
                },
                &quick,
            )
            .unwrap_err(),
            ConfigVisualError::Stale
        );
        // So is an id from an earlier revision, even with the current one.
        assert_eq!(
            api.dispatch(
                ConfigVisualRequest::Remove {
                    document_handle: handle.clone(),
                    revision: 3,
                    node_id: block,
                },
                &quick,
            )
            .unwrap_err(),
            ConfigVisualError::Stale
        );
        let unchanged = view_of(
            api.dispatch(
                ConfigVisualRequest::View {
                    document_handle: handle,
                    revision: 3,
                },
                &quick,
            )
            .unwrap(),
        );
        assert_eq!(unchanged.text.as_deref(), Some(text.as_str()));
    }

    #[test]
    fn a_field_cannot_become_a_second_statement_and_a_refusal_keeps_the_revision() {
        let (api, quick) = api();
        let blank = new_blank(&api, &quick);
        for (name, arguments) in [
            ("listen", "80; include /etc/passwd"),
            ("listen", "80 } server {"),
            ("", "80"),
            ("listen", "\"unterminated"),
        ] {
            assert_eq!(
                add(
                    &api,
                    &quick,
                    &blank,
                    None,
                    VisualAddKind::Directive,
                    name,
                    arguments
                )
                .unwrap_err(),
                ConfigVisualError::Rejected,
                "{name} {arguments}"
            );
        }
        let still = view_of(
            api.dispatch(
                ConfigVisualRequest::View {
                    document_handle: blank.document_handle,
                    revision: 1,
                },
                &quick,
            )
            .unwrap(),
        );
        assert_eq!(still.total_bytes, 0);
    }

    #[test]
    fn hidden_values_stay_hidden_cannot_be_copied_and_are_not_touched() {
        let (api, quick) = api();
        let source = "server {\n    proxy_set_header Authorization \"Bearer s3cr3t\";\n}\n";
        let imported = import(&api, &quick, VisualProduct::Nginx, source);
        assert!(imported.contains_sensitive && imported.text.is_none() && !imported.copy_allowed);
        assert!(!serde_json::to_string(&imported).unwrap().contains("s3cr3t"));
        let block = imported
            .rows
            .iter()
            .find(|row| row.kind == "block")
            .unwrap();
        assert!(block.sensitive && !block.editable);
        assert_eq!(
            api.dispatch(
                ConfigVisualRequest::Remove {
                    document_handle: imported.document_handle.clone(),
                    revision: 1,
                    node_id: block.id.clone(),
                },
                &quick,
            )
            .unwrap_err(),
            ConfigVisualError::Sensitive
        );
        assert_eq!(
            api.dispatch(
                ConfigVisualRequest::Export {
                    document_handle: imported.document_handle.clone(),
                    revision: 1,
                    purpose: VisualExportPurpose::Copy,
                },
                &quick,
            )
            .unwrap_err(),
            ConfigVisualError::Sensitive
        );
        // Saving to a file the operator chose keeps the bytes as they were.
        match api
            .dispatch(
                ConfigVisualRequest::Export {
                    document_handle: imported.document_handle,
                    revision: 1,
                    purpose: VisualExportPurpose::Save,
                },
                &quick,
            )
            .unwrap()
        {
            ConfigVisualResponse::Export(export) => assert_eq!(export.contents, source),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn quick_drafts_of_visual_products_open_byte_exact_and_others_are_not_offered() {
        let (api, quick) = api();
        for (product, artifact_key, suggested) in [
            ("nginx", "site", "nginx-visual.conf"),
            ("apache", "site", "httpd-visual.conf"),
            ("redis", "main", "redis.conf"),
            ("haproxy", "main", "haproxy.cfg"),
            ("mysql", "main", "my.cnf"),
            ("mariadb", "main", "my.cnf"),
        ] {
            let input: crate::config_api::ConfigGenerateInput =
                serde_json::from_value(serde_json::json!({"product": product})).unwrap();
            let draft = serde_json::to_value(quick.generate(input).unwrap()).unwrap();
            let handle = draft["handle"].as_str().unwrap().to_owned();
            let opened = view_of(
                api.dispatch(
                    ConfigVisualRequest::OpenQuick {
                        handle: handle.clone(),
                        revision: 1,
                        artifact_key: artifact_key.into(),
                    },
                    &quick,
                )
                .unwrap(),
            );
            let original = quick.artifact(&handle, 1, artifact_key).unwrap();
            assert!(opened.structured, "{product}");
            // A generated draft is read whole: nothing kept as unreadable text.
            assert!(
                opened.rows.iter().all(|row| row.kind != "opaque"),
                "{product}"
            );
            assert_eq!(opened.product, product);
            assert_eq!(opened.source, "quick");
            assert_eq!(opened.suggested_name, suggested);
            assert_eq!(
                opened.text.as_deref(),
                Some(
                    serde_json::to_value(original).unwrap()["contents"]
                        .as_str()
                        .unwrap()
                ),
                "{product}"
            );
        }
        // Products without a visual editor stay in the generator.
        for product in ["postgresql", "mongodb"] {
            let input: crate::config_api::ConfigGenerateInput =
                serde_json::from_value(serde_json::json!({ "product": product })).unwrap();
            let draft = serde_json::to_value(quick.generate(input).unwrap()).unwrap();
            let key = draft["artifacts"][0]["key"].as_str().unwrap().to_owned();
            assert_eq!(
                api.dispatch(
                    ConfigVisualRequest::OpenQuick {
                        handle: draft["handle"].as_str().unwrap().to_owned(),
                        revision: 1,
                        artifact_key: key,
                    },
                    &quick,
                )
                .unwrap_err(),
                ConfigVisualError::Unsupported,
                "{product}"
            );
        }
    }

    #[test]
    fn apache_sections_nest_edit_and_keep_what_they_cannot_parse() {
        let (api, quick) = api();
        let blank = new_document(&api, &quick, VisualProduct::Apache, VisualTemplate::Blank);
        assert_eq!(blank.product, "apache");
        let host = add(
            &api,
            &quick,
            &blank,
            None,
            VisualAddKind::Block,
            "VirtualHost",
            "*:80",
        )
        .unwrap();
        let section = host
            .rows
            .iter()
            .find(|row| row.kind == "block")
            .unwrap()
            .id
            .clone();
        let named = add(
            &api,
            &quick,
            &host,
            Some(section),
            VisualAddKind::Directive,
            "ServerName",
            "probe.example.test",
        )
        .unwrap();
        let text = named.text.clone().unwrap();
        assert!(
            text.contains("<VirtualHost *:80>")
                && text.contains("    ServerName probe.example.test")
                && text.contains("</VirtualHost>"),
            "{text}"
        );
        // A second statement cannot hide in an argument here either.
        assert_eq!(
            add(
                &api,
                &quick,
                &named,
                None,
                VisualAddKind::Directive,
                "ServerName",
                "x\nInclude /etc/passwd"
            )
            .unwrap_err(),
            ConfigVisualError::Rejected
        );
        // Renaming a section rewrites its closing tag too.
        let section = named
            .rows
            .iter()
            .find(|row| row.kind == "block")
            .unwrap()
            .id
            .clone();
        let renamed = view_of(
            api.dispatch(
                ConfigVisualRequest::Update {
                    document_handle: named.document_handle.clone(),
                    revision: named.revision,
                    node_id: section,
                    name: Some("VirtualHost".into()),
                    arguments: Some("*:8080".into()),
                    text: None,
                },
                &quick,
            )
            .unwrap(),
        );
        let text = renamed.text.unwrap();
        assert!(text.contains("<VirtualHost *:8080>") && text.contains("</VirtualHost>"));

        let perl = import(
            &api,
            &quick,
            VisualProduct::Apache,
            "ServerRoot \"/etc/httpd\"\n<Perl>\nmy $x = 1;\n</Perl>\nListen 80\n",
        );
        assert!(perl.partly_opaque && perl.rows.iter().any(|row| row.kind == "opaque"));
        let secret = import(
            &api,
            &quick,
            VisualProduct::Apache,
            "<VirtualHost *:80>\n    SSLPassPhraseDialog exec:/usr/local/bin/pass\n</VirtualHost>\n",
        );
        assert!(secret.contains_sensitive && !secret.copy_allowed && secret.text.is_none());
    }

    #[test]
    fn redis_lines_are_added_edited_and_moved_one_line_at_a_time() {
        let (api, quick) = api();
        let template = new_document(
            &api,
            &quick,
            VisualProduct::Redis,
            VisualTemplate::Competition,
        );
        assert_eq!(template.product, "redis");
        assert_eq!(template.suggested_name, "redis.conf");
        assert!(template.structured && !template.partly_opaque && !template.contains_sensitive);
        assert!(template.copy_allowed && template.text.is_some());
        assert!(template.rows.iter().all(|row| row.depth == 0));

        let blank = new_document(&api, &quick, VisualProduct::Redis, VisualTemplate::Blank);
        let bound = add(
            &api,
            &quick,
            &blank,
            None,
            VisualAddKind::Directive,
            "bind",
            "127.0.0.1 -::1",
        )
        .unwrap();
        let included = add(
            &api,
            &quick,
            &bound,
            None,
            VisualAddKind::Directive,
            "include",
            "/etc/redis/local.conf",
        )
        .unwrap();
        // A blank file keeps having no final line break, as files it reads do.
        assert_eq!(
            included.text.as_deref(),
            Some("bind 127.0.0.1 -::1\ninclude /etc/redis/local.conf")
        );
        let bind = included.rows[0].clone();
        assert_eq!(
            (bind.kind, bind.name.as_deref(), bind.arguments.as_deref()),
            ("directive", Some("bind"), Some("127.0.0.1 -::1"))
        );
        // No sections in redis.conf, and nothing under a line.
        assert_eq!(
            add(
                &api,
                &quick,
                &included,
                None,
                VisualAddKind::Block,
                "server",
                ""
            )
            .unwrap_err(),
            ConfigVisualError::Rejected
        );
        assert_eq!(
            add(
                &api,
                &quick,
                &included,
                Some(bind.id.clone()),
                VisualAddKind::Directive,
                "port",
                "6379",
            )
            .unwrap_err(),
            ConfigVisualError::NotBlock
        );
        for (name, arguments) in [
            ("port", "6379\nslaveof attacker 6379"),
            ("maxmemory", "\"256mb"),
            ("max\"memory", "256mb"),
        ] {
            assert_eq!(
                add(
                    &api,
                    &quick,
                    &included,
                    None,
                    VisualAddKind::Directive,
                    name,
                    arguments,
                )
                .unwrap_err(),
                ConfigVisualError::Rejected,
                "{name} {arguments}"
            );
        }
        let updated = view_of(
            api.dispatch(
                ConfigVisualRequest::Update {
                    document_handle: included.document_handle.clone(),
                    revision: included.revision,
                    node_id: bind.id,
                    name: Some("bind".into()),
                    arguments: Some("10.0.0.5".into()),
                    text: None,
                },
                &quick,
            )
            .unwrap(),
        );
        let include_id = updated.rows[1].id.clone();
        let moved = view_of(
            api.dispatch(
                ConfigVisualRequest::Move {
                    document_handle: updated.document_handle.clone(),
                    revision: updated.revision,
                    node_id: include_id,
                    direction: VisualDirection::Up,
                },
                &quick,
            )
            .unwrap(),
        );
        assert_eq!(
            moved
                .text
                .as_deref()
                .map(|text| text.lines().collect::<Vec<_>>()),
            Some(vec!["include /etc/redis/local.conf", "bind 10.0.0.5"])
        );

        // Passwords and private command names stay out of the page.
        let source = "port 6379\nrequirepass s3cr3t\nrename-command CONFIG cfg-7f3a9\n";
        let imported = import(&api, &quick, VisualProduct::Redis, source);
        assert!(imported.contains_sensitive && imported.text.is_none() && !imported.copy_allowed);
        let json = serde_json::to_string(&imported).unwrap();
        assert!(!json.contains("s3cr3t") && !json.contains("cfg-7f3a9"));
        let hidden = imported.rows.iter().filter(|row| row.sensitive).count();
        assert_eq!(hidden, 2);
        let secret = imported.rows.iter().find(|row| row.sensitive).unwrap();
        assert!(!secret.editable);
        assert_eq!(
            api.dispatch(
                ConfigVisualRequest::Update {
                    document_handle: imported.document_handle.clone(),
                    revision: 1,
                    node_id: secret.id.clone(),
                    name: Some("requirepass".into()),
                    arguments: Some("other".into()),
                    text: None,
                },
                &quick,
            )
            .unwrap_err(),
            ConfigVisualError::Sensitive
        );

        // A line Redis would not split is kept as written beside readable ones.
        let mixed = import(
            &api,
            &quick,
            VisualProduct::Redis,
            "port 6379\nbind \"unterminated\n",
        );
        assert!(mixed.structured && mixed.partly_opaque);
        assert_eq!(mixed.rows[1].kind, "opaque");
        assert!(!mixed.rows[1].editable);
    }

    #[test]
    fn a_chinese_note_lands_right_above_the_new_item_or_nothing_changes() {
        let (api, quick) = api();
        // Nginx, inside a block that already holds a nested block.
        let blank = new_blank(&api, &quick);
        let server = add(
            &api,
            &quick,
            &blank,
            None,
            VisualAddKind::Block,
            "server",
            "",
        )
        .unwrap();
        let server_id = server.rows[0].id.clone();
        let nested = add(
            &api,
            &quick,
            &server,
            Some(server_id),
            VisualAddKind::Block,
            "location",
            "/",
        )
        .unwrap();
        let noted = add_noted(
            &api,
            &quick,
            &nested,
            Some(nested.rows[0].id.clone()),
            VisualAddKind::Directive,
            "listen",
            "80",
            Some("监听 80 端口"),
        )
        .unwrap();
        assert_eq!(noted.revision, nested.revision + 1);
        let text = noted.text.as_deref().unwrap();
        assert!(
            text.contains("    # 监听 80 端口\n    listen 80;\n"),
            "{text}"
        );
        let comment = noted
            .rows
            .iter()
            .position(|row| row.kind == "comment")
            .unwrap();
        let listen = &noted.rows[comment + 1];
        assert_eq!(listen.name.as_deref(), Some("listen"));
        assert_eq!(listen.parent_id, noted.rows[comment].parent_id);
        assert_eq!(listen.parent_id.as_deref(), Some(noted.rows[0].id.as_str()));

        // A refused directive leaves no orphan comment behind.
        for (arguments, note) in [("80; include /etc/passwd", "说明"), ("80", "两行\n注释")] {
            assert_eq!(
                add_noted(
                    &api,
                    &quick,
                    &noted,
                    None,
                    VisualAddKind::Directive,
                    "listen",
                    arguments,
                    Some(note),
                )
                .unwrap_err(),
                ConfigVisualError::Rejected
            );
        }
        let still = view_of(
            api.dispatch(
                ConfigVisualRequest::View {
                    document_handle: noted.document_handle.clone(),
                    revision: noted.revision,
                },
                &quick,
            )
            .unwrap(),
        );
        assert_eq!(still.text, noted.text);
        // A comment carries its own text, not a note.
        assert_eq!(
            api.dispatch(
                ConfigVisualRequest::Add {
                    document_handle: noted.document_handle.clone(),
                    revision: noted.revision,
                    parent_id: None,
                    kind: VisualAddKind::Comment,
                    name: None,
                    arguments: None,
                    text: Some("注释".into()),
                    note: Some("说明".into()),
                },
                &quick,
            )
            .unwrap_err(),
            ConfigVisualError::Invalid
        );

        // Apache and Redis keep the note directly above too.
        let apache = new_document(&api, &quick, VisualProduct::Apache, VisualTemplate::Blank);
        let apache = add_noted(
            &api,
            &quick,
            &apache,
            None,
            VisualAddKind::Block,
            "VirtualHost",
            "*:80",
            Some("一个站点"),
        )
        .unwrap();
        assert!(
            apache
                .text
                .as_deref()
                .unwrap()
                .starts_with("# 一个站点\n<VirtualHost *:80>")
        );
        let redis = new_document(&api, &quick, VisualProduct::Redis, VisualTemplate::Blank);
        let redis = add_noted(
            &api,
            &quick,
            &redis,
            None,
            VisualAddKind::Directive,
            "protected-mode",
            "yes",
            Some("没设口令时只接受本机连接"),
        )
        .unwrap();
        assert_eq!(
            redis
                .text
                .as_deref()
                .map(|text| text.lines().collect::<Vec<_>>()),
            Some(vec!["# 没设口令时只接受本机连接", "protected-mode yes"])
        );
    }

    #[test]
    fn option_files_keep_options_inside_groups_and_hide_passwords() {
        let (api, quick) = api();
        for (product, label) in [
            (VisualProduct::Mysql, "mysql"),
            (VisualProduct::Mariadb, "mariadb"),
        ] {
            let template = new_document(&api, &quick, product, VisualTemplate::Competition);
            assert_eq!(template.product, label);
            assert_eq!(template.suggested_name, "my.cnf");
            assert!(template.structured && !template.partly_opaque && !template.contains_sensitive);
            let groups = template
                .rows
                .iter()
                .filter(|row| row.kind == "block")
                .map(|row| (row.name.as_deref(), row.arguments.as_deref()))
                .collect::<Vec<_>>();
            assert_eq!(groups, [(Some("mysqld"), None), (Some("client"), None)]);
            assert!(template.rows.iter().all(|row| row.depth <= 1));
            let flag = template
                .rows
                .iter()
                .find(|row| row.name.as_deref() == Some("skip-name-resolve"))
                .unwrap();
            assert_eq!((flag.kind, flag.arguments.as_deref()), ("directive", None));

            let blank = new_document(&api, &quick, product, VisualTemplate::Blank);
            // An option outside every group is refused, as the server would not read it.
            assert_eq!(
                add(
                    &api,
                    &quick,
                    &blank,
                    None,
                    VisualAddKind::Directive,
                    "port",
                    "3306"
                )
                .unwrap_err(),
                ConfigVisualError::Rejected
            );
            // A group header is its name alone.
            assert_eq!(
                add(
                    &api,
                    &quick,
                    &blank,
                    None,
                    VisualAddKind::Block,
                    "mysqld",
                    "extra"
                )
                .unwrap_err(),
                ConfigVisualError::Rejected
            );
            let group = add(
                &api,
                &quick,
                &blank,
                None,
                VisualAddKind::Block,
                "mysqld",
                "",
            )
            .unwrap();
            let id = group.rows[0].id.clone();
            let port = add(
                &api,
                &quick,
                &group,
                Some(id),
                VisualAddKind::Directive,
                "port",
                "3306",
            )
            .unwrap();
            let id = port.rows[0].id.clone();
            let flag = add_noted(
                &api,
                &quick,
                &port,
                Some(id.clone()),
                VisualAddKind::Directive,
                "skip-name-resolve",
                "",
                Some("不按主机名解析客户端地址"),
            )
            .unwrap();
            let id = flag.rows[0].id.clone();
            // A group cannot hold another group.
            assert_eq!(
                add(
                    &api,
                    &quick,
                    &flag,
                    Some(id.clone()),
                    VisualAddKind::Block,
                    "client",
                    ""
                )
                .unwrap_err(),
                ConfigVisualError::Rejected
            );
            let included = add(
                &api,
                &quick,
                &flag,
                None,
                VisualAddKind::Directive,
                "!includedir",
                "/etc/mysql/conf.d/",
            )
            .unwrap();
            // A top-level include goes before the first group: any line after
            // a [group] header belongs to that group.
            assert_eq!(
                included.text.as_deref(),
                Some(
                    "!includedir /etc/mysql/conf.d/\n[mysqld]\nport=3306\n# 不按主机名解析客户端地址\nskip-name-resolve"
                )
            );

            // Renaming the group keeps its options; a value after the name is refused.
            let group_id = included
                .rows
                .iter()
                .find(|row| row.kind == "block")
                .unwrap()
                .id
                .clone();
            let update = |view: &ConfigVisualViewDto, node: String, name: &str, arguments: &str| {
                api.dispatch(
                    ConfigVisualRequest::Update {
                        document_handle: view.document_handle.clone(),
                        revision: view.revision,
                        node_id: node,
                        name: Some(name.into()),
                        arguments: Some(arguments.into()),
                        text: None,
                    },
                    &quick,
                )
                .map(view_of)
            };
            assert_eq!(
                update(&included, group_id.clone(), "mariadb", "x").unwrap_err(),
                ConfigVisualError::Rejected
            );
            let renamed = update(&included, group_id, "mariadb", "").unwrap();
            assert!(
                renamed
                    .text
                    .as_deref()
                    .unwrap()
                    .starts_with("!includedir /etc/mysql/conf.d/\n[mariadb]\nport=3306\n")
            );
            let flag_id = renamed
                .rows
                .iter()
                .find(|row| row.name.as_deref() == Some("skip-name-resolve"))
                .unwrap()
                .id
                .clone();
            let valued = update(&renamed, flag_id, "max_connections", "500").unwrap();
            // The flag was the last line; it is rewritten in place, value and all.
            assert!(
                valued
                    .text
                    .as_deref()
                    .unwrap()
                    .ends_with("# 不按主机名解析客户端地址\nmax_connections=500")
            );

            // A password in a client group is hidden, and so is the whole text.
            let secret = import(
                &api,
                &quick,
                product,
                "[client]\nuser=ops\npassword=hunter2\n",
            );
            assert!(secret.contains_sensitive && secret.text.is_none() && !secret.copy_allowed);
            assert!(
                secret
                    .rows
                    .iter()
                    .all(|row| !format!("{row:?}").contains("hunter2"))
            );
        }
    }

    #[test]
    fn haproxy_sections_take_their_lines_and_settings_stay_inside_them() {
        let (api, quick) = api();
        let template = new_document(
            &api,
            &quick,
            VisualProduct::Haproxy,
            VisualTemplate::Competition,
        );
        assert_eq!(template.product, "haproxy");
        assert_eq!(template.suggested_name, "haproxy.cfg");
        assert!(template.structured && !template.partly_opaque && !template.contains_sensitive);
        let frontend = template
            .rows
            .iter()
            .find(|row| row.kind == "block" && row.name.as_deref() == Some("frontend"))
            .unwrap();
        assert_eq!(frontend.arguments.as_deref(), Some("http_in"));
        assert!(template.rows.iter().all(|row| row.depth <= 1));

        let blank = new_document(&api, &quick, VisualProduct::Haproxy, VisualTemplate::Blank);
        // A setting outside a section is refused, as HAProxy refuses it.
        assert_eq!(
            add(
                &api,
                &quick,
                &blank,
                None,
                VisualAddKind::Directive,
                "maxconn",
                "100"
            )
            .unwrap_err(),
            ConfigVisualError::Rejected
        );
        let global = add(
            &api,
            &quick,
            &blank,
            None,
            VisualAddKind::Block,
            "global",
            "",
        )
        .unwrap();
        let section = global.rows[0].id.clone();
        let daemon = add(
            &api,
            &quick,
            &global,
            Some(section.clone()),
            VisualAddKind::Directive,
            "daemon",
            "",
        )
        .unwrap();
        let section = daemon.rows[0].id.clone();
        let noted = add_noted(
            &api,
            &quick,
            &daemon,
            Some(section),
            VisualAddKind::Directive,
            "maxconn",
            "4096",
            Some("连接上限"),
        )
        .unwrap();
        let frontend = add_noted(
            &api,
            &quick,
            &noted,
            None,
            VisualAddKind::Block,
            "frontend",
            "web",
            Some("对外入口"),
        )
        .unwrap();
        assert_eq!(
            frontend.text.as_deref(),
            Some("global\n    daemon\n    # 连接上限\n    maxconn 4096\n# 对外入口\nfrontend web")
        );
        let kinds = frontend
            .rows
            .iter()
            .map(|row| (row.depth, row.kind))
            .collect::<Vec<_>>();
        assert_eq!(
            kinds,
            [
                (0, "block"),
                (1, "directive"),
                (1, "comment"),
                (1, "directive"),
                (0, "comment"),
                (0, "block"),
            ]
        );
        // Sections do not nest, and unknown section words are refused.
        let web = frontend.rows[5].id.clone();
        for (kind, name, arguments, parent) in [
            (VisualAddKind::Block, "backend", "app", Some(web.clone())),
            (VisualAddKind::Block, "server", "x", None),
            (
                VisualAddKind::Directive,
                "bind",
                ":80 # all",
                Some(web.clone()),
            ),
            (VisualAddKind::Directive, "bind", "\":80", Some(web.clone())),
        ] {
            assert_eq!(
                add(&api, &quick, &frontend, parent, kind, name, arguments).unwrap_err(),
                ConfigVisualError::Rejected,
                "{name} {arguments}"
            );
        }
        let renamed = view_of(
            api.dispatch(
                ConfigVisualRequest::Update {
                    document_handle: frontend.document_handle.clone(),
                    revision: frontend.revision,
                    node_id: web,
                    name: Some("frontend".into()),
                    arguments: Some("public".into()),
                    text: None,
                },
                &quick,
            )
            .unwrap(),
        );
        assert!(
            renamed
                .text
                .as_deref()
                .unwrap()
                .ends_with("# 对外入口\nfrontend public")
        );

        let imported = import(
            &api,
            &quick,
            VisualProduct::Haproxy,
            "listen stats\n    bind 127.0.0.1:8404\n    stats auth admin:s3cr3t\n",
        );
        assert!(imported.contains_sensitive && imported.text.is_none() && !imported.copy_allowed);
        assert!(!serde_json::to_string(&imported).unwrap().contains("s3cr3t"));
        let hidden = imported.rows.iter().find(|row| row.sensitive).unwrap();
        assert!(!hidden.editable && hidden.depth == 1);
    }

    fn send(
        api: &ConfigVisualApi,
        quick: &ConfigApi,
        request: serde_json::Value,
    ) -> Result<ConfigVisualResponse, ConfigVisualError> {
        api.dispatch(serde_json::from_value(request).unwrap(), quick)
    }

    fn schema_index(artifact_key: &str, version: &str) -> usize {
        DATABASE_CONFIG_SCHEMAS
            .iter()
            .position(|schema| {
                schema.binding.artifact_key == artifact_key
                    && schema.version_label.contains(version)
            })
            .unwrap_or_else(|| panic!("schema {artifact_key} {version}"))
    }

    #[test]
    fn every_schema_is_named_in_words_and_no_two_for_one_file_read_alike() {
        let labelled = DATABASE_CONFIG_SCHEMAS
            .iter()
            .enumerate()
            .map(|(index, schema)| (schema, schema_dto(index, schema)))
            .collect::<Vec<_>>();
        let pg16 = &labelled[schema_index("postgresql-main", ">=16.")].1;
        assert_eq!(
            (pg16.label.as_str(), pg16.version.as_str()),
            ("PostgreSQL 16.x", "16.0.0 及以上、低于 17.0.0")
        );
        let mysql80 = &labelled[schema_index("mysql-option-file", "8.0")].1;
        assert_eq!(mysql80.version, "8.0.11 及以上、低于 8.1.0");
        assert!(mysql80.label.ends_with("8.0.11 及以上、低于 8.1.0"));
        for (schema, dto) in &labelled {
            // The catalogue's own English names never reach the page.
            for word in [
                "schema",
                "configuration",
                "partial",
                "reviewed",
                "exact",
                ">=",
                "<",
            ] {
                assert!(
                    !dto.label.contains(word) && !dto.version.contains(word),
                    "{} / {}",
                    dto.label,
                    dto.version
                );
            }
            match schema.binding.edition_key {
                Some("enterprise") => assert!(dto.label.ends_with("企业版")),
                Some("lite") => assert!(dto.label.ends_with("轻量版")),
                _ => {}
            }
            if let DatabaseConfigVersionSelector::Exact(_) = schema.binding.versions {
                assert!(dto.version.starts_with("仅 "));
            }
        }
        // Two versions offered for one file are told apart by their names.
        for (index, (schema, dto)) in labelled.iter().enumerate() {
            for (other, other_dto) in &labelled[index + 1..] {
                if schema.binding.artifact_key == other.binding.artifact_key
                    && schema.binding.product == other.binding.product
                {
                    assert_ne!(
                        (&dto.label, &dto.version),
                        (&other_dto.label, &other_dto.version),
                        "{}",
                        schema.display_label
                    );
                }
            }
        }
    }

    #[test]
    fn catalogued_database_files_open_read_against_a_schema_and_take_reviewed_values() {
        let (api, quick) = api();
        let ConfigVisualResponse::DatabaseCatalog(catalog) = send(
            &api,
            &quick,
            serde_json::json!({ "action": "database-catalog" }),
        )
        .unwrap() else {
            panic!("catalog expected");
        };
        let postgresql = catalog
            .products
            .iter()
            .find(|product| product.product == "postgresql")
            .expect("PostgreSQL has visual files");
        let main = postgresql
            .files
            .iter()
            .find(|file| file.key == "postgresql-main")
            .unwrap();
        assert_eq!((main.syntax, main.read_only), ("postgresql-conf", None));
        assert!(main.schemas > 0);
        let auto = postgresql
            .files
            .iter()
            .find(|file| file.key == "postgresql-auto-conf")
            .unwrap();
        assert_eq!(auto.read_only, Some("generated"));
        // Every product listed has a file; none is listed empty.
        assert!(
            catalog
                .products
                .iter()
                .all(|product| !product.files.is_empty())
        );

        let opened = view_of(
            send(
                &api,
                &quick,
                serde_json::json!({ "action": "new-database", "artifactKey": "postgresql-main" }),
            )
            .unwrap(),
        );
        assert_eq!((opened.product, opened.source), ("database", "starter"));
        let database = opened.database.as_ref().unwrap();
        assert_eq!(database.artifact_key, "postgresql-main");
        assert_eq!(database.read_only, None);
        assert!(database.schema_index.is_none() && database.parameters.is_empty());
        assert!(
            opened
                .text
                .as_deref()
                .unwrap()
                .contains("listen_addresses = 'localhost'")
        );
        assert!(opened.rows.iter().all(|row| row.meaning != Some("catalog")));

        // A value cannot be set before a version is chosen.
        let index_16 = schema_index("postgresql-main", ">=16.");
        assert_eq!(
            send(
                &api,
                &quick,
                serde_json::json!({ "action": "set-parameter", "documentHandle": opened.document_handle,
                    "revision": opened.revision, "parameterIndex": 0, "value": "250" })
            )
            .unwrap_err(),
            ConfigVisualError::NoSchema
        );
        // Another file's schema is refused and the revision does not move.
        let other = schema_index("mysql-option-file", "8.4");
        assert_eq!(
            send(
                &api,
                &quick,
                serde_json::json!({ "action": "select-schema", "documentHandle": opened.document_handle,
                    "revision": opened.revision, "schema": other })
            )
            .unwrap_err(),
            ConfigVisualError::Rejected
        );
        let chosen = view_of(
            send(
                &api,
                &quick,
                serde_json::json!({ "action": "select-schema", "documentHandle": opened.document_handle,
                    "revision": opened.revision, "schema": index_16 }),
            )
            .unwrap(),
        );
        assert_eq!(chosen.text, opened.text);
        let database = chosen.database.as_ref().unwrap();
        assert_eq!(database.schema_index, Some(index_16));
        let max = database
            .parameters
            .iter()
            .find(|parameter| parameter.key == "max_connections")
            .expect("max_connections in the catalogue");
        assert!(max.settable && max.occurrences == 0);
        let listen = chosen
            .rows
            .iter()
            .find(|row| row.name.as_deref() == Some("listen_addresses"))
            .unwrap();
        if listen.meaning == Some("catalog") {
            assert!(listen.parameter_index.is_some());
            assert!(
                listen
                    .search_terms
                    .iter()
                    .any(|term| term == "listen_addresses")
            );
        }
        assert!(chosen.rows.iter().all(|row| {
            row.search_terms
                .iter()
                .all(|term| !term.contains("localhost"))
        }));

        let set = |view: &ConfigVisualViewDto, value: &str| {
            send(
                &api,
                &quick,
                serde_json::json!({ "action": "set-parameter", "documentHandle": view.document_handle,
                    "revision": view.revision, "parameterIndex": max.index, "value": value }),
            )
            .map(view_of)
        };
        let first = set(&chosen, "250").unwrap();
        assert!(
            first
                .text
                .as_deref()
                .unwrap()
                .contains("max_connections = 250")
        );
        let second = set(&first, "300").unwrap();
        let text = second.text.as_deref().unwrap();
        assert!(text.contains("max_connections = 300") && !text.contains("250"));
        assert_eq!(text.matches("max_connections").count(), 1);
        let max_after = second
            .database
            .as_ref()
            .unwrap()
            .parameters
            .iter()
            .find(|parameter| parameter.key == "max_connections")
            .unwrap();
        assert_eq!(max_after.occurrences, 1);
        // A value the schema refuses changes nothing, revision included.
        assert_eq!(
            set(&second, &"x".repeat(33)).unwrap_err(),
            ConfigVisualError::ValueRefused
        );
        assert_eq!(
            view_of(
                send(
                    &api,
                    &quick,
                    serde_json::json!({ "action": "view", "documentHandle": second.document_handle,
                    "revision": second.revision })
                )
                .unwrap()
            )
            .text,
            second.text
        );
    }

    #[test]
    fn read_only_and_duplicated_database_files_refuse_changes_and_hide_secrets() {
        let (api, quick) = api();
        let read_only = view_of(
            send(&api, &quick, serde_json::json!({ "action": "new-database", "artifactKey": "postgresql-auto-conf" }))
                .unwrap(),
        );
        assert_eq!(read_only.source, "blank");
        assert_eq!(
            read_only.database.as_ref().unwrap().read_only,
            Some("generated")
        );
        assert_eq!(
            add(
                &api,
                &quick,
                &read_only,
                None,
                VisualAddKind::Directive,
                "port",
                "5433"
            )
            .unwrap_err(),
            ConfigVisualError::ReadOnly
        );

        let duplicated = import_database(
            &api,
            &quick,
            "postgresql-main",
            "max_connections = 100\nmax_connections = 200\n",
        );
        let chosen = view_of(
            send(
                &api,
                &quick,
                serde_json::json!({ "action": "select-schema", "documentHandle": duplicated.document_handle,
                    "revision": duplicated.revision, "schema": schema_index("postgresql-main", ">=16.") }),
            )
            .unwrap(),
        );
        let max = chosen
            .database
            .as_ref()
            .unwrap()
            .parameters
            .iter()
            .find(|parameter| parameter.key == "max_connections")
            .unwrap();
        assert_eq!(max.occurrences, 2);
        assert_eq!(
            send(
                &api,
                &quick,
                serde_json::json!({ "action": "set-parameter", "documentHandle": chosen.document_handle,
                    "revision": chosen.revision, "parameterIndex": max.index, "value": "300" })
            )
            .unwrap_err(),
            ConfigVisualError::ParameterDuplicate
        );

        let secret = import_database(
            &api,
            &quick,
            "dm-init",
            "[DAMENG]\nSYSDBA_PWD=NeverShow-X9\n",
        );
        assert!(secret.contains_sensitive && secret.text.is_none() && !secret.copy_allowed);
        assert!(
            !serde_json::to_string(&secret)
                .unwrap()
                .contains("NeverShow-X9")
        );

        // Unknown and binary-only files are not opened.
        for key in ["no-such-file", "mysql-plugin-registry"] {
            assert!(
                send(
                    &api,
                    &quick,
                    serde_json::json!({ "action": "new-database", "artifactKey": key })
                )
                .is_err(),
                "{key}"
            );
        }
    }

    fn import_database(
        api: &ConfigVisualApi,
        quick: &ConfigApi,
        artifact_key: &str,
        source: &str,
    ) -> ConfigVisualViewDto {
        let path =
            std::env::temp_dir().join(format!("lovelyhawk-database-{}.conf", uuid::Uuid::new_v4()));
        std::fs::write(&path, source).unwrap();
        let imported = view_of(
            send(
                api,
                quick,
                serde_json::json!({ "action": "import-database", "artifactKey": artifact_key, "selectedPath": path }),
            )
            .unwrap(),
        );
        std::fs::remove_file(&path).unwrap();
        imported
    }

    fn goal(
        api: &ConfigVisualApi,
        quick: &ConfigApi,
        request: serde_json::Value,
    ) -> Result<serde_json::Value, ConfigVisualError> {
        send(api, quick, request).map(|response| {
            assert!(matches!(response, ConfigVisualResponse::GoalSearch(_)));
            serde_json::to_value(&response).unwrap()
        })
    }

    fn bound(view: &ConfigVisualViewDto, unsaved: bool) -> serde_json::Value {
        serde_json::json!({ "documentHandle": view.document_handle, "revision": view.revision, "unsaved": unsaved })
    }

    fn current(
        api: &ConfigVisualApi,
        quick: &ConfigApi,
        view: &ConfigVisualViewDto,
    ) -> ConfigVisualViewDto {
        view_of(
            send(
                api,
                quick,
                serde_json::json!({ "action": "view", "documentHandle": view.document_handle, "revision": view.revision }),
            )
            .unwrap(),
        )
    }

    fn select_schema(
        api: &ConfigVisualApi,
        quick: &ConfigApi,
        view: &ConfigVisualViewDto,
        schema: usize,
    ) -> ConfigVisualViewDto {
        view_of(
            send(
                api,
                quick,
                serde_json::json!({ "action": "select-schema", "documentHandle": view.document_handle,
                    "revision": view.revision, "schema": schema }),
            )
            .unwrap(),
        )
    }

    #[test]
    fn database_assignment_schema_revision_and_dirty_version_mismatch_fail_closed() {
        let (api, quick) = api();
        let pg16 = schema_index("postgresql-main", ">=16.");
        let pg17 = schema_index("postgresql-main", ">=17.");
        let opened = import_database(&api, &quick, "postgresql-main", "shared_buffers = 128MB\n");
        let on16 = select_schema(&api, &quick, &opened, pg16);
        let preview = goal(
            &api,
            &quick,
            serde_json::json!({ "action": "goal-search",
                "query": "PostgreSQL 16 @postgresql-main max_connections = 300", "document": bound(&on16, false) }),
        )
        .unwrap();
        let assignment = &preview["assignment"];
        assert_eq!(assignment["state"], "ready");
        assert_eq!(assignment["landing"], "open-draft");
        assert_eq!(assignment["blocked"], serde_json::Value::Null);
        let old_lease = assignment["lease"].as_str().unwrap().to_owned();

        // 16 → 17 → 16: the same version again, but not the document the
        // preview was made against. The old lease writes nothing.
        let on17 = select_schema(&api, &quick, &on16, pg17);
        let back = select_schema(&api, &quick, &on17, pg16);
        for document in [bound(&back, false), bound(&on16, false)] {
            assert_eq!(
                send(
                    &api,
                    &quick,
                    serde_json::json!({ "action": "goal-confirm", "lease": old_lease, "value": "300",
                        "document": document }),
                )
                .unwrap_err(),
                ConfigVisualError::GoalStale
            );
        }
        let unchanged = current(&api, &quick, &back);
        assert_eq!(unchanged.text.as_deref(), Some("shared_buffers = 128MB\n"));

        // Unsaved edits read against 17: an assignment for 16 is blocked
        // before confirming, and confirming changes nothing.
        let dirty17 = select_schema(&api, &quick, &back, pg17);
        let blocked = goal(
            &api,
            &quick,
            serde_json::json!({ "action": "goal-search",
                "query": "PostgreSQL 16 @postgresql-main max_connections = 301", "document": bound(&dirty17, true) }),
        )
        .unwrap();
        assert_eq!(blocked["assignment"]["blocked"], "other-version-unsaved");
        assert_eq!(blocked["assignment"]["landing"], serde_json::Value::Null);
        let lease = blocked["assignment"]["lease"].as_str().unwrap().to_owned();
        assert_eq!(
            send(
                &api,
                &quick,
                serde_json::json!({ "action": "goal-confirm", "lease": lease, "value": "301",
                    "document": bound(&dirty17, true) }),
            )
            .unwrap_err(),
            ConfigVisualError::GoalOtherVersionUnsaved
        );
        let still = current(&api, &quick, &dirty17);
        assert_eq!(still.revision, dirty17.revision);
        assert_eq!(still.text.as_deref(), Some("shared_buffers = 128MB\n"));
        // A lease from before the latest search is never current again.
        assert_eq!(
            send(
                &api,
                &quick,
                serde_json::json!({ "action": "goal-confirm", "lease": old_lease, "value": "300",
                    "document": bound(&dirty17, true) }),
            )
            .unwrap_err(),
            ConfigVisualError::GoalStale
        );
    }

    #[test]
    fn an_assignment_previews_without_change_then_lands_once_in_a_new_or_the_open_draft() {
        let (api, quick) = api();
        let pg16 = schema_index("postgresql-main", ">=16.");
        let preview = goal(
            &api,
            &quick,
            serde_json::json!({ "action": "goal-search",
                "query": "PostgreSQL 16 @postgresql-main max_connections = 250", "document": null }),
        )
        .unwrap();
        let assignment = &preview["assignment"];
        assert_eq!(assignment["state"], "ready");
        assert_eq!(assignment["value"], "250");
        assert_eq!(assignment["landing"], "new-draft");
        assert_eq!(assignment["target"]["key"], "max_connections");
        assert_eq!(assignment["target"]["schema"]["label"], "PostgreSQL 16.x");
        assert_eq!(assignment["target"]["schema"]["index"], pg16);
        // An assignment is never mixed with fuzzy results.
        assert_eq!(preview["results"], serde_json::json!([]));
        // Previewing opened nothing.
        assert!(api.documents.lock().is_empty());
        let lease = assignment["lease"].as_str().unwrap().to_owned();

        // The value as edited on the card, not as first typed.
        let landed = view_of(
            send(
                &api,
                &quick,
                serde_json::json!({ "action": "goal-confirm", "lease": lease, "value": "300", "document": null }),
            )
            .unwrap(),
        );
        assert_eq!(landed.source, "goal");
        assert_eq!(
            landed.text.as_deref().unwrap().trim(),
            "max_connections = 300"
        );
        let database = landed.database.as_ref().unwrap();
        assert_eq!(database.schema_index, Some(pg16));
        // A confirmed lease never applies twice.
        assert_eq!(
            send(
                &api,
                &quick,
                serde_json::json!({ "action": "goal-confirm", "lease": lease, "value": "300", "document": null }),
            )
            .unwrap_err(),
            ConfigVisualError::GoalStale
        );
        assert_eq!(api.documents.lock().len(), 1);

        // Into the open draft of the same file and version, unsaved or not.
        let again = goal(
            &api,
            &quick,
            serde_json::json!({ "action": "goal-search",
                "query": "PostgreSQL 16 @postgresql-main max_connections = 310", "document": bound(&landed, true) }),
        )
        .unwrap();
        assert_eq!(again["assignment"]["landing"], "open-draft");
        let lease = again["assignment"]["lease"].as_str().unwrap().to_owned();
        // A value outside the rules writes nothing and the lease stays.
        assert_eq!(
            send(
                &api,
                &quick,
                serde_json::json!({ "action": "goal-confirm", "lease": lease, "value": "x".repeat(33),
                    "document": bound(&landed, true) }),
            )
            .unwrap_err(),
            ConfigVisualError::GoalValueRefused
        );
        let replaced = view_of(
            send(
                &api,
                &quick,
                serde_json::json!({ "action": "goal-confirm", "lease": lease, "value": "310",
                    "document": bound(&landed, true) }),
            )
            .unwrap(),
        );
        assert_eq!(replaced.document_handle, landed.document_handle);
        assert_eq!(replaced.revision, landed.revision + 1);
        let text = replaced.text.as_deref().unwrap();
        assert!(text.contains("max_connections = 310") && !text.contains("300"));
        assert_eq!(text.matches("max_connections").count(), 1);
        assert_eq!(api.documents.lock().len(), 1);
    }

    #[test]
    fn an_ambiguous_refused_or_blocked_assignment_never_changes_a_document_or_echoes_its_value() {
        let (api, quick) = api();
        let ambiguous = goal(
            &api,
            &quick,
            serde_json::json!({ "action": "goal-search",
                "query": "MariaDB 11.4 @mariadb-option-file wait_timeout = 60", "document": null }),
        )
        .unwrap();
        let assignment = &ambiguous["assignment"];
        assert_eq!(assignment["state"], "ambiguous");
        // The candidates say where, never what value is waiting.
        assert_eq!(assignment["value"], serde_json::Value::Null);
        let candidates = assignment["candidates"].as_array().unwrap();
        assert!(candidates.len() > 1);
        let mysqld = candidates
            .iter()
            .position(|candidate| candidate["group"] == "mysqld")
            .expect("a [mysqld] candidate");
        let lease = assignment["lease"].as_str().unwrap().to_owned();
        // Nothing is confirmed before a candidate is chosen.
        assert_eq!(
            send(
                &api,
                &quick,
                serde_json::json!({ "action": "goal-confirm", "lease": lease, "value": "60", "document": null }),
            )
            .unwrap_err(),
            ConfigVisualError::GoalStale
        );
        assert_eq!(
            send(
                &api,
                &quick,
                serde_json::json!({ "action": "goal-choose", "lease": lease, "candidate": candidates.len(), "document": null }),
            )
            .unwrap_err(),
            ConfigVisualError::Invalid
        );
        let chosen = goal(
            &api,
            &quick,
            serde_json::json!({ "action": "goal-choose", "lease": lease, "candidate": mysqld, "document": null }),
        )
        .unwrap();
        assert_eq!(chosen["assignment"]["state"], "ready");
        assert_eq!(chosen["assignment"]["target"]["group"], "mysqld");
        assert_eq!(chosen["assignment"]["value"], "60");
        assert_ne!(chosen["assignment"]["lease"], lease.as_str());
        assert!(api.documents.lock().is_empty());

        // Refusals name the reason and never the value.
        for (query, reason) in [
            (
                "PostgreSQL 16 @postgresql-main max_connections = NeverEcho_X9NeverEcho_X9NeverEcho_X9",
                "value-refused",
            ),
            (
                "PostgreSQL 16 @postgresql-main max_connections 改成 NeverEcho_X9",
                "unsupported-operator",
            ),
            (
                "PostgreSQL 15 max_connections = NeverEcho_X9",
                "version-not-catalogued",
            ),
        ] {
            let refused = goal(
                &api,
                &quick,
                serde_json::json!({ "action": "goal-search", "query": query, "document": null }),
            )
            .unwrap();
            assert_eq!(refused["assignment"]["state"], "rejected", "{query}");
            assert_eq!(refused["assignment"]["rejection"], reason, "{query}");
            assert_eq!(refused["assignment"]["lease"], serde_json::Value::Null);
            assert_eq!(refused["results"], serde_json::json!([]));
            assert!(!refused.to_string().contains("NeverEcho"), "{query}");
        }

        // A file that writes the parameter twice: blocked before confirming,
        // and refused on confirming, with the document as it was.
        let pg16 = schema_index("postgresql-main", ">=16.");
        let opened = import_database(
            &api,
            &quick,
            "postgresql-main",
            "max_connections = 100\nmax_connections = 200\n",
        );
        let twice = select_schema(&api, &quick, &opened, pg16);
        let preview = goal(
            &api,
            &quick,
            serde_json::json!({ "action": "goal-search",
                "query": "PostgreSQL 16 @postgresql-main max_connections = 300", "document": bound(&twice, false) }),
        )
        .unwrap();
        assert_eq!(preview["assignment"]["blocked"], "duplicate");
        let lease = preview["assignment"]["lease"].as_str().unwrap().to_owned();
        assert_eq!(
            send(
                &api,
                &quick,
                serde_json::json!({ "action": "goal-confirm", "lease": lease, "value": "300", "document": bound(&twice, false) }),
            )
            .unwrap_err(),
            ConfigVisualError::ParameterDuplicate
        );
        let same = current(&api, &quick, &twice);
        assert_eq!(
            same.text.as_deref(),
            Some("max_connections = 100\nmax_connections = 200\n")
        );

        // Another product's document with unsaved edits is never set aside.
        let nginx = new_document(
            &api,
            &quick,
            VisualProduct::Nginx,
            VisualTemplate::Competition,
        );
        let elsewhere = goal(
            &api,
            &quick,
            serde_json::json!({ "action": "goal-search",
                "query": "PostgreSQL 16 @postgresql-main max_connections = 300", "document": bound(&nginx, true) }),
        )
        .unwrap();
        assert_eq!(elsewhere["assignment"]["blocked"], "other-file-unsaved");
        let lease = elsewhere["assignment"]["lease"]
            .as_str()
            .unwrap()
            .to_owned();
        let before = api.documents.lock().len();
        assert_eq!(
            send(
                &api,
                &quick,
                serde_json::json!({ "action": "goal-confirm", "lease": lease, "value": "300", "document": bound(&nginx, true) }),
            )
            .unwrap_err(),
            ConfigVisualError::GoalOtherFileUnsaved
        );
        assert_eq!(api.documents.lock().len(), before);
        assert_eq!(current(&api, &quick, &nginx).text, nginx.text);
    }

    #[test]
    fn unified_goal_search_finds_database_guidance_files_and_explains_unavailable_products() {
        let (api, quick) = api();
        let search = |query: &str| {
            goal(
                &api,
                &quick,
                serde_json::json!({ "action": "goal-search", "query": query, "document": null }),
            )
            .unwrap()
        };
        let results = |found: &serde_json::Value| found["results"].as_array().unwrap().clone();

        // A goal of several steps lists the version's parameters and the
        // steps that happen outside the file.
        let remote = search("PostgreSQL 允许数据库远程连接");
        assert_eq!(remote["assignment"], serde_json::Value::Null);
        let bundles = results(&remote)
            .into_iter()
            .filter(|result| result["kind"] == "database-goal" && result["product"] == "postgresql")
            .collect::<Vec<_>>();
        assert!(!bundles.is_empty());
        for bundle in &bundles {
            let steps = bundle["steps"].as_array().unwrap();
            assert!(steps.iter().any(|step| {
                step["parameters"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|key| key == "listen_addresses")
            }));
            assert!(bundle["missingRequired"].as_u64().unwrap() > 0);
            assert!(bundle["gap"].is_string());
        }

        // One reviewed parameter, findable by what it does.
        let raise = search("PostgreSQL 提高最大连接数");
        assert!(
            results(&raise)
                .iter()
                .any(|result| result["kind"] == "database-parameter"
                    && result["target"]["key"] == "max_connections"
                    && result["draftable"] == true)
        );

        // Files by product, saying whether they open here.
        let mogdb = search("MogDB");
        let files = results(&mogdb)
            .into_iter()
            .filter(|result| result["kind"] == "database-file")
            .collect::<Vec<_>>();
        assert!(!files.is_empty());
        assert!(files.iter().all(|file| file["product"] == "mogdb"));
        assert!(files.iter().any(|file| file["opens"] == true));

        // Named products that cannot do this keep their reason.
        for (query, subject, gap) in [
            ("shentong-native", "神通数据库原生版", None),
            ("Apache TLS", "Apache httpd", None),
            (
                "PostgreSQL 15 max_connections",
                "PostgreSQL",
                Some("version-not-catalogued"),
            ),
        ] {
            let found = search(query);
            let unavailable = results(&found)
                .into_iter()
                .find(|result| result["kind"] == "unavailable")
                .unwrap_or_else(|| panic!("{query}: {found}"));
            if subject != "神通数据库原生版" {
                assert_eq!(unavailable["subject"], subject, "{query}");
            }
            assert!(unavailable["gap"].is_string(), "{query}");
            if let Some(gap) = gap {
                assert_eq!(unavailable["gap"], gap, "{query}");
            }
        }

        // No text shown here repeats the catalogue's English working words
        // (field names of the answer are not text shown).
        fn strings(value: &serde_json::Value, out: &mut Vec<String>) {
            match value {
                serde_json::Value::String(text) => out.push(text.clone()),
                serde_json::Value::Array(items) => items.iter().for_each(|item| strings(item, out)),
                serde_json::Value::Object(fields) => {
                    fields.values().for_each(|item| strings(item, out))
                }
                _ => {}
            }
        }
        for query in [
            "PostgreSQL 允许数据库远程连接",
            "MogDB",
            "shentong-native",
            "PostgreSQL 提高最大连接数",
        ] {
            let mut shown = Vec::new();
            strings(&search(query), &mut shown);
            assert!(!shown.is_empty(), "{query}");
            for text in &shown {
                for word in ["Schema", "schema", "typed", "TargetGuard", "edition"] {
                    assert!(!text.contains(word), "{query}: {word} in {text}");
                }
            }
        }
        // A sentence too long for goal search is refused, not cut short.
        assert_eq!(
            send(
                &api,
                &quick,
                serde_json::json!({ "action": "goal-search", "query": "数".repeat(129), "document": null }),
            )
            .unwrap_err(),
            ConfigVisualError::GoalQueryRefused
        );
    }

    #[test]
    fn open_documents_are_never_evicted_and_closing_needs_the_current_revision() {
        let (api, quick) = api();
        let first = new_blank(&api, &quick);
        for _ in 1..MAX_DOCUMENTS {
            new_blank(&api, &quick);
        }
        assert!(matches!(
            api.dispatch(
                ConfigVisualRequest::New {
                    product: VisualProduct::Apache,
                    template: VisualTemplate::Competition,
                },
                &quick,
            ),
            Err(ConfigVisualError::Capacity)
        ));
        assert_eq!(
            api.dispatch(
                ConfigVisualRequest::Close {
                    document_handle: first.document_handle.clone(),
                    revision: 2,
                },
                &quick,
            )
            .unwrap_err(),
            ConfigVisualError::Stale
        );
        assert!(matches!(
            api.dispatch(
                ConfigVisualRequest::Close {
                    document_handle: first.document_handle,
                    revision: 1,
                },
                &quick,
            ),
            Ok(ConfigVisualResponse::Closed(_))
        ));
        let competition = new_document(
            &api,
            &quick,
            VisualProduct::Apache,
            VisualTemplate::Competition,
        );
        assert!(competition.structured && competition.total_rows > 3);
    }
}
