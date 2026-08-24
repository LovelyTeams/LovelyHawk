use std::{collections::HashMap, fmt, ops::Range, path::PathBuf, sync::Arc};

use gpui::{
    AnyElement, ClipboardItem, Context, Entity, IntoElement, PathPromptOptions, Render,
    ScrollHandle, SharedString, Subscription, UniformListScrollHandle, Window, div, prelude::*, px,
    uniform_list,
};
use gpui_component::{
    Disableable, Selectable, Sizable, StyledExt,
    button::ButtonVariants,
    input::{Input, InputEvent, InputState},
    scroll::ScrollableElement,
};
use lovelyres_core::{
    BackendServices, CoreResult,
    apache_visual::{
        ApacheVisualDocument, ApacheVisualNodeId, ApacheVisualNodeKind, ApacheVisualOutput,
        ApacheVisualRow,
    },
    configuration_goal::{
        ConfigurationGoalAvailability, ConfigurationGoalMatch, ConfigurationGoalRecipeAction,
        ConfigurationGoalSubject, ConfigurationGoalSupportGap, DatabaseGoalDefinition,
        DatabaseGoalVersionRequest, DatabaseParameterAssignment,
        DatabaseParameterAssignmentAmbiguity, DatabaseParameterAssignmentError,
        DatabaseParameterAssignmentResolution, DatabaseParameterAssignmentTarget,
        DatabaseParameterGoalDraft, DatabaseParameterGoalDraftError, apache_disable_trace_draft,
        apache_forbidden_path_draft_from_goal_query, apache_reduce_version_disclosure_draft,
        database_goal_available_version_labels, database_goal_resolutions_for_version,
        database_parameter_goal_availability, nginx_forbidden_path_from_goal_query,
        resolve_database_parameter_assignment, revalidate_database_parameter_assignment,
        revalidate_database_parameter_assignment_value, search_configuration_goals,
        select_database_parameter_assignment_candidate, validate_database_parameter_goal_value,
    },
    database_config::{
        DATABASE_CONFIG_PRODUCTS, DatabaseConfigArtifactDefinition, DatabaseConfigDialect,
        DatabaseConfigEditPolicy, DatabaseConfigProduct, DatabaseConfigProductDefinition,
        artifacts_for,
    },
    database_config_schema::{
        DATABASE_CONFIG_SCHEMAS, DatabaseConfigParameterLocator, DatabaseConfigParameterSchema,
        DatabaseConfigSchema, DatabaseConfigSchemaActivation, DatabaseConfigSchemaCompleteness,
        DatabaseConfigSchemaRisk, DatabaseConfigSchemaScope, DatabaseConfigSchemaSensitivity,
        DatabaseConfigSchemaValueError, DatabaseConfigSchemaValueKind,
        DatabaseConfigTextNormalization, MAX_DATABASE_CONFIG_SCHEMA_INPUT_BYTES,
    },
    line_config_visual::{
        LineConfigDialect, LineConfigNodeId, LineConfigNodeKind, LineConfigOutput, LineConfigRow,
        LineConfigVisualDocument,
    },
    nginx_config::{
        GeneratedNginxConfig, NginxForbiddenPath, NginxForbiddenPathRule, NginxForbiddenPathScope,
        NginxListenPort, NginxServerNames, NginxSiteConfig, NginxSiteKind, NginxSiteTarget,
        NginxStaticRoot, NginxUpstream,
    },
    nginx_visual::{
        NginxVisualDocument, NginxVisualNodeId, NginxVisualNodeKind, NginxVisualOutput,
        NginxVisualRow,
    },
    structured_config_visual::{
        StructuredConfigDialect, StructuredConfigNodeId, StructuredConfigNodeKind,
        StructuredConfigOutput, StructuredConfigRow, StructuredConfigVisualDocument,
    },
};
use tokio::task::AbortHandle;

use crate::{app::SharedAppState, runtime::TokioBridge, theme::ThemeTokens};

const DEFAULT_SERVER_NAME: &str = "example.com";
const DEFAULT_LISTEN_PORT: &str = "80";
const DEFAULT_STATIC_ROOT: &str = "/var/www/html";
const DEFAULT_UPSTREAM: &str = "http://127.0.0.1:3000";
const DEFAULT_FORBIDDEN_PATH: &str = "/admin";
const MAX_PREVIEW_LINES: usize = 512;
const MAX_PREVIEW_CHARS: usize = 16 * 1024;
const MAX_VISUAL_SEARCH_CHARS: usize = 128;
const MAX_VISUAL_ROW_LABEL_CHARS: usize = 128;
const MAX_VISUAL_ROW_PREVIEW_CHARS: usize = 192;
const MAX_DATABASE_GOAL_CHOICES: usize = 24;
const REDACTED_SCHEMA_VALUE: &str = "[sensitive value redacted]";
const LOCAL_DRAFT_SCOPE_NOTICE: &str = "未经过目标校验，不能应用/部署";
const LOCAL_DRAFT_SAVE_LABEL: &str = "另存本地草稿";
const DOCUMENTED_DEFAULT_STATUS_LABEL: &str =
    "官方文档默认（只读元数据；不是当前值、推荐值或自动填充值）";

#[derive(Clone, Copy, Debug, PartialEq)]
struct VisualWorkspaceLayout {
    split_min_height: f32,
    editor_max_height: f32,
    preview_min_height: f32,
    node_row_height: f32,
}

const VISUAL_WORKSPACE_LAYOUT: VisualWorkspaceLayout = VisualWorkspaceLayout {
    split_min_height: 600.0,
    editor_max_height: 360.0,
    preview_min_height: 200.0,
    node_row_height: 58.0,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VisualNodeKind {
    Statement,
    Container,
    Comment,
    Opaque,
}

impl VisualNodeKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Statement => "语句",
            Self::Container => "块",
            Self::Comment => "注释",
            Self::Opaque => "原文",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum VisualNodeId {
    Nginx(NginxVisualNodeId),
    Apache(ApacheVisualNodeId),
    Line(LineConfigNodeId),
    Structured(StructuredConfigNodeId),
}

impl VisualNodeId {
    const fn get(self) -> u128 {
        match self {
            Self::Nginx(id) => id.get(),
            Self::Apache(id) => id.get(),
            Self::Line(id) => id.get(),
            Self::Structured(id) => id.get(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DatabaseParameterMatch {
    NotApplicable,
    VisibleUnvalidated,
    Matched(&'static DatabaseConfigParameterSchema),
}

#[derive(Clone)]
struct VisualRow {
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
    const fn id(&self) -> VisualNodeId {
        self.id
    }

    const fn depth(&self) -> usize {
        self.depth
    }

    const fn kind(&self) -> VisualNodeKind {
        self.kind
    }

    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    fn arguments(&self) -> Option<&str> {
        self.arguments.as_deref()
    }

    fn preview(&self) -> &str {
        &self.preview
    }

    const fn child_count(&self) -> usize {
        self.child_count
    }

    const fn truncated(&self) -> bool {
        self.truncated
    }

    const fn allows_local_draft_mutation(&self) -> bool {
        self.allows_local_draft_mutation
    }

    const fn database_parameter(&self) -> DatabaseParameterMatch {
        self.database_parameter
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

impl From<LineConfigRow> for VisualRow {
    fn from(row: LineConfigRow) -> Self {
        visual_row_from_line(row, DatabaseParameterMatch::NotApplicable)
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
            allows_local_draft_mutation: false,
            sensitive: row.sensitive(),
            database_parameter: DatabaseParameterMatch::NotApplicable,
        }
    }
}

#[derive(Clone)]
enum VisualOutput {
    Nginx(NginxVisualOutput),
    Apache(ApacheVisualOutput),
    Line {
        output: LineConfigOutput,
        suggested_file_name: &'static str,
    },
    Structured {
        output: StructuredConfigOutput,
        suggested_file_name: &'static str,
    },
}

impl VisualOutput {
    fn text(&self) -> CoreResult<&str> {
        match self {
            Self::Nginx(output) => output.text(),
            Self::Apache(output) => output.text(),
            Self::Line { output, .. } => output.text(),
            Self::Structured { output, .. } => output.text(),
        }
    }

    fn suggested_file_name(&self) -> &'static str {
        match self {
            Self::Nginx(output) => output.suggested_file_name(),
            Self::Apache(output) => output.suggested_file_name(),
            Self::Line {
                suggested_file_name,
                ..
            }
            | Self::Structured {
                suggested_file_name,
                ..
            } => suggested_file_name,
        }
    }

    fn write_new(&self, destination: &std::path::Path) -> CoreResult<PathBuf> {
        match self {
            Self::Nginx(output) => output.write_new(destination),
            Self::Apache(output) => output.write_new(destination),
            Self::Line { output, .. } => output.write_new(destination),
            Self::Structured { output, .. } => output.write_new(destination),
        }
    }
}

fn database_artifact_display_label(artifact: &DatabaseConfigArtifactDefinition) -> &'static str {
    match artifact.key {
        "gbase-8a-gnode-cluster-common" => "cluster_common.cnf · GNode",
        "gbase-8a-gcluster-cluster-common" => "cluster_common.cnf · GCluster",
        _ => artifact.default_file_name.unwrap_or(artifact.key),
    }
}

fn database_goal_parameter_label(parameter: &DatabaseConfigParameterSchema) -> String {
    format!(
        "{} · {}",
        parameter.container_path.unwrap_or("根级配置"),
        parameter.canonical_key,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VisualDocumentKind {
    Nginx,
    Apache,
    Database(&'static DatabaseConfigArtifactDefinition),
}

impl VisualDocumentKind {
    fn label(self) -> &'static str {
        match self {
            Self::Nginx => "Nginx",
            Self::Apache => "Apache HTTPD",
            Self::Database(artifact) => database_product(artifact.product).label,
        }
    }

    fn validator_label(self) -> &'static str {
        match self {
            Self::Nginx => "nginx -t",
            Self::Apache => "apachectl -t",
            Self::Database(_) => "匹配产品/版本的目标校验器",
        }
    }

    fn container_label(self) -> &'static str {
        match self {
            Self::Nginx => "块",
            Self::Apache => "区段",
            Self::Database(artifact) => match artifact.dialect {
                DatabaseConfigDialect::Toml => "表",
                _ => "分组",
            },
        }
    }

    fn statement_label(self) -> &'static str {
        match self {
            Self::Nginx | Self::Apache => "指令",
            Self::Database(artifact)
                if matches!(
                    artifact.dialect,
                    DatabaseConfigDialect::PgHbaConf | DatabaseConfigDialect::PgIdentConf
                ) =>
            {
                "记录"
            }
            Self::Database(_) => "配置项",
        }
    }

    fn supports_containers(self) -> bool {
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

    fn supports_nested_containers(self) -> bool {
        match self {
            Self::Nginx | Self::Apache => true,
            Self::Database(artifact) => artifact.dialect == DatabaseConfigDialect::Toml,
        }
    }

    fn artifact_label(self) -> &'static str {
        match self {
            Self::Nginx => "nginx.conf",
            Self::Apache => "httpd.conf / apache2.conf",
            Self::Database(artifact) => database_artifact_display_label(artifact),
        }
    }

    const fn allows_lossless_local_draft(self) -> bool {
        match self {
            Self::Nginx | Self::Apache => true,
            Self::Database(artifact) => artifact.allows_lossless_local_draft(),
        }
    }

    const fn read_only_notice(self) -> Option<&'static str> {
        match self {
            Self::Database(artifact) if !artifact.allows_lossless_local_draft() => {
                if matches!(
                    artifact.edit_policy,
                    DatabaseConfigEditPolicy::VendorSchemaRequired
                ) {
                    Some(
                        "只读展示：该工件策略要求匹配产品/版本的厂商 schema；选择静态 schema 也不会解锁本地结构修改。当前仅允许导入、预览和另存本地副本，未经过目标校验，不能应用/部署。",
                    )
                } else {
                    Some(
                        "只读展示：该工件由服务器或厂商工具生成；当前仅允许导入、预览和另存本地副本，所有结构修改均已禁用，不能应用/部署。",
                    )
                }
            }
            Self::Nginx | Self::Apache | Self::Database(_) => None,
        }
    }
}

#[derive(Clone, Debug)]
enum VisualDocument {
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
    fn nginx_competition_skeleton() -> CoreResult<Self> {
        NginxVisualDocument::competition_skeleton().map(Self::Nginx)
    }

    fn apache_competition_skeleton() -> CoreResult<Self> {
        ApacheVisualDocument::competition_skeleton().map(Self::Apache)
    }

    fn competition_skeleton(kind: VisualDocumentKind) -> CoreResult<Self> {
        if let VisualDocumentKind::Database(artifact) = kind
            && !artifact.allows_lossless_local_draft()
        {
            return Err(read_only_visual_artifact(artifact));
        }
        match kind {
            VisualDocumentKind::Nginx => Self::nginx_competition_skeleton(),
            VisualDocumentKind::Apache => Self::apache_competition_skeleton(),
            VisualDocumentKind::Database(artifact) => Self::database_starter(artifact),
        }
    }

    fn selection_document(kind: VisualDocumentKind) -> CoreResult<Self> {
        match kind {
            VisualDocumentKind::Database(artifact) if !artifact.allows_lossless_local_draft() => {
                Self::parse_database(artifact, "")
            }
            VisualDocumentKind::Nginx
            | VisualDocumentKind::Apache
            | VisualDocumentKind::Database(_) => Self::competition_skeleton(kind),
        }
    }

    fn database_starter(artifact: &'static DatabaseConfigArtifactDefinition) -> CoreResult<Self> {
        if !artifact.allows_lossless_local_draft() {
            return Err(read_only_visual_artifact(artifact));
        }
        Self::parse_database(artifact, database_starter_contents(artifact))
    }

    fn parse_database(
        artifact: &'static DatabaseConfigArtifactDefinition,
        source: &str,
    ) -> CoreResult<Self> {
        match database_visual_parser(artifact).ok_or_else(unsupported_visual_artifact)? {
            DatabaseVisualParser::Line(dialect) => LineConfigVisualDocument::parse(dialect, source)
                .map(|document| Self::Line { artifact, document }),
            DatabaseVisualParser::Structured(dialect) => {
                StructuredConfigVisualDocument::parse(dialect, source)
                    .map(|document| Self::Structured { artifact, document })
            }
        }
    }

    fn from_generated(generated: &GeneratedNginxConfig) -> CoreResult<Self> {
        NginxVisualDocument::from_generated(generated).map(Self::Nginx)
    }

    fn read_local(kind: VisualDocumentKind, path: &std::path::Path) -> CoreResult<Self> {
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

    const fn kind(&self) -> VisualDocumentKind {
        match self {
            Self::Nginx(_) => VisualDocumentKind::Nginx,
            Self::Apache(_) => VisualDocumentKind::Apache,
            Self::Line { artifact, .. } => VisualDocumentKind::Database(artifact),
            Self::Structured { artifact, .. } => VisualDocumentKind::Database(artifact),
        }
    }

    const fn is_structured(&self) -> bool {
        match self {
            Self::Nginx(document) => document.is_structured(),
            Self::Apache(document) => document.is_structured(),
            Self::Line { document, .. } => document.is_structured(),
            Self::Structured { document, .. } => document.is_structured(),
        }
    }

    const fn contains_sensitive_values(&self) -> bool {
        match self {
            Self::Nginx(document) => document.contains_sensitive_values(),
            Self::Apache(document) => document.contains_sensitive_values(),
            Self::Line { document, .. } => document.contains_sensitive_values(),
            Self::Structured { document, .. } => document.contains_sensitive_values(),
        }
    }

    const fn can_copy(&self) -> bool {
        !self.contains_sensitive_values()
    }

    fn raw_bytes(&self) -> &[u8] {
        match self {
            Self::Nginx(document) => document.raw_bytes(),
            Self::Apache(document) => document.raw_bytes(),
            Self::Line { document, .. } => document.raw_bytes(),
            Self::Structured { document, .. } => document.raw_bytes(),
        }
    }

    fn output(&self) -> VisualOutput {
        match self {
            Self::Nginx(document) => VisualOutput::Nginx(document.output()),
            Self::Apache(document) => VisualOutput::Apache(document.output()),
            Self::Line { artifact, document } => VisualOutput::Line {
                output: document.output(),
                suggested_file_name: artifact
                    .default_file_name
                    .unwrap_or_else(|| document.dialect().suggested_file_name()),
            },
            Self::Structured { artifact, document } => VisualOutput::Structured {
                output: document.output(),
                suggested_file_name: artifact
                    .default_file_name
                    .unwrap_or_else(|| document.dialect().suggested_file_name()),
            },
        }
    }

    fn rows(&self) -> Vec<VisualRow> {
        self.rows_with_database_schema(None)
    }

    fn rows_with_database_schema(
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
            .map(|row: VisualRow| {
                row.with_local_draft_permission(artifact.allows_lossless_local_draft())
            })
            .collect(),
            Self::Structured { artifact, document } => document
                .rows()
                .into_iter()
                .map(Into::into)
                .map(|row: VisualRow| {
                    row.with_local_draft_permission(artifact.allows_lossless_local_draft())
                })
                .collect(),
        }
    }

    fn add_statement(
        &mut self,
        parent: Option<VisualNodeId>,
        name: &str,
        arguments: &str,
    ) -> CoreResult<()> {
        self.ensure_lossless_local_draft()?;
        match (self, parent) {
            (Self::Nginx(document), parent) => {
                document.add_directive(unwrap_nginx_parent(parent)?, name, arguments)
            }
            (Self::Apache(document), parent) => {
                document.add_directive(unwrap_apache_parent(parent)?, name, arguments)
            }
            (Self::Line { document, .. }, parent) => {
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
            (Self::Structured { .. }, _) => Err(unsupported_visual_artifact()),
        }
    }

    fn add_container(
        &mut self,
        parent: Option<VisualNodeId>,
        name: &str,
        arguments: &str,
    ) -> CoreResult<()> {
        self.ensure_lossless_local_draft()?;
        match (self, parent) {
            (Self::Nginx(document), parent) => {
                document.add_block(unwrap_nginx_parent(parent)?, name, arguments)
            }
            (Self::Apache(document), parent) => {
                document.add_section(unwrap_apache_parent(parent)?, name, arguments)
            }
            (Self::Line { document, .. }, parent) => match document.dialect() {
                LineConfigDialect::MySqlOption | LineConfigDialect::Ini => {
                    if parent.is_some() || !arguments.is_empty() {
                        return Err(unsupported_visual_artifact());
                    }
                    document.add_section(name)
                }
                LineConfigDialect::Toml => document.add_table(unwrap_line_parent(parent)?, name),
                _ => Err(unsupported_visual_artifact()),
            },
            (Self::Structured { .. }, _) => Err(unsupported_visual_artifact()),
        }
    }

    fn add_comment(&mut self, parent: Option<VisualNodeId>, text: &str) -> CoreResult<()> {
        self.ensure_lossless_local_draft()?;
        match (self, parent) {
            (Self::Nginx(document), parent) => {
                document.add_comment(unwrap_nginx_parent(parent)?, text)
            }
            (Self::Apache(document), parent) => {
                document.add_comment(unwrap_apache_parent(parent)?, text)
            }
            (Self::Line { document, .. }, parent) => {
                document.add_comment(unwrap_line_parent(parent)?, text)
            }
            (Self::Structured { .. }, _) => Err(unsupported_visual_artifact()),
        }
    }

    fn update_statement(
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

    fn update_comment(&mut self, id: VisualNodeId, text: &str) -> CoreResult<()> {
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

    fn remove(&mut self, id: VisualNodeId) -> CoreResult<()> {
        self.ensure_lossless_local_draft()?;
        match (self, id) {
            (Self::Nginx(document), VisualNodeId::Nginx(id)) => document.remove(id),
            (Self::Apache(document), VisualNodeId::Apache(id)) => document.remove(id),
            (Self::Line { document, .. }, VisualNodeId::Line(id)) => document.remove(id),
            _ => Err(stale_visual_node()),
        }
    }

    fn move_up(&mut self, id: VisualNodeId) -> CoreResult<()> {
        self.ensure_lossless_local_draft()?;
        match (self, id) {
            (Self::Nginx(document), VisualNodeId::Nginx(id)) => document.move_up(id),
            (Self::Apache(document), VisualNodeId::Apache(id)) => document.move_up(id),
            (Self::Line { document, .. }, VisualNodeId::Line(id)) => document.move_up(id),
            _ => Err(stale_visual_node()),
        }
    }

    fn move_down(&mut self, id: VisualNodeId) -> CoreResult<()> {
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
            let database_parameter = line_database_parameter(schema, &row, &container_names);
            visual_row_from_line(row, database_parameter)
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
            VisualNodeId::Apache(_) | VisualNodeId::Line(_) | VisualNodeId::Structured(_) => {
                Err(stale_visual_node())
            }
        })
        .transpose()
}

fn unwrap_apache_parent(parent: Option<VisualNodeId>) -> CoreResult<Option<ApacheVisualNodeId>> {
    parent
        .map(|id| match id {
            VisualNodeId::Apache(id) => Ok(id),
            VisualNodeId::Nginx(_) | VisualNodeId::Line(_) | VisualNodeId::Structured(_) => {
                Err(stale_visual_node())
            }
        })
        .transpose()
}

fn unwrap_line_parent(parent: Option<VisualNodeId>) -> CoreResult<Option<LineConfigNodeId>> {
    parent
        .map(|id| match id {
            VisualNodeId::Line(id) => Ok(id),
            VisualNodeId::Nginx(_) | VisualNodeId::Apache(_) | VisualNodeId::Structured(_) => {
                Err(stale_visual_node())
            }
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

fn visual_editor_values(row: &VisualRow) -> (String, String) {
    (
        row.name().unwrap_or_default().to_owned(),
        row.arguments().unwrap_or_default().to_owned(),
    )
}

fn unsupported_visual_artifact() -> lovelyres_core::CoreError {
    lovelyres_core::CoreError::Validation {
        subject: "visual configuration artifact",
        message: "the selected artifact does not support this structural operation".to_owned(),
    }
}

fn read_only_visual_artifact(
    artifact: &DatabaseConfigArtifactDefinition,
) -> lovelyres_core::CoreError {
    let reason = if matches!(
        artifact.edit_policy,
        DatabaseConfigEditPolicy::VendorSchemaRequired
    ) {
        "the selected artifact policy forbids local draft mutation; selecting schema metadata does not unlock it"
    } else {
        "the selected generated artifact forbids local draft mutation"
    };
    lovelyres_core::CoreError::Validation {
        subject: "local lossless configuration draft mutation",
        message: reason.to_owned(),
    }
}

fn database_product(product: DatabaseConfigProduct) -> &'static DatabaseConfigProductDefinition {
    DATABASE_CONFIG_PRODUCTS
        .iter()
        .find(|definition| definition.product == product)
        .expect("database configuration catalog covers every product enum")
}

fn database_schema_matches_artifact(
    schema: &DatabaseConfigSchema,
    artifact: &DatabaseConfigArtifactDefinition,
) -> bool {
    schema.binding.product == artifact.product
        && schema.binding.component == artifact.component
        && schema.binding.artifact_key == artifact.key
}

const fn schema_completeness_label(completeness: DatabaseConfigSchemaCompleteness) -> &'static str {
    match completeness {
        DatabaseConfigSchemaCompleteness::Partial => {
            "Partial（未列出的 key 保持 VisibleUnvalidated）"
        }
        DatabaseConfigSchemaCompleteness::Complete => "Complete",
    }
}

const fn schema_scope_label(scope: DatabaseConfigSchemaScope) -> &'static str {
    match scope {
        DatabaseConfigSchemaScope::Session => "Session",
        DatabaseConfigSchemaScope::Instance => "Instance",
        DatabaseConfigSchemaScope::Component => "Component",
        DatabaseConfigSchemaScope::Cluster => "Cluster",
        DatabaseConfigSchemaScope::Global => "Global",
        DatabaseConfigSchemaScope::VendorDefined => "VendorDefined",
    }
}

const fn schema_activation_label(activation: DatabaseConfigSchemaActivation) -> &'static str {
    match activation {
        DatabaseConfigSchemaActivation::Dynamic => "Dynamic",
        DatabaseConfigSchemaActivation::Reload => "Reload",
        DatabaseConfigSchemaActivation::Restart => "Restart",
        DatabaseConfigSchemaActivation::RollingRestart => "RollingRestart",
        DatabaseConfigSchemaActivation::VendorProcedure => "VendorProcedure",
    }
}

const fn schema_risk_label(risk: DatabaseConfigSchemaRisk) -> &'static str {
    match risk {
        DatabaseConfigSchemaRisk::Informational => "Informational",
        DatabaseConfigSchemaRisk::Low => "Low",
        DatabaseConfigSchemaRisk::Medium => "Medium",
        DatabaseConfigSchemaRisk::High => "High",
        DatabaseConfigSchemaRisk::Critical => "Critical",
    }
}

const fn schema_sensitivity_label(sensitivity: DatabaseConfigSchemaSensitivity) -> &'static str {
    match sensitivity {
        DatabaseConfigSchemaSensitivity::Public => "Public",
        DatabaseConfigSchemaSensitivity::OperationalMetadata => "OperationalMetadata",
        DatabaseConfigSchemaSensitivity::MayContainSecrets => "MayContainSecrets",
        DatabaseConfigSchemaSensitivity::PrivateKeyReference => "PrivateKeyReference",
    }
}

const fn schema_value_kind_label(value_kind: DatabaseConfigSchemaValueKind) -> &'static str {
    match value_kind {
        DatabaseConfigSchemaValueKind::Boolean { .. } => "Boolean",
        DatabaseConfigSchemaValueKind::Integer { .. } => "Integer",
        DatabaseConfigSchemaValueKind::Enumeration { .. } => "Enumeration",
        DatabaseConfigSchemaValueKind::Text { .. } => "Text",
    }
}

const fn text_normalization_label(normalization: DatabaseConfigTextNormalization) -> &'static str {
    match normalization {
        DatabaseConfigTextNormalization::Preserve => "Preserve",
        DatabaseConfigTextNormalization::TrimAsciiWhitespace => "TrimAsciiWhitespace",
    }
}

fn schema_value_kind_description(value_kind: DatabaseConfigSchemaValueKind) -> String {
    match value_kind {
        DatabaseConfigSchemaValueKind::Boolean {
            true_literal,
            false_literal,
        } => format!("Boolean（true={true_literal}；false={false_literal}）"),
        DatabaseConfigSchemaValueKind::Integer {
            minimum_inclusive,
            maximum_inclusive,
        } => format!("Integer（{minimum_inclusive}..={maximum_inclusive}）"),
        DatabaseConfigSchemaValueKind::Enumeration { values } => {
            format!("Enumeration（{}）", values.join("、"))
        }
        DatabaseConfigSchemaValueKind::Text {
            minimum_bytes,
            maximum_bytes,
            normalization,
        } => format!(
            "Text（{minimum_bytes}..={maximum_bytes} bytes；normalization={}）",
            text_normalization_label(normalization)
        ),
    }
}

fn schema_value_kind_matches_bounded_query(
    value_kind: DatabaseConfigSchemaValueKind,
    query: &str,
) -> bool {
    if ascii_case_insensitive_contains(schema_value_kind_label(value_kind), query) {
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

fn bounded_visual_search_query(value: &str) -> String {
    value.chars().take(MAX_VISUAL_SEARCH_CHARS).collect()
}

fn nginx_forbidden_goal_query_path(value: &str) -> Option<String> {
    let core_path = nginx_forbidden_path_from_goal_query(value)?;
    let query = bounded_visual_search_query(value);
    for (start, character) in query.char_indices() {
        if character != '/' {
            continue;
        }
        let has_safe_start = query[..start].chars().next_back().is_none_or(|character| {
            character.is_whitespace() || matches!(character, ',' | '，' | '。' | '、' | ':' | '：')
        });
        if !has_safe_start {
            continue;
        }
        let tail = &query[start..];
        let end = tail
            .char_indices()
            .take_while(|(_, character)| {
                character.is_ascii_alphanumeric()
                    || matches!(character, '/' | '-' | '_' | '.' | '~')
            })
            .last()
            .map_or(1, |(index, character)| index + character.len_utf8());
        let candidate = &tail[..end];
        let has_safe_boundary = tail[end..].chars().next().is_none_or(|character| {
            character.is_whitespace() || matches!(character, ',' | '，' | '。' | '、' | ':' | '：')
        });
        if has_safe_boundary
            && NginxForbiddenPath::parse(candidate).is_ok()
            && candidate == core_path.as_str()
        {
            return Some(core_path.as_str().to_owned());
        }
    }
    None
}

fn nginx_forbidden_goal_matches(value: &str) -> bool {
    let registered_match = search_configuration_goals(value).is_ok_and(|results| {
        results.matches().iter().any(|goal| {
            matches!(
                goal,
                ConfigurationGoalMatch::Recipe(recipe)
                    if recipe.action == ConfigurationGoalRecipeAction::NginxForbiddenPath403
            )
        })
    });
    if !registered_match {
        return false;
    }
    let query = bounded_visual_search_query(value);
    if query.trim().is_empty() {
        return true;
    }
    const ALIASES: &[&str] = &[
        "403",
        "禁止访问",
        "拒绝访问",
        "封禁",
        "禁止路径",
        "外部访问",
        "访问控制",
        "admin",
        "forbidden",
        "deny",
    ];
    ALIASES
        .iter()
        .any(|alias| ascii_case_insensitive_contains(&query, alias))
        || nginx_forbidden_goal_query_path(&query).is_some()
}

fn bounded_visual_row_text(value: &str, maximum_chars: usize) -> String {
    let mut characters = value.chars();
    let mut bounded = characters.by_ref().take(maximum_chars).collect::<String>();
    if characters.next().is_some() {
        bounded.push('…');
    }
    bounded
}

fn ascii_case_insensitive_contains(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|candidate| candidate.eq_ignore_ascii_case(needle.as_bytes()))
}

const fn visual_node_kind_search_key(kind: VisualNodeKind) -> &'static str {
    match kind {
        VisualNodeKind::Statement => "statement",
        VisualNodeKind::Container => "container",
        VisualNodeKind::Comment => "comment",
        VisualNodeKind::Opaque => "opaque",
    }
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

fn schema_parameter_matches_bounded_query(
    schema: &DatabaseConfigSchema,
    parameter: &DatabaseConfigParameterSchema,
    query: &str,
) -> bool {
    let matches = |candidate: &str| ascii_case_insensitive_contains(candidate, query);
    matches(parameter.canonical_key)
        || parameter.exact_aliases.iter().copied().any(matches)
        || parameter.container_path.is_some_and(matches)
        || schema_value_kind_matches_bounded_query(parameter.value_kind, query)
        || matches(schema_scope_label(parameter.scope))
        || matches(schema_activation_label(parameter.activation))
        || matches(schema_risk_label(parameter.risk))
        || matches(schema_sensitivity_label(parameter.sensitivity))
        || parameter.required_capability.is_some_and(matches)
        || matches(parameter.risk_rationale)
        || matches(parameter.competition_rationale)
        || schema.references.iter().any(|reference| {
            reference.id == parameter.official_reference_id
                && (matches(reference.id) || matches(reference.title))
        })
}

fn visual_row_matches_bounded_query(
    row: &VisualRow,
    schema: Option<&DatabaseConfigSchema>,
    query: &str,
) -> bool {
    if query.is_empty()
        || ascii_case_insensitive_contains(row.kind().label(), query)
        || ascii_case_insensitive_contains(visual_node_kind_search_key(row.kind()), query)
    {
        return true;
    }
    // Comment bodies and opaque/raw text are deliberately excluded even if a
    // future parser starts placing a display label in `name` for those rows.
    if matches!(
        row.kind(),
        VisualNodeKind::Statement | VisualNodeKind::Container
    ) && row
        .name()
        .is_some_and(|name| ascii_case_insensitive_contains(name, query))
    {
        return true;
    }
    let (Some(schema), DatabaseParameterMatch::Matched(parameter)) =
        (schema, row.database_parameter())
    else {
        return false;
    };
    schema_contains_parameter(schema, parameter)
        && schema_parameter_matches_bounded_query(schema, parameter, query)
}

fn filtered_visual_row_indices(
    rows: &[VisualRow],
    schema: Option<&DatabaseConfigSchema>,
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
        if !visual_row_matches_bounded_query(row, schema, &query) {
            continue;
        }
        let mut current = Some(index);
        // Rows are bounded by the core parser. The additional step bound makes
        // malformed parent cycles fail closed without looping in the UI.
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

fn filtered_schema_parameter_indices(schema: &DatabaseConfigSchema, query: &str) -> Vec<usize> {
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

fn database_schema_status(schema: Option<&DatabaseConfigSchema>) -> String {
    let Some(schema) = schema else {
        return format!(
            "Schema：未绑定。只能从当前工件的固定版本按钮选择；当前行保持本地语法展示，unknown key 不会被宣称已验证；{LOCAL_DRAFT_SCOPE_NOTICE}。"
        );
    };
    format!(
        "Schema：{} · {}；完整性：{}；edition：{}。仅做本地元数据匹配与脱敏，未核验目标版本/edition/能力，也未执行值语法验证；选择 schema 不改变本地无损草稿权限；{LOCAL_DRAFT_SCOPE_NOTICE}。",
        schema.display_label,
        schema.version_label,
        schema_completeness_label(schema.completeness),
        schema.binding.edition_key.unwrap_or("未声明"),
    )
}

fn database_parameter_guidance(
    schema: &DatabaseConfigSchema,
    parameter: &DatabaseConfigParameterSchema,
) -> String {
    let reference = schema
        .references
        .iter()
        .find(|reference| reference.id == parameter.official_reference_id);
    let reference = reference.map_or_else(
        || format!("{}（引用元数据缺失）", parameter.official_reference_id),
        |reference| format!("{} · {} · {}", reference.id, reference.title, reference.url),
    );
    let aliases = if parameter.exact_aliases.is_empty() {
        "无".to_owned()
    } else {
        parameter.exact_aliases.join("、")
    };
    // This accessor is the display boundary: it rejects sensitive or invalid
    // metadata and returns a control-free value bounded by core.
    let documented_default = parameter
        .documented_default_for_display()
        .map(|value| {
            let value = if value.is_empty() {
                "〈空字符串〉"
            } else {
                value.as_ref()
            };
            format!(" {DOCUMENTED_DEFAULT_STATUS_LABEL}：{value}。")
        })
        .unwrap_or_default();
    format!(
        "CatalogGuidance（未核目标）：参数元数据（未读取 raw value、未执行 SyntaxValid）：container={}；canonical={}；exact aliases={}；value kind={}；sensitivity={}；scope={}；activation={}；risk={}；required capability={}。风险依据：{} 竞赛依据：{} 官方参考：{}{documented_default}",
        parameter.container_path.unwrap_or("<root>"),
        parameter.canonical_key,
        aliases,
        schema_value_kind_description(parameter.value_kind),
        schema_sensitivity_label(parameter.sensitivity),
        schema_scope_label(parameter.scope),
        schema_activation_label(parameter.activation),
        schema_risk_label(parameter.risk),
        parameter.required_capability.unwrap_or("无"),
        parameter.risk_rationale,
        parameter.competition_rationale,
        reference,
    )
}

fn database_parameter_goal_error_message(error: DatabaseParameterGoalDraftError) -> &'static str {
    match error {
        DatabaseParameterGoalDraftError::SchemaUnavailable => "该 Schema 不在已审生产注册表中",
        DatabaseParameterGoalDraftError::UnknownParameter => "该参数目标已经失效",
        DatabaseParameterGoalDraftError::ArtifactUnavailable
        | DatabaseParameterGoalDraftError::ArtifactBindingMismatch => {
            "参数目标与配置工件的绑定不完整"
        }
        DatabaseParameterGoalDraftError::ReadOnlyArtifact => "该工件仅能查看，不能生成本地草稿",
        DatabaseParameterGoalDraftError::UnsupportedDialect => "该工件尚无支持受控写入的行式生成器",
        DatabaseParameterGoalDraftError::NonPublicParameter => {
            "该参数不是公开值，通用表单不会接收或保存它"
        }
        DatabaseParameterGoalDraftError::RequiredCapability => {
            "该参数依赖尚未核验的插件或厂商能力，当前只能查看说明"
        }
        DatabaseParameterGoalDraftError::VisibleUnvalidated => {
            "该参数没有通过当前 Schema 的精确定位"
        }
        DatabaseParameterGoalDraftError::InvalidValue(error) => match error {
            DatabaseConfigSchemaValueError::InputTooLong => "输入超过该 Schema 的安全上限",
            DatabaseConfigSchemaValueError::InvalidBoolean => "请输入列出的布尔值之一",
            DatabaseConfigSchemaValueError::InvalidInteger => "请输入十进制整数",
            DatabaseConfigSchemaValueError::BelowMinimum => "输入低于允许的最小值",
            DatabaseConfigSchemaValueError::AboveMaximum => "输入高于允许的最大值",
            DatabaseConfigSchemaValueError::UnknownEnumerationValue => "请输入列出的枚举值之一",
            DatabaseConfigSchemaValueError::TextTooShort => "输入短于允许的最小长度",
            DatabaseConfigSchemaValueError::TextTooLong => "输入长于允许的最大长度",
        },
        DatabaseParameterGoalDraftError::UnsafeValue => {
            "输入含控制字符或双向文本控制符，已拒绝生成"
        }
        DatabaseParameterGoalDraftError::EmptyValueUnsupported => {
            "当前写入器无法区分空赋值与无值选项，已拒绝生成"
        }
    }
}

fn database_parameter_assignment_error_message(
    error: DatabaseParameterAssignmentError,
) -> &'static str {
    match error {
        DatabaseParameterAssignmentError::QueryTooLong => "目标描述超过安全长度上限",
        DatabaseParameterAssignmentError::InvalidQuery => "目标描述含控制字符或双向文本控制符",
        DatabaseParameterAssignmentError::UnsupportedOperator => {
            "请使用“设置为”“设为”或“=”连接参数和值"
        }
        DatabaseParameterAssignmentError::MissingTarget => "赋值运算符左侧缺少完整配置目标",
        DatabaseParameterAssignmentError::MissingValue => "赋值运算符右侧缺少配置值",
        DatabaseParameterAssignmentError::MultipleOperators => "目标描述包含多个赋值运算符",
        DatabaseParameterAssignmentError::MissingProduct => "请先写明数据库产品",
        DatabaseParameterAssignmentError::AmbiguousProduct => "目标描述同时命中多个产品",
        DatabaseParameterAssignmentError::InvalidVersion => "版本格式无效",
        DatabaseParameterAssignmentError::MissingVersion => "没有匹配该版本的精确 Schema",
        DatabaseParameterAssignmentError::MissingExactSchema => {
            "该产品尚无可用于赋值的精确版本 Schema"
        }
        DatabaseParameterAssignmentError::MissingParameter => "请写明 canonical key 或精确别名",
        DatabaseParameterAssignmentError::InvalidQualifier => {
            "工件或容器限定格式无效；请按 @精确工件key [精确容器] 的顺序填写"
        }
        DatabaseParameterAssignmentError::UnknownArtifact => "没有登记这个精确工件 key",
        DatabaseParameterAssignmentError::ArtifactProductMismatch => {
            "工件 key 不属于所选数据库产品"
        }
        DatabaseParameterAssignmentError::UnknownContainer => "该精确 Schema 中没有匹配的容器路径",
        DatabaseParameterAssignmentError::UnknownParameter => "精确版本 Schema 中没有这个参数",
        DatabaseParameterAssignmentError::UnknownCandidate => "候选参数已经失效",
        DatabaseParameterAssignmentError::TooManyCandidates => {
            "候选超过安全上限；请加入精确版本、@工件key 与 [容器] 限定"
        }
        DatabaseParameterAssignmentError::Draft(error) => {
            database_parameter_goal_error_message(error)
        }
    }
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

fn stage_database_parameter_goal_document(
    document: &VisualDocument,
    schema: &'static DatabaseConfigSchema,
    parameter_index: usize,
    draft: &DatabaseParameterGoalDraft,
) -> Result<VisualDocument, &'static str> {
    let parameter = schema
        .parameters
        .get(parameter_index)
        .ok_or("目标参数已经失效")?;
    let VisualDocumentKind::Database(artifact) = document.kind() else {
        return Err("当前文档不是数据库配置工件");
    };
    if artifact.key != schema.binding.artifact_key
        || artifact.product != schema.binding.product
        || artifact.component != schema.binding.component
        || draft.container_path() != parameter.container_path
        || draft.canonical_key() != parameter.canonical_key
    {
        return Err("目标参数与当前工件、容器或 canonical key 不一致");
    }
    if !artifact.allows_lossless_local_draft() {
        return Err("当前工件只读，不能写入本地草稿");
    }

    let mut staged = document.clone();
    let rows = staged.rows_with_database_schema(Some(schema));
    let existing = rows
        .iter()
        .filter(|row| {
            matches!(
                row.database_parameter(),
                DatabaseParameterMatch::Matched(candidate)
                    if std::ptr::eq(candidate, parameter)
            )
        })
        .map(VisualRow::id)
        .collect::<Vec<_>>();
    if existing.len() > 1 {
        return Err("当前文档中该参数出现多次；为避免改变优先级，请在文档树中选择具体节点编辑");
    }

    if let Some(existing) = existing.first().copied() {
        let editable = rows
            .iter()
            .find(|row| row.id() == existing)
            .is_some_and(VisualRow::allows_local_draft_mutation);
        if !editable {
            return Err("当前参数节点不可进行本地草稿修改");
        }
        staged
            .update_statement(existing, draft.canonical_key(), draft.normalized_value())
            .map_err(|_| "本地草稿写入器拒绝更新该参数")?;
    } else {
        add_database_parameter_goal_statement_to_document(&mut staged, schema, draft)?;
    }

    let exact_rows = staged.rows_with_database_schema(Some(schema));
    let exact = exact_rows
        .iter()
        .filter(|row| {
            matches!(
                row.database_parameter(),
                DatabaseParameterMatch::Matched(candidate)
                    if std::ptr::eq(candidate, parameter)
            )
        })
        .collect::<Vec<_>>();
    if exact.len() != 1
        || exact[0].name() != Some(draft.canonical_key())
        || exact[0].arguments() != Some(draft.normalized_value())
    {
        return Err("写入后无法按 exact container + canonical key + normalized value 回读");
    }
    Ok(staged)
}

fn add_database_parameter_goal_statement_to_document(
    document: &mut VisualDocument,
    schema: &'static DatabaseConfigSchema,
    draft: &DatabaseParameterGoalDraft,
) -> Result<(), &'static str> {
    let artifact = match document.kind() {
        VisualDocumentKind::Database(artifact) => artifact,
        VisualDocumentKind::Nginx | VisualDocumentKind::Apache => {
            return Err("当前文档不是数据库配置工件");
        }
    };
    let mut added_container = None;
    let parent = if let Some(container_path) = draft.container_path() {
        let rows = document.rows_with_database_schema(Some(schema));
        let matching = rows
            .iter()
            .filter(|row| {
                row.kind() == VisualNodeKind::Container
                    && row.parent.is_none()
                    && row.name().is_some_and(|name| {
                        database_goal_container_name_matches(artifact.dialect, name, container_path)
                    })
            })
            .map(VisualRow::id)
            .collect::<Vec<_>>();
        match matching.as_slice() {
            [parent] => Some(*parent),
            [] => {
                document
                    .add_container(None, container_path, "")
                    .map_err(|_| "无法创建该参数要求的精确配置区段")?;
                let rows = document.rows_with_database_schema(Some(schema));
                let matching = rows
                    .iter()
                    .filter(|row| {
                        row.kind() == VisualNodeKind::Container
                            && row.parent.is_none()
                            && row.name().is_some_and(|name| {
                                database_goal_container_name_matches(
                                    artifact.dialect,
                                    name,
                                    container_path,
                                )
                            })
                    })
                    .map(VisualRow::id)
                    .collect::<Vec<_>>();
                let [parent] = matching.as_slice() else {
                    return Err("新建配置区段后无法精确定位，已停止写入");
                };
                added_container = Some(*parent);
                Some(*parent)
            }
            _ => return Err("当前文档存在多个同名配置区段，无法确定写入位置"),
        }
    } else {
        None
    };

    if document
        .add_statement(parent, draft.canonical_key(), draft.normalized_value())
        .is_err()
    {
        if let Some(container) = added_container {
            let _ = document.remove(container);
        }
        return Err("本地草稿写入器拒绝新增该参数");
    }
    Ok(())
}

fn database_parameter_status(
    row: Option<&VisualRow>,
    schema: Option<&DatabaseConfigSchema>,
) -> Option<String> {
    let schema = schema?;
    let row = row?;
    match row.database_parameter() {
        DatabaseParameterMatch::NotApplicable => Some(
            "SyntaxOnlyUnknown · NotApplicable：所选节点不是可由 container+key 定位的参数 Entry；未执行 schema 值验证。"
                .to_owned(),
        ),
        DatabaseParameterMatch::VisibleUnvalidated => Some(
            "SyntaxOnlyUnknown · VisibleUnvalidated：所选 Entry 的 exact parent container+key 未列入当前 schema；原文保持可见，但不声明 SyntaxValid 或目标有效。"
                .to_owned(),
        ),
        DatabaseParameterMatch::Matched(parameter) => {
            if schema_contains_parameter(schema, parameter) {
                Some(database_parameter_guidance(schema, parameter))
            } else {
                Some(
                    "SyntaxOnlyUnknown · NotApplicable：所选节点携带不属于当前 schema 的过期参数定位，已拒绝目录说明。"
                        .to_owned(),
                )
            }
        }
    }
}

const fn yes_no(value: bool) -> &'static str {
    if value { "是" } else { "否" }
}

fn visual_row_explanation(
    document_kind: VisualDocumentKind,
    row: &VisualRow,
    schema: Option<&DatabaseConfigSchema>,
) -> String {
    let meaning = match document_kind {
        VisualDocumentKind::Database(_) => database_parameter_status(Some(row), schema)
            .unwrap_or_else(|| {
                "SyntaxOnlyUnknown：尚未选择与当前工件精确绑定的静态 schema；这里只说明本地解析形状。"
                    .to_owned()
            }),
        VisualDocumentKind::Nginx | VisualDocumentKind::Apache => {
            "SyntaxOnlyUnknown：当前类型没有闭合 Schema 配置目录；这里只说明当前文档节点的本地解析形状。"
                .to_owned()
        }
    };
    let sensitive_notice = if row.sensitive {
        " 敏感值未进入搜索、配置说明或复制状态。"
    } else {
        ""
    };
    format!(
        "{meaning} 节点类型={}；层级={}；直接子节点={}；本地可编辑={}；敏感={}；显示截断={}。{sensitive_notice}",
        row.kind().label(),
        row.depth(),
        row.child_count(),
        yes_no(document_kind.allows_lossless_local_draft() && row.allows_local_draft_mutation()),
        yes_no(row.sensitive),
        yes_no(row.truncated()),
    )
}

fn database_catalog_parameter_explanation(
    schema: &DatabaseConfigSchema,
    parameter: &DatabaseConfigParameterSchema,
) -> String {
    format!(
        "{} 来源=Schema 配置目录；该目录是静态已审指导，不是目标探测或目标验证。选择目录项只显示说明，不会自动新增、修改或回填当前文件。",
        database_parameter_guidance(schema, parameter)
    )
}

fn no_visual_selection_explanation(
    document_kind: VisualDocumentKind,
    schema: Option<&DatabaseConfigSchema>,
) -> String {
    match (document_kind, schema) {
        (VisualDocumentKind::Database(_), Some(_)) => {
            "SyntaxOnlyUnknown：请选择当前文档节点，或从 Schema 配置目录选择静态指导项；目录选择不会修改文件。"
                .to_owned()
        }
        (VisualDocumentKind::Database(_), None) => {
            "SyntaxOnlyUnknown：请选择当前文档节点；当前未选择与工件精确绑定的静态 schema，因此没有 Schema 配置目录。"
                .to_owned()
        }
        (VisualDocumentKind::Nginx | VisualDocumentKind::Apache, _) => {
            "SyntaxOnlyUnknown：请选择当前文档节点；当前类型没有闭合 Schema 配置目录。"
                .to_owned()
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DatabaseVisualParser {
    Line(LineConfigDialect),
    Structured(StructuredConfigDialect),
}

fn line_dialect(artifact: &DatabaseConfigArtifactDefinition) -> Option<LineConfigDialect> {
    if !artifact.has_source_backed_visual_parser() {
        return None;
    }
    match artifact.dialect {
        DatabaseConfigDialect::MySqlOptionFile => Some(LineConfigDialect::MySqlOption),
        DatabaseConfigDialect::PostgreSqlConf => Some(LineConfigDialect::PostgresConf),
        DatabaseConfigDialect::PgHbaConf => Some(LineConfigDialect::PgHba),
        DatabaseConfigDialect::PgIdentConf => Some(LineConfigDialect::PgIdent),
        DatabaseConfigDialect::Ini => Some(LineConfigDialect::Ini),
        DatabaseConfigDialect::Toml => Some(LineConfigDialect::Toml),
        DatabaseConfigDialect::JavaProperties => Some(LineConfigDialect::JavaProperties),
        DatabaseConfigDialect::KeyValue => Some(LineConfigDialect::FlatKeyValue),
        DatabaseConfigDialect::VendorText => Some(LineConfigDialect::Whitespace),
        DatabaseConfigDialect::PostgreSqlAutoConf => Some(LineConfigDialect::PostgresConf),
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

fn database_visual_parser(
    artifact: &DatabaseConfigArtifactDefinition,
) -> Option<DatabaseVisualParser> {
    line_dialect(artifact)
        .map(DatabaseVisualParser::Line)
        .or_else(|| structured_dialect(artifact).map(DatabaseVisualParser::Structured))
}

fn database_product_has_visual_files(product: DatabaseConfigProduct) -> bool {
    artifacts_for(product).any(|artifact| {
        artifact.has_source_backed_visual_parser() && database_visual_parser(artifact).is_some()
    })
}

fn first_database_visual_artifact(
    product: DatabaseConfigProduct,
) -> Option<&'static DatabaseConfigArtifactDefinition> {
    artifacts_for(product).find(|artifact| {
        artifact.has_source_backed_visual_parser() && database_visual_parser(artifact).is_some()
    })
}

fn database_starter_contents(artifact: &DatabaseConfigArtifactDefinition) -> &'static str {
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
            "# LovelyRes MySQL/MariaDB 应急响应比赛起始配置；部署前必须按所选产品与精确版本使用官方校验器复核。\n[mysqld]\nbind-address = 127.0.0.1\nport = 3306\nlocal-infile = 0\nskip-symbolic-links\n\n[client]\nport = 3306\n"
        }
        (DatabaseConfigProduct::PostgreSql, DatabaseConfigDialect::PostgreSqlConf) => {
            "# LovelyRes 应急响应比赛起始配置；部署前以目标产品/版本校验。\nlisten_addresses = 'localhost'\nport = 5432\npassword_encryption = 'scram-sha-256'\nlogging_collector = on\nlog_connections = on\nlog_disconnections = on\n"
        }
        (DatabaseConfigProduct::PostgreSql, DatabaseConfigDialect::PgHbaConf) => {
            "# TYPE  DATABASE  USER  ADDRESS  METHOD\nlocal   all       all            peer\nhost    all       all   127.0.0.1/32   scram-sha-256\nhost    all       all   ::1/128        scram-sha-256\n"
        }
        (DatabaseConfigProduct::PostgreSql, DatabaseConfigDialect::PgIdentConf) => {
            "# MAPNAME  SYSTEM-USERNAME  DATABASE-USERNAME\n"
        }
        (_, DatabaseConfigDialect::MySqlOptionFile) => {
            "# 当前工件没有经审查的产品级 starter；请导入目标实例原文件，本页不会依据 MySQL 兼容方言猜测参数或端口。\n"
        }
        (
            _,
            DatabaseConfigDialect::PostgreSqlConf
            | DatabaseConfigDialect::PgHbaConf
            | DatabaseConfigDialect::PgIdentConf,
        ) => {
            "# 当前工件没有经审查的产品级 starter；请导入目标实例原文件，本页不会依据 PostgreSQL 兼容方言猜测参数或端口。\n"
        }
        (DatabaseConfigProduct::Dm, DatabaseConfigDialect::Ini) if artifact.key == "dm-main" => {
            "# LovelyRes DM 本地 inspect 起始配置；仅供检查，参数动态级别与范围必须由目标 DM 精确版本回读，不得据此直接应用。\nINSTANCE_NAME = DMSERVER\nPORT_NUM = 5236\n"
        }
        (_, DatabaseConfigDialect::Ini) => {
            "# LovelyRes INI 起始配置；按当前组件和目标版本添加 section/参数。\n"
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
            "# LovelyRes TOML 起始配置；组件参数随版本变化，请导入目标机原文件后编辑。\n"
        }
        (_, DatabaseConfigDialect::JavaProperties) => {
            "# LovelyRes Java properties 起始配置；请导入匹配组件版本的原文件。\n"
        }
        (DatabaseConfigProduct::Yashan, DatabaseConfigDialect::KeyValue)
            if artifact.key == "yashandb-yasdb-ini" =>
        {
            ""
        }
        (_, DatabaseConfigDialect::KeyValue | DatabaseConfigDialect::VendorText) => {
            "# LovelyRes 起始配置；请导入目标实例原文件以保留厂商扩展。\n"
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

fn stale_visual_node() -> lovelyres_core::CoreError {
    lovelyres_core::CoreError::Validation {
        subject: "visual configuration edit",
        message: "selected node is stale".to_owned(),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConfigGeneratorMode {
    Quick,
    Visual,
}

impl ConfigGeneratorMode {
    const fn label(self) -> &'static str {
        match self {
            Self::Quick => "按目标生成",
            Self::Visual => "本地无损草稿",
        }
    }
}

#[derive(Clone)]
enum ConfigSavePayload {
    Quick(GeneratedNginxConfig),
    Visual(VisualOutput),
}

impl ConfigSavePayload {
    fn suggested_file_name(&self) -> &'static str {
        match self {
            Self::Quick(generated) => generated.suggested_file_name(),
            Self::Visual(output) => output.suggested_file_name(),
        }
    }

    fn write_new(&self, destination: &std::path::Path) -> CoreResult<PathBuf> {
        match self {
            Self::Quick(generated) => generated.write_new(destination),
            Self::Visual(output) => output.write_new(destination),
        }
    }
}

#[derive(Debug)]
struct ConfigGeneratorModel {
    active: bool,
    activation_generation: u64,
    mode: ConfigGeneratorMode,
    kind: NginxSiteKind,
    security_headers: bool,
    forbidden_path_enabled: bool,
    forbidden_path_scope: NginxForbiddenPathScope,
    generated: Option<GeneratedNginxConfig>,
    visual_document: VisualDocument,
    selected_database_schema: Option<&'static DatabaseConfigSchema>,
    visual_rows: Vec<VisualRow>,
    selected_visual_node: Option<VisualNodeId>,
    selected_schema_parameter: Option<usize>,
    visual_dirty: bool,
    visual_generation: u64,
}

impl ConfigGeneratorModel {
    fn new(generated: GeneratedNginxConfig) -> Self {
        let visual_document = VisualDocument::nginx_competition_skeleton()
            .expect("checked-in Nginx competition skeleton must remain structurally valid");
        let visual_rows = visual_document.rows();
        Self {
            active: false,
            activation_generation: 0,
            mode: ConfigGeneratorMode::Quick,
            kind: NginxSiteKind::ReverseProxy,
            security_headers: true,
            forbidden_path_enabled: false,
            forbidden_path_scope: NginxForbiddenPathScope::PathAndDescendants,
            generated: Some(generated),
            visual_document,
            selected_database_schema: None,
            visual_rows,
            selected_visual_node: None,
            selected_schema_parameter: None,
            visual_dirty: false,
            visual_generation: 1,
        }
    }

    fn activate(&mut self) {
        self.active = true;
        self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
    }

    fn deactivate(&mut self) {
        self.active = false;
        self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
    }

    fn accepts(&self, activation_generation: u64) -> bool {
        self.active && self.activation_generation == activation_generation
    }

    fn refresh_visual_rows(&mut self) {
        let schema = self.current_database_schema();
        self.visual_rows = self.visual_document.rows_with_database_schema(schema);
        // Core node ids are revision leases. Never carry either document or
        // catalog selection through a reparse/schema reclassification.
        self.selected_visual_node = None;
        self.selected_schema_parameter = None;
    }

    fn selected_visual_row(&self) -> Option<&VisualRow> {
        let selected = self.selected_visual_node?;
        self.visual_rows.iter().find(|row| row.id() == selected)
    }

    fn selected_schema_parameter(&self) -> Option<&'static DatabaseConfigParameterSchema> {
        let schema = self.current_database_schema()?;
        schema.parameters.get(self.selected_schema_parameter?)
    }

    fn filtered_visual_row_indices(&self, query: &str) -> Vec<usize> {
        filtered_visual_row_indices(&self.visual_rows, self.current_database_schema(), query)
    }

    fn filtered_schema_parameter_indices(&self, query: &str) -> Vec<usize> {
        self.current_database_schema()
            .map(|schema| filtered_schema_parameter_indices(schema, query))
            .unwrap_or_default()
    }

    fn reconcile_visual_search_selection(&mut self, query: &str) -> bool {
        let visible_rows = self.filtered_visual_row_indices(query);
        let selected_row_visible = self.selected_visual_node.is_none_or(|selected| {
            self.visual_rows
                .iter()
                .position(|row| row.id() == selected)
                .is_some_and(|index| visible_rows.contains(&index))
        });
        let visible_parameters = self.filtered_schema_parameter_indices(query);
        let selected_parameter_visible = self
            .selected_schema_parameter
            .is_none_or(|index| visible_parameters.contains(&index));
        let cleared = !selected_row_visible || !selected_parameter_visible;
        if !selected_row_visible {
            self.selected_visual_node = None;
        }
        if !selected_parameter_visible {
            self.selected_schema_parameter = None;
        }
        cleared
    }

    fn select_visible_visual_node(&mut self, id: VisualNodeId, query: &str) -> Option<VisualRow> {
        let visible_rows = self.filtered_visual_row_indices(query);
        let (index, row) = self
            .visual_rows
            .iter()
            .enumerate()
            .find(|(_, row)| row.id() == id)?;
        if !visible_rows.contains(&index) {
            return None;
        }
        let row = row.clone();
        self.selected_visual_node = Some(id);
        self.selected_schema_parameter = None;
        Some(row)
    }

    fn select_visible_schema_parameter(
        &mut self,
        expected_schema: &'static DatabaseConfigSchema,
        index: usize,
        query: &str,
    ) -> Option<&'static DatabaseConfigParameterSchema> {
        if !self
            .current_database_schema()
            .is_some_and(|schema| std::ptr::eq(schema, expected_schema))
        {
            return None;
        }
        let visible_parameters = self.filtered_schema_parameter_indices(query);
        if !visible_parameters.contains(&index) {
            return None;
        }
        let parameter = expected_schema.parameters.get(index)?;
        self.selected_visual_node = None;
        self.selected_schema_parameter = Some(index);
        Some(parameter)
    }

    fn can_mutate_selected_local_draft_row(&self) -> bool {
        self.visual_document.kind().allows_lossless_local_draft()
            && self
                .selected_visual_row()
                .is_some_and(VisualRow::allows_local_draft_mutation)
    }

    fn current_database_schema(&self) -> Option<&'static DatabaseConfigSchema> {
        let VisualDocumentKind::Database(artifact) = self.visual_document.kind() else {
            return None;
        };
        self.selected_database_schema
            .filter(|schema| database_schema_matches_artifact(schema, artifact))
    }

    fn select_database_schema_from_registry(
        &mut self,
        schema: &'static DatabaseConfigSchema,
        registry: &'static [DatabaseConfigSchema],
    ) -> bool {
        let VisualDocumentKind::Database(artifact) = self.visual_document.kind() else {
            return false;
        };
        if !database_schema_matches_artifact(schema, artifact)
            || !registry
                .iter()
                .any(|candidate| std::ptr::eq(candidate, schema))
        {
            return false;
        }
        let schema_changed = !self
            .selected_database_schema
            .is_some_and(|current| std::ptr::eq(current, schema));
        self.selected_database_schema = Some(schema);
        if schema_changed {
            self.visual_generation = self.visual_generation.wrapping_add(1).max(1);
        }
        self.selected_visual_node = None;
        self.selected_schema_parameter = None;
        self.refresh_visual_rows();
        true
    }

    fn replace_visual_document(&mut self, document: VisualDocument) {
        let retained_schema = match document.kind() {
            VisualDocumentKind::Database(artifact) => self
                .selected_database_schema
                .filter(|schema| database_schema_matches_artifact(schema, artifact)),
            VisualDocumentKind::Nginx | VisualDocumentKind::Apache => None,
        };
        self.visual_document = document;
        self.selected_database_schema = retained_schema;
        self.selected_visual_node = None;
        self.selected_schema_parameter = None;
        self.visual_dirty = false;
        self.visual_generation = self.visual_generation.wrapping_add(1).max(1);
        self.refresh_visual_rows();
    }

    fn contains_sensitive_visual_values(&self) -> bool {
        self.visual_document.contains_sensitive_values()
            || self.visual_rows.iter().any(|row| row.sensitive)
    }

    fn can_copy_visual(&self) -> bool {
        self.visual_document.can_copy() && !self.visual_rows.iter().any(|row| row.sensitive)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DatabaseAssignmentLease {
    activation_generation: u64,
    input_generation: u64,
    visual_generation: u64,
    visual_dirty: bool,
    selected_schema: Option<*const DatabaseConfigSchema>,
}

enum PendingDatabaseAssignmentState {
    NotAssignment,
    Consumed,
    Ready {
        assignment: DatabaseParameterAssignment,
        value_error: Option<DatabaseParameterAssignmentError>,
    },
    Ambiguous(DatabaseParameterAssignmentAmbiguity),
    Rejected(DatabaseParameterAssignmentError),
}

struct PendingDatabaseAssignment {
    lease: DatabaseAssignmentLease,
    state: PendingDatabaseAssignmentState,
}

fn preflight_database_parameter_assignment_document(
    model: &ConfigGeneratorModel,
    assignment: &DatabaseParameterAssignment,
) -> Result<VisualDocument, &'static str> {
    let target = assignment.target();
    let schema = target.schema();
    let artifact = artifacts_for(schema.binding.product)
        .find(|artifact| {
            artifact.product == schema.binding.product
                && artifact.key == schema.binding.artifact_key
                && artifact.component == schema.binding.component
        })
        .ok_or("目标配方绑定的数据库工件不存在")?;
    let target_kind = VisualDocumentKind::Database(artifact);
    if model.visual_dirty {
        if model.visual_document.kind() != target_kind {
            return Err("当前有另一工件的未另存本地草稿；请先另存草稿");
        }
        if !model
            .current_database_schema()
            .is_some_and(|current| std::ptr::eq(current, schema))
        {
            return Err(
                "当前未另存草稿绑定的 Schema/版本与赋值目标不一致；请先另存草稿或选择完全相同的 Schema",
            );
        }
    }

    let same_schema = model
        .current_database_schema()
        .is_some_and(|current| std::ptr::eq(current, schema));
    let base = if model.visual_document.kind() == target_kind && same_schema {
        model.visual_document.clone()
    } else {
        VisualDocument::parse_database(artifact, "")
            .map_err(|_| "无法创建仅包含目标参数的空白本地草稿")?
    };
    stage_database_parameter_goal_document(
        &base,
        schema,
        target.parameter_index(),
        assignment.draft(),
    )
}

pub struct ConfigGeneratorPage {
    services: Arc<BackendServices>,
    tokio: Arc<TokioBridge>,
    shared: Entity<SharedAppState>,
    model: ConfigGeneratorModel,
    server_name_input: Entity<InputState>,
    listen_port_input: Entity<InputState>,
    static_root_input: Entity<InputState>,
    upstream_input: Entity<InputState>,
    nginx_goal_search_input: Entity<InputState>,
    forbidden_path_input: Entity<InputState>,
    visual_search_input: Entity<InputState>,
    database_assignment_value_input: Entity<InputState>,
    database_goal_value_input: Entity<InputState>,
    visual_name_input: Entity<InputState>,
    visual_arguments_input: Entity<InputState>,
    page_scroll: ScrollHandle,
    visual_node_scroll: UniformListScrollHandle,
    visual_catalog_scroll: UniformListScrollHandle,
    database_assignment_generation: u64,
    pending_database_assignment: PendingDatabaseAssignment,
    visual_editor_reset_pending: bool,
    importing: bool,
    import_abort: Option<AbortHandle>,
    saving: bool,
    save_abort: Option<AbortHandle>,
    error: Option<SharedString>,
    notice: Option<SharedString>,
    _subscriptions: Vec<Subscription>,
}

impl ConfigGeneratorPage {
    pub fn new(
        services: Arc<BackendServices>,
        tokio: Arc<TokioBridge>,
        shared: Entity<SharedAppState>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let server_name_input = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(DEFAULT_SERVER_NAME)
                .placeholder("example.com")
        });
        let listen_port_input = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(DEFAULT_LISTEN_PORT)
                .placeholder("1 - 65535")
        });
        let static_root_input = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(DEFAULT_STATIC_ROOT)
                .placeholder("/var/www/html")
        });
        let upstream_input = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(DEFAULT_UPSTREAM)
                .placeholder("http://127.0.0.1:3000")
        });
        let nginx_goal_search_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("例如：/admin 外部访问全部返回 403")
                .validate(|value, _| value.chars().count() <= MAX_VISUAL_SEARCH_CHARS)
        });
        let forbidden_path_input = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(DEFAULT_FORBIDDEN_PATH)
                .placeholder("/admin")
        });
        let visual_search_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("搜索安全名称与静态说明（最多 128 字符）")
                .validate(|value, _| value.chars().count() <= MAX_VISUAL_SEARCH_CHARS)
        });
        let database_assignment_value_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("确认前可单独修改这个公开配置值")
                .validate(|value, _| value.len() <= MAX_DATABASE_CONFIG_SCHEMA_INPUT_BYTES)
        });
        let database_goal_value_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("输入这个配置目标的新值")
                .validate(|value, _| value.len() <= MAX_DATABASE_CONFIG_SCHEMA_INPUT_BYTES)
        });
        let visual_name_input = cx.new(|cx| {
            InputState::new(window, cx).placeholder("例如 listen、location、第三方指令名")
        });
        let visual_arguments_input = cx.new(|cx| {
            InputState::new(window, cx)
                .multi_line(true)
                .placeholder("指令/块参数；选择注释时填写注释正文")
        });
        let generated = generate_from_values(
            NginxSiteKind::ReverseProxy,
            DEFAULT_SERVER_NAME,
            DEFAULT_LISTEN_PORT,
            DEFAULT_STATIC_ROOT,
            DEFAULT_UPSTREAM,
            true,
        )
        .expect("checked-in Nginx generator defaults must remain valid");

        let mut subscriptions = vec![cx.observe(&shared, |_, _, cx| cx.notify())];
        for input in [
            &server_name_input,
            &listen_port_input,
            &static_root_input,
            &upstream_input,
            &forbidden_path_input,
        ] {
            subscriptions.push(cx.subscribe_in(
                input,
                window,
                |page, _, event: &InputEvent, _, cx| {
                    if matches!(event, InputEvent::Change) {
                        page.regenerate(cx);
                    }
                },
            ));
        }
        subscriptions.push(cx.subscribe_in(
            &nginx_goal_search_input,
            window,
            |page, _, event: &InputEvent, window, cx| {
                if matches!(event, InputEvent::Change) {
                    page.handle_database_assignment_query_change(window, cx);
                }
            },
        ));
        subscriptions.push(cx.subscribe_in(
            &visual_search_input,
            window,
            |page, _, event: &InputEvent, window, cx| {
                if matches!(event, InputEvent::Change) {
                    page.handle_visual_search_change(window, cx);
                }
            },
        ));
        subscriptions.push(cx.subscribe_in(
            &database_assignment_value_input,
            window,
            |page, _, event: &InputEvent, _, cx| {
                if matches!(event, InputEvent::Change) {
                    page.handle_database_assignment_value_change(cx);
                }
            },
        ));
        subscriptions.push(cx.subscribe_in(
            &database_goal_value_input,
            window,
            |page, _, event: &InputEvent, _, cx| {
                if matches!(event, InputEvent::Change) {
                    page.error = None;
                    page.notice = None;
                    cx.notify();
                }
            },
        ));

        Self {
            services,
            tokio,
            shared,
            model: ConfigGeneratorModel::new(generated),
            server_name_input,
            listen_port_input,
            static_root_input,
            upstream_input,
            nginx_goal_search_input,
            forbidden_path_input,
            visual_search_input,
            database_assignment_value_input,
            database_goal_value_input,
            visual_name_input,
            visual_arguments_input,
            page_scroll: ScrollHandle::new(),
            visual_node_scroll: UniformListScrollHandle::new(),
            visual_catalog_scroll: UniformListScrollHandle::new(),
            database_assignment_generation: 1,
            pending_database_assignment: PendingDatabaseAssignment {
                lease: DatabaseAssignmentLease {
                    activation_generation: 0,
                    input_generation: 1,
                    visual_generation: 1,
                    visual_dirty: false,
                    selected_schema: None,
                },
                state: PendingDatabaseAssignmentState::NotAssignment,
            },
            visual_editor_reset_pending: false,
            importing: false,
            import_abort: None,
            saving: false,
            save_abort: None,
            error: None,
            notice: None,
            _subscriptions: subscriptions,
        }
    }

    pub fn activate(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.model.activate();
        self.regenerate(cx);
        self.handle_database_assignment_query_change(window, cx);
        if self.model.mode == ConfigGeneratorMode::Quick {
            self.server_name_input
                .update(cx, |input, cx| input.focus(window, cx));
        }
        cx.notify();
    }

    pub fn deactivate(&mut self, cx: &mut Context<Self>) {
        if let Some(abort) = self.import_abort.take() {
            abort.abort();
        }
        if let Some(abort) = self.save_abort.take() {
            abort.abort();
        }
        self.importing = false;
        self.saving = false;
        self.model.deactivate();
        self.advance_database_assignment_generation();
        self.pending_database_assignment = PendingDatabaseAssignment {
            lease: self.database_assignment_lease(),
            state: PendingDatabaseAssignmentState::NotAssignment,
        };
        self.notice = None;
        cx.notify();
    }

    fn select_kind(&mut self, kind: NginxSiteKind, window: &mut Window, cx: &mut Context<Self>) {
        if self.model.kind == kind {
            return;
        }
        self.model.kind = kind;
        self.regenerate(cx);
        let input = match kind {
            NginxSiteKind::Static => &self.static_root_input,
            NginxSiteKind::ReverseProxy => &self.upstream_input,
        };
        input.update(cx, |input, cx| input.focus(window, cx));
        cx.notify();
    }

    fn start_curated_configuration_goal(
        &mut self,
        action: ConfigurationGoalRecipeAction,
        query: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        match action {
            ConfigurationGoalRecipeAction::NginxStaticSite
            | ConfigurationGoalRecipeAction::NginxReverseProxy => {
                let kind = match action {
                    ConfigurationGoalRecipeAction::NginxStaticSite => NginxSiteKind::Static,
                    ConfigurationGoalRecipeAction::NginxReverseProxy => NginxSiteKind::ReverseProxy,
                    ConfigurationGoalRecipeAction::NginxForbiddenPath403
                    | ConfigurationGoalRecipeAction::ApacheForbiddenPath403
                    | ConfigurationGoalRecipeAction::ApacheDisableTrace
                    | ConfigurationGoalRecipeAction::ApacheReduceVersionDisclosure => {
                        unreachable!()
                    }
                };
                self.model.mode = ConfigGeneratorMode::Quick;
                self.model.kind = kind;
                self.regenerate(cx);
                let input = match kind {
                    NginxSiteKind::Static => &self.static_root_input,
                    NginxSiteKind::ReverseProxy => &self.upstream_input,
                };
                input.update(cx, |input, cx| input.focus(window, cx));
                self.notice = Some(
                    format!(
                        "已打开目标：{}。请填写受控字段并查看完整预览；当前只生成本地草稿，未经 nginx -t 与真实请求验证，不能应用/部署。",
                        kind.label()
                    )
                    .into(),
                );
                self.error = None;
                cx.notify();
            }
            ConfigurationGoalRecipeAction::NginxForbiddenPath403 => {
                self.start_forbidden_path_goal(query, window, cx)
            }
            ConfigurationGoalRecipeAction::ApacheForbiddenPath403 => {
                self.start_apache_forbidden_path_goal(query, window, cx)
            }
            ConfigurationGoalRecipeAction::ApacheDisableTrace => {
                self.start_apache_fixed_goal(
                    apache_disable_trace_draft,
                    "已生成 Apache server-config 禁用 TRACE 的本地草稿；TRACE 将返回 405，而不是 403。该设置是请求方法策略，不代表 TRACE 本身是漏洞；尚未执行目标 httpd -t 与真实请求验证，不能应用/部署。",
                    window,
                    cx,
                )
            }
            ConfigurationGoalRecipeAction::ApacheReduceVersionDisclosure => {
                self.start_apache_fixed_goal(
                    apache_reduce_version_disclosure_draft,
                    "已生成 Apache 全局 server-config 减少版本暴露的本地草稿；ServerTokens Prod 仍会标识 Apache，ServerSignature Off 只关闭服务器生成页面的页脚签名，这不是独立安全控制。尚未执行目标 httpd -t 与真实请求验证，不能应用/部署。",
                    window,
                    cx,
                )
            }
        }
    }

    fn start_apache_fixed_goal(
        &mut self,
        build: fn() -> CoreResult<ApacheVisualDocument>,
        notice: &'static str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if !self.allow_visual_replacement(cx) {
            return;
        }
        match build() {
            Ok(document) => self.replace_visual_document(
                VisualDocument::Apache(document),
                notice,
                Some(window),
                cx,
            ),
            Err(error) => {
                self.model.generated = None;
                self.error = Some(format!("Apache 本地目标草稿生成失败：{error}").into());
                self.notice = None;
                cx.notify();
            }
        }
    }

    fn start_apache_forbidden_path_goal(
        &mut self,
        query: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if !self.allow_visual_replacement(cx) {
            return;
        }
        match apache_forbidden_path_draft_from_goal_query(query) {
            Ok(Some(document)) => self.replace_visual_document(
                VisualDocument::Apache(document),
                "已生成 Apache 2.4 server/vhost 路径及子路径 403 本地草稿；规则拒绝所有来源（含本机）。尚未核验 mod_authz_core、目标配置图、配置合并顺序、httpd -t 或真实请求，不能应用/部署。",
                Some(window),
                cx,
            ),
            Ok(None) => {
                self.model.generated = None;
                self.error = Some(
                    "请在目标描述中写入一个规范绝对 URI 路径，例如：Apache /admin 返回 403。"
                        .into(),
                );
                self.notice = None;
                cx.notify();
            }
            Err(error) => {
                self.model.generated = None;
                self.error = Some(format!("Apache 403 本地草稿生成失败：{error}").into());
                self.notice = None;
                cx.notify();
            }
        }
    }

    fn toggle_security_headers(&mut self, cx: &mut Context<Self>) {
        self.model.security_headers = !self.model.security_headers;
        self.regenerate(cx);
    }

    fn start_forbidden_path_goal(
        &mut self,
        query: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if let Some(path) = nginx_forbidden_goal_query_path(query) {
            self.forbidden_path_input
                .update(cx, |input, cx| input.set_value(path, window, cx));
        }
        self.model.mode = ConfigGeneratorMode::Quick;
        self.model.forbidden_path_enabled = true;
        self.model.forbidden_path_scope = NginxForbiddenPathScope::PathAndDescendants;
        self.regenerate(cx);
        self.forbidden_path_input
            .update(cx, |input, cx| input.focus(window, cx));
    }

    fn toggle_forbidden_path_goal(&mut self, cx: &mut Context<Self>) {
        self.model.forbidden_path_enabled = !self.model.forbidden_path_enabled;
        self.regenerate(cx);
    }

    fn select_forbidden_path_scope(
        &mut self,
        scope: NginxForbiddenPathScope,
        cx: &mut Context<Self>,
    ) {
        if self.model.forbidden_path_scope == scope {
            return;
        }
        self.model.forbidden_path_scope = scope;
        self.regenerate(cx);
    }

    fn regenerate(&mut self, cx: &mut Context<Self>) {
        let forbidden_path = self.model.forbidden_path_enabled.then(|| {
            self.forbidden_path_input
                .read(cx)
                .value()
                .as_ref()
                .to_owned()
        });
        let result = generate_from_values_with_forbidden_path(
            self.model.kind,
            self.server_name_input.read(cx).value().as_ref(),
            self.listen_port_input.read(cx).value().as_ref(),
            self.static_root_input.read(cx).value().as_ref(),
            self.upstream_input.read(cx).value().as_ref(),
            self.model.security_headers,
            forbidden_path
                .as_deref()
                .map(|path| (path, self.model.forbidden_path_scope)),
        );
        match result {
            Ok(generated) => {
                self.model.generated = Some(generated);
                self.error = None;
            }
            Err(error) => {
                self.model.generated = None;
                self.error = Some(format!("参数校验失败：{error}").into());
            }
        }
        self.notice = None;
        cx.notify();
    }

    fn select_mode(&mut self, mode: ConfigGeneratorMode, cx: &mut Context<Self>) {
        self.model.mode = mode;
        self.error = None;
        self.notice = None;
        cx.notify();
    }

    fn database_assignment_lease(&self) -> DatabaseAssignmentLease {
        DatabaseAssignmentLease {
            activation_generation: self.model.activation_generation,
            input_generation: self.database_assignment_generation,
            visual_generation: self.model.visual_generation,
            visual_dirty: self.model.visual_dirty,
            selected_schema: self.model.selected_database_schema.map(std::ptr::from_ref),
        }
    }

    fn database_assignment_lease_is_current(&self, lease: DatabaseAssignmentLease) -> bool {
        lease == self.pending_database_assignment.lease
            && lease.activation_generation == self.model.activation_generation
            && lease.input_generation == self.database_assignment_generation
            && lease.visual_generation == self.model.visual_generation
            && lease.visual_dirty == self.model.visual_dirty
            && lease.selected_schema == self.model.selected_database_schema.map(std::ptr::from_ref)
            && self.model.active
    }

    fn advance_database_assignment_generation(&mut self) {
        self.database_assignment_generation =
            self.database_assignment_generation.wrapping_add(1).max(1);
    }

    fn handle_database_assignment_query_change(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let resolution = {
            let input = self.nginx_goal_search_input.read(cx);
            resolve_database_parameter_assignment(input.value().as_ref())
        };
        self.advance_database_assignment_generation();
        let state = match resolution {
            DatabaseParameterAssignmentResolution::NotAssignment => {
                PendingDatabaseAssignmentState::NotAssignment
            }
            DatabaseParameterAssignmentResolution::Ready(assignment) => {
                PendingDatabaseAssignmentState::Ready {
                    assignment,
                    value_error: None,
                }
            }
            DatabaseParameterAssignmentResolution::Ambiguous(ambiguity) => {
                PendingDatabaseAssignmentState::Ambiguous(ambiguity)
            }
            DatabaseParameterAssignmentResolution::Rejected(error) => {
                PendingDatabaseAssignmentState::Rejected(error)
            }
        };
        let normalized_value = match &state {
            PendingDatabaseAssignmentState::Ready { assignment, .. } => {
                Some(assignment.draft().normalized_value().to_owned())
            }
            PendingDatabaseAssignmentState::NotAssignment
            | PendingDatabaseAssignmentState::Consumed
            | PendingDatabaseAssignmentState::Ambiguous(_)
            | PendingDatabaseAssignmentState::Rejected(_) => None,
        };
        self.pending_database_assignment = PendingDatabaseAssignment {
            lease: self.database_assignment_lease(),
            state,
        };
        let replacement = normalized_value.unwrap_or_default();
        if self
            .database_assignment_value_input
            .read(cx)
            .value()
            .as_ref()
            != replacement
        {
            self.database_assignment_value_input
                .update(cx, |input, cx| input.set_value(replacement, window, cx));
        }
        self.error = None;
        self.notice = None;
        cx.notify();
    }

    fn handle_database_assignment_value_change(&mut self, cx: &mut Context<Self>) {
        if !self.database_assignment_lease_is_current(self.pending_database_assignment.lease) {
            return;
        }
        self.advance_database_assignment_generation();
        let previous = std::mem::replace(
            &mut self.pending_database_assignment.state,
            PendingDatabaseAssignmentState::NotAssignment,
        );
        self.pending_database_assignment.state = match previous {
            PendingDatabaseAssignmentState::Ready { assignment, .. } => {
                let validation = {
                    let input = self.database_assignment_value_input.read(cx);
                    revalidate_database_parameter_assignment_value(
                        &assignment,
                        input.value().as_ref(),
                    )
                };
                match validation {
                    Ok(assignment) => PendingDatabaseAssignmentState::Ready {
                        assignment,
                        value_error: None,
                    },
                    Err(error) => PendingDatabaseAssignmentState::Ready {
                        assignment,
                        value_error: Some(error),
                    },
                }
            }
            state @ (PendingDatabaseAssignmentState::NotAssignment
            | PendingDatabaseAssignmentState::Consumed
            | PendingDatabaseAssignmentState::Ambiguous(_)
            | PendingDatabaseAssignmentState::Rejected(_)) => state,
        };
        self.pending_database_assignment.lease = self.database_assignment_lease();
        self.error = None;
        self.notice = None;
        cx.notify();
    }

    fn select_database_assignment_candidate(
        &mut self,
        expected_lease: DatabaseAssignmentLease,
        target: DatabaseParameterAssignmentTarget,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if !self.database_assignment_lease_is_current(expected_lease) {
            return;
        }
        let previous = std::mem::replace(
            &mut self.pending_database_assignment.state,
            PendingDatabaseAssignmentState::NotAssignment,
        );
        let PendingDatabaseAssignmentState::Ambiguous(ambiguity) = previous else {
            return;
        };
        self.advance_database_assignment_generation();
        let state = match select_database_parameter_assignment_candidate(&ambiguity, target) {
            Ok(assignment) => PendingDatabaseAssignmentState::Ready {
                assignment,
                value_error: None,
            },
            Err(error) => PendingDatabaseAssignmentState::Rejected(error),
        };
        let normalized_value = match &state {
            PendingDatabaseAssignmentState::Ready { assignment, .. } => {
                Some(assignment.draft().normalized_value().to_owned())
            }
            PendingDatabaseAssignmentState::NotAssignment
            | PendingDatabaseAssignmentState::Consumed
            | PendingDatabaseAssignmentState::Ambiguous(_)
            | PendingDatabaseAssignmentState::Rejected(_) => None,
        };
        self.pending_database_assignment = PendingDatabaseAssignment {
            lease: self.database_assignment_lease(),
            state,
        };
        if let Some(value) = normalized_value {
            self.database_assignment_value_input
                .update(cx, |input, cx| input.set_value(value, window, cx));
        }
        self.error = None;
        self.notice = None;
        cx.notify();
    }

    fn confirm_database_parameter_assignment(
        &mut self,
        expected_lease: DatabaseAssignmentLease,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.importing
            || self.saving
            || !self.database_assignment_lease_is_current(expected_lease)
        {
            return;
        }
        let previous = std::mem::replace(
            &mut self.pending_database_assignment.state,
            PendingDatabaseAssignmentState::NotAssignment,
        );
        let PendingDatabaseAssignmentState::Ready {
            assignment,
            value_error,
        } = previous
        else {
            return;
        };
        if let Some(error) = value_error {
            self.pending_database_assignment.state = PendingDatabaseAssignmentState::Ready {
                assignment,
                value_error: Some(error),
            };
            return;
        }
        let assignment = match revalidate_database_parameter_assignment(&assignment) {
            Ok(assignment) => assignment,
            Err(error) => {
                self.pending_database_assignment.state =
                    PendingDatabaseAssignmentState::Rejected(error);
                self.error = Some(
                    format!(
                        "不能确认这个本地草稿：{}。",
                        database_parameter_assignment_error_message(error)
                    )
                    .into(),
                );
                self.notice = None;
                cx.notify();
                return;
            }
        };
        let target = assignment.target();
        let schema = target.schema();
        let parameter_index = target.parameter_index();
        let staged =
            match preflight_database_parameter_assignment_document(&self.model, &assignment) {
                Ok(staged) => staged,
                Err(message) => {
                    self.pending_database_assignment.state =
                        PendingDatabaseAssignmentState::Ready {
                            assignment,
                            value_error: None,
                        };
                    self.error =
                        Some(format!("不能确认这个本地草稿：{message}。原文档保持不变。").into());
                    self.notice = None;
                    cx.notify();
                    return;
                }
            };

        let draft = assignment.draft();
        let normalized_value = draft.normalized_value().to_owned();
        let container_path = draft.container_path();
        let canonical_key = draft.canonical_key();
        self.model.visual_document = staged;
        self.model.selected_database_schema = Some(schema);
        self.model.mode = ConfigGeneratorMode::Visual;
        self.model.visual_dirty = true;
        self.model.visual_generation = self.model.visual_generation.wrapping_add(1).max(1);
        self.model.refresh_visual_rows();
        self.model.selected_schema_parameter = Some(parameter_index);
        self.reset_visual_editor(window, cx);
        self.visual_search_input
            .update(cx, |input, cx| input.set_value(canonical_key, window, cx));
        self.advance_database_assignment_generation();
        self.pending_database_assignment = PendingDatabaseAssignment {
            lease: self.database_assignment_lease(),
            state: PendingDatabaseAssignmentState::Consumed,
        };
        self.notice = Some(
            format!(
                "已确认写入本地草稿：{}{} = {}。仅为 SyntaxValid 的规范化公开值；未连接数据库、未修改远端、未执行 reload/restart，也未验证目标版本或当前值。",
                container_path.map_or_else(String::new, |container| format!("[{container}] · ")),
                canonical_key,
                normalized_value,
            )
            .into(),
        );
        self.error = None;
        cx.notify();
    }

    fn reset_visual_editor(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.database_goal_value_input
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.visual_name_input
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.visual_arguments_input
            .update(cx, |input, cx| input.set_value("", window, cx));
    }

    fn visual_search_query(&self, cx: &Context<Self>) -> String {
        bounded_visual_search_query(self.visual_search_input.read(cx).value().as_ref())
    }

    fn handle_visual_search_change(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let query = self.visual_search_query(cx);
        if self.model.reconcile_visual_search_selection(&query) {
            self.reset_visual_editor(window, cx);
        }
        cx.notify();
    }

    fn select_visual_node(
        &mut self,
        id: VisualNodeId,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let query = self.visual_search_query(cx);
        let Some(row) = self.model.select_visible_visual_node(id, &query) else {
            return;
        };
        let (name, arguments) = visual_editor_values(&row);
        self.visual_name_input
            .update(cx, |input, cx| input.set_value(name, window, cx));
        self.visual_arguments_input
            .update(cx, |input, cx| input.set_value(arguments, window, cx));
        if row.allows_local_draft_mutation()
            && self
                .model
                .visual_document
                .kind()
                .allows_lossless_local_draft()
        {
            match row.kind() {
                VisualNodeKind::Statement | VisualNodeKind::Container => self
                    .visual_name_input
                    .update(cx, |input, cx| input.focus(window, cx)),
                VisualNodeKind::Comment => self
                    .visual_arguments_input
                    .update(cx, |input, cx| input.focus(window, cx)),
                VisualNodeKind::Opaque => {}
            }
        }
        self.error = None;
        cx.notify();
    }

    fn select_schema_catalog_parameter(
        &mut self,
        schema: &'static DatabaseConfigSchema,
        index: usize,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let query = self.visual_search_query(cx);
        if self
            .model
            .select_visible_schema_parameter(schema, index, &query)
            .is_none()
        {
            return;
        }
        self.reset_visual_editor(window, cx);
        self.error = None;
        cx.notify();
    }

    fn replace_visual_document(
        &mut self,
        document: VisualDocument,
        notice: impl Into<SharedString>,
        window: Option<&mut Window>,
        cx: &mut Context<Self>,
    ) {
        self.model.replace_visual_document(document);
        self.model.mode = ConfigGeneratorMode::Visual;
        if let Some(window) = window {
            self.reset_visual_editor(window, cx);
        } else {
            self.visual_editor_reset_pending = true;
        }
        self.notice = Some(notice.into());
        self.error = None;
        cx.notify();
    }

    fn new_competition_skeleton(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if !self.allow_visual_replacement(cx) {
            return;
        }
        let kind = self.model.visual_document.kind();
        match VisualDocument::competition_skeleton(kind) {
            Ok(document) => self.replace_visual_document(
                document,
                format!(
                    "已新建 {} · {} 本地无损草稿；{LOCAL_DRAFT_SCOPE_NOTICE}",
                    kind.label(),
                    kind.artifact_label()
                ),
                Some(window),
                cx,
            ),
            Err(error) => {
                self.error = Some(format!("新建 {} 比赛骨架失败：{error}", kind.label()).into());
                self.notice = None;
                cx.notify();
            }
        }
    }

    fn select_visual_document_kind(
        &mut self,
        kind: VisualDocumentKind,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.model.visual_document.kind() == kind || !self.allow_visual_replacement(cx) {
            return;
        }
        match VisualDocument::selection_document(kind) {
            Ok(document) => self.replace_visual_document(
                document,
                if kind.allows_lossless_local_draft() {
                    format!(
                        "已切换到 {} · {} 本地无损草稿并载入安全起始配置；{LOCAL_DRAFT_SCOPE_NOTICE}",
                        kind.label(),
                        kind.artifact_label()
                    )
                } else {
                    format!(
                        "已切换到 {} · {} 只读展示；请选择要导入的本地文件；不能应用/部署",
                        kind.label(),
                        kind.artifact_label()
                    )
                },
                Some(window),
                cx,
            ),
            Err(error) => {
                self.error = Some(format!("切换到 {} 失败：{error}", kind.label()).into());
                self.notice = None;
                cx.notify();
            }
        }
    }

    fn select_database_product(
        &mut self,
        product: DatabaseConfigProduct,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(artifact) = first_database_visual_artifact(product) else {
            self.error = Some("该产品当前没有可供本地结构化读取的文件工件".into());
            self.notice = None;
            cx.notify();
            return;
        };
        self.select_visual_document_kind(VisualDocumentKind::Database(artifact), window, cx);
    }

    fn select_database_artifact(
        &mut self,
        artifact: &'static DatabaseConfigArtifactDefinition,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if database_visual_parser(artifact).is_none() {
            self.error = Some("该工件没有可用的本地结构解析器，不能导入展示".into());
            self.notice = None;
            cx.notify();
            return;
        }
        self.select_visual_document_kind(VisualDocumentKind::Database(artifact), window, cx);
    }

    fn select_database_schema(
        &mut self,
        schema: &'static DatabaseConfigSchema,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if !self
            .model
            .select_database_schema_from_registry(schema, DATABASE_CONFIG_SCHEMAS)
        {
            self.error =
                Some("该 schema 不属于当前工件或不在已审静态 registry 中，已拒绝选择".into());
            self.notice = None;
            cx.notify();
            return;
        }
        self.reset_visual_editor(window, cx);
        self.notice = Some(
            format!(
                "已选择 {} · {}；仅显示本地参数元数据并执行脱敏，不改变本地无损草稿权限；未验证目标版本、edition、能力或当前值语法，不能应用/部署",
                schema.display_label, schema.version_label
            )
            .into(),
        );
        self.error = None;
        cx.notify();
    }

    fn open_database_parameter_goal(
        &mut self,
        schema: &'static DatabaseConfigSchema,
        parameter_index: usize,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(parameter) = schema.parameters.get(parameter_index) else {
            return;
        };
        let Some(artifact) = artifacts_for(schema.binding.product)
            .find(|artifact| artifact.key == schema.binding.artifact_key)
        else {
            self.error = Some("目标配方绑定的数据库工件不存在，已拒绝打开".into());
            self.notice = None;
            cx.notify();
            return;
        };

        self.select_database_artifact(artifact, window, cx);
        if self.model.visual_document.kind() != VisualDocumentKind::Database(artifact) {
            return;
        }
        self.select_database_schema(schema, window, cx);
        if !self
            .model
            .current_database_schema()
            .is_some_and(|current| std::ptr::eq(current, schema))
        {
            return;
        }

        self.visual_search_input.update(cx, |input, cx| {
            input.set_value(parameter.canonical_key, window, cx)
        });
        if self
            .model
            .select_visible_schema_parameter(schema, parameter_index, parameter.canonical_key)
            .is_none()
        {
            self.error = Some("目标参数未通过当前 Schema 的精确定位，已拒绝选择".into());
            self.notice = None;
            cx.notify();
            return;
        }
        self.notice = Some(
            format!(
                "已打开目标：{} · {} · {}。当前仅提供 CatalogGuidance 与本地草稿入口；未核验目标版本、edition、能力或当前值，不能应用/部署。",
                ConfigurationGoalMatch::DatabaseParameter {
                    schema,
                    parameter_index,
                }
                .subject()
                .label(),
                schema.version_label,
                parameter.canonical_key,
            )
            .into(),
        );
        self.error = None;
        cx.notify();
    }

    fn choose_database_parameter_goal_value(
        &mut self,
        value: &'static str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.database_goal_value_input
            .update(cx, |input, cx| input.set_value(value, window, cx));
        self.database_goal_value_input
            .update(cx, |input, cx| input.focus(window, cx));
    }

    fn apply_selected_database_parameter_goal(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(schema) = self.model.current_database_schema() else {
            return;
        };
        let Some(parameter_index) = self.model.selected_schema_parameter else {
            return;
        };
        let raw_value = self.database_goal_value_input.read(cx).value().to_string();
        let draft =
            match validate_database_parameter_goal_value(schema, parameter_index, &raw_value) {
                Ok(draft) => draft,
                Err(error) => {
                    self.error = Some(
                        format!(
                            "不能生成这个配置目标：{}。",
                            database_parameter_goal_error_message(error)
                        )
                        .into(),
                    );
                    self.notice = None;
                    cx.notify();
                    return;
                }
            };
        let staged = match stage_database_parameter_goal_document(
            &self.model.visual_document,
            schema,
            parameter_index,
            &draft,
        ) {
            Ok(staged) => staged,
            Err(message) => {
                self.error =
                    Some(format!("不能生成这个配置目标：{message}。原参数未被覆盖。 ").into());
                self.notice = None;
                cx.notify();
                return;
            }
        };
        self.model.visual_document = staged;
        self.model.refresh_visual_rows();
        self.model.selected_schema_parameter = Some(parameter_index);
        self.model.visual_dirty = true;
        self.model.visual_generation = self.model.visual_generation.wrapping_add(1).max(1);
        self.database_goal_value_input.update(cx, |input, cx| {
            input.set_value(draft.normalized_value().to_owned(), window, cx)
        });
        self.notice = Some(
            format!(
                "已将目标写入本地草稿：{}{} = {}。这是 SyntaxValid 的规范化公开值；尚未核验目标版本、edition、能力、当前值或激活结果，不能应用/部署。",
                draft
                    .container_path()
                    .map_or_else(String::new, |container| format!("[{container}] · ")),
                draft.canonical_key(),
                draft.normalized_value(),
            )
            .into(),
        );
        self.error = None;
        cx.notify();
    }

    fn load_quick_into_visual(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if !self.allow_visual_replacement(cx) {
            return;
        }
        let Some(generated) = self.model.generated.as_ref() else {
            return;
        };
        match VisualDocument::from_generated(generated) {
            Ok(document) => self.replace_visual_document(
                document,
                "快捷生成结果已载入本地无损草稿；后续修改不会回写快捷表单；未经过目标校验，不能应用/部署",
                Some(window),
                cx,
            ),
            Err(error) => {
                self.error = Some(format!("快捷配置载入树形编辑器失败：{error}").into());
                self.notice = None;
                cx.notify();
            }
        }
    }

    fn finish_visual_edit(
        &mut self,
        result: CoreResult<()>,
        success: &'static str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let label = self.model.visual_document.kind().label();
        match result {
            Ok(()) => {
                self.model.selected_visual_node = None;
                self.model.refresh_visual_rows();
                self.model.visual_dirty = true;
                self.model.visual_generation = self.model.visual_generation.wrapping_add(1).max(1);
                self.reset_visual_editor(window, cx);
                self.notice = Some(success.into());
                self.error = None;
            }
            Err(error) => {
                self.error = Some(format!("{label} 可视化编辑失败：{error}").into());
                self.notice = None;
            }
        }
        cx.notify();
    }

    fn add_visual_node(
        &mut self,
        kind: VisualNodeKind,
        as_child: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.importing || self.saving || !self.model.visual_document.is_structured() {
            return;
        }
        let parent = if as_child {
            let Some(row) = self.model.selected_visual_row() else {
                return;
            };
            if row.kind() != VisualNodeKind::Container {
                self.error = Some("只有容器节点可以接收子节点".into());
                self.notice = None;
                cx.notify();
                return;
            }
            Some(row.id())
        } else {
            None
        };
        let name = self.visual_name_input.read(cx).value().to_string();
        let arguments = self.visual_arguments_input.read(cx).value().to_string();
        let result = match kind {
            VisualNodeKind::Statement => self
                .model
                .visual_document
                .add_statement(parent, &name, &arguments),
            VisualNodeKind::Container => self
                .model
                .visual_document
                .add_container(parent, &name, &arguments),
            VisualNodeKind::Comment => self.model.visual_document.add_comment(parent, &arguments),
            VisualNodeKind::Opaque => return,
        };
        self.finish_visual_edit(
            result,
            "已更新本地无损草稿；未经过目标校验，不能应用/部署",
            window,
            cx,
        );
    }

    fn update_selected_visual_node(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.importing || self.saving || !self.model.can_mutate_selected_local_draft_row() {
            return;
        }
        let Some(row) = self.model.selected_visual_row().cloned() else {
            return;
        };
        let name = self.visual_name_input.read(cx).value().to_string();
        let arguments = self.visual_arguments_input.read(cx).value().to_string();
        let result = match row.kind() {
            VisualNodeKind::Statement | VisualNodeKind::Container => self
                .model
                .visual_document
                .update_statement(row.id(), &name, &arguments),
            VisualNodeKind::Comment => self
                .model
                .visual_document
                .update_comment(row.id(), &arguments),
            VisualNodeKind::Opaque => return,
        };
        self.finish_visual_edit(
            result,
            "本地无损草稿中的所选节点已更新；未经过目标校验，不能应用/部署",
            window,
            cx,
        );
    }

    fn remove_selected_visual_node(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.importing || self.saving || !self.model.can_mutate_selected_local_draft_row() {
            return;
        }
        let Some(id) = self.model.selected_visual_node else {
            return;
        };
        let result = self.model.visual_document.remove(id);
        self.finish_visual_edit(
            result,
            "所选节点或完整块子树已从本地无损草稿删除；未经过目标校验，不能应用/部署",
            window,
            cx,
        );
    }

    fn move_selected_visual_node(
        &mut self,
        down: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.importing || self.saving || !self.model.can_mutate_selected_local_draft_row() {
            return;
        }
        let Some(id) = self.model.selected_visual_node else {
            return;
        };
        let result = if down {
            self.model.visual_document.move_down(id)
        } else {
            self.model.visual_document.move_up(id)
        };
        self.finish_visual_edit(
            result,
            "所选节点已在本地无损草稿内移动；未经过目标校验，不能应用/部署",
            window,
            cx,
        );
    }

    fn save_payload(&self) -> Option<ConfigSavePayload> {
        match self.model.mode {
            ConfigGeneratorMode::Quick => {
                self.model.generated.clone().map(ConfigSavePayload::Quick)
            }
            ConfigGeneratorMode::Visual => Some(ConfigSavePayload::Visual(
                self.model.visual_document.output(),
            )),
        }
    }

    fn copy_current(&mut self, cx: &mut Context<Self>) {
        let copy_label = match self.model.mode {
            ConfigGeneratorMode::Quick => "Nginx",
            ConfigGeneratorMode::Visual => self.model.visual_document.kind().label(),
        };
        let text = match self.model.mode {
            ConfigGeneratorMode::Quick => self
                .model
                .generated
                .as_ref()
                .map(|generated| generated.contents().to_owned()),
            ConfigGeneratorMode::Visual => {
                if !self.model.can_copy_visual() {
                    self.error = Some(
                        "检测到可能的凭据或令牌，已禁止复制到剪贴板；请另存本地草稿或只读副本以保留完整字节；该文件不能应用/部署"
                            .into(),
                    );
                    self.notice = None;
                    cx.notify();
                    return;
                }
                let output = self.model.visual_document.output();
                match output.text() {
                    Ok(text) => Some(text.to_owned()),
                    Err(error) => {
                        self.error = Some(format!("{copy_label} 配置无法复制：{error}").into());
                        self.notice = None;
                        cx.notify();
                        return;
                    }
                }
            }
        };
        let Some(text) = text else {
            return;
        };
        cx.write_to_clipboard(ClipboardItem::new_string(text));
        self.notice = Some(format!("{copy_label} 配置已复制到剪贴板").into());
        self.error = None;
        cx.notify();
    }

    fn choose_import_path(&mut self, cx: &mut Context<Self>) {
        if self.importing || self.saving || !self.model.active {
            return;
        }
        if !self.allow_visual_replacement(cx) {
            return;
        }
        self.importing = true;
        self.error = None;
        let kind = self.model.visual_document.kind();
        let label = kind.label();
        let artifact_label = kind.artifact_label();
        self.notice = Some(format!("等待选择本地 {label} · {artifact_label} 文件…").into());
        let activation_generation = self.model.activation_generation;
        let receiver = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some(format!("选择本地 {label} · {artifact_label} 配置").into()),
        });
        cx.spawn(async move |page, cx| {
            let selected = match receiver.await {
                Ok(Ok(Some(mut paths))) if paths.len() == 1 => paths.remove(0),
                Ok(Ok(None)) => {
                    let _ = cx.update(|cx| {
                        if let Some(page) = page.upgrade() {
                            page.update(cx, |page, cx| {
                                if page.model.accepts(activation_generation) {
                                    page.importing = false;
                                    page.notice =
                                        Some(format!("已取消导入本地 {label} 配置").into());
                                    cx.notify();
                                }
                            });
                        }
                    });
                    return;
                }
                Ok(Ok(Some(_))) => {
                    let _ = cx.update(|cx| {
                        if let Some(page) = page.upgrade() {
                            page.update(cx, |page, cx| {
                                if page.model.accepts(activation_generation) {
                                    page.importing = false;
                                    page.error = Some("一次只能导入一个配置文件".into());
                                    page.notice = None;
                                    cx.notify();
                                }
                            });
                        }
                    });
                    return;
                }
                Ok(Err(error)) => {
                    let message = error.to_string();
                    let _ = cx.update(|cx| {
                        if let Some(page) = page.upgrade() {
                            page.update(cx, |page, cx| {
                                if page.model.accepts(activation_generation) {
                                    page.importing = false;
                                    page.error =
                                        Some(format!("本地配置选择失败：{message}").into());
                                    page.notice = None;
                                    cx.notify();
                                }
                            });
                        }
                    });
                    return;
                }
                Err(error) => {
                    let message = error.to_string();
                    let _ = cx.update(|cx| {
                        if let Some(page) = page.upgrade() {
                            page.update(cx, |page, cx| {
                                if page.model.accepts(activation_generation) {
                                    page.importing = false;
                                    page.error =
                                        Some(format!("本地配置选择任务失败：{message}").into());
                                    page.notice = None;
                                    cx.notify();
                                }
                            });
                        }
                    });
                    return;
                }
            };
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        page.start_import(activation_generation, selected, cx)
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn start_import(
        &mut self,
        activation_generation: u64,
        source: PathBuf,
        cx: &mut Context<Self>,
    ) {
        if !self.importing || !self.model.accepts(activation_generation) {
            return;
        }
        self.notice = Some(format!("正在导入：{}", source.display()).into());
        let kind = self.model.visual_document.kind();
        let task = self.tokio.spawn(async move {
            VisualDocument::read_local(kind, &source).map(|document| (source, document))
        });
        self.import_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        page.finish_import(activation_generation, result, cx)
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_import(
        &mut self,
        activation_generation: u64,
        result: Result<CoreResult<(PathBuf, VisualDocument)>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if !self.model.accepts(activation_generation) {
            return;
        }
        self.importing = false;
        self.import_abort = None;
        match result {
            Ok(Ok((path, document))) => {
                let label = document.kind().label();
                let import_scope = if document.kind().allows_lossless_local_draft() {
                    "本地无损草稿"
                } else {
                    "本地只读副本"
                };
                self.replace_visual_document(
                    document,
                    format!(
                        "已导入 {label} 配置为{import_scope}：{}；{LOCAL_DRAFT_SCOPE_NOTICE}",
                        path.display()
                    ),
                    None,
                    cx,
                )
            }
            Ok(Err(error)) => {
                self.error = Some(
                    format!(
                        "本地 {} 配置导入失败：{error}",
                        self.model.visual_document.kind().label()
                    )
                    .into(),
                );
                self.notice = None;
                cx.notify();
            }
            Err(error) if error.is_cancelled() => {}
            Err(error) => {
                self.error = Some(
                    format!(
                        "本地 {} 配置导入任务失败：{error}",
                        self.model.visual_document.kind().label()
                    )
                    .into(),
                );
                self.notice = None;
                cx.notify();
            }
        }
    }

    fn choose_save_path(&mut self, cx: &mut Context<Self>) {
        if self.saving || self.importing || self.save_payload().is_none() || !self.model.active {
            return;
        }
        let initial = self
            .services
            .store()
            .root()
            .parent()
            .map_or_else(|| self.services.store().root().to_path_buf(), PathBuf::from);
        let suggested = self
            .save_payload()
            .expect("savable configuration was checked")
            .suggested_file_name();
        let activation_generation = self.model.activation_generation;
        let receiver = cx.prompt_for_new_path(&initial, Some(suggested));
        cx.spawn(async move |page, cx| {
            let selected = match receiver.await {
                Ok(Ok(Some(path))) => path,
                Ok(Ok(None)) => return,
                Ok(Err(error)) => {
                    let message = error.to_string();
                    let _ = cx.update(|cx| {
                        if let Some(page) = page.upgrade() {
                            page.update(cx, |page, cx| {
                                if page.model.accepts(activation_generation) {
                                    page.error =
                                        Some(format!("保存路径选择失败：{message}").into());
                                    page.notice = None;
                                    cx.notify();
                                }
                            });
                        }
                    });
                    return;
                }
                Err(error) => {
                    let message = error.to_string();
                    let _ = cx.update(|cx| {
                        if let Some(page) = page.upgrade() {
                            page.update(cx, |page, cx| {
                                if page.model.accepts(activation_generation) {
                                    page.error =
                                        Some(format!("保存路径选择已取消：{message}").into());
                                    page.notice = None;
                                    cx.notify();
                                }
                            });
                        }
                    });
                    return;
                }
            };
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        page.start_save(activation_generation, selected, cx);
                    });
                }
            });
        })
        .detach();
    }

    fn start_save(
        &mut self,
        activation_generation: u64,
        destination: PathBuf,
        cx: &mut Context<Self>,
    ) {
        if self.saving || self.importing || !self.model.accepts(activation_generation) {
            return;
        }
        let Some(payload) = self.save_payload() else {
            return;
        };
        self.saving = true;
        self.error = None;
        self.notice = Some(format!("正在另存本地文件：{}", destination.display()).into());
        let task = self
            .tokio
            .spawn(async move { payload.write_new(&destination) });
        self.save_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        page.finish_save(activation_generation, result, cx);
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_save(
        &mut self,
        activation_generation: u64,
        result: Result<CoreResult<PathBuf>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if !self.model.accepts(activation_generation) {
            return;
        }
        self.saving = false;
        self.save_abort = None;
        let label = match self.model.mode {
            ConfigGeneratorMode::Quick => "Nginx",
            ConfigGeneratorMode::Visual => self.model.visual_document.kind().label(),
        };
        let save_scope = match self.model.mode {
            ConfigGeneratorMode::Quick => "本地草稿",
            ConfigGeneratorMode::Visual
                if self
                    .model
                    .visual_document
                    .kind()
                    .allows_lossless_local_draft() =>
            {
                "本地草稿"
            }
            ConfigGeneratorMode::Visual => "本地只读副本",
        };
        match result {
            Ok(Ok(path)) => {
                if self.model.mode == ConfigGeneratorMode::Visual {
                    self.model.visual_dirty = false;
                }
                self.notice = Some(
                    format!(
                        "{label} 已另存为{save_scope}：{}；{LOCAL_DRAFT_SCOPE_NOTICE}",
                        path.display()
                    )
                    .into(),
                );
                self.error = None;
            }
            Ok(Err(error)) => {
                self.error = Some(format!("{label} 配置保存失败：{error}").into());
                self.notice = None;
            }
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                self.error = Some(format!("{label} 配置保存任务失败：{error}").into());
                self.notice = None;
            }
        }
        cx.notify();
    }

    fn allow_visual_replacement(&mut self, cx: &mut Context<Self>) -> bool {
        if !self.model.visual_dirty {
            return true;
        }
        self.error = Some(
            "本地无损草稿有未另存的修改；请先另存本地草稿，再新建、导入或切换产品/工件".into(),
        );
        self.notice = None;
        cx.notify();
        false
    }

    fn render_database_bundle_goal_card(
        &self,
        goal: &'static DatabaseGoalDefinition,
        product: DatabaseConfigProduct,
        version: Option<DatabaseGoalVersionRequest>,
        goal_index: usize,
        tokens: ThemeTokens,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let resolutions = database_goal_resolutions_for_version(goal, product, version);
        div()
            .rounded_md()
            .border_1()
            .border_color(tokens.border)
            .bg(tokens.surface_alt)
            .p_3()
            .flex()
            .flex_col()
            .gap_2()
            .child(
                div().text_sm().font_semibold().child(format!(
                    "完整目标 · {} · {}",
                    database_product(product).label,
                    goal.title
                )),
            )
            .child(
                div()
                    .text_xs()
                    .text_color(tokens.muted)
                    .child(goal.summary),
            )
            .children(
                resolutions
                    .into_iter()
                    .take(4)
                    .enumerate()
                    .map(|(resolution_index, resolution)| {
                        let schema = resolution.schema();
                        let reviewed = resolution.reviewed_parameter_count();
                        let missing = resolution.missing_required_count();
                        div()
                            .rounded_md()
                            .border_1()
                            .border_color(tokens.border)
                            .bg(tokens.surface)
                            .p_2()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(
                                div().text_xs().font_semibold().child(format!(
                                    "{} · {} · 已审参数 {} · 尚缺必需步骤 {}",
                                    schema.display_label,
                                    schema.version_label,
                                    reviewed,
                                    missing,
                                )),
                            )
                            .children(resolution.steps().iter().enumerate().map(
                                |(step_index, step)| {
                                    let definition = step.definition();
                                    let missing_required = step.is_missing_required();
                                    div()
                                        .mt_1()
                                        .flex()
                                        .flex_col()
                                        .gap_1()
                                        .child(
                                            div()
                                                .text_xs()
                                                .font_semibold()
                                                .text_color(if missing_required {
                                                    tokens.warning
                                                } else {
                                                    tokens.text
                                                })
                                                .child(format!(
                                                    "{}{}",
                                                    if definition.required {
                                                        "必需 · "
                                                    } else {
                                                        "可选 · "
                                                    },
                                                    definition.title,
                                                )),
                                        )
                                        .child(
                                            div()
                                                .text_xs()
                                                .text_color(tokens.muted)
                                                .child(definition.explanation),
                                        )
                                        .when(step.parameter_indices().is_empty(), |row| {
                                            row.child(
                                                div()
                                                    .text_xs()
                                                    .text_color(tokens.warning)
                                                    .child("当前版本化 Schema 没有可定位参数；该步骤不能自动完成。"),
                                            )
                                        })
                                        .when(!step.parameter_indices().is_empty(), |row| {
                                            row.child(
                                                div()
                                                    .flex()
                                                    .flex_wrap()
                                                    .gap_1()
                                                    .children(
                                                        step.parameter_indices()
                                                            .iter()
                                                            .copied()
                                                            .enumerate()
                                                            .map(
                                                                |(
                                                                    parameter_order,
                                                                    parameter_index,
                                                                )| {
                                                                    let parameter = &schema
                                                                        .parameters
                                                                        [parameter_index];
                                                                    let actionable =
                                                                        database_parameter_goal_availability(
                                                                            schema,
                                                                            parameter_index,
                                                                        ) == ConfigurationGoalAvailability::LocalDraftRecipe;
                                                                    let parameter_label =
                                                                        database_goal_parameter_label(
                                                                            parameter,
                                                                        );
                                                                    crate::buttons::button(
                                                                        SharedString::from(format!(
                                                                            "config-generator-database-bundle-{goal_index}-{resolution_index}-{step_index}-{parameter_order}"
                                                                        )),
                                                                    )
                                                                    .label(if actionable {
                                                                        format!(
                                                                            "配置 {}",
                                                                            parameter_label
                                                                        )
                                                                    } else {
                                                                        format!(
                                                                            "查看 {}",
                                                                            parameter_label
                                                                        )
                                                                    })
                                                                    .small()
                                                                    .on_click(cx.listener(
                                                                        move |page, _, window, cx| {
                                                                            page.open_database_parameter_goal(
                                                                                schema,
                                                                                parameter_index,
                                                                                window,
                                                                                cx,
                                                                            )
                                                                        },
                                                                    ))
                                                                },
                                                            ),
                                                    ),
                                            )
                                        })
                                },
                            ))
                    }),
            )
            .into_any_element()
    }

    fn database_assignment_recognized(&self) -> bool {
        !matches!(
            self.pending_database_assignment.state,
            PendingDatabaseAssignmentState::NotAssignment
        )
    }

    fn render_database_assignment_card(
        &self,
        tokens: ThemeTokens,
        cx: &mut Context<Self>,
    ) -> Option<AnyElement> {
        let lease = self.pending_database_assignment.lease;
        let lease_current = self.database_assignment_lease_is_current(lease);
        let busy = self.importing || self.saving;
        match &self.pending_database_assignment.state {
            PendingDatabaseAssignmentState::NotAssignment => None,
            PendingDatabaseAssignmentState::Consumed => Some(
                div()
                    .id("config-generator-database-assignment-consumed")
                    .debug_selector(|| {
                        "config-generator-database-assignment-consumed".to_owned()
                    })
                    .rounded_md()
                    .border_1()
                    .border_color(tokens.accent)
                    .bg(tokens.surface_alt)
                    .p_3()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(
                        div()
                            .text_sm()
                            .font_semibold()
                            .child("参数赋值目标 · 已写入本地草稿"),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(tokens.muted)
                            .child("修改目标描述后可以生成下一项；当前不会回退到普通模糊搜索结果。"),
                    )
                    .into_any_element(),
            ),
            PendingDatabaseAssignmentState::Rejected(error) => Some(
                div()
                    .id("config-generator-database-assignment-blocked")
                    .debug_selector(|| {
                        "config-generator-database-assignment-blocked".to_owned()
                    })
                    .rounded_md()
                    .border_1()
                    .border_color(tokens.warning)
                    .bg(tokens.surface_alt)
                    .p_3()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(
                        div()
                            .text_sm()
                            .font_semibold()
                            .child("参数赋值目标 · Blocked"),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(tokens.warning)
                            .child(database_parameter_assignment_error_message(*error)),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(tokens.muted)
                            .child(
                                "格式：产品 [版本] [@精确工件key] [[精确容器]] canonical_key 设置为 值。被拒绝的值不会复制到提示、日志或普通目标结果中。",
                            ),
                    )
                    .into_any_element(),
            ),
            PendingDatabaseAssignmentState::Ambiguous(ambiguity) => Some(
                div()
                    .id("config-generator-database-assignment-ambiguous")
                    .debug_selector(|| {
                        "config-generator-database-assignment-ambiguous".to_owned()
                    })
                    .rounded_md()
                    .border_1()
                    .border_color(tokens.warning)
                    .bg(tokens.surface_alt)
                    .p_3()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(
                        div()
                            .text_sm()
                            .font_semibold()
                            .child("参数赋值目标 · 请选择精确位置"),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(tokens.muted)
                            .child(
                                "多个精确版本、工件或容器包含同名参数。原值仍由 core 持有；选择不会改变它，也不会写入草稿。",
                            ),
                    )
                    .children(ambiguity.candidates().iter().copied().enumerate().map(
                        |(candidate_index, target)| {
                            let schema = target.schema();
                            let parameter = target.parameter();
                            let container = parameter.container_path.map_or_else(
                                || "根级配置（无需 [] 限定）".to_owned(),
                                |container| format!("[{container}]"),
                            );
                            crate::buttons::button(SharedString::from(format!(
                                "config-generator-database-assignment-candidate-{candidate_index}"
                            )))
                            .label(format!(
                                "{} · {} · @{} · {} · {}",
                                database_product(schema.binding.product).label,
                                schema.version_label,
                                schema.binding.artifact_key,
                                container,
                                parameter.canonical_key,
                            ))
                            .small()
                            .disabled(busy || !lease_current)
                            .on_click(cx.listener(move |page, _, window, cx| {
                                page.select_database_assignment_candidate(
                                    lease, target, window, cx,
                                )
                            }))
                        },
                    ))
                    .when(!lease_current, |card| {
                        card.child(
                            div()
                                .text_xs()
                                .text_color(tokens.warning)
                                .child("页面或文档状态已变化；请重新编辑目标描述以刷新候选。"),
                        )
                    })
                    .into_any_element(),
            ),
            PendingDatabaseAssignmentState::Ready {
                assignment,
                value_error,
            } => {
                let schema = assignment.schema();
                let parameter = assignment.target().parameter();
                let draft = assignment.draft();
                let container = parameter.container_path.map_or_else(
                    || "根级配置（无需 [] 限定）".to_owned(),
                    |container| format!("[{container}]"),
                );
                let preflight_error = if value_error.is_none() && lease_current {
                    preflight_database_parameter_assignment_document(&self.model, assignment).err()
                } else {
                    None
                };
                let actionable = value_error.is_none()
                    && lease_current
                    && preflight_error.is_none();
                let blocked = value_error.is_some() || preflight_error.is_some() || !lease_current;
                let normalized_preview = value_error.is_none().then(|| {
                    format!(
                        "{}{} = {}",
                        draft
                            .container_path()
                            .map_or_else(String::new, |container| format!("[{container}] · ")),
                        draft.canonical_key(),
                        draft.normalized_value(),
                    )
                });
                Some(
                    div()
                        .id("config-generator-database-assignment-ready")
                        .debug_selector(|| {
                            "config-generator-database-assignment-ready".to_owned()
                        })
                        .rounded_md()
                        .border_1()
                        .border_color(if actionable {
                            tokens.accent
                        } else {
                            tokens.warning
                        })
                        .bg(tokens.surface_alt)
                        .p_3()
                        .flex()
                        .flex_col()
                        .gap_2()
                        .child(
                            div()
                                .text_sm()
                                .font_semibold()
                                .child(if blocked {
                                    "参数赋值目标 · Blocked"
                                } else {
                                    "参数赋值目标 · Ready"
                                }),
                        )
                        .child(
                            div().text_xs().font_semibold().child(format!(
                                "{} · {} · {}",
                                database_product(schema.binding.product).label,
                                schema.display_label,
                                schema.version_label,
                            )),
                        )
                        .child(
                            div().text_xs().text_color(tokens.muted).child(format!(
                                "@{} · {} · {}",
                                schema.binding.artifact_key,
                                container,
                                parameter.canonical_key,
                            )),
                        )
                        .child(
                            div()
                                .text_xs()
                                .text_color(tokens.muted)
                                .child(bounded_visual_row_text(
                                    parameter.competition_rationale,
                                    180,
                                )),
                        )
                        .child(
                            div().text_xs().text_color(tokens.muted).child(format!(
                                "值域：{} · 风险：{} · 激活：{}",
                                schema_value_kind_description(parameter.value_kind),
                                schema_risk_label(parameter.risk),
                                schema_activation_label(parameter.activation),
                            )),
                        )
                        .child(
                            div()
                                .child(section_label("独立配置值", tokens))
                                .child(
                                    div()
                                        .mt_1()
                                        .child(
                                            Input::new(&self.database_assignment_value_input)
                                                .small()
                                                .disabled(busy || !lease_current),
                                        ),
                                ),
                        )
                        .when_some(*value_error, |card, error| {
                            card.child(
                                div()
                                    .rounded_md()
                                    .bg(tokens.surface)
                                    .p_2()
                                    .text_xs()
                                    .text_color(tokens.warning)
                                    .child(format!(
                                        "Blocked：{}",
                                        database_parameter_assignment_error_message(error)
                                    )),
                            )
                        })
                        .when_some(normalized_preview, |card, preview| {
                            card.child(
                                div()
                                    .rounded_md()
                                    .bg(tokens.surface)
                                    .p_2()
                                    .text_xs()
                                    .child(format!("待确认写入：{preview}")),
                            )
                        })
                        .when_some(preflight_error, |card, message| {
                            card.child(
                                div()
                                    .id("config-generator-database-assignment-preflight-blocked")
                                    .debug_selector(|| {
                                        "config-generator-database-assignment-preflight-blocked"
                                            .to_owned()
                                    })
                                    .rounded_md()
                                    .bg(tokens.surface)
                                    .p_2()
                                    .text_xs()
                                    .text_color(tokens.warning)
                                    .child(format!("Blocked：{message}。原文档保持不变。")),
                            )
                        })
                        .when(!lease_current, |card| {
                            card.child(
                                div()
                                    .text_xs()
                                    .text_color(tokens.warning)
                                    .child(
                                        "页面、搜索值或文档状态已变化；请重新编辑目标描述以刷新预览。",
                                    ),
                            )
                        })
                        .child(
                            crate::buttons::button(
                                "config-generator-confirm-database-assignment",
                            )
                            .label("确认写入本地草稿")
                            .small()
                            .primary()
                            .disabled(busy || !actionable)
                            .on_click(cx.listener(move |page, _, window, cx| {
                                page.confirm_database_parameter_assignment(lease, window, cx)
                            })),
                        )
                        .child(
                            div()
                                .text_xs()
                                .text_color(tokens.warning)
                                .child(
                                    "确认只修改本地草稿；不会连接数据库、写远端、reload/restart 或宣称目标已验证。",
                                ),
                        )
                        .into_any_element(),
                )
            }
        }
    }

    fn render_quick_workspace(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let kind = self.model.kind;
        let security_headers = self.model.security_headers;
        let forbidden_path_enabled = self.model.forbidden_path_enabled;
        let forbidden_path_scope = self.model.forbidden_path_scope;
        let database_assignment_recognized = self.database_assignment_recognized();
        let goal_query = if database_assignment_recognized {
            String::new()
        } else {
            bounded_visual_search_query(self.nginx_goal_search_input.read(cx).value().as_ref())
        };
        let goal_results = if database_assignment_recognized {
            None
        } else {
            search_configuration_goals(&goal_query).ok()
        };
        let simple_recipe_matches = goal_results
            .as_ref()
            .into_iter()
            .flat_map(|results| results.matches())
            .filter_map(|goal| match *goal {
                ConfigurationGoalMatch::Recipe(recipe)
                    if recipe.action != ConfigurationGoalRecipeAction::NginxForbiddenPath403 =>
                {
                    Some(recipe)
                }
                ConfigurationGoalMatch::Recipe(_)
                | ConfigurationGoalMatch::DatabaseArtifact { .. }
                | ConfigurationGoalMatch::DatabaseGoal { .. }
                | ConfigurationGoalMatch::DatabaseParameter { .. }
                | ConfigurationGoalMatch::UnavailableSubject { .. } => None,
            })
            .collect::<Vec<_>>();
        let forbidden_goal_matches = goal_results.as_ref().is_some_and(|results| {
            results.matches().iter().any(|goal| {
                matches!(
                    goal,
                    ConfigurationGoalMatch::Recipe(recipe)
                        if recipe.action
                            == ConfigurationGoalRecipeAction::NginxForbiddenPath403
                )
            })
        });
        let database_bundle_goal_matches = goal_results
            .as_ref()
            .into_iter()
            .flat_map(|results| results.matches())
            .filter_map(|matched| match *matched {
                ConfigurationGoalMatch::DatabaseGoal {
                    goal,
                    product,
                    version,
                } => Some((goal, product, version)),
                ConfigurationGoalMatch::Recipe(_)
                | ConfigurationGoalMatch::DatabaseArtifact { .. }
                | ConfigurationGoalMatch::DatabaseParameter { .. }
                | ConfigurationGoalMatch::UnavailableSubject { .. } => None,
            })
            .take(8)
            .collect::<Vec<_>>();
        let database_artifact_goal_matches = goal_results
            .as_ref()
            .into_iter()
            .flat_map(|results| results.matches())
            .filter_map(|matched| match *matched {
                ConfigurationGoalMatch::DatabaseArtifact { artifact } => Some(artifact),
                ConfigurationGoalMatch::Recipe(_)
                | ConfigurationGoalMatch::DatabaseGoal { .. }
                | ConfigurationGoalMatch::DatabaseParameter { .. }
                | ConfigurationGoalMatch::UnavailableSubject { .. } => None,
            })
            .take(24)
            .collect::<Vec<_>>();
        let database_goal_matches = goal_results
            .as_ref()
            .into_iter()
            .flat_map(|results| results.matches())
            .filter_map(|goal| match *goal {
                ConfigurationGoalMatch::DatabaseParameter {
                    schema,
                    parameter_index,
                } => Some((schema, parameter_index)),
                ConfigurationGoalMatch::Recipe(_)
                | ConfigurationGoalMatch::DatabaseArtifact { .. }
                | ConfigurationGoalMatch::DatabaseGoal { .. }
                | ConfigurationGoalMatch::UnavailableSubject { .. } => None,
            })
            .take(24)
            .collect::<Vec<_>>();
        let unavailable_goal_subjects = goal_results
            .as_ref()
            .into_iter()
            .flat_map(|results| results.matches())
            .filter_map(|goal| match *goal {
                ConfigurationGoalMatch::UnavailableSubject { coverage, gap } => {
                    Some((coverage, gap))
                }
                ConfigurationGoalMatch::Recipe(_)
                | ConfigurationGoalMatch::DatabaseArtifact { .. }
                | ConfigurationGoalMatch::DatabaseGoal { .. }
                | ConfigurationGoalMatch::DatabaseParameter { .. } => None,
            })
            .take(8)
            .collect::<Vec<_>>();
        let goal_results_truncated = goal_results
            .as_ref()
            .is_some_and(|results| results.truncated());
        let no_goal_matches = !database_assignment_recognized
            && simple_recipe_matches.is_empty()
            && !forbidden_goal_matches
            && database_artifact_goal_matches.is_empty()
            && database_bundle_goal_matches.is_empty()
            && database_goal_matches.is_empty()
            && unavailable_goal_subjects.is_empty();
        let generated = self.model.generated.clone();
        let saving = self.saving;
        div()
            .flex_1()
            .min_h_0()
            .flex()
            .gap_4()
            .child(
                div()
                    .w(px(390.0))
                    .flex_none()
                    .min_h_0()
                    .overflow_y_scrollbar()
                    .rounded_lg()
                    .border_1()
                    .border_color(tokens.border)
                    .bg(tokens.surface)
                    .p_4()
                    .flex()
                    .flex_col()
                    .gap_4()
                    .child(input_field(
                        "我想实现什么（全部产品）",
                        "例如：/admin 返回 403、PostgreSQL 提高最大连接数、MySQL 开启慢查询；只展示已审配方或参数依据。",
                        &self.nginx_goal_search_input,
                        tokens,
                    ))
                    .when_some(
                        self.render_database_assignment_card(tokens, cx),
                        |panel, card| panel.child(card),
                    )
                    .when(!simple_recipe_matches.is_empty(), |panel| {
                        panel.child(
                            div()
                                .id("config-generator-simple-goal-results")
                                .debug_selector(|| {
                                    "config-generator-simple-goal-results".to_owned()
                                })
                                .flex()
                                .flex_col()
                                .gap_2()
                                .children(simple_recipe_matches.into_iter().enumerate().map(
                                    |(recipe_index, recipe)| {
                                        let action = recipe.action;
                                        let query = goal_query.clone();
                                        div()
                                            .rounded_md()
                                            .border_1()
                                            .border_color(tokens.border)
                                            .bg(tokens.surface_alt)
                                            .p_3()
                                            .flex()
                                            .flex_col()
                                            .gap_2()
                                            .child(
                                                div()
                                                    .text_sm()
                                                    .font_semibold()
                                                    .child(format!(
                                                        "配置目标 · {}",
                                                        recipe.title
                                                    )),
                                            )
                                            .child(
                                                div()
                                                    .text_xs()
                                                    .text_color(tokens.muted)
                                                    .child(format!(
                                                        "{} 预计：{}",
                                                        recipe.summary, recipe.expected_effect
                                                    )),
                                            )
                                            .child(
                                                crate::buttons::button(SharedString::from(
                                                    format!(
                                                        "config-generator-simple-goal-{recipe_index}"
                                                    ),
                                                ))
                                                .label("使用这个目标")
                                                .small()
                                                .on_click(cx.listener(
                                                    move |page, _, window, cx| {
                                                        page.start_curated_configuration_goal(
                                                            action,
                                                            &query,
                                                            window,
                                                            cx,
                                                        )
                                                    },
                                                )),
                                            )
                                    },
                                )),
                        )
                    })
                    .when(forbidden_goal_matches, |panel| {
                        let goal_query = goal_query.clone();
                        panel.child(
                            div()
                                .id("config-generator-nginx-forbidden-goal")
                                .debug_selector(|| {
                                    "config-generator-nginx-forbidden-goal".to_owned()
                                })
                                .rounded_md()
                                .border_1()
                                .border_color(if forbidden_path_enabled {
                                    tokens.accent
                                } else {
                                    tokens.border
                                })
                                .bg(tokens.surface_alt)
                                .p_3()
                                .flex()
                                .flex_col()
                                .gap_2()
                                .child(
                                    div()
                                        .text_sm()
                                        .font_semibold()
                                        .child("配置目标 · 禁止指定路径（HTTP 403）"),
                                )
                                .child(
                                    div()
                                        .text_xs()
                                        .text_color(tokens.muted)
                                        .child(
                                            "预计行为：/admin、/admin/、/admin/users → 403；/administrator 不受影响。URI 路径按 Nginx 规则匹配，部署前仍需 nginx -t 与真实请求验证。",
                                        ),
                                )
                                .child(
                                    crate::buttons::button(
                                        "config-generator-toggle-forbidden-path-goal",
                                    )
                                    .label(if forbidden_path_enabled {
                                        "已启用 · 点击关闭"
                                    } else {
                                        "使用这个目标"
                                    })
                                    .small()
                                    .selected(forbidden_path_enabled)
                                    .on_click(cx.listener(move |page, _, window, cx| {
                                        if page.model.forbidden_path_enabled {
                                            page.toggle_forbidden_path_goal(cx);
                                        } else {
                                            page.start_forbidden_path_goal(
                                                &goal_query,
                                                window,
                                                cx,
                                            );
                                        }
                                    })),
                                )
                                .when(forbidden_path_enabled, |goal| {
                                    goal.child(input_field(
                                        "禁止访问路径",
                                        "规范绝对 URI，例如 /admin；不接受根路径、尾斜杠、查询参数、变量或 Nginx 元字符。",
                                        &self.forbidden_path_input,
                                        tokens,
                                    ))
                                    .child(
                                        div()
                                            .child(section_label("匹配范围", tokens))
                                            .child(
                                                div()
                                                    .mt_2()
                                                    .flex()
                                                    .gap_2()
                                                    .children(
                                                        NginxForbiddenPathScope::ALL
                                                            .into_iter()
                                                            .map(|scope| {
                                                                crate::buttons::button(
                                                                    SharedString::from(format!(
                                                                        "config-generator-forbidden-scope-{scope:?}"
                                                                    )),
                                                                )
                                                                .label(scope.label())
                                                                .small()
                                                                .selected(
                                                                    forbidden_path_scope == scope,
                                                                )
                                                                .on_click(cx.listener(
                                                                    move |page, _, _, cx| {
                                                                        page.select_forbidden_path_scope(
                                                                            scope, cx,
                                                                        )
                                                                    },
                                                                ))
                                                            }),
                                                    ),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .rounded_md()
                                            .bg(tokens.surface)
                                            .p_2()
                                            .text_xs()
                                            .text_color(tokens.warning)
                                            .child(
                                                "当前规则对所有来源生效，包括本机。若只拒绝公网、仍允许内网或本机，必须先确认可信 real_ip 链路与允许网段；本模板不会猜测。",
                                            ),
                                    )
                                }),
                        )
                    })
                    .when(!database_artifact_goal_matches.is_empty(), |panel| {
                        panel.child(
                            div()
                                .id("config-generator-database-artifact-results")
                                .debug_selector(|| {
                                    "config-generator-database-artifact-results".to_owned()
                                })
                                .flex()
                                .flex_col()
                                .gap_2()
                                .child(section_label("数据库配置工件", tokens))
                                .children(database_artifact_goal_matches.into_iter().enumerate().map(
                                    |(artifact_index, artifact)| {
                                        let matched =
                                            ConfigurationGoalMatch::DatabaseArtifact { artifact };
                                        let support_gap = matched.support_gap();
                                        let can_open = database_visual_parser(artifact).is_some();
                                        let workspace_label = if can_open {
                                            if artifact.allows_lossless_local_draft() {
                                                "可打开本地无损草稿工作区"
                                            } else {
                                                "可打开本地只读查看工作区"
                                            }
                                        } else {
                                            "当前仅提供目录说明"
                                        };
                                        let button_id = SharedString::from(format!(
                                            "config-generator-database-artifact-{artifact_index}"
                                        ));
                                        div()
                                            .rounded_md()
                                            .border_1()
                                            .border_color(tokens.border)
                                            .bg(tokens.surface_alt)
                                            .p_3()
                                            .flex()
                                            .flex_col()
                                            .gap_2()
                                            .child(
                                                div().text_sm().font_semibold().child(format!(
                                                    "{} · {}",
                                                    database_product(artifact.product).label,
                                                    database_artifact_display_label(artifact),
                                                )),
                                            )
                                            .child(
                                                div()
                                                    .text_xs()
                                                    .text_color(tokens.muted)
                                                    .child(format!(
                                                        "{} · {} · {}",
                                                        artifact.key,
                                                        artifact.default_file_name.unwrap_or("无固定文件名"),
                                                        workspace_label,
                                                    )),
                                            )
                                            .child(
                                                div()
                                                    .text_xs()
                                                    .text_color(tokens.muted)
                                                    .child(bounded_visual_row_text(
                                                        artifact.validation_note,
                                                        160,
                                                    )),
                                            )
                                            .when_some(support_gap, |card, gap| {
                                                card.child(
                                                    div()
                                                        .rounded_md()
                                                        .bg(tokens.surface)
                                                        .p_2()
                                                        .text_xs()
                                                        .text_color(tokens.warning)
                                                        .child(format!(
                                                            "{}：{} 开放条件：{}",
                                                            gap.label(),
                                                            gap.explanation(),
                                                            gap.acceptance(),
                                                        )),
                                                )
                                            })
                                            .when(can_open, |card| {
                                                card.child(
                                                    crate::buttons::button(button_id)
                                                        .label("打开此配置")
                                                        .small()
                                                        .disabled(
                                                            saving
                                                                || self.importing
                                                                || self.model.visual_dirty,
                                                        )
                                                        .on_click(cx.listener(
                                                            move |page, _, window, cx| {
                                                                page.select_database_artifact(
                                                                    artifact, window, cx,
                                                                )
                                                            },
                                                        )),
                                                )
                                            })
                                    },
                                )),
                        )
                    })
                    .when(!database_bundle_goal_matches.is_empty(), |panel| {
                        panel.child(
                            div()
                                .id("config-generator-database-bundle-goal-results")
                                .debug_selector(|| {
                                    "config-generator-database-bundle-goal-results".to_owned()
                                })
                                .flex()
                                .flex_col()
                                .gap_2()
                                .children(
                                    database_bundle_goal_matches
                                        .into_iter()
                                        .enumerate()
                                        .map(|(goal_index, (goal, product, version))| {
                                            self.render_database_bundle_goal_card(
                                                goal, product, version, goal_index, tokens, cx,
                                            )
                                        }),
                                ),
                        )
                    })
                    .when(!database_goal_matches.is_empty(), |panel| {
                        panel.child(
                            div()
                                .id("config-generator-database-goal-results")
                                .debug_selector(|| {
                                    "config-generator-database-goal-results".to_owned()
                                })
                                .flex()
                                .flex_col()
                                .gap_2()
                                .child(section_label("数据库参数目标", tokens))
                                .children(database_goal_matches.into_iter().map(
                                    |(schema, parameter_index)| {
                                        let parameter = &schema.parameters[parameter_index];
                                        let matched = ConfigurationGoalMatch::DatabaseParameter {
                                            schema,
                                            parameter_index,
                                        };
                                        let subject = matched.subject();
                                        let support_gap = matched.support_gap();
                                        let actionable = database_parameter_goal_availability(
                                            schema,
                                            parameter_index,
                                        ) == ConfigurationGoalAvailability::LocalDraftRecipe;
                                        let button_id = SharedString::from(format!(
                                            "config-generator-database-goal-{}-{}-{}",
                                            schema.binding.artifact_key,
                                            schema.version_label,
                                            parameter_index,
                                        ));
                                        div()
                                            .rounded_md()
                                            .border_1()
                                            .border_color(tokens.border)
                                            .bg(tokens.surface_alt)
                                            .p_3()
                                            .flex()
                                            .flex_col()
                                            .gap_2()
                                            .child(
                                                div().text_sm().font_semibold().child(format!(
                                                    "{} · {} · {}",
                                                    subject.label(),
                                                    parameter
                                                        .container_path
                                                        .unwrap_or("根级配置"),
                                                    parameter.canonical_key,
                                                )),
                                            )
                                            .child(
                                                div()
                                                    .text_xs()
                                                    .text_color(tokens.muted)
                                                    .child(format!(
                                                        "{} · {}",
                                                        schema.version_label,
                                                        bounded_visual_row_text(
                                                            parameter.competition_rationale,
                                                            140,
                                                        ),
                                                    )),
                                            )
                                            .when_some(support_gap, |card, gap| {
                                                card.child(
                                                    div()
                                                        .rounded_md()
                                                        .bg(tokens.surface)
                                                        .p_2()
                                                        .text_xs()
                                                        .text_color(tokens.warning)
                                                        .child(format!(
                                                            "{}：{} 开放条件：{}",
                                                            gap.label(),
                                                            gap.explanation(),
                                                            gap.acceptance(),
                                                        )),
                                                )
                                            })
                                            .child(
                                                crate::buttons::button(button_id)
                                                    .label(if actionable {
                                                        "配置这个目标"
                                                    } else {
                                                        "查看这个配置目标"
                                                    })
                                                    .small()
                                                    .on_click(cx.listener(
                                                        move |page, _, window, cx| {
                                                            page.open_database_parameter_goal(
                                                                schema,
                                                                parameter_index,
                                                                window,
                                                                cx,
                                                            )
                                                        },
                                                    )),
                                            )
                                    },
                                )),
                        )
                    })
                    .when(!unavailable_goal_subjects.is_empty(), |panel| {
                        panel.child(
                            div()
                                .id("config-generator-unavailable-goal-results")
                                .debug_selector(|| {
                                    "config-generator-unavailable-goal-results".to_owned()
                                })
                                .flex()
                                .flex_col()
                                .gap_2()
                                .children(unavailable_goal_subjects.into_iter().map(|(coverage, gap)| {
                                    let available_versions = match (coverage.subject, gap) {
                                        (
                                            ConfigurationGoalSubject::Database(product),
                                            ConfigurationGoalSupportGap::MissingVersion,
                                        ) => Some(
                                            database_goal_available_version_labels(product).join("、"),
                                        ),
                                        _ => None,
                                    };
                                    div()
                                        .rounded_md()
                                        .border_1()
                                        .border_color(tokens.warning)
                                        .bg(tokens.surface_alt)
                                        .p_3()
                                        .flex()
                                        .flex_col()
                                        .gap_1()
                                        .child(
                                            div().text_xs().font_semibold().child(format!(
                                                "{} · {}",
                                                coverage.subject.label(),
                                                gap.label(),
                                            )),
                                        )
                                        .child(
                                            div()
                                                .text_xs()
                                                .text_color(tokens.muted)
                                                .child(gap.explanation()),
                                        )
                                        .child(
                                            div()
                                                .text_xs()
                                                .text_color(tokens.muted)
                                                .child(format!(
                                                    "当前已有：{}",
                                                    coverage.evidence_summary()
                                                )),
                                        )
                                        .child(
                                            div()
                                                .text_xs()
                                                .text_color(tokens.warning)
                                                .child(format!("开放条件：{}", gap.acceptance())),
                                        )
                                        .when_some(available_versions, |card, versions| {
                                            card.child(
                                                div()
                                                    .text_xs()
                                                    .text_color(tokens.muted)
                                                    .child(format!("当前已登记版本：{versions}")),
                                            )
                                        })
                                })),
                        )
                    })
                    .when(goal_results_truncated, |panel| {
                        panel.child(
                            div()
                                .rounded_md()
                                .bg(tokens.surface_alt)
                                .p_2()
                                .text_xs()
                                .text_color(tokens.muted)
                                .child("结果较多，仅显示最相关的一部分；请加入产品名或参数名缩小范围。"),
                        )
                    })
                    .when(no_goal_matches, |panel| {
                        panel.child(
                            div()
                                .rounded_md()
                                .border_1()
                                .border_color(tokens.border)
                                .p_3()
                                .text_xs()
                                .text_color(tokens.muted)
                                .child(
                                    "尚未收录与该搜索匹配的安全配方或参数依据；不会把自然语言直接拼成配置。",
                                ),
                        )
                    })
                    .child(
                        div().child(section_label("站点类型", tokens)).child(
                            div().mt_2().flex().gap_2().children(
                                NginxSiteKind::ALL.into_iter().map(|option| {
                                    crate::buttons::button(SharedString::from(format!(
                                        "config-generator-kind-{option:?}"
                                    )))
                                    .label(option.label())
                                    .small()
                                    .selected(kind == option)
                                    .on_click(cx.listener(move |page, _, window, cx| {
                                        page.select_kind(option, window, cx)
                                    }))
                                }),
                            ),
                        ),
                    )
                    .child(input_field(
                        "域名",
                        "快捷模板接受一个精确 DNS 名称；本地无损草稿可处理任意 Nginx 语法节点，但不能应用/部署。",
                        &self.server_name_input,
                        tokens,
                    ))
                    .child(input_field(
                        "监听端口",
                        "范围 1 - 65535。",
                        &self.listen_port_input,
                        tokens,
                    ))
                    .child(match kind {
                        NginxSiteKind::Static => input_field(
                            "站点目录",
                            "绝对 POSIX 路径；拒绝遍历、空格和 Nginx 元字符。",
                            &self.static_root_input,
                            tokens,
                        ),
                        NginxSiteKind::ReverseProxy => input_field(
                            "上游地址",
                            "仅支持 http/https origin，例如 http://127.0.0.1:3000。",
                            &self.upstream_input,
                            tokens,
                        ),
                    })
                    .child(
                        crate::buttons::button("config-generator-security-headers")
                            .label(if security_headers {
                                "安全基础项：已启用"
                            } else {
                                "安全基础项：未启用"
                            })
                            .small()
                            .selected(security_headers)
                            .on_click(cx.listener(|page, _, _, cx| {
                                page.toggle_security_headers(cx)
                            })),
                    )
                    .child(
                        div()
                            .rounded_md()
                            .bg(tokens.surface_alt)
                            .p_3()
                            .text_xs()
                            .text_color(tokens.muted)
                            .child("安全基础项仅加入固定的版本隐藏与响应头；部署前仍需在目标机运行 nginx -t。"),
                    )
                    .child(
                        crate::buttons::button("config-generator-regenerate")
                            .label("重新生成")
                            .small()
                            .on_click(cx.listener(|page, _, _, cx| page.regenerate(cx))),
                    ),
            )
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .min_h_0()
                    .rounded_lg()
                    .border_1()
                    .border_color(tokens.border)
                    .bg(tokens.surface)
                    .p_4()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(
                                div()
                                    .flex_1()
                                    .child(section_label("Nginx 配置预览", tokens)),
                            )
                            .child(
                                crate::buttons::button("config-generator-load-visual")
                                    .label("载入本地草稿")
                                    .small()
                                    .disabled(generated.is_none() || saving || self.importing)
                                    .on_click(cx.listener(|page, _, window, cx| {
                                        page.load_quick_into_visual(window, cx)
                                    })),
                            )
                            .child(
                                crate::buttons::button("config-generator-copy")
                                    .label("复制")
                                    .small()
                                    .disabled(generated.is_none())
                                    .on_click(cx.listener(|page, _, _, cx| page.copy_current(cx))),
                            )
                            .child(
                                crate::buttons::button("config-generator-save")
                                    .label(if saving {
                                        "正在另存…"
                                    } else {
                                        LOCAL_DRAFT_SAVE_LABEL
                                    })
                                    .small()
                                    .disabled(saving || self.importing || generated.is_none())
                                    .on_click(cx.listener(|page, _, _, cx| {
                                        page.choose_save_path(cx)
                                    })),
                            ),
                    )
                    .child(config_preview(generated.as_ref(), tokens)),
            )
            .into_any_element()
    }

    fn render_visual_node_rows(
        &mut self,
        range: Range<usize>,
        visible_indices: Arc<Vec<usize>>,
        tokens: ThemeTokens,
        cx: &mut Context<Self>,
    ) -> Vec<AnyElement> {
        range
            .filter_map(|index| {
                let source_index = *visible_indices.get(index)?;
                let row = self.model.visual_rows.get(source_index)?.clone();
                let id = row.id();
                let selected = self.model.selected_visual_node == Some(id);
                let depth = row.depth().min(16) as f32 * 14.0;
                let name = row.name().unwrap_or_default();
                let label = if name.is_empty() {
                    row.kind().label().to_owned()
                } else if row.kind() == VisualNodeKind::Container {
                    format!(
                        "{} · {name} · {} 子节点",
                        row.kind().label(),
                        row.child_count()
                    )
                } else {
                    format!("{} · {name}", row.kind().label())
                };
                let label = bounded_visual_row_text(&label, MAX_VISUAL_ROW_LABEL_CHARS);
                let preview = if row.truncated() {
                    format!("{} …", row.preview())
                } else {
                    row.preview().to_owned()
                };
                let preview = bounded_visual_row_text(&preview, MAX_VISUAL_ROW_PREVIEW_CHARS);
                Some(
                    div()
                        .id(SharedString::from(format!(
                            "config-generator-visual-node-{}",
                            id.get()
                        )))
                        .h(px(VISUAL_WORKSPACE_LAYOUT.node_row_height))
                        .min_w_0()
                        .px_2()
                        .py_2()
                        .pl(px(8.0 + depth))
                        .flex()
                        .flex_col()
                        .justify_center()
                        .gap_1()
                        .border_b_1()
                        .border_color(tokens.border)
                        .bg(if selected {
                            tokens.surface_alt
                        } else {
                            tokens.surface
                        })
                        .cursor_pointer()
                        .on_click(cx.listener(move |page, _, window, cx| {
                            page.select_visual_node(id, window, cx)
                        }))
                        .child(
                            div()
                                .w_full()
                                .min_w_0()
                                .truncate()
                                .text_xs()
                                .font_semibold()
                                .text_color(if row.allows_local_draft_mutation() {
                                    tokens.accent
                                } else {
                                    tokens.warning
                                })
                                .child(label),
                        )
                        .child(
                            div()
                                .w_full()
                                .min_w_0()
                                .truncate()
                                .text_xs()
                                .text_color(tokens.text)
                                .child(preview),
                        )
                        .into_any_element(),
                )
            })
            .collect()
    }

    fn render_schema_catalog_rows(
        &mut self,
        range: Range<usize>,
        schema: &'static DatabaseConfigSchema,
        visible_indices: Arc<Vec<usize>>,
        tokens: ThemeTokens,
        cx: &mut Context<Self>,
    ) -> Vec<AnyElement> {
        range
            .filter_map(|visible_index| {
                let parameter_index = *visible_indices.get(visible_index)?;
                let parameter = schema.parameters.get(parameter_index)?;
                let selected = self.model.selected_schema_parameter == Some(parameter_index);
                let container = parameter.container_path.unwrap_or("<root>");
                Some(
                    div()
                        .id(SharedString::from(format!(
                            "config-generator-schema-catalog-{parameter_index}"
                        )))
                        .h(px(VISUAL_WORKSPACE_LAYOUT.node_row_height))
                        .min_w_0()
                        .px_2()
                        .py_2()
                        .flex()
                        .flex_col()
                        .justify_center()
                        .gap_1()
                        .border_b_1()
                        .border_color(tokens.border)
                        .bg(if selected {
                            tokens.surface_alt
                        } else {
                            tokens.surface
                        })
                        .cursor_pointer()
                        .on_click(cx.listener(move |page, _, window, cx| {
                            page.select_schema_catalog_parameter(
                                schema,
                                parameter_index,
                                window,
                                cx,
                            )
                        }))
                        .child(
                            div()
                                .w_full()
                                .min_w_0()
                                .truncate()
                                .text_xs()
                                .font_semibold()
                                .text_color(tokens.accent)
                                .child(parameter.canonical_key),
                        )
                        .child(
                            div()
                                .w_full()
                                .min_w_0()
                                .truncate()
                                .text_xs()
                                .text_color(tokens.muted)
                                .child(format!(
                                    "{} · {}",
                                    container,
                                    schema_sensitivity_label(parameter.sensitivity)
                                )),
                        )
                        .into_any_element(),
                )
            })
            .collect()
    }

    fn render_visual_workspace(
        &mut self,
        tokens: ThemeTokens,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let document_kind = self.model.visual_document.kind();
        let selected_database_schema = self.model.current_database_schema();
        let search_query = self.visual_search_query(cx);
        let show_forbidden_goal_result = document_kind == VisualDocumentKind::Nginx
            && !search_query.trim().is_empty()
            && nginx_forbidden_goal_matches(&search_query);
        let visible_visual_indices =
            Arc::new(self.model.filtered_visual_row_indices(&search_query));
        let visible_schema_parameter_indices =
            Arc::new(self.model.filtered_schema_parameter_indices(&search_query));
        let row_count = visible_visual_indices.len();
        let total_row_count = self.model.visual_rows.len();
        let schema_parameter_count = visible_schema_parameter_indices.len();
        let total_schema_parameter_count = selected_database_schema
            .map(|schema| schema.parameters.len())
            .unwrap_or_default();
        let search_scope_notice = match (document_kind, selected_database_schema) {
            (VisualDocumentKind::Database(_), Some(_)) => {
                "搜索覆盖当前文档的安全结构字段，以及完整 Schema 配置目录；目录结果不修改文件。"
            }
            (VisualDocumentKind::Database(_), None) => {
                "搜索仅覆盖当前文档的安全结构字段；选择与工件精确绑定的静态 schema 后才提供配置目录。"
            }
            (VisualDocumentKind::Nginx, _) => {
                "搜索覆盖当前文档节点；403、禁止访问、外部访问或 /路径 还会显示已审查的目标配方。不会索引参数、注释或原文。"
            }
            (VisualDocumentKind::Apache, _) => {
                "当前类型没有闭合 Schema 配置目录；搜索仅覆盖当前文档节点，不读取参数、注释或原文。"
            }
        };
        let selected = self.model.selected_visual_row().cloned();
        let selected_schema_parameter = self.model.selected_schema_parameter();
        let schema_catalog_selected = selected_schema_parameter.is_some();
        let selected_schema_parameter_index = self.model.selected_schema_parameter;
        let database_goal_actionable = selected_database_schema
            .zip(selected_schema_parameter_index)
            .is_some_and(|(schema, parameter_index)| {
                database_parameter_goal_availability(schema, parameter_index)
                    == ConfigurationGoalAvailability::LocalDraftRecipe
            });
        let database_goal_choices = selected_schema_parameter
            .map(|parameter| match parameter.value_kind {
                DatabaseConfigSchemaValueKind::Boolean {
                    true_literal,
                    false_literal,
                } => vec![true_literal, false_literal],
                DatabaseConfigSchemaValueKind::Enumeration { values } => values
                    .iter()
                    .copied()
                    .take(MAX_DATABASE_GOAL_CHOICES)
                    .collect(),
                DatabaseConfigSchemaValueKind::Integer { .. }
                | DatabaseConfigSchemaValueKind::Text { .. } => Vec::new(),
            })
            .unwrap_or_default();
        let configuration_explanation = match (selected_database_schema, selected_schema_parameter)
        {
            (Some(schema), Some(parameter)) => {
                database_catalog_parameter_explanation(schema, parameter)
            }
            (_, None) if selected.is_some() => visual_row_explanation(
                document_kind,
                selected.as_ref().expect("selected row checked above"),
                selected_database_schema,
            ),
            _ => no_visual_selection_explanation(document_kind, selected_database_schema),
        };
        let explanation_heading = selected_schema_parameter.map_or_else(
            || {
                selected.as_ref().map_or_else(
                    || "新增根节点 / 选择节点编辑".to_owned(),
                    |row| {
                        let name = row.name().unwrap_or_default();
                        if name.is_empty() {
                            row.kind().label().to_owned()
                        } else {
                            format!("{} · {name}", row.kind().label())
                        }
                    },
                )
            },
            |parameter| format!("Schema 配置目录 · {}", parameter.canonical_key),
        );
        let allows_lossless_local_draft = self
            .model
            .visual_document
            .kind()
            .allows_lossless_local_draft();
        let selected_local_draft_mutable = allows_lossless_local_draft
            && selected
                .as_ref()
                .is_some_and(VisualRow::allows_local_draft_mutation);
        let selected_local_draft_container = selected.as_ref().is_some_and(|row| {
            row.allows_local_draft_mutation() && row.kind() == VisualNodeKind::Container
        }) && allows_lossless_local_draft;
        let structured = self.model.visual_document.is_structured();
        let contains_sensitive_values = self.model.contains_sensitive_visual_values();
        let can_copy = self.model.can_copy_visual();
        let visual_dirty = self.model.visual_dirty;
        let busy = self.importing || self.saving;
        let supports_containers = document_kind.supports_containers();
        let supports_nested_containers = document_kind.supports_nested_containers();
        let selected_database_artifact = match document_kind {
            VisualDocumentKind::Database(artifact) => Some(artifact),
            VisualDocumentKind::Nginx | VisualDocumentKind::Apache => None,
        };
        let selected_database_product = selected_database_artifact.map(|artifact| artifact.product);
        let product_selector = div()
            .flex_none()
            .rounded_md()
            .border_1()
            .border_color(tokens.border)
            .bg(tokens.surface)
            .p_2()
            .flex()
            .flex_wrap()
            .gap_2()
            .children(
                [VisualDocumentKind::Nginx, VisualDocumentKind::Apache]
                    .into_iter()
                    .map(|kind| {
                        crate::buttons::button(SharedString::from(format!(
                            "config-generator-visual-product-{kind:?}"
                        )))
                        .label(kind.label())
                        .small()
                        .selected(document_kind == kind)
                        .disabled(busy || visual_dirty)
                        .on_click(cx.listener(
                            move |page, _, window, cx| {
                                page.select_visual_document_kind(kind, window, cx)
                            },
                        ))
                    }),
            )
            .children(
                DATABASE_CONFIG_PRODUCTS
                    .iter()
                    .filter(|definition| database_product_has_visual_files(definition.product))
                    .map(|definition| {
                        let product = definition.product;
                        crate::buttons::button(SharedString::from(format!(
                            "config-generator-database-product-{}",
                            definition.key
                        )))
                        .label(definition.label)
                        .small()
                        .selected(selected_database_product == Some(product))
                        .disabled(busy || visual_dirty)
                        .on_click(cx.listener(
                            move |page, _, window, cx| {
                                page.select_database_product(product, window, cx)
                            },
                        ))
                    }),
            );
        let artifact_selector = selected_database_product.map(|product| {
            div()
                .flex_none()
                .rounded_md()
                .border_1()
                .border_color(tokens.border)
                .bg(tokens.surface_alt)
                .p_2()
                .flex()
                .flex_wrap()
                .gap_2()
                .children(
                    artifacts_for(product)
                        .filter(|artifact| database_visual_parser(artifact).is_some())
                        .map(|artifact| {
                            crate::buttons::button(SharedString::from(format!(
                                "config-generator-database-artifact-{}",
                                artifact.key
                            )))
                            .label(database_artifact_display_label(artifact))
                            .small()
                            .selected(document_kind == VisualDocumentKind::Database(artifact))
                            .disabled(busy || visual_dirty)
                            .on_click(cx.listener(
                                move |page, _, window, cx| {
                                    page.select_database_artifact(artifact, window, cx)
                                },
                            ))
                        }),
                )
                .into_any_element()
        });
        let schema_selector = selected_database_artifact.map(|artifact| {
            let schema_buttons = DATABASE_CONFIG_SCHEMAS
                .iter()
                .enumerate()
                .filter(|(_, schema)| database_schema_matches_artifact(schema, artifact))
                .map(|(index, schema)| {
                    crate::buttons::button(SharedString::from(format!(
                        "config-generator-database-schema-{}-{index}",
                        artifact.key
                    )))
                    .label(format!(
                        "{} · {}",
                        schema.display_label, schema.version_label
                    ))
                    .small()
                    .selected(
                        selected_database_schema
                            .is_some_and(|selected| std::ptr::eq(selected, schema)),
                    )
                    .disabled(busy)
                    .on_click(cx.listener(move |page, _, window, cx| {
                        page.select_database_schema(schema, window, cx)
                    }))
                    .into_any_element()
                })
                .collect::<Vec<_>>();
            let has_schema_options = !schema_buttons.is_empty();
            div()
                .flex_none()
                .rounded_md()
                .border_1()
                .border_color(tokens.border)
                .bg(tokens.surface_alt)
                .p_2()
                .flex()
                .flex_col()
                .gap_2()
                .child(div().text_xs().font_semibold().child("已审静态 Schema"))
                .child(
                    div()
                        .flex()
                        .flex_wrap()
                        .gap_2()
                        .children(schema_buttons)
                        .when(!has_schema_options, |buttons| {
                            buttons.child(
                                div()
                                    .text_xs()
                                    .text_color(tokens.muted)
                                    .child("当前工件暂无已审静态 schema；不会猜测默认版本。"),
                            )
                        }),
                )
                .child(
                    div()
                        .text_xs()
                        .text_color(tokens.muted)
                        .child(database_schema_status(selected_database_schema)),
                )
                .into_any_element()
        });
        div()
            .w_full()
            .flex_none()
            .flex()
            .flex_col()
            .gap_3()
            .child(product_selector)
            .when_some(artifact_selector, |workspace, selector| {
                workspace.child(selector)
            })
            .when_some(schema_selector, |workspace, selector| {
                workspace.child(selector)
            })
            .child(
                div()
                    .flex_none()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(
                        crate::buttons::button("config-generator-new-competition")
                            .label("新建本地比赛草稿")
                            .small()
                            .disabled(busy || visual_dirty || !allows_lossless_local_draft)
                            .on_click(cx.listener(|page, _, window, cx| {
                                page.new_competition_skeleton(window, cx)
                            })),
                    )
                    .child(
                        crate::buttons::button("config-generator-import-conf")
                            .label(if self.importing {
                                "正在导入…"
                            } else {
                                "导入本地配置"
                            })
                            .small()
                            .disabled(busy || visual_dirty)
                            .on_click(cx.listener(|page, _, _, cx| page.choose_import_path(cx))),
                    )
                    .child(
                        crate::buttons::button("config-generator-use-quick")
                            .label("载入本地草稿")
                            .small()
                            .disabled(
                                busy || visual_dirty || self.model.generated.is_none(),
                            )
                            .on_click(cx.listener(|page, _, window, cx| {
                                page.load_quick_into_visual(window, cx)
                            })),
                    )
                    .child(div().flex_1())
                    .child(
                        crate::buttons::button("config-generator-visual-copy")
                            .label("复制本地配置")
                            .small()
                            .disabled(busy || !can_copy)
                            .on_click(cx.listener(|page, _, _, cx| page.copy_current(cx))),
                    )
                    .child(
                        crate::buttons::button("config-generator-visual-save")
                            .label(if self.saving {
                                "正在另存…"
                            } else if allows_lossless_local_draft {
                                LOCAL_DRAFT_SAVE_LABEL
                            } else {
                                "另存只读副本"
                            })
                            .small()
                            .disabled(busy)
                            .on_click(cx.listener(|page, _, _, cx| {
                                page.choose_save_path(cx)
                            })),
                    ),
            )
            .child(
                div()
                    .flex_none()
                    .rounded_md()
                    .border_1()
                    .border_color(if structured
                        && allows_lossless_local_draft
                        && !contains_sensitive_values
                    {
                        tokens.border
                    } else {
                        tokens.warning
                    })
                    .bg(tokens.surface_alt)
                    .px_3()
                    .py_2()
                    .text_xs()
                    .text_color(if structured
                        && allows_lossless_local_draft
                        && !contains_sensitive_values
                    {
                        tokens.muted
                    } else {
                        tokens.warning
                    })
                    .child(if let Some(read_only_notice) = document_kind.read_only_notice() {
                        let sensitive_notice = if contains_sensitive_values {
                            " 检测到可能的凭据或令牌；树中敏感值与预览已隐藏，剪贴板复制已禁用。"
                        } else {
                            ""
                        };
                        format!("{read_only_notice}{sensitive_notice}")
                    } else if contains_sensitive_values {
                        format!("检测到可能的凭据或令牌；树中敏感值与预览已隐藏，剪贴板复制已禁用。另存本地草稿仍保留完整字节；尚未运行 {}；{LOCAL_DRAFT_SCOPE_NOTICE}。", document_kind.validator_label())
                    } else if structured && visual_dirty {
                        format!("通用语法覆盖未知/第三方 {} 配置节点；本地无损草稿有未另存修改，尚未在目标机运行 {}；{LOCAL_DRAFT_SCOPE_NOTICE}。", document_kind.label(), document_kind.validator_label())
                    } else if structured {
                        format!("通用语法覆盖未知/第三方 {} 配置节点；当前仅为本地无损草稿，尚未在目标机运行 {}；{LOCAL_DRAFT_SCOPE_NOTICE}。", document_kind.label(), document_kind.validator_label())
                    } else {
                        format!("该文件含非 UTF-8 或不完整结构，已作为不透明原文字节完整保留；可预览和另存只读副本，结构操作已禁用。尚未运行 {}，不能应用/部署。", document_kind.validator_label())
                    }),
            )
            .child(
                div()
                    .flex_1()
                    .min_h(px(VISUAL_WORKSPACE_LAYOUT.split_min_height))
                    .flex()
                    .gap_3()
                    .child(
                        div()
                            .w(px(430.0))
                            .flex_none()
                            .min_h_0()
                            .rounded_lg()
                            .border_1()
                            .border_color(tokens.border)
                            .bg(tokens.surface)
                            .flex()
                            .flex_col()
                            .child(
                                div()
                                    .flex_none()
                                    .px_3()
                                    .py_2()
                                    .border_b_1()
                                    .border_color(tokens.border)
                                    .flex()
                                    .flex_col()
                                    .gap_2()
                                    .child(div().font_semibold().child("快速搜索"))
                                    .child(Input::new(&self.visual_search_input).small())
                                    .child(
                                        div()
                                            .text_xs()
                                            .text_color(tokens.muted)
                                            .child(search_scope_notice),
                                    ),
                            )
                            .when(show_forbidden_goal_result, |tree| {
                                let goal_query = search_query.clone();
                                tree.child(
                                    div()
                                        .id("config-generator-visual-forbidden-goal-result")
                                        .debug_selector(|| {
                                            "config-generator-visual-forbidden-goal-result"
                                                .to_owned()
                                        })
                                        .flex_none()
                                        .px_3()
                                        .py_2()
                                        .border_b_1()
                                        .border_color(tokens.border)
                                        .bg(tokens.surface_alt)
                                        .flex()
                                        .flex_col()
                                        .gap_1()
                                        .child(
                                            div()
                                                .text_xs()
                                                .font_semibold()
                                                .text_color(tokens.accent)
                                                .child(
                                                    "按目标配置 · 禁止指定路径（HTTP 403）",
                                                ),
                                        )
                                        .child(
                                            div()
                                                .text_xs()
                                                .text_color(tokens.muted)
                                                .child(
                                                    "生成精确路径与可选子路径规则，不把搜索原句直接写进配置。",
                                                ),
                                        )
                                        .child(
                                            crate::buttons::button(
                                                "config-generator-use-forbidden-goal-result",
                                            )
                                            .label("进入按目标生成")
                                            .small()
                                            .on_click(cx.listener(
                                                move |page, _, window, cx| {
                                                    page.start_forbidden_path_goal(
                                                        &goal_query,
                                                        window,
                                                        cx,
                                                    )
                                                },
                                            )),
                                        ),
                                )
                            })
                            .when_some(selected_database_schema, |tree, schema| {
                                tree.child(
                                    div()
                                        .flex_none()
                                        .px_3()
                                        .py_2()
                                        .border_b_1()
                                        .border_color(tokens.border)
                                        .font_semibold()
                                        .child(format!(
                                            "Schema 配置目录 · {schema_parameter_count}/{total_schema_parameter_count}"
                                        )),
                                )
                                .when(schema_parameter_count == 0, |tree| {
                                    tree.child(
                                        div()
                                            .flex_none()
                                            .px_3()
                                            .py_2()
                                            .text_xs()
                                            .text_color(tokens.muted)
                                            .child("目录中没有匹配项。"),
                                    )
                                })
                                .child(
                                    uniform_list(
                                        "config-generator-schema-catalog",
                                        schema_parameter_count,
                                        {
                                            let visible_indices =
                                                Arc::clone(&visible_schema_parameter_indices);
                                            cx.processor(move |page, range, _, cx| {
                                                page.render_schema_catalog_rows(
                                                    range,
                                                    schema,
                                                    Arc::clone(&visible_indices),
                                                    tokens,
                                                    cx,
                                                )
                                            })
                                        },
                                    )
                                    .h(px(150.0))
                                    .min_h_0()
                                    .track_scroll(self.visual_catalog_scroll.clone()),
                                )
                            })
                            .child(
                                div()
                                    .flex_none()
                                    .px_3()
                                    .py_2()
                                    .border_y_1()
                                    .border_color(tokens.border)
                                    .font_semibold()
                                    .child(format!(
                                        "{} 当前文档节点 · {row_count}/{total_row_count}",
                                        document_kind.label()
                                    )),
                            )
                            .when(row_count == 0, |tree| {
                                tree.child(
                                    div()
                                        .flex_none()
                                        .px_3()
                                        .py_2()
                                        .text_xs()
                                        .text_color(tokens.muted)
                                        .child("当前文档没有匹配节点。"),
                                )
                            })
                            .child(
                                uniform_list(
                                    "config-generator-visual-tree",
                                    row_count,
                                    {
                                        let visible_indices = Arc::clone(&visible_visual_indices);
                                        cx.processor(move |page, range, _, cx| {
                                            page.render_visual_node_rows(
                                                range,
                                                Arc::clone(&visible_indices),
                                                tokens,
                                                cx,
                                            )
                                        })
                                    },
                                )
                                .flex_1()
                                .min_h_0()
                                .track_scroll(self.visual_node_scroll.clone()),
                            ),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .min_h_0()
                            .flex()
                            .flex_col()
                            .gap_3()
                            .child(
                                div()
                                    .flex_none()
                                    .max_h(px(VISUAL_WORKSPACE_LAYOUT.editor_max_height))
                                    .overflow_y_scrollbar()
                                    .rounded_lg()
                                    .border_1()
                                    .border_color(tokens.border)
                                    .bg(tokens.surface)
                                    .p_3()
                                    .flex()
                                    .flex_col()
                                    .gap_2()
                                    .child(div().font_semibold().child(explanation_heading))
                                    .child(
                                        div()
                                            .text_xs()
                                            .text_color(tokens.muted)
                                            .child(if schema_catalog_selected {
                                                if database_goal_actionable {
                                                    "该目录项可用已审值域生成本地草稿；输入仍只做 SyntaxValid，不代表目标已核验。"
                                                        .to_owned()
                                                } else {
                                                    "该目录项当前只显示静态说明；秘密、能力依赖或只读工件不会开放通用值输入。"
                                                        .to_owned()
                                                }
                                            } else {
                                                format!(
                                                    "名称用于指令/{}；“参数 / 注释正文”在注释节点上只表示正文。",
                                                    document_kind.container_label()
                                                )
                                            }),
                                    )
                                    .child(
                                        div()
                                            .rounded_md()
                                            .border_1()
                                            .border_color(tokens.border)
                                            .bg(tokens.surface_alt)
                                            .p_2()
                                            .flex()
                                            .flex_col()
                                            .gap_1()
                                            .child(
                                                div()
                                                    .text_xs()
                                                    .font_semibold()
                                                    .child("配置说明"),
                                            )
                                            .child(
                                                div()
                                                    .text_xs()
                                                    .text_color(tokens.muted)
                                                    .child(configuration_explanation),
                                            ),
                                    )
                                    .when_some(selected_schema_parameter, |editor, parameter| {
                                        editor.child(
                                            div()
                                                .id("config-generator-database-goal-editor")
                                                .debug_selector(|| {
                                                    "config-generator-database-goal-editor".to_owned()
                                                })
                                                .rounded_md()
                                                .border_1()
                                                .border_color(if database_goal_actionable {
                                                    tokens.accent
                                                } else {
                                                    tokens.border
                                                })
                                                .bg(tokens.surface_alt)
                                                .p_2()
                                                .flex()
                                                .flex_col()
                                                .gap_2()
                                                .child(
                                                    div()
                                                        .text_xs()
                                                        .font_semibold()
                                                        .child(if database_goal_actionable {
                                                            "按目标填写新值"
                                                        } else {
                                                            "该目标当前只能查看"
                                                        }),
                                                )
                                                .child(
                                                    div()
                                                        .text_xs()
                                                        .text_color(tokens.muted)
                                                        .child(format!(
                                                            "{}；输出只使用 canonical key `{}`。",
                                                            schema_value_kind_description(
                                                                parameter.value_kind
                                                            ),
                                                            parameter.canonical_key,
                                                        )),
                                                )
                                                .when(database_goal_actionable, |goal| {
                                                    goal.child(
                                                        Input::new(
                                                            &self.database_goal_value_input,
                                                        )
                                                        .small(),
                                                    )
                                                    .when(
                                                        !database_goal_choices.is_empty(),
                                                        |goal| {
                                                            goal.child(
                                                                div()
                                                                    .flex()
                                                                    .flex_wrap()
                                                                    .gap_2()
                                                                    .children(
                                                                        database_goal_choices
                                                                            .iter()
                                                                            .enumerate()
                                                                            .map(
                                                                                |(
                                                                                    choice_index,
                                                                                    choice,
                                                                                )| {
                                                                                    let choice =
                                                                                        *choice;
                                                                                    crate::buttons::button(
                                                                                        SharedString::from(format!(
                                                                                            "config-generator-database-goal-choice-{choice_index}"
                                                                                        )),
                                                                                    )
                                                                                    .label(choice)
                                                                                    .small()
                                                                                    .on_click(cx.listener(
                                                                                        move |page, _, window, cx| {
                                                                                            page.choose_database_parameter_goal_value(
                                                                                                choice,
                                                                                                window,
                                                                                                cx,
                                                                                            )
                                                                                        },
                                                                                    ))
                                                                                },
                                                                            ),
                                                                    ),
                                                            )
                                                        },
                                                    )
                                                    .child(
                                                        crate::buttons::button(
                                                            "config-generator-apply-database-goal",
                                                        )
                                                        .label("校验并加入本地草稿")
                                                        .small()
                                                        .primary()
                                                        .disabled(busy)
                                                        .on_click(cx.listener(
                                                            |page, _, window, cx| {
                                                                page.apply_selected_database_parameter_goal(
                                                                    window, cx,
                                                                )
                                                            },
                                                        )),
                                                    )
                                                    .child(
                                                        div()
                                                            .text_xs()
                                                            .text_color(tokens.warning)
                                                            .child(
                                                                "只生成本地草稿；不会连接数据库、修改远端、执行 reload/restart 或宣称目标已验证。",
                                                            ),
                                                    )
                                                })
                                                .when(!database_goal_actionable, |goal| {
                                                    goal.child(
                                                        div()
                                                            .text_xs()
                                                            .text_color(tokens.warning)
                                                            .child(
                                                                "请先补齐精确目标能力或专用秘密输入边界；当前不提供生成按钮。",
                                                            ),
                                                    )
                                                }),
                                        )
                                    })
                                    .child(
                                        div()
                                            .child(section_label("名称", tokens))
                                            .child(
                                                div()
                                                    .mt_1()
                                                    .child(
                                                        Input::new(&self.visual_name_input)
                                                            .small()
                                                            .disabled(
                                                                busy
                                                                    || !allows_lossless_local_draft
                                                                    || schema_catalog_selected,
                                                            ),
                                                    ),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .child(section_label("参数 / 注释正文", tokens))
                                            .child(
                                                div()
                                                    .mt_1()
                                                    .h(px(76.0))
                                                    .child(
                                                        Input::new(&self.visual_arguments_input)
                                                            .disabled(
                                                                busy
                                                                    || !allows_lossless_local_draft
                                                                    || schema_catalog_selected,
                                                            ),
                                                    ),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .flex_wrap()
                                            .gap_2()
                                            .child(
                                                crate::buttons::button(
                                                    "config-generator-visual-apply",
                                                )
                                                .label("更新本地所选")
                                                .small()
                                                .primary()
                                                .disabled(
                                                    busy || !selected_local_draft_mutable,
                                                )
                                                .on_click(cx.listener(|page, _, window, cx| {
                                                    page.update_selected_visual_node(window, cx)
                                                })),
                                            )
                                            .child(
                                                crate::buttons::button(
                                                    "config-generator-visual-move-up",
                                                )
                                                .label("同级上移")
                                                .small()
                                                .disabled(
                                                    busy || !selected_local_draft_mutable,
                                                )
                                                .on_click(cx.listener(|page, _, window, cx| {
                                                    page.move_selected_visual_node(false, window, cx)
                                                })),
                                            )
                                            .child(
                                                crate::buttons::button(
                                                    "config-generator-visual-move-down",
                                                )
                                                .label("同级下移")
                                                .small()
                                                .disabled(
                                                    busy || !selected_local_draft_mutable,
                                                )
                                                .on_click(cx.listener(|page, _, window, cx| {
                                                    page.move_selected_visual_node(true, window, cx)
                                                })),
                                            )
                                            .child(
                                                crate::buttons::button(
                                                    "config-generator-visual-delete",
                                                )
                                                .label("删除节点/子树")
                                                .small()
                                                .danger()
                                                .disabled(
                                                    busy || !selected_local_draft_mutable,
                                                )
                                                .on_click(cx.listener(|page, _, window, cx| {
                                                    page.remove_selected_visual_node(window, cx)
                                                })),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .flex_wrap()
                                            .gap_2()
                                            .child(
                                                crate::buttons::button(
                                                    "config-generator-add-root-directive",
                                                )
                                                .label(format!(
                                                    "根{}",
                                                    document_kind.statement_label()
                                                ))
                                                .small()
                                                .disabled(
                                                    busy
                                                        || !structured
                                                        || !allows_lossless_local_draft
                                                        || schema_catalog_selected,
                                                )
                                                .on_click(cx.listener(|page, _, window, cx| {
                                                    page.add_visual_node(
                                                        VisualNodeKind::Statement,
                                                        false,
                                                        window,
                                                        cx,
                                                    )
                                                })),
                                            )
                                            .child(
                                                crate::buttons::button(
                                                    "config-generator-add-root-block",
                                                )
                                                .label(format!("根{}", document_kind.container_label()))
                                                .small()
                                                .disabled(
                                                    busy
                                                        || !structured
                                                        || !allows_lossless_local_draft
                                                        || !supports_containers
                                                        || schema_catalog_selected,
                                                )
                                                .on_click(cx.listener(|page, _, window, cx| {
                                                    page.add_visual_node(
                                                        VisualNodeKind::Container,
                                                        false,
                                                        window,
                                                        cx,
                                                    )
                                                })),
                                            )
                                            .child(
                                                crate::buttons::button(
                                                    "config-generator-add-root-comment",
                                                )
                                                .label("根注释")
                                                .small()
                                                .disabled(
                                                    busy
                                                        || !structured
                                                        || !allows_lossless_local_draft
                                                        || schema_catalog_selected,
                                                )
                                                .on_click(cx.listener(|page, _, window, cx| {
                                                    page.add_visual_node(
                                                        VisualNodeKind::Comment,
                                                        false,
                                                        window,
                                                        cx,
                                                    )
                                                })),
                                            )
                                            .child(
                                                crate::buttons::button(
                                                    "config-generator-add-child-directive",
                                                )
                                                .label(format!(
                                                    "子{}",
                                                    document_kind.statement_label()
                                                ))
                                                .small()
                                                .disabled(
                                                    busy || !selected_local_draft_container,
                                                )
                                                .on_click(cx.listener(|page, _, window, cx| {
                                                    page.add_visual_node(
                                                        VisualNodeKind::Statement,
                                                        true,
                                                        window,
                                                        cx,
                                                    )
                                                })),
                                            )
                                            .child(
                                                crate::buttons::button(
                                                    "config-generator-add-child-block",
                                                )
                                                .label(format!("子{}", document_kind.container_label()))
                                                .small()
                                                .disabled(
                                                    busy
                                                        || !selected_local_draft_container
                                                        || !supports_nested_containers,
                                                )
                                                .on_click(cx.listener(|page, _, window, cx| {
                                                    page.add_visual_node(
                                                        VisualNodeKind::Container,
                                                        true,
                                                        window,
                                                        cx,
                                                    )
                                                })),
                                            )
                                            .child(
                                                crate::buttons::button(
                                                    "config-generator-add-child-comment",
                                                )
                                                .label("子注释")
                                                .small()
                                                .disabled(
                                                    busy || !selected_local_draft_container,
                                                )
                                                .on_click(cx.listener(|page, _, window, cx| {
                                                    page.add_visual_node(
                                                        VisualNodeKind::Comment,
                                                        true,
                                                        window,
                                                        cx,
                                                    )
                                                })),
                                            ),
                                    ),
                            )
                            .child(
                                div()
                                    .debug_selector(|| {
                                        "config-generator-full-preview".to_owned()
                                    })
                                    .flex_1()
                                    .min_h(px(VISUAL_WORKSPACE_LAYOUT.preview_min_height))
                                    .rounded_lg()
                                    .border_1()
                                    .border_color(tokens.border)
                                    .bg(tokens.surface)
                                    .p_3()
                                    .flex()
                                    .flex_col()
                                    .gap_2()
                                    .child(section_label("完整配置预览", tokens))
                                    .child(visual_config_preview(
                                        &self.model.visual_document,
                                        contains_sensitive_values,
                                        tokens,
                                    )),
                            ),
                    ),
            )
            .into_any_element()
    }
}

impl Render for ConfigGeneratorPage {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        if self.visual_editor_reset_pending {
            self.visual_editor_reset_pending = false;
            self.reset_visual_editor(window, cx);
        }
        let tokens = self.shared.read(cx).theme.tokens();
        let error = self.error.clone();
        let notice = self.notice.clone();
        let mode = self.model.mode;
        let workspace = match mode {
            ConfigGeneratorMode::Quick => self.render_quick_workspace(tokens, cx),
            ConfigGeneratorMode::Visual => self.render_visual_workspace(tokens, cx),
        };

        let page_content = div()
            .id("config-generator-page-scroll")
            .size_full()
            .overflow_y_scroll()
            .track_scroll(&self.page_scroll)
            .flex()
            .flex_col()
            .gap_4()
            .child(
                div()
                    .flex_none()
                    .flex()
                    .items_end()
                    .gap_4()
                    .child(
                        div()
                            .flex_1()
                            .child(div().text_2xl().mb_2().child("配置生成与本地无损草稿"))
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(tokens.muted)
                                    .child("Nginx 按目标生成与多产品通用语法树只用于本地无损草稿、预览、复制、导入或另存；未经过目标校验，不能应用/部署。"),
                            ),
                    )
                    .child(
                        div().flex().gap_2().children(
                            [ConfigGeneratorMode::Quick, ConfigGeneratorMode::Visual]
                                .into_iter()
                                .map(|option| {
                                    crate::buttons::button(SharedString::from(format!(
                                        "config-generator-mode-{option:?}"
                                    )))
                                    .label(option.label())
                                    .small()
                                    .selected(mode == option)
                                    .on_click(cx.listener(move |page, _, _, cx| {
                                        page.select_mode(option, cx)
                                    }))
                                }),
                        ),
                    ),
            )
            .when_some(error, |page, message| {
                page.child(message_banner(message, true, tokens))
            })
            .when_some(notice, |page, message| {
                page.child(message_banner(message, false, tokens))
            })
            .child(workspace);

        div()
            .id("config-generator-page")
            .relative()
            .size_full()
            .min_h_0()
            .child(page_content)
            .vertical_scrollbar(&self.page_scroll)
    }
}

fn generate_from_values(
    kind: NginxSiteKind,
    server_name: &str,
    listen_port: &str,
    static_root: &str,
    upstream: &str,
    security_headers: bool,
) -> CoreResult<GeneratedNginxConfig> {
    generate_from_values_with_forbidden_path(
        kind,
        server_name,
        listen_port,
        static_root,
        upstream,
        security_headers,
        None,
    )
}

fn generate_from_values_with_forbidden_path(
    kind: NginxSiteKind,
    server_name: &str,
    listen_port: &str,
    static_root: &str,
    upstream: &str,
    security_headers: bool,
    forbidden_path: Option<(&str, NginxForbiddenPathScope)>,
) -> CoreResult<GeneratedNginxConfig> {
    let names = NginxServerNames::parse(server_name)?;
    let port = NginxListenPort::parse(listen_port)?;
    let target = match kind {
        NginxSiteKind::Static => NginxSiteTarget::Static(NginxStaticRoot::parse(static_root)?),
        NginxSiteKind::ReverseProxy => {
            NginxSiteTarget::ReverseProxy(NginxUpstream::parse(upstream)?)
        }
    };
    let mut config = NginxSiteConfig::new(names, port, target, security_headers)?;
    if let Some((path, scope)) = forbidden_path {
        config = config.with_forbidden_path_rule(NginxForbiddenPathRule::new(
            NginxForbiddenPath::parse(path)?,
            scope,
        )?)?;
    }
    config.generate()
}

fn input_field(
    label: &'static str,
    help: &'static str,
    input: &Entity<InputState>,
    tokens: ThemeTokens,
) -> AnyElement {
    div()
        .child(section_label(label, tokens))
        .child(div().mt_2().child(Input::new(input).small()))
        .child(div().mt_1().text_xs().text_color(tokens.muted).child(help))
        .into_any_element()
}

fn section_label(label: &'static str, tokens: ThemeTokens) -> AnyElement {
    div()
        .text_sm()
        .font_weight(gpui::FontWeight::SEMIBOLD)
        .text_color(tokens.text)
        .child(label)
        .into_any_element()
}

fn message_banner(message: SharedString, is_error: bool, tokens: ThemeTokens) -> AnyElement {
    let color = if is_error {
        tokens.danger
    } else {
        tokens.success
    };
    div()
        .flex_none()
        .rounded_md()
        .border_1()
        .border_color(color)
        .p_3()
        .text_sm()
        .text_color(color)
        .child(message)
        .into_any_element()
}

const MINIMUM_PREVIEW_TEXT_CONTRAST: f32 = 4.5;

#[derive(Clone, Copy, Debug)]
struct ConfigPreviewColors {
    background: gpui::Rgba,
    code_text: gpui::Rgba,
}

impl ConfigPreviewColors {
    fn from_tokens(tokens: ThemeTokens) -> Self {
        let code_text =
            higher_contrast_color(tokens.text, tokens.surface, tokens.terminal_background);
        debug_assert!(
            contrast_ratio(code_text, tokens.terminal_background) >= MINIMUM_PREVIEW_TEXT_CONTRAST
        );
        Self {
            background: tokens.terminal_background,
            code_text,
        }
    }
}

fn higher_contrast_color(
    first: gpui::Rgba,
    second: gpui::Rgba,
    background: gpui::Rgba,
) -> gpui::Rgba {
    if contrast_ratio(first, background) >= contrast_ratio(second, background) {
        first
    } else {
        second
    }
}

fn contrast_ratio(first: gpui::Rgba, second: gpui::Rgba) -> f32 {
    let first = relative_luminance(first);
    let second = relative_luminance(second);
    (first.max(second) + 0.05) / (first.min(second) + 0.05)
}

fn relative_luminance(color: gpui::Rgba) -> f32 {
    fn linearize(channel: f32) -> f32 {
        if channel <= 0.04045 {
            channel / 12.92
        } else {
            ((channel + 0.055) / 1.055).powf(2.4)
        }
    }

    0.2126 * linearize(color.r) + 0.7152 * linearize(color.g) + 0.0722 * linearize(color.b)
}

fn config_preview(config: Option<&GeneratedNginxConfig>, tokens: ThemeTokens) -> AnyElement {
    let colors = ConfigPreviewColors::from_tokens(tokens);
    let Some(config) = config else {
        return div()
            .flex_1()
            .min_h_0()
            .rounded_md()
            .bg(colors.background)
            .flex()
            .items_center()
            .justify_center()
            .text_sm()
            .text_color(colors.code_text)
            .child("修正左侧参数后会自动生成预览")
            .into_any_element();
    };
    let (lines, truncated) = bounded_preview_lines(config.contents());
    div()
        .flex_1()
        .min_h_0()
        .overflow_scrollbar()
        .rounded_md()
        .bg(colors.background)
        .p_3()
        .font_family("Cascadia Mono")
        .text_xs()
        .text_color(colors.code_text)
        .children(lines.into_iter().map(|line| {
            div().child(if line.is_empty() {
                " ".to_owned()
            } else {
                line
            })
        }))
        .when(truncated, |preview| {
            preview.child(
                div()
                    .mt_2()
                    .text_color(tokens.warning)
                    .child("预览已截断；复制和保存仍使用完整配置。"),
            )
        })
        .into_any_element()
}

fn visual_config_preview(
    document: &VisualDocument,
    contains_sensitive_values: bool,
    tokens: ThemeTokens,
) -> AnyElement {
    let colors = ConfigPreviewColors::from_tokens(tokens);
    if contains_sensitive_values {
        return div()
            .flex_1()
            .min_h_0()
            .rounded_md()
            .bg(colors.background)
            .flex()
            .items_center()
            .justify_center()
            .p_4()
            .text_sm()
            .text_color(tokens.warning)
            .child("检测到敏感内容，完整预览已隐藏；另存本地草稿会保留原始字节，不能应用/部署。")
            .into_any_element();
    }
    let text = String::from_utf8_lossy(document.raw_bytes());
    let (lines, truncated) = bounded_preview_lines(text.as_ref());
    div()
        .flex_1()
        .min_h_0()
        .overflow_scrollbar()
        .rounded_md()
        .bg(colors.background)
        .p_3()
        .font_family("Cascadia Mono")
        .text_xs()
        .text_color(colors.code_text)
        .children(lines.into_iter().map(|line| {
            div().child(if line.is_empty() {
                " ".to_owned()
            } else {
                line
            })
        }))
        .when(truncated, |preview| {
            preview.child(
                div()
                    .mt_2()
                    .text_color(tokens.warning)
                    .child("预览已截断；复制和保存仍使用完整配置。"),
            )
        })
        .into_any_element()
}

fn bounded_preview_lines(text: &str) -> (Vec<String>, bool) {
    let mut lines = Vec::new();
    let mut chars = 0usize;
    let mut truncated = false;
    for line in text.lines() {
        let remaining = MAX_PREVIEW_CHARS.saturating_sub(chars);
        if lines.len() == MAX_PREVIEW_LINES || remaining == 0 {
            truncated = true;
            break;
        }
        let mut characters = line.chars();
        let bounded = characters.by_ref().take(remaining).collect::<String>();
        chars += bounded.chars().count();
        if characters.next().is_some() {
            truncated = true;
        }
        lines.push(bounded);
        if truncated {
            break;
        }
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    (lines, truncated)
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, fs};

    use super::*;
    use gpui::{ScrollDelta, ScrollWheelEvent, TestAppContext, point, size};
    use lovelyres_core::{
        PortableStore,
        database_config::{DatabaseConfigComponent, DatabaseConfigSupportLevel},
        database_config_schema::{
            DatabaseConfigDocumentedDefault, DatabaseConfigSchemaBinding,
            DatabaseConfigSchemaLookupError, DatabaseConfigSchemaReference,
            DatabaseConfigSchemaTarget, DatabaseConfigSchemaValueKind,
            DatabaseConfigTextNormalization, DatabaseConfigVersion, DatabaseConfigVersionSelector,
            registered_database_config_schema_catalog,
        },
    };
    use uuid::Uuid;

    fn app_shell_scroll_mount(page: Entity<ConfigGeneratorPage>) -> AnyElement {
        div()
            .size_full()
            .min_h_0()
            .flex()
            .flex_col()
            .child(crate::app::scroll_managed_workspace(
                crate::app::constrained_workspace_page(page),
            ))
            .into_any_element()
    }

    const TEST_SCHEMA_REFERENCES: &[DatabaseConfigSchemaReference] =
        &[DatabaseConfigSchemaReference {
            id: "test:config-generator-schema",
            title: "Config generator test-only schema reference",
            url: "https://example.invalid/lovelyres/config-generator-schema",
        }];

    #[test]
    fn database_bundle_parameter_labels_disambiguate_every_mariadb_container() {
        let schemas = DATABASE_CONFIG_SCHEMAS
            .iter()
            .filter(|schema| schema.binding.product == DatabaseConfigProduct::MariaDb)
            .collect::<Vec<_>>();
        assert_eq!(schemas.len(), 2);

        for schema in schemas {
            let labels = schema
                .parameters
                .iter()
                .filter(|parameter| parameter.canonical_key == "wait_timeout")
                .map(database_goal_parameter_label)
                .collect::<HashSet<_>>();
            assert_eq!(labels.len(), 9, "{}", schema.version_label);
            assert!(labels.iter().all(|label| label.ends_with("· wait_timeout")));
            assert!(!labels.contains("根级配置 · wait_timeout"));
        }
    }

    const TEST_MYSQL_PARAMETERS: &[DatabaseConfigParameterSchema] = &[
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

    const TEST_POSTGRESQL_SCHEMA: DatabaseConfigSchema = DatabaseConfigSchema {
        display_label: "Test PostgreSQL schema",
        version_label: "17 test fixture",
        binding: DatabaseConfigSchemaBinding {
            product: DatabaseConfigProduct::PostgreSql,
            versions: DatabaseConfigVersionSelector::Exact(DatabaseConfigVersion::new(17, 0, 0)),
            edition_key: None,
            component: DatabaseConfigComponent::Server,
            artifact_key: "postgresql-main",
        },
        ..TEST_MYSQL_SCHEMA
    };

    const TEST_SCHEMA_REGISTRY: &[DatabaseConfigSchema] =
        &[TEST_MYSQL_SCHEMA, TEST_POSTGRESQL_SCHEMA];

    const TEST_DEFAULT_ONLY_PARAMETERS: &[DatabaseConfigParameterSchema] =
        &[DatabaseConfigParameterSchema {
            documented_default: Some(DatabaseConfigDocumentedDefault::Text(
                "default-only-search-sentinel",
            )),
            ..TEST_MYSQL_PARAMETERS[1]
        }];

    const TEST_DEFAULT_ONLY_SCHEMA: DatabaseConfigSchema = DatabaseConfigSchema {
        parameters: TEST_DEFAULT_ONLY_PARAMETERS,
        ..TEST_MYSQL_SCHEMA
    };

    const TEST_READ_ONLY_SCHEMAS: &[DatabaseConfigSchema] = &[
        DatabaseConfigSchema {
            display_label: "Test vendor-schema artifact",
            binding: DatabaseConfigSchemaBinding {
                product: DatabaseConfigProduct::OpenGauss,
                versions: DatabaseConfigVersionSelector::Exact(DatabaseConfigVersion::new(6, 0, 0)),
                edition_key: Some("test.standard"),
                component: DatabaseConfigComponent::Deployment,
                artifact_key: "opengauss-om-cluster-xml",
            },
            completeness: DatabaseConfigSchemaCompleteness::Partial,
            ..TEST_MYSQL_SCHEMA
        },
        DatabaseConfigSchema {
            display_label: "Test generated artifact",
            binding: DatabaseConfigSchemaBinding {
                product: DatabaseConfigProduct::MySql,
                versions: DatabaseConfigVersionSelector::Exact(DatabaseConfigVersion::new(8, 0, 0)),
                edition_key: None,
                component: DatabaseConfigComponent::Persistence,
                artifact_key: "mysql-persisted-variables",
            },
            completeness: DatabaseConfigSchemaCompleteness::Complete,
            ..TEST_MYSQL_SCHEMA
        },
    ];

    fn database_artifact(key: &str) -> &'static DatabaseConfigArtifactDefinition {
        lovelyres_core::database_config::DATABASE_CONFIG_ARTIFACTS
            .iter()
            .find(|artifact| artifact.key == key)
            .unwrap_or_else(|| panic!("missing database configuration artifact {key}"))
    }

    fn model_with_visual_document(document: VisualDocument) -> ConfigGeneratorModel {
        let generated = generate_from_values(
            NginxSiteKind::ReverseProxy,
            DEFAULT_SERVER_NAME,
            DEFAULT_LISTEN_PORT,
            DEFAULT_STATIC_ROOT,
            DEFAULT_UPSTREAM,
            true,
        )
        .unwrap();
        let mut model = ConfigGeneratorModel::new(generated);
        model.replace_visual_document(document);
        model
    }

    fn visual_selector_contains(artifact: &DatabaseConfigArtifactDefinition) -> bool {
        artifacts_for(artifact.product)
            .filter(|candidate| database_visual_parser(candidate).is_some())
            .any(|candidate| candidate.key == artifact.key)
    }

    fn assert_local_draft_mutation_denied<T>(result: CoreResult<T>, key: &str) {
        let error = match result {
            Ok(_) => panic!("read-only artifact {key} accepted a local draft mutation"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("local draft mutation"),
            "unexpected {key} mutation error: {error}"
        );
    }

    fn filtered_row_names<'a>(rows: &'a [VisualRow], indices: &[usize]) -> Vec<&'a str> {
        indices
            .iter()
            .filter_map(|index| rows.get(*index).and_then(VisualRow::name))
            .collect()
    }

    #[test]
    fn visual_workspace_layout_keeps_small_windows_scrollable_and_panels_bounded() {
        let layout = VISUAL_WORKSPACE_LAYOUT;
        assert!(layout.split_min_height > 480.0);
        assert!(
            layout.editor_max_height + layout.preview_min_height + 24.0 <= layout.split_min_height
        );
        assert!(layout.node_row_height >= 56.0);

        let long_text = "可读摘要".repeat(80);
        let label = bounded_visual_row_text(&long_text, MAX_VISUAL_ROW_LABEL_CHARS);
        let preview = bounded_visual_row_text(&long_text, MAX_VISUAL_ROW_PREVIEW_CHARS);
        assert_eq!(label.chars().count(), MAX_VISUAL_ROW_LABEL_CHARS + 1);
        assert_eq!(preview.chars().count(), MAX_VISUAL_ROW_PREVIEW_CHARS + 1);
        assert!(label.ends_with('…'));
        assert!(preview.ends_with('…'));
    }

    #[gpui::test]
    fn short_viewport_scrolls_page_from_header_to_full_preview(cx: &mut TestAppContext) {
        let root = std::env::temp_dir().join(format!(
            "lovelyres-config-generator-scroll-{}",
            Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let services =
            Arc::new(BackendServices::new(PortableStore::prepare(root.clone()).unwrap()).unwrap());
        let tokio = TokioBridge::new().unwrap();

        cx.update(gpui_component::init);
        let cx = cx.add_empty_window();
        let page = cx.update(|window, cx| {
            let shared = cx.new(|_| SharedAppState::default());
            cx.new(|cx| {
                let mut page = ConfigGeneratorPage::new(services, tokio, shared, window, cx);
                page.model.mode = ConfigGeneratorMode::Visual;
                page
            })
        });

        let short_viewport = size(px(1_200.0), px(420.0));
        cx.draw(point(px(0.0), px(0.0)), short_viewport, |_, _| {
            app_shell_scroll_mount(page.clone())
        });
        let page_scroll = page.update(cx, |page, _| page.page_scroll.clone());
        assert!(
            page_scroll.max_offset().height > px(0.0),
            "the complete visual workspace must overflow the real app-shell mount"
        );
        let initial_preview = cx
            .debug_bounds("config-generator-full-preview")
            .expect("full preview bounds after initial draw");
        assert!(
            initial_preview.origin.y >= short_viewport.height,
            "the short viewport must require page scrolling to reach the full preview"
        );

        cx.simulate_event(ScrollWheelEvent {
            position: point(px(1_100.0), px(24.0)),
            delta: ScrollDelta::Pixels(point(px(0.0), px(-5_000.0))),
            ..Default::default()
        });
        cx.draw(point(px(0.0), px(0.0)), short_viewport, |_, _| {
            app_shell_scroll_mount(page.clone())
        });
        assert_eq!(
            page_scroll.offset().y,
            -page_scroll.max_offset().height,
            "a wheel gesture on the fixed page header must reach the page bottom"
        );
        let preview = cx
            .debug_bounds("config-generator-full-preview")
            .expect("full preview bounds after bottom scroll");
        let preview_bottom = preview.origin.y + preview.size.height;
        assert!(
            preview.origin.y < short_viewport.height && preview_bottom > px(0.0),
            "the complete preview must intersect the viewport at the page bottom"
        );
        assert!(
            preview_bottom <= short_viewport.height,
            "the complete preview bottom must be reachable, got {preview_bottom:?}"
        );

        let _ = fs::remove_dir_all(root);
    }

    #[gpui::test]
    fn nginx_403_goal_is_discoverable_and_drives_the_typed_preview(cx: &mut TestAppContext) {
        let root = std::env::temp_dir().join(format!(
            "lovelyres-config-generator-goal-{}",
            Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let services =
            Arc::new(BackendServices::new(PortableStore::prepare(root.clone()).unwrap()).unwrap());
        let tokio = TokioBridge::new().unwrap();

        cx.update(gpui_component::init);
        let cx = cx.add_empty_window();
        let page = cx.update(|window, cx| {
            let shared = cx.new(|_| SharedAppState::default());
            cx.new(|cx| ConfigGeneratorPage::new(services, tokio, shared, window, cx))
        });
        let viewport = size(px(1_200.0), px(900.0));
        cx.draw(point(px(0.0), px(0.0)), viewport, |_, _| {
            app_shell_scroll_mount(page.clone())
        });
        assert!(
            cx.debug_bounds("config-generator-nginx-forbidden-goal")
                .is_some(),
            "the reviewed 403 goal must be visible in goal mode without knowing directive names"
        );
        assert!(
            cx.debug_bounds("config-generator-simple-goal-results")
                .is_some(),
            "the reviewed static-site and reverse-proxy goals must share the goal catalog"
        );

        cx.update(|window, cx| {
            page.update(cx, |page, cx| {
                page.start_curated_configuration_goal(
                    ConfigurationGoalRecipeAction::NginxStaticSite,
                    "",
                    window,
                    cx,
                );
                assert_eq!(page.model.kind, NginxSiteKind::Static);
                assert!(
                    page.model
                        .generated
                        .as_ref()
                        .unwrap()
                        .contents()
                        .contains("root \"/var/www/html\";")
                );
                page.start_curated_configuration_goal(
                    ConfigurationGoalRecipeAction::NginxReverseProxy,
                    "",
                    window,
                    cx,
                );
                assert_eq!(page.model.kind, NginxSiteKind::ReverseProxy);
                assert!(
                    page.model
                        .generated
                        .as_ref()
                        .unwrap()
                        .contents()
                        .contains("proxy_pass http://127.0.0.1:3000;")
                );
            });
        });

        cx.update(|window, cx| {
            page.update(cx, |page, cx| {
                page.start_forbidden_path_goal("让 /admin 从外部访问全部返回 403", window, cx);
            });
        });
        let generated = page.update(cx, |page, _| {
            page.model.generated.as_ref().unwrap().contents().to_owned()
        });
        assert!(generated.contains("location = /admin"));
        assert!(generated.contains("location ^~ /admin/"));

        cx.update(|window, cx| {
            page.update(cx, |page, cx| {
                page.load_quick_into_visual(window, cx);
                assert_eq!(page.model.mode, ConfigGeneratorMode::Visual);
                assert!(!page.model.visual_dirty);
                assert_eq!(page.model.visual_document.raw_bytes(), generated.as_bytes());

                let locations = page
                    .model
                    .visual_rows
                    .iter()
                    .filter(|row| row.name() == Some("location"))
                    .filter(|row| matches!(row.arguments(), Some("= /admin" | "^~ /admin/")))
                    .collect::<Vec<_>>();
                assert_eq!(locations.len(), 2);
                for location in locations {
                    assert!(page.model.visual_rows.iter().any(|row| {
                        row.parent == Some(location.id())
                            && row.name() == Some("return")
                            && row.arguments() == Some("403")
                    }));
                }

                page.visual_search_input.update(cx, |input, cx| {
                    input.set_value("/admin 外部访问返回 403", window, cx)
                });
                cx.notify();
            });
        });
        cx.draw(point(px(0.0), px(0.0)), viewport, |_, _| {
            app_shell_scroll_mount(page.clone())
        });
        assert!(
            cx.debug_bounds("config-generator-visual-forbidden-goal-result")
                .is_some(),
            "the existing document search must surface the matching goal recipe"
        );

        cx.update(|window, cx| {
            page.update(cx, |page, cx| {
                page.start_curated_configuration_goal(
                    ConfigurationGoalRecipeAction::ApacheForbiddenPath403,
                    "Apache block /admin.v1 with 403",
                    window,
                    cx,
                );
                assert_eq!(page.model.mode, ConfigGeneratorMode::Visual);
                assert!(!page.model.visual_dirty);
                assert_eq!(
                    page.model.visual_document.raw_bytes(),
                    b"<LocationMatch \"^/admin\\.v1(?:/.*)?$\">\n    Require all denied\n</LocationMatch>\n"
                );
                assert!(matches!(
                    page.model.visual_document,
                    VisualDocument::Apache(_)
                ));
                let location = page
                    .model
                    .visual_rows
                    .iter()
                    .find(|row| row.name() == Some("LocationMatch"))
                    .expect("generated LocationMatch row");
                assert!(page.model.visual_rows.iter().any(|row| {
                    row.parent == Some(location.id())
                        && row.name() == Some("Require")
                        && row.arguments() == Some("all denied")
                }));

                page.start_curated_configuration_goal(
                    ConfigurationGoalRecipeAction::ApacheDisableTrace,
                    "Apache 禁用 TRACE；Header set X-Evil yes",
                    window,
                    cx,
                );
                assert_eq!(page.model.visual_document.raw_bytes(), b"TraceEnable Off\n");
                assert!(page
                    .notice
                    .as_deref()
                    .is_some_and(|notice| notice.contains("405") && notice.contains("不是 403")));

                page.start_curated_configuration_goal(
                    ConfigurationGoalRecipeAction::ApacheReduceVersionDisclosure,
                    "Apache 隐藏版本号",
                    window,
                    cx,
                );
                assert_eq!(
                    page.model.visual_document.raw_bytes(),
                    b"ServerTokens Prod\nServerSignature Off\n"
                );
                assert!(page.notice.as_deref().is_some_and(|notice| {
                    notice.contains("仍会标识 Apache") && notice.contains("不是独立安全控制")
                }));
            });
        });

        let _ = fs::remove_dir_all(root);
    }

    #[gpui::test]
    fn unified_goal_search_opens_database_guidance_and_explains_unavailable_products(
        cx: &mut TestAppContext,
    ) {
        let root = std::env::temp_dir().join(format!(
            "lovelyres-config-generator-unified-goals-{}",
            Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let services =
            Arc::new(BackendServices::new(PortableStore::prepare(root.clone()).unwrap()).unwrap());
        let tokio = TokioBridge::new().unwrap();
        let schema = DATABASE_CONFIG_SCHEMAS
            .iter()
            .find(|schema| schema.binding.product == DatabaseConfigProduct::PostgreSql)
            .expect("PostgreSQL goal fixture schema");
        let parameter_index = schema
            .parameters
            .iter()
            .position(|parameter| parameter.canonical_key == "max_connections")
            .expect("PostgreSQL max_connections goal fixture");

        cx.update(gpui_component::init);
        let cx = cx.add_empty_window();
        let page = cx.update(|window, cx| {
            let shared = cx.new(|_| SharedAppState::default());
            cx.new(|cx| ConfigGeneratorPage::new(services, tokio, shared, window, cx))
        });
        let viewport = size(px(1_200.0), px(900.0));
        cx.update(|window, cx| {
            page.update(cx, |page, cx| {
                page.nginx_goal_search_input.update(cx, |input, cx| {
                    input.set_value("PostgreSQL 允许数据库远程连接", window, cx)
                });
            });
        });
        cx.draw(point(px(0.0), px(0.0)), viewport, |_, _| {
            app_shell_scroll_mount(page.clone())
        });
        assert!(
            cx.debug_bounds("config-generator-database-bundle-goal-results")
                .is_some(),
            "multi-step goals must expose reviewed parameters and missing required steps"
        );

        cx.update(|window, cx| {
            page.update(cx, |page, cx| {
                page.nginx_goal_search_input.update(cx, |input, cx| {
                    input.set_value("PostgreSQL 提高最大连接数", window, cx)
                });
            });
        });
        cx.draw(point(px(0.0), px(0.0)), viewport, |_, _| {
            app_shell_scroll_mount(page.clone())
        });
        assert!(
            cx.debug_bounds("config-generator-database-goal-results")
                .is_some(),
            "reviewed database parameters must be discoverable from the shared goal search"
        );

        cx.update(|window, cx| {
            page.update(cx, |page, cx| {
                page.open_database_parameter_goal(schema, parameter_index, window, cx);
                assert_eq!(page.model.mode, ConfigGeneratorMode::Visual);
                assert!(!page.model.visual_dirty);
                assert!(
                    page.model
                        .current_database_schema()
                        .is_some_and(|current| std::ptr::eq(current, schema))
                );
                assert_eq!(page.model.selected_schema_parameter, Some(parameter_index));
                assert_eq!(
                    page.visual_search_input.read(cx).value().as_ref(),
                    "max_connections"
                );
                assert!(
                    page.notice
                        .as_deref()
                        .is_some_and(|notice| notice.contains("CatalogGuidance"))
                );

                page.database_goal_value_input
                    .update(cx, |input, cx| input.set_value("250", window, cx));
                page.apply_selected_database_parameter_goal(window, cx);
                assert!(page.model.visual_dirty);
                assert_eq!(page.model.selected_schema_parameter, Some(parameter_index));
                let output = page.model.visual_document.output();
                assert!(output.text().unwrap().contains("max_connections = 250"));
                assert!(page.error.is_none());
                assert!(
                    page.notice
                        .as_deref()
                        .is_some_and(|notice| notice.contains("SyntaxValid"))
                );

                page.database_goal_value_input
                    .update(cx, |input, cx| input.set_value("300", window, cx));
                page.apply_selected_database_parameter_goal(window, cx);
                let text = page
                    .model
                    .visual_document
                    .output()
                    .text()
                    .unwrap()
                    .to_owned();
                assert!(text.contains("max_connections = 300"));
                assert!(!text.contains("max_connections = 250"));
                assert_eq!(text.matches("max_connections").count(), 1);

                page.model.mode = ConfigGeneratorMode::Quick;
                page.model.visual_dirty = false;
                page.nginx_goal_search_input
                    .update(cx, |input, cx| input.set_value("MogDB", window, cx));
                cx.notify();
            });
        });
        cx.draw(point(px(0.0), px(0.0)), viewport, |_, _| {
            app_shell_scroll_mount(page.clone())
        });
        assert!(
            cx.debug_bounds("config-generator-database-artifact-results")
                .is_some(),
            "catalogued configuration artifacts must be discoverable by product"
        );

        cx.update(|window, cx| {
            page.update(cx, |page, cx| {
                let mogdb = artifacts_for(DatabaseConfigProduct::MogDb)
                    .find(|artifact| database_visual_parser(artifact).is_some())
                    .expect("MogDB visual artifact fixture");
                page.select_database_artifact(mogdb, window, cx);
                assert_eq!(
                    page.model.visual_document.kind(),
                    VisualDocumentKind::Database(mogdb)
                );
                assert!(!page.model.visual_dirty);

                page.model.visual_dirty = true;
                let postgres = artifacts_for(DatabaseConfigProduct::PostgreSql)
                    .find(|artifact| database_visual_parser(artifact).is_some())
                    .expect("PostgreSQL visual artifact fixture");
                page.select_database_artifact(postgres, window, cx);
                assert_eq!(
                    page.model.visual_document.kind(),
                    VisualDocumentKind::Database(mogdb),
                    "a dirty draft must not be replaced by an artifact search result"
                );

                page.model.visual_dirty = false;
                page.model.mode = ConfigGeneratorMode::Quick;
                page.nginx_goal_search_input.update(cx, |input, cx| {
                    input.set_value("shentong-native", window, cx)
                });
                cx.notify();
            });
        });
        cx.draw(point(px(0.0), px(0.0)), viewport, |_, _| {
            app_shell_scroll_mount(page.clone())
        });
        assert!(
            cx.debug_bounds("config-generator-unavailable-goal-results")
                .is_some(),
            "a product without any artifact must retain an explicit typed gap"
        );

        for query in ["Apache TLS", "PostgreSQL 15 max_connections"] {
            cx.update(|window, cx| {
                page.update(cx, |page, cx| {
                    page.nginx_goal_search_input
                        .update(cx, |input, cx| input.set_value(query, window, cx));
                    cx.notify();
                });
            });
            cx.draw(point(px(0.0), px(0.0)), viewport, |_, _| {
                app_shell_scroll_mount(page.clone())
            });
            assert!(
                cx.debug_bounds("config-generator-unavailable-goal-results")
                    .is_some(),
                "{query:?} must render its typed gap instead of a wrong recipe or an empty panel"
            );
        }

        let _ = fs::remove_dir_all(root);
    }

    #[gpui::test]
    fn database_assignment_previews_then_atomically_confirms_a_typed_local_draft(
        cx: &mut TestAppContext,
    ) {
        let root = std::env::temp_dir().join(format!(
            "lovelyres-config-generator-assignment-ready-{}",
            Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let services =
            Arc::new(BackendServices::new(PortableStore::prepare(root.clone()).unwrap()).unwrap());
        let tokio = TokioBridge::new().unwrap();
        let schema = DATABASE_CONFIG_SCHEMAS
            .iter()
            .find(|schema| {
                schema.binding.product == DatabaseConfigProduct::PostgreSql
                    && schema.version_label.contains("16")
                    && schema
                        .parameters
                        .iter()
                        .any(|parameter| parameter.canonical_key == "max_connections")
            })
            .expect("PostgreSQL 16 assignment fixture");

        cx.update(gpui_component::init);
        let cx = cx.add_empty_window();
        let page = cx.update(|window, cx| {
            let shared = cx.new(|_| SharedAppState::default());
            cx.new(|cx| ConfigGeneratorPage::new(services, tokio, shared, window, cx))
        });
        let (original_kind, original_bytes) = cx.update(|_, cx| {
            let page = page.read(cx);
            (
                page.model.visual_document.kind(),
                page.model.visual_document.raw_bytes().to_vec(),
            )
        });
        cx.update(|window, cx| {
            page.update(cx, |page, cx| {
                page.model.activate();
                let query = format!(
                    "PostgreSQL 16 @{} max_connections = 250",
                    schema.binding.artifact_key
                );
                page.nginx_goal_search_input
                    .update(cx, |input, cx| input.set_value(query, window, cx));
            });
        });
        cx.update(|window, cx| {
            page.update(cx, |page, cx| {
                assert!(matches!(
                    page.pending_database_assignment.state,
                    PendingDatabaseAssignmentState::Ready {
                        value_error: None,
                        ..
                    }
                ));
                assert_eq!(
                    page.database_assignment_value_input
                        .read(cx)
                        .value()
                        .as_ref(),
                    "250"
                );
                assert_eq!(page.model.visual_document.kind(), original_kind);
                assert_eq!(page.model.visual_document.raw_bytes(), original_bytes);
                assert!(!page.model.visual_dirty);

                page.database_assignment_value_input
                    .update(cx, |input, cx| input.set_value("300", window, cx));
            });
        });
        cx.update(|_, cx| {
            page.update(cx, |page, _| {
                let PendingDatabaseAssignmentState::Ready {
                    assignment,
                    value_error,
                } = &page.pending_database_assignment.state
                else {
                    panic!("edited public value must retain the exact Ready target")
                };
                assert_eq!(assignment.draft().normalized_value(), "300");
                assert_eq!(*value_error, None);
                assert_eq!(page.model.visual_document.raw_bytes(), original_bytes);
                assert_eq!(page.model.visual_document.kind(), original_kind);
                assert!(!page.model.visual_dirty);
            });
        });

        let viewport = size(px(1_200.0), px(900.0));
        cx.draw(point(px(0.0), px(0.0)), viewport, |_, _| {
            app_shell_scroll_mount(page.clone())
        });
        assert!(
            cx.debug_bounds("config-generator-database-assignment-ready")
                .is_some(),
            "a resolved assignment must render its exclusive confirmation card"
        );
        assert!(
            cx.debug_bounds("config-generator-database-goal-results")
                .is_none(),
            "a Ready assignment must not enter ordinary fuzzy goal results"
        );
        cx.update(|window, cx| {
            page.update(cx, |page, cx| {
                assert_eq!(page.model.visual_document.kind(), original_kind);
                assert_eq!(page.model.visual_document.raw_bytes(), original_bytes);
                assert!(!page.model.visual_dirty);
                let lease = page.pending_database_assignment.lease;
                page.confirm_database_parameter_assignment(lease, window, cx);
                assert_eq!(page.model.mode, ConfigGeneratorMode::Visual);
                assert!(page.model.visual_dirty);
                assert!(matches!(
                    page.pending_database_assignment.state,
                    PendingDatabaseAssignmentState::Consumed
                ));
                let output = page.model.visual_document.output();
                let text = output.text().unwrap();
                assert_eq!(text.trim(), "max_connections = 300");
                assert!(page.error.is_none());
                assert!(page.notice.as_deref().is_some_and(|notice| {
                    notice.contains("确认写入本地草稿") && notice.contains("SyntaxValid")
                }));
            });
        });

        cx.update(|_, cx| {
            page.update(cx, |page, cx| {
                page.select_mode(ConfigGeneratorMode::Quick, cx)
            });
        });
        cx.draw(point(px(0.0), px(0.0)), viewport, |_, _| {
            app_shell_scroll_mount(page.clone())
        });
        assert!(
            cx.debug_bounds("config-generator-database-assignment-consumed")
                .is_some()
        );
        assert!(
            cx.debug_bounds("config-generator-database-goal-results")
                .is_none(),
            "a consumed assignment must not fall through to fuzzy parameter results"
        );

        let _ = fs::remove_dir_all(root);
    }

    #[gpui::test]
    fn database_assignment_ambiguity_rejection_and_failed_stage_never_mutate_the_document(
        cx: &mut TestAppContext,
    ) {
        let root = std::env::temp_dir().join(format!(
            "lovelyres-config-generator-assignment-fail-closed-{}",
            Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let services =
            Arc::new(BackendServices::new(PortableStore::prepare(root.clone()).unwrap()).unwrap());
        let tokio = TokioBridge::new().unwrap();
        let maria_schema = DATABASE_CONFIG_SCHEMAS
            .iter()
            .find(|schema| {
                schema.binding.product == DatabaseConfigProduct::MariaDb
                    && schema.version_label.contains("11.4")
                    && schema.parameters.iter().any(|parameter| {
                        parameter.canonical_key == "wait_timeout"
                            && parameter.container_path == Some("mysqld")
                    })
            })
            .expect("MariaDB 11.4 assignment fixture");
        let postgres_schema = DATABASE_CONFIG_SCHEMAS
            .iter()
            .find(|schema| {
                schema.binding.product == DatabaseConfigProduct::PostgreSql
                    && schema.version_label.contains("16")
                    && schema
                        .parameters
                        .iter()
                        .any(|parameter| parameter.canonical_key == "max_connections")
            })
            .expect("PostgreSQL 16 duplicate fixture");
        let invalid_value = "NeverEcho_X9NeverEcho_X9NeverEcho_X9";

        cx.update(gpui_component::init);
        let cx = cx.add_empty_window();
        let page = cx.update(|window, cx| {
            let shared = cx.new(|_| SharedAppState::default());
            cx.new(|cx| ConfigGeneratorPage::new(services, tokio, shared, window, cx))
        });
        cx.update(|window, cx| {
            page.update(cx, |page, cx| {
                page.model.activate();
                let query = format!(
                    "MariaDB 11.4 @{} wait_timeout = 60",
                    maria_schema.binding.artifact_key
                );
                page.nginx_goal_search_input
                    .update(cx, |input, cx| input.set_value(query, window, cx));
            });
        });
        let original = cx.update(|_, cx| page.read(cx).model.visual_document.raw_bytes().to_vec());
        cx.update(|window, cx| {
            page.update(cx, |page, cx| {
                let PendingDatabaseAssignmentState::Ambiguous(ambiguity) =
                    &page.pending_database_assignment.state
                else {
                    panic!("unqualified MariaDB option group must stay ambiguous")
                };
                let target = ambiguity
                    .candidates()
                    .iter()
                    .copied()
                    .find(|target| target.parameter().container_path == Some("mysqld"))
                    .expect("mysqld candidate");
                let lease = page.pending_database_assignment.lease;
                page.select_database_assignment_candidate(lease, target, window, cx);
            });
        });
        cx.update(|_, cx| {
            page.update(cx, |page, _| {
                assert!(matches!(
                    page.pending_database_assignment.state,
                    PendingDatabaseAssignmentState::Ready {
                        value_error: None,
                        ..
                    }
                ));
                assert_eq!(page.model.visual_document.raw_bytes(), original);
            });
        });
        cx.update(|window, cx| {
            page.update(cx, |page, cx| {
                let invalid = format!(
                    "PostgreSQL 16 @{} max_connections = {invalid_value}",
                    postgres_schema.binding.artifact_key,
                );
                page.nginx_goal_search_input
                    .update(cx, |input, cx| input.set_value(invalid, window, cx));
            });
        });
        cx.update(|_, cx| {
            page.update(cx, |page, _| {
                assert!(matches!(
                    page.pending_database_assignment.state,
                    PendingDatabaseAssignmentState::Rejected(_)
                ));
                assert_eq!(page.model.visual_document.raw_bytes(), original);
                assert!(
                    page.error
                        .as_deref()
                        .is_none_or(|error| !error.contains(invalid_value))
                );
                assert!(
                    page.notice
                        .as_deref()
                        .is_none_or(|notice| !notice.contains(invalid_value))
                );
            });
        });
        cx.update(|window, cx| {
            page.update(cx, |page, cx| {
                let valid = format!(
                    "PostgreSQL 16 @{} max_connections = 300",
                    postgres_schema.binding.artifact_key
                );
                page.nginx_goal_search_input
                    .update(cx, |input, cx| input.set_value(valid, window, cx));
            });
        });
        let (stale_lease, stale_kind, stale_bytes, stale_dirty) = cx.update(|_, cx| {
            let page = page.read(cx);
            assert!(matches!(
                page.pending_database_assignment.state,
                PendingDatabaseAssignmentState::Ready {
                    value_error: None,
                    ..
                }
            ));
            (
                page.pending_database_assignment.lease,
                page.model.visual_document.kind(),
                page.model.visual_document.raw_bytes().to_vec(),
                page.model.visual_dirty,
            )
        });
        cx.update(|window, cx| {
            page.update(cx, |page, cx| {
                let changed_query = format!(
                    "PostgreSQL 16 @{} max_connections = 301",
                    postgres_schema.binding.artifact_key
                );
                page.nginx_goal_search_input
                    .update(cx, |input, cx| input.set_value(changed_query, window, cx));
            });
        });
        cx.update(|window, cx| {
            page.update(cx, |page, cx| {
                page.confirm_database_parameter_assignment(stale_lease, window, cx);
                assert_eq!(page.model.visual_document.kind(), stale_kind);
                assert_eq!(page.model.visual_document.raw_bytes(), stale_bytes);
                assert_eq!(page.model.visual_dirty, stale_dirty);
            });
        });
        cx.update(|window, cx| {
            page.update(cx, |page, cx| {
                page.model.visual_dirty = true;
                let changed_query = format!(
                    "PostgreSQL 16 @{} max_connections = 302",
                    postgres_schema.binding.artifact_key
                );
                page.nginx_goal_search_input
                    .update(cx, |input, cx| input.set_value(changed_query, window, cx));
            });
        });
        cx.update(|window, cx| {
            page.update(cx, |page, cx| {
                let dirty_kind = page.model.visual_document.kind();
                let dirty_bytes = page.model.visual_document.raw_bytes().to_vec();
                let dirty_lease = page.pending_database_assignment.lease;
                page.confirm_database_parameter_assignment(dirty_lease, window, cx);
                assert_eq!(page.model.visual_document.kind(), dirty_kind);
                assert_eq!(page.model.visual_document.raw_bytes(), dirty_bytes);
                assert!(page.model.visual_dirty);
                assert!(page.error.as_deref().is_some_and(|error| {
                    error.contains("另一工件") && !error.contains("302")
                }));
            });
        });
        cx.update(|window, cx| {
            page.update(cx, |page, cx| {
                let artifact = artifacts_for(DatabaseConfigProduct::PostgreSql)
                    .find(|artifact| artifact.key == postgres_schema.binding.artifact_key)
                    .expect("PostgreSQL assignment artifact");
                let duplicate = VisualDocument::parse_database(
                    artifact,
                    "max_connections = 100\nmax_connections = 200\n",
                )
                .unwrap();
                page.model.replace_visual_document(duplicate);
                page.model.selected_database_schema = Some(postgres_schema);
                page.model.refresh_visual_rows();
                let query = format!(
                    "PostgreSQL 16 @{} max_connections = 300",
                    postgres_schema.binding.artifact_key
                );
                page.nginx_goal_search_input
                    .update(cx, |input, cx| input.set_value(query, window, cx));
            });
        });
        let viewport = size(px(1_200.0), px(900.0));
        cx.draw(point(px(0.0), px(0.0)), viewport, |_, _| {
            app_shell_scroll_mount(page.clone())
        });
        assert!(
            cx.debug_bounds("config-generator-database-assignment-preflight-blocked")
                .is_some(),
            "a duplicate exact parameter must be visibly Blocked before confirmation"
        );
        cx.update(|window, cx| {
            page.update(cx, |page, cx| {
                let duplicate_kind = page.model.visual_document.kind();
                let duplicate_before = page.model.visual_document.raw_bytes().to_vec();
                let lease = page.pending_database_assignment.lease;
                page.confirm_database_parameter_assignment(lease, window, cx);
                assert_eq!(page.model.visual_document.kind(), duplicate_kind);
                assert_eq!(page.model.visual_document.raw_bytes(), duplicate_before);
                assert!(!page.model.visual_dirty);
                assert!(
                    page.error
                        .as_deref()
                        .is_some_and(|error| error.contains("出现多次"))
                );
            });
        });

        cx.update(|window, cx| {
            page.update(cx, |page, cx| {
                page.model.mode = ConfigGeneratorMode::Quick;
                let unsupported = format!(
                    "PostgreSQL 16 @{} max_connections 改成 NeverEcho_X9",
                    postgres_schema.binding.artifact_key
                );
                page.nginx_goal_search_input
                    .update(cx, |input, cx| input.set_value(unsupported, window, cx));
            });
        });
        cx.update(|_, cx| {
            page.update(cx, |page, _| {
                assert!(matches!(
                    page.pending_database_assignment.state,
                    PendingDatabaseAssignmentState::Rejected(
                        DatabaseParameterAssignmentError::UnsupportedOperator
                    )
                ));
            });
        });
        cx.draw(point(px(0.0), px(0.0)), viewport, |_, _| {
            app_shell_scroll_mount(page.clone())
        });
        assert!(
            cx.debug_bounds("config-generator-database-assignment-blocked")
                .is_some()
        );
        assert!(
            cx.debug_bounds("config-generator-database-goal-results")
                .is_none(),
            "recognized rejected assignments must not fall back to fuzzy results"
        );

        let _ = fs::remove_dir_all(root);
    }

    #[gpui::test]
    fn database_assignment_schema_revision_and_dirty_version_mismatch_fail_closed(
        cx: &mut TestAppContext,
    ) {
        let root = std::env::temp_dir().join(format!(
            "lovelyres-config-generator-assignment-schema-lease-{}",
            Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let services =
            Arc::new(BackendServices::new(PortableStore::prepare(root.clone()).unwrap()).unwrap());
        let tokio = TokioBridge::new().unwrap();
        let postgres_16 = DATABASE_CONFIG_SCHEMAS
            .iter()
            .find(|schema| {
                schema.binding.product == DatabaseConfigProduct::PostgreSql
                    && schema.version_label.contains("16")
                    && schema
                        .parameters
                        .iter()
                        .any(|parameter| parameter.canonical_key == "max_connections")
            })
            .expect("PostgreSQL 16 assignment fixture");
        let postgres_17 = DATABASE_CONFIG_SCHEMAS
            .iter()
            .find(|schema| {
                schema.binding.product == DatabaseConfigProduct::PostgreSql
                    && schema.version_label.starts_with(">=17.")
                    && schema.binding.artifact_key == postgres_16.binding.artifact_key
                    && schema.binding.component == postgres_16.binding.component
                    && schema
                        .parameters
                        .iter()
                        .any(|parameter| parameter.canonical_key == "max_connections")
            })
            .expect("PostgreSQL 17 same-artifact fixture");
        let artifact = artifacts_for(DatabaseConfigProduct::PostgreSql)
            .find(|artifact| artifact.key == postgres_16.binding.artifact_key)
            .expect("PostgreSQL assignment artifact");

        cx.update(gpui_component::init);
        let cx = cx.add_empty_window();
        let page = cx.update(|window, cx| {
            let shared = cx.new(|_| SharedAppState::default());
            cx.new(|cx| ConfigGeneratorPage::new(services, tokio, shared, window, cx))
        });
        cx.update(|window, cx| {
            page.update(cx, |page, cx| {
                page.model.activate();
                page.model.replace_visual_document(
                    VisualDocument::parse_database(artifact, "shared_buffers = 128MB\n").unwrap(),
                );
                page.select_database_schema(postgres_16, window, cx);
                let query = format!(
                    "PostgreSQL 16 @{} max_connections = 300",
                    postgres_16.binding.artifact_key
                );
                page.nginx_goal_search_input
                    .update(cx, |input, cx| input.set_value(query, window, cx));
            });
        });
        let (old_lease, original_kind, original_bytes) = cx.update(|_, cx| {
            let page = page.read(cx);
            assert!(
                page.database_assignment_lease_is_current(page.pending_database_assignment.lease)
            );
            (
                page.pending_database_assignment.lease,
                page.model.visual_document.kind(),
                page.model.visual_document.raw_bytes().to_vec(),
            )
        });
        cx.update(|window, cx| {
            page.update(cx, |page, cx| {
                page.select_database_schema(postgres_17, window, cx);
                page.select_database_schema(postgres_16, window, cx);
                assert!(std::ptr::eq(
                    page.model.current_database_schema().unwrap(),
                    postgres_16
                ));
                assert!(!page.database_assignment_lease_is_current(old_lease));
                page.confirm_database_parameter_assignment(old_lease, window, cx);
                assert_eq!(page.model.visual_document.kind(), original_kind);
                assert_eq!(page.model.visual_document.raw_bytes(), original_bytes);
                assert!(!page.model.visual_dirty);
            });
        });

        cx.update(|window, cx| {
            page.update(cx, |page, cx| {
                page.select_database_schema(postgres_17, window, cx);
                page.model.visual_dirty = true;
                let query = format!(
                    "PostgreSQL 16 @{} max_connections = 301",
                    postgres_16.binding.artifact_key
                );
                page.nginx_goal_search_input
                    .update(cx, |input, cx| input.set_value(query, window, cx));
            });
        });
        cx.update(|window, cx| {
            page.update(cx, |page, cx| {
                let lease = page.pending_database_assignment.lease;
                assert!(page.database_assignment_lease_is_current(lease));
                page.confirm_database_parameter_assignment(lease, window, cx);
                assert_eq!(page.model.visual_document.kind(), original_kind);
                assert_eq!(page.model.visual_document.raw_bytes(), original_bytes);
                assert!(page.model.visual_dirty);
                assert!(page.error.as_deref().is_some_and(|error| {
                    error.contains("Schema/版本") && !error.contains("301")
                }));
            });
        });

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn database_assignment_writer_preserves_product_tokens_and_equals_inside_the_value() {
        let schema = DATABASE_CONFIG_SCHEMAS
            .iter()
            .find(|schema| {
                schema.binding.product == DatabaseConfigProduct::PostgreSql
                    && schema.version_label.contains("16")
                    && schema
                        .parameters
                        .iter()
                        .any(|parameter| parameter.canonical_key == "max_connections")
            })
            .expect("PostgreSQL 16 assignment fixture");
        let query = format!(
            "PostgreSQL 16 @{} max_connections = MySQL=a=b",
            schema.binding.artifact_key
        );
        let DatabaseParameterAssignmentResolution::Ready(assignment) =
            resolve_database_parameter_assignment(&query)
        else {
            panic!("a product token and equals signs in the RHS must remain value text")
        };
        assert_eq!(assignment.draft().normalized_value(), "MySQL=a=b");

        let artifact = artifacts_for(DatabaseConfigProduct::PostgreSql)
            .find(|artifact| artifact.key == schema.binding.artifact_key)
            .expect("PostgreSQL assignment artifact");
        let original = VisualDocument::selection_document(VisualDocumentKind::Database(artifact))
            .expect("checked-in PostgreSQL starter");
        let original_bytes = original.raw_bytes().to_vec();
        let staged = stage_database_parameter_goal_document(
            &original,
            assignment.schema(),
            assignment.parameter_index(),
            assignment.draft(),
        )
        .expect("validated assignment must survive the exact writer and reparse boundary");
        assert_eq!(original.raw_bytes(), original_bytes);

        let target_parameter = assignment.target().parameter();
        let matching = staged
            .rows_with_database_schema(Some(assignment.schema()))
            .into_iter()
            .filter(|row| {
                matches!(
                    row.database_parameter(),
                    DatabaseParameterMatch::Matched(parameter)
                        if std::ptr::eq(parameter, target_parameter)
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(matching.len(), 1);
        assert_eq!(matching[0].arguments(), Some("MySQL=a=b"));
        assert!(staged.output().text().unwrap().contains("MySQL=a=b"));
    }

    #[test]
    fn config_preview_colors_are_readable_on_every_current_theme() {
        for theme in crate::theme::ThemeId::ALL {
            let tokens = theme.tokens();
            let colors = ConfigPreviewColors::from_tokens(tokens);
            assert_eq!(
                u32::from(colors.background),
                u32::from(tokens.terminal_background),
                "{theme:?} preview background"
            );
            assert!(
                contrast_ratio(colors.code_text, colors.background)
                    >= MINIMUM_PREVIEW_TEXT_CONTRAST,
                "{theme:?} preview text contrast was {}",
                contrast_ratio(colors.code_text, colors.background)
            );
        }
    }

    #[test]
    fn nginx_goal_search_recognizes_403_intent_and_extracts_only_typed_paths() {
        for query in [
            "403",
            "禁止访问",
            "拒绝访问 /admin",
            "我现在要配 nginx 的 /admin 从外部访问全部返回 403",
            "FORBIDDEN",
            "deny access",
            "admin",
        ] {
            assert!(nginx_forbidden_goal_matches(query), "{query:?}");
        }
        assert!(!nginx_forbidden_goal_matches("启用 gzip 压缩"));
        assert!(!nginx_forbidden_goal_matches("access_log"));
        assert!(!nginx_forbidden_goal_matches("location root"));
        assert_eq!(
            nginx_forbidden_goal_query_path("让 /admin 从外部访问返回 403").as_deref(),
            Some("/admin")
        );
        assert_eq!(
            nginx_forbidden_goal_query_path("禁止 /admin/tools，返回 403").as_deref(),
            Some("/admin/tools")
        );
        assert!(nginx_forbidden_goal_query_path("/admin; return 200").is_none());
        assert!(nginx_forbidden_goal_query_path("/admin%2Fusers").is_none());
        assert!(nginx_forbidden_goal_query_path("/admin{ return 200; }").is_none());
        assert!(nginx_forbidden_goal_query_path("//admin").is_none());
        assert!(nginx_forbidden_goal_query_path("/admin//users").is_none());
        assert!(nginx_forbidden_goal_query_path("https://host/admin").is_none());
        assert!(nginx_forbidden_goal_query_path("只禁止根路径 /").is_none());
        assert!(nginx_forbidden_goal_query_path("禁止 /管理").is_none());

        let document = VisualDocument::Nginx(
            NginxVisualDocument::parse("server { location = /admin { return 403; } }\n").unwrap(),
        );
        assert!(
            filtered_visual_row_indices(&document.rows(), None, "403").is_empty(),
            "goal discovery must not weaken the document search boundary by indexing arguments"
        );
    }

    #[test]
    fn nginx_403_goal_generates_and_reloads_as_an_exact_visual_tree() {
        let generated = generate_from_values_with_forbidden_path(
            NginxSiteKind::ReverseProxy,
            "example.com",
            "80",
            "/var/www/html",
            "http://127.0.0.1:3000",
            true,
            Some(("/admin", NginxForbiddenPathScope::PathAndDescendants)),
        )
        .unwrap();
        let contents = generated.contents();
        assert!(contents.contains("location = /admin {\n        return 403;\n    }"));
        assert!(contents.contains("location ^~ /admin/ {\n        return 403;\n    }"));
        assert!(!contents.contains("location /admin {"));
        assert!(!contents.contains("/administrator"));

        let document = NginxVisualDocument::from_generated(&generated).unwrap();
        assert!(document.is_structured());
        let rows = document.rows();
        let locations = rows
            .iter()
            .filter(|row| row.name() == Some("location"))
            .collect::<Vec<_>>();
        assert!(
            locations
                .iter()
                .any(|row| row.arguments() == Some("= /admin"))
        );
        assert!(
            locations
                .iter()
                .any(|row| row.arguments() == Some("^~ /admin/"))
        );
        for location in locations
            .into_iter()
            .filter(|row| matches!(row.arguments(), Some("= /admin" | "^~ /admin/")))
        {
            assert!(rows.iter().any(|row| {
                row.parent() == Some(location.id())
                    && row.name() == Some("return")
                    && row.arguments() == Some("403")
            }));
        }
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
        assert!(filtered_visual_row_indices(&rows, None, "zero-match-X9").is_empty());
    }

    #[test]
    fn visual_search_uses_reviewed_schema_meaning_but_never_defaults_or_row_values() {
        const VALUE_SENTINEL: &str = "row-value-must-not-be-indexed-X9";
        let artifact = database_artifact("mysql-option-file");
        let source =
            format!("[mysqld]\nfixture_payload = classified\nunknown_setting = {VALUE_SENTINEL}\n");
        let document = VisualDocument::parse_database(artifact, &source).unwrap();
        let mut model = model_with_visual_document(document);
        let schema = &TEST_SCHEMA_REGISTRY[0];
        assert!(model.select_database_schema_from_registry(schema, TEST_SCHEMA_REGISTRY));
        let matched_index = model
            .visual_rows
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
        ] {
            assert!(
                model
                    .filtered_visual_row_indices(query)
                    .contains(&matched_index),
                "reviewed schema field did not match: {query}"
            );
            assert_eq!(
                model.filtered_schema_parameter_indices(query),
                [0],
                "catalog field did not match: {query}"
            );
        }
        for query in [
            "TEST:CONFIG-GENERATOR-SCHEMA",
            "CONFIG GENERATOR TEST-ONLY SCHEMA REFERENCE",
        ] {
            assert!(
                model
                    .filtered_visual_row_indices(query)
                    .contains(&matched_index)
            );
            assert_eq!(model.filtered_schema_parameter_indices(query), [0, 1]);
        }

        assert!(model.filtered_visual_row_indices(VALUE_SENTINEL).is_empty());
        assert!(
            filtered_schema_parameter_indices(
                &TEST_DEFAULT_ONLY_SCHEMA,
                "default-only-search-sentinel"
            )
            .is_empty()
        );
        assert_eq!(model.filtered_schema_parameter_indices(""), [0, 1]);
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
        assert_eq!(
            schema_value_kind_description(boolean),
            "Boolean（true=ENABLED_REVIEWED；false=DISABLED_REVIEWED）"
        );
        assert_eq!(schema_value_kind_description(integer), "Integer（-8..=64）");
        assert_eq!(
            schema_value_kind_description(enumeration),
            "Enumeration（alpha、ReviewedEnum-X9）"
        );
        assert_eq!(
            schema_value_kind_description(text),
            "Text（1..=256 bytes；normalization=TrimAsciiWhitespace）"
        );
    }

    #[test]
    fn schema_catalog_covers_parameters_absent_from_the_document_without_mutation() {
        let artifact = database_artifact("mysql-option-file");
        let document = VisualDocument::parse_database(artifact, "").unwrap();
        let mut model = model_with_visual_document(document);
        let schema = &TEST_SCHEMA_REGISTRY[0];
        let bytes_before = model.visual_document.raw_bytes().to_vec();
        assert!(model.select_database_schema_from_registry(schema, TEST_SCHEMA_REGISTRY));
        assert!(model.visual_rows.is_empty());
        assert_eq!(model.filtered_schema_parameter_indices(""), [0, 1]);
        assert_eq!(model.filtered_schema_parameter_indices("fixture-host"), [1]);

        let selected = model
            .select_visible_schema_parameter(schema, 1, "fixture-host")
            .expect("visible catalog item");
        assert_eq!(selected.canonical_key, "fixture-host");
        assert!(model.selected_visual_node.is_none());
        assert_eq!(model.selected_schema_parameter, Some(1));
        assert_eq!(model.visual_document.raw_bytes(), bytes_before);
        assert!(!model.visual_dirty);
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
            assert!(document.contains_sensitive_values());
            let rows = document.rows();
            assert!(rows.iter().any(|row| row.sensitive));
            assert!(filtered_visual_row_indices(&rows, None, SECRET).is_empty());
            for row in rows.iter().filter(|row| row.sensitive) {
                let explanation = visual_row_explanation(document.kind(), row, None);
                assert!(!explanation.contains(SECRET));
            }
        }
    }

    #[test]
    fn hidden_and_stale_search_selections_fail_closed() {
        let document = VisualDocument::Nginx(
            NginxVisualDocument::parse("events {}\nhttp { target_match one; }\n").unwrap(),
        );
        let mut model = model_with_visual_document(document);
        let target_id = model
            .visual_rows
            .iter()
            .find(|row| row.name() == Some("target_match"))
            .unwrap()
            .id();

        assert!(
            model
                .select_visible_visual_node(target_id, "TARGET_MATCH")
                .is_some()
        );
        assert!(!model.reconcile_visual_search_selection("target"));
        assert!(model.reconcile_visual_search_selection("no-match-X9"));
        assert!(model.selected_visual_node.is_none());
        assert!(
            model
                .select_visible_visual_node(target_id, "no-match-X9")
                .is_none()
        );

        assert!(
            model
                .select_visible_visual_node(target_id, "target_match")
                .is_some()
        );
        model.refresh_visual_rows();
        assert!(model.selected_visual_node.is_none());

        let database = VisualDocument::parse_database(
            database_artifact("mysql-option-file"),
            "[mysqld]\nfixture_payload=value\n",
        )
        .unwrap();
        model.replace_visual_document(database);
        let schema = &TEST_SCHEMA_REGISTRY[0];
        assert!(model.select_database_schema_from_registry(schema, TEST_SCHEMA_REGISTRY));
        assert!(
            model
                .select_visible_schema_parameter(schema, 0, "fixture")
                .is_some()
        );
        assert!(model.reconcile_visual_search_selection("fixture-host"));
        assert!(model.selected_schema_parameter.is_none());
        assert!(
            model
                .select_visible_schema_parameter(&TEST_SCHEMA_REGISTRY[1], 0, "fixture")
                .is_none()
        );
    }

    #[test]
    fn configuration_explanations_use_fail_closed_meaning_levels_without_values() {
        const SECRET: &str = "ExplanationSecret-X9";
        let artifact = database_artifact("mysql-option-file");
        let document = VisualDocument::parse_database(
            artifact,
            &format!("[mysqld]\nfixture_payload={SECRET}\nunknown_setting=visible\n"),
        )
        .unwrap();
        let mut model = model_with_visual_document(document);
        let schema = &TEST_SCHEMA_REGISTRY[0];
        assert!(model.select_database_schema_from_registry(schema, TEST_SCHEMA_REGISTRY));
        let matched = model
            .visual_rows
            .iter()
            .find(|row| matches!(row.database_parameter(), DatabaseParameterMatch::Matched(_)))
            .unwrap();
        let visible = model
            .visual_rows
            .iter()
            .find(|row| {
                matches!(
                    row.database_parameter(),
                    DatabaseParameterMatch::VisibleUnvalidated
                )
            })
            .unwrap();
        let not_applicable = model
            .visual_rows
            .iter()
            .find(|row| {
                matches!(
                    row.database_parameter(),
                    DatabaseParameterMatch::NotApplicable
                )
            })
            .unwrap();
        let matched_explanation = visual_row_explanation(
            VisualDocumentKind::Database(artifact),
            matched,
            Some(schema),
        );
        let visible_explanation = visual_row_explanation(
            VisualDocumentKind::Database(artifact),
            visible,
            Some(schema),
        );
        let not_applicable_explanation = visual_row_explanation(
            VisualDocumentKind::Database(artifact),
            not_applicable,
            Some(schema),
        );
        let nginx = VisualDocument::nginx_competition_skeleton().unwrap();
        let syntax_only_explanation =
            visual_row_explanation(VisualDocumentKind::Nginx, &nginx.rows()[0], None);
        let catalog_explanation =
            database_catalog_parameter_explanation(schema, &schema.parameters[0]);

        assert!(matched_explanation.contains("CatalogGuidance（未核目标）"));
        assert!(matched_explanation.contains("value kind=Text"));
        assert!(matched_explanation.contains("层级="));
        assert!(matched_explanation.contains("直接子节点="));
        assert!(matched_explanation.contains("本地可编辑="));
        assert!(matched_explanation.contains("敏感=是"));
        assert!(matched_explanation.contains("显示截断="));
        assert!(matched_explanation.contains("敏感值未进入搜索、配置说明或复制状态"));
        assert!(!matched_explanation.contains(SECRET));
        assert!(visible_explanation.contains("SyntaxOnlyUnknown · VisibleUnvalidated"));
        assert!(not_applicable_explanation.contains("SyntaxOnlyUnknown · NotApplicable"));
        assert!(syntax_only_explanation.contains("SyntaxOnlyUnknown"));
        assert!(syntax_only_explanation.contains("没有闭合 Schema 配置目录"));
        assert!(catalog_explanation.contains("CatalogGuidance（未核目标）"));
        assert!(catalog_explanation.contains("不会自动新增、修改或回填"));
        for explanation in [
            matched_explanation,
            visible_explanation,
            not_applicable_explanation,
            syntax_only_explanation,
            catalog_explanation,
        ] {
            assert!(!explanation.contains("Verified"));
        }
    }

    #[test]
    fn form_translation_generates_both_closed_templates() {
        let static_config = generate_from_values(
            NginxSiteKind::Static,
            "example.com",
            "8080",
            "/srv/www/site",
            "ignored because the static template is selected",
            true,
        )
        .unwrap();
        assert!(static_config.contents().contains("root \"/srv/www/site\";"));

        let proxy_config = generate_from_values(
            NginxSiteKind::ReverseProxy,
            "api.example.com",
            "80",
            "ignored because the proxy template is selected",
            "http://127.0.0.1:3000",
            false,
        )
        .unwrap();
        assert!(
            proxy_config
                .contents()
                .contains("proxy_pass http://127.0.0.1:3000;")
        );
    }

    #[test]
    fn form_translation_rejects_nginx_directive_injection() {
        assert!(
            generate_from_values(
                NginxSiteKind::ReverseProxy,
                "example.com; return 200",
                "80",
                "/srv/www/site",
                "http://127.0.0.1:3000",
                true,
            )
            .is_err()
        );
        assert!(
            generate_from_values(
                NginxSiteKind::Static,
                "example.com",
                "80",
                "/srv/www/site; include /etc/shadow",
                "http://127.0.0.1:3000",
                true,
            )
            .is_err()
        );
    }

    #[test]
    fn model_starts_with_independent_quick_and_competition_documents() {
        let generated = generate_from_values(
            NginxSiteKind::ReverseProxy,
            DEFAULT_SERVER_NAME,
            DEFAULT_LISTEN_PORT,
            DEFAULT_STATIC_ROOT,
            DEFAULT_UPSTREAM,
            true,
        )
        .unwrap();
        let quick_contents = generated.contents().to_owned();
        let mut model = ConfigGeneratorModel::new(generated);

        assert_eq!(model.mode, ConfigGeneratorMode::Quick);
        assert!(model.visual_document.is_structured());
        assert!(
            model
                .visual_rows
                .iter()
                .any(|row| row.name() == Some("events"))
        );
        assert!(
            model
                .visual_rows
                .iter()
                .any(|row| row.name() == Some("http"))
        );

        model
            .visual_document
            .add_statement(None, "third_party_directive", "competition value")
            .unwrap();
        model.refresh_visual_rows();
        assert!(model.visual_rows.iter().any(|row| {
            row.kind() == VisualNodeKind::Statement && row.name() == Some("third_party_directive")
        }));
        assert_eq!(model.generated.as_ref().unwrap().contents(), quick_contents);
    }

    #[test]
    fn quick_result_can_become_a_structured_visual_document() {
        let generated = generate_from_values(
            NginxSiteKind::Static,
            "visual.example.com",
            "8080",
            "/srv/visual",
            DEFAULT_UPSTREAM,
            true,
        )
        .unwrap();
        let visual = VisualDocument::from_generated(&generated).unwrap();

        assert!(visual.is_structured());
        assert!(visual.rows().iter().any(|row| {
            row.kind() == VisualNodeKind::Container && row.name() == Some("server")
        }));
        assert_eq!(visual.output().text().unwrap(), generated.contents());
    }

    #[test]
    fn schema_selection_rejects_cross_artifact_and_resets_when_artifact_changes() {
        let mysql_artifact = database_artifact("mysql-option-file");
        let mysql_document = VisualDocument::parse_database(mysql_artifact, "").unwrap();
        let mut model = model_with_visual_document(mysql_document);
        let mysql_schema = &TEST_SCHEMA_REGISTRY[0];
        let postgresql_schema = &TEST_SCHEMA_REGISTRY[1];

        assert!(
            !model.select_database_schema_from_registry(postgresql_schema, TEST_SCHEMA_REGISTRY)
        );
        assert!(model.selected_database_schema.is_none());

        static UNREGISTERED_SCHEMA: DatabaseConfigSchema = DatabaseConfigSchema {
            display_label: "Unregistered test schema",
            ..TEST_MYSQL_SCHEMA
        };
        assert!(
            !model.select_database_schema_from_registry(&UNREGISTERED_SCHEMA, TEST_SCHEMA_REGISTRY)
        );
        assert!(model.selected_database_schema.is_none());

        assert!(model.select_database_schema_from_registry(mysql_schema, TEST_SCHEMA_REGISTRY));
        assert!(std::ptr::eq(
            model.current_database_schema().unwrap(),
            mysql_schema
        ));
        assert!(
            !model.select_database_schema_from_registry(postgresql_schema, TEST_SCHEMA_REGISTRY)
        );
        assert!(std::ptr::eq(
            model.current_database_schema().unwrap(),
            mysql_schema
        ));

        let postgresql_document =
            VisualDocument::parse_database(database_artifact("postgresql-main"), "port = 5433\n")
                .unwrap();
        model.replace_visual_document(postgresql_document);
        assert!(model.selected_database_schema.is_none());
        assert!(model.current_database_schema().is_none());
    }

    #[test]
    fn partial_schema_is_metadata_only_and_preserves_local_draft_permission() {
        let artifact = database_artifact("mysql-option-file");
        let document = VisualDocument::parse_database(
            artifact,
            "[mysqld]\nunknown_local_draft_key = retained\n",
        )
        .unwrap();
        let mut model = model_with_visual_document(document);
        let partial_schema = &TEST_SCHEMA_REGISTRY[0];
        let permission_before = model.visual_document.kind().allows_lossless_local_draft();
        assert!(permission_before);
        assert_eq!(
            partial_schema.completeness,
            DatabaseConfigSchemaCompleteness::Partial
        );

        assert!(model.select_database_schema_from_registry(partial_schema, TEST_SCHEMA_REGISTRY,));
        assert_eq!(
            model.visual_document.kind().allows_lossless_local_draft(),
            permission_before
        );
        let unknown = model
            .visual_rows
            .iter()
            .find(|row| row.name() == Some("unknown_local_draft_key"))
            .unwrap();
        assert!(unknown.allows_local_draft_mutation());
        assert!(matches!(
            unknown.database_parameter(),
            DatabaseParameterMatch::VisibleUnvalidated
        ));

        let status = database_schema_status(Some(partial_schema));
        assert!(status.contains("不改变本地无损草稿权限"));
        assert!(status.contains(LOCAL_DRAFT_SCOPE_NOTICE));
        assert!(!status.contains("已验证"));
        assert_eq!(ConfigGeneratorMode::Visual.label(), "本地无损草稿");
        assert_eq!(LOCAL_DRAFT_SAVE_LABEL, "另存本地草稿");
    }

    #[test]
    fn schema_metadata_lookup_is_path_qualified_and_redacts_before_ui_copy() {
        let artifact = database_artifact("mysql-option-file");
        let empty = VisualDocument::parse_database(artifact, "").unwrap();
        let mut model = model_with_visual_document(empty);
        let mysql_schema = &TEST_SCHEMA_REGISTRY[0];
        assert!(model.select_database_schema_from_registry(mysql_schema, TEST_SCHEMA_REGISTRY));

        let classified_value = "classified-value-X9";
        let source = format!(
            "[mysqld]\nfixture_payload = {classified_value}\n[client]\nfixture_payload = visible-client\nfixture-host = db01\nunknown_setting = visible-unknown\n"
        );
        let imported = VisualDocument::parse_database(artifact, &source).unwrap();
        assert!(!imported.contains_sensitive_values());
        model.replace_visual_document(imported);

        let sensitive = model
            .visual_rows
            .iter()
            .find(|row| {
                row.name() == Some("fixture_payload")
                    && matches!(row.database_parameter(), DatabaseParameterMatch::Matched(_))
            })
            .unwrap();
        let sensitive_id = sensitive.id();
        assert!(sensitive.sensitive);
        assert!(!sensitive.allows_local_draft_mutation());
        assert!(sensitive.arguments().is_none());
        assert_eq!(sensitive.preview(), REDACTED_SCHEMA_VALUE);
        let (_, editor_arguments) = visual_editor_values(sensitive);
        assert!(editor_arguments.is_empty());
        assert!(!format!("{sensitive:?}").contains(classified_value));
        assert!(!format!("{:?}", model.visual_rows).contains(classified_value));
        assert!(!model.can_copy_visual());
        assert!(model.contains_sensitive_visual_values());
        assert_eq!(model.visual_document.output().text().unwrap(), source);

        let wrong_container = model
            .visual_rows
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
        assert!(!wrong_container.sensitive);
        assert!(
            database_parameter_status(Some(wrong_container), Some(mysql_schema))
                .unwrap()
                .contains("VisibleUnvalidated")
        );

        let operational = model
            .visual_rows
            .iter()
            .find(|row| row.name() == Some("fixture-host"))
            .unwrap();
        assert_eq!(operational.arguments(), Some("db01"));
        assert!(!operational.sensitive);

        let unknown = model
            .visual_rows
            .iter()
            .find(|row| row.name() == Some("unknown_setting"))
            .unwrap();
        assert_eq!(unknown.arguments(), Some("visible-unknown"));
        assert!(matches!(
            unknown.database_parameter(),
            DatabaseParameterMatch::VisibleUnvalidated
        ));

        let metadata = database_parameter_status(Some(sensitive), Some(mysql_schema)).unwrap();
        assert!(metadata.contains("test.fixture.capability"));
        assert!(metadata.contains("Instance"));
        assert!(metadata.contains("Restart"));
        assert!(metadata.contains("High"));
        assert!(metadata.contains("Config generator test-only schema reference"));
        assert!(metadata.contains("未读取 raw value"));
        assert!(database_schema_status(Some(mysql_schema)).contains("Partial"));
        assert!(database_schema_status(Some(mysql_schema)).contains("test.standard"));
        assert!(database_schema_status(None).contains("未绑定"));
        model.selected_visual_node = Some(sensitive_id);
        assert!(!model.can_mutate_selected_local_draft_row());
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

        let source = "[SQLEXEC]\r\nupdate_grade = 2\r\nselect_grade = 4\r\nmvcc_grade = 1\r\n[GENERAL]\r\nswitch_insert_value_on_duplicate_key_update_sw = 0\r\ninsert_value_on_duplicate_key_update_usage_level = 1\r\nunknown_setting = retained\r\n";
        let document = VisualDocument::parse_database(artifact, source).unwrap();
        let mut model = model_with_visual_document(document);
        let output_before = model.visual_document.output().text().unwrap().to_owned();
        let raw_before = model.visual_document.raw_bytes().to_vec();
        let permission_before = model.visual_document.kind().allows_lossless_local_draft();
        let row_permissions_before = model
            .visual_rows
            .iter()
            .map(VisualRow::allows_local_draft_mutation)
            .collect::<Vec<_>>();
        let can_copy_before = model.can_copy_visual();
        let starter_before = database_starter_contents(artifact);

        assert!(!permission_before);
        assert_eq!(output_before, source);
        assert_eq!(raw_before, source.as_bytes());
        let unselected = model
            .visual_rows
            .iter()
            .find(|row| row.name() == Some("update_grade"))
            .unwrap();
        assert!(database_parameter_status(Some(unselected), None).is_none());
        assert_local_draft_mutation_denied(
            VisualDocument::database_starter(artifact),
            artifact.key,
        );

        assert!(model.select_database_schema_from_registry(schema, DATABASE_CONFIG_SCHEMAS));
        for (key, current_value, documented_default) in [
            ("update_grade", "2", "0"),
            ("select_grade", "4", "0"),
            ("mvcc_grade", "1", "0"),
            ("switch_insert_value_on_duplicate_key_update_sw", "0", "1"),
            ("insert_value_on_duplicate_key_update_usage_level", "1", "0"),
        ] {
            let row = model
                .visual_rows
                .iter()
                .find(|row| row.name() == Some(key))
                .unwrap_or_else(|| panic!("missing GoldenDB row {key}"));
            assert_eq!(row.arguments(), Some(current_value), "{key}");
            assert!(matches!(
                row.database_parameter(),
                DatabaseParameterMatch::Matched(_)
            ));
            let status = database_parameter_status(Some(row), Some(schema)).unwrap();
            assert!(
                status.contains(&format!(
                    "{DOCUMENTED_DEFAULT_STATUS_LABEL}：{documented_default}。"
                )),
                "{key} status did not show its documented default: {status}"
            );
        }

        let unknown = model
            .visual_rows
            .iter()
            .find(|row| row.name() == Some("unknown_setting"))
            .unwrap();
        assert!(matches!(
            unknown.database_parameter(),
            DatabaseParameterMatch::VisibleUnvalidated
        ));
        let unknown_status = database_parameter_status(Some(unknown), Some(schema)).unwrap();
        assert!(unknown_status.contains("VisibleUnvalidated"));
        assert!(!unknown_status.contains(DOCUMENTED_DEFAULT_STATUS_LABEL));

        assert_eq!(
            model.visual_document.output().text().unwrap(),
            output_before
        );
        assert_eq!(model.visual_document.raw_bytes(), raw_before);
        assert_eq!(
            model.visual_document.kind().allows_lossless_local_draft(),
            permission_before
        );
        assert_eq!(
            model
                .visual_rows
                .iter()
                .map(VisualRow::allows_local_draft_mutation)
                .collect::<Vec<_>>(),
            row_permissions_before
        );
        assert_eq!(model.can_copy_visual(), can_copy_before);
        assert_eq!(database_starter_contents(artifact), starter_before);
        assert_local_draft_mutation_denied(
            VisualDocument::database_starter(artifact),
            artifact.key,
        );
        model.selected_visual_node = model
            .visual_rows
            .iter()
            .find(|row| row.name() == Some("update_grade"))
            .map(VisualRow::id);
        assert!(!model.can_mutate_selected_local_draft_row());
    }

    #[test]
    fn documented_defaults_render_empty_text_but_hide_invalid_sensitive_metadata() {
        const SECRET_DEFAULT: &str = "documented-default-must-not-reach-ui";
        const INVALID_PARAMETERS: &[DatabaseConfigParameterSchema] =
            &[DatabaseConfigParameterSchema {
                documented_default: Some(DatabaseConfigDocumentedDefault::Text(SECRET_DEFAULT)),
                ..TEST_MYSQL_PARAMETERS[0]
            }];
        const INVALID_SCHEMA: DatabaseConfigSchema = DatabaseConfigSchema {
            parameters: INVALID_PARAMETERS,
            ..TEST_MYSQL_SCHEMA
        };
        const INVALID_REGISTRY: &[DatabaseConfigSchema] = &[INVALID_SCHEMA];

        let artifact = database_artifact("mysql-option-file");
        let source = "[mysqld]\nfixture_payload = current-sensitive-value\n";
        let document = VisualDocument::parse_database(artifact, source).unwrap();
        let mut model = model_with_visual_document(document);
        let schema = &INVALID_REGISTRY[0];
        assert!(model.select_database_schema_from_registry(schema, INVALID_REGISTRY));
        let row = model
            .visual_rows
            .iter()
            .find(|row| row.name() == Some("fixture_payload"))
            .unwrap();
        let DatabaseParameterMatch::Matched(parameter) = row.database_parameter() else {
            panic!("invalid sensitive fixture did not match its exact path");
        };
        assert!(parameter.documented_default_for_display().is_none());
        let status = database_parameter_status(Some(row), Some(schema)).unwrap();
        assert!(!status.contains(DOCUMENTED_DEFAULT_STATUS_LABEL));
        assert!(!status.contains(SECRET_DEFAULT));
        assert!(!format!("{parameter:?}{row:?}{model:?}").contains(SECRET_DEFAULT));
        assert_eq!(model.visual_document.output().text().unwrap(), source);

        const EMPTY_PARAMETERS: &[DatabaseConfigParameterSchema] =
            &[DatabaseConfigParameterSchema {
                value_kind: DatabaseConfigSchemaValueKind::Text {
                    minimum_bytes: 0,
                    maximum_bytes: 256,
                    normalization: DatabaseConfigTextNormalization::Preserve,
                },
                documented_default: Some(DatabaseConfigDocumentedDefault::Text("")),
                ..TEST_MYSQL_PARAMETERS[1]
            }];
        const EMPTY_SCHEMA: DatabaseConfigSchema = DatabaseConfigSchema {
            parameters: EMPTY_PARAMETERS,
            ..TEST_MYSQL_SCHEMA
        };
        const EMPTY_REGISTRY: &[DatabaseConfigSchema] = &[EMPTY_SCHEMA];

        let source = "[client]\nfixture-host = current-host\n";
        let document = VisualDocument::parse_database(artifact, source).unwrap();
        let mut model = model_with_visual_document(document);
        let schema = &EMPTY_REGISTRY[0];
        assert!(model.select_database_schema_from_registry(schema, EMPTY_REGISTRY));
        let row = model
            .visual_rows
            .iter()
            .find(|row| row.name() == Some("fixture-host"))
            .unwrap();
        assert_eq!(row.arguments(), Some("current-host"));
        let status = database_parameter_status(Some(row), Some(schema)).unwrap();
        assert!(status.contains(&format!(
            "{DOCUMENTED_DEFAULT_STATUS_LABEL}：〈空字符串〉。"
        )));
        assert_eq!(model.visual_document.output().text().unwrap(), source);
    }

    #[test]
    fn schemas_never_change_vendor_or_generated_local_draft_permission() {
        for (index, key, source) in [
            (
                0,
                "opengauss-om-cluster-xml",
                "<?xml version=\"1.0\"?><cluster />\n",
            ),
            (
                1,
                "mysql-persisted-variables",
                "{\"Version\": 2, \"mysql_server\": {}}\n",
            ),
        ] {
            let artifact = database_artifact(key);
            let document = VisualDocument::parse_database(artifact, source).unwrap();
            let mut model = model_with_visual_document(document);
            let before = model.visual_document.kind().allows_lossless_local_draft();
            assert!(!before);
            assert!(model.select_database_schema_from_registry(
                &TEST_READ_ONLY_SCHEMAS[index],
                TEST_READ_ONLY_SCHEMAS,
            ));
            assert!(model.current_database_schema().is_some());
            assert_eq!(
                model.visual_document.kind().allows_lossless_local_draft(),
                before
            );
            model.selected_visual_node = model.visual_rows.first().map(VisualRow::id);
            assert!(!model.can_mutate_selected_local_draft_row());
            assert_local_draft_mutation_denied(
                model
                    .visual_document
                    .add_statement(None, "fixture", "value"),
                key,
            );
        }
        assert_eq!(
            TEST_READ_ONLY_SCHEMAS[0].completeness,
            DatabaseConfigSchemaCompleteness::Partial
        );
        assert_eq!(
            TEST_READ_ONLY_SCHEMAS[1].completeness,
            DatabaseConfigSchemaCompleteness::Complete
        );
    }

    #[test]
    fn apache_competition_skeleton_is_available_through_visual_facade() {
        let document = VisualDocument::competition_skeleton(VisualDocumentKind::Apache).unwrap();
        let rows = document.rows();

        assert_eq!(document.kind(), VisualDocumentKind::Apache);
        assert!(document.is_structured());
        assert!(rows.iter().any(|row| {
            row.kind() == VisualNodeKind::Container
                && row.name() == Some("VirtualHost")
                && row.allows_local_draft_mutation()
        }));
        assert!(rows.iter().any(|row| row.name() == Some("ServerTokens")));
    }

    #[test]
    fn supported_database_starters_remain_structured() {
        for key in [
            "mysql-option-file",
            "postgresql-main",
            "postgresql-hba",
            "dm-main",
            "tidb-server-toml",
            "sequoiadb-standalone-config",
        ] {
            let artifact = database_artifact(key);
            let document =
                VisualDocument::competition_skeleton(VisualDocumentKind::Database(artifact))
                    .unwrap();

            assert!(document.is_structured(), "starter {key} became opaque");
            assert_eq!(document.kind(), VisualDocumentKind::Database(artifact));
            assert!(!document.rows().is_empty(), "starter {key} has no rows");
        }
    }

    #[test]
    fn compatible_and_domestic_starters_do_not_guess_upstream_defaults() {
        for key in ["kingbase-es-main", "gbase-8c-main", "tidb-server-toml"] {
            let starter = database_starter_contents(database_artifact(key));
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
                    "{key} inherited guessed default {guessed_default}"
                );
            }
            assert!(
                starter.contains("导入"),
                "{key} must request an original file"
            );
        }

        assert!(database_starter_contents(database_artifact("mysql-option-file")).contains("3306"));
        assert!(database_starter_contents(database_artifact("postgresql-main")).contains("5432"));
        let dm = database_starter_contents(database_artifact("dm-main"));
        assert!(dm.contains("inspect"));
        assert!(dm.contains("仅供检查"));
    }

    #[test]
    fn local_visual_selection_hides_managed_runtime_cloud_binary_and_unparsed_artifacts() {
        for product in [
            DatabaseConfigProduct::TdsqlMysqlManaged,
            DatabaseConfigProduct::TdsqlPostgresqlManaged,
            DatabaseConfigProduct::PolarDbManagedMySql,
            DatabaseConfigProduct::PolarDbManagedPostgresql,
            DatabaseConfigProduct::PolarDbManagedOracle,
        ] {
            assert!(!database_product_has_visual_files(product));
            assert!(first_database_visual_artifact(product).is_none());
        }

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
            let artifact = database_artifact(key);
            assert!(database_visual_parser(artifact).is_none());
            assert!(
                !visual_selector_contains(artifact),
                "{key} entered the selector"
            );
        }
    }

    #[test]
    fn unparsed_vendor_text_never_reaches_visual_rows_or_copy_boundaries() {
        const PAYLOAD: &str = "AUTHKEY K9z7Q2\n";
        let path = std::env::temp_dir().join(format!(
            "lovelyres-unparsed-vendor-text-{}.conf",
            std::process::id()
        ));
        std::fs::write(&path, PAYLOAD).unwrap();

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
            let artifact = database_artifact(key);
            let kind = VisualDocumentKind::Database(artifact);

            assert!(artifact.is_file_visual_readable(), "{key}");
            assert!(!artifact.has_source_backed_visual_parser(), "{key}");
            assert_eq!(line_dialect(artifact), None, "{key}");
            assert_eq!(structured_dialect(artifact), None, "{key}");
            assert_eq!(database_visual_parser(artifact), None, "{key}");
            assert!(!visual_selector_contains(artifact), "{key}");
            assert!(VisualDocument::selection_document(kind).is_err(), "{key}");

            let parsed = VisualDocument::parse_database(artifact, PAYLOAD);
            assert!(parsed.is_err(), "{key} exposed structured rows/copy state");
            assert!(
                !format!("{parsed:?}").contains("K9z7Q2"),
                "{key} leaked the rejected payload"
            );
            assert!(
                VisualDocument::read_local(kind, &path).is_err(),
                "{key} crossed the local-read parser gate"
            );
        }

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn dm_dcr_array_and_startup_command_payloads_never_reach_the_generic_ini_editor() {
        const DCR_CONFIG: &str = concat!(
            "// DCR group/member arrays are ordered vendor-owned units\n",
            "[GRP]\nDCR_GRP_NAME=CSS_GRP\nDCR_GRP_TYPE=CSS\n",
            "[CSS]\nDCR_EP_NAME=CSS0\n",
            "[CSS]\nDCR_EP_NAME=CSS1\n",
            "[GRP]\nDCR_GRP_NAME=ASM_GRP\nDCR_GRP_TYPE=ASM\n",
            "[ASM]\nDCR_EP_NAME=ASM0\n",
            "[ASM]\nDCR_EP_NAME=ASM1\n",
        );
        const DCR_NODE: &str = concat!(
            "DMDCR_PATH=/dmdata/dmdcr_cfg.ini\n",
            "DMDCR_DB_STARTUP_CMD=/opt/dmdbms/bin/dmserver path=/dmdata/DAMENG/dm.ini\n",
        );
        let path = std::env::temp_dir().join(format!(
            "lovelyres-dm-dcr-fail-closed-{}.ini",
            std::process::id()
        ));

        for (key, payload) in [("dm-dcr-config", DCR_CONFIG), ("dm-dcr-node", DCR_NODE)] {
            std::fs::write(&path, payload).unwrap();
            let artifact = database_artifact(key);
            let kind = VisualDocumentKind::Database(artifact);

            assert!(artifact.is_file_visual_readable(), "{key}");
            assert!(!artifact.has_source_backed_visual_parser(), "{key}");
            assert!(!kind.allows_lossless_local_draft(), "{key}");
            assert_eq!(line_dialect(artifact), None, "{key}");
            assert_eq!(structured_dialect(artifact), None, "{key}");
            assert_eq!(database_visual_parser(artifact), None, "{key}");
            assert!(!visual_selector_contains(artifact), "{key}");
            assert!(VisualDocument::selection_document(kind).is_err(), "{key}");

            let parsed = VisualDocument::parse_database(artifact, payload);
            assert!(parsed.is_err(), "{key} reached a generic parser");
            assert!(
                !format!("{parsed:?}").contains(payload),
                "{key} leaked a rejected DCR payload"
            );
            assert!(
                VisualDocument::read_local(kind, &path).is_err(),
                "{key} crossed the local-read parser gate"
            );
            assert_local_draft_mutation_denied(VisualDocument::database_starter(artifact), key);
            assert_local_draft_mutation_denied(VisualDocument::competition_skeleton(kind), key);
        }

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn dm_init_password_is_redacted_non_copyable_and_rejects_ordinary_updates() {
        const SECRET: &str = "NeverShow42";
        const SOURCE: &str = concat!(
            "[DAMENG]\r\n",
            "SYSDBA_PWD=NeverShow42\r\n",
            "LOG_PATH=/var/log/dm/primary\r\n",
            "LOG_PATH=/var/log/dm/archive\r\n",
        );
        let artifact = database_artifact("dm-init");
        assert!(artifact.allows_lossless_local_draft());
        assert_eq!(
            database_visual_parser(artifact),
            Some(DatabaseVisualParser::Line(LineConfigDialect::Ini))
        );

        let mut document = VisualDocument::parse_database(artifact, SOURCE).unwrap();
        assert!(document.is_structured());
        assert!(document.contains_sensitive_values());
        assert!(!document.can_copy());
        assert_eq!(document.raw_bytes(), SOURCE.as_bytes());
        assert_eq!(document.output().text().unwrap(), SOURCE);

        let rows = document.rows();
        let dameng = rows
            .iter()
            .find(|row| row.name() == Some("DAMENG"))
            .expect("DAMENG section");
        assert_eq!(dameng.kind(), VisualNodeKind::Container);
        assert_eq!(dameng.child_count(), 3);
        let password = rows
            .iter()
            .find(|row| row.name() == Some("SYSDBA_PWD"))
            .expect("SYSDBA password row");
        assert_eq!(password.parent, Some(dameng.id()));
        assert!(password.sensitive);
        assert_eq!(password.arguments(), None);
        assert_eq!(password.preview(), REDACTED_SCHEMA_VALUE);
        assert!(!password.allows_local_draft_mutation());
        let (_, editor_value) = visual_editor_values(password);
        assert!(editor_value.is_empty());
        let log_paths = rows
            .iter()
            .filter(|row| row.name() == Some("LOG_PATH"))
            .map(VisualRow::arguments)
            .collect::<Vec<_>>();
        assert_eq!(
            log_paths,
            [Some("/var/log/dm/primary"), Some("/var/log/dm/archive")]
        );

        for debug in [format!("{document:?}"), format!("{rows:?}")] {
            assert!(!debug.contains(SECRET));
        }

        let before = document.raw_bytes().to_vec();
        let error = document
            .update_statement(password.id(), "SYSDBA_PWD", "replacement")
            .expect_err("ordinary visual update must reject a secret row");
        assert!(error.to_string().contains("dedicated secret input flow"));
        assert_eq!(document.raw_bytes(), before);

        let model = model_with_visual_document(document);
        assert!(model.contains_sensitive_visual_values());
        assert!(!model.visual_document.can_copy());
        assert!(!model.can_copy_visual());
        let password = model
            .visual_rows
            .iter()
            .find(|row| row.name() == Some("SYSDBA_PWD"))
            .expect("model SYSDBA password row");
        assert!(password.sensitive);
        assert_eq!(password.arguments(), None);
        assert_eq!(password.preview(), REDACTED_SCHEMA_VALUE);
        assert!(!format!("{model:?}").contains(SECRET));
    }

    #[test]
    fn gbase_8s_known_text_grammars_remain_byte_exact_visual_and_read_only() {
        for (key, source) in [
            ("gbase-8s-onconfig", "ROOTNAME rootdbs\r\nSERVERNUM 0\r\n"),
            (
                "gbase-8s-sqlhosts",
                "# dbserver nettype hostname service options\r\ngbaseserver onsoctcp 192.0.2.10 9088 g=g_cluster_1\r\n",
            ),
        ] {
            let artifact = database_artifact(key);
            let kind = VisualDocumentKind::Database(artifact);

            assert_eq!(
                artifact.support,
                DatabaseConfigSupportLevel::VisualSyntax,
                "{key}"
            );
            assert!(artifact.is_file_visual_readable(), "{key}");
            assert!(artifact.has_source_backed_visual_parser(), "{key}");
            assert!(!artifact.allows_lossless_local_draft(), "{key}");
            assert_eq!(
                database_visual_parser(artifact),
                Some(DatabaseVisualParser::Line(LineConfigDialect::Whitespace)),
                "{key}"
            );
            assert!(visual_selector_contains(artifact), "{key}");

            let mut document = VisualDocument::parse_database(artifact, source).unwrap();
            let rows = document.rows();
            let id = rows
                .first()
                .unwrap_or_else(|| panic!("{key} has no source-backed visual row"))
                .id();
            assert_eq!(document.kind(), kind, "{key}");
            assert!(document.is_structured(), "{key}");
            assert_eq!(document.raw_bytes(), source.as_bytes(), "{key}");
            assert_eq!(document.output().text().unwrap(), source, "{key}");
            assert!(
                rows.iter().all(|row| !row.allows_local_draft_mutation()),
                "{key}"
            );
            assert_local_draft_mutation_denied(
                document.update_statement(id, "CHANGED", "value"),
                key,
            );
            assert_eq!(document.raw_bytes(), source.as_bytes(), "{key}");
        }

        assert!(database_product_has_visual_files(
            DatabaseConfigProduct::GBase8s
        ));
        assert_eq!(
            first_database_visual_artifact(DatabaseConfigProduct::GBase8s)
                .map(|artifact| artifact.key),
            Some("gbase-8s-onconfig")
        );
    }

    #[test]
    fn gbase_8s_visual_text_authkey_is_redacted_and_blocks_whole_document_copy() {
        const SOURCE: &str = "AUTHKEY K9z7Q2\n";
        const SENTINEL: &str = "K9z7Q2";

        for key in ["gbase-8s-onconfig", "gbase-8s-sqlhosts"] {
            let artifact = database_artifact(key);
            let document = VisualDocument::parse_database(artifact, SOURCE).unwrap();
            let rows = document.rows();
            let authkey = rows
                .iter()
                .find(|row| row.name() == Some("AUTHKEY"))
                .unwrap_or_else(|| panic!("{key} lost the AUTHKEY row"));

            assert!(document.is_structured(), "{key}");
            assert_eq!(document.raw_bytes(), SOURCE.as_bytes(), "{key}");
            assert!(document.contains_sensitive_values(), "{key}");
            assert!(!document.can_copy(), "{key}");
            assert!(authkey.sensitive, "{key}");
            assert!(authkey.arguments().is_none(), "{key}");
            assert_eq!(authkey.preview(), REDACTED_SCHEMA_VALUE, "{key}");
            assert!(
                rows.iter().all(|row| {
                    row.arguments() != Some(SENTINEL) && !row.preview().contains(SENTINEL)
                }),
                "{key} exposed the AUTHKEY value through a row"
            );
            assert!(
                !format!("{document:?}{rows:?}").contains(SENTINEL),
                "{key} leaked the AUTHKEY value through Debug"
            );
        }
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
            assert_eq!(database_visual_parser(artifact), Some(parser));
            assert!(
                visual_selector_contains(artifact),
                "{key} left the selector"
            );
            assert!(database_product_has_visual_files(artifact.product));
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
        let kind = VisualDocumentKind::Database(artifact);
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
        assert!(visual_selector_contains(artifact));
        assert!(!artifact.allows_lossless_local_draft());
        assert_eq!(database_starter_contents(artifact), "");

        let selection = VisualDocument::selection_document(kind).unwrap();
        assert_eq!(selection.kind(), kind);
        assert_eq!(selection.output().text().unwrap(), "");
        assert_eq!(selection.output().suggested_file_name(), "auto.cnf");

        let document = VisualDocument::parse_database(artifact, SOURCE).unwrap();
        let mut model = model_with_visual_document(document);
        let section = model
            .visual_rows
            .iter()
            .find(|row| row.name() == Some("auto"))
            .expect("auto.cnf must expose its [auto] section");
        assert_eq!(section.kind(), VisualNodeKind::Container);
        let identity = model
            .visual_rows
            .iter()
            .find(|row| row.name() == Some("server-uuid"))
            .expect("auto.cnf must expose server-uuid");
        let identity_id = identity.id();
        assert_eq!(identity.kind(), VisualNodeKind::Statement);
        assert_eq!(
            identity.arguments(),
            Some("8a94f357-aab4-11df-86ab-c80aa9429562")
        );
        assert!(!identity.sensitive);
        assert!(
            model
                .visual_rows
                .iter()
                .all(|row| !row.allows_local_draft_mutation())
        );
        assert!(model.visual_document.is_structured());
        assert_eq!(model.visual_document.raw_bytes(), SOURCE.as_bytes());
        assert_eq!(model.visual_document.output().text().unwrap(), SOURCE);
        assert_eq!(
            model.visual_document.output().suggested_file_name(),
            "auto.cnf"
        );
        assert!(!model.contains_sensitive_visual_values());
        assert!(model.visual_document.can_copy());
        assert!(model.can_copy_visual());

        let save_payload = ConfigSavePayload::Visual(model.visual_document.output());
        assert_eq!(save_payload.suggested_file_name(), "auto.cnf");
        let ConfigSavePayload::Visual(save_output) = save_payload else {
            panic!("auto.cnf used the wrong save payload");
        };
        assert_eq!(save_output.text().unwrap(), SOURCE);

        let notice = kind.read_only_notice().unwrap();
        assert!(notice.contains("只读展示"));
        assert!(notice.contains("另存本地副本"));
        assert_local_draft_mutation_denied(
            VisualDocument::database_starter(artifact),
            artifact.key,
        );
        assert_local_draft_mutation_denied(
            VisualDocument::competition_skeleton(kind),
            artifact.key,
        );

        let before = model.visual_document.raw_bytes().to_vec();
        assert_local_draft_mutation_denied(
            model
                .visual_document
                .add_statement(None, "server-uuid", "replacement"),
            artifact.key,
        );
        assert_eq!(model.visual_document.raw_bytes(), before);
        assert_local_draft_mutation_denied(
            model.visual_document.add_container(None, "new", ""),
            artifact.key,
        );
        assert_eq!(model.visual_document.raw_bytes(), before);
        assert_local_draft_mutation_denied(
            model.visual_document.add_comment(None, "new comment"),
            artifact.key,
        );
        assert_eq!(model.visual_document.raw_bytes(), before);
        assert_local_draft_mutation_denied(
            model
                .visual_document
                .update_statement(identity_id, "server-uuid", "replacement"),
            artifact.key,
        );
        assert_eq!(model.visual_document.raw_bytes(), before);
        assert_local_draft_mutation_denied(
            model.visual_document.update_comment(identity_id, "changed"),
            artifact.key,
        );
        assert_eq!(model.visual_document.raw_bytes(), before);
        assert_local_draft_mutation_denied(model.visual_document.remove(identity_id), artifact.key);
        assert_eq!(model.visual_document.raw_bytes(), before);
        assert_local_draft_mutation_denied(
            model.visual_document.move_up(identity_id),
            artifact.key,
        );
        assert_eq!(model.visual_document.raw_bytes(), before);
        assert_local_draft_mutation_denied(
            model.visual_document.move_down(identity_id),
            artifact.key,
        );
        assert_eq!(model.visual_document.raw_bytes(), before);

        for key in [
            "mysql-plugin-registry",
            "mysql-component-registry",
            "mariadb-plugin-registry",
        ] {
            let runtime = database_artifact(key);
            assert_eq!(database_visual_parser(runtime), None, "{key}");
            assert!(!visual_selector_contains(runtime), "{key}");
        }
        assert!(
            artifacts_for(DatabaseConfigProduct::MariaDb).all(|candidate| {
                candidate.default_file_name != Some("auto.cnf")
                    && candidate.component != DatabaseConfigComponent::ComponentRegistry
            })
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
                "# dbserver nettype hostname service options\n\
gbaseserver onsoctcp 192.0.2.10 9088 g=g_cluster_1\n",
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
            let before = document.raw_bytes().to_vec();
            let id = document
                .rows()
                .first()
                .unwrap_or_else(|| panic!("readable artifact {key} has no visible row"))
                .id();

            assert_eq!(document.kind(), kind);
            assert_eq!(document.output().text().unwrap(), source);
            assert!(
                document
                    .rows()
                    .iter()
                    .all(|row| !row.allows_local_draft_mutation())
            );
            assert!(kind.read_only_notice().unwrap().contains("只读展示"));
            assert_local_draft_mutation_denied(VisualDocument::competition_skeleton(kind), key);
            assert_local_draft_mutation_denied(
                document.add_statement(None, "new_key", "new_value"),
                key,
            );
            assert_eq!(document.raw_bytes(), before);
            assert_local_draft_mutation_denied(document.add_container(None, "new_group", ""), key);
            assert_eq!(document.raw_bytes(), before);
            assert_local_draft_mutation_denied(document.add_comment(None, "new comment"), key);
            assert_eq!(document.raw_bytes(), before);
            assert_local_draft_mutation_denied(
                document.update_statement(id, "changed", "value"),
                key,
            );
            assert_eq!(document.raw_bytes(), before);
            assert_local_draft_mutation_denied(document.update_comment(id, "changed comment"), key);
            assert_eq!(document.raw_bytes(), before);
            assert_local_draft_mutation_denied(document.remove(id), key);
            assert_eq!(document.raw_bytes(), before);
            assert_local_draft_mutation_denied(document.move_up(id), key);
            assert_eq!(document.raw_bytes(), before);
            assert_local_draft_mutation_denied(document.move_down(id), key);
            assert_eq!(document.raw_bytes(), before);
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
            assert_eq!(
                database_visual_parser(artifact),
                Some(DatabaseVisualParser::Line(LineConfigDialect::Toml)),
                "{key}"
            );
            assert!(visual_selector_contains(artifact), "{key}");
            assert_eq!(database_starter_contents(artifact), "", "{key}");
            assert!(
                DATABASE_CONFIG_SCHEMAS
                    .iter()
                    .all(|schema| !database_schema_matches_artifact(schema, artifact)),
                "{key} inherited the TiDB Server 8.5.7 schema"
            );

            let selection = VisualDocument::selection_document(kind).unwrap();
            assert_eq!(selection.kind(), kind, "{key}");
            assert_eq!(selection.output().text().unwrap(), "", "{key}");
            assert_eq!(
                selection.output().suggested_file_name(),
                default_file_name,
                "{key}"
            );

            let mut document = VisualDocument::parse_database(artifact, source).unwrap();
            let rows = document.rows();
            let id = rows
                .first()
                .unwrap_or_else(|| panic!("{key} has no visible TOML row"))
                .id();
            assert!(document.is_structured(), "{key}");
            assert_eq!(document.kind(), kind, "{key}");
            assert_eq!(document.raw_bytes(), source.as_bytes(), "{key}");
            assert_eq!(document.output().text().unwrap(), source, "{key}");
            assert_eq!(
                document.output().suggested_file_name(),
                default_file_name,
                "{key}"
            );
            assert!(
                rows.iter().all(|row| !row.allows_local_draft_mutation()),
                "{key} exposed a local draft row"
            );

            let notice = kind.read_only_notice().unwrap();
            assert!(notice.contains("只读展示"), "{key}");
            assert!(notice.contains("另存本地副本"), "{key}");
            assert!(notice.contains("不能应用/部署"), "{key}");
            assert_local_draft_mutation_denied(VisualDocument::database_starter(artifact), key);
            assert_local_draft_mutation_denied(VisualDocument::competition_skeleton(kind), key);

            let before = document.raw_bytes().to_vec();
            assert_local_draft_mutation_denied(
                document.add_statement(None, "new_key", "new_value"),
                key,
            );
            assert_eq!(document.raw_bytes(), before, "{key}");
            assert_local_draft_mutation_denied(document.add_container(None, "new", ""), key);
            assert_eq!(document.raw_bytes(), before, "{key}");
            assert_local_draft_mutation_denied(document.add_comment(None, "new comment"), key);
            assert_eq!(document.raw_bytes(), before, "{key}");
            assert_local_draft_mutation_denied(
                document.update_statement(id, "changed", "value"),
                key,
            );
            assert_eq!(document.raw_bytes(), before, "{key}");
            assert_local_draft_mutation_denied(document.update_comment(id, "changed"), key);
            assert_eq!(document.raw_bytes(), before, "{key}");
            assert_local_draft_mutation_denied(document.remove(id), key);
            assert_eq!(document.raw_bytes(), before, "{key}");
            assert_local_draft_mutation_denied(document.move_up(id), key);
            assert_eq!(document.raw_bytes(), before, "{key}");
            assert_local_draft_mutation_denied(document.move_down(id), key);
            assert_eq!(document.raw_bytes(), before, "{key}");
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
        assert_ne!(gnode_options.component, gcluster_options.component);
        assert!(
            artifacts_for(DatabaseConfigProduct::GBase8a)
                .all(|artifact| artifact.default_file_name != Some("gnode.cnf")),
            "the UI catalog must not invent gnode.cnf"
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
            let other_artifact = database_artifact(other_key);
            let kind = VisualDocumentKind::Database(artifact);
            let source = format!(
                "{{\r\n  \"role\": \"{role}\",\r\n  \"host\": \"db01\",\r\n  \"password\": \"{secret}\"\r\n}}"
            );

            assert_eq!(artifact.product, DatabaseConfigProduct::GBase8a, "{key}");
            assert_eq!(artifact.component, component, "{key}");
            assert_ne!(artifact.component, other_artifact.component, "{key}");
            assert_eq!(
                database_artifact_display_label(artifact),
                display_label,
                "{key}"
            );
            assert_eq!(kind.artifact_label(), display_label, "{key}");
            assert_ne!(
                database_artifact_display_label(artifact),
                database_artifact_display_label(other_artifact),
                "{key} kept an ambiguous selector label"
            );
            assert_eq!(artifact.dialect, DatabaseConfigDialect::Json, "{key}");
            assert!(artifact.is_file_visual_readable(), "{key}");
            assert!(!artifact.allows_lossless_local_draft(), "{key}");
            assert_eq!(line_dialect(artifact), None, "{key}");
            assert_eq!(
                structured_dialect(artifact),
                Some(StructuredConfigDialect::Json),
                "{key}"
            );
            assert_eq!(
                database_visual_parser(artifact),
                Some(DatabaseVisualParser::Structured(
                    StructuredConfigDialect::Json
                )),
                "{key}"
            );
            assert!(visual_selector_contains(artifact), "{key}");
            assert_eq!(
                artifact.default_file_name,
                Some("cluster_common.cnf"),
                "{key}"
            );
            assert_eq!(database_starter_contents(artifact), "", "{key}");

            let selection = VisualDocument::selection_document(kind).unwrap();
            assert_eq!(selection.kind(), kind, "{key}");
            assert_ne!(
                selection.kind(),
                VisualDocumentKind::Database(other_artifact),
                "{key} selected the other cluster_common.cnf role"
            );
            assert_eq!(selection.output().text().unwrap(), "", "{key}");
            assert_eq!(
                selection.output().suggested_file_name(),
                "cluster_common.cnf",
                "{key}"
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
            assert_eq!(document.kind(), kind, "{key}");
            assert_ne!(
                document.kind(),
                VisualDocumentKind::Database(other_artifact),
                "{key} parsed as the other component"
            );
            assert_eq!(document.raw_bytes(), source.as_bytes(), "{key}");
            assert_eq!(document.output().text().unwrap(), source, "{key}");
            assert_eq!(
                document.output().suggested_file_name(),
                "cluster_common.cnf",
                "{key}"
            );
            assert!(document.contains_sensitive_values(), "{key}");
            assert!(!document.can_copy(), "{key}");
            assert!(password.sensitive, "{key}");
            assert_eq!(password.preview(), REDACTED_SCHEMA_VALUE, "{key}");
            assert!(password.arguments().is_none(), "{key}");
            assert!(!format!("{document:?}{rows:?}").contains(secret), "{key}");
            assert!(
                rows.iter().all(|row| !row.allows_local_draft_mutation()),
                "{key} exposed a local draft mutation"
            );

            let notice = kind.read_only_notice().unwrap();
            assert!(notice.contains("只读展示"), "{key}");
            assert!(notice.contains("另存本地副本"), "{key}");
            assert!(notice.contains("不能应用/部署"), "{key}");
            assert_local_draft_mutation_denied(VisualDocument::database_starter(artifact), key);
            assert_local_draft_mutation_denied(VisualDocument::competition_skeleton(kind), key);

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
            assert_local_draft_mutation_denied(
                document.update_statement(id, "changed", "value"),
                key,
            );
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
    }

    #[test]
    fn gbase_8a_generated_json_authkey_is_redacted_and_blocks_whole_document_copy() {
        const SOURCE: &str = r#"{"AUTHKEY":"K9z7Q2"}"#;
        const SENTINEL: &str = "K9z7Q2";

        for key in [
            "gbase-8a-gnode-cluster-common",
            "gbase-8a-gcluster-cluster-common",
        ] {
            let artifact = database_artifact(key);
            let document = VisualDocument::parse_database(artifact, SOURCE).unwrap();
            let rows = document.rows();
            let authkey = rows
                .iter()
                .find(|row| row.name() == Some("AUTHKEY"))
                .unwrap_or_else(|| panic!("{key} lost the AUTHKEY member"));

            assert!(document.is_structured(), "{key}");
            assert_eq!(document.raw_bytes(), SOURCE.as_bytes(), "{key}");
            assert!(document.contains_sensitive_values(), "{key}");
            assert!(!document.can_copy(), "{key}");
            assert!(authkey.sensitive, "{key}");
            assert!(authkey.arguments().is_none(), "{key}");
            assert!(!authkey.preview().contains(SENTINEL), "{key}");
            assert!(
                rows.iter().all(|row| {
                    row.arguments() != Some(SENTINEL) && !row.preview().contains(SENTINEL)
                }),
                "{key} exposed the AUTHKEY value through a row"
            );
            assert!(
                !format!("{document:?}{rows:?}").contains(SENTINEL),
                "{key} leaked the AUTHKEY value through Debug"
            );
        }
    }

    #[test]
    fn yashandb_23_5_4_100_schema_is_exact_read_only_metadata_and_never_serialized() {
        const SOURCE: &str = concat!(
            "ARCH_CLEAN_IGNORE_MODE=BOTH\r\n",
            "AUDIT_LOG_FILE_COUNT=500\r\n",
            "AUDIT_QUEUE_WRITE=FALSE\r\n",
            "AUDIT_RECORD_TABLE=FALSE\r\n",
            "DIN_SSL_ENABLE=ON\r\n",
            "ENABLE_SEPARATE_DUTY=TRUE\r\n",
            "ENCRYPT_TYPE=TLCP\r\n",
            "HA_ELECTION_TIMEOUT=12\r\n",
            "HA_SSL_ENABLE=ON\r\n",
            "LISTENER_LOG_ENABLED=TRUE\r\n",
            "MAX_LOGIN_WORKERS=4\r\n",
            "REDOFILE_IO_MODE=SYNC\r\n",
            "RUN_LOG_LEVEL=DEBUG\r\n",
            "SSL_ENABLE=ON\r\n",
            "UNIFIED_AUDITING=TRUE\r\n",
            "ssl_enable=OFF\r\n",
            "ARCHIVE_DEST_1=standby-1\r\n",
            "MAX_SESSIONS=2048",
        );
        let expected = [
            ("ARCH_CLEAN_IGNORE_MODE", "BOTH", "NONE"),
            ("AUDIT_LOG_FILE_COUNT", "500", "200"),
            ("AUDIT_QUEUE_WRITE", "FALSE", "TRUE"),
            ("AUDIT_RECORD_TABLE", "FALSE", "TRUE"),
            ("DIN_SSL_ENABLE", "ON", "OFF"),
            ("ENABLE_SEPARATE_DUTY", "TRUE", "FALSE"),
            ("ENCRYPT_TYPE", "TLCP", "SSL"),
            ("HA_ELECTION_TIMEOUT", "12", "9"),
            ("HA_SSL_ENABLE", "ON", "OFF"),
            ("LISTENER_LOG_ENABLED", "TRUE", "FALSE"),
            ("MAX_LOGIN_WORKERS", "4", "1"),
            ("REDOFILE_IO_MODE", "SYNC", "DSYNC"),
            ("RUN_LOG_LEVEL", "DEBUG", "INFO"),
            ("SSL_ENABLE", "ON", "OFF"),
            ("UNIFIED_AUDITING", "TRUE", "FALSE"),
        ];
        let artifact = database_artifact("yashandb-yasdb-ini");
        let kind = VisualDocumentKind::Database(artifact);
        let schema_options = DATABASE_CONFIG_SCHEMAS
            .iter()
            .filter(|schema| database_schema_matches_artifact(schema, artifact))
            .collect::<Vec<_>>();
        assert_eq!(schema_options.len(), 1);
        let schema = schema_options[0];
        assert_eq!(DATABASE_CONFIG_SCHEMAS.len(), 18);
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
        assert!(schema.version_label.contains("v23.5.4.100 exact"));
        assert_eq!(
            DATABASE_CONFIG_SCHEMAS
                .iter()
                .flat_map(|schema| schema.parameters)
                .filter(|parameter| parameter.documented_default_for_display().is_some())
                .count(),
            20
        );

        let catalog = registered_database_config_schema_catalog().unwrap();
        let exact_target = DatabaseConfigSchemaTarget {
            product: DatabaseConfigProduct::Yashan,
            version: DatabaseConfigVersion::new_with_revision(23, 5, 4, 100),
            edition_key: Some("official-doc-family-23.5.4.100"),
            component: DatabaseConfigComponent::Server,
            artifact_key: artifact.key,
        };
        assert_eq!(catalog.lookup(exact_target), Ok(schema));
        for edition_key in [None, Some("enterprise"), Some("ai-edition")] {
            assert_eq!(
                catalog.lookup(DatabaseConfigSchemaTarget {
                    edition_key,
                    ..exact_target
                }),
                Err(DatabaseConfigSchemaLookupError::EditionMismatch)
            );
        }
        for version in [
            DatabaseConfigVersion::new(23, 5, 4),
            DatabaseConfigVersion::new_with_revision(23, 5, 4, 99),
            DatabaseConfigVersion::new_with_revision(23, 5, 4, 101),
        ] {
            assert_eq!(
                catalog.lookup(DatabaseConfigSchemaTarget {
                    version,
                    ..exact_target
                }),
                Err(DatabaseConfigSchemaLookupError::VersionMismatch)
            );
        }

        let document = VisualDocument::parse_database(artifact, SOURCE).unwrap();
        let mut model = model_with_visual_document(document);
        let raw_before = model.visual_document.raw_bytes().to_vec();
        let output_before = model.visual_document.output().text().unwrap().to_owned();
        let permission_before = kind.allows_lossless_local_draft();
        let row_permissions_before = model
            .visual_rows
            .iter()
            .map(VisualRow::allows_local_draft_mutation)
            .collect::<Vec<_>>();
        let can_copy_before = model.can_copy_visual();

        assert!(!permission_before);
        assert!(can_copy_before);
        assert!(model.current_database_schema().is_none());
        for (key, _, _) in expected {
            let row = model
                .visual_rows
                .iter()
                .find(|row| row.name() == Some(key))
                .unwrap_or_else(|| panic!("missing unselected YashanDB row {key}"));
            assert!(matches!(
                row.database_parameter(),
                DatabaseParameterMatch::NotApplicable
            ));
            assert!(database_parameter_status(Some(row), None).is_none());
        }

        assert!(model.select_database_schema_from_registry(schema, DATABASE_CONFIG_SCHEMAS));
        assert!(std::ptr::eq(
            model.current_database_schema().unwrap(),
            schema
        ));
        assert_eq!(
            model
                .visual_rows
                .iter()
                .filter(|row| matches!(
                    row.database_parameter(),
                    DatabaseParameterMatch::Matched(_)
                ))
                .count(),
            15
        );
        for (key, current_value, documented_default) in expected {
            let row = model
                .visual_rows
                .iter()
                .find(|row| row.name() == Some(key))
                .unwrap_or_else(|| panic!("missing matched YashanDB row {key}"));
            let DatabaseParameterMatch::Matched(parameter) = row.database_parameter() else {
                panic!("YashanDB row {key} did not match its root uppercase metadata");
            };
            assert_eq!(parameter.container_path, None, "{key}");
            assert_eq!(parameter.canonical_key, key, "{key}");
            assert!(key.bytes().all(|byte| !byte.is_ascii_lowercase()), "{key}");
            assert_eq!(row.arguments(), Some(current_value), "{key}");
            assert_eq!(
                parameter.documented_default_for_display().as_deref(),
                Some(documented_default),
                "{key}"
            );
            let status = database_parameter_status(Some(row), Some(schema)).unwrap();
            assert!(status.contains("container=<root>"), "{key}: {status}");
            assert!(
                status.contains(&format!("canonical={key}")),
                "{key}: {status}"
            );
            assert!(
                status.contains(&format!(
                    "{DOCUMENTED_DEFAULT_STATUS_LABEL}：{documented_default}。"
                )),
                "{key}: {status}"
            );
            let (editor_name, editor_value) = visual_editor_values(row);
            assert_eq!(editor_name, key, "{key}");
            assert_eq!(editor_value, current_value, "{key}");
            assert_ne!(editor_value, documented_default, "{key}");
        }

        for (key, current_value) in [
            ("ssl_enable", "OFF"),
            ("ARCHIVE_DEST_1", "standby-1"),
            ("MAX_SESSIONS", "2048"),
        ] {
            let row = model
                .visual_rows
                .iter()
                .find(|row| row.name() == Some(key))
                .unwrap_or_else(|| panic!("missing VisibleUnvalidated YashanDB row {key}"));
            assert_eq!(row.arguments(), Some(current_value), "{key}");
            assert!(matches!(
                row.database_parameter(),
                DatabaseParameterMatch::VisibleUnvalidated
            ));
            let status = database_parameter_status(Some(row), Some(schema)).unwrap();
            assert!(status.contains("VisibleUnvalidated"), "{key}");
            assert!(!status.contains(DOCUMENTED_DEFAULT_STATUS_LABEL), "{key}");
        }

        let schema_status = database_schema_status(Some(schema));
        assert!(schema_status.contains("v23.5.4.100 exact"));
        assert!(schema_status.contains("official-doc-family-23.5.4.100"));
        assert!(schema_status.contains("Partial"));
        assert!(schema_status.contains(LOCAL_DRAFT_SCOPE_NOTICE));
        assert_eq!(model.visual_document.raw_bytes(), raw_before);
        assert_eq!(
            model.visual_document.output().text().unwrap(),
            output_before
        );
        assert_eq!(kind.allows_lossless_local_draft(), permission_before);
        assert_eq!(
            model
                .visual_rows
                .iter()
                .map(VisualRow::allows_local_draft_mutation)
                .collect::<Vec<_>>(),
            row_permissions_before
        );
        assert_eq!(model.can_copy_visual(), can_copy_before);
        assert!(
            !model
                .visual_document
                .output()
                .text()
                .unwrap()
                .contains(DOCUMENTED_DEFAULT_STATUS_LABEL)
        );
        assert_eq!(database_starter_contents(artifact), "");
        assert_local_draft_mutation_denied(
            VisualDocument::database_starter(artifact),
            artifact.key,
        );
        assert_local_draft_mutation_denied(
            VisualDocument::competition_skeleton(kind),
            artifact.key,
        );
        let notice = kind.read_only_notice().unwrap();
        assert!(notice.contains("另存本地副本"));
        assert!(notice.contains("不能应用/部署"));

        let save_payload = ConfigSavePayload::Visual(model.visual_document.output());
        assert_eq!(save_payload.suggested_file_name(), "yasdb.ini");
        let ConfigSavePayload::Visual(save_output) = save_payload else {
            panic!("YashanDB read-only copy used the wrong save payload");
        };
        assert_eq!(save_output.text().unwrap(), SOURCE);

        let id = model
            .visual_rows
            .iter()
            .find(|row| row.name() == Some("SSL_ENABLE"))
            .unwrap()
            .id();
        model.selected_visual_node = Some(id);
        assert!(!model.can_mutate_selected_local_draft_row());
        let before = model.visual_document.raw_bytes().to_vec();
        assert_local_draft_mutation_denied(
            model
                .visual_document
                .add_statement(None, "NEW_PARAMETER", "value"),
            artifact.key,
        );
        assert_eq!(model.visual_document.raw_bytes(), before);
        assert_local_draft_mutation_denied(
            model.visual_document.add_container(None, "new", ""),
            artifact.key,
        );
        assert_eq!(model.visual_document.raw_bytes(), before);
        assert_local_draft_mutation_denied(
            model.visual_document.add_comment(None, "new comment"),
            artifact.key,
        );
        assert_eq!(model.visual_document.raw_bytes(), before);
        assert_local_draft_mutation_denied(
            model
                .visual_document
                .update_statement(id, "SSL_ENABLE", "OFF"),
            artifact.key,
        );
        assert_eq!(model.visual_document.raw_bytes(), before);
        assert_local_draft_mutation_denied(
            model.visual_document.update_comment(id, "changed"),
            artifact.key,
        );
        assert_eq!(model.visual_document.raw_bytes(), before);
        assert_local_draft_mutation_denied(model.visual_document.remove(id), artifact.key);
        assert_eq!(model.visual_document.raw_bytes(), before);
        assert_local_draft_mutation_denied(model.visual_document.move_up(id), artifact.key);
        assert_eq!(model.visual_document.raw_bytes(), before);
        assert_local_draft_mutation_denied(model.visual_document.move_down(id), artifact.key);
        assert_eq!(model.visual_document.raw_bytes(), before);
    }

    #[test]
    fn yashandb_23_5_yasdb_ini_is_selectable_byte_exact_and_fully_read_only() {
        let artifact = database_artifact("yashandb-yasdb-ini");
        let kind = VisualDocumentKind::Database(artifact);
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
        assert_eq!(
            database_visual_parser(artifact),
            Some(DatabaseVisualParser::Line(LineConfigDialect::FlatKeyValue))
        );
        assert!(visual_selector_contains(artifact));
        assert!(database_product_has_visual_files(
            DatabaseConfigProduct::Yashan
        ));
        assert_eq!(
            first_database_visual_artifact(DatabaseConfigProduct::Yashan)
                .map(|candidate| candidate.key),
            Some("yashandb-yasdb-ini")
        );
        assert_eq!(artifact.default_file_name, Some("yasdb.ini"));
        assert_eq!(database_starter_contents(artifact), "");
        assert_eq!(
            DATABASE_CONFIG_SCHEMAS
                .iter()
                .filter(|schema| database_schema_matches_artifact(schema, artifact))
                .count(),
            1,
            "yasdb.ini must expose exactly one reviewed fixed-version schema"
        );

        let selection = VisualDocument::selection_document(kind).unwrap();
        assert_eq!(selection.kind(), kind);
        assert_eq!(selection.output().text().unwrap(), "");
        assert_eq!(selection.output().suggested_file_name(), "yasdb.ini");

        let mut document = VisualDocument::parse_database(artifact, source).unwrap();
        let rows = document.rows();
        let id = rows
            .first()
            .expect("representative yasdb.ini must expose a row")
            .id();
        assert!(document.is_structured());
        assert_eq!(document.kind(), kind);
        assert_eq!(document.raw_bytes(), source.as_bytes());
        assert_eq!(document.output().text().unwrap(), source);
        assert_eq!(document.output().suggested_file_name(), "yasdb.ini");
        assert!(rows.iter().all(|row| !row.allows_local_draft_mutation()));
        for key in ["LISTENER_ADDR", "MAX_SESSIONS", "UNKNOWN_23_5_KEY"] {
            assert!(
                rows.iter().any(|row| row.name() == Some(key)),
                "yasdb.ini row {key} was not visible"
            );
        }

        let notice = kind.read_only_notice().unwrap();
        assert!(notice.contains("只读展示"));
        assert!(notice.contains("另存本地副本"));
        assert!(notice.contains("不能应用/部署"));
        assert_local_draft_mutation_denied(
            VisualDocument::database_starter(artifact),
            artifact.key,
        );
        assert_local_draft_mutation_denied(
            VisualDocument::competition_skeleton(kind),
            artifact.key,
        );

        let before = document.raw_bytes().to_vec();
        assert_local_draft_mutation_denied(
            document.add_statement(None, "NEW_KEY", "new-value"),
            artifact.key,
        );
        assert_eq!(document.raw_bytes(), before);
        assert_local_draft_mutation_denied(
            document.add_container(None, "new-group", ""),
            artifact.key,
        );
        assert_eq!(document.raw_bytes(), before);
        assert_local_draft_mutation_denied(document.add_comment(None, "new comment"), artifact.key);
        assert_eq!(document.raw_bytes(), before);
        assert_local_draft_mutation_denied(
            document.update_statement(id, "CHANGED", "value"),
            artifact.key,
        );
        assert_eq!(document.raw_bytes(), before);
        assert_local_draft_mutation_denied(
            document.update_comment(id, "changed comment"),
            artifact.key,
        );
        assert_eq!(document.raw_bytes(), before);
        assert_local_draft_mutation_denied(document.remove(id), artifact.key);
        assert_eq!(document.raw_bytes(), before);
        assert_local_draft_mutation_denied(document.move_up(id), artifact.key);
        assert_eq!(document.raw_bytes(), before);
        assert_local_draft_mutation_denied(document.move_down(id), artifact.key);
        assert_eq!(document.raw_bytes(), before);
    }

    #[test]
    fn yashandb_23_5_vendor_binary_artifacts_never_enter_or_read_as_text() {
        for key in ["yashandb-spfile", "yashandb-password-file"] {
            let artifact = database_artifact(key);
            let kind = VisualDocumentKind::Database(artifact);

            assert_eq!(artifact.product, DatabaseConfigProduct::Yashan, "{key}");
            assert_eq!(
                artifact.dialect,
                DatabaseConfigDialect::VendorBinary,
                "{key}"
            );
            assert!(!artifact.is_file_visual_readable(), "{key}");
            assert!(!artifact.allows_lossless_local_draft(), "{key}");
            assert_eq!(line_dialect(artifact), None, "{key}");
            assert_eq!(structured_dialect(artifact), None, "{key}");
            assert_eq!(database_visual_parser(artifact), None, "{key}");
            assert!(!visual_selector_contains(artifact), "{key}");
            assert!(VisualDocument::parse_database(artifact, "MUST_NOT_PARSE=1").is_err());
            assert!(VisualDocument::selection_document(kind).is_err());
            assert!(
                VisualDocument::read_local(kind, std::path::Path::new("must-not-be-read")).is_err(),
                "{key} accepted a text-file read"
            );
            assert_eq!(database_starter_contents(artifact), "", "{key}");
            assert_local_draft_mutation_denied(VisualDocument::database_starter(artifact), key);
            assert_local_draft_mutation_denied(VisualDocument::competition_skeleton(kind), key);
        }
    }

    #[test]
    fn gcware_catalog_document_is_nested_byte_exact_and_never_deployable() {
        let artifact = database_artifact("gbase-8a-gcware-config");
        let kind = VisualDocumentKind::Database(artifact);
        let source = "totem {\r\n\tversion: 2\r\n\tinterface {\r\n\t\tmember {\r\n\t\t\tmemberaddr: 10.0.0.1\r\n\t\t}\r\n\t}\r\n}\r\n";
        let mut document = VisualDocument::parse_database(artifact, source).unwrap();
        let rows = document.rows();
        let named = |name: &str| {
            rows.iter()
                .find(|row| row.name() == Some(name))
                .unwrap_or_else(|| panic!("missing gcware row {name}"))
        };
        let totem = named("totem");
        let interface = named("interface");
        let member = named("member");
        let memberaddr = named("memberaddr");

        assert_eq!(
            database_visual_parser(artifact),
            Some(DatabaseVisualParser::Structured(
                StructuredConfigDialect::Gcware
            ))
        );
        assert!(visual_selector_contains(artifact));
        assert_eq!(document.output().text().unwrap(), source);
        assert_eq!(interface.parent, Some(totem.id()));
        assert_eq!(member.parent, Some(interface.id()));
        assert_eq!(memberaddr.parent, Some(member.id()));
        assert!(rows.iter().all(|row| !row.allows_local_draft_mutation()));

        let notice = kind.read_only_notice().unwrap();
        assert!(notice.contains("另存本地副本"));
        assert!(notice.contains("不能应用/部署"));
        assert_local_draft_mutation_denied(
            VisualDocument::competition_skeleton(kind),
            artifact.key,
        );
        assert_local_draft_mutation_denied(
            document.update_statement(memberaddr.id(), "memberaddr", "10.0.0.2"),
            artifact.key,
        );
        assert_eq!(document.output().text().unwrap(), source);
    }

    #[test]
    fn sequoia_quick_deploy_catalog_artifacts_are_selectable_read_only_and_byte_exact() {
        const CLUSTER_DEFAULT: &str = concat!(
            "role,groupName,hostName,serviceName,dbPath\r\n",
            "\r\n",
            "catalog,SYSCatalogGroup,localhost,11800,[installPath]/database/catalog/11800\r\n",
            "\r\n",
            "coord,SYSCoord,localhost,11810,[installPath]/database/coord/11810\r\n",
            "\r\n",
            "data,group1,localhost,11820,[installPath]/database/data/11820\r\n",
            "data,group2,localhost,11830,[installPath]/database/data/11830\r\n",
            "data,group3,localhost,11840,[installPath]/database/data/11840\r\n",
            "\r\n",
            "# Note: This configuration file only supports cluster mode, doesn't support standalone mode.\r\n",
        );
        const SQL_NOTE: &str = "# Note: coordAddr, '-' means the first coord in sdb.conf. You can configure it by format hostName1:serviceName1 or [hostname1:serviceName1,hostname2:serviceName2]\r\n";
        let sql_default = |port| {
            format!(
                "instanceName,port,databaseDir,coordAddr\r\nmyinst,{port},[installPath]/database/{port},-\r\n\r\n{SQL_NOTE}"
            )
        };

        for (
            key,
            default_file_name,
            expected_database_dialect,
            expected_structured_dialect,
            source,
            expected_comment,
        ) in [
            (
                "sequoiadb-quick-deploy-cluster",
                "sequoiadb.conf",
                DatabaseConfigDialect::SequoiaQuickDeployClusterCsv,
                StructuredConfigDialect::SequoiaQuickDeployClusterCsv,
                CLUSTER_DEFAULT.to_owned(),
                "only supports cluster mode",
            ),
            (
                "sequoiadb-quick-deploy-mysql",
                "mysql.conf",
                DatabaseConfigDialect::SequoiaQuickDeploySqlInstanceCsv,
                StructuredConfigDialect::SequoiaQuickDeploySqlInstanceCsv,
                sql_default(3306),
                "coordAddr",
            ),
            (
                "sequoiadb-quick-deploy-mariadb",
                "mariadb.conf",
                DatabaseConfigDialect::SequoiaQuickDeploySqlInstanceCsv,
                StructuredConfigDialect::SequoiaQuickDeploySqlInstanceCsv,
                sql_default(6101),
                "coordAddr",
            ),
            (
                "sequoiadb-quick-deploy-postgresql",
                "postgresql.conf",
                DatabaseConfigDialect::SequoiaQuickDeploySqlInstanceCsv,
                StructuredConfigDialect::SequoiaQuickDeploySqlInstanceCsv,
                sql_default(5432),
                "coordAddr",
            ),
        ] {
            let artifact = database_artifact(key);
            let kind = VisualDocumentKind::Database(artifact);

            assert_eq!(artifact.dialect, expected_database_dialect, "{key}");
            assert_eq!(line_dialect(artifact), None, "{key} used a line dialect");
            assert_eq!(
                structured_dialect(artifact),
                Some(expected_structured_dialect),
                "{key} lost its dedicated structured dialect"
            );
            assert_eq!(
                database_visual_parser(artifact),
                Some(DatabaseVisualParser::Structured(
                    expected_structured_dialect
                )),
                "{key} selected the wrong parser"
            );
            assert!(
                visual_selector_contains(artifact),
                "{key} left the selector"
            );
            assert!(!kind.allows_lossless_local_draft(), "{key} became mutable");
            assert_eq!(artifact.default_file_name, Some(default_file_name), "{key}");

            let selection = VisualDocument::selection_document(kind).unwrap();
            assert_eq!(selection.kind(), kind);
            assert_eq!(selection.output().text().unwrap(), "", "{key}");
            assert_eq!(selection.output().suggested_file_name(), default_file_name);

            let document = VisualDocument::parse_database(artifact, &source).unwrap();
            let VisualDocument::Structured {
                document: structured,
                ..
            } = &document
            else {
                panic!("{key} did not use the structured document facade");
            };
            assert_eq!(
                structured.dialect(),
                expected_structured_dialect,
                "{key} used the wrong structured dialect"
            );
            assert!(
                document.is_structured(),
                "{key} representative input became opaque"
            );
            assert_eq!(document.raw_bytes(), source.as_bytes(), "{key}");
            assert_eq!(document.output().text().unwrap(), source.as_str(), "{key}");
            assert_eq!(
                document.output().suggested_file_name(),
                default_file_name,
                "{key}"
            );
            assert!(
                document
                    .rows()
                    .iter()
                    .all(|row| !row.allows_local_draft_mutation()),
                "{key} exposed a mutable row"
            );
            let comments = document
                .rows()
                .into_iter()
                .filter(|row| row.kind() == VisualNodeKind::Comment)
                .collect::<Vec<_>>();
            assert_eq!(comments.len(), 1, "{key} lost its official comment");
            assert!(
                comments[0].preview().contains(expected_comment),
                "{key} hid its official comment"
            );
            assert!(!comments[0].sensitive, "{key} redacted an ordinary comment");
            assert!(
                document.can_copy(),
                "{key} safe official default was blocked"
            );
        }
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
            let artifact = database_artifact(key);
            let document = VisualDocument::parse_database(artifact, cross_role_source).unwrap();
            let rows = document.rows();

            assert!(
                !document.is_structured(),
                "{key} accepted a cross-role header"
            );
            assert!(document.contains_sensitive_values(), "{key}");
            assert!(!document.can_copy(), "{key}");
            assert_eq!(document.raw_bytes(), cross_role_source.as_bytes(), "{key}");
            assert_eq!(
                document.output().text().unwrap(),
                cross_role_source,
                "{key}"
            );
            assert_eq!(
                document.output().suggested_file_name(),
                default_file_name,
                "{key} suggested the wrong catalog file"
            );
            assert_eq!(rows.len(), 1, "{key} cross-role input was not whole opaque");
            assert_eq!(rows[0].kind(), VisualNodeKind::Opaque, "{key}");
            assert!(rows[0].sensitive, "{key}");
            assert_eq!(rows[0].preview(), REDACTED_SCHEMA_VALUE, "{key}");
            assert!(
                rows.iter().all(|row| !row.allows_local_draft_mutation()),
                "{key} exposed a mutable cross-role row"
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
        let artifact = database_artifact("sequoiadb-quick-deploy-mariadb");
        let document = VisualDocument::parse_database(artifact, &source).unwrap();
        let rows = document.rows();
        let opaque = rows
            .iter()
            .filter(|row| row.kind() == VisualNodeKind::Opaque)
            .collect::<Vec<_>>();

        assert!(document.is_structured());
        assert!(document.contains_sensitive_values());
        assert!(!document.can_copy());
        assert_eq!(document.output().text().unwrap(), source);
        assert_eq!(document.output().suggested_file_name(), "mariadb.conf");
        assert_eq!(opaque.len(), 2);
        assert!(
            opaque
                .iter()
                .all(|row| row.sensitive && row.preview() == REDACTED_SCHEMA_VALUE)
        );
        assert!(rows.iter().any(|row| {
            row.kind() == VisualNodeKind::Statement
                && row.sensitive
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
            assert!(document.contains_sensitive_values(), "{key}");
            assert!(!document.can_copy(), "{key}");
            assert!(opaque.sensitive, "{key}");
            assert_eq!(opaque.preview(), REDACTED_SCHEMA_VALUE, "{key}");
            assert!(!format!("{document:?}{rows:?}").contains(secret), "{key}");
            assert_eq!(document.output().text().unwrap(), source, "{key}");
            assert_eq!(database_starter_contents(artifact), "", "{key}");

            let notice = kind.read_only_notice().unwrap();
            assert!(notice.contains("只读展示"), "{key}");
            assert!(notice.contains("不能应用/部署"), "{key}");
            assert_local_draft_mutation_denied(VisualDocument::database_starter(artifact), key);
            assert_local_draft_mutation_denied(VisualDocument::competition_skeleton(kind), key);

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
            assert_local_draft_mutation_denied(
                document.update_statement(opaque_id, "changed", "value"),
                key,
            );
            assert_eq!(document.raw_bytes(), before, "{key}");
            assert_local_draft_mutation_denied(
                document.update_comment(opaque_id, "changed comment"),
                key,
            );
            assert_eq!(document.raw_bytes(), before, "{key}");
            assert_local_draft_mutation_denied(document.remove(opaque_id), key);
            assert_eq!(document.raw_bytes(), before, "{key}");
            assert_local_draft_mutation_denied(document.move_up(opaque_id), key);
            assert_eq!(document.raw_bytes(), before, "{key}");
            assert_local_draft_mutation_denied(document.move_down(opaque_id), key);
            assert_eq!(document.raw_bytes(), before, "{key}");
        }
    }

    #[test]
    fn read_only_status_distinguishes_generated_and_vendor_schema_artifacts() {
        let generated =
            VisualDocumentKind::Database(database_artifact("mysql-persisted-variables"))
                .read_only_notice()
                .unwrap();
        assert!(generated.contains("只读展示"));
        assert!(generated.contains("生成"));

        let vendor = VisualDocumentKind::Database(database_artifact("opengauss-om-cluster-xml"))
            .read_only_notice()
            .unwrap();
        assert!(vendor.contains("只读展示"));
        assert!(vendor.contains("schema"));
        assert!(vendor.contains("版本"));
    }

    #[test]
    fn sensitive_structured_documents_remain_non_copyable_and_redacted() {
        let secret = "do-not-copy-this-secret";
        let source =
            format!("{{\"Version\": 2, \"mysql_server\": {{\"password\": \"{secret}\"}}}}\n");
        let document =
            VisualDocument::parse_database(database_artifact("mysql-persisted-variables"), &source)
                .unwrap();
        let rows = document.rows();

        assert!(document.contains_sensitive_values());
        assert!(!document.can_copy());
        assert!(rows.iter().any(|row| row.sensitive));
        assert!(
            rows.iter()
                .filter(|row| row.sensitive)
                .all(|row| row.preview() == "[sensitive value redacted]")
        );
        assert!(!format!("{document:?}").contains(secret));
        assert!(!format!("{rows:?}").contains(secret));
        assert_eq!(document.output().text().unwrap(), source);
    }

    #[test]
    fn foreign_document_node_ids_fail_closed_without_mutation() {
        let nginx = VisualDocument::nginx_competition_skeleton().unwrap();
        let nginx_id = nginx.rows().first().unwrap().id();
        let apache = VisualDocument::apache_competition_skeleton().unwrap();
        let apache_id = apache.rows().first().unwrap().id();
        let line =
            VisualDocument::database_starter(database_artifact("mysql-option-file")).unwrap();
        let line_id = line.rows().first().unwrap().id();

        for (mut document, foreign_id) in [(nginx, apache_id), (apache, line_id), (line, nginx_id)]
        {
            let before = document.raw_bytes().to_vec();
            assert!(document.remove(foreign_id).is_err());
            assert!(
                document
                    .add_comment(Some(foreign_id), "must not be inserted")
                    .is_err()
            );
            assert_eq!(document.raw_bytes(), before);
        }
    }

    #[test]
    fn lifecycle_rejects_late_save_completions() {
        let generated = generate_from_values(
            NginxSiteKind::ReverseProxy,
            DEFAULT_SERVER_NAME,
            DEFAULT_LISTEN_PORT,
            DEFAULT_STATIC_ROOT,
            DEFAULT_UPSTREAM,
            true,
        )
        .unwrap();
        let mut model = ConfigGeneratorModel::new(generated);
        model.activate();
        let lease = model.activation_generation;
        assert!(model.accepts(lease));
        model.deactivate();
        assert!(!model.accepts(lease));
        model.activate();
        assert!(!model.accepts(lease));
    }

    #[test]
    fn preview_is_bounded_and_never_interprets_text() {
        let long = (0..600)
            .map(|index| format!("<script>{index}</script>"))
            .collect::<Vec<_>>()
            .join("\n");
        let (lines, truncated) = bounded_preview_lines(&long);
        assert_eq!(lines.len(), MAX_PREVIEW_LINES);
        assert!(truncated);
        assert_eq!(lines[0], "<script>0</script>");
    }
}
