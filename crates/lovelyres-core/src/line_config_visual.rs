//! Lossless, bounded visual model for line-oriented service configuration.
//!
//! This module recognizes a deliberately small syntax surface shared by many
//! database products. It does not claim that a key or value is meaningful for
//! a particular product, version, edition, component, or runtime. Unknown and
//! unsafe structures remain byte-exact opaque nodes.

use std::{
    fmt,
    fs::{File, OpenOptions},
    io::{Read, Write},
    ops::Range,
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{
    CoreError, CoreResult, database_config::DatabaseConfigProduct,
    database_config_schema::DatabaseConfigVersion,
};
use zeroize::Zeroizing;

pub const MAX_LINE_CONFIG_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_LINE_CONFIG_NODES: usize = 65_536;
pub const MAX_LINE_CONFIG_DEPTH: usize = 128;
pub const MAX_LINE_CONFIG_EDIT_BYTES: usize = 256 * 1024;
const MAX_LINE_CONFIG_ROW_PREVIEW_BYTES: usize = 512;

static NEXT_LINE_CONFIG_REVISION: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LineConfigDialect {
    MySqlOption,
    Ini,
    PostgresConf,
    PgHba,
    PgIdent,
    FlatKeyValue,
    Whitespace,
    Toml,
    JavaProperties,
}

impl LineConfigDialect {
    pub const fn label(self) -> &'static str {
        match self {
            Self::MySqlOption => "MySQL option file",
            Self::Ini => "INI",
            Self::PostgresConf => "PostgreSQL configuration",
            Self::PgHba => "PostgreSQL HBA",
            Self::PgIdent => "PostgreSQL ident map",
            Self::FlatKeyValue => "flat key/value",
            Self::Whitespace => "whitespace-delimited",
            Self::Toml => "TOML",
            Self::JavaProperties => "Java properties",
        }
    }

    pub const fn suggested_file_name(self) -> &'static str {
        match self {
            Self::MySqlOption => "my.cnf",
            Self::Ini => "database.ini",
            Self::PostgresConf => "postgresql.conf",
            Self::PgHba => "pg_hba.conf",
            Self::PgIdent => "pg_ident.conf",
            Self::FlatKeyValue | Self::Whitespace => "database.conf",
            Self::Toml => "database.toml",
            Self::JavaProperties => "server.properties",
        }
    }

    const fn supports_sections(self) -> bool {
        matches!(self, Self::MySqlOption | Self::Ini)
    }

    const fn supports_tables(self) -> bool {
        matches!(self, Self::Toml)
    }

    const fn record_only(self) -> bool {
        matches!(self, Self::PgHba | Self::PgIdent)
    }
}

/// Closed, typed syntax policy for a database target.
///
/// Callers can select a product and version, but cannot directly grant a
/// syntax capability. Versions outside the audited table remain fail-closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LineConfigTargetPolicy {
    database_target: Option<(DatabaseConfigProduct, DatabaseConfigVersion)>,
    mariadb_optional_includedir: bool,
}

impl LineConfigTargetPolicy {
    const UNVERSIONED: Self = Self {
        database_target: None,
        mariadb_optional_includedir: false,
    };

    pub const fn for_database_config(
        product: DatabaseConfigProduct,
        version: DatabaseConfigVersion,
    ) -> Self {
        // This is intentionally an exact allowlist rather than a numerical
        // threshold. MariaDB's official release-tag sources show the feature in
        // 11.4.10, 11.8.6, and 12.2.2, but not in the adjacent audited tags
        // 11.4.9, 11.8.5, 12.0.2, or 12.1.2. Unknown patches fail closed.
        // https://github.com/MariaDB/server/blob/mariadb-11.4.10/mysys/my_default.c#L681-L717
        // https://github.com/MariaDB/server/blob/mariadb-11.8.6/mysys/my_default.c#L681-L717
        // https://github.com/MariaDB/server/blob/mariadb-12.2.2/mysys/my_default.c#L681-L717
        let mariadb_optional_includedir = matches!(product, DatabaseConfigProduct::MariaDb)
            && matches!(
                (
                    version.major(),
                    version.minor(),
                    version.patch(),
                    version.revision()
                ),
                (11, 4, 10, 0) | (11, 8, 6, 0) | (12, 2, 2, 0)
            );
        Self {
            database_target: Some((product, version)),
            mariadb_optional_includedir,
        }
    }

    const fn supports_mariadb_optional_includedir(self) -> bool {
        self.mariadb_optional_includedir
    }
}

/// Revision-scoped identifier. Every successful edit reparses the document,
/// so callers must discard all previously selected identifiers.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LineConfigNodeId(u128);

impl LineConfigNodeId {
    pub const fn get(self) -> u128 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LineConfigNodeKind {
    Section,
    Table,
    Entry,
    Include,
    Record,
    Comment,
    Opaque,
}

impl LineConfigNodeKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Section => "section",
            Self::Table => "table",
            Self::Entry => "entry",
            Self::Include => "include",
            Self::Record => "record",
            Self::Comment => "comment",
            Self::Opaque => "opaque source",
        }
    }

    const fn is_container(self) -> bool {
        matches!(self, Self::Section | Self::Table)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct LineConfigRow {
    id: LineConfigNodeId,
    parent: Option<LineConfigNodeId>,
    depth: usize,
    kind: LineConfigNodeKind,
    name: Option<Zeroizing<String>>,
    value: Option<Zeroizing<String>>,
    preview: Zeroizing<String>,
    child_count: usize,
    truncated: bool,
    editable: bool,
    sensitive: bool,
}

impl fmt::Debug for LineConfigRow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LineConfigRow")
            .field("id", &self.id)
            .field("parent", &self.parent)
            .field("depth", &self.depth)
            .field("kind", &self.kind)
            .field("name_present", &self.name.is_some())
            .field("value_present", &self.value.is_some())
            .field("preview_bytes", &self.preview.len())
            .field("child_count", &self.child_count)
            .field("truncated", &self.truncated)
            .field("editable", &self.editable)
            .field("sensitive", &self.sensitive)
            .finish()
    }
}

impl LineConfigRow {
    pub const fn id(&self) -> LineConfigNodeId {
        self.id
    }

    pub const fn parent(&self) -> Option<LineConfigNodeId> {
        self.parent
    }

    pub const fn depth(&self) -> usize {
        self.depth
    }

    pub const fn kind(&self) -> LineConfigNodeKind {
        self.kind
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_ref().map(|value| value.as_str())
    }

    /// Sensitive values are never returned through the visual row API.
    pub fn value(&self) -> Option<&str> {
        self.value.as_ref().map(|value| value.as_str())
    }

    pub fn preview(&self) -> &str {
        self.preview.as_str()
    }

    pub const fn child_count(&self) -> usize {
        self.child_count
    }

    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    pub const fn editable(&self) -> bool {
        self.editable
    }

    pub const fn sensitive(&self) -> bool {
        self.sensitive
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct LineConfigOutput {
    dialect: LineConfigDialect,
    bytes: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for LineConfigOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LineConfigOutput")
            .field("dialect", &self.dialect)
            .field("bytes", &self.bytes.len())
            .field("utf8", &std::str::from_utf8(&self.bytes).is_ok())
            .finish()
    }
}

impl LineConfigOutput {
    pub const fn dialect(&self) -> LineConfigDialect {
        self.dialect
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn text(&self) -> CoreResult<&str> {
        std::str::from_utf8(&self.bytes).map_err(|_| {
            CoreError::validation(
                "line configuration",
                "contains non-UTF-8 bytes; save the preserved bytes instead of copying text",
            )
        })
    }

    pub fn text_lossy(&self) -> Zeroizing<String> {
        Zeroizing::new(String::from_utf8_lossy(&self.bytes).into_owned())
    }

    pub const fn suggested_file_name(&self) -> &'static str {
        self.dialect.suggested_file_name()
    }

    /// Writes to a newly-created path and never overwrites an existing file.
    /// A post-create I/O failure may leave a partial file: deleting by path here
    /// would introduce a replacement race against an unrelated file.
    pub fn write_new(&self, destination: &Path) -> CoreResult<PathBuf> {
        validate_destination(destination)?;
        validate_size(self.bytes.len())?;

        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(destination)
            .map_err(|source| CoreError::io("create line configuration", destination, source))?;
        file.write_all(&self.bytes)
            .map_err(|source| CoreError::io("write line configuration", destination, source))?;
        file.flush()
            .map_err(|source| CoreError::io("flush line configuration", destination, source))?;
        file.sync_all()
            .map_err(|source| CoreError::io("sync line configuration", destination, source))?;
        Ok(destination.to_path_buf())
    }
}

#[derive(Clone)]
pub struct LineConfigVisualDocument {
    dialect: LineConfigDialect,
    target_policy: LineConfigTargetPolicy,
    source: Zeroizing<Vec<u8>>,
    nodes: Vec<NodeRecord>,
    structured: bool,
    whole_opaque: bool,
    contains_sensitive_values: bool,
}

impl fmt::Debug for LineConfigVisualDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LineConfigVisualDocument")
            .field("dialect", &self.dialect)
            .field("target_policy", &self.target_policy)
            .field("bytes", &self.source.len())
            .field("nodes", &self.nodes.len())
            .field("structured", &self.structured)
            .field("whole_opaque", &self.whole_opaque)
            .field("contains_sensitive_values", &self.contains_sensitive_values)
            .finish()
    }
}

#[derive(Clone, Debug)]
struct NodeRecord {
    id: LineConfigNodeId,
    parent: Option<LineConfigNodeId>,
    depth: usize,
    kind: LineConfigNodeKind,
    span: Range<usize>,
    header_span: Range<usize>,
    name_span: Option<Range<usize>>,
    value_span: Option<Range<usize>>,
    child_count: usize,
}

#[derive(Clone, Debug)]
struct ParsedNode {
    kind: LineConfigNodeKind,
    span: Range<usize>,
    header_span: Range<usize>,
    name_span: Option<Range<usize>>,
    value_span: Option<Range<usize>>,
    children: Vec<ParsedNode>,
}

impl LineConfigVisualDocument {
    pub fn blank(dialect: LineConfigDialect) -> Self {
        Self::blank_with_target_policy(dialect, LineConfigTargetPolicy::UNVERSIONED)
    }

    pub fn blank_with_target_policy(
        dialect: LineConfigDialect,
        target_policy: LineConfigTargetPolicy,
    ) -> Self {
        Self {
            dialect,
            target_policy,
            source: Zeroizing::new(Vec::new()),
            nodes: Vec::new(),
            structured: true,
            whole_opaque: false,
            contains_sensitive_values: false,
        }
    }

    pub fn parse(dialect: LineConfigDialect, text: &str) -> CoreResult<Self> {
        Self::parse_bytes(dialect, text.as_bytes().to_vec())
    }

    pub fn parse_with_target_policy(
        dialect: LineConfigDialect,
        target_policy: LineConfigTargetPolicy,
        text: &str,
    ) -> CoreResult<Self> {
        Self::parse_bytes_with_target_policy(dialect, target_policy, text.as_bytes().to_vec())
    }

    pub fn parse_bytes(dialect: LineConfigDialect, source: Vec<u8>) -> CoreResult<Self> {
        Self::parse_bytes_with_target_policy(dialect, LineConfigTargetPolicy::UNVERSIONED, source)
    }

    pub fn parse_bytes_with_target_policy(
        dialect: LineConfigDialect,
        target_policy: LineConfigTargetPolicy,
        source: Vec<u8>,
    ) -> CoreResult<Self> {
        let mut source = Zeroizing::new(source);
        validate_size(source.len())?;
        if source.contains(&0) || std::str::from_utf8(&source).is_err() {
            return Ok(Self::opaque(
                dialect,
                target_policy,
                std::mem::take(&mut *source),
            ));
        }
        match parse_document(dialect, target_policy, &source, false) {
            Ok(parsed) => Ok(Self::from_parsed(
                dialect,
                target_policy,
                std::mem::take(&mut *source),
                parsed,
            )),
            Err(()) => Ok(Self::opaque(
                dialect,
                target_policy,
                std::mem::take(&mut *source),
            )),
        }
    }

    pub fn read_local(dialect: LineConfigDialect, path: &Path) -> CoreResult<Self> {
        Self::read_local_with_target_policy(dialect, LineConfigTargetPolicy::UNVERSIONED, path)
    }

    pub fn read_local_with_target_policy(
        dialect: LineConfigDialect,
        target_policy: LineConfigTargetPolicy,
        path: &Path,
    ) -> CoreResult<Self> {
        validate_import_path(path)?;
        let file = File::open(path)
            .map_err(|source| CoreError::io("open local line configuration", path, source))?;
        let metadata = file
            .metadata()
            .map_err(|source| CoreError::io("inspect local line configuration", path, source))?;
        let length = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
        validate_size(length)?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(length.min(MAX_LINE_CONFIG_BYTES)));
        file.take((MAX_LINE_CONFIG_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|source| CoreError::io("read local line configuration", path, source))?;
        validate_size(bytes.len())?;
        Self::parse_bytes_with_target_policy(dialect, target_policy, std::mem::take(&mut *bytes))
    }

    pub const fn dialect(&self) -> LineConfigDialect {
        self.dialect
    }

    /// False means at least one source region is intentionally opaque.
    pub const fn is_structured(&self) -> bool {
        self.structured
    }

    pub const fn contains_sensitive_values(&self) -> bool {
        self.contains_sensitive_values
    }

    pub fn raw_bytes(&self) -> &[u8] {
        &self.source
    }

    pub fn output(&self) -> LineConfigOutput {
        LineConfigOutput {
            dialect: self.dialect,
            bytes: Zeroizing::new(self.source.to_vec()),
        }
    }

    pub fn rows(&self) -> Vec<LineConfigRow> {
        self.nodes.iter().map(|node| self.row(node)).collect()
    }

    pub fn root_rows(&self) -> Vec<LineConfigRow> {
        self.nodes
            .iter()
            .filter(|node| node.parent.is_none())
            .map(|node| self.row(node))
            .collect()
    }

    pub fn children(&self, parent: LineConfigNodeId) -> CoreResult<Vec<LineConfigRow>> {
        let node = self.require_node(parent)?;
        if !node.kind.is_container() {
            return Err(invalid_edit("selected parent is not a section or table"));
        }
        Ok(self
            .nodes
            .iter()
            .filter(|node| node.parent == Some(parent))
            .map(|node| self.row(node))
            .collect())
    }

    pub fn row_by_id(&self, id: LineConfigNodeId) -> Option<LineConfigRow> {
        self.node(id).map(|node| self.row(node))
    }

    pub fn add_entry(
        &mut self,
        parent: Option<LineConfigNodeId>,
        key: &str,
        value: Option<&str>,
    ) -> CoreResult<()> {
        let fragment = entry_fragment(self.dialect, key, value)?;
        self.insert_node(parent, fragment, LineConfigNodeKind::Entry)
    }

    pub fn add_include(
        &mut self,
        parent: Option<LineConfigNodeId>,
        directive: &str,
        target: &str,
    ) -> CoreResult<()> {
        let fragment = include_fragment(self.dialect, self.target_policy, directive, target)?;
        self.insert_node(parent, fragment, LineConfigNodeKind::Include)
    }

    pub fn add_section(&mut self, name: &str) -> CoreResult<()> {
        if !self.dialect.supports_sections() {
            return Err(invalid_edit("selected dialect does not support sections"));
        }
        let fragment = container_fragment(self.dialect, None, name, LineConfigNodeKind::Section)?;
        self.insert_node(None, fragment, LineConfigNodeKind::Section)
    }

    pub fn add_table(&mut self, parent: Option<LineConfigNodeId>, name: &str) -> CoreResult<()> {
        if !self.dialect.supports_tables() {
            return Err(invalid_edit("selected dialect does not support tables"));
        }
        let parent_name = parent
            .map(|id| self.require_container_name(id))
            .transpose()?;
        let fragment = container_fragment(
            self.dialect,
            parent_name.as_ref().map(|value| value.as_str()),
            name,
            LineConfigNodeKind::Table,
        )?;
        self.insert_node(parent, fragment, LineConfigNodeKind::Table)
    }

    pub fn add_record(&mut self, parent: Option<LineConfigNodeId>, record: &str) -> CoreResult<()> {
        let (fragment, kind) = record_fragment(self.dialect, record)?;
        self.insert_node(parent, fragment, kind)
    }

    pub fn add_comment(&mut self, parent: Option<LineConfigNodeId>, text: &str) -> CoreResult<()> {
        let fragment = comment_fragment(self.dialect, text)?;
        self.insert_node(parent, fragment, LineConfigNodeKind::Comment)
    }

    pub fn update_entry(
        &mut self,
        id: LineConfigNodeId,
        key: &str,
        value: Option<&str>,
    ) -> CoreResult<()> {
        let node = self.require_node(id)?.clone();
        if !matches!(
            node.kind,
            LineConfigNodeKind::Entry | LineConfigNodeKind::Include
        ) {
            return Err(invalid_edit("selected node is not an entry"));
        }
        if self.node_sensitive(&node) {
            return Err(invalid_edit(
                "sensitive values require a dedicated secret input flow",
            ));
        }
        let fragment = if node.kind == LineConfigNodeKind::Include
            && self.dialect == LineConfigDialect::MySqlOption
        {
            include_fragment(
                self.dialect,
                self.target_policy,
                key,
                value.unwrap_or_default(),
            )?
        } else if let Some(styled_value) = value.filter(|_| node.value_span.is_some()) {
            styled_entry_fragment(self.dialect, &self.source, &node, key, styled_value)?
        } else if node.kind == LineConfigNodeKind::Include {
            include_fragment(
                self.dialect,
                self.target_policy,
                key,
                value.unwrap_or_default(),
            )?
        } else {
            entry_fragment(self.dialect, key, value)?
        };
        self.splice_and_reparse(node.header_span, &fragment)
    }

    pub fn update_container(&mut self, id: LineConfigNodeId, name: &str) -> CoreResult<()> {
        let node = self.require_node(id)?.clone();
        if !node.kind.is_container() {
            return Err(invalid_edit("selected node is not a section or table"));
        }
        if node.kind == LineConfigNodeKind::Table
            && self.nodes.iter().any(|candidate| {
                candidate.parent == Some(node.id) && candidate.kind == LineConfigNodeKind::Table
            })
        {
            return Err(invalid_edit(
                "tables with child tables cannot be renamed independently",
            ));
        }
        let parent_name = node
            .parent
            .map(|parent| self.require_container_name(parent))
            .transpose()?;
        let fragment = container_fragment(
            self.dialect,
            parent_name.as_ref().map(|value| value.as_str()),
            name,
            node.kind,
        )?;
        self.splice_and_reparse(node.header_span, &fragment)
    }

    pub fn update_record(&mut self, id: LineConfigNodeId, record: &str) -> CoreResult<()> {
        let node = self.require_node(id)?.clone();
        if !matches!(
            node.kind,
            LineConfigNodeKind::Record | LineConfigNodeKind::Include
        ) {
            return Err(invalid_edit("selected node is not an ordered record"));
        }
        if self.node_sensitive(&node) {
            return Err(invalid_edit(
                "sensitive values require a dedicated secret input flow",
            ));
        }
        let (fragment, kind) = record_fragment(self.dialect, record)?;
        if kind != node.kind {
            return Err(invalid_edit("record edit would change the node kind"));
        }
        self.splice_and_reparse(node.header_span, &fragment)
    }

    pub fn update_comment(&mut self, id: LineConfigNodeId, text: &str) -> CoreResult<()> {
        let node = self.require_node(id)?.clone();
        if node.kind != LineConfigNodeKind::Comment {
            return Err(invalid_edit("selected node is not a comment"));
        }
        if self.node_sensitive(&node) {
            return Err(invalid_edit(
                "sensitive comments require explicit raw replacement",
            ));
        }
        let fragment = comment_fragment(self.dialect, text)?;
        self.splice_and_reparse(node.header_span, &fragment)
    }

    pub fn remove(&mut self, id: LineConfigNodeId) -> CoreResult<()> {
        let node = self.require_node(id)?.clone();
        if self.whole_opaque {
            return Err(invalid_edit(
                "opaque source requires explicit raw replacement",
            ));
        }
        if node.kind == LineConfigNodeKind::Opaque {
            return Err(invalid_edit(
                "opaque logical records cannot be deleted by a structural edit",
            ));
        }
        self.splice_and_reparse(node.span, &[])
    }

    pub fn move_up(&mut self, id: LineConfigNodeId) -> CoreResult<()> {
        self.move_sibling(id, false)
    }

    pub fn move_down(&mut self, id: LineConfigNodeId) -> CoreResult<()> {
        self.move_sibling(id, true)
    }

    pub fn replace_raw(&mut self, source: Vec<u8>) -> CoreResult<()> {
        let replacement =
            Self::parse_bytes_with_target_policy(self.dialect, self.target_policy, source)?;
        *self = replacement;
        Ok(())
    }

    fn from_parsed(
        dialect: LineConfigDialect,
        target_policy: LineConfigTargetPolicy,
        source: Vec<u8>,
        parsed: ParsedDocument,
    ) -> Self {
        let revision = next_document_revision();
        let mut next_id = 1u64;
        let mut nodes = Vec::new();
        flatten_nodes(&parsed.nodes, None, 0, revision, &mut next_id, &mut nodes);
        let contains_sensitive_values = nodes.iter().any(|node| node_is_sensitive(&source, node));
        Self {
            dialect,
            target_policy,
            source: Zeroizing::new(source),
            nodes,
            structured: parsed.structured,
            whole_opaque: false,
            contains_sensitive_values,
        }
    }

    fn opaque(
        dialect: LineConfigDialect,
        target_policy: LineConfigTargetPolicy,
        source: Vec<u8>,
    ) -> Self {
        let revision = next_document_revision();
        let nodes = (!source.is_empty())
            .then_some(NodeRecord {
                id: revision_node_id(revision, 1),
                parent: None,
                depth: 0,
                kind: LineConfigNodeKind::Opaque,
                span: 0..source.len(),
                header_span: 0..source.len(),
                name_span: None,
                value_span: None,
                child_count: 0,
            })
            .into_iter()
            .collect();
        let contains_sensitive_values = contains_sensitive_marker(&source);
        Self {
            dialect,
            target_policy,
            source: Zeroizing::new(source),
            nodes,
            structured: false,
            whole_opaque: true,
            contains_sensitive_values,
        }
    }

    fn row(&self, node: &NodeRecord) -> LineConfigRow {
        let sensitive = self.node_sensitive(node);
        let name = node
            .name_span
            .as_ref()
            .map(|span| Zeroizing::new(bounded_field(&self.source[span.clone()])));
        let value = (!sensitive)
            .then(|| {
                node.value_span
                    .as_ref()
                    .map(|span| Zeroizing::new(bounded_field(&self.source[span.clone()])))
            })
            .flatten();
        let (preview, preview_truncated) = if sensitive {
            ("[sensitive value redacted]".to_owned(), false)
        } else {
            bounded_preview(&self.source[node.header_span.clone()])
        };
        let fields_fit = node
            .name_span
            .iter()
            .chain(node.value_span.iter())
            .all(|span| span.end.saturating_sub(span.start) <= MAX_LINE_CONFIG_EDIT_BYTES)
            && node.header_span.end.saturating_sub(node.header_span.start)
                <= MAX_LINE_CONFIG_EDIT_BYTES;
        LineConfigRow {
            id: node.id,
            parent: node.parent,
            depth: node.depth,
            kind: node.kind,
            name,
            value,
            preview: Zeroizing::new(preview),
            child_count: node.child_count,
            truncated: preview_truncated || !fields_fit,
            editable: !self.whole_opaque
                && fields_fit
                && !sensitive
                && node.kind != LineConfigNodeKind::Opaque,
            sensitive,
        }
    }

    fn node(&self, id: LineConfigNodeId) -> Option<&NodeRecord> {
        self.nodes.iter().find(|node| node.id == id)
    }

    fn require_node(&self, id: LineConfigNodeId) -> CoreResult<&NodeRecord> {
        self.node(id)
            .ok_or_else(|| invalid_edit("selected line configuration node is stale or missing"))
    }

    fn require_container_name(&self, id: LineConfigNodeId) -> CoreResult<Zeroizing<String>> {
        let node = self.require_node(id)?;
        if !node.kind.is_container() {
            return Err(invalid_edit("selected parent is not a section or table"));
        }
        let span = node
            .name_span
            .as_ref()
            .ok_or_else(|| invalid_edit("selected container has no safe name span"))?;
        Ok(Zeroizing::new(bounded_field(&self.source[span.clone()])))
    }

    fn node_sensitive(&self, node: &NodeRecord) -> bool {
        node_is_sensitive(&self.source, node)
    }

    fn insert_node(
        &mut self,
        parent: Option<LineConfigNodeId>,
        fragment: Zeroizing<Vec<u8>>,
        kind: LineConfigNodeKind,
    ) -> CoreResult<()> {
        if self.whole_opaque {
            return Err(invalid_edit(
                "opaque source requires explicit raw replacement",
            ));
        }
        if self.dialect == LineConfigDialect::MySqlOption
            && parent.is_none()
            && kind == LineConfigNodeKind::Entry
        {
            return Err(invalid_edit(
                "MySQL option entries require a preceding option group",
            ));
        }
        let insert_at = match parent {
            Some(parent_id) => {
                let parent = self.require_node(parent_id)?;
                if !parent.kind.is_container() {
                    return Err(invalid_edit("children require a section or table parent"));
                }
                if kind == LineConfigNodeKind::Section {
                    return Err(invalid_edit("INI sections are root nodes"));
                }
                if kind == LineConfigNodeKind::Table && parent.kind != LineConfigNodeKind::Table {
                    return Err(invalid_edit("nested tables require a table parent"));
                }
                if kind != LineConfigNodeKind::Table {
                    self.nodes
                        .iter()
                        .filter(|node| node.parent == Some(parent_id))
                        .find(|node| node.kind.is_container())
                        .map_or(parent.span.end, |node| node.span.start)
                } else {
                    parent.span.end
                }
            }
            None => {
                if !kind.is_container() {
                    self.nodes
                        .iter()
                        .filter(|node| node.parent.is_none())
                        .find(|node| node.kind.is_container())
                        .map_or(self.source.len(), |node| node.span.start)
                } else {
                    self.source.len()
                }
            }
        };
        let mut insertion = build_insertion(&self.source, insert_at, &fragment);
        // MySQL on Windows ignores a terminal include directive when the file
        // has no line terminator. Always make a newly generated terminal
        // include portable across the supported server platforms.
        if self.dialect == LineConfigDialect::MySqlOption
            && kind == LineConfigNodeKind::Include
            && insert_at == self.source.len()
            && !insertion.ends_with(b"\n")
        {
            insertion.extend_from_slice(preferred_newline(&self.source));
        }
        self.splice_and_reparse(insert_at..insert_at, &insertion)
    }

    fn move_sibling(&mut self, id: LineConfigNodeId, down: bool) -> CoreResult<()> {
        if self.whole_opaque {
            return Err(invalid_edit("opaque source cannot be structurally moved"));
        }
        let node = self.require_node(id)?.clone();
        if node.kind == LineConfigNodeKind::Opaque {
            return Err(invalid_edit(
                "opaque logical records cannot be structurally moved",
            ));
        }
        let siblings = self
            .nodes
            .iter()
            .filter(|candidate| candidate.parent == node.parent && candidate.depth == node.depth)
            .collect::<Vec<_>>();
        let index = siblings
            .iter()
            .position(|candidate| candidate.id == id)
            .expect("selected node exists in its sibling list");
        let other_index = if down {
            index.checked_add(1).filter(|next| *next < siblings.len())
        } else {
            index.checked_sub(1)
        }
        .ok_or_else(|| invalid_edit("selected node is already at the requested edge"))?;
        if siblings[other_index].kind == LineConfigNodeKind::Opaque {
            return Err(invalid_edit(
                "structural moves cannot cross an opaque logical record",
            ));
        }
        let first = if down { &node } else { siblings[other_index] };
        let second = if down { siblings[other_index] } else { &node };
        if first.span.end > second.span.start {
            return Err(invalid_edit("sibling source ranges overlap"));
        }
        let first_bytes = &self.source[first.span.clone()];
        let second_bytes = &self.source[second.span.clone()];
        let first_body_end = trailing_newlines_start(first_bytes);
        let second_body_end = trailing_newlines_start(second_bytes);
        let (first_body, first_newlines) = first_bytes.split_at(first_body_end);
        let (second_body, second_newlines) = second_bytes.split_at(second_body_end);
        let mut replacement = Zeroizing::new(Vec::with_capacity(
            second.span.end.saturating_sub(first.span.start),
        ));
        replacement.extend_from_slice(second_body);
        replacement.extend_from_slice(first_newlines);
        replacement.extend_from_slice(&self.source[first.span.end..second.span.start]);
        replacement.extend_from_slice(first_body);
        replacement.extend_from_slice(second_newlines);
        self.splice_and_reparse(first.span.start..second.span.end, &replacement)
    }

    fn splice_and_reparse(&mut self, range: Range<usize>, replacement: &[u8]) -> CoreResult<()> {
        if range.start > range.end || range.end > self.source.len() {
            return Err(invalid_edit("edit range is outside the current document"));
        }
        if replacement.len() > MAX_LINE_CONFIG_EDIT_BYTES {
            return Err(invalid_edit("one visual edit exceeds the edit-size limit"));
        }
        let new_len = self
            .source
            .len()
            .saturating_sub(range.end - range.start)
            .saturating_add(replacement.len());
        validate_size(new_len)?;
        let mut source = Zeroizing::new(Vec::with_capacity(new_len));
        source.extend_from_slice(&self.source[..range.start]);
        source.extend_from_slice(replacement);
        source.extend_from_slice(&self.source[range.end..]);
        let replacement = Self::parse_bytes_with_target_policy(
            self.dialect,
            self.target_policy,
            std::mem::take(&mut *source),
        )?;
        if replacement.whole_opaque && !replacement.source.is_empty() {
            return Err(invalid_edit("edit would make the complete document opaque"));
        }
        *self = replacement;
        Ok(())
    }
}

#[derive(Debug)]
struct ParsedDocument {
    nodes: Vec<ParsedNode>,
    structured: bool,
}

#[derive(Clone, Debug)]
struct PhysicalLine {
    full: Range<usize>,
    content: Range<usize>,
}

#[derive(Debug)]
struct ClassifiedLine {
    node: ParsedNode,
    table_path: Option<Vec<Range<usize>>>,
}

#[derive(Clone, Debug)]
struct ActiveTable {
    position: Vec<usize>,
    path: Vec<Range<usize>>,
}

fn parse_document(
    dialect: LineConfigDialect,
    target_policy: LineConfigTargetPolicy,
    source: &[u8],
    validating_fragment: bool,
) -> Result<ParsedDocument, ()> {
    let mut roots: Vec<ParsedNode> = Vec::new();
    let postgres_auth = matches!(
        dialect,
        LineConfigDialect::PgHba | LineConfigDialect::PgIdent
    );
    // PostgreSQL's authentication-file tokenizer does not consume a UTF-8 BOM.
    // Keep it in the first logical record so that the record fails closed instead
    // of making an invalid server file appear structurally editable.
    let mut cursor = if postgres_auth || dialect == LineConfigDialect::MySqlOption {
        0
    } else {
        bom_len(source)
    };
    let mut node_count = 0usize;
    let mut structured = true;
    let mut current_section: Option<usize> = None;
    let mut active_tables: Vec<ActiveTable> = Vec::new();

    while cursor < source.len() {
        let line = next_physical_line(source, cursor);
        cursor = line.full.end;
        if trim_dialect_space(dialect, source, line.content.clone()).is_empty() {
            continue;
        }

        let mut classified =
            if postgres_auth && postgres_record_line_continues(&source[line.content.clone()]) {
                let mut end = line.full.end;
                let mut content_end = line.content.end;
                while end < source.len() {
                    let continuation = next_physical_line(source, end);
                    end = continuation.full.end;
                    content_end = continuation.content.end;
                    if !postgres_record_line_continues(&source[continuation.content]) {
                        break;
                    }
                }
                cursor = end;
                let logical_line = PhysicalLine {
                    full: line.full.start..end,
                    content: line.content.start..content_end,
                };
                classify_line(dialect, target_policy, source, &logical_line)
            } else if dialect == LineConfigDialect::Toml
                && toml_line_is_table_like(source, &line)
                && !toml_line_is_supported_table(source, &line)
            {
                let end = toml_opaque_table_region_end(source, &line);
                cursor = end;
                ClassifiedLine {
                    node: opaque_node(line.full.start..end, line.content.start..end),
                    table_path: None,
                }
            } else if dialect == LineConfigDialect::JavaProperties
                && java_line_continues(&source[line.content.clone()])
            {
                let mut end = line.full.end;
                while end < source.len() {
                    let continuation = next_physical_line(source, end);
                    end = continuation.full.end;
                    if !java_line_continues(&source[continuation.content]) {
                        break;
                    }
                }
                cursor = end;
                ClassifiedLine {
                    node: opaque_node(line.full.start..end, line.content.start..end),
                    table_path: None,
                }
            } else if dialect == LineConfigDialect::Toml {
                if let Some(end) = toml_complex_value_end(source, &line) {
                    cursor = end;
                    ClassifiedLine {
                        node: opaque_node(line.full.start..end, line.content.start..end),
                        table_path: None,
                    }
                } else {
                    classify_line(dialect, target_policy, source, &line)
                }
            } else {
                classify_line(dialect, target_policy, source, &line)
            };

        // MySQL and MariaDB reject options that appear before the first
        // option group. Fragment validation is the only caller allowed to
        // classify a standalone entry because it later inserts that fragment
        // under an already-validated section.
        if !validating_fragment
            && dialect == LineConfigDialect::MySqlOption
            && current_section.is_none()
            && classified.node.kind == LineConfigNodeKind::Entry
        {
            classified = opaque_classification(&line);
        }
        // A terminal include without LF is ignored by MySQL on Windows. The
        // dialect is target-platform agnostic, and appending or moving another
        // row could silently activate it, so imported documents with this
        // boundary remain whole-document opaque. Fragment validation is safe
        // because generated terminal includes receive a newline on insertion.
        if !validating_fragment
            && dialect == LineConfigDialect::MySqlOption
            && classified.node.kind == LineConfigNodeKind::Include
            && line.full.end == source.len()
            && !source.ends_with(b"\n")
        {
            return Err(());
        }

        node_count = node_count.saturating_add(1);
        if node_count > MAX_LINE_CONFIG_NODES {
            return Err(());
        }
        structured &= classified.node.kind != LineConfigNodeKind::Opaque;

        let ambiguous_section_barrier = dialect.supports_sections()
            && classified.node.kind == LineConfigNodeKind::Opaque
            && source.get(trim_dialect_space(dialect, source, line.content.clone()).start)
                == Some(&b'[');
        if ambiguous_section_barrier {
            if let Some(index) = current_section.take() {
                roots[index].span.end = classified.node.span.start;
            }
            roots.push(classified.node);
            continue;
        }

        if dialect == LineConfigDialect::Toml
            && classified.node.kind == LineConfigNodeKind::Opaque
            && toml_line_is_table_like(source, &line)
        {
            for active in &active_tables {
                node_mut_at(&mut roots, &active.position).span.end = classified.node.span.start;
            }
            active_tables.clear();
            roots.push(classified.node);
            continue;
        }

        if classified.node.kind == LineConfigNodeKind::Section {
            if let Some(index) = current_section.take() {
                roots[index].span.end = classified.node.span.start;
            }
            let index = roots.len();
            roots.push(classified.node);
            current_section = Some(index);
            continue;
        }

        if classified.node.kind == LineConfigNodeKind::Table {
            let path = classified.table_path.ok_or(())?;
            let parent_index = active_tables.iter().rposition(|active| {
                active.path.len() < path.len() && table_path_is_prefix(source, &active.path, &path)
            });
            let keep = parent_index.map_or(0, |index| index + 1);
            for active in &active_tables[keep..] {
                node_mut_at(&mut roots, &active.position).span.end = classified.node.span.start;
            }
            active_tables.truncate(keep);
            if active_tables.len() >= MAX_LINE_CONFIG_DEPTH {
                return Err(());
            }
            let parent_position = parent_index
                .and_then(|index| active_tables.get(index))
                .map(|active| active.position.as_slice());
            let position = push_parsed_node(&mut roots, parent_position, classified.node);
            active_tables.push(ActiveTable { position, path });
            continue;
        }

        if dialect.supports_tables() {
            let parent = active_tables
                .last()
                .map(|active| active.position.as_slice());
            push_parsed_node(&mut roots, parent, classified.node);
        } else if let Some(index) = current_section {
            roots[index].children.push(classified.node);
        } else {
            roots.push(classified.node);
        }
    }

    if let Some(index) = current_section {
        roots[index].span.end = source.len();
    }
    for active in &active_tables {
        node_mut_at(&mut roots, &active.position).span.end = source.len();
    }
    Ok(ParsedDocument {
        nodes: roots,
        structured,
    })
}

fn classify_line(
    dialect: LineConfigDialect,
    target_policy: LineConfigTargetPolicy,
    source: &[u8],
    line: &PhysicalLine,
) -> ClassifiedLine {
    let trimmed = trim_dialect_space(dialect, source, line.content.clone());
    if matches!(
        dialect,
        LineConfigDialect::PgHba | LineConfigDialect::PgIdent
    ) {
        return classify_ordered_record(dialect, source, line, trimmed);
    }
    let first = source[trimmed.start];
    let is_comment = match dialect {
        LineConfigDialect::MySqlOption | LineConfigDialect::Ini => {
            matches!(first, b'#' | b';')
        }
        LineConfigDialect::JavaProperties => matches!(first, b'#' | b'!'),
        _ => first == b'#',
    };
    if is_comment {
        return ClassifiedLine {
            node: ParsedNode {
                kind: LineConfigNodeKind::Comment,
                span: line.full.clone(),
                header_span: trimmed.clone(),
                name_span: None,
                value_span: (trimmed.start + 1 < trimmed.end)
                    .then(|| trim_horizontal(source, trimmed.start + 1..trimmed.end)),
                children: Vec::new(),
            },
            table_path: None,
        };
    }

    match dialect {
        LineConfigDialect::MySqlOption | LineConfigDialect::Ini => {
            if let Some(section) = parse_section_header(dialect, source, trimmed.clone()) {
                return ClassifiedLine {
                    node: container_node(LineConfigNodeKind::Section, line, section.0, section.1),
                    table_path: None,
                };
            }
            if first == b'[' {
                return opaque_classification(line);
            }
        }
        LineConfigDialect::Toml => {
            if let Some((header, name)) = parse_toml_table_header(source, trimmed.clone()) {
                let Some(path) = split_toml_path(source, name.clone()) else {
                    return opaque_classification(line);
                };
                return ClassifiedLine {
                    node: container_node(LineConfigNodeKind::Table, line, header, name),
                    table_path: Some(path),
                };
            }
        }
        _ => {}
    }

    if dialect == LineConfigDialect::MySqlOption && matches!(first, b'!' | b'?') {
        if let Some((directive, target, header)) =
            parse_mysql_include(target_policy, source, trimmed.clone())
        {
            return ClassifiedLine {
                node: leaf_node(
                    LineConfigNodeKind::Include,
                    line,
                    header,
                    Some(directive),
                    Some(target),
                ),
                table_path: None,
            };
        }
        // Unknown, wrong-case, version-specific, or structurally unsafe
        // directives must remain byte-exact until a matching server parser
        // proves their meaning.
        return opaque_classification(line);
    }

    match dialect {
        LineConfigDialect::JavaProperties => classify_java_property(source, line, trimmed),
        LineConfigDialect::Whitespace => classify_whitespace_entry(source, line, trimmed),
        _ => classify_equals_entry(dialect, source, line, trimmed),
    }
}

fn classify_equals_entry(
    dialect: LineConfigDialect,
    source: &[u8],
    line: &PhysicalLine,
    trimmed: Range<usize>,
) -> ClassifiedLine {
    let comment = match if dialect == LineConfigDialect::MySqlOption {
        mysql_inline_hash(source, trimmed.clone())
    } else {
        inline_hash(source, trimmed.clone())
    } {
        Ok(comment) => comment,
        Err(()) => return opaque_classification(line),
    };
    let header = trim_dialect_space(
        dialect,
        source,
        trimmed.start..comment.unwrap_or(trimmed.end),
    );
    if header.is_empty() {
        return opaque_classification(line);
    }
    let equals = match if dialect == LineConfigDialect::MySqlOption {
        Ok(source[header.clone()]
            .iter()
            .position(|byte| *byte == b'=')
            .map(|offset| header.start + offset))
    } else {
        unquoted_byte(source, header.clone(), b'=')
    } {
        Ok(equals) => equals,
        Err(()) => return opaque_classification(line),
    };
    let Some(equals) = equals else {
        if dialect == LineConfigDialect::PostgresConf {
            return classify_postgres_whitespace_entry(source, line, header);
        }
        if dialect == LineConfigDialect::MySqlOption
            && !source[header.clone()]
                .iter()
                .any(|byte| is_mysql_space(*byte))
        {
            return ClassifiedLine {
                node: leaf_node(
                    LineConfigNodeKind::Entry,
                    line,
                    header.clone(),
                    Some(header),
                    None,
                ),
                table_path: None,
            };
        }
        return opaque_classification(line);
    };
    let key = trim_dialect_space(dialect, source, header.start..equals);
    let value = trim_dialect_space(dialect, source, equals + 1..header.end);
    if key.is_empty() || has_line_control(&source[key.clone()]) {
        return opaque_classification(line);
    }
    if dialect == LineConfigDialect::Toml
        && !toml_single_line_value_is_balanced(&source[value.clone()])
    {
        return opaque_classification(line);
    }
    let kind = if dialect == LineConfigDialect::PostgresConf
        && is_postgres_include_key(&source[key.clone()])
    {
        LineConfigNodeKind::Include
    } else {
        LineConfigNodeKind::Entry
    };
    ClassifiedLine {
        node: leaf_node(kind, line, header, Some(key), Some(value)),
        table_path: None,
    }
}

fn classify_postgres_whitespace_entry(
    source: &[u8],
    line: &PhysicalLine,
    header: Range<usize>,
) -> ClassifiedLine {
    let Some(tokens) = whitespace_tokens(source, header.clone()) else {
        return opaque_classification(line);
    };
    if tokens.len() < 2 {
        return opaque_classification(line);
    }
    let key = tokens[0].clone();
    let value = tokens[1].start..tokens.last().expect("at least two tokens").end;
    let kind = if is_postgres_include_key(&source[key.clone()]) {
        LineConfigNodeKind::Include
    } else {
        LineConfigNodeKind::Entry
    };
    ClassifiedLine {
        node: leaf_node(kind, line, header, Some(key), Some(value)),
        table_path: None,
    }
}

fn classify_whitespace_entry(
    source: &[u8],
    line: &PhysicalLine,
    trimmed: Range<usize>,
) -> ClassifiedLine {
    let comment = match inline_hash(source, trimmed.clone()) {
        Ok(comment) => comment,
        Err(()) => return opaque_classification(line),
    };
    let header = trim_horizontal(source, trimmed.start..comment.unwrap_or(trimmed.end));
    let Some(split) = source[header.clone()]
        .iter()
        .position(u8::is_ascii_whitespace)
        .map(|offset| header.start + offset)
    else {
        return ClassifiedLine {
            node: leaf_node(
                LineConfigNodeKind::Entry,
                line,
                header.clone(),
                Some(header),
                None,
            ),
            table_path: None,
        };
    };
    let key = trim_horizontal(source, header.start..split);
    let value = trim_horizontal(source, split..header.end);
    if key.is_empty() || value.is_empty() {
        return opaque_classification(line);
    }
    ClassifiedLine {
        node: leaf_node(
            LineConfigNodeKind::Entry,
            line,
            header,
            Some(key),
            Some(value),
        ),
        table_path: None,
    }
}

fn classify_ordered_record(
    dialect: LineConfigDialect,
    source: &[u8],
    line: &PhysicalLine,
    trimmed: Range<usize>,
) -> ClassifiedLine {
    let Some(lexed) = postgres_record_fields(source, line.content.clone()) else {
        return opaque_classification(line);
    };
    if lexed.fields.is_empty() {
        let Some(comment) = lexed.comment else {
            return opaque_classification(line);
        };
        return ClassifiedLine {
            node: ParsedNode {
                kind: LineConfigNodeKind::Comment,
                span: line.full.clone(),
                header_span: trimmed,
                name_span: None,
                value_span: (comment + 1 < line.content.end)
                    .then(|| trim_horizontal(source, comment + 1..line.content.end)),
                children: Vec::new(),
            },
            table_path: None,
        };
    }
    let header = trim_horizontal(
        source,
        trimmed.start..lexed.comment.unwrap_or(line.content.end),
    );
    let Some(record_type) = lexed.fields[0].single_token() else {
        return opaque_classification(line);
    };
    let include = lexed.fields.len() == 2
        && lexed.fields[1].single_token().is_some()
        && is_postgres_auth_include_key(record_type);
    let valid_shape = if include {
        true
    } else if dialect == LineConfigDialect::PgHba {
        postgres_hba_record_shape_is_safe(record_type, &lexed.fields)
    } else {
        // pg_ident.conf records are map, system user, database user.
        lexed.fields.len() >= 3
            && lexed.fields[..3]
                .iter()
                .all(|field| field.single_token().is_some())
    };
    if !valid_shape {
        return opaque_classification(line);
    }
    let kind = if include {
        LineConfigNodeKind::Include
    } else {
        LineConfigNodeKind::Record
    };
    ClassifiedLine {
        node: leaf_node(
            kind,
            line,
            header,
            Some(lexed.fields[0].span.clone()),
            (lexed.fields.len() > 1)
                .then(|| lexed.fields[1].span.start..lexed.fields.last().unwrap().span.end),
        ),
        table_path: None,
    }
}

fn postgres_hba_record_shape_is_safe(record_type: &[u8], fields: &[PostgresRecordField]) -> bool {
    if record_type == b"local" {
        return fields.len() >= 4
            && fields[3..]
                .iter()
                .all(|field| field.single_token().is_some());
    }
    if ![
        b"host".as_slice(),
        b"hostssl".as_slice(),
        b"hostnossl".as_slice(),
        b"hostgssenc".as_slice(),
        b"hostnogssenc".as_slice(),
    ]
    .contains(&record_type)
        || fields.len() < 5
    {
        return false;
    }
    let Some(address) = fields[3].single_token() else {
        return false;
    };
    if address.is_empty() {
        return false;
    }
    let numeric_address = std::str::from_utf8(address)
        .ok()
        .and_then(|value| value.parse::<std::net::IpAddr>().ok());
    let method_index = if let Some(address) = numeric_address {
        if fields.len() < 6 {
            return false;
        }
        let Some(mask) = fields[4]
            .single_token()
            .and_then(|value| std::str::from_utf8(value).ok())
            .and_then(|value| value.parse::<std::net::IpAddr>().ok())
        else {
            return false;
        };
        if !matches!(
            (address, mask),
            (std::net::IpAddr::V4(_), std::net::IpAddr::V4(_))
                | (std::net::IpAddr::V6(_), std::net::IpAddr::V6(_))
        ) {
            return false;
        }
        5
    } else {
        4
    };
    fields[method_index..]
        .iter()
        .all(|field| field.single_token().is_some())
}

fn classify_java_property(
    source: &[u8],
    line: &PhysicalLine,
    trimmed: Range<usize>,
) -> ClassifiedLine {
    let mut escaped = false;
    let mut separator = None;
    for index in trimmed.clone() {
        let byte = source[index];
        if escaped {
            escaped = false;
            continue;
        }
        if byte == b'\\' {
            escaped = true;
            continue;
        }
        if matches!(byte, b'=' | b':') || byte.is_ascii_whitespace() {
            separator = Some(index);
            break;
        }
    }
    if escaped {
        return opaque_classification(line);
    }
    let Some(separator) = separator else {
        return ClassifiedLine {
            node: leaf_node(
                LineConfigNodeKind::Entry,
                line,
                trimmed.clone(),
                Some(trimmed),
                None,
            ),
            table_path: None,
        };
    };
    let key = trim_horizontal(source, trimmed.start..separator);
    if key.is_empty() {
        return opaque_classification(line);
    }
    let mut value_start = separator;
    while value_start < trimmed.end && source[value_start].is_ascii_whitespace() {
        value_start += 1;
    }
    if value_start < trimmed.end && matches!(source[value_start], b'=' | b':') {
        value_start += 1;
    }
    while value_start < trimmed.end && source[value_start].is_ascii_whitespace() {
        value_start += 1;
    }
    ClassifiedLine {
        node: leaf_node(
            LineConfigNodeKind::Entry,
            line,
            trimmed.clone(),
            Some(key),
            Some(value_start..trimmed.end),
        ),
        table_path: None,
    }
}

fn parse_section_header(
    dialect: LineConfigDialect,
    source: &[u8],
    trimmed: Range<usize>,
) -> Option<(Range<usize>, Range<usize>)> {
    let header = if dialect == LineConfigDialect::MySqlOption {
        // MySQL handles a group before its ordinary end-comment scanner and
        // uses the first `]` as the terminator. Only the exact, unambiguous
        // subset is structural here; trailing bytes become an opaque scope
        // barrier in `parse_document`.
        trim_mysql_space(source, trimmed)
    } else {
        let comment = inline_hash(source, trimmed.clone()).ok().flatten();
        trim_horizontal(source, trimmed.start..comment.unwrap_or(trimmed.end))
    };
    if header.len() < 3 || source[header.start] != b'[' || source[header.end - 1] != b']' {
        return None;
    }
    let name = if dialect == LineConfigDialect::MySqlOption {
        trim_mysql_space_end(source, header.start + 1..header.end - 1)
    } else {
        trim_horizontal(source, header.start + 1..header.end - 1)
    };
    (!name.is_empty() && !source[name.clone()].contains(&b']')).then_some((header, name))
}

fn parse_toml_table_header(
    source: &[u8],
    trimmed: Range<usize>,
) -> Option<(Range<usize>, Range<usize>)> {
    let comment = inline_hash(source, trimmed.clone()).ok().flatten();
    let header = trim_horizontal(source, trimmed.start..comment.unwrap_or(trimmed.end));
    if header.len() < 3
        || source[header.start] != b'['
        || source[header.end - 1] != b']'
        || (header.len() >= 4 && source[header.start + 1] == b'[' && source[header.end - 2] == b']')
    {
        return None;
    }
    let name = trim_horizontal(source, header.start + 1..header.end - 1);
    (!name.is_empty()).then_some((header, name))
}

fn toml_line_is_table_like(source: &[u8], line: &PhysicalLine) -> bool {
    let trimmed = trim_horizontal(source, line.content.clone());
    source.get(trimmed.start) == Some(&b'[')
}

fn toml_line_is_supported_table(source: &[u8], line: &PhysicalLine) -> bool {
    let trimmed = trim_horizontal(source, line.content.clone());
    parse_toml_table_header(source, trimmed)
        .is_some_and(|(_, name)| split_toml_path(source, name).is_some())
}

fn toml_opaque_table_region_end(source: &[u8], line: &PhysicalLine) -> usize {
    let mut end = line.full.end;
    while end < source.len() {
        let next = next_physical_line(source, end);
        if toml_line_is_supported_table(source, &next) {
            break;
        }
        if let Some(complex_end) = toml_complex_value_end(source, &next) {
            end = complex_end;
            continue;
        }
        end = next.full.end;
    }
    end
}

fn parse_mysql_include(
    target_policy: LineConfigTargetPolicy,
    source: &[u8],
    trimmed: Range<usize>,
) -> Option<(Range<usize>, Range<usize>, Range<usize>)> {
    let full_header = trim_mysql_space(source, trimmed);
    if source[full_header.clone()].first() == Some(&b'?') {
        return parse_mariadb_optional_includedir(target_policy, source, full_header);
    }
    let comment = source[full_header.clone()]
        .iter()
        .position(|byte| *byte == b'#')
        .map(|offset| full_header.start + offset);
    let header = trim_mysql_space(
        source,
        full_header.start..comment.unwrap_or(full_header.end),
    );
    let bytes = &source[header.clone()];
    let directive_length = mysql_include_directive_length(bytes)?;
    if directive_length >= bytes.len() || !is_mysql_space(bytes[directive_length]) {
        return None;
    }
    let mut target_start = header.start + directive_length;
    while target_start < header.end && is_mysql_space(source[target_start]) {
        target_start += 1;
    }
    let directive = header.start..header.start + directive_length;
    let target = target_start..header.end;
    mysql_include_target_is_parseable(&source[target.clone()])
        .then_some((directive, target, header))
}

fn parse_mariadb_optional_includedir(
    target_policy: LineConfigTargetPolicy,
    source: &[u8],
    header: Range<usize>,
) -> Option<(Range<usize>, Range<usize>, Range<usize>)> {
    // MariaDB's `get_argument` trims whitespace only: `#` is path data, not an
    // end comment. The legacy `!include` comment truncation is therefore not a
    // safe parser for this version-gated directive.
    if !target_policy.supports_mariadb_optional_includedir()
        || source[header.clone()].contains(&b'#')
    {
        return None;
    }
    let bytes = &source[header.clone()];
    let directive_length = mariadb_optional_includedir_directive_length(bytes)?;
    if directive_length >= bytes.len() || !is_mysql_space(bytes[directive_length]) {
        return None;
    }
    let mut target_start = header.start + directive_length;
    while target_start < header.end && is_mysql_space(source[target_start]) {
        target_start += 1;
    }
    let directive = header.start..header.start + directive_length;
    let target = target_start..header.end;
    mysql_include_target_is_parseable(&source[target.clone()])
        .then_some((directive, target, header))
}

fn mysql_include_directive_length(bytes: &[u8]) -> Option<usize> {
    if bytes.first() != Some(&b'!') {
        return None;
    }
    let mut keyword_start = 1;
    while keyword_start < bytes.len() && is_mysql_space(bytes[keyword_start]) {
        keyword_start += 1;
    }
    for keyword in [b"includedir".as_slice(), b"include".as_slice()] {
        if bytes[keyword_start..].starts_with(keyword) {
            return Some(keyword_start + keyword.len());
        }
    }
    None
}

fn mysql_include_directive_is_safe(bytes: &[u8]) -> bool {
    mysql_include_directive_length(bytes) == Some(bytes.len())
}

fn mariadb_optional_includedir_directive_length(bytes: &[u8]) -> Option<usize> {
    if bytes.first() != Some(&b'?') {
        return None;
    }
    let mut keyword_start = 1;
    while keyword_start < bytes.len() && is_mysql_space(bytes[keyword_start]) {
        keyword_start += 1;
    }
    let keyword = b"includedir";
    bytes[keyword_start..]
        .starts_with(keyword)
        .then_some(keyword_start + keyword.len())
}

fn mysql_include_directive_is_safe_for_policy(
    target_policy: LineConfigTargetPolicy,
    bytes: &[u8],
) -> bool {
    mysql_include_directive_is_safe(bytes)
        || (target_policy.supports_mariadb_optional_includedir()
            && mariadb_optional_includedir_directive_length(bytes) == Some(bytes.len()))
}

fn mysql_include_target_is_parseable(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|target| {
        !target.is_empty()
            && target
                .chars()
                .all(|character| !character.is_control() && !matches!(character, '\'' | '"' | '#'))
    })
}

fn mysql_include_target_is_safe(bytes: &[u8]) -> bool {
    mysql_include_target_is_parseable(bytes)
        && !bytes
            .windows(2)
            .any(|pair| pair[0] == b'\\' && pair[1].is_ascii_whitespace())
}

fn split_toml_path(source: &[u8], range: Range<usize>) -> Option<Vec<Range<usize>>> {
    let mut output = Vec::new();
    let mut start = range.start;
    let mut cursor = range.start;
    let mut quote = None;
    let mut escaped = false;
    while cursor < range.end {
        let byte = source[cursor];
        if escaped {
            escaped = false;
            cursor += 1;
            continue;
        }
        if byte == b'\\' && quote == Some(b'"') {
            escaped = true;
            cursor += 1;
            continue;
        }
        if let Some(active) = quote {
            if byte == active {
                quote = None;
            }
            cursor += 1;
            continue;
        }
        if matches!(byte, b'\'' | b'"') {
            quote = Some(byte);
        } else if byte == b'.' {
            let segment = trim_horizontal(source, start..cursor);
            if segment.is_empty() {
                return None;
            }
            output.push(segment);
            if output.len() > MAX_LINE_CONFIG_DEPTH {
                return None;
            }
            start = cursor + 1;
        }
        cursor += 1;
    }
    if escaped || quote.is_some() {
        return None;
    }
    let segment = trim_horizontal(source, start..range.end);
    if segment.is_empty() {
        return None;
    }
    output.push(segment);
    (output.len() <= MAX_LINE_CONFIG_DEPTH).then_some(output)
}

fn table_path_is_prefix(source: &[u8], parent: &[Range<usize>], child: &[Range<usize>]) -> bool {
    parent
        .iter()
        .zip(child)
        .all(|(left, right)| source[left.clone()] == source[right.clone()])
}

fn container_node(
    kind: LineConfigNodeKind,
    line: &PhysicalLine,
    header: Range<usize>,
    name: Range<usize>,
) -> ParsedNode {
    ParsedNode {
        kind,
        span: line.full.start..line.full.end,
        header_span: header,
        name_span: Some(name),
        value_span: None,
        children: Vec::new(),
    }
}

fn leaf_node(
    kind: LineConfigNodeKind,
    line: &PhysicalLine,
    header: Range<usize>,
    name: Option<Range<usize>>,
    value: Option<Range<usize>>,
) -> ParsedNode {
    ParsedNode {
        kind,
        span: line.full.clone(),
        header_span: header,
        name_span: name,
        value_span: value,
        children: Vec::new(),
    }
}

fn opaque_node(span: Range<usize>, header_span: Range<usize>) -> ParsedNode {
    ParsedNode {
        kind: LineConfigNodeKind::Opaque,
        span,
        header_span,
        name_span: None,
        value_span: None,
        children: Vec::new(),
    }
}

fn opaque_classification(line: &PhysicalLine) -> ClassifiedLine {
    ClassifiedLine {
        node: opaque_node(line.full.clone(), line.content.clone()),
        table_path: None,
    }
}

fn push_parsed_node(
    roots: &mut Vec<ParsedNode>,
    parent_position: Option<&[usize]>,
    node: ParsedNode,
) -> Vec<usize> {
    match parent_position {
        Some(parent_position) => {
            let parent = node_mut_at(roots, parent_position);
            let index = parent.children.len();
            parent.children.push(node);
            let mut position = parent_position.to_vec();
            position.push(index);
            position
        }
        None => {
            let index = roots.len();
            roots.push(node);
            vec![index]
        }
    }
}

fn node_mut_at<'a>(roots: &'a mut [ParsedNode], position: &[usize]) -> &'a mut ParsedNode {
    let mut node = &mut roots[position[0]];
    for index in &position[1..] {
        node = &mut node.children[*index];
    }
    node
}

fn next_physical_line(source: &[u8], start: usize) -> PhysicalLine {
    let newline = source[start..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map(|offset| start + offset);
    let full_end = newline.map_or(source.len(), |index| index + 1);
    let mut content_end = newline.unwrap_or(source.len());
    if content_end > start && source[content_end - 1] == b'\r' {
        content_end -= 1;
    }
    PhysicalLine {
        full: start..full_end,
        content: start..content_end,
    }
}

fn bom_len(source: &[u8]) -> usize {
    usize::from(source.starts_with(&[0xEF, 0xBB, 0xBF])) * 3
}

fn trim_horizontal(source: &[u8], mut range: Range<usize>) -> Range<usize> {
    while range.start < range.end && matches!(source[range.start], b' ' | b'\t') {
        range.start += 1;
    }
    while range.start < range.end && matches!(source[range.end - 1], b' ' | b'\t') {
        range.end -= 1;
    }
    range
}

fn trim_mysql_space(source: &[u8], mut range: Range<usize>) -> Range<usize> {
    while range.start < range.end && is_mysql_space(source[range.start]) {
        range.start += 1;
    }
    while range.start < range.end && is_mysql_space(source[range.end - 1]) {
        range.end -= 1;
    }
    range
}

fn trim_mysql_space_end(source: &[u8], mut range: Range<usize>) -> Range<usize> {
    while range.start < range.end && is_mysql_space(source[range.end - 1]) {
        range.end -= 1;
    }
    range
}

fn is_mysql_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

fn trim_dialect_space(
    dialect: LineConfigDialect,
    source: &[u8],
    range: Range<usize>,
) -> Range<usize> {
    if dialect == LineConfigDialect::MySqlOption {
        trim_mysql_space(source, range)
    } else {
        trim_horizontal(source, range)
    }
}

fn inline_hash(source: &[u8], range: Range<usize>) -> Result<Option<usize>, ()> {
    inline_hash_with_escape_mode(source, range, true)
}

fn mysql_inline_hash(source: &[u8], range: Range<usize>) -> Result<Option<usize>, ()> {
    inline_hash_with_escape_mode(source, range, false)
}

fn inline_hash_with_escape_mode(
    source: &[u8],
    range: Range<usize>,
    escape_outside_quotes: bool,
) -> Result<Option<usize>, ()> {
    let mut quote = None;
    let mut escaped = false;
    let mut cursor = range.start;
    while cursor < range.end {
        let byte = source[cursor];
        if escaped {
            escaped = false;
            cursor += 1;
            continue;
        }
        if byte == b'\\' && (escape_outside_quotes || quote.is_some()) {
            escaped = true;
            cursor += 1;
            continue;
        }
        if let Some(active) = quote {
            if byte == active {
                if cursor + 1 < range.end && source[cursor + 1] == active {
                    cursor += 2;
                    continue;
                }
                quote = None;
            }
            cursor += 1;
            continue;
        }
        if matches!(byte, b'\'' | b'"') {
            quote = Some(byte);
        } else if byte == b'#' {
            return Ok(Some(cursor));
        }
        cursor += 1;
    }
    if escaped || quote.is_some() {
        Err(())
    } else {
        Ok(None)
    }
}

fn unquoted_byte(source: &[u8], range: Range<usize>, target: u8) -> Result<Option<usize>, ()> {
    unquoted_byte_with_escape_mode(source, range, target, true)
}

fn unquoted_byte_with_escape_mode(
    source: &[u8],
    range: Range<usize>,
    target: u8,
    escape_outside_quotes: bool,
) -> Result<Option<usize>, ()> {
    let mut quote = None;
    let mut escaped = false;
    let mut cursor = range.start;
    while cursor < range.end {
        let byte = source[cursor];
        if escaped {
            escaped = false;
            cursor += 1;
            continue;
        }
        if byte == b'\\' && (escape_outside_quotes || quote.is_some()) {
            escaped = true;
            cursor += 1;
            continue;
        }
        if let Some(active) = quote {
            if byte == active {
                if cursor + 1 < range.end && source[cursor + 1] == active {
                    cursor += 2;
                    continue;
                }
                quote = None;
            }
        } else if matches!(byte, b'\'' | b'"') {
            quote = Some(byte);
        } else if byte == target {
            return Ok(Some(cursor));
        }
        cursor += 1;
    }
    if escaped || quote.is_some() {
        Err(())
    } else {
        Ok(None)
    }
}

fn whitespace_tokens(source: &[u8], range: Range<usize>) -> Option<Vec<Range<usize>>> {
    let mut output = Vec::new();
    let mut cursor = range.start;
    while cursor < range.end {
        while cursor < range.end && source[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor == range.end {
            break;
        }
        let start = cursor;
        let mut quote = None;
        let mut escaped = false;
        while cursor < range.end {
            let byte = source[cursor];
            if escaped {
                escaped = false;
                cursor += 1;
                continue;
            }
            if byte == b'\\' {
                escaped = true;
                cursor += 1;
                continue;
            }
            if let Some(active) = quote {
                if byte == active {
                    quote = None;
                }
                cursor += 1;
                continue;
            }
            if matches!(byte, b'\'' | b'"') {
                quote = Some(byte);
                cursor += 1;
                continue;
            }
            if byte.is_ascii_whitespace() {
                break;
            }
            cursor += 1;
        }
        if escaped || quote.is_some() || cursor == start {
            return None;
        }
        output.push(start..cursor);
    }
    Some(output)
}

struct PostgresRecordField {
    span: Range<usize>,
    tokens: Vec<Zeroizing<Vec<u8>>>,
}

impl PostgresRecordField {
    fn single_token(&self) -> Option<&[u8]> {
        (self.tokens.len() == 1).then(|| self.tokens[0].as_slice())
    }
}

struct PostgresLexedRecord {
    fields: Vec<PostgresRecordField>,
    comment: Option<usize>,
}

struct PostgresRecordToken {
    span: Range<usize>,
    value: Zeroizing<Vec<u8>>,
    trailing_comma: bool,
}

fn postgres_record_fields(source: &[u8], range: Range<usize>) -> Option<PostgresLexedRecord> {
    let (logical, raw_offsets) = postgres_logical_record(source, range)?;
    let mut fields = Vec::new();
    let mut comment = None;
    let mut cursor = 0usize;
    loop {
        let Some(mut token) =
            next_postgres_record_token(&logical, &raw_offsets, &mut cursor, &mut comment)?
        else {
            break;
        };
        let field_start = token.span.start;
        let mut field_end;
        let mut tokens = Vec::new();
        loop {
            let trailing_comma = token.trailing_comma;
            field_end = token.span.end;
            tokens.push(token.value);
            if !trailing_comma {
                break;
            }
            let Some(next) =
                next_postgres_record_token(&logical, &raw_offsets, &mut cursor, &mut comment)?
            else {
                break;
            };
            token = next;
        }
        fields.push(PostgresRecordField {
            span: field_start..field_end,
            tokens,
        });
        if comment.is_some() {
            break;
        }
    }
    Some(PostgresLexedRecord { fields, comment })
}

fn postgres_logical_record(
    source: &[u8],
    range: Range<usize>,
) -> Option<(Zeroizing<Vec<u8>>, Vec<usize>)> {
    let mut logical = Zeroizing::new(Vec::with_capacity(range.len()));
    let mut raw_offsets = Vec::with_capacity(range.len());
    let mut cursor = range.start;
    while cursor < range.end {
        let byte = source[cursor];
        if byte == 0 {
            return None;
        }
        if byte == b'\\' {
            if cursor + 1 == range.end {
                // The backend removes a final continuation marker even when
                // EOF arrives before another physical line.
                cursor += 1;
                continue;
            }
            if source[cursor + 1] == b'\n' {
                cursor += 2;
                continue;
            }
            if cursor + 2 < range.end && source[cursor + 1] == b'\r' && source[cursor + 2] == b'\n'
            {
                cursor += 3;
                continue;
            }
        }
        if byte == b'\n' {
            return None;
        }
        logical.push(byte);
        raw_offsets.push(cursor);
        cursor += 1;
    }
    Some((logical, raw_offsets))
}

fn next_postgres_record_token(
    logical: &[u8],
    raw_offsets: &[usize],
    cursor: &mut usize,
    comment: &mut Option<usize>,
) -> Option<Option<PostgresRecordToken>> {
    while *cursor < logical.len()
        && (postgres_record_blank(logical[*cursor]) || logical[*cursor] == b',')
    {
        *cursor += 1;
    }
    if *cursor == logical.len() {
        return Some(None);
    }
    if logical[*cursor] == b'#' {
        *comment = Some(raw_offsets[*cursor]);
        *cursor = logical.len();
        return Some(None);
    }

    let start = *cursor;
    let mut value = Zeroizing::new(Vec::new());
    let mut in_quote = false;
    let mut saw_quote = false;
    let mut trailing_comma = false;
    while *cursor < logical.len() {
        let byte = logical[*cursor];
        if !in_quote {
            if postgres_record_blank(byte) {
                break;
            }
            if byte == b',' {
                trailing_comma = true;
                *cursor += 1;
                break;
            }
            if byte == b'#' {
                *comment = Some(raw_offsets[*cursor]);
                break;
            }
        }
        if byte == b'"' {
            saw_quote = true;
            if in_quote && *cursor + 1 < logical.len() && logical[*cursor + 1] == b'"' {
                value.push(b'"');
                *cursor += 2;
                continue;
            }
            in_quote = !in_quote;
            *cursor += 1;
            continue;
        }
        value.push(byte);
        *cursor += 1;
    }
    if in_quote || (!saw_quote && value.is_empty()) {
        return None;
    }
    let end = *cursor - usize::from(trailing_comma);
    let span = raw_offsets[start]..raw_offsets[end - 1] + 1;
    Some(Some(PostgresRecordToken {
        span,
        value,
        trailing_comma,
    }))
}

const fn postgres_record_blank(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r')
}

fn java_line_continues(content: &[u8]) -> bool {
    let mut backslashes = 0usize;
    for byte in content.iter().rev() {
        if *byte == b'\\' {
            backslashes += 1;
        } else {
            break;
        }
    }
    backslashes % 2 == 1
}

fn postgres_record_line_continues(content: &[u8]) -> bool {
    content.last() == Some(&b'\\')
}

fn toml_complex_value_end(source: &[u8], line: &PhysicalLine) -> Option<usize> {
    let trimmed = trim_horizontal(source, line.content.clone());
    if matches!(source.get(trimmed.start), Some(b'#' | b'[')) {
        return None;
    }
    let equals = unquoted_byte(source, trimmed.clone(), b'=')
        .ok()
        .flatten()?;
    let value = trim_horizontal(source, equals + 1..trimmed.end);
    let triple = if source[value.clone()].starts_with(b"\"\"\"") {
        Some(b"\"\"\"".as_slice())
    } else if source[value.clone()].starts_with(b"'''") {
        Some(b"'''".as_slice())
    } else {
        None
    };
    if let Some(delimiter) = triple {
        let closing = find_toml_multiline_close(source, value.start + delimiter.len(), delimiter);
        return Some(closing.map_or(source.len(), |closing| {
            source[closing..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(source.len(), |newline| closing + newline + 1)
        }));
    }
    let balance = toml_bracket_balance(&source[value])?;
    if balance == 0 {
        return None;
    }
    let mut total = balance;
    let mut end = line.full.end;
    while end < source.len() && total > 0 {
        let next = next_physical_line(source, end);
        total += toml_bracket_delta(&source[next.content.clone()], false).unwrap_or(0);
        end = next.full.end;
    }
    Some(end)
}

fn find_toml_multiline_close(source: &[u8], mut cursor: usize, delimiter: &[u8]) -> Option<usize> {
    while cursor + delimiter.len() <= source.len() {
        if &source[cursor..cursor + delimiter.len()] == delimiter
            && (delimiter == b"'''" || !toml_basic_quote_is_escaped(source, cursor))
        {
            return Some(cursor);
        }
        cursor += 1;
    }
    None
}

fn toml_basic_quote_is_escaped(source: &[u8], quote: usize) -> bool {
    let mut cursor = quote;
    let mut backslashes = 0usize;
    while cursor > 0 && source[cursor - 1] == b'\\' {
        backslashes += 1;
        cursor -= 1;
    }
    backslashes % 2 == 1
}

fn toml_bracket_balance(bytes: &[u8]) -> Option<i32> {
    toml_bracket_delta(bytes, true)
}

fn toml_bracket_delta(bytes: &[u8], reject_negative: bool) -> Option<i32> {
    let mut quote = None;
    let mut escaped = false;
    let mut balance = 0i32;
    for byte in bytes {
        if escaped {
            escaped = false;
            continue;
        }
        if *byte == b'\\' && quote == Some(b'"') {
            escaped = true;
            continue;
        }
        if let Some(active) = quote {
            if *byte == active {
                quote = None;
            }
            continue;
        }
        if matches!(*byte, b'\'' | b'"') {
            quote = Some(*byte);
        } else if matches!(*byte, b'[' | b'{') {
            balance += 1;
        } else if matches!(*byte, b']' | b'}') {
            balance -= 1;
            if reject_negative && balance < 0 {
                return None;
            }
        } else if *byte == b'#' {
            break;
        }
    }
    (!escaped && quote.is_none()).then_some(balance)
}

fn toml_single_line_value_is_balanced(bytes: &[u8]) -> bool {
    toml_bracket_balance(bytes) == Some(0)
}

fn has_line_control(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .any(|byte| matches!(*byte, 0..=8 | 10..=31 | 127))
}

fn is_postgres_include_key(bytes: &[u8]) -> bool {
    matches_ignore_ascii_case(bytes, &[b"include", b"include_if_exists", b"include_dir"])
}

fn is_postgres_auth_include_key(bytes: &[u8]) -> bool {
    bytes == b"include" || bytes == b"include_if_exists" || bytes == b"include_dir"
}

fn matches_ignore_ascii_case(bytes: &[u8], candidates: &[&[u8]]) -> bool {
    candidates
        .iter()
        .any(|candidate| bytes.eq_ignore_ascii_case(candidate))
}

fn entry_fragment(
    dialect: LineConfigDialect,
    key: &str,
    value: Option<&str>,
) -> CoreResult<Zeroizing<Vec<u8>>> {
    if dialect.record_only() {
        return Err(invalid_edit("ordered-record dialects require add_record"));
    }
    validate_edit_field("entry key", key, false)?;
    validate_mysql_edit_field(dialect, "entry key", key)?;
    if let Some(value) = value {
        validate_edit_field("entry value", value, true)?;
        validate_mysql_edit_field(dialect, "entry value", value)?;
    }
    let key = key.trim_matches([' ', '\t']);
    if key.is_empty() {
        return Err(invalid_edit("entry key must not be empty"));
    }
    if value.is_none()
        && !matches!(
            dialect,
            LineConfigDialect::MySqlOption
                | LineConfigDialect::JavaProperties
                | LineConfigDialect::Whitespace
        )
    {
        return Err(invalid_edit("selected dialect requires an explicit value"));
    }
    let value = value.map(|value| value.trim_matches([' ', '\t']));
    let mut fragment = Zeroizing::new(Vec::with_capacity(
        key.len() + value.map_or(0, str::len) + 3,
    ));
    fragment.extend_from_slice(key.as_bytes());
    if let Some(value) = value {
        match dialect {
            LineConfigDialect::PostgresConf | LineConfigDialect::Toml => {
                fragment.extend_from_slice(b" = ")
            }
            LineConfigDialect::Whitespace => fragment.push(b' '),
            _ => fragment.push(b'='),
        }
        fragment.extend_from_slice(value.as_bytes());
    }
    validate_fragment(
        dialect,
        &fragment,
        LineConfigNodeKind::Entry,
        Some(key),
        value,
    )?;
    Ok(fragment)
}

fn styled_entry_fragment(
    dialect: LineConfigDialect,
    source: &[u8],
    node: &NodeRecord,
    key: &str,
    value: &str,
) -> CoreResult<Zeroizing<Vec<u8>>> {
    validate_edit_field("entry key", key, false)?;
    validate_edit_field("entry value", value, true)?;
    validate_mysql_edit_field(dialect, "entry key", key)?;
    validate_mysql_edit_field(dialect, "entry value", value)?;
    let key = key.trim_matches([' ', '\t']);
    let value = value.trim_matches([' ', '\t']);
    let name_span = node
        .name_span
        .as_ref()
        .ok_or_else(|| invalid_edit("selected entry has no safe name span"))?;
    let value_span = node
        .value_span
        .as_ref()
        .ok_or_else(|| invalid_edit("selected entry has no safe value span"))?;
    if name_span.end > value_span.start {
        return Err(invalid_edit("selected entry has an invalid separator span"));
    }
    let separator = &source[name_span.end..value_span.start];
    if separator.is_empty() || separator.iter().any(|byte| matches!(byte, b'\r' | b'\n')) {
        return Err(invalid_edit(
            "selected entry has no safe single-line separator",
        ));
    }
    let mut fragment = Zeroizing::new(Vec::with_capacity(
        key.len() + separator.len() + value.len(),
    ));
    fragment.extend_from_slice(key.as_bytes());
    fragment.extend_from_slice(separator);
    fragment.extend_from_slice(value.as_bytes());
    validate_fragment(dialect, &fragment, node.kind, Some(key), Some(value))?;
    Ok(fragment)
}

fn include_fragment(
    dialect: LineConfigDialect,
    target_policy: LineConfigTargetPolicy,
    directive: &str,
    target: &str,
) -> CoreResult<Zeroizing<Vec<u8>>> {
    validate_edit_field("include directive", directive, false)?;
    validate_edit_field("include target", target, false)?;
    validate_mysql_edit_field(dialect, "include directive", directive)?;
    validate_mysql_edit_field(dialect, "include target", target)?;
    let directive = directive.trim_matches([' ', '\t']);
    let target = target.trim_matches([' ', '\t']);
    if directive.is_empty() || target.is_empty() {
        return Err(invalid_edit(
            "include directive and target must not be empty",
        ));
    }
    if dialect == LineConfigDialect::MySqlOption
        && (!mysql_include_directive_is_safe_for_policy(target_policy, directive.as_bytes())
            || !mysql_include_target_is_safe(target.as_bytes()))
    {
        return Err(invalid_edit(
            "MySQL include requires an exact lowercase directive and one unquoted path without control characters or comments",
        ));
    }
    let mut fragment = Zeroizing::new(Vec::with_capacity(directive.len() + target.len() + 3));
    fragment.extend_from_slice(directive.as_bytes());
    match dialect {
        LineConfigDialect::MySqlOption | LineConfigDialect::PgHba | LineConfigDialect::PgIdent => {
            fragment.push(b' ')
        }
        LineConfigDialect::PostgresConf => fragment.extend_from_slice(b" = "),
        _ => {
            return Err(invalid_edit(
                "selected dialect has no recognized include form",
            ));
        }
    }
    fragment.extend_from_slice(target.as_bytes());
    validate_fragment_with_target_policy(
        dialect,
        target_policy,
        &fragment,
        LineConfigNodeKind::Include,
        Some(directive),
        Some(target),
    )?;
    Ok(fragment)
}

fn container_fragment(
    dialect: LineConfigDialect,
    parent_name: Option<&str>,
    name: &str,
    kind: LineConfigNodeKind,
) -> CoreResult<Zeroizing<Vec<u8>>> {
    validate_edit_field("container name", name, false)?;
    validate_mysql_edit_field(dialect, "container name", name)?;
    let name = name.trim_matches([' ', '\t']);
    if name.is_empty() {
        return Err(invalid_edit("container name must not be empty"));
    }
    if kind == LineConfigNodeKind::Section && !dialect.supports_sections() {
        return Err(invalid_edit("selected dialect does not support sections"));
    }
    if kind == LineConfigNodeKind::Table && !dialect.supports_tables() {
        return Err(invalid_edit("selected dialect does not support tables"));
    }
    let full_name = if kind == LineConfigNodeKind::Table {
        if let Some(parent) = parent_name {
            let parent = parent.trim_matches([' ', '\t']);
            if table_name_has_parent(name, parent) {
                Zeroizing::new(name.to_owned())
            } else {
                Zeroizing::new(format!("{parent}.{name}"))
            }
        } else {
            Zeroizing::new(name.to_owned())
        }
    } else {
        Zeroizing::new(name.to_owned())
    };
    let mut fragment = Zeroizing::new(Vec::with_capacity(full_name.len() + 2));
    fragment.push(b'[');
    fragment.extend_from_slice(full_name.as_bytes());
    fragment.push(b']');
    validate_fragment(dialect, &fragment, kind, Some(full_name.as_str()), None)?;
    Ok(fragment)
}

fn record_fragment(
    dialect: LineConfigDialect,
    record: &str,
) -> CoreResult<(Zeroizing<Vec<u8>>, LineConfigNodeKind)> {
    if !dialect.record_only() {
        return Err(invalid_edit(
            "selected dialect is not an ordered-record dialect",
        ));
    }
    validate_edit_field("ordered record", record, false)?;
    let record = record.trim_matches([' ', '\t']);
    if record.is_empty() {
        return Err(invalid_edit("ordered record must not be empty"));
    }
    if record.as_bytes().last() == Some(&b'\\') {
        return Err(invalid_edit(
            "ordered record must not continue into the following physical line",
        ));
    }
    let fragment = Zeroizing::new(record.as_bytes().to_vec());
    let parsed = parse_document(
        dialect,
        LineConfigTargetPolicy::UNVERSIONED,
        &fragment,
        false,
    )
    .map_err(|()| invalid_edit("ordered record cannot be parsed safely"))?;
    let Some(node) = parsed.nodes.first() else {
        return Err(invalid_edit("ordered record did not produce a node"));
    };
    if parsed.nodes.len() != 1
        || !parsed.structured
        || !matches!(
            node.kind,
            LineConfigNodeKind::Record | LineConfigNodeKind::Include
        )
        || !node.children.is_empty()
        || node.header_span != (0..fragment.len())
    {
        return Err(invalid_edit(
            "input must describe exactly one ordered record",
        ));
    }
    Ok((fragment, node.kind))
}

fn comment_fragment(dialect: LineConfigDialect, text: &str) -> CoreResult<Zeroizing<Vec<u8>>> {
    validate_edit_field("comment", text, true)?;
    validate_mysql_edit_field(dialect, "comment", text)?;
    let text = text.trim_matches([' ', '\t']);
    let mut fragment = Zeroizing::new(Vec::with_capacity(text.len() + 2));
    fragment.push(b'#');
    if !text.is_empty() {
        fragment.push(b' ');
        fragment.extend_from_slice(text.as_bytes());
    }
    validate_fragment(dialect, &fragment, LineConfigNodeKind::Comment, None, None)?;
    Ok(fragment)
}

fn validate_fragment(
    dialect: LineConfigDialect,
    fragment: &[u8],
    expected_kind: LineConfigNodeKind,
    expected_name: Option<&str>,
    expected_value: Option<&str>,
) -> CoreResult<()> {
    validate_fragment_with_target_policy(
        dialect,
        LineConfigTargetPolicy::UNVERSIONED,
        fragment,
        expected_kind,
        expected_name,
        expected_value,
    )
}

fn validate_fragment_with_target_policy(
    dialect: LineConfigDialect,
    target_policy: LineConfigTargetPolicy,
    fragment: &[u8],
    expected_kind: LineConfigNodeKind,
    expected_name: Option<&str>,
    expected_value: Option<&str>,
) -> CoreResult<()> {
    if fragment.len() > MAX_LINE_CONFIG_EDIT_BYTES {
        return Err(invalid_edit("visual fragment exceeds the edit-size limit"));
    }
    if dialect.record_only() && fragment.last() == Some(&b'\\') {
        return Err(invalid_edit(
            "visual fragment must not continue into the following physical line",
        ));
    }
    let parsed = parse_document(dialect, target_policy, fragment, true)
        .map_err(|()| invalid_edit("visual fragment cannot be parsed safely"))?;
    let Some(node) = parsed.nodes.first() else {
        return Err(invalid_edit("visual fragment did not produce a node"));
    };
    if parsed.nodes.len() != 1
        || !parsed.structured
        || node.kind != expected_kind
        || !node.children.is_empty()
        || node.header_span != (0..fragment.len())
    {
        return Err(invalid_edit(
            "input must describe exactly one node of the requested kind",
        ));
    }
    if let Some(expected) = expected_name {
        let matches = node
            .name_span
            .as_ref()
            .is_some_and(|span| &fragment[span.clone()] == expected.as_bytes());
        if !matches {
            return Err(invalid_edit("entry name contains structural syntax"));
        }
    }
    if let Some(expected) = expected_value {
        let matches = node
            .value_span
            .as_ref()
            .is_some_and(|span| &fragment[span.clone()] == expected.as_bytes());
        if !matches {
            return Err(invalid_edit(
                "entry value contains structural or comment syntax",
            ));
        }
    }
    Ok(())
}

fn validate_edit_field(subject: &'static str, value: &str, allow_empty: bool) -> CoreResult<()> {
    if value.len() > MAX_LINE_CONFIG_EDIT_BYTES
        || value.contains(['\0', '\r', '\n'])
        || (!allow_empty && value.trim_matches([' ', '\t']).is_empty())
    {
        return Err(CoreError::validation(
            "line configuration visual edit",
            format!("{subject} must be one bounded physical line without NUL or line breaks"),
        ));
    }
    Ok(())
}

fn validate_mysql_edit_field(
    dialect: LineConfigDialect,
    subject: &'static str,
    value: &str,
) -> CoreResult<()> {
    if dialect == LineConfigDialect::MySqlOption && value.chars().any(char::is_control) {
        return Err(CoreError::validation(
            "line configuration visual edit",
            format!("{subject} must not contain control characters for a MySQL option file"),
        ));
    }
    Ok(())
}

fn table_name_has_parent(name: &str, parent: &str) -> bool {
    name.strip_prefix(parent)
        .is_some_and(|suffix| suffix.starts_with('.'))
}

fn build_insertion(source: &[u8], insert_at: usize, fragment: &[u8]) -> Zeroizing<Vec<u8>> {
    let newline = preferred_newline(source);
    let content_start = bom_len(source);
    let effectively_empty = source.len() == content_start && insert_at == content_start;
    let at_end = insert_at == source.len();
    let terminal_newline = source.ends_with(b"\n");
    let mut insertion = Zeroizing::new(Vec::with_capacity(fragment.len() + newline.len() * 2));
    if !effectively_empty
        && insert_at > content_start
        && !matches!(source[insert_at - 1], b'\n' | b'\r')
    {
        insertion.extend_from_slice(newline);
    }
    insertion.extend_from_slice(fragment);
    if !at_end || terminal_newline {
        insertion.extend_from_slice(newline);
    }
    insertion
}

fn preferred_newline(source: &[u8]) -> &'static [u8] {
    if source.windows(2).any(|window| window == b"\r\n") {
        b"\r\n"
    } else {
        b"\n"
    }
}

fn trailing_newlines_start(bytes: &[u8]) -> usize {
    let mut end = bytes.len();
    loop {
        if end >= 2 && &bytes[end - 2..end] == b"\r\n" {
            end -= 2;
        } else if end >= 1 && bytes[end - 1] == b'\n' {
            end -= 1;
        } else {
            return end;
        }
    }
}

fn flatten_nodes(
    parsed: &[ParsedNode],
    parent: Option<LineConfigNodeId>,
    depth: usize,
    revision: u64,
    next_id: &mut u64,
    output: &mut Vec<NodeRecord>,
) {
    for node in parsed {
        let id = revision_node_id(revision, *next_id);
        *next_id = next_id.saturating_add(1);
        output.push(NodeRecord {
            id,
            parent,
            depth,
            kind: node.kind,
            span: node.span.clone(),
            header_span: node.header_span.clone(),
            name_span: node.name_span.clone(),
            value_span: node.value_span.clone(),
            child_count: node.children.len(),
        });
        flatten_nodes(
            &node.children,
            Some(id),
            depth + 1,
            revision,
            next_id,
            output,
        );
    }
}

fn next_document_revision() -> u64 {
    NEXT_LINE_CONFIG_REVISION
        .fetch_add(1, Ordering::Relaxed)
        .max(1)
}

const fn revision_node_id(revision: u64, ordinal: u64) -> LineConfigNodeId {
    LineConfigNodeId(((revision as u128) << 64) | ordinal as u128)
}

fn node_is_sensitive(source: &[u8], node: &NodeRecord) -> bool {
    node.name_span.as_ref().is_some_and(|span| {
        let key = &source[span.clone()];
        is_sensitive_key(key) || is_secret_carrier_key(key)
    }) || contains_sensitive_marker(&source[node.header_span.clone()])
}

fn is_sensitive_key(bytes: &[u8]) -> bool {
    let normalized = normalize_identifier(bytes);
    const EXACT: [&[u8]; 21] = [
        b"password",
        b"passwd",
        b"pwd",
        b"requirepass",
        b"masterauth",
        b"authkey",
        b"auth_key",
        b"secret",
        b"token",
        b"api_key",
        b"apikey",
        b"access_key",
        b"secret_key",
        b"auth_token",
        b"credential",
        b"credentials",
        b"private_key",
        b"ssl_key",
        b"keyfile",
        b"cipherfile",
        b"wsrep_sst_auth",
    ];
    const CONTAINED: [&[u8]; 9] = [
        b"password",
        b"passwd",
        b"requirepass",
        b"masterauth",
        b"secret",
        b"credential",
        b"private_key",
        b"access_token",
        b"auth_token",
    ];
    EXACT
        .iter()
        .any(|candidate| normalized.as_slice() == *candidate)
        || CONTAINED
            .iter()
            .any(|marker| contains_bytes(&normalized, marker))
        || normalized
            .split(|byte| *byte == b'_')
            .any(|component| matches!(component, b"pwd" | b"token" | b"apikey"))
}

fn is_secret_carrier_key(bytes: &[u8]) -> bool {
    let normalized = normalize_identifier(bytes);
    const CARRIERS: [&[u8]; 12] = [
        b"primary_conninfo",
        b"conninfo",
        b"connection_string",
        b"connection_url",
        b"database_url",
        b"db_url",
        b"jdbc_url",
        b"ldap_url",
        b"ldap_uri",
        b"url",
        b"uri",
        b"dsn",
    ];
    CARRIERS
        .iter()
        .any(|carrier| normalized.as_slice() == *carrier)
}

fn normalize_identifier(bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut normalized = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut previous_was_upper = false;
    let mut previous_was_lower_or_digit = false;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if byte.is_ascii_uppercase() {
            let next_is_lower = bytes.get(index + 1).is_some_and(u8::is_ascii_lowercase);
            if normalized.last().is_some_and(|last| *last != b'_')
                && (previous_was_lower_or_digit || (previous_was_upper && next_is_lower))
            {
                normalized.push(b'_');
            }
            normalized.push(byte.to_ascii_lowercase());
            previous_was_upper = true;
            previous_was_lower_or_digit = false;
        } else if byte.is_ascii_lowercase() || byte.is_ascii_digit() {
            normalized.push(byte);
            previous_was_upper = false;
            previous_was_lower_or_digit = true;
        } else {
            if normalized.last().is_some_and(|last| *last != b'_') {
                normalized.push(b'_');
            }
            previous_was_upper = false;
            previous_was_lower_or_digit = false;
        }
    }
    while normalized.last() == Some(&b'_') {
        normalized.pop();
    }
    normalized
}

fn contains_sensitive_marker(bytes: &[u8]) -> bool {
    const RAW_MARKERS: [&[u8]; 8] = [
        b"password",
        b"passwd",
        b"requirepass",
        b"masterauth",
        b"secret",
        b"credential",
        b"apikey",
        b"privatekey",
    ];
    const NORMALIZED_MARKERS: [&[u8]; 7] = [
        b"api_key",
        b"private_key",
        b"access_token",
        b"auth_token",
        b"secret_key",
        b"ldap_bind_passwd",
        b"wsrep_sst_auth",
    ];
    RAW_MARKERS.iter().any(|marker| {
        bytes
            .windows(marker.len())
            .any(|window| window.eq_ignore_ascii_case(marker))
    }) || {
        let normalized = normalize_identifier(bytes);
        NORMALIZED_MARKERS
            .iter()
            .any(|marker| contains_bytes(&normalized, marker))
    } || contains_authkey_marker(bytes)
        || contains_url_userinfo(bytes)
}

fn contains_authkey_marker(bytes: &[u8]) -> bool {
    [b"authkey".as_slice(), b"auth_key".as_slice()]
        .iter()
        .any(|marker| {
            bytes
                .windows(marker.len())
                .enumerate()
                .any(|(start, window)| {
                    window.eq_ignore_ascii_case(marker)
                        && (start == 0 || !is_identifier_byte(bytes[start - 1]))
                        && bytes
                            .get(start + marker.len())
                            .is_none_or(|byte| !is_identifier_byte(*byte))
                })
        })
}

const fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn contains_url_userinfo(bytes: &[u8]) -> bool {
    bytes.windows(3).enumerate().any(|(index, window)| {
        window == b"://"
            && bytes[index + 3..]
                .iter()
                .take_while(|byte| !byte.is_ascii_whitespace())
                .any(|byte| *byte == b'@')
    })
}

fn bounded_field(bytes: &[u8]) -> String {
    let bounded = &bytes[..bytes.len().min(MAX_LINE_CONFIG_EDIT_BYTES)];
    String::from_utf8_lossy(bounded).into_owned()
}

fn bounded_preview(bytes: &[u8]) -> (String, bool) {
    let truncated = bytes.len() > MAX_LINE_CONFIG_ROW_PREVIEW_BYTES;
    let bounded = &bytes[..bytes.len().min(MAX_LINE_CONFIG_ROW_PREVIEW_BYTES)];
    let mut preview = String::from_utf8_lossy(bounded)
        .split_ascii_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    truncate_utf8(&mut preview, MAX_LINE_CONFIG_ROW_PREVIEW_BYTES);
    (preview, truncated)
}

fn truncate_utf8(value: &mut String, maximum_bytes: usize) {
    if value.len() <= maximum_bytes {
        return;
    }
    let mut end = maximum_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
}

fn validate_size(bytes: usize) -> CoreResult<()> {
    if bytes > MAX_LINE_CONFIG_BYTES {
        return Err(CoreError::validation(
            "line configuration",
            format!("must contain at most {MAX_LINE_CONFIG_BYTES} bytes"),
        ));
    }
    Ok(())
}

fn validate_import_path(path: &Path) -> CoreResult<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        || !path.is_file()
    {
        return Err(CoreError::validation(
            "line configuration import path",
            "must be an existing absolute file selected by the native dialog",
        ));
    }
    Ok(())
}

fn validate_destination(path: &Path) -> CoreResult<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        || path.file_name().is_none()
        || !path.parent().is_some_and(Path::is_dir)
    {
        return Err(CoreError::validation(
            "line configuration destination",
            "must be a new absolute file path in an existing directory without traversal components",
        ));
    }
    Ok(())
}

fn invalid_edit(message: &'static str) -> CoreError {
    CoreError::validation("line configuration visual edit", message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{env, fs, process};

    fn row_id(document: &LineConfigVisualDocument, name: &str) -> LineConfigNodeId {
        document
            .rows()
            .into_iter()
            .find(|row| row.name() == Some(name))
            .unwrap_or_else(|| panic!("missing row named {name}"))
            .id()
    }

    #[test]
    fn every_dialect_round_trips_recognized_source_byte_exactly() {
        let samples: &[(LineConfigDialect, &[u8])] = &[
            (
                LineConfigDialect::MySqlOption,
                b"; retained\r\n[mysqld]\r\npassword = \"abc#def\"\r\nmax_connections=100\r\nmax_connections=200\r\n!include /etc/mysql/extra.cnf\r\n!includedir /etc/mysql/conf.d\r\n",
            ),
            (
                LineConfigDialect::Ini,
                b"global=1\r\n[ARCHIVE_LOCAL1]\r\nARCH_DEST=/backup\r\n# retained",
            ),
            (
                LineConfigDialect::PostgresConf,
                b"listen_addresses = '*'\nshared_preload_libraries = 'a#b'\ninclude = '/etc/postgresql/local.conf'\ninclude_dir = 'conf.d'\nmax_connections = 100\nmax_connections = 200",
            ),
            (
                LineConfigDialect::PgHba,
                b"local all all peer\nhost all all 10.0.0.0/8 scram-sha-256\ninclude /etc/postgresql/hba-extra.conf",
            ),
            (
                LineConfigDialect::PgIdent,
                b"map_one system_user database_user\ninclude /etc/postgresql/ident-extra.conf",
            ),
            (
                LineConfigDialect::FlatKeyValue,
                b"host=127.0.0.1\nport=5432",
            ),
            (
                LineConfigDialect::Whitespace,
                b"max_connections 100\nfeature_flag",
            ),
            (
                LineConfigDialect::Toml,
                b"[server]\nport = 4000\n[server.tls]\ncertificate = 'server.pem'",
            ),
            (
                LineConfigDialect::JavaProperties,
                b"server.port=8080\npath\\ key: retained\nfeature.flag",
            ),
        ];

        for (dialect, source) in samples {
            let document = LineConfigVisualDocument::parse_bytes(*dialect, source.to_vec())
                .expect("recognized sample should parse");
            assert!(document.is_structured(), "{dialect:?}");
            assert_eq!(document.dialect(), *dialect);
            assert_eq!(document.raw_bytes(), *source);
            assert_eq!(document.output().bytes(), *source);
            assert_eq!(
                document.output().suggested_file_name(),
                dialect.suggested_file_name()
            );
        }
    }

    #[test]
    fn sections_tables_duplicates_includes_and_order_are_visible() {
        let mysql = LineConfigVisualDocument::parse(
            LineConfigDialect::MySqlOption,
            "; root\n[mysqld]\nquoted=\"value#inside\"\nmax_connections=100\nmax_connections=200\n!include /tmp/one.cnf\n!includedir /tmp/conf.d\n",
        )
        .expect("MySQL source should parse");
        let section = row_id(&mysql, "mysqld");
        let section_row = mysql.row_by_id(section).expect("section row should exist");
        assert_eq!(section_row.kind(), LineConfigNodeKind::Section);
        assert_eq!(section_row.child_count(), 5);
        let children = mysql
            .children(section)
            .expect("section children should resolve");
        assert_eq!(children.len(), 5);
        assert!(children.iter().all(|row| row.parent() == Some(section)));
        assert_eq!(
            children
                .iter()
                .filter(|row| row.name() == Some("max_connections"))
                .count(),
            2
        );
        assert_eq!(
            children
                .iter()
                .find(|row| row.name() == Some("quoted"))
                .and_then(LineConfigRow::value),
            Some("\"value#inside\"")
        );
        assert_eq!(
            children
                .iter()
                .filter(|row| row.kind() == LineConfigNodeKind::Include)
                .count(),
            2
        );

        let ini = LineConfigVisualDocument::parse(
            LineConfigDialect::Ini,
            "flat=value\n[ARCHIVE_LOCAL1]\nARCH_DEST=/backup",
        )
        .expect("INI source should parse");
        assert_eq!(ini.root_rows().len(), 2);
        let archive = row_id(&ini, "ARCHIVE_LOCAL1");
        assert_eq!(ini.children(archive).expect("INI children").len(), 1);

        let toml = LineConfigVisualDocument::parse(
            LineConfigDialect::Toml,
            "[server]\nport = 4000\n[server.tls]\ncertificate = 'server.pem'",
        )
        .expect("TOML source should parse");
        let server = row_id(&toml, "server");
        let server_children = toml.children(server).expect("table children");
        assert_eq!(server_children.len(), 2);
        let tls = server_children
            .iter()
            .find(|row| row.kind() == LineConfigNodeKind::Table)
            .expect("nested table");
        assert_eq!(tls.name(), Some("server.tls"));
        assert_eq!(tls.depth(), 1);
        let tls_children = toml.children(tls.id()).expect("nested table children");
        assert_eq!(tls_children.len(), 1);
        assert_eq!(tls_children[0].depth(), 2);

        let hba = LineConfigVisualDocument::parse(
            LineConfigDialect::PgHba,
            "local all all peer\nhost all all 127.0.0.1/32 scram-sha-256\ninclude /tmp/hba.conf",
        )
        .expect("HBA source should parse");
        let ordered_names = hba
            .root_rows()
            .into_iter()
            .map(|row| row.name().unwrap_or_default().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(ordered_names, ["local", "host", "include"]);
        assert_eq!(hba.root_rows()[2].kind(), LineConfigNodeKind::Include);
    }

    #[test]
    fn dm_thread_ini_ranges_duplicates_and_comments_round_trip_byte_exactly() {
        let source = b"# retained thread bindings\r\nTHREAD=[2,4]\r\nTHREAD=[,1] # retained latest binding\r\n; retained final comment";
        let document =
            LineConfigVisualDocument::parse_bytes(LineConfigDialect::Ini, source.to_vec())
                .expect("DM thread INI source should parse");

        assert!(document.is_structured());
        assert_eq!(document.output().bytes(), source);
        let rows = document.root_rows();
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[0].kind(), LineConfigNodeKind::Comment);
        assert_eq!(rows[3].kind(), LineConfigNodeKind::Comment);
        let thread_values = rows
            .iter()
            .filter(|row| row.name() == Some("THREAD"))
            .map(LineConfigRow::value)
            .collect::<Vec<_>>();
        assert_eq!(thread_values, [Some("[2,4]"), Some("[,1]")]);
    }

    #[test]
    fn dm_timer_repeat_interval_keeps_semicolons_inside_the_ini_value() {
        // The official dmtimer.ini example uses this calendar expression.
        // https://eco.dameng.com/document/dm/zh-cn/pm/configuration-description.html
        let source = b"[TIMER_03]\nTYPE=10\nREPEAT_INTERVAL=FREQ=SECONDLY;INTERVAL=1\n";
        let document =
            LineConfigVisualDocument::parse_bytes(LineConfigDialect::Ini, source.to_vec())
                .expect("DM timer INI source should parse");

        assert_eq!(document.output().bytes(), source);
        let timer = row_id(&document, "TIMER_03");
        let repeat_interval = document
            .children(timer)
            .expect("timer section children")
            .into_iter()
            .find(|row| row.name() == Some("REPEAT_INTERVAL"))
            .expect("repeat interval row");
        assert_eq!(repeat_interval.value(), Some("FREQ=SECONDLY;INTERVAL=1"));
    }

    #[test]
    fn dm_init_secret_and_duplicate_log_paths_round_trip_without_leaking() {
        const SECRET: &str = "NeverShow42";
        let source = b"[DAMENG]\r\nSYSDBA_PWD=NeverShow42\r\nLOG_PATH=/var/log/dm/primary\r\nLOG_PATH=/var/log/dm/archive\r\n";
        let document =
            LineConfigVisualDocument::parse_bytes(LineConfigDialect::Ini, source.to_vec())
                .expect("dminit.ini source should parse");

        assert!(document.is_structured());
        assert!(document.contains_sensitive_values());
        assert_eq!(document.raw_bytes(), source);
        assert_eq!(document.output().bytes(), source);

        let dameng = row_id(&document, "DAMENG");
        let children = document.children(dameng).expect("DAMENG children");
        assert_eq!(children.len(), 3);
        assert!(children.iter().all(|row| row.parent() == Some(dameng)));
        let password = children
            .iter()
            .find(|row| row.name() == Some("SYSDBA_PWD"))
            .expect("SYSDBA password row");
        assert!(password.sensitive());
        assert_eq!(password.value(), None);
        assert_eq!(password.preview(), "[sensitive value redacted]");
        assert!(!password.editable());
        let log_paths = children
            .iter()
            .filter(|row| row.name() == Some("LOG_PATH"))
            .map(LineConfigRow::value)
            .collect::<Vec<_>>();
        assert_eq!(
            log_paths,
            [Some("/var/log/dm/primary"), Some("/var/log/dm/archive")]
        );

        for debug in [
            format!("{document:?}"),
            format!("{:?}", document.output()),
            format!("{children:?}"),
        ] {
            assert!(!debug.contains(SECRET));
        }

        let password_id = password.id();
        let mut editable = document.clone();
        let before = editable.raw_bytes().to_vec();
        let error = editable
            .update_entry(password_id, "SYSDBA_PWD", Some("replacement"))
            .expect_err("ordinary entry update must reject a secret row");
        assert!(error.to_string().contains("dedicated secret input flow"));
        assert_eq!(editable.raw_bytes(), before);
    }

    #[test]
    fn dm_css_monitor_duplicate_ipv4_and_scoped_ipv6_endpoints_remain_entries() {
        let source =
            b"CSSM_OGUID=453331\r\nCSSM_CSS_IP=192.0.2.10:9343\r\nCSSM_CSS_IP=[fe80::1%3]:9343\r\n";
        let document =
            LineConfigVisualDocument::parse_bytes(LineConfigDialect::Ini, source.to_vec())
                .expect("dmcssm.ini source should parse");

        assert!(document.is_structured());
        assert_eq!(document.raw_bytes(), source);
        assert_eq!(document.output().bytes(), source);
        let endpoints = document
            .root_rows()
            .into_iter()
            .filter(|row| row.name() == Some("CSSM_CSS_IP"))
            .collect::<Vec<_>>();
        assert_eq!(endpoints.len(), 2);
        assert!(
            endpoints
                .iter()
                .all(|row| { row.kind() == LineConfigNodeKind::Entry && row.parent().is_none() })
        );
        assert_eq!(
            endpoints.iter().map(|row| row.value()).collect::<Vec<_>>(),
            [Some("192.0.2.10:9343"), Some("[fe80::1%3]:9343")]
        );
    }

    #[test]
    fn dm_asm_mal_global_and_multi_section_shape_round_trips_with_scoped_ipv6() {
        let source = b"ASM_MAL_CHECK_INTERVAL=5\r\n[ASM0]\r\nMAL_INST_NAME=ASM0\r\nMAL_HOST=192.0.2.20:7236\r\n[ASM1]\r\nMAL_INST_NAME=ASM1\r\nMAL_HOST=[fe80::20%ens192]:7237\r\n";
        let document =
            LineConfigVisualDocument::parse_bytes(LineConfigDialect::Ini, source.to_vec())
                .expect("dmasvrmal.ini source should parse");

        assert!(document.is_structured());
        assert_eq!(document.raw_bytes(), source);
        assert_eq!(document.output().bytes(), source);
        let global = document
            .root_rows()
            .into_iter()
            .find(|row| row.name() == Some("ASM_MAL_CHECK_INTERVAL"))
            .expect("global ASM MAL scalar");
        assert_eq!(global.kind(), LineConfigNodeKind::Entry);
        assert_eq!(global.parent(), None);
        assert_eq!(global.value(), Some("5"));

        let asm0 = row_id(&document, "ASM0");
        let asm1 = row_id(&document, "ASM1");
        for section in [asm0, asm1] {
            assert!(
                document
                    .children(section)
                    .expect("ASM section children")
                    .iter()
                    .all(|row| row.parent() == Some(section))
            );
        }
        let asm1_host = document
            .children(asm1)
            .expect("ASM1 children")
            .into_iter()
            .find(|row| row.name() == Some("MAL_HOST"))
            .expect("ASM1 IPv6 host");
        assert_eq!(asm1_host.value(), Some("[fe80::20%ens192]:7237"));
    }

    #[test]
    fn dm_mp_flat_and_mp1_mp2_section_forms_are_structured_and_byte_exact() {
        let flat = b"MP_HOST=192.0.2.30\r\nMP_PORT=5236\r\n";
        let flat_document =
            LineConfigVisualDocument::parse_bytes(LineConfigDialect::Ini, flat.to_vec())
                .expect("flat mp.ini source should parse");
        assert!(flat_document.is_structured());
        assert_eq!(flat_document.raw_bytes(), flat);
        assert_eq!(flat_document.output().bytes(), flat);
        assert!(
            flat_document
                .root_rows()
                .iter()
                .all(|row| { row.kind() == LineConfigNodeKind::Entry && row.parent().is_none() })
        );

        let sectioned = b"[MP1]\r\nMP_HOST=192.0.2.31\r\nMP_PORT=5237\r\n[MP2]\r\nMP_HOST=192.0.2.32\r\nMP_PORT=5238\r\n";
        let sectioned_document =
            LineConfigVisualDocument::parse_bytes(LineConfigDialect::Ini, sectioned.to_vec())
                .expect("MP1/MP2 mp.ini source should parse");
        assert!(sectioned_document.is_structured());
        assert_eq!(sectioned_document.raw_bytes(), sectioned);
        assert_eq!(sectioned_document.output().bytes(), sectioned);
        let mp1 = row_id(&sectioned_document, "MP1");
        let mp2 = row_id(&sectioned_document, "MP2");
        assert_eq!(
            sectioned_document
                .root_rows()
                .iter()
                .map(LineConfigRow::kind)
                .collect::<Vec<_>>(),
            [LineConfigNodeKind::Section, LineConfigNodeKind::Section]
        );
        for section in [mp1, mp2] {
            let children = sectioned_document
                .children(section)
                .expect("MP section children");
            assert_eq!(children.len(), 2);
            assert!(children.iter().all(|row| row.parent() == Some(section)));
        }
    }

    #[test]
    fn mariadb_optional_includedir_uses_an_exact_audited_version_matrix() {
        let source = b"?includedir /etc/mysql/conf.d\n";
        // Official MariaDB release-tag source evidence for the negative and
        // positive sides of each audited boundary:
        // https://github.com/MariaDB/server/blob/mariadb-11.4.9/mysys/my_default.c#L679-L708
        // https://github.com/MariaDB/server/blob/mariadb-11.4.10/mysys/my_default.c#L681-L717
        // https://github.com/MariaDB/server/blob/mariadb-11.8.5/mysys/my_default.c#L679-L708
        // https://github.com/MariaDB/server/blob/mariadb-11.8.6/mysys/my_default.c#L681-L717
        // https://github.com/MariaDB/server/blob/mariadb-12.0.2/mysys/my_default.c#L679-L708
        // https://github.com/MariaDB/server/blob/mariadb-12.1.2/mysys/my_default.c#L679-L708
        // https://github.com/MariaDB/server/blob/mariadb-12.2.2/mysys/my_default.c#L681-L717
        for version in [
            DatabaseConfigVersion::new(11, 4, 10),
            DatabaseConfigVersion::new(11, 8, 6),
            DatabaseConfigVersion::new(12, 2, 2),
        ] {
            let policy = LineConfigTargetPolicy::for_database_config(
                DatabaseConfigProduct::MariaDb,
                version,
            );
            let document = LineConfigVisualDocument::parse_bytes_with_target_policy(
                LineConfigDialect::MySqlOption,
                policy,
                source.to_vec(),
            )
            .expect("audited MariaDB optional includedir source");
            assert_eq!(document.target_policy, policy, "{version:?}");
            assert!(document.is_structured(), "{version:?}");
            assert_eq!(document.output().bytes(), source, "{version:?}");
            assert_eq!(
                document.root_rows()[0].kind(),
                LineConfigNodeKind::Include,
                "{version:?}"
            );
        }

        for version in [
            DatabaseConfigVersion::new(11, 4, 9),
            DatabaseConfigVersion::new(11, 4, 11),
            DatabaseConfigVersion::new(11, 8, 5),
            DatabaseConfigVersion::new(11, 8, 7),
            DatabaseConfigVersion::new(12, 0, 2),
            DatabaseConfigVersion::new(12, 1, 2),
            DatabaseConfigVersion::new(12, 2, 1),
            DatabaseConfigVersion::new(12, 2, 3),
            DatabaseConfigVersion::new_with_revision(11, 4, 10, 1),
        ] {
            let policy = LineConfigTargetPolicy::for_database_config(
                DatabaseConfigProduct::MariaDb,
                version,
            );
            let document = LineConfigVisualDocument::parse_bytes_with_target_policy(
                LineConfigDialect::MySqlOption,
                policy,
                source.to_vec(),
            )
            .expect("unknown or unsupported MariaDB source remains inspectable");
            assert_eq!(document.target_policy, policy, "{version:?}");
            assert!(!document.is_structured(), "{version:?}");
            assert_eq!(document.output().bytes(), source, "{version:?}");
            assert_eq!(
                document.root_rows()[0].kind(),
                LineConfigNodeKind::Opaque,
                "{version:?}"
            );
        }

        let mysql_policy = LineConfigTargetPolicy::for_database_config(
            DatabaseConfigProduct::MySql,
            DatabaseConfigVersion::new(11, 4, 10),
        );
        let mysql = LineConfigVisualDocument::parse_bytes_with_target_policy(
            LineConfigDialect::MySqlOption,
            mysql_policy,
            source.to_vec(),
        )
        .expect("a MariaDB version number must not grant MySQL syntax");
        assert_eq!(mysql.root_rows()[0].kind(), LineConfigNodeKind::Opaque);

        let default =
            LineConfigVisualDocument::parse_bytes(LineConfigDialect::MySqlOption, source.to_vec())
                .expect("the unversioned constructor remains inspectable");
        assert_eq!(default.target_policy, LineConfigTargetPolicy::UNVERSIONED);
        assert_eq!(default.root_rows()[0].kind(), LineConfigNodeKind::Opaque);
        assert_eq!(default.output().bytes(), source);
    }

    #[test]
    fn mariadb_optional_includedir_matches_only_official_safe_line_shapes() {
        let policy = LineConfigTargetPolicy::for_database_config(
            DatabaseConfigProduct::MariaDb,
            DatabaseConfigVersion::new(11, 8, 6),
        );
        let source = concat!(
            "?includedir /one\n",
            "? includedir /two\n",
            " \t?\tincludedir\t/three\t\n",
            "?includedir /path with spaces\n",
            "?INCLUDEDIR /upper\n",
            "?includeDir /mixed\n",
            "?include /file.cnf\n",
            "? includedir /with/hash # is path data, not a comment\n",
            "?includedir /literal#hash\n",
        );
        let document = LineConfigVisualDocument::parse_with_target_policy(
            LineConfigDialect::MySqlOption,
            policy,
            source,
        )
        .expect("mixed optional include shapes remain inspectable");
        assert_eq!(document.output().bytes(), source.as_bytes());
        assert!(!document.is_structured());
        let rows = document.root_rows();
        assert_eq!(rows.len(), 9);
        assert!(
            rows[..4]
                .iter()
                .all(|row| row.kind() == LineConfigNodeKind::Include && row.editable())
        );
        assert_eq!(rows[0].name(), Some("?includedir"));
        assert_eq!(rows[1].name(), Some("? includedir"));
        assert_eq!(rows[2].name(), Some("?\tincludedir"));
        assert_eq!(rows[2].value(), Some("/three"));
        assert_eq!(rows[3].value(), Some("/path with spaces"));
        assert!(
            rows[4..]
                .iter()
                .all(|row| row.kind() == LineConfigNodeKind::Opaque && !row.editable())
        );
    }

    #[test]
    fn mariadb_optional_includedir_mutations_reparse_with_the_same_policy() {
        let policy = LineConfigTargetPolicy::for_database_config(
            DatabaseConfigProduct::MariaDb,
            DatabaseConfigVersion::new(12, 2, 2),
        );
        let mut unversioned = LineConfigVisualDocument::blank(LineConfigDialect::MySqlOption);
        assert!(
            unversioned
                .add_include(None, "?includedir", "/etc/mysql/optional.d")
                .is_err()
        );
        assert!(unversioned.raw_bytes().is_empty());

        let mut unsupported = LineConfigVisualDocument::blank_with_target_policy(
            LineConfigDialect::MySqlOption,
            LineConfigTargetPolicy::for_database_config(
                DatabaseConfigProduct::MariaDb,
                DatabaseConfigVersion::new(12, 2, 3),
            ),
        );
        assert!(
            unsupported
                .add_include(None, "?includedir", "/etc/mysql/optional.d")
                .is_err()
        );

        let mut document = LineConfigVisualDocument::blank_with_target_policy(
            LineConfigDialect::MySqlOption,
            policy,
        );
        document
            .add_include(None, "? includedir", "/etc/mysql/old.d")
            .expect("audited target can generate optional includedir");
        assert_eq!(document.target_policy, policy);
        assert_eq!(
            document.output().bytes(),
            b"? includedir /etc/mysql/old.d\n"
        );
        assert_eq!(document.root_rows()[0].kind(), LineConfigNodeKind::Include);

        let stale_after_insert = document.root_rows()[0].id();
        document
            .add_section("mariadb")
            .expect("a following group reparses under the same policy");
        assert_eq!(document.target_policy, policy);
        assert!(document.row_by_id(stale_after_insert).is_none());
        assert_eq!(document.root_rows()[0].kind(), LineConfigNodeKind::Include);

        let include = document.root_rows()[0].id();
        document
            .update_entry(include, "?includedir", Some("/etc/mysql/new.d"))
            .expect("optional includedir update uses the stored policy");
        assert!(document.row_by_id(include).is_none());
        assert_eq!(document.target_policy, policy);
        assert_eq!(
            document.output().bytes(),
            b"?includedir /etc/mysql/new.d\n[mariadb]\n"
        );
        assert_eq!(document.root_rows()[0].kind(), LineConfigNodeKind::Include);

        let current = document.root_rows()[0].id();
        for (directive, target) in [
            ("?include", "/tmp/file.cnf"),
            ("?INCLUDEDIR", "/tmp/upper"),
            ("?includedir", "/tmp/hash#path"),
            ("?includedir", "\"/tmp/quoted\""),
            ("?includedir", r"/tmp/escaped\ path"),
            ("?includedir", "/tmp/good\nport=1"),
        ] {
            let before = document.output();
            assert!(
                document
                    .update_entry(current, directive, Some(target))
                    .is_err(),
                "unexpectedly accepted {directive} {target:?}"
            );
            assert_eq!(document.output(), before);
            assert!(document.row_by_id(current).is_some());
        }

        document
            .replace_raw(b"? includedir /etc/mysql/replaced.d\n".to_vec())
            .expect("raw replacement reparses with the stored policy");
        assert_eq!(document.target_policy, policy);
        assert_eq!(document.root_rows()[0].kind(), LineConfigNodeKind::Include);
        assert_eq!(
            document.output().bytes(),
            b"? includedir /etc/mysql/replaced.d\n"
        );

        let mut normal = LineConfigVisualDocument::parse(
            LineConfigDialect::MySqlOption,
            "!includedir /etc/mysql/required.d\n",
        )
        .expect("ordinary include remains structured by default");
        let required = normal.root_rows()[0].id();
        assert!(
            normal
                .update_entry(required, "?includedir", Some("/etc/mysql/optional.d"))
                .is_err()
        );
        assert_eq!(
            normal.output().bytes(),
            b"!includedir /etc/mysql/required.d\n"
        );
    }

    #[test]
    fn mariadb_optional_includedir_preserves_bytes_and_requires_terminal_lf() {
        let policy = LineConfigTargetPolicy::for_database_config(
            DatabaseConfigProduct::MariaDb,
            DatabaseConfigVersion::new(11, 4, 10),
        );
        let crlf = b"? includedir C:/MariaDB/optional.d\r\n[mariadb]\r\nport=3306\r\n";
        let document = LineConfigVisualDocument::parse_bytes_with_target_policy(
            LineConfigDialect::MySqlOption,
            policy,
            crlf.to_vec(),
        )
        .expect("CRLF source should remain byte exact");
        assert!(document.is_structured());
        assert_eq!(document.output().bytes(), crlf);
        assert_eq!(document.root_rows()[0].kind(), LineConfigNodeKind::Include);

        let terminal = b"[mariadb]\n?includedir /etc/mysql/optional.d";
        let mut opaque = LineConfigVisualDocument::parse_bytes_with_target_policy(
            LineConfigDialect::MySqlOption,
            policy,
            terminal.to_vec(),
        )
        .expect("a terminal optional include without LF remains inspectable");
        assert!(!opaque.is_structured());
        assert_eq!(opaque.output().bytes(), terminal);
        assert_eq!(opaque.root_rows().len(), 1);
        assert_eq!(opaque.root_rows()[0].kind(), LineConfigNodeKind::Opaque);
        assert!(opaque.add_section("client").is_err());
        assert_eq!(opaque.output().bytes(), terminal);

        let directory = env::temp_dir().join(format!(
            "lovelyres-mariadb-optional-include-{}-{}",
            process::id(),
            next_document_revision()
        ));
        fs::create_dir(&directory).expect("create isolated temporary directory");
        let source_path = directory.join("my.cnf");
        fs::write(&source_path, crlf).expect("write isolated MariaDB fixture");
        let imported = LineConfigVisualDocument::read_local_with_target_policy(
            LineConfigDialect::MySqlOption,
            policy,
            &source_path,
        )
        .expect("explicit local target policy should be honored");
        assert_eq!(imported.target_policy, policy);
        assert_eq!(imported.output().bytes(), crlf);
        assert_eq!(imported.root_rows()[0].kind(), LineConfigNodeKind::Include);
        fs::remove_file(&source_path).expect("remove isolated MariaDB fixture");
        fs::remove_dir(&directory).expect("remove isolated temporary directory");
    }

    #[test]
    fn mysql_option_lexer_fails_closed_and_round_trips_vendor_boundaries() {
        let source = b"root_only=1\n\
!INCLUDE /tmp/upper.cnf\n\
!include \"/tmp/quoted.cnf\"\n\
!include /tmp/escaped\\ path.cnf\n\
!include /tmp/escaped\\#hash.cnf\n\
?includedir /tmp/optional\n\
[mysqld]\n\
x=abc\\#tail\n\
! include /etc/mysql/extra.cnf\n\
! includedir C:\\ProgramData\\MySQL\\conf.d\n\
!include C:/ProgramData/MySQL/MySQL Server/myopts.ini # trailing comment\n";
        let document =
            LineConfigVisualDocument::parse_bytes(LineConfigDialect::MySqlOption, source.to_vec())
                .expect("MySQL source should remain available");

        assert!(!document.is_structured());
        assert_eq!(document.output().bytes(), source);
        let roots = document.root_rows();
        assert_eq!(roots.len(), 7);
        assert_eq!(roots[0].kind(), LineConfigNodeKind::Opaque);
        assert_eq!(roots[1].kind(), LineConfigNodeKind::Opaque);
        assert_eq!(roots[2].kind(), LineConfigNodeKind::Opaque);
        assert_eq!(roots[3].kind(), LineConfigNodeKind::Include);
        assert_eq!(roots[3].value(), Some(r"/tmp/escaped\ path.cnf"));
        assert_eq!(roots[4].kind(), LineConfigNodeKind::Include);
        assert_eq!(roots[4].value(), Some(r"/tmp/escaped\"));
        assert_eq!(roots[5].kind(), LineConfigNodeKind::Opaque);

        let section = row_id(&document, "mysqld");
        let children = document.children(section).expect("MySQL section children");
        assert_eq!(children.len(), 4);
        let escaped_hash = children
            .iter()
            .find(|row| row.name() == Some("x"))
            .expect("entry before an inline comment");
        assert_eq!(escaped_hash.value(), Some("abc\\"));
        assert!(children.iter().any(|row| {
            row.kind() == LineConfigNodeKind::Include
                && row.name() == Some("! include")
                && row.value() == Some("/etc/mysql/extra.cnf")
        }));
        assert!(children.iter().any(|row| {
            row.kind() == LineConfigNodeKind::Include
                && row.name() == Some("! includedir")
                && row.value() == Some(r"C:\ProgramData\MySQL\conf.d")
        }));
        assert!(children.iter().any(|row| {
            row.kind() == LineConfigNodeKind::Include
                && row.name() == Some("!include")
                && row.value() == Some("C:/ProgramData/MySQL/MySQL Server/myopts.ini")
        }));
    }

    #[test]
    fn mysql_utf8_bom_is_not_silently_consumed() {
        let source = b"\xEF\xBB\xBF; not-a-server-comment\r\n[mysqld]\r\nport=3306";
        let document =
            LineConfigVisualDocument::parse_bytes(LineConfigDialect::MySqlOption, source.to_vec())
                .expect("a BOM-prefixed MySQL file must remain inspectable");

        assert!(!document.is_structured());
        assert_eq!(document.output().bytes(), source);
        let roots = document.root_rows();
        assert_eq!(roots.len(), 2);
        assert_eq!(roots[0].kind(), LineConfigNodeKind::Opaque);
        assert_eq!(roots[1].name(), Some("mysqld"));
        assert_eq!(document.children(roots[1].id()).unwrap().len(), 1);
    }

    #[test]
    fn mysql_terminal_include_without_lf_is_a_portability_barrier() {
        let source = b"[mysqld]\n!include /etc/mysql/extra.cnf";
        let mut document =
            LineConfigVisualDocument::parse_bytes(LineConfigDialect::MySqlOption, source.to_vec())
                .expect("a terminal include without LF must remain inspectable");

        assert!(!document.is_structured());
        assert_eq!(document.output().bytes(), source);
        let rows = document.rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind(), LineConfigNodeKind::Opaque);
        assert!(document.add_entry(None, "port", Some("3306")).is_err());
        assert_eq!(document.output().bytes(), source);
    }

    #[test]
    fn mysql_option_generation_requires_group_and_safe_exact_includes() {
        let mut document = LineConfigVisualDocument::blank(LineConfigDialect::MySqlOption);
        assert!(document.add_entry(None, "port", Some("3306")).is_err());
        assert!(document.raw_bytes().is_empty());

        document
            .add_include(None, "! includedir", r"C:\ProgramData\MySQL\conf.d")
            .expect("ordinary Windows backslashes are valid in an include path");
        document
            .add_include(
                None,
                "!include",
                "C:/ProgramData/MySQL/MySQL Server/myopts.ini",
            )
            .expect("an unquoted include path may contain ordinary spaces");
        document
            .add_section("mysqld")
            .expect("MySQL section should be generated");
        let section = row_id(&document, "mysqld");
        document
            .add_entry(Some(section), "port", Some("3306"))
            .expect("option under a group should be generated");
        let section = row_id(&document, "mysqld");
        document
            .add_include(Some(section), "!include", "/etc/mysql/extra.cnf")
            .expect("compact lowercase include should be generated");
        assert_eq!(
            document.raw_bytes(),
            b"! includedir C:\\ProgramData\\MySQL\\conf.d\n!include C:/ProgramData/MySQL/MySQL Server/myopts.ini\n[mysqld]\nport=3306\n!include /etc/mysql/extra.cnf\n"
        );

        let section = row_id(&document, "mysqld");
        for (directive, target) in [
            ("!INCLUDE", "/tmp/x.cnf"),
            ("! includeDir", "/tmp/x.cnf"),
            ("?includedir", "/tmp/x"),
            ("!unknown", "/tmp/x"),
            ("!include", "\"/tmp/x.cnf\""),
            ("!include", r"/tmp/bad\ path.cnf"),
            ("!include", r"/tmp/bad\#path.cnf"),
            ("!include", r#"/tmp/bad\"path.cnf"#),
            ("!include", "\t"),
            ("!include", ""),
            ("!include", "/tmp/x.cnf\nport=1"),
        ] {
            let before = document.raw_bytes().to_vec();
            assert!(
                document
                    .add_include(Some(section), directive, target)
                    .is_err(),
                "unexpectedly accepted {directive} {target:?}"
            );
            assert_eq!(document.raw_bytes(), before);
        }

        let imported = b"[mysqld]\n!include /tmp/good.cnf\n";
        let mut imported_document = LineConfigVisualDocument::parse_bytes(
            LineConfigDialect::MySqlOption,
            imported.to_vec(),
        )
        .expect("a safe imported include should remain structured");
        let include = imported_document
            .rows()
            .into_iter()
            .find(|row| row.kind() == LineConfigNodeKind::Include)
            .expect("the imported include should be visible")
            .id();
        assert!(
            imported_document
                .update_entry(include, "!include", Some(r"/tmp/bad\ path.cnf"))
                .is_err(),
            "updating an imported include must use the same generation safety boundary"
        );
        assert_eq!(imported_document.raw_bytes(), imported);
    }

    #[test]
    fn mysql_ambiguous_section_lines_are_scope_barriers_and_cannot_be_generated() {
        let source = b"[client]\n[mysqld]junk\nskip-grant-tables\n[mysqld]\nport=3306";
        let document =
            LineConfigVisualDocument::parse_bytes(LineConfigDialect::MySqlOption, source.to_vec())
                .expect("ambiguous MySQL groups must remain visible");

        assert!(!document.is_structured());
        assert_eq!(document.output().bytes(), source);
        let roots = document.root_rows();
        assert_eq!(roots.len(), 4);
        assert_eq!(roots[0].name(), Some("client"));
        assert!(document.children(roots[0].id()).unwrap().is_empty());
        assert_eq!(roots[1].kind(), LineConfigNodeKind::Opaque);
        assert_eq!(roots[2].kind(), LineConfigNodeKind::Opaque);
        assert_eq!(roots[3].name(), Some("mysqld"));
        let mysqld = document.children(roots[3].id()).unwrap();
        assert_eq!(mysqld.len(), 1);
        assert_eq!(mysqld[0].name(), Some("port"));

        let mut generated = LineConfigVisualDocument::blank(LineConfigDialect::MySqlOption);
        generated.add_section("client").unwrap();
        let client = row_id(&generated, "client");
        let before = generated.raw_bytes().to_vec();
        for key in ["[mysqld]junk", "[[mysqld]]", "[unterminated"] {
            assert!(generated.add_entry(Some(client), key, None).is_err());
            assert_eq!(generated.raw_bytes(), before);
        }
        assert!(
            generated
                .add_entry(Some(client), "quoted\"=separator\"", Some("value"))
                .is_err()
        );
        assert_eq!(generated.raw_bytes(), before);

        let separator = LineConfigVisualDocument::parse(
            LineConfigDialect::MySqlOption,
            "[client]\nquoted\"=separator\"=value",
        )
        .expect("MySQL always uses the first equals byte as the separator");
        let row = separator.children(separator.root_rows()[0].id()).unwrap();
        assert_eq!(row[0].name(), Some("quoted\""));
        assert_eq!(row[0].value(), Some("separator\"=value"));

        let leading_space =
            LineConfigVisualDocument::parse(LineConfigDialect::MySqlOption, "[ mysqld]\nport=3306")
                .expect("a leading group-name space is source data, not trimming trivia");
        assert_eq!(leading_space.root_rows()[0].name(), Some(" mysqld"));
    }

    #[test]
    fn mysql_latin1_control_whitespace_matches_the_server_group_scanner() {
        let source = b"[client]\n\x0b[mysqld\x0c]\nskip-grant-tables\n";
        let second_line = next_physical_line(source, b"[client]\n".len());
        let second_trimmed = trim_dialect_space(
            LineConfigDialect::MySqlOption,
            source,
            second_line.content.clone(),
        );
        assert_eq!(&source[second_trimmed.clone()], b"[mysqld\x0c]");
        assert!(
            parse_section_header(LineConfigDialect::MySqlOption, source, second_trimmed,).is_some()
        );
        let document =
            LineConfigVisualDocument::parse_bytes(LineConfigDialect::MySqlOption, source.to_vec())
                .expect("MySQL control whitespace around a group must remain byte exact");

        assert!(document.is_structured(), "rows: {:?}", document.rows());
        assert_eq!(document.output().bytes(), source);
        let roots = document.root_rows();
        assert_eq!(roots.len(), 2);
        assert_eq!(roots[0].name(), Some("client"));
        assert_eq!(roots[1].name(), Some("mysqld"));
        let children = document.children(roots[1].id()).unwrap();
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].name(), Some("skip-grant-tables"));

        let mut generated = LineConfigVisualDocument::blank(LineConfigDialect::MySqlOption);
        assert!(generated.add_section("client\u{000b}").is_err());
        assert!(generated.raw_bytes().is_empty());
        generated.add_section("mysqld").unwrap();
        let mysqld = row_id(&generated, "mysqld");
        assert!(
            generated
                .add_entry(Some(mysqld), "port\u{000c}", Some("3306"))
                .is_err()
        );
        assert!(
            generated
                .add_comment(Some(mysqld), "hidden\u{000b}comment")
                .is_err()
        );
        assert_eq!(generated.raw_bytes(), b"[mysqld]");
    }

    #[test]
    fn gbase_8s_sqlhosts_records_are_visible_and_round_trip_byte_exactly() {
        let source = b"# dbserver nettype hostname service options\r\n\
g_cluster_1 group - - i=1\r\n\
gbaseserver onsoctcp 192.0.2.10 9088 g=g_cluster_1\r\n";
        let document =
            LineConfigVisualDocument::parse_bytes(LineConfigDialect::Whitespace, source.to_vec())
                .expect("GBase 8s sqlhosts sample should parse");

        assert!(document.is_structured());
        assert_eq!(document.raw_bytes(), source);
        assert_eq!(document.output().bytes(), source);
        let rows = document.rows();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].kind(), LineConfigNodeKind::Comment);
        assert_eq!(rows[1].kind(), LineConfigNodeKind::Entry);
        assert_eq!(rows[1].name(), Some("g_cluster_1"));
        assert_eq!(rows[1].value(), Some("group - - i=1"));
        assert_eq!(rows[2].name(), Some("gbaseserver"));
        assert_eq!(
            rows[2].value(),
            Some("onsoctcp 192.0.2.10 9088 g=g_cluster_1")
        );
    }

    #[test]
    fn unknown_and_complex_structures_stay_opaque_and_lossless() {
        let binary = vec![0xFF, 0, b'p', b'a', b's', b's'];
        let binary_document =
            LineConfigVisualDocument::parse_bytes(LineConfigDialect::FlatKeyValue, binary.clone())
                .expect("binary source is preserved as opaque");
        assert!(!binary_document.is_structured());
        assert_eq!(binary_document.output().bytes(), binary);
        assert_eq!(binary_document.rows().len(), 1);
        assert_eq!(binary_document.rows()[0].kind(), LineConfigNodeKind::Opaque);

        let malformed = b"good=1\nnot safely recognized\nother=2";
        let mixed = LineConfigVisualDocument::parse_bytes(
            LineConfigDialect::FlatKeyValue,
            malformed.to_vec(),
        )
        .expect("mixed source should parse conservatively");
        assert!(!mixed.is_structured());
        assert_eq!(mixed.output().bytes(), malformed);
        assert_eq!(
            mixed
                .rows()
                .iter()
                .filter(|row| row.kind() == LineConfigNodeKind::Opaque)
                .count(),
            1
        );

        let toml_source = b"description = \"\"\"first\nsecond\"\"\"\nitems = [\n  1,\n  2\n]\nvalid = true\n[[array_table]]";
        let toml =
            LineConfigVisualDocument::parse_bytes(LineConfigDialect::Toml, toml_source.to_vec())
                .expect("complex TOML should remain available");
        assert!(!toml.is_structured());
        assert_eq!(toml.output().bytes(), toml_source);
        assert_eq!(
            toml.rows()
                .iter()
                .filter(|row| row.kind() == LineConfigNodeKind::Opaque)
                .count(),
            3
        );
        assert!(
            toml.rows().iter().any(|row| {
                row.kind() == LineConfigNodeKind::Entry && row.name() == Some("valid")
            })
        );

        let properties_source = b"continued=first\\\n second\nnormal=value";
        let properties = LineConfigVisualDocument::parse_bytes(
            LineConfigDialect::JavaProperties,
            properties_source.to_vec(),
        )
        .expect("continued property should remain available");
        assert!(!properties.is_structured());
        assert_eq!(properties.output().bytes(), properties_source);
        assert_eq!(properties.rows()[0].kind(), LineConfigNodeKind::Opaque);
        assert_eq!(properties.rows()[1].name(), Some("normal"));
    }

    #[test]
    fn visual_inputs_cannot_inject_lines_or_comment_syntax() {
        let mut document = LineConfigVisualDocument::blank(LineConfigDialect::FlatKeyValue);
        let original = document.output();
        assert!(
            document
                .add_entry(None, "safe\ninjected", Some("1"))
                .is_err()
        );
        assert!(
            document
                .add_entry(None, "safe", Some("1\ninjected=2"))
                .is_err()
        );
        assert!(document.add_entry(None, "safe#hidden", Some("1")).is_err());
        assert!(
            document
                .add_entry(None, "safe", Some("1 # hidden=2"))
                .is_err()
        );
        assert!(document.add_comment(None, "ok\ninjected=2").is_err());
        assert_eq!(document.output(), original);

        document
            .add_entry(None, "safe", Some("\"quoted#value\""))
            .expect("quoted hash remains data");
        assert_eq!(document.rows()[0].value(), Some("\"quoted#value\""));

        let mut ini = LineConfigVisualDocument::blank(LineConfigDialect::Ini);
        assert!(ini.add_section("main]\n[injected").is_err());
        assert!(ini.add_section("main] # injected").is_err());
        assert!(ini.raw_bytes().is_empty());

        let mut hba = LineConfigVisualDocument::blank(LineConfigDialect::PgHba);
        assert!(
            hba.add_record(None, "local all all peer\nhost all all trust")
                .is_err()
        );
        assert!(hba.add_comment(None, "disabled \\").is_err());
        assert!(hba.raw_bytes().is_empty());
    }

    #[test]
    fn node_ids_fail_closed_after_every_successful_edit() {
        let mut document =
            LineConfigVisualDocument::parse(LineConfigDialect::FlatKeyValue, "first=1\nsecond=2")
                .expect("fixture should parse");
        let first = row_id(&document, "first");
        document
            .update_entry(first, "first", Some("changed"))
            .expect("entry update should succeed");
        assert!(document.row_by_id(first).is_none());
        assert!(
            document
                .update_entry(first, "first", Some("again"))
                .is_err()
        );

        let current_first = row_id(&document, "first");
        document
            .move_down(current_first)
            .expect("sibling move should succeed");
        assert!(document.row_by_id(current_first).is_none());
        assert!(document.remove(current_first).is_err());

        let current_first = row_id(&document, "first");
        document
            .remove(current_first)
            .expect("remove should succeed");
        assert!(document.row_by_id(current_first).is_none());
    }

    #[test]
    fn foreign_document_node_ids_fail_closed_without_mutation() {
        fn assert_rejected_unchanged(
            document: &mut LineConfigVisualDocument,
            mutation: impl FnOnce(&mut LineConfigVisualDocument) -> CoreResult<()>,
        ) {
            let dialect = document.dialect();
            let raw = document.raw_bytes().to_vec();
            let output = document.output().bytes().to_vec();
            let rows = document.rows();
            let structured = document.is_structured();
            let contains_sensitive_values = document.contains_sensitive_values();

            match mutation(document).expect_err("foreign line-config node ID must fail closed") {
                CoreError::Validation { subject, message } => {
                    assert_eq!(subject, "line configuration visual edit");
                    assert_eq!(
                        message,
                        "selected line configuration node is stale or missing"
                    );
                }
                error => panic!("unexpected foreign-ID error: {error}"),
            }

            assert_eq!(document.dialect(), dialect);
            assert_eq!(document.raw_bytes(), raw);
            assert_eq!(document.output().bytes(), output);
            // Rows include revision-scoped IDs, so exact equality also proves
            // that the document revision and complete projected tree did not change.
            assert_eq!(document.rows(), rows);
            assert_eq!(document.is_structured(), structured);
            assert_eq!(
                document.contains_sensitive_values(),
                contains_sensitive_values
            );
        }

        let mut document = LineConfigVisualDocument::parse(
            LineConfigDialect::Ini,
            "[local]\nkey=value\n# local document\n",
        )
        .unwrap();
        let foreign_document =
            LineConfigVisualDocument::parse(LineConfigDialect::Ini, "[foreign]\nkey=value\n")
                .unwrap();
        let foreign = foreign_document.rows()[0].id();

        assert_rejected_unchanged(&mut document, |document| {
            document.add_entry(Some(foreign), "added", Some("value"))
        });
        assert_rejected_unchanged(&mut document, |document| {
            document.add_comment(Some(foreign), "foreign comment")
        });
        assert_rejected_unchanged(&mut document, |document| {
            document.update_entry(foreign, "key", Some("changed"))
        });
        assert_rejected_unchanged(&mut document, |document| {
            document.update_container(foreign, "renamed")
        });
        assert_rejected_unchanged(&mut document, |document| {
            document.update_record(foreign, "local all all peer")
        });
        assert_rejected_unchanged(&mut document, |document| {
            document.update_comment(foreign, "foreign comment")
        });
        assert_rejected_unchanged(&mut document, |document| document.remove(foreign));
        assert_rejected_unchanged(&mut document, |document| document.move_up(foreign));
        assert_rejected_unchanged(&mut document, |document| document.move_down(foreign));

        let mut postgres = LineConfigVisualDocument::parse(
            LineConfigDialect::PostgresConf,
            "max_connections = 100\n",
        )
        .unwrap();
        let foreign_postgres = LineConfigVisualDocument::parse(
            LineConfigDialect::PostgresConf,
            "shared_buffers = '128MB'\n",
        )
        .unwrap()
        .rows()[0]
            .id();
        assert_rejected_unchanged(&mut postgres, |document| {
            document.add_include(Some(foreign_postgres), "include", "'local.conf'")
        });

        let mut toml =
            LineConfigVisualDocument::parse(LineConfigDialect::Toml, "[local]\nkey = 1\n").unwrap();
        let foreign_toml =
            LineConfigVisualDocument::parse(LineConfigDialect::Toml, "[foreign]\nkey = 1\n")
                .unwrap()
                .rows()[0]
                .id();
        assert_rejected_unchanged(&mut toml, |document| {
            document.add_table(Some(foreign_toml), "child")
        });

        let mut hba =
            LineConfigVisualDocument::parse(LineConfigDialect::PgHba, "local all all peer\n")
                .unwrap();
        let foreign_hba = LineConfigVisualDocument::parse(
            LineConfigDialect::PgHba,
            "host all all 127.0.0.1/32 scram-sha-256\n",
        )
        .unwrap()
        .rows()[0]
            .id();
        assert_rejected_unchanged(&mut hba, |document| {
            document.add_record(Some(foreign_hba), "host all all 10.0.0.0/8 scram-sha-256")
        });
    }

    #[test]
    fn sensitive_values_never_escape_rows_or_debug_output() {
        let source = "password=super-secret\nendpoint=postgres://alice:url-secret@localhost/db\nwsrep_sst_auth=alice:galera-secret\nnormal=visible\n# password backup-secret";
        let document = LineConfigVisualDocument::parse(LineConfigDialect::FlatKeyValue, source)
            .expect("fixture should parse");
        assert!(document.contains_sensitive_values());
        let rows = document.rows();
        let password = rows
            .iter()
            .find(|row| row.name() == Some("password"))
            .expect("password row");
        assert!(password.sensitive());
        assert_eq!(password.value(), None);
        assert!(!password.editable());
        assert_eq!(password.preview(), "[sensitive value redacted]");
        let endpoint = rows
            .iter()
            .find(|row| row.name() == Some("endpoint"))
            .expect("URL row");
        assert!(endpoint.sensitive());
        assert_eq!(endpoint.value(), None);
        let galera = rows
            .iter()
            .find(|row| row.name() == Some("wsrep_sst_auth"))
            .expect("Galera SST credential row");
        assert!(galera.sensitive());
        assert_eq!(galera.value(), None);
        assert_eq!(galera.preview(), "[sensitive value redacted]");
        assert!(
            rows.iter()
                .any(|row| { row.kind() == LineConfigNodeKind::Comment && row.sensitive() })
        );

        for debug in [
            format!("{document:?}"),
            format!("{:?}", document.output()),
            format!("{rows:?}"),
        ] {
            assert!(!debug.contains("super-secret"));
            assert!(!debug.contains("url-secret"));
            assert!(!debug.contains("galera-secret"));
            assert!(!debug.contains("backup-secret"));
            assert!(!debug.contains("visible"));
        }

        let password_id = password.id();
        let mut editable = document.clone();
        assert!(
            editable
                .update_entry(password_id, "password", Some("replacement"))
                .is_err()
        );

        let opaque_secret = b"\0wsrep_sst_auth=alice:opaque-secret".to_vec();
        let opaque =
            LineConfigVisualDocument::parse_bytes(LineConfigDialect::FlatKeyValue, opaque_secret)
                .expect("opaque source should parse");
        let opaque_row = &opaque.rows()[0];
        assert!(opaque_row.sensitive());
        assert_eq!(opaque_row.value(), None);
        assert!(!format!("{opaque_row:?}").contains("opaque-secret"));
    }

    #[test]
    fn authkey_exact_spellings_are_redacted_without_matching_other_auth_settings() {
        let source = "AUTHKEY K9z7Q2\nauthKey CamelDontLeak\nAUTH_KEY SnakeDontLeak\nauthority safe-authority\nauth_method scram\nauthentication_mode strict\n# authKey CommentDontLeak\n# authority remains visible\n# notauthkey remains visible";
        let document = LineConfigVisualDocument::parse(LineConfigDialect::Whitespace, source)
            .expect("vendor whitespace fixture");
        assert!(document.is_structured());
        assert!(document.contains_sensitive_values());
        assert_eq!(document.output().bytes(), source.as_bytes());

        let rows = document.rows();
        for key in ["AUTHKEY", "authKey", "AUTH_KEY"] {
            let row = rows
                .iter()
                .find(|row| row.name() == Some(key))
                .unwrap_or_else(|| panic!("missing {key} row"));
            assert!(row.sensitive());
            assert_eq!(row.value(), None);
            assert_eq!(row.preview(), "[sensitive value redacted]");
            assert!(!row.editable());
        }
        for key in ["authority", "auth_method", "authentication_mode"] {
            let row = rows
                .iter()
                .find(|row| row.name() == Some(key))
                .unwrap_or_else(|| panic!("missing safe {key} row"));
            assert!(!row.sensitive());
            assert!(row.value().is_some());
        }
        let comments = rows
            .iter()
            .filter(|row| row.kind() == LineConfigNodeKind::Comment)
            .collect::<Vec<_>>();
        assert_eq!(comments.len(), 3);
        assert!(comments[0].sensitive());
        assert!(!comments[1].sensitive());
        assert!(!comments[2].sensitive());

        for debug in [
            format!("{document:?}"),
            format!("{:?}", document.output()),
            format!("{rows:?}"),
        ] {
            for secret in [
                "K9z7Q2",
                "CamelDontLeak",
                "SnakeDontLeak",
                "CommentDontLeak",
            ] {
                assert!(!debug.contains(secret));
            }
        }

        let opaque_source = b"\0AUTH_KEY OpaqueDontLeak".to_vec();
        let opaque = LineConfigVisualDocument::parse_bytes(
            LineConfigDialect::Whitespace,
            opaque_source.clone(),
        )
        .expect("opaque vendor whitespace fixture");
        assert!(!opaque.is_structured());
        assert!(opaque.contains_sensitive_values());
        assert_eq!(opaque.output().bytes(), opaque_source);
        let opaque_rows = opaque.rows();
        assert_eq!(opaque_rows.len(), 1);
        assert!(opaque_rows[0].sensitive());
        assert_eq!(opaque_rows[0].value(), None);
        assert_eq!(opaque_rows[0].preview(), "[sensitive value redacted]");
        assert!(!format!("{opaque:?}{opaque_rows:?}").contains("OpaqueDontLeak"));
    }

    #[test]
    fn document_node_depth_preview_and_edit_limits_are_enforced() {
        let maximum = vec![b' '; MAX_LINE_CONFIG_BYTES];
        let maximum_document =
            LineConfigVisualDocument::parse_bytes(LineConfigDialect::FlatKeyValue, maximum)
                .expect("exact document limit should be accepted");
        assert_eq!(maximum_document.raw_bytes().len(), MAX_LINE_CONFIG_BYTES);
        assert!(
            LineConfigVisualDocument::parse_bytes(
                LineConfigDialect::FlatKeyValue,
                vec![b'x'; MAX_LINE_CONFIG_BYTES + 1],
            )
            .is_err()
        );

        let mut too_many_nodes = Vec::with_capacity((MAX_LINE_CONFIG_NODES + 1) * 4);
        for _ in 0..=MAX_LINE_CONFIG_NODES {
            too_many_nodes.extend_from_slice(b"a=1\n");
        }
        let too_many_nodes_document = LineConfigVisualDocument::parse_bytes(
            LineConfigDialect::FlatKeyValue,
            too_many_nodes.clone(),
        )
        .expect("excess nodes should fail closed to opaque");
        assert!(!too_many_nodes_document.is_structured());
        assert_eq!(too_many_nodes_document.rows().len(), 1);
        assert_eq!(too_many_nodes_document.output().bytes(), too_many_nodes);

        let mut too_deep = String::new();
        let mut path = String::new();
        for depth in 0..=MAX_LINE_CONFIG_DEPTH {
            if depth > 0 {
                path.push('.');
            }
            path.push('a');
            too_deep.push('[');
            too_deep.push_str(&path);
            too_deep.push_str("]\n");
        }
        let too_deep_document = LineConfigVisualDocument::parse(LineConfigDialect::Toml, &too_deep)
            .expect("excess depth should fail closed to opaque");
        assert!(!too_deep_document.is_structured());
        assert_eq!(too_deep_document.rows().len(), MAX_LINE_CONFIG_DEPTH + 1);
        assert!(
            too_deep_document
                .rows()
                .iter()
                .all(|row| row.depth() <= MAX_LINE_CONFIG_DEPTH)
        );
        assert_eq!(
            too_deep_document.rows().last().map(LineConfigRow::kind),
            Some(LineConfigNodeKind::Opaque)
        );
        assert_eq!(too_deep_document.output().bytes(), too_deep.as_bytes());

        let long_value = "x".repeat(MAX_LINE_CONFIG_ROW_PREVIEW_BYTES * 3);
        let preview_document = LineConfigVisualDocument::parse(
            LineConfigDialect::FlatKeyValue,
            &format!("note={long_value}"),
        )
        .expect("long row should parse");
        let preview_row = &preview_document.rows()[0];
        assert!(preview_row.preview().len() <= MAX_LINE_CONFIG_ROW_PREVIEW_BYTES);
        assert!(preview_row.truncated());

        let mut editable = LineConfigVisualDocument::blank(LineConfigDialect::FlatKeyValue);
        let oversized_value = "x".repeat(MAX_LINE_CONFIG_EDIT_BYTES + 1);
        assert!(
            editable
                .add_entry(None, "key", Some(&oversized_value))
                .is_err()
        );
        assert!(editable.raw_bytes().is_empty());
    }

    #[test]
    fn bom_crlf_no_final_newline_survives_subtree_moves() {
        let original =
            b"\xEF\xBB\xBF; root\r\n[first]\r\na=1\r\n# keep first\r\n\r\n[second]\r\nb=2";
        let expected_moved =
            b"\xEF\xBB\xBF; root\r\n[second]\r\nb=2\r\n\r\n[first]\r\na=1\r\n# keep first";
        let mut document =
            LineConfigVisualDocument::parse_bytes(LineConfigDialect::Ini, original.to_vec())
                .expect("fixture should parse");
        let first = row_id(&document, "first");
        document
            .move_down(first)
            .expect("whole section subtree should move");
        assert_eq!(document.output().bytes(), expected_moved);
        assert!(document.output().bytes().starts_with(&[0xEF, 0xBB, 0xBF]));
        assert!(
            document
                .output()
                .bytes()
                .windows(2)
                .any(|pair| pair == b"\r\n")
        );
        assert!(!document.output().bytes().ends_with(b"\n"));
        assert!(document.row_by_id(first).is_none());
        let roots = document
            .root_rows()
            .into_iter()
            .filter(|row| row.kind() == LineConfigNodeKind::Section)
            .map(|row| row.name().unwrap_or_default().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(roots, ["second", "first"]);
        let moved_first = row_id(&document, "first");
        let first_children = document.children(moved_first).expect("moved children");
        assert!(first_children.iter().any(|row| row.name() == Some("a")));
        assert!(
            first_children
                .iter()
                .any(|row| row.kind() == LineConfigNodeKind::Comment)
        );

        document
            .move_up(moved_first)
            .expect("reverse subtree move should succeed");
        assert_eq!(document.output().bytes(), original);
    }

    #[test]
    fn visual_mutations_cover_root_container_leaf_comment_record_and_table() {
        let mut ini = LineConfigVisualDocument::blank(LineConfigDialect::Ini);
        ini.add_entry(None, "global", Some("1"))
            .expect("root entry");
        ini.add_section("main").expect("section");
        let main = row_id(&ini, "main");
        ini.add_entry(Some(main), "a", Some("1"))
            .expect("first section entry");
        let main = row_id(&ini, "main");
        ini.add_entry(Some(main), "b", Some("2"))
            .expect("second section entry");
        let b = row_id(&ini, "b");
        ini.update_entry(b, "beta", Some("9"))
            .expect("entry update");
        let main = row_id(&ini, "main");
        ini.update_container(main, "primary")
            .expect("container update");
        let a = row_id(&ini, "a");
        ini.move_down(a).expect("leaf move");
        let primary = row_id(&ini, "primary");
        let child_names = ini
            .children(primary)
            .expect("section children")
            .into_iter()
            .filter_map(|row| row.name().map(str::to_owned))
            .collect::<Vec<_>>();
        assert_eq!(child_names, ["beta", "a"]);
        let a = row_id(&ini, "a");
        ini.remove(a).expect("leaf remove");
        let primary = row_id(&ini, "primary");
        ini.add_comment(Some(primary), "retained")
            .expect("comment add");
        let comment = ini
            .rows()
            .into_iter()
            .find(|row| row.kind() == LineConfigNodeKind::Comment)
            .expect("comment row");
        ini.update_comment(comment.id(), "changed")
            .expect("comment update");
        let comment = ini
            .rows()
            .into_iter()
            .find(|row| row.kind() == LineConfigNodeKind::Comment)
            .expect("updated comment row");
        ini.remove(comment.id()).expect("comment remove");
        let primary = row_id(&ini, "primary");
        ini.remove(primary).expect("section subtree remove");
        assert_eq!(ini.root_rows().len(), 1);
        assert_eq!(ini.root_rows()[0].name(), Some("global"));

        let mut hba = LineConfigVisualDocument::parse(
            LineConfigDialect::PgHba,
            "local all all peer\nhost all all 127.0.0.1/32 scram-sha-256",
        )
        .expect("HBA fixture");
        let local = row_id(&hba, "local");
        hba.update_record(local, "local all all scram-sha-256")
            .expect("record update");
        let local = row_id(&hba, "local");
        hba.move_down(local).expect("record move");
        assert_eq!(hba.root_rows()[0].name(), Some("host"));
        let local = row_id(&hba, "local");
        hba.remove(local).expect("record remove");
        assert_eq!(hba.root_rows().len(), 1);

        let mut toml = LineConfigVisualDocument::blank(LineConfigDialect::Toml);
        toml.add_table(None, "server").expect("root table");
        let server = row_id(&toml, "server");
        toml.add_entry(Some(server), "port", Some("4000"))
            .expect("table entry");
        let server = row_id(&toml, "server");
        toml.add_table(Some(server), "tls").expect("nested table");
        let tls = row_id(&toml, "server.tls");
        toml.add_entry(Some(tls), "enabled", Some("true"))
            .expect("nested entry");
        let tls = row_id(&toml, "server.tls");
        toml.update_container(tls, "secure")
            .expect("nested table rename");
        assert!(
            toml.rows()
                .iter()
                .any(|row| row.name() == Some("server.secure"))
        );
    }

    #[test]
    fn postgres_record_continuations_form_atomic_logical_nodes() {
        let source = b"# disabled rule \\\nhost all all 0.0.0.0/0 trust\nhost all all 10.0.0.0/8 scram-sha-256";
        let mut hba =
            LineConfigVisualDocument::parse_bytes(LineConfigDialect::PgHba, source.to_vec())
                .expect("continued HBA source should remain available");
        assert_eq!(hba.output().bytes(), source);
        assert!(hba.is_structured());
        assert_eq!(hba.root_rows().len(), 2);
        assert_eq!(hba.root_rows()[0].kind(), LineConfigNodeKind::Comment);
        assert!(hba.root_rows()[0].editable());
        assert_eq!(hba.root_rows()[1].kind(), LineConfigNodeKind::Record);
        let continued_comment = hba.root_rows()[0].id();
        hba.remove(continued_comment)
            .expect("the complete continued comment is one removable node");
        assert_eq!(
            hba.output().bytes(),
            b"host all all 10.0.0.0/8 scram-sha-256"
        );

        let quoted = b"host all all 0.0.0.0/0 \"quoted\\\ncontinuation\" trust\nhost all all 10.0.0.0/8 scram-sha-256";
        let quoted_hba =
            LineConfigVisualDocument::parse_bytes(LineConfigDialect::PgHba, quoted.to_vec())
                .expect("quoted continuation should remain atomic");
        assert_eq!(quoted_hba.output().bytes(), quoted);
        assert_eq!(quoted_hba.root_rows().len(), 2);
        assert_eq!(quoted_hba.root_rows()[0].kind(), LineConfigNodeKind::Record);
        assert!(quoted_hba.root_rows()[0].editable());

        let ident = b"# disabled map \\\nmap_one system_user database_user\nmap_two other_user other_database_user";
        let ident_document =
            LineConfigVisualDocument::parse_bytes(LineConfigDialect::PgIdent, ident.to_vec())
                .expect("continued ident source should remain atomic");
        assert_eq!(ident_document.output().bytes(), ident);
        assert_eq!(ident_document.root_rows().len(), 2);
        assert_eq!(
            ident_document.root_rows()[0].kind(),
            LineConfigNodeKind::Comment
        );

        let split_keyword = b"ho\\\r\nst all all 127.0.0.1/32 trust\r\n";
        let split_document =
            LineConfigVisualDocument::parse_bytes(LineConfigDialect::PgHba, split_keyword.to_vec())
                .expect("CRLF continuation should be removed before tokenization");
        assert!(split_document.is_structured());
        assert_eq!(split_document.output().bytes(), split_keyword);
        assert_eq!(
            split_document.root_rows()[0].kind(),
            LineConfigNodeKind::Record
        );

        let not_continued = b"# NOT continued \\   \nhost all all 0.0.0.0/0 trust\nhost all all 10.0.0.0/8 scram-sha-256";
        let strict =
            LineConfigVisualDocument::parse_bytes(LineConfigDialect::PgHba, not_continued.to_vec())
                .expect("backslash followed by spaces is not a continuation");
        assert!(strict.is_structured());
        assert_eq!(strict.root_rows().len(), 3);
        assert_eq!(strict.root_rows()[0].kind(), LineConfigNodeKind::Comment);
        assert_eq!(strict.root_rows()[1].name(), Some("host"));
        assert_eq!(strict.output().bytes(), not_continued);
    }

    #[test]
    fn unsupported_toml_table_like_nodes_are_root_opaque_barriers() {
        let source = b"[a]\nx=1\n[[b]]\ny=2\n";
        let mut document =
            LineConfigVisualDocument::parse_bytes(LineConfigDialect::Toml, source.to_vec())
                .expect("unsupported array table should remain lossless");
        assert_eq!(document.output().bytes(), source);
        assert!(!document.is_structured());
        let roots = document.root_rows();
        assert_eq!(roots.len(), 2);
        assert_eq!(roots[0].name(), Some("a"));
        assert_eq!(roots[1].kind(), LineConfigNodeKind::Opaque);
        let a = roots[0].id();
        let barrier = roots[1].id();
        assert_eq!(document.children(a).expect("a children").len(), 1);
        assert!(!document.rows().iter().any(|row| row.name() == Some("y")));
        assert!(document.remove(barrier).is_err());
        assert!(document.move_down(a).is_err());
        assert_eq!(document.output().bytes(), source);

        document
            .remove(a)
            .expect("known table subtree may be removed");
        assert_eq!(document.output().bytes(), b"[[b]]\ny=2\n");
        assert_eq!(document.root_rows().len(), 1);
        assert_eq!(document.root_rows()[0].kind(), LineConfigNodeKind::Opaque);

        let followed_by_known =
            LineConfigVisualDocument::parse(LineConfigDialect::Toml, "[[b]]\ny=2\n[c]\nz=3")
                .expect("known table should end the opaque array-table region");
        assert_eq!(followed_by_known.root_rows().len(), 2);
        assert_eq!(
            followed_by_known.root_rows()[0].kind(),
            LineConfigNodeKind::Opaque
        );
        assert_eq!(followed_by_known.root_rows()[1].name(), Some("c"));
        let c = followed_by_known.root_rows()[1].id();
        assert_eq!(
            followed_by_known.children(c).expect("known table children")[0].name(),
            Some("z")
        );

        let header_inside_string = br#"[[array]]
text = """opening
[not_a_table]
evil = 1
"""
[real]
ok=1"#;
        let lexical_barrier = LineConfigVisualDocument::parse_bytes(
            LineConfigDialect::Toml,
            header_inside_string.to_vec(),
        )
        .expect("header-shaped multiline content must stay opaque");
        assert_eq!(lexical_barrier.output().bytes(), header_inside_string);
        assert_eq!(lexical_barrier.root_rows().len(), 2);
        assert_eq!(
            lexical_barrier.root_rows()[0].kind(),
            LineConfigNodeKind::Opaque
        );
        assert_eq!(lexical_barrier.root_rows()[1].name(), Some("real"));
        assert!(
            !lexical_barrier
                .rows()
                .iter()
                .any(|row| matches!(row.name(), Some("not_a_table" | "evil")))
        );

        let nested_source = b"[a]\nx=1\n[a.b]\ny=2";
        let mut nested =
            LineConfigVisualDocument::parse_bytes(LineConfigDialect::Toml, nested_source.to_vec())
                .expect("nested table fixture");
        let parent = row_id(&nested, "a");
        assert!(nested.update_container(parent, "renamed").is_err());
        assert_eq!(nested.output().bytes(), nested_source);
        assert!(nested.row_by_id(parent).is_some());
    }

    #[test]
    fn toml_multiline_strings_ignore_escaped_triple_quote_candidates() {
        let source = br#"[a]
x = """opening \"""
evil = 1
"""
[b]
y=2"#;
        let mut document =
            LineConfigVisualDocument::parse_bytes(LineConfigDialect::Toml, source.to_vec())
                .expect("multiline TOML should remain lossless");
        assert_eq!(document.output().bytes(), source);
        assert!(!document.is_structured());
        assert!(!document.rows().iter().any(|row| row.name() == Some("evil")));
        let a = row_id(&document, "a");
        let a_children = document.children(a).expect("a children");
        assert_eq!(a_children.len(), 1);
        assert_eq!(a_children[0].kind(), LineConfigNodeKind::Opaque);
        assert!(!a_children[0].editable());
        let opaque = a_children[0].id();
        assert!(document.remove(opaque).is_err());
        let b = row_id(&document, "b");
        assert_eq!(
            document.children(b).expect("b children")[0].name(),
            Some("y")
        );
    }

    #[test]
    fn carrier_keys_camel_case_and_record_markers_are_redacted() {
        let postgres_source = "primary_conninfo = 'host=db password=PrimaryDontLeak'";
        let postgres =
            LineConfigVisualDocument::parse(LineConfigDialect::PostgresConf, postgres_source)
                .expect("PostgreSQL carrier fixture");
        assert!(postgres.contains_sensitive_values());
        let postgres_rows = postgres.rows();
        let postgres_row = &postgres_rows[0];
        assert!(postgres_row.sensitive());
        assert_eq!(postgres_row.value(), None);
        assert_eq!(postgres_row.preview(), "[sensitive value redacted]");

        let hba_source = "host all all 0.0.0.0/0 ldap ldapbinddn=admin ldapbindpasswd=LdapDontLeak";
        let hba = LineConfigVisualDocument::parse(LineConfigDialect::PgHba, hba_source)
            .expect("HBA LDAP fixture");
        assert!(hba.contains_sensitive_values());
        let hba_rows = hba.rows();
        let hba_row = &hba_rows[0];
        assert!(hba_row.sensitive());
        assert_eq!(hba_row.value(), None);
        assert_eq!(hba_row.preview(), "[sensitive value redacted]");

        let java_source = "metaDbPasswd=MetaDontLeak\ndnPasswordKey=DnDontLeak\nnormal=value";
        let java = LineConfigVisualDocument::parse(LineConfigDialect::JavaProperties, java_source)
            .expect("Java secret fixture");
        assert!(java.contains_sensitive_values());
        let java_rows = java.rows();
        for key in ["metaDbPasswd", "dnPasswordKey"] {
            let row = java_rows
                .iter()
                .find(|row| row.name() == Some(key))
                .expect("secret Java property");
            assert!(row.sensitive());
            assert_eq!(row.value(), None);
            assert_eq!(row.preview(), "[sensitive value redacted]");
        }
        assert_eq!(
            java_rows
                .iter()
                .find(|row| row.name() == Some("normal"))
                .and_then(LineConfigRow::value),
            Some("value")
        );

        for (debug, secret) in [
            (format!("{postgres:?}{postgres_rows:?}"), "PrimaryDontLeak"),
            (format!("{hba:?}{hba_rows:?}"), "LdapDontLeak"),
            (format!("{java:?}{java_rows:?}"), "MetaDontLeak"),
            (format!("{java:?}{java_rows:?}"), "DnDontLeak"),
        ] {
            assert!(!debug.contains(secret));
        }
    }

    #[test]
    fn postgres_whitespace_entries_and_explicit_includes_are_supported() {
        let source = b"port 5432\ninclude 'x.conf'\nlisten_addresses = '*'";
        let postgres =
            LineConfigVisualDocument::parse_bytes(LineConfigDialect::PostgresConf, source.to_vec())
                .expect("PostgreSQL whitespace form should parse");
        assert!(postgres.is_structured());
        assert_eq!(postgres.output().bytes(), source);
        assert_eq!(postgres.root_rows()[0].name(), Some("port"));
        assert_eq!(postgres.root_rows()[0].value(), Some("5432"));
        assert_eq!(postgres.root_rows()[1].kind(), LineConfigNodeKind::Include);
        assert_eq!(postgres.root_rows()[1].value(), Some("'x.conf'"));

        let mut updated = postgres.clone();
        let port = row_id(&updated, "port");
        updated
            .update_entry(port, "port", Some("5433"))
            .expect("whitespace-style entry update");
        let include = row_id(&updated, "include");
        updated
            .update_entry(include, "include", Some("'y.conf'"))
            .expect("whitespace-style include update");
        assert_eq!(
            updated.output().bytes(),
            b"port 5433\ninclude 'y.conf'\nlisten_addresses = '*'"
        );

        let mut generated = LineConfigVisualDocument::blank(LineConfigDialect::PostgresConf);
        generated
            .add_include(None, "include", "'local.conf'")
            .expect("explicit PostgreSQL include");
        assert_eq!(generated.output().bytes(), b"include = 'local.conf'");
        assert_eq!(generated.root_rows()[0].kind(), LineConfigNodeKind::Include);
        assert!(
            generated
                .add_include(None, "include", "'bad.conf'\ninjected=1")
                .is_err()
        );

        let mut mysql = LineConfigVisualDocument::blank(LineConfigDialect::MySqlOption);
        mysql.add_section("mysqld").expect("MySQL section");
        let mysqld = row_id(&mysql, "mysqld");
        mysql
            .add_include(Some(mysqld), "!includedir", "/etc/mysql/conf.d")
            .expect("explicit MySQL include");
        assert_eq!(
            mysql.output().bytes(),
            b"[mysqld]\n!includedir /etc/mysql/conf.d\n"
        );
        assert_eq!(
            mysql
                .rows()
                .iter()
                .filter(|row| row.kind() == LineConfigNodeKind::Include)
                .count(),
            1
        );
    }

    #[test]
    fn pg_hba_record_shapes_fail_closed_and_preserve_quoted_fields() {
        let cases = [
            ("host trust", LineConfigNodeKind::Opaque),
            ("local all trust", LineConfigNodeKind::Opaque),
            (
                "unknown all all 127.0.0.1/32 trust",
                LineConfigNodeKind::Opaque,
            ),
            (
                "Host all all 127.0.0.1/32 trust",
                LineConfigNodeKind::Opaque,
            ),
            ("host all all 127.0.0.1 trust", LineConfigNodeKind::Opaque),
            (
                "host all all 127.0.0.1 not-a-mask trust",
                LineConfigNodeKind::Opaque,
            ),
            (
                "host all all 127.0.0.1 ffff:ffff:ffff:ffff:: trust",
                LineConfigNodeKind::Opaque,
            ),
            ("host all all ::1 trust", LineConfigNodeKind::Opaque),
            (
                "local \"db name\" \"user name\" scram-sha-256",
                LineConfigNodeKind::Record,
            ),
            (
                "local \"db \"\"quoted\"\"\" all peer",
                LineConfigNodeKind::Record,
            ),
            (
                "\"host\" all all 127.0.0.1/32 trust",
                LineConfigNodeKind::Record,
            ),
            (
                "hostssl all all 127.0.0.1/32 scram-sha-256",
                LineConfigNodeKind::Record,
            ),
            (
                "hostnossl all all 127.0.0.1/32 reject",
                LineConfigNodeKind::Record,
            ),
            (
                "hostgssenc all all 127.0.0.1/32 gss",
                LineConfigNodeKind::Record,
            ),
            (
                "hostnogssenc all all 127.0.0.1/32 scram-sha-256",
                LineConfigNodeKind::Record,
            ),
            (
                "host all all 127.0.0.1 255.255.255.255 trust",
                LineConfigNodeKind::Record,
            ),
            (
                "host all all ::1 ffff:ffff:ffff:ffff:: trust",
                LineConfigNodeKind::Record,
            ),
            (
                "host all all database.example.test trust",
                LineConfigNodeKind::Record,
            ),
            ("host all all all trust", LineConfigNodeKind::Record),
            ("host all all samehost trust", LineConfigNodeKind::Record),
            ("host all all samenet trust", LineConfigNodeKind::Record),
        ];
        for (source, expected_kind) in cases {
            let document = LineConfigVisualDocument::parse(LineConfigDialect::PgHba, source)
                .expect("HBA source should remain byte-preserving");
            assert_eq!(document.output().bytes(), source.as_bytes(), "{source}");
            let row = &document.root_rows()[0];
            assert_eq!(row.kind(), expected_kind, "{source}");
            assert_eq!(row.editable(), expected_kind == LineConfigNodeKind::Record);
        }

        let mut generated = LineConfigVisualDocument::blank(LineConfigDialect::PgHba);
        for malformed in [
            "host trust",
            "local all trust",
            "unknown all all 127.0.0.1/32 trust",
            "host all all 127.0.0.1 trust",
            "host all all 127.0.0.1 not-a-mask trust",
            "include one.conf trailing",
        ] {
            assert!(
                generated.add_record(None, malformed).is_err(),
                "{malformed}"
            );
        }
        generated
            .add_record(None, "host all all 127.0.0.1/32 scram-sha-256")
            .expect("valid host record");
        generated
            .add_record(None, "local \"db name\" \"user name\" peer")
            .expect("valid quoted local record");
        generated
            .add_record(None, "host all all 127.0.0.1 255.255.255.255 scram-sha-256")
            .expect("valid address-and-netmask record");
    }

    #[test]
    fn postgres_auth_lexer_uses_only_double_quotes_and_never_backslash_escapes_hash() {
        let source = br#""host" "db ""quoted""" user 127.0.0.1/32 trust\#ignored"#;
        let lexed = postgres_record_fields(source, 0..source.len()).expect("valid auth record");
        assert_eq!(lexed.fields.len(), 5);
        assert_eq!(lexed.fields[0].single_token(), Some(b"host".as_slice()));
        assert_eq!(
            lexed.fields[1].single_token(),
            Some(b"db \"quoted\"".as_slice())
        );
        assert_eq!(lexed.fields[4].single_token(), Some(b"trust\\".as_slice()));
        assert_eq!(lexed.comment, source.iter().position(|byte| *byte == b'#'));

        let single_quoted = b"include 'local hba.conf'";
        let lexed = postgres_record_fields(single_quoted, 0..single_quoted.len())
            .expect("single quotes are ordinary bytes");
        assert_eq!(lexed.fields.len(), 3);
        assert_eq!(lexed.fields[1].single_token(), Some(b"'local".as_slice()));
        assert_eq!(
            lexed.fields[2].single_token(),
            Some(b"hba.conf'".as_slice())
        );

        let continued = b"ho\\\r\nst";
        let lexed = postgres_record_fields(continued, 0..continued.len())
            .expect("physical continuation should be removed first");
        assert_eq!(lexed.fields[0].single_token(), Some(b"host".as_slice()));

        let unclosed = b"local \"unterminated all peer";
        assert!(postgres_record_fields(unclosed, 0..unclosed.len()).is_none());
    }

    #[test]
    fn postgres_auth_include_detection_is_exact_and_ident_three_fields_are_records() {
        let hba_source = concat!(
            "include \"local hba.conf\"\n",
            "\"include\" \"quoted.conf\"\n",
            "include_if_exists optional.conf # retained\n",
            "include_dir conf.d\n",
            "INCLUDE uppercase.conf\n",
            "include one.conf trailing\n",
            "include_if_exists 'local hba.conf'\n",
            "include \"local \"\"quoted\"\".conf\""
        );
        let hba = LineConfigVisualDocument::parse(LineConfigDialect::PgHba, hba_source)
            .expect("mixed HBA include source");
        assert_eq!(hba.output().bytes(), hba_source.as_bytes());
        let hba_rows = hba.root_rows();
        assert_eq!(hba_rows.len(), 8);
        for index in [0, 1, 2, 3, 7] {
            assert_eq!(
                hba_rows[index].kind(),
                LineConfigNodeKind::Include,
                "{index}"
            );
        }
        for index in [4, 5, 6] {
            assert_eq!(
                hba_rows[index].kind(),
                LineConfigNodeKind::Opaque,
                "{index}"
            );
        }

        let ident_source = concat!(
            "include two-fields.conf\n",
            "include system_user database_user\n",
            "include_if_exists system_user database_user\n",
            "INCLUDE system_user database_user\n",
            "\"include\" \"quoted path.conf\""
        );
        let ident = LineConfigVisualDocument::parse(LineConfigDialect::PgIdent, ident_source)
            .expect("mixed ident include source");
        assert_eq!(ident.output().bytes(), ident_source.as_bytes());
        let ident_rows = ident.root_rows();
        assert_eq!(ident_rows.len(), 5);
        assert_eq!(ident_rows[0].kind(), LineConfigNodeKind::Include);
        assert!(
            ident_rows[1..4]
                .iter()
                .all(|row| row.kind() == LineConfigNodeKind::Record && row.editable())
        );
        assert_eq!(ident_rows[4].kind(), LineConfigNodeKind::Include);
    }

    #[test]
    fn postgres_auth_bom_crlf_stale_ids_and_secret_redaction_regressions() {
        let source = b"\xEF\xBB\xBFlocal all all peer\r\nhost all all 127.0.0.1/32 trust\r\nho\\\r\nst all all ::1 ffff:ffff:ffff:ffff:: trust\r\n";
        let document =
            LineConfigVisualDocument::parse_bytes(LineConfigDialect::PgHba, source.to_vec())
                .expect("BOM and CRLF source remains visible");
        assert_eq!(document.output().bytes(), source);
        assert!(!document.is_structured());
        let rows = document.root_rows();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].kind(), LineConfigNodeKind::Opaque);
        assert_eq!(rows[1].kind(), LineConfigNodeKind::Record);
        assert_eq!(rows[2].kind(), LineConfigNodeKind::Record);

        let mut editable = LineConfigVisualDocument::parse(
            LineConfigDialect::PgHba,
            "host all all 127.0.0.1 255.255.255.255 trust",
        )
        .expect("editable netmask fixture");
        let stale = editable.root_rows()[0].id();
        editable
            .update_record(stale, "host all all 127.0.0.1/32 trust")
            .expect("valid replacement");
        assert!(editable.row_by_id(stale).is_none());
        assert!(
            editable
                .update_record(stale, "host all all 127.0.0.1/32 reject")
                .is_err()
        );
        let current = editable.root_rows()[0].id();
        let before_invalid_edit = editable.output();
        assert!(
            editable
                .update_record(current, "host all all 127.0.0.1 trust")
                .is_err()
        );
        assert_eq!(editable.output(), before_invalid_edit);
        assert!(editable.row_by_id(current).is_some());

        let secrets = "host all all 127.0.0.1/32 ldap ldapbindpasswd=StructuredLexerSecret\nhost all all 127.0.0.1 ldapbindpasswd=OpaqueLexerSecret";
        let secret_document = LineConfigVisualDocument::parse(LineConfigDialect::PgHba, secrets)
            .expect("secret fixture stays visible");
        assert!(secret_document.contains_sensitive_values());
        let secret_rows = secret_document.root_rows();
        assert_eq!(secret_rows[0].kind(), LineConfigNodeKind::Record);
        assert_eq!(secret_rows[1].kind(), LineConfigNodeKind::Opaque);
        assert!(secret_rows.iter().all(LineConfigRow::sensitive));
        assert!(secret_rows.iter().all(|row| row.value().is_none()));
        for debug in [
            format!("{secret_document:?}"),
            format!("{secret_rows:?}"),
            format!("{:?}", secret_document.output()),
        ] {
            assert!(!debug.contains("StructuredLexerSecret"));
            assert!(!debug.contains("OpaqueLexerSecret"));
        }
    }

    #[test]
    fn output_uses_create_new_and_read_local_keeps_dialect_and_bytes() {
        let directory = env::temp_dir().join(format!(
            "lovelyres-line-config-{}-{}",
            process::id(),
            next_document_revision()
        ));
        fs::create_dir(&directory).expect("create isolated temporary directory");
        let destination = directory.join("postgresql.conf");
        let source = b"\xEF\xBB\xBFlisten_addresses = '*'\r\nmax_connections = 100";
        let document =
            LineConfigVisualDocument::parse_bytes(LineConfigDialect::PostgresConf, source.to_vec())
                .expect("fixture should parse");
        let output = document.output();
        assert_eq!(output.suggested_file_name(), "postgresql.conf");
        assert_eq!(
            output
                .write_new(&destination)
                .expect("first write should create"),
            destination
        );
        assert!(output.write_new(&destination).is_err());
        assert_eq!(fs::read(&destination).expect("read created file"), source);

        let imported =
            LineConfigVisualDocument::read_local(LineConfigDialect::PostgresConf, &destination)
                .expect("absolute local path should import");
        assert_eq!(imported.dialect(), LineConfigDialect::PostgresConf);
        assert_eq!(imported.output().bytes(), source);

        fs::remove_file(&destination).expect("remove isolated temporary file");
        fs::remove_dir(&directory).expect("remove isolated temporary directory");
    }
}
