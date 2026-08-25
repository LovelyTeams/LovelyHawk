//! Lossless, bounded, read-only visualization for structured configuration.
//!
//! JSON is parsed as an ordered, source-backed concrete syntax tree. YAML and
//! XML intentionally remain one visible opaque node until dedicated parsers
//! can preserve their complete syntax without silently rewriting source.

use std::{
    fmt,
    fs::{File, OpenOptions},
    io::{Read, Write},
    ops::Range,
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{
    CoreError, CoreResult,
    structured_gcware::{GcwareParsedKind, GcwareParsedNode, parse_gcware},
    structured_sequoia_csv::{
        SequoiaCsvExpectedSchema, SequoiaCsvParsedKind, SequoiaCsvParsedNode, parse_sequoia_csv,
    },
    structured_xml::{XmlParsedKind, XmlParsedNode, parse_xml},
    structured_yaml::{YamlParsedKind, YamlParsedNode, parse_yaml},
};
use zeroize::Zeroizing;

pub const MAX_STRUCTURED_CONFIG_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_STRUCTURED_CONFIG_NODES: usize = 65_536;
pub const MAX_STRUCTURED_CONFIG_DEPTH: usize = 128;
pub const MAX_STRUCTURED_CONFIG_TOKENS: usize = 262_144;
pub const MAX_STRUCTURED_CONFIG_ROW_PREVIEW_BYTES: usize = 512;

static NEXT_STRUCTURED_CONFIG_REVISION: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum StructuredConfigDialect {
    Json,
    Yaml,
    Xml,
    Gcware,
    SequoiaQuickDeployClusterCsv,
    SequoiaQuickDeploySqlInstanceCsv,
}

impl StructuredConfigDialect {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Json => "JSON",
            Self::Yaml => "YAML",
            Self::Xml => "XML",
            Self::Gcware => "GBase 8a gcware.conf",
            Self::SequoiaQuickDeployClusterCsv => "SequoiaDB quickDeploy cluster CSV",
            Self::SequoiaQuickDeploySqlInstanceCsv => "SequoiaDB quickDeploy SQL instance CSV",
        }
    }

    pub const fn suggested_file_name(self) -> &'static str {
        match self {
            Self::Json => "config.json",
            Self::Yaml => "config.yaml",
            Self::Xml => "config.xml",
            Self::Gcware => "gcware.conf",
            Self::SequoiaQuickDeployClusterCsv => "sequoiadb.conf",
            // The catalog owns the required mysql.conf, mariadb.conf, or
            // postgresql.conf name; a shared syntax dialect must not guess it.
            Self::SequoiaQuickDeploySqlInstanceCsv => "sql-instance.conf",
        }
    }
}

/// Identifier scoped to one parsed document revision.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StructuredConfigNodeId(u128);

impl StructuredConfigNodeId {
    pub const fn get(self) -> u128 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StructuredConfigNodeKind {
    Document,
    Object,
    Array,
    Member,
    Scalar,
    Comment,
    Opaque,
}

impl StructuredConfigNodeKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Document => "document",
            Self::Object => "object",
            Self::Array => "array",
            Self::Member => "member",
            Self::Scalar => "scalar",
            Self::Comment => "comment",
            Self::Opaque => "opaque source",
        }
    }

    const fn can_have_children(self) -> bool {
        matches!(
            self,
            Self::Document | Self::Object | Self::Array | Self::Member
        )
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct StructuredConfigRow {
    id: StructuredConfigNodeId,
    parent: Option<StructuredConfigNodeId>,
    depth: usize,
    kind: StructuredConfigNodeKind,
    name: Option<Zeroizing<String>>,
    value: Option<Zeroizing<String>>,
    preview: Zeroizing<String>,
    child_count: usize,
    truncated: bool,
    sensitive: bool,
}

impl fmt::Debug for StructuredConfigRow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StructuredConfigRow")
            .field("id", &self.id)
            .field("parent", &self.parent)
            .field("depth", &self.depth)
            .field("kind", &self.kind)
            .field("name_present", &self.name.is_some())
            .field("value_present", &self.value.is_some())
            .field("preview_bytes", &self.preview.len())
            .field("child_count", &self.child_count)
            .field("truncated", &self.truncated)
            .field("sensitive", &self.sensitive)
            .finish()
    }
}

impl StructuredConfigRow {
    pub const fn id(&self) -> StructuredConfigNodeId {
        self.id
    }

    pub const fn parent(&self) -> Option<StructuredConfigNodeId> {
        self.parent
    }

    pub const fn depth(&self) -> usize {
        self.depth
    }

    pub const fn kind(&self) -> StructuredConfigNodeKind {
        self.kind
    }

    /// Decoded JSON object key. Opaque and non-member rows have no name.
    pub fn name(&self) -> Option<&str> {
        self.name.as_ref().map(|value| value.as_str())
    }

    /// Source-exact JSON scalar text. Sensitive values are never returned.
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

    pub const fn sensitive(&self) -> bool {
        self.sensitive
    }

    /// Structured artifacts are read-only until a product/version schema grants
    /// mutation through a separate catalog-authorized API.
    pub const fn editable(&self) -> bool {
        false
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct StructuredConfigOutput {
    dialect: StructuredConfigDialect,
    bytes: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for StructuredConfigOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StructuredConfigOutput")
            .field("dialect", &self.dialect)
            .field("bytes", &self.bytes.len())
            .field("utf8", &std::str::from_utf8(&self.bytes).is_ok())
            .finish()
    }
}

impl StructuredConfigOutput {
    pub const fn dialect(&self) -> StructuredConfigDialect {
        self.dialect
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn text(&self) -> CoreResult<&str> {
        std::str::from_utf8(&self.bytes).map_err(|_| {
            CoreError::validation(
                "structured configuration",
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

    /// Writes a new local file without replacing an existing path.
    pub fn write_new(&self, destination: &Path) -> CoreResult<PathBuf> {
        validate_destination(destination)?;
        validate_size(self.bytes.len())?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(destination)
            .map_err(|source| {
                CoreError::io("create structured configuration", destination, source)
            })?;
        file.write_all(&self.bytes).map_err(|source| {
            CoreError::io("write structured configuration", destination, source)
        })?;
        file.flush().map_err(|source| {
            CoreError::io("flush structured configuration", destination, source)
        })?;
        file.sync_all().map_err(|source| {
            CoreError::io("sync structured configuration", destination, source)
        })?;
        Ok(destination.to_path_buf())
    }
}

#[derive(Clone)]
pub struct StructuredConfigVisualDocument {
    dialect: StructuredConfigDialect,
    source: Zeroizing<Vec<u8>>,
    nodes: Vec<NodeRecord>,
    structured: bool,
    contains_sensitive_values: bool,
}

impl fmt::Debug for StructuredConfigVisualDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StructuredConfigVisualDocument")
            .field("dialect", &self.dialect)
            .field("bytes", &self.source.len())
            .field("nodes", &self.nodes.len())
            .field("structured", &self.structured)
            .field("contains_sensitive_values", &self.contains_sensitive_values)
            .finish()
    }
}

#[derive(Clone, Debug)]
struct NodeRecord {
    id: StructuredConfigNodeId,
    parent: Option<StructuredConfigNodeId>,
    depth: usize,
    kind: StructuredConfigNodeKind,
    span: Range<usize>,
    name_span: Option<Range<usize>>,
    child_count: usize,
    sensitive: bool,
}

#[derive(Debug)]
struct ParsedNode {
    kind: StructuredConfigNodeKind,
    span: Range<usize>,
    name_span: Option<Range<usize>>,
    sensitive: bool,
    children: Vec<ParsedNode>,
}

impl StructuredConfigVisualDocument {
    pub fn parse(dialect: StructuredConfigDialect, text: &str) -> CoreResult<Self> {
        Self::parse_bytes(dialect, text.as_bytes().to_vec())
    }

    pub fn parse_bytes(dialect: StructuredConfigDialect, source: Vec<u8>) -> CoreResult<Self> {
        let mut source = Zeroizing::new(source);
        validate_size(source.len())?;
        if std::str::from_utf8(&source).is_err() {
            return Self::opaque(dialect, std::mem::take(&mut *source));
        }
        match dialect {
            StructuredConfigDialect::Json => match JsonParser::new(&source).parse() {
                Ok(root) => Self::from_json(std::mem::take(&mut *source), root),
                Err(()) => Self::opaque(dialect, std::mem::take(&mut *source)),
            },
            StructuredConfigDialect::Yaml => match parse_yaml(&source) {
                Ok(root) => Self::from_yaml(std::mem::take(&mut *source), root),
                Err(()) => Self::opaque(dialect, std::mem::take(&mut *source)),
            },
            StructuredConfigDialect::Xml => match parse_xml(&source) {
                Ok(root) => Self::from_xml(std::mem::take(&mut *source), root),
                Err(()) => Self::opaque(dialect, std::mem::take(&mut *source)),
            },
            StructuredConfigDialect::Gcware => match parse_gcware(&source) {
                Ok(root) => Self::from_gcware(std::mem::take(&mut *source), root),
                Err(()) => Self::opaque(dialect, std::mem::take(&mut *source)),
            },
            StructuredConfigDialect::SequoiaQuickDeployClusterCsv => {
                match parse_sequoia_csv(&source, SequoiaCsvExpectedSchema::Cluster) {
                    Ok(root) => Self::from_sequoia_csv(dialect, std::mem::take(&mut *source), root),
                    Err(()) => Self::opaque(dialect, std::mem::take(&mut *source)),
                }
            }
            StructuredConfigDialect::SequoiaQuickDeploySqlInstanceCsv => {
                match parse_sequoia_csv(&source, SequoiaCsvExpectedSchema::SqlInstance) {
                    Ok(root) => Self::from_sequoia_csv(dialect, std::mem::take(&mut *source), root),
                    Err(()) => Self::opaque(dialect, std::mem::take(&mut *source)),
                }
            }
        }
    }

    pub fn read_local(dialect: StructuredConfigDialect, path: &Path) -> CoreResult<Self> {
        validate_import_path(path)?;
        let file = File::open(path)
            .map_err(|source| CoreError::io("open local structured configuration", path, source))?;
        let metadata = file.metadata().map_err(|source| {
            CoreError::io("inspect local structured configuration", path, source)
        })?;
        let length = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
        validate_size(length)?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(length));
        file.take((MAX_STRUCTURED_CONFIG_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|source| CoreError::io("read local structured configuration", path, source))?;
        validate_size(bytes.len())?;
        Self::parse_bytes(dialect, std::mem::take(&mut *bytes))
    }

    pub const fn dialect(&self) -> StructuredConfigDialect {
        self.dialect
    }

    pub const fn is_structured(&self) -> bool {
        self.structured
    }

    pub const fn contains_sensitive_values(&self) -> bool {
        self.contains_sensitive_values
    }

    /// Ordinary clipboard text is allowed only for a fully structured document
    /// whose parsed tree contains no sensitive value. Source bytes remain
    /// available to the separate explicit file-save boundary.
    pub const fn can_copy_text(&self) -> bool {
        self.structured && !self.contains_sensitive_values
    }

    pub fn raw_bytes(&self) -> &[u8] {
        &self.source
    }

    pub fn output(&self) -> StructuredConfigOutput {
        StructuredConfigOutput {
            dialect: self.dialect,
            bytes: Zeroizing::new(self.source.to_vec()),
        }
    }

    pub fn rows(&self) -> Vec<StructuredConfigRow> {
        self.nodes.iter().map(|node| self.row(node)).collect()
    }

    pub fn root_rows(&self) -> Vec<StructuredConfigRow> {
        self.nodes
            .iter()
            .filter(|node| node.parent.is_none())
            .map(|node| self.row(node))
            .collect()
    }

    pub fn children(&self, parent: StructuredConfigNodeId) -> CoreResult<Vec<StructuredConfigRow>> {
        let selected = self.require_node(parent)?;
        if !selected.kind.can_have_children() {
            return Err(CoreError::validation(
                "structured configuration selection",
                "selected row cannot contain children",
            ));
        }
        Ok(self
            .nodes
            .iter()
            .filter(|node| node.parent == Some(parent))
            .map(|node| self.row(node))
            .collect())
    }

    pub fn row_by_id(&self, id: StructuredConfigNodeId) -> Option<StructuredConfigRow> {
        self.nodes
            .iter()
            .find(|node| node.id == id)
            .map(|node| self.row(node))
    }

    /// Replaces the complete source and issues a fresh revision of every row.
    pub fn replace_raw(&mut self, source: Vec<u8>) -> CoreResult<()> {
        let replacement = Self::parse_bytes(self.dialect, source)?;
        *self = replacement;
        Ok(())
    }

    fn from_json(source: Vec<u8>, value: ParsedNode) -> CoreResult<Self> {
        let root = ParsedNode {
            kind: StructuredConfigNodeKind::Document,
            span: 0..source.len(),
            name_span: None,
            sensitive: false,
            children: vec![value],
        };
        Self::from_parsed(StructuredConfigDialect::Json, source, root)
    }

    fn from_xml(source: Vec<u8>, root: XmlParsedNode) -> CoreResult<Self> {
        match parsed_xml_node(&source, root) {
            Ok(root) => Self::from_parsed(StructuredConfigDialect::Xml, source, root),
            Err(()) => Self::opaque(StructuredConfigDialect::Xml, source),
        }
    }

    fn from_yaml(source: Vec<u8>, root: YamlParsedNode) -> CoreResult<Self> {
        if root.kind == YamlParsedKind::Document
            && root.children.len() == 1
            && root.children[0].kind == YamlParsedKind::Opaque
            && root.children[0].span == (0..source.len())
        {
            return Self::opaque(StructuredConfigDialect::Yaml, source);
        }
        match parsed_yaml_node(&source, root) {
            Ok(root) => Self::from_parsed(StructuredConfigDialect::Yaml, source, root),
            Err(()) => Self::opaque(StructuredConfigDialect::Yaml, source),
        }
    }

    fn from_gcware(source: Vec<u8>, root: GcwareParsedNode) -> CoreResult<Self> {
        if root.kind == GcwareParsedKind::Document
            && root.children.len() == 1
            && root.children[0].kind == GcwareParsedKind::Opaque
            && root.children[0].span == (0..source.len())
        {
            return Self::opaque(StructuredConfigDialect::Gcware, source);
        }
        match parsed_gcware_node(&source, root) {
            Ok(root) => Self::from_parsed(StructuredConfigDialect::Gcware, source, root),
            Err(()) => Self::opaque(StructuredConfigDialect::Gcware, source),
        }
    }

    fn from_sequoia_csv(
        dialect: StructuredConfigDialect,
        source: Vec<u8>,
        root: SequoiaCsvParsedNode,
    ) -> CoreResult<Self> {
        if root.kind == SequoiaCsvParsedKind::Document
            && root.children.len() == 1
            && root.children[0].kind == SequoiaCsvParsedKind::Opaque
            && root.children[0].span == (0..source.len())
        {
            return Self::opaque(dialect, source);
        }
        match parsed_sequoia_csv_node(&source, root) {
            Ok(root) => Self::from_parsed(dialect, source, root),
            Err(()) => Self::opaque(dialect, source),
        }
    }

    fn from_parsed(
        dialect: StructuredConfigDialect,
        source: Vec<u8>,
        root: ParsedNode,
    ) -> CoreResult<Self> {
        let revision = next_document_revision()?;
        let mut ordinal = 1;
        let mut nodes = Vec::new();
        flatten_nodes(&[root], None, 0, false, revision, &mut ordinal, &mut nodes);
        let contains_sensitive_values = nodes.iter().any(|node| node.sensitive);
        Ok(Self {
            dialect,
            source: Zeroizing::new(source),
            nodes,
            structured: true,
            contains_sensitive_values,
        })
    }

    fn opaque(dialect: StructuredConfigDialect, source: Vec<u8>) -> CoreResult<Self> {
        let revision = next_document_revision()?;
        // Opaque bytes have no proven token boundaries. Secret-name scanning is
        // bypassable through escaping and vendor extensions, so every non-empty
        // opaque region is redacted and excluded from the ordinary clipboard flow.
        let sensitive = !source.is_empty();
        let nodes = if source.is_empty() {
            Vec::new()
        } else {
            vec![NodeRecord {
                id: revision_node_id(revision, 1),
                parent: None,
                depth: 0,
                kind: StructuredConfigNodeKind::Opaque,
                span: 0..source.len(),
                name_span: None,
                child_count: 0,
                sensitive,
            }]
        };
        Ok(Self {
            dialect,
            nodes,
            source: Zeroizing::new(source),
            structured: false,
            contains_sensitive_values: sensitive,
        })
    }

    fn require_node(&self, id: StructuredConfigNodeId) -> CoreResult<&NodeRecord> {
        self.nodes.iter().find(|node| node.id == id).ok_or_else(|| {
            CoreError::validation(
                "structured configuration selection",
                "selected row is stale or belongs to another document",
            )
        })
    }

    fn row(&self, node: &NodeRecord) -> StructuredConfigRow {
        let (name, name_truncated) = node
            .name_span
            .as_ref()
            .and_then(|span| self.decode_node_name(span))
            .map_or((None, false), |decoded| {
                let (bounded, truncated) = bounded_preview(decoded.as_bytes());
                (Some(Zeroizing::new(bounded)), truncated)
            });
        let (value, value_truncated) =
            if node.kind == StructuredConfigNodeKind::Scalar && !node.sensitive {
                let (bounded, truncated) = bounded_preview(&self.source[node.span.clone()]);
                (Some(Zeroizing::new(bounded)), truncated)
            } else {
                (None, false)
            };
        let (preview, preview_truncated) =
            self.row_preview(node, name.as_ref().map(|value| value.as_str()));
        StructuredConfigRow {
            id: node.id,
            parent: node.parent,
            depth: node.depth,
            kind: node.kind,
            name,
            value,
            preview: Zeroizing::new(preview),
            child_count: node.child_count,
            truncated: name_truncated || value_truncated || preview_truncated,
            sensitive: node.sensitive,
        }
    }

    fn row_preview(&self, node: &NodeRecord, name: Option<&str>) -> (String, bool) {
        if node.sensitive {
            return ("[sensitive value redacted]".to_owned(), false);
        }
        match node.kind {
            StructuredConfigNodeKind::Document => {
                (format!("{} document", self.dialect.label()), false)
            }
            StructuredConfigNodeKind::Object => {
                (format!("object ({} members)", node.child_count), false)
            }
            StructuredConfigNodeKind::Array => {
                (format!("array ({} items)", node.child_count), false)
            }
            StructuredConfigNodeKind::Member => (name.unwrap_or("member").to_owned(), false),
            StructuredConfigNodeKind::Scalar
            | StructuredConfigNodeKind::Comment
            | StructuredConfigNodeKind::Opaque => bounded_preview(&self.source[node.span.clone()]),
        }
    }

    fn decode_node_name(&self, span: &Range<usize>) -> Option<Zeroizing<String>> {
        let raw = self.source.get(span.clone())?;
        match self.dialect {
            StructuredConfigDialect::Json => decode_json_string(raw).ok().flatten(),
            StructuredConfigDialect::Yaml
            | StructuredConfigDialect::Xml
            | StructuredConfigDialect::Gcware
            | StructuredConfigDialect::SequoiaQuickDeployClusterCsv
            | StructuredConfigDialect::SequoiaQuickDeploySqlInstanceCsv => std::str::from_utf8(raw)
                .ok()
                .map(|value| Zeroizing::new(value.to_owned())),
        }
    }
}

fn parsed_sequoia_csv_node(source: &[u8], node: SequoiaCsvParsedNode) -> Result<ParsedNode, ()> {
    if node.span.start > node.span.end || node.span.end > source.len() {
        return Err(());
    }
    if let Some(name_span) = &node.name_span
        && (name_span.start < node.span.start
            || name_span.start > name_span.end
            || name_span.end > node.span.end)
    {
        return Err(());
    }
    if matches!(
        node.kind,
        SequoiaCsvParsedKind::Field | SequoiaCsvParsedKind::Comment | SequoiaCsvParsedKind::Opaque
    ) && !node.children.is_empty()
    {
        return Err(());
    }
    let mut previous_end = node.span.start;
    for child in &node.children {
        if child.span.start < previous_end || child.span.end > node.span.end {
            return Err(());
        }
        previous_end = child.span.end;
    }

    let kind = match node.kind {
        SequoiaCsvParsedKind::Document => StructuredConfigNodeKind::Document,
        SequoiaCsvParsedKind::Header | SequoiaCsvParsedKind::Record => {
            StructuredConfigNodeKind::Array
        }
        SequoiaCsvParsedKind::Field => StructuredConfigNodeKind::Scalar,
        SequoiaCsvParsedKind::Comment => StructuredConfigNodeKind::Comment,
        SequoiaCsvParsedKind::Opaque => StructuredConfigNodeKind::Opaque,
    };
    let raw = source.get(node.span.clone()).ok_or(())?;
    let text_sensitive = match kind {
        StructuredConfigNodeKind::Scalar => std::str::from_utf8(raw)
            .ok()
            .is_some_and(contains_sensitive_text),
        StructuredConfigNodeKind::Comment => std::str::from_utf8(raw).ok().is_some_and(|text| {
            contains_sensitive_marker_text(text) || contains_sensitive_text(text)
        }),
        StructuredConfigNodeKind::Opaque => true,
        StructuredConfigNodeKind::Document
        | StructuredConfigNodeKind::Object
        | StructuredConfigNodeKind::Array
        | StructuredConfigNodeKind::Member => false,
    };
    let children = node
        .children
        .into_iter()
        .map(|child| parsed_sequoia_csv_node(source, child))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ParsedNode {
        kind,
        span: node.span,
        name_span: node.name_span,
        sensitive: node.sensitive || text_sensitive,
        children,
    })
}

fn parsed_gcware_node(source: &[u8], node: GcwareParsedNode) -> Result<ParsedNode, ()> {
    if node.span.start > node.span.end || node.span.end > source.len() {
        return Err(());
    }
    if let Some(name_span) = &node.name_span
        && (name_span.start < node.span.start
            || name_span.start > name_span.end
            || name_span.end > node.span.end)
    {
        return Err(());
    }
    if node.kind == GcwareParsedKind::Opaque && !node.children.is_empty() {
        return Err(());
    }
    let mut previous_end = node.span.start;
    for child in &node.children {
        if child.span.start < previous_end || child.span.end > node.span.end {
            return Err(());
        }
        previous_end = child.span.end;
    }

    let kind = match node.kind {
        GcwareParsedKind::Document => StructuredConfigNodeKind::Document,
        GcwareParsedKind::Block | GcwareParsedKind::Entry => StructuredConfigNodeKind::Member,
        GcwareParsedKind::Scalar => StructuredConfigNodeKind::Scalar,
        GcwareParsedKind::Opaque => StructuredConfigNodeKind::Opaque,
    };
    let name_sensitive = node
        .name_span
        .as_ref()
        .and_then(|span| source.get(span.clone()))
        .is_some_and(is_sensitive_key);
    let raw = source.get(node.span.clone()).ok_or(())?;
    let text_sensitive = match kind {
        StructuredConfigNodeKind::Scalar => std::str::from_utf8(raw)
            .ok()
            .is_some_and(contains_sensitive_text),
        StructuredConfigNodeKind::Opaque => true,
        StructuredConfigNodeKind::Document
        | StructuredConfigNodeKind::Object
        | StructuredConfigNodeKind::Array
        | StructuredConfigNodeKind::Member
        | StructuredConfigNodeKind::Comment => false,
    };
    let children = node
        .children
        .into_iter()
        .map(|child| parsed_gcware_node(source, child))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ParsedNode {
        kind,
        span: node.span,
        name_span: node.name_span,
        sensitive: node.sensitive || name_sensitive || text_sensitive,
        children,
    })
}

fn parsed_yaml_node(source: &[u8], node: YamlParsedNode) -> Result<ParsedNode, ()> {
    if node.span.start > node.span.end || node.span.end > source.len() {
        return Err(());
    }
    if let Some(name_span) = &node.name_span
        && (name_span.start < node.span.start
            || name_span.start > name_span.end
            || name_span.end > node.span.end)
    {
        return Err(());
    }
    if node.kind == YamlParsedKind::Opaque && !node.children.is_empty() {
        return Err(());
    }
    let mut previous_end = node.span.start;
    for child in &node.children {
        if child.span.start < previous_end || child.span.end > node.span.end {
            return Err(());
        }
        previous_end = child.span.end;
    }

    let kind = match node.kind {
        YamlParsedKind::Document => StructuredConfigNodeKind::Document,
        YamlParsedKind::Mapping => StructuredConfigNodeKind::Object,
        YamlParsedKind::Sequence => StructuredConfigNodeKind::Array,
        YamlParsedKind::Pair => StructuredConfigNodeKind::Member,
        YamlParsedKind::Scalar => StructuredConfigNodeKind::Scalar,
        YamlParsedKind::Comment => StructuredConfigNodeKind::Comment,
        YamlParsedKind::Opaque => StructuredConfigNodeKind::Opaque,
    };
    let name_sensitive = node
        .name_span
        .as_ref()
        .and_then(|span| source.get(span.clone()))
        .is_some_and(is_sensitive_key);
    let raw = source.get(node.span.clone()).ok_or(())?;
    let text_sensitive = match kind {
        StructuredConfigNodeKind::Scalar => {
            let decoded_marker = std::str::from_utf8(raw)
                .ok()
                .is_some_and(contains_sensitive_text);
            // YAML double-quoted escapes can hide an otherwise recognizable
            // carrier. Until the read-only layer has a complete YAML decoder,
            // conceal escaped strings instead of scanning a misleading form.
            decoded_marker
                || (raw.first() == Some(&b'"') && raw.last() == Some(&b'"') && raw.contains(&b'\\'))
        }
        StructuredConfigNodeKind::Comment => std::str::from_utf8(raw)
            .ok()
            .is_none_or(contains_sensitive_marker_text),
        StructuredConfigNodeKind::Opaque => true,
        StructuredConfigNodeKind::Document
        | StructuredConfigNodeKind::Object
        | StructuredConfigNodeKind::Array
        | StructuredConfigNodeKind::Member => false,
    };
    let children = node
        .children
        .into_iter()
        .map(|child| parsed_yaml_node(source, child))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ParsedNode {
        kind,
        span: node.span,
        name_span: node.name_span,
        sensitive: node.sensitive || name_sensitive || text_sensitive,
        children,
    })
}

fn parsed_xml_node(source: &[u8], node: XmlParsedNode) -> Result<ParsedNode, ()> {
    if node.span.start > node.span.end || node.span.end > source.len() {
        return Err(());
    }
    if let Some(name_span) = &node.name_span
        && (name_span.start < node.span.start
            || name_span.start > name_span.end
            || name_span.end > node.span.end)
    {
        return Err(());
    }
    if node.kind == XmlParsedKind::Opaque && !node.children.is_empty() {
        return Err(());
    }
    let mut previous_end = node.span.start;
    for child in &node.children {
        if child.span.start < previous_end || child.span.end > node.span.end {
            return Err(());
        }
        previous_end = child.span.end;
    }

    let kind = match node.kind {
        XmlParsedKind::Document => StructuredConfigNodeKind::Document,
        XmlParsedKind::Element => StructuredConfigNodeKind::Member,
        // Attributes are named leaves. Mapping them to Scalar keeps the exact
        // `name="value"` source visible without inventing a decoded value.
        XmlParsedKind::Attribute | XmlParsedKind::Text => StructuredConfigNodeKind::Scalar,
        XmlParsedKind::Comment => StructuredConfigNodeKind::Comment,
        XmlParsedKind::Opaque => StructuredConfigNodeKind::Opaque,
    };
    let name_sensitive = node
        .name_span
        .as_ref()
        .and_then(|span| source.get(span.clone()))
        .is_some_and(is_sensitive_key);
    let raw = source.get(node.span.clone()).ok_or(())?;
    let text_sensitive = match kind {
        StructuredConfigNodeKind::Scalar => std::str::from_utf8(raw)
            .ok()
            .is_some_and(contains_sensitive_text),
        StructuredConfigNodeKind::Comment => std::str::from_utf8(raw)
            .ok()
            .is_none_or(contains_sensitive_marker_text),
        StructuredConfigNodeKind::Opaque => true,
        StructuredConfigNodeKind::Document
        | StructuredConfigNodeKind::Object
        | StructuredConfigNodeKind::Array
        | StructuredConfigNodeKind::Member => false,
    };
    let children = node
        .children
        .into_iter()
        .map(|child| parsed_xml_node(source, child))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ParsedNode {
        kind,
        span: node.span,
        name_span: node.name_span,
        sensitive: node.sensitive || name_sensitive || text_sensitive,
        children,
    })
}

struct JsonParser<'a> {
    source: &'a [u8],
    cursor: usize,
    nodes: usize,
    tokens: usize,
}

impl<'a> JsonParser<'a> {
    fn new(source: &'a [u8]) -> Self {
        Self {
            source,
            cursor: 0,
            nodes: 1, // The document node is materialized after parsing.
            tokens: 0,
        }
    }

    fn parse(mut self) -> Result<ParsedNode, ()> {
        if self.source.starts_with(b"\xEF\xBB\xBF") {
            self.cursor = 3;
        }
        self.skip_whitespace();
        let value = self.parse_value(1)?;
        self.skip_whitespace();
        (self.cursor == self.source.len())
            .then_some(value)
            .ok_or(())
    }

    fn parse_value(&mut self, depth: usize) -> Result<ParsedNode, ()> {
        if depth > MAX_STRUCTURED_CONFIG_DEPTH {
            return Err(());
        }
        match self.peek().ok_or(())? {
            b'{' => self.parse_object(depth),
            b'[' => self.parse_array(depth),
            b'"' => {
                let span = self.parse_string()?;
                let decoded = decode_json_string(&self.source[span.clone()])?;
                let sensitive = decoded
                    .as_ref()
                    .is_none_or(|value| contains_sensitive_text(value.as_str()));
                self.scalar(span, sensitive)
            }
            b't' => {
                let span = self.parse_literal(b"true")?;
                self.scalar(span, false)
            }
            b'f' => {
                let span = self.parse_literal(b"false")?;
                self.scalar(span, false)
            }
            b'n' => {
                let span = self.parse_literal(b"null")?;
                self.scalar(span, false)
            }
            b'-' | b'0'..=b'9' => {
                let span = self.parse_number()?;
                self.scalar(span, false)
            }
            _ => Err(()),
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<ParsedNode, ()> {
        let start = self.cursor;
        self.consume_punctuation(b'{')?;
        self.skip_whitespace();
        let mut children = Vec::new();
        if self.peek() == Some(b'}') {
            self.consume_punctuation(b'}')?;
        } else {
            loop {
                let key_span = self.parse_string()?;
                let key = decode_json_string(&self.source[key_span.clone()])?;
                let sensitive = key
                    .as_ref()
                    .is_none_or(|value| is_sensitive_key(value.as_bytes()));
                self.skip_whitespace();
                self.consume_punctuation(b':')?;
                self.skip_whitespace();
                let value = self.parse_value(depth + 1)?;
                let end = value.span.end;
                self.bump_node()?;
                children.push(ParsedNode {
                    kind: StructuredConfigNodeKind::Member,
                    span: key_span.start..end,
                    name_span: Some(key_span),
                    sensitive,
                    children: vec![value],
                });
                self.skip_whitespace();
                match self.peek() {
                    Some(b',') => {
                        self.consume_punctuation(b',')?;
                        self.skip_whitespace();
                        if self.peek() == Some(b'}') {
                            return Err(());
                        }
                    }
                    Some(b'}') => {
                        self.consume_punctuation(b'}')?;
                        break;
                    }
                    _ => return Err(()),
                }
            }
        }
        self.bump_node()?;
        Ok(ParsedNode {
            kind: StructuredConfigNodeKind::Object,
            span: start..self.cursor,
            name_span: None,
            sensitive: false,
            children,
        })
    }

    fn parse_array(&mut self, depth: usize) -> Result<ParsedNode, ()> {
        let start = self.cursor;
        self.consume_punctuation(b'[')?;
        self.skip_whitespace();
        let mut children = Vec::new();
        if self.peek() == Some(b']') {
            self.consume_punctuation(b']')?;
        } else {
            loop {
                children.push(self.parse_value(depth + 1)?);
                self.skip_whitespace();
                match self.peek() {
                    Some(b',') => {
                        self.consume_punctuation(b',')?;
                        self.skip_whitespace();
                        if self.peek() == Some(b']') {
                            return Err(());
                        }
                    }
                    Some(b']') => {
                        self.consume_punctuation(b']')?;
                        break;
                    }
                    _ => return Err(()),
                }
            }
        }
        self.bump_node()?;
        Ok(ParsedNode {
            kind: StructuredConfigNodeKind::Array,
            span: start..self.cursor,
            name_span: None,
            sensitive: false,
            children,
        })
    }

    fn scalar(&mut self, span: Range<usize>, sensitive: bool) -> Result<ParsedNode, ()> {
        self.bump_node()?;
        Ok(ParsedNode {
            kind: StructuredConfigNodeKind::Scalar,
            span,
            name_span: None,
            sensitive,
            children: Vec::new(),
        })
    }

    fn parse_string(&mut self) -> Result<Range<usize>, ()> {
        let start = self.cursor;
        if self.peek() != Some(b'"') {
            return Err(());
        }
        self.cursor += 1;
        while let Some(byte) = self.peek() {
            match byte {
                b'"' => {
                    self.cursor += 1;
                    self.bump_token()?;
                    return Ok(start..self.cursor);
                }
                b'\\' => {
                    self.cursor += 1;
                    match self.peek().ok_or(())? {
                        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {
                            self.cursor += 1;
                        }
                        b'u' => {
                            self.cursor += 1;
                            self.read_hex_quad()?;
                        }
                        _ => return Err(()),
                    }
                }
                0x00..=0x1F => return Err(()),
                _ => self.cursor += 1,
            }
        }
        Err(())
    }

    fn read_hex_quad(&mut self) -> Result<u16, ()> {
        let bytes = self.source.get(self.cursor..self.cursor + 4).ok_or(())?;
        let mut value = 0u16;
        for byte in bytes {
            value = value.checked_mul(16).ok_or(())? + hex_value(*byte).ok_or(())? as u16;
        }
        self.cursor += 4;
        Ok(value)
    }

    fn parse_literal(&mut self, literal: &[u8]) -> Result<Range<usize>, ()> {
        let start = self.cursor;
        if self.source.get(start..start + literal.len()) != Some(literal) {
            return Err(());
        }
        self.cursor += literal.len();
        self.bump_token()?;
        Ok(start..self.cursor)
    }

    fn parse_number(&mut self) -> Result<Range<usize>, ()> {
        let start = self.cursor;
        if self.peek() == Some(b'-') {
            self.cursor += 1;
        }
        match self.peek() {
            Some(b'0') => self.cursor += 1,
            Some(b'1'..=b'9') => {
                self.cursor += 1;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.cursor += 1;
                }
            }
            _ => return Err(()),
        }
        if self.peek() == Some(b'.') {
            self.cursor += 1;
            let fraction_start = self.cursor;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.cursor += 1;
            }
            if self.cursor == fraction_start {
                return Err(());
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.cursor += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.cursor += 1;
            }
            let exponent_start = self.cursor;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.cursor += 1;
            }
            if self.cursor == exponent_start {
                return Err(());
            }
        }
        self.bump_token()?;
        Ok(start..self.cursor)
    }

    fn consume_punctuation(&mut self, punctuation: u8) -> Result<(), ()> {
        if self.peek() != Some(punctuation) {
            return Err(());
        }
        self.cursor += 1;
        self.bump_token()
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.cursor += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.source.get(self.cursor).copied()
    }

    fn bump_node(&mut self) -> Result<(), ()> {
        self.nodes = self.nodes.checked_add(1).ok_or(())?;
        (self.nodes <= MAX_STRUCTURED_CONFIG_NODES)
            .then_some(())
            .ok_or(())
    }

    fn bump_token(&mut self) -> Result<(), ()> {
        self.tokens = self.tokens.checked_add(1).ok_or(())?;
        (self.tokens <= MAX_STRUCTURED_CONFIG_TOKENS)
            .then_some(())
            .ok_or(())
    }
}

fn flatten_nodes(
    parsed: &[ParsedNode],
    parent: Option<StructuredConfigNodeId>,
    depth: usize,
    inherited_sensitive: bool,
    revision: u64,
    ordinal: &mut u64,
    output: &mut Vec<NodeRecord>,
) {
    for node in parsed {
        let id = revision_node_id(revision, *ordinal);
        *ordinal = ordinal.saturating_add(1);
        let sensitive = inherited_sensitive || node.sensitive;
        output.push(NodeRecord {
            id,
            parent,
            depth,
            kind: node.kind,
            span: node.span.clone(),
            name_span: node.name_span.clone(),
            child_count: node.children.len(),
            sensitive,
        });
        flatten_nodes(
            &node.children,
            Some(id),
            depth + 1,
            sensitive,
            revision,
            ordinal,
            output,
        );
    }
}

fn decode_json_string(raw: &[u8]) -> Result<Option<Zeroizing<String>>, ()> {
    if raw.len() < 2 || raw.first() != Some(&b'"') || raw.last() != Some(&b'"') {
        return Err(());
    }
    let content = &raw[1..raw.len() - 1];
    let mut output = Zeroizing::new(String::with_capacity(content.len()));
    let mut display_valid = true;
    let mut cursor = 0;
    while cursor < content.len() {
        if content[cursor] != b'\\' {
            let byte = content[cursor];
            let width = match byte {
                0x00..=0x7f => 1,
                0xc2..=0xdf => 2,
                0xe0..=0xef => 3,
                0xf0..=0xf4 => 4,
                _ => return Err(()),
            };
            let end = cursor.checked_add(width).ok_or(())?;
            let encoded = content.get(cursor..end).ok_or(())?;
            let character = std::str::from_utf8(encoded)
                .map_err(|_| ())?
                .chars()
                .next()
                .ok_or(())?;
            output.push(character);
            cursor = end;
            continue;
        }
        cursor += 1;
        let escaped = *content.get(cursor).ok_or(())?;
        cursor += 1;
        match escaped {
            b'"' => output.push('"'),
            b'\\' => output.push('\\'),
            b'/' => output.push('/'),
            b'b' => output.push('\u{0008}'),
            b'f' => output.push('\u{000C}'),
            b'n' => output.push('\n'),
            b'r' => output.push('\r'),
            b't' => output.push('\t'),
            b'u' => {
                let high = decode_hex_quad(content.get(cursor..cursor + 4).ok_or(())?)?;
                cursor += 4;
                if (0xD800..=0xDBFF).contains(&high) {
                    let low = if content.get(cursor..cursor + 2) == Some(b"\\u") {
                        content
                            .get(cursor + 2..cursor + 6)
                            .and_then(|bytes| decode_hex_quad(bytes).ok())
                            .filter(|unit| (0xDC00..=0xDFFF).contains(unit))
                    } else {
                        None
                    };
                    if let Some(low) = low {
                        cursor += 6;
                        let code_point =
                            0x1_0000 + (((high - 0xD800) as u32) << 10) + (low - 0xDC00) as u32;
                        output.push(char::from_u32(code_point).ok_or(())?);
                    } else {
                        display_valid = false;
                    }
                } else if (0xDC00..=0xDFFF).contains(&high) {
                    display_valid = false;
                } else {
                    output.push(char::from_u32(high as u32).ok_or(())?);
                }
            }
            _ => return Err(()),
        }
    }
    Ok(display_valid.then_some(output))
}

fn decode_hex_quad(bytes: &[u8]) -> Result<u16, ()> {
    if bytes.len() != 4 {
        return Err(());
    }
    let mut value = 0u16;
    for byte in bytes {
        value = value.checked_mul(16).ok_or(())? + hex_value(*byte).ok_or(())? as u16;
    }
    Ok(value)
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn is_sensitive_key(key: &[u8]) -> bool {
    let normalized = normalize_identifier(key);
    const EXACT: [&[u8]; 33] = [
        b"password",
        b"passwd",
        b"passphrase",
        b"pwd",
        b"secret",
        b"token",
        b"authkey",
        b"auth_key",
        b"authorization",
        b"cookie",
        b"api_key",
        b"apikey",
        b"access_key",
        b"secret_key",
        b"auth_token",
        b"access_token",
        b"refresh_token",
        b"id_token",
        b"credential",
        b"credentials",
        b"private_key",
        b"privatekey",
        b"ssl_key",
        b"sslkey",
        b"keyfile",
        b"key_file",
        b"connection_string",
        b"connectionstring",
        b"conninfo",
        b"jdbc_url",
        b"jdbcurl",
        b"bindpasswd",
        b"accesskey",
    ];
    const CONTAINED: [&[u8]; 15] = [
        b"password",
        b"passwd",
        b"passphrase",
        b"secret",
        b"token",
        b"authorization",
        b"cookie",
        b"credential",
        b"private_key",
        b"access_key",
        b"secret_key",
        b"connection_string",
        b"conninfo",
        b"jdbc_url",
        b"bindpasswd",
    ];
    EXACT.iter().any(|candidate| normalized == *candidate)
        || CONTAINED
            .iter()
            .any(|marker| normalized.windows(marker.len()).any(|part| part == *marker))
}

pub(crate) fn contains_sensitive_text(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("bearer ")
        || lower.contains("private key")
        || [
            "password",
            "passwd",
            "passphrase",
            "pwd",
            "secret",
            "token",
            "authkey",
            "auth_key",
            "authorization",
            "cookie",
            "api_key",
            "apikey",
            "access_key",
            "accesskey",
            "secret_key",
            "auth_token",
            "access_token",
            "refresh_token",
            "id_token",
            "client_secret",
            "credential",
            "credentials",
            "private_key",
            "privatekey",
            "ssl_key",
            "sslkey",
            "keyfile",
            "key_file",
            "connection_string",
            "connectionstring",
            "conninfo",
            "jdbc_url",
            "jdbcurl",
            "bindpasswd",
        ]
        .iter()
        .any(|key| contains_sensitive_assignment(&lower, key))
        || (lower.contains("://") && lower.contains('@'))
}

fn contains_sensitive_assignment(value: &str, key: &str) -> bool {
    value.match_indices(key).any(|(start, _)| {
        let before = value.as_bytes()[..start].last().copied();
        if before.is_some_and(|byte| byte.is_ascii_alphanumeric() || byte == b'_') {
            return false;
        }
        let mut suffix = value[start + key.len()..].bytes();
        let delimiter = suffix.find(|byte| !matches!(byte, b' ' | b'\t'));
        matches!(delimiter, Some(b'=' | b':'))
    })
}

pub(crate) fn contains_sensitive_marker_text(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "password",
        "passwd",
        "passphrase",
        "private key",
        "private_key",
        "privatekey",
        "secret",
        "token",
        "cookie",
        "api key",
        "api_key",
        "apikey",
        "credential",
        "authorization",
        "connection string",
        "connection_string",
        "connectionstring",
        "conninfo",
        "jdbc url",
        "jdbc_url",
        "jdbcurl",
        "access key",
        "access_key",
        "accesskey",
        "secret key",
        "secret_key",
        "client secret",
        "client_secret",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
        || contains_authkey_marker(value.as_bytes())
}

fn contains_authkey_marker(value: &[u8]) -> bool {
    [b"authkey".as_slice(), b"auth_key".as_slice()]
        .iter()
        .any(|marker| {
            value
                .windows(marker.len())
                .enumerate()
                .any(|(start, window)| {
                    window.eq_ignore_ascii_case(marker)
                        && (start == 0 || !is_identifier_byte(value[start - 1]))
                        && value
                            .get(start + marker.len())
                            .is_none_or(|byte| !is_identifier_byte(*byte))
                })
        })
}

const fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn normalize_identifier(value: &[u8]) -> Vec<u8> {
    let mut normalized = Vec::with_capacity(value.len());
    let mut separator = false;
    let mut previous_was_lowercase_or_digit = false;
    for byte in value {
        if byte.is_ascii_alphanumeric() {
            let camel_boundary = byte.is_ascii_uppercase() && previous_was_lowercase_or_digit;
            if (separator || camel_boundary)
                && !normalized.is_empty()
                && normalized.last() != Some(&b'_')
            {
                normalized.push(b'_');
            }
            normalized.push(byte.to_ascii_lowercase());
            separator = false;
            previous_was_lowercase_or_digit = byte.is_ascii_lowercase() || byte.is_ascii_digit();
        } else if matches!(*byte, b'_' | b'-' | b'.' | b' ' | b'\t') {
            separator = true;
            previous_was_lowercase_or_digit = false;
        } else {
            separator = false;
            normalized.push(*byte);
            previous_was_lowercase_or_digit = false;
        }
    }
    normalized
}

fn bounded_preview(source: &[u8]) -> (String, bool) {
    let truncated = source.len() > MAX_STRUCTURED_CONFIG_ROW_PREVIEW_BYTES;
    let end = source.len().min(MAX_STRUCTURED_CONFIG_ROW_PREVIEW_BYTES);
    let mut preview = String::from_utf8_lossy(&source[..end]).into_owned();
    while preview.len() > MAX_STRUCTURED_CONFIG_ROW_PREVIEW_BYTES {
        let mut truncate_at = MAX_STRUCTURED_CONFIG_ROW_PREVIEW_BYTES;
        while !preview.is_char_boundary(truncate_at) {
            truncate_at -= 1;
        }
        preview.truncate(truncate_at);
    }
    (preview, truncated)
}

fn next_document_revision() -> CoreResult<u64> {
    NEXT_STRUCTURED_CONFIG_REVISION
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |revision| {
            revision.checked_add(1)
        })
        .map_err(|_| {
            CoreError::validation(
                "structured configuration revision",
                "revision identifier space is exhausted; restart before parsing another document",
            )
        })
}

const fn revision_node_id(revision: u64, ordinal: u64) -> StructuredConfigNodeId {
    StructuredConfigNodeId(((revision as u128) << 64) | ordinal as u128)
}

fn validate_size(bytes: usize) -> CoreResult<()> {
    if bytes > MAX_STRUCTURED_CONFIG_BYTES {
        return Err(CoreError::validation(
            "structured configuration",
            format!("must contain at most {MAX_STRUCTURED_CONFIG_BYTES} bytes"),
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
            "structured configuration import path",
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
            "structured configuration destination",
            "must be a new absolute file path in an existing directory without traversal components",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, time::SystemTime};

    use super::*;

    fn row_named<'a>(rows: &'a [StructuredConfigRow], name: &str) -> &'a StructuredConfigRow {
        rows.iter()
            .find(|row| row.name() == Some(name))
            .unwrap_or_else(|| panic!("missing row named {name}"))
    }

    fn only_child(
        document: &StructuredConfigVisualDocument,
        parent: StructuredConfigNodeId,
    ) -> StructuredConfigRow {
        let children = document.children(parent).expect("children");
        assert_eq!(children.len(), 1);
        children.into_iter().next().expect("one child")
    }

    #[test]
    fn json_preserves_bom_order_duplicates_and_raw_scalars() {
        let source =
            b"\xEF\xBB\xBF {\"a\":-0,\"a\":1E+400,\"nested\":[true,null,\"x\\u0061\"]}\r\n";
        let document = StructuredConfigVisualDocument::parse_bytes(
            StructuredConfigDialect::Json,
            source.to_vec(),
        )
        .expect("valid JSON");
        assert!(document.is_structured());
        assert_eq!(document.output().bytes(), source);

        let roots = document.root_rows();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].kind(), StructuredConfigNodeKind::Document);
        let object = only_child(&document, roots[0].id());
        assert_eq!(object.kind(), StructuredConfigNodeKind::Object);
        let members = document.children(object.id()).unwrap();
        assert_eq!(
            members
                .iter()
                .map(StructuredConfigRow::name)
                .collect::<Vec<_>>(),
            [Some("a"), Some("a"), Some("nested")]
        );
        assert_eq!(only_child(&document, members[0].id()).value(), Some("-0"));
        assert_eq!(
            only_child(&document, members[1].id()).value(),
            Some("1E+400")
        );
        let array = only_child(&document, members[2].id());
        let items = document.children(array.id()).unwrap();
        assert_eq!(items[0].value(), Some("true"));
        assert_eq!(items[1].value(), Some("null"));
        assert_eq!(items[2].value(), Some("\"x\\u0061\""));
        assert!(document.rows().iter().all(|row| !row.editable()));
    }

    #[test]
    fn yaml_and_xml_safe_subsets_are_ordered_source_backed_trees() {
        let yaml = b"\xEF\xBB\xBF# safe header\r\ncluster:\r\n  name: emergency\r\n  nodes:\r\n    - host: db01\r\n      port: 5432\r\n    - host: db02\r\nduplicate: one\r\nduplicate: two\r\n";
        let document = StructuredConfigVisualDocument::parse_bytes(
            StructuredConfigDialect::Yaml,
            yaml.to_vec(),
        )
        .unwrap();
        assert!(document.is_structured());
        assert!(!document.contains_sensitive_values());
        assert_eq!(document.output().bytes(), yaml);
        let rows = document.rows();
        assert_eq!(
            row_named(&rows, "cluster").kind(),
            StructuredConfigNodeKind::Member
        );
        assert_eq!(
            row_named(&rows, "nodes").kind(),
            StructuredConfigNodeKind::Member
        );
        assert_eq!(
            rows.iter().filter(|row| row.name() == Some("host")).count(),
            2
        );
        assert_eq!(
            rows.iter()
                .filter(|row| row.name() == Some("duplicate"))
                .count(),
            2
        );
        assert!(
            rows.iter()
                .any(|row| row.kind() == StructuredConfigNodeKind::Comment)
        );

        let xml = b"\xEF\xBB\xBF<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n<!-- safe -->\r\n<cluster id=\"one\"><node host=\"db01\"/>text<node host='db02'/></cluster>\r\n";
        let document =
            StructuredConfigVisualDocument::parse_bytes(StructuredConfigDialect::Xml, xml.to_vec())
                .unwrap();
        assert!(document.is_structured());
        assert!(!document.contains_sensitive_values());
        assert_eq!(document.output().bytes(), xml);
        let rows = document.rows();
        assert_eq!(
            row_named(&rows, "cluster").kind(),
            StructuredConfigNodeKind::Member
        );
        assert_eq!(
            row_named(&rows, "id").kind(),
            StructuredConfigNodeKind::Scalar
        );
        assert_eq!(
            rows.iter().filter(|row| row.name() == Some("node")).count(),
            2
        );
        assert_eq!(
            rows.iter().filter(|row| row.name() == Some("host")).count(),
            2
        );
        assert!(
            rows.iter()
                .any(|row| row.kind() == StructuredConfigNodeKind::Comment)
        );
        assert!(rows.iter().any(|row| {
            row.kind() == StructuredConfigNodeKind::Scalar
                && row.value().is_some_and(|value| value == "text")
        }));
    }

    #[test]
    fn gcware_is_source_exact_read_only_and_redacts_opaque_boundaries() {
        let source = b"\xEF\xBB\xBFtotem {\r\n\tversion:\t2\r\n\tmember {\r\n\t\tmemberaddr: 10.0.0.1\r\n\t}\r\n\t@future syntax\r\n\tpassword: NeverShow\r\n\tafter: visible\r\n}\r\n";
        let document = StructuredConfigVisualDocument::parse_bytes(
            StructuredConfigDialect::Gcware,
            source.to_vec(),
        )
        .unwrap();
        assert!(document.is_structured());
        assert!(document.contains_sensitive_values());
        assert_eq!(document.output().bytes(), source);
        assert_eq!(document.output().suggested_file_name(), "gcware.conf");
        assert_eq!(
            StructuredConfigDialect::Gcware.label(),
            "GBase 8a gcware.conf"
        );

        let rows = document.rows();
        assert_eq!(
            row_named(&rows, "totem").kind(),
            StructuredConfigNodeKind::Member
        );
        assert_eq!(
            only_child(&document, row_named(&rows, "version").id()).value(),
            Some("2")
        );
        assert_eq!(
            only_child(&document, row_named(&rows, "after").id()).value(),
            Some("visible")
        );
        let password = row_named(&rows, "password");
        assert!(password.sensitive());
        assert_eq!(password.preview(), "[sensitive value redacted]");
        assert!(only_child(&document, password.id()).value().is_none());
        assert!(rows.iter().any(|row| {
            row.kind() == StructuredConfigNodeKind::Opaque
                && row.sensitive()
                && row.preview() == "[sensitive value redacted]"
        }));
        assert!(rows.iter().all(|row| !row.editable()));
        assert!(!format!("{document:?}{rows:?}").contains("NeverShow"));
    }

    #[test]
    fn gcware_nested_document_is_byte_exact_and_read_only() {
        let source = b"totem {\r\n\tversion: 2\r\n\tinterface {\r\n\t\tmember {\r\n\t\t\tmemberaddr: 10.0.0.1\r\n\t\t}\r\n\t}\r\n}\r\n";
        let document = StructuredConfigVisualDocument::parse_bytes(
            StructuredConfigDialect::Gcware,
            source.to_vec(),
        )
        .expect("reviewed nested gcware.conf fixture");

        assert!(document.is_structured());
        assert_eq!(document.raw_bytes(), source);
        assert_eq!(document.output().bytes(), source);
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
        assert_eq!(interface.parent(), Some(totem.id()));
        assert_eq!(member.parent(), Some(interface.id()));
        assert_eq!(memberaddr.parent(), Some(member.id()));
        assert!(rows.iter().all(|row| !row.editable()));
    }

    #[test]
    fn structurally_ambiguous_gcware_is_complete_redacted_opaque() {
        let source = b"totem{\n    password: NeverShow\n}\n";
        let document = StructuredConfigVisualDocument::parse_bytes(
            StructuredConfigDialect::Gcware,
            source.to_vec(),
        )
        .unwrap();
        assert!(!document.is_structured());
        assert!(document.contains_sensitive_values());
        assert_eq!(document.output().bytes(), source);
        let rows = document.rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind(), StructuredConfigNodeKind::Opaque);
        assert!(rows[0].sensitive());
        assert_eq!(rows[0].preview(), "[sensitive value redacted]");
        assert!(!format!("{document:?}{rows:?}").contains("NeverShow"));
    }

    #[test]
    fn sequoia_quick_deploy_dialects_are_byte_exact_read_only_and_redacted() {
        let source = b"instanceName,port,databaseDir,coordAddr\r\n# ordinary note\r\nsecret,3306,/srv/api_key=NeverShow,-\r\n# cookie=CookieLeak \"\r\nquoted,3307,/srv/\"QuoteLeak,-\r\nsafe,3308,/srv/api_keys/cache,[localhost:50000,localhost:11810]\r\n";
        let document = StructuredConfigVisualDocument::parse_bytes(
            StructuredConfigDialect::SequoiaQuickDeploySqlInstanceCsv,
            source.to_vec(),
        )
        .unwrap();
        assert!(document.is_structured());
        assert!(document.contains_sensitive_values());
        assert_eq!(document.output().bytes(), source);
        assert_eq!(document.output().suggested_file_name(), "sql-instance.conf");
        assert_eq!(
            StructuredConfigDialect::SequoiaQuickDeploySqlInstanceCsv.label(),
            "SequoiaDB quickDeploy SQL instance CSV"
        );

        let root = document.root_rows();
        assert_eq!(root.len(), 1);
        assert_eq!(root[0].kind(), StructuredConfigNodeKind::Document);
        let records = document.children(root[0].id()).unwrap();
        assert_eq!(records.len(), 6);
        assert_eq!(records[0].kind(), StructuredConfigNodeKind::Array);
        assert_eq!(records[1].kind(), StructuredConfigNodeKind::Comment);
        assert!(!records[1].sensitive());
        assert!(records[1].preview().starts_with("# ordinary note"));
        assert_eq!(records[2].kind(), StructuredConfigNodeKind::Array);
        assert_eq!(records[3].kind(), StructuredConfigNodeKind::Comment);
        assert!(records[3].sensitive());
        assert_eq!(records[3].preview(), "[sensitive value redacted]");
        assert_eq!(records[4].kind(), StructuredConfigNodeKind::Opaque);
        assert!(records[4].sensitive());
        assert_eq!(records[5].kind(), StructuredConfigNodeKind::Array);

        let header = document.children(records[0].id()).unwrap();
        assert_eq!(
            header
                .iter()
                .map(StructuredConfigRow::value)
                .collect::<Vec<_>>(),
            [
                Some("instanceName"),
                Some("port"),
                Some("databaseDir"),
                Some("coordAddr")
            ]
        );
        let secret = document.children(records[2].id()).unwrap();
        assert!(secret[2].sensitive());
        assert_eq!(secret[2].value(), None);
        assert_eq!(secret[2].preview(), "[sensitive value redacted]");
        let safe = document.children(records[5].id()).unwrap();
        assert_eq!(safe[2].value(), Some("/srv/api_keys/cache"));
        assert!(!safe[2].sensitive());
        assert_eq!(safe[3].value(), Some("[localhost:50000,localhost:11810]"));
        let rows = document.rows();
        assert!(rows.iter().all(|row| !row.editable()));
        let debug = format!("{document:?}{rows:?}");
        for secret in ["NeverShow", "CookieLeak", "QuoteLeak"] {
            assert!(!debug.contains(secret));
        }

        let cluster = b"role,groupName,hostName,serviceName,dbPath\r\ndata,group1,localhost,11820,[installPath]/database/data/11820\r\n# ordinary cluster note\r\n";
        let cluster_document = StructuredConfigVisualDocument::parse_bytes(
            StructuredConfigDialect::SequoiaQuickDeployClusterCsv,
            cluster.to_vec(),
        )
        .unwrap();
        assert!(cluster_document.is_structured());
        assert_eq!(cluster_document.output().bytes(), cluster);
        assert_eq!(
            cluster_document.output().suggested_file_name(),
            "sequoiadb.conf"
        );
        assert_eq!(
            StructuredConfigDialect::SequoiaQuickDeployClusterCsv.label(),
            "SequoiaDB quickDeploy cluster CSV"
        );
        assert!(cluster_document.rows().iter().all(|row| !row.editable()));
    }

    #[test]
    fn sequoia_quick_deploy_cross_role_headers_fail_closed() {
        for (dialect, source) in [
            (
                StructuredConfigDialect::SequoiaQuickDeployClusterCsv,
                b"instanceName,port,databaseDir,coordAddr\nsql,3306,/srv,-\n".as_slice(),
            ),
            (
                StructuredConfigDialect::SequoiaQuickDeploySqlInstanceCsv,
                b"role,groupName,hostName,serviceName,dbPath\ndata,g,h,11820,/srv\n".as_slice(),
            ),
        ] {
            let document =
                StructuredConfigVisualDocument::parse_bytes(dialect, source.to_vec()).unwrap();
            assert!(!document.is_structured());
            assert!(document.contains_sensitive_values());
            assert_eq!(document.output().bytes(), source);
            let rows = document.rows();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].kind(), StructuredConfigNodeKind::Opaque);
            assert!(rows[0].sensitive());
            assert_eq!(rows[0].preview(), "[sensitive value redacted]");
        }
    }

    #[test]
    fn yaml_and_xml_advanced_regions_are_atomic_without_hiding_safe_siblings() {
        let yaml = b"safe: before\nscript: |\n  password: DontLeak\nafter: visible\n";
        let document = StructuredConfigVisualDocument::parse_bytes(
            StructuredConfigDialect::Yaml,
            yaml.to_vec(),
        )
        .unwrap();
        assert!(document.is_structured());
        assert!(document.contains_sensitive_values());
        assert_eq!(document.output().bytes(), yaml);
        let rows = document.rows();
        assert!(
            rows.iter()
                .any(|row| row.kind() == StructuredConfigNodeKind::Opaque)
        );
        assert!(!row_named(&rows, "after").sensitive());
        assert_eq!(
            only_child(&document, row_named(&rows, "after").id()).value(),
            Some("visible")
        );
        assert!(!format!("{document:?}{rows:?}").contains("DontLeak"));

        let xml = b"<!DOCTYPE cluster [<!ENTITY x SYSTEM 'file:///not-read'>]><cluster><safe>before</safe><![CDATA[DontLeak]]><after>visible</after></cluster>";
        let document =
            StructuredConfigVisualDocument::parse_bytes(StructuredConfigDialect::Xml, xml.to_vec())
                .unwrap();
        assert!(document.is_structured());
        assert!(document.contains_sensitive_values());
        assert_eq!(document.output().bytes(), xml);
        let rows = document.rows();
        assert!(
            rows.iter()
                .filter(|row| row.kind() == StructuredConfigNodeKind::Opaque)
                .count()
                >= 2
        );
        assert!(!row_named(&rows, "after").sensitive());
        assert!(rows.iter().any(|row| {
            !row.sensitive()
                && row.kind() == StructuredConfigNodeKind::Scalar
                && row.value().is_some_and(|value| value == "visible")
        }));
        assert!(!format!("{document:?}{rows:?}").contains("DontLeak"));
    }

    #[test]
    fn yaml_directives_are_opaque_only_within_their_document_boundary() {
        let source = b"safe: 1\n...\n%YAML 1.2\n---\nadvanced: x\n...\n---\nafter: 2\n";
        let document = StructuredConfigVisualDocument::parse_bytes(
            StructuredConfigDialect::Yaml,
            source.to_vec(),
        )
        .unwrap();
        assert!(document.is_structured());
        assert_eq!(document.output().bytes(), source);
        let rows = document.rows();
        assert_eq!(
            rows.iter()
                .filter(|row| row.kind() == StructuredConfigNodeKind::Opaque)
                .count(),
            1
        );
        assert_eq!(
            rows.iter()
                .filter(|row| row.kind() == StructuredConfigNodeKind::Object)
                .count(),
            2
        );
        assert!(!row_named(&rows, "safe").sensitive());
        assert!(!row_named(&rows, "after").sensitive());
    }

    #[test]
    fn invalid_json_and_non_utf8_fail_to_lossless_redacted_opaque() {
        for source in [
            b"{\"a\":1,}".as_slice(),
            b"{/*comment*/\"a\":1}".as_slice(),
            b"NaN".as_slice(),
            b"01".as_slice(),
            b"{} []".as_slice(),
            b"1e+".as_slice(),
            b"\"unterminated".as_slice(),
        ] {
            let document = StructuredConfigVisualDocument::parse_bytes(
                StructuredConfigDialect::Json,
                source.to_vec(),
            )
            .expect("invalid input remains preservable");
            assert!(!document.is_structured());
            assert!(document.contains_sensitive_values());
            assert_eq!(document.output().bytes(), source);
            let rows = document.rows();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].kind(), StructuredConfigNodeKind::Opaque);
            assert!(rows[0].sensitive());
            assert_eq!(rows[0].preview(), "[sensitive value redacted]");
        }

        let binary = vec![0xff, 0xfe, 0x00, b'{'];
        let document = StructuredConfigVisualDocument::parse_bytes(
            StructuredConfigDialect::Json,
            binary.clone(),
        )
        .unwrap();
        assert!(!document.is_structured());
        assert!(document.output().text().is_err());
        assert_eq!(document.output().bytes(), binary);

        let empty = StructuredConfigVisualDocument::parse(StructuredConfigDialect::Yaml, "")
            .expect("empty placeholder");
        assert!(empty.is_structured());
        assert_eq!(empty.root_rows().len(), 1);
        assert_eq!(
            empty.root_rows()[0].kind(),
            StructuredConfigNodeKind::Document
        );
        assert!(!empty.contains_sensitive_values());
    }

    #[test]
    fn opaque_regions_never_expose_escaped_secret_names() {
        for (dialect, source) in [
            (
                StructuredConfigDialect::Json,
                br#"{"pass\u0077ord":"DontLeak",}"#.as_slice(),
            ),
            (
                StructuredConfigDialect::Yaml,
                br#""pass\x77ord": DontLeak"#.as_slice(),
            ),
            (
                StructuredConfigDialect::Xml,
                br#"<PARAM name="pass&#119;ord" value="DontLeak"/>"#.as_slice(),
            ),
        ] {
            let document =
                StructuredConfigVisualDocument::parse_bytes(dialect, source.to_vec()).unwrap();
            assert!(document.contains_sensitive_values());
            assert_eq!(document.output().bytes(), source);
            let rows = document.rows();
            assert!(rows.iter().any(StructuredConfigRow::sensitive));
            assert!(rows.iter().all(|row| {
                !row.preview().contains("DontLeak")
                    && row.value().is_none_or(|value| !value.contains("DontLeak"))
            }));
            assert!(!format!("{document:?}{rows:?}").contains("DontLeak"));
        }
    }

    #[test]
    fn escaped_keys_tokens_connection_strings_and_carriers_are_redacted() {
        let source = r#"{"pass\u0077ord":"DontLeak","refresh_token":"RefreshLeak","connection_string":"OpaqueDsn","privateKey":"CamelPrivate","accessKey":"CamelAccess","connectionString":"CamelDsn","normal":"ok","url":"https://user:pass@example.test"}"#;
        let document = StructuredConfigVisualDocument::parse(StructuredConfigDialect::Json, source)
            .expect("sensitive JSON");
        assert!(document.is_structured());
        assert!(document.contains_sensitive_values());
        let rows = document.rows();
        for name in [
            "password",
            "refresh_token",
            "connection_string",
            "privateKey",
            "accessKey",
            "connectionString",
        ] {
            let member = row_named(&rows, name);
            assert!(member.sensitive());
            let value = only_child(&document, member.id());
            assert!(value.sensitive());
            assert!(value.value().is_none());
            assert_eq!(value.preview(), "[sensitive value redacted]");
        }
        assert_eq!(
            only_child(&document, row_named(&rows, "normal").id()).value(),
            Some("\"ok\"")
        );
        let url = only_child(&document, row_named(&rows, "url").id());
        assert!(url.sensitive());
        for debug in [
            format!("{document:?}"),
            format!("{:?}", document.output()),
            format!("{rows:?}"),
        ] {
            for secret in [
                "DontLeak",
                "RefreshLeak",
                "OpaqueDsn",
                "CamelPrivate",
                "CamelAccess",
                "CamelDsn",
                "user:pass",
            ] {
                assert!(!debug.contains(secret));
            }
        }
    }

    #[test]
    fn authkey_keys_assignments_and_comments_are_redacted_without_broad_auth_matches() {
        let json_source = r#"{"authKey":"JsonDontLeak","AUTHKEY":"UpperDontLeak","path":"/srv/auth_key=ScalarDontLeak","authority":"safe","auth_method":"scram","authentication_mode":"strict"}"#;
        let json =
            StructuredConfigVisualDocument::parse(StructuredConfigDialect::Json, json_source)
                .expect("AUTHKEY JSON fixture");
        assert!(json.is_structured());
        assert!(json.contains_sensitive_values());
        assert!(!json.can_copy_text());
        assert_eq!(json.output().bytes(), json_source.as_bytes());
        let json_rows = json.rows();
        for key in ["authKey", "AUTHKEY"] {
            let member = row_named(&json_rows, key);
            assert!(member.sensitive());
            let value = only_child(&json, member.id());
            assert!(value.sensitive());
            assert_eq!(value.value(), None);
            assert_eq!(value.preview(), "[sensitive value redacted]");
        }
        let assigned = only_child(&json, row_named(&json_rows, "path").id());
        assert!(assigned.sensitive());
        assert_eq!(assigned.value(), None);
        for key in ["authority", "auth_method", "authentication_mode"] {
            let member = row_named(&json_rows, key);
            assert!(!member.sensitive());
            assert!(!only_child(&json, member.id()).sensitive());
        }

        let yaml_source = b"AUTH_KEY: YamlDontLeak\nauthority: safe\nauth_method: scram\nauthentication_mode: strict\n# authKey CommentDontLeak\n# authority remains visible\n# notauthkey remains visible\n";
        let yaml = StructuredConfigVisualDocument::parse_bytes(
            StructuredConfigDialect::Yaml,
            yaml_source.to_vec(),
        )
        .expect("AUTH_KEY YAML fixture");
        assert!(yaml.is_structured());
        assert!(yaml.contains_sensitive_values());
        assert!(!yaml.can_copy_text());
        assert_eq!(yaml.output().bytes(), yaml_source);
        let yaml_rows = yaml.rows();
        let yaml_member = row_named(&yaml_rows, "AUTH_KEY");
        assert!(yaml_member.sensitive());
        assert!(only_child(&yaml, yaml_member.id()).sensitive());
        for key in ["authority", "auth_method", "authentication_mode"] {
            assert!(!row_named(&yaml_rows, key).sensitive());
        }
        let yaml_comments = yaml_rows
            .iter()
            .filter(|row| row.kind() == StructuredConfigNodeKind::Comment)
            .collect::<Vec<_>>();
        assert_eq!(yaml_comments.len(), 3);
        assert!(yaml_comments[0].sensitive());
        assert!(!yaml_comments[1].sensitive());
        assert!(!yaml_comments[2].sensitive());

        let xml_source = br#"<server authKey="XmlDontLeak" authority="safe" auth_method="scram" authentication_mode="strict"/>"#;
        let xml = StructuredConfigVisualDocument::parse_bytes(
            StructuredConfigDialect::Xml,
            xml_source.to_vec(),
        )
        .expect("authKey XML attribute fixture");
        assert!(xml.is_structured());
        assert!(xml.contains_sensitive_values());
        assert!(!xml.can_copy_text());
        assert_eq!(xml.output().bytes(), xml_source);
        let xml_rows = xml.rows();
        assert!(row_named(&xml_rows, "authKey").sensitive());
        for key in ["authority", "auth_method", "authentication_mode"] {
            assert!(!row_named(&xml_rows, key).sensitive());
        }

        let sequoia_source = b"instanceName,port,databaseDir,coordAddr\ncamel,3306,/srv/authkey=SequoiaCamelDontLeak,-\nsnake,3307,/srv/AUTH_KEY=SequoiaSnakeDontLeak,-\nplain,3308,/srv/authority=safe,auth_method=scram\n# authKey SequoiaCommentDontLeak\n# authority remains visible\n";
        let sequoia = StructuredConfigVisualDocument::parse_bytes(
            StructuredConfigDialect::SequoiaQuickDeploySqlInstanceCsv,
            sequoia_source.to_vec(),
        )
        .expect("AUTHKEY SequoiaDB quickDeploy fixture");
        assert!(sequoia.is_structured());
        assert!(sequoia.contains_sensitive_values());
        assert!(!sequoia.can_copy_text());
        assert_eq!(sequoia.output().bytes(), sequoia_source);
        let sequoia_root = sequoia.root_rows();
        let sequoia_records = sequoia.children(sequoia_root[0].id()).unwrap();
        for record in &sequoia_records[1..=2] {
            let fields = sequoia.children(record.id()).unwrap();
            assert!(fields[2].sensitive());
            assert_eq!(fields[2].value(), None);
            assert_eq!(fields[2].preview(), "[sensitive value redacted]");
        }
        let safe_fields = sequoia.children(sequoia_records[3].id()).unwrap();
        assert!(safe_fields.iter().all(|field| !field.sensitive()));
        assert!(sequoia_records[4].sensitive());
        assert!(!sequoia_records[5].sensitive());
        let sequoia_rows = sequoia.rows();

        assert!(contains_sensitive_text("/srv/authkey=AssignmentDontLeak"));
        assert!(contains_sensitive_text(
            "/srv/AUTH_KEY=SnakeAssignmentDontLeak"
        ));
        assert!(contains_sensitive_marker_text("AUTHKEY OpaqueDontLeak"));
        for safe in [
            "authority=safe",
            "auth_method=scram",
            "authentication_mode=strict",
            "notauthkey=safe",
        ] {
            assert!(!contains_sensitive_text(safe));
            assert!(!contains_sensitive_marker_text(safe));
        }

        for debug in [
            format!("{json:?}{json_rows:?}"),
            format!("{yaml:?}{yaml_rows:?}"),
            format!("{xml:?}{xml_rows:?}"),
            format!("{sequoia:?}{sequoia_rows:?}"),
        ] {
            for secret in [
                "JsonDontLeak",
                "UpperDontLeak",
                "ScalarDontLeak",
                "YamlDontLeak",
                "CommentDontLeak",
                "XmlDontLeak",
                "SequoiaCamelDontLeak",
                "SequoiaSnakeDontLeak",
                "SequoiaCommentDontLeak",
            ] {
                assert!(!debug.contains(secret));
            }
        }
    }

    #[test]
    fn sensitive_json_blocks_whole_text_copy_and_redacts_rows_and_debug() {
        let secret = "do-not-copy-this-secret";
        let source =
            format!("{{\"Version\": 2, \"mysql_server\": {{\"password\": \"{secret}\"}}}}\n");
        let document =
            StructuredConfigVisualDocument::parse(StructuredConfigDialect::Json, &source)
                .expect("reviewed sensitive JSON fixture");
        let rows = document.rows();

        assert!(document.is_structured());
        assert!(document.contains_sensitive_values());
        assert!(!document.can_copy_text());
        assert!(rows.iter().any(StructuredConfigRow::sensitive));
        assert!(
            rows.iter()
                .filter(|row| row.sensitive())
                .all(|row| row.preview() == "[sensitive value redacted]")
        );
        assert!(!format!("{document:?}{rows:?}").contains(secret));
        assert_eq!(document.output().bytes(), source.as_bytes());

        let safe = StructuredConfigVisualDocument::parse(
            StructuredConfigDialect::Json,
            r#"{"role":"readonly"}"#,
        )
        .expect("reviewed non-sensitive JSON fixture");
        assert!(!safe.contains_sensitive_values());
        assert!(safe.can_copy_text());
    }

    #[test]
    fn rfc_grammar_lone_surrogates_remain_structured_but_not_displayable() {
        let source = br#"{"\uDEAD":"\uD800","pair":"\uD83D\uDE00"}"#;
        let document = StructuredConfigVisualDocument::parse_bytes(
            StructuredConfigDialect::Json,
            source.to_vec(),
        )
        .expect("RFC JSON string ABNF permits escaped unpaired surrogates");
        assert!(document.is_structured());
        assert_eq!(document.output().bytes(), source);
        let rows = document.rows();
        let unnamed = rows
            .iter()
            .find(|row| row.kind() == StructuredConfigNodeKind::Member && row.name().is_none())
            .expect("unpaired-surrogate key remains represented");
        assert!(unnamed.sensitive());
        assert_eq!(row_named(&rows, "pair").name(), Some("pair"));
        assert_eq!(
            only_child(&document, row_named(&rows, "pair").id()).value(),
            Some("\"\\uD83D\\uDE00\"")
        );
    }

    #[test]
    fn row_names_and_scalars_are_bounded() {
        let key = "a".repeat(MAX_STRUCTURED_CONFIG_ROW_PREVIEW_BYTES + 37);
        let scalar = "b".repeat(MAX_STRUCTURED_CONFIG_ROW_PREVIEW_BYTES * 4);
        let source = format!("{{\"{key}\":\"{scalar}\"}}");
        let document =
            StructuredConfigVisualDocument::parse(StructuredConfigDialect::Json, &source)
                .expect("large bounded rows");
        let rows = document.rows();
        let member = rows
            .iter()
            .find(|row| row.kind() == StructuredConfigNodeKind::Member)
            .unwrap();
        assert!(member.name().unwrap().len() <= MAX_STRUCTURED_CONFIG_ROW_PREVIEW_BYTES);
        assert!(member.preview().len() <= MAX_STRUCTURED_CONFIG_ROW_PREVIEW_BYTES);
        assert!(member.truncated());
        let value = only_child(&document, member.id());
        assert!(value.value().unwrap().len() <= MAX_STRUCTURED_CONFIG_ROW_PREVIEW_BYTES);
        assert!(value.preview().len() <= MAX_STRUCTURED_CONFIG_ROW_PREVIEW_BYTES);
        assert!(value.truncated());
    }

    #[test]
    fn maximum_size_non_ascii_json_string_parses_with_bounded_rows() {
        let mut source = Vec::with_capacity(MAX_STRUCTURED_CONFIG_BYTES);
        source.push(b'"');
        source.extend(
            "é".as_bytes()
                .iter()
                .copied()
                .cycle()
                .take(MAX_STRUCTURED_CONFIG_BYTES - 2),
        );
        source.push(b'"');
        let document = StructuredConfigVisualDocument::parse_bytes(
            StructuredConfigDialect::Json,
            source.clone(),
        )
        .expect("bounded non-ASCII JSON string");
        assert!(document.is_structured());
        assert_eq!(document.output().bytes(), source);
        let scalar = document
            .rows()
            .into_iter()
            .find(|row| row.kind() == StructuredConfigNodeKind::Scalar)
            .unwrap();
        assert!(scalar.truncated());
        assert!(scalar.value().unwrap().len() <= MAX_STRUCTURED_CONFIG_ROW_PREVIEW_BYTES);
    }

    #[test]
    fn depth_node_and_byte_limits_fail_closed() {
        let exact_depth = format!(
            "{}null{}",
            "[".repeat(MAX_STRUCTURED_CONFIG_DEPTH - 1),
            "]".repeat(MAX_STRUCTURED_CONFIG_DEPTH - 1)
        );
        let document =
            StructuredConfigVisualDocument::parse(StructuredConfigDialect::Json, &exact_depth)
                .unwrap();
        assert!(document.is_structured());
        assert_eq!(
            document.rows().iter().map(StructuredConfigRow::depth).max(),
            Some(MAX_STRUCTURED_CONFIG_DEPTH)
        );

        let over_depth = format!(
            "{}null{}",
            "[".repeat(MAX_STRUCTURED_CONFIG_DEPTH),
            "]".repeat(MAX_STRUCTURED_CONFIG_DEPTH)
        );
        let document =
            StructuredConfigVisualDocument::parse(StructuredConfigDialect::Json, &over_depth)
                .unwrap();
        assert!(!document.is_structured());
        assert_eq!(document.output().bytes(), over_depth.as_bytes());

        let exact_nodes = format!(
            "[{}]",
            vec!["null"; MAX_STRUCTURED_CONFIG_NODES - 2].join(",")
        );
        let document =
            StructuredConfigVisualDocument::parse(StructuredConfigDialect::Json, &exact_nodes)
                .unwrap();
        assert!(document.is_structured());
        assert_eq!(document.rows().len(), MAX_STRUCTURED_CONFIG_NODES);

        let over_nodes = format!(
            "[{}]",
            vec!["null"; MAX_STRUCTURED_CONFIG_NODES - 1].join(",")
        );
        let document =
            StructuredConfigVisualDocument::parse(StructuredConfigDialect::Json, &over_nodes)
                .unwrap();
        assert!(!document.is_structured());
        assert_eq!(document.output().bytes(), over_nodes.as_bytes());

        assert!(
            StructuredConfigVisualDocument::parse_bytes(
                StructuredConfigDialect::Json,
                vec![b' '; MAX_STRUCTURED_CONFIG_BYTES + 1],
            )
            .is_err()
        );
    }

    #[test]
    fn replacement_and_cross_document_ids_fail_closed() {
        let mut first =
            StructuredConfigVisualDocument::parse(StructuredConfigDialect::Json, "{\"a\":1}")
                .unwrap();
        let old_root = first.root_rows()[0].id();
        let second =
            StructuredConfigVisualDocument::parse(StructuredConfigDialect::Json, "{\"b\":2}")
                .unwrap();
        let foreign = second.root_rows()[0].id();
        assert!(first.children(foreign).is_err());
        first.replace_raw(b"{\"c\":3}".to_vec()).unwrap();
        assert!(first.children(old_root).is_err());
        assert_ne!(first.root_rows()[0].id(), old_root);
    }

    #[test]
    fn import_and_create_new_reject_traversal_and_never_overwrite() {
        let unique = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "lovelyres-structured-config-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        let child = directory.join("child");
        fs::create_dir(&child).unwrap();
        let input = directory.join("input.json");
        fs::write(&input, b"{\"a\":1}").unwrap();
        let document =
            StructuredConfigVisualDocument::read_local(StructuredConfigDialect::Json, &input)
                .unwrap();
        let lexical_traversal = child.join("..").join("input.json");
        assert!(
            StructuredConfigVisualDocument::read_local(
                StructuredConfigDialect::Json,
                &lexical_traversal,
            )
            .is_err()
        );

        let destination = directory.join("saved.json");
        document.output().write_new(&destination).unwrap();
        assert_eq!(fs::read(&destination).unwrap(), document.raw_bytes());
        assert!(document.output().write_new(&destination).is_err());
        assert!(
            document
                .output()
                .write_new(&child.join("..").join("other.json"))
                .is_err()
        );

        fs::remove_file(input).unwrap();
        fs::remove_file(destination).unwrap();
        fs::remove_dir(child).unwrap();
        fs::remove_dir(directory).unwrap();
    }
}
