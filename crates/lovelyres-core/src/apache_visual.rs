//! Lossless, bounded Apache HTTPD document model for the native visual editor.
//!
//! Apache modules can register directives and configuration sections, so this
//! module intentionally models the configuration grammar rather than a closed
//! directive catalogue. Unknown directives and paired sections remain normal
//! visual nodes. Text whose boundaries cannot be proven safe remains opaque
//! while the original bytes are retained exactly.

use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    ops::Range,
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{CoreError, CoreResult};
use zeroize::Zeroizing;

pub const MAX_APACHE_VISUAL_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_APACHE_VISUAL_NODES: usize = 65_536;
pub const MAX_APACHE_VISUAL_DEPTH: usize = 128;
pub const MAX_APACHE_VISUAL_EDIT_BYTES: usize = 256 * 1024;
const MAX_APACHE_VISUAL_TOKENS: usize = 262_144;
const MAX_ROW_TEXT_BYTES: usize = 512;
const SUGGESTED_FILE_NAME: &str = "httpd-visual.conf";
static NEXT_DOCUMENT_REVISION: AtomicU64 = AtomicU64::new(1);

// mod_perl delegates the body of <Perl> to the Perl interpreter rather than
// Apache's directive parser. Keeping the complete section opaque prevents
// Perl statements from being exposed as safely movable HTTPD directives.
const KNOWN_RAW_SECTIONS: [&[u8]; 1] = [b"perl"];

const COMPETITION_SKELETON: &str = r#"# LovelyRes 应急响应比赛 Apache HTTPD 全面编辑骨架
# 模块、路径和用户取决于目标机；部署前必须使用目标实例运行 apachectl/httpd -t。
ServerRoot "/etc/httpd"
Listen 80
ServerName localhost
ServerTokens Prod
ServerSignature Off
TraceEnable Off
DocumentRoot "/var/www/html"
ErrorLog "logs/error_log"
LogLevel warn

<Directory "/">
    AllowOverride None
    Require all denied
</Directory>

<Directory "/var/www/html">
    Options -Indexes -ExecCGI
    AllowOverride None
    Require all granted
</Directory>

<VirtualHost *:80>
    ServerName example.com
    DocumentRoot "/var/www/html"
    ErrorLog "logs/example-error_log"
    CustomLog "logs/example-access_log" combined

    <Location "/healthz">
        Require all granted
    </Location>

    <FilesMatch "\.(?:php|phtml|phar)$">
        Require all denied
    </FilesMatch>
</VirtualHost>

<IfModule headers_module>
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "DENY"
</IfModule>

IncludeOptional "conf.d/*.conf"
"#;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
/// A lease-like identifier for one parsed document revision.
///
/// Every successful mutation reparses the source. Callers must therefore
/// discard all previously selected identifiers after a mutation succeeds.
pub struct ApacheVisualNodeId(u128);

impl ApacheVisualNodeId {
    pub const fn get(self) -> u128 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApacheVisualNodeKind {
    Directive,
    Section,
    Comment,
    Opaque,
}

impl ApacheVisualNodeKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Directive => "指令",
            Self::Section => "区段",
            Self::Comment => "注释",
            Self::Opaque => "原文",
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ApacheVisualRow {
    id: ApacheVisualNodeId,
    parent: Option<ApacheVisualNodeId>,
    depth: usize,
    kind: ApacheVisualNodeKind,
    name: Option<Zeroizing<String>>,
    arguments: Option<Zeroizing<String>>,
    preview: Zeroizing<String>,
    child_count: usize,
    truncated: bool,
    editable: bool,
    sensitive: bool,
}

impl fmt::Debug for ApacheVisualRow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApacheVisualRow")
            .field("id", &self.id)
            .field("parent", &self.parent)
            .field("depth", &self.depth)
            .field("kind", &self.kind)
            .field("name_present", &self.name.is_some())
            .field("arguments_present", &self.arguments.is_some())
            .field("preview_bytes", &self.preview.len())
            .field("child_count", &self.child_count)
            .field("truncated", &self.truncated)
            .field("editable", &self.editable)
            .field("sensitive", &self.sensitive)
            .finish()
    }
}

impl ApacheVisualRow {
    pub const fn id(&self) -> ApacheVisualNodeId {
        self.id
    }

    pub const fn parent(&self) -> Option<ApacheVisualNodeId> {
        self.parent
    }

    pub const fn depth(&self) -> usize {
        self.depth
    }

    pub const fn kind(&self) -> ApacheVisualNodeKind {
        self.kind
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_ref().map(|value| value.as_str())
    }

    pub fn arguments(&self) -> Option<&str> {
        self.arguments.as_ref().map(|value| value.as_str())
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
pub struct ApacheVisualOutput {
    bytes: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for ApacheVisualOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApacheVisualOutput")
            .field("bytes", &self.bytes.len())
            .field("utf8", &std::str::from_utf8(&self.bytes).is_ok())
            .finish()
    }
}

impl ApacheVisualOutput {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn text(&self) -> CoreResult<&str> {
        std::str::from_utf8(&self.bytes).map_err(|_| {
            CoreError::validation(
                "Apache visual configuration",
                "contains non-UTF-8 bytes and cannot be copied as text; save the original bytes instead",
            )
        })
    }

    pub fn text_lossy(&self) -> Zeroizing<String> {
        Zeroizing::new(String::from_utf8_lossy(&self.bytes).into_owned())
    }

    pub const fn suggested_file_name(&self) -> &'static str {
        SUGGESTED_FILE_NAME
    }

    /// Write the complete byte-preserving document without replacing a file.
    pub fn write_new(&self, destination: &Path) -> CoreResult<PathBuf> {
        validate_destination(destination)?;
        validate_size(self.bytes.len())?;

        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(destination)
            .map_err(|source| {
                CoreError::io("create visual Apache configuration", destination, source)
            })?;
        let result = (|| {
            file.write_all(&self.bytes).map_err(|source| {
                CoreError::io("write visual Apache configuration", destination, source)
            })?;
            file.flush().map_err(|source| {
                CoreError::io("flush visual Apache configuration", destination, source)
            })?;
            file.sync_all().map_err(|source| {
                CoreError::io("sync visual Apache configuration", destination, source)
            })
        })();
        drop(file);
        if let Err(error) = result {
            if let Err(cleanup_error) = fs::remove_file(destination) {
                tracing::error!(error = %cleanup_error, "failed to remove partial visual Apache configuration");
            }
            return Err(error);
        }
        Ok(destination.to_path_buf())
    }
}

#[derive(Clone)]
pub struct ApacheVisualDocument {
    source: Zeroizing<Vec<u8>>,
    nodes: Vec<NodeRecord>,
    structured: bool,
    has_opaque_regions: bool,
    contains_sensitive_values: bool,
}

impl fmt::Debug for ApacheVisualDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApacheVisualDocument")
            .field("bytes", &self.source.len())
            .field("nodes", &self.nodes.len())
            .field("structured", &self.structured)
            .field("has_opaque_regions", &self.has_opaque_regions)
            .field("contains_sensitive_values", &self.contains_sensitive_values)
            .finish()
    }
}

#[derive(Clone, Debug)]
struct NodeRecord {
    id: ApacheVisualNodeId,
    parent: Option<ApacheVisualNodeId>,
    depth: usize,
    kind: ApacheVisualNodeKind,
    span: Range<usize>,
    header_span: Range<usize>,
    footer_span: Option<Range<usize>>,
    name_span: Option<Range<usize>>,
    arguments_span: Option<Range<usize>>,
    close_at: Option<usize>,
    child_count: usize,
}

#[derive(Debug)]
struct ParsedNode {
    kind: ApacheVisualNodeKind,
    span: Range<usize>,
    header_span: Range<usize>,
    footer_span: Option<Range<usize>>,
    name_span: Option<Range<usize>>,
    arguments_span: Option<Range<usize>>,
    close_at: Option<usize>,
    children: Vec<ParsedNode>,
}

impl ApacheVisualDocument {
    pub fn blank() -> Self {
        Self {
            source: Zeroizing::new(Vec::new()),
            nodes: Vec::new(),
            structured: true,
            has_opaque_regions: false,
            contains_sensitive_values: false,
        }
    }

    pub fn competition_skeleton() -> CoreResult<Self> {
        Self::parse(COMPETITION_SKELETON)
    }

    pub fn parse(text: &str) -> CoreResult<Self> {
        Self::parse_bytes(text.as_bytes().to_vec())
    }

    pub fn parse_bytes(source: Vec<u8>) -> CoreResult<Self> {
        validate_size(source.len())?;
        if std::str::from_utf8(&source).is_err() || source.contains(&0) {
            return Ok(Self::opaque(source));
        }
        match Parser::new(&source).parse() {
            Ok(parsed) => Ok(Self::from_parsed(source, parsed)),
            Err(_) => Ok(Self::opaque(source)),
        }
    }

    pub fn read_local(path: &Path) -> CoreResult<Self> {
        validate_import_path(path)?;
        let file = File::open(path)
            .map_err(|source| CoreError::io("open local Apache configuration", path, source))?;
        let metadata = file
            .metadata()
            .map_err(|source| CoreError::io("inspect local Apache configuration", path, source))?;
        let length = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
        validate_size(length)?;
        let mut bytes = Vec::with_capacity(length.min(MAX_APACHE_VISUAL_BYTES));
        file.take((MAX_APACHE_VISUAL_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|source| CoreError::io("read local Apache configuration", path, source))?;
        validate_size(bytes.len())?;
        Self::parse_bytes(bytes)
    }

    pub const fn is_structured(&self) -> bool {
        self.structured
    }

    pub const fn has_opaque_regions(&self) -> bool {
        self.has_opaque_regions
    }

    pub const fn contains_sensitive_values(&self) -> bool {
        self.contains_sensitive_values
    }

    pub fn raw_bytes(&self) -> &[u8] {
        &self.source
    }

    pub fn output(&self) -> ApacheVisualOutput {
        ApacheVisualOutput {
            bytes: Zeroizing::new(self.source.to_vec()),
        }
    }

    pub fn rows(&self) -> Vec<ApacheVisualRow> {
        self.nodes.iter().map(|node| self.row(node)).collect()
    }

    pub fn row_by_id(&self, id: ApacheVisualNodeId) -> Option<ApacheVisualRow> {
        self.node(id).map(|node| self.row(node))
    }

    pub fn add_directive(
        &mut self,
        parent: Option<ApacheVisualNodeId>,
        name: &str,
        arguments: &str,
    ) -> CoreResult<()> {
        let fragment = directive_fragment(name, arguments)?;
        self.insert_child(parent, fragment)
    }

    pub fn add_section(
        &mut self,
        parent: Option<ApacheVisualNodeId>,
        name: &str,
        arguments: &str,
    ) -> CoreResult<()> {
        let fragment = section_fragment(name, arguments)?;
        self.insert_child(parent, fragment.complete)
    }

    /// Alias used by format-agnostic visual editor controls.
    pub fn add_block(
        &mut self,
        parent: Option<ApacheVisualNodeId>,
        name: &str,
        arguments: &str,
    ) -> CoreResult<()> {
        self.add_section(parent, name, arguments)
    }

    pub fn add_comment(
        &mut self,
        parent: Option<ApacheVisualNodeId>,
        text: &str,
    ) -> CoreResult<()> {
        validate_comment(text)?;
        let mut fragment = Vec::with_capacity(text.len() + 2);
        fragment.push(b'#');
        if !text.is_empty() {
            fragment.push(b' ');
            fragment.extend_from_slice(text.as_bytes());
        }
        self.insert_child(parent, fragment)
    }

    pub fn update_statement(
        &mut self,
        id: ApacheVisualNodeId,
        name: &str,
        arguments: &str,
    ) -> CoreResult<()> {
        match self.require_node(id)?.kind {
            ApacheVisualNodeKind::Directive => self.update_directive(id, name, arguments),
            ApacheVisualNodeKind::Section => self.update_section(id, name, arguments),
            _ => Err(invalid_edit("selected node is not a directive or section")),
        }
    }

    pub fn update_directive(
        &mut self,
        id: ApacheVisualNodeId,
        name: &str,
        arguments: &str,
    ) -> CoreResult<()> {
        let node = self.require_node(id)?.clone();
        if node.kind != ApacheVisualNodeKind::Directive {
            return Err(invalid_edit("selected node is not a directive"));
        }
        self.require_non_sensitive_node(&node)?;
        let fragment = directive_fragment(name, arguments)?;
        self.splice_and_reparse(node.span, &fragment)
    }

    pub fn update_section(
        &mut self,
        id: ApacheVisualNodeId,
        name: &str,
        arguments: &str,
    ) -> CoreResult<()> {
        let node = self.require_node(id)?.clone();
        if node.kind != ApacheVisualNodeKind::Section {
            return Err(invalid_edit("selected node is not a section"));
        }
        self.require_non_sensitive_node(&node)?;
        let footer_span = node
            .footer_span
            .ok_or_else(|| invalid_edit("selected section has no proven closing tag"))?;
        let fragment = section_fragment(name, arguments)?;
        self.splice_many_and_reparse(vec![
            (node.header_span, fragment.header),
            (footer_span, fragment.footer),
        ])
    }

    pub fn update_comment(&mut self, id: ApacheVisualNodeId, text: &str) -> CoreResult<()> {
        validate_comment(text)?;
        let node = self.require_node(id)?.clone();
        if node.kind != ApacheVisualNodeKind::Comment {
            return Err(invalid_edit("selected node is not a comment"));
        }
        self.require_non_sensitive_node(&node)?;
        let mut replacement = Vec::with_capacity(text.len() + 2);
        replacement.push(b'#');
        if !text.is_empty() {
            replacement.push(b' ');
            replacement.extend_from_slice(text.as_bytes());
        }
        self.splice_and_reparse(node.span, &replacement)
    }

    pub fn remove(&mut self, id: ApacheVisualNodeId) -> CoreResult<()> {
        let node = self.require_node(id)?.clone();
        if node.kind == ApacheVisualNodeKind::Opaque {
            return Err(invalid_edit(
                "opaque source must be replaced explicitly, not structurally deleted",
            ));
        }
        self.require_non_sensitive_node(&node)?;
        let range = self.line_extended_span(&node);
        self.splice_and_reparse(range, &[])
    }

    pub fn move_up(&mut self, id: ApacheVisualNodeId) -> CoreResult<()> {
        self.move_sibling(id, false)
    }

    pub fn move_down(&mut self, id: ApacheVisualNodeId) -> CoreResult<()> {
        self.move_sibling(id, true)
    }

    /// Explicit raw fallback for malformed, non-UTF-8, or embedded syntax.
    pub fn replace_raw(&mut self, bytes: Vec<u8>) -> CoreResult<()> {
        *self = Self::parse_bytes(bytes)?;
        Ok(())
    }

    fn from_parsed(source: Vec<u8>, parsed: Vec<ParsedNode>) -> Self {
        let contains_sensitive_values = contains_sensitive_marker(&source);
        let has_opaque_regions = parsed_contains_opaque(&parsed);
        let revision = next_document_revision();
        let mut next_id = 1u64;
        let mut nodes = Vec::new();
        flatten_nodes(&parsed, None, 0, revision, &mut next_id, &mut nodes);
        Self {
            source: Zeroizing::new(source),
            nodes,
            structured: true,
            has_opaque_regions,
            contains_sensitive_values,
        }
    }

    fn opaque(source: Vec<u8>) -> Self {
        let contains_sensitive_values = contains_sensitive_marker(&source);
        let revision = next_document_revision();
        let nodes: Vec<NodeRecord> = (!source.is_empty())
            .then_some(NodeRecord {
                id: revision_node_id(revision, 1),
                parent: None,
                depth: 0,
                kind: ApacheVisualNodeKind::Opaque,
                span: 0..source.len(),
                header_span: 0..source.len(),
                footer_span: None,
                name_span: None,
                arguments_span: None,
                close_at: None,
                child_count: 0,
            })
            .into_iter()
            .collect();
        let has_opaque_regions = !nodes.is_empty();
        Self {
            source: Zeroizing::new(source),
            nodes,
            structured: false,
            has_opaque_regions,
            contains_sensitive_values,
        }
    }

    fn row(&self, node: &NodeRecord) -> ApacheVisualRow {
        let sensitive = contains_sensitive_marker(&self.source[node.span.clone()]);
        let name = node
            .name_span
            .as_ref()
            .map(|span| Zeroizing::new(bounded_field(&self.source[span.clone()])));
        let arguments = (!sensitive)
            .then(|| {
                node.arguments_span
                    .as_ref()
                    .map(|span| Zeroizing::new(bounded_field(&self.source[span.clone()])))
            })
            .flatten();
        let (preview, preview_truncated) = if sensitive {
            ("[敏感内容已隐藏]".to_owned(), false)
        } else {
            bounded_preview(&self.source[node.span.clone()])
        };
        let editable_span = match node.kind {
            ApacheVisualNodeKind::Section => &node.header_span,
            _ => &node.span,
        };
        let fields_fit = node
            .name_span
            .iter()
            .chain(node.arguments_span.iter())
            .all(|span| span.end - span.start <= MAX_APACHE_VISUAL_EDIT_BYTES)
            && editable_span.end - editable_span.start <= MAX_APACHE_VISUAL_EDIT_BYTES;
        ApacheVisualRow {
            id: node.id,
            parent: node.parent,
            depth: node.depth,
            kind: node.kind,
            name,
            arguments,
            preview: Zeroizing::new(preview),
            child_count: node.child_count,
            truncated: preview_truncated || !fields_fit,
            editable: node.kind != ApacheVisualNodeKind::Opaque && fields_fit && !sensitive,
            sensitive,
        }
    }

    fn node(&self, id: ApacheVisualNodeId) -> Option<&NodeRecord> {
        self.nodes.iter().find(|node| node.id == id)
    }

    fn require_node(&self, id: ApacheVisualNodeId) -> CoreResult<&NodeRecord> {
        self.node(id)
            .ok_or_else(|| invalid_edit("selected Apache node is stale or missing"))
    }

    fn require_non_sensitive_node(&self, node: &NodeRecord) -> CoreResult<()> {
        if contains_sensitive_marker(&self.source[node.span.clone()]) {
            return Err(invalid_edit(
                "sensitive nodes cannot be updated, removed, moved, or used as insertion parents",
            ));
        }
        Ok(())
    }

    fn insert_child(
        &mut self,
        parent: Option<ApacheVisualNodeId>,
        fragment: Vec<u8>,
    ) -> CoreResult<()> {
        if !self.structured {
            return Err(invalid_edit(
                "opaque source cannot accept structural children; edit its raw bytes first",
            ));
        }
        let (insert_at, depth) = match parent {
            Some(parent) => {
                let node = self.require_node(parent)?;
                if node.kind != ApacheVisualNodeKind::Section {
                    return Err(invalid_edit("children can only be added to a section"));
                }
                self.require_non_sensitive_node(node)?;
                let close_at = node
                    .close_at
                    .ok_or_else(|| invalid_edit("section has no proven closing tag"))?;
                let line_start = self.source[..close_at]
                    .iter()
                    .rposition(|byte| *byte == b'\n')
                    .map_or(0, |newline| newline + 1);
                let insert_at = if self.source[line_start..close_at]
                    .iter()
                    .all(|byte| matches!(byte, b' ' | b'\t' | b'\r'))
                {
                    line_start
                } else {
                    close_at
                };
                (insert_at, node.depth + 1)
            }
            None => (self.source.len(), 0),
        };
        let newline = preferred_newline(&self.source);
        let mut insertion = Vec::new();
        let source_has_body =
            self.source.len() > usize::from(self.source.starts_with(&[0xEF, 0xBB, 0xBF])) * 3;
        if insert_at > 0 && source_has_body && !matches!(self.source[insert_at - 1], b'\n' | b'\r')
        {
            insertion.extend_from_slice(newline);
        }
        append_indented_fragment(&mut insertion, &fragment, depth, newline);
        insertion.extend_from_slice(newline);
        self.splice_and_reparse(insert_at..insert_at, &insertion)
    }

    fn move_sibling(&mut self, id: ApacheVisualNodeId, down: bool) -> CoreResult<()> {
        let node = self.require_node(id)?.clone();
        if node.kind == ApacheVisualNodeKind::Opaque {
            return Err(invalid_edit("opaque source cannot be structurally moved"));
        }
        self.require_non_sensitive_node(&node)?;
        let siblings = self
            .nodes
            .iter()
            .filter(|candidate| candidate.parent == node.parent && candidate.depth == node.depth)
            .collect::<Vec<_>>();
        let index = siblings
            .iter()
            .position(|candidate| candidate.id == id)
            .expect("selected node is present in its sibling list");
        let other_index = if down {
            index.checked_add(1).filter(|next| *next < siblings.len())
        } else {
            index.checked_sub(1)
        }
        .ok_or_else(|| invalid_edit("selected node is already at the requested edge"))?;
        let other = siblings[other_index];
        if other.kind == ApacheVisualNodeKind::Opaque {
            return Err(invalid_edit(
                "structured nodes cannot be moved across an opaque region",
            ));
        }
        self.require_non_sensitive_node(other)?;
        let first = if down { &node } else { other };
        let second = if down { other } else { &node };
        let first_range = self.line_extended_span(first);
        let second_range = self.line_extended_span(second);
        if first_range.end > second_range.start {
            return Err(invalid_edit("sibling source ranges overlap"));
        }
        let mut replacement = Vec::with_capacity(second_range.end - first_range.start);
        replacement.extend_from_slice(&self.source[second_range.clone()]);
        replacement.extend_from_slice(&self.source[first_range.end..second_range.start]);
        replacement.extend_from_slice(&self.source[first_range.clone()]);
        self.splice_and_reparse(first_range.start..second_range.end, &replacement)
    }

    fn line_extended_span(&self, node: &NodeRecord) -> Range<usize> {
        let mut start = node.span.start;
        let line_start = self.source[..start]
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |newline| newline + 1);
        if self.source[line_start..start]
            .iter()
            .all(|byte| matches!(byte, b' ' | b'\t' | b'\r'))
        {
            start = line_start;
        }
        let mut end = node.span.end;
        while end < self.source.len() && matches!(self.source[end], b' ' | b'\t') {
            end += 1;
        }
        if end < self.source.len() && self.source[end] == b'\r' {
            end += 1;
        }
        if end < self.source.len() && self.source[end] == b'\n' {
            end += 1;
        }
        start..end
    }

    fn splice_and_reparse(&mut self, range: Range<usize>, replacement: &[u8]) -> CoreResult<()> {
        self.splice_many_and_reparse(vec![(range, replacement.to_vec())])
    }

    fn splice_many_and_reparse(
        &mut self,
        mut replacements: Vec<(Range<usize>, Vec<u8>)>,
    ) -> CoreResult<()> {
        replacements.sort_by_key(|(range, _)| (range.start, range.end));
        let mut cursor = 0usize;
        let mut new_len = self.source.len();
        for (range, replacement) in &replacements {
            if range.start < cursor || range.start > range.end || range.end > self.source.len() {
                return Err(invalid_edit(
                    "replacement ranges overlap or are out of bounds",
                ));
            }
            new_len = new_len
                .checked_sub(range.end - range.start)
                .and_then(|length| length.checked_add(replacement.len()))
                .ok_or_else(|| invalid_edit("replacement byte count overflow"))?;
            cursor = range.end;
        }
        validate_size(new_len)?;
        let mut source = Vec::with_capacity(new_len);
        cursor = 0;
        for (range, replacement) in replacements {
            source.extend_from_slice(&self.source[cursor..range.start]);
            source.extend_from_slice(&replacement);
            cursor = range.end;
        }
        source.extend_from_slice(&self.source[cursor..]);
        let parsed = Parser::new(&source).parse().map_err(|failure| {
            CoreError::validation(
                "Apache visual edit",
                format!(
                    "would make the document structurally unsafe at byte {}",
                    failure.offset
                ),
            )
        })?;
        *self = Self::from_parsed(source, parsed);
        Ok(())
    }
}

fn parsed_contains_opaque(nodes: &[ParsedNode]) -> bool {
    nodes.iter().any(|node| {
        node.kind == ApacheVisualNodeKind::Opaque || parsed_contains_opaque(&node.children)
    })
}

fn flatten_nodes(
    parsed: &[ParsedNode],
    parent: Option<ApacheVisualNodeId>,
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
            footer_span: node.footer_span.clone(),
            name_span: node.name_span.clone(),
            arguments_span: node.arguments_span.clone(),
            close_at: node.close_at,
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
    NEXT_DOCUMENT_REVISION.fetch_add(1, Ordering::Relaxed)
}

const fn revision_node_id(revision: u64, ordinal: u64) -> ApacheVisualNodeId {
    ApacheVisualNodeId(((revision as u128) << 64) | ordinal as u128)
}

#[derive(Clone, Copy, Debug)]
struct ParseFailure {
    offset: usize,
}

#[derive(Clone, Debug)]
struct LogicalLine {
    span: Range<usize>,
    token_start: usize,
    dangling_continuation: bool,
}

#[derive(Clone, Debug)]
struct SectionTag {
    span: Range<usize>,
    name_span: Range<usize>,
    arguments_span: Option<Range<usize>>,
    closing: bool,
}

struct ParsedDirectiveLine {
    name_span: Range<usize>,
    arguments_span: Option<Range<usize>>,
    tokens: usize,
}

struct ParsedLevel {
    nodes: Vec<ParsedNode>,
    closing: Option<SectionTag>,
}

struct Parser<'a> {
    source: &'a [u8],
    cursor: usize,
    nodes: usize,
    tokens: usize,
}

impl<'a> Parser<'a> {
    fn new(source: &'a [u8]) -> Self {
        Self {
            source,
            cursor: usize::from(source.starts_with(&[0xEF, 0xBB, 0xBF])) * 3,
            nodes: 0,
            tokens: 0,
        }
    }

    fn parse(mut self) -> Result<Vec<ParsedNode>, ParseFailure> {
        if self.source.contains(&0) {
            return Err(self.failure());
        }
        let level = self.parse_level(0, None)?;
        if level.closing.is_some() || self.cursor != self.source.len() {
            return Err(self.failure());
        }
        Ok(level.nodes)
    }

    fn parse_level(
        &mut self,
        depth: usize,
        expected_close: Option<Range<usize>>,
    ) -> Result<ParsedLevel, ParseFailure> {
        if depth > MAX_APACHE_VISUAL_DEPTH {
            return Err(self.failure());
        }
        let mut output = Vec::new();
        while let Some(line) = self.next_logical_line() {
            if line.token_start == line.span.end {
                continue;
            }
            if self.source[line.token_start] == b'#' {
                self.bump_node()?;
                output.push(ParsedNode {
                    kind: ApacheVisualNodeKind::Comment,
                    span: line.token_start..line.span.end,
                    header_span: line.token_start..line.span.end,
                    footer_span: None,
                    name_span: None,
                    arguments_span: (line.token_start + 1 < line.span.end)
                        .then(|| trim_span(self.source, line.token_start + 1..line.span.end))
                        .filter(|span| !span.is_empty()),
                    close_at: None,
                    children: Vec::new(),
                });
                continue;
            }
            if self.source[line.token_start] == b'<' {
                let tag = self.parse_section_tag(&line)?;
                let argument_tokens = token_count(self.source, tag.arguments_span.clone())
                    .map_err(|offset| self.failure_at(offset))?;
                self.bump_tokens(1 + argument_tokens)?;
                if tag.closing {
                    let Some(expected) = expected_close.as_ref() else {
                        return Err(self.failure_at(tag.span.start));
                    };
                    if !self.source[expected.clone()]
                        .eq_ignore_ascii_case(&self.source[tag.name_span.clone()])
                    {
                        return Err(self.failure_at(tag.name_span.start));
                    }
                    return Ok(ParsedLevel {
                        nodes: output,
                        closing: Some(tag),
                    });
                }

                self.bump_node()?;
                if is_known_raw_section(&self.source[tag.name_span.clone()]) {
                    let close = self.consume_raw_section(&tag)?;
                    output.push(ParsedNode {
                        kind: ApacheVisualNodeKind::Opaque,
                        span: tag.span.start..close.span.end,
                        header_span: tag.span.clone(),
                        footer_span: Some(close.span),
                        name_span: Some(tag.name_span),
                        arguments_span: tag.arguments_span,
                        close_at: None,
                        children: Vec::new(),
                    });
                    continue;
                }
                let nested = self.parse_level(depth + 1, Some(tag.name_span.clone()))?;
                let close = nested
                    .closing
                    .ok_or_else(|| self.failure_at(tag.span.end))?;
                output.push(ParsedNode {
                    kind: ApacheVisualNodeKind::Section,
                    span: tag.span.start..close.span.end,
                    header_span: tag.span.clone(),
                    footer_span: Some(close.span.clone()),
                    name_span: Some(tag.name_span),
                    arguments_span: tag.arguments_span,
                    close_at: Some(close.span.start),
                    children: nested.nodes,
                });
                continue;
            }

            let parsed = self.parse_directive_line(&line);
            match parsed {
                Ok(parsed) => {
                    self.bump_tokens(parsed.tokens)?;
                    self.bump_node()?;
                    output.push(ParsedNode {
                        kind: ApacheVisualNodeKind::Directive,
                        span: line.token_start..line.span.end,
                        header_span: line.token_start..line.span.end,
                        footer_span: None,
                        name_span: Some(parsed.name_span),
                        arguments_span: parsed.arguments_span,
                        close_at: None,
                        children: Vec::new(),
                    });
                }
                Err(()) => {
                    self.bump_node()?;
                    output.push(ParsedNode {
                        kind: ApacheVisualNodeKind::Opaque,
                        span: line.token_start..line.span.end,
                        header_span: line.token_start..line.span.end,
                        footer_span: None,
                        name_span: None,
                        arguments_span: None,
                        close_at: None,
                        children: Vec::new(),
                    });
                }
            }
        }
        if expected_close.is_some() {
            Err(self.failure())
        } else {
            Ok(ParsedLevel {
                nodes: output,
                closing: None,
            })
        }
    }

    fn consume_raw_section(&mut self, opening: &SectionTag) -> Result<SectionTag, ParseFailure> {
        while let Some(line) = self.next_logical_line() {
            if let Some(close) =
                exact_raw_section_close(self.source, &line, &self.source[opening.name_span.clone()])
            {
                return Ok(close);
            }
        }
        Err(self.failure_at(opening.span.end))
    }

    fn next_logical_line(&mut self) -> Option<LogicalLine> {
        if self.cursor >= self.source.len() {
            return None;
        }
        let start = self.cursor;
        let mut content_end;
        let dangling_continuation;
        loop {
            let newline = self.source[self.cursor..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map(|relative| self.cursor + relative);
            let full_end = newline.map_or(self.source.len(), |newline| newline + 1);
            content_end = newline.unwrap_or(self.source.len());
            if content_end > self.cursor && self.source[content_end - 1] == b'\r' {
                content_end -= 1;
            }
            let continued = content_end > self.cursor && self.source[content_end - 1] == b'\\';
            self.cursor = full_end;
            if !continued {
                dangling_continuation = false;
                break;
            }
            if self.cursor >= self.source.len() {
                dangling_continuation = true;
                break;
            }
        }
        let token_start = trim_ascii_start(self.source, start, content_end);
        Some(LogicalLine {
            span: start..content_end,
            token_start,
            dangling_continuation,
        })
    }

    fn parse_section_tag(&self, line: &LogicalLine) -> Result<SectionTag, ParseFailure> {
        if line.dangling_continuation {
            return Err(self.failure_at(line.span.end));
        }
        let tag_end = find_section_end(self.source, line.token_start + 1, line.span.end)
            .map_err(|offset| self.failure_at(offset))?;
        if self.source[tag_end + 1..line.span.end]
            .iter()
            .any(|byte| !byte.is_ascii_whitespace())
        {
            return Err(self.failure_at(tag_end + 1));
        }
        let mut inner_start = line.token_start + 1;
        if inner_start >= tag_end || self.source[inner_start].is_ascii_whitespace() {
            return Err(self.failure_at(inner_start));
        }
        let inner_end = trim_ascii_end(self.source, inner_start, tag_end);
        let closing = inner_start < inner_end && self.source[inner_start] == b'/';
        if closing {
            inner_start += 1;
            if inner_start >= inner_end || self.source[inner_start].is_ascii_whitespace() {
                return Err(self.failure_at(inner_start));
            }
        }
        let mut name_end = inner_start;
        while name_end < inner_end && !self.source[name_end].is_ascii_whitespace() {
            name_end += 1;
        }
        if inner_start == name_end
            || !valid_apache_name(&self.source[inner_start..name_end])
            || contains_apache_variable(&self.source[inner_start..name_end])
            || (closing && trim_ascii_start(self.source, name_end, inner_end) != inner_end)
        {
            return Err(self.failure_at(inner_start));
        }
        let arguments_start = trim_ascii_start(self.source, name_end, inner_end);
        let arguments_end = trim_ascii_end(self.source, arguments_start, inner_end);
        let arguments_span =
            (!closing && arguments_start < arguments_end).then_some(arguments_start..arguments_end);
        if let Some(arguments) = &arguments_span {
            scan_arguments(self.source, arguments.clone())
                .map_err(|offset| self.failure_at(offset))?;
        }
        Ok(SectionTag {
            span: line.token_start..tag_end + 1,
            name_span: inner_start..name_end,
            arguments_span,
            closing,
        })
    }

    fn parse_directive_line(&self, line: &LogicalLine) -> Result<ParsedDirectiveLine, ()> {
        if line.dangling_continuation {
            return Err(());
        }
        let mut name_end = line.token_start;
        while name_end < line.span.end && !self.source[name_end].is_ascii_whitespace() {
            name_end += 1;
        }
        if name_end == line.token_start
            || !valid_apache_name(&self.source[line.token_start..name_end])
            || contains_apache_variable(&self.source[line.token_start..name_end])
        {
            return Err(());
        }
        let value_start = trim_ascii_start(self.source, name_end, line.span.end);
        let value_end = trim_ascii_end(self.source, value_start, line.span.end);
        let arguments_span = (value_start < value_end).then_some(value_start..value_end);
        let argument_tokens = token_count(self.source, arguments_span.clone()).map_err(|_| ())?;
        Ok(ParsedDirectiveLine {
            name_span: line.token_start..name_end,
            arguments_span,
            tokens: 1 + argument_tokens,
        })
    }

    fn bump_node(&mut self) -> Result<(), ParseFailure> {
        self.nodes = self.nodes.saturating_add(1);
        if self.nodes > MAX_APACHE_VISUAL_NODES {
            return Err(self.failure());
        }
        Ok(())
    }

    fn bump_tokens(&mut self, tokens: usize) -> Result<(), ParseFailure> {
        self.tokens = self.tokens.saturating_add(tokens);
        if self.tokens > MAX_APACHE_VISUAL_TOKENS {
            return Err(self.failure());
        }
        Ok(())
    }

    const fn failure(&self) -> ParseFailure {
        ParseFailure {
            offset: self.cursor,
        }
    }

    const fn failure_at(&self, offset: usize) -> ParseFailure {
        ParseFailure { offset }
    }
}

fn find_section_end(source: &[u8], start: usize, end: usize) -> Result<usize, usize> {
    let mut cursor = start;
    let mut quote = None;
    let mut in_unquoted_token = false;
    let mut candidate = None;
    while cursor < end {
        let byte = source[cursor];
        if let Some(active) = quote {
            if byte == b'\\' {
                if let Some(next) = continuation_end(source, cursor, end) {
                    cursor = next;
                    continue;
                }
                if source
                    .get(cursor + 1)
                    .is_some_and(|next| *next == active || *next == b'\\')
                {
                    cursor += 2;
                    continue;
                }
            }
            if byte == active {
                quote = None;
                in_unquoted_token = false;
            }
            cursor += 1;
            continue;
        }
        if byte == b'\\'
            && let Some(next) = continuation_end(source, cursor, end)
        {
            cursor = next;
            continue;
        }
        if byte.is_ascii_whitespace() {
            in_unquoted_token = false;
            cursor += 1;
            continue;
        }
        if !in_unquoted_token && matches!(byte, b'\'' | b'"') {
            quote = Some(byte);
            cursor += 1;
            continue;
        }
        if !in_unquoted_token {
            in_unquoted_token = true;
        }
        if byte == b'>' {
            candidate = Some(cursor);
        }
        cursor += 1;
    }
    if quote.is_none() {
        candidate.ok_or(end)
    } else {
        Err(end)
    }
}

fn token_count(source: &[u8], span: Option<Range<usize>>) -> Result<usize, usize> {
    let Some(span) = span else {
        return Ok(0);
    };
    scan_arguments(source, span)
}

fn scan_arguments(source: &[u8], span: Range<usize>) -> Result<usize, usize> {
    let mut cursor = span.start;
    let mut quote = None;
    let mut in_unquoted_token = false;
    let mut tokens = 0usize;
    while cursor < span.end {
        let byte = source[cursor];
        if let Some(active) = quote {
            if byte == b'\\' {
                if let Some(next) = continuation_end(source, cursor, span.end) {
                    cursor = next;
                    continue;
                }
                if source
                    .get(cursor + 1)
                    .is_some_and(|next| *next == active || *next == b'\\')
                {
                    cursor += 2;
                    continue;
                }
            }
            if byte == active {
                quote = None;
                in_unquoted_token = false;
            }
            cursor += 1;
            continue;
        }
        if byte == b'\\'
            && let Some(next) = continuation_end(source, cursor, span.end)
        {
            cursor = next;
            continue;
        }
        if byte.is_ascii_whitespace() {
            in_unquoted_token = false;
            cursor += 1;
            continue;
        }
        if !in_unquoted_token {
            tokens = tokens.saturating_add(1);
            if matches!(byte, b'\'' | b'"') {
                quote = Some(byte);
            } else {
                in_unquoted_token = true;
            }
        }
        cursor += 1;
    }
    if quote.is_some() {
        Err(span.end)
    } else {
        Ok(tokens)
    }
}

fn continuation_end(source: &[u8], cursor: usize, end: usize) -> Option<usize> {
    if source.get(cursor) != Some(&b'\\') {
        return None;
    }
    match source.get(cursor + 1) {
        Some(b'\n') if cursor + 2 <= end => Some(cursor + 2),
        Some(b'\r') if source.get(cursor + 2) == Some(&b'\n') && cursor + 3 <= end => {
            Some(cursor + 3)
        }
        _ => None,
    }
}

fn valid_apache_name(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes.iter().all(|byte| {
            byte.is_ascii_graphic()
                && !matches!(byte, b'<' | b'>' | b'/' | b'#' | b'\'' | b'"' | b'\\')
        })
}

fn contains_apache_variable(bytes: &[u8]) -> bool {
    bytes
        .windows(2)
        .enumerate()
        .any(|(index, pair)| pair == b"${" && bytes[index + 2..].contains(&b'}'))
}

fn is_known_raw_section(name: &[u8]) -> bool {
    KNOWN_RAW_SECTIONS
        .iter()
        .any(|known| name.eq_ignore_ascii_case(known))
}

fn exact_raw_section_close(
    source: &[u8],
    line: &LogicalLine,
    expected_name: &[u8],
) -> Option<SectionTag> {
    if line.dangling_continuation || line.token_start + 3 > line.span.end {
        return None;
    }
    let start = line.token_start;
    if !source[start..].starts_with(b"</") {
        return None;
    }
    let name_start = start + 2;
    let name_end = name_start.checked_add(expected_name.len())?;
    if name_end >= line.span.end
        || !source[name_start..name_end].eq_ignore_ascii_case(expected_name)
        || source[name_end] != b'>'
        || source[name_end + 1..line.span.end]
            .iter()
            .any(|byte| !byte.is_ascii_whitespace())
    {
        return None;
    }
    Some(SectionTag {
        span: start..name_end + 1,
        name_span: name_start..name_end,
        arguments_span: None,
        closing: true,
    })
}

struct SectionFragment {
    complete: Vec<u8>,
    header: Vec<u8>,
    footer: Vec<u8>,
}

fn directive_fragment(name: &str, arguments: &str) -> CoreResult<Vec<u8>> {
    let name = trim_apache_whitespace(name);
    let arguments = trim_apache_whitespace(arguments);
    validate_edit_lengths(name, arguments)?;
    let mut fragment = Vec::with_capacity(name.len() + arguments.len() + 1);
    fragment.extend_from_slice(name.as_bytes());
    if !arguments.is_empty() {
        fragment.push(b' ');
        fragment.extend_from_slice(arguments.as_bytes());
    }
    if fragment.len() > MAX_APACHE_VISUAL_EDIT_BYTES {
        return Err(invalid_edit(
            "complete directive replacement exceeds the visual edit byte limit",
        ));
    }
    let parsed = Parser::new(&fragment).parse().map_err(|failure| {
        CoreError::validation(
            "Apache visual directive",
            format!(
                "must describe exactly one safe logical directive; invalid structure at byte {}",
                failure.offset
            ),
        )
    })?;
    let valid = parsed.len() == 1
        && parsed[0].kind == ApacheVisualNodeKind::Directive
        && parsed[0].children.is_empty()
        && parsed[0].name_span.as_ref().is_some_and(|span| {
            std::str::from_utf8(&fragment[span.clone()])
                .is_ok_and(|parsed_name| parsed_name == name)
        });
    if !valid {
        return Err(invalid_edit(
            "directive input would create more than one node or change its kind",
        ));
    }
    Ok(fragment)
}

fn section_fragment(name: &str, arguments: &str) -> CoreResult<SectionFragment> {
    let name = trim_apache_whitespace(name);
    let arguments = trim_apache_whitespace(arguments);
    validate_edit_lengths(name, arguments)?;
    let mut header = Vec::with_capacity(name.len() + arguments.len() + 3);
    header.push(b'<');
    header.extend_from_slice(name.as_bytes());
    if !arguments.is_empty() {
        header.push(b' ');
        header.extend_from_slice(arguments.as_bytes());
    }
    header.push(b'>');
    let mut footer = Vec::with_capacity(name.len() + 3);
    footer.extend_from_slice(b"</");
    footer.extend_from_slice(name.as_bytes());
    footer.push(b'>');
    let mut complete = Vec::with_capacity(header.len() + footer.len() + 1);
    complete.extend_from_slice(&header);
    complete.push(b'\n');
    complete.extend_from_slice(&footer);
    if complete.len() > MAX_APACHE_VISUAL_EDIT_BYTES {
        return Err(invalid_edit(
            "complete paired section replacement exceeds the visual edit byte limit",
        ));
    }

    let parsed = Parser::new(&complete).parse().map_err(|failure| {
        CoreError::validation(
            "Apache visual section",
            format!(
                "must describe exactly one safe paired section; invalid structure at byte {}",
                failure.offset
            ),
        )
    })?;
    let valid = parsed.len() == 1
        && parsed[0].kind == ApacheVisualNodeKind::Section
        && parsed[0].children.is_empty()
        && parsed[0].name_span.as_ref().is_some_and(|span| {
            std::str::from_utf8(&complete[span.clone()])
                .is_ok_and(|parsed_name| parsed_name == name)
        });
    if !valid {
        return Err(invalid_edit(
            "section input would create more than one node or change its kind",
        ));
    }
    Ok(SectionFragment {
        complete,
        header,
        footer,
    })
}

fn validate_edit_lengths(name: &str, arguments: &str) -> CoreResult<()> {
    if name.is_empty()
        || name.len() > MAX_APACHE_VISUAL_EDIT_BYTES
        || arguments.len() > MAX_APACHE_VISUAL_EDIT_BYTES
        || name.contains('\0')
        || arguments.contains('\0')
    {
        return Err(invalid_edit(
            "name and arguments must be non-empty/bounded and contain no NUL",
        ));
    }
    let combined = name
        .len()
        .checked_add(arguments.len())
        .and_then(|bytes| bytes.checked_add(usize::from(!arguments.is_empty())))
        .ok_or_else(|| invalid_edit("combined edit byte count overflow"))?;
    if combined > MAX_APACHE_VISUAL_EDIT_BYTES {
        return Err(invalid_edit(
            "combined name and arguments exceed the visual edit byte limit",
        ));
    }
    Ok(())
}

fn validate_comment(text: &str) -> CoreResult<()> {
    let replacement_bytes = text.len().saturating_add(2);
    if replacement_bytes > MAX_APACHE_VISUAL_EDIT_BYTES || text.contains(['\0', '\r', '\n']) {
        return Err(invalid_edit(
            "comment must be one bounded physical line without NUL",
        ));
    }
    Ok(())
}

fn append_indented_fragment(output: &mut Vec<u8>, fragment: &[u8], depth: usize, _newline: &[u8]) {
    let indent = depth.saturating_mul(4);
    output.extend(std::iter::repeat_n(b' ', indent));
    for (index, byte) in fragment.iter().copied().enumerate() {
        output.push(byte);
        if byte == b'\n' && index + 1 < fragment.len() {
            output.extend(std::iter::repeat_n(b' ', indent));
        }
    }
}

fn trim_span(source: &[u8], mut span: Range<usize>) -> Range<usize> {
    while span.start < span.end && source.get(span.start).is_some_and(u8::is_ascii_whitespace) {
        span.start += 1;
    }
    while span.start < span.end
        && source
            .get(span.end - 1)
            .is_some_and(u8::is_ascii_whitespace)
    {
        span.end -= 1;
    }
    span
}

fn trim_ascii_start(source: &[u8], mut start: usize, end: usize) -> usize {
    while start < end && source[start].is_ascii_whitespace() {
        start += 1;
    }
    start
}

fn trim_ascii_end(source: &[u8], start: usize, mut end: usize) -> usize {
    while start < end && source[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    end
}

fn trim_apache_whitespace(value: &str) -> &str {
    value.trim_matches([' ', '\t', '\r', '\n'])
}

fn bounded_field(bytes: &[u8]) -> String {
    let bounded = &bytes[..bytes.len().min(MAX_APACHE_VISUAL_EDIT_BYTES)];
    String::from_utf8_lossy(bounded).into_owned()
}

fn bounded_preview(bytes: &[u8]) -> (String, bool) {
    let truncated = bytes.len() > MAX_ROW_TEXT_BYTES;
    let bounded = &bytes[..bytes.len().min(MAX_ROW_TEXT_BYTES)];
    let preview = String::from_utf8_lossy(bounded)
        .split_ascii_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    (preview, truncated)
}

fn preferred_newline(source: &[u8]) -> &'static [u8] {
    if source.windows(2).any(|window| window == b"\r\n") {
        b"\r\n"
    } else {
        b"\n"
    }
}

fn contains_sensitive_marker(bytes: &[u8]) -> bool {
    const MARKERS: [&[u8]; 15] = [
        b"authorization",
        b"password",
        b"passwd",
        b"passphrase",
        b"secret",
        b"credential",
        b"api_key",
        b"apikey",
        b"bearer ",
        b"private_key",
        b"private key",
        b"access_token",
        b"sslpassphrasedialog",
        b"dbdparams",
        b"cookie",
    ];
    MARKERS.iter().any(|marker| {
        bytes
            .windows(marker.len())
            .any(|window| window.eq_ignore_ascii_case(marker))
    }) || contains_url_userinfo(bytes)
}

fn contains_url_userinfo(bytes: &[u8]) -> bool {
    bytes.windows(3).enumerate().any(|(index, window)| {
        if window != b"://" {
            return false;
        }
        bytes[index + 3..]
            .iter()
            .take_while(|byte| !byte.is_ascii_whitespace() && !matches!(**byte, b'<' | b'>'))
            .any(|byte| *byte == b'@')
    })
}

fn validate_size(bytes: usize) -> CoreResult<()> {
    if bytes > MAX_APACHE_VISUAL_BYTES {
        return Err(CoreError::validation(
            "Apache visual configuration",
            format!("must contain at most {MAX_APACHE_VISUAL_BYTES} bytes"),
        ));
    }
    Ok(())
}

fn validate_import_path(path: &Path) -> CoreResult<()> {
    if !path.is_absolute()
        || has_lexical_navigation_component(path)
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        || !path.is_file()
    {
        return Err(CoreError::validation(
            "Apache configuration import path",
            "must be an existing absolute file selected by the native dialog",
        ));
    }
    Ok(())
}

fn validate_destination(path: &Path) -> CoreResult<()> {
    let valid_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            let extension = Path::new(name)
                .extension()
                .and_then(|extension| extension.to_str());
            name == ".htaccess"
                || extension.is_some_and(|extension| {
                    extension.eq_ignore_ascii_case("conf") || extension.eq_ignore_ascii_case("load")
                })
                || (!name.starts_with('.') && extension.is_none())
        });
    if !path.is_absolute()
        || has_lexical_navigation_component(path)
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        || !valid_name
        || !path.parent().is_some_and(Path::is_dir)
    {
        return Err(CoreError::validation(
            "visual Apache configuration destination",
            "must be a new absolute .conf, .load, .htaccess, or extensionless include path in an existing directory without traversal components",
        ));
    }
    Ok(())
}

fn has_lexical_navigation_component(path: &Path) -> bool {
    // `Path::components` normalizes interior `.` components away. Inspect the
    // original spelling too so a dialog/import boundary never accepts a path
    // that reached its target through explicit navigation syntax.
    path.as_os_str()
        .to_string_lossy()
        .split(std::path::is_separator)
        .any(|component| matches!(component, "." | ".."))
}

fn invalid_edit(message: &'static str) -> CoreError {
    CoreError::validation("Apache visual edit", message)
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMPREHENSIVE: &str = r#"# main server
Define SITE_ROOT "/srv/www"
Listen 80
Header set X-Inline value # this is an argument, not an Apache comment
<IfModule ssl_module>
    Listen 443
</IfModule>
<IfDefine COMPETITION>
    LogLevel debug
</IfDefine>
<IfVersion >= 2.4>
    Protocols h2 http/1.1
</IfVersion>
<VirtualHost *:80 [::]:80>
    ServerName example.test
    ServerAlias *.example.test
    <Directory "${SITE_ROOT}">
        <FilesMatch "\.(?:php|phtml)$">
            Require all denied
        </FilesMatch>
        <If "req('Host') =~ /example\.test$/">
            Require all granted
        </If>
    </Directory>
    <LocationMatch "^/api(?:/|$)">
        ProxyPass "http://127.0.0.1:8080/"
    </LocationMatch>
    <Proxy "balancer://backend">
        BalancerMember "http://127.0.0.1:8080"
    </Proxy>
</VirtualHost>
<ThirdPartySection arbitrary "a > b">
    ThirdPartyDirective unknown tokens
</thirdpartysection>
IncludeOptional "conf.d/*.conf"
"#;

    #[test]
    fn comprehensive_unknown_and_nested_configuration_is_byte_exact() {
        let document = ApacheVisualDocument::parse(COMPREHENSIVE).unwrap();

        assert!(document.is_structured());
        assert!(!document.has_opaque_regions());
        assert_eq!(document.raw_bytes(), COMPREHENSIVE.as_bytes());
        assert_eq!(document.output().bytes(), COMPREHENSIVE.as_bytes());
        let rows = document.rows();
        for section in [
            "IfModule",
            "IfDefine",
            "IfVersion",
            "VirtualHost",
            "Directory",
            "FilesMatch",
            "If",
            "LocationMatch",
            "Proxy",
            "ThirdPartySection",
        ] {
            assert!(rows.iter().any(|row| {
                row.kind() == ApacheVisualNodeKind::Section && row.name() == Some(section)
            }));
        }
        assert!(rows.iter().any(|row| {
            row.name() == Some("ThirdPartyDirective") && row.arguments() == Some("unknown tokens")
        }));
        let header = rows
            .iter()
            .find(|row| row.name() == Some("Header"))
            .unwrap();
        assert!(
            header
                .arguments()
                .unwrap()
                .contains("# this is an argument")
        );
        assert_eq!(
            rows.iter()
                .filter(|row| row.kind() == ApacheVisualNodeKind::Comment)
                .count(),
            1
        );
    }

    #[test]
    fn logical_lines_and_continued_comments_follow_apache_rules() {
        let bytes = b"LogFormat \"%h %l \\\r\n%u %t\" combined\r\n# continued comment \\\r\nthis is still comment text\r\nHeader set X-Test value #not-an-inline-comment\r\n";
        let document = ApacheVisualDocument::parse_bytes(bytes.to_vec()).unwrap();

        assert!(document.is_structured());
        assert_eq!(document.output().bytes(), bytes);
        let rows = document.rows();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].name(), Some("LogFormat"));
        assert!(rows[0].arguments().unwrap().contains("\\\r\n"));
        assert_eq!(rows[1].kind(), ApacheVisualNodeKind::Comment);
        assert!(rows[1].preview().contains("this is still comment text"));
        assert_eq!(rows[2].name(), Some("Header"));
        assert!(
            rows[2]
                .arguments()
                .unwrap()
                .contains("#not-an-inline-comment")
        );

        let not_continued =
            ApacheVisualDocument::parse("Header set X-Test value\\   \nNext yes\n").unwrap();
        assert!(not_continued.is_structured());
        assert_eq!(not_continued.rows().len(), 2);
    }

    #[test]
    fn only_a_token_initial_quote_quotes_and_adjacent_quotes_count_separately() {
        let adjacent = br#""bar""baz""#;
        assert_eq!(token_count(adjacent, Some(0..adjacent.len())).unwrap(), 2);

        let mid_token = br#"foo"bar baz""#;
        assert_eq!(token_count(mid_token, Some(0..mid_token.len())).unwrap(), 2);

        let exact = format!("Directive {}", "\"x\"".repeat(MAX_APACHE_VISUAL_TOKENS - 1));
        assert!(ApacheVisualDocument::parse(&exact).unwrap().is_structured());

        let over = format!("Directive {}", "\"x\"".repeat(MAX_APACHE_VISUAL_TOKENS));
        let document = ApacheVisualDocument::parse(&over).unwrap();
        assert!(!document.is_structured());
        assert_eq!(document.output().bytes(), over.as_bytes());
    }

    #[test]
    fn bom_crlf_and_missing_terminal_newline_round_trip() {
        let bytes =
            b"\xEF\xBB\xBF<VirtualHost *:80>\r\n  ServerName example.test\r\n</virtualhost>"
                .to_vec();
        let document = ApacheVisualDocument::parse_bytes(bytes.clone()).unwrap();

        assert!(document.is_structured());
        assert_eq!(document.rows()[0].kind(), ApacheVisualNodeKind::Section);
        assert_eq!(document.output().bytes(), bytes);
    }

    #[test]
    fn known_embedded_language_sections_are_atomic_opaque_regions() {
        let embedded = br#"<Perl>
$Foo = "bar";
print $Foo;
</Perl>
Listen 80
"#
        .to_vec();
        let document = ApacheVisualDocument::parse_bytes(embedded.clone()).unwrap();
        assert!(document.is_structured());
        assert!(document.has_opaque_regions());
        assert_eq!(document.rows()[0].kind(), ApacheVisualNodeKind::Opaque);
        assert_eq!(document.rows()[0].name(), Some("Perl"));
        assert_eq!(document.rows()[1].name(), Some("Listen"));
        assert_eq!(document.output().bytes(), embedded);

        let unknown = ApacheVisualDocument::parse(
            "<ThirdPartyLanguage>\n$Foo = \"bar\";\n</ThirdPartyLanguage>\n",
        )
        .unwrap();
        assert!(unknown.is_structured());
        assert!(!unknown.has_opaque_regions());
        assert_eq!(unknown.rows()[0].kind(), ApacheVisualNodeKind::Section);
        assert_eq!(unknown.rows()[1].kind(), ApacheVisualNodeKind::Directive);
    }

    #[test]
    fn unbalanced_or_unsafe_sections_fall_back_byte_exact() {
        for malformed in [
            b"<VirtualHost *:80>\nServerName x\n".to_vec(),
            b"</Directory>\n".to_vec(),
            b"<Directory /x> trailing\n</Directory>\n".to_vec(),
            b"<Directory /x> # inline comments are not section comments\n</Directory>\n".to_vec(),
            vec![b'#', b' ', 0xFF, b'\n'],
            b"Listen 80\0tail".to_vec(),
        ] {
            let document = ApacheVisualDocument::parse_bytes(malformed.clone()).unwrap();
            assert!(!document.is_structured());
            assert_eq!(document.output().bytes(), malformed);
        }
    }

    #[test]
    fn section_delimiters_reject_whitespace_and_variable_names_fail_closed() {
        for malformed in [
            b"< Directory>\n</Directory>\n".to_vec(),
            b"<Directory>\n</ Directory>\n".to_vec(),
            b"<${SECTION} *:80>\nListen 80\n</${SECTION}>\n".to_vec(),
        ] {
            let document = ApacheVisualDocument::parse_bytes(malformed.clone()).unwrap();
            assert!(!document.is_structured());
            assert_eq!(document.output().bytes(), malformed);
        }

        let source = b"${OPEN} *:80\nListen 80\n";
        let mut document = ApacheVisualDocument::parse_bytes(source.to_vec()).unwrap();
        assert!(document.is_structured());
        assert!(document.has_opaque_regions());
        let rows = document.rows();
        assert_eq!(rows[0].kind(), ApacheVisualNodeKind::Opaque);
        assert_eq!(rows[1].name(), Some("Listen"));
        assert!(document.remove(rows[0].id()).is_err());
        assert!(document.move_down(rows[0].id()).is_err());
        assert!(document.move_up(rows[1].id()).is_err());
        assert_eq!(document.output().bytes(), source);
    }

    #[test]
    fn invalid_directive_quotes_are_local_opaque_regions() {
        let source = b"<VirtualHost *:80>\n    Broken \"unterminated\n    ServerName example.test\n</VirtualHost>\n";
        let document = ApacheVisualDocument::parse_bytes(source.to_vec()).unwrap();

        assert!(document.is_structured());
        assert!(document.has_opaque_regions());
        assert_eq!(document.output().bytes(), source);
        assert!(
            document
                .rows()
                .iter()
                .any(|row| row.kind() == ApacheVisualNodeKind::Opaque && row.depth() == 1)
        );
        assert!(
            document
                .rows()
                .iter()
                .any(|row| row.name() == Some("ServerName"))
        );
    }

    #[test]
    fn add_update_remove_and_move_preserve_sections_as_atomic_subtrees() {
        let mut document = ApacheVisualDocument::parse(
            "<VirtualHost *:80>\n    ServerName one.test\n</VirtualHost>\n\n<VirtualHost *:81>\n    ServerName two.test\n</VirtualHost>\n",
        )
        .unwrap();
        let first = document.rows()[0].id();
        document.move_down(first).unwrap();
        assert!(
            document
                .output()
                .text()
                .unwrap()
                .starts_with("<VirtualHost *:81>\n    ServerName two.test\n</VirtualHost>")
        );

        let first = document
            .rows()
            .into_iter()
            .find(|row| row.kind() == ApacheVisualNodeKind::Section)
            .unwrap()
            .id();
        document
            .add_section(Some(first), "Directory", "\"/srv/www\"")
            .unwrap();
        let directory = document
            .rows()
            .into_iter()
            .find(|row| row.name() == Some("Directory"))
            .unwrap()
            .id();
        document
            .add_directive(Some(directory), "Require", "all granted")
            .unwrap();
        let directory = document
            .rows()
            .into_iter()
            .find(|row| row.name() == Some("Directory"))
            .unwrap()
            .id();
        document
            .update_section(directory, "Location", "\"/public\"")
            .unwrap();
        let output = document.output();
        let rendered = output.text().unwrap();
        assert!(rendered.contains("<Location \"/public\">"));
        assert!(rendered.contains("</Location>"));
        assert!(!rendered.contains("</Directory>"));
        assert!(rendered.contains("Require all granted"));

        let require = document
            .rows()
            .into_iter()
            .find(|row| row.name() == Some("Require"))
            .unwrap()
            .id();
        document
            .update_directive(require, "Require", "all denied")
            .unwrap();
        let location = document
            .rows()
            .into_iter()
            .find(|row| row.name() == Some("Location"))
            .unwrap()
            .id();
        document.remove(location).unwrap();
        assert!(!document.output().text().unwrap().contains("/public"));
        assert!(document.is_structured());
    }

    #[test]
    fn field_inputs_cannot_inject_sibling_nodes() {
        let mut document =
            ApacheVisualDocument::parse("<VirtualHost *:80>\n</VirtualHost>\n").unwrap();
        let parent = document.rows()[0].id();
        for (name, arguments) in [
            ("Listen\nInclude", "/etc/shadow"),
            ("Listen Extra", "80"),
            ("Listen", "80\nInclude /etc/shadow"),
            ("Listen", "80\n# hidden sibling"),
            ("Listen", "80\n<VirtualHost *:81>"),
            ("Listen", "80\0Include /etc/shadow"),
        ] {
            assert!(
                document
                    .add_directive(Some(parent), name, arguments)
                    .is_err()
            );
        }
        for (name, arguments) in [
            ("Directory\nVirtualHost", "\"/srv\""),
            ("Directory", "\"/srv\">\n</Directory>\nInclude /etc/shadow"),
            ("Directory", "\"unterminated"),
        ] {
            assert!(document.add_section(Some(parent), name, arguments).is_err());
        }
        assert!(
            document
                .add_comment(Some(parent), "x\nInclude /etc/shadow")
                .is_err()
        );
        assert_eq!(
            document.output().text().unwrap(),
            "<VirtualHost *:80>\n</VirtualHost>\n"
        );

        // A valid Apache continuation is still one logical directive, not a
        // structural injection, so it is accepted as opaque directive syntax.
        document
            .add_directive(Some(parent), "Header", "set X-Test one \\\ntwo")
            .unwrap();
        assert_eq!(
            document
                .rows()
                .iter()
                .filter(|row| row.name() == Some("Header"))
                .count(),
            1
        );
    }

    #[test]
    fn complete_replacement_fragments_share_one_edit_byte_limit() {
        let exact_directive_arguments = "x".repeat(MAX_APACHE_VISUAL_EDIT_BYTES - 2);
        assert_eq!(
            directive_fragment("D", &exact_directive_arguments)
                .unwrap()
                .len(),
            MAX_APACHE_VISUAL_EDIT_BYTES
        );
        assert!(directive_fragment("D", &"x".repeat(MAX_APACHE_VISUAL_EDIT_BYTES - 1)).is_err());

        let exact_section_name = "S".repeat((MAX_APACHE_VISUAL_EDIT_BYTES - 6) / 2);
        assert_eq!(
            section_fragment(&exact_section_name, "")
                .unwrap()
                .complete
                .len(),
            MAX_APACHE_VISUAL_EDIT_BYTES
        );
        assert!(
            section_fragment(&"S".repeat((MAX_APACHE_VISUAL_EDIT_BYTES - 6) / 2 + 1), "").is_err()
        );

        assert!(validate_comment(&"x".repeat(MAX_APACHE_VISUAL_EDIT_BYTES - 2)).is_ok());
        assert!(validate_comment(&"x".repeat(MAX_APACHE_VISUAL_EDIT_BYTES - 1)).is_err());
    }

    #[test]
    fn stale_node_ids_fail_closed_after_mutation() {
        let mut document = ApacheVisualDocument::parse("Listen 80\nServerName one.test\n").unwrap();
        let old = document.rows()[0].id();
        document.remove(old).unwrap();
        assert!(document.update_directive(old, "Listen", "443").is_err());
        assert_eq!(document.output().text().unwrap(), "ServerName one.test\n");
    }

    #[test]
    fn sensitive_values_are_redacted_from_rows_and_debug() {
        let secret =
            "ProxyPass / https://user:secret@example.test/\nDBDParams \"password=top-secret\"\n";
        let document = ApacheVisualDocument::parse(secret).unwrap();
        let output = document.output();
        let rows = document.rows();

        assert!(document.contains_sensitive_values());
        assert!(rows.iter().all(ApacheVisualRow::sensitive));
        assert!(rows.iter().all(|row| !row.editable()));
        assert!(rows.iter().all(|row| row.arguments().is_none()));
        assert!(rows.iter().all(|row| !row.preview().contains("top-secret")));
        assert!(!format!("{document:?}").contains("top-secret"));
        assert!(!format!("{output:?}").contains("top-secret"));
        assert!(!format!("{:?}", rows[0]).contains("top-secret"));
        assert_eq!(output.bytes(), secret.as_bytes());
    }

    #[test]
    fn sensitive_nodes_reject_string_updates_removal_movement_and_child_insertion() {
        let source = "Listen 80\nDBDParams \"password=top-secret\"\nServerName one.test\n# password top-secret\n";
        let mut document = ApacheVisualDocument::parse(source).unwrap();
        let rows = document.rows();
        let listen = rows[0].id();
        let dbd = rows[1].id();
        let server_name = rows[2].id();
        let comment = rows[3].id();

        assert!(document.update_directive(dbd, "DBDParams", "safe").is_err());
        assert!(document.update_statement(dbd, "DBDParams", "safe").is_err());
        assert!(document.remove(dbd).is_err());
        assert!(document.move_down(listen).is_err());
        assert!(document.move_up(server_name).is_err());
        assert!(document.update_comment(comment, "redacted").is_err());
        assert_eq!(document.output().bytes(), source.as_bytes());

        let section_source =
            "<VirtualHost *:80>\n    DBDParams \"password=top-secret\"\n</VirtualHost>\n";
        let mut section = ApacheVisualDocument::parse(section_source).unwrap();
        let section_id = section.rows()[0].id();
        assert!(
            section
                .update_section(section_id, "VirtualHost", "*:443")
                .is_err()
        );
        assert!(section.remove(section_id).is_err());
        assert!(
            section
                .add_directive(Some(section_id), "ServerName", "safe.test")
                .is_err()
        );
        assert_eq!(section.output().bytes(), section_source.as_bytes());
    }

    #[test]
    fn node_token_depth_and_byte_limits_fail_to_lossless_opaque() {
        let exact_nodes = "Directive\n".repeat(MAX_APACHE_VISUAL_NODES);
        let document = ApacheVisualDocument::parse(&exact_nodes).unwrap();
        assert!(document.is_structured());
        assert_eq!(document.rows().len(), MAX_APACHE_VISUAL_NODES);

        let over_nodes = "Directive\n".repeat(MAX_APACHE_VISUAL_NODES + 1);
        let document = ApacheVisualDocument::parse(&over_nodes).unwrap();
        assert!(!document.is_structured());
        assert_eq!(document.output().bytes(), over_nodes.as_bytes());

        let exact_tokens = format!("Directive {}", "x ".repeat(MAX_APACHE_VISUAL_TOKENS - 1));
        let document = ApacheVisualDocument::parse(&exact_tokens).unwrap();
        assert!(document.is_structured());

        let over_tokens = format!("Directive {}", "x ".repeat(MAX_APACHE_VISUAL_TOKENS));
        let document = ApacheVisualDocument::parse(&over_tokens).unwrap();
        assert!(!document.is_structured());
        assert_eq!(document.output().bytes(), over_tokens.as_bytes());

        let exact_depth = format!(
            "{}Leaf yes\n{}",
            "<Section>\n".repeat(MAX_APACHE_VISUAL_DEPTH),
            "</Section>\n".repeat(MAX_APACHE_VISUAL_DEPTH)
        );
        assert!(
            ApacheVisualDocument::parse(&exact_depth)
                .unwrap()
                .is_structured()
        );
        let over_depth = format!(
            "{}Leaf yes\n{}",
            "<Section>\n".repeat(MAX_APACHE_VISUAL_DEPTH + 1),
            "</Section>\n".repeat(MAX_APACHE_VISUAL_DEPTH + 1)
        );
        let document = ApacheVisualDocument::parse(&over_depth).unwrap();
        assert!(!document.is_structured());
        assert_eq!(document.output().bytes(), over_depth.as_bytes());

        let exact = ApacheVisualDocument::parse_bytes(vec![b' '; MAX_APACHE_VISUAL_BYTES]).unwrap();
        assert!(exact.is_structured());
        let error =
            ApacheVisualDocument::parse_bytes(vec![b'x'; MAX_APACHE_VISUAL_BYTES + 1]).unwrap_err();
        assert!(!error.to_string().contains("xxxx"));
    }

    #[test]
    fn output_uses_exclusive_create_for_supported_apache_include_names() {
        let directory =
            std::env::temp_dir().join(format!("lovelyres-apache-visual-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let output = ApacheVisualDocument::parse("Listen 80\n").unwrap().output();
        let _: Zeroizing<String> = output.text_lossy();
        let conf = directory.join("httpd.conf");
        output.write_new(&conf).unwrap();
        assert_eq!(fs::read(&conf).unwrap(), output.bytes());
        assert!(output.write_new(&conf).is_err());
        let htaccess = directory.join(".htaccess");
        output.write_new(&htaccess).unwrap();
        let load = directory.join("security.load");
        output.write_new(&load).unwrap();
        let extensionless = directory.join("ports");
        output.write_new(&extensionless).unwrap();
        assert!(!directory.join("invalid.txt").is_file());
        assert!(output.write_new(&directory.join("invalid.txt")).is_err());
        assert!(output.write_new(&directory.join(".env")).is_err());
        fs::remove_file(conf).unwrap();
        fs::remove_file(htaccess).unwrap();
        fs::remove_file(load).unwrap();
        fs::remove_file(extensionless).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn local_import_rejects_explicit_current_and_parent_navigation() {
        let directory =
            std::env::temp_dir().join(format!("lovelyres-apache-import-{}", uuid::Uuid::new_v4()));
        let child = directory.join("child");
        fs::create_dir_all(&child).unwrap();
        let file = directory.join("httpd.conf");
        fs::write(&file, b"Listen 80\n").unwrap();

        assert!(
            ApacheVisualDocument::read_local(&file)
                .unwrap()
                .is_structured()
        );
        assert!(ApacheVisualDocument::read_local(&directory.join(".").join("httpd.conf")).is_err());
        assert!(ApacheVisualDocument::read_local(&child.join("..").join("httpd.conf")).is_err());

        fs::remove_file(file).unwrap();
        fs::remove_dir(child).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn checked_in_competition_skeleton_remains_structured() {
        let document = ApacheVisualDocument::competition_skeleton().unwrap();
        assert!(document.is_structured());
        assert!(!document.has_opaque_regions());
        assert!(
            document
                .rows()
                .iter()
                .any(|row| row.name() == Some("VirtualHost"))
        );
        assert!(
            document
                .rows()
                .iter()
                .any(|row| row.name() == Some("IncludeOptional"))
        );
    }
}
