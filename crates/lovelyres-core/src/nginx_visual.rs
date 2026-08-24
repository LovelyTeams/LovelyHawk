//! Lossless, bounded Nginx document model for the native visual editor.
//!
//! Nginx modules can register new directives and even custom block grammars.
//! This model therefore describes syntax, not a closed directive catalogue.
//! Well-formed Nginx statements become visual nodes; bytes that cannot be
//! interpreted safely remain one opaque node and are still preserved exactly.

use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    ops::Range,
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{CoreError, CoreResult, nginx_config::GeneratedNginxConfig};
use zeroize::Zeroizing;

pub const MAX_NGINX_VISUAL_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_NGINX_VISUAL_NODES: usize = 65_536;
pub const MAX_NGINX_VISUAL_DEPTH: usize = 128;
pub const MAX_NGINX_VISUAL_EDIT_BYTES: usize = 256 * 1024;
const MAX_NGINX_VISUAL_TOKENS: usize = 262_144;

const SUGGESTED_FILE_NAME: &str = "nginx-visual.conf";
const MAX_ROW_TEXT_BYTES: usize = 512;
static NEXT_DOCUMENT_REVISION: AtomicU64 = AtomicU64::new(1);

const COMPETITION_SKELETON: &str = r#"# LovelyRes 应急响应比赛 Nginx 全面编辑骨架
# 保存前请按目标机 `nginx -V` 的模块能力删改，并运行真实的 `nginx -t`。
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /run/nginx.pid;

events {
    worker_connections 4096;
    multi_accept on;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" "$http_user_agent"';
    access_log /var/log/nginx/access.log main;
    sendfile on;
    keepalive_timeout 65;
    server_tokens off;

    map $http_upgrade $connection_upgrade {
        default upgrade;
        '' close;
    }

    upstream app_backend {
        server 127.0.0.1:8080;
        keepalive 32;
    }

    server {
        listen 80 default_server;
        server_name _;
        root /var/www/html;

        location = /healthz {
            access_log off;
            return 200 "ok\n";
        }

        location / {
            proxy_pass http://app_backend;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
        }
    }
}

# stream/mail 是可选编译模块；下面的块用于比赛现场可视化起点。
stream {
    upstream tcp_backend { server 127.0.0.1:9000; }
    server { listen 9001; proxy_pass tcp_backend; }
}

mail {
    server { listen 143; protocol imap; }
}
"#;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
/// A lease-like identifier for the current parsed revision.
///
/// Structural edits reparse the document, so callers must discard selected
/// identifiers after any successful mutation.
pub struct NginxVisualNodeId(u128);

impl NginxVisualNodeId {
    pub const fn get(self) -> u128 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NginxVisualNodeKind {
    Directive,
    Block,
    Comment,
    Opaque,
}

impl NginxVisualNodeKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Directive => "语句",
            Self::Block => "块",
            Self::Comment => "注释",
            Self::Opaque => "原文",
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct NginxVisualRow {
    id: NginxVisualNodeId,
    parent: Option<NginxVisualNodeId>,
    depth: usize,
    kind: NginxVisualNodeKind,
    name: Option<Zeroizing<String>>,
    arguments: Option<Zeroizing<String>>,
    preview: Zeroizing<String>,
    child_count: usize,
    truncated: bool,
    editable: bool,
    sensitive: bool,
}

impl fmt::Debug for NginxVisualRow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NginxVisualRow")
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

impl NginxVisualRow {
    pub const fn id(&self) -> NginxVisualNodeId {
        self.id
    }

    pub const fn parent(&self) -> Option<NginxVisualNodeId> {
        self.parent
    }

    pub const fn depth(&self) -> usize {
        self.depth
    }

    pub const fn kind(&self) -> NginxVisualNodeKind {
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
pub struct NginxVisualOutput {
    bytes: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for NginxVisualOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NginxVisualOutput")
            .field("bytes", &self.bytes.len())
            .field("utf8", &std::str::from_utf8(&self.bytes).is_ok())
            .finish()
    }
}

impl NginxVisualOutput {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn text(&self) -> CoreResult<&str> {
        std::str::from_utf8(&self.bytes).map_err(|_| {
            CoreError::validation(
                "Nginx visual configuration",
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

    /// Write the complete byte-preserving document to a new native-dialog path.
    pub fn write_new(&self, destination: &Path) -> CoreResult<PathBuf> {
        validate_destination(destination)?;
        validate_size(self.bytes.len())?;

        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(destination)
            .map_err(|source| {
                CoreError::io("create visual Nginx configuration", destination, source)
            })?;
        let result = (|| {
            file.write_all(&self.bytes).map_err(|source| {
                CoreError::io("write visual Nginx configuration", destination, source)
            })?;
            file.flush().map_err(|source| {
                CoreError::io("flush visual Nginx configuration", destination, source)
            })?;
            file.sync_all().map_err(|source| {
                CoreError::io("sync visual Nginx configuration", destination, source)
            })
        })();
        drop(file);
        if let Err(error) = result {
            if let Err(cleanup_error) = fs::remove_file(destination) {
                tracing::error!(error = %cleanup_error, "failed to remove partial visual Nginx configuration");
            }
            return Err(error);
        }
        Ok(destination.to_path_buf())
    }
}

#[derive(Clone)]
pub struct NginxVisualDocument {
    source: Zeroizing<Vec<u8>>,
    nodes: Vec<NodeRecord>,
    structured: bool,
    contains_sensitive_values: bool,
}

impl fmt::Debug for NginxVisualDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NginxVisualDocument")
            .field("bytes", &self.source.len())
            .field("nodes", &self.nodes.len())
            .field("structured", &self.structured)
            .field("contains_sensitive_values", &self.contains_sensitive_values)
            .finish()
    }
}

#[derive(Clone, Debug)]
struct NodeRecord {
    id: NginxVisualNodeId,
    parent: Option<NginxVisualNodeId>,
    depth: usize,
    kind: NginxVisualNodeKind,
    span: Range<usize>,
    header_span: Range<usize>,
    name_span: Option<Range<usize>>,
    arguments_span: Option<Range<usize>>,
    close_at: Option<usize>,
    child_count: usize,
}

#[derive(Debug)]
struct ParsedNode {
    kind: NginxVisualNodeKind,
    span: Range<usize>,
    header_span: Range<usize>,
    name_span: Option<Range<usize>>,
    arguments_span: Option<Range<usize>>,
    close_at: Option<usize>,
    children: Vec<ParsedNode>,
}

impl NginxVisualDocument {
    pub fn blank() -> Self {
        Self {
            source: Zeroizing::new(Vec::new()),
            nodes: Vec::new(),
            structured: true,
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
        if std::str::from_utf8(&source).is_err() {
            return Ok(Self::opaque(source));
        }
        match Parser::new(&source).parse() {
            Ok(parsed) => Ok(Self::from_parsed(source, parsed)),
            Err(_) => Ok(Self::opaque(source)),
        }
    }

    pub fn from_generated(generated: &GeneratedNginxConfig) -> CoreResult<Self> {
        Self::parse(generated.contents())
    }

    pub fn read_local(path: &Path) -> CoreResult<Self> {
        validate_import_path(path)?;
        let file = File::open(path)
            .map_err(|source| CoreError::io("open local Nginx configuration", path, source))?;
        let metadata = file
            .metadata()
            .map_err(|source| CoreError::io("inspect local Nginx configuration", path, source))?;
        let length = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
        validate_size(length)?;
        let mut bytes = Vec::with_capacity(length.min(MAX_NGINX_VISUAL_BYTES));
        file.take((MAX_NGINX_VISUAL_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|source| CoreError::io("read local Nginx configuration", path, source))?;
        validate_size(bytes.len())?;
        Self::parse_bytes(bytes)
    }

    pub const fn is_structured(&self) -> bool {
        self.structured
    }

    pub const fn contains_sensitive_values(&self) -> bool {
        self.contains_sensitive_values
    }

    pub fn raw_bytes(&self) -> &[u8] {
        &self.source
    }

    pub fn output(&self) -> NginxVisualOutput {
        NginxVisualOutput {
            bytes: Zeroizing::new(self.source.to_vec()),
        }
    }

    pub fn rows(&self) -> Vec<NginxVisualRow> {
        self.nodes.iter().map(|node| self.row(node)).collect()
    }

    pub fn row_by_id(&self, id: NginxVisualNodeId) -> Option<NginxVisualRow> {
        self.node(id).map(|node| self.row(node))
    }

    pub fn add_directive(
        &mut self,
        parent: Option<NginxVisualNodeId>,
        name: &str,
        arguments: &str,
    ) -> CoreResult<()> {
        let fragment = statement_fragment(name, arguments, NginxVisualNodeKind::Directive)?;
        self.insert_child(parent, fragment)
    }

    pub fn add_block(
        &mut self,
        parent: Option<NginxVisualNodeId>,
        name: &str,
        arguments: &str,
    ) -> CoreResult<()> {
        let fragment = statement_fragment(name, arguments, NginxVisualNodeKind::Block)?;
        self.insert_child(parent, fragment)
    }

    pub fn add_comment(&mut self, parent: Option<NginxVisualNodeId>, text: &str) -> CoreResult<()> {
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
        id: NginxVisualNodeId,
        name: &str,
        arguments: &str,
    ) -> CoreResult<()> {
        let node = self.require_node(id)?.clone();
        if contains_sensitive_marker(&self.source[node.span.clone()]) {
            return Err(invalid_edit(
                "sensitive statements require a dedicated secret-aware edit flow",
            ));
        }
        if !matches!(
            node.kind,
            NginxVisualNodeKind::Directive | NginxVisualNodeKind::Block
        ) {
            return Err(invalid_edit("selected node is not a statement or block"));
        }
        let fragment = statement_fragment(name, arguments, node.kind)?;
        let (range, replacement) = if node.kind == NginxVisualNodeKind::Block {
            let open = fragment
                .iter()
                .rposition(|byte| *byte == b'{')
                .expect("validated block fragment contains an opening brace");
            (node.header_span, fragment[..open].to_vec())
        } else {
            (node.span, fragment)
        };
        self.splice_and_reparse(range, &replacement)
    }

    pub fn update_comment(&mut self, id: NginxVisualNodeId, text: &str) -> CoreResult<()> {
        validate_comment(text)?;
        let node = self.require_node(id)?.clone();
        if contains_sensitive_marker(&self.source[node.span.clone()]) {
            return Err(invalid_edit(
                "sensitive comments require a dedicated secret-aware edit flow",
            ));
        }
        if node.kind != NginxVisualNodeKind::Comment {
            return Err(invalid_edit("selected node is not a comment"));
        }
        let mut replacement = Vec::with_capacity(text.len() + 2);
        replacement.push(b'#');
        if !text.is_empty() {
            replacement.push(b' ');
            replacement.extend_from_slice(text.as_bytes());
        }
        self.splice_and_reparse(node.span, &replacement)
    }

    pub fn remove(&mut self, id: NginxVisualNodeId) -> CoreResult<()> {
        let node = self.require_node(id)?.clone();
        if node.kind == NginxVisualNodeKind::Opaque {
            return Err(invalid_edit(
                "opaque source must be replaced explicitly, not structurally deleted",
            ));
        }
        let range = self.line_extended_span(&node);
        self.splice_and_reparse(range, &[])
    }

    pub fn move_up(&mut self, id: NginxVisualNodeId) -> CoreResult<()> {
        self.move_sibling(id, false)
    }

    pub fn move_down(&mut self, id: NginxVisualNodeId) -> CoreResult<()> {
        self.move_sibling(id, true)
    }

    /// Explicit raw fallback for malformed, non-UTF-8, or custom embedded syntax.
    pub fn replace_raw(&mut self, bytes: Vec<u8>) -> CoreResult<()> {
        let replacement = Self::parse_bytes(bytes)?;
        *self = replacement;
        Ok(())
    }

    fn from_parsed(source: Vec<u8>, parsed: Vec<ParsedNode>) -> Self {
        let contains_sensitive_values = contains_sensitive_marker(&source);
        let mut nodes = Vec::new();
        let mut next_id = 1u64;
        let revision = next_document_revision();
        flatten_nodes(&parsed, None, 0, revision, &mut next_id, &mut nodes);
        Self {
            source: Zeroizing::new(source),
            nodes,
            structured: true,
            contains_sensitive_values,
        }
    }

    fn opaque(source: Vec<u8>) -> Self {
        let contains_sensitive_values = contains_sensitive_marker(&source);
        let revision = next_document_revision();
        let nodes = (!source.is_empty())
            .then_some(NodeRecord {
                id: revision_node_id(revision, 1),
                parent: None,
                depth: 0,
                kind: NginxVisualNodeKind::Opaque,
                span: 0..source.len(),
                header_span: 0..source.len(),
                name_span: None,
                arguments_span: None,
                close_at: None,
                child_count: 0,
            })
            .into_iter()
            .collect();
        Self {
            source: Zeroizing::new(source),
            nodes,
            structured: false,
            contains_sensitive_values,
        }
    }

    fn row(&self, node: &NodeRecord) -> NginxVisualRow {
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
        let editable_span = if node.kind == NginxVisualNodeKind::Block {
            &node.header_span
        } else {
            &node.span
        };
        let fields_fit = node
            .name_span
            .iter()
            .chain(node.arguments_span.iter())
            .all(|span| span.end - span.start <= MAX_NGINX_VISUAL_EDIT_BYTES)
            && editable_span.end - editable_span.start <= MAX_NGINX_VISUAL_EDIT_BYTES;
        NginxVisualRow {
            id: node.id,
            parent: node.parent,
            depth: node.depth,
            kind: node.kind,
            name,
            arguments,
            preview: Zeroizing::new(preview),
            child_count: node.child_count,
            truncated: preview_truncated || !fields_fit,
            editable: node.kind != NginxVisualNodeKind::Opaque && fields_fit && !sensitive,
            sensitive,
        }
    }

    fn node(&self, id: NginxVisualNodeId) -> Option<&NodeRecord> {
        self.nodes.iter().find(|node| node.id == id)
    }

    fn require_node(&self, id: NginxVisualNodeId) -> CoreResult<&NodeRecord> {
        self.node(id)
            .ok_or_else(|| invalid_edit("selected Nginx node is stale or missing"))
    }

    fn insert_child(
        &mut self,
        parent: Option<NginxVisualNodeId>,
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
                if node.kind != NginxVisualNodeKind::Block {
                    return Err(invalid_edit("children can only be added to a block"));
                }
                let close_at = node
                    .close_at
                    .expect("structured block has a closing delimiter");
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
        if insert_at > 0 && !matches!(self.source[insert_at - 1], b'\n' | b'\r') {
            insertion.extend_from_slice(newline);
        }
        insertion.extend(std::iter::repeat_n(b' ', depth.saturating_mul(4)));
        insertion.extend_from_slice(&fragment);
        insertion.extend_from_slice(newline);
        self.splice_and_reparse(insert_at..insert_at, &insertion)
    }

    fn move_sibling(&mut self, id: NginxVisualNodeId, down: bool) -> CoreResult<()> {
        let node = self.require_node(id)?.clone();
        if node.kind == NginxVisualNodeKind::Opaque {
            return Err(invalid_edit("opaque source cannot be structurally moved"));
        }
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
        let first = if down { &node } else { siblings[other_index] };
        let second = if down { siblings[other_index] } else { &node };
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
            .all(|byte| is_nginx_whitespace(*byte))
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
        let new_len = self
            .source
            .len()
            .saturating_sub(range.end.saturating_sub(range.start))
            .saturating_add(replacement.len());
        validate_size(new_len)?;
        let mut source = Vec::with_capacity(new_len);
        source.extend_from_slice(&self.source[..range.start]);
        source.extend_from_slice(replacement);
        source.extend_from_slice(&self.source[range.end..]);
        let parsed = Parser::new(&source).parse().map_err(|error| {
            CoreError::validation(
                "Nginx visual edit",
                format!(
                    "would make the document structurally unsafe at byte {}",
                    error.offset
                ),
            )
        })?;
        *self = Self::from_parsed(source, parsed);
        Ok(())
    }
}

fn flatten_nodes(
    parsed: &[ParsedNode],
    parent: Option<NginxVisualNodeId>,
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

const fn revision_node_id(revision: u64, ordinal: u64) -> NginxVisualNodeId {
    NginxVisualNodeId(((revision as u128) << 64) | ordinal as u128)
}

#[derive(Clone, Copy, Debug)]
struct ParseFailure {
    offset: usize,
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
        let nodes = self.parse_level(0, false)?;
        if self.cursor != self.source.len() {
            return Err(self.failure());
        }
        Ok(nodes)
    }

    fn parse_level(
        &mut self,
        depth: usize,
        expect_close: bool,
    ) -> Result<Vec<ParsedNode>, ParseFailure> {
        if depth > MAX_NGINX_VISUAL_DEPTH {
            return Err(self.failure());
        }
        let mut output = Vec::new();
        loop {
            self.skip_whitespace();
            if self.cursor == self.source.len() {
                return if expect_close {
                    Err(self.failure())
                } else {
                    Ok(output)
                };
            }
            if self.source[self.cursor] == b'}' {
                if expect_close {
                    self.cursor += 1;
                    return Ok(output);
                }
                return Err(self.failure());
            }
            let node = if self.source[self.cursor] == b'#' {
                self.parse_comment()?
            } else {
                self.parse_statement(depth)?
            };
            self.bump_node()?;
            output.push(node);
        }
    }

    fn parse_comment(&mut self) -> Result<ParsedNode, ParseFailure> {
        let start = self.cursor;
        while self.cursor < self.source.len() && self.source[self.cursor] != b'\n' {
            self.cursor += 1;
        }
        let end = self
            .cursor
            .checked_sub(usize::from(
                self.cursor > start && self.source[self.cursor - 1] == b'\r',
            ))
            .unwrap_or(self.cursor);
        Ok(ParsedNode {
            kind: NginxVisualNodeKind::Comment,
            span: start..end,
            header_span: start..end,
            name_span: None,
            arguments_span: (start + 1 < end).then_some(trim_span(self.source, start + 1..end)),
            close_at: None,
            children: Vec::new(),
        })
    }

    fn parse_statement(&mut self, depth: usize) -> Result<ParsedNode, ParseFailure> {
        let start = self.cursor;
        let mut tokens = Vec::new();
        loop {
            self.skip_whitespace();
            if self.cursor >= self.source.len() {
                return Err(self.failure());
            }
            if self.source[self.cursor] == b'#' {
                self.skip_comment();
                continue;
            }
            match self.source[self.cursor] {
                b';' if !tokens.is_empty() => {
                    let delimiter = self.cursor;
                    self.cursor += 1;
                    return Ok(statement_node(
                        NginxVisualNodeKind::Directive,
                        start,
                        delimiter,
                        self.cursor,
                        tokens,
                        None,
                        Vec::new(),
                    ));
                }
                b'{' if !tokens.is_empty() => {
                    let delimiter = self.cursor;
                    self.cursor += 1;
                    let children = self.parse_level(depth + 1, true)?;
                    let close_at = self.cursor - 1;
                    return Ok(statement_node(
                        NginxVisualNodeKind::Block,
                        start,
                        delimiter,
                        self.cursor,
                        tokens,
                        Some(close_at),
                        children,
                    ));
                }
                b';' | b'{' | b'}' => return Err(self.failure()),
                _ => {
                    let token = self.parse_token()?;
                    self.tokens = self.tokens.saturating_add(1);
                    if self.tokens > MAX_NGINX_VISUAL_TOKENS {
                        return Err(self.failure());
                    }
                    tokens.push(token);
                }
            }
        }
    }

    fn parse_token(&mut self) -> Result<Range<usize>, ParseFailure> {
        let start = self.cursor;
        let mut quote = match self.source.get(self.cursor) {
            Some(b'\'' | b'"') => {
                let quote = self.source[self.cursor];
                self.cursor += 1;
                Some(quote)
            }
            _ => None,
        };
        let mut escaped = false;
        let mut variable = false;
        let mut quote_just_closed = false;
        while self.cursor < self.source.len() {
            let byte = self.source[self.cursor];
            if escaped {
                escaped = false;
                variable = false;
                quote_just_closed = false;
                self.cursor += 1;
                continue;
            }
            if byte == b'\\' {
                escaped = true;
                quote_just_closed = false;
                self.cursor += 1;
                continue;
            }
            if let Some(active) = quote {
                if byte == active {
                    quote = None;
                    quote_just_closed = true;
                }
                self.cursor += 1;
                continue;
            }
            if quote_just_closed {
                if is_nginx_whitespace(byte) || matches!(byte, b';' | b'{' | b')') {
                    break;
                }
                return Err(self.failure());
            }
            if byte == b'$' {
                variable = true;
                self.cursor += 1;
                continue;
            }
            if byte == b'{' {
                if variable {
                    variable = false;
                    self.cursor += 1;
                    continue;
                }
                break;
            }
            variable = false;
            if is_nginx_whitespace(byte) || matches!(byte, b';') {
                break;
            }
            self.cursor += 1;
        }
        if escaped || quote.is_some() || self.cursor == start {
            return Err(self.failure());
        }
        Ok(start..self.cursor)
    }

    fn skip_whitespace(&mut self) {
        while self.cursor < self.source.len() && is_nginx_whitespace(self.source[self.cursor]) {
            self.cursor += 1;
        }
    }

    fn skip_comment(&mut self) {
        while self.cursor < self.source.len() && self.source[self.cursor] != b'\n' {
            self.cursor += 1;
        }
    }

    fn bump_node(&mut self) -> Result<(), ParseFailure> {
        self.nodes = self.nodes.saturating_add(1);
        if self.nodes > MAX_NGINX_VISUAL_NODES {
            return Err(self.failure());
        }
        Ok(())
    }

    const fn failure(&self) -> ParseFailure {
        ParseFailure {
            offset: self.cursor,
        }
    }
}

fn statement_node(
    kind: NginxVisualNodeKind,
    start: usize,
    delimiter: usize,
    end: usize,
    tokens: Vec<Range<usize>>,
    close_at: Option<usize>,
    children: Vec<ParsedNode>,
) -> ParsedNode {
    let name_span = tokens.first().cloned();
    let arguments_span = (tokens.len() > 1).then(|| tokens[1].start..tokens.last().unwrap().end);
    ParsedNode {
        kind,
        span: start..end,
        header_span: start..delimiter,
        name_span,
        arguments_span,
        close_at,
        children,
    }
}

fn statement_fragment(
    name: &str,
    arguments: &str,
    kind: NginxVisualNodeKind,
) -> CoreResult<Vec<u8>> {
    if !matches!(
        kind,
        NginxVisualNodeKind::Directive | NginxVisualNodeKind::Block
    ) {
        return Err(invalid_edit("new node kind is not a statement"));
    }
    let name = trim_nginx_whitespace(name);
    let arguments = trim_nginx_whitespace(arguments);
    if name.is_empty()
        || name.len() > MAX_NGINX_VISUAL_EDIT_BYTES
        || arguments.len() > MAX_NGINX_VISUAL_EDIT_BYTES
        || name.contains('\0')
        || arguments.contains('\0')
    {
        return Err(invalid_edit(
            "statement name and arguments must be non-empty/bounded and contain no NUL",
        ));
    }
    let mut fragment = Vec::with_capacity(name.len() + arguments.len() + 4);
    fragment.extend_from_slice(name.as_bytes());
    if !arguments.is_empty() {
        fragment.push(b' ');
        fragment.extend_from_slice(arguments.as_bytes());
    }
    match kind {
        NginxVisualNodeKind::Directive => fragment.push(b';'),
        NginxVisualNodeKind::Block => fragment.extend_from_slice(b" {}"),
        _ => unreachable!(),
    }
    let parsed = Parser::new(&fragment).parse().map_err(|failure| {
        CoreError::validation(
            "Nginx visual statement",
            format!(
                "must describe exactly one safe node; invalid structure at byte {}",
                failure.offset
            ),
        )
    })?;
    let valid = parsed.len() == 1
        && parsed[0].kind == kind
        && parsed[0].children.is_empty()
        && parsed[0].name_span.as_ref().is_some_and(|span| {
            std::str::from_utf8(&fragment[span.clone()])
                .is_ok_and(|parsed_name| parsed_name == name)
        });
    if !valid {
        return Err(invalid_edit(
            "statement input would create more than one node or change its kind",
        ));
    }
    Ok(fragment)
}

fn validate_comment(text: &str) -> CoreResult<()> {
    if text.len() > MAX_NGINX_VISUAL_EDIT_BYTES || text.contains(['\0', '\r', '\n']) {
        return Err(invalid_edit(
            "comment must be one bounded physical line without NUL",
        ));
    }
    Ok(())
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

const fn is_nginx_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

fn trim_nginx_whitespace(value: &str) -> &str {
    value.trim_matches([' ', '\t', '\r', '\n'])
}

fn bounded_field(bytes: &[u8]) -> String {
    let bounded = &bytes[..bytes.len().min(MAX_NGINX_VISUAL_EDIT_BYTES)];
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
    const MARKERS: [&[u8]; 11] = [
        b"authorization",
        b"password",
        b"passwd",
        b"secret",
        b"credential",
        b"api_key",
        b"apikey",
        b"bearer ",
        b"private_key",
        b"private key",
        b"access_token",
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
            .take_while(|byte| {
                !is_nginx_whitespace(**byte) && !matches!(**byte, b';' | b'{' | b'}')
            })
            .any(|byte| *byte == b'@')
    })
}

fn validate_size(bytes: usize) -> CoreResult<()> {
    if bytes > MAX_NGINX_VISUAL_BYTES {
        return Err(CoreError::validation(
            "Nginx visual configuration",
            format!("must contain at most {MAX_NGINX_VISUAL_BYTES} bytes"),
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
            "Nginx configuration import path",
            "must be an existing absolute file selected by the native dialog without traversal components",
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
            "visual Nginx configuration destination",
            "must be a new absolute file path in an existing directory without traversal components",
        ));
    }
    Ok(())
}

fn invalid_edit(message: &'static str) -> CoreError {
    CoreError::validation("Nginx visual edit", message)
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMPREHENSIVE: &str = r#"# main
user nginx;
events { worker_connections 1024; }
http {
    map $http_host $backend { hostnames; default "api;#{}"; }
    geo $country { default ZZ; 127.0.0.1 LOCAL; }
    types { text/html html htm; application/octet-stream bin exe dll; }
    split_clients "${remote_addr}AAA" $variant { 50.0% one; * ""; }
    upstream app { server 127.0.0.1:8080; keepalive 32; }
    server {
        listen 80;
        server_name ~^(?<name>.+)\.example\.com$;
        location ~* \.(gif|jpg)$ { try_files $uri =404; }
        if ($request_method = POST) { return 405; }
        third_party_directive arbitrary tokens;
    }
}
stream { upstream tcp { server 127.0.0.1:9000; } server { listen 53 udp; proxy_pass tcp; } }
mail { server { listen 143; protocol imap; } }
third_party_block option { nested_unknown yes; }
"#;

    #[test]
    fn comprehensive_document_is_structured_and_byte_exact() {
        let document = NginxVisualDocument::parse(COMPREHENSIVE).unwrap();
        assert!(document.is_structured());
        assert_eq!(document.raw_bytes(), COMPREHENSIVE.as_bytes());
        assert_eq!(document.output().bytes(), COMPREHENSIVE.as_bytes());
        let rows = document.rows();
        assert!(rows.iter().any(|row| row.name() == Some("stream")));
        assert!(rows.iter().any(|row| row.name() == Some("mail")));
        assert!(
            rows.iter()
                .any(|row| row.name() == Some("third_party_directive"))
        );
        assert!(rows.iter().any(|row| row.depth() >= 3));
    }

    #[test]
    fn crlf_bom_and_missing_terminal_newline_round_trip() {
        let bytes = b"\xEF\xBB\xBF# x\r\nevents {\r\n    worker_connections 1;\r\n}".to_vec();
        let document = NginxVisualDocument::parse_bytes(bytes.clone()).unwrap();
        assert!(document.is_structured());
        assert_eq!(document.output().bytes(), bytes);
    }

    #[test]
    fn malformed_and_non_utf8_sources_are_visible_opaque_and_lossless() {
        for bytes in [
            b"http { server {".to_vec(),
            vec![b'#', b' ', 0xFF, b'\n', b'x', b';'],
            b"events { worker_connections 1; }\0tail".to_vec(),
        ] {
            let document = NginxVisualDocument::parse_bytes(bytes.clone()).unwrap();
            assert!(!document.is_structured());
            assert_eq!(document.output().bytes(), bytes);
            assert_eq!(document.rows()[0].kind(), NginxVisualNodeKind::Opaque);
        }
    }

    #[test]
    fn custom_embedded_language_falls_back_without_rewriting_bytes() {
        let lua = br#"http {
    server {
        content_by_lua_block {
            ngx.say("ok")
        }
    }
}
"#
        .to_vec();
        let document = NginxVisualDocument::parse_bytes(lua.clone()).unwrap();
        assert!(!document.is_structured());
        assert_eq!(document.rows()[0].kind(), NginxVisualNodeKind::Opaque);
        assert_eq!(document.output().bytes(), lua);
    }

    #[test]
    fn bom_crlf_subtree_move_header_edit_and_remove_preserve_neighbors() {
        let original = b"\xEF\xBB\xBFhttp {\r\n    server {\r\n        listen 80;\r\n        # first\r\n    }\r\n\r\n    server {\r\n        listen 81;\r\n    }\r\n}\r\n# tail\r\n";
        let mut document = NginxVisualDocument::parse_bytes(original.to_vec()).unwrap();
        let first_server = document
            .rows()
            .into_iter()
            .find(|row| row.name() == Some("server"))
            .unwrap()
            .id();
        document.move_down(first_server).unwrap();
        let moved = b"\xEF\xBB\xBFhttp {\r\n    server {\r\n        listen 81;\r\n    }\r\n\r\n    server {\r\n        listen 80;\r\n        # first\r\n    }\r\n}\r\n# tail\r\n";
        assert_eq!(document.output().bytes(), moved);

        let first_server = document
            .rows()
            .into_iter()
            .find(|row| row.name() == Some("server"))
            .unwrap()
            .id();
        document
            .update_statement(first_server, "server", "disabled")
            .unwrap();
        let edited = b"\xEF\xBB\xBFhttp {\r\n    server disabled {\r\n        listen 81;\r\n    }\r\n\r\n    server {\r\n        listen 80;\r\n        # first\r\n    }\r\n}\r\n# tail\r\n";
        assert_eq!(document.output().bytes(), edited);

        let edited_server = document
            .rows()
            .into_iter()
            .find(|row| row.arguments() == Some("disabled"))
            .unwrap()
            .id();
        document.remove(edited_server).unwrap();
        let removed = b"\xEF\xBB\xBFhttp {\r\n\r\n    server {\r\n        listen 80;\r\n        # first\r\n    }\r\n}\r\n# tail\r\n";
        assert_eq!(document.output().bytes(), removed);
    }

    #[test]
    fn safe_operations_add_update_remove_and_move_whole_subtrees() {
        let mut document = NginxVisualDocument::parse("http {\n}\n").unwrap();
        let http = document.rows()[0].id();
        document.add_block(Some(http), "server", "").unwrap();
        let server = document
            .rows()
            .into_iter()
            .find(|row| row.name() == Some("server"))
            .unwrap()
            .id();
        document
            .add_directive(Some(server), "listen", "443 ssl")
            .unwrap();
        let server = document
            .rows()
            .into_iter()
            .find(|row| row.name() == Some("server"))
            .unwrap()
            .id();
        document
            .add_comment(Some(server), "competition TLS listener")
            .unwrap();
        let server = document
            .rows()
            .into_iter()
            .find(|row| row.name() == Some("server"))
            .unwrap()
            .id();
        document
            .add_directive(Some(server), "server_name", "example.com")
            .unwrap();
        let listen = document
            .rows()
            .into_iter()
            .find(|row| row.name() == Some("listen"))
            .unwrap()
            .id();
        document
            .update_statement(listen, "listen", "8443 ssl")
            .unwrap();
        let server_name = document
            .rows()
            .into_iter()
            .find(|row| row.name() == Some("server_name"))
            .unwrap()
            .id();
        document.move_up(server_name).unwrap();
        let comment = document
            .rows()
            .into_iter()
            .find(|row| row.kind() == NginxVisualNodeKind::Comment)
            .unwrap()
            .id();
        document.update_comment(comment, "edited").unwrap();
        let comment = document
            .rows()
            .into_iter()
            .find(|row| row.kind() == NginxVisualNodeKind::Comment)
            .unwrap()
            .id();
        document.remove(comment).unwrap();
        let output = document.output();
        let rendered = output.text().unwrap();
        assert!(rendered.contains("listen 8443 ssl;"));
        assert!(rendered.contains("server_name example.com;"));
        assert!(!rendered.contains("competition TLS listener"));
        assert!(
            NginxVisualDocument::parse(rendered)
                .unwrap()
                .is_structured()
        );
    }

    #[test]
    fn node_ids_fail_closed_after_every_successful_mutation() {
        let mut document =
            NginxVisualDocument::parse("worker_processes auto;\nerror_log logs/error.log;\n")
                .unwrap();
        let old_first = document.rows()[0].id();
        document.remove(old_first).unwrap();
        assert!(
            document
                .update_statement(old_first, "error_log", "logs/changed.log")
                .is_err()
        );
        assert_eq!(
            document.output().text().unwrap(),
            "error_log logs/error.log;\n"
        );
    }

    #[test]
    fn one_field_cannot_inject_an_additional_node() {
        let mut document = NginxVisualDocument::parse("events {}\n").unwrap();
        let events = document.rows()[0].id();
        for (name, arguments) in [
            ("worker_connections; include", "/etc/shadow"),
            ("worker_connections", "1; include /etc/shadow"),
            ("worker_connections", "1 } http { server"),
            ("worker_connections\nuser", "root"),
            ("set", r#"$x a"; error_log /tmp/visual-boundary-bypass; #"#),
            (
                "set",
                "$x a\u{000b}#not-a-comment ; error_log /tmp/vt-bypass;\nset $y ok",
            ),
            (
                "set",
                "$x a\u{000c}#not-a-comment ; error_log /tmp/ff-bypass;\nset $y ok",
            ),
        ] {
            assert!(
                document
                    .add_directive(Some(events), name, arguments)
                    .is_err()
            );
        }
        assert_eq!(document.output().text().unwrap(), "events {}\n");
    }

    #[test]
    fn quoted_metacharacters_and_braced_variables_remain_one_node() {
        let document = NginxVisualDocument::parse(
            "map ${host} $out { default \"value ; # { }\"; foo#bar value; }\n",
        )
        .unwrap();
        assert!(document.is_structured());
        assert_eq!(document.rows().len(), 3);
    }

    #[test]
    fn lexer_matches_nginx_quote_variable_and_if_parenthesis_boundaries() {
        let document = NginxVisualDocument::parse(
            r#"http { server { if ($request_method = "POST") { return 405; } } }
"#,
        )
        .unwrap();
        assert!(document.is_structured());
        assert!(document.rows().iter().any(|row| row.name() == Some("if")));

        // The escaped dollar does not activate Nginx's `${...}` exception, so
        // the following opening brace starts a real block.
        let escaped = NginxVisualDocument::parse(r"third \${ nested yes; }").unwrap();
        assert!(escaped.is_structured());
        assert_eq!(escaped.rows()[0].kind(), NginxVisualNodeKind::Block);
    }

    #[test]
    fn debug_output_never_contains_configuration_text() {
        let secret = "proxy_set_header Authorization secret-token;\n";
        let mut document = NginxVisualDocument::parse(secret).unwrap();
        let output = document.output();
        let row = &document.rows()[0];
        assert!(document.contains_sensitive_values());
        assert!(row.sensitive());
        assert!(!row.editable());
        assert!(row.arguments().is_none());
        assert!(!row.preview().contains("secret-token"));
        assert!(!format!("{document:?}").contains("secret-token"));
        assert!(!format!("{output:?}").contains("secret-token"));
        assert!(!format!("{row:?}").contains("secret-token"));
        let _: Zeroizing<String> = output.text_lossy();
        let sensitive_id = row.id();
        assert!(
            document
                .update_statement(
                    sensitive_id,
                    "proxy_set_header",
                    "Authorization replacement"
                )
                .is_err()
        );

        let userinfo =
            NginxVisualDocument::parse("proxy_pass https://user:pass@example.test;\n").unwrap();
        assert!(userinfo.contains_sensitive_values());
        assert!(userinfo.rows()[0].sensitive());
    }

    #[test]
    fn local_paths_reject_traversal_and_output_supports_native_nginx_names() {
        let directory = std::env::temp_dir().join(format!(
            "lovelyres-nginx-visual-{}-{}",
            std::process::id(),
            next_document_revision()
        ));
        fs::create_dir(&directory).expect("create isolated temporary directory");
        let source_path = directory.join("input.conf");
        fs::write(&source_path, b"events {}\n").expect("write import fixture");
        let child = directory.join("child");
        fs::create_dir(&child).expect("create traversal fixture directory");
        let traversing_path = child.join("..").join("input.conf");
        assert!(NginxVisualDocument::read_local(&traversing_path).is_err());

        let document = NginxVisualDocument::parse("events {}\n").expect("output fixture");
        let extensionless = directory.join("default");
        document
            .output()
            .write_new(&extensionless)
            .expect("Nginx site includes are commonly extensionless");
        assert!(document.output().write_new(&extensionless).is_err());
        let types = directory.join("mime.types");
        document
            .output()
            .write_new(&types)
            .expect("Nginx includes may use non-conf extensions");

        fs::remove_file(&source_path).expect("remove import fixture");
        fs::remove_file(&extensionless).expect("remove extensionless output");
        fs::remove_file(&types).expect("remove types output");
        fs::remove_dir(&child).expect("remove traversal fixture directory");
        fs::remove_dir(&directory).expect("remove isolated temporary directory");
    }

    #[test]
    fn over_size_input_fails_without_echoing_contents() {
        let exact = NginxVisualDocument::parse_bytes(vec![b' '; MAX_NGINX_VISUAL_BYTES]).unwrap();
        assert!(exact.is_structured());
        assert_eq!(exact.output().bytes().len(), MAX_NGINX_VISUAL_BYTES);

        let error =
            NginxVisualDocument::parse_bytes(vec![b'x'; MAX_NGINX_VISUAL_BYTES + 1]).unwrap_err();
        assert!(!error.to_string().contains("xxxx"));
    }

    #[test]
    fn node_token_and_depth_limits_fail_to_lossless_opaque() {
        let exact_nodes = "x;\n".repeat(MAX_NGINX_VISUAL_NODES);
        let document = NginxVisualDocument::parse(&exact_nodes).unwrap();
        assert!(document.is_structured());
        assert_eq!(document.rows().len(), MAX_NGINX_VISUAL_NODES);

        let over_nodes = "x;\n".repeat(MAX_NGINX_VISUAL_NODES + 1);
        let document = NginxVisualDocument::parse(&over_nodes).unwrap();
        assert!(!document.is_structured());
        assert_eq!(document.output().bytes(), over_nodes.as_bytes());

        let exact_tokens = format!("directive {};", "x ".repeat(MAX_NGINX_VISUAL_TOKENS - 1));
        let document = NginxVisualDocument::parse(&exact_tokens).unwrap();
        assert!(document.is_structured());
        assert_eq!(document.output().bytes(), exact_tokens.as_bytes());

        let over_tokens = format!("directive {};", "x ".repeat(MAX_NGINX_VISUAL_TOKENS));
        let document = NginxVisualDocument::parse(&over_tokens).unwrap();
        assert!(!document.is_structured());
        assert_eq!(document.output().bytes(), over_tokens.as_bytes());

        let exact_depth = format!(
            "{}leaf on;{}",
            "block {".repeat(MAX_NGINX_VISUAL_DEPTH),
            "}".repeat(MAX_NGINX_VISUAL_DEPTH)
        );
        let document = NginxVisualDocument::parse(&exact_depth).unwrap();
        assert!(document.is_structured());

        let over_depth = format!(
            "{}leaf on;{}",
            "block {".repeat(MAX_NGINX_VISUAL_DEPTH + 1),
            "}".repeat(MAX_NGINX_VISUAL_DEPTH + 1)
        );
        let document = NginxVisualDocument::parse(&over_depth).unwrap();
        assert!(!document.is_structured());
        assert_eq!(document.output().bytes(), over_depth.as_bytes());
    }
}
