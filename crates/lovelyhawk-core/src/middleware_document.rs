//! Lossless, bounded document model for middleware configuration files.
//!
//! Parsers in this module are deliberately lexical. They expose only byte
//! spans that can be replaced without serializing the rest of the document.
//! Product-specific semantic validation and remote config-test commands belong
//! to the middleware service layer, after a patched document has been staged.

use std::{error::Error, fmt};
use zeroize::Zeroizing;

pub const MAX_MIDDLEWARE_DOCUMENT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_MIDDLEWARE_DOCUMENT_NODES: usize = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MiddlewareDocumentSyntax {
    Nginx,
    Apache,
    Redis,
    TomcatXml,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ByteSpan {
    start: usize,
    end: usize,
}

impl ByteSpan {
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    pub const fn start(self) -> usize {
        self.start
    }

    pub const fn end(self) -> usize {
        self.end
    }

    pub const fn len(self) -> usize {
        self.end.saturating_sub(self.start)
    }

    pub const fn is_empty(self) -> bool {
        self.start == self.end
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MiddlewareDocumentNodeKind {
    Preamble,
    Whitespace,
    Comment,
    Directive,
    BlockStart,
    BlockEnd,
    ElementStart,
    ElementEnd,
    Attribute,
    Text,
    Cdata,
    ProcessingInstruction,
    Declaration,
    Opaque,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MiddlewareDocumentNode {
    pub kind: MiddlewareDocumentNodeKind,
    pub name: Option<String>,
    pub span: ByteSpan,
    pub editable_value: Option<ByteSpan>,
    pub depth: usize,
}

#[derive(Clone, Eq, PartialEq)]
pub struct MiddlewareDocumentPatch {
    pub span: ByteSpan,
    pub replacement: String,
}

impl fmt::Debug for MiddlewareDocumentPatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MiddlewareDocumentPatch")
            .field("span", &self.span)
            .field("replacement_bytes", &self.replacement.len())
            .finish()
    }
}

impl MiddlewareDocumentPatch {
    pub fn new(span: ByteSpan, replacement: impl Into<String>) -> Self {
        Self {
            span,
            replacement: replacement.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MiddlewareDocumentError {
    TooLarge { bytes: usize, maximum: usize },
    ContainsNul,
    PatchOutOfBounds(ByteSpan),
    PatchIsNotEditable(ByteSpan),
    OverlappingPatches { first: ByteSpan, second: ByteSpan },
}

impl fmt::Display for MiddlewareDocumentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { bytes, maximum } => {
                write!(
                    formatter,
                    "document has {bytes} bytes; maximum is {maximum}"
                )
            }
            Self::ContainsNul => formatter.write_str("document replacement must not contain NUL"),
            Self::PatchOutOfBounds(span) => write!(
                formatter,
                "patch span {}..{} is outside the document",
                span.start, span.end
            ),
            Self::PatchIsNotEditable(span) => write!(
                formatter,
                "patch span {}..{} is not an exact editable value span",
                span.start, span.end
            ),
            Self::OverlappingPatches { first, second } => write!(
                formatter,
                "patch spans {}..{} and {}..{} overlap",
                first.start, first.end, second.start, second.end
            ),
        }
    }
}

impl Error for MiddlewareDocumentError {}

#[derive(Clone, Eq, PartialEq)]
pub struct MiddlewareDocument {
    syntax: MiddlewareDocumentSyntax,
    raw: Zeroizing<Vec<u8>>,
    nodes: Vec<MiddlewareDocumentNode>,
}

impl fmt::Debug for MiddlewareDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MiddlewareDocument")
            .field("syntax", &self.syntax)
            .field("raw_bytes", &self.raw.len())
            .field("nodes", &self.nodes.len())
            .finish()
    }
}

impl MiddlewareDocument {
    pub fn parse(
        syntax: MiddlewareDocumentSyntax,
        raw: impl Into<Vec<u8>>,
    ) -> Result<Self, MiddlewareDocumentError> {
        let raw = raw.into();
        ensure_size(raw.len())?;
        let nodes = parse_nodes(syntax, &raw);
        Ok(Self {
            syntax,
            raw: Zeroizing::new(raw),
            nodes,
        })
    }

    pub const fn syntax(&self) -> MiddlewareDocumentSyntax {
        self.syntax
    }

    pub fn raw_bytes(&self) -> &[u8] {
        self.raw.as_slice()
    }

    pub fn nodes(&self) -> &[MiddlewareDocumentNode] {
        &self.nodes
    }

    /// Replace the entire file in explicit raw-edit mode.
    pub fn replace_raw(&self, replacement: &str) -> Result<Self, MiddlewareDocumentError> {
        if replacement.as_bytes().contains(&0) {
            return Err(MiddlewareDocumentError::ContainsNul);
        }
        Self::parse(self.syntax, replacement.as_bytes().to_vec())
    }

    /// Apply exact, non-overlapping editable spans without serializing any
    /// unmodified part of the source document.
    pub fn apply_patches(
        &self,
        patches: &[MiddlewareDocumentPatch],
    ) -> Result<Self, MiddlewareDocumentError> {
        if patches.is_empty() {
            return Ok(self.clone());
        }

        let mut ordered: Vec<_> = patches.iter().collect();
        for patch in &ordered {
            let span = patch.span;
            if span.start > span.end || span.end > self.raw.len() {
                return Err(MiddlewareDocumentError::PatchOutOfBounds(span));
            }
            if patch.replacement.as_bytes().contains(&0) {
                return Err(MiddlewareDocumentError::ContainsNul);
            }
        }
        ordered.sort_by_key(|patch| (patch.span.start, patch.span.end));

        for pair in ordered.windows(2) {
            let first = pair[0].span;
            let second = pair[1].span;
            if spans_conflict(first, second) {
                return Err(MiddlewareDocumentError::OverlappingPatches { first, second });
            }
        }

        for patch in &ordered {
            if !self
                .nodes
                .iter()
                .any(|node| node.editable_value == Some(patch.span))
            {
                return Err(MiddlewareDocumentError::PatchIsNotEditable(patch.span));
            }
        }

        let removed = ordered
            .iter()
            .try_fold(0usize, |total, patch| total.checked_add(patch.span.len()));
        let added = ordered.iter().try_fold(0usize, |total, patch| {
            total.checked_add(patch.replacement.len())
        });
        let resulting_size = removed
            .and_then(|removed| self.raw.len().checked_sub(removed))
            .and_then(|remaining| added.and_then(|added| remaining.checked_add(added)))
            .ok_or(MiddlewareDocumentError::TooLarge {
                bytes: usize::MAX,
                maximum: MAX_MIDDLEWARE_DOCUMENT_BYTES,
            })?;
        ensure_size(resulting_size)?;

        let mut patched = Vec::with_capacity(resulting_size);
        let mut cursor = 0usize;
        for patch in ordered {
            patched.extend_from_slice(&self.raw[cursor..patch.span.start]);
            patched.extend_from_slice(patch.replacement.as_bytes());
            cursor = patch.span.end;
        }
        patched.extend_from_slice(&self.raw[cursor..]);
        Self::parse(self.syntax, patched)
    }
}

fn ensure_size(bytes: usize) -> Result<(), MiddlewareDocumentError> {
    if bytes > MAX_MIDDLEWARE_DOCUMENT_BYTES {
        return Err(MiddlewareDocumentError::TooLarge {
            bytes,
            maximum: MAX_MIDDLEWARE_DOCUMENT_BYTES,
        });
    }
    Ok(())
}

fn spans_conflict(first: ByteSpan, second: ByteSpan) -> bool {
    first.start == second.start
        || (first.start < second.end && second.start < first.end)
        || (first.is_empty() && second.start <= first.start && first.start < second.end)
        || (second.is_empty() && first.start <= second.start && second.start < first.end)
}

fn parse_nodes(syntax: MiddlewareDocumentSyntax, raw: &[u8]) -> Vec<MiddlewareDocumentNode> {
    if raw.is_empty() {
        return Vec::new();
    }
    if std::str::from_utf8(raw).is_err() || raw.contains(&0) {
        return opaque_nodes(raw);
    }
    match syntax {
        MiddlewareDocumentSyntax::Nginx => parse_nginx(raw),
        MiddlewareDocumentSyntax::Apache => parse_apache(raw),
        MiddlewareDocumentSyntax::Redis => parse_redis(raw),
        MiddlewareDocumentSyntax::TomcatXml => parse_xml(raw),
    }
}

fn opaque_nodes(raw: &[u8]) -> Vec<MiddlewareDocumentNode> {
    let mut nodes = Vec::with_capacity(2);
    let start = push_preamble(&mut nodes, raw);
    if start < raw.len() {
        nodes.push(node(
            MiddlewareDocumentNodeKind::Opaque,
            None,
            start,
            raw.len(),
            None,
            0,
        ));
    }
    nodes
}

struct NodeBuilder {
    nodes: Vec<MiddlewareDocumentNode>,
    raw_len: usize,
    capped: bool,
}

impl NodeBuilder {
    fn new(raw: &[u8]) -> (Self, usize) {
        let mut nodes = Vec::new();
        let start = push_preamble(&mut nodes, raw);
        (
            Self {
                nodes,
                raw_len: raw.len(),
                capped: false,
            },
            start,
        )
    }

    fn push(&mut self, value: MiddlewareDocumentNode) -> Option<usize> {
        if self.capped {
            return None;
        }
        if self.nodes.len() >= MAX_MIDDLEWARE_DOCUMENT_NODES.saturating_sub(1) {
            self.capped = true;
            self.nodes.push(node(
                MiddlewareDocumentNodeKind::Opaque,
                None,
                value.span.start.min(self.raw_len),
                self.raw_len,
                None,
                value.depth,
            ));
            return None;
        }
        let index = self.nodes.len();
        self.nodes.push(value);
        Some(index)
    }

    fn is_capped(&self) -> bool {
        self.capped
    }

    fn finish(self) -> Vec<MiddlewareDocumentNode> {
        self.nodes
    }
}

fn node(
    kind: MiddlewareDocumentNodeKind,
    name: Option<String>,
    start: usize,
    end: usize,
    editable_value: Option<ByteSpan>,
    depth: usize,
) -> MiddlewareDocumentNode {
    MiddlewareDocumentNode {
        kind,
        name,
        span: ByteSpan::new(start, end),
        editable_value,
        depth,
    }
}

fn push_preamble(nodes: &mut Vec<MiddlewareDocumentNode>, raw: &[u8]) -> usize {
    if raw.starts_with(&[0xef, 0xbb, 0xbf]) {
        nodes.push(node(
            MiddlewareDocumentNodeKind::Preamble,
            None,
            0,
            3,
            None,
            0,
        ));
        3
    } else {
        0
    }
}

fn text(raw: &[u8], span: ByteSpan) -> String {
    // All syntax parsers run only after the complete document passed UTF-8
    // validation, and every delimiter is ASCII, so these boundaries are valid.
    String::from_utf8_lossy(&raw[span.start..span.end]).into_owned()
}

fn trim_horizontal_start(raw: &[u8], mut start: usize, end: usize) -> usize {
    while start < end && matches!(raw[start], b' ' | b'\t') {
        start += 1;
    }
    start
}

fn trim_horizontal_end(raw: &[u8], start: usize, mut end: usize) -> usize {
    while end > start && matches!(raw[end - 1], b' ' | b'\t') {
        end -= 1;
    }
    end
}

fn trim_ascii_start(raw: &[u8], mut start: usize, end: usize) -> usize {
    while start < end && raw[start].is_ascii_whitespace() {
        start += 1;
    }
    start
}

fn trim_ascii_end(raw: &[u8], start: usize, mut end: usize) -> usize {
    while end > start && raw[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    end
}

fn name_and_value(raw: &[u8], start: usize, end: usize) -> Option<(String, Option<ByteSpan>)> {
    let start = trim_ascii_start(raw, start, end);
    let end = trim_ascii_end(raw, start, end);
    if start == end {
        return None;
    }
    let mut name_end = start;
    while name_end < end && !raw[name_end].is_ascii_whitespace() {
        name_end += 1;
    }
    let name = text(raw, ByteSpan::new(start, name_end));
    let value_start = trim_ascii_start(raw, name_end, end);
    let value_end = trim_ascii_end(raw, value_start, end);
    let value = (value_start < value_end).then(|| ByteSpan::new(value_start, value_end));
    Some((name, value))
}

fn parse_nginx(raw: &[u8]) -> Vec<MiddlewareDocumentNode> {
    let (mut builder, mut cursor) = NodeBuilder::new(raw);
    let mut blocks: Vec<usize> = Vec::new();

    while cursor < raw.len() && !builder.is_capped() {
        if raw[cursor].is_ascii_whitespace() {
            let start = cursor;
            while cursor < raw.len() && raw[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
            let _ = builder.push(node(
                MiddlewareDocumentNodeKind::Whitespace,
                None,
                start,
                cursor,
                None,
                blocks.len(),
            ));
            continue;
        }
        if raw[cursor] == b'#' {
            let start = cursor;
            while cursor < raw.len() && raw[cursor] != b'\n' {
                cursor += 1;
            }
            let _ = builder.push(node(
                MiddlewareDocumentNodeKind::Comment,
                None,
                start,
                cursor,
                None,
                blocks.len(),
            ));
            continue;
        }
        if raw[cursor] == b'}' {
            let depth = blocks.len().saturating_sub(1);
            let kind = if blocks.pop().is_some() {
                MiddlewareDocumentNodeKind::BlockEnd
            } else {
                MiddlewareDocumentNodeKind::Opaque
            };
            let _ = builder.push(node(kind, None, cursor, cursor + 1, None, depth));
            cursor += 1;
            continue;
        }

        let statement_start = cursor;
        let mut quote = None;
        let mut escaped = false;
        let mut internal_comments = Vec::new();
        let mut delimiter = None;
        while cursor < raw.len() {
            let byte = raw[cursor];
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
            if byte == b'#' {
                let comment_start = cursor;
                while cursor < raw.len() && raw[cursor] != b'\n' {
                    cursor += 1;
                }
                internal_comments.push(ByteSpan::new(comment_start, cursor));
                continue;
            }
            if matches!(byte, b';' | b'{' | b'}') {
                delimiter = Some((cursor, byte));
                break;
            }
            cursor += 1;
        }

        match delimiter {
            Some((delimiter_at, b';' | b'{')) => {
                let delimiter_byte = raw[delimiter_at];
                let parsed = name_and_value(raw, statement_start, delimiter_at);
                let depth = blocks.len();
                let kind = if parsed.is_some() {
                    if delimiter_byte == b'{' {
                        MiddlewareDocumentNodeKind::BlockStart
                    } else {
                        MiddlewareDocumentNodeKind::Directive
                    }
                } else {
                    MiddlewareDocumentNodeKind::Opaque
                };
                let (name, editable) = parsed
                    .map(|(name, value)| {
                        let editable = internal_comments.is_empty().then_some(value).flatten();
                        (Some(name), editable)
                    })
                    .unwrap_or((None, None));
                let index = builder.push(node(
                    kind,
                    name,
                    statement_start,
                    delimiter_at + 1,
                    editable,
                    depth,
                ));
                for comment in internal_comments {
                    let _ = builder.push(node(
                        MiddlewareDocumentNodeKind::Comment,
                        None,
                        comment.start,
                        comment.end,
                        None,
                        depth,
                    ));
                }
                cursor = delimiter_at + 1;
                if kind == MiddlewareDocumentNodeKind::BlockStart
                    && let Some(index) = index
                {
                    blocks.push(index);
                }
            }
            Some((delimiter_at, b'}')) => {
                let end = trim_ascii_end(raw, statement_start, delimiter_at);
                if statement_start < end {
                    let _ = builder.push(node(
                        MiddlewareDocumentNodeKind::Opaque,
                        None,
                        statement_start,
                        end,
                        None,
                        blocks.len(),
                    ));
                }
                cursor = delimiter_at;
            }
            Some(_) => unreachable!(),
            None => {
                let _ = builder.push(node(
                    MiddlewareDocumentNodeKind::Opaque,
                    None,
                    statement_start,
                    raw.len(),
                    None,
                    blocks.len(),
                ));
                break;
            }
        }
    }

    for index in blocks {
        if let Some(open) = builder.nodes.get_mut(index) {
            open.kind = MiddlewareDocumentNodeKind::Opaque;
            open.editable_value = None;
        }
    }
    builder.finish()
}

fn for_each_line(mut start: usize, raw: &[u8], mut visit: impl FnMut(usize, usize, usize)) {
    while start < raw.len() {
        let newline = raw[start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|relative| start + relative);
        let full_end = newline.map_or(raw.len(), |newline| newline + 1);
        let mut content_end = newline.unwrap_or(raw.len());
        if content_end > start && raw[content_end - 1] == b'\r' {
            content_end -= 1;
        }
        visit(start, content_end, full_end);
        start = full_end;
    }
}

fn for_each_apache_logical_line(
    mut start: usize,
    raw: &[u8],
    mut visit: impl FnMut(usize, usize, usize, bool),
) {
    while start < raw.len() {
        let logical_start = start;
        let (content_end, full_end, dangling_continuation) = loop {
            let newline = raw[start..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map(|relative| start + relative);
            let full_end = newline.map_or(raw.len(), |newline| newline + 1);
            let mut content_end = newline.unwrap_or(raw.len());
            if content_end > start && raw[content_end - 1] == b'\r' {
                content_end -= 1;
            }
            let continued = content_end > start && raw[content_end - 1] == b'\\';
            start = full_end;
            if !continued {
                break (content_end, full_end, false);
            }
            if start >= raw.len() {
                break (content_end, full_end, true);
            }
        };
        visit(logical_start, content_end, full_end, dangling_continuation);
    }
}

fn apache_arguments_are_balanced(raw: &[u8], start: usize, end: usize) -> bool {
    let mut cursor = start;
    let mut quote = None;
    let mut escaped = false;
    while cursor < end {
        let byte = raw[cursor];
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if let Some(active) = quote {
            if byte == active {
                quote = None;
            }
        } else if matches!(byte, b'\'' | b'"') {
            quote = Some(byte);
        }
        cursor += 1;
    }
    quote.is_none() && !escaped
}

fn quote_aware_comment(raw: &[u8], start: usize, end: usize) -> Result<Option<usize>, ()> {
    let mut cursor = start;
    let mut quote = None;
    let mut escaped = false;
    while cursor < end {
        let byte = raw[cursor];
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
        } else if byte == b'#'
            && (cursor == start || raw[cursor.saturating_sub(1)].is_ascii_whitespace())
        {
            return Ok(Some(cursor));
        }
        cursor += 1;
    }
    if quote.is_some() || escaped {
        Err(())
    } else {
        Ok(None)
    }
}

fn parse_redis(raw: &[u8]) -> Vec<MiddlewareDocumentNode> {
    let (mut builder, start) = NodeBuilder::new(raw);
    for_each_line(start, raw, |line_start, content_end, full_end| {
        if builder.is_capped() {
            return;
        }
        let first = trim_horizontal_start(raw, line_start, content_end);
        if first == content_end {
            let _ = builder.push(node(
                MiddlewareDocumentNodeKind::Whitespace,
                None,
                line_start,
                full_end,
                None,
                0,
            ));
            return;
        }
        if raw[first] == b'#' {
            let _ = builder.push(node(
                MiddlewareDocumentNodeKind::Comment,
                None,
                line_start,
                content_end,
                None,
                0,
            ));
            push_line_ending(&mut builder, raw, content_end, full_end, 0);
            return;
        }

        let mut name_end = first;
        while name_end < content_end && !raw[name_end].is_ascii_whitespace() {
            name_end += 1;
        }
        let comment = quote_aware_comment(raw, name_end, content_end);
        let Ok(comment_start) = comment else {
            let _ = builder.push(node(
                MiddlewareDocumentNodeKind::Opaque,
                None,
                line_start,
                content_end,
                None,
                0,
            ));
            push_line_ending(&mut builder, raw, content_end, full_end, 0);
            return;
        };
        let directive_end = comment_start.unwrap_or(content_end);
        let value_start = trim_horizontal_start(raw, name_end, directive_end);
        let value_end = trim_horizontal_end(raw, value_start, directive_end);
        let editable = (value_start < value_end).then(|| ByteSpan::new(value_start, value_end));
        let _ = builder.push(node(
            MiddlewareDocumentNodeKind::Directive,
            Some(text(raw, ByteSpan::new(first, name_end))),
            line_start,
            directive_end,
            editable,
            0,
        ));
        if let Some(comment_start) = comment_start {
            let _ = builder.push(node(
                MiddlewareDocumentNodeKind::Comment,
                None,
                comment_start,
                content_end,
                None,
                0,
            ));
        }
        push_line_ending(&mut builder, raw, content_end, full_end, 0);
    });
    builder.finish()
}

fn push_line_ending(
    builder: &mut NodeBuilder,
    raw: &[u8],
    content_end: usize,
    full_end: usize,
    depth: usize,
) {
    if content_end < full_end {
        let _ = builder.push(node(
            MiddlewareDocumentNodeKind::Whitespace,
            None,
            content_end,
            full_end.min(raw.len()),
            None,
            depth,
        ));
    }
}

fn find_quoted_delimiter(raw: &[u8], start: usize, end: usize, delimiter: u8) -> Option<usize> {
    let mut cursor = start;
    let mut quote = None;
    let mut escaped = false;
    while cursor < end {
        let byte = raw[cursor];
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if let Some(active) = quote {
            if byte == active {
                quote = None;
            }
        } else if matches!(byte, b'\'' | b'"') {
            quote = Some(byte);
        } else if byte == delimiter {
            return Some(cursor);
        }
        cursor += 1;
    }
    None
}

fn parse_apache(raw: &[u8]) -> Vec<MiddlewareDocumentNode> {
    let (mut builder, start) = NodeBuilder::new(raw);
    let mut blocks: Vec<(String, usize)> = Vec::new();
    for_each_apache_logical_line(
        start,
        raw,
        |line_start, content_end, full_end, dangling_continuation| {
            if builder.is_capped() {
                return;
            }
            let first = trim_ascii_start(raw, line_start, content_end);
            if first == content_end {
                let _ = builder.push(node(
                    MiddlewareDocumentNodeKind::Whitespace,
                    None,
                    line_start,
                    full_end,
                    None,
                    blocks.len(),
                ));
                return;
            }

            if dangling_continuation {
                let _ = builder.push(node(
                    MiddlewareDocumentNodeKind::Opaque,
                    None,
                    line_start,
                    content_end,
                    None,
                    blocks.len(),
                ));
                push_line_ending(&mut builder, raw, content_end, full_end, blocks.len());
                return;
            }
            if raw[first] == b'#' {
                let _ = builder.push(node(
                    MiddlewareDocumentNodeKind::Comment,
                    None,
                    line_start,
                    content_end,
                    None,
                    blocks.len(),
                ));
                push_line_ending(&mut builder, raw, content_end, full_end, blocks.len());
                return;
            }

            if raw[first] == b'<' {
                let Some(close) = find_quoted_delimiter(raw, first + 1, content_end, b'>') else {
                    let _ = builder.push(node(
                        MiddlewareDocumentNodeKind::Opaque,
                        None,
                        line_start,
                        content_end,
                        None,
                        blocks.len(),
                    ));
                    push_line_ending(&mut builder, raw, content_end, full_end, blocks.len());
                    return;
                };
                let after = trim_ascii_start(raw, close + 1, content_end);
                if after < content_end {
                    let _ = builder.push(node(
                        MiddlewareDocumentNodeKind::Opaque,
                        None,
                        line_start,
                        content_end,
                        None,
                        blocks.len(),
                    ));
                    push_line_ending(&mut builder, raw, content_end, full_end, blocks.len());
                    return;
                }
                let mut inner_start = trim_ascii_start(raw, first + 1, close);
                let inner_end = trim_ascii_end(raw, inner_start, close);
                let closing = inner_start < inner_end && raw[inner_start] == b'/';
                if closing {
                    inner_start = trim_ascii_start(raw, inner_start + 1, inner_end);
                }
                let mut name_end = inner_start;
                while name_end < inner_end && !raw[name_end].is_ascii_whitespace() {
                    name_end += 1;
                }
                if inner_start == name_end {
                    let _ = builder.push(node(
                        MiddlewareDocumentNodeKind::Opaque,
                        None,
                        line_start,
                        close + 1,
                        None,
                        blocks.len(),
                    ));
                } else {
                    let name = text(raw, ByteSpan::new(inner_start, name_end));
                    if closing {
                        let matches = blocks
                            .last()
                            .is_some_and(|(open, _)| open.eq_ignore_ascii_case(&name));
                        let depth = blocks.len().saturating_sub(1);
                        let kind = if matches {
                            blocks.pop();
                            MiddlewareDocumentNodeKind::BlockEnd
                        } else {
                            MiddlewareDocumentNodeKind::Opaque
                        };
                        let _ = builder.push(node(
                            kind,
                            Some(name),
                            line_start,
                            close + 1,
                            None,
                            depth,
                        ));
                    } else {
                        let value_start = trim_ascii_start(raw, name_end, inner_end);
                        let value_end = trim_ascii_end(raw, value_start, inner_end);
                        let editable = (value_start < value_end)
                            .then(|| ByteSpan::new(value_start, value_end));
                        let depth = blocks.len();
                        let index = builder.push(node(
                            MiddlewareDocumentNodeKind::BlockStart,
                            Some(name.clone()),
                            line_start,
                            close + 1,
                            editable,
                            depth,
                        ));
                        if let Some(index) = index {
                            blocks.push((name, index));
                        }
                    }
                }
                push_line_ending(&mut builder, raw, content_end, full_end, blocks.len());
                return;
            }

            if !apache_arguments_are_balanced(raw, first, content_end) {
                let _ = builder.push(node(
                    MiddlewareDocumentNodeKind::Opaque,
                    None,
                    line_start,
                    content_end,
                    None,
                    blocks.len(),
                ));
                push_line_ending(&mut builder, raw, content_end, full_end, blocks.len());
                return;
            }
            // Apache only recognizes comments when `#` is the first non-whitespace
            // byte of a logical line. A later `#` is directive argument data.
            let directive_end = trim_ascii_end(raw, first, content_end);
            let parsed = name_and_value(raw, first, directive_end);
            let (kind, name, editable) = parsed
                .map(|(name, value)| (MiddlewareDocumentNodeKind::Directive, Some(name), value))
                .unwrap_or((MiddlewareDocumentNodeKind::Opaque, None, None));
            let _ = builder.push(node(
                kind,
                name,
                line_start,
                directive_end,
                editable,
                blocks.len(),
            ));
            push_line_ending(&mut builder, raw, content_end, full_end, blocks.len());
        },
    );

    for (_, index) in blocks {
        if let Some(open) = builder.nodes.get_mut(index) {
            open.kind = MiddlewareDocumentNodeKind::Opaque;
            open.editable_value = None;
        }
    }
    builder.finish()
}

fn find_bytes(raw: &[u8], start: usize, needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || start > raw.len() {
        return None;
    }
    raw[start..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|relative| start + relative)
}

fn find_xml_tag_end(raw: &[u8], start: usize) -> Option<usize> {
    let mut cursor = start;
    let mut quote = None;
    while cursor < raw.len() {
        let byte = raw[cursor];
        if let Some(active) = quote {
            if byte == active {
                quote = None;
            }
        } else if matches!(byte, b'\'' | b'"') {
            quote = Some(byte);
        } else if byte == b'>' {
            return Some(cursor);
        }
        cursor += 1;
    }
    None
}

fn find_xml_declaration_end(raw: &[u8], start: usize) -> Option<usize> {
    let mut cursor = start;
    let mut quote = None;
    let mut brackets = 0usize;
    while cursor < raw.len() {
        let byte = raw[cursor];
        if let Some(active) = quote {
            if byte == active {
                quote = None;
            }
        } else {
            match byte {
                b'\'' | b'"' => quote = Some(byte),
                b'[' => brackets = brackets.saturating_add(1),
                b']' => brackets = brackets.saturating_sub(1),
                b'>' if brackets == 0 => return Some(cursor),
                _ => {}
            }
        }
        cursor += 1;
    }
    None
}

#[derive(Debug)]
struct XmlOpen {
    name: String,
    node_indices: Vec<usize>,
}

fn mark_xml_open_opaque(builder: &mut NodeBuilder, open: XmlOpen) {
    for index in open.node_indices {
        if let Some(value) = builder.nodes.get_mut(index) {
            value.kind = MiddlewareDocumentNodeKind::Opaque;
            value.editable_value = None;
        }
    }
}

fn parse_xml(raw: &[u8]) -> Vec<MiddlewareDocumentNode> {
    let (mut builder, mut cursor) = NodeBuilder::new(raw);
    let mut elements: Vec<XmlOpen> = Vec::new();

    while cursor < raw.len() && !builder.is_capped() {
        if raw[cursor] != b'<' {
            let end = raw[cursor..]
                .iter()
                .position(|byte| *byte == b'<')
                .map_or(raw.len(), |relative| cursor + relative);
            let whitespace = raw[cursor..end].iter().all(u8::is_ascii_whitespace);
            let kind = if whitespace {
                MiddlewareDocumentNodeKind::Whitespace
            } else {
                MiddlewareDocumentNodeKind::Text
            };
            let editable = (!whitespace).then(|| ByteSpan::new(cursor, end));
            let _ = builder.push(node(kind, None, cursor, end, editable, elements.len()));
            cursor = end;
            continue;
        }

        if raw[cursor..].starts_with(b"<!--") {
            let Some(end_start) = find_bytes(raw, cursor + 4, b"-->") else {
                let _ = builder.push(node(
                    MiddlewareDocumentNodeKind::Opaque,
                    None,
                    cursor,
                    raw.len(),
                    None,
                    elements.len(),
                ));
                break;
            };
            let end = end_start + 3;
            let _ = builder.push(node(
                MiddlewareDocumentNodeKind::Comment,
                None,
                cursor,
                end,
                None,
                elements.len(),
            ));
            cursor = end;
            continue;
        }
        if raw[cursor..].starts_with(b"<![CDATA[") {
            let Some(end_start) = find_bytes(raw, cursor + 9, b"]]>") else {
                let _ = builder.push(node(
                    MiddlewareDocumentNodeKind::Opaque,
                    None,
                    cursor,
                    raw.len(),
                    None,
                    elements.len(),
                ));
                break;
            };
            let end = end_start + 3;
            let _ = builder.push(node(
                MiddlewareDocumentNodeKind::Cdata,
                None,
                cursor,
                end,
                None,
                elements.len(),
            ));
            cursor = end;
            continue;
        }
        if raw[cursor..].starts_with(b"<?") {
            let Some(end_start) = find_bytes(raw, cursor + 2, b"?>") else {
                let _ = builder.push(node(
                    MiddlewareDocumentNodeKind::Opaque,
                    None,
                    cursor,
                    raw.len(),
                    None,
                    elements.len(),
                ));
                break;
            };
            let end = end_start + 2;
            let _ = builder.push(node(
                MiddlewareDocumentNodeKind::ProcessingInstruction,
                None,
                cursor,
                end,
                None,
                elements.len(),
            ));
            cursor = end;
            continue;
        }
        if raw[cursor..].starts_with(b"<!") {
            let Some(end_start) = find_xml_declaration_end(raw, cursor + 2) else {
                let _ = builder.push(node(
                    MiddlewareDocumentNodeKind::Opaque,
                    None,
                    cursor,
                    raw.len(),
                    None,
                    elements.len(),
                ));
                break;
            };
            let end = end_start + 1;
            let _ = builder.push(node(
                MiddlewareDocumentNodeKind::Declaration,
                None,
                cursor,
                end,
                None,
                elements.len(),
            ));
            cursor = end;
            continue;
        }

        let Some(tag_end) = find_xml_tag_end(raw, cursor + 1) else {
            let _ = builder.push(node(
                MiddlewareDocumentNodeKind::Opaque,
                None,
                cursor,
                raw.len(),
                None,
                elements.len(),
            ));
            break;
        };
        if raw[cursor..].starts_with(b"</") {
            let name_start = trim_ascii_start(raw, cursor + 2, tag_end);
            let name_end = trim_ascii_end(raw, name_start, tag_end);
            let valid = name_start < name_end
                && !raw[name_start..name_end]
                    .iter()
                    .any(u8::is_ascii_whitespace);
            let name = valid.then(|| text(raw, ByteSpan::new(name_start, name_end)));
            let matches = name
                .as_ref()
                .is_some_and(|name| elements.last().is_some_and(|open| open.name == *name));
            let depth = elements.len().saturating_sub(1);
            let kind = if matches {
                elements.pop();
                MiddlewareDocumentNodeKind::ElementEnd
            } else {
                MiddlewareDocumentNodeKind::Opaque
            };
            let _ = builder.push(node(kind, name, cursor, tag_end + 1, None, depth));
            cursor = tag_end + 1;
            continue;
        }

        let mut interior_end = trim_ascii_end(raw, cursor + 1, tag_end);
        let self_closing = interior_end > cursor + 1 && raw[interior_end - 1] == b'/';
        if self_closing {
            interior_end = trim_ascii_end(raw, cursor + 1, interior_end - 1);
        }
        let name_start = trim_ascii_start(raw, cursor + 1, interior_end);
        let mut name_end = name_start;
        while name_end < interior_end
            && !raw[name_end].is_ascii_whitespace()
            && !matches!(raw[name_end], b'/' | b'=')
        {
            name_end += 1;
        }
        if name_start == name_end {
            let _ = builder.push(node(
                MiddlewareDocumentNodeKind::Opaque,
                None,
                cursor,
                tag_end + 1,
                None,
                elements.len(),
            ));
            cursor = tag_end + 1;
            continue;
        }

        let name = text(raw, ByteSpan::new(name_start, name_end));
        let element_index = builder.push(node(
            MiddlewareDocumentNodeKind::ElementStart,
            Some(name.clone()),
            cursor,
            tag_end + 1,
            None,
            elements.len(),
        ));
        let mut node_indices = element_index.into_iter().collect::<Vec<_>>();
        let mut attribute_names = Vec::new();
        let mut attribute_cursor = name_end;
        let mut malformed = false;
        while attribute_cursor < interior_end {
            attribute_cursor = trim_ascii_start(raw, attribute_cursor, interior_end);
            if attribute_cursor == interior_end {
                break;
            }
            let attribute_start = attribute_cursor;
            while attribute_cursor < interior_end
                && !raw[attribute_cursor].is_ascii_whitespace()
                && raw[attribute_cursor] != b'='
            {
                attribute_cursor += 1;
            }
            let attribute_name_end = attribute_cursor;
            attribute_cursor = trim_ascii_start(raw, attribute_cursor, interior_end);
            if attribute_start == attribute_name_end
                || attribute_cursor == interior_end
                || raw[attribute_cursor] != b'='
            {
                malformed = true;
                break;
            }
            let attribute_name = text(raw, ByteSpan::new(attribute_start, attribute_name_end));
            if attribute_names.iter().any(|seen| seen == &attribute_name) {
                malformed = true;
                break;
            }
            attribute_names.push(attribute_name.clone());
            attribute_cursor += 1;
            attribute_cursor = trim_ascii_start(raw, attribute_cursor, interior_end);
            if attribute_cursor == interior_end || !matches!(raw[attribute_cursor], b'\'' | b'"') {
                malformed = true;
                break;
            }
            let quote = raw[attribute_cursor];
            let value_start = attribute_cursor + 1;
            let Some(relative_end) = raw[value_start..interior_end]
                .iter()
                .position(|byte| *byte == quote)
            else {
                malformed = true;
                break;
            };
            let value_end = value_start + relative_end;
            attribute_cursor = value_end + 1;
            if let Some(index) = builder.push(node(
                MiddlewareDocumentNodeKind::Attribute,
                Some(attribute_name),
                attribute_start,
                attribute_cursor,
                Some(ByteSpan::new(value_start, value_end)),
                elements.len() + 1,
            )) {
                node_indices.push(index);
            }
        }

        if malformed {
            mark_xml_open_opaque(&mut builder, XmlOpen { name, node_indices });
        } else if !self_closing {
            elements.push(XmlOpen { name, node_indices });
        }
        cursor = tag_end + 1;
    }

    for open in elements {
        mark_xml_open_opaque(&mut builder, open);
    }
    builder.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node_named<'a>(
        document: &'a MiddlewareDocument,
        kind: MiddlewareDocumentNodeKind,
        name: &str,
    ) -> &'a MiddlewareDocumentNode {
        document
            .nodes()
            .iter()
            .find(|node| node.kind == kind && node.name.as_deref() == Some(name))
            .unwrap_or_else(|| panic!("missing {kind:?} node named {name}"))
    }

    fn nodes_named<'a>(
        document: &'a MiddlewareDocument,
        kind: MiddlewareDocumentNodeKind,
        name: &str,
    ) -> Vec<&'a MiddlewareDocumentNode> {
        document
            .nodes()
            .iter()
            .filter(|node| node.kind == kind && node.name.as_deref() == Some(name))
            .collect()
    }

    #[test]
    fn nginx_round_trip_preserves_bom_crlf_unknown_directives_and_nested_blocks() {
        let raw = b"\xef\xbb\xbf# keep\r\nunknown_directive  one  two;\r\nhttp {\r\n  include /etc/nginx/conf.d/*.conf;\r\n  server { listen 8080; }\r\n}\r\n";
        let document =
            MiddlewareDocument::parse(MiddlewareDocumentSyntax::Nginx, raw.to_vec()).unwrap();

        assert_eq!(document.raw_bytes(), raw);
        assert_eq!(
            document.nodes()[0].kind,
            MiddlewareDocumentNodeKind::Preamble
        );
        assert!(document.nodes().iter().any(|node| {
            node.kind == MiddlewareDocumentNodeKind::BlockStart
                && node.name.as_deref() == Some("server")
                && node.depth == 1
        }));
        assert!(
            node_named(
                &document,
                MiddlewareDocumentNodeKind::Directive,
                "unknown_directive"
            )
            .editable_value
            .is_some()
        );
    }

    #[test]
    fn nginx_patch_changes_only_the_exact_value_bytes() {
        let raw = b"worker_processes  2; # untouched\n";
        let document =
            MiddlewareDocument::parse(MiddlewareDocumentSyntax::Nginx, raw.to_vec()).unwrap();
        let value = node_named(
            &document,
            MiddlewareDocumentNodeKind::Directive,
            "worker_processes",
        )
        .editable_value
        .unwrap();
        let patched = document
            .apply_patches(&[MiddlewareDocumentPatch::new(value, "auto")])
            .unwrap();

        assert_eq!(
            patched.raw_bytes(),
            b"worker_processes  auto; # untouched\n"
        );
    }

    #[test]
    fn apache_preserves_duplicates_unknowns_comments_and_nested_blocks() {
        let raw = b"\xef\xbb\xbf<VirtualHost *:80>\r\n  UnknownThing one\r\n  UnknownThing two\r\n  <Directory \"/srv/www\">\r\n    Require all granted # keep\r\n  </Directory>\r\n</VirtualHost>\r\n";
        let document =
            MiddlewareDocument::parse(MiddlewareDocumentSyntax::Apache, raw.to_vec()).unwrap();

        assert_eq!(document.raw_bytes(), raw);
        assert_eq!(
            nodes_named(
                &document,
                MiddlewareDocumentNodeKind::Directive,
                "UnknownThing"
            )
            .len(),
            2
        );
        assert_eq!(
            node_named(
                &document,
                MiddlewareDocumentNodeKind::BlockStart,
                "Directory"
            )
            .depth,
            1
        );
        let require = node_named(&document, MiddlewareDocumentNodeKind::Directive, "Require");
        let value = require.editable_value.unwrap();
        assert_eq!(&raw[value.start()..value.end()], b"all granted # keep");
        assert!(
            !document
                .nodes()
                .iter()
                .any(|node| node.kind == MiddlewareDocumentNodeKind::Comment)
        );
    }

    #[test]
    fn apache_continuations_are_one_directive_and_hash_is_argument_data() {
        let raw = b"# retained\\\r\ncontinued comment\r\nLogFormat \"%h \\\r\n%u\" combined\r\nHeader set X-Test value #not-an-inline-comment\r\n";
        let document =
            MiddlewareDocument::parse(MiddlewareDocumentSyntax::Apache, raw.to_vec()).unwrap();

        assert_eq!(document.raw_bytes(), raw);
        assert_eq!(
            document
                .nodes()
                .iter()
                .filter(|node| node.kind == MiddlewareDocumentNodeKind::Comment)
                .count(),
            1
        );
        assert_eq!(
            nodes_named(
                &document,
                MiddlewareDocumentNodeKind::Directive,
                "LogFormat"
            )
            .len(),
            1
        );
        let header = node_named(&document, MiddlewareDocumentNodeKind::Directive, "Header");
        let value = header.editable_value.unwrap();
        assert_eq!(
            &raw[value.start()..value.end()],
            b"set X-Test value #not-an-inline-comment"
        );
        assert!(
            !document
                .nodes()
                .iter()
                .any(|node| node.kind == MiddlewareDocumentNodeKind::Opaque)
        );
    }

    #[test]
    fn redis_duplicate_keys_have_distinct_editable_spans() {
        let raw = b"# heading\r\nmaxmemory 64mb\r\nmaxmemory 128mb # later wins\r\nfuture-setting \"a # b\"\r\n";
        let document =
            MiddlewareDocument::parse(MiddlewareDocumentSyntax::Redis, raw.to_vec()).unwrap();
        let repeated = nodes_named(
            &document,
            MiddlewareDocumentNodeKind::Directive,
            "maxmemory",
        );

        assert_eq!(document.raw_bytes(), raw);
        assert_eq!(repeated.len(), 2);
        assert_ne!(repeated[0].editable_value, repeated[1].editable_value);
        let unknown = node_named(
            &document,
            MiddlewareDocumentNodeKind::Directive,
            "future-setting",
        );
        assert_eq!(
            &raw[unknown.editable_value.unwrap().start()..unknown.editable_value.unwrap().end()],
            b"\"a # b\""
        );
    }

    #[test]
    fn tomcat_xml_preserves_comments_namespaces_and_attribute_spans() {
        let raw = br#"<?xml version="1.0"?>
<tc:Server xmlns:tc="urn:test">
  <!-- preserve me -->
  <tc:Connector port="8080" tc:mode='safe'/>
</tc:Server>
"#;
        let document =
            MiddlewareDocument::parse(MiddlewareDocumentSyntax::TomcatXml, raw.to_vec()).unwrap();

        assert_eq!(document.raw_bytes(), raw);
        assert!(document.nodes().iter().any(|node| {
            node.kind == MiddlewareDocumentNodeKind::ElementStart
                && node.name.as_deref() == Some("tc:Connector")
        }));
        assert!(
            document
                .nodes()
                .iter()
                .any(|node| node.kind == MiddlewareDocumentNodeKind::Comment)
        );
        let port = node_named(&document, MiddlewareDocumentNodeKind::Attribute, "port");
        let port_span = port.editable_value.unwrap();
        assert_eq!(&raw[port_span.start()..port_span.end()], b"8080");
        let patched = document
            .apply_patches(&[MiddlewareDocumentPatch::new(port_span, "8443")])
            .unwrap();
        assert!(
            String::from_utf8(patched.raw_bytes().to_vec())
                .unwrap()
                .contains("port=\"8443\" tc:mode='safe'")
        );
    }

    #[test]
    fn incomplete_or_invalid_structures_become_opaque_without_losing_bytes() {
        let cases = [
            (
                MiddlewareDocumentSyntax::Nginx,
                b"http { listen 80;".as_slice(),
            ),
            (
                MiddlewareDocumentSyntax::Apache,
                b"<VirtualHost *:80>\nServerName example.test\n".as_slice(),
            ),
            (
                MiddlewareDocumentSyntax::Redis,
                b"requirepass \"unterminated\n".as_slice(),
            ),
            (
                MiddlewareDocumentSyntax::TomcatXml,
                b"<Server><Connector port=\"8080\">".as_slice(),
            ),
        ];

        for (syntax, raw) in cases {
            let document = MiddlewareDocument::parse(syntax, raw.to_vec()).unwrap();
            assert_eq!(document.raw_bytes(), raw);
            assert!(
                document
                    .nodes()
                    .iter()
                    .any(|node| node.kind == MiddlewareDocumentNodeKind::Opaque)
            );
        }
    }

    #[test]
    fn invalid_utf8_is_preserved_as_opaque() {
        let raw = vec![b'a', 0xff, b'b'];
        let document =
            MiddlewareDocument::parse(MiddlewareDocumentSyntax::Redis, raw.clone()).unwrap();
        assert_eq!(document.raw_bytes(), raw);
        assert_eq!(document.nodes().len(), 1);
        assert_eq!(document.nodes()[0].kind, MiddlewareDocumentNodeKind::Opaque);
    }

    #[test]
    fn patches_reject_conflicts_out_of_bounds_and_non_editable_spans() {
        let document = MiddlewareDocument::parse(
            MiddlewareDocumentSyntax::Redis,
            b"maxmemory 64mb\n".to_vec(),
        )
        .unwrap();
        let value = node_named(
            &document,
            MiddlewareDocumentNodeKind::Directive,
            "maxmemory",
        )
        .editable_value
        .unwrap();
        let duplicate = [
            MiddlewareDocumentPatch::new(value, "128mb"),
            MiddlewareDocumentPatch::new(value, "256mb"),
        ];
        assert!(matches!(
            document.apply_patches(&duplicate),
            Err(MiddlewareDocumentError::OverlappingPatches { .. })
        ));
        assert!(matches!(
            document.apply_patches(&[MiddlewareDocumentPatch::new(
                ByteSpan::new(0, document.raw_bytes().len() + 1),
                "x"
            )]),
            Err(MiddlewareDocumentError::PatchOutOfBounds(_))
        ));
        assert!(matches!(
            document.apply_patches(&[MiddlewareDocumentPatch::new(ByteSpan::new(0, 3), "max")]),
            Err(MiddlewareDocumentError::PatchIsNotEditable(_))
        ));
    }

    #[test]
    fn raw_replacement_requires_bounded_nul_free_utf8() {
        let document =
            MiddlewareDocument::parse(MiddlewareDocumentSyntax::Redis, b"port 6379\n".to_vec())
                .unwrap();
        assert_eq!(
            document.replace_raw("port 6380\n").unwrap().raw_bytes(),
            b"port 6380\n"
        );
        assert_eq!(
            document.replace_raw("port \0\n"),
            Err(MiddlewareDocumentError::ContainsNul)
        );
        let oversized = "x".repeat(MAX_MIDDLEWARE_DOCUMENT_BYTES + 1);
        assert!(matches!(
            document.replace_raw(&oversized),
            Err(MiddlewareDocumentError::TooLarge { .. })
        ));
    }

    #[test]
    fn debug_output_never_contains_document_or_replacement_text() {
        let document = MiddlewareDocument::parse(
            MiddlewareDocumentSyntax::Redis,
            b"requirepass super-secret\n".to_vec(),
        )
        .unwrap();
        let span = node_named(
            &document,
            MiddlewareDocumentNodeKind::Directive,
            "requirepass",
        )
        .editable_value
        .unwrap();
        let patch = MiddlewareDocumentPatch::new(span, "replacement-secret");

        let document_debug = format!("{document:?}");
        let patch_debug = format!("{patch:?}");
        assert!(!document_debug.contains("super-secret"));
        assert!(!patch_debug.contains("replacement-secret"));
        assert!(patch_debug.contains("replacement_bytes"));
    }
}
