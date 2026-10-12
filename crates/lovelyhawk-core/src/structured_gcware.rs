//! Bounded, source-backed inspection for GBase 8a `gcware.conf`.
//!
//! The reviewed V9.5.3 grammar uses physical-line `key: value` entries and
//! named brace blocks. This parser recognizes only those proven boundaries.
//! Unknown delimiter-free lines remain local opaque atoms; any ambiguous brace
//! makes the complete document opaque so the UI cannot invent a false tree.

use std::ops::Range;

use crate::structured_config_visual::{
    MAX_STRUCTURED_CONFIG_BYTES, MAX_STRUCTURED_CONFIG_DEPTH, MAX_STRUCTURED_CONFIG_NODES,
    MAX_STRUCTURED_CONFIG_TOKENS,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GcwareParsedKind {
    Document,
    Block,
    Entry,
    Scalar,
    Opaque,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GcwareParsedNode {
    pub(crate) kind: GcwareParsedKind,
    pub(crate) span: Range<usize>,
    pub(crate) name_span: Option<Range<usize>>,
    pub(crate) sensitive: bool,
    pub(crate) children: Vec<GcwareParsedNode>,
}

pub(crate) fn parse_gcware(source: &[u8]) -> Result<GcwareParsedNode, ()> {
    if source.len() > MAX_STRUCTURED_CONFIG_BYTES {
        return Err(());
    }
    if source.is_empty() {
        return Ok(document(0, Vec::new()));
    }
    if std::str::from_utf8(source).is_err() || source.contains(&0) {
        return Ok(opaque_document(source.len()));
    }

    let parser = Parser {
        source,
        position: 0,
        nodes: 1,
        tokens: 0,
    };
    match parser.parse_document() {
        Ok(root) => Ok(root),
        Err(ParseFailure::Syntax) => Ok(opaque_document(source.len())),
        Err(ParseFailure::Limit) => Err(()),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ParseFailure {
    Syntax,
    Limit,
}

type ParseResult<T> = Result<T, ParseFailure>;

#[derive(Clone, Debug)]
struct PhysicalLine {
    start: usize,
    end: usize,
    significant: Range<usize>,
}

struct Parser<'a> {
    source: &'a [u8],
    position: usize,
    nodes: usize,
    tokens: usize,
}

impl<'a> Parser<'a> {
    fn parse_document(mut self) -> ParseResult<GcwareParsedNode> {
        let (children, close_end) = self.parse_level(false, 0, false)?;
        if close_end.is_some() || self.position != self.source.len() {
            return Err(ParseFailure::Syntax);
        }
        Ok(document(self.source.len(), children))
    }

    fn parse_level(
        &mut self,
        expect_close: bool,
        parent_depth: usize,
        inherited_sensitive: bool,
    ) -> ParseResult<(Vec<GcwareParsedNode>, Option<usize>)> {
        let mut children = Vec::new();
        loop {
            let Some(line) = self.next_line()? else {
                return if expect_close {
                    Err(ParseFailure::Syntax)
                } else {
                    Ok((children, None))
                };
            };
            if line.significant.is_empty() {
                continue;
            }
            let significant = &self.source[line.significant.clone()];
            if significant == b"}" {
                self.bump_tokens(1)?;
                return if expect_close {
                    Ok((children, Some(line.end)))
                } else {
                    Err(ParseFailure::Syntax)
                };
            }

            if let Some(name_span) = self.block_name(&line) {
                let depth = parent_depth.checked_add(1).ok_or(ParseFailure::Limit)?;
                self.ensure_depth(depth)?;
                self.bump_tokens(2)?;
                self.bump_node()?;
                let sensitive = inherited_sensitive
                    || contains_sensitive_identifier(&self.source[name_span.clone()]);
                let (block_children, close_end) = self.parse_level(true, depth, sensitive)?;
                let close_end = close_end.ok_or(ParseFailure::Syntax)?;
                children.push(GcwareParsedNode {
                    kind: GcwareParsedKind::Block,
                    span: line.start..close_end,
                    name_span: Some(name_span),
                    sensitive,
                    children: block_children,
                });
                continue;
            }

            if significant.contains(&b'{') || significant.contains(&b'}') {
                return Err(ParseFailure::Syntax);
            }

            if parent_depth > 0
                && let Some((name_span, value_span)) = self.entry_parts(&line)
            {
                let entry_depth = parent_depth.checked_add(1).ok_or(ParseFailure::Limit)?;
                let scalar_depth = entry_depth.checked_add(1).ok_or(ParseFailure::Limit)?;
                self.ensure_depth(scalar_depth)?;
                self.bump_tokens(3)?;
                self.bump_node()?;
                self.bump_node()?;
                let entry_sensitive = inherited_sensitive
                    || contains_sensitive_identifier(&self.source[name_span.clone()]);
                let value = &self.source[value_span.clone()];
                let scalar_proven = proven_scalar(value);
                let scalar_sensitive =
                    entry_sensitive || !scalar_proven || contains_sensitive_scalar(value);
                children.push(GcwareParsedNode {
                    kind: GcwareParsedKind::Entry,
                    span: line.start..line.end,
                    name_span: Some(name_span),
                    sensitive: entry_sensitive,
                    children: vec![GcwareParsedNode {
                        kind: if scalar_proven {
                            GcwareParsedKind::Scalar
                        } else {
                            GcwareParsedKind::Opaque
                        },
                        span: value_span,
                        name_span: None,
                        sensitive: scalar_sensitive,
                        children: Vec::new(),
                    }],
                });
                continue;
            }

            self.bump_tokens(1)?;
            self.bump_node()?;
            children.push(GcwareParsedNode {
                kind: GcwareParsedKind::Opaque,
                span: line.start..line.end,
                name_span: None,
                sensitive: true,
                children: Vec::new(),
            });
        }
    }

    fn next_line(&mut self) -> ParseResult<Option<PhysicalLine>> {
        if self.position == self.source.len() {
            return Ok(None);
        }
        self.bump_tokens(1)?;
        let start = self.position;
        let newline = self.source[start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|relative| start + relative);
        let end = newline.map_or(self.source.len(), |index| index + 1);
        self.position = end;
        let mut content_end = newline.unwrap_or(self.source.len());
        if content_end > start && self.source[content_end - 1] == b'\r' {
            content_end -= 1;
        }
        let mut body_start = start;
        if start == 0 && self.source.starts_with(b"\xEF\xBB\xBF") {
            body_start = 3;
        }
        let significant = trim_horizontal(self.source, body_start..content_end);
        Ok(Some(PhysicalLine {
            start,
            end,
            significant,
        }))
    }

    fn block_name(&self, line: &PhysicalLine) -> Option<Range<usize>> {
        let brace = line.significant.end.checked_sub(1)?;
        if self.source.get(brace) != Some(&b'{') {
            return None;
        }
        let name = trim_horizontal_end(self.source, line.significant.start..brace);
        if name.end == brace || !is_identifier(&self.source[name.clone()]) {
            return None;
        }
        self.source[name.end..brace]
            .iter()
            .all(|byte| is_horizontal(*byte))
            .then_some(name)
    }

    fn entry_parts(&self, line: &PhysicalLine) -> Option<(Range<usize>, Range<usize>)> {
        let colon = self.source[line.significant.clone()]
            .iter()
            .position(|byte| *byte == b':')
            .map(|relative| line.significant.start + relative)?;
        let name = trim_horizontal_end(self.source, line.significant.start..colon);
        if !is_identifier(&self.source[name.clone()]) {
            return None;
        }
        let value_start = skip_horizontal(self.source, colon + 1, line.significant.end);
        (value_start < line.significant.end).then_some((name, value_start..line.significant.end))
    }

    fn bump_node(&mut self) -> ParseResult<()> {
        self.nodes = self.nodes.checked_add(1).ok_or(ParseFailure::Limit)?;
        (self.nodes <= MAX_STRUCTURED_CONFIG_NODES)
            .then_some(())
            .ok_or(ParseFailure::Limit)
    }

    fn bump_tokens(&mut self, count: usize) -> ParseResult<()> {
        self.tokens = self.tokens.checked_add(count).ok_or(ParseFailure::Limit)?;
        (self.tokens <= MAX_STRUCTURED_CONFIG_TOKENS)
            .then_some(())
            .ok_or(ParseFailure::Limit)
    }

    fn ensure_depth(&self, depth: usize) -> ParseResult<()> {
        (depth <= MAX_STRUCTURED_CONFIG_DEPTH)
            .then_some(())
            .ok_or(ParseFailure::Limit)
    }
}

fn document(length: usize, children: Vec<GcwareParsedNode>) -> GcwareParsedNode {
    GcwareParsedNode {
        kind: GcwareParsedKind::Document,
        span: 0..length,
        name_span: None,
        sensitive: false,
        children,
    }
}

fn opaque_document(length: usize) -> GcwareParsedNode {
    document(
        length,
        if length == 0 {
            Vec::new()
        } else {
            vec![GcwareParsedNode {
                kind: GcwareParsedKind::Opaque,
                span: 0..length,
                name_span: None,
                sensitive: true,
                children: Vec::new(),
            }]
        },
    )
}

fn is_identifier(value: &[u8]) -> bool {
    !value.is_empty()
        && value
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-' | b'.'))
}

fn proven_scalar(value: &[u8]) -> bool {
    !value.is_empty()
        && !value.iter().any(|byte| {
            matches!(*byte, b'\0'..=b'\x08' | b'\x0B' | b'\x0C' | b'\x0E'..=b'\x1F')
                || matches!(*byte, b'\'' | b'"' | b'\\' | b'#' | b';')
        })
}

fn trim_horizontal(source: &[u8], range: Range<usize>) -> Range<usize> {
    let mut start = range.start;
    while start < range.end && is_horizontal(source[start]) {
        start += 1;
    }
    trim_horizontal_end(source, start..range.end)
}

fn trim_horizontal_end(source: &[u8], mut range: Range<usize>) -> Range<usize> {
    while range.start < range.end && is_horizontal(source[range.end - 1]) {
        range.end -= 1;
    }
    range
}

fn skip_horizontal(source: &[u8], mut start: usize, end: usize) -> usize {
    while start < end && is_horizontal(source[start]) {
        start += 1;
    }
    start
}

const fn is_horizontal(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t')
}

fn contains_sensitive_identifier(value: &[u8]) -> bool {
    let normalized = value
        .iter()
        .map(u8::to_ascii_lowercase)
        .filter(|byte| byte.is_ascii_alphanumeric())
        .collect::<Vec<_>>();
    [
        b"password".as_slice(),
        b"passwd".as_slice(),
        b"passphrase".as_slice(),
        b"pwd".as_slice(),
        b"secret".as_slice(),
        b"token".as_slice(),
        b"authorization".as_slice(),
        b"credential".as_slice(),
        b"privatekey".as_slice(),
        b"accesskey".as_slice(),
        b"connectionstring".as_slice(),
        b"bindpasswd".as_slice(),
    ]
    .iter()
    .any(|marker| normalized.windows(marker.len()).any(|part| part == *marker))
}

fn contains_sensitive_scalar(value: &[u8]) -> bool {
    let lower = value.iter().map(u8::to_ascii_lowercase).collect::<Vec<_>>();
    lower.windows(7).any(|part| part == b"bearer ")
        || lower.windows(4).any(|part| part == b"pwd=")
        || lower.windows(9).any(|part| part == b"password=")
        || lower.windows(7).any(|part| part == b"passwd=")
        || lower.windows(6).any(|part| part == b"token=")
        || lower.windows(7).any(|part| part == b"secret=")
        || (lower.windows(3).any(|part| part == b"://") && lower.contains(&b'@'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_span<'a>(source: &'a [u8], node: &GcwareParsedNode) -> &'a [u8] {
        &source[node.span.clone()]
    }

    fn nodes_named<'a>(
        node: &'a GcwareParsedNode,
        source: &[u8],
        name: &[u8],
    ) -> Vec<&'a GcwareParsedNode> {
        let mut output = Vec::new();
        if node
            .name_span
            .as_ref()
            .is_some_and(|span| &source[span.clone()] == name)
        {
            output.push(node);
        }
        for child in &node.children {
            output.extend(nodes_named(child, source, name));
        }
        output
    }

    fn contains_kind(node: &GcwareParsedNode, kind: GcwareParsedKind) -> bool {
        node.kind == kind || node.children.iter().any(|child| contains_kind(child, kind))
    }

    fn assert_tree_spans(node: &GcwareParsedNode) {
        let mut previous_end = node.span.start;
        for child in &node.children {
            assert!(node.span.start <= child.span.start);
            assert!(child.span.end <= node.span.end);
            assert!(previous_end <= child.span.start);
            assert!(child.span.start <= child.span.end);
            previous_end = child.span.end;
            assert_tree_spans(child);
        }
    }

    fn assert_document_opaque(source: &[u8]) {
        let parsed = parse_gcware(source).expect("bounded opaque document");
        assert_eq!(parsed.kind, GcwareParsedKind::Document);
        assert_eq!(parsed.span, 0..source.len());
        assert_eq!(parsed.children.len(), 1);
        assert_eq!(parsed.children[0].kind, GcwareParsedKind::Opaque);
        assert_eq!(source_span(source, &parsed.children[0]), source);
        assert!(parsed.children[0].sensitive);
    }

    #[test]
    fn documented_shape_is_nested_ordered_and_source_exact() {
        let source = b"totem {\n    version: 2\n    interface {\n        member {\n            memberaddr: 10.0.0.1\n        }\n        member {\n            memberaddr: 10.0.0.2\n        }\n        ringnumber: 0\n    }\n    leader_heartbeat:200\n    data_dir:/srv/gcware/data\n}\nlogging {\n    to_file: yes\n    logger {\n        ident: TEST\n        tags: enter|leave|trace\n    }\n}\n";
        let parsed = parse_gcware(source).expect("documented grammar");
        assert_eq!(parsed.kind, GcwareParsedKind::Document);
        assert_eq!(source_span(source, &parsed), source);
        assert_eq!(parsed.children.len(), 2);
        assert_eq!(nodes_named(&parsed, source, b"member").len(), 2);
        assert_eq!(nodes_named(&parsed, source, b"memberaddr").len(), 2);
        let version = nodes_named(&parsed, source, b"version")[0];
        assert_eq!(version.kind, GcwareParsedKind::Entry);
        assert_eq!(source_span(source, &version.children[0]), b"2");
        let heartbeat = nodes_named(&parsed, source, b"leader_heartbeat")[0];
        assert_eq!(source_span(source, &heartbeat.children[0]), b"200");
        let tags = nodes_named(&parsed, source, b"tags")[0];
        assert_eq!(source_span(source, &tags.children[0]), b"enter|leave|trace");
        assert_tree_spans(&parsed);
    }

    #[test]
    fn bom_crlf_tabs_and_missing_terminal_newline_preserve_spans() {
        let source = b"\xEF\xBB\xBFtotem {\r\n\tversion:\t2\r\n\tdata_dir:/srv/data\r\n}";
        let parsed = parse_gcware(source).unwrap();
        assert_eq!(source_span(source, &parsed), source);
        assert_eq!(parsed.children.len(), 1);
        assert_eq!(parsed.children[0].span, 0..source.len());
        assert_eq!(nodes_named(&parsed, source, b"version").len(), 1);
        assert_tree_spans(&parsed);
    }

    #[test]
    fn delimiter_free_unknown_lines_are_local_sensitive_opaque_atoms() {
        let source = b"totem {\n    before: one\n    @future syntax\n    # unproven comment syntax\n    after: two\n}\n";
        let parsed = parse_gcware(source).unwrap();
        assert_eq!(nodes_named(&parsed, source, b"before").len(), 1);
        assert_eq!(nodes_named(&parsed, source, b"after").len(), 1);
        let block = &parsed.children[0];
        let opaque = block
            .children
            .iter()
            .filter(|node| node.kind == GcwareParsedKind::Opaque)
            .collect::<Vec<_>>();
        assert_eq!(opaque.len(), 2);
        assert!(opaque.iter().all(|node| node.sensitive));
        assert_eq!(source_span(source, opaque[0]), b"    @future syntax\n");
        assert_eq!(
            source_span(source, opaque[1]),
            b"    # unproven comment syntax\n"
        );
        assert_tree_spans(&parsed);
    }

    #[test]
    fn uncertain_scalar_forms_are_atomic_without_hiding_siblings() {
        let source = b"totem {\n    before: one\n    quoted: \"unknown\"\n    escaped: hidden\\q\n    after: two\n}\n";
        let parsed = parse_gcware(source).unwrap();
        for key in [b"quoted".as_slice(), b"escaped".as_slice()] {
            let entry = nodes_named(&parsed, source, key)[0];
            assert_eq!(entry.kind, GcwareParsedKind::Entry);
            assert_eq!(entry.children[0].kind, GcwareParsedKind::Opaque);
            assert!(entry.children[0].sensitive);
        }
        assert_eq!(nodes_named(&parsed, source, b"after").len(), 1);
        assert_tree_spans(&parsed);
    }

    #[test]
    fn ambiguous_or_unbalanced_braces_fail_to_complete_opaque() {
        for source in [
            b"totem {\n    version: 2\n".as_slice(),
            b"}\n".as_slice(),
            b"totem{\n}\n".as_slice(),
            b"totem { trailing\n}\n".as_slice(),
            b"totem {\n    value: before { after\n}\n".as_slice(),
            b"totem {\n}\ntrailing }\n".as_slice(),
            b"totem {\0}\n".as_slice(),
        ] {
            assert_document_opaque(source);
        }
    }

    #[test]
    fn invalid_utf8_is_visible_as_complete_opaque() {
        assert_document_opaque(b"totem {\n value: \xff\n}\n");
    }

    #[test]
    fn sensitive_keys_blocks_and_carrier_values_propagate_once() {
        let source = b"credentials {\n    normal: hidden-by-parent\n}\ntotem {\n    password: NeverShow\n    endpoint:https://user:pass@example.test\n    secauth: off\n    nodeid: 7\n    memberaddr: 10.0.0.7\n}\n";
        let parsed = parse_gcware(source).unwrap();
        let credentials = nodes_named(&parsed, source, b"credentials")[0];
        assert!(credentials.sensitive);
        assert!(credentials.children.iter().all(|node| node.sensitive));
        let password = nodes_named(&parsed, source, b"password")[0];
        assert!(password.sensitive);
        assert!(password.children[0].sensitive);
        let endpoint = nodes_named(&parsed, source, b"endpoint")[0];
        assert!(!endpoint.sensitive);
        assert!(endpoint.children[0].sensitive);
        for safe in [
            b"secauth".as_slice(),
            b"nodeid".as_slice(),
            b"memberaddr".as_slice(),
        ] {
            let entry = nodes_named(&parsed, source, safe)[0];
            assert!(!entry.sensitive, "{safe:?}");
            assert!(!entry.children[0].sensitive, "{safe:?}");
        }
    }

    #[test]
    fn empty_and_whitespace_documents_are_bounded_and_structured() {
        for source in [b"".as_slice(), b" \t\r\n\n".as_slice()] {
            let parsed = parse_gcware(source).unwrap();
            assert_eq!(parsed.kind, GcwareParsedKind::Document);
            assert_eq!(parsed.span, 0..source.len());
            assert!(parsed.children.is_empty());
        }
    }

    #[test]
    fn byte_node_depth_and_token_limits_are_enforced() {
        let exact_bytes = vec![b' '; MAX_STRUCTURED_CONFIG_BYTES];
        assert!(parse_gcware(&exact_bytes).is_ok());
        assert!(parse_gcware(&vec![b' '; MAX_STRUCTURED_CONFIG_BYTES + 1]).is_err());

        let exact_entries = (MAX_STRUCTURED_CONFIG_NODES - 2) / 2;
        let mut exact_nodes = String::from("totem {\n");
        exact_nodes.push_str(&"k:v\n".repeat(exact_entries));
        exact_nodes.push_str("}\n");
        assert!(parse_gcware(exact_nodes.as_bytes()).is_ok());
        exact_nodes.insert_str(exact_nodes.len() - 2, "k:v\n");
        assert!(parse_gcware(exact_nodes.as_bytes()).is_err());

        let exact_depth = format!(
            "{}{}",
            "block {\n".repeat(MAX_STRUCTURED_CONFIG_DEPTH),
            "}\n".repeat(MAX_STRUCTURED_CONFIG_DEPTH)
        );
        assert!(parse_gcware(exact_depth.as_bytes()).is_ok());
        let over_depth = format!(
            "{}{}",
            "block {\n".repeat(MAX_STRUCTURED_CONFIG_DEPTH + 1),
            "}\n".repeat(MAX_STRUCTURED_CONFIG_DEPTH + 1)
        );
        assert!(parse_gcware(over_depth.as_bytes()).is_err());

        let exact_tokens = vec![b'\n'; MAX_STRUCTURED_CONFIG_TOKENS];
        assert!(parse_gcware(&exact_tokens).is_ok());
        assert!(parse_gcware(&vec![b'\n'; MAX_STRUCTURED_CONFIG_TOKENS + 1]).is_err());
    }

    #[test]
    fn every_exposed_name_and_child_span_stays_inside_its_owner() {
        let source =
            b"outer {\n    first: one\n    nested {\n        second: two:three\n    }\n}\n";
        let parsed = parse_gcware(source).unwrap();
        assert_tree_spans(&parsed);
        for name in [
            b"outer".as_slice(),
            b"first".as_slice(),
            b"nested".as_slice(),
            b"second".as_slice(),
        ] {
            let node = nodes_named(&parsed, source, name)[0];
            let name_span = node.name_span.as_ref().unwrap();
            assert!(node.span.start <= name_span.start);
            assert!(name_span.end <= node.span.end);
        }
        let second = nodes_named(&parsed, source, b"second")[0];
        assert_eq!(source_span(source, &second.children[0]), b"two:three");
        assert!(!contains_kind(&parsed, GcwareParsedKind::Opaque));
    }
}
