//! Bounded, source-backed YAML inspection for the structured configuration view.
//!
//! This parser deliberately recognizes only YAML constructs whose indentation and
//! token boundaries can be proven locally. Syntax with graph, schema, or multiline
//! semantics remains one source-backed opaque atom so the UI cannot present a
//! misleading editable-looking tree.

use std::ops::Range;

use crate::structured_config_visual::{
    MAX_STRUCTURED_CONFIG_BYTES, MAX_STRUCTURED_CONFIG_DEPTH, MAX_STRUCTURED_CONFIG_NODES,
    MAX_STRUCTURED_CONFIG_TOKENS,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum YamlParsedKind {
    Document,
    Mapping,
    Sequence,
    Pair,
    Scalar,
    Comment,
    Opaque,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct YamlParsedNode {
    pub(crate) kind: YamlParsedKind,
    pub(crate) span: Range<usize>,
    pub(crate) name_span: Option<Range<usize>>,
    pub(crate) sensitive: bool,
    pub(crate) children: Vec<YamlParsedNode>,
}

pub(crate) fn parse_yaml(source: &[u8]) -> Result<YamlParsedNode, ()> {
    if source.len() > MAX_STRUCTURED_CONFIG_BYTES {
        return Err(());
    }
    if source.is_empty() {
        return Ok(YamlParsedNode {
            kind: YamlParsedKind::Document,
            span: 0..0,
            name_span: None,
            sensitive: false,
            children: Vec::new(),
        });
    }
    if std::str::from_utf8(source).is_err() {
        return Ok(opaque_document(source.len()));
    }

    let lines = scan_lines(source)?;
    let mut parser = Parser {
        source,
        lines,
        nodes: 1,
        tokens: 0,
    };
    match parser.parse_stream() {
        Ok(root) => Ok(root),
        Err(ParseFailure::Syntax) => Ok(opaque_document(source.len())),
        Err(ParseFailure::Limit) => Err(()),
    }
}

#[derive(Clone, Debug)]
struct Line {
    start: usize,
    content_end: usize,
    end: usize,
    body_start: usize,
    significant_end: usize,
    indent: usize,
    trivia: bool,
    comment_only: bool,
    invalid_indent: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ParseFailure {
    Syntax,
    Limit,
}

type ParseResult<T> = Result<T, ParseFailure>;

struct Parser<'a> {
    source: &'a [u8],
    lines: Vec<Line>,
    nodes: usize,
    tokens: usize,
}

impl<'a> Parser<'a> {
    fn parse_stream(&mut self) -> ParseResult<YamlParsedNode> {
        let marker_lines = self
            .lines
            .iter()
            .enumerate()
            .filter_map(|(index, line)| self.is_start_marker(line).then_some(index))
            .collect::<Vec<_>>();
        let mut segments = Vec::new();
        if marker_lines.is_empty() {
            segments.push((0, self.lines.len(), None));
        } else {
            let explicit = marker_lines
                .iter()
                .copied()
                .enumerate()
                .map(|(ordinal, marker)| {
                    let lower = ordinal
                        .checked_sub(1)
                        .map_or(0, |previous| marker_lines[previous] + 1);
                    let mut start = marker;
                    while start > lower
                        && (self.lines[start - 1].trivia
                            || self.is_directive(&self.lines[start - 1]))
                    {
                        start -= 1;
                    }
                    (start, marker)
                })
                .collect::<Vec<_>>();
            if explicit[0].0 > 0 {
                segments.push((0, explicit[0].0, None));
            }
            for (ordinal, (start, marker)) in explicit.iter().copied().enumerate() {
                let end = explicit
                    .get(ordinal + 1)
                    .map(|(start, _)| *start)
                    .unwrap_or(self.lines.len());
                segments.push((start, end, Some(marker)));
            }
        }

        let mut documents = Vec::with_capacity(segments.len().max(1));
        for (segment_start, segment_end, marker) in segments {
            let document = self.parse_document(segment_start, segment_end, marker)?;
            documents.push(document);
        }
        if documents.is_empty() {
            self.bump_node()?;
            documents.push(YamlParsedNode {
                kind: YamlParsedKind::Document,
                span: 0..self.source.len(),
                name_span: None,
                sensitive: false,
                children: Vec::new(),
            });
        }
        Ok(YamlParsedNode {
            kind: YamlParsedKind::Document,
            span: 0..self.source.len(),
            name_span: None,
            sensitive: false,
            children: documents,
        })
    }

    fn parse_document(
        &mut self,
        segment_start: usize,
        segment_end: usize,
        marker: Option<usize>,
    ) -> ParseResult<YamlParsedNode> {
        self.ensure_depth(1)?;
        self.bump_node()?;
        let span_start = self.lines.get(segment_start).map_or(0, |line| line.start);
        let span_end = self
            .lines
            .get(segment_end.saturating_sub(1))
            .map_or(span_start, |line| line.end);
        let content_start = marker.map_or(segment_start, |index| index + 1);
        if self.lines[segment_start..segment_end]
            .iter()
            .any(|line| self.is_directive(line))
        {
            let opaque = self.opaque_node(span_start..span_end)?;
            return Ok(YamlParsedNode {
                kind: YamlParsedKind::Document,
                span: span_start..span_end,
                name_span: None,
                sensitive: false,
                children: vec![opaque],
            });
        }
        let mut content_end = segment_end;
        let mut end_marker = None;
        for index in content_start..segment_end {
            let line = &self.lines[index];
            if self.is_end_marker(line) {
                if end_marker.is_some() {
                    return Err(ParseFailure::Syntax);
                }
                end_marker = Some(index);
                content_end = index;
            } else if end_marker.is_some() && !line.trivia {
                return Err(ParseFailure::Syntax);
            }
        }

        if self.lines[content_start..content_end]
            .iter()
            .any(|line| line.invalid_indent)
        {
            let opaque = self.opaque_node(span_start..span_end)?;
            return Ok(YamlParsedNode {
                kind: YamlParsedKind::Document,
                span: span_start..span_end,
                name_span: None,
                sensitive: false,
                children: vec![opaque],
            });
        }

        let first = self.next_content(content_start, content_end);
        let mut children = if let Some(first) = first {
            if self.lines[first].indent != 0 {
                vec![self.opaque_node(span_start..span_end)?]
            } else {
                match self.parse_block(first, content_end, 0, 2) {
                    Ok((node, cursor)) => {
                        if self.next_content(cursor, content_end).is_some() {
                            vec![self.opaque_node(span_start..span_end)?]
                        } else {
                            vec![node]
                        }
                    }
                    Err(ParseFailure::Syntax) => vec![self.opaque_node(span_start..span_end)?],
                    Err(ParseFailure::Limit) => return Err(ParseFailure::Limit),
                }
            }
        } else {
            Vec::new()
        };
        let comments = self.lines[segment_start..segment_end]
            .iter()
            .filter(|line| line.comment_only)
            .map(|line| {
                (
                    line.start..line.end,
                    contains_sensitive_comment(&self.source[line.body_start..line.content_end]),
                )
            })
            .collect::<Vec<_>>();
        for (span, sensitive) in comments {
            if contains_opaque_span(&children, &span) {
                continue;
            }
            self.bump_node()?;
            self.bump_tokens(1)?;
            insert_comment(
                &mut children,
                YamlParsedNode {
                    kind: YamlParsedKind::Comment,
                    span,
                    name_span: None,
                    sensitive,
                    children: Vec::new(),
                },
            );
        }
        sort_children(&mut children);
        Ok(YamlParsedNode {
            kind: YamlParsedKind::Document,
            span: span_start..span_end,
            name_span: None,
            sensitive: false,
            children,
        })
    }

    fn parse_block(
        &mut self,
        start: usize,
        end: usize,
        indent: usize,
        depth: usize,
    ) -> ParseResult<(YamlParsedNode, usize)> {
        self.ensure_depth(depth)?;
        let first = self.next_content(start, end).ok_or(ParseFailure::Syntax)?;
        let line = &self.lines[first];
        if line.indent != indent {
            return Err(ParseFailure::Syntax);
        }
        let body = self.significant(line);
        if is_sequence_indicator(body) {
            self.parse_sequence(first, end, indent, depth)
        } else if find_mapping_colon(body).is_some() || begins_complex_key(body) {
            self.parse_mapping(first, end, indent, depth)
        } else {
            self.parse_root_scalar(first, end, indent, depth)
        }
    }

    fn parse_mapping(
        &mut self,
        start: usize,
        end: usize,
        indent: usize,
        depth: usize,
    ) -> ParseResult<(YamlParsedNode, usize)> {
        self.ensure_depth(depth)?;
        self.bump_node()?;
        let first_start = self.lines[start].start;
        let mut cursor = start;
        let mut children = Vec::new();
        let mut last_end = self.lines[start].end;
        loop {
            let Some(index) = self.next_content(cursor, end) else {
                cursor = end;
                break;
            };
            let line = &self.lines[index];
            if line.indent < indent {
                cursor = index;
                break;
            }
            if line.indent > indent || is_sequence_indicator(self.significant(line)) {
                return Err(ParseFailure::Syntax);
            }
            let (pair, next) = self.parse_pair(index, end, indent, depth + 1)?;
            last_end = pair.span.end;
            children.push(pair);
            cursor = next;
        }
        if children.is_empty() {
            return Err(ParseFailure::Syntax);
        }
        Ok((
            YamlParsedNode {
                kind: YamlParsedKind::Mapping,
                span: first_start..last_end,
                name_span: None,
                sensitive: false,
                children,
            },
            cursor,
        ))
    }

    fn parse_pair(
        &mut self,
        index: usize,
        end: usize,
        indent: usize,
        depth: usize,
    ) -> ParseResult<(YamlParsedNode, usize)> {
        self.ensure_depth(depth)?;
        let line = self.lines[index].clone();
        let body = self.significant(&line);
        if begins_complex_key(body) {
            return self.opaque_complex_key_construct(index, end, indent, depth);
        }
        let colon = find_mapping_colon(body).ok_or(ParseFailure::Syntax)?;
        let key_end = trim_ascii_end(&body[..colon]).len();
        let key = &body[..key_end];
        if !is_simple_key(key) || key == b"<<" {
            return self.opaque_construct(index, end, indent, depth);
        }
        self.bump_tokens(2)?;
        self.bump_node()?;

        let key_start = line.body_start;
        let name_span = key_start..key_start + key.len();
        let value_from = line.body_start + colon + 1;
        let value_start = skip_ascii_space(self.source, value_from, line.significant_end);
        let sensitive_key = contains_sensitive_identifier(key);
        let next_content = self.next_content(index + 1, end);
        let mut cursor = index + 1;
        let mut children = Vec::new();
        let mut span_end = line.end;

        if value_start < line.significant_end {
            let value = &self.source[value_start..line.significant_end];
            if classify_advanced(value) {
                let (opaque, next) =
                    self.opaque_value_construct(value_start, index, end, indent, depth + 1)?;
                span_end = opaque.span.end;
                children.push(opaque);
                cursor = next;
            } else {
                validate_simple_scalar(value)?;
                self.ensure_depth(depth + 1)?;
                self.bump_tokens(1)?;
                self.bump_node()?;
                let scalar_sensitive = sensitive_key || contains_sensitive_scalar(value);
                children.push(YamlParsedNode {
                    kind: YamlParsedKind::Scalar,
                    span: value_start..line.significant_end,
                    name_span: None,
                    sensitive: scalar_sensitive,
                    children: Vec::new(),
                });
                if next_content.is_some_and(|next| self.lines[next].indent > indent) {
                    return Err(ParseFailure::Syntax);
                }
            }
        } else if let Some(next) = next_content
            && self.lines[next].indent > indent
        {
            let child_indent = self.lines[next].indent;
            let (mut child, after_child) = self.parse_block(next, end, child_indent, depth + 1)?;
            if sensitive_key {
                mark_sensitive(&mut child);
            }
            span_end = child.span.end;
            children.push(child);
            cursor = after_child;
        }
        Ok((
            YamlParsedNode {
                kind: YamlParsedKind::Pair,
                span: line.start..span_end,
                name_span: Some(name_span),
                sensitive: sensitive_key,
                children,
            },
            cursor,
        ))
    }

    fn parse_sequence(
        &mut self,
        start: usize,
        end: usize,
        indent: usize,
        depth: usize,
    ) -> ParseResult<(YamlParsedNode, usize)> {
        self.ensure_depth(depth)?;
        self.bump_node()?;
        let first_start = self.lines[start].start;
        let mut cursor = start;
        let mut children = Vec::new();
        let mut last_end = self.lines[start].end;
        loop {
            let Some(index) = self.next_content(cursor, end) else {
                cursor = end;
                break;
            };
            let line = self.lines[index].clone();
            if line.indent < indent {
                cursor = index;
                break;
            }
            if line.indent > indent {
                return Err(ParseFailure::Syntax);
            }
            let body = self.significant(&line);
            if !is_sequence_indicator(body) {
                cursor = index;
                break;
            }
            self.bump_tokens(1)?;
            let remainder_from = line.body_start + 1;
            let value_start = skip_ascii_space(self.source, remainder_from, line.significant_end);
            let (item, next) = if value_start == line.significant_end {
                if let Some(nested) = self.next_content(index + 1, end) {
                    if self.lines[nested].indent > indent {
                        let child_indent = self.lines[nested].indent;
                        self.parse_block(nested, end, child_indent, depth + 1)?
                    } else {
                        self.empty_scalar(line.significant_end, index + 1, depth + 1)?
                    }
                } else {
                    self.empty_scalar(line.significant_end, index + 1, depth + 1)?
                }
            } else {
                let value = &self.source[value_start..line.significant_end];
                if find_mapping_colon(value).is_some() || begins_complex_key(value) {
                    self.parse_sequence_mapping_item(index, end, indent, value_start, depth + 1)?
                } else if classify_advanced(value) {
                    self.opaque_value_construct(value_start, index, end, indent, depth + 1)?
                } else {
                    validate_simple_scalar(value)?;
                    self.ensure_depth(depth + 1)?;
                    self.bump_tokens(1)?;
                    self.bump_node()?;
                    if self
                        .next_content(index + 1, end)
                        .is_some_and(|next| self.lines[next].indent > indent)
                    {
                        return Err(ParseFailure::Syntax);
                    }
                    (
                        YamlParsedNode {
                            kind: YamlParsedKind::Scalar,
                            span: value_start..line.significant_end,
                            name_span: None,
                            sensitive: contains_sensitive_scalar(value),
                            children: Vec::new(),
                        },
                        index + 1,
                    )
                }
            };
            last_end = item.span.end.max(line.end);
            children.push(item);
            cursor = next;
        }
        if children.is_empty() {
            return Err(ParseFailure::Syntax);
        }
        Ok((
            YamlParsedNode {
                kind: YamlParsedKind::Sequence,
                span: first_start..last_end,
                name_span: None,
                sensitive: false,
                children,
            },
            cursor,
        ))
    }

    fn parse_sequence_mapping_item(
        &mut self,
        index: usize,
        end: usize,
        sequence_indent: usize,
        value_start: usize,
        depth: usize,
    ) -> ParseResult<(YamlParsedNode, usize)> {
        self.ensure_depth(depth)?;
        let line = self.lines[index].clone();
        let value = &self.source[value_start..line.significant_end];
        let colon = find_mapping_colon(value).ok_or(ParseFailure::Syntax)?;
        let key_end = trim_ascii_end(&value[..colon]).len();
        let key = &value[..key_end];
        let conceptual_indent = sequence_indent.checked_add(2).ok_or(ParseFailure::Limit)?;
        if begins_complex_key(value) || !is_simple_key(key) || key == b"<<" {
            return self.opaque_value_construct(value_start, index, end, sequence_indent, depth);
        }

        self.bump_node()?;
        self.bump_node()?;
        self.bump_tokens(2)?;
        let name_span = value_start..value_start + key.len();
        let scalar_start =
            skip_ascii_space(self.source, value_start + colon + 1, line.significant_end);
        let sensitive_key = contains_sensitive_identifier(key);
        let mut pair_children = Vec::new();
        let mut pair_end = line.end;
        let mut cursor = index + 1;
        if scalar_start < line.significant_end {
            let scalar = &self.source[scalar_start..line.significant_end];
            if classify_advanced(scalar) {
                let (opaque, next) = self.opaque_value_construct(
                    scalar_start,
                    index,
                    end,
                    conceptual_indent,
                    depth + 2,
                )?;
                pair_end = opaque.span.end;
                pair_children.push(opaque);
                cursor = next;
            } else {
                validate_simple_scalar(scalar)?;
                self.ensure_depth(depth + 2)?;
                self.bump_node()?;
                self.bump_tokens(1)?;
                pair_children.push(YamlParsedNode {
                    kind: YamlParsedKind::Scalar,
                    span: scalar_start..line.significant_end,
                    name_span: None,
                    sensitive: sensitive_key || contains_sensitive_scalar(scalar),
                    children: Vec::new(),
                });
            }
        } else if let Some(next) = self.next_content(index + 1, end)
            && self.lines[next].indent > conceptual_indent
        {
            let child_indent = self.lines[next].indent;
            let (mut child, after_child) = self.parse_block(next, end, child_indent, depth + 2)?;
            if sensitive_key {
                mark_sensitive(&mut child);
            }
            pair_end = child.span.end;
            pair_children.push(child);
            cursor = after_child;
        }
        let first_pair = YamlParsedNode {
            kind: YamlParsedKind::Pair,
            span: line.start..pair_end,
            name_span: Some(name_span),
            sensitive: sensitive_key,
            children: pair_children,
        };
        let mut pairs = vec![first_pair];

        if let Some(next) = self.next_content(cursor, end)
            && self.lines[next].indent > sequence_indent
        {
            if self.lines[next].indent != conceptual_indent
                || is_sequence_indicator(self.significant(&self.lines[next]))
            {
                return Err(ParseFailure::Syntax);
            }
            let (continuation, after) =
                self.parse_mapping(next, end, conceptual_indent, depth + 1)?;
            pairs.extend(continuation.children);
            pair_end = continuation.span.end;
            cursor = after;
        }
        Ok((
            YamlParsedNode {
                kind: YamlParsedKind::Mapping,
                span: line.start..pair_end,
                name_span: None,
                sensitive: false,
                children: pairs,
            },
            cursor,
        ))
    }

    fn parse_root_scalar(
        &mut self,
        index: usize,
        end: usize,
        indent: usize,
        depth: usize,
    ) -> ParseResult<(YamlParsedNode, usize)> {
        let line = self.lines[index].clone();
        let value = self.significant(&line);
        if value.is_empty() {
            return Err(ParseFailure::Syntax);
        }
        if classify_advanced(value) {
            return self.opaque_value_construct(line.body_start, index, end, indent, depth);
        }
        validate_simple_scalar(value)?;
        if self.next_content(index + 1, end).is_some() {
            return Err(ParseFailure::Syntax);
        }
        self.bump_node()?;
        self.bump_tokens(1)?;
        Ok((
            YamlParsedNode {
                kind: YamlParsedKind::Scalar,
                span: line.body_start..line.significant_end,
                name_span: None,
                sensitive: contains_sensitive_scalar(value),
                children: Vec::new(),
            },
            index + 1,
        ))
    }

    fn empty_scalar(
        &mut self,
        offset: usize,
        next: usize,
        depth: usize,
    ) -> ParseResult<(YamlParsedNode, usize)> {
        self.ensure_depth(depth)?;
        self.bump_node()?;
        Ok((
            YamlParsedNode {
                kind: YamlParsedKind::Scalar,
                span: offset..offset,
                name_span: None,
                sensitive: false,
                children: Vec::new(),
            },
            next,
        ))
    }

    fn opaque_construct(
        &mut self,
        index: usize,
        end: usize,
        indent: usize,
        depth: usize,
    ) -> ParseResult<(YamlParsedNode, usize)> {
        let start = self.lines[index].start;
        let (span_end, next) = self.consume_indented(index, end, indent);
        Ok((self.opaque_node_at_depth(start..span_end, depth)?, next))
    }

    fn opaque_complex_key_construct(
        &mut self,
        index: usize,
        end: usize,
        indent: usize,
        depth: usize,
    ) -> ParseResult<(YamlParsedNode, usize)> {
        let start = self.lines[index].start;
        let (mut span_end, mut next) = self.consume_indented(index, end, indent);
        if let Some(value_line) = self.next_content(next, end) {
            let value = self.significant(&self.lines[value_line]);
            if self.lines[value_line].indent == indent
                && value.first() == Some(&b':')
                && value.get(1).is_none_or(|byte| byte.is_ascii_whitespace())
            {
                (span_end, next) = self.consume_indented(value_line, end, indent);
            }
        }
        Ok((self.opaque_node_at_depth(start..span_end, depth)?, next))
    }

    fn opaque_value_construct(
        &mut self,
        value_start: usize,
        index: usize,
        end: usize,
        parent_indent: usize,
        depth: usize,
    ) -> ParseResult<(YamlParsedNode, usize)> {
        let (span_end, next) = self.consume_indented(index, end, parent_indent);
        Ok((
            self.opaque_node_at_depth(value_start..span_end, depth)?,
            next,
        ))
    }

    fn consume_indented(&self, index: usize, end: usize, parent_indent: usize) -> (usize, usize) {
        let mut cursor = index + 1;
        let mut span_end = self.lines[index].end;
        while cursor < end {
            let line = &self.lines[cursor];
            if line.trivia {
                if line.comment_only && line.indent <= parent_indent {
                    break;
                }
                span_end = line.end;
                cursor += 1;
                continue;
            }
            if line.indent <= parent_indent {
                break;
            }
            span_end = line.end;
            cursor += 1;
        }
        (span_end, cursor)
    }

    fn opaque_node(&mut self, span: Range<usize>) -> ParseResult<YamlParsedNode> {
        self.opaque_node_at_depth(span, 2)
    }

    fn opaque_node_at_depth(
        &mut self,
        span: Range<usize>,
        depth: usize,
    ) -> ParseResult<YamlParsedNode> {
        self.ensure_depth(depth)?;
        self.bump_node()?;
        self.bump_tokens(1)?;
        Ok(YamlParsedNode {
            kind: YamlParsedKind::Opaque,
            span,
            name_span: None,
            sensitive: true,
            children: Vec::new(),
        })
    }

    fn next_content(&self, mut index: usize, end: usize) -> Option<usize> {
        while index < end && self.lines[index].trivia {
            index += 1;
        }
        (index < end).then_some(index)
    }

    fn significant(&self, line: &Line) -> &'a [u8] {
        &self.source[line.body_start..line.significant_end]
    }

    fn is_start_marker(&self, line: &Line) -> bool {
        line.indent == 0 && self.significant(line) == b"---"
    }

    fn is_end_marker(&self, line: &Line) -> bool {
        line.indent == 0 && self.significant(line) == b"..."
    }

    fn is_directive(&self, line: &Line) -> bool {
        line.indent == 0 && self.significant(line).first() == Some(&b'%')
    }

    fn bump_node(&mut self) -> ParseResult<()> {
        self.nodes = self.nodes.checked_add(1).ok_or(ParseFailure::Limit)?;
        if self.nodes > MAX_STRUCTURED_CONFIG_NODES {
            return Err(ParseFailure::Limit);
        }
        Ok(())
    }

    fn bump_tokens(&mut self, count: usize) -> ParseResult<()> {
        self.tokens = self.tokens.checked_add(count).ok_or(ParseFailure::Limit)?;
        if self.tokens > MAX_STRUCTURED_CONFIG_TOKENS {
            return Err(ParseFailure::Limit);
        }
        Ok(())
    }

    fn ensure_depth(&self, depth: usize) -> ParseResult<()> {
        if depth > MAX_STRUCTURED_CONFIG_DEPTH {
            return Err(ParseFailure::Limit);
        }
        Ok(())
    }
}

fn scan_lines(source: &[u8]) -> Result<Vec<Line>, ()> {
    let mut lines = Vec::new();
    let mut start = 0;
    while start < source.len() {
        if lines.len() >= MAX_STRUCTURED_CONFIG_TOKENS {
            return Err(());
        }
        let newline = source[start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|relative| start + relative);
        let end = newline.map_or(source.len(), |index| index + 1);
        let mut content_end = newline.unwrap_or(source.len());
        if content_end > start && source[content_end - 1] == b'\r' {
            content_end -= 1;
        }
        let mut body_start = start;
        if start == 0 && source.starts_with(b"\xEF\xBB\xBF") {
            body_start = 3;
        }
        let mut indent = 0;
        let mut invalid_indent = false;
        while body_start < content_end {
            match source[body_start] {
                b' ' => {
                    indent += 1;
                    body_start += 1;
                }
                b'\t' => {
                    invalid_indent = true;
                    body_start += 1;
                }
                _ => break,
            }
        }
        let comment = find_comment(&source[body_start..content_end])
            .map(|relative| body_start + relative)
            .unwrap_or(content_end);
        let significant_end = trim_ascii_end(&source[body_start..comment]).len() + body_start;
        let comment_only = source.get(body_start).is_some_and(|byte| *byte == b'#');
        let trivia = significant_end == body_start;
        lines.push(Line {
            start,
            content_end,
            end,
            body_start,
            significant_end,
            indent,
            trivia,
            comment_only,
            invalid_indent,
        });
        start = end;
    }
    Ok(lines)
}

fn find_comment(value: &[u8]) -> Option<usize> {
    let mut quote = None;
    let mut escaped = false;
    let mut index = 0;
    while index < value.len() {
        let byte = value[index];
        match quote {
            Some(b'"') => {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    quote = None;
                }
            }
            Some(b'\'') => {
                if byte == b'\'' {
                    if value.get(index + 1) == Some(&b'\'') {
                        index += 1;
                    } else {
                        quote = None;
                    }
                }
            }
            _ if matches!(byte, b'"' | b'\'') => quote = Some(byte),
            _ if byte == b'#' && (index == 0 || value[index - 1].is_ascii_whitespace()) => {
                return Some(index);
            }
            _ => {}
        }
        index += 1;
    }
    None
}

fn find_mapping_colon(value: &[u8]) -> Option<usize> {
    let mut quote = None;
    let mut escaped = false;
    let mut index = 0;
    while index < value.len() {
        let byte = value[index];
        match quote {
            Some(b'"') => {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    quote = None;
                }
            }
            Some(b'\'') => {
                if byte == b'\'' {
                    if value.get(index + 1) == Some(&b'\'') {
                        index += 1;
                    } else {
                        quote = None;
                    }
                }
            }
            _ if matches!(byte, b'"' | b'\'') => quote = Some(byte),
            _ if byte == b':'
                && value
                    .get(index + 1)
                    .is_none_or(|next| next.is_ascii_whitespace()) =>
            {
                return Some(index);
            }
            _ => {}
        }
        index += 1;
    }
    None
}

fn validate_simple_scalar(value: &[u8]) -> ParseResult<()> {
    if value.is_empty() {
        return Err(ParseFailure::Syntax);
    }
    match value[0] {
        b'"' => validate_double_quoted(value),
        b'\'' => validate_single_quoted(value),
        b'?' | b':' if value.get(1).is_none_or(|byte| byte.is_ascii_whitespace()) => {
            Err(ParseFailure::Syntax)
        }
        b'@' | b'`' => Err(ParseFailure::Syntax),
        _ => {
            if value
                .iter()
                .any(|byte| matches!(*byte, b'\r' | b'\n' | b'\t'))
            {
                return Err(ParseFailure::Syntax);
            }
            Ok(())
        }
    }
}

fn validate_double_quoted(value: &[u8]) -> ParseResult<()> {
    if value.last() != Some(&b'"') || value.len() < 2 {
        return Err(ParseFailure::Syntax);
    }
    let mut escaped = false;
    for (index, byte) in value.iter().copied().enumerate().skip(1) {
        if escaped {
            escaped = false;
            continue;
        }
        if byte == b'\\' {
            escaped = true;
        } else if byte == b'"' && index + 1 != value.len() {
            return Err(ParseFailure::Syntax);
        }
    }
    (!escaped).then_some(()).ok_or(ParseFailure::Syntax)
}

fn validate_single_quoted(value: &[u8]) -> ParseResult<()> {
    if value.last() != Some(&b'\'') || value.len() < 2 {
        return Err(ParseFailure::Syntax);
    }
    let mut index = 1;
    while index + 1 < value.len() {
        if value[index] == b'\'' {
            if value.get(index + 1) == Some(&b'\'') {
                index += 2;
                continue;
            }
            return Err(ParseFailure::Syntax);
        }
        index += 1;
    }
    Ok(())
}

fn classify_advanced(value: &[u8]) -> bool {
    let trimmed = trim_ascii(value);
    if trimmed.is_empty() {
        return false;
    }
    if matches!(trimmed.first(), Some(b'|' | b'>'))
        || (trimmed.first() == Some(&b'"') && trimmed.contains(&b'\\'))
        || matches!(trimmed[0], b'&' | b'*' | b'!')
        || begins_complex_key(trimmed)
        || contains_unquoted_flow(trimmed)
    {
        return true;
    }
    contains_graph_indicator(trimmed)
}

fn contains_unquoted_flow(value: &[u8]) -> bool {
    outside_quotes(value, |byte| matches!(byte, b'[' | b']' | b'{' | b'}'))
}

fn contains_graph_indicator(value: &[u8]) -> bool {
    let mut at_token_start = true;
    let mut quote = None;
    let mut escaped = false;
    for byte in value.iter().copied() {
        match quote {
            Some(b'"') => {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    quote = None;
                }
            }
            Some(b'\'') => {
                if byte == b'\'' {
                    quote = None;
                }
            }
            _ if matches!(byte, b'"' | b'\'') => quote = Some(byte),
            _ if at_token_start && matches!(byte, b'&' | b'*' | b'!') => return true,
            _ => {}
        }
        at_token_start = byte.is_ascii_whitespace();
    }
    false
}

fn outside_quotes(value: &[u8], predicate: impl Fn(u8) -> bool) -> bool {
    let mut quote = None;
    let mut escaped = false;
    let mut index = 0;
    while index < value.len() {
        let byte = value[index];
        match quote {
            Some(b'"') => {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    quote = None;
                }
            }
            Some(b'\'') => {
                if byte == b'\'' {
                    if value.get(index + 1) == Some(&b'\'') {
                        index += 1;
                    } else {
                        quote = None;
                    }
                }
            }
            _ if matches!(byte, b'"' | b'\'') => quote = Some(byte),
            _ if predicate(byte) => return true,
            _ => {}
        }
        index += 1;
    }
    false
}

fn begins_complex_key(value: &[u8]) -> bool {
    value.first() == Some(&b'?') && value.get(1).is_none_or(|byte| byte.is_ascii_whitespace())
}

fn is_sequence_indicator(value: &[u8]) -> bool {
    value.first() == Some(&b'-') && value.get(1).is_none_or(|byte| byte.is_ascii_whitespace())
}

fn is_simple_key(value: &[u8]) -> bool {
    !value.is_empty()
        && value
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-' | b'.'))
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
        || lower.windows(6).any(|part| part == b"token=")
        || lower.windows(7).any(|part| part == b"secret=")
        || (lower.windows(3).any(|part| part == b"://") && lower.contains(&b'@'))
}

fn mark_sensitive(node: &mut YamlParsedNode) {
    node.sensitive = true;
    for child in &mut node.children {
        mark_sensitive(child);
    }
}

fn insert_comment(nodes: &mut Vec<YamlParsedNode>, comment: YamlParsedNode) {
    if let Some(container) = nodes.iter_mut().find(|node| {
        matches!(
            node.kind,
            YamlParsedKind::Document
                | YamlParsedKind::Mapping
                | YamlParsedKind::Sequence
                | YamlParsedKind::Pair
        ) && node.span.start <= comment.span.start
            && comment.span.end <= node.span.end
    }) {
        insert_comment(&mut container.children, comment);
    } else {
        nodes.push(comment);
    }
}

fn contains_opaque_span(nodes: &[YamlParsedNode], span: &Range<usize>) -> bool {
    nodes.iter().any(|node| {
        (node.kind == YamlParsedKind::Opaque
            && node.span.start <= span.start
            && span.end <= node.span.end)
            || contains_opaque_span(&node.children, span)
    })
}

fn sort_children(nodes: &mut [YamlParsedNode]) {
    nodes.sort_by_key(|node| (node.span.start, node.span.end));
    for node in nodes {
        sort_children(&mut node.children);
    }
}

fn contains_sensitive_comment(value: &[u8]) -> bool {
    let normalized = value
        .iter()
        .map(u8::to_ascii_lowercase)
        .filter(|byte| byte.is_ascii_alphanumeric())
        .collect::<Vec<_>>();
    [
        b"password".as_slice(),
        b"passwd".as_slice(),
        b"token".as_slice(),
        b"privatekey".as_slice(),
        b"connectionstring".as_slice(),
    ]
    .iter()
    .any(|marker| normalized.windows(marker.len()).any(|part| part == *marker))
}

fn opaque_document(length: usize) -> YamlParsedNode {
    YamlParsedNode {
        kind: YamlParsedKind::Document,
        span: 0..length,
        name_span: None,
        sensitive: false,
        children: if length == 0 {
            Vec::new()
        } else {
            vec![YamlParsedNode {
                kind: YamlParsedKind::Opaque,
                span: 0..length,
                name_span: None,
                sensitive: true,
                children: Vec::new(),
            }]
        },
    }
}

fn trim_ascii(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(value.len());
    trim_ascii_end(&value[start..])
}

fn trim_ascii_end(value: &[u8]) -> &[u8] {
    let end = value
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(0, |index| index + 1);
    &value[..end]
}

fn skip_ascii_space(source: &[u8], mut start: usize, end: usize) -> usize {
    while start < end && matches!(source[start], b' ' | b'\t') {
        start += 1;
    }
    start
}

#[cfg(test)]
mod tests {
    use super::*;

    fn semantic_root(parsed: &YamlParsedNode) -> &YamlParsedNode {
        let document = parsed.children.first().expect("stream document");
        document
            .children
            .iter()
            .find(|node| node.kind != YamlParsedKind::Comment)
            .expect("semantic root")
    }

    fn source_span<'a>(source: &'a [u8], node: &YamlParsedNode) -> &'a [u8] {
        &source[node.span.clone()]
    }

    #[test]
    fn parses_crlf_bom_mapping_comments_and_duplicate_keys_in_order() {
        let source = b"\xEF\xBB\xBF# heading\r\na: one # comment\r\na: \"two:#\"\r\nnested:\r\n  child: 'yes'\r\n";
        let parsed = parse_yaml(source).expect("parse");
        assert_eq!(parsed.span, 0..source.len());
        let mapping = semantic_root(&parsed);
        assert_eq!(mapping.kind, YamlParsedKind::Mapping);
        assert_eq!(mapping.children.len(), 3);
        assert_eq!(
            source_span(source, &mapping.children[0]),
            b"a: one # comment\r\n"
        );
        assert_eq!(
            source_span(source, &mapping.children[1]),
            b"a: \"two:#\"\r\n"
        );
        assert_eq!(
            mapping.children[0]
                .name_span
                .as_ref()
                .map(|span| &source[span.clone()]),
            Some(b"a".as_slice())
        );
        assert_eq!(
            mapping.children[2].children[0].kind,
            YamlParsedKind::Mapping
        );
    }

    #[test]
    fn parses_block_sequence_and_inline_mapping_items() {
        let source = b"servers:\n  - name: first\n    port: 3306\n  - name: second\n    flags:\n      - safe\n      - quoted\n";
        let parsed = parse_yaml(source).unwrap();
        let mapping = semantic_root(&parsed);
        let sequence = &mapping.children[0].children[0];
        assert_eq!(sequence.kind, YamlParsedKind::Sequence);
        assert_eq!(sequence.children.len(), 2);
        assert_eq!(sequence.children[0].kind, YamlParsedKind::Mapping);
        assert_eq!(sequence.children[0].children.len(), 2);
        let nested = &sequence.children[1].children[1].children[0];
        assert_eq!(nested.kind, YamlParsedKind::Sequence);
        assert_eq!(nested.children.len(), 2);
        assert_tree_spans(&parsed);
    }

    #[test]
    fn separates_explicit_and_implicit_documents() {
        let source = b"first: 1\n---\nsecond: 2\n...\n# between\n---\nthird: 3\n";
        let parsed = parse_yaml(source).unwrap();
        assert_eq!(parsed.children.len(), 3);
        for document in &parsed.children {
            assert_eq!(document.kind, YamlParsedKind::Document);
            assert_eq!(
                document
                    .children
                    .iter()
                    .filter(|node| node.kind == YamlParsedKind::Mapping)
                    .count(),
                1
            );
        }
        assert!(parsed.children[0].span.end <= parsed.children[1].span.start);
        assert!(parsed.children[1].span.end <= parsed.children[2].span.start);
    }

    #[test]
    fn block_scalars_are_complete_opaque_atoms_without_swallowing_siblings() {
        for header in ["|", ">", "|-", ">2+"] {
            let text = format!(
                "before: ok\nscript: {header}\n  password: not-a-key\n  line two\nafter: safe\n"
            );
            let parsed = parse_yaml(text.as_bytes()).unwrap();
            let mapping = semantic_root(&parsed);
            assert_eq!(mapping.children.len(), 3);
            let opaque = &mapping.children[1].children[0];
            assert_eq!(opaque.kind, YamlParsedKind::Opaque);
            assert!(opaque.sensitive);
            assert_eq!(
                source_span(text.as_bytes(), opaque),
                format!("{header}\n  password: not-a-key\n  line two\n").as_bytes()
            );
            assert_eq!(
                mapping.children[2]
                    .name_span
                    .as_ref()
                    .map(|span| &text.as_bytes()[span.clone()]),
                Some(b"after".as_slice())
            );
        }
    }

    #[test]
    fn comments_claimed_by_opaque_blocks_are_not_overlapping_nodes() {
        let source = b"before: ok\nscript: |\n  # literal block content\n  ok\n# outside note\nafter: safe\n";
        let parsed = parse_yaml(source).unwrap();
        let mapping = semantic_root(&parsed);
        let opaque = &mapping.children[1].children[0];
        assert_eq!(opaque.kind, YamlParsedKind::Opaque);
        assert!(source_span(source, opaque).ends_with(b"  ok\n"));
        let comments = collect_kind(&parsed, YamlParsedKind::Comment);
        assert_eq!(comments.len(), 1);
        assert_eq!(source_span(source, comments[0]), b"# outside note\n");
        assert_tree_spans(&parsed);
    }

    #[test]
    fn uncertain_quoted_escapes_and_invalid_block_headers_are_atomic_opaque() {
        for advanced in [r#""bad\q""#, "|bogus"] {
            let text = format!("before: ok\nkey: {advanced}\nafter: safe\n");
            let parsed = parse_yaml(text.as_bytes()).unwrap();
            let mapping = semantic_root(&parsed);
            assert_eq!(mapping.children.len(), 3);
            let opaque = &mapping.children[1].children[0];
            assert_eq!(opaque.kind, YamlParsedKind::Opaque);
            assert!(opaque.sensitive);
            assert_eq!(
                source_span(text.as_bytes(), opaque),
                format!("{advanced}\n").as_bytes()
            );
            assert_eq!(
                mapping.children[2]
                    .name_span
                    .as_ref()
                    .map(|span| &text.as_bytes()[span.clone()]),
                Some(b"after".as_slice())
            );
            assert_tree_spans(&parsed);
        }
    }

    #[test]
    fn anchors_aliases_tags_merges_and_flow_values_are_atomic_opaque() {
        let source = b"safe: first\ndefaults: &base\n  user: root\ncopy: *base\ntagged: !vault secret\nmerge:\n  <<: *base\nflow_map: {a: 1}\nflow_seq: [a, b]\nafter: last\n";
        let parsed = parse_yaml(source).unwrap();
        let mapping = semantic_root(&parsed);
        assert_eq!(mapping.children.len(), 8);
        for index in 1..7 {
            assert!(contains_kind(
                &mapping.children[index],
                YamlParsedKind::Opaque
            ));
        }
        assert_eq!(
            mapping.children[7]
                .name_span
                .as_ref()
                .map(|span| &source[span.clone()]),
            Some(b"after".as_slice())
        );
    }

    #[test]
    fn quoted_or_escaped_keys_and_complex_keys_are_opaque_constructs() {
        let source = b"safe: one\n\"pass\\u0077ord\": hidden\n  nested: hidden-too\n? [complex, key]\n: value\nafter: two\n";
        let parsed = parse_yaml(source).unwrap();
        let mapping = semantic_root(&parsed);
        assert_eq!(mapping.children[0].kind, YamlParsedKind::Pair);
        assert_eq!(mapping.children[1].kind, YamlParsedKind::Opaque);
        assert!(mapping.children[1].sensitive);
        assert!(source_span(source, &mapping.children[1]).ends_with(b"nested: hidden-too\n"));
        assert_eq!(mapping.children[2].kind, YamlParsedKind::Opaque);
        assert_eq!(mapping.children[3].kind, YamlParsedKind::Pair);
    }

    #[test]
    fn tabs_bad_dedent_and_plain_multiline_fail_to_document_opaque() {
        for source in [
            b"a:\n\tchild: value\n".as_slice(),
            b"a:\n    child: value\n  bad: value\n".as_slice(),
            b"a: one\ncontinued plain scalar\n".as_slice(),
        ] {
            let parsed = parse_yaml(source).unwrap();
            let document = &parsed.children[0];
            assert_eq!(document.children.len(), 1);
            assert_eq!(document.children[0].kind, YamlParsedKind::Opaque);
            assert_eq!(source_span(source, &document.children[0]), source);
            assert!(document.children[0].sensitive);
        }
    }

    #[test]
    fn directives_and_invalid_utf8_fail_visible_and_byte_exact() {
        for source in [
            b"%YAML 1.2\n---\na: b\n".as_slice(),
            b"a: \xff\n".as_slice(),
        ] {
            let parsed = parse_yaml(source).unwrap();
            assert_eq!(parsed.span, 0..source.len());
            let opaque = collect_kind(&parsed, YamlParsedKind::Opaque);
            assert_eq!(opaque.len(), 1);
            assert_eq!(source_span(source, opaque[0]), source);
        }
    }

    #[test]
    fn directive_document_is_opaque_without_crossing_explicit_boundaries() {
        let source = b"safe: 1\n...\n%YAML 1.2\n---\nadvanced: x\n...\n---\nafter: 2\n";
        let parsed = parse_yaml(source).unwrap();
        assert_eq!(parsed.span, 0..source.len());
        assert_eq!(parsed.children.len(), 3);
        assert_eq!(parsed.children[0].children[0].kind, YamlParsedKind::Mapping);
        assert_eq!(parsed.children[1].children[0].kind, YamlParsedKind::Opaque);
        assert_eq!(
            source_span(source, &parsed.children[1].children[0]),
            b"%YAML 1.2\n---\nadvanced: x\n...\n"
        );
        assert_eq!(parsed.children[2].children[0].kind, YamlParsedKind::Mapping);
        assert_tree_spans(&parsed);
    }

    #[test]
    fn sensitive_keys_and_carrier_scalars_propagate_without_source_copies() {
        let source = b"password: NeverShow\nnormal: https://user:pass@example.test\nsafe: value\n";
        let parsed = parse_yaml(source).unwrap();
        let mapping = semantic_root(&parsed);
        assert!(mapping.children[0].sensitive);
        assert!(mapping.children[0].children[0].sensitive);
        assert!(!mapping.children[1].sensitive);
        assert!(mapping.children[1].children[0].sensitive);
        assert!(!mapping.children[2].sensitive);
        assert_eq!(
            source_span(source, &mapping.children[2].children[0]),
            b"value"
        );
    }

    #[test]
    fn empty_comment_only_and_root_scalars_are_bounded_documents() {
        let empty = parse_yaml(b"").unwrap();
        assert!(empty.children.is_empty());
        let comments = parse_yaml(b"# a\n\n# b\n").unwrap();
        assert_eq!(comments.children.len(), 1);
        assert_eq!(comments.children[0].children.len(), 2);
        assert!(
            comments.children[0]
                .children
                .iter()
                .all(|node| node.kind == YamlParsedKind::Comment && !node.sensitive)
        );
        let scalar = parse_yaml(b"\"quoted scalar\"").unwrap();
        assert_eq!(semantic_root(&scalar).kind, YamlParsedKind::Scalar);
    }

    #[test]
    fn full_line_comments_are_source_ordered_nodes_and_only_marked_when_sensitive() {
        let source = b"# ordinary\nroot:\n  # password is documented here\n  child: value\n# connection-string reminder\nafter: ok\n";
        let parsed = parse_yaml(source).unwrap();
        let document = &parsed.children[0];
        let comments = collect_kind(document, YamlParsedKind::Comment);
        assert_eq!(comments.len(), 3);
        assert_eq!(source_span(source, comments[0]), b"# ordinary\n");
        assert!(!comments[0].sensitive);
        assert!(comments[1].sensitive);
        assert!(comments[2].sensitive);
        assert!(
            comments
                .windows(2)
                .all(|pair| pair[0].span.start < pair[1].span.start)
        );
    }

    #[test]
    fn byte_node_depth_and_token_limits_fail_closed() {
        assert!(parse_yaml(&vec![b' '; MAX_STRUCTURED_CONFIG_BYTES + 1]).is_err());

        let many_nodes = format!("[{}]", vec!["x"; MAX_STRUCTURED_CONFIG_NODES].join(","));
        let parsed = parse_yaml(many_nodes.as_bytes()).unwrap();
        assert_eq!(semantic_root(&parsed).kind, YamlParsedKind::Opaque);

        let too_deep = format!(
            "{}value\n",
            (0..MAX_STRUCTURED_CONFIG_DEPTH)
                .map(|depth| format!("{}k{depth}:\n", "  ".repeat(depth)))
                .collect::<String>()
        );
        assert!(parse_yaml(too_deep.as_bytes()).is_err());

        let mut comments = Vec::new();
        for _ in 0..=MAX_STRUCTURED_CONFIG_TOKENS {
            comments.extend_from_slice(b"#\n");
        }
        assert!(comments.len() <= MAX_STRUCTURED_CONFIG_BYTES);
        assert!(parse_yaml(&comments).is_err());
    }

    fn contains_kind(node: &YamlParsedNode, kind: YamlParsedKind) -> bool {
        node.kind == kind || node.children.iter().any(|child| contains_kind(child, kind))
    }

    fn collect_kind(node: &YamlParsedNode, kind: YamlParsedKind) -> Vec<&YamlParsedNode> {
        let mut found = Vec::new();
        if node.kind == kind {
            found.push(node);
        }
        for child in &node.children {
            found.extend(collect_kind(child, kind));
        }
        found.sort_by_key(|node| node.span.start);
        found
    }

    fn assert_tree_spans(node: &YamlParsedNode) {
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
}
