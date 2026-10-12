//! Bounded, source-backed XML parsing for read-only configuration views.
//!
//! This parser never resolves entities, reads external subsets, processes
//! XInclude, or normalizes source text. Syntax whose meaning depends on those
//! operations remains one sensitive opaque node (or rejects the document when
//! a safe boundary cannot be established).

use std::{collections::HashSet, ops::Range};

use crate::structured_config_visual::{
    MAX_STRUCTURED_CONFIG_BYTES, MAX_STRUCTURED_CONFIG_DEPTH, MAX_STRUCTURED_CONFIG_NODES,
    MAX_STRUCTURED_CONFIG_TOKENS,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum XmlParsedKind {
    Document,
    Element,
    Attribute,
    Text,
    Comment,
    Opaque,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct XmlParsedNode {
    pub(crate) kind: XmlParsedKind,
    pub(crate) span: Range<usize>,
    pub(crate) name_span: Option<Range<usize>>,
    pub(crate) sensitive: bool,
    pub(crate) children: Vec<XmlParsedNode>,
}

pub(crate) fn parse_xml(source: &[u8]) -> Result<XmlParsedNode, ()> {
    if source.len() > MAX_STRUCTURED_CONFIG_BYTES {
        return Err(());
    }
    let text = std::str::from_utf8(source).map_err(|_| ())?;
    if !text.chars().all(is_xml_char) {
        return Err(());
    }
    XmlParser::new(source, text).parse_document()
}

struct PendingAttribute {
    span: Range<usize>,
    name_span: Range<usize>,
    sensitive: bool,
    identifies_sensitive_value: bool,
    opaque: bool,
}

struct XmlParser<'a> {
    source: &'a [u8],
    text: &'a str,
    pos: usize,
    nodes: usize,
    tokens: usize,
}

impl<'a> XmlParser<'a> {
    fn new(source: &'a [u8], text: &'a str) -> Self {
        Self {
            source,
            text,
            pos: usize::from(source.starts_with(&[0xef, 0xbb, 0xbf])) * 3,
            nodes: 0,
            tokens: 0,
        }
    }

    fn parse_document(mut self) -> Result<XmlParsedNode, ()> {
        self.bump_node()?;
        let mut children = Vec::new();
        if self.starts_xml_declaration() {
            children.push(self.parse_xml_declaration()?);
        }

        let mut root_seen = false;
        let mut doctype_seen = false;
        while self.pos < self.source.len() {
            if self.source[self.pos] != b'<' {
                let text = self.parse_text(false)?;
                if !self.source[text.span.clone()]
                    .iter()
                    .all(|byte| is_xml_whitespace(*byte))
                {
                    return Err(());
                }
                children.push(text);
                continue;
            }
            if self.starts(b"<!--") {
                children.push(self.parse_comment()?);
            } else if self.starts(b"<?") {
                children.push(self.parse_processing_instruction()?);
            } else if self.starts_doctype() {
                if root_seen || doctype_seen {
                    return Err(());
                }
                doctype_seen = true;
                children.push(self.parse_doctype()?);
            } else if self.starts(b"</") || self.starts(b"<![CDATA[") || self.starts(b"<!") {
                return Err(());
            } else {
                if root_seen {
                    return Err(());
                }
                root_seen = true;
                children.push(self.parse_element(false, 1)?);
            }
        }
        if !root_seen {
            return Err(());
        }
        Ok(XmlParsedNode {
            kind: XmlParsedKind::Document,
            span: 0..self.source.len(),
            name_span: None,
            sensitive: false,
            children,
        })
    }

    fn parse_element(
        &mut self,
        inherited_sensitive: bool,
        depth: usize,
    ) -> Result<XmlParsedNode, ()> {
        if depth > MAX_STRUCTURED_CONFIG_DEPTH || !self.consume(b"<") {
            return Err(());
        }
        self.bump_tokens(1)?;
        let start = self.pos - 1;
        let name_span = self.parse_name()?;
        self.bump_tokens(1)?;
        let element_name = &self.source[name_span.clone()];
        let mut namespace_ambiguous = element_name.contains(&b':');
        let mut element_sensitive = inherited_sensitive || is_sensitive_name(element_name);
        let mut attributes = Vec::new();
        let mut seen_attributes: HashSet<&'a [u8]> = HashSet::new();

        let self_closing = loop {
            let had_whitespace = self.skip_whitespace();
            if self.consume(b"/>") {
                self.bump_tokens(2)?;
                break true;
            }
            if self.consume(b">") {
                self.bump_tokens(1)?;
                break false;
            }
            if !had_whitespace {
                return Err(());
            }
            let attribute_start = self.pos;
            let attribute_name_span = self.parse_name()?;
            self.bump_tokens(1)?;
            let attribute_name = &self.source[attribute_name_span.clone()];
            if !seen_attributes.insert(attribute_name) {
                return Err(());
            }
            namespace_ambiguous |= attribute_name.contains(&b':')
                || attribute_name == b"xmlns"
                || attribute_name.starts_with(b"xmlns:");
            self.skip_whitespace();
            if !self.consume(b"=") {
                return Err(());
            }
            self.bump_tokens(1)?;
            self.skip_whitespace();
            let quote = self.peek().filter(|byte| matches!(*byte, b'\'' | b'"'));
            let Some(quote) = quote else {
                return Err(());
            };
            self.pos += 1;
            self.bump_tokens(1)?;
            let value_start = self.pos;
            while self.peek().is_some_and(|byte| byte != quote) {
                if self.peek() == Some(b'<') {
                    return Err(());
                }
                self.advance_char()?;
            }
            if self.peek() != Some(quote) {
                return Err(());
            }
            let value_span = value_start..self.pos;
            self.pos += 1;
            self.bump_tokens(2)?;
            let value = &self.source[value_span];
            let sensitive = is_sensitive_name(attribute_name)
                || value.contains(&b'&')
                || contains_sensitive_text(value);
            let identifies_sensitive_value = is_carrier_name(attribute_name)
                && (value.contains(&b'&') || is_sensitive_name(trim_xml_whitespace(value)));
            // A direct secret-valued attribute only redacts that leaf. A
            // carrier such as `name="password"` changes the meaning of sibling
            // attributes/body, so only that proven context taints the element.
            element_sensitive |= identifies_sensitive_value;
            attributes.push(PendingAttribute {
                span: attribute_start..self.pos,
                name_span: attribute_name_span,
                sensitive,
                identifies_sensitive_value,
                opaque: value.contains(&b'&'),
            });
        };

        let mut children = Vec::with_capacity(attributes.len());
        for attribute in attributes {
            self.bump_node()?;
            children.push(XmlParsedNode {
                kind: if attribute.opaque {
                    XmlParsedKind::Opaque
                } else {
                    XmlParsedKind::Attribute
                },
                span: attribute.span,
                name_span: Some(attribute.name_span),
                sensitive: element_sensitive
                    || attribute.sensitive
                    || attribute.identifies_sensitive_value,
                children: Vec::new(),
            });
        }

        if !self_closing {
            loop {
                if self.pos >= self.source.len() {
                    return Err(());
                }
                if self.starts(b"</") {
                    self.pos += 2;
                    self.bump_tokens(2)?;
                    let closing_name = self.parse_name()?;
                    self.bump_tokens(1)?;
                    if self.source[closing_name] != self.source[name_span.clone()] {
                        return Err(());
                    }
                    self.skip_whitespace();
                    if !self.consume(b">") {
                        return Err(());
                    }
                    self.bump_tokens(1)?;
                    break;
                }
                if self.starts(b"<!--") {
                    children.push(self.parse_comment()?);
                } else if self.starts(b"<![CDATA[") {
                    children.push(self.parse_cdata()?);
                } else if self.starts(b"<?") {
                    children.push(self.parse_processing_instruction()?);
                } else if self.starts(b"<!") {
                    return Err(());
                } else if self.starts(b"<") {
                    children.push(self.parse_element(element_sensitive, depth + 1)?);
                } else {
                    children.push(self.parse_text(element_sensitive)?);
                }
            }
        }

        self.bump_node()?;
        let mut node = XmlParsedNode {
            kind: XmlParsedKind::Element,
            span: start..self.pos,
            name_span: Some(name_span),
            sensitive: element_sensitive,
            children,
        };
        if namespace_ambiguous {
            node.kind = XmlParsedKind::Opaque;
            node.sensitive = true;
            node.children.clear();
        }
        Ok(node)
    }

    fn parse_text(&mut self, inherited_sensitive: bool) -> Result<XmlParsedNode, ()> {
        let start = self.pos;
        while self.pos < self.source.len() && self.source[self.pos] != b'<' {
            self.advance_char()?;
        }
        if start == self.pos {
            return Err(());
        }
        let value = &self.source[start..self.pos];
        if value.windows(3).any(|window| window == b"]]>") {
            return Err(());
        }
        self.bump_tokens(1)?;
        self.bump_node()?;
        let unresolved = value.contains(&b'&');
        Ok(XmlParsedNode {
            kind: if unresolved {
                XmlParsedKind::Opaque
            } else {
                XmlParsedKind::Text
            },
            span: start..self.pos,
            name_span: None,
            sensitive: inherited_sensitive || unresolved || contains_sensitive_text(value),
            children: Vec::new(),
        })
    }

    fn parse_xml_declaration(&mut self) -> Result<XmlParsedNode, ()> {
        let start = self.pos;
        self.pos += b"<?xml".len();
        self.bump_tokens(2)?;
        if !self.skip_whitespace() {
            return Err(());
        }

        let mut field = 0usize;
        let mut version_seen = false;
        loop {
            if self.consume(b"?>") {
                self.bump_tokens(2)?;
                break;
            }
            let name_span = self.parse_name()?;
            self.bump_tokens(1)?;
            let name = &self.source[name_span];
            self.skip_whitespace();
            if !self.consume(b"=") {
                return Err(());
            }
            self.bump_tokens(1)?;
            self.skip_whitespace();
            let quote = self.peek().filter(|byte| matches!(*byte, b'\'' | b'"'));
            let Some(quote) = quote else {
                return Err(());
            };
            self.pos += 1;
            self.bump_tokens(1)?;
            let value_start = self.pos;
            while self.peek().is_some_and(|byte| byte != quote) {
                if matches!(self.peek(), Some(b'<' | b'&')) {
                    return Err(());
                }
                self.advance_char()?;
            }
            if self.peek() != Some(quote) {
                return Err(());
            }
            let value = &self.source[value_start..self.pos];
            self.pos += 1;
            self.bump_tokens(2)?;
            match (field, name) {
                (0, b"version") if matches!(value, b"1.0" | b"1.1") => {
                    version_seen = true;
                }
                (1, b"encoding") if valid_utf8_encoding_name(value) => {}
                (1 | 2, b"standalone") if matches!(value, b"yes" | b"no") => {
                    field = 2;
                }
                _ => return Err(()),
            }
            field += 1;
            if self.starts(b"?>") {
                continue;
            }
            if !self.skip_whitespace() {
                return Err(());
            }
        }
        if !version_seen {
            return Err(());
        }
        self.bump_node()?;
        Ok(XmlParsedNode {
            kind: XmlParsedKind::Text,
            span: start..self.pos,
            name_span: Some(start + 2..start + 5),
            sensitive: false,
            children: Vec::new(),
        })
    }

    fn parse_comment(&mut self) -> Result<XmlParsedNode, ()> {
        let start = self.pos;
        self.pos += b"<!--".len();
        self.bump_tokens(1)?;
        let content_start = self.pos;
        let relative_end = find_subslice(&self.source[self.pos..], b"-->").ok_or(())?;
        let content_end = self.pos + relative_end;
        if self.source[content_start..content_end]
            .windows(2)
            .any(|window| window == b"--")
            || self.source[content_start..content_end].ends_with(b"-")
        {
            return Err(());
        }
        self.pos = content_end + 3;
        self.bump_tokens(1)?;
        self.bump_node()?;
        let content = &self.source[content_start..content_end];
        Ok(XmlParsedNode {
            kind: XmlParsedKind::Comment,
            span: start..self.pos,
            name_span: None,
            sensitive: is_sensitive_name(content) || contains_sensitive_text(content),
            children: Vec::new(),
        })
    }

    fn parse_cdata(&mut self) -> Result<XmlParsedNode, ()> {
        let start = self.pos;
        self.pos += b"<![CDATA[".len();
        self.bump_tokens(1)?;
        let relative_end = find_subslice(&self.source[self.pos..], b"]]>").ok_or(())?;
        self.pos += relative_end + 3;
        self.bump_tokens(1)?;
        self.bump_node()?;
        Ok(XmlParsedNode {
            kind: XmlParsedKind::Opaque,
            span: start..self.pos,
            name_span: None,
            sensitive: true,
            children: Vec::new(),
        })
    }

    fn parse_processing_instruction(&mut self) -> Result<XmlParsedNode, ()> {
        let start = self.pos;
        self.pos += 2;
        self.bump_tokens(1)?;
        let target_span = self.parse_name()?;
        self.bump_tokens(1)?;
        if self.source[target_span.clone()].eq_ignore_ascii_case(b"xml") {
            return Err(());
        }
        if !self.starts(b"?>") && !self.skip_whitespace() {
            return Err(());
        }
        let relative_end = find_subslice(&self.source[self.pos..], b"?>").ok_or(())?;
        self.pos += relative_end + 2;
        self.bump_tokens(1)?;
        self.bump_node()?;
        Ok(XmlParsedNode {
            kind: XmlParsedKind::Opaque,
            span: start..self.pos,
            name_span: Some(target_span),
            sensitive: true,
            children: Vec::new(),
        })
    }

    fn parse_doctype(&mut self) -> Result<XmlParsedNode, ()> {
        let start = self.pos;
        self.pos += b"<!DOCTYPE".len();
        self.bump_tokens(1)?;
        if !self.skip_whitespace() {
            return Err(());
        }
        self.parse_name()?;
        self.bump_tokens(1)?;
        let mut quote = None;
        let mut subset_depth = 0usize;
        loop {
            let byte = self.peek().ok_or(())?;
            if let Some(active_quote) = quote {
                self.pos += 1;
                if byte == active_quote {
                    quote = None;
                }
                continue;
            }
            if self.starts(b"<!--") {
                let content_start = self.pos + b"<!--".len();
                let relative_end = find_subslice(&self.source[content_start..], b"-->").ok_or(())?;
                let content_end = content_start + relative_end;
                let content = &self.source[content_start..content_end];
                if content.windows(2).any(|window| window == b"--") || content.ends_with(b"-") {
                    return Err(());
                }
                self.pos = content_end + b"-->".len();
                self.bump_tokens(2)?;
                continue;
            }
            if self.starts(b"<?") {
                let relative_end = find_subslice(&self.source[self.pos + 2..], b"?>").ok_or(())?;
                self.pos += 2 + relative_end + 2;
                self.bump_tokens(2)?;
                continue;
            }
            match byte {
                b'\'' | b'"' => {
                    quote = Some(byte);
                    self.pos += 1;
                    self.bump_tokens(1)?;
                }
                b'[' => {
                    subset_depth = subset_depth.checked_add(1).ok_or(())?;
                    self.pos += 1;
                    self.bump_tokens(1)?;
                }
                b']' => {
                    if subset_depth == 0 {
                        return Err(());
                    }
                    subset_depth -= 1;
                    self.pos += 1;
                    self.bump_tokens(1)?;
                }
                b'>' if subset_depth == 0 => {
                    self.pos += 1;
                    self.bump_tokens(1)?;
                    break;
                }
                b'<' | b'>' | b'%' | b'&' => {
                    self.pos += 1;
                    self.bump_tokens(1)?;
                }
                _ => self.advance_char()?,
            }
        }
        self.bump_node()?;
        Ok(XmlParsedNode {
            kind: XmlParsedKind::Opaque,
            span: start..self.pos,
            name_span: None,
            sensitive: true,
            children: Vec::new(),
        })
    }

    fn parse_name(&mut self) -> Result<Range<usize>, ()> {
        let start = self.pos;
        let first = self.peek_char().ok_or(())?;
        if !is_xml_name_start(first) {
            return Err(());
        }
        self.pos += first.len_utf8();
        while let Some(character) = self.peek_char() {
            if !is_xml_name_char(character) {
                break;
            }
            self.pos += character.len_utf8();
        }
        Ok(start..self.pos)
    }

    fn advance_char(&mut self) -> Result<(), ()> {
        let character = self.peek_char().ok_or(())?;
        self.pos += character.len_utf8();
        Ok(())
    }

    fn peek_char(&self) -> Option<char> {
        self.text.get(self.pos..)?.chars().next()
    }

    fn starts_xml_declaration(&self) -> bool {
        self.starts(b"<?xml")
            && self
                .source
                .get(self.pos + b"<?xml".len())
                .is_some_and(|byte| is_xml_whitespace(*byte))
    }

    fn starts_doctype(&self) -> bool {
        self.starts(b"<!DOCTYPE")
            && self
                .source
                .get(self.pos + b"<!DOCTYPE".len())
                .is_some_and(|byte| is_xml_whitespace(*byte))
    }

    fn starts(&self, prefix: &[u8]) -> bool {
        self.source[self.pos..].starts_with(prefix)
    }

    fn consume(&mut self, token: &[u8]) -> bool {
        if self.starts(token) {
            self.pos += token.len();
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<u8> {
        self.source.get(self.pos).copied()
    }

    fn skip_whitespace(&mut self) -> bool {
        let start = self.pos;
        while self.peek().is_some_and(is_xml_whitespace) {
            self.pos += 1;
        }
        self.pos != start
    }

    fn bump_node(&mut self) -> Result<(), ()> {
        self.nodes = self.nodes.checked_add(1).ok_or(())?;
        (self.nodes <= MAX_STRUCTURED_CONFIG_NODES)
            .then_some(())
            .ok_or(())
    }

    fn bump_tokens(&mut self, count: usize) -> Result<(), ()> {
        self.tokens = self.tokens.checked_add(count).ok_or(())?;
        (self.tokens <= MAX_STRUCTURED_CONFIG_TOKENS)
            .then_some(())
            .ok_or(())
    }
}

fn is_xml_char(character: char) -> bool {
    matches!(character, '\u{9}' | '\u{a}' | '\u{d}')
        || matches!(character as u32, 0x20..=0xd7ff | 0xe000..=0xfffd | 0x10000..=0x10ffff)
}

fn is_xml_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

fn is_xml_name_start(character: char) -> bool {
    matches!(character, ':' | 'A'..='Z' | '_' | 'a'..='z')
        || matches!(
            character as u32,
            0xc0..=0xd6
                | 0xd8..=0xf6
                | 0xf8..=0x2ff
                | 0x370..=0x37d
                | 0x37f..=0x1fff
                | 0x200c..=0x200d
                | 0x2070..=0x218f
                | 0x2c00..=0x2fef
                | 0x3001..=0xd7ff
                | 0xf900..=0xfdcf
                | 0xfdf0..=0xfffd
                | 0x10000..=0xeffff
        )
}

fn is_xml_name_char(character: char) -> bool {
    is_xml_name_start(character)
        || matches!(character, '-' | '.' | '0'..='9' | '\u{b7}')
        || matches!(character as u32, 0x300..=0x36f | 0x203f..=0x2040)
}

fn valid_utf8_encoding_name(value: &[u8]) -> bool {
    value.eq_ignore_ascii_case(b"utf-8") || value.eq_ignore_ascii_case(b"utf8")
}

fn trim_xml_whitespace(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(|byte| is_xml_whitespace(*byte)) {
        value = &value[1..];
    }
    while value.last().is_some_and(|byte| is_xml_whitespace(*byte)) {
        value = &value[..value.len() - 1];
    }
    value
}

fn is_carrier_name(value: &[u8]) -> bool {
    matches!(
        normalize_name(value).as_slice(),
        b"name" | b"key" | b"param" | b"parameter" | b"property"
    )
}

fn is_sensitive_name(value: &[u8]) -> bool {
    let normalized = normalize_name(value);
    const MARKERS: [&[u8]; 15] = [
        b"password",
        b"passwd",
        b"passphrase",
        b"pwd",
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
        b"bindpasswd",
    ];
    MARKERS.iter().any(|marker| {
        normalized == *marker || normalized.windows(marker.len()).any(|part| part == *marker)
    })
}

fn normalize_name(value: &[u8]) -> Vec<u8> {
    let mut normalized = Vec::with_capacity(value.len());
    let mut separator = false;
    let mut previous_lower_or_digit = false;
    for byte in value {
        if byte.is_ascii_alphanumeric() {
            let camel_boundary = byte.is_ascii_uppercase() && previous_lower_or_digit;
            if (separator || camel_boundary)
                && !normalized.is_empty()
                && normalized.last() != Some(&b'_')
            {
                normalized.push(b'_');
            }
            normalized.push(byte.to_ascii_lowercase());
            separator = false;
            previous_lower_or_digit = byte.is_ascii_lowercase() || byte.is_ascii_digit();
        } else if matches!(*byte, b'_' | b'-' | b'.' | b' ' | b'\t') {
            separator = true;
            previous_lower_or_digit = false;
        } else {
            separator = false;
            normalized.push(*byte);
            previous_lower_or_digit = false;
        }
    }
    normalized
}

fn contains_sensitive_text(value: &[u8]) -> bool {
    let lower = String::from_utf8_lossy(value).to_ascii_lowercase();
    lower.contains("bearer ")
        || lower.contains("private key")
        || lower.contains("pwd=")
        || lower.contains("password=")
        || lower.contains("passwd=")
        || lower.contains("passphrase=")
        || lower.contains("token=")
        || lower.contains("secret=")
        || lower.contains("authorization:")
        || lower.contains("client_secret=")
        || lower.contains("access_key=")
        || lower.contains("secret_key=")
        || (lower.contains("://") && lower.contains('@'))
}

fn find_subslice(source: &[u8], needle: &[u8]) -> Option<usize> {
    source
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn element<'a>(node: &'a XmlParsedNode, name: &[u8], source: &[u8]) -> &'a XmlParsedNode {
        node.children
            .iter()
            .find(|child| {
                child.kind == XmlParsedKind::Element
                    && child
                        .name_span
                        .as_ref()
                        .is_some_and(|span| &source[span.clone()] == name)
            })
            .unwrap_or_else(|| panic!("missing element {}", String::from_utf8_lossy(name)))
    }

    #[test]
    fn bom_declaration_crlf_and_source_spans_are_exact() {
        let source = b"\xef\xbb\xbf<?xml version='1.0' encoding=\"UTF-8\"?>\r\n<root/>\r\n";
        let document = parse_xml(source).expect("valid XML");
        assert_eq!(document.kind, XmlParsedKind::Document);
        assert_eq!(&source[document.span], source);
        assert_eq!(document.children.len(), 4);
        assert_eq!(document.children[0].kind, XmlParsedKind::Text);
        assert!(!document.children[0].sensitive);
        assert_eq!(
            &source[document.children[0].span.clone()],
            b"<?xml version='1.0' encoding=\"UTF-8\"?>"
        );
        assert_eq!(&source[document.children[1].span.clone()], b"\r\n");
        assert_eq!(&source[document.children[2].span.clone()], b"<root/>");
    }

    #[test]
    fn nested_elements_self_closing_and_raw_attribute_order_are_preserved() {
        let source = br#"<root z='1' a="2"><child enabled = 'yes'/><leaf>ok</leaf></root>"#;
        let document = parse_xml(source).unwrap();
        let root = element(&document, b"root", source);
        assert_eq!(root.children.len(), 4);
        assert_eq!(root.children[0].kind, XmlParsedKind::Attribute);
        assert_eq!(&source[root.children[0].span.clone()], b"z='1'");
        assert_eq!(&source[root.children[1].span.clone()], b"a=\"2\"");
        assert_eq!(root.children[2].kind, XmlParsedKind::Element);
        assert_eq!(
            &source[root.children[2].span.clone()],
            b"<child enabled = 'yes'/>"
        );
        assert_eq!(&source[root.children[3].span.clone()], b"<leaf>ok</leaf>");
    }

    #[test]
    fn mixed_content_keeps_text_element_text_order() {
        let source = b"<p>before<b>bold</b>after</p>";
        let document = parse_xml(source).unwrap();
        let paragraph = element(&document, b"p", source);
        assert_eq!(
            paragraph
                .children
                .iter()
                .map(|child| child.kind)
                .collect::<Vec<_>>(),
            [
                XmlParsedKind::Text,
                XmlParsedKind::Element,
                XmlParsedKind::Text
            ]
        );
        assert_eq!(&source[paragraph.children[0].span.clone()], b"before");
        assert_eq!(&source[paragraph.children[2].span.clone()], b"after");
    }

    #[test]
    fn comments_cdata_and_pi_are_atomic_without_swallowing_neighbors() {
        let source = b"<r>safe<!-- note --><a/>mid<![CDATA[<raw>&x;]]><?work item?><b/></r>";
        let document = parse_xml(source).unwrap();
        let root = element(&document, b"r", source);
        assert_eq!(
            root.children
                .iter()
                .map(|node| node.kind)
                .collect::<Vec<_>>(),
            [
                XmlParsedKind::Text,
                XmlParsedKind::Comment,
                XmlParsedKind::Element,
                XmlParsedKind::Text,
                XmlParsedKind::Opaque,
                XmlParsedKind::Opaque,
                XmlParsedKind::Element,
            ]
        );
        assert_eq!(&source[root.children[0].span.clone()], b"safe");
        assert_eq!(&source[root.children[1].span.clone()], b"<!-- note -->");
        assert_eq!(&source[root.children[2].span.clone()], b"<a/>");
        assert_eq!(&source[root.children[3].span.clone()], b"mid");
        assert_eq!(
            &source[root.children[4].span.clone()],
            b"<![CDATA[<raw>&x;]]>"
        );
        assert_eq!(&source[root.children[6].span.clone()], b"<b/>");
        assert!(!root.children[1].sensitive);
        assert!(
            root.children
                .iter()
                .filter(|node| node.kind == XmlParsedKind::Opaque)
                .all(|node| node.sensitive)
        );
    }

    #[test]
    fn comment_sensitivity_uses_common_credential_markers() {
        let source = b"<r><!-- routine note --><!-- private-key: DontLeak --><port>80</port></r>";
        let document = parse_xml(source).unwrap();
        let root = element(&document, b"r", source);
        assert_eq!(root.children[0].kind, XmlParsedKind::Comment);
        assert!(!root.children[0].sensitive);
        assert_eq!(root.children[1].kind, XmlParsedKind::Comment);
        assert!(root.children[1].sensitive);
        assert_eq!(root.children[2].kind, XmlParsedKind::Element);
    }

    #[test]
    fn doctype_internal_subset_is_one_opaque_node_and_entities_are_never_expanded() {
        let source = br#"<!DOCTYPE r [<!ENTITY x "DontExpand"><!ELEMENT r (#PCDATA)>]><r>left &x; right</r>"#;
        let document = parse_xml(source).unwrap();
        assert_eq!(document.children[0].kind, XmlParsedKind::Opaque);
        assert_eq!(
            &source[document.children[0].span.clone()],
            br#"<!DOCTYPE r [<!ENTITY x "DontExpand"><!ELEMENT r (#PCDATA)>]>"#
        );
        let root = element(&document, b"r", source);
        assert_eq!(root.children.len(), 1);
        assert_eq!(root.children[0].kind, XmlParsedKind::Opaque);
        assert!(root.children[0].sensitive);
        assert_eq!(&source[root.children[0].span.clone()], b"left &x; right");
    }

    #[test]
    fn doctype_comment_and_pi_delimiters_do_not_end_the_opaque_unit_early() {
        let source = b"<!DOCTYPE r [<!-- ] --><!ELEMENT r EMPTY><?inside ] ?>]><r/>";
        let document = parse_xml(source).unwrap();
        assert_eq!(document.children.len(), 2);
        assert_eq!(document.children[0].kind, XmlParsedKind::Opaque);
        assert_eq!(
            &source[document.children[0].span.clone()],
            b"<!DOCTYPE r [<!-- ] --><!ELEMENT r EMPTY><?inside ] ?>]>"
        );
        assert_eq!(&source[document.children[1].span.clone()], b"<r/>");
    }

    #[test]
    fn namespace_context_is_an_atomic_opaque_subtree() {
        let source =
            b"<safe><x:cluster xmlns:x='urn:test'><x:item/></x:cluster><port>80</port></safe>";
        let document = parse_xml(source).unwrap();
        let root = element(&document, b"safe", source);
        assert_eq!(root.children.len(), 2);
        assert_eq!(root.children[0].kind, XmlParsedKind::Opaque);
        assert!(root.children[0].sensitive);
        assert_eq!(
            &source[root.children[0].span.clone()],
            b"<x:cluster xmlns:x='urn:test'><x:item/></x:cluster>"
        );
        assert_eq!(root.children[1].kind, XmlParsedKind::Element);
        assert_eq!(&source[root.children[1].span.clone()], b"<port>80</port>");
    }

    #[test]
    fn duplicate_attributes_and_mismatched_or_extra_roots_fail_closed() {
        for source in [
            b"<r a='1' a='2'/>".as_slice(),
            b"<r><a></r></a>".as_slice(),
            b"<r></R>".as_slice(),
            b"<r/><s/>".as_slice(),
            b"</r>".as_slice(),
        ] {
            assert!(parse_xml(source).is_err(), "accepted {source:?}");
        }
    }

    #[test]
    fn malformed_comments_declarations_and_unknown_markup_fail_closed() {
        for source in [
            b"<?xml encoding='UTF-8'?><r/>".as_slice(),
            b"<?xml version='1.0' encoding='UTF-16'?><r/>".as_slice(),
            b"<r><!-- bad -- comment --></r>".as_slice(),
            b"<r><!-- bad ---></r>".as_slice(),
            b"<r><![CDATA[unterminated</r>".as_slice(),
            b"<r><!ENTITY x 'y'></r>".as_slice(),
            b"<r>bad]]>text</r>".as_slice(),
        ] {
            assert!(parse_xml(source).is_err(), "accepted {source:?}");
        }
    }

    #[test]
    fn entity_bearing_attributes_and_sensitive_elements_are_redacted_independently() {
        let source = b"<r><property name='password' value='DontLeak'/><PARAM name='pass&#119;ord' value='EscapedCarrierLeak'/><url value='a&amp;b'/><server password='LeafOnly'><port>80</port></server></r>";
        let document = parse_xml(source).unwrap();
        let root = element(&document, b"r", source);
        assert!(root.children[0].sensitive);
        assert!(root.children[1].sensitive);
        assert!(root.children[1].children.iter().all(|node| node.sensitive));
        assert!(!root.children[2].sensitive);
        assert_eq!(root.children[2].children[0].kind, XmlParsedKind::Opaque);
        assert!(root.children[2].children[0].sensitive);
        assert!(!root.children[3].sensitive);
        assert!(root.children[3].children[0].sensitive);
        assert!(!root.children[3].children[1].sensitive);
        assert_eq!(
            &source[root.children[3].children[1].span.clone()],
            b"<port>80</port>"
        );
        assert!(root.children[0].children.iter().all(|node| node.sensitive));
    }

    #[test]
    fn unicode_names_and_non_utf8_or_invalid_xml_characters_are_handled_safely() {
        let source = "<配置><端口>80</端口></配置>".as_bytes();
        let document = parse_xml(source).unwrap();
        assert_eq!(&source[document.span], source);
        assert!(parse_xml(b"<r>\xff</r>").is_err());
        assert!(parse_xml(b"<r>\0</r>").is_err());
    }

    #[test]
    fn depth_limit_accepts_boundary_and_rejects_one_more() {
        let exact = format!(
            "{}{}",
            "<x>".repeat(MAX_STRUCTURED_CONFIG_DEPTH),
            "</x>".repeat(MAX_STRUCTURED_CONFIG_DEPTH)
        );
        assert!(parse_xml(exact.as_bytes()).is_ok());
        let over = format!(
            "{}{}",
            "<x>".repeat(MAX_STRUCTURED_CONFIG_DEPTH + 1),
            "</x>".repeat(MAX_STRUCTURED_CONFIG_DEPTH + 1)
        );
        assert!(parse_xml(over.as_bytes()).is_err());
    }

    #[test]
    fn byte_node_and_token_limits_are_enforced() {
        assert!(parse_xml(&vec![b' '; MAX_STRUCTURED_CONFIG_BYTES + 1]).is_err());

        let exact_nodes = format!("<r>{}</r>", "<x/>".repeat(MAX_STRUCTURED_CONFIG_NODES - 2));
        assert!(parse_xml(exact_nodes.as_bytes()).is_ok());
        let over_nodes = format!("<r>{}</r>", "<x/>".repeat(MAX_STRUCTURED_CONFIG_NODES - 1));
        assert!(parse_xml(over_nodes.as_bytes()).is_err());

        let exact_attribute_count = (MAX_STRUCTURED_CONFIG_TOKENS - 4) / 5;
        let mut exact_tokens = String::from("<r");
        for index in 0..exact_attribute_count {
            exact_tokens.push_str(&format!(" a{index}=''"));
        }
        exact_tokens.push_str("/>");
        assert!(parse_xml(exact_tokens.as_bytes()).is_ok());
        exact_tokens.insert_str(exact_tokens.len() - 2, " overflow=''");
        assert!(parse_xml(exact_tokens.as_bytes()).is_err());
    }
}
