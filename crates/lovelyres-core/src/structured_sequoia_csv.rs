//! Bounded, source-backed inspection for SequoiaDB `quickDeploy` tables.
//!
//! The upstream `tools/deploy` fixtures and `quickDeploy.js` prove two
//! physical-line layouts: `role,groupName,hostName,serviceName,dbPath` for
//! `sequoiadb.conf` and `instanceName,port,databaseDir,coordAddr` for the SQL
//! instance files. The script compares the first physical line exactly, skips
//! comments only when byte zero is `#`, and splits each remaining physical
//! line on commas. It also accepts an unquoted `[host:port,host:port]`
//! `coordAddr`, so this format must not be treated as generic RFC 4180 CSV.
//! Quotes, ambiguous brackets, and unknown record layouts remain local opaque
//! rows because the script never joins physical lines.
//!
//! Official syntax evidence:
//! <https://raw.githubusercontent.com/SequoiaDB/SequoiaDB/master/tools/deploy/quickDeploy.js>
//! <https://raw.githubusercontent.com/SequoiaDB/SequoiaDB/master/tools/deploy/mariadb.conf>
//! <https://doc.sequoiadb.com/cn/sequoiadb_back-cat_id-1557810775-edition_id-508>

use std::ops::Range;

use crate::structured_config_visual::{
    MAX_STRUCTURED_CONFIG_BYTES, MAX_STRUCTURED_CONFIG_DEPTH, MAX_STRUCTURED_CONFIG_NODES,
    MAX_STRUCTURED_CONFIG_TOKENS, contains_sensitive_marker_text, contains_sensitive_text,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SequoiaCsvExpectedSchema {
    Cluster,
    SqlInstance,
}

impl SequoiaCsvExpectedSchema {
    const fn header(self) -> &'static [u8] {
        match self {
            Self::Cluster => b"role,groupName,hostName,serviceName,dbPath",
            Self::SqlInstance => b"instanceName,port,databaseDir,coordAddr",
        }
    }

    const fn field_count(self) -> usize {
        match self {
            Self::Cluster => 5,
            Self::SqlInstance => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SequoiaCsvParsedKind {
    Document,
    Header,
    Record,
    Field,
    Comment,
    Opaque,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SequoiaCsvParsedNode {
    pub(crate) kind: SequoiaCsvParsedKind,
    pub(crate) span: Range<usize>,
    pub(crate) name_span: Option<Range<usize>>,
    pub(crate) sensitive: bool,
    pub(crate) children: Vec<SequoiaCsvParsedNode>,
}

pub(crate) fn parse_sequoia_csv(
    source: &[u8],
    expected: SequoiaCsvExpectedSchema,
) -> Result<SequoiaCsvParsedNode, ()> {
    if source.len() > MAX_STRUCTURED_CONFIG_BYTES {
        return Err(());
    }
    if source.is_empty() {
        return Ok(opaque_document(0));
    }
    if std::str::from_utf8(source).is_err() || source.contains(&0) {
        return Ok(opaque_document(source.len()));
    }

    let parser = Parser {
        source,
        expected,
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
    content: Range<usize>,
}

struct Parser<'a> {
    source: &'a [u8],
    expected: SequoiaCsvExpectedSchema,
    position: usize,
    nodes: usize,
    tokens: usize,
}

impl<'a> Parser<'a> {
    fn parse_document(mut self) -> ParseResult<SequoiaCsvParsedNode> {
        self.ensure_depth(2)?;
        let header_line = self.next_line()?.ok_or(ParseFailure::Syntax)?;
        let header = &self.source[header_line.content.clone()];
        if header != self.expected.header() {
            return Err(ParseFailure::Syntax);
        }
        let header_fields = self.parse_fields(&header_line, self.expected, true)?;
        let mut children = vec![self.structured_line(
            SequoiaCsvParsedKind::Header,
            &header_line,
            header_fields,
            true,
        )?];

        while let Some(line) = self.next_line()? {
            if line.content.is_empty() {
                continue;
            }
            let raw = &self.source[line.content.clone()];
            if raw.first() == Some(&b'#') {
                children.push(self.comment_line(&line)?);
                continue;
            }
            if raw.contains(&b'"') {
                self.bump_tokens(1)?;
                children.push(self.opaque_line(&line)?);
                continue;
            }

            let fields = match self.parse_fields(&line, self.expected, false) {
                Ok(fields) => fields,
                Err(ParseFailure::Syntax) => {
                    children.push(self.opaque_line(&line)?);
                    continue;
                }
                Err(ParseFailure::Limit) => return Err(ParseFailure::Limit),
            };
            if fields.len() == self.expected.field_count() {
                children.push(self.structured_line(
                    SequoiaCsvParsedKind::Record,
                    &line,
                    fields,
                    false,
                )?);
            } else {
                children.push(self.opaque_line(&line)?);
            }
        }

        Ok(document(self.source.len(), children))
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
        Ok(Some(PhysicalLine {
            start,
            end,
            content: start..content_end,
        }))
    }

    fn parse_fields(
        &mut self,
        line: &PhysicalLine,
        schema: SequoiaCsvExpectedSchema,
        header: bool,
    ) -> ParseResult<Vec<Range<usize>>> {
        let mut fields = Vec::new();
        let mut field_start = line.content.start;
        let mut in_coord_list = false;

        for index in line.content.clone() {
            match self.source[index] {
                b'[' => {
                    if in_coord_list {
                        return Err(ParseFailure::Syntax);
                    }
                    if !header
                        && schema == SequoiaCsvExpectedSchema::SqlInstance
                        && fields.len() == 3
                        && index == field_start
                    {
                        in_coord_list = true;
                        self.bump_tokens(1)?;
                    }
                }
                b']' => {
                    if in_coord_list {
                        if index + 1 != line.content.end {
                            return Err(ParseFailure::Syntax);
                        }
                        in_coord_list = false;
                        self.bump_tokens(1)?;
                    } else if !header
                        && schema == SequoiaCsvExpectedSchema::SqlInstance
                        && fields.len() == 3
                    {
                        return Err(ParseFailure::Syntax);
                    }
                }
                b',' => {
                    self.bump_tokens(1)?;
                    if !in_coord_list {
                        fields.push(field_start..index);
                        field_start = index + 1;
                    }
                }
                _ => {}
            }
        }
        if in_coord_list {
            return Err(ParseFailure::Syntax);
        }
        fields.push(field_start..line.content.end);
        self.bump_tokens(fields.len())?;
        Ok(fields)
    }

    fn structured_line(
        &mut self,
        kind: SequoiaCsvParsedKind,
        line: &PhysicalLine,
        fields: Vec<Range<usize>>,
        header: bool,
    ) -> ParseResult<SequoiaCsvParsedNode> {
        self.bump_node()?;
        let mut children = Vec::with_capacity(fields.len());
        for span in fields {
            self.bump_node()?;
            let sensitive = !header && contains_sensitive_field(&self.source[span.clone()]);
            children.push(SequoiaCsvParsedNode {
                kind: SequoiaCsvParsedKind::Field,
                span,
                name_span: None,
                sensitive,
                children: Vec::new(),
            });
        }
        Ok(SequoiaCsvParsedNode {
            kind,
            span: line.start..line.end,
            name_span: None,
            sensitive: false,
            children,
        })
    }

    fn opaque_line(&mut self, line: &PhysicalLine) -> ParseResult<SequoiaCsvParsedNode> {
        self.bump_node()?;
        Ok(SequoiaCsvParsedNode {
            kind: SequoiaCsvParsedKind::Opaque,
            span: line.start..line.end,
            name_span: None,
            sensitive: true,
            children: Vec::new(),
        })
    }

    fn comment_line(&mut self, line: &PhysicalLine) -> ParseResult<SequoiaCsvParsedNode> {
        self.bump_node()?;
        let text = std::str::from_utf8(&self.source[line.content.clone()])
            .map_err(|_| ParseFailure::Syntax)?;
        Ok(SequoiaCsvParsedNode {
            kind: SequoiaCsvParsedKind::Comment,
            span: line.start..line.end,
            name_span: None,
            sensitive: contains_sensitive_marker_text(text) || contains_sensitive_text(text),
            children: Vec::new(),
        })
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

fn contains_sensitive_field(value: &[u8]) -> bool {
    std::str::from_utf8(value)
        .ok()
        .is_some_and(contains_sensitive_text)
}

fn document(length: usize, children: Vec<SequoiaCsvParsedNode>) -> SequoiaCsvParsedNode {
    SequoiaCsvParsedNode {
        kind: SequoiaCsvParsedKind::Document,
        span: 0..length,
        name_span: None,
        sensitive: false,
        children,
    }
}

fn opaque_document(length: usize) -> SequoiaCsvParsedNode {
    document(
        length,
        vec![SequoiaCsvParsedNode {
            kind: SequoiaCsvParsedKind::Opaque,
            span: 0..length,
            name_span: None,
            sensitive: length != 0,
            children: Vec::new(),
        }],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_span<'a>(source: &'a [u8], node: &SequoiaCsvParsedNode) -> &'a [u8] {
        &source[node.span.clone()]
    }

    fn assert_tree_spans(node: &SequoiaCsvParsedNode) {
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

    fn tree_depth(node: &SequoiaCsvParsedNode) -> usize {
        node.children
            .iter()
            .map(tree_depth)
            .max()
            .map_or(0, |depth| depth + 1)
    }

    fn assert_document_opaque(source: &[u8], expected: SequoiaCsvExpectedSchema) {
        let parsed =
            parse_sequoia_csv(source, expected).expect("bounded opaque quickDeploy document");
        assert_eq!(parsed.kind, SequoiaCsvParsedKind::Document);
        assert_eq!(parsed.span, 0..source.len());
        assert_eq!(parsed.children.len(), 1);
        assert_eq!(parsed.children[0].kind, SequoiaCsvParsedKind::Opaque);
        assert_eq!(source_span(source, &parsed.children[0]), source);
        assert_eq!(parsed.children[0].sensitive, !source.is_empty());
    }

    #[test]
    fn upstream_default_four_files_are_crlf_source_backed() {
        const CLUSTER: &str = concat!(
            "role,groupName,hostName,serviceName,dbPath\n",
            "\n",
            "catalog,SYSCatalogGroup,localhost,11800,[installPath]/database/catalog/11800\n",
            "\n",
            "coord,SYSCoord,localhost,11810,[installPath]/database/coord/11810\n",
            "\n",
            "data,group1,localhost,11820,[installPath]/database/data/11820\n",
            "data,group2,localhost,11830,[installPath]/database/data/11830\n",
            "data,group3,localhost,11840,[installPath]/database/data/11840\n",
            "\n",
            "# Note: This configuration file only supports cluster mode, doesn't support standalone mode.\n",
        );
        const SQL_NOTE: &str = "# Note: coordAddr, '-' means the first coord in sdb.conf. You can configure it by format hostName1:serviceName1 or [hostname1:serviceName1,hostname2:serviceName2]\n";
        let fixtures = [
            (CLUSTER.to_owned(), SequoiaCsvExpectedSchema::Cluster, 7),
            (
                format!(
                    "instanceName,port,databaseDir,coordAddr\nmyinst,3306,[installPath]/database/3306,-\n\n{SQL_NOTE}"
                ),
                SequoiaCsvExpectedSchema::SqlInstance,
                3,
            ),
            (
                format!(
                    "instanceName,port,databaseDir,coordAddr\nmyinst,6101,[installPath]/database/6101,-\n\n{SQL_NOTE}"
                ),
                SequoiaCsvExpectedSchema::SqlInstance,
                3,
            ),
            (
                format!(
                    "instanceName,port,databaseDir,coordAddr\nmyinst,5432,[installPath]/database/5432,-\n\n{SQL_NOTE}"
                ),
                SequoiaCsvExpectedSchema::SqlInstance,
                3,
            ),
        ];

        for (fixture, expected, visible_lines) in fixtures {
            let source = fixture.replace('\n', "\r\n").into_bytes();
            let parsed = parse_sequoia_csv(&source, expected).unwrap();
            assert_eq!(source_span(&source, &parsed), source);
            assert_eq!(parsed.children.len(), visible_lines);
            assert_eq!(parsed.children[0].kind, SequoiaCsvParsedKind::Header);
            assert_eq!(
                parsed.children.last().unwrap().kind,
                SequoiaCsvParsedKind::Comment
            );
            assert!(!parsed.children.last().unwrap().sensitive);
            assert_eq!(tree_depth(&parsed), 2);
            assert_tree_spans(&parsed);
        }
    }

    #[test]
    fn empty_fields_duplicates_and_missing_terminal_newline_are_exact() {
        let source = b"role,groupName,hostName,serviceName,dbPath\r\ncoord,,sdbserver1,11810,\r\ncoord,,sdbserver1,11810,";
        let parsed = parse_sequoia_csv(source, SequoiaCsvExpectedSchema::Cluster).unwrap();
        assert_eq!(source_span(source, &parsed), source);
        assert_eq!(parsed.children.len(), 3);
        assert_eq!(parsed.children[0].span.start, 0);
        for record in &parsed.children[1..] {
            assert_eq!(record.kind, SequoiaCsvParsedKind::Record);
            assert_eq!(record.children.len(), 5);
            assert_eq!(source_span(source, &record.children[1]), b"");
            assert_eq!(source_span(source, &record.children[4]), b"");
        }
        assert_eq!(
            parsed.children[1]
                .children
                .iter()
                .map(|field| source_span(source, field))
                .collect::<Vec<_>>(),
            [b"coord".as_slice(), b"", b"sdbserver1", b"11810", b""]
        );
        assert_tree_spans(&parsed);
    }

    #[test]
    fn odd_even_quotes_and_unknown_column_counts_are_local_opaque() {
        let source = b"instanceName,port,databaseDir,coordAddr\nodd,3306,/srv/\"odd,-\neven,3307,/srv/\"\"even,-\nfuture,3308,/srv/3308,-,extension\nsafe,3309,/srv/3309,-\n";
        let parsed = parse_sequoia_csv(source, SequoiaCsvExpectedSchema::SqlInstance).unwrap();
        assert_eq!(parsed.children.len(), 5);
        assert_eq!(parsed.children[1].kind, SequoiaCsvParsedKind::Opaque);
        assert_eq!(parsed.children[2].kind, SequoiaCsvParsedKind::Opaque);
        assert_eq!(parsed.children[3].kind, SequoiaCsvParsedKind::Opaque);
        assert!(parsed.children[1].sensitive);
        assert!(parsed.children[2].sensitive);
        assert_eq!(
            source_span(source, &parsed.children[1]),
            b"odd,3306,/srv/\"odd,-\n"
        );
        assert_eq!(parsed.children[4].kind, SequoiaCsvParsedKind::Record);
        assert_eq!(source_span(source, &parsed), source);
        assert_tree_spans(&parsed);
    }

    #[test]
    fn exact_first_physical_header_is_role_bound() {
        for source in [
            b"role,groupName,hostName,serviceName,dbPath".as_slice(),
            b"role,groupName,hostName,serviceName,dbPath\n".as_slice(),
            b"role,groupName,hostName,serviceName,dbPath\r\n".as_slice(),
        ] {
            let parsed = parse_sequoia_csv(source, SequoiaCsvExpectedSchema::Cluster).unwrap();
            assert_eq!(source_span(source, &parsed), source);
            assert_eq!(parsed.children.len(), 1);
            assert_eq!(parsed.children[0].kind, SequoiaCsvParsedKind::Header);
        }

        for source in [
            b"\xEF\xBB\xBFrole,groupName,hostName,serviceName,dbPath\n".as_slice(),
            b"\nrole,groupName,hostName,serviceName,dbPath\n".as_slice(),
            b"# note\nrole,groupName,hostName,serviceName,dbPath\n".as_slice(),
            b" role,groupName,hostName,serviceName,dbPath\n".as_slice(),
            b"role,groupName,hostName,serviceName,dbPath \n".as_slice(),
            b"Role,groupName,hostName,serviceName,dbPath\n".as_slice(),
            b"instanceName,port,databaseDir,coordAddr\n".as_slice(),
        ] {
            assert_document_opaque(source, SequoiaCsvExpectedSchema::Cluster);
        }
        assert_document_opaque(
            b"role,groupName,hostName,serviceName,dbPath\n",
            SequoiaCsvExpectedSchema::SqlInstance,
        );
    }

    #[test]
    fn comments_are_byte_zero_only_source_backed_and_do_not_swallow_records() {
        let source = b"instanceName,port,databaseDir,coordAddr\n# ordinary \" note,a,b,c\n# api_key=NeverShow \"\n # data,a,b,c\nsafe,3308,/srv/plain,-\n";
        let parsed = parse_sequoia_csv(source, SequoiaCsvExpectedSchema::SqlInstance).unwrap();
        assert_eq!(parsed.children.len(), 5);
        assert_eq!(parsed.children[1].kind, SequoiaCsvParsedKind::Comment);
        assert!(!parsed.children[1].sensitive);
        assert_eq!(
            source_span(source, &parsed.children[1]),
            b"# ordinary \" note,a,b,c\n"
        );
        assert_eq!(parsed.children[2].kind, SequoiaCsvParsedKind::Comment);
        assert!(parsed.children[2].sensitive);
        assert_eq!(parsed.children[3].kind, SequoiaCsvParsedKind::Record);
        assert_eq!(parsed.children[4].kind, SequoiaCsvParsedKind::Record);
        assert_eq!(
            source_span(source, &parsed.children[4].children[0]),
            b"safe"
        );
        assert_tree_spans(&parsed);
    }

    #[test]
    fn ambiguous_brackets_are_local_opaque_without_hiding_safe_siblings() {
        let source = b"instanceName,port,databaseDir,coordAddr\nunmatched,3306,/srv,[host:1,host:2\nnested,3307,/srv,[host:[1]]\ntail,3308,/srv,[host:1]tail\nclosing,3309,/srv,host:1]\nsafe,3310,/srv/plain,[host:1,host:2]\n";
        let parsed = parse_sequoia_csv(source, SequoiaCsvExpectedSchema::SqlInstance).unwrap();
        assert_eq!(parsed.children.len(), 6);
        assert!(
            parsed.children[1..5]
                .iter()
                .all(|node| { node.kind == SequoiaCsvParsedKind::Opaque && node.sensitive })
        );
        assert_eq!(parsed.children[5].kind, SequoiaCsvParsedKind::Record);
        assert_eq!(
            source_span(source, &parsed.children[5].children[0]),
            b"safe"
        );
        assert_tree_spans(&parsed);
    }

    #[test]
    fn invalid_utf8_and_nul_are_complete_opaque() {
        assert_document_opaque(
            b"role,groupName,hostName,serviceName,dbPath\n\xff\n",
            SequoiaCsvExpectedSchema::Cluster,
        );
        assert_document_opaque(
            b"role,groupName,hostName,serviceName,dbPath\n\0\n",
            SequoiaCsvExpectedSchema::Cluster,
        );
    }

    #[test]
    fn sensitive_carriers_and_opaque_rows_fail_closed_without_tainting_siblings() {
        let source = b"instanceName,port,databaseDir,coordAddr\napi_key,3306,/srv/api_key=NeverShow,-\napikey,3307,/srv/apikey=NeverShow,-\ncookie,3308,/srv/cookie=NeverShow,-\nconninfo,3309,/srv/conninfo=NeverShow,-\njdbc,3310,/srv/jdbc_url=NeverShow,-\nprivate,3311,/srv/private_key=NeverShow,-\nurl,3312,/srv,https://user:pass@example.test\nplain,3313,/srv/api_keys/cache,localhost:11810\n";
        let parsed = parse_sequoia_csv(source, SequoiaCsvExpectedSchema::SqlInstance).unwrap();
        for record in &parsed.children[1..7] {
            assert!(!record.children[0].sensitive);
            assert!(record.children[2].sensitive);
        }
        assert!(parsed.children[7].children[3].sensitive);
        let plain_record = &parsed.children[8];
        assert!(plain_record.children.iter().all(|field| !field.sensitive));
    }

    #[test]
    fn authkey_field_assignments_and_comments_are_sensitive_without_broad_auth_matches() {
        let source = b"instanceName,port,databaseDir,coordAddr\ncamel,3306,/srv/authkey=CamelDontLeak,-\nsnake,3307,/srv/AUTH_KEY=SnakeDontLeak,-\nplain,3308,/srv/authority=safe,auth_method=scram\nmode,3309,/srv/authentication_mode=strict,-\nprefix,3310,/srv/notauthkey=safe,-\n# authKey CommentDontLeak\n# authority remains visible\n";
        let parsed = parse_sequoia_csv(source, SequoiaCsvExpectedSchema::SqlInstance).unwrap();
        assert_eq!(source_span(source, &parsed), source);
        assert_eq!(parsed.children.len(), 8);
        assert!(parsed.children[1].children[2].sensitive);
        assert!(parsed.children[2].children[2].sensitive);
        assert!(
            parsed.children[3]
                .children
                .iter()
                .all(|field| !field.sensitive)
        );
        assert!(
            parsed.children[4]
                .children
                .iter()
                .all(|field| !field.sensitive)
        );
        assert!(
            parsed.children[5]
                .children
                .iter()
                .all(|field| !field.sensitive)
        );
        assert_eq!(parsed.children[6].kind, SequoiaCsvParsedKind::Comment);
        assert!(parsed.children[6].sensitive);
        assert_eq!(parsed.children[7].kind, SequoiaCsvParsedKind::Comment);
        assert!(!parsed.children[7].sensitive);
        assert_tree_spans(&parsed);
    }

    #[test]
    fn empty_and_leading_blank_documents_fail_the_header_gate() {
        for source in [b"".as_slice(), b"\r\n\n".as_slice()] {
            assert_document_opaque(source, SequoiaCsvExpectedSchema::Cluster);
        }
    }

    #[test]
    fn byte_node_and_token_limits_are_enforced() {
        let exact_bytes = vec![b' '; MAX_STRUCTURED_CONFIG_BYTES];
        assert!(parse_sequoia_csv(&exact_bytes, SequoiaCsvExpectedSchema::Cluster).is_ok());
        assert!(
            parse_sequoia_csv(
                &vec![b' '; MAX_STRUCTURED_CONFIG_BYTES + 1],
                SequoiaCsvExpectedSchema::Cluster,
            )
            .is_err()
        );

        let header_nodes = 1 + 1 + 5;
        let record_nodes = 1 + 5;
        let exact_records = (MAX_STRUCTURED_CONFIG_NODES - header_nodes) / record_nodes;
        let mut exact_nodes = String::from("role,groupName,hostName,serviceName,dbPath\n");
        exact_nodes.push_str(&"data,group,host,11820,/srv\n".repeat(exact_records));
        assert!(
            parse_sequoia_csv(exact_nodes.as_bytes(), SequoiaCsvExpectedSchema::Cluster).is_ok()
        );
        exact_nodes.push_str("data,group,host,11820,/srv\n");
        assert!(
            parse_sequoia_csv(exact_nodes.as_bytes(), SequoiaCsvExpectedSchema::Cluster).is_err()
        );

        let header_tokens = 1 + 5 + 4;
        let mut exact_tokens = String::from("role,groupName,hostName,serviceName,dbPath\n");
        exact_tokens.push_str(&"\n".repeat(MAX_STRUCTURED_CONFIG_TOKENS - header_tokens));
        assert!(
            parse_sequoia_csv(exact_tokens.as_bytes(), SequoiaCsvExpectedSchema::Cluster).is_ok()
        );
        exact_tokens.push('\n');
        assert!(
            parse_sequoia_csv(exact_tokens.as_bytes(), SequoiaCsvExpectedSchema::Cluster).is_err()
        );
    }
}
