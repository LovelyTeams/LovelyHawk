//! Bounded, target-bound evidence parsed from Apache HTTPD capability dumps.
//!
//! Apache modules can register configuration directives at runtime.  `httpd
//! -M` is therefore useful evidence about one exact invocation, while `httpd
//! -L` must not be treated as a complete catalogue for every shared or
//! third-party module.  This module deliberately performs no process or SSH
//! execution.  Callers must capture successful, untruncated command output
//! with the same target and startup context, then bind the parsed evidence to
//! the corresponding runtime and configuration-graph digests.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use crate::{
    CoreError, CoreResult,
    apache_runtime::{ApacheRuntimeInvocationEvidence, ApacheStableConfigGraphEvidence},
    target::TargetGuard,
};

pub const MAX_APACHE_MODULE_OUTPUT_BYTES: usize = 256 * 1024;
pub const MAX_APACHE_DIRECTIVE_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_APACHE_CAPABILITY_LINE_BYTES: usize = 16 * 1024;
pub const MAX_APACHE_CAPABILITY_LINES: usize = 65_536;
pub const MAX_APACHE_LOADED_MODULES: usize = 2_048;
pub const MAX_APACHE_DIRECTIVE_EVIDENCE: usize = 16_384;
const MAX_APACHE_CAPABILITY_NAME_BYTES: usize = 128;
const MAX_APACHE_DIRECTIVE_PROVIDER_BYTES: usize = 256;
const MAX_APACHE_DIRECTIVE_DETAIL_LINES: usize = 64;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ApacheModuleName(String);

impl ApacheModuleName {
    pub fn new(value: impl Into<String>) -> CoreResult<Self> {
        let value = value.into();
        validate_identifier("Apache module name", &value, |byte| {
            byte.is_ascii_alphanumeric() || byte == b'_'
        })?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ApacheDirectiveName(String);

impl ApacheDirectiveName {
    pub fn new(value: impl Into<String>) -> CoreResult<Self> {
        let value = value.into();
        validate_identifier("Apache directive name", &value, |byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
        })?;
        // Apache directive lookup is case-insensitive.  A canonical spelling
        // makes duplicate evidence and UI lookup deterministic.
        Ok(Self(value.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ApacheRuntimeFingerprint(String);

impl ApacheRuntimeFingerprint {
    #[allow(
        dead_code,
        reason = "only the UNWIRED typed Apache runtime provider may mint this digest"
    )]
    pub(crate) fn new(value: impl Into<String>) -> CoreResult<Self> {
        Ok(Self(validate_sha256(
            "Apache runtime fingerprint",
            value.into(),
        )?))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ApacheConfigGraphDigest(String);

impl ApacheConfigGraphDigest {
    #[allow(
        dead_code,
        reason = "only the UNWIRED typed Apache graph provider may mint this digest"
    )]
    pub(crate) fn new(value: impl Into<String>) -> CoreResult<Self> {
        Ok(Self(validate_sha256(
            "Apache configuration graph digest",
            value.into(),
        )?))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApacheModuleLinkage {
    Static,
    Shared,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ApacheModuleInventory {
    modules: BTreeMap<ApacheModuleName, ApacheModuleLinkage>,
}

impl fmt::Debug for ApacheModuleInventory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApacheModuleInventory")
            .field("module_count", &self.modules.len())
            .finish()
    }
}

impl ApacheModuleInventory {
    /// Parse the stdout of one successful, untruncated `httpd -M` invocation.
    ///
    /// The accepted grammar is intentionally narrow: one `Loaded Modules:`
    /// header followed only by indented `name (static|shared)` records.  Any
    /// diagnostic or unknown trailer makes the evidence unavailable instead
    /// of silently producing a partial inventory.
    pub fn parse_httpd_m(output: &[u8]) -> CoreResult<Self> {
        let text = validate_output("Apache -M output", output, MAX_APACHE_MODULE_OUTPUT_BYTES)?;
        let mut saw_header = false;
        let mut modules = BTreeMap::new();

        for raw_line in text.lines() {
            let line = raw_line.trim_end_matches('\r');
            if line.trim().is_empty() {
                continue;
            }
            if !saw_header {
                if line != "Loaded Modules:" {
                    return Err(CoreError::validation(
                        "Apache -M output",
                        "expected the exact Loaded Modules header before module records",
                    ));
                }
                saw_header = true;
                continue;
            }
            if !line.as_bytes()[0].is_ascii_whitespace() {
                return Err(CoreError::validation(
                    "Apache -M output",
                    "module records must be indented and contain no unknown trailer",
                ));
            }
            let record = line.trim();
            let Some(record) = record.strip_suffix(')') else {
                return Err(malformed_module_output());
            };
            let Some((name, linkage)) = record.rsplit_once(" (") else {
                return Err(malformed_module_output());
            };
            let name = ApacheModuleName::new(name.to_owned())?;
            let linkage = match linkage {
                "static" => ApacheModuleLinkage::Static,
                "shared" => ApacheModuleLinkage::Shared,
                _ => return Err(malformed_module_output()),
            };
            if modules.insert(name, linkage).is_some() {
                return Err(CoreError::validation(
                    "Apache -M output",
                    "contains a duplicate module record",
                ));
            }
            if modules.len() > MAX_APACHE_LOADED_MODULES {
                return Err(CoreError::validation(
                    "Apache -M output",
                    format!("contains more than {MAX_APACHE_LOADED_MODULES} modules"),
                ));
            }
        }

        if !saw_header || modules.is_empty() {
            return Err(CoreError::validation(
                "Apache -M output",
                "did not contain a non-empty loaded-module inventory",
            ));
        }
        Ok(Self { modules })
    }

    pub fn modules(&self) -> &BTreeMap<ApacheModuleName, ApacheModuleLinkage> {
        &self.modules
    }

    pub fn contains(&self, name: &ApacheModuleName) -> bool {
        self.modules.contains_key(name)
    }

    pub fn len(&self) -> usize {
        self.modules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }

    fn evaluate_if_module(&self, expression: &str) -> ApacheIfModuleEvaluation {
        if expression.is_empty()
            || expression.len() > MAX_APACHE_CAPABILITY_NAME_BYTES + 1
            || expression.chars().any(char::is_control)
            || expression.trim() != expression
            || expression.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return ApacheIfModuleEvaluation::Unresolved;
        }
        let (negated, operand) = expression
            .strip_prefix('!')
            .map_or((false, expression), |operand| (true, operand));
        if operand.is_empty() || operand.starts_with('!') {
            return ApacheIfModuleEvaluation::Unresolved;
        }
        // Apache also accepts a module source-file spelling such as
        // `mod_mime.c`.  `-M` exposes module identifiers, not a trustworthy
        // identifier-to-file map, so source-file operands remain unresolved.
        let Ok(module) = ApacheModuleName::new(operand.to_owned()) else {
            return ApacheIfModuleEvaluation::Unresolved;
        };
        // `-M` is a final inventory, while `<IfModule>` is evaluated at the
        // directive's position during configuration reading. A shared module
        // may therefore have been loaded only after the section. Only a static
        // module is proven to have existed throughout configuration parsing.
        match (self.modules.get(&module), negated) {
            (Some(ApacheModuleLinkage::Static), false) => ApacheIfModuleEvaluation::Active,
            (Some(ApacheModuleLinkage::Static), true) => ApacheIfModuleEvaluation::Inactive,
            (Some(ApacheModuleLinkage::Shared) | None, _) => ApacheIfModuleEvaluation::Unresolved,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApacheDirectiveCatalogCompleteness {
    /// Conservative lower-bound evidence only.  There is deliberately no
    /// `Complete` variant: absence from `-L` never proves unsupported syntax.
    StaticOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApacheDirectiveSupport {
    /// The bounded `-L` evidence contains this directive.  This proves only
    /// the conservative static-catalogue claim represented by this snapshot.
    ProvenStatic,
    /// Absence from `-L` is not an unsupported verdict because a loaded shared
    /// or third-party module may register the directive.
    UnknownSharedOrThirdParty,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ApacheDirectiveEvidence {
    name: ApacheDirectiveName,
    spelling: String,
    section: bool,
    provider: String,
    detail_lines: Vec<String>,
}

impl fmt::Debug for ApacheDirectiveEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApacheDirectiveEvidence")
            .field("name", &self.name)
            .field("section", &self.section)
            .field("provider", &self.provider)
            .field("detail_line_count", &self.detail_lines.len())
            .finish()
    }
}

impl ApacheDirectiveEvidence {
    pub fn name(&self) -> &ApacheDirectiveName {
        &self.name
    }

    pub fn spelling(&self) -> &str {
        &self.spelling
    }

    pub const fn is_section(&self) -> bool {
        self.section
    }

    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// Bounded, hostile plain text from `httpd -L`; callers must not interpret
    /// these lines as markup, paths, commands, or action identifiers.
    pub fn detail_lines(&self) -> &[String] {
        &self.detail_lines
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ApacheDirectiveCatalog {
    entries: Vec<ApacheDirectiveEvidence>,
    names: BTreeSet<ApacheDirectiveName>,
}

impl fmt::Debug for ApacheDirectiveCatalog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApacheDirectiveCatalog")
            .field("completeness", &self.completeness())
            .field("entry_count", &self.entries.len())
            .field("distinct_name_count", &self.names.len())
            .finish()
    }
}

impl ApacheDirectiveCatalog {
    /// Parse bounded `httpd -L` evidence.
    ///
    /// Even when parsing succeeds, this catalogue is `StaticOnly`.  Consumers
    /// must never turn an absent directive into an unsupported verdict.
    /// Apache does not escape multiline help: a third-party continuation that
    /// is byte-for-byte identical to a header is inherently ambiguous and may
    /// make this strict parser reject the whole catalogue rather than guess.
    pub fn parse_httpd_l(output: &[u8]) -> CoreResult<Self> {
        let text = validate_output(
            "Apache -L output",
            output,
            MAX_APACHE_DIRECTIVE_OUTPUT_BYTES,
        )?;
        let mut entries = Vec::new();
        let mut current: Option<ApacheDirectiveEvidence> = None;

        for raw_line in text.lines() {
            let line = raw_line.trim_end_matches('\r');
            if line.trim().is_empty() {
                continue;
            }

            if let Some(header) = try_parse_directive_header(line)? {
                if let Some(entry) = current.take() {
                    finish_directive_entry(entry, &mut entries)?;
                }
                current = Some(header);
                continue;
            }

            let Some(entry) = current.as_mut() else {
                return Err(malformed_directive_output());
            };
            append_directive_detail(entry, line)?;
        }
        if let Some(entry) = current {
            finish_directive_entry(entry, &mut entries)?;
        }
        if entries.is_empty() {
            return Err(CoreError::validation(
                "Apache -L output",
                "did not contain any directive evidence",
            ));
        }
        let names = entries.iter().map(|entry| entry.name.clone()).collect();
        Ok(Self { entries, names })
    }

    pub const fn completeness(&self) -> ApacheDirectiveCatalogCompleteness {
        ApacheDirectiveCatalogCompleteness::StaticOnly
    }

    pub fn entries(&self) -> &[ApacheDirectiveEvidence] {
        &self.entries
    }

    pub fn has_static_evidence(&self, name: &ApacheDirectiveName) -> bool {
        self.names.contains(name)
    }

    pub fn support(&self, name: &ApacheDirectiveName) -> ApacheDirectiveSupport {
        if self.has_static_evidence(name) {
            ApacheDirectiveSupport::ProvenStatic
        } else {
            ApacheDirectiveSupport::UnknownSharedOrThirdParty
        }
    }

    pub fn evidence_for(
        &self,
        name: &ApacheDirectiveName,
    ) -> impl Iterator<Item = &ApacheDirectiveEvidence> {
        self.entries.iter().filter(move |entry| &entry.name == name)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApacheCapabilityFreshness {
    Current,
    TargetChanged,
    RuntimeChanged,
    ConfigurationChanged,
}

impl ApacheCapabilityFreshness {
    pub const fn is_stale(self) -> bool {
        !matches!(self, Self::Current)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApacheIfModuleEvaluation {
    /// The referenced module is statically linked and the condition is true.
    Active,
    /// The referenced module is statically linked and the condition is false.
    Inactive,
    /// Shared/missing modules, complex expressions, and module-file operands
    /// cannot be resolved at one configuration position from a final `-M`
    /// inventory and therefore fail closed.
    Unresolved,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ApacheCapabilitySnapshot {
    target: TargetGuard,
    runtime_fingerprint: ApacheRuntimeFingerprint,
    config_graph_digest: ApacheConfigGraphDigest,
    modules: ApacheModuleInventory,
    directives: ApacheDirectiveCatalog,
}

impl fmt::Debug for ApacheCapabilitySnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApacheCapabilitySnapshot")
            .field("target", &self.target)
            .field("runtime_fingerprint", &self.runtime_fingerprint)
            .field("config_graph_digest", &self.config_graph_digest)
            .field("module_count", &self.modules.len())
            .field("directive_evidence_count", &self.directives.len())
            .field("directive_completeness", &self.directives.completeness())
            .finish()
    }
}

impl ApacheCapabilitySnapshot {
    #[allow(
        dead_code,
        reason = "capability transport remains explicitly UNWIRED in Phase A"
    )]
    pub(crate) fn from_outputs(
        runtime: &ApacheRuntimeInvocationEvidence,
        graph: &ApacheStableConfigGraphEvidence,
        httpd_m_output: &[u8],
        httpd_l_output: &[u8],
    ) -> CoreResult<Self> {
        graph.validate_runtime(runtime)?;
        let modules = ApacheModuleInventory::parse_httpd_m(httpd_m_output)?;
        let directives = ApacheDirectiveCatalog::parse_httpd_l(httpd_l_output)?;
        Self::new(runtime, graph, modules, directives)
    }

    #[allow(
        dead_code,
        reason = "reachable only from the intentionally UNWIRED capability transport boundary"
    )]
    fn new(
        runtime: &ApacheRuntimeInvocationEvidence,
        graph: &ApacheStableConfigGraphEvidence,
        modules: ApacheModuleInventory,
        directives: ApacheDirectiveCatalog,
    ) -> CoreResult<Self> {
        graph.validate_runtime(runtime)?;
        if modules.is_empty() || directives.is_empty() {
            return Err(CoreError::validation(
                "Apache capability snapshot",
                "module and directive evidence must both be non-empty",
            ));
        }
        Ok(Self {
            target: runtime.target().clone(),
            runtime_fingerprint: runtime.fingerprint().clone(),
            config_graph_digest: graph.digest().clone(),
            modules,
            directives,
        })
    }

    pub fn target(&self) -> &TargetGuard {
        &self.target
    }

    pub fn runtime_fingerprint(&self) -> &ApacheRuntimeFingerprint {
        &self.runtime_fingerprint
    }

    pub fn config_graph_digest(&self) -> &ApacheConfigGraphDigest {
        &self.config_graph_digest
    }

    pub fn evidence_if_fresh(
        &self,
        current_target: &TargetGuard,
        current_runtime: &ApacheRuntimeFingerprint,
        current_config: &ApacheConfigGraphDigest,
    ) -> CoreResult<(&ApacheModuleInventory, &ApacheDirectiveCatalog)> {
        self.validate_fresh(current_target, current_runtime, current_config)?;
        Ok((&self.modules, &self.directives))
    }

    /// Compare all three immutable bindings.  Target mismatch takes
    /// precedence, followed by runtime and configuration changes.
    pub fn freshness(
        &self,
        current_target: &TargetGuard,
        current_runtime: &ApacheRuntimeFingerprint,
        current_config: &ApacheConfigGraphDigest,
    ) -> ApacheCapabilityFreshness {
        if &self.target != current_target {
            ApacheCapabilityFreshness::TargetChanged
        } else if &self.runtime_fingerprint != current_runtime {
            ApacheCapabilityFreshness::RuntimeChanged
        } else if &self.config_graph_digest != current_config {
            ApacheCapabilityFreshness::ConfigurationChanged
        } else {
            ApacheCapabilityFreshness::Current
        }
    }

    pub fn validate_fresh(
        &self,
        current_target: &TargetGuard,
        current_runtime: &ApacheRuntimeFingerprint,
        current_config: &ApacheConfigGraphDigest,
    ) -> CoreResult<()> {
        match self.freshness(current_target, current_runtime, current_config) {
            ApacheCapabilityFreshness::Current => Ok(()),
            ApacheCapabilityFreshness::TargetChanged => Err(CoreError::TargetChanged {
                expected_identity: self.target.identity.as_str().to_owned(),
                expected_generation: self.target.generation,
                current: format!(
                    "{}@{}",
                    current_target.identity.as_str(),
                    current_target.generation
                ),
            }),
            ApacheCapabilityFreshness::RuntimeChanged => Err(CoreError::validation(
                "Apache capability snapshot",
                "runtime fingerprint changed after capability capture",
            )),
            ApacheCapabilityFreshness::ConfigurationChanged => Err(CoreError::validation(
                "Apache capability snapshot",
                "configuration graph digest changed after capability capture",
            )),
        }
    }

    /// Evaluate the statically linked subset of one `<IfModule
    /// module_identifier>` or its `!identifier` negation after proving that
    /// this snapshot still owns the current target, runtime, and graph.
    /// Shared or absent identifiers remain unresolved because `-M` reports the
    /// final inventory, not the inventory at the section's source position.
    pub fn evaluate_if_module(
        &self,
        current_target: &TargetGuard,
        current_runtime: &ApacheRuntimeFingerprint,
        current_config: &ApacheConfigGraphDigest,
        expression: &str,
    ) -> CoreResult<ApacheIfModuleEvaluation> {
        self.validate_fresh(current_target, current_runtime, current_config)?;
        Ok(self.modules.evaluate_if_module(expression))
    }
}

fn validate_identifier(
    subject: &'static str,
    value: &str,
    allowed: impl Fn(u8) -> bool,
) -> CoreResult<()> {
    if value.is_empty()
        || value.len() > MAX_APACHE_CAPABILITY_NAME_BYTES
        || !value.as_bytes()[0].is_ascii_alphabetic()
        || !value.bytes().all(allowed)
    {
        return Err(CoreError::validation(
            subject,
            format!(
                "must be 1-{MAX_APACHE_CAPABILITY_NAME_BYTES} ASCII bytes, start with a letter, and contain only identifier characters"
            ),
        ));
    }
    Ok(())
}

#[allow(
    dead_code,
    reason = "used only by crate-private Apache evidence digest constructors"
)]
fn validate_sha256(subject: &'static str, value: String) -> CoreResult<String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CoreError::validation(
            subject,
            "must be one exact 64-character hexadecimal SHA-256 digest",
        ));
    }
    Ok(value.to_ascii_lowercase())
}

fn validate_output<'a>(
    subject: &'static str,
    output: &'a [u8],
    maximum_bytes: usize,
) -> CoreResult<&'a str> {
    if output.is_empty() || output.len() > maximum_bytes {
        return Err(CoreError::validation(
            subject,
            format!("must contain 1-{maximum_bytes} bytes of untruncated output"),
        ));
    }
    if !output.ends_with(b"\n") {
        return Err(CoreError::validation(
            subject,
            "must end with a line terminator so a truncated final record cannot be accepted",
        ));
    }
    if output
        .iter()
        .enumerate()
        .any(|(index, byte)| *byte == b'\r' && output.get(index + 1) != Some(&b'\n'))
    {
        return Err(CoreError::validation(
            subject,
            "contains a bare carriage return instead of an LF or CRLF line ending",
        ));
    }
    let text = std::str::from_utf8(output)
        .map_err(|_| CoreError::validation(subject, "must be valid UTF-8"))?;
    if text
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(CoreError::validation(
            subject,
            "contains an unsupported control character",
        ));
    }
    let mut line_count = 0usize;
    for line in text.lines() {
        line_count = line_count.checked_add(1).ok_or_else(|| {
            CoreError::validation(subject, "line count overflowed the bounded parser")
        })?;
        if line_count > MAX_APACHE_CAPABILITY_LINES {
            return Err(CoreError::validation(
                subject,
                format!("contains more than {MAX_APACHE_CAPABILITY_LINES} lines"),
            ));
        }
        if line.len() > MAX_APACHE_CAPABILITY_LINE_BYTES {
            return Err(CoreError::validation(
                subject,
                format!("contains a line longer than {MAX_APACHE_CAPABILITY_LINE_BYTES} bytes"),
            ));
        }
    }
    Ok(text)
}

fn malformed_module_output() -> CoreError {
    CoreError::validation(
        "Apache -M output",
        "expected one exact `module_name (static|shared)` record",
    )
}

fn try_parse_directive_header(line: &str) -> CoreResult<Option<ApacheDirectiveEvidence>> {
    let Some(line) = line.strip_suffix(')') else {
        return Ok(None);
    };
    let Some((raw_name, provider)) = line.rsplit_once(" (") else {
        return Ok(None);
    };
    let section = raw_name.starts_with('<');
    let raw_identifier = if section {
        raw_name
            .strip_prefix('<')
            .and_then(|name| name.strip_suffix('>').or(Some(name)))
            .unwrap_or_default()
    } else {
        raw_name
    };
    let Ok(name) = ApacheDirectiveName::new(raw_identifier.to_owned()) else {
        // command_rec help text may contain unindented physical lines.  A
        // line is a new record only when its complete header grammar is
        // unambiguous; all other text remains bounded detail of the current
        // directive.
        return Ok(None);
    };
    if provider.is_empty()
        || provider.len() > MAX_APACHE_DIRECTIVE_PROVIDER_BYTES
        || !provider
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Ok(None);
    }
    Ok(Some(ApacheDirectiveEvidence {
        name,
        spelling: raw_name.to_owned(),
        section,
        provider: provider.to_owned(),
        detail_lines: Vec::new(),
    }))
}

fn append_directive_detail(entry: &mut ApacheDirectiveEvidence, line: &str) -> CoreResult<()> {
    if entry.detail_lines.len() >= MAX_APACHE_DIRECTIVE_DETAIL_LINES {
        return Err(CoreError::validation(
            "Apache -L output",
            format!(
                "one directive contains more than {MAX_APACHE_DIRECTIVE_DETAIL_LINES} detail lines"
            ),
        ));
    }
    entry.detail_lines.push(line.trim().to_owned());
    Ok(())
}

fn finish_directive_entry(
    entry: ApacheDirectiveEvidence,
    entries: &mut Vec<ApacheDirectiveEvidence>,
) -> CoreResult<()> {
    let complete_context = entry
        .detail_lines
        .last()
        .is_some_and(|allowed| parse_allowed_context_line(allowed, false).is_some())
        || match entry.detail_lines.as_slice() {
            [.., allowed, when] => match (
                parse_allowed_context_line(allowed, true),
                parse_allow_override_context_line(when),
            ) {
                (Some(ApacheAllowedContext::Anywhere), Some(_)) => true,
                (Some(ApacheAllowedContext::OnlyInside), Some(mask)) => {
                    mask & !(APACHE_OVERRIDE_AUTH_CONFIG | APACHE_OVERRIDE_LIMIT) == 0
                }
                _ => false,
            },
            _ => false,
        };
    if !complete_context {
        return Err(CoreError::validation(
            "Apache -L output",
            "each directive record must end with complete `Allowed in` context evidence",
        ));
    }
    entries.push(entry);
    if entries.len() > MAX_APACHE_DIRECTIVE_EVIDENCE {
        return Err(CoreError::validation(
            "Apache -L output",
            format!(
                "contains more than {MAX_APACHE_DIRECTIVE_EVIDENCE} directive evidence records"
            ),
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApacheAllowedContext {
    Anywhere,
    OnlyOutside,
    OnlyInside,
}

const APACHE_OVERRIDE_AUTH_CONFIG: u8 = 1 << 0;
const APACHE_OVERRIDE_LIMIT: u8 = 1 << 1;
const APACHE_OVERRIDE_OPTIONS: u8 = 1 << 2;
const APACHE_OVERRIDE_FILE_INFO: u8 = 1 << 3;
const APACHE_OVERRIDE_INDEXES: u8 = 1 << 4;
const APACHE_OVERRIDE_ALL: u8 = APACHE_OVERRIDE_AUTH_CONFIG
    | APACHE_OVERRIDE_LIMIT
    | APACHE_OVERRIDE_OPTIONS
    | APACHE_OVERRIDE_FILE_INFO
    | APACHE_OVERRIDE_INDEXES;

fn parse_allowed_context_line(line: &str, expect_htaccess: bool) -> Option<ApacheAllowedContext> {
    const MODES: [(&str, ApacheAllowedContext); 3] = [
        ("anywhere", ApacheAllowedContext::Anywhere),
        (
            "only outside <Directory>, <Files>, <Location>, or <If>",
            ApacheAllowedContext::OnlyOutside,
        ),
        (
            "only inside <Directory>, <Files>, <Location>, or <If>",
            ApacheAllowedContext::OnlyInside,
        ),
    ];
    const NO_PER_DIR: &str = " [no per-dir config]";
    const HTACCESS: &str = " and in .htaccess";

    let rest = line.strip_prefix("Allowed in *.conf ")?;
    MODES.into_iter().find_map(|(spelling, mode)| {
        let mut suffix = rest.strip_prefix(spelling)?;
        let mut no_per_dir = false;
        if let Some(remaining) = suffix.strip_prefix(NO_PER_DIR) {
            suffix = remaining;
            no_per_dir = true;
        }
        let exact_suffix = if expect_htaccess {
            suffix == HTACCESS
        } else {
            suffix.is_empty()
        };
        if !exact_suffix
            || mode == ApacheAllowedContext::OnlyOutside && (no_per_dir || expect_htaccess)
        {
            return None;
        }
        Some(mode)
    })
}

fn parse_allow_override_context_line(line: &str) -> Option<u8> {
    if line == "when AllowOverride isn't None" {
        return Some(APACHE_OVERRIDE_ALL);
    }
    let list = line.strip_prefix("when AllowOverride includes ")?;
    const OVERRIDES: [(&str, u8); 5] = [
        ("AuthConfig", APACHE_OVERRIDE_AUTH_CONFIG),
        ("Limit", APACHE_OVERRIDE_LIMIT),
        ("Options", APACHE_OVERRIDE_OPTIONS),
        ("FileInfo", APACHE_OVERRIDE_FILE_INFO),
        ("Indexes", APACHE_OVERRIDE_INDEXES),
    ];
    let mut previous = None;
    let mut mask = 0u8;
    for item in list.split(" or ") {
        let position = OVERRIDES
            .iter()
            .position(|(candidate, _)| *candidate == item)?;
        if previous.is_some_and(|previous| position <= previous) {
            return None;
        }
        mask |= OVERRIDES[position].1;
        previous = Some(position);
    }
    previous.map(|_| mask)
}

fn malformed_directive_output() -> CoreError {
    CoreError::validation(
        "Apache -L output",
        "expected one exact `DirectiveName (provider.c)` header",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        apache_runtime::{ApacheConfigGraphEvidence, ApacheRuntimeInvocationEvidence},
        target::TargetIdentity,
    };

    const MODULES: &[u8] = b"Loaded Modules:\r\n core_module (static)\r\n headers_module (shared)\r\n ssl_module (shared)\r\n";
    const DIRECTIVES: &[u8] = b"ServerRoot (core.c)\n\tCommon directory of server-related files\n\tAllowed in *.conf only outside <Directory>, <Files>, <Location>, or <If>\n<Directory (core.c)\n\tContainer for directives affecting the requested directory\n\tAllowed in *.conf anywhere\nHeader (mod_headers.c)\n\tAn HTTP response header\n\tAllowed in *.conf anywhere and in .htaccess\n\twhen AllowOverride includes FileInfo\n";

    fn target(identity: &str, generation: u64) -> TargetGuard {
        TargetGuard {
            identity: TargetIdentity::new(identity).unwrap(),
            generation,
        }
    }

    fn runtime(byte: char) -> ApacheRuntimeFingerprint {
        ApacheRuntimeFingerprint::new(byte.to_string().repeat(64)).unwrap()
    }

    fn config(byte: char) -> ApacheConfigGraphDigest {
        ApacheConfigGraphDigest::new(byte.to_string().repeat(64)).unwrap()
    }

    fn snapshot() -> ApacheCapabilitySnapshot {
        let runtime =
            ApacheRuntimeInvocationEvidence::test_fixture(target("host-a", 7), 1).unwrap();
        let capture = ApacheConfigGraphEvidence::test_fixture(&runtime, 2).unwrap();
        let graph = ApacheStableConfigGraphEvidence::seal(capture.clone(), capture).unwrap();
        ApacheCapabilitySnapshot::from_outputs(&runtime, &graph, MODULES, DIRECTIVES).unwrap()
    }

    #[test]
    fn typed_names_and_digests_reject_ambiguous_or_injectable_values() {
        assert!(ApacheModuleName::new("headers_module").is_ok());
        assert!(ApacheModuleName::new("headers-module").is_err());
        assert!(ApacheModuleName::new("headers_module\nnext").is_err());
        assert!(ApacheModuleName::new("1module").is_err());
        assert!(ApacheDirectiveName::new("Header").is_ok());
        assert!(ApacheDirectiveName::new("Header;id").is_err());
        assert!(ApacheRuntimeFingerprint::new("a".repeat(63)).is_err());
        assert!(ApacheConfigGraphDigest::new("g".repeat(64)).is_err());
        assert_eq!(
            ApacheConfigGraphDigest::new("AB".repeat(32))
                .unwrap()
                .as_str(),
            "ab".repeat(32)
        );
    }

    #[test]
    fn httpd_m_parser_preserves_typed_linkage_and_crlf() {
        let inventory = ApacheModuleInventory::parse_httpd_m(MODULES).unwrap();
        assert_eq!(inventory.len(), 3);
        assert_eq!(
            inventory
                .modules()
                .get(&ApacheModuleName::new("core_module").unwrap()),
            Some(&ApacheModuleLinkage::Static)
        );
        assert_eq!(
            inventory
                .modules()
                .get(&ApacheModuleName::new("headers_module").unwrap()),
            Some(&ApacheModuleLinkage::Shared)
        );
    }

    #[test]
    fn httpd_m_parser_rejects_partial_duplicate_and_unknown_records() {
        for output in [
            b" core_module (static)\n".as_slice(),
            b"Loaded Modules:\n".as_slice(),
            b"Loaded Modules:\n core_module (dynamic)\n".as_slice(),
            b"Loaded Modules:\n core_module (static)\nunknown trailer\n".as_slice(),
            b"Loaded Modules:\n core_module (static)\n core_module (static)\n".as_slice(),
            b"Loaded Modules:\n core_module (static)".as_slice(),
            b"Loaded Modules:\n core_module (static)\n\x1b[31m".as_slice(),
            &[0xff, 0xfe],
        ] {
            assert!(ApacheModuleInventory::parse_httpd_m(output).is_err());
        }
    }

    #[test]
    fn capability_output_byte_and_line_limits_fail_closed() {
        let oversized = vec![b'x'; MAX_APACHE_MODULE_OUTPUT_BYTES + 1];
        assert!(ApacheModuleInventory::parse_httpd_m(&oversized).is_err());

        let mut long_line = b"Loaded Modules:\n ".to_vec();
        long_line.extend(std::iter::repeat_n(
            b'a',
            MAX_APACHE_CAPABILITY_LINE_BYTES + 1,
        ));
        long_line.push(b'\n');
        assert!(ApacheModuleInventory::parse_httpd_m(&long_line).is_err());

        let mut exact_line = vec![b'a'; MAX_APACHE_CAPABILITY_LINE_BYTES];
        exact_line.push(b'\n');
        assert!(
            validate_output(
                "bounded Apache test output",
                &exact_line,
                MAX_APACHE_DIRECTIVE_OUTPUT_BYTES,
            )
            .is_ok()
        );
        let mut over_line = vec![b'a'; MAX_APACHE_CAPABILITY_LINE_BYTES + 1];
        over_line.push(b'\n');
        assert!(
            validate_output(
                "bounded Apache test output",
                &over_line,
                MAX_APACHE_DIRECTIVE_OUTPUT_BYTES,
            )
            .is_err()
        );
    }

    #[test]
    fn httpd_l_parser_is_explicitly_static_only_and_case_insensitive() {
        let catalog = ApacheDirectiveCatalog::parse_httpd_l(DIRECTIVES).unwrap();
        assert_eq!(catalog.len(), 3);
        assert_eq!(
            catalog.completeness(),
            ApacheDirectiveCatalogCompleteness::StaticOnly
        );
        let header = ApacheDirectiveName::new("HEADER").unwrap();
        assert!(catalog.has_static_evidence(&header));
        assert_eq!(
            catalog.support(&header),
            ApacheDirectiveSupport::ProvenStatic
        );
        let header = catalog.evidence_for(&header).next().unwrap();
        assert_eq!(header.spelling(), "Header");
        assert_eq!(header.provider(), "mod_headers.c");
        assert!(!header.is_section());
        assert_eq!(header.detail_lines().len(), 3);

        let directory = ApacheDirectiveName::new("Directory").unwrap();
        assert!(
            catalog
                .evidence_for(&directory)
                .next()
                .unwrap()
                .is_section()
        );

        let dynamic = ApacheDirectiveName::new("ThirdPartyDirective").unwrap();
        assert!(!catalog.has_static_evidence(&dynamic));
        assert_eq!(
            catalog.support(&dynamic),
            ApacheDirectiveSupport::UnknownSharedOrThirdParty
        );
    }

    #[test]
    fn httpd_l_parser_rejects_missing_details_or_malformed_remote_text() {
        for output in [
            b"\tAllowed in *.conf anywhere\n".as_slice(),
            b"Header (mod_headers.c)\n".as_slice(),
            b"Header (/tmp/evil.c)\n\targuments\n".as_slice(),
            b"Header (mod_headers.c) trailing\n\targuments\n".as_slice(),
            b"Header (mod_headers.c)\n\targument\0hidden\n".as_slice(),
            b"Header (mod_headers.c)\n\targument".as_slice(),
            b"Header (mod_headers.c)\n\ttrusted\rFORGED\n".as_slice(),
            b"Header (mod_headers.c)\n\thelp\n\tAllowed in *.conf attacker-controlled\n"
                .as_slice(),
            b"Header (mod_headers.c)\n\thelp\n\tAllowed in *.conf anywhere and in .htaccess\n\twhen AllowOverride attacker-controlled\n"
                .as_slice(),
            b"Header (mod_headers.c)\n\thelp\n\tAllowed in *.conf anywhere and in .htaccess\n\twhen AllowOverride includes FileInfo or AuthConfig\n"
                .as_slice(),
            &[0xff],
        ] {
            assert!(ApacheDirectiveCatalog::parse_httpd_l(output).is_err());
        }
    }

    #[test]
    fn httpd_l_parser_accepts_real_multiline_help_and_requires_complete_context() {
        let auth_ldap_url = b"AuthLDAPURL (mod_authnz_ldap.c)\n\
\tURL to define LDAP connection. This should be an RFC 2255 compliant\n\
URL of the form ldap://host[:port]/basedn[?attrib[?scope[?filter]]].\n\
<ul>\n\
<li>Host is the name of the LDAP server. Use a space separated list of hosts\n\
to specify redundant servers.\n\
<li>Port is optional, and specifies the port to connect to.\n\
<li>basedn specifies the base DN to start searches from\n\
<li>Attrib specifies what attribute to search for in the directory.\n\
<li>Scope is the scope of the search.\n\
<li>Filter is a filter to use in the search.\n\
</ul>\n\
Searches are performed using the attribute and the filter combined.\n\
For example, assume that the LDAP URL is ldap://ldap.example.test/ou=People.\n\
Searches will be done using the combined filter.\n\
The search will be a subtree search on the configured branch.\n\
\tAllowed in *.conf anywhere and in .htaccess\n\
\twhen AllowOverride includes AuthConfig\n";
        let catalog = ApacheDirectiveCatalog::parse_httpd_l(auth_ldap_url).unwrap();
        assert_eq!(catalog.len(), 1);
        let evidence = &catalog.entries()[0];
        assert_eq!(evidence.name().as_str(), "authldapurl");
        assert_eq!(evidence.detail_lines().len(), 17);
        assert_eq!(
            evidence.detail_lines()[1],
            "URL of the form ldap://host[:port]/basedn[?attrib[?scope[?filter]]]."
        );

        let truncated_before_context = b"AuthLDAPURL (mod_authnz_ldap.c)\n\targument help\n";
        assert!(
            ApacheDirectiveCatalog::parse_httpd_l(truncated_before_context).is_err(),
            "a successful-looking record without show_overrides context is incomplete"
        );
        let truncated_before_allow_override = b"AuthLDAPURL (mod_authnz_ldap.c)\n\
\targument help\n\
\tAllowed in *.conf anywhere and in .htaccess\n";
        assert!(ApacheDirectiveCatalog::parse_httpd_l(truncated_before_allow_override).is_err());

        let directive_like_help = b"Example (core.c)\n\
\tfirst line\n\
Syntax (one argument)\n\
\tAllowed in *.conf anywhere\n";
        let catalog = ApacheDirectiveCatalog::parse_httpd_l(directive_like_help).unwrap();
        assert_eq!(
            catalog.entries()[0].detail_lines()[1],
            "Syntax (one argument)"
        );
    }

    #[test]
    fn httpd_l_context_cross_fields_match_show_overrides_reachable_states() {
        let only_inside_htaccess = b"Example (core.c)\n\
\thelp\n\
\tAllowed in *.conf only inside <Directory>, <Files>, <Location>, or <If> and in .htaccess\n\
\twhen AllowOverride includes AuthConfig or Limit\n";
        assert!(ApacheDirectiveCatalog::parse_httpd_l(only_inside_htaccess).is_ok());

        for impossible in [
            b"Example (core.c)\n\thelp\n\tAllowed in *.conf only outside <Directory>, <Files>, <Location>, or <If> [no per-dir config]\n"
                .as_slice(),
            b"Example (core.c)\n\thelp\n\tAllowed in *.conf only outside <Directory>, <Files>, <Location>, or <If> and in .htaccess\n\twhen AllowOverride includes AuthConfig\n"
                .as_slice(),
            b"Example (core.c)\n\thelp\n\tAllowed in *.conf only inside <Directory>, <Files>, <Location>, or <If> and in .htaccess\n\twhen AllowOverride isn't None\n"
                .as_slice(),
            b"Example (core.c)\n\thelp\n\tAllowed in *.conf only inside <Directory>, <Files>, <Location>, or <If> and in .htaccess\n\twhen AllowOverride includes Options\n"
                .as_slice(),
        ] {
            assert!(ApacheDirectiveCatalog::parse_httpd_l(impossible).is_err());
        }
    }

    #[test]
    fn duplicate_directive_names_are_evidence_not_a_completeness_claim() {
        let catalog = ApacheDirectiveCatalog::parse_httpd_l(
            b"Example (core.c)\n\tfirst form\n\tAllowed in *.conf anywhere\nExample (mod_example.c)\n\tsecond form\n\tAllowed in *.conf anywhere\n",
        )
        .unwrap();
        let name = ApacheDirectiveName::new("example").unwrap();
        assert_eq!(catalog.evidence_for(&name).count(), 2);
        assert_eq!(
            catalog.completeness(),
            ApacheDirectiveCatalogCompleteness::StaticOnly
        );
    }

    #[test]
    fn snapshot_binds_target_runtime_and_configuration_digests() {
        let snapshot = snapshot();
        let current_target = snapshot.target().clone();
        let current_runtime = snapshot.runtime_fingerprint().clone();
        let current_config = snapshot.config_graph_digest().clone();
        assert_eq!(
            snapshot.freshness(&current_target, &current_runtime, &current_config),
            ApacheCapabilityFreshness::Current
        );
        assert_eq!(
            snapshot.freshness(&target("host-a", 8), &current_runtime, &current_config),
            ApacheCapabilityFreshness::TargetChanged
        );
        assert_eq!(
            snapshot.freshness(&current_target, &runtime('c'), &current_config),
            ApacheCapabilityFreshness::RuntimeChanged
        );
        assert_eq!(
            snapshot.freshness(&current_target, &current_runtime, &config('d')),
            ApacheCapabilityFreshness::ConfigurationChanged
        );
        assert!(
            snapshot
                .validate_fresh(&target("host-b", 7), &current_runtime, &current_config)
                .is_err()
        );
        assert!(ApacheCapabilityFreshness::RuntimeChanged.is_stale());
        assert!(!ApacheCapabilityFreshness::Current.is_stale());
        let (modules, directives) = snapshot
            .evidence_if_fresh(&current_target, &current_runtime, &current_config)
            .unwrap();
        assert_eq!(modules.len(), 3);
        assert_eq!(directives.len(), 3);
        assert!(
            snapshot
                .evidence_if_fresh(&target("host-a", 8), &current_runtime, &current_config)
                .is_err()
        );
    }

    #[test]
    fn snapshot_requires_matching_runtime_and_stable_graph_evidence() {
        let runtime =
            ApacheRuntimeInvocationEvidence::test_fixture(target("host-a", 7), 1).unwrap();
        let other_runtime =
            ApacheRuntimeInvocationEvidence::test_fixture(target("host-a", 8), 1).unwrap();
        let capture = ApacheConfigGraphEvidence::test_fixture(&other_runtime, 2).unwrap();
        let graph = ApacheStableConfigGraphEvidence::seal(capture.clone(), capture).unwrap();
        assert!(
            ApacheCapabilitySnapshot::from_outputs(&runtime, &graph, MODULES, DIRECTIVES).is_err()
        );
    }

    #[test]
    fn if_module_evaluates_only_single_identifier_and_negation() {
        let snapshot = snapshot();
        let current_target = snapshot.target().clone();
        let current_runtime = snapshot.runtime_fingerprint().clone();
        let current_config = snapshot.config_graph_digest().clone();
        let evaluate = |expression| {
            snapshot
                .evaluate_if_module(
                    &current_target,
                    &current_runtime,
                    &current_config,
                    expression,
                )
                .unwrap()
        };

        assert_eq!(evaluate("core_module"), ApacheIfModuleEvaluation::Active);
        assert_eq!(evaluate("!core_module"), ApacheIfModuleEvaluation::Inactive);
        for expression in [
            "headers_module",
            "!headers_module",
            "missing_module",
            "!missing_module",
            "mod_headers.c",
            "headers_module ssl_module",
            " headers_module",
            "! headers_module",
            "!!headers_module",
            "",
        ] {
            assert_eq!(evaluate(expression), ApacheIfModuleEvaluation::Unresolved);
        }
    }

    #[test]
    fn stale_snapshot_cannot_evaluate_if_module() {
        let snapshot = snapshot();
        let current_runtime = snapshot.runtime_fingerprint().clone();
        let current_config = snapshot.config_graph_digest().clone();
        assert!(
            snapshot
                .evaluate_if_module(
                    &target("host-a", 8),
                    &current_runtime,
                    &current_config,
                    "headers_module",
                )
                .is_err()
        );
        assert!(
            snapshot
                .evaluate_if_module(
                    snapshot.target(),
                    &current_runtime,
                    &config('c'),
                    "headers_module",
                )
                .is_err()
        );
    }

    #[test]
    fn debug_output_does_not_copy_hostile_directive_details() {
        let marker = "remote-secret-marker";
        let catalog = ApacheDirectiveCatalog::parse_httpd_l(
            format!("Example (core.c)\n\t{marker}\n\tAllowed in *.conf anywhere\n").as_bytes(),
        )
        .unwrap();
        assert!(!format!("{catalog:?}").contains(marker));
        assert!(!format!("{:?}", catalog.entries()[0]).contains(marker));
    }
}
