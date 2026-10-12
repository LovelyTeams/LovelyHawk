//! Typed, bounded evidence for one observed Apache HTTPD runtime invocation.
//!
//! This module does not collect `/proc`, systemd, or command output. The future
//! provider must capture those sources under one [`TargetGuard`] and pass only
//! bounded, zeroizing payloads into the crate-private constructor. A matching
//! pair of graph captures proves equality at the two capture endpoints; it does
//! not prove that the remote filesystem was unchanged between them.
#![allow(
    dead_code,
    reason = "Phase A evidence constructors intentionally await the provider recorded in UNWIRED_FEATURES.md"
)]

use std::{fmt, num::NonZeroU32};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    CoreError, CoreResult,
    apache_capability::{ApacheConfigGraphDigest, ApacheRuntimeFingerprint},
    sftp::RemotePath,
    target::TargetGuard,
};

pub const MAX_APACHE_RUNTIME_ARGV_BYTES: usize = 256 * 1024;
pub const MAX_APACHE_RUNTIME_ARGUMENTS: usize = 4_096;
pub const MAX_APACHE_RUNTIME_ARGUMENT_BYTES: usize = 64 * 1024;
pub const MAX_APACHE_RUNTIME_EXEC_START_BYTES: usize = 256 * 1024;
pub const MAX_APACHE_RUNTIME_ENVIRONMENT_BYTES: usize = 1024 * 1024;
pub const MAX_APACHE_ENVIRONMENT_FILES: usize = 128;
pub const MAX_APACHE_ENVIRONMENT_FILE_BYTES: usize = 1024 * 1024;
pub const MAX_APACHE_ENVIRONMENT_FILES_TOTAL_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_APACHE_CONFIG_GRAPH_ITEMS: usize = 8_192;
const MAX_APACHE_RUNTIME_UNIT_BYTES: usize = 256;
const MAX_APACHE_CONFIG_GRAPH_ITEM_FIELDS: usize = 32;
const MAX_APACHE_CONFIG_GRAPH_ITEM_FIELD_BYTES: usize = 256 * 1024;
const MAX_APACHE_CONFIG_GRAPH_ITEM_BYTES: usize = 512 * 1024;

const RUNTIME_DIGEST_DOMAIN: &[u8] = b"lovelyres.apache-runtime-invocation.v1";
const ARGUMENT_VALUE_DIGEST_DOMAIN: &[u8] = b"lovelyres.apache-argument-value.v1";
const EXEC_START_DIGEST_DOMAIN: &[u8] = b"lovelyres.apache-exec-start.v1";
const ARGV_DIGEST_DOMAIN: &[u8] = b"lovelyres.apache-argv.v1";
const ENVIRONMENT_DIGEST_DOMAIN: &[u8] = b"lovelyres.apache-environment.v1";
const ENVIRONMENT_FILES_DIGEST_DOMAIN: &[u8] = b"lovelyres.apache-environment-files.v1";
const GRAPH_ITEM_DIGEST_DOMAIN: &[u8] = b"lovelyres.apache-config-graph-item.v1";
const GRAPH_DIGEST_DOMAIN: &[u8] = b"lovelyres.apache-config-graph.v1";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ApacheStartupArgumentKind {
    ServerRoot,
    ConfigFile,
    Define,
    BeforeConfig,
    AfterConfig,
    Other,
}

impl ApacheStartupArgumentKind {
    const fn digest_tag(self) -> u8 {
        match self {
            Self::ServerRoot => 1,
            Self::ConfigFile => 2,
            Self::Define => 3,
            Self::BeforeConfig => 4,
            Self::AfterConfig => 5,
            Self::Other => 255,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ApacheStartupArgument {
    kind: ApacheStartupArgumentKind,
    value_len: usize,
    value_digest: [u8; 32],
}

impl fmt::Debug for ApacheStartupArgument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApacheStartupArgument")
            .field("kind", &self.kind)
            .field("value_len", &self.value_len)
            .finish_non_exhaustive()
    }
}

impl ApacheStartupArgument {
    fn captured(kind: ApacheStartupArgumentKind, value: &[u8]) -> CoreResult<Self> {
        if value.is_empty() || value.len() > MAX_APACHE_RUNTIME_ARGUMENT_BYTES {
            return Err(CoreError::validation(
                "Apache runtime argument",
                "contains an empty or oversized value",
            ));
        }
        Ok(Self {
            kind,
            value_len: value.len(),
            value_digest: digest_parts(ARGUMENT_VALUE_DIGEST_DOMAIN, [value])?,
        })
    }

    pub const fn kind(&self) -> ApacheStartupArgumentKind {
        self.kind
    }

    pub const fn value_len(&self) -> usize {
        self.value_len
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApacheInvocationUnavailableReason {
    ProviderNotWired,
    PermissionDenied,
    UnsupportedWrapper,
    UnstableCapture,
    InvalidEvidence,
    EvidenceLimitExceeded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApacheInvocationEvidenceState {
    NotCollected,
    Collected(Box<ApacheRuntimeInvocationEvidence>),
    Unavailable(ApacheInvocationUnavailableReason),
}

#[derive(Clone, Eq, PartialEq)]
pub struct ApacheRuntimeInvocationEvidence {
    target: TargetGuard,
    unit: String,
    invocation_id: String,
    main_pid: NonZeroU32,
    start_time_ticks: u64,
    canonical_executable: RemotePath,
    executable_sha256: String,
    exec_start_digest: String,
    argv_digest: String,
    environment_digest: String,
    environment_files_digest: String,
    startup_arguments: Vec<ApacheStartupArgument>,
    environment_file_count: usize,
    fingerprint: ApacheRuntimeFingerprint,
}

impl fmt::Debug for ApacheRuntimeInvocationEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApacheRuntimeInvocationEvidence")
            .field("target", &self.target)
            .field("main_pid", &self.main_pid)
            .field("start_time_ticks", &self.start_time_ticks)
            .field("fingerprint", &self.fingerprint)
            .field("startup_argument_count", &self.startup_arguments.len())
            .field("environment_file_count", &self.environment_file_count)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ApacheEnvironmentFileCapture {
    path: RemotePath,
    optional: bool,
    contents: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for ApacheEnvironmentFileCapture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApacheEnvironmentFileCapture")
            .field("path", &self.path)
            .field("optional", &self.optional)
            .field(
                "contents",
                &format_args!("[REDACTED; {} bytes]", self.contents.len()),
            )
            .finish()
    }
}

impl ApacheEnvironmentFileCapture {
    pub(crate) fn new(path: RemotePath, optional: bool, contents: Zeroizing<Vec<u8>>) -> Self {
        Self {
            path,
            optional,
            contents,
        }
    }
}

/// Core-owned raw capture handed to the evidence constructor.
///
/// This structure only carries observations; constructing it does not prove
/// their provenance. The future provider must verify that the systemd
/// `ExecStart` executable resolves to the same canonical executable as
/// `/proc/<MainPID>/exe`. A wrapper or any mismatch must become
/// [`ApacheInvocationUnavailableReason::UnsupportedWrapper`], not collected
/// evidence.
pub(crate) struct ApacheRuntimeCapture {
    pub(crate) target: TargetGuard,
    pub(crate) unit: String,
    pub(crate) invocation_id: String,
    pub(crate) main_pid: NonZeroU32,
    pub(crate) start_time_ticks: u64,
    pub(crate) canonical_executable: RemotePath,
    pub(crate) executable_sha256: String,
    pub(crate) exec_start: Zeroizing<Vec<u8>>,
    pub(crate) argv: Zeroizing<Vec<u8>>,
    pub(crate) environment: Zeroizing<Vec<u8>>,
    pub(crate) environment_files: Vec<ApacheEnvironmentFileCapture>,
}

impl fmt::Debug for ApacheRuntimeCapture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApacheRuntimeCapture")
            .field("target", &self.target)
            .field("main_pid", &self.main_pid)
            .field("start_time_ticks", &self.start_time_ticks)
            .field("environment_file_count", &self.environment_files.len())
            .field("payloads", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl ApacheRuntimeInvocationEvidence {
    /// Validate and digest one bounded provider capture.
    ///
    /// This constructor validates shape, bounds, ordering and digest binding;
    /// it cannot itself prove that the caller read systemd and `/proc` from the
    /// claimed process. That provenance check remains the provider's fail-closed
    /// responsibility.
    pub(crate) fn from_capture(capture: ApacheRuntimeCapture) -> CoreResult<Self> {
        let ApacheRuntimeCapture {
            target,
            unit,
            invocation_id,
            main_pid,
            start_time_ticks,
            canonical_executable,
            executable_sha256,
            exec_start,
            argv,
            environment,
            environment_files,
        } = capture;
        validate_target(&target, "Apache runtime invocation target")?;
        validate_unit(&unit)?;
        let invocation_id = validate_fixed_hex("Apache systemd invocation id", invocation_id, 32)?;
        if start_time_ticks == 0 {
            return Err(CoreError::validation(
                "Apache process start time",
                "must be non-zero",
            ));
        }
        if canonical_executable.as_str() == "/" {
            return Err(CoreError::validation(
                "Apache canonical executable",
                "must identify one absolute executable path",
            ));
        }
        let executable_sha256 =
            validate_fixed_hex("Apache executable SHA-256", executable_sha256, 64)?;
        validate_bounded_blob(
            "Apache systemd ExecStart evidence",
            &exec_start,
            MAX_APACHE_RUNTIME_EXEC_START_BYTES,
            false,
        )?;
        let argv_items = validate_nul_list(
            "Apache process argv evidence",
            &argv,
            MAX_APACHE_RUNTIME_ARGV_BYTES,
            MAX_APACHE_RUNTIME_ARGUMENTS,
            MAX_APACHE_RUNTIME_ARGUMENT_BYTES,
        )?;
        if argv_items.is_empty() {
            return Err(CoreError::validation(
                "Apache process argv evidence",
                "must contain argv[0]",
            ));
        }
        let environment_items = validate_nul_list(
            "Apache process environment evidence",
            &environment,
            MAX_APACHE_RUNTIME_ENVIRONMENT_BYTES,
            MAX_APACHE_RUNTIME_ARGUMENTS,
            MAX_APACHE_RUNTIME_ARGUMENT_BYTES,
        )?;
        if environment_items
            .iter()
            .any(|entry| entry.first() == Some(&b'=') || !entry.contains(&b'='))
        {
            return Err(CoreError::validation(
                "Apache process environment evidence",
                "contains an entry without one non-empty variable name",
            ));
        }
        let startup_arguments = parse_startup_arguments(&argv_items[1..])?;
        let exec_start_digest = hex_digest(digest_parts(
            EXEC_START_DIGEST_DOMAIN,
            [exec_start.as_slice()],
        )?);
        let argv_digest = hex_digest(digest_parts(ARGV_DIGEST_DOMAIN, [argv.as_slice()])?);
        let environment_digest = hex_digest(digest_parts(
            ENVIRONMENT_DIGEST_DOMAIN,
            [environment.as_slice()],
        )?);
        let (environment_files_digest, environment_file_count) =
            digest_environment_files(&environment_files)?;

        let mut runtime = DigestEncoder::new(RUNTIME_DIGEST_DOMAIN)?;
        runtime.field(target.identity.as_str().as_bytes())?;
        runtime.u64(target.generation);
        runtime.field(unit.as_bytes())?;
        runtime.field(invocation_id.as_bytes())?;
        runtime.u64(u64::from(main_pid.get()));
        runtime.u64(start_time_ticks);
        runtime.field(canonical_executable.as_str().as_bytes())?;
        runtime.field(executable_sha256.as_bytes())?;
        runtime.field(exec_start_digest.as_bytes())?;
        runtime.field(argv_digest.as_bytes())?;
        runtime.field(environment_digest.as_bytes())?;
        runtime.field(environment_files_digest.as_bytes())?;
        runtime.u64(usize_to_u64(
            startup_arguments.len(),
            "Apache startup arguments",
        )?);
        for argument in &startup_arguments {
            runtime.byte(argument.kind.digest_tag());
            runtime.u64(usize_to_u64(argument.value_len, "Apache runtime argument")?);
            runtime.field(&argument.value_digest)?;
        }
        let fingerprint = ApacheRuntimeFingerprint::new(hex_digest(runtime.finish()))?;

        Ok(Self {
            target,
            unit,
            invocation_id,
            main_pid,
            start_time_ticks,
            canonical_executable,
            executable_sha256,
            exec_start_digest,
            argv_digest,
            environment_digest,
            environment_files_digest,
            startup_arguments,
            environment_file_count,
            fingerprint,
        })
    }

    pub fn target(&self) -> &TargetGuard {
        &self.target
    }

    pub fn unit(&self) -> &str {
        &self.unit
    }

    pub fn invocation_id(&self) -> &str {
        &self.invocation_id
    }

    pub const fn main_pid(&self) -> NonZeroU32 {
        self.main_pid
    }

    pub const fn start_time_ticks(&self) -> u64 {
        self.start_time_ticks
    }

    pub fn canonical_executable(&self) -> &RemotePath {
        &self.canonical_executable
    }

    pub fn executable_sha256(&self) -> &str {
        &self.executable_sha256
    }

    pub(crate) fn exec_start_digest(&self) -> &str {
        &self.exec_start_digest
    }

    pub(crate) fn argv_digest(&self) -> &str {
        &self.argv_digest
    }

    pub(crate) fn environment_digest(&self) -> &str {
        &self.environment_digest
    }

    pub(crate) fn environment_files_digest(&self) -> &str {
        &self.environment_files_digest
    }

    pub fn startup_arguments(&self) -> &[ApacheStartupArgument] {
        &self.startup_arguments
    }

    pub const fn environment_file_count(&self) -> usize {
        self.environment_file_count
    }

    pub fn fingerprint(&self) -> &ApacheRuntimeFingerprint {
        &self.fingerprint
    }

    #[cfg(test)]
    pub(crate) fn test_fixture(target: TargetGuard, marker: u8) -> CoreResult<Self> {
        let invocation_id = format!("{marker:02x}").repeat(16);
        Self::from_capture(ApacheRuntimeCapture {
            target,
            unit: "httpd.service".to_owned(),
            invocation_id,
            main_pid: NonZeroU32::new(42).expect("test PID is non-zero"),
            start_time_ticks: u64::from(marker) + 1,
            canonical_executable: RemotePath::new("/usr/sbin/httpd")?,
            executable_sha256: format!("{marker:02x}").repeat(32),
            exec_start: Zeroizing::new(
                b"{ path=/usr/sbin/httpd ; argv[]=/usr/sbin/httpd -DFOREGROUND ; }".to_vec(),
            ),
            argv: Zeroizing::new(b"/usr/sbin/httpd\0-DFOREGROUND\0".to_vec()),
            environment: Zeroizing::new(b"LANG=C\0".to_vec()),
            environment_files: Vec::new(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ApacheConfigGraphItemKind {
    ConfigFile,
    IncludeReference,
    DirectoryManifest,
    DirectoryEntry,
}

impl ApacheConfigGraphItemKind {
    const fn digest_tag(self) -> u8 {
        match self {
            Self::ConfigFile => 1,
            Self::IncludeReference => 2,
            Self::DirectoryManifest => 3,
            Self::DirectoryEntry => 4,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ApacheConfigGraphItem {
    kind: ApacheConfigGraphItemKind,
    field_count: usize,
    digest: [u8; 32],
}

impl fmt::Debug for ApacheConfigGraphItem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApacheConfigGraphItem")
            .field("kind", &self.kind)
            .field("field_count", &self.field_count)
            .finish_non_exhaustive()
    }
}

impl ApacheConfigGraphItem {
    pub(crate) fn new(kind: ApacheConfigGraphItemKind, fields: Vec<Vec<u8>>) -> CoreResult<Self> {
        if fields.is_empty() || fields.len() > MAX_APACHE_CONFIG_GRAPH_ITEM_FIELDS {
            return Err(CoreError::validation(
                "Apache configuration graph item",
                "contains an empty or oversized field list",
            ));
        }
        let field_count = fields.len();
        let mut total = 0usize;
        let mut digest = DigestEncoder::new(GRAPH_ITEM_DIGEST_DOMAIN)?;
        digest.byte(kind.digest_tag());
        digest.u64(usize_to_u64(fields.len(), "Apache graph item fields")?);
        for field in fields {
            if field.len() > MAX_APACHE_CONFIG_GRAPH_ITEM_FIELD_BYTES {
                return Err(CoreError::validation(
                    "Apache configuration graph item",
                    "contains an oversized field",
                ));
            }
            total = total.checked_add(field.len()).ok_or_else(|| {
                CoreError::validation(
                    "Apache configuration graph item",
                    "field byte accounting overflowed",
                )
            })?;
            if total > MAX_APACHE_CONFIG_GRAPH_ITEM_BYTES {
                return Err(CoreError::validation(
                    "Apache configuration graph item",
                    "contains too many field bytes",
                ));
            }
            digest.field(&field)?;
        }
        Ok(Self {
            kind,
            field_count,
            digest: digest.finish(),
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ApacheConfigGraphEvidence {
    target: TargetGuard,
    instance_id: String,
    runtime_fingerprint: ApacheRuntimeFingerprint,
    items: Vec<ApacheConfigGraphItem>,
    digest: ApacheConfigGraphDigest,
}

impl fmt::Debug for ApacheConfigGraphEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApacheConfigGraphEvidence")
            .field("target", &self.target)
            .field("runtime_fingerprint", &self.runtime_fingerprint)
            .field("digest", &self.digest)
            .field("item_count", &self.items.len())
            .finish_non_exhaustive()
    }
}

impl ApacheConfigGraphEvidence {
    pub(crate) fn from_items(
        invocation: &ApacheRuntimeInvocationEvidence,
        instance_id: String,
        items: Vec<ApacheConfigGraphItem>,
    ) -> CoreResult<Self> {
        let instance_id = validate_fixed_hex("Apache middleware instance id", instance_id, 64)?;
        if items.is_empty() || items.len() > MAX_APACHE_CONFIG_GRAPH_ITEMS {
            return Err(CoreError::validation(
                "Apache configuration graph evidence",
                format!("must contain 1-{MAX_APACHE_CONFIG_GRAPH_ITEMS} bounded items"),
            ));
        }
        let mut digest = DigestEncoder::new(GRAPH_DIGEST_DOMAIN)?;
        digest.field(invocation.target.identity.as_str().as_bytes())?;
        digest.u64(invocation.target.generation);
        digest.field(instance_id.as_bytes())?;
        digest.field(invocation.fingerprint.as_str().as_bytes())?;
        digest.u64(usize_to_u64(items.len(), "Apache graph items")?);
        for item in &items {
            digest.byte(item.kind.digest_tag());
            digest.u64(usize_to_u64(item.field_count, "Apache graph item fields")?);
            digest.field(&item.digest)?;
        }
        let digest = ApacheConfigGraphDigest::new(hex_digest(digest.finish()))?;
        Ok(Self {
            target: invocation.target.clone(),
            instance_id,
            runtime_fingerprint: invocation.fingerprint.clone(),
            items,
            digest,
        })
    }

    pub fn target(&self) -> &TargetGuard {
        &self.target
    }

    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    pub fn runtime_fingerprint(&self) -> &ApacheRuntimeFingerprint {
        &self.runtime_fingerprint
    }

    pub fn digest(&self) -> &ApacheConfigGraphDigest {
        &self.digest
    }

    pub const fn item_count(&self) -> usize {
        self.items.len()
    }

    #[cfg(test)]
    pub(crate) fn test_fixture(
        invocation: &ApacheRuntimeInvocationEvidence,
        marker: u8,
    ) -> CoreResult<Self> {
        Self::from_items(
            invocation,
            format!("{marker:02x}").repeat(32),
            vec![ApacheConfigGraphItem::new(
                ApacheConfigGraphItemKind::ConfigFile,
                vec![b"/etc/httpd/conf/httpd.conf".to_vec(), vec![marker; 32]],
            )?],
        )
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ApacheStableConfigGraphEvidence {
    capture: ApacheConfigGraphEvidence,
}

impl fmt::Debug for ApacheStableConfigGraphEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApacheStableConfigGraphEvidence")
            .field("target", self.target())
            .field("runtime_fingerprint", self.runtime_fingerprint())
            .field("digest", self.digest())
            .field("item_count", &self.item_count())
            .field("proof", &"matching endpoint captures")
            .finish()
    }
}

impl ApacheStableConfigGraphEvidence {
    /// Seal two exactly matching endpoint captures.
    ///
    /// This is deliberately not an atomic-filesystem or continuous-stability
    /// claim. A future command transaction must sandwich its work between the
    /// two captures and reject every mismatch.
    pub fn seal(
        before: ApacheConfigGraphEvidence,
        after: ApacheConfigGraphEvidence,
    ) -> CoreResult<Self> {
        if before.target != after.target {
            return Err(CoreError::validation(
                "Apache stable configuration graph",
                "endpoint captures belong to different target guards",
            ));
        }
        if before.instance_id != after.instance_id {
            return Err(CoreError::validation(
                "Apache stable configuration graph",
                "endpoint captures belong to different middleware instances",
            ));
        }
        if before.runtime_fingerprint != after.runtime_fingerprint {
            return Err(CoreError::validation(
                "Apache stable configuration graph",
                "runtime invocation changed between endpoint captures",
            ));
        }
        if before != after {
            return Err(CoreError::validation(
                "Apache stable configuration graph",
                "configuration graph changed between endpoint captures",
            ));
        }
        Ok(Self { capture: before })
    }

    pub fn target(&self) -> &TargetGuard {
        self.capture.target()
    }

    pub fn instance_id(&self) -> &str {
        self.capture.instance_id()
    }

    pub fn runtime_fingerprint(&self) -> &ApacheRuntimeFingerprint {
        self.capture.runtime_fingerprint()
    }

    pub fn digest(&self) -> &ApacheConfigGraphDigest {
        self.capture.digest()
    }

    pub const fn item_count(&self) -> usize {
        self.capture.item_count()
    }

    pub(crate) fn validate_runtime(
        &self,
        invocation: &ApacheRuntimeInvocationEvidence,
    ) -> CoreResult<()> {
        if self.target() != invocation.target()
            || self.runtime_fingerprint() != invocation.fingerprint()
        {
            return Err(CoreError::validation(
                "Apache capability evidence binding",
                "runtime invocation and stable graph evidence do not match",
            ));
        }
        Ok(())
    }
}

fn parse_startup_arguments(argv: &[&[u8]]) -> CoreResult<Vec<ApacheStartupArgument>> {
    let mut parsed = Vec::with_capacity(argv.len());
    let mut index = 0usize;
    while index < argv.len() {
        let argument = argv[index];
        if let Some(kind) = exact_option_kind(argument) {
            let value = argv.get(index + 1).ok_or_else(|| {
                CoreError::validation(
                    "Apache runtime argument",
                    "a startup-context option is missing its value",
                )
            })?;
            parsed.push(ApacheStartupArgument::captured(kind, value)?);
            index += 2;
            continue;
        }
        if let Some((kind, value)) = attached_option(argument) {
            parsed.push(ApacheStartupArgument::captured(kind, value)?);
        } else {
            parsed.push(ApacheStartupArgument::captured(
                ApacheStartupArgumentKind::Other,
                argument,
            )?);
        }
        index += 1;
    }
    Ok(parsed)
}

fn exact_option_kind(argument: &[u8]) -> Option<ApacheStartupArgumentKind> {
    match argument {
        b"-d" => Some(ApacheStartupArgumentKind::ServerRoot),
        b"-f" => Some(ApacheStartupArgumentKind::ConfigFile),
        b"-D" => Some(ApacheStartupArgumentKind::Define),
        b"-C" => Some(ApacheStartupArgumentKind::BeforeConfig),
        b"-c" => Some(ApacheStartupArgumentKind::AfterConfig),
        _ => None,
    }
}

fn attached_option(argument: &[u8]) -> Option<(ApacheStartupArgumentKind, &[u8])> {
    if argument.len() <= 2 || argument.first() != Some(&b'-') {
        return None;
    }
    let kind = match argument[1] {
        b'd' => ApacheStartupArgumentKind::ServerRoot,
        b'f' => ApacheStartupArgumentKind::ConfigFile,
        b'D' => ApacheStartupArgumentKind::Define,
        b'C' => ApacheStartupArgumentKind::BeforeConfig,
        b'c' => ApacheStartupArgumentKind::AfterConfig,
        _ => return None,
    };
    Some((kind, &argument[2..]))
}

fn digest_environment_files(files: &[ApacheEnvironmentFileCapture]) -> CoreResult<(String, usize)> {
    if files.len() > MAX_APACHE_ENVIRONMENT_FILES {
        return Err(CoreError::validation(
            "Apache EnvironmentFile evidence",
            format!("contains more than {MAX_APACHE_ENVIRONMENT_FILES} files"),
        ));
    }
    let mut total = 0usize;
    let mut digest = DigestEncoder::new(ENVIRONMENT_FILES_DIGEST_DOMAIN)?;
    digest.u64(usize_to_u64(
        files.len(),
        "Apache EnvironmentFile evidence",
    )?);
    for file in files {
        if file.contents.len() > MAX_APACHE_ENVIRONMENT_FILE_BYTES {
            return Err(CoreError::validation(
                "Apache EnvironmentFile evidence",
                "contains an oversized file",
            ));
        }
        total = total.checked_add(file.contents.len()).ok_or_else(|| {
            CoreError::validation(
                "Apache EnvironmentFile evidence",
                "byte accounting overflowed",
            )
        })?;
        if total > MAX_APACHE_ENVIRONMENT_FILES_TOTAL_BYTES {
            return Err(CoreError::validation(
                "Apache EnvironmentFile evidence",
                "aggregate contents exceed the bounded evidence limit",
            ));
        }
        digest.field(file.path.as_str().as_bytes())?;
        digest.byte(u8::from(file.optional));
        digest.field(&file.contents)?;
    }
    Ok((hex_digest(digest.finish()), files.len()))
}

fn validate_target(target: &TargetGuard, subject: &'static str) -> CoreResult<()> {
    if target.generation == 0 {
        return Err(CoreError::validation(
            subject,
            "target generation must be non-zero",
        ));
    }
    Ok(())
}

fn validate_unit(unit: &str) -> CoreResult<()> {
    if unit.is_empty()
        || unit.len() > MAX_APACHE_RUNTIME_UNIT_BYTES
        || !unit.ends_with(".service")
        || unit.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'@' | b':'))
        })
    {
        return Err(CoreError::validation(
            "Apache systemd unit",
            "must be one bounded service-unit identifier",
        ));
    }
    Ok(())
}

fn validate_fixed_hex(
    subject: &'static str,
    value: String,
    expected_bytes: usize,
) -> CoreResult<String> {
    if value.len() != expected_bytes || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CoreError::validation(
            subject,
            "must be one exact hexadecimal value of the required length",
        ));
    }
    Ok(value.to_ascii_lowercase())
}

fn validate_bounded_blob(
    subject: &'static str,
    value: &[u8],
    maximum_bytes: usize,
    allow_empty: bool,
) -> CoreResult<()> {
    if (!allow_empty && value.is_empty()) || value.len() > maximum_bytes || value.contains(&0) {
        return Err(CoreError::validation(
            subject,
            "contains an empty, oversized, or NUL-bearing payload",
        ));
    }
    Ok(())
}

fn validate_nul_list<'a>(
    subject: &'static str,
    value: &'a [u8],
    maximum_bytes: usize,
    maximum_items: usize,
    maximum_item_bytes: usize,
) -> CoreResult<Vec<&'a [u8]>> {
    if value.is_empty() || value.len() > maximum_bytes || !value.ends_with(&[0]) {
        return Err(CoreError::validation(
            subject,
            "must be one bounded, NUL-terminated list",
        ));
    }
    let items = value[..value.len() - 1]
        .split(|byte| *byte == 0)
        .collect::<Vec<_>>();
    if items.len() > maximum_items
        || items
            .iter()
            .any(|item| item.is_empty() || item.len() > maximum_item_bytes)
    {
        return Err(CoreError::validation(
            subject,
            "contains an empty, oversized, or excessive item list",
        ));
    }
    Ok(items)
}

struct DigestEncoder(Sha256);

impl DigestEncoder {
    fn new(domain: &[u8]) -> CoreResult<Self> {
        let mut encoder = Self(Sha256::new());
        encoder.field(domain)?;
        Ok(encoder)
    }

    fn field(&mut self, value: &[u8]) -> CoreResult<()> {
        self.u64(usize_to_u64(value.len(), "Apache evidence digest field")?);
        self.0.update(value);
        Ok(())
    }

    fn byte(&mut self, value: u8) {
        self.0.update([value]);
    }

    fn u64(&mut self, value: u64) {
        self.0.update(value.to_be_bytes());
    }

    fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

fn digest_parts<'a>(
    domain: &[u8],
    parts: impl IntoIterator<Item = &'a [u8]>,
) -> CoreResult<[u8; 32]> {
    let mut digest = DigestEncoder::new(domain)?;
    for part in parts {
        digest.field(part)?;
    }
    Ok(digest.finish())
}

fn usize_to_u64(value: usize, subject: &'static str) -> CoreResult<u64> {
    u64::try_from(value).map_err(|_| CoreError::validation(subject, "length overflowed u64"))
}

fn hex_digest(value: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in value {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::TargetIdentity;

    fn target(identity: &str, generation: u64) -> TargetGuard {
        TargetGuard {
            identity: TargetIdentity::new(identity).unwrap(),
            generation,
        }
    }

    fn captured(
        target: TargetGuard,
        start_time_ticks: u64,
        executable_sha256: char,
        argv: Vec<u8>,
        environment: Vec<u8>,
        environment_file_contents: Vec<u8>,
    ) -> CoreResult<ApacheRuntimeInvocationEvidence> {
        ApacheRuntimeInvocationEvidence::from_capture(ApacheRuntimeCapture {
            target,
            unit: "httpd.service".to_owned(),
            invocation_id: "1a".repeat(16),
            main_pid: NonZeroU32::new(42).unwrap(),
            start_time_ticks,
            canonical_executable: RemotePath::new("/usr/sbin/httpd").unwrap(),
            executable_sha256: executable_sha256.to_string().repeat(64),
            exec_start: Zeroizing::new(b"{ path=/usr/sbin/httpd ; }".to_vec()),
            argv: Zeroizing::new(argv),
            environment: Zeroizing::new(environment),
            environment_files: vec![ApacheEnvironmentFileCapture::new(
                RemotePath::new("/etc/sysconfig/httpd").unwrap(),
                false,
                Zeroizing::new(environment_file_contents),
            )],
        })
    }

    #[test]
    fn ordered_repeated_startup_arguments_are_preserved_and_bound() {
        let argv = b"/usr/sbin/httpd\0-DONE\0-C\0secret-before\0-DFOO\0-csecret-after\0-d\0/etc/httpd\0-fconf/httpd.conf\0-DONE\0".to_vec();
        let evidence = captured(
            target("host-a", 7),
            10,
            'a',
            argv.clone(),
            b"LANG=C\0".to_vec(),
            b"HTTPD=/usr/sbin/httpd\n".to_vec(),
        )
        .unwrap();
        assert_eq!(
            evidence
                .startup_arguments()
                .iter()
                .map(ApacheStartupArgument::kind)
                .collect::<Vec<_>>(),
            vec![
                ApacheStartupArgumentKind::Define,
                ApacheStartupArgumentKind::BeforeConfig,
                ApacheStartupArgumentKind::Define,
                ApacheStartupArgumentKind::AfterConfig,
                ApacheStartupArgumentKind::ServerRoot,
                ApacheStartupArgumentKind::ConfigFile,
                ApacheStartupArgumentKind::Define,
            ]
        );

        let reordered = captured(
            target("host-a", 7),
            10,
            'a',
            b"/usr/sbin/httpd\0-C\0secret-before\0-DONE\0-DFOO\0-csecret-after\0-d\0/etc/httpd\0-fconf/httpd.conf\0-DONE\0".to_vec(),
            b"LANG=C\0".to_vec(),
            b"HTTPD=/usr/sbin/httpd\n".to_vec(),
        )
        .unwrap();
        assert_ne!(evidence.fingerprint(), reordered.fingerprint());
        assert_ne!(evidence.argv_digest(), reordered.argv_digest());
    }

    #[test]
    fn nul_and_size_limits_fail_closed_without_echoing_payloads() {
        let missing_nul = captured(
            target("host-a", 7),
            10,
            'a',
            b"/usr/sbin/httpd".to_vec(),
            b"LANG=C\0".to_vec(),
            Vec::new(),
        )
        .unwrap_err();
        assert!(!missing_nul.to_string().contains("/usr/sbin/httpd"));

        let mut oversized = vec![b'x'; MAX_APACHE_RUNTIME_ARGV_BYTES + 1];
        oversized[MAX_APACHE_RUNTIME_ARGV_BYTES] = 0;
        assert!(
            captured(
                target("host-a", 7),
                10,
                'a',
                oversized,
                b"LANG=C\0".to_vec(),
                Vec::new(),
            )
            .is_err()
        );
        assert!(
            captured(
                target("host-a", 0),
                10,
                'a',
                b"/usr/sbin/httpd\0".to_vec(),
                b"LANG=C\0".to_vec(),
                Vec::new(),
            )
            .is_err()
        );
    }

    #[test]
    fn debug_never_contains_argument_environment_or_environment_file_payloads() {
        let marker = "runtime-secret-marker";
        let evidence = captured(
            target("host-a", 7),
            10,
            'a',
            format!("/usr/sbin/httpd\0-C\0SetEnv TOKEN {marker}\0").into_bytes(),
            format!("TOKEN={marker}\0").into_bytes(),
            format!("TOKEN={marker}\n").into_bytes(),
        )
        .unwrap();
        assert!(!format!("{evidence:?}").contains(marker));
        assert!(
            evidence
                .startup_arguments()
                .iter()
                .all(|argument| !format!("{argument:?}").contains(marker))
        );
        assert!(
            !format!(
                "{:?}",
                ApacheInvocationEvidenceState::Collected(Box::new(evidence))
            )
            .contains(marker)
        );
    }

    #[test]
    fn runtime_digest_changes_with_process_binary_environment_and_environment_file() {
        let base = captured(
            target("host-a", 7),
            10,
            'a',
            b"/usr/sbin/httpd\0-DFOREGROUND\0".to_vec(),
            b"LANG=C\0".to_vec(),
            b"HTTPD=/usr/sbin/httpd\n".to_vec(),
        )
        .unwrap();
        let changed_start = captured(
            target("host-a", 7),
            11,
            'a',
            b"/usr/sbin/httpd\0-DFOREGROUND\0".to_vec(),
            b"LANG=C\0".to_vec(),
            b"HTTPD=/usr/sbin/httpd\n".to_vec(),
        )
        .unwrap();
        let changed_binary = captured(
            target("host-a", 7),
            10,
            'b',
            b"/usr/sbin/httpd\0-DFOREGROUND\0".to_vec(),
            b"LANG=C\0".to_vec(),
            b"HTTPD=/usr/sbin/httpd\n".to_vec(),
        )
        .unwrap();
        let changed_environment = captured(
            target("host-a", 7),
            10,
            'a',
            b"/usr/sbin/httpd\0-DFOREGROUND\0".to_vec(),
            b"LANG=en_US.UTF-8\0".to_vec(),
            b"HTTPD=/usr/sbin/httpd\n".to_vec(),
        )
        .unwrap();
        let changed_file = captured(
            target("host-a", 7),
            10,
            'a',
            b"/usr/sbin/httpd\0-DFOREGROUND\0".to_vec(),
            b"LANG=C\0".to_vec(),
            b"HTTPD=/opt/httpd\n".to_vec(),
        )
        .unwrap();
        for changed in [
            changed_start,
            changed_binary,
            changed_environment,
            changed_file,
        ] {
            assert_ne!(base.fingerprint(), changed.fingerprint());
        }
    }

    #[test]
    fn stable_graph_requires_exact_endpoints_runtime_and_guard() {
        let invocation =
            ApacheRuntimeInvocationEvidence::test_fixture(target("host-a", 7), 1).unwrap();
        let before = ApacheConfigGraphEvidence::test_fixture(&invocation, 2).unwrap();
        let stable = ApacheStableConfigGraphEvidence::seal(before.clone(), before.clone()).unwrap();
        assert_eq!(stable.target(), invocation.target());
        assert_eq!(stable.runtime_fingerprint(), invocation.fingerprint());

        let changed = ApacheConfigGraphEvidence::test_fixture(&invocation, 3).unwrap();
        assert!(ApacheStableConfigGraphEvidence::seal(before.clone(), changed).is_err());

        let other_guard =
            ApacheRuntimeInvocationEvidence::test_fixture(target("host-a", 8), 1).unwrap();
        let other_graph = ApacheConfigGraphEvidence::test_fixture(&other_guard, 2).unwrap();
        assert!(ApacheStableConfigGraphEvidence::seal(before, other_graph).is_err());
    }
}
