//! Lossless middleware discovery, configuration and guarded activation.
//!
//! Configuration bytes are never re-serialized. Visual edits are exact byte
//! span patches produced by [`crate::middleware_document`]; raw edits replace
//! the explicitly selected file only. Remote paths and commands are derived
//! from a closed product catalog and a validated systemd instance.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use parking_lot::Mutex as SyncMutex;
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{Error as _, IgnoredAny, SeqAccess, Visitor},
};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    CoreError, CoreResult, PortableStore,
    apache_runtime::{
        ApacheConfigGraphEvidence, ApacheConfigGraphItem, ApacheConfigGraphItemKind,
        ApacheInvocationEvidenceState, ApacheRuntimeInvocationEvidence,
    },
    middleware_document::{
        ByteSpan, MAX_MIDDLEWARE_DOCUMENT_BYTES, MiddlewareDocument, MiddlewareDocumentNode,
        MiddlewareDocumentNodeKind, MiddlewareDocumentPatch, MiddlewareDocumentSyntax,
    },
    operations::{
        DangerousConfirmation, ExecutionReceipt, OperationExecutor, OperationPlan, OperationState,
        PlannedOperation, PortableOperationJournal, VerificationResult,
    },
    sftp::{
        BoundSftpSession, MAX_EDIT_BYTES, RemotePath, SftpAtomicBackup, SftpFileKind, SftpMetadata,
        SftpMutation, SftpPlannedOperation, SftpService,
    },
    shell_escape::shq,
    ssh::{BoundSshSession, SshCommandOutput, SshService},
    store::StoreFile,
    target::{TargetContext, TargetGuard, TargetIdentity},
};

pub const MAX_MIDDLEWARE_INSTANCES: usize = 32;
pub const MAX_MIDDLEWARE_CONFIG_FILES: usize = 256;
pub const MAX_MIDDLEWARE_INCLUDE_DEPTH: usize = 12;
const MAX_MIDDLEWARE_INCLUDE_PATH_COMPONENTS: usize = 128;
pub const MAX_MIDDLEWARE_TOTAL_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_MIDDLEWARE_DIRECTORY_ENTRIES: usize = 2048;
const MAX_DISCOVERY_OUTPUT_BYTES: usize = 512 * 1024;
const MAX_HISTORY_RECORDS: usize = 512;
const MAX_MIDDLEWARE_HISTORY_STORAGE_BYTES: usize = 32 * 1024 * 1024;
const MAX_MIDDLEWARE_HISTORY_RECORD_TEXT_BYTES: usize = 32 * 1024;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MiddlewareProduct {
    Nginx,
    ApacheHttpd,
    Redis,
    Tomcat,
}

impl MiddlewareProduct {
    pub const ALL: [Self; 4] = [Self::Nginx, Self::ApacheHttpd, Self::Redis, Self::Tomcat];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Nginx => "Nginx",
            Self::ApacheHttpd => "Apache HTTPD",
            Self::Redis => "Redis",
            Self::Tomcat => "Tomcat",
        }
    }

    pub const fn document_syntax(self) -> MiddlewareDocumentSyntax {
        match self {
            Self::Nginx => MiddlewareDocumentSyntax::Nginx,
            Self::ApacheHttpd => MiddlewareDocumentSyntax::Apache,
            Self::Redis => MiddlewareDocumentSyntax::Redis,
            Self::Tomcat => MiddlewareDocumentSyntax::TomcatXml,
        }
    }

    pub const fn validator(self) -> MiddlewareValidator {
        match self {
            Self::Nginx => MiddlewareValidator::NginxConfigTest,
            Self::ApacheHttpd => MiddlewareValidator::ApacheConfigTest,
            Self::Redis => MiddlewareValidator::StructuralOnly,
            Self::Tomcat => MiddlewareValidator::StructuralOnly,
        }
    }

    pub const fn activation(self) -> MiddlewareActivationPolicy {
        match self {
            Self::Nginx | Self::ApacheHttpd => MiddlewareActivationPolicy::Reload,
            Self::Redis | Self::Tomcat => MiddlewareActivationPolicy::Restart,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MiddlewareRuntimeKind {
    Systemd,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MiddlewareConfigRole {
    Primary,
    Included,
    TomcatWeb,
    TomcatContext,
    Properties,
    Logging,
    Users,
    Other,
}

impl MiddlewareConfigRole {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Primary => "主配置",
            Self::Included => "包含配置",
            Self::TomcatWeb => "Web 默认配置",
            Self::TomcatContext => "Context 配置",
            Self::Properties => "属性配置",
            Self::Logging => "日志配置",
            Self::Users => "用户配置",
            Self::Other => "其他配置",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MiddlewareValidator {
    NginxConfigTest,
    ApacheConfigTest,
    StructuralOnly,
}

impl MiddlewareValidator {
    pub const fn label(self) -> &'static str {
        match self {
            Self::NginxConfigTest => "nginx -t",
            Self::ApacheConfigTest => "apachectl configtest",
            Self::StructuralOnly => "本地结构校验 + 启动健康回读",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MiddlewareActivationPolicy {
    Reload,
    Restart,
}

impl MiddlewareActivationPolicy {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Reload => "平滑重载",
            Self::Restart => "重启服务",
        }
    }

    const fn systemctl_action(self) -> &'static str {
        match self {
            Self::Reload => "reload",
            Self::Restart => "restart",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MiddlewareCatalogEntry {
    pub product: MiddlewareProduct,
    pub service_prefixes: &'static [&'static str],
    pub fallback_config_paths: &'static [&'static str],
    pub approved_config_roots: &'static [&'static str],
    pub validator: MiddlewareValidator,
    pub activation: MiddlewareActivationPolicy,
    pub native_reload: bool,
}

pub const MIDDLEWARE_CATALOG: [MiddlewareCatalogEntry; 4] = [
    MiddlewareCatalogEntry {
        product: MiddlewareProduct::Nginx,
        service_prefixes: &["nginx"],
        fallback_config_paths: &[
            "/etc/nginx/nginx.conf",
            "/usr/local/nginx/conf/nginx.conf",
            "/usr/local/etc/nginx/nginx.conf",
        ],
        approved_config_roots: &[
            "/etc/nginx",
            "/usr/local/nginx",
            "/usr/local/etc/nginx",
            "/usr/share/nginx",
        ],
        validator: MiddlewareValidator::NginxConfigTest,
        activation: MiddlewareActivationPolicy::Reload,
        native_reload: true,
    },
    MiddlewareCatalogEntry {
        product: MiddlewareProduct::ApacheHttpd,
        service_prefixes: &["apache2", "httpd"],
        fallback_config_paths: &[
            "/etc/apache2/apache2.conf",
            "/etc/httpd/conf/httpd.conf",
            "/usr/local/apache2/conf/httpd.conf",
        ],
        approved_config_roots: &["/etc/apache2", "/etc/httpd", "/usr/local/apache2"],
        validator: MiddlewareValidator::ApacheConfigTest,
        activation: MiddlewareActivationPolicy::Reload,
        native_reload: true,
    },
    MiddlewareCatalogEntry {
        product: MiddlewareProduct::Redis,
        service_prefixes: &["redis", "redis-server"],
        fallback_config_paths: &[
            "/etc/redis/redis.conf",
            "/etc/redis.conf",
            "/usr/local/etc/redis.conf",
        ],
        approved_config_roots: &["/etc/redis", "/usr/local/etc/redis"],
        validator: MiddlewareValidator::StructuralOnly,
        activation: MiddlewareActivationPolicy::Restart,
        native_reload: false,
    },
    MiddlewareCatalogEntry {
        product: MiddlewareProduct::Tomcat,
        service_prefixes: &["tomcat", "catalina"],
        fallback_config_paths: &[
            "/etc/tomcat/server.xml",
            "/etc/tomcat9/server.xml",
            "/etc/tomcat10/server.xml",
            "/usr/local/tomcat/conf/server.xml",
        ],
        approved_config_roots: &[
            "/etc/tomcat",
            "/etc/tomcat9",
            "/etc/tomcat10",
            "/usr/local/tomcat/conf",
        ],
        validator: MiddlewareValidator::StructuralOnly,
        activation: MiddlewareActivationPolicy::Restart,
        native_reload: false,
    },
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MiddlewareInstance {
    target: TargetGuard,
    id: String,
    product: MiddlewareProduct,
    runtime: MiddlewareRuntimeKind,
    unit: String,
    version: String,
    active_state: String,
    sub_state: String,
    main_pid: u32,
    binary_path: RemotePath,
    fragment_path: RemotePath,
    runtime_fingerprint: String,
    apache_invocation_evidence: Option<ApacheInvocationEvidenceState>,
    primary_config: RemotePath,
    config_root: RemotePath,
    discovered_config_root: bool,
    validator: MiddlewareValidator,
    activation: MiddlewareActivationPolicy,
    supports_native_reload: bool,
}

impl MiddlewareInstance {
    pub fn target(&self) -> &TargetGuard {
        &self.target
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn product(&self) -> MiddlewareProduct {
        self.product
    }

    pub const fn runtime(&self) -> MiddlewareRuntimeKind {
        self.runtime
    }

    pub fn unit(&self) -> &str {
        &self.unit
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn active_state(&self) -> &str {
        &self.active_state
    }

    pub fn sub_state(&self) -> &str {
        &self.sub_state
    }

    pub const fn main_pid(&self) -> u32 {
        self.main_pid
    }

    pub fn binary_path(&self) -> &RemotePath {
        &self.binary_path
    }

    pub fn primary_config(&self) -> &RemotePath {
        &self.primary_config
    }

    pub fn apache_invocation_evidence(&self) -> Option<&ApacheInvocationEvidenceState> {
        self.apache_invocation_evidence.as_ref()
    }

    pub fn config_root(&self) -> &RemotePath {
        &self.config_root
    }

    pub const fn validator(&self) -> MiddlewareValidator {
        self.validator
    }

    pub const fn activation(&self) -> MiddlewareActivationPolicy {
        self.activation
    }

    pub const fn supports_native_reload(&self) -> bool {
        self.supports_native_reload
    }

    pub fn is_active(&self) -> bool {
        self.active_state == "active"
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MiddlewareIncludeReference {
    pub source: RemotePath,
    pub raw_value: String,
    pub optional: bool,
    pub resolved: Vec<RemotePath>,
    pub unresolved_reason: Option<String>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct MiddlewareConfigSnapshot {
    target: TargetGuard,
    instance_id: String,
    product: MiddlewareProduct,
    role: MiddlewareConfigRole,
    path: RemotePath,
    metadata: SftpMetadata,
    sha256: String,
    bytes: Zeroizing<Vec<u8>>,
    document: MiddlewareDocument,
    includes: Vec<MiddlewareIncludeReference>,
}

impl MiddlewareConfigSnapshot {
    pub fn target(&self) -> &TargetGuard {
        &self.target
    }

    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    pub const fn product(&self) -> MiddlewareProduct {
        self.product
    }

    pub const fn role(&self) -> MiddlewareConfigRole {
        self.role
    }

    pub fn path(&self) -> &RemotePath {
        &self.path
    }

    pub fn metadata(&self) -> &SftpMetadata {
        &self.metadata
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn byte_len(&self) -> usize {
        self.bytes.len()
    }

    pub fn create_draft(&self) -> CoreResult<MiddlewareDraft> {
        MiddlewareDraft::from_snapshot(self)
    }

    pub fn includes(&self) -> &[MiddlewareIncludeReference] {
        &self.includes
    }
}

#[derive(Clone)]
pub struct MiddlewareDraft {
    product: MiddlewareProduct,
    base_sha256: String,
    document: MiddlewareDocument,
    patches: Vec<MiddlewareDraftPatch>,
    raw_replacement: Option<Zeroizing<String>>,
    contains_sensitive_values: bool,
    sensitive_spans: Vec<ByteSpan>,
}

#[derive(Clone)]
struct MiddlewareDraftPatch {
    span: ByteSpan,
    replacement: Zeroizing<String>,
}

impl fmt::Debug for MiddlewareDraft {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MiddlewareDraft")
            .field("product", &self.product)
            .field("base_sha256", &self.base_sha256)
            .field("nodes", &self.document.nodes().len())
            .field("patches", &self.patches.len())
            .field("raw_replacement", &self.raw_replacement.is_some())
            .field("contains_sensitive_values", &self.contains_sensitive_values)
            .field("sensitive_spans", &self.sensitive_spans.len())
            .finish()
    }
}

impl MiddlewareDraft {
    fn from_snapshot(snapshot: &MiddlewareConfigSnapshot) -> CoreResult<Self> {
        let contains_sensitive_values =
            document_contains_sensitive_values(snapshot.product, &snapshot.document);
        let sensitive_spans = sensitive_editable_spans(snapshot.product, &snapshot.document);
        let document = redact_document(snapshot.product, &snapshot.document)?;
        Ok(Self {
            product: snapshot.product,
            base_sha256: snapshot.sha256.clone(),
            document,
            patches: Vec::new(),
            raw_replacement: None,
            contains_sensitive_values,
            sensitive_spans,
        })
    }

    fn restore_replacement(
        snapshot: &MiddlewareConfigSnapshot,
        replacement: Vec<u8>,
    ) -> CoreResult<Self> {
        let replacement = String::from_utf8(replacement).map_err(|_| {
            CoreError::validation(
                "middleware restore draft",
                "recorded configuration backup is not valid UTF-8",
            )
        })?;
        let mut draft = Self::from_snapshot(snapshot)?;
        draft.raw_replacement = Some(Zeroizing::new(replacement));
        Ok(draft)
    }

    pub fn nodes(&self) -> &[MiddlewareDocumentNode] {
        self.document.nodes()
    }

    pub fn byte_len(&self) -> usize {
        self.document.raw_bytes().len()
    }

    pub const fn contains_sensitive_values(&self) -> bool {
        self.contains_sensitive_values
    }

    pub fn has_changes(&self) -> bool {
        self.raw_replacement.is_some() || !self.patches.is_empty()
    }

    pub fn safe_raw_text(&self) -> Option<&str> {
        (!self.contains_sensitive_values)
            .then(|| std::str::from_utf8(self.document.raw_bytes()).ok())
            .flatten()
    }

    pub fn node_preview(&self, index: usize) -> String {
        let Some(node) = self.document.nodes().get(index) else {
            return String::new();
        };
        let bytes = self
            .document
            .raw_bytes()
            .get(node.span.start()..node.span.end())
            .unwrap_or_default();
        if node
            .editable_value
            .is_some_and(|span| self.sensitive_spans.contains(&span))
            || node_value_is_sensitive(self.product, &self.document, node)
            || text_contains_sensitive_marker(bytes)
        {
            return format!("<敏感内容由 core 保留 · {} B>", bytes.len());
        }
        bounded_node_preview(bytes)
    }

    pub fn editable_value(&self, index: usize) -> Option<MiddlewareDraftValue> {
        let node = self.document.nodes().get(index)?;
        let span = node.editable_value?;
        let sensitive = self.sensitive_spans.contains(&span)
            || node_value_is_sensitive(self.product, &self.document, node);
        let value = (!sensitive)
            .then(|| {
                std::str::from_utf8(&self.document.raw_bytes()[span.start()..span.end()])
                    .ok()
                    .map(str::to_owned)
            })
            .flatten();
        Some(MiddlewareDraftValue { value, sensitive })
    }

    pub fn apply_node_edit(&self, index: usize, replacement: String) -> CoreResult<Self> {
        let node = self.document.nodes().get(index).ok_or_else(|| {
            CoreError::validation(
                "middleware draft node",
                "node index is outside the document",
            )
        })?;
        let span = node.editable_value.ok_or_else(|| {
            CoreError::validation("middleware draft node", "selected node is read-only")
        })?;
        let sensitive = self.sensitive_spans.contains(&span)
            || node_value_is_sensitive(self.product, &self.document, node)
            || text_contains_sensitive_marker(replacement.as_bytes());
        let display_replacement = if sensitive {
            "*".repeat(replacement.len())
        } else {
            replacement.clone()
        };
        let document = self
            .document
            .apply_patches(&[MiddlewareDocumentPatch::new(span, display_replacement)])
            .map_err(|error| CoreError::validation("middleware draft patch", error.to_string()))?;
        let mut next = self.clone();
        next.document = document;
        next.raw_replacement = None;
        next.contains_sensitive_values |= sensitive;
        next.sensitive_spans =
            shifted_sensitive_spans(&self.sensitive_spans, span, replacement.len(), sensitive);
        next.patches.push(MiddlewareDraftPatch {
            span,
            replacement: Zeroizing::new(replacement),
        });
        Ok(next)
    }

    pub fn replace_safe_raw(&self, replacement: String) -> CoreResult<Self> {
        if self.contains_sensitive_values {
            return Err(CoreError::validation(
                "middleware raw editor",
                "raw editing is disabled because the file contains credential-like values",
            ));
        }
        let document = self
            .document
            .replace_raw(&replacement)
            .map_err(|error| CoreError::validation("middleware raw editor", error.to_string()))?;
        let contains_sensitive_values = document_contains_sensitive_values(self.product, &document);
        let sensitive_spans = if contains_sensitive_values {
            sensitive_editable_spans(self.product, &document)
        } else {
            Vec::new()
        };
        let display_document = if contains_sensitive_values {
            redact_document(self.product, &document)?
        } else {
            document
        };
        let mut next = self.clone();
        next.document = display_document;
        next.patches.clear();
        next.raw_replacement = Some(Zeroizing::new(replacement));
        next.contains_sensitive_values = contains_sensitive_values;
        next.sensitive_spans = sensitive_spans;
        Ok(next)
    }

    pub fn safe_diff(&self, snapshot: &MiddlewareConfigSnapshot) -> String {
        if self.product != snapshot.product || self.base_sha256 != snapshot.sha256 {
            return "草稿与不可变配置快照不匹配，已拒绝生成差异。".to_owned();
        }
        if self.contains_sensitive_values
            || document_contains_sensitive_values(snapshot.product, &snapshot.document)
        {
            return format!(
                "敏感配置正文差异已隐藏；原始 {} B，当前草稿 {} B，所有未修改字节仍由 core 原样保留。",
                snapshot.bytes.len(),
                self.document.raw_bytes().len()
            );
        }
        bounded_line_diff_bytes(&snapshot.bytes, self.document.raw_bytes())
    }

    fn materialize(&self, snapshot: &MiddlewareConfigSnapshot) -> CoreResult<Vec<u8>> {
        if self.product != snapshot.product || self.base_sha256 != snapshot.sha256 {
            return Err(CoreError::validation(
                "middleware draft",
                "draft is not bound to the selected immutable snapshot",
            ));
        }
        if let Some(replacement) = &self.raw_replacement {
            return Ok(replacement.as_bytes().to_vec());
        }
        let mut document = snapshot.document.clone();
        for patch in &self.patches {
            document = document
                .apply_patches(&[MiddlewareDocumentPatch::new(
                    patch.span,
                    patch.replacement.as_str(),
                )])
                .map_err(|error| {
                    CoreError::validation("middleware draft materialization", error.to_string())
                })?;
        }
        Ok(document.raw_bytes().to_vec())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MiddlewareDraftValue {
    pub value: Option<String>,
    pub sensitive: bool,
}

impl fmt::Debug for MiddlewareConfigSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MiddlewareConfigSnapshot")
            .field("instance_id", &self.instance_id)
            .field("product", &self.product)
            .field("role", &self.role)
            .field("path", &self.path)
            .field("metadata", &self.metadata)
            .field("sha256", &self.sha256)
            .field(
                "bytes",
                &format_args!("[REDACTED; {} bytes]", self.bytes.len()),
            )
            .field("include_count", &self.includes.len())
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MiddlewareConfigurationBundle {
    target: TargetGuard,
    instance: MiddlewareInstance,
    files: Vec<MiddlewareConfigSnapshot>,
    unresolved_includes: Vec<MiddlewareIncludeReference>,
    directory_manifests: Vec<MiddlewareDirectoryManifest>,
    total_bytes: usize,
    loaded_at: DateTime<Utc>,
}

impl MiddlewareConfigurationBundle {
    pub fn target(&self) -> &TargetGuard {
        &self.target
    }

    pub fn instance(&self) -> &MiddlewareInstance {
        &self.instance
    }

    pub fn files(&self) -> &[MiddlewareConfigSnapshot] {
        &self.files
    }

    pub fn unresolved_includes(&self) -> &[MiddlewareIncludeReference] {
        &self.unresolved_includes
    }

    pub const fn directory_manifest_count(&self) -> usize {
        self.directory_manifests.len()
    }

    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub const fn loaded_at(&self) -> DateTime<Utc> {
        self.loaded_at
    }

    pub fn apache_config_graph_evidence(
        &self,
        invocation: &ApacheRuntimeInvocationEvidence,
    ) -> CoreResult<ApacheConfigGraphEvidence> {
        if self.instance.product != MiddlewareProduct::ApacheHttpd {
            return Err(CoreError::validation(
                "Apache configuration graph evidence",
                "requires one Apache HTTPD configuration bundle",
            ));
        }
        if &self.target != invocation.target()
            || self.instance.target != self.target
            || self.instance.unit != invocation.unit()
        {
            return Err(CoreError::validation(
                "Apache configuration graph evidence",
                "bundle and runtime invocation evidence do not share one target and instance",
            ));
        }
        if !self.unresolved_includes.is_empty() {
            return Err(CoreError::validation(
                "Apache configuration graph evidence",
                "cannot seal a graph with unresolved include references",
            ));
        }

        let mut items = Vec::new();
        items.push(ApacheConfigGraphItem::new(
            ApacheConfigGraphItemKind::DirectoryManifest,
            vec![
                b"configuration-scope".to_vec(),
                self.instance.primary_config.as_str().as_bytes().to_vec(),
                self.instance.config_root.as_str().as_bytes().to_vec(),
            ],
        )?);
        for file in &self.files {
            items.push(ApacheConfigGraphItem::new(
                ApacheConfigGraphItemKind::ConfigFile,
                vec![
                    file.path.as_str().as_bytes().to_vec(),
                    middleware_config_role_tag(file.role).to_vec(),
                    file.sha256.as_bytes().to_vec(),
                    bounded_usize_bytes(file.bytes.len(), "Apache configuration file length")?,
                ],
            )?);
            for (include_index, include) in file.includes.iter().enumerate() {
                if include.unresolved_reason.is_some() {
                    return Err(CoreError::validation(
                        "Apache configuration graph evidence",
                        "cannot seal a graph with an unresolved include reference",
                    ));
                }
                items.push(ApacheConfigGraphItem::new(
                    ApacheConfigGraphItemKind::IncludeReference,
                    vec![
                        include.source.as_str().as_bytes().to_vec(),
                        bounded_usize_bytes(include_index, "Apache include index")?,
                        include.raw_value.as_bytes().to_vec(),
                        vec![u8::from(include.optional)],
                        bounded_usize_bytes(include.resolved.len(), "Apache include targets")?,
                    ],
                )?);
                for (resolution_index, resolved) in include.resolved.iter().enumerate() {
                    items.push(ApacheConfigGraphItem::new(
                        ApacheConfigGraphItemKind::IncludeReference,
                        vec![
                            include.source.as_str().as_bytes().to_vec(),
                            bounded_usize_bytes(include_index, "Apache include index")?,
                            bounded_usize_bytes(
                                resolution_index,
                                "Apache include resolution index",
                            )?,
                            resolved.as_str().as_bytes().to_vec(),
                        ],
                    )?);
                }
            }
        }
        for (manifest_index, manifest) in self.directory_manifests.iter().enumerate() {
            items.push(ApacheConfigGraphItem::new(
                ApacheConfigGraphItemKind::DirectoryManifest,
                vec![
                    bounded_usize_bytes(manifest_index, "Apache directory manifest index")?,
                    manifest.path.as_str().as_bytes().to_vec(),
                    manifest
                        .pattern
                        .as_deref()
                        .unwrap_or("")
                        .as_bytes()
                        .to_vec(),
                    vec![u8::from(manifest.activation_sensitive)],
                    vec![u8::from(manifest.include_directories)],
                    bounded_usize_bytes(
                        manifest.entries.len(),
                        "Apache directory manifest entries",
                    )?,
                ],
            )?);
            for entry in &manifest.entries {
                items.push(ApacheConfigGraphItem::new(
                    ApacheConfigGraphItemKind::DirectoryEntry,
                    vec![
                        bounded_usize_bytes(manifest_index, "Apache directory manifest index")?,
                        entry.path.as_str().as_bytes().to_vec(),
                        sftp_file_kind_tag(entry.kind).to_vec(),
                    ],
                )?);
            }
        }
        ApacheConfigGraphEvidence::from_items(invocation, self.instance.id.clone(), items)
    }
}

fn middleware_config_role_tag(role: MiddlewareConfigRole) -> &'static [u8] {
    match role {
        MiddlewareConfigRole::Primary => b"primary",
        MiddlewareConfigRole::Included => b"included",
        MiddlewareConfigRole::TomcatWeb => b"tomcat-web",
        MiddlewareConfigRole::TomcatContext => b"tomcat-context",
        MiddlewareConfigRole::Properties => b"properties",
        MiddlewareConfigRole::Logging => b"logging",
        MiddlewareConfigRole::Users => b"users",
        MiddlewareConfigRole::Other => b"other",
    }
}

fn sftp_file_kind_tag(kind: SftpFileKind) -> &'static [u8] {
    match kind {
        SftpFileKind::File => b"file",
        SftpFileKind::Directory => b"directory",
        SftpFileKind::Symlink => b"symlink",
        SftpFileKind::Other => b"other",
    }
}

fn bounded_usize_bytes(value: usize, subject: &'static str) -> CoreResult<Vec<u8>> {
    let value =
        u64::try_from(value).map_err(|_| CoreError::validation(subject, "value overflowed u64"))?;
    Ok(value.to_be_bytes().to_vec())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MiddlewareDirectoryManifest {
    path: RemotePath,
    pattern: Option<String>,
    activation_sensitive: bool,
    include_directories: bool,
    entries: Vec<MiddlewareDirectoryEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MiddlewareDirectoryEntry {
    path: RemotePath,
    kind: SftpFileKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MiddlewareChangePreview {
    pub path: RemotePath,
    pub old_sha256: String,
    pub new_sha256: String,
    pub old_bytes: usize,
    pub new_bytes: usize,
    pub changed_lines: usize,
    pub validator: MiddlewareValidator,
    pub activation: MiddlewareActivationPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MiddlewareChangeState {
    RecoveryPending,
    Applied,
    AutomaticallyRestored,
    RestoreFailed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MiddlewareChangeRecord {
    pub id: String,
    pub operation_id: String,
    pub target: TargetIdentity,
    pub instance_id: String,
    pub product: MiddlewareProduct,
    pub unit: String,
    pub binary_path: RemotePath,
    pub fragment_path: RemotePath,
    pub runtime_fingerprint: String,
    pub primary_config: RemotePath,
    pub config_root: RemotePath,
    #[serde(default)]
    pub discovered_config_root: bool,
    pub path: RemotePath,
    pub remote_backup: RemotePath,
    pub old_sha256: String,
    pub new_sha256: String,
    pub old_bytes: usize,
    pub new_bytes: usize,
    pub validator: MiddlewareValidator,
    pub activation: MiddlewareActivationPolicy,
    pub state: MiddlewareChangeState,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct StoredMiddlewareHistory {
    #[serde(deserialize_with = "deserialize_middleware_history_records")]
    records: Vec<MiddlewareChangeRecord>,
}

fn deserialize_middleware_history_records<'de, D>(
    deserializer: D,
) -> Result<Vec<MiddlewareChangeRecord>, D::Error>
where
    D: Deserializer<'de>,
{
    struct MiddlewareHistoryVisitor;

    impl<'de> Visitor<'de> for MiddlewareHistoryVisitor {
        type Value = Vec<MiddlewareChangeRecord>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "at most {MAX_HISTORY_RECORDS} middleware history records"
            )
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut records = Vec::with_capacity(
                sequence
                    .size_hint()
                    .unwrap_or_default()
                    .min(MAX_HISTORY_RECORDS),
            );
            while records.len() < MAX_HISTORY_RECORDS {
                let Some(record) = sequence.next_element()? else {
                    return Ok(records);
                };
                records.push(record);
            }
            if sequence.next_element::<IgnoredAny>()?.is_some() {
                return Err(A::Error::custom(
                    "middleware history record count exceeds its storage budget",
                ));
            }
            Ok(records)
        }
    }

    deserializer.deserialize_seq(MiddlewareHistoryVisitor)
}

#[derive(Debug, Clone)]
pub struct MiddlewareService {
    ssh: SshService,
    sftp: SftpService,
    target: Arc<TargetContext>,
    journal: PortableOperationJournal,
    store: PortableStore,
    history_lock: Arc<SyncMutex<()>>,
}

impl MiddlewareService {
    pub fn new(
        ssh: SshService,
        sftp: SftpService,
        target: Arc<TargetContext>,
        journal: PortableOperationJournal,
        store: PortableStore,
    ) -> Self {
        Self {
            ssh,
            sftp,
            target,
            journal,
            store,
            history_lock: Arc::new(SyncMutex::new(())),
        }
    }

    pub async fn discover(&self, session: &BoundSshSession) -> CoreResult<Vec<MiddlewareInstance>> {
        self.target.validate(session.target())?;
        let output = self
            .ssh
            .execute_bound(
                session,
                middleware_unit_inventory_command(),
                Duration::from_secs(20),
            )
            .await?;
        self.target.validate(session.target())?;
        if output
            .output
            .lines()
            .any(|line| line.trim() == NO_SYSTEMD_MARKER)
        {
            return Err(CoreError::Unsupported {
                feature: "middleware discovery without systemd",
            });
        }
        ensure_command_succeeded("middleware unit inventory", &output)?;
        if output.output.len() > MAX_DISCOVERY_OUTPUT_BYTES {
            return Err(CoreError::validation(
                "middleware unit inventory",
                "remote output exceeds the bounded discovery limit",
            ));
        }

        let mut units = parse_unit_inventory(&output.output)?;
        units.truncate(MAX_MIDDLEWARE_INSTANCES);
        let mut instances = Vec::with_capacity(units.len());
        for unit in units {
            self.target.validate(session.target())?;
            let details = self.inspect_unit(session, unit.product, &unit.unit).await?;
            if let Some(instance) = details {
                instances.push(instance);
            }
        }
        self.target.validate(session.target())?;
        instances.sort_by(|left, right| {
            left.product
                .cmp(&right.product)
                .then_with(|| left.unit.cmp(&right.unit))
        });
        instances.dedup_by(|left, right| left.id == right.id);
        Ok(instances)
    }

    async fn inspect_unit(
        &self,
        session: &BoundSshSession,
        product: MiddlewareProduct,
        unit: &str,
    ) -> CoreResult<Option<MiddlewareInstance>> {
        validate_systemd_unit(unit)?;
        let command = format!(
            "LC_ALL=C systemctl show --no-pager --property=Id,LoadState,ActiveState,SubState,MainPID,FragmentPath,ExecStart,Environment,EnvironmentFiles -- {} 2>/dev/null",
            shq(unit)
        );
        self.target.validate(session.target())?;
        let output = self
            .ssh
            .execute_bound(session, command, Duration::from_secs(15))
            .await?;
        self.target.validate(session.target())?;
        if output.timed_out || output.exit_code.is_some_and(|code| code != 0) {
            return Ok(None);
        }
        let fields = parse_key_value_lines(&output.output, 64)?;
        if fields
            .get("LoadState")
            .is_some_and(|value| value == "not-found")
        {
            return Ok(None);
        }
        let exec_start = fields.get("ExecStart").map(String::as_str).unwrap_or("");
        let environment = fields.get("Environment").map(String::as_str).unwrap_or("");
        let Ok(binary_path) = discover_exec_path(exec_start) else {
            return Ok(None);
        };
        if validate_product_executable(product, &binary_path, exec_start).is_err() {
            return Ok(None);
        }
        let product_probe = self.product_probe(session, product, &binary_path).await?;
        let (primary_config, config_root) = discover_config_path(
            product,
            exec_start,
            environment,
            product_probe.as_deref().unwrap_or(""),
        )?;
        let root_is_target_reported = apache_scope_is_target_reported(
            product,
            exec_start,
            product_probe.as_deref().unwrap_or(""),
            &primary_config,
            &config_root,
        );
        let Ok((primary_config, config_root, discovered_config_root)) = self
            .select_existing_config(
                session,
                product,
                primary_config,
                config_root,
                root_is_target_reported,
            )
            .await
        else {
            return Ok(None);
        };
        let version = parse_product_version(product, product_probe.as_deref().unwrap_or(""));
        let fragment_path = fields
            .get("FragmentPath")
            .and_then(|value| RemotePath::new(value.clone()).ok())
            .ok_or_else(|| {
                CoreError::validation(
                    "middleware systemd instance",
                    "loaded unit did not report a valid absolute FragmentPath",
                )
            })?;
        let environment_files = fields
            .get("EnvironmentFiles")
            .map(String::as_str)
            .unwrap_or("");
        let runtime_fingerprint = runtime_fingerprint(
            unit,
            &fragment_path,
            exec_start,
            environment,
            environment_files,
        );
        let id = middleware_instance_id(product, unit, primary_config.as_str());
        let catalog = catalog_for(product);
        Ok(Some(MiddlewareInstance {
            target: session.target().clone(),
            id,
            product,
            runtime: MiddlewareRuntimeKind::Systemd,
            unit: unit.to_owned(),
            version,
            active_state: fields
                .get("ActiveState")
                .cloned()
                .unwrap_or_else(|| "unknown".to_owned()),
            sub_state: fields
                .get("SubState")
                .cloned()
                .unwrap_or_else(|| "unknown".to_owned()),
            main_pid: fields
                .get("MainPID")
                .and_then(|value| value.parse().ok())
                .unwrap_or(0),
            binary_path,
            fragment_path,
            runtime_fingerprint,
            apache_invocation_evidence: (product == MiddlewareProduct::ApacheHttpd)
                .then_some(ApacheInvocationEvidenceState::NotCollected),
            primary_config,
            config_root,
            discovered_config_root,
            validator: catalog.validator,
            activation: catalog.activation,
            supports_native_reload: catalog.native_reload,
        }))
    }

    async fn select_existing_config(
        &self,
        session: &BoundSshSession,
        product: MiddlewareProduct,
        discovered: RemotePath,
        discovered_root: RemotePath,
        root_is_target_reported: bool,
    ) -> CoreResult<(RemotePath, RemotePath, bool)> {
        let sftp = self
            .sftp
            .bind_session(session.target().clone(), session.session_id())
            .await?;
        let mut candidates = vec![(discovered, discovered_root, root_is_target_reported)];
        candidates.extend(
            catalog_for(product)
                .fallback_config_paths
                .iter()
                .map(|candidate| {
                    let path = RemotePath::new(*candidate)?;
                    let root = path.parent()?;
                    Ok((path, root, false))
                })
                .collect::<CoreResult<Vec<_>>>()?,
        );
        for (path, root, target_reported_root) in candidates {
            let catalog_scope = validate_config_scope(product, &path, &root).is_ok();
            // A vendor install may live outside the closed catalog.  It is
            // admitted only for the exact ServerRoot reported by this target's
            // validated httpd executable; both paths are canonicalized below.
            let discovered_scope = !catalog_scope
                && target_reported_root
                && validate_discovered_apache_scope(product, &path, &root).is_ok();
            if !catalog_scope && !discovered_scope {
                continue;
            }
            if self
                .sftp
                .metadata(&sftp, &path, false)
                .await
                .is_ok_and(|metadata| metadata.kind == SftpFileKind::File)
            {
                let Ok(root_metadata) = self.sftp.metadata(&sftp, &root, false).await else {
                    continue;
                };
                if root_metadata.kind != SftpFileKind::Directory {
                    continue;
                }
                let canonical_path = self.sftp.canonicalize(&sftp, &path).await?;
                let canonical_root = self.sftp.canonicalize(&sftp, &root).await?;
                if canonical_path == path
                    && canonical_root == root
                    && (validate_config_scope(product, &canonical_path, &canonical_root).is_ok()
                        || (discovered_scope
                            && validate_discovered_apache_scope(
                                product,
                                &canonical_path,
                                &canonical_root,
                            )
                            .is_ok()))
                {
                    return Ok((canonical_path, canonical_root, discovered_scope));
                }
            }
        }
        Err(CoreError::validation(
            "middleware configuration scope",
            "no regular canonical configuration file was found inside the closed product roots",
        ))
    }

    async fn product_probe(
        &self,
        session: &BoundSshSession,
        product: MiddlewareProduct,
        binary_path: &RemotePath,
    ) -> CoreResult<Option<String>> {
        self.target.validate(session.target())?;
        let output = self
            .ssh
            .execute_bound(
                session,
                product_probe_command(product, binary_path),
                Duration::from_secs(15),
            )
            .await?;
        self.target.validate(session.target())?;
        if output.timed_out
            || output.exit_code != Some(0)
            || output.output.len() > MAX_DISCOVERY_OUTPUT_BYTES
        {
            return Ok(None);
        }
        Ok(Some(output.output))
    }

    pub async fn load_configuration(
        &self,
        session: &BoundSshSession,
        instance: &MiddlewareInstance,
    ) -> CoreResult<MiddlewareConfigurationBundle> {
        self.target.validate(session.target())?;
        validate_instance(instance)?;
        if instance.target != *session.target() {
            return Err(CoreError::validation(
                "middleware instance target",
                "instance was discovered for a different target generation",
            ));
        }
        let sftp = self
            .sftp
            .bind_session(session.target().clone(), session.session_id())
            .await?;
        let canonical_root = self.sftp.canonicalize(&sftp, &instance.config_root).await?;
        let root_metadata = self
            .sftp
            .metadata(&sftp, &instance.config_root, false)
            .await?;
        if canonical_root != instance.config_root || root_metadata.kind != SftpFileKind::Directory {
            return Err(CoreError::validation(
                "middleware configuration root",
                "captured configuration root is no longer one exact canonical directory",
            ));
        }
        let mut queue = VecDeque::from([PendingConfigPath {
            path: instance.primary_config.clone(),
            role: MiddlewareConfigRole::Primary,
            depth: 0,
            optional: false,
            ancestors: Vec::new(),
        }]);
        if instance.product == MiddlewareProduct::Tomcat {
            enqueue_tomcat_known_files(instance, &mut queue)?;
        }
        let mut visited = BTreeSet::new();
        let mut files = Vec::new();
        let mut unresolved = Vec::new();
        let mut directory_manifests = Vec::new();
        let mut total_bytes = 0usize;

        while let Some(pending) = queue.pop_front() {
            if files.len() >= MAX_MIDDLEWARE_CONFIG_FILES
                || queue.len() > MAX_MIDDLEWARE_CONFIG_FILES * 2
                || visited.len() > MAX_MIDDLEWARE_CONFIG_FILES * 2
            {
                return Err(CoreError::validation(
                    "middleware configuration graph",
                    format!("contains more than {MAX_MIDDLEWARE_CONFIG_FILES} files"),
                ));
            }
            if !is_approved_config_path(instance, &pending.path) {
                return Err(CoreError::validation(
                    "middleware configuration path",
                    "configuration path escaped the selected instance roots",
                ));
            }
            if !self.sftp.exists(&sftp, &pending.path).await? {
                if pending.optional && pending.role != MiddlewareConfigRole::Primary {
                    let manifest = capture_optional_path_guard(
                        &self.sftp,
                        &sftp,
                        instance,
                        &pending.path,
                        true,
                    )
                    .await?;
                    directory_manifests.push(manifest);
                    validate_directory_manifest_limits(&directory_manifests)?;
                    continue;
                }
                return Err(CoreError::validation(
                    "middleware required include",
                    format!("{} matched no path", pending.path.as_str()),
                ));
            }
            let canonical = self.sftp.canonicalize(&sftp, &pending.path).await?;
            if canonical != pending.path {
                return Err(CoreError::validation(
                    "middleware configuration path",
                    "configuration path contains a symbolic-link ancestor",
                ));
            }
            if !visited.insert(pending.path.clone()) {
                continue;
            }
            let metadata = self.sftp.metadata(&sftp, &pending.path, false).await?;
            if metadata.kind != SftpFileKind::File {
                if metadata.kind == SftpFileKind::Directory {
                    let manifest =
                        enqueue_directory_files(&self.sftp, &sftp, &pending, &mut queue, &visited)
                            .await?;
                    directory_manifests.push(manifest);
                    validate_directory_manifest_limits(&directory_manifests)?;
                    continue;
                }
                return Err(CoreError::validation(
                    "middleware configuration file",
                    "configuration path must be a regular file and not a symlink",
                ));
            }
            if metadata.size > MAX_EDIT_BYTES {
                return Err(CoreError::validation(
                    "middleware configuration file",
                    format!(
                        "{} exceeds the {MAX_EDIT_BYTES}-byte edit limit",
                        pending.path.as_str()
                    ),
                ));
            }
            let bytes = self.sftp.read_file(&sftp, &pending.path).await?;
            if bytes.len() as u64 != metadata.size {
                return Err(CoreError::validation(
                    "middleware configuration file",
                    format!(
                        "{} changed size while it was being captured",
                        pending.path.as_str()
                    ),
                ));
            }
            total_bytes = total_bytes.checked_add(bytes.len()).ok_or_else(|| {
                CoreError::validation("middleware configuration graph", "byte count overflow")
            })?;
            if total_bytes > MAX_MIDDLEWARE_TOTAL_BYTES {
                return Err(CoreError::validation(
                    "middleware configuration graph",
                    format!("exceeds the {MAX_MIDDLEWARE_TOTAL_BYTES}-byte aggregate limit"),
                ));
            }
            let syntax = syntax_for_path(instance.product, &pending.path);
            let document = MiddlewareDocument::parse(syntax, bytes.clone())
                .map_err(|error| CoreError::validation("middleware document", error.to_string()))?;
            let mut includes = extract_include_references(instance, &pending.path, &document)?;
            for include in &mut includes {
                if include.resolved.is_empty()
                    && include
                        .unresolved_reason
                        .as_deref()
                        .is_some_and(|reason| reason.starts_with("glob include"))
                {
                    let manifests =
                        expand_wildcard_include(&self.sftp, &sftp, instance, include).await?;
                    directory_manifests.extend(manifests);
                    validate_directory_manifest_limits(&directory_manifests)?;
                }
            }
            for include in &includes {
                if include.unresolved_reason.is_some() {
                    unresolved.push(include.clone());
                }
                if !include.resolved.is_empty() && pending.depth >= MAX_MIDDLEWARE_INCLUDE_DEPTH {
                    return Err(CoreError::validation(
                        "middleware include depth",
                        format!("exceeds {MAX_MIDDLEWARE_INCLUDE_DEPTH}"),
                    ));
                }
                for path in &include.resolved {
                    enqueue_include_path(&mut queue, &pending, include, path)?;
                }
            }
            files.push(MiddlewareConfigSnapshot {
                target: session.target().clone(),
                instance_id: instance.id.clone(),
                product: instance.product,
                role: pending.role,
                path: pending.path,
                metadata,
                sha256: sha256_hex(&bytes),
                bytes: Zeroizing::new(bytes),
                document,
                includes,
            });
        }
        self.target.validate(session.target())?;
        files.sort_by(|left, right| {
            (left.role != MiddlewareConfigRole::Primary)
                .cmp(&(right.role != MiddlewareConfigRole::Primary))
                .then_with(|| left.path.cmp(&right.path))
        });
        directory_manifests.sort_by(|left, right| {
            left.path
                .cmp(&right.path)
                .then_with(|| left.pattern.cmp(&right.pattern))
                .then_with(|| left.activation_sensitive.cmp(&right.activation_sensitive))
                .then_with(|| left.include_directories.cmp(&right.include_directories))
        });
        directory_manifests.dedup();
        if directory_manifests.len() > MAX_MIDDLEWARE_CONFIG_FILES {
            return Err(CoreError::validation(
                "middleware configuration directories",
                "directory manifest count exceeded the bounded graph",
            ));
        }
        let directory_entries = directory_manifests
            .iter()
            .try_fold(0usize, |total, manifest| {
                total.checked_add(manifest.entries.len())
            })
            .ok_or_else(|| {
                CoreError::validation(
                    "middleware configuration directories",
                    "directory entry accounting overflowed",
                )
            })?;
        if directory_entries > MAX_MIDDLEWARE_DIRECTORY_ENTRIES {
            return Err(CoreError::validation(
                "middleware configuration directories",
                format!("directory membership exceeds {MAX_MIDDLEWARE_DIRECTORY_ENTRIES} entries"),
            ));
        }
        Ok(MiddlewareConfigurationBundle {
            target: session.target().clone(),
            instance: instance.clone(),
            files,
            unresolved_includes: unresolved,
            directory_manifests,
            total_bytes,
            loaded_at: Utc::now(),
        })
    }

    pub fn history(&self, target: &TargetGuard) -> CoreResult<Vec<MiddlewareChangeRecord>> {
        self.target.validate(target)?;
        let _guard = self.history_lock.lock();
        let mut records = read_stored_middleware_history(&self.store)?
            .records
            .into_iter()
            .filter(|record| record.target == target.identity)
            .collect::<Vec<_>>();
        for record in &records {
            validate_change_record(record)?;
        }
        records.sort_by(|left, right| right.updated_at.cmp(&left.updated_at));
        Ok(records)
    }
}

#[derive(Clone, Debug)]
struct PendingConfigPath {
    path: RemotePath,
    role: MiddlewareConfigRole,
    depth: usize,
    optional: bool,
    ancestors: Vec<RemotePath>,
}

#[derive(Clone, Debug)]
struct UnitCandidate {
    product: MiddlewareProduct,
    unit: String,
}

pub struct MiddlewareChangePlan {
    operation: PlannedOperation,
    executor: MiddlewareChangeExecutor,
    target: Arc<TargetContext>,
    journal: PortableOperationJournal,
    store: PortableStore,
    history_lock: Arc<SyncMutex<()>>,
    preview: MiddlewareChangePreview,
    record_id: String,
}

impl fmt::Debug for MiddlewareChangePlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MiddlewareChangePlan")
            .field("operation", self.operation.definition())
            .field("preview", &self.preview)
            .field("record_id", &self.record_id)
            .finish_non_exhaustive()
    }
}

impl MiddlewareChangePlan {
    pub fn definition(&self) -> &OperationPlan {
        self.operation.definition()
    }

    pub fn preview(&self) -> &MiddlewareChangePreview {
        &self.preview
    }

    pub fn state(&self) -> OperationState {
        self.operation.state()
    }

    pub fn confirm(&mut self, confirmation: DangerousConfirmation) -> CoreResult<()> {
        self.operation.confirm(confirmation)
    }

    /// Execute the immutable CAS plan and automatically restore the original
    /// bytes if config-test, activation or the health readback fails.
    pub async fn execute_and_verify(&mut self) -> CoreResult<MiddlewareChangeOutcome> {
        ensure_apache_execution_evidence(&self.executor.instance)?;
        let (_, prepared) = self.persist_record(MiddlewareChangeState::RecoveryPending)?;
        if !prepared {
            return Err(CoreError::validation(
                "middleware recovery record",
                "the durable recovery record could not be written, so no remote mutation was dispatched",
            ));
        }
        if let Err(error) = self.operation.execute(&self.target, &self.executor).await {
            let failure = self.executor.failure_state.load(Ordering::Acquire);
            let recovery_state = match (failure, self.operation.state()) {
                (1, _) => Some(MiddlewareChangeState::AutomaticallyRestored),
                (2, _) | (_, OperationState::StaleAfterExecution) => {
                    if self.operation.state() == OperationState::StaleAfterExecution {
                        let _ = self.operation.journal(&self.journal);
                    }
                    Some(MiddlewareChangeState::RestoreFailed)
                }
                _ => Some(MiddlewareChangeState::RecoveryPending),
            };
            if let Some(state) = recovery_state {
                return Err(self.recovery_error("middleware execution", &error, state, None));
            }
            return Err(error);
        }
        if let Err(journal_error) = self.operation.journal(&self.journal) {
            let restore = self
                .operation
                .restore(&self.target, &self.executor, &self.journal)
                .await;
            let restored = restore.is_ok() || self.operation.state() == OperationState::Restored;
            let state = if restored {
                MiddlewareChangeState::AutomaticallyRestored
            } else {
                MiddlewareChangeState::RestoreFailed
            };
            return Err(self.recovery_error(
                "middleware execution journal",
                &journal_error,
                state,
                restore.err().as_ref(),
            ));
        }
        match self
            .operation
            .verify(&self.target, &self.executor, &self.journal)
            .await
        {
            Ok(verification) if verification.passed => {
                let (record, history_persisted) =
                    self.persist_record(MiddlewareChangeState::Applied)?;
                Ok(MiddlewareChangeOutcome {
                    verification,
                    automatically_restored: false,
                    record,
                    history_persisted,
                })
            }
            Ok(verification) => {
                let restore = self
                    .operation
                    .restore(&self.target, &self.executor, &self.journal)
                    .await;
                let restored =
                    restore.is_ok() || self.operation.state() == OperationState::Restored;
                let state = if restored {
                    MiddlewareChangeState::AutomaticallyRestored
                } else {
                    MiddlewareChangeState::RestoreFailed
                };
                if let Err(restore_error) = restore {
                    return Err(self.recovery_error(
                        "middleware activation verification",
                        &CoreError::validation(
                            "middleware activation verification",
                            verification.detail,
                        ),
                        state,
                        Some(&restore_error),
                    ));
                }
                Err(self.recovery_error(
                    "middleware activation verification",
                    &CoreError::validation(
                        "middleware activation verification",
                        verification.detail,
                    ),
                    state,
                    None,
                ))
            }
            Err(error) => {
                let restore = self
                    .operation
                    .restore(&self.target, &self.executor, &self.journal)
                    .await;
                let restored =
                    restore.is_ok() || self.operation.state() == OperationState::Restored;
                let state = if restored {
                    MiddlewareChangeState::AutomaticallyRestored
                } else {
                    MiddlewareChangeState::RestoreFailed
                };
                if let Err(restore_error) = restore {
                    return Err(self.recovery_error(
                        "middleware automatic restore",
                        &error,
                        state,
                        Some(&restore_error),
                    ));
                }
                Err(self.recovery_error("middleware verification", &error, state, None))
            }
        }
    }

    fn recovery_error(
        &self,
        subject: &'static str,
        original: &CoreError,
        state: MiddlewareChangeState,
        restore_error: Option<&CoreError>,
    ) -> CoreError {
        let (record_id, persisted) = match self.persist_record(state) {
            Ok((record, persisted)) => (record.id, persisted),
            Err(_) => (self.record_id.clone(), false),
        };
        let restore_detail = restore_error
            .map(|error| format!("; restore error: {error}"))
            .unwrap_or_default();
        CoreError::validation(
            subject,
            format!(
                "{original}{restore_detail}; recovery state {state:?}; record {record_id}; history persisted={persisted}; remote backup {}",
                self.executor.backup.backup.as_str()
            ),
        )
    }

    fn persist_record(
        &self,
        state: MiddlewareChangeState,
    ) -> CoreResult<(MiddlewareChangeRecord, bool)> {
        let now = Utc::now();
        let definition = self.operation.definition();
        let record = MiddlewareChangeRecord {
            id: self.record_id.clone(),
            operation_id: definition.id.clone(),
            target: definition.target.identity.clone(),
            instance_id: self.executor.instance.id.clone(),
            product: self.executor.instance.product,
            unit: self.executor.instance.unit.clone(),
            binary_path: self.executor.instance.binary_path.clone(),
            fragment_path: self.executor.instance.fragment_path.clone(),
            runtime_fingerprint: self.executor.instance.runtime_fingerprint.clone(),
            primary_config: self.executor.instance.primary_config.clone(),
            config_root: self.executor.instance.config_root.clone(),
            discovered_config_root: self.executor.instance.discovered_config_root,
            path: self.preview.path.clone(),
            remote_backup: self.executor.backup.backup.clone(),
            old_sha256: self.preview.old_sha256.clone(),
            new_sha256: self.preview.new_sha256.clone(),
            old_bytes: self.preview.old_bytes,
            new_bytes: self.preview.new_bytes,
            validator: self.preview.validator,
            activation: self.preview.activation,
            state,
            created_at: now,
            updated_at: now,
        };
        validate_change_record(&record)?;
        let persisted = (|| {
            let _guard = self.history_lock.lock();
            let mut stored = read_stored_middleware_history(&self.store)?;
            stored.records.retain(|existing| existing.id != record.id);
            stored.records.push(record.clone());
            if stored.records.len() > MAX_HISTORY_RECORDS {
                stored
                    .records
                    .sort_by(|left, right| right.updated_at.cmp(&left.updated_at));
                stored.records.truncate(MAX_HISTORY_RECORDS);
            }
            self.store.write(StoreFile::Middleware, &stored)
        })();
        if let Err(error) = &persisted {
            tracing::error!(error = %error, operation_id = %record.operation_id, "middleware change succeeded but portable history persistence failed");
        }
        Ok((record, persisted.is_ok()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MiddlewareChangeOutcome {
    pub verification: VerificationResult,
    pub automatically_restored: bool,
    pub record: MiddlewareChangeRecord,
    pub history_persisted: bool,
}

impl MiddlewareService {
    pub async fn plan_change(
        &self,
        session: &BoundSshSession,
        bundle: &MiddlewareConfigurationBundle,
        file_index: usize,
        draft: MiddlewareDraft,
    ) -> CoreResult<MiddlewareChangePlan> {
        self.target.validate(session.target())?;
        validate_bundle_binding(session, bundle)?;
        let instance = &bundle.instance;
        let snapshot = bundle.files.get(file_index).ok_or_else(|| {
            CoreError::validation(
                "middleware configuration selection",
                "selected file index is outside the captured configuration graph",
            )
        })?;
        validate_instance(instance)?;
        ensure_apache_plan_evidence(instance)?;
        validate_snapshot_binding(instance, snapshot)?;
        let replacement = draft.materialize(snapshot)?;
        if replacement.len() as u64 > MAX_EDIT_BYTES
            || replacement.len() > MAX_MIDDLEWARE_DOCUMENT_BYTES
        {
            return Err(CoreError::validation(
                "middleware replacement",
                format!("must not exceed {MAX_EDIT_BYTES} bytes"),
            ));
        }
        if replacement.contains(&0) {
            return Err(CoreError::validation(
                "middleware replacement",
                "must not contain NUL bytes",
            ));
        }
        let replacement_document =
            MiddlewareDocument::parse(snapshot.document.syntax(), replacement.clone()).map_err(
                |error| CoreError::validation("middleware replacement", error.to_string()),
            )?;
        validate_document_structure(instance.product, &replacement_document)?;
        if include_directive_signature(instance.product, &snapshot.document)?
            != include_directive_signature(instance.product, &replacement_document)?
        {
            return Err(CoreError::validation(
                "middleware include topology",
                "include directives cannot be added, removed, or retargeted inside a file-content plan; rediscover the instance and use a separately captured graph workflow",
            ));
        }
        let current_hash = sha256_hex(&snapshot.bytes);
        if current_hash != snapshot.sha256 {
            return Err(CoreError::validation(
                "middleware snapshot",
                "snapshot bytes do not match the captured SHA-256",
            ));
        }
        let new_hash = sha256_hex(&replacement);
        if new_hash == snapshot.sha256 {
            return Err(CoreError::validation(
                "middleware replacement",
                "replacement is byte-for-byte identical to the current file",
            ));
        }
        let sftp_session = self
            .sftp
            .bind_session(session.target().clone(), session.session_id())
            .await?;
        let backup_directory = instance
            .primary_config
            .parent()?
            .child(".lovelyres-backups")?;
        if bundle
            .directory_manifests
            .iter()
            .any(|manifest| manifest_would_activate_backup(manifest, &backup_directory))
        {
            return Err(CoreError::validation(
                "middleware backup namespace",
                "the instance includes the whole backup parent directory; guarded editing is refused because a recoverable copy could become active configuration",
            ));
        }
        let inner = self.sftp.plan(
            &sftp_session,
            SftpMutation::AtomicWriteIfMatch {
                path: snapshot.path.clone(),
                expected_sha256: snapshot.sha256.clone(),
                expected_canonical_path: Some(snapshot.path.clone()),
                backup_directory: Some(backup_directory),
                content: replacement.clone(),
            },
        )?;
        let backup = inner.atomic_backup().ok_or_else(|| {
            CoreError::validation(
                "middleware atomic backup",
                "atomic write plan did not reserve a typed backup path",
            )
        })?;
        let changed_lines = changed_line_count(&snapshot.bytes, &replacement);
        let preview = MiddlewareChangePreview {
            path: snapshot.path.clone(),
            old_sha256: snapshot.sha256.clone(),
            new_sha256: new_hash,
            old_bytes: snapshot.bytes.len(),
            new_bytes: replacement.len(),
            changed_lines,
            validator: instance.validator,
            activation: instance.activation,
        };
        let summary = format!(
            "{} {} 应用 {} 的无损配置变更（{} 行受影响）",
            instance.product.label(),
            instance.unit,
            snapshot.path.as_str(),
            changed_lines
        );
        let mut definition = OperationPlan::new(
            session.target().clone(),
            summary,
            true,
            Some(format!(
                "从远端原子备份恢复 {}，重新{}并验证服务",
                snapshot.path.as_str(),
                instance.activation.label()
            )),
        )?;
        definition
            .metadata
            .insert("source".to_owned(), "middleware".to_owned());
        definition
            .metadata
            .insert("product".to_owned(), format!("{:?}", instance.product));
        definition
            .metadata
            .insert("instance-id".to_owned(), instance.id.clone());
        definition
            .metadata
            .insert("path".to_owned(), snapshot.path.as_str().to_owned());
        definition
            .metadata
            .insert("old-sha256".to_owned(), snapshot.sha256.clone());
        definition
            .metadata
            .insert("new-sha256".to_owned(), preview.new_sha256.clone());
        let executor = MiddlewareChangeExecutor {
            ssh: self.ssh.clone(),
            sftp: self.sftp.clone(),
            target: self.target.clone(),
            session: session.clone(),
            sftp_session,
            instance: instance.clone(),
            graph_manifest: bundle
                .files
                .iter()
                .map(|file| MiddlewareGraphEntry {
                    path: file.path.clone(),
                    sha256: file.sha256.clone(),
                    bytes: file.bytes.len(),
                })
                .collect(),
            directory_manifests: bundle.directory_manifests.clone(),
            post_graph_manifest: bundle
                .files
                .iter()
                .map(|file| {
                    if file.path == snapshot.path {
                        MiddlewareGraphEntry {
                            path: file.path.clone(),
                            sha256: preview.new_sha256.clone(),
                            bytes: replacement.len(),
                        }
                    } else {
                        MiddlewareGraphEntry {
                            path: file.path.clone(),
                            sha256: file.sha256.clone(),
                            bytes: file.bytes.len(),
                        }
                    }
                })
                .collect(),
            backup,
            failure_state: AtomicU8::new(0),
            inner: Mutex::new(inner),
        };
        Ok(MiddlewareChangePlan {
            operation: PlannedOperation::plan(definition),
            executor,
            target: self.target.clone(),
            journal: self.journal.clone(),
            store: self.store.clone(),
            history_lock: self.history_lock.clone(),
            preview,
            record_id: Uuid::new_v4().to_string(),
        })
    }

    /// Plan a durable restore from the remote backup captured by a previously
    /// verified middleware change. Both the current file and backup are hash
    /// checked before a new exact-confirmation CAS plan is returned.
    pub async fn plan_restore(
        &self,
        session: &BoundSshSession,
        record_id: &str,
    ) -> CoreResult<MiddlewareChangePlan> {
        self.target.validate(session.target())?;
        if Uuid::parse_str(record_id).is_err() {
            return Err(CoreError::validation(
                "middleware restore record",
                "record id must be a UUID",
            ));
        }
        let record = read_stored_middleware_history(&self.store)?
            .records
            .into_iter()
            .find(|record| record.id == record_id && record.target == session.target().identity)
            .ok_or_else(|| CoreError::NotFound {
                entity: "middleware change record",
                id: record_id.to_owned(),
            })?;
        validate_change_record(&record)?;
        if !matches!(
            record.state,
            MiddlewareChangeState::RecoveryPending
                | MiddlewareChangeState::Applied
                | MiddlewareChangeState::RestoreFailed
        ) {
            return Err(CoreError::validation(
                "middleware restore record",
                "only an applied, pending-recovery, or failed-restore change with an intact remote backup can be restored",
            ));
        }
        let instance = MiddlewareInstance {
            target: session.target().clone(),
            id: record.instance_id.clone(),
            product: record.product,
            runtime: MiddlewareRuntimeKind::Systemd,
            unit: record.unit.clone(),
            version: "restored history".to_owned(),
            active_state: "unknown".to_owned(),
            sub_state: "unknown".to_owned(),
            main_pid: 0,
            binary_path: record.binary_path.clone(),
            fragment_path: record.fragment_path.clone(),
            runtime_fingerprint: record.runtime_fingerprint.clone(),
            apache_invocation_evidence: (record.product == MiddlewareProduct::ApacheHttpd)
                .then_some(ApacheInvocationEvidenceState::NotCollected),
            primary_config: record.primary_config.clone(),
            config_root: record.config_root.clone(),
            discovered_config_root: record.discovered_config_root,
            validator: record.validator,
            activation: record.activation,
            supports_native_reload: matches!(
                record.product,
                MiddlewareProduct::Nginx | MiddlewareProduct::ApacheHttpd
            ),
        };
        validate_instance(&instance)?;
        verify_runtime_identity(&self.target, &self.ssh, session, &instance).await?;
        let sftp = self
            .sftp
            .bind_session(session.target().clone(), session.session_id())
            .await?;
        let backup_metadata = self
            .sftp
            .metadata(&sftp, &record.remote_backup, false)
            .await?;
        if backup_metadata.kind != SftpFileKind::File {
            return Err(CoreError::validation(
                "middleware restore files",
                "remote backup must be a regular file",
            ));
        }
        let backup = self.sftp.read_file(&sftp, &record.remote_backup).await?;
        if sha256_hex(&backup) != record.old_sha256 {
            return Err(CoreError::validation(
                "middleware restore precondition",
                "remote backup changed after the recorded operation",
            ));
        }
        let bundle = self.load_configuration(session, &instance).await?;
        let file_index = bundle
            .files
            .iter()
            .position(|file| file.path == record.path)
            .ok_or_else(|| {
                CoreError::validation(
                    "middleware restore graph",
                    "recorded configuration file is no longer part of the captured instance graph",
                )
            })?;
        if bundle.files[file_index].sha256 != record.new_sha256 {
            return Err(CoreError::validation(
                "middleware restore precondition",
                "current configuration changed after the recorded operation",
            ));
        }
        let draft = MiddlewareDraft::restore_replacement(&bundle.files[file_index], backup)?;
        self.plan_change(session, &bundle, file_index, draft).await
    }
}

struct MiddlewareChangeExecutor {
    ssh: SshService,
    sftp: SftpService,
    target: Arc<TargetContext>,
    session: BoundSshSession,
    sftp_session: BoundSftpSession,
    instance: MiddlewareInstance,
    graph_manifest: Vec<MiddlewareGraphEntry>,
    post_graph_manifest: Vec<MiddlewareGraphEntry>,
    directory_manifests: Vec<MiddlewareDirectoryManifest>,
    backup: SftpAtomicBackup,
    failure_state: AtomicU8,
    inner: Mutex<SftpPlannedOperation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MiddlewareGraphEntry {
    path: RemotePath,
    sha256: String,
    bytes: usize,
}

impl fmt::Debug for MiddlewareChangeExecutor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MiddlewareChangeExecutor")
            .field("target", self.session.target())
            .field("instance_id", &self.instance.id)
            .field("product", &self.instance.product)
            .field("unit", &self.instance.unit)
            .field("graph_files", &self.graph_manifest.len())
            .field("graph_directories", &self.directory_manifests.len())
            .field("backup", &self.backup)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl OperationExecutor for MiddlewareChangeExecutor {
    async fn execute(&self, plan: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        validate_executor_binding(plan, &self.session, &self.instance)?;
        ensure_apache_execution_evidence(&self.instance)?;
        self.target.validate(self.session.target())?;
        verify_runtime_identity(&self.target, &self.ssh, &self.session, &self.instance).await?;
        self.verify_graph_manifest().await?;
        let mut inner = self.inner.lock().await;
        let confirmation = DangerousConfirmation::approve(inner.definition());
        inner.confirm(confirmation)?;
        let write_result = inner.execute_and_verify().await;
        let write_error = match write_result {
            Ok(verification) if verification.passed => None,
            Ok(verification) => Some(verification.detail),
            Err(error) => Some(error.to_string()),
        };
        if let Some(write_error) = write_error {
            let can_restore = matches!(
                inner.state(),
                OperationState::Executed
                    | OperationState::StaleAfterExecution
                    | OperationState::Journaled
                    | OperationState::Verified
                    | OperationState::VerificationFailed
            );
            if can_restore {
                match inner.restore().await {
                    Ok(()) => self.failure_state.store(1, Ordering::Release),
                    Err(_) if inner.state() == OperationState::Restored => {
                        self.failure_state.store(1, Ordering::Release)
                    }
                    Err(restore_error) => {
                        self.failure_state.store(2, Ordering::Release);
                        return Err(CoreError::validation(
                            "middleware CAS automatic restore",
                            format!(
                                "atomic write verification failed: {write_error}; restore failed: {restore_error}"
                            ),
                        ));
                    }
                }
            }
            return Err(CoreError::validation(
                "middleware CAS write",
                if can_restore {
                    format!(
                        "atomic write verification failed and original bytes were restored: {write_error}"
                    )
                } else {
                    format!(
                        "atomic write failed before a restorable receipt was available: {write_error}"
                    )
                },
            ));
        }
        self.target.validate(self.session.target())?;
        Ok(ExecutionReceipt {
            summary: format!(
                "atomically replaced configuration for {} with matching original SHA-256",
                self.instance.unit
            ),
            restore_token: Some(plan.id.clone()),
        })
    }

    async fn verify(
        &self,
        plan: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        validate_executor_binding(plan, &self.session, &self.instance)?;
        self.target.validate(self.session.target())?;
        verify_runtime_identity(&self.target, &self.ssh, &self.session, &self.instance).await?;
        self.verify_post_graph_manifest().await?;
        run_native_validator(&self.target, &self.ssh, &self.session, &self.instance).await?;
        self.verify_post_graph_manifest().await?;
        verify_runtime_identity(&self.target, &self.ssh, &self.session, &self.instance).await?;
        activate_instance(&self.target, &self.ssh, &self.session, &self.instance).await?;
        verify_instance_health(&self.target, &self.ssh, &self.session, &self.instance).await?;
        verify_runtime_identity(&self.target, &self.ssh, &self.session, &self.instance).await?;
        self.verify_post_graph_manifest().await?;
        self.target.validate(self.session.target())?;
        Ok(VerificationResult {
            passed: true,
            detail: format!(
                "{} passed {}, {}, and systemd health readback",
                self.instance.unit,
                self.instance.validator.label(),
                self.instance.activation.label()
            ),
        })
    }

    async fn restore(&self, plan: &OperationPlan, _receipt: &ExecutionReceipt) -> CoreResult<()> {
        validate_executor_binding(plan, &self.session, &self.instance)?;
        self.target.validate(self.session.target())?;
        verify_runtime_identity(&self.target, &self.ssh, &self.session, &self.instance).await?;
        self.verify_post_graph_manifest().await?;
        let mut inner = self.inner.lock().await;
        inner.restore().await?;
        self.verify_graph_manifest().await?;
        run_native_validator(&self.target, &self.ssh, &self.session, &self.instance).await?;
        verify_runtime_identity(&self.target, &self.ssh, &self.session, &self.instance).await?;
        activate_instance(&self.target, &self.ssh, &self.session, &self.instance).await?;
        verify_instance_health(&self.target, &self.ssh, &self.session, &self.instance).await?;
        verify_runtime_identity(&self.target, &self.ssh, &self.session, &self.instance).await?;
        self.verify_graph_manifest().await?;
        self.target.validate(self.session.target())
    }
}

impl MiddlewareChangeExecutor {
    async fn verify_graph_manifest(&self) -> CoreResult<()> {
        self.verify_configuration_root().await?;
        self.verify_manifest(&self.graph_manifest).await?;
        self.verify_directory_manifests().await
    }

    async fn verify_post_graph_manifest(&self) -> CoreResult<()> {
        self.verify_configuration_root().await?;
        self.verify_manifest(&self.post_graph_manifest).await?;
        self.verify_directory_manifests().await
    }

    async fn verify_configuration_root(&self) -> CoreResult<()> {
        self.target.validate(self.session.target())?;
        let canonical = self
            .sftp
            .canonicalize(&self.sftp_session, &self.instance.config_root)
            .await?;
        let metadata = self
            .sftp
            .metadata(&self.sftp_session, &self.instance.config_root, false)
            .await?;
        self.target.validate(self.session.target())?;
        if canonical != self.instance.config_root || metadata.kind != SftpFileKind::Directory {
            return Err(CoreError::validation(
                "middleware configuration root CAS",
                "configuration root canonical identity changed after capture",
            ));
        }
        Ok(())
    }

    async fn verify_manifest(&self, manifest: &[MiddlewareGraphEntry]) -> CoreResult<()> {
        if manifest.is_empty() || manifest.len() > MAX_MIDDLEWARE_CONFIG_FILES {
            return Err(CoreError::validation(
                "middleware configuration graph CAS",
                "manifest is empty or oversized",
            ));
        }
        for entry in manifest {
            self.target.validate(self.session.target())?;
            let canonical = self
                .sftp
                .canonicalize(&self.sftp_session, &entry.path)
                .await?;
            self.target.validate(self.session.target())?;
            if canonical != entry.path {
                return Err(CoreError::validation(
                    "middleware configuration graph CAS",
                    "configuration path canonical identity changed after capture",
                ));
            }
            let bytes = self.sftp.read_file(&self.sftp_session, &entry.path).await?;
            self.target.validate(self.session.target())?;
            if bytes.len() != entry.bytes || sha256_hex(&bytes) != entry.sha256 {
                return Err(CoreError::validation(
                    "middleware configuration graph CAS",
                    format!(
                        "{} changed after the graph was captured",
                        entry.path.as_str()
                    ),
                ));
            }
        }
        Ok(())
    }

    async fn verify_directory_manifests(&self) -> CoreResult<()> {
        if self.directory_manifests.len() > MAX_MIDDLEWARE_CONFIG_FILES {
            return Err(CoreError::validation(
                "middleware configuration directory CAS",
                "directory manifest is oversized",
            ));
        }
        for expected in &self.directory_manifests {
            if !is_approved_config_path(&self.instance, &expected.path) {
                return Err(CoreError::validation(
                    "middleware configuration directory CAS",
                    "directory escaped the selected instance roots",
                ));
            }
            self.target.validate(self.session.target())?;
            let actual = capture_directory_manifest(
                &self.sftp,
                &self.sftp_session,
                &expected.path,
                expected.pattern.as_deref(),
                expected.activation_sensitive,
                expected.include_directories,
            )
            .await?;
            self.target.validate(self.session.target())?;
            if actual != *expected {
                return Err(CoreError::validation(
                    "middleware configuration directory CAS",
                    format!(
                        "{} membership changed after the graph was captured",
                        expected.path.as_str()
                    ),
                ));
            }
        }
        Ok(())
    }
}

fn catalog_for(product: MiddlewareProduct) -> &'static MiddlewareCatalogEntry {
    MIDDLEWARE_CATALOG
        .iter()
        .find(|entry| entry.product == product)
        .expect("every closed middleware product has one catalog entry")
}

/// Printed instead of a unit list when the host has no systemd at all.
///
/// Without this the missing `systemctl` came back as exit 127 with stderr
/// discarded, which reads as "the middleware investigation failed" on a host
/// where it never could have run. Reporting no instances would be worse still:
/// the services are there, they are just not systemd units.
const NO_SYSTEMD_MARKER: &str = "LR_MIDDLEWARE_NO_SYSTEMD";

fn middleware_unit_inventory_command() -> String {
    format!(
        "command -v systemctl >/dev/null 2>&1 || {{ printf '%s\\n' {NO_SYSTEMD_MARKER}; exit 0; }}; \
         LC_ALL=C systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null"
    )
}

fn product_probe_command(product: MiddlewareProduct, binary_path: &RemotePath) -> String {
    let binary = shq(binary_path.as_str());
    match product {
        MiddlewareProduct::Nginx | MiddlewareProduct::ApacheHttpd => {
            format!("{binary} -V 2>&1")
        }
        MiddlewareProduct::Redis => format!("{binary} --version 2>&1"),
        MiddlewareProduct::Tomcat => "printf '%s\n' 'Tomcat (systemd instance)'".to_owned(),
    }
}

fn discover_exec_path(exec_start: &str) -> CoreResult<RemotePath> {
    let value = extract_property_path(exec_start, "path=").ok_or_else(|| {
        CoreError::validation(
            "middleware systemd instance",
            "ExecStart did not expose one absolute executable path",
        )
    })?;
    let path = RemotePath::new(value)?;
    if path.as_str() == "/" {
        return Err(CoreError::validation(
            "middleware systemd instance",
            "ExecStart executable path cannot be the filesystem root",
        ));
    }
    Ok(path)
}

fn validate_product_executable(
    product: MiddlewareProduct,
    path: &RemotePath,
    exec_start: &str,
) -> CoreResult<()> {
    let file_name = path.file_name()?.to_ascii_lowercase();
    let basename_matches = product_executable_basename_matches(product, &file_name);
    let tomcat_marker_matches = product != MiddlewareProduct::Tomcat
        || ["catalina", "tomcat", "org.apache.catalina", "jsvc"]
            .iter()
            .any(|marker| exec_start.to_ascii_lowercase().contains(marker));
    if !basename_matches || !tomcat_marker_matches {
        return Err(CoreError::validation(
            "middleware systemd executable",
            "ExecStart executable is not in the closed product-specific executable set",
        ));
    }
    Ok(())
}

fn product_executable_basename_matches(product: MiddlewareProduct, file_name: &str) -> bool {
    match product {
        MiddlewareProduct::Nginx => file_name == "nginx",
        MiddlewareProduct::ApacheHttpd => {
            matches!(file_name, "apache2" | "apache2ctl" | "apachectl" | "httpd")
        }
        MiddlewareProduct::Redis => file_name == "redis-server",
        MiddlewareProduct::Tomcat => matches!(
            file_name,
            "java" | "jsvc" | "sh" | "bash" | "catalina.sh" | "startup.sh"
        ),
    }
}

fn parse_unit_inventory(output: &str) -> CoreResult<Vec<UnitCandidate>> {
    let mut candidates = Vec::new();
    let mut seen = BTreeSet::new();
    for (index, line) in output.lines().enumerate() {
        if index >= 4096 {
            return Err(CoreError::validation(
                "middleware unit inventory",
                "contains more than 4096 lines",
            ));
        }
        if line.len() > 2048 {
            return Err(CoreError::validation(
                "middleware unit inventory",
                "contains an oversized line",
            ));
        }
        let Some(unit) = line.split_ascii_whitespace().next() else {
            continue;
        };
        if !unit.ends_with(".service") || validate_systemd_unit(unit).is_err() {
            continue;
        }
        let stem = unit.trim_end_matches(".service").to_ascii_lowercase();
        let product = MIDDLEWARE_CATALOG.iter().find_map(|entry| {
            entry
                .service_prefixes
                .iter()
                .any(|prefix| {
                    stem == *prefix
                        || stem.starts_with(&format!("{prefix}@"))
                        || stem.starts_with(&format!("{prefix}-"))
                        || stem
                            .strip_prefix(prefix)
                            .and_then(|suffix| suffix.as_bytes().first().copied())
                            .is_some_and(|byte| byte.is_ascii_digit())
                })
                .then_some(entry.product)
        });
        if let Some(product) = product
            && seen.insert(unit.to_owned())
        {
            candidates.push(UnitCandidate {
                product,
                unit: unit.to_owned(),
            });
        }
    }
    Ok(candidates)
}

fn validate_systemd_unit(unit: &str) -> CoreResult<()> {
    if unit.is_empty()
        || unit.len() > 256
        || !unit.ends_with(".service")
        || !unit.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'@' | b'_' | b'.' | b':' | b'-')
        })
    {
        return Err(CoreError::validation(
            "middleware systemd unit",
            "must be a bounded service unit containing only systemd identifier characters",
        ));
    }
    Ok(())
}

fn parse_key_value_lines(output: &str, maximum: usize) -> CoreResult<BTreeMap<String, String>> {
    let mut values = BTreeMap::new();
    for (index, line) in output.lines().enumerate() {
        if index >= maximum {
            return Err(CoreError::validation(
                "middleware unit details",
                format!("contains more than {maximum} fields"),
            ));
        }
        if line.len() > 64 * 1024 {
            return Err(CoreError::validation(
                "middleware unit details",
                "contains an oversized field",
            ));
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.is_empty() || key.len() > 64 || !key.bytes().all(|byte| byte.is_ascii_alphanumeric())
        {
            continue;
        }
        values.insert(key.to_owned(), value.to_owned());
    }
    Ok(values)
}

fn discover_config_path(
    product: MiddlewareProduct,
    exec_start: &str,
    environment: &str,
    probe: &str,
) -> CoreResult<(RemotePath, RemotePath)> {
    let catalog = catalog_for(product);
    let fallback = || RemotePath::new(catalog.fallback_config_paths[0]);
    match product {
        MiddlewareProduct::Nginx => {
            let prefix = extract_long_option(probe, "--prefix=")
                .and_then(|value| RemotePath::new(value).ok());
            let config = extract_long_option(probe, "--conf-path=")
                .and_then(|value| resolve_discovered_path(prefix.as_ref(), value).ok())
                .or_else(|| {
                    extract_absolute_config_path(exec_start, &[".conf"])
                        .and_then(|value| RemotePath::new(value).ok())
                })
                .map(Ok)
                .unwrap_or_else(fallback)?;
            let root = prefix.unwrap_or(config.parent()?);
            Ok((config, root))
        }
        MiddlewareProduct::ApacheHttpd => {
            let root = extract_build_define(probe, "HTTPD_ROOT")
                .and_then(|value| RemotePath::new(value).ok());
            let config_name = extract_build_define(probe, "SERVER_CONFIG_FILE");
            let config = config_name
                .as_deref()
                .and_then(|value| resolve_discovered_path(root.as_ref(), value).ok())
                .or_else(|| {
                    extract_absolute_config_path(exec_start, &[".conf"])
                        .and_then(|value| RemotePath::new(value).ok())
                })
                .map(Ok)
                .unwrap_or_else(fallback)?;
            let root = root.unwrap_or(config.parent()?);
            Ok((config, root))
        }
        MiddlewareProduct::Redis => {
            let config = extract_absolute_config_path(exec_start, &[".conf"])
                .and_then(|value| RemotePath::new(value).ok())
                .map(Ok)
                .unwrap_or_else(fallback)?;
            let root = config.parent()?;
            Ok((config, root))
        }
        MiddlewareProduct::Tomcat => {
            let base = extract_environment_path(environment, "CATALINA_BASE")
                .or_else(|| extract_property_path(exec_start, "-Dcatalina.base="))
                .and_then(|value| RemotePath::new(value).ok());
            let config = if let Some(base) = &base {
                remote_join(base, "conf/server.xml")?
            } else {
                fallback()?
            };
            let root = if let Some(base) = base {
                remote_join(&base, "conf")?
            } else {
                config.parent()?
            };
            Ok((config, root))
        }
    }
}

fn apache_scope_is_target_reported(
    product: MiddlewareProduct,
    exec_start: &str,
    probe: &str,
    primary: &RemotePath,
    root: &RemotePath,
) -> bool {
    if product != MiddlewareProduct::ApacheHttpd {
        return false;
    }
    let Some(reported_root) =
        extract_build_define(probe, "HTTPD_ROOT").and_then(|value| RemotePath::new(value).ok())
    else {
        return false;
    };
    if &reported_root != root {
        return false;
    }
    let reported_config = extract_build_define(probe, "SERVER_CONFIG_FILE")
        .and_then(|value| resolve_discovered_path(Some(&reported_root), &value).ok())
        .or_else(|| {
            extract_absolute_config_path(exec_start, &[".conf"])
                .and_then(|value| RemotePath::new(value).ok())
        });
    reported_config.as_ref() == Some(primary)
}

fn extract_long_option<'a>(text: &'a str, option: &str) -> Option<&'a str> {
    text.split_ascii_whitespace().find_map(|token| {
        token
            .strip_prefix(option)
            .map(|value| value.trim_matches(['\'', '"']))
            .filter(|value| !value.is_empty() && value.len() <= 4096)
    })
}

fn extract_build_define(text: &str, name: &str) -> Option<String> {
    let needle = format!("-D {name}=");
    let start = text.find(&needle)? + needle.len();
    let value = text[start..].lines().next()?.trim();
    let value = value.trim_matches(['\'', '"']);
    (!value.is_empty() && value.len() <= 4096).then(|| value.to_owned())
}

fn extract_environment_path(environment: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=");
    environment.split_ascii_whitespace().find_map(|token| {
        token
            .trim_matches(['\'', '"'])
            .strip_prefix(&needle)
            .map(|value| value.trim_matches(['\'', '"']))
            .filter(|value| value.starts_with('/') && value.len() <= 4096)
            .map(str::to_owned)
    })
}

fn extract_property_path(text: &str, prefix: &str) -> Option<String> {
    text.split_ascii_whitespace().find_map(|token| {
        token
            .trim_matches(['\'', '"'])
            .strip_prefix(prefix)
            .map(|value| value.trim_matches(['\'', '"']))
            .filter(|value| value.starts_with('/') && value.len() <= 4096)
            .map(str::to_owned)
    })
}

fn extract_absolute_config_path(text: &str, suffixes: &[&str]) -> Option<String> {
    text.split(|character: char| {
        character.is_ascii_whitespace()
            || matches!(character, ';' | '{' | '}' | '[' | ']' | '"' | '\'')
    })
    .find(|token| {
        token.starts_with('/')
            && token.len() <= 4096
            && suffixes.iter().any(|suffix| token.ends_with(suffix))
    })
    .map(str::to_owned)
}

fn resolve_discovered_path(root: Option<&RemotePath>, value: &str) -> CoreResult<RemotePath> {
    if value.starts_with('/') {
        RemotePath::new(value)
    } else if let Some(root) = root {
        remote_join(root, value)
    } else {
        Err(CoreError::validation(
            "middleware configuration path",
            "relative path has no validated product root",
        ))
    }
}

fn parse_product_version(product: MiddlewareProduct, output: &str) -> String {
    let line = output
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("unknown")
        .trim();
    let mut end = line.len().min(256);
    while !line.is_char_boundary(end) {
        end -= 1;
    }
    let bounded = &line[..end];
    if bounded.is_empty() {
        format!("{} (version unavailable)", product.label())
    } else {
        bounded.to_owned()
    }
}

fn middleware_instance_id(product: MiddlewareProduct, unit: &str, path: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(format!("{product:?}\0{unit}\0{path}").as_bytes());
    format!("{:x}", digest.finalize())
}

fn runtime_fingerprint(
    unit: &str,
    fragment_path: &RemotePath,
    exec_start: &str,
    environment: &str,
    environment_files: &str,
) -> String {
    let mut digest = Sha256::new();
    digest.update(unit.as_bytes());
    digest.update([0]);
    digest.update(fragment_path.as_str().as_bytes());
    digest.update([0]);
    digest.update(exec_start.as_bytes());
    digest.update([0]);
    digest.update(environment.as_bytes());
    digest.update([0]);
    digest.update(environment_files.as_bytes());
    format!("{:x}", digest.finalize())
}

fn validate_instance(instance: &MiddlewareInstance) -> CoreResult<()> {
    validate_systemd_unit(&instance.unit)?;
    if instance.discovered_config_root {
        validate_discovered_apache_scope(
            instance.product,
            &instance.primary_config,
            &instance.config_root,
        )?;
    } else {
        validate_config_scope(
            instance.product,
            &instance.primary_config,
            &instance.config_root,
        )?;
    }
    if !product_executable_basename_matches(
        instance.product,
        &instance.binary_path.file_name()?.to_ascii_lowercase(),
    ) {
        return Err(CoreError::validation(
            "middleware instance",
            "captured executable is not valid for the selected product",
        ));
    }
    if instance.id
        != middleware_instance_id(
            instance.product,
            &instance.unit,
            instance.primary_config.as_str(),
        )
        || instance.id.len() != 64
        || instance.target.generation == 0
        || instance.binary_path.as_str() == "/"
        || instance.fragment_path.as_str() == "/"
        || instance.runtime_fingerprint.len() != 64
        || instance.primary_config.as_str() == "/"
        || instance.config_root.as_str() == "/"
        || instance.validator != instance.product.validator()
        || instance.activation != instance.product.activation()
        || (instance.product == MiddlewareProduct::ApacheHttpd)
            != instance.apache_invocation_evidence.is_some()
    {
        return Err(CoreError::validation(
            "middleware instance",
            "instance identity or closed product policy is invalid",
        ));
    }
    Ok(())
}

fn ensure_apache_plan_evidence(instance: &MiddlewareInstance) -> CoreResult<()> {
    ensure_apache_mutation_evidence(instance, "Apache remote change plan")
}

fn ensure_apache_execution_evidence(instance: &MiddlewareInstance) -> CoreResult<()> {
    ensure_apache_mutation_evidence(instance, "Apache remote change execution")
}

fn ensure_apache_mutation_evidence(
    instance: &MiddlewareInstance,
    subject: &'static str,
) -> CoreResult<()> {
    if instance.product != MiddlewareProduct::ApacheHttpd {
        return Ok(());
    }
    let _state = instance
        .apache_invocation_evidence
        .as_ref()
        .ok_or_else(|| CoreError::validation(subject, "typed evidence state is missing"))?;
    // Phase A defines the evidence and endpoint-seal contracts but deliberately
    // has no transport provider. Never fall back to the legacy systemd-string
    // fingerprint or replay attacker-controlled startup arguments through a shell.
    Err(CoreError::validation(
        subject,
        "exact runtime invocation and matching stable graph evidence are unavailable; Apache remote changes remain disabled",
    ))
}

fn enqueue_tomcat_known_files(
    instance: &MiddlewareInstance,
    queue: &mut VecDeque<PendingConfigPath>,
) -> CoreResult<()> {
    queue.push_back(PendingConfigPath {
        path: instance.config_root.clone(),
        role: MiddlewareConfigRole::Other,
        depth: 0,
        optional: false,
        ancestors: Vec::new(),
    });
    Ok(())
}

fn enqueue_include_path(
    queue: &mut VecDeque<PendingConfigPath>,
    pending: &PendingConfigPath,
    include: &MiddlewareIncludeReference,
    path: &RemotePath,
) -> CoreResult<()> {
    if path == &pending.path || pending.ancestors.contains(path) {
        return Err(CoreError::validation(
            "middleware include cycle",
            format!("{} closes an include cycle", path.as_str()),
        ));
    }
    if queue.len() >= MAX_MIDDLEWARE_CONFIG_FILES * 2 {
        return Err(CoreError::validation(
            "middleware configuration graph",
            "include expansion exceeded the bounded queue",
        ));
    }
    let mut ancestors = pending.ancestors.clone();
    ancestors.push(pending.path.clone());
    queue.push_back(PendingConfigPath {
        path: path.clone(),
        role: MiddlewareConfigRole::Included,
        depth: pending.depth + 1,
        optional: include.optional,
        ancestors,
    });
    Ok(())
}

fn validate_directory_manifest_limits(manifests: &[MiddlewareDirectoryManifest]) -> CoreResult<()> {
    if manifests.len() > MAX_MIDDLEWARE_CONFIG_FILES {
        return Err(CoreError::validation(
            "middleware configuration directories",
            "directory manifest count exceeded the bounded graph",
        ));
    }
    let entries = manifests.iter().try_fold(0usize, |total, manifest| {
        total.checked_add(manifest.entries.len())
    });
    if entries.is_none_or(|entries| entries > MAX_MIDDLEWARE_DIRECTORY_ENTRIES) {
        return Err(CoreError::validation(
            "middleware configuration directories",
            format!("directory membership exceeds {MAX_MIDDLEWARE_DIRECTORY_ENTRIES} entries"),
        ));
    }
    Ok(())
}

async fn enqueue_directory_files(
    service: &SftpService,
    session: &BoundSftpSession,
    pending: &PendingConfigPath,
    queue: &mut VecDeque<PendingConfigPath>,
    visited: &BTreeSet<RemotePath>,
) -> CoreResult<MiddlewareDirectoryManifest> {
    if pending.depth >= MAX_MIDDLEWARE_INCLUDE_DEPTH {
        return Err(CoreError::validation(
            "middleware configuration directory",
            format!("directory depth exceeds {MAX_MIDDLEWARE_INCLUDE_DEPTH}"),
        ));
    }
    let manifest = capture_directory_manifest(
        service,
        session,
        &pending.path,
        None,
        pending.role == MiddlewareConfigRole::Included,
        true,
    )
    .await?;
    for entry in &manifest.entries {
        if pending.role == MiddlewareConfigRole::Included
            && (entry.path == pending.path || pending.ancestors.contains(&entry.path))
        {
            return Err(CoreError::validation(
                "middleware include cycle",
                format!(
                    "{} closes a recursive directory include",
                    entry.path.as_str()
                ),
            ));
        }
        if visited.contains(&entry.path) {
            continue;
        }
        match entry.kind {
            SftpFileKind::Directory => queue.push_back(PendingConfigPath {
                path: entry.path.clone(),
                role: pending.role,
                depth: pending.depth + 1,
                optional: pending.optional,
                ancestors: {
                    let mut ancestors = pending.ancestors.clone();
                    ancestors.push(pending.path.clone());
                    ancestors
                },
            }),
            SftpFileKind::File => queue.push_back(PendingConfigPath {
                role: role_for_path(&entry.path, pending.role),
                path: entry.path.clone(),
                depth: pending.depth + 1,
                optional: pending.optional,
                ancestors: {
                    let mut ancestors = pending.ancestors.clone();
                    ancestors.push(pending.path.clone());
                    ancestors
                },
            }),
            SftpFileKind::Symlink | SftpFileKind::Other => {}
        }
        if queue.len() > MAX_MIDDLEWARE_CONFIG_FILES * 2 {
            return Err(CoreError::validation(
                "middleware configuration directory",
                "directory traversal exceeded the bounded queue",
            ));
        }
    }
    Ok(manifest)
}

async fn capture_directory_manifest(
    service: &SftpService,
    session: &BoundSftpSession,
    path: &RemotePath,
    pattern: Option<&str>,
    activation_sensitive: bool,
    include_directories: bool,
) -> CoreResult<MiddlewareDirectoryManifest> {
    let canonical = service.canonicalize(session, path).await?;
    if canonical != *path {
        return Err(CoreError::validation(
            "middleware configuration directory",
            "directory canonical path differs from the captured path",
        ));
    }
    let compiled_pattern = pattern.map(compile_glob_component).transpose()?;
    let mut entries = service
        .list(session, path)
        .await?
        .into_iter()
        .map(|entry| {
            if !entry.path.parent().is_ok_and(|parent| &parent == path)
                || entry.path.file_name().ok() != Some(entry.name.as_str())
            {
                return Err(CoreError::validation(
                    "middleware configuration directory",
                    "directory listing returned a path outside its exact parent",
                ));
            }
            Ok(entry)
        })
        .collect::<CoreResult<Vec<_>>>()?
        .into_iter()
        .filter(|entry| entry.name != ".lovelyres-backups")
        .filter(|entry| {
            compiled_pattern
                .as_ref()
                .is_none_or(|pattern| pattern.matches(&entry.name))
        })
        .map(|entry| MiddlewareDirectoryEntry {
            path: entry.path,
            kind: entry.metadata.kind,
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    if entries.len() > MAX_MIDDLEWARE_CONFIG_FILES * 2 {
        return Err(CoreError::validation(
            "middleware configuration directory",
            "directory membership exceeds the bounded graph",
        ));
    }
    validate_activation_directory_entries(
        activation_sensitive,
        pattern,
        include_directories,
        &entries,
    )?;
    Ok(MiddlewareDirectoryManifest {
        path: path.clone(),
        pattern: pattern.map(str::to_owned),
        activation_sensitive,
        include_directories,
        entries,
    })
}

fn validate_activation_directory_entries(
    activation_sensitive: bool,
    pattern: Option<&str>,
    include_directories: bool,
    entries: &[MiddlewareDirectoryEntry],
) -> CoreResult<()> {
    if !activation_sensitive {
        return Ok(());
    }
    let unsupported = entries.iter().any(|entry| match (pattern, entry.kind) {
        (Some(_), SftpFileKind::File) => false,
        (Some(_), SftpFileKind::Directory) if include_directories => false,
        (Some(_), _) => true,
        (None, SftpFileKind::File | SftpFileKind::Directory) => false,
        (None, SftpFileKind::Symlink | SftpFileKind::Other) => true,
    });
    if unsupported {
        return Err(CoreError::validation(
            "middleware configuration directory",
            "activation-sensitive includes matched a symbolic link, special file, or unsupported directory",
        ));
    }
    Ok(())
}

fn manifest_would_activate_backup(
    manifest: &MiddlewareDirectoryManifest,
    backup_directory: &RemotePath,
) -> bool {
    if !manifest.activation_sensitive {
        return false;
    }
    match manifest.pattern.as_deref() {
        None => path_is_within(backup_directory, &manifest.path),
        Some(pattern) => {
            backup_directory
                .parent()
                .is_ok_and(|parent| parent == manifest.path)
                && backup_directory
                    .file_name()
                    .is_ok_and(|name| glob_file_name_matches(pattern, name))
        }
    }
}

fn syntax_for_path(product: MiddlewareProduct, path: &RemotePath) -> MiddlewareDocumentSyntax {
    if product == MiddlewareProduct::Tomcat {
        if path.as_str().ends_with(".xml") {
            MiddlewareDocumentSyntax::TomcatXml
        } else {
            MiddlewareDocumentSyntax::Apache
        }
    } else {
        product.document_syntax()
    }
}

fn role_for_path(path: &RemotePath, fallback: MiddlewareConfigRole) -> MiddlewareConfigRole {
    match path.file_name().unwrap_or_default() {
        "server.xml" => MiddlewareConfigRole::Primary,
        "web.xml" => MiddlewareConfigRole::TomcatWeb,
        "context.xml" => MiddlewareConfigRole::TomcatContext,
        "catalina.properties" => MiddlewareConfigRole::Properties,
        "logging.properties" => MiddlewareConfigRole::Logging,
        "tomcat-users.xml" => MiddlewareConfigRole::Users,
        _ => fallback,
    }
}

fn extract_include_references(
    instance: &MiddlewareInstance,
    source: &RemotePath,
    document: &MiddlewareDocument,
) -> CoreResult<Vec<MiddlewareIncludeReference>> {
    if instance.product == MiddlewareProduct::Tomcat {
        return Ok(Vec::new());
    }
    let mut references = Vec::new();
    for node in document.nodes() {
        if node.kind != MiddlewareDocumentNodeKind::Directive {
            continue;
        }
        let Some(name) = node.name.as_deref() else {
            continue;
        };
        if !is_include_directive(instance.product, name) {
            continue;
        }
        let optional = instance.product == MiddlewareProduct::ApacheHttpd
            && name.eq_ignore_ascii_case("includeoptional");
        let Some(span) = node.editable_value else {
            continue;
        };
        let raw = document
            .raw_bytes()
            .get(span.start()..span.end())
            .ok_or_else(|| CoreError::validation("middleware include", "value span is invalid"))?;
        let raw = std::str::from_utf8(raw)
            .map_err(|_| CoreError::validation("middleware include", "path must be UTF-8"))?
            .trim();
        let value = raw.trim_matches(['\'', '"']);
        if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
            references.push(MiddlewareIncludeReference {
                source: source.clone(),
                raw_value: raw.to_owned(),
                optional,
                resolved: Vec::new(),
                unresolved_reason: Some(
                    "include path is empty, oversized, or contains controls".to_owned(),
                ),
            });
            continue;
        }
        if value.contains('$') {
            references.push(MiddlewareIncludeReference {
                source: source.clone(),
                raw_value: value.to_owned(),
                optional,
                resolved: Vec::new(),
                unresolved_reason: Some(
                    "variable include requires native product expansion".to_owned(),
                ),
            });
            continue;
        }
        let glob = value.contains(['*', '?', '[', ']']);
        let (resolved, unresolved_reason) = if glob {
            match validate_glob_include_pattern(instance, source, value) {
                Ok(()) => (
                    Vec::new(),
                    Some("glob include pending bounded directory expansion".to_owned()),
                ),
                Err(error) => (
                    Vec::new(),
                    Some(format!("glob include is unsupported or unsafe: {error}")),
                ),
            }
        } else {
            match resolve_include_path(instance, source, value) {
                Ok(path) => (vec![path], None),
                Err(error) => (Vec::new(), Some(error.to_string())),
            }
        };
        references.push(MiddlewareIncludeReference {
            source: source.clone(),
            raw_value: value.to_owned(),
            optional,
            resolved,
            unresolved_reason,
        });
    }
    Ok(references)
}

fn include_directive_signature(
    product: MiddlewareProduct,
    document: &MiddlewareDocument,
) -> CoreResult<Vec<(String, String)>> {
    let mut signature = Vec::new();
    for node in document.nodes() {
        if node.kind != MiddlewareDocumentNodeKind::Directive {
            continue;
        }
        let Some(name) = node.name.as_deref() else {
            continue;
        };
        if !is_include_directive(product, name) {
            continue;
        }
        let span = node.editable_value.ok_or_else(|| {
            CoreError::validation(
                "middleware include topology",
                "include directive has no exact editable value span",
            )
        })?;
        let raw = document
            .raw_bytes()
            .get(span.start()..span.end())
            .ok_or_else(|| {
                CoreError::validation(
                    "middleware include topology",
                    "include directive value span is invalid",
                )
            })?;
        let value = std::str::from_utf8(raw)
            .map_err(|_| {
                CoreError::validation(
                    "middleware include topology",
                    "include directive value must be UTF-8",
                )
            })?
            .trim()
            .trim_matches(['\'', '"'])
            .to_owned();
        signature.push((name.to_ascii_lowercase(), value));
    }
    Ok(signature)
}

fn is_include_directive(product: MiddlewareProduct, name: &str) -> bool {
    match product {
        MiddlewareProduct::Nginx | MiddlewareProduct::Redis => name.eq_ignore_ascii_case("include"),
        MiddlewareProduct::ApacheHttpd => {
            name.eq_ignore_ascii_case("include") || name.eq_ignore_ascii_case("includeoptional")
        }
        MiddlewareProduct::Tomcat => false,
    }
}

fn resolve_include_path(
    instance: &MiddlewareInstance,
    source: &RemotePath,
    value: &str,
) -> CoreResult<RemotePath> {
    let path = if value.starts_with('/') {
        RemotePath::new(value)?
    } else {
        let base = match instance.product {
            MiddlewareProduct::Nginx | MiddlewareProduct::ApacheHttpd => &instance.config_root,
            MiddlewareProduct::Redis => &source.parent()?,
            MiddlewareProduct::Tomcat => &instance.config_root,
        };
        remote_join(base, value)?
    };
    if !is_approved_config_path(instance, &path) {
        return Err(CoreError::validation(
            "middleware include path",
            "absolute include is outside the discovered instance configuration roots",
        ));
    }
    Ok(path)
}

async fn expand_wildcard_include(
    service: &SftpService,
    session: &BoundSftpSession,
    instance: &MiddlewareInstance,
    reference: &mut MiddlewareIncludeReference,
) -> CoreResult<Vec<MiddlewareDirectoryManifest>> {
    let (mut base, components) = include_pattern_base_and_components(
        instance,
        &reference.source,
        reference.raw_value.as_str(),
    )?;
    let first_glob = components
        .iter()
        .position(|component| component.contains(['*', '?', '[', ']']))
        .ok_or_else(|| {
            CoreError::validation("middleware glob include", "path contains no supported glob")
        })?;
    for component in &components[..first_glob] {
        base = base.child(component)?;
    }
    let mut candidates = vec![base];
    let mut manifests = Vec::new();

    for (index, component) in components[first_glob..].iter().enumerate() {
        let final_component = first_glob + index + 1 == components.len();
        let is_glob = component.contains(['*', '?', '[', ']']);
        let mut next = Vec::new();
        if is_glob {
            compile_glob_component(component)?;
            for parent in &candidates {
                match checked_remote_kind(service, session, instance, parent).await? {
                    Some(SftpFileKind::Directory) => {}
                    Some(SftpFileKind::File) => {
                        if reference.optional {
                            manifests.push(
                                capture_optional_path_guard(
                                    service, session, instance, parent, false,
                                )
                                .await?,
                            );
                            validate_directory_manifest_limits(&manifests)?;
                        }
                        continue;
                    }
                    None => {
                        if reference.optional {
                            manifests.push(
                                capture_optional_path_guard(
                                    service, session, instance, parent, true,
                                )
                                .await?,
                            );
                            validate_directory_manifest_limits(&manifests)?;
                        }
                        continue;
                    }
                    Some(SftpFileKind::Symlink | SftpFileKind::Other) => {
                        return Err(CoreError::validation(
                            "middleware glob include",
                            "glob traversal encountered a symbolic link or special file",
                        ));
                    }
                }
                let include_directories =
                    !final_component || instance.product == MiddlewareProduct::ApacheHttpd;
                let manifest = capture_directory_manifest(
                    service,
                    session,
                    parent,
                    Some(component),
                    true,
                    include_directories,
                )
                .await?;
                for entry in &manifest.entries {
                    if final_component {
                        match entry.kind {
                            SftpFileKind::File => next.push(entry.path.clone()),
                            SftpFileKind::Directory if include_directories => {
                                next.push(entry.path.clone())
                            }
                            SftpFileKind::Directory
                            | SftpFileKind::Symlink
                            | SftpFileKind::Other => {
                                return Err(CoreError::validation(
                                    "middleware glob include",
                                    "glob matched an unsupported directory, symbolic link, or special file",
                                ));
                            }
                        }
                    } else if entry.kind == SftpFileKind::Directory {
                        next.push(entry.path.clone());
                    }
                }
                manifests.push(manifest);
                validate_directory_manifest_limits(&manifests)?;
            }
        } else {
            for parent in &candidates {
                if checked_remote_kind(service, session, instance, parent).await?
                    != Some(SftpFileKind::Directory)
                {
                    return Err(CoreError::validation(
                        "middleware glob include",
                        "expanded parent stopped being one canonical directory",
                    ));
                }
                let include_directories =
                    !final_component || instance.product == MiddlewareProduct::ApacheHttpd;
                let manifest = capture_directory_manifest(
                    service,
                    session,
                    parent,
                    Some(component),
                    true,
                    include_directories,
                )
                .await?;
                for entry in &manifest.entries {
                    if final_component {
                        match entry.kind {
                            SftpFileKind::File => next.push(entry.path.clone()),
                            SftpFileKind::Directory if include_directories => {
                                next.push(entry.path.clone())
                            }
                            SftpFileKind::Directory
                            | SftpFileKind::Symlink
                            | SftpFileKind::Other => {
                                return Err(CoreError::validation(
                                    "middleware glob include",
                                    "literal segment matched an unsupported directory, symbolic link, or special file",
                                ));
                            }
                        }
                    } else if entry.kind == SftpFileKind::Directory {
                        next.push(entry.path.clone());
                    }
                }
                manifests.push(manifest);
                validate_directory_manifest_limits(&manifests)?;
            }
        }
        next.sort();
        next.dedup();
        if next.len() > MAX_MIDDLEWARE_CONFIG_FILES {
            return Err(CoreError::validation(
                "middleware glob include",
                format!("expands to more than {MAX_MIDDLEWARE_CONFIG_FILES} paths"),
            ));
        }
        candidates = next;
        if candidates.is_empty() {
            break;
        }
    }

    validate_include_match(reference.optional, &reference.raw_value, candidates.len())?;
    reference.resolved = candidates;
    reference.unresolved_reason = None;
    Ok(manifests)
}

fn validate_include_match(optional: bool, value: &str, matches: usize) -> CoreResult<()> {
    if matches == 0 && !optional {
        return Err(CoreError::validation(
            "middleware required include",
            format!("{value} matched no path"),
        ));
    }
    Ok(())
}

#[cfg(test)]
fn wildcard_parent_and_pattern<'a>(
    instance: &MiddlewareInstance,
    source: &RemotePath,
    value: &'a str,
) -> CoreResult<(RemotePath, &'a str)> {
    let (mut parent, components) = include_pattern_base_and_components(instance, source, value)?;
    let (pattern, parents) = components.split_last().ok_or_else(|| {
        CoreError::validation("middleware glob include", "path has no components")
    })?;
    if !pattern.contains(['*', '?', '[', ']'])
        || parents
            .iter()
            .any(|component| component.contains(['*', '?', '[', ']']))
    {
        return Err(CoreError::validation(
            "middleware glob include",
            "this helper requires one glob in the final path component",
        ));
    }
    for component in parents {
        parent = parent.child(component)?;
    }
    Ok((parent, pattern))
}

async fn checked_remote_kind(
    service: &SftpService,
    session: &BoundSftpSession,
    instance: &MiddlewareInstance,
    path: &RemotePath,
) -> CoreResult<Option<SftpFileKind>> {
    if !is_approved_config_path(instance, path) {
        return Err(CoreError::validation(
            "middleware include path",
            "path escaped the selected instance roots",
        ));
    }
    if !service.exists(session, path).await? {
        return Ok(None);
    }
    let canonical = service.canonicalize(session, path).await?;
    if canonical != *path {
        return Err(CoreError::validation(
            "middleware include path",
            "path contains a symbolic-link ancestor",
        ));
    }
    Ok(Some(service.metadata(session, path, false).await?.kind))
}

async fn capture_optional_path_guard(
    service: &SftpService,
    session: &BoundSftpSession,
    instance: &MiddlewareInstance,
    path: &RemotePath,
    expected_absent: bool,
) -> CoreResult<MiddlewareDirectoryManifest> {
    // An empty IncludeOptional is still graph state.  Capture the nearest
    // exact parent membership so a path cannot appear between preview and CAS.
    let mut guarded_child = path.clone();
    let mut guard_must_be_empty = expected_absent;
    for _ in 0..=MAX_MIDDLEWARE_INCLUDE_PATH_COMPONENTS {
        let parent = guarded_child.parent()?;
        if !is_approved_config_path(instance, &guarded_child)
            || !is_approved_config_path(instance, &parent)
        {
            return Err(CoreError::validation(
                "middleware optional include guard",
                "missing path escaped the selected instance roots",
            ));
        }
        match checked_remote_kind(service, session, instance, &parent).await? {
            Some(SftpFileKind::Directory) => {
                let name = guarded_child.file_name()?;
                let manifest = capture_directory_manifest(
                    service,
                    session,
                    &parent,
                    Some(name),
                    true,
                    instance.product == MiddlewareProduct::ApacheHttpd,
                )
                .await?;
                let membership_changed = if guard_must_be_empty {
                    !manifest.entries.is_empty()
                } else {
                    manifest.entries.len() != 1 || manifest.entries[0].path != guarded_child
                };
                if membership_changed {
                    return Err(CoreError::validation(
                        "middleware optional include guard",
                        "exact parent membership changed while the empty include was captured",
                    ));
                }
                return Ok(manifest);
            }
            Some(SftpFileKind::File) => {
                guarded_child = parent;
                guard_must_be_empty = false;
            }
            Some(SftpFileKind::Symlink | SftpFileKind::Other) => {
                return Err(CoreError::validation(
                    "middleware optional include guard",
                    "nearest existing ancestor is a symbolic link or special file",
                ));
            }
            None => guarded_child = parent,
        }
    }
    Err(CoreError::validation(
        "middleware optional include guard",
        format!("missing path exceeds {MAX_MIDDLEWARE_INCLUDE_PATH_COMPONENTS} guarded components"),
    ))
}

fn validate_glob_include_pattern(
    instance: &MiddlewareInstance,
    source: &RemotePath,
    value: &str,
) -> CoreResult<()> {
    let (mut prefix, components) = include_pattern_base_and_components(instance, source, value)?;
    let mut found_glob = false;
    for component in components {
        if component.contains(['*', '?', '[', ']']) {
            compile_glob_component(component)?;
            found_glob = true;
            break;
        }
        prefix = prefix.child(component)?;
    }
    if !found_glob {
        return Err(CoreError::validation(
            "middleware glob include",
            "path does not contain a supported glob",
        ));
    }
    if !is_approved_config_path(instance, &prefix) {
        return Err(CoreError::validation(
            "middleware glob include",
            "literal prefix before the first glob is outside the selected instance roots",
        ));
    }
    Ok(())
}

fn include_pattern_base_and_components<'a>(
    instance: &MiddlewareInstance,
    source: &RemotePath,
    value: &'a str,
) -> CoreResult<(RemotePath, Vec<&'a str>)> {
    if value.is_empty()
        || value.len() > 4096
        || value.contains('\\')
        || value.chars().any(char::is_control)
    {
        return Err(CoreError::validation(
            "middleware glob include",
            "path is empty, oversized, or contains backslashes or controls",
        ));
    }
    let (base, relative) = if let Some(relative) = value.strip_prefix('/') {
        (RemotePath::new("/")?, relative)
    } else {
        let base = match instance.product {
            MiddlewareProduct::Nginx | MiddlewareProduct::ApacheHttpd => {
                instance.config_root.clone()
            }
            MiddlewareProduct::Redis => source.parent()?,
            MiddlewareProduct::Tomcat => instance.config_root.clone(),
        };
        (base, value)
    };
    let components = relative.split('/').collect::<Vec<_>>();
    if components.is_empty()
        || components.len() > MAX_MIDDLEWARE_INCLUDE_PATH_COMPONENTS
        || components
            .iter()
            .any(|component| component.is_empty() || matches!(*component, "." | ".."))
    {
        return Err(CoreError::validation(
            "middleware glob include",
            "path is too deep or contains an empty, current-directory, or parent-directory component",
        ));
    }
    for component in &components {
        if component.contains(['*', '?', '[', ']']) {
            compile_glob_component(component)?;
        }
    }
    Ok((base, components))
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum GlobToken {
    Literal(u8),
    AnyByte,
    AnySequence,
    Class {
        negated: bool,
        ranges: Vec<(u8, u8)>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CompiledGlob {
    tokens: Vec<GlobToken>,
}

impl CompiledGlob {
    fn matches(&self, value: &str) -> bool {
        let value = value.as_bytes();
        let mut pattern_index = 0usize;
        let mut value_index = 0usize;
        let mut star = None;
        let mut star_value_index = 0usize;
        while value_index < value.len() {
            if self
                .tokens
                .get(pattern_index)
                .is_some_and(|token| glob_token_matches(token, value[value_index]))
            {
                pattern_index += 1;
                value_index += 1;
            } else if self.tokens.get(pattern_index) == Some(&GlobToken::AnySequence) {
                star = Some(pattern_index);
                pattern_index += 1;
                star_value_index = value_index;
            } else if let Some(star_index) = star {
                pattern_index = star_index + 1;
                star_value_index += 1;
                value_index = star_value_index;
            } else {
                return false;
            }
        }
        while self.tokens.get(pattern_index) == Some(&GlobToken::AnySequence) {
            pattern_index += 1;
        }
        pattern_index == self.tokens.len()
    }
}

fn glob_token_matches(token: &GlobToken, value: u8) -> bool {
    match token {
        GlobToken::Literal(expected) => *expected == value,
        GlobToken::AnyByte => true,
        GlobToken::AnySequence => false,
        GlobToken::Class { negated, ranges } => {
            let contained = ranges
                .iter()
                .any(|(start, end)| *start <= value && value <= *end);
            contained != *negated
        }
    }
}

fn compile_glob_component(pattern: &str) -> CoreResult<CompiledGlob> {
    // APR fnmatch accepts a wider grammar.  The graph loader deliberately
    // implements only deterministic component globs and simple ASCII classes;
    // escapes, POSIX classes, and malformed ranges stay visibly unresolved.
    if pattern.is_empty()
        || pattern.len() > 255
        || pattern.contains('/')
        || pattern.contains('\\')
        || pattern.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(CoreError::validation(
            "middleware glob component",
            "must be a bounded file-name component without slashes, escapes, or controls",
        ));
    }
    let bytes = pattern.as_bytes();
    let mut tokens = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'*' => {
                if tokens.last() != Some(&GlobToken::AnySequence) {
                    tokens.push(GlobToken::AnySequence);
                }
                index += 1;
            }
            b'?' => {
                tokens.push(GlobToken::AnyByte);
                index += 1;
            }
            b']' => {
                return Err(CoreError::validation(
                    "middleware glob component",
                    "contains an unmatched closing character class",
                ));
            }
            b'[' => {
                index += 1;
                let negated = bytes
                    .get(index)
                    .is_some_and(|byte| matches!(*byte, b'!' | b'^'));
                index += usize::from(negated);
                let mut ranges = Vec::new();
                while index < bytes.len() && bytes[index] != b']' {
                    let start = bytes[index];
                    if !start.is_ascii_graphic() || matches!(start, b'[' | b'\\' | b'*' | b'?') {
                        return Err(CoreError::validation(
                            "middleware glob component",
                            "character classes support only printable ASCII literals and ranges",
                        ));
                    }
                    index += 1;
                    if bytes.get(index) == Some(&b'-')
                        && bytes.get(index + 1).is_some_and(|byte| *byte != b']')
                    {
                        let end = bytes[index + 1];
                        if !end.is_ascii_graphic()
                            || matches!(end, b'[' | b'\\' | b'*' | b'?' | b'-')
                            || start > end
                        {
                            return Err(CoreError::validation(
                                "middleware glob component",
                                "character-class range is invalid or descending",
                            ));
                        }
                        ranges.push((start, end));
                        index += 2;
                    } else {
                        ranges.push((start, start));
                    }
                }
                if ranges.is_empty() || bytes.get(index) != Some(&b']') {
                    return Err(CoreError::validation(
                        "middleware glob component",
                        "character class is empty or unterminated",
                    ));
                }
                tokens.push(GlobToken::Class { negated, ranges });
                index += 1;
            }
            literal => {
                tokens.push(GlobToken::Literal(literal));
                index += 1;
            }
        }
    }
    Ok(CompiledGlob { tokens })
}

fn glob_file_name_matches(pattern: &str, value: &str) -> bool {
    compile_glob_component(pattern).is_ok_and(|pattern| pattern.matches(value))
}

fn remote_join(root: &RemotePath, relative: &str) -> CoreResult<RemotePath> {
    if relative.starts_with('/') {
        return RemotePath::new(relative);
    }
    let mut joined = root.clone();
    for component in relative.split('/') {
        if component.is_empty() || matches!(component, "." | "..") {
            return Err(CoreError::validation(
                "middleware relative path",
                "must contain only non-empty child components without traversal",
            ));
        }
        joined = joined.child(component)?;
    }
    Ok(joined)
}

fn validate_bundle_binding(
    session: &BoundSshSession,
    bundle: &MiddlewareConfigurationBundle,
) -> CoreResult<()> {
    if bundle.target != *session.target()
        || bundle.instance.target != *session.target()
        || bundle.files.is_empty()
        || bundle.files.len() > MAX_MIDDLEWARE_CONFIG_FILES
    {
        return Err(CoreError::validation(
            "middleware configuration bundle",
            "bundle is empty, oversized, or belongs to a different target generation",
        ));
    }
    if !bundle.unresolved_includes.is_empty() {
        return Err(CoreError::validation(
            "middleware configuration bundle",
            "all includes must resolve inside approved configuration roots before applying",
        ));
    }
    let directory_entry_count = bundle
        .directory_manifests
        .iter()
        .try_fold(0usize, |total, manifest| {
            total.checked_add(manifest.entries.len())
        })
        .ok_or_else(|| {
            CoreError::validation(
                "middleware configuration directory manifests",
                "directory entry accounting overflowed",
            )
        })?;
    if bundle.directory_manifests.len() > MAX_MIDDLEWARE_CONFIG_FILES
        || directory_entry_count > MAX_MIDDLEWARE_DIRECTORY_ENTRIES
        || bundle.directory_manifests.iter().any(|manifest| {
            !is_approved_config_path(&bundle.instance, &manifest.path)
                || manifest.entries.iter().any(|entry| {
                    !path_is_within(&entry.path, &manifest.path) || entry.path == manifest.path
                })
        })
    {
        return Err(CoreError::validation(
            "middleware configuration directory manifests",
            "directory manifests are oversized or outside the selected instance roots",
        ));
    }
    validate_instance(&bundle.instance)?;
    let mut total = 0usize;
    let mut paths = BTreeSet::new();
    let mut has_primary = false;
    for snapshot in &bundle.files {
        validate_snapshot_binding(&bundle.instance, snapshot)?;
        if !paths.insert(snapshot.path.clone()) {
            return Err(CoreError::validation(
                "middleware configuration bundle",
                "configuration graph contains duplicate paths",
            ));
        }
        has_primary |= snapshot.path == bundle.instance.primary_config;
        total = total.checked_add(snapshot.bytes.len()).ok_or_else(|| {
            CoreError::validation("middleware configuration bundle", "byte count overflow")
        })?;
        if total > MAX_MIDDLEWARE_TOTAL_BYTES {
            return Err(CoreError::validation(
                "middleware configuration bundle",
                "captured bytes exceed the aggregate limit",
            ));
        }
        let parsed =
            extract_include_references(&bundle.instance, &snapshot.path, &snapshot.document)?;
        let parsed_values = parsed
            .iter()
            .map(|reference| (&reference.source, &reference.raw_value, reference.optional))
            .collect::<Vec<_>>();
        let captured_values = snapshot
            .includes
            .iter()
            .map(|reference| (&reference.source, &reference.raw_value, reference.optional))
            .collect::<Vec<_>>();
        if parsed_values != captured_values
            || snapshot.includes.iter().any(|reference| {
                reference.unresolved_reason.is_some()
                    || reference
                        .resolved
                        .iter()
                        .any(|path| !is_approved_config_path(&bundle.instance, path))
            })
        {
            return Err(CoreError::validation(
                "middleware configuration bundle",
                "captured include graph does not match the lossless document",
            ));
        }
    }
    if !has_primary || total != bundle.total_bytes {
        return Err(CoreError::validation(
            "middleware configuration bundle",
            "primary file or aggregate byte binding is invalid",
        ));
    }
    Ok(())
}

fn validate_snapshot_binding(
    instance: &MiddlewareInstance,
    snapshot: &MiddlewareConfigSnapshot,
) -> CoreResult<()> {
    if snapshot.target != instance.target
        || snapshot.instance_id != instance.id
        || snapshot.product != instance.product
        || snapshot.sha256 != sha256_hex(&snapshot.bytes)
        || snapshot.document.raw_bytes() != snapshot.bytes.as_slice()
        || snapshot.metadata.kind != SftpFileKind::File
        || snapshot.metadata.size as usize != snapshot.bytes.len()
        || snapshot.document.syntax() != syntax_for_path(instance.product, &snapshot.path)
        || !is_approved_config_path(instance, &snapshot.path)
    {
        return Err(CoreError::validation(
            "middleware configuration snapshot",
            "snapshot does not match the selected immutable instance and captured bytes",
        ));
    }
    Ok(())
}

fn validate_config_scope(
    product: MiddlewareProduct,
    primary: &RemotePath,
    config_root: &RemotePath,
) -> CoreResult<()> {
    let catalog = catalog_for(product);
    let primary_is_fallback = catalog
        .fallback_config_paths
        .iter()
        .any(|candidate| *candidate == primary.as_str());
    let primary_in_root = catalog
        .approved_config_roots
        .iter()
        .filter_map(|root| RemotePath::new(*root).ok())
        .any(|root| path_is_within(primary, &root));
    let root_is_approved = catalog
        .approved_config_roots
        .iter()
        .filter_map(|root| RemotePath::new(*root).ok())
        .any(|root| path_is_within(config_root, &root));
    let exact_fallback_parent =
        primary_is_fallback && primary.parent().is_ok_and(|parent| &parent == config_root);
    if (!primary_is_fallback && !primary_in_root)
        || (!root_is_approved && !exact_fallback_parent)
        || config_root.as_str() == "/"
    {
        return Err(CoreError::validation(
            "middleware configuration scope",
            "primary configuration and root must stay inside the closed product catalog",
        ));
    }
    Ok(())
}

fn validate_discovered_apache_scope(
    product: MiddlewareProduct,
    primary: &RemotePath,
    config_root: &RemotePath,
) -> CoreResult<()> {
    if product != MiddlewareProduct::ApacheHttpd
        || primary.as_str() == "/"
        || config_root.as_str() == "/"
    {
        return Err(CoreError::validation(
            "middleware discovered Apache scope",
            "only an exact non-root Apache configuration and ServerRoot may use target discovery",
        ));
    }
    Ok(())
}

fn is_approved_config_path(instance: &MiddlewareInstance, path: &RemotePath) -> bool {
    if path == &instance.primary_config {
        return true;
    }
    if instance.discovered_config_root
        && instance.product == MiddlewareProduct::ApacheHttpd
        && path_is_within(path, &instance.config_root)
    {
        return true;
    }
    let catalog = catalog_for(instance.product);
    let config_root_is_approved = catalog
        .approved_config_roots
        .iter()
        .filter_map(|root| RemotePath::new(*root).ok())
        .any(|root| path_is_within(&instance.config_root, &root));
    let primary_parent = instance.primary_config.parent().ok();
    let primary_parent_is_approved = primary_parent.as_ref().is_some_and(|parent| {
        catalog
            .approved_config_roots
            .iter()
            .filter_map(|root| RemotePath::new(*root).ok())
            .any(|root| path_is_within(parent, &root))
    });
    (config_root_is_approved && path_is_within(path, &instance.config_root))
        || (primary_parent_is_approved
            && primary_parent.is_some_and(|parent| path_is_within(path, &parent)))
}

fn path_is_within(path: &RemotePath, root: &RemotePath) -> bool {
    if path == root {
        return true;
    }
    let prefix = if root.as_str() == "/" {
        "/".to_owned()
    } else {
        format!("{}/", root.as_str())
    };
    path.as_str().starts_with(&prefix)
}

fn validate_document_structure(
    product: MiddlewareProduct,
    document: &MiddlewareDocument,
) -> CoreResult<()> {
    if document.raw_bytes().is_empty() {
        return Err(CoreError::validation(
            "middleware configuration",
            "configuration file must not be empty",
        ));
    }
    if std::str::from_utf8(document.raw_bytes()).is_err() {
        return Err(CoreError::validation(
            "middleware configuration",
            "edited configuration must remain valid UTF-8; non-UTF-8 files are read-only",
        ));
    }
    let opaque = document
        .nodes()
        .iter()
        .filter(|node| node.kind == MiddlewareDocumentNodeKind::Opaque)
        .count();
    if opaque > 0 {
        return Err(CoreError::validation(
            "middleware configuration",
            format!(
                "contains {opaque} structurally opaque region(s); fix them in raw mode before applying"
            ),
        ));
    }
    if product == MiddlewareProduct::Tomcat
        && !document.nodes().iter().any(|node| {
            matches!(
                node.kind,
                MiddlewareDocumentNodeKind::ElementStart | MiddlewareDocumentNodeKind::ElementEnd
            )
        })
    {
        return Err(CoreError::validation(
            "Tomcat XML configuration",
            "must contain an XML document element",
        ));
    }
    Ok(())
}

fn validate_executor_binding(
    plan: &OperationPlan,
    session: &BoundSshSession,
    instance: &MiddlewareInstance,
) -> CoreResult<()> {
    validate_instance(instance)?;
    if &plan.target != session.target()
        || instance.target != *session.target()
        || plan.metadata.get("source").map(String::as_str) != Some("middleware")
        || plan.metadata.get("instance-id") != Some(&instance.id)
    {
        return Err(CoreError::validation(
            "middleware operation binding",
            "operation, target session, and middleware instance do not match",
        ));
    }
    Ok(())
}

async fn run_native_validator(
    target: &TargetContext,
    ssh: &SshService,
    session: &BoundSshSession,
    instance: &MiddlewareInstance,
) -> CoreResult<()> {
    let command = match instance.validator {
        MiddlewareValidator::NginxConfigTest => format!(
            "{} -t -p {} -c {}",
            shq(instance.binary_path.as_str()),
            shq(instance.config_root.as_str()),
            shq(instance.primary_config.as_str())
        ),
        MiddlewareValidator::ApacheConfigTest => format!(
            "{binary} -t -d {root} -f {config}",
            binary = shq(instance.binary_path.as_str()),
            root = shq(instance.config_root.as_str()),
            config = shq(instance.primary_config.as_str())
        ),
        MiddlewareValidator::StructuralOnly => return Ok(()),
    };
    target.validate(session.target())?;
    let output = ssh
        .execute_bound(session, command, Duration::from_secs(45))
        .await?;
    target.validate(session.target())?;
    ensure_command_succeeded("middleware native config test", &output)
}

async fn activate_instance(
    target: &TargetContext,
    ssh: &SshService,
    session: &BoundSshSession,
    instance: &MiddlewareInstance,
) -> CoreResult<()> {
    validate_systemd_unit(&instance.unit)?;
    let command = format!(
        "LC_ALL=C systemctl {} -- {}",
        instance.activation.systemctl_action(),
        shq(&instance.unit)
    );
    target.validate(session.target())?;
    let output = ssh
        .execute_bound(session, command, Duration::from_secs(90))
        .await?;
    target.validate(session.target())?;
    ensure_command_succeeded("middleware activation", &output)
}

async fn verify_instance_health(
    target: &TargetContext,
    ssh: &SshService,
    session: &BoundSshSession,
    instance: &MiddlewareInstance,
) -> CoreResult<()> {
    validate_systemd_unit(&instance.unit)?;
    let command = format!(
        "LC_ALL=C systemctl is-active --quiet -- {unit} && systemctl show --no-pager --property=ActiveState,SubState,MainPID -- {unit}",
        unit = shq(&instance.unit)
    );
    target.validate(session.target())?;
    let output = ssh
        .execute_bound(session, command, Duration::from_secs(30))
        .await?;
    target.validate(session.target())?;
    ensure_command_succeeded("middleware health readback", &output)?;
    let values = parse_key_value_lines(&output.output, 8)?;
    let main_pid = values
        .get("MainPID")
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);
    if values.get("ActiveState").map(String::as_str) != Some("active")
        || values.get("SubState").map(String::as_str) != Some("running")
        || main_pid == 0
    {
        return Err(CoreError::validation(
            "middleware health readback",
            "systemd unit is not active/running with a non-zero main process after activation",
        ));
    }
    Ok(())
}

async fn verify_runtime_identity(
    target: &TargetContext,
    ssh: &SshService,
    session: &BoundSshSession,
    instance: &MiddlewareInstance,
) -> CoreResult<()> {
    validate_systemd_unit(&instance.unit)?;
    let command = format!(
        "LC_ALL=C systemctl show --no-pager --property=Id,FragmentPath,ExecStart,Environment,EnvironmentFiles -- {} 2>/dev/null",
        shq(&instance.unit)
    );
    target.validate(session.target())?;
    let output = ssh
        .execute_bound(session, command, Duration::from_secs(15))
        .await?;
    target.validate(session.target())?;
    ensure_command_succeeded("middleware runtime identity", &output)?;
    let fields = parse_key_value_lines(&output.output, 8)?;
    let id = fields.get("Id").map(String::as_str).unwrap_or_default();
    let fragment = fields
        .get("FragmentPath")
        .and_then(|path| RemotePath::new(path.clone()).ok())
        .ok_or_else(|| {
            CoreError::validation(
                "middleware runtime identity",
                "unit no longer reports a valid FragmentPath",
            )
        })?;
    let exec_start = fields.get("ExecStart").map(String::as_str).unwrap_or("");
    let environment = fields.get("Environment").map(String::as_str).unwrap_or("");
    let environment_files = fields
        .get("EnvironmentFiles")
        .map(String::as_str)
        .unwrap_or("");
    let binary_path = discover_exec_path(exec_start)?;
    if id != instance.unit
        || binary_path != instance.binary_path
        || fragment != instance.fragment_path
        || runtime_fingerprint(
            &instance.unit,
            &fragment,
            exec_start,
            environment,
            environment_files,
        ) != instance.runtime_fingerprint
    {
        return Err(CoreError::validation(
            "middleware runtime identity",
            "systemd FragmentPath, ExecStart, or environment changed after discovery",
        ));
    }
    if instance.discovered_config_root {
        let output = ssh
            .execute_bound(
                session,
                product_probe_command(instance.product, &instance.binary_path),
                Duration::from_secs(15),
            )
            .await?;
        target.validate(session.target())?;
        ensure_command_succeeded("middleware discovered Apache ServerRoot", &output)?;
        if !apache_scope_is_target_reported(
            instance.product,
            exec_start,
            &output.output,
            &instance.primary_config,
            &instance.config_root,
        ) {
            return Err(CoreError::validation(
                "middleware discovered Apache ServerRoot",
                "httpd -V and systemd no longer report the exact captured configuration scope",
            ));
        }
    }
    Ok(())
}

fn ensure_command_succeeded(subject: &'static str, output: &SshCommandOutput) -> CoreResult<()> {
    if output.output.len() > MAX_DISCOVERY_OUTPUT_BYTES {
        return Err(CoreError::validation(
            subject,
            "remote output exceeds the bounded limit",
        ));
    }
    if output.timed_out || output.exit_code != Some(0) {
        return Err(CoreError::ssh(
            subject,
            format!(
                "remote command exited with {:?}; output is intentionally not persisted because middleware diagnostics may contain secrets",
                output.exit_code
            ),
        ));
    }
    Ok(())
}

fn document_contains_sensitive_values(
    product: MiddlewareProduct,
    document: &MiddlewareDocument,
) -> bool {
    text_contains_sensitive_marker(document.raw_bytes())
        || document
            .nodes()
            .iter()
            .any(|node| node_value_is_sensitive(product, document, node))
}

fn sensitive_editable_spans(
    product: MiddlewareProduct,
    document: &MiddlewareDocument,
) -> Vec<ByteSpan> {
    let mut spans = document
        .nodes()
        .iter()
        .filter(|node| node_value_is_sensitive(product, document, node))
        .filter_map(|node| node.editable_value)
        .collect::<Vec<_>>();
    spans.sort_unstable();
    spans.dedup();
    spans
}

fn shifted_sensitive_spans(
    spans: &[ByteSpan],
    edited: ByteSpan,
    replacement_bytes: usize,
    edited_is_sensitive: bool,
) -> Vec<ByteSpan> {
    let removed = edited.len();
    let mut shifted = Vec::with_capacity(spans.len() + usize::from(edited_is_sensitive));
    for span in spans {
        if *span == edited {
            continue;
        }
        if span.start() >= edited.end() {
            let start = if replacement_bytes >= removed {
                span.start().saturating_add(replacement_bytes - removed)
            } else {
                span.start().saturating_sub(removed - replacement_bytes)
            };
            let end = start.saturating_add(span.len());
            shifted.push(ByteSpan::new(start, end));
        } else {
            shifted.push(*span);
        }
    }
    if edited_is_sensitive {
        shifted.push(ByteSpan::new(
            edited.start(),
            edited.start().saturating_add(replacement_bytes),
        ));
    }
    shifted.sort_unstable();
    shifted.dedup();
    shifted
}

fn redact_document(
    product: MiddlewareProduct,
    document: &MiddlewareDocument,
) -> CoreResult<MiddlewareDocument> {
    let mut redacted = document.raw_bytes().to_vec();
    for node in document.nodes() {
        if !node_value_is_sensitive(product, document, node) {
            continue;
        }
        if let Some(span) = node.editable_value
            && let Some(bytes) = redacted.get_mut(span.start()..span.end())
        {
            bytes.fill(b'*');
        }
    }
    MiddlewareDocument::parse(document.syntax(), redacted)
        .map_err(|error| CoreError::validation("middleware redacted view", error.to_string()))
}

fn node_value_is_sensitive(
    product: MiddlewareProduct,
    document: &MiddlewareDocument,
    node: &MiddlewareDocumentNode,
) -> bool {
    let name = node
        .name
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let compact = name.replace(['-', '_', '.'], "");
    let identifier_sensitive = [
        "password",
        "passwd",
        "passphrase",
        "secret",
        "token",
        "credential",
        "apikey",
        "privatekey",
        "keypass",
        "keystorepass",
        "truststorepass",
        "masterauth",
        "requirepass",
        "bindpassword",
    ]
    .iter()
    .any(|marker| compact.contains(marker))
        || (product == MiddlewareProduct::Redis && name == "user");
    if identifier_sensitive {
        return true;
    }
    let Some(span) = node.editable_value else {
        return false;
    };
    document
        .raw_bytes()
        .get(span.start()..span.end())
        .is_some_and(text_contains_sensitive_marker)
}

fn text_contains_sensitive_marker(bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    [
        "password",
        "passwd",
        "passphrase",
        "requirepass",
        "masterauth",
        "authorization",
        "bearer ",
        "secret",
        "token",
        "credential",
        "api_key",
        "apikey",
        "private_key",
        "private-key",
        "keystorepass",
        "truststorepass",
        "cookie",
    ]
    .iter()
    .any(|marker| text.contains(marker))
        || contains_uri_userinfo(&text)
}

fn contains_uri_userinfo(text: &str) -> bool {
    text.match_indices("://").any(|(scheme_end, _)| {
        let authority = &text[scheme_end + 3..];
        let end = authority
            .find(['/', ' ', '\t', '\r', '\n', '\'', '"', ';'])
            .unwrap_or(authority.len());
        authority[..end].contains('@')
    })
}

fn bounded_node_preview(bytes: &[u8]) -> String {
    if std::str::from_utf8(bytes).is_err() {
        return format!("<非 UTF-8 · {} B>", bytes.len());
    }
    let text = String::from_utf8_lossy(bytes);
    let mut preview = String::new();
    for character in text.chars().take(180) {
        match character {
            '\n' => preview.push_str("\\n"),
            '\r' => preview.push_str("\\r"),
            '\t' => preview.push_str("\\t"),
            value if value.is_control() => preview.push('�'),
            value => preview.push(value),
        }
    }
    if text.chars().count() > 180 {
        preview.push('…');
    }
    preview
}

fn bounded_line_diff_bytes(before: &[u8], after: &[u8]) -> String {
    if before == after {
        return "无差异".to_owned();
    }
    let (Ok(before), Ok(after)) = (std::str::from_utf8(before), std::str::from_utf8(after)) else {
        return format!(
            "非 UTF-8 文件不生成文本差异；原始字节保持只读。\n{} B → {} B",
            before.len(),
            after.len()
        );
    };
    const MAX_DIFF_LINES: usize = 2_000;
    const MAX_DIFF_BYTES: usize = 256 * 1024;
    let left = before.lines().collect::<Vec<_>>();
    let right = after.lines().collect::<Vec<_>>();
    let mut output = String::new();
    let mut emitted = 0usize;
    for index in 0..left.len().max(right.len()) {
        let old = left.get(index).copied();
        let new = right.get(index).copied();
        if old == new {
            continue;
        }
        if let Some(old) = old {
            output.push_str(&format!("- {:>5} | {old}\n", index + 1));
        }
        if let Some(new) = new {
            output.push_str(&format!("+ {:>5} | {new}\n", index + 1));
        }
        emitted += 1;
        if emitted >= MAX_DIFF_LINES || output.len() >= MAX_DIFF_BYTES {
            output.push_str("… 差异预览已达到界面边界；计划仍使用完整字节 …\n");
            break;
        }
    }
    output
}

fn changed_line_count(old: &[u8], new: &[u8]) -> usize {
    let mut old_lines = old.split(|byte| *byte == b'\n').collect::<Vec<_>>();
    let mut new_lines = new.split(|byte| *byte == b'\n').collect::<Vec<_>>();
    if old_lines.last().is_some_and(|line| line.is_empty()) {
        old_lines.pop();
    }
    if new_lines.last().is_some_and(|line| line.is_empty()) {
        new_lines.pop();
    }
    let maximum = old_lines.len().max(new_lines.len());
    (0..maximum)
        .filter(|index| old_lines.get(*index) != new_lines.get(*index))
        .count()
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn read_stored_middleware_history(store: &PortableStore) -> CoreResult<StoredMiddlewareHistory> {
    let stored = store.read_or_default_bounded::<StoredMiddlewareHistory>(
        StoreFile::Middleware,
        MAX_MIDDLEWARE_HISTORY_STORAGE_BYTES,
    )?;
    validate_stored_middleware_history(&stored)?;
    Ok(stored)
}

fn validate_stored_middleware_history(history: &StoredMiddlewareHistory) -> CoreResult<()> {
    if history.records.len() > MAX_HISTORY_RECORDS {
        return Err(CoreError::validation(
            "middleware change history",
            "persisted history exceeds the bounded record limit",
        ));
    }
    for record in &history.records {
        let text_bytes = [
            record.id.as_str(),
            record.operation_id.as_str(),
            record.target.as_str(),
            record.instance_id.as_str(),
            record.unit.as_str(),
            record.binary_path.as_str(),
            record.fragment_path.as_str(),
            record.runtime_fingerprint.as_str(),
            record.primary_config.as_str(),
            record.config_root.as_str(),
            record.path.as_str(),
            record.remote_backup.as_str(),
            record.old_sha256.as_str(),
            record.new_sha256.as_str(),
        ]
        .into_iter()
        .fold(0usize, |total, value| total.saturating_add(value.len()));
        if text_bytes > MAX_MIDDLEWARE_HISTORY_RECORD_TEXT_BYTES
            || TargetIdentity::new(record.target.as_str().to_owned()).is_err()
        {
            return Err(CoreError::validation(
                "middleware change history",
                "persisted record text exceeds its bounded validated shape",
            ));
        }
        validate_change_record(record)?;
    }
    Ok(())
}

fn validate_change_record(record: &MiddlewareChangeRecord) -> CoreResult<()> {
    if Uuid::parse_str(&record.id).is_err()
        || Uuid::parse_str(&record.operation_id).is_err()
        || record.instance_id.len() != 64
        || record.old_sha256.len() != 64
        || record.new_sha256.len() != 64
        || record.old_sha256 == record.new_sha256
        || record.instance_id
            != middleware_instance_id(record.product, &record.unit, record.primary_config.as_str())
        || record.validator != record.product.validator()
        || record.activation != record.product.activation()
        || record.binary_path.as_str() == "/"
        || record.fragment_path.as_str() == "/"
        || record.runtime_fingerprint.len() != 64
    {
        return Err(CoreError::validation(
            "middleware change record",
            "record identity or hash binding is invalid",
        ));
    }
    validate_systemd_unit(&record.unit)?;
    if !product_executable_basename_matches(
        record.product,
        &record.binary_path.file_name()?.to_ascii_lowercase(),
    ) {
        return Err(CoreError::validation(
            "middleware change record",
            "recorded executable does not match the closed product set",
        ));
    }
    if record.discovered_config_root {
        validate_discovered_apache_scope(
            record.product,
            &record.primary_config,
            &record.config_root,
        )?;
    } else {
        validate_config_scope(record.product, &record.primary_config, &record.config_root)?;
    }
    if !is_approved_config_path(
        &MiddlewareInstance {
            target: TargetGuard {
                identity: record.target.clone(),
                generation: 1,
            },
            id: record.instance_id.clone(),
            product: record.product,
            runtime: MiddlewareRuntimeKind::Systemd,
            unit: record.unit.clone(),
            version: String::new(),
            active_state: String::new(),
            sub_state: String::new(),
            main_pid: 0,
            binary_path: record.binary_path.clone(),
            fragment_path: record.fragment_path.clone(),
            runtime_fingerprint: record.runtime_fingerprint.clone(),
            apache_invocation_evidence: (record.product == MiddlewareProduct::ApacheHttpd)
                .then_some(ApacheInvocationEvidenceState::NotCollected),
            primary_config: record.primary_config.clone(),
            config_root: record.config_root.clone(),
            discovered_config_root: record.discovered_config_root,
            validator: record.validator,
            activation: record.activation,
            supports_native_reload: matches!(
                record.product,
                MiddlewareProduct::Nginx | MiddlewareProduct::ApacheHttpd
            ),
        },
        &record.path,
    ) {
        return Err(CoreError::validation(
            "middleware change record",
            "recorded configuration path is outside the closed instance roots",
        ));
    }
    let backup_namespace = record.remote_backup.parent()?;
    if backup_namespace.file_name()? != ".lovelyres-backups"
        || backup_namespace.parent()? != record.primary_config.parent()?
        || record.remote_backup.file_name()?.len() > 512
    {
        return Err(CoreError::validation(
            "middleware change record",
            "remote backup is outside the configuration's managed backup namespace",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use super::*;
    use crate::{
        apache_runtime::{ApacheRuntimeInvocationEvidence, ApacheStableConfigGraphEvidence},
        ssh::SshConnectionStatus,
    };

    #[derive(Debug)]
    struct TestArchiveRoot(PathBuf);

    impl TestArchiveRoot {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("lovelyres-middleware-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestArchiveRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn instance(
        product: MiddlewareProduct,
        unit: &str,
        config: &str,
        root: &str,
    ) -> MiddlewareInstance {
        let primary_config = RemotePath::new(config).unwrap();
        let fragment_path = RemotePath::new(format!("/etc/systemd/system/{unit}")).unwrap();
        let binary_path = match product {
            MiddlewareProduct::Nginx => "/usr/sbin/nginx",
            MiddlewareProduct::ApacheHttpd => "/usr/sbin/apache2ctl",
            MiddlewareProduct::Redis => "/usr/bin/redis-server",
            MiddlewareProduct::Tomcat => "/usr/bin/java",
        };
        MiddlewareInstance {
            target: TargetGuard {
                identity: TargetIdentity::new("host-a").unwrap(),
                generation: 1,
            },
            id: middleware_instance_id(product, unit, config),
            product,
            runtime: MiddlewareRuntimeKind::Systemd,
            unit: unit.to_owned(),
            version: "test".to_owned(),
            active_state: "active".to_owned(),
            sub_state: "running".to_owned(),
            main_pid: 42,
            binary_path: RemotePath::new(binary_path).unwrap(),
            runtime_fingerprint: runtime_fingerprint(unit, &fragment_path, "test-exec", "", ""),
            apache_invocation_evidence: (product == MiddlewareProduct::ApacheHttpd)
                .then_some(ApacheInvocationEvidenceState::NotCollected),
            fragment_path,
            primary_config,
            config_root: RemotePath::new(root).unwrap(),
            discovered_config_root: false,
            validator: product.validator(),
            activation: product.activation(),
            supports_native_reload: matches!(
                product,
                MiddlewareProduct::Nginx | MiddlewareProduct::ApacheHttpd
            ),
        }
    }

    fn session(identity: &str, generation: u64) -> BoundSshSession {
        let target = TargetGuard {
            identity: TargetIdentity::new(identity).unwrap(),
            generation,
        };
        let status = SshConnectionStatus {
            session_id: format!("session-{identity}"),
            connection_id: identity.to_owned(),
            host: format!("{identity}.test"),
            port: 22,
            username: "operator".to_owned(),
            host_key_fingerprint: "SHA256:test".to_owned(),
            connected_at: Utc::now(),
        };
        BoundSshSession::from_status(target, &status, "middleware test session").unwrap()
    }

    fn bundle(instance: MiddlewareInstance, bytes: &[u8]) -> MiddlewareConfigurationBundle {
        let document = MiddlewareDocument::parse(
            syntax_for_path(instance.product, &instance.primary_config),
            bytes.to_vec(),
        )
        .unwrap();
        let includes =
            extract_include_references(&instance, &instance.primary_config, &document).unwrap();
        let snapshot = MiddlewareConfigSnapshot {
            target: instance.target.clone(),
            instance_id: instance.id.clone(),
            product: instance.product,
            role: MiddlewareConfigRole::Primary,
            path: instance.primary_config.clone(),
            metadata: SftpMetadata {
                size: bytes.len() as u64,
                permissions: Some(0o640),
                uid: Some(0),
                gid: Some(0),
                modified_at: None,
                kind: SftpFileKind::File,
            },
            sha256: sha256_hex(bytes),
            bytes: Zeroizing::new(bytes.to_vec()),
            document,
            includes,
        };
        MiddlewareConfigurationBundle {
            target: instance.target.clone(),
            instance,
            files: vec![snapshot],
            unresolved_includes: Vec::new(),
            directory_manifests: Vec::new(),
            total_bytes: bytes.len(),
            loaded_at: Utc::now(),
        }
    }

    fn change_record() -> MiddlewareChangeRecord {
        let instance = instance(
            MiddlewareProduct::Nginx,
            "nginx.service",
            "/etc/nginx/nginx.conf",
            "/etc/nginx",
        );
        MiddlewareChangeRecord {
            id: Uuid::new_v4().to_string(),
            operation_id: Uuid::new_v4().to_string(),
            target: TargetIdentity::new("host-a").unwrap(),
            instance_id: instance.id.clone(),
            product: instance.product,
            unit: instance.unit.clone(),
            binary_path: instance.binary_path.clone(),
            fragment_path: instance.fragment_path.clone(),
            runtime_fingerprint: instance.runtime_fingerprint.clone(),
            primary_config: instance.primary_config.clone(),
            config_root: instance.config_root.clone(),
            discovered_config_root: false,
            path: instance.primary_config.clone(),
            remote_backup: RemotePath::new(
                "/etc/nginx/.lovelyres-backups/00000000-0000-0000-0000-000000000000-nginx.conf",
            )
            .unwrap(),
            old_sha256: "1".repeat(64),
            new_sha256: "2".repeat(64),
            old_bytes: 10,
            new_bytes: 11,
            validator: instance.validator,
            activation: instance.activation,
            state: MiddlewareChangeState::Applied,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn catalog_is_closed_complete_and_matches_product_policy() {
        assert_eq!(MIDDLEWARE_CATALOG.len(), MiddlewareProduct::ALL.len());
        let products = MIDDLEWARE_CATALOG
            .iter()
            .map(|entry| entry.product)
            .collect::<BTreeSet<_>>();
        assert_eq!(products, MiddlewareProduct::ALL.into_iter().collect());
        for entry in MIDDLEWARE_CATALOG {
            assert!(!entry.service_prefixes.is_empty());
            assert!(!entry.fallback_config_paths.is_empty());
            assert!(!entry.approved_config_roots.is_empty());
            assert!(
                entry
                    .fallback_config_paths
                    .iter()
                    .all(|path| RemotePath::new(*path).is_ok())
            );
            assert!(
                entry
                    .approved_config_roots
                    .iter()
                    .all(|path| RemotePath::new(*path).is_ok())
            );
            assert_eq!(entry.validator, entry.product.validator());
            assert_eq!(entry.activation, entry.product.activation());
        }
    }

    #[test]
    fn unit_inventory_accepts_only_closed_product_service_units() {
        let parsed = parse_unit_inventory(
            "nginx.service enabled\napache2.service enabled\nredis-server@cache.service disabled\ntomcat10.service enabled\npostgresql.service enabled\nnginx.service enabled\n../../nginx.service enabled\n",
        )
        .unwrap();
        assert_eq!(parsed.len(), 4);
        assert_eq!(parsed[0].product, MiddlewareProduct::Nginx);
        assert_eq!(parsed[1].product, MiddlewareProduct::ApacheHttpd);
        assert_eq!(parsed[2].product, MiddlewareProduct::Redis);
        assert_eq!(parsed[3].product, MiddlewareProduct::Tomcat);
        assert!(validate_systemd_unit("nginx.service;reboot").is_err());
    }

    #[test]
    fn discovery_prefers_product_reported_paths_and_preserves_instance_identity() {
        let binary = discover_exec_path(
            "{ path=/opt/nginx/sbin/nginx ; argv[]=/opt/nginx/sbin/nginx -g daemon on; ; }",
        )
        .unwrap();
        assert_eq!(binary.as_str(), "/opt/nginx/sbin/nginx");
        assert_eq!(
            product_probe_command(MiddlewareProduct::Nginx, &binary),
            "'/opt/nginx/sbin/nginx' -V 2>&1"
        );
        assert!(discover_exec_path("/opt/nginx/sbin/nginx -g daemon").is_err());
        assert!(validate_product_executable(MiddlewareProduct::Nginx, &binary, "nginx").is_ok());
        assert!(
            validate_product_executable(
                MiddlewareProduct::Nginx,
                &RemotePath::new("/bin/sh").unwrap(),
                "nginx",
            )
            .is_err()
        );
        assert!(
            validate_product_executable(
                MiddlewareProduct::Tomcat,
                &RemotePath::new("/usr/bin/java").unwrap(),
                "org.apache.catalina.startup.Bootstrap start",
            )
            .is_ok()
        );

        let (nginx, root) = discover_config_path(
            MiddlewareProduct::Nginx,
            "",
            "",
            "nginx version: nginx/1.28 --prefix=/usr/share/nginx --conf-path=/etc/nginx/nginx.conf",
        )
        .unwrap();
        assert_eq!(nginx.as_str(), "/etc/nginx/nginx.conf");
        assert_eq!(root.as_str(), "/usr/share/nginx");

        let (apache, root) = discover_config_path(
            MiddlewareProduct::ApacheHttpd,
            "",
            "",
            " -D HTTPD_ROOT=\"/etc/httpd\"\n -D SERVER_CONFIG_FILE=\"conf/httpd.conf\"\n",
        )
        .unwrap();
        assert_eq!(apache.as_str(), "/etc/httpd/conf/httpd.conf");
        assert_eq!(root.as_str(), "/etc/httpd");

        let (redis, _) = discover_config_path(
            MiddlewareProduct::Redis,
            "{ path=/usr/bin/redis-server ; argv[]=/usr/bin/redis-server /etc/redis/6380.conf --supervised systemd ; }",
            "",
            "Redis server v=8.0",
        )
        .unwrap();
        assert_eq!(redis.as_str(), "/etc/redis/6380.conf");

        let (tomcat, root) = discover_config_path(
            MiddlewareProduct::Tomcat,
            "",
            "CATALINA_BASE=/srv/tomcat/instance-a JAVA_HOME=/usr/lib/jvm/java",
            "Tomcat",
        )
        .unwrap();
        assert_eq!(tomcat.as_str(), "/srv/tomcat/instance-a/conf/server.xml");
        assert_eq!(root.as_str(), "/srv/tomcat/instance-a/conf");
    }

    #[test]
    fn include_extraction_keeps_duplicates_unknowns_and_relative_roots() {
        let instance = instance(
            MiddlewareProduct::Nginx,
            "nginx.service",
            "/etc/nginx/nginx.conf",
            "/etc/nginx",
        );
        let source = instance.primary_config.clone();
        let document = MiddlewareDocument::parse(
            MiddlewareDocumentSyntax::Nginx,
            b"include conf.d/*.conf;\ninclude /etc/nginx/mime.types;\ninclude conf.d/*.conf;\n"
                .to_vec(),
        )
        .unwrap();
        let references = extract_include_references(&instance, &source, &document).unwrap();
        assert_eq!(references.len(), 3);
        assert!(references[0].resolved.is_empty());
        assert_eq!(references[1].resolved[0].as_str(), "/etc/nginx/mime.types");
        assert_eq!(references[0].raw_value, references[2].raw_value);
    }

    #[test]
    fn include_extraction_fails_closed_outside_the_discovered_instance_roots() {
        let instance = instance(
            MiddlewareProduct::Nginx,
            "nginx.service",
            "/etc/nginx/nginx.conf",
            "/etc/nginx",
        );
        let document = MiddlewareDocument::parse(
            MiddlewareDocumentSyntax::Nginx,
            b"include /etc/shadow;\ninclude /etc/nginx/mime.types;\n".to_vec(),
        )
        .unwrap();
        let references =
            extract_include_references(&instance, &instance.primary_config, &document).unwrap();
        assert!(references[0].resolved.is_empty());
        assert!(references[0].unresolved_reason.is_some());
        assert_eq!(references[1].resolved[0].as_str(), "/etc/nginx/mime.types");
    }

    #[test]
    fn include_topology_signature_rejects_semantic_retargeting() {
        let original = MiddlewareDocument::parse(
            MiddlewareDocumentSyntax::Apache,
            b"IncludeOptional conf.d/*.conf\n".to_vec(),
        )
        .unwrap();
        let equivalent = MiddlewareDocument::parse(
            MiddlewareDocumentSyntax::Apache,
            b"includeoptional \"conf.d/*.conf\"\n".to_vec(),
        )
        .unwrap();
        let required = MiddlewareDocument::parse(
            MiddlewareDocumentSyntax::Apache,
            b"Include conf.d/*.conf\n".to_vec(),
        )
        .unwrap();
        let retargeted = MiddlewareDocument::parse(
            MiddlewareDocumentSyntax::Apache,
            b"IncludeOptional /tmp/*.conf\n".to_vec(),
        )
        .unwrap();
        let signature =
            include_directive_signature(MiddlewareProduct::ApacheHttpd, &original).unwrap();
        assert_eq!(
            signature,
            include_directive_signature(MiddlewareProduct::ApacheHttpd, &equivalent).unwrap()
        );
        assert_ne!(
            signature,
            include_directive_signature(MiddlewareProduct::ApacheHttpd, &required).unwrap()
        );
        assert_ne!(
            signature,
            include_directive_signature(MiddlewareProduct::ApacheHttpd, &retargeted).unwrap()
        );
    }

    #[test]
    fn configuration_bundle_is_bound_to_target_epoch_bytes_metadata_and_complete_graph() {
        let instance = instance(
            MiddlewareProduct::Nginx,
            "nginx.service",
            "/etc/nginx/nginx.conf",
            "/etc/nginx",
        );
        let mut bundle = bundle(instance, b"worker_processes auto;\n");
        let matching = session("host-a", 1);
        validate_bundle_binding(&matching, &bundle).unwrap();

        assert!(validate_bundle_binding(&session("host-a", 2), &bundle).is_err());
        assert!(validate_bundle_binding(&session("host-b", 1), &bundle).is_err());

        bundle.files[0].metadata.size += 1;
        assert!(validate_bundle_binding(&matching, &bundle).is_err());
        bundle.files[0].metadata.size -= 1;

        bundle.unresolved_includes.push(MiddlewareIncludeReference {
            source: bundle.instance.primary_config.clone(),
            raw_value: "/etc/shadow".to_owned(),
            optional: false,
            resolved: Vec::new(),
            unresolved_reason: Some("outside approved roots".to_owned()),
        });
        assert!(validate_bundle_binding(&matching, &bundle).is_err());
    }

    #[test]
    fn file_name_glob_is_bounded_and_does_not_treat_regex_as_glob() {
        assert!(glob_file_name_matches("*.conf", "site.conf"));
        assert!(glob_file_name_matches("redis-?.conf", "redis-a.conf"));
        assert!(glob_file_name_matches("site-[0-9].conf", "site-7.conf"));
        assert!(glob_file_name_matches("site-[!0-9].conf", "site-a.conf"));
        assert!(!glob_file_name_matches("site-[!0-9].conf", "site-7.conf"));
        assert!(glob_file_name_matches("[ab][0-2].conf", "b2.conf"));
        assert!(!glob_file_name_matches("*.conf", "site.conf.bak"));
        assert!(!glob_file_name_matches("site.+", "site.conf"));
        assert!(compile_glob_component("site-[9-0].conf").is_err());
        assert!(compile_glob_component("site-[[:digit:]].conf").is_err());
        assert!(compile_glob_component("site-[abc.conf").is_err());
        assert!(compile_glob_component("site-abc].conf").is_err());
        let instance = instance(
            MiddlewareProduct::Nginx,
            "nginx.service",
            "/etc/nginx/nginx.conf",
            "/etc/nginx",
        );
        let (parent, pattern) =
            wildcard_parent_and_pattern(&instance, &instance.primary_config, "conf.d/*.conf")
                .unwrap();
        assert_eq!(parent.as_str(), "/etc/nginx/conf.d");
        assert_eq!(pattern, "*.conf");
        assert!(
            wildcard_parent_and_pattern(&instance, &instance.primary_config, "../secret/*.conf")
                .is_err()
        );

        let backup = RemotePath::new("/etc/nginx/.lovelyres-backups").unwrap();
        let manifest = |pattern: Option<&str>| MiddlewareDirectoryManifest {
            path: RemotePath::new("/etc/nginx").unwrap(),
            pattern: pattern.map(str::to_owned),
            activation_sensitive: true,
            include_directories: pattern.is_none(),
            entries: Vec::new(),
        };
        assert!(manifest_would_activate_backup(&manifest(None), &backup));
        assert!(manifest_would_activate_backup(
            &manifest(Some("*")),
            &backup
        ));
        assert!(!manifest_would_activate_backup(
            &manifest(Some("*.conf")),
            &backup
        ));
    }

    #[test]
    fn apache_globs_accept_directory_segments_and_safe_character_classes() {
        let apache = instance(
            MiddlewareProduct::ApacheHttpd,
            "apache2.service",
            "/etc/apache2/apache2.conf",
            "/etc/apache2",
        );
        validate_glob_include_pattern(
            &apache,
            &apache.primary_config,
            "sites-[0-9]/*/vhost-[!x].conf",
        )
        .unwrap();
        let (base, components) = include_pattern_base_and_components(
            &apache,
            &apache.primary_config,
            "sites-[0-9]/*/vhost-[!x].conf",
        )
        .unwrap();
        assert_eq!(base.as_str(), "/etc/apache2");
        assert_eq!(components, vec!["sites-[0-9]", "*", "vhost-[!x].conf"]);
        validate_glob_include_pattern(
            &apache,
            &apache.primary_config,
            "/etc/apache2/sites-[0-9]/*.conf",
        )
        .unwrap();
        assert!(
            validate_glob_include_pattern(
                &apache,
                &apache.primary_config,
                "/opt/httpd-*/conf/*.conf",
            )
            .is_err()
        );
        assert!(
            validate_glob_include_pattern(&apache, &apache.primary_config, "../private/*.conf",)
                .is_err()
        );

        let mut custom = instance(
            MiddlewareProduct::ApacheHttpd,
            "httpd.service",
            "/opt/vendor-httpd/conf/httpd.conf",
            "/opt/vendor-httpd",
        );
        custom.discovered_config_root = true;
        validate_glob_include_pattern(&custom, &custom.primary_config, "conf.d/[a-z]*/vhost?.conf")
            .unwrap();
        validate_glob_include_pattern(
            &custom,
            &custom.primary_config,
            "/opt/vendor-httpd/conf.d/[a-z]*/vhost?.conf",
        )
        .unwrap();
    }

    #[test]
    fn apache_include_optional_preserves_empty_match_semantics() {
        let apache = instance(
            MiddlewareProduct::ApacheHttpd,
            "apache2.service",
            "/etc/apache2/apache2.conf",
            "/etc/apache2",
        );
        let document = MiddlewareDocument::parse(
            MiddlewareDocumentSyntax::Apache,
            b"Include conf.d/required.conf\nIncludeOptional conf.d/missing.conf\nIncludeOptional conf.d/missing-[0-9].conf\nIncludeOptional conf.d/[[:digit:]].conf\n".to_vec(),
        )
        .unwrap();
        let references =
            extract_include_references(&apache, &apache.primary_config, &document).unwrap();
        assert_eq!(references.len(), 4);
        assert!(!references[0].optional);
        assert!(references[1].optional);
        assert_eq!(
            references[1].resolved[0].as_str(),
            "/etc/apache2/conf.d/missing.conf"
        );
        assert!(
            references[2]
                .unresolved_reason
                .as_deref()
                .is_some_and(|reason| reason.starts_with("glob include pending"))
        );
        assert!(
            references[3]
                .unresolved_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("unsupported or unsafe"))
        );
        assert!(validate_include_match(true, "missing-*.conf", 0).is_ok());
        assert!(validate_include_match(false, "missing-*.conf", 0).is_err());
        assert!(validate_include_match(false, "required.conf", 1).is_ok());
    }

    #[test]
    fn apache_relative_and_absolute_includes_stay_inside_bound_server_root() {
        let mut apache = instance(
            MiddlewareProduct::ApacheHttpd,
            "httpd.service",
            "/opt/vendor-httpd/conf/httpd.conf",
            "/opt/vendor-httpd",
        );
        apache.discovered_config_root = true;
        assert_eq!(
            resolve_include_path(&apache, &apache.primary_config, "conf.d/site.conf")
                .unwrap()
                .as_str(),
            "/opt/vendor-httpd/conf.d/site.conf"
        );
        assert_eq!(
            resolve_include_path(
                &apache,
                &apache.primary_config,
                "/opt/vendor-httpd/extra/site.conf",
            )
            .unwrap()
            .as_str(),
            "/opt/vendor-httpd/extra/site.conf"
        );
        assert!(
            resolve_include_path(&apache, &apache.primary_config, "/opt/unrelated/site.conf")
                .is_err()
        );
    }

    #[test]
    fn target_discovered_apache_root_is_explicit_and_product_scoped() {
        let primary = RemotePath::new("/opt/vendor-httpd/conf/httpd.conf").unwrap();
        let root = RemotePath::new("/opt/vendor-httpd").unwrap();
        let probe =
            " -D HTTPD_ROOT=\"/opt/vendor-httpd\"\n -D SERVER_CONFIG_FILE=\"conf/httpd.conf\"\n";
        assert!(apache_scope_is_target_reported(
            MiddlewareProduct::ApacheHttpd,
            "",
            probe,
            &primary,
            &root,
        ));
        assert!(!apache_scope_is_target_reported(
            MiddlewareProduct::ApacheHttpd,
            "",
            " -D HTTPD_ROOT=\"/opt/vendor-httpd\"\n",
            &primary,
            &root,
        ));
        assert!(apache_scope_is_target_reported(
            MiddlewareProduct::ApacheHttpd,
            "{ path=/opt/vendor-httpd/bin/httpd ; argv[]=/opt/vendor-httpd/bin/httpd -f /opt/vendor-httpd/conf/httpd.conf ; }",
            " -D HTTPD_ROOT=\"/opt/vendor-httpd\"\n",
            &primary,
            &root,
        ));
        assert!(!apache_scope_is_target_reported(
            MiddlewareProduct::Nginx,
            "",
            probe,
            &primary,
            &root,
        ));
        assert!(validate_config_scope(MiddlewareProduct::ApacheHttpd, &primary, &root).is_err());
        validate_discovered_apache_scope(MiddlewareProduct::ApacheHttpd, &primary, &root).unwrap();
        assert!(
            validate_discovered_apache_scope(MiddlewareProduct::Nginx, &primary, &root).is_err()
        );
        assert!(
            validate_discovered_apache_scope(
                MiddlewareProduct::ApacheHttpd,
                &primary,
                &RemotePath::new("/").unwrap(),
            )
            .is_err()
        );

        let mut apache = instance(
            MiddlewareProduct::ApacheHttpd,
            "httpd.service",
            primary.as_str(),
            root.as_str(),
        );
        assert!(validate_instance(&apache).is_err());
        apache.discovered_config_root = true;
        validate_instance(&apache).unwrap();
        assert!(is_approved_config_path(
            &apache,
            &RemotePath::new("/opt/vendor-httpd/conf.d/site.conf").unwrap()
        ));
        assert!(!is_approved_config_path(
            &apache,
            &RemotePath::new("/opt/another-product/site.conf").unwrap()
        ));
        assert!(!is_approved_config_path(
            &apache,
            &RemotePath::new("/opt/vendor-httpd-escape/site.conf").unwrap()
        ));
    }

    #[test]
    fn include_cycles_and_graph_limits_fail_closed() {
        let primary = RemotePath::new("/etc/apache2/apache2.conf").unwrap();
        let pending = PendingConfigPath {
            path: primary.clone(),
            role: MiddlewareConfigRole::Primary,
            depth: 0,
            optional: false,
            ancestors: Vec::new(),
        };
        let include = MiddlewareIncludeReference {
            source: primary.clone(),
            raw_value: "apache2.conf".to_owned(),
            optional: false,
            resolved: vec![primary.clone()],
            unresolved_reason: None,
        };
        assert!(enqueue_include_path(&mut VecDeque::new(), &pending, &include, &primary).is_err());

        let nested = PendingConfigPath {
            path: RemotePath::new("/etc/apache2/conf.d/site.conf").unwrap(),
            role: MiddlewareConfigRole::Included,
            depth: 1,
            optional: false,
            ancestors: vec![primary.clone()],
        };
        assert!(enqueue_include_path(&mut VecDeque::new(), &nested, &include, &primary).is_err());

        let oversized = (0..=MAX_MIDDLEWARE_CONFIG_FILES)
            .map(|index| MiddlewareDirectoryManifest {
                path: RemotePath::new(format!("/etc/apache2/conf-{index}")).unwrap(),
                pattern: Some("*.conf".to_owned()),
                activation_sensitive: true,
                include_directories: true,
                entries: Vec::new(),
            })
            .collect::<Vec<_>>();
        assert!(validate_directory_manifest_limits(&oversized).is_err());
    }

    #[test]
    fn edited_documents_fail_closed_on_opaque_or_non_utf8_content() {
        let malformed = MiddlewareDocument::parse(
            MiddlewareDocumentSyntax::TomcatXml,
            b"<Server><Service></Server>".to_vec(),
        )
        .unwrap();
        assert!(validate_document_structure(MiddlewareProduct::Tomcat, &malformed).is_err());
        let invalid_utf8 = MiddlewareDocument::parse(
            MiddlewareDocumentSyntax::Redis,
            vec![b'p', b'o', b'r', b't', b' ', 0xff],
        )
        .unwrap();
        assert!(validate_document_structure(MiddlewareProduct::Redis, &invalid_utf8).is_err());
    }

    #[test]
    fn snapshots_and_operation_metadata_never_debug_configuration_bytes() {
        let secret = b"requirepass super-secret-password\n".to_vec();
        let snapshot = MiddlewareConfigSnapshot {
            target: TargetGuard {
                identity: TargetIdentity::new("host-a").unwrap(),
                generation: 1,
            },
            instance_id: "a".repeat(64),
            product: MiddlewareProduct::Redis,
            role: MiddlewareConfigRole::Primary,
            path: RemotePath::new("/etc/redis/redis.conf").unwrap(),
            metadata: SftpMetadata {
                size: secret.len() as u64,
                permissions: Some(0o600),
                uid: Some(0),
                gid: Some(0),
                modified_at: None,
                kind: SftpFileKind::File,
            },
            sha256: sha256_hex(&secret),
            bytes: Zeroizing::new(secret.clone()),
            document: MiddlewareDocument::parse(MiddlewareDocumentSyntax::Redis, secret).unwrap(),
            includes: Vec::new(),
        };
        let debug = format!("{snapshot:?}");
        assert!(!debug.contains("super-secret-password"));
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn credential_like_values_stay_core_owned_and_drafts_only_expose_redacted_views() {
        let redis_instance = instance(
            MiddlewareProduct::Redis,
            "redis-server.service",
            "/etc/redis/redis.conf",
            "/etc/redis",
        );
        let redis_bundle = bundle(
            redis_instance,
            b"# keep this comment\nrequirepass old-super-secret\nmaxmemory 128mb\n",
        );
        let snapshot = &redis_bundle.files[0];
        let draft = snapshot.create_draft().unwrap();
        assert!(draft.contains_sensitive_values());
        assert!(draft.safe_raw_text().is_none());
        assert!(!format!("{draft:?}").contains("old-super-secret"));
        let secret_index = draft
            .nodes()
            .iter()
            .position(|node| node.name.as_deref() == Some("requirepass"))
            .unwrap();
        let value = draft.editable_value(secret_index).unwrap();
        assert!(value.sensitive);
        assert_eq!(value.value, None);
        assert!(
            !draft
                .node_preview(secret_index)
                .contains("old-super-secret")
        );

        let patched = draft
            .apply_node_edit(secret_index, "new-super-secret".to_owned())
            .unwrap();
        assert!(!format!("{patched:?}").contains("new-super-secret"));
        assert!(
            !patched
                .node_preview(secret_index)
                .contains("new-super-secret")
        );
        let materialized = patched.materialize(snapshot).unwrap();
        assert_eq!(
            materialized,
            b"# keep this comment\nrequirepass new-super-secret\nmaxmemory 128mb\n"
        );
        assert!(patched.safe_diff(snapshot).contains("正文差异已隐藏"));

        let safe_bundle = bundle(
            instance(
                MiddlewareProduct::Redis,
                "redis-server.service",
                "/etc/redis/redis.conf",
                "/etc/redis",
            ),
            b"port 6379\n",
        );
        let unrelated = safe_bundle.files[0].create_draft().unwrap();
        let rejected = unrelated.safe_diff(snapshot);
        assert!(rejected.contains("快照不匹配"));
        assert!(!rejected.contains("old-super-secret"));

        let raw_secret = unrelated
            .replace_safe_raw("port 6379\nrequirepass raw-added-secret\n".to_owned())
            .unwrap();
        assert!(raw_secret.contains_sensitive_values());
        assert!(raw_secret.safe_raw_text().is_none());
        assert!(!format!("{raw_secret:?}").contains("raw-added-secret"));
        assert_eq!(
            raw_secret.materialize(&safe_bundle.files[0]).unwrap(),
            b"port 6379\nrequirepass raw-added-secret\n"
        );

        let uri_secret = unrelated
            .replace_safe_raw("proxy_pass http://admin:s3cr3t@backend;\n".to_owned())
            .unwrap();
        assert!(uri_secret.contains_sensitive_values());
        assert!(uri_secret.safe_raw_text().is_none());
        assert!(!format!("{uri_secret:?}").contains("s3cr3t"));
    }

    #[test]
    fn runtime_fingerprint_binds_environment_and_environment_files() {
        let fragment = RemotePath::new("/etc/systemd/system/tomcat.service").unwrap();
        let base = runtime_fingerprint(
            "tomcat.service",
            &fragment,
            "{ path=/usr/bin/java ; }",
            "CATALINA_BASE=/srv/tomcat/a",
            "/etc/default/tomcat",
        );
        assert_ne!(
            base,
            runtime_fingerprint(
                "tomcat.service",
                &fragment,
                "{ path=/usr/bin/java ; }",
                "CATALINA_BASE=/srv/tomcat/b",
                "/etc/default/tomcat",
            )
        );
        assert_ne!(
            base,
            runtime_fingerprint(
                "tomcat.service",
                &fragment,
                "{ path=/usr/bin/java ; }",
                "CATALINA_BASE=/srv/tomcat/a",
                "/etc/sysconfig/tomcat",
            )
        );
    }

    #[test]
    fn apache_graph_evidence_binds_bundle_runtime_and_matching_endpoints() {
        let apache = instance(
            MiddlewareProduct::ApacheHttpd,
            "httpd.service",
            "/etc/httpd/conf/httpd.conf",
            "/etc/httpd",
        );
        let first_bundle = bundle(apache.clone(), b"ServerName first.example\n");
        let invocation =
            ApacheRuntimeInvocationEvidence::test_fixture(apache.target.clone(), 1).unwrap();
        let first = first_bundle
            .apache_config_graph_evidence(&invocation)
            .unwrap();
        let stable = ApacheStableConfigGraphEvidence::seal(first.clone(), first.clone()).unwrap();
        assert_eq!(stable.target(), apache.target());
        assert_eq!(stable.runtime_fingerprint(), invocation.fingerprint());

        let changed_bundle = bundle(apache.clone(), b"ServerName changed.example\n");
        let changed = changed_bundle
            .apache_config_graph_evidence(&invocation)
            .unwrap();
        assert_ne!(first.digest(), changed.digest());
        assert!(ApacheStableConfigGraphEvidence::seal(first, changed).is_err());

        let other_guard = ApacheRuntimeInvocationEvidence::test_fixture(
            TargetGuard {
                identity: apache.target.identity.clone(),
                generation: apache.target.generation + 1,
            },
            1,
        )
        .unwrap();
        assert!(
            first_bundle
                .apache_config_graph_evidence(&other_guard)
                .is_err()
        );
    }

    #[test]
    fn apache_plan_and_execution_fail_closed_while_nginx_remains_available() {
        let apache = instance(
            MiddlewareProduct::ApacheHttpd,
            "httpd.service",
            "/etc/httpd/conf/httpd.conf",
            "/etc/httpd",
        );
        for error in [
            ensure_apache_plan_evidence(&apache).unwrap_err(),
            ensure_apache_execution_evidence(&apache).unwrap_err(),
        ] {
            let message = error.to_string();
            assert!(message.contains("Apache remote changes remain disabled"));
            assert!(!message.contains(apache.unit()));
            assert!(!message.contains(apache.primary_config().as_str()));
        }
        assert_eq!(
            apache.apache_invocation_evidence(),
            Some(&ApacheInvocationEvidenceState::NotCollected)
        );

        let nginx = instance(
            MiddlewareProduct::Nginx,
            "nginx.service",
            "/etc/nginx/nginx.conf",
            "/etc/nginx",
        );
        ensure_apache_plan_evidence(&nginx).unwrap();
        ensure_apache_execution_evidence(&nginx).unwrap();
        assert_eq!(nginx.apache_invocation_evidence(), None);
    }

    #[test]
    fn activation_sensitive_directory_manifests_reject_untracked_entry_kinds() {
        let file = MiddlewareDirectoryEntry {
            path: RemotePath::new("/etc/nginx/conf.d/site.conf").unwrap(),
            kind: SftpFileKind::File,
        };
        let directory = MiddlewareDirectoryEntry {
            path: RemotePath::new("/etc/nginx/conf.d/nested.conf").unwrap(),
            kind: SftpFileKind::Directory,
        };
        let symlink = MiddlewareDirectoryEntry {
            path: RemotePath::new("/etc/nginx/conf.d/alias.conf").unwrap(),
            kind: SftpFileKind::Symlink,
        };
        assert!(
            validate_activation_directory_entries(true, None, true, std::slice::from_ref(&file),)
                .is_ok()
        );
        assert!(
            validate_activation_directory_entries(
                true,
                None,
                true,
                &[file.clone(), directory.clone()],
            )
            .is_ok()
        );
        assert!(
            validate_activation_directory_entries(true, None, true, &[file.clone(), symlink])
                .is_err()
        );
        assert!(
            validate_activation_directory_entries(true, Some("*.conf"), false, &[file]).is_ok()
        );
        assert!(
            validate_activation_directory_entries(true, Some("*.conf"), false, &[directory])
                .is_err()
        );
        let directory = MiddlewareDirectoryEntry {
            path: RemotePath::new("/etc/nginx/conf.d/nested.conf").unwrap(),
            kind: SftpFileKind::Directory,
        };
        assert!(
            validate_activation_directory_entries(true, Some("*.conf"), true, &[directory]).is_ok()
        );
    }

    #[test]
    fn catalog_scope_does_not_turn_exact_fallback_parents_into_broad_roots() {
        let redis_primary = RemotePath::new("/etc/redis.conf").unwrap();
        let redis_parent = RemotePath::new("/etc").unwrap();
        validate_config_scope(MiddlewareProduct::Redis, &redis_primary, &redis_parent).unwrap();
        let redis = instance(
            MiddlewareProduct::Redis,
            "redis.service",
            "/etc/redis.conf",
            "/etc",
        );
        assert!(is_approved_config_path(&redis, &redis_primary));
        assert!(!is_approved_config_path(
            &redis,
            &RemotePath::new("/etc/shadow").unwrap()
        ));
        assert!(
            validate_config_scope(
                MiddlewareProduct::Nginx,
                &RemotePath::new("/etc/pam.conf").unwrap(),
                &RemotePath::new("/etc").unwrap(),
            )
            .is_err()
        );
    }

    #[test]
    fn changed_line_count_counts_byte_lines_without_normalizing_endings() {
        assert_eq!(changed_line_count(b"a\r\nb\r\n", b"a\r\nc\r\n"), 1);
        assert_eq!(changed_line_count(b"a\n", b"a\nextra\n"), 1);
    }

    #[test]
    fn persisted_restore_record_is_bound_to_managed_backup_and_closed_policy() {
        let mut record = change_record();
        validate_change_record(&record).unwrap();
        record.remote_backup = RemotePath::new("/tmp/stolen.conf").unwrap();
        assert!(validate_change_record(&record).is_err());
        record.remote_backup = RemotePath::new(
            "/etc/nginx/.lovelyres-backups/00000000-0000-0000-0000-000000000000-nginx.conf",
        )
        .unwrap();
        record.activation = MiddlewareActivationPolicy::Restart;
        assert!(validate_change_record(&record).is_err());
    }

    #[test]
    fn persisted_history_is_byte_item_and_text_bounded_before_use() {
        let root = TestArchiveRoot::new();
        let store = PortableStore::prepare(root.0.clone()).unwrap();
        let path = store.path_for(StoreFile::Middleware);
        let oversized = fs::File::create(path).unwrap();
        oversized
            .set_len(MAX_MIDDLEWARE_HISTORY_STORAGE_BYTES as u64 + 1)
            .unwrap();
        drop(oversized);
        assert!(matches!(
            read_stored_middleware_history(&store),
            Err(CoreError::Validation {
                subject: "middleware changes",
                ..
            })
        ));

        let record = change_record();
        let exact_limit = StoredMiddlewareHistory {
            records: vec![record.clone(); MAX_HISTORY_RECORDS],
        };
        store.write(StoreFile::Middleware, &exact_limit).unwrap();
        assert_eq!(
            read_stored_middleware_history(&store)
                .unwrap()
                .records
                .len(),
            MAX_HISTORY_RECORDS
        );

        let too_many = StoredMiddlewareHistory {
            records: vec![record.clone(); MAX_HISTORY_RECORDS + 1],
        };
        store.write(StoreFile::Middleware, &too_many).unwrap();
        let encoded_error = read_stored_middleware_history(&store).unwrap_err();
        assert!(matches!(
            &encoded_error,
            CoreError::Decode {
                subject: "middleware changes",
                ..
            }
        ));
        assert!(
            encoded_error
                .to_string()
                .contains("middleware history record count exceeds its storage budget")
        );
        assert!(matches!(
            validate_stored_middleware_history(&too_many),
            Err(CoreError::Validation {
                subject: "middleware change history",
                ..
            })
        ));

        let mut oversized_text = record;
        oversized_text.old_sha256 = "x".repeat(MAX_MIDDLEWARE_HISTORY_RECORD_TEXT_BYTES + 1);
        assert!(matches!(
            validate_stored_middleware_history(&StoredMiddlewareHistory {
                records: vec![oversized_text],
            }),
            Err(CoreError::Validation {
                subject: "middleware change history",
                ..
            })
        ));
    }
}
