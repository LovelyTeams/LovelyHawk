//! Read-only, capability-based SFTP browser boundary for Electron.
//!
//! Remote paths, target identity, raw session data, and SFTP requests remain
//! sidecar-owned. The renderer can only traverse or preview entries that were
//! returned as binding- and browser-scoped opaque capabilities.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use lovelyres_core::{
    BackendServices, CoreError,
    path_guard::PathGuard,
    sftp::{BoundSftpSession, MAX_DIRECTORY_ENTRIES, RemotePath, SftpEntry, SftpFileKind},
    ssh::BoundSshSession,
    target::TargetGuard,
};
use serde::Serialize;
use tokio::time::timeout;
use uuid::Uuid;

use crate::ssh_api::SshApi;

const MAX_HANDLE_BYTES: usize = 128;
const MAX_DISPLAYED_ENTRIES: usize = 128;
// Entry names and directory labels cross the boundary through the same
// normaliser, so they share one ceiling.
const MAX_ENTRY_NAME_BYTES: usize = 256;
const MAX_NAVIGATION_DEPTH: usize = 64;
const MAX_BROWSERS: usize = 4;
const MAX_BROWSER_BYTES: usize = 1024 * 1024;
const MAX_REGISTRY_BYTES: usize = 4 * 1024 * 1024;
const MAX_ACTIVE_OPENS: usize = 2;
const MAX_ACTIVE_OPERATIONS: usize = 4;
const MAX_CORE_TEXT_BYTES: usize = 2 * 1024 * 1024;
const MAX_TEXT_LINES: usize = 2_000;
const MAX_TEXT_LINE_BYTES: usize = 4 * 1024;
const MAX_TEXT_BYTES: usize = 256 * 1024;
const MAX_DIRECTORY_RESPONSE_BYTES: usize = 128 * 1024;
const MAX_TEXT_RESPONSE_BYTES: usize = 384 * 1024;
const BROWSER_TTL: Duration = Duration::from_secs(5 * 60);
const BIND_DEADLINE: Duration = Duration::from_secs(15);
const LIST_DEADLINE: Duration = Duration::from_secs(20);
const READ_DEADLINE: Duration = Duration::from_secs(20);
const TRANSFER_DEADLINE: Duration = Duration::from_secs(180);
// Names and file text cross the boundary as the target has them. Blanking a
// file called "secret_key" or a config line containing "password=" removes the
// very thing the operator opened the browser to look at.
const ROOT_LABEL: &str = "根目录";

#[derive(Clone)]
pub(crate) struct SftpBrowserApi {
    services: BackendServices,
    ssh_api: Arc<SshApi>,
    registry: Arc<Mutex<SftpBrowserRegistry>>,
    /// Owns which local paths a transfer may touch; the renderer never sees one.
    paths: Arc<PathGuard>,
}

impl fmt::Debug for SftpBrowserApi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (browsers, bytes, opens, operations) = self
            .registry
            .lock()
            .map(|registry| {
                (
                    registry.browsers.len(),
                    registry.total_bytes(),
                    registry.active_open_bindings.len(),
                    registry.active_operations.len(),
                )
            })
            .unwrap_or_default();
        formatter
            .debug_struct("SftpBrowserApi")
            .field("browser_count", &browsers)
            .field("registry_bytes", &bytes)
            .field("active_opens", &opens)
            .field("active_operations", &operations)
            .finish()
    }
}

impl SftpBrowserApi {
    pub(crate) fn new(services: BackendServices, ssh_api: Arc<SshApi>) -> Self {
        let staging = services.store().root().join("sftp-staging");
        let paths = PathGuard::new(staging, [])
            .expect("the portable store root is always writable at startup");
        Self {
            services,
            ssh_api,
            registry: Arc::new(Mutex::new(SftpBrowserRegistry::default())),
            paths: Arc::new(paths),
        }
    }

    /// Copies one remote file to a local path the operator picked in the save
    /// dialog. The path arrives from main, never from the renderer, and the
    /// core refuses anything outside what a save dialog can produce.
    pub(crate) async fn download_entry(
        &self,
        binding_handle: &str,
        browser_handle: &str,
        file_handle: &str,
        local_path: &Path,
    ) -> Result<SftpTransferDto, SftpBrowserApiError> {
        validate_handle(browser_handle)?;
        validate_handle(file_handle)?;
        let (_, scope) = self.capture_binding(binding_handle)?;
        let (access, _permit) =
            self.begin_operation(&scope, browser_handle, file_handle, EntryAction::Preview)?;
        let session = self.bind_sftp(&scope).await?;
        self.validate_binding(&scope)?;
        self.verify_operation(&access)?;
        let receipt = timeout(
            TRANSFER_DEADLINE,
            self.services
                .sftp()
                .download_new(&session, &self.paths, &access.node.path, local_path),
        )
        .await
        .map_err(|_| SftpBrowserApiError::Deadline)??;
        self.validate_binding(&scope)?;
        validate_sftp_session(&scope, &session)?;
        self.verify_operation(&access)?;
        Ok(SftpTransferDto {
            browser_handle: access.browser_handle.clone(),
            file_handle: access.node.handle.clone(),
            bytes: receipt.bytes.to_string(),
        })
    }

    pub(crate) async fn open_sftp_browser(
        &self,
        binding_handle: &str,
    ) -> Result<SftpDirectoryDto, SftpBrowserApiError> {
        let (_, scope) = self.capture_binding(binding_handle)?;
        let _permit = self.begin_open(&scope)?;
        let session = self.bind_sftp(&scope).await?;
        self.validate_binding(&scope)?;
        let root = RemotePath::new("/").map_err(|_| SftpBrowserApiError::InvalidListing)?;
        let entries = timeout(LIST_DEADLINE, self.services.sftp().list(&session, &root))
            .await
            .map_err(|_| SftpBrowserApiError::Deadline)??;
        self.validate_binding(&scope)?;
        validate_sftp_session(&scope, &session)?;

        let now = Instant::now();
        let (browser, dto) = BrowserSnapshot::from_root(scope.clone(), entries, now)?;
        ensure_serialized_bound(&dto, MAX_DIRECTORY_RESPONSE_BYTES)?;
        let browser_handle = browser.browser_handle.clone();
        let browser_token = browser.token;
        let directory_handle = browser.root_handle.clone();
        let revision = browser.revision;
        let mut registry = self.lock_registry()?;
        registry.prune(now);
        registry.replace(browser)?;
        drop(registry);

        self.validate_binding(&scope)?;
        self.verify_directory_response(
            &scope,
            &browser_handle,
            browser_token,
            &directory_handle,
            revision,
        )?;
        Ok(dto)
    }

    pub(crate) async fn list_sftp_directory(
        &self,
        binding_handle: &str,
        browser_handle: &str,
        directory_handle: &str,
    ) -> Result<SftpDirectoryDto, SftpBrowserApiError> {
        validate_handle(browser_handle)?;
        validate_handle(directory_handle)?;
        let (_, scope) = self.capture_binding(binding_handle)?;
        let (access, _permit) = self.begin_operation(
            &scope,
            browser_handle,
            directory_handle,
            EntryAction::Browse,
        )?;
        let session = self.bind_sftp(&scope).await?;
        self.validate_binding(&scope)?;
        self.verify_operation(&access)?;
        let entries = timeout(
            LIST_DEADLINE,
            self.services.sftp().list(&session, &access.node.path),
        )
        .await
        .map_err(|_| SftpBrowserApiError::Deadline)??;
        self.validate_binding(&scope)?;
        validate_sftp_session(&scope, &session)?;
        self.verify_operation(&access)?;

        let receipt = {
            let mut registry = self.lock_registry()?;
            registry.apply_listing(&access, entries, Instant::now())?
        };
        if ensure_serialized_bound(&receipt.dto, MAX_DIRECTORY_RESPONSE_BYTES).is_err() {
            self.invalidate_browser(&access.browser_handle);
            return Err(SftpBrowserApiError::Capacity);
        }
        self.validate_binding(&scope)?;
        self.verify_directory_response(
            &scope,
            &receipt.browser_handle,
            receipt.browser_token,
            &receipt.directory_handle,
            receipt.revision,
        )?;
        Ok(receipt.dto)
    }

    pub(crate) async fn read_sftp_text(
        &self,
        binding_handle: &str,
        browser_handle: &str,
        file_handle: &str,
    ) -> Result<SftpTextPreviewDto, SftpBrowserApiError> {
        validate_handle(browser_handle)?;
        validate_handle(file_handle)?;
        let (_, scope) = self.capture_binding(binding_handle)?;
        let (access, _permit) =
            self.begin_operation(&scope, browser_handle, file_handle, EntryAction::Preview)?;
        let session = self.bind_sftp(&scope).await?;
        self.validate_binding(&scope)?;
        self.verify_operation(&access)?;
        let source = timeout(
            READ_DEADLINE,
            self.services.sftp().read_text(&session, &access.node.path),
        )
        .await
        .map_err(|_| SftpBrowserApiError::Deadline)??;
        self.validate_binding(&scope)?;
        validate_sftp_session(&scope, &session)?;
        self.verify_operation(&access)?;

        let projected = project_text(&source)?;
        let dto = SftpTextPreviewDto {
            browser_handle: access.browser_handle.clone(),
            file_handle: access.node.handle.clone(),
            text: projected.text,
            observed_line_count: projected.observed_line_count,
            displayed_line_count: projected.displayed_line_count,
            truncated: projected.truncated,
        };
        ensure_serialized_bound(&dto, MAX_TEXT_RESPONSE_BYTES)?;
        self.validate_binding(&scope)?;
        self.verify_operation(&access)?;
        Ok(dto)
    }

    fn capture_binding(
        &self,
        binding_handle: &str,
    ) -> Result<(BoundSshSession, BindingScope), SftpBrowserApiError> {
        validate_handle(binding_handle)?;
        let session = self
            .ssh_api
            .binding_session_clone(binding_handle)
            .map_err(|_| SftpBrowserApiError::BindingUnavailable)?;
        self.services
            .target()
            .validate(session.target())
            .map_err(|_| SftpBrowserApiError::BindingUnavailable)?;
        let scope = BindingScope::from_session(binding_handle, &session);
        Ok((session, scope))
    }

    async fn bind_sftp(
        &self,
        scope: &BindingScope,
    ) -> Result<BoundSftpSession, SftpBrowserApiError> {
        self.validate_binding(scope)?;
        let session = timeout(
            BIND_DEADLINE,
            self.services
                .sftp()
                .bind_session(scope.target.clone(), &scope.session_id),
        )
        .await
        .map_err(|_| SftpBrowserApiError::Deadline)??;
        self.validate_binding(scope)?;
        validate_sftp_session(scope, &session)?;
        Ok(session)
    }

    fn validate_binding(&self, expected: &BindingScope) -> Result<(), SftpBrowserApiError> {
        let (_, current) = self.capture_binding(&expected.binding_handle)?;
        if &current != expected {
            return Err(SftpBrowserApiError::BindingUnavailable);
        }
        Ok(())
    }

    fn begin_open(&self, scope: &BindingScope) -> Result<OpenPermit, SftpBrowserApiError> {
        let mut registry = self.lock_registry()?;
        registry.prune(Instant::now());
        registry.begin_open(scope)?;
        Ok(OpenPermit {
            registry: Arc::clone(&self.registry),
            binding_handle: scope.binding_handle.clone(),
        })
    }

    fn begin_operation(
        &self,
        scope: &BindingScope,
        browser_handle: &str,
        entry_handle: &str,
        required_action: EntryAction,
    ) -> Result<(OperationAccess, OperationPermit), SftpBrowserApiError> {
        let mut registry = self.lock_registry()?;
        registry.prune(Instant::now());
        let access = registry.begin_operation(
            scope,
            browser_handle,
            entry_handle,
            required_action,
            Instant::now(),
        )?;
        let permit = OperationPermit {
            registry: Arc::clone(&self.registry),
            operation_token: access.operation_token,
        };
        Ok((access, permit))
    }

    fn verify_operation(&self, access: &OperationAccess) -> Result<(), SftpBrowserApiError> {
        self.lock_registry()?
            .verify_operation(access, Instant::now())
    }

    fn verify_directory_response(
        &self,
        scope: &BindingScope,
        browser_handle: &str,
        browser_token: Uuid,
        directory_handle: &str,
        revision: u64,
    ) -> Result<(), SftpBrowserApiError> {
        self.lock_registry()?.verify_directory_response(
            scope,
            browser_handle,
            browser_token,
            directory_handle,
            revision,
            Instant::now(),
        )
    }

    /// Drops every browser that belonged to a target that is going away.
    /// Drops every browser that belonged to a target that is going away.
    pub(crate) fn close_binding(&self, binding_handle: &str) {
        if let Ok(mut registry) = self.registry.lock() {
            registry
                .browsers
                .retain(|_, browser| browser.scope.binding_handle != binding_handle);
            registry.active_open_bindings.remove(binding_handle);
            registry
                .active_operations
                .retain(|_, operation| operation.binding_handle != binding_handle);
        }
    }

    fn invalidate_browser(&self, browser_handle: &str) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.browsers.remove(browser_handle);
        }
    }

    fn lock_registry(&self) -> Result<MutexGuard<'_, SftpBrowserRegistry>, SftpBrowserApiError> {
        self.registry
            .lock()
            .map_err(|_| SftpBrowserApiError::RegistryUnavailable)
    }
}

pub(crate) enum SftpBrowserApiError {
    Core,
    BindingUnavailable,
    InvalidHandle,
    BrowserStale,
    EntryUnavailable,
    InvalidListing,
    InvalidText,
    Busy,
    Capacity,
    Deadline,
    RegistryUnavailable,
}

impl fmt::Debug for SftpBrowserApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core => "Core([REDACTED])",
            Self::BindingUnavailable => "BindingUnavailable",
            Self::InvalidHandle => "InvalidHandle",
            Self::BrowserStale => "BrowserStale",
            Self::EntryUnavailable => "EntryUnavailable",
            Self::InvalidListing => "InvalidListing",
            Self::InvalidText => "InvalidText",
            Self::Busy => "Busy",
            Self::Capacity => "Capacity",
            Self::Deadline => "Deadline",
            Self::RegistryUnavailable => "RegistryUnavailable",
        })
    }
}

impl fmt::Display for SftpBrowserApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core => "the SFTP browser operation failed",
            Self::BindingUnavailable => "the SSH binding is missing or stale",
            Self::InvalidHandle => "the SFTP browser capability is invalid",
            Self::BrowserStale => "the SFTP browser capability is missing or stale",
            Self::EntryUnavailable => "the selected SFTP entry cannot be opened",
            Self::InvalidListing => "the SFTP directory result was rejected",
            Self::InvalidText => "the SFTP text result was rejected",
            Self::Busy => "the SFTP browser boundary is busy",
            Self::Capacity => "the SFTP browser boundary reached its capacity",
            Self::Deadline => "the SFTP browser operation exceeded its deadline",
            Self::RegistryUnavailable => "the SFTP browser registry is unavailable",
        })
    }
}

impl std::error::Error for SftpBrowserApiError {}

impl From<CoreError> for SftpBrowserApiError {
    fn from(_: CoreError) -> Self {
        Self::Core
    }
}

#[derive(Clone, PartialEq, Eq)]
struct BindingScope {
    binding_handle: String,
    session_id: String,
    connection_id: String,
    target: TargetGuard,
}

impl BindingScope {
    fn from_session(binding_handle: &str, session: &BoundSshSession) -> Self {
        Self {
            binding_handle: binding_handle.to_owned(),
            session_id: session.session_id().to_owned(),
            connection_id: session.connection_id().to_owned(),
            target: session.target().clone(),
        }
    }

    fn estimated_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(self.binding_handle.len())
            .saturating_add(self.session_id.len())
            .saturating_add(self.connection_id.len())
            .saturating_add(self.target.identity.as_str().len())
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SftpBrowserEntryKind {
    Directory,
    File,
    Symlink,
    Other,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SftpBrowserEntryAction {
    Browse,
    Preview,
    None,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SftpDirectoryDto {
    pub(crate) browser_handle: String,
    pub(crate) directory_handle: String,
    pub(crate) parent_directory_handle: Option<String>,
    pub(crate) directory_label: String,
    pub(crate) directory_label_truncated: bool,
    pub(crate) expires_in_seconds: u64,
    pub(crate) observed_entry_count: u32,
    pub(crate) displayed_entry_count: u32,
    pub(crate) truncated: bool,
    pub(crate) entries: Vec<SftpBrowserEntryDto>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SftpBrowserEntryDto {
    pub(crate) entry_handle: String,
    pub(crate) name: String,
    pub(crate) name_truncated: bool,
    pub(crate) kind: SftpBrowserEntryKind,
    pub(crate) action: SftpBrowserEntryAction,
    pub(crate) size_bytes: String,
    pub(crate) modified_at: Option<String>,
}

/// What a finished transfer moved, in capability terms only.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SftpTransferDto {
    pub(crate) browser_handle: String,
    pub(crate) file_handle: String,
    /// A byte count as a decimal string, because it can exceed 2^53.
    pub(crate) bytes: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SftpTextPreviewDto {
    pub(crate) browser_handle: String,
    pub(crate) file_handle: String,
    pub(crate) text: String,
    pub(crate) observed_line_count: u32,
    pub(crate) displayed_line_count: u32,
    pub(crate) truncated: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EntryAction {
    Browse,
    Preview,
    None,
}

impl EntryAction {
    const fn dto(self) -> SftpBrowserEntryAction {
        match self {
            Self::Browse => SftpBrowserEntryAction::Browse,
            Self::Preview => SftpBrowserEntryAction::Preview,
            Self::None => SftpBrowserEntryAction::None,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct StoredNode {
    handle: String,
    path: RemotePath,
    kind: SftpBrowserEntryKind,
    action: EntryAction,
    parent_handle: Option<String>,
    depth: usize,
    display_name: String,
    name_truncated: bool,
    size_bytes: String,
    modified_at: Option<String>,
}

impl StoredNode {
    fn estimated_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(self.handle.len())
            .saturating_add(self.path.as_str().len())
            .saturating_add(self.parent_handle.as_ref().map_or(0, String::len))
            .saturating_add(self.display_name.len())
            .saturating_add(self.size_bytes.len())
            .saturating_add(self.modified_at.as_ref().map_or(0, String::len))
    }

    fn dto(&self) -> SftpBrowserEntryDto {
        SftpBrowserEntryDto {
            entry_handle: self.handle.clone(),
            name: self.display_name.clone(),
            name_truncated: self.name_truncated,
            kind: self.kind,
            action: self.action.dto(),
            size_bytes: self.size_bytes.clone(),
            modified_at: self.modified_at.clone(),
        }
    }
}

#[derive(Clone)]
struct BrowserSnapshot {
    browser_handle: String,
    token: Uuid,
    scope: BindingScope,
    root_handle: String,
    nodes: HashMap<String, StoredNode>,
    revision: u64,
    expires_at: Instant,
    last_used_at: Instant,
    stored_bytes: usize,
}

impl BrowserSnapshot {
    fn from_root(
        scope: BindingScope,
        entries: Vec<SftpEntry>,
        now: Instant,
    ) -> Result<(Self, SftpDirectoryDto), SftpBrowserApiError> {
        let browser_handle = Uuid::new_v4().to_string();
        let root_handle = Uuid::new_v4().to_string();
        let root = StoredNode {
            handle: root_handle.clone(),
            path: RemotePath::new("/").map_err(|_| SftpBrowserApiError::InvalidListing)?,
            kind: SftpBrowserEntryKind::Directory,
            action: EntryAction::Browse,
            parent_handle: None,
            depth: 0,
            display_name: ROOT_LABEL.to_owned(),
            name_truncated: false,
            size_bytes: "0".to_owned(),
            modified_at: None,
        };
        let mut nodes = HashMap::new();
        nodes.insert(root_handle.clone(), root);
        let mut browser = Self {
            browser_handle,
            token: Uuid::new_v4(),
            scope,
            root_handle: root_handle.clone(),
            nodes,
            revision: 0,
            expires_at: now + BROWSER_TTL,
            last_used_at: now,
            stored_bytes: 0,
        };
        let dto = browser.refresh_directory(&root_handle, entries, now)?;
        Ok((browser, dto))
    }

    fn refresh_directory(
        &mut self,
        directory_handle: &str,
        mut entries: Vec<SftpEntry>,
        now: Instant,
    ) -> Result<SftpDirectoryDto, SftpBrowserApiError> {
        if entries.len() > MAX_DIRECTORY_ENTRIES {
            return Err(SftpBrowserApiError::InvalidListing);
        }
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        if entries.windows(2).any(|pair| pair[0].path == pair[1].path) {
            return Err(SftpBrowserApiError::InvalidListing);
        }
        entries.sort_by(|left, right| {
            entry_kind(left.metadata.kind)
                .cmp(&entry_kind(right.metadata.kind))
                .then_with(|| left.name.cmp(&right.name))
        });

        let directory = self
            .nodes
            .get(directory_handle)
            .cloned()
            .ok_or(SftpBrowserApiError::BrowserStale)?;
        if directory.action != EntryAction::Browse {
            return Err(SftpBrowserApiError::EntryUnavailable);
        }
        let old_children = self
            .nodes
            .values()
            .filter(|node| node.parent_handle.as_deref() == Some(directory_handle))
            .map(|node| (node.path.clone(), node.clone()))
            .collect::<HashMap<_, _>>();
        let observed_entry_count =
            u32::try_from(entries.len()).map_err(|_| SftpBrowserApiError::InvalidListing)?;
        let truncated = entries.len() > MAX_DISPLAYED_ENTRIES;
        let mut projected = Vec::with_capacity(entries.len().min(MAX_DISPLAYED_ENTRIES));
        for entry in entries.into_iter().take(MAX_DISPLAYED_ENTRIES) {
            let kind = entry_kind(entry.metadata.kind);
            let depth = directory.depth.saturating_add(1);
            let action = match kind {
                SftpBrowserEntryKind::Directory if depth <= MAX_NAVIGATION_DEPTH => {
                    EntryAction::Browse
                }
                SftpBrowserEntryKind::File => EntryAction::Preview,
                _ => EntryAction::None,
            };
            let (display_name, name_truncated) = project_name(&entry.name);
            let existing = old_children
                .get(&entry.path)
                .filter(|node| node.kind == kind);
            projected.push(StoredNode {
                handle: existing
                    .map(|node| node.handle.clone())
                    .unwrap_or_else(|| Uuid::new_v4().to_string()),
                path: RemotePath::new(entry.path.as_str().to_owned())
                    .map_err(|_| SftpBrowserApiError::InvalidListing)?,
                kind,
                action,
                parent_handle: Some(directory_handle.to_owned()),
                depth,
                display_name,
                name_truncated,
                size_bytes: entry.metadata.size.to_string(),
                modified_at: entry.metadata.modified_at.map(|value| value.to_rfc3339()),
            });
        }

        let mut retained = HashMap::new();
        let mut cursor = Some(directory_handle.to_owned());
        while let Some(handle) = cursor {
            let node = self
                .nodes
                .get(&handle)
                .cloned()
                .ok_or(SftpBrowserApiError::BrowserStale)?;
            cursor = node.parent_handle.clone();
            retained.insert(handle, node);
        }
        for node in projected {
            retained.insert(node.handle.clone(), node);
        }
        self.nodes = retained;
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(SftpBrowserApiError::Capacity)?;
        self.last_used_at = now;
        self.stored_bytes = self.estimated_bytes();
        if self.stored_bytes > MAX_BROWSER_BYTES
            || self.nodes.len() > MAX_NAVIGATION_DEPTH + 1 + MAX_DISPLAYED_ENTRIES
        {
            return Err(SftpBrowserApiError::Capacity);
        }
        self.directory_dto(directory_handle, observed_entry_count, truncated, now)
    }

    fn directory_dto(
        &self,
        directory_handle: &str,
        observed_entry_count: u32,
        truncated: bool,
        now: Instant,
    ) -> Result<SftpDirectoryDto, SftpBrowserApiError> {
        let directory = self
            .nodes
            .get(directory_handle)
            .ok_or(SftpBrowserApiError::BrowserStale)?;
        let mut entries = self
            .nodes
            .values()
            .filter(|node| node.parent_handle.as_deref() == Some(directory_handle))
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| {
            left.kind
                .cmp(&right.kind)
                .then_with(|| left.display_name.cmp(&right.display_name))
                .then_with(|| left.handle.cmp(&right.handle))
        });
        let displayed_entry_count =
            u32::try_from(entries.len()).map_err(|_| SftpBrowserApiError::InvalidListing)?;
        Ok(SftpDirectoryDto {
            browser_handle: self.browser_handle.clone(),
            directory_handle: directory.handle.clone(),
            parent_directory_handle: directory.parent_handle.clone(),
            directory_label: directory.display_name.clone(),
            directory_label_truncated: directory.name_truncated,
            expires_in_seconds: remaining_seconds(self.expires_at, now)?,
            observed_entry_count,
            displayed_entry_count,
            truncated,
            entries: entries.into_iter().map(StoredNode::dto).collect(),
        })
    }

    fn estimated_bytes(&self) -> usize {
        self.scope
            .estimated_bytes()
            .saturating_add(std::mem::size_of::<Self>())
            .saturating_add(self.browser_handle.len())
            .saturating_add(self.root_handle.len())
            .saturating_add(
                self.nodes
                    .iter()
                    .map(|(handle, node)| {
                        node.estimated_bytes()
                            .saturating_add(handle.len())
                            .saturating_add(128)
                    })
                    .fold(0usize, usize::saturating_add),
            )
    }

    fn registry_bytes(&self) -> usize {
        self.stored_bytes
            .saturating_add(self.browser_handle.len())
            .saturating_add(128)
    }
}

#[derive(Clone, PartialEq, Eq)]
struct OperationAccess {
    browser_handle: String,
    browser_token: Uuid,
    operation_token: Uuid,
    scope: BindingScope,
    node: StoredNode,
    required_action: EntryAction,
}

struct ActiveOperation {
    browser_handle: String,
    browser_token: Uuid,
    binding_handle: String,
}

struct DirectoryReceipt {
    dto: SftpDirectoryDto,
    browser_handle: String,
    browser_token: Uuid,
    directory_handle: String,
    revision: u64,
}

#[derive(Default)]
struct SftpBrowserRegistry {
    browsers: HashMap<String, BrowserSnapshot>,
    active_open_bindings: HashSet<String>,
    active_operations: HashMap<Uuid, ActiveOperation>,
}

impl SftpBrowserRegistry {
    fn total_bytes(&self) -> usize {
        let browsers = self
            .browsers
            .values()
            .map(BrowserSnapshot::registry_bytes)
            .fold(0usize, usize::saturating_add);
        let opens = self
            .active_open_bindings
            .iter()
            .fold(0usize, |total, binding| {
                total.saturating_add(binding.len()).saturating_add(64)
            });
        let operations = self
            .active_operations
            .values()
            .fold(0usize, |total, operation| {
                total
                    .saturating_add(std::mem::size_of::<ActiveOperation>())
                    .saturating_add(operation.browser_handle.len())
                    .saturating_add(operation.binding_handle.len())
                    .saturating_add(64)
            });
        browsers.saturating_add(opens).saturating_add(operations)
    }

    fn begin_open(&mut self, scope: &BindingScope) -> Result<(), SftpBrowserApiError> {
        if self.active_open_bindings.len() >= MAX_ACTIVE_OPENS
            || self.active_open_bindings.contains(&scope.binding_handle)
            || self
                .active_operations
                .values()
                .any(|operation| operation.binding_handle == scope.binding_handle)
        {
            return Err(SftpBrowserApiError::Busy);
        }
        self.active_open_bindings
            .insert(scope.binding_handle.clone());
        Ok(())
    }

    fn finish_open(&mut self, binding_handle: &str) {
        self.active_open_bindings.remove(binding_handle);
    }

    fn replace(&mut self, browser: BrowserSnapshot) -> Result<(), SftpBrowserApiError> {
        if browser.stored_bytes > MAX_BROWSER_BYTES || browser.registry_bytes() > MAX_REGISTRY_BYTES
        {
            return Err(SftpBrowserApiError::Capacity);
        }
        let binding_handle = browser.scope.binding_handle.clone();
        self.browsers
            .retain(|_, stored| stored.scope.binding_handle != binding_handle);
        while self.browsers.len() >= MAX_BROWSERS
            || self.total_bytes().saturating_add(browser.registry_bytes()) > MAX_REGISTRY_BYTES
        {
            let Some(handle) = self
                .browsers
                .iter()
                .filter(|(handle, _)| !self.browser_is_active(handle))
                .min_by_key(|(_, stored)| stored.last_used_at)
                .map(|(handle, _)| handle.clone())
            else {
                return Err(SftpBrowserApiError::Capacity);
            };
            self.browsers.remove(&handle);
        }
        self.browsers
            .insert(browser.browser_handle.clone(), browser);
        Ok(())
    }

    fn begin_operation(
        &mut self,
        scope: &BindingScope,
        browser_handle: &str,
        entry_handle: &str,
        required_action: EntryAction,
        now: Instant,
    ) -> Result<OperationAccess, SftpBrowserApiError> {
        if self.active_operations.len() >= MAX_ACTIVE_OPERATIONS
            || self.active_open_bindings.contains(&scope.binding_handle)
            || self
                .active_operations
                .values()
                .any(|operation| operation.browser_handle == browser_handle)
        {
            return Err(SftpBrowserApiError::Busy);
        }
        let browser = self
            .browsers
            .get(browser_handle)
            .ok_or(SftpBrowserApiError::BrowserStale)?;
        if &browser.scope != scope || browser.expires_at <= now {
            return Err(SftpBrowserApiError::BrowserStale);
        }
        let node = browser
            .nodes
            .get(entry_handle)
            .filter(|node| node.action == required_action)
            .cloned()
            .ok_or(SftpBrowserApiError::EntryUnavailable)?;
        let operation_token = Uuid::new_v4();
        let access = OperationAccess {
            browser_handle: browser_handle.to_owned(),
            browser_token: browser.token,
            operation_token,
            scope: scope.clone(),
            node,
            required_action,
        };
        self.active_operations.insert(
            operation_token,
            ActiveOperation {
                browser_handle: browser_handle.to_owned(),
                browser_token: browser.token,
                binding_handle: scope.binding_handle.clone(),
            },
        );
        Ok(access)
    }

    fn verify_operation(
        &self,
        access: &OperationAccess,
        now: Instant,
    ) -> Result<(), SftpBrowserApiError> {
        let active = self
            .active_operations
            .get(&access.operation_token)
            .ok_or(SftpBrowserApiError::BrowserStale)?;
        let browser = self
            .browsers
            .get(&access.browser_handle)
            .ok_or(SftpBrowserApiError::BrowserStale)?;
        if active.browser_handle != access.browser_handle
            || active.browser_token != access.browser_token
            || active.binding_handle != access.scope.binding_handle
            || browser.token != access.browser_token
            || browser.scope != access.scope
            || browser.expires_at <= now
            || browser.nodes.get(&access.node.handle) != Some(&access.node)
            || access.node.action != access.required_action
        {
            return Err(SftpBrowserApiError::BrowserStale);
        }
        Ok(())
    }

    fn apply_listing(
        &mut self,
        access: &OperationAccess,
        entries: Vec<SftpEntry>,
        now: Instant,
    ) -> Result<DirectoryReceipt, SftpBrowserApiError> {
        self.verify_operation(access, now)?;
        let current = self
            .browsers
            .get(&access.browser_handle)
            .cloned()
            .ok_or(SftpBrowserApiError::BrowserStale)?;
        let mut candidate = current.clone();
        let dto = candidate.refresh_directory(&access.node.handle, entries, now)?;
        let projected_total = self
            .total_bytes()
            .saturating_sub(current.registry_bytes())
            .saturating_add(candidate.registry_bytes());
        if candidate.stored_bytes > MAX_BROWSER_BYTES || projected_total > MAX_REGISTRY_BYTES {
            return Err(SftpBrowserApiError::Capacity);
        }
        let revision = candidate.revision;
        self.browsers
            .insert(access.browser_handle.clone(), candidate);
        Ok(DirectoryReceipt {
            dto,
            browser_handle: access.browser_handle.clone(),
            browser_token: access.browser_token,
            directory_handle: access.node.handle.clone(),
            revision,
        })
    }

    fn verify_directory_response(
        &self,
        scope: &BindingScope,
        browser_handle: &str,
        browser_token: Uuid,
        directory_handle: &str,
        revision: u64,
        now: Instant,
    ) -> Result<(), SftpBrowserApiError> {
        let browser = self
            .browsers
            .get(browser_handle)
            .ok_or(SftpBrowserApiError::BrowserStale)?;
        if browser.token != browser_token
            || &browser.scope != scope
            || browser.revision != revision
            || browser.expires_at <= now
            || browser
                .nodes
                .get(directory_handle)
                .is_none_or(|node| node.action != EntryAction::Browse)
        {
            return Err(SftpBrowserApiError::BrowserStale);
        }
        Ok(())
    }

    fn finish_operation(&mut self, operation_token: Uuid) {
        self.active_operations.remove(&operation_token);
    }

    fn prune(&mut self, now: Instant) {
        let active = self
            .active_operations
            .values()
            .map(|operation| operation.browser_handle.as_str())
            .collect::<HashSet<_>>();
        self.browsers
            .retain(|handle, browser| browser.expires_at > now || active.contains(handle.as_str()));
    }

    fn browser_is_active(&self, browser_handle: &str) -> bool {
        self.active_operations
            .values()
            .any(|operation| operation.browser_handle == browser_handle)
    }
}

struct OpenPermit {
    registry: Arc<Mutex<SftpBrowserRegistry>>,
    binding_handle: String,
}

impl Drop for OpenPermit {
    fn drop(&mut self) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.finish_open(&self.binding_handle);
        }
    }
}

struct OperationPermit {
    registry: Arc<Mutex<SftpBrowserRegistry>>,
    operation_token: Uuid,
}

impl Drop for OperationPermit {
    fn drop(&mut self) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.finish_operation(self.operation_token);
        }
    }
}

struct ProjectedText {
    text: String,
    observed_line_count: u32,
    displayed_line_count: u32,
    truncated: bool,
}

fn project_text(source: &str) -> Result<ProjectedText, SftpBrowserApiError> {
    if source.len() > MAX_CORE_TEXT_BYTES {
        return Err(SftpBrowserApiError::InvalidText);
    }
    let observed = source.lines().count();
    let observed_line_count =
        u32::try_from(observed).map_err(|_| SftpBrowserApiError::InvalidText)?;
    let mut lines = Vec::with_capacity(observed.min(MAX_TEXT_LINES));
    let mut bytes = 0usize;
    let mut truncated = false;
    for line in source.lines() {
        if lines.len() >= MAX_TEXT_LINES {
            truncated = true;
            break;
        }
        // Only control characters and the per-line ceiling are applied.
        let (projected, line_truncated) = normalize_plain_text(line, MAX_TEXT_LINE_BYTES);
        let separator = usize::from(!lines.is_empty());
        if bytes
            .saturating_add(separator)
            .saturating_add(projected.len())
            > MAX_TEXT_BYTES
        {
            truncated = true;
            break;
        }
        bytes = bytes
            .saturating_add(separator)
            .saturating_add(projected.len());
        truncated |= line_truncated;
        lines.push(projected);
    }
    truncated |= observed > lines.len();
    Ok(ProjectedText {
        text: lines.join("\n"),
        observed_line_count,
        displayed_line_count: u32::try_from(lines.len())
            .map_err(|_| SftpBrowserApiError::InvalidText)?,
        truncated,
    })
}

fn project_name(value: &str) -> (String, bool) {
    normalize_plain_text(value, MAX_ENTRY_NAME_BYTES)
}

fn normalize_plain_text(value: &str, maximum_bytes: usize) -> (String, bool) {
    let mut output = String::with_capacity(value.len().min(maximum_bytes));
    let mut truncated = false;
    for character in value.chars() {
        let replacement = if character == '\t' || !character.is_control() {
            character
        } else {
            '\u{fffd}'
        };
        if output.len().saturating_add(replacement.len_utf8()) > maximum_bytes {
            truncated = true;
            break;
        }
        output.push(replacement);
    }
    (output, truncated)
}

const fn entry_kind(value: SftpFileKind) -> SftpBrowserEntryKind {
    match value {
        SftpFileKind::Directory => SftpBrowserEntryKind::Directory,
        SftpFileKind::File => SftpBrowserEntryKind::File,
        SftpFileKind::Symlink => SftpBrowserEntryKind::Symlink,
        SftpFileKind::Other => SftpBrowserEntryKind::Other,
    }
}

fn validate_sftp_session(
    scope: &BindingScope,
    session: &BoundSftpSession,
) -> Result<(), SftpBrowserApiError> {
    if session.session_id() != scope.session_id
        || session.connection_id() != scope.connection_id
        || session.target() != &scope.target
    {
        return Err(SftpBrowserApiError::BindingUnavailable);
    }
    Ok(())
}

fn validate_handle(value: &str) -> Result<(), SftpBrowserApiError> {
    if value.is_empty()
        || value.len() > MAX_HANDLE_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(SftpBrowserApiError::InvalidHandle);
    }
    Ok(())
}

fn remaining_seconds(expires_at: Instant, now: Instant) -> Result<u64, SftpBrowserApiError> {
    if expires_at <= now {
        return Err(SftpBrowserApiError::BrowserStale);
    }
    Ok(expires_at
        .saturating_duration_since(now)
        .as_secs()
        .saturating_add(1)
        .min(BROWSER_TTL.as_secs()))
}

fn ensure_serialized_bound<T: Serialize>(
    value: &T,
    maximum_bytes: usize,
) -> Result<(), SftpBrowserApiError> {
    let bytes = serde_json::to_vec(value).map_err(|_| SftpBrowserApiError::InvalidListing)?;
    if bytes.len() > maximum_bytes {
        return Err(SftpBrowserApiError::Capacity);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use lovelyres_core::{
        sftp::SftpMetadata,
        target::{TargetContext, TargetIdentity},
    };

    use super::*;

    fn scope(binding: &str, identity: &str, generation: usize) -> BindingScope {
        let target = TargetContext::new();
        let mut guard = target
            .activate(TargetIdentity::new(identity).unwrap())
            .unwrap();
        for _ in 0..generation {
            guard = target
                .activate(TargetIdentity::new(identity).unwrap())
                .unwrap();
        }
        BindingScope {
            binding_handle: binding.to_owned(),
            session_id: format!("session-{identity}"),
            connection_id: identity.to_owned(),
            target: guard,
        }
    }

    fn entry(parent: &str, name: &str, kind: SftpFileKind) -> SftpEntry {
        let parent = RemotePath::new(parent).unwrap();
        SftpEntry {
            name: name.to_owned(),
            path: parent.child(name).unwrap(),
            metadata: SftpMetadata {
                size: 42,
                permissions: Some(0o640),
                uid: Some(1000),
                gid: Some(1000),
                modified_at: None,
                kind,
            },
        }
    }

    #[test]
    fn root_listing_maps_paths_and_entry_types_to_opaque_capabilities() {
        let private_scope = scope("binding-private", "target-private", 0);
        let (browser, dto) = BrowserSnapshot::from_root(
            private_scope,
            vec![
                entry("/", "etc", SftpFileKind::Directory),
                entry("/", "evidence.txt", SftpFileKind::File),
                entry("/", "latest", SftpFileKind::Symlink),
                entry("/", "socket", SftpFileKind::Other),
            ],
            Instant::now(),
        )
        .unwrap();
        assert_eq!(dto.directory_label, ROOT_LABEL);
        assert!(dto.parent_directory_handle.is_none());
        assert_eq!(dto.displayed_entry_count, 4);
        assert_eq!(dto.observed_entry_count, 4);
        assert!(!dto.truncated);
        assert_eq!(browser.nodes.len(), 5);
        assert!(dto.entries.iter().any(|entry| {
            entry.name == "etc" && entry.action == SftpBrowserEntryAction::Browse
        }));
        assert!(dto.entries.iter().any(|entry| {
            entry.name == "evidence.txt" && entry.action == SftpBrowserEntryAction::Preview
        }));
        assert!(
            dto.entries
                .iter()
                .filter(|entry| {
                    matches!(
                        entry.kind,
                        SftpBrowserEntryKind::Symlink | SftpBrowserEntryKind::Other
                    )
                })
                .all(|entry| entry.action == SftpBrowserEntryAction::None)
        );
        let encoded = serde_json::to_string(&dto).unwrap();
        for forbidden in [
            "binding-private",
            "target-private",
            "session-target-private",
            "remotePath",
            "sessionId",
            "connectionId",
            "fingerprint",
            "permissions",
            "uid",
            "gid",
            "\"/etc\"",
        ] {
            assert!(!encoded.contains(forbidden), "encoded {forbidden}");
        }
        assert!(encoded.len() <= MAX_DIRECTORY_RESPONSE_BYTES);
    }

    #[test]
    fn registry_scopes_handles_rotates_on_open_and_rejects_symlink_actions() {
        let now = Instant::now();
        let original_scope = scope("binding-one", "target-one", 0);
        let (first, first_dto) = BrowserSnapshot::from_root(
            original_scope.clone(),
            vec![
                entry("/", "dir", SftpFileKind::Directory),
                entry("/", "link", SftpFileKind::Symlink),
            ],
            now,
        )
        .unwrap();
        let first_handle = first.browser_handle.clone();
        let directory = first_dto
            .entries
            .iter()
            .find(|entry| entry.name == "dir")
            .unwrap()
            .entry_handle
            .clone();
        let symlink = first_dto
            .entries
            .iter()
            .find(|entry| entry.name == "link")
            .unwrap()
            .entry_handle
            .clone();
        let mut registry = SftpBrowserRegistry::default();
        registry.replace(first).unwrap();
        let access = registry
            .begin_operation(
                &original_scope,
                &first_handle,
                &directory,
                EntryAction::Browse,
                now,
            )
            .unwrap();
        assert!(matches!(
            registry.begin_operation(
                &original_scope,
                &first_handle,
                &directory,
                EntryAction::Browse,
                now,
            ),
            Err(SftpBrowserApiError::Busy)
        ));
        registry.finish_operation(access.operation_token);
        assert!(matches!(
            registry.begin_operation(
                &original_scope,
                &first_handle,
                &symlink,
                EntryAction::Browse,
                now,
            ),
            Err(SftpBrowserApiError::EntryUnavailable)
        ));

        let changed_generation = scope("binding-one", "target-one", 1);
        assert!(matches!(
            registry.begin_operation(
                &changed_generation,
                &first_handle,
                &directory,
                EntryAction::Browse,
                now,
            ),
            Err(SftpBrowserApiError::BrowserStale)
        ));
        let (replacement, _) =
            BrowserSnapshot::from_root(original_scope, Vec::new(), now + Duration::from_millis(1))
                .unwrap();
        let replacement_handle = replacement.browser_handle.clone();
        registry.replace(replacement).unwrap();
        assert!(!registry.browsers.contains_key(&first_handle));
        assert!(registry.browsers.contains_key(&replacement_handle));
    }

    #[test]
    fn directory_refresh_preserves_matching_handles_and_computes_parent_in_registry() {
        let now = Instant::now();
        let private_scope = scope("binding-one", "target-one", 0);
        let (browser, root_dto) = BrowserSnapshot::from_root(
            private_scope.clone(),
            vec![entry("/", "etc", SftpFileKind::Directory)],
            now,
        )
        .unwrap();
        let browser_handle = browser.browser_handle.clone();
        let directory_handle = root_dto.entries[0].entry_handle.clone();
        let root_handle = root_dto.directory_handle.clone();
        let mut registry = SftpBrowserRegistry::default();
        registry.replace(browser).unwrap();
        let access = registry
            .begin_operation(
                &private_scope,
                &browser_handle,
                &directory_handle,
                EntryAction::Browse,
                now,
            )
            .unwrap();
        let receipt = registry
            .apply_listing(
                &access,
                vec![entry("/etc", "config", SftpFileKind::File)],
                now + Duration::from_millis(1),
            )
            .unwrap();
        assert_eq!(receipt.dto.parent_directory_handle, Some(root_handle));
        assert_eq!(receipt.dto.directory_label, "etc");
        let file_handle = receipt.dto.entries[0].entry_handle.clone();
        registry.finish_operation(access.operation_token);

        let access = registry
            .begin_operation(
                &private_scope,
                &browser_handle,
                &directory_handle,
                EntryAction::Browse,
                now + Duration::from_millis(2),
            )
            .unwrap();
        let refreshed = registry
            .apply_listing(
                &access,
                vec![entry("/etc", "config", SftpFileKind::File)],
                now + Duration::from_millis(3),
            )
            .unwrap();
        assert_eq!(refreshed.dto.entries[0].entry_handle, file_handle);
        registry.finish_operation(access.operation_token);
    }

    #[test]
    fn listing_and_registry_are_entry_ttl_memory_and_capacity_bounded() {
        let now = Instant::now();
        let entries = (0..MAX_DISPLAYED_ENTRIES + 20)
            .map(|index| entry("/", &format!("item-{index:03}"), SftpFileKind::File))
            .collect();
        let (mut browser, dto) =
            BrowserSnapshot::from_root(scope("binding", "target", 0), entries, now).unwrap();
        assert_eq!(dto.displayed_entry_count, MAX_DISPLAYED_ENTRIES as u32);
        assert_eq!(
            dto.observed_entry_count,
            (MAX_DISPLAYED_ENTRIES + 20) as u32
        );
        assert!(dto.truncated);
        assert!(browser.stored_bytes <= MAX_BROWSER_BYTES);
        assert!(browser.nodes.len() <= MAX_NAVIGATION_DEPTH + 1 + MAX_DISPLAYED_ENTRIES);
        browser.expires_at = now;
        let mut registry = SftpBrowserRegistry::default();
        registry.replace(browser).unwrap();
        registry.prune(now);
        assert!(registry.browsers.is_empty());

        for index in 0..MAX_BROWSERS + 1 {
            let (browser, _) = BrowserSnapshot::from_root(
                scope(&format!("binding-{index}"), &format!("target-{index}"), 0),
                Vec::new(),
                now + Duration::from_millis(index as u64),
            )
            .unwrap();
            registry.replace(browser).unwrap();
        }
        assert_eq!(registry.browsers.len(), MAX_BROWSERS);
        assert!(registry.total_bytes() <= MAX_REGISTRY_BYTES);
    }

    #[test]
    fn hostile_names_are_plain_bounded_and_credential_like_names_are_redacted() {
        let long_name = format!("{}{}", "界".repeat(100), "tail");
        let (_, dto) = BrowserSnapshot::from_root(
            scope("binding", "target", 0),
            vec![
                entry(
                    "/",
                    "<script>steal()<img src=x onerror=steal()>",
                    SftpFileKind::File,
                ),
                entry("/", "password=do-not-render", SftpFileKind::File),
                entry("/", &long_name, SftpFileKind::File),
            ],
            Instant::now(),
        )
        .unwrap();
        assert!(
            dto.entries
                .iter()
                .any(|entry| entry.name.contains("<script>"))
        );
        // A name that merely looks credential-shaped is still the operator's
        // evidence, so it crosses as written.
        assert!(
            serde_json::to_string(&dto)
                .unwrap()
                .contains("do-not-render")
        );
        let truncated = dto
            .entries
            .iter()
            .find(|entry| entry.name_truncated)
            .unwrap();
        assert!(truncated.name.len() <= MAX_ENTRY_NAME_BYTES);
    }

    #[test]
    fn text_preview_crosses_verbatim_within_line_byte_and_control_bounds() {
        let hostile = [
            "</pre><script>steal()</script><img src=x onerror=steal()>",
            "password=keep-this-visible",
            "root:$6$salt$hash:19000:0:99999:7:::",
            "plain\u{0007}control",
            &"x".repeat(MAX_TEXT_LINE_BYTES + 20),
        ]
        .join("\n");
        let projected = project_text(&hostile).unwrap();
        // Markup stays inert text; the rest is what the file actually holds.
        assert!(projected.text.contains("</pre><script>steal()</script>"));
        assert!(projected.text.contains("password=keep-this-visible"));
        assert!(projected.text.contains("root:$6$salt$hash"));
        // Only control characters are normalised, because they break rendering.
        assert!(projected.text.contains("plain\u{fffd}control"));
        assert!(projected.truncated);
        assert!(projected.displayed_line_count <= MAX_TEXT_LINES as u32);
        assert!(projected.text.len() <= MAX_TEXT_BYTES);
        assert!(
            projected
                .text
                .lines()
                .all(|line| line.len() <= MAX_TEXT_LINE_BYTES)
        );
    }

    #[test]
    fn text_preview_many_lines_and_serialized_escaping_stay_bounded() {
        let source = (0..MAX_TEXT_LINES + 200)
            .map(|index| format!("<line-{index}>\\\""))
            .collect::<Vec<_>>()
            .join("\n");
        let projected = project_text(&source).unwrap();
        assert_eq!(projected.displayed_line_count, MAX_TEXT_LINES as u32);
        assert!(projected.truncated);
        let dto = SftpTextPreviewDto {
            browser_handle: "opaque-browser".to_owned(),
            file_handle: "opaque-file".to_owned(),
            text: projected.text,
            observed_line_count: projected.observed_line_count,
            displayed_line_count: projected.displayed_line_count,
            truncated: projected.truncated,
        };
        ensure_serialized_bound(&dto, MAX_TEXT_RESPONSE_BYTES).unwrap();
    }

    #[test]
    fn duplicate_paths_invalid_handles_and_public_errors_fail_closed() {
        let duplicate = entry("/", "same", SftpFileKind::File);
        assert!(
            BrowserSnapshot::from_root(
                scope("binding", "target", 0),
                vec![duplicate.clone(), duplicate],
                Instant::now(),
            )
            .is_err()
        );
        for invalid in [
            "",
            "space value",
            "slash/value",
            "control\n",
            &"x".repeat(129),
        ] {
            assert!(validate_handle(invalid).is_err());
        }
        assert!(validate_handle("opaque-123-ABC").is_ok());
        let error = SftpBrowserApiError::Core;
        assert_eq!(error.to_string(), "the SFTP browser operation failed");
        assert!(!format!("{error:?}").contains("secret"));
    }

    #[test]
    fn production_source_uses_only_the_closed_core_sftp_surface() {
        let source = include_str!("sftp_browser_api.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains(".sftp()\n                .bind_session("));
        assert!(production.contains("self.services.sftp().list("));
        assert!(production.contains("self.services.sftp().read_text("));
        assert!(production.contains("RemotePath::new(\"/\")"));
        // The one transfer that exists goes through the core call that checks
        // the local target against the path guard.
        assert!(production.contains(".download_new(&session, &self.paths,"));
        assert!(production.contains("&self.paths,"));
        for forbidden in [
            [".ssh()", ".sftp("].concat(),
            ["Sftp", "Request"].concat(),
            ["upload", "_staged"].concat(),
            ["open_directory", "_terminal"].concat(),
            ["plan", "_extract"].concat(),
            ["Dangerous", "Confirmation"].concat(),
            ["Sftp", "Mutation"].concat(),
            ["canonical", "ize"].concat(),
            ["metadata", "("].concat(),
        ] {
            assert!(
                !production.contains(&forbidden),
                "production contains {forbidden}"
            );
        }
    }
}
