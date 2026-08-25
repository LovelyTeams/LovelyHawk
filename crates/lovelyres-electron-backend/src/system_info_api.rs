//! Read-only, capability-bound Electron boundary for the first system-info slice.

use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use lovelyres_core::{
    BackendServices, CoreError,
    ssh::BoundSshSession,
    system_info::{
        SystemInfoDetail, SystemInfoDetailField, SystemInfoGroup, SystemInfoRequest,
        SystemInfoRisk, SystemInfoRow, SystemInfoSummary, SystemInfoTab, SystemInfoTable,
    },
    target::TargetGuard,
};
use serde::Serialize;
use uuid::Uuid;

use crate::ssh_api::SshApi;

const MAX_REQUEST_ROWS: usize = 500;
const MAX_SNAPSHOTS: usize = 16;
const MAX_SNAPSHOT_ROWS: usize = 500;
const MAX_TOTAL_SNAPSHOT_ROWS: usize = 4_000;
const MAX_SNAPSHOT_BYTES: usize = 512 * 1024;
const MAX_TOTAL_SNAPSHOT_BYTES: usize = 4 * 1024 * 1024;
const MAX_HANDLE_BYTES: usize = 128;
const MAX_ROW_ID_BYTES: usize = 256;
const SNAPSHOT_TTL: Duration = Duration::from_secs(5 * 60);

pub(crate) struct SystemInfoApi {
    services: BackendServices,
    ssh: Arc<SshApi>,
    snapshots: Mutex<SnapshotRegistry>,
}

impl fmt::Debug for SystemInfoApi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let snapshot_count = self
            .snapshots
            .lock()
            .map(|registry| registry.snapshots.len())
            .unwrap_or_default();
        formatter
            .debug_struct("SystemInfoApi")
            .field("snapshot_count", &snapshot_count)
            .finish()
    }
}

impl SystemInfoApi {
    pub(crate) fn new(services: BackendServices, ssh: Arc<SshApi>) -> Self {
        Self {
            services,
            ssh,
            snapshots: Mutex::new(SnapshotRegistry::default()),
        }
    }

    pub(crate) fn catalog() -> Vec<SystemInfoTabDto> {
        SystemInfoTab::ALL
            .into_iter()
            .map(SystemInfoTabDto::from)
            .collect()
    }

    pub(crate) async fn summary(
        &self,
        binding_handle: &str,
    ) -> Result<SystemInfoSummaryDto, SystemInfoApiError> {
        let session = self.binding_session(binding_handle)?;
        let summary = self.services.system_info().summary(&session).await?;
        self.ensure_binding_unchanged(binding_handle, &session)?;
        Ok(summary.into())
    }

    pub(crate) async fn collect(
        &self,
        binding_handle: &str,
        tab_key: &str,
        maximum_rows: usize,
    ) -> Result<SystemInfoTableDto, SystemInfoApiError> {
        if !(1..=MAX_REQUEST_ROWS).contains(&maximum_rows) {
            return Err(SystemInfoApiError::InvalidBounds);
        }
        let tab = tab_from_key(tab_key).ok_or(SystemInfoApiError::InvalidTab)?;
        let request = SystemInfoRequest::new(tab, maximum_rows)?;
        let session = self.binding_session(binding_handle)?;
        let table = self
            .services
            .system_info()
            .collect(&session, &request)
            .await?;
        self.ensure_binding_unchanged(binding_handle, &session)?;
        let snapshot_handle = self.lock_snapshots()?.insert(
            binding_handle,
            session.target(),
            table.clone(),
            Instant::now(),
        )?;
        Ok(SystemInfoTableDto::from_table(snapshot_handle, table))
    }

    pub(crate) async fn detail(
        &self,
        binding_handle: &str,
        snapshot_handle: &str,
        row_id: &str,
    ) -> Result<SystemInfoDetailDto, SystemInfoApiError> {
        if snapshot_handle.is_empty() || snapshot_handle.len() > MAX_HANDLE_BYTES {
            return Err(SystemInfoApiError::InvalidSnapshot);
        }
        if row_id.is_empty() || row_id.len() > MAX_ROW_ID_BYTES {
            return Err(SystemInfoApiError::InvalidRow);
        }
        let session = self.binding_session(binding_handle)?;
        let table = self.lock_snapshots()?.table(
            binding_handle,
            session.target(),
            snapshot_handle,
            Instant::now(),
        )?;
        let request = table
            .detail_request(row_id)
            .map_err(|_| SystemInfoApiError::InvalidRow)?
            .ok_or(SystemInfoApiError::DetailUnavailable)?;
        let detail = self
            .services
            .system_info()
            .detail(&session, &request)
            .await?;
        self.ensure_binding_unchanged(binding_handle, &session)?;
        Ok(detail.into())
    }

    fn binding_session(&self, binding_handle: &str) -> Result<BoundSshSession, SystemInfoApiError> {
        self.ssh
            .binding_session_clone(binding_handle)
            .map_err(|_| SystemInfoApiError::BindingUnavailable)
    }

    fn ensure_binding_unchanged(
        &self,
        binding_handle: &str,
        expected: &BoundSshSession,
    ) -> Result<(), SystemInfoApiError> {
        let current = self.binding_session(binding_handle)?;
        if &current != expected {
            return Err(SystemInfoApiError::BindingUnavailable);
        }
        Ok(())
    }

    fn lock_snapshots(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, SnapshotRegistry>, SystemInfoApiError> {
        self.snapshots
            .lock()
            .map_err(|_| SystemInfoApiError::RegistryUnavailable)
    }
}

pub(crate) enum SystemInfoApiError {
    Core(CoreError),
    BindingUnavailable,
    InvalidBounds,
    InvalidTab,
    InvalidSnapshot,
    SnapshotCapacity,
    InvalidRow,
    DetailUnavailable,
    RegistryUnavailable,
}

impl fmt::Debug for SystemInfoApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Core(_) => "Core([REDACTED])",
            Self::BindingUnavailable => "BindingUnavailable",
            Self::InvalidBounds => "InvalidBounds",
            Self::InvalidTab => "InvalidTab",
            Self::InvalidSnapshot => "InvalidSnapshot",
            Self::SnapshotCapacity => "SnapshotCapacity",
            Self::InvalidRow => "InvalidRow",
            Self::DetailUnavailable => "DetailUnavailable",
            Self::RegistryUnavailable => "RegistryUnavailable",
        };
        formatter.write_str(name)
    }
}

impl fmt::Display for SystemInfoApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core(_) => "the system-information operation failed",
            Self::BindingUnavailable => "the SSH binding is missing or stale",
            Self::InvalidBounds => "the system-information bounds are invalid",
            Self::InvalidTab => "the system-information tab is invalid",
            Self::InvalidSnapshot => "the system-information snapshot is missing or stale",
            Self::SnapshotCapacity => "the system-information snapshot registry is full",
            Self::InvalidRow => "the system-information row is invalid",
            Self::DetailUnavailable => "this system-information row has no detail request",
            Self::RegistryUnavailable => "the system-information snapshot registry is unavailable",
        })
    }
}

impl std::error::Error for SystemInfoApiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Core(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CoreError> for SystemInfoApiError {
    fn from(error: CoreError) -> Self {
        Self::Core(error)
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SystemInfoTabDto {
    key: &'static str,
    label: &'static str,
    group: &'static str,
    group_label: &'static str,
    columns: &'static [&'static str],
}

impl From<SystemInfoTab> for SystemInfoTabDto {
    fn from(tab: SystemInfoTab) -> Self {
        Self {
            key: tab_key(tab),
            label: tab.label(),
            group: group_key(tab.group()),
            group_label: tab.group().label(),
            columns: tab.columns(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SystemInfoSummaryDto {
    hostname: String,
    operating_system: String,
    kernel: String,
    architecture: String,
    virtualization: String,
    boot_time: String,
    timezone: String,
    locale: String,
    init_system: String,
    package_manager: String,
    selinux: String,
    apparmor: String,
    uptime_seconds: u64,
    load_average: [String; 3],
    cpu_model: String,
    cpu_cores: u32,
    memory_total_bytes: u64,
    memory_available_bytes: u64,
    swap_total_bytes: u64,
    swap_free_bytes: u64,
    root_device: String,
    root_filesystem: String,
    root_total_bytes: u64,
    root_available_bytes: u64,
    primary_ip: String,
    default_gateway: String,
    dns_servers: String,
    process_count: usize,
    logged_in_users: usize,
    network_connections: usize,
    received_bytes: u64,
    transmitted_bytes: u64,
}

impl fmt::Debug for SystemInfoSummaryDto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SystemInfoSummaryDto([REDACTED])")
    }
}

impl From<SystemInfoSummary> for SystemInfoSummaryDto {
    fn from(value: SystemInfoSummary) -> Self {
        Self {
            hostname: value.hostname,
            operating_system: value.operating_system,
            kernel: value.kernel,
            architecture: value.architecture,
            virtualization: value.virtualization,
            boot_time: value.boot_time,
            timezone: value.timezone,
            locale: value.locale,
            init_system: value.init_system,
            package_manager: value.package_manager,
            selinux: value.selinux,
            apparmor: value.apparmor,
            uptime_seconds: value.uptime_seconds,
            load_average: value.load_average,
            cpu_model: value.cpu_model,
            cpu_cores: value.cpu_cores,
            memory_total_bytes: value.memory_total_bytes,
            memory_available_bytes: value.memory_available_bytes,
            swap_total_bytes: value.swap_total_bytes,
            swap_free_bytes: value.swap_free_bytes,
            root_device: value.root_device,
            root_filesystem: value.root_filesystem,
            root_total_bytes: value.root_total_bytes,
            root_available_bytes: value.root_available_bytes,
            primary_ip: value.primary_ip,
            default_gateway: value.default_gateway,
            dns_servers: value.dns_servers,
            process_count: value.process_count,
            logged_in_users: value.logged_in_users,
            network_connections: value.network_connections,
            received_bytes: value.received_bytes,
            transmitted_bytes: value.transmitted_bytes,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SystemInfoTableDto {
    snapshot_handle: String,
    tab: &'static str,
    columns: Vec<String>,
    rows: Vec<SystemInfoRowDto>,
    truncated: bool,
}

impl fmt::Debug for SystemInfoTableDto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SystemInfoTableDto")
            .field("row_count", &self.rows.len())
            .field("truncated", &self.truncated)
            .finish()
    }
}

impl SystemInfoTableDto {
    fn from_table(snapshot_handle: String, table: SystemInfoTable) -> Self {
        Self {
            snapshot_handle,
            tab: tab_key(table.tab),
            columns: table.columns,
            rows: table.rows.into_iter().map(SystemInfoRowDto::from).collect(),
            truncated: table.truncated,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SystemInfoRowDto {
    id: String,
    cells: Vec<String>,
    risk: &'static str,
}

impl From<SystemInfoRow> for SystemInfoRowDto {
    fn from(row: SystemInfoRow) -> Self {
        Self {
            id: row.id,
            cells: row.cells,
            risk: risk_key(row.risk),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SystemInfoDetailDto {
    tab: &'static str,
    row_id: String,
    fields: Vec<SystemInfoDetailFieldDto>,
}

impl fmt::Debug for SystemInfoDetailDto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SystemInfoDetailDto")
            .field("field_count", &self.fields.len())
            .finish()
    }
}

impl From<SystemInfoDetail> for SystemInfoDetailDto {
    fn from(detail: SystemInfoDetail) -> Self {
        Self {
            tab: tab_key(detail.tab),
            row_id: detail.row_id,
            fields: detail
                .fields
                .into_iter()
                .map(SystemInfoDetailFieldDto::from)
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct SystemInfoDetailFieldDto {
    label: String,
    value: String,
}

impl From<SystemInfoDetailField> for SystemInfoDetailFieldDto {
    fn from(field: SystemInfoDetailField) -> Self {
        Self {
            label: field.label,
            value: field.value,
        }
    }
}

#[derive(Default)]
struct SnapshotRegistry {
    snapshots: HashMap<String, Snapshot>,
}

impl fmt::Debug for SnapshotRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rows = self
            .snapshots
            .values()
            .map(|snapshot| snapshot.rows)
            .sum::<usize>();
        let bytes = self
            .snapshots
            .values()
            .map(|snapshot| snapshot.bytes)
            .sum::<usize>();
        formatter
            .debug_struct("SnapshotRegistry")
            .field("snapshot_count", &self.snapshots.len())
            .field("row_count", &rows)
            .field("byte_count", &bytes)
            .finish()
    }
}

struct Snapshot {
    binding_handle: String,
    target: TargetGuard,
    table: SystemInfoTable,
    rows: usize,
    bytes: usize,
    expires_at: Instant,
}

impl SnapshotRegistry {
    fn insert(
        &mut self,
        binding_handle: &str,
        target: &TargetGuard,
        table: SystemInfoTable,
        now: Instant,
    ) -> Result<String, SystemInfoApiError> {
        self.prune(now);
        let rows = table.rows.len();
        let bytes = estimated_snapshot_bytes(binding_handle, target, &table);
        if rows > MAX_SNAPSHOT_ROWS || bytes > MAX_SNAPSHOT_BYTES {
            return Err(SystemInfoApiError::SnapshotCapacity);
        }
        // A collect always supersedes the previous snapshot of the same tab on
        // the same binding: the page only ever reads the newest one, and its
        // detail view is cleared whenever the tab changes.
        let superseded = table.tab;
        self.snapshots.retain(|_, snapshot| {
            snapshot.binding_handle != binding_handle || snapshot.table.tab != superseded
        });
        // Reclaim the oldest snapshots until the new one fits. Without this a
        // handful of tab switches would exhaust the registry for a full TTL.
        while self.snapshots.len() >= MAX_SNAPSHOTS
            || self.total_rows().saturating_add(rows) > MAX_TOTAL_SNAPSHOT_ROWS
            || self.total_bytes().saturating_add(bytes) > MAX_TOTAL_SNAPSHOT_BYTES
        {
            let Some(oldest) = self.oldest_handle() else {
                return Err(SystemInfoApiError::SnapshotCapacity);
            };
            self.snapshots.remove(&oldest);
        }
        let handle = unique_snapshot_handle(&self.snapshots)?;
        self.snapshots.insert(
            handle.clone(),
            Snapshot {
                binding_handle: binding_handle.to_owned(),
                target: target.clone(),
                table,
                rows,
                bytes,
                expires_at: now + SNAPSHOT_TTL,
            },
        );
        Ok(handle)
    }

    fn table(
        &mut self,
        binding_handle: &str,
        target: &TargetGuard,
        snapshot_handle: &str,
        now: Instant,
    ) -> Result<SystemInfoTable, SystemInfoApiError> {
        self.prune(now);
        let snapshot = self
            .snapshots
            .get(snapshot_handle)
            .ok_or(SystemInfoApiError::InvalidSnapshot)?;
        if snapshot.binding_handle != binding_handle || &snapshot.target != target {
            return Err(SystemInfoApiError::InvalidSnapshot);
        }
        Ok(snapshot.table.clone())
    }

    fn prune(&mut self, now: Instant) {
        self.snapshots
            .retain(|_, snapshot| snapshot.expires_at > now);
    }

    fn total_rows(&self) -> usize {
        self.snapshots.values().map(|snapshot| snapshot.rows).sum()
    }

    fn total_bytes(&self) -> usize {
        self.snapshots.values().map(|snapshot| snapshot.bytes).sum()
    }

    /// Oldest by expiry, which is insertion order because every snapshot shares
    /// one TTL.
    fn oldest_handle(&self) -> Option<String> {
        self.snapshots
            .iter()
            .min_by_key(|(handle, snapshot)| (snapshot.expires_at, (*handle).clone()))
            .map(|(handle, _)| handle.clone())
    }
}

fn estimated_snapshot_bytes(
    binding_handle: &str,
    target: &TargetGuard,
    table: &SystemInfoTable,
) -> usize {
    let mut bytes = std::mem::size_of::<Snapshot>()
        .saturating_add(36)
        .saturating_add(binding_handle.len())
        .saturating_add(target.identity.as_str().len())
        .saturating_add(
            table
                .columns
                .capacity()
                .saturating_mul(std::mem::size_of::<String>()),
        )
        .saturating_add(
            table
                .rows
                .capacity()
                .saturating_mul(std::mem::size_of::<SystemInfoRow>()),
        );
    for column in &table.columns {
        bytes = bytes.saturating_add(column.capacity());
    }
    for row in &table.rows {
        bytes = bytes.saturating_add(row.id.capacity()).saturating_add(
            row.cells
                .capacity()
                .saturating_mul(std::mem::size_of::<String>()),
        );
        for cell in &row.cells {
            bytes = bytes.saturating_add(cell.capacity());
        }
    }
    bytes
}

fn unique_snapshot_handle(
    snapshots: &HashMap<String, Snapshot>,
) -> Result<String, SystemInfoApiError> {
    for _ in 0..8 {
        let handle = Uuid::new_v4().to_string();
        if !snapshots.contains_key(&handle) {
            return Ok(handle);
        }
    }
    Err(SystemInfoApiError::SnapshotCapacity)
}

const fn group_key(group: SystemInfoGroup) -> &'static str {
    match group {
        SystemInfoGroup::Realtime => "realtime",
        SystemInfoGroup::Persistence => "persistence",
        SystemInfoGroup::Security => "security",
        SystemInfoGroup::Workload => "workload",
    }
}

const fn risk_key(risk: SystemInfoRisk) -> &'static str {
    match risk {
        SystemInfoRisk::Normal => "normal",
        SystemInfoRisk::Warning => "warning",
        SystemInfoRisk::High => "high",
    }
}

const fn tab_key(tab: SystemInfoTab) -> &'static str {
    match tab {
        SystemInfoTab::Processes => "processes",
        SystemInfoTab::Network => "network",
        SystemInfoTab::Services => "services",
        SystemInfoTab::Established => "established",
        SystemInfoTab::OpenPorts => "open-ports",
        SystemInfoTab::Users => "users",
        SystemInfoTab::Autostart => "autostart",
        SystemInfoTab::Cron => "cron",
        SystemInfoTab::SshKeys => "ssh-keys",
        SystemInfoTab::LoginHistory => "login-history",
        SystemInfoTab::SuidFiles => "suid-files",
        SystemInfoTab::Autoruns => "autoruns",
        SystemInfoTab::Firewall => "firewall",
        SystemInfoTab::EnvVars => "env-vars",
        SystemInfoTab::ShellConfigs => "shell-configs",
        SystemInfoTab::Packages => "packages",
        SystemInfoTab::Sudoers => "sudoers",
        SystemInfoTab::Timers => "timers",
        SystemInfoTab::KernelModules => "kernel-modules",
        SystemInfoTab::Rootcheck => "rootcheck",
        SystemInfoTab::Sensitive => "sensitive",
        SystemInfoTab::RecentFiles => "recent-files",
        SystemInfoTab::Docker => "docker",
        SystemInfoTab::Kubernetes => "kubernetes",
        SystemInfoTab::WebApps => "web-apps",
    }
}

fn tab_from_key(key: &str) -> Option<SystemInfoTab> {
    SystemInfoTab::ALL
        .into_iter()
        .find(|tab| tab_key(*tab) == key)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use lovelyres_core::target::TargetIdentity;

    use super::*;

    fn guard(identity: &str, generation: u64) -> TargetGuard {
        TargetGuard {
            identity: TargetIdentity::new(identity).unwrap(),
            generation,
        }
    }

    fn table(tab: SystemInfoTab, row_id: &str, cell: &str) -> SystemInfoTable {
        SystemInfoTable {
            tab,
            columns: tab
                .columns()
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            rows: vec![SystemInfoRow {
                id: row_id.to_owned(),
                cells: vec![cell.to_owned(); tab.columns().len()],
                risk: SystemInfoRisk::Warning,
            }],
            truncated: false,
        }
    }

    #[test]
    fn catalog_is_closed_unique_and_complete() {
        let catalog = SystemInfoApi::catalog();
        assert_eq!(catalog.len(), 25);
        assert_eq!(
            catalog
                .iter()
                .map(|entry| entry.key)
                .collect::<HashSet<_>>()
                .len(),
            25
        );
        for entry in catalog {
            assert!(!entry.label.is_empty());
            assert!(!entry.group.is_empty());
            assert!(!entry.group_label.is_empty());
            assert!(!entry.columns.is_empty());
            assert_eq!(tab_key(tab_from_key(entry.key).unwrap()), entry.key);
        }
    }

    #[test]
    fn snapshots_are_opaque_binding_and_target_scoped_and_expire() {
        let now = Instant::now();
        let target = guard("server-1", 7);
        let mut registry = SnapshotRegistry::default();
        let handle = registry
            .insert(
                "binding-one",
                &target,
                table(SystemInfoTab::Processes, "row-one", "plain"),
                now,
            )
            .unwrap();
        assert!(!handle.contains("binding-one"));
        assert!(registry.table("binding-one", &target, &handle, now).is_ok());
        assert!(matches!(
            registry.table("binding-two", &target, &handle, now),
            Err(SystemInfoApiError::InvalidSnapshot)
        ));
        assert!(matches!(
            registry.table("binding-one", &guard("server-1", 8), &handle, now),
            Err(SystemInfoApiError::InvalidSnapshot)
        ));
        assert!(matches!(
            registry.table("binding-one", &target, &handle, now + SNAPSHOT_TTL),
            Err(SystemInfoApiError::InvalidSnapshot)
        ));
    }

    #[test]
    fn snapshot_registry_enforces_count_row_and_byte_caps() {
        let now = Instant::now();
        let target = guard("server-1", 1);
        let mut registry = SnapshotRegistry::default();

        // Re-collecting a tab supersedes its previous snapshot instead of
        // accumulating: the page only ever reads the newest one.
        let mut previous = None;
        for index in 0..MAX_SNAPSHOTS {
            let handle = registry
                .insert(
                    "binding",
                    &target,
                    table(SystemInfoTab::Users, &format!("row-{index}"), "bounded"),
                    now,
                )
                .unwrap();
            assert_eq!(registry.snapshots.len(), 1);
            if let Some(stale) = previous.replace(handle) {
                assert!(matches!(
                    registry.table("binding", &target, &stale, now),
                    Err(SystemInfoApiError::InvalidSnapshot)
                ));
            }
        }

        // Distinct tabs coexist, and going past the caps evicts the oldest
        // snapshot rather than locking the page out for a whole TTL.
        let mut distinct = SnapshotRegistry::default();
        let tabs = [
            SystemInfoTab::Users,
            SystemInfoTab::Processes,
            SystemInfoTab::Services,
            SystemInfoTab::OpenPorts,
        ];
        for (index, tab) in tabs.iter().enumerate() {
            distinct
                .insert(
                    "binding",
                    &target,
                    table(*tab, &format!("row-{index}"), "bounded"),
                    now,
                )
                .unwrap();
        }
        assert_eq!(distinct.snapshots.len(), tabs.len());
        for index in 0..MAX_SNAPSHOTS * 2 {
            distinct
                .insert(
                    &format!("binding-{index}"),
                    &target,
                    table(SystemInfoTab::Users, &format!("row-{index}"), "bounded"),
                    now,
                )
                .unwrap();
            assert!(distinct.snapshots.len() <= MAX_SNAPSHOTS);
            assert!(distinct.total_rows() <= MAX_TOTAL_SNAPSHOT_ROWS);
            assert!(distinct.total_bytes() <= MAX_TOTAL_SNAPSHOT_BYTES);
        }

        let oversized = SystemInfoTable {
            tab: SystemInfoTab::Users,
            columns: vec!["column".to_owned()],
            rows: (0..=MAX_SNAPSHOT_ROWS)
                .map(|index| SystemInfoRow {
                    id: format!("row-{index}"),
                    cells: vec!["bounded".to_owned()],
                    risk: SystemInfoRisk::Normal,
                })
                .collect(),
            truncated: false,
        };
        assert!(matches!(
            SnapshotRegistry::default().insert("binding", &target, oversized, now),
            Err(SystemInfoApiError::SnapshotCapacity)
        ));

        let oversized_bytes = table(
            SystemInfoTab::Users,
            "large-row",
            &"x".repeat(MAX_SNAPSHOT_BYTES),
        );
        assert!(matches!(
            SnapshotRegistry::default().insert("binding", &target, oversized_bytes, now),
            Err(SystemInfoApiError::SnapshotCapacity)
        ));
    }

    #[test]
    fn hostile_rows_remain_plain_and_errors_and_debug_do_not_echo_them() {
        let hostile = "</script><img src=x onerror=steal()>";
        let now = Instant::now();
        let target = guard("server-1", 1);
        let mut registry = SnapshotRegistry::default();
        let handle = registry
            .insert(
                "binding",
                &target,
                table(SystemInfoTab::Processes, "safe-row", hostile),
                now,
            )
            .unwrap();
        let stored = registry.table("binding", &target, &handle, now).unwrap();
        assert_eq!(stored.rows[0].cells[0], hostile);
        let error = stored
            .detail_request(hostile)
            .map_err(|_| SystemInfoApiError::InvalidRow);
        assert!(error.is_err());
        assert!(!format!("{:?}", error.unwrap_err()).contains(hostile));
        assert!(!format!("{registry:?}").contains(hostile));
        assert!(!format!("{registry:?}").contains(&handle));

        let dto = SystemInfoTableDto::from_table(handle.clone(), stored);
        let dto_debug = format!("{dto:?}");
        assert!(!dto_debug.contains(hostile));
        assert!(!dto_debug.contains(&handle));
    }
}
