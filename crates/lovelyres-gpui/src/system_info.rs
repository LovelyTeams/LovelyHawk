use std::{collections::BTreeMap, net::IpAddr, ops::Range, sync::Arc};

use gpui::{
    Action, AnyElement, ClickEvent, ClipboardItem, Context, Corner, Entity, IntoElement,
    MouseButton, MouseDownEvent, Pixels, Point, Render, ScrollStrategy, SharedString, Subscription,
    UniformListScrollHandle, Window, anchored, deferred, div, point, prelude::*, px, uniform_list,
};
use gpui_component::{
    Disableable, IconName, Sizable,
    button::ButtonVariants,
    input::{Input, InputEvent, InputState},
    scroll::ScrollableElement,
};
use lovelyres_core::{
    BackendServices, CoreError, CoreResult,
    firewall::{
        FirewallMutationPlan, FirewallMutationRequest, FirewallOperationOutcome,
        FirewallResolution, FirewallResolutionPlan,
    },
    operations::DangerousConfirmation,
    ssh::BoundSshSession,
    system_info::{
        ArtifactInvestigationAction, ArtifactInvestigationResult, ArtifactMutationAction,
        ArtifactMutationOutcome, ArtifactMutationPlan, CronInvestigationAction,
        EnvVarInvestigationAction, KernelModuleInvestigationAction, LoginInvestigationAction,
        LoginInvestigationGroup, LoginInvestigationResult, NetworkDisconnectOutcome,
        NetworkDisconnectPlan, NetworkInvestigationAction, NetworkInvestigationGroup,
        NetworkInvestigationResult, PackageInvestigationAction, ProcessInvestigationAction,
        ProcessInvestigationGroup, ProcessInvestigationResult, ProcessSignal, ProcessSignalOutcome,
        ProcessSignalPlan, ServiceInvestigationAction, ServiceInvestigationGroup,
        ServiceInvestigationResult, ServiceRuntimeAction, ServiceRuntimeOutcome,
        ServiceRuntimePlan, ShellConfigInvestigationAction, SshKeyInvestigationAction,
        StartupInvestigationAction, SudoersInvestigationAction, SuidFileInvestigationAction,
        SystemInfoDetail, SystemInfoDetailRequest, SystemInfoGroup, SystemInfoRequest,
        SystemInfoRisk, SystemInfoRow, SystemInfoSummary, SystemInfoTab, SystemInfoTable,
        TimerInvestigationAction, UserAccountAction, UserAccountOutcome, UserAccountPlan,
        UserInvestigationAction, UserInvestigationGroup, UserInvestigationResult,
    },
    target::TargetGuard,
};

use crate::{app::SharedAppState, runtime::TokioBridge, theme::ThemeTokens};
use serde::Deserialize;

const DEFAULT_MAXIMUM_ROWS: usize = 1_000;

#[derive(Action, Clone, Debug, Eq, PartialEq, Deserialize)]
#[action(namespace = system_info, no_json)]
struct OpenRowDetail {
    row_id: String,
}

#[derive(Action, Clone, Debug, Eq, PartialEq, Deserialize)]
#[action(namespace = system_info, no_json)]
struct CopyContextRow {
    row_id: String,
}

#[derive(Action, Clone, Debug, Eq, PartialEq, Deserialize)]
#[action(namespace = system_info, no_json)]
struct CopyContextIdentity {
    row_id: String,
}

#[derive(Action, Clone, Debug, Eq, PartialEq, Deserialize)]
#[action(namespace = system_info, no_json)]
struct FilterContextIdentity {
    row_id: String,
}

#[derive(Action, Clone, Debug, Default, Eq, PartialEq, Deserialize)]
#[action(namespace = system_info, no_json)]
struct RefreshContextTable;

#[derive(Action, Clone, Debug, Default, Eq, PartialEq, Deserialize)]
#[action(namespace = system_info, no_json)]
struct ClearContextFilters;

#[derive(Clone, Debug)]
struct RowContextMenuState {
    tab: SystemInfoTab,
    row_id: String,
    identity: String,
    position: Point<Pixels>,
}

#[derive(Clone, Debug)]
enum TableFilterMenuKind {
    Risk,
    Facet { index: usize, label: &'static str },
}

#[derive(Clone, Copy, Debug)]
enum NetworkCopyField {
    LocalEndpoint,
    RemoteEndpoint,
    Process,
}

#[derive(Clone, Debug)]
struct TableFilterMenuState {
    kind: TableFilterMenuKind,
    position: Point<Pixels>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcessInteractionLease {
    activation_generation: u64,
    request_id: u64,
    binding: SystemInfoBinding,
    row_id: String,
}

#[derive(Clone, Debug)]
struct PendingProcessSignal {
    lease: ProcessInteractionLease,
    plan: ProcessSignalPlan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ServiceInteractionLease {
    activation_generation: u64,
    request_id: u64,
    binding: SystemInfoBinding,
    tab: SystemInfoTab,
    row_id: String,
}

#[derive(Clone, Debug)]
struct PendingServiceRuntime {
    lease: ServiceInteractionLease,
    plan: ServiceRuntimePlan,
}

#[derive(Debug)]
struct PendingArtifactMutation {
    lease: ArtifactInteractionLease,
    plan: ArtifactMutationPlan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AccountInteractionLease {
    activation_generation: u64,
    request_id: u64,
    binding: SystemInfoBinding,
    tab: SystemInfoTab,
    row_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ArtifactInteractionLease {
    activation_generation: u64,
    request_id: u64,
    binding: SystemInfoBinding,
    tab: SystemInfoTab,
    row_id: String,
}

#[derive(Clone, Debug)]
struct PendingUserAccount {
    lease: AccountInteractionLease,
    plan: UserAccountPlan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NetworkInteractionLease {
    activation_generation: u64,
    request_id: u64,
    binding: SystemInfoBinding,
    tab: SystemInfoTab,
    row_id: String,
}

#[derive(Clone, Debug)]
struct PendingNetworkDisconnect {
    lease: NetworkInteractionLease,
    plan: NetworkDisconnectPlan,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NetworkFirewallIntent {
    Block,
    Allow,
    TemporaryBlock,
    KeepBlock,
}

impl NetworkFirewallIntent {
    const fn label(self) -> &'static str {
        match self {
            Self::Block => "封禁远端 IP",
            Self::Allow => "恢复远端 IP 放行",
            Self::TemporaryBlock => "临时封禁 5 分钟",
            Self::KeepBlock => "永久保留封禁",
        }
    }
}

#[derive(Clone, Debug)]
enum PendingNetworkFirewall {
    Mutation {
        lease: FirewallInteractionLease,
        intent: NetworkFirewallIntent,
        plan: FirewallMutationPlan,
    },
    Resolution {
        lease: FirewallInteractionLease,
        intent: NetworkFirewallIntent,
        plan: FirewallResolutionPlan,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum FirewallInteractionLease {
    Network(NetworkInteractionLease),
    LoginHistory(AccountInteractionLease),
}

impl FirewallInteractionLease {
    const fn request_id(&self) -> u64 {
        match self {
            Self::Network(lease) => lease.request_id,
            Self::LoginHistory(lease) => lease.request_id,
        }
    }

    fn row_id(&self) -> &str {
        match self {
            Self::Network(lease) => &lease.row_id,
            Self::LoginHistory(lease) => &lease.row_id,
        }
    }
}

#[derive(Clone, Debug)]
enum NetworkFirewallPlanResult {
    Mutation(FirewallMutationPlan),
    Resolution(FirewallResolutionPlan),
}

impl PendingNetworkFirewall {
    fn lease(&self) -> &FirewallInteractionLease {
        match self {
            Self::Mutation { lease, .. } | Self::Resolution { lease, .. } => lease,
        }
    }

    fn definition(&self) -> &lovelyres_core::operations::OperationPlan {
        match self {
            Self::Mutation { plan, .. } => plan.definition(),
            Self::Resolution { plan, .. } => plan.definition(),
        }
    }

    const fn intent(&self) -> NetworkFirewallIntent {
        match self {
            Self::Mutation { intent, .. } | Self::Resolution { intent, .. } => *intent,
        }
    }
}

fn process_lease_is_current(model: &SystemInfoModel, lease: &ProcessInteractionLease) -> bool {
    model.active
        && model.activation_generation == lease.activation_generation
        && model.binding.as_ref() == Some(&lease.binding)
        && model.active_tab == SystemInfoTab::Processes
        && model.selected_row_id.as_deref() == Some(lease.row_id.as_str())
}

fn is_service_runtime_tab(tab: SystemInfoTab) -> bool {
    matches!(
        tab,
        SystemInfoTab::Services | SystemInfoTab::Autostart | SystemInfoTab::Timers
    )
}

fn service_lease_is_current(model: &SystemInfoModel, lease: &ServiceInteractionLease) -> bool {
    model.active
        && model.activation_generation == lease.activation_generation
        && model.binding.as_ref() == Some(&lease.binding)
        && model.active_tab == lease.tab
        && is_service_runtime_tab(lease.tab)
        && model.selected_row_id.as_deref() == Some(lease.row_id.as_str())
}

fn is_account_tab(tab: SystemInfoTab) -> bool {
    matches!(tab, SystemInfoTab::Users | SystemInfoTab::LoginHistory)
}

fn account_lease_is_current(model: &SystemInfoModel, lease: &AccountInteractionLease) -> bool {
    model.active
        && model.activation_generation == lease.activation_generation
        && model.binding.as_ref() == Some(&lease.binding)
        && model.active_tab == lease.tab
        && is_account_tab(lease.tab)
        && model.selected_row_id.as_deref() == Some(lease.row_id.as_str())
}

fn is_artifact_tab(tab: SystemInfoTab) -> bool {
    matches!(
        tab,
        SystemInfoTab::Packages
            | SystemInfoTab::KernelModules
            | SystemInfoTab::EnvVars
            | SystemInfoTab::Autostart
            | SystemInfoTab::Cron
            | SystemInfoTab::Timers
            | SystemInfoTab::ShellConfigs
            | SystemInfoTab::Sudoers
            | SystemInfoTab::SuidFiles
            | SystemInfoTab::SshKeys
    )
}

fn artifact_lease_is_current(model: &SystemInfoModel, lease: &ArtifactInteractionLease) -> bool {
    model.active
        && model.activation_generation == lease.activation_generation
        && model.binding.as_ref() == Some(&lease.binding)
        && model.active_tab == lease.tab
        && is_artifact_tab(lease.tab)
        && model.selected_row_id.as_deref() == Some(lease.row_id.as_str())
}

fn artifact_actions(tab: SystemInfoTab) -> Vec<ArtifactInvestigationAction> {
    match tab {
        SystemInfoTab::Packages => PackageInvestigationAction::ALL
            .into_iter()
            .map(ArtifactInvestigationAction::Package)
            .collect(),
        SystemInfoTab::KernelModules => KernelModuleInvestigationAction::ALL
            .into_iter()
            .map(ArtifactInvestigationAction::KernelModule)
            .collect(),
        SystemInfoTab::EnvVars => EnvVarInvestigationAction::ALL
            .into_iter()
            .map(ArtifactInvestigationAction::Environment)
            .collect(),
        SystemInfoTab::Autostart => StartupInvestigationAction::ALL
            .into_iter()
            .map(ArtifactInvestigationAction::Startup)
            .collect(),
        SystemInfoTab::Cron => CronInvestigationAction::ALL
            .into_iter()
            .map(ArtifactInvestigationAction::Cron)
            .collect(),
        SystemInfoTab::Timers => TimerInvestigationAction::ALL
            .into_iter()
            .map(ArtifactInvestigationAction::Timer)
            .collect(),
        SystemInfoTab::ShellConfigs => ShellConfigInvestigationAction::ALL
            .into_iter()
            .map(ArtifactInvestigationAction::ShellConfig)
            .collect(),
        SystemInfoTab::Sudoers => SudoersInvestigationAction::ALL
            .into_iter()
            .map(ArtifactInvestigationAction::Sudoers)
            .collect(),
        SystemInfoTab::SuidFiles => SuidFileInvestigationAction::ALL
            .into_iter()
            .map(ArtifactInvestigationAction::SuidFile)
            .collect(),
        SystemInfoTab::SshKeys => SshKeyInvestigationAction::ALL
            .into_iter()
            .map(ArtifactInvestigationAction::SshKey)
            .collect(),
        _ => Vec::new(),
    }
}

fn is_network_tab(tab: SystemInfoTab) -> bool {
    matches!(
        tab,
        SystemInfoTab::Network | SystemInfoTab::Established | SystemInfoTab::OpenPorts
    )
}

fn network_lease_is_current(model: &SystemInfoModel, lease: &NetworkInteractionLease) -> bool {
    model.active
        && model.activation_generation == lease.activation_generation
        && model.binding.as_ref() == Some(&lease.binding)
        && model.active_tab == lease.tab
        && is_network_tab(lease.tab)
        && model.selected_row_id.as_deref() == Some(lease.row_id.as_str())
}

fn firewall_lease_is_current(model: &SystemInfoModel, lease: &FirewallInteractionLease) -> bool {
    match lease {
        FirewallInteractionLease::Network(lease) => network_lease_is_current(model, lease),
        FirewallInteractionLease::LoginHistory(lease) => {
            lease.tab == SystemInfoTab::LoginHistory && account_lease_is_current(model, lease)
        }
    }
}

#[derive(Clone, Debug)]
enum TableFilterChoice {
    Risk(Option<SystemInfoRisk>),
    Facet { index: usize, value: Option<String> },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemInfoBinding {
    connection_id: String,
    session_id: String,
    target: TargetGuard,
}

impl SystemInfoBinding {
    fn from_session(session: &BoundSshSession) -> Self {
        Self {
            connection_id: session.connection_id().to_owned(),
            session_id: session.session_id().to_owned(),
            target: session.target().clone(),
        }
    }

    fn capture(shared: &SharedAppState) -> Option<Self> {
        shared
            .active_ssh
            .as_ref()
            .map(|active| Self::from_session(&active.session))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestKind {
    Summary,
    Table(SystemInfoTab),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemInfoRequestLease {
    activation_generation: u64,
    request_id: u64,
    binding: SystemInfoBinding,
    kind: RequestKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemInfoDetailLease {
    activation_generation: u64,
    request_id: u64,
    binding: SystemInfoBinding,
    tab: SystemInfoTab,
    row_id: String,
}

#[derive(Debug)]
pub struct SystemInfoModel {
    active: bool,
    activation_generation: u64,
    next_request_id: u64,
    binding: Option<SystemInfoBinding>,
    active_tab: SystemInfoTab,
    summary: Option<SystemInfoSummary>,
    tables: BTreeMap<SystemInfoTab, SystemInfoTable>,
    latest_summary_request: Option<u64>,
    latest_table_request: Option<(SystemInfoTab, u64)>,
    latest_detail_request: Option<(SystemInfoTab, String, u64)>,
    selected_row_id: Option<String>,
    detail: Option<SystemInfoDetail>,
    query: String,
    risk_filter: Option<SystemInfoRisk>,
    facet_filters: [Option<String>; 2],
    filtered_row_indices: Vec<usize>,
}

impl Default for SystemInfoModel {
    fn default() -> Self {
        Self {
            active: false,
            activation_generation: 0,
            next_request_id: 0,
            binding: None,
            active_tab: SystemInfoTab::Processes,
            summary: None,
            tables: BTreeMap::new(),
            latest_summary_request: None,
            latest_table_request: None,
            latest_detail_request: None,
            selected_row_id: None,
            detail: None,
            query: String::new(),
            risk_filter: None,
            facet_filters: [None, None],
            filtered_row_indices: Vec::new(),
        }
    }
}

impl SystemInfoModel {
    pub fn activate(&mut self, binding: Option<SystemInfoBinding>) -> u64 {
        self.active = true;
        self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
        self.rebind(binding);
        self.activation_generation
    }

    pub fn deactivate(&mut self) {
        self.active = false;
        self.latest_summary_request = None;
        self.latest_table_request = None;
        self.latest_detail_request = None;
        self.detail = None;
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub const fn active_tab(&self) -> SystemInfoTab {
        self.active_tab
    }

    pub fn binding(&self) -> Option<&SystemInfoBinding> {
        self.binding.as_ref()
    }

    pub fn summary(&self) -> Option<&SystemInfoSummary> {
        self.summary.as_ref()
    }

    pub fn active_table(&self) -> Option<&SystemInfoTable> {
        self.tables.get(&self.active_tab)
    }

    pub fn selected_row(&self) -> Option<&SystemInfoRow> {
        let id = self.selected_row_id.as_deref()?;
        self.active_table()?.rows.iter().find(|row| row.id == id)
    }

    pub fn detail(&self) -> Option<&SystemInfoDetail> {
        self.detail.as_ref()
    }

    pub fn query(&self) -> &str {
        &self.query
    }

    pub fn set_query(&mut self, query: String) {
        self.query = query;
        self.rebuild_filtered_rows();
    }

    pub const fn risk_filter(&self) -> Option<SystemInfoRisk> {
        self.risk_filter
    }

    pub fn set_risk_filter(&mut self, risk: Option<SystemInfoRisk>) {
        self.risk_filter = risk;
        self.rebuild_filtered_rows();
    }

    pub fn facet_value(&self, index: usize) -> Option<&str> {
        self.facet_filters
            .get(index)
            .and_then(|value| value.as_deref())
    }

    pub fn facet_options(&self, index: usize) -> Vec<String> {
        let Some(column) = filter_columns(self.active_tab).get(index).copied() else {
            return Vec::new();
        };
        let mut values = self
            .active_table()
            .into_iter()
            .flat_map(|table| &table.rows)
            .filter_map(|row| row.cells.get(column))
            .filter(|value| !value.is_empty())
            .cloned()
            .collect::<Vec<_>>();
        values.sort();
        values.dedup();
        values.truncate(100);
        values
    }

    pub fn set_facet(&mut self, index: usize, value: Option<String>) -> bool {
        if index >= self.facet_filters.len()
            || value
                .as_ref()
                .is_some_and(|candidate| !self.facet_options(index).contains(candidate))
        {
            return false;
        }
        self.facet_filters[index] = value;
        self.rebuild_filtered_rows();
        true
    }

    pub fn reset_filters(&mut self) {
        self.query.clear();
        self.risk_filter = None;
        self.facet_filters = [None, None];
        self.rebuild_filtered_rows();
    }

    pub fn switch_tab(&mut self, tab: SystemInfoTab) {
        if self.active_tab == tab {
            return;
        }
        self.active_tab = tab;
        self.selected_row_id = None;
        self.detail = None;
        self.latest_detail_request = None;
        self.reset_filters();
    }

    pub fn select_row(&mut self, row_id: &str) -> bool {
        if !self
            .active_table()
            .is_some_and(|table| table.rows.iter().any(|row| row.id == row_id))
        {
            return false;
        }
        self.selected_row_id = Some(row_id.to_owned());
        self.detail = None;
        self.latest_detail_request = None;
        true
    }

    pub fn close_detail(&mut self) {
        self.selected_row_id = None;
        self.detail = None;
        self.latest_detail_request = None;
    }

    fn invalidate_detail(&mut self) {
        self.detail = None;
        self.latest_detail_request = None;
    }

    fn rebind(&mut self, binding: Option<SystemInfoBinding>) {
        if self.binding == binding {
            return;
        }
        self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
        self.binding = binding;
        self.summary = None;
        self.tables.clear();
        self.latest_summary_request = None;
        self.latest_table_request = None;
        self.latest_detail_request = None;
        self.selected_row_id = None;
        self.detail = None;
        self.reset_filters();
    }

    fn begin_request(
        &mut self,
        kind: RequestKind,
        binding: Option<SystemInfoBinding>,
    ) -> CoreResult<SystemInfoRequestLease> {
        if !self.active {
            return Err(CoreError::Validation {
                subject: "system information page",
                message: "page is not active".to_owned(),
            });
        }
        self.rebind(binding);
        let binding = self.binding.clone().ok_or(CoreError::NoActiveTarget)?;
        self.next_request_id = self.next_request_id.wrapping_add(1).max(1);
        let lease = SystemInfoRequestLease {
            activation_generation: self.activation_generation,
            request_id: self.next_request_id,
            binding,
            kind,
        };
        match kind {
            RequestKind::Summary => self.latest_summary_request = Some(lease.request_id),
            RequestKind::Table(tab) => {
                self.latest_table_request = Some((tab, lease.request_id));
            }
        }
        Ok(lease)
    }

    fn begin_detail_request(
        &mut self,
        binding: Option<SystemInfoBinding>,
    ) -> CoreResult<Option<(SystemInfoDetailLease, SystemInfoDetailRequest)>> {
        if !self.active {
            return Err(CoreError::Validation {
                subject: "system information page",
                message: "page is not active".to_owned(),
            });
        }
        self.rebind(binding);
        let binding = self.binding.clone().ok_or(CoreError::NoActiveTarget)?;
        let row_id = self
            .selected_row_id
            .clone()
            .ok_or_else(|| CoreError::Validation {
                subject: "system information detail",
                message: "no row is selected".to_owned(),
            })?;
        let tab = self.active_tab;
        let Some(request) = self
            .active_table()
            .ok_or_else(|| CoreError::Validation {
                subject: "system information detail",
                message: "active table is not loaded".to_owned(),
            })?
            .detail_request(&row_id)?
        else {
            self.latest_detail_request = None;
            self.detail = None;
            return Ok(None);
        };
        self.next_request_id = self.next_request_id.wrapping_add(1).max(1);
        let lease = SystemInfoDetailLease {
            activation_generation: self.activation_generation,
            request_id: self.next_request_id,
            binding,
            tab,
            row_id: row_id.clone(),
        };
        self.latest_detail_request = Some((tab, row_id, lease.request_id));
        self.detail = None;
        Ok(Some((lease, request)))
    }

    pub fn accepts(
        &self,
        lease: &SystemInfoRequestLease,
        binding: Option<&SystemInfoBinding>,
    ) -> bool {
        self.active
            && self.activation_generation == lease.activation_generation
            && binding == Some(&lease.binding)
            && match lease.kind {
                RequestKind::Summary => self.latest_summary_request == Some(lease.request_id),
                RequestKind::Table(tab) => {
                    self.latest_table_request == Some((tab, lease.request_id))
                }
            }
    }

    fn accepts_detail(
        &self,
        lease: &SystemInfoDetailLease,
        binding: Option<&SystemInfoBinding>,
    ) -> bool {
        self.active
            && self.activation_generation == lease.activation_generation
            && binding == Some(&lease.binding)
            && self.active_tab == lease.tab
            && self.selected_row_id.as_deref() == Some(lease.row_id.as_str())
            && self
                .latest_detail_request
                .as_ref()
                .is_some_and(|(tab, row_id, request_id)| {
                    *tab == lease.tab && row_id == &lease.row_id && *request_id == lease.request_id
                })
    }

    fn apply_summary(
        &mut self,
        lease: &SystemInfoRequestLease,
        binding: Option<&SystemInfoBinding>,
        summary: SystemInfoSummary,
    ) -> bool {
        if !self.accepts(lease, binding) || lease.kind != RequestKind::Summary {
            return false;
        }
        self.latest_summary_request = None;
        self.summary = Some(summary);
        true
    }

    fn apply_table(
        &mut self,
        lease: &SystemInfoRequestLease,
        binding: Option<&SystemInfoBinding>,
        table: SystemInfoTable,
    ) -> bool {
        let RequestKind::Table(tab) = lease.kind else {
            return false;
        };
        if table.tab != tab || !self.accepts(lease, binding) {
            return false;
        }
        self.latest_table_request = None;
        let selected = self
            .selected_row_id
            .clone()
            .filter(|row_id| table.rows.iter().any(|row| row.id == *row_id));
        self.tables.insert(tab, table);
        self.selected_row_id = selected;
        self.latest_detail_request = None;
        self.detail = None;
        self.rebuild_filtered_rows();
        true
    }

    fn apply_detail(
        &mut self,
        lease: &SystemInfoDetailLease,
        binding: Option<&SystemInfoBinding>,
        detail: SystemInfoDetail,
    ) -> bool {
        if detail.tab != lease.tab
            || detail.row_id != lease.row_id
            || !self.accepts_detail(lease, binding)
        {
            return false;
        }
        self.latest_detail_request = None;
        self.detail = Some(detail);
        true
    }

    pub fn filtered_rows(&self) -> Vec<&SystemInfoRow> {
        let Some(table) = self.active_table() else {
            return Vec::new();
        };
        self.filtered_row_indices
            .iter()
            .filter_map(|index| table.rows.get(*index))
            .collect()
    }

    pub fn filtered_row_count(&self) -> usize {
        self.filtered_row_indices.len()
    }

    fn rebuild_filtered_rows(&mut self) {
        let query = self.query.trim().to_lowercase();
        let filter_columns = filter_columns(self.active_tab);
        self.filtered_row_indices = self
            .active_table()
            .into_iter()
            .flat_map(|table| table.rows.iter().enumerate())
            .filter_map(|(index, row)| {
                ((query.is_empty()
                    || row
                        .cells
                        .iter()
                        .any(|cell| cell.to_lowercase().contains(&query)))
                    && self
                        .risk_filter
                        .is_none_or(|risk_filter| row.risk == risk_filter)
                    && self.facet_filters.iter().enumerate().all(|(index, value)| {
                        value.as_ref().is_none_or(|value| {
                            filter_columns
                                .get(index)
                                .and_then(|column| row.cells.get(*column))
                                == Some(value)
                        })
                    }))
                .then_some(index)
            })
            .collect();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemInfoClipboardIntent {
    pub row_count: usize,
    pub text: String,
}

impl SystemInfoClipboardIntent {
    pub fn from_rows(table: &SystemInfoTable, rows: &[&SystemInfoRow]) -> Self {
        let mut lines = vec![table.columns.join("\t")];
        lines.extend(rows.iter().map(|row| row.cells.join("\t")));
        Self {
            row_count: rows.len(),
            text: lines.join("\n"),
        }
    }

    pub fn from_row(
        table: &SystemInfoTable,
        row: &SystemInfoRow,
        detail: Option<&SystemInfoDetail>,
    ) -> Self {
        let mut lines = table
            .columns
            .iter()
            .zip(&row.cells)
            .map(|(column, value)| format!("{column}: {value}"))
            .collect::<Vec<_>>();
        if let Some(detail) = detail.filter(|detail| detail.row_id == row.id) {
            lines.extend(
                detail
                    .fields
                    .iter()
                    .map(|field| format!("{}: {}", field.label, field.value)),
            );
        }
        Self {
            row_count: 1,
            text: lines.join("\n"),
        }
    }
}

pub struct SystemInfoPage {
    services: Arc<BackendServices>,
    tokio: Arc<TokioBridge>,
    shared: Entity<SharedAppState>,
    model: SystemInfoModel,
    show_overview: bool,
    search_input: Entity<InputState>,
    table_scroll: UniformListScrollHandle,
    summary_abort: Option<tokio::task::AbortHandle>,
    table_abort: Option<tokio::task::AbortHandle>,
    detail_abort: Option<tokio::task::AbortHandle>,
    process_investigation_abort: Option<tokio::task::AbortHandle>,
    process_signal_plan_abort: Option<tokio::task::AbortHandle>,
    service_investigation_abort: Option<tokio::task::AbortHandle>,
    service_runtime_plan_abort: Option<tokio::task::AbortHandle>,
    user_investigation_abort: Option<tokio::task::AbortHandle>,
    login_investigation_abort: Option<tokio::task::AbortHandle>,
    user_account_plan_abort: Option<tokio::task::AbortHandle>,
    network_investigation_abort: Option<tokio::task::AbortHandle>,
    network_disconnect_plan_abort: Option<tokio::task::AbortHandle>,
    network_firewall_plan_abort: Option<tokio::task::AbortHandle>,
    summary_loading: bool,
    table_loading: bool,
    detail_loading: bool,
    summary_error: Option<SharedString>,
    table_error: Option<SharedString>,
    detail_error: Option<SharedString>,
    process_investigation_request_id: u64,
    process_signal_request_id: u64,
    process_execution_request_id: u64,
    process_group: ProcessInvestigationGroup,
    process_investigation_action: Option<ProcessInvestigationAction>,
    process_investigation_loading: bool,
    process_investigation_result: Option<ProcessInvestigationResult>,
    process_investigation_error: Option<SharedString>,
    process_signal_busy: bool,
    process_signal_executing: bool,
    pending_process_signal: Option<PendingProcessSignal>,
    service_investigation_request_id: u64,
    service_runtime_request_id: u64,
    service_execution_request_id: u64,
    service_group: ServiceInvestigationGroup,
    service_investigation_action: Option<ServiceInvestigationAction>,
    service_investigation_loading: bool,
    service_investigation_result: Option<ServiceInvestigationResult>,
    service_investigation_error: Option<SharedString>,
    service_runtime_busy: bool,
    service_runtime_executing: bool,
    pending_service_runtime: Option<PendingServiceRuntime>,
    user_investigation_request_id: u64,
    login_investigation_request_id: u64,
    user_account_request_id: u64,
    user_account_execution_request_id: u64,
    user_group: UserInvestigationGroup,
    login_group: LoginInvestigationGroup,
    user_investigation_action: Option<UserInvestigationAction>,
    login_investigation_action: Option<LoginInvestigationAction>,
    user_investigation_loading: bool,
    login_investigation_loading: bool,
    user_investigation_result: Option<UserInvestigationResult>,
    login_investigation_result: Option<LoginInvestigationResult>,
    user_investigation_error: Option<SharedString>,
    login_investigation_error: Option<SharedString>,
    user_account_busy: bool,
    user_account_executing: bool,
    pending_user_account: Option<PendingUserAccount>,
    artifact_investigation_abort: Option<tokio::task::AbortHandle>,
    artifact_mutation_plan_abort: Option<tokio::task::AbortHandle>,
    artifact_investigation_request_id: u64,
    artifact_mutation_request_id: u64,
    artifact_mutation_execution_request_id: u64,
    artifact_investigation_action: Option<ArtifactInvestigationAction>,
    artifact_investigation_loading: bool,
    artifact_investigation_result: Option<ArtifactInvestigationResult>,
    artifact_investigation_error: Option<SharedString>,
    artifact_mutation_busy: bool,
    artifact_mutation_executing: bool,
    pending_artifact_mutation: Option<PendingArtifactMutation>,
    network_investigation_request_id: u64,
    network_disconnect_request_id: u64,
    network_execution_request_id: u64,
    network_group: NetworkInvestigationGroup,
    network_investigation_action: Option<NetworkInvestigationAction>,
    network_investigation_loading: bool,
    network_investigation_result: Option<NetworkInvestigationResult>,
    network_investigation_error: Option<SharedString>,
    network_disconnect_busy: bool,
    network_disconnect_executing: bool,
    pending_network_disconnect: Option<PendingNetworkDisconnect>,
    network_firewall_request_id: u64,
    network_firewall_execution_request_id: u64,
    network_firewall_busy: bool,
    network_firewall_executing: bool,
    pending_network_firewall: Option<PendingNetworkFirewall>,
    notice: Option<(SharedString, bool)>,
    row_context_menu: Option<RowContextMenuState>,
    filter_menu: Option<TableFilterMenuState>,
    _subscriptions: Vec<Subscription>,
}

impl SystemInfoPage {
    pub fn new(
        services: Arc<BackendServices>,
        tokio: Arc<TokioBridge>,
        shared: Entity<SharedAppState>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let search_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("搜索当前数据面的任意字段…"));
        let subscriptions = vec![
            cx.subscribe_in(
                &search_input,
                window,
                |page, input, event: &InputEvent, _, cx| {
                    if matches!(event, InputEvent::Change) {
                        page.model.set_query(input.read(cx).value().to_string());
                        page.reset_table_scroll(cx);
                        cx.notify();
                    }
                },
            ),
            cx.observe(&shared, |page, _, cx| page.handle_shared_change(cx)),
        ];
        Self {
            services,
            tokio,
            shared,
            model: SystemInfoModel::default(),
            show_overview: true,
            search_input,
            table_scroll: UniformListScrollHandle::new(),
            summary_abort: None,
            table_abort: None,
            detail_abort: None,
            process_investigation_abort: None,
            process_signal_plan_abort: None,
            service_investigation_abort: None,
            service_runtime_plan_abort: None,
            user_investigation_abort: None,
            login_investigation_abort: None,
            user_account_plan_abort: None,
            network_investigation_abort: None,
            network_disconnect_plan_abort: None,
            network_firewall_plan_abort: None,
            summary_loading: false,
            table_loading: false,
            detail_loading: false,
            summary_error: None,
            table_error: None,
            detail_error: None,
            process_investigation_request_id: 0,
            process_signal_request_id: 0,
            process_execution_request_id: 0,
            process_group: ProcessInvestigationGroup::Basics,
            process_investigation_action: None,
            process_investigation_loading: false,
            process_investigation_result: None,
            process_investigation_error: None,
            process_signal_busy: false,
            process_signal_executing: false,
            pending_process_signal: None,
            service_investigation_request_id: 0,
            service_runtime_request_id: 0,
            service_execution_request_id: 0,
            service_group: ServiceInvestigationGroup::Basics,
            service_investigation_action: None,
            service_investigation_loading: false,
            service_investigation_result: None,
            service_investigation_error: None,
            service_runtime_busy: false,
            service_runtime_executing: false,
            pending_service_runtime: None,
            user_investigation_request_id: 0,
            login_investigation_request_id: 0,
            user_account_request_id: 0,
            user_account_execution_request_id: 0,
            user_group: UserInvestigationGroup::Basics,
            login_group: LoginInvestigationGroup::User,
            user_investigation_action: None,
            login_investigation_action: None,
            user_investigation_loading: false,
            login_investigation_loading: false,
            user_investigation_result: None,
            login_investigation_result: None,
            user_investigation_error: None,
            login_investigation_error: None,
            user_account_busy: false,
            user_account_executing: false,
            pending_user_account: None,
            artifact_investigation_abort: None,
            artifact_mutation_plan_abort: None,
            artifact_investigation_request_id: 0,
            artifact_mutation_request_id: 0,
            artifact_mutation_execution_request_id: 0,
            artifact_investigation_action: None,
            artifact_investigation_loading: false,
            artifact_investigation_result: None,
            artifact_investigation_error: None,
            artifact_mutation_busy: false,
            artifact_mutation_executing: false,
            pending_artifact_mutation: None,
            network_investigation_request_id: 0,
            network_disconnect_request_id: 0,
            network_execution_request_id: 0,
            network_group: NetworkInvestigationGroup::IpInformation,
            network_investigation_action: None,
            network_investigation_loading: false,
            network_investigation_result: None,
            network_investigation_error: None,
            network_disconnect_busy: false,
            network_disconnect_executing: false,
            pending_network_disconnect: None,
            network_firewall_request_id: 0,
            network_firewall_execution_request_id: 0,
            network_firewall_busy: false,
            network_firewall_executing: false,
            pending_network_firewall: None,
            notice: None,
            row_context_menu: None,
            filter_menu: None,
            _subscriptions: subscriptions,
        }
    }

    pub fn activate(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let binding = SystemInfoBinding::capture(self.shared.read(cx));
        self.model.activate(binding);
        self.search_input
            .update(cx, |input, cx| input.focus(window, cx));
        self.refresh(cx);
    }

    pub fn deactivate(&mut self, cx: &mut Context<Self>) {
        if let Some(abort) = self.summary_abort.take() {
            abort.abort();
        }
        if let Some(abort) = self.table_abort.take() {
            abort.abort();
        }
        if let Some(abort) = self.detail_abort.take() {
            abort.abort();
        }
        self.reset_row_interactions();
        self.summary_loading = false;
        self.table_loading = false;
        self.detail_loading = false;
        self.detail_error = None;
        self.row_context_menu = None;
        self.filter_menu = None;
        self.model.deactivate();
        cx.notify();
    }

    pub const fn is_active(&self) -> bool {
        self.model.is_active()
    }

    pub fn refresh(&mut self, cx: &mut Context<Self>) {
        self.refresh_summary(cx);
        if !self.show_overview {
            self.refresh_table(cx);
        }
    }

    fn handle_shared_change(&mut self, cx: &mut Context<Self>) {
        if !self.model.is_active() {
            return;
        }
        let binding = self.current_binding(cx);
        if self.model.binding() == binding.as_ref() {
            return;
        }
        if let Some(abort) = self.summary_abort.take() {
            abort.abort();
        }
        if let Some(abort) = self.table_abort.take() {
            abort.abort();
        }
        if let Some(abort) = self.detail_abort.take() {
            abort.abort();
        }
        self.reset_row_interactions();
        self.summary_loading = false;
        self.table_loading = false;
        self.detail_loading = false;
        self.summary_error = None;
        self.table_error = None;
        self.detail_error = None;
        self.row_context_menu = None;
        self.filter_menu = None;
        self.model.rebind(binding);
        self.reset_table_scroll(cx);
        if self.model.binding().is_some() {
            self.refresh(cx);
        } else {
            self.summary_error = Some("未连接目标，无法读取系统概要".into());
            self.table_error = Some("未连接目标，无法读取系统信息".into());
            cx.notify();
        }
    }

    fn current_session(&self, cx: &Context<Self>) -> Option<BoundSshSession> {
        self.shared
            .read(cx)
            .active_ssh
            .as_ref()
            .map(|active| active.session.clone())
    }

    fn current_binding(&self, cx: &Context<Self>) -> Option<SystemInfoBinding> {
        SystemInfoBinding::capture(self.shared.read(cx))
    }

    fn reset_process_interaction(&mut self) {
        let detached_execution = self.process_signal_executing;
        if let Some(abort) = self.process_investigation_abort.take() {
            abort.abort();
        }
        if let Some(abort) = self.process_signal_plan_abort.take() {
            abort.abort();
        }
        self.process_investigation_request_id =
            self.process_investigation_request_id.wrapping_add(1).max(1);
        self.process_signal_request_id = self.process_signal_request_id.wrapping_add(1).max(1);
        self.process_execution_request_id =
            self.process_execution_request_id.wrapping_add(1).max(1);
        self.process_group = ProcessInvestigationGroup::Basics;
        self.process_investigation_action = None;
        self.process_investigation_loading = false;
        self.process_investigation_result = None;
        self.process_investigation_error = None;
        self.process_signal_busy = false;
        self.process_signal_executing = false;
        self.pending_process_signal = None;
        if detached_execution {
            self.notice = Some((
                "进程操作继续在后台完成审计与验证；结果可在操作日志查看".into(),
                false,
            ));
        }
    }

    fn reset_service_interaction(&mut self) {
        let detached_execution = self.service_runtime_executing;
        if let Some(abort) = self.service_investigation_abort.take() {
            abort.abort();
        }
        if let Some(abort) = self.service_runtime_plan_abort.take() {
            abort.abort();
        }
        self.service_investigation_request_id =
            self.service_investigation_request_id.wrapping_add(1).max(1);
        self.service_runtime_request_id = self.service_runtime_request_id.wrapping_add(1).max(1);
        self.service_execution_request_id =
            self.service_execution_request_id.wrapping_add(1).max(1);
        self.service_group = ServiceInvestigationGroup::Basics;
        self.service_investigation_action = None;
        self.service_investigation_loading = false;
        self.service_investigation_result = None;
        self.service_investigation_error = None;
        self.service_runtime_busy = false;
        self.service_runtime_executing = false;
        self.pending_service_runtime = None;
        if detached_execution {
            self.notice = Some((
                "服务操作继续在后台完成审计与验证；结果可在操作日志查看".into(),
                false,
            ));
        }
    }

    fn reset_account_interaction(&mut self) {
        let detached_execution = self.user_account_executing;
        if let Some(abort) = self.user_investigation_abort.take() {
            abort.abort();
        }
        if let Some(abort) = self.login_investigation_abort.take() {
            abort.abort();
        }
        if let Some(abort) = self.user_account_plan_abort.take() {
            abort.abort();
        }
        self.user_investigation_request_id =
            self.user_investigation_request_id.wrapping_add(1).max(1);
        self.login_investigation_request_id =
            self.login_investigation_request_id.wrapping_add(1).max(1);
        self.user_account_request_id = self.user_account_request_id.wrapping_add(1).max(1);
        self.user_account_execution_request_id = self
            .user_account_execution_request_id
            .wrapping_add(1)
            .max(1);
        self.user_group = UserInvestigationGroup::Basics;
        self.login_group = LoginInvestigationGroup::User;
        self.user_investigation_action = None;
        self.login_investigation_action = None;
        self.user_investigation_loading = false;
        self.login_investigation_loading = false;
        self.user_investigation_result = None;
        self.login_investigation_result = None;
        self.user_investigation_error = None;
        self.login_investigation_error = None;
        self.user_account_busy = false;
        self.user_account_executing = false;
        self.pending_user_account = None;
        if detached_execution {
            self.notice = Some((
                "账户操作继续在后台完成审计与验证；结果可在操作日志查看".into(),
                false,
            ));
        }
    }

    fn reset_artifact_interaction(&mut self) {
        let detached_execution = self.artifact_mutation_executing;
        if let Some(abort) = self.artifact_investigation_abort.take() {
            abort.abort();
        }
        if let Some(abort) = self.artifact_mutation_plan_abort.take() {
            abort.abort();
        }
        self.artifact_investigation_request_id = self
            .artifact_investigation_request_id
            .wrapping_add(1)
            .max(1);
        self.artifact_investigation_action = None;
        self.artifact_investigation_loading = false;
        self.artifact_investigation_result = None;
        self.artifact_investigation_error = None;
        self.artifact_mutation_request_id =
            self.artifact_mutation_request_id.wrapping_add(1).max(1);
        self.artifact_mutation_execution_request_id = self
            .artifact_mutation_execution_request_id
            .wrapping_add(1)
            .max(1);
        self.artifact_mutation_busy = false;
        self.artifact_mutation_executing = false;
        self.pending_artifact_mutation = None;
        if detached_execution {
            self.notice = Some((
                "系统对象处置继续在后台完成审计与验证；结果可在操作日志查看".into(),
                false,
            ));
        }
    }

    fn reset_network_interaction(&mut self) {
        let detached_execution =
            self.network_disconnect_executing || self.network_firewall_executing;
        if let Some(abort) = self.network_investigation_abort.take() {
            abort.abort();
        }
        if let Some(abort) = self.network_disconnect_plan_abort.take() {
            abort.abort();
        }
        if let Some(abort) = self.network_firewall_plan_abort.take() {
            abort.abort();
        }
        self.network_investigation_request_id =
            self.network_investigation_request_id.wrapping_add(1).max(1);
        self.network_disconnect_request_id =
            self.network_disconnect_request_id.wrapping_add(1).max(1);
        self.network_execution_request_id =
            self.network_execution_request_id.wrapping_add(1).max(1);
        self.network_firewall_request_id = self.network_firewall_request_id.wrapping_add(1).max(1);
        self.network_firewall_execution_request_id = self
            .network_firewall_execution_request_id
            .wrapping_add(1)
            .max(1);
        self.network_group = NetworkInvestigationGroup::IpInformation;
        self.network_investigation_action = None;
        self.network_investigation_loading = false;
        self.network_investigation_result = None;
        self.network_investigation_error = None;
        self.network_disconnect_busy = false;
        self.network_disconnect_executing = false;
        self.pending_network_disconnect = None;
        self.network_firewall_busy = false;
        self.network_firewall_executing = false;
        self.pending_network_firewall = None;
        if detached_execution {
            self.notice = Some((
                "网络处置继续在后台完成审计与验证；结果可在操作日志查看".into(),
                false,
            ));
        }
    }

    fn reset_row_interactions(&mut self) {
        self.reset_process_interaction();
        self.reset_service_interaction();
        self.reset_account_interaction();
        self.reset_artifact_interaction();
        self.reset_network_interaction();
    }

    fn process_lease(
        &self,
        request_id: u64,
        row_id: impl Into<String>,
        cx: &Context<Self>,
    ) -> CoreResult<ProcessInteractionLease> {
        let binding = self.current_binding(cx).ok_or(CoreError::NoActiveTarget)?;
        Ok(ProcessInteractionLease {
            activation_generation: self.model.activation_generation,
            request_id,
            binding,
            row_id: row_id.into(),
        })
    }

    fn accepts_process_lease(&self, lease: &ProcessInteractionLease) -> bool {
        process_lease_is_current(&self.model, lease)
    }

    fn service_lease(
        &self,
        request_id: u64,
        row_id: impl Into<String>,
        cx: &Context<Self>,
    ) -> CoreResult<ServiceInteractionLease> {
        let binding = self.current_binding(cx).ok_or(CoreError::NoActiveTarget)?;
        Ok(ServiceInteractionLease {
            activation_generation: self.model.activation_generation,
            request_id,
            binding,
            tab: self.model.active_tab(),
            row_id: row_id.into(),
        })
    }

    fn accepts_service_lease(&self, lease: &ServiceInteractionLease) -> bool {
        service_lease_is_current(&self.model, lease)
    }

    fn account_lease(
        &self,
        request_id: u64,
        row_id: impl Into<String>,
        cx: &Context<Self>,
    ) -> CoreResult<AccountInteractionLease> {
        let binding = self.current_binding(cx).ok_or(CoreError::NoActiveTarget)?;
        let tab = self.model.active_tab();
        if !is_account_tab(tab) {
            return Err(CoreError::Validation {
                subject: "account interaction",
                message: "the active data view is not a user or login-history inventory".to_owned(),
            });
        }
        Ok(AccountInteractionLease {
            activation_generation: self.model.activation_generation,
            request_id,
            binding,
            tab,
            row_id: row_id.into(),
        })
    }

    fn accepts_account_lease(&self, lease: &AccountInteractionLease) -> bool {
        account_lease_is_current(&self.model, lease)
    }

    fn artifact_lease(
        &self,
        request_id: u64,
        row_id: impl Into<String>,
        cx: &Context<Self>,
    ) -> CoreResult<ArtifactInteractionLease> {
        let binding = self.current_binding(cx).ok_or(CoreError::NoActiveTarget)?;
        let tab = self.model.active_tab();
        if !is_artifact_tab(tab) {
            return Err(CoreError::Validation {
                subject: "system artifact interaction",
                message: "the active data view does not expose typed artifact investigations"
                    .to_owned(),
            });
        }
        Ok(ArtifactInteractionLease {
            activation_generation: self.model.activation_generation,
            request_id,
            binding,
            tab,
            row_id: row_id.into(),
        })
    }

    fn accepts_artifact_lease(&self, lease: &ArtifactInteractionLease) -> bool {
        artifact_lease_is_current(&self.model, lease)
    }

    fn network_lease(
        &self,
        request_id: u64,
        row_id: impl Into<String>,
        cx: &Context<Self>,
    ) -> CoreResult<NetworkInteractionLease> {
        let binding = self.current_binding(cx).ok_or(CoreError::NoActiveTarget)?;
        let tab = self.model.active_tab();
        if !is_network_tab(tab) {
            return Err(CoreError::Validation {
                subject: "network interaction",
                message: "the active data view is not a network inventory".to_owned(),
            });
        }
        Ok(NetworkInteractionLease {
            activation_generation: self.model.activation_generation,
            request_id,
            binding,
            tab,
            row_id: row_id.into(),
        })
    }

    fn accepts_network_lease(&self, lease: &NetworkInteractionLease) -> bool {
        network_lease_is_current(&self.model, lease)
    }

    fn firewall_lease(
        &self,
        request_id: u64,
        row_id: impl Into<String>,
        cx: &Context<Self>,
    ) -> CoreResult<FirewallInteractionLease> {
        let row_id = row_id.into();
        match self.model.active_tab() {
            SystemInfoTab::LoginHistory => self
                .account_lease(request_id, row_id, cx)
                .map(FirewallInteractionLease::LoginHistory),
            tab if is_network_tab(tab) => self
                .network_lease(request_id, row_id, cx)
                .map(FirewallInteractionLease::Network),
            _ => Err(CoreError::Validation {
                subject: "firewall interaction",
                message: "the active data view has no source IP firewall action".to_owned(),
            }),
        }
    }

    fn renew_firewall_lease(
        &self,
        previous: &FirewallInteractionLease,
        request_id: u64,
        cx: &Context<Self>,
    ) -> CoreResult<FirewallInteractionLease> {
        let row_id = previous.row_id().to_owned();
        match previous {
            FirewallInteractionLease::Network(_) => self
                .network_lease(request_id, row_id, cx)
                .map(FirewallInteractionLease::Network),
            FirewallInteractionLease::LoginHistory(_) => self
                .account_lease(request_id, row_id, cx)
                .map(FirewallInteractionLease::LoginHistory),
        }
    }

    fn accepts_firewall_lease(&self, lease: &FirewallInteractionLease) -> bool {
        firewall_lease_is_current(&self.model, lease)
    }

    fn prepare_request(
        &mut self,
        kind: RequestKind,
        cx: &mut Context<Self>,
    ) -> CoreResult<(SystemInfoRequestLease, BoundSshSession)> {
        let session = self.current_session(cx).ok_or(CoreError::NoActiveTarget)?;
        let binding = Some(SystemInfoBinding::from_session(&session));
        let lease = self.model.begin_request(kind, binding)?;
        Ok((lease, session))
    }

    fn refresh_summary(&mut self, cx: &mut Context<Self>) {
        let (lease, session) = match self.prepare_request(RequestKind::Summary, cx) {
            Ok(request) => request,
            Err(error) => {
                self.summary_error = Some(format!("无法加载概要：{error}").into());
                self.summary_loading = false;
                cx.notify();
                return;
            }
        };
        if let Some(abort) = self.summary_abort.take() {
            abort.abort();
        }
        self.summary_loading = true;
        self.summary_error = None;
        let service = self.services.system_info().clone();
        let task = self
            .tokio
            .spawn(async move { service.summary(&session).await });
        self.summary_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_summary(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_summary(
        &mut self,
        lease: SystemInfoRequestLease,
        result: Result<CoreResult<SystemInfoSummary>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            return;
        }
        self.summary_loading = false;
        self.summary_abort = None;
        match result {
            Ok(Ok(summary)) => {
                let _ = self.model.apply_summary(&lease, binding.as_ref(), summary);
                self.summary_error = None;
            }
            Ok(Err(error)) => {
                self.summary_error = Some(format!("系统概要读取失败：{error}").into());
            }
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                self.summary_error = Some(format!("系统概要任务失败：{error}").into());
            }
        }
        cx.notify();
    }

    fn refresh_table(&mut self, cx: &mut Context<Self>) {
        self.reset_row_interactions();
        self.row_context_menu = None;
        self.filter_menu = None;
        let tab = self.model.active_tab();
        let (lease, session) = match self.prepare_request(RequestKind::Table(tab), cx) {
            Ok(request) => request,
            Err(error) => {
                self.table_error = Some(format!("无法加载 {}：{error}", tab.label()).into());
                self.table_loading = false;
                cx.notify();
                return;
            }
        };
        if let Some(abort) = self.table_abort.take() {
            abort.abort();
        }
        if let Some(abort) = self.detail_abort.take() {
            abort.abort();
        }
        self.detail_loading = false;
        self.detail_error = None;
        self.model.invalidate_detail();
        self.table_loading = true;
        self.table_error = None;
        let request = match SystemInfoRequest::new(tab, DEFAULT_MAXIMUM_ROWS) {
            Ok(request) => request,
            Err(error) => {
                self.table_error = Some(format!("系统信息请求无效：{error}").into());
                self.table_loading = false;
                return;
            }
        };
        let service = self.services.system_info().clone();
        let task = self
            .tokio
            .spawn(async move { service.collect(&session, &request).await });
        self.table_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_table(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_table(
        &mut self,
        lease: SystemInfoRequestLease,
        result: Result<CoreResult<SystemInfoTable>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            return;
        }
        self.table_loading = false;
        self.table_abort = None;
        match result {
            Ok(Ok(table)) => {
                let applied = self.model.apply_table(&lease, binding.as_ref(), table);
                self.table_error = None;
                if applied {
                    self.reset_table_scroll(cx);
                }
                if applied && self.model.selected_row().is_some() {
                    self.refresh_detail(cx);
                }
            }
            Ok(Err(error)) => {
                self.table_error =
                    Some(format!("{} 读取失败：{error}", self.model.active_tab().label()).into());
            }
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                self.table_error = Some(format!("系统信息任务失败：{error}").into());
            }
        }
        cx.notify();
    }

    fn switch_tab(&mut self, tab: SystemInfoTab, window: &mut Window, cx: &mut Context<Self>) {
        self.reset_row_interactions();
        if let Some(abort) = self.detail_abort.take() {
            abort.abort();
        }
        self.detail_loading = false;
        self.detail_error = None;
        self.row_context_menu = None;
        self.filter_menu = None;
        self.show_overview = false;
        self.model.switch_tab(tab);
        self.reset_table_scroll(cx);
        self.search_input
            .update(cx, |input, cx| input.set_value("", window, cx));
        if self.model.active_table().is_none() {
            self.refresh_table(cx);
        } else {
            cx.notify();
        }
    }

    fn open_overview(&mut self, cx: &mut Context<Self>) {
        self.reset_row_interactions();
        if let Some(abort) = self.table_abort.take() {
            abort.abort();
        }
        if let Some(abort) = self.detail_abort.take() {
            abort.abort();
        }
        self.table_loading = false;
        self.detail_loading = false;
        self.detail_error = None;
        self.row_context_menu = None;
        self.filter_menu = None;
        self.model.close_detail();
        self.show_overview = true;
        if self.model.summary().is_none() && !self.summary_loading {
            self.refresh_summary(cx);
        } else {
            cx.notify();
        }
    }

    fn reset_filters(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.filter_menu = None;
        self.model.reset_filters();
        self.reset_table_scroll(cx);
        self.search_input
            .update(cx, |input, cx| input.set_value("", window, cx));
        cx.notify();
    }

    fn select_row(&mut self, row_id: &str, cx: &mut Context<Self>) {
        if self.model.selected_row_id.as_deref() != Some(row_id) {
            self.reset_row_interactions();
        }
        if self.model.select_row(row_id) {
            self.refresh_detail(cx);
        }
    }

    fn refresh_detail(&mut self, cx: &mut Context<Self>) {
        if let Some(abort) = self.detail_abort.take() {
            abort.abort();
        }
        self.detail_loading = false;
        self.detail_error = None;
        let Some(session) = self.current_session(cx) else {
            self.detail_error = Some("无法读取详情：当前没有活动 SSH 目标".into());
            cx.notify();
            return;
        };
        let binding = Some(SystemInfoBinding::from_session(&session));
        let (lease, request) = match self.model.begin_detail_request(binding) {
            Ok(Some(request)) => request,
            Ok(None) => {
                cx.notify();
                return;
            }
            Err(error) => {
                self.detail_error = Some(format!("无法读取详情：{error}").into());
                cx.notify();
                return;
            }
        };
        self.detail_loading = true;
        let service = self.services.system_info().clone();
        let task = self
            .tokio
            .spawn(async move { service.detail(&session, &request).await });
        self.detail_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_detail(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_detail(
        &mut self,
        lease: SystemInfoDetailLease,
        result: Result<CoreResult<SystemInfoDetail>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts_detail(&lease, binding.as_ref()) {
            return;
        }
        self.detail_loading = false;
        self.detail_abort = None;
        match result {
            Ok(Ok(detail)) => {
                let _ = self.model.apply_detail(&lease, binding.as_ref(), detail);
                self.detail_error = None;
            }
            Ok(Err(error)) => {
                self.detail_error = Some(format!("详情读取失败：{error}").into());
            }
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                self.detail_error = Some(format!("详情任务失败：{error}").into());
            }
        }
        cx.notify();
    }

    fn close_detail(&mut self, cx: &mut Context<Self>) {
        self.reset_row_interactions();
        if let Some(abort) = self.detail_abort.take() {
            abort.abort();
        }
        self.detail_loading = false;
        self.detail_error = None;
        self.model.close_detail();
        cx.notify();
    }

    fn reset_table_scroll(&self, cx: &mut Context<Self>) {
        self.table_scroll.scroll_to_item(0, ScrollStrategy::Top);
        cx.notify();
    }

    fn copy_selected(&mut self, cx: &mut Context<Self>) {
        let (Some(table), Some(row)) = (self.model.active_table(), self.model.selected_row())
        else {
            return;
        };
        let intent = SystemInfoClipboardIntent::from_row(table, row, self.model.detail());
        cx.write_to_clipboard(ClipboardItem::new_string(intent.text));
        self.notice = Some(("已复制所选行详情".into(), false));
        cx.notify();
    }

    fn copy_overview(&mut self, cx: &mut Context<Self>) {
        let Some(summary) = self.model.summary() else {
            return;
        };
        let text = overview_fields(summary)
            .into_iter()
            .map(|(label, value)| format!("{label}: {value}"))
            .collect::<Vec<_>>()
            .join("\n");
        cx.write_to_clipboard(ClipboardItem::new_string(text));
        self.notice = Some(("已复制系统概览".into(), false));
        cx.notify();
    }

    fn select_process_group(&mut self, group: ProcessInvestigationGroup, cx: &mut Context<Self>) {
        self.process_group = group;
        cx.notify();
    }

    fn run_process_investigation(
        &mut self,
        row_id: &str,
        action: ProcessInvestigationAction,
        cx: &mut Context<Self>,
    ) {
        if self.model.selected_row_id.as_deref() != Some(row_id) {
            self.select_row(row_id, cx);
        }
        let request = match self
            .model
            .active_table()
            .ok_or_else(|| CoreError::Validation {
                subject: "process investigation",
                message: "process table missing".to_owned(),
            })
            .and_then(|table| table.process_investigation_request(row_id, action))
        {
            Ok(request) => request,
            Err(error) => {
                self.process_investigation_error = Some(error.to_string().into());
                cx.notify();
                return;
            }
        };
        let Some(session) = self.current_session(cx) else {
            self.process_investigation_error = Some("当前没有活动 SSH 目标".into());
            cx.notify();
            return;
        };
        if let Some(abort) = self.process_investigation_abort.take() {
            abort.abort();
        }
        self.process_investigation_request_id =
            self.process_investigation_request_id.wrapping_add(1).max(1);
        let lease = match self.process_lease(
            self.process_investigation_request_id,
            row_id.to_owned(),
            cx,
        ) {
            Ok(lease) => lease,
            Err(error) => {
                self.process_investigation_error = Some(error.to_string().into());
                cx.notify();
                return;
            }
        };
        self.process_group = action.group();
        self.process_investigation_action = Some(action);
        self.process_investigation_loading = true;
        self.process_investigation_result = None;
        self.process_investigation_error = None;
        self.row_context_menu = None;
        let service = self.services.system_info().clone();
        let task = self
            .tokio
            .spawn(async move { service.investigate_process(&session, &request).await });
        self.process_investigation_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        page.finish_process_investigation(lease, result, cx)
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_process_investigation(
        &mut self,
        lease: ProcessInteractionLease,
        result: Result<CoreResult<ProcessInvestigationResult>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if lease.request_id != self.process_investigation_request_id
            || !self.accepts_process_lease(&lease)
        {
            return;
        }
        self.process_investigation_abort = None;
        self.process_investigation_loading = false;
        match result {
            Ok(Ok(result)) if result.row_id == lease.row_id => {
                self.process_investigation_action = Some(result.action);
                self.process_investigation_result = Some(result);
                self.process_investigation_error = None;
            }
            Ok(Ok(_)) => return,
            Ok(Err(error)) => {
                self.process_investigation_result = None;
                self.process_investigation_error = Some(error.to_string().into());
            }
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                self.process_investigation_result = None;
                self.process_investigation_error = Some(format!("调查任务失败：{error}").into());
            }
        }
        cx.notify();
    }

    fn copy_process_investigation(&mut self, cx: &mut Context<Self>) {
        let Some(result) = self.process_investigation_result.as_ref() else {
            return;
        };
        cx.write_to_clipboard(ClipboardItem::new_string(result.output.clone()));
        self.notice = Some(("已复制进程调查结果".into(), false));
        cx.notify();
    }

    fn prepare_process_signal(
        &mut self,
        row_id: &str,
        signal: ProcessSignal,
        cx: &mut Context<Self>,
    ) {
        if self.process_signal_busy {
            return;
        }
        if self.model.selected_row_id.as_deref() != Some(row_id) {
            self.select_row(row_id, cx);
        }
        let request = match self
            .model
            .active_table()
            .ok_or_else(|| CoreError::Validation {
                subject: "process signal",
                message: "process table missing".to_owned(),
            })
            .and_then(|table| table.process_signal_request(row_id, signal))
        {
            Ok(request) => request,
            Err(error) => {
                self.notice = Some((error.to_string().into(), true));
                cx.notify();
                return;
            }
        };
        let Some(session) = self.current_session(cx) else {
            self.notice = Some(("当前没有活动 SSH 目标".into(), true));
            cx.notify();
            return;
        };
        if let Some(abort) = self.process_signal_plan_abort.take() {
            abort.abort();
        }
        self.process_signal_request_id = self.process_signal_request_id.wrapping_add(1).max(1);
        let lease = match self.process_lease(self.process_signal_request_id, row_id.to_owned(), cx)
        {
            Ok(lease) => lease,
            Err(error) => {
                self.notice = Some((error.to_string().into(), true));
                cx.notify();
                return;
            }
        };
        self.pending_process_signal = None;
        self.process_signal_busy = true;
        self.process_signal_executing = false;
        self.row_context_menu = None;
        let service = self.services.system_info().clone();
        let task = self
            .tokio
            .spawn(async move { service.plan_process_signal(&session, &request).await });
        self.process_signal_plan_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        page.finish_process_signal_plan(lease, result, cx)
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_process_signal_plan(
        &mut self,
        lease: ProcessInteractionLease,
        result: Result<CoreResult<ProcessSignalPlan>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if lease.request_id != self.process_signal_request_id || !self.accepts_process_lease(&lease)
        {
            return;
        }
        self.process_signal_plan_abort = None;
        self.process_signal_busy = false;
        self.process_signal_executing = false;
        match result {
            Ok(Ok(plan)) if plan.row_id() == lease.row_id => {
                self.pending_process_signal = Some(PendingProcessSignal { lease, plan });
                self.notice = None;
            }
            Ok(Ok(_)) => return,
            Ok(Err(error)) => self.notice = Some((error.to_string().into(), true)),
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                self.notice = Some((format!("终止计划创建失败：{error}").into(), true));
            }
        }
        cx.notify();
    }

    fn cancel_process_signal(&mut self, cx: &mut Context<Self>) {
        if self.process_signal_busy {
            return;
        }
        self.pending_process_signal = None;
        self.process_signal_executing = false;
        self.process_signal_request_id = self.process_signal_request_id.wrapping_add(1).max(1);
        cx.notify();
    }

    fn approve_process_signal(&mut self, cx: &mut Context<Self>) {
        if self.process_signal_busy {
            return;
        }
        let Some(pending) = self.pending_process_signal.take() else {
            return;
        };
        if !self.accepts_process_lease(&pending.lease) {
            self.notice = Some(("目标或进程已变化，请重新创建终止计划".into(), true));
            cx.notify();
            return;
        }
        let Some(session) = self.current_session(cx) else {
            self.notice = Some(("当前没有活动 SSH 目标".into(), true));
            cx.notify();
            return;
        };
        self.process_execution_request_id =
            self.process_execution_request_id.wrapping_add(1).max(1);
        let lease = match self.process_lease(
            self.process_execution_request_id,
            pending.lease.row_id.clone(),
            cx,
        ) {
            Ok(lease) => lease,
            Err(error) => {
                self.notice = Some((error.to_string().into(), true));
                cx.notify();
                return;
            }
        };
        let confirmation = DangerousConfirmation::approve(pending.plan.definition());
        let service = self.services.system_info().clone();
        let journal = self.services.operation_journal().clone();
        self.process_signal_busy = true;
        self.process_signal_executing = true;
        self.notice = Some(("正在发送进程信号并验证结果…".into(), false));
        let task = self.tokio.spawn(async move {
            service
                .execute_process_signal(&session, pending.plan, confirmation, &journal)
                .await
        });
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        page.finish_process_signal_execution(lease, result, cx)
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_process_signal_execution(
        &mut self,
        lease: ProcessInteractionLease,
        result: Result<CoreResult<ProcessSignalOutcome>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if lease.request_id != self.process_execution_request_id
            || !self.accepts_process_lease(&lease)
        {
            return;
        }
        self.process_signal_busy = false;
        self.process_signal_executing = false;
        match result {
            Ok(Ok(outcome)) if outcome.verification.passed => {
                self.notice = Some((
                    format!("{} 已完成并通过状态回读", outcome.signal.label()).into(),
                    false,
                ));
                self.refresh_table(cx);
            }
            Ok(Ok(outcome)) => {
                self.notice = Some((outcome.verification.detail.into(), true));
            }
            Ok(Err(error)) => self.notice = Some((error.to_string().into(), true)),
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                self.notice = Some((format!("进程信号任务失败：{error}").into(), true));
            }
        }
        cx.notify();
    }

    fn select_service_group(&mut self, group: ServiceInvestigationGroup, cx: &mut Context<Self>) {
        self.service_group = group;
        cx.notify();
    }

    fn run_service_investigation(
        &mut self,
        row_id: &str,
        action: ServiceInvestigationAction,
        cx: &mut Context<Self>,
    ) {
        if self.model.selected_row_id.as_deref() != Some(row_id) {
            self.select_row(row_id, cx);
        }
        let request = match self
            .model
            .active_table()
            .ok_or_else(|| CoreError::Validation {
                subject: "service investigation",
                message: "service table missing".to_owned(),
            })
            .and_then(|table| table.service_investigation_request(row_id, action))
        {
            Ok(request) => request,
            Err(error) => {
                self.service_investigation_error = Some(error.to_string().into());
                cx.notify();
                return;
            }
        };
        let Some(session) = self.current_session(cx) else {
            self.service_investigation_error = Some("当前没有活动 SSH 目标".into());
            cx.notify();
            return;
        };
        if let Some(abort) = self.service_investigation_abort.take() {
            abort.abort();
        }
        self.service_investigation_request_id =
            self.service_investigation_request_id.wrapping_add(1).max(1);
        let lease = match self.service_lease(
            self.service_investigation_request_id,
            row_id.to_owned(),
            cx,
        ) {
            Ok(lease) => lease,
            Err(error) => {
                self.service_investigation_error = Some(error.to_string().into());
                cx.notify();
                return;
            }
        };
        self.service_group = action.group();
        self.service_investigation_action = Some(action);
        self.service_investigation_loading = true;
        self.service_investigation_result = None;
        self.service_investigation_error = None;
        self.row_context_menu = None;
        let service = self.services.system_info().clone();
        let task = self
            .tokio
            .spawn(async move { service.investigate_service(&session, &request).await });
        self.service_investigation_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        page.finish_service_investigation(lease, result, cx)
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_service_investigation(
        &mut self,
        lease: ServiceInteractionLease,
        result: Result<CoreResult<ServiceInvestigationResult>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if lease.request_id != self.service_investigation_request_id
            || !self.accepts_service_lease(&lease)
        {
            return;
        }
        self.service_investigation_abort = None;
        self.service_investigation_loading = false;
        match result {
            Ok(Ok(result)) if result.row_id == lease.row_id => {
                self.service_investigation_action = Some(result.action);
                self.service_investigation_result = Some(result);
                self.service_investigation_error = None;
            }
            Ok(Ok(_)) => return,
            Ok(Err(error)) => {
                self.service_investigation_result = None;
                self.service_investigation_error = Some(error.to_string().into());
            }
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                self.service_investigation_result = None;
                self.service_investigation_error = Some(format!("调查任务失败：{error}").into());
            }
        }
        cx.notify();
    }

    fn copy_service_investigation(&mut self, cx: &mut Context<Self>) {
        let Some(result) = self.service_investigation_result.as_ref() else {
            return;
        };
        cx.write_to_clipboard(ClipboardItem::new_string(result.output.clone()));
        self.notice = Some(("已复制服务调查结果".into(), false));
        cx.notify();
    }

    fn prepare_service_runtime(
        &mut self,
        row_id: &str,
        action: ServiceRuntimeAction,
        cx: &mut Context<Self>,
    ) {
        if self.service_runtime_busy {
            return;
        }
        if self.model.selected_row_id.as_deref() != Some(row_id) {
            self.select_row(row_id, cx);
        }
        let request = match self
            .model
            .active_table()
            .ok_or_else(|| CoreError::Validation {
                subject: "service runtime",
                message: "service table missing".to_owned(),
            })
            .and_then(|table| table.service_runtime_request(row_id, action))
        {
            Ok(request) => request,
            Err(error) => {
                self.notice = Some((error.to_string().into(), true));
                cx.notify();
                return;
            }
        };
        let Some(session) = self.current_session(cx) else {
            self.notice = Some(("当前没有活动 SSH 目标".into(), true));
            cx.notify();
            return;
        };
        if let Some(abort) = self.service_runtime_plan_abort.take() {
            abort.abort();
        }
        self.service_runtime_request_id = self.service_runtime_request_id.wrapping_add(1).max(1);
        let lease = match self.service_lease(self.service_runtime_request_id, row_id.to_owned(), cx)
        {
            Ok(lease) => lease,
            Err(error) => {
                self.notice = Some((error.to_string().into(), true));
                cx.notify();
                return;
            }
        };
        self.pending_service_runtime = None;
        self.service_runtime_busy = true;
        self.service_runtime_executing = false;
        self.row_context_menu = None;
        let service = self.services.system_info().clone();
        let task = self
            .tokio
            .spawn(async move { service.plan_service_runtime(&session, &request).await });
        self.service_runtime_plan_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        page.finish_service_runtime_plan(lease, result, cx)
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_service_runtime_plan(
        &mut self,
        lease: ServiceInteractionLease,
        result: Result<CoreResult<ServiceRuntimePlan>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if lease.request_id != self.service_runtime_request_id
            || !self.accepts_service_lease(&lease)
        {
            return;
        }
        self.service_runtime_plan_abort = None;
        self.service_runtime_busy = false;
        self.service_runtime_executing = false;
        match result {
            Ok(Ok(plan)) if plan.row_id() == lease.row_id => {
                self.pending_service_runtime = Some(PendingServiceRuntime { lease, plan });
                self.notice = None;
            }
            Ok(Ok(_)) => return,
            Ok(Err(error)) => self.notice = Some((error.to_string().into(), true)),
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                self.notice = Some((format!("服务操作计划创建失败：{error}").into(), true));
            }
        }
        cx.notify();
    }

    fn cancel_service_runtime(&mut self, cx: &mut Context<Self>) {
        if self.service_runtime_busy {
            return;
        }
        self.pending_service_runtime = None;
        self.service_runtime_executing = false;
        self.service_runtime_request_id = self.service_runtime_request_id.wrapping_add(1).max(1);
        cx.notify();
    }

    fn approve_service_runtime(&mut self, cx: &mut Context<Self>) {
        if self.service_runtime_busy {
            return;
        }
        let Some(pending) = self.pending_service_runtime.take() else {
            return;
        };
        if !self.accepts_service_lease(&pending.lease) {
            self.notice = Some(("目标或服务已变化，请重新创建操作计划".into(), true));
            cx.notify();
            return;
        }
        let Some(session) = self.current_session(cx) else {
            self.notice = Some(("当前没有活动 SSH 目标".into(), true));
            cx.notify();
            return;
        };
        self.service_execution_request_id =
            self.service_execution_request_id.wrapping_add(1).max(1);
        let lease = match self.service_lease(
            self.service_execution_request_id,
            pending.lease.row_id.clone(),
            cx,
        ) {
            Ok(lease) => lease,
            Err(error) => {
                self.notice = Some((error.to_string().into(), true));
                cx.notify();
                return;
            }
        };
        let confirmation = DangerousConfirmation::approve(pending.plan.definition());
        let service = self.services.system_info().clone();
        let journal = self.services.operation_journal().clone();
        self.service_runtime_busy = true;
        self.service_runtime_executing = true;
        self.notice = Some(("正在执行服务操作并回读 systemd 状态…".into(), false));
        let task = self.tokio.spawn(async move {
            service
                .execute_service_runtime(&session, pending.plan, confirmation, &journal)
                .await
        });
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        page.finish_service_runtime_execution(lease, result, cx)
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_service_runtime_execution(
        &mut self,
        lease: ServiceInteractionLease,
        result: Result<CoreResult<ServiceRuntimeOutcome>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if lease.request_id != self.service_execution_request_id
            || !self.accepts_service_lease(&lease)
        {
            return;
        }
        self.service_runtime_busy = false;
        self.service_runtime_executing = false;
        match result {
            Ok(Ok(outcome)) if outcome.verification.passed => {
                self.notice = Some((
                    format!("{} 已完成并通过状态回读", outcome.action.label()).into(),
                    false,
                ));
                self.refresh_table(cx);
            }
            Ok(Ok(outcome)) if outcome.restored_after_failed_verification => {
                self.notice = Some((
                    format!(
                        "{} 未通过回读，已自动恢复确认前的启用状态",
                        outcome.action.label()
                    )
                    .into(),
                    true,
                ));
                self.refresh_table(cx);
            }
            Ok(Ok(outcome)) => {
                self.notice = Some((outcome.verification.detail.into(), true));
            }
            Ok(Err(error)) => self.notice = Some((error.to_string().into(), true)),
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                self.notice = Some((format!("服务操作任务失败：{error}").into(), true));
            }
        }
        cx.notify();
    }

    fn select_user_group(&mut self, group: UserInvestigationGroup, cx: &mut Context<Self>) {
        self.user_group = group;
        cx.notify();
    }

    fn run_user_investigation(
        &mut self,
        row_id: &str,
        action: UserInvestigationAction,
        cx: &mut Context<Self>,
    ) {
        if self.model.selected_row_id.as_deref() != Some(row_id) {
            self.select_row(row_id, cx);
        }
        let request = match self
            .model
            .active_table()
            .ok_or_else(|| CoreError::Validation {
                subject: "user investigation",
                message: "user table missing".to_owned(),
            })
            .and_then(|table| table.user_investigation_request(row_id, action))
        {
            Ok(request) => request,
            Err(error) => {
                self.user_investigation_error = Some(error.to_string().into());
                self.row_context_menu = None;
                cx.notify();
                return;
            }
        };
        let Some(session) = self.current_session(cx) else {
            self.user_investigation_error = Some("当前没有活动 SSH 目标".into());
            cx.notify();
            return;
        };
        if let Some(abort) = self.user_investigation_abort.take() {
            abort.abort();
        }
        self.user_investigation_request_id =
            self.user_investigation_request_id.wrapping_add(1).max(1);
        let lease =
            match self.account_lease(self.user_investigation_request_id, row_id.to_owned(), cx) {
                Ok(lease) => lease,
                Err(error) => {
                    self.user_investigation_error = Some(error.to_string().into());
                    cx.notify();
                    return;
                }
            };
        self.user_group = action.group();
        self.user_investigation_action = Some(action);
        self.user_investigation_loading = true;
        self.user_investigation_result = None;
        self.user_investigation_error = None;
        self.row_context_menu = None;
        let service = self.services.system_info().clone();
        let task = self
            .tokio
            .spawn(async move { service.investigate_user(&session, &request).await });
        self.user_investigation_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        page.finish_user_investigation(lease, result, cx)
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_user_investigation(
        &mut self,
        lease: AccountInteractionLease,
        result: Result<CoreResult<UserInvestigationResult>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if lease.request_id != self.user_investigation_request_id
            || lease.tab != SystemInfoTab::Users
            || !self.accepts_account_lease(&lease)
        {
            return;
        }
        self.user_investigation_abort = None;
        self.user_investigation_loading = false;
        match result {
            Ok(Ok(result)) if result.row_id == lease.row_id => {
                self.user_investigation_action = Some(result.action);
                self.user_investigation_result = Some(result);
                self.user_investigation_error = None;
            }
            Ok(Ok(_)) => return,
            Ok(Err(error)) => {
                self.user_investigation_result = None;
                self.user_investigation_error = Some(error.to_string().into());
            }
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                self.user_investigation_result = None;
                self.user_investigation_error = Some(format!("用户调查任务失败：{error}").into());
            }
        }
        cx.notify();
    }

    fn copy_user_investigation(&mut self, cx: &mut Context<Self>) {
        let Some(result) = self.user_investigation_result.as_ref() else {
            return;
        };
        cx.write_to_clipboard(ClipboardItem::new_string(result.output.clone()));
        self.notice = Some(("已复制用户调查结果".into(), false));
        cx.notify();
    }

    fn select_login_group(&mut self, group: LoginInvestigationGroup, cx: &mut Context<Self>) {
        self.login_group = group;
        cx.notify();
    }

    fn run_login_investigation(
        &mut self,
        row_id: &str,
        action: LoginInvestigationAction,
        cx: &mut Context<Self>,
    ) {
        if self.model.selected_row_id.as_deref() != Some(row_id) {
            self.select_row(row_id, cx);
        }
        let request = match self
            .model
            .active_table()
            .ok_or_else(|| CoreError::Validation {
                subject: "login-history investigation",
                message: "login-history table missing".to_owned(),
            })
            .and_then(|table| table.login_investigation_request(row_id, action))
        {
            Ok(request) => request,
            Err(error) => {
                self.login_investigation_error = Some(error.to_string().into());
                self.row_context_menu = None;
                cx.notify();
                return;
            }
        };
        let Some(session) = self.current_session(cx) else {
            self.login_investigation_error = Some("当前没有活动 SSH 目标".into());
            cx.notify();
            return;
        };
        if let Some(abort) = self.login_investigation_abort.take() {
            abort.abort();
        }
        self.login_investigation_request_id =
            self.login_investigation_request_id.wrapping_add(1).max(1);
        let lease =
            match self.account_lease(self.login_investigation_request_id, row_id.to_owned(), cx) {
                Ok(lease) => lease,
                Err(error) => {
                    self.login_investigation_error = Some(error.to_string().into());
                    cx.notify();
                    return;
                }
            };
        self.login_group = action.group();
        self.login_investigation_action = Some(action);
        self.login_investigation_loading = true;
        self.login_investigation_result = None;
        self.login_investigation_error = None;
        self.row_context_menu = None;
        let service = self.services.system_info().clone();
        let task = self
            .tokio
            .spawn(async move { service.investigate_login(&session, &request).await });
        self.login_investigation_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        page.finish_login_investigation(lease, result, cx)
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_login_investigation(
        &mut self,
        lease: AccountInteractionLease,
        result: Result<CoreResult<LoginInvestigationResult>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if lease.request_id != self.login_investigation_request_id
            || lease.tab != SystemInfoTab::LoginHistory
            || !self.accepts_account_lease(&lease)
        {
            return;
        }
        self.login_investigation_abort = None;
        self.login_investigation_loading = false;
        match result {
            Ok(Ok(result)) if result.row_id == lease.row_id => {
                self.login_investigation_action = Some(result.action);
                self.login_investigation_result = Some(result);
                self.login_investigation_error = None;
            }
            Ok(Ok(_)) => return,
            Ok(Err(error)) => {
                self.login_investigation_result = None;
                self.login_investigation_error = Some(error.to_string().into());
            }
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                self.login_investigation_result = None;
                self.login_investigation_error =
                    Some(format!("登录历史调查任务失败：{error}").into());
            }
        }
        cx.notify();
    }

    fn copy_login_investigation(&mut self, cx: &mut Context<Self>) {
        let Some(result) = self.login_investigation_result.as_ref() else {
            return;
        };
        cx.write_to_clipboard(ClipboardItem::new_string(result.output.clone()));
        self.notice = Some(("已复制登录历史调查结果".into(), false));
        cx.notify();
    }

    fn run_artifact_investigation(
        &mut self,
        row_id: &str,
        action: ArtifactInvestigationAction,
        cx: &mut Context<Self>,
    ) {
        if self.model.selected_row_id.as_deref() != Some(row_id) {
            self.select_row(row_id, cx);
        }
        let request = match self
            .model
            .active_table()
            .ok_or_else(|| CoreError::Validation {
                subject: "system artifact investigation",
                message: "artifact table missing".to_owned(),
            })
            .and_then(|table| table.artifact_investigation_request(row_id, action))
        {
            Ok(request) => request,
            Err(error) => {
                self.artifact_investigation_error = Some(error.to_string().into());
                self.row_context_menu = None;
                cx.notify();
                return;
            }
        };
        let Some(session) = self.current_session(cx) else {
            self.artifact_investigation_error = Some("当前没有活动 SSH 目标".into());
            cx.notify();
            return;
        };
        if let Some(abort) = self.artifact_investigation_abort.take() {
            abort.abort();
        }
        self.artifact_investigation_request_id = self
            .artifact_investigation_request_id
            .wrapping_add(1)
            .max(1);
        let lease = match self.artifact_lease(
            self.artifact_investigation_request_id,
            row_id.to_owned(),
            cx,
        ) {
            Ok(lease) => lease,
            Err(error) => {
                self.artifact_investigation_error = Some(error.to_string().into());
                cx.notify();
                return;
            }
        };
        self.artifact_investigation_action = Some(action);
        self.artifact_investigation_loading = true;
        self.artifact_investigation_result = None;
        self.artifact_investigation_error = None;
        self.row_context_menu = None;
        let service = self.services.system_info().clone();
        let task = self
            .tokio
            .spawn(async move { service.investigate_artifact(&session, &request).await });
        self.artifact_investigation_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        page.finish_artifact_investigation(lease, result, cx)
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_artifact_investigation(
        &mut self,
        lease: ArtifactInteractionLease,
        result: Result<CoreResult<ArtifactInvestigationResult>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if lease.request_id != self.artifact_investigation_request_id
            || !self.accepts_artifact_lease(&lease)
        {
            return;
        }
        self.artifact_investigation_abort = None;
        self.artifact_investigation_loading = false;
        match result {
            Ok(Ok(result)) if result.row_id == lease.row_id && result.action.tab() == lease.tab => {
                self.artifact_investigation_action = Some(result.action);
                self.artifact_investigation_result = Some(result);
                self.artifact_investigation_error = None;
            }
            Ok(Ok(_)) => return,
            Ok(Err(error)) => {
                self.artifact_investigation_result = None;
                self.artifact_investigation_error = Some(error.to_string().into());
            }
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                self.artifact_investigation_result = None;
                self.artifact_investigation_error =
                    Some(format!("系统对象调查任务失败：{error}").into());
            }
        }
        cx.notify();
    }

    fn copy_artifact_investigation(&mut self, cx: &mut Context<Self>) {
        let Some(result) = self.artifact_investigation_result.as_ref() else {
            return;
        };
        cx.write_to_clipboard(ClipboardItem::new_string(result.output.clone()));
        self.notice = Some(("已复制调查结果".into(), false));
        cx.notify();
    }

    fn prepare_artifact_mutation(
        &mut self,
        row_id: &str,
        action: ArtifactMutationAction,
        cx: &mut Context<Self>,
    ) {
        if self.artifact_mutation_busy || self.pending_artifact_mutation.is_some() {
            return;
        }
        if self.model.selected_row_id.as_deref() != Some(row_id) {
            self.select_row(row_id, cx);
        }
        let request = match self
            .model
            .active_table()
            .ok_or_else(|| CoreError::Validation {
                subject: "system artifact mutation",
                message: "artifact table missing".to_owned(),
            })
            .and_then(|table| table.artifact_mutation_request(row_id, action))
        {
            Ok(request) => request,
            Err(error) => {
                self.notice = Some((error.to_string().into(), true));
                self.row_context_menu = None;
                cx.notify();
                return;
            }
        };
        let Some(session) = self.current_session(cx) else {
            self.notice = Some(("当前没有活动 SSH 目标".into(), true));
            cx.notify();
            return;
        };
        if let Some(abort) = self.artifact_mutation_plan_abort.take() {
            abort.abort();
        }
        self.artifact_mutation_request_id =
            self.artifact_mutation_request_id.wrapping_add(1).max(1);
        let lease =
            match self.artifact_lease(self.artifact_mutation_request_id, row_id.to_owned(), cx) {
                Ok(lease) => lease,
                Err(error) => {
                    self.notice = Some((error.to_string().into(), true));
                    cx.notify();
                    return;
                }
            };
        self.artifact_mutation_busy = true;
        self.artifact_mutation_executing = false;
        self.row_context_menu = None;
        self.notice = Some(("正在读取文件快照并生成可恢复操作计划…".into(), false));
        let service = self.services.system_info().clone();
        let task = self
            .tokio
            .spawn(async move { service.plan_artifact_mutation(&session, &request).await });
        self.artifact_mutation_plan_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        page.finish_artifact_mutation_plan(lease, result, cx)
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_artifact_mutation_plan(
        &mut self,
        lease: ArtifactInteractionLease,
        result: Result<CoreResult<ArtifactMutationPlan>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if lease.request_id != self.artifact_mutation_request_id
            || !self.accepts_artifact_lease(&lease)
        {
            return;
        }
        self.artifact_mutation_plan_abort = None;
        self.artifact_mutation_busy = false;
        self.artifact_mutation_executing = false;
        match result {
            Ok(Ok(plan)) if plan.row_id() == lease.row_id && plan.action().tab() == lease.tab => {
                self.pending_artifact_mutation = Some(PendingArtifactMutation { lease, plan });
                self.notice = None;
            }
            Ok(Ok(_)) => return,
            Ok(Err(error)) => self.notice = Some((error.to_string().into(), true)),
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                self.notice = Some((format!("文件处置计划创建失败：{error}").into(), true));
            }
        }
        cx.notify();
    }

    fn cancel_artifact_mutation(&mut self, cx: &mut Context<Self>) {
        if self.artifact_mutation_busy {
            return;
        }
        self.pending_artifact_mutation = None;
        self.artifact_mutation_executing = false;
        self.artifact_mutation_request_id =
            self.artifact_mutation_request_id.wrapping_add(1).max(1);
        cx.notify();
    }

    fn approve_artifact_mutation(&mut self, cx: &mut Context<Self>) {
        if self.artifact_mutation_busy {
            return;
        }
        let Some(pending) = self.pending_artifact_mutation.take() else {
            return;
        };
        if !self.accepts_artifact_lease(&pending.lease) {
            self.notice = Some(("目标、页面或对象行已变化，请重新创建操作计划".into(), true));
            cx.notify();
            return;
        }
        let Some(session) = self.current_session(cx) else {
            self.notice = Some(("当前没有活动 SSH 目标".into(), true));
            cx.notify();
            return;
        };
        self.artifact_mutation_execution_request_id = self
            .artifact_mutation_execution_request_id
            .wrapping_add(1)
            .max(1);
        let lease = match self.artifact_lease(
            self.artifact_mutation_execution_request_id,
            pending.lease.row_id.clone(),
            cx,
        ) {
            Ok(lease) => lease,
            Err(error) => {
                self.notice = Some((error.to_string().into(), true));
                cx.notify();
                return;
            }
        };
        let confirmation = DangerousConfirmation::approve(pending.plan.definition());
        let service = self.services.system_info().clone();
        let journal = self.services.operation_journal().clone();
        self.artifact_mutation_busy = true;
        self.artifact_mutation_executing = true;
        self.notice = Some(("正在执行文件处置、写入审计并回读验证…".into(), false));
        let task = self.tokio.spawn(async move {
            service
                .execute_artifact_mutation(&session, pending.plan, confirmation, &journal)
                .await
        });
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        page.finish_artifact_mutation_execution(lease, result, cx)
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_artifact_mutation_execution(
        &mut self,
        lease: ArtifactInteractionLease,
        result: Result<CoreResult<ArtifactMutationOutcome>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if lease.request_id != self.artifact_mutation_execution_request_id
            || !self.accepts_artifact_lease(&lease)
        {
            return;
        }
        self.artifact_mutation_busy = false;
        self.artifact_mutation_executing = false;
        match result {
            Ok(Ok(outcome)) if outcome.row_id == lease.row_id && outcome.verification.passed => {
                self.notice = Some((
                    format!("{} 已完成并通过回读验证", outcome.action.label()).into(),
                    false,
                ));
                self.refresh_table(cx);
            }
            Ok(Ok(outcome)) if outcome.restored_after_failed_verification => {
                self.notice = Some((
                    format!(
                        "{} 未通过回读，已自动恢复确认前状态",
                        outcome.action.label()
                    )
                    .into(),
                    true,
                ));
                self.refresh_table(cx);
            }
            Ok(Ok(outcome)) => {
                self.notice = Some((outcome.verification.detail.into(), true));
            }
            Ok(Err(error)) => self.notice = Some((error.to_string().into(), true)),
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                self.notice = Some((format!("文件处置任务失败：{error}").into(), true));
            }
        }
        cx.notify();
    }

    fn copy_environment_value(&mut self, row_id: &str, cx: &mut Context<Self>) {
        let result = self
            .model
            .active_table()
            .filter(|table| table.tab == SystemInfoTab::EnvVars)
            .and_then(|table| table.rows.iter().find(|row| row.id == row_id))
            .and_then(|row| row.cells.get(1));
        match result {
            Some(value) => {
                cx.write_to_clipboard(ClipboardItem::new_string(value.clone()));
                self.notice = Some(("已复制变量值".into(), false));
            }
            None => self.notice = Some(("变量值已过期，请刷新后重试".into(), true)),
        }
        self.row_context_menu = None;
        cx.notify();
    }

    fn prepare_user_account(
        &mut self,
        row_id: &str,
        action: UserAccountAction,
        cx: &mut Context<Self>,
    ) {
        if self.user_account_busy {
            return;
        }
        if self.model.selected_row_id.as_deref() != Some(row_id) {
            self.select_row(row_id, cx);
        }
        let request = match self
            .model
            .active_table()
            .ok_or_else(|| CoreError::Validation {
                subject: "user account operation",
                message: "account table missing".to_owned(),
            })
            .and_then(|table| table.user_account_request(row_id, action))
        {
            Ok(request) => request,
            Err(error) => {
                self.notice = Some((error.to_string().into(), true));
                cx.notify();
                return;
            }
        };
        let Some(session) = self.current_session(cx) else {
            self.notice = Some(("当前没有活动 SSH 目标".into(), true));
            cx.notify();
            return;
        };
        if let Some(abort) = self.user_account_plan_abort.take() {
            abort.abort();
        }
        self.user_account_request_id = self.user_account_request_id.wrapping_add(1).max(1);
        let lease = match self.account_lease(self.user_account_request_id, row_id.to_owned(), cx) {
            Ok(lease) => lease,
            Err(error) => {
                self.notice = Some((error.to_string().into(), true));
                cx.notify();
                return;
            }
        };
        self.pending_user_account = None;
        self.user_account_busy = true;
        self.user_account_executing = false;
        self.row_context_menu = None;
        let service = self.services.system_info().clone();
        let task = self
            .tokio
            .spawn(async move { service.plan_user_account(&session, &request).await });
        self.user_account_plan_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        page.finish_user_account_plan(lease, result, cx)
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_user_account_plan(
        &mut self,
        lease: AccountInteractionLease,
        result: Result<CoreResult<UserAccountPlan>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if lease.request_id != self.user_account_request_id || !self.accepts_account_lease(&lease) {
            return;
        }
        self.user_account_plan_abort = None;
        self.user_account_busy = false;
        self.user_account_executing = false;
        match result {
            Ok(Ok(plan)) if plan.row_id() == lease.row_id => {
                self.pending_user_account = Some(PendingUserAccount { lease, plan });
                self.notice = None;
            }
            Ok(Ok(_)) => return,
            Ok(Err(error)) => self.notice = Some((error.to_string().into(), true)),
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                self.notice = Some((format!("账户操作计划创建失败：{error}").into(), true));
            }
        }
        cx.notify();
    }

    fn cancel_user_account(&mut self, cx: &mut Context<Self>) {
        if self.user_account_busy {
            return;
        }
        self.pending_user_account = None;
        self.user_account_executing = false;
        self.user_account_request_id = self.user_account_request_id.wrapping_add(1).max(1);
        cx.notify();
    }

    fn approve_user_account(&mut self, cx: &mut Context<Self>) {
        if self.user_account_busy {
            return;
        }
        let Some(pending) = self.pending_user_account.take() else {
            return;
        };
        if !self.accepts_account_lease(&pending.lease) {
            self.notice = Some(("目标或用户行已变化，请重新创建账户操作计划".into(), true));
            cx.notify();
            return;
        }
        let Some(session) = self.current_session(cx) else {
            self.notice = Some(("当前没有活动 SSH 目标".into(), true));
            cx.notify();
            return;
        };
        self.user_account_execution_request_id = self
            .user_account_execution_request_id
            .wrapping_add(1)
            .max(1);
        let lease = match self.account_lease(
            self.user_account_execution_request_id,
            pending.lease.row_id.clone(),
            cx,
        ) {
            Ok(lease) => lease,
            Err(error) => {
                self.notice = Some((error.to_string().into(), true));
                cx.notify();
                return;
            }
        };
        let confirmation = DangerousConfirmation::approve(pending.plan.definition());
        let service = self.services.system_info().clone();
        let journal = self.services.operation_journal().clone();
        self.user_account_busy = true;
        self.user_account_executing = true;
        self.notice = Some(("正在执行账户操作并回读密码状态…".into(), false));
        let task = self.tokio.spawn(async move {
            service
                .execute_user_account(&session, pending.plan, confirmation, &journal)
                .await
        });
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        page.finish_user_account_execution(lease, result, cx)
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_user_account_execution(
        &mut self,
        lease: AccountInteractionLease,
        result: Result<CoreResult<UserAccountOutcome>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if lease.request_id != self.user_account_execution_request_id
            || !self.accepts_account_lease(&lease)
        {
            return;
        }
        self.user_account_busy = false;
        self.user_account_executing = false;
        match result {
            Ok(Ok(outcome)) if outcome.verification.passed => {
                self.notice = Some((
                    format!("{} 已完成并通过状态回读", outcome.action.label()).into(),
                    false,
                ));
                self.refresh_table(cx);
            }
            Ok(Ok(outcome)) if outcome.restored_after_failed_verification => {
                self.notice = Some((
                    format!(
                        "{} 未通过回读，已恢复确认前账户状态",
                        outcome.action.label()
                    )
                    .into(),
                    true,
                ));
                self.refresh_table(cx);
            }
            Ok(Ok(outcome)) => {
                self.notice = Some((outcome.verification.detail.into(), true));
            }
            Ok(Err(error)) => self.notice = Some((error.to_string().into(), true)),
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                self.notice = Some((format!("账户操作任务失败：{error}").into(), true));
            }
        }
        cx.notify();
    }

    fn select_network_group(&mut self, group: NetworkInvestigationGroup, cx: &mut Context<Self>) {
        self.network_group = group;
        cx.notify();
    }

    fn run_network_investigation(
        &mut self,
        row_id: &str,
        action: NetworkInvestigationAction,
        cx: &mut Context<Self>,
    ) {
        if self.model.selected_row_id.as_deref() != Some(row_id) {
            self.select_row(row_id, cx);
        }
        let request = match self
            .model
            .active_table()
            .ok_or_else(|| CoreError::Validation {
                subject: "network investigation",
                message: "network table missing".to_owned(),
            })
            .and_then(|table| table.network_investigation_request(row_id, action))
        {
            Ok(request) => request,
            Err(error) => {
                self.network_investigation_error = Some(error.to_string().into());
                self.row_context_menu = None;
                cx.notify();
                return;
            }
        };
        let Some(session) = self.current_session(cx) else {
            self.network_investigation_error = Some("当前没有活动 SSH 目标".into());
            cx.notify();
            return;
        };
        if let Some(abort) = self.network_investigation_abort.take() {
            abort.abort();
        }
        self.network_investigation_request_id =
            self.network_investigation_request_id.wrapping_add(1).max(1);
        let lease = match self.network_lease(
            self.network_investigation_request_id,
            row_id.to_owned(),
            cx,
        ) {
            Ok(lease) => lease,
            Err(error) => {
                self.network_investigation_error = Some(error.to_string().into());
                cx.notify();
                return;
            }
        };
        self.network_group = action.group();
        self.network_investigation_action = Some(action);
        self.network_investigation_loading = true;
        self.network_investigation_result = None;
        self.network_investigation_error = None;
        self.row_context_menu = None;
        let service = self.services.system_info().clone();
        let task = self
            .tokio
            .spawn(async move { service.investigate_network(&session, &request).await });
        self.network_investigation_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        page.finish_network_investigation(lease, result, cx)
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_network_investigation(
        &mut self,
        lease: NetworkInteractionLease,
        result: Result<CoreResult<NetworkInvestigationResult>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if lease.request_id != self.network_investigation_request_id
            || !self.accepts_network_lease(&lease)
        {
            return;
        }
        self.network_investigation_abort = None;
        self.network_investigation_loading = false;
        match result {
            Ok(Ok(result)) if result.row_id == lease.row_id => {
                self.network_investigation_action = Some(result.action);
                self.network_investigation_result = Some(result);
                self.network_investigation_error = None;
            }
            Ok(Ok(_)) => return,
            Ok(Err(error)) => {
                self.network_investigation_result = None;
                self.network_investigation_error = Some(error.to_string().into());
            }
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                self.network_investigation_result = None;
                self.network_investigation_error =
                    Some(format!("网络调查任务失败：{error}").into());
            }
        }
        cx.notify();
    }

    fn copy_network_investigation(&mut self, cx: &mut Context<Self>) {
        let Some(result) = self.network_investigation_result.as_ref() else {
            return;
        };
        cx.write_to_clipboard(ClipboardItem::new_string(result.output.clone()));
        self.notice = Some(("已复制网络调查结果".into(), false));
        cx.notify();
    }

    fn prepare_network_disconnect(&mut self, row_id: &str, cx: &mut Context<Self>) {
        if self.network_disconnect_busy {
            return;
        }
        if self.model.selected_row_id.as_deref() != Some(row_id) {
            self.select_row(row_id, cx);
        }
        let request = match self
            .model
            .active_table()
            .ok_or_else(|| CoreError::Validation {
                subject: "network disconnect",
                message: "network table missing".to_owned(),
            })
            .and_then(|table| table.network_disconnect_request(row_id))
        {
            Ok(request) => request,
            Err(error) => {
                self.notice = Some((error.to_string().into(), true));
                self.row_context_menu = None;
                cx.notify();
                return;
            }
        };
        let Some(session) = self.current_session(cx) else {
            self.notice = Some(("当前没有活动 SSH 目标".into(), true));
            cx.notify();
            return;
        };
        if let Some(abort) = self.network_disconnect_plan_abort.take() {
            abort.abort();
        }
        self.network_disconnect_request_id =
            self.network_disconnect_request_id.wrapping_add(1).max(1);
        let lease =
            match self.network_lease(self.network_disconnect_request_id, row_id.to_owned(), cx) {
                Ok(lease) => lease,
                Err(error) => {
                    self.notice = Some((error.to_string().into(), true));
                    cx.notify();
                    return;
                }
            };
        self.pending_network_disconnect = None;
        self.network_disconnect_busy = true;
        self.network_disconnect_executing = false;
        self.row_context_menu = None;
        let service = self.services.system_info().clone();
        let task = self
            .tokio
            .spawn(async move { service.plan_network_disconnect(&session, &request).await });
        self.network_disconnect_plan_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        page.finish_network_disconnect_plan(lease, result, cx)
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_network_disconnect_plan(
        &mut self,
        lease: NetworkInteractionLease,
        result: Result<CoreResult<NetworkDisconnectPlan>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if lease.request_id != self.network_disconnect_request_id
            || !self.accepts_network_lease(&lease)
        {
            return;
        }
        self.network_disconnect_plan_abort = None;
        self.network_disconnect_busy = false;
        self.network_disconnect_executing = false;
        match result {
            Ok(Ok(plan)) if plan.identity().row_id == lease.row_id => {
                self.pending_network_disconnect = Some(PendingNetworkDisconnect { lease, plan });
                self.notice = None;
            }
            Ok(Ok(_)) => return,
            Ok(Err(error)) => self.notice = Some((error.to_string().into(), true)),
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                self.notice = Some((format!("断开计划创建失败：{error}").into(), true));
            }
        }
        cx.notify();
    }

    fn cancel_network_disconnect(&mut self, cx: &mut Context<Self>) {
        if self.network_disconnect_busy {
            return;
        }
        self.pending_network_disconnect = None;
        self.network_disconnect_executing = false;
        self.network_disconnect_request_id =
            self.network_disconnect_request_id.wrapping_add(1).max(1);
        cx.notify();
    }

    fn approve_network_disconnect(&mut self, cx: &mut Context<Self>) {
        if self.network_disconnect_busy {
            return;
        }
        let Some(pending) = self.pending_network_disconnect.take() else {
            return;
        };
        if !self.accepts_network_lease(&pending.lease) {
            self.notice = Some(("目标或连接已变化，请重新创建断开计划".into(), true));
            cx.notify();
            return;
        }
        let Some(session) = self.current_session(cx) else {
            self.notice = Some(("当前没有活动 SSH 目标".into(), true));
            cx.notify();
            return;
        };
        self.network_execution_request_id =
            self.network_execution_request_id.wrapping_add(1).max(1);
        let lease = match self.network_lease(
            self.network_execution_request_id,
            pending.lease.row_id.clone(),
            cx,
        ) {
            Ok(lease) => lease,
            Err(error) => {
                self.notice = Some((error.to_string().into(), true));
                cx.notify();
                return;
            }
        };
        let confirmation = DangerousConfirmation::approve(pending.plan.definition());
        let service = self.services.system_info().clone();
        let journal = self.services.operation_journal().clone();
        self.network_disconnect_busy = true;
        self.network_disconnect_executing = true;
        self.notice = Some(("正在断开精确 TCP 连接并回读验证…".into(), false));
        let task = self.tokio.spawn(async move {
            service
                .execute_network_disconnect(&session, pending.plan, confirmation, &journal)
                .await
        });
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        page.finish_network_disconnect_execution(lease, result, cx)
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_network_disconnect_execution(
        &mut self,
        lease: NetworkInteractionLease,
        result: Result<CoreResult<NetworkDisconnectOutcome>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if lease.request_id != self.network_execution_request_id
            || !self.accepts_network_lease(&lease)
        {
            return;
        }
        self.network_disconnect_busy = false;
        self.network_disconnect_executing = false;
        match result {
            Ok(Ok(outcome)) if outcome.verification.passed => {
                self.notice = Some(("连接已断开并通过状态回读".into(), false));
                self.refresh_table(cx);
            }
            Ok(Ok(outcome)) => {
                self.notice = Some((outcome.verification.detail.into(), true));
            }
            Ok(Err(error)) => self.notice = Some((error.to_string().into(), true)),
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                self.notice = Some((format!("断开连接任务失败：{error}").into(), true));
            }
        }
        cx.notify();
    }

    fn network_remote_ipv4(&self, row_id: &str) -> CoreResult<String> {
        let identity = self
            .model
            .active_table()
            .ok_or_else(|| CoreError::Validation {
                subject: "network firewall",
                message: "network table missing".to_owned(),
            })?
            .network_identity(row_id)?;
        let address = identity
            .remote
            .as_ref()
            .map(|endpoint| endpoint.address)
            .ok_or_else(|| CoreError::Validation {
                subject: "network firewall",
                message: "remote IP is unavailable".to_owned(),
            })?;
        match address {
            IpAddr::V4(address) if !address.is_unspecified() => Ok(address.to_string()),
            IpAddr::V4(_) => Err(CoreError::Validation {
                subject: "network firewall",
                message: "unspecified IPv4 addresses cannot be changed".to_owned(),
            }),
            IpAddr::V6(_) => Err(CoreError::Unsupported {
                feature: "network-row IPv6 firewall mutation",
            }),
        }
    }

    fn login_source_ipv4(&self, row_id: &str) -> CoreResult<String> {
        let identity = self
            .model
            .active_table()
            .ok_or_else(|| CoreError::Validation {
                subject: "login-history firewall",
                message: "login-history table missing".to_owned(),
            })?
            .login_identity(row_id)?;
        match identity.source {
            Some(IpAddr::V4(address)) if !address.is_unspecified() => Ok(address.to_string()),
            Some(IpAddr::V4(_)) | None => Err(CoreError::Validation {
                subject: "login-history firewall",
                message: "the selected login record has no usable source IPv4 address".to_owned(),
            }),
            Some(IpAddr::V6(_)) => Err(CoreError::Unsupported {
                feature: "login-history IPv6 firewall mutation",
            }),
        }
    }

    fn prepare_network_firewall(
        &mut self,
        row_id: &str,
        intent: NetworkFirewallIntent,
        cx: &mut Context<Self>,
    ) {
        let source = match self.network_remote_ipv4(row_id) {
            Ok(source) => source,
            Err(error) => {
                self.notice = Some((error.to_string().into(), true));
                self.row_context_menu = None;
                cx.notify();
                return;
            }
        };
        self.prepare_firewall(row_id, intent, source, cx);
    }

    fn prepare_login_firewall(&mut self, row_id: &str, cx: &mut Context<Self>) {
        let source = match self.login_source_ipv4(row_id) {
            Ok(source) => source,
            Err(error) => {
                self.notice = Some((error.to_string().into(), true));
                self.row_context_menu = None;
                cx.notify();
                return;
            }
        };
        self.prepare_firewall(row_id, NetworkFirewallIntent::Block, source, cx);
    }

    fn prepare_firewall(
        &mut self,
        row_id: &str,
        intent: NetworkFirewallIntent,
        source: String,
        cx: &mut Context<Self>,
    ) {
        if self.network_firewall_busy || self.pending_network_firewall.is_some() {
            return;
        }
        if self.model.selected_row_id.as_deref() != Some(row_id) {
            self.select_row(row_id, cx);
        }
        let Some(session) = self.current_session(cx) else {
            self.notice = Some(("当前没有活动 SSH 目标".into(), true));
            cx.notify();
            return;
        };
        if let Some(abort) = self.network_firewall_plan_abort.take() {
            abort.abort();
        }
        self.network_firewall_request_id = self.network_firewall_request_id.wrapping_add(1).max(1);
        let lease =
            match self.firewall_lease(self.network_firewall_request_id, row_id.to_owned(), cx) {
                Ok(lease) => lease,
                Err(error) => {
                    self.notice = Some((error.to_string().into(), true));
                    cx.notify();
                    return;
                }
            };
        self.network_firewall_busy = true;
        self.network_firewall_executing = false;
        self.row_context_menu = None;
        self.notice = Some((format!("正在创建“{}”计划…", intent.label()).into(), false));
        let service = self.services.firewall().clone();
        let task = self.tokio.spawn(async move {
            match intent {
                NetworkFirewallIntent::Block => service
                    .plan_mutation(&session, FirewallMutationRequest::block_ipv4(source)?)
                    .await
                    .map(NetworkFirewallPlanResult::Mutation),
                NetworkFirewallIntent::TemporaryBlock => service
                    .plan_mutation(
                        &session,
                        FirewallMutationRequest::temporary_block_ipv4(source)?,
                    )
                    .await
                    .map(NetworkFirewallPlanResult::Mutation),
                NetworkFirewallIntent::Allow => service
                    .plan_restore_ipv4_block(&session, source)
                    .map(NetworkFirewallPlanResult::Resolution),
                NetworkFirewallIntent::KeepBlock => Err(CoreError::Validation {
                    subject: "network firewall",
                    message: "keep plans can only follow a verified block".to_owned(),
                }),
            }
        });
        self.network_firewall_plan_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        page.finish_network_firewall_plan(lease, intent, result, cx)
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_network_firewall_plan(
        &mut self,
        lease: FirewallInteractionLease,
        intent: NetworkFirewallIntent,
        result: Result<CoreResult<NetworkFirewallPlanResult>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if lease.request_id() != self.network_firewall_request_id
            || !self.accepts_firewall_lease(&lease)
        {
            return;
        }
        self.network_firewall_plan_abort = None;
        self.network_firewall_busy = false;
        self.network_firewall_executing = false;
        match result {
            Ok(Ok(NetworkFirewallPlanResult::Mutation(plan))) => {
                self.pending_network_firewall = Some(PendingNetworkFirewall::Mutation {
                    lease,
                    intent,
                    plan,
                });
                self.notice = None;
            }
            Ok(Ok(NetworkFirewallPlanResult::Resolution(plan))) => {
                self.pending_network_firewall = Some(PendingNetworkFirewall::Resolution {
                    lease,
                    intent,
                    plan,
                });
                self.notice = None;
            }
            Ok(Err(error)) => self.notice = Some((error.to_string().into(), true)),
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                self.notice = Some((format!("防火墙计划创建失败：{error}").into(), true));
            }
        }
        cx.notify();
    }

    fn cancel_network_firewall(&mut self, cx: &mut Context<Self>) {
        if self.network_firewall_busy {
            return;
        }
        let was_keep = self
            .pending_network_firewall
            .as_ref()
            .is_some_and(|pending| pending.intent() == NetworkFirewallIntent::KeepBlock);
        self.pending_network_firewall = None;
        self.network_firewall_executing = false;
        self.network_firewall_request_id = self.network_firewall_request_id.wrapping_add(1).max(1);
        self.notice = Some((
            if was_keep {
                "未保留封禁；远端死人开关将在剩余时间结束后自动恢复规则"
            } else {
                "防火墙计划已取消，未产生新的远端变更"
            }
            .into(),
            false,
        ));
        cx.notify();
    }

    fn approve_network_firewall(&mut self, cx: &mut Context<Self>) {
        if self.network_firewall_busy {
            return;
        }
        let Some(pending) = self.pending_network_firewall.take() else {
            return;
        };
        if !self.accepts_firewall_lease(pending.lease()) {
            self.notice = Some(("目标或网络连接已变化，请重新创建防火墙计划".into(), true));
            cx.notify();
            return;
        }
        let Some(session) = self.current_session(cx) else {
            self.notice = Some(("当前没有活动 SSH 目标".into(), true));
            cx.notify();
            return;
        };
        self.network_firewall_execution_request_id = self
            .network_firewall_execution_request_id
            .wrapping_add(1)
            .max(1);
        let lease = match self.renew_firewall_lease(
            pending.lease(),
            self.network_firewall_execution_request_id,
            cx,
        ) {
            Ok(lease) => lease,
            Err(error) => {
                self.notice = Some((error.to_string().into(), true));
                cx.notify();
                return;
            }
        };
        let intent = pending.intent();
        let confirmation = DangerousConfirmation::approve(pending.definition());
        let service = self.services.firewall().clone();
        self.network_firewall_busy = true;
        self.network_firewall_executing = true;
        self.notice = Some((
            format!("正在执行“{}”并回读验证…", intent.label()).into(),
            false,
        ));
        let task = self.tokio.spawn(async move {
            match pending {
                PendingNetworkFirewall::Mutation { plan, .. } => {
                    service.execute_mutation(&session, plan, confirmation).await
                }
                PendingNetworkFirewall::Resolution { plan, .. } => {
                    service
                        .execute_resolution(&session, plan, confirmation)
                        .await
                }
            }
        });
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        page.finish_network_firewall_execution(lease, intent, result, cx)
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_network_firewall_execution(
        &mut self,
        lease: FirewallInteractionLease,
        intent: NetworkFirewallIntent,
        result: Result<CoreResult<FirewallOperationOutcome>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if lease.request_id() != self.network_firewall_execution_request_id
            || !self.accepts_firewall_lease(&lease)
        {
            return;
        }
        self.network_firewall_busy = false;
        self.network_firewall_executing = false;
        match result {
            Ok(Ok(outcome)) if outcome.verification.passed => {
                if intent == NetworkFirewallIntent::Block {
                    let Some(session) = self.current_session(cx) else {
                        self.notice = Some((
                            "封禁已应用，但当前会话已离开；死人开关将自动恢复，未永久保留".into(),
                            true,
                        ));
                        cx.notify();
                        return;
                    };
                    match self.services.firewall().plan_resolution(
                        &session,
                        &outcome.change.id,
                        FirewallResolution::Keep,
                    ) {
                        Ok(plan) => {
                            self.network_firewall_request_id =
                                self.network_firewall_request_id.wrapping_add(1).max(1);
                            let keep_lease = match self.renew_firewall_lease(
                                &lease,
                                self.network_firewall_request_id,
                                cx,
                            ) {
                                Ok(lease) => lease,
                                Err(error) => {
                                    self.notice = Some((error.to_string().into(), true));
                                    cx.notify();
                                    return;
                                }
                            };
                            self.pending_network_firewall =
                                Some(PendingNetworkFirewall::Resolution {
                                    lease: keep_lease,
                                    intent: NetworkFirewallIntent::KeepBlock,
                                    plan,
                                });
                            self.notice = Some((
                                "封禁已临时应用；请再次确认永久保留，否则 60 秒后自动恢复".into(),
                                false,
                            ));
                        }
                        Err(error) => {
                            self.notice = Some((
                                format!(
                                    "封禁已应用但无法创建保留计划：{error}；死人开关将自动恢复"
                                )
                                .into(),
                                true,
                            ));
                        }
                    }
                } else {
                    let message = match intent {
                        NetworkFirewallIntent::TemporaryBlock => {
                            "远端 IP 已临时封禁；300 秒后由远端死人开关自动恢复"
                        }
                        NetworkFirewallIntent::Allow => {
                            "LovelyRes 管理的精确 IP 封禁已恢复并通过回读"
                        }
                        NetworkFirewallIntent::KeepBlock => "远端 IP 封禁已永久保留并通过回读",
                        NetworkFirewallIntent::Block => unreachable!("handled above"),
                    };
                    self.notice = Some((message.into(), false));
                }
            }
            Ok(Ok(outcome)) => {
                self.notice = Some((outcome.verification.detail.into(), true));
            }
            Ok(Err(error)) => self.notice = Some((error.to_string().into(), true)),
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                self.notice = Some((format!("防火墙处置任务失败：{error}").into(), true));
            }
        }
        cx.notify();
    }

    fn open_context_row_detail(
        &mut self,
        action: &OpenRowDetail,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.select_row(&action.row_id, cx);
    }

    fn copy_context_row(
        &mut self,
        action: &CopyContextRow,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(table) = self.model.active_table() else {
            return;
        };
        let Some(row) = table.rows.iter().find(|row| row.id == action.row_id) else {
            return;
        };
        let intent = SystemInfoClipboardIntent::from_row(table, row, self.model.detail());
        cx.write_to_clipboard(ClipboardItem::new_string(intent.text));
        self.notice = Some(("已复制该条记录".into(), false));
        cx.notify();
    }

    fn copy_context_identity(
        &mut self,
        action: &CopyContextIdentity,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(value) = self.context_identity(&action.row_id) else {
            return;
        };
        cx.write_to_clipboard(ClipboardItem::new_string(value.to_owned()));
        self.notice = Some(("已复制主标识".into(), false));
        cx.notify();
    }

    fn copy_network_field(
        &mut self,
        row_id: &str,
        field: NetworkCopyField,
        cx: &mut Context<Self>,
    ) {
        let Some(identity) = self
            .model
            .active_table()
            .and_then(|table| table.network_identity(row_id).ok())
        else {
            self.notice = Some(("无法读取当前网络行身份".into(), true));
            cx.notify();
            return;
        };
        let (label, value) = match field {
            NetworkCopyField::LocalEndpoint => ("本地端点", identity.local_display),
            NetworkCopyField::RemoteEndpoint => ("远端端点", identity.remote_display),
            NetworkCopyField::Process => ("进程信息", identity.process),
        };
        if value.trim().is_empty() {
            self.notice = Some((format!("当前记录没有{label}").into(), true));
        } else {
            cx.write_to_clipboard(ClipboardItem::new_string(value));
            self.notice = Some((format!("已复制{label}").into(), false));
        }
        self.row_context_menu = None;
        cx.notify();
    }

    fn copy_login_source(&mut self, row_id: &str, cx: &mut Context<Self>) {
        let source = self
            .model
            .active_table()
            .and_then(|table| table.login_identity(row_id).ok())
            .and_then(|identity| identity.source);
        match source {
            Some(source) => {
                cx.write_to_clipboard(ClipboardItem::new_string(source.to_string()));
                self.notice = Some(("已复制来源 IP".into(), false));
            }
            None => self.notice = Some(("当前登录记录没有有效来源 IP".into(), true)),
        }
        self.row_context_menu = None;
        cx.notify();
    }

    fn filter_context_identity(
        &mut self,
        action: &FilterContextIdentity,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(value) = self.context_identity(&action.row_id) else {
            return;
        };
        let value = value.to_owned();
        self.model.set_query(value.clone());
        self.search_input
            .update(cx, |input, cx| input.set_value(value, window, cx));
        self.reset_table_scroll(cx);
        cx.notify();
    }

    fn refresh_context_table(
        &mut self,
        _: &RefreshContextTable,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.refresh_table(cx);
    }

    fn clear_context_filters(
        &mut self,
        _: &ClearContextFilters,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.reset_filters(window, cx);
    }

    fn context_identity(&self, row_id: &str) -> Option<&str> {
        let table = self.model.active_table()?;
        let row = table.rows.iter().find(|row| row.id == row_id)?;
        let index = primary_context_column(table.tab);
        row.cells.get(index).map(String::as_str)
    }

    fn open_filter_menu(
        &mut self,
        kind: TableFilterMenuKind,
        event: &ClickEvent,
        cx: &mut Context<Self>,
    ) {
        self.row_context_menu = None;
        let position = event.position();
        self.filter_menu = Some(TableFilterMenuState {
            kind,
            position: point(position.x, position.y + px(8.0)),
        });
        cx.notify();
    }

    fn apply_filter_choice(&mut self, choice: &TableFilterChoice, cx: &mut Context<Self>) {
        match choice {
            TableFilterChoice::Risk(risk) => self.model.set_risk_filter(*risk),
            TableFilterChoice::Facet { index, value } => {
                let _ = self.model.set_facet(*index, value.clone());
            }
        }
        self.filter_menu = None;
        self.reset_table_scroll(cx);
        cx.notify();
    }

    fn render_filter_menu(
        &mut self,
        tokens: ThemeTokens,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Option<AnyElement> {
        let state = self.filter_menu.clone()?;
        let (title, choices) = match state.kind.clone() {
            TableFilterMenuKind::Risk => (
                "风险".to_owned(),
                [
                    ("全部".to_owned(), None),
                    ("正常".to_owned(), Some(SystemInfoRisk::Normal)),
                    ("警告".to_owned(), Some(SystemInfoRisk::Warning)),
                    ("高危".to_owned(), Some(SystemInfoRisk::High)),
                ]
                .into_iter()
                .map(|(label, value)| {
                    let selected = self.model.risk_filter() == value;
                    (label, TableFilterChoice::Risk(value), selected)
                })
                .collect::<Vec<_>>(),
            ),
            TableFilterMenuKind::Facet { index, label } => {
                let selected = self.model.facet_value(index).map(str::to_owned);
                let mut choices = vec![(
                    "全部".to_owned(),
                    TableFilterChoice::Facet { index, value: None },
                    selected.is_none(),
                )];
                choices.extend(self.model.facet_options(index).into_iter().map(|value| {
                    let is_selected = selected.as_deref() == Some(value.as_str());
                    (
                        context_label(&value),
                        TableFilterChoice::Facet {
                            index,
                            value: Some(value),
                        },
                        is_selected,
                    )
                }));
                (label.to_owned(), choices)
            }
        };
        let menu = div()
            .id("system-info-filter-menu")
            .w(px(188.0))
            .max_h(px(360.0))
            .overflow_y_scrollbar()
            .p_1()
            .rounded_md()
            .border_1()
            .border_color(tokens.border)
            .bg(tokens.surface)
            .text_color(tokens.text)
            .occlude()
            .on_mouse_down_out(cx.listener(|this, _, _, cx| {
                this.filter_menu = None;
                cx.notify();
            }))
            .child(
                div()
                    .px_3()
                    .py_2()
                    .text_xs()
                    .text_color(tokens.muted)
                    .child(title),
            )
            .children(choices.into_iter().enumerate().map(
                |(option_index, (label, choice, selected))| {
                    div()
                        .id(SharedString::from(format!(
                            "system-info-filter-option-{option_index}"
                        )))
                        .h(px(32.0))
                        .px_3()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap_2()
                        .rounded_sm()
                        .cursor_pointer()
                        .text_sm()
                        .bg(if selected {
                            tokens.surface_alt
                        } else {
                            tokens.surface
                        })
                        .hover(|row| row.bg(tokens.surface_alt))
                        .child(div().flex_1().min_w_0().truncate().child(label))
                        .when(selected, |row| {
                            row.child(div().text_color(tokens.accent).child("✓"))
                        })
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.apply_filter_choice(&choice, cx);
                        }))
                },
            ));
        let window_size = window.bounds().size;

        Some(
            deferred(
                anchored().child(
                    div()
                        .w(window_size.width)
                        .h(window_size.height)
                        .occlude()
                        .child(
                            anchored()
                                .position(state.position)
                                .snap_to_window_with_margin(px(8.0))
                                .anchor(Corner::TopLeft)
                                .child(menu),
                        ),
                ),
            )
            .with_priority(1)
            .into_any_element(),
        )
    }

    fn render_row_context_menu(
        &mut self,
        tokens: ThemeTokens,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Option<AnyElement> {
        let state = self.row_context_menu.clone()?;
        let detail = OpenRowDetail {
            row_id: state.row_id.clone(),
        };
        let copy_identity = CopyContextIdentity {
            row_id: state.row_id.clone(),
        };
        let copy_row = CopyContextRow {
            row_id: state.row_id.clone(),
        };
        let filter_identity = FilterContextIdentity {
            row_id: state.row_id.clone(),
        };
        let process_row_id = state.row_id.clone();
        let terminate_row_id = state.row_id.clone();
        let kill_row_id = state.row_id.clone();
        let service_read_row_id = state.row_id.clone();
        let service_runtime_row_id = state.row_id.clone();
        let user_read_row_id = state.row_id.clone();
        let login_read_row_id = state.row_id.clone();
        let account_lock_row_id = state.row_id.clone();
        let account_unlock_row_id = state.row_id.clone();
        let login_source_row_id = state.row_id.clone();
        let login_block_row_id = state.row_id.clone();
        let artifact_read_row_id = state.row_id.clone();
        let artifact_mutation_row_id = state.row_id.clone();
        let environment_value_row_id = state.row_id.clone();
        let network_read_row_id = state.row_id.clone();
        let network_disconnect_row_id = state.row_id.clone();
        let network_local_row_id = state.row_id.clone();
        let network_remote_row_id = state.row_id.clone();
        let network_process_row_id = state.row_id.clone();
        let network_block_row_id = state.row_id.clone();
        let network_allow_row_id = state.row_id.clone();
        let network_temporary_row_id = state.row_id.clone();
        let network_identity = self
            .model
            .active_table()
            .and_then(|table| table.network_identity(&state.row_id).ok());
        let has_network_remote = network_identity
            .as_ref()
            .is_some_and(|identity| !identity.remote_display.trim().is_empty());
        let has_network_remote_ipv4 = network_identity.as_ref().is_some_and(|identity| {
            identity.remote.as_ref().is_some_and(
                |endpoint| matches!(endpoint.address, IpAddr::V4(value) if !value.is_unspecified()),
            )
        });
        let network_actions = if is_network_tab(state.tab) {
            self.model.active_table().map_or_else(Vec::new, |table| {
                [
                    NetworkInvestigationAction::Whois,
                    NetworkInvestigationAction::ReverseDns,
                    NetworkInvestigationAction::PortProcess,
                    NetworkInvestigationAction::AnomalyDetect,
                    NetworkInvestigationAction::FirewallRules,
                    NetworkInvestigationAction::SecurityLogs,
                ]
                .into_iter()
                .filter(|action| {
                    table
                        .network_investigation_request(&state.row_id, *action)
                        .is_ok()
                })
                .collect()
            })
        } else {
            Vec::new()
        };
        let can_disconnect = is_network_tab(state.tab)
            && self
                .model
                .active_table()
                .is_some_and(|table| table.network_disconnect_request(&state.row_id).is_ok());
        let login_actions = if state.tab == SystemInfoTab::LoginHistory {
            self.model.active_table().map_or_else(Vec::new, |table| {
                LoginInvestigationAction::ALL
                    .into_iter()
                    .filter(|action| {
                        table
                            .login_investigation_request(&state.row_id, *action)
                            .is_ok()
                    })
                    .collect()
            })
        } else {
            Vec::new()
        };
        let has_login_source = state.tab == SystemInfoTab::LoginHistory
            && self.model.active_table().is_some_and(|table| {
                table
                    .login_identity(&state.row_id)
                    .is_ok_and(|identity| identity.source.is_some())
            });
        let has_login_source_ipv4 = state.tab == SystemInfoTab::LoginHistory
            && self.login_source_ipv4(&state.row_id).is_ok();
        let artifact_actions = if is_artifact_tab(state.tab) {
            self.model.active_table().map_or_else(Vec::new, |table| {
                artifact_actions(state.tab)
                    .into_iter()
                    .filter(|action| {
                        table
                            .artifact_investigation_request(&state.row_id, *action)
                            .is_ok()
                    })
                    .collect()
            })
        } else {
            Vec::new()
        };
        let artifact_mutation_actions = self.model.active_table().map_or_else(Vec::new, |table| {
            let candidates = match state.tab {
                SystemInfoTab::Cron => vec![ArtifactMutationAction::DeleteCronFile],
                SystemInfoTab::ShellConfigs => vec![ArtifactMutationAction::CommentShellLine],
                SystemInfoTab::SuidFiles => vec![
                    ArtifactMutationAction::RemoveSuidBits,
                    ArtifactMutationAction::QuarantineSuidFile,
                ],
                SystemInfoTab::KernelModules => vec![
                    ArtifactMutationAction::AddManagedModuleBlacklist,
                    ArtifactMutationAction::RemoveManagedModuleBlacklist,
                ],
                _ => Vec::new(),
            };
            candidates
                .into_iter()
                .filter(|action| {
                    table
                        .artifact_mutation_request(&state.row_id, *action)
                        .is_ok()
                })
                .collect()
        });
        let service_runtime_actions = match state.tab {
            SystemInfoTab::Services => ServiceRuntimeAction::ALL.to_vec(),
            SystemInfoTab::Autostart => ServiceRuntimeAction::AUTOSTART.to_vec(),
            SystemInfoTab::Timers => ServiceRuntimeAction::TIMER.to_vec(),
            _ => Vec::new(),
        };
        let menu = div()
            .id("system-info-row-context-menu")
            .w(px(252.0))
            .max_h(px(720.0))
            .overflow_y_scrollbar()
            .p_1()
            .rounded_md()
            .border_1()
            .border_color(tokens.border)
            .bg(tokens.surface)
            .text_color(tokens.text)
            .occlude()
            .on_mouse_down_out(cx.listener(|this, _, _, cx| {
                this.row_context_menu = None;
                cx.notify();
            }))
            .child(
                div()
                    .px_3()
                    .py_2()
                    .text_xs()
                    .text_color(tokens.muted)
                    .child(format!("{} · {}", state.tab.label(), state.identity)),
            )
            .child(
                crate::buttons::button("system-info-context-detail")
                    .ghost()
                    .icon(IconName::Inspector)
                    .label(context_detail_label(state.tab))
                    .w_full()
                    .justify_start()
                    .on_click(cx.listener(move |this, _, window, cx| {
                        this.row_context_menu = None;
                        this.open_context_row_detail(&detail, window, cx);
                    })),
            )
            .when(state.tab == SystemInfoTab::Processes, |menu| {
                menu.children(
                    [
                        (
                            "system-info-process-command-line",
                            ProcessInvestigationAction::CommandLine,
                        ),
                        (
                            "system-info-process-open-files",
                            ProcessInvestigationAction::OpenFiles,
                        ),
                        (
                            "system-info-process-network",
                            ProcessInvestigationAction::NetworkConnections,
                        ),
                        (
                            "system-info-process-tree",
                            ProcessInvestigationAction::ProcessTree,
                        ),
                        (
                            "system-info-process-risk-path",
                            ProcessInvestigationAction::SuspiciousPath,
                        ),
                    ]
                    .into_iter()
                    .map(|(id, action)| {
                        let row_id = process_row_id.clone();
                        crate::buttons::button(id)
                            .ghost()
                            .icon(IconName::Inspector)
                            .label(action.label())
                            .w_full()
                            .justify_start()
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.run_process_investigation(&row_id, action, cx);
                            }))
                    }),
                )
            })
            .when(state.tab == SystemInfoTab::Services, |menu| {
                menu.children(
                    [
                        ServiceInvestigationAction::Status,
                        ServiceInvestigationAction::Logs,
                        ServiceInvestigationAction::Dependencies,
                        ServiceInvestigationAction::SecurityCheck,
                    ]
                    .into_iter()
                    .enumerate()
                    .map(|(index, action)| {
                        let row_id = service_read_row_id.clone();
                        crate::buttons::button(("system-info-service-investigation", index))
                            .ghost()
                            .icon(IconName::Inspector)
                            .label(action.label())
                            .w_full()
                            .justify_start()
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.run_service_investigation(&row_id, action, cx);
                            }))
                    }),
                )
            })
            .when(state.tab == SystemInfoTab::Users, |menu| {
                menu.children(UserInvestigationAction::ALL.into_iter().enumerate().map(
                    |(index, action)| {
                        let row_id = user_read_row_id.clone();
                        crate::buttons::button(("system-info-user-investigation", index))
                            .ghost()
                            .icon(IconName::Inspector)
                            .label(action.label())
                            .w_full()
                            .justify_start()
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.run_user_investigation(&row_id, action, cx);
                            }))
                    },
                ))
            })
            .when(state.tab == SystemInfoTab::LoginHistory, |menu| {
                menu.children(
                    login_actions
                        .into_iter()
                        .enumerate()
                        .map(|(index, action)| {
                            let row_id = login_read_row_id.clone();
                            crate::buttons::button(("system-info-login-investigation", index))
                                .ghost()
                                .icon(IconName::Inspector)
                                .label(action.label())
                                .w_full()
                                .justify_start()
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.run_login_investigation(&row_id, action, cx);
                                }))
                        }),
                )
            })
            .when(is_artifact_tab(state.tab), |menu| {
                menu.children(
                    artifact_actions
                        .into_iter()
                        .enumerate()
                        .map(|(index, action)| {
                            let row_id = artifact_read_row_id.clone();
                            crate::buttons::button(("system-info-artifact-investigation", index))
                                .ghost()
                                .icon(IconName::Inspector)
                                .label(action.label())
                                .w_full()
                                .justify_start()
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.run_artifact_investigation(&row_id, action, cx);
                                }))
                        }),
                )
            })
            .when(is_network_tab(state.tab), |menu| {
                menu.children(
                    network_actions
                        .into_iter()
                        .enumerate()
                        .map(|(index, action)| {
                            let row_id = network_read_row_id.clone();
                            crate::buttons::button(("system-info-network-investigation", index))
                                .ghost()
                                .icon(IconName::Inspector)
                                .label(action.label())
                                .w_full()
                                .justify_start()
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.run_network_investigation(&row_id, action, cx);
                                }))
                        }),
                )
            })
            .when(is_network_tab(state.tab), |menu| {
                menu.child(context_menu_separator(tokens))
                    .child(
                        crate::buttons::button("system-info-copy-network-local")
                            .ghost()
                            .icon(IconName::Copy)
                            .label("复制本地端点")
                            .w_full()
                            .justify_start()
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.copy_network_field(
                                    &network_local_row_id,
                                    NetworkCopyField::LocalEndpoint,
                                    cx,
                                );
                            })),
                    )
                    .when(has_network_remote, |menu| {
                        menu.child(
                            crate::buttons::button("system-info-copy-network-remote")
                                .ghost()
                                .icon(IconName::Copy)
                                .label("复制远端端点")
                                .w_full()
                                .justify_start()
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.copy_network_field(
                                        &network_remote_row_id,
                                        NetworkCopyField::RemoteEndpoint,
                                        cx,
                                    );
                                })),
                        )
                    })
                    .child(
                        crate::buttons::button("system-info-copy-network-process")
                            .ghost()
                            .icon(IconName::Copy)
                            .label("复制进程信息")
                            .w_full()
                            .justify_start()
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.copy_network_field(
                                    &network_process_row_id,
                                    NetworkCopyField::Process,
                                    cx,
                                );
                            })),
                    )
            })
            .when(has_login_source, |menu| {
                menu.child(context_menu_separator(tokens)).child(
                    crate::buttons::button("system-info-copy-login-source")
                        .ghost()
                        .icon(IconName::Copy)
                        .label("复制来源 IP")
                        .w_full()
                        .justify_start()
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.copy_login_source(&login_source_row_id, cx);
                        })),
                )
            })
            .when(state.tab == SystemInfoTab::EnvVars, |menu| {
                menu.child(context_menu_separator(tokens)).child(
                    crate::buttons::button("system-info-copy-environment-value")
                        .ghost()
                        .icon(IconName::Copy)
                        .label("复制变量值")
                        .w_full()
                        .justify_start()
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.copy_environment_value(&environment_value_row_id, cx);
                        })),
                )
            })
            .child(context_menu_separator(tokens))
            .child(
                crate::buttons::button("system-info-context-copy-identity")
                    .ghost()
                    .icon(IconName::Copy)
                    .label("复制主标识")
                    .w_full()
                    .justify_start()
                    .on_click(cx.listener(move |this, _, window, cx| {
                        this.row_context_menu = None;
                        this.copy_context_identity(&copy_identity, window, cx);
                    })),
            )
            .child(
                crate::buttons::button("system-info-context-copy-row")
                    .ghost()
                    .icon(IconName::Copy)
                    .label("复制完整记录")
                    .w_full()
                    .justify_start()
                    .on_click(cx.listener(move |this, _, window, cx| {
                        this.row_context_menu = None;
                        this.copy_context_row(&copy_row, window, cx);
                    })),
            )
            .child(
                crate::buttons::button("system-info-context-filter")
                    .ghost()
                    .icon(IconName::Search)
                    .label("按主标识筛选")
                    .w_full()
                    .justify_start()
                    .on_click(cx.listener(move |this, _, window, cx| {
                        this.row_context_menu = None;
                        this.filter_context_identity(&filter_identity, window, cx);
                    })),
            )
            .child(
                crate::buttons::button("system-info-context-clear-filter")
                    .ghost()
                    .icon(IconName::CircleX)
                    .label("清除筛选")
                    .w_full()
                    .justify_start()
                    .on_click(cx.listener(|this, _, window, cx| {
                        this.row_context_menu = None;
                        this.clear_context_filters(&ClearContextFilters, window, cx);
                    })),
            )
            .child(context_menu_separator(tokens))
            .child(
                crate::buttons::button("system-info-context-refresh")
                    .ghost()
                    .icon(IconName::Redo2)
                    .label("刷新当前分类")
                    .w_full()
                    .justify_start()
                    .on_click(cx.listener(|this, _, window, cx| {
                        this.row_context_menu = None;
                        this.refresh_context_table(&RefreshContextTable, window, cx);
                    })),
            )
            .when(state.tab == SystemInfoTab::Processes, |menu| {
                menu.child(context_menu_separator(tokens))
                    .child(
                        div()
                            .id("system-info-process-danger-actions")
                            .flex()
                            .flex_col()
                            .gap_1()
                            .py_1()
                            .child(
                                crate::buttons::button("system-info-process-terminate")
                                    .danger()
                                    .label(ProcessSignal::Terminate.label())
                                    .w_full()
                                    .justify_start()
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.prepare_process_signal(
                                            &terminate_row_id,
                                            ProcessSignal::Terminate,
                                            cx,
                                        );
                                    })),
                            )
                            .child(
                                crate::buttons::button("system-info-process-kill")
                                    .danger()
                                    .label(ProcessSignal::Kill.label())
                                    .w_full()
                                    .justify_start()
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.prepare_process_signal(
                                            &kill_row_id,
                                            ProcessSignal::Kill,
                                            cx,
                                        );
                                    })),
                            ),
                    )
            })
            .when(is_service_runtime_tab(state.tab), |menu| {
                menu.child(context_menu_separator(tokens)).children(
                    service_runtime_actions
                        .into_iter()
                        .enumerate()
                        .map(|(index, action)| {
                            let row_id = service_runtime_row_id.clone();
                            crate::buttons::button(("system-info-service-runtime", index))
                                .danger()
                                .label(action.label())
                                .w_full()
                                .justify_start()
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.prepare_service_runtime(&row_id, action, cx);
                                }))
                        }),
                )
            })
            .when(!artifact_mutation_actions.is_empty(), |menu| {
                menu.child(context_menu_separator(tokens)).children(
                    artifact_mutation_actions
                        .into_iter()
                        .enumerate()
                        .map(|(index, action)| {
                            let row_id = artifact_mutation_row_id.clone();
                            crate::buttons::button(("system-info-artifact-mutation", index))
                                .danger()
                                .label(action.label())
                                .w_full()
                                .justify_start()
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.prepare_artifact_mutation(&row_id, action, cx);
                                }))
                        }),
                )
            })
            .when(state.tab == SystemInfoTab::Users, |menu| {
                let lock_row_id = account_lock_row_id.clone();
                let unlock_row_id = account_unlock_row_id.clone();
                menu.child(context_menu_separator(tokens))
                    .child(
                        crate::buttons::button("system-info-user-lock")
                            .danger()
                            .label(UserAccountAction::Lock.label())
                            .w_full()
                            .justify_start()
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.prepare_user_account(
                                    &lock_row_id,
                                    UserAccountAction::Lock,
                                    cx,
                                );
                            })),
                    )
                    .child(
                        crate::buttons::button("system-info-user-unlock")
                            .danger()
                            .label(UserAccountAction::Unlock.label())
                            .w_full()
                            .justify_start()
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.prepare_user_account(
                                    &unlock_row_id,
                                    UserAccountAction::Unlock,
                                    cx,
                                );
                            })),
                    )
            })
            .when(state.tab == SystemInfoTab::LoginHistory, |menu| {
                let row_id = account_lock_row_id.clone();
                menu.child(context_menu_separator(tokens))
                    .child(
                        crate::buttons::button("system-info-login-lock-user")
                            .danger()
                            .label(UserAccountAction::Lock.label())
                            .w_full()
                            .justify_start()
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.prepare_user_account(&row_id, UserAccountAction::Lock, cx);
                            })),
                    )
                    .when(has_login_source_ipv4, |menu| {
                        menu.child(
                            crate::buttons::button("system-info-login-block-source-ip")
                                .danger()
                                .label("封禁来源 IP")
                                .w_full()
                                .justify_start()
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.prepare_login_firewall(&login_block_row_id, cx);
                                })),
                        )
                    })
            })
            .when(has_network_remote_ipv4, |menu| {
                menu.child(context_menu_separator(tokens))
                    .child(
                        crate::buttons::button("system-info-context-network-block")
                            .danger()
                            .label("封禁远端 IP")
                            .w_full()
                            .justify_start()
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.prepare_network_firewall(
                                    &network_block_row_id,
                                    NetworkFirewallIntent::Block,
                                    cx,
                                );
                            })),
                    )
                    .child(
                        crate::buttons::button("system-info-context-network-allow")
                            .ghost()
                            .label("恢复 LovelyRes 管理的 IP 封禁")
                            .w_full()
                            .justify_start()
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.prepare_network_firewall(
                                    &network_allow_row_id,
                                    NetworkFirewallIntent::Allow,
                                    cx,
                                );
                            })),
                    )
                    .child(
                        crate::buttons::button("system-info-context-network-temporary-block")
                            .danger()
                            .label("临时封禁 5 分钟")
                            .w_full()
                            .justify_start()
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.prepare_network_firewall(
                                    &network_temporary_row_id,
                                    NetworkFirewallIntent::TemporaryBlock,
                                    cx,
                                );
                            })),
                    )
            })
            .when(can_disconnect, |menu| {
                menu.child(context_menu_separator(tokens)).child(
                    crate::buttons::button("system-info-network-disconnect")
                        .danger()
                        .label("断开精确 TCP 连接")
                        .w_full()
                        .justify_start()
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.prepare_network_disconnect(&network_disconnect_row_id, cx);
                        })),
                )
            })
            .child(context_menu_separator(tokens))
            .child(
                div()
                    .px_3()
                    .py_2()
                    .text_xs()
                    .text_color(tokens.muted)
                    .child(match state.tab {
                        SystemInfoTab::Processes => "终止操作需核对 PID 启动身份并二次确认",
                        SystemInfoTab::Services => "服务操作需核对 systemd 状态快照并二次确认",
                        SystemInfoTab::Users => {
                            "账户锁定状态操作需核对 UID、主目录、Shell 与密码状态并二次确认"
                        }
                        SystemInfoTab::LoginHistory => {
                            "账户处置核对身份快照；来源封禁使用 60 秒死人开关并需再次确认保留"
                        }
                        SystemInfoTab::Network | SystemInfoTab::Established => {
                            "断开连接需核对本地/远端端点及进程快照并二次确认"
                        }
                        SystemInfoTab::OpenPorts => "监听端口仅开放只读调查，不伪造断连能力",
                        SystemInfoTab::Packages => {
                            "卸载仅提供本地模拟预览；版本锁定和真实卸载尚未开放"
                        }
                        SystemInfoTab::KernelModules => {
                            "模块卸载仍保持禁用；LovelyRes 受管黑名单使用固定路径、独占创建、精确内容校验和可恢复操作计划"
                        }
                        SystemInfoTab::EnvVars => {
                            "环境调查不启动用户 Shell，也不会修改远端进程环境"
                        }
                        _ => "修改操作统一从处置流程进入",
                    }),
            );
        let window_size = window.bounds().size;

        Some(
            deferred(
                anchored().child(
                    div()
                        .w(window_size.width)
                        .h(window_size.height)
                        .occlude()
                        .child(
                            anchored()
                                .position(state.position)
                                .snap_to_window_with_margin(px(8.0))
                                .anchor(Corner::TopLeft)
                                .child(menu),
                        ),
                ),
            )
            .with_priority(1)
            .into_any_element(),
        )
    }

    fn export_filtered(&mut self, cx: &mut Context<Self>) {
        let Some(table) = self.model.active_table() else {
            return;
        };
        let rows = self.model.filtered_rows();
        let intent = SystemInfoClipboardIntent::from_rows(table, &rows);
        cx.write_to_clipboard(ClipboardItem::new_string(intent.text));
        self.notice = Some((
            format!("已复制 {} 行 TSV 数据", intent.row_count).into(),
            false,
        ));
        cx.notify();
    }
}

impl Render for SystemInfoPage {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let (tokens, binding) = {
            let state = self.shared.read(cx);
            (state.theme.tokens(), state.target_label.clone())
        };
        let notice = self.notice.clone();
        let context_menu = self.render_row_context_menu(tokens, window, cx);
        let filter_menu = self.render_filter_menu(tokens, window, cx);
        div()
            .id("system-info-page")
            .on_action(cx.listener(Self::open_context_row_detail))
            .on_action(cx.listener(Self::copy_context_row))
            .on_action(cx.listener(Self::copy_context_identity))
            .on_action(cx.listener(Self::filter_context_identity))
            .on_action(cx.listener(Self::refresh_context_table))
            .on_action(cx.listener(Self::clear_context_filters))
            .size_full()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(div().size(px(8.0)).rounded_full().bg(tokens.success))
                            .child(div().text_sm().text_color(tokens.muted).child(binding)),
                    )
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .child(
                                crate::buttons::button("system-info-refresh")
                                    .label(if self.summary_loading || self.table_loading {
                                        "刷新中…"
                                    } else {
                                        "刷新"
                                    })
                                    .small()
                                    .primary()
                                    .on_click(cx.listener(|this, _, _, cx| this.refresh(cx))),
                            )
                            .child(
                                crate::buttons::button("system-info-export")
                                    .label(if self.show_overview {
                                        "复制系统概览"
                                    } else {
                                        "复制当前表"
                                    })
                                    .small()
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        if this.show_overview {
                                            this.copy_overview(cx);
                                        } else {
                                            this.export_filtered(cx);
                                        }
                                    })),
                            ),
                    ),
            )
            .when_some(notice, |page, (message, is_error)| {
                page.child(
                    div()
                        .rounded_md()
                        .border_1()
                        .border_color(if is_error {
                            tokens.danger
                        } else {
                            tokens.success
                        })
                        .p_2()
                        .text_sm()
                        .text_color(if is_error {
                            tokens.danger
                        } else {
                            tokens.success
                        })
                        .child(message),
                )
            })
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .flex()
                    .gap_3()
                    .child(self.render_navigation(tokens, cx))
                    .child(if self.show_overview {
                        self.render_summary(tokens)
                    } else {
                        self.render_active_table(tokens, cx)
                    }),
            )
            .children(context_menu)
            .children(filter_menu)
    }
}

impl SystemInfoPage {
    fn render_summary(&self, tokens: ThemeTokens) -> AnyElement {
        if let Some(error) = self.summary_error.clone() {
            return div()
                .flex_1()
                .min_w_0()
                .min_h_0()
                .rounded_lg()
                .border_1()
                .border_color(tokens.danger)
                .p_3()
                .text_color(tokens.danger)
                .child(error)
                .into_any_element();
        }
        let Some(summary) = self.model.summary() else {
            return div()
                .flex_1()
                .min_w_0()
                .min_h_0()
                .flex()
                .items_center()
                .justify_center()
                .rounded_lg()
                .border_1()
                .border_color(tokens.border)
                .p_3()
                .text_color(tokens.muted)
                .child(if self.summary_loading {
                    "正在读取系统概要…"
                } else {
                    "尚未加载系统概要"
                })
                .into_any_element();
        };
        let identity = vec![
            ("主机名", display_summary_value(&summary.hostname)),
            ("操作系统", display_summary_value(&summary.operating_system)),
            ("内核", display_summary_value(&summary.kernel)),
            ("架构", display_summary_value(&summary.architecture)),
            ("虚拟化", display_summary_value(&summary.virtualization)),
            ("Init 系统", display_summary_value(&summary.init_system)),
            ("启动时间", display_summary_value(&summary.boot_time)),
            ("运行时间", format_duration(summary.uptime_seconds)),
            ("时区", display_summary_value(&summary.timezone)),
            ("Locale", display_summary_value(&summary.locale)),
            ("包管理器", display_summary_value(&summary.package_manager)),
        ];
        let resources = vec![
            ("CPU", display_summary_value(&summary.cpu_model)),
            ("逻辑核心", summary.cpu_cores.to_string()),
            (
                "负载 (1/5/15m)",
                format!(
                    "{} / {} / {}",
                    summary.load_average[0], summary.load_average[1], summary.load_average[2]
                ),
            ),
            (
                "内存",
                format!(
                    "可用 {} / 总计 {}",
                    format_bytes(summary.memory_available_bytes),
                    format_bytes(summary.memory_total_bytes)
                ),
            ),
            (
                "交换分区",
                format!(
                    "可用 {} / 总计 {}",
                    format_bytes(summary.swap_free_bytes),
                    format_bytes(summary.swap_total_bytes)
                ),
            ),
            (
                "运行态势",
                format!(
                    "进程 {} · 登录用户 {} · 网络连接 {}",
                    summary.process_count, summary.logged_in_users, summary.network_connections
                ),
            ),
        ];
        let storage_network = vec![
            ("根设备", display_summary_value(&summary.root_device)),
            (
                "根文件系统",
                display_summary_value(&summary.root_filesystem),
            ),
            (
                "根分区空间",
                format!(
                    "可用 {} / 总计 {}",
                    format_bytes(summary.root_available_bytes),
                    format_bytes(summary.root_total_bytes)
                ),
            ),
            ("主 IP", display_summary_value(&summary.primary_ip)),
            ("默认网关", display_summary_value(&summary.default_gateway)),
            ("DNS", display_summary_value(&summary.dns_servers)),
            (
                "累计流量",
                format!(
                    "RX {} · TX {}",
                    format_bytes(summary.received_bytes),
                    format_bytes(summary.transmitted_bytes)
                ),
            ),
        ];
        let security = vec![
            ("SELinux", display_summary_value(&summary.selinux)),
            ("AppArmor", display_summary_value(&summary.apparmor)),
            ("采集边界", "只读 SSH 命令 · 目标前后双校验".to_owned()),
            ("资源来源", "/proc · /etc · systemd · iproute2".to_owned()),
        ];
        div()
            .flex_1()
            .min_w_0()
            .min_h_0()
            .overflow_y_scrollbar()
            .rounded_lg()
            .border_1()
            .border_color(tokens.border)
            .bg(tokens.surface)
            .p_4()
            .flex()
            .flex_col()
            .child(
                div()
                    .mb_1()
                    .text_xl()
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .child("系统概览"),
            )
            .child(
                div()
                    .mb_4()
                    .text_sm()
                    .text_color(tokens.muted)
                    .child("集中查看主机身份、资源、存储网络与安全运行环境。"),
            )
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_3()
                    .child(overview_section("系统身份", identity, tokens))
                    .child(overview_section("硬件与资源", resources, tokens))
                    .child(overview_section("存储与网络", storage_network, tokens))
                    .child(overview_section("安全与采集", security, tokens)),
            )
            .into_any_element()
    }

    fn render_navigation(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        div()
            .w(px(204.0))
            .flex_none()
            .min_h_0()
            .overflow_y_scrollbar()
            .rounded_lg()
            .border_1()
            .border_color(tokens.border)
            .bg(tokens.surface)
            .p_2()
            .child(
                div()
                    .id("system-info-overview")
                    .w_full()
                    .h(px(36.0))
                    .mb_2()
                    .px_3()
                    .flex()
                    .items_center()
                    .rounded_md()
                    .cursor_pointer()
                    .text_sm()
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .text_color(if self.show_overview {
                        tokens.accent
                    } else {
                        tokens.text
                    })
                    .bg(if self.show_overview {
                        tokens.surface_alt
                    } else {
                        tokens.surface
                    })
                    .when(self.show_overview, |item| {
                        item.border_l_2().border_color(tokens.accent)
                    })
                    .hover(|item| item.bg(tokens.surface_alt))
                    .child("系统概览")
                    .on_click(cx.listener(|this, _, _, cx| this.open_overview(cx))),
            )
            .children(SystemInfoGroup::ALL.into_iter().map(|group| {
                div()
                    .mb_2()
                    .child(
                        div()
                            .px_2()
                            .mb_1()
                            .text_xs()
                            .text_color(tokens.muted)
                            .child(group.label()),
                    )
                    .children(
                        SystemInfoTab::ALL
                            .into_iter()
                            .filter(move |tab| tab.group() == group)
                            .map(|tab| {
                                let active = !self.show_overview && self.model.active_tab() == tab;
                                div()
                                    .id(SharedString::from(format!("system-info-tab-{tab:?}")))
                                    .w_full()
                                    .h(px(32.0))
                                    .mb_1()
                                    .px_3()
                                    .flex()
                                    .items_center()
                                    .rounded_md()
                                    .cursor_pointer()
                                    .text_sm()
                                    .text_color(if active { tokens.accent } else { tokens.text })
                                    .bg(if active {
                                        tokens.surface_alt
                                    } else {
                                        tokens.surface
                                    })
                                    .when(active, |item| {
                                        item.border_l_2().border_color(tokens.accent)
                                    })
                                    .hover(|item| item.bg(tokens.surface_alt))
                                    .child(tab.label())
                                    .on_click(cx.listener(move |this, _, window, cx| {
                                        this.switch_tab(tab, window, cx)
                                    }))
                            }),
                    )
            }))
            .into_any_element()
    }

    fn render_active_table(&mut self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let tab = self.model.active_tab();
        let filtered_total = self.model.filtered_row_count();
        let (table_total, table_truncated, columns) = self.model.active_table().map_or_else(
            || (0, false, None),
            |table| {
                (
                    table.rows.len(),
                    table.truncated,
                    Some(table.columns.clone()),
                )
            },
        );
        let selected = self.model.selected_row().cloned();
        let detail_columns = self
            .model
            .active_table()
            .map(|table| (table.tab, table.columns.clone()));
        let filter_spec = filter_spec(tab);
        div()
            .flex_1()
            .min_w_0()
            .min_h_0()
            .flex()
            .gap_3()
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .min_h_0()
                    .rounded_lg()
                    .border_1()
                    .border_color(tokens.border)
                    .bg(tokens.surface)
                    .p_3()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_3()
                            .child(div().text_sm().text_color(tokens.muted).child(format!(
                                "{} / {} 行{}",
                                filtered_total,
                                table_total,
                                if table_truncated {
                                    " · 已达采集上限"
                                } else {
                                    ""
                                }
                            )))
                            .child(
                                div()
                                    .ml_auto()
                                    .w(px(320.0))
                                    .child(Input::new(&self.search_input)),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_4()
                            .child(
                                crate::buttons::button("system-info-risk-filter")
                                    .label(self.model.risk_filter().map_or_else(
                                        || "风险：全部".to_owned(),
                                        |risk| format!("风险：{}", risk.label()),
                                    ))
                                    .dropdown_caret(true)
                                    .min_w(px(128.0))
                                    .small()
                                    .on_click(cx.listener(|this, event, _, cx| {
                                        this.open_filter_menu(TableFilterMenuKind::Risk, event, cx);
                                    })),
                            )
                            .children(filter_spec.iter().enumerate().map(|(index, descriptor)| {
                                let label = descriptor.label;
                                crate::buttons::button(SharedString::from(format!(
                                    "system-info-facet-{index}"
                                )))
                                .label(format!(
                                    "{}：{}",
                                    descriptor.label,
                                    self.model.facet_value(index).unwrap_or("全部")
                                ))
                                .dropdown_caret(true)
                                .min_w(px(128.0))
                                .small()
                                .on_click(cx.listener(
                                    move |this, event, _, cx| {
                                        this.open_filter_menu(
                                            TableFilterMenuKind::Facet { index, label },
                                            event,
                                            cx,
                                        );
                                    },
                                ))
                            }))
                            .child(
                                crate::buttons::button("system-info-reset-filters")
                                    .label("重置")
                                    .small()
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.reset_filters(window, cx)
                                    })),
                            )
                            .child(
                                div()
                                    .ml_auto()
                                    .text_xs()
                                    .text_color(tokens.muted)
                                    .child(table_result_hint(filtered_total)),
                            ),
                    )
                    .when_some(self.table_error.clone(), |panel, error| {
                        panel.child(
                            div()
                                .rounded_md()
                                .border_1()
                                .border_color(tokens.danger)
                                .p_2()
                                .text_color(tokens.danger)
                                .child(error),
                        )
                    })
                    .child(match columns {
                        Some(columns) => {
                            self.render_virtual_table(tab, columns, filtered_total, tokens, cx)
                        }
                        None => div()
                            .flex_1()
                            .flex()
                            .items_center()
                            .justify_center()
                            .text_color(tokens.muted)
                            .child(if self.table_loading {
                                "正在加载当前数据面…"
                            } else {
                                "尚未加载当前数据面"
                            })
                            .into_any_element(),
                    }),
            )
            .when_some(
                selected.zip(detail_columns),
                |view, (row, (tab, columns))| {
                    view.child(self.render_detail(tab, columns, row, tokens, cx))
                },
            )
            .into_any_element()
    }

    fn render_virtual_table(
        &mut self,
        tab: SystemInfoTab,
        columns: Vec<String>,
        row_count: usize,
        tokens: ThemeTokens,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let widths = Arc::new(
            columns
                .iter()
                .enumerate()
                .map(|(index, column)| table_column_width(tab, index, column))
                .collect::<Vec<_>>(),
        );
        let table_width = widths
            .iter()
            .copied()
            .fold(px(0.0), |sum, width| sum + width);
        let column_count = columns.len();
        let row_widths = widths.clone();
        let scroll_handle = self.table_scroll.clone();

        div()
            .flex_1()
            .min_h_0()
            .overflow_hidden()
            .child(
                div().size_full().overflow_x_scrollbar().child(
                    div()
                        .w_full()
                        .min_w(table_width)
                        .h_full()
                        .min_h_0()
                        .flex()
                        .flex_col()
                        .child(
                            div()
                                .h(px(36.0))
                                .flex_none()
                                .flex()
                                .border_b_1()
                                .border_color(tokens.border)
                                .bg(tokens.surface_alt)
                                .children(
                                    columns
                                        .into_iter()
                                        .zip(widths.iter().copied())
                                        .enumerate()
                                        .map(move |(index, (column, width))| {
                                            div()
                                                .h_full()
                                                .flex()
                                                .items_center()
                                                .px_3()
                                                .text_xs()
                                                .text_color(tokens.muted)
                                                .truncate()
                                                .when(
                                                    is_flexible_table_column(index, column_count),
                                                    |cell| cell.flex_1().min_w(width),
                                                )
                                                .when(
                                                    !is_flexible_table_column(index, column_count),
                                                    |cell| cell.w(width).flex_none(),
                                                )
                                                .child(column)
                                        }),
                                ),
                        )
                        .child(
                            div()
                                .relative()
                                .flex_1()
                                .min_h_0()
                                .when(row_count == 0, |body| {
                                    body.child(
                                        div()
                                            .size_full()
                                            .flex()
                                            .items_center()
                                            .justify_center()
                                            .text_color(tokens.muted)
                                            .child("当前筛选无数据"),
                                    )
                                })
                                .when(row_count > 0, |body| {
                                    body.child(
                                        uniform_list(
                                            "system-info-table-rows",
                                            row_count,
                                            cx.processor(
                                                move |this, range: Range<usize>, _, cx| {
                                                    this.render_virtual_rows(
                                                        range,
                                                        &row_widths,
                                                        tab,
                                                        tokens,
                                                        cx,
                                                    )
                                                },
                                            ),
                                        )
                                        .size_full()
                                        .track_scroll(scroll_handle.clone()),
                                    )
                                })
                                .vertical_scrollbar(&self.table_scroll),
                        ),
                ),
            )
            .into_any_element()
    }

    fn render_virtual_rows(
        &mut self,
        range: Range<usize>,
        widths: &[gpui::Pixels],
        tab: SystemInfoTab,
        tokens: ThemeTokens,
        cx: &mut Context<Self>,
    ) -> Vec<AnyElement> {
        range
            .filter_map(|visible_index| {
                let row = {
                    let table = self.model.active_table()?;
                    let table_index = *self.model.filtered_row_indices.get(visible_index)?;
                    table.rows.get(table_index)?.clone()
                };
                let selected = self.model.selected_row_id.as_deref() == Some(row.id.as_str());
                let row_id = row.id.clone();
                let right_click_row_id = row.id.clone();
                let identity = row
                    .cells
                    .get(primary_context_column(tab))
                    .map_or_else(|| "当前记录".to_owned(), |value| context_label(value));
                let risk = row.risk;
                let column_count = widths.len();
                let row_element = div()
                    .id(("system-info-row", visible_index))
                    .w_full()
                    .h(px(36.0))
                    .flex_none()
                    .flex()
                    .cursor_pointer()
                    .border_b_1()
                    .border_color(tokens.border)
                    .bg(if selected || risk != SystemInfoRisk::Normal {
                        tokens.surface_alt
                    } else {
                        tokens.surface
                    })
                    .hover(|row| row.bg(tokens.surface_alt))
                    .when(selected, |row| row.border_l_2().border_color(tokens.accent))
                    .children(
                        row.cells
                            .into_iter()
                            .zip(widths.iter().copied())
                            .enumerate()
                            .map(move |(index, (cell, width))| {
                                let column = tab.columns().get(index).copied().unwrap_or_default();
                                let is_risk = column.contains("风险");
                                let is_monospace = is_monospace_column(column);
                                div()
                                    .h_full()
                                    .flex()
                                    .items_center()
                                    .px_3()
                                    .text_sm()
                                    .text_color(if is_risk {
                                        risk_color(risk, tokens)
                                    } else {
                                        tokens.text
                                    })
                                    .when(is_monospace, |cell| {
                                        cell.font_family("Cascadia Mono").text_xs()
                                    })
                                    .when(is_flexible_table_column(index, column_count), |cell| {
                                        cell.flex_1().min_w(width)
                                    })
                                    .when(!is_flexible_table_column(index, column_count), |cell| {
                                        cell.w(width).flex_none()
                                    })
                                    .truncate()
                                    .child(cell)
                            }),
                    )
                    .on_click(cx.listener(move |this, _, _, cx| this.select_row(&row_id, cx)))
                    .on_mouse_down(
                        MouseButton::Right,
                        cx.listener(move |this, event: &MouseDownEvent, _, cx| {
                            this.select_row(&right_click_row_id, cx);
                            this.filter_menu = None;
                            this.row_context_menu = Some(RowContextMenuState {
                                tab,
                                row_id: right_click_row_id.clone(),
                                identity: identity.clone(),
                                position: event.position,
                            });
                            cx.notify();
                        }),
                    );
                Some(row_element.into_any_element())
            })
            .collect()
    }

    fn render_process_investigation(
        &self,
        row: &SystemInfoRow,
        tokens: ThemeTokens,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let row_id = row.id.clone();
        let selected_group = self.process_group;
        let busy = self.process_signal_busy;
        let has_pending = self.pending_process_signal.is_some();
        let result = self.process_investigation_result.clone();
        let error = self.process_investigation_error.clone();
        let pending = self.pending_process_signal.clone();
        div()
            .mt_4()
            .border_t_1()
            .border_color(tokens.border)
            .pt_3()
            .child(
                div()
                    .text_sm()
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .child("进程调查"),
            )
            .child(
                div()
                    .mt_1()
                    .text_xs()
                    .text_color(tokens.muted)
                    .child("所有远端命令均由闭集动作生成，并绑定当前目标、行身份与请求代次。"),
            )
            .child(
                div().mt_3().flex().flex_wrap().gap_1().children(
                    ProcessInvestigationGroup::ALL
                        .into_iter()
                        .enumerate()
                        .map(|(index, group)| {
                            crate::buttons::button(("system-info-process-group", index))
                                .label(group.label())
                                .small()
                                .when(group == selected_group, |button| button.primary())
                                .when(group != selected_group, |button| button.ghost())
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.select_process_group(group, cx);
                                }))
                        }),
                ),
            )
            .child(
                div().mt_2().flex().flex_wrap().gap_1().children(
                    ProcessInvestigationAction::ALL
                        .into_iter()
                        .filter(|action| action.group() == selected_group)
                        .enumerate()
                        .map(|(index, action)| {
                            let row_id = row_id.clone();
                            crate::buttons::button(("system-info-process-action", index))
                                .label(action.label())
                                .small()
                                .ghost()
                                .disabled(self.process_investigation_loading)
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.run_process_investigation(&row_id, action, cx);
                                }))
                        }),
                ),
            )
            .when(self.process_investigation_loading, |panel| {
                panel.child(
                    div()
                        .mt_3()
                        .text_sm()
                        .text_color(tokens.muted)
                        .child(format!(
                            "正在执行 {}…",
                            self.process_investigation_action
                                .map_or("进程调查", ProcessInvestigationAction::label)
                        )),
                )
            })
            .when_some(error, |panel, error| {
                panel.child(
                    div()
                        .mt_3()
                        .rounded_md()
                        .border_1()
                        .border_color(tokens.danger)
                        .p_2()
                        .text_sm()
                        .text_color(tokens.danger)
                        .child(error),
                )
            })
            .when_some(result, |panel, result| {
                panel.child(
                    div()
                        .mt_3()
                        .rounded_md()
                        .border_1()
                        .border_color(tokens.border)
                        .bg(tokens.surface_alt)
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .px_3()
                                .py_2()
                                .border_b_1()
                                .border_color(tokens.border)
                                .child(div().flex_1().text_sm().child(format!(
                                    "{}{}",
                                    result.action.label(),
                                    if result.truncated {
                                        " · 已截断"
                                    } else {
                                        ""
                                    }
                                )))
                                .child(
                                    crate::buttons::button(
                                        "system-info-copy-process-investigation",
                                    )
                                    .label("复制")
                                    .small()
                                    .ghost()
                                    .on_click(cx.listener(
                                        |this, _, _, cx| this.copy_process_investigation(cx),
                                    )),
                                ),
                        )
                        .child(
                            div()
                                .max_h(px(300.0))
                                .overflow_y_scrollbar()
                                .p_3()
                                .font_family("Cascadia Mono")
                                .text_xs()
                                .child(if result.output.is_empty() {
                                    "(无输出)".to_owned()
                                } else {
                                    result.output
                                }),
                        ),
                )
            })
            .child(
                div()
                    .mt_4()
                    .border_t_1()
                    .border_color(tokens.border)
                    .pt_3()
                    .child(
                        div()
                            .text_sm()
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child("处置进程"),
                    )
                    .child(
                        div()
                            .mt_1()
                            .text_xs()
                            .text_color(tokens.muted)
                            .child("确认前会绑定 PID、命令名与启动时钟；PID 被复用时拒绝执行。"),
                    )
                    .child(
                        div()
                            .mt_2()
                            .flex()
                            .gap_2()
                            .child(
                                crate::buttons::button("system-info-detail-terminate")
                                    .label("SIGTERM")
                                    .danger()
                                    .small()
                                    .disabled(busy || has_pending)
                                    .on_click({
                                        let row_id = row_id.clone();
                                        cx.listener(move |this, _, _, cx| {
                                            this.prepare_process_signal(
                                                &row_id,
                                                ProcessSignal::Terminate,
                                                cx,
                                            )
                                        })
                                    }),
                            )
                            .child(
                                crate::buttons::button("system-info-detail-kill")
                                    .label("SIGKILL")
                                    .danger()
                                    .small()
                                    .disabled(busy || has_pending)
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.prepare_process_signal(
                                            &row_id,
                                            ProcessSignal::Kill,
                                            cx,
                                        )
                                    })),
                            ),
                    )
                    .when(busy, |section| {
                        section.child(
                            div()
                                .mt_2()
                                .text_xs()
                                .text_color(tokens.muted)
                                .child("正在生成计划或执行并验证…"),
                        )
                    })
                    .when_some(pending, |section, pending| {
                        section.child(
                            div()
                                .mt_3()
                                .rounded_md()
                                .border_1()
                                .border_color(tokens.danger)
                                .bg(tokens.surface_alt)
                                .p_3()
                                .child(
                                    div()
                                        .text_sm()
                                        .text_color(tokens.danger)
                                        .font_weight(gpui::FontWeight::SEMIBOLD)
                                        .child("危险操作确认"),
                                )
                                .child(
                                    div()
                                        .mt_2()
                                        .text_sm()
                                        .child(pending.plan.definition().summary.clone()),
                                )
                                .child(
                                    div()
                                        .mt_3()
                                        .flex()
                                        .gap_2()
                                        .child(
                                            crate::buttons::button(
                                                "system-info-cancel-process-signal",
                                            )
                                            .label("取消")
                                            .on_click(
                                                cx.listener(|this, _, _, cx| {
                                                    this.cancel_process_signal(cx)
                                                }),
                                            ),
                                        )
                                        .child(
                                            crate::buttons::button(
                                                "system-info-approve-process-signal",
                                            )
                                            .label("确认执行")
                                            .danger()
                                            .on_click(
                                                cx.listener(|this, _, _, cx| {
                                                    this.approve_process_signal(cx)
                                                }),
                                            ),
                                        ),
                                ),
                        )
                    }),
            )
            .into_any_element()
    }

    fn render_service_runtime_controls(
        &self,
        row_id: String,
        actions: Vec<ServiceRuntimeAction>,
        title: &'static str,
        description: &'static str,
        tokens: ThemeTokens,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let busy = self.service_runtime_busy;
        let has_pending = self.pending_service_runtime.is_some();
        let pending = self.pending_service_runtime.clone();
        div()
            .mt_4()
            .border_t_1()
            .border_color(tokens.border)
            .pt_3()
            .child(
                div()
                    .text_sm()
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .child(title),
            )
            .child(
                div()
                    .mt_1()
                    .text_xs()
                    .text_color(tokens.muted)
                    .child(description),
            )
            .child(div().mt_2().flex().flex_wrap().gap_2().children(
                actions.into_iter().enumerate().map(|(index, action)| {
                    let row_id = row_id.clone();
                    crate::buttons::button(("system-info-detail-service-runtime", index))
                        .label(action.label())
                        .danger()
                        .small()
                        .disabled(busy || has_pending)
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.prepare_service_runtime(&row_id, action, cx)
                        }))
                }),
            ))
            .when(busy, |section| {
                section.child(
                    div()
                        .mt_2()
                        .text_xs()
                        .text_color(tokens.muted)
                        .child("正在生成计划或执行并验证…"),
                )
            })
            .when_some(pending, |section, pending| {
                section.child(
                    div()
                        .mt_3()
                        .rounded_md()
                        .border_1()
                        .border_color(tokens.danger)
                        .bg(tokens.surface_alt)
                        .p_3()
                        .child(
                            div()
                                .text_sm()
                                .text_color(tokens.danger)
                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                .child("危险操作确认"),
                        )
                        .child(
                            div()
                                .mt_2()
                                .text_sm()
                                .child(pending.plan.definition().summary.clone()),
                        )
                        .child(
                            div()
                                .mt_3()
                                .flex()
                                .gap_2()
                                .child(
                                    crate::buttons::button("system-info-cancel-service-runtime")
                                        .label("取消")
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.cancel_service_runtime(cx)
                                        })),
                                )
                                .child(
                                    crate::buttons::button("system-info-approve-service-runtime")
                                        .label("确认执行")
                                        .danger()
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.approve_service_runtime(cx)
                                        })),
                                ),
                        ),
                )
            })
            .into_any_element()
    }

    fn render_service_investigation(
        &self,
        row: &SystemInfoRow,
        tokens: ThemeTokens,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let row_id = row.id.clone();
        let selected_group = self.service_group;
        let result = self.service_investigation_result.clone();
        let error = self.service_investigation_error.clone();
        div()
            .mt_4()
            .border_t_1()
            .border_color(tokens.border)
            .pt_3()
            .child(
                div()
                    .text_sm()
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .child("服务调查"),
            )
            .child(
                div()
                    .mt_1()
                    .text_xs()
                    .text_color(tokens.muted)
                    .child("19 项只读调查均由闭集命令生成，并绑定当前目标、服务行与请求代次。"),
            )
            .child(
                div().mt_3().flex().flex_wrap().gap_1().children(
                    ServiceInvestigationGroup::ALL
                        .into_iter()
                        .enumerate()
                        .map(|(index, group)| {
                            crate::buttons::button(("system-info-service-group", index))
                                .label(group.label())
                                .small()
                                .when(group == selected_group, |button| button.primary())
                                .when(group != selected_group, |button| button.ghost())
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.select_service_group(group, cx);
                                }))
                        }),
                ),
            )
            .child(
                div().mt_2().flex().flex_wrap().gap_1().children(
                    ServiceInvestigationAction::ALL
                        .into_iter()
                        .filter(|action| action.group() == selected_group)
                        .enumerate()
                        .map(|(index, action)| {
                            let row_id = row_id.clone();
                            crate::buttons::button(("system-info-service-action", index))
                                .label(action.label())
                                .small()
                                .ghost()
                                .disabled(self.service_investigation_loading)
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.run_service_investigation(&row_id, action, cx);
                                }))
                        }),
                ),
            )
            .when(self.service_investigation_loading, |panel| {
                panel.child(
                    div()
                        .mt_3()
                        .text_sm()
                        .text_color(tokens.muted)
                        .child(format!(
                            "正在执行 {}…",
                            self.service_investigation_action
                                .map_or("服务调查", ServiceInvestigationAction::label)
                        )),
                )
            })
            .when_some(error, |panel, error| {
                panel.child(
                    div()
                        .mt_3()
                        .rounded_md()
                        .border_1()
                        .border_color(tokens.danger)
                        .p_2()
                        .text_sm()
                        .text_color(tokens.danger)
                        .child(error),
                )
            })
            .when_some(result, |panel, result| {
                panel.child(
                    div()
                        .mt_3()
                        .rounded_md()
                        .border_1()
                        .border_color(tokens.border)
                        .bg(tokens.surface_alt)
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .px_3()
                                .py_2()
                                .border_b_1()
                                .border_color(tokens.border)
                                .child(div().flex_1().text_sm().child(format!(
                                    "{}{}",
                                    result.action.label(),
                                    if result.truncated {
                                        " · 已截断"
                                    } else {
                                        ""
                                    }
                                )))
                                .child(
                                    crate::buttons::button(
                                        "system-info-copy-service-investigation",
                                    )
                                    .label("复制")
                                    .small()
                                    .ghost()
                                    .on_click(cx.listener(
                                        |this, _, _, cx| this.copy_service_investigation(cx),
                                    )),
                                ),
                        )
                        .child(
                            div()
                                .max_h(px(300.0))
                                .overflow_y_scrollbar()
                                .p_3()
                                .font_family("Cascadia Mono")
                                .text_xs()
                                .child(if result.output.is_empty() {
                                    "(无输出)".to_owned()
                                } else {
                                    result.output
                                }),
                        ),
                )
            })
            .child(self.render_service_runtime_controls(
                row_id,
                ServiceRuntimeAction::ALL.to_vec(),
                "服务状态操作",
                "确认前绑定 Load/Active/Sub/UnitFile/MainPID 等快照；变化即拒绝执行。",
                tokens,
                cx,
            ))
            .into_any_element()
    }

    fn render_user_account_controls(
        &self,
        row_id: String,
        allow_unlock: bool,
        tokens: ThemeTokens,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let busy = self.user_account_busy;
        let has_pending = self.pending_user_account.is_some();
        let pending = self.pending_user_account.clone();
        let unlock_row_id = row_id.clone();
        div()
            .mt_4()
            .border_t_1()
            .border_color(tokens.border)
            .pt_3()
            .child(
                div()
                    .text_sm()
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .child("账户处置"),
            )
            .child(div().mt_1().text_xs().text_color(tokens.muted).child(
                "操作绑定 UID、主目录、Shell 和密码状态；执行后回读验证，失败则恢复原锁定状态。",
            ))
            .child(
                div()
                    .mt_2()
                    .flex()
                    .gap_2()
                    .child(
                        crate::buttons::button("system-info-detail-user-lock")
                            .label(UserAccountAction::Lock.label())
                            .danger()
                            .small()
                            .disabled(busy || has_pending)
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.prepare_user_account(&row_id, UserAccountAction::Lock, cx);
                            })),
                    )
                    .when(allow_unlock, |buttons| {
                        buttons.child(
                            crate::buttons::button("system-info-detail-user-unlock")
                                .label(UserAccountAction::Unlock.label())
                                .danger()
                                .small()
                                .disabled(busy || has_pending)
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.prepare_user_account(
                                        &unlock_row_id,
                                        UserAccountAction::Unlock,
                                        cx,
                                    );
                                })),
                        )
                    }),
            )
            .when(busy, |section| {
                section.child(
                    div()
                        .mt_2()
                        .text_xs()
                        .text_color(tokens.muted)
                        .child("正在生成计划或执行并验证…"),
                )
            })
            .when_some(pending, |section, pending| {
                section.child(
                    div()
                        .mt_3()
                        .rounded_md()
                        .border_1()
                        .border_color(tokens.danger)
                        .bg(tokens.surface_alt)
                        .p_3()
                        .child(
                            div()
                                .text_sm()
                                .text_color(tokens.danger)
                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                .child("危险操作确认"),
                        )
                        .child(
                            div()
                                .mt_2()
                                .text_sm()
                                .child(pending.plan.definition().summary.clone()),
                        )
                        .child(
                            div()
                                .mt_3()
                                .flex()
                                .gap_2()
                                .child(
                                    crate::buttons::button("system-info-cancel-user-account")
                                        .label("取消")
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.cancel_user_account(cx)
                                        })),
                                )
                                .child(
                                    crate::buttons::button("system-info-approve-user-account")
                                        .label("确认执行")
                                        .danger()
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.approve_user_account(cx)
                                        })),
                                ),
                        ),
                )
            })
            .into_any_element()
    }

    fn render_login_firewall_controls(
        &self,
        row_id: String,
        tokens: ThemeTokens,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let has_source_ipv4 = self.login_source_ipv4(&row_id).is_ok();
        let pending = self
            .pending_network_firewall
            .clone()
            .filter(|pending| matches!(pending.lease(), FirewallInteractionLease::LoginHistory(_)));
        div()
            .when(has_source_ipv4, |section| {
                section
                    .mt_4()
                    .border_t_1()
                    .border_color(tokens.border)
                    .pt_3()
                    .child(
                        div()
                            .text_sm()
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child("来源 IP 处置"),
                    )
                    .child(div().mt_1().text_xs().text_color(tokens.muted).child(
                        "仅封禁该登录记录中解析出的 IPv4；先应用 60 秒死人开关，再次确认后才永久保留。",
                    ))
                    .child(
                        div().mt_2().child(
                            crate::buttons::button("system-info-login-block-source-ip")
                                .label("封禁来源 IP")
                                .danger()
                                .small()
                                .disabled(
                                    self.network_firewall_busy
                                        || self.pending_network_firewall.is_some(),
                                )
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.prepare_login_firewall(&row_id, cx);
                                })),
                        ),
                    )
                    .when(self.network_firewall_busy, |section| {
                        section.child(
                            div()
                                .mt_2()
                                .text_xs()
                                .text_color(tokens.muted)
                                .child("正在生成计划或执行并验证…"),
                        )
                    })
                    .when_some(pending, |section, pending| {
                        section.child(
                            div()
                                .mt_3()
                                .rounded_md()
                                .border_1()
                                .border_color(tokens.danger)
                                .bg(tokens.surface_alt)
                                .p_3()
                                .child(
                                    div()
                                        .text_sm()
                                        .text_color(tokens.danger)
                                        .font_weight(gpui::FontWeight::SEMIBOLD)
                                        .child(format!(
                                            "危险操作确认 · {}",
                                            pending.intent().label()
                                        )),
                                )
                                .child(
                                    div()
                                        .mt_2()
                                        .text_sm()
                                        .child(pending.definition().summary.clone()),
                                )
                                .child(
                                    div()
                                        .mt_3()
                                        .flex()
                                        .gap_2()
                                        .child(
                                            crate::buttons::button(
                                                "system-info-cancel-login-firewall",
                                            )
                                            .label("取消")
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.cancel_network_firewall(cx)
                                            })),
                                        )
                                        .child(
                                            crate::buttons::button(
                                                "system-info-approve-login-firewall",
                                            )
                                            .label("确认执行")
                                            .danger()
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.approve_network_firewall(cx)
                                            })),
                                        ),
                                ),
                        )
                    })
            })
            .into_any_element()
    }

    fn render_artifact_mutation_controls(
        &self,
        row_id: String,
        actions: Vec<ArtifactMutationAction>,
        tokens: ThemeTokens,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let busy = self.artifact_mutation_busy;
        let pending_summary = self
            .pending_artifact_mutation
            .as_ref()
            .map(|pending| pending.plan.definition().summary.clone());
        div()
            .mt_4()
            .border_t_1()
            .border_color(tokens.border)
            .pt_3()
            .child(
                div()
                    .text_sm()
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .child("文件处置"),
            )
            .child(
                div()
                    .mt_1()
                    .text_xs()
                    .text_color(tokens.muted)
                    .child("所有入口均先捕获不可变快照，再执行精确确认、审计、回读与失败恢复。"),
            )
            .child(div().mt_2().flex().flex_wrap().gap_2().children(
                actions.into_iter().enumerate().map(|(index, action)| {
                    let row_id = row_id.clone();
                    crate::buttons::button(("system-info-artifact-mutation", index))
                        .label(action.label())
                        .danger()
                        .small()
                        .disabled(busy || pending_summary.is_some())
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.prepare_artifact_mutation(&row_id, action, cx)
                        }))
                }),
            ))
            .when(busy, |section| {
                section.child(
                    div()
                        .mt_2()
                        .text_xs()
                        .text_color(tokens.muted)
                        .child("正在生成计划或执行并验证…"),
                )
            })
            .when_some(pending_summary, |section, summary| {
                section.child(
                    div()
                        .mt_3()
                        .rounded_md()
                        .border_1()
                        .border_color(tokens.danger)
                        .bg(tokens.surface_alt)
                        .p_3()
                        .child(
                            div()
                                .text_sm()
                                .text_color(tokens.danger)
                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                .child("危险文件操作确认"),
                        )
                        .child(div().mt_2().text_sm().child(summary))
                        .child(
                            div()
                                .mt_3()
                                .flex()
                                .gap_2()
                                .child(
                                    crate::buttons::button("system-info-cancel-artifact-mutation")
                                        .label("取消")
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.cancel_artifact_mutation(cx)
                                        })),
                                )
                                .child(
                                    crate::buttons::button("system-info-approve-artifact-mutation")
                                        .label("确认执行")
                                        .danger()
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.approve_artifact_mutation(cx)
                                        })),
                                ),
                        ),
                )
            })
            .into_any_element()
    }

    fn render_artifact_investigation(
        &self,
        row: &SystemInfoRow,
        tokens: ThemeTokens,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let row_id = row.id.clone();
        let tab = self.model.active_tab();
        let result = self.artifact_investigation_result.clone();
        let error = self.artifact_investigation_error.clone();
        let actions = self.model.active_table().map_or_else(Vec::new, |table| {
            artifact_actions(tab)
                .into_iter()
                .filter(|action| {
                    table
                        .artifact_investigation_request(&row.id, *action)
                        .is_ok()
                })
                .collect::<Vec<_>>()
        });
        let title = match tab {
            SystemInfoTab::Packages => "软件包调查",
            SystemInfoTab::KernelModules => "内核模块调查",
            SystemInfoTab::EnvVars => "环境变量调查",
            SystemInfoTab::Autostart => "自启动调查",
            SystemInfoTab::Cron => "Cron 任务调查",
            SystemInfoTab::Timers => "systemd 定时器调查",
            SystemInfoTab::ShellConfigs => "Shell 配置调查",
            SystemInfoTab::Sudoers => "Sudoers 调查",
            SystemInfoTab::SuidFiles => "SUID 文件调查",
            SystemInfoTab::SshKeys => "SSH 公钥调查",
            _ => "系统对象调查",
        };
        let mutation_actions = self.model.active_table().map_or_else(Vec::new, |table| {
            match tab {
                SystemInfoTab::Cron => vec![ArtifactMutationAction::DeleteCronFile],
                SystemInfoTab::ShellConfigs => vec![ArtifactMutationAction::CommentShellLine],
                SystemInfoTab::SuidFiles => vec![
                    ArtifactMutationAction::RemoveSuidBits,
                    ArtifactMutationAction::QuarantineSuidFile,
                ],
                SystemInfoTab::KernelModules => vec![
                    ArtifactMutationAction::AddManagedModuleBlacklist,
                    ArtifactMutationAction::RemoveManagedModuleBlacklist,
                ],
                _ => Vec::new(),
            }
            .into_iter()
            .filter(|action| table.artifact_mutation_request(&row.id, *action).is_ok())
            .collect()
        });
        div()
            .mt_4()
            .border_t_1()
            .border_color(tokens.border)
            .pt_3()
            .child(
                div()
                    .text_sm()
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .child(title),
            )
            .child(
                div()
                    .mt_1()
                    .text_xs()
                    .text_color(tokens.muted)
                    .child(match tab {
                        SystemInfoTab::Packages => {
                            "仅查询本地包数据库与文件；卸载预览是模拟，不执行卸载或联网 changelog。"
                        }
                        SystemInfoTab::KernelModules => {
                            "调查读取 modinfo、sysfs、签名、哈希与日志；可创建或移除 LovelyRes 受管自动加载黑名单，模块卸载仍未开放。"
                        }
                        SystemInfoTab::EnvVars => {
                            "变量名经过闭集语法校验；跨进程调查只读取可访问的 /proc 环境，不启动用户 Shell。"
                        }
                        SystemInfoTab::Autostart => {
                            "调查仅读取 systemd 单元、依赖、日志、哈希与资源；状态操作另行绑定快照、确认、审计并回读验证。"
                        }
                        SystemInfoTab::Cron => {
                            "任务命令始终作为惰性文本分析；不会运行命令。仅 /etc/cron.d 独立文件可在 SHA-256 CAS 后移入受管备份。"
                        }
                        SystemInfoTab::Timers => {
                            "调查只读取 timer 与触发单元；停止、禁用和屏蔽均需快照、危险确认、审计与回读验证。"
                        }
                        SystemInfoTab::ShellConfigs => {
                            "路径限定为已采集的系统与用户 Shell 配置；精确行注释会核对原始内容并原子写入，验证失败自动恢复。"
                        }
                        SystemInfoTab::Sudoers => {
                            "来源限定为 /etc/sudoers 与 sudoers.d；语法和权限调查不会改写授权规则。"
                        }
                        SystemInfoTab::SuidFiles => {
                            "权限处置绑定内容哈希、模式、设备号和 inode；先写受管备份，再对同一文件描述符移除特权位或设为 000。"
                        }
                        SystemInfoTab::SshKeys => {
                            "仅调查 authorized_keys 公钥及 sshd 公钥认证配置；不会读取私钥或修改认证设置。"
                        }
                        _ => "只读调查绑定当前目标、分类、行和请求代次。",
                    }),
            )
            .child(
                div()
                    .mt_3()
                    .flex()
                    .flex_wrap()
                    .gap_2()
                    .children(actions.into_iter().enumerate().map(|(index, action)| {
                        let row_id = row_id.clone();
                        crate::buttons::button(("system-info-artifact-action", index))
                            .label(action.label())
                            .small()
                            .ghost()
                            .disabled(self.artifact_investigation_loading)
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.run_artifact_investigation(&row_id, action, cx);
                            }))
                    })),
            )
            .when(self.artifact_investigation_loading, |panel| {
                panel.child(
                    div()
                        .mt_3()
                        .text_sm()
                        .text_color(tokens.muted)
                        .child(format!(
                            "正在执行 {}…",
                            self.artifact_investigation_action
                                .map_or("系统对象调查", ArtifactInvestigationAction::label)
                        )),
                )
            })
            .when_some(error, |panel, error| {
                panel.child(
                    div()
                        .mt_3()
                        .rounded_md()
                        .border_1()
                        .border_color(tokens.danger)
                        .p_2()
                        .text_sm()
                        .text_color(tokens.danger)
                        .child(error),
                )
            })
            .when_some(result, |panel, result| {
                panel.child(
                    div()
                        .mt_3()
                        .rounded_md()
                        .border_1()
                        .border_color(tokens.border)
                        .bg(tokens.surface_alt)
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .px_3()
                                .py_2()
                                .border_b_1()
                                .border_color(tokens.border)
                                .child(div().flex_1().text_sm().child(format!(
                                    "{}{}",
                                    result.action.label(),
                                    if result.truncated { " · 已截断" } else { "" }
                                )))
                                .child(
                                    crate::buttons::button("system-info-copy-artifact-investigation")
                                        .label("复制")
                                        .small()
                                        .ghost()
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.copy_artifact_investigation(cx)
                                        })),
                                ),
                        )
                        .child(
                            div()
                                .max_h(px(360.0))
                                .overflow_y_scrollbar()
                                .p_3()
                                .font_family("Cascadia Mono")
                                .text_xs()
                                .child(if result.output.is_empty() {
                                    "(无输出)".to_owned()
                                } else {
                                    result.output
                                }),
                        ),
                )
            })
            .when(tab == SystemInfoTab::Autostart, |panel| {
                panel.child(self.render_service_runtime_controls(
                    row.id.clone(),
                    ServiceRuntimeAction::AUTOSTART.to_vec(),
                    "启动项状态操作",
                    "启动、启用或禁用前绑定完整 systemd 状态；单元文件状态失败时自动恢复。",
                    tokens,
                    cx,
                ))
            })
            .when(tab == SystemInfoTab::Timers, |panel| {
                panel.child(self.render_service_runtime_controls(
                    row.id.clone(),
                    ServiceRuntimeAction::TIMER.to_vec(),
                    "定时器状态操作",
                    "停止不可自动恢复；禁用与屏蔽会绑定并恢复确认前的单元文件状态。",
                    tokens,
                    cx,
                ))
            })
            .when(!mutation_actions.is_empty(), |panel| {
                panel.child(self.render_artifact_mutation_controls(
                    row.id.clone(),
                    mutation_actions,
                    tokens,
                    cx,
                ))
            })
            .into_any_element()
    }

    fn render_user_investigation(
        &self,
        row: &SystemInfoRow,
        tokens: ThemeTokens,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let row_id = row.id.clone();
        let controls_row_id = row.id.clone();
        let selected_group = self.user_group;
        let result = self.user_investigation_result.clone();
        let error = self.user_investigation_error.clone();
        div()
            .mt_4()
            .border_t_1()
            .border_color(tokens.border)
            .pt_3()
            .child(
                div()
                    .text_sm()
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .child("用户调查"),
            )
            .child(
                div()
                    .mt_1()
                    .text_xs()
                    .text_color(tokens.muted)
                    .child("20 项只读调查均由闭集命令生成，并绑定当前目标、用户行与请求代次。"),
            )
            .child(
                div().mt_3().flex().flex_wrap().gap_1().children(
                    UserInvestigationGroup::ALL
                        .into_iter()
                        .enumerate()
                        .map(|(index, group)| {
                            crate::buttons::button(("system-info-user-group", index))
                                .label(group.label())
                                .small()
                                .when(group == selected_group, |button| button.primary())
                                .when(group != selected_group, |button| button.ghost())
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.select_user_group(group, cx);
                                }))
                        }),
                ),
            )
            .child(
                div().mt_2().flex().flex_wrap().gap_1().children(
                    UserInvestigationAction::ALL
                        .into_iter()
                        .filter(|action| action.group() == selected_group)
                        .enumerate()
                        .map(|(index, action)| {
                            let row_id = row_id.clone();
                            crate::buttons::button(("system-info-user-action", index))
                                .label(action.label())
                                .small()
                                .ghost()
                                .disabled(self.user_investigation_loading)
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.run_user_investigation(&row_id, action, cx);
                                }))
                        }),
                ),
            )
            .when(self.user_investigation_loading, |panel| {
                panel.child(
                    div()
                        .mt_3()
                        .text_sm()
                        .text_color(tokens.muted)
                        .child(format!(
                            "正在执行 {}…",
                            self.user_investigation_action
                                .map_or("用户调查", UserInvestigationAction::label)
                        )),
                )
            })
            .when_some(error, |panel, error| {
                panel.child(
                    div()
                        .mt_3()
                        .rounded_md()
                        .border_1()
                        .border_color(tokens.danger)
                        .p_2()
                        .text_sm()
                        .text_color(tokens.danger)
                        .child(error),
                )
            })
            .when_some(result, |panel, result| {
                panel.child(
                    div()
                        .mt_3()
                        .rounded_md()
                        .border_1()
                        .border_color(tokens.border)
                        .bg(tokens.surface_alt)
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .px_3()
                                .py_2()
                                .border_b_1()
                                .border_color(tokens.border)
                                .child(div().flex_1().text_sm().child(format!(
                                    "{}{}",
                                    result.action.label(),
                                    if result.truncated {
                                        " · 已截断"
                                    } else {
                                        ""
                                    }
                                )))
                                .child(
                                    crate::buttons::button("system-info-copy-user-investigation")
                                        .label("复制")
                                        .small()
                                        .ghost()
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.copy_user_investigation(cx)
                                        })),
                                ),
                        )
                        .child(
                            div()
                                .max_h(px(300.0))
                                .overflow_y_scrollbar()
                                .p_3()
                                .font_family("Cascadia Mono")
                                .text_xs()
                                .child(if result.output.is_empty() {
                                    "(无输出)".to_owned()
                                } else {
                                    result.output
                                }),
                        ),
                )
            })
            .child(self.render_user_account_controls(controls_row_id, true, tokens, cx))
            .into_any_element()
    }

    fn render_login_investigation(
        &self,
        row: &SystemInfoRow,
        tokens: ThemeTokens,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let row_id = row.id.clone();
        let controls_row_id = row.id.clone();
        let firewall_row_id = row.id.clone();
        let selected_group = self.login_group;
        let result = self.login_investigation_result.clone();
        let error = self.login_investigation_error.clone();
        let actions = self.model.active_table().map_or_else(Vec::new, |table| {
            LoginInvestigationAction::ALL
                .into_iter()
                .filter(|action| action.group() == selected_group)
                .filter(|action| table.login_investigation_request(&row.id, *action).is_ok())
                .collect::<Vec<_>>()
        });
        div()
            .mt_4()
            .border_t_1()
            .border_color(tokens.border)
            .pt_3()
            .child(
                div()
                    .text_sm()
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .child("登录历史调查"),
            )
            .child(
                div()
                    .mt_1()
                    .text_xs()
                    .text_color(tokens.muted)
                    .child("用户与来源 IP 均从所选登录记录生成；缺少有效 IP 时自动隐藏来源调查。"),
            )
            .child(
                div().mt_3().flex().flex_wrap().gap_1().children(
                    LoginInvestigationGroup::ALL
                        .into_iter()
                        .enumerate()
                        .map(|(index, group)| {
                            crate::buttons::button(("system-info-login-group", index))
                                .label(group.label())
                                .small()
                                .when(group == selected_group, |button| button.primary())
                                .when(group != selected_group, |button| button.ghost())
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.select_login_group(group, cx);
                                }))
                        }),
                ),
            )
            .child(div().mt_2().flex().flex_wrap().gap_1().children(
                actions.into_iter().enumerate().map(|(index, action)| {
                    let row_id = row_id.clone();
                    crate::buttons::button(("system-info-login-action", index))
                        .label(action.label())
                        .small()
                        .ghost()
                        .disabled(self.login_investigation_loading)
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.run_login_investigation(&row_id, action, cx);
                        }))
                }),
            ))
            .when(self.login_investigation_loading, |panel| {
                panel.child(
                    div()
                        .mt_3()
                        .text_sm()
                        .text_color(tokens.muted)
                        .child(format!(
                            "正在执行 {}…",
                            self.login_investigation_action
                                .map_or("登录历史调查", LoginInvestigationAction::label)
                        )),
                )
            })
            .when_some(error, |panel, error| {
                panel.child(
                    div()
                        .mt_3()
                        .rounded_md()
                        .border_1()
                        .border_color(tokens.danger)
                        .p_2()
                        .text_sm()
                        .text_color(tokens.danger)
                        .child(error),
                )
            })
            .when_some(result, |panel, result| {
                panel.child(
                    div()
                        .mt_3()
                        .rounded_md()
                        .border_1()
                        .border_color(tokens.border)
                        .bg(tokens.surface_alt)
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .px_3()
                                .py_2()
                                .border_b_1()
                                .border_color(tokens.border)
                                .child(div().flex_1().text_sm().child(format!(
                                    "{}{}",
                                    result.action.label(),
                                    if result.truncated {
                                        " · 已截断"
                                    } else {
                                        ""
                                    }
                                )))
                                .child(
                                    crate::buttons::button("system-info-copy-login-investigation")
                                        .label("复制")
                                        .small()
                                        .ghost()
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.copy_login_investigation(cx)
                                        })),
                                ),
                        )
                        .child(
                            div()
                                .max_h(px(300.0))
                                .overflow_y_scrollbar()
                                .p_3()
                                .font_family("Cascadia Mono")
                                .text_xs()
                                .child(if result.output.is_empty() {
                                    "(无输出)".to_owned()
                                } else {
                                    result.output
                                }),
                        ),
                )
            })
            .child(self.render_user_account_controls(controls_row_id, false, tokens, cx))
            .child(self.render_login_firewall_controls(firewall_row_id, tokens, cx))
            .into_any_element()
    }

    fn render_network_investigation(
        &self,
        row: &SystemInfoRow,
        tokens: ThemeTokens,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let row_id = row.id.clone();
        let busy = self.network_disconnect_busy;
        let has_pending = self.pending_network_disconnect.is_some();
        let result = self.network_investigation_result.clone();
        let error = self.network_investigation_error.clone();
        let pending_disconnect = self.pending_network_disconnect.clone();
        let pending_firewall = self.pending_network_firewall.clone();
        let available_actions = self.model.active_table().map_or_else(Vec::new, |table| {
            NetworkInvestigationAction::ALL
                .into_iter()
                .filter(|action| {
                    table
                        .network_investigation_request(&row_id, *action)
                        .is_ok()
                })
                .collect::<Vec<_>>()
        });
        let selected_group = if available_actions
            .iter()
            .any(|action| action.group() == self.network_group)
        {
            self.network_group
        } else {
            available_actions
                .first()
                .map_or(self.network_group, |action| action.group())
        };
        let can_disconnect = self
            .model
            .active_table()
            .is_some_and(|table| table.network_disconnect_request(&row_id).is_ok());
        let has_remote_ipv4 = self.model.active_table().is_some_and(|table| {
            table
                .network_identity(&row_id)
                .ok()
                .and_then(|identity| identity.remote.map(|endpoint| endpoint.address))
                .is_some_and(
                    |address| matches!(address, IpAddr::V4(value) if !value.is_unspecified()),
                )
        });
        div()
            .mt_4()
            .border_t_1()
            .border_color(tokens.border)
            .pt_3()
            .child(
                div()
                    .text_sm()
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .child("网络调查"),
            )
            .child(
                div()
                    .mt_1()
                    .text_xs()
                    .text_color(tokens.muted)
                    .child("动作仅接受解析后的 IP/端口，不接受原始命令；远端输出以纯文本显示。"),
            )
            .child(
                div().mt_3().flex().flex_wrap().gap_1().children(
                    NetworkInvestigationGroup::ALL
                        .into_iter()
                        .filter(|group| {
                            available_actions
                                .iter()
                                .any(|action| action.group() == *group)
                        })
                        .enumerate()
                        .map(|(index, group)| {
                            crate::buttons::button(("system-info-network-group", index))
                                .label(group.label())
                                .small()
                                .when(group == selected_group, |button| button.primary())
                                .when(group != selected_group, |button| button.ghost())
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.select_network_group(group, cx);
                                }))
                        }),
                ),
            )
            .child(
                div().mt_2().flex().flex_wrap().gap_1().children(
                    available_actions
                        .into_iter()
                        .filter(|action| action.group() == selected_group)
                        .enumerate()
                        .map(|(index, action)| {
                            let row_id = row_id.clone();
                            crate::buttons::button(("system-info-network-action", index))
                                .label(action.label())
                                .small()
                                .ghost()
                                .disabled(self.network_investigation_loading)
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.run_network_investigation(&row_id, action, cx);
                                }))
                        }),
                ),
            )
            .when(self.network_investigation_loading, |panel| {
                panel.child(
                    div()
                        .mt_3()
                        .text_sm()
                        .text_color(tokens.muted)
                        .child(format!(
                            "正在执行 {}…",
                            self.network_investigation_action
                                .map_or("网络调查", NetworkInvestigationAction::label)
                        )),
                )
            })
            .when_some(error, |panel, error| {
                panel.child(
                    div()
                        .mt_3()
                        .rounded_md()
                        .border_1()
                        .border_color(tokens.danger)
                        .p_2()
                        .text_sm()
                        .text_color(tokens.danger)
                        .child(error),
                )
            })
            .when_some(result, |panel, result| {
                panel.child(
                    div()
                        .mt_3()
                        .rounded_md()
                        .border_1()
                        .border_color(tokens.border)
                        .bg(tokens.surface_alt)
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .px_3()
                                .py_2()
                                .border_b_1()
                                .border_color(tokens.border)
                                .child(div().flex_1().text_sm().child(format!(
                                    "{}{}",
                                    result.action.label(),
                                    if result.truncated {
                                        " · 已截断"
                                    } else {
                                        ""
                                    }
                                )))
                                .child(
                                    crate::buttons::button(
                                        "system-info-copy-network-investigation",
                                    )
                                    .label("复制")
                                    .small()
                                    .ghost()
                                    .on_click(cx.listener(
                                        |this, _, _, cx| this.copy_network_investigation(cx),
                                    )),
                                ),
                        )
                        .child(
                            div()
                                .max_h(px(300.0))
                                .overflow_y_scrollbar()
                                .p_3()
                                .font_family("Cascadia Mono")
                                .text_xs()
                                .child(if result.output.is_empty() {
                                    "(无输出)".to_owned()
                                } else {
                                    result.output
                                }),
                        ),
                )
            })
            .when(can_disconnect, |panel| {
                panel.child(
                    div()
                        .mt_4()
                        .border_t_1()
                        .border_color(tokens.border)
                        .pt_3()
                        .child(
                            div()
                                .text_sm()
                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                .child("连接处置"),
                        )
                        .child(div().mt_1().text_xs().text_color(tokens.muted).child(
                            "仅对精确 TCP 四元组执行 ss -K；确认前后均重新核对端点与进程快照。",
                        ))
                        .child(
                            div().mt_2().child(
                                crate::buttons::button("system-info-detail-network-disconnect")
                                    .label("断开精确 TCP 连接")
                                    .danger()
                                    .small()
                                    .disabled(busy || has_pending)
                                    .on_click({
                                        let row_id = row_id.clone();
                                        cx.listener(move |this, _, _, cx| {
                                            this.prepare_network_disconnect(&row_id, cx)
                                        })
                                    }),
                            ),
                        )
                        .when(busy, |section| {
                            section.child(
                                div()
                                    .mt_2()
                                    .text_xs()
                                    .text_color(tokens.muted)
                                    .child("正在生成计划或执行并验证…"),
                            )
                        })
                        .when_some(pending_disconnect, |section, pending| {
                            section.child(
                                div()
                                    .mt_3()
                                    .rounded_md()
                                    .border_1()
                                    .border_color(tokens.danger)
                                    .bg(tokens.surface_alt)
                                    .p_3()
                                    .child(
                                        div()
                                            .text_sm()
                                            .text_color(tokens.danger)
                                            .font_weight(gpui::FontWeight::SEMIBOLD)
                                            .child("危险操作确认"),
                                    )
                                    .child(
                                        div()
                                            .mt_2()
                                            .text_sm()
                                            .child(pending.plan.definition().summary.clone()),
                                    )
                                    .child(
                                        div()
                                            .mt_3()
                                            .flex()
                                            .gap_2()
                                            .child(
                                                crate::buttons::button(
                                                    "system-info-cancel-network-disconnect",
                                                )
                                                .label("取消")
                                                .on_click(cx.listener(|this, _, _, cx| {
                                                    this.cancel_network_disconnect(cx)
                                                })),
                                            )
                                            .child(
                                                crate::buttons::button(
                                                    "system-info-approve-network-disconnect",
                                                )
                                                .label("确认断开")
                                                .danger()
                                                .on_click(cx.listener(|this, _, _, cx| {
                                                    this.approve_network_disconnect(cx)
                                                })),
                                            ),
                                    ),
                            )
                        }),
                )
            })
            .when(has_remote_ipv4, |panel| {
                let row_for_allow = row_id.clone();
                let row_for_temporary = row_id.clone();
                panel.child(
                    div()
                        .mt_4()
                        .border_t_1()
                        .border_color(tokens.border)
                        .pt_3()
                        .child(
                            div()
                                .text_sm()
                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                .child("IP 边界处置"),
                        )
                        .child(div().mt_1().text_xs().text_color(tokens.muted).child(
                            "仅创建 LovelyRes 独立规则对象；不会改写默认策略或删除任意系统规则。",
                        ))
                        .child(
                            div()
                                .mt_2()
                                .flex()
                                .flex_wrap()
                                .gap_2()
                                .child(
                                    crate::buttons::button("system-info-network-block-ip")
                                        .label("封禁 IP")
                                        .danger()
                                        .small()
                                        .disabled(
                                            self.network_firewall_busy
                                                || pending_firewall.is_some(),
                                        )
                                        .on_click({
                                            let row_id = row_id.clone();
                                            cx.listener(move |this, _, _, cx| {
                                                this.prepare_network_firewall(
                                                    &row_id,
                                                    NetworkFirewallIntent::Block,
                                                    cx,
                                                )
                                            })
                                        }),
                                )
                                .child(
                                    crate::buttons::button("system-info-network-allow-ip")
                                        .label("恢复放行")
                                        .small()
                                        .disabled(
                                            self.network_firewall_busy
                                                || pending_firewall.is_some(),
                                        )
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.prepare_network_firewall(
                                                &row_for_allow,
                                                NetworkFirewallIntent::Allow,
                                                cx,
                                            )
                                        })),
                                )
                                .child(
                                    crate::buttons::button(
                                        "system-info-network-temporary-block-ip",
                                    )
                                    .label("临时封禁 5 分钟")
                                    .danger()
                                    .small()
                                    .disabled(
                                        self.network_firewall_busy || pending_firewall.is_some(),
                                    )
                                    .on_click(cx.listener(
                                        move |this, _, _, cx| {
                                            this.prepare_network_firewall(
                                                &row_for_temporary,
                                                NetworkFirewallIntent::TemporaryBlock,
                                                cx,
                                            )
                                        },
                                    )),
                                ),
                        )
                        .when(self.network_firewall_busy, |section| {
                            section.child(
                                div()
                                    .mt_2()
                                    .text_xs()
                                    .text_color(tokens.muted)
                                    .child("正在生成计划或执行并验证…"),
                            )
                        })
                        .when_some(pending_firewall, |section, pending| {
                            section.child(
                                div()
                                    .mt_3()
                                    .rounded_md()
                                    .border_1()
                                    .border_color(tokens.danger)
                                    .bg(tokens.surface_alt)
                                    .p_3()
                                    .child(
                                        div()
                                            .text_sm()
                                            .text_color(tokens.danger)
                                            .font_weight(gpui::FontWeight::SEMIBOLD)
                                            .child(format!(
                                                "危险操作确认 · {}",
                                                pending.intent().label()
                                            )),
                                    )
                                    .child(
                                        div()
                                            .mt_2()
                                            .text_sm()
                                            .child(pending.definition().summary.clone()),
                                    )
                                    .child(
                                        div()
                                            .mt_3()
                                            .flex()
                                            .gap_2()
                                            .child(
                                                crate::buttons::button(
                                                    "system-info-cancel-network-firewall",
                                                )
                                                .label("取消")
                                                .on_click(cx.listener(|this, _, _, cx| {
                                                    this.cancel_network_firewall(cx)
                                                })),
                                            )
                                            .child(
                                                crate::buttons::button(
                                                    "system-info-approve-network-firewall",
                                                )
                                                .label("确认执行")
                                                .danger()
                                                .on_click(cx.listener(|this, _, _, cx| {
                                                    this.approve_network_firewall(cx)
                                                })),
                                            ),
                                    ),
                            )
                        }),
                )
            })
            .into_any_element()
    }

    fn render_detail(
        &self,
        tab: SystemInfoTab,
        columns: Vec<String>,
        row: SystemInfoRow,
        tokens: ThemeTokens,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let process_row = row.clone();
        let service_row = row.clone();
        let user_row = row.clone();
        let login_row = row.clone();
        let network_row = row.clone();
        let artifact_row = row.clone();
        div()
            .w(
                if is_artifact_tab(tab)
                    || matches!(
                        tab,
                        SystemInfoTab::Processes
                            | SystemInfoTab::Services
                            | SystemInfoTab::Network
                            | SystemInfoTab::Established
                            | SystemInfoTab::OpenPorts
                            | SystemInfoTab::Users
                            | SystemInfoTab::LoginHistory
                    )
                {
                    px(440.0)
                } else {
                    px(360.0)
                },
            )
            .flex_none()
            .min_h_0()
            .overflow_y_scrollbar()
            .rounded_lg()
            .border_1()
            .border_color(tokens.border)
            .bg(tokens.surface)
            .p_3()
            .child(
                div()
                    .flex()
                    .items_center()
                    .child(div().text_lg().child(detail_title(tab)))
                    .child(
                        crate::buttons::button("system-info-copy-row")
                            .label("复制")
                            .small()
                            .on_click(cx.listener(|this, _, _, cx| this.copy_selected(cx))),
                    )
                    .child(
                        crate::buttons::close_button("system-info-close-detail")
                            .small()
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.close_detail(cx);
                            })),
                    ),
            )
            .child(
                div()
                    .mt_2()
                    .text_xs()
                    .text_color(tokens.muted)
                    .child(match tab {
                        SystemInfoTab::Processes => {
                            "调查动作只读；SIGTERM/SIGKILL 必须经过精确身份确认、审计和状态回读。"
                        }
                        SystemInfoTab::Services => {
                            "调查动作只读；服务状态操作必须经过快照绑定、确认、审计和回读。"
                        }
                        SystemInfoTab::Users | SystemInfoTab::LoginHistory => {
                            "调查动作只读；账户锁定状态操作必须经过身份快照、确认、审计、回读与失败恢复。"
                        }
                        SystemInfoTab::Network | SystemInfoTab::Established => {
                            "网络调查只读；精确断连必须经过端点快照绑定、确认、审计和回读。"
                        }
                        SystemInfoTab::OpenPorts => {
                            "监听端口开放只读端口/进程调查；没有远端四元组时不提供断连。"
                        }
                        _ => "本面板只执行只读检查；修改操作统一从对应处置流程进入。",
                    }),
            )
            .child(
                div()
                    .mt_2()
                    .rounded_md()
                    .border_1()
                    .border_color(risk_color(row.risk, tokens))
                    .p_2()
                    .text_color(risk_color(row.risk, tokens))
                    .child(format!("风险：{}", row.risk.label())),
            )
            .children(columns.into_iter().zip(row.cells).map(|(column, value)| {
                div()
                    .mt_3()
                    .child(div().text_xs().text_color(tokens.muted).child(column))
                    .child(div().mt_1().text_sm().child(value))
            }))
            .child(
                div()
                    .mt_4()
                    .border_t_1()
                    .border_color(tokens.border)
                    .pt_3()
                    .child(
                        div()
                            .text_sm()
                            .text_color(tokens.muted)
                            .child("只读自动概要"),
                    )
                    .when(self.detail_loading, |detail| {
                        detail.child(
                            div()
                                .mt_2()
                                .text_sm()
                                .text_color(tokens.muted)
                                .child("正在读取目标详情…"),
                        )
                    })
                    .when_some(self.detail_error.clone(), |detail, error| {
                        detail.child(
                            div()
                                .mt_2()
                                .text_sm()
                                .text_color(tokens.danger)
                                .child(error),
                        )
                    })
                    .when_some(self.model.detail().cloned(), |detail_panel, detail| {
                        detail_panel.children(detail.fields.into_iter().map(|field| {
                            div()
                                .mt_3()
                                .child(div().text_xs().text_color(tokens.muted).child(field.label))
                                .child(div().mt_1().text_sm().child(field.value))
                        }))
                    })
                    .when(
                        !self.detail_loading
                            && self.detail_error.is_none()
                            && self.model.detail().is_none(),
                        |detail| {
                            detail.child(
                                div()
                                    .mt_2()
                                    .text_xs()
                                    .text_color(tokens.muted)
                                    .child("此数据面仅提供本次采集字段，不执行远端动作。"),
                            )
                        },
                    ),
            )
            .when(tab == SystemInfoTab::Processes, |detail| {
                detail.child(self.render_process_investigation(&process_row, tokens, cx))
            })
            .when(tab == SystemInfoTab::Services, |detail| {
                detail.child(self.render_service_investigation(&service_row, tokens, cx))
            })
            .when(tab == SystemInfoTab::Users, |detail| {
                detail.child(self.render_user_investigation(&user_row, tokens, cx))
            })
            .when(tab == SystemInfoTab::LoginHistory, |detail| {
                detail.child(self.render_login_investigation(&login_row, tokens, cx))
            })
            .when(is_network_tab(tab), |detail| {
                detail.child(self.render_network_investigation(&network_row, tokens, cx))
            })
            .when(is_artifact_tab(tab), |detail| {
                detail.child(self.render_artifact_investigation(&artifact_row, tokens, cx))
            })
            .into_any_element()
    }
}

fn overview_section(
    title: &'static str,
    fields: Vec<(&'static str, String)>,
    tokens: ThemeTokens,
) -> gpui::Div {
    div()
        .min_w(px(320.0))
        .flex_1()
        .rounded_lg()
        .border_1()
        .border_color(tokens.border)
        .bg(tokens.background)
        .p_3()
        .child(
            div()
                .mb_2()
                .text_sm()
                .font_weight(gpui::FontWeight::SEMIBOLD)
                .child(title),
        )
        .children(
            fields
                .into_iter()
                .enumerate()
                .map(|(index, (label, value))| {
                    div()
                        .min_h(px(34.0))
                        .py_2()
                        .flex()
                        .items_start()
                        .justify_between()
                        .gap_4()
                        .when(index > 0, |row| {
                            row.border_t_1().border_color(tokens.border)
                        })
                        .child(div().text_xs().text_color(tokens.muted).child(label))
                        .child(
                            div()
                                .max_w(px(300.0))
                                .text_right()
                                .text_sm()
                                .font_weight(gpui::FontWeight::MEDIUM)
                                .child(value),
                        )
                }),
        )
}

fn display_summary_value(value: &str) -> String {
    if value.trim().is_empty() {
        "未检测到".to_owned()
    } else {
        value.to_owned()
    }
}

fn overview_fields(summary: &SystemInfoSummary) -> Vec<(&'static str, String)> {
    vec![
        ("主机名", display_summary_value(&summary.hostname)),
        ("操作系统", display_summary_value(&summary.operating_system)),
        ("内核", display_summary_value(&summary.kernel)),
        ("架构", display_summary_value(&summary.architecture)),
        ("虚拟化", display_summary_value(&summary.virtualization)),
        ("Init 系统", display_summary_value(&summary.init_system)),
        ("启动时间", display_summary_value(&summary.boot_time)),
        ("运行时间", format_duration(summary.uptime_seconds)),
        ("时区", display_summary_value(&summary.timezone)),
        ("Locale", display_summary_value(&summary.locale)),
        ("包管理器", display_summary_value(&summary.package_manager)),
        ("CPU", display_summary_value(&summary.cpu_model)),
        ("逻辑核心", summary.cpu_cores.to_string()),
        (
            "负载 (1/5/15m)",
            format!(
                "{} / {} / {}",
                summary.load_average[0], summary.load_average[1], summary.load_average[2]
            ),
        ),
        (
            "内存",
            format!(
                "可用 {} / 总计 {}",
                format_bytes(summary.memory_available_bytes),
                format_bytes(summary.memory_total_bytes)
            ),
        ),
        (
            "交换分区",
            format!(
                "可用 {} / 总计 {}",
                format_bytes(summary.swap_free_bytes),
                format_bytes(summary.swap_total_bytes)
            ),
        ),
        ("根设备", display_summary_value(&summary.root_device)),
        (
            "根文件系统",
            display_summary_value(&summary.root_filesystem),
        ),
        (
            "根分区空间",
            format!(
                "可用 {} / 总计 {}",
                format_bytes(summary.root_available_bytes),
                format_bytes(summary.root_total_bytes)
            ),
        ),
        ("主 IP", display_summary_value(&summary.primary_ip)),
        ("默认网关", display_summary_value(&summary.default_gateway)),
        ("DNS", display_summary_value(&summary.dns_servers)),
        ("SELinux", display_summary_value(&summary.selinux)),
        ("AppArmor", display_summary_value(&summary.apparmor)),
        ("进程数", summary.process_count.to_string()),
        ("登录用户", summary.logged_in_users.to_string()),
        ("网络连接", summary.network_connections.to_string()),
        (
            "累计流量",
            format!(
                "RX {} · TX {}",
                format_bytes(summary.received_bytes),
                format_bytes(summary.transmitted_bytes)
            ),
        ),
    ]
}

fn table_result_hint(filtered_total: usize) -> &'static str {
    if filtered_total == 0 {
        "筛选结果为空"
    } else {
        "点击行查看详情"
    }
}

const fn primary_context_column(tab: SystemInfoTab) -> usize {
    match tab {
        SystemInfoTab::Processes => 1,
        SystemInfoTab::Network => 2,
        SystemInfoTab::Established => 1,
        SystemInfoTab::OpenPorts => 2,
        SystemInfoTab::Docker | SystemInfoTab::Kubernetes => 1,
        _ => 0,
    }
}

const fn context_detail_label(tab: SystemInfoTab) -> &'static str {
    match tab {
        SystemInfoTab::Processes => "调查进程（路径、权限、资源）",
        SystemInfoTab::Network | SystemInfoTab::Established | SystemInfoTab::OpenPorts => {
            "查看连接与端口详情"
        }
        SystemInfoTab::Services | SystemInfoTab::Autostart | SystemInfoTab::Timers => {
            "检查服务配置与状态"
        }
        SystemInfoTab::Users | SystemInfoTab::LoginHistory | SystemInfoTab::SshKeys => {
            "检查账号与登录详情"
        }
        SystemInfoTab::SuidFiles
        | SystemInfoTab::ShellConfigs
        | SystemInfoTab::Sensitive
        | SystemInfoTab::RecentFiles => "检查文件属性与痕迹",
        SystemInfoTab::Packages | SystemInfoTab::KernelModules => "检查来源、完整性与依赖",
        _ => "查看记录详情",
    }
}

fn context_label(value: &str) -> String {
    const MAXIMUM_CHARS: usize = 48;
    let mut chars = value.chars();
    let mut label = chars.by_ref().take(MAXIMUM_CHARS).collect::<String>();
    if chars.next().is_some() {
        label.push('…');
    }
    if label.trim().is_empty() {
        "当前记录".to_owned()
    } else {
        label
    }
}

fn context_menu_separator(tokens: ThemeTokens) -> impl IntoElement {
    div().h(px(1.0)).mx_1().my_1().flex_none().bg(tokens.border)
}

const fn is_flexible_table_column(index: usize, column_count: usize) -> bool {
    column_count > 0 && index + 1 == column_count
}

fn table_column_width(tab: SystemInfoTab, index: usize, column: &str) -> gpui::Pixels {
    if tab == SystemInfoTab::Processes {
        return [84.0, 84.0, 84.0, 112.0, 84.0, 84.0, 84.0, 112.0, 480.0]
            .get(index)
            .copied()
            .map(px)
            .unwrap_or_else(|| px(140.0));
    }

    if ["命令", "内容", "描述", "公钥", "选项", "路径/命令", "值"]
        .iter()
        .any(|hint| column.contains(hint))
    {
        px(360.0)
    } else if ["路径", "文件", "目录", "地址", "URL"]
        .iter()
        .any(|hint| column.contains(hint))
    {
        px(260.0)
    } else if ["时间", "日期", "触发", "创建"]
        .iter()
        .any(|hint| column.contains(hint))
    {
        px(180.0)
    } else {
        px(132.0)
    }
}

fn is_monospace_column(column: &str) -> bool {
    ["命令", "内容", "公钥", "路径", "地址", "URL", "选项", "值"]
        .iter()
        .any(|hint| column.contains(hint))
}

#[derive(Clone, Copy)]
struct FilterDescriptor {
    label: &'static str,
    column: usize,
}

fn filter_spec(tab: SystemInfoTab) -> &'static [FilterDescriptor] {
    match tab {
        SystemInfoTab::Processes => &[
            FilterDescriptor {
                label: "用户",
                column: 3,
            },
            FilterDescriptor {
                label: "状态",
                column: 4,
            },
        ],
        SystemInfoTab::Network => &[FilterDescriptor {
            label: "状态",
            column: 3,
        }],
        SystemInfoTab::Services => &[FilterDescriptor {
            label: "状态",
            column: 1,
        }],
        SystemInfoTab::Users => &[FilterDescriptor {
            label: "Shell",
            column: 4,
        }],
        SystemInfoTab::LoginHistory => &[FilterDescriptor {
            label: "状态",
            column: 4,
        }],
        SystemInfoTab::Docker | SystemInfoTab::Kubernetes => &[FilterDescriptor {
            label: "状态",
            column: 3,
        }],
        _ => &[],
    }
}

fn filter_columns(tab: SystemInfoTab) -> Vec<usize> {
    filter_spec(tab)
        .iter()
        .map(|descriptor| descriptor.column)
        .collect()
}

const fn detail_title(tab: SystemInfoTab) -> &'static str {
    match tab {
        SystemInfoTab::Processes => "进程详情",
        SystemInfoTab::Network => "网络连接详情",
        SystemInfoTab::Services => "服务详情",
        SystemInfoTab::Established => "外连详情",
        SystemInfoTab::OpenPorts => "开放端口详情",
        SystemInfoTab::Users => "用户详情",
        SystemInfoTab::Autostart => "自启动详情",
        SystemInfoTab::Cron => "计划任务详情",
        SystemInfoTab::SshKeys => "SSH 密钥详情",
        SystemInfoTab::LoginHistory => "登录记录详情",
        SystemInfoTab::SuidFiles => "SUID 文件详情",
        SystemInfoTab::Autoruns => "启动项详情",
        SystemInfoTab::Firewall => "防火墙规则详情",
        SystemInfoTab::EnvVars => "环境变量详情",
        SystemInfoTab::ShellConfigs => "Shell 配置详情",
        SystemInfoTab::Packages => "软件包详情",
        SystemInfoTab::Sudoers => "Sudoers 详情",
        SystemInfoTab::Timers => "定时器详情",
        SystemInfoTab::KernelModules => "内核模块详情",
        SystemInfoTab::Rootcheck => "Rootkit 检查详情",
        SystemInfoTab::Sensitive => "敏感文件详情",
        SystemInfoTab::RecentFiles => "最近文件详情",
        SystemInfoTab::Docker => "Docker 容器详情",
        SystemInfoTab::Kubernetes => "Kubernetes 工作负载详情",
        SystemInfoTab::WebApps => "Web 应用详情",
    }
}

fn risk_color(risk: SystemInfoRisk, tokens: ThemeTokens) -> gpui::Rgba {
    match risk {
        SystemInfoRisk::Normal => tokens.success,
        SystemInfoRisk::Warning => tokens.warning,
        SystemInfoRisk::High => tokens.danger,
    }
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

fn format_duration(seconds: u64) -> String {
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;
    format!("{days}d {hours}h {minutes}m")
}

#[cfg(test)]
mod tests {
    use lovelyres_core::target::TargetIdentity;

    use super::*;

    fn binding(identity: &str, generation: u64) -> SystemInfoBinding {
        SystemInfoBinding {
            connection_id: identity.to_owned(),
            session_id: format!("session-{identity}-{generation}"),
            target: TargetGuard {
                identity: TargetIdentity::new(identity).unwrap(),
                generation,
            },
        }
    }

    fn table(tab: SystemInfoTab, text: &str) -> SystemInfoTable {
        SystemInfoTable {
            tab,
            columns: tab
                .columns()
                .iter()
                .map(|column| (*column).to_owned())
                .collect(),
            rows: vec![SystemInfoRow {
                id: "row-1".to_owned(),
                cells: vec![text.to_owned(); tab.columns().len()],
                risk: SystemInfoRisk::Normal,
            }],
            truncated: false,
        }
    }

    #[test]
    fn navigation_exposes_all_twenty_five_legacy_read_only_tabs() {
        assert_eq!(SystemInfoTab::ALL.len(), 25);
        for group in SystemInfoGroup::ALL {
            assert!(SystemInfoTab::ALL.iter().any(|tab| tab.group() == group));
        }
    }

    #[test]
    fn overview_exposes_common_system_identity_resource_and_security_fields() {
        let summary = SystemInfoSummary {
            hostname: "incident-host".to_owned(),
            architecture: "x86_64".to_owned(),
            virtualization: "kvm".to_owned(),
            timezone: "Asia/Taipei".to_owned(),
            root_filesystem: "xfs".to_owned(),
            primary_ip: "10.0.0.2".to_owned(),
            selinux: "Enforcing".to_owned(),
            ..SystemInfoSummary::default()
        };
        let fields = overview_fields(&summary);

        for (label, expected) in [
            ("主机名", "incident-host"),
            ("架构", "x86_64"),
            ("虚拟化", "kvm"),
            ("时区", "Asia/Taipei"),
            ("根文件系统", "xfs"),
            ("主 IP", "10.0.0.2"),
            ("SELinux", "Enforcing"),
        ] {
            assert_eq!(
                fields
                    .iter()
                    .find(|(field, _)| *field == label)
                    .map(|(_, value)| value.as_str()),
                Some(expected),
                "missing overview field {label}"
            );
        }
        assert_eq!(
            fields
                .iter()
                .find(|(field, _)| *field == "AppArmor")
                .map(|(_, value)| value.as_str()),
            Some("未检测到")
        );
    }

    #[test]
    fn row_context_menu_identity_and_labels_are_stable_and_utf8_safe() {
        assert_eq!(primary_context_column(SystemInfoTab::Processes), 1);
        assert_eq!(primary_context_column(SystemInfoTab::Network), 2);
        assert_eq!(primary_context_column(SystemInfoTab::Established), 1);
        assert_eq!(primary_context_column(SystemInfoTab::Docker), 1);
        assert_eq!(primary_context_column(SystemInfoTab::Services), 0);

        for tab in SystemInfoTab::ALL {
            assert!(!context_detail_label(tab).trim().is_empty());
        }
        assert_eq!(context_label("   "), "当前记录");
        let bounded = context_label(&"界".repeat(80));
        assert_eq!(bounded.chars().count(), 49);
        assert!(bounded.ends_with('…'));

        let process_columns = SystemInfoTab::Processes.columns().len();
        assert!(!is_flexible_table_column(0, process_columns));
        assert!(is_flexible_table_column(
            process_columns - 1,
            process_columns
        ));
    }

    #[test]
    fn row_context_menu_uses_the_flat_native_surface_without_component_shadow() {
        let source = include_str!("system_info.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source precedes tests");
        assert!(!production.contains(".context_menu("));
        let start = production
            .find("fn render_row_context_menu")
            .expect("native row context menu renderer");
        let end = production[start..]
            .find("fn export_filtered")
            .map(|offset| start + offset)
            .expect("context menu renderer boundary");
        let menu = &production[start..end];
        assert!(menu.contains("system-info-row-context-menu"));
        assert!(!menu.contains("shadow_"));
    }

    #[test]
    fn process_context_menu_danger_actions_have_neutral_hover_gutters() {
        let source = include_str!("system_info.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source precedes tests");
        let start = production
            .find(".id(\"system-info-process-danger-actions\")")
            .expect("process danger action group");
        let end = production[start..]
            .find(".when(is_service_runtime_tab")
            .map(|offset| start + offset)
            .expect("process danger action group boundary");
        let danger_group = &production[start..end];

        assert!(danger_group.contains(".gap_1()"));
        assert!(danger_group.contains(".py_1()"));
        assert!(!danger_group.contains(".on_hover("));
        assert!(!danger_group.contains("cx.notify()"));
    }

    #[test]
    fn target_and_page_generation_reject_late_results() {
        let first = binding("connection-a", 1);
        let second = binding("connection-b", 2);
        let mut model = SystemInfoModel::default();
        model.activate(Some(first.clone()));
        let lease = model
            .begin_request(RequestKind::Table(SystemInfoTab::Processes), Some(first))
            .unwrap();
        model.rebind(Some(second.clone()));
        assert!(!model.apply_table(
            &lease,
            Some(&second),
            table(SystemInfoTab::Processes, "late")
        ));

        let current = model
            .begin_request(
                RequestKind::Table(SystemInfoTab::Processes),
                Some(second.clone()),
            )
            .unwrap();
        model.deactivate();
        assert!(!model.apply_table(
            &current,
            Some(&second),
            table(SystemInfoTab::Processes, "late after deactivate")
        ));
    }

    #[test]
    fn hostile_remote_strings_remain_plain_text_and_filterable() {
        let attack = "<img src=x onerror=alert(1)><script>bad()</script>";
        let current = binding("connection-a", 1);
        let mut model = SystemInfoModel::default();
        model.activate(Some(current.clone()));
        model.switch_tab(SystemInfoTab::Users);
        let lease = model
            .begin_request(
                RequestKind::Table(SystemInfoTab::Users),
                Some(current.clone()),
            )
            .unwrap();
        assert!(model.apply_table(&lease, Some(&current), table(SystemInfoTab::Users, attack)));
        model.set_query("<script>".to_owned());
        assert_eq!(model.filtered_rows()[0].cells[0], attack);
        let source = include_str!("system_info.rs").to_lowercase();
        assert!(!source.contains(&["inner", "_html"].concat()));
        assert!(!source.contains(&["render", "_markdown"].concat()));
    }

    #[test]
    fn filters_and_clipboard_intents_are_deterministic() {
        let mut table = table(SystemInfoTab::Services, "active");
        table.rows.push(SystemInfoRow {
            id: "row-2".to_owned(),
            cells: vec!["failed".to_owned(); table.columns.len()],
            risk: SystemInfoRisk::Warning,
        });
        let current = binding("connection-a", 1);
        let mut model = SystemInfoModel::default();
        model.activate(Some(current.clone()));
        model.switch_tab(SystemInfoTab::Services);
        let lease = model
            .begin_request(
                RequestKind::Table(SystemInfoTab::Services),
                Some(current.clone()),
            )
            .unwrap();
        assert!(model.apply_table(&lease, Some(&current), table));
        assert_eq!(model.facet_options(0), ["active", "failed"]);
        assert!(model.set_facet(0, Some("failed".to_owned())));
        assert!(!model.set_facet(0, Some("missing".to_owned())));
        model.set_risk_filter(Some(SystemInfoRisk::Warning));
        let rows = model.filtered_rows();
        assert_eq!(rows.len(), 1);
        let intent = SystemInfoClipboardIntent::from_rows(model.active_table().unwrap(), &rows);
        assert_eq!(intent.row_count, 1);
        assert!(intent.text.starts_with("服务名\t状态\t启用状态\t描述\n"));
        assert!(intent.text.contains("failed"));
    }

    #[test]
    fn detail_result_requires_exact_row_target_and_page_lease() {
        let current = binding("connection-a", 1);
        let mut model = SystemInfoModel::default();
        model.activate(Some(current.clone()));
        let lease = model
            .begin_request(
                RequestKind::Table(SystemInfoTab::Processes),
                Some(current.clone()),
            )
            .unwrap();
        let mut process_table = SystemInfoTable {
            tab: SystemInfoTab::Processes,
            columns: SystemInfoTab::Processes
                .columns()
                .iter()
                .map(|column| (*column).to_owned())
                .collect(),
            rows: Vec::new(),
            truncated: false,
        };
        for (id, pid) in [("process-a", "123"), ("process-b", "456")] {
            process_table.rows.push(SystemInfoRow {
                id: id.to_owned(),
                cells: vec![
                    "normal".to_owned(),
                    pid.to_owned(),
                    "1".to_owned(),
                    "root".to_owned(),
                    "S".to_owned(),
                    "0".to_owned(),
                    "0".to_owned(),
                    "1".to_owned(),
                    "/bin/sh".to_owned(),
                ],
                risk: SystemInfoRisk::Normal,
            });
        }
        assert!(model.apply_table(&lease, Some(&current), process_table));
        assert!(model.select_row("process-a"));
        let (detail_lease, _) = model
            .begin_detail_request(Some(current.clone()))
            .unwrap()
            .unwrap();
        assert!(model.select_row("process-b"));
        let late = SystemInfoDetail {
            tab: SystemInfoTab::Processes,
            row_id: "process-a".to_owned(),
            fields: Vec::new(),
        };
        assert!(!model.apply_detail(&detail_lease, Some(&current), late));

        let (current_lease, _) = model
            .begin_detail_request(Some(current.clone()))
            .unwrap()
            .unwrap();
        let other_target = binding("connection-b", 2);
        let wrong_target = SystemInfoDetail {
            tab: SystemInfoTab::Processes,
            row_id: "process-b".to_owned(),
            fields: Vec::new(),
        };
        assert!(!model.apply_detail(&current_lease, Some(&other_target), wrong_target));
        model.deactivate();
        let after_deactivate = SystemInfoDetail {
            tab: SystemInfoTab::Processes,
            row_id: "process-b".to_owned(),
            fields: Vec::new(),
        };
        assert!(!model.apply_detail(&current_lease, Some(&current), after_deactivate));
    }

    #[test]
    fn stable_selection_survives_refresh_insertion_and_sort_change() {
        let current = binding("connection-a", 1);
        let mut model = SystemInfoModel::default();
        model.activate(Some(current.clone()));
        model.switch_tab(SystemInfoTab::Users);
        let first_lease = model
            .begin_request(
                RequestKind::Table(SystemInfoTab::Users),
                Some(current.clone()),
            )
            .unwrap();
        let mut first = table(SystemInfoTab::Users, "alice");
        first.rows[0].id = "users-stable-alice-0".to_owned();
        assert!(model.apply_table(&first_lease, Some(&current), first));
        assert!(model.select_row("users-stable-alice-0"));

        let refresh_lease = model
            .begin_request(
                RequestKind::Table(SystemInfoTab::Users),
                Some(current.clone()),
            )
            .unwrap();
        let mut refreshed = table(SystemInfoTab::Users, "mallory");
        refreshed.rows[0].id = "users-new-mallory-0".to_owned();
        refreshed.rows.push(SystemInfoRow {
            id: "users-stable-alice-0".to_owned(),
            cells: vec!["alice".to_owned(); SystemInfoTab::Users.columns().len()],
            risk: SystemInfoRisk::Normal,
        });
        assert!(model.apply_table(&refresh_lease, Some(&current), refreshed));
        assert_eq!(
            model.selected_row().map(|row| row.id.as_str()),
            Some("users-stable-alice-0")
        );
    }

    #[test]
    fn thousand_rows_use_cached_filter_indices() {
        let current = binding("connection-a", 1);
        let mut model = SystemInfoModel::default();
        model.activate(Some(current.clone()));
        model.switch_tab(SystemInfoTab::Services);
        let lease = model
            .begin_request(
                RequestKind::Table(SystemInfoTab::Services),
                Some(current.clone()),
            )
            .unwrap();
        let rows = (0..1_000)
            .map(|index| SystemInfoRow {
                id: format!("service-{index}"),
                cells: vec![
                    if index == 999 {
                        "needle.service".to_owned()
                    } else {
                        format!("service-{index}.service")
                    },
                    "active".to_owned(),
                    "enabled".to_owned(),
                    "description".to_owned(),
                ],
                risk: SystemInfoRisk::Normal,
            })
            .collect();
        assert!(
            model.apply_table(
                &lease,
                Some(&current),
                SystemInfoTable {
                    tab: SystemInfoTab::Services,
                    columns: SystemInfoTab::Services
                        .columns()
                        .iter()
                        .map(|column| (*column).to_owned())
                        .collect(),
                    rows,
                    truncated: false,
                }
            )
        );
        assert_eq!(model.filtered_row_count(), 1_000);
        model.set_query("needle".to_owned());
        let rows = model.filtered_rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].cells[0], "needle.service");
    }

    #[test]
    fn table_result_hint_does_not_repeat_the_title_total() {
        assert_eq!(table_result_hint(407), "点击行查看详情");
        assert!(!table_result_hint(407).contains("407"));
        assert_eq!(table_result_hint(0), "筛选结果为空");
    }

    #[test]
    fn process_interaction_lease_rejects_row_target_tab_and_lifecycle_changes() {
        let current = binding("connection-a", 1);
        let mut model = SystemInfoModel::default();
        let activation_generation = model.activate(Some(current.clone()));
        let lease = model
            .begin_request(
                RequestKind::Table(SystemInfoTab::Processes),
                Some(current.clone()),
            )
            .unwrap();
        let mut processes = table(SystemInfoTab::Processes, "value");
        processes.rows[0].id = "process-a".to_owned();
        processes.rows.push(SystemInfoRow {
            id: "process-b".to_owned(),
            cells: vec!["value".to_owned(); SystemInfoTab::Processes.columns().len()],
            risk: SystemInfoRisk::Normal,
        });
        assert!(model.apply_table(&lease, Some(&current), processes));
        assert!(model.select_row("process-a"));
        let interaction = ProcessInteractionLease {
            activation_generation,
            request_id: 7,
            binding: current.clone(),
            row_id: "process-a".to_owned(),
        };
        assert!(process_lease_is_current(&model, &interaction));

        assert!(model.select_row("process-b"));
        assert!(!process_lease_is_current(&model, &interaction));
        assert!(model.select_row("process-a"));
        model.switch_tab(SystemInfoTab::Users);
        assert!(!process_lease_is_current(&model, &interaction));
        model.switch_tab(SystemInfoTab::Processes);
        model.rebind(Some(binding("connection-b", 2)));
        assert!(!process_lease_is_current(&model, &interaction));
        model.deactivate();
        assert!(!process_lease_is_current(&model, &interaction));
    }

    #[test]
    fn process_menu_uses_typed_core_actions_and_journaled_signal_workflow() {
        let source = include_str!("system_info.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source precedes tests");
        for required in [
            "ProcessInvestigationAction::ALL",
            "process_investigation_request",
            "investigate_process",
            "process_signal_request",
            "plan_process_signal",
            "DangerousConfirmation::approve",
            "execute_process_signal",
            "operation_journal",
            "verification.passed",
        ] {
            assert!(production.contains(required), "missing {required}");
        }
        assert!(!production.contains("ssh_execute_command_direct"));
        assert!(!production.contains("kill -9"));
        assert!(!production.contains("kill ${"));
    }

    #[test]
    fn service_interaction_lease_rejects_row_target_tab_and_lifecycle_changes() {
        let current = binding("connection-a", 1);
        let mut model = SystemInfoModel::default();
        let activation_generation = model.activate(Some(current.clone()));
        model.switch_tab(SystemInfoTab::Services);
        let lease = model
            .begin_request(
                RequestKind::Table(SystemInfoTab::Services),
                Some(current.clone()),
            )
            .unwrap();
        let mut services = table(SystemInfoTab::Services, "value");
        services.rows[0].id = "service-a".to_owned();
        services.rows.push(SystemInfoRow {
            id: "service-b".to_owned(),
            cells: vec!["value".to_owned(); SystemInfoTab::Services.columns().len()],
            risk: SystemInfoRisk::Normal,
        });
        assert!(model.apply_table(&lease, Some(&current), services));
        assert!(model.select_row("service-a"));
        let interaction = ServiceInteractionLease {
            activation_generation,
            request_id: 9,
            binding: current.clone(),
            tab: SystemInfoTab::Services,
            row_id: "service-a".to_owned(),
        };
        assert!(service_lease_is_current(&model, &interaction));

        assert!(model.select_row("service-b"));
        assert!(!service_lease_is_current(&model, &interaction));
        assert!(model.select_row("service-a"));
        model.switch_tab(SystemInfoTab::Processes);
        assert!(!service_lease_is_current(&model, &interaction));
        model.switch_tab(SystemInfoTab::Services);
        model.rebind(Some(binding("connection-b", 2)));
        assert!(!service_lease_is_current(&model, &interaction));
        model.deactivate();
        assert!(!service_lease_is_current(&model, &interaction));
    }

    #[test]
    fn service_menu_uses_typed_core_actions_and_journaled_runtime_workflow() {
        let source = include_str!("system_info.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source precedes tests");
        for required in [
            "ServiceInvestigationAction::ALL",
            "service_investigation_request",
            "investigate_service",
            "ServiceRuntimeAction::ALL",
            "service_runtime_request",
            "plan_service_runtime",
            "DangerousConfirmation::approve",
            "execute_service_runtime",
            "operation_journal",
            "verification.passed",
        ] {
            assert!(production.contains(required), "missing {required}");
        }
        assert!(!production.contains("ssh_execute_command_direct"));
        assert!(!production.contains("systemctl ${"));
        assert!(!production.contains("systemctl stop"));
    }

    #[test]
    fn account_interaction_lease_rejects_row_target_tab_and_lifecycle_changes() {
        let current = binding("connection-a", 1);
        let mut model = SystemInfoModel::default();
        let activation_generation = model.activate(Some(current.clone()));
        model.switch_tab(SystemInfoTab::Users);
        let lease = model
            .begin_request(
                RequestKind::Table(SystemInfoTab::Users),
                Some(current.clone()),
            )
            .unwrap();
        let users = SystemInfoTable {
            tab: SystemInfoTab::Users,
            columns: SystemInfoTab::Users
                .columns()
                .iter()
                .map(|column| (*column).to_owned())
                .collect(),
            rows: ["user-a", "user-b"]
                .into_iter()
                .map(|id| SystemInfoRow {
                    id: id.to_owned(),
                    cells: vec![
                        "alice".to_owned(),
                        "1000".to_owned(),
                        "1000".to_owned(),
                        "/home/alice".to_owned(),
                        "/bin/bash".to_owned(),
                    ],
                    risk: SystemInfoRisk::Normal,
                })
                .collect(),
            truncated: false,
        };
        assert!(model.apply_table(&lease, Some(&current), users));
        assert!(model.select_row("user-a"));
        let interaction = AccountInteractionLease {
            activation_generation,
            request_id: 13,
            binding: current.clone(),
            tab: SystemInfoTab::Users,
            row_id: "user-a".to_owned(),
        };
        assert!(account_lease_is_current(&model, &interaction));

        assert!(model.select_row("user-b"));
        assert!(!account_lease_is_current(&model, &interaction));
        assert!(model.select_row("user-a"));
        model.switch_tab(SystemInfoTab::LoginHistory);
        assert!(!account_lease_is_current(&model, &interaction));
        model.switch_tab(SystemInfoTab::Users);
        model.rebind(Some(binding("connection-b", 2)));
        assert!(!account_lease_is_current(&model, &interaction));
        model.deactivate();
        assert!(!account_lease_is_current(&model, &interaction));
    }

    #[test]
    fn user_and_login_menus_use_typed_core_and_journaled_account_workflow() {
        let source = include_str!("system_info.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source precedes tests");
        for required in [
            "UserInvestigationAction::ALL",
            "user_investigation_request",
            "investigate_user",
            "LoginInvestigationAction::ALL",
            "login_investigation_request",
            "investigate_login",
            "user_account_request",
            "plan_user_account",
            "DangerousConfirmation::approve",
            "execute_user_account",
            "prepare_login_firewall",
            "FirewallMutationRequest::block_ipv4",
            "execute_mutation",
            "execute_resolution",
            "NetworkFirewallIntent::KeepBlock",
            "operation_journal",
            "verification.passed",
            "copy_login_source",
        ] {
            assert!(production.contains(required), "missing {required}");
        }
        for forbidden in [
            "ssh_execute_command_direct",
            "userdel -rf",
            "pkill -9 -u",
            "DenyUsers ",
            "passwd -l ${",
        ] {
            assert!(!production.contains(forbidden), "found {forbidden}");
        }
    }

    #[test]
    fn login_firewall_lease_rejects_row_target_tab_and_lifecycle_changes() {
        let current = binding("connection-a", 1);
        let mut model = SystemInfoModel::default();
        let activation_generation = model.activate(Some(current.clone()));
        model.switch_tab(SystemInfoTab::LoginHistory);
        let lease = model
            .begin_request(
                RequestKind::Table(SystemInfoTab::LoginHistory),
                Some(current.clone()),
            )
            .unwrap();
        let logins = SystemInfoTable {
            tab: SystemInfoTab::LoginHistory,
            columns: SystemInfoTab::LoginHistory
                .columns()
                .iter()
                .map(|column| (*column).to_owned())
                .collect(),
            rows: ["login-a", "login-b"]
                .into_iter()
                .map(|id| SystemInfoRow {
                    id: id.to_owned(),
                    cells: vec![
                        "alice".to_owned(),
                        "pts/0".to_owned(),
                        "203.0.113.8".to_owned(),
                        "2026-08-12T00:00:00Z".to_owned(),
                        "active".to_owned(),
                    ],
                    risk: SystemInfoRisk::Normal,
                })
                .collect(),
            truncated: false,
        };
        assert!(model.apply_table(&lease, Some(&current), logins));
        assert!(model.select_row("login-a"));
        let interaction = FirewallInteractionLease::LoginHistory(AccountInteractionLease {
            activation_generation,
            request_id: 21,
            binding: current.clone(),
            tab: SystemInfoTab::LoginHistory,
            row_id: "login-a".to_owned(),
        });
        assert!(firewall_lease_is_current(&model, &interaction));

        assert!(model.select_row("login-b"));
        assert!(!firewall_lease_is_current(&model, &interaction));
        assert!(model.select_row("login-a"));
        model.switch_tab(SystemInfoTab::Network);
        assert!(!firewall_lease_is_current(&model, &interaction));
        model.switch_tab(SystemInfoTab::LoginHistory);
        model.rebind(Some(binding("connection-b", 2)));
        assert!(!firewall_lease_is_current(&model, &interaction));
        model.deactivate();
        assert!(!firewall_lease_is_current(&model, &interaction));
    }

    #[test]
    fn artifact_interaction_lease_rejects_row_target_tab_and_lifecycle_changes() {
        let current = binding("connection-a", 1);
        let mut model = SystemInfoModel::default();
        let activation_generation = model.activate(Some(current.clone()));
        model.switch_tab(SystemInfoTab::Packages);
        let lease = model
            .begin_request(
                RequestKind::Table(SystemInfoTab::Packages),
                Some(current.clone()),
            )
            .unwrap();
        let packages = SystemInfoTable {
            tab: SystemInfoTab::Packages,
            columns: SystemInfoTab::Packages
                .columns()
                .iter()
                .map(|column| (*column).to_owned())
                .collect(),
            rows: ["package-a", "package-b"]
                .into_iter()
                .map(|id| SystemInfoRow {
                    id: id.to_owned(),
                    cells: vec![
                        "openssl".to_owned(),
                        "3.0".to_owned(),
                        "2026-08-12".to_owned(),
                        "dpkg".to_owned(),
                    ],
                    risk: SystemInfoRisk::Normal,
                })
                .collect(),
            truncated: false,
        };
        assert!(model.apply_table(&lease, Some(&current), packages));
        assert!(model.select_row("package-a"));
        let interaction = ArtifactInteractionLease {
            activation_generation,
            request_id: 23,
            binding: current.clone(),
            tab: SystemInfoTab::Packages,
            row_id: "package-a".to_owned(),
        };
        assert!(artifact_lease_is_current(&model, &interaction));

        assert!(model.select_row("package-b"));
        assert!(!artifact_lease_is_current(&model, &interaction));
        assert!(model.select_row("package-a"));
        model.switch_tab(SystemInfoTab::KernelModules);
        assert!(!artifact_lease_is_current(&model, &interaction));
        model.switch_tab(SystemInfoTab::Packages);
        model.rebind(Some(binding("connection-b", 2)));
        assert!(!artifact_lease_is_current(&model, &interaction));
        model.deactivate();
        assert!(!artifact_lease_is_current(&model, &interaction));
    }

    #[test]
    fn artifact_menus_use_typed_core_workflows_without_raw_shell_surface() {
        let source = include_str!("system_info.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source precedes tests");
        for required in [
            "PackageInvestigationAction::ALL",
            "KernelModuleInvestigationAction::ALL",
            "EnvVarInvestigationAction::ALL",
            "StartupInvestigationAction::ALL",
            "CronInvestigationAction::ALL",
            "TimerInvestigationAction::ALL",
            "ShellConfigInvestigationAction::ALL",
            "SudoersInvestigationAction::ALL",
            "SuidFileInvestigationAction::ALL",
            "SshKeyInvestigationAction::ALL",
            "artifact_investigation_request",
            "investigate_artifact",
            "ArtifactMutationAction::DeleteCronFile",
            "ArtifactMutationAction::CommentShellLine",
            "ArtifactMutationAction::RemoveSuidBits",
            "ArtifactMutationAction::QuarantineSuidFile",
            "ArtifactMutationAction::AddManagedModuleBlacklist",
            "ArtifactMutationAction::RemoveManagedModuleBlacklist",
            "artifact_mutation_request",
            "plan_artifact_mutation",
            "execute_artifact_mutation",
            "DangerousConfirmation::approve",
            "operation_journal",
            "ArtifactInteractionLease",
            "copy_environment_value",
        ] {
            assert!(production.contains(required), "missing {required}");
        }
        for forbidden in [
            "ssh_execute_command_direct",
            "apt-mark hold",
            "rmmod ${",
            ">> /etc/modprobe.d",
            "su - $user",
        ] {
            assert!(!production.contains(forbidden), "found {forbidden}");
        }
    }

    #[test]
    fn persistence_artifact_menus_expose_the_closed_core_catalogs() {
        let expected = [
            (SystemInfoTab::Autostart, 18),
            (SystemInfoTab::Cron, 15),
            (SystemInfoTab::Timers, 6),
            (SystemInfoTab::ShellConfigs, 6),
            (SystemInfoTab::Sudoers, 8),
            (SystemInfoTab::SuidFiles, 8),
            (SystemInfoTab::SshKeys, 7),
        ];
        for (tab, count) in expected {
            let actions = artifact_actions(tab);
            assert_eq!(actions.len(), count, "{tab:?}");
            assert!(actions.into_iter().all(|action| action.tab() == tab));
            assert!(is_artifact_tab(tab));
        }
    }

    #[test]
    fn network_interaction_lease_rejects_row_target_tab_and_lifecycle_changes() {
        let current = binding("connection-a", 1);
        let mut model = SystemInfoModel::default();
        let activation_generation = model.activate(Some(current.clone()));
        model.switch_tab(SystemInfoTab::Network);
        let lease = model
            .begin_request(
                RequestKind::Table(SystemInfoTab::Network),
                Some(current.clone()),
            )
            .unwrap();
        let network = SystemInfoTable {
            tab: SystemInfoTab::Network,
            columns: SystemInfoTab::Network
                .columns()
                .iter()
                .map(|column| (*column).to_owned())
                .collect(),
            rows: ["network-a", "network-b"]
                .into_iter()
                .map(|id| SystemInfoRow {
                    id: id.to_owned(),
                    cells: vec![
                        "tcp".to_owned(),
                        "10.0.0.1:50000".to_owned(),
                        "203.0.113.8:443".to_owned(),
                        "ESTAB".to_owned(),
                        "123".to_owned(),
                        "sshd".to_owned(),
                    ],
                    risk: SystemInfoRisk::Normal,
                })
                .collect(),
            truncated: false,
        };
        assert!(model.apply_table(&lease, Some(&current), network));
        assert!(model.select_row("network-a"));
        let interaction = NetworkInteractionLease {
            activation_generation,
            request_id: 11,
            binding: current.clone(),
            tab: SystemInfoTab::Network,
            row_id: "network-a".to_owned(),
        };
        assert!(network_lease_is_current(&model, &interaction));

        assert!(model.select_row("network-b"));
        assert!(!network_lease_is_current(&model, &interaction));
        assert!(model.select_row("network-a"));
        model.switch_tab(SystemInfoTab::Established);
        assert!(!network_lease_is_current(&model, &interaction));
        model.switch_tab(SystemInfoTab::Network);
        model.rebind(Some(binding("connection-b", 2)));
        assert!(!network_lease_is_current(&model, &interaction));
        model.deactivate();
        assert!(!network_lease_is_current(&model, &interaction));
    }

    #[test]
    fn network_menu_uses_typed_core_actions_and_journaled_disconnect_workflow() {
        let source = include_str!("system_info.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source precedes tests");
        for required in [
            "NetworkInvestigationAction::ALL",
            "network_investigation_request",
            "investigate_network",
            "network_disconnect_request",
            "plan_network_disconnect",
            "DangerousConfirmation::approve",
            "execute_network_disconnect",
            "operation_journal",
            "verification.passed",
            "NetworkCopyField::LocalEndpoint",
            "NetworkCopyField::RemoteEndpoint",
            "NetworkCopyField::Process",
            "FirewallMutationRequest::block_ipv4",
            "FirewallMutationRequest::temporary_block_ipv4",
            "plan_restore_ipv4_block",
            "execute_mutation",
            "execute_resolution",
            "NetworkFirewallIntent::KeepBlock",
        ] {
            assert!(production.contains(required), "missing {required}");
        }
        for forbidden in ["ssh_execute_command_direct", "ss -K src", "iptables -A"] {
            assert!(!production.contains(forbidden), "found {forbidden}");
        }
    }
}
