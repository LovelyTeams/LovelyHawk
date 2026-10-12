//! Acting on a row the system-information page already showed.
//!
//! The page holds a snapshot handle and row ids the sidecar minted. When the
//! operator right-clicks a row it asks which actions apply, and the answer is
//! computed here from the snapshot the sidecar kept — a row the renderer made
//! up names nothing, and a tab that has no actions offers none.
//!
//! Every action is one the core already knows how to carry out. Read-only
//! ones ("排查") run a bounded command and hand the output back. The ones that
//! change the host ("处置") go through the core's plan, confirm, execute,
//! journal and verify pipeline, with the same handle-per-plan rule the Docker
//! and Kubernetes panes use: a plan is described before it runs, approval and
//! execution are separate calls, and a plan leaves the registry as it is
//! taken so it can never run twice.

use std::{
    collections::HashMap,
    fmt,
    time::{Duration, Instant},
};

use lovelyhawk_core::{
    CoreError, CoreResult,
    operations::{DangerousConfirmation, OperationPlan, VerificationResult},
    system_info::{
        ArtifactInvestigationAction, ArtifactMutationAction, ArtifactMutationPlan,
        BootScriptRuntimePlan, COMMAND_TIMEOUT_MARKER, CronInvestigationAction,
        EnvVarInvestigationAction, KernelModuleInvestigationAction, LoginInvestigationAction,
        NetworkDisconnectPlan, NetworkInvestigationAction, PackageInvestigationAction,
        ProcessInvestigationAction, ProcessSignal, ProcessSignalPlan, RuntimeChangeRequest,
        ServiceInvestigationAction, ServiceRuntimeAction, ServiceRuntimePlan,
        ShellConfigInvestigationAction, SshKeyInvestigationAction, StartupInvestigationAction,
        SudoersInvestigationAction, SuidFileInvestigationAction, SystemInfoRow, SystemInfoTab,
        SystemInfoTable, TimerInvestigationAction, UserAccountAction, UserAccountPlan,
        UserInvestigationAction,
    },
    target::TargetGuard,
};
use serde::{Serialize, de::DeserializeOwned};
use tokio::time::timeout;
use uuid::Uuid;

use crate::system_info_api::{SystemInfoApi, SystemInfoApiError, tab_key};

const MAX_PLANS: usize = 16;
const MAX_ACTION_KEY_BYTES: usize = 64;
const MAX_SUBJECT_BYTES: usize = 256;
const MAX_PLAN_TEXT_BYTES: usize = 2_048;
/// Long enough to read what the plan says and decide; short enough that an
/// abandoned dialog cannot be executed from later.
const PLAN_TTL: Duration = Duration::from_secs(5 * 60);
/// The slowest read-only action the core allows itself is thirty seconds.
const INSPECT_DEADLINE: Duration = Duration::from_secs(45);
const PLAN_DEADLINE: Duration = Duration::from_secs(30);
/// Execution covers the change, the journal write, the verification read and
/// a restore if verification failed.
const EXECUTE_DEADLINE: Duration = Duration::from_secs(120);

/// One thing the operator may ask of one row: a closed set, addressed by a
/// fixed key such as `process.open-files` or `process.signal.kill`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RowAction {
    ProcessInspect(ProcessInvestigationAction),
    ProcessSignal(ProcessSignal),
    ServiceInspect(ServiceInvestigationAction),
    ServiceRuntime(ServiceRuntimeAction),
    UserInspect(UserInvestigationAction),
    UserAccount(UserAccountAction),
    LoginInspect(LoginInvestigationAction),
    NetworkInspect(NetworkInvestigationAction),
    NetworkDisconnect,
    ArtifactInspect(ArtifactInvestigationAction),
    ArtifactMutation(ArtifactMutationAction),
}

impl RowAction {
    /// The key the renderer addresses this action by. Stable, kebab-case, and
    /// namespaced by the family of row it applies to.
    pub(crate) fn key(self) -> String {
        match self {
            Self::ProcessInspect(action) => format!("process.{}", kebab(action)),
            Self::ProcessSignal(signal) => format!("process.signal.{}", kebab(signal)),
            Self::ServiceInspect(action) => format!("service.{}", kebab(action)),
            Self::ServiceRuntime(action) => format!("service.runtime.{}", kebab(action)),
            Self::UserInspect(action) => format!("user.{}", kebab(action)),
            Self::UserAccount(action) => format!("account.{}", kebab(action)),
            Self::LoginInspect(action) => format!("login.{}", kebab(action)),
            Self::NetworkInspect(action) => format!("network.{}", kebab(action)),
            Self::NetworkDisconnect => "network.disconnect".to_owned(),
            Self::ArtifactInspect(action) => match action {
                ArtifactInvestigationAction::Package(inner) => format!("package.{}", kebab(inner)),
                ArtifactInvestigationAction::KernelModule(inner) => {
                    format!("module.{}", kebab(inner))
                }
                ArtifactInvestigationAction::Environment(inner) => format!("env.{}", kebab(inner)),
                ArtifactInvestigationAction::Startup(inner) => format!("startup.{}", kebab(inner)),
                ArtifactInvestigationAction::Cron(inner) => format!("cron.{}", kebab(inner)),
                ArtifactInvestigationAction::Timer(inner) => format!("timer.{}", kebab(inner)),
                ArtifactInvestigationAction::ShellConfig(inner) => {
                    format!("shell.{}", kebab(inner))
                }
                ArtifactInvestigationAction::Sudoers(inner) => format!("sudoers.{}", kebab(inner)),
                ArtifactInvestigationAction::SuidFile(inner) => format!("suid.{}", kebab(inner)),
                ArtifactInvestigationAction::SshKey(inner) => format!("ssh-key.{}", kebab(inner)),
            },
            Self::ArtifactMutation(action) => match action {
                ArtifactMutationAction::DeleteCronFile => "cron.delete-file",
                ArtifactMutationAction::CommentShellLine => "shell.comment-line",
                ArtifactMutationAction::RemoveSuidBits => "suid.remove-bits",
                ArtifactMutationAction::QuarantineSuidFile => "suid.quarantine",
                ArtifactMutationAction::AddManagedModuleBlacklist => "module.blacklist.add",
                ArtifactMutationAction::RemoveManagedModuleBlacklist => "module.blacklist.remove",
            }
            .to_owned(),
        }
    }

    /// The inverse of [`RowAction::key`]. Anything that is not exactly one of
    /// the keys this module hands out is nothing.
    pub(crate) fn parse(key: &str) -> Option<Self> {
        if key.is_empty() || key.len() > MAX_ACTION_KEY_BYTES {
            return None;
        }
        let (family, rest) = key.split_once('.')?;
        match family {
            "process" => match rest.strip_prefix("signal.") {
                Some(signal) => from_kebab(signal).map(Self::ProcessSignal),
                None => from_kebab(rest).map(Self::ProcessInspect),
            },
            "service" => match rest.strip_prefix("runtime.") {
                Some(action) => from_kebab(action).map(Self::ServiceRuntime),
                None => from_kebab(rest).map(Self::ServiceInspect),
            },
            "user" => from_kebab(rest).map(Self::UserInspect),
            "account" => from_kebab(rest).map(Self::UserAccount),
            "login" => from_kebab(rest).map(Self::LoginInspect),
            "network" => match rest {
                "disconnect" => Some(Self::NetworkDisconnect),
                _ => from_kebab(rest).map(Self::NetworkInspect),
            },
            "package" => from_kebab(rest)
                .map(ArtifactInvestigationAction::Package)
                .map(Self::ArtifactInspect),
            "module" => match rest {
                "blacklist.add" => Some(Self::ArtifactMutation(
                    ArtifactMutationAction::AddManagedModuleBlacklist,
                )),
                "blacklist.remove" => Some(Self::ArtifactMutation(
                    ArtifactMutationAction::RemoveManagedModuleBlacklist,
                )),
                _ => from_kebab(rest)
                    .map(ArtifactInvestigationAction::KernelModule)
                    .map(Self::ArtifactInspect),
            },
            "env" => from_kebab(rest)
                .map(ArtifactInvestigationAction::Environment)
                .map(Self::ArtifactInspect),
            "startup" => from_kebab(rest)
                .map(ArtifactInvestigationAction::Startup)
                .map(Self::ArtifactInspect),
            "cron" => match rest {
                "delete-file" => Some(Self::ArtifactMutation(
                    ArtifactMutationAction::DeleteCronFile,
                )),
                _ => from_kebab(rest)
                    .map(ArtifactInvestigationAction::Cron)
                    .map(Self::ArtifactInspect),
            },
            "timer" => from_kebab(rest)
                .map(ArtifactInvestigationAction::Timer)
                .map(Self::ArtifactInspect),
            "shell" => match rest {
                "comment-line" => Some(Self::ArtifactMutation(
                    ArtifactMutationAction::CommentShellLine,
                )),
                _ => from_kebab(rest)
                    .map(ArtifactInvestigationAction::ShellConfig)
                    .map(Self::ArtifactInspect),
            },
            "sudoers" => from_kebab(rest)
                .map(ArtifactInvestigationAction::Sudoers)
                .map(Self::ArtifactInspect),
            "suid" => match rest {
                "remove-bits" => Some(Self::ArtifactMutation(
                    ArtifactMutationAction::RemoveSuidBits,
                )),
                "quarantine" => Some(Self::ArtifactMutation(
                    ArtifactMutationAction::QuarantineSuidFile,
                )),
                _ => from_kebab(rest)
                    .map(ArtifactInvestigationAction::SuidFile)
                    .map(Self::ArtifactInspect),
            },
            "ssh-key" => from_kebab(rest)
                .map(ArtifactInvestigationAction::SshKey)
                .map(Self::ArtifactInspect),
            _ => None,
        }
    }

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::ProcessInspect(action) => action.label(),
            Self::ProcessSignal(signal) => signal.label(),
            Self::ServiceInspect(action) => action.label(),
            Self::ServiceRuntime(action) => action.label(),
            Self::UserInspect(action) => action.label(),
            Self::UserAccount(action) => action.label(),
            Self::LoginInspect(action) => action.label(),
            Self::NetworkInspect(action) => action.label(),
            Self::NetworkDisconnect => "断开此连接",
            Self::ArtifactInspect(action) => action.label(),
            Self::ArtifactMutation(action) => action.label(),
        }
    }

    /// Whether choosing this only reads, or asks for a plan to change the host.
    pub(crate) const fn changes_host(self) -> bool {
        matches!(
            self,
            Self::ProcessSignal(_)
                | Self::ServiceRuntime(_)
                | Self::UserAccount(_)
                | Self::NetworkDisconnect
                | Self::ArtifactMutation(_)
        )
    }

    /// Whether the menu should show this in the colour that means "this
    /// stops or removes something". A change that only turns something on is
    /// still confirmed through a plan, but is not painted red.
    const fn dangerous(self) -> bool {
        match self {
            Self::ProcessSignal(_) | Self::NetworkDisconnect | Self::ArtifactMutation(_) => true,
            Self::ServiceRuntime(action) => matches!(
                action,
                ServiceRuntimeAction::Stop
                    | ServiceRuntimeAction::Disable
                    | ServiceRuntimeAction::Mask
            ),
            Self::UserAccount(action) => matches!(action, UserAccountAction::Lock),
            _ => false,
        }
    }

    /// Which heading the menu files this under.
    fn group(self) -> (String, &'static str) {
        match self {
            Self::ProcessInspect(action) => (kebab(action.group()), action.group().label()),
            Self::ServiceInspect(action) => (kebab(action.group()), action.group().label()),
            Self::UserInspect(action) => (kebab(action.group()), action.group().label()),
            Self::LoginInspect(action) => (kebab(action.group()), action.group().label()),
            Self::NetworkInspect(action) => (kebab(action.group()), action.group().label()),
            Self::ArtifactInspect(_) => ("inspect".to_owned(), "排查"),
            Self::ProcessSignal(_)
            | Self::ServiceRuntime(_)
            | Self::UserAccount(_)
            | Self::NetworkDisconnect
            | Self::ArtifactMutation(_) => ("change".to_owned(), "处置"),
        }
    }

    /// Every action a tab could offer, in menu order. Which of them a given
    /// row actually gets is decided by [`applies`].
    pub(crate) fn candidates(tab: SystemInfoTab) -> Vec<Self> {
        let mut actions = Vec::new();
        match tab {
            SystemInfoTab::Processes => {
                actions.extend(ProcessInvestigationAction::ALL.map(Self::ProcessInspect));
                actions.extend(
                    [ProcessSignal::Terminate, ProcessSignal::Kill].map(Self::ProcessSignal),
                );
            }
            SystemInfoTab::Services => {
                actions.extend(ServiceInvestigationAction::ALL.map(Self::ServiceInspect));
                actions.extend(ServiceRuntimeAction::ALL.map(Self::ServiceRuntime));
            }
            SystemInfoTab::Autostart => {
                actions.extend(
                    StartupInvestigationAction::ALL
                        .map(ArtifactInvestigationAction::Startup)
                        .map(Self::ArtifactInspect),
                );
                actions.extend(ServiceRuntimeAction::AUTOSTART.map(Self::ServiceRuntime));
            }
            SystemInfoTab::Timers => {
                actions.extend(
                    TimerInvestigationAction::ALL
                        .map(ArtifactInvestigationAction::Timer)
                        .map(Self::ArtifactInspect),
                );
                actions.extend(ServiceRuntimeAction::TIMER.map(Self::ServiceRuntime));
            }
            SystemInfoTab::Users => {
                actions.extend(UserInvestigationAction::ALL.map(Self::UserInspect));
                actions.extend(
                    [UserAccountAction::Lock, UserAccountAction::Unlock].map(Self::UserAccount),
                );
            }
            SystemInfoTab::LoginHistory => {
                actions.extend(LoginInvestigationAction::ALL.map(Self::LoginInspect));
                actions.extend(
                    [UserAccountAction::Lock, UserAccountAction::Unlock].map(Self::UserAccount),
                );
            }
            SystemInfoTab::Network | SystemInfoTab::Established | SystemInfoTab::OpenPorts => {
                actions.extend(NetworkInvestigationAction::ALL.map(Self::NetworkInspect));
                actions.push(Self::NetworkDisconnect);
            }
            SystemInfoTab::Packages => actions.extend(
                PackageInvestigationAction::ALL
                    .map(ArtifactInvestigationAction::Package)
                    .map(Self::ArtifactInspect),
            ),
            SystemInfoTab::KernelModules => {
                actions.extend(
                    KernelModuleInvestigationAction::ALL
                        .map(ArtifactInvestigationAction::KernelModule)
                        .map(Self::ArtifactInspect),
                );
                actions.extend(
                    [
                        ArtifactMutationAction::AddManagedModuleBlacklist,
                        ArtifactMutationAction::RemoveManagedModuleBlacklist,
                    ]
                    .map(Self::ArtifactMutation),
                );
            }
            SystemInfoTab::EnvVars => actions.extend(
                EnvVarInvestigationAction::ALL
                    .map(ArtifactInvestigationAction::Environment)
                    .map(Self::ArtifactInspect),
            ),
            SystemInfoTab::Cron => {
                actions.extend(
                    CronInvestigationAction::ALL
                        .map(ArtifactInvestigationAction::Cron)
                        .map(Self::ArtifactInspect),
                );
                actions.push(Self::ArtifactMutation(
                    ArtifactMutationAction::DeleteCronFile,
                ));
            }
            SystemInfoTab::ShellConfigs => {
                actions.extend(
                    ShellConfigInvestigationAction::ALL
                        .map(ArtifactInvestigationAction::ShellConfig)
                        .map(Self::ArtifactInspect),
                );
                actions.push(Self::ArtifactMutation(
                    ArtifactMutationAction::CommentShellLine,
                ));
            }
            SystemInfoTab::Sudoers => actions.extend(
                SudoersInvestigationAction::ALL
                    .map(ArtifactInvestigationAction::Sudoers)
                    .map(Self::ArtifactInspect),
            ),
            SystemInfoTab::SuidFiles => {
                actions.extend(
                    SuidFileInvestigationAction::ALL
                        .map(ArtifactInvestigationAction::SuidFile)
                        .map(Self::ArtifactInspect),
                );
                actions.extend(
                    [
                        ArtifactMutationAction::RemoveSuidBits,
                        ArtifactMutationAction::QuarantineSuidFile,
                    ]
                    .map(Self::ArtifactMutation),
                );
            }
            SystemInfoTab::SshKeys => actions.extend(
                SshKeyInvestigationAction::ALL
                    .map(ArtifactInvestigationAction::SshKey)
                    .map(Self::ArtifactInspect),
            ),
            SystemInfoTab::Firewall
            | SystemInfoTab::Autoruns
            | SystemInfoTab::Rootcheck
            | SystemInfoTab::Sensitive
            | SystemInfoTab::RecentFiles
            | SystemInfoTab::Docker
            | SystemInfoTab::Kubernetes
            | SystemInfoTab::WebApps => {}
        }
        actions
    }
}

/// Whether the core would accept this action for this row. The request
/// builders are pure: they read the row's cells and nothing else, so this
/// costs nothing and never touches the host.
fn applies(table: &SystemInfoTable, row_id: &str, action: RowAction) -> bool {
    match action {
        RowAction::ProcessInspect(inner) => {
            table.process_investigation_request(row_id, inner).is_ok()
        }
        RowAction::ProcessSignal(inner) => table.process_signal_request(row_id, inner).is_ok(),
        RowAction::ServiceInspect(inner) => {
            table.service_investigation_request(row_id, inner).is_ok()
        }
        RowAction::ServiceRuntime(inner) => table.runtime_change_request(row_id, inner).is_ok(),
        RowAction::UserInspect(inner) => table.user_investigation_request(row_id, inner).is_ok(),
        RowAction::UserAccount(inner) => table.user_account_request(row_id, inner).is_ok(),
        RowAction::LoginInspect(inner) => table.login_investigation_request(row_id, inner).is_ok(),
        RowAction::NetworkInspect(inner) => {
            table.network_investigation_request(row_id, inner).is_ok()
        }
        RowAction::NetworkDisconnect => table.network_disconnect_request(row_id).is_ok(),
        RowAction::ArtifactInspect(inner) => {
            table.artifact_investigation_request(row_id, inner).is_ok()
        }
        RowAction::ArtifactMutation(inner) => {
            table.artifact_mutation_request(row_id, inner).is_ok()
        }
    }
}

fn kebab<T: Serialize>(value: T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn from_kebab<T: DeserializeOwned>(value: &str) -> Option<T> {
    serde_json::from_value(serde_json::Value::String(value.to_owned())).ok()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SystemInfoRowActionsDto {
    tab: &'static str,
    row_id: String,
    /// What the row is, in the words the table used, so the menu can say what
    /// it is about. Display only; nothing resolves through it.
    subject: String,
    groups: Vec<SystemInfoRowActionGroupDto>,
}

impl fmt::Debug for SystemInfoRowActionsDto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SystemInfoRowActionsDto")
            .field("tab", &self.tab)
            .field("group_count", &self.groups.len())
            .finish()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SystemInfoRowActionGroupDto {
    key: String,
    label: &'static str,
    actions: Vec<SystemInfoRowActionDto>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SystemInfoRowActionDto {
    key: String,
    label: &'static str,
    kind: &'static str,
    dangerous: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SystemInfoRowInspectionDto {
    tab: &'static str,
    row_id: String,
    action: String,
    label: &'static str,
    subject: String,
    output: String,
    truncated: bool,
}

impl fmt::Debug for SystemInfoRowInspectionDto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SystemInfoRowInspectionDto")
            .field("tab", &self.tab)
            .field("action", &self.action)
            .field("output_bytes", &self.output.len())
            .field("truncated", &self.truncated)
            .finish()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SystemInfoRowPlanDto {
    plan_handle: String,
    tab: &'static str,
    row_id: String,
    action: String,
    label: &'static str,
    subject: String,
    summary: String,
    dangerous: bool,
    restore_description: Option<String>,
    confirmed: bool,
    expires_in_seconds: u32,
}

impl fmt::Debug for SystemInfoRowPlanDto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SystemInfoRowPlanDto")
            .field("tab", &self.tab)
            .field("action", &self.action)
            .field("confirmed", &self.confirmed)
            .finish()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SystemInfoRowReceiptDto {
    plan_handle: String,
    tab: &'static str,
    row_id: String,
    action: String,
    label: &'static str,
    subject: String,
    /// Whether the host, read back afterwards, is in the state the plan said
    /// it would be. A command that returned zero is not the same thing.
    verified: bool,
    detail: String,
    restored: bool,
}

impl fmt::Debug for SystemInfoRowReceiptDto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SystemInfoRowReceiptDto")
            .field("tab", &self.tab)
            .field("action", &self.action)
            .field("verified", &self.verified)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
struct RowScope {
    binding_handle: String,
    session_id: String,
    connection_id: String,
    target: TargetGuard,
}

enum RowPlan {
    ProcessSignal(ProcessSignalPlan),
    ServiceRuntime(ServiceRuntimePlan),
    /// The same request on a host that boots with scripts instead of units.
    BootScriptRuntime(BootScriptRuntimePlan),
    UserAccount(UserAccountPlan),
    NetworkDisconnect(NetworkDisconnectPlan),
    ArtifactMutation(ArtifactMutationPlan),
}

impl RowPlan {
    fn definition(&self) -> &OperationPlan {
        match self {
            Self::ProcessSignal(plan) => plan.definition(),
            Self::ServiceRuntime(plan) => plan.definition(),
            Self::BootScriptRuntime(plan) => plan.definition(),
            Self::UserAccount(plan) => plan.definition(),
            Self::NetworkDisconnect(plan) => plan.definition(),
            Self::ArtifactMutation(plan) => plan.definition(),
        }
    }
}

struct StoredRowPlan {
    plan_handle: String,
    scope: RowScope,
    tab: SystemInfoTab,
    row_id: String,
    action: RowAction,
    subject: String,
    plan: RowPlan,
    /// Set by `confirm` and never unset. `execute` refuses without it, and the
    /// plan leaves the registry as it is taken, so approval covers one run.
    confirmed: bool,
    expires_at: Instant,
}

#[derive(Default)]
pub(crate) struct RowPlanRegistry {
    plans: HashMap<String, StoredRowPlan>,
}

impl fmt::Debug for RowPlanRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RowPlanRegistry")
            .field("plan_count", &self.plans.len())
            .finish()
    }
}

impl RowPlanRegistry {
    fn prune(&mut self, now: Instant) {
        self.plans.retain(|_, plan| plan.expires_at > now);
    }

    pub(crate) fn close_binding(&mut self, binding_handle: &str) {
        self.plans
            .retain(|_, plan| plan.scope.binding_handle != binding_handle);
    }

    fn store(&mut self, plan: StoredRowPlan) -> Result<(), SystemInfoApiError> {
        // A page drives one dialog at a time, so an older plan of the same
        // binding is one the operator already walked away from.
        self.plans
            .retain(|_, stored| stored.scope.binding_handle != plan.scope.binding_handle);
        if self.plans.len() >= MAX_PLANS {
            return Err(SystemInfoApiError::SnapshotCapacity);
        }
        self.plans.insert(plan.plan_handle.clone(), plan);
        Ok(())
    }

    fn plan_mut(
        &mut self,
        scope: &RowScope,
        plan_handle: &str,
        now: Instant,
    ) -> Result<&mut StoredRowPlan, SystemInfoApiError> {
        let plan = self
            .plans
            .get_mut(plan_handle)
            .ok_or(SystemInfoApiError::PlanStale)?;
        if &plan.scope != scope || plan.expires_at <= now {
            return Err(SystemInfoApiError::PlanStale);
        }
        Ok(plan)
    }

    /// Takes an approved plan out, so it can never run twice.
    fn take_confirmed(
        &mut self,
        scope: &RowScope,
        plan_handle: &str,
        now: Instant,
    ) -> Result<StoredRowPlan, SystemInfoApiError> {
        if !self.plan_mut(scope, plan_handle, now)?.confirmed {
            return Err(SystemInfoApiError::PlanNotConfirmed);
        }
        self.plans
            .remove(plan_handle)
            .ok_or(SystemInfoApiError::PlanStale)
    }

    fn remove(&mut self, scope: &RowScope, plan_handle: &str) {
        if self
            .plans
            .get(plan_handle)
            .is_some_and(|plan| &plan.scope == scope)
        {
            self.plans.remove(plan_handle);
        }
    }
}

impl SystemInfoApi {
    /// Which actions this row can take, grouped the way the menu shows them.
    /// Reads the snapshot only; the host is not asked anything.
    pub(crate) fn row_actions(
        &self,
        binding_handle: &str,
        snapshot_handle: &str,
        row_id: &str,
    ) -> Result<SystemInfoRowActionsDto, SystemInfoApiError> {
        let (_, table) = self.snapshot_for(binding_handle, snapshot_handle, row_id)?;
        let row = find_row(&table, row_id)?;
        let mut groups: Vec<SystemInfoRowActionGroupDto> = Vec::new();
        for action in RowAction::candidates(table.tab) {
            if !applies(&table, row_id, action) {
                continue;
            }
            let (key, label) = action.group();
            let entry = SystemInfoRowActionDto {
                key: action.key(),
                label: action.label(),
                kind: if action.changes_host() {
                    "change"
                } else {
                    "inspect"
                },
                dangerous: action.dangerous(),
            };
            match groups.iter_mut().find(|group| group.key == key) {
                Some(group) => group.actions.push(entry),
                None => groups.push(SystemInfoRowActionGroupDto {
                    key,
                    label,
                    actions: vec![entry],
                }),
            }
        }
        Ok(SystemInfoRowActionsDto {
            tab: tab_key(table.tab),
            row_id: row.id.clone(),
            subject: row_subject(&table, row),
            groups,
        })
    }

    /// Runs one read-only action and hands the bounded output back.
    pub(crate) async fn inspect_row(
        &self,
        binding_handle: &str,
        snapshot_handle: &str,
        row_id: &str,
        action_key: &str,
    ) -> Result<SystemInfoRowInspectionDto, SystemInfoApiError> {
        let action = RowAction::parse(action_key).ok_or(SystemInfoApiError::InvalidAction)?;
        if action.changes_host() {
            return Err(SystemInfoApiError::InvalidAction);
        }
        let (session, table) = self.snapshot_for(binding_handle, snapshot_handle, row_id)?;
        let row = find_row(&table, row_id)?;
        let subject = row_subject(&table, row);
        let service = self.services.system_info();
        let outcome = timeout(INSPECT_DEADLINE, async {
            match action {
                RowAction::ProcessInspect(inner) => {
                    let request = table.process_investigation_request(row_id, inner)?;
                    let result = service.investigate_process(&session, &request).await?;
                    Ok((result.output, result.truncated))
                }
                RowAction::ServiceInspect(inner) => {
                    let request = table.service_investigation_request(row_id, inner)?;
                    let result = service.investigate_service(&session, &request).await?;
                    Ok((result.output, result.truncated))
                }
                RowAction::UserInspect(inner) => {
                    let request = table.user_investigation_request(row_id, inner)?;
                    let result = service.investigate_user(&session, &request).await?;
                    Ok((result.output, result.truncated))
                }
                RowAction::LoginInspect(inner) => {
                    let request = table.login_investigation_request(row_id, inner)?;
                    let result = service.investigate_login(&session, &request).await?;
                    Ok((result.output, result.truncated))
                }
                RowAction::NetworkInspect(inner) => {
                    let request = table.network_investigation_request(row_id, inner)?;
                    let result = service.investigate_network(&session, &request).await?;
                    Ok((result.output, result.truncated))
                }
                RowAction::ArtifactInspect(inner) => {
                    let request = table.artifact_investigation_request(row_id, inner)?;
                    let result = service.investigate_artifact(&session, &request).await?;
                    Ok((result.output, result.truncated))
                }
                RowAction::ProcessSignal(_)
                | RowAction::ServiceRuntime(_)
                | RowAction::UserAccount(_)
                | RowAction::NetworkDisconnect
                | RowAction::ArtifactMutation(_) => Err(CoreError::Validation {
                    subject: "system-information row action",
                    message: "this action changes the host and must be planned".to_owned(),
                }),
            }
        })
        .await
        .map_err(|_| SystemInfoApiError::Deadline)?
        .map_err(action_failure)?;
        self.ensure_binding_unchanged(binding_handle, &session)?;
        let (output, truncated) = outcome;
        Ok(SystemInfoRowInspectionDto {
            tab: tab_key(table.tab),
            row_id: row.id.clone(),
            action: action.key(),
            label: action.label(),
            subject,
            output,
            truncated,
        })
    }

    /// Describes what a change would do, without doing any of it.
    ///
    /// The row's current state is read from the host here rather than taken
    /// from the snapshot: the snapshot may be minutes old, and the
    /// precondition the core checks has to be checked against now.
    pub(crate) async fn plan_row_action(
        &self,
        binding_handle: &str,
        snapshot_handle: &str,
        row_id: &str,
        action_key: &str,
    ) -> Result<SystemInfoRowPlanDto, SystemInfoApiError> {
        let action = RowAction::parse(action_key).ok_or(SystemInfoApiError::InvalidAction)?;
        if !action.changes_host() {
            return Err(SystemInfoApiError::InvalidAction);
        }
        let scope = self.capture_scope(binding_handle)?;
        let (session, table) = self.snapshot_for(binding_handle, snapshot_handle, row_id)?;
        let row = find_row(&table, row_id)?;
        let subject = row_subject(&table, row);
        let service = self.services.system_info();
        let plan = timeout(PLAN_DEADLINE, async {
            match action {
                RowAction::ProcessSignal(signal) => {
                    let request = table.process_signal_request(row_id, signal)?;
                    service
                        .plan_process_signal(&session, &request)
                        .await
                        .map(RowPlan::ProcessSignal)
                }
                RowAction::ServiceRuntime(inner) => {
                    // Which of the two this row is was decided by the row
                    // itself, not by anything the window said.
                    match table.runtime_change_request(row_id, inner)? {
                        RuntimeChangeRequest::Service(request) => service
                            .plan_service_runtime(&session, &request)
                            .await
                            .map(RowPlan::ServiceRuntime),
                        RuntimeChangeRequest::BootScript(request) => service
                            .plan_boot_script_runtime(&session, &request)
                            .await
                            .map(RowPlan::BootScriptRuntime),
                    }
                }
                RowAction::UserAccount(inner) => {
                    let request = table.user_account_request(row_id, inner)?;
                    service
                        .plan_user_account(&session, &request)
                        .await
                        .map(RowPlan::UserAccount)
                }
                RowAction::NetworkDisconnect => {
                    let request = table.network_disconnect_request(row_id)?;
                    service
                        .plan_network_disconnect(&session, &request)
                        .await
                        .map(RowPlan::NetworkDisconnect)
                }
                RowAction::ArtifactMutation(inner) => {
                    let request = table.artifact_mutation_request(row_id, inner)?;
                    service
                        .plan_artifact_mutation(&session, &request)
                        .await
                        .map(RowPlan::ArtifactMutation)
                }
                RowAction::ProcessInspect(_)
                | RowAction::ServiceInspect(_)
                | RowAction::UserInspect(_)
                | RowAction::LoginInspect(_)
                | RowAction::NetworkInspect(_)
                | RowAction::ArtifactInspect(_) => Err(CoreError::Validation {
                    subject: "system-information row action",
                    message: "this action only reads and has nothing to plan".to_owned(),
                }),
            }
        })
        .await
        .map_err(|_| SystemInfoApiError::Deadline)?
        .map_err(action_failure)?;
        self.validate_scope(&scope)?;

        let now = Instant::now();
        let stored = StoredRowPlan {
            plan_handle: Uuid::new_v4().to_string(),
            scope,
            tab: table.tab,
            row_id: row.id.clone(),
            action,
            subject,
            plan,
            confirmed: false,
            expires_at: now + PLAN_TTL,
        };
        let dto = plan_dto(&stored, now);
        let mut registry = self.lock_plans()?;
        registry.prune(now);
        registry.store(stored)?;
        Ok(dto)
    }

    /// Records the operator's approval; nothing runs until this happened.
    pub(crate) fn confirm_row_action(
        &self,
        binding_handle: &str,
        plan_handle: &str,
    ) -> Result<SystemInfoRowPlanDto, SystemInfoApiError> {
        validate_plan_handle(plan_handle)?;
        let scope = self.capture_scope(binding_handle)?;
        let now = Instant::now();
        let mut registry = self.lock_plans()?;
        registry.prune(now);
        let plan = registry.plan_mut(&scope, plan_handle, now)?;
        plan.confirmed = true;
        Ok(plan_dto(plan, now))
    }

    /// Runs the approved plan once, verifies it, and reports what the host
    /// said afterwards.
    pub(crate) async fn execute_row_action(
        &self,
        binding_handle: &str,
        plan_handle: &str,
    ) -> Result<SystemInfoRowReceiptDto, SystemInfoApiError> {
        validate_plan_handle(plan_handle)?;
        let scope = self.capture_scope(binding_handle)?;
        // The plan leaves the registry before the await, so the lock is never
        // held across it and the plan can never run twice.
        let stored = {
            let now = Instant::now();
            let mut registry = self.lock_plans()?;
            registry.prune(now);
            registry.take_confirmed(&scope, plan_handle, now)?
        };
        let session = self.binding_session(&scope.binding_handle)?;
        let confirmation = DangerousConfirmation::approve(stored.plan.definition());
        let service = self.services.system_info();
        let journal = self.services.operation_journal();
        let StoredRowPlan {
            plan_handle,
            tab,
            row_id,
            action,
            subject,
            plan,
            ..
        } = stored;
        let outcome: Result<CoreResult<(VerificationResult, bool)>, _> =
            timeout(EXECUTE_DEADLINE, async move {
                match plan {
                    RowPlan::ProcessSignal(plan) => service
                        .execute_process_signal(&session, plan, confirmation, journal)
                        .await
                        .map(|outcome| (outcome.verification, false)),
                    RowPlan::ServiceRuntime(plan) => service
                        .execute_service_runtime(&session, plan, confirmation, journal)
                        .await
                        .map(|outcome| {
                            (
                                outcome.verification,
                                outcome.restored_after_failed_verification,
                            )
                        }),
                    RowPlan::BootScriptRuntime(plan) => service
                        .execute_boot_script_runtime(&session, plan, confirmation, journal)
                        .await
                        .map(|outcome| {
                            (
                                outcome.verification,
                                outcome.restored_after_failed_verification,
                            )
                        }),
                    RowPlan::UserAccount(plan) => service
                        .execute_user_account(&session, plan, confirmation, journal)
                        .await
                        .map(|outcome| {
                            (
                                outcome.verification,
                                outcome.restored_after_failed_verification,
                            )
                        }),
                    RowPlan::NetworkDisconnect(plan) => service
                        .execute_network_disconnect(&session, plan, confirmation, journal)
                        .await
                        .map(|outcome| (outcome.verification, false)),
                    RowPlan::ArtifactMutation(plan) => service
                        .execute_artifact_mutation(&session, plan, confirmation, journal)
                        .await
                        .map(|outcome| {
                            (
                                outcome.verification,
                                outcome.restored_after_failed_verification,
                            )
                        }),
                }
            })
            .await;
        self.validate_scope(&scope)?;

        let receipt = |verified: bool, detail: String, restored: bool| SystemInfoRowReceiptDto {
            plan_handle: plan_handle.clone(),
            tab: tab_key(tab),
            row_id: row_id.clone(),
            action: action.key(),
            label: action.label(),
            subject: subject.clone(),
            verified,
            detail,
            restored,
        };
        match outcome {
            Err(_) => Err(SystemInfoApiError::Deadline),
            // The core restores on failed verification itself and journals
            // whatever it got to, so a failure here is reported rather than
            // retried: retrying a half-applied change is worse than telling
            // the operator to look.
            Ok(Err(error)) => Ok(receipt(false, execution_failure_detail(&error), false)),
            Ok(Ok((verification, restored))) => Ok(receipt(
                verification.passed,
                bounded_text(&verification.detail, MAX_PLAN_TEXT_BYTES),
                restored,
            )),
        }
    }

    /// Drops a plan the operator decided against.
    pub(crate) fn cancel_row_action(
        &self,
        binding_handle: &str,
        plan_handle: &str,
    ) -> Result<(), SystemInfoApiError> {
        validate_plan_handle(plan_handle)?;
        let scope = self.capture_scope(binding_handle)?;
        self.lock_plans()?.remove(&scope, plan_handle);
        Ok(())
    }

    fn capture_scope(&self, binding_handle: &str) -> Result<RowScope, SystemInfoApiError> {
        let session = self.binding_session(binding_handle)?;
        self.services
            .target()
            .validate(session.target())
            .map_err(|_| SystemInfoApiError::BindingUnavailable)?;
        Ok(RowScope {
            binding_handle: binding_handle.to_owned(),
            session_id: session.session_id().to_owned(),
            connection_id: session.connection_id().to_owned(),
            target: session.target().clone(),
        })
    }

    fn validate_scope(&self, expected: &RowScope) -> Result<(), SystemInfoApiError> {
        let current = self.capture_scope(&expected.binding_handle)?;
        if &current != expected {
            return Err(SystemInfoApiError::BindingUnavailable);
        }
        Ok(())
    }

    fn lock_plans(&self) -> Result<std::sync::MutexGuard<'_, RowPlanRegistry>, SystemInfoApiError> {
        self.plans
            .lock()
            .map_err(|_| SystemInfoApiError::RegistryUnavailable)
    }
}

fn find_row<'a>(
    table: &'a SystemInfoTable,
    row_id: &str,
) -> Result<&'a SystemInfoRow, SystemInfoApiError> {
    table
        .rows
        .iter()
        .find(|row| row.id == row_id)
        .ok_or(SystemInfoApiError::InvalidRow)
}

fn validate_plan_handle(handle: &str) -> Result<(), SystemInfoApiError> {
    if handle.is_empty() || handle.len() > 128 {
        return Err(SystemInfoApiError::InvalidSnapshot);
    }
    Ok(())
}

/// What the row is, in the words the table used. Chosen per tab so the menu
/// title reads as the thing, not as the first cell.
fn row_subject(table: &SystemInfoTable, row: &SystemInfoRow) -> String {
    let cell = |index: usize| row.cells.get(index).map(String::as_str).unwrap_or("");
    let subject = match table.tab {
        SystemInfoTab::Processes => format!("PID {} · {}", cell(1), cell(8)),
        SystemInfoTab::Network => match cell(2) {
            "" | "-" | "*" => format!("{} {}", cell(0), cell(1)),
            remote => format!("{} {} → {}", cell(0), cell(1), remote),
        },
        SystemInfoTab::Established => format!("{} → {}", cell(0), cell(1)),
        SystemInfoTab::OpenPorts => format!("{} {}:{}", cell(0), cell(1), cell(2)),
        SystemInfoTab::LoginHistory => match cell(2) {
            "" | "-" => cell(0).to_owned(),
            source => format!("{} ← {}", cell(0), source),
        },
        SystemInfoTab::Cron => format!("{}: {}", cell(0), cell(2)),
        SystemInfoTab::ShellConfigs => format!("{}:{}", cell(0), cell(3)),
        SystemInfoTab::SshKeys => format!("{} {}", cell(0), cell(1)),
        _ => cell(0).to_owned(),
    };
    bounded_text(subject.trim(), MAX_SUBJECT_BYTES)
}

fn plan_dto(stored: &StoredRowPlan, now: Instant) -> SystemInfoRowPlanDto {
    let definition = stored.plan.definition();
    let remaining = stored.expires_at.saturating_duration_since(now).as_secs();
    SystemInfoRowPlanDto {
        plan_handle: stored.plan_handle.clone(),
        tab: tab_key(stored.tab),
        row_id: stored.row_id.clone(),
        action: stored.action.key(),
        label: stored.action.label(),
        subject: stored.subject.clone(),
        summary: bounded_text(&definition.summary, MAX_PLAN_TEXT_BYTES),
        dangerous: definition.dangerous,
        restore_description: definition
            .restore_description
            .as_deref()
            .map(|text| bounded_text(text, MAX_PLAN_TEXT_BYTES)),
        confirmed: stored.confirmed,
        expires_in_seconds: u32::try_from(remaining.max(1)).unwrap_or(u32::MAX),
    }
}

/// A core refusal that is about this row — the process is gone, the row is
/// not a TCP connection, the line is already a comment — is a different thing
/// from the feature failing, and is reported as such.
///
/// A target that never answered is a third thing again, and must not be
/// reported as either. Saying "this action no longer applies to this row"
/// about a host that is merely slow sends an operator looking for a change on
/// the target that never happened.
fn action_failure(error: CoreError) -> SystemInfoApiError {
    match error {
        CoreError::Validation { message, .. } if message.contains(COMMAND_TIMEOUT_MARKER) => {
            SystemInfoApiError::Deadline
        }
        error @ (CoreError::Validation { .. } | CoreError::NotFound { .. }) => {
            SystemInfoApiError::ActionUnavailable(error)
        }
        other => SystemInfoApiError::from(other),
    }
}

fn execution_failure_detail(error: &CoreError) -> String {
    match error {
        CoreError::Validation { .. } | CoreError::NotFound { .. } => {
            "目标机上的状态在确认之后变了，这次没有执行。请刷新后再看。".to_owned()
        }
        _ => "操作没有完成，目标机上的状态请再确认一次。".to_owned(),
    }
}

fn bounded_text(text: &str, maximum_bytes: usize) -> String {
    if text.len() <= maximum_bytes {
        return text.to_owned();
    }
    let mut end = maximum_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

#[cfg(test)]
mod tests {
    use lovelyhawk_core::system_info::SystemInfoRisk;

    use super::*;

    fn table(tab: SystemInfoTab, rows: Vec<Vec<&str>>) -> SystemInfoTable {
        SystemInfoTable {
            tab,
            columns: tab
                .columns()
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            rows: rows
                .into_iter()
                .enumerate()
                .map(|(index, cells)| SystemInfoRow {
                    id: format!("row-{index}"),
                    cells: cells.into_iter().map(str::to_owned).collect(),
                    risk: SystemInfoRisk::Normal,
                })
                .collect(),
            truncated: false,
            missing_tool: None,
            failed_tool: None,
        }
    }

    fn actions_for(table: &SystemInfoTable, row_id: &str) -> Vec<(String, String, bool)> {
        RowAction::candidates(table.tab)
            .into_iter()
            .filter(|action| applies(table, row_id, *action))
            .map(|action| (action.group().0, action.key(), action.dangerous()))
            .collect()
    }

    #[test]
    fn every_action_key_round_trips_and_is_unique() {
        // Two or three kebab-case segments, nothing else: the renderer's
        // validator accepts exactly this shape.
        fn well_formed(key: &str) -> bool {
            let segments: Vec<&str> = key.split('.').collect();
            (2..=3).contains(&segments.len())
                && segments.iter().all(|segment| {
                    segment
                        .bytes()
                        .next()
                        .is_some_and(|byte| byte.is_ascii_lowercase())
                        && segment.bytes().all(|byte| {
                            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                        })
                })
        }
        let mut seen: HashMap<String, RowAction> = HashMap::new();
        let mut total = 0;
        for tab in SystemInfoTab::ALL {
            for action in RowAction::candidates(tab) {
                let key = action.key();
                assert!(well_formed(&key), "{key} is not a well-formed key");
                assert!(key.len() <= MAX_ACTION_KEY_BYTES);
                assert_eq!(
                    RowAction::parse(&key),
                    Some(action),
                    "{key} does not parse back"
                );
                assert!(!action.label().is_empty());
                // The same action may be offered by several tabs (network
                // rows, account locks), but one key must always mean one thing.
                if let Some(previous) = seen.insert(key.clone(), action) {
                    assert_eq!(previous, action, "{key} maps to two actions");
                }
                total += 1;
            }
        }
        assert!(total > 200, "expected the full catalogue, got {total}");
        assert!(
            seen.len() > 150,
            "expected distinct keys, got {}",
            seen.len()
        );
    }

    #[test]
    fn forged_keys_name_nothing() {
        for hostile in [
            "",
            "process",
            "process.",
            "process.signal",
            "process.signal.hup",
            "process.kill -9",
            "network.disconnect.now",
            "shell.rm-rf",
            "module.blacklist.everything",
            "../process.open-files",
            "Process.Open-Files",
            &"process.".repeat(20),
        ] {
            assert_eq!(RowAction::parse(hostile), None, "{hostile:?} parsed");
        }
    }

    #[test]
    fn process_rows_offer_grouped_inspection_and_dangerous_signals() {
        let table = table(
            SystemInfoTab::Processes,
            vec![vec![
                "normal",
                "4242",
                "1",
                "root",
                "S",
                "0.1",
                "0.5",
                "120",
                "/usr/bin/sshd -D",
            ]],
        );
        let actions = actions_for(&table, "row-0");
        assert!(actions.iter().any(|(group, key, dangerous)| {
            group == "basics" && key == "process.command-line" && !dangerous
        }));
        assert!(actions.iter().any(|(group, key, dangerous)| {
            group == "change" && key == "process.signal.kill" && *dangerous
        }));
        assert_eq!(actions.len(), ProcessInvestigationAction::ALL.len() + 2);
        // The change group comes last, after every read-only group.
        let first_change = actions
            .iter()
            .position(|(group, ..)| group == "change")
            .unwrap();
        assert!(
            actions[first_change..]
                .iter()
                .all(|(group, ..)| group == "change")
        );
        assert_eq!(
            row_subject(&table, &table.rows[0]),
            "PID 4242 · /usr/bin/sshd -D"
        );
    }

    #[test]
    fn rows_that_cannot_take_an_action_are_not_offered_it() {
        let ports = table(
            SystemInfoTab::OpenPorts,
            vec![
                vec![
                    "udp",
                    "0.0.0.0",
                    "53",
                    "12",
                    "systemd-resolve",
                    "systemd-resolve",
                ],
                vec!["tcp", "0.0.0.0", "22", "33", "sshd", "root"],
            ],
        );
        // A listening socket has no peer to disconnect, whatever the transport.
        for row in ["row-0", "row-1"] {
            assert!(
                actions_for(&ports, row)
                    .iter()
                    .all(|(_, key, _)| key != "network.disconnect")
            );
        }
        // Nor can a UDP row be TCP-probed, while the TCP one can be asked
        // which process owns the port.
        assert!(
            actions_for(&ports, "row-0")
                .iter()
                .all(|(_, key, _)| key != "network.tcp-probe")
        );
        assert!(
            actions_for(&ports, "row-1")
                .iter()
                .any(|(_, key, _)| key == "network.port-process")
        );

        let established = table(
            SystemInfoTab::Established,
            vec![vec![
                "10.0.0.5:44210",
                "203.0.113.9",
                "4444",
                "777",
                "nc",
                "www-data",
            ]],
        );
        let keys: Vec<_> = actions_for(&established, "row-0")
            .into_iter()
            .map(|(_, key, _)| key)
            .collect();
        assert!(keys.contains(&"network.disconnect".to_owned()));
        assert!(keys.contains(&"network.whois".to_owned()));
        assert_eq!(
            row_subject(&established, &established.rows[0]),
            "10.0.0.5:44210 → 203.0.113.9"
        );

        // A shell line that is already a comment cannot be commented again.
        let shell = table(
            SystemInfoTab::ShellConfigs,
            vec![
                vec![
                    "/root/.bashrc",
                    "root",
                    "1700000000",
                    "3",
                    "# harmless",
                    "normal",
                ],
                vec![
                    "/root/.bashrc",
                    "root",
                    "1700000000",
                    "9",
                    "curl x | sh",
                    "high",
                ],
            ],
        );
        assert!(
            actions_for(&shell, "row-0")
                .iter()
                .all(|(_, key, _)| key != "shell.comment-line")
        );
        assert!(
            actions_for(&shell, "row-1")
                .iter()
                .any(|(_, key, _)| key == "shell.comment-line")
        );

        // Tabs without a row vocabulary offer nothing, and a missing row is
        // refused rather than answered with the tab's defaults.
        let firewall = table(
            SystemInfoTab::Firewall,
            vec![vec![
                "INPUT",
                "ACCEPT",
                "tcp",
                "0.0.0.0/0",
                "0.0.0.0/0",
                "dpt:22",
            ]],
        );
        assert!(actions_for(&firewall, "row-0").is_empty());
        assert!(RowAction::candidates(SystemInfoTab::Rootcheck).is_empty());
        assert!(matches!(
            find_row(&firewall, "row-99"),
            Err(SystemInfoApiError::InvalidRow)
        ));
    }

    #[test]
    fn hostile_cells_are_bounded_and_never_echoed_by_debug() {
        let hostile = "<script>steal()</script>".repeat(40);
        let table = table(
            SystemInfoTab::Users,
            vec![vec![&hostile, "0", "0", "/root", "/bin/bash"]],
        );
        let subject = row_subject(&table, &table.rows[0]);
        assert!(subject.len() <= MAX_SUBJECT_BYTES + "…".len());
        assert!(subject.ends_with('…'));
        // An invalid username means the user vocabulary does not apply.
        assert!(actions_for(&table, "row-0").is_empty());
        let dto = SystemInfoRowInspectionDto {
            tab: "users",
            row_id: "row-0".to_owned(),
            action: "user.details".to_owned(),
            label: "用户详情",
            subject,
            output: hostile.clone(),
            truncated: false,
        };
        let debug = format!("{dto:?}");
        assert!(!debug.contains("steal()"));
        assert!(!format!("{:?}", RowPlanRegistry::default()).contains("row-0"));
    }

    #[test]
    fn execution_failures_are_described_without_the_core_wording() {
        let stale = CoreError::Validation {
            subject: "process signal precondition",
            message: "identity changed".to_owned(),
        };
        assert!(execution_failure_detail(&stale).contains("刷新"));
        assert!(!execution_failure_detail(&stale).contains("identity"));
        // A target that never answered is a timeout, not a row that moved on.
        let timed_out = action_failure(CoreError::Validation {
            subject: "system information command",
            message: "process identity failed (exit=None, timed_out=true)".to_owned(),
        });
        assert!(matches!(timed_out, SystemInfoApiError::Deadline));

        let refusal = action_failure(stale);
        assert!(matches!(refusal, SystemInfoApiError::ActionUnavailable(_)));
        // The reason is kept for the log, and never printed by Debug.
        assert!(!format!("{refusal:?}").contains("identity changed"));
        assert!(matches!(
            action_failure(CoreError::NotFound {
                entity: "process",
                id: "1".to_owned()
            }),
            SystemInfoApiError::ActionUnavailable(_)
        ));
    }
}
