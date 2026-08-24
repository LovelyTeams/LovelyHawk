use std::{collections::BTreeMap, sync::Arc};

use gpui::{
    AnyElement, Context, Entity, EventEmitter, IntoElement, Render, SharedString, Subscription,
    Window, div, prelude::*, px,
};
use gpui_component::{
    Disableable, Sizable,
    button::ButtonVariants,
    input::{Input, InputEvent, InputState},
    scroll::ScrollableElement,
};
use lovelyres_core::{
    BackendServices, CoreError, CoreResult,
    docker::{
        ContainerAction, ContainerActionRequest, ContainerFilePath, ContainerIdentity,
        ContainerImage, ContainerInspection, ContainerLogs, ContainerLogsRequest, ContainerRuntime,
        ContainerShell, ContainerStats, ContainerSummary, DockerActionOutcome, DockerActionPlan,
        DockerCollection, DockerComposeAction, DockerComposeActionOutcome, DockerComposeActionPlan,
        DockerComposeActionRequest, DockerComposeProject, DockerFileContent,
        DockerFileCopyDirection, DockerFileCopyOutcome, DockerFileCopyPlan, DockerFileCopyRequest,
        DockerFileWriteOutcome, DockerFileWritePlan, DockerFileWriteRequest, DockerNetwork,
        DockerNetworkInspection, DockerResourceMutationOutcome, DockerResourceMutationPlan,
        DockerResourceMutationRequest, DockerSecurityAudit, DockerSecuritySeverity, DockerVolume,
        MAX_CONTAINER_FILE_BYTES,
    },
    operations::DangerousConfirmation,
    sftp::RemotePath,
    ssh::BoundSshSession,
    target::TargetGuard,
};
use tokio::task::AbortHandle;

use crate::{
    app::SharedAppState, container_terminal::ContainerTerminalLaunch, runtime::TokioBridge,
    theme::ThemeTokens,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenContainerTerminal {
    launch: ContainerTerminalLaunch,
}

impl OpenContainerTerminal {
    pub fn launch(&self) -> &ContainerTerminalLaunch {
        &self.launch
    }

    pub fn into_launch(self) -> ContainerTerminalLaunch {
        self.launch
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerBinding {
    connection_id: String,
    session_id: String,
    target: TargetGuard,
}

impl DockerBinding {
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

    fn label(&self) -> String {
        format!(
            "目标 {} · generation {}",
            self.target.identity.as_str(),
            self.target.generation
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum DockerRequestKind {
    Containers,
    Stats,
    Images,
    Networks,
    Volumes,
    ComposeProjects,
    SecurityAudit,
    NetworkInspect(String),
    Inspect(ContainerIdentity),
    Logs(ContainerIdentity),
    Action(ContainerIdentity),
    FileRead(ContainerIdentity),
    FileWrite(ContainerIdentity),
    FileCopy(ContainerIdentity),
    ResourceOperation(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerRequestLease {
    activation_generation: u64,
    request_id: u64,
    binding: DockerBinding,
    kind: DockerRequestKind,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum DetailView {
    #[default]
    Inspect,
    Logs,
    Files,
    Security,
    Resources,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum FileToolMode {
    #[default]
    Edit,
    Copy,
}

#[derive(Debug, Default)]
pub struct DockerModel {
    active: bool,
    activation_generation: u64,
    next_request_id: u64,
    binding: Option<DockerBinding>,
    latest: BTreeMap<DockerRequestKind, u64>,
    containers: Vec<ContainerSummary>,
    stats: BTreeMap<String, ContainerStats>,
    images: Vec<ContainerImage>,
    networks: Vec<DockerNetwork>,
    volumes: Vec<DockerVolume>,
    compose_projects: Vec<DockerComposeProject>,
    selected_network: Option<String>,
    network_inspection: Option<DockerNetworkInspection>,
    selected: Option<ContainerIdentity>,
    inspection: Option<ContainerInspection>,
    logs: Option<ContainerLogs>,
    security_audit: Option<DockerSecurityAudit>,
    query: String,
    detail_view: DetailView,
    containers_truncated: bool,
    images_truncated: bool,
    networks_truncated: bool,
    volumes_truncated: bool,
    compose_truncated: bool,
}

impl DockerModel {
    pub fn activate(&mut self, binding: Option<DockerBinding>) -> u64 {
        self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
        self.active = true;
        self.rebind(binding);
        self.activation_generation
    }

    pub fn deactivate(&mut self) {
        self.active = false;
        self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
        self.latest.clear();
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn binding(&self) -> Option<&DockerBinding> {
        self.binding.as_ref()
    }

    fn rebind(&mut self, binding: Option<DockerBinding>) {
        if self.binding == binding {
            return;
        }
        self.binding = binding;
        self.latest.clear();
        self.containers.clear();
        self.stats.clear();
        self.images.clear();
        self.networks.clear();
        self.volumes.clear();
        self.compose_projects.clear();
        self.selected_network = None;
        self.network_inspection = None;
        self.selected = None;
        self.inspection = None;
        self.logs = None;
        self.security_audit = None;
        self.containers_truncated = false;
        self.images_truncated = false;
        self.networks_truncated = false;
        self.volumes_truncated = false;
        self.compose_truncated = false;
    }

    fn begin_request(
        &mut self,
        kind: DockerRequestKind,
        binding: Option<DockerBinding>,
    ) -> CoreResult<DockerRequestLease> {
        if !self.active {
            return Err(CoreError::Validation {
                subject: "Docker page",
                message: "page is not active".to_owned(),
            });
        }
        self.rebind(binding);
        let binding = self.binding.clone().ok_or(CoreError::NoActiveTarget)?;
        self.next_request_id = self.next_request_id.wrapping_add(1).max(1);
        self.latest.insert(kind.clone(), self.next_request_id);
        Ok(DockerRequestLease {
            activation_generation: self.activation_generation,
            request_id: self.next_request_id,
            binding,
            kind,
        })
    }

    fn accepts(&self, lease: &DockerRequestLease, binding: Option<&DockerBinding>) -> bool {
        if !self.active
            || self.activation_generation != lease.activation_generation
            || binding != Some(&lease.binding)
            || self.latest.get(&lease.kind) != Some(&lease.request_id)
        {
            return false;
        }
        match &lease.kind {
            DockerRequestKind::NetworkInspect(network_id) => {
                self.selected_network.as_ref() == Some(network_id)
            }
            DockerRequestKind::Inspect(identity)
            | DockerRequestKind::Logs(identity)
            | DockerRequestKind::Action(identity)
            | DockerRequestKind::FileRead(identity)
            | DockerRequestKind::FileWrite(identity)
            | DockerRequestKind::FileCopy(identity) => self.selected.as_ref() == Some(identity),
            DockerRequestKind::ResourceOperation(_) => self.detail_view == DetailView::Resources,
            DockerRequestKind::Containers
            | DockerRequestKind::Stats
            | DockerRequestKind::Images
            | DockerRequestKind::Networks
            | DockerRequestKind::Volumes
            | DockerRequestKind::ComposeProjects
            | DockerRequestKind::SecurityAudit => true,
        }
    }

    fn apply_containers(
        &mut self,
        lease: &DockerRequestLease,
        binding: Option<&DockerBinding>,
        mut result: DockerCollection<ContainerSummary>,
    ) -> bool {
        if lease.kind != DockerRequestKind::Containers || !self.accepts(lease, binding) {
            return false;
        }
        result.items.sort_by(|left, right| {
            left.name
                .to_lowercase()
                .cmp(&right.name.to_lowercase())
                .then_with(|| left.identity.cmp(&right.identity))
        });
        let selected = self
            .selected
            .clone()
            .filter(|selected| result.items.iter().any(|item| &item.identity == selected))
            .or_else(|| result.items.first().map(|item| item.identity.clone()));
        if self.selected != selected {
            self.inspection = None;
            self.logs = None;
        }
        self.selected = selected;
        self.containers = result.items;
        self.containers_truncated = result.truncated;
        self.latest.remove(&lease.kind);
        true
    }

    fn apply_stats(
        &mut self,
        lease: &DockerRequestLease,
        binding: Option<&DockerBinding>,
        result: DockerCollection<ContainerStats>,
    ) -> bool {
        if lease.kind != DockerRequestKind::Stats || !self.accepts(lease, binding) {
            return false;
        }
        self.stats = result
            .items
            .into_iter()
            .map(|stats| (stats.identity.stable_key(), stats))
            .collect();
        self.latest.remove(&lease.kind);
        true
    }

    fn apply_images(
        &mut self,
        lease: &DockerRequestLease,
        binding: Option<&DockerBinding>,
        mut result: DockerCollection<ContainerImage>,
    ) -> bool {
        if lease.kind != DockerRequestKind::Images || !self.accepts(lease, binding) {
            return false;
        }
        result.items.sort_by(|left, right| {
            left.repository
                .to_lowercase()
                .cmp(&right.repository.to_lowercase())
                .then_with(|| left.tag.cmp(&right.tag))
                .then_with(|| left.id.cmp(&right.id))
        });
        self.images = result.items;
        self.images_truncated = result.truncated;
        self.latest.remove(&lease.kind);
        true
    }

    fn apply_networks(
        &mut self,
        lease: &DockerRequestLease,
        binding: Option<&DockerBinding>,
        mut result: DockerCollection<DockerNetwork>,
    ) -> bool {
        if lease.kind != DockerRequestKind::Networks || !self.accepts(lease, binding) {
            return false;
        }
        result.items.sort_by(|left, right| {
            left.name
                .to_lowercase()
                .cmp(&right.name.to_lowercase())
                .then_with(|| left.id.cmp(&right.id))
        });
        let selected = self
            .selected_network
            .clone()
            .filter(|selected| result.items.iter().any(|network| &network.id == selected));
        if self.selected_network != selected {
            self.network_inspection = None;
        }
        self.selected_network = selected;
        self.networks = result.items;
        self.networks_truncated = result.truncated;
        self.latest.remove(&lease.kind);
        true
    }

    fn apply_volumes(
        &mut self,
        lease: &DockerRequestLease,
        binding: Option<&DockerBinding>,
        mut result: DockerCollection<DockerVolume>,
    ) -> bool {
        if lease.kind != DockerRequestKind::Volumes || !self.accepts(lease, binding) {
            return false;
        }
        result
            .items
            .sort_by(|left, right| left.name.to_lowercase().cmp(&right.name.to_lowercase()));
        self.volumes = result.items;
        self.volumes_truncated = result.truncated;
        self.latest.remove(&lease.kind);
        true
    }

    fn apply_compose_projects(
        &mut self,
        lease: &DockerRequestLease,
        binding: Option<&DockerBinding>,
        mut result: DockerCollection<DockerComposeProject>,
    ) -> bool {
        if lease.kind != DockerRequestKind::ComposeProjects || !self.accepts(lease, binding) {
            return false;
        }
        result
            .items
            .sort_by(|left, right| left.name.cmp(&right.name));
        self.compose_projects = result.items;
        self.compose_truncated = result.truncated;
        self.latest.remove(&lease.kind);
        true
    }

    fn apply_network_inspection(
        &mut self,
        lease: &DockerRequestLease,
        binding: Option<&DockerBinding>,
        inspection: DockerNetworkInspection,
    ) -> bool {
        let DockerRequestKind::NetworkInspect(network_id) = &lease.kind else {
            return false;
        };
        if inspection.network.runtime != ContainerRuntime::Docker
            || &inspection.network.id != network_id
            || !self.accepts(lease, binding)
        {
            return false;
        }
        self.network_inspection = Some(inspection);
        self.latest.remove(&lease.kind);
        true
    }

    fn apply_inspection(
        &mut self,
        lease: &DockerRequestLease,
        binding: Option<&DockerBinding>,
        inspection: ContainerInspection,
    ) -> bool {
        let DockerRequestKind::Inspect(identity) = &lease.kind else {
            return false;
        };
        if &inspection.identity != identity || !self.accepts(lease, binding) {
            return false;
        }
        self.inspection = Some(inspection);
        self.latest.remove(&lease.kind);
        true
    }

    fn apply_logs(
        &mut self,
        lease: &DockerRequestLease,
        binding: Option<&DockerBinding>,
        logs: ContainerLogs,
    ) -> bool {
        let DockerRequestKind::Logs(identity) = &lease.kind else {
            return false;
        };
        if &logs.identity != identity || !self.accepts(lease, binding) {
            return false;
        }
        self.logs = Some(logs);
        self.detail_view = DetailView::Logs;
        self.latest.remove(&lease.kind);
        true
    }

    fn apply_security_audit(
        &mut self,
        lease: &DockerRequestLease,
        binding: Option<&DockerBinding>,
        audit: DockerSecurityAudit,
    ) -> bool {
        if lease.kind != DockerRequestKind::SecurityAudit
            || audit.runtime != ContainerRuntime::Docker
            || !self.accepts(lease, binding)
        {
            return false;
        }
        self.security_audit = Some(audit);
        self.latest.remove(&lease.kind);
        true
    }

    fn reject(&mut self, lease: &DockerRequestLease, binding: Option<&DockerBinding>) -> bool {
        if !self.accepts(lease, binding) {
            return false;
        }
        self.latest.remove(&lease.kind);
        true
    }

    pub fn set_query(&mut self, query: impl Into<String>) {
        self.query = query.into().chars().take(512).collect();
    }

    pub fn filtered_containers(&self) -> Vec<&ContainerSummary> {
        let query = self.query.trim().to_lowercase();
        self.containers
            .iter()
            .filter(|container| {
                query.is_empty()
                    || [
                        container.name.as_str(),
                        container.image.as_str(),
                        container.state.as_str(),
                        container.status.as_str(),
                        container.identity.id(),
                    ]
                    .iter()
                    .any(|value| value.to_lowercase().contains(&query))
            })
            .collect()
    }

    fn select(&mut self, identity: &ContainerIdentity) -> bool {
        if !self
            .containers
            .iter()
            .any(|container| &container.identity == identity)
        {
            return false;
        }
        if self.selected.as_ref() != Some(identity) {
            self.selected = Some(identity.clone());
            self.inspection = None;
            self.logs = None;
            self.detail_view = DetailView::Inspect;
            self.latest.retain(|kind, _| {
                !matches!(
                    kind,
                    DockerRequestKind::Inspect(_)
                        | DockerRequestKind::Logs(_)
                        | DockerRequestKind::Action(_)
                        | DockerRequestKind::FileRead(_)
                        | DockerRequestKind::FileWrite(_)
                        | DockerRequestKind::FileCopy(_)
                )
            });
        }
        true
    }

    fn select_network(&mut self, network_id: &str) -> bool {
        if !self.networks.iter().any(|network| network.id == network_id) {
            return false;
        }
        if self.selected_network.as_deref() != Some(network_id) {
            self.selected_network = Some(network_id.to_owned());
            self.network_inspection = None;
            self.latest
                .retain(|kind, _| !matches!(kind, DockerRequestKind::NetworkInspect(_)));
        }
        true
    }

    fn selected_network(&self) -> Option<&DockerNetwork> {
        let selected = self.selected_network.as_deref()?;
        self.networks.iter().find(|network| network.id == selected)
    }

    fn selected_container(&self) -> Option<&ContainerSummary> {
        let selected = self.selected.as_ref()?;
        self.containers
            .iter()
            .find(|container| &container.identity == selected)
    }

    fn selected_identity(&self) -> Option<ContainerIdentity> {
        self.selected.clone()
    }

    fn stats_for(&self, identity: &ContainerIdentity) -> Option<&ContainerStats> {
        self.stats.get(&identity.stable_key())
    }
}

#[derive(Debug)]
struct PendingDockerAction {
    binding: DockerBinding,
    plan: DockerActionPlan,
}

#[derive(Debug)]
struct PendingDockerFileWrite {
    binding: DockerBinding,
    plan: DockerFileWritePlan,
}

#[derive(Debug)]
struct PendingDockerFileCopy {
    binding: DockerBinding,
    plan: DockerFileCopyPlan,
}

#[derive(Debug)]
enum DockerResourceOperationPlan {
    Resource(DockerResourceMutationPlan),
    Compose(DockerComposeActionPlan),
}

impl DockerResourceOperationPlan {
    fn definition(&self) -> &lovelyres_core::operations::OperationPlan {
        match self {
            Self::Resource(plan) => plan.definition(),
            Self::Compose(plan) => plan.definition(),
        }
    }

    fn key(&self) -> String {
        match self {
            Self::Resource(plan) => {
                format!("resource:{}:{}", plan.kind().id(), plan.definition().id)
            }
            Self::Compose(plan) => format!(
                "compose:{}:{}:{}",
                plan.project().name,
                plan.action().id(),
                plan.definition().id
            ),
        }
    }

    fn label(&self) -> String {
        match self {
            Self::Resource(plan) => {
                format!("{}（{} 项）", plan.kind().label(), plan.targets().len())
            }
            Self::Compose(plan) => format!(
                "{} Compose 项目 {}",
                plan.action().label(),
                plan.project().name
            ),
        }
    }

    fn detail(&self) -> String {
        match self {
            Self::Resource(plan) => plan
                .targets()
                .iter()
                .map(|target| target.label())
                .take(8)
                .collect::<Vec<_>>()
                .join("、"),
            Self::Compose(plan) => format!(
                "配置文件：{}",
                plan.config_files()
                    .iter()
                    .map(|path| path.as_str())
                    .collect::<Vec<_>>()
                    .join("、")
            ),
        }
    }
}

#[derive(Debug)]
struct PendingDockerResourceOperation {
    binding: DockerBinding,
    plan: DockerResourceOperationPlan,
}

#[derive(Debug)]
enum DockerResourceOperationOutcome {
    Resource(DockerResourceMutationOutcome),
    Compose(DockerComposeActionOutcome),
}

fn resource_request_key(request: &DockerResourceMutationRequest) -> String {
    match request {
        DockerResourceMutationRequest::RemoveNetwork { network } => {
            format!("remove-network:{}", network.id)
        }
        DockerResourceMutationRequest::PruneNetworks { runtime } => {
            format!("prune-networks:{}", runtime.label())
        }
        DockerResourceMutationRequest::RemoveVolume { volume } => {
            format!("remove-volume:{}", volume.name)
        }
        DockerResourceMutationRequest::PruneVolumes { runtime } => {
            format!("prune-volumes:{}", runtime.label())
        }
    }
}

pub struct DockerPage {
    services: Arc<BackendServices>,
    tokio: Arc<TokioBridge>,
    shared: Entity<SharedAppState>,
    model: DockerModel,
    search_input: Entity<InputState>,
    file_path_input: Entity<InputState>,
    file_content_input: Entity<InputState>,
    copy_source_input: Entity<InputState>,
    copy_target_input: Entity<InputState>,
    containers_abort: Option<AbortHandle>,
    stats_abort: Option<AbortHandle>,
    images_abort: Option<AbortHandle>,
    security_abort: Option<AbortHandle>,
    networks_abort: Option<AbortHandle>,
    volumes_abort: Option<AbortHandle>,
    compose_abort: Option<AbortHandle>,
    network_inspection_abort: Option<AbortHandle>,
    inspection_abort: Option<AbortHandle>,
    logs_abort: Option<AbortHandle>,
    action_plan_abort: Option<AbortHandle>,
    file_read_abort: Option<AbortHandle>,
    file_plan_abort: Option<AbortHandle>,
    resource_plan_abort: Option<AbortHandle>,
    action_plan_request_id: Option<u64>,
    action_execution_request_id: Option<u64>,
    file_plan_request_id: Option<u64>,
    file_execution_request_id: Option<u64>,
    resource_plan_request_id: Option<u64>,
    resource_execution_request_id: Option<u64>,
    containers_loading: bool,
    stats_loading: bool,
    images_loading: bool,
    security_loading: bool,
    networks_loading: bool,
    volumes_loading: bool,
    compose_loading: bool,
    network_inspection_loading: bool,
    inspection_loading: bool,
    logs_loading: bool,
    action_busy: bool,
    file_busy: bool,
    resource_busy: bool,
    pending_action: Option<PendingDockerAction>,
    pending_file_write: Option<PendingDockerFileWrite>,
    pending_file_copy: Option<PendingDockerFileCopy>,
    pending_resource_operation: Option<PendingDockerResourceOperation>,
    loaded_file: Option<DockerFileContent>,
    file_editing: bool,
    file_tool_mode: FileToolMode,
    copy_direction: DockerFileCopyDirection,
    error: Option<SharedString>,
    notice: Option<SharedString>,
    _subscriptions: Vec<Subscription>,
}

impl DockerPage {
    pub fn new(
        services: Arc<BackendServices>,
        tokio: Arc<TokioBridge>,
        shared: Entity<SharedAppState>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let search_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("搜索容器名、镜像、状态或 ID…"));
        let file_path_input = cx.new(|cx| {
            InputState::new(window, cx).placeholder("容器内绝对路径，例如 /etc/nginx/nginx.conf")
        });
        let file_content_input = cx.new(|cx| {
            InputState::new(window, cx)
                .multi_line(true)
                .placeholder("加载文件后在此编辑 UTF-8 文本")
        });
        let copy_source_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("源文件绝对路径"));
        let copy_target_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("目标文件绝对路径"));
        let subscriptions = vec![
            cx.subscribe_in(
                &search_input,
                window,
                |page, input, event: &InputEvent, _, cx| {
                    if matches!(event, InputEvent::Change) {
                        page.model.set_query(input.read(cx).value().to_string());
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
            model: DockerModel::default(),
            search_input,
            file_path_input,
            file_content_input,
            copy_source_input,
            copy_target_input,
            containers_abort: None,
            stats_abort: None,
            images_abort: None,
            security_abort: None,
            networks_abort: None,
            volumes_abort: None,
            compose_abort: None,
            network_inspection_abort: None,
            inspection_abort: None,
            logs_abort: None,
            action_plan_abort: None,
            file_read_abort: None,
            file_plan_abort: None,
            resource_plan_abort: None,
            action_plan_request_id: None,
            action_execution_request_id: None,
            file_plan_request_id: None,
            file_execution_request_id: None,
            resource_plan_request_id: None,
            resource_execution_request_id: None,
            containers_loading: false,
            stats_loading: false,
            images_loading: false,
            security_loading: false,
            networks_loading: false,
            volumes_loading: false,
            compose_loading: false,
            network_inspection_loading: false,
            inspection_loading: false,
            logs_loading: false,
            action_busy: false,
            file_busy: false,
            resource_busy: false,
            pending_action: None,
            pending_file_write: None,
            pending_file_copy: None,
            pending_resource_operation: None,
            loaded_file: None,
            file_editing: false,
            file_tool_mode: FileToolMode::Edit,
            copy_direction: DockerFileCopyDirection::ContainerToHost,
            error: None,
            notice: None,
            _subscriptions: subscriptions,
        }
    }

    pub fn activate(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.model.activate(self.current_binding(cx));
        self.search_input
            .update(cx, |input, cx| input.focus(window, cx));
        self.refresh(cx);
    }

    pub fn deactivate(&mut self, cx: &mut Context<Self>) {
        self.abort_all();
        self.action_plan_request_id = None;
        self.pending_action = None;
        self.file_plan_request_id = None;
        self.pending_file_write = None;
        self.pending_file_copy = None;
        self.resource_plan_request_id = None;
        self.pending_resource_operation = None;
        self.loaded_file = None;
        self.file_editing = false;
        if self.action_execution_request_id.is_none() {
            self.action_busy = false;
        }
        if self.file_execution_request_id.is_none() {
            self.file_busy = false;
        }
        if self.resource_execution_request_id.is_none() {
            self.resource_busy = false;
        }
        self.model.deactivate();
        self.set_all_loading(false);
        cx.notify();
    }

    pub const fn is_active(&self) -> bool {
        self.model.is_active()
    }

    pub fn refresh(&mut self, cx: &mut Context<Self>) {
        self.refresh_containers(cx);
        self.refresh_stats(cx);
        self.refresh_images(cx);
        self.refresh_networks(cx);
        self.refresh_volumes(cx);
        self.refresh_compose_projects(cx);
    }

    fn current_binding(&self, cx: &Context<Self>) -> Option<DockerBinding> {
        DockerBinding::capture(self.shared.read(cx))
    }

    fn current_session(&self, cx: &Context<Self>) -> Option<BoundSshSession> {
        self.shared
            .read(cx)
            .active_ssh
            .as_ref()
            .map(|active| active.session.clone())
    }

    fn resource_operation_active(&self) -> bool {
        self.resource_busy || self.pending_resource_operation.is_some()
    }

    fn container_terminal_launch(&self, cx: &Context<Self>) -> CoreResult<ContainerTerminalLaunch> {
        if !self.model.is_active() {
            return Err(CoreError::Validation {
                subject: "container terminal",
                message: "Docker page is not active".to_owned(),
            });
        }
        let container = self
            .model
            .selected_container()
            .filter(|container| container.can_open_terminal())
            .ok_or_else(|| CoreError::Validation {
                subject: "container terminal",
                message: "selected container is not running".to_owned(),
            })?;
        let session = self.current_session(cx).ok_or(CoreError::NoActiveTarget)?;
        let binding = DockerBinding::from_session(&session);
        if self.model.binding() != Some(&binding) {
            return Err(CoreError::Validation {
                subject: "container terminal",
                message: "Docker selection belongs to a stale SSH target".to_owned(),
            });
        }
        self.services.target().validate(session.target())?;
        Ok(ContainerTerminalLaunch::new(
            session,
            container.identity.clone(),
            ContainerShell::Sh,
        ))
    }

    fn request_container_terminal(&mut self, cx: &mut Context<Self>) {
        if self.model.detail_view == DetailView::Files || self.resource_operation_active() {
            self.error = Some("请先关闭文件编辑器或完成资源操作".into());
            cx.notify();
            return;
        }
        match self.container_terminal_launch(cx) {
            Ok(launch) => {
                self.error = None;
                cx.emit(OpenContainerTerminal { launch });
            }
            Err(error) => {
                self.error = Some(format!("无法打开容器终端：{error}").into());
            }
        }
        cx.notify();
    }

    fn prepare_action(&mut self, action: ContainerAction, cx: &mut Context<Self>) {
        if self.action_busy
            || self.pending_action.is_some()
            || self.file_busy
            || self.pending_file_write.is_some()
            || self.pending_file_copy.is_some()
            || self.resource_operation_active()
            || self.model.detail_view == DetailView::Files
        {
            return;
        }
        let Some(container) = self.model.selected_container() else {
            self.error = Some("请选择容器".into());
            cx.notify();
            return;
        };
        if !action.is_available_in_state(&container.state) {
            self.error = Some(
                format!(
                    "容器状态 {} 不允许执行“{}”",
                    container.state,
                    action.label()
                )
                .into(),
            );
            cx.notify();
            return;
        }
        let identity = container.identity.clone();
        let (lease, session) =
            match self.prepare_request(DockerRequestKind::Action(identity.clone()), cx) {
                Ok(value) => value,
                Err(error) => {
                    self.error = Some(format!("无法创建容器操作计划：{error}").into());
                    cx.notify();
                    return;
                }
            };
        if let Some(abort) = self.action_plan_abort.take() {
            abort.abort();
        }
        self.action_busy = true;
        self.error = None;
        self.notice = Some(format!("正在复核远端状态并创建“{}”计划…", action.label()).into());
        let service = self.services.docker().clone();
        let request = ContainerActionRequest {
            container: identity,
            action,
        };
        let task = self
            .tokio
            .spawn(async move { service.plan_action(&session, &request).await });
        self.action_plan_abort = Some(task.abort_handle());
        self.action_plan_request_id = Some(lease.request_id);
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_action_plan(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_action_plan(
        &mut self,
        lease: DockerRequestLease,
        result: Result<CoreResult<DockerActionPlan>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if self.action_plan_request_id != Some(lease.request_id) {
            return;
        }
        self.action_plan_request_id = None;
        self.action_busy = false;
        self.action_plan_abort = None;
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            cx.notify();
            return;
        }
        let _ = self.model.reject(&lease, binding.as_ref());
        match result {
            Ok(Ok(plan)) => {
                self.pending_action = Some(PendingDockerAction {
                    binding: lease.binding,
                    plan,
                });
                self.notice = None;
                self.error = None;
            }
            Ok(Err(error)) => {
                self.error = Some(format!("容器操作计划创建失败：{error}").into());
                self.notice = None;
            }
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                self.error = Some(format!("容器操作计划任务失败：{error}").into());
                self.notice = None;
            }
        }
        cx.notify();
    }

    fn cancel_pending_action(&mut self, cx: &mut Context<Self>) {
        if self.pending_action.take().is_some() {
            self.notice = Some("操作计划已取消，未对远端容器产生变更".into());
            self.error = None;
            cx.notify();
        }
    }

    fn approve_pending_action(&mut self, cx: &mut Context<Self>) {
        if self.action_busy || self.resource_operation_active() {
            return;
        }
        let Some(pending) = self.pending_action.take() else {
            return;
        };
        let Some(session) = self.current_session(cx) else {
            self.error = Some("目标已断开，计划未执行".into());
            cx.notify();
            return;
        };
        let binding = DockerBinding::from_session(&session);
        if binding != pending.binding
            || self.model.binding() != Some(&binding)
            || self.model.selected_identity().as_ref() != Some(pending.plan.container())
        {
            self.error = Some("目标、会话或容器选择已变化，原计划已作废".into());
            cx.notify();
            return;
        }
        let identity = pending.plan.container().clone();
        let (lease, current_session) =
            match self.prepare_request(DockerRequestKind::Action(identity), cx) {
                Ok(value) => value,
                Err(error) => {
                    self.error = Some(format!("无法执行容器操作：{error}").into());
                    cx.notify();
                    return;
                }
            };
        self.action_busy = true;
        self.action_execution_request_id = Some(lease.request_id);
        self.error = None;
        self.notice = Some("正在执行、写入操作日志并回读验证容器状态…".into());
        let service = self.services.docker().clone();
        let journal = self.services.operation_journal().clone();
        let confirmation = DangerousConfirmation::approve(pending.plan.definition());
        let task = self.tokio.spawn(async move {
            service
                .execute_action(&current_session, pending.plan, confirmation, &journal)
                .await
        });
        // Destructive work is deliberately detached: navigation or target UI
        // changes must not interrupt execute -> journal -> verify/restore.
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        page.finish_action_execution(lease, result, cx)
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_action_execution(
        &mut self,
        lease: DockerRequestLease,
        result: Result<CoreResult<DockerActionOutcome>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if self.action_execution_request_id != Some(lease.request_id) {
            return;
        }
        self.action_execution_request_id = None;
        self.action_busy = false;
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            cx.notify();
            return;
        }
        let _ = self.model.reject(&lease, binding.as_ref());
        match result {
            Ok(Ok(outcome)) if outcome.verified => {
                self.notice =
                    Some(format!("容器操作已完成并验证：{}", outcome.verification_detail).into());
                self.error = None;
                self.refresh(cx);
            }
            Ok(Ok(outcome)) => {
                self.error = Some(
                    format!(
                        "容器状态回读验证失败：{}{}",
                        outcome.verification_detail,
                        if outcome.restored_after_failed_verification {
                            "；已恢复操作前状态"
                        } else {
                            ""
                        }
                    )
                    .into(),
                );
                self.refresh(cx);
            }
            Ok(Err(error)) => {
                self.error = Some(format!("容器操作失败：{error}").into());
                self.refresh(cx);
            }
            Err(error) => {
                self.error = Some(format!("容器操作任务异常终止：{error}").into());
            }
        }
        cx.notify();
    }

    fn open_file_panel(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.action_busy
            || self.pending_action.is_some()
            || self.file_busy
            || self.pending_file_write.is_some()
            || self.pending_file_copy.is_some()
            || self.resource_operation_active()
        {
            self.error = Some("容器状态操作完成前不能打开文件编辑器".into());
            cx.notify();
            return;
        }
        if self.model.selected_identity().is_none() {
            self.error = Some("请选择容器".into());
            cx.notify();
            return;
        }
        if self.model.detail_view == DetailView::Resources {
            self.leave_resources_view();
        }
        self.model.detail_view = DetailView::Files;
        self.file_tool_mode = FileToolMode::Edit;
        self.loaded_file = None;
        self.file_editing = false;
        self.pending_file_write = None;
        self.pending_file_copy = None;
        self.file_path_input.update(cx, |input, cx| {
            input.set_value("", window, cx);
            input.focus(window, cx);
        });
        self.file_content_input
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.error = None;
        self.notice = None;
        cx.notify();
    }

    fn open_copy_panel(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.action_busy
            || self.pending_action.is_some()
            || self.file_busy
            || self.pending_file_write.is_some()
            || self.pending_file_copy.is_some()
            || self.resource_operation_active()
        {
            self.error = Some("容器状态操作完成前不能打开文件复制工具".into());
            cx.notify();
            return;
        }
        if self.model.selected_identity().is_none() {
            self.error = Some("请选择容器".into());
            cx.notify();
            return;
        }
        if self.model.detail_view == DetailView::Resources {
            self.leave_resources_view();
        }
        self.model.detail_view = DetailView::Files;
        self.file_tool_mode = FileToolMode::Copy;
        self.loaded_file = None;
        self.file_editing = false;
        self.pending_file_write = None;
        self.pending_file_copy = None;
        self.copy_source_input.update(cx, |input, cx| {
            input.set_value("", window, cx);
            input.focus(window, cx);
        });
        self.copy_target_input
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.error = None;
        self.notice = None;
        cx.notify();
    }

    fn set_copy_direction(&mut self, direction: DockerFileCopyDirection, cx: &mut Context<Self>) {
        if self.file_busy || self.pending_file_copy.is_some() {
            return;
        }
        self.copy_direction = direction;
        self.error = None;
        cx.notify();
    }

    fn close_file_panel(&mut self, cx: &mut Context<Self>) {
        if let Some(abort) = self.file_read_abort.take() {
            abort.abort();
        }
        if let Some(abort) = self.file_plan_abort.take() {
            abort.abort();
        }
        self.file_plan_request_id = None;
        self.pending_file_write = None;
        self.pending_file_copy = None;
        self.loaded_file = None;
        self.file_editing = false;
        if self.file_execution_request_id.is_none() {
            self.file_busy = false;
        }
        self.model.latest.retain(|kind, _| {
            !matches!(
                kind,
                DockerRequestKind::FileRead(_)
                    | DockerRequestKind::FileWrite(_)
                    | DockerRequestKind::FileCopy(_)
            )
        });
        self.model.detail_view = DetailView::Inspect;
        cx.notify();
    }

    fn load_container_file(&mut self, cx: &mut Context<Self>) {
        if self.file_busy
            || self.pending_file_write.is_some()
            || self.pending_file_copy.is_some()
            || self.action_busy
            || self.resource_operation_active()
        {
            return;
        }
        let Some(identity) = self.model.selected_identity() else {
            self.error = Some("请选择容器".into());
            cx.notify();
            return;
        };
        let path =
            match ContainerFilePath::new(self.file_path_input.read(cx).value().trim().to_owned()) {
                Ok(path) => path,
                Err(error) => {
                    self.error = Some(format!("容器文件路径无效：{error}").into());
                    cx.notify();
                    return;
                }
            };
        let (lease, session) =
            match self.prepare_request(DockerRequestKind::FileRead(identity.clone()), cx) {
                Ok(value) => value,
                Err(error) => {
                    self.error = Some(format!("无法读取容器文件：{error}").into());
                    cx.notify();
                    return;
                }
            };
        if let Some(abort) = self.file_read_abort.take() {
            abort.abort();
        }
        self.loaded_file = None;
        self.file_editing = false;
        self.file_busy = true;
        self.error = None;
        self.notice = Some("正在读取并核对文件 SHA-256 快照…".into());
        let service = self.services.docker().clone();
        let task = self
            .tokio
            .spawn(async move { service.read_file(&session, &identity, &path).await });
        self.file_read_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_file_read(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_file_read(
        &mut self,
        lease: DockerRequestLease,
        result: Result<CoreResult<DockerFileContent>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref())
            || self.model.detail_view != DetailView::Files
            || self.file_tool_mode != FileToolMode::Edit
        {
            return;
        }
        self.file_busy = false;
        self.file_read_abort = None;
        let _ = self.model.reject(&lease, binding.as_ref());
        match result {
            Ok(Ok(file)) => {
                self.notice = Some(
                    format!(
                        "已校验 {} 字节 · SHA-256 {}",
                        file.content_bytes(),
                        file.sha256()
                    )
                    .into(),
                );
                self.loaded_file = Some(file);
                self.file_editing = false;
                self.error = None;
            }
            Ok(Err(error)) => {
                self.error = Some(format!("容器文件读取失败：{error}").into());
                self.notice = None;
            }
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                self.error = Some(format!("容器文件读取任务失败：{error}").into());
                self.notice = None;
            }
        }
        cx.notify();
    }

    fn begin_file_edit(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(loaded) = self.loaded_file.as_ref() else {
            return;
        };
        let content = loaded.content().to_owned();
        self.file_content_input.update(cx, |input, cx| {
            input.set_value(content, window, cx);
            input.focus(window, cx);
        });
        self.file_editing = true;
        self.error = None;
        cx.notify();
    }

    fn cancel_file_edit(&mut self, cx: &mut Context<Self>) {
        if self.file_busy {
            return;
        }
        self.file_editing = false;
        self.pending_file_write = None;
        self.pending_file_copy = None;
        self.error = None;
        cx.notify();
    }

    fn prepare_file_write(&mut self, cx: &mut Context<Self>) {
        if self.file_busy
            || self.pending_file_write.is_some()
            || self.pending_file_copy.is_some()
            || self.action_busy
            || self.pending_action.is_some()
            || self.resource_operation_active()
        {
            return;
        }
        let Some(loaded) = self.loaded_file.as_ref().cloned() else {
            self.error = Some("请先加载容器文件".into());
            cx.notify();
            return;
        };
        if self.model.selected_identity().as_ref() != Some(loaded.container())
            || self.file_path_input.read(cx).value().trim() != loaded.path().as_str()
        {
            self.error = Some("目标、容器或文件路径已变化，请重新加载后再保存".into());
            cx.notify();
            return;
        }
        let content = self.file_content_input.read(cx).value().to_string();
        let request = match DockerFileWriteRequest::replace(&loaded, content) {
            Ok(request) => request,
            Err(error) => {
                self.error = Some(format!("容器文件内容无效：{error}").into());
                cx.notify();
                return;
            }
        };
        let identity = loaded.container().clone();
        let (lease, session) =
            match self.prepare_request(DockerRequestKind::FileWrite(identity), cx) {
                Ok(value) => value,
                Err(error) => {
                    self.error = Some(format!("无法创建文件写入计划：{error}").into());
                    cx.notify();
                    return;
                }
            };
        if let Some(abort) = self.file_plan_abort.take() {
            abort.abort();
        }
        self.file_busy = true;
        self.error = None;
        self.notice = Some("正在复核文件快照并创建原子写入计划…".into());
        let service = self.services.docker().clone();
        let task = self
            .tokio
            .spawn(async move { service.plan_file_write(&session, request).await });
        self.file_plan_abort = Some(task.abort_handle());
        self.file_plan_request_id = Some(lease.request_id);
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_file_plan(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_file_plan(
        &mut self,
        lease: DockerRequestLease,
        result: Result<CoreResult<DockerFileWritePlan>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if self.file_plan_request_id != Some(lease.request_id) {
            return;
        }
        self.file_plan_request_id = None;
        self.file_plan_abort = None;
        self.file_busy = false;
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref())
            || self.model.detail_view != DetailView::Files
            || self.file_tool_mode != FileToolMode::Edit
        {
            cx.notify();
            return;
        }
        let _ = self.model.reject(&lease, binding.as_ref());
        match result {
            Ok(Ok(plan)) => {
                self.pending_file_write = Some(PendingDockerFileWrite {
                    binding: lease.binding,
                    plan,
                });
                self.notice = None;
                self.error = None;
            }
            Ok(Err(error)) => {
                self.error = Some(format!("文件写入计划创建失败：{error}").into());
                self.notice = None;
            }
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                self.error = Some(format!("文件写入计划任务失败：{error}").into());
                self.notice = None;
            }
        }
        cx.notify();
    }

    fn cancel_pending_file_write(&mut self, cx: &mut Context<Self>) {
        if self.pending_file_write.take().is_some() {
            self.notice = Some("文件写入计划已取消，远端文件未发生变化".into());
            self.error = None;
            cx.notify();
        }
    }

    fn approve_pending_file_write(&mut self, cx: &mut Context<Self>) {
        if self.file_busy || self.resource_operation_active() {
            return;
        }
        let Some(pending) = self.pending_file_write.take() else {
            return;
        };
        let Some(session) = self.current_session(cx) else {
            self.error = Some("目标已断开，文件写入计划未执行".into());
            cx.notify();
            return;
        };
        let binding = DockerBinding::from_session(&session);
        if binding != pending.binding
            || self.model.binding() != Some(&binding)
            || self.model.selected_identity().as_ref() != Some(pending.plan.container())
            || self.model.detail_view != DetailView::Files
        {
            self.error = Some("目标、会话、容器或文件界面已变化，原计划已作废".into());
            cx.notify();
            return;
        }
        let identity = pending.plan.container().clone();
        let (lease, current_session) =
            match self.prepare_request(DockerRequestKind::FileWrite(identity), cx) {
                Ok(value) => value,
                Err(error) => {
                    self.error = Some(format!("无法执行文件写入计划：{error}").into());
                    cx.notify();
                    return;
                }
            };
        self.file_busy = true;
        self.file_execution_request_id = Some(lease.request_id);
        self.error = None;
        self.notice = Some("正在原子写入、记录操作日志并精确读回验证…".into());
        let service = self.services.docker().clone();
        let journal = self.services.operation_journal().clone();
        let confirmation = DangerousConfirmation::approve(pending.plan.definition());
        let task = self.tokio.spawn(async move {
            service
                .execute_file_write(&current_session, pending.plan, confirmation, &journal)
                .await
        });
        // Confirmed destructive work must finish its audit and restore path even
        // when the page is closed or the visible target changes.
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_file_execution(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_file_execution(
        &mut self,
        lease: DockerRequestLease,
        result: Result<CoreResult<DockerFileWriteOutcome>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if self.file_execution_request_id != Some(lease.request_id) {
            return;
        }
        self.file_execution_request_id = None;
        self.file_busy = false;
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref())
            || self.model.detail_view != DetailView::Files
        {
            cx.notify();
            return;
        }
        let _ = self.model.reject(&lease, binding.as_ref());
        match result {
            Ok(Ok(outcome)) if outcome.verified => {
                self.notice = Some(
                    format!("容器文件已原子写入并验证：{}", outcome.verification_detail).into(),
                );
                self.error = None;
                self.loaded_file = None;
                self.file_editing = false;
                self.load_container_file(cx);
            }
            Ok(Ok(outcome)) => {
                self.error = Some(
                    format!(
                        "容器文件验证失败：{}{}",
                        outcome.verification_detail,
                        if outcome.restored_after_failed_verification {
                            "；已恢复写入前状态"
                        } else {
                            ""
                        }
                    )
                    .into(),
                );
            }
            Ok(Err(error)) => {
                self.error = Some(format!("容器文件写入失败：{error}").into());
            }
            Err(error) => {
                self.error = Some(format!("容器文件写入任务异常终止：{error}").into());
            }
        }
        cx.notify();
    }

    fn prepare_file_copy(&mut self, cx: &mut Context<Self>) {
        if self.file_busy
            || self.pending_file_write.is_some()
            || self.pending_file_copy.is_some()
            || self.action_busy
            || self.pending_action.is_some()
            || self.resource_operation_active()
        {
            return;
        }
        let Some(container) = self.model.selected_identity() else {
            self.error = Some("请选择容器".into());
            cx.notify();
            return;
        };
        let source = self.copy_source_input.read(cx).value().trim().to_owned();
        let target = self.copy_target_input.read(cx).value().trim().to_owned();
        let request = match self.copy_direction {
            DockerFileCopyDirection::ContainerToHost => {
                ContainerFilePath::new(source).and_then(|source| {
                    RemotePath::new(target).map(|target| DockerFileCopyRequest::ContainerToHost {
                        container: container.clone(),
                        source,
                        target,
                    })
                })
            }
            DockerFileCopyDirection::HostToContainer => {
                RemotePath::new(source).and_then(|source| {
                    ContainerFilePath::new(target).map(|target| {
                        DockerFileCopyRequest::HostToContainer {
                            container: container.clone(),
                            source,
                            target,
                        }
                    })
                })
            }
            DockerFileCopyDirection::InContainer => {
                ContainerFilePath::new(source).and_then(|source| {
                    ContainerFilePath::new(target).map(|target| {
                        DockerFileCopyRequest::InContainer {
                            container: container.clone(),
                            source,
                            target,
                        }
                    })
                })
            }
        };
        let request = match request {
            Ok(request) => request,
            Err(error) => {
                self.error = Some(format!("复制路径无效：{error}").into());
                cx.notify();
                return;
            }
        };
        let (lease, session) =
            match self.prepare_request(DockerRequestKind::FileCopy(container), cx) {
                Ok(value) => value,
                Err(error) => {
                    self.error = Some(format!("无法创建文件复制计划：{error}").into());
                    cx.notify();
                    return;
                }
            };
        if let Some(abort) = self.file_plan_abort.take() {
            abort.abort();
        }
        self.file_busy = true;
        self.error = None;
        self.notice = Some("正在复核复制源、目标及远端摘要…".into());
        let service = self.services.docker().clone();
        let task = self
            .tokio
            .spawn(async move { service.plan_file_copy(&session, request).await });
        self.file_plan_abort = Some(task.abort_handle());
        self.file_plan_request_id = Some(lease.request_id);
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_file_copy_plan(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_file_copy_plan(
        &mut self,
        lease: DockerRequestLease,
        result: Result<CoreResult<DockerFileCopyPlan>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if self.file_plan_request_id != Some(lease.request_id) {
            return;
        }
        self.file_plan_request_id = None;
        self.file_plan_abort = None;
        self.file_busy = false;
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref())
            || self.model.detail_view != DetailView::Files
            || self.file_tool_mode != FileToolMode::Copy
        {
            cx.notify();
            return;
        }
        let _ = self.model.reject(&lease, binding.as_ref());
        match result {
            Ok(Ok(plan)) => {
                self.pending_file_copy = Some(PendingDockerFileCopy {
                    binding: lease.binding,
                    plan,
                });
                self.notice = None;
                self.error = None;
            }
            Ok(Err(error)) => {
                self.error = Some(format!("文件复制计划创建失败：{error}").into());
                self.notice = None;
            }
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                self.error = Some(format!("文件复制计划任务失败：{error}").into());
                self.notice = None;
            }
        }
        cx.notify();
    }

    fn cancel_pending_file_copy(&mut self, cx: &mut Context<Self>) {
        if self.pending_file_copy.take().is_some() {
            self.notice = Some("文件复制计划已取消，源和目标均未变化".into());
            self.error = None;
            cx.notify();
        }
    }

    fn approve_pending_file_copy(&mut self, cx: &mut Context<Self>) {
        if self.file_busy || self.resource_operation_active() {
            return;
        }
        let Some(pending) = self.pending_file_copy.take() else {
            return;
        };
        let Some(session) = self.current_session(cx) else {
            self.error = Some("目标已断开，文件复制计划未执行".into());
            cx.notify();
            return;
        };
        let binding = DockerBinding::from_session(&session);
        if binding != pending.binding
            || self.model.binding() != Some(&binding)
            || self.model.selected_identity().as_ref() != Some(pending.plan.container())
            || self.model.detail_view != DetailView::Files
            || self.file_tool_mode != FileToolMode::Copy
        {
            self.error = Some("目标、会话、容器或复制界面已变化，原计划已作废".into());
            cx.notify();
            return;
        }
        let identity = pending.plan.container().clone();
        let (lease, current_session) =
            match self.prepare_request(DockerRequestKind::FileCopy(identity), cx) {
                Ok(value) => value,
                Err(error) => {
                    self.error = Some(format!("无法执行文件复制计划：{error}").into());
                    cx.notify();
                    return;
                }
            };
        self.file_busy = true;
        self.file_execution_request_id = Some(lease.request_id);
        self.error = None;
        self.notice = Some("正在复制、写入操作日志并核对源与目标摘要…".into());
        let service = self.services.docker().clone();
        let journal = self.services.operation_journal().clone();
        let confirmation = DangerousConfirmation::approve(pending.plan.definition());
        let task = self.tokio.spawn(async move {
            service
                .execute_file_copy(&current_session, pending.plan, confirmation, &journal)
                .await
        });
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        page.finish_file_copy_execution(lease, result, cx)
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_file_copy_execution(
        &mut self,
        lease: DockerRequestLease,
        result: Result<CoreResult<DockerFileCopyOutcome>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if self.file_execution_request_id != Some(lease.request_id) {
            return;
        }
        self.file_execution_request_id = None;
        self.file_busy = false;
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref())
            || self.model.detail_view != DetailView::Files
            || self.file_tool_mode != FileToolMode::Copy
        {
            cx.notify();
            return;
        }
        let _ = self.model.reject(&lease, binding.as_ref());
        match result {
            Ok(Ok(outcome)) if outcome.verified => {
                self.notice =
                    Some(format!("文件复制完成并验证：{}", outcome.verification_detail).into());
                self.error = None;
            }
            Ok(Ok(outcome)) => {
                self.error = Some(
                    format!(
                        "文件复制验证失败：{}{}",
                        outcome.verification_detail,
                        if outcome.restored_after_failed_verification {
                            "；已恢复复制前目标"
                        } else {
                            ""
                        }
                    )
                    .into(),
                );
            }
            Ok(Err(error)) => {
                self.error = Some(format!("文件复制失败：{error}").into());
            }
            Err(error) => {
                self.error = Some(format!("文件复制任务异常终止：{error}").into());
            }
        }
        cx.notify();
    }

    fn prepare_request(
        &mut self,
        kind: DockerRequestKind,
        cx: &mut Context<Self>,
    ) -> CoreResult<(DockerRequestLease, BoundSshSession)> {
        let session = self.current_session(cx).ok_or(CoreError::NoActiveTarget)?;
        let binding = Some(DockerBinding::from_session(&session));
        let lease = self.model.begin_request(kind, binding)?;
        Ok((lease, session))
    }

    fn handle_shared_change(&mut self, cx: &mut Context<Self>) {
        if !self.model.is_active() {
            return;
        }
        let binding = self.current_binding(cx);
        if self.model.binding() == binding.as_ref() {
            return;
        }
        self.abort_all();
        self.action_plan_request_id = None;
        if self.action_execution_request_id.is_none() {
            self.action_busy = false;
        }
        self.file_plan_request_id = None;
        if self.file_execution_request_id.is_none() {
            self.file_busy = false;
        }
        self.resource_plan_request_id = None;
        if self.resource_execution_request_id.is_none() {
            self.resource_busy = false;
        }
        self.set_all_loading(false);
        self.error = None;
        self.notice = None;
        self.pending_action = None;
        self.pending_file_write = None;
        self.pending_file_copy = None;
        self.pending_resource_operation = None;
        self.loaded_file = None;
        self.file_editing = false;
        self.model.rebind(binding);
        if self.model.binding().is_some() {
            self.refresh(cx);
        } else {
            self.error = Some("未连接目标，Docker 只读纵切无法加载".into());
            cx.notify();
        }
    }

    fn refresh_containers(&mut self, cx: &mut Context<Self>) {
        let (lease, session) = match self.prepare_request(DockerRequestKind::Containers, cx) {
            Ok(value) => value,
            Err(error) => {
                self.error = Some(format!("无法加载容器：{error}").into());
                self.containers_loading = false;
                cx.notify();
                return;
            }
        };
        if let Some(abort) = self.containers_abort.take() {
            abort.abort();
        }
        self.containers_loading = true;
        self.error = None;
        let service = self.services.docker().clone();
        let task = self
            .tokio
            .spawn(async move { service.list(&session, ContainerRuntime::Docker).await });
        self.containers_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_containers(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_containers(
        &mut self,
        lease: DockerRequestLease,
        result: Result<CoreResult<DockerCollection<ContainerSummary>>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            return;
        }
        self.containers_loading = false;
        self.containers_abort = None;
        match result {
            Ok(Ok(containers)) => {
                if self
                    .model
                    .apply_containers(&lease, binding.as_ref(), containers)
                    && self.model.selected_identity().is_some()
                    && self.model.detail_view == DetailView::Inspect
                {
                    self.refresh_inspection(cx);
                }
            }
            Ok(Err(error)) => {
                let _ = self.model.reject(&lease, binding.as_ref());
                self.error = Some(format!("容器列表读取失败：{error}").into());
            }
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                let _ = self.model.reject(&lease, binding.as_ref());
                self.error = Some(format!("容器列表任务失败：{error}").into());
            }
        }
        cx.notify();
    }

    fn refresh_stats(&mut self, cx: &mut Context<Self>) {
        let (lease, session) = match self.prepare_request(DockerRequestKind::Stats, cx) {
            Ok(value) => value,
            Err(_) => return,
        };
        if let Some(abort) = self.stats_abort.take() {
            abort.abort();
        }
        self.stats_loading = true;
        let service = self.services.docker().clone();
        let task = self
            .tokio
            .spawn(async move { service.stats(&session, ContainerRuntime::Docker).await });
        self.stats_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_stats(lease, result, cx));
                }
            });
        })
        .detach();
    }

    fn finish_stats(
        &mut self,
        lease: DockerRequestLease,
        result: Result<CoreResult<DockerCollection<ContainerStats>>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            return;
        }
        self.stats_loading = false;
        self.stats_abort = None;
        match result {
            Ok(Ok(stats)) => {
                let _ = self.model.apply_stats(&lease, binding.as_ref(), stats);
            }
            Ok(Err(error)) => {
                let _ = self.model.reject(&lease, binding.as_ref());
                self.notice = Some(format!("资源统计暂不可用：{error}").into());
            }
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                let _ = self.model.reject(&lease, binding.as_ref());
                self.notice = Some(format!("资源统计任务失败：{error}").into());
            }
        }
        cx.notify();
    }

    fn refresh_images(&mut self, cx: &mut Context<Self>) {
        let (lease, session) = match self.prepare_request(DockerRequestKind::Images, cx) {
            Ok(value) => value,
            Err(_) => return,
        };
        if let Some(abort) = self.images_abort.take() {
            abort.abort();
        }
        self.images_loading = true;
        let service = self.services.docker().clone();
        let task = self
            .tokio
            .spawn(async move { service.images(&session, ContainerRuntime::Docker).await });
        self.images_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_images(lease, result, cx));
                }
            });
        })
        .detach();
    }

    fn finish_images(
        &mut self,
        lease: DockerRequestLease,
        result: Result<CoreResult<DockerCollection<ContainerImage>>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            return;
        }
        self.images_loading = false;
        self.images_abort = None;
        match result {
            Ok(Ok(images)) => {
                let _ = self.model.apply_images(&lease, binding.as_ref(), images);
            }
            Ok(Err(error)) => {
                let _ = self.model.reject(&lease, binding.as_ref());
                self.notice = Some(format!("镜像列表暂不可用：{error}").into());
            }
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                let _ = self.model.reject(&lease, binding.as_ref());
                self.notice = Some(format!("镜像列表任务失败：{error}").into());
            }
        }
        cx.notify();
    }

    fn refresh_networks(&mut self, cx: &mut Context<Self>) {
        let (lease, session) = match self.prepare_request(DockerRequestKind::Networks, cx) {
            Ok(value) => value,
            Err(_) => return,
        };
        if let Some(abort) = self.networks_abort.take() {
            abort.abort();
        }
        self.networks_loading = true;
        let service = self.services.docker().clone();
        let task = self
            .tokio
            .spawn(async move { service.networks(&session, ContainerRuntime::Docker).await });
        self.networks_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_networks(lease, result, cx));
                }
            });
        })
        .detach();
    }

    fn finish_networks(
        &mut self,
        lease: DockerRequestLease,
        result: Result<CoreResult<DockerCollection<DockerNetwork>>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            return;
        }
        self.networks_loading = false;
        self.networks_abort = None;
        match result {
            Ok(Ok(networks)) => {
                let _ = self
                    .model
                    .apply_networks(&lease, binding.as_ref(), networks);
            }
            Ok(Err(error)) => {
                let _ = self.model.reject(&lease, binding.as_ref());
                self.notice = Some(format!("网络清单暂不可用：{error}").into());
            }
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                let _ = self.model.reject(&lease, binding.as_ref());
                self.notice = Some(format!("网络清单任务失败：{error}").into());
            }
        }
        cx.notify();
    }

    fn refresh_volumes(&mut self, cx: &mut Context<Self>) {
        let (lease, session) = match self.prepare_request(DockerRequestKind::Volumes, cx) {
            Ok(value) => value,
            Err(_) => return,
        };
        if let Some(abort) = self.volumes_abort.take() {
            abort.abort();
        }
        self.volumes_loading = true;
        let service = self.services.docker().clone();
        let task = self
            .tokio
            .spawn(async move { service.volumes(&session, ContainerRuntime::Docker).await });
        self.volumes_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_volumes(lease, result, cx));
                }
            });
        })
        .detach();
    }

    fn finish_volumes(
        &mut self,
        lease: DockerRequestLease,
        result: Result<CoreResult<DockerCollection<DockerVolume>>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            return;
        }
        self.volumes_loading = false;
        self.volumes_abort = None;
        match result {
            Ok(Ok(volumes)) => {
                let _ = self.model.apply_volumes(&lease, binding.as_ref(), volumes);
            }
            Ok(Err(error)) => {
                let _ = self.model.reject(&lease, binding.as_ref());
                self.notice = Some(format!("数据卷清单暂不可用：{error}").into());
            }
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                let _ = self.model.reject(&lease, binding.as_ref());
                self.notice = Some(format!("数据卷清单任务失败：{error}").into());
            }
        }
        cx.notify();
    }

    fn refresh_compose_projects(&mut self, cx: &mut Context<Self>) {
        let (lease, session) = match self.prepare_request(DockerRequestKind::ComposeProjects, cx) {
            Ok(value) => value,
            Err(_) => return,
        };
        if let Some(abort) = self.compose_abort.take() {
            abort.abort();
        }
        self.compose_loading = true;
        let service = self.services.docker().clone();
        let task = self.tokio.spawn(async move {
            service
                .compose_projects(&session, ContainerRuntime::Docker)
                .await
        });
        self.compose_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        page.finish_compose_projects(lease, result, cx)
                    });
                }
            });
        })
        .detach();
    }

    fn finish_compose_projects(
        &mut self,
        lease: DockerRequestLease,
        result: Result<CoreResult<DockerCollection<DockerComposeProject>>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            return;
        }
        self.compose_loading = false;
        self.compose_abort = None;
        match result {
            Ok(Ok(projects)) => {
                let _ = self
                    .model
                    .apply_compose_projects(&lease, binding.as_ref(), projects);
            }
            Ok(Err(error)) => {
                let _ = self.model.reject(&lease, binding.as_ref());
                self.notice = Some(format!("Compose 项目暂不可用：{error}").into());
            }
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                let _ = self.model.reject(&lease, binding.as_ref());
                self.notice = Some(format!("Compose 项目任务失败：{error}").into());
            }
        }
        cx.notify();
    }

    fn select_network(&mut self, network_id: &str, cx: &mut Context<Self>) {
        if !self.model.select_network(network_id) {
            return;
        }
        self.refresh_network_inspection(cx);
    }

    fn refresh_network_inspection(&mut self, cx: &mut Context<Self>) {
        let Some(network) = self.model.selected_network().cloned() else {
            return;
        };
        let (lease, session) =
            match self.prepare_request(DockerRequestKind::NetworkInspect(network.id.clone()), cx) {
                Ok(value) => value,
                Err(error) => {
                    self.error = Some(format!("无法读取 Docker 网络详情：{error}").into());
                    return;
                }
            };
        if let Some(abort) = self.network_inspection_abort.take() {
            abort.abort();
        }
        self.network_inspection_loading = true;
        self.error = None;
        let service = self.services.docker().clone();
        let task = self
            .tokio
            .spawn(async move { service.inspect_network(&session, &network).await });
        self.network_inspection_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        page.finish_network_inspection(lease, result, cx)
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_network_inspection(
        &mut self,
        lease: DockerRequestLease,
        result: Result<CoreResult<DockerNetworkInspection>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if self.model.detail_view != DetailView::Resources
            || !self.model.accepts(&lease, binding.as_ref())
        {
            return;
        }
        self.network_inspection_loading = false;
        self.network_inspection_abort = None;
        match result {
            Ok(Ok(inspection)) => {
                let _ = self
                    .model
                    .apply_network_inspection(&lease, binding.as_ref(), inspection);
            }
            Ok(Err(error)) => {
                let _ = self.model.reject(&lease, binding.as_ref());
                self.error = Some(format!("Docker 网络详情读取失败：{error}").into());
            }
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                let _ = self.model.reject(&lease, binding.as_ref());
                self.error = Some(format!("Docker 网络详情任务失败：{error}").into());
            }
        }
        cx.notify();
    }

    fn close_network_inspection(&mut self, cx: &mut Context<Self>) {
        if let Some(abort) = self.network_inspection_abort.take() {
            abort.abort();
        }
        self.network_inspection_loading = false;
        self.model.selected_network = None;
        self.model.network_inspection = None;
        self.model
            .latest
            .retain(|kind, _| !matches!(kind, DockerRequestKind::NetworkInspect(_)));
        self.error = None;
        cx.notify();
    }

    fn refresh_resources(&mut self, cx: &mut Context<Self>) {
        self.refresh_networks(cx);
        self.refresh_volumes(cx);
        self.refresh_compose_projects(cx);
        if self.model.selected_network().is_some() {
            self.refresh_network_inspection(cx);
        }
    }

    fn prepare_resource_mutation(
        &mut self,
        request: DockerResourceMutationRequest,
        cx: &mut Context<Self>,
    ) {
        if self.resource_busy
            || self.pending_resource_operation.is_some()
            || self.action_busy
            || self.pending_action.is_some()
            || self.file_busy
            || self.pending_file_write.is_some()
            || self.pending_file_copy.is_some()
            || self.model.detail_view != DetailView::Resources
        {
            return;
        }
        let key = resource_request_key(&request);
        let (lease, session) =
            match self.prepare_request(DockerRequestKind::ResourceOperation(key), cx) {
                Ok(value) => value,
                Err(error) => {
                    self.error = Some(format!("无法创建 Docker 资源操作计划：{error}").into());
                    cx.notify();
                    return;
                }
            };
        if let Some(abort) = self.resource_plan_abort.take() {
            abort.abort();
        }
        self.resource_busy = true;
        self.error = None;
        self.notice = Some("正在创建精确资源快照并复核使用关系…".into());
        let service = self.services.docker().clone();
        let task = self.tokio.spawn(async move {
            service
                .plan_resource_mutation(&session, request)
                .await
                .map(DockerResourceOperationPlan::Resource)
        });
        self.resource_plan_abort = Some(task.abort_handle());
        self.resource_plan_request_id = Some(lease.request_id);
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        page.finish_resource_operation_plan(lease, result, cx)
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn prepare_compose_action(
        &mut self,
        project: DockerComposeProject,
        action: DockerComposeAction,
        cx: &mut Context<Self>,
    ) {
        if self.resource_busy
            || self.pending_resource_operation.is_some()
            || self.action_busy
            || self.pending_action.is_some()
            || self.file_busy
            || self.pending_file_write.is_some()
            || self.pending_file_copy.is_some()
            || self.model.detail_view != DetailView::Resources
        {
            return;
        }
        if !action.is_available(&project) {
            self.error = Some(
                format!(
                    "Compose 项目 {} 当前不允许“{}”",
                    project.name,
                    action.label()
                )
                .into(),
            );
            cx.notify();
            return;
        }
        let key = format!("compose:{}:{}", project.name, action.id());
        let (lease, session) =
            match self.prepare_request(DockerRequestKind::ResourceOperation(key), cx) {
                Ok(value) => value,
                Err(error) => {
                    self.error = Some(format!("无法创建 Compose 操作计划：{error}").into());
                    cx.notify();
                    return;
                }
            };
        if let Some(abort) = self.resource_plan_abort.take() {
            abort.abort();
        }
        self.resource_busy = true;
        self.error = None;
        self.notice = Some(format!("正在复核 Compose 项目并创建“{}”计划…", action.label()).into());
        let service = self.services.docker().clone();
        let request = DockerComposeActionRequest { project, action };
        let task = self.tokio.spawn(async move {
            service
                .plan_compose_action(&session, request)
                .await
                .map(DockerResourceOperationPlan::Compose)
        });
        self.resource_plan_abort = Some(task.abort_handle());
        self.resource_plan_request_id = Some(lease.request_id);
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        page.finish_resource_operation_plan(lease, result, cx)
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_resource_operation_plan(
        &mut self,
        lease: DockerRequestLease,
        result: Result<CoreResult<DockerResourceOperationPlan>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if self.resource_plan_request_id != Some(lease.request_id) {
            return;
        }
        self.resource_plan_request_id = None;
        self.resource_plan_abort = None;
        self.resource_busy = false;
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            cx.notify();
            return;
        }
        let _ = self.model.reject(&lease, binding.as_ref());
        match result {
            Ok(Ok(plan)) => {
                self.pending_resource_operation = Some(PendingDockerResourceOperation {
                    binding: lease.binding,
                    plan,
                });
                self.notice = None;
                self.error = None;
            }
            Ok(Err(error)) => {
                self.error = Some(format!("Docker 资源操作计划创建失败：{error}").into());
                self.notice = None;
            }
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                self.error = Some(format!("Docker 资源计划任务失败：{error}").into());
                self.notice = None;
            }
        }
        cx.notify();
    }

    fn cancel_pending_resource_operation(&mut self, cx: &mut Context<Self>) {
        if self.pending_resource_operation.take().is_some() {
            self.notice = Some("资源操作计划已取消，未对远端资源产生变更".into());
            self.error = None;
            cx.notify();
        }
    }

    fn approve_pending_resource_operation(&mut self, cx: &mut Context<Self>) {
        if self.resource_busy
            || self.action_busy
            || self.pending_action.is_some()
            || self.file_busy
            || self.pending_file_write.is_some()
            || self.pending_file_copy.is_some()
            || self.model.detail_view != DetailView::Resources
        {
            return;
        }
        let Some(pending) = self.pending_resource_operation.take() else {
            return;
        };
        let Some(session) = self.current_session(cx) else {
            self.error = Some("目标已断开，资源计划未执行".into());
            cx.notify();
            return;
        };
        let binding = DockerBinding::from_session(&session);
        if binding != pending.binding || self.model.binding() != Some(&binding) {
            self.error = Some("目标或会话已变化，原资源计划已作废".into());
            cx.notify();
            return;
        }
        let key = pending.plan.key();
        let (lease, current_session) =
            match self.prepare_request(DockerRequestKind::ResourceOperation(key), cx) {
                Ok(value) => value,
                Err(error) => {
                    self.error = Some(format!("无法执行 Docker 资源操作：{error}").into());
                    cx.notify();
                    return;
                }
            };
        self.resource_busy = true;
        self.resource_execution_request_id = Some(lease.request_id);
        self.error = None;
        self.notice = Some("正在执行、写入操作日志并回读验证资源状态…".into());
        let service = self.services.docker().clone();
        let journal = self.services.operation_journal().clone();
        let confirmation = DangerousConfirmation::approve(pending.plan.definition());
        let task = self.tokio.spawn(async move {
            match pending.plan {
                DockerResourceOperationPlan::Resource(plan) => service
                    .execute_resource_mutation(&current_session, plan, confirmation, &journal)
                    .await
                    .map(DockerResourceOperationOutcome::Resource),
                DockerResourceOperationPlan::Compose(plan) => service
                    .execute_compose_action(&current_session, plan, confirmation, &journal)
                    .await
                    .map(DockerResourceOperationOutcome::Compose),
            }
        });
        // A confirmed destructive workflow must finish journaling and
        // verification even if the page is deactivated. Presentation is still
        // guarded by the lifecycle lease below.
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        page.finish_resource_operation_execution(lease, result, cx)
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_resource_operation_execution(
        &mut self,
        lease: DockerRequestLease,
        result: Result<CoreResult<DockerResourceOperationOutcome>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if self.resource_execution_request_id != Some(lease.request_id) {
            return;
        }
        self.resource_execution_request_id = None;
        self.resource_busy = false;
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            cx.notify();
            return;
        }
        let _ = self.model.reject(&lease, binding.as_ref());
        match result {
            Ok(Ok(DockerResourceOperationOutcome::Resource(outcome))) if outcome.verified => {
                self.notice = Some(
                    format!(
                        "{}完成并验证：{}",
                        outcome.kind.label(),
                        outcome.verification_detail
                    )
                    .into(),
                );
                self.error = None;
                self.close_network_inspection(cx);
                self.refresh_resources(cx);
            }
            Ok(Ok(DockerResourceOperationOutcome::Compose(outcome))) if outcome.verified => {
                self.notice = Some(
                    format!(
                        "Compose {}完成并验证：{}",
                        outcome.action.label(),
                        outcome.verification_detail
                    )
                    .into(),
                );
                self.error = None;
                self.refresh_resources(cx);
            }
            Ok(Ok(DockerResourceOperationOutcome::Resource(outcome))) => {
                self.error = Some(
                    format!(
                        "{}回读验证失败：{}",
                        outcome.kind.label(),
                        outcome.verification_detail
                    )
                    .into(),
                );
                self.refresh_resources(cx);
            }
            Ok(Ok(DockerResourceOperationOutcome::Compose(outcome))) => {
                self.error = Some(
                    format!(
                        "Compose {}回读验证失败：{}",
                        outcome.action.label(),
                        outcome.verification_detail
                    )
                    .into(),
                );
                self.refresh_resources(cx);
            }
            Ok(Err(error)) => {
                self.error = Some(format!("Docker 资源操作失败：{error}").into());
                self.refresh_resources(cx);
            }
            Err(error) => {
                self.error = Some(format!("Docker 资源操作任务异常终止：{error}").into());
            }
        }
        cx.notify();
    }

    fn refresh_security_audit(&mut self, cx: &mut Context<Self>) {
        if self.action_busy
            || self.file_busy
            || self.resource_operation_active()
            || self.model.detail_view == DetailView::Files
        {
            return;
        }
        if self.model.detail_view == DetailView::Resources {
            self.leave_resources_view();
        }
        let (lease, session) = match self.prepare_request(DockerRequestKind::SecurityAudit, cx) {
            Ok(value) => value,
            Err(error) => {
                self.error = Some(format!("无法运行 Docker 安全审计：{error}").into());
                return;
            }
        };
        if let Some(abort) = self.security_abort.take() {
            abort.abort();
        }
        self.security_loading = true;
        self.model.detail_view = DetailView::Security;
        self.error = None;
        self.notice = Some("正在获取精确容器清单并执行八类只读安全检查…".into());
        let service = self.services.docker().clone();
        let task = self.tokio.spawn(async move {
            service
                .security_audit(&session, ContainerRuntime::Docker)
                .await
        });
        self.security_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_security_audit(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_security_audit(
        &mut self,
        lease: DockerRequestLease,
        result: Result<CoreResult<DockerSecurityAudit>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref())
            || self.model.detail_view != DetailView::Security
        {
            return;
        }
        self.security_loading = false;
        self.security_abort = None;
        match result {
            Ok(Ok(audit)) => {
                let score = audit.summary.score;
                let total = audit.summary.total;
                let _ = self
                    .model
                    .apply_security_audit(&lease, binding.as_ref(), audit);
                self.notice = Some(format!("安全审计完成：{score}/100，{total} 项发现").into());
                self.error = None;
            }
            Ok(Err(error)) => {
                let _ = self.model.reject(&lease, binding.as_ref());
                self.error = Some(format!("Docker 安全审计失败：{error}").into());
                self.notice = None;
            }
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                let _ = self.model.reject(&lease, binding.as_ref());
                self.error = Some(format!("Docker 安全审计任务失败：{error}").into());
                self.notice = None;
            }
        }
        cx.notify();
    }

    fn leave_security_view(&mut self) {
        if let Some(abort) = self.security_abort.take() {
            abort.abort();
        }
        self.security_loading = false;
        self.model.latest.remove(&DockerRequestKind::SecurityAudit);
    }

    fn leave_resources_view(&mut self) {
        if let Some(abort) = self.network_inspection_abort.take() {
            abort.abort();
        }
        self.network_inspection_loading = false;
        if let Some(abort) = self.resource_plan_abort.take() {
            abort.abort();
        }
        self.resource_plan_request_id = None;
        self.pending_resource_operation = None;
        if self.resource_execution_request_id.is_none() {
            self.resource_busy = false;
        }
        self.model.selected_network = None;
        self.model.network_inspection = None;
        self.model.latest.retain(|kind, _| {
            !matches!(
                kind,
                DockerRequestKind::NetworkInspect(_) | DockerRequestKind::ResourceOperation(_)
            )
        });
    }

    fn select_container(&mut self, identity: &ContainerIdentity, cx: &mut Context<Self>) {
        if self.model.detail_view == DetailView::Security {
            self.leave_security_view();
        }
        let changed = self.model.selected_identity().as_ref() != Some(identity);
        if !self.model.select(identity) {
            return;
        }
        if changed {
            if let Some(abort) = self.action_plan_abort.take() {
                abort.abort();
            }
            self.action_plan_request_id = None;
            self.pending_action = None;
            if self.action_execution_request_id.is_none() {
                self.action_busy = false;
            }
            if let Some(abort) = self.file_read_abort.take() {
                abort.abort();
            }
            if let Some(abort) = self.file_plan_abort.take() {
                abort.abort();
            }
            self.file_plan_request_id = None;
            self.pending_file_write = None;
            self.pending_file_copy = None;
            self.loaded_file = None;
            self.file_editing = false;
            if self.file_execution_request_id.is_none() {
                self.file_busy = false;
            }
        }
        if let Some(abort) = self.inspection_abort.take() {
            abort.abort();
        }
        if let Some(abort) = self.logs_abort.take() {
            abort.abort();
        }
        self.refresh_inspection(cx);
    }

    fn refresh_inspection(&mut self, cx: &mut Context<Self>) {
        if self.model.detail_view == DetailView::Security {
            self.leave_security_view();
        }
        if self.model.detail_view == DetailView::Resources {
            self.leave_resources_view();
        }
        let Some(identity) = self.model.selected_identity() else {
            return;
        };
        let (lease, session) =
            match self.prepare_request(DockerRequestKind::Inspect(identity.clone()), cx) {
                Ok(value) => value,
                Err(error) => {
                    self.notice = Some(format!("无法读取容器详情：{error}").into());
                    return;
                }
            };
        if let Some(abort) = self.inspection_abort.take() {
            abort.abort();
        }
        self.inspection_loading = true;
        self.model.detail_view = DetailView::Inspect;
        let service = self.services.docker().clone();
        let task = self
            .tokio
            .spawn(async move { service.inspect(&session, &identity).await });
        self.inspection_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_inspection(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_inspection(
        &mut self,
        lease: DockerRequestLease,
        result: Result<CoreResult<ContainerInspection>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            return;
        }
        self.inspection_loading = false;
        self.inspection_abort = None;
        match result {
            Ok(Ok(inspection)) => {
                let _ = self
                    .model
                    .apply_inspection(&lease, binding.as_ref(), inspection);
            }
            Ok(Err(error)) => {
                let _ = self.model.reject(&lease, binding.as_ref());
                self.notice = Some(format!("容器详情读取失败：{error}").into());
            }
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                let _ = self.model.reject(&lease, binding.as_ref());
                self.notice = Some(format!("容器详情任务失败：{error}").into());
            }
        }
        cx.notify();
    }

    fn refresh_logs(&mut self, cx: &mut Context<Self>) {
        if self.model.detail_view == DetailView::Files {
            self.close_file_panel(cx);
        }
        if self.model.detail_view == DetailView::Security {
            self.leave_security_view();
        }
        if self.model.detail_view == DetailView::Resources {
            self.leave_resources_view();
        }
        let Some(identity) = self.model.selected_identity() else {
            return;
        };
        let (lease, session) =
            match self.prepare_request(DockerRequestKind::Logs(identity.clone()), cx) {
                Ok(value) => value,
                Err(error) => {
                    self.notice = Some(format!("无法读取容器日志：{error}").into());
                    return;
                }
            };
        if let Some(abort) = self.logs_abort.take() {
            abort.abort();
        }
        self.logs_loading = true;
        self.model.detail_view = DetailView::Logs;
        let service = self.services.docker().clone();
        let request = ContainerLogsRequest::recent(identity);
        let task = self
            .tokio
            .spawn(async move { service.logs(&session, &request).await });
        self.logs_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_logs(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_logs(
        &mut self,
        lease: DockerRequestLease,
        result: Result<CoreResult<ContainerLogs>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            return;
        }
        self.logs_loading = false;
        self.logs_abort = None;
        match result {
            Ok(Ok(logs)) => {
                let _ = self.model.apply_logs(&lease, binding.as_ref(), logs);
            }
            Ok(Err(error)) => {
                let _ = self.model.reject(&lease, binding.as_ref());
                self.notice = Some(format!("容器日志读取失败：{error}").into());
            }
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                let _ = self.model.reject(&lease, binding.as_ref());
                self.notice = Some(format!("容器日志任务失败：{error}").into());
            }
        }
        cx.notify();
    }

    fn show_inspection(&mut self, cx: &mut Context<Self>) {
        if self.model.detail_view == DetailView::Files {
            self.close_file_panel(cx);
        }
        if self.model.detail_view == DetailView::Security {
            self.leave_security_view();
        }
        if self.model.detail_view == DetailView::Resources {
            self.leave_resources_view();
        }
        self.model.detail_view = DetailView::Inspect;
        if self.model.inspection.is_none() && !self.inspection_loading {
            self.refresh_inspection(cx);
        } else {
            cx.notify();
        }
    }

    fn show_resources(&mut self, cx: &mut Context<Self>) {
        if self.model.detail_view == DetailView::Files {
            self.close_file_panel(cx);
        }
        if self.model.detail_view == DetailView::Security {
            self.leave_security_view();
        }
        self.model.detail_view = DetailView::Resources;
        self.error = None;
        self.refresh_resources(cx);
        cx.notify();
    }

    fn abort_all(&mut self) {
        for abort in [
            &mut self.containers_abort,
            &mut self.stats_abort,
            &mut self.images_abort,
            &mut self.security_abort,
            &mut self.networks_abort,
            &mut self.volumes_abort,
            &mut self.compose_abort,
            &mut self.network_inspection_abort,
            &mut self.inspection_abort,
            &mut self.logs_abort,
            &mut self.action_plan_abort,
            &mut self.file_read_abort,
            &mut self.file_plan_abort,
            &mut self.resource_plan_abort,
        ] {
            if let Some(abort) = abort.take() {
                abort.abort();
            }
        }
    }

    fn set_all_loading(&mut self, value: bool) {
        self.containers_loading = value;
        self.stats_loading = value;
        self.images_loading = value;
        self.security_loading = value;
        self.networks_loading = value;
        self.volumes_loading = value;
        self.compose_loading = value;
        self.network_inspection_loading = value;
        self.inspection_loading = value;
        self.logs_loading = value;
    }

    fn render_container_list(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let rows = self
            .model
            .filtered_containers()
            .into_iter()
            .map(|container| {
                let identity = container.identity.clone();
                let selected = self.model.selected.as_ref() == Some(&container.identity);
                let stats = self.model.stats_for(&container.identity);
                let status_color = match container.state.as_str() {
                    "running" => tokens.success,
                    "paused" => tokens.warning,
                    _ => tokens.muted,
                };
                div()
                    .mb_2()
                    .rounded_md()
                    .border_1()
                    .border_color(if selected {
                        tokens.accent
                    } else {
                        tokens.border
                    })
                    .bg(if selected {
                        tokens.surface_alt
                    } else {
                        tokens.surface
                    })
                    .p_2()
                    .child(
                        crate::buttons::button(SharedString::from(format!(
                            "docker-container-{}",
                            container.identity.id()
                        )))
                        .label(container.name.clone())
                        .small()
                        .on_click(
                            cx.listener(move |page, _, _, cx| page.select_container(&identity, cx)),
                        ),
                    )
                    .child(
                        div()
                            .mt_1()
                            .text_xs()
                            .text_color(tokens.muted)
                            .child(format!(
                                "{} · {} · {}",
                                container.image,
                                container.status,
                                container.identity.id()
                            )),
                    )
                    .child(
                        div()
                            .mt_1()
                            .flex()
                            .items_center()
                            .gap_3()
                            .text_xs()
                            .child(
                                div()
                                    .text_color(status_color)
                                    .child(container.state.clone()),
                            )
                            .child(format!(
                                "CPU {} · MEM {} · PID {}",
                                stats.map(|value| value.cpu_percent.as_str()).unwrap_or("-"),
                                stats
                                    .map(|value| value.memory_percent.as_str())
                                    .unwrap_or("-"),
                                stats
                                    .and_then(|value| value.pids)
                                    .map(|value| value.to_string())
                                    .unwrap_or_else(|| "-".to_owned())
                            )),
                    )
                    .into_any_element()
            })
            .collect::<Vec<_>>();
        div()
            .flex_1()
            .min_h_0()
            .overflow_y_scrollbar()
            .children(rows)
            .into_any_element()
    }

    fn render_images(&self, tokens: ThemeTokens) -> AnyElement {
        let images = self.model.images.iter().take(100).map(|image| {
            div()
                .py_1()
                .border_b_1()
                .border_color(tokens.border)
                .text_xs()
                .child(format!(
                    "{}:{} · {} · {}",
                    image.repository, image.tag, image.size, image.id
                ))
        });
        div()
            .h(px(150.0))
            .min_h(px(100.0))
            .overflow_y_scrollbar()
            .children(images)
            .into_any_element()
    }

    fn render_network_inspection(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let selected = self.model.selected_network();
        let title = selected
            .map(|network| network.name.as_str())
            .unwrap_or("Docker 网络");
        let Some(inspection) = self.model.network_inspection.as_ref() else {
            return div()
                .flex_1()
                .min_h_0()
                .flex()
                .flex_col()
                .gap_3()
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_3()
                        .child(
                            div()
                                .flex_1()
                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                .child(format!("网络详情 · {title}")),
                        )
                        .child(
                            crate::buttons::button("docker-network-inspect-back-empty")
                                .label("返回资源清单")
                                .small()
                                .on_click(
                                    cx.listener(|page, _, _, cx| page.close_network_inspection(cx)),
                                ),
                        ),
                )
                .child(
                    div()
                        .flex_1()
                        .items_center()
                        .justify_center()
                        .flex()
                        .flex_col()
                        .gap_3()
                        .text_color(tokens.muted)
                        .child(if self.network_inspection_loading {
                            "正在读取并核对网络详情…"
                        } else {
                            "网络详情未加载或加载失败"
                        })
                        .when(!self.network_inspection_loading, |view| {
                            view.child(
                                crate::buttons::button("docker-network-inspect-retry")
                                    .label("重试")
                                    .small()
                                    .on_click(cx.listener(|page, _, _, cx| {
                                        page.refresh_network_inspection(cx)
                                    })),
                            )
                        }),
                )
                .into_any_element();
        };
        let ipam = inspection
            .ipam
            .iter()
            .take(64)
            .map(|config| {
                div()
                    .rounded_md()
                    .bg(tokens.surface_alt)
                    .p_2()
                    .text_xs()
                    .font_family("Cascadia Mono")
                    .child(format!(
                        "子网 {} · 网关 {} · 地址池 {}",
                        if config.subnet.is_empty() {
                            "-"
                        } else {
                            config.subnet.as_str()
                        },
                        if config.gateway.is_empty() {
                            "-"
                        } else {
                            config.gateway.as_str()
                        },
                        if config.ip_range.is_empty() {
                            "-"
                        } else {
                            config.ip_range.as_str()
                        }
                    ))
                    .into_any_element()
            })
            .collect::<Vec<_>>();
        let attachments = inspection
            .attachments
            .iter()
            .take(200)
            .map(|attachment| {
                div()
                    .rounded_md()
                    .border_1()
                    .border_color(tokens.border)
                    .p_2()
                    .child(div().font_weight(gpui::FontWeight::SEMIBOLD).child(
                        if attachment.name.is_empty() {
                            attachment.container_id.clone()
                        } else {
                            attachment.name.clone()
                        },
                    ))
                    .child(
                        div()
                            .mt_1()
                            .text_xs()
                            .font_family("Cascadia Mono")
                            .text_color(tokens.muted)
                            .child(format!(
                                "{} · IPv4 {} · IPv6 {} · MAC {}",
                                attachment.container_id,
                                if attachment.ipv4_address.is_empty() {
                                    "-"
                                } else {
                                    attachment.ipv4_address.as_str()
                                },
                                if attachment.ipv6_address.is_empty() {
                                    "-"
                                } else {
                                    attachment.ipv6_address.as_str()
                                },
                                if attachment.mac_address.is_empty() {
                                    "-"
                                } else {
                                    attachment.mac_address.as_str()
                                }
                            )),
                    )
                    .into_any_element()
            })
            .collect::<Vec<_>>();
        let options = inspection
            .options
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join("\n");
        let labels = inspection
            .labels
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join("\n");
        let network_for_remove = inspection.network.clone();
        let resource_operation_active = self.resource_operation_active();
        let protected = matches!(inspection.network.name.as_str(), "bridge" | "host" | "none")
            || inspection.ingress;
        let has_attachments = !inspection.attachments.is_empty();
        div()
            .flex_1()
            .min_h_0()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(
                        div()
                            .flex_1()
                            .child(
                                div()
                                    .font_weight(gpui::FontWeight::SEMIBOLD)
                                    .child(format!("网络详情 · {}", inspection.network.name)),
                            )
                            .child(
                                div()
                                    .mt_1()
                                    .text_xs()
                                    .font_family("Cascadia Mono")
                                    .text_color(tokens.muted)
                                    .child(inspection.network.id.clone()),
                            ),
                    )
                    .when(!protected, |header| {
                        header.child(
                            crate::buttons::button("docker-network-inspect-remove")
                                .label(if has_attachments {
                                    "仍有容器连接"
                                } else {
                                    "删除网络"
                                })
                                .small()
                                .danger()
                                .disabled(resource_operation_active || has_attachments)
                                .on_click(cx.listener(move |page, _, _, cx| {
                                    page.prepare_resource_mutation(
                                        DockerResourceMutationRequest::RemoveNetwork {
                                            network: network_for_remove.clone(),
                                        },
                                        cx,
                                    )
                                })),
                        )
                    })
                    .child(
                        crate::buttons::button("docker-network-inspect-refresh")
                            .label(if self.network_inspection_loading {
                                "刷新中…"
                            } else {
                                "刷新详情"
                            })
                            .small()
                            .disabled(self.network_inspection_loading || resource_operation_active)
                            .on_click(
                                cx.listener(|page, _, _, cx| page.refresh_network_inspection(cx)),
                            ),
                    )
                    .child(
                        crate::buttons::button("docker-network-inspect-back")
                            .label("返回资源清单")
                            .small()
                            .on_click(
                                cx.listener(|page, _, _, cx| page.close_network_inspection(cx)),
                            ),
                    ),
            )
            .child(
                div()
                    .rounded_md()
                    .bg(tokens.surface_alt)
                    .p_3()
                    .text_xs()
                    .child(format!(
                        "驱动 {} · 范围 {} · IPAM {} · 内部 {} · IPv6 {} · 可附加 {} · Ingress {}",
                        inspection.network.driver,
                        inspection.network.scope,
                        inspection.ipam_driver,
                        if inspection.network.internal {
                            "是"
                        } else {
                            "否"
                        },
                        if inspection.network.ipv6 {
                            "是"
                        } else {
                            "否"
                        },
                        if inspection.attachable { "是" } else { "否" },
                        if inspection.ingress { "是" } else { "否" }
                    )),
            )
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scrollbar()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(
                        div()
                            .text_sm()
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child(format!("IPAM 配置 · {}", inspection.ipam.len())),
                    )
                    .when(ipam.is_empty(), |view| {
                        view.child(
                            div()
                                .text_xs()
                                .text_color(tokens.muted)
                                .child("无 IPAM 配置"),
                        )
                    })
                    .children(ipam)
                    .child(
                        div()
                            .mt_2()
                            .text_sm()
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child(format!(
                                "已连接容器 · {}{}",
                                inspection.attachments.len(),
                                if inspection.attachments.len() > 200 {
                                    "（界面展示前 200 项）"
                                } else {
                                    ""
                                }
                            )),
                    )
                    .when(attachments.is_empty(), |view| {
                        view.child(
                            div()
                                .text_xs()
                                .text_color(tokens.muted)
                                .child("无已连接容器"),
                        )
                    })
                    .children(attachments)
                    .when(!options.is_empty(), |view| {
                        view.child(
                            div()
                                .mt_2()
                                .text_sm()
                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                .child("网络选项"),
                        )
                        .child(
                            div()
                                .rounded_md()
                                .bg(tokens.surface_alt)
                                .p_2()
                                .text_xs()
                                .font_family("Cascadia Mono")
                                .child(options.clone()),
                        )
                    })
                    .when(!labels.is_empty(), |view| {
                        view.child(
                            div()
                                .mt_2()
                                .text_sm()
                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                .child("标签"),
                        )
                        .child(
                            div()
                                .rounded_md()
                                .bg(tokens.surface_alt)
                                .p_2()
                                .text_xs()
                                .font_family("Cascadia Mono")
                                .child(labels.clone()),
                        )
                    }),
            )
            .into_any_element()
    }

    fn render_resources(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        if self.model.selected_network.is_some() {
            return self.render_network_inspection(tokens, cx);
        }
        let networks = self
            .model
            .networks
            .iter()
            .map(|network| {
                let network_id = network.id.clone();
                let network_for_remove = network.clone();
                let resource_operation_active = self.resource_operation_active();
                let protected = matches!(network.name.as_str(), "bridge" | "host" | "none");
                let driver = if network.driver.is_empty() {
                    "-"
                } else {
                    network.driver.as_str()
                };
                let scope = if network.scope.is_empty() {
                    "-"
                } else {
                    network.scope.as_str()
                };
                div()
                    .rounded_md()
                    .border_1()
                    .border_color(tokens.border)
                    .bg(tokens.surface_alt)
                    .p_3()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(
                                div()
                                    .flex_1()
                                    .font_weight(gpui::FontWeight::SEMIBOLD)
                                    .child(network.name.clone()),
                            )
                            .child(
                                crate::buttons::button(SharedString::from(format!(
                                    "docker-network-inspect-{}",
                                    network.id
                                )))
                                .label("查看详情")
                                .xsmall()
                                .on_click(cx.listener(
                                    move |page, _, _, cx| page.select_network(&network_id, cx),
                                )),
                            )
                            .when(!protected, |row| {
                                row.child(
                                    crate::buttons::button(SharedString::from(format!(
                                        "docker-network-remove-{}",
                                        network_for_remove.id
                                    )))
                                    .label("删除")
                                    .xsmall()
                                    .danger()
                                    .disabled(resource_operation_active)
                                    .on_click(cx.listener(move |page, _, _, cx| {
                                        page.prepare_resource_mutation(
                                            DockerResourceMutationRequest::RemoveNetwork {
                                                network: network_for_remove.clone(),
                                            },
                                            cx,
                                        )
                                    })),
                                )
                            }),
                    )
                    .child(
                        div()
                            .mt_1()
                            .text_xs()
                            .text_color(tokens.muted)
                            .child(format!(
                                "驱动 {driver} · 范围 {scope} · 内部 {} · IPv6 {}",
                                if network.internal { "是" } else { "否" },
                                if network.ipv6 { "是" } else { "否" }
                            )),
                    )
                    .child(
                        div()
                            .mt_1()
                            .text_xs()
                            .font_family("Cascadia Mono")
                            .text_color(tokens.muted)
                            .child(network.id.clone()),
                    )
                    .into_any_element()
            })
            .collect::<Vec<_>>();
        let volumes =
            self.model
                .volumes
                .iter()
                .map(|volume| {
                    let volume_for_remove = volume.clone();
                    let resource_operation_active = self.resource_operation_active();
                    let driver = if volume.driver.is_empty() {
                        "-"
                    } else {
                        volume.driver.as_str()
                    };
                    let scope = if volume.scope.is_empty() {
                        "-"
                    } else {
                        volume.scope.as_str()
                    };
                    div()
                        .rounded_md()
                        .border_1()
                        .border_color(tokens.border)
                        .bg(tokens.surface_alt)
                        .p_3()
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap_2()
                                .child(
                                    div()
                                        .flex_1()
                                        .font_weight(gpui::FontWeight::SEMIBOLD)
                                        .child(volume.name.clone()),
                                )
                                .child(
                                    crate::buttons::button(SharedString::from(format!(
                                        "docker-volume-remove-{}",
                                        volume_for_remove.name
                                    )))
                                    .label("删除")
                                    .xsmall()
                                    .danger()
                                    .disabled(resource_operation_active)
                                    .on_click(cx.listener(move |page, _, _, cx| {
                                        page.prepare_resource_mutation(
                                            DockerResourceMutationRequest::RemoveVolume {
                                                volume: volume_for_remove.clone(),
                                            },
                                            cx,
                                        )
                                    })),
                                ),
                        )
                        .child(
                            div()
                                .mt_1()
                                .text_xs()
                                .text_color(tokens.muted)
                                .child(format!("驱动 {driver} · 范围 {scope}")),
                        )
                        .when(!volume.mountpoint.is_empty(), |view| {
                            view.child(
                                div()
                                    .mt_1()
                                    .text_xs()
                                    .font_family("Cascadia Mono")
                                    .text_color(tokens.muted)
                                    .child(volume.mountpoint.clone()),
                            )
                        })
                        .when(!volume.labels.is_empty(), |view| {
                            view.child(
                                div()
                                    .mt_1()
                                    .text_xs()
                                    .text_color(tokens.muted)
                                    .child(format!("标签：{}", volume.labels)),
                            )
                        })
                        .into_any_element()
                })
                .collect::<Vec<_>>();
        let compose_projects = self
            .model
            .compose_projects
            .iter()
            .map(|project| {
                let actions = DockerComposeAction::ALL
                    .into_iter()
                    .map(|action| {
                        let project = project.clone();
                        let mut button = crate::buttons::button(SharedString::from(format!(
                            "docker-compose-{}-{}",
                            action.id(),
                            project.name
                        )))
                        .label(action.label())
                        .xsmall()
                        .disabled(
                            self.resource_operation_active() || !action.is_available(&project),
                        );
                        if action == DockerComposeAction::Down {
                            button = button.danger();
                        }
                        button
                            .on_click(cx.listener(move |page, _, _, cx| {
                                page.prepare_compose_action(project.clone(), action, cx)
                            }))
                            .into_any_element()
                    })
                    .collect::<Vec<_>>();
                div()
                    .rounded_md()
                    .border_1()
                    .border_color(tokens.border)
                    .bg(tokens.surface_alt)
                    .p_3()
                    .child(
                        div()
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child(project.name.clone()),
                    )
                    .child(
                        div()
                            .mt_1()
                            .text_xs()
                            .text_color(tokens.muted)
                            .child(format!(
                                "{} · 服务 {} · 运行 {} · 停止 {}",
                                project.status, project.services, project.running, project.stopped
                            )),
                    )
                    .when(!project.config_files.is_empty(), |view| {
                        view.child(
                            div()
                                .mt_1()
                                .text_xs()
                                .font_family("Cascadia Mono")
                                .text_color(tokens.muted)
                                .child(project.config_files.clone()),
                        )
                    })
                    .child(div().mt_2().flex().flex_wrap().gap_2().children(actions))
                    .into_any_element()
            })
            .collect::<Vec<_>>();
        let loading = self.networks_loading || self.volumes_loading || self.compose_loading;
        div()
            .flex_1()
            .min_h_0()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(
                        div()
                            .flex_1()
                            .child(
                                div()
                                    .font_weight(gpui::FontWeight::SEMIBOLD)
                                    .child("Docker 网络、数据卷与 Compose"),
                            )
                            .child(
                                div()
                                    .mt_1()
                                    .text_xs()
                                    .text_color(tokens.muted)
                                    .child(format!(
                                        "网络 {} · 数据卷 {} · Compose 项目 {} · 操作前均重新绑定精确快照",
                                        self.model.networks.len(),
                                        self.model.volumes.len(),
                                        self.model.compose_projects.len()
                                    )),
                            ),
                    )
                    .child(
                        crate::buttons::button("docker-resources-refresh")
                            .label(if loading {
                                "刷新中…"
                            } else {
                                "刷新清单"
                            })
                            .small()
                            .disabled(loading || self.resource_operation_active())
                            .on_click(cx.listener(|page, _, _, cx| page.refresh_resources(cx))),
                    )
                    .child(
                        crate::buttons::button("docker-resources-back")
                            .label("返回容器详情")
                            .small()
                            .on_click(cx.listener(|page, _, _, cx| page.show_inspection(cx))),
                    ),
            )
            .when(
                self.model.networks_truncated
                    || self.model.volumes_truncated
                    || self.model.compose_truncated,
                |view| {
                    view.child(
                        div()
                            .rounded_md()
                            .bg(tokens.surface_alt)
                            .p_2()
                            .text_xs()
                            .text_color(tokens.warning)
                            .child("网络、数据卷或 Compose 清单已在 1,000 项边界截断"),
                    )
                },
            )
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .flex()
                    .gap_3()
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .flex()
                            .flex_col()
                            .gap_2()
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child(
                                        div()
                                            .flex_1()
                                            .text_sm()
                                            .font_weight(gpui::FontWeight::SEMIBOLD)
                                            .child("网络"),
                                    )
                                    .child(
                                        crate::buttons::button("docker-network-prune")
                                            .label("清理未使用")
                                            .xsmall()
                                            .danger()
                                            .disabled(
                                                self.resource_operation_active()
                                                    || self.networks_loading
                                                    || self.model.networks_truncated,
                                            )
                                            .on_click(cx.listener(|page, _, _, cx| {
                                                page.prepare_resource_mutation(
                                                    DockerResourceMutationRequest::PruneNetworks {
                                                        runtime: ContainerRuntime::Docker,
                                                    },
                                                    cx,
                                                )
                                            })),
                                    ),
                            )
                            .child(
                                div()
                                    .flex_1()
                                    .min_h_0()
                                    .overflow_y_scrollbar()
                                    .flex()
                                    .flex_col()
                                    .gap_2()
                                    .when(networks.is_empty(), |view| {
                                        view.child(div().text_xs().text_color(tokens.muted).child(
                                            if self.networks_loading {
                                                "正在读取 Docker 网络…"
                                            } else {
                                                "未发现 Docker 网络"
                                            },
                                        ))
                                    })
                                    .children(networks),
                            ),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .flex()
                            .flex_col()
                            .gap_2()
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child(
                                        div()
                                            .flex_1()
                                            .text_sm()
                                            .font_weight(gpui::FontWeight::SEMIBOLD)
                                            .child("数据卷"),
                                    )
                                    .child(
                                        crate::buttons::button("docker-volume-prune")
                                            .label("清理未使用")
                                            .xsmall()
                                            .danger()
                                            .disabled(
                                                self.resource_operation_active()
                                                    || self.volumes_loading
                                                    || self.model.volumes_truncated,
                                            )
                                            .on_click(cx.listener(|page, _, _, cx| {
                                                page.prepare_resource_mutation(
                                                    DockerResourceMutationRequest::PruneVolumes {
                                                        runtime: ContainerRuntime::Docker,
                                                    },
                                                    cx,
                                                )
                                            })),
                                    ),
                            )
                            .child(
                                div()
                                    .flex_1()
                                    .min_h_0()
                                    .overflow_y_scrollbar()
                                    .flex()
                                    .flex_col()
                                    .gap_2()
                                    .when(volumes.is_empty(), |view| {
                                        view.child(div().text_xs().text_color(tokens.muted).child(
                                            if self.volumes_loading {
                                                "正在读取 Docker 数据卷…"
                                            } else {
                                                "未发现 Docker 数据卷"
                                            },
                                        ))
                                    })
                                    .children(volumes),
                            ),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .flex()
                            .flex_col()
                            .gap_2()
                            .child(
                                div()
                                    .text_sm()
                                    .font_weight(gpui::FontWeight::SEMIBOLD)
                                    .child("Compose"),
                            )
                            .child(
                                div()
                                    .flex_1()
                                    .min_h_0()
                                    .overflow_y_scrollbar()
                                    .flex()
                                    .flex_col()
                                    .gap_2()
                                    .when(compose_projects.is_empty(), |view| {
                                        view.child(div().text_xs().text_color(tokens.muted).child(
                                            if self.compose_loading {
                                                "正在发现 Compose 项目…"
                                            } else {
                                                "未发现 Compose 项目或插件不可用"
                                            },
                                        ))
                                    })
                                    .children(compose_projects),
                            ),
                    ),
            )
            .into_any_element()
    }

    fn render_security_audit(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let Some(audit) = self.model.security_audit.as_ref() else {
            return div()
                .flex_1()
                .flex()
                .flex_col()
                .items_center()
                .justify_center()
                .gap_3()
                .text_color(tokens.muted)
                .child(if self.security_loading {
                    "正在执行 Docker 安全审计…"
                } else {
                    "尚未运行安全审计"
                })
                .child(
                    crate::buttons::button("docker-security-back-empty")
                        .label("返回容器详情")
                        .small()
                        .on_click(cx.listener(|page, _, _, cx| page.show_inspection(cx))),
                )
                .into_any_element();
        };
        let summary = &audit.summary;
        let score_color = if summary.score >= 80 {
            tokens.success
        } else if summary.score >= 50 {
            tokens.warning
        } else {
            tokens.danger
        };
        let findings = audit
            .findings
            .iter()
            .map(|finding| {
                let severity_color = match finding.severity {
                    DockerSecuritySeverity::Critical => tokens.danger,
                    DockerSecuritySeverity::High => tokens.warning,
                    DockerSecuritySeverity::Medium => gpui::rgb(0xc26a16),
                    DockerSecuritySeverity::Low => tokens.muted,
                    DockerSecuritySeverity::Info => tokens.accent,
                };
                let container = if finding.container_name.is_empty() {
                    finding.container.id().to_owned()
                } else {
                    finding.container_name.clone()
                };
                div()
                    .rounded_md()
                    .border_1()
                    .border_color(tokens.border)
                    .bg(tokens.surface_alt)
                    .p_3()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(
                                div()
                                    .text_xs()
                                    .font_weight(gpui::FontWeight::SEMIBOLD)
                                    .text_color(severity_color)
                                    .child(finding.severity.label()),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(tokens.muted)
                                    .child(finding.category.label()),
                            )
                            .child(
                                div()
                                    .ml_auto()
                                    .text_xs()
                                    .font_family("Cascadia Mono")
                                    .text_color(tokens.muted)
                                    .child(container),
                            ),
                    )
                    .child(div().mt_2().text_sm().child(finding.description.clone()))
                    .child(
                        div()
                            .mt_1()
                            .text_xs()
                            .text_color(tokens.muted)
                            .child(format!("建议：{}", finding.remediation)),
                    )
                    .into_any_element()
            })
            .collect::<Vec<_>>();
        div()
            .flex_1()
            .min_h_0()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(
                        div()
                            .w(px(92.0))
                            .h(px(72.0))
                            .rounded_lg()
                            .border_1()
                            .border_color(score_color)
                            .flex()
                            .flex_col()
                            .items_center()
                            .justify_center()
                            .child(
                                div()
                                    .text_2xl()
                                    .font_weight(gpui::FontWeight::BOLD)
                                    .text_color(score_color)
                                    .child(summary.score.to_string()),
                            )
                            .child(div().text_xs().text_color(tokens.muted).child("安全评分")),
                    )
                    .child(
                        div()
                            .flex_1()
                            .child(div().font_weight(gpui::FontWeight::SEMIBOLD).child(format!(
                                "扫描 {} 个容器 · {} 项发现",
                                audit.containers_scanned, summary.total
                            )))
                            .child(
                                div()
                                    .mt_1()
                                    .text_xs()
                                    .text_color(tokens.muted)
                                    .child(format!(
                                        "严重 {} · 高危 {} · 中危 {} · 低危 {} · 信息 {}",
                                        summary.critical,
                                        summary.high,
                                        summary.medium,
                                        summary.low,
                                        summary.info
                                    )),
                            )
                            .when(audit.truncated, |view| {
                                view.child(
                                    div()
                                        .mt_1()
                                        .text_xs()
                                        .text_color(tokens.warning)
                                        .child("容器清单或发现已在安全边界截断"),
                                )
                            }),
                    )
                    .child(
                        crate::buttons::button("docker-security-back")
                            .label("返回容器详情")
                            .small()
                            .on_click(cx.listener(|page, _, _, cx| page.show_inspection(cx))),
                    ),
            )
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scrollbar()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .when(findings.is_empty(), |view| {
                        view.child(
                            div()
                                .rounded_md()
                                .border_1()
                                .border_color(tokens.success)
                                .p_3()
                                .text_color(tokens.success)
                                .child("本次八类检查未发现风险；这不等同于完整镜像漏洞扫描。"),
                        )
                    })
                    .children(findings),
            )
            .into_any_element()
    }

    fn render_detail(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        if self.model.detail_view == DetailView::Security {
            return self.render_security_audit(tokens, cx);
        }
        if self.model.detail_view == DetailView::Resources {
            return self.render_resources(tokens, cx);
        }
        let Some(container) = self.model.selected_container() else {
            return div()
                .flex_1()
                .items_center()
                .justify_center()
                .text_color(tokens.muted)
                .child("选择容器以查看类型化详情")
                .into_any_element();
        };
        let title = format!("{} · {}", container.name, container.identity.id());
        let body = match self.model.detail_view {
            DetailView::Inspect => self.render_inspection(tokens),
            DetailView::Logs => self.render_logs(tokens),
            DetailView::Files => self.render_files(tokens, cx),
            DetailView::Security => {
                unreachable!("security view is rendered before container detail")
            }
            DetailView::Resources => {
                unreachable!("resource view is rendered before container detail")
            }
        };
        let terminal_enabled = self.container_terminal_launch(cx).is_ok();
        let file_panel_open = self.model.detail_view == DetailView::Files;
        let operation_busy = self.action_busy
            || self.pending_action.is_some()
            || self.file_busy
            || self.pending_file_write.is_some()
            || self.pending_file_copy.is_some()
            || self.resource_operation_active()
            || file_panel_open;
        let state = container.state.clone();
        let action_buttons = ContainerAction::ALL
            .into_iter()
            .map(|action| {
                let enabled = action.is_available_in_state(&state) && !operation_busy;
                let button = crate::buttons::button(SharedString::from(format!(
                    "docker-action-{}",
                    action.id()
                )))
                .label(action.label())
                .xsmall()
                .disabled(!enabled)
                .on_click(cx.listener(move |page, _, _, cx| page.prepare_action(action, cx)));
                if matches!(
                    action,
                    ContainerAction::Stop | ContainerAction::Kill | ContainerAction::Remove
                ) {
                    button.danger()
                } else {
                    button
                }
            })
            .collect::<Vec<_>>();
        div()
            .flex_1()
            .min_h_0()
            .flex()
            .flex_col()
            .gap_2()
            .child(div().font_weight(gpui::FontWeight::SEMIBOLD).child(title))
            .child(
                div()
                    .flex()
                    .gap_2()
                    .child(
                        crate::buttons::button("docker-detail-inspect")
                            .label("类型化 Inspect")
                            .small()
                            .on_click(cx.listener(|page, _, _, cx| page.show_inspection(cx))),
                    )
                    .child(
                        crate::buttons::button("docker-detail-logs")
                            .label("最近 200 行日志")
                            .small()
                            .on_click(cx.listener(|page, _, _, cx| page.refresh_logs(cx))),
                    ),
            )
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_2()
                    .children(action_buttons)
                    .child(
                        crate::buttons::button("docker-action-terminal")
                            .label("容器终端")
                            .xsmall()
                            .disabled(!terminal_enabled || operation_busy)
                            .on_click(
                                cx.listener(|page, _, _, cx| page.request_container_terminal(cx)),
                            ),
                    )
                    .child(
                        crate::buttons::button("docker-action-file-editor")
                            .label("文件编辑")
                            .xsmall()
                            .disabled(operation_busy)
                            .on_click(
                                cx.listener(|page, _, window, cx| page.open_file_panel(window, cx)),
                            ),
                    )
                    .child(
                        crate::buttons::button("docker-action-file-copy")
                            .label("文件复制")
                            .xsmall()
                            .disabled(operation_busy)
                            .on_click(
                                cx.listener(|page, _, window, cx| page.open_copy_panel(window, cx)),
                            ),
                    ),
            )
            .child(body)
            .into_any_element()
    }

    fn render_files(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        match self.file_tool_mode {
            FileToolMode::Edit => self.render_file_editor(tokens, cx),
            FileToolMode::Copy => self.render_file_copy(tokens, cx),
        }
    }

    fn render_file_editor(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let pending = self.pending_file_write.as_ref().map(|pending| {
            (
                pending.plan.definition().summary.clone(),
                pending.plan.path().as_str().to_owned(),
                pending.plan.content_bytes(),
                pending.plan.content_sha256().to_owned(),
            )
        });
        let loaded = self.loaded_file.as_ref();
        let content = loaded.map(DockerFileContent::content).unwrap_or_default();
        let has_pending = pending.is_some();
        div()
            .flex_1()
            .min_h_0()
            .flex()
            .flex_col()
            .gap_2()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(div().flex_1().child(Input::new(&self.file_path_input)))
                    .child(
                        crate::buttons::button("docker-file-load")
                            .label(if self.file_busy {
                                "处理中…"
                            } else {
                                "加载"
                            })
                            .small()
                            .disabled(self.file_busy || self.pending_file_write.is_some())
                            .on_click(cx.listener(|page, _, _, cx| page.load_container_file(cx))),
                    )
                    .child(
                        crate::buttons::close_button("docker-file-close")
                            .small()
                            .on_click(cx.listener(|page, _, _, cx| page.close_file_panel(cx))),
                    ),
            )
            .child(div().text_xs().text_color(tokens.muted).child(format!(
                "仅打开普通 UTF-8 文件，最大 {} MiB；加载与保存均校验长度和 SHA-256。",
                MAX_CONTAINER_FILE_BYTES / 1024 / 1024
            )))
            .when_some(pending, |view, (summary, path, bytes, sha256)| {
                view.child(
                    div()
                        .rounded_lg()
                        .border_1()
                        .border_color(tokens.danger)
                        .bg(tokens.surface)
                        .p_3()
                        .child(
                            div()
                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                .text_color(tokens.danger)
                                .child("确认原子写入容器文件"),
                        )
                        .child(div().mt_1().text_sm().child(summary))
                        .child(
                            div()
                                .mt_1()
                                .text_xs()
                                .text_color(tokens.muted)
                                .child(format!("路径：{path} · {bytes} 字节 · SHA-256 {sha256}")),
                        )
                        .child(
                            div()
                                .mt_3()
                                .flex()
                                .justify_end()
                                .gap_2()
                                .child(
                                    crate::buttons::button("docker-file-plan-cancel")
                                        .label("取消")
                                        .disabled(self.file_busy)
                                        .on_click(cx.listener(|page, _, _, cx| {
                                            page.cancel_pending_file_write(cx)
                                        })),
                                )
                                .child(
                                    crate::buttons::button("docker-file-plan-approve")
                                        .label("确认保存")
                                        .danger()
                                        .disabled(self.file_busy)
                                        .on_click(cx.listener(|page, _, _, cx| {
                                            page.approve_pending_file_write(cx)
                                        })),
                                ),
                        ),
                )
            })
            .when(self.file_editing && !has_pending, |view| {
                view.child(
                    div()
                        .flex_1()
                        .min_h(px(260.0))
                        .child(Input::new(&self.file_content_input).h_full()),
                )
                .child(
                    div()
                        .flex()
                        .justify_between()
                        .items_center()
                        .child(div().text_xs().text_color(tokens.muted).child(format!(
                            "当前编辑 {} 字节",
                            self.file_content_input.read(cx).value().len()
                        )))
                        .child(
                            div()
                                .flex()
                                .gap_2()
                                .child(
                                    crate::buttons::button("docker-file-edit-cancel")
                                        .label("放弃编辑")
                                        .disabled(self.file_busy)
                                        .on_click(
                                            cx.listener(|page, _, _, cx| page.cancel_file_edit(cx)),
                                        ),
                                )
                                .child(
                                    crate::buttons::button("docker-file-edit-save")
                                        .label("创建保存计划")
                                        .disabled(self.file_busy)
                                        .on_click(cx.listener(|page, _, _, cx| {
                                            page.prepare_file_write(cx)
                                        })),
                                ),
                        ),
                )
            })
            .when(!self.file_editing && loaded.is_some(), |view| {
                view.child(
                    div()
                        .flex_1()
                        .min_h(px(260.0))
                        .overflow_scrollbar()
                        .rounded_md()
                        .border_1()
                        .border_color(tokens.border)
                        .bg(tokens.terminal_background)
                        .p_3()
                        .font_family("Cascadia Mono")
                        .text_sm()
                        .text_color(gpui::rgb(0xe5edf7))
                        .child(content.to_owned()),
                )
                .child(
                    div()
                        .flex()
                        .justify_between()
                        .items_center()
                        .child(div().text_xs().text_color(tokens.muted).child(format!(
                            "{} 字节 · SHA-256 {}",
                            loaded.map(DockerFileContent::content_bytes).unwrap_or(0),
                            loaded.map(DockerFileContent::sha256).unwrap_or("-")
                        )))
                        .child(
                            crate::buttons::button("docker-file-edit")
                                .label("编辑")
                                .disabled(self.file_busy)
                                .on_click(cx.listener(|page, _, window, cx| {
                                    page.begin_file_edit(window, cx)
                                })),
                        ),
                )
            })
            .when(
                !self.file_editing && loaded.is_none() && !has_pending,
                |view| {
                    view.child(
                        div()
                            .flex_1()
                            .items_center()
                            .justify_center()
                            .text_color(tokens.muted)
                            .child("输入容器内文件绝对路径并加载"),
                    )
                },
            )
            .into_any_element()
    }

    fn render_file_copy(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let pending = self.pending_file_copy.as_ref().map(|pending| {
            (
                pending.plan.definition().summary.clone(),
                pending.plan.direction().label(),
                pending.plan.source_path().to_owned(),
                pending.plan.target_path().to_owned(),
                pending.plan.source_bytes(),
                pending.plan.source_sha256().to_owned(),
            )
        });
        let has_pending = pending.is_some();
        let (source_label, target_label) = match self.copy_direction {
            DockerFileCopyDirection::ContainerToHost => ("容器内源文件", "远端主机目标文件"),
            DockerFileCopyDirection::HostToContainer => ("远端主机源文件", "容器内目标文件"),
            DockerFileCopyDirection::InContainer => ("容器内源文件", "容器内目标文件"),
        };
        let direction_buttons = DockerFileCopyDirection::ALL
            .into_iter()
            .map(|direction| {
                let button = crate::buttons::button(SharedString::from(format!(
                    "docker-copy-direction-{}",
                    direction.id()
                )))
                .label(direction.label())
                .small()
                .disabled(self.file_busy || has_pending)
                .on_click(
                    cx.listener(move |page, _, _, cx| page.set_copy_direction(direction, cx)),
                );
                if direction == self.copy_direction {
                    button.primary()
                } else {
                    button
                }
            })
            .collect::<Vec<_>>();
        div()
            .flex_1()
            .min_h_0()
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
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child("容器文件复制"),
                    )
                    .child(
                        crate::buttons::close_button("docker-copy-close")
                            .small()
                            .on_click(cx.listener(|page, _, _, cx| page.close_file_panel(cx))),
                    ),
            )
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_2()
                    .children(direction_buttons),
            )
            .child(
                div()
                    .grid()
                    .grid_cols(2)
                    .gap_3()
                    .child(
                        div()
                            .child(div().mb_1().text_xs().text_color(tokens.muted).child(source_label))
                            .child(Input::new(&self.copy_source_input)),
                    )
                    .child(
                        div()
                            .child(div().mb_1().text_xs().text_color(tokens.muted).child(target_label))
                            .child(Input::new(&self.copy_target_input)),
                    ),
            )
            .child(
                div()
                    .text_xs()
                    .text_color(tokens.muted)
                    .child("“远端主机”始终指当前绑定的 SSH 目标，不是本机 Windows 路径。仅复制普通文件，源与已有目标均限制为 64 MiB；目标父目录必须已存在。"),
            )
            .when_some(
                pending,
                |view, (summary, direction, source, target, bytes, sha256)| {
                    view.child(
                        div()
                            .rounded_lg()
                            .border_1()
                            .border_color(tokens.danger)
                            .bg(tokens.surface)
                            .p_3()
                            .child(
                                div()
                                    .font_weight(gpui::FontWeight::SEMIBOLD)
                                    .text_color(tokens.danger)
                                    .child("确认文件复制"),
                            )
                            .child(div().mt_1().text_sm().child(summary))
                            .child(
                                div()
                                    .mt_1()
                                    .text_xs()
                                    .text_color(tokens.muted)
                                    .child(format!(
                                        "{direction} · {source} → {target} · {bytes} 字节 · SHA-256 {sha256}"
                                    )),
                            )
                            .child(
                                div()
                                    .mt_3()
                                    .flex()
                                    .justify_end()
                                    .gap_2()
                                    .child(
                                        crate::buttons::button("docker-copy-plan-cancel")
                                            .label("取消")
                                            .disabled(self.file_busy)
                                            .on_click(cx.listener(|page, _, _, cx| {
                                                page.cancel_pending_file_copy(cx)
                                            })),
                                    )
                                    .child(
                                        crate::buttons::button("docker-copy-plan-approve")
                                            .label("确认复制")
                                            .danger()
                                            .disabled(self.file_busy)
                                            .on_click(cx.listener(|page, _, _, cx| {
                                                page.approve_pending_file_copy(cx)
                                            })),
                                    ),
                            ),
                    )
                },
            )
            .child(
                div()
                    .mt_auto()
                    .flex()
                    .justify_end()
                    .child(
                        crate::buttons::button("docker-copy-create-plan")
                            .label(if self.file_busy {
                                "正在处理…"
                            } else {
                                "创建复制计划"
                            })
                            .disabled(self.file_busy || has_pending)
                            .on_click(cx.listener(|page, _, _, cx| page.prepare_file_copy(cx))),
                    ),
            )
            .into_any_element()
    }

    fn render_inspection(&self, tokens: ThemeTokens) -> AnyElement {
        if self.inspection_loading {
            return div()
                .text_color(tokens.muted)
                .child("正在读取容器详情…")
                .into_any_element();
        }
        let Some(inspection) = self.model.inspection.as_ref() else {
            return div()
                .text_color(tokens.muted)
                .child("尚未取得类型化详情")
                .into_any_element();
        };
        let fields = inspection.fields.iter().map(|field| {
            div()
                .grid()
                .grid_cols(2)
                .gap_2()
                .py_1()
                .border_b_1()
                .border_color(tokens.border)
                .child(div().text_color(tokens.muted).child(field.label.clone()))
                .child(field.value.clone())
        });
        let mounts = inspection.mounts.iter().map(|mount| {
            div().py_1().text_xs().child(format!(
                "{}: {} → {} ({}, rw={})",
                mount.kind, mount.source, mount.destination, mount.mode, mount.read_write
            ))
        });
        let networks = inspection.networks.iter().map(|network| {
            div().py_1().text_xs().child(format!(
                "{} · IPv4 {} · IPv6 {} · MAC {}",
                network.name, network.ipv4_address, network.ipv6_address, network.mac_address
            ))
        });
        div()
            .flex_1()
            .min_h_0()
            .overflow_y_scrollbar()
            .children(fields)
            .when(!inspection.mounts.is_empty(), |view| {
                view.child(
                    div()
                        .mt_3()
                        .font_weight(gpui::FontWeight::SEMIBOLD)
                        .child("挂载"),
                )
                .children(mounts)
            })
            .when(!inspection.networks.is_empty(), |view| {
                view.child(
                    div()
                        .mt_3()
                        .font_weight(gpui::FontWeight::SEMIBOLD)
                        .child("网络"),
                )
                .children(networks)
            })
            .into_any_element()
    }

    fn render_logs(&self, tokens: ThemeTokens) -> AnyElement {
        if self.logs_loading {
            return div()
                .text_color(tokens.muted)
                .child("正在读取最近日志…")
                .into_any_element();
        }
        let Some(logs) = self.model.logs.as_ref() else {
            return div()
                .text_color(tokens.muted)
                .child("点击“最近 200 行日志”按需加载；不会后台持续跟随。")
                .into_any_element();
        };
        div()
            .flex_1()
            .min_h_0()
            .overflow_y_scrollbar()
            .rounded_md()
            .bg(tokens.terminal_background)
            .p_3()
            .font_family("Cascadia Mono")
            .text_xs()
            .text_color(tokens.text)
            .child(logs.text.clone())
            .when(logs.truncated, |view| {
                view.child(
                    div()
                        .mt_2()
                        .text_color(tokens.warning)
                        .child("日志已在 500,000 字符边界截断"),
                )
            })
            .into_any_element()
    }
}

impl Render for DockerPage {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens = self.shared.read(cx).theme.tokens();
        let target = self
            .model
            .binding()
            .map(DockerBinding::label)
            .unwrap_or_else(|| "未连接目标".to_owned());
        let running = self
            .model
            .containers
            .iter()
            .filter(|container| container.state == "running")
            .count();
        let filtered = self.model.filtered_containers().len();
        let pending_action = self.pending_action.as_ref().map(|pending| {
            (
                pending.plan.definition().summary.clone(),
                pending.plan.action().label(),
                pending.plan.before_state().to_owned(),
            )
        });
        let pending_resource_operation = self.pending_resource_operation.as_ref().map(|pending| {
            (
                pending.plan.definition().summary.clone(),
                pending.plan.label(),
                pending.plan.detail(),
            )
        });
        div()
            .size_full()
            .flex()
            .flex_col()
            .gap_3()
            .p_4()
            .bg(tokens.background)
            .text_color(tokens.text)
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .child(
                                div()
                                    .text_lg()
                                    .font_weight(gpui::FontWeight::SEMIBOLD)
                                    .child("Docker 管理"),
                            )
                            .child(div().text_xs().text_color(tokens.muted).child(target)),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .w(px(560.0))
                            .child(div().flex_1().child(Input::new(&self.search_input).small()))
                            .child(
                                crate::buttons::button("docker-resources")
                                    .label("资源")
                                    .small()
                                    .disabled(
                                        self.action_busy
                                            || self.file_busy
                                            || self.resource_operation_active()
                                            || self.model.detail_view == DetailView::Files,
                                    )
                                    .on_click(cx.listener(|page, _, _, cx| {
                                        page.show_resources(cx)
                                    })),
                            )
                            .child(
                                crate::buttons::button("docker-security-audit")
                                    .label(if self.security_loading {
                                        "审计中…"
                                    } else {
                                        "安全审计"
                                    })
                                    .small()
                                    .disabled(
                                        self.action_busy
                                            || self.file_busy
                                            || self.resource_operation_active()
                                            || self.security_loading
                                            || self.model.detail_view == DetailView::Files,
                                    )
                                    .on_click(cx.listener(|page, _, _, cx| {
                                        page.refresh_security_audit(cx)
                                    })),
                            )
                            .child(
                                crate::buttons::button("docker-refresh")
                                    .label("刷新")
                                    .small()
                                    .disabled(
                                        self.action_busy
                                            || self.file_busy
                                            || self.resource_operation_active()
                                            || self.model.detail_view == DetailView::Files,
                                    )
                                    .on_click(cx.listener(|page, _, _, cx| page.refresh(cx))),
                            ),
                    ),
            )
            .child(
                div()
                    .rounded_md()
                    .border_1()
                    .border_color(tokens.warning)
                    .bg(tokens.surface_alt)
                    .p_2()
                    .text_xs()
                    .child("网络、数据卷、Compose、容器状态与文件操作均绑定目标快照；删除与清理只作用于确认时列出的精确资源集合，不调用全局 prune。所有变更均经计划、确认、执行、日志与回读验证。"),
            )
            .when_some(self.error.clone(), |view, error| {
                view.child(
                    div()
                        .rounded_md()
                        .bg(tokens.surface_alt)
                        .p_2()
                        .text_color(tokens.danger)
                        .child(error),
                )
            })
            .when_some(self.notice.clone(), |view, notice| {
                view.child(div().text_xs().text_color(tokens.warning).child(notice))
            })
            .when_some(
                pending_resource_operation,
                |view, (summary, label, detail)| {
                    view.child(
                        div()
                            .rounded_lg()
                            .border_1()
                            .border_color(tokens.danger)
                            .bg(tokens.surface)
                            .p_3()
                            .flex()
                            .items_center()
                            .gap_3()
                            .child(
                                div()
                                    .flex_1()
                                    .child(
                                        div()
                                            .font_weight(gpui::FontWeight::SEMIBOLD)
                                            .text_color(tokens.danger)
                                            .child(format!("确认资源操作 · {label}")),
                                    )
                                    .child(div().mt_1().text_sm().child(summary))
                                    .child(
                                        div()
                                            .mt_1()
                                            .text_xs()
                                            .font_family("Cascadia Mono")
                                            .text_color(tokens.muted)
                                            .child(detail),
                                    )
                                    .child(
                                        div()
                                            .mt_1()
                                            .text_xs()
                                            .text_color(tokens.warning)
                                            .child("删除与 Compose 操作不可自动恢复；确认仅适用于当前目标 epoch 与计划 ID。"),
                                    ),
                            )
                            .child(
                                crate::buttons::button("docker-resource-cancel-plan")
                                    .label("取消")
                                    .disabled(self.resource_busy)
                                    .on_click(cx.listener(|page, _, _, cx| {
                                        page.cancel_pending_resource_operation(cx)
                                    })),
                            )
                            .child(
                                crate::buttons::button("docker-resource-approve-plan")
                                    .label("确认执行")
                                    .danger()
                                    .disabled(self.resource_busy)
                                    .on_click(cx.listener(|page, _, _, cx| {
                                        page.approve_pending_resource_operation(cx)
                                    })),
                            ),
                    )
                },
            )
            .when_some(pending_action, |view, (summary, action, before_state)| {
                view.child(
                    div()
                        .rounded_lg()
                        .border_1()
                        .border_color(tokens.danger)
                        .bg(tokens.surface)
                        .p_3()
                        .flex()
                        .items_center()
                        .gap_3()
                        .child(
                            div()
                                .flex_1()
                                .child(
                                    div()
                                        .font_weight(gpui::FontWeight::SEMIBOLD)
                                        .text_color(tokens.danger)
                                        .child(format!("确认容器操作 · {action}")),
                                )
                                .child(div().mt_1().text_sm().child(summary))
                                .child(
                                    div()
                                        .mt_1()
                                        .text_xs()
                                        .text_color(tokens.muted)
                                        .child(format!(
                                            "操作前状态：{before_state}。确认仅适用于这一个目标 epoch、容器 ID 与计划 ID。"
                                        )),
                                ),
                        )
                        .child(
                            crate::buttons::button("docker-action-cancel-plan")
                                .label("取消")
                                .disabled(self.action_busy)
                                .on_click(cx.listener(|page, _, _, cx| {
                                    page.cancel_pending_action(cx)
                                })),
                        )
                        .child(
                            crate::buttons::button("docker-action-approve-plan")
                                .label("确认执行")
                                .danger()
                                .disabled(self.action_busy)
                                .on_click(cx.listener(|page, _, _, cx| {
                                    page.approve_pending_action(cx)
                                })),
                        ),
                )
            })
            .child(
                div()
                    .flex()
                    .gap_3()
                    .text_xs()
                    .child(format!("容器 {} · 运行中 {}", self.model.containers.len(), running))
                    .child(format!("筛选结果 {filtered}"))
                    .child(format!("镜像 {}", self.model.images.len()))
                    .child(format!("网络 {}", self.model.networks.len()))
                    .child(format!("卷 {}", self.model.volumes.len()))
                    .child(format!("Compose {}", self.model.compose_projects.len()))
                    .child(if self.containers_loading
                        || self.stats_loading
                        || self.images_loading
                        || self.security_loading
                        || self.networks_loading
                        || self.volumes_loading
                        || self.compose_loading
                        || self.network_inspection_loading
                    {
                        "正在刷新…".to_owned()
                    } else {
                        "数据为一次性快照".to_owned()
                    })
                    .when(
                        self.model.containers_truncated
                            || self.model.images_truncated
                            || self.model.networks_truncated
                            || self.model.volumes_truncated
                            || self.model.compose_truncated,
                        |view| {
                            view.child(
                                div()
                                    .text_color(tokens.warning)
                                    .child("结果已在 1,000 行边界截断"),
                            )
                        },
                    ),
            )
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .flex()
                    .gap_3()
                    .child(
                        div()
                            .w(px(520.0))
                            .min_w(px(360.0))
                            .flex()
                            .flex_col()
                            .gap_2()
                            .rounded_lg()
                            .border_1()
                            .border_color(tokens.border)
                            .bg(tokens.surface)
                            .p_3()
                            .child(
                                div()
                                    .font_weight(gpui::FontWeight::SEMIBOLD)
                                    .child("容器"),
                            )
                            .child(self.render_container_list(tokens, cx))
                            .child(
                                div()
                                    .mt_1()
                                    .font_weight(gpui::FontWeight::SEMIBOLD)
                                    .child("镜像（最多展示前 100 项）"),
                            )
                            .child(self.render_images(tokens)),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .rounded_lg()
                            .border_1()
                            .border_color(tokens.border)
                            .bg(tokens.surface)
                            .p_3()
                            .child(self.render_detail(tokens, cx)),
                    ),
            )
    }
}

impl EventEmitter<OpenContainerTerminal> for DockerPage {}

#[cfg(test)]
mod tests {
    use lovelyres_core::target::{TargetContext, TargetIdentity};

    use super::*;

    const CONTAINER_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const CONTAINER_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn binding(target: &TargetContext, identity: &str) -> DockerBinding {
        let guard = target
            .activate(TargetIdentity::new(identity).unwrap())
            .unwrap();
        DockerBinding {
            connection_id: identity.to_owned(),
            session_id: format!("session-{identity}"),
            target: guard,
        }
    }

    fn container(id: &str, name: &str, status: &str) -> ContainerSummary {
        ContainerSummary {
            identity: ContainerIdentity::new(ContainerRuntime::Docker, id).unwrap(),
            name: name.to_owned(),
            image: "nginx:latest".to_owned(),
            state: status.to_owned(),
            status: status.to_owned(),
            ports: String::new(),
            created_at: String::new(),
            command: String::new(),
        }
    }

    #[test]
    fn sorted_refresh_preserves_selected_container_identity_not_row_position() {
        let target = TargetContext::new();
        let current = binding(&target, "host-a");
        let mut model = DockerModel::default();
        model.activate(Some(current.clone()));
        let first = model
            .begin_request(DockerRequestKind::Containers, Some(current.clone()))
            .unwrap();
        assert!(model.apply_containers(
            &first,
            Some(&current),
            DockerCollection {
                items: vec![
                    container(CONTAINER_B, "zeta", "running"),
                    container(CONTAINER_A, "alpha", "running"),
                ],
                truncated: false,
            }
        ));
        let selected = ContainerIdentity::new(ContainerRuntime::Docker, CONTAINER_B).unwrap();
        assert!(model.select(&selected));
        let refresh = model
            .begin_request(DockerRequestKind::Containers, Some(current.clone()))
            .unwrap();
        assert!(model.apply_containers(
            &refresh,
            Some(&current),
            DockerCollection {
                items: vec![
                    container(CONTAINER_B, "aardvark", "paused"),
                    container(CONTAINER_A, "zulu", "running"),
                ],
                truncated: false,
            }
        ));
        assert_eq!(model.selected_identity(), Some(selected));
        assert_eq!(model.selected_container().unwrap().name, "aardvark");
    }

    #[test]
    fn deactivation_and_target_switch_reject_late_results() {
        let target = TargetContext::new();
        let first_binding = binding(&target, "host-a");
        let mut model = DockerModel::default();
        model.activate(Some(first_binding.clone()));
        let deactivated = model
            .begin_request(DockerRequestKind::Containers, Some(first_binding.clone()))
            .unwrap();
        model.deactivate();
        assert!(!model.apply_containers(
            &deactivated,
            Some(&first_binding),
            DockerCollection {
                items: Vec::new(),
                truncated: false,
            }
        ));

        model.activate(Some(first_binding.clone()));
        let stale = model
            .begin_request(DockerRequestKind::Containers, Some(first_binding.clone()))
            .unwrap();
        let replacement = binding(&target, "host-b");
        model.rebind(Some(replacement.clone()));
        assert!(!model.apply_containers(
            &stale,
            Some(&replacement),
            DockerCollection {
                items: vec![container(CONTAINER_A, "wrong-host", "running")],
                truncated: false,
            }
        ));
        assert!(model.containers.is_empty());
    }

    #[test]
    fn action_lease_is_bound_to_the_exact_target_container_and_lifecycle() {
        let target = TargetContext::new();
        let first_binding = binding(&target, "host-a");
        let mut model = DockerModel::default();
        model.activate(Some(first_binding.clone()));
        let containers = model
            .begin_request(DockerRequestKind::Containers, Some(first_binding.clone()))
            .unwrap();
        assert!(model.apply_containers(
            &containers,
            Some(&first_binding),
            DockerCollection {
                items: vec![
                    container(CONTAINER_A, "alpha", "running"),
                    container(CONTAINER_B, "beta", "exited"),
                ],
                truncated: false,
            }
        ));
        let first = ContainerIdentity::new(ContainerRuntime::Docker, CONTAINER_A).unwrap();
        let second = ContainerIdentity::new(ContainerRuntime::Docker, CONTAINER_B).unwrap();
        assert!(model.select(&first));
        let action = model
            .begin_request(
                DockerRequestKind::Action(first.clone()),
                Some(first_binding.clone()),
            )
            .unwrap();
        assert!(model.accepts(&action, Some(&first_binding)));

        assert!(model.select(&second));
        assert!(!model.accepts(&action, Some(&first_binding)));

        let replacement = binding(&target, "host-b");
        model.rebind(Some(replacement.clone()));
        assert!(!model.accepts(&action, Some(&replacement)));

        model.deactivate();
        assert!(!model.accepts(&action, Some(&first_binding)));
    }

    #[test]
    fn native_action_controls_use_only_the_closed_typed_catalog() {
        let ids = ContainerAction::ALL
            .into_iter()
            .map(ContainerAction::id)
            .collect::<Vec<_>>();
        assert_eq!(
            ids,
            vec![
                "start", "stop", "restart", "pause", "unpause", "kill", "remove"
            ]
        );
        let source = include_str!("docker.rs");
        assert!(source.contains("service.plan_action(&session, &request)"));
        assert!(source.contains(".execute_action("));
        assert!(!source.contains(&["docker-action-start", "-disabled"].concat()));
        assert!(!source.contains(&["docker-action-stop", "-disabled"].concat()));
    }

    #[test]
    fn file_editor_leases_are_bound_to_target_container_and_lifecycle() {
        let target = TargetContext::new();
        let first_binding = binding(&target, "host-a");
        let mut model = DockerModel::default();
        model.activate(Some(first_binding.clone()));
        let containers = model
            .begin_request(DockerRequestKind::Containers, Some(first_binding.clone()))
            .unwrap();
        assert!(model.apply_containers(
            &containers,
            Some(&first_binding),
            DockerCollection {
                items: vec![
                    container(CONTAINER_A, "alpha", "running"),
                    container(CONTAINER_B, "beta", "running"),
                ],
                truncated: false,
            }
        ));
        let first = ContainerIdentity::new(ContainerRuntime::Docker, CONTAINER_A).unwrap();
        let second = ContainerIdentity::new(ContainerRuntime::Docker, CONTAINER_B).unwrap();
        assert!(model.select(&first));
        let read = model
            .begin_request(
                DockerRequestKind::FileRead(first.clone()),
                Some(first_binding.clone()),
            )
            .unwrap();
        assert!(model.accepts(&read, Some(&first_binding)));
        assert!(model.select(&second));
        assert!(!model.accepts(&read, Some(&first_binding)));

        assert!(model.select(&first));
        let write = model
            .begin_request(
                DockerRequestKind::FileWrite(first),
                Some(first_binding.clone()),
            )
            .unwrap();
        let replacement = binding(&target, "host-b");
        model.rebind(Some(replacement.clone()));
        assert!(!model.accepts(&write, Some(&replacement)));
        model.deactivate();
        assert!(!model.accepts(&write, Some(&first_binding)));
    }

    #[test]
    fn native_file_editor_uses_snapshot_bound_planned_workflow_only() {
        let source = include_str!("docker.rs");
        assert!(source.contains("service.read_file(&session, &identity, &path)"));
        assert!(source.contains("DockerFileWriteRequest::replace(&loaded, content)"));
        assert!(source.contains("service.plan_file_write(&session, request)"));
        assert!(source.contains(".execute_file_write("));
        assert!(source.contains("DangerousConfirmation::approve(pending.plan.definition())"));
        assert!(!source.contains(&["docker-action-file-editor", "-disabled"].concat()));
    }

    #[test]
    fn native_file_copy_uses_closed_directions_and_planned_workflow_only() {
        let ids = DockerFileCopyDirection::ALL
            .into_iter()
            .map(DockerFileCopyDirection::id)
            .collect::<Vec<_>>();
        assert_eq!(
            ids,
            vec!["container-to-host", "host-to-container", "in-container"]
        );
        let source = include_str!("docker.rs");
        assert!(source.contains("DockerFileCopyRequest::ContainerToHost"));
        assert!(source.contains("DockerFileCopyRequest::HostToContainer"));
        assert!(source.contains("DockerFileCopyRequest::InContainer"));
        assert!(source.contains("service.plan_file_copy(&session, request)"));
        assert!(source.contains(".execute_file_copy("));
        assert!(!source.contains(&["docker-action-file-copy", "-disabled"].concat()));
    }

    #[test]
    fn file_copy_lease_rejects_container_target_and_lifecycle_changes() {
        let target = TargetContext::new();
        let first_binding = binding(&target, "host-a");
        let mut model = DockerModel::default();
        model.activate(Some(first_binding.clone()));
        let containers = model
            .begin_request(DockerRequestKind::Containers, Some(first_binding.clone()))
            .unwrap();
        assert!(model.apply_containers(
            &containers,
            Some(&first_binding),
            DockerCollection {
                items: vec![
                    container(CONTAINER_A, "alpha", "running"),
                    container(CONTAINER_B, "beta", "running"),
                ],
                truncated: false,
            }
        ));
        let first = ContainerIdentity::new(ContainerRuntime::Docker, CONTAINER_A).unwrap();
        let second = ContainerIdentity::new(ContainerRuntime::Docker, CONTAINER_B).unwrap();
        assert!(model.select(&first));
        let copy = model
            .begin_request(
                DockerRequestKind::FileCopy(first),
                Some(first_binding.clone()),
            )
            .unwrap();
        assert!(model.accepts(&copy, Some(&first_binding)));
        assert!(model.select(&second));
        assert!(!model.accepts(&copy, Some(&first_binding)));

        let replacement = binding(&target, "host-b");
        model.rebind(Some(replacement.clone()));
        assert!(!model.accepts(&copy, Some(&replacement)));
        model.deactivate();
        assert!(!model.accepts(&copy, Some(&first_binding)));
    }

    #[test]
    fn security_audit_is_target_bound_read_only_and_preserves_hostile_text_as_data() {
        let target = TargetContext::new();
        let current = binding(&target, "host-a");
        let mut model = DockerModel::default();
        model.activate(Some(current.clone()));
        let lease = model
            .begin_request(DockerRequestKind::SecurityAudit, Some(current.clone()))
            .unwrap();
        let hostile = "<script>window.evil()</script>\nnot markup";
        let audit = DockerSecurityAudit {
            runtime: ContainerRuntime::Docker,
            containers_scanned: 1,
            findings: vec![lovelyres_core::docker::DockerSecurityFinding {
                id: "docker:audit:1".to_owned(),
                severity: DockerSecuritySeverity::Critical,
                category: lovelyres_core::docker::DockerSecurityCategory::Privileged,
                container: ContainerIdentity::new(ContainerRuntime::Docker, CONTAINER_A).unwrap(),
                container_name: "hostile<img>".to_owned(),
                description: hostile.to_owned(),
                remediation: "ordinary text".to_owned(),
            }],
            summary: lovelyres_core::docker::DockerSecuritySummary {
                critical: 1,
                high: 0,
                medium: 0,
                low: 0,
                info: 0,
                total: 1,
                score: 85,
            },
            truncated: false,
        };
        assert!(model.apply_security_audit(&lease, Some(&current), audit));
        assert_eq!(
            model.security_audit.as_ref().unwrap().findings[0].description,
            hostile
        );

        let source = include_str!("docker.rs");
        assert!(source.contains(".security_audit(&session, ContainerRuntime::Docker)"));
        assert!(source.contains("八类只读安全检查"));
        assert!(!source.contains(&["docker-security", "-remediate"].concat()));
    }

    #[test]
    fn security_audit_lease_rejects_target_and_lifecycle_changes() {
        let target = TargetContext::new();
        let first_binding = binding(&target, "host-a");
        let mut model = DockerModel::default();
        model.activate(Some(first_binding.clone()));
        let lease = model
            .begin_request(
                DockerRequestKind::SecurityAudit,
                Some(first_binding.clone()),
            )
            .unwrap();
        let replacement = binding(&target, "host-b");
        model.rebind(Some(replacement.clone()));
        assert!(!model.accepts(&lease, Some(&replacement)));
        model.deactivate();
        assert!(!model.accepts(&lease, Some(&first_binding)));
    }

    #[test]
    fn network_and_volume_inventory_and_planned_mutations_are_target_bound() {
        let target = TargetContext::new();
        let first_binding = binding(&target, "host-a");
        let mut model = DockerModel::default();
        model.activate(Some(first_binding.clone()));
        let network_lease = model
            .begin_request(DockerRequestKind::Networks, Some(first_binding.clone()))
            .unwrap();
        let volume_lease = model
            .begin_request(DockerRequestKind::Volumes, Some(first_binding.clone()))
            .unwrap();
        let hostile_name = "<img src=x onerror=network_evil()>";
        let hostile_labels = "</div><script>volume_evil()</script>";

        assert!(model.apply_networks(
            &network_lease,
            Some(&first_binding),
            DockerCollection {
                items: vec![DockerNetwork {
                    runtime: ContainerRuntime::Docker,
                    id: CONTAINER_A.to_owned(),
                    name: hostile_name.to_owned(),
                    driver: "bridge".to_owned(),
                    scope: "local".to_owned(),
                    internal: true,
                    ipv6: false,
                }],
                truncated: false,
            }
        ));
        assert!(model.apply_volumes(
            &volume_lease,
            Some(&first_binding),
            DockerCollection {
                items: vec![DockerVolume {
                    runtime: ContainerRuntime::Docker,
                    name: "evidence_data".to_owned(),
                    driver: "local".to_owned(),
                    mountpoint: "/var/lib/docker/volumes/evidence_data/_data".to_owned(),
                    scope: "local".to_owned(),
                    labels: hostile_labels.to_owned(),
                }],
                truncated: false,
            }
        ));
        assert_eq!(model.networks[0].name, hostile_name);
        assert_eq!(model.volumes[0].labels, hostile_labels);

        let stale = model
            .begin_request(DockerRequestKind::Networks, Some(first_binding.clone()))
            .unwrap();
        let replacement = binding(&target, "host-b");
        model.rebind(Some(replacement.clone()));
        assert!(!model.apply_networks(
            &stale,
            Some(&replacement),
            DockerCollection {
                items: vec![DockerNetwork {
                    runtime: ContainerRuntime::Docker,
                    id: CONTAINER_B.to_owned(),
                    name: "wrong-target".to_owned(),
                    driver: "bridge".to_owned(),
                    scope: "local".to_owned(),
                    internal: false,
                    ipv6: false,
                }],
                truncated: false,
            }
        ));
        assert!(model.networks.is_empty());
        assert!(model.volumes.is_empty());

        model.activate(Some(replacement.clone()));
        let deactivated = model
            .begin_request(DockerRequestKind::Volumes, Some(replacement.clone()))
            .unwrap();
        model.deactivate();
        assert!(!model.apply_volumes(
            &deactivated,
            Some(&replacement),
            DockerCollection {
                items: vec![DockerVolume {
                    runtime: ContainerRuntime::Docker,
                    name: "late_data".to_owned(),
                    driver: "local".to_owned(),
                    mountpoint: String::new(),
                    scope: "local".to_owned(),
                    labels: String::new(),
                }],
                truncated: false,
            }
        ));
        assert!(model.volumes.is_empty());

        let source = include_str!("docker.rs");
        assert!(source.contains("service.networks(&session, ContainerRuntime::Docker)"));
        assert!(source.contains("service.volumes(&session, ContainerRuntime::Docker)"));
        assert!(source.contains(&["Docker 网络、", "数据卷与 Compose"].concat()));
        assert!(source.contains(&[".plan_", "resource_mutation(&session, request)"].concat()));
        assert!(source.contains(&[".execute_", "resource_mutation("].concat()));
        assert!(source.contains(&["DockerResourceMutationRequest::", "RemoveNetwork"].concat()));
        assert!(source.contains(&["DockerResourceMutationRequest::", "RemoveVolume"].concat()));
        assert!(source.contains(&["DockerResourceMutationRequest::", "PruneNetworks"].concat()));
        assert!(source.contains(&["DockerResourceMutationRequest::", "PruneVolumes"].concat()));
        assert!(!source.contains(&["docker network", " rm"].concat()));
        assert!(!source.contains(&["docker volume", " rm"].concat()));
        assert!(!source.contains(&["network prune", " -f"].concat()));
        assert!(!source.contains(&["volume prune", " -f"].concat()));
    }

    #[test]
    fn network_inspection_and_compose_actions_are_exact_target_bound_views() {
        let target = TargetContext::new();
        let first_binding = binding(&target, "host-a");
        let mut model = DockerModel::default();
        model.activate(Some(first_binding.clone()));
        model.detail_view = DetailView::Resources;
        let networks = model
            .begin_request(DockerRequestKind::Networks, Some(first_binding.clone()))
            .unwrap();
        assert!(model.apply_networks(
            &networks,
            Some(&first_binding),
            DockerCollection {
                items: vec![DockerNetwork {
                    runtime: ContainerRuntime::Docker,
                    id: CONTAINER_A.to_owned(),
                    name: "incident-net".to_owned(),
                    driver: "bridge".to_owned(),
                    scope: "local".to_owned(),
                    internal: false,
                    ipv6: true,
                }],
                truncated: false,
            }
        ));
        assert!(model.select_network(CONTAINER_A));
        let inspection_lease = model
            .begin_request(
                DockerRequestKind::NetworkInspect(CONTAINER_A.to_owned()),
                Some(first_binding.clone()),
            )
            .unwrap();
        let hostile = "</div><script>network_detail()</script>";
        let mut labels = BTreeMap::new();
        labels.insert("case".to_owned(), hostile.to_owned());
        let inspection = DockerNetworkInspection {
            network: DockerNetwork {
                runtime: ContainerRuntime::Docker,
                id: CONTAINER_A.to_owned(),
                name: "incident-net".to_owned(),
                driver: "bridge".to_owned(),
                scope: "local".to_owned(),
                internal: false,
                ipv6: true,
            },
            attachable: true,
            ingress: false,
            ipam_driver: "default".to_owned(),
            ipam: Vec::new(),
            attachments: Vec::new(),
            options: BTreeMap::new(),
            labels,
        };
        let mut wrong = inspection.clone();
        wrong.network.id = CONTAINER_B.to_owned();
        assert!(!model.apply_network_inspection(&inspection_lease, Some(&first_binding), wrong));
        assert!(model.network_inspection.is_none());
        assert!(model.apply_network_inspection(
            &inspection_lease,
            Some(&first_binding),
            inspection
        ));
        assert_eq!(
            model
                .network_inspection
                .as_ref()
                .unwrap()
                .labels
                .get("case")
                .unwrap(),
            hostile
        );

        let compose_lease = model
            .begin_request(
                DockerRequestKind::ComposeProjects,
                Some(first_binding.clone()),
            )
            .unwrap();
        assert!(model.apply_compose_projects(
            &compose_lease,
            Some(&first_binding),
            DockerCollection {
                items: vec![DockerComposeProject {
                    runtime: ContainerRuntime::Docker,
                    name: "incident".to_owned(),
                    status: "running(1)".to_owned(),
                    config_files: hostile.to_owned(),
                    services: 1,
                    running: 1,
                    stopped: 0,
                }],
                truncated: false,
            }
        ));
        assert_eq!(model.compose_projects[0].config_files, hostile);

        let resource_action = model
            .begin_request(
                DockerRequestKind::ResourceOperation("compose:incident:stop".to_owned()),
                Some(first_binding.clone()),
            )
            .unwrap();
        assert!(model.accepts(&resource_action, Some(&first_binding)));
        model.detail_view = DetailView::Inspect;
        assert!(!model.accepts(&resource_action, Some(&first_binding)));
        model.detail_view = DetailView::Resources;

        let stale = model
            .begin_request(
                DockerRequestKind::NetworkInspect(CONTAINER_A.to_owned()),
                Some(first_binding.clone()),
            )
            .unwrap();
        let replacement = binding(&target, "host-b");
        model.rebind(Some(replacement.clone()));
        assert!(!model.accepts(&stale, Some(&replacement)));
        assert!(model.network_inspection.is_none());
        assert!(model.compose_projects.is_empty());

        model.activate(Some(replacement.clone()));
        let deactivated = model
            .begin_request(
                DockerRequestKind::ComposeProjects,
                Some(replacement.clone()),
            )
            .unwrap();
        model.deactivate();
        assert!(!model.accepts(&deactivated, Some(&replacement)));

        let source = include_str!("docker.rs");
        assert!(source.contains("service.inspect_network(&session, &network)"));
        assert!(source.contains(".compose_projects(&session, ContainerRuntime::Docker)"));
        assert!(source.contains("Docker 网络、数据卷与 Compose"));
        assert!(source.contains(&["DockerComposeAction::", "ALL"].concat()));
        assert!(source.contains(&[".plan_", "compose_action(&session, request)"].concat()));
        assert!(source.contains(&[".execute_", "compose_action("].concat()));
        assert!(!source.contains(&["docker compose", " -f"].concat()));
    }

    #[test]
    fn hostile_remote_text_stays_inert_and_filterable() {
        let target = TargetContext::new();
        let current = binding(&target, "host-a");
        let mut model = DockerModel::default();
        model.activate(Some(current.clone()));
        let lease = model
            .begin_request(DockerRequestKind::Containers, Some(current.clone()))
            .unwrap();
        assert!(model.apply_containers(
            &lease,
            Some(&current),
            DockerCollection {
                items: vec![container(
                    CONTAINER_A,
                    "<img src=x onerror=alert(1)>",
                    "running"
                )],
                truncated: false,
            }
        ));
        model.set_query("onerror");
        assert_eq!(model.filtered_containers().len(), 1);
        assert_eq!(
            model.filtered_containers()[0].name,
            "<img src=x onerror=alert(1)>"
        );
        let source = include_str!("docker.rs").to_lowercase();
        assert!(!source.contains(&["inner", "_html"].concat()));
        assert!(!source.contains(&["web", "view"].concat()));
    }
}
