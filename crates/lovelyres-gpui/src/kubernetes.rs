use std::{collections::BTreeMap, sync::Arc};

use gpui::{
    AnyElement, Context, Entity, IntoElement, Render, SharedString, Subscription, Window, div,
    prelude::*, px,
};
use gpui_component::{
    Disableable, Selectable, Sizable,
    button::ButtonVariants,
    input::{Input, InputEvent, InputState},
    scroll::ScrollableElement,
};
use lovelyres_core::{
    BackendServices, CoreError, CoreResult,
    kubernetes::{
        KubernetesAvailability, KubernetesCollection, KubernetesDeployment,
        KubernetesDetailRequest, KubernetesMutationOutcome, KubernetesMutationPlan,
        KubernetesMutationRequest, KubernetesNamespace, KubernetesNode, KubernetesPod,
        KubernetesPodLogsRequest, KubernetesResourceKind, KubernetesRowId, KubernetesScope,
        KubernetesText,
    },
    operations::DangerousConfirmation,
    ssh::BoundSshSession,
    target::TargetGuard,
};
use tokio::task::AbortHandle;

use crate::{app::SharedAppState, runtime::TokioBridge, theme::ThemeTokens};

const MAXIMUM_ROWS: usize = 1_000;
const ROW_WINDOW_SIZE: usize = 60;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KubernetesBinding {
    connection_id: String,
    session_id: String,
    target: TargetGuard,
}

impl KubernetesBinding {
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

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum KubernetesTab {
    Namespaces,
    Pods,
    Deployments,
    Nodes,
}

impl KubernetesTab {
    pub const ALL: [Self; 4] = [Self::Namespaces, Self::Pods, Self::Deployments, Self::Nodes];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Namespaces => "Namespaces",
            Self::Pods => "Pods",
            Self::Deployments => "Deployments",
            Self::Nodes => "Nodes",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum KubernetesRow {
    Namespace(KubernetesNamespace),
    Pod(KubernetesPod),
    Deployment(KubernetesDeployment),
    Node(KubernetesNode),
}

impl KubernetesRow {
    fn id(&self) -> &KubernetesRowId {
        match self {
            Self::Namespace(value) => &value.id,
            Self::Pod(value) => &value.id,
            Self::Deployment(value) => &value.id,
            Self::Node(value) => &value.id,
        }
    }

    fn name(&self) -> &str {
        match self {
            Self::Namespace(value) => &value.name,
            Self::Pod(value) => &value.name,
            Self::Deployment(value) => &value.name,
            Self::Node(value) => &value.name,
        }
    }

    fn namespace(&self) -> Option<&str> {
        match self {
            Self::Pod(value) => Some(&value.namespace),
            Self::Deployment(value) => Some(&value.namespace),
            Self::Namespace(_) | Self::Node(_) => None,
        }
    }

    fn searchable_text(&self) -> String {
        match self {
            Self::Namespace(value) => {
                format!("{} {} {}", value.name, value.phase, value.created_at)
            }
            Self::Pod(value) => format!(
                "{} {} {} {} {} {}",
                value.namespace,
                value.name,
                value.phase,
                value.node,
                value.pod_ip,
                value.images.join(" ")
            ),
            Self::Deployment(value) => format!(
                "{} {} {}",
                value.namespace,
                value.name,
                value.images.join(" ")
            ),
            Self::Node(value) => format!(
                "{} {} {} {}",
                value.name,
                value.kubelet_version,
                value.internal_ip,
                value.roles.join(" ")
            ),
        }
    }

    fn subtitle(&self) -> String {
        match self {
            Self::Namespace(value) => format!("{} · {}", value.phase, value.created_at),
            Self::Pod(value) => format!(
                "{} · {} · Ready {}/{} · 重启 {} · Node {} · IP {}",
                value.namespace,
                value.phase,
                value.ready_containers,
                value.total_containers,
                value.restarts,
                value.node,
                value.pod_ip
            ),
            Self::Deployment(value) => format!(
                "{} · Ready {}/{} · Available {} · Updated {}",
                value.namespace,
                value.ready_replicas,
                value.desired_replicas,
                value.available_replicas,
                value.updated_replicas
            ),
            Self::Node(value) => format!(
                "{} · {} · {} · {} · CPU {} · MEM {} · Pods {}",
                if value.ready { "Ready" } else { "NotReady" },
                if value.unschedulable {
                    "Unschedulable"
                } else {
                    "Schedulable"
                },
                value.roles.join(", "),
                value.internal_ip,
                value.cpu_capacity,
                value.memory_capacity,
                value.pod_capacity
            ),
        }
    }

    fn detail_request(&self) -> CoreResult<KubernetesDetailRequest> {
        match self {
            Self::Namespace(value) => KubernetesDetailRequest::cluster_scoped(
                KubernetesResourceKind::Namespace,
                value.name.clone(),
            ),
            Self::Pod(value) => KubernetesDetailRequest::namespaced(
                KubernetesResourceKind::Pod,
                value.namespace.clone(),
                value.name.clone(),
            ),
            Self::Deployment(value) => KubernetesDetailRequest::namespaced(
                KubernetesResourceKind::Deployment,
                value.namespace.clone(),
                value.name.clone(),
            ),
            Self::Node(value) => KubernetesDetailRequest::cluster_scoped(
                KubernetesResourceKind::Node,
                value.name.clone(),
            ),
        }
    }

    fn logs_request(&self) -> CoreResult<KubernetesPodLogsRequest> {
        match self {
            Self::Pod(value) => {
                KubernetesPodLogsRequest::recent(value.namespace.clone(), value.name.clone())
            }
            _ => Err(CoreError::Validation {
                subject: "Kubernetes logs",
                message: "logs are only available for pods".to_owned(),
            }),
        }
    }

    fn mutation_request(
        &self,
        action: KubernetesMutationAction,
    ) -> CoreResult<KubernetesMutationRequest> {
        match (self, action) {
            (
                Self::Deployment(deployment),
                KubernetesMutationAction::ScaleDeployment { replicas },
            ) => Ok(KubernetesMutationRequest::ScaleDeployment {
                deployment: deployment.clone(),
                replicas,
            }),
            (
                Self::Node(node),
                KubernetesMutationAction::SetNodeUnschedulable { unschedulable },
            ) => Ok(KubernetesMutationRequest::SetNodeUnschedulable {
                node: node.clone(),
                unschedulable,
            }),
            _ => Err(CoreError::Validation {
                subject: "Kubernetes mutation",
                message: "the selected resource does not support this closed action".to_owned(),
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KubernetesMutationAction {
    ScaleDeployment { replicas: u64 },
    SetNodeUnschedulable { unschedulable: bool },
}

#[derive(Debug)]
struct PendingKubernetesMutation {
    binding: KubernetesBinding,
    plan: KubernetesMutationPlan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum KubernetesRows {
    Namespaces(KubernetesCollection<KubernetesNamespace>),
    Pods(KubernetesCollection<KubernetesPod>),
    Deployments(KubernetesCollection<KubernetesDeployment>),
    Nodes(KubernetesCollection<KubernetesNode>),
}

impl KubernetesRows {
    fn into_parts(self) -> (KubernetesTab, Vec<KubernetesRow>, bool) {
        match self {
            Self::Namespaces(collection) => (
                KubernetesTab::Namespaces,
                collection
                    .items
                    .into_iter()
                    .map(KubernetesRow::Namespace)
                    .collect(),
                collection.truncated,
            ),
            Self::Pods(collection) => (
                KubernetesTab::Pods,
                collection
                    .items
                    .into_iter()
                    .map(KubernetesRow::Pod)
                    .collect(),
                collection.truncated,
            ),
            Self::Deployments(collection) => (
                KubernetesTab::Deployments,
                collection
                    .items
                    .into_iter()
                    .map(KubernetesRow::Deployment)
                    .collect(),
                collection.truncated,
            ),
            Self::Nodes(collection) => (
                KubernetesTab::Nodes,
                collection
                    .items
                    .into_iter()
                    .map(KubernetesRow::Node)
                    .collect(),
                collection.truncated,
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum RequestKind {
    Availability,
    List(KubernetesTab),
    Detail(KubernetesRowId),
    Logs(KubernetesRowId),
    Mutation(KubernetesRowId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RequestLease {
    activation_generation: u64,
    request_id: u64,
    binding: KubernetesBinding,
    kind: RequestKind,
}

#[derive(Debug)]
pub struct KubernetesModel {
    active: bool,
    activation_generation: u64,
    next_request_id: u64,
    binding: Option<KubernetesBinding>,
    latest: BTreeMap<RequestKind, u64>,
    active_tab: KubernetesTab,
    tables: BTreeMap<KubernetesTab, Vec<KubernetesRow>>,
    truncated: BTreeMap<KubernetesTab, bool>,
    availability: Option<KubernetesAvailability>,
    selected: Option<KubernetesRowId>,
    detail: Option<KubernetesText>,
    logs: Option<KubernetesText>,
    query: String,
    namespace_scope: Option<String>,
    row_window_start: usize,
}

impl Default for KubernetesModel {
    fn default() -> Self {
        Self {
            active: false,
            activation_generation: 0,
            next_request_id: 0,
            binding: None,
            latest: BTreeMap::new(),
            active_tab: KubernetesTab::Pods,
            tables: BTreeMap::new(),
            truncated: BTreeMap::new(),
            availability: None,
            selected: None,
            detail: None,
            logs: None,
            query: String::new(),
            namespace_scope: None,
            row_window_start: 0,
        }
    }
}

impl KubernetesModel {
    pub fn activate(&mut self, binding: Option<KubernetesBinding>) -> u64 {
        self.active = true;
        self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
        self.rebind(binding);
        self.activation_generation
    }

    pub fn deactivate(&mut self) {
        self.active = false;
        self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
        self.latest.clear();
        self.detail = None;
        self.logs = None;
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn binding(&self) -> Option<&KubernetesBinding> {
        self.binding.as_ref()
    }

    fn rebind(&mut self, binding: Option<KubernetesBinding>) {
        if self.binding == binding {
            return;
        }
        self.binding = binding;
        self.latest.clear();
        self.tables.clear();
        self.truncated.clear();
        self.availability = None;
        self.selected = None;
        self.detail = None;
        self.logs = None;
        self.row_window_start = 0;
    }

    fn begin_request(
        &mut self,
        kind: RequestKind,
        binding: Option<KubernetesBinding>,
    ) -> CoreResult<RequestLease> {
        if !self.active {
            return Err(CoreError::Validation {
                subject: "Kubernetes page",
                message: "page is not active".to_owned(),
            });
        }
        self.rebind(binding);
        let binding = self.binding.clone().ok_or(CoreError::NoActiveTarget)?;
        self.next_request_id = self.next_request_id.wrapping_add(1).max(1);
        self.latest.insert(kind.clone(), self.next_request_id);
        Ok(RequestLease {
            activation_generation: self.activation_generation,
            request_id: self.next_request_id,
            binding,
            kind,
        })
    }

    fn accepts(&self, lease: &RequestLease, binding: Option<&KubernetesBinding>) -> bool {
        if !self.active
            || self.activation_generation != lease.activation_generation
            || binding != Some(&lease.binding)
            || self.latest.get(&lease.kind) != Some(&lease.request_id)
        {
            return false;
        }
        match &lease.kind {
            RequestKind::Detail(id) | RequestKind::Logs(id) | RequestKind::Mutation(id) => {
                self.selected.as_ref() == Some(id)
            }
            RequestKind::Availability | RequestKind::List(_) => true,
        }
    }

    fn apply_availability(
        &mut self,
        lease: &RequestLease,
        binding: Option<&KubernetesBinding>,
        availability: KubernetesAvailability,
    ) -> bool {
        if lease.kind != RequestKind::Availability || !self.accepts(lease, binding) {
            return false;
        }
        self.availability = Some(availability);
        self.latest.remove(&lease.kind);
        true
    }

    fn apply_rows(
        &mut self,
        lease: &RequestLease,
        binding: Option<&KubernetesBinding>,
        rows: KubernetesRows,
    ) -> bool {
        let (tab, mut rows, truncated) = rows.into_parts();
        if lease.kind != RequestKind::List(tab) || !self.accepts(lease, binding) {
            return false;
        }
        rows.sort_by(|left, right| {
            left.namespace()
                .unwrap_or_default()
                .cmp(right.namespace().unwrap_or_default())
                .then_with(|| left.name().to_lowercase().cmp(&right.name().to_lowercase()))
                .then_with(|| left.id().cmp(right.id()))
        });
        if tab == self.active_tab {
            self.selected = self
                .selected
                .clone()
                .filter(|id| rows.iter().any(|row| row.id() == id));
            self.detail = None;
            self.logs = None;
            self.row_window_start = 0;
        }
        self.tables.insert(tab, rows);
        self.truncated.insert(tab, truncated);
        self.latest.remove(&lease.kind);
        true
    }

    fn apply_detail(
        &mut self,
        lease: &RequestLease,
        binding: Option<&KubernetesBinding>,
        detail: KubernetesText,
    ) -> bool {
        if !matches!(lease.kind, RequestKind::Detail(_)) || !self.accepts(lease, binding) {
            return false;
        }
        self.detail = Some(detail);
        self.latest.remove(&lease.kind);
        true
    }

    fn apply_logs(
        &mut self,
        lease: &RequestLease,
        binding: Option<&KubernetesBinding>,
        logs: KubernetesText,
    ) -> bool {
        if !matches!(lease.kind, RequestKind::Logs(_)) || !self.accepts(lease, binding) {
            return false;
        }
        self.logs = Some(logs);
        self.latest.remove(&lease.kind);
        true
    }

    fn reject(&mut self, lease: &RequestLease, binding: Option<&KubernetesBinding>) -> bool {
        if !self.accepts(lease, binding) {
            return false;
        }
        self.latest.remove(&lease.kind);
        true
    }

    pub fn switch_tab(&mut self, tab: KubernetesTab) {
        if self.active_tab == tab {
            return;
        }
        self.active_tab = tab;
        self.selected = None;
        self.detail = None;
        self.logs = None;
        self.row_window_start = 0;
    }

    pub fn set_query(&mut self, query: impl Into<String>) {
        self.query = query.into().chars().take(512).collect();
        self.row_window_start = 0;
    }

    fn set_namespace_scope(&mut self, namespace: Option<String>) {
        self.namespace_scope = namespace;
        self.selected = None;
        self.detail = None;
        self.logs = None;
        self.row_window_start = 0;
    }

    fn scope(&self) -> CoreResult<KubernetesScope> {
        self.namespace_scope
            .clone()
            .map(KubernetesScope::namespace)
            .transpose()
            .map(|scope| scope.unwrap_or(KubernetesScope::AllNamespaces))
    }

    fn filtered_rows(&self) -> Vec<&KubernetesRow> {
        let query = self.query.trim().to_lowercase();
        self.tables
            .get(&self.active_tab)
            .into_iter()
            .flatten()
            .filter(|row| query.is_empty() || row.searchable_text().to_lowercase().contains(&query))
            .collect()
    }

    fn visible_rows(&self) -> Vec<&KubernetesRow> {
        self.filtered_rows()
            .into_iter()
            .skip(self.row_window_start)
            .take(ROW_WINDOW_SIZE)
            .collect()
    }

    fn move_window(&mut self, direction: i32) {
        let total = self.filtered_rows().len();
        if direction < 0 {
            self.row_window_start = self.row_window_start.saturating_sub(ROW_WINDOW_SIZE);
        } else if self.row_window_start + ROW_WINDOW_SIZE < total {
            self.row_window_start += ROW_WINDOW_SIZE;
        }
    }

    fn select(&mut self, id: &KubernetesRowId) -> bool {
        if !self
            .tables
            .get(&self.active_tab)
            .into_iter()
            .flatten()
            .any(|row| row.id() == id)
        {
            return false;
        }
        self.selected = Some(id.clone());
        self.detail = None;
        self.logs = None;
        self.latest.retain(|kind, _| {
            !matches!(
                kind,
                RequestKind::Detail(_) | RequestKind::Logs(_) | RequestKind::Mutation(_)
            )
        });
        true
    }

    fn selected_row(&self) -> Option<&KubernetesRow> {
        let id = self.selected.as_ref()?;
        self.tables
            .get(&self.active_tab)?
            .iter()
            .find(|row| row.id() == id)
    }

    fn namespace_names(&self) -> Vec<String> {
        self.tables
            .get(&KubernetesTab::Namespaces)
            .into_iter()
            .flatten()
            .filter_map(|row| match row {
                KubernetesRow::Namespace(namespace) => Some(namespace.name.clone()),
                _ => None,
            })
            .take(20)
            .collect()
    }
}

pub struct KubernetesPage {
    services: Arc<BackendServices>,
    tokio: Arc<TokioBridge>,
    shared: Entity<SharedAppState>,
    model: KubernetesModel,
    search_input: Entity<InputState>,
    replicas_input: Entity<InputState>,
    availability_abort: Option<AbortHandle>,
    list_abort: Option<AbortHandle>,
    detail_abort: Option<AbortHandle>,
    logs_abort: Option<AbortHandle>,
    mutation_plan_abort: Option<AbortHandle>,
    availability_loading: bool,
    list_loading: bool,
    detail_loading: bool,
    logs_loading: bool,
    mutation_plan_request_id: Option<u64>,
    mutation_execution_request_id: Option<u64>,
    mutation_busy: bool,
    pending_mutation: Option<PendingKubernetesMutation>,
    error: Option<SharedString>,
    notice: Option<SharedString>,
    _subscriptions: Vec<Subscription>,
}

impl KubernetesPage {
    pub fn new(
        services: Arc<BackendServices>,
        tokio: Arc<TokioBridge>,
        shared: Entity<SharedAppState>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let search_input = cx.new(|cx| {
            InputState::new(window, cx).placeholder("筛选名称、namespace、状态、镜像或 IP…")
        });
        let replicas_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("0–10000")
                .default_value("1")
        });
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
            model: KubernetesModel::default(),
            search_input,
            replicas_input,
            availability_abort: None,
            list_abort: None,
            detail_abort: None,
            logs_abort: None,
            mutation_plan_abort: None,
            availability_loading: false,
            list_loading: false,
            detail_loading: false,
            logs_loading: false,
            mutation_plan_request_id: None,
            mutation_execution_request_id: None,
            mutation_busy: false,
            pending_mutation: None,
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
        self.mutation_plan_request_id = None;
        self.pending_mutation = None;
        if self.mutation_execution_request_id.is_none() {
            self.mutation_busy = false;
        }
        self.model.deactivate();
        self.set_all_loading(false);
        cx.notify();
    }

    pub const fn is_active(&self) -> bool {
        self.model.is_active()
    }

    pub fn refresh(&mut self, cx: &mut Context<Self>) {
        self.refresh_availability(cx);
        self.refresh_current(cx);
    }

    fn current_binding(&self, cx: &Context<Self>) -> Option<KubernetesBinding> {
        KubernetesBinding::capture(self.shared.read(cx))
    }

    fn current_session(&self, cx: &Context<Self>) -> Option<BoundSshSession> {
        self.shared
            .read(cx)
            .active_ssh
            .as_ref()
            .map(|active| active.session.clone())
    }

    fn prepare_request(
        &mut self,
        kind: RequestKind,
        cx: &mut Context<Self>,
    ) -> CoreResult<(RequestLease, BoundSshSession)> {
        let session = self.current_session(cx).ok_or(CoreError::NoActiveTarget)?;
        let binding = Some(KubernetesBinding::from_session(&session));
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
        self.set_all_loading(false);
        self.error = None;
        self.notice = None;
        self.mutation_plan_request_id = None;
        self.pending_mutation = None;
        if self.mutation_execution_request_id.is_none() {
            self.mutation_busy = false;
        }
        self.model.rebind(binding);
        if self.model.binding().is_some() {
            self.refresh(cx);
        } else {
            self.error = Some("未连接目标，Kubernetes 只读纵切无法加载".into());
            cx.notify();
        }
    }

    fn refresh_availability(&mut self, cx: &mut Context<Self>) {
        let (lease, session) = match self.prepare_request(RequestKind::Availability, cx) {
            Ok(value) => value,
            Err(error) => {
                self.error = Some(format!("无法检查 Kubernetes：{error}").into());
                cx.notify();
                return;
            }
        };
        if let Some(abort) = self.availability_abort.take() {
            abort.abort();
        }
        self.availability_loading = true;
        let service = self.services.kubernetes().clone();
        let task = self
            .tokio
            .spawn(async move { service.availability(&session).await });
        self.availability_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        page.finish_availability(lease, result, cx);
                    });
                }
            });
        })
        .detach();
    }

    fn finish_availability(
        &mut self,
        lease: RequestLease,
        result: Result<CoreResult<KubernetesAvailability>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            return;
        }
        self.availability_loading = false;
        self.availability_abort = None;
        match result {
            Ok(Ok(availability)) => {
                let reachable = availability.api_reachable;
                let _ = self
                    .model
                    .apply_availability(&lease, binding.as_ref(), availability);
                if !reachable {
                    self.notice = Some("kubectl 存在，但当前 context 的 API 不可达".into());
                }
            }
            Ok(Err(error)) => {
                let _ = self.model.reject(&lease, binding.as_ref());
                self.error = Some(format!("Kubernetes 可用性检查失败：{error}").into());
            }
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                let _ = self.model.reject(&lease, binding.as_ref());
                self.error = Some(format!("Kubernetes 可用性任务失败：{error}").into());
            }
        }
        cx.notify();
    }

    fn refresh_current(&mut self, cx: &mut Context<Self>) {
        self.refresh_list(self.model.active_tab, cx);
    }

    fn refresh_list(&mut self, tab: KubernetesTab, cx: &mut Context<Self>) {
        let (lease, session) = match self.prepare_request(RequestKind::List(tab), cx) {
            Ok(value) => value,
            Err(error) => {
                self.error = Some(format!("无法加载 {}：{error}", tab.label()).into());
                self.list_loading = false;
                cx.notify();
                return;
            }
        };
        if let Some(abort) = self.list_abort.take() {
            abort.abort();
        }
        self.list_loading = true;
        self.error = None;
        let service = self.services.kubernetes().clone();
        let scope = match self.model.scope() {
            Ok(scope) => scope,
            Err(error) => {
                self.error = Some(format!("Namespace 无效：{error}").into());
                return;
            }
        };
        let task = self.tokio.spawn(async move {
            match tab {
                KubernetesTab::Namespaces => service
                    .namespaces(&session, MAXIMUM_ROWS)
                    .await
                    .map(KubernetesRows::Namespaces),
                KubernetesTab::Pods => service
                    .pods(&session, &scope, MAXIMUM_ROWS)
                    .await
                    .map(KubernetesRows::Pods),
                KubernetesTab::Deployments => service
                    .deployments(&session, &scope, MAXIMUM_ROWS)
                    .await
                    .map(KubernetesRows::Deployments),
                KubernetesTab::Nodes => service
                    .nodes(&session, MAXIMUM_ROWS)
                    .await
                    .map(KubernetesRows::Nodes),
            }
        });
        self.list_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_list(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_list(
        &mut self,
        lease: RequestLease,
        result: Result<CoreResult<KubernetesRows>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            return;
        }
        self.list_loading = false;
        self.list_abort = None;
        match result {
            Ok(Ok(rows)) => {
                let _ = self.model.apply_rows(&lease, binding.as_ref(), rows);
            }
            Ok(Err(error)) => {
                let _ = self.model.reject(&lease, binding.as_ref());
                self.error = Some(format!("Kubernetes 列表读取失败：{error}").into());
            }
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                let _ = self.model.reject(&lease, binding.as_ref());
                self.error = Some(format!("Kubernetes 列表任务失败：{error}").into());
            }
        }
        cx.notify();
    }

    fn switch_tab(&mut self, tab: KubernetesTab, cx: &mut Context<Self>) {
        if self.model.active_tab == tab {
            return;
        }
        self.abort_detail();
        self.invalidate_mutation_plan();
        self.model.switch_tab(tab);
        self.refresh_current(cx);
        cx.notify();
    }

    fn set_namespace_scope(&mut self, namespace: Option<String>, cx: &mut Context<Self>) {
        if self.model.namespace_scope == namespace {
            return;
        }
        self.abort_detail();
        self.invalidate_mutation_plan();
        self.model.set_namespace_scope(namespace);
        if matches!(
            self.model.active_tab,
            KubernetesTab::Pods | KubernetesTab::Deployments
        ) {
            self.refresh_current(cx);
        }
        cx.notify();
    }

    fn select_row(&mut self, id: &KubernetesRowId, window: &mut Window, cx: &mut Context<Self>) {
        let previous = self.model.selected.clone();
        if !self.model.select(id) {
            return;
        }
        if previous.as_ref() != Some(id) {
            self.invalidate_mutation_plan();
            if let Some(KubernetesRow::Deployment(deployment)) = self.model.selected_row() {
                let replicas = deployment.desired_replicas.to_string();
                self.replicas_input
                    .update(cx, |input, cx| input.set_value(replicas, window, cx));
            }
        }
        self.refresh_detail(cx);
    }

    fn prepare_scale_from_input(&mut self, cx: &mut Context<Self>) {
        let value = self.replicas_input.read(cx).value().trim().to_owned();
        let replicas = match value.parse::<u64>() {
            Ok(value) if value <= 10_000 => value,
            _ => {
                self.error = Some("目标副本数必须是 0–10000 的整数".into());
                cx.notify();
                return;
            }
        };
        self.prepare_mutation(KubernetesMutationAction::ScaleDeployment { replicas }, cx);
    }

    fn refresh_detail(&mut self, cx: &mut Context<Self>) {
        let Some(row) = self.model.selected_row().cloned() else {
            return;
        };
        let request = match row.detail_request() {
            Ok(request) => request,
            Err(error) => {
                self.notice = Some(format!("无法构造详情请求：{error}").into());
                return;
            }
        };
        let id = row.id().clone();
        let (lease, session) = match self.prepare_request(RequestKind::Detail(id), cx) {
            Ok(value) => value,
            Err(error) => {
                self.notice = Some(format!("无法读取详情：{error}").into());
                return;
            }
        };
        if let Some(abort) = self.detail_abort.take() {
            abort.abort();
        }
        self.detail_loading = true;
        let service = self.services.kubernetes().clone();
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
        lease: RequestLease,
        result: Result<CoreResult<KubernetesText>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            return;
        }
        self.detail_loading = false;
        self.detail_abort = None;
        match result {
            Ok(Ok(detail)) => {
                let _ = self.model.apply_detail(&lease, binding.as_ref(), detail);
            }
            Ok(Err(error)) => {
                let _ = self.model.reject(&lease, binding.as_ref());
                self.notice = Some(format!("资源详情读取失败：{error}").into());
            }
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                let _ = self.model.reject(&lease, binding.as_ref());
                self.notice = Some(format!("资源详情任务失败：{error}").into());
            }
        }
        cx.notify();
    }

    fn refresh_logs(&mut self, cx: &mut Context<Self>) {
        let Some(row) = self.model.selected_row().cloned() else {
            return;
        };
        let request = match row.logs_request() {
            Ok(request) => request,
            Err(error) => {
                self.notice = Some(format!("无法构造日志请求：{error}").into());
                return;
            }
        };
        let id = row.id().clone();
        let (lease, session) = match self.prepare_request(RequestKind::Logs(id), cx) {
            Ok(value) => value,
            Err(error) => {
                self.notice = Some(format!("无法读取日志：{error}").into());
                return;
            }
        };
        if let Some(abort) = self.logs_abort.take() {
            abort.abort();
        }
        self.logs_loading = true;
        let service = self.services.kubernetes().clone();
        let task = self
            .tokio
            .spawn(async move { service.pod_logs(&session, &request).await });
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
        lease: RequestLease,
        result: Result<CoreResult<KubernetesText>, tokio::task::JoinError>,
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
                self.notice = Some(format!("Pod 日志读取失败：{error}").into());
            }
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                let _ = self.model.reject(&lease, binding.as_ref());
                self.notice = Some(format!("Pod 日志任务失败：{error}").into());
            }
        }
        cx.notify();
    }

    fn prepare_mutation(&mut self, action: KubernetesMutationAction, cx: &mut Context<Self>) {
        if self.mutation_busy || self.pending_mutation.is_some() {
            return;
        }
        let Some(row) = self.model.selected_row().cloned() else {
            self.error = Some("请选择 Kubernetes 资源".into());
            cx.notify();
            return;
        };
        let request = match row.mutation_request(action) {
            Ok(request) => request,
            Err(error) => {
                self.error = Some(format!("无法创建 Kubernetes 操作：{error}").into());
                cx.notify();
                return;
            }
        };
        let id = row.id().clone();
        let (lease, session) = match self.prepare_request(RequestKind::Mutation(id), cx) {
            Ok(value) => value,
            Err(error) => {
                self.error = Some(format!("无法创建 Kubernetes 操作计划：{error}").into());
                cx.notify();
                return;
            }
        };
        if let Some(abort) = self.mutation_plan_abort.take() {
            abort.abort();
        }
        self.mutation_busy = true;
        self.mutation_plan_request_id = Some(lease.request_id);
        self.error = None;
        self.notice = Some("正在复核 UID、resourceVersion 与资源状态…".into());
        let service = self.services.kubernetes().clone();
        let task = self
            .tokio
            .spawn(async move { service.plan_mutation(&session, &request).await });
        self.mutation_plan_abort = Some(task.abort_handle());
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| page.finish_mutation_plan(lease, result, cx));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_mutation_plan(
        &mut self,
        lease: RequestLease,
        result: Result<CoreResult<KubernetesMutationPlan>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if self.mutation_plan_request_id != Some(lease.request_id) {
            return;
        }
        self.mutation_plan_request_id = None;
        self.mutation_plan_abort = None;
        self.mutation_busy = false;
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            cx.notify();
            return;
        }
        let _ = self.model.reject(&lease, binding.as_ref());
        match result {
            Ok(Ok(plan)) => {
                self.pending_mutation = Some(PendingKubernetesMutation {
                    binding: lease.binding,
                    plan,
                });
                self.error = None;
                self.notice = None;
            }
            Ok(Err(error)) => {
                self.error = Some(format!("Kubernetes 操作计划创建失败：{error}").into());
                self.notice = None;
            }
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                self.error = Some(format!("Kubernetes 操作计划任务失败：{error}").into());
                self.notice = None;
            }
        }
        cx.notify();
    }

    fn cancel_pending_mutation(&mut self, cx: &mut Context<Self>) {
        if self.pending_mutation.take().is_some() {
            self.notice = Some("Kubernetes 操作计划已取消，远端资源未发生变化".into());
            self.error = None;
            cx.notify();
        }
    }

    fn approve_pending_mutation(&mut self, cx: &mut Context<Self>) {
        if self.mutation_busy {
            return;
        }
        let Some(pending) = self.pending_mutation.take() else {
            return;
        };
        let Some(session) = self.current_session(cx) else {
            self.error = Some("目标已断开，Kubernetes 操作计划未执行".into());
            cx.notify();
            return;
        };
        let binding = KubernetesBinding::from_session(&session);
        if binding != pending.binding
            || self.model.binding() != Some(&binding)
            || self.model.selected.as_ref() != Some(pending.plan.row_id())
        {
            self.error = Some("目标、会话或资源选择已变化，原 Kubernetes 计划已作废".into());
            cx.notify();
            return;
        }
        let row_id = pending.plan.row_id().clone();
        let (lease, session) = match self.prepare_request(RequestKind::Mutation(row_id), cx) {
            Ok(value) => value,
            Err(error) => {
                self.error = Some(format!("无法执行 Kubernetes 操作：{error}").into());
                cx.notify();
                return;
            }
        };
        self.mutation_busy = true;
        self.mutation_execution_request_id = Some(lease.request_id);
        self.error = None;
        self.notice = Some("正在执行、写入操作日志并读回验证 Kubernetes 资源…".into());
        let service = self.services.kubernetes().clone();
        let journal = self.services.operation_journal().clone();
        let confirmation = DangerousConfirmation::approve(pending.plan.definition());
        let task = self.tokio.spawn(async move {
            service
                .execute_mutation(&session, pending.plan, confirmation, &journal)
                .await
        });
        cx.spawn(async move |page, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(page) = page.upgrade() {
                    page.update(cx, |page, cx| {
                        page.finish_mutation_execution(lease, result, cx)
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_mutation_execution(
        &mut self,
        lease: RequestLease,
        result: Result<CoreResult<KubernetesMutationOutcome>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if self.mutation_execution_request_id != Some(lease.request_id) {
            return;
        }
        self.mutation_execution_request_id = None;
        self.mutation_busy = false;
        let binding = self.current_binding(cx);
        if !self.model.accepts(&lease, binding.as_ref()) {
            cx.notify();
            return;
        }
        let _ = self.model.reject(&lease, binding.as_ref());
        match result {
            Ok(Ok(outcome)) if outcome.verified => {
                self.notice = Some(
                    format!(
                        "Kubernetes 操作已完成并验证：{}",
                        outcome.verification_detail
                    )
                    .into(),
                );
                self.error = None;
                self.refresh_current(cx);
            }
            Ok(Ok(outcome)) if outcome.restored_after_failed_verification => {
                self.error = Some(
                    format!(
                        "Kubernetes 操作验证失败，已自动恢复：{}",
                        outcome.verification_detail
                    )
                    .into(),
                );
                self.notice = None;
                self.refresh_current(cx);
            }
            Ok(Ok(outcome)) => {
                self.error = Some(
                    format!("Kubernetes 操作未通过验证：{}", outcome.verification_detail).into(),
                );
                self.notice = None;
            }
            Ok(Err(error)) => {
                self.error = Some(format!("Kubernetes 操作失败：{error}").into());
                self.notice = None;
            }
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                self.error = Some(format!("Kubernetes 操作任务失败：{error}").into());
                self.notice = None;
            }
        }
        cx.notify();
    }

    fn abort_detail(&mut self) {
        for abort in [&mut self.detail_abort, &mut self.logs_abort] {
            if let Some(abort) = abort.take() {
                abort.abort();
            }
        }
        self.detail_loading = false;
        self.logs_loading = false;
    }

    fn invalidate_mutation_plan(&mut self) {
        if let Some(abort) = self.mutation_plan_abort.take() {
            abort.abort();
        }
        self.mutation_plan_request_id = None;
        self.pending_mutation = None;
        if self.mutation_execution_request_id.is_none() {
            self.mutation_busy = false;
        }
    }

    fn abort_all(&mut self) {
        for abort in [
            &mut self.availability_abort,
            &mut self.list_abort,
            &mut self.detail_abort,
            &mut self.logs_abort,
            &mut self.mutation_plan_abort,
        ] {
            if let Some(abort) = abort.take() {
                abort.abort();
            }
        }
    }

    fn set_all_loading(&mut self, value: bool) {
        self.availability_loading = value;
        self.list_loading = value;
        self.detail_loading = value;
        self.logs_loading = value;
    }

    fn render_rows(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let rows = self.model.visible_rows().into_iter().map(|row| {
            let id = row.id().clone();
            let selected = self.model.selected.as_ref() == Some(row.id());
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
                        "kubernetes-row-{}",
                        row.id().as_str()
                    )))
                    .label(row.name().to_owned())
                    .small()
                    .on_click(
                        cx.listener(move |page, _, window, cx| page.select_row(&id, window, cx)),
                    ),
                )
                .child(
                    div()
                        .mt_1()
                        .text_xs()
                        .text_color(tokens.muted)
                        .child(row.subtitle()),
                )
        });
        div()
            .flex_1()
            .min_h_0()
            .overflow_y_scrollbar()
            .children(rows)
            .into_any_element()
    }

    fn render_detail(&self, tokens: ThemeTokens, cx: &mut Context<Self>) -> AnyElement {
        let Some(row) = self.model.selected_row() else {
            return div()
                .flex_1()
                .flex()
                .items_center()
                .justify_center()
                .text_color(tokens.muted)
                .child("选择资源以读取受限 describe；Pod 可按需读取最近 200 行日志。")
                .into_any_element();
        };
        let is_pod = matches!(row, KubernetesRow::Pod(_));
        let mutation_blocked = self.mutation_busy || self.pending_mutation.is_some();
        let mutation_controls = match row {
            KubernetesRow::Deployment(deployment) => {
                let desired = deployment.desired_replicas;
                vec![
                    div()
                        .w(px(180.0))
                        .flex()
                        .items_center()
                        .gap_1()
                        .child(div().text_xs().child("目标副本"))
                        .child(
                            div()
                                .flex_1()
                                .child(Input::new(&self.replicas_input).small()),
                        )
                        .into_any_element(),
                    crate::buttons::button("kubernetes-scale-apply")
                        .label("创建扩缩容计划")
                        .xsmall()
                        .danger()
                        .disabled(mutation_blocked)
                        .on_click(cx.listener(|page, _, _, cx| page.prepare_scale_from_input(cx)))
                        .into_any_element(),
                    crate::buttons::button("kubernetes-scale-zero")
                        .label("缩容至 0")
                        .xsmall()
                        .danger()
                        .disabled(mutation_blocked || desired == 0)
                        .on_click(cx.listener(|page, _, _, cx| {
                            page.prepare_mutation(
                                KubernetesMutationAction::ScaleDeployment { replicas: 0 },
                                cx,
                            )
                        }))
                        .into_any_element(),
                ]
            }
            KubernetesRow::Node(node) => {
                let target = !node.unschedulable;
                let label = if target { "Cordon" } else { "Uncordon" };
                vec![
                    crate::buttons::button("kubernetes-node-scheduling")
                        .label(label)
                        .xsmall()
                        .danger()
                        .disabled(mutation_blocked)
                        .on_click(cx.listener(move |page, _, _, cx| {
                            page.prepare_mutation(
                                KubernetesMutationAction::SetNodeUnschedulable {
                                    unschedulable: target,
                                },
                                cx,
                            )
                        }))
                        .into_any_element(),
                    crate::buttons::button("kubernetes-drain-disabled")
                        .label("Drain（工作负载迁移待实现）")
                        .xsmall()
                        .danger()
                        .disabled(true)
                        .into_any_element(),
                ]
            }
            KubernetesRow::Namespace(_) | KubernetesRow::Pod(_) => Vec::new(),
        };
        let body = if self.logs_loading {
            "正在读取 Pod 日志…".to_owned()
        } else if let Some(logs) = &self.model.logs {
            logs.text.clone()
        } else if self.detail_loading {
            "正在读取资源详情…".to_owned()
        } else {
            self.model
                .detail
                .as_ref()
                .map(|detail| detail.text.clone())
                .unwrap_or_else(|| "尚未取得资源详情".to_owned())
        };
        let truncated = self.model.logs.as_ref().is_some_and(|text| text.truncated)
            || self
                .model
                .detail
                .as_ref()
                .is_some_and(|text| text.truncated);
        div()
            .flex_1()
            .min_h_0()
            .flex()
            .flex_col()
            .gap_2()
            .child(
                div()
                    .text_lg()
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .child(row.name().to_owned()),
            )
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_1()
                    .child(
                        crate::buttons::button("kubernetes-detail-refresh")
                            .label("刷新 describe")
                            .xsmall()
                            .on_click(cx.listener(|page, _, _, cx| page.refresh_detail(cx))),
                    )
                    .child(
                        crate::buttons::button("kubernetes-pod-logs")
                            .label("Pod 最近日志")
                            .xsmall()
                            .disabled(!is_pod)
                            .on_click(cx.listener(|page, _, _, cx| page.refresh_logs(cx))),
                    ),
            )
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_1()
                    .children(mutation_controls)
                    .children([
                        crate::buttons::button("kubernetes-isolate-disabled")
                            .label("隔离（待完整回滚）")
                            .xsmall()
                            .danger()
                            .disabled(true),
                        crate::buttons::button("kubernetes-delete-disabled")
                            .label("删除（不可恢复，禁用）")
                            .xsmall()
                            .danger()
                            .disabled(true),
                        crate::buttons::button("kubernetes-exec-apply-disabled")
                            .label("Exec/Apply（任意命令面已删除）")
                            .xsmall()
                            .danger()
                            .disabled(true),
                    ]),
            )
            .child(
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
                    .child(body)
                    .when(truncated, |view| {
                        view.child(
                            div()
                                .mt_2()
                                .text_color(tokens.warning)
                                .child("远端文本已在 core 边界截断"),
                        )
                    }),
            )
            .into_any_element()
    }
}

impl Render for KubernetesPage {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens = self.shared.read(cx).theme.tokens();
        let target = self
            .model
            .binding()
            .map(KubernetesBinding::label)
            .unwrap_or_else(|| "未连接目标".to_owned());
        let filtered = self.model.filtered_rows().len();
        let window_start = self.model.row_window_start;
        let window_end = (window_start + ROW_WINDOW_SIZE).min(filtered);
        let namespace_names = self.model.namespace_names();
        let current_scope = self
            .model
            .namespace_scope
            .clone()
            .unwrap_or_else(|| "全部 Namespace".to_owned());
        let availability = self.model.availability.as_ref().map(|value| {
            format!(
                "kubectl {} · API {} · context {}",
                if value.kubectl_installed {
                    "已安装"
                } else {
                    "未安装"
                },
                if value.api_reachable {
                    "可达"
                } else {
                    "不可达"
                },
                if value.current_context.is_empty() {
                    "<none>"
                } else {
                    &value.current_context
                }
            )
        });
        let pending_mutation = self.pending_mutation.as_ref().map(|pending| {
            (
                pending.plan.label(),
                pending.plan.definition().summary.clone(),
                pending.plan.state_change(),
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
                                    .child("Kubernetes 管理"),
                            )
                            .child(div().text_xs().text_color(tokens.muted).child(target)),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .w(px(480.0))
                            .child(div().flex_1().child(Input::new(&self.search_input).small()))
                            .child(
                                crate::buttons::button("kubernetes-refresh")
                                    .label("刷新")
                                    .small()
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
                    .child("已接通：类型化资源清单、受限 describe/Pod 日志、Deployment 扩缩容和 Node Cordon/Uncordon。两类变更均复核 UID/resourceVersion，经精确确认、操作日志、读回验证和自动恢复；任意 YAML、Exec、Delete、Drain 与网络隔离仍保持禁用。"),
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
            .when_some(pending_mutation, |view, (label, summary, state_change)| {
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
                                        .child(format!("确认 Kubernetes 操作 · {label}")),
                                )
                                .child(div().mt_1().text_sm().child(summary))
                                .child(
                                    div()
                                        .mt_1()
                                        .text_xs()
                                        .text_color(tokens.muted)
                                        .child(format!(
                                            "{state_change}；确认仅适用于当前目标 epoch、资源 UID、resourceVersion 与计划 ID。"
                                        )),
                                ),
                        )
                        .child(
                            crate::buttons::button("kubernetes-mutation-cancel")
                                .label("取消")
                                .disabled(self.mutation_busy)
                                .on_click(cx.listener(|page, _, _, cx| {
                                    page.cancel_pending_mutation(cx)
                                })),
                        )
                        .child(
                            crate::buttons::button("kubernetes-mutation-approve")
                                .label("确认执行")
                                .danger()
                                .disabled(self.mutation_busy)
                                .on_click(cx.listener(|page, _, _, cx| {
                                    page.approve_pending_mutation(cx)
                                })),
                        ),
                )
            })
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .children(KubernetesTab::ALL.into_iter().map(|tab| {
                        crate::buttons::button(SharedString::from(format!(
                            "kubernetes-tab-{}",
                            tab.label().to_lowercase()
                        )))
                        .label(tab.label())
                        .small()
                        .selected(self.model.active_tab == tab)
                        .on_click(cx.listener(move |page, _, _, cx| page.switch_tab(tab, cx)))
                    }))
                    .when_some(availability, |view, availability| {
                        view.child(
                            div()
                                .ml_auto()
                                .text_xs()
                                .text_color(tokens.muted)
                                .child(availability),
                        )
                    }),
            )
            .when(
                matches!(
                    self.model.active_tab,
                    KubernetesTab::Pods | KubernetesTab::Deployments
                ),
                |view| {
                    view.child(
                        div()
                            .flex()
                            .flex_wrap()
                            .items_center()
                            .gap_1()
                            .text_xs()
                            .child(format!("范围：{current_scope}"))
                            .child(
                                crate::buttons::button("kubernetes-scope-all")
                                    .label("全部")
                                    .xsmall()
                                    .on_click(cx.listener(|page, _, _, cx| {
                                        page.set_namespace_scope(None, cx);
                                    })),
                            )
                            .children(namespace_names.into_iter().map(|namespace| {
                                let label = namespace.clone();
                                crate::buttons::button(SharedString::from(format!(
                                    "kubernetes-scope-{namespace}"
                                )))
                                .label(label)
                                .xsmall()
                                .on_click(cx.listener(move |page, _, _, cx| {
                                    page.set_namespace_scope(Some(namespace.clone()), cx);
                                }))
                            })),
                    )
                },
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .text_xs()
                    .child(format!("筛选结果 {filtered}"))
                    .child(if self.availability_loading || self.list_loading {
                        "正在刷新…".to_owned()
                    } else {
                        "一次性快照".to_owned()
                    })
                    .when(
                        self.model
                            .truncated
                            .get(&self.model.active_tab)
                            .copied()
                            .unwrap_or(false),
                        |view| {
                            view.child(
                                div()
                                    .text_color(tokens.warning)
                                    .child("结果已在 1,000 行边界截断"),
                            )
                        },
                    )
                    .child(
                        div()
                            .ml_auto()
                            .child(format!("显示 {}–{} / {filtered}", window_start, window_end)),
                    )
                    .child(
                        crate::buttons::button("kubernetes-window-previous")
                            .label("上一段")
                            .xsmall()
                            .disabled(window_start == 0)
                            .on_click(cx.listener(|page, _, _, cx| {
                                page.model.move_window(-1);
                                cx.notify();
                            })),
                    )
                    .child(
                        crate::buttons::button("kubernetes-window-next")
                            .label("下一段")
                            .xsmall()
                            .disabled(window_end >= filtered)
                            .on_click(cx.listener(|page, _, _, cx| {
                                page.model.move_window(1);
                                cx.notify();
                            })),
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
                            .w(px(570.0))
                            .min_w(px(360.0))
                            .flex()
                            .flex_col()
                            .rounded_lg()
                            .border_1()
                            .border_color(tokens.border)
                            .bg(tokens.surface)
                            .p_3()
                            .child(self.render_rows(tokens, cx)),
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

#[cfg(test)]
mod tests {
    use lovelyres_core::target::{TargetContext, TargetIdentity};

    use super::*;

    fn row_id(value: &str) -> KubernetesRowId {
        serde_json::from_value(serde_json::json!(value)).unwrap()
    }

    fn binding(target: &TargetContext, identity: &str) -> KubernetesBinding {
        let guard = target
            .activate(TargetIdentity::new(identity).unwrap())
            .unwrap();
        KubernetesBinding {
            connection_id: identity.to_owned(),
            session_id: format!("session-{identity}"),
            target: guard,
        }
    }

    fn pod(uid: &str, namespace: &str, name: &str) -> KubernetesPod {
        KubernetesPod {
            id: row_id(&format!("pod:{uid}")),
            namespace: namespace.to_owned(),
            name: name.to_owned(),
            phase: "Running".to_owned(),
            ready_containers: 1,
            total_containers: 1,
            restarts: 0,
            node: "worker-1".to_owned(),
            pod_ip: "10.0.0.2".to_owned(),
            images: vec!["registry/image:1".to_owned()],
            created_at: String::new(),
        }
    }

    fn deployment(uid: &str, replicas: u64) -> KubernetesDeployment {
        KubernetesDeployment {
            id: row_id(&format!("deployment:{uid}")),
            namespace: "incident".to_owned(),
            name: "api".to_owned(),
            desired_replicas: replicas,
            ready_replicas: replicas,
            available_replicas: replicas,
            updated_replicas: replicas,
            images: vec!["registry/api:1".to_owned()],
            created_at: String::new(),
        }
    }

    #[test]
    fn target_switch_and_deactivation_reject_late_results() {
        let target = TargetContext::new();
        let first = binding(&target, "host-a");
        let mut model = KubernetesModel::default();
        model.activate(Some(first.clone()));
        let stale = model
            .begin_request(RequestKind::List(KubernetesTab::Pods), Some(first.clone()))
            .unwrap();
        let second = binding(&target, "host-b");
        model.rebind(Some(second.clone()));
        assert!(!model.apply_rows(
            &stale,
            Some(&second),
            KubernetesRows::Pods(KubernetesCollection {
                items: vec![pod("late", "default", "late")],
                truncated: false,
            })
        ));

        let current = model
            .begin_request(RequestKind::List(KubernetesTab::Pods), Some(second.clone()))
            .unwrap();
        model.deactivate();
        assert!(!model.apply_rows(
            &current,
            Some(&second),
            KubernetesRows::Pods(KubernetesCollection {
                items: vec![pod("late-2", "default", "late-2")],
                truncated: false,
            })
        ));
    }

    #[test]
    fn stable_row_id_survives_sort_and_refresh() {
        let target = TargetContext::new();
        let current = binding(&target, "host-a");
        let mut model = KubernetesModel::default();
        model.activate(Some(current.clone()));
        let first = model
            .begin_request(
                RequestKind::List(KubernetesTab::Pods),
                Some(current.clone()),
            )
            .unwrap();
        assert!(model.apply_rows(
            &first,
            Some(&current),
            KubernetesRows::Pods(KubernetesCollection {
                items: vec![pod("uid-b", "zeta", "api"), pod("uid-a", "alpha", "web"),],
                truncated: false,
            })
        ));
        let selected = row_id("pod:uid-b");
        assert!(model.select(&selected));

        let refresh = model
            .begin_request(
                RequestKind::List(KubernetesTab::Pods),
                Some(current.clone()),
            )
            .unwrap();
        assert!(model.apply_rows(
            &refresh,
            Some(&current),
            KubernetesRows::Pods(KubernetesCollection {
                items: vec![pod("uid-a", "zulu", "web"), pod("uid-b", "aardvark", "api"),],
                truncated: false,
            })
        ));
        assert_eq!(model.selected.as_ref(), Some(&selected));
        assert_eq!(model.selected_row().unwrap().namespace(), Some("aardvark"));
    }

    #[test]
    fn filtering_and_windowing_are_bounded_and_hostile_text_stays_plain() {
        let target = TargetContext::new();
        let current = binding(&target, "host-a");
        let mut model = KubernetesModel::default();
        model.activate(Some(current.clone()));
        let lease = model
            .begin_request(
                RequestKind::List(KubernetesTab::Pods),
                Some(current.clone()),
            )
            .unwrap();
        let attack = "<img src=x onerror=alert(1)><script>bad()</script>";
        let mut items = (0..150)
            .map(|index| pod(&format!("uid-{index}"), "default", &format!("pod-{index}")))
            .collect::<Vec<_>>();
        items.push(pod("uid-attack", "default", attack));
        assert!(model.apply_rows(
            &lease,
            Some(&current),
            KubernetesRows::Pods(KubernetesCollection {
                items,
                truncated: false,
            })
        ));
        assert_eq!(model.visible_rows().len(), ROW_WINDOW_SIZE);
        model.move_window(1);
        assert_eq!(model.row_window_start, ROW_WINDOW_SIZE);
        model.set_query("<script>");
        assert_eq!(model.visible_rows().len(), 1);
        assert_eq!(model.visible_rows()[0].name(), attack);
        let source = include_str!("kubernetes.rs").to_lowercase();
        assert!(!source.contains(&["inner", "_html"].concat()));
        assert!(!source.contains(&["render", "_markdown"].concat()));
    }

    #[test]
    fn detail_and_logs_require_the_exact_selected_row_lease() {
        let target = TargetContext::new();
        let current = binding(&target, "host-a");
        let mut model = KubernetesModel::default();
        model.activate(Some(current.clone()));
        let list = model
            .begin_request(
                RequestKind::List(KubernetesTab::Pods),
                Some(current.clone()),
            )
            .unwrap();
        assert!(model.apply_rows(
            &list,
            Some(&current),
            KubernetesRows::Pods(KubernetesCollection {
                items: vec![
                    pod("uid-a", "default", "api"),
                    pod("uid-b", "default", "web"),
                ],
                truncated: false,
            })
        ));
        let first = row_id("pod:uid-a");
        assert!(model.select(&first));
        let detail = model
            .begin_request(RequestKind::Detail(first), Some(current.clone()))
            .unwrap();
        let second = row_id("pod:uid-b");
        assert!(model.select(&second));
        assert!(!model.apply_detail(
            &detail,
            Some(&current),
            KubernetesText {
                text: "late".to_owned(),
                truncated: false,
            }
        ));
    }

    #[test]
    fn mutation_lease_requires_the_exact_selected_row_target_and_lifecycle() {
        let target = TargetContext::new();
        let current = binding(&target, "host-a");
        let mut model = KubernetesModel::default();
        model.activate(Some(current.clone()));
        model.switch_tab(KubernetesTab::Deployments);
        let list = model
            .begin_request(
                RequestKind::List(KubernetesTab::Deployments),
                Some(current.clone()),
            )
            .unwrap();
        assert!(model.apply_rows(
            &list,
            Some(&current),
            KubernetesRows::Deployments(KubernetesCollection {
                items: vec![deployment("uid-a", 2), deployment("uid-b", 3)],
                truncated: false,
            })
        ));
        let first = row_id("deployment:uid-a");
        assert!(model.select(&first));
        let mutation = model
            .begin_request(RequestKind::Mutation(first), Some(current.clone()))
            .unwrap();
        assert!(model.accepts(&mutation, Some(&current)));
        assert!(model.select(&row_id("deployment:uid-b")));
        assert!(!model.accepts(&mutation, Some(&current)));
        model.deactivate();
        assert!(!model.accepts(&mutation, Some(&current)));
    }

    #[test]
    fn closed_reversible_mutations_are_wired_and_unsafe_surfaces_stay_disabled() {
        let source = include_str!("kubernetes.rs");
        for label in ["创建扩缩容计划", "缩容至 0", "Cordon", "Uncordon"] {
            assert!(source.contains(label));
        }
        assert!(source.contains("service.plan_mutation(&session, &request)"));
        assert!(source.contains("DangerousConfirmation::approve(pending.plan.definition())"));
        assert!(source.contains("service.execute_mutation("));
        for label in [
            "隔离（待完整回滚）",
            "Drain（工作负载迁移待实现）",
            "删除（不可恢复，禁用）",
            "Exec/Apply（任意命令面已删除）",
        ] {
            assert!(source.contains(label));
        }
    }
}
