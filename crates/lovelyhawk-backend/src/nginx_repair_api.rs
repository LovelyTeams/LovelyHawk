//! Finite Nginx repair workflow. Paths, node indexes, commands, replacement
//! bytes and core confirmations never come from the renderer.
use crate::ssh_api::SshApi;
use lovelyhawk_core::{
    BackendServices, CoreError,
    investigation::{AddEvidence, CaseCollectionReservation},
    middleware::{
        MiddlewareChangePlan, MiddlewareChangeState, MiddlewareConfigurationBundle,
        MiddlewareInstance, NginxConnectivityInput, NginxConnectivityReport,
        NginxHardeningCandidate, NginxListener,
    },
    operations::{DangerousConfirmation, OperationState},
    ssh::BoundSshSession,
    target::TargetGuard,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use uuid::Uuid;

const TTL: Duration = Duration::from_secs(300);
const MAX_BINDINGS: usize = 4;
const MAX_GRAPH_BYTES: usize = 4 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 512 * 1024;

#[derive(Deserialize)]
#[serde(
    tag = "action",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum NginxRepairRequest {
    Discover {
        binding_handle: String,
    },
    Load {
        binding_handle: String,
        instance_handle: String,
    },
    Listeners {
        binding_handle: String,
        instance_handle: String,
    },
    Probe {
        binding_handle: String,
        endpoint_handle: String,
        server_name: String,
        path: String,
    },
    Retain {
        binding_handle: String,
        observation_handle: String,
    },
    DiscardObservation {
        binding_handle: String,
        observation_handle: String,
    },
    Plan {
        binding_handle: String,
        configuration_handle: String,
        candidate_handle: String,
    },
    Confirm {
        binding_handle: String,
        plan_handle: String,
    },
    Execute {
        binding_handle: String,
        plan_handle: String,
    },
    Execution {
        binding_handle: String,
        execution_handle: String,
    },
    Cancel {
        binding_handle: String,
        plan_handle: String,
    },
    History {
        binding_handle: String,
    },
    Restore {
        binding_handle: String,
        record_handle: String,
    },
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InstanceDto {
    instance_handle: String,
    title: String,
    version: String,
    main_pid: u32,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ListenerDto {
    endpoint_handle: String,
    address: String,
    port: u16,
    connect_address: String,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RetentionDto {
    state: &'static str,
    case_id: Option<String>,
    case_title: Option<String>,
    evidence_id: Option<String>,
    sha256: Option<String>,
    detail: &'static str,
    can_retry: bool,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CandidateDto {
    candidate_handle: String,
    setting: String,
    title: String,
    path: String,
    line: usize,
    before: String,
    after: String,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PlanDto {
    plan_handle: String,
    target_label: String,
    candidate_handle: Option<String>,
    title: String,
    path: String,
    line: Option<usize>,
    diff: String,
    impact: String,
    restore_description: String,
    confirmed: bool,
    expires_in_seconds: u32,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReceiptDto {
    plan_handle: String,
    state: String,
    detail: String,
    record_handle: Option<String>,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecordDto {
    record_handle: String,
    path: String,
    state: String,
    created_at: String,
    can_prepare_restore: bool,
}
#[derive(Clone, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub(crate) enum NginxRepairResponse {
    Inventory {
        instances: Vec<InstanceDto>,
    },
    Listeners {
        instance_handle: String,
        endpoints: Vec<ListenerDto>,
    },
    Connectivity {
        observation_handle: String,
        record_text: Option<String>,
        endpoint_handle: String,
        server_name: String,
        path: String,
        checked_at: String,
        report: NginxConnectivityReport,
        retention: RetentionDto,
    },
    Retention {
        observation_handle: String,
        retention: RetentionDto,
    },
    ObservationDiscarded {
        observation_handle: String,
    },
    Configuration {
        configuration_handle: String,
        instance_handle: String,
        file_count: usize,
        unresolved_includes: usize,
        candidates: Vec<CandidateDto>,
    },
    Plan {
        plan: PlanDto,
    },
    Execution {
        execution_handle: String,
        receipt: Option<ReceiptDto>,
    },
    Cancelled {
        cancelled: bool,
    },
    History {
        records: Vec<RecordDto>,
        total_records: usize,
        truncated: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Scope {
    binding: String,
    session: String,
    connection: String,
    target: TargetGuard,
}
struct Configuration {
    handle: String,
    bundle: Arc<MiddlewareConfigurationBundle>,
    candidates: HashMap<String, NginxHardeningCandidate>,
}
struct Plan {
    core: MiddlewareChangePlan,
    dto: PlanDto,
    expires: Instant,
}
struct Observation {
    handle: String,
    material: Option<AddEvidence>,
    destination: Option<(String, String)>,
    retention: RetentionDto,
}
struct Entry {
    scope: Scope,
    expires: Instant,
    lease: Option<Uuid>,
    instances: HashMap<String, MiddlewareInstance>,
    endpoints: HashMap<String, (MiddlewareInstance, NginxListener)>,
    observation: Option<Observation>,
    configuration: Option<Configuration>,
    plan: Option<Plan>,
    records: HashMap<String, String>,
    execution: Option<(String, Option<ReceiptDto>)>,
}
#[derive(Default)]
struct Registry {
    entries: HashMap<String, Entry>,
}

#[derive(Clone)]
pub(crate) struct NginxRepairApi {
    services: BackendServices,
    ssh: Arc<SshApi>,
    registry: Arc<Mutex<Registry>>,
}
impl std::fmt::Debug for NginxRepairApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NginxRepairApi([private state])")
    }
}
#[derive(Clone, Copy, Debug)]
pub(crate) enum NginxRepairError {
    Invalid,
    Stale,
    Busy,
    Capacity,
    Unsupported,
    Connectivity,
    PendingEvidence,
    Core,
}

struct Lease {
    registry: Arc<Mutex<Registry>>,
    scope: Scope,
    ticket: Uuid,
}
impl Drop for Lease {
    fn drop(&mut self) {
        if let Ok(mut registry) = self.registry.lock()
            && let Some(entry) = registry.entries.get_mut(&self.scope.binding)
            && entry.scope == self.scope
            && entry.lease == Some(self.ticket)
        {
            entry.lease = None;
            entry.expires = Instant::now() + TTL;
        }
    }
}

impl NginxRepairApi {
    pub(crate) fn new(services: BackendServices, ssh: Arc<SshApi>) -> Self {
        Self {
            services,
            ssh,
            registry: Arc::new(Mutex::new(Registry::default())),
        }
    }
    pub(crate) fn close_binding(&self, binding: &str) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.entries.remove(binding);
        }
    }
    fn capture(&self, binding: &str) -> Result<(Scope, BoundSshSession), NginxRepairError> {
        handle(binding)?;
        let session = self
            .ssh
            .binding_session_clone(binding)
            .map_err(|_| NginxRepairError::Stale)?;
        self.services
            .target()
            .validate(session.target())
            .map_err(|_| NginxRepairError::Stale)?;
        Ok((
            Scope {
                binding: binding.to_owned(),
                session: session.session_id().to_owned(),
                connection: session.connection_id().to_owned(),
                target: session.target().clone(),
            },
            session,
        ))
    }
    fn validate(&self, scope: &Scope) -> Result<(), NginxRepairError> {
        if self.capture(&scope.binding)?.0 != *scope {
            return Err(NginxRepairError::Stale);
        }
        Ok(())
    }
    fn with_entry<T>(
        &self,
        scope: &Scope,
        work: impl FnOnce(&mut Entry) -> Result<T, NginxRepairError>,
    ) -> Result<T, NginxRepairError> {
        self.validate(scope)?;
        let mut registry = self.registry.lock().map_err(|_| NginxRepairError::Core)?;
        let entry = registry
            .entries
            .get_mut(&scope.binding)
            .ok_or(NginxRepairError::Stale)?;
        if entry.scope != *scope || entry.lease.is_none() && entry.expires <= Instant::now() {
            return Err(NginxRepairError::Stale);
        }
        work(entry)
    }
    fn begin(&self, binding: &str) -> Result<(Lease, BoundSshSession), NginxRepairError> {
        let (scope, session) = self.capture(binding)?;
        let mut registry = self.registry.lock().map_err(|_| NginxRepairError::Core)?;
        registry
            .entries
            .retain(|_, entry| entry.lease.is_some() || entry.expires > Instant::now());
        if !registry.entries.contains_key(binding) {
            if registry.entries.len() >= MAX_BINDINGS {
                return Err(NginxRepairError::Capacity);
            }
            registry.entries.insert(
                binding.to_owned(),
                Entry {
                    scope: scope.clone(),
                    expires: Instant::now() + TTL,
                    lease: None,
                    instances: HashMap::new(),
                    endpoints: HashMap::new(),
                    observation: None,
                    configuration: None,
                    plan: None,
                    records: HashMap::new(),
                    execution: None,
                },
            );
        }
        let entry = registry
            .entries
            .get_mut(binding)
            .ok_or(NginxRepairError::Stale)?;
        if entry.scope != scope {
            return Err(NginxRepairError::Stale);
        }
        if entry.lease.is_some() {
            return Err(NginxRepairError::Busy);
        }
        let ticket = Uuid::new_v4();
        entry.lease = Some(ticket);
        Ok((
            Lease {
                registry: self.registry.clone(),
                scope,
                ticket,
            },
            session,
        ))
    }
    fn finish<T>(
        &self,
        lease: &Lease,
        work: impl FnOnce(&mut Entry) -> Result<T, NginxRepairError>,
    ) -> Result<T, NginxRepairError> {
        self.with_entry(&lease.scope, |entry| {
            if entry.lease != Some(lease.ticket) {
                return Err(NginxRepairError::Stale);
            }
            work(entry)
        })
    }
    pub(crate) async fn dispatch(
        &self,
        request: NginxRepairRequest,
    ) -> Result<NginxRepairResponse, NginxRepairError> {
        let result = match request {
            NginxRepairRequest::Retain {
                binding_handle,
                observation_handle,
            } => self.retain(&binding_handle, &observation_handle),
            NginxRepairRequest::DiscardObservation {
                binding_handle,
                observation_handle,
            } => self.discard_observation(&binding_handle, &observation_handle),
            NginxRepairRequest::Discover { binding_handle } => self.discover(&binding_handle).await,
            NginxRepairRequest::Load {
                binding_handle,
                instance_handle,
            } => self.load(&binding_handle, &instance_handle).await,
            NginxRepairRequest::Listeners {
                binding_handle,
                instance_handle,
            } => self.listeners(&binding_handle, &instance_handle).await,
            NginxRepairRequest::Probe {
                binding_handle,
                endpoint_handle,
                server_name,
                path,
            } => {
                self.probe(&binding_handle, &endpoint_handle, &server_name, &path)
                    .await
            }
            NginxRepairRequest::Plan {
                binding_handle,
                configuration_handle,
                candidate_handle,
            } => {
                self.plan(&binding_handle, &configuration_handle, &candidate_handle)
                    .await
            }
            NginxRepairRequest::Confirm {
                binding_handle,
                plan_handle,
            } => self.confirm(&binding_handle, &plan_handle),
            NginxRepairRequest::Execute {
                binding_handle,
                plan_handle,
            } => self.execute(&binding_handle, &plan_handle),
            NginxRepairRequest::Execution {
                binding_handle,
                execution_handle,
            } => self.execution(&binding_handle, &execution_handle),
            NginxRepairRequest::Cancel {
                binding_handle,
                plan_handle,
            } => self.cancel(&binding_handle, &plan_handle),
            NginxRepairRequest::History { binding_handle } => self.history(&binding_handle),
            NginxRepairRequest::Restore {
                binding_handle,
                record_handle,
            } => self.restore(&binding_handle, &record_handle).await,
        }?;
        bounded(&result)?;
        Ok(result)
    }
    async fn discover(&self, binding: &str) -> Result<NginxRepairResponse, NginxRepairError> {
        let (lease, session) = self.begin(binding)?;
        self.finish(&lease, |entry| {
            replace_observation(entry)?;
            entry.instances.clear();
            entry.endpoints.clear();
            entry.configuration = None;
            entry.plan = None;
            Ok(())
        })?;
        let instances = self
            .services
            .middleware()
            .discover_nginx_processes(&session)
            .await
            .map_err(|_| NginxRepairError::Unsupported)?;
        let mut stored = HashMap::new();
        let mut dto = Vec::new();
        for instance in instances {
            let key = Uuid::new_v4().to_string();
            dto.push(InstanceDto {
                instance_handle: key.clone(),
                title: format!("Nginx 主进程 {}", instance.main_pid()),
                version: display(instance.version(), 256),
                main_pid: instance.main_pid(),
            });
            stored.insert(key, instance);
        }
        self.finish(&lease, |entry| {
            entry.instances = stored;
            Ok(())
        })?;
        Ok(NginxRepairResponse::Inventory { instances: dto })
    }
    async fn load(
        &self,
        binding: &str,
        instance: &str,
    ) -> Result<NginxRepairResponse, NginxRepairError> {
        handle(instance)?;
        let (lease, session) = self.begin(binding)?;
        let selected = self.finish(&lease, |entry| {
            replace_observation(entry)?;
            entry.endpoints.clear();
            entry.configuration = None;
            entry.plan = None;
            entry
                .instances
                .get(instance)
                .cloned()
                .ok_or(NginxRepairError::Stale)
        })?;
        let bundle = Arc::new(
            self.services
                .middleware()
                .load_configuration(&session, &selected)
                .await
                .map_err(|_| NginxRepairError::Core)?,
        );
        if bundle.total_bytes() > MAX_GRAPH_BYTES {
            return Err(NginxRepairError::Capacity);
        }
        let candidates = bundle
            .nginx_hardening_candidates()
            .map_err(|_| NginxRepairError::Unsupported)?;
        let configuration_handle = Uuid::new_v4().to_string();
        let mut stored = HashMap::new();
        let mut dto = Vec::new();
        for candidate in candidates {
            let key = Uuid::new_v4().to_string();
            dto.push(CandidateDto {
                candidate_handle: key.clone(),
                setting: candidate.setting().id().to_owned(),
                title: candidate.setting().label().to_owned(),
                path: candidate.path().as_str().to_owned(),
                line: candidate.line(),
                before: candidate.before().to_owned(),
                after: candidate.after().to_owned(),
            });
            stored.insert(key, candidate);
        }
        let response = NginxRepairResponse::Configuration {
            configuration_handle: configuration_handle.clone(),
            instance_handle: instance.to_owned(),
            file_count: bundle.files().len(),
            unresolved_includes: bundle.unresolved_includes().len(),
            candidates: dto,
        };
        bounded(&response)?;
        self.finish(&lease, |entry| {
            entry.configuration = Some(Configuration {
                handle: configuration_handle,
                bundle,
                candidates: stored,
            });
            Ok(())
        })?;
        Ok(response)
    }
    async fn listeners(
        &self,
        binding: &str,
        instance: &str,
    ) -> Result<NginxRepairResponse, NginxRepairError> {
        handle(instance)?;
        let (lease, session) = self.begin(binding)?;
        let selected = self.finish(&lease, |entry| {
            replace_observation(entry)?;
            entry.endpoints.clear();
            entry
                .instances
                .get(instance)
                .cloned()
                .ok_or(NginxRepairError::Stale)
        })?;
        let listeners = self
            .services
            .middleware()
            .nginx_listeners(&session, &selected)
            .await
            .map_err(|_| NginxRepairError::Connectivity)?;
        let mut stored = HashMap::new();
        let mut endpoints = Vec::new();
        for listener in listeners {
            let key = Uuid::new_v4().to_string();
            endpoints.push(ListenerDto {
                endpoint_handle: key.clone(),
                address: listener.address(),
                port: listener.port(),
                connect_address: listener.connect_address(),
            });
            stored.insert(key, (selected.clone(), listener));
        }
        self.finish(&lease, |entry| {
            entry.endpoints = stored;
            Ok(())
        })?;
        Ok(NginxRepairResponse::Listeners {
            instance_handle: instance.to_owned(),
            endpoints,
        })
    }

    async fn probe(
        &self,
        binding: &str,
        endpoint: &str,
        server_name: &str,
        path: &str,
    ) -> Result<NginxRepairResponse, NginxRepairError> {
        handle(endpoint)?;
        let input = NginxConnectivityInput::new(server_name, path)
            .map_err(|_| NginxRepairError::Invalid)?;
        let (lease, session) = self.begin(binding)?;
        let (instance, listener) = self.finish(&lease, |entry| {
            replace_observation(entry)?;
            entry
                .endpoints
                .get(endpoint)
                .cloned()
                .ok_or(NginxRepairError::Stale)
        })?;
        let status = self
            .services
            .ssh()
            .list_sessions()
            .await
            .map_err(|_| NginxRepairError::Stale)?
            .into_iter()
            .find(|status| {
                status.session_id == lease.scope.session
                    && status.connection_id == lease.scope.connection
            })
            .ok_or(NginxRepairError::Stale)?;
        let host = if status.host.contains(':') {
            format!("[{}]", status.host)
        } else {
            status.host
        };
        let source_label = format!("{}@{host}:{}", status.username, status.port);
        self.validate(&lease.scope)?;
        let mut observation = Observation {
            handle: Uuid::new_v4().to_string(),
            material: None,
            destination: None,
            retention: unsaved("尚未保存连接观察。", true),
        };
        let reservation = self.reserve_observation_case(&lease.scope, &mut observation);
        let report = self
            .services
            .middleware()
            .nginx_connectivity(&session, &instance, &listener, &input)
            .await
            .map_err(|_| NginxRepairError::Connectivity)?;
        observation.material = self
            .services
            .middleware()
            .nginx_connectivity_evidence(
                &session,
                &instance,
                &listener,
                &input,
                &report,
                &source_label,
            )
            .ok();
        if observation.material.is_none() {
            observation.retention = unsaved(
                "未能生成符合保存要求的完整连接记录，当前结果未留证；请保留页面信息后放弃本次未保存结果并重新读取实例。",
                false,
            );
        } else if reservation.is_ok() {
            self.finish(&lease, |_| {
                self.save_observation(&lease.scope, &mut observation);
                Ok(())
            })?;
        }
        let observation_handle = observation.handle.clone();
        let record_text = observation
            .material
            .as_ref()
            .map(|material| material.preview.clone());
        let retention = observation.retention.clone();
        self.finish(&lease, |entry| {
            entry.observation = Some(observation);
            Ok(())
        })?;
        drop(reservation);
        Ok(NginxRepairResponse::Connectivity {
            observation_handle,
            record_text,
            endpoint_handle: endpoint.to_owned(),
            server_name: server_name.to_owned(),
            path: path.to_owned(),
            checked_at: report.checked_at().to_rfc3339(),
            report,
            retention,
        })
    }

    fn reserve_observation_case(
        &self,
        scope: &Scope,
        observation: &mut Observation,
    ) -> Result<CaseCollectionReservation, ()> {
        let cases = self.services.investigation().cases();
        if observation.destination.is_none() {
            match cases.ensure_active(&scope.target.identity, None) {
                Ok(incident) => observation.destination = Some((incident.id, incident.title)),
                Err(error) => {
                    observation.retention = unsaved(retention_error(&error), true);
                    return Err(());
                }
            }
        }
        let Some((case_id, case_title)) = observation.destination.as_ref() else {
            return Err(());
        };
        observation.retention.case_id = Some(case_id.clone());
        observation.retention.case_title = Some(case_title.clone());
        cases
            .reserve_collection(&scope.target.identity, case_id)
            .map_err(|error| {
                observation.retention.detail = retention_error(&error);
            })
    }

    fn save_observation(&self, scope: &Scope, observation: &mut Observation) {
        let (Some(material), Some((case_id, case_title))) =
            (&observation.material, &observation.destination)
        else {
            return;
        };
        match self.services.investigation().cases().add_evidence_to_case(
            &scope.target.identity,
            case_id,
            material.clone(),
        ) {
            Ok(evidence) => {
                observation.retention = RetentionDto {
                    state: "saved",
                    case_id: Some(case_id.clone()),
                    case_title: Some(case_title.clone()),
                    evidence_id: Some(evidence.id),
                    sha256: Some(evidence.sha256),
                    can_retry: false,
                    detail: "已保存完整连接观察并加入案件时间线；摘要校验案件记录，不代表原始网络包或业务已恢复。",
                }
            }
            Err(error) => {
                observation.retention.state = "unsaved";
                observation.retention.detail = retention_error(&error);
            }
        }
    }

    fn retain(
        &self,
        binding: &str,
        handle_value: &str,
    ) -> Result<NginxRepairResponse, NginxRepairError> {
        handle(handle_value)?;
        let (lease, _) = self.begin(binding)?;
        self.finish(&lease, |entry| {
            let observation = entry
                .observation
                .as_mut()
                .filter(|item| item.handle == handle_value)
                .ok_or(NginxRepairError::Stale)?;
            if observation.retention.state != "saved"
                && observation.retention.can_retry
                && let Ok(_reservation) = self.reserve_observation_case(&lease.scope, observation)
            {
                self.save_observation(&lease.scope, observation);
            }
            Ok(NginxRepairResponse::Retention {
                observation_handle: handle_value.to_owned(),
                retention: observation.retention.clone(),
            })
        })
    }

    fn discard_observation(
        &self,
        binding: &str,
        handle_value: &str,
    ) -> Result<NginxRepairResponse, NginxRepairError> {
        handle(handle_value)?;
        let (lease, _) = self.begin(binding)?;
        self.finish(&lease, |entry| {
            if entry
                .observation
                .as_ref()
                .is_none_or(|item| item.handle != handle_value)
            {
                return Err(NginxRepairError::Stale);
            }
            entry.observation = None;
            Ok(NginxRepairResponse::ObservationDiscarded {
                observation_handle: handle_value.to_owned(),
            })
        })
    }

    async fn plan(
        &self,
        binding: &str,
        configuration: &str,
        candidate: &str,
    ) -> Result<NginxRepairResponse, NginxRepairError> {
        handle(configuration)?;
        handle(candidate)?;
        let (lease, session) = self.begin(binding)?;
        let (bundle, selected) = self.finish(&lease, |entry| {
            entry.plan = None;
            let cached = entry
                .configuration
                .as_ref()
                .filter(|config| config.handle == configuration)
                .ok_or(NginxRepairError::Stale)?;
            Ok((
                cached.bundle.clone(),
                cached
                    .candidates
                    .get(candidate)
                    .cloned()
                    .ok_or(NginxRepairError::Stale)?,
            ))
        })?;
        let plan = self
            .services
            .middleware()
            .plan_nginx_hardening(&session, &bundle, &selected)
            .await
            .map_err(|_| NginxRepairError::Core)?;
        let diff = format!("- {}\n+ {}", selected.before(), selected.after());
        self.store_plan(
            &lease,
            plan,
            selected.setting().label(),
            diff,
            Some((candidate.to_owned(), selected.line())),
        )
        .await
    }
    async fn store_plan(
        &self,
        lease: &Lease,
        core: MiddlewareChangePlan,
        title: &str,
        diff: String,
        location: Option<(String, usize)>,
    ) -> Result<NginxRepairResponse, NginxRepairError> {
        if diff.len() > 256 * 1024 {
            return Err(NginxRepairError::Capacity);
        }
        let connected = self
            .services
            .ssh()
            .list_sessions()
            .await
            .map_err(|_| NginxRepairError::Stale)?
            .into_iter()
            .find(|status| {
                status.session_id == lease.scope.session
                    && status.connection_id == lease.scope.connection
            })
            .ok_or(NginxRepairError::Stale)?;
        let host = if connected.host.contains(':') {
            format!("[{}]", connected.host)
        } else {
            connected.host
        };
        let target_label = display(
            &format!(
                "{}@{}:{} · Nginx 主进程 {}",
                connected.username,
                host,
                connected.port,
                core.instance().main_pid()
            ),
            1024,
        );
        let impact = if title == "隐藏 Nginx 版本" {
            "写入所选配置文件并平滑重载此实例；关闭该位置的 Nginx 版本显示，不会移除所有响应标识。验证工作进程切换后仍需检查业务。"
        } else if title == "移除旧版 TLS/SSL 协议" {
            "仅从这一处 ssl_protocols 移除旧版协议，保留原有 TLSv1.2/TLSv1.3 组合并平滑重载。仅支持旧版协议的客户端可能无法连接；请先确认客户端兼容性。实际协议还受监听地址的默认服务器及 OpenSSL 配置影响，重载后须用真实客户端复核 TLS 连接。"
        } else if location.is_some() {
            "写入所选配置文件并平滑重载此实例；关闭目录列表可能使目录请求返回 403。验证工作进程切换后仍需检查业务。"
        } else {
            "恢复备份中的完整文件并平滑重载；这会撤销此前修补，可能重新启用旧版 TLS/SSL 协议、目录列表或版本显示。请核对差异并检查实际业务连接。"
        };
        let dto = PlanDto {
            plan_handle: Uuid::new_v4().to_string(),
            target_label,
            title: title.to_owned(),
            candidate_handle: location.as_ref().map(|(key, _)| key.clone()),
            line: location.map(|(_, line)| line),
            path: core.preview().path.as_str().to_owned(),
            diff,
            impact: impact.to_owned(),
            restore_description:
                "先保留远端备份；验证失败时，在实例和配置未被其他操作改变的条件下恢复。".to_owned(),
            confirmed: false,
            expires_in_seconds: 300,
        };
        let response = NginxRepairResponse::Plan { plan: dto.clone() };
        bounded(&response)?;
        self.finish(lease, |entry| {
            entry.plan = Some(Plan {
                core,
                dto,
                expires: Instant::now() + TTL,
            });
            Ok(())
        })?;
        Ok(response)
    }
    fn confirm(&self, binding: &str, plan: &str) -> Result<NginxRepairResponse, NginxRepairError> {
        handle(plan)?;
        let scope = self.capture(binding)?.0;
        self.with_entry(&scope, |entry| {
            if entry.lease.is_some() {
                return Err(NginxRepairError::Busy);
            }
            let stored = entry
                .plan
                .as_mut()
                .filter(|stored| stored.dto.plan_handle == plan && stored.expires > Instant::now())
                .ok_or(NginxRepairError::Stale)?;
            if !stored.dto.confirmed {
                stored
                    .core
                    .confirm(DangerousConfirmation::approve(stored.core.definition()))
                    .map_err(|_| NginxRepairError::Core)?;
                stored.dto.confirmed = true;
            }
            stored.dto.expires_in_seconds = seconds_left(stored.expires);
            Ok(NginxRepairResponse::Plan {
                plan: stored.dto.clone(),
            })
        })
    }
    fn execute(&self, binding: &str, plan: &str) -> Result<NginxRepairResponse, NginxRepairError> {
        handle(plan)?;
        let (lease, _) = self.begin(binding)?;
        let mut stored = self.finish(&lease, |entry| {
            replace_observation(entry)?;
            let stored = entry
                .plan
                .as_ref()
                .filter(|stored| stored.dto.plan_handle == plan && stored.expires > Instant::now())
                .ok_or(NginxRepairError::Stale)?;
            if !stored.dto.confirmed {
                return Err(NginxRepairError::Invalid);
            }
            entry.plan.take().ok_or(NginxRepairError::Stale)
        })?;
        let execution_handle = Uuid::new_v4().to_string();
        self.finish(&lease, |entry| {
            entry.execution = Some((execution_handle.clone(), None));
            entry.endpoints.clear();
            Ok(())
        })?;
        let api = self.clone();
        // serve() processes RPC frames serially. Continue the core verification
        // and recovery job independently so status/disconnect requests can run,
        // and a renderer timeout does not drop a half-applied operation future.
        tokio::spawn(async move {
            let operation_id = stored.core.definition().id.clone();
            let outcome = stored.core.execute_and_verify().await;
            let (state, detail) = match &outcome {
                Ok(value) if value.verification.passed => (
                    "verified",
                    "所选配置已写入，Nginx 检查与工作进程切换已核实。请继续检查业务请求。",
                ),
                _ if stored.core.state() == OperationState::Restored => (
                    "restored",
                    "修补验证未通过，原配置已恢复并完成运行检查；请确认业务状态。",
                ),
                _ => (
                    "unverified",
                    "未能确认操作最终状态。已尝试保留恢复记录，请重新检查实例和历史；不要重放旧计划。",
                ),
            };
            let record = api
                .services
                .middleware()
                .history(&lease.scope.target)
                .ok()
                .and_then(|records| {
                    records
                        .into_iter()
                        .find(|record| record.operation_id == operation_id)
                });
            let _ = api.finish(&lease, |entry| {
                let record_handle = record.map(|record| {
                    if entry.records.len() >= 64 {
                        entry.records.clear();
                    }
                    let key = Uuid::new_v4().to_string();
                    entry.records.insert(key.clone(), record.id);
                    key
                });
                if let Some((_, receipt)) = &mut entry.execution {
                    *receipt = Some(ReceiptDto {
                        plan_handle: stored.dto.plan_handle,
                        state: state.to_owned(),
                        detail: detail.to_owned(),
                        record_handle,
                    });
                }
                entry.configuration = None;
                Ok(())
            });
        });
        Ok(NginxRepairResponse::Execution {
            execution_handle,
            receipt: None,
        })
    }
    fn execution(
        &self,
        binding: &str,
        execution: &str,
    ) -> Result<NginxRepairResponse, NginxRepairError> {
        handle(execution)?;
        let scope = self.capture(binding)?.0;
        self.with_entry(&scope, |entry| {
            let (key, receipt) = entry
                .execution
                .as_ref()
                .filter(|(key, _)| key == execution)
                .ok_or(NginxRepairError::Stale)?;
            Ok(NginxRepairResponse::Execution {
                execution_handle: key.clone(),
                receipt: receipt.clone(),
            })
        })
    }
    fn cancel(&self, binding: &str, plan: &str) -> Result<NginxRepairResponse, NginxRepairError> {
        handle(plan)?;
        let scope = self.capture(binding)?.0;
        self.with_entry(&scope, |entry| {
            let cancelled = entry
                .plan
                .as_ref()
                .is_some_and(|stored| stored.dto.plan_handle == plan);
            if cancelled {
                entry.plan = None;
            }
            Ok(NginxRepairResponse::Cancelled { cancelled })
        })
    }
    fn history(&self, binding: &str) -> Result<NginxRepairResponse, NginxRepairError> {
        let (lease, _) = self.begin(binding)?;
        let records = self
            .services
            .middleware()
            .history(&lease.scope.target)
            .map_err(|_| NginxRepairError::Core)?
            .into_iter()
            .filter(|record| record.nginx_process_evidence.is_some())
            .collect::<Vec<_>>();
        let total_records = records.len();
        let previous = self.finish(&lease, |entry| Ok(entry.records.clone()))?;
        let mut handles = HashMap::new();
        let mut dto = Vec::new();
        for record in records.into_iter().take(64) {
            let key = previous
                .iter()
                .find(|(_, id)| **id == record.id)
                .map(|(key, _)| key.clone())
                .unwrap_or_else(|| Uuid::new_v4().to_string());
            let state = match record.state {
                MiddlewareChangeState::Applied => "applied",
                MiddlewareChangeState::AutomaticallyRestored => "restored",
                MiddlewareChangeState::RecoveryPending => "pending",
                MiddlewareChangeState::RestoreFailed => "restore-failed",
            };
            dto.push(RecordDto {
                record_handle: key.clone(),
                path: record.path.as_str().to_owned(),
                state: state.to_owned(),
                created_at: record.created_at.to_rfc3339(),
                can_prepare_restore: record.state != MiddlewareChangeState::AutomaticallyRestored,
            });
            handles.insert(key, record.id);
        }
        self.finish(&lease, |entry| {
            entry.records = handles;
            Ok(())
        })?;
        Ok(NginxRepairResponse::History {
            records: dto,
            total_records,
            truncated: total_records > 64,
        })
    }
    async fn restore(
        &self,
        binding: &str,
        record: &str,
    ) -> Result<NginxRepairResponse, NginxRepairError> {
        handle(record)?;
        let (lease, session) = self.begin(binding)?;
        let record = self.finish(&lease, |entry| {
            entry.plan = None;
            entry
                .records
                .get(record)
                .cloned()
                .ok_or(NginxRepairError::Stale)
        })?;
        let plan = self
            .services
            .middleware()
            .plan_restore(&session, &record)
            .await
            .map_err(|_| NginxRepairError::Core)?;
        let diff = plan.safe_diff().to_owned();
        self.store_plan(&lease, plan, "恢复先前配置", diff, None)
            .await
    }
}

fn seconds_left(expires: Instant) -> u32 {
    u32::try_from(
        expires
            .saturating_duration_since(Instant::now())
            .as_secs()
            .max(1),
    )
    .unwrap_or(300)
    .min(300)
}
fn replace_observation(entry: &mut Entry) -> Result<(), NginxRepairError> {
    if entry
        .observation
        .as_ref()
        .is_some_and(|item| item.retention.state != "saved")
    {
        return Err(NginxRepairError::PendingEvidence);
    }
    entry.observation = None;
    Ok(())
}
fn unsaved(detail: &'static str, can_retry: bool) -> RetentionDto {
    RetentionDto {
        state: "unsaved",
        case_id: None,
        case_title: None,
        evidence_id: None,
        sha256: None,
        detail,
        can_retry,
    }
}
fn retention_error(error: &CoreError) -> &'static str {
    match error {
        CoreError::Validation {
            subject: "case capacity" | "case evidence capacity" | "case timeline capacity",
            ..
        } => {
            "案件或记录容量已满，本次结果尚未保存，现有记录未删除。请先复制完整记录；案件已满时需新建案件后重新复核。"
        }
        _ => {
            "连接结果尚未保存。请检查本机空间、案件是否仍开放及采集占用后重试；重试只保存本次观察，不重新探测。"
        }
    }
}
fn handle(value: &str) -> Result<(), NginxRepairError> {
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(NginxRepairError::Invalid);
    }
    Ok(())
}
fn display(value: &str, limit: usize) -> String {
    value
        .chars()
        .take(limit)
        .map(|c| if c.is_control() { '\u{fffd}' } else { c })
        .collect()
}
fn bounded(value: &NginxRepairResponse) -> Result<(), NginxRepairError> {
    if serde_json::to_vec(value)
        .map_err(|_| NginxRepairError::Core)?
        .len()
        > MAX_RESPONSE_BYTES
    {
        return Err(NginxRepairError::Capacity);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lovelyhawk_core::target::TargetIdentity;
    use serde_json::json;

    #[test]
    fn connection_probe_cannot_supply_an_address_port_ca_file_or_shell_program() {
        let value = json!({"action":"probe","bindingHandle":"b","endpointHandle":"e","serverName":"a.test","path":"/"});
        assert!(serde_json::from_value::<NginxRepairRequest>(value.clone()).is_ok());
        for field in [
            "address",
            "port",
            "caFile",
            "skipVerify",
            "command",
            "__proto__",
        ] {
            let mut forged = value.clone();
            forged[field] = json!("untrusted");
            assert!(serde_json::from_value::<NginxRepairRequest>(forged).is_err());
        }
        for field in ["endpointHandle", "serverName", "path"] {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<NginxRepairRequest>(missing).is_err());
        }
    }

    #[test]
    fn retaining_an_observation_never_accepts_client_case_evidence_or_source_fields() {
        for action in ["retain", "discard-observation"] {
            let value = json!({"action":action,"bindingHandle":"b","observationHandle":"o"});
            assert!(serde_json::from_value::<NginxRepairRequest>(value.clone()).is_ok());
            for key in [
                "caseId",
                "sha256",
                "recordText",
                "target",
                "source",
                "evidenceId",
            ] {
                let mut forged = value.clone();
                forged[key] = json!("invented");
                assert!(serde_json::from_value::<NginxRepairRequest>(forged).is_err());
            }
        }
    }

    #[test]
    fn requests_are_closed_intents_without_paths_commands_or_confirmation_material() {
        for (action, fields) in [
            ("discover", vec![]),
            ("history", vec![]),
            ("load", vec!["instanceHandle"]),
            ("plan", vec!["configurationHandle", "candidateHandle"]),
            ("confirm", vec!["planHandle"]),
            ("execute", vec!["planHandle"]),
            ("cancel", vec!["planHandle"]),
            ("execution", vec!["executionHandle"]),
            ("restore", vec!["recordHandle"]),
        ] {
            let mut valid = json!({"action": action, "bindingHandle": "b"});
            for field in &fields {
                valid[field] = json!("h");
            }
            assert!(serde_json::from_value::<NginxRepairRequest>(valid.clone()).is_ok());
            for extra in [
                "path",
                "command",
                "replacement",
                "nodeIndex",
                "confirmed",
                "target",
                "__proto__",
            ] {
                let mut forged = valid.clone();
                forged[extra] = json!("forged");
                assert!(
                    serde_json::from_value::<NginxRepairRequest>(forged).is_err(),
                    "{action}: {extra}"
                );
            }
            for field in fields {
                let mut missing = valid.clone();
                missing.as_object_mut().unwrap().remove(field);
                assert!(serde_json::from_value::<NginxRepairRequest>(missing).is_err());
            }
        }
        for action in [
            "shell",
            "repair-any",
            "constructor",
            "__proto__",
            "Discover",
        ] {
            assert!(
                serde_json::from_value::<NginxRepairRequest>(
                    json!({"action": action, "bindingHandle": "b"})
                )
                .is_err()
            );
        }
    }

    #[test]
    fn handles_are_bounded_by_utf8_bytes_and_reject_control_characters() {
        for invalid in [
            String::new(),
            "x".repeat(129),
            "汉".repeat(60),
            "a\n".into(),
            "a\u{7f}".into(),
            "a\u{85}".into(),
        ] {
            assert!(matches!(handle(&invalid), Err(NginxRepairError::Invalid)));
        }
        assert!(handle(&"x".repeat(128)).is_ok());
    }

    fn scope() -> Scope {
        Scope {
            binding: "b".into(),
            session: "s".into(),
            connection: "c".into(),
            target: TargetGuard {
                identity: TargetIdentity::new("host").unwrap(),
                generation: 1,
            },
        }
    }
    fn entry(scope: Scope, ticket: Uuid) -> Entry {
        Entry {
            scope,
            expires: Instant::now() + TTL,
            lease: Some(ticket),
            instances: HashMap::new(),
            endpoints: HashMap::new(),
            observation: None,
            configuration: None,
            plan: None,
            records: HashMap::new(),
            execution: None,
        }
    }
    #[test]
    fn new_reads_cannot_silently_overwrite_an_unsaved_measurement() {
        let mut entry = entry(scope(), Uuid::new_v4());
        entry.observation = Some(Observation {
            handle: "original".into(),
            material: None,
            destination: None,
            retention: unsaved("failed", false),
        });
        assert!(matches!(
            replace_observation(&mut entry),
            Err(NginxRepairError::PendingEvidence)
        ));
        assert_eq!(entry.observation.as_ref().unwrap().handle, "original");
        entry.observation.as_mut().unwrap().retention.state = "saved";
        replace_observation(&mut entry).unwrap();
        assert!(entry.observation.is_none());
    }
    #[test]
    fn dropping_old_leases_cannot_release_new_jobs_or_recreate_closed_bindings() {
        let registry = Arc::new(Mutex::new(Registry::default()));
        let scope = scope();
        let old = Uuid::new_v4();
        let new = Uuid::new_v4();
        let lease = || Lease {
            registry: registry.clone(),
            scope: scope.clone(),
            ticket: old,
        };
        registry
            .lock()
            .unwrap()
            .entries
            .insert(scope.binding.clone(), entry(scope.clone(), new));
        drop(lease());
        assert_eq!(registry.lock().unwrap().entries["b"].lease, Some(new));
        let mut replacement = scope.clone();
        replacement.target.generation += 1;
        registry
            .lock()
            .unwrap()
            .entries
            .insert("b".into(), entry(replacement, old));
        drop(lease());
        assert_eq!(registry.lock().unwrap().entries["b"].lease, Some(old));
        registry.lock().unwrap().entries.clear();
        drop(lease());
        assert!(registry.lock().unwrap().entries.is_empty());
        registry
            .lock()
            .unwrap()
            .entries
            .insert("b".into(), entry(scope.clone(), old));
        drop(lease());
        assert!(registry.lock().unwrap().entries["b"].lease.is_none());
    }

    #[test]
    fn responses_keep_tagged_camel_case_and_reject_oversized_payloads() {
        let response = NginxRepairResponse::Execution {
            execution_handle: "e".into(),
            receipt: Some(ReceiptDto {
                plan_handle: "p".into(),
                state: "verified".into(),
                detail: "已核实".into(),
                record_handle: None,
            }),
        };
        assert_eq!(
            serde_json::to_value(&response).unwrap(),
            json!({"kind": "execution", "executionHandle": "e", "receipt": {
            "planHandle": "p", "state": "verified", "detail": "已核实", "recordHandle": null }})
        );
        let huge = NginxRepairResponse::Inventory {
            instances: vec![InstanceDto {
                instance_handle: "i".into(),
                title: "x".repeat(MAX_RESPONSE_BYTES),
                version: "1".into(),
                main_pid: 1,
            }],
        };
        assert!(matches!(bounded(&huge), Err(NginxRepairError::Capacity)));
    }
}
