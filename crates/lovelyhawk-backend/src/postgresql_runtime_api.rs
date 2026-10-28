//! Native, read-only PostgreSQL review. Credentials and revision digests stay in core.
use crate::ssh_api::SshApi;
use lovelyhawk_core::{
    BackendServices, CoreError,
    crypto::SecretValue,
    database::{
        DatabaseEngine, DatabaseProfileChanges, DatabaseProfileConfig, DatabaseProfileDeletePlan,
        DatabaseProfileSnapshot, DatabaseRuntimeParametersSnapshot, DatabaseSecretChange,
    },
    database_config_runtime::{
        DatabaseConfigRuntimeApply, DatabaseConfigRuntimeRow, DatabaseConfigRuntimeSensitivity,
        DatabaseConfigRuntimeValuePresence, PostgreSqlRuntimeContext,
    },
    investigation::{AddEvidence, CaseCollectionReservation},
    operations::DangerousConfirmation,
    postgresql_access::AccessSection,
    postgresql_native::{PostgresqlTlsMode, PostgresqlTlsSettings},
    postgresql_objects::{ObjectFilter, ObjectSection},
    postgresql_observation::{PostgresqlReviewOutcome, REVIEW_NAMES, case_summary},
    postgresql_role_graph::RoleAccessMode,
    ssh::BoundSshSession,
    target::TargetGuard,
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use uuid::Uuid;

const TTL: Duration = Duration::from_secs(600);
const PLAN_TTL: Duration = Duration::from_secs(120);
const MAX_BINDINGS: usize = 4;

#[derive(Deserialize)]
#[serde(
    tag = "action",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum PostgresqlRuntimeRequest {
    List {
        binding_handle: String,
    },
    Edit {
        binding_handle: String,
        profile_handle: String,
    },
    Save {
        binding_handle: String,
        #[serde(deserialize_with = "required_option")]
        profile_handle: Option<String>,
        profile: ProfileInput,
        password: PasswordChange,
    },
    PlanDelete {
        binding_handle: String,
        profile_handle: String,
    },
    Delete {
        binding_handle: String,
        plan_handle: String,
    },
    Begin {
        binding_handle: String,
        profile_handle: String,
        retain_evidence: bool,
    },
    Poll {
        binding_handle: String,
        job_handle: String,
    },
    Cancel {
        binding_handle: String,
        job_handle: String,
    },
    Retain {
        binding_handle: String,
        job_handle: String,
    },
    DiscardEvidence {
        binding_handle: String,
        job_handle: String,
    },
    ObjectRows {
        binding_handle: String,
        job_handle: String,
        section: ObjectSection,
        query: String,
        filter: ObjectFilter,
        offset: usize,
    },
    ObjectDetail {
        binding_handle: String,
        job_handle: String,
        section: ObjectSection,
        oid: u32,
        sub_id: u16,
        #[serde(deserialize_with = "required_option")]
        role_oid: Option<u32>,
    },
    RoleAccess {
        binding_handle: String,
        job_handle: String,
        role_oid: u32,
        mode: RoleAccessMode,
        query: String,
        offset: usize,
    },
    AccessRows {
        binding_handle: String,
        job_handle: String,
        section: AccessSection,
        query: String,
        offset: usize,
    },
    Rows {
        binding_handle: String,
        job_handle: String,
        query: String,
        offset: usize,
    },
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProfileInput {
    name: String,
    host: String,
    port: u16,
    username: String,
    database: String,
    tls_mode: PostgresqlTlsMode,
    #[serde(deserialize_with = "required_option")]
    ca_pem: Option<String>,
}
#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum PasswordChange {
    Keep,
    Remove,
    Replace {
        #[serde(deserialize_with = "read_password")]
        value: SecretValue,
    },
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProfileDto {
    profile_handle: String,
    name: String,
    host: String,
    port: u16,
    username: String,
    database: String,
    tls_mode: PostgresqlTlsMode,
    has_password: bool,
    has_ca: bool,
    unassigned: bool,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct JobDto {
    job_handle: String,
    profile: ProfileDto,
    target_label: String,
    state: &'static str,
    started_at: String,
    finished_at: Option<String>,
    detail: String,
    result: Option<Value>,
    retention: Option<RetentionDto>,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct RetentionDto {
    state: &'static str,
    case_id: Option<String>,
    case_title: Option<String>,
    evidence_id: Option<String>,
    sha256: Option<String>,
    can_retry: bool,
    detail: &'static str,
    record_text: Option<String>,
}
#[derive(Clone, PartialEq, Eq)]
struct Scope {
    binding: String,
    session: String,
    connection: String,
    target: TargetGuard,
}
struct Job {
    dto: JobDto,
    profile: DatabaseProfileSnapshot,
    snapshot: Option<DatabaseRuntimeParametersSnapshot>,
    abort: Option<tokio::task::AbortHandle>,
    created: Instant,
    source_label: String,
    material: Option<AddEvidence>,
    reservation: Option<CaseCollectionReservation>,
}
impl Job {
    fn unsaved(&self) -> bool {
        self.dto
            .retention
            .as_ref()
            .is_some_and(|r| r.state == "unsaved")
    }
    fn expire(&mut self) {
        if self.dto.state != "reading" && self.created.elapsed() >= TTL {
            self.snapshot = None;
            self.dto.result = None;
            self.dto.state = "expired";
            self.dto.detail =
                "生效参数结果已过期。未保存的检查摘要仍保留，请重试留证或明确放弃。".into();
        }
    }
}
impl Drop for Job {
    fn drop(&mut self) {
        if let Some(abort) = &self.abort {
            abort.abort();
        }
    }
}
struct DeletePlan {
    handle: String,
    profile: ProfileDto,
    core: DatabaseProfileDeletePlan,
    created: Instant,
}
struct Entry {
    scope: Scope,
    touched: Instant,
    profiles: HashMap<String, DatabaseProfileSnapshot>,
    job: Option<Job>,
    delete: Option<DeletePlan>,
    deleting: bool,
}
#[derive(Clone)]
pub(crate) struct PostgresqlRuntimeApi {
    services: BackendServices,
    ssh: Arc<SshApi>,
    entries: Arc<Mutex<HashMap<String, Entry>>>,
}
impl std::fmt::Debug for PostgresqlRuntimeApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresqlRuntimeApi")
            .finish_non_exhaustive()
    }
}
#[derive(Debug)]
pub(crate) enum PostgresqlRuntimeError {
    Invalid,
    Stale,
    Busy,
    Capacity,
    Store,
}
type Result<T> = std::result::Result<T, PostgresqlRuntimeError>;
fn text(value: &str, cap: usize, empty: bool) -> bool {
    value.len() <= cap
        && (empty || !value.trim().is_empty())
        && !value.chars().any(char::is_control)
}
fn handle(value: &str) -> Result<()> {
    if text(value, 128, false) {
        Ok(())
    } else {
        Err(PostgresqlRuntimeError::Invalid)
    }
}
fn new_handle() -> String {
    Uuid::new_v4().to_string()
}
fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}
fn profile_dto(handle: &str, snapshot: &DatabaseProfileSnapshot) -> ProfileDto {
    let view = snapshot.view();
    let config = &view.config;
    let tls = config.postgresql_tls.clone().unwrap_or_default();
    let username = config
        .connection
        .username
        .clone()
        .unwrap_or_else(|| "postgres".into());
    ProfileDto {
        profile_handle: handle.into(),
        name: config.name.clone(),
        host: config.connection.host.clone(),
        port: config.connection.port,
        database: config
            .connection
            .database
            .clone()
            .unwrap_or_else(|| username.clone()),
        username,
        tls_mode: tls.mode,
        has_ca: tls.ca_certificate_pem.is_some(),
        has_password: view.has_password,
        unassigned: config.ssh_connection_id.is_none(),
    }
}

impl PostgresqlRuntimeApi {
    pub(crate) fn new(services: BackendServices, ssh: Arc<SshApi>) -> Self {
        Self {
            services,
            ssh,
            entries: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    pub(crate) fn close_binding(&self, binding: &str) {
        self.entries.lock().remove(binding);
    }
    fn capture(&self, binding: &str) -> Result<(Scope, BoundSshSession)> {
        handle(binding)?;
        let session = self
            .ssh
            .binding_session_clone(binding)
            .map_err(|_| PostgresqlRuntimeError::Stale)?;
        self.services
            .target()
            .validate(session.target())
            .map_err(|_| PostgresqlRuntimeError::Stale)?;
        Ok((
            Scope {
                binding: binding.into(),
                session: session.session_id().into(),
                connection: session.connection_id().into(),
                target: session.target().clone(),
            },
            session,
        ))
    }
    fn validate(&self, scope: &Scope) -> Result<()> {
        if self.capture(&scope.binding)?.0 == *scope {
            Ok(())
        } else {
            Err(PostgresqlRuntimeError::Stale)
        }
    }
    fn with_entry<T>(
        &self,
        scope: &Scope,
        work: impl FnOnce(&mut Entry) -> Result<T>,
    ) -> Result<T> {
        self.validate(scope)?;
        let mut entries = self.entries.lock();
        entries.retain(|_, entry| {
            entry.deleting
                || entry.job.as_ref().is_some_and(Job::unsaved)
                || entry.touched.elapsed() < TTL
        });
        let entry = entries
            .get_mut(&scope.binding)
            .filter(|entry| entry.scope == *scope)
            .ok_or(PostgresqlRuntimeError::Stale)?;
        entry.touched = Instant::now();
        if entry
            .job
            .as_ref()
            .is_some_and(|job| job.created.elapsed() >= TTL)
        {
            if entry.job.as_ref().is_some_and(Job::unsaved) {
                entry.job.as_mut().expect("checked job").expire();
            } else {
                entry.job = None;
            }
        }
        if entry
            .delete
            .as_ref()
            .is_some_and(|plan| plan.created.elapsed() >= PLAN_TTL)
        {
            entry.delete = None;
        }
        work(entry)
    }
    fn profile(&self, entry: &Entry, id: &str) -> Result<DatabaseProfileSnapshot> {
        handle(id)?;
        let snapshot = entry
            .profiles
            .get(id)
            .ok_or(PostgresqlRuntimeError::Stale)?;
        self.services
            .database()
            .validate_profile_snapshot(snapshot)
            .map_err(|_| PostgresqlRuntimeError::Stale)?;
        Ok(snapshot.clone())
    }
    fn idle(entry: &Entry) -> Result<()> {
        if entry.deleting
            || entry
                .job
                .as_ref()
                .is_some_and(|job| job.dto.state == "reading" || job.unsaved())
        {
            Err(PostgresqlRuntimeError::Busy)
        } else {
            Ok(())
        }
    }
    pub(crate) async fn dispatch(&self, request: PostgresqlRuntimeRequest) -> Value {
        use PostgresqlRuntimeRequest::*;
        let action = match &request {
            List { .. } => "list",
            Edit { .. } => "edit",
            Save { .. } => "save",
            PlanDelete { .. } => "plan-delete",
            Delete { .. } => "delete",
            Begin { .. } => "begin",
            Poll { .. } => "poll",
            Cancel { .. } => "cancel",
            Retain { .. } => "retain",
            DiscardEvidence { .. } => "discard-evidence",
            Rows { .. } => "rows",
            ObjectRows { .. } => "object-rows",
            ObjectDetail { .. } => "object-detail",
            RoleAccess { .. } => "role-access",
            AccessRows { .. } => "access-rows",
        };
        match self.dispatch_inner(request).await {
            Ok(response) => response,
            Err(error) => {
                let (code, detail) = match error {
                    PostgresqlRuntimeError::Invalid => (
                        "invalid-params",
                        "数据库请求无效。请检查地址、端口、证书和账号；旧连接需先保存并关联当前主机。",
                    ),
                    PostgresqlRuntimeError::Stale => {
                        ("stale", "连接、配置或检查结果已变化或过期，请刷新后重试。")
                    }
                    PostgresqlRuntimeError::Busy => (
                        "busy",
                        "请先等待或取消当前数据库操作，并处理尚未保存的检查摘要。",
                    ),
                    PostgresqlRuntimeError::Capacity => (
                        "capacity",
                        "数据库连接或检查结果已达到数量限制，请关闭其他检查后重试。",
                    ),
                    PostgresqlRuntimeError::Store => (
                        "store",
                        "无法保存或读取数据库连接。请刷新确认最新配置，并检查本机数据目录的权限与空间。",
                    ),
                };
                json!({"kind":"rejected", "action":action, "code":code, "detail":detail})
            }
        }
    }
    async fn dispatch_inner(&self, request: PostgresqlRuntimeRequest) -> Result<Value> {
        use PostgresqlRuntimeRequest::*;
        let binding = match &request {
            List { binding_handle }
            | Edit { binding_handle, .. }
            | Save { binding_handle, .. }
            | PlanDelete { binding_handle, .. }
            | Delete { binding_handle, .. }
            | Begin { binding_handle, .. }
            | Poll { binding_handle, .. }
            | Cancel { binding_handle, .. }
            | Retain { binding_handle, .. }
            | DiscardEvidence { binding_handle, .. }
            | Rows { binding_handle, .. }
            | ObjectRows { binding_handle, .. }
            | ObjectDetail { binding_handle, .. }
            | RoleAccess { binding_handle, .. }
            | AccessRows { binding_handle, .. } => binding_handle,
        };
        let (scope, session) = self.capture(binding)?;
        let response = match request {
            List { .. } => {
                let snapshots = self.services.database().profile_snapshots().map_err(|_| PostgresqlRuntimeError::Store)?;
                self.validate(&scope)?;
                let mut entries = self.entries.lock();
                entries.retain(|_, entry| entry.deleting || entry.job.as_ref().is_some_and(Job::unsaved) || entry.touched.elapsed() < TTL);
                if entries.get(&scope.binding).is_some_and(|entry| entry.scope != scope) { entries.remove(&scope.binding); }
                if !entries.contains_key(&scope.binding) && entries.len() >= MAX_BINDINGS { return Err(PostgresqlRuntimeError::Capacity); }
                let entry = entries.entry(scope.binding.clone()).or_insert_with(|| Entry { scope: scope.clone(), touched: Instant::now(), profiles: HashMap::new(), job: None, delete: None, deleting: false });
                Self::idle(entry)?;
                let mut refreshed = HashMap::new();
                let mut profiles = Vec::new();
                for snapshot in snapshots.into_iter().filter(|s| s.view().config.connection.engine == DatabaseEngine::Postgresql && s.view().config.ssh_connection_id.as_ref().is_none_or(|owner| owner == &scope.connection)) {
                    let id = entry.profiles.iter().find(|(_, old)| old.same_revision(&snapshot)).map(|(id, _)| id.clone()).unwrap_or_else(new_handle);
                    profiles.push(profile_dto(&id, &snapshot));
                    refreshed.insert(id, snapshot);
                }
                entry.profiles = refreshed;
                entry.touched = Instant::now();
                json!({"kind":"profiles", "profiles":profiles})
            }
            Edit { profile_handle, .. } => self.with_entry(&scope, |entry| {
                Self::idle(entry)?;
                let snapshot = self.profile(entry, &profile_handle)?;
                let ca = snapshot.view().config.postgresql_tls.as_ref().and_then(|tls| tls.ca_certificate_pem.as_ref());
                Ok(json!({"kind":"editor", "profile":profile_dto(&profile_handle, &snapshot), "caPem":ca}))
            })?,
            Save { profile_handle, profile, password, .. } => self.with_entry(&scope, |entry| {
                Self::idle(entry)?;
                if !text(&profile.name, 256, false) || !text(&profile.host, 253, false) ||
                    !profile.host.bytes().all(|c| c.is_ascii_alphanumeric() || b"._:[]-".contains(&c)) ||
                    !text(&profile.username, 128, false) || !text(&profile.database, 128, false) || profile.port == 0 {
                    return Err(PostgresqlRuntimeError::Invalid);
                }
                let expected = profile_handle.as_deref().map(|id| self.profile(entry, id)).transpose()?;
                let mut config = expected.as_ref().map(|s| s.view().config.clone()).unwrap_or_else(|| DatabaseProfileConfig::new(&profile.name, DatabaseEngine::Postgresql));
                config.name = profile.name; config.connection.host = profile.host; config.connection.port = profile.port;
                config.connection.username = Some(profile.username); config.connection.database = Some(profile.database);
                config.postgresql_tls = Some(PostgresqlTlsSettings { mode: profile.tls_mode, ca_certificate_pem: profile.ca_pem });
                config.ssh_connection_id = Some(scope.connection.clone());
                config.validate().map_err(|_| PostgresqlRuntimeError::Invalid)?;
                let password = match password {
                    PasswordChange::Keep => DatabaseSecretChange::Keep,
                    PasswordChange::Remove => DatabaseSecretChange::Remove,
                    PasswordChange::Replace { value } => {
                        DatabaseSecretChange::Replace(value)
                    }
                };
                let saved = self.services.database().save_profile_if_unchanged(config, DatabaseProfileChanges { password }, expected.as_ref()).map_err(|_| PostgresqlRuntimeError::Store)?;
                if let Some(old) = profile_handle { entry.profiles.remove(&old); }
                // A completed review belongs to its original credential/configuration revision.
                entry.job = None; entry.delete = None;
                let id = new_handle();
                let dto = profile_dto(&id, &saved);
                entry.profiles.insert(id, saved);
                Ok(json!({"kind":"saved", "profile":dto}))
            })?,
            PlanDelete { profile_handle, .. } => self.with_entry(&scope, |entry| {
                Self::idle(entry)?;
                let snapshot = self.profile(entry, &profile_handle)?;
                let core = self.services.database().plan_delete_profile_snapshot(&snapshot).map_err(|_| PostgresqlRuntimeError::Stale)?;
                let profile = profile_dto(&profile_handle, &snapshot);
                let id = new_handle();
                let response = json!({"kind":"delete-plan","planHandle":id,"profile":profile,"expiresInMs":120000});
                entry.delete = Some(DeletePlan { handle: id, profile, core, created: Instant::now() });
                Ok(response)
            })?,
            Delete { plan_handle, .. } => {
                handle(&plan_handle)?;
                let plan = self.with_entry(&scope, |entry| {
                    Self::idle(entry)?;
                    if entry.delete.as_ref().is_none_or(|plan| plan.handle != plan_handle) { return Err(PostgresqlRuntimeError::Stale); }
                    entry.deleting = true;
                    Ok(entry.delete.take().expect("checked plan"))
                })?;
                let _lease = DeleteLease { entries: self.entries.clone(), scope: scope.clone() };
                let confirmation = DangerousConfirmation::approve(plan.core.definition());
                let result = self.services.database().execute_delete_profile(plan.core, confirmation, self.services.operation_journal()).await;
                let verified = result.is_ok_and(|outcome| outcome.verification.passed);
                self.with_entry(&scope, |entry| {
                    entry.deleting = false; entry.job = None;
                    entry.profiles.remove(&plan.profile.profile_handle);
                    Ok(())
                })?;
                json!({"kind":"deleted","planHandle":plan_handle,"profileHandle":plan.profile.profile_handle,"verified":verified,
                    "detail":if verified { "已删除本机保存的数据库连接并核实结果。" } else { "删除状态尚未确认，请刷新连接列表；不要重复使用原确认。" }})
            }
            Begin { profile_handle, retain_evidence, .. } => {
                let source_label = if retain_evidence {
                    let status = self.services.ssh().list_sessions().await.map_err(|_| PostgresqlRuntimeError::Stale)?
                        .into_iter().find(|s| s.session_id == scope.session && s.connection_id == scope.connection).ok_or(PostgresqlRuntimeError::Stale)?;
                    let host = if status.host.contains(':') { format!("[{}]", status.host) } else { status.host };
                    let label = format!("{}@{host}:{}", status.username, status.port);
                    if !text(&label, 1024, false) { return Err(PostgresqlRuntimeError::Invalid); }
                    label
                } else { String::new() };
                self.with_entry(&scope, |entry| {
                Self::idle(entry)?;
                let snapshot = self.profile(entry, &profile_handle)?;
                if snapshot.view().config.ssh_connection_id.as_ref() != Some(&scope.connection) { return Err(PostgresqlRuntimeError::Invalid); }
                let target_label = self.ssh.binding_target_label(&scope.binding).map_err(|_| PostgresqlRuntimeError::Stale)?;
                if !text(&target_label, 1024, false) { return Err(PostgresqlRuntimeError::Invalid); }
                let id = new_handle();
                let dto = JobDto { job_handle: id.clone(), profile: profile_dto(&profile_handle, &snapshot), target_label,
                    state: "reading", started_at: now(), finished_at: None, detail: "正在通过当前 SSH 连接读取 PostgreSQL 参数、访问规则与角色属性，最长约 40 秒。".into(), result: None,
                    retention: retain_evidence.then_some(RetentionDto { state: "pending", case_id: None, case_title: None, evidence_id: None, sha256: None, can_retry: false, record_text: None, detail: "读取结束后保存检查摘要；只读查询可能产生数据库连接与审计日志。" }) };
                let expected = snapshot.clone();
                let mut job = Job { dto, profile: snapshot, snapshot: None, abort: None, created: Instant::now(), source_label, material: None, reservation: None };
                if retain_evidence { self.reserve_case(&scope, &mut job); }
                let dto = job.dto.clone();
                entry.job = Some(job);
                entry.delete = None;
                let api = self.clone(); let captured = scope.clone();
                let task = tokio::spawn(async move {
                    let result = api.services.database().read_postgresql_runtime_snapshot(&session, &expected).await;
                    let _ = api.with_entry(&captured, |entry| {
                        let job = entry.job.as_mut().filter(|job| job.dto.job_handle == id && job.dto.state == "reading").ok_or(PostgresqlRuntimeError::Stale)?;
                        if api.services.database().validate_profile_snapshot(&job.profile).is_err() { api.finish_job(&captured, job, "failed", "连接配置已变化，请重新读取。".into()); return Ok(()); }
                        match result {
                            Ok(snapshot) => {
                                if api.services.database().validate_runtime_parameters_snapshot(&snapshot).is_err() {
                                    api.finish_job(&captured, job, "failed", "连接或配置已变化，未采用迟到的读取结果。".into()); return Ok(());
                                }
                                job.dto.result = Some(runtime_summary(&snapshot)); job.snapshot = Some(snapshot);
                                api.finish_job(&captured, job, "completed", "已读取此会话的生效参数。观察值需要结合权限、业务要求和配置来源判断。".into());
                            }
                            Err(error) => api.finish_job(&captured, job, "failed", public_error(&error)),
                        }
                        Ok(())
                    });
                });
                entry.job.as_mut().expect("inserted job").abort = Some(task.abort_handle());
                Ok(json!({"kind":"job","job":dto}))
            })? },
            Poll { job_handle, .. } => self.job_response(&scope, &job_handle, false)?,
            Cancel { job_handle, .. } => self.job_response(&scope, &job_handle, true)?,
            Retain { job_handle, .. } => self.with_entry(&scope, |entry| {
                let job = self.valid_job(entry, &job_handle)?;
                if job.dto.state == "reading" { return Err(PostgresqlRuntimeError::Busy); }
                if job.dto.retention.as_ref().is_some_and(|r| r.state == "unsaved" && r.can_retry) {
                    self.reserve_case(&scope, job);
                    if job.reservation.is_some() { self.save_evidence(&scope, job); }
                    job.reservation = None;
                }
                Ok(json!({"kind":"job","job":job.dto}))
            })?,
            DiscardEvidence { job_handle, .. } => self.with_entry(&scope, |entry| {
                let job = self.valid_job(entry, &job_handle)?;
                if job.dto.state == "reading" { return Err(PostgresqlRuntimeError::Busy); }
                if !job.unsaved() { return Err(PostgresqlRuntimeError::Stale); }
                job.dto.retention = None; job.material = None; job.reservation = None;
                Ok(json!({"kind":"job","job":job.dto}))
            })?,
            ObjectRows { job_handle, section, query, filter, offset, .. } => self.with_entry(&scope, |entry| {
                if !text(&query,128,true) || offset>2048 {return Err(PostgresqlRuntimeError::Invalid);}
                let job=self.valid_job(entry,&job_handle)?;
                let snapshot=job.snapshot.as_ref().ok_or(PostgresqlRuntimeError::Stale)?;
                self.services.database().validate_runtime_parameters_snapshot(snapshot).map_err(|_|PostgresqlRuntimeError::Stale)?;
                let mut page=snapshot.postgresql_access().ok_or(PostgresqlRuntimeError::Stale)?.object_page(section,&query,filter,offset).map_err(|_|PostgresqlRuntimeError::Stale)?;
                page["kind"]=json!("object-rows");page["jobHandle"]=json!(job_handle);Ok(page)
            })?,
            ObjectDetail { job_handle, section, oid, sub_id, role_oid, .. } => self.with_entry(&scope, |entry| {
                if oid==0 || sub_id>32767 || (section==ObjectSection::Columns)!=(sub_id>0) || role_oid==Some(0) || section==ObjectSection::Defaults && role_oid.is_some() {return Err(PostgresqlRuntimeError::Invalid);}
                let job=self.valid_job(entry,&job_handle)?;
                let snapshot=job.snapshot.as_ref().ok_or(PostgresqlRuntimeError::Stale)?;
                self.services.database().validate_runtime_parameters_snapshot(snapshot).map_err(|_|PostgresqlRuntimeError::Stale)?;
                let mut detail=snapshot.postgresql_access().ok_or(PostgresqlRuntimeError::Stale)?.object_detail(section,oid,sub_id,role_oid).map_err(|_|PostgresqlRuntimeError::Stale)?;
                detail["kind"]=json!("object-detail");detail["jobHandle"]=json!(job_handle);Ok(detail)
            })?,
            RoleAccess { job_handle, role_oid, mode, query, offset, .. } => self.with_entry(&scope, |entry| {
                if role_oid == 0 || !text(&query, 128, true) || offset > 1024 { return Err(PostgresqlRuntimeError::Invalid); }
                let job = self.valid_job(entry, &job_handle)?;
                let snapshot = job.snapshot.as_ref().ok_or(PostgresqlRuntimeError::Stale)?;
                self.services.database().validate_runtime_parameters_snapshot(snapshot).map_err(|_| PostgresqlRuntimeError::Stale)?;
                let access = snapshot.postgresql_access().ok_or(PostgresqlRuntimeError::Stale)?;
                let mut page = access.role_page(role_oid, mode, &query, offset).map_err(|_| PostgresqlRuntimeError::Stale)?;
                page["kind"] = json!("role-access"); page["jobHandle"] = json!(job_handle);
                Ok(page)
            })?,
            AccessRows { job_handle, section, query, offset, .. } => self.with_entry(&scope, |entry| {
                if !text(&query, 128, true) || offset > if section == AccessSection::Memberships { 2048 } else { 1024 } { return Err(PostgresqlRuntimeError::Invalid); }
                let job = self.valid_job(entry, &job_handle)?;
                let snapshot = job.snapshot.as_ref().ok_or(PostgresqlRuntimeError::Stale)?;
                self.services.database().validate_runtime_parameters_snapshot(snapshot).map_err(|_| PostgresqlRuntimeError::Stale)?;
                let access = snapshot.postgresql_access().ok_or(PostgresqlRuntimeError::Stale)?;
                let mut page = access.page(section, &query, offset).map_err(|_| PostgresqlRuntimeError::Stale)?;
                page["kind"] = json!("access-rows"); page["jobHandle"] = json!(job_handle);
                Ok(page)
            })?,
            Rows { job_handle, query, offset, .. } => self.with_entry(&scope, |entry| {
                if !text(&query, 128, true) || offset > 16384 { return Err(PostgresqlRuntimeError::Invalid); }
                let job = self.valid_job(entry, &job_handle)?;
                let snapshot = job.snapshot.as_ref().ok_or(PostgresqlRuntimeError::Stale)?;
                self.services.database().validate_runtime_parameters_snapshot(snapshot).map_err(|_| PostgresqlRuntimeError::Stale)?;
                let folded = query.to_lowercase();
                let rows = snapshot.document().rows();
                let matching: Vec<_> = rows.iter().filter(|row| row.name().to_lowercase().contains(&folded)).collect();
                let page: Vec<_> = matching.iter().skip(offset).take(50).map(|row| runtime_row(row)).collect();
                Ok(json!({"kind":"rows","jobHandle":job_handle,"query":query,"offset":offset,"matched":matching.len(),"total":rows.len(),"rows":page}))
            })?,
        };
        self.validate(&scope)?;
        if serde_json::to_vec(&response)
            .map_err(|_| PostgresqlRuntimeError::Store)?
            .len()
            > 512 * 1024
        {
            return Err(PostgresqlRuntimeError::Capacity);
        }
        Ok(response)
    }
    fn valid_job<'a>(&self, entry: &'a mut Entry, id: &str) -> Result<&'a mut Job> {
        handle(id)?;
        let job = entry
            .job
            .as_mut()
            .filter(|job| job.dto.job_handle == id)
            .ok_or(PostgresqlRuntimeError::Stale)?;
        // The evidence is historical and may still be retained after a profile
        // changes. Only runtime rows require the current profile revision.
        if job.dto.state == "completed"
            && self
                .services
                .database()
                .validate_profile_snapshot(&job.profile)
                .is_err()
        {
            job.snapshot = None;
            job.dto.result = None;
            job.dto.state = "expired";
            job.dto.detail = "连接配置已变化。原检查摘要仍可留证，生效参数需重新读取。".into();
        }
        Ok(job)
    }
    fn job_response(&self, scope: &Scope, id: &str, cancel: bool) -> Result<Value> {
        self.with_entry(scope, |entry| {
            let job = self.valid_job(entry, id)?;
            if cancel && job.dto.state == "reading" {
                if let Some(abort) = job.abort.take() {
                    abort.abort();
                }
                self.finish_job(
                    scope,
                    job,
                    "cancelled",
                    "已停止接收结果并关闭读取连接。数据库中的语句可能仍需等待超时，最长约 20 秒。"
                        .into(),
                );
            }
            Ok(json!({"kind":"job","job":job.dto}))
        })
    }
    fn reserve_case(&self, scope: &Scope, job: &mut Job) {
        let Some(retention) = job.dto.retention.as_mut() else {
            return;
        };
        let cases = self.services.investigation().cases();
        if retention.case_id.is_none() {
            match cases.ensure_active(&scope.target.identity, None) {
                Ok(case) => {
                    retention.case_id = Some(case.id);
                    retention.case_title = Some(case.title);
                }
                Err(_) => {
                    retention.detail = "尚未取得归属案件。检查仍会继续；重试留证时会使用那时的采集案件，并显示案件名称。";
                    return;
                }
            }
        }
        match cases.reserve_collection(
            &scope.target.identity,
            retention.case_id.as_deref().expect("captured case"),
        ) {
            Ok(reservation) => job.reservation = Some(reservation),
            Err(_) => {
                retention.detail =
                    "无法占用原归属案件。检查仍会继续；请核对案件是否开放及正在进行的采集。"
            }
        }
    }
    fn finish_job(&self, scope: &Scope, job: &mut Job, state: &'static str, detail: String) {
        finish(job, state, detail);
        let Some(retention) = job.dto.retention.as_mut() else {
            return;
        };
        let outcome = match state {
            "completed" => PostgresqlReviewOutcome::Completed,
            "cancelled" => PostgresqlReviewOutcome::Cancelled,
            _ => PostgresqlReviewOutcome::Failed,
        };
        job.material = case_summary(
            Uuid::parse_str(&job.dto.job_handle).expect("generated UUID"),
            &job.profile,
            &job.source_label,
            chrono::DateTime::parse_from_rfc3339(&job.dto.started_at)
                .expect("generated timestamp")
                .with_timezone(&chrono::Utc),
            chrono::DateTime::parse_from_rfc3339(
                job.dto.finished_at.as_deref().expect("finished timestamp"),
            )
            .expect("generated timestamp")
            .with_timezone(&chrono::Utc),
            outcome,
            job.snapshot.as_ref(),
        )
        .ok();
        retention.state = "unsaved";
        retention.can_retry = job.material.is_some();
        retention.record_text = job.material.as_ref().map(|m| m.preview.clone());
        if job.material.is_none() {
            retention.detail =
                "本次摘要无法在案件记录限额内完整保存。请保留页面信息，再明确放弃本次未保存摘要。";
        } else if job.reservation.is_some() {
            self.save_evidence(scope, job);
        }
        job.reservation = None;
    }
    fn save_evidence(&self, scope: &Scope, job: &mut Job) {
        let (Some(retention), Some(material)) = (&mut job.dto.retention, &job.material) else {
            return;
        };
        let Some(case_id) = &retention.case_id else {
            return;
        };
        match self.services.investigation().cases().add_evidence_to_case(
            &scope.target.identity,
            case_id,
            material.clone(),
        ) {
            Ok(evidence) => {
                retention.state = "saved";
                retention.evidence_id = Some(evidence.id);
                retention.sha256 = Some(evidence.sha256);
                retention.can_retry = false;
                retention.detail = "检查摘要已进入原归属案件及时间线，可从案件工作台查看和导出。摘要校验保存记录，不代表完整参数或业务恢复。";
            }
            Err(_) => {
                retention.state = "unsaved";
                retention.can_retry = true;
                retention.detail = "摘要尚未保存。请检查本机空间、案件是否开放及记录容量，再重试留证；重试只补存本次摘要，不重新读取数据库。";
            }
        }
    }
}
fn finish(job: &mut Job, state: &'static str, detail: String) {
    job.dto.state = state;
    job.dto.finished_at = Some(now());
    job.dto.detail = detail;
}
fn public_error(error: &CoreError) -> String {
    match error {
        CoreError::Validation {
            subject:
                "PostgreSQL native transport"
                | "PostgreSQL native identity"
                | "PostgreSQL native parameters"
                | "PostgreSQL native observation",
            message,
        } => message.clone(),
        _ => "无法完成读取。请检查 SSH 转发权限、数据库地址、证书、账号权限和连接状态，然后重试。"
            .into(),
    }
}
fn limited(value: &str, cap: usize, truncated: &mut bool) -> String {
    let mut result = String::new();
    for c in value.chars() {
        let c = if c.is_control() { '\u{fffd}' } else { c };
        if result.len() + c.len_utf8() > cap {
            *truncated = true;
            break;
        }
        result.push(c);
    }
    result
}
fn runtime_row(row: &DatabaseConfigRuntimeRow) -> Value {
    let mut truncated = row.enum_values().len() > 32;
    let source = row.source().map(|s| limited(s, 256, &mut truncated));
    let minimum = row.minimum().map(|s| limited(s, 128, &mut truncated));
    let maximum = row.maximum().map(|s| limited(s, 128, &mut truncated));
    let enums: Vec<_> = row
        .enum_values()
        .iter()
        .take(32)
        .map(|s| limited(s, 256, &mut truncated))
        .collect();
    let context = match row.apply() {
        DatabaseConfigRuntimeApply::PostgreSql(value) => match value {
            PostgreSqlRuntimeContext::Internal => "internal",
            PostgreSqlRuntimeContext::Postmaster => "postmaster",
            PostgreSqlRuntimeContext::Sighup => "sighup",
            PostgreSqlRuntimeContext::SuperuserBackend => "superuser-backend",
            PostgreSqlRuntimeContext::Backend => "backend",
            PostgreSqlRuntimeContext::Superuser => "superuser",
            PostgreSqlRuntimeContext::User => "user",
        },
        _ => "internal",
    };
    json!({"name":row.name(),"value":row.value().public_value(),"sensitivity":match row.value().sensitivity() { DatabaseConfigRuntimeSensitivity::Public => "public", DatabaseConfigRuntimeSensitivity::MayContainSecrets => "redacted", DatabaseConfigRuntimeSensitivity::PrivateKeyReference => "private-key" },
        "presence":match row.value().presence() { DatabaseConfigRuntimeValuePresence::Null => "null", DatabaseConfigRuntimeValuePresence::Empty => "empty", DatabaseConfigRuntimeValuePresence::Present => "present" },
        "context":context,"source":source,"pendingRestart":row.pending_restart().unwrap_or(false),"minimum":minimum,"maximum":maximum,"enumValues":enums,"metadataTruncated":truncated})
}
fn runtime_summary(snapshot: &DatabaseRuntimeParametersSnapshot) -> Value {
    let observations: Vec<_> = snapshot
        .document()
        .rows()
        .iter()
        .filter(|row| REVIEW_NAMES.contains(&row.name()))
        .map(runtime_row)
        .collect();
    json!({"version":format!("{}.{}", snapshot.version().major(), snapshot.version().minor()), "tlsMode":snapshot.postgresql_tls_mode(),
        "parameterCount":snapshot.document().rows().len(),"noticeCount":snapshot.notice_count(),"observations":observations,"session":snapshot.postgresql_observation(),"hostProcess":snapshot.postgresql_host_process(),"access":snapshot.postgresql_access().map(|access| access.summary())})
}

fn read_password<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<SecretValue, D::Error> {
    let value = zeroize::Zeroizing::new(String::deserialize(deserializer)?);
    if value.is_empty() || value.len() > 16384 || value.contains('\0') {
        return Err(serde::de::Error::custom("invalid database credential"));
    }
    Ok(SecretValue::new(value.to_string()))
}

fn required_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error> {
    Option::<T>::deserialize(deserializer)
}

struct DeleteLease {
    entries: Arc<Mutex<HashMap<String, Entry>>>,
    scope: Scope,
}
impl Drop for DeleteLease {
    fn drop(&mut self) {
        if let Some(entry) = self
            .entries
            .lock()
            .get_mut(&self.scope.binding)
            .filter(|entry| entry.scope == self.scope)
        {
            entry.deleting = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn failed_case_write_keeps_original_material_case_and_reservation_then_retries_idempotently()
     {
        use lovelyhawk_core::{PortableStore, store::StoreFile, target::TargetIdentity};
        struct Root(std::path::PathBuf);
        impl Drop for Root {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let root = Root(
            std::env::temp_dir().join(format!("lovelyres-pg-evidence-test-{}", Uuid::new_v4())),
        );
        let store = PortableStore::prepare(root.0.clone()).unwrap();
        let cases_file = store.path_for(StoreFile::Cases);
        let services =
            BackendServices::with_runtime(store, tokio::runtime::Handle::current()).unwrap();
        let target = services
            .activate_target(TargetIdentity::new("owned-lab").unwrap())
            .unwrap();
        let api =
            PostgresqlRuntimeApi::new(services.clone(), Arc::new(SshApi::new(services.clone())));
        let mut config = DatabaseProfileConfig::new("test database", DatabaseEngine::Postgresql);
        config.connection.username = Some("audit".into());
        config.connection.database = Some("postgres".into());
        let profile = services
            .database()
            .save_profile_if_unchanged(
                config,
                DatabaseProfileChanges {
                    password: DatabaseSecretChange::Replace(SecretValue::new(
                        "evidence-password-canary",
                    )),
                },
                None,
            )
            .unwrap();
        let scope = Scope {
            binding: "b".into(),
            session: "s".into(),
            connection: "owned-lab".into(),
            target,
        };
        let mut job = Job {
            dto: JobDto {
                job_handle: new_handle(),
                profile: profile_dto("p", &profile),
                target_label: "label".into(),
                state: "reading",
                started_at: now(),
                finished_at: None,
                detail: "reading".into(),
                result: None,
                retention: Some(RetentionDto {
                    state: "pending",
                    case_id: None,
                    case_title: None,
                    evidence_id: None,
                    sha256: None,
                    can_retry: false,
                    record_text: None,
                    detail: "pending",
                }),
            },
            profile,
            snapshot: None,
            abort: None,
            created: Instant::now(),
            source_label: "audit@[::1]:22".into(),
            material: None,
            reservation: None,
        };
        api.reserve_case(&scope, &mut job);
        let original_id = job.dto.retention.as_ref().unwrap().case_id.clone().unwrap();
        assert!(job.reservation.is_some());
        assert!(
            services
                .investigation()
                .cases()
                .plan_close(&scope.target.identity, &original_id)
                .is_err()
        );
        let original_file = std::fs::read(&cases_file).unwrap();
        std::fs::write(&cases_file, b"invalid-owned-test-store").unwrap();
        api.finish_job(&scope, &mut job, "failed", "read failed".into());
        assert!(job.reservation.is_none());
        assert!(job.unsaved());
        let record = job.material.clone().unwrap();
        assert!(record.preview.contains("读取失败"));
        assert!(record.preview.contains("audit@[::1]:22"));
        assert!(!record.preview.contains("evidence-password-canary"));
        assert_eq!(
            std::fs::read(&cases_file).unwrap(),
            b"invalid-owned-test-store"
        );
        std::fs::write(&cases_file, original_file).unwrap();
        let other = services
            .investigation()
            .cases()
            .create(&scope.target.identity, Some("next investigation".into()))
            .unwrap();
        job.created = Instant::now() - TTL - Duration::from_secs(1);
        job.expire();
        assert_eq!(job.dto.state, "expired");
        assert_eq!(job.material.as_ref().unwrap(), &record);
        api.reserve_case(&scope, &mut job);
        api.save_evidence(&scope, &mut job);
        job.reservation = None;
        let saved = job.dto.retention.as_ref().unwrap().clone();
        assert_eq!(saved.state, "saved");
        assert_eq!(saved.case_id.as_deref(), Some(original_id.as_str()));
        api.reserve_case(&scope, &mut job);
        api.save_evidence(&scope, &mut job);
        job.reservation = None;
        assert_eq!(
            job.dto.retention.as_ref().unwrap().evidence_id,
            saved.evidence_id
        );
        let cases = services
            .investigation()
            .cases()
            .list_for_target(&scope.target.identity)
            .unwrap();
        let original = cases.iter().find(|c| c.id == original_id).unwrap();
        assert_eq!(original.evidence.len(), 1);
        assert_eq!(original.evidence[0].preview, record.preview);
        assert_eq!(
            cases
                .iter()
                .find(|c| c.id == other.id)
                .unwrap()
                .evidence
                .len(),
            0
        );
        assert_eq!(
            services
                .investigation()
                .cases()
                .active(&scope.target.identity)
                .unwrap()
                .unwrap()
                .id,
            other.id
        );
    }
    #[test]
    fn requests_reject_extra_sql_missing_nullable_fields_and_oversize_credentials() {
        let valid = json!({"action":"save","bindingHandle":"b","profileHandle":null,"profile":{"name":"a","host":"127.0.0.1","port":5432,"username":"audit","database":"postgres","tlsMode":"verify-full","caPem":null},"password":{"action":"replace","value":"test-secret"}});
        assert!(serde_json::from_value::<PostgresqlRuntimeRequest>(valid.clone()).is_ok());
        let object = json!({"action":"object-detail","bindingHandle":"b","jobHandle":"j","section":"relations","oid":18000,"subId":0,"roleOid":null});
        assert!(serde_json::from_value::<PostgresqlRuntimeRequest>(object.clone()).is_ok());
        for key in ["section", "oid", "subId", "roleOid"] {
            let mut partial = object.clone();
            partial.as_object_mut().unwrap().remove(key);
            assert!(serde_json::from_value::<PostgresqlRuntimeRequest>(partial).is_err());
        }
        for (key, value) in [
            ("oid", json!("18000")),
            ("section", json!("arbitrary")),
            ("sql", json!("untrusted")),
        ] {
            let mut invalid = object.clone();
            invalid[key] = value;
            assert!(serde_json::from_value::<PostgresqlRuntimeRequest>(invalid).is_err());
        }
        let mut candidates = Vec::new();
        let mut missing = valid.clone();
        missing.as_object_mut().unwrap().remove("profileHandle");
        candidates.push(missing);
        let mut missing = valid.clone();
        missing["profile"].as_object_mut().unwrap().remove("caPem");
        candidates.push(missing);
        let mut extra = valid.clone();
        extra["sql"] = json!("not authorized");
        candidates.push(extra);
        let mut extra = valid.clone();
        extra["profile"]["caFile"] = json!("/private");
        candidates.push(extra);
        for password in ["".to_owned(), "x".repeat(16385), "with\0nul".to_owned()] {
            let mut candidate = valid.clone();
            candidate["password"]["value"] = json!(password);
            candidates.push(candidate);
        }
        for candidate in candidates {
            let error = serde_json::from_value::<PostgresqlRuntimeRequest>(candidate)
                .err()
                .expect("must refuse");
            assert!(!error.to_string().contains("test-secret"));
        }
    }
    #[test]
    fn errors_and_metadata_never_echo_arbitrary_io_or_remote_error_text() {
        let error = CoreError::Validation {
            subject: "untrusted server",
            message: "password-canary".into(),
        };
        assert!(!public_error(&error).contains("password-canary"));
        let mut truncated = false;
        assert_eq!(limited("汉字abc", 7, &mut truncated), "汉字a");
        assert!(truncated);
        assert_eq!(limited("a\nb", 10, &mut false), "a�b");
    }
    #[test]
    fn local_profile_dto_contains_no_core_identity_or_secret_material() {
        // The DTO serializer has an exact finite surface independent of portable profiles.
        let dto = ProfileDto {
            profile_handle: "opaque".into(),
            name: "audit".into(),
            host: "127.0.0.1".into(),
            port: 5432,
            username: "audit".into(),
            database: "postgres".into(),
            tls_mode: PostgresqlTlsMode::VerifyFull,
            has_password: true,
            has_ca: false,
            unassigned: false,
        };
        let value = serde_json::to_value(dto).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 10);
        for key in [
            "password",
            "encryptedPassword",
            "digest",
            "id",
            "sshConnectionId",
            "caPem",
        ] {
            assert!(value.get(key).is_none());
        }
    }
}
