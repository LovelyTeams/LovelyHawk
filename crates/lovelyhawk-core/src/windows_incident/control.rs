//! Bounded service/driver/task intents. The page selects a collected object id,
//! then confirms an immutable plan; it never supplies a service name to execute.
use super::{BASE64, WindowsIncidentService, WindowsInventoryKind, WindowsInventorySnapshot};
use crate::{CoreError, CoreResult, store::StoreFile};
use base64::Engine as _;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

const BUDGET: usize = 4 * 1024 * 1024;
fn invalid(message: &str) -> CoreError {
    CoreError::validation("windows control", message)
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControlOperation {
    Start,
    Stop,
    Restart,
    Automatic,
    Manual,
    Enable,
    Disable,
    Run,
    Delete,
}
impl ControlOperation {
    pub fn label(self) -> &'static str {
        match self {
            Self::Start => "启动",
            Self::Stop => "停止",
            Self::Restart => "重启",
            Self::Automatic => "设为自动启动",
            Self::Manual => "设为手动启动",
            Self::Enable => "启用",
            Self::Disable => "禁用",
            Self::Run => "立即运行",
            Self::Delete => "删除注册项",
        }
    }
    fn setting(self, kind: WindowsInventoryKind) -> Option<&'static str> {
        match (self, kind) {
            (Self::Automatic, _) => Some("2"),
            (Self::Manual, _) => Some("3"),
            (Self::Enable, WindowsInventoryKind::Tasks) => Some("1"),
            (Self::Disable, WindowsInventoryKind::Tasks) => Some("0"),
            (Self::Disable, _) => Some("4"),
            _ => None,
        }
    }
    fn allowed(self, kind: WindowsInventoryKind) -> bool {
        match kind {
            WindowsInventoryKind::Tasks => {
                matches!(
                    self,
                    Self::Run | Self::Stop | Self::Enable | Self::Disable | Self::Delete
                )
            }
            _ => matches!(
                self,
                Self::Start
                    | Self::Stop
                    | Self::Restart
                    | Self::Automatic
                    | Self::Manual
                    | Self::Disable
                    | Self::Delete
            ),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Subject {
    kind: WindowsInventoryKind,
    name: String,
    location: String,
}
#[derive(Debug, Clone)]
struct Collected {
    subject: Subject,
    session: String,
    command: String,
    state: String,
    created: Instant,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ControlPlan {
    pub id: String,
    pub target: String,
    pub kind: WindowsInventoryKind,
    pub name: String,
    pub operation: ControlOperation,
    pub command: String,
    pub current_state: String,
    pub before_setting: String,
    pub after_setting: String,
    pub impact: Vec<String>,
    pub restoring: bool,
    pub expires_at: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControlResultState {
    Verified,
    Submitted,
    Refused,
    Uncertain,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ControlReport {
    pub id: String,
    pub target: String,
    pub kind: WindowsInventoryKind,
    pub name: String,
    pub operation: ControlOperation,
    pub state: ControlResultState,
    pub message: String,
    pub can_restore: bool,
    pub created_at: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InventoryDetailField {
    pub label: String,
    pub value: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InventoryDetails {
    pub object_id: String,
    pub target: String,
    pub kind: WindowsInventoryKind,
    pub name: String,
    pub observed_at: String,
    pub fields: Vec<InventoryDetailField>,
    pub warnings: Vec<String>,
}
impl InventoryDetails {
    fn valid(&self) -> bool {
        Uuid::parse_str(&self.object_id).is_ok()
            && !self.target.is_empty()
            && self.target.len() <= 255
            && !self.name.is_empty()
            && self.name.len() <= 1024
            && self.observed_at.len() <= 64
            && chrono::DateTime::parse_from_rfc3339(&self.observed_at).is_ok()
            && self.fields.len() <= 96
            && !self.fields.is_empty()
            && self
                .fields
                .iter()
                .all(|v| !v.label.is_empty() && v.label.len() <= 128 && v.value.len() <= 8192)
            && self.warnings.len() <= 16
            && self.warnings.iter().all(|v| v.len() <= 1024)
    }
}
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeletionObservation {
    machine: String,
    kind: WindowsInventoryKind,
    name: String,
    state: DeletionState,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum DeletionState {
    Absent,
    Pending,
    Present,
}
fn deletion_matches(plan: &Plan, after: &DeletionObservation) -> bool {
    plan.view.operation == ControlOperation::Delete
        && after.machine == plan.machine
        && after.kind == plan.subject.kind
        && after.name == plan.view.name
}
fn deletion_verified(plan: &Plan, after: &DeletionObservation, result: ControlResultState) -> bool {
    deletion_matches(plan, after)
        && after.state == DeletionState::Absent
        && result == ControlResultState::Verified
}
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Observation {
    config_hash: String,
    setting: String,
    state: String,
    command: String,
    critical: u32,
    #[serde(rename = "canStop")]
    _can_stop: bool,
    #[serde(rename = "pid")]
    _pid: u32,
    dependents: Vec<String>,
    dependencies: Vec<String>,
    instances: Vec<String>,
    fingerprint: String,
}
impl Observation {
    fn valid(&self) -> bool {
        let hash = |s: &str| s.len() == 64 && s.bytes().all(|v| v.is_ascii_hexdigit());
        hash(&self.config_hash)
            && hash(&self.fingerprint)
            && ["0", "1", "2", "3", "4"].contains(&self.setting.as_str())
            && self.state.len() <= 64
            && self.command.len() <= 8192
            && self.critical <= 3
            && self.dependents.len() <= 64
            && self.dependencies.len() <= 64
            && self.instances.len() <= 64
            && self
                .dependents
                .iter()
                .chain(&self.dependencies)
                .all(|s| s.len() <= 1024)
            && self.instances.iter().all(|s| s.len() <= 64)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inspection {
    target: String,
    machine: String,
    observation: Observation,
}
#[derive(Debug, Clone)]
struct Plan {
    view: ControlPlan,
    subject: Subject,
    session: String,
    machine: String,
    before: Observation,
    created: Instant,
    source_record: Option<String>,
}
#[derive(Debug, Default)]
pub(super) struct ControlChanges {
    objects: Mutex<HashMap<String, Collected>>,
    pending: Mutex<Option<Plan>>,
    execution: Mutex<()>,
}
impl ControlChanges {
    fn consume(&self, id: &str, session: &str) -> CoreResult<Plan> {
        let mut pending = self.pending.lock();
        let p = pending
            .as_ref()
            .ok_or_else(|| invalid("计划已失效，请重新预览。"))?;
        if p.view.id != id
            || p.session != session
            || p.created.elapsed() >= Duration::from_secs(120)
        {
            return Err(invalid("计划已过期或连接已变化。"));
        }
        Ok(pending.take().expect("checked plan"))
    }
}
fn readback_matches(plan: &Plan, after: &Observation, result: ControlResultState) -> bool {
    let op = plan.view.operation;
    let kind = plan.subject.kind;
    if op == ControlOperation::Delete
        || !after.valid()
        || after.config_hash != plan.before.config_hash
        || after.setting != op.setting(kind).unwrap_or(&plan.before.setting)
    {
        return false;
    }
    if result == ControlResultState::Submitted {
        return kind == WindowsInventoryKind::Tasks && op == ControlOperation::Run;
    }
    if kind == WindowsInventoryKind::Tasks {
        return op != ControlOperation::Run
            && (op != ControlOperation::Stop
                || after
                    .instances
                    .iter()
                    .all(|id| !plan.before.instances.contains(id)));
    }
    match op {
        ControlOperation::Start | ControlOperation::Restart => after.state == "Running",
        ControlOperation::Stop => after.state == "Stopped",
        _ => true,
    }
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Record {
    report: ControlReport,
    subject: Subject,
    machine: String,
    before_setting: String,
    after_setting: String,
    config_hash: String,
    source_record: Option<String>,
}
fn setting_label(kind: WindowsInventoryKind, s: &str) -> String {
    if kind == WindowsInventoryKind::Tasks {
        return if s == "1" { "启用" } else { "禁用" }.into();
    };
    match s {
        "0" => "引导",
        "1" => "系统",
        "2" => "自动",
        "3" => "手动",
        "4" => "禁用",
        _ => "未取得",
    }
    .into()
}
fn state_label(state: &str) -> String {
    match state {
        "Running" => "运行中",
        "Stopped" => "已停止",
        "Ready" => "就绪",
        "Disabled" => "已禁用",
        "Queued" => "已排队",
        "Unknown" => "未知",
        other => other,
    }
    .into()
}
fn subject_valid(s: &Subject) -> bool {
    let name = &s.name;
    if name.is_empty()
        || name.len() > 1024
        || name
            .chars()
            .any(|c| c.is_control() || matches!(c, '\\' | '/'))
        || matches!(name.as_str(), "." | "..")
    {
        return false;
    }
    if s.kind == WindowsInventoryKind::Tasks {
        let p = &s.location;
        p.starts_with('\\')
            && p.ends_with('\\')
            && p.len() <= 2048
            && !p.chars().any(char::is_control)
            && !p.split('\\').any(|c| matches!(c, "." | ".."))
    } else {
        true
    }
}
fn control_display_name(s: &Subject) -> String {
    if s.kind == WindowsInventoryKind::Tasks {
        format!("{}{}", s.location, s.name)
    } else {
        s.name.clone()
    }
}
impl WindowsIncidentService {
    pub(super) fn bind_inventory(&self, snapshot: &mut WindowsInventorySnapshot, session: &str) {
        let mut cache = self.control_changes.objects.lock();
        cache.retain(|_, o| {
            o.session == session
                && o.subject.kind != snapshot.kind
                && o.created.elapsed() < Duration::from_secs(600)
        });
        for entry in &mut snapshot.entries {
            entry.object_id = None;
            let subject = Subject {
                kind: snapshot.kind,
                name: entry.name.clone(),
                location: entry.location.clone(),
            };
            if !subject_valid(&subject)
                || entry.command.contains("[截断]")
                || entry.name.contains("[截断]")
            {
                continue;
            }
            let id = Uuid::new_v4().to_string();
            cache.insert(
                id.clone(),
                Collected {
                    subject,
                    session: session.into(),
                    command: entry.command.clone(),
                    state: entry.state.clone(),
                    created: Instant::now(),
                },
            );
            entry.object_id = Some(id);
        }
    }
    fn control_script(&self, request: serde_json::Value, session: &str) -> CoreResult<String> {
        let script = if request["mode"] == "details" {
            include_str!("inventory_detail.ps1")
        } else {
            include_str!("control.ps1")
        };
        let data =
            BASE64.encode(serde_json::to_vec(&request).map_err(|_| invalid("无法准备操作请求。"))?);
        self.run_bounded_script(&format!("$request=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{data}'))|ConvertFrom-Json\n{script}"),session)
    }
    fn collected_control(&self, object_id: &str, session: &str) -> CoreResult<Collected> {
        self.require_control_session(session)?;
        self.control_changes
            .objects
            .lock()
            .get(object_id)
            .cloned()
            .filter(|s| s.session == session && s.created.elapsed() < Duration::from_secs(600))
            .ok_or_else(|| invalid("对象已过期，请刷新清单后重试。"))
    }
    pub fn inspect_inventory(
        &self,
        object_id: &str,
        session: &str,
    ) -> CoreResult<InventoryDetails> {
        let selected = self.collected_control(object_id, session)?;
        let raw = self.control_script(
            serde_json::json!({"mode":"details","objectId":object_id,"subject":selected.subject}),
            session,
        )?;
        let details: InventoryDetails = serde_json::from_str(raw.trim()).map_err(|_| {
            invalid("无法读取对象详情；对象可能已移除或当前权限不足，请刷新清单后重试。")
        })?;
        if !details.valid()
            || details.object_id != object_id
            || details.kind != selected.subject.kind
            || details.name != control_display_name(&selected.subject)
        {
            return Err(invalid("详情响应不完整或对象不一致，请刷新清单。"));
        }
        self.require_control_session(session)?;
        Ok(details)
    }
    fn require_control_session(&self, session: &str) -> CoreResult<()> {
        let status = self.status();
        if !status.channel_connected || status.session_id.as_deref() != Some(session) {
            return Err(invalid("连接已变化，请重新采集并预览。"));
        }
        Ok(())
    }
    fn inspect_control(
        &self,
        subject: &Subject,
        op: ControlOperation,
        session: &str,
    ) -> CoreResult<Inspection> {
        if !subject_valid(subject) || !op.allowed(subject.kind) {
            return Err(invalid("对象或操作无效。"));
        }
        let raw = self.control_script(
            serde_json::json!({"mode":"inspect","subject":subject,"operation":op}),
            session,
        )?;
        let inspected:Inspection=serde_json::from_str(raw.trim()).map_err(|_|invalid(if op == ControlOperation::Delete { "无法生成删除计划：请先禁用并停止对象、刷新清单后再试。服务及驱动还须没有依赖它的对象；核心、引导及系统保护对象不能在此处删除。" } else { "无法生成操作计划：请核对读取 / 操作权限、依赖及系统保护条件。核心、引导和采集连接服务不能在此处直接变更。" }))?;
        if inspected.target.is_empty()
            || inspected.target.len() > 255
            || inspected.machine.len() != 64
            || !inspected.machine.bytes().all(|b| b.is_ascii_hexdigit())
            || !inspected.observation.valid()
        {
            return Err(invalid("对象检查结果不完整，未生成计划。"));
        }
        self.require_control_session(session)?;
        Ok(inspected)
    }
    fn save_control_plan(
        &self,
        subject: Subject,
        op: ControlOperation,
        inspected: Inspection,
        session: &str,
        source: Option<String>,
    ) -> CoreResult<ControlPlan> {
        let display_name = control_display_name(&subject);
        if display_name.len() > 1024 {
            return Err(invalid("对象完整名称超过展示上限，未生成操作计划。"));
        }
        if op.setting(subject.kind) == Some(inspected.observation.setting.as_str()) {
            return Err(invalid("当前已经是所选配置，无需重复修改。"));
        }
        let mut impact = vec![
            format!(
                "对当前对象「{}」执行所选操作，不主动停止依赖项，不自动提权。",
                subject.name
            ),
            "确认期间配置、运行状态、权限或依赖变化会拒绝旧计划；系统不提供跨工具的原子配置事务。"
                .into(),
        ];
        if matches!(op, ControlOperation::Start | ControlOperation::Restart)
            && !inspected.observation.dependencies.is_empty()
        {
            impact.push("启动由 Windows 处理依赖关系；仅当已核对的依赖均在运行时允许继续。核对与启动不是原子事务，期间依赖退出仍可能被 Windows 拉起。".into());
            let mut line = String::from("已核对依赖：");
            for dependency in &inspected.observation.dependencies {
                if line.len() + dependency.len() > 1800 {
                    impact.push(line);
                    line = String::from("已核对依赖（续）：");
                }
                line.push_str(dependency);
                line.push('；');
            }
            impact.push(line);
        }
        let after = op
            .setting(subject.kind)
            .map(|s| setting_label(subject.kind, s))
            .unwrap_or_else(|| {
                match op {
                    ControlOperation::Start | ControlOperation::Restart => "运行中（仅服务状态）",
                    ControlOperation::Stop => "停止本次确认的对象 / 任务实例",
                    ControlOperation::Run => "提交一次运行请求",
                    ControlOperation::Delete => "删除注册定义（执行文件保留）",
                    _ => "未取得",
                }
                .into()
            });
        if op.setting(subject.kind).is_some() {
            impact.push("保存原启动 / 启用配置，回读通过后可从操作记录发起恢复；恢复前仍需预览确认并核对是否出现后续修改。".into());
            impact.push(
                "修改启动 / 启用配置不会停止当前正在运行的对象；如需遏制，另行确认停止操作。"
                    .into(),
            );
            if subject.kind != WindowsInventoryKind::Tasks {
                impact.push("只修改启动方式，保留原有的延迟启动、触发器与失败恢复设置。".into());
            }
        } else if op == ControlOperation::Delete {
            impact.push("仅删除此对象的注册定义，不删除程序、驱动文件或安装包；不停止其他对象，也不自动重启系统。".into());
            impact.push("此删除不能一键恢复：操作记录只保存身份与配置摘要，不是完整备份。请先自行留存可用的任务定义或安装包及所需凭据；恢复需重新注册或重新安装。".into());
            impact.push("仅允许已禁用且无运行实例的对象；服务 / 驱动还必须已停止，且没有任何依赖它的服务。确认后会再次核对配置与依赖。".into());
            if subject.kind != WindowsInventoryKind::Tasks {
                impact.push("Windows 可能先标记删除并等待其他程序释放引用；只有重新查询明确不存在才报告已移除。删除驱动注册项不等于卸载驱动包或恢复设备。".into());
            }
        } else {
            impact.push("运行状态变更不可回滚：停止 / 重启可能丢失数据，运行任务可能产生其配置的业务效果；失败后不会自动重新启动。".into());
        }
        if subject.kind == WindowsInventoryKind::Drivers {
            impact.push("驱动操作可能影响设备、网络或导致系统不稳定；引导 / 系统及严重错误控制的驱动会被拒绝。".into());
        }
        if subject.kind == WindowsInventoryKind::Tasks && op == ControlOperation::Stop {
            impact.push(format!(
                "本次只停止已核实的 {} 个运行实例；新建或当前权限无法读取的实例需要另行复查。",
                inspected.observation.instances.len()
            ));
        }
        if impact.len() > 12 {
            return Err(invalid(
                "依赖范围过大，无法在本次计划中完整展示，请使用系统管理工具逐项核对。",
            ));
        }
        let view = ControlPlan {
            id: Uuid::new_v4().to_string(),
            target: inspected.target,
            kind: subject.kind,
            name: display_name,
            operation: op,
            command: inspected.observation.command.clone(),
            current_state: state_label(&inspected.observation.state),
            before_setting: if op.setting(subject.kind).is_some() {
                setting_label(subject.kind, &inspected.observation.setting)
            } else {
                state_label(&inspected.observation.state)
            },
            after_setting: after,
            impact,
            restoring: source.is_some(),
            expires_at: now() + 120,
        };
        *self.control_changes.pending.lock() = Some(Plan {
            view: view.clone(),
            subject,
            session: session.into(),
            machine: inspected.machine,
            before: inspected.observation,
            created: Instant::now(),
            source_record: source,
        });
        Ok(view)
    }
    pub fn plan_control(
        &self,
        object_id: &str,
        operation: ControlOperation,
        session: &str,
    ) -> CoreResult<ControlPlan> {
        let _guard = self
            .control_changes
            .execution
            .try_lock()
            .ok_or_else(|| invalid("另一个操作正在进行。"))?;
        self.require_control_session(session)?;
        *self.control_changes.pending.lock() = None;
        let selected = self.collected_control(object_id, session)?;
        let inspected = self.inspect_control(&selected.subject, operation, session)?;
        if inspected.observation.state != selected.state {
            return Err(invalid("对象运行状态已变化，请刷新后预览。"));
        }
        // Task/service command text must still describe the selected row. Truncated rows have no action id.
        if inspected.observation.command.trim() != selected.command.trim() {
            return Err(invalid(
                "对象执行配置与列表不一致，请刷新并核对路径与参数。",
            ));
        }
        self.save_control_plan(selected.subject, operation, inspected, session, None)
    }
    pub fn discard_control_plan(&self, id: &str, session: &str) {
        let mut pending = self.control_changes.pending.lock();
        if pending
            .as_ref()
            .is_some_and(|p| p.view.id == id && p.session == session)
        {
            *pending = None;
        }
    }
    fn control_records(&self) -> CoreResult<Vec<Record>> {
        self.baseline_store
            .as_ref()
            .ok_or_else(|| invalid("本机记录不可用，不能执行修改。"))?
            .read_or_default_bounded(StoreFile::WindowsControl, BUDGET)
    }
    pub fn control_history(&self) -> CoreResult<Vec<ControlReport>> {
        let records = self.control_records()?;
        let restored: Vec<_> = records
            .iter()
            .filter(|r| r.report.state == ControlResultState::Verified)
            .filter_map(|r| r.source_record.as_deref())
            .collect();
        Ok(records
            .iter()
            .rev()
            .map(|r| {
                let mut report = r.report.clone();
                if restored.contains(&report.id.as_str()) {
                    report.can_restore = false;
                }
                report
            })
            .collect())
    }
    pub fn plan_control_restore(&self, record_id: &str, session: &str) -> CoreResult<ControlPlan> {
        let _guard = self
            .control_changes
            .execution
            .try_lock()
            .ok_or_else(|| invalid("另一个操作正在进行。"))?;
        self.require_control_session(session)?;
        *self.control_changes.pending.lock() = None;
        let records = self.control_records()?;
        let record = records
            .iter()
            .find(|r| r.report.id == record_id && r.report.can_restore)
            .ok_or_else(|| invalid("此记录没有可恢复的配置。"))?;
        if records.iter().any(|r| {
            r.source_record.as_deref() == Some(record_id)
                && r.report.state == ControlResultState::Verified
        }) {
            return Err(invalid("此记录已经恢复。"));
        }
        let op = match (record.subject.kind, record.before_setting.as_str()) {
            (WindowsInventoryKind::Tasks, "1") => ControlOperation::Enable,
            (WindowsInventoryKind::Tasks, "0") => ControlOperation::Disable,
            (_, "2") => ControlOperation::Automatic,
            (_, "3") => ControlOperation::Manual,
            (_, "4") => ControlOperation::Disable,
            _ => return Err(invalid("旧配置不支持安全恢复。")),
        };
        let inspected = self.inspect_control(&record.subject, op, session)?;
        if inspected.machine != record.machine
            || inspected.target != record.report.target
            || inspected.observation.config_hash != record.config_hash
            || inspected.observation.setting != record.after_setting
        {
            return Err(invalid(
                "主机或配置已经出现后续变化，拒绝覆盖；请重新调查。",
            ));
        }
        self.save_control_plan(
            record.subject.clone(),
            op,
            inspected,
            session,
            Some(record_id.into()),
        )
    }
    pub fn apply_control(&self, id: &str, session: &str) -> CoreResult<ControlReport> {
        let _guard = self
            .control_changes
            .execution
            .try_lock()
            .ok_or_else(|| invalid("另一个操作正在进行。"))?;
        self.require_control_session(session)?;
        let plan = self.control_changes.consume(id, session)?;
        let mut records = self.control_records()?;
        if records.len() >= 100 {
            return Err(invalid("操作记录已达 100 条上限，请先归档本机记录。"));
        }
        let mut report = ControlReport {
            id: id.into(),
            target: plan.view.target.clone(),
            kind: plan.subject.kind,
            name: plan.view.name.clone(),
            operation: plan.view.operation,
            state: ControlResultState::Uncertain,
            message: "执行结果未知，请重新采集核对；旧计划不能重试。".into(),
            can_restore: false,
            created_at: now(),
        };
        records.push(Record {
            report: report.clone(),
            subject: plan.subject.clone(),
            machine: plan.machine.clone(),
            before_setting: plan.before.setting.clone(),
            after_setting: plan
                .view
                .operation
                .setting(plan.subject.kind)
                .unwrap_or(&plan.before.setting)
                .into(),
            config_hash: plan.before.config_hash.clone(),
            source_record: plan.source_record.clone(),
        });
        let store = self
            .baseline_store
            .as_ref()
            .ok_or_else(|| invalid("本机记录不可用。"))?;
        store.write_bounded(StoreFile::WindowsControl, &records, BUDGET)?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Receipt {
            state: ControlResultState,
            message: String,
            after: Option<Observation>,
            #[serde(default)]
            deletion: Option<DeletionObservation>,
        }
        if let Ok(raw)=self.control_script(serde_json::json!({"mode":"apply","subject":plan.subject,"operation":plan.view.operation,"machine":plan.machine,"fingerprint":plan.before.fingerprint}),session)
            && let Ok(receipt)=serde_json::from_str::<Receipt>(raw.trim())
            && receipt.message.len()<=2048 {
            let deleted=receipt.after.is_none() && receipt.deletion.as_ref().is_some_and(|o|deletion_verified(&plan,o,receipt.state));
            let pending_delete=receipt.deletion.as_ref().is_some_and(|o|deletion_matches(&plan,o) && o.state==DeletionState::Pending) && receipt.state==ControlResultState::Uncertain;
            let consistent=deleted || receipt.after.as_ref().is_some_and(|o|readback_matches(&plan,o,receipt.state));
            if matches!(receipt.state,ControlResultState::Refused|ControlResultState::Uncertain)||consistent{
                report.state=receipt.state;
                report.message=match report.state{ControlResultState::Verified=>"已独立回读并核实本次操作；请刷新清单，结合日志复查业务结果。",ControlResultState::Submitted=>"调度器已接受本次运行请求；任务可能已迅速退出，请查看任务日志与实际业务结果。",ControlResultState::Refused=>"执行前检查未通过，未执行。对象、配置、权限或依赖可能变化，请刷新后重新预览。",ControlResultState::Uncertain=>"操作已经开始，但未能完整核实结果。请刷新并核对日志，不要重复旧计划；不会自动重新启动已停止的对象。"}.into();
                report.can_restore=consistent&&report.state==ControlResultState::Verified&&plan.source_record.is_none()&&plan.view.operation.setting(plan.subject.kind).is_some();
                if deleted { report.message="已重新查询并确认注册项不存在；执行文件保留。此删除没有一键恢复备份，也不代表设备或业务已恢复。".into(); }
                else if pending_delete { report.message="Windows 已标记删除，仍在等待其他程序释放引用，尚未确认注册项消失。请稍后刷新复查，不要重复删除；不会自动重启系统。".into(); }
            }
        }
        records.last_mut().expect("record").report = report.clone();
        if store
            .write_bounded(StoreFile::WindowsControl, &records, BUDGET)
            .is_err()
        {
            report
                .message
                .push_str(" 本机结果保存失败；执行前记录仍保留，请核对现场。");
            report.can_restore = false;
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn test_plan() -> Plan {
        let observation: Observation = serde_json::from_value(serde_json::json!({"configHash":"a".repeat(64),"setting":"3","state":"Running","command":"fixture.exe","critical":1,"canStop":true,"pid":10,"dependents":[],"dependencies":[],"instances":[],"fingerprint":"b".repeat(64)})).unwrap();
        Plan {
            view: ControlPlan {
                id: Uuid::new_v4().to_string(),
                target: "lab".into(),
                kind: WindowsInventoryKind::Services,
                name: "owned".into(),
                operation: ControlOperation::Stop,
                command: "fixture.exe".into(),
                current_state: "Running".into(),
                before_setting: "手动".into(),
                after_setting: "停止".into(),
                impact: vec![],
                restoring: false,
                expires_at: now() + 120,
            },
            subject: Subject {
                kind: WindowsInventoryKind::Services,
                name: "owned".into(),
                location: String::new(),
            },
            session: "owned-session".into(),
            machine: "a".repeat(64),
            before: observation,
            created: Instant::now(),
            source_record: None,
        }
    }
    #[test]
    fn confirmation_is_single_use_and_cannot_change_session_or_plan() {
        let state = ControlChanges::default();
        let plan = test_plan();
        let id = plan.view.id.clone();
        *state.pending.lock() = Some(plan.clone());
        assert!(state.consume(&id, "another").is_err());
        assert!(state.consume("another", "owned-session").is_err());
        assert!(state.consume(&id, "owned-session").is_ok());
        assert!(state.consume(&id, "owned-session").is_err());
        *state.pending.lock() = Some(Plan {
            created: Instant::now() - Duration::from_secs(121),
            ..plan
        });
        assert!(state.consume(&id, "owned-session").is_err());
    }
    #[test]
    fn successful_exit_or_task_submission_does_not_replace_readback() {
        let mut plan = test_plan();
        let mut after = plan.before.clone();
        assert!(!readback_matches(
            &plan,
            &after,
            ControlResultState::Verified
        ));
        after.state = "Stopped".into();
        assert!(readback_matches(
            &plan,
            &after,
            ControlResultState::Verified
        ));
        after.config_hash = "c".repeat(64);
        assert!(!readback_matches(
            &plan,
            &after,
            ControlResultState::Verified
        ));
        after.config_hash = plan.before.config_hash.clone();
        assert!(!readback_matches(
            &plan,
            &after,
            ControlResultState::Submitted
        ));
        plan.subject.kind = WindowsInventoryKind::Tasks;
        plan.view.operation = ControlOperation::Run;
        assert!(readback_matches(
            &plan,
            &after,
            ControlResultState::Submitted
        ));
        assert!(!readback_matches(
            &plan,
            &after,
            ControlResultState::Verified
        ));
        plan.view.operation = ControlOperation::Stop;
        plan.before.instances = vec!["approved".into()];
        after.instances = vec!["approved".into()];
        assert!(!readback_matches(
            &plan,
            &after,
            ControlResultState::Verified
        ));
        after.instances = vec!["new-instance".into()];
        assert!(readback_matches(
            &plan,
            &after,
            ControlResultState::Verified
        ));
    }
    #[test]
    fn actions_are_closed_by_object_kind() {
        assert!(!ControlOperation::Run.allowed(WindowsInventoryKind::Drivers));
        assert!(!ControlOperation::Restart.allowed(WindowsInventoryKind::Tasks));
        assert!(ControlOperation::Disable.allowed(WindowsInventoryKind::Services));
        for kind in [
            WindowsInventoryKind::Tasks,
            WindowsInventoryKind::Services,
            WindowsInventoryKind::Drivers,
        ] {
            assert!(ControlOperation::Delete.allowed(kind));
        }
    }
    #[test]
    fn deletion_requires_exact_absence_and_never_reuses_a_state_readback() {
        let mut plan = test_plan();
        plan.view.operation = ControlOperation::Delete;
        assert!(!readback_matches(
            &plan,
            &plan.before,
            ControlResultState::Verified
        ));
        let mut proof = DeletionObservation {
            machine: plan.machine.clone(),
            kind: plan.subject.kind,
            name: plan.view.name.clone(),
            state: DeletionState::Absent,
        };
        assert!(deletion_verified(
            &plan,
            &proof,
            ControlResultState::Verified
        ));
        for state in [DeletionState::Pending, DeletionState::Present] {
            proof.state = state;
            assert!(!deletion_verified(
                &plan,
                &proof,
                ControlResultState::Verified
            ));
        }
        proof.state = DeletionState::Absent;
        assert!(!deletion_verified(
            &plan,
            &proof,
            ControlResultState::Submitted
        ));
        proof.name.push_str("-another");
        assert!(!deletion_verified(
            &plan,
            &proof,
            ControlResultState::Verified
        ));
        proof.name = plan.view.name.clone();
        proof.machine = "another".into();
        assert!(!deletion_verified(
            &plan,
            &proof,
            ControlResultState::Verified
        ));
        proof.machine = plan.machine.clone();
        proof.kind = WindowsInventoryKind::Tasks;
        assert!(!deletion_verified(
            &plan,
            &proof,
            ControlResultState::Verified
        ));
    }
    #[test]
    fn details_are_bounded_and_reject_private_or_executable_extra_fields() {
        let value = serde_json::json!({"objectId":Uuid::new_v4().to_string(),"target":"lab","kind":"tasks","name":"\\owned\\task","observedAt":"2026-10-27T00:00:00Z","fields":[{"label":"触发器","value":"按需"}],"warnings":["时间为观察值"]});
        let mut detail: InventoryDetails = serde_json::from_value(value.clone()).unwrap();
        assert!(detail.valid());
        detail.fields[0].value = "x".repeat(8193);
        assert!(!detail.valid());
        let mut extra = value;
        extra["xml"] = "private task definition".into();
        assert!(serde_json::from_value::<InventoryDetails>(extra).is_err());
    }
    #[test]
    fn names_and_task_folders_cannot_escape_their_namespace() {
        let mut s = Subject {
            kind: WindowsInventoryKind::Tasks,
            name: "owned task".into(),
            location: "\\owned\\".into(),
        };
        assert!(subject_valid(&s));
        assert_eq!(control_display_name(&s), "\\owned\\owned task");
        s.location = "\\..\\".into();
        assert!(!subject_valid(&s));
        s.kind = WindowsInventoryKind::Services;
        s.name = "evil\\Parameters".into();
        assert!(!subject_valid(&s));
    }
    #[test]
    fn scripts_fit_the_bounded_transport() {
        assert!(
            super::super::script_transport::compressed_command(include_str!(
                "inventory_detail.ps1"
            ))
            .unwrap()
            .len()
                < 30000
        );
        assert!(
            super::super::script_transport::compressed_command(include_str!("control.ps1"))
                .unwrap()
                .len()
                < 30000
        );
        assert!(
            super::super::script_transport::compressed_command(include_str!("startup_catalog.ps1"))
                .unwrap()
                .len()
                < 30000
        );
    }
}
