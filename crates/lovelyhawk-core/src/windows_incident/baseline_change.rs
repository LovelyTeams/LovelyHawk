//! Bounded registry policy changes. Plans and original values never come from the page.
use super::{
    BASE64, DEFAULT_COLLECTION_TIMEOUT, WindowsIncidentService, encode_powershell_command,
    strip_exit_prefix,
};
use crate::{
    CoreError, CoreResult,
    store::{PortableStore, StoreFile},
};
use base64::Engine as _;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

const BUDGET: usize = 4 * 1024 * 1024;
const TTL: u64 = 300;
const SCRIPT: &str = include_str!("baseline_change.ps1");
fn invalid(message: &str) -> CoreError {
    CoreError::validation("windows baseline plan", message)
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

#[derive(Clone, Copy, Serialize)]
struct Rule {
    id: &'static str,
    #[serde(skip_serializing)]
    title: &'static str,
    hive: &'static str,
    path: &'static str,
    name: &'static str,
    #[serde(skip_serializing)]
    value: u32,
    #[serde(skip_serializing)]
    impact: &'static str,
}
const LSA: &str = r"SYSTEM\CurrentControlSet\Control\Lsa";
const UAC: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
const RDP: &str = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";
const WINRM: &str = r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service";
const INSTALLER: &str = r"SOFTWARE\Policies\Microsoft\Windows\Installer";
macro_rules! rule {
    ($id:literal,$title:literal,$hive:literal,$path:expr,$name:literal,$value:literal,$impact:literal) => {
        Rule {
            id: $id,
            title: $title,
            hive: $hive,
            path: $path,
            name: $name,
            value: $value,
            impact: $impact,
        }
    };
}
const RULES: &[Rule] = &[
    rule!(
        "rdp-nla",
        "远程桌面网络级别身份验证",
        "HKLM",
        RDP,
        "UserAuthentication",
        1,
        "旧版客户端可能无法连接；执行前准备其他管理通道，连接生效需另行复核。"
    ),
    rule!(
        "rdp-encryption",
        "远程桌面高加密级别",
        "HKLM",
        RDP,
        "MinEncryptionLevel",
        3,
        "旧版客户端可能无法连接；不重启远程桌面服务。"
    ),
    rule!(
        "rdp-security-layer",
        "远程桌面 TLS 安全层",
        "HKLM",
        RDP,
        "SecurityLayer",
        2,
        "需可用的 TLS 证书与兼容客户端；不验证当前 RDP 连接协议。"
    ),
    rule!(
        "wdigest",
        "关闭 WDigest 明文缓存",
        "HKLM",
        r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
        "UseLogonCredential",
        0,
        "不会清除已经缓存的凭据；重启后再核查运行状态。"
    ),
    rule!(
        "uac",
        "启用 UAC",
        "HKLM",
        UAC,
        "EnableLUA",
        1,
        "需要重启后完全生效；旧应用兼容性需另行验证。"
    ),
    rule!(
        "uac-prompt",
        "管理员提升提示",
        "HKLM",
        UAC,
        "ConsentPromptBehaviorAdmin",
        2,
        "管理员操作将出现同意提示，可能影响无人值守流程。"
    ),
    rule!(
        "uac-secure-desktop",
        "使用安全桌面提示",
        "HKLM",
        UAC,
        "PromptOnSecureDesktop",
        1,
        "提升提示切换到安全桌面，可能影响远程辅助。"
    ),
    rule!(
        "uac-filter-admin",
        "内置管理员审批模式",
        "HKLM",
        UAC,
        "FilterAdministratorToken",
        1,
        "内置管理员的提升行为变化；需重新登录或重启复核。"
    ),
    rule!(
        "blank-password",
        "限制空口令远程登录",
        "HKLM",
        LSA,
        "LimitBlankPasswordUse",
        1,
        "空口令账户的远程登录受限；不会修改账户口令。"
    ),
    rule!(
        "anonymous",
        "限制匿名枚举共享",
        "HKLM",
        LSA,
        "RestrictAnonymous",
        1,
        "可能影响依赖匿名访问的旧服务；不等于关闭全部匿名访问。"
    ),
    rule!(
        "anonymous-sam",
        "限制匿名枚举账户",
        "HKLM",
        LSA,
        "RestrictAnonymousSAM",
        1,
        "可能影响旧式目录查询，需业务验证。"
    ),
    rule!(
        "ntlm",
        "仅使用 NTLMv2 并拒绝旧协议",
        "HKLM",
        LSA,
        "LmCompatibilityLevel",
        5,
        "旧客户端、NAS 和应用可能认证失败；需另行验证业务连接。"
    ),
    rule!(
        "lm-hash",
        "停止保存 LM 口令摘要",
        "HKLM",
        LSA,
        "NoLMHash",
        1,
        "只影响后续口令变更，不会转换或清除已有摘要。"
    ),
    rule!(
        "winrm-basic",
        "禁用 WinRM Basic 认证",
        "HKLM",
        WINRM,
        "AllowBasic",
        0,
        "依赖 Basic 的远程管理可能失败；不重启 WinRM。"
    ),
    rule!(
        "winrm-cleartext",
        "禁止 WinRM 未加密通信",
        "HKLM",
        WINRM,
        "AllowUnencryptedTraffic",
        0,
        "旧管理流程可能无法连接；生效连接需单独验证。"
    ),
    rule!(
        "installer-machine",
        "关闭本机高权限安装策略",
        "HKLM",
        INSTALLER,
        "AlwaysInstallElevated",
        0,
        "旧 MSI 分发流程可能需要显式管理员授权。"
    ),
    rule!(
        "installer-user",
        "关闭当前账户高权限安装策略",
        "HKCU",
        INSTALLER,
        "AlwaysInstallElevated",
        0,
        "仅作用于当前采集账户；不覆盖其他用户配置。"
    ),
    rule!(
        "autorun",
        "禁用自动播放自动运行",
        "HKLM",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "NoDriveTypeAutoRun",
        255,
        "影响插入媒体时的自动启动，需重新登录或策略刷新后核实。"
    ),
    rule!(
        "ps-scriptblock-logging",
        "开启 PowerShell 脚本块日志",
        "HKLM",
        r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
        "EnableScriptBlockLogging",
        1,
        "脚本内容可能包含秘密；需规划日志权限、容量及保留范围，新会话另行验证。"
    ),
];
fn rule(id: &str) -> CoreResult<Rule> {
    RULES
        .iter()
        .find(|rule| rule.id == id)
        .copied()
        .ok_or_else(|| invalid("此项尚未支持带备份的批量配置"))
}
pub fn baseline_change_supported(id: &str) -> bool {
    rule(id).is_ok()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Identity {
    machine: String,
    account: String,
    host_name: String,
    version: String,
    boot: String,
    elevated: bool,
    domain: bool,
    product_type: u32,
}
impl Identity {
    fn check(&self) -> CoreResult<()> {
        if self.machine.is_empty()
            || self.machine.len() > 128
            || !self.account.starts_with("S-1-")
            || self.account.len() > 184
            || self.host_name.is_empty()
            || self.host_name.len() > 255
            || self.version.len() > 64
            || self.boot.len() > 64
            || !self.version.starts_with("10.")
            || !self.elevated
            || self.domain
            || !matches!(self.product_type, 1 | 3)
        {
            return Err(invalid(
                "需要 Windows 10/11 或 Server 2016+ 的本机管理员；当前批量配置不适用于域成员或域控制器，也不会自动提权",
            ));
        }
        Ok(())
    }
    fn same_host(&self, other: &Self) -> bool {
        self.machine == other.machine
            && self.account == other.account
            && self.host_name == other.host_name
            && self.version == other.version
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Value {
    id: String,
    key_exists: bool,
    value: Option<u32>,
    security: String,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Readback {
    identity: Identity,
    values: Vec<Value>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BaselinePlanItem {
    pub id: String,
    pub title: String,
    pub location: String,
    pub current_value: String,
    pub expected_value: String,
    pub impact: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BaselineChangePlan {
    pub id: String,
    pub target: String,
    pub expires_at: u64,
    pub restoring: bool,
    pub items: Vec<BaselinePlanItem>,
    pub notes: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BaselineChangeState {
    Pending,
    Applying,
    Verified,
    Restored,
    Refused,
    Uncertain,
    Skipped,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BaselineChangeItem {
    pub id: String,
    pub title: String,
    pub state: BaselineChangeState,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BaselineChangeReport {
    pub id: String,
    pub target: String,
    pub created_at: u64,
    pub restoring: bool,
    pub finished: bool,
    pub recovery_available: bool,
    pub items: Vec<BaselineChangeItem>,
    pub message: String,
}
#[derive(Debug, Clone)]
struct Plan {
    view: BaselineChangePlan,
    session: String,
    identity: Identity,
    before: Vec<Value>,
    desired: Vec<Option<u32>>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    view: BaselineChangeReport,
    identity: Identity,
    before: Vec<Value>,
    after: Vec<Option<Value>>,
    desired: Vec<Option<u32>>,
}
#[derive(Debug, Default)]
pub(super) struct BaselineChanges {
    gate: Mutex<()>,
    plans: Mutex<Vec<Plan>>,
    running: Mutex<Option<(String, String, Arc<AtomicBool>)>>,
    progress: Mutex<Option<BaselineChangeReport>>,
}

trait Remote {
    fn read(&self, rules: &[Rule]) -> CoreResult<Readback>;
    fn write(
        &self,
        identity: &Identity,
        rule: Rule,
        before: &Value,
        desired: Option<u32>,
    ) -> CoreResult<bool>;
}
struct DvcRemote<'a> {
    svc: &'a WindowsIncidentService,
    session: &'a str,
}
impl DvcRemote<'_> {
    fn run(&self, payload: serde_json::Value) -> CoreResult<String> {
        let script = SCRIPT.replace(
            "__PAYLOAD__",
            &BASE64.encode(serde_json::to_vec(&payload).map_err(|_| invalid("配置参数编码失败"))?),
        );
        let command = encode_powershell_command(&script);
        if command.encode_utf16().count() > 30_000 {
            return Err(invalid("配置权限信息超出安全执行长度，拒绝写入"));
        }
        let raw = self
            .svc
            .hub
            .execute_command_for_session(&command, DEFAULT_COLLECTION_TIMEOUT, self.session)
            .map_err(|_| invalid("远程请求未完成；写入结果需要复核，不能重复执行旧计划"))?;
        let output = strip_exit_prefix(&raw)?;
        if output.len() > 256 * 1024 {
            return Err(invalid("配置查询返回超限"));
        }
        Ok(output)
    }
}
impl Remote for DvcRemote<'_> {
    fn read(&self, rules: &[Rule]) -> CoreResult<Readback> {
        let mut combined: Option<Readback> = None;
        for batch in rules.chunks(6) {
            let result: Readback =
                serde_json::from_str(&self.run(serde_json::json!({"mode":"read","rules":batch}))?)
                    .map_err(|_| {
                        invalid("无法完整读取注册表值、权限或目标身份；请核对管理员权限和配置类型")
                    })?;
            validate_readback(&result, batch)?;
            if let Some(previous) = &mut combined {
                if previous.identity != result.identity {
                    return Err(invalid("分批读取期间目标身份变化"));
                }
                previous.values.extend(result.values);
            } else {
                combined = Some(result);
            }
        }
        combined.ok_or_else(|| invalid("没有需要读取的配置项"))
    }
    fn write(
        &self,
        identity: &Identity,
        rule: Rule,
        before: &Value,
        desired: Option<u32>,
    ) -> CoreResult<bool> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Reply {
            outcome: String,
        }
        let reply: Reply = serde_json::from_str(&self.run(serde_json::json!({"mode":"write","identity":identity,"rule":rule,"before":before,"desired":desired}))?).map_err(|_| invalid("写入结果无法确认"))?;
        match reply.outcome.as_str() {
            "written" => Ok(true),
            "refused" => Ok(false),
            _ => Err(invalid("写入结果无法确认")),
        }
    }
}
fn validate_readback(readback: &Readback, rules: &[Rule]) -> CoreResult<()> {
    readback.identity.check()?;
    if readback.values.len() != rules.len()
        || readback.values.iter().zip(rules).any(|(v, r)| {
            v.id != r.id
                || v.security.len() > 2048
                || (v.key_exists && v.security.is_empty())
                || (!v.key_exists && (v.value.is_some() || !v.security.is_empty()))
        })
    {
        return Err(invalid("注册表读取范围或权限信息不完整"));
    }
    Ok(())
}
fn describe(value: Option<u32>) -> String {
    value.map_or_else(|| "未设置此值".into(), |v| format!("DWORD {v} (0x{v:08X})"))
}
fn make_plan(
    remote: &impl Remote,
    ids: &[String],
    session: &str,
    restore: Option<&Record>,
) -> CoreResult<Plan> {
    if ids.is_empty()
        || ids.len() > RULES.len()
        || ids.iter().collect::<HashSet<_>>().len() != ids.len()
    {
        return Err(invalid("请选择 1 至 19 个不同的支持项"));
    }
    let rules = ids
        .iter()
        .map(|id| rule(id))
        .collect::<CoreResult<Vec<_>>>()?;
    let readback = remote.read(&rules)?;
    validate_readback(&readback, &rules)?;
    if restore.is_some_and(|record| !record.identity.same_host(&readback.identity)) {
        return Err(invalid("当前主机、采集账户或系统版本与备份不一致"));
    }
    let mut before = Vec::new();
    let mut desired = Vec::new();
    let mut items = Vec::new();
    for (r, value) in rules.iter().zip(readback.values) {
        let target = if let Some(record) = restore {
            let index = record
                .before
                .iter()
                .position(|v| v.id == r.id)
                .ok_or_else(|| invalid("备份范围不完整"))?;
            if record.after[index].as_ref() != Some(&value) {
                return Err(invalid("配置或权限已在上次操作后变化，拒绝覆盖后续修改"));
            }
            record.before[index].value
        } else {
            Some(r.value)
        };
        if value.value == target {
            continue;
        }
        items.push(BaselinePlanItem {
            id: r.id.into(),
            title: r.title.into(),
            location: format!("{}\\{}\\{}", r.hive, r.path, r.name),
            current_value: describe(value.value),
            expected_value: describe(target),
            impact: r.impact.into(),
        });
        before.push(value);
        desired.push(target);
    }
    Ok(Plan { view:BaselineChangePlan {id:Uuid::new_v4().to_string(),target:readback.identity.host_name.clone(),expires_at:now()+TTL,restoring:restore.is_some(),items,notes:vec!["仅修改列出的 64 位注册表 DWORD 策略值；当前账户项仅作用于采集账户。".into(),"执行前在本机便携数据中保存原值与权限；回读验证的是配置值，不代表运行状态或业务恢复。".into(),"不自动重启、刷新组策略或提权。部分配置需重新登录或重启，另行确认后验证。".into(),"失败时停止后续并尝试恢复已核实的本次修改；结果不明的项保留现场。取消只停止后续项。".into(),"恢复前比较当前值和权限；新增的空策略键会保留。注册表比较与写入不是原子事务。".into()]},session:session.into(),identity:readback.identity,before,desired })
}

impl WindowsIncidentService {
    fn baseline_store(&self) -> CoreResult<&PortableStore> {
        self.baseline_store
            .as_ref()
            .ok_or_else(|| invalid("便携备份存储不可用，拒绝写配置"))
    }
    fn baseline_records(&self) -> CoreResult<Vec<Record>> {
        let records: Vec<Record> = self
            .baseline_store()?
            .read_or_default_bounded(StoreFile::WindowsBaseline, BUDGET)?;
        if records.len() > 100
            || records.iter().any(|r| {
                r.before.len() > RULES.len()
                    || r.before.len() != r.after.len()
                    || r.before.len() != r.desired.len()
                    || r.before.len() != r.view.items.len()
                    || r.before
                        .iter()
                        .zip(&r.view.items)
                        .any(|(v, item)| v.id != item.id || !baseline_change_supported(&v.id))
            })
        {
            return Err(invalid("配置历史超限或格式异常"));
        }
        Ok(records)
    }
    pub fn plan_baseline_changes(
        &self,
        ids: &[String],
        session: &str,
    ) -> CoreResult<BaselineChangePlan> {
        let _guard = self
            .baseline_changes
            .gate
            .try_lock()
            .ok_or_else(|| invalid("已有配置任务正在运行"))?;
        if self.baseline_records()?.len() >= 100 {
            return Err(invalid("配置历史达到 100 条上限，请先保留历史并处理容量"));
        }
        self.keep_baseline_plan(make_plan(
            &DvcRemote { svc: self, session },
            ids,
            session,
            None,
        )?)
    }
    fn keep_baseline_plan(&self, plan: Plan) -> CoreResult<BaselineChangePlan> {
        let mut plans = self.baseline_changes.plans.lock();
        plans.retain(|p| p.view.expires_at > now() && p.session == plan.session);
        if plans.len() >= 8 {
            return Err(invalid("待确认计划过多，请关闭旧计划后重试"));
        }
        let view = plan.view.clone();
        plans.push(plan);
        Ok(view)
    }
    pub fn discard_baseline_plan(&self, id: &str, session: &str) {
        self.baseline_changes
            .plans
            .lock()
            .retain(|p| p.view.id != id || p.session != session);
    }
    pub fn baseline_change_history(&self, session: &str) -> CoreResult<Vec<BaselineChangeReport>> {
        if self.status().session_id.as_deref() != Some(session) {
            return Err(invalid("连接已变化"));
        }
        Ok(self
            .baseline_records()?
            .into_iter()
            .rev()
            .map(|r| r.view)
            .collect())
    }
    pub fn plan_baseline_restore(&self, id: &str, session: &str) -> CoreResult<BaselineChangePlan> {
        let _guard = self
            .baseline_changes
            .gate
            .try_lock()
            .ok_or_else(|| invalid("已有配置任务正在运行"))?;
        let records = self.baseline_records()?;
        if records.len() >= 100 {
            return Err(invalid("配置历史达到上限"));
        }
        let record = records
            .iter()
            .find(|r| r.view.id == id && r.view.recovery_available && !r.view.restoring)
            .ok_or_else(|| invalid("该记录没有可自动恢复的已核实修改"))?;
        let ids = record
            .view
            .items
            .iter()
            .filter(|i| i.state == BaselineChangeState::Verified)
            .map(|i| i.id.clone())
            .collect::<Vec<_>>();
        self.keep_baseline_plan(make_plan(
            &DvcRemote { svc: self, session },
            &ids,
            session,
            Some(record),
        )?)
    }
    pub fn cancel_baseline_changes(&self, id: &str, session: &str) -> bool {
        let running = self.baseline_changes.running.lock();
        if let Some((active_id, active_session, cancel)) = running.as_ref()
            && active_id == id
            && active_session == session
        {
            cancel.store(true, Ordering::SeqCst);
            return true;
        }
        false
    }
    pub fn baseline_change_progress(
        &self,
        id: &str,
        session: &str,
    ) -> Option<BaselineChangeReport> {
        if self.status().session_id.as_deref() != Some(session) {
            return None;
        }
        self.baseline_changes
            .progress
            .lock()
            .as_ref()
            .filter(|p| p.id == id)
            .cloned()
    }
    pub fn apply_baseline_plan(&self, id: &str, session: &str) -> CoreResult<BaselineChangeReport> {
        let _guard = self
            .baseline_changes
            .gate
            .try_lock()
            .ok_or_else(|| invalid("已有配置任务正在运行"))?;
        let plan = {
            let mut plans = self.baseline_changes.plans.lock();
            let index = plans
                .iter()
                .position(|p| p.view.id == id && p.session == session)
                .ok_or_else(|| invalid("计划已使用、已取消或属于其他会话"))?;
            plans.remove(index)
        };
        if plan.view.expires_at <= now() || plan.before.is_empty() {
            return Err(invalid("计划已过期或没有需要修改的值，请重新预览"));
        }
        let cancel = Arc::new(AtomicBool::new(false));
        *self.baseline_changes.running.lock() =
            Some((id.into(), session.into(), Arc::clone(&cancel)));
        let result = self.execute_baseline_plan(&DvcRemote { svc: self, session }, &plan, &cancel);
        *self.baseline_changes.running.lock() = None;
        result
    }
    fn execute_baseline_plan(
        &self,
        remote: &impl Remote,
        plan: &Plan,
        cancel: &AtomicBool,
    ) -> CoreResult<BaselineChangeReport> {
        let started = Instant::now();
        let rules = plan
            .before
            .iter()
            .map(|v| rule(&v.id))
            .collect::<CoreResult<Vec<_>>>()?;
        let check = remote.read(&rules)?;
        validate_readback(&check, &rules)?;
        if check.identity != plan.identity || check.values != plan.before {
            return Err(invalid("确认期间配置、权限或目标身份变化，请重新生成计划"));
        }
        let mut records = self.baseline_records()?;
        if records.len() >= 100 {
            return Err(invalid("配置历史达到上限，拒绝写入"));
        }
        let index = records.len();
        records.push(Record {
            view: BaselineChangeReport {
                id: plan.view.id.clone(),
                target: plan.view.target.clone(),
                created_at: now(),
                restoring: plan.view.restoring,
                finished: false,
                recovery_available: false,
                items: plan
                    .view
                    .items
                    .iter()
                    .map(|i| BaselineChangeItem {
                        id: i.id.clone(),
                        title: i.title.clone(),
                        state: BaselineChangeState::Pending,
                    })
                    .collect(),
                message: "原值已保存，等待逐项执行".into(),
            },
            identity: plan.identity.clone(),
            before: plan.before.clone(),
            after: vec![None; plan.before.len()],
            desired: plan.desired.clone(),
        });
        let persist = |records: &[Record]| -> CoreResult<()> {
            self.baseline_store()?
                .write_bounded(StoreFile::WindowsBaseline, &records, BUDGET)?;
            *self.baseline_changes.progress.lock() = Some(records[index].view.clone());
            Ok(())
        };
        persist(&records)?; // Durable backup and intent precede every remote mutation.
        let mut failed = false;
        let mut execution_before = plan.before.clone();
        for (i, r) in rules.iter().enumerate() {
            if started.elapsed() > Duration::from_secs(180) {
                cancel.store(true, Ordering::SeqCst);
            }
            if cancel.load(Ordering::SeqCst) {
                break;
            }
            records[index].view.items[i].state = BaselineChangeState::Applying;
            records[index].view.message =
                format!("正在配置并复核第 {} / {} 项", i + 1, rules.len());
            persist(&records)?;
            let result = remote.write(&plan.identity, *r, &execution_before[i], plan.desired[i]);
            let state = match result {
                Ok(false) => BaselineChangeState::Refused,
                Err(_) => BaselineChangeState::Uncertain,
                Ok(true) => match remote.read(&[*r]) {
                    Ok(read)
                        if validate_readback(&read, &[*r]).is_ok()
                            && read.identity == plan.identity
                            && read.values[0].value == plan.desired[i]
                            && (!execution_before[i].key_exists
                                || read.values[0].security == execution_before[i].security) =>
                    {
                        // Several values can share a key created by this plan. Carry only
                        // its verified existence/ACL forward; other values must stay absent.
                        if !execution_before[i].key_exists {
                            for (next, next_rule) in rules.iter().enumerate().skip(i + 1) {
                                if !execution_before[next].key_exists
                                    && next_rule.hive == r.hive
                                    && next_rule.path == r.path
                                {
                                    execution_before[next].key_exists = true;
                                    execution_before[next].security =
                                        read.values[0].security.clone();
                                }
                            }
                        }
                        records[index].after[i] = Some(read.values[0].clone());
                        if plan.view.restoring {
                            BaselineChangeState::Restored
                        } else {
                            BaselineChangeState::Verified
                        }
                    }
                    _ => BaselineChangeState::Uncertain,
                },
            };
            failed = !matches!(
                state,
                BaselineChangeState::Verified | BaselineChangeState::Restored
            );
            records[index].view.items[i].state = state;
            records[index].view.recovery_available = records[index]
                .view
                .items
                .iter()
                .any(|i| i.state == BaselineChangeState::Verified);
            persist(&records)?;
            if failed {
                break;
            }
        }
        // On failure, restore only values whose complete post-write observation is known.
        if failed && !plan.view.restoring {
            for (i, r) in rules.iter().enumerate().rev() {
                if started.elapsed() > Duration::from_secs(300) {
                    break;
                }
                if records[index].view.items[i].state != BaselineChangeState::Verified {
                    continue;
                }
                let after = records[index].after[i]
                    .clone()
                    .ok_or_else(|| invalid("缺少修改后观察"))?;
                records[index].view.items[i].state = BaselineChangeState::Applying;
                records[index].view.message = "正在恢复本次已经核实的修改…".into();
                records[index].view.recovery_available = records[index]
                    .view
                    .items
                    .iter()
                    .any(|item| item.state == BaselineChangeState::Verified);
                persist(&records)?;
                records[index].view.items[i].state = BaselineChangeState::Uncertain;
                if let Ok(true) = remote.write(&plan.identity, *r, &after, plan.before[i].value)
                    && let Ok(read) = remote.read(&[*r])
                    && validate_readback(&read, &[*r]).is_ok()
                    && read.identity == plan.identity
                    && read.values[0].value == plan.before[i].value
                    && read.values[0].security == after.security
                {
                    records[index].view.items[i].state = BaselineChangeState::Restored;
                }
                records[index].view.recovery_available = records[index]
                    .view
                    .items
                    .iter()
                    .any(|i| i.state == BaselineChangeState::Verified);
                persist(&records)?;
            }
        }
        let view = &mut records[index].view;
        for item in &mut view.items {
            if item.state == BaselineChangeState::Pending {
                item.state = BaselineChangeState::Skipped;
            }
        }
        view.finished = true;
        view.recovery_available = !view.restoring
            && view
                .items
                .iter()
                .any(|i| i.state == BaselineChangeState::Verified);
        view.message = if failed && view.restoring {
            "恢复中断；已恢复的原值保留，结果不明项需人工复核，不会重新应用先前的配置。"
        } else if failed {
            "操作中断；已尝试恢复本次已核实的修改。结果不明项不可重复执行旧计划，请核对目标后处理。"
        } else if cancel.load(Ordering::SeqCst) {
            "后续项已停止；已经完成的配置保留，可另行预览恢复。"
        } else {
            "所列配置值已独立回读；运行状态、重启条件与业务连接仍需另行复核。"
        }
        .into();
        persist(&records)?;
        Ok(records[index].view.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    struct Fixture {
        values: Mutex<BTreeMap<String, Value>>,
        writes: Mutex<Vec<String>>,
        fail_at: usize,
        uncertain: bool,
        cancel: Option<Arc<AtomicBool>>,
        after_first: Option<(String, u32)>,
    }
    fn identity() -> Identity {
        Identity {
            machine: "owned-unit-fixture".into(),
            account: "S-1-5-21-1-2-3-1001".into(),
            host_name: "LAB".into(),
            version: "10.0.26200".into(),
            boot: "2026-10-26T00:00:00Z".into(),
            elevated: true,
            domain: false,
            product_type: 1,
        }
    }
    impl Fixture {
        fn new() -> Self {
            Self {
                values: Mutex::new(
                    ["wdigest", "uac"]
                        .map(|id| {
                            (
                                id.into(),
                                Value {
                                    id: id.into(),
                                    value: Some(if id == "wdigest" { 1 } else { 0 }),
                                    key_exists: true,
                                    security: "O:SYG:SYD:(A;;KA;;;SY)".into(),
                                },
                            )
                        })
                        .into(),
                ),
                writes: Mutex::new(Vec::new()),
                fail_at: 0,
                uncertain: false,
                cancel: None,
                after_first: None,
            }
        }
    }
    impl Remote for Fixture {
        fn read(&self, rules: &[Rule]) -> CoreResult<Readback> {
            Ok(Readback {
                identity: identity(),
                values: rules
                    .iter()
                    .map(|r| self.values.lock()[r.id].clone())
                    .collect(),
            })
        }
        fn write(
            &self,
            _: &Identity,
            r: Rule,
            before: &Value,
            desired: Option<u32>,
        ) -> CoreResult<bool> {
            let mut writes = self.writes.lock();
            writes.push(r.id.into());
            if writes.len() == self.fail_at {
                return if self.uncertain {
                    Err(invalid("test transport timeout"))
                } else {
                    Ok(false)
                };
            }
            let mut values = self.values.lock();
            if values[r.id] != *before {
                return Ok(false);
            }
            if !before.key_exists {
                for value in values.values_mut() {
                    let sibling = rule(&value.id).unwrap();
                    if sibling.hive == r.hive && sibling.path == r.path {
                        value.key_exists = true;
                        value.security = "O:SYG:SYD:(A;;KA;;;SY)".into();
                    }
                }
            }
            values.get_mut(r.id).unwrap().value = desired;
            if writes.len() == 1
                && let Some((id, value)) = &self.after_first
            {
                values.get_mut(id).unwrap().value = Some(*value);
            }
            if let Some(cancel) = &self.cancel {
                cancel.store(true, Ordering::SeqCst);
            }
            Ok(true)
        }
    }
    struct TestDirectory(std::path::PathBuf);
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            if let (Ok(root), Ok(temp)) =
                (self.0.canonicalize(), std::env::temp_dir().canonicalize())
                && root.starts_with(&temp)
                && root.file_name().is_some_and(|name| {
                    name.to_string_lossy()
                        .starts_with("lovelyhawk-windows-baseline-test-")
                })
            {
                let _ = std::fs::remove_dir_all(root);
            }
        }
    }
    fn service() -> (TestDirectory, WindowsIncidentService) {
        let dir = TestDirectory(std::env::temp_dir().join(format!(
            "lovelyhawk-windows-baseline-test-{}",
            Uuid::new_v4()
        )));
        let svc =
            WindowsIncidentService::with_store(PortableStore::prepare(dir.0.clone()).unwrap());
        (dir, svc)
    }
    fn ids() -> Vec<String> {
        vec!["wdigest".into(), "uac".into()]
    }
    #[test]
    fn encoded_fixed_queries_fit_windows_process_command_limits() {
        let encoded_len = |payload: serde_json::Value| {
            encode_powershell_command(&SCRIPT.replace(
                "__PAYLOAD__",
                &BASE64.encode(serde_json::to_vec(&payload).unwrap()),
            ))
            .encode_utf16()
            .count()
        };
        for batch in RULES.chunks(6) {
            assert!(encoded_len(serde_json::json!({"mode":"read", "rules":batch})) < 30_000);
        }
        for rule in RULES {
            let before = Value {
                id: rule.id.into(),
                key_exists: true,
                value: Some(u32::MAX),
                security: "X".repeat(2048),
            };
            assert!(
                encoded_len(
                    serde_json::json!({"mode":"write","identity":identity(),"rule":rule,"before":before,"desired":rule.value})
                ) < 30_000
            );
        }
    }

    #[test]
    fn rejects_injected_duplicate_and_unsupported_scope() {
        let remote = Fixture::new();
        for values in [
            vec![],
            vec!["wdigest".into(), "wdigest".into()],
            vec!["wdigest'; Remove-Item C:\\".into()],
            vec!["lsass-ppl".into()],
        ] {
            assert!(make_plan(&remote, &values, "session", None).is_err());
        }
        let mut target = identity();
        target.domain = true;
        assert!(target.check().is_err());
        target.domain = false;
        target.elevated = false;
        assert!(target.check().is_err());
        target.elevated = true;
        target.product_type = 2;
        assert!(target.check().is_err());
    }
    #[test]
    fn backup_precedes_writes_and_independent_reads_enable_guarded_restore() {
        let (_dir, svc) = service();
        let remote = Fixture::new();
        let plan = make_plan(&remote, &ids(), "s", None).unwrap();
        let result = svc
            .execute_baseline_plan(&remote, &plan, &AtomicBool::new(false))
            .unwrap();
        assert!(result.finished && result.recovery_available);
        assert!(
            result
                .items
                .iter()
                .all(|i| i.state == BaselineChangeState::Verified)
        );
        let records = svc.baseline_records().unwrap();
        assert_eq!(records[0].before[0].value, Some(1));
        assert_eq!(records[0].after[0].as_ref().unwrap().value, Some(0));
        let no_op = make_plan(&remote, &ids(), "s", None).unwrap();
        assert!(no_op.view.items.is_empty());
        let restore = make_plan(&remote, &ids(), "s", Some(&records[0])).unwrap();
        let result = svc
            .execute_baseline_plan(&remote, &restore, &AtomicBool::new(false))
            .unwrap();
        assert!(
            result
                .items
                .iter()
                .all(|i| i.state == BaselineChangeState::Restored)
        );
        assert!(!result.recovery_available);
        assert_eq!(remote.values.lock()["wdigest"].value, Some(1));
    }
    #[test]
    fn changed_value_or_acl_after_confirmation_causes_zero_writes() {
        for acl in [false, true] {
            let (_dir, svc) = service();
            let remote = Fixture::new();
            let plan = make_plan(&remote, &ids(), "s", None).unwrap();
            if acl {
                remote
                    .values
                    .lock()
                    .get_mut("uac")
                    .unwrap()
                    .security
                    .push('X');
            } else {
                remote.values.lock().get_mut("uac").unwrap().value = Some(9);
            }
            assert!(
                svc.execute_baseline_plan(&remote, &plan, &AtomicBool::new(false))
                    .is_err()
            );
            assert!(remote.writes.lock().is_empty());
        }
    }
    #[test]
    fn shared_missing_key_can_be_configured_and_restored_without_masking_foreign_values() {
        for foreign_change in [false, true] {
            let (_dir, svc) = service();
            let mut remote = Fixture::new();
            let ids = vec!["winrm-basic".into(), "winrm-cleartext".into()];
            *remote.values.lock() = ids
                .iter()
                .map(|id: &String| {
                    (
                        id.clone(),
                        Value {
                            id: id.clone(),
                            key_exists: false,
                            value: None,
                            security: String::new(),
                        },
                    )
                })
                .collect();
            if foreign_change {
                remote.after_first = Some(("winrm-cleartext".into(), 9));
            }
            let plan = make_plan(&remote, &ids, "s", None).unwrap();
            let report = svc
                .execute_baseline_plan(&remote, &plan, &AtomicBool::new(false))
                .unwrap();
            let records = svc.baseline_records().unwrap();
            assert!(
                records[0]
                    .before
                    .iter()
                    .all(|value| !value.key_exists && value.value.is_none())
            );
            if foreign_change {
                assert_eq!(report.items[0].state, BaselineChangeState::Restored);
                assert_eq!(report.items[1].state, BaselineChangeState::Refused);
                assert_eq!(remote.values.lock()["winrm-cleartext"].value, Some(9));
            } else {
                assert!(
                    report
                        .items
                        .iter()
                        .all(|item| item.state == BaselineChangeState::Verified)
                );
                let restore = make_plan(&remote, &ids, "s", Some(&records[0])).unwrap();
                let report = svc
                    .execute_baseline_plan(&remote, &restore, &AtomicBool::new(false))
                    .unwrap();
                assert!(
                    report
                        .items
                        .iter()
                        .all(|item| item.state == BaselineChangeState::Restored)
                );
                assert!(
                    remote
                        .values
                        .lock()
                        .values()
                        .all(|value| value.key_exists && value.value.is_none())
                );
            }
        }
    }
    #[test]
    fn failed_second_item_restores_verified_first_and_records_partial_outcome() {
        let (_dir, svc) = service();
        let mut remote = Fixture::new();
        remote.fail_at = 2;
        let plan = make_plan(&remote, &ids(), "s", None).unwrap();
        let report = svc
            .execute_baseline_plan(&remote, &plan, &AtomicBool::new(false))
            .unwrap();
        assert_eq!(report.items[0].state, BaselineChangeState::Restored);
        assert_eq!(report.items[1].state, BaselineChangeState::Refused);
        assert!(!report.recovery_available);
        assert_eq!(remote.values.lock()["wdigest"].value, Some(1));
        assert_eq!(remote.writes.lock().len(), 3);
    }
    #[test]
    fn uncertain_write_is_not_retried_or_rolled_back_without_post_state() {
        let (_dir, svc) = service();
        let mut remote = Fixture::new();
        remote.fail_at = 1;
        remote.uncertain = true;
        let plan = make_plan(&remote, &ids(), "s", None).unwrap();
        let report = svc
            .execute_baseline_plan(&remote, &plan, &AtomicBool::new(false))
            .unwrap();
        assert_eq!(report.items[0].state, BaselineChangeState::Uncertain);
        assert_eq!(report.items[1].state, BaselineChangeState::Skipped);
        assert_eq!(remote.writes.lock().len(), 1);
    }
    #[test]
    fn cancellation_stops_subsequent_items_and_preserves_recovery() {
        let (_dir, svc) = service();
        let mut remote = Fixture::new();
        let cancel = Arc::new(AtomicBool::new(false));
        remote.cancel = Some(Arc::clone(&cancel));
        let plan = make_plan(&remote, &ids(), "s", None).unwrap();
        let report = svc.execute_baseline_plan(&remote, &plan, &cancel).unwrap();
        assert_eq!(report.items[0].state, BaselineChangeState::Verified);
        assert_eq!(report.items[1].state, BaselineChangeState::Skipped);
        assert!(report.recovery_available);
    }
    #[test]
    fn restore_refuses_business_changes_and_backup_failure_prevents_writes() {
        let (_dir, svc) = service();
        let remote = Fixture::new();
        let plan = make_plan(&remote, &ids(), "s", None).unwrap();
        svc.execute_baseline_plan(&remote, &plan, &AtomicBool::new(false))
            .unwrap();
        let records = svc.baseline_records().unwrap();
        remote.values.lock().get_mut("uac").unwrap().value = Some(9);
        assert!(make_plan(&remote, &ids(), "s", Some(&records[0])).is_err());
        let remote = Fixture::new();
        let plan = make_plan(&remote, &ids(), "s", None).unwrap();
        assert!(
            WindowsIncidentService::new()
                .execute_baseline_plan(&remote, &plan, &AtomicBool::new(false))
                .is_err()
        );
        assert!(remote.writes.lock().is_empty());
    }
    #[test]
    fn plans_are_consumed_before_expiry_and_session_errors_never_write() {
        let (_dir, svc) = service();
        let remote = Fixture::new();
        let mut plan = make_plan(&remote, &ids(), "session", None).unwrap();
        plan.view.expires_at = now() - 1;
        let id = plan.view.id.clone();
        svc.keep_baseline_plan(plan).unwrap();
        assert!(svc.apply_baseline_plan(&id, "wrong-session").is_err());
        assert_eq!(svc.baseline_changes.plans.lock().len(), 1);
        assert!(svc.apply_baseline_plan(&id, "session").is_err());
        assert!(svc.baseline_changes.plans.lock().is_empty());
        assert!(svc.apply_baseline_plan(&id, "session").is_err());
    }
}
