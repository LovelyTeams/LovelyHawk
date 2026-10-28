//! Single-use, session-bound process termination plans. No process names or scripts
//! supplied by the page become commands. Termination has no rollback.
use super::{
    BASE64, WindowsIncidentService, encode_powershell_command, strip_exit_prefix,
    valid_process_identity,
};
use crate::{CoreError, CoreResult, store::StoreFile};
use base64::Engine as _;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

const SCRIPT: &str = include_str!("process_change.ps1");
const BUDGET: usize = 4 * 1024 * 1024;
fn invalid(message: &str) -> CoreError {
    CoreError::validation("windows process plan", message)
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessPlanItem {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub start_time: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessChangePlan {
    pub id: String,
    pub target: String,
    pub expires_at: u64,
    pub tree: bool,
    /// Root first, then descendants. Execution runs in reverse order.
    pub items: Vec<ProcessPlanItem>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProcessChangeState {
    Verified,
    Refused,
    Failed,
    Skipped,
    Uncertain,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessChangeItem {
    pub pid: u32,
    pub state: ProcessChangeState,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessChangeReport {
    pub id: String,
    pub items: Vec<ProcessChangeItem>,
    pub message: String,
}
#[derive(Debug)]
struct Plan {
    view: ProcessChangePlan,
    session: String,
    created: Instant,
}
#[derive(Debug, Default)]
pub(super) struct ProcessChanges {
    plan: Mutex<Option<Plan>>,
    execution: Mutex<()>,
}
impl ProcessChanges {
    fn consume(
        &self,
        id: &str,
        session: &str,
        connected_session: Option<&str>,
    ) -> CoreResult<Plan> {
        let mut pending = self.plan.lock();
        let plan = pending
            .as_ref()
            .ok_or_else(|| invalid("计划已失效，请重新预览。"))?;
        if plan.view.id != id
            || plan.session != session
            || connected_session != Some(session)
            || plan.created.elapsed() > Duration::from_secs(120)
        {
            return Err(invalid("计划已过期或连接已变化，请重新预览。"));
        }
        Ok(pending.take().expect("checked plan"))
    }
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Discovery {
    target: String,
    items: Vec<ProcessPlanItem>,
}
#[derive(Serialize, Deserialize)]
struct Record {
    plan: ProcessChangePlan,
    created_at: u64,
    report: ProcessChangeReport,
}

fn validate_discovery(discovery: &Discovery, pid: u32, start: &str, tree: bool) -> CoreResult<()> {
    if discovery.target.is_empty()
        || discovery.target.len() > 255
        || discovery.items.is_empty()
        || discovery.items.len() > 64
        || (!tree && discovery.items.len() != 1)
    {
        return Err(invalid(
            "未取得完整的进程范围（每次最多 64 个），请缩小范围后重试。",
        ));
    }
    let root = &discovery.items[0];
    if root.pid != pid || root.start_time != start {
        return Err(invalid("进程身份已变化，请刷新后重新预览。"));
    }
    let mut seen = HashSet::new();
    for item in &discovery.items {
        if item.pid <= 4
            || !valid_process_identity(item.pid, &item.start_time)
            || item.name.is_empty()
            || item.name.len() > 260
            || !seen.insert(item.pid)
            || [
                "system",
                "idle",
                "registry",
                "smss.exe",
                "csrss.exe",
                "wininit.exe",
                "services.exe",
                "lsass.exe",
                "winlogon.exe",
                "fontdrvhost.exe",
                "dwm.exe",
            ]
            .contains(&item.name.to_ascii_lowercase().as_str())
        {
            return Err(invalid(
                "范围内包含无法核实身份或受保护的进程，未生成结束计划。",
            ));
        }
        if item.pid != pid {
            let parent = discovery
                .items
                .iter()
                .find(|p| p.pid == item.ppid && seen.contains(&p.pid));
            if parent.is_none_or(|p| {
                p.pid == item.pid
                    || chrono::DateTime::parse_from_rfc3339(&p.start_time).ok()
                        >= chrono::DateTime::parse_from_rfc3339(&item.start_time).ok()
            }) {
                return Err(invalid("无法可靠核对父子进程关系，请重新采集。"));
            }
        }
    }
    Ok(())
}

fn apply_payload(plan: &ProcessChangePlan) -> CoreResult<serde_json::Value> {
    // Integer-only identities bound the Windows command line. Names stay in the
    // immutable local preview and journal, never in a shell program.
    let items = plan
        .items
        .iter()
        .map(|p| {
            let time = chrono::DateTime::parse_from_rfc3339(&p.start_time)
                .map_err(|_| invalid("进程时间无效。"))?;
            let filetime = time
                .timestamp_micros()
                .checked_mul(10)
                .and_then(|v| v.checked_add(116_444_736_000_000_000))
                .filter(|v| *v > 0)
                .ok_or_else(|| invalid("进程时间无效。"))?;
            Ok(serde_json::json!([p.pid, p.ppid, filetime]))
        })
        .collect::<CoreResult<Vec<_>>>()?;
    Ok(serde_json::json!({"mode":"apply","plan":{"id":plan.id,"tree":plan.tree,"items":items}}))
}
fn process_command(input: &serde_json::Value) -> CoreResult<String> {
    let encoded =
        BASE64.encode(serde_json::to_vec(input).map_err(|_| invalid("无法生成进程计划。"))?);
    let script = format!(
        "$request = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded}')) | ConvertFrom-Json\n{SCRIPT}"
    );
    let command = encode_powershell_command(&script);
    if command.encode_utf16().count() > 30_000 {
        return Err(invalid("进程范围超过本次传输上限，请缩小范围。"));
    }
    Ok(command)
}

impl WindowsIncidentService {
    fn process_script(&self, input: serde_json::Value, session: &str) -> CoreResult<String> {
        let command = process_command(&input)?;
        let output = self
            .hub
            .execute_command_for_session(&command, Duration::from_secs(45), session)
            .map_err(|_| {
                invalid("未取得远端处置结果；请核对连接并重新采集，不能据此判断进程已结束。")
            })?;
        Ok(strip_exit_prefix(&output)?.to_owned())
    }
    pub fn plan_process_change(
        &self,
        pid: u32,
        start: &str,
        tree: bool,
        session: &str,
    ) -> CoreResult<ProcessChangePlan> {
        if pid <= 4 || !valid_process_identity(pid, start) {
            return Err(invalid("进程身份无效。"));
        }
        let _guard = self
            .process_changes
            .execution
            .try_lock()
            .ok_or_else(|| invalid("正在处理另一个进程计划。"))?;
        *self.process_changes.plan.lock() = None;
        let output = self.process_script(
            serde_json::json!({"mode":"plan","pid":pid,"startTime":start,"tree":tree}),
            session,
        )?;
        let discovery: Discovery = serde_json::from_str(output.trim()).map_err(|_| {
            invalid("无法预览完整进程范围；可能进程已退出、权限不足或包含采集端，请刷新后核对。")
        })?;
        validate_discovery(&discovery, pid, start, tree)?;
        let view = ProcessChangePlan {
            id: Uuid::new_v4().to_string(),
            target: discovery.target,
            expires_at: now() + 120,
            tree,
            items: discovery.items,
        };
        process_command(&apply_payload(&view)?)?;
        *self.process_changes.plan.lock() = Some(Plan {
            view: view.clone(),
            session: session.into(),
            created: Instant::now(),
        });
        Ok(view)
    }
    pub fn discard_process_plan(&self, id: &str, session: &str) {
        let mut pending = self.process_changes.plan.lock();
        if pending
            .as_ref()
            .is_some_and(|p| p.view.id == id && p.session == session)
        {
            *pending = None;
        }
    }
    pub fn apply_process_plan(&self, id: &str, session: &str) -> CoreResult<ProcessChangeReport> {
        let _guard = self
            .process_changes
            .execution
            .try_lock()
            .ok_or_else(|| invalid("已有进程处置正在执行。"))?;
        let status = self.status();
        let plan = self.process_changes.consume(
            id,
            session,
            if status.channel_connected {
                status.session_id.as_deref()
            } else {
                None
            },
        )?;
        let store = self
            .baseline_store
            .as_ref()
            .ok_or_else(|| invalid("本机操作记录不可用，未执行结束操作。"))?;
        let mut records: Vec<Record> =
            store.read_or_default_bounded(StoreFile::WindowsProcesses, BUDGET)?;
        if records.len() >= 100 {
            return Err(invalid("进程处置记录已达 100 条上限，请先归档本机记录。"));
        }
        let mut report = ProcessChangeReport {
            id: id.into(),
            items: plan
                .view
                .items
                .iter()
                .map(|p| ProcessChangeItem {
                    pid: p.pid,
                    state: ProcessChangeState::Uncertain,
                })
                .collect(),
            message: "执行结果未知，请重新采集核对；终止进程不可恢复。".into(),
        };
        records.push(Record {
            plan: plan.view.clone(),
            created_at: now(),
            report: report.clone(),
        });
        store.write_bounded(StoreFile::WindowsProcesses, &records, BUDGET)?;
        if let Ok(output) = self.process_script(apply_payload(&plan.view)?, session)
            && let Ok(result) = serde_json::from_str::<ProcessChangeReport>(output.trim())
            && result.id == id
            && result.items.len() == report.items.len()
            && result.message.len() <= 2048
            && result
                .items
                .iter()
                .zip(&report.items)
                .all(|(a, b)| a.pid == b.pid)
        {
            report = result;
            let verified = report
                .items
                .iter()
                .filter(|i| i.state == ProcessChangeState::Verified)
                .count();
            report.message = format!(
                "计划内 {} 个进程，已核实退出 {verified} 个；其余请查看逐项结果。终止进程不可恢复，请刷新并复查执行期间新建或自动拉起的进程与持久化。",
                report.items.len()
            );
        }
        records.last_mut().expect("inserted record").report = report.clone();
        if store
            .write_bounded(StoreFile::WindowsProcesses, &records, BUDGET)
            .is_err()
        {
            report
                .message
                .push_str(" 本机结果保存失败；执行前记录已保留，请保存本次结果并核对现场。");
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn item(pid: u32, ppid: u32, second: u32) -> ProcessPlanItem {
        ProcessPlanItem {
            pid,
            ppid,
            name: "harmless.exe".into(),
            start_time: format!("2026-10-27T00:00:{second:02}.0000000Z"),
        }
    }
    #[test]
    fn tree_requires_complete_ordered_unique_nonprotected_identities() {
        let root = item(100, 40, 1);
        let mut d = Discovery {
            target: "lab".into(),
            items: vec![root.clone(), item(101, 100, 2), item(102, 101, 3)],
        };
        assert!(validate_discovery(&d, 100, &root.start_time, true).is_ok());
        assert!(validate_discovery(&d, 100, &root.start_time, false).is_err());
        d.items[2].ppid = 999;
        assert!(validate_discovery(&d, 100, &root.start_time, true).is_err());
        d.items[2] = item(100, 101, 3);
        assert!(validate_discovery(&d, 100, &root.start_time, true).is_err());
        d.items[2] = item(102, 101, 0);
        assert!(validate_discovery(&d, 100, &root.start_time, true).is_err());
        d.items[2] = item(102, 101, 3);
        d.items[2].name = "LSASS.EXE".into();
        assert!(validate_discovery(&d, 100, &root.start_time, true).is_err());
    }
    fn plan(items: Vec<ProcessPlanItem>) -> ProcessChangePlan {
        ProcessChangePlan {
            id: Uuid::new_v4().to_string(),
            target: "owned lab".into(),
            tree: true,
            expires_at: now() + 120,
            items,
        }
    }
    #[test]
    fn compact_64_member_plan_fits_command_line_without_names_or_shell_text() {
        let view = plan(
            (0..64)
                .map(|i| ProcessPlanItem {
                    pid: u32::MAX - i,
                    ppid: u32::MAX - 100,
                    name: "';secret $()".repeat(20),
                    start_time: "2026-10-27T00:00:00.1234560Z".into(),
                })
                .collect(),
        );
        let payload = apply_payload(&view).unwrap();
        assert!(!payload.to_string().contains("secret"));
        assert!(process_command(&payload).unwrap().len() < 30000);
    }
    #[test]
    fn plans_are_single_use_expiring_and_session_bound() {
        let state = ProcessChanges::default();
        let view = plan(vec![item(100, 10, 1)]);
        *state.plan.lock() = Some(Plan {
            view: view.clone(),
            session: "owned-session".into(),
            created: Instant::now(),
        });
        assert!(state.consume(&view.id, "other", Some("other")).is_err());
        assert!(state.consume(&view.id, "owned-session", None).is_err());
        assert!(
            state
                .consume("different-plan", "owned-session", Some("owned-session"))
                .is_err()
        );
        assert!(
            state
                .consume(&view.id, "owned-session", Some("owned-session"))
                .is_ok()
        );
        assert!(
            state
                .consume(&view.id, "owned-session", Some("owned-session"))
                .is_err()
        );
        *state.plan.lock() = Some(Plan {
            view: view.clone(),
            session: "owned-session".into(),
            created: Instant::now() - Duration::from_secs(121),
        });
        assert!(
            state
                .consume(&view.id, "owned-session", Some("owned-session"))
                .is_err()
        );
    }
}
