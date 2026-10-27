import { useEffect, useRef, useState } from "react";
import type { WindowsControlOperation, WindowsControlPlan, WindowsControlReport, WindowsIncidentResponse, WindowsInventoryKind, WindowsRemoteIntent } from "../shared/windows-incident-contract";
import { WinIrModal } from "./WinIrKit";
import { errorText } from "./error-text";

export const CONTROL_LABELS: Record<WindowsControlOperation, string> = { start: "启动", stop: "停止", restart: "重启", automatic: "设为自动启动", manual: "设为手动启动", enable: "启用", disable: "禁用", run: "立即运行", delete: "删除注册项" };
export const CONTROL_ACTIONS: Record<WindowsInventoryKind, readonly WindowsControlOperation[]> = {tasks:["run","stop","enable","disable","delete"],services:["start","stop","restart","automatic","manual","disable","delete"],drivers:["start","stop","restart","automatic","manual","disable","delete"]};
const RESULTS = { verified: "已核实", submitted: "已提交运行", refused: "未执行", uncertain: "结果待核实" };
export type ControlSelection = { kind: WindowsInventoryKind; session: string; action: { objectId: string; name: string; operation: WindowsControlOperation } | null };

export function WinIrControlChange({ selection, currentSession, onRequest, onClose, onRefresh, onResult }: {
  selection: ControlSelection; currentSession: string | null;
  onRequest: (request: WindowsRemoteIntent, session: string, label?: string) => Promise<WindowsIncidentResponse>;
  onClose: () => void; onRefresh: () => void; onResult: (message: string, failed: boolean) => void;
}) {
  const [plan, setPlan] = useState<WindowsControlPlan | null>(null);
  const [history, setHistory] = useState<WindowsControlReport[]>([]);
  const [report, setReport] = useState<WindowsControlReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [working, setWorking] = useState(true);
  const [attempted, setAttempted] = useState(false);
  const [deletionUnderstood, setDeletionUnderstood] = useState(false);
  const [clock, setClock] = useState(Date.now);
  const lock = useRef(false);
  const initial = useRef(false);
  const live = useRef(true);
  const region = useRef<HTMLDivElement>(null);
  const available = selection.session === currentSession;
  useEffect(() => { live.current = true; const timer = setInterval(() => setClock(Date.now()), 1000); return () => { live.current = false; clearInterval(timer); }; }, []);
  useEffect(() => { if (plan) region.current?.focus({ preventScroll: true }); }, [plan]);
  useEffect(() => {
    if (initial.current) return;
    initial.current = true;
    lock.current = true;
    const request: WindowsRemoteIntent = selection.action ? { action: "plan-control", objectId: selection.action.objectId, operation: selection.action.operation } : { action: "control-history" };
    void onRequest(request, selection.session, selection.action ? "正在只读核对对象、配置与依赖…" : "正在读取处置记录…").then((response) => {
      if (!live.current) return;
      if (response.kind === "control-plan") setPlan(response.plan);
      else if (response.kind === "control-history") setHistory(response.records);
    }).catch((reason: unknown) => { if (live.current) setError(errorText(reason, "读取失败，请刷新清单后重试。")); }).finally(() => { lock.current = false; if (live.current) setWorking(false); });
  }, [onRequest, selection]);
  async function restore(recordId: string) {
    if (lock.current || !available) return;
    lock.current = true; setWorking(true); setError(null);
    try {
      const response = await onRequest({ action: "plan-control-restore", recordId }, selection.session, "正在核对原目标与修改后的配置…");
      if (live.current && response.kind === "control-plan") setPlan(response.plan);
    } catch (reason) { if (live.current) setError(errorText(reason, "恢复条件不满足，请查看当前配置。")); }
    finally { lock.current = false; if (live.current) setWorking(false); }
  }
  async function apply() {
    if (lock.current || !available || !plan || attempted || plan.expiresAt * 1000 <= Date.now() || (plan.operation==="delete" && !deletionUnderstood)) return;
    lock.current = true; setWorking(true); setAttempted(true); setError(null);
    try {
      const response = await onRequest({ action: "apply-control", planId: plan.id }, selection.session, "正在执行已确认的操作并独立回读…");
      if (response.kind !== "control-report" || response.report.kind !== plan.kind || response.report.name !== plan.name || response.report.operation !== plan.operation) throw new Error("返回的操作范围不一致，请刷新清单核对结果。");
      if (live.current) { setReport(response.report); onResult(response.report.message, response.report.state === "uncertain" || response.report.state === "refused"); }
    } catch (reason) { if (live.current) { const message = errorText(reason, "未取得操作结果，请刷新清单核对。不要直接重复执行。"); setError(message); onResult(message, true); } }
    finally { lock.current = false; if (live.current) setWorking(false); }
  }
  async function close() {
    if (lock.current) return;
    lock.current = true; setWorking(true);
    if (plan && !attempted && available) { try { await onRequest({ action: "discard-control-plan", planId: plan.id }, selection.session); } catch { /* The unused plan expires after two minutes. */ } }
    onClose();
  }
  const title = plan ? `${plan.restoring ? "恢复配置 · " : ""}${CONTROL_LABELS[plan.operation]}` : selection.action ? CONTROL_LABELS[selection.action.operation] : "处置与恢复记录";
  return <WinIrModal wide title={title} subtitle={plan?.name ?? selection.action?.name ?? "仅保存操作结果与可恢复的配置原值"} onClose={() => void close()} actions={<>
    <button type="button" className="win-ir-btn" disabled={working} onClick={() => void close()}>关闭</button>
    {plan && !attempted ? <button type="button" className="win-ir-btn is-danger" disabled={working || !available || plan.expiresAt * 1000 <= clock || (plan.operation==="delete" && !deletionUnderstood)} onClick={() => void apply()}>确认{plan.restoring ? "恢复配置" : CONTROL_LABELS[plan.operation]}</button> : null}
    {attempted && !working ? <button type="button" className="win-ir-btn is-primary" disabled={!available} onClick={() => { onClose(); onRefresh(); }}>刷新清单并复查</button> : null}
  </>}>
    {!available ? <p role="alert">连接已变化，当前计划失效，请关闭后重新核对目标。</p> : null}
    {working ? <p role="status">{attempted ? "正在执行并核对结果，请等待…" : "正在只读核对，请等待…"}</p> : null}
    {error ? <p className="wir-reader-warning" role="alert">{error}</p> : null}
    {plan ? <div ref={region} tabIndex={0} role="region" aria-label="完整操作计划" className="wir-baseline-plan">
      <p>目标：<strong>{plan.target}</strong> · 对象：<strong>{plan.name}</strong></p>
      <p>当前状态：{plan.currentState} · 预期变化：{plan.beforeSetting} → {plan.afterSetting}</p>
      <pre>{plan.command || "未提供命令操作"}</pre>
      <ul>{plan.impact.map((message, index) => <li key={index}>{message}</li>)}</ul>
      <p>有效至 {new Date(plan.expiresAt * 1000).toLocaleTimeString()}；目标、配置或运行状态变化后需重新预览。</p>
      {plan.expiresAt * 1000 <= clock && !attempted ? <p role="alert">计划已过期，请关闭后重新预览。</p> : null}
    </div> : null}
    {plan?.operation==="delete" && !attempted ? <label className="wir-delete-ack"><input type="checkbox" checked={deletionUnderstood} disabled={working||!available} onChange={event=>setDeletionUnderstood(event.target.checked)}/>我已核对删除范围，理解此操作没有完整备份、不能一键恢复，执行文件将保留。</label> : null}
    {report ? <p role="status">{RESULTS[report.state]}：{report.message}{report.canRestore ? " 可在处置记录中预览恢复原配置。" : ""}</p> : null}
    {!selection.action && !plan && !working ? <div className="wir-baseline-plan">
      <p>恢复只还原启动方式或任务启用状态；不会自动重新启动服务、驱动或任务。需要连接记录中的原主机。</p>
      {history.filter((r) => r.kind === selection.kind).map((record) => <article key={record.id}>
        <strong>{record.name} · {CONTROL_LABELS[record.operation]} · {RESULTS[record.state]}</strong>
        <p>{record.target} · {new Date(record.createdAt * 1000).toLocaleString()}</p><p>{record.message}</p>
        {record.canRestore ? <button type="button" className="win-ir-btn" disabled={working || !available} onClick={() => void restore(record.id)}>预览恢复原配置</button> : null}
      </article>)}
      {!history.some((r) => r.kind === selection.kind) ? <p>尚无此类对象的操作记录。</p> : null}
    </div> : null}
  </WinIrModal>;
}
