import { useEffect, useRef, useState } from "react";
import type { WindowsIncidentResponse, WindowsProcessEntry, WindowsProcessPlan, WindowsProcessChangeReport, WindowsRemoteIntent } from "../shared/windows-incident-contract";
import { WinIrModal } from "./WinIrKit";
import { errorText } from "./error-text";

const LABELS = { verified: "已核实退出", refused: "检查未通过，未执行", failed: "终止失败", skipped: "未执行", uncertain: "结果待核实" };
export function WinIrProcessChange({ process, tree, session, currentSession, onRequest, onClose, onRefresh, onResult }: {
  process: WindowsProcessEntry; tree: boolean; session: string; currentSession: string | null;
  onRequest: (request: WindowsRemoteIntent, session: string, label?: string) => Promise<WindowsIncidentResponse>;
  onClose: () => void; onRefresh: () => void; onResult: (message: string, failed: boolean) => void;
}) {
  const [plan, setPlan] = useState<WindowsProcessPlan | null>(null);
  const [report, setReport] = useState<WindowsProcessChangeReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [working, setWorking] = useState(false);
  const [attempted, setAttempted] = useState(false);
  const [clock, setClock] = useState(Date.now);
  const lock = useRef(false);
  const planRegion = useRef<HTMLDivElement>(null);
  useEffect(() => { if (plan) planRegion.current?.focus({preventScroll:true}); }, [plan]);
  const live = useRef(true);
  const available = currentSession === session;
  useEffect(() => { live.current = true; const timer = setInterval(() => setClock(Date.now()), 1000); return () => { live.current = false; clearInterval(timer); }; }, []);
  async function preview() {
    if (lock.current || !available) return;
    lock.current = true; setWorking(true); setError(null); setPlan(null);
    try {
      const response = await onRequest({ action: "plan-process-change", pid: process.pid, startTime: process.startTime, tree }, session, "正在核对进程及影响范围…");
      if (live.current && response.kind === "process-plan") setPlan(response.plan);
    } catch (reason) { if (live.current) setError(errorText(reason, "未能读取完整进程范围，请刷新后重试。")); }
    finally { lock.current = false; if (live.current) setWorking(false); }
  }
  async function apply() {
    if (lock.current || !available || !plan || attempted || plan.expiresAt * 1000 <= Date.now()) return;
    lock.current = true; setWorking(true); setAttempted(true); setError(null);
    try {
      const response = await onRequest({ action: "apply-process-plan", planId: plan.id }, session, "正在核对身份、结束进程并验证退出…");
      if (response.kind !== "process-change" || response.report.items.length !== plan.items.length || response.report.items.some((item, i) => item.pid !== plan.items[i]?.pid)) throw new Error("处置返回范围不一致，请重新采集核对。");
      if (live.current) {
        setReport(response.report);
        onResult(response.report.message, response.report.items.some((item) => item.state !== "verified"));
      }
    } catch (reason) {
      if (live.current) { const message = errorText(reason, "未取得处置结果，请重新采集核对，不能确认进程已经结束。"); setError(message); onResult(message, true); }
    } finally { lock.current = false; if (live.current) setWorking(false); }
  }
  async function close() {
    if (lock.current) return;
    lock.current = true; setWorking(true);
    if (plan && !attempted && available) { try { await onRequest({ action: "discard-process-plan", planId: plan.id }, session); } catch { /* Unused plans expire after two minutes. */ } }
    onClose();
  }
  return <WinIrModal wide title={tree ? "结束进程树" : "结束进程"} subtitle={`${process.name} · PID ${process.pid} · 先预览范围，再确认执行`} onClose={() => void close()} actions={<>
    <button type="button" className="win-ir-btn" disabled={working} onClick={() => void close()}>关闭</button>
    {!plan && !attempted ? <button type="button" className="win-ir-btn is-primary" disabled={working || !available} onClick={() => void preview()}>预览影响范围</button> : null}
    {plan && !attempted ? <button type="button" className="win-ir-btn is-danger" disabled={working || !available || plan.expiresAt * 1000 <= clock} onClick={() => void apply()}>确认结束这 {plan.items.length} 个进程</button> : null}
    {attempted && !working ? <button type="button" className="win-ir-btn" disabled={!available} onClick={() => { onClose(); onRefresh(); }}>刷新进程并复查</button> : null}
  </>}>
    <p className="wir-reader-warning">强制结束会丢失未保存的数据，并可能中断服务。没有备份，无法恢复进程运行状态；请先留存所需证据。不会自动提权或绕过系统保护。</p>
    <p>{tree ? "读取当前根进程及全部可核实的后代（最多 64 个），从最深层子进程开始结束。确认期间范围或身份变化会拒绝执行。" : "仅结束选中的进程，不结束其子进程。"}执行期间新建或自动拉起的进程需另外复查。</p>
    {!available ? <p role="alert">连接已变化，当前计划失效，请关闭后重新核对目标。</p> : null}
    {working ? <p role="status">{attempted ? "正在执行并核对退出状态，请等待结果…" : "正在只读预览影响范围…"}</p> : null}
    {error ? <p className="wir-reader-warning" role="alert">{error}</p> : null}
    {plan ? <div ref={planRegion} className="wir-baseline-plan" tabIndex={0} role="region" aria-label="完整进程范围">
      <p>目标：<strong>{plan.target}</strong> · 共 {plan.items.length} 个 · 有效至 {new Date(plan.expiresAt * 1000).toLocaleTimeString()}</p>
      {plan.expiresAt * 1000 <= clock && !attempted ? <p role="alert">预览已过期，请关闭并重新读取。</p> : null}
      {plan.items.map((item, i) => <article key={item.pid}><strong>{i === 0 ? "根进程 · " : "子进程 · "}{item.name}</strong><p>PID {item.pid} · PPID {item.ppid} · 启动于 {item.startTime}</p>{report ? <p>{LABELS[report.items[i]!.state]}</p> : null}</article>)}
    </div> : null}
    {report ? <p role="status">{report.message}</p> : null}
  </WinIrModal>;
}
