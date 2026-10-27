import { useEffect, useRef, useState } from "react";
import { WINDOWS_BASELINE_CHANGE_IDS, type WindowsBaselineChangePlan, type WindowsBaselineChangeReport, type WindowsBaselineItem, type WindowsIncidentResponse, type WindowsRemoteIntent } from "../shared/windows-incident-contract";
import { CollectionWarnings, WinIrModal } from "./WinIrKit";
import { errorText } from "./error-text";

const STATE = { pending: "未执行", applying: "正在执行 / 结果待核实", verified: "配置回读通过", restored: "原值回读通过", refused: "状态变化，拒绝写入", uncertain: "结果不明，需人工复核", skipped: "未执行" } as const;
export function WinIrBaselineChanges({ items, initialIds, session, currentSession, onRequest, onClose, onRefresh }: {
  items: readonly WindowsBaselineItem[]; initialIds: readonly string[]; session: string; currentSession: string | null;
  onRequest: (intent: WindowsRemoteIntent, session: string, label?: string) => Promise<WindowsIncidentResponse>; onClose: () => void; onRefresh: () => void;
}) {
  const [selected, setSelected] = useState(new Set(initialIds));
  const [plan, setPlan] = useState<WindowsBaselineChangePlan | null>(null);
  const [report, setReport] = useState<WindowsBaselineChangeReport | null>(null);
  const [history, setHistory] = useState<WindowsBaselineChangeReport[] | null>(null);
  const [working, setWorking] = useState(false);
  const [applying, setApplying] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const live = useRef(true);
  const workingRef = useRef(false);
  const planRegion = useRef<HTMLDivElement>(null);
  const available = session === currentSession;
  const eligible = items.filter((item) => (WINDOWS_BASELINE_CHANGE_IDS as readonly string[]).includes(item.id) && item.status === "fail");
  useEffect(() => { live.current = true; return () => { live.current = false; }; }, []);
  useEffect(() => { if (plan) planRegion.current?.focus({ preventScroll: true }); }, [plan?.id]);
  useEffect(() => {
    if (!applying || !plan || !available) return;
    let stopped = false;
    const poll = async () => {
      try { const response = await onRequest({ action: "baseline-plan-progress", planId: plan.id }, session); if (!stopped && response.kind === "baseline-progress" && response.report) setReport(response.report); }
      catch { /* The main request keeps its own failure visible. */ }
      if (!stopped) timer = window.setTimeout(() => void poll(), 1000);
    };
    let timer = window.setTimeout(() => void poll(), 1000);
    return () => { stopped = true; window.clearTimeout(timer); };
  }, [applying, available, onRequest, plan, session]);
  async function request(intent: WindowsRemoteIntent, label: string) {
    if (workingRef.current) return null;
    workingRef.current = true; setWorking(true); setError(null);
    try { return await onRequest(intent, session, label); }
    catch (reason) { if (live.current) setError(errorText(reason, "操作未完成，请核对连接、权限和配置历史。")); return null; }
    finally { workingRef.current = false; if (live.current) setWorking(false); }
  }
  async function preview(recordId?: string) {
    const response = await request(recordId ? { action: "plan-baseline-restore", recordId } : { action: "plan-baseline", ruleIds: [...selected] }, "正在读取原值与权限，生成固定配置计划…");
    if (response?.kind === "baseline-plan") { setPlan(response.plan); setReport(null); setHistory(null); }
  }
  async function apply() {
    if (!plan || workingRef.current || working || !available) return;
    setApplying(true); setStopping(false);
    const response = await request({ action: "apply-baseline-plan", planId: plan.id }, `正在备份、配置并逐项复核 ${plan.items.length} 项策略…`);
    if (response?.kind === "baseline-change") setReport(response.report);
    setApplying(false); setPlan(null);
    // A failed transport may have left writes behind; refresh is an explicit follow-up.
  }
  async function close() {
    if (workingRef.current || working) { setError("请先中止后续项，并等待当前请求返回；断连或关闭不能保证远程写入已停止。"); return; }
    if (plan && available) { try { await onRequest({ action: "discard-baseline-plan", planId: plan.id }, session); } catch { /* Unused plans also expire in core. */ } }
    onClose();
  }
  async function cancel() {
    if (!plan) return;
    try { const response = await onRequest({ action: "cancel-baseline-plan", planId: plan.id }, session); if (response.kind === "baseline-acknowledged" && response.accepted) setStopping(true); else setError("当前任务尚未进入可取消阶段或已经结束，请等待当前请求返回后核对结果。"); }
    catch (reason) { setError(errorText(reason, "未能送达中止请求，不能确认远程写入已停止。")); }
  }
  return <WinIrModal wide title={plan?.restoring ? "恢复基线配置：确认具体差异" : "一键配置 Windows 基线"} subtitle="勾选配置 → 预览差异与影响 → 确认执行 → 查看逐项复核与恢复记录" onClose={() => void close()} actions={<>
    <button type="button" className="win-ir-btn" disabled={working} onClick={() => void close()}>关闭</button>
    {!plan && !working ? <button type="button" className="win-ir-btn" disabled={!available} onClick={() => void request({ action: "baseline-history" }, "正在读取配置历史…").then((response) => { if (response?.kind === "baseline-history") setHistory(response.records); })}>配置历史 / 恢复</button> : null}
    {applying ? <button type="button" className="win-ir-btn" disabled={stopping || !available} onClick={() => void cancel()}>{stopping ? "等待当前项结束…" : "中止后续项"}</button> : plan ? <button type="button" className="win-ir-btn is-primary" disabled={working || !available || !plan.items.length || plan.expiresAt * 1000 <= Date.now()} onClick={() => void apply()}>确认{plan.restoring ? "恢复" : "配置"}这 {plan.items.length} 项并复核</button> : !report && !history ? <button type="button" className="win-ir-btn is-primary" disabled={working || !available || !selected.size} onClick={() => void preview()}>预览 {selected.size} 项配置</button> : null}
    {report && !working ? <button type="button" className="win-ir-btn is-primary" disabled={!available} onClick={() => { onClose(); onRefresh(); }}>重新核查完整基线</button> : null}
  </>}>
    {!available ? <p role="alert" className="wir-context-note">会话已变化，本窗口的计划与执行入口已失效。历史反馈仍保留，请重新连接后核对目标。</p> : null}
    <CollectionWarnings inline announce source="基线配置" summary="操作未完成 · 查看原因" severity="error" warnings={error ? [error] : []} />
    {working ? <p role="status">{applying ? report?.message ?? "正在检查原状态并持久保存备份…" : "正在读取，请稍候…"}</p> : null}
    {plan ? <div ref={planRegion} className="wir-baseline-plan" tabIndex={0} role="region" aria-label="配置差异与影响"><p>目标：<strong>{plan.target}</strong> · 有效至 {new Date(plan.expiresAt * 1000).toLocaleTimeString()}</p>
      <ul>{plan.notes.map((note) => <li key={note}>{note}</li>)}</ul>
      {!plan.items.length ? <p role="status">所选值已经符合目标，无需修改。</p> : plan.items.map((item) => <article key={item.id}><strong>{item.title}</strong><code>{item.location}</code><p>{item.currentValue} → <b>{item.expectedValue}</b></p><p>{item.impact}</p></article>)}
    </div> : null}
    {report ? <div className="wir-baseline-report"><p>{report.message}</p><p>目标：{report.target} · {new Date(report.createdAt * 1000).toLocaleString()}</p><ul>{report.items.map((item) => <li key={item.id}><strong>{item.title}</strong><span>{STATE[item.state]}</span></li>)}</ul></div> : null}
    {history ? <div className="wir-baseline-history"><p>本机最多保留 100 次配置记录；其他主机记录仅供查看，恢复时会重新核对主机、账户、配置及权限。</p>{history.length ? history.map((record) => <article key={record.id}><strong>{record.target} · {new Date(record.createdAt * 1000).toLocaleString()}</strong><p>{record.finished ? record.message : "上次执行未记录结束，结果尚未核实。请先读取当前配置。"}</p><p>{record.items.map((item) => `${item.title}：${STATE[item.state]}`).join("；")}</p>{record.recoveryAvailable && !record.restoring ? <button type="button" className="win-ir-btn" disabled={working || !available} onClick={() => void preview(record.id)}>预览恢复差异</button> : null}</article>) : <p>暂无本机配置记录。</p>}</div> : null}
    {!plan && !report && !history ? <div className="wir-baseline-selection"><p>配置功能仍属实验性，请先在测试主机验证。当前支持 19 项注册表策略，列出本次检查中不通过的可配置项。其他检查仍需按建议处理。自动配置目前限非域成员的本机管理员会话，不会自动提权。</p>
      <div className="wir-toolbar"><button type="button" className="win-ir-btn" disabled={working} onClick={() => setSelected(new Set(eligible.map((item) => item.id)))}>选择全部可配置项（{eligible.length}）</button><button type="button" className="win-ir-btn" disabled={working} onClick={() => setSelected(new Set())}>清空选择</button></div>
      {eligible.length ? eligible.map((item) => <label key={item.id}><input type="checkbox" disabled={working} checked={selected.has(item.id)} onChange={(event) => { const checked = event.currentTarget.checked; setSelected((before) => { const next = new Set(before); if (checked) next.add(item.id); else next.delete(item.id); return next; }); }} /><span><strong>{item.title}</strong><small>{item.currentValue} → {item.expectedValue}</small></span></label>) : <p>本次结果没有不通过的可配置项。可查看历史，或关闭后重新核查基线。</p>}
    </div> : null}
  </WinIrModal>;
}
