import { useEffect, useRef, useState } from "react";
import type { WindowsNetworkEntry, WindowsProcessEntry, WindowsProcessInspection, WindowsRiskLevel } from "../shared/windows-incident-contract";
import { CollectionWarnings, RiskBadge, SearchBox } from "./WinIrKit";
import { endpoint, formatBytes, matchesQuery, processKey } from "./win-ir-helpers";

export type LinkKind = "network" | "services" | "modules";

type LinkRow = { id: string; name: string; state: string; detail: string; path: string; risk?: WindowsRiskLevel };

export interface ProcessInspectionState {
  inspection: WindowsProcessInspection | null;
  loading: boolean;
  error: string;
  canRead: boolean;
  read: () => Promise<void>;
}

/** Reads the network, services and modules of one process, checked by PID and start time; late answers are dropped. */
export function useProcessInspection(process: WindowsProcessEntry | null, snapshot: object | null, busy: boolean, connected: boolean,
  onInspect: (pid: number, startTime: string) => Promise<WindowsProcessInspection>): ProcessInspectionState {
  const identity = process ? processKey(process) : null;
  const [result, setResult] = useState<{ identity: string; inspection: WindowsProcessInspection } | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const request = useRef(0);
  useEffect(() => {
    request.current++; setResult(null); setError(""); setLoading(false);
    return () => { request.current++; };
  }, [identity, snapshot, connected]);
  const canRead = process !== null && !busy && !loading && connected && process.startTime !== "";
  async function read() {
    if (!canRead || process === null || identity === null) return;
    const id = ++request.current; setLoading(true); setError("");
    try { const inspection = await onInspect(process.pid, process.startTime); if (request.current === id) setResult({ identity, inspection }); }
    catch (reason) { if (request.current === id) setError(reason instanceof Error ? reason.message : "进程关联读取失败，请重试。"); }
    finally { if (request.current === id) setLoading(false); }
  }
  return { inspection: result?.identity === identity ? result.inspection : null, loading, error, canRead, read };
}

const LIMIT = 300;
const KIND_LABEL: Record<LinkKind, string> = { network: "网络连接", services: "承载服务", modules: "已加载 DLL" };

function networkRows(entries: readonly WindowsNetworkEntry[]): LinkRow[] {
  return entries.map((n, i) => ({ id: String(i), name: `${n.protocol} ${endpoint(n.localAddress, n.localPort)}`, state: n.state || "无连接状态", detail: `远端 ${endpoint(n.remoteAddress, n.remotePort)}${n.riskReason ? ` · ${n.riskReason}` : ""}`, path: "", risk: n.riskLevel }));
}

/** One kind of related records for the selected process, inside its detail pane. */
export function WinIrProcessLinks({ kind, process, state, snapshotNetwork, onFile, onCopy }: {
  kind: LinkKind; process: WindowsProcessEntry; state: ProcessInspectionState;
  /** Connections of this PID in the network snapshot, or null before it is collected. */
  snapshotNetwork: readonly WindowsNetworkEntry[] | null;
  onFile: (path: string) => void; onCopy: (text: string) => void;
}) {
  const [query, setQuery] = useState("");
  const { inspection, loading, error, canRead, read } = state;
  const fromSnapshot = inspection === null && kind === "network" && snapshotNetwork !== null;
  const rows: LinkRow[] = inspection === null ? (fromSnapshot ? networkRows(snapshotNetwork) : [])
    : kind === "network" ? networkRows(inspection.network)
      : kind === "services" ? inspection.services.map((s, i) => ({ id: String(i), name: `${s.name} · ${s.displayName}`, state: `${s.state} / ${s.startMode}`, detail: `${s.account} · ${s.path}`, path: "" }))
        : inspection.modules.map((m, i) => ({ id: String(i), name: m.name, state: formatBytes(m.sizeBytes), detail: m.path, path: m.path }));
  const visible = rows.filter((r) => matchesQuery(query, r.name, r.state, r.detail));
  return <div className="wir-link-pane">
    <div className="wir-link-head">
      <p>{inspection ? `读取于 ${inspection.observedAt} · 账户 ${inspection.user || "未取得"}`
        : fromSnapshot ? "来自网络连接快照，只按 PID 对应。读取后按 PID 与启动时间核对同一进程。"
          : `按 PID 与启动时间核对同一进程后，读取${KIND_LABEL[kind]}。`}</p>
      <button type="button" className="win-ir-btn is-primary" disabled={!canRead} onClick={() => void read()}>{loading ? <><span className="win-ir-spinner" />正在核对…</> : inspection ? "刷新关联信息" : "读取网络 / 服务 / DLL"}</button>
    </div>
    {!process.startTime ? <p className="wir-footnote">缺少启动时间，不能可靠核对进程身份，请刷新或检查读取权限。</p> : null}
    {error ? <p className="wir-preview-error" role="alert">{error}</p> : null}
    <CollectionWarnings warnings={inspection?.warnings ?? []} />
    {rows.length > 0 ? <SearchBox value={query} onChange={setQuery} placeholder={`筛选${KIND_LABEL[kind]}`} /> : null}
    {visible.length > 0 ? <ul className="wir-link-list" aria-label={`${process.name} 的${KIND_LABEL[kind]}`}>
      {visible.slice(0, LIMIT).map((r) => <li key={r.id}>
        <div className="wir-link-title">{r.risk && r.risk !== "normal" ? <RiskBadge level={r.risk} /> : null}<strong className="is-mono" title={r.name}>{r.name}</strong><small>{r.state}</small></div>
        <p className="is-mono">{r.detail}</p>
        <div className="wir-link-actions">
          <button type="button" className="wir-link" onClick={() => onCopy(`${r.name}\n${r.state}\n${r.detail}`)}>复制</button>
          {r.path ? <button type="button" className="wir-link" onClick={() => onFile(r.path)}>在文件排查中打开 ↗</button> : null}
        </div>
      </li>)}
    </ul> : <div className="wir-empty">{rows.length > 0 ? "没有符合筛选的记录。"
      : inspection ? "本次没有返回记录，请同时核对采集缺口。"
        : kind === "network" ? "尚未采集网络连接快照。点击读取，核对后查看这个进程的连接。"
          : `点击读取，查看这个进程的${KIND_LABEL[kind]}。`}</div>}
    {visible.length > LIMIT ? <p className="wir-footnote">共 {visible.length} 条，仅显示前 {LIMIT} 条，请输入筛选条件缩小范围。</p> : null}
    {fromSnapshot ? <p className="wir-footnote">网络快照与进程快照不是同时采集，PID 可能已被复用。</p> : null}
    <details className="wir-collection-warnings"><summary>关联与判读范围</summary><p>读取前后核对进程启动时间；各数据仍不是原子快照。服务按报告的进程编号对应，DLL 来自系统模块枚举，不包含隐藏或手工映射模块。路径、外连或模块数量本身不能证明恶意或安全。</p></details>
  </div>;
}
