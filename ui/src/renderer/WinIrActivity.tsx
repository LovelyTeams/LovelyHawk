import { useEffect, useMemo, useRef, useState } from "react";

import type { WindowsNetworkEntry, WindowsNetworkSnapshot, WindowsProcessEntry, WindowsProcessInspection, WindowsProcessesSnapshot } from "../shared/windows-incident-contract";
import { DataTable, DetailPane, DetailTabs, FilterChips, RiskBadge, RiskCell, SearchBox, SourceTime, StatStrip, riskChipOptions, riskSort, type Column } from "./WinIrKit";
import { buildProcessTree, endpoint, isPublicAddress, matchesQuery, processAncestors, processChildren, processKey, resolveParent, riskCounts, type ProcessTreeRow, type RiskFilter } from "./win-ir-helpers";
import { WinIrProcessLinks, useProcessInspection, type LinkKind } from "./WinIrProcessLinks";
import { WinIrRelated, type RelatedContext } from "./WinIrRelated";
import { RELATED_ID } from "./win-ir-links";
import { networkKey, type FocusTarget, type InvestigationFocus } from "./win-ir-model";

type DetailTab = "overview" | "lineage" | LinkKind | "related";
type ProcessTarget = Extract<FocusTarget, { tab: "processes" }>;
type NetworkTarget = Extract<FocusTarget, { tab: "network" }>;

const TREE_PAGE_SIZE = 2000;
const SPLIT_HIDDEN: ReadonlySet<string> = new Set(["user", "start", "memory"]);
const PROTECTED_PROCESSES: ReadonlySet<string> = new Set([
  "system", "idle", "registry", "smss.exe", "csrss.exe", "wininit.exe",
  "services.exe", "lsass.exe", "winlogon.exe", "fontdrvhost.exe", "dwm.exe",
]);

function canKillProcess(process: WindowsProcessEntry): boolean {
  return process.pid > 4 && process.startTime !== "" && !PROTECTED_PROCESSES.has(process.name.toLowerCase());
}

function PpidCell({ row }: { row: ProcessTreeRow }) {
  const { process, link } = row;
  if (link.gap === "exited") return <span className="wir-ppid is-gap" title="父进程不在当前快照中，可能已退出">{process.ppid}<small>已退出</small></span>;
  if (link.gap === "reused") return <span className="wir-ppid is-gap" title="该 PID 当前对应的进程晚于本进程启动，PID 已被复用，不是真实父进程">{process.ppid}<small>已复用</small></span>;
  if (link.parent === null) return <span className="wir-ppid wir-muted">{process.ppid}</span>;
  return <span className={`wir-ppid${link.verified ? "" : " is-unverified"}`} title={link.verified ? `父进程 ${link.parent.name}` : `父进程 ${link.parent.name}；缺少启动时间，未核实父子关系`}>{process.ppid}</span>;
}

function Lineage({ current, processes, onReveal }: { current: WindowsProcessEntry; processes: readonly WindowsProcessEntry[]; onReveal: (process: WindowsProcessEntry) => void }) {
  const byPid = new Map(processes.map((process) => [process.pid, process]));
  const chain = [...processAncestors(current.pid, processes)].reverse();
  const top = chain[0] ?? current;
  const gap = resolveParent(top, byPid).gap;
  const children = processChildren(current.pid, processes);
  const unverified = (process: WindowsProcessEntry) => {
    const link = resolveParent(process, byPid);
    return link.parent !== null && !link.verified ? <span className="wir-tag is-caution" title="缺少启动时间，未核实与上一级的父子关系">关系未核实</span> : null;
  };
  return <div className="wir-lineage">
    <h4>启动链（自上而下）</h4>
    {gap === "exited" ? <p className="wir-footnote">父进程 PID {top.ppid} 不在当前快照中，可能已退出，启动链只能追溯到这里。</p> : null}
    {gap === "reused" ? <p className="wir-footnote">PID {top.ppid} 当前对应的进程晚于 {top.name} 启动，是被复用的 PID，不是真实父进程；真实父进程已退出。</p> : null}
    <ol className="wir-chain">
      {chain.map((process) => <li key={processKey(process)}>
        <button type="button" className="wir-link" onClick={() => onReveal(process)}>{process.name} <span className="is-mono">({process.pid})</span></button>
        {process.riskLevel !== "normal" ? <RiskBadge level={process.riskLevel} /> : null}{unverified(process)}
      </li>)}
      <li aria-current="true"><strong>{current.name}</strong> <span className="is-mono">({current.pid})</span><span className="wir-tag is-accent">当前</span>{unverified(current)}</li>
    </ol>
    <h4>直接子进程 · {children.length}</h4>
    {children.length ? <ul className="wir-chain is-children">{children.map((process) => <li key={processKey(process)}>
      <button type="button" className="wir-link" onClick={() => onReveal(process)}>{process.name} <span className="is-mono">({process.pid})</span></button>
      {process.riskLevel !== "normal" ? <RiskBadge level={process.riskLevel} /> : null}
    </li>)}</ul> : <p className="wir-footnote">当前快照中没有子进程。</p>}
    <p className="wir-footnote">父子关系来自当前快照，并以启动时间排除被复用的 PID；已退出的进程无法从快照中还原。</p>
  </div>;
}

export function WinIrProcesses({ snapshot, network, focus, related, onCopy, onFile, onNetwork, busy, connected, onInspect, onKill }: {
  snapshot: WindowsProcessesSnapshot | null; network: WindowsNetworkSnapshot | null; focus: InvestigationFocus<ProcessTarget> | null;
  related?: RelatedContext;
  busy: boolean; connected: boolean; onInspect: (pid: number, startTime: string) => Promise<WindowsProcessInspection>;
  onCopy: (text: string) => void; onFile: (path: string) => void; onNetwork: (pid: number) => void;
  onKill?: (process: WindowsProcessEntry) => void;
}) {
  const [query, setQueryValue] = useState("");
  const [risk, setRiskValue] = useState<RiskFilter>("all");
  const [view, setView] = useState<"tree" | "list">("tree");
  const [collapsed, setCollapsed] = useState<ReadonlySet<number>>(new Set());
  const [selected, setSelected] = useState<string | null>(null);
  /** A process shown outside the current filter because the user went to it. */
  const [pinned, setPinned] = useState<number | null>(null);
  const [missing, setMissing] = useState<number | null>(null);
  const [tab, setTab] = useState<DetailTab>("overview");
  const handledFocus = useRef<number | null>(null);
  const processes = useMemo(() => snapshot?.processes ?? [], [snapshot]);
  const tree = useMemo(() => buildProcessTree(processes), [processes]);
  const isTree = view === "tree";
  const setQuery = (value: string) => { setQueryValue(value); setPinned(null); };
  const setRisk = (value: RiskFilter) => { setRiskValue(value); setPinned(null); };
  const matchesFilter = (process: WindowsProcessEntry) => (risk === "all" || process.riskLevel === risk) &&
    matchesQuery(query, process.pid, process.ppid, process.name, process.executablePath, process.commandLine, process.user);
  const filtering = query.trim() !== "" || risk !== "all";

  function reveal(target: WindowsProcessEntry) {
    const ancestors = processAncestors(target.pid, processes);
    setCollapsed((before) => {
      if (!ancestors.some((parent) => before.has(parent.pid))) return before;
      const after = new Set(before);
      for (const parent of ancestors) after.delete(parent.pid);
      return after;
    });
    setPinned(target.pid);
    setMissing(null);
    setSelected(processKey(target));
  }
  useEffect(() => {
    if (!focus || !snapshot || handledFocus.current === focus.request) return;
    handledFocus.current = focus.request;
    setQueryValue(""); setRiskValue("all"); setTab("overview");
    const { pid, startTime } = focus.target;
    const target = processes.find((process) => process.pid === pid && (startTime === undefined || process.startTime === startTime));
    if (target) reveal(target);
    else { setSelected(null); setPinned(null); setMissing(pid); }
    // reveal only reads the current snapshot.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focus, snapshot]);

  const counts = useMemo(() => riskCounts(processes, (entry) => entry.riskLevel), [processes]);
  const { visible, context } = useMemo(() => {
    const matched = new Set(processes.filter((process) => process.pid === pinned || matchesFilter(process)).map((process) => process.pid));
    if (!isTree) return { visible: tree.filter((row) => matched.has(row.process.pid)), context: new Set<number>() };
    // Matches keep their ancestors so the start chain stays readable.
    const included = new Set<number>();
    const path: number[] = [];
    for (const row of tree) {
      path.length = row.depth;
      path.push(row.process.pid);
      if (matched.has(row.process.pid)) for (const pid of path) included.add(pid);
    }
    let hiddenBelow: number | null = null;
    const rows = tree.filter((row) => {
      if (hiddenBelow !== null && row.depth > hiddenBelow) return false;
      hiddenBelow = null;
      if (!included.has(row.process.pid)) return false;
      if (collapsed.has(row.process.pid)) hiddenBelow = row.depth;
      return true;
    });
    return { visible: rows, context: filtering ? new Set([...included].filter((pid) => !matched.has(pid))) : new Set<number>() };
    // matchesFilter reads query and risk.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [collapsed, filtering, pinned, processes, query, risk, tree, isTree]);

  const current = processes.find((process) => processKey(process) === selected);
  const pinnedProcess = pinned === null ? undefined : processes.find((process) => process.pid === pinned);
  const inspection = useProcessInspection(current ?? null, snapshot, busy, connected, onInspect);
  const snapshotNetwork: WindowsNetworkEntry[] | null = current && network ? network.connections.filter((entry) => entry.pid === current.pid) : null;

  function toggle(row: ProcessTreeRow) {
    const pid = row.process.pid;
    const collapsing = !collapsed.has(pid);
    setCollapsed((before) => {
      const after = new Set(before);
      if (after.has(pid)) after.delete(pid); else after.add(pid);
      return after;
    });
    if (collapsing && current && processAncestors(current.pid, processes).some((parent) => parent.pid === pid)) setSelected(processKey(row.process));
  }
  const collapseWhere = (predicate: (row: ProcessTreeRow) => boolean) => setCollapsed(new Set(tree.filter((row) => row.hasChildren && predicate(row)).map((row) => row.process.pid)));
  const expandToRisk = () => {
    setView("tree"); setQueryValue(""); setRiskValue("all"); setPinned(null);
    collapseWhere((row) => row.descendantRisk.high + row.descendantRisk.medium === 0);
  };
  const onRowKey = isTree ? (key: string, row: ProcessTreeRow) => {
    const isCollapsed = collapsed.has(row.process.pid);
    if (key === "ArrowLeft") {
      if (row.hasChildren && !isCollapsed) { toggle(row); return true; }
      const parent = row.link.parent;
      if (parent && visible.some((candidate) => candidate.process === parent)) { setSelected(processKey(parent)); return true; }
    } else if (key === "ArrowRight" && row.hasChildren) {
      if (isCollapsed) { toggle(row); return true; }
      const next = visible[visible.indexOf(row) + 1];
      if (next && next.depth > row.depth) { setSelected(processKey(next.process)); return true; }
    }
    return false;
  } : undefined;

  const sortable = <V,>(value: (row: ProcessTreeRow) => V) => (isTree ? undefined : value);
  const split = current !== undefined;
  const columns: Column<ProcessTreeRow>[] = [
    { key: "pid", label: "PID", width: "78px", mono: true, sort: sortable((row) => row.process.pid), render: ({ process }) => process.pid },
    { key: "ppid", label: "PPID", width: "104px", mono: true, sort: sortable((row) => row.process.ppid), render: (row) => <PpidCell row={row} /> },
    { key: "name", label: "进程名称", width: split ? "34%" : "25%", sort: sortable((row) => row.process.name), render: (row) => {
      const { process, depth, hasChildren, childCount, descendantRisk } = row;
      const isCollapsed = collapsed.has(process.pid);
      return <span className="wir-process-name" style={isTree ? { paddingInlineStart: Math.min(depth, 12) * 14 } : undefined}>
        {isTree ? (hasChildren
          ? <button type="button" className="wir-tree-toggle" aria-label={`${isCollapsed ? "展开" : "折叠"} ${process.name} 的子进程`} aria-expanded={!isCollapsed} onClick={(event) => { event.stopPropagation(); toggle(row); }}>{isCollapsed ? "›" : "⌄"}</button>
          : <span className="wir-tree-spacer" aria-hidden="true" />) : null}
        <strong title={process.name}>{process.name}</strong>
        {isTree && isCollapsed ? <span className="wir-tag">子进程 {childCount}</span> : null}
        {isTree && isCollapsed && descendantRisk.high ? <span className="wir-tag is-danger">含 {descendantRisk.high} 个高危</span> : null}
        {isTree && isCollapsed && descendantRisk.medium ? <span className="wir-tag is-caution">含 {descendantRisk.medium} 个中危</span> : null}
      </span>;
    } },
    { key: "user", label: "用户", width: "13%", sort: sortable((row) => row.process.user), render: ({ process }) => <span className="wir-clip" title={process.user}>{process.user || "未取得"}</span> },
    { key: "start", label: "启动时间", width: "196px", sort: sortable((row) => row.process.startTime), render: ({ process }) => <SourceTime value={process.startTime} /> },
    { key: "memory", label: "内存", width: "84px", sort: sortable((row) => row.process.workingSetMb), render: ({ process }) => `${process.workingSetMb.toLocaleString()} MB` },
    { key: "path", label: "执行路径", mono: true, render: ({ process }) => <span className="wir-clip" title={process.executablePath}>{process.executablePath || "未取得 / 受保护"}</span> },
    { key: "risk", label: "风险", width: "84px", sort: isTree ? undefined : riskSort((row) => row.process.riskLevel), render: ({ process }) => <RiskCell level={process.riskLevel} /> },
  ];
  // With the detail pane open, fields it already shows leave the table.
  const hiddenColumns = split ? SPLIT_HIDDEN : undefined;

  const ancestors = current ? processAncestors(current.pid, processes) : [];
  const fields = current ? [
    { label: "执行路径", value: current.executablePath || "未取得 / 受保护", mono: true },
    { label: "命令行", value: current.commandLine || "未取得", mono: true },
    { label: "运行账户", value: current.user || "未取得" },
    { label: "启动时间", value: current.startTime || "未取得", mono: true },
    { label: "内存 / 会话", value: `${current.workingSetMb} MB · 会话 ${current.sessionId}` },
  ] : [];
  const copyText = current ? [
    `${current.name} · PID ${current.pid} · PPID ${current.ppid}`,
    ...fields.map((field) => `${field.label}：${field.value}`),
    ...current.riskReasons.map((reason) => `风险：${reason}`),
    `父进程链：${ancestors.length ? ancestors.map((parent) => `${parent.name}(${parent.pid})`).join(" ← ") : "当前快照中没有可核实的父进程"}`,
  ].join("\n") : "";

  return (
    <div className="wir-module">
      <StatStrip cards={[
        { label: "已取得进程", value: snapshot?.totalCount ?? "—" },
        { label: "高危线索", value: snapshot ? counts.high : "—", tone: "high", onClick: () => setRisk("high") },
        { label: "需关注进程", value: snapshot?.suspiciousCount ?? "—", tone: "medium", hint: "高危与中危，点击在进程树中展开", onClick: expandToRisk },
        { label: "可见进程内存合计", value: snapshot ? `${(processes.reduce((sum, process) => sum + process.workingSetMb, 0) / 1024).toFixed(1)} GB` : "—", hint: "共享内存可能重复计入" },
      ]} />
      <div className="wir-toolbar">
        <SearchBox value={query} onChange={setQuery} placeholder="搜索进程、PID、命令行、路径或用户" />
        <FilterChips label="进程视图" value={view} onChange={setView} options={[{ value: "tree", label: "进程树" }, { value: "list", label: "平铺列表" }]} />
      </div>
      <div className="wir-toolbar">
        <FilterChips label="进程风险" value={risk} onChange={setRisk} options={riskChipOptions(counts)} />
        {isTree ? <div className="wir-tree-actions" role="group" aria-label="进程树展开">
          <button type="button" className="win-ir-btn" onClick={() => setCollapsed(new Set())}>全部展开</button>
          <button type="button" className="win-ir-btn" onClick={() => collapseWhere(() => true)}>全部折叠</button>
          <button type="button" className="win-ir-btn" onClick={expandToRisk}>只展开到风险进程</button>
        </div> : null}
      </div>
      {missing !== null ? <p className="wir-footnote" role="status">当前进程快照中没有 PID {missing}，进程可能已退出或快照较旧，请刷新进程后再查找。</p> : null}
      {pinnedProcess && filtering && !matchesFilter(pinnedProcess) ? <p className="wir-footnote">已临时显示 {pinnedProcess.name}（PID {pinnedProcess.pid}），它不符合当前筛选；修改筛选后恢复。</p> : null}
      {isTree && filtering ? <p className="wir-footnote">进程树保留匹配记录的父进程（淡色显示），便于对照启动链。</p> : null}
      <div className={`wir-master wir-process-master${split ? " is-split" : ""}`}>
        <div className="wir-process-table">
          <DataTable key={view} label="进程分析" columns={columns} hiddenColumns={hiddenColumns} rows={visible} rowKey={({ process }) => processKey(process)} selectedKey={selected}
            onSelect={(row) => setSelected(row ? processKey(row.process) : null)} rowRisk={({ process }) => process.riskLevel}
            rowClass={({ process }) => (context.has(process.pid) ? "is-context" : "")} onRowKey={onRowKey}
            keyHint={isTree ? "↑↓ 切换 · ←→ 折叠/展开" : "↑↓ 切换"} pageSize={isTree ? TREE_PAGE_SIZE : undefined}
            defaultSort={isTree ? undefined : { key: "risk", descending: true }}
            empty={snapshot ? "当前进程快照中没有符合筛选的记录。" : "点击「刷新进程」，读取进程路径、命令行与父子关系。"} />
        </div>
        {current ? <DetailPane className="wir-process-detail" title={current.name} subtitle={`PID ${current.pid} · PPID ${current.ppid}`} risk={current.riskLevel}
          reasons={tab === "overview" ? current.riskReasons : []} onClose={() => setSelected(null)} onCopy={onCopy} copyText={copyText}
          fields={tab === "overview" ? fields : []}
          tabs={<DetailTabs label="进程详情" value={tab} onChange={setTab} options={[
            { value: "overview", label: "概况" },
            { value: "lineage", label: "进程链" },
            { value: "network", label: "网络", count: inspection.inspection?.network.length ?? snapshotNetwork?.length },
            { value: "services", label: "服务", count: inspection.inspection?.services.length },
            { value: "modules", label: "DLL", count: inspection.inspection?.modules.length },
            ...(related ? [{ value: "related" as const, label: "关联" }] : []),
          ]} />}
          actions={<>
            <button type="button" className="win-ir-btn" onClick={() => onNetwork(current.pid)}>在网络连接中查看 ↗</button>
            {current.executablePath ? <button type="button" className="win-ir-btn" onClick={() => onFile(current.executablePath)}>在文件排查中打开 ↗</button> : null}
            {onKill ? (
              <button
                type="button"
                className="win-ir-btn is-danger"
                disabled={busy || !connected || !canKillProcess(current)}
                title={!canKillProcess(current) ? "系统核心进程或缺少启动时间，不能直接终止" : undefined}
                onClick={() => onKill(current)}
              >
                结束进程
              </button>
            ) : null}
          </>}>
          {tab === "lineage" ? <Lineage current={current} processes={processes} onReveal={reveal} /> : null}
          {tab === "network" || tab === "services" || tab === "modules"
            ? <WinIrProcessLinks key={`${processKey(current)}:${tab}`} kind={tab} process={current} state={inspection} snapshotNetwork={snapshotNetwork} onFile={onFile} onCopy={onCopy} />
            : null}
          {tab === "related" && related ? <WinIrRelated key={processKey(current)} context={related}
            query={{ paths: [current.executablePath], accounts: [current.user], pid: current.pid, exclude: RELATED_ID.process(current) }} /> : null}
        </DetailPane> : null}
      </div>
      <p className="wir-footnote">父子关系来自当前快照：父进程晚于子进程启动时视为 PID 被复用，不再挂接；已退出的父进程无法还原。无法读取的路径和命令行保持未知，风险标记只作为调查线索。</p>
    </div>
  );
}

export function WinIrNetwork({ snapshot, processes, focus, related, busy = false, connected = false, onCopy, onProcess, onFile, onKillProcess }: {
  snapshot: WindowsNetworkSnapshot | null; processes?: WindowsProcessesSnapshot | null;
  focus: InvestigationFocus<NetworkTarget> | null; related?: RelatedContext;
  busy?: boolean; connected?: boolean;
  onCopy: (text: string) => void; onProcess: (pid: number) => void; onFile: (path: string) => void;
  onKillProcess?: (process: WindowsProcessEntry) => void;
}) {
  const [query, setQuery] = useState("");
  const [scope, setScope] = useState("all");
  const [risk, setRisk] = useState<RiskFilter>("all");
  const [pid, setPid] = useState<number | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [missing, setMissing] = useState(false);
  const handledFocus = useRef<number | null>(null);
  const entries = useMemo(() => (snapshot?.connections ?? []).map((entry, index) => ({ ...entry, rowId: `${networkKey(entry)}#${index}` })), [snapshot]);
  useEffect(() => {
    if (!focus || !snapshot || handledFocus.current === focus.request) return;
    handledFocus.current = focus.request;
    setPid(focus.target.pid ?? null); setScope("all"); setRisk("all"); setQuery("");
    const target = focus.target.key === undefined ? undefined : entries.find((entry) => networkKey(entry) === focus.target.key);
    setSelected(target?.rowId ?? null);
    setMissing(focus.target.key !== undefined && target === undefined);
  }, [entries, focus, snapshot]);
  const listening = (entry: WindowsNetworkEntry) => /^listen/iu.test(entry.state);
  const established = (entry: WindowsNetworkEntry) => /^established$/iu.test(entry.state);
  const external = (entry: WindowsNetworkEntry) => isPublicAddress(entry.remoteAddress);
  const visible = entries.filter((entry) =>
    (pid === null || pid === entry.pid) && (risk === "all" || risk === entry.riskLevel) &&
    (scope === "all" || (scope === "listen" && listening(entry)) || (scope === "established" && established(entry)) ||
      (scope === "public" && external(entry)) || (scope === "udp" && entry.protocol.toUpperCase().startsWith("UDP"))) &&
    matchesQuery(query, entry.localAddress, entry.localPort, entry.remoteAddress, entry.remotePort, entry.pid, entry.processName, entry.processPath));
  const current = entries.find((entry) => entry.rowId === selected);
  const columns: Column<WindowsNetworkEntry & { rowId: string }>[] = [
    { key: "state", label: "状态 / 协议", width: "130px", sort: (entry) => entry.state, render: (entry) => <div className="wir-cell-stack"><span className={`wir-connection-state${established(entry) ? " is-active" : ""}`}>{entry.state || "无连接状态"}</span><small>{entry.protocol}</small></div> },
    { key: "local", label: "本地端点", width: "22%", mono: true, sort: (entry) => entry.localPort, render: (entry) => <span className="wir-clip" title={endpoint(entry.localAddress, entry.localPort)}>{endpoint(entry.localAddress, entry.localPort)}</span> },
    { key: "remote", label: "远端地址", width: "24%", mono: true, sort: (entry) => entry.remoteAddress, render: (entry) => <div className="wir-cell-stack"><span className="wir-clip" title={endpoint(entry.remoteAddress, entry.remotePort)}>{endpoint(entry.remoteAddress, entry.remotePort)}</span>{external(entry) ? <small className="wir-accent">公网地址</small> : null}</div> },
    { key: "process", label: "所属进程", sort: (entry) => entry.processName, render: (entry) => <div className="wir-cell-stack"><strong>{entry.processName || "未取得进程名"}</strong><small className="is-mono">PID {entry.pid}</small></div> },
    { key: "risk", label: "风险", width: "85px", sort: riskSort((entry) => entry.riskLevel), render: (entry) => <RiskCell level={entry.riskLevel} /> },
  ];
  return (
    <div className="wir-module">
      <StatStrip cards={[
        { label: "网络记录", value: snapshot?.totalCount ?? "—" },
        { label: "监听端点", value: snapshot ? entries.filter(listening).length : "—", onClick: () => setScope("listen") },
        { label: "已建立连接", value: snapshot ? entries.filter(established).length : "—", tone: "normal", onClick: () => setScope("established") },
        { label: "公网远端", value: snapshot ? entries.filter(external).length : "—", hint: "公网通信不等于恶意", tone: "low", onClick: () => setScope("public") },
      ]} />
      <div className="wir-toolbar">
        <SearchBox value={query} onChange={setQuery} placeholder="搜索地址、端口、进程名称或 PID" />
        {pid !== null ? <button type="button" className="wir-chip is-accent" onClick={() => setPid(null)} aria-label={`取消 PID ${pid} 筛选`}>仅 PID {pid} ×</button> : null}
        <select className="win-ir-input wir-select" value={scope} aria-label="连接范围" onChange={(event) => setScope(event.target.value)}>
          <option value="all">全部连接</option><option value="listen">监听端点</option><option value="established">已建立</option><option value="public">公网远端</option><option value="udp">UDP</option>
        </select>
      </div>
      <FilterChips label="网络风险" value={risk} onChange={setRisk} options={riskChipOptions(riskCounts(entries, (entry) => entry.riskLevel))} />
      {missing ? <p className="wir-footnote" role="status">当前网络快照中没有要定位的连接，连接可能已关闭或快照较旧，请刷新连接后再查找。</p> : null}
      <div className={`wir-master${current ? " is-split" : ""}`}>
        <DataTable label="网络连接" columns={columns} rows={visible} rowKey={(entry) => entry.rowId} selectedKey={selected} onSelect={(entry) => setSelected(entry?.rowId ?? null)} rowRisk={(entry) => entry.riskLevel} defaultSort={{ key: "risk", descending: true }} empty={snapshot ? "没有符合条件的网络记录。" : "刷新连接后，查看监听端点、远端地址和所属进程。"} />
        {current ? <DetailPane title={current.processName || `PID ${current.pid}`} subtitle={`${current.protocol} · ${current.state}`} risk={current.riskLevel} reasons={current.riskReason ? [current.riskReason] : []} onClose={() => setSelected(null)} onCopy={onCopy} fields={[
          { label: "本地端点", value: endpoint(current.localAddress, current.localPort), mono: true },
          { label: "远端地址", value: endpoint(current.remoteAddress, current.remotePort), mono: true },
          { label: "地址范围", value: external(current) ? "公网地址（不能据此判断恶意）" : "非公网地址 / 未指定" },
          { label: "进程 PID", value: String(current.pid), mono: true },
          { label: "进程路径", value: current.processPath || "未取得", mono: true },
        ]} actions={<>
          <button type="button" className="win-ir-btn" onClick={() => onProcess(current.pid)}>在进程分析中查看 ↗</button>
          {current.processPath ? <button type="button" className="win-ir-btn" onClick={() => onFile(current.processPath)}>在文件排查中打开 ↗</button> : null}
          {(() => {
            const owner = onKillProcess ? processes?.processes.find((process) => process.pid === current.pid) : undefined;
            return owner ? (
              <button
                type="button"
                className="win-ir-btn is-danger"
                disabled={busy || !connected || !canKillProcess(owner)}
                title={!canKillProcess(owner) ? "系统核心进程或缺少启动时间，不能直接终止" : undefined}
                onClick={() => onKillProcess!(owner)}
              >
                结束所属进程
              </button>
            ) : null;
          })()}
        </>}>
          {related ? <WinIrRelated key={current.rowId} context={related}
            query={{ addresses: [current.remoteAddress], paths: [current.processPath], pid: current.pid, exclude: RELATED_ID.network(current) }} /> : null}
        </DetailPane> : null}
      </div>
      <p className="wir-footnote">这是采集时的连接快照，不含历史流量。进程对应应与同一时段的进程快照核对；未取得的进程名保持未知。</p>
    </div>
  );
}
