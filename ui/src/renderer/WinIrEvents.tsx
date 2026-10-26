import { useMemo, useState } from "react";

import type { WindowsEventLogEntry, WindowsLogsSnapshot, WindowsRiskLevel } from "../shared/windows-incident-contract";
import { CollectionWarnings, DataTable, DetailPane, FilterChips, RiskBadge, RiskCell, SearchBox, SourceTime, StatStrip, riskChipOptions, riskSort, useFocusRequest, type Column } from "./WinIrKit";
import { matchesQuery, riskCounts, toCsv, type RiskFilter } from "./win-ir-helpers";
import { moduleLabel, type CollectionTab, type FocusTarget, type InvestigationFocus, type WinIrSnapshots } from "./win-ir-model";

/** A sortable moment for a source time; unreadable times sort last when newest comes first. */
function timeValue(value: string): number {
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? -Infinity : parsed;
}

export const LOG_CATEGORIES = [
  { value: "all", label: "核心事件" },
  { value: "logon", label: "登录审计" },
  { value: "account", label: "账户变更" },
  { value: "service", label: "服务与系统" },
  { value: "powershell", label: "PowerShell · 4103 / 4104" },
  { value: "failed-logon", label: "登录失败 / 账户锁定" },
  { value: "rdp", label: "远程桌面登录 / 重连" },
  { value: "defender", label: "Defender 告警 / 配置变更" },
  { value: "tasks", label: "计划任务创建 / 执行" },
  { value: "sysmon", label: "Sysmon 进程 / 网络 / 注入线索" },
  { value: "clear-log", label: "日志清除 · 104 / 1102" },
  { value: "process", label: "进程创建 / 退出 · 4688 / 4689" },
  { value: "wmi", label: "WMI 活动" },
  { value: "security", label: "Security 最近事件" },
  { value: "system", label: "System 最近事件" },
  { value: "application", label: "Application 最近事件" },
] as const;

export function WinIrLogs({ snapshot, busy, category, onCategory, focus, onCopy, onDirectory }: {
  snapshot: WindowsLogsSnapshot | null; busy: boolean; category: string; onCategory: (category: string) => void;
  focus: InvestigationFocus<Extract<FocusTarget, { tab: "logs" }>> | null; onCopy: (text: string) => void; onDirectory?: (path: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [risk, setRisk] = useState<RiskFilter>("all");
  const [eventId, setEventId] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [missing, setMissing] = useState(false);
  const entries = useMemo(() => (snapshot?.entries ?? []).map((entry, index) => ({ ...entry, rowId: `${entry.channel}:${entry.recordId}:${index}` })), [snapshot]);
  useFocusRequest(focus, snapshot !== null || focus?.target.recordId === undefined, (target) => {
    setRisk("all"); setEventId(""); setQuery(target.query ?? "");
    const found = target.recordId === undefined ? undefined : entries.find((entry) => entry.recordId === target.recordId && (target.channel === undefined || entry.channel === target.channel));
    setSelected(found?.rowId ?? null);
    setMissing(target.recordId !== undefined && found === undefined);
  });
  const visible = entries.filter((entry) => (risk === "all" || risk === entry.riskLevel) &&
    (!eventId || eventId.split(/[,，\s]+/u).includes(String(entry.eventId))) && matchesQuery(query, entry.summary, entry.detail, entry.channel, entry.category, entry.eventId));
  const current = entries.find((entry) => entry.rowId === selected);
  const columns: Column<WindowsEventLogEntry & { rowId: string }>[] = [
    { key: "time", label: "时间", width: "196px", mono: true, sort: (entry) => timeValue(entry.timeCreated), render: (entry) => <SourceTime value={entry.timeCreated} /> },
    { key: "event", label: "事件 ID", width: "105px", sort: (entry) => entry.eventId, render: (entry) => <span className="wir-event-id">{entry.eventId}</span> },
    { key: "summary", label: "事件摘要", render: (entry) => <div className="wir-cell-stack"><strong className="wir-clip" title={entry.summary}>{entry.summary || entry.category}</strong><small className="wir-clip">{entry.channel}</small></div> },
    { key: "risk", label: "风险", width: "90px", sort: riskSort((entry) => entry.riskLevel), render: (entry) => <RiskCell level={entry.riskLevel} /> },
  ];
  return (
    <div className="wir-module wir-logs-layout">
      <aside className="wir-log-rail" aria-label="快速查询与常见日志位置">
        <p className="wir-log-rail-title">快速查询</p>
        <nav className="wir-log-presets" aria-label="日志快速查询">{LOG_CATEGORIES.map((preset) => <button type="button" aria-pressed={category === preset.value} disabled={busy} key={preset.value} title={preset.label} onClick={() => { setEventId(""); setQuery(""); setRisk("all"); onCategory(preset.value); }}>{preset.label}</button>)}</nav>
        <p className="wir-footnote">查询最近 7 天，每个通道最多 200 条。快速查询在远程日志服务中筛选；右侧搜索与事件 ID 只筛选已返回记录。</p>
        <p className="wir-log-rail-title">常见日志位置</p>
        <nav className="wir-log-presets is-locations" aria-label="常见日志文件目录">{[
          ["EVTX 日志目录", "%SystemRoot%\\System32\\winevt\\Logs"], ["IIS 访问日志", "%SystemDrive%\\inetpub\\logs\\LogFiles"],
          ["HTTP 错误日志", "%SystemRoot%\\System32\\LogFiles\\HTTPERR"], ["防火墙日志", "%SystemRoot%\\System32\\LogFiles\\Firewall"],
          ["PowerShell 命令历史", "%APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine"], ["系统安装日志", "%SystemRoot%\\Panther"],
        ].map(([label, path]) => <button key={path} type="button" disabled={busy || !onDirectory} title={`在文件排查中打开 ${path}`} onClick={() => onDirectory?.(path!)}>{label} <span aria-hidden="true">↗</span></button>)}</nav>
      </aside>
      <div className="wir-log-main">
        <p className="wir-query-scope">远端查询：{LOG_CATEGORIES.find((preset) => preset.value === category)?.label ?? category} · 最近 7 天 · 每通道最多 200 条。下方搜索仅筛选已返回记录。</p>
        <StatStrip cards={[
          { label: "已返回事件", value: snapshot?.totalCount ?? "—", hint: "最近事件样本，非全部历史" },
          { label: "高危线索", value: snapshot?.highRiskCount ?? "—", tone: "high", onClick: () => setRisk("high") },
          { label: "登录失败 4625", value: snapshot ? entries.filter((entry) => entry.channel.toLowerCase() === "security" && entry.eventId === 4625).length : "—", tone: "medium", onClick: () => setEventId("4625") },
          { label: "日志清除 104 / 1102", value: snapshot ? entries.filter((entry) => (entry.channel.toLowerCase() === "system" && entry.eventId === 104) || (entry.channel.toLowerCase() === "security" && entry.eventId === 1102)).length : "—", tone: "high" },
        ]} />
        <div className="wir-toolbar">
          <SearchBox value={query} onChange={setQuery} placeholder="在已返回事件中搜索内容、账户或地址" />
          <input className="win-ir-input wir-event-filter" type="text" inputMode="numeric" value={eventId} aria-label="事件 ID 筛选" placeholder="事件 ID" onChange={(event) => setEventId(event.target.value.replace(/[^\d,， ]/gu, ""))} />
          <button type="button" className="win-ir-btn" disabled={!visible.length} onClick={() => onCopy(toCsv(
            ["时间", "通道", "记录 ID", "事件 ID", "分类", "摘要", "详情"],
            visible.map((entry) => [entry.timeCreated, entry.channel, String(entry.recordId), String(entry.eventId), entry.category, entry.summary, entry.detail]),
          ))}>复制 CSV</button>
        </div>
        <FilterChips label="事件风险" value={risk} onChange={setRisk} options={riskChipOptions(riskCounts(entries, (entry) => entry.riskLevel))} />
        <CollectionWarnings warnings={snapshot?.warnings ?? []} />
        {missing ? <p className="wir-footnote" role="status">当前返回的事件中没有要定位的记录，可能不在本次日志类别或已超出采集上限，请切换类别或重新读取。</p> : null}
        <div className={`wir-master${current ? " is-split" : ""}`}>
          <DataTable label="事件日志" columns={columns} rows={visible} rowKey={(entry) => entry.rowId} selectedKey={selected} onSelect={(entry) => setSelected(entry?.rowId ?? null)} rowRisk={(entry) => entry.riskLevel} defaultSort={{ key: "time", descending: true }} empty={snapshot ? "当前采集范围中没有符合筛选的事件；请同时核对权限与审计配置。" : "选择日志类别后读取近期关键事件。"} />
          {current ? <DetailPane title={current.summary || `事件 ${current.eventId}`} subtitle={`${current.channel} · ${current.eventId}`} risk={current.riskLevel} onClose={() => setSelected(null)} onCopy={onCopy} fields={[
            { label: "事件时间（原始值）", value: current.timeCreated, mono: true },
            { label: "记录 ID", value: String(current.recordId), mono: true },
            { label: "事件级别 / 类别", value: `${current.level} · ${current.category}` },
            { label: current.detailTruncated ? "事件详情（仅前 2048 字符）" : "返回的事件详情", value: current.detail, mono: true },
          ]} /> : null}
        </div>
        <p className="wir-footnote">事件数量受采集端上限、权限和日志保留影响。没有返回某类事件不能证明其没有发生；需要完整日志时应另行保全原始 EVTX。</p>
      </div>
    </div>
  );
}

export interface TimelineEntry {
  id: string;
  time: string;
  /** The moment the source time denotes, with its offset applied; NaN when unreadable. */
  epoch: number;
  title: string;
  source: CollectionTab;
  sourceLabel: string;
  detail: string;
  risk: WindowsRiskLevel;
  target: FocusTarget;
  /** Executable of a process start, used to fold routine system starts. */
  path?: string;
}

/** Observed timestamps only; never assign a scan time to an undated artifact. */
export function buildWindowsTimeline(snapshots: Partial<WinIrSnapshots>): TimelineEntry[] {
  const rows: TimelineEntry[] = [];
  const push = (row: Omit<TimelineEntry, "epoch">) => rows.push({ ...row, epoch: Date.parse(row.time) });
  for (const [index, entry] of (snapshots.logs?.entries ?? []).entries()) {
    push({ id: `log:${entry.channel}:${entry.recordId}:${index}`, time: entry.timeCreated, title: `${entry.eventId} · ${entry.summary}`, source: "logs", sourceLabel: "事件日志", detail: `${entry.channel}\n${entry.detail}`, risk: entry.riskLevel, target: { tab: "logs", channel: entry.channel, recordId: entry.recordId } });
  }
  for (const entry of snapshots.processes?.processes ?? []) {
    push({ id: `process:${entry.pid}:${entry.startTime}`, time: entry.startTime, title: `进程启动 · ${entry.name}`, source: "processes", sourceLabel: "进程启动", detail: `PID ${entry.pid} / 父 PID ${entry.ppid}\n${entry.executablePath}\n${entry.commandLine}`, risk: entry.riskLevel, target: { tab: "processes", pid: entry.pid, startTime: entry.startTime }, path: entry.executablePath });
  }
  for (const entry of snapshots.files?.entries ?? []) {
    push({ id: `file:${entry.fullPath}`, time: entry.lastWriteTime, title: `修改 · ${entry.name}`, source: "files", sourceLabel: "文件修改", detail: `${entry.fullPath}${entry.sha256 ? `\nSHA256 ${entry.sha256}` : ""}`, risk: entry.riskLevel, target: { tab: "files", path: entry.fullPath } });
  }
  for (const entry of snapshots.accounts?.accounts ?? []) {
    push({ id: `account:${entry.sid || entry.name}`, time: entry.lastLogon, title: `最近登录 · ${entry.name}`, source: "accounts", sourceLabel: "账户登录", detail: `${entry.name}\n${entry.sid}`, risk: entry.riskLevel, target: { tab: "accounts", sid: entry.sid, name: entry.name } });
  }
  return rows.filter((entry) => /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/u.test(entry.time));
}

const AROUND_MS = 10 * 60 * 1000;
const SYSTEM_DIRECTORY = /^[a-z]:\\windows\\/iu;

/** A routine start: an unmarked process run from the Windows directory. */
export function isRoutineSystemStart(entry: TimelineEntry): boolean {
  return entry.source === "processes" && entry.risk === "normal" && SYSTEM_DIRECTORY.test(entry.path ?? "");
}

export function WinIrTimeline({ snapshots, onCopy, onGo }: {
  snapshots: Partial<WinIrSnapshots>; onCopy: (text: string) => void; onGo: (target: FocusTarget) => void;
}) {
  const [query, setQuery] = useState("");
  const [risk, setRisk] = useState<RiskFilter>("all");
  const [source, setSource] = useState("all");
  const [after, setAfter] = useState("");
  const [before, setBefore] = useState("");
  const [around, setAround] = useState<{ epoch: number; label: string } | null>(null);
  const [hideRoutine, setHideRoutine] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const rows = useMemo(() => buildWindowsTimeline(snapshots), [snapshots]);
  const filtered = rows.filter((entry) => (source === "all" || source === entry.source) && (risk === "all" || risk === entry.risk) &&
    (!after || entry.time.slice(0, 10) >= after) && (!before || entry.time.slice(0, 10) <= before) && matchesQuery(query, entry.title, entry.detail) &&
    (around === null || (!Number.isNaN(entry.epoch) && Math.abs(entry.epoch - around.epoch) <= AROUND_MS)));
  const visible = hideRoutine ? filtered.filter((entry) => !isRoutineSystemStart(entry)) : filtered;
  const hidden = filtered.length - visible.length;
  const current = rows.find((entry) => entry.id === selected);
  const columns: Column<TimelineEntry>[] = [
    { key: "time", label: "观察时间", width: "196px", mono: true, sort: (entry) => (Number.isNaN(entry.epoch) ? -Infinity : entry.epoch), render: (entry) => <SourceTime value={entry.time} /> },
    { key: "source", label: "来源", width: "110px", sort: (entry) => entry.sourceLabel, render: (entry) => <span className="wir-tag">{entry.sourceLabel}</span> },
    { key: "event", label: "活动与线索", render: (entry) => <div className="wir-cell-stack"><strong>{entry.title}</strong><small className="wir-clip" title={entry.detail}>{entry.detail.split("\n")[0]}</small></div> },
    { key: "risk", label: "风险", width: "90px", sort: riskSort((entry) => entry.risk), render: (entry) => <RiskCell level={entry.risk} /> },
  ];
  return (
    <div className="wir-module">
      <StatStrip cards={[
        { label: "带时间的记录", value: rows.length },
        { label: "数据来源", value: new Set(rows.map((entry) => entry.source)).size },
        { label: "高危线索", value: rows.filter((entry) => entry.risk === "high").length, tone: "high", onClick: () => setRisk("high") },
      ]} />
      <div className="wir-toolbar">
        <SearchBox value={query} onChange={setQuery} placeholder="搜索活动、路径、命令或账户" />
        <select aria-label="时间线来源" className="win-ir-input wir-select" value={source} onChange={(event) => setSource(event.target.value)}>
          <option value="all">全部来源</option><option value="logs">事件日志</option><option value="processes">进程启动</option><option value="files">文件修改</option><option value="accounts">账户登录</option>
        </select>
        <label className="wir-date-filter">从<input type="date" aria-label="起始日期" value={after} onChange={(event) => setAfter(event.target.value)} /></label>
        <label className="wir-date-filter">至<input type="date" aria-label="结束日期" value={before} onChange={(event) => setBefore(event.target.value)} /></label>
        <button type="button" className="win-ir-btn" disabled={!visible.length} onClick={() => onCopy(toCsv(["时间", "来源", "活动", "详情"], visible.map((entry) => [entry.time, entry.sourceLabel, entry.title, entry.detail])))}>复制 CSV</button>
      </div>
      <div className="wir-toolbar">
        <FilterChips label="时间线风险" value={risk} onChange={setRisk} options={riskChipOptions(riskCounts(rows, (entry) => entry.risk))} />
        {around ? <button type="button" className="wir-chip is-accent" aria-label={`取消围绕 ${around.label} 的时间范围`} onClick={() => setAround(null)}>围绕 {around.label} ±10 分钟 ×</button> : null}
        <label className="wir-toggle"><input type="checkbox" checked={hideRoutine} onChange={(event) => setHideRoutine(event.target.checked)} />隐藏 Windows 目录中未标记的进程启动{hideRoutine ? ` · 已隐藏 ${hidden} 条` : ""}</label>
      </div>
      <div className={`wir-master${current ? " is-split" : ""}`}>
        <DataTable label="调查时间线" rows={visible} columns={columns} rowKey={(entry) => entry.id} selectedKey={selected} onSelect={(entry) => setSelected(entry?.id ?? null)} rowRisk={(entry) => entry.risk} defaultSort={{ key: "time", descending: true }} empty={rows.length ? "没有符合日期或筛选条件的记录。" : "先采集进程、账户、事件日志或浏览目录，带时间的记录会在这里汇总。"} />
        {current ? <DetailPane title={current.title} subtitle={current.sourceLabel} risk={current.risk} onClose={() => setSelected(null)} onCopy={onCopy} fields={[
          { label: "原始时间", value: current.time, mono: true },
          { label: "来源记录", value: current.detail, mono: true },
        ]} actions={<>
          {!Number.isNaN(current.epoch) ? <button type="button" className="win-ir-btn" onClick={() => setAround({ epoch: current.epoch, label: current.time })}>查看前后 10 分钟</button> : null}
          <button type="button" className="win-ir-btn" onClick={() => onGo(current.target)}>在{moduleLabel(current.target.tab)}中定位 ↗</button>
        </>} /> : null}
      </div>
      <p className="wir-footnote">仅汇总本次会话已采集且有明确时间的记录，文件范围是当前目录。排序已换算各记录自带的时区偏移，但各来源的时钟偏差尚未校正；先后相邻不表示因果关系。</p>
    </div>
  );
}
