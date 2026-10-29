import { useEffect, useMemo, useRef, useState } from "react";

import type {
  WindowsCommandEntry,
  WindowsCommandMonitorSnapshot,
  WindowsDefenderConfigChange,
  WindowsDefenderDetection,
  WindowsDefenderExclusion,
  WindowsDefenderSnapshot,
  WindowsEventLogEntry,
  WindowsLogsSnapshot,
  WindowsRiskLevel,
  WindowsWebshellEntry,
  WindowsWebshellSnapshot,
} from "../shared/windows-incident-contract";
import { CollectionWarnings, DataTable, DetailPane, FilterChips, RiskBadge, RiskCell, SearchBox, SourceTime, StatStrip, riskChipOptions, riskSort, useFocusRequest, type Column } from "./WinIrKit";
import { formatBytes, matchesQuery, riskCounts, toCsv, type RiskFilter } from "./win-ir-helpers";
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
        <CollectionWarnings source="事件日志" warnings={snapshot?.warnings ?? []} />
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

const WEBSHELL_PRESETS = [
  { label: "自动探测 Web 目录", path: "auto" },
  { label: "IIS 默认站点", path: "C:\\inetpub\\wwwroot" },
  { label: "PHPStudy WWW", path: "C:\\phpstudy_pro\\WWW" },
  { label: "XAMPP htdocs", path: "C:\\xampp\\htdocs" },
  { label: "宝塔 / wwwroot", path: "C:\\wwwroot" },
  { label: "公共可写目录", path: "C:\\Users\\Public" },
  { label: "当前用户 Temp", path: "%TEMP%" },
] as const;

export function WinIrWebshell({ snapshot, busy, connected, onScan, onCopy, onFile, onPull }: {
  snapshot: WindowsWebshellSnapshot | null; busy: boolean; connected: boolean;
  onScan: (path: string) => void; onCopy: (text: string) => void;
  onFile: (path: string) => void; onPull: (path: string) => void;
}) {
  const [targetPath, setTargetPath] = useState(snapshot?.scannedPaths[0] ?? "auto");
  const [query, setQuery] = useState("");
  const [risk, setRisk] = useState<RiskFilter>("all");
  const [selected, setSelected] = useState<string | null>(null);
  const entries = snapshot?.entries ?? [];
  const visible = entries.filter((entry) =>
    (risk === "all" || entry.riskLevel === risk) &&
    matchesQuery(query, entry.name, entry.fullPath, entry.threatType, entry.sha256, entry.lineSnippet, ...entry.matchedRules));
  const current = entries.find((entry) => entry.fullPath === selected);
  const columns: Column<WindowsWebshellEntry>[] = [
    { key: "name", label: "可疑文件 / 路径", width: "30%", sort: (entry) => entry.name, render: (entry) => <div className="wir-cell-stack"><strong className="wir-clip" title={entry.name}>{entry.name}</strong><small className="wir-clip" title={entry.fullPath}>{entry.fullPath}</small></div> },
    { key: "threat", label: "检测类型 (D盾规则)", width: "24%", sort: (entry) => entry.threatType, render: (entry) => <div className="wir-cell-stack"><strong>{entry.threatType}</strong><small className="wir-clip" title={entry.lineSnippet}>{entry.lineSnippet}</small></div> },
    { key: "level", label: "置信度", width: "90px", sort: (entry) => entry.confidenceLevel, render: (entry) => <span className="wir-tag is-accent">级别 {entry.confidenceLevel}</span> },
    { key: "time", label: "修改时间", width: "175px", mono: true, sort: (entry) => entry.lastWriteTime, render: (entry) => <SourceTime value={entry.lastWriteTime} /> },
    { key: "risk", label: "风险", width: "85px", sort: riskSort((entry) => entry.riskLevel), render: (entry) => <RiskCell level={entry.riskLevel} /> },
  ];
  return (
    <div className="wir-module">
      <StatStrip cards={[
        { label: "已扫描脚本", value: snapshot?.scannedFiles ?? "—", hint: snapshot ? `遍历 ${snapshot.scannedDirs} 个子目录` : "支持多线程并行扫描" },
        { label: "高危木马 (级别 5)", value: snapshot?.highRiskCount ?? "—", tone: "high", onClick: () => setRisk("high") },
        { label: "可疑混淆 (级别 3-4)", value: snapshot?.mediumRiskCount ?? "—", tone: "medium", onClick: () => setRisk("medium") },
        { label: "引擎耗时 / 线程", value: snapshot ? `${snapshot.elapsedMs} ms` : "—", hint: snapshot ? `${snapshot.workerThreads} 个并发工作线程` : "Agent 原生线程池" },
      ]} />
      <CollectionWarnings source="Webshell 查杀" stamp={snapshot?.observedAt} warnings={[
        ...(snapshot?.warnings ?? []),
        ...(snapshot?.truncated ? ["扫描达到单次目录或文件数量上限，请针对具体站点子目录进一步深度查杀。"] : []),
      ]} />
      <form className="wir-toolbar" onSubmit={(event) => { event.preventDefault(); if (connected && !busy) onScan(targetPath.trim() || "auto"); }}>
        <input className="win-ir-input" value={targetPath} aria-label="Webshell 扫描路径" placeholder="输入站点目录路径（如 C:\inetpub\wwwroot，留空或 auto 自动探测常见站点目录）" onChange={(event) => setTargetPath(event.target.value)} />
        <button type="submit" className="win-ir-btn is-primary" disabled={busy || !connected}>多线程查杀目录</button>
      </form>
      <div className="wir-chips" role="group" aria-label="常见站点目录预设">
        {WEBSHELL_PRESETS.map((preset) => (
          <button key={preset.path} type="button" className="wir-chip" disabled={busy || !connected} aria-pressed={targetPath === preset.path} onClick={() => { setTargetPath(preset.path); onScan(preset.path); }}>
            {preset.label}
          </button>
        ))}
      </div>
      {snapshot?.scannedPaths.length ? <p className="wir-query-scope">本次扫描目录：{snapshot.scannedPaths.join(" ； ")}</p> : null}
      <div className="wir-toolbar">
        <SearchBox value={query} onChange={setQuery} placeholder="搜索文件名、路径、威胁类型、代码片段或 SHA256" />
        <FilterChips label="Webshell 风险" value={risk} onChange={setRisk} options={riskChipOptions(riskCounts(entries, (entry) => entry.riskLevel))} />
        <button type="button" className="win-ir-btn" disabled={!visible.length} onClick={() => onCopy(toCsv(
          ["文件路径", "威胁类型", "级别", "风险", "大小", "修改时间", "SHA256", "命中规则", "代码片段"],
          visible.map((entry) => [entry.fullPath, entry.threatType, String(entry.confidenceLevel), entry.riskLevel, String(entry.sizeBytes), entry.lastWriteTime, entry.sha256, entry.matchedRules.join(" | "), entry.lineSnippet]),
        ))}>复制 CSV</button>
      </div>
      <div className={`wir-master${current ? " is-split" : ""}`}>
        <DataTable label="Webshell 查杀结果" columns={columns} rows={visible} rowKey={(entry) => entry.fullPath} selectedKey={selected} onSelect={(entry) => setSelected(entry?.fullPath ?? null)} rowRisk={(entry) => entry.riskLevel} defaultSort={{ key: "risk", descending: true }} empty={snapshot ? "所扫目录内未检出已知 Webshell 或高危后门特征。" : "选择站点目录或点击「开始查杀」，使用多线程引擎扫描 PHP / ASP / ASP.NET / JSP / 脚本后门。"} />
        {current ? <DetailPane title={current.name} subtitle={`${current.threatType} · 级别 ${current.confidenceLevel}`} risk={current.riskLevel} reasons={current.matchedRules} onClose={() => setSelected(null)} onCopy={onCopy} fields={[
          { label: "完整文件路径", value: current.fullPath, mono: true },
          { label: "文件大小 / 扩展名", value: `${formatBytes(current.sizeBytes)} (${current.sizeBytes} 字节) · ${current.extension}` },
          { label: "最后修改时间", value: current.lastWriteTime, mono: true },
          { label: "SHA256", value: current.sha256 || "未计算", mono: true },
          { label: "命中代码特征行", value: current.lineSnippet || "—", mono: true },
        ]} actions={<>
          <button type="button" className="win-ir-btn is-primary" onClick={() => onFile(current.fullPath)}>在文件排查中打开并处置 ↗</button>
          <button type="button" className="win-ir-btn" disabled={busy || !connected} onClick={() => onPull(current.fullPath)}>取证拉取样本</button>
        </>} /> : null}
      </div>
    </div>
  );
}

type DefenderTab = "detections" | "exclusions" | "changes";

export function WinIrDefender({ snapshot, busy, connected, onCopy, onFile }: {
  snapshot: WindowsDefenderSnapshot | null; busy: boolean; connected: boolean;
  onCopy: (text: string) => void; onFile: (path: string) => void;
}) {
  const [tab, setTab] = useState<DefenderTab>("detections");
  const [query, setQuery] = useState("");
  const [risk, setRisk] = useState<RiskFilter>("all");
  const [selected, setSelected] = useState<string | null>(null);

  const detections = snapshot?.detections ?? [];
  const exclusions = snapshot?.exclusions ?? [];
  const changes = snapshot?.configChanges ?? [];

  const visibleDetections = detections.filter((d) =>
    (risk === "all" || d.riskLevel === risk) &&
    matchesQuery(query, d.threatName, d.filePath, d.processName, d.action, d.user, d.eventId, d.detail));
  const visibleExclusions = exclusions.filter((e) =>
    (risk === "all" || e.riskLevel === risk) &&
    matchesQuery(query, e.kind, e.value, e.source, e.riskReason));
  const visibleChanges = changes.filter((c) =>
    (risk === "all" || c.riskLevel === risk) &&
    matchesQuery(query, c.changeType, c.oldValue, c.newValue, c.eventId, c.detail));

  const currentDetection = tab === "detections" ? detections.find((d) => `${d.recordId}:${d.eventId}` === selected) : undefined;
  const currentExclusion = tab === "exclusions" ? exclusions.find((e) => `${e.kind}:${e.value}` === selected) : undefined;
  const currentChange = tab === "changes" ? changes.find((c) => `${c.recordId}:${c.eventId}` === selected) : undefined;
  const hasDetail = Boolean(currentDetection || currentExclusion || currentChange);

  const detectionColumns: Column<WindowsDefenderDetection>[] = [
    { key: "time", label: "时间", width: "180px", mono: true, sort: (d) => timeValue(d.timeCreated), render: (d) => <SourceTime value={d.timeCreated} /> },
    { key: "event", label: "事件", width: "85px", sort: (d) => d.eventId, render: (d) => <span className="wir-event-id">{d.eventId}</span> },
    { key: "threat", label: "威胁名称 / 受影响路径", width: "36%", sort: (d) => d.threatName, render: (d) => <div className="wir-cell-stack"><strong>{d.threatName}</strong><small className="wir-clip" title={d.filePath || d.detail}>{d.filePath || d.detail}</small></div> },
    { key: "action", label: "处置状态", width: "130px", sort: (d) => d.action, render: (d) => d.action },
    { key: "risk", label: "风险", width: "85px", sort: riskSort((d) => d.riskLevel), render: (d) => <RiskCell level={d.riskLevel} /> },
  ];

  const exclusionColumns: Column<WindowsDefenderExclusion>[] = [
    { key: "kind", label: "排除类型", width: "120px", sort: (e) => e.kind, render: (e) => <span className="wir-tag">{e.kind === "path" ? "路径排除" : e.kind === "process" ? "进程排除" : e.kind === "extension" ? "扩展名排除" : "IP 排除"}</span> },
    { key: "value", label: "排除目标值", mono: true, sort: (e) => e.value, render: (e) => <strong className="wir-clip" title={e.value}>{e.value}</strong> },
    { key: "source", label: "配置来源", width: "150px", sort: (e) => e.source, render: (e) => e.source },
    { key: "risk", label: "风险", width: "85px", sort: riskSort((e) => e.riskLevel), render: (e) => <RiskCell level={e.riskLevel} /> },
  ];

  const changeColumns: Column<WindowsDefenderConfigChange>[] = [
    { key: "time", label: "时间", width: "180px", mono: true, sort: (c) => timeValue(c.timeCreated), render: (c) => <SourceTime value={c.timeCreated} /> },
    { key: "event", label: "事件", width: "85px", sort: (c) => c.eventId, render: (c) => <span className="wir-event-id">{c.eventId}</span> },
    { key: "type", label: "变更类型", width: "210px", sort: (c) => c.changeType, render: (c) => <strong>{c.changeType}</strong> },
    { key: "diff", label: "变更内容 (旧值 → 新值)", mono: true, render: (c) => <span className="wir-clip" title={`${c.oldValue} -> ${c.newValue}`}>{c.newValue ? `${c.oldValue || "(空)"} → ${c.newValue}` : c.detail}</span> },
    { key: "risk", label: "风险", width: "85px", sort: riskSort((c) => c.riskLevel), render: (c) => <RiskCell level={c.riskLevel} /> },
  ];

  return (
    <div className="wir-module">
      <StatStrip cards={[
        { label: "运行模式", value: snapshot ? (snapshot.runningMode || "未取得") : "—", hint: snapshot?.engineVersion ? `引擎 ${snapshot.engineVersion}` : "Get-MpComputerStatus" },
        { label: "实时保护", value: snapshot ? (snapshot.realtimeProtection === true ? "开启" : snapshot.realtimeProtection === false ? "已关闭" : "未知") : "—", tone: snapshot?.realtimeProtection === false ? "high" : "normal" },
        { label: "威胁检出记录", value: snapshot ? detections.length : "—", tone: detections.length ? "high" : "normal", onClick: () => { setTab("detections"); setSelected(null); } },
        { label: "白名单排除项", value: snapshot ? exclusions.length : "—", tone: exclusions.length ? "medium" : "normal", onClick: () => { setTab("exclusions"); setSelected(null); } },
        { label: "配置篡改事件", value: snapshot ? changes.length : "—", tone: changes.length ? "high" : "normal", onClick: () => { setTab("changes"); setSelected(null); } },
        { label: "防篡改 / 签名时效", value: snapshot ? `${snapshot.tamperProtected ? "防篡改开启" : "防篡改未开"} · ${snapshot.signatureAgeDays ?? "?"} 天` : "—", hint: snapshot?.signatureVersion ? `签名 ${snapshot.signatureVersion}` : "病毒定义版本" },
      ]} />
      <CollectionWarnings source="Defender 解析" stamp={snapshot?.observedAt} warnings={snapshot?.warnings ?? []} />
      <div className="wir-toolbar">
        <FilterChips<DefenderTab> label="Defender 视图" value={tab} onChange={(next) => { setTab(next); setSelected(null); }} options={[
          { value: "detections", label: "威胁检出与处置 (1116-1119)", count: detections.length, tone: detections.length ? "high" : "info" },
          { value: "exclusions", label: "排除项白名单 (Exclusions)", count: exclusions.length, tone: exclusions.length ? "medium" : "info" },
          { value: "changes", label: "防护关闭与配置变更 (5001/5007/5013)", count: changes.length, tone: changes.length ? "high" : "info" },
        ]} />
        <SearchBox value={query} onChange={setQuery} placeholder="搜索威胁名称、文件路径、排除项或注册表变更值" />
      </div>
      <div className={`wir-master${hasDetail ? " is-split" : ""}`}>
        {tab === "detections" ? (
          <DataTable label="Defender 威胁检出" columns={detectionColumns} rows={visibleDetections} rowKey={(d) => `${d.recordId}:${d.eventId}`} selectedKey={selected} onSelect={(d) => setSelected(d ? `${d.recordId}:${d.eventId}` : null)} rowRisk={(d) => d.riskLevel} defaultSort={{ key: "time", descending: true }} empty={snapshot ? "最近 30 天内未读取到 Defender 威胁检出事件 (1116/1117/1118/1119)。" : "点击「解析 Defender」快速提取防病毒威胁日志、排除项与配置篡改记录。"} />
        ) : tab === "exclusions" ? (
          <DataTable label="Defender 排除项" columns={exclusionColumns} rows={visibleExclusions} rowKey={(e) => `${e.kind}:${e.value}`} selectedKey={selected} onSelect={(e) => setSelected(e ? `${e.kind}:${e.value}` : null)} rowRisk={(e) => e.riskLevel} defaultSort={{ key: "risk", descending: true }} empty={snapshot ? "未发现配置 Defender 路径、进程或扩展名排除项。" : "点击「解析 Defender」读取排除项配置。"} />
        ) : (
          <DataTable label="Defender 配置变更" columns={changeColumns} rows={visibleChanges} rowKey={(c) => `${c.recordId}:${c.eventId}`} selectedKey={selected} onSelect={(c) => setSelected(c ? `${c.recordId}:${c.eventId}` : null)} rowRisk={(c) => c.riskLevel} defaultSort={{ key: "time", descending: true }} empty={snapshot ? "最近 30 天内未读取到 Defender 实时保护关闭或配置变更事件 (5001/5007/5013)。" : "点击「解析 Defender」读取配置变更事件。"} />
        )}
        {currentDetection ? <DetailPane title={currentDetection.threatName} subtitle={`事件 ${currentDetection.eventId} · 记录 ${currentDetection.recordId}`} risk={currentDetection.riskLevel} onClose={() => setSelected(null)} onCopy={onCopy} fields={[
          { label: "检出时间", value: currentDetection.timeCreated, mono: true },
          { label: "处置状态 / 严重度", value: `${currentDetection.action} · ${currentDetection.severity} · ${currentDetection.category}` },
          { label: "受影响文件 / 路径", value: currentDetection.filePath || "未标明具体文件", mono: true },
          { label: "关联进程", value: currentDetection.processName || "—", mono: true },
          { label: "关联用户", value: currentDetection.user || "—" },
          { label: "原始事件详情", value: currentDetection.detail, mono: true },
        ]} actions={currentDetection.filePath && /^[a-zA-Z]:\\/u.test(currentDetection.filePath) ? (
          <button type="button" className="win-ir-btn is-primary" disabled={busy || !connected} onClick={() => onFile(currentDetection.filePath)}>在文件排查中打开 ↗</button>
        ) : undefined} /> : null}
        {currentExclusion ? <DetailPane title={currentExclusion.value} subtitle={`排除项 · ${currentExclusion.source}`} risk={currentExclusion.riskLevel} reasons={[currentExclusion.riskReason]} onClose={() => setSelected(null)} onCopy={onCopy} fields={[
          { label: "排除类型", value: currentExclusion.kind },
          { label: "排除目标", value: currentExclusion.value, mono: true },
          { label: "配置来源", value: currentExclusion.source },
        ]} actions={currentExclusion.kind === "path" && /^[a-zA-Z]:\\/u.test(currentExclusion.value) ? (
          <button type="button" className="win-ir-btn is-primary" disabled={busy || !connected} onClick={() => onFile(currentExclusion.value)}>在文件排查中打开目录 ↗</button>
        ) : undefined} /> : null}
        {currentChange ? <DetailPane title={currentChange.changeType} subtitle={`事件 ${currentChange.eventId} · 记录 ${currentChange.recordId}`} risk={currentChange.riskLevel} onClose={() => setSelected(null)} onCopy={onCopy} fields={[
          { label: "发生时间", value: currentChange.timeCreated, mono: true },
          { label: "变更前值 (Old Value)", value: currentChange.oldValue || "（空）", mono: true },
          { label: "变更后值 (New Value)", value: currentChange.newValue || "（空）", mono: true },
          { label: "完整事件消息", value: currentChange.detail, mono: true },
        ]} /> : null}
      </div>
      <p className="wir-footnote">结合 Get-MpComputerStatus、Get-MpPreference、注册表 Exclusions 策略及 Microsoft-Windows-Windows Defender/Operational 事件 XML 结构化解析。攻击者常在投放木马前添加目录/扩展名排除项（事件 5007）或关闭实时保护（事件 5001）。</p>
    </div>
  );
}

const COMMAND_SOURCE_LABELS: Readonly<Record<string, string>> = {
  "active-process": "实时进程",
  "security-4688": "Security 4688",
  "sysmon-1": "Sysmon Event 1",
  "powershell-4104": "PowerShell 4104",
  "psreadline-history": "PSReadLine 历史",
};

export function WinIrCommands({ snapshot, busy, connected, onCollect, onCopy, onProcess, onFile, onEnableAudit }: {
  snapshot: WindowsCommandMonitorSnapshot | null; busy: boolean; connected: boolean;
  onCollect: () => void; onCopy: (text: string) => void;
  onProcess: (pid: number) => void; onFile: (path: string) => void;
  onEnableAudit?: () => void;
}) {
  const [query, setQuery] = useState("");
  const [source, setSource] = useState("all");
  const [risk, setRisk] = useState<RiskFilter>("all");
  const [liveMonitor, setLiveMonitor] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const accumulatedRef = useRef<Map<string, WindowsCommandEntry>>(new Map());

  useEffect(() => {
    if (!snapshot) {
      accumulatedRef.current.clear();
      return;
    }
    for (const entry of snapshot.entries) {
      accumulatedRef.current.set(entry.id, entry);
    }
  }, [snapshot]);

  useEffect(() => {
    if (!liveMonitor || !connected) return;
    const timer = window.setInterval(() => {
      if (!busy) onCollect();
    }, 5000);
    return () => window.clearInterval(timer);
  }, [busy, connected, liveMonitor, onCollect]);

  const entries = useMemo(() => {
    if (!snapshot) return [];
    const merged = new Map<string, WindowsCommandEntry>(accumulatedRef.current);
    for (const entry of snapshot.entries) merged.set(entry.id, entry);
    return [...merged.values()];
  }, [snapshot]);

  const visible = entries.filter((entry) =>
    (source === "all" || entry.source === source) &&
    (risk === "all" || entry.riskLevel === risk) &&
    matchesQuery(query, entry.processName, entry.commandLine, entry.executablePath, entry.user, entry.parentName, entry.pid));
  const current = entries.find((entry) => entry.id === selected);

  const columns: Column<WindowsCommandEntry>[] = [
    { key: "time", label: "时间", width: "180px", mono: true, sort: (e) => timeValue(e.timeCreated), render: (e) => <SourceTime value={e.timeCreated} /> },
    { key: "source", label: "捕获来源", width: "130px", sort: (e) => e.source, render: (e) => <span className="wir-tag">{COMMAND_SOURCE_LABELS[e.source] ?? e.source}</span> },
    { key: "process", label: "进程 / 账户", width: "18%", sort: (e) => e.processName, render: (e) => <div className="wir-cell-stack"><strong>{e.processName}{e.pid ? ` (${e.pid})` : ""}</strong><small className="wir-clip">{e.user || e.executablePath || "—"}</small></div> },
    { key: "command", label: "执行的完整命令行 / 脚本块", mono: true, render: (e) => <span className="wir-clip" title={e.commandLine}>{e.commandLine}</span> },
    { key: "risk", label: "风险", width: "85px", sort: riskSort((e) => e.riskLevel), render: (e) => <RiskCell level={e.riskLevel} /> },
  ];

  return (
    <div className="wir-module">
      <StatStrip cards={[
        { label: "已捕获命令记录", value: snapshot ? entries.length : "—", hint: liveMonitor ? "实时持续监控开启中 (每 5 秒增量同步)" : "汇总 5 类命令执行来源" },
        { label: "高危命令", value: snapshot ? entries.filter((e) => e.riskLevel === "high").length : "—", tone: "high", onClick: () => setRisk("high") },
        { label: "4688 进程与命令行审计", value: snapshot ? (snapshot.processCreationEventsEnabled && snapshot.commandLineAuditEnabled ? "已完整开启" : "未完整开启") : "—", tone: snapshot && (!snapshot.processCreationEventsEnabled || !snapshot.commandLineAuditEnabled) ? "medium" : "normal" },
        { label: "PS 4104 脚本块日志", value: snapshot ? (snapshot.scriptBlockLoggingEnabled ? "已开启" : "未开启") : "—", tone: snapshot && !snapshot.scriptBlockLoggingEnabled ? "medium" : "normal" },
        { label: "Sysmon Event 1", value: snapshot ? (snapshot.sysmonInstalled ? "已启用" : "未安装") : "—" },
      ]} />
      <CollectionWarnings source="命令监控" stamp={snapshot?.observedAt} warnings={snapshot?.warnings ?? []} />
      <div className="wir-toolbar">
        <SearchBox value={query} onChange={setQuery} placeholder="搜索执行的命令参数、脚本内容、进程名、PID 或执行账户" />
        <select className="win-ir-input wir-select" aria-label="命令捕获来源" value={source} onChange={(event) => setSource(event.target.value)}>
          <option value="all">全部来源</option>
          <option value="active-process">实时活动进程 (Win32_Process)</option>
          <option value="security-4688">Security 4688 (进程创建)</option>
          <option value="sysmon-1">Sysmon Event 1</option>
          <option value="powershell-4104">PowerShell 4104/4103</option>
          <option value="psreadline-history">PSReadLine 历史记录</option>
        </select>
        <label className="wir-toggle">
          <input type="checkbox" checked={liveMonitor} disabled={!connected} onChange={(event) => setLiveMonitor(event.target.checked)} />
          实时持续监控（自动增量捕获新命令）
        </label>
        {onEnableAudit && snapshot && (!snapshot.processCreationEventsEnabled || !snapshot.commandLineAuditEnabled || !snapshot.scriptBlockLoggingEnabled) ? (
          <button type="button" className="win-ir-btn is-primary" disabled={busy || !connected} onClick={onEnableAudit}>一键开启完整命令审计策略…</button>
        ) : null}
        <button type="button" className="win-ir-btn" disabled={!visible.length} onClick={() => onCopy(toCsv(
          ["时间", "来源", "进程", "PID", "PPID", "账户", "路径", "命令行", "风险"],
          visible.map((e) => [e.timeCreated, e.source, e.processName, String(e.pid), String(e.ppid), e.user, e.executablePath, e.commandLine, e.riskLevel]),
        ))}>复制 CSV</button>
      </div>
      <FilterChips label="命令风险" value={risk} onChange={setRisk} options={riskChipOptions(riskCounts(entries, (entry) => entry.riskLevel))} />
      <div className={`wir-master${current ? " is-split" : ""}`}>
        <DataTable label="命令执行监控" columns={columns} rows={visible} rowKey={(entry) => entry.id} selectedKey={selected} onSelect={(entry) => setSelected(entry?.id ?? null)} rowRisk={(entry) => entry.riskLevel} defaultSort={{ key: "time", descending: true }} empty={snapshot ? "当前筛选条件下没有匹配的命令记录。" : "点击「采集命令活动」或开启「实时持续监控」，全方位捕获主机执行的命令与脚本。"} />
        {current ? <DetailPane title={current.processName} subtitle={`${COMMAND_SOURCE_LABELS[current.source] ?? current.source}${current.pid ? ` · PID ${current.pid}` : ""}`} risk={current.riskLevel} reasons={current.riskReasons} onClose={() => setSelected(null)} onCopy={onCopy} fields={[
          { label: "捕获时间", value: current.timeCreated, mono: true },
          { label: "证据来源", value: COMMAND_SOURCE_LABELS[current.source] ?? current.source },
          { label: "执行账户", value: current.user || "未记录" },
          { label: "进程路径 / 历史文件", value: current.executablePath || "未记录", mono: true },
          { label: "父进程信息", value: current.parentName || (current.ppid ? `PPID ${current.ppid}` : "—"), mono: true },
          { label: "完整命令行 / 脚本块内容", value: current.commandLine, mono: true },
        ]} actions={<>
          <button type="button" className="win-ir-btn" onClick={() => onCopy(current.commandLine)}>复制命令内容</button>
          {current.pid > 4 ? <button type="button" className="win-ir-btn" onClick={() => onProcess(current.pid)}>在进程分析中定位 ↗</button> : null}
          {current.executablePath && /^[a-zA-Z]:\\/u.test(current.executablePath) ? <button type="button" className="win-ir-btn" onClick={() => onFile(current.executablePath)}>在文件排查中打开 ↗</button> : null}
        </>} /> : null}
      </div>
      <p className="wir-footnote">同时采集活动进程命令行、Security 4688 进程创建事件、Sysmon Event 1、PowerShell 4103/4104 脚本块日志及各用户 PSReadLine 历史文件；自动过滤本应急工作台自身的采集脚本。开启「实时持续监控」可在会话期间持续累积新出现的命令。</p>
    </div>
  );
}
