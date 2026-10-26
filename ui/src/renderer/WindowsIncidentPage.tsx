import { WinIrDesktop } from "./WinIrDesktop";
import { Activity, useEffect, useRef, useState, type ReactElement } from "react";

import type { PageGroup } from "../shared/contract";
import type {
  WindowsAccountEntry, WindowsBaselineItem, WindowsFileEntry, WindowsIncidentApi,
  WindowsProcessEntry, WindowsRegistryValue, WindowsStartupEntry,
} from "../shared/windows-incident-contract";
import { DialogHost } from "./DialogHost";
import { ChevronIcon, NavGroupIcon, SearchIcon } from "./SidebarNav";
import { errorText } from "./error-text";
import { useConfirmDialog } from "./use-confirm-dialog";
import { WinIrProcesses, WinIrNetwork } from "./WinIrActivity";
import { WinIrAccounts, WinIrBaseline, WinIrStartup } from "./WinIrChecks";
import { WinIrConsole } from "./WinIrConsole";
import { WinIrLogs, WinIrTimeline } from "./WinIrEvents";
import { WinIrFileManager } from "./WinIrFileManager";
import { WinIrIcon } from "./WinIrIcon";
import { ModuleHeader } from "./WinIrKit";
import { WinIrOverview } from "./WinIrOverview";
import { WinIrRegistry } from "./WinIrRegistry";
import { WinIrSetup } from "./WinIrSetup";
import { formatBytes, matchesQuery, parentPath } from "./win-ir-helpers";
import { collectedTime, focusFor, moduleLabel, WIN_IR_MODULES, type CollectionTab, type FocusTarget, type InvestigationFocus, type WindowsIncidentTab } from "./win-ir-model";
import type { RelatedContext } from "./WinIrRelated";
import { useWindowsIncident } from "./use-windows-incident";
import "./windows-incident.css";
import "./win-ir-workspace.css";

export type { WindowsIncidentTab } from "./win-ir-model";

function EvidenceIcon() {
  return (
    <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M4 1.8h5.6L12.6 5v9.2H4Z" /><path d="M9.4 1.8V5h3.2" /><path d="m6.2 9.4 1.6 1.6 2.6-3" />
    </svg>
  );
}

/** Each module group takes the colour and icon of the matching group in the main navigation. */
const NAV_GROUP_LOOK: Record<string, { tone: PageGroup; icon: ReactElement }> = {
  研判: { tone: "triage", icon: <NavGroupIcon group="triage" /> },
  排查: { tone: "investigation", icon: <NavGroupIcon group="investigation" /> },
  取证: { tone: "intelligence", icon: <EvidenceIcon /> },
  连接: { tone: "target", icon: <NavGroupIcon group="target" /> },
};

export interface WindowsIncidentPageProps {
  api: WindowsIncidentApi;
  writeClipboard?: (text: string) => Promise<void>;
  onBackToWelcome?: () => void;
  channelOpenRequest?: number;
  covered?: boolean;
  onConnectionChange?: (connected: boolean, hostname: string | null) => void;
}

export function WindowsIncidentPage({ api, writeClipboard, onBackToWelcome, onConnectionChange, channelOpenRequest = 0, covered = false }: WindowsIncidentPageProps) {
  const data = useWindowsIncident(api);
  const confirm = useConfirmDialog();
  const [activeTab, setActiveTab] = useState<WindowsIncidentTab>("overview");
  const [visited, setVisited] = useState<ReadonlySet<WindowsIncidentTab>>(new Set(["overview"]));
  const [navigationQuery, setNavigationQuery] = useState("");
  const [rail, setRail] = useState(false);
  const [closedGroups, setClosedGroups] = useState<ReadonlySet<string>>(new Set());
  const [consoleOpen, setConsoleOpen] = useState(false);
  useEffect(() => { if (channelOpenRequest > 0) setConsoleOpen((open) => !open); }, [channelOpenRequest]);
  const [setupOpen, setSetupOpen] = useState(false);
  const [focus, setFocus] = useState<InvestigationFocus | null>(null);
  /** The module a cross-link left, so the target can offer the way back. */
  const [returnTo, setReturnTo] = useState<{ from: WindowsIncidentTab; to: WindowsIncidentTab } | null>(null);
  const mainRef = useRef<HTMLDivElement>(null);
  const requestId = useRef(0);
  const attempted = useRef(new Set<string>());
  const connected = data.sessionKey !== null;
  const busy = data.busy !== null;
  const host = data.snapshots.overview?.hostname ?? null;
  const hasSnapshots = Object.keys(data.snapshots).length > 0;
  const showWorkspace = connected || hasSnapshots || activeTab === "desktop";
  const setupView = !showWorkspace || setupOpen;
  const activeModule = WIN_IR_MODULES.find((module) => module.key === activeTab)!;
  const groups = [...new Set(WIN_IR_MODULES.map((module) => module.group))];

  useEffect(() => { onConnectionChange?.(connected, host); }, [connected, host, onConnectionChange]);
  // The guide opens by itself only before anything was collected; after a disconnect the old records stay in view.
  useEffect(() => { if (!connected && !hasSnapshots && activeTab !== "desktop") setSetupOpen(true); }, [connected, hasSnapshots, activeTab]);
  useEffect(() => () => onConnectionChange?.(false, null), [onConnectionChange]);
  useEffect(() => {
    if (!connected || busy) return;
    const overviewKey = `${data.epoch}:overview`;
    const tab = !data.snapshots.overview && !attempted.current.has(overviewKey) ? "overview" : activeTab;
    if (tab === "console" || tab === "timeline" || tab === "desktop") return;
    const key = `${data.epoch}:${tab}`;
    if (data.snapshots[tab] || attempted.current.has(key)) return;
    attempted.current.add(key);
    void data.collect(tab);
  }, [activeTab, busy, connected, data.collect, data.epoch, data.snapshots]);
  useEffect(() => { if (connected) setSetupOpen(false); }, [connected]);

  function navigate(tab: WindowsIncidentTab, crossLink = false) {
    if (tab === "console") { setConsoleOpen(true); return; }
    setConsoleOpen(false);
    setReturnTo(crossLink && tab !== activeTab ? { from: activeTab, to: tab } : null);
    setActiveTab(tab);
    setVisited((before) => new Set([...before, tab]));
    setClosedGroups((before) => {
      const next = new Set(before);
      next.delete(WIN_IR_MODULES.find((module) => module.key === tab)!.group);
      return next;
    });
  }
  async function copy(text: string) {
    if (!writeClipboard) { data.setError("当前窗口无法访问剪贴板。"); return; }
    if (new TextEncoder().encode(text).byteLength > 128 * 1024) { data.setError("内容超过 128 KB 剪贴板上限，请缩小筛选范围或复制单条记录。"); return; }
    try { await writeClipboard(text); data.setNotice("已复制到剪贴板。"); }
    catch (reason) { data.setError(errorText(reason, "复制失败，请重试。")); }
  }
  function locateFile(path: string) {
    if (busy || !connected) { data.setError("定位文件需要连接正常且当前采集结束，请稍后重试。"); return; }
    const directory = parentPath(path);
    if (!directory) { data.setError("没有取得可浏览的完整文件路径，请在文件管理器中输入目录。"); return; }
    setFocus({ target: { tab: "files", path }, request: ++requestId.current });
    navigate("files", true);
    void data.collect("files", directory);
  }
  function locateRegistry(keyPath: string, valueName?: string) {
    if (busy || !connected) { data.setError("定位注册表需要连接正常且当前采集结束，请稍后重试。"); return; }
    setFocus({ target: { tab: "registry", keyPath, ...(valueName === undefined ? {} : { valueName }) }, request: ++requestId.current });
    navigate("registry", true);
    void data.collect("registry", keyPath);
  }
  /** Opens the module of a record and selects it there; the module header then offers the way back. */
  function goTo(target: FocusTarget) {
    if (target.tab === "files") { locateFile(target.path); return; }
    if (target.tab === "registry") { locateRegistry(target.keyPath, target.valueName); return; }
    setFocus({ target, request: ++requestId.current });
    navigate(target.tab, true);
  }
  const related: RelatedContext = { snapshots: data.snapshots, collectedAt: data.collectedAt, onGo: goTo };
  const back = returnTo && returnTo.to === activeTab ? returnTo : null;
  function collectCurrent() {
    if (activeTab === "desktop") return;
    if (activeTab === "console") void data.refresh().catch((reason: unknown) => data.setError(errorText(reason, "状态读取失败。")));
    else if (activeTab === "timeline") void data.collectAll();
    else void data.collect(activeTab);
  }
  function attentionCount(tab: WindowsIncidentTab): number | undefined {
    switch (tab) {
      case "baseline": return data.snapshots.baseline?.failedCount;
      case "processes": return data.snapshots.processes?.suspiciousCount;
      case "network": return data.snapshots.network?.suspiciousCount;
      case "startup": return data.snapshots.startup?.suspiciousCount;
      case "accounts": return data.snapshots.accounts?.suspiciousCount;
      case "logs": return data.snapshots.logs?.highRiskCount;
      case "files": return data.snapshots.files?.entries.filter((entry) => entry.riskLevel === "high" || entry.riskLevel === "medium").length;
      default: return undefined;
    }
  }
  const local = data.localAction;
  const targetHost = host || "当前远程会话";
  async function remediateBaseline(item: WindowsBaselineItem) {
    const capturedSession = data.sessionKey;
    if (!capturedSession || busy) return;
    if (await confirm.ask(
      "确认快速修复基线项",
      `目标主机：${targetHost}\n检查项：${item.title} (${item.id})\n当前值：${item.currentValue}\n修复目标值：${item.expectedValue}\n\n将通过当前远程会话修改对应注册表、服务或安全策略，并立即重新采集基线以独立复核。部分策略（如 UAC、LSA 受保护进程）需重启系统后完全生效。`,
      "确认修复并复核",
    )) {
      await data.dispose("baseline", { action: "remediate-baseline", ruleId: item.id }, capturedSession, `正在修复「${item.title}」并复核基线…`, `已完成「${item.title}」修复操作并刷新基线复核结果。`);
    }
  }
  async function killProcess(process: WindowsProcessEntry) {
    const capturedSession = data.sessionKey;
    if (!capturedSession || busy) return;
    if (await confirm.ask(
      "确认结束远程进程",
      `目标主机：${targetHost}\n进程名称：${process.name}\nPID：${process.pid}（PPID ${process.ppid}）\n启动时间：${process.startTime}\n执行路径：${process.executablePath || "未取得"}\n命令行：${process.commandLine || "未取得"}\n\n执行前将再次核对 PID 与启动时间以防误杀复用进程。强制终止进程可能导致关联服务中断或未保存数据丢失。`,
      "确认结束进程",
    )) {
      await data.dispose("processes", { action: "kill-process", pid: process.pid, startTime: process.startTime }, capturedSession, `正在核对身份并结束进程 ${process.name} (PID ${process.pid})…`, `已终止进程 ${process.name} (PID ${process.pid}) 并刷新进程列表。`);
    }
  }
  async function removeStartup(entry: WindowsStartupEntry) {
    const capturedSession = data.sessionKey;
    if (!capturedSession || busy) return;
    const isService = entry.sourceType.toLowerCase() === "service";
    if (await confirm.ask(
      isService ? "确认停止并禁用服务" : "确认清理启动项",
      `目标主机：${targetHost}\n名称：${entry.name}\n来源：${entry.sourceType}\n位置：${entry.location}\n命令：${entry.command || "未取得"}\n\n${isService ? "将停止该服务并将其启动类型设为禁用（Disabled），随后重新采集启动项复核。" : "将按来源移除对应注册表自启动值、删除启动目录文件或注销计划任务，随后重新采集启动项复核。"}`,
      isService ? "确认停止并禁用" : "确认清理启动项",
    )) {
      await data.dispose("startup", { action: "remove-startup", sourceType: entry.sourceType, name: entry.name, location: entry.location }, capturedSession, `正在清理启动项「${entry.name}」并复核…`, `已清理启动项「${entry.name}」并刷新持久化列表。`);
    }
  }
  async function disableAccount(entry: WindowsAccountEntry) {
    const capturedSession = data.sessionKey;
    if (!capturedSession || busy) return;
    if (await confirm.ask(
      "确认禁用本地账户",
      `目标主机：${targetHost}\n账户名称：${entry.name}\nSID：${entry.sid}（RID ${entry.rid}）\n权限组：${entry.isAdmin ? "管理员组" : "普通账户"}\n\n将按 SID 与账户名核对身份并禁用该本地账户（自动拒绝禁用当前登录会话账户），随后重新采集本地账户列表。`,
      "确认禁用账户",
    )) {
      await data.dispose("accounts", { action: "disable-account", name: entry.name, sid: entry.sid }, capturedSession, `正在禁用账户「${entry.name}」并复核…`, `已禁用本地账户「${entry.name}」并刷新账户快照。`);
    }
  }
  async function deleteFile(entry: WindowsFileEntry) {
    const capturedSession = data.sessionKey;
    const currentDir = data.snapshots.files?.currentPath;
    if (!capturedSession || !currentDir || busy) return;
    if (await confirm.ask(
      "确认删除远程文件",
      `目标主机：${targetHost}\n文件名称：${entry.name}\n完整路径：${entry.fullPath}\n文件大小：${formatBytes(entry.sizeBytes)}（${entry.sizeBytes} 字节）\n修改时间：${entry.lastWriteTime || "未取得"}${entry.sha256 ? `\nSHA256：${entry.sha256}` : ""}\n\n注意：远程删除不可恢复（若带有只读/隐藏/系统属性将一并清除后删除）。如尚未留存样本证据，请先取消并点击「取证拉取」。`,
      "确认永久删除",
    )) {
      await data.dispose("files", { action: "delete-file", path: entry.fullPath, dirPath: currentDir }, capturedSession, `正在删除文件「${entry.name}」并刷新目录…`, `已删除远程文件「${entry.name}」并刷新当前目录。`);
    }
  }
  async function deleteRegistryValue(keyPath: string, value: WindowsRegistryValue) {
    const capturedSession = data.sessionKey;
    if (!capturedSession || busy) return;
    if (await confirm.ask(
      "确认删除注册表键值",
      `目标主机：${targetHost}\n注册表键：${keyPath}\n值名称：${value.name}\n值类型：${value.kind}\n当前数据：${value.data || "（空字符串）"}\n\n将从目标注册表键中删除该值，并立即重新读取当前注册表键以核实结果。`,
      "确认删除键值",
    )) {
      await data.dispose("registry", { action: "delete-registry-value", keyPath, valueName: value.name }, capturedSession, `正在删除注册表值「${value.name}」并复核…`, `已删除注册表值「${value.name}」并刷新当前注册表键。`);
    }
  }
  const setup = <WinIrSetup status={data.status} script={data.filelessScript} busy={busy} canCopy={writeClipboard !== undefined}
    onRegister={() => void local("register-plugin", "正在注册插件并准备本地监听…", "注册请求已完成，请根据接入状态继续下一步。")}
    onListen={() => void local("start-listener", "正在启动本地监听…", "监听启动请求已完成。")}
    onOpenDesktop={() => { navigate("desktop"); setSetupOpen(false); }}
    onCopyScript={() => void copy(data.filelessScript)}
    onRevealAgent={() => void local("reveal-agent", "正在定位采集程序…", "已在资源管理器中定位 Agent，请复制到远程会话并运行。")}
  />;

  return (
    <section className={`page windows-incident-page${rail ? " is-rail" : ""}`} data-testid="windows-incident-page">
      <aside className={`sidebar win-ir-sidebar${rail ? " is-rail" : ""}`} aria-label="Windows 应急响应边栏">
        {rail ? null : <div className={`sidebar-target${connected ? "" : " is-idle"}`}>
          <span className="sidebar-target-state"><span className={connected ? "status-dot" : "status-dot idle"} aria-hidden="true" />{connected ? "已连接被检会话" : hasSnapshots ? "连接已断开" : "等待连接被检主机"}</span>
          {connected || hasSnapshots ? <strong title={host ?? undefined}>{host || "主机名称待采集"}</strong> : null}
          <p>{connected ? "经远程桌面通道只读采集。" : hasSnapshots ? "旧快照仅供查看，远程操作已暂停。" : "完成三步接入后开始调查。"}</p>
          {connected ? <div className="sidebar-target-actions">
            <button type="button" aria-expanded={setupOpen} onClick={() => setSetupOpen(!setupOpen)}>{setupOpen ? "收起接入说明" : "接入管理"}</button>
            <button type="button" aria-current={activeTab === "desktop" ? "page" : undefined} onClick={() => navigate("desktop")}>远程桌面</button>
          </div> : <button type="button" className="sidebar-target-primary" aria-expanded={setupOpen} onClick={() => setSetupOpen(!setupOpen)}>{setupOpen ? "收起接入说明" : "重新接入"}</button>}
        </div>}
        {onBackToWelcome ? <div className="nav-switch-row">
          <button type="button" className="nav-item nav-switch" data-testid="windows-back-welcome" disabled={busy} title="返回模块选择 / 切换至 Linux" aria-label="返回模块选择 / 切换至 Linux" onClick={onBackToWelcome}>
            <span className="nav-icon" aria-hidden="true">←</span><strong>切换至 Linux 工作台</strong>
          </button>
        </div> : null}
        {rail ? null : <div className="sidebar-search">
          <SearchIcon />
          <input type="search" value={navigationQuery} aria-label="查找排查模块" placeholder="查找排查模块" autoComplete="off" spellCheck={false}
            onChange={(event) => setNavigationQuery(event.target.value)}
            onKeyDown={(event) => { if (event.key === "Escape" && navigationQuery !== "") { event.preventDefault(); event.stopPropagation(); setNavigationQuery(""); } }} />
          {navigationQuery ? <button type="button" className="sidebar-search-clear" aria-label="清除查找" title="清除查找" onClick={() => setNavigationQuery("")}>×</button> : null}
        </div>}
        <nav aria-label="Windows 应急响应模块">
          {groups.map((group) => {
            const modules = WIN_IR_MODULES.filter((module) => module.key !== "console" && module.group === group && (rail || matchesQuery(navigationQuery, module.label, module.description)));
            if (!modules.length) return null;
            const open = rail || navigationQuery !== "" || !closedGroups.has(group);
            const look = NAV_GROUP_LOOK[group] ?? NAV_GROUP_LOOK["连接"]!;
            return <section className={`nav-group nav-group--${look.tone}${open ? " is-open" : ""}`} key={group} aria-label={group}>
              {rail ? null : <button type="button" className="nav-group-row" aria-expanded={open} disabled={navigationQuery !== ""} onClick={() => setClosedGroups((before) => { const next = new Set(before); if (next.has(group)) next.delete(group); else next.add(group); return next; })}>
                <span className="nav-group-icon">{look.icon}</span>
                <span className="nav-group-label">{group}</span>
                <span className="nav-group-count" aria-label={`${modules.length} 个模块`}>{modules.length}</span>
                <ChevronIcon />
              </button>}
              <div className="nav-group-items" inert={open ? undefined : true}>
                <div className="nav-group-items-inner">
                  {modules.map((module) => {
                    const count = attentionCount(module.key);
                    const active = activeTab === module.key;
                    const waiting = !connected && module.key !== "desktop" && !data.snapshots[module.key as CollectionTab];
                    return <button key={module.key} type="button" className={["nav-item", "win-ir-nav-item", active ? "active" : "", waiting ? "needs-target" : ""].filter(Boolean).join(" ")}
                      aria-label={module.label} aria-current={active ? "page" : undefined} title={rail ? module.label : module.description} onClick={() => navigate(module.key)}>
                      <span className="nav-icon"><WinIrIcon name={module.key} size={16} /></span>
                      <strong>{module.label}</strong>
                      {count ? <em className="win-ir-nav-count" aria-label={`${count} 条待关注线索`}>{count > 99 ? "99+" : count}</em> : waiting ? <i className="nav-needs-target" aria-label="需要连接被检主机" /> : <i aria-hidden="true" />}
                    </button>;
                  })}
                </div>
              </div>
            </section>;
          })}
          {!rail && !WIN_IR_MODULES.some((module) => matchesQuery(navigationQuery, module.label, module.description)) ? <p className="nav-empty" role="status">没有名称或说明包含“{navigationQuery.trim()}”的模块。</p> : null}
        </nav>
        <div className="sidebar-rail-toggle win-ir-sidebar-foot">
          <button type="button" aria-label="通道与传输" aria-expanded={consoleOpen} title="通道与传输" onClick={() => setConsoleOpen(!consoleOpen)}>
            <WinIrIcon name="console" size={14} />{rail ? null : <span>通道与传输</span>}
          </button>
          <button type="button" aria-label={rail ? "展开导航" : "收起导航"} aria-pressed={rail} title={rail ? "展开导航" : "收起为图标栏"} onClick={() => setRail(!rail)}>
            <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <rect x="1.8" y="2.4" width="12.4" height="11.2" rx="2" /><path d="M6 2.4v11.2" /><path d={rail ? "m9 6.2 1.8 1.8L9 9.8" : "m10.8 6.2-1.8 1.8 1.8 1.8"} />
            </svg>
            {rail ? null : <span>收起导航</span>}
          </button>
        </div>
      </aside>

      <div className={`win-ir-main${activeTab === "desktop" ? " is-desktop" : ""}`} ref={mainRef} onKeyDown={(event) => {
        if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "f") {
          const input = Array.from(mainRef.current?.querySelectorAll<HTMLInputElement>(".wir-search input") ?? []).find((element) => element.getClientRects().length > 0);
          if (input) { event.preventDefault(); input.focus(); input.select(); }
        }
      }}>
        {showWorkspace && !connected && !setupView && activeTab !== "desktop" ? <div className="wir-session-bar is-disconnected" role="status">
          <span className="status-dot idle" aria-hidden="true" /><strong>连接已断开</strong><span className="wir-session-host">{host || "主机名称待采集"}</span><span className="wir-session-hint">旧快照仅供查看，远程操作已暂停</span>
          <button type="button" className="win-ir-btn" onClick={() => setSetupOpen(true)}>重新接入</button>
        </div> : null}
        {data.statusError ? <details className="wir-collection-warnings" role="alert"><summary>连接状态待核实 · 远程操作已暂停</summary><span>{data.statusError}</span><button type="button" className="win-ir-btn" onClick={() => void data.refresh().catch(() => undefined)}>重试连接状态</button></details> : null}
        {data.reconnect?.phase === "verifying" ? <div className="win-ir-notice" role="status"><span>采集通道已重新连接，正在核对是否仍是 {data.reconnect.host}；核对完成前显示的是重连前的结果。</span></div> : null}
        {data.reconnect?.phase === "kept" ? <div className="win-ir-notice is-ok" role="status"><span>已重新连接 {data.reconnect.host}（按主机名、域和系统版本核对），保留了重连前采集的结果；各模块的采集时间不变，可按需刷新。</span><button type="button" className="wir-icon-button" aria-label="关闭重连提示" onClick={data.dismissReconnect}>×</button></div> : null}
        {data.reconnect?.phase === "replaced" ? <div className="win-ir-notice is-warn" role="status"><span>重新连接的主机（{data.reconnect.host}）与之前（{data.reconnect.previous}）不同，已清空旧结果。</span><button type="button" className="wir-icon-button" aria-label="关闭重连提示" onClick={data.dismissReconnect}>×</button></div> : null}
        {data.reconnect?.phase === "failed" ? <div className="win-ir-notice is-warn" role="alert"><span>采集通道已重新连接，但未能核对是否仍是 {data.reconnect.host}：{data.reconnect.message} 当前显示的是重连前的结果。</span><button type="button" className="win-ir-btn" onClick={data.retryReconnect}>重试核对</button><button type="button" className="win-ir-btn" onClick={data.discardPrevious}>清空旧结果</button></div> : null}
        {data.error ? <div className="win-ir-notice is-error" role="alert"><span>{data.error}</span><button type="button" className="wir-icon-button" aria-label="关闭错误提示" onClick={data.dismissError}>×</button></div> : null}
        {data.notice ? <div className="win-ir-notice" role="status"><span>{data.notice}</span><button type="button" className="wir-icon-button" aria-label="关闭操作提示" onClick={data.dismissNotice}>×</button></div> : null}
        {busy ? <div className="wir-collection-progress" role="status"><span className="win-ir-spinner" aria-hidden="true" /><span>{data.busy}</span>{data.batch ? <><progress aria-label="核心模块采集进度" value={data.batch.done} max={data.batch.total} /><button type="button" className="win-ir-btn" disabled={data.batch.stopping} onClick={data.cancelBatch}>{data.batch.stopping ? "本项结束后停止…" : "停止后续采集"}</button></> : null}</div> : null}
        {setupView ? <section className="wir-setup-view" aria-label="接入被检主机">
          {showWorkspace ? <div className="wir-setup-bar">
            <button type="button" className="win-ir-btn" onClick={() => setSetupOpen(false)}>← 返回{activeTab === "desktop" ? "远程桌面" : moduleLabel(activeTab)}</button>
            <span>{connected ? "会话已连接；接入设置不影响已采集的结果。" : "完成接入前，仍可返回查看断开前采集的记录。"}</span>
          </div> : null}
          {setup}
        </section> : null}
        {/* The modules stay mounted behind the setup view so their selections and filters survive it. */}
        {showWorkspace ? <div className="wir-workspace" hidden={setupView}>
          {activeTab !== "desktop" ? <ModuleHeader title={activeModule.label} description={activeModule.description} collectedAt={collectedTime(data.collectedAt[activeTab as CollectionTab])} busy={busy || !connected} actionLabel={activeModule.action} onCollect={collectCurrent}
            extra={<>
              {back ? <button type="button" className="win-ir-btn wir-back-link" onClick={() => navigate(back.from)}>← 返回{moduleLabel(back.from)}</button> : null}
              {activeTab === "files" ? <button type="button" className="win-ir-btn" onClick={() => navigate("console")}>接收与保存</button> : null}
              {activeTab !== "console" && activeTab !== "timeline" && data.snapshots[activeTab] ? <button type="button" className="win-ir-btn" onClick={() => void copy(JSON.stringify({ hostname: host, collectedAt: data.collectedAt[activeTab], module: activeTab, snapshot: data.snapshots[activeTab] }, null, 2))}>复制结果 JSON</button> : null}
            </>}
          /> : null}
          {data.collectionErrors[activeTab as CollectionTab] ? <details className="wir-collection-warnings"><summary>上次采集未完成 · 查看原因与重试</summary><span>上次采集未完成：{data.collectionErrors[activeTab as CollectionTab]}{data.snapshots[activeTab as CollectionTab] ? " 下面保留上一次成功采集的结果。" : ""}</span><button type="button" className="win-ir-btn" disabled={busy || !connected} onClick={collectCurrent}>重试</button></details> : null}
          {WIN_IR_MODULES.filter((module) => visited.has(module.key)).map(({ key }) => <Activity key={`${data.snapshotKey}:${key}`} mode={key === activeTab ? "visible" : "hidden"}>
            {key === "desktop" ? <WinIrDesktop api={api.windowsRdp} covered={covered || consoleOpen || setupOpen} /> : null}
            {key === "overview" ? <WinIrOverview snapshots={data.snapshots} collectedAt={data.collectedAt} busy={busy || !connected} onNavigate={(tab) => navigate(tab, true)} onGo={goTo} onCollectAll={() => void data.collectAll()} /> : null}
            {key === "baseline" ? <WinIrBaseline snapshot={data.snapshots.baseline ?? null} focus={focusFor(focus, "baseline")} busy={busy} connected={connected} onCopy={(text) => void copy(text)} onRemediate={(item) => void remediateBaseline(item)} /> : null}
            {key === "processes" ? <WinIrProcesses busy={busy} connected={connected} onInspect={data.inspectProcess} onKill={(process) => void killProcess(process)} snapshot={data.snapshots.processes ?? null} network={data.snapshots.network ?? null} focus={focusFor(focus, "processes")} related={related} onCopy={(text) => void copy(text)} onFile={locateFile} onNetwork={(pid) => goTo({ tab: "network", pid })} /> : null}
            {key === "network" ? <WinIrNetwork snapshot={data.snapshots.network ?? null} processes={data.snapshots.processes ?? null} busy={busy} connected={connected} focus={focusFor(focus, "network")} related={related} onCopy={(text) => void copy(text)} onProcess={(pid) => goTo({ tab: "processes", pid })} onFile={locateFile} onKillProcess={(process) => void killProcess(process)} /> : null}
            {key === "startup" ? <WinIrStartup snapshot={data.snapshots.startup ?? null} busy={busy} connected={connected} focus={focusFor(focus, "startup")} related={related} onCopy={(text) => void copy(text)} onFile={locateFile} onRegistry={locateRegistry} onRemove={(entry) => void removeStartup(entry)} /> : null}
            {key === "accounts" ? <WinIrAccounts snapshot={data.snapshots.accounts ?? null} busy={busy} connected={connected} focus={focusFor(focus, "accounts")} related={related} onCopy={(text) => void copy(text)} onLogs={(query) => goTo({ tab: "logs", query })} onDisable={(entry) => void disableAccount(entry)} /> : null}
            {key === "logs" ? <WinIrLogs onDirectory={(path) => { if (!busy && connected) { navigate("files", true); void data.collect("files", path); } }} snapshot={data.snapshots.logs ?? null} busy={busy || !connected} category={data.snapshots.logs?.categoryFilter ?? "all"} onCategory={(category) => void data.collect("logs", category)} focus={focusFor(focus, "logs")} onCopy={(text) => void copy(text)} /> : null}
            {key === "timeline" ? <WinIrTimeline snapshots={data.snapshots} onCopy={(text) => void copy(text)} onGo={goTo} /> : null}
            {key === "files" ? <WinIrFileManager snapshot={data.snapshots.files ?? null} busy={busy} connected={connected} revealPath={focus?.target.tab === "files" ? focus.target.path : null} related={related} onNavigate={(path) => void data.collect("files", path)} onPreview={data.previewFile} onPull={(path) => void data.pullFile(path)} onDelete={(entry) => void deleteFile(entry)} onCopy={(text) => void copy(text)} /> : null}
            {key === "registry" ? <WinIrRegistry snapshot={data.snapshots.registry ?? null} busy={busy} connected={connected} focus={focusFor(focus, "registry")} related={related} onNavigate={(path) => void data.collect("registry", path)} onDeleteValue={(keyPath, value) => void deleteRegistryValue(keyPath, value)} onCopy={(text) => void copy(text)} /> : null}

          </Activity>)}
        </div> : null}
      </div>
      <Activity mode={consoleOpen ? "visible" : "hidden"}>
        <aside className="wir-channel-drawer" aria-label="通道与传输面板" onKeyDown={(event) => { if (event.key === "Escape" && !document.querySelector('[role="dialog"], [role="alertdialog"]') && !busy && !event.defaultPrevented && !(event.target instanceof HTMLTextAreaElement)) { setConsoleOpen(false); } }}>
          <header><strong>通道与传输</strong><span>{connected ? "会话已连接" : "未连接"} · {data.status?.receivedFiles.length ?? 0} 个接收文件</span><button type="button" className="wir-icon-button" aria-label="收起通道与传输" disabled={busy} onClick={() => setConsoleOpen(false)}>⌄</button></header>
          <div className="wir-channel-content"><WinIrConsole status={data.status} busy={busy} sessionKey={data.sessionKey} hostname={host || "当前远程会话"} output={data.commandOutput} savedFiles={data.savedFiles} canSave={api.saveWindowsFile !== undefined} onSave={(fileId) => void data.saveFile(fileId)} onCopy={(text) => void copy(text)} onSend={data.sendChat} onRun={data.runCommand} onUnregister={() => void local("unregister-plugin", "正在移除插件注册…", "当前用户的插件注册已移除。")} /></div>
        </aside>
      </Activity>
      {confirm.dialog ? <DialogHost dialog={confirm.dialog} scrollMessage onResolve={confirm.resolve} /> : null}
    </section>
  );
}
