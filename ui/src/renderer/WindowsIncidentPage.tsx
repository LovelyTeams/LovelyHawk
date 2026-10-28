import { WinIrCollectionNotices } from "./WinIrCollectionNotices";
import { WinIrInventoryDetails, type InventoryDetailSelection } from "./WinIrInventoryDetails";
import { WinIrInventory } from "./WinIrInventory";
import { WinIrControlChange, type ControlSelection } from "./WinIrControlChange";
import { NoticeScopeContext, NoticeSummary } from "./NoticeSummary";
import { TransientNotice } from "./NotificationCenter";
import { WinIrProcessChange } from "./WinIrProcessChange";
import { WinIrDesktop } from "./WinIrDesktop";
import { Activity, useEffect, useImperativeHandle, useRef, useState, type Ref, type ReactNode } from "react";

import type {
  WindowsAccountEntry, WindowsFileEntry, WindowsIncidentApi,
  WindowsProcessEntry, WindowsRegistryValue, WindowsStartupEntry,
} from "../shared/windows-incident-contract";
import { DialogHost } from "./DialogHost";
import { errorText } from "./error-text";
import { useConfirmDialog } from "./use-confirm-dialog";
import { WinIrProcesses, WinIrNetwork } from "./WinIrActivity";
import { WinIrAccounts, WinIrBaseline, WinIrStartup } from "./WinIrChecks";
import { useWindowsChannel } from "./use-windows-channel";
import type { WindowsChannelTab } from "../shared/windows-channel-contract";
import { WinIrCommands, WinIrDefender, WinIrLogs, WinIrTimeline, WinIrWebshell } from "./WinIrEvents";
import { WinIrBaselineChanges } from "./WinIrBaselineChanges";
import { WinIrFileManager } from "./WinIrFileManager";
import { WinIrIcon } from "./WinIrIcon";
import { ModuleHeader } from "./WinIrKit";
import { WinIrOverview } from "./WinIrOverview";
import { WinIrPlaybooks } from "./WinIrPlaybooks";
import type { PlaybookAction } from "./win-ir-playbooks";
import { FILE_PLACES, REGISTRY_PLACES } from "./win-ir-presets";
import { WinIrRegistry } from "./WinIrRegistry";
import { WinIrSetup } from "./WinIrSetup";
import { formatBytes, parentPath } from "./win-ir-helpers";
import { collectedTime, focusFor, moduleLabel, WIN_IR_MODULES, type CollectionTab, type FocusTarget, type InvestigationFocus, type WindowsIncidentTab } from "./win-ir-model";
import type { RelatedContext } from "./WinIrRelated";
import { useWindowsIncident } from "./use-windows-incident";
import "./windows-incident.css";
import "./win-ir-workspace.css";

export type { WindowsIncidentTab } from "./win-ir-model";

export interface WindowsIncidentPageHandle { beforeDeactivate(): Promise<boolean> }

export interface WindowsIncidentPageProps {
  ref?: Ref<WindowsIncidentPageHandle>;
  api: WindowsIncidentApi;
  writeClipboard?: (text: string) => Promise<void>;
  onBackToWelcome?: () => void;
  onOpenSettings?: (returnFocus: HTMLElement) => void;
  channelOpenRequest?: number;
  covered?: boolean;
  sidebarActions?: ReactNode;
  onBusyChange?: (busy: boolean) => void;
  onConnectionChange?: (connected: boolean, hostname: string | null) => void;
}

export function WindowsIncidentPage({ ref, api, writeClipboard, onBackToWelcome, onOpenSettings, onConnectionChange, onBusyChange, channelOpenRequest = 0, covered = false, sidebarActions }: WindowsIncidentPageProps) {
  const data = useWindowsIncident(api);
  const confirm = useConfirmDialog();
  const [baselineSelection, setBaselineSelection] = useState<{ ids: string[]; session: string } | null>(null);
  const [inventoryDetail,setInventoryDetail]=useState<InventoryDetailSelection|null>(null);
  const [controlSelection, setControlSelection] = useState<ControlSelection|null>(null);
  const [inventoryFocus,setInventoryFocus]=useState<{kind:"services"|"drivers"|"tasks";name:string;location:string;request:number}|null>(null);
  const [activeTab, setActiveTab] = useState<WindowsIncidentTab>("overview");
  const [visited, setVisited] = useState<ReadonlySet<WindowsIncidentTab>>(new Set(["overview"]));
  const [rail, setRail] = useState(false);
  useEffect(() => {
    const narrow = window.matchMedia("(max-width: 1100px)");
    const update = () => setRail(narrow.matches);
    update(); narrow.addEventListener("change", update);
    return () => narrow.removeEventListener("change", update);
  }, []);
  const [commandSuggestion, setCommandSuggestion] = useState<{ id: string; request: number } | null>(null);
  const channel = useWindowsChannel(api.windowsChannel, data, commandSuggestion, api.saveWindowsFile !== undefined);
  function openDock(tab: WindowsChannelTab) { void channel.open(tab); }
  const handledChannelRequest = useRef(channelOpenRequest);
  useEffect(() => {
    if (channelOpenRequest !== handledChannelRequest.current) {
      handledChannelRequest.current = channelOpenRequest; openDock("tasks");
    }
  }, [channelOpenRequest]);
  useImperativeHandle(ref, () => ({ beforeDeactivate: () => channel.beforeLeave(confirm.ask) }));
  const [setupOpen, setSetupOpen] = useState(false);
  const [focus, setFocus] = useState<InvestigationFocus | null>(null);
  /** The module a cross-link left, so the target can offer the way back. */
  const [returnTo, setReturnTo] = useState<{ from: WindowsIncidentTab; to: WindowsIncidentTab } | null>(null);
  const mainRef = useRef<HTMLDivElement>(null);
  const requestId = useRef(0);
  const attempted = useRef(new Set<string>());
  const connected = data.sessionKey !== null;
  const busy = data.busy !== null;
  useEffect(() => { onBusyChange?.(busy || channel.pending); return () => onBusyChange?.(false); }, [busy, channel.pending, onBusyChange]);
  const host = data.snapshots.overview?.hostname ?? null;
  const hasSnapshots = Object.keys(data.snapshots).length > 0;
  const showWorkspace = connected || hasSnapshots || activeTab === "desktop" || activeTab === "playbooks";
  const setupView = !showWorkspace || setupOpen;
  const activeModule = WIN_IR_MODULES.find((module) => module.key === activeTab)!;
  const groups = ["调查", "取证", "配置"];
  const unsavedCount = data.status?.receivedFiles.filter((file) => !data.savedFiles.has(file.fileId)).length ?? 0;

  useEffect(() => { onConnectionChange?.(connected, host); }, [connected, host, onConnectionChange]);
  // The guide opens by itself only before anything was collected; after a disconnect the old records stay in view.
  useEffect(() => { if (!connected && !hasSnapshots && activeTab !== "desktop" && activeTab !== "playbooks") setSetupOpen(true); }, [connected, hasSnapshots, activeTab]);
  useEffect(() => () => onConnectionChange?.(false, null), [onConnectionChange]);
  useEffect(() => {
    if (!connected || busy || activeTab === "playbooks") return;
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
    if (tab === "console") { openDock("command"); return; }
    if (tab === "playbooks") setSetupOpen(false);
    setReturnTo(crossLink && tab !== activeTab ? { from: activeTab, to: tab } : null);
    setActiveTab(tab);
    setVisited((before) => new Set([...before, tab]));
  }
  async function copy(text: string) {
    if (!writeClipboard) { data.setError("当前窗口无法访问剪贴板。"); return; }
    if (new TextEncoder().encode(text).byteLength > 128 * 1024) { data.setError("内容超过 128 KB 剪贴板上限，请缩小筛选范围或复制单条记录。"); return; }
    data.setNotice(null);
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
  function openPlaybookAction(action: PlaybookAction) {
    if (action.kind === "command") {
      setCommandSuggestion({ id: action.preset, request: ++requestId.current });
      openDock("command");
      return;
    }
    if (!connected || busy) return;
    setFocus(null);
    if (action.kind === "module") { navigate(action.tab, true); return; }
    if (action.kind === "files") {
      const place = FILE_PLACES.find((item) => item.label === action.preset);
      if (place) { navigate("files", true); void data.collect("files", place.path); }
    } else if (action.kind === "registry") {
      const place = REGISTRY_PLACES.find((item) => item.label === action.preset);
      if (place) locateRegistry(place.keyPath);
    } else {
      setFocus({ target: { tab: "logs", query: "" }, request: ++requestId.current });
      navigate("logs", true);
      void data.collect("logs", action.category);
    }
  }
  function collectCurrent() {
    if (activeTab === "desktop" || activeTab === "playbooks") return;
    if (activeTab === "console") void data.refresh().catch((reason: unknown) => data.setError(errorText(reason, "状态读取失败。")));
    else if (activeTab === "timeline") void data.collectAll();
    else void data.collect(activeTab);
  }
  function attentionCount(tab: WindowsIncidentTab): number | undefined {
    switch (tab) {
      case "baseline": return data.snapshots.baseline?.failedCount;
      case "processes": return data.snapshots.processes?.suspiciousCount;
      case "commands": return data.snapshots.commands?.highRiskCount;
      case "network": return data.snapshots.network?.suspiciousCount;
      case "startup": return data.snapshots.startup?.suspiciousCount;
      case "services": case "drivers": case "tasks": return data.snapshots[tab]?.entries.filter((entry) => entry.riskLevel !== "normal").length;
      case "accounts": return data.snapshots.accounts?.suspiciousCount;
      case "logs": return data.snapshots.logs?.highRiskCount;
      case "defender": return data.snapshots.defender?.highRiskCount;
      case "files": return data.snapshots.files?.entries.filter((entry) => entry.riskLevel === "high" || entry.riskLevel === "medium").length;
      case "webshell": return data.snapshots.webshell ? data.snapshots.webshell.highRiskCount + data.snapshots.webshell.mediumRiskCount : undefined;
      default: return undefined;
    }
  }
  const local = data.localAction;
  const targetHost = host || "当前远程会话";
  function configureBaseline(ids: string[] = []) { if (data.sessionKey && !busy) setBaselineSelection({ ids, session: data.sessionKey }); }
  const [processSelection, setProcessSelection] = useState<{ process: WindowsProcessEntry; tree: boolean; session: string } | null>(null);
  function killProcess(process: WindowsProcessEntry, tree = false) {
    if (data.sessionKey && !busy) setProcessSelection({process,tree,session:data.sessionKey});
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
  async function deleteAccount(entry: WindowsAccountEntry) {
    const capturedSession = data.sessionKey;
    if (!capturedSession || busy) return;
    if (await confirm.ask(
      "确认删除本地账户",
      `目标主机：${targetHost}\n账户名称：${entry.name}\nSID：${entry.sid}（RID ${entry.rid}）\n权限组：${entry.isAdmin ? "管理员组" : "普通账户"}\n\n注意：将按 SID 与账户名核对身份并从本机 SAM 中永久删除该本地账户（自动拒绝删除内置系统账户和当前登录会话账户；磁盘上的用户配置目录将保留供取证核查），随后重新采集本地账户列表。`,
      "确认删除账户",
    )) {
      await data.dispose("accounts", { action: "delete-account", name: entry.name, sid: entry.sid }, capturedSession, `正在删除账户「${entry.name}」并复核…`, `已删除本地账户「${entry.name}」并刷新账户快照。`);
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
    <NoticeScopeContext.Provider value={{key:data.snapshotKey,label:host ? `目标：${host}` : "Windows 当前会话"}}><section className={`page windows-incident-page${rail ? " is-rail" : ""}`} data-testid="windows-incident-page">
      <WinIrCollectionNotices snapshots={data.snapshots} collectedAt={data.collectedAt} errors={data.collectionErrors} />
      <header className="wir-host-bar" aria-label="当前被检主机">
        <span className="wir-host-icon"><WinIrIcon name="overview" size={20} /></span>
        <strong title={host ?? undefined}>{host || (connected ? "主机名称待采集" : "等待连接被检主机")}</strong>
        {data.snapshots.overview ? <><span className="wir-host-system" title={data.snapshots.overview.osCaption}>{data.snapshots.overview.osCaption}</span><span className="wir-host-permission">{data.snapshots.overview.isElevated ? "管理员权限" : "普通用户权限"}</span></> : null}
        <span className={`wir-host-connection${connected && !data.statusError ? "" : " is-offline"}`} role="status"><i className={connected && !data.statusError ? "status-dot" : "status-dot idle"} aria-hidden="true" />{data.statusError ? "连接状态待核实" : connected ? "采集通道已连接" : hasSnapshots ? "已断连 · 查看旧快照" : "采集通道未连接"}</span>
        <div className="wir-host-actions">
          {unsavedCount > 0 ? <button type="button" className="wir-unsaved-link" onClick={() => openDock("files")}>{unsavedCount} 个文件待保存</button> : null}
          <button type="button" className="win-ir-btn" aria-label="远程桌面" aria-current={activeTab === "desktop" ? "page" : undefined} onClick={() => { navigate("desktop"); setSetupOpen(false); }}><WinIrIcon name="desktop" size={14} />远程桌面</button>
        </div>
      </header>
      <aside className={`sidebar win-ir-sidebar${rail ? " is-rail" : ""}`} aria-label="Windows 应急响应边栏">
        <nav aria-label="Windows 应急响应模块">
          {groups.map((group) => <section className="wir-nav-group" key={group} aria-label={group}>
            <h2>{group}</h2>
            {WIN_IR_MODULES.filter((module) => module.group === group).map((module) => {
              const count = attentionCount(module.key);
              const active = activeTab === module.key && !setupView;
              return <button key={module.key} type="button" className={`nav-item win-ir-nav-item${active ? " active" : ""}`} aria-label={module.label} aria-current={active ? "page" : undefined} title={module.label} onClick={() => { navigate(module.key); if (showWorkspace) setSetupOpen(false); }}>
                <span className="nav-icon"><WinIrIcon name={module.key} size={18} /></span><strong>{module.label}</strong>
                {count ? <em className="win-ir-nav-count" aria-label={`${count} 条待关注线索`}>{count > 99 ? "99+" : count}</em> : null}
              </button>;
            })}
          </section>)}
        </nav>
        <div className="sidebar-rail-toggle win-ir-sidebar-foot">
          <button type="button" aria-label="接入管理" aria-expanded={setupView} title="接入管理" onClick={() => setSetupOpen(!setupOpen)}><WinIrIcon name="network" size={16} /><span>接入管理</span></button>
          <button type="button" aria-label="通道与传输" title="在独立窗口中打开通道与传输" onClick={() => openDock("tasks")}><WinIrIcon name="console" size={16} /><span>通道与传输</span></button>
          {onOpenSettings ? <button type="button" aria-label="界面设置" title="界面设置" onClick={(event) => onOpenSettings(event.currentTarget)}><WinIrIcon name="baseline" size={16} /><span>界面设置</span></button> : null}
          {onBackToWelcome ? <button type="button" data-testid="windows-back-welcome" aria-label="返回模块选择 / 切换至 Linux" title="返回模块选择 / 切换至 Linux" disabled={busy} onClick={onBackToWelcome}><span aria-hidden="true">←</span><span>切换工作台</span></button> : null}
          <button type="button" aria-label={rail ? "展开导航" : "收起导航"} aria-pressed={rail} title={rail ? "展开导航" : "收起导航"} onClick={() => setRail(!rail)}><span aria-hidden="true">{rail ? "»" : "«"}</span><span>{rail ? "展开导航" : "收起导航"}</span></button>
        </div>
        {sidebarActions}
      </aside>

      <div className={`win-ir-main${activeTab === "desktop" ? " is-desktop" : ""}`} ref={mainRef} onKeyDown={(event) => {
        if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "f") {
          const input = Array.from(mainRef.current?.querySelectorAll<HTMLInputElement>(".wir-search input") ?? []).find((element) => element.getClientRects().length > 0);
          if (input) { event.preventDefault(); input.focus(); input.select(); }
        }
      }}>
        {showWorkspace && !connected && !setupView && activeTab !== "desktop" && activeTab !== "playbooks" ? <div className="wir-session-bar is-disconnected" role="status">
          <span className="status-dot idle" aria-hidden="true" /><strong>连接已断开</strong><span className="wir-session-host">{host || "主机名称待采集"}</span><span className="wir-session-hint">旧快照仅供查看，远程操作已暂停</span>
          <button type="button" className="win-ir-btn" onClick={() => setSetupOpen(true)}>重新接入</button>
        </div> : null}
        {data.statusError ? <NoticeSummary source="连接状态" messages={[data.statusError]} summary="连接待核实 · 操作已暂停" severity="error"><button type="button" className="wir-link" onClick={() => void data.refresh().catch(() => undefined)}>重试连接状态</button></NoticeSummary> : null}
        {data.reconnect?.phase === "verifying" ? <div className="win-ir-notice" role="status"><span>采集通道已重新连接，正在核对是否仍是 {data.reconnect.host}；核对完成前显示的是重连前的结果。</span></div> : null}
        {data.reconnect?.phase === "kept" ? <TransientNotice source="Windows 应急响应" message={`已重新连接 ${data.reconnect.host}（按主机名、域和系统版本核对），保留原采集结果；可按需刷新。`} severity="success"><div className="win-ir-notice is-ok" role="status"><span>已重新连接 {data.reconnect.host}（按主机名、域和系统版本核对），保留了重连前采集的结果；各模块的采集时间不变，可按需刷新。</span><button type="button" className="wir-icon-button" aria-label="关闭重连提示" onClick={data.dismissReconnect}>×</button></div></TransientNotice> : null}
        {data.reconnect?.phase === "replaced" ? <TransientNotice source="Windows 应急响应" message={`重新连接的主机 ${data.reconnect.host} 与之前 ${data.reconnect.previous} 不同，已清空旧结果。`} severity="warning"><div className="win-ir-notice is-warn" role="status"><span>重新连接的主机（{data.reconnect.host}）与之前（{data.reconnect.previous}）不同，已清空旧结果。</span><button type="button" className="wir-icon-button" aria-label="关闭重连提示" onClick={data.dismissReconnect}>×</button></div></TransientNotice> : null}
        {data.reconnect?.phase === "failed" ? <div className="win-ir-notice is-warn" role="alert"><span>采集通道已重新连接，但未能核对是否仍是 {data.reconnect.host}：{data.reconnect.message} 当前显示的是重连前的结果。</span><button type="button" className="win-ir-btn" onClick={data.retryReconnect}>重试核对</button><button type="button" className="win-ir-btn" onClick={data.discardPrevious}>清空旧结果</button></div> : null}
        {data.error ? <TransientNotice source="Windows 应急响应" message={data.error} severity="error"><div className="win-ir-notice is-error" role="alert"><span>{data.error}</span><button type="button" className="wir-icon-button" aria-label="关闭错误提示" onClick={data.dismissError}>×</button></div></TransientNotice> : null}
        {data.notice ? <TransientNotice source="Windows 应急响应" message={data.notice} severity="info"><div className="win-ir-notice" role="status"><span>{data.notice}</span><button type="button" className="wir-icon-button" aria-label="关闭操作提示" onClick={data.dismissNotice}>×</button></div></TransientNotice> : null}
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
          {activeTab !== "desktop" && activeTab !== "playbooks" ? <ModuleHeader title={activeModule.label} description={activeModule.description} collectedAt={collectedTime(data.collectedAt[activeTab as CollectionTab])} busy={busy || !connected} actionLabel={activeModule.action} onCollect={collectCurrent}
            extra={<>
              {back ? <button type="button" className="win-ir-btn wir-back-link" onClick={() => navigate(back.from)}>← 返回{moduleLabel(back.from)}</button> : null}
              {activeTab === "files" ? <button type="button" className="win-ir-btn" onClick={() => openDock("files")}>接收与保存</button> : null}
              {activeTab !== "console" && activeTab !== "timeline" && data.snapshots[activeTab] ? <button type="button" className="win-ir-btn" onClick={() => void copy(JSON.stringify({ hostname: host, collectedAt: data.collectedAt[activeTab], module: activeTab, snapshot: data.snapshots[activeTab] }, null, 2))}>复制结果 JSON</button> : null}
            </>}
          /> : null}
          {data.collectionErrors[activeTab as CollectionTab] ? <NoticeSummary announce={false} source={`${activeModule.label}采集`} summary="上次未完成 · 查看原因" messages={[`上次采集未完成：${data.collectionErrors[activeTab as CollectionTab]}${data.snapshots[activeTab as CollectionTab] ? " 当前保留上一次成功采集的结果。" : ""}`]} severity="error"><button type="button" className="wir-link" disabled={busy || !connected} onClick={collectCurrent}>重试</button></NoticeSummary> : null}
          {WIN_IR_MODULES.filter((module) => visited.has(module.key)).map(({ key }) => <Activity key={key === "playbooks" ? key : `${data.snapshotKey}:${key}`} mode={key === activeTab ? "visible" : "hidden"}>
            {key === "playbooks" ? <WinIrPlaybooks connected={connected} busy={busy} onAction={openPlaybookAction} onCopy={(text) => void copy(text)} /> : null}
            {key === "desktop" ? <WinIrDesktop api={api.windowsRdp} covered={covered || setupOpen} canCopyScript={Boolean(data.filelessScript && writeClipboard)} onCopyScript={() => void copy(data.filelessScript)} /> : null}
            {key === "overview" ? <WinIrOverview snapshots={data.snapshots} collectedAt={data.collectedAt} busy={busy || !connected} onNavigate={(tab) => navigate(tab, true)} onGo={goTo} onCollectAll={() => void data.collectAll()} /> : null}
            {key === "baseline" ? <WinIrBaseline snapshot={data.snapshots.baseline ?? null} focus={focusFor(focus, "baseline")} busy={busy} connected={connected} onCopy={(text) => void copy(text)} onRemediate={(item) => configureBaseline([item.id])} onConfigure={() => configureBaseline((data.snapshots.baseline?.items ?? []).filter((item) => item.remediationAvailable && (item.status === "fail" || item.status === "warn")).map((item) => item.id))} /> : null}
            {key === "processes" ? <WinIrProcesses busy={busy} connected={connected} onInspect={data.inspectProcess} onKill={(process) => killProcess(process)} onKillTree={(process) => killProcess(process, true)} snapshot={data.snapshots.processes ?? null} network={data.snapshots.network ?? null} focus={focusFor(focus, "processes")} related={related} onCopy={(text) => void copy(text)} onFile={locateFile} onNetwork={(pid) => goTo({ tab: "network", pid })} /> : null}
            {key === "commands" ? <WinIrCommands snapshot={data.snapshots.commands ?? null} busy={busy} connected={connected} onCollect={() => void data.collect("commands")} onCopy={(text) => void copy(text)} onProcess={(pid) => goTo({ tab: "processes", pid })} onFile={locateFile} onEnableAudit={() => configureBaseline(["audit-process-creation", "process-command-line", "ps-scriptblock-logging"])} /> : null}
            {key === "network" ? <WinIrNetwork snapshot={data.snapshots.network ?? null} processes={data.snapshots.processes ?? null} busy={busy} connected={connected} focus={focusFor(focus, "network")} related={related} onCopy={(text) => void copy(text)} onProcess={(pid) => goTo({ tab: "processes", pid })} onFile={locateFile} onKillProcess={(process) => void killProcess(process)} /> : null}
            {key === "services" || key === "drivers" || key === "tasks" ? <WinIrInventory onInspect={entry=>setInventoryDetail({kind:key,entry,session:data.sessionKey,observedAt:data.snapshots[key]?.observedAt??"未取得"})} kind={key} snapshot={data.snapshots[key] ?? null} busy={busy} connected={connected} focus={inventoryFocus?.kind===key?inventoryFocus:null} onAction={(entry,operation)=>{if(data.sessionKey&&!busy&&entry.objectId)setControlSelection({kind:key,session:data.sessionKey,action:{objectId:entry.objectId,name:entry.name,operation}});}} onHistory={()=>{if(data.sessionKey&&!busy)setControlSelection({kind:key,session:data.sessionKey,action:null});}} onFile={locateFile} onCopy={(text) => void copy(text)} onRegistry={locateRegistry} onProcess={(pid) => goTo({tab:"processes",pid})} onCommand={(id) => { setCommandSuggestion({id,request:++requestId.current}); openDock("command"); }} /> : null}
            {key === "startup" ? <WinIrStartup snapshot={data.snapshots.startup ?? null} busy={busy} connected={connected} focus={focusFor(focus, "startup")} related={related} onCopy={(text) => void copy(text)} onFile={locateFile} onRegistry={locateRegistry} onRemove={(entry) => void removeStartup(entry)} onManage={(kind,entry)=>{setInventoryFocus({kind,name:entry.name,location:entry.location,request:++requestId.current});navigate(kind,true);}} /> : null}
            {key === "accounts" ? <WinIrAccounts snapshot={data.snapshots.accounts ?? null} busy={busy} connected={connected} focus={focusFor(focus, "accounts")} related={related} onCopy={(text) => void copy(text)} onLogs={(query) => goTo({ tab: "logs", query })} onDisable={(entry) => void disableAccount(entry)} onDelete={(entry) => void deleteAccount(entry)} /> : null}
            {key === "logs" ? <WinIrLogs onDirectory={(path) => { if (!busy && connected) { navigate("files", true); void data.collect("files", path); } }} snapshot={data.snapshots.logs ?? null} busy={busy || !connected} category={data.snapshots.logs?.categoryFilter ?? "all"} onCategory={(category) => void data.collect("logs", category)} focus={focusFor(focus, "logs")} onCopy={(text) => void copy(text)} /> : null}
            {key === "defender" ? <WinIrDefender snapshot={data.snapshots.defender ?? null} busy={busy} connected={connected} onCopy={(text) => void copy(text)} onFile={locateFile} /> : null}
            {key === "timeline" ? <WinIrTimeline snapshots={data.snapshots} onCopy={(text) => void copy(text)} onGo={goTo} /> : null}
            {key === "files" ? <WinIrFileManager snapshot={data.snapshots.files ?? null} busy={busy} connected={connected} revealPath={focus?.target.tab === "files" ? focus.target.path : null} related={related} onNavigate={(path) => void data.collect("files", path)} onPreview={data.previewFile} onInspectAccess={data.inspectFileAccess} onCommands={() => openDock("command")} onPull={(path) => void data.pullFile(path).then((received) => { if (received) openDock("files"); })} onDelete={(entry) => void deleteFile(entry)} onScanWebshells={(path) => { navigate("webshell", true); void data.collect("webshell", path); }} onCopy={(text) => void copy(text)} /> : null}
            {key === "webshell" ? <WinIrWebshell snapshot={data.snapshots.webshell ?? null} busy={busy} connected={connected} onScan={(path) => void data.collect("webshell", path)} onCopy={(text) => void copy(text)} onFile={locateFile} onPull={(path) => void data.pullFile(path).then((received) => { if (received) openDock("files"); })} /> : null}
            {key === "registry" ? <WinIrRegistry snapshot={data.snapshots.registry ?? null} busy={busy} connected={connected} focus={focusFor(focus, "registry")} related={related} onNavigate={(path) => void data.collect("registry", path)} onDeleteValue={(keyPath, value) => void deleteRegistryValue(keyPath, value)} onCopy={(text) => void copy(text)} /> : null}

          </Activity>)}
        </div> : null}
      </div>

      {processSelection ? <WinIrProcessChange {...processSelection} currentSession={data.sessionKey} onRequest={data.baselineRequest} onClose={() => setProcessSelection(null)} onRefresh={() => void data.collect("processes")} onResult={(message, failed) => failed ? data.setError(message) : data.setNotice(message)} /> : null}
      {inventoryDetail?<WinIrInventoryDetails selection={inventoryDetail} currentSession={data.sessionKey} onRequest={data.baselineRequest} onClose={()=>setInventoryDetail(null)} onCopy={text=>void copy(text)} onAction={operation=>{if(inventoryDetail.session===data.sessionKey&&data.sessionKey&&inventoryDetail.entry.objectId&&!busy){setInventoryDetail(null);setControlSelection({kind:inventoryDetail.kind,session:data.sessionKey,action:{objectId:inventoryDetail.entry.objectId,name:inventoryDetail.entry.name,operation}});}}}/>:null}
      {controlSelection?<WinIrControlChange selection={controlSelection} currentSession={data.sessionKey} onRequest={data.baselineRequest} onClose={()=>setControlSelection(null)} onRefresh={()=>void data.collect(controlSelection.kind)} onResult={(message,failed)=>failed?data.setError(message):data.setNotice(message)}/>:null}
      {baselineSelection ? <WinIrBaselineChanges items={data.snapshots.baseline?.items ?? []} initialIds={baselineSelection.ids} session={baselineSelection.session} currentSession={data.sessionKey} onRequest={data.baselineRequest} onClose={() => setBaselineSelection(null)} onRefresh={() => void data.collect("baseline")} /> : null}
      {confirm.dialog ? <DialogHost dialog={confirm.dialog} scrollMessage onResolve={confirm.resolve} /> : null}
    </section></NoticeScopeContext.Provider>
  );
}
