import type { WindowsIncidentPageHandle } from "./WindowsIncidentPage";
import { NotificationCenter, NotificationContext, NotificationOpenContext } from "./NotificationCenter";
import { useAppUpdate } from "./AppUpdate";
import {
  lazy,
  Suspense,
  useCallback,
  useEffect,
  useMemo,
  useReducer,
  useRef,
  useState,
} from "react";

import type {
  BootstrapResult,
  ConnectionSummary,
  PageDescriptor,
  PageGroup,
} from "../shared/contract";
import type { SshTargetSummary } from "../shared/ssh-contract";
import type { DatabasePageHandle } from "./DatabasePage";
import type { ConfigurationPageHandle } from "./ConfigurationPage";
import { ConnectionManager } from "./ConnectionManager";
import {
  CommandHistoryPanel,
  type CommandHistoryPanelHandle,
} from "./CommandHistoryPanel";
import {
  DisposalReportOverlay,
  type DisposalReportOverlayHandle,
} from "./DisposalReportOverlay";
import type { NotesHandle } from "./Notes";
import type { DisposalReportSnapshot } from "../shared/disposal-report-contract";
import {
  ApplicationLogOverlay,
  type ApplicationLogOverlayHandle,
} from "./ApplicationLogOverlay";
import { AppTitleBar } from "./AppTitleBar";
import { NavIcon } from "./nav-icons";
import { SidebarNav } from "./SidebarNav";
import { SidebarTarget } from "./SidebarTarget";
import { ThemePicker } from "./ThemePicker";
import { TargetRequiredBanner } from "./TargetRequiredBanner";
import { WelcomeView } from "./WelcomeView";
import { errorText } from "./error-text";
import { DialogHost } from "./DialogHost";
import { useConfirmDialog } from "./use-confirm-dialog";
import { applyUiPreferences, DEFAULT_UI_PREFERENCES, type UiPreferences } from "./ui-preferences";
import { isModalScrimActive, subscribeModalScrim } from "./modal-scrim";
import type { ConnectionManagerIntent } from "./ConnectionManager";
import {
  SettingsPanel,
  type SettingsPanelHandle,
} from "./SettingsPanel";
import { beforeSettingsTransition, toSettingsSaveInput } from "./settings-helpers";
import { NotificationStack } from "./NotificationStack";

/**
 * One chunk per page. Everything the registry can show used to be parsed at
 * boot even though the window shows a single page, which put the whole
 * application over the bundler's size warning. The files sit next to the
 * entry chunk, so a page still loads from local disk with nothing to fetch.
 */
const DatabasePage = lazy(async () => ({ default: (await import("./DatabasePage")).DatabasePage }));
const SecurityReference = lazy(async () => ({ default: (await import("./SecurityReference")).SecurityReference }));
const Notes = lazy(async () => ({ default: (await import("./Notes")).Notes }));
const ConfigurationPage = lazy(async () => ({ default: (await import("./ConfigurationPage")).ConfigurationPage }));
const SystemInfoPage = lazy(async () => ({ default: (await import("./SystemInfoPage")).SystemInfoPage }));
const AiHistoryPage = lazy(async () => ({ default: (await import("./AiHistoryPage")).AiHistoryPage }));
const CheckAuditPage = lazy(async () => ({ default: (await import("./CheckAuditPage")).CheckAuditPage }));
const IntegrityPage = lazy(async () => ({ default: (await import("./IntegrityPage")).IntegrityPage }));
const LogAnalysisPage = lazy(async () => ({ default: (await import("./LogAnalysisPage")).LogAnalysisPage }));
const PacketCapturePage = lazy(async () => ({ default: (await import("./PacketCapturePage")).PacketCapturePage }));
const JavaHotUpdatePage = lazy(async () => ({ default: (await import("./JavaHotUpdatePage")).JavaHotUpdatePage }));
const KubernetesPage = lazy(async () => ({ default: (await import("./KubernetesPage")).KubernetesPage }));
const DockerPage = lazy(async () => ({ default: (await import("./DockerPage")).DockerPage }));
const EmergencyCommandsPage = lazy(async () => ({ default: (await import("./EmergencyCommandsPage")).EmergencyCommandsPage }));
const ResponseEnginePage = lazy(async () => ({ default: (await import("./ResponseEnginePage")).ResponseEnginePage }));
const WindowsIncidentPage = lazy(async () => ({ default: (await import("./WindowsIncidentPage")).WindowsIncidentPage }));
import {
  initialNotificationState,
  notificationReducer,
  type NotificationIntent,
} from "./notification-state";
import {
  DEFAULT_THEME_ID,
  applyTheme,
  themeDefinition,
} from "./theme/theme";
import type { SettingsTheme } from "../shared/settings-contract";

interface ConnectionManagerRequest {
  connectionId: string | null;
  startCreating: boolean;
  intent?: ConnectionManagerIntent;
}

/** Not a backend page: the disconnected landing view rendered by App itself. */
export const WELCOME_PAGE_ID = "welcome";
export const WINDOWS_INCIDENT_PAGE_ID = "windows-incident";
/** Page the app opens once a target is bound from the welcome view. */
const FIRST_CONNECTED_PAGE_ID = "system-info";

const WINDOWS_PAGE_DESCRIPTOR: PageDescriptor = {
  id: WINDOWS_INCIDENT_PAGE_ID,
  group: "triage",
  title: "Windows 应急响应",
  icon: "⊞",
  capability: "local-workspace",
  summary: "Windows 应急响应独立工作台",
  primaryAction: "刷新状态",
  sections: [],
  migrationState: "ready",
};

const groupLabels: Record<PageGroup, string> = {
  target: "目标",
  triage: "摸底",
  investigation: "调查",
  operations: "运维",
  intelligence: "助手",
};

export interface ActiveSshTarget {
  bindingHandle: string;
  target: SshTargetSummary;
}

export function App() {
  const [bootstrap, setBootstrap] = useState<BootstrapResult | null>(null);
  const [connections, setConnections] = useState<ConnectionSummary[]>([]);
  const [connectionsError, setConnectionsError] = useState<string | null>(null);
  const acceptConnections = useCallback((list: ConnectionSummary[]) => {
    setConnections(list);
    setConnectionsError(null);
  }, []);
  // Landing state: without an SSH target every page is a "connect first" prompt,
  // so the app opens on the welcome view until a target is bound.
  const [activePageId, setActivePageId] = useState(WELCOME_PAGE_ID);
  const [historyRerun, setHistoryRerun] = useState<{ historyId: string; key: number } | null>(null);
  const historyRerunKeyRef = useRef(0);
  const [investigateTarget, setInvestigateTarget] =
    useState<{ kind: "container" | "pod"; name: string; key: number } | null>(null);
  const investigateKeyRef = useRef(0);
  const [favoriteIds, setFavoriteIds] = useState<string[]>([]);
  const [connectionManagerRequest, setConnectionManagerRequest] = useState<
    ConnectionManagerRequest | undefined
  >(undefined);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [commandHistoryOpen, setCommandHistoryOpen] = useState(false);
  const [disposalReportOpen, setDisposalReportOpen] = useState(false);
  const [applicationLogOpen, setApplicationLogOpen] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [notificationState, dispatchNotification] = useReducer(
    notificationReducer,
    initialNotificationState,
  );
  const [error, setError] = useState<string | null>(null);
  const appUpdate = useAppUpdate();
  const [themeId, setThemeId] = useState<SettingsTheme>(DEFAULT_THEME_ID);
  const [uiPreferences, setUiPreferences] = useState<UiPreferences>(DEFAULT_UI_PREFERENCES);
  const [navigationBusy, setNavigationBusy] = useState(false);
  const [railPreferred, setRailPreferred] = useState(false);
  const [activeTarget, setActiveTarget] = useState<ActiveSshTarget | null>(null);
  const windowsBusy = useRef(false);
  const windowsRef = useRef<WindowsIncidentPageHandle>(null);
  const acceptWindowsBusy = useCallback((busy: boolean) => { windowsBusy.current = busy; }, []);
  const [windowsChannelRequest, setWindowsChannelRequest] = useState(0);
  const [windowsTarget, setWindowsTarget] = useState<{ connected: boolean; hostname: string | null }>({ connected: false, hostname: null });
  const acceptWindowsTarget = useCallback((connected: boolean, hostname: string | null) => {
    setWindowsTarget((previous) => previous.connected === connected && previous.hostname === hostname ? previous : { connected, hostname });
  }, []);
  const [caseReport, setCaseReport] = useState<DisposalReportSnapshot | null>(null);
  const [disconnecting, setDisconnecting] = useState(false);
  const unsavedEditorsConfirm = useConfirmDialog();
  const [targetError, setTargetError] = useState<string | null>(null);
  // Page-level dialogs dim the page too, and main cannot see them from here.
  const [pageModalOpen, setPageModalOpen] = useState(isModalScrimActive);
  // Declared with the state it derives from: the theme effect below depends on it.
  const overlayOpen = connectionManagerRequest !== undefined || settingsOpen || commandHistoryOpen ||
    disposalReportOpen || applicationLogOpen || notificationsOpen;
  const databaseRef = useRef<DatabasePageHandle>(null);
  const configurationRef = useRef<ConfigurationPageHandle>(null);
  const notesRef = useRef<NotesHandle>(null);
  const settingsPanelRef = useRef<SettingsPanelHandle>(null);
  const commandHistoryPanelRef = useRef<CommandHistoryPanelHandle>(null);
  const disposalReportOverlayRef = useRef<DisposalReportOverlayHandle>(null);
  const applicationLogOverlayRef = useRef<ApplicationLogOverlayHandle>(null);
  const navigationPendingRef = useRef(false);
  const connectionManagerReturnFocusRef = useRef<HTMLElement | null>(null);
  const settingsReturnFocusRef = useRef<HTMLElement | null>(null);
  const commandHistoryReturnFocusRef = useRef<HTMLElement | null>(null);
  const disposalReportReturnFocusRef = useRef<HTMLElement | null>(null);
  const applicationLogReturnFocusRef = useRef<HTMLElement | null>(null);

  const publishNotification = useCallback((source: string, message: string, severity: import("./notification-state").NotificationSeverity, key?: string) => {
    dispatchNotification({type:"message",source,message,severity,key,now:Date.now()});
  }, []);
  useEffect(() => { if (notificationsOpen) dispatchNotification({type:"read"}); }, [notificationsOpen,notificationState.history]);
  useEffect(() => { if (!overlayOpen && !pageModalOpen) dispatchNotification({type:"resume",now:Date.now()}); }, [overlayOpen,pageModalOpen]);
  const unreadNotifications = notificationState.history.filter((item) => !item.read).length;
  const notificationButton = <button type="button" className="statusbar-button" data-testid="open-notifications" aria-label={`通知${unreadNotifications ? `，${unreadNotifications} 条未读` : ""}`} aria-haspopup="dialog" onClick={() => setNotificationsOpen(true)}><svg aria-hidden="true" width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4"><path d="M3 11h10l-1.4-2V6a3.6 3.6 0 0 0-7.2 0v3L3 11Z"/><path d="M6.2 13a1.8 1.8 0 0 0 3.6 0"/></svg> 通知{unreadNotifications ? <b className="notification-count">{unreadNotifications}</b> : null}</button>;
  const showNotification = useCallback((intent: NotificationIntent) => {
    dispatchNotification({ type: "show", intent, now: Date.now() });
  }, []);
  const applyThemeChoice = useCallback((value: unknown): SettingsTheme => {
    const applied = applyTheme(document.documentElement, value);
    setThemeId(applied);
    return applied;
  }, []);
  const syncThemeFromSettings = useCallback(() => {
    // Theme falls back to the default when settings are unavailable; the
    // bootstrap effect already surfaces backend startup failures.
    void window.lovelyhawk.loadSettings()
      .then((snapshot) => {
        applyThemeChoice(snapshot.theme);
        setUiPreferences(applyUiPreferences(document.documentElement, snapshot.ui));
      })
      .catch(() => undefined);
  }, [applyThemeChoice]);
  const chooseTheme = useCallback(async (wanted: SettingsTheme) => {
    const previous = themeId;
    if (wanted === previous) return;
    const next = applyThemeChoice(wanted);
    try {
      const snapshot = await window.lovelyhawk.loadSettings();
      await window.lovelyhawk.saveSettings({ ...toSettingsSaveInput(snapshot), theme: next });
    } catch {
      applyThemeChoice(previous);
      showNotification("operation-failed");
    }
  }, [applyThemeChoice, showNotification, themeId]);
  const dismissNotification = useCallback((id: string) => {
    dispatchNotification({ type: "dismiss", id });
  }, []);
  const expireNotifications = useCallback((now: number) => {
    dispatchNotification({ type: "expire", now });
  }, []);

  useEffect(() => window.lovelyhawk.onBeforeClose(async ({ unsavedEditors }) => {
    if (windowsBusy.current) { publishNotification("Windows 应急响应", "Windows 任务尚未结束。请等待当前项返回，或先中止后续项并核对结果，再关闭窗口。", "warning"); return false; }
    if (unsavedEditors > 0 && !(await unsavedEditorsConfirm.ask(
      "放弃编辑窗口里未保存的修改？",
      `还有 ${unsavedEditors} 个文件编辑窗口有没保存到服务器的修改。关闭 LovelyHawk 会一并关闭它们，这些修改会丢失。`,
      "放弃修改并关闭",
    ))) return false;
    if (commandHistoryOpen) await commandHistoryPanelRef.current?.beforeClose();
    if (disposalReportOpen) await disposalReportOverlayRef.current?.beforeClose();
    if (applicationLogOpen) applicationLogOverlayRef.current?.beforeClose();
    if (!(await beforeSettingsTransition(settingsOpen, settingsPanelRef.current))) {
      return false;
    }
    if (activePageId === "windows-incident" && !(await windowsRef.current?.beforeDeactivate() ?? true)) return false;
    if (activePageId === "notes") {
      return notesRef.current?.beforeDeactivate() ?? true;
    }
    if (activePageId === "database") return databaseRef.current?.beforeDeactivate() ?? true;
    if (activePageId === "config-generator") {
      return configurationRef.current?.beforeDeactivate() ?? true;
    }
    return true;
  }), [activePageId, applicationLogOpen, commandHistoryOpen, disposalReportOpen, settingsOpen, unsavedEditorsConfirm.ask]);

  useEffect(() => {
    syncThemeFromSettings();
  }, [syncThemeFromSettings]);

  useEffect(() => subscribeModalScrim(setPageModalOpen), []);

  useEffect(() => {
    // Main repaints the native title bar and themes new windows from this. The
    // OS draws the window controls above the page, so it also needs to know
    // when anything dims the page. Purely cosmetic: never block on it.
    void window.lovelyhawk
      .setWindowTheme({ theme: themeId, scrim: overlayOpen || pageModalOpen })
      .catch(() => undefined);
  }, [overlayOpen, pageModalOpen, themeId]);

  useEffect(() => {
    let active = true;
    // A connection store that cannot be read must not keep the operator out of
    // everything else (notes, the case library, the offline references); it is
    // shown where the connections would have been.
    const savedConnections = window.lovelyhawk.listConnections().then(
      (list) => ({ list, error: null }),
      (reason: unknown) => ({
        list: [],
        error: errorText(reason, "无法读取已保存的连接。"),
      }),
    );
    void Promise.all([window.lovelyhawk.bootstrap(), savedConnections])
      .then(([bootstrapResult, connectionResult]) => {
        if (!active) return;
        setBootstrap(bootstrapResult);
        setConnections(connectionResult.list);
        setConnectionsError(connectionResult.error);
        setFavoriteIds(bootstrapResult.securityReferenceFavoriteIds);
        window.lovelyhawk.notifyRendererReady();
      })
      .catch((reason: unknown) => {
        if (!active) return;
        setError(errorText(reason, "LovelyHawk 后端启动失败。"));
      });
    return () => {
      active = false;
    };
  }, []);

  const activePage = useMemo(
    () =>
      activePageId === WINDOWS_INCIDENT_PAGE_ID
        ? WINDOWS_PAGE_DESCRIPTOR
        : bootstrap?.pages.find((page) => page.id === activePageId) ?? null,
    [activePageId, bootstrap],
  );
  const waitingForTarget = activeTarget === null && activePage?.capability === "connected-target";
  const welcomeScreen = activePage === null && activeTarget === null && uiPreferences.showStatusBar;
  // The rail drops the target card, so it is only offered while the status
  // bar carries the target, its disconnect and the log and report entries.
  const rail = railPreferred && uiPreferences.showStatusBar;

  if (error !== null) {
    return (
      <div className="window-shell">
        <AppTitleBar section="启动失败" />
        <main className="startup-state error-state">
          <img src="./logo.png" alt="LovelyHawk" />
          <h1>无法启动 LovelyHawk</h1>
          <p>{error}</p>
        </main>
      </div>
    );
  }
  if (bootstrap === null) {
    return (
      <div className="window-shell">
        <AppTitleBar section="正在启动" />
        <main className="startup-state">
          <img src="./logo.png" alt="LovelyHawk" />
          <div className="loader" />
          <p>正在启动，读取程序旁的数据目录…</p>
        </main>
      </div>
    );
  }

  async function saveFavoriteIds(ids: string[]) {
    const result = await window.lovelyhawk.setSecurityReferenceFavorites(ids);
    setFavoriteIds(result.favoriteIds);
    return result.favoriteIds;
  }

  /** Resolves true once the page is shown, false when something kept it from leaving. */
  async function navigateTo(pageId: string): Promise<boolean> {
    if (windowsBusy.current) { setError("Windows 任务尚未结束，请先等待当前项返回或中止后续项。"); return false; }
    if (navigationPendingRef.current || pageId === activePageId) return false;
    navigationPendingRef.current = true;
    setNavigationBusy(true);
    try {
      if (!(await beforeSettingsTransition(settingsOpen, settingsPanelRef.current))) return false;
      if (settingsOpen) closeSettings();
      if (commandHistoryOpen) await closeCommandHistory();
      if (disposalReportOpen) await closeDisposalReport();
      if (applicationLogOpen) closeApplicationLog();
      if (activePageId === "notes") {
        const canDeactivate = await notesRef.current?.beforeDeactivate() ?? true;
        if (!canDeactivate) return false;
      }
      if (activePageId === "database" && !(await databaseRef.current?.beforeDeactivate() ?? true)) return false;
      if (activePageId === "config-generator") {
        const canDeactivate = await configurationRef.current?.beforeDeactivate() ?? true;
        if (!canDeactivate) return false;
      }
      if (activePageId === "windows-incident" && !(await windowsRef.current?.beforeDeactivate() ?? true)) return false;
      setActivePageId(pageId);
      return true;
    } finally {
      navigationPendingRef.current = false;
      setNavigationBusy(false);
    }
  }

  /**
   * Takes a command-history record back to the workbench: the panel closes and
   * the workbench finds that check in its own catalogue. Nothing runs until
   * the operator presses run there.
   */
  /**
   * Takes a container or pod from the Docker or Kubernetes page to the
   * workbench, chosen as where the checks run. Nothing runs until the
   * operator presses run there.
   */
  async function investigateIn(kind: "container" | "pod", name: string) {
    const key = ++investigateKeyRef.current;
    if (activePageId !== "emergency-commands" && !(await navigateTo("emergency-commands"))) return;
    setInvestigateTarget({ kind, name, key });
  }

  async function rerunHistoryCheck(historyId: string) {
    const key = ++historyRerunKeyRef.current;
    if (activePageId === "emergency-commands") {
      await closeCommandHistory();
    } else if (!(await navigateTo("emergency-commands"))) {
      return;
    }
    setHistoryRerun({ historyId, key });
  }

  async function disconnectTarget() {
    const bindingHandle = activeTarget?.bindingHandle;
    if (bindingHandle === undefined || disconnecting) return;
    setDisconnecting(true);
    try {
      // Disconnecting closes this connection's editor windows. If the count
      // cannot be read, ask anyway rather than risk unsaved text.
      const unsavedEditors = await window.lovelyhawk.unsavedEditorCount().catch(() => null);
      if (unsavedEditors !== 0 && !(await unsavedEditorsConfirm.ask(
        "放弃编辑窗口里未保存的修改？",
        unsavedEditors === null
          ? "无法确认文件编辑窗口里是否还有未保存的修改。断开连接会关闭这些窗口，未保存的修改会丢失。"
          : `还有 ${unsavedEditors} 个文件编辑窗口有没保存到服务器的修改。断开连接会关闭它们，这些修改会丢失。`,
        "放弃修改并断开",
      ))) return;
      if (activePageId === "database" && !(await databaseRef.current?.beforeDeactivate() ?? true)) return;
      if (activePageId === "config-generator" && !(await configurationRef.current?.beforeDeactivate() ?? true)) return;
      if (commandHistoryOpen) await closeCommandHistory();
      if (disposalReportOpen) await closeDisposalReport();
      if (applicationLogOpen) closeApplicationLog();
      const outcome = await window.lovelyhawk.disconnectSshBinding(bindingHandle);
      if (!outcome.disconnected) throw new Error("SSH 目标断开未被确认。");
      setActiveTarget((current) => clearDisconnectedTarget(current, bindingHandle));
      setTargetError(null);
    } catch (reason: unknown) {
      setTargetError(errorText(reason, "SSH 目标断开失败。"));
    } finally {
      setDisconnecting(false);
    }
  }

  async function openSshTerminal() {
    if (activeTarget === null) return;
    try {
      await window.lovelyhawk.openSshTerminal();
      setTargetError(null);
    } catch {
      setTargetError("无法打开当前 SSH 目标的终端。");
    }
  }

  async function acceptConnectedTarget(bindingHandle: string, target: SshTargetSummary) {
    if (disposalReportOpen) await closeDisposalReport();
    if (applicationLogOpen) closeApplicationLog();
    setActiveTarget({ bindingHandle, target });
    setTargetError(null);
    // Leaving the welcome view needs no dirty-editor handshake: it owns no
    // editor. Any other page the user chose stays where it is.
    setActivePageId((current) => (current === WELCOME_PAGE_ID ? FIRST_CONNECTED_PAGE_ID : current));
  }

  async function openConnectionManager(
    request: ConnectionManagerRequest,
    returnFocus: HTMLElement,
  ) {
    if (activePageId === "database" && !(await databaseRef.current?.beforeDeactivate() ?? true)) return;
    if (activePageId === "config-generator" && !(await configurationRef.current?.beforeDeactivate() ?? true)) return;
    if (settingsOpen || commandHistoryOpen || disposalReportOpen || applicationLogOpen) return;
    connectionManagerReturnFocusRef.current = returnFocus;
    setConnectionManagerRequest(request);
  }

  function closeConnectionManager() {
    const returnFocus = connectionManagerReturnFocusRef.current;
    connectionManagerReturnFocusRef.current = null;
    setConnectionManagerRequest(undefined);
    requestAnimationFrame(() => {
      if (returnFocus?.isConnected) returnFocus.focus();
    });
  }

  function openSettings(returnFocus: HTMLElement) {
    if (connectionManagerRequest !== undefined || settingsOpen || commandHistoryOpen || disposalReportOpen || applicationLogOpen) return;
    settingsReturnFocusRef.current = returnFocus;
    setSettingsOpen(true);
  }

  function closeSettings() {
    const returnFocus = settingsReturnFocusRef.current;
    settingsReturnFocusRef.current = null;
    setSettingsOpen(false);
    requestAnimationFrame(() => {
      if (returnFocus?.isConnected) returnFocus.focus();
    });
  }

  function openCommandHistory(returnFocus: HTMLElement) {
    if (connectionManagerRequest !== undefined || settingsOpen || commandHistoryOpen || disposalReportOpen || applicationLogOpen) return;
    commandHistoryReturnFocusRef.current = returnFocus;
    setCommandHistoryOpen(true);
  }

  async function closeCommandHistory() {
    await commandHistoryPanelRef.current?.beforeClose();
    const returnFocus = commandHistoryReturnFocusRef.current;
    commandHistoryReturnFocusRef.current = null;
    setCommandHistoryOpen(false);
    requestAnimationFrame(() => {
      if (returnFocus?.isConnected) returnFocus.focus();
    });
  }

  function openDisposalReport(returnFocus: HTMLElement, snapshot: DisposalReportSnapshot | null = null) {
    if (connectionManagerRequest !== undefined || settingsOpen || commandHistoryOpen || disposalReportOpen || applicationLogOpen) return;
    disposalReportReturnFocusRef.current = returnFocus;
    setCaseReport(snapshot);
    setDisposalReportOpen(true);
  }

  async function closeDisposalReport() {
    await disposalReportOverlayRef.current?.beforeClose();
    const returnFocus = disposalReportReturnFocusRef.current;
    disposalReportReturnFocusRef.current = null;
    setDisposalReportOpen(false);
    setCaseReport(null);
    requestAnimationFrame(() => {
      if (returnFocus?.isConnected) returnFocus.focus();
    });
  }

  function openApplicationLog(returnFocus: HTMLElement) {
    if (connectionManagerRequest !== undefined || settingsOpen || commandHistoryOpen ||
      disposalReportOpen || applicationLogOpen) return;
    applicationLogReturnFocusRef.current = returnFocus;
    setApplicationLogOpen(true);
  }

  function finishApplicationLogClose() {
    const returnFocus = applicationLogReturnFocusRef.current;
    applicationLogReturnFocusRef.current = null;
    setApplicationLogOpen(false);
    requestAnimationFrame(() => {
      if (returnFocus?.isConnected) returnFocus.focus();
    });
  }

  function closeApplicationLog() {
    applicationLogOverlayRef.current?.beforeClose();
    finishApplicationLogClose();
  }


  const sidebarActions = <div className="sidebar-footer">
    {notificationButton}
    {appUpdate.button}
    <button type="button" data-testid="sidebar-open-application-log" onClick={(event) => openApplicationLog(event.currentTarget)}>应用日志</button>
    <button type="button" data-testid="sidebar-open-disposal-report" onClick={(event) => openDisposalReport(event.currentTarget)}>处置报告</button>
  </div>;
  return (
    <NotificationContext.Provider value={publishNotification}><NotificationOpenContext.Provider value={() => setNotificationsOpen(true)}><div className={uiPreferences.showStatusBar ? "window-shell" : "window-shell no-statusbar"}>
      <AppTitleBar
        section={activePage === null ? "欢迎" : activePage.title}
        backgroundHidden={overlayOpen}
        actions={{
          onOpenConnections: (returnFocus) =>
            openConnectionManager({ connectionId: null, startCreating: false }, returnFocus),
          sshTerminalDisabled: activeTarget === null,
          onOpenSshTerminal: () => void openSshTerminal(),
          onOpenCommandHistory: openCommandHistory,
          onOpenSettings: openSettings,
        }}
      />
      {/* The welcome view is a start screen of its own: nothing is connected,
          its cards already offer connecting and every page that needs no
          target, so the sidebar steps aside. It stays when the status bar is
          hidden, because then the sidebar carries the log, the report and
          any connection error. */}
      <div className={["app-frame", welcomeScreen ? "is-welcome" : "", rail ? "is-rail" : ""].filter(Boolean).join(" ")}>
      <aside className={rail ? "sidebar is-rail" : "sidebar"} aria-hidden={overlayOpen ? true : undefined} inert={overlayOpen ? true : undefined}>
        {rail ? null : (
          <SidebarTarget
            target={activeTarget?.target ?? null}
            disconnecting={disconnecting}
            onConnect={(returnFocus) =>
              openConnectionManager({ connectionId: null, startCreating: false }, returnFocus)}
            onOpenTerminal={() => void openSshTerminal()}
            onDisconnect={() => void disconnectTarget()}
            error={uiPreferences.showStatusBar ? null : targetError}
          />
        )}
        <div className="nav-switch-row">
          <button
            type="button"
            className="nav-item nav-switch"
            disabled={navigationBusy}
            aria-label={rail ? "切换至 Windows 应急" : undefined}
            title="切换至 Windows 应急响应工作台"
            onClick={() => void navigateTo(WINDOWS_INCIDENT_PAGE_ID)}
          >
            <span className="nav-icon"><NavIcon pageId="windows-incident" glyph="⊞" /></span>
            <strong>切换至 Windows 应急</strong>
          </button>
        </div>
        <SidebarNav
          pages={bootstrap.pages}
          groupLabels={groupLabels}
          activePageId={activePageId}
          targetConnected={activeTarget !== null}
          busy={navigationBusy}
          rail={rail}
          onNavigate={(pageId) => void navigateTo(pageId)}
        />
        {uiPreferences.showStatusBar ? (
          <div className="sidebar-rail-toggle">
            <button
              type="button"
              data-testid="sidebar-rail-toggle"
              aria-pressed={rail}
              aria-label={rail ? "展开导航" : "收起导航"}
              title={rail ? "展开导航" : "收起为图标栏"}
              onClick={() => setRailPreferred((value) => !value)}
            >
              <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <rect x="1.8" y="2.4" width="12.4" height="11.2" rx="2" />
                <path d="M6 2.4v11.2" />
                <path d={rail ? "m9 6.2 1.8 1.8L9 9.8" : "m10.8 6.2-1.8 1.8 1.8 1.8"} />
              </svg>
              {rail ? null : <span>收起导航</span>}
            </button>
          </div>
        ) : null}
        {!uiPreferences.showStatusBar && activePageId !== WINDOWS_INCIDENT_PAGE_ID ? sidebarActions : null}
      </aside>

      <div className="workspace" aria-hidden={overlayOpen ? true : undefined} inert={overlayOpen ? true : undefined}>
        <main className="content">
          {waitingForTarget && activePage !== null ? (
            <TargetRequiredBanner
              pageTitle={activePage.title}
              summary={activePage.summary}
              sections={activePage.sections}
              icon={<NavIcon pageId={activePage.id} glyph={activePage.icon} />}
              connections={connections}
              onConnect={(connectionId, returnFocus) =>
                openConnectionManager(
                  connectionId === null
                    // With nothing saved, the only way forward is a new one.
                    ? { connectionId: null, startCreating: connections.length === 0 }
                    : { connectionId, startCreating: false, intent: "connect" },
                  returnFocus,
                )}
            />
          ) : null}
          {/* While it waits for a target the page stays mounted, hidden: its
              state, a capture it must stop, an unsaved edit, all keep their
              own lifecycle. The panel above is what shows. */}
          <div className="content-page" hidden={waitingForTarget}>
          <Suspense fallback={<div className="content-page-loading" role="status">正在打开页面…</div>}>
          {activePage === null ? (
            <WelcomeView
              connections={connections}
              connectionsError={connectionsError}
              offlinePages={bootstrap.pages.filter((page) =>
                page.capability !== "connected-target")}
              onNavigate={(pageId) => void navigateTo(pageId)}
              onOpenWindowsIncident={() => void navigateTo(WINDOWS_INCIDENT_PAGE_ID)}
              onOpenConnections={(returnFocus) =>
                openConnectionManager({ connectionId: null, startCreating: false }, returnFocus)}
              onConnectionAction={(connectionId, intent, returnFocus) =>
                openConnectionManager({ connectionId, startCreating: false, intent }, returnFocus)}
              onCreateConnection={(returnFocus) =>
                openConnectionManager({ connectionId: null, startCreating: true }, returnFocus)}
            />
          ) : activePage.id === "security-reference" ? (
            <SecurityReference favoriteIds={favoriteIds} onFavoriteIdsChange={saveFavoriteIds} />
          ) : activePage.id === "notes" ? (
            <Notes ref={notesRef} />
          ) : activePage.id === "database" ? (
            <DatabasePage ref={databaseRef} api={window.lovelyhawk} bindingHandle={activeTarget?.bindingHandle ?? null}
              targetLabel={activeTarget === null ? "未连接主机" : `${activeTarget.target.username}@${activeTarget.target.host}:${activeTarget.target.port}`} />
          ) : activePage.id === "config-generator" ? (
            <ConfigurationPage
              ref={configurationRef}
              onCopyRecord={window.lovelyhawk.writeClipboard}
              bindingHandle={activeTarget?.bindingHandle ?? null}
              api={window.lovelyhawk}
            />
          ) : activePage.id === "system-info" ? (
            <SystemInfoPage
              connection={activeTarget}
              api={window.lovelyhawk}
              writeClipboard={window.lovelyhawk.writeClipboard}
              openFile={window.lovelyhawk.openSystemInfoFile}
            />
          ) : activePage.id === "ai-history" ? (
            <AiHistoryPage
              api={window.lovelyhawk}
              writeClipboard={window.lovelyhawk.writeClipboard}
            />
          ) : activePage.id === "check-audit" ? (
            <CheckAuditPage
              bindingHandle={activeTarget?.bindingHandle ?? null}
              api={window.lovelyhawk}
              writeClipboard={window.lovelyhawk.writeClipboard}
            />
          ) : activePage.id === "integrity" ? (
            <IntegrityPage
              bindingHandle={activeTarget?.bindingHandle ?? null}
              api={window.lovelyhawk}
            />
          ) : activePage.id === "log-analysis" ? (
            <LogAnalysisPage
              bindingHandle={activeTarget?.bindingHandle ?? null}
              api={window.lovelyhawk}
            />
          ) : activePage.id === "packet-capture" ? (
            <PacketCapturePage
              bindingHandle={activeTarget?.bindingHandle ?? null}
              api={window.lovelyhawk}
              evidenceApi={window.lovelyhawk}
            />
          ) : activePage.id === "kubernetes" ? (
            <KubernetesPage
              bindingHandle={activeTarget?.bindingHandle ?? null}
              api={window.lovelyhawk}
              onInvestigate={(kind, name) => void investigateIn(kind, name)}
            />
          ) : activePage.id === "docker" ? (
            <DockerPage
              bindingHandle={activeTarget?.bindingHandle ?? null}
              api={window.lovelyhawk}
              onInvestigate={(kind, name) => void investigateIn(kind, name)}
            />
          ) : activePage.id === "emergency-commands" ? (
            <EmergencyCommandsPage
              bindingHandle={activeTarget?.bindingHandle ?? null}
              api={window.lovelyhawk}
              rerun={historyRerun}
              runIn={investigateTarget}
            />
          ) : activePage.id === "response-engine" ? (
            <ResponseEnginePage
              bindingHandle={activeTarget?.bindingHandle ?? null}
              api={window.lovelyhawk}
            />
          ) : activePage.id === "java-hot-update" ? (
            <JavaHotUpdatePage
              bindingHandle={activeTarget?.bindingHandle ?? null}
              api={window.lovelyhawk}
            />
          ) : activePage.id === "windows-incident" ? (
            <WindowsIncidentPage ref={windowsRef} onBusyChange={acceptWindowsBusy} onOpenSettings={openSettings} covered={overlayOpen || pageModalOpen || notificationState.notifications.length > 0} channelOpenRequest={windowsChannelRequest}
              sidebarActions={uiPreferences.showStatusBar ? null : sidebarActions}
              api={window.lovelyhawk}
              writeClipboard={window.lovelyhawk.writeClipboard}
              onConnectionChange={acceptWindowsTarget}
              onBackToWelcome={() => void navigateTo(WELCOME_PAGE_ID)}
            />
          ) : (
            <MigrationPlaceholder page={activePage} />
          )}
          </Suspense>
          </div>
        </main>
      </div>
      {connectionManagerRequest !== undefined ? (
        <ConnectionManager
          initialConnectionId={connectionManagerRequest.connectionId}
          startCreating={connectionManagerRequest.startCreating}
          {...(connectionManagerRequest.intent === undefined
            ? {}
            : { initialIntent: connectionManagerRequest.intent })}
          onClose={closeConnectionManager}
          onConnectionsChanged={acceptConnections}
          onTargetConnected={acceptConnectedTarget}
        />
      ) : settingsOpen ? (
        <SettingsPanel
          ref={settingsPanelRef}
          api={window.lovelyhawk}
          onClose={closeSettings}
          onSaved={() => {
            showNotification("settings-saved");
            syncThemeFromSettings();
          }}
          returnFocusElement={settingsReturnFocusRef.current}
        />
      ) : commandHistoryOpen ? (
        <CommandHistoryPanel
          ref={commandHistoryPanelRef}
          activeTarget={activeTarget}
          api={window.lovelyhawk}
          onClose={closeCommandHistory}
          returnFocusElement={commandHistoryReturnFocusRef.current}
          writeClipboard={window.lovelyhawk.writeClipboard}
          onRerunCheck={rerunHistoryCheck}
        />
      ) : disposalReportOpen ? (
        <DisposalReportOverlay
          ref={disposalReportOverlayRef}
          activeTarget={activeTarget}
          fixedReport={caseReport}
          api={window.lovelyhawk}
          onClose={closeDisposalReport}
          returnFocusElement={disposalReportReturnFocusRef.current}
          writeClipboard={window.lovelyhawk.writeClipboard}
        />
      ) : applicationLogOpen ? (
        <ApplicationLogOverlay
          ref={applicationLogOverlayRef}
          api={window.lovelyhawk}
          onClose={finishApplicationLogClose}
          returnFocusElement={applicationLogReturnFocusRef.current}
          writeClipboard={window.lovelyhawk.writeClipboard}
          onCopied={() => showNotification("application-log-copied")}
        />
      ) : null}
      {notificationsOpen ? <NotificationCenter history={notificationState.history} omitted={notificationState.omitted} onClose={() => setNotificationsOpen(false)} onClear={() => dispatchNotification({type:"clear"})} onRemove={(id) => dispatchNotification({type:"remove",id})} /> : null}
      <NotificationStack
        notifications={notificationState.notifications}
        modalOpen={overlayOpen || pageModalOpen}
        onDismiss={dismissNotification}
        onExpire={expireNotifications}
      />
      {unsavedEditorsConfirm.dialog !== null ? (
        <DialogHost dialog={unsavedEditorsConfirm.dialog} onResolve={unsavedEditorsConfirm.resolve} />
      ) : null}
      </div>
      {uiPreferences.showStatusBar ? (
      <footer
        className="window-statusbar"
        aria-label="状态栏"
        aria-hidden={overlayOpen ? true : undefined}
        inert={overlayOpen ? true : undefined}
      >
        <div className="statusbar-group">
          {notificationButton}
          {activePageId === WINDOWS_INCIDENT_PAGE_ID ? <button type="button" className="statusbar-button" data-testid="open-windows-channel" onClick={() => setWindowsChannelRequest((n) => n + 1)}>通道与传输</button> : null}
          <button type="button" className="statusbar-button" data-testid="open-application-log" onClick={(event) => openApplicationLog(event.currentTarget)}>应用日志</button>
          <button type="button" className="statusbar-button" data-testid="open-disposal-report" onClick={(event) => openDisposalReport(event.currentTarget)}>处置报告</button>
        </div>
        <div className="statusbar-target">
          <span className={(activePageId === WINDOWS_INCIDENT_PAGE_ID ? windowsTarget.connected : activeTarget !== null) ? "status-dot" : "status-dot idle"} />
          <span>{activePageId === WINDOWS_INCIDENT_PAGE_ID ? (windowsTarget.connected ? windowsTarget.hostname ?? "Windows 会话已连接" : "Windows 会话未连接") : activeTarget === null ? "未连接目标" : targetLabel(activeTarget.target)}</span>
          {activePageId !== WINDOWS_INCIDENT_PAGE_ID && activeTarget !== null ? (
            <button
              type="button"
              className="statusbar-button statusbar-disconnect"
              data-testid="disconnect-target"
              disabled={disconnecting}
              onClick={() => void disconnectTarget()}
            >
              {disconnecting ? "断开中…" : "断开"}
            </button>
          ) : null}
          {activePageId !== WINDOWS_INCIDENT_PAGE_ID && targetError !== null ? <span className="statusbar-error" role="alert">{targetError}</span> : null}
        </div>
        <div className="statusbar-group statusbar-end">
          <ThemePicker themeId={themeId} onSelect={(next) => void chooseTheme(next)} />
          {appUpdate.button}
        </div>
      </footer>
      ) : null}
      {appUpdate.dialog}
    </div></NotificationOpenContext.Provider></NotificationContext.Provider>
  );
}

export function targetLabel(target: SshTargetSummary): string {
  return `${target.username}@${target.host}:${target.port}`;
}

export function clearDisconnectedTarget(
  current: ActiveSshTarget | null,
  disconnectedBindingHandle: string,
): ActiveSshTarget | null {
  return current?.bindingHandle === disconnectedBindingHandle ? null : current;
}

function MigrationPlaceholder({ page }: { page: PageDescriptor }) {
  return (
    <section className="page placeholder-page">
      <header className="page-heading">
        <div><p className="eyebrow">尚未开放</p><h1>{page.title}</h1><p>{page.summary}</p></div>
        <span className="pending-badge">规划中</span>
      </header>
      <div className="placeholder-card">
        <span><NavIcon pageId={page.id} glyph={page.icon} /></span>
        <h2>这个功能还没有开放</h2>
        <p>这里暂时不能执行任何操作，也不会连接目标。功能完成并通过验证后，会在这里提供完整界面。</p>
        <div>{page.sections.map((section) => <span key={section}>{section}</span>)}</div>
      </div>
    </section>
  );
}
