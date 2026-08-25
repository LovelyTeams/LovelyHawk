import { useCallback, useEffect, useMemo, useReducer, useRef, useState } from "react";

import type {
  BootstrapResult,
  ConnectionSummary,
  PageDescriptor,
  PageGroup,
} from "../shared/contract";
import type { SshTargetSummary } from "../shared/ssh-contract";
import {
  ConfigGeneratorPage,
  type ConfigGeneratorPageHandle,
} from "./ConfigGeneratorPage";
import { ConnectionManager } from "./ConnectionManager";
import {
  CommandHistoryPanel,
  type CommandHistoryPanelHandle,
} from "./CommandHistoryPanel";
import {
  DisposalReportOverlay,
  type DisposalReportOverlayHandle,
} from "./DisposalReportOverlay";
import { AiHistoryPage } from "./AiHistoryPage";
import { Notes, type NotesHandle } from "./Notes";
import { SecurityReference } from "./SecurityReference";
import { BaselinePage } from "./BaselinePage";
import { FirewallPage } from "./FirewallPage";
import { MiddlewarePage } from "./MiddlewarePage";
import { CheckAuditPage } from "./CheckAuditPage";
import { IntegrityPage } from "./IntegrityPage";
import { KubernetesPage } from "./KubernetesPage";
import { DockerPage } from "./DockerPage";
import { LogAnalysisPage } from "./LogAnalysisPage";
import { EmergencyCommandsPage } from "./EmergencyCommandsPage";
import { PacketCapturePage } from "./PacketCapturePage";
import { QuickDetectionPage } from "./QuickDetectionPage";
import {
  ApplicationLogOverlay,
  type ApplicationLogOverlayHandle,
} from "./ApplicationLogOverlay";
import { SnapshotPage } from "./SnapshotPage";
import { SystemInfoPage } from "./SystemInfoPage";
import { AppTitleBar } from "./AppTitleBar";
import { WelcomeView } from "./WelcomeView";
import { isModalScrimActive, subscribeModalScrim } from "./modal-scrim";
import type { ConnectionManagerIntent } from "./ConnectionManager";
import {
  SettingsPanel,
  type SettingsPanelHandle,
} from "./SettingsPanel";
import { beforeSettingsTransition, toSettingsSaveInput } from "./settings-helpers";
import { NotificationStack } from "./NotificationStack";
import {
  initialNotificationState,
  notificationReducer,
  type NotificationIntent,
} from "./notification-state";
import {
  DEFAULT_THEME_ID,
  applyTheme,
  nextThemeId,
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
/** Page the app opens once a target is bound from the welcome view. */
const FIRST_CONNECTED_PAGE_ID = "system-info";

const groupLabels: Record<PageGroup, string> = {
  target: "目标",
  triage: "摸底",
  investigation: "调查",
  response: "处置",
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
  // Landing state: without an SSH target every page is a "connect first" prompt,
  // so the app opens on the welcome view until a target is bound.
  const [activePageId, setActivePageId] = useState(WELCOME_PAGE_ID);
  const [favoriteIds, setFavoriteIds] = useState<string[]>([]);
  const [connectionManagerRequest, setConnectionManagerRequest] = useState<
    ConnectionManagerRequest | undefined
  >(undefined);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [commandHistoryOpen, setCommandHistoryOpen] = useState(false);
  const [disposalReportOpen, setDisposalReportOpen] = useState(false);
  const [applicationLogOpen, setApplicationLogOpen] = useState(false);
  const [notificationState, dispatchNotification] = useReducer(
    notificationReducer,
    initialNotificationState,
  );
  const [error, setError] = useState<string | null>(null);
  const [themeId, setThemeId] = useState<SettingsTheme>(DEFAULT_THEME_ID);
  const [navigationBusy, setNavigationBusy] = useState(false);
  const [activeTarget, setActiveTarget] = useState<ActiveSshTarget | null>(null);
  const [disconnecting, setDisconnecting] = useState(false);
  const [targetError, setTargetError] = useState<string | null>(null);
  // Page-level dialogs dim the page too, and main cannot see them from here.
  const [pageModalOpen, setPageModalOpen] = useState(isModalScrimActive);
  // Declared with the state it derives from: the theme effect below depends on it.
  const overlayOpen = connectionManagerRequest !== undefined || settingsOpen || commandHistoryOpen ||
    disposalReportOpen || applicationLogOpen;
  const configGeneratorRef = useRef<ConfigGeneratorPageHandle>(null);
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
    void window.lovelyres.loadSettings()
      .then((snapshot) => applyThemeChoice(snapshot.theme))
      .catch(() => undefined);
  }, [applyThemeChoice]);
  const cycleTheme = useCallback(async () => {
    const previous = themeId;
    const next = applyThemeChoice(nextThemeId(previous));
    try {
      const snapshot = await window.lovelyres.loadSettings();
      await window.lovelyres.saveSettings({ ...toSettingsSaveInput(snapshot), theme: next });
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

  useEffect(() => window.lovelyres.onBeforeClose(async () => {
    if (commandHistoryOpen) await commandHistoryPanelRef.current?.beforeClose();
    if (disposalReportOpen) await disposalReportOverlayRef.current?.beforeClose();
    if (applicationLogOpen) applicationLogOverlayRef.current?.beforeClose();
    if (!(await beforeSettingsTransition(settingsOpen, settingsPanelRef.current))) {
      return false;
    }
    if (activePageId === "notes") {
      return notesRef.current?.beforeDeactivate() ?? true;
    }
    if (activePageId === "config-generator") {
      return configGeneratorRef.current?.beforeDeactivate() ?? true;
    }
    return true;
  }), [activePageId, applicationLogOpen, commandHistoryOpen, disposalReportOpen, settingsOpen]);

  useEffect(() => {
    syncThemeFromSettings();
  }, [syncThemeFromSettings]);

  useEffect(() => subscribeModalScrim(setPageModalOpen), []);

  useEffect(() => {
    // Main repaints the native title bar and themes new windows from this. The
    // OS draws the window controls above the page, so it also needs to know
    // when anything dims the page. Purely cosmetic: never block on it.
    void window.lovelyres
      .setWindowTheme({ theme: themeId, scrim: overlayOpen || pageModalOpen })
      .catch(() => undefined);
  }, [overlayOpen, pageModalOpen, themeId]);

  useEffect(() => {
    let active = true;
    void Promise.all([window.lovelyres.bootstrap(), window.lovelyres.listConnections()])
      .then(([bootstrapResult, connectionResult]) => {
        if (!active) return;
        setBootstrap(bootstrapResult);
        setConnections(connectionResult);
        setFavoriteIds(bootstrapResult.securityReferenceFavoriteIds);
        window.lovelyres.notifyRendererReady();
      })
      .catch((reason: unknown) => {
        if (!active) return;
        setError(reason instanceof Error ? reason.message : "LovelyRes 后端启动失败。");
      });
    return () => {
      active = false;
    };
  }, []);

  const activePage = useMemo(
    () => bootstrap?.pages.find((page) => page.id === activePageId) ?? null,
    [activePageId, bootstrap],
  );

  if (error !== null) {
    return (
      <div className="window-shell">
        <AppTitleBar section="启动失败" />
        <main className="startup-state error-state">
          <img src="./logo.png" alt="LovelyRes" />
          <h1>无法启动 LovelyRes</h1>
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
          <img src="./logo.png" alt="LovelyRes" />
          <div className="loader" />
          <p>正在启动便携 Rust 后端…</p>
        </main>
      </div>
    );
  }

  async function saveFavoriteIds(ids: string[]) {
    const result = await window.lovelyres.setSecurityReferenceFavorites(ids);
    setFavoriteIds(result.favoriteIds);
    return result.favoriteIds;
  }

  async function navigateTo(pageId: string) {
    if (navigationPendingRef.current || pageId === activePageId) return;
    navigationPendingRef.current = true;
    setNavigationBusy(true);
    try {
      if (!(await beforeSettingsTransition(settingsOpen, settingsPanelRef.current))) return;
      if (settingsOpen) closeSettings();
      if (commandHistoryOpen) await closeCommandHistory();
      if (disposalReportOpen) await closeDisposalReport();
      if (applicationLogOpen) closeApplicationLog();
      if (activePageId === "notes") {
        const canDeactivate = await notesRef.current?.beforeDeactivate() ?? true;
        if (!canDeactivate) return;
      }
      if (activePageId === "config-generator") {
        const canDeactivate = await configGeneratorRef.current?.beforeDeactivate() ?? true;
        if (!canDeactivate) return;
      }
      setActivePageId(pageId);
    } finally {
      navigationPendingRef.current = false;
      setNavigationBusy(false);
    }
  }

  async function disconnectTarget() {
    const bindingHandle = activeTarget?.bindingHandle;
    if (bindingHandle === undefined || disconnecting) return;
    setDisconnecting(true);
    try {
      if (commandHistoryOpen) await closeCommandHistory();
      if (disposalReportOpen) await closeDisposalReport();
      if (applicationLogOpen) closeApplicationLog();
      const outcome = await window.lovelyres.disconnectSshBinding(bindingHandle);
      if (!outcome.disconnected) throw new Error("SSH 目标断开未被确认。");
      setActiveTarget((current) => clearDisconnectedTarget(current, bindingHandle));
      setTargetError(null);
    } catch (reason: unknown) {
      setTargetError(reason instanceof Error ? reason.message : "SSH 目标断开失败。");
    } finally {
      setDisconnecting(false);
    }
  }

  async function openSshTerminal() {
    if (activeTarget === null) return;
    try {
      await window.lovelyres.openSshTerminal();
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

  function openConnectionManager(
    request: ConnectionManagerRequest,
    returnFocus: HTMLElement,
  ) {
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

  function openDisposalReport(returnFocus: HTMLElement) {
    if (connectionManagerRequest !== undefined || settingsOpen || commandHistoryOpen || disposalReportOpen || applicationLogOpen) return;
    disposalReportReturnFocusRef.current = returnFocus;
    setDisposalReportOpen(true);
  }

  async function closeDisposalReport() {
    await disposalReportOverlayRef.current?.beforeClose();
    const returnFocus = disposalReportReturnFocusRef.current;
    disposalReportReturnFocusRef.current = null;
    setDisposalReportOpen(false);
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


  return (
    <div className="window-shell">
      <AppTitleBar
        section={activePage === null ? "欢迎" : activePage.title}
        backgroundHidden={overlayOpen}
        actions={{
          themeLabel: themeDefinition(themeId).label,
          onOpenConnections: (returnFocus) =>
            openConnectionManager({ connectionId: null, startCreating: false }, returnFocus),
          themeKind: themeDefinition(themeId).kind,
          sshTerminalDisabled: activeTarget === null,
          onOpenSshTerminal: () => void openSshTerminal(),
          onOpenCommandHistory: openCommandHistory,
          onCycleTheme: () => void cycleTheme(),
          onOpenSettings: openSettings,
        }}
      />
      <div className="app-frame">
      <aside className="sidebar" aria-hidden={overlayOpen ? true : undefined} inert={overlayOpen ? true : undefined}>
        <nav aria-label="主导航" aria-busy={navigationBusy}>
          {(Object.keys(groupLabels) as PageGroup[]).map((group) => (
            <div className="nav-group" key={group}>
              <p>{groupLabels[group]}</p>
              {bootstrap.pages.filter((page) => page.group === group).map((page) => (
                <button
                  className={page.id === activePageId ? "nav-item active" : "nav-item"}
                  key={page.id}
                  type="button"
                  disabled={navigationBusy}
                  onClick={() => void navigateTo(page.id)}
                >
                  <span>{page.icon}</span><strong>{page.title}</strong>
                </button>
              ))}
            </div>
          ))}
        </nav>
      </aside>

      <div className="workspace" aria-hidden={overlayOpen ? true : undefined} inert={overlayOpen ? true : undefined}>
        <main className="content">
          {activePage === null ? (
            <WelcomeView
              productName={bootstrap.productName}
              connections={connections}
              onConnectionAction={(connectionId, intent, returnFocus) =>
                openConnectionManager({ connectionId, startCreating: false, intent }, returnFocus)}
              onCreateConnection={(returnFocus) =>
                openConnectionManager({ connectionId: null, startCreating: true }, returnFocus)}
            />
          ) : activePage.id === "security-reference" ? (
            <SecurityReference favoriteIds={favoriteIds} onFavoriteIdsChange={saveFavoriteIds} />
          ) : activePage.id === "notes" ? (
            <Notes ref={notesRef} />
          ) : activePage.id === "config-generator" ? (
            <ConfigGeneratorPage ref={configGeneratorRef} />
          ) : activePage.id === "system-info" ? (
            <SystemInfoPage
              connection={activeTarget}
              api={window.lovelyres}
              writeClipboard={window.lovelyres.writeClipboard}
            />
          ) : activePage.id === "ai-history" ? (
            <AiHistoryPage
              api={window.lovelyres}
              writeClipboard={window.lovelyres.writeClipboard}
            />
          ) : activePage.id === "snapshot" ? (
            <SnapshotPage
              bindingHandle={activeTarget?.bindingHandle ?? null}
              api={window.lovelyres}
            />
          ) : activePage.id === "firewall" ? (
            <FirewallPage
              bindingHandle={activeTarget?.bindingHandle ?? null}
              api={window.lovelyres}
              writeClipboard={window.lovelyres.writeClipboard}
            />
          ) : activePage.id === "baseline-quick-edit" ? (
            <BaselinePage
              bindingHandle={activeTarget?.bindingHandle ?? null}
              api={window.lovelyres}
            />
          ) : activePage.id === "middleware" ? (
            <MiddlewarePage
              bindingHandle={activeTarget?.bindingHandle ?? null}
              api={window.lovelyres}
            />
          ) : activePage.id === "check-audit" ? (
            <CheckAuditPage
              bindingHandle={activeTarget?.bindingHandle ?? null}
              api={window.lovelyres}
            />
          ) : activePage.id === "integrity" ? (
            <IntegrityPage
              bindingHandle={activeTarget?.bindingHandle ?? null}
              api={window.lovelyres}
            />
          ) : activePage.id === "log-analysis" ? (
            <LogAnalysisPage
              bindingHandle={activeTarget?.bindingHandle ?? null}
              api={window.lovelyres}
            />
          ) : activePage.id === "quick-detection" ? (
            <QuickDetectionPage
              bindingHandle={activeTarget?.bindingHandle ?? null}
              api={window.lovelyres}
            />
          ) : activePage.id === "packet-capture" ? (
            <PacketCapturePage
              bindingHandle={activeTarget?.bindingHandle ?? null}
              api={window.lovelyres}
            />
          ) : activePage.id === "kubernetes" ? (
            <KubernetesPage
              bindingHandle={activeTarget?.bindingHandle ?? null}
              api={window.lovelyres}
            />
          ) : activePage.id === "docker" ? (
            <DockerPage
              bindingHandle={activeTarget?.bindingHandle ?? null}
              api={window.lovelyres}
            />
          ) : activePage.id === "emergency-commands" ? (
            <EmergencyCommandsPage
              bindingHandle={activeTarget?.bindingHandle ?? null}
              api={window.lovelyres}
            />
          ) : (
            <MigrationPlaceholder page={activePage} />
          )}
          {activeTarget === null && activePage?.capability === "connected-target" ? (
            <div className="content-connect-action">
              <button
                type="button"
                data-testid="content-connect-target"
                onClick={(event) =>
                  openConnectionManager({ connectionId: null, startCreating: false }, event.currentTarget)}
              >
                连接目标
              </button>
            </div>
          ) : null}
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
          onConnectionsChanged={setConnections}
          onTargetConnected={acceptConnectedTarget}
        />
      ) : settingsOpen ? (
        <SettingsPanel
          ref={settingsPanelRef}
          api={window.lovelyres}
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
          api={window.lovelyres}
          onClose={closeCommandHistory}
          returnFocusElement={commandHistoryReturnFocusRef.current}
          writeClipboard={window.lovelyres.writeClipboard}
        />
      ) : disposalReportOpen ? (
        <DisposalReportOverlay
          ref={disposalReportOverlayRef}
          activeTarget={activeTarget}
          api={window.lovelyres}
          onClose={closeDisposalReport}
          returnFocusElement={disposalReportReturnFocusRef.current}
          writeClipboard={window.lovelyres.writeClipboard}
        />
      ) : applicationLogOpen ? (
        <ApplicationLogOverlay
          ref={applicationLogOverlayRef}
          api={window.lovelyres}
          onClose={finishApplicationLogClose}
          returnFocusElement={applicationLogReturnFocusRef.current}
          writeClipboard={window.lovelyres.writeClipboard}
          onCopied={() => showNotification("application-log-copied")}
        />
      ) : null}
      <NotificationStack
        notifications={notificationState.notifications}
        modalOpen={overlayOpen}
        onDismiss={dismissNotification}
        onExpire={expireNotifications}
      />
      </div>
      <footer
        className="window-statusbar"
        aria-label="状态栏"
        aria-hidden={overlayOpen ? true : undefined}
        inert={overlayOpen ? true : undefined}
      >
        <div className="statusbar-group">
          <button type="button" className="statusbar-button" data-testid="open-application-log" onClick={(event) => openApplicationLog(event.currentTarget)}>应用日志</button>
          <button type="button" className="statusbar-button" data-testid="open-disposal-report" onClick={(event) => openDisposalReport(event.currentTarget)}>处置报告</button>
        </div>
        <div className="statusbar-target">
          <span className={activeTarget === null ? "status-dot idle" : "status-dot"} />
          <span>{activeTarget === null ? "未连接目标" : targetLabel(activeTarget.target)}</span>
          {activeTarget !== null ? (
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
          {targetError !== null ? <span className="statusbar-error" role="alert">{targetError}</span> : null}
        </div>
        <div className="statusbar-group statusbar-meta">
          <span>后端已连接</span>
          <span>v{bootstrap.appVersion}</span>
        </div>
      </footer>
    </div>
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
        <div><p className="eyebrow">开发中</p><h1>{page.title}</h1><p>{page.summary}</p></div>
        <span className="pending-badge">迁移中</span>
      </header>
      <div className="placeholder-card">
        <span>{page.icon}</span>
        <h2>此工作流正在迁移到 Electron</h2>
        <p>该功能尚未开放，接入完成后会在这里提供完整界面。</p>
        <div>{page.sections.map((section) => <span key={section}>{section}</span>)}</div>
      </div>
    </section>
  );
}
