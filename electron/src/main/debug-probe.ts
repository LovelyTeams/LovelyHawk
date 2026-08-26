import fs from "node:fs";
import path from "node:path";

import { BrowserWindow, type Debugger } from "electron";

import { DEFAULT_THEME_ID, themeDefinition } from "../shared/theme-contract.js";

const PROBE_TIMEOUT_MS = 15_000;
const COMMAND_TIMEOUT_MS = 5_000;
const MAIN_PRELOAD_API_COUNT = 117;
const UNAUTHORIZED_TERMINAL_URL = "lovelyres://app/?window=terminal";

/** The default theme's chrome color as the renderer reports it, so a repalette
 * updates this expectation instead of breaking the probe. */
function expectedTitleBarBackground(): string {
  const hex = themeDefinition(DEFAULT_THEME_ID).chromeColor.slice(1);
  const value = Number.parseInt(hex, 16);
  return `rgb(${(value >> 16) & 0xff}, ${(value >> 8) & 0xff}, ${value & 0xff})`;
}

interface RuntimeEvaluation<T> {
  result: {
    type: string;
    value?: T;
    description?: string;
  };
  exceptionDetails?: unknown;
}

interface ProbeReport {
  schema: "lovelyres-electron-debug/v1";
  status: "PASS" | "FAIL";
  generatedAt: string;
  checks: Record<string, unknown>;
  consoleErrors: string[];
  failure?: string;
}

export function installDebugProbe(
  window: BrowserWindow,
  outputDirectory: string,
  complete: (exitCode: number) => Promise<void>,
): void {
  if (!path.isAbsolute(outputDirectory)) {
    throw new Error("LOVELYRES_DEBUG_PROBE_DIR must be an absolute path.");
  }
  window.webContents.once("did-finish-load", () => {
    void runDebugProbe(window, path.resolve(outputDirectory))
      .then(() => complete(0))
      .catch(async (error: unknown) => {
        const message = error instanceof Error ? error.stack ?? error.message : String(error);
        fs.mkdirSync(outputDirectory, { recursive: true });
        const report: ProbeReport = {
          schema: "lovelyres-electron-debug/v1",
          status: "FAIL",
          generatedAt: new Date().toISOString(),
          checks: {},
          consoleErrors: [],
          failure: message,
        };
        fs.writeFileSync(
          path.join(outputDirectory, "report.json"),
          `${JSON.stringify(report, null, 2)}\n`,
          "utf8",
        );
        await complete(1);
      });
  });
}

async function runDebugProbe(window: BrowserWindow, outputDirectory: string): Promise<void> {
  const client = window.webContents.debugger;
  const consoleErrors: string[] = [];
  client.attach("1.3");
  client.on("message", (_event, method, parameters: unknown) => {
    const record = isRecord(parameters) ? parameters : null;
    const logEntry = record !== null && isRecord(record.entry) ? record.entry : null;
    const consoleType = record?.type;
    if (
      method === "Runtime.exceptionThrown" ||
      (method === "Runtime.consoleAPICalled" && consoleType === "error") ||
      (method === "Log.entryAdded" && logEntry?.level === "error")
    ) {
      consoleErrors.push(truncate(JSON.stringify(parameters)));
    }
  });

  try {
    await sendCommand(client, "Runtime.enable");
    await sendCommand(client, "Page.enable");
    await sendCommand(client, "Log.enable");
    await sendCommand(client, "Accessibility.enable");

    // The disconnected app now lands on the welcome view, not on a feature page.
    await waitFor(client, "document.querySelector('[data-testid=\"welcome-view\"]') !== null");
    const initial = await evaluate<Record<string, unknown>>(
      client,
      `(() => ({
        href: location.href,
        title: document.title,
        navItems: document.querySelectorAll('.nav-item').length,
        readyPages: document.querySelectorAll('.nav-item i').length,
        backendConnected: document.body.textContent.includes('后端已连接'),
        welcomeView: document.querySelectorAll('[data-testid="welcome-view"]').length,
        welcomeText: document.querySelector('[data-testid="welcome-view"]')?.textContent ?? '',
        systemInfoPrompt: document.querySelector('.system-info-connect-prompt')?.textContent ?? '',
        systemInfoTables: document.querySelectorAll('.system-info-table-scroll table').length,
        processType: typeof window.process,
        requireType: typeof window.require,
        apiMethods: Object.keys(window.lovelyres).sort(),
        csp: document.querySelector('meta[http-equiv="Content-Security-Policy"]')?.content ?? '',
        resourceUrls: performance.getEntriesByType('resource').map(entry => entry.name),
        inlineHandlers: document.querySelectorAll('[onclick],[onerror],[onload]').length,
        dynamicScripts: document.querySelectorAll('script').length,
        titlebar: (() => {
          const element = document.querySelector('[data-testid="window-titlebar"]');
          if (!(element instanceof HTMLElement)) return null;
          const style = getComputedStyle(element);
          return {
            height: element.getBoundingClientRect().height,
            background: style.backgroundColor,
            paddingRight: style.paddingRight,
            appRegion: style.getPropertyValue('-webkit-app-region'),
            label: element.getAttribute('aria-label'),
            section: element.querySelector('small')?.textContent ?? '',
            controls: [...element.querySelectorAll('button')].map(button => button.dataset.testid ?? ''),
            nonButtonWidgets: element.querySelectorAll('input,textarea,select,a[href]').length,
            undraggableControls: [...element.querySelectorAll('button')]
              .filter(button => getComputedStyle(button).getPropertyValue('-webkit-app-region') !== 'no-drag').length
          };
        })()
      }))()`,
    );
    assert(initial.href === "lovelyres://app/", "renderer origin is not the packaged custom scheme");
    assert(initial.title === "LovelyRes", "renderer title is missing");
    assert(initial.navItems === 18, "page registry did not render exactly 18 navigation items");
    // Build bookkeeping never belongs in the operator's sidebar.
    assert(initial.readyPages === 0, "the sidebar still renders migration markers");
    assert(initial.welcomeView === 1, "disconnected app did not open on the welcome view");
    assert(
      typeof initial.welcomeText === "string" && initial.welcomeText.includes("先在连接管理中建立一个 SSH 连接"),
      "welcome view did not explain the disconnected state",
    );
    assert(initial.systemInfoPrompt === "", "system-info rendered before the user navigated to it");
    assert(initial.backendConnected === true, "renderer did not complete the backend handshake");
    assert(initial.processType === "undefined", "Node process leaked into the renderer");
    assert(initial.requireType === "undefined", "Node require leaked into the renderer");
    assert(
      Array.isArray(initial.apiMethods) &&
        initial.apiMethods.join(",") ===
          "addNoteTag,bootstrap,cancelAiHistoryMutation,cancelCommandHistoryMutation,cancelConnectionDelete,cancelEmergencyPathAction,cancelIntegrityComparison,cancelNoteDelete,cancelSettingsMutation,cancelSshAttempt,clearApplicationLogBuffer,closeConfigDraft,collectCheckAuditStatus,collectSystemInfo,confirmAiHistoryMutation,confirmCommandHistoryMutation,confirmConnectionDelete,confirmEmergencyPathAction,confirmNoteDelete,confirmSettingsMutation,confirmSshHostKey,copyConfig,correlateLogSources,createConnection,createNote,diffForensicSnapshots,disconnectSshBinding,discoverLogSources,discoverMiddleware,executeEmergencyPathAction,exportAiHistory,exportApplicationLogs,exportConfigArtifact,exportConnections,exportDisposalReport,exportNotes,generateConfig,generateDisposalReport,getAiHistoryRecord,getApplicationLogPreview,getBaselineCatalog,getCheckAuditCatalog,getCommandHistory,getConfigCatalog,getConnection,getDisposalReportContent,getDockerCollection,getDockerLogs,getDockerSecurityAudit,getIntegrityPresets,getKubernetesAvailability,getKubernetesPodLogs,getKubernetesResourceDetail,getNote,getSnapshotDetail,getSshAttempt,getSystemInfoCatalog,getSystemInfoDetail,getSystemInfoSummary,importConnections,inspectDockerResource,inspectEmergencyPath,inspectFirewall,listAiHistory,listApplicationLogs,listBaselineHistory,listCommandHistory,listConnections,listFirewallChangeHistory,listIntegrityBaselines,listKubernetesResources,listMiddlewareHistory,listNotes,listPacketCaptureInterfaces,listSnapshots,loadEmergencyCommandCatalog,loadMiddlewareConfiguration,loadSettings,notifyRendererReady,onBeforeClose,openSshTerminal,planAiHistoryClear,planAiHistoryRemove,planCommandHistoryClear,planCommandHistoryRemove,planCommandReplay,planConnectionDelete,planEmergencyPathAction,planNoteDelete,planSettingsAiApiKeyClear,planSettingsAiProviderRemoval,pollIntegrityComparison,pollPacketCapture,readBaselineFile,readCheckAuditLog,readLogSource,refreshDockerContainers,removeNoteTag,replaceSettingsAiApiKey,respondSshMfa,reviseConfig,runEmergencyCommand,saveSettings,scanBaseline,searchLogIocs,setApplicationLogLevel,setNotePinned,setSecurityReferenceFavorites,setWindowTheme,startIntegrityComparison,startPacketCapture,startSshConnect,startSshProbe,stopPacketCapture,updateConnection,updateNote,writeClipboard",
      "preload exposed an unexpected API surface",
    );
    await waitFor(client, "document.fonts.status === 'loaded'");
    window.showInactive();
    await new Promise((resolve) => setTimeout(resolve, 100));
    const welcomeScreenshot = await withTimeout(
      capturePageWithVizRetry(window),
      "Electron disconnected welcome capturePage",
    ).finally(() => window.hide());
    const welcomeScreenshotBytes = welcomeScreenshot.toPNG();
    assert(welcomeScreenshotBytes.length > 100, "welcome screenshot capture failed");
    fs.mkdirSync(outputDirectory, { recursive: true });
    fs.writeFileSync(path.join(outputDirectory, "welcome-disconnected.png"), welcomeScreenshotBytes);

    const clickedSystemInfo = await evaluate<boolean>(
      client,
      `(() => {
        const item = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent.includes('主机全景'));
        item?.click();
        return item instanceof HTMLButtonElement;
      })()`,
    );
    assert(clickedSystemInfo, "the host overview nav item is missing");
    // Each page is its own chunk, so it arrives after the click rather than
    // with the entry bundle. Wait for the page, do not guess at a delay.
    await waitFor(client, "document.querySelector('.system-info-connect-prompt') !== null");
    const landedSystemInfo = await evaluate<Record<string, unknown>>(
      client,
      `(() => ({
        prompt: document.querySelector('.system-info-connect-prompt')?.textContent ?? '',
        tables: document.querySelectorAll('.system-info-table-scroll table').length,
        section: document.querySelector('[data-testid="window-titlebar"] small')?.textContent ?? ''
      }))()`,
    );
    assert(
      landedSystemInfo.section === "主机全景",
      "custom titlebar did not follow navigation away from the welcome view",
    );
    assert(
      typeof landedSystemInfo.prompt === "string" &&
        landedSystemInfo.prompt.includes("连接目标后查看系统信息"),
      "unconnected system-info page did not render its connection prompt",
    );
    assert(landedSystemInfo.tables === 0, "unconnected system-info rendered remote table data");
    assert(
      typeof initial.csp === "string" && initial.csp.includes("default-src 'none'"),
      "strict renderer CSP is missing",
    );
    assert(
      Array.isArray(initial.resourceUrls) &&
        initial.resourceUrls.every(
          (url) => typeof url === "string" && url.startsWith("lovelyres://app/"),
        ),
      "renderer loaded a resource outside the packaged LovelyRes origin",
    );
    assert(initial.inlineHandlers === 0, "renderer contains inline event handler attributes");
    assert(initial.dynamicScripts === 1, "renderer contains unexpected script elements");
    assert(isRecord(initial.titlebar), "custom titlebar is missing");
    assert(initial.titlebar.height === 40, "custom titlebar height is not exact40");
    assert(
      initial.titlebar.background === expectedTitleBarBackground(),
      "custom titlebar background does not match the native control overlay",
    );
    assert(initial.titlebar.paddingRight === "150px", "custom titlebar did not reserve window controls");
    assert(initial.titlebar.appRegion === "drag", "custom titlebar is not draggable");
    assert(initial.titlebar.label === "窗口标题栏", "custom titlebar has no accessible label");
    assert(initial.titlebar.section === "欢迎", "custom titlebar did not follow the welcome landing view");
    assert(
      Array.isArray(initial.titlebar.controls) &&
        initial.titlebar.controls.join(",") ===
          "open-connections,open-ssh-terminal,open-command-history,cycle-theme,open-settings",
      "custom titlebar does not expose exactly the five named application actions",
    );
    assert(
      initial.titlebar.nonButtonWidgets === 0,
      "custom titlebar contains widgets outside the fixed action set",
    );
    assert(
      initial.titlebar.undraggableControls === 0,
      "custom titlebar actions did not opt out of the window drag region",
    );

    const terminalDisconnected = await evaluate<Record<string, unknown>>(
      client,
      `(async () => {
        const marker = 'terminal-main-capability-marker-must-not-return';
        let rejected = false;
        let markerInError = false;
        try {
          await window.lovelyres.openSshTerminal(marker);
        } catch (error) {
          rejected = true;
          markerInError = String(error).includes(marker);
        }
        const button = document.querySelector('[data-testid="open-ssh-terminal"]');
        return {
          publicApiCount: Object.keys(window.lovelyres).length,
          openArity: window.lovelyres.openSshTerminal.length,
          buttonPresent: button instanceof HTMLButtonElement,
          buttonDisabled: button instanceof HTMLButtonElement && button.disabled,
          rejected,
          markerInError,
          markerInDom: document.body.textContent.includes(marker)
        };
      })()`,
    );
    assert(
      terminalDisconnected.publicApiCount === MAIN_PRELOAD_API_COUNT,
      `main renderer preload is not exact${MAIN_PRELOAD_API_COUNT}`,
    );
    assert(terminalDisconnected.openArity === 0, "openSshTerminal accepts renderer arguments");
    assert(terminalDisconnected.buttonPresent === true, "terminal launch control is missing");
    assert(terminalDisconnected.buttonDisabled === true, "terminal launch is enabled while disconnected");
    assert(terminalDisconnected.rejected === true, "disconnected terminal launch did not fail closed");
    assert(terminalDisconnected.markerInError === false, "terminal launch error echoed hostile input");
    assert(terminalDisconnected.markerInDom === false, "terminal launch marker entered the main DOM");

    await waitFor(client, "document.fonts.status === 'loaded'");
    window.showInactive();
    await new Promise((resolve) => setTimeout(resolve, 100));
    const systemInfoScreenshot = await withTimeout(
      capturePageWithVizRetry(window),
      "Electron disconnected system-information capturePage",
    ).finally(() => window.hide());
    const systemInfoScreenshotBytes = systemInfoScreenshot.toPNG();
    assert(systemInfoScreenshotBytes.length > 100, "system-information screenshot capture failed");
    fs.mkdirSync(outputDirectory, { recursive: true });
    fs.writeFileSync(
      path.join(outputDirectory, "system-info-disconnected.png"),
      systemInfoScreenshotBytes,
    );

    const snapshotBoundary = await evaluate<Record<string, unknown>>(
      client,
      `(async () => {
        const marker = 'forged-snapshot-capability-must-not-echo';
        const rejected = async (operation) => {
          try {
            await operation();
            return { rejected: false, echoed: false };
          } catch (error) {
            return { rejected: true, echoed: String(error).includes(marker) };
          }
        };
        const list = await rejected(() => window.lovelyres.listSnapshots(marker));
        const detail = await rejected(() => window.lovelyres.getSnapshotDetail(
          marker, 'opaque-snapshot-detail'
        ));
        const diff = await rejected(() => window.lovelyres.diffForensicSnapshots(marker, {
          olderSnapshotHandle: 'opaque-snapshot-older',
          newerSnapshotHandle: 'opaque-snapshot-newer'
        }));
        const hostileInput = await rejected(() => window.lovelyres.diffForensicSnapshots(marker, {
          olderSnapshotHandle: 'opaque-snapshot-older',
          newerSnapshotHandle: 'opaque-snapshot-newer',
          snapshotId: marker,
          path: marker
        }));
        return {
          publicApiCount: Object.keys(window.lovelyres).length,
          listType: typeof window.lovelyres.listSnapshots,
          detailType: typeof window.lovelyres.getSnapshotDetail,
          diffType: typeof window.lovelyres.diffForensicSnapshots,
          list,
          detail,
          diff,
          hostileInput,
          createMethod: typeof window.lovelyres.createSnapshot,
          captureMethod: typeof window.lovelyres.captureSnapshot,
          exportMethod: typeof window.lovelyres.exportSnapshot,
          deleteMethod: typeof window.lovelyres.deleteSnapshot,
          restoreMethod: typeof window.lovelyres.restoreSnapshot,
          pathMethod: typeof window.lovelyres.readSnapshotPath,
          commandMethod: typeof window.lovelyres.executeSnapshotCommand,
          genericInvoke: typeof window.lovelyres.invoke,
          markerInDom: document.documentElement.textContent.includes(marker)
        };
      })()`,
    );
    assert(snapshotBoundary.publicApiCount === MAIN_PRELOAD_API_COUNT, "Snapshot boundary is outside the exact preload surface");
    assert(snapshotBoundary.listType === "function", "listSnapshots is unavailable");
    assert(snapshotBoundary.detailType === "function", "getSnapshotDetail is unavailable");
    assert(snapshotBoundary.diffType === "function", "diffForensicSnapshots is unavailable");
    for (const name of ["list", "detail", "diff", "hostileInput"]) {
      const result = snapshotBoundary[name];
      assert(isRecord(result) && result.rejected === true, `Snapshot ${name} request did not fail closed`);
      assert(isRecord(result) && result.echoed === false, `Snapshot ${name} request echoed hostile input`);
    }
    for (const name of [
      "createMethod", "captureMethod", "exportMethod", "deleteMethod", "restoreMethod",
      "pathMethod", "commandMethod", "genericInvoke",
    ]) {
      assert(snapshotBoundary[name] === "undefined", `Snapshot renderer exposed forbidden ${name}`);
    }
    assert(snapshotBoundary.markerInDom === false, "Snapshot hostile marker entered the DOM");

    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('取证快照'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(client, "document.querySelector('.snapshot-disconnected') !== null");
    const snapshotDisconnected = await evaluate<Record<string, unknown>>(
      client,
      `(() => {
        const page = document.querySelector('.snapshot-disconnected');
        const prompt = page?.querySelector('p');
        const parseRgb = (value) => {
          const match = value.match(/^rgba?\\(\\s*([0-9.]+)[, ]+\\s*([0-9.]+)[, ]+\\s*([0-9.]+)/i);
          return match ? [Number(match[1]), Number(match[2]), Number(match[3])] : null;
        };
        const luminance = (rgb) => {
          if (rgb === null) return null;
          const channels = rgb.map(channel => {
            const value = channel / 255;
            return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
          });
          return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
        };
        const contrast = (foreground, background) => {
          const foregroundLuminance = luminance(parseRgb(foreground));
          const backgroundLuminance = luminance(parseRgb(background));
          if (foregroundLuminance === null || backgroundLuminance === null) return null;
          return (Math.max(foregroundLuminance, backgroundLuminance) + 0.05) /
            (Math.min(foregroundLuminance, backgroundLuminance) + 0.05);
        };
        const pageStyle = page === null ? null : getComputedStyle(page);
        const promptStyle = prompt === null || prompt === undefined ? null : getComputedStyle(prompt);
        const background = pageStyle?.backgroundColor ?? '';
        const color = pageStyle?.color ?? '';
        const promptColor = promptStyle?.color ?? '';
        const text = page?.textContent ?? '';
        return {
          title: page?.querySelector('h1')?.textContent ?? '',
          prompt: prompt?.textContent ?? '',
          background,
          color,
          promptColor,
          pageContrast: contrast(color, background),
          promptContrast: contrast(promptColor, background),
          listRows: page?.querySelectorAll('.snapshot-list-item').length ?? -1,
          tables: page?.querySelectorAll('table').length ?? -1,
          preformatted: page?.querySelectorAll('pre').length ?? -1,
          scripts: page?.querySelectorAll('script').length ?? -1,
          images: page?.querySelectorAll('img').length ?? -1,
          inputs: page?.querySelectorAll('input,textarea,select').length ?? -1,
          inlineHandlers: page?.querySelectorAll('[onclick],[onerror],[onload]').length ?? -1,
          markerVisible: document.documentElement.textContent.includes('forged-snapshot-capability-must-not-echo'),
          internalIdentityVisible: /bindingHandle|connectionId|sessionId|TargetGuard|snapshotId|dataRoot|filePath/iu.test(text),
          sidebarInert: document.querySelector('.sidebar')?.inert,
          workspaceInert: document.querySelector('.workspace')?.inert
        };
      })()`,
    );
    assert(snapshotDisconnected.title === "快照调查", "disconnected Snapshot page title is missing");
    assert(
      typeof snapshotDisconnected.prompt === "string" &&
        snapshotDisconnected.prompt.includes("连接 SSH 目标后"),
      "disconnected Snapshot page did not render its honest connection prompt",
    );
    assert(
      typeof snapshotDisconnected.background === "string" &&
        snapshotDisconnected.background !== "transparent" &&
        snapshotDisconnected.background !== "rgba(0, 0, 0, 0)",
      "Snapshot page background is transparent",
    );
    assert(
      typeof snapshotDisconnected.pageContrast === "number" && snapshotDisconnected.pageContrast >= 4.5,
      "Snapshot page foreground/background contrast is below 4.5:1",
    );
    assert(
      typeof snapshotDisconnected.promptContrast === "number" && snapshotDisconnected.promptContrast >= 4.5,
      "Snapshot disconnected prompt contrast is below 4.5:1",
    );
    for (const name of ["listRows", "tables", "preformatted", "scripts", "images", "inputs", "inlineHandlers"]) {
      assert(snapshotDisconnected[name] === 0, `disconnected Snapshot page rendered unexpected ${name}`);
    }
    assert(snapshotDisconnected.markerVisible === false, "forged Snapshot capability reached the page");
    assert(snapshotDisconnected.internalIdentityVisible === false, "Snapshot page exposed internal identity material");
    assert(snapshotDisconnected.sidebarInert === false, "Snapshot page unexpectedly made navigation inert");
    assert(snapshotDisconnected.workspaceInert === false, "Snapshot page unexpectedly made its workspace inert");

    await waitFor(client, "document.fonts.status === 'loaded'");
    window.showInactive();
    await new Promise((resolve) => setTimeout(resolve, 100));
    const snapshotScreenshot = await withTimeout(
      window.webContents.capturePage(),
      "Electron disconnected Snapshot capturePage",
    ).finally(() => window.hide());
    const snapshotScreenshotBytes = snapshotScreenshot.toPNG();
    assert(snapshotScreenshotBytes.length > 100, "Snapshot screenshot capture failed");
    fs.writeFileSync(path.join(outputDirectory, "snapshot-disconnected.png"), snapshotScreenshotBytes);

    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('主机全景'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(
      client,
      "document.querySelector('.snapshot-page') === null && document.querySelector('.system-info-connect-prompt') !== null",
    );
    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('取证快照'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(client, "document.querySelector('.snapshot-disconnected') !== null");
    const snapshotLifecycle = await evaluate<Record<string, unknown>>(
      client,
      `(() => ({
        remounted: document.querySelectorAll('.snapshot-disconnected').length === 1,
        noRemoteRows: document.querySelectorAll('.snapshot-list-item, .snapshot-forensic-text').length === 0,
        prompt: document.querySelector('.snapshot-disconnected p')?.textContent ?? ''
      }))()`,
    );
    assert(snapshotLifecycle.remounted === true, "Snapshot page did not remount cleanly");
    assert(snapshotLifecycle.noRemoteRows === true, "Snapshot page retained remote rows across navigation");
    assert(
      typeof snapshotLifecycle.prompt === "string" && snapshotLifecycle.prompt.includes("连接 SSH 目标后"),
      "Snapshot page lost its disconnected state after remount",
    );
    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('主机全景'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(client, "document.querySelector('.system-info-connect-prompt') !== null");

    const firewallBoundary = await evaluate<Record<string, unknown>>(
      client,
      `(async () => {
        const marker = 'forged-firewall-capability-must-not-echo';
        const rejected = async (operation) => {
          try {
            await operation();
            return { rejected: false, echoed: false };
          } catch (error) {
            return { rejected: true, echoed: String(error).includes(marker) };
          }
        };
        const inspect = await rejected(() => window.lovelyres.inspectFirewall(marker));
        const history = await rejected(() => window.lovelyres.listFirewallChangeHistory(marker));
        const inspectWithUnknown = await rejected(() =>
          window.lovelyres.inspectFirewall(marker, { path: marker, command: marker })
        );
        const historyWithUnknown = await rejected(() =>
          window.lovelyres.listFirewallChangeHistory(marker, { target: marker })
        );
        return {
          publicApiCount: Object.keys(window.lovelyres).length,
          inspectType: typeof window.lovelyres.inspectFirewall,
          historyType: typeof window.lovelyres.listFirewallChangeHistory,
          inspectArity: window.lovelyres.inspectFirewall.length,
          historyArity: window.lovelyres.listFirewallChangeHistory.length,
          inspect,
          history,
          inspectWithUnknown,
          historyWithUnknown,
          planMethod: typeof window.lovelyres.planFirewallMutation,
          confirmMethod: typeof window.lovelyres.confirmFirewallMutation,
          executeMethod: typeof window.lovelyres.executeFirewallMutation,
          restoreMethod: typeof window.lovelyres.restoreFirewallChange,
          reconcileMethod: typeof window.lovelyres.reconcileFirewall,
          terminalMethod: typeof window.lovelyres.openFirewallTerminal,
          fileMethod: typeof window.lovelyres.readFirewallFile,
          exportMethod: typeof window.lovelyres.exportFirewallRules,
          genericInvoke: typeof window.lovelyres.invoke,
          markerInDom: document.documentElement.textContent.includes(marker)
        };
      })()`,
    );
    assert(firewallBoundary.publicApiCount === MAIN_PRELOAD_API_COUNT, "Firewall boundary is outside the exact preload surface");
    assert(firewallBoundary.inspectType === "function", "inspectFirewall is unavailable");
    assert(
      firewallBoundary.historyType === "function",
      "listFirewallChangeHistory is unavailable",
    );
    assert(
      typeof firewallBoundary.inspectArity === "number" &&
        typeof firewallBoundary.historyArity === "number",
      "Firewall contextBridge methods do not expose callable function metadata",
    );
    for (const name of ["inspect", "history", "inspectWithUnknown", "historyWithUnknown"]) {
      const result = firewallBoundary[name];
      assert(isRecord(result) && result.rejected === true, `Firewall ${name} did not fail closed`);
      assert(isRecord(result) && result.echoed === false, `Firewall ${name} echoed hostile input`);
    }
    for (const name of [
      "planMethod", "confirmMethod", "executeMethod", "restoreMethod", "reconcileMethod",
      "terminalMethod", "fileMethod", "exportMethod", "genericInvoke",
    ]) {
      assert(firewallBoundary[name] === "undefined", `Firewall renderer exposed forbidden ${name}`);
    }
    assert(firewallBoundary.markerInDom === false, "Firewall hostile marker entered the DOM");

    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('边界隔离'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(client, "document.querySelector('.firewall-connect-state') !== null");
    const firewallDisconnected = await evaluate<Record<string, unknown>>(
      client,
      `(() => {
        const page = document.querySelector('.firewall-page');
        const prompt = page?.querySelector('.firewall-connect-state p');
        const parseRgb = (value) => {
          const match = value.match(/^rgba?\\(\\s*([0-9.]+)[, ]+\\s*([0-9.]+)[, ]+\\s*([0-9.]+)/i);
          return match ? [Number(match[1]), Number(match[2]), Number(match[3])] : null;
        };
        const luminance = (rgb) => {
          if (rgb === null) return null;
          const channels = rgb.map(channel => {
            const value = channel / 255;
            return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
          });
          return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
        };
        const contrast = (foreground, background) => {
          const foregroundLuminance = luminance(parseRgb(foreground));
          const backgroundLuminance = luminance(parseRgb(background));
          if (foregroundLuminance === null || backgroundLuminance === null) return null;
          return (Math.max(foregroundLuminance, backgroundLuminance) + 0.05) /
            (Math.min(foregroundLuminance, backgroundLuminance) + 0.05);
        };
        const pageStyle = page === null ? null : getComputedStyle(page);
        const promptStyle = prompt === null || prompt === undefined ? null : getComputedStyle(prompt);
        const background = pageStyle?.backgroundColor ?? '';
        const color = pageStyle?.color ?? '';
        const promptColor = promptStyle?.color ?? '';
        const text = page?.textContent ?? '';
        const resources = performance.getEntriesByType('resource').map(entry => entry.name);
        return {
          title: page?.querySelector('h1')?.textContent ?? '',
          prompt: prompt?.textContent ?? '',
          background,
          color,
          promptColor,
          pageContrast: contrast(color, background),
          promptContrast: contrast(promptColor, background),
          rulePanels: page?.querySelectorAll('.firewall-rule-panel').length ?? -1,
          historyPanels: page?.querySelectorAll('.firewall-history-workbench').length ?? -1,
          tables: page?.querySelectorAll('table').length ?? -1,
          preformatted: page?.querySelectorAll('pre').length ?? -1,
          scripts: page?.querySelectorAll('script').length ?? -1,
          images: page?.querySelectorAll('img').length ?? -1,
          inputs: page?.querySelectorAll('input,textarea,select').length ?? -1,
          inlineHandlers: page?.querySelectorAll('[onclick],[onerror],[onload]').length ?? -1,
          markerVisible: document.documentElement.textContent.includes('forged-firewall-capability-must-not-echo'),
          internalIdentityVisible: /bindingHandle|connectionId|sessionId|TargetGuard|dataRoot|filePath|username/iu.test(text),
          localResources: resources.every(url => url.startsWith('lovelyres://app/')),
          sidebarInert: document.querySelector('.sidebar')?.inert,
          workspaceInert: document.querySelector('.workspace')?.inert
        };
      })()`,
    );
    assert(
      firewallDisconnected.title === "连接目标后调查防火墙",
      "disconnected Firewall page title is missing",
    );
    assert(
      typeof firewallDisconnected.prompt === "string" &&
        firewallDisconnected.prompt.includes("不会修改防火墙"),
      "disconnected Firewall page did not render its honest opaque-binding prompt",
    );
    assert(
      typeof firewallDisconnected.background === "string" &&
        firewallDisconnected.background !== "transparent" &&
        firewallDisconnected.background !== "rgba(0, 0, 0, 0)",
      "Firewall page background is transparent",
    );
    assert(
      typeof firewallDisconnected.pageContrast === "number" &&
        firewallDisconnected.pageContrast >= 4.5,
      "Firewall page foreground/background contrast is below 4.5:1",
    );
    assert(
      typeof firewallDisconnected.promptContrast === "number" &&
        firewallDisconnected.promptContrast >= 4.5,
      "Firewall disconnected prompt contrast is below 4.5:1",
    );
    for (const name of [
      "rulePanels", "historyPanels", "tables", "preformatted", "scripts", "images", "inputs",
      "inlineHandlers",
    ]) {
      assert(firewallDisconnected[name] === 0, `disconnected Firewall page rendered ${name}`);
    }
    assert(firewallDisconnected.markerVisible === false, "forged Firewall capability reached the page");
    assert(
      firewallDisconnected.internalIdentityVisible === false,
      "Firewall page exposed internal identity material",
    );
    assert(firewallDisconnected.localResources === true, "Firewall page loaded a non-local resource");
    assert(firewallDisconnected.sidebarInert === false, "Firewall page made navigation inert");
    assert(firewallDisconnected.workspaceInert === false, "Firewall page made its workspace inert");

    await waitFor(client, "document.fonts.status === 'loaded'");
    window.showInactive();
    await new Promise((resolve) => setTimeout(resolve, 100));
    const firewallScreenshot = await withTimeout(
      window.webContents.capturePage(),
      "Electron disconnected Firewall capturePage",
    ).finally(() => window.hide());
    const firewallScreenshotBytes = firewallScreenshot.toPNG();
    assert(firewallScreenshotBytes.length > 100, "Firewall screenshot capture failed");
    fs.writeFileSync(
      path.join(outputDirectory, "firewall-disconnected.png"),
      firewallScreenshotBytes,
    );

    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('主机全景'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(
      client,
      "document.querySelector('.firewall-page') === null && document.querySelector('.system-info-connect-prompt') !== null",
    );
    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('边界隔离'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(client, "document.querySelector('.firewall-connect-state') !== null");
    const firewallLifecycle = await evaluate<Record<string, unknown>>(
      client,
      `(() => ({
        remounted: document.querySelectorAll('.firewall-connect-state').length === 1,
        noRemoteRows: document.querySelectorAll('.firewall-rule-panel, .firewall-history-workbench').length === 0,
        prompt: document.querySelector('.firewall-connect-state p')?.textContent ?? ''
      }))()`,
    );
    assert(firewallLifecycle.remounted === true, "Firewall page did not remount cleanly");
    assert(firewallLifecycle.noRemoteRows === true, "Firewall page retained remote state");
    assert(
      typeof firewallLifecycle.prompt === "string" &&
        firewallLifecycle.prompt.includes("不会修改防火墙"),
      "Firewall page lost its disconnected state after remount",
    );
    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('主机全景'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(client, "document.querySelector('.system-info-connect-prompt') !== null");

    const baselineBoundary = await evaluate<Record<string, unknown>>(
      client,
      `(async () => {
        const marker = 'forged-baseline-capability-must-not-echo';
        const rejected = async (operation) => {
          try {
            await operation();
            return { rejected: false, echoed: false };
          } catch (error) {
            return { rejected: true, echoed: String(error).includes(marker) };
          }
        };
        const catalog = await window.lovelyres.getBaselineCatalog();
        const catalogWithUnknown = await window.lovelyres.getBaselineCatalog({ command: marker });
        const scan = await rejected(() => window.lovelyres.scanBaseline(marker));
        const history = await rejected(() => window.lovelyres.listBaselineHistory(marker));
        const scanWithUnknown = await rejected(() => window.lovelyres.scanBaseline({
          bindingHandle: marker,
          command: marker,
          targetIdentity: marker
        }));
        const historyWithUnknown = await rejected(() => window.lovelyres.listBaselineHistory({
          bindingHandle: marker,
          path: marker
        }));
        return {
          publicApiCount: Object.keys(window.lovelyres).length,
          catalogType: typeof window.lovelyres.getBaselineCatalog,
          scanType: typeof window.lovelyres.scanBaseline,
          historyType: typeof window.lovelyres.listBaselineHistory,
          catalogArity: window.lovelyres.getBaselineCatalog.length,
          scanArity: window.lovelyres.scanBaseline.length,
          historyArity: window.lovelyres.listBaselineHistory.length,
          catalogDisplayed: catalog.displayed,
          catalogUnknownStripped: catalogWithUnknown.displayed === catalog.displayed &&
            !JSON.stringify(catalogWithUnknown).includes(marker),
          scan,
          history,
          scanWithUnknown,
          historyWithUnknown,
          planMethod: typeof window.lovelyres.planBaselineChanges,
          confirmMethod: typeof window.lovelyres.confirmBaselineChanges,
          executeMethod: typeof window.lovelyres.executeBaselineChanges,
          restoreMethod: typeof window.lovelyres.restoreBaselineChange,
          reloadMethod: typeof window.lovelyres.reloadBaselineService,
          terminalMethod: typeof window.lovelyres.openBaselineTerminal,
          readFileType: typeof window.lovelyres.readBaselineFile,
          readFileArity: window.lovelyres.readBaselineFile.length,
          readFile: await rejected(() =>
            window.lovelyres.readBaselineFile(marker, marker)),
          readFileWithPath: await rejected(() =>
            window.lovelyres.readBaselineFile(marker, { itemHandle: marker, path: '/etc/shadow' })),
          readFileWithExtraKeys: await rejected(() =>
            window.lovelyres.readBaselineFile({ bindingHandle: marker, path: '/etc/shadow' }, marker)),
          writeFileMethod: typeof window.lovelyres.writeBaselineFile,
          exportMethod: typeof window.lovelyres.exportBaseline,
          genericInvoke: typeof window.lovelyres.invoke,
          markerInDom: document.documentElement.textContent.includes(marker)
        };
      })()`,
    );
    assert(baselineBoundary.publicApiCount === MAIN_PRELOAD_API_COUNT, "Baseline boundary is outside the exact preload surface");
    assert(baselineBoundary.catalogType === "function", "getBaselineCatalog is unavailable");
    assert(baselineBoundary.scanType === "function", "scanBaseline is unavailable");
    assert(baselineBoundary.historyType === "function", "listBaselineHistory is unavailable");
    assert(baselineBoundary.readFileType === "function", "readBaselineFile is unavailable");
    assert(
      typeof baselineBoundary.catalogArity === "number" &&
        typeof baselineBoundary.scanArity === "number" &&
        typeof baselineBoundary.historyArity === "number" &&
        typeof baselineBoundary.readFileArity === "number",
      "Baseline contextBridge methods do not expose callable function metadata",
    );
    assert(baselineBoundary.catalogDisplayed === 75, "bounded Baseline catalog did not load");
    assert(
      baselineBoundary.catalogUnknownStripped === true,
      "catalog extra ingredients crossed the arity-zero preload boundary",
    );
    for (const name of [
      "scan", "history", "scanWithUnknown", "historyWithUnknown",
      // A forged item handle names no check, and a path smuggled in place
      // of one names no file.
      "readFile", "readFileWithPath", "readFileWithExtraKeys",
    ]) {
      const result = baselineBoundary[name];
      assert(isRecord(result) && result.rejected === true, `Baseline ${name} did not fail closed`);
      assert(isRecord(result) && result.echoed === false, `Baseline ${name} echoed hostile input`);
    }
    for (const name of [
      "planMethod", "confirmMethod", "executeMethod", "restoreMethod", "reloadMethod",
      "terminalMethod", "writeFileMethod", "exportMethod", "genericInvoke",
    ]) {
      assert(baselineBoundary[name] === "undefined", `Baseline renderer exposed forbidden ${name}`);
    }
    assert(baselineBoundary.markerInDom === false, "Baseline hostile marker entered the DOM");

    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('配置'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(client, "document.querySelectorAll('.baseline-card').length === 75");
    const baselineDisconnected = await evaluate<Record<string, unknown>>(
      client,
      `(() => {
        const page = document.querySelector('.baseline-page');
        const shell = document.querySelector('.configuration-page');
        const prompt = page?.querySelector('.baseline-connection-note');
        const parseRgb = (value) => {
          const match = value.match(/^rgba?\\(\\s*([0-9.]+)[, ]+\\s*([0-9.]+)[, ]+\\s*([0-9.]+)/i);
          return match ? [Number(match[1]), Number(match[2]), Number(match[3])] : null;
        };
        const luminance = (rgb) => {
          if (rgb === null) return null;
          const channels = rgb.map(channel => {
            const value = channel / 255;
            return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
          });
          return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
        };
        const contrast = (foreground, background) => {
          const foregroundLuminance = luminance(parseRgb(foreground));
          const backgroundLuminance = luminance(parseRgb(background));
          if (foregroundLuminance === null || backgroundLuminance === null) return null;
          return (Math.max(foregroundLuminance, backgroundLuminance) + 0.05) /
            (Math.min(foregroundLuminance, backgroundLuminance) + 0.05);
        };
        const pageStyle = page === null ? null : getComputedStyle(page);
        const promptStyle = prompt === null || prompt === undefined ? null : getComputedStyle(prompt);
        const background = pageStyle?.backgroundColor ?? '';
        const color = pageStyle?.color ?? '';
        const promptColor = promptStyle?.color ?? '';
        const text = page?.textContent ?? '';
        const scanButton = [...(page?.querySelectorAll('button') ?? [])]
          .find(button => button.textContent?.includes('手动扫描'));
        const resources = performance.getEntriesByType('resource').map(entry => entry.name);
        return {
          // The page's name is the title bar's job; repeating it inside the
          // page cost a header band the operator scrolled past every time.
          title: document.querySelector('.window-titlebar small')?.textContent ?? '',
          pageHeadings: shell?.querySelectorAll('h1').length ?? -1,
          prompt: prompt?.textContent ?? '',
          modes: [...(shell?.querySelectorAll('.configuration-modes button strong') ?? [])]
            .map(node => node.textContent).join(','),
          background,
          color,
          promptColor,
          pageContrast: contrast(color, background),
          promptContrast: contrast(promptColor, background),
          catalogCards: page?.querySelectorAll('.baseline-card').length ?? -1,
          compliantRows: page?.querySelectorAll('.baseline-card .is-compliant, .baseline-card .is-noncompliant').length ?? -1,
          historyRows: page?.querySelectorAll('.baseline-history-list article').length ?? -1,
          scanButtonDisabled: scanButton instanceof HTMLButtonElement && scanButton.disabled,
          scripts: page?.querySelectorAll('script').length ?? -1,
          images: page?.querySelectorAll('img').length ?? -1,
          inlineHandlers: page?.querySelectorAll('[onclick],[onerror],[onload]').length ?? -1,
          markerVisible: document.documentElement.textContent.includes('forged-baseline-capability-must-not-echo'),
          internalIdentityVisible: /bindingHandle|connectionId|sessionId|TargetGuard|dataRoot|filePath|username/iu.test(text),
          localResources: resources.every(url => url.startsWith('lovelyres://app/')),
          sidebarInert: document.querySelector('.sidebar')?.inert,
          workspaceInert: document.querySelector('.workspace')?.inert
        };
      })()`,
    );
    assert(baselineDisconnected.title === "配置", "configuration page title is missing");
    assert(
      baselineDisconnected.pageHeadings === 0,
      "the configuration page repeated its own name below the title bar",
    );
    assert(
      baselineDisconnected.modes === "检查这台主机,生成新配置",
      "configuration page did not offer both halves of the job",
    );
    assert(
      typeof baselineDisconnected.prompt === "string" &&
        baselineDisconnected.prompt.includes("连接 SSH 目标后才能扫描"),
      "the checking half did not render its honest disconnected state",
    );
    assert(baselineDisconnected.catalogCards === 75, "Baseline local catalog is incomplete");
    assert(baselineDisconnected.compliantRows === 0, "Baseline page invented remote scan results");
    assert(baselineDisconnected.historyRows === 0, "Baseline page invented remote history");
    assert(baselineDisconnected.scanButtonDisabled === true, "Baseline scan is enabled disconnected");
    assert(
      typeof baselineDisconnected.background === "string" &&
        baselineDisconnected.background !== "transparent" &&
        baselineDisconnected.background !== "rgba(0, 0, 0, 0)",
      "Baseline page background is transparent",
    );
    assert(
      typeof baselineDisconnected.pageContrast === "number" &&
        baselineDisconnected.pageContrast >= 4.5,
      "Baseline page foreground/background contrast is below 4.5:1",
    );
    assert(
      typeof baselineDisconnected.promptContrast === "number" &&
        baselineDisconnected.promptContrast >= 4.5,
      "Baseline disconnected prompt contrast is below 4.5:1",
    );
    for (const name of ["scripts", "images", "inlineHandlers"]) {
      assert(baselineDisconnected[name] === 0, `Baseline page rendered unexpected ${name}`);
    }
    assert(baselineDisconnected.markerVisible === false, "forged Baseline input reached the page");
    assert(
      baselineDisconnected.internalIdentityVisible === false,
      "Baseline page exposed internal identity material",
    );
    assert(baselineDisconnected.localResources === true, "Baseline page loaded a non-local resource");
    assert(baselineDisconnected.sidebarInert === false, "Baseline page made navigation inert");
    assert(baselineDisconnected.workspaceInert === false, "Baseline page made workspace inert");

    await waitFor(client, "document.fonts.status === 'loaded'");
    window.showInactive();
    await new Promise((resolve) => setTimeout(resolve, 100));
    const baselineScreenshot = await withTimeout(
      window.webContents.capturePage(),
      "Electron disconnected Baseline capturePage",
    ).finally(() => window.hide());
    const baselineScreenshotBytes = baselineScreenshot.toPNG();
    assert(baselineScreenshotBytes.length > 100, "Baseline screenshot capture failed");
    fs.writeFileSync(
      path.join(outputDirectory, "baseline-disconnected.png"),
      baselineScreenshotBytes,
    );

    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('主机全景'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(
      client,
      "document.querySelector('.baseline-page') === null && document.querySelector('.system-info-connect-prompt') !== null",
    );
    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('配置'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(client, "document.querySelectorAll('.baseline-card').length === 75");
    const baselineLifecycle = await evaluate<Record<string, unknown>>(
      client,
      `(() => ({
        remounted: document.querySelectorAll('.baseline-page').length === 1,
        catalogCards: document.querySelectorAll('.baseline-card').length,
        noRemoteRows: document.querySelectorAll('.baseline-card .is-compliant, .baseline-card .is-noncompliant, .baseline-history-list article').length === 0,
        prompt: document.querySelector('.baseline-connection-note')?.textContent ?? '',
        mode: document.querySelector('.configuration-modes .is-active strong')?.textContent ?? ''
      }))()`,
    );
    assert(baselineLifecycle.remounted === true, "Baseline page did not remount cleanly");
    assert(baselineLifecycle.catalogCards === 75, "Baseline catalog drifted after remount");
    assert(baselineLifecycle.noRemoteRows === true, "Baseline page retained remote state");
    assert(
      baselineLifecycle.mode === "检查这台主机",
      "the configuration page did not come back on the checking half",
    );
    assert(
      typeof baselineLifecycle.prompt === "string" &&
        baselineLifecycle.prompt.includes("连接 SSH 目标后才能扫描"),
      "the checking half lost its disconnected state after remount",
    );
    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('主机全景'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(client, "document.querySelector('.system-info-connect-prompt') !== null");

    const middlewareBoundary = await evaluate<Record<string, unknown>>(
      client,
      `(async () => {
        const marker = 'forged-middleware-capability-must-not-echo';
        const rejected = async (operation) => {
          try {
            await operation();
            return { rejected: false, echoed: false };
          } catch (error) {
            return { rejected: true, echoed: String(error).includes(marker) };
          }
        };
        return {
          publicApiCount: Object.keys(window.lovelyres).length,
          discoverType: typeof window.lovelyres.discoverMiddleware,
          configurationType: typeof window.lovelyres.loadMiddlewareConfiguration,
          historyType: typeof window.lovelyres.listMiddlewareHistory,
          discoverArity: window.lovelyres.discoverMiddleware.length,
          configurationArity: window.lovelyres.loadMiddlewareConfiguration.length,
          historyArity: window.lovelyres.listMiddlewareHistory.length,
          discover: await rejected(() => window.lovelyres.discoverMiddleware(marker)),
          configuration: await rejected(() =>
            window.lovelyres.loadMiddlewareConfiguration(marker, marker, marker)),
          history: await rejected(() => window.lovelyres.listMiddlewareHistory(marker)),
          discoverWithUnknown: await rejected(() => window.lovelyres.discoverMiddleware({
            bindingHandle: marker,
            command: marker,
            targetIdentity: marker
          })),
          planMethod: typeof window.lovelyres.planMiddlewareChange,
          confirmMethod: typeof window.lovelyres.confirmMiddlewareChange,
          executeMethod: typeof window.lovelyres.executeMiddlewareChange,
          restoreMethod: typeof window.lovelyres.restoreMiddlewareChange,
          terminalMethod: typeof window.lovelyres.openMiddlewareTerminal,
          fileMethod: typeof window.lovelyres.readMiddlewareFile,
          exportMethod: typeof window.lovelyres.exportMiddleware,
          genericInvoke: typeof window.lovelyres.invoke,
          markerInDom: document.documentElement.textContent.includes(marker)
        };
      })()`,
    );
    assert(middlewareBoundary.publicApiCount === MAIN_PRELOAD_API_COUNT, "Middleware boundary is outside the exact preload surface");
    assert(middlewareBoundary.discoverType === "function", "discoverMiddleware is unavailable");
    assert(
      middlewareBoundary.configurationType === "function",
      "loadMiddlewareConfiguration is unavailable",
    );
    assert(middlewareBoundary.historyType === "function", "listMiddlewareHistory is unavailable");
    assert(
      typeof middlewareBoundary.discoverArity === "number" &&
        typeof middlewareBoundary.configurationArity === "number" &&
        typeof middlewareBoundary.historyArity === "number",
      "Middleware contextBridge methods do not expose callable function metadata",
    );
    for (const name of ["discover", "configuration", "history", "discoverWithUnknown"]) {
      const result = middlewareBoundary[name];
      assert(isRecord(result) && result.rejected === true, `Middleware ${name} did not fail closed`);
      assert(isRecord(result) && result.echoed === false, `Middleware ${name} echoed hostile input`);
    }
    for (const name of [
      "planMethod", "confirmMethod", "executeMethod", "restoreMethod", "terminalMethod",
      "fileMethod", "exportMethod", "genericInvoke",
    ]) {
      assert(middlewareBoundary[name] === "undefined", `Middleware renderer exposed forbidden ${name}`);
    }
    assert(middlewareBoundary.markerInDom === false, "Middleware hostile marker entered the DOM");

    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('中间件'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(client, "document.querySelector('.middleware-page') !== null");
    const middlewareDisconnected = await evaluate<Record<string, unknown>>(
      client,
      `(() => {
        const page = document.querySelector('.middleware-page');
        const target = page?.querySelector('.middleware-target');
        const pageStyle = page === null ? null : getComputedStyle(page);
        const resources = performance.getEntriesByType('resource').map(entry => entry.name);
        const text = page?.textContent ?? '';
        const refresh = page?.querySelector('.middleware-view-header button');
        return {
          title: page?.querySelector('h1')?.textContent ?? '',
          target: target?.textContent ?? '',
          disconnectedNote: page?.querySelector('.middleware-connection-note')?.textContent ?? '',
          instanceRows: page?.querySelectorAll('.middleware-instance-grid > button').length ?? -1,
          historyRows: page?.querySelectorAll('.middleware-history-list > article').length ?? -1,
          refreshDisabled: refresh instanceof HTMLButtonElement && refresh.disabled,
          background: pageStyle?.backgroundColor ?? '',
          color: pageStyle?.color ?? '',
          scripts: page?.querySelectorAll('script').length ?? -1,
          images: page?.querySelectorAll('img').length ?? -1,
          inlineHandlers: page?.querySelectorAll('[onclick],[onerror],[onload]').length ?? -1,
          markerVisible: document.documentElement.textContent.includes('forged-middleware-capability-must-not-echo'),
          internalIdentityVisible: /connectionId|sessionId|TargetGuard|generation|dataRoot|filePath|remotePath|username@/iu.test(text),
          localResources: resources.every(url => url.startsWith('lovelyres://app/'))
        };
      })()`,
    );
    assert(middlewareDisconnected.title === "中间件配置调查", "Middleware page title is missing");
    assert(
      typeof middlewareDisconnected.target === "string" &&
        middlewareDisconnected.target.includes("尚未连接 SSH 目标"),
      "Middleware page did not render its honest disconnected target",
    );
    assert(
      typeof middlewareDisconnected.disconnectedNote === "string" &&
        middlewareDisconnected.disconnectedNote.includes("当前页面没有目标数据"),
      "Middleware page did not explain its disconnected empty state",
    );
    assert(middlewareDisconnected.instanceRows === 0, "Middleware page invented remote instances");
    assert(middlewareDisconnected.historyRows === 0, "Middleware page invented remote history");
    assert(middlewareDisconnected.refreshDisabled === true, "Middleware discovery is enabled disconnected");
    assert(
      typeof middlewareDisconnected.background === "string" &&
        middlewareDisconnected.background !== "transparent" &&
        middlewareDisconnected.background !== "rgba(0, 0, 0, 0)",
      "Middleware page background is transparent",
    );
    for (const name of ["scripts", "images", "inlineHandlers"]) {
      assert(middlewareDisconnected[name] === 0, `Middleware page rendered unexpected ${name}`);
    }
    assert(middlewareDisconnected.markerVisible === false, "forged Middleware input reached the page");
    assert(
      middlewareDisconnected.internalIdentityVisible === false,
      "Middleware page exposed internal identity material",
    );
    assert(middlewareDisconnected.localResources === true, "Middleware page loaded a non-local resource");

    await waitFor(client, "document.fonts.status === 'loaded'");
    window.showInactive();
    await new Promise((resolve) => setTimeout(resolve, 100));
    const middlewareScreenshot = await withTimeout(
      window.webContents.capturePage(),
      "Electron disconnected Middleware capturePage",
    ).finally(() => window.hide());
    const middlewareScreenshotBytes = middlewareScreenshot.toPNG();
    assert(middlewareScreenshotBytes.length > 100, "Middleware screenshot capture failed");
    fs.writeFileSync(
      path.join(outputDirectory, "middleware-disconnected.png"),
      middlewareScreenshotBytes,
    );

    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('主机全景'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(
      client,
      "document.querySelector('.middleware-page') === null && document.querySelector('.system-info-connect-prompt') !== null",
    );
    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('中间件'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(client, "document.querySelector('.middleware-page') !== null");
    const middlewareLifecycle = await evaluate<Record<string, unknown>>(
      client,
      `(() => ({
        remounted: document.querySelectorAll('.middleware-page').length === 1,
        noRemoteRows: document.querySelectorAll('.middleware-instance-grid > button, .middleware-history-list > article').length === 0,
        prompt: document.querySelector('.middleware-target')?.textContent ?? ''
      }))()`,
    );
    assert(middlewareLifecycle.remounted === true, "Middleware page did not remount cleanly");
    assert(middlewareLifecycle.noRemoteRows === true, "Middleware page retained remote state");
    assert(
      typeof middlewareLifecycle.prompt === "string" &&
        middlewareLifecycle.prompt.includes("尚未连接 SSH 目标"),
      "Middleware page lost its disconnected state after remount",
    );
    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('主机全景'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(client, "document.querySelector('.system-info-connect-prompt') !== null");

    const checkAuditBoundary = await evaluate<Record<string, unknown>>(
      client,
      `(async () => {
        const marker = 'forged-check-audit-capability-must-not-echo';
        const rejected = async (operation) => {
          try {
            await operation();
            return { rejected: false, echoed: false };
          } catch (error) {
            return { rejected: true, echoed: String(error).includes(marker) };
          }
        };
        return {
          publicApiCount: Object.keys(window.lovelyres).length,
          catalogType: typeof window.lovelyres.getCheckAuditCatalog,
          statusType: typeof window.lovelyres.collectCheckAuditStatus,
          logType: typeof window.lovelyres.readCheckAuditLog,
          catalogArity: window.lovelyres.getCheckAuditCatalog.length,
          statusArity: window.lovelyres.collectCheckAuditStatus.length,
          logArity: window.lovelyres.readCheckAuditLog.length,
          catalog: await rejected(() =>
            window.lovelyres.getCheckAuditCatalog(marker, { customCommandNames: [] })),
          status: await rejected(() => window.lovelyres.collectCheckAuditStatus(marker, marker)),
          log: await rejected(() =>
            window.lovelyres.readCheckAuditLog(marker, marker, { limit: 200, search: null })),
          catalogWithUnknown: await rejected(() => window.lovelyres.getCheckAuditCatalog({
            bindingHandle: marker,
            input: { customCommandNames: [] },
            command: marker
          }, { customCommandNames: [] })),
          planMethod: typeof window.lovelyres.planCheckAudit,
          confirmMethod: typeof window.lovelyres.confirmCheckAudit,
          executeMethod: typeof window.lovelyres.executeCheckAudit,
          restoreMethod: typeof window.lovelyres.restoreCheckAudit,
          terminalMethod: typeof window.lovelyres.openCheckAuditTerminal,
          fileMethod: typeof window.lovelyres.readCheckAuditFile,
          exportMethod: typeof window.lovelyres.exportCheckAudit,
          genericInvoke: typeof window.lovelyres.invoke,
          markerInDom: document.documentElement.textContent.includes(marker)
        };
      })()`,
    );
    assert(checkAuditBoundary.publicApiCount === MAIN_PRELOAD_API_COUNT, "Check Audit boundary is outside the exact preload surface");
    assert(checkAuditBoundary.catalogType === "function", "getCheckAuditCatalog is unavailable");
    assert(
      checkAuditBoundary.statusType === "function",
      "collectCheckAuditStatus is unavailable",
    );
    assert(checkAuditBoundary.logType === "function", "readCheckAuditLog is unavailable");
    assert(
      typeof checkAuditBoundary.catalogArity === "number" &&
        typeof checkAuditBoundary.statusArity === "number" &&
        typeof checkAuditBoundary.logArity === "number",
      "Check Audit contextBridge methods do not expose callable function metadata",
    );
    for (const name of ["catalog", "status", "log", "catalogWithUnknown"]) {
      const result = checkAuditBoundary[name];
      assert(isRecord(result) && result.rejected === true, `Check Audit ${name} did not fail closed`);
      assert(isRecord(result) && result.echoed === false, `Check Audit ${name} echoed hostile input`);
    }
    for (const name of [
      "planMethod", "confirmMethod", "executeMethod", "restoreMethod", "terminalMethod",
      "fileMethod", "exportMethod", "genericInvoke",
    ]) {
      assert(checkAuditBoundary[name] === "undefined", `Check Audit exposed forbidden ${name}`);
    }
    assert(checkAuditBoundary.markerInDom === false, "Check Audit hostile marker entered the DOM");

    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('核查审计'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(client, "document.querySelector('.check-audit-disconnected') !== null");
    const checkAuditDisconnected = await evaluate<Record<string, unknown>>(
      client,
      `(() => {
        const page = document.querySelector('.check-audit-disconnected');
        const style = page === null ? null : getComputedStyle(page);
        const resources = performance.getEntriesByType('resource').map(entry => entry.name);
        const text = page?.textContent ?? '';
        return {
          title: page?.querySelector('h1')?.textContent ?? '',
          prompt: page?.querySelector('p')?.textContent ?? '',
          commandRows: page?.querySelectorAll('.check-audit-command-list > *').length ?? -1,
          logRows: page?.querySelectorAll('.check-audit-log-list > article').length ?? -1,
          background: style?.backgroundColor ?? '',
          scripts: page?.querySelectorAll('script').length ?? -1,
          images: page?.querySelectorAll('img').length ?? -1,
          inlineHandlers: page?.querySelectorAll('[onclick],[onerror],[onload]').length ?? -1,
          markerVisible: document.documentElement.textContent.includes('forged-check-audit-capability-must-not-echo'),
          internalIdentityVisible: /bindingHandle|connectionId|sessionId|TargetGuard|generation|dataRoot|filePath|remotePath|username@/iu.test(text),
          localResources: resources.every(url => url.startsWith('lovelyres://app/'))
        };
      })()`,
    );
    assert(checkAuditDisconnected.title === "命令审计", "Check Audit page title is missing");
    assert(
      typeof checkAuditDisconnected.prompt === "string" &&
        checkAuditDisconnected.prompt.includes("连接 SSH 目标后"),
      "Check Audit page did not render its honest disconnected state",
    );
    assert(checkAuditDisconnected.commandRows === 0, "Check Audit page invented remote commands");
    assert(checkAuditDisconnected.logRows === 0, "Check Audit page invented remote log rows");
    assert(
      typeof checkAuditDisconnected.background === "string" &&
        checkAuditDisconnected.background !== "transparent" &&
        checkAuditDisconnected.background !== "rgba(0, 0, 0, 0)",
      "Check Audit page background is transparent",
    );
    for (const name of ["scripts", "images", "inlineHandlers"]) {
      assert(checkAuditDisconnected[name] === 0, `Check Audit page rendered unexpected ${name}`);
    }
    assert(checkAuditDisconnected.markerVisible === false, "forged Check Audit input reached the page");
    assert(
      checkAuditDisconnected.internalIdentityVisible === false,
      "Check Audit page exposed internal identity material",
    );
    assert(checkAuditDisconnected.localResources === true, "Check Audit page loaded a non-local resource");

    await waitFor(client, "document.fonts.status === 'loaded'");
    window.showInactive();
    await new Promise((resolve) => setTimeout(resolve, 100));
    const checkAuditScreenshot = await withTimeout(
      window.webContents.capturePage(),
      "Electron disconnected Check Audit capturePage",
    ).finally(() => window.hide());
    const checkAuditScreenshotBytes = checkAuditScreenshot.toPNG();
    assert(checkAuditScreenshotBytes.length > 100, "Check Audit screenshot capture failed");
    fs.writeFileSync(
      path.join(outputDirectory, "check-audit-disconnected.png"),
      checkAuditScreenshotBytes,
    );

    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('主机全景'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(
      client,
      "document.querySelector('.check-audit-page') === null && document.querySelector('.system-info-connect-prompt') !== null",
    );
    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('核查审计'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(client, "document.querySelector('.check-audit-disconnected') !== null");
    const checkAuditLifecycle = await evaluate<Record<string, unknown>>(
      client,
      `(() => ({
        remounted: document.querySelectorAll('.check-audit-disconnected').length === 1,
        noRemoteRows: document.querySelectorAll('.check-audit-command-list > *, .check-audit-log-list > article').length === 0,
        prompt: document.querySelector('.check-audit-disconnected p')?.textContent ?? ''
      }))()`,
    );
    assert(checkAuditLifecycle.remounted === true, "Check Audit page did not remount cleanly");
    assert(checkAuditLifecycle.noRemoteRows === true, "Check Audit page retained remote state");
    assert(
      typeof checkAuditLifecycle.prompt === "string" &&
        checkAuditLifecycle.prompt.includes("连接 SSH 目标后"),
      "Check Audit page lost its disconnected state after remount",
    );
    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('主机全景'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(client, "document.querySelector('.system-info-connect-prompt') !== null");

    const integrityBoundary = await evaluate<Record<string, unknown>>(
      client,
      `(async () => {
        const marker = 'ffffffff-ffff-4fff-8fff-ffffffffffff';
        const baselineHandle = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
        const operationHandle = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
        const capabilities = [marker, baselineHandle, operationHandle];
        const rejected = async (operation, expectedMessage) => {
          try {
            await operation();
            return { rejected: false, fixed: false, echoed: false };
          } catch (error) {
            const message = String(error);
            return {
              rejected: true,
              fixed: message.includes(expectedMessage),
              echoed: capabilities.some(capability => message.includes(capability))
            };
          }
        };
        const bindingFailure =
          'The file-integrity binding is missing, expired, or stale.';
        const catalog = await window.lovelyres.getIntegrityPresets();
        const catalogWithIgnoredArgument = await window.lovelyres.getIntegrityPresets(marker);
        return {
          publicApiCount: Object.keys(window.lovelyres).length,
          presetsType: typeof window.lovelyres.getIntegrityPresets,
          listType: typeof window.lovelyres.listIntegrityBaselines,
          startType: typeof window.lovelyres.startIntegrityComparison,
          pollType: typeof window.lovelyres.pollIntegrityComparison,
          cancelType: typeof window.lovelyres.cancelIntegrityComparison,
          presetsArity: window.lovelyres.getIntegrityPresets.length,
          listArity: window.lovelyres.listIntegrityBaselines.length,
          startArity: window.lovelyres.startIntegrityComparison.length,
          pollArity: window.lovelyres.pollIntegrityComparison.length,
          cancelArity: window.lovelyres.cancelIntegrityComparison.length,
          catalogPresets: Array.isArray(catalog?.presets) ? catalog.presets.length : -1,
          catalogMaximum: catalog?.maximumSelected ?? -1,
          ignoredArgumentSafe:
            Array.isArray(catalogWithIgnoredArgument?.presets) &&
            catalogWithIgnoredArgument.presets.length === 6 &&
            catalogWithIgnoredArgument.maximumSelected === 6 &&
            !JSON.stringify(catalogWithIgnoredArgument).includes(marker),
          list: await rejected(
            () => window.lovelyres.listIntegrityBaselines(marker),
            bindingFailure
          ),
          start: await rejected(
            () => window.lovelyres.startIntegrityComparison(marker, baselineHandle),
            bindingFailure
          ),
          poll: await rejected(
            () => window.lovelyres.pollIntegrityComparison(marker, operationHandle, 0, 1),
            bindingFailure
          ),
          cancel: await rejected(
            () => window.lovelyres.cancelIntegrityComparison(marker, operationHandle),
            bindingFailure
          ),
          listWithObject: await rejected(
            () => window.lovelyres.listIntegrityBaselines({
              bindingHandle: marker,
              shellCommand: marker,
              shell: marker,
              command: marker
            }),
            'Invalid file-integrity baseline list request.'
          ),
          startWithObject: await rejected(
            () => window.lovelyres.startIntegrityComparison(marker, {
              baselineHandle,
              shellCommand: marker,
              shell: marker,
              command: marker
            }),
            'Invalid file-integrity comparison start request.'
          ),
          pollWithObject: await rejected(
            () => window.lovelyres.pollIntegrityComparison(marker, {
              operationHandle,
              shellCommand: marker,
              shell: marker,
              command: marker
            }, 0, 1),
            'Invalid file-integrity comparison poll request.'
          ),
          cancelWithObject: await rejected(
            () => window.lovelyres.cancelIntegrityComparison(marker, {
              operationHandle,
              shellCommand: marker,
              shell: marker,
              command: marker
            }),
            'Invalid file-integrity comparison cancellation request.'
          ),
          createMethod: typeof window.lovelyres.createIntegrityBaseline,
          quarantineMethod: typeof window.lovelyres.quarantineIntegrityFile,
          pathMethod: typeof window.lovelyres.readIntegrityPath,
          fileMethod: typeof window.lovelyres.readIntegrityFile,
          terminalMethod: typeof window.lovelyres.openIntegrityTerminal,
          exportMethod: typeof window.lovelyres.exportIntegrityComparison,
          commandMethod: typeof window.lovelyres.executeIntegrityCommand,
          genericMethod: typeof window.lovelyres.invokeIntegrity,
          genericInvoke: typeof window.lovelyres.invoke,
          markerInDom: document.documentElement.outerHTML.includes(marker)
        };
      })()`,
    );
    assert(
      integrityBoundary.publicApiCount === MAIN_PRELOAD_API_COUNT,
      "File Integrity boundary is outside the exact preload surface",
    );
    for (const name of ["presetsType", "listType", "startType", "pollType", "cancelType"]) {
      assert(
        integrityBoundary[name] === "function",
        "File Integrity API is unavailable: " + name,
      );
    }
    for (const name of [
      "presetsArity",
      "listArity",
      "startArity",
      "pollArity",
      "cancelArity",
    ]) {
      assert(
        typeof integrityBoundary[name] === "number",
        "File Integrity contextBridge method has no callable metadata: " + name,
      );
    }
    assert(
      integrityBoundary.catalogPresets === 6 && integrityBoundary.catalogMaximum === 6,
      "File Integrity fixed catalog is not exact6/max6",
    );
    assert(
      integrityBoundary.ignoredArgumentSafe === true,
      "File Integrity catalog did not safely ignore a renderer-only extra argument",
    );
    for (const name of [
      "list",
      "start",
      "poll",
      "cancel",
      "listWithObject",
      "startWithObject",
      "pollWithObject",
      "cancelWithObject",
    ]) {
      const result = integrityBoundary[name];
      assert(
        isRecord(result) && result.rejected === true,
        "File Integrity " + name + " did not fail closed",
      );
      assert(
        isRecord(result) && result.fixed === true,
        "File Integrity " + name + " did not return its fixed failure",
      );
      assert(
        isRecord(result) && result.echoed === false,
        "File Integrity " + name + " echoed hostile capability material",
      );
    }
    for (const name of [
      "createMethod",
      "quarantineMethod",
      "pathMethod",
      "fileMethod",
      "terminalMethod",
      "exportMethod",
      "commandMethod",
      "genericMethod",
      "genericInvoke",
    ]) {
      assert(
        integrityBoundary[name] === "undefined",
        "File Integrity exposed forbidden " + name,
      );
    }
    assert(
      integrityBoundary.markerInDom === false,
      "File Integrity hostile marker entered the DOM",
    );

    const integrityNavigation = await evaluate<boolean>(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.querySelector('strong')?.textContent === '文件完整性');
        if (!(button instanceof HTMLButtonElement)) return false;
        button.focus();
        button.click();
        return true;
      })()`,
    );
    assert(integrityNavigation, "File Integrity navigation control is missing");
    await waitFor(
      client,
      "document.querySelector('.integrity-page.integrity-connect-state') !== null && [...document.querySelectorAll('.nav-item')].some(candidate => candidate.querySelector('strong')?.textContent === '文件完整性' && !candidate.disabled)",
    );
    const integrityDisconnected = await evaluate<Record<string, unknown>>(
      client,
      `(() => {
        const page = document.querySelector('.integrity-page.integrity-connect-state');
        const title = page?.querySelector('h1');
        const prompt = page?.querySelector('p');
        const nav = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.querySelector('strong')?.textContent === '文件完整性');
        if (nav instanceof HTMLElement) nav.focus();
        const resources = performance.getEntriesByType('resource').map(entry => entry.name);
        const text = page?.textContent ?? '';
        const html = document.documentElement.outerHTML;
        const parseRgb = (value) => {
          const parts = value.match(/[0-9.]+/g)?.slice(0, 3).map(Number) ?? [];
          return parts.length === 3 ? parts : [0, 0, 0];
        };
        const luminance = (rgb) => {
          const linear = rgb.map(channel => {
            const value = channel / 255;
            return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
          });
          return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
        };
        const contrast = (foreground, background) => {
          const foregroundLuminance = luminance(parseRgb(foreground));
          const backgroundLuminance = luminance(parseRgb(background));
          return (Math.max(foregroundLuminance, backgroundLuminance) + 0.05) /
            (Math.min(foregroundLuminance, backgroundLuminance) + 0.05);
        };
        const background = page === null ? '' : getComputedStyle(page).backgroundColor;
        const titleColor = title === null ? '' : getComputedStyle(title).color;
        const promptColor = prompt === null ? '' : getComputedStyle(prompt).color;
        return {
          title: title?.textContent ?? '',
          prompt: prompt?.textContent ?? '',
          background,
          titleColor,
          promptColor,
          titleContrast: contrast(titleColor, background),
          promptContrast: contrast(promptColor, background),
          presetRows: page?.querySelectorAll('.integrity-preset-grid > *').length ?? -1,
          baselineRows: page?.querySelectorAll('.integrity-baseline-list > button').length ?? -1,
          findingRows: page?.querySelectorAll('.integrity-findings > article').length ?? -1,
          statisticRows: page?.querySelectorAll('.integrity-stats > div').length ?? -1,
          workbenchRows: page?.querySelectorAll('.integrity-workbench > section').length ?? -1,
          buttons: page?.querySelectorAll('button').length ?? -1,
          alerts: page?.querySelectorAll('[role="alert"]').length ?? -1,
          scripts: page?.querySelectorAll('script').length ?? -1,
          images: page?.querySelectorAll('img').length ?? -1,
          inlineHandlers: page?.querySelectorAll('[onclick],[onerror],[onload]').length ?? -1,
          navActive: nav?.classList.contains('active') ?? false,
          navFocused: document.activeElement === nav,
          markerVisible: document.documentElement.outerHTML.includes(
            'ffffffff-ffff-4fff-8fff-ffffffffffff'
          ),
          internalIdentityVisible: /bindingHandle|connectionId|sessionId|TargetGuard|targetGeneration|generation|dataRoot|filePath|remotePath|username@/iu.test(text + html),
          localResources: resources.every(url => url.startsWith('lovelyres://app/'))
        };
      })()`,
    );
    assert(
      integrityDisconnected.title === "连接目标后检查文件完整性",
      "File Integrity disconnected title is missing",
    );
    assert(
      typeof integrityDisconnected.prompt === "string" &&
        integrityDisconnected.prompt.includes("连接目标后可比对文件完整性基线") &&
        integrityDisconnected.prompt.includes("文件完整性基线"),
      "File Integrity page did not render its honest disconnected prompt",
    );
    assert(
      typeof integrityDisconnected.background === "string" &&
        integrityDisconnected.background !== "transparent" &&
        integrityDisconnected.background !== "rgba(0, 0, 0, 0)",
      "File Integrity disconnected background is transparent",
    );
    assert(
      typeof integrityDisconnected.titleContrast === "number" &&
        integrityDisconnected.titleContrast >= 4.5,
      "File Integrity disconnected heading contrast is below 4.5:1",
    );
    assert(
      typeof integrityDisconnected.promptContrast === "number" &&
        integrityDisconnected.promptContrast >= 4.5,
      "File Integrity disconnected prompt contrast is below 4.5:1",
    );
    for (const name of [
      "presetRows",
      "baselineRows",
      "findingRows",
      "statisticRows",
      "workbenchRows",
      "buttons",
      "alerts",
      "scripts",
      "images",
      "inlineHandlers",
    ]) {
      assert(
        integrityDisconnected[name] === 0,
        "File Integrity disconnected page rendered unexpected " + name,
      );
    }
    assert(
      integrityDisconnected.navActive === true && integrityDisconnected.navFocused === true,
      "File Integrity navigation did not remain active and focused",
    );
    assert(
      integrityDisconnected.markerVisible === false,
      "forged File Integrity capability reached the page",
    );
    assert(
      integrityDisconnected.internalIdentityVisible === false,
      "File Integrity page exposed internal identity material",
    );
    assert(
      integrityDisconnected.localResources === true,
      "File Integrity page loaded a non-local resource",
    );

    const integrityAccessibility = (await sendCommand(
      client,
      "Accessibility.getFullAXTree",
    )) as {
      nodes?: Array<{ role?: { value?: string }; name?: { value?: string } }>;
    };
    integrityDisconnected.axHeading = (integrityAccessibility.nodes ?? []).some(
      (node) =>
        node.role?.value === "heading" && node.name?.value === "连接目标后检查文件完整性",
    );
    assert(
      integrityDisconnected.axHeading === true,
      "File Integrity disconnected heading is missing from the accessibility tree",
    );

    await waitFor(client, "document.fonts.status === 'loaded'");
    window.showInactive();
    await new Promise((resolve) => setTimeout(resolve, 100));
    const integrityScreenshot = await withTimeout(
      capturePageWithVizRetry(window),
      "Electron disconnected File Integrity capturePage",
    ).finally(() => window.hide());
    const integrityScreenshotBytes = integrityScreenshot.toPNG();
    assert(integrityScreenshotBytes.length > 100, "File Integrity screenshot capture failed");
    fs.writeFileSync(
      path.join(outputDirectory, "integrity-disconnected.png"),
      integrityScreenshotBytes,
    );

    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.querySelector('strong')?.textContent === '主机全景');
        if (!(button instanceof HTMLButtonElement)) return false;
        button.focus();
        button.click();
        return true;
      })()`,
    );
    await waitFor(
      client,
      "document.querySelector('.integrity-page') === null && document.querySelector('.system-info-connect-prompt') !== null",
    );
    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.querySelector('strong')?.textContent === '文件完整性');
        if (!(button instanceof HTMLButtonElement)) return false;
        button.focus();
        button.click();
        return true;
      })()`,
    );
    await waitFor(
      client,
      "document.querySelector('.integrity-page.integrity-connect-state') !== null && [...document.querySelectorAll('.nav-item')].some(candidate => candidate.querySelector('strong')?.textContent === '文件完整性' && !candidate.disabled)",
    );
    const integrityLifecycle = await evaluate<Record<string, unknown>>(
      client,
      `(() => {
        const page = document.querySelector('.integrity-page.integrity-connect-state');
        const nav = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.querySelector('strong')?.textContent === '文件完整性');
        if (nav instanceof HTMLElement) nav.focus();
        return {
          remounted: document.querySelectorAll('.integrity-page.integrity-connect-state').length === 1,
          noRemoteState: document.querySelectorAll('.integrity-preset-grid > *, .integrity-baseline-list > button, .integrity-findings > article, .integrity-stats > div, .integrity-workbench > section, .integrity-notice[role="alert"]').length === 0,
          noControls: (page?.querySelectorAll('button').length ?? -1) === 0,
          title: page?.querySelector('h1')?.textContent ?? '',
          prompt: page?.querySelector('p')?.textContent ?? '',
          navActive: nav?.classList.contains('active') ?? false,
          navFocused: document.activeElement === nav,
          markerVisible: document.documentElement.outerHTML.includes(
            'ffffffff-ffff-4fff-8fff-ffffffffffff'
          )
        };
      })()`,
    );
    assert(
      integrityLifecycle.remounted === true,
      "File Integrity page did not remount cleanly",
    );
    assert(
      integrityLifecycle.noRemoteState === true && integrityLifecycle.noControls === true,
      "File Integrity page retained remote state or controls",
    );
    assert(
      integrityLifecycle.title === "连接目标后检查文件完整性" &&
        typeof integrityLifecycle.prompt === "string" &&
        integrityLifecycle.prompt.includes("连接目标后可比对文件完整性基线"),
      "File Integrity page lost its disconnected state after remount",
    );
    assert(
      integrityLifecycle.navActive === true && integrityLifecycle.navFocused === true,
      "File Integrity navigation lost active focus after remount",
    );
    assert(
      integrityLifecycle.markerVisible === false,
      "File Integrity remount retained hostile marker state",
    );
    const integrityConsole = { errorCount: consoleErrors.length };
    assert(integrityConsole.errorCount === 0, "File Integrity probe emitted console errors");
    assert(
      !JSON.stringify({
        integrityBoundary,
        integrityDisconnected,
        integrityLifecycle,
        integrityConsole,
      }).includes("ffffffff-ffff-4fff-8fff-ffffffffffff"),
      "File Integrity report fields retained the hostile marker",
    );
    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.querySelector('strong')?.textContent === '主机全景');
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(client, "document.querySelector('.system-info-connect-prompt') !== null");

    const logAnalysisBoundary = await evaluate<Record<string, unknown>>(
      client,
      `(async () => {
        const marker = 'forged-log-analysis-capability-must-not-echo';
        const secondSource = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
        const readInput = {
          page: 1,
          pageSize: 100,
          keyword: null,
          date: null,
          journalUnit: null
        };
        const correlationInput = {
          sourceHandles: [marker, secondSource],
          lineLimit: 200
        };
        const iocInput = {
          sourceHandles: [marker],
          indicators: ['203.0.113.7']
        };
        const rejected = async (operation) => {
          try {
            await operation();
            return { rejected: false, echoed: false };
          } catch (error) {
            return { rejected: true, echoed: String(error).includes(marker) };
          }
        };
        return {
          publicApiCount: Object.keys(window.lovelyres).length,
          discoverType: typeof window.lovelyres.discoverLogSources,
          readType: typeof window.lovelyres.readLogSource,
          correlateType: typeof window.lovelyres.correlateLogSources,
          searchType: typeof window.lovelyres.searchLogIocs,
          discoverArity: window.lovelyres.discoverLogSources.length,
          readArity: window.lovelyres.readLogSource.length,
          correlateArity: window.lovelyres.correlateLogSources.length,
          searchArity: window.lovelyres.searchLogIocs.length,
          discover: await rejected(() => window.lovelyres.discoverLogSources(marker)),
          read: await rejected(() =>
            window.lovelyres.readLogSource(marker, marker, marker, readInput)),
          correlate: await rejected(() =>
            window.lovelyres.correlateLogSources(marker, marker, correlationInput)),
          search: await rejected(() => window.lovelyres.searchLogIocs(marker, marker, iocInput)),
          discoverWithUnknown: await rejected(() => window.lovelyres.discoverLogSources({
            bindingHandle: marker,
            command: marker,
            targetIdentity: marker
          })),
          readWithUnknown: await rejected(() => window.lovelyres.readLogSource(
            marker,
            marker,
            marker,
            { ...readInput, path: marker }
          )),
          correlateWithUnknown: await rejected(() => window.lovelyres.correlateLogSources(
            marker,
            marker,
            { ...correlationInput, command: marker }
          )),
          searchWithUnknown: await rejected(() => window.lovelyres.searchLogIocs(
            marker,
            marker,
            { ...iocInput, remotePath: marker }
          )),
          analyzeAiMethod: typeof window.lovelyres.analyzeLogWithAi,
          addRuleMethod: typeof window.lovelyres.addLogRule,
          removeRuleMethod: typeof window.lovelyres.removeLogRule,
          mutationPlanMethod: typeof window.lovelyres.planLogRuleChange,
          fileMethod: typeof window.lovelyres.openLogFile,
          terminalMethod: typeof window.lovelyres.openLogTerminal,
          exportMethod: typeof window.lovelyres.exportLogAnalysis,
          genericInvoke: typeof window.lovelyres.invoke,
          markerInDom: document.documentElement.textContent.includes(marker)
        };
      })()`,
    );
    assert(logAnalysisBoundary.publicApiCount === MAIN_PRELOAD_API_COUNT, "Log Analysis boundary is outside the exact preload surface");
    for (const name of ["discoverType", "readType", "correlateType", "searchType"]) {
      assert(logAnalysisBoundary[name] === "function", `Log Analysis API is unavailable: ${name}`);
    }
    for (const name of ["discoverArity", "readArity", "correlateArity", "searchArity"]) {
      assert(
        typeof logAnalysisBoundary[name] === "number",
        `Log Analysis contextBridge method has no callable metadata: ${name}`,
      );
    }
    for (const name of [
      "discover",
      "read",
      "correlate",
      "search",
      "discoverWithUnknown",
      "readWithUnknown",
      "correlateWithUnknown",
      "searchWithUnknown",
    ]) {
      const result = logAnalysisBoundary[name];
      assert(isRecord(result) && result.rejected === true, `Log Analysis ${name} did not fail closed`);
      assert(isRecord(result) && result.echoed === false, `Log Analysis ${name} echoed hostile input`);
    }
    for (const name of [
      "analyzeAiMethod",
      "addRuleMethod",
      "removeRuleMethod",
      "mutationPlanMethod",
      "fileMethod",
      "terminalMethod",
      "exportMethod",
      "genericInvoke",
    ]) {
      assert(logAnalysisBoundary[name] === "undefined", `Log Analysis exposed forbidden ${name}`);
    }
    assert(logAnalysisBoundary.markerInDom === false, "Log Analysis hostile marker entered the DOM");

    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('日志分析'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(client, "document.querySelector('.log-analysis-disconnected') !== null");
    const logAnalysisDisconnected = await evaluate<Record<string, unknown>>(
      client,
      `(() => {
        const page = document.querySelector('.log-analysis-disconnected');
        const style = page === null ? null : getComputedStyle(page);
        const resources = performance.getEntriesByType('resource').map(entry => entry.name);
        const text = page?.textContent ?? '';
        return {
          title: page?.querySelector('h1')?.textContent ?? '',
          prompt: page?.querySelector('p')?.textContent ?? '',
          sourceRows: page?.querySelectorAll('.log-analysis-source-list > button').length ?? -1,
          entryRows: page?.querySelectorAll('.log-analysis-entry-list > article').length ?? -1,
          selectorRows: page?.querySelectorAll('.log-analysis-selector label').length ?? -1,
          iocRows: page?.querySelectorAll('.log-analysis-ioc-results > article').length ?? -1,
          background: style?.backgroundColor ?? '',
          scripts: page?.querySelectorAll('script').length ?? -1,
          images: page?.querySelectorAll('img').length ?? -1,
          inlineHandlers: page?.querySelectorAll('[onclick],[onerror],[onload]').length ?? -1,
          markerVisible: document.documentElement.textContent.includes('forged-log-analysis-capability-must-not-echo'),
          internalIdentityVisible: /bindingHandle|connectionId|sessionId|TargetGuard|targetGeneration|generation|dataRoot|filePath|remotePath|username@/iu.test(text),
          localResources: resources.every(url => url.startsWith('lovelyres://app/'))
        };
      })()`,
    );
    assert(logAnalysisDisconnected.title === "日志分析", "Log Analysis page title is missing");
    assert(
      typeof logAnalysisDisconnected.prompt === "string" &&
        logAnalysisDisconnected.prompt.includes("连接 SSH 目标后"),
      "Log Analysis page did not render its honest disconnected state",
    );
    for (const name of ["sourceRows", "entryRows", "selectorRows", "iocRows"]) {
      assert(logAnalysisDisconnected[name] === 0, `Log Analysis page invented remote rows: ${name}`);
    }
    assert(
      typeof logAnalysisDisconnected.background === "string" &&
        logAnalysisDisconnected.background !== "transparent" &&
        logAnalysisDisconnected.background !== "rgba(0, 0, 0, 0)",
      "Log Analysis page background is transparent",
    );
    for (const name of ["scripts", "images", "inlineHandlers"]) {
      assert(logAnalysisDisconnected[name] === 0, `Log Analysis page rendered unexpected ${name}`);
    }
    assert(logAnalysisDisconnected.markerVisible === false, "forged Log Analysis input reached the page");
    assert(
      logAnalysisDisconnected.internalIdentityVisible === false,
      "Log Analysis page exposed internal identity material",
    );
    assert(logAnalysisDisconnected.localResources === true, "Log Analysis page loaded a non-local resource");

    await waitFor(client, "document.fonts.status === 'loaded'");
    window.showInactive();
    await new Promise((resolve) => setTimeout(resolve, 100));
    const logAnalysisScreenshot = await withTimeout(
      window.webContents.capturePage(),
      "Electron disconnected Log Analysis capturePage",
    ).finally(() => window.hide());
    const logAnalysisScreenshotBytes = logAnalysisScreenshot.toPNG();
    assert(logAnalysisScreenshotBytes.length > 100, "Log Analysis screenshot capture failed");
    fs.writeFileSync(
      path.join(outputDirectory, "log-analysis-disconnected.png"),
      logAnalysisScreenshotBytes,
    );

    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('主机全景'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(
      client,
      "document.querySelector('.log-analysis-page') === null && document.querySelector('.system-info-connect-prompt') !== null",
    );
    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('日志分析'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(client, "document.querySelector('.log-analysis-disconnected') !== null");
    const logAnalysisLifecycle = await evaluate<Record<string, unknown>>(
      client,
      `(() => ({
        remounted: document.querySelectorAll('.log-analysis-disconnected').length === 1,
        noRemoteRows: document.querySelectorAll('.log-analysis-source-list > button, .log-analysis-entry-list > article, .log-analysis-selector label, .log-analysis-ioc-results > article').length === 0,
        prompt: document.querySelector('.log-analysis-disconnected p')?.textContent ?? ''
      }))()`,
    );
    assert(logAnalysisLifecycle.remounted === true, "Log Analysis page did not remount cleanly");
    assert(logAnalysisLifecycle.noRemoteRows === true, "Log Analysis page retained remote state");
    assert(
      typeof logAnalysisLifecycle.prompt === "string" &&
        logAnalysisLifecycle.prompt.includes("连接 SSH 目标后"),
      "Log Analysis page lost its disconnected state after remount",
    );
    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('主机全景'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(client, "document.querySelector('.system-info-connect-prompt') !== null");

    const kubernetesBoundary = await evaluate<Record<string, unknown>>(
      client,
      `(async () => {
        const marker = 'forged-kubernetes-capability-must-not-echo';
        const listInput = { tab: 'pods', namespaceScope: null };
        const rejected = async (operation) => {
          try {
            await operation();
            return { rejected: false, echoed: false };
          } catch (error) {
            return { rejected: true, echoed: String(error).includes(marker) };
          }
        };
        return {
          publicApiCount: Object.keys(window.lovelyres).length,
          availabilityType: typeof window.lovelyres.getKubernetesAvailability,
          listType: typeof window.lovelyres.listKubernetesResources,
          detailType: typeof window.lovelyres.getKubernetesResourceDetail,
          logsType: typeof window.lovelyres.getKubernetesPodLogs,
          availabilityArity: window.lovelyres.getKubernetesAvailability.length,
          listArity: window.lovelyres.listKubernetesResources.length,
          detailArity: window.lovelyres.getKubernetesResourceDetail.length,
          logsArity: window.lovelyres.getKubernetesPodLogs.length,
          availability: await rejected(() =>
            window.lovelyres.getKubernetesAvailability(marker)),
          list: await rejected(() =>
            window.lovelyres.listKubernetesResources(marker, listInput)),
          detail: await rejected(() =>
            window.lovelyres.getKubernetesResourceDetail(marker, marker, marker)),
          logs: await rejected(() =>
            window.lovelyres.getKubernetesPodLogs(marker, marker, marker)),
          availabilityWithUnknown: await rejected(() =>
            window.lovelyres.getKubernetesAvailability({
              bindingHandle: marker,
              command: marker,
              targetIdentity: marker
            })),
          listWithUnknown: await rejected(() =>
            window.lovelyres.listKubernetesResources(marker, {
              ...listInput,
              command: marker,
              remotePath: marker
            })),
          detailWithUnknown: await rejected(() =>
            window.lovelyres.getKubernetesResourceDetail(
              marker,
              { snapshotHandle: marker, command: marker },
              marker
            )),
          logsWithUnknown: await rejected(() =>
            window.lovelyres.getKubernetesPodLogs(
              marker,
              marker,
              { rowHandle: marker, remotePath: marker }
            )),
          scaleMethod: typeof window.lovelyres.scaleKubernetesDeployment,
          restartMethod: typeof window.lovelyres.restartKubernetesResource,
          deleteMethod: typeof window.lovelyres.deleteKubernetesResource,
          cordonMethod: typeof window.lovelyres.cordonKubernetesNode,
          drainMethod: typeof window.lovelyres.drainKubernetesNode,
          execMethod: typeof window.lovelyres.execKubernetesPod,
          fileMethod: typeof window.lovelyres.openKubernetesFile,
          terminalMethod: typeof window.lovelyres.openKubernetesTerminal,
          exportMethod: typeof window.lovelyres.exportKubernetes,
          genericInvoke: typeof window.lovelyres.invoke,
          markerInDom: document.documentElement.textContent.includes(marker)
        };
      })()`,
    );
    assert(kubernetesBoundary.publicApiCount === MAIN_PRELOAD_API_COUNT, "Kubernetes boundary is outside the exact preload surface");
    for (const name of ["availabilityType", "listType", "detailType", "logsType"]) {
      assert(kubernetesBoundary[name] === "function", `Kubernetes API is unavailable: ${name}`);
    }
    for (const name of ["availabilityArity", "listArity", "detailArity", "logsArity"]) {
      assert(
        typeof kubernetesBoundary[name] === "number",
        `Kubernetes contextBridge method has no callable metadata: ${name}`,
      );
    }
    for (const name of [
      "availability",
      "list",
      "detail",
      "logs",
      "availabilityWithUnknown",
      "listWithUnknown",
      "detailWithUnknown",
      "logsWithUnknown",
    ]) {
      const result = kubernetesBoundary[name];
      assert(isRecord(result) && result.rejected === true, `Kubernetes ${name} did not fail closed`);
      assert(isRecord(result) && result.echoed === false, `Kubernetes ${name} echoed hostile input`);
    }
    for (const name of [
      "scaleMethod",
      "restartMethod",
      "deleteMethod",
      "cordonMethod",
      "drainMethod",
      "execMethod",
      "fileMethod",
      "terminalMethod",
      "exportMethod",
      "genericInvoke",
    ]) {
      assert(kubernetesBoundary[name] === "undefined", `Kubernetes exposed forbidden ${name}`);
    }
    assert(kubernetesBoundary.markerInDom === false, "Kubernetes hostile marker entered the DOM");

    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('Kubernetes'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(client, "document.querySelector('.kubernetes-connect-state') !== null");
    const kubernetesDisconnected = await evaluate<Record<string, unknown>>(
      client,
      `(() => {
        const page = document.querySelector('.kubernetes-page');
        const disconnected = page?.querySelector('.kubernetes-connect-state');
        const title = disconnected?.querySelector('h1');
        const prompt = disconnected?.querySelector('p');
        const content = document.querySelector('.content');
        const resources = performance.getEntriesByType('resource').map(entry => entry.name);
        const text = page?.textContent ?? '';
        const parseRgb = (value) => {
          const parts = value.match(/[0-9.]+/g)?.slice(0, 3).map(Number) ?? [];
          return parts.length === 3 ? parts : [0, 0, 0];
        };
        const luminance = (rgb) => {
          const linear = rgb.map(channel => {
            const value = channel / 255;
            return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
          });
          return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
        };
        const contrast = (foreground, background) => {
          const foregroundLuminance = luminance(parseRgb(foreground));
          const backgroundLuminance = luminance(parseRgb(background));
          return (Math.max(foregroundLuminance, backgroundLuminance) + 0.05) /
            (Math.min(foregroundLuminance, backgroundLuminance) + 0.05);
        };
        const background = content === null ? '' : getComputedStyle(content).backgroundColor;
        const titleColor = title === null ? '' : getComputedStyle(title).color;
        const promptColor = prompt === null ? '' : getComputedStyle(prompt).color;
        return {
          title: title?.textContent ?? '',
          prompt: prompt?.textContent ?? '',
          background,
          titleColor,
          promptColor,
          titleContrast: contrast(titleColor, background),
          promptContrast: contrast(promptColor, background),
          namespaceRows: page?.querySelectorAll('.kubernetes-namespace-list > button').length ?? -1,
          resourceRows: page?.querySelectorAll('.kubernetes-resource-list > button').length ?? -1,
          detailRows: page?.querySelectorAll('.kubernetes-text-result').length ?? -1,
          tabRows: page?.querySelectorAll('.kubernetes-tabs > button').length ?? -1,
          scripts: page?.querySelectorAll('script').length ?? -1,
          images: page?.querySelectorAll('img').length ?? -1,
          inlineHandlers: page?.querySelectorAll('[onclick],[onerror],[onload]').length ?? -1,
          markerVisible: document.documentElement.textContent.includes('forged-kubernetes-capability-must-not-echo'),
          internalIdentityVisible: /bindingHandle|connectionId|sessionId|TargetGuard|targetGeneration|generation|dataRoot|filePath|remotePath|username@/iu.test(text),
          localResources: resources.every(url => url.startsWith('lovelyres://app/'))
        };
      })()`,
    );
    assert(
      typeof kubernetesDisconnected.title === "string" &&
        kubernetesDisconnected.title.includes("连接目标后调查 Kubernetes"),
      "Kubernetes disconnected page title is missing",
    );
    assert(
      typeof kubernetesDisconnected.prompt === "string" &&
        kubernetesDisconnected.prompt.includes("不会修改集群"),
      "Kubernetes page did not render its honest disconnected prompt",
    );
    assert(
      typeof kubernetesDisconnected.titleContrast === "number" &&
        kubernetesDisconnected.titleContrast >= 4.5,
      "Kubernetes disconnected title contrast is below 4.5:1",
    );
    assert(
      typeof kubernetesDisconnected.promptContrast === "number" &&
        kubernetesDisconnected.promptContrast >= 4.5,
      "Kubernetes disconnected prompt contrast is below 4.5:1",
    );
    for (const name of ["namespaceRows", "resourceRows", "detailRows", "tabRows"]) {
      assert(kubernetesDisconnected[name] === 0, `Kubernetes page invented remote rows: ${name}`);
    }
    for (const name of ["scripts", "images", "inlineHandlers"]) {
      assert(kubernetesDisconnected[name] === 0, `Kubernetes page rendered unexpected ${name}`);
    }
    assert(kubernetesDisconnected.markerVisible === false, "forged Kubernetes input reached the page");
    assert(
      kubernetesDisconnected.internalIdentityVisible === false,
      "Kubernetes page exposed internal identity material",
    );
    assert(kubernetesDisconnected.localResources === true, "Kubernetes page loaded a non-local resource");

    await waitFor(client, "document.fonts.status === 'loaded'");
    window.showInactive();
    await new Promise((resolve) => setTimeout(resolve, 100));
    const kubernetesScreenshot = await withTimeout(
      window.webContents.capturePage(),
      "Electron disconnected Kubernetes capturePage",
    ).finally(() => window.hide());
    const kubernetesScreenshotBytes = kubernetesScreenshot.toPNG();
    assert(kubernetesScreenshotBytes.length > 100, "Kubernetes screenshot capture failed");
    fs.writeFileSync(
      path.join(outputDirectory, "kubernetes-disconnected.png"),
      kubernetesScreenshotBytes,
    );

    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('主机全景'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(
      client,
      "document.querySelector('.kubernetes-page') === null && document.querySelector('.system-info-connect-prompt') !== null",
    );
    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('Kubernetes'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(client, "document.querySelector('.kubernetes-connect-state') !== null");
    const kubernetesLifecycle = await evaluate<Record<string, unknown>>(
      client,
      `(() => ({
        remounted: document.querySelectorAll('.kubernetes-connect-state').length === 1,
        noRemoteRows: document.querySelectorAll('.kubernetes-namespace-list > button, .kubernetes-resource-list > button, .kubernetes-text-result, .kubernetes-tabs > button').length === 0,
        prompt: document.querySelector('.kubernetes-connect-state p')?.textContent ?? ''
      }))()`,
    );
    assert(kubernetesLifecycle.remounted === true, "Kubernetes page did not remount cleanly");
    assert(kubernetesLifecycle.noRemoteRows === true, "Kubernetes page retained remote state");
    assert(
      typeof kubernetesLifecycle.prompt === "string" &&
        kubernetesLifecycle.prompt.includes("不会修改集群"),
      "Kubernetes page lost its disconnected state after remount",
    );
    const kubernetesConsole = { errorCount: consoleErrors.length };
    assert(kubernetesConsole.errorCount === 0, "Kubernetes probe emitted console errors");
    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('主机全景'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(client, "document.querySelector('.system-info-connect-prompt') !== null");

    const dockerBoundary = await evaluate<Record<string, unknown>>(
      client,
      `(async () => {
        const marker = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
        const rejected = async (operation) => {
          try {
            await operation();
            return { rejected: false, echoed: false };
          } catch (error) {
            return { rejected: true, echoed: String(error).includes(marker) };
          }
        };
        return {
          publicApiCount: Object.keys(window.lovelyres).length,
          refreshType: typeof window.lovelyres.refreshDockerContainers,
          collectionType: typeof window.lovelyres.getDockerCollection,
          inspectType: typeof window.lovelyres.inspectDockerResource,
          auditType: typeof window.lovelyres.getDockerSecurityAudit,
          logsType: typeof window.lovelyres.getDockerLogs,
          refreshArity: window.lovelyres.refreshDockerContainers.length,
          collectionArity: window.lovelyres.getDockerCollection.length,
          inspectArity: window.lovelyres.inspectDockerResource.length,
          auditArity: window.lovelyres.getDockerSecurityAudit.length,
          logsArity: window.lovelyres.getDockerLogs.length,
          refresh: await rejected(() =>
            window.lovelyres.refreshDockerContainers(marker)),
          collection: await rejected(() =>
            window.lovelyres.getDockerCollection(marker, marker, 'stats')),
          inspect: await rejected(() =>
            window.lovelyres.inspectDockerResource(marker, marker, 'container', marker)),
          audit: await rejected(() =>
            window.lovelyres.getDockerSecurityAudit(marker, marker)),
          logs: await rejected(() =>
            window.lovelyres.getDockerLogs(marker, marker, marker, 200)),
          refreshWithUnknown: await rejected(() =>
            window.lovelyres.refreshDockerContainers({
              bindingHandle: marker,
              command: marker,
              targetIdentity: marker
            })),
          collectionWithUnknown: await rejected(() =>
            window.lovelyres.getDockerCollection(
              marker,
              marker,
              { kind: 'stats', command: marker, remotePath: marker }
            )),
          inspectWithUnknown: await rejected(() =>
            window.lovelyres.inspectDockerResource(
              marker,
              marker,
              'container',
              { resourceHandle: marker, shellText: marker }
            )),
          auditWithUnknown: await rejected(() =>
            window.lovelyres.getDockerSecurityAudit(
              marker,
              { snapshotHandle: marker, targetGeneration: marker }
            )),
          logsWithUnknown: await rejected(() =>
            window.lovelyres.getDockerLogs(
              marker,
              marker,
              marker,
              { tail: 200, command: marker }
            )),
          startMethod: typeof window.lovelyres.startDockerContainer,
          stopMethod: typeof window.lovelyres.stopDockerContainer,
          restartMethod: typeof window.lovelyres.restartDockerContainer,
          removeMethod: typeof window.lovelyres.removeDockerResource,
          execMethod: typeof window.lovelyres.execDockerContainer,
          fileMethod: typeof window.lovelyres.openDockerFile,
          terminalMethod: typeof window.lovelyres.openDockerTerminal,
          exportMethod: typeof window.lovelyres.exportDocker,
          mutationMethod: typeof window.lovelyres.planDockerMutation,
          genericInvoke: typeof window.lovelyres.invoke,
          markerInDom: document.documentElement.textContent.includes(marker)
        };
      })()`,
    );
    assert(dockerBoundary.publicApiCount === MAIN_PRELOAD_API_COUNT, "Docker boundary is outside the exact preload surface");
    for (const name of [
      "refreshType",
      "collectionType",
      "inspectType",
      "auditType",
      "logsType",
    ]) {
      assert(dockerBoundary[name] === "function", "Docker API is unavailable: " + name);
    }
    for (const name of [
      "refreshArity",
      "collectionArity",
      "inspectArity",
      "auditArity",
      "logsArity",
    ]) {
      assert(
        typeof dockerBoundary[name] === "number",
        "Docker contextBridge method has no callable metadata: " + name,
      );
    }
    for (const name of [
      "refresh",
      "collection",
      "inspect",
      "audit",
      "logs",
      "refreshWithUnknown",
      "collectionWithUnknown",
      "inspectWithUnknown",
      "auditWithUnknown",
      "logsWithUnknown",
    ]) {
      const result = dockerBoundary[name];
      assert(isRecord(result) && result.rejected === true, "Docker " + name + " did not fail closed");
      assert(isRecord(result) && result.echoed === false, "Docker " + name + " echoed hostile input");
    }
    for (const name of [
      "startMethod",
      "stopMethod",
      "restartMethod",
      "removeMethod",
      "execMethod",
      "fileMethod",
      "terminalMethod",
      "exportMethod",
      "mutationMethod",
      "genericInvoke",
    ]) {
      assert(dockerBoundary[name] === "undefined", "Docker exposed forbidden " + name);
    }
    assert(dockerBoundary.markerInDom === false, "Docker hostile marker entered the DOM");

    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('Docker'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(client, "document.querySelector('.docker-connect-prompt') !== null");
    const dockerDisconnected = await evaluate<Record<string, unknown>>(
      client,
      `(() => {
        const page = document.querySelector('.docker-page');
        const disconnected = page?.querySelector('.docker-connect-prompt');
        const title = disconnected?.querySelector('h1');
        const prompt = disconnected?.querySelector('p');
        const resources = performance.getEntriesByType('resource').map(entry => entry.name);
        const text = page?.textContent ?? '';
        const parseRgb = (value) => {
          const parts = value.match(/[0-9.]+/g)?.slice(0, 3).map(Number) ?? [];
          return parts.length === 3 ? parts : [0, 0, 0];
        };
        const luminance = (rgb) => {
          const linear = rgb.map(channel => {
            const value = channel / 255;
            return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
          });
          return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
        };
        const contrast = (foreground, background) => {
          const foregroundLuminance = luminance(parseRgb(foreground));
          const backgroundLuminance = luminance(parseRgb(background));
          return (Math.max(foregroundLuminance, backgroundLuminance) + 0.05) /
            (Math.min(foregroundLuminance, backgroundLuminance) + 0.05);
        };
        const background = disconnected === null ? '' : getComputedStyle(disconnected).backgroundColor;
        const titleColor = title === null ? '' : getComputedStyle(title).color;
        const promptColor = prompt === null ? '' : getComputedStyle(prompt).color;
        return {
          title: title?.textContent ?? '',
          prompt: prompt?.textContent ?? '',
          background,
          titleColor,
          promptColor,
          titleContrast: contrast(titleColor, background),
          promptContrast: contrast(promptColor, background),
          tableRows: page?.querySelectorAll('.docker-table tbody tr').length ?? -1,
          resourceRows: page?.querySelectorAll('.docker-resource-list > button').length ?? -1,
          cardRows: page?.querySelectorAll('.docker-card-grid > article').length ?? -1,
          findingRows: page?.querySelectorAll('.docker-findings > article').length ?? -1,
          inspectionRows: page?.querySelectorAll('.docker-inspection').length ?? -1,
          logRows: page?.querySelectorAll('.docker-log-text').length ?? -1,
          tabRows: page?.querySelectorAll('.docker-tabs > button').length ?? -1,
          scripts: page?.querySelectorAll('script').length ?? -1,
          images: page?.querySelectorAll('img').length ?? -1,
          inlineHandlers: page?.querySelectorAll('[onclick],[onerror],[onload]').length ?? -1,
          markerVisible: document.documentElement.textContent.includes(
            'dddddddd-dddd-4ddd-8ddd-dddddddddddd'
          ),
          internalIdentityVisible: /bindingHandle|connectionId|sessionId|TargetGuard|targetGeneration|generation|dataRoot|filePath|remotePath|username@/iu.test(text),
          localResources: resources.every(url => url.startsWith('lovelyres://app/'))
        };
      })()`,
    );
    assert(
      typeof dockerDisconnected.title === "string" &&
        dockerDisconnected.title.includes("连接目标后调查 Docker"),
      "Docker disconnected title is missing",
    );
    assert(
      typeof dockerDisconnected.prompt === "string" &&
        dockerDisconnected.prompt.includes("不会修改容器"),
      "Docker page did not render its honest disconnected prompt",
    );
    assert(
      typeof dockerDisconnected.titleContrast === "number" &&
        dockerDisconnected.titleContrast >= 4.5,
      "Docker disconnected title contrast is below 4.5:1",
    );
    assert(
      typeof dockerDisconnected.promptContrast === "number" &&
        dockerDisconnected.promptContrast >= 4.5,
      "Docker disconnected prompt contrast is below 4.5:1",
    );
    for (const name of [
      "tableRows",
      "resourceRows",
      "cardRows",
      "findingRows",
      "inspectionRows",
      "logRows",
      "tabRows",
    ]) {
      assert(dockerDisconnected[name] === 0, "Docker page invented remote rows: " + name);
    }
    for (const name of ["scripts", "images", "inlineHandlers"]) {
      assert(dockerDisconnected[name] === 0, "Docker page rendered unexpected " + name);
    }
    assert(dockerDisconnected.markerVisible === false, "forged Docker input reached the page");
    assert(
      dockerDisconnected.internalIdentityVisible === false,
      "Docker page exposed internal identity material",
    );
    assert(dockerDisconnected.localResources === true, "Docker page loaded a non-local resource");

    await waitFor(client, "document.fonts.status === 'loaded'");
    window.showInactive();
    await new Promise((resolve) => setTimeout(resolve, 100));
    const dockerScreenshot = await withTimeout(
      window.webContents.capturePage(),
      "Electron disconnected Docker capturePage",
    ).finally(() => window.hide());
    const dockerScreenshotBytes = dockerScreenshot.toPNG();
    assert(dockerScreenshotBytes.length > 100, "Docker screenshot capture failed");
    fs.writeFileSync(
      path.join(outputDirectory, "docker-disconnected.png"),
      dockerScreenshotBytes,
    );

    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('主机全景'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(
      client,
      "document.querySelector('.docker-page') === null && document.querySelector('.system-info-connect-prompt') !== null",
    );
    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('Docker'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(client, "document.querySelector('.docker-connect-prompt') !== null");
    const dockerLifecycle = await evaluate<Record<string, unknown>>(
      client,
      `(() => ({
        remounted: document.querySelectorAll('.docker-connect-prompt').length === 1,
        noRemoteRows: document.querySelectorAll('.docker-table tbody tr, .docker-resource-list > button, .docker-card-grid > article, .docker-findings > article, .docker-inspection, .docker-log-text, .docker-tabs > button').length === 0,
        prompt: document.querySelector('.docker-connect-prompt p')?.textContent ?? ''
      }))()`,
    );
    assert(dockerLifecycle.remounted === true, "Docker page did not remount cleanly");
    assert(dockerLifecycle.noRemoteRows === true, "Docker page retained remote state");
    assert(
      typeof dockerLifecycle.prompt === "string" &&
        dockerLifecycle.prompt.includes("不会修改容器"),
      "Docker page lost its disconnected state after remount",
    );
    const dockerConsole = { errorCount: consoleErrors.length };
    assert(dockerConsole.errorCount === 0, "Docker probe emitted console errors");
    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('主机全景'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(client, "document.querySelector('.system-info-connect-prompt') !== null");

    const packetCaptureBoundary = await evaluate<Record<string, unknown>>(
      client,
      `(async () => {
        const marker = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
        const rejected = async (operation) => {
          try {
            await operation();
            return { rejected: false, echoed: false };
          } catch (error) {
            return { rejected: true, echoed: String(error).includes(marker) };
          }
        };
        const input = { filter: null, packetLimit: 1, durationSeconds: 1 };
        return {
          publicApiCount: Object.keys(window.lovelyres).length,
          listType: typeof window.lovelyres.listPacketCaptureInterfaces,
          startType: typeof window.lovelyres.startPacketCapture,
          pollType: typeof window.lovelyres.pollPacketCapture,
          stopType: typeof window.lovelyres.stopPacketCapture,
          listArity: window.lovelyres.listPacketCaptureInterfaces.length,
          startArity: window.lovelyres.startPacketCapture.length,
          pollArity: window.lovelyres.pollPacketCapture.length,
          stopArity: window.lovelyres.stopPacketCapture.length,
          list: await rejected(() =>
            window.lovelyres.listPacketCaptureInterfaces(marker)),
          start: await rejected(() =>
            window.lovelyres.startPacketCapture(marker, marker, input)),
          poll: await rejected(() =>
            window.lovelyres.pollPacketCapture(marker, marker, 0)),
          stop: await rejected(() =>
            window.lovelyres.stopPacketCapture(marker, marker)),
          listWithUnknown: await rejected(() =>
            window.lovelyres.listPacketCaptureInterfaces({
              bindingHandle: marker,
              command: marker,
              targetIdentity: marker
            })),
          startWithUnknown: await rejected(() =>
            window.lovelyres.startPacketCapture(marker, marker, {
              ...input,
              shellText: marker,
              remotePath: marker
            })),
          pollWithUnknown: await rejected(() =>
            window.lovelyres.pollPacketCapture(marker, marker, {
              afterSequence: 0,
              command: marker
            })),
          stopWithUnknown: await rejected(() =>
            window.lovelyres.stopPacketCapture(marker, {
              captureHandle: marker,
              filePath: marker
            })),
          commandMethod: typeof window.lovelyres.executePacketCaptureCommand,
          fileMethod: typeof window.lovelyres.openPacketCaptureFile,
          terminalMethod: typeof window.lovelyres.openPacketCaptureTerminal,
          downloadMethod: typeof window.lovelyres.downloadPacketCapture,
          exportMethod: typeof window.lovelyres.exportPacketCapture,
          aiMethod: typeof window.lovelyres.analyzePacketCaptureWithAi,
          mutationMethod: typeof window.lovelyres.planPacketCaptureMutation,
          genericInvoke: typeof window.lovelyres.invoke,
          markerInDom: document.documentElement.textContent.includes(marker)
        };
      })()`,
    );
    assert(
      packetCaptureBoundary.publicApiCount === MAIN_PRELOAD_API_COUNT,
      "Packet Capture boundary is outside the exact preload surface",
    );
    for (const name of ["listType", "startType", "pollType", "stopType"]) {
      assert(packetCaptureBoundary[name] === "function", "Packet Capture API is unavailable: " + name);
    }
    for (const name of ["listArity", "startArity", "pollArity", "stopArity"]) {
      assert(
        typeof packetCaptureBoundary[name] === "number",
        "Packet Capture contextBridge method has no callable metadata: " + name,
      );
    }
    for (const name of [
      "list",
      "start",
      "poll",
      "stop",
      "listWithUnknown",
      "startWithUnknown",
      "pollWithUnknown",
      "stopWithUnknown",
    ]) {
      const result = packetCaptureBoundary[name];
      assert(
        isRecord(result) && result.rejected === true,
        "Packet Capture " + name + " did not fail closed",
      );
      assert(
        isRecord(result) && result.echoed === false,
        "Packet Capture " + name + " echoed hostile input",
      );
    }
    for (const name of [
      "commandMethod",
      "fileMethod",
      "terminalMethod",
      "downloadMethod",
      "exportMethod",
      "aiMethod",
      "mutationMethod",
      "genericInvoke",
    ]) {
      assert(
        packetCaptureBoundary[name] === "undefined",
        "Packet Capture exposed forbidden " + name,
      );
    }
    assert(
      packetCaptureBoundary.markerInDom === false,
      "Packet Capture hostile marker entered the DOM",
    );

    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('网络抓包'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(client, "document.querySelector('.packet-capture-connect-state') !== null");
    const packetCaptureDisconnected = await evaluate<Record<string, unknown>>(
      client,
      `(() => {
        const page = document.querySelector('.packet-capture-page');
        const disconnected = page?.querySelector('.packet-capture-connect-state');
        const title = disconnected?.querySelector('h1');
        const prompt = disconnected?.querySelector('p');
        const resources = performance.getEntriesByType('resource').map(entry => entry.name);
        const text = page?.textContent ?? '';
        const parseRgb = (value) => {
          const parts = value.match(/[0-9.]+/g)?.slice(0, 3).map(Number) ?? [];
          return parts.length === 3 ? parts : [0, 0, 0];
        };
        const luminance = (rgb) => {
          const linear = rgb.map(channel => {
            const value = channel / 255;
            return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
          });
          return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
        };
        const contrast = (foreground, background) => {
          const foregroundLuminance = luminance(parseRgb(foreground));
          const backgroundLuminance = luminance(parseRgb(background));
          return (Math.max(foregroundLuminance, backgroundLuminance) + 0.05) /
            (Math.min(foregroundLuminance, backgroundLuminance) + 0.05);
        };
        const background = disconnected === null ? '' : getComputedStyle(disconnected).backgroundColor;
        const titleColor = title === null ? '' : getComputedStyle(title).color;
        const promptColor = prompt === null ? '' : getComputedStyle(prompt).color;
        return {
          title: title?.textContent ?? '',
          prompt: prompt?.textContent ?? '',
          background,
          titleColor,
          promptColor,
          titleContrast: contrast(titleColor, background),
          promptContrast: contrast(promptColor, background),
          interfaceRows: page?.querySelectorAll('.packet-capture-interface-list > button').length ?? -1,
          packetRows: page?.querySelectorAll('.packet-capture-table > button[role="row"]').length ?? -1,
          metricRows: page?.querySelectorAll('.packet-capture-metrics > div').length ?? -1,
          protocolRows: page?.querySelectorAll('.packet-capture-protocols > span:not(:first-child)').length ?? -1,
          detailRows: page?.querySelectorAll('.packet-capture-detail-content').length ?? -1,
          controlRows: page?.querySelectorAll('.packet-capture-controls').length ?? -1,
          scripts: page?.querySelectorAll('script').length ?? -1,
          images: page?.querySelectorAll('img').length ?? -1,
          inlineHandlers: page?.querySelectorAll('[onclick],[onerror],[onload]').length ?? -1,
          markerVisible: document.documentElement.textContent.includes(
            'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'
          ),
          internalIdentityVisible: /bindingHandle|connectionId|sessionId|TargetGuard|targetGeneration|generation|dataRoot|filePath|remotePath|username@/iu.test(text),
          localResources: resources.every(url => url.startsWith('lovelyres://app/'))
        };
      })()`,
    );
    assert(
      typeof packetCaptureDisconnected.title === "string" &&
        packetCaptureDisconnected.title.includes("连接目标后开始受控网络抓包"),
      "Packet Capture disconnected title is missing",
    );
    assert(
      typeof packetCaptureDisconnected.prompt === "string" &&
        packetCaptureDisconnected.prompt.includes("实时抓包只在当前 SSH 目标上进行"),
      "Packet Capture page did not render its honest disconnected prompt",
    );
    assert(
      typeof packetCaptureDisconnected.titleContrast === "number" &&
        packetCaptureDisconnected.titleContrast >= 4.5,
      "Packet Capture disconnected title contrast is below 4.5:1",
    );
    assert(
      typeof packetCaptureDisconnected.promptContrast === "number" &&
        packetCaptureDisconnected.promptContrast >= 4.5,
      "Packet Capture disconnected prompt contrast is below 4.5:1",
    );
    for (const name of [
      "interfaceRows",
      "packetRows",
      "metricRows",
      "protocolRows",
      "detailRows",
      "controlRows",
    ]) {
      assert(
        packetCaptureDisconnected[name] === 0,
        "Packet Capture page invented remote rows: " + name,
      );
    }
    for (const name of ["scripts", "images", "inlineHandlers"]) {
      assert(
        packetCaptureDisconnected[name] === 0,
        "Packet Capture page rendered unexpected " + name,
      );
    }
    assert(
      packetCaptureDisconnected.markerVisible === false,
      "forged Packet Capture input reached the page",
    );
    assert(
      packetCaptureDisconnected.internalIdentityVisible === false,
      "Packet Capture page exposed internal identity material",
    );
    assert(
      packetCaptureDisconnected.localResources === true,
      "Packet Capture page loaded a non-local resource",
    );

    await waitFor(client, "document.fonts.status === 'loaded'");
    window.showInactive();
    await new Promise((resolve) => setTimeout(resolve, 100));
    const packetCaptureScreenshot = await withTimeout(
      window.webContents.capturePage(),
      "Electron disconnected Packet Capture capturePage",
    ).finally(() => window.hide());
    const packetCaptureScreenshotBytes = packetCaptureScreenshot.toPNG();
    assert(packetCaptureScreenshotBytes.length > 100, "Packet Capture screenshot capture failed");
    fs.writeFileSync(
      path.join(outputDirectory, "packet-capture-disconnected.png"),
      packetCaptureScreenshotBytes,
    );

    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('主机全景'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(
      client,
      "document.querySelector('.packet-capture-page') === null && document.querySelector('.system-info-connect-prompt') !== null",
    );
    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('网络抓包'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(client, "document.querySelector('.packet-capture-connect-state') !== null");
    const packetCaptureLifecycle = await evaluate<Record<string, unknown>>(
      client,
      `(() => ({
        remounted: document.querySelectorAll('.packet-capture-connect-state').length === 1,
        noRemoteRows: document.querySelectorAll('.packet-capture-interface-list > button, .packet-capture-table > button[role="row"], .packet-capture-metrics > div, .packet-capture-protocols > span:not(:first-child), .packet-capture-detail-content, .packet-capture-controls').length === 0,
        prompt: document.querySelector('.packet-capture-connect-state p')?.textContent ?? ''
      }))()`,
    );
    assert(
      packetCaptureLifecycle.remounted === true,
      "Packet Capture page did not remount cleanly",
    );
    assert(
      packetCaptureLifecycle.noRemoteRows === true,
      "Packet Capture page retained remote state",
    );
    assert(
      typeof packetCaptureLifecycle.prompt === "string" &&
        packetCaptureLifecycle.prompt.includes("实时抓包只在当前 SSH 目标上进行"),
      "Packet Capture page lost its disconnected state after remount",
    );
    const packetCaptureConsole = { errorCount: consoleErrors.length };
    assert(packetCaptureConsole.errorCount === 0, "Packet Capture probe emitted console errors");
    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('主机全景'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(client, "document.querySelector('.system-info-connect-prompt') !== null");

    const emergencyCommandBoundary = await evaluate<Record<string, unknown>>(
      client,
      `(async () => {
        const marker = 'forged-emergency-command-capability-must-not-echo';
        const rejected = async (operation) => {
          try {
            await operation();
            return { rejected: false, echoed: false };
          } catch (error) {
            return { rejected: true, echoed: String(error).includes(marker) };
          }
        };
        return {
          publicApiCount: Object.keys(window.lovelyres).length,
          loadType: typeof window.lovelyres.loadEmergencyCommandCatalog,
          runType: typeof window.lovelyres.runEmergencyCommand,
          loadArity: window.lovelyres.loadEmergencyCommandCatalog.length,
          runArity: window.lovelyres.runEmergencyCommand.length,
          load: await rejected(() =>
            window.lovelyres.loadEmergencyCommandCatalog(marker)),
          run: await rejected(() =>
            window.lovelyres.runEmergencyCommand(marker, marker, marker)),
          loadWithUnknown: await rejected(() =>
            window.lovelyres.loadEmergencyCommandCatalog({
              bindingHandle: marker,
              commandText: marker,
              targetIdentity: marker
            })),
          runWithUnknown: await rejected(() =>
            window.lovelyres.runEmergencyCommand(
              marker,
              marker,
              { commandHandle: marker, shellText: marker, remotePath: marker }
            )),
          customMethod: typeof window.lovelyres.runCustomEmergencyCommand,
          shellMethod: typeof window.lovelyres.executeEmergencyShell,
          fileMethod: typeof window.lovelyres.openEmergencyFile,
          terminalMethod: typeof window.lovelyres.openEmergencyTerminal,
          exportMethod: typeof window.lovelyres.exportEmergencyCommand,
          mutationMethod: typeof window.lovelyres.planEmergencyMutation,
          genericInvoke: typeof window.lovelyres.invoke,
          markerInDom: document.documentElement.textContent.includes(marker)
        };
      })()`,
    );
    assert(
      emergencyCommandBoundary.publicApiCount === MAIN_PRELOAD_API_COUNT,
      "Emergency Commands boundary is outside the exact preload surface",
    );
    for (const name of ["loadType", "runType"]) {
      assert(
        emergencyCommandBoundary[name] === "function",
        "Emergency Commands API is unavailable: " + name,
      );
    }
    for (const name of ["loadArity", "runArity"]) {
      assert(
        typeof emergencyCommandBoundary[name] === "number",
        "Emergency Commands contextBridge method has no callable metadata: " + name,
      );
    }
    for (const name of ["load", "run", "loadWithUnknown", "runWithUnknown"]) {
      const result = emergencyCommandBoundary[name];
      assert(
        isRecord(result) && result.rejected === true,
        "Emergency Commands " + name + " did not fail closed",
      );
      assert(
        isRecord(result) && result.echoed === false,
        "Emergency Commands " + name + " echoed hostile input",
      );
    }
    for (const name of [
      "customMethod",
      "shellMethod",
      "fileMethod",
      "terminalMethod",
      "exportMethod",
      "mutationMethod",
      "genericInvoke",
    ]) {
      assert(
        emergencyCommandBoundary[name] === "undefined",
        "Emergency Commands exposed forbidden " + name,
      );
    }
    assert(
      emergencyCommandBoundary.markerInDom === false,
      "Emergency Commands hostile marker entered the DOM",
    );

    // Acting on a file the catalogue printed. A capability the sidecar never
    // minted names nothing, so every one of these has to fail closed. They run
    // together because each is a round trip and this call is time-bounded.
    const emergencyPathBoundary = await evaluate<Record<string, unknown>>(
      client,
      `(async () => {
        const marker = 'forged-emergency-path-capability-must-not-echo';
        const rejected = async (operation) => {
          try {
            await operation();
            return { rejected: false, echoed: false };
          } catch (error) {
            return { rejected: true, echoed: String(error).includes(marker) };
          }
        };
        const attempts = {
          inspectPath: () => window.lovelyres.inspectEmergencyPath(marker, marker),
          planPath: () => window.lovelyres.planEmergencyPathAction(marker, marker, 'disarm'),
          confirmPath: () => window.lovelyres.confirmEmergencyPathAction(marker, marker),
          executePath: () => window.lovelyres.executeEmergencyPathAction(marker, marker),
          cancelPath: () => window.lovelyres.cancelEmergencyPathAction(marker, marker),
          planUnknownAction: () =>
            window.lovelyres.planEmergencyPathAction(marker, marker, 'delete'),
          planWithPath: () => window.lovelyres.planEmergencyPathAction(
            marker,
            { pathHandle: marker, path: '/etc/shadow' },
            'quarantine'
          ),
          planWithExtraKeys: () => window.lovelyres.planEmergencyPathAction(
            { bindingHandle: marker, remotePath: '/etc/shadow' },
            marker,
            'disarm'
          )
        };
        const names = Object.keys(attempts);
        const outcomes = await Promise.all(names.map(name => rejected(attempts[name])));
        const results = {};
        names.forEach((name, index) => { results[name] = outcomes[index]; });
        return {
          ...results,
          inspectPathType: typeof window.lovelyres.inspectEmergencyPath,
          planPathType: typeof window.lovelyres.planEmergencyPathAction,
          confirmPathType: typeof window.lovelyres.confirmEmergencyPathAction,
          executePathType: typeof window.lovelyres.executeEmergencyPathAction,
          cancelPathType: typeof window.lovelyres.cancelEmergencyPathAction,
          inspectPathArity: window.lovelyres.inspectEmergencyPath.length,
          planPathArity: window.lovelyres.planEmergencyPathAction.length,
          quarantineMethod: typeof window.lovelyres.quarantineEmergencyPath,
          removeMethod: typeof window.lovelyres.removeEmergencyPath,
          chmodMethod: typeof window.lovelyres.chmodEmergencyPath,
          markerInDom: document.documentElement.textContent.includes(marker)
        };
      })()`,
    );
    for (const name of [
      "inspectPathType",
      "planPathType",
      "confirmPathType",
      "executePathType",
      "cancelPathType",
    ]) {
      assert(
        emergencyPathBoundary[name] === "function",
        "Emergency path API is unavailable: " + name,
      );
    }
    for (const name of ["inspectPathArity", "planPathArity"]) {
      assert(
        typeof emergencyPathBoundary[name] === "number",
        "Emergency path contextBridge method has no callable metadata: " + name,
      );
    }
    for (const name of [
      "inspectPath",
      "planPath",
      "confirmPath",
      "executePath",
      "cancelPath",
      "planUnknownAction",
      "planWithPath",
      "planWithExtraKeys",
    ]) {
      const result = emergencyPathBoundary[name];
      assert(
        isRecord(result) && result.rejected === true,
        "Emergency path " + name + " did not fail closed",
      );
      assert(
        isRecord(result) && result.echoed === false,
        "Emergency path " + name + " echoed hostile input",
      );
    }
    // A file is disarmed or quarantined through a plan, never by a method that
    // does it outright.
    for (const name of ["quarantineMethod", "removeMethod", "chmodMethod"]) {
      assert(
        emergencyPathBoundary[name] === "undefined",
        "Emergency path exposed forbidden " + name,
      );
    }
    assert(
      emergencyPathBoundary.markerInDom === false,
      "Emergency path hostile marker entered the DOM",
    );

    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('命令工作台'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(client, "document.querySelector('.emergency-commands-disconnected') !== null");
    const emergencyCommandDisconnected = await evaluate<Record<string, unknown>>(
      client,
      `(() => {
        const page = document.querySelector('.emergency-commands-disconnected');
        const title = page?.querySelector('h1');
        const prompt = page?.querySelector('p');
        const resources = performance.getEntriesByType('resource').map(entry => entry.name);
        const text = page?.textContent ?? '';
        const parseRgb = (value) => {
          const parts = value.match(/[0-9.]+/g)?.slice(0, 3).map(Number) ?? [];
          return parts.length === 3 ? parts : [0, 0, 0];
        };
        const luminance = (rgb) => {
          const linear = rgb.map(channel => {
            const value = channel / 255;
            return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
          });
          return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
        };
        const contrast = (foreground, background) => {
          const foregroundLuminance = luminance(parseRgb(foreground));
          const backgroundLuminance = luminance(parseRgb(background));
          return (Math.max(foregroundLuminance, backgroundLuminance) + 0.05) /
            (Math.min(foregroundLuminance, backgroundLuminance) + 0.05);
        };
        const background = page === null ? '' : getComputedStyle(page).backgroundColor;
        const titleColor = title === null ? '' : getComputedStyle(title).color;
        const promptColor = prompt === null ? '' : getComputedStyle(prompt).color;
        return {
          title: title?.textContent ?? '',
          prompt: prompt?.textContent ?? '',
          background,
          titleColor,
          promptColor,
          titleContrast: contrast(titleColor, background),
          promptContrast: contrast(promptColor, background),
          commandRows: page?.querySelectorAll('.emergency-commands-list > button').length ?? -1,
          categoryRows: page?.querySelectorAll('.emergency-commands-categories > button').length ?? -1,
          resultRows: page?.querySelectorAll('.emergency-command-result').length ?? -1,
          outputRows: page?.querySelectorAll('.emergency-command-output').length ?? -1,
          scripts: page?.querySelectorAll('script').length ?? -1,
          images: page?.querySelectorAll('img').length ?? -1,
          inlineHandlers: page?.querySelectorAll('[onclick],[onerror],[onload]').length ?? -1,
          markerVisible: document.documentElement.textContent.includes(
            'forged-emergency-command-capability-must-not-echo'
          ),
          internalIdentityVisible: /bindingHandle|connectionId|sessionId|TargetGuard|targetGeneration|generation|dataRoot|filePath|remotePath|username@/iu.test(text),
          localResources: resources.every(url => url.startsWith('lovelyres://app/'))
        };
      })()`,
    );
    assert(
      emergencyCommandDisconnected.title === "应急命令工作台",
      "Emergency Commands disconnected title is missing",
    );
    assert(
      typeof emergencyCommandDisconnected.prompt === "string" &&
        emergencyCommandDisconnected.prompt.includes("连接 SSH 目标后"),
      "Emergency Commands page did not render its honest disconnected prompt",
    );
    assert(
      typeof emergencyCommandDisconnected.titleContrast === "number" &&
        emergencyCommandDisconnected.titleContrast >= 4.5,
      "Emergency Commands disconnected title contrast is below 4.5:1",
    );
    assert(
      typeof emergencyCommandDisconnected.promptContrast === "number" &&
        emergencyCommandDisconnected.promptContrast >= 4.5,
      "Emergency Commands disconnected prompt contrast is below 4.5:1",
    );
    for (const name of ["commandRows", "categoryRows", "resultRows", "outputRows"]) {
      assert(
        emergencyCommandDisconnected[name] === 0,
        "Emergency Commands page invented remote rows: " + name,
      );
    }
    for (const name of ["scripts", "images", "inlineHandlers"]) {
      assert(
        emergencyCommandDisconnected[name] === 0,
        "Emergency Commands page rendered unexpected " + name,
      );
    }
    assert(
      emergencyCommandDisconnected.markerVisible === false,
      "forged Emergency Commands input reached the page",
    );
    assert(
      emergencyCommandDisconnected.internalIdentityVisible === false,
      "Emergency Commands page exposed internal identity material",
    );
    assert(
      emergencyCommandDisconnected.localResources === true,
      "Emergency Commands page loaded a non-local resource",
    );

    await waitFor(client, "document.fonts.status === 'loaded'");
    window.showInactive();
    await new Promise((resolve) => setTimeout(resolve, 100));
    const emergencyCommandScreenshot = await withTimeout(
      window.webContents.capturePage(),
      "Electron disconnected Emergency Commands capturePage",
    ).finally(() => window.hide());
    const emergencyCommandScreenshotBytes = emergencyCommandScreenshot.toPNG();
    assert(
      emergencyCommandScreenshotBytes.length > 100,
      "Emergency Commands screenshot capture failed",
    );
    fs.writeFileSync(
      path.join(outputDirectory, "emergency-commands-disconnected.png"),
      emergencyCommandScreenshotBytes,
    );

    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('主机全景'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(
      client,
      "document.querySelector('.emergency-commands-page') === null && document.querySelector('.system-info-connect-prompt') !== null",
    );
    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('命令工作台'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(client, "document.querySelector('.emergency-commands-disconnected') !== null");
    const emergencyCommandLifecycle = await evaluate<Record<string, unknown>>(
      client,
      `(() => ({
        remounted: document.querySelectorAll('.emergency-commands-disconnected').length === 1,
        noRemoteRows: document.querySelectorAll('.emergency-commands-list > button, .emergency-commands-categories > button, .emergency-command-result, .emergency-command-output').length === 0,
        prompt: document.querySelector('.emergency-commands-disconnected p')?.textContent ?? ''
      }))()`,
    );
    assert(
      emergencyCommandLifecycle.remounted === true,
      "Emergency Commands page did not remount cleanly",
    );
    assert(
      emergencyCommandLifecycle.noRemoteRows === true,
      "Emergency Commands page retained remote state",
    );
    assert(
      typeof emergencyCommandLifecycle.prompt === "string" &&
        emergencyCommandLifecycle.prompt.includes("连接 SSH 目标后"),
      "Emergency Commands page lost its disconnected state after remount",
    );
    const emergencyCommandConsole = { errorCount: consoleErrors.length };
    assert(
      emergencyCommandConsole.errorCount === 0,
      "Emergency Commands probe emitted console errors",
    );
    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.textContent?.includes('主机全景'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(client, "document.querySelector('.system-info-connect-prompt') !== null");

    const applicationLogBoundary = await evaluate<Record<string, unknown>>(
      client,
      `(async () => {
        const marker = 'application-log-cdp-hostile-marker-must-not-echo';
        const filter = { minimumLevel: null, search: '' };
        const rejected = async (operation) => {
          try {
            await operation();
            return { rejected: false, echoed: false };
          } catch (error) {
            return { rejected: true, echoed: String(error).includes(marker) };
          }
        };
        const snapshot = await window.lovelyres.listApplicationLogs(filter);
        const preview = await window.lovelyres.getApplicationLogPreview(filter);
        const level = await window.lovelyres.setApplicationLogLevel('info');
        return {
          publicApiCount: Object.keys(window.lovelyres).length,
          listType: typeof window.lovelyres.listApplicationLogs,
          levelType: typeof window.lovelyres.setApplicationLogLevel,
          clearType: typeof window.lovelyres.clearApplicationLogBuffer,
          previewType: typeof window.lovelyres.getApplicationLogPreview,
          exportType: typeof window.lovelyres.exportApplicationLogs,
          listArity: window.lovelyres.listApplicationLogs.length,
          levelArity: window.lovelyres.setApplicationLogLevel.length,
          clearArity: window.lovelyres.clearApplicationLogBuffer.length,
          previewArity: window.lovelyres.getApplicationLogPreview.length,
          exportArity: window.lovelyres.exportApplicationLogs.length,
          capacity: snapshot?.capacity ?? -1,
          totalBuffered: snapshot?.totalBuffered ?? -1,
          displayed: snapshot?.displayed ?? -1,
          entryRows: Array.isArray(snapshot?.entries) ? snapshot.entries.length : -1,
          entriesBounded: Array.isArray(snapshot?.entries) &&
            snapshot.entries.length <= 100 &&
            snapshot.entries.every(entry =>
              typeof entry?.message === 'string' &&
              typeof entry?.module === 'string' &&
              Array.isArray(entry?.details) &&
              entry.details.length <= 32
            ),
          previewCount: preview?.entryCount ?? -1,
          previewTruncated: preview?.truncated,
          previewContainsMarker: String(preview?.content ?? '').includes(marker),
          levelResult: level?.level,
          levelPersisted: level?.persisted,
          listWithUnknown: await rejected(() =>
            window.lovelyres.listApplicationLogs({
              ...filter,
              shellText: marker
            })),
          levelWithUnknown: await rejected(() =>
            window.lovelyres.setApplicationLogLevel({
              level: 'info',
              shellText: marker
            })),
          previewWithUnknown: await rejected(() =>
            window.lovelyres.getApplicationLogPreview({
              ...filter,
              filePath: marker
            })),
          exportWithUnknown: await rejected(() =>
            window.lovelyres.exportApplicationLogs({
              ...filter,
              contents: marker
            })),
          stderrMethod: typeof window.lovelyres.readBackendStderr,
          fileMethod: typeof window.lovelyres.readApplicationLogFile,
          pathMethod: typeof window.lovelyres.getApplicationLogPath,
          payloadMethod: typeof window.lovelyres.prepareApplicationLogExport,
          genericInvoke: typeof window.lovelyres.invoke,
          markerInSnapshot: JSON.stringify(snapshot).includes(marker),
          markerInDom: document.documentElement.textContent.includes(marker)
        };
      })()`,
    );
    assert(
      applicationLogBoundary.publicApiCount === MAIN_PRELOAD_API_COUNT,
      "Application Log boundary is outside the exact preload surface",
    );
    for (const name of ["listType", "levelType", "clearType", "previewType", "exportType"]) {
      assert(
        applicationLogBoundary[name] === "function",
        "Application Log API is unavailable: " + name,
      );
    }
    for (const name of ["listArity", "levelArity", "clearArity", "previewArity", "exportArity"]) {
      assert(
        typeof applicationLogBoundary[name] === "number",
        "Application Log contextBridge method has no callable metadata: " + name,
      );
    }
    assert(applicationLogBoundary.capacity === 500, "Application Log ring capacity is not 500");
    assert(
      typeof applicationLogBoundary.totalBuffered === "number" &&
        applicationLogBoundary.totalBuffered >= 0 &&
        applicationLogBoundary.totalBuffered <= 500,
      "Application Log totalBuffered is outside the bounded ring",
    );
    assert(
      applicationLogBoundary.displayed === applicationLogBoundary.entryRows &&
        typeof applicationLogBoundary.displayed === "number" &&
        applicationLogBoundary.displayed >= 0 &&
        applicationLogBoundary.displayed <= 100 &&
        applicationLogBoundary.entriesBounded === true,
      "Application Log snapshot is not bounded or correlated",
    );
    assert(
      typeof applicationLogBoundary.previewCount === "number" &&
        applicationLogBoundary.previewCount >= 0 &&
        applicationLogBoundary.previewCount <= 500 &&
        typeof applicationLogBoundary.previewTruncated === "boolean" &&
        applicationLogBoundary.previewContainsMarker === false,
      "Application Log preview is invalid or retained hostile input",
    );
    assert(
      applicationLogBoundary.levelResult === "info" &&
        applicationLogBoundary.levelPersisted === false,
      "Application Log dynamic level result falsely claimed persistence",
    );
    for (const name of [
      "listWithUnknown",
      "levelWithUnknown",
      "previewWithUnknown",
      "exportWithUnknown",
    ]) {
      const result = applicationLogBoundary[name];
      assert(
        isRecord(result) && result.rejected === true,
        "Application Log " + name + " did not fail closed",
      );
      assert(
        isRecord(result) && result.echoed === false,
        "Application Log " + name + " echoed hostile input",
      );
    }
    for (const name of [
      "stderrMethod",
      "fileMethod",
      "pathMethod",
      "payloadMethod",
      "genericInvoke",
    ]) {
      assert(
        applicationLogBoundary[name] === "undefined",
        "Application Log exposed forbidden " + name,
      );
    }
    assert(
      applicationLogBoundary.markerInSnapshot === false &&
        applicationLogBoundary.markerInDom === false,
      "Application Log hostile marker crossed the process-local boundary",
    );

    await evaluate(
      client,
      `(() => {
        const button = document.querySelector('[data-testid="open-application-log"]');
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(client, "document.querySelector('.application-log-overlay') !== null");
    await waitFor(
      client,
      "document.querySelector('.application-log-list')?.getAttribute('aria-busy') === 'false' && document.querySelector('.application-log-state[role=\"alert\"]') === null",
    );
    const applicationLogOverlay = await evaluate<Record<string, unknown>>(
      client,
      `(() => {
        const overlay = document.querySelector('.application-log-overlay');
        const title = overlay?.querySelector('#application-log-title');
        const footnote = overlay?.querySelector('.application-log-footnote');
        const search = overlay?.querySelector('input[type="search"]');
        const resources = performance.getEntriesByType('resource').map(entry => entry.name);
        const text = overlay?.textContent ?? '';
        const parseRgb = (value) => {
          const parts = value.match(/[0-9.]+/g)?.slice(0, 3).map(Number) ?? [];
          return parts.length === 3 ? parts : [0, 0, 0];
        };
        const luminance = (rgb) => {
          const linear = rgb.map(channel => {
            const value = channel / 255;
            return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
          });
          return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
        };
        const contrast = (foreground, background) => {
          const foregroundLuminance = luminance(parseRgb(foreground));
          const backgroundLuminance = luminance(parseRgb(background));
          return (Math.max(foregroundLuminance, backgroundLuminance) + 0.05) /
            (Math.min(foregroundLuminance, backgroundLuminance) + 0.05);
        };
        const background = overlay === null ? '' : getComputedStyle(overlay).backgroundColor;
        const titleColor = title === null ? '' : getComputedStyle(title).color;
        const footnoteColor = footnote === null ? '' : getComputedStyle(footnote).color;
        return {
          dialogs: document.querySelectorAll('.application-log-overlay[role="dialog"][aria-modal="true"]').length,
          title: title?.textContent ?? '',
          capacityText: overlay?.querySelector('.application-log-heading span')?.textContent ?? '',
          entryRows: overlay?.querySelectorAll('.application-log-entry').length ?? -1,
          detailRows: overlay?.querySelectorAll('.application-log-entry dl > div').length ?? -1,
          errorRows: overlay?.querySelectorAll('.application-log-state[role="alert"]').length ?? -1,
          scripts: overlay?.querySelectorAll('script').length ?? -1,
          images: overlay?.querySelectorAll('img').length ?? -1,
          inlineHandlers: overlay?.querySelectorAll('[onclick],[onerror],[onload]').length ?? -1,
          passwordInputs: overlay?.querySelectorAll('input[type="password"],input[type="file"]').length ?? -1,
          focusedSearch: document.activeElement === search,
          sidebarInert: document.querySelector('.sidebar')?.inert === true,
          workspaceInert: document.querySelector('.workspace')?.inert === true,
          sidebarHidden: document.querySelector('.sidebar')?.getAttribute('aria-hidden') === 'true',
          workspaceHidden: document.querySelector('.workspace')?.getAttribute('aria-hidden') === 'true',
          internalPayloadVisible: /InternalApplicationLogExportPayload|suggestedName|selectedPath|filePath|contents|archiveRoot|dataRoot/iu.test(text),
          markerVisible: text.includes('application-log-cdp-hostile-marker-must-not-echo'),
          localResources: resources.every(url => url.startsWith('lovelyres://app/')),
          titleContrast: contrast(titleColor, background),
          footnoteContrast: contrast(footnoteColor, background)
        };
      })()`,
    );
    assert(
      applicationLogOverlay.dialogs === 1 &&
        applicationLogOverlay.title === "应用诊断日志",
      "Application Log overlay did not mount as one modal dialog",
    );
    assert(
      typeof applicationLogOverlay.capacityText === "string" &&
        applicationLogOverlay.capacityText.includes("/500") &&
        applicationLogOverlay.capacityText.includes("最近 100 条"),
      "Application Log overlay omitted its honest ring/display bounds",
    );
    assert(
      typeof applicationLogOverlay.entryRows === "number" &&
        applicationLogOverlay.entryRows >= 0 &&
        applicationLogOverlay.entryRows <= 100 &&
        typeof applicationLogOverlay.detailRows === "number" &&
        applicationLogOverlay.detailRows >= 0 &&
        applicationLogOverlay.errorRows === 0,
      "Application Log overlay rendered unbounded or failed rows",
    );
    for (const name of ["scripts", "images", "inlineHandlers", "passwordInputs"]) {
      assert(
        applicationLogOverlay[name] === 0,
        "Application Log overlay rendered unexpected " + name,
      );
    }
    for (const name of [
      "focusedSearch",
      "sidebarInert",
      "workspaceInert",
      "sidebarHidden",
      "workspaceHidden",
      "localResources",
    ]) {
      assert(
        applicationLogOverlay[name] === true,
        "Application Log overlay failed modal/local invariant: " + name,
      );
    }
    assert(
      applicationLogOverlay.internalPayloadVisible === false &&
        applicationLogOverlay.markerVisible === false,
      "Application Log overlay exposed internal payload or hostile input",
    );
    assert(
      typeof applicationLogOverlay.titleContrast === "number" &&
        applicationLogOverlay.titleContrast >= 4.5,
      "Application Log title contrast is below 4.5:1",
    );
    assert(
      typeof applicationLogOverlay.footnoteContrast === "number" &&
        applicationLogOverlay.footnoteContrast >= 4.5,
      "Application Log footnote contrast is below 4.5:1",
    );

    await waitFor(client, "document.fonts.status === 'loaded'");
    window.showInactive();
    await new Promise((resolve) => setTimeout(resolve, 100));
    const applicationLogScreenshot = await withTimeout(
      window.webContents.capturePage(),
      "Electron Application Log overlay capturePage",
    ).finally(() => window.hide());
    const applicationLogScreenshotBytes = applicationLogScreenshot.toPNG();
    assert(applicationLogScreenshotBytes.length > 100, "Application Log screenshot capture failed");
    fs.writeFileSync(
      path.join(outputDirectory, "application-log-overlay.png"),
      applicationLogScreenshotBytes,
    );

    await evaluate(
      client,
      `(() => {
        document.dispatchEvent(new KeyboardEvent('keydown', {
          key: 'Escape', bubbles: true, cancelable: true
        }));
        return true;
      })()`,
    );
    await waitFor(client, "document.querySelector('.application-log-overlay') === null");
    await new Promise((resolve) => setTimeout(resolve, 50));
    const applicationLogEscape = await evaluate<Record<string, unknown>>(
      client,
      `(() => ({
        closed: document.querySelector('.application-log-overlay') === null,
        focusRestored: document.activeElement === document.querySelector('[data-testid="open-application-log"]'),
        sidebarInert: document.querySelector('.sidebar')?.inert === true,
        workspaceInert: document.querySelector('.workspace')?.inert === true
      }))()`,
    );
    assert(applicationLogEscape.closed === true, "Escape did not close Application Log");
    assert(
      applicationLogEscape.focusRestored === true,
      "Application Log did not restore focus to its trigger",
    );
    assert(
      applicationLogEscape.sidebarInert === false &&
        applicationLogEscape.workspaceInert === false,
      "Application Log left the background inert after close",
    );

    await evaluate(
      client,
      `(() => {
        const button = document.querySelector('[data-testid="open-application-log"]');
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(client, "document.querySelector('.application-log-overlay') !== null");
    await waitFor(
      client,
      "document.querySelector('.application-log-list')?.getAttribute('aria-busy') === 'false'",
    );
    const applicationLogLifecycle = await evaluate<Record<string, unknown>>(
      client,
      `(() => ({
        remounted: document.querySelectorAll('.application-log-overlay').length === 1,
        boundedRows: document.querySelectorAll('.application-log-entry').length <= 100,
        markerVisible: document.querySelector('.application-log-overlay')?.textContent.includes(
          'application-log-cdp-hostile-marker-must-not-echo'
        ) === true,
        internalPayloadVisible: /suggestedName|selectedPath|filePath|contents|archiveRoot|dataRoot/iu.test(
          document.querySelector('.application-log-overlay')?.textContent ?? ''
        )
      }))()`,
    );
    assert(
      applicationLogLifecycle.remounted === true &&
        applicationLogLifecycle.boundedRows === true,
      "Application Log overlay did not remount with bounded state",
    );
    assert(
      applicationLogLifecycle.markerVisible === false &&
        applicationLogLifecycle.internalPayloadVisible === false,
      "Application Log remount exposed stale hostile or internal payload state",
    );
    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.application-log-actions button')]
          .find(candidate => candidate.textContent?.includes('关闭'));
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(client, "document.querySelector('.application-log-overlay') === null");
    const applicationLogConsole = { errorCount: consoleErrors.length };
    assert(
      applicationLogConsole.errorCount === 0,
      "Application Log probe emitted console errors",
    );

    const unauthorizedTerminal = await probeUnauthorizedTerminalRenderer(outputDirectory);

    const settingsSecretMarker = "settings-cdp-secret-20260824-must-not-return";
    const settingsBoundary = await evaluate<Record<string, unknown>>(
      client,
      `(async () => {
        const snapshot = await window.lovelyres.loadSettings();
        const provider = {
          id: 'debug-plain-text',
          label: '</option><script>settings-plain-text()</script>',
          kind: 'open-ai-compatible',
          endpoint: 'http://127.0.0.1:11434/v1',
          model: 'local-model',
          enabled: true
        };
        const providers = snapshot.ai.providers.map(({ hasApiKey: _hasApiKey, ...entry }) =>
          entry.id === provider.id ? provider : entry
        );
        if (!providers.some(entry => entry.id === provider.id)) providers.push(provider);
        const input = {
          ...snapshot,
          ai: { ...snapshot.ai, providers, defaultProviderId: provider.id }
        };
        let extraPathRejected = false;
        let extraPathError = '';
        try {
          await window.lovelyres.saveSettings({ ...input, dataRoot: 'renderer-path-marker' });
        } catch (error) {
          extraPathRejected = true;
          extraPathError = String(error);
        }
        let secretFieldRejected = false;
        let secretFieldError = '';
        try {
          const secretProviders = providers.map(entry =>
            entry.id === provider.id ? { ...entry, apiKey: 'renderer-secret-marker' } : entry
          );
          await window.lovelyres.saveSettings({
            ...input,
            ai: { ...input.ai, providers: secretProviders }
          });
        } catch (error) {
          secretFieldRejected = true;
          secretFieldError = String(error);
        }
        const saved = await window.lovelyres.saveSettings(input);
        const savedProvider = saved.ai.providers.find(entry => entry.id === provider.id);
        return {
          loadCallable: typeof window.lovelyres.loadSettings === 'function',
          saveCallable: typeof window.lovelyres.saveSettings === 'function',
          extraPathRejected,
          extraPathEchoed: extraPathError.includes('renderer-path-marker'),
          secretFieldRejected,
          secretFieldEchoed: secretFieldError.includes('renderer-secret-marker'),
          topKeys: Object.keys(saved).sort(),
          providerKeys: Object.keys(savedProvider ?? {}).sort(),
          providerLabel: savedProvider?.label ?? '',
          providerHasApiKey: savedProvider?.hasApiKey,
          passwordKey: Object.prototype.hasOwnProperty.call(savedProvider ?? {}, 'apiKey')
        };
      })()`,
    );
    assert(settingsBoundary.loadCallable === true, "settings load API is unavailable");
    assert(settingsBoundary.saveCallable === true, "settings save API is unavailable");
    assert(settingsBoundary.extraPathRejected === true, "settings save accepted an extra data root");
    assert(settingsBoundary.extraPathEchoed === false, "settings path marker was echoed to renderer");
    assert(settingsBoundary.secretFieldRejected === true, "settings save accepted an API key field");
    assert(settingsBoundary.secretFieldEchoed === false, "settings secret marker was echoed to renderer");
    assert(
      Array.isArray(settingsBoundary.topKeys) &&
        !settingsBoundary.topKeys.includes("dataRoot") &&
        !settingsBoundary.topKeys.includes("path"),
      "settings snapshot exposed a data root or path",
    );
    assert(
      Array.isArray(settingsBoundary.providerKeys) &&
        settingsBoundary.providerKeys.join(",") ===
          "enabled,endpoint,hasApiKey,id,kind,label,model",
      "settings provider snapshot shape drifted or exposed a credential",
    );
    assert(settingsBoundary.providerHasApiKey === false, "debug Provider unexpectedly has a secret");
    assert(settingsBoundary.passwordKey === false, "settings Provider returned an API key field");

    await evaluate(
      client,
      `(() => {
        document.querySelector('[data-testid="open-settings"]')?.click();
        return true;
      })()`,
    );
    await waitFor(
      client,
      "document.querySelector('.settings-panel .settings-page') !== null && document.querySelectorAll('.settings-tabs [role=\"tab\"]').length === 4",
    );
    const settingsOverlay = await evaluate<Record<string, unknown>>(
      client,
      `(() => {
        const panel = document.querySelector('.settings-panel');
        const tabs = [...document.querySelectorAll('.settings-tabs [role="tab"]')];
        const close = document.querySelector('.settings-icon-button');
        const initiallyFocused = document.activeElement === close;
        close?.focus();
        document.dispatchEvent(new KeyboardEvent('keydown', {
          key: 'Tab', shiftKey: true, bubbles: true, cancelable: true
        }));
        return {
          modal: panel?.getAttribute('aria-modal'),
          tabs: tabs.map(tab => tab.textContent?.trim()),
          passwordInputs: panel?.querySelectorAll('input[type="password"]').length ?? -1,
          initiallyFocused,
          focusTrapped: panel?.contains(document.activeElement) ?? false,
          sidebarInert: document.querySelector('.sidebar')?.inert,
          workspaceInert: document.querySelector('.workspace')?.inert,
          sidebarHidden: document.querySelector('.sidebar')?.getAttribute('aria-hidden'),
          workspaceHidden: document.querySelector('.workspace')?.getAttribute('aria-hidden')
        };
      })()`,
    );
    assert(settingsOverlay.modal === "true", "Settings overlay is not modal");
    assert(
      Array.isArray(settingsOverlay.tabs) && settingsOverlay.tabs.join(",") === "通用,连接,终端,AI",
      "Settings overlay did not expose the fixed four tabs",
    );
    assert(settingsOverlay.passwordInputs === 0, "Settings phase one mounted a password input");
    assert(settingsOverlay.initiallyFocused === true, "Settings overlay did not take initial focus");
    assert(settingsOverlay.focusTrapped === true, "Settings focus escaped the modal");
    assert(settingsOverlay.sidebarInert === true, "Settings did not make the sidebar inert");
    assert(settingsOverlay.workspaceInert === true, "Settings did not make the workspace inert");
    assert(settingsOverlay.sidebarHidden === "true", "Settings did not hide the sidebar from AT");
    assert(settingsOverlay.workspaceHidden === "true", "Settings did not hide the workspace from AT");

    await evaluate(
      client,
      `(() => {
        document.querySelector('#settings-tab-ai')?.click();
        return true;
      })()`,
    );
    await waitFor(
      client,
      "document.querySelector('#settings-page-ai')?.textContent.includes('</option><script>settings-plain-text()</script>') === true",
    );
    const settingsPlainText = await evaluate<Record<string, unknown>>(
      client,
      `(() => {
        const panel = document.querySelector('.settings-panel');
        return {
          hostileTextVisible: panel?.textContent.includes('</option><script>settings-plain-text()</script>'),
          scripts: panel?.querySelectorAll('script').length ?? -1,
          images: panel?.querySelectorAll('img').length ?? -1,
          inlineHandlers: panel?.querySelectorAll('[onclick],[onerror],[onload]').length ?? -1,
          passwordInputs: panel?.querySelectorAll('input[type="password"]').length ?? -1,
          passwordValuesEmpty: [...(panel?.querySelectorAll('input[type="password"]') ?? [])]
            .every(input => input instanceof HTMLInputElement && input.value === ''),
          credentialState: panel?.querySelector('.settings-credential-state')?.textContent ?? '',
          bodyHasPathMarker: document.body.textContent.includes('renderer-path-marker'),
          bodyHasSecretMarker: document.body.textContent.includes('renderer-secret-marker')
        };
      })()`,
    );
    assert(settingsPlainText.hostileTextVisible === true, "hostile Settings label was not preserved as text");
    assert(settingsPlainText.scripts === 0, "Settings text created a script element");
    assert(settingsPlainText.images === 0, "Settings text created an image element");
    assert(settingsPlainText.inlineHandlers === 0, "Settings text created an inline handler");
    assert(settingsPlainText.passwordInputs === 1, "Settings phase two did not mount exactly one write-only password input");
    assert(settingsPlainText.passwordValuesEmpty === true, "Settings password input retained a value during CDP smoke");
    assert(
      typeof settingsPlainText.credentialState === "string" &&
        settingsPlainText.credentialState.includes("未配置"),
      "Settings did not project credential presence safely",
    );
    assert(settingsPlainText.bodyHasPathMarker === false, "Settings rendered a rejected path marker");
    assert(settingsPlainText.bodyHasSecretMarker === false, "Settings rendered a rejected secret marker");

    await evaluate(
      client,
      `(() => {
        const input = document.querySelector('[data-testid="settings-api-key-input"]');
        if (!(input instanceof HTMLInputElement)) return false;
        const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
        setter?.call(input, ${JSON.stringify(settingsSecretMarker)});
        input.dispatchEvent(new Event('input', { bubbles: true }));
        return true;
      })()`,
    );
    await waitFor(
      client,
      "document.querySelector('[data-testid=\"settings-api-key-replace\"]')?.disabled === false",
    );
    await evaluate(
      client,
      `(() => {
        document.querySelector('[data-testid="settings-api-key-replace"]')?.click();
        return true;
      })()`,
    );
    await waitFor(
      client,
      `document.querySelector('[data-testid="settings-api-key-input"]')?.value === '' &&
        document.querySelector('.settings-credential-state')?.textContent.includes('已加密保存') === true`,
    );
    const settingsSecretReplacement = await evaluate<Record<string, unknown>>(
      client,
      `(async () => {
        const snapshot = await window.lovelyres.loadSettings();
        const provider = snapshot.ai.providers.find(entry => entry.id === 'debug-plain-text');
        const encoded = JSON.stringify(snapshot);
        return {
          providerHasApiKey: provider?.hasApiKey,
          providerHasSecretField: Object.prototype.hasOwnProperty.call(provider ?? {}, 'apiKey'),
          inputEmpty: document.querySelector('[data-testid="settings-api-key-input"]')?.value === '',
          bodyHasSecret: document.body.textContent.includes(${JSON.stringify(settingsSecretMarker)}),
          snapshotHasSecret: encoded.includes(${JSON.stringify(settingsSecretMarker)}),
          genericSecretWriter: typeof window.lovelyres.setSettingsSecret,
          pathWriter: typeof window.lovelyres.writeSettingsPath,
          commandMethod: typeof window.lovelyres.executeSettingsCommand
        };
      })()`,
    );
    assert(settingsSecretReplacement.providerHasApiKey === true, "Settings write-only replacement was not verified");
    assert(settingsSecretReplacement.providerHasSecretField === false, "Settings replacement returned an API key field");
    assert(settingsSecretReplacement.inputEmpty === true, "Settings password input retained the submitted secret");
    assert(settingsSecretReplacement.bodyHasSecret === false, "Settings rendered the submitted secret");
    assert(settingsSecretReplacement.snapshotHasSecret === false, "Settings snapshot returned the submitted secret");
    assert(settingsSecretReplacement.genericSecretWriter === "undefined", "Settings exposed a generic secret writer");
    assert(settingsSecretReplacement.pathWriter === "undefined", "Settings exposed a path writer");
    assert(settingsSecretReplacement.commandMethod === "undefined", "Settings exposed a command capability");

    window.showInactive();
    await new Promise((resolve) => setTimeout(resolve, 100));
    const settingsScreenshot = await withTimeout(
      window.webContents.capturePage(),
      "Electron Settings overlay capturePage",
    ).finally(() => window.hide());
    const settingsScreenshotBytes = settingsScreenshot.toPNG();
    assert(settingsScreenshotBytes.length > 100, "Settings screenshot capture failed");
    assert(
      !settingsScreenshotBytes.includes(Buffer.from(settingsSecretMarker, "utf8")),
      "Settings screenshot embedded the submitted secret marker",
    );
    fs.writeFileSync(path.join(outputDirectory, "settings-overlay.png"), settingsScreenshotBytes);

    await waitFor(
      client,
      "document.querySelector('[data-testid=\"settings-api-key-clear\"]')?.disabled === false",
    );
    await evaluate(
      client,
      `(() => {
        document.querySelector('[data-testid="settings-api-key-clear"]')?.click();
        return true;
      })()`,
    );
    await waitFor(client, "document.querySelector('[data-testid=\"settings-danger-overlay\"]') !== null");
    const settingsClearCancellationPlan = await evaluate<Record<string, unknown>>(
      client,
      `(() => {
        const dialog = document.querySelector('.settings-danger-dialog');
        const text = dialog?.textContent ?? '';
        return {
          modal: dialog?.getAttribute('aria-modal'),
          correctKind: text.includes('永久清除 API Key'),
          handleVisible: /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i.test(text),
          bodyHasSecret: document.body.textContent.includes(${JSON.stringify(settingsSecretMarker)}),
          cancelFocused: document.activeElement === document.querySelector('[data-testid="settings-mutation-cancel"]')
        };
      })()`,
    );
    assert(settingsClearCancellationPlan.modal === "true", "Settings clear plan is not modal");
    assert(settingsClearCancellationPlan.correctKind === true, "Settings clear plan kind drifted");
    assert(settingsClearCancellationPlan.handleVisible === false, "Settings clear plan exposed its opaque handle");
    assert(settingsClearCancellationPlan.bodyHasSecret === false, "Settings clear plan rendered the submitted secret");
    assert(settingsClearCancellationPlan.cancelFocused === true, "Settings clear plan did not focus cancel");
    await evaluate(
      client,
      `(() => {
        document.querySelector('[data-testid="settings-mutation-cancel"]')?.click();
        return true;
      })()`,
    );
    await waitFor(
      client,
      "document.querySelector('[data-testid=\"settings-danger-overlay\"]') === null",
    );
    const settingsClearCancellation = await evaluate<Record<string, unknown>>(
      client,
      `(async () => {
        const snapshot = await window.lovelyres.loadSettings();
        const provider = snapshot.ai.providers.find(entry => entry.id === 'debug-plain-text');
        return {
          providerPresent: provider !== undefined,
          providerHasApiKey: provider?.hasApiKey,
          bodyHasSecret: document.body.textContent.includes(${JSON.stringify(settingsSecretMarker)})
        };
      })()`,
    );
    assert(settingsClearCancellation.providerPresent === true, "cancelling Settings clear removed the provider");
    assert(settingsClearCancellation.providerHasApiKey === true, "cancelling Settings clear changed key state");
    assert(settingsClearCancellation.bodyHasSecret === false, "Settings clear cancellation rendered the secret");

    await waitFor(
      client,
      "document.querySelector('[data-testid=\"settings-api-key-clear\"]')?.disabled === false",
    );
    await evaluate(
      client,
      `(() => {
        document.querySelector('[data-testid="settings-api-key-clear"]')?.click();
        return true;
      })()`,
    );
    await waitFor(client, "document.querySelector('[data-testid=\"settings-danger-overlay\"]') !== null");
    const settingsClearConfirmationPlan = await evaluate<Record<string, unknown>>(
      client,
      `(() => {
        const text = document.querySelector('.settings-danger-dialog')?.textContent ?? '';
        return {
          correctKind: text.includes('永久清除 API Key'),
          handleVisible: /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i.test(text)
        };
      })()`,
    );
    assert(settingsClearConfirmationPlan.correctKind === true, "Settings clear confirmation kind drifted");
    assert(settingsClearConfirmationPlan.handleVisible === false, "Settings clear confirmation exposed its handle");
    await evaluate(
      client,
      `(() => {
        document.querySelector('[data-testid="settings-mutation-confirm"]')?.click();
        return true;
      })()`,
    );
    await waitFor(
      client,
      `document.querySelector('[data-testid="settings-danger-overlay"]') === null &&
        document.querySelector('.settings-credential-state')?.textContent.includes('未配置') === true`,
    );
    const settingsClearConfirmation = await evaluate<Record<string, unknown>>(
      client,
      `(async () => {
        const snapshot = await window.lovelyres.loadSettings();
        const provider = snapshot.ai.providers.find(entry => entry.id === 'debug-plain-text');
        return {
          providerPresent: provider !== undefined,
          providerHasApiKey: provider?.hasApiKey,
          snapshotHasSecret: JSON.stringify(snapshot).includes(${JSON.stringify(settingsSecretMarker)})
        };
      })()`,
    );
    assert(settingsClearConfirmation.providerPresent === true, "confirmed Settings clear removed the provider");
    assert(settingsClearConfirmation.providerHasApiKey === false, "confirmed Settings clear was not verified");
    assert(settingsClearConfirmation.snapshotHasSecret === false, "Settings clear snapshot returned the secret");

    await waitFor(
      client,
      "document.querySelector('[data-testid=\"settings-provider-remove\"]')?.disabled === false",
    );
    await evaluate(
      client,
      `(() => {
        document.querySelector('[data-testid="settings-provider-remove"]')?.click();
        return true;
      })()`,
    );
    await waitFor(client, "document.querySelector('[data-testid=\"settings-danger-overlay\"]') !== null");
    const settingsRemovalCancellationPlan = await evaluate<Record<string, unknown>>(
      client,
      `(() => {
        const text = document.querySelector('.settings-danger-dialog')?.textContent ?? '';
        return {
          correctKind: text.includes('永久删除 Provider'),
          handleVisible: /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i.test(text)
        };
      })()`,
    );
    assert(settingsRemovalCancellationPlan.correctKind === true, "Settings provider removal plan kind drifted");
    assert(settingsRemovalCancellationPlan.handleVisible === false, "Settings provider removal plan exposed its handle");
    await evaluate(
      client,
      `(() => {
        document.querySelector('[data-testid="settings-mutation-cancel"]')?.click();
        return true;
      })()`,
    );
    await waitFor(
      client,
      "document.querySelector('[data-testid=\"settings-danger-overlay\"]') === null",
    );
    const settingsRemovalCancellation = await evaluate<Record<string, unknown>>(
      client,
      `(async () => {
        const snapshot = await window.lovelyres.loadSettings();
        return {
          providerPresent: snapshot.ai.providers.some(entry => entry.id === 'debug-plain-text'),
          defaultProviderUnchanged: snapshot.ai.defaultProviderId === 'debug-plain-text'
        };
      })()`,
    );
    assert(settingsRemovalCancellation.providerPresent === true, "cancelling Settings removal deleted the provider");
    assert(settingsRemovalCancellation.defaultProviderUnchanged === true, "cancelling Settings removal changed the default provider");

    await waitFor(
      client,
      "document.querySelector('[data-testid=\"settings-provider-remove\"]')?.disabled === false",
    );
    await evaluate(
      client,
      `(() => {
        document.querySelector('[data-testid="settings-provider-remove"]')?.click();
        return true;
      })()`,
    );
    await waitFor(client, "document.querySelector('[data-testid=\"settings-danger-overlay\"]') !== null");
    const settingsRemovalConfirmationPlan = await evaluate<Record<string, unknown>>(
      client,
      `(() => {
        const text = document.querySelector('.settings-danger-dialog')?.textContent ?? '';
        return {
          correctKind: text.includes('永久删除 Provider'),
          handleVisible: /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i.test(text)
        };
      })()`,
    );
    assert(settingsRemovalConfirmationPlan.correctKind === true, "Settings removal confirmation kind drifted");
    assert(settingsRemovalConfirmationPlan.handleVisible === false, "Settings removal confirmation exposed its handle");
    await evaluate(
      client,
      `(() => {
        document.querySelector('[data-testid="settings-mutation-confirm"]')?.click();
        return true;
      })()`,
    );
    await waitFor(
      client,
      `document.querySelector('[data-testid="settings-danger-overlay"]') === null &&
        document.body.textContent.includes('</option><script>settings-plain-text()</script>') === false`,
    );
    const settingsRemovalConfirmation = await evaluate<Record<string, unknown>>(
      client,
      `(async () => {
        const snapshot = await window.lovelyres.loadSettings();
        return {
          providerPresent: snapshot.ai.providers.some(entry => entry.id === 'debug-plain-text'),
          defaultProviderRemoved: snapshot.ai.defaultProviderId !== 'debug-plain-text',
          bodyHasSecret: document.body.textContent.includes(${JSON.stringify(settingsSecretMarker)}),
          snapshotHasSecret: JSON.stringify(snapshot).includes(${JSON.stringify(settingsSecretMarker)})
        };
      })()`,
    );
    assert(settingsRemovalConfirmation.providerPresent === false, "confirmed Settings provider removal was not verified");
    assert(settingsRemovalConfirmation.defaultProviderRemoved === true, "removed Settings provider remained default");
    assert(settingsRemovalConfirmation.bodyHasSecret === false, "Settings provider removal rendered the secret");
    assert(settingsRemovalConfirmation.snapshotHasSecret === false, "Settings provider removal snapshot returned the secret");

    await evaluate(
      client,
      `(() => {
        document.dispatchEvent(new KeyboardEvent('keydown', {
          key: 'Escape', bubbles: true, cancelable: true
        }));
        return true;
      })()`,
    );
    await waitFor(
      client,
      "document.querySelector('.settings-panel') === null",
    );
    const settingsEscape = await evaluate<Record<string, unknown>>(
      client,
      `(() => ({
        closed: document.querySelector('.settings-panel') === null,
        focusRestored: document.activeElement === document.querySelector('[data-testid="open-settings"]'),
        sidebarInert: document.querySelector('.sidebar')?.inert,
        workspaceInert: document.querySelector('.workspace')?.inert
      }))()`,
    );
    assert(settingsEscape.closed === true, "Escape did not close clean Settings");
    assert(settingsEscape.focusRestored === true, "Settings did not restore focus to its trigger");
    assert(settingsEscape.sidebarInert === false, "sidebar remained inert after Settings closed");
    assert(settingsEscape.workspaceInert === false, "workspace remained inert after Settings closed");

    const commandHistoryBoundary = await evaluate<Record<string, unknown>>(
      client,
      `(async () => {
        const marker = 'forged-binding-must-not-echo';
        let forgedRejected = false;
        let forgedEchoed = false;
        try {
          await window.lovelyres.listCommandHistory(marker, '', 0, 25);
        } catch (error) {
          forgedRejected = true;
          forgedEchoed = String(error).includes(marker);
        }
        return {
          forgedRejected,
          forgedEchoed,
          executeMethod: typeof window.lovelyres.executeCommand,
          shellMethod: typeof window.lovelyres.shell,
          createMethod: typeof window.lovelyres.createCommandHistory,
          importMethod: typeof window.lovelyres.importCommandHistory
        };
      })()`,
    );
    assert(commandHistoryBoundary.forgedRejected === true, "command history accepted a forged binding");
    assert(commandHistoryBoundary.forgedEchoed === false, "command history echoed a forged binding");
    assert(commandHistoryBoundary.executeMethod === "undefined", "command history exposed execution");
    assert(commandHistoryBoundary.shellMethod === "undefined", "command history exposed a shell capability");
    assert(commandHistoryBoundary.createMethod === "undefined", "renderer can forge command history");
    assert(commandHistoryBoundary.importMethod === "undefined", "renderer can import command history");

    await evaluate(
      client,
      `(() => {
        document.querySelector('[data-testid="open-command-history"]')?.click();
        return true;
      })()`,
    );
    await waitFor(
      client,
      "document.querySelector('.command-history-panel') !== null && document.activeElement === document.querySelector('.command-history-panel')",
    );
    const commandHistoryEmpty = await evaluate<Record<string, unknown>>(
      client,
      `(() => {
        const panel = document.querySelector('.command-history-panel');
        const prompt = panel?.querySelector('.command-history-disconnected');
        const parseRgb = (value) => {
          const match = value.match(/^rgba?\\(\\s*([0-9.]+)[, ]+\\s*([0-9.]+)[, ]+\\s*([0-9.]+)/i);
          return match ? [Number(match[1]), Number(match[2]), Number(match[3])] : null;
        };
        const luminance = (rgb) => {
          if (rgb === null) return null;
          const channels = rgb.map(channel => {
            const value = channel / 255;
            return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
          });
          return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
        };
        const contrast = (foreground, background) => {
          const foregroundLuminance = luminance(parseRgb(foreground));
          const backgroundLuminance = luminance(parseRgb(background));
          if (foregroundLuminance === null || backgroundLuminance === null) return null;
          return (Math.max(foregroundLuminance, backgroundLuminance) + 0.05) /
            (Math.min(foregroundLuminance, backgroundLuminance) + 0.05);
        };
        const panelStyle = panel === null ? null : getComputedStyle(panel);
        const promptStyle = prompt === null || prompt === undefined ? null : getComputedStyle(prompt);
        const panelBackground = panelStyle?.backgroundColor ?? '';
        const panelColor = panelStyle?.color ?? '';
        const promptColor = promptStyle?.color ?? '';
        return {
          modal: panel?.getAttribute('aria-modal'),
          prompt: panel?.textContent ?? '',
          panelBackground,
          panelColor,
          promptColor,
          panelContrast: contrast(panelColor, panelBackground),
          promptContrast: contrast(promptColor, panelBackground),
          focused: document.activeElement === panel,
          rows: panel?.querySelectorAll('.command-history-row').length ?? -1,
          preformatted: panel?.querySelectorAll('pre').length ?? -1,
          scripts: panel?.querySelectorAll('script').length ?? -1,
          images: panel?.querySelectorAll('img').length ?? -1,
          inlineHandlers: panel?.querySelectorAll('[onclick],[onerror],[onload]').length ?? -1,
          passwordInputs: panel?.querySelectorAll('input[type="password"]').length ?? -1,
          alertDialogs: panel?.querySelectorAll('[role="alertdialog"]').length ?? -1,
          sidebarInert: document.querySelector('.sidebar')?.inert,
          workspaceInert: document.querySelector('.workspace')?.inert,
          sidebarHidden: document.querySelector('.sidebar')?.getAttribute('aria-hidden'),
          workspaceHidden: document.querySelector('.workspace')?.getAttribute('aria-hidden'),
          forgedVisible: document.body.textContent.includes('forged-binding-must-not-echo'),
          internalHandleVisible: panel?.textContent.includes('bindingHandle') || panel?.textContent.includes('TargetGuard')
        };
      })()`,
    );
    assert(commandHistoryEmpty.modal === "true", "command history overlay is not modal");
    assert(
      typeof commandHistoryEmpty.panelBackground === "string" &&
        commandHistoryEmpty.panelBackground !== "transparent" &&
        commandHistoryEmpty.panelBackground !== "rgba(0, 0, 0, 0)",
      "command history panel background is transparent",
    );
    assert(
      typeof commandHistoryEmpty.panelContrast === "number" && commandHistoryEmpty.panelContrast >= 4.5,
      "command history panel foreground/background contrast is below 4.5:1",
    );
    assert(
      typeof commandHistoryEmpty.promptContrast === "number" && commandHistoryEmpty.promptContrast >= 4.5,
      "command history disconnected prompt contrast is below 4.5:1",
    );
    assert(
      typeof commandHistoryEmpty.prompt === "string" &&
        commandHistoryEmpty.prompt.includes("请先在连接管理器中建立 SSH 连接"),
      "disconnected command history did not render the empty prompt",
    );
    assert(commandHistoryEmpty.focused === true, "disconnected command history did not take focus");
    assert(commandHistoryEmpty.rows === 0, "disconnected command history forged rows");
    assert(commandHistoryEmpty.preformatted === 0, "disconnected command history rendered command text");
    assert(commandHistoryEmpty.scripts === 0, "command history text created script content");
    assert(commandHistoryEmpty.images === 0, "command history text created image content");
    assert(commandHistoryEmpty.inlineHandlers === 0, "command history mounted inline handlers");
    assert(commandHistoryEmpty.passwordInputs === 0, "command history mounted a secret input");
    assert(commandHistoryEmpty.alertDialogs === 0, "command history opened an unplanned mutation dialog");
    assert(commandHistoryEmpty.sidebarInert === true, "command history did not make sidebar inert");
    assert(commandHistoryEmpty.workspaceInert === true, "command history did not make workspace inert");
    assert(commandHistoryEmpty.sidebarHidden === "true", "command history did not hide sidebar from AT");
    assert(commandHistoryEmpty.workspaceHidden === "true", "command history did not hide workspace from AT");
    assert(commandHistoryEmpty.forgedVisible === false, "forged command history input reached the UI");
    assert(commandHistoryEmpty.internalHandleVisible === false, "command history exposed an internal handle");

    window.showInactive();
    await new Promise((resolve) => setTimeout(resolve, 100));
    const commandHistoryScreenshot = await withTimeout(
      window.webContents.capturePage(),
      "Electron disconnected command history capturePage",
    ).finally(() => window.hide());
    const commandHistoryScreenshotBytes = commandHistoryScreenshot.toPNG();
    assert(commandHistoryScreenshotBytes.length > 100, "command history screenshot capture failed");
    fs.writeFileSync(
      path.join(outputDirectory, "command-history-disconnected.png"),
      commandHistoryScreenshotBytes,
    );

    await evaluate(
      client,
      `(() => {
        document.dispatchEvent(new KeyboardEvent('keydown', {
          key: 'Escape', bubbles: true, cancelable: true
        }));
        return true;
      })()`,
    );
    await waitFor(
      client,
      "document.querySelector('.command-history-panel') === null && document.activeElement === document.querySelector('[data-testid=\"open-command-history\"]')",
    );
    const commandHistoryEscape = await evaluate<Record<string, unknown>>(
      client,
      `(() => ({
        closed: document.querySelector('.command-history-panel') === null,
        focusRestored: document.activeElement === document.querySelector('[data-testid="open-command-history"]'),
        sidebarInert: document.querySelector('.sidebar')?.inert,
        workspaceInert: document.querySelector('.workspace')?.inert
      }))()`,
    );
    assert(commandHistoryEscape.closed === true, "Escape did not close command history");
    assert(commandHistoryEscape.focusRestored === true, "command history did not restore trigger focus");
    assert(commandHistoryEscape.sidebarInert === false, "sidebar remained inert after command history closed");
    assert(commandHistoryEscape.workspaceInert === false, "workspace remained inert after command history closed");

    const disposalReportBoundary = await evaluate<Record<string, unknown>>(
      client,
      `(async () => {
        const marker = 'forged-disposal-binding-must-not-echo';
        let forgedRejected = false;
        let forgedEchoed = false;
        try {
          await window.lovelyres.generateDisposalReport(marker);
        } catch (error) {
          forgedRejected = true;
          forgedEchoed = String(error).includes(marker);
        }
        return {
          forgedRejected,
          forgedEchoed,
          createMethod: typeof window.lovelyres.createDisposalReport,
          bodyMethod: typeof window.lovelyres.setDisposalReportBody,
          pathMethod: typeof window.lovelyres.saveDisposalReportToPath,
          detectionMethod: typeof window.lovelyres.submitDisposalDetection
        };
      })()`,
    );
    assert(disposalReportBoundary.forgedRejected === true, "disposal report accepted a forged binding");
    assert(disposalReportBoundary.forgedEchoed === false, "disposal report echoed a forged binding");
    assert(disposalReportBoundary.createMethod === "undefined", "renderer can create an arbitrary disposal report");
    assert(disposalReportBoundary.bodyMethod === "undefined", "renderer can submit a disposal report body");
    assert(disposalReportBoundary.pathMethod === "undefined", "renderer can submit an export path");
    assert(disposalReportBoundary.detectionMethod === "undefined", "renderer can submit a detection snapshot");

    await evaluate(
      client,
      `(() => {
        document.querySelector('[data-testid="open-disposal-report"]')?.click();
        return true;
      })()`,
    );
    await waitFor(
      client,
      "document.querySelector('.disposal-report-overlay') !== null && document.activeElement === document.querySelector('.disposal-report-heading button:last-child')",
    );
    const disposalReportEmpty = await evaluate<Record<string, unknown>>(
      client,
      `(() => {
        const panel = document.querySelector('.disposal-report-overlay');
        const prompt = panel?.querySelector('.disposal-report-empty');
        const closeButton = panel?.querySelector('.disposal-report-heading button:last-child');
        const parseRgb = (value) => {
          const match = value.match(/^rgba?\\(\\s*([0-9.]+)[, ]+\\s*([0-9.]+)[, ]+\\s*([0-9.]+)/i);
          return match ? [Number(match[1]), Number(match[2]), Number(match[3])] : null;
        };
        const luminance = (rgb) => {
          if (rgb === null) return null;
          const channels = rgb.map(channel => {
            const value = channel / 255;
            return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
          });
          return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
        };
        const contrast = (foreground, background) => {
          const foregroundLuminance = luminance(parseRgb(foreground));
          const backgroundLuminance = luminance(parseRgb(background));
          if (foregroundLuminance === null || backgroundLuminance === null) return null;
          return (Math.max(foregroundLuminance, backgroundLuminance) + 0.05) /
            (Math.min(foregroundLuminance, backgroundLuminance) + 0.05);
        };
        const panelStyle = panel === null ? null : getComputedStyle(panel);
        const promptStyle = prompt === null || prompt === undefined ? null : getComputedStyle(prompt);
        const panelBackground = panelStyle?.backgroundColor ?? '';
        const panelColor = panelStyle?.color ?? '';
        const promptColor = promptStyle?.color ?? '';
        return {
          modal: panel?.getAttribute('aria-modal'),
          prompt: prompt?.textContent ?? '',
          panelBackground,
          panelColor,
          promptColor,
          panelContrast: contrast(panelColor, panelBackground),
          promptContrast: contrast(promptColor, panelBackground),
          focusedClose: document.activeElement === closeButton,
          summaryCards: panel?.querySelectorAll('.disposal-report-summary-grid article').length ?? -1,
          preformatted: panel?.querySelectorAll('pre').length ?? -1,
          scripts: panel?.querySelectorAll('script').length ?? -1,
          images: panel?.querySelectorAll('img').length ?? -1,
          inlineHandlers: panel?.querySelectorAll('[onclick],[onerror],[onload]').length ?? -1,
          inputs: panel?.querySelectorAll('input,textarea,select').length ?? -1,
          alertDialogs: panel?.querySelectorAll('[role="alertdialog"]').length ?? -1,
          enabledButtons: panel?.querySelectorAll('button:not([disabled])').length ?? -1,
          sidebarInert: document.querySelector('.sidebar')?.inert,
          workspaceInert: document.querySelector('.workspace')?.inert,
          sidebarHidden: document.querySelector('.sidebar')?.getAttribute('aria-hidden'),
          workspaceHidden: document.querySelector('.workspace')?.getAttribute('aria-hidden'),
          forgedVisible: document.body.textContent.includes('forged-disposal-binding-must-not-echo'),
          internalHandleVisible: panel?.textContent.includes('bindingHandle') || panel?.textContent.includes('TargetGuard')
        };
      })()`,
    );
    assert(disposalReportEmpty.modal === "true", "disposal report overlay is not modal");
    assert(
      typeof disposalReportEmpty.panelBackground === "string" &&
        disposalReportEmpty.panelBackground !== "transparent" &&
        disposalReportEmpty.panelBackground !== "rgba(0, 0, 0, 0)",
      "disposal report panel background is transparent",
    );
    assert(
      typeof disposalReportEmpty.panelContrast === "number" && disposalReportEmpty.panelContrast >= 4.5,
      "disposal report panel foreground/background contrast is below 4.5:1",
    );
    assert(
      typeof disposalReportEmpty.promptContrast === "number" && disposalReportEmpty.promptContrast >= 4.5,
      "disposal report disconnected prompt contrast is below 4.5:1",
    );
    assert(
      typeof disposalReportEmpty.prompt === "string" && disposalReportEmpty.prompt.includes("请先建立 SSH 连接"),
      "disconnected disposal report did not render the empty prompt",
    );
    assert(disposalReportEmpty.focusedClose === true, "disconnected disposal report did not focus its close action");
    assert(disposalReportEmpty.summaryCards === 0, "disconnected disposal report forged summary data");
    assert(disposalReportEmpty.preformatted === 0, "disconnected disposal report rendered report content");
    assert(disposalReportEmpty.scripts === 0, "disposal report text created script content");
    assert(disposalReportEmpty.images === 0, "disposal report text created image content");
    assert(disposalReportEmpty.inlineHandlers === 0, "disposal report mounted inline handlers");
    assert(disposalReportEmpty.inputs === 0, "disposal report exposed renderer-controlled report ingredients");
    assert(disposalReportEmpty.alertDialogs === 0, "disposal report opened an unplanned dangerous dialog");
    assert(disposalReportEmpty.enabledButtons === 1, "disconnected disposal report enabled a report action");
    assert(disposalReportEmpty.sidebarInert === true, "disposal report did not make sidebar inert");
    assert(disposalReportEmpty.workspaceInert === true, "disposal report did not make workspace inert");
    assert(disposalReportEmpty.sidebarHidden === "true", "disposal report did not hide sidebar from AT");
    assert(disposalReportEmpty.workspaceHidden === "true", "disposal report did not hide workspace from AT");
    assert(disposalReportEmpty.forgedVisible === false, "forged disposal report input reached the UI");
    assert(disposalReportEmpty.internalHandleVisible === false, "disposal report exposed an internal handle");

    window.showInactive();
    await new Promise((resolve) => setTimeout(resolve, 100));
    const disposalReportScreenshot = await withTimeout(
      window.webContents.capturePage(),
      "Electron disconnected disposal report capturePage",
    ).finally(() => window.hide());
    const disposalReportScreenshotBytes = disposalReportScreenshot.toPNG();
    assert(disposalReportScreenshotBytes.length > 100, "disposal report screenshot capture failed");
    fs.writeFileSync(
      path.join(outputDirectory, "disposal-report-disconnected.png"),
      disposalReportScreenshotBytes,
    );

    await evaluate(
      client,
      `(() => {
        document.dispatchEvent(new KeyboardEvent('keydown', {
          key: 'Escape', bubbles: true, cancelable: true
        }));
        return true;
      })()`,
    );
    await waitFor(
      client,
      "document.querySelector('.disposal-report-overlay') === null && document.activeElement === document.querySelector('[data-testid=\"open-disposal-report\"]')",
    );
    const disposalReportEscape = await evaluate<Record<string, unknown>>(
      client,
      `(() => ({
        closed: document.querySelector('.disposal-report-overlay') === null,
        focusRestored: document.activeElement === document.querySelector('[data-testid="open-disposal-report"]'),
        sidebarInert: document.querySelector('.sidebar')?.inert,
        workspaceInert: document.querySelector('.workspace')?.inert
      }))()`,
    );
    assert(disposalReportEscape.closed === true, "Escape did not close disposal report");
    assert(disposalReportEscape.focusRestored === true, "disposal report did not restore trigger focus");
    assert(disposalReportEscape.sidebarInert === false, "sidebar remained inert after disposal report closed");
    assert(disposalReportEscape.workspaceInert === false, "workspace remained inert after disposal report closed");

    const aiHistoryBoundary = await evaluate<Record<string, unknown>>(
      client,
      `(async () => {
        const page = await window.lovelyres.listAiHistory('', 0, 100);
        const marker = 'renderer-forged-ai-record-marker';
        let forgedRejected = false;
        let forgedEchoed = false;
        try {
          await window.lovelyres.getAiHistoryRecord(marker);
        } catch (error) {
          forgedRejected = true;
          forgedEchoed = String(error).includes(marker);
        }
        return {
          total: page.total,
          items: page.items.length,
          forgedRejected,
          forgedEchoed,
          createMethod: typeof window.lovelyres.createAiHistory,
          importMethod: typeof window.lovelyres.importAiHistory
        };
      })()`,
    );
    assert(aiHistoryBoundary.total === 0, "AI history portable store was not empty in smoke mode");
    assert(aiHistoryBoundary.items === 0, "AI history returned a forged smoke record");
    assert(aiHistoryBoundary.forgedRejected === true, "AI history accepted a forged record identifier");
    assert(aiHistoryBoundary.forgedEchoed === false, "AI history error echoed a forged identifier");
    assert(aiHistoryBoundary.createMethod === "undefined", "renderer can forge an AI history record");
    assert(aiHistoryBoundary.importMethod === "undefined", "renderer can import an AI history record");

    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('button')]
          .find(candidate => candidate.textContent.includes('AI 历史'));
        if (!button) return false;
        button.click();
        return true;
      })()`,
    );
    await waitFor(
      client,
      "document.querySelector('.ai-history-page .ai-history-empty')?.textContent.includes('暂无 AI 历史记录') === true",
    );
    const aiHistoryEmpty = await evaluate<Record<string, unknown>>(
      client,
      `(() => {
        const page = document.querySelector('.ai-history-page');
        return {
          emptyText: page?.querySelector('.ai-history-empty')?.textContent ?? '',
          rows: page?.querySelectorAll('.ai-history-row').length ?? -1,
          dialogs: page?.querySelectorAll('[role="dialog"]').length ?? -1,
          scripts: page?.querySelectorAll('script').length ?? -1,
          images: page?.querySelectorAll('img').length ?? -1,
          inlineHandlers: page?.querySelectorAll('[onclick],[onerror],[onload]').length ?? -1,
          passwordInputs: page?.querySelectorAll('input[type="password"]').length ?? -1,
          bodyHasForgedMarker: document.body.textContent.includes('renderer-forged-ai-record-marker')
        };
      })()`,
    );
    assert(aiHistoryEmpty.rows === 0, "AI history empty page rendered a record");
    assert(aiHistoryEmpty.dialogs === 0, "AI history empty page opened a mutation dialog");
    assert(aiHistoryEmpty.scripts === 0, "AI history empty page created a script element");
    assert(aiHistoryEmpty.images === 0, "AI history empty page created an image element");
    assert(aiHistoryEmpty.inlineHandlers === 0, "AI history empty page created an inline handler");
    assert(aiHistoryEmpty.passwordInputs === 0, "AI history empty page mounted a secret input");
    assert(aiHistoryEmpty.bodyHasForgedMarker === false, "AI history rendered a forged identifier");

    window.showInactive();
    await new Promise((resolve) => setTimeout(resolve, 100));
    const aiHistoryScreenshot = await withTimeout(
      window.webContents.capturePage(),
      "Electron AI history empty-state capturePage",
    ).finally(() => window.hide());
    const aiHistoryScreenshotBytes = aiHistoryScreenshot.toPNG();
    assert(aiHistoryScreenshotBytes.length > 100, "AI history empty-state screenshot failed");
    fs.writeFileSync(
      path.join(outputDirectory, "ai-history-empty.png"),
      aiHistoryScreenshotBytes,
    );

    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('button')]
          .find(candidate => candidate.textContent.includes('安全速查'));
        if (!button) return false;
        button.click();
        return true;
      })()`,
    );
    await waitFor(client, "document.querySelector('.security-reference') !== null");
    const catalog = await evaluate<Record<string, unknown>>(
      client,
      `(() => ({
        resultCount: document.querySelector('.result-count strong')?.textContent,
        cards: document.querySelectorAll('.snippet-card').length,
        languages: document.querySelectorAll('.language-pill').length,
        scriptElements: document.querySelectorAll('script').length,
        htmlNamedText: [...document.querySelectorAll('.snippet-card')]
          .some(card => card.textContent.includes('innerHTML'))
      }))()`,
    );
    assert(catalog.resultCount === "107", "security-reference result count is not 107");
    assert(catalog.cards === 107, "security-reference catalog did not render 107 cards");
    assert(catalog.languages === 13, "security-reference language registry is incomplete");
    assert(catalog.scriptElements === 1, "catalog text created executable script elements");
    assert(catalog.htmlNamedText === true, "hostile-markup regression fixture is missing");

    await evaluate(
      client,
      `(() => {
        const input = document.querySelector('.search-field input');
        if (!input) return false;
        const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
        setter.call(input, '参数化查询');
        input.dispatchEvent(new Event('input', { bubbles: true }));
        return true;
      })()`,
    );
    await waitFor(
      client,
      "Number(document.querySelector('.result-count strong')?.textContent ?? '0') > 0 && Number(document.querySelector('.result-count strong')?.textContent ?? '0') < 107",
    );
    const search = await evaluate<Record<string, unknown>>(
      client,
      `(() => ({
        query: document.querySelector('.search-field input')?.value,
        resultCount: Number(document.querySelector('.result-count strong')?.textContent ?? '0'),
        containsSqlFix: [...document.querySelectorAll('.snippet-card')]
          .some(card => card.textContent.includes('SQL注入 -- 参数化查询'))
      }))()`,
    );
    assert(search.query === "参数化查询", "security-reference search input did not update");
    assert(search.containsSqlFix === true, "security-reference search missed the SQL fix fixture");

    const accessibility = (await sendCommand(client, "Accessibility.getFullAXTree")) as {
      nodes?: Array<{ ignored?: boolean; role?: { value?: string }; name?: { value?: string } }>;
    };
    const accessibilityNodes = accessibility.nodes ?? [];
    assert(
      accessibilityNodes.some(
        (node) => node.role?.value === "textbox" && String(node.name?.value ?? "").includes("搜索"),
      ),
      "security-reference search is missing from the accessibility tree",
    );

    window.showInactive();
    await new Promise((resolve) => setTimeout(resolve, 100));
    const screenshot = await withTimeout(
      window.webContents.capturePage(),
      "Electron webContents.capturePage",
    ).finally(() => window.hide());
    const screenshotBytes = screenshot.toPNG();
    assert(screenshotBytes.length > 100, "screenshot capture failed");

    fs.mkdirSync(outputDirectory, { recursive: true });
    fs.writeFileSync(
      path.join(outputDirectory, "security-reference.png"),
      screenshotBytes,
    );

    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.nav-item')]
          .find(candidate => candidate.querySelector('strong')?.textContent === '配置');
        if (!button) return false;
        button.click();
        return true;
      })()`,
    );
    // Generating is the second half of the same page, so it is reached by the
    // mode switch rather than by its own navigation entry.
    await waitFor(client, "document.querySelector('.configuration-modes') !== null");
    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.configuration-modes button')]
          .find(candidate => candidate.querySelector('strong')?.textContent === '生成新配置');
        button?.click();
        return button instanceof HTMLButtonElement;
      })()`,
    );
    await waitFor(
      client,
      "document.querySelector('.config-generator-page') !== null && [...document.querySelectorAll('.config-catalog-count strong')].map(node => node.textContent).join(',') === '9,137'",
    );
    const catalogIntegrity = await evaluate<Record<string, unknown>>(
      client,
      `(async () => {
        const catalog = await window.lovelyres.getConfigCatalog();
        return {
          products: catalog.products.length,
          features: catalog.products.reduce((total, product) => total + product.features.length, 0)
        };
      })()`,
    );
    assert(catalogIntegrity.products === 9, "configuration catalog did not expose 9 products");
    assert(catalogIntegrity.features === 137, "configuration catalog did not expose 137 features");

    await evaluate(
      client,
      `(() => {
        document.querySelector('[data-testid="config-product-postgresql"]')?.click();
        return true;
      })()`,
    );
    await waitFor(client, "document.querySelector('[data-testid=\"config-version-postgresql-14\"]') !== null");
    await evaluate(
      client,
      `(() => {
        document.querySelector('[data-testid="config-version-postgresql-14"]')?.click();
        return true;
      })()`,
    );
    await waitFor(client, "document.querySelector('[data-testid=\"config-version-postgresql-14\"]')?.checked === true");
    await evaluate(
      client,
      `(() => {
        document.querySelector('[data-testid="config-product-mongodb"]')?.click();
        const input = document.querySelector('.config-search input');
        if (!input) return false;
        const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
        setter.call(input, 'PostgreSQL');
        input.dispatchEvent(new Event('input', { bubbles: true }));
        return true;
      })()`,
    );
    await waitFor(
      client,
      "[...document.querySelectorAll('.config-search-results button')].some(button => button.querySelector('span')?.textContent === 'PostgreSQL')",
    );
    await evaluate(
      client,
      `(() => {
        const result = [...document.querySelectorAll('.config-search-results button')]
          .find(button => button.querySelector('span')?.textContent === 'PostgreSQL');
        if (!result) return false;
        result.click();
        return true;
      })()`,
    );
    await waitFor(
      client,
      "document.querySelector('[data-testid=\"config-product-postgresql\"]')?.getAttribute('aria-pressed') === 'true' && document.querySelectorAll('.config-feature-list label.selected').length === 1",
    );
    const atomicSearchSelection = await evaluate<Record<string, unknown>>(
      client,
      `(() => ({
        activeProduct: document.querySelector('.config-product-list button[aria-pressed="true"]')?.getAttribute('data-testid'),
        selectedSubjects: [...document.querySelectorAll('.config-feature-list label.selected')]
          .map(node => node.getAttribute('data-config-subject')),
        v14Checked: document.querySelector('[data-testid="config-version-postgresql-14"]')?.checked
      }))()`,
    );
    assert(
      atomicSearchSelection.activeProduct === "config-product-postgresql",
      "configuration search did not atomically switch the active product",
    );
    assert(
      Array.isArray(atomicSearchSelection.selectedSubjects) &&
        atomicSearchSelection.selectedSubjects.length === 1 &&
        String(atomicSearchSelection.selectedSubjects[0]).startsWith("postgresql:"),
      "configuration search left a stale or non-unique selected subject",
    );
    assert(
      atomicSearchSelection.v14Checked === true,
      "PostgreSQL V14 stable test id did not preserve the selected version",
    );

    await evaluate(
      client,
      `(() => {
        document.querySelector('[data-testid="config-generate"]')?.click();
        return true;
      })()`,
    );
    await waitFor(
      client,
      "document.querySelector('.config-artifact-panel pre')?.textContent.length > 0 && document.body.textContent.includes('已生成')",
    );
    const generatedPreview = await evaluate<Record<string, unknown>>(
      client,
      `(() => {
        const preview = document.querySelector('.config-artifact-panel pre');
        return {
          textLength: preview?.textContent.length ?? 0,
          previewElements: preview?.childElementCount ?? -1,
          scripts: document.querySelectorAll('script').length,
          images: document.querySelectorAll('.config-generator-page img').length,
          inlineHandlers: document.querySelectorAll('.config-generator-page [onclick],[onerror],[onload]').length
        };
      })()`,
    );
    assert((generatedPreview.textLength as number) > 0, "default configuration generation was empty");
    assert(generatedPreview.previewElements === 0, "configuration preview was interpreted as markup");
    assert(generatedPreview.scripts === 1, "configuration generation created a script element");
    assert(generatedPreview.images === 0, "configuration generation created an image element");
    assert(generatedPreview.inlineHandlers === 0, "configuration generation created an inline handler");
    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.config-preview footer button')]
          .find(candidate => candidate.textContent.includes('复制全部'));
        if (!button) return false;
        button.click();
        return true;
      })()`,
    );
    await waitFor(client, "document.body.textContent.includes('已复制')");
    const copyStatus = await evaluate<string>(
      client,
      "document.querySelector('.config-notice')?.textContent ?? ''",
    );
    assert(copyStatus.includes("个文件"), "configuration copy did not report its bounded result");

    window.showInactive();
    await new Promise((resolve) => setTimeout(resolve, 100));
    const configScreenshot = await withTimeout(
      window.webContents.capturePage(),
      "Electron configuration generator capturePage",
    ).finally(() => window.hide());
    fs.writeFileSync(
      path.join(outputDirectory, "config-generator.png"),
      configScreenshot.toPNG(),
    );

    await evaluate(
      client,
      `(() => {
        document.querySelector('[aria-label="关闭配置草稿"]')?.click();
        return true;
      })()`,
    );
    await waitFor(
      client,
      "document.querySelector('.config-preview-empty') !== null && document.querySelector('.config-artifact-panel') === null",
    );
    const configGenerator = {
      catalogIntegrity,
      atomicSearchSelection,
      generatedPreview,
      copyStatus,
      previewCleared: true,
    };

    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('button')]
          .find(candidate => candidate.querySelector('strong')?.textContent === 'Notes');
        if (!button) return false;
        button.click();
        return true;
      })()`,
    );
    await waitFor(client, "document.querySelector('.notes-page') !== null");
    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.notes-heading-actions button')]
          .find(candidate => candidate.textContent.includes('新建笔记'));
        if (!button) return false;
        button.click();
        return true;
      })()`,
    );
    await waitFor(client, "document.querySelector('.note-title-input') !== null");
    await evaluate(
      client,
      `(() => {
        const title = document.querySelector('.note-title-input');
        const content = document.querySelector('.notes-editor-fields textarea');
        if (!title || !content) return false;
        const inputSetter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
        const textAreaSetter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set;
        inputSetter.call(title, '<img src=x onerror=steal()> 调查');
        title.dispatchEvent(new Event('input', { bubbles: true }));
        textAreaSetter.call(content, 'Electron migration note: remote text stays plain.');
        content.dispatchEvent(new Event('input', { bubbles: true }));
        return true;
      })()`,
    );
    await waitFor(client, "[...document.querySelectorAll('.notes-editor-toolbar button')].some(button => button.textContent.includes('保存') && !button.disabled)");
    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.notes-editor-toolbar button')]
          .find(candidate => candidate.textContent.includes('保存'));
        if (!button) return false;
        button.click();
        return true;
      })()`,
    );
    await waitFor(client, "document.body.textContent.includes('笔记已保存')");
    await evaluate(
      client,
      `(() => {
        const input = document.querySelector('.notes-tags input');
        if (!input) return false;
        const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
        setter.call(input, '取证');
        input.dispatchEvent(new Event('input', { bubbles: true }));
        input.form.requestSubmit();
        return true;
      })()`,
    );
    await waitFor(client, "document.body.textContent.includes('标签已添加')");
    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.notes-editor-toolbar button')]
          .find(candidate => candidate.textContent.trim() === '置顶');
        if (!button) return false;
        button.click();
        return true;
      })()`,
    );
    await waitFor(client, "document.body.textContent.includes('笔记已置顶')");
    await evaluate(
      client,
      `(() => {
        const input = document.querySelector('.notes-search input');
        if (!input) return false;
        const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
        setter.call(input, '#取证');
        input.dispatchEvent(new Event('input', { bubbles: true }));
        return true;
      })()`,
    );
    await waitFor(client, "document.querySelectorAll('.note-row').length === 1");
    const notes = await evaluate<Record<string, unknown>>(
      client,
      `(async () => {
        const page = await window.lovelyres.listNotes('#取证', 0, 100);
        const exported = await window.lovelyres.exportNotes(page.items[0]?.id ?? null);
        return {
          total: page.total,
          title: page.items[0]?.title,
          pinned: page.items[0]?.pinned,
          tags: page.items[0]?.tags,
          exportContainsContent: exported.text.includes('Electron migration note'),
          injectedImages: document.querySelectorAll('.notes-page img').length,
          injectedHandlers: document.querySelectorAll('.notes-page [onerror]').length,
          dialogCount: document.querySelectorAll('[role="dialog"]').length
        };
      })()`,
    );
    assert(notes.total === 1, "notes tag search did not return the created note");
    assert(notes.title === "<img src=x onerror=steal()> 调查", "notes title was not preserved as text");
    assert(notes.pinned === true, "notes pin mutation did not persist");
    assert(Array.isArray(notes.tags) && notes.tags.includes("取证"), "notes tag mutation did not persist");
    assert(notes.exportContainsContent === true, "notes text export missed the saved content");
    assert(notes.injectedImages === 0, "hostile notes text created an image element");
    assert(notes.injectedHandlers === 0, "hostile notes text created an event handler");
    assert(notes.dialogCount === 0, "notes page opened an unexpected dialog");

    window.showInactive();
    await new Promise((resolve) => setTimeout(resolve, 100));
    const notesScreenshot = await withTimeout(
      window.webContents.capturePage(),
      "Electron notes capturePage",
    ).finally(() => window.hide());
    const notesScreenshotBytes = notesScreenshot.toPNG();
    assert(notesScreenshotBytes.length > 100, "notes screenshot capture failed");
    fs.writeFileSync(path.join(outputDirectory, "notes.png"), notesScreenshotBytes);

    const noteDeleteCancellation = await evaluate<Record<string, unknown>>(
      client,
      `(async () => {
        const page = await window.lovelyres.listNotes('', 0, 100);
        const noteId = page.items[0]?.id;
        if (!noteId) throw new Error('missing note for delete cancellation probe');
        const note = await window.lovelyres.getNote(noteId);
        const proposal = await window.lovelyres.planNoteDelete(
          noteId,
          note.revision,
          crypto.randomUUID()
        );
        const cancellation = await window.lovelyres.cancelNoteDelete(
          proposal.handle,
          crypto.randomUUID()
        );
        let consumedHandleRejected = false;
        try {
          await window.lovelyres.confirmNoteDelete(proposal.handle, crypto.randomUUID());
        } catch {
          consumedHandleRejected = true;
        }
        return {
          cancelled: cancellation.cancelled,
          consumedHandleRejected,
          remaining: (await window.lovelyres.listNotes('', 0, 100)).total
        };
      })()`,
    );
    assert(noteDeleteCancellation.cancelled === true, "notes delete cancellation was not acknowledged");
    assert(
      noteDeleteCancellation.consumedHandleRejected === true,
      "cancelled notes delete handle remained usable",
    );
    assert(noteDeleteCancellation.remaining === 1, "notes delete cancellation mutated the record");

    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.notes-editor-toolbar button')]
          .find(candidate => candidate.textContent.trim() === '删除');
        if (!button) return false;
        button.click();
        return true;
      })()`,
    );
    await waitFor(client, "document.querySelector('.danger-dialog') !== null");
    const deleteDialog = await evaluate<Record<string, unknown>>(
      client,
      `(() => ({
        modal: document.querySelector('.danger-dialog')?.getAttribute('aria-modal'),
        summary: document.querySelector('.danger-dialog')?.textContent,
        scriptElements: document.querySelectorAll('script').length
      }))()`,
    );
    assert(deleteDialog.modal === "true", "notes delete confirmation is not modal");
    assert(
      typeof deleteDialog.summary === "string" && deleteDialog.summary.includes("不可恢复"),
      "notes delete confirmation omitted the immutable plan summary",
    );
    assert(deleteDialog.scriptElements === 1, "notes delete text created executable markup");
    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.danger-dialog button')]
          .find(candidate => candidate.textContent.includes('确认永久删除'));
        if (!button) return false;
        button.click();
        return true;
      })()`,
    );
    await waitFor(client, "document.body.textContent.includes('完成审计与结果验证')");
    const afterDelete = await evaluate<Record<string, unknown>>(
      client,
      `(async () => {
        const page = await window.lovelyres.listNotes('', 0, 100);
        return { total: page.total, dialogs: document.querySelectorAll('[role="dialog"]').length };
      })()`,
    );
    assert(afterDelete.total === 0, "verified notes deletion did not remove the record");
    assert(afterDelete.dialogs === 0, "notes delete dialog remained after completion");

    await evaluate(
      client,
      `(() => {
        const button = document.querySelector('[data-testid="open-connections"]');
        if (!button) return false;
        button.click();
        return true;
      })()`,
    );
    await waitFor(client, "document.querySelector('.connection-manager') !== null");
    await waitFor(
      client,
      "[...document.querySelectorAll('.connection-manager-header button')].some(button => button.textContent.includes('新建连接') && !button.disabled)",
    );
    const connectionFileControls = await evaluate<Record<string, unknown>>(
      client,
      `(() => ({
        importVisible: document.querySelector('[data-testid="connection-import"]')?.textContent.includes('导入 JSON'),
        exportVisible: document.querySelector('[data-testid="connection-export"]')?.textContent.includes('导出 JSON'),
        importDisabled: document.querySelector('[data-testid="connection-import"]')?.disabled,
        exportDisabled: document.querySelector('[data-testid="connection-export"]')?.disabled,
        importArity: window.lovelyres.importConnections.length,
        exportArity: window.lovelyres.exportConnections.length
      }))()`,
    );
    assert(connectionFileControls.importVisible === true, "connection import control is missing");
    assert(connectionFileControls.exportVisible === true, "connection export control is missing");
    assert(connectionFileControls.importDisabled === false, "connection import control is unavailable");
    assert(connectionFileControls.exportDisabled === false, "connection export control is unavailable");
    assert(connectionFileControls.importArity === 0, "connection import API accepts renderer arguments");
    assert(connectionFileControls.exportArity === 0, "connection export API accepts renderer arguments");
    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.connection-manager-header button')]
          .find(candidate => candidate.textContent.includes('新建连接'));
        if (!button) return false;
        button.click();
        return true;
      })()`,
    );
    await waitFor(client, "document.querySelector('.connection-editor') !== null");
    await evaluate(
      client,
      `(() => {
        const setField = (label, value) => {
          const labelNode = [...document.querySelectorAll('.connection-field > span')]
            .find(candidate => candidate.textContent.includes(label));
          const control = labelNode?.parentElement?.querySelector('input, textarea');
          if (!control) throw new Error('missing connection field: ' + label);
          const prototype = control instanceof HTMLTextAreaElement
            ? HTMLTextAreaElement.prototype
            : HTMLInputElement.prototype;
          const setter = Object.getOwnPropertyDescriptor(prototype, 'value').set;
          setter.call(control, value);
          control.dispatchEvent(new Event('input', { bubbles: true }));
        };
        setField('连接名称', '<img src=x onerror=steal()> Production');
        setField('主机名或 IP', '127.0.0.1');
        setField('SSH 密码', 'debug-secret-do-not-return');
        setField('标签（中英文逗号分隔', 'critical, 取证');
        setField('备注', '<script>remote-note()</script> stays plain');
        return true;
      })()`,
    );
    await evaluate(
      client,
      `(() => {
        const button = document.querySelector('.connection-editor footer button[type="submit"]');
        if (!button) return false;
        button.click();
        return true;
      })()`,
    );
    await waitFor(client, "document.querySelector('.connection-details-view') !== null && document.body.textContent.includes('连接已写入')");
    const connectionCreate = await evaluate<Record<string, unknown>>(
      client,
      `(async () => {
        const list = await window.lovelyres.listConnections();
        const edit = await window.lovelyres.getConnection(list[0]?.id ?? 'missing');
        const encoded = JSON.stringify({ list, edit });
        return {
          count: list.length,
          id: edit.id,
          name: edit.name,
          tags: edit.tags,
          notes: edit.notes,
          hasPassword: edit.hasPassword,
          secretReturned: encoded.includes('debug-secret-do-not-return'),
          encryptedValueReturned: encoded.includes('enc:v1:'),
          passwordKeyReturned: Object.prototype.hasOwnProperty.call(edit, 'password'),
          injectedImages: document.querySelectorAll('.connection-manager img').length,
          scriptElements: document.querySelectorAll('script').length,
          passwordInputsAfterSave: document.querySelectorAll('.connection-manager input[type="password"]').length
        };
      })()`,
    );
    assert(connectionCreate.count === 1, "connection create did not persist exactly one record");
    assert(
      connectionCreate.name === "<img src=x onerror=steal()> Production",
      "hostile connection name was not preserved as text",
    );
    assert(
      Array.isArray(connectionCreate.tags) && connectionCreate.tags.includes("取证"),
      "connection tags did not persist",
    );
    assert(
      connectionCreate.notes === "<script>remote-note()</script> stays plain",
      "connection notes did not persist as plain text",
    );
    assert(connectionCreate.hasPassword === true, "connection credential presence was not reported");
    assert(connectionCreate.secretReturned === false, "connection secret crossed the read boundary");
    assert(connectionCreate.encryptedValueReturned === false, "encrypted credential crossed the read boundary");
    assert(connectionCreate.passwordKeyReturned === false, "connection edit DTO contains a password field");
    assert(connectionCreate.injectedImages === 0, "connection name created an image element");
    assert(connectionCreate.scriptElements === 1, "connection text created executable markup");
    assert(connectionCreate.passwordInputsAfterSave === 0, "secret input remained mounted after save");

    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.connection-details-view footer button')]
          .find(candidate => candidate.textContent.includes('编辑配置'));
        if (!button) return false;
        button.click();
        return true;
      })()`,
    );
    await waitFor(client, "document.querySelector('.connection-editor') !== null");
    await evaluate(
      client,
      `(() => {
        const labelNode = [...document.querySelectorAll('.connection-field > span')]
          .find(candidate => candidate.textContent === '连接名称');
        const input = labelNode?.parentElement?.querySelector('input');
        if (!input) return false;
        const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
        setter.call(input, 'Electron target updated');
        input.dispatchEvent(new Event('input', { bubbles: true }));
        document.querySelector('.connection-editor footer button[type="submit"]')?.click();
        return true;
      })()`,
    );
    await waitFor(client, "document.querySelector('.connection-details-view h2')?.textContent === 'Electron target updated'");
    const connectionUpdate = await evaluate<Record<string, unknown>>(
      client,
      `(async () => {
        const list = await window.lovelyres.listConnections();
        const edit = await window.lovelyres.getConnection(list[0]?.id ?? 'missing');
        return { count: list.length, name: edit.name, hasPassword: edit.hasPassword };
      })()`,
    );
    assert(connectionUpdate.count === 1, "connection update changed record cardinality");
    assert(connectionUpdate.name === "Electron target updated", "connection update did not persist");
    assert(connectionUpdate.hasPassword === true, "keep-secret update removed the stored password");

    window.showInactive();
    await new Promise((resolve) => setTimeout(resolve, 100));
    const connectionScreenshot = await withTimeout(
      window.webContents.capturePage(),
      "Electron connection manager capturePage",
    ).finally(() => window.hide());
    const connectionScreenshotBytes = connectionScreenshot.toPNG();
    assert(connectionScreenshotBytes.length > 100, "connection manager screenshot capture failed");
    fs.writeFileSync(
      path.join(outputDirectory, "connection-manager.png"),
      connectionScreenshotBytes,
    );

    const connectionDeleteCancellation = await evaluate<Record<string, unknown>>(
      client,
      `(async () => {
        const list = await window.lovelyres.listConnections();
        const connectionId = list[0]?.id;
        if (!connectionId) throw new Error('missing connection for delete cancellation probe');
        const prompt = await window.lovelyres.planConnectionDelete(connectionId);
        const cancellation = await window.lovelyres.cancelConnectionDelete(prompt.handle);
        let consumedHandleRejected = false;
        try {
          await window.lovelyres.confirmConnectionDelete(prompt.handle);
        } catch {
          consumedHandleRejected = true;
        }
        return {
          cancelled: cancellation.cancelled,
          consumedHandleRejected,
          remaining: (await window.lovelyres.listConnections()).length
        };
      })()`,
    );
    assert(
      connectionDeleteCancellation.cancelled === true,
      "connection delete cancellation was not acknowledged",
    );
    assert(
      connectionDeleteCancellation.consumedHandleRejected === true,
      "cancelled connection delete handle remained usable",
    );
    assert(
      connectionDeleteCancellation.remaining === 1,
      "connection delete cancellation mutated the record",
    );

    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.connection-details-view footer button')]
          .find(candidate => candidate.textContent.includes('永久删除'));
        if (!button) return false;
        button.click();
        return true;
      })()`,
    );
    await waitFor(
      client,
      `document.querySelector('.connection-delete-backdrop [role="alertdialog"]') !== null`,
    );
    const connectionDeleteDialog = await evaluate<Record<string, unknown>>(
      client,
      `(() => ({
        modal: document.querySelector('.connection-delete-backdrop [role="alertdialog"]')?.getAttribute('aria-modal'),
        summary: document.querySelector('.connection-delete-backdrop')?.textContent,
        handleVisible: document.querySelector('.connection-delete-backdrop')?.textContent.includes('operationId')
      }))()`,
    );
    assert(connectionDeleteDialog.modal === "true", "connection delete confirmation is not modal");
    assert(
      typeof connectionDeleteDialog.summary === "string" &&
        connectionDeleteDialog.summary.includes("永久删除") &&
        connectionDeleteDialog.summary.includes("不可恢复"),
      "connection delete confirmation omitted the immutable dangerous summary",
    );
    assert(connectionDeleteDialog.handleVisible === false, "connection delete handle leaked into the UI");
    await evaluate(
      client,
      `(() => {
        const button = [...document.querySelectorAll('.connection-delete-backdrop button')]
          .find(candidate => candidate.textContent.includes('确认永久删除'));
        if (!button) return false;
        button.click();
        return true;
      })()`,
    );
    await waitFor(client, "document.body.textContent.includes('已永久删除，并完成审计验证')");
    const connectionAfterDelete = await evaluate<Record<string, unknown>>(
      client,
      `(async () => ({
        count: (await window.lovelyres.listConnections()).length,
        deleteDialogs: document.querySelectorAll('.connection-delete-backdrop').length
      }))()`,
    );
    assert(connectionAfterDelete.count === 0, "verified connection deletion did not remove the record");
    assert(connectionAfterDelete.deleteDialogs === 0, "connection delete dialog remained after completion");

    const report: ProbeReport = {
      schema: "lovelyres-electron-debug/v1",
      status: "PASS",
      generatedAt: new Date().toISOString(),
      checks: {
        initial,
        terminalDisconnected,
        unauthorizedTerminal,
        snapshotBoundary,
        snapshotDisconnected,
        snapshotLifecycle,
        firewallBoundary,
        firewallDisconnected,
        firewallLifecycle,
        baselineBoundary,
        baselineDisconnected,
        baselineLifecycle,
        middlewareBoundary,
        middlewareDisconnected,
        middlewareLifecycle,
        checkAuditBoundary,
        checkAuditDisconnected,
        checkAuditLifecycle,
        integrityBoundary,
        integrityDisconnected,
        integrityLifecycle,
        integrityConsole,
        logAnalysisBoundary,
        logAnalysisDisconnected,
        logAnalysisLifecycle,
        kubernetesBoundary,
        kubernetesDisconnected,
        kubernetesLifecycle,
        kubernetesConsole,
        dockerBoundary,
        dockerDisconnected,
        dockerLifecycle,
        dockerConsole,
        packetCaptureBoundary,
        packetCaptureDisconnected,
        packetCaptureLifecycle,
        packetCaptureConsole,
        emergencyCommandBoundary,
        emergencyCommandDisconnected,
        emergencyCommandLifecycle,
        emergencyCommandConsole,
        applicationLogBoundary,
        applicationLogOverlay,
        applicationLogEscape,
        applicationLogLifecycle,
        applicationLogConsole,
        settingsBoundary,
        settingsOverlay,
        settingsPlainText,
        settingsSecretReplacement,
        settingsClearCancellationPlan,
        settingsClearCancellation,
        settingsClearConfirmationPlan,
        settingsClearConfirmation,
        settingsRemovalCancellationPlan,
        settingsRemovalCancellation,
        settingsRemovalConfirmationPlan,
        settingsRemovalConfirmation,
        settingsEscape,
        commandHistoryBoundary,
        commandHistoryEmpty,
        commandHistoryEscape,
        disposalReportBoundary,
        disposalReportEmpty,
        disposalReportEscape,
        aiHistoryBoundary,
        aiHistoryEmpty,
        catalog,
        search,
        configGenerator,
        notes,
        noteDeleteCancellation,
        deleteDialog,
        afterDelete,
        connectionCreate,
        connectionFileControls,
        connectionUpdate,
        connectionDeleteCancellation,
        connectionDeleteDialog,
        connectionAfterDelete,
        accessibilityNodeCount: accessibilityNodes.length,
      },
      consoleErrors,
    };
    assert(
      consoleErrors.length === 0,
      `renderer emitted console exceptions or log errors: ${consoleErrors.join(" | ")}`,
    );
    assert(
      !JSON.stringify(report).includes(settingsSecretMarker),
      "Electron debug report retained the Settings secret marker",
    );
    fs.writeFileSync(
      path.join(outputDirectory, "report.json"),
      `${JSON.stringify(report, null, 2)}\n`,
      "utf8",
    );
  } finally {
    if (client.isAttached()) client.detach();
  }
}

async function probeUnauthorizedTerminalRenderer(
  outputDirectory: string,
): Promise<Record<string, unknown>> {
  const terminalWindow = new BrowserWindow({
    width: 1_120,
    height: 760,
    minWidth: 1_080,
    minHeight: 700,
    show: false,
    backgroundColor: "#100c16",
    title: "LovelyRes SSH Terminal Boundary Probe",
    webPreferences: {
      preload: path.join(__dirname, "..", "preload", "terminal.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
    },
  });
  terminalWindow.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  terminalWindow.webContents.on("will-navigate", (event) => event.preventDefault());
  terminalWindow.webContents.on("will-redirect", (event) => event.preventDefault());

  const client = terminalWindow.webContents.debugger;
  const consoleErrors: string[] = [];
  let checks: Record<string, unknown> | null = null;

  try {
    await terminalWindow.loadURL(UNAUTHORIZED_TERMINAL_URL);
    client.attach("1.3");
    client.on("message", (_event, method, parameters: unknown) => {
      const record = isRecord(parameters) ? parameters : null;
      const logEntry = record !== null && isRecord(record.entry) ? record.entry : null;
      if (
        method === "Runtime.exceptionThrown" ||
        (method === "Runtime.consoleAPICalled" && record?.type === "error") ||
        (method === "Log.entryAdded" && logEntry?.level === "error")
      ) {
        consoleErrors.push(truncate(JSON.stringify(parameters)));
      }
    });
    await sendCommand(client, "Runtime.enable");
    await sendCommand(client, "Page.enable");
    await sendCommand(client, "Log.enable");
    const resourceTree = await sendCommand(client, "Page.getResourceTree");
    const cdpResourceUrls = new Set<string>();
    collectNamedStringFields(resourceTree, "url", cdpResourceUrls);
    assert(cdpResourceUrls.size >= 3, "terminal CDP resource tree is unexpectedly empty");
    assert(
      [...cdpResourceUrls].every((url) => url.startsWith("lovelyres://app/")),
      "terminal CDP resource tree contains a non-local URL",
    );
    await waitFor(client, "document.querySelector('[data-testid=\"terminal-window\"]') !== null");
    await waitFor(
      client,
      "document.querySelector('.terminal-error')?.textContent.includes('无法打开当前目标的终端') === true",
    );

    const initial = await evaluate<Record<string, unknown>>(
      client,
      `(() => {
        const api = window.lovelyresTerminal;
        const surface = document.querySelector('.terminal-surface');
        const error = document.querySelector('.terminal-error');
        const parseRgb = (value) => {
          const values = value.match(/[0-9.]+/g)?.slice(0, 3).map(Number) ?? [];
          if (values.length !== 3) throw new Error('invalid terminal color');
          return values;
        };
        const luminance = (rgb) => {
          const channels = rgb.map(value => {
            const channel = value / 255;
            return channel <= 0.03928
              ? channel / 12.92
              : ((channel + 0.055) / 1.055) ** 2.4;
          });
          return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
        };
        const contrast = (foreground, background) => {
          const foregroundLuminance = luminance(parseRgb(foreground));
          const backgroundLuminance = luminance(parseRgb(background));
          return (Math.max(foregroundLuminance, backgroundLuminance) + 0.05) /
            (Math.min(foregroundLuminance, backgroundLuminance) + 0.05);
        };
        const surfaceStyle = getComputedStyle(surface);
        const errorStyle = getComputedStyle(error);
        const methods = Object.keys(api).sort();
        return {
          href: location.href,
          search: location.search,
          hash: location.hash,
          windowName: window.name,
          processType: typeof window.process,
          requireType: typeof window.require,
          apiFrozen: Object.isFrozen(api),
          apiMethods: methods,
          apiArities: Object.fromEntries(methods.map(method => [method, api[method].length])),
          terminalWindow: document.querySelectorAll('[data-testid="terminal-window"]').length,
          terminalSurfaces: document.querySelectorAll('.terminal-surface').length,
          xtermHosts: document.querySelectorAll('.terminal-xterm-host').length,
          surfaceTools: document.querySelectorAll('.terminal-surface-tools').length,
          surfaceButtons: document.querySelectorAll('.terminal-surface button').length,
          passwordInputs: document.querySelectorAll('input[type="password"]').length,
          imageElements: document.querySelectorAll('img').length,
          scriptElements: document.querySelectorAll('script').length,
          inlineHandlers: document.querySelectorAll('[onclick],[onerror],[onload]').length,
          csp: document.querySelector('meta[http-equiv="Content-Security-Policy"]')?.content ?? '',
          resourceUrls: performance.getEntriesByType('resource').map(entry => entry.name),
          forbiddenDomCapability: /bindingHandle|sessionId|targetGuard|launchToken/i.test(document.documentElement.textContent),
          surfaceBackground: surfaceStyle.backgroundColor,
          surfaceColor: surfaceStyle.color,
          errorColor: errorStyle.color,
          surfaceContrast: contrast(surfaceStyle.color, surfaceStyle.backgroundColor),
          errorContrast: contrast(errorStyle.color, surfaceStyle.backgroundColor)
        };
      })()`,
    );
    assert(initial.href === UNAUTHORIZED_TERMINAL_URL, "terminal renderer URL is not fixed");
    assert(initial.search === "?window=terminal", "terminal renderer has unexpected query data");
    assert(initial.hash === "", "terminal renderer contains a hash capability");
    assert(initial.windowName === "", "terminal renderer contains window.name data");
    assert(initial.processType === "undefined", "Node process leaked into terminal renderer");
    assert(initial.requireType === "undefined", "Node require leaked into terminal renderer");
    assert(initial.apiFrozen === true, "terminal preload API is not frozen");
    assert(
      Array.isArray(initial.apiMethods) &&
        initial.apiMethods.join(",") ===
          "cancelSftpOperation,close,confirmSftpOperation,copySelection,downloadSftpEntry," +
            "executeSftpOperation,input,listLocalDirectory,listSftpDirectory,open," +
            "openLocalBrowser,openSftpBrowser,planSftpOperation,poll,readSftpText,resize," +
            "search,stageSftpUpload",
      "terminal preload is not the exact eighteen-method surface",
    );
    assert(
      JSON.stringify(initial.apiArities) ===
        JSON.stringify({
          cancelSftpOperation: 0,
          close: 0,
          confirmSftpOperation: 0,
          copySelection: 0,
          downloadSftpEntry: 0,
          executeSftpOperation: 0,
          input: 0,
          listLocalDirectory: 0,
          listSftpDirectory: 0,
          open: 0,
          openLocalBrowser: 0,
          openSftpBrowser: 0,
          planSftpOperation: 0,
          poll: 0,
          readSftpText: 0,
          resize: 0,
          search: 0,
          stageSftpUpload: 0,
        }),
      `terminal preload method arities changed: ${JSON.stringify(initial.apiArities)}`,
    );
    assert(initial.terminalWindow === 1, "terminal renderer root is missing");
    assert(initial.terminalSurfaces === 1, "terminal surface is missing");
    assert(initial.xtermHosts === 1, "terminal xterm host is missing");
    assert(initial.surfaceTools === 0, "terminal surface still floats a toolbar over the output");
    assert(initial.surfaceButtons === 0, "terminal surface still draws controls over the output");
    assert(initial.passwordInputs === 0, "terminal renderer mounted a password input");
    assert(initial.imageElements === 0, "terminal renderer mounted an image");
    assert(initial.scriptElements === 1, "terminal renderer mounted unexpected scripts");
    assert(initial.inlineHandlers === 0, "terminal renderer mounted inline handlers");
    assert(initial.forbiddenDomCapability === false, "terminal DOM exposes an internal capability");
    assert(
      typeof initial.csp === "string" && initial.csp.includes("default-src 'none'"),
      "terminal renderer CSP is missing",
    );
    assert(
      typeof initial.csp === "string" &&
        initial.csp.includes("script-src 'self'") &&
        !/script-src[^;]*(?:unsafe-inline|unsafe-eval|wasm-unsafe-eval|https?:|data:)/iu.test(initial.csp),
      "terminal renderer script CSP was weakened",
    );
    assert(
      typeof initial.csp === "string" &&
        initial.csp.includes("style-src 'self' 'unsafe-inline'") &&
        initial.csp.includes("worker-src 'none'") &&
        initial.csp.includes("frame-src 'none'") &&
        initial.csp.includes("object-src 'none'") &&
        initial.csp.includes("base-uri 'none'") &&
        initial.csp.includes("form-action 'none'"),
      "terminal-only xterm style CSP exception is not narrowly pinned",
    );
    assert(
      Array.isArray(initial.resourceUrls) &&
        initial.resourceUrls.every(
          (url) => typeof url === "string" && url.startsWith("lovelyres://app/"),
        ),
      "terminal renderer loaded a remote resource",
    );
    assert(
      typeof initial.surfaceBackground === "string" &&
        initial.surfaceBackground !== "transparent" &&
        !initial.surfaceBackground.endsWith(", 0)"),
      "terminal surface background is transparent",
    );
    assert(
      typeof initial.surfaceContrast === "number" && initial.surfaceContrast >= 4.5,
      "terminal surface foreground contrast is below 4.5:1",
    );
    assert(
      typeof initial.errorContrast === "number" && initial.errorContrast >= 4.5,
      "terminal error contrast is below 4.5:1",
    );

    const operations = await evaluate<Record<string, unknown>>(
      client,
      `(async () => {
        const api = window.lovelyresTerminal;
        const marker = 'terminal-copy-secret-20260824-</textarea><script>must-stay-plain()</script>';
        const rejected = async (operation) => {
          try {
            await operation();
            return false;
          } catch (error) {
            return !String(error).includes(marker);
          }
        };
        const results = {
          open: await rejected(() => api.open(80, 24)),
          poll: await rejected(() => api.poll(1, 1)),
          input: await rejected(() => api.input('YQ==')),
          resize: await rejected(() => api.resize(80, 24)),
          search: await rejected(() => api.search('</script>plain', false, false, 1)),
          copySelection: await rejected(() => api.copySelection(marker)),
          oversizedCopySelection: await rejected(() => api.copySelection('界'.repeat(43691))),
          close: await rejected(() => api.close())
        };
        return {
          ...results,
          markerInDom: document.documentElement.textContent.includes(marker),
          markerInWindowName: window.name.includes(marker),
          urlContainsMarker: location.href.includes(marker)
        };
      })()`,
    );
    for (const name of [
      "open",
      "poll",
      "input",
      "resize",
      "search",
      "copySelection",
      "oversizedCopySelection",
      "close",
    ]) {
      assert(operations[name] === true, `unauthorized terminal operation did not fail closed: ${name}`);
    }
    assert(operations.markerInDom === false, "terminal copy marker entered the DOM");
    assert(operations.markerInWindowName === false, "terminal copy marker entered window.name");
    assert(operations.urlContainsMarker === false, "terminal copy marker entered the URL");

    const snapshot = await sendCommand(client, "DOMSnapshot.captureSnapshot", {
      computedStyles: [],
    });
    const snapshotText = JSON.stringify(snapshot);
    assert(
      !/terminal-copy-secret-20260824|bindingHandle|sessionId|targetGuard|launchToken/iu.test(snapshotText),
      "terminal capability or copy marker entered the DOM snapshot",
    );
    assert(
      consoleErrors.length === 0,
      `unauthorized terminal renderer emitted console errors: ${consoleErrors.join(" | ")}`,
    );

    await waitFor(client, "document.fonts.status === 'loaded'");
    terminalWindow.showInactive();
    await new Promise((resolve) => setTimeout(resolve, 100));
    const screenshot = await withTimeout(
      terminalWindow.webContents.capturePage(),
      "Electron unauthorized terminal capturePage",
    ).finally(() => terminalWindow.hide());
    const screenshotBytes = screenshot.toPNG();
    assert(screenshotBytes.length > 100, "unauthorized terminal screenshot capture failed");
    fs.writeFileSync(
      path.join(outputDirectory, "ssh-terminal-unauthorized.png"),
      screenshotBytes,
    );

    checks = {
      mainLovelyResApiCount: MAIN_PRELOAD_API_COUNT,
      terminalPreloadApiCount: 7,
      initial,
      operations,
      consoleErrors,
      localResourceUrls: [...cdpResourceUrls].sort(),
      domSnapshotSensitiveData: false,
      screenshot: "ssh-terminal-unauthorized.png",
      cspDesign: "terminal-only inline CSS required by xterm DOM dimensions; scripts remain self-only",
      sshTransport: "NOT_RUN",
      productionKeyedWindowLifecycle: "NOT_RUN",
    };
  } finally {
    if (client.isAttached()) client.detach();
    if (!terminalWindow.isDestroyed()) terminalWindow.destroy();
  }

  assert(checks !== null, "unauthorized terminal probe did not complete");
  return { ...checks, windowDestroyed: terminalWindow.isDestroyed() };
}

async function evaluate<T = unknown>(client: Debugger, expression: string): Promise<T> {
  const response = (await sendCommand(client, "Runtime.evaluate", {
    expression,
    returnByValue: true,
    awaitPromise: true,
  })) as RuntimeEvaluation<T>;
  if (response.exceptionDetails !== undefined) {
    throw new Error(`CDP evaluation failed: ${JSON.stringify(response.exceptionDetails)}`);
  }
  return response.result.value as T;
}

async function sendCommand(
  client: Debugger,
  method: string,
  parameters?: Record<string, unknown>,
): Promise<unknown> {
  let timeout: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      client.sendCommand(method, parameters),
      new Promise<never>((_resolve, reject) => {
        timeout = setTimeout(
          () => reject(new Error(`CDP command timed out: ${method}`)),
          COMMAND_TIMEOUT_MS,
        );
      }),
    ]);
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
}

async function withTimeout<T>(promise: Promise<T>, operation: string): Promise<T> {
  let timeout: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timeout = setTimeout(
          () => reject(new Error(`${operation} timed out`)),
          COMMAND_TIMEOUT_MS,
        );
      }),
    ]);
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
}

async function capturePageWithVizRetry(window: BrowserWindow) {
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      return await window.webContents.capturePage();
    } catch (error: unknown) {
      if (!String(error).includes("UnknownVizError") || attempt === 3) throw error;
      window.webContents.invalidate();
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
  }
  throw new Error("Electron capturePage exhausted its bounded Viz retries.");
}

async function waitFor(client: Debugger, expression: string): Promise<void> {
  const deadline = Date.now() + PROBE_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (await evaluate<boolean>(client, expression)) return;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`Timed out waiting for renderer condition: ${expression}`);
}

function assert(condition: boolean, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function truncate(value: string): string {
  return value.length <= 2_048 ? value : `${value.slice(0, 2_048)}…`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function collectNamedStringFields(
  value: unknown,
  fieldName: string,
  output: Set<string>,
): void {
  if (Array.isArray(value)) {
    for (const item of value) collectNamedStringFields(item, fieldName, output);
    return;
  }
  if (!isRecord(value)) return;
  for (const [key, nested] of Object.entries(value)) {
    if (key === fieldName && typeof nested === "string") output.add(nested);
    else collectNamedStringFields(nested, fieldName, output);
  }
}
