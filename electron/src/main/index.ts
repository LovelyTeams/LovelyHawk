import fs from "node:fs";
import { randomUUID } from "node:crypto";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

import {
  app,
  BrowserWindow,
  clipboard,
  dialog,
  ipcMain,
  Menu,
  net,
  protocol,
  session,
  type IpcMainInvokeEvent,
} from "electron";

import { BackendClient } from "./backend-client.js";
import {
  cancelledConnectionExport,
  cancelledConnectionImport,
  completedConnectionExport,
  completedConnectionImport,
  isSelectedConnectionJsonPath,
} from "./connection-file-boundary.js";
import {
  createBeforeQuitHandler,
  createRendererCloseGate,
  resolveArchiveRootPath,
  type RendererCloseGate,
} from "./app-lifecycle.js";
import { installDebugProbe } from "./debug-probe.js";
import { LocalBrowser } from "./local-browser.js";
import { installDevToolsToggle, isDebugModeEnabled } from "./debug-mode.js";
import {
  cancelledAiHistoryExport,
  saveAiHistoryExport,
} from "./ai-history-export-boundary.js";
import {
  cancelledDisposalReportExport,
  saveDisposalReportExport,
} from "./disposal-report-export-boundary.js";
import {
  cancelledApplicationLogExport,
  saveApplicationLogExport,
} from "./application-log-export-boundary.js";
import {
  type AiHistoryExportFormat,
  type ApplicationLogFilter,
  type ApplicationLogLevel,
  type ConfigClipboardResult,
  type ConfigExportResult,
  type InternalConfigCopy,
  type DisposalReportExportFormat,
  type SshAttemptStatus,
  type TerminalClosed,
  type TerminalWindowLaunchResult,
  type QuickDetectionPlanInput,
  isConfigGenerateInput,
  isBaselineOpaqueHandle,
  isCheckAuditCatalogInput,
  isCheckAuditLogInput,
  isCheckAuditOpaqueHandle,
  isLogAnalysisOpaqueHandle,
  isLogCorrelationInput,
  isLogIocSearchInput,
  isLogSourceReadInput,
  isKubernetesListInput,
  isKubernetesOpaqueHandle,
  isDockerCollectionKind,
  isDockerLogTail,
  isDockerOpaqueHandle,
  isDockerResourceKind,
  isEmergencyCommandOpaqueHandle,
  isLocalBrowserOpaqueHandle,
  isLocalDirectorySnapshot,
  isSftpBrowserOpaqueHandle,
  isPacketCaptureCursor,
  isPacketCaptureOpaqueHandle,
  isPacketCaptureStartInput,
  isQuickDetectionHistoryRequest,
  isQuickDetectionOpaqueHandle,
  isQuickDetectionPlanInput,
  isQuickDetectionPollRequest,
  isApplicationLogFilter,
  isApplicationLogLevel,
  isIntegrityOpaqueHandle,
  isIntegrityPollRequest,
  isMiddlewareOpaqueHandle,
  isAiHistoryExportFormat,
  isAiHistoryId,
  isAiHistoryOpaqueHandle,
  isAiHistoryPageRequest,
  isAiHistoryQuery,
  isCommandHistoryId,
  isCommandHistoryOpaqueHandle,
  isCommandHistoryPageRequest,
  isCommandHistoryQuery,
  isDisposalReportExportFormat,
  isDisposalReportOpaqueHandle,
  isDisposalReportPreviewFormat,
  isFirewallOpaqueHandle,
  isConnectionDeleteHandle,
  isConnectionId,
  isConnectionWriteInput,
  isSshMfaResponses,
  isSshOpaqueHandle,
  isSettingsAiApiKeyReplacementInput,
  isSettingsMutationHandle,
  isSettingsProviderId,
  isSettingsSaveInput,
  isSnapshotDiffInput,
  isSnapshotOpaqueHandle,
  isSystemInfoMaximumRows,
  isSystemInfoOpaqueHandle,
  isSystemInfoTabKey,
  isTerminalPollBounds,
  isTerminalSearchRequest,
  isTerminalSize,
  isWindowThemeInput,
  terminalBase64DecodedLength,
  TERMINAL_LIMITS,
  type WindowThemeApplied,
} from "../shared/contract.js";
import {
  DEFAULT_THEME_ID,
  TARGET_LABEL_ARGUMENT_PREFIX,
  THEME_ARGUMENT_PREFIX,
  sanitizeTargetLabel,
  isThemeId,
  themeDefinition,
} from "../shared/theme-contract.js";
import {
  RENDERER_HOST,
  RENDERER_SCHEME,
  isTerminalRendererUrl,
  isTrustedRendererUrl,
  resolveRendererAsset,
} from "./renderer-protocol.js";
import { TerminalBindingLaunchState } from "./terminal-launch-state.js";
import {
  isTerminalSelectionCopyRequest,
  openTerminalWithFailureCleanup,
} from "./terminal-open-boundary.js";

const MAX_CLIPBOARD_BYTES = 128 * 1024;
const MAX_CONFIG_CLIPBOARD_BYTES = 256 * 1024;
const CONFIG_EXPORT_FALLBACK_NAME = "lovelyres-config.txt";
const CONNECTION_JSON_FILTER = [
  { name: "LovelyRes connections JSON", extensions: ["json"] },
];
const AI_HISTORY_TEXT_FILTER = [{ name: "Plain text", extensions: ["txt"] }];
const AI_HISTORY_JSON_FILTER = [{ name: "JSON", extensions: ["json"] }];
const DISPOSAL_REPORT_MARKDOWN_FILTER = [{ name: "Markdown", extensions: ["md"] }];
const DISPOSAL_REPORT_HTML_FILTER = [{ name: "HTML", extensions: ["html"] }];
const APPLICATION_LOG_FILTER = [{ name: "Application log", extensions: ["log"] }];
const TERMINAL_WINDOW_KIND = "ssh-terminal";
const TERMINAL_WINDOW_URL = `${RENDERER_SCHEME}://${RENDERER_HOST}/?window=terminal`;
const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join("; ");
const TERMINAL_CSP = [
  "default-src 'none'",
  "script-src 'self'",
  // xterm's local DOM renderer computes dimensions and palette rules at runtime.
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self'",
  "font-src 'self'",
  "connect-src 'self'",
  "worker-src 'none'",
  "frame-src 'none'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join("; ");

protocol.registerSchemesAsPrivileged([
  {
    scheme: RENDERER_SCHEME,
    privileges: {
      standard: true,
      secure: true,
      supportFetchAPI: true,
      stream: true,
    },
  },
]);
app.enableSandbox();

const debugProbeDirectory = !app.isPackaged
  ? process.env.LOVELYRES_DEBUG_PROBE_DIR
  : undefined;
const debugMode = isDebugModeEnabled(app.isPackaged, process.env);
const TITLE_BAR_HEIGHT = 40;
/**
 * Last theme the renderer applied. Main uses it for native colors that must be
 * correct before a window paints, so a light theme never flashes a dark frame.
 */
let activeTheme = DEFAULT_THEME_ID;
/** True while a modal dims the page, so the native controls match it. */
let activeScrim = false;
const archiveRoot = resolveArchiveRootPath({
  isPackaged: app.isPackaged,
  platform: process.platform,
  executablePath: process.execPath,
  appPath: app.getAppPath(),
  developmentOverride: process.env.LOVELYRES_ARCHIVE_ROOT,
});
configurePortableElectronPaths(path.join(archiveRoot, "data"));
const singleInstance = app.requestSingleInstanceLock();
if (!singleInstance) app.quit();

const backend = new BackendClient(resolveBackendPath(), archiveRoot);
let mainWindow: BrowserWindow | null = null;
let rendererReady = false;
let rendererCloseGate: RendererCloseGate | null = null;
const terminalBindingState = new TerminalBindingLaunchState();
// Reads the operator's own machine for the SSH window's local pane.
const localBrowser = new LocalBrowser();

interface TerminalWindowContext {
  readonly key: string;
  readonly bindingHandle: string;
  readonly window: BrowserWindow;
  readonly webContentsId: number;
  launchToken: string | null;
  terminalHandle: string | null;
  closing: boolean;
  closePromise: Promise<void> | null;
}

const terminalWindowsByKey = new Map<string, TerminalWindowContext>();
const terminalWindowsByWebContents = new Map<number, TerminalWindowContext>();

function resolveBackendPath(): string {
  const fileName = process.platform === "win32" ? "lovelyres-backend.exe" : "lovelyres-backend";
  if (app.isPackaged) return path.join(process.resourcesPath, "bin", fileName);
  return path.resolve(app.getAppPath(), "..", "target", "debug", fileName);
}

function configurePortableElectronPaths(root: string): void {
  const electronRoot = path.join(root, "electron");
  const paths = {
    appData: path.join(electronRoot, "app-data"),
    userData: path.join(electronRoot, "user-data"),
    sessionData: path.join(electronRoot, "session-data"),
    temp: path.join(electronRoot, "temp"),
    logs: path.join(electronRoot, "logs"),
    crashDumps: path.join(electronRoot, "crash-dumps"),
  } as const;
  for (const destination of Object.values(paths)) fs.mkdirSync(destination, { recursive: true });
  app.setPath("appData", paths.appData);
  app.setPath("userData", paths.userData);
  app.setPath("sessionData", paths.sessionData);
  app.setPath("temp", paths.temp);
  app.setPath("logs", paths.logs);
  app.setPath("crashDumps", paths.crashDumps);
}

function validateSender(event: IpcMainInvokeEvent): void {
  if (
    mainWindow === null ||
    event.sender !== mainWindow.webContents ||
    event.senderFrame !== event.sender.mainFrame ||
    event.senderFrame === null ||
    !isTrustedRendererUrl(event.senderFrame.url)
  ) {
    throw new Error("Rejected IPC from an untrusted renderer.");
  }
}

function terminalWindowKey(bindingHandle: string): string {
  return `${TERMINAL_WINDOW_KIND}:${bindingHandle}`;
}

function terminalContextFor(event: IpcMainInvokeEvent): TerminalWindowContext {
  const context = terminalWindowsByWebContents.get(event.sender.id);
  if (
    context === undefined ||
    context.closing ||
    context.window.isDestroyed() ||
    context.window.webContents !== event.sender ||
    event.senderFrame === null ||
    event.senderFrame !== event.sender.mainFrame ||
    !isTerminalRendererUrl(event.senderFrame.url) ||
    terminalWindowsByKey.get(context.key) !== context ||
    terminalBindingState.currentBindingHandle() !== context.bindingHandle
  ) {
    throw new Error("Rejected terminal IPC from an unavailable renderer context.");
  }
  return context;
}

function terminalContextIsCurrent(context: TerminalWindowContext): boolean {
  return (
    !context.closing &&
    !context.window.isDestroyed() &&
    terminalWindowsByKey.get(context.key) === context &&
    terminalWindowsByWebContents.get(context.webContentsId) === context &&
    terminalBindingState.currentBindingHandle() === context.bindingHandle
  );
}

function invalidateTerminalContext(context: TerminalWindowContext): string | null {
  if (context.closing) return null;
  context.closing = true;
  context.launchToken = null;
  terminalWindowsByKey.delete(context.key);
  terminalWindowsByWebContents.delete(context.webContentsId);
  const handle = context.terminalHandle;
  context.terminalHandle = null;
  return handle;
}

function closeTerminalContext(
  context: TerminalWindowContext,
  destroyWindow: boolean,
): Promise<void> {
  if (context.closePromise !== null) return context.closePromise;
  const handle = invalidateTerminalContext(context);
  if (destroyWindow && !context.window.isDestroyed()) context.window.destroy();
  context.closePromise = handle === null
    ? Promise.resolve()
    : backend.closeTerminal(handle).then(
      () => undefined,
      () => undefined,
    );
  return context.closePromise;
}

async function closeTerminalWindowsForBinding(bindingHandle: string): Promise<void> {
  const contexts = [...terminalWindowsByKey.values()]
    .filter((context) => context.bindingHandle === bindingHandle);
  await Promise.all(contexts.map((context) => closeTerminalContext(context, true)));
}

async function closeAllTerminalWindows(): Promise<void> {
  const contexts = [...terminalWindowsByKey.values()];
  await Promise.all(contexts.map((context) => closeTerminalContext(context, true)));
}

async function observeSshAttemptStatus(
  attemptHandle: string,
  status: SshAttemptStatus,
): Promise<SshAttemptStatus> {
  const transition = terminalBindingState.observe(attemptHandle, status);
  if (transition.kind === "stale") {
    throw new Error("The SSH connect attempt is no longer current.");
  }
  if (
    transition.kind === "accepted" &&
    transition.previousBindingHandle !== null &&
    transition.previousBindingHandle !== transition.bindingHandle
  ) {
    await closeTerminalWindowsForBinding(transition.previousBindingHandle);
  }
  return status;
}

function createTerminalWindow(bindingHandle: string): TerminalWindowLaunchResult {
  const key = terminalWindowKey(bindingHandle);
  const existing = terminalWindowsByKey.get(key);
  if (existing !== undefined && terminalContextIsCurrent(existing)) {
    if (existing.window.isMinimized()) existing.window.restore();
    existing.window.show();
    existing.window.focus();
    return { opened: true, reused: true };
  }

  const theme = themeDefinition(activeTheme);
  const terminalWindow = new BrowserWindow({
    width: 1_120,
    height: 760,
    minWidth: 1_080,
    minHeight: 700,
    show: false,
    backgroundColor: theme.terminalBackground,
    title: "LovelyRes SSH Terminal",
    // The window draws its own title bar; only the system buttons stay native.
    titleBarStyle: "hidden",
    titleBarOverlay: {
      color: theme.chromeColor,
      symbolColor: theme.chromeSymbolColor,
      height: TITLE_BAR_HEIGHT,
    },
    webPreferences: {
      preload: path.join(__dirname, "..", "preload", "terminal.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      devTools: debugMode,
      // The terminal window is invoke-only, so its theme arrives as a launch
      // switch the preload stamps before first paint.
      additionalArguments: [
        THEME_ARGUMENT_PREFIX + theme.id,
        TARGET_LABEL_ARGUMENT_PREFIX + sanitizeTargetLabel(terminalBindingState.currentTargetLabel()),
      ],
    },
  });
  installDevToolsToggle(terminalWindow, debugMode);
  const context: TerminalWindowContext = {
    key,
    bindingHandle,
    window: terminalWindow,
    webContentsId: terminalWindow.webContents.id,
    launchToken: randomUUID(),
    terminalHandle: null,
    closing: false,
    closePromise: null,
  };
  terminalWindowsByKey.set(key, context);
  terminalWindowsByWebContents.set(terminalWindow.webContents.id, context);
  terminalWindow.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  terminalWindow.webContents.on("will-navigate", (event) => {
    event.preventDefault();
    void closeTerminalContext(context, true);
  });
  terminalWindow.webContents.on("will-redirect", (event) => {
    event.preventDefault();
    void closeTerminalContext(context, true);
  });
  terminalWindow.webContents.on("render-process-gone", () => {
    void closeTerminalContext(context, true);
  });
  terminalWindow.once("ready-to-show", () => {
    if (!terminalContextIsCurrent(context)) return;
    terminalWindow.show();
    terminalWindow.focus();
  });
  terminalWindow.on("closed", () => {
    void closeTerminalContext(context, false);
  });
  void terminalWindow.loadURL(TERMINAL_WINDOW_URL).catch(() => {
    void closeTerminalContext(context, true);
  });
  return { opened: true, reused: false };
}

async function stopBackendWithTerminalWindows(): Promise<void> {
  await closeAllTerminalWindows();
  await backend.stop();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOnlyKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.every((key) => allowed.includes(key));
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === expected.length && keys.every((key) => expected.includes(key));
}

function isBoundedString(value: unknown, maximum: number, allowEmpty = true): value is string {
  return (
    typeof value === "string" &&
    Buffer.byteLength(value, "utf8") <= maximum &&
    (allowEmpty || value.trim().length > 0)
  );
}

function isMutationId(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{16,64}$/u.test(value);
}

function isConfigRevision(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function isConfigIdentifier(value: unknown): value is string {
  return (
    isBoundedString(value, 128, false) &&
    /^[A-Za-z0-9._-]+$/u.test(value)
  );
}

function configClipboardText(payload: InternalConfigCopy): string {
  return payload.artifacts.map((artifact) => artifact.contents).join("\n\n");
}

function safeConfigExportName(suggestedName: string): string {
  const name = path.posix.basename(suggestedName);
  if (
    name.length === 0 ||
    Buffer.byteLength(name, "utf8") > 240 ||
    name === "." ||
    name === ".." ||
    /[\u0000-\u001f<>:"/\\|?*]/u.test(name) ||
    /[. ]$/u.test(name) ||
    /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/iu.test(name)
  ) {
    return CONFIG_EXPORT_FALLBACK_NAME;
  }
  return name;
}

async function saveConfigArtifact(
  suggestedName: string,
  contents: string,
): Promise<ConfigExportResult> {
  if (mainWindow === null) throw new Error("The main window is not available.");
  const result = await dialog.showSaveDialog(mainWindow, {
    title: "导出配置文件",
    defaultPath: safeConfigExportName(suggestedName),
    buttonLabel: "保存",
  });
  if (result.canceled || result.filePath === undefined) {
    return { saved: false, fileName: null };
  }
  if (!path.isAbsolute(result.filePath)) {
    throw new Error("The selected configuration export path is invalid.");
  }

  const file = await fs.promises.open(result.filePath, "wx", 0o600);
  try {
    await file.writeFile(contents, { encoding: "utf8" });
    await file.sync();
    await file.close();
  } catch (error) {
    await file.close().catch(() => undefined);
    throw error;
  }
  return { saved: true, fileName: path.basename(result.filePath) };
}

function isNoteRevision(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/u.test(value);
}

function isNoteId(value: unknown): value is string {
  return isBoundedString(value, 128, false);
}

function isNoteTags(value: unknown): value is string[] {
  return (
    Array.isArray(value) &&
    value.length <= 32 &&
    value.every((tag) => isBoundedString(tag, 64, false))
  );
}

function requireNoteCreate(value: unknown): asserts value is {
  mutationId: string;
  title?: string;
  content: string;
  tags: string[];
} {
  if (
    !isRecord(value) ||
    !hasOnlyKeys(value, ["mutationId", "title", "content", "tags"]) ||
    !isMutationId(value.mutationId) ||
    (value.title !== undefined && !isBoundedString(value.title, 1_024)) ||
    !isBoundedString(value.content, 4 * 1_048_576) ||
    !isNoteTags(value.tags)
  ) {
    throw new Error("Invalid note creation request.");
  }
}

function requireNoteUpdate(value: unknown): asserts value is {
  id: string;
  expectedRevision: string;
  mutationId: string;
  title?: string;
  content?: string;
  tags?: string[];
} {
  if (
    !isRecord(value) ||
    !hasOnlyKeys(value, ["id", "expectedRevision", "mutationId", "title", "content", "tags"]) ||
    !isNoteId(value.id) ||
    !isNoteRevision(value.expectedRevision) ||
    !isMutationId(value.mutationId) ||
    (value.title !== undefined && !isBoundedString(value.title, 1_024)) ||
    (value.content !== undefined && !isBoundedString(value.content, 4 * 1_048_576)) ||
    (value.tags !== undefined && !isNoteTags(value.tags))
  ) {
    throw new Error("Invalid note update request.");
  }
}

function registerIpc(): void {
  ipcMain.handle("lovelyres:bootstrap", async (event) => {
    validateSender(event);
    return backend.bootstrap();
  });
  ipcMain.handle("lovelyres:connections:list", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 0) throw new Error("Invalid connection list request.");
    return backend.listConnections();
  });
  ipcMain.handle("lovelyres:connections:get", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (values.length !== 1) throw new Error("Invalid connection get request.");
    if (!isConnectionId(value)) throw new Error("Invalid connection identifier.");
    return backend.getConnection(value);
  });
  ipcMain.handle("lovelyres:connections:create", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (values.length !== 1) throw new Error("Invalid connection creation request.");
    if (!isConnectionWriteInput(value)) throw new Error("Invalid connection creation request.");
    return backend.createConnection(value);
  });
  ipcMain.handle("lovelyres:connections:update", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (values.length !== 1) throw new Error("Invalid connection update request.");
    if (!isConnectionWriteInput(value)) throw new Error("Invalid connection update request.");
    return backend.updateConnection(value);
  });
  ipcMain.handle("lovelyres:connections:delete:plan", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (values.length !== 1) throw new Error("Invalid connection delete plan request.");
    if (!isConnectionId(value)) throw new Error("Invalid connection identifier.");
    return backend.planConnectionDelete(value);
  });
  ipcMain.handle("lovelyres:connections:delete:confirm", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (values.length !== 1) throw new Error("Invalid connection delete confirmation request.");
    if (!isConnectionDeleteHandle(value)) {
      throw new Error("Invalid connection delete plan handle.");
    }
    return backend.confirmConnectionDelete(value);
  });
  ipcMain.handle("lovelyres:connections:delete:cancel", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (values.length !== 1) throw new Error("Invalid connection delete cancellation request.");
    if (!isConnectionDeleteHandle(value)) {
      throw new Error("Invalid connection delete plan handle.");
    }
    return backend.cancelConnectionDelete(value);
  });
  ipcMain.handle("lovelyres:connections:import", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 0) throw new Error("Invalid connection import request.");
    if (mainWindow === null) throw new Error("The main window is not available.");
    const selection = await dialog.showOpenDialog(mainWindow, {
      title: "导入 LovelyRes 连接",
      filters: [...CONNECTION_JSON_FILTER],
      properties: ["openFile", "dontAddToRecent"],
    });
    if (selection.canceled) return cancelledConnectionImport();
    if (
      selection.filePaths.length !== 1 ||
      !isSelectedConnectionJsonPath(selection.filePaths[0])
    ) {
      throw new Error("The selected connection import path is invalid.");
    }
    const result = await backend.importConnectionsFile(selection.filePaths[0]);
    return completedConnectionImport(result);
  });
  ipcMain.handle("lovelyres:connections:export", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 0) throw new Error("Invalid connection export request.");
    if (mainWindow === null) throw new Error("The main window is not available.");
    const selection = await dialog.showSaveDialog(mainWindow, {
      title: "导出 LovelyRes 连接",
      defaultPath: "lovelyres-connections.json",
      filters: [...CONNECTION_JSON_FILTER],
      buttonLabel: "导出",
      properties: ["dontAddToRecent"],
    });
    if (selection.canceled || selection.filePath === undefined) {
      return cancelledConnectionExport();
    }
    if (!isSelectedConnectionJsonPath(selection.filePath)) {
      throw new Error("The selected connection export path is invalid.");
    }
    const result = await backend.exportConnectionsFile(selection.filePath);
    return completedConnectionExport(result, selection.filePath);
  });
  ipcMain.handle("lovelyres:ssh:connect:start", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1 || !isConnectionId(values[0])) {
      throw new Error("Invalid SSH connect request.");
    }
    const started = await backend.startSshConnect(values[0]);
    terminalBindingState.startConnect(started.attemptHandle);
    return started;
  });
  ipcMain.handle("lovelyres:ssh:probe:start", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1 || !isConnectionWriteInput(values[0])) {
      throw new Error("Invalid SSH probe request.");
    }
    return backend.startSshProbe(values[0]);
  });
  ipcMain.handle("lovelyres:ssh:attempt:get", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1 || !isSshOpaqueHandle(values[0])) {
      throw new Error("Invalid SSH attempt request.");
    }
    const status = await backend.getSshAttempt(values[0]);
    return observeSshAttemptStatus(values[0], status);
  });
  ipcMain.handle("lovelyres:ssh:host-key:confirm", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasOnlyKeys(value, ["attemptHandle", "promptHandle"]) ||
      !isSshOpaqueHandle(value.attemptHandle) ||
      !isSshOpaqueHandle(value.promptHandle)
    ) {
      throw new Error("Invalid SSH host-key confirmation request.");
    }
    const status = await backend.confirmSshHostKey(value.attemptHandle, value.promptHandle);
    return observeSshAttemptStatus(value.attemptHandle, status);
  });
  ipcMain.handle("lovelyres:ssh:mfa:respond", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasOnlyKeys(value, ["attemptHandle", "promptHandle", "responses"]) ||
      !isSshOpaqueHandle(value.attemptHandle) ||
      !isSshOpaqueHandle(value.promptHandle) ||
      !isSshMfaResponses(value.responses)
    ) {
      throw new Error("Invalid SSH MFA response request.");
    }
    const status = await backend.respondSshMfa(
      value.attemptHandle,
      value.promptHandle,
      value.responses,
    );
    return observeSshAttemptStatus(value.attemptHandle, status);
  });
  ipcMain.handle("lovelyres:ssh:attempt:cancel", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1 || !isSshOpaqueHandle(values[0])) {
      throw new Error("Invalid SSH attempt cancellation request.");
    }
    const result = await backend.cancelSshAttempt(values[0]);
    terminalBindingState.cancelAttempt(values[0]);
    return result;
  });
  ipcMain.handle("lovelyres:ssh:binding:disconnect", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1 || !isSshOpaqueHandle(values[0])) {
      throw new Error("Invalid SSH binding disconnection request.");
    }
    const bindingHandle = values[0];
    terminalBindingState.disconnect(bindingHandle);
    await closeTerminalWindowsForBinding(bindingHandle);
    return backend.disconnectSshBinding(bindingHandle);
  });
  ipcMain.handle("lovelyres:terminal-window:open", (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 0) throw new Error("Invalid terminal window launch request.");
    const bindingHandle = terminalBindingState.currentBindingHandle();
    if (bindingHandle === null) throw new Error("No current SSH binding is available.");
    return createTerminalWindow(bindingHandle);
  });
  ipcMain.handle("lovelyres:terminal:open", async (event, ...values: unknown[]) => {
    const context = terminalContextFor(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasOnlyKeys(value, ["columns", "rows"]) ||
      typeof value.columns !== "number" ||
      typeof value.rows !== "number" ||
      !isTerminalSize(value.columns, value.rows) ||
      context.launchToken === null ||
      context.terminalHandle !== null
    ) {
      throw new Error("Invalid terminal open request.");
    }
    const launchToken = context.launchToken;
    const columns = value.columns;
    const rows = value.rows;
    context.launchToken = null;
    if (launchToken.length === 0) throw new Error("Invalid terminal launch authorization.");
    const opened = await openTerminalWithFailureCleanup(
      () => backend.openTerminal(
        context.bindingHandle,
        columns,
        rows,
      ),
      () => closeTerminalContext(context, true),
    );
    if (!terminalContextIsCurrent(context) || context.terminalHandle !== null) {
      await backend.closeTerminal(opened.handle).catch(() => undefined);
      throw new Error("The terminal launch context is no longer current.");
    }
    context.terminalHandle = opened.handle;
    return { columns: opened.columns, rows: opened.rows };
  });
  ipcMain.handle("lovelyres:terminal:poll", async (event, ...values: unknown[]) => {
    const context = terminalContextFor(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasOnlyKeys(value, ["maximumEvents", "maximumBytes"]) ||
      typeof value.maximumEvents !== "number" ||
      typeof value.maximumBytes !== "number" ||
      !isTerminalPollBounds(value.maximumEvents, value.maximumBytes) ||
      context.terminalHandle === null
    ) {
      throw new Error("Invalid terminal poll request.");
    }
    const handle = context.terminalHandle;
    const result = await backend.pollTerminal(handle, value.maximumEvents, value.maximumBytes);
    if (!terminalContextIsCurrent(context) || context.terminalHandle !== handle) {
      throw new Error("The terminal poll context is no longer current.");
    }
    return result;
  });
  ipcMain.handle("lovelyres:terminal:input", async (event, ...values: unknown[]) => {
    const context = terminalContextFor(event);
    const value = values[0];
    const decodedBytes = typeof value === "string"
      ? terminalBase64DecodedLength(value, TERMINAL_LIMITS.maximumInputBytes, false)
      : null;
    if (values.length !== 1 || typeof value !== "string" || decodedBytes === null || context.terminalHandle === null) {
      throw new Error("Invalid terminal input request.");
    }
    const handle = context.terminalHandle;
    const result = await backend.inputTerminal(handle, value);
    if (
      !terminalContextIsCurrent(context) ||
      context.terminalHandle !== handle ||
      result.acceptedBytes !== decodedBytes
    ) {
      throw new Error("The terminal input response is no longer current.");
    }
    return result;
  });
  ipcMain.handle("lovelyres:terminal:resize", async (event, ...values: unknown[]) => {
    const context = terminalContextFor(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasOnlyKeys(value, ["columns", "rows"]) ||
      typeof value.columns !== "number" ||
      typeof value.rows !== "number" ||
      !isTerminalSize(value.columns, value.rows) ||
      context.terminalHandle === null
    ) {
      throw new Error("Invalid terminal resize request.");
    }
    const handle = context.terminalHandle;
    const result = await backend.resizeTerminal(handle, value.columns, value.rows);
    if (!terminalContextIsCurrent(context) || context.terminalHandle !== handle) {
      throw new Error("The terminal resize context is no longer current.");
    }
    return result;
  });
  ipcMain.handle("lovelyres:terminal:search", async (event, ...values: unknown[]) => {
    const context = terminalContextFor(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasOnlyKeys(value, ["query", "caseSensitive", "regex", "maximumResults"]) ||
      typeof value.query !== "string" ||
      typeof value.maximumResults !== "number" ||
      !isTerminalSearchRequest(value.query, value.maximumResults) ||
      typeof value.caseSensitive !== "boolean" ||
      typeof value.regex !== "boolean" ||
      context.terminalHandle === null
    ) {
      throw new Error("Invalid terminal search request.");
    }
    const handle = context.terminalHandle;
    const result = await backend.searchTerminal(
      handle,
      value.query,
      value.caseSensitive,
      value.regex,
      value.maximumResults,
    );
    if (!terminalContextIsCurrent(context) || context.terminalHandle !== handle) {
      throw new Error("The terminal search context is no longer current.");
    }
    return result;
  });
  ipcMain.handle("lovelyres:terminal:copy-selection", (event, ...values: unknown[]) => {
    const context = terminalContextFor(event);
    if (!isTerminalSelectionCopyRequest(context.terminalHandle !== null, values)) {
      throw new Error("Invalid terminal selection copy request.");
    }
    clipboard.writeText(values[0]);
  });
  ipcMain.handle("lovelyres:terminal:close", async (event, ...values: unknown[]) => {
    const context = terminalContextFor(event);
    if (values.length !== 0) throw new Error("Invalid terminal close request.");
    await closeTerminalContext(context, false);
    setImmediate(() => {
      if (!context.window.isDestroyed()) context.window.destroy();
    });
    return { closed: true } satisfies TerminalClosed;
  });
  ipcMain.handle("lovelyres:system-info:catalog:get", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 0) throw new Error("Invalid system-information catalog request.");
    return backend.getSystemInfoCatalog();
  });
  ipcMain.handle("lovelyres:system-info:summary:get", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1 || !isSshOpaqueHandle(values[0])) {
      throw new Error("Invalid system-information summary request.");
    }
    return backend.getSystemInfoSummary(values[0]);
  });
  ipcMain.handle("lovelyres:system-info:table:collect", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasOnlyKeys(value, ["bindingHandle", "tab", "maximumRows"]) ||
      !isSshOpaqueHandle(value.bindingHandle) ||
      !isSystemInfoTabKey(value.tab) ||
      !isSystemInfoMaximumRows(value.maximumRows)
    ) {
      throw new Error("Invalid system-information collection request.");
    }
    return backend.collectSystemInfo(value.bindingHandle, value.tab, value.maximumRows);
  });
  ipcMain.handle("lovelyres:system-info:detail:get", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasOnlyKeys(value, ["bindingHandle", "snapshotHandle", "rowId"]) ||
      !isSshOpaqueHandle(value.bindingHandle) ||
      !isSystemInfoOpaqueHandle(value.snapshotHandle) ||
      !isBoundedString(value.rowId, 256, false)
    ) {
      throw new Error("Invalid system-information detail request.");
    }
    return backend.getSystemInfoDetail(value.bindingHandle, value.snapshotHandle, value.rowId);
  });
  ipcMain.handle("lovelyres:snapshot:list", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1 || !isSnapshotOpaqueHandle(values[0])) {
      throw new Error("Invalid snapshot list request.");
    }
    return backend.listSnapshots(values[0]);
  });
  ipcMain.handle("lovelyres:snapshot:detail:get", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasOnlyKeys(value, ["bindingHandle", "snapshotHandle"]) ||
      !isSnapshotOpaqueHandle(value.bindingHandle) ||
      !isSnapshotOpaqueHandle(value.snapshotHandle)
    ) {
      throw new Error("Invalid snapshot detail request.");
    }
    return backend.getSnapshotDetail(value.bindingHandle, value.snapshotHandle);
  });
  ipcMain.handle("lovelyres:snapshot:forensic:diff", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasOnlyKeys(value, ["bindingHandle", "input"]) ||
      !isSnapshotOpaqueHandle(value.bindingHandle) ||
      !isSnapshotDiffInput(value.input)
    ) {
      throw new Error("Invalid forensic snapshot diff request.");
    }
    return backend.diffForensicSnapshots(value.bindingHandle, value.input);
  });
  ipcMain.handle("lovelyres:firewall:inspect", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1 || !isFirewallOpaqueHandle(values[0])) {
      throw new Error("Invalid firewall inspection request.");
    }
    return backend.inspectFirewall(values[0]);
  });
  ipcMain.handle(
    "lovelyres:firewall:change-history:list",
    async (event, ...values: unknown[]) => {
      validateSender(event);
      if (values.length !== 1 || !isFirewallOpaqueHandle(values[0])) {
        throw new Error("Invalid firewall change-history request.");
      }
      return backend.listFirewallChangeHistory(values[0]);
    },
  );
  ipcMain.handle("lovelyres:baseline:catalog:get", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 0) throw new Error("Invalid baseline catalog request.");
    return backend.getBaselineCatalog();
  });
  ipcMain.handle("lovelyres:baseline:scan", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1 || !isBaselineOpaqueHandle(values[0])) {
      throw new Error("Invalid baseline scan request.");
    }
    return backend.scanBaseline(values[0]);
  });
  ipcMain.handle("lovelyres:baseline:history:list", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1 || !isBaselineOpaqueHandle(values[0])) {
      throw new Error("Invalid baseline history request.");
    }
    return backend.listBaselineHistory(values[0]);
  });
  ipcMain.handle("lovelyres:middleware:discover", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1 || !isMiddlewareOpaqueHandle(values[0])) {
      throw new Error("Invalid middleware discovery request.");
    }
    return backend.discoverMiddleware(values[0]);
  });
  ipcMain.handle(
    "lovelyres:middleware:configuration:load",
    async (event, ...values: unknown[]) => {
      validateSender(event);
      const value = values[0];
      if (
        values.length !== 1 ||
        !isRecord(value) ||
        !hasOnlyKeys(value, ["bindingHandle", "discoveryHandle", "instanceHandle"]) ||
        !isMiddlewareOpaqueHandle(value.bindingHandle) ||
        !isMiddlewareOpaqueHandle(value.discoveryHandle) ||
        !isMiddlewareOpaqueHandle(value.instanceHandle)
      ) {
        throw new Error("Invalid middleware configuration request.");
      }
      return backend.loadMiddlewareConfiguration(
        value.bindingHandle,
        value.discoveryHandle,
        value.instanceHandle,
      );
    },
  );
  ipcMain.handle("lovelyres:middleware:history:list", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1 || !isMiddlewareOpaqueHandle(values[0])) {
      throw new Error("Invalid middleware history request.");
    }
    return backend.listMiddlewareHistory(values[0]);
  });
  ipcMain.handle("lovelyres:check-audit:catalog:get", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasOnlyKeys(value, ["bindingHandle", "input"]) ||
      !isCheckAuditOpaqueHandle(value.bindingHandle) ||
      !isCheckAuditCatalogInput(value.input)
    ) {
      throw new Error("Invalid command-audit catalog request.");
    }
    return backend.getCheckAuditCatalog(value.bindingHandle, value.input);
  });
  ipcMain.handle("lovelyres:check-audit:status:collect", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasOnlyKeys(value, ["bindingHandle", "snapshotHandle"]) ||
      !isCheckAuditOpaqueHandle(value.bindingHandle) ||
      !isCheckAuditOpaqueHandle(value.snapshotHandle)
    ) {
      throw new Error("Invalid command-audit status request.");
    }
    return backend.collectCheckAuditStatus(value.bindingHandle, value.snapshotHandle);
  });
  ipcMain.handle("lovelyres:check-audit:log:read", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasOnlyKeys(value, ["bindingHandle", "snapshotHandle", "input"]) ||
      !isCheckAuditOpaqueHandle(value.bindingHandle) ||
      !isCheckAuditOpaqueHandle(value.snapshotHandle) ||
      !isCheckAuditLogInput(value.input)
    ) {
      throw new Error("Invalid command-audit log request.");
    }
    return backend.readCheckAuditLog(value.bindingHandle, value.snapshotHandle, value.input);
  });
  ipcMain.handle("lovelyres:log-analysis:sources:discover", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1 || !isLogAnalysisOpaqueHandle(values[0])) {
      throw new Error("Invalid log source discovery request.");
    }
    return backend.discoverLogSources(values[0]);
  });
  ipcMain.handle("lovelyres:log-analysis:source:read", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasOnlyKeys(value, ["bindingHandle", "snapshotHandle", "sourceHandle", "input"]) ||
      !isLogAnalysisOpaqueHandle(value.bindingHandle) ||
      !isLogAnalysisOpaqueHandle(value.snapshotHandle) ||
      !isLogAnalysisOpaqueHandle(value.sourceHandle) ||
      !isLogSourceReadInput(value.input)
    ) {
      throw new Error("Invalid log source read request.");
    }
    return backend.readLogSource(
      value.bindingHandle,
      value.snapshotHandle,
      value.sourceHandle,
      value.input,
    );
  });
  ipcMain.handle(
    "lovelyres:log-analysis:sources:correlate",
    async (event, ...values: unknown[]) => {
      validateSender(event);
      const value = values[0];
      if (
        values.length !== 1 ||
        !isRecord(value) ||
        !hasOnlyKeys(value, ["bindingHandle", "snapshotHandle", "input"]) ||
        !isLogAnalysisOpaqueHandle(value.bindingHandle) ||
        !isLogAnalysisOpaqueHandle(value.snapshotHandle) ||
        !isLogCorrelationInput(value.input)
      ) {
        throw new Error("Invalid log source correlation request.");
      }
      return backend.correlateLogSources(value.bindingHandle, value.snapshotHandle, value.input);
    },
  );
  ipcMain.handle("lovelyres:log-analysis:iocs:search", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasOnlyKeys(value, ["bindingHandle", "snapshotHandle", "input"]) ||
      !isLogAnalysisOpaqueHandle(value.bindingHandle) ||
      !isLogAnalysisOpaqueHandle(value.snapshotHandle) ||
      !isLogIocSearchInput(value.input)
    ) {
      throw new Error("Invalid log IOC search request.");
    }
    return backend.searchLogIocs(value.bindingHandle, value.snapshotHandle, value.input);
  });
  ipcMain.handle("lovelyres:kubernetes:availability:get", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1 || !isKubernetesOpaqueHandle(values[0])) {
      throw new Error("Invalid Kubernetes availability request.");
    }
    return backend.getKubernetesAvailability(values[0]);
  });
  ipcMain.handle("lovelyres:kubernetes:resources:list", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasOnlyKeys(value, ["bindingHandle", "input"]) ||
      !isKubernetesOpaqueHandle(value.bindingHandle) ||
      !isKubernetesListInput(value.input)
    ) {
      throw new Error("Invalid Kubernetes resource list request.");
    }
    return backend.listKubernetesResources(value.bindingHandle, value.input);
  });
  ipcMain.handle("lovelyres:kubernetes:resource:detail:get", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasOnlyKeys(value, ["bindingHandle", "snapshotHandle", "rowHandle"]) ||
      !isKubernetesOpaqueHandle(value.bindingHandle) ||
      !isKubernetesOpaqueHandle(value.snapshotHandle) ||
      !isKubernetesOpaqueHandle(value.rowHandle)
    ) {
      throw new Error("Invalid Kubernetes resource detail request.");
    }
    return backend.getKubernetesResourceDetail(
      value.bindingHandle,
      value.snapshotHandle,
      value.rowHandle,
    );
  });
  ipcMain.handle("lovelyres:kubernetes:pod:logs:get", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasOnlyKeys(value, ["bindingHandle", "snapshotHandle", "rowHandle"]) ||
      !isKubernetesOpaqueHandle(value.bindingHandle) ||
      !isKubernetesOpaqueHandle(value.snapshotHandle) ||
      !isKubernetesOpaqueHandle(value.rowHandle)
    ) {
      throw new Error("Invalid Kubernetes Pod log request.");
    }
    return backend.getKubernetesPodLogs(
      value.bindingHandle,
      value.snapshotHandle,
      value.rowHandle,
    );
  });
  ipcMain.handle("lovelyres:docker:containers:refresh", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasExactKeys(value, ["bindingHandle"]) ||
      !isDockerOpaqueHandle(value.bindingHandle)
    ) {
      throw new Error("Invalid Docker container refresh request.");
    }
    return backend.refreshDockerContainers(value.bindingHandle);
  });
  ipcMain.handle("lovelyres:docker:collection:get", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasExactKeys(value, ["bindingHandle", "snapshotHandle", "kind"]) ||
      !isDockerOpaqueHandle(value.bindingHandle) ||
      !isDockerOpaqueHandle(value.snapshotHandle) ||
      !isDockerCollectionKind(value.kind)
    ) {
      throw new Error("Invalid Docker collection request.");
    }
    return backend.getDockerCollection(value.bindingHandle, value.snapshotHandle, value.kind);
  });
  ipcMain.handle("lovelyres:docker:resource:inspect", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasExactKeys(value, ["bindingHandle", "snapshotHandle", "kind", "resourceHandle"]) ||
      !isDockerOpaqueHandle(value.bindingHandle) ||
      !isDockerOpaqueHandle(value.snapshotHandle) ||
      !isDockerResourceKind(value.kind) ||
      !isDockerOpaqueHandle(value.resourceHandle)
    ) {
      throw new Error("Invalid Docker resource inspection request.");
    }
    return backend.inspectDockerResource(
      value.bindingHandle,
      value.snapshotHandle,
      value.kind,
      value.resourceHandle,
    );
  });
  ipcMain.handle("lovelyres:docker:security:audit:get", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasExactKeys(value, ["bindingHandle", "snapshotHandle"]) ||
      !isDockerOpaqueHandle(value.bindingHandle) ||
      !isDockerOpaqueHandle(value.snapshotHandle)
    ) {
      throw new Error("Invalid Docker security audit request.");
    }
    return backend.getDockerSecurityAudit(value.bindingHandle, value.snapshotHandle);
  });
  ipcMain.handle("lovelyres:docker:container:logs:get", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasExactKeys(value, ["bindingHandle", "snapshotHandle", "containerHandle", "tail"]) ||
      !isDockerOpaqueHandle(value.bindingHandle) ||
      !isDockerOpaqueHandle(value.snapshotHandle) ||
      !isDockerOpaqueHandle(value.containerHandle) ||
      !isDockerLogTail(value.tail)
    ) {
      throw new Error("Invalid Docker container log request.");
    }
    return backend.getDockerLogs(
      value.bindingHandle,
      value.snapshotHandle,
      value.containerHandle,
      value.tail,
    );
  });
  ipcMain.handle("lovelyres:emergency-command:catalog:load", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1 || !isEmergencyCommandOpaqueHandle(values[0])) {
      throw new Error("Invalid emergency command catalog request.");
    }
    return backend.loadEmergencyCommandCatalog(values[0]);
  });
  ipcMain.handle("lovelyres:emergency-command:run", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasOnlyKeys(value, ["bindingHandle", "snapshotHandle", "commandHandle"]) ||
      !isEmergencyCommandOpaqueHandle(value.bindingHandle) ||
      !isEmergencyCommandOpaqueHandle(value.snapshotHandle) ||
      !isEmergencyCommandOpaqueHandle(value.commandHandle)
    ) {
      throw new Error("Invalid emergency command run request.");
    }
    return backend.runEmergencyCommand(
      value.bindingHandle,
      value.snapshotHandle,
      value.commandHandle,
    );
  });
  ipcMain.handle("lovelyres:packet-capture:interfaces:list", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasExactKeys(value, ["bindingHandle"]) ||
      !isPacketCaptureOpaqueHandle(value.bindingHandle)
    ) {
      throw new Error("Invalid packet capture interface request.");
    }
    return backend.listPacketCaptureInterfaces(value.bindingHandle);
  });
  ipcMain.handle("lovelyres:packet-capture:start", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasExactKeys(value, ["bindingHandle", "interfaceHandle", "input"]) ||
      !isPacketCaptureOpaqueHandle(value.bindingHandle) ||
      !isPacketCaptureOpaqueHandle(value.interfaceHandle) ||
      !isPacketCaptureStartInput(value.input)
    ) {
      throw new Error("Invalid packet capture start request.");
    }
    return backend.startPacketCapture(value.bindingHandle, value.interfaceHandle, value.input);
  });
  ipcMain.handle("lovelyres:packet-capture:poll", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasExactKeys(value, ["bindingHandle", "captureHandle", "afterSequence"]) ||
      !isPacketCaptureOpaqueHandle(value.bindingHandle) ||
      !isPacketCaptureOpaqueHandle(value.captureHandle) ||
      !isPacketCaptureCursor(value.afterSequence)
    ) {
      throw new Error("Invalid packet capture poll request.");
    }
    return backend.pollPacketCapture(
      value.bindingHandle,
      value.captureHandle,
      value.afterSequence,
    );
  });
  ipcMain.handle("lovelyres:packet-capture:stop", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasExactKeys(value, ["bindingHandle", "captureHandle"]) ||
      !isPacketCaptureOpaqueHandle(value.bindingHandle) ||
      !isPacketCaptureOpaqueHandle(value.captureHandle)
    ) {
      throw new Error("Invalid packet capture stop request.");
    }
    return backend.stopPacketCapture(value.bindingHandle, value.captureHandle);
  });
  ipcMain.handle("lovelyres:quick-detection:catalog:get", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 0) {
      throw new Error("Invalid quick-detection catalog request.");
    }
    return backend.getQuickDetectionCatalog();
  });
  ipcMain.handle("lovelyres:quick-detection:plan", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasExactKeys(value, ["bindingHandle", "input"]) ||
      !isQuickDetectionOpaqueHandle(value.bindingHandle) ||
      !isQuickDetectionPlanInput(value.input)
    ) {
      throw new Error("Invalid quick-detection plan request.");
    }
    return backend.planQuickDetection(
      value.bindingHandle,
      value.input as QuickDetectionPlanInput,
    );
  });
  ipcMain.handle("lovelyres:quick-detection:start", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasExactKeys(value, ["bindingHandle", "planHandle"]) ||
      !isQuickDetectionOpaqueHandle(value.bindingHandle) ||
      !isQuickDetectionOpaqueHandle(value.planHandle) ||
      value.bindingHandle === value.planHandle
    ) {
      throw new Error("Invalid quick-detection start request.");
    }
    return backend.startQuickDetection(value.bindingHandle, value.planHandle);
  });
  ipcMain.handle("lovelyres:quick-detection:poll", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasExactKeys(value, ["bindingHandle", "scanHandle", "afterEvent", "limit"]) ||
      !isQuickDetectionOpaqueHandle(value.bindingHandle) ||
      !isQuickDetectionOpaqueHandle(value.scanHandle) ||
      value.bindingHandle === value.scanHandle ||
      !isQuickDetectionPollRequest(value.afterEvent, value.limit)
    ) {
      throw new Error("Invalid quick-detection poll request.");
    }
    return backend.pollQuickDetection(
      value.bindingHandle,
      value.scanHandle,
      value.afterEvent as number,
      value.limit as number,
    );
  });
  ipcMain.handle("lovelyres:quick-detection:cancel", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasExactKeys(value, ["bindingHandle", "scanHandle"]) ||
      !isQuickDetectionOpaqueHandle(value.bindingHandle) ||
      !isQuickDetectionOpaqueHandle(value.scanHandle) ||
      value.bindingHandle === value.scanHandle
    ) {
      throw new Error("Invalid quick-detection cancellation request.");
    }
    return backend.cancelQuickDetection(value.bindingHandle, value.scanHandle);
  });
  ipcMain.handle("lovelyres:quick-detection:history:list", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasExactKeys(value, ["bindingHandle", "offset", "limit"]) ||
      !isQuickDetectionOpaqueHandle(value.bindingHandle) ||
      !isQuickDetectionHistoryRequest(value.offset, value.limit)
    ) {
      throw new Error("Invalid quick-detection history request.");
    }
    return backend.listQuickDetectionHistory(
      value.bindingHandle,
      value.offset as number,
      value.limit as number,
    );
  });
  ipcMain.handle("lovelyres:quick-detection:report:get", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasExactKeys(value, ["bindingHandle", "reportHandle"]) ||
      !isQuickDetectionOpaqueHandle(value.bindingHandle) ||
      !isQuickDetectionOpaqueHandle(value.reportHandle) ||
      value.bindingHandle === value.reportHandle
    ) {
      throw new Error("Invalid quick-detection report request.");
    }
    return backend.getQuickDetectionReport(value.bindingHandle, value.reportHandle);
  });
  ipcMain.handle("lovelyres:application-log:list", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1 || !isApplicationLogFilter(values[0])) {
      throw new Error("Invalid application log list request.");
    }
    return backend.listApplicationLogs(values[0] as ApplicationLogFilter);
  });
  ipcMain.handle("lovelyres:application-log:level:set", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1 || !isApplicationLogLevel(values[0])) {
      throw new Error("Invalid application log level request.");
    }
    return backend.setApplicationLogLevel(values[0] as ApplicationLogLevel);
  });
  ipcMain.handle("lovelyres:application-log:buffer:clear", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 0) {
      throw new Error("Invalid application log clear request.");
    }
    return backend.clearApplicationLogBuffer();
  });
  ipcMain.handle("lovelyres:application-log:preview:get", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1 || !isApplicationLogFilter(values[0])) {
      throw new Error("Invalid application log preview request.");
    }
    return backend.getApplicationLogPreview(values[0] as ApplicationLogFilter);
  });
  ipcMain.handle("lovelyres:application-log:export", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1 || !isApplicationLogFilter(values[0])) {
      throw new Error("Invalid application log export request.");
    }
    if (mainWindow === null) throw new Error("The main window is not available.");
    const payload = await backend.prepareApplicationLogExport(
      values[0] as ApplicationLogFilter,
    );
    const selection = await dialog.showSaveDialog(mainWindow, {
      title: "导出应用日志",
      defaultPath: payload.suggestedName,
      filters: [...APPLICATION_LOG_FILTER],
      buttonLabel: "导出",
      properties: ["dontAddToRecent"],
    });
    if (selection.canceled || selection.filePath === undefined) {
      return cancelledApplicationLogExport();
    }
    return saveApplicationLogExport(selection.filePath, payload);
  });
  ipcMain.handle("lovelyres:integrity:presets:get", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 0) {
      throw new Error("Invalid file-integrity preset catalog request.");
    }
    return backend.getIntegrityPresets();
  });
  ipcMain.handle("lovelyres:integrity:baselines:list", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (values.length !== 1 || !isRecord(value) ||
      !hasExactKeys(value, ["bindingHandle"]) ||
      !isIntegrityOpaqueHandle(value.bindingHandle)) {
      throw new Error("Invalid file-integrity baseline list request.");
    }
    return backend.listIntegrityBaselines(value.bindingHandle);
  });
  ipcMain.handle("lovelyres:integrity:comparison:start", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (values.length !== 1 || !isRecord(value) ||
      !hasExactKeys(value, ["bindingHandle", "baselineHandle"]) ||
      !isIntegrityOpaqueHandle(value.bindingHandle) ||
      !isIntegrityOpaqueHandle(value.baselineHandle) ||
      value.bindingHandle === value.baselineHandle) {
      throw new Error("Invalid file-integrity comparison start request.");
    }
    return backend.startIntegrityComparison(value.bindingHandle, value.baselineHandle);
  });
  ipcMain.handle("lovelyres:integrity:comparison:poll", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (values.length !== 1 || !isRecord(value) ||
      !hasExactKeys(value, ["bindingHandle", "operationHandle", "afterEvent", "limit"]) ||
      !isIntegrityOpaqueHandle(value.bindingHandle) ||
      !isIntegrityOpaqueHandle(value.operationHandle) ||
      value.bindingHandle === value.operationHandle ||
      !isIntegrityPollRequest(value.afterEvent, value.limit)) {
      throw new Error("Invalid file-integrity comparison poll request.");
    }
    return backend.pollIntegrityComparison(
      value.bindingHandle,
      value.operationHandle,
      value.afterEvent as number,
      value.limit as number,
    );
  });
  ipcMain.handle("lovelyres:integrity:comparison:cancel", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (values.length !== 1 || !isRecord(value) ||
      !hasExactKeys(value, ["bindingHandle", "operationHandle"]) ||
      !isIntegrityOpaqueHandle(value.bindingHandle) ||
      !isIntegrityOpaqueHandle(value.operationHandle) ||
      value.bindingHandle === value.operationHandle) {
      throw new Error("Invalid file-integrity comparison cancellation request.");
    }
    return backend.cancelIntegrityComparison(value.bindingHandle, value.operationHandle);
  });
  ipcMain.handle("lovelyres:settings:get", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 0) throw new Error("Invalid settings load request.");
    return backend.loadSettings();
  });
  ipcMain.handle("lovelyres:ui:window-theme", (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (values.length !== 1 || !isWindowThemeInput(value) || !isThemeId(value.theme)) {
      throw new Error("Invalid window theme request.");
    }
    activeTheme = value.theme;
    activeScrim = value.scrim;
    const definition = themeDefinition(activeTheme);
    if (mainWindow !== null && process.platform === "win32") {
      mainWindow.setTitleBarOverlay({
        // The OS paints the window controls above the page, so a modal backdrop
        // cannot dim them; repaint the overlay with the composited color instead.
        color: activeScrim ? definition.chromeScrimColor : definition.chromeColor,
        symbolColor: definition.chromeSymbolColor,
        height: TITLE_BAR_HEIGHT,
      });
    }
    return { theme: activeTheme, scrim: activeScrim } satisfies WindowThemeApplied;
  });
  ipcMain.handle("lovelyres:settings:save", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1 || !isSettingsSaveInput(values[0])) {
      throw new Error("Invalid settings save request.");
    }
    return backend.saveSettings(values[0]);
  });
  ipcMain.handle("lovelyres:settings:ai-api-key:replace", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1 || !isSettingsAiApiKeyReplacementInput(values[0])) {
      throw new Error("Invalid Settings API-key replacement request.");
    }
    return backend.replaceSettingsAiApiKey(values[0]);
  });
  ipcMain.handle("lovelyres:settings:ai-api-key:clear:plan", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1 || !isSettingsProviderId(values[0])) {
      throw new Error("Invalid Settings API-key clear plan request.");
    }
    return backend.planSettingsAiApiKeyClear(values[0]);
  });
  ipcMain.handle("lovelyres:settings:ai-provider:remove:plan", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1 || !isSettingsProviderId(values[0])) {
      throw new Error("Invalid Settings provider removal plan request.");
    }
    return backend.planSettingsAiProviderRemoval(values[0]);
  });
  ipcMain.handle("lovelyres:settings:mutation:confirm", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1 || !isSettingsMutationHandle(values[0])) {
      throw new Error("Invalid Settings mutation confirmation request.");
    }
    return backend.confirmSettingsMutation(values[0]);
  });
  ipcMain.handle("lovelyres:settings:mutation:cancel", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1 || !isSettingsMutationHandle(values[0])) {
      throw new Error("Invalid Settings mutation cancellation request.");
    }
    return backend.cancelSettingsMutation(values[0]);
  });
  ipcMain.handle("lovelyres:ai-history:list", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasOnlyKeys(value, ["query", "offset", "limit"]) ||
      !isAiHistoryQuery(value.query) ||
      !isAiHistoryPageRequest(value.offset, value.limit)
    ) {
      throw new Error("Invalid AI history list request.");
    }
    return backend.listAiHistory(value.query, value.offset as number, value.limit as number);
  });
  ipcMain.handle("lovelyres:ai-history:get", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1 || !isAiHistoryId(values[0])) {
      throw new Error("Invalid AI history record request.");
    }
    return backend.getAiHistoryRecord(values[0]);
  });
  ipcMain.handle("lovelyres:ai-history:remove:plan", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1 || !isAiHistoryId(values[0])) {
      throw new Error("Invalid AI history removal plan request.");
    }
    return backend.planAiHistoryRemove(values[0]);
  });
  ipcMain.handle("lovelyres:ai-history:clear:plan", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 0) throw new Error("Invalid AI history clear plan request.");
    return backend.planAiHistoryClear();
  });
  ipcMain.handle("lovelyres:ai-history:mutation:confirm", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1 || !isAiHistoryOpaqueHandle(values[0])) {
      throw new Error("Invalid AI history mutation confirmation request.");
    }
    return backend.confirmAiHistoryMutation(values[0]);
  });
  ipcMain.handle("lovelyres:ai-history:mutation:cancel", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1 || !isAiHistoryOpaqueHandle(values[0])) {
      throw new Error("Invalid AI history mutation cancellation request.");
    }
    return backend.cancelAiHistoryMutation(values[0]);
  });
  ipcMain.handle("lovelyres:ai-history:export", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1 || !isAiHistoryExportFormat(values[0])) {
      throw new Error("Invalid AI history export request.");
    }
    if (mainWindow === null) throw new Error("The main window is not available.");
    const format: AiHistoryExportFormat = values[0];
    const payload = await backend.prepareAiHistoryExport(format);
    const selection = await dialog.showSaveDialog(mainWindow, {
      title: "导出 AI 历史",
      defaultPath: payload.suggestedName,
      filters: format === "json" ? [...AI_HISTORY_JSON_FILTER] : [...AI_HISTORY_TEXT_FILTER],
      buttonLabel: "导出",
      properties: ["dontAddToRecent"],
    });
    if (selection.canceled || selection.filePath === undefined) {
      return cancelledAiHistoryExport();
    }
    return saveAiHistoryExport(selection.filePath, payload);
  });
  ipcMain.handle("lovelyres:command-history:list", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (values.length !== 1 || !isRecord(value) ||
      !hasOnlyKeys(value, ["bindingHandle", "query", "offset", "limit"]) ||
      !isCommandHistoryOpaqueHandle(value.bindingHandle) ||
      !isCommandHistoryQuery(value.query) ||
      !isCommandHistoryPageRequest(value.offset, value.limit)) {
      throw new Error("Invalid command history list request.");
    }
    return backend.listCommandHistory(
      value.bindingHandle,
      value.query,
      value.offset as number,
      value.limit as number,
    );
  });
  ipcMain.handle("lovelyres:command-history:get", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (values.length !== 1 || !isRecord(value) ||
      !hasOnlyKeys(value, ["bindingHandle", "recordId"]) ||
      !isCommandHistoryOpaqueHandle(value.bindingHandle) || !isCommandHistoryId(value.recordId)) {
      throw new Error("Invalid command history record request.");
    }
    return backend.getCommandHistory(value.bindingHandle, value.recordId);
  });
  ipcMain.handle("lovelyres:command-history:replay:plan", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (values.length !== 1 || !isRecord(value) ||
      !hasOnlyKeys(value, ["bindingHandle", "recordId"]) ||
      !isCommandHistoryOpaqueHandle(value.bindingHandle) || !isCommandHistoryId(value.recordId)) {
      throw new Error("Invalid command history replay request.");
    }
    return backend.planCommandReplay(value.bindingHandle, value.recordId);
  });
  ipcMain.handle("lovelyres:command-history:remove:plan", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (values.length !== 1 || !isRecord(value) ||
      !hasOnlyKeys(value, ["bindingHandle", "recordId"]) ||
      !isCommandHistoryOpaqueHandle(value.bindingHandle) || !isCommandHistoryId(value.recordId)) {
      throw new Error("Invalid command history removal plan request.");
    }
    return backend.planCommandHistoryRemove(value.bindingHandle, value.recordId);
  });
  ipcMain.handle("lovelyres:command-history:clear:plan", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1 || !isCommandHistoryOpaqueHandle(values[0])) {
      throw new Error("Invalid command history clear plan request.");
    }
    return backend.planCommandHistoryClear(values[0]);
  });
  ipcMain.handle("lovelyres:command-history:mutation:confirm", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (values.length !== 1 || !isRecord(value) ||
      !hasOnlyKeys(value, ["bindingHandle", "mutationHandle"]) ||
      !isCommandHistoryOpaqueHandle(value.bindingHandle) ||
      !isCommandHistoryOpaqueHandle(value.mutationHandle)) {
      throw new Error("Invalid command history mutation confirmation request.");
    }
    return backend.confirmCommandHistoryMutation(value.bindingHandle, value.mutationHandle);
  });
  ipcMain.handle("lovelyres:command-history:mutation:cancel", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (values.length !== 1 || !isRecord(value) ||
      !hasOnlyKeys(value, ["bindingHandle", "mutationHandle"]) ||
      !isCommandHistoryOpaqueHandle(value.bindingHandle) ||
      !isCommandHistoryOpaqueHandle(value.mutationHandle)) {
      throw new Error("Invalid command history mutation cancellation request.");
    }
    return backend.cancelCommandHistoryMutation(value.bindingHandle, value.mutationHandle);
  });
  ipcMain.handle("lovelyres:disposal-report:generate", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1 || !isDisposalReportOpaqueHandle(values[0])) {
      throw new Error("Invalid disposal report generation request.");
    }
    return backend.generateDisposalReport(values[0]);
  });
  ipcMain.handle("lovelyres:disposal-report:content:get", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (values.length !== 1 || !isRecord(value) ||
      !hasOnlyKeys(value, ["bindingHandle", "reportHandle", "format"]) ||
      !isDisposalReportOpaqueHandle(value.bindingHandle) ||
      !isDisposalReportOpaqueHandle(value.reportHandle) ||
      !isDisposalReportPreviewFormat(value.format)) {
      throw new Error("Invalid disposal report content request.");
    }
    return backend.getDisposalReportContent(
      value.bindingHandle,
      value.reportHandle,
      value.format,
    );
  });
  ipcMain.handle("lovelyres:disposal-report:export", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (values.length !== 1 || !isRecord(value) ||
      !hasOnlyKeys(value, ["bindingHandle", "reportHandle", "format"]) ||
      !isDisposalReportOpaqueHandle(value.bindingHandle) ||
      !isDisposalReportOpaqueHandle(value.reportHandle) ||
      !isDisposalReportExportFormat(value.format)) {
      throw new Error("Invalid disposal report export request.");
    }
    if (mainWindow === null) throw new Error("The main window is not available.");
    const format: DisposalReportExportFormat = value.format;
    const payload = await backend.prepareDisposalReportExport(
      value.bindingHandle,
      value.reportHandle,
      format,
    );
    const selection = await dialog.showSaveDialog(mainWindow, {
      title: "导出处置交付报告",
      defaultPath: payload.suggestedName,
      filters: format === "markdown"
        ? [...DISPOSAL_REPORT_MARKDOWN_FILTER]
        : [...DISPOSAL_REPORT_HTML_FILTER],
      buttonLabel: "导出",
      properties: ["dontAddToRecent"],
    });
    if (selection.canceled || selection.filePath === undefined) {
      return cancelledDisposalReportExport();
    }
    return saveDisposalReportExport(selection.filePath, payload);
  });
  ipcMain.handle("lovelyres:config:catalog:get", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 0) throw new Error("Invalid configuration catalog request.");
    return backend.getConfigCatalog();
  });
  ipcMain.handle("lovelyres:config:generate", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1 || !isConfigGenerateInput(values[0])) {
      throw new Error("Invalid configuration generation request.");
    }
    return backend.generateConfig(values[0]);
  });
  ipcMain.handle("lovelyres:config:revise", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasOnlyKeys(value, ["handle", "revision", "input"]) ||
      !isConfigIdentifier(value.handle) ||
      !isConfigRevision(value.revision) ||
      !isConfigGenerateInput(value.input)
    ) {
      throw new Error("Invalid configuration revision request.");
    }
    return backend.reviseConfig(value.handle, value.revision, value.input);
  });
  ipcMain.handle("lovelyres:config:copy", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasOnlyKeys(value, ["handle", "revision"]) ||
      !isConfigIdentifier(value.handle) ||
      !isConfigRevision(value.revision)
    ) {
      throw new Error("Invalid configuration copy request.");
    }
    const payload = await backend.copyConfigDraft(value.handle, value.revision);
    const text = configClipboardText(payload);
    const byteLength = Buffer.byteLength(text, "utf8");
    if (byteLength > MAX_CONFIG_CLIPBOARD_BYTES) {
      throw new Error("The configuration copy payload is too large.");
    }
    clipboard.writeText(text);
    return {
      artifactCount: payload.artifacts.length,
      byteLength,
    } satisfies ConfigClipboardResult;
  });
  ipcMain.handle("lovelyres:config:artifact:export", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasOnlyKeys(value, ["handle", "revision", "artifactKey"]) ||
      !isConfigIdentifier(value.handle) ||
      !isConfigRevision(value.revision) ||
      !isConfigIdentifier(value.artifactKey)
    ) {
      throw new Error("Invalid configuration export request.");
    }
    const artifact = await backend.getConfigArtifact(
      value.handle,
      value.revision,
      value.artifactKey,
    );
    return saveConfigArtifact(artifact.suggestedName, artifact.contents);
  });
  ipcMain.handle("lovelyres:config:draft:close", async (event, ...values: unknown[]) => {
    validateSender(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasOnlyKeys(value, ["handle", "revision"]) ||
      !isConfigIdentifier(value.handle) ||
      !isConfigRevision(value.revision)
    ) {
      throw new Error("Invalid configuration close request.");
    }
    return backend.closeConfigDraft(value.handle, value.revision);
  });
  ipcMain.handle("lovelyres:security-reference:set-favorites", async (event, value: unknown) => {
    validateSender(event);
    if (
      !Array.isArray(value) ||
      value.length > 512 ||
      !value.every((item) => typeof item === "string" && item.length <= 128)
    ) {
      throw new Error("Invalid security-reference favorites.");
    }
    return backend.setSecurityReferenceFavorites(value);
  });
  ipcMain.handle("lovelyres:notes:list", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1) throw new Error("Invalid notes list request.");
    const value = values[0];
    if (
      !isRecord(value) ||
      !hasOnlyKeys(value, ["query", "offset", "limit"]) ||
      !isBoundedString(value.query, 256) ||
      !Number.isSafeInteger(value.offset) ||
      (value.offset as number) < 0 ||
      (value.offset as number) > 100_000 ||
      !Number.isSafeInteger(value.limit) ||
      (value.limit as number) < 1 ||
      (value.limit as number) > 100
    ) {
      throw new Error("Invalid notes list request.");
    }
    return backend.listNotes(value.query, value.offset as number, value.limit as number);
  });
  ipcMain.handle("lovelyres:notes:get", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1) throw new Error("Invalid note get request.");
    const value = values[0];
    if (!isNoteId(value)) throw new Error("Invalid note identifier.");
    return backend.getNote(value);
  });
  ipcMain.handle("lovelyres:notes:create", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1) throw new Error("Invalid note creation request.");
    const value = values[0];
    requireNoteCreate(value);
    return backend.createNote(value);
  });
  ipcMain.handle("lovelyres:notes:update", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1) throw new Error("Invalid note update request.");
    const value = values[0];
    requireNoteUpdate(value);
    return backend.updateNote(value);
  });
  ipcMain.handle("lovelyres:notes:set-pinned", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1) throw new Error("Invalid note pin request.");
    const value = values[0];
    if (
      !isRecord(value) ||
      !hasOnlyKeys(value, ["id", "pinned", "expectedRevision", "mutationId"]) ||
      !isNoteId(value.id) ||
      !isNoteRevision(value.expectedRevision) ||
      !isMutationId(value.mutationId) ||
      typeof value.pinned !== "boolean"
    ) {
      throw new Error("Invalid note pin request.");
    }
    return backend.setNotePinned(value.id, value.pinned, value.expectedRevision, value.mutationId);
  });
  ipcMain.handle("lovelyres:notes:add-tag", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1) throw new Error("Invalid note tag request.");
    const value = values[0];
    if (
      !isRecord(value) ||
      !hasOnlyKeys(value, ["id", "tag", "expectedRevision", "mutationId"]) ||
      !isNoteId(value.id) ||
      !isNoteRevision(value.expectedRevision) ||
      !isMutationId(value.mutationId) ||
      !isBoundedString(value.tag, 64, false)
    ) {
      throw new Error("Invalid note tag request.");
    }
    return backend.addNoteTag(value.id, value.tag, value.expectedRevision, value.mutationId);
  });
  ipcMain.handle("lovelyres:notes:remove-tag", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1) throw new Error("Invalid note tag request.");
    const value = values[0];
    if (
      !isRecord(value) ||
      !hasOnlyKeys(value, ["id", "tag", "expectedRevision", "mutationId"]) ||
      !isNoteId(value.id) ||
      !isNoteRevision(value.expectedRevision) ||
      !isMutationId(value.mutationId) ||
      !isBoundedString(value.tag, 64, false)
    ) {
      throw new Error("Invalid note tag request.");
    }
    return backend.removeNoteTag(value.id, value.tag, value.expectedRevision, value.mutationId);
  });
  ipcMain.handle("lovelyres:notes:delete:plan", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1) throw new Error("Invalid note delete plan request.");
    const value = values[0];
    if (!isRecord(value) || !hasOnlyKeys(value, ["id", "expectedRevision", "mutationId"]) || !isNoteId(value.id) || !isNoteRevision(value.expectedRevision) || !isMutationId(value.mutationId)) throw new Error("Invalid note delete plan request.");
    return backend.planNoteDelete(value.id, value.expectedRevision, value.mutationId);
  });
  ipcMain.handle("lovelyres:notes:delete:confirm", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1) throw new Error("Invalid delete confirmation request.");
    const value = values[0];
    if (!isRecord(value) || !hasOnlyKeys(value, ["handle", "mutationId"]) || !isBoundedString(value.handle, 128, false) || !isMutationId(value.mutationId)) throw new Error("Invalid delete plan handle.");
    return backend.confirmNoteDelete(value.handle, value.mutationId);
  });
  ipcMain.handle("lovelyres:notes:delete:cancel", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1) throw new Error("Invalid delete cancellation request.");
    const value = values[0];
    if (!isRecord(value) || !hasOnlyKeys(value, ["handle", "mutationId"]) || !isBoundedString(value.handle, 128, false) || !isMutationId(value.mutationId)) throw new Error("Invalid delete plan handle.");
    return backend.cancelNoteDelete(value.handle, value.mutationId);
  });
  ipcMain.handle("lovelyres:notes:export", async (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1) throw new Error("Invalid notes export request.");
    const value = values[0];
    if (value !== null && !isNoteId(value)) throw new Error("Invalid notes export request.");
    return backend.exportNotes(value);
  });
  ipcMain.handle("lovelyres:clipboard:write-text", (event, ...values: unknown[]) => {
    validateSender(event);
    if (values.length !== 1) throw new Error("Invalid clipboard payload.");
    const value = values[0];
    if (typeof value !== "string" || Buffer.byteLength(value, "utf8") > MAX_CLIPBOARD_BYTES) {
      throw new Error("Invalid clipboard payload.");
    }
    clipboard.writeText(value);
  });
  // The SFTP browser answers only the terminal window, whose binding main
  // resolves from the calling window; the renderer never sends target identity.
  ipcMain.handle("lovelyres:terminal:sftp:download", async (event, ...values: unknown[]) => {
    const context = terminalContextFor(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasOnlyKeys(value, ["browserHandle", "fileHandle"]) ||
      !isSftpBrowserOpaqueHandle(value.browserHandle) ||
      !isSftpBrowserOpaqueHandle(value.fileHandle)
    ) {
      throw new Error("Invalid SFTP download request.");
    }
    // The operator picks where the bytes land; the renderer never names a path.
    const window = BrowserWindow.fromWebContents(event.sender);
    if (window === null) throw new Error("The SFTP download window is not available.");
    const selection = await dialog.showSaveDialog(window, {
      title: "保存远程文件",
      buttonLabel: "保存",
    });
    if (selection.canceled || selection.filePath === undefined) {
      return { saved: false, fileName: null, bytes: null };
    }
    if (!path.isAbsolute(selection.filePath)) {
      throw new Error("The selected download path is invalid.");
    }
    const transfer = await backend.downloadSftpEntry(
      context.bindingHandle,
      value.browserHandle,
      value.fileHandle,
      selection.filePath,
    );
    return { saved: true, fileName: path.basename(selection.filePath), bytes: transfer.bytes };
  });
  ipcMain.handle("lovelyres:terminal:local:open", async (event, ...values: unknown[]) => {
    terminalContextFor(event);
    if (values.length !== 0) throw new Error("Invalid local browser request.");
    const snapshot = await localBrowser.open();
    if (!isLocalDirectorySnapshot(snapshot)) throw new Error("Invalid local directory listing.");
    return snapshot;
  });
  ipcMain.handle("lovelyres:terminal:local:list", async (event, ...values: unknown[]) => {
    terminalContextFor(event);
    if (values.length !== 1 || !isLocalBrowserOpaqueHandle(values[0])) {
      throw new Error("Invalid local directory request.");
    }
    const snapshot = await localBrowser.list(values[0]);
    if (!isLocalDirectorySnapshot(snapshot)) throw new Error("Invalid local directory listing.");
    return snapshot;
  });
  ipcMain.handle("lovelyres:terminal:sftp:open", async (event, ...values: unknown[]) => {
    const context = terminalContextFor(event);
    if (values.length !== 0) throw new Error("Invalid SFTP browser request.");
    return backend.openSftpBrowser(context.bindingHandle);
  });
  ipcMain.handle("lovelyres:terminal:sftp:directory:list", async (event, ...values: unknown[]) => {
    const context = terminalContextFor(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasOnlyKeys(value, ["browserHandle", "directoryHandle"]) ||
      !isSftpBrowserOpaqueHandle(value.browserHandle) ||
      !isSftpBrowserOpaqueHandle(value.directoryHandle)
    ) {
      throw new Error("Invalid SFTP directory request.");
    }
    return backend.listSftpDirectory(context.bindingHandle, value.browserHandle, value.directoryHandle);
  });
  ipcMain.handle("lovelyres:terminal:sftp:text:read", async (event, ...values: unknown[]) => {
    const context = terminalContextFor(event);
    const value = values[0];
    if (
      values.length !== 1 ||
      !isRecord(value) ||
      !hasOnlyKeys(value, ["browserHandle", "fileHandle"]) ||
      !isSftpBrowserOpaqueHandle(value.browserHandle) ||
      !isSftpBrowserOpaqueHandle(value.fileHandle)
    ) {
      throw new Error("Invalid SFTP preview request.");
    }
    return backend.readSftpText(context.bindingHandle, value.browserHandle, value.fileHandle);
  });
  ipcMain.on("lovelyres:renderer-ready", (event) => {
    if (
      mainWindow === null ||
      event.sender !== mainWindow.webContents ||
      !isTrustedRendererUrl(event.senderFrame?.url ?? "")
    ) {
      return;
    }
    if (rendererReady) return;
    rendererReady = true;
    writeRequestedSmokeMarker();
  });
  ipcMain.on("lovelyres:before-close-result", (event, ...values: unknown[]) => {
    if (
      values.length !== 1 ||
      typeof values[0] !== "boolean" ||
      mainWindow === null ||
      event.sender !== mainWindow.webContents ||
      !isTrustedRendererUrl(event.senderFrame?.url ?? "")
    ) return;
    rendererCloseGate?.resolve(values[0]);
  });
}

async function registerRendererProtocol(): Promise<void> {
  const rendererRoot = path.join(app.getAppPath(), "dist-renderer");
  await protocol.handle(RENDERER_SCHEME, (request) => {
    const asset = resolveRendererAsset(request.url, rendererRoot);
    if (asset === null || !fs.existsSync(asset) || !fs.statSync(asset).isFile()) {
      return new Response("Not found", { status: 404 });
    }
    return net.fetch(pathToFileURL(asset).toString());
  });
}

function createWindow(): void {
  Menu.setApplicationMenu(null);
  const theme = themeDefinition(activeTheme);
  mainWindow = new BrowserWindow({
    width: 1_440,
    height: 920,
    minWidth: 1_080,
    minHeight: 700,
    show: false,
    backgroundColor: theme.windowBackground,
    title: "LovelyRes",
    titleBarStyle: "hidden",
    titleBarOverlay: {
      color: theme.chromeColor,
      symbolColor: theme.chromeSymbolColor,
      height: TITLE_BAR_HEIGHT,
    },
    webPreferences: {
      preload: path.join(__dirname, "..", "preload", "index.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      devTools: debugMode,
    },
  });
  installDevToolsToggle(mainWindow, debugMode);
  mainWindow.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  mainWindow.webContents.on("will-navigate", (event, targetUrl) => {
    if (!isTrustedRendererUrl(targetUrl)) event.preventDefault();
  });
  rendererCloseGate = createRendererCloseGate(
    () => mainWindow?.webContents.send("lovelyres:before-close"),
    () => mainWindow?.close(),
  );
  mainWindow.on("close", (event) => rendererCloseGate?.request(event));
  if (debugProbeDirectory === undefined) {
    mainWindow.once("ready-to-show", () => mainWindow?.show());
  } else {
    installDebugProbe(mainWindow, debugProbeDirectory, async (exitCode) => {
      await stopBackendWithTerminalWindows();
      app.exit(exitCode);
    });
  }
  mainWindow.on("closed", () => {
    rendererCloseGate?.dispose();
    rendererCloseGate = null;
    mainWindow = null;
    void closeAllTerminalWindows();
  });
  void mainWindow.loadURL(`${RENDERER_SCHEME}://${RENDERER_HOST}/`);
}

function writeRequestedSmokeMarker(): void {
  const requestedRoot = process.env.LOVELYRES_SMOKE_READY_ROOT;
  const nonce = process.env.LOVELYRES_SMOKE_READY_NONCE;
  if (requestedRoot === undefined && nonce === undefined) return;
  if (requestedRoot === undefined || nonce === undefined || !/^[a-f0-9]{32}$/.test(nonce)) {
    throw new Error("Invalid portable smoke marker request.");
  }

  const temporaryRoot = fs.realpathSync(path.resolve(os.tmpdir()));
  const markerRoot = fs.realpathSync(path.resolve(requestedRoot));
  const relativeRoot = path.relative(temporaryRoot, markerRoot);
  if (
    relativeRoot.length === 0 ||
    relativeRoot.startsWith(`..${path.sep}`) ||
    relativeRoot === ".." ||
    path.isAbsolute(relativeRoot) ||
    !/^lovelyres-electron-smoke-[a-f0-9]{32}$/.test(path.basename(markerRoot))
  ) {
    throw new Error("Portable smoke marker root must be a controlled temporary directory.");
  }

  const destination = path.join(markerRoot, `ready-${nonce}.json`);
  if (fs.existsSync(destination)) throw new Error("Portable smoke marker destination already exists.");
  const temporary = path.join(markerRoot, `.marker-${process.pid}-${nonce}.tmp`);
  const handle = fs.openSync(temporary, "wx");
  try {
    fs.writeFileSync(handle, '{"schema":"lovelyres-smoke-ready/v1","status":"ready"}', "utf8");
    fs.fsyncSync(handle);
  } finally {
    fs.closeSync(handle);
  }
  try {
    fs.linkSync(temporary, destination);
  } finally {
    fs.unlinkSync(temporary);
  }
}

if (singleInstance) {
  app.whenReady().then(async () => {
    session.defaultSession.setPermissionRequestHandler((_webContents, _permission, callback) => {
      callback(false);
    });
    session.defaultSession.setPermissionCheckHandler(() => false);
    session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
      if (!isTrustedRendererUrl(details.url)) {
        callback(
          details.responseHeaders === undefined
            ? {}
            : { responseHeaders: details.responseHeaders },
        );
        return;
      }
      callback({
        responseHeaders: {
          ...details.responseHeaders,
          "Content-Security-Policy": [isTerminalRendererUrl(details.url) ? TERMINAL_CSP : CSP],
        },
      });
    });
    await registerRendererProtocol();
    backend.start();
    registerIpc();
    createWindow();
  });

  app.on("second-instance", () => {
    if (mainWindow === null) return;
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.focus();
  });
  app.on("window-all-closed", () => app.quit());
  const stopBackendBeforeQuit = createBeforeQuitHandler(
    () => stopBackendWithTerminalWindows(),
    () => app.quit(),
    (error) => console.error("[backend] Failed to stop before quit.", error),
  );
  app.on("before-quit", (event) => {
    if (mainWindow !== null) {
      event.preventDefault();
      mainWindow.close();
      return;
    }
    stopBackendBeforeQuit(event);
  });
}
