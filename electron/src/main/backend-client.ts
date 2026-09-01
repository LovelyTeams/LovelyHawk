import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { randomUUID } from "node:crypto";

import {
  BACKEND_PROTOCOL,
  type AiHistoryExportFormat,
  type AiHistoryListPage,
  type AiHistoryMutationCancellation,
  type AiHistoryMutationProposal,
  type AiHistoryMutationResult,
  type AiHistoryRecord,
  type BootstrapResult,
  type BaselineCatalog,
  type BaselineFile,
  type BaselineHistory,
  type BaselineScan,
  type CheckAuditCatalog,
  type CheckAuditCatalogInput,
  type CheckAuditLogInput,
  type CheckAuditLogResult,
  type CheckAuditStatus,
  type LogCorrelationInput,
  type LogCorrelationResult,
  type LogIocSearchInput,
  type LogIocSearchResult,
  type LogSourceReadInput,
  type LogSourceReadResult,
  type LogSourceSnapshot,
  type KubernetesActionCancellation,
  type KubernetesActionPlan,
  type KubernetesActionReceipt,
  type KubernetesAvailability,
  type KubernetesWriteAction,
  type KubernetesListInput,
  type KubernetesSnapshot,
  type KubernetesTextResult,
  type DockerCollectionKind,
  type DockerContainerSnapshot,
  type DockerActionCancellation,
  type DockerActionPlan,
  type DockerActionReceipt,
  type DockerWriteAction,
  type DockerLogs,
  type DockerReadCollection,
  type DockerReadInspection,
  type DockerResourceKind,
  type DockerSecurityAudit,
  type EmergencyCommandCatalog,
  type EmergencyCommandResult,
  type EmergencyPathAction,
  type EmergencyPathDetail,
  type EmergencyPathPlan,
  type EmergencyPathReceipt,
  type SftpDirectorySnapshot,
  type SftpOperationInput,
  type SftpOperationPlan,
  type SftpOperationReceipt,
  type SftpStagedUpload,
  type SftpTextPreview,
  type PacketCaptureInterfaceList,
  type PacketCapturePoll,
  type PacketCaptureStarted,
  type PacketCaptureStartInput,
  type PacketCaptureStopped,
  type ApplicationLogClearResult,
  type ApplicationLogFilter,
  type ApplicationLogLevel,
  type ApplicationLogLevelResult,
  type ApplicationLogPreview,
  type ApplicationLogSnapshot,
  type IntegrityBaselineList,
  type IntegrityComparisonCancellation,
  type IntegrityComparisonPoll,
  type IntegrityComparisonStarted,
  type IntegrityPresetCatalog,
  type ConfigCatalog,
  type ConfigClosedResult,
  type ConfigDraft,
  type ConfigGenerateInput,
  type CommandHistoryListPage,
  type CommandHistoryMutationCancellation,
  type CommandHistoryMutationProposal,
  type CommandHistoryMutationResult,
  type CommandHistoryRecord,
  type CommandReplayIntent,
  type DisposalReportContent,
  type DisposalReportExportFormat,
  type DisposalReportPreviewFormat,
  type DisposalReportSnapshot,
  type ConnectionDeleteCancellation,
  type ConnectionDeletePrompt,
  type ConnectionDeleteResult,
  type ConnectionEditView,
  type InternalConnectionExportResult,
  type InternalConnectionImportResult,
  type ConnectionSummary,
  type ConnectionWriteInput,
  type InternalConfigArtifact,
  type InternalConfigCopy,
  type NoteCreateInput,
  type NoteDeleteProposal,
  type NoteDeleteCancellation,
  type NoteDeleteResult,
  type NoteListPage,
  type NoteResult,
  type NotesTextExport,
  type NoteUpdateInput,
  type SecurityReferenceFavoritesResult,
  type SettingsSaveInput,
  type SettingsAiApiKeyReplacementInput,
  type SettingsAiApiKeyReplacementResult,
  type SettingsMutationCancellation,
  type SettingsMutationProposal,
  type SettingsMutationResult,
  type SettingsSnapshot,
  type SshAttemptCancellation,
  type SshAttemptStarted,
  type SshAttemptStatus,
  type SshBindingDisconnection,
  type SystemInfoDetail,
  type SystemInfoRowActions,
  type SystemInfoRowInspection,
  type SystemInfoRowPlan,
  type SystemInfoRowReceipt,
  type SystemInfoSummary,
  type SystemInfoTabCatalogEntry,
  type SystemInfoTabKey,
  type SystemInfoTable,
  type ContainerTerminalOpened,
  type TerminalClosed,
  type TerminalInputAcknowledgement,
  type TerminalOpened,
  type TerminalPoll,
  type TerminalRenderSnapshot,
  type TerminalResized,
  type TerminalSearch,
  isBootstrapResult,
  isBaselineCatalog,
  isBaselineFile,
  isBaselineHistory,
  isBaselineOpaqueHandle,
  isBaselineScan,
  isCheckAuditCatalog,
  isCheckAuditCatalogInput,
  isCheckAuditLogInput,
  isCheckAuditLogResult,
  isCheckAuditOpaqueHandle,
  isCheckAuditStatus,
  isLogAnalysisOpaqueHandle,
  isLogCorrelationInput,
  isLogCorrelationResult,
  isLogIocSearchInput,
  isLogIocSearchResult,
  isLogSourceReadInput,
  isLogSourceReadResult,
  isLogSourceSnapshot,
  isKubernetesAvailability,
  isKubernetesListInput,
  isKubernetesActionCancellation,
  isKubernetesActionPlan,
  isKubernetesActionReceipt,
  isKubernetesOpaqueHandle,
  isKubernetesResourceName,
  isKubernetesWriteAction,
  isKubernetesSnapshot,
  isKubernetesTextResult,
  isDockerCollectionKind,
  isDockerContainerSnapshot,
  isDockerLogs,
  isDockerLogTail,
  isDockerActionCancellation,
  isDockerActionPlan,
  isDockerActionReceipt,
  isDockerContainerName,
  isDockerOpaqueHandle,
  isDockerWriteAction,
  isDockerReadCollection,
  isDockerReadInspection,
  isDockerResourceKind,
  isDockerSecurityAudit,
  isEmergencyCommandCatalog,
  isEmergencyCommandOpaqueHandle,
  isEmergencyCommandResult,
  isEmergencyPathAction,
  isEmergencyPathDetail,
  isEmergencyPathPlan,
  isEmergencyPathReceipt,
  isSftpBrowserOpaqueHandle,
  isSftpDirectorySnapshot,
  isSftpOperationPlan,
  isSftpOperationReceipt,
  isSftpStagedUpload,
  isSftpTextPreview,
  isPacketCaptureCursor,
  isPacketCaptureInterfaceList,
  isPacketCaptureOpaqueHandle,
  isPacketCapturePoll,
  isPacketCaptureStarted,
  isPacketCaptureStartInput,
  isPacketCaptureStopped,
  isApplicationLogClearResult,
  isApplicationLogFilter,
  isApplicationLogLevel,
  isApplicationLogLevelResult,
  isApplicationLogPreview,
  isApplicationLogSnapshot,
  isIntegrityBaselineList,
  isIntegrityComparisonCancellation,
  isIntegrityComparisonPoll,
  isIntegrityComparisonStarted,
  isIntegrityOpaqueHandle,
  isIntegrityPollRequest,
  isIntegrityPresetCatalog,
  isAiHistoryExportFormat,
  isAiHistoryId,
  isAiHistoryListPage,
  isAiHistoryMutationCancellation,
  isAiHistoryMutationProposal,
  isAiHistoryMutationResult,
  isAiHistoryOpaqueHandle,
  isAiHistoryPageRequest,
  isAiHistoryQuery,
  isAiHistoryRecord,
  isConfigCatalog,
  isCommandHistoryId,
  isCommandHistoryListPage,
  isCommandHistoryMutationCancellation,
  isCommandHistoryMutationProposal,
  isCommandHistoryMutationResult,
  isCommandHistoryOpaqueHandle,
  isCommandHistoryPageRequest,
  isCommandHistoryQuery,
  isCommandHistoryRecord,
  isCommandReplayIntent,
  isDisposalReportContent,
  isDisposalReportExportFormat,
  isDisposalReportOpaqueHandle,
  isDisposalReportPreviewFormat,
  isDisposalReportSnapshot,
  isConfigClosedResult,
  isConfigDraft,
  isConnectionDeleteCancellation,
  isConnectionDeletePrompt,
  isConnectionDeleteResult,
  isConnectionEditView,
  isConnectionSummaryArray,
  isInternalConnectionExportResult,
  isInternalConnectionImportResult,
  isInternalConfigArtifact,
  isInternalConfigCopy,
  isNoteDeleteProposal,
  isNoteDeleteCancellation,
  isNoteDeleteResult,
  isNoteListPage,
  isNoteResult,
  isNotesTextExport,
  isSecurityReferenceFavoritesResult,
  isSettingsSaveInput,
  isSettingsAiApiKeyReplacementInput,
  isSettingsAiApiKeyReplacementResult,
  isSettingsMutationCancellation,
  isSettingsMutationHandle,
  isSettingsMutationProposal,
  isSettingsMutationResult,
  isSettingsProviderId,
  isSettingsSnapshot,
  isSshAttemptCancellation,
  isSshAttemptStarted,
  isSshAttemptStatus,
  isSshBindingDisconnection,
  isSshOpaqueHandle,
  isSystemInfoCatalog,
  isSystemInfoDetail,
  isSystemInfoOpaqueHandle,
  isSystemInfoRowActionKey,
  isSystemInfoRowActions,
  isSystemInfoRowInspection,
  isSystemInfoRowPlan,
  isSystemInfoRowReceipt,
  isSystemInfoSummary,
  isSystemInfoTable,
  isContainerTerminalOpened,
  isTerminalBindingHandle,
  isTerminalClosed,
  isTerminalHandle,
  isTerminalInputAcknowledgement,
  isTerminalOpened,
  isTerminalPoll,
  isTerminalPollBounds,
  isTerminalRenderSnapshot,
  isTerminalResized,
  isTerminalSearch,
  isTerminalSearchRequest,
  isTerminalSize,
  terminalBase64DecodedLength,
  TERMINAL_LIMITS,
} from "../shared/contract.js";
import {
  isInternalAiHistoryExportPayload,
  type InternalAiHistoryExportPayload,
} from "./ai-history-export-boundary.js";
import {
  isInternalDisposalReportExportPayload,
  type InternalDisposalReportExportPayload,
} from "./disposal-report-export-boundary.js";
import {
  isInternalApplicationLogExportPayload,
  type InternalApplicationLogExportPayload,
} from "./application-log-export-boundary.js";

// Mirrors the sidecar frame bound and covers the worst-case JSON escaping for
// the core's one-million-character note limit.
const MAX_REQUEST_BYTES = 8 * 1024 * 1024;
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
/**
 * How long to wait for one sidecar answer.
 *
 * This is not how a dead sidecar is noticed: the child's exit and error events
 * fail every pending request at once. It only fires while the sidecar is alive
 * and still working, so it has to sit above whatever bound the sidecar itself
 * applies — otherwise the operator is told the request timed out instead of
 * the specific reason the sidecar was a moment away from giving, and the answer
 * that does arrive is dropped on the floor.
 *
 * The default suits work that never leaves this machine. Anything that runs a
 * command on a target waits longer, because the core gives those commands up
 * to forty-five seconds each and a loaded host uses all of it.
 */
const REQUEST_TIMEOUT_MS = 15_000;
const REMOTE_REQUEST_TIMEOUT_MS = 60_000;
const EMERGENCY_COMMAND_CATALOG_TIMEOUT_MS = 45_000;
/** Above emergency_command_api's own EXECUTION_DEADLINE of seventy-five seconds. */
const EMERGENCY_COMMAND_RUN_TIMEOUT_MS = 90_000;
/**
 * Longer than the sidecar's own execution deadline for a container action.
 *
 * Bound below it and a slow host turns a real receipt — which says what the
 * verification read back, and whether a restore ran — into "the request timed
 * out", which tells the operator nothing about what the host now looks like.
 */
const DOCKER_ACTION_TIMEOUT_MS = 150_000;
/** Same reasoning: longer than the sidecar deadline for a workload action. */
const KUBERNETES_ACTION_TIMEOUT_MS = 150_000;
const SFTP_BROWSER_TIMEOUT_MS = 30_000;
const SFTP_TRANSFER_TIMEOUT_MS = 190_000;
const SFTP_OPERATION_TIMEOUT_MS = 100_000;
const PACKET_CAPTURE_LIST_TIMEOUT_MS = 20_000;
const PACKET_CAPTURE_START_TIMEOUT_MS = 40_000;
const PACKET_CAPTURE_POLL_TIMEOUT_MS = 20_000;
const PACKET_CAPTURE_STOP_TIMEOUT_MS = 10_000;
const BACKEND_STOP_GRACE_MS = 3_000;

export const SYSTEM_INFO_RPC_METHODS = Object.freeze({
  catalog: "system-info.catalog.get",
  summary: "system-info.summary.get",
  collect: "system-info.table.collect",
  detail: "system-info.detail.get",
  rowActions: "system-info.row.actions.list",
  rowInspect: "system-info.row.inspect",
  rowPlan: "system-info.row.action.plan",
  rowConfirm: "system-info.row.action.confirm",
  rowExecute: "system-info.row.action.execute",
  rowCancel: "system-info.row.action.cancel",
} as const);

/** The sidecar gives a read-only row action 45 seconds; this leaves room to hear back. */
const SYSTEM_INFO_ROW_INSPECT_TIMEOUT_MS = 60_000;
/** Planning reads the row's live state from the target first. */
const SYSTEM_INFO_ROW_PLAN_TIMEOUT_MS = 45_000;
/** Execution covers the change, the journal, the verification and a restore. */
const SYSTEM_INFO_ROW_EXECUTE_TIMEOUT_MS = 130_000;

export const BASELINE_READ_RPC_METHODS = Object.freeze({
  catalog: "baseline.catalog.get",
  scan: "baseline.scan",
  listHistory: "baseline.history.list",
  readFile: "baseline.file.read",
} as const);

export const CHECK_AUDIT_READ_RPC_METHODS = Object.freeze({
  catalog: "check-audit.catalog.get",
  collectStatus: "check-audit.status.collect",
  readLog: "check-audit.log.read",
} as const);

export const LOG_ANALYSIS_READ_RPC_METHODS = Object.freeze({
  discoverSources: "log-analysis.sources.discover",
  readSource: "log-analysis.source.read",
  correlateSources: "log-analysis.sources.correlate",
  searchIocs: "log-analysis.iocs.search",
} as const);

export const KUBERNETES_READ_RPC_METHODS = Object.freeze({
  availability: "kubernetes.availability.get",
  listResources: "kubernetes.resources.list",
  resourceDetail: "kubernetes.resource.detail.get",
  podLogs: "kubernetes.pod.logs.get",
} as const);

export const KUBERNETES_WRITE_RPC_METHODS = Object.freeze({
  planAction: "kubernetes.workload.action.plan",
  confirmAction: "kubernetes.workload.action.confirm",
  executeAction: "kubernetes.workload.action.execute",
  cancelAction: "kubernetes.workload.action.cancel",
} as const);

export const DOCKER_READ_RPC_METHODS = Object.freeze({
  refreshContainers: "docker.containers.refresh",
  getCollection: "docker.collection.get",
  inspectResource: "docker.resource.inspect",
  getSecurityAudit: "docker.security.audit.get",
  getContainerLogs: "docker.container.logs.get",
} as const);

export const DOCKER_TERMINAL_RPC_METHODS = Object.freeze({
  open: "docker.container.terminal.open",
} as const);

export const DOCKER_WRITE_RPC_METHODS = Object.freeze({
  planAction: "docker.container.action.plan",
  confirmAction: "docker.container.action.confirm",
  executeAction: "docker.container.action.execute",
  cancelAction: "docker.container.action.cancel",
} as const);

export const EMERGENCY_COMMAND_RPC_METHODS = Object.freeze({
  loadCatalog: "emergency-command.catalog.load",
  run: "emergency-command.run",
  inspectPath: "emergency-command.path.inspect",
  planPath: "emergency-command.path.plan",
  confirmPath: "emergency-command.path.confirm",
  executePath: "emergency-command.path.execute",
  cancelPath: "emergency-command.path.cancel",
} as const);

export const SFTP_BROWSER_RPC_METHODS = Object.freeze({
  open: "sftp-browser.open",
  listDirectory: "sftp-browser.directory.list",
  readText: "sftp-browser.text.read",
  download: "sftp-browser.download",
  planOperation: "sftp-browser.operation.plan",
  confirmOperation: "sftp-browser.operation.confirm",
  executeOperation: "sftp-browser.operation.execute",
  cancelOperation: "sftp-browser.operation.cancel",
  stageUpload: "sftp-browser.upload.stage",
} as const);

export const PACKET_CAPTURE_LIVE_RPC_METHODS = Object.freeze({
  listInterfaces: "packet-capture.interfaces.list",
  start: "packet-capture.start",
  poll: "packet-capture.poll",
  stop: "packet-capture.stop",
} as const);

export const APPLICATION_LOG_RPC_METHODS = Object.freeze({
  list: "application-log.list",
  setLevel: "application-log.level.set",
  clearBuffer: "application-log.buffer.clear",
  preview: "application-log.preview.get",
  prepareExport: "application-log.export.prepare",
} as const);

export const INTEGRITY_RPC_METHODS = Object.freeze({
  presets: "integrity.presets.get",
  listBaselines: "integrity.baselines.list",
  startComparison: "integrity.comparison.start",
  pollComparison: "integrity.comparison.poll",
  cancelComparison: "integrity.comparison.cancel",
} as const);

export const SETTINGS_RPC_METHODS = Object.freeze({
  get: "settings.get",
  save: "settings.save",
  replaceAiApiKey: "settings.ai-api-key.replace",
  planAiApiKeyClear: "settings.ai-api-key.clear.plan",
  planAiProviderRemoval: "settings.ai-provider.remove.plan",
  confirmMutation: "settings.mutation.confirm",
  cancelMutation: "settings.mutation.cancel",
} as const);

export const AI_HISTORY_RPC_METHODS = Object.freeze({
  list: "ai-history.list",
  get: "ai-history.get",
  planRemove: "ai-history.remove.plan",
  planClear: "ai-history.clear.plan",
  confirm: "ai-history.mutation.confirm",
  cancel: "ai-history.mutation.cancel",
  export: "ai-history.export",
} as const);

export const COMMAND_HISTORY_RPC_METHODS = Object.freeze({
  list: "command-history.list",
  get: "command-history.get",
  planReplay: "command-history.replay.plan",
  planRemove: "command-history.remove.plan",
  planClear: "command-history.clear.plan",
  confirm: "command-history.mutation.confirm",
  cancel: "command-history.mutation.cancel",
} as const);

export const DISPOSAL_REPORT_RPC_METHODS = Object.freeze({
  generate: "disposal-report.generate",
  content: "disposal-report.content.get",
  export: "disposal-report.export",
} as const);

export const TERMINAL_RPC_METHODS = Object.freeze({
  open: "terminal.open",
  poll: "terminal.poll",
  input: "terminal.input",
  resize: "terminal.resize",
  renderSnapshot: "terminal.render-snapshot",
  search: "terminal.search",
  close: "terminal.close",
} as const);

export interface StoppableChildProcess {
  readonly stdin: { end(): void };
  readonly exitCode: number | null;
  readonly signalCode: NodeJS.Signals | null;
  once(
    event: "exit",
    listener: (code: number | null, signal: NodeJS.Signals | null) => void,
  ): this;
  removeListener(
    event: "exit",
    listener: (code: number | null, signal: NodeJS.Signals | null) => void,
  ): this;
  kill(signal?: NodeJS.Signals | number): boolean;
}

export function stopChildProcess(
  child: StoppableChildProcess,
  forceAfterMs = BACKEND_STOP_GRACE_MS,
): Promise<void> {
  return new Promise((resolve) => {
    let forceTimer: NodeJS.Timeout | null = null;
    const onExit = () => {
      if (forceTimer !== null) clearTimeout(forceTimer);
      child.removeListener("exit", onExit);
      resolve();
    };

    child.once("exit", onExit);
    if (child.exitCode !== null || child.signalCode !== null) {
      onExit();
      return;
    }
    forceTimer = setTimeout(() => {
      child.kill("SIGKILL");
    }, forceAfterMs);
    child.stdin.end();
  });
}

interface PendingRequest {
  resolve(value: unknown): void;
  reject(error: Error): void;
  timeout: NodeJS.Timeout;
}

interface RpcResponse {
  protocol: string;
  requestId: string | null;
  ok: boolean;
  result?: unknown;
  error?: {
    code: string;
    message: string;
  };
}

/**
 * Namespaces whose methods run a command on the target. Anything else is local
 * work — reading a note, saving a setting — and answers in milliseconds.
 */
const REMOTE_NAMESPACES: ReadonlySet<string> = new Set([
  "baseline", "check-audit", "docker", "emergency-command", "firewall",
  "integrity", "kubernetes", "log-analysis", "middleware", "packet-capture",
  "sftp-browser", "snapshot", "system-info",
]);

/**
 * A method that reaches the target gets the longer bound unless its caller
 * passes one of its own. The SSH namespace is deliberately absent: connecting
 * is a poll loop of short calls, and the attempt carries its own deadline.
 */
/** A row is named by two opaque handles and a bounded, non-empty row id. */
function isSystemInfoRowRequest(
  bindingHandle: string,
  snapshotHandle: string,
  rowId: string,
): boolean {
  return (
    isSshOpaqueHandle(bindingHandle) &&
    isSystemInfoOpaqueHandle(snapshotHandle) &&
    typeof rowId === "string" &&
    rowId.trim().length > 0 &&
    Buffer.byteLength(rowId, "utf8") <= 256
  );
}

function defaultTimeoutFor(method: string): number {
  const namespace = method.split(".")[0] ?? "";
  return REMOTE_NAMESPACES.has(namespace) ? REMOTE_REQUEST_TIMEOUT_MS : REQUEST_TIMEOUT_MS;
}

export class BackendClient {
  readonly #backendPath: string;
  readonly #archiveRoot: string;
  readonly #pending = new Map<string, PendingRequest>();
  #process: ChildProcessWithoutNullStreams | null = null;
  #stdoutBuffer = "";
  #stopping = false;
  #stopPromise: Promise<void> | null = null;

  constructor(backendPath: string, archiveRoot: string) {
    this.#backendPath = backendPath;
    this.#archiveRoot = archiveRoot;
  }

  start(): void {
    if (this.#process !== null) return;
    this.#stopping = false;
    const child = spawn(this.#backendPath, ["--archive-root", this.#archiveRoot], {
      env: process.env,
      shell: false,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    this.#process = child;
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => this.#consumeStdout(chunk));
    child.stderr.on("data", (chunk: string) => process.stderr.write(`[backend] ${chunk}`));
    child.on("error", (error) => this.#failAll(error));
    child.on("exit", (code, signal) => {
      this.#process = null;
      if (!this.#stopping) {
        this.#failAll(
          new Error(`LovelyRes backend exited unexpectedly (${code ?? "no-code"}/${signal ?? "no-signal"}).`),
        );
      }
    });
  }

  async stop(): Promise<void> {
    if (this.#stopPromise !== null) return this.#stopPromise;
    const child = this.#process;
    if (child === null) return;
    this.#stopping = true;
    this.#failAll(new Error("LovelyRes backend is stopping."));
    const stopPromise = stopChildProcess(child).finally(() => {
      if (this.#process === child) this.#process = null;
      if (this.#stopPromise === stopPromise) this.#stopPromise = null;
    });
    this.#stopPromise = stopPromise;
    await stopPromise;
  }

  async bootstrap(): Promise<BootstrapResult> {
    const value = await this.#request("app.bootstrap", {});
    if (!isBootstrapResult(value)) throw new Error("The backend returned an invalid bootstrap payload.");
    return value;
  }

  async listConnections(): Promise<ConnectionSummary[]> {
    const value = await this.#request("connections.list", {});
    if (!isConnectionSummaryArray(value)) {
      throw new Error("The backend returned an invalid connection list.");
    }
    return value;
  }

  async getConnection(id: string): Promise<ConnectionEditView> {
    const value = await this.#request("connections.get", { id });
    if (!isConnectionEditView(value)) {
      throw new Error("The backend returned an invalid connection.");
    }
    return value;
  }

  async createConnection(input: ConnectionWriteInput): Promise<ConnectionEditView> {
    const value = await this.#request("connections.create", input);
    if (!isConnectionEditView(value)) {
      throw new Error("The backend returned an invalid created connection.");
    }
    return value;
  }

  async updateConnection(input: ConnectionWriteInput): Promise<ConnectionEditView> {
    const value = await this.#request("connections.update", input);
    if (!isConnectionEditView(value)) {
      throw new Error("The backend returned an invalid updated connection.");
    }
    return value;
  }

  async planConnectionDelete(id: string): Promise<ConnectionDeletePrompt> {
    const value = await this.#request("connections.delete.plan", { id });
    if (!isConnectionDeletePrompt(value)) {
      throw new Error("The backend returned an invalid connection delete plan.");
    }
    return value;
  }

  async confirmConnectionDelete(handle: string): Promise<ConnectionDeleteResult> {
    const value = await this.#request("connections.delete.confirm", { handle });
    if (!isConnectionDeleteResult(value)) {
      throw new Error("The backend returned an invalid connection delete outcome.");
    }
    return value;
  }

  async cancelConnectionDelete(handle: string): Promise<ConnectionDeleteCancellation> {
    const value = await this.#request("connections.delete.cancel", { handle });
    if (!isConnectionDeleteCancellation(value)) {
      throw new Error("The backend returned an invalid connection delete cancellation.");
    }
    return value;
  }

  async importConnectionsFile(filePath: string): Promise<InternalConnectionImportResult> {
    const value = await this.#request("connections.import-file", { path: filePath });
    if (!isInternalConnectionImportResult(value)) {
      throw new Error("The backend returned an invalid connection import outcome.");
    }
    return value;
  }

  async exportConnectionsFile(filePath: string): Promise<InternalConnectionExportResult> {
    const value = await this.#request("connections.export-file", { path: filePath });
    if (!isInternalConnectionExportResult(value)) {
      throw new Error("The backend returned an invalid connection export outcome.");
    }
    return value;
  }

  async startSshConnect(connectionId: string): Promise<SshAttemptStarted> {
    const value = await this.#request("ssh.connect.start", { connectionId });
    if (!isSshAttemptStarted(value)) {
      throw new Error("The backend returned an invalid SSH connect attempt.");
    }
    return value;
  }

  async startSshProbe(input: ConnectionWriteInput): Promise<SshAttemptStarted> {
    const value = await this.#request("ssh.probe.start", input);
    if (!isSshAttemptStarted(value)) {
      throw new Error("The backend returned an invalid SSH probe attempt.");
    }
    return value;
  }

  async getSshAttempt(attemptHandle: string): Promise<SshAttemptStatus> {
    const value = await this.#request("ssh.attempt.get", { attemptHandle });
    if (!isSshAttemptStatus(value)) {
      throw new Error("The backend returned an invalid SSH attempt status.");
    }
    return value;
  }

  async confirmSshHostKey(
    attemptHandle: string,
    promptHandle: string,
  ): Promise<SshAttemptStatus> {
    const value = await this.#request("ssh.host-key.confirm", {
      attemptHandle,
      promptHandle,
    });
    if (!isSshAttemptStatus(value)) {
      throw new Error("The backend returned an invalid SSH host-key outcome.");
    }
    return value;
  }

  async respondSshMfa(
    attemptHandle: string,
    promptHandle: string,
    responses: string[],
  ): Promise<SshAttemptStatus> {
    const value = await this.#request("ssh.mfa.respond", {
      attemptHandle,
      promptHandle,
      responses,
    });
    if (!isSshAttemptStatus(value)) {
      throw new Error("The backend returned an invalid SSH MFA outcome.");
    }
    return value;
  }

  async cancelSshAttempt(attemptHandle: string): Promise<SshAttemptCancellation> {
    const value = await this.#request("ssh.attempt.cancel", { attemptHandle });
    if (!isSshAttemptCancellation(value)) {
      throw new Error("The backend returned an invalid SSH attempt cancellation.");
    }
    return value;
  }

  async disconnectSshBinding(bindingHandle: string): Promise<SshBindingDisconnection> {
    const value = await this.#request("ssh.binding.disconnect", { bindingHandle });
    if (!isSshBindingDisconnection(value)) {
      throw new Error("The backend returned an invalid SSH binding disconnection.");
    }
    return value;
  }

  async openTerminal(
    bindingHandle: string,
    columns: number,
    rows: number,
  ): Promise<TerminalOpened> {
    if (!isTerminalBindingHandle(bindingHandle) || !isTerminalSize(columns, rows)) {
      throw new Error("The terminal open request is invalid.");
    }
    const value = await this.#request(TERMINAL_RPC_METHODS.open, {
      bindingHandle,
      columns,
      rows,
    });
    if (!isTerminalOpened(value) || value.columns !== columns || value.rows !== rows) {
      throw new Error("The backend returned an invalid terminal open response.");
    }
    return value;
  }

  async pollTerminal(
    handle: string,
    maximumEvents: number,
    maximumBytes: number,
  ): Promise<TerminalPoll> {
    if (!isTerminalHandle(handle) || !isTerminalPollBounds(maximumEvents, maximumBytes)) {
      throw new Error("The terminal poll request is invalid.");
    }
    const value = await this.#request(TERMINAL_RPC_METHODS.poll, {
      handle,
      maximumEvents,
      maximumBytes,
    });
    if (!isTerminalPoll(value)) {
      throw new Error("The backend returned an invalid terminal poll response.");
    }
    return value;
  }

  async inputTerminal(
    handle: string,
    bytesBase64: string,
  ): Promise<TerminalInputAcknowledgement> {
    if (
      !isTerminalHandle(handle) ||
      terminalBase64DecodedLength(bytesBase64, TERMINAL_LIMITS.maximumInputBytes, false) === null
    ) {
      throw new Error("The terminal input request is invalid.");
    }
    const value = await this.#request(TERMINAL_RPC_METHODS.input, { handle, bytesBase64 });
    if (!isTerminalInputAcknowledgement(value)) {
      throw new Error("The backend returned an invalid terminal input response.");
    }
    return value;
  }

  async resizeTerminal(
    handle: string,
    columns: number,
    rows: number,
  ): Promise<TerminalResized> {
    if (!isTerminalHandle(handle) || !isTerminalSize(columns, rows)) {
      throw new Error("The terminal resize request is invalid.");
    }
    const value = await this.#request(TERMINAL_RPC_METHODS.resize, {
      handle,
      columns,
      rows,
    });
    if (!isTerminalResized(value) || value.columns !== columns || value.rows !== rows) {
      throw new Error("The backend returned an invalid terminal resize response.");
    }
    return value;
  }

  async renderTerminalSnapshot(handle: string): Promise<TerminalRenderSnapshot> {
    if (!isTerminalHandle(handle)) throw new Error("The terminal snapshot request is invalid.");
    const value = await this.#request(TERMINAL_RPC_METHODS.renderSnapshot, { handle });
    if (!isTerminalRenderSnapshot(value)) {
      throw new Error("The backend returned an invalid terminal snapshot response.");
    }
    return value;
  }

  async searchTerminal(
    handle: string,
    query: string,
    caseSensitive: boolean,
    regex: boolean,
    maximumResults: number,
  ): Promise<TerminalSearch> {
    if (
      !isTerminalHandle(handle) ||
      !isTerminalSearchRequest(query, maximumResults) ||
      typeof caseSensitive !== "boolean" ||
      typeof regex !== "boolean"
    ) {
      throw new Error("The terminal search request is invalid.");
    }
    const value = await this.#request(TERMINAL_RPC_METHODS.search, {
      handle,
      query,
      caseSensitive,
      regex,
      maximumResults,
    });
    if (!isTerminalSearch(value)) {
      throw new Error("The backend returned an invalid terminal search response.");
    }
    return value;
  }

  async closeTerminal(handle: string): Promise<TerminalClosed> {
    if (!isTerminalHandle(handle)) throw new Error("The terminal close request is invalid.");
    const value = await this.#request(TERMINAL_RPC_METHODS.close, { handle });
    if (!isTerminalClosed(value)) {
      throw new Error("The backend returned an invalid terminal close response.");
    }
    return value;
  }

  async getSystemInfoCatalog(): Promise<SystemInfoTabCatalogEntry[]> {
    const value = await this.#request(SYSTEM_INFO_RPC_METHODS.catalog, {});
    if (!isSystemInfoCatalog(value)) {
      throw new Error("The backend returned an invalid system-information catalog.");
    }
    return value;
  }

  async getSystemInfoSummary(bindingHandle: string): Promise<SystemInfoSummary> {
    const value = await this.#request(SYSTEM_INFO_RPC_METHODS.summary, { bindingHandle });
    if (!isSystemInfoSummary(value)) {
      throw new Error("The backend returned an invalid system-information summary.");
    }
    return value;
  }

  async collectSystemInfo(
    bindingHandle: string,
    tab: SystemInfoTabKey,
    maximumRows: number,
  ): Promise<SystemInfoTable> {
    const value = await this.#request(SYSTEM_INFO_RPC_METHODS.collect, {
      bindingHandle,
      tab,
      maximumRows,
    });
    if (!isSystemInfoTable(value)) {
      throw new Error("The backend returned an invalid system-information table.");
    }
    return value;
  }

  async getSystemInfoDetail(
    bindingHandle: string,
    snapshotHandle: string,
    rowId: string,
  ): Promise<SystemInfoDetail> {
    const value = await this.#request(SYSTEM_INFO_RPC_METHODS.detail, {
      bindingHandle,
      snapshotHandle,
      rowId,
    });
    if (!isSystemInfoDetail(value)) {
      throw new Error("The backend returned invalid system-information detail.");
    }
    return value;
  }

  async listSystemInfoRowActions(
    bindingHandle: string,
    snapshotHandle: string,
    rowId: string,
  ): Promise<SystemInfoRowActions> {
    if (!isSystemInfoRowRequest(bindingHandle, snapshotHandle, rowId)) {
      throw new Error("The system-information row request is invalid.");
    }
    const value = await this.#request(SYSTEM_INFO_RPC_METHODS.rowActions, {
      bindingHandle,
      snapshotHandle,
      rowId,
    });
    if (!isSystemInfoRowActions(value) || value.rowId !== rowId) {
      throw new Error("The backend returned invalid system-information row actions.");
    }
    return value;
  }

  async inspectSystemInfoRow(
    bindingHandle: string,
    snapshotHandle: string,
    rowId: string,
    action: string,
  ): Promise<SystemInfoRowInspection> {
    if (
      !isSystemInfoRowRequest(bindingHandle, snapshotHandle, rowId) ||
      !isSystemInfoRowActionKey(action)
    ) {
      throw new Error("The system-information row inspection request is invalid.");
    }
    const value = await this.#request(SYSTEM_INFO_RPC_METHODS.rowInspect, {
      bindingHandle,
      snapshotHandle,
      rowId,
      action,
    }, SYSTEM_INFO_ROW_INSPECT_TIMEOUT_MS);
    if (!isSystemInfoRowInspection(value) || value.rowId !== rowId || value.action !== action) {
      throw new Error("The backend returned an invalid system-information row inspection.");
    }
    return value;
  }

  async planSystemInfoRowAction(
    bindingHandle: string,
    snapshotHandle: string,
    rowId: string,
    action: string,
  ): Promise<SystemInfoRowPlan> {
    if (
      !isSystemInfoRowRequest(bindingHandle, snapshotHandle, rowId) ||
      !isSystemInfoRowActionKey(action)
    ) {
      throw new Error("The system-information row plan request is invalid.");
    }
    const value = await this.#request(SYSTEM_INFO_RPC_METHODS.rowPlan, {
      bindingHandle,
      snapshotHandle,
      rowId,
      action,
    }, SYSTEM_INFO_ROW_PLAN_TIMEOUT_MS);
    if (!isSystemInfoRowPlan(value) || value.rowId !== rowId || value.action !== action) {
      throw new Error("The backend returned an invalid system-information row plan.");
    }
    return value;
  }

  async confirmSystemInfoRowAction(
    bindingHandle: string,
    planHandle: string,
  ): Promise<SystemInfoRowPlan> {
    if (!isSshOpaqueHandle(bindingHandle) || !isSystemInfoOpaqueHandle(planHandle)) {
      throw new Error("The system-information row confirmation is invalid.");
    }
    const value = await this.#request(SYSTEM_INFO_RPC_METHODS.rowConfirm, {
      bindingHandle,
      planHandle,
    });
    if (!isSystemInfoRowPlan(value) || value.planHandle !== planHandle || !value.confirmed) {
      throw new Error("The backend returned an invalid system-information row plan.");
    }
    return value;
  }

  async executeSystemInfoRowAction(
    bindingHandle: string,
    planHandle: string,
  ): Promise<SystemInfoRowReceipt> {
    if (!isSshOpaqueHandle(bindingHandle) || !isSystemInfoOpaqueHandle(planHandle)) {
      throw new Error("The system-information row execution request is invalid.");
    }
    const value = await this.#request(SYSTEM_INFO_RPC_METHODS.rowExecute, {
      bindingHandle,
      planHandle,
    }, SYSTEM_INFO_ROW_EXECUTE_TIMEOUT_MS);
    if (!isSystemInfoRowReceipt(value) || value.planHandle !== planHandle) {
      throw new Error("The backend returned an invalid system-information row receipt.");
    }
    return value;
  }

  async cancelSystemInfoRowAction(bindingHandle: string, planHandle: string): Promise<void> {
    if (!isSshOpaqueHandle(bindingHandle) || !isSystemInfoOpaqueHandle(planHandle)) {
      throw new Error("The system-information row cancellation is invalid.");
    }
    await this.#request(SYSTEM_INFO_RPC_METHODS.rowCancel, { bindingHandle, planHandle });
  }

  async getBaselineCatalog(): Promise<BaselineCatalog> {
    const value = await this.#request(BASELINE_READ_RPC_METHODS.catalog, {});
    if (!isBaselineCatalog(value)) {
      throw new Error("The backend returned an invalid baseline catalog.");
    }
    return value;
  }

  async scanBaseline(bindingHandle: string): Promise<BaselineScan> {
    if (!isBaselineOpaqueHandle(bindingHandle)) {
      throw new Error("The baseline binding is invalid.");
    }
    const value = await this.#request(BASELINE_READ_RPC_METHODS.scan, { bindingHandle });
    if (!isBaselineScan(value)) {
      throw new Error("The backend returned an invalid baseline scan.");
    }
    return value;
  }

  async listBaselineHistory(bindingHandle: string): Promise<BaselineHistory> {
    if (!isBaselineOpaqueHandle(bindingHandle)) {
      throw new Error("The baseline binding is invalid.");
    }
    const value = await this.#request(BASELINE_READ_RPC_METHODS.listHistory, { bindingHandle });
    if (!isBaselineHistory(value)) {
      throw new Error("The backend returned invalid baseline history.");
    }
    return value;
  }

  async readBaselineFile(bindingHandle: string, itemHandle: string): Promise<BaselineFile> {
    if (![bindingHandle, itemHandle].every(isBaselineOpaqueHandle)) {
      throw new Error("The baseline file request is invalid.");
    }
    const value = await this.#request(BASELINE_READ_RPC_METHODS.readFile, {
      bindingHandle,
      itemHandle,
    });
    if (!isBaselineFile(value) || value.itemHandle !== itemHandle) {
      throw new Error("The backend returned an invalid baseline file.");
    }
    return value;
  }

  async getCheckAuditCatalog(
    bindingHandle: string,
    input: CheckAuditCatalogInput,
  ): Promise<CheckAuditCatalog> {
    if (!isCheckAuditOpaqueHandle(bindingHandle) || !isCheckAuditCatalogInput(input)) {
      throw new Error("The command-audit catalog request is invalid.");
    }
    const value = await this.#request(CHECK_AUDIT_READ_RPC_METHODS.catalog, {
      bindingHandle,
      input,
    });
    if (!isCheckAuditCatalog(value) || value.customCount !== input.customCommandNames.length) {
      throw new Error("The backend returned an invalid command-audit catalog.");
    }
    const returnedCustomNames = value.commands.slice(value.commands.length - value.customCount)
      .map((command) => command.name);
    const requestedCustomNames = [...input.customCommandNames].sort();
    if (returnedCustomNames.some((name, index) => name !== requestedCustomNames[index])) {
      throw new Error("The backend returned a mismatched command-audit catalog.");
    }
    return value;
  }

  async collectCheckAuditStatus(
    bindingHandle: string,
    snapshotHandle: string,
  ): Promise<CheckAuditStatus> {
    if (![bindingHandle, snapshotHandle].every(isCheckAuditOpaqueHandle)) {
      throw new Error("The command-audit status request is invalid.");
    }
    const value = await this.#request(CHECK_AUDIT_READ_RPC_METHODS.collectStatus, {
      bindingHandle,
      snapshotHandle,
    });
    if (!isCheckAuditStatus(value) || value.snapshotHandle !== snapshotHandle) {
      throw new Error("The backend returned invalid command-audit status.");
    }
    return value;
  }

  async readCheckAuditLog(
    bindingHandle: string,
    snapshotHandle: string,
    input: CheckAuditLogInput,
  ): Promise<CheckAuditLogResult> {
    if (
      !isCheckAuditOpaqueHandle(bindingHandle) ||
      !isCheckAuditOpaqueHandle(snapshotHandle) ||
      !isCheckAuditLogInput(input)
    ) {
      throw new Error("The command-audit log request is invalid.");
    }
    const value = await this.#request(CHECK_AUDIT_READ_RPC_METHODS.readLog, {
      bindingHandle,
      snapshotHandle,
      input,
    });
    if (
      !isCheckAuditLogResult(value) ||
      value.snapshotHandle !== snapshotHandle ||
      value.limit !== input.limit
    ) {
      throw new Error("The backend returned an invalid command-audit log.");
    }
    return value;
  }

  async discoverLogSources(bindingHandle: string): Promise<LogSourceSnapshot> {
    if (!isLogAnalysisOpaqueHandle(bindingHandle)) {
      throw new Error("The log investigation binding is invalid.");
    }
    const value = await this.#request(LOG_ANALYSIS_READ_RPC_METHODS.discoverSources, {
      bindingHandle,
    });
    if (!isLogSourceSnapshot(value)) {
      throw new Error("The backend returned invalid log source discovery.");
    }
    return value;
  }

  async readLogSource(
    bindingHandle: string,
    snapshotHandle: string,
    sourceHandle: string,
    input: LogSourceReadInput,
  ): Promise<LogSourceReadResult> {
    if (
      ![bindingHandle, snapshotHandle, sourceHandle].every(isLogAnalysisOpaqueHandle) ||
      !isLogSourceReadInput(input)
    ) {
      throw new Error("The log source read request is invalid.");
    }
    const value = await this.#request(LOG_ANALYSIS_READ_RPC_METHODS.readSource, {
      bindingHandle,
      snapshotHandle,
      sourceHandle,
      input,
    });
    if (
      !isLogSourceReadResult(value) ||
      value.snapshotHandle !== snapshotHandle ||
      value.sourceHandle !== sourceHandle ||
      value.page !== input.page ||
      value.pageSize !== input.pageSize
    ) {
      throw new Error("The backend returned an invalid log source page.");
    }
    return value;
  }

  async correlateLogSources(
    bindingHandle: string,
    snapshotHandle: string,
    input: LogCorrelationInput,
  ): Promise<LogCorrelationResult> {
    if (
      ![bindingHandle, snapshotHandle].every(isLogAnalysisOpaqueHandle) ||
      !isLogCorrelationInput(input)
    ) {
      throw new Error("The log correlation request is invalid.");
    }
    const value = await this.#request(LOG_ANALYSIS_READ_RPC_METHODS.correlateSources, {
      bindingHandle,
      snapshotHandle,
      input,
    });
    if (
      !isLogCorrelationResult(value) ||
      value.snapshotHandle !== snapshotHandle ||
      value.sourceHandles.length !== input.sourceHandles.length ||
      value.sourceHandles.some((handle, index) => handle !== input.sourceHandles[index])
    ) {
      throw new Error("The backend returned invalid log correlation.");
    }
    return value;
  }

  async searchLogIocs(
    bindingHandle: string,
    snapshotHandle: string,
    input: LogIocSearchInput,
  ): Promise<LogIocSearchResult> {
    if (
      ![bindingHandle, snapshotHandle].every(isLogAnalysisOpaqueHandle) ||
      !isLogIocSearchInput(input)
    ) {
      throw new Error("The log IOC search request is invalid.");
    }
    const value = await this.#request(LOG_ANALYSIS_READ_RPC_METHODS.searchIocs, {
      bindingHandle,
      snapshotHandle,
      input,
    });
    if (
      !isLogIocSearchResult(value) ||
      value.snapshotHandle !== snapshotHandle ||
      value.results.some((result) =>
        !input.sourceHandles.includes(result.sourceHandle) ||
        !input.indicators.includes(result.indicator))
    ) {
      throw new Error("The backend returned invalid log IOC search results.");
    }
    return value;
  }

  async getKubernetesAvailability(bindingHandle: string): Promise<KubernetesAvailability> {
    if (!isKubernetesOpaqueHandle(bindingHandle)) {
      throw new Error("The Kubernetes availability request is invalid.");
    }
    const value = await this.#request(KUBERNETES_READ_RPC_METHODS.availability, {
      bindingHandle,
    });
    if (!isKubernetesAvailability(value)) {
      throw new Error("The backend returned invalid Kubernetes availability.");
    }
    return value;
  }

  async listKubernetesResources(
    bindingHandle: string,
    input: KubernetesListInput,
  ): Promise<KubernetesSnapshot> {
    if (!isKubernetesOpaqueHandle(bindingHandle) || !isKubernetesListInput(input)) {
      throw new Error("The Kubernetes resource list request is invalid.");
    }
    const value = await this.#request(KUBERNETES_READ_RPC_METHODS.listResources, {
      bindingHandle,
      input,
    });
    if (
      !isKubernetesSnapshot(value) ||
      value.tab !== input.tab ||
      value.namespaceScoped !== (input.namespaceScope !== null)
    ) {
      throw new Error("The backend returned an invalid Kubernetes resource snapshot.");
    }
    return value;
  }

  async getKubernetesResourceDetail(
    bindingHandle: string,
    snapshotHandle: string,
    rowHandle: string,
  ): Promise<KubernetesTextResult> {
    if (![bindingHandle, snapshotHandle, rowHandle].every(isKubernetesOpaqueHandle)) {
      throw new Error("The Kubernetes resource detail request is invalid.");
    }
    const value = await this.#request(KUBERNETES_READ_RPC_METHODS.resourceDetail, {
      bindingHandle,
      snapshotHandle,
      rowHandle,
    });
    if (
      !isKubernetesTextResult(value) ||
      value.snapshotHandle !== snapshotHandle ||
      value.rowHandle !== rowHandle ||
      value.contentKind !== "detail"
    ) {
      throw new Error("The backend returned invalid Kubernetes resource detail.");
    }
    return value;
  }

  async getKubernetesPodLogs(
    bindingHandle: string,
    snapshotHandle: string,
    rowHandle: string,
  ): Promise<KubernetesTextResult> {
    if (![bindingHandle, snapshotHandle, rowHandle].every(isKubernetesOpaqueHandle)) {
      throw new Error("The Kubernetes Pod log request is invalid.");
    }
    const value = await this.#request(KUBERNETES_READ_RPC_METHODS.podLogs, {
      bindingHandle,
      snapshotHandle,
      rowHandle,
    });
    if (
      !isKubernetesTextResult(value) ||
      value.snapshotHandle !== snapshotHandle ||
      value.rowHandle !== rowHandle ||
      value.contentKind !== "pod-logs"
    ) {
      throw new Error("The backend returned invalid Kubernetes Pod logs.");
    }
    return value;
  }

  async planKubernetesWorkloadAction(
    bindingHandle: string,
    snapshotHandle: string,
    rowHandle: string,
    resourceName: string,
    action: KubernetesWriteAction,
  ): Promise<KubernetesActionPlan> {
    if (
      ![bindingHandle, snapshotHandle, rowHandle].every(isKubernetesOpaqueHandle) ||
      !isKubernetesResourceName(resourceName) ||
      !isKubernetesWriteAction(action)
    ) {
      throw new Error("The Kubernetes workload action plan request is invalid.");
    }
    const value = await this.#request(KUBERNETES_WRITE_RPC_METHODS.planAction, {
      bindingHandle,
      snapshotHandle,
      rowHandle,
      resourceName,
      action,
    });
    // The plan has to be for the workload and action that were asked for. One
    // that came back describing something else is one the operator would be
    // approving without having chosen it.
    if (
      !isKubernetesActionPlan(value) ||
      value.rowHandle !== rowHandle ||
      value.action !== action.kind ||
      value.confirmed
    ) {
      throw new Error("The backend returned an invalid Kubernetes workload action plan.");
    }
    return value;
  }

  async confirmKubernetesWorkloadAction(
    bindingHandle: string,
    planHandle: string,
  ): Promise<KubernetesActionPlan> {
    if (![bindingHandle, planHandle].every(isKubernetesOpaqueHandle)) {
      throw new Error("The Kubernetes workload action confirmation is invalid.");
    }
    const value = await this.#request(KUBERNETES_WRITE_RPC_METHODS.confirmAction, {
      bindingHandle,
      planHandle,
    });
    if (!isKubernetesActionPlan(value) || value.planHandle !== planHandle || !value.confirmed) {
      throw new Error("The backend returned an invalid Kubernetes workload action confirmation.");
    }
    return value;
  }

  async executeKubernetesWorkloadAction(
    bindingHandle: string,
    planHandle: string,
  ): Promise<KubernetesActionReceipt> {
    if (![bindingHandle, planHandle].every(isKubernetesOpaqueHandle)) {
      throw new Error("The Kubernetes workload action request is invalid.");
    }
    const value = await this.#request(
      KUBERNETES_WRITE_RPC_METHODS.executeAction,
      { bindingHandle, planHandle },
      KUBERNETES_ACTION_TIMEOUT_MS,
    );
    if (!isKubernetesActionReceipt(value) || value.planHandle !== planHandle) {
      throw new Error("The backend returned an invalid Kubernetes workload action receipt.");
    }
    return value;
  }

  async cancelKubernetesWorkloadAction(
    bindingHandle: string,
    planHandle: string,
  ): Promise<KubernetesActionCancellation> {
    if (![bindingHandle, planHandle].every(isKubernetesOpaqueHandle)) {
      throw new Error("The Kubernetes workload action cancellation is invalid.");
    }
    const value = await this.#request(KUBERNETES_WRITE_RPC_METHODS.cancelAction, {
      bindingHandle,
      planHandle,
    });
    if (!isKubernetesActionCancellation(value)) {
      throw new Error("The backend returned an invalid Kubernetes workload action cancellation.");
    }
    return value;
  }

  async refreshDockerContainers(bindingHandle: string): Promise<DockerContainerSnapshot> {
    if (!isDockerOpaqueHandle(bindingHandle)) {
      throw new Error("The Docker container refresh request is invalid.");
    }
    const value = await this.#request(DOCKER_READ_RPC_METHODS.refreshContainers, {
      bindingHandle,
    });
    if (!isDockerContainerSnapshot(value)) {
      throw new Error("The backend returned an invalid Docker container snapshot.");
    }
    return value;
  }

  async getDockerCollection(
    bindingHandle: string,
    snapshotHandle: string,
    kind: DockerCollectionKind,
  ): Promise<DockerReadCollection> {
    if (
      !isDockerOpaqueHandle(bindingHandle) ||
      !isDockerOpaqueHandle(snapshotHandle) ||
      !isDockerCollectionKind(kind)
    ) {
      throw new Error("The Docker collection request is invalid.");
    }
    const value = await this.#request(DOCKER_READ_RPC_METHODS.getCollection, {
      bindingHandle,
      snapshotHandle,
      kind,
    });
    if (
      !isDockerReadCollection(value) ||
      value.snapshotHandle !== snapshotHandle ||
      value.kind !== kind
    ) {
      throw new Error("The backend returned an invalid Docker collection.");
    }
    return value;
  }

  async inspectDockerResource(
    bindingHandle: string,
    snapshotHandle: string,
    kind: DockerResourceKind,
    resourceHandle: string,
  ): Promise<DockerReadInspection> {
    if (
      !isDockerOpaqueHandle(bindingHandle) ||
      !isDockerOpaqueHandle(snapshotHandle) ||
      !isDockerResourceKind(kind) ||
      !isDockerOpaqueHandle(resourceHandle)
    ) {
      throw new Error("The Docker resource inspection request is invalid.");
    }
    const value = await this.#request(DOCKER_READ_RPC_METHODS.inspectResource, {
      bindingHandle,
      snapshotHandle,
      kind,
      resourceHandle,
    });
    if (
      !isDockerReadInspection(value) ||
      value.snapshotHandle !== snapshotHandle ||
      value.resourceHandle !== resourceHandle ||
      value.kind !== kind
    ) {
      throw new Error("The backend returned an invalid Docker resource inspection.");
    }
    return value;
  }

  async getDockerSecurityAudit(
    bindingHandle: string,
    snapshotHandle: string,
  ): Promise<DockerSecurityAudit> {
    if (![bindingHandle, snapshotHandle].every(isDockerOpaqueHandle)) {
      throw new Error("The Docker security audit request is invalid.");
    }
    const value = await this.#request(DOCKER_READ_RPC_METHODS.getSecurityAudit, {
      bindingHandle,
      snapshotHandle,
    });
    if (!isDockerSecurityAudit(value) || value.snapshotHandle !== snapshotHandle) {
      throw new Error("The backend returned an invalid Docker security audit.");
    }
    return value;
  }

  async getDockerLogs(
    bindingHandle: string,
    snapshotHandle: string,
    containerHandle: string,
    tail: number,
  ): Promise<DockerLogs> {
    if (
      ![bindingHandle, snapshotHandle, containerHandle].every(isDockerOpaqueHandle) ||
      !isDockerLogTail(tail)
    ) {
      throw new Error("The Docker container log request is invalid.");
    }
    const value = await this.#request(DOCKER_READ_RPC_METHODS.getContainerLogs, {
      bindingHandle,
      snapshotHandle,
      containerHandle,
      tail,
    });
    if (
      !isDockerLogs(value) ||
      value.snapshotHandle !== snapshotHandle ||
      value.containerHandle !== containerHandle ||
      value.tail !== tail
    ) {
      throw new Error("The backend returned invalid Docker container logs.");
    }
    return value;
  }

  async planDockerContainerAction(
    bindingHandle: string,
    snapshotHandle: string,
    containerHandle: string,
    containerName: string,
    action: DockerWriteAction,
  ): Promise<DockerActionPlan> {
    if (
      ![bindingHandle, snapshotHandle, containerHandle].every(isDockerOpaqueHandle) ||
      !isDockerContainerName(containerName) ||
      !isDockerWriteAction(action)
    ) {
      throw new Error("The Docker container action plan request is invalid.");
    }
    const value = await this.#request(DOCKER_WRITE_RPC_METHODS.planAction, {
      bindingHandle,
      snapshotHandle,
      containerHandle,
      containerName,
      action,
    });
    // The plan has to be for the container and action that were asked for.
    // A plan that came back describing something else is one the operator
    // would be approving without having chosen it.
    if (
      !isDockerActionPlan(value) ||
      value.containerHandle !== containerHandle ||
      value.action !== action ||
      value.confirmed
    ) {
      throw new Error("The backend returned an invalid Docker container action plan.");
    }
    return value;
  }

  async confirmDockerContainerAction(
    bindingHandle: string,
    planHandle: string,
  ): Promise<DockerActionPlan> {
    if (![bindingHandle, planHandle].every(isDockerOpaqueHandle)) {
      throw new Error("The Docker container action confirmation is invalid.");
    }
    const value = await this.#request(DOCKER_WRITE_RPC_METHODS.confirmAction, {
      bindingHandle,
      planHandle,
    });
    if (!isDockerActionPlan(value) || value.planHandle !== planHandle || !value.confirmed) {
      throw new Error("The backend returned an invalid Docker container action confirmation.");
    }
    return value;
  }

  async executeDockerContainerAction(
    bindingHandle: string,
    planHandle: string,
  ): Promise<DockerActionReceipt> {
    if (![bindingHandle, planHandle].every(isDockerOpaqueHandle)) {
      throw new Error("The Docker container action request is invalid.");
    }
    const value = await this.#request(
      DOCKER_WRITE_RPC_METHODS.executeAction,
      { bindingHandle, planHandle },
      DOCKER_ACTION_TIMEOUT_MS,
    );
    if (!isDockerActionReceipt(value) || value.planHandle !== planHandle) {
      throw new Error("The backend returned an invalid Docker container action receipt.");
    }
    return value;
  }

  async cancelDockerContainerAction(
    bindingHandle: string,
    planHandle: string,
  ): Promise<DockerActionCancellation> {
    if (![bindingHandle, planHandle].every(isDockerOpaqueHandle)) {
      throw new Error("The Docker container action cancellation is invalid.");
    }
    const value = await this.#request(DOCKER_WRITE_RPC_METHODS.cancelAction, {
      bindingHandle,
      planHandle,
    });
    if (!isDockerActionCancellation(value)) {
      throw new Error("The backend returned an invalid Docker container action cancellation.");
    }
    return value;
  }

  /**
   * Open a shell inside a listed container.
   *
   * Takes the same opaque handles every other Docker call takes and returns
   * the same terminal handle a host shell does, so the poll, input, resize and
   * close paths below need no container-aware branch at all.
   */
  async openDockerContainerTerminal(
    bindingHandle: string,
    snapshotHandle: string,
    containerHandle: string,
    columns: number,
    rows: number,
  ): Promise<ContainerTerminalOpened> {
    if (
      !isTerminalBindingHandle(bindingHandle) ||
      ![snapshotHandle, containerHandle].every(isDockerOpaqueHandle) ||
      !isTerminalSize(columns, rows)
    ) {
      throw new Error("The container terminal open request is invalid.");
    }
    const value = await this.#request(DOCKER_TERMINAL_RPC_METHODS.open, {
      bindingHandle,
      snapshotHandle,
      containerHandle,
      columns,
      rows,
    });
    if (!isContainerTerminalOpened(value) || value.columns !== columns || value.rows !== rows) {
      throw new Error("The backend returned an invalid container terminal open response.");
    }
    return value;
  }

  async loadEmergencyCommandCatalog(bindingHandle: string): Promise<EmergencyCommandCatalog> {
    if (!isEmergencyCommandOpaqueHandle(bindingHandle)) {
      throw new Error("The emergency command catalog request is invalid.");
    }
    const value = await this.#request(EMERGENCY_COMMAND_RPC_METHODS.loadCatalog, {
      bindingHandle,
    }, EMERGENCY_COMMAND_CATALOG_TIMEOUT_MS);
    if (!isEmergencyCommandCatalog(value)) {
      throw new Error("The backend returned an invalid emergency command catalog.");
    }
    return value;
  }

  async runEmergencyCommand(
    bindingHandle: string,
    snapshotHandle: string,
    commandHandle: string,
    containerHandle?: string,
  ): Promise<EmergencyCommandResult> {
    if (
      ![bindingHandle, snapshotHandle, commandHandle].every(isEmergencyCommandOpaqueHandle) ||
      !(containerHandle === undefined || isEmergencyCommandOpaqueHandle(containerHandle))
    ) {
      throw new Error("The emergency command run request is invalid.");
    }
    const value = await this.#request(EMERGENCY_COMMAND_RPC_METHODS.run, {
      bindingHandle,
      snapshotHandle,
      commandHandle,
      containerHandle,
    }, EMERGENCY_COMMAND_RUN_TIMEOUT_MS);
    if (
      !isEmergencyCommandResult(value) ||
      value.snapshotHandle !== snapshotHandle ||
      value.commandHandle !== commandHandle
    ) {
      throw new Error("The backend returned an invalid emergency command result.");
    }
    return value;
  }

  async inspectEmergencyPath(
    bindingHandle: string,
    pathHandle: string,
  ): Promise<EmergencyPathDetail> {
    if (![bindingHandle, pathHandle].every(isEmergencyCommandOpaqueHandle)) {
      throw new Error("The emergency path request is invalid.");
    }
    const value = await this.#request(EMERGENCY_COMMAND_RPC_METHODS.inspectPath, {
      bindingHandle,
      pathHandle,
    });
    if (!isEmergencyPathDetail(value) || value.pathHandle !== pathHandle) {
      throw new Error("The backend returned invalid emergency path details.");
    }
    return value;
  }

  async planEmergencyPathAction(
    bindingHandle: string,
    pathHandle: string,
    action: EmergencyPathAction,
  ): Promise<EmergencyPathPlan> {
    if (![bindingHandle, pathHandle].every(isEmergencyCommandOpaqueHandle) ||
      !isEmergencyPathAction(action)) {
      throw new Error("The emergency path plan request is invalid.");
    }
    const value = await this.#request(EMERGENCY_COMMAND_RPC_METHODS.planPath, {
      bindingHandle,
      pathHandle,
      action,
    });
    if (!isEmergencyPathPlan(value) || value.pathHandle !== pathHandle || value.action !== action) {
      throw new Error("The backend returned an invalid emergency path plan.");
    }
    return value;
  }

  async confirmEmergencyPathAction(
    bindingHandle: string,
    planHandle: string,
  ): Promise<EmergencyPathPlan> {
    if (![bindingHandle, planHandle].every(isEmergencyCommandOpaqueHandle)) {
      throw new Error("The emergency path confirmation is invalid.");
    }
    const value = await this.#request(EMERGENCY_COMMAND_RPC_METHODS.confirmPath, {
      bindingHandle,
      planHandle,
    });
    if (!isEmergencyPathPlan(value) || value.planHandle !== planHandle) {
      throw new Error("The backend returned an invalid emergency path plan.");
    }
    return value;
  }

  async executeEmergencyPathAction(
    bindingHandle: string,
    planHandle: string,
  ): Promise<EmergencyPathReceipt> {
    if (![bindingHandle, planHandle].every(isEmergencyCommandOpaqueHandle)) {
      throw new Error("The emergency path execution request is invalid.");
    }
    const value = await this.#request(EMERGENCY_COMMAND_RPC_METHODS.executePath, {
      bindingHandle,
      planHandle,
    }, EMERGENCY_COMMAND_RUN_TIMEOUT_MS);
    if (!isEmergencyPathReceipt(value) || value.planHandle !== planHandle) {
      throw new Error("The backend returned an invalid emergency path receipt.");
    }
    return value;
  }

  async cancelEmergencyPathAction(bindingHandle: string, planHandle: string): Promise<void> {
    if (![bindingHandle, planHandle].every(isEmergencyCommandOpaqueHandle)) {
      throw new Error("The emergency path cancellation is invalid.");
    }
    await this.#request(EMERGENCY_COMMAND_RPC_METHODS.cancelPath, { bindingHandle, planHandle });
  }

  async listPacketCaptureInterfaces(
    bindingHandle: string,
  ): Promise<PacketCaptureInterfaceList> {
    if (!isPacketCaptureOpaqueHandle(bindingHandle)) {
      throw new Error("The packet capture interface request is invalid.");
    }
    const value = await this.#request(PACKET_CAPTURE_LIVE_RPC_METHODS.listInterfaces, {
      bindingHandle,
    }, PACKET_CAPTURE_LIST_TIMEOUT_MS);
    if (
      !isPacketCaptureInterfaceList(value) ||
      value.interfaces.some((item) => item.interfaceHandle === bindingHandle)
    ) {
      throw new Error("The backend returned an invalid packet capture interface list.");
    }
    return value;
  }

  async startPacketCapture(
    bindingHandle: string,
    interfaceHandle: string,
    input: PacketCaptureStartInput,
  ): Promise<PacketCaptureStarted> {
    if (
      !isPacketCaptureOpaqueHandle(bindingHandle) ||
      !isPacketCaptureOpaqueHandle(interfaceHandle) ||
      !isPacketCaptureStartInput(input)
    ) {
      throw new Error("The packet capture start request is invalid.");
    }
    const value = await this.#request(PACKET_CAPTURE_LIVE_RPC_METHODS.start, {
      bindingHandle,
      interfaceHandle,
      input,
    }, PACKET_CAPTURE_START_TIMEOUT_MS);
    if (
      !isPacketCaptureStarted(value) ||
      value.captureHandle === bindingHandle ||
      value.captureHandle === interfaceHandle
    ) {
      throw new Error("The backend returned an invalid packet capture start result.");
    }
    return value;
  }

  async pollPacketCapture(
    bindingHandle: string,
    captureHandle: string,
    afterSequence: number,
  ): Promise<PacketCapturePoll> {
    if (
      !isPacketCaptureOpaqueHandle(bindingHandle) ||
      !isPacketCaptureOpaqueHandle(captureHandle) ||
      !isPacketCaptureCursor(afterSequence)
    ) {
      throw new Error("The packet capture poll request is invalid.");
    }
    const value = await this.#request(PACKET_CAPTURE_LIVE_RPC_METHODS.poll, {
      bindingHandle,
      captureHandle,
      afterSequence,
    }, PACKET_CAPTURE_POLL_TIMEOUT_MS);
    if (
      !isPacketCapturePoll(value) ||
      value.captureHandle !== captureHandle ||
      (!value.cursorReset && value.events.some((event) => event.sequence <= afterSequence))
    ) {
      throw new Error("The backend returned an invalid packet capture poll result.");
    }
    return value;
  }

  async stopPacketCapture(
    bindingHandle: string,
    captureHandle: string,
  ): Promise<PacketCaptureStopped> {
    if (
      !isPacketCaptureOpaqueHandle(bindingHandle) ||
      !isPacketCaptureOpaqueHandle(captureHandle)
    ) {
      throw new Error("The packet capture stop request is invalid.");
    }
    const value = await this.#request(PACKET_CAPTURE_LIVE_RPC_METHODS.stop, {
      bindingHandle,
      captureHandle,
    }, PACKET_CAPTURE_STOP_TIMEOUT_MS);
    if (!isPacketCaptureStopped(value)) {
      throw new Error("The backend returned an invalid packet capture stop result.");
    }
    return value;
  }

  async listApplicationLogs(filter: ApplicationLogFilter): Promise<ApplicationLogSnapshot> {
    if (!isApplicationLogFilter(filter)) {
      throw new Error("The application log filter is invalid.");
    }
    const value = await this.#request(APPLICATION_LOG_RPC_METHODS.list, { filter });
    if (!isApplicationLogSnapshot(value)) {
      throw new Error("The backend returned an invalid application log snapshot.");
    }
    return value;
  }

  async setApplicationLogLevel(
    level: ApplicationLogLevel,
  ): Promise<ApplicationLogLevelResult> {
    if (!isApplicationLogLevel(level)) {
      throw new Error("The application log level is invalid.");
    }
    const value = await this.#request(APPLICATION_LOG_RPC_METHODS.setLevel, { level });
    if (!isApplicationLogLevelResult(value) || value.level !== level) {
      throw new Error("The backend returned an invalid application log level result.");
    }
    return value;
  }

  async clearApplicationLogBuffer(): Promise<ApplicationLogClearResult> {
    const value = await this.#request(APPLICATION_LOG_RPC_METHODS.clearBuffer, {});
    if (!isApplicationLogClearResult(value)) {
      throw new Error("The backend returned an invalid application log clear result.");
    }
    return value;
  }

  async getApplicationLogPreview(filter: ApplicationLogFilter): Promise<ApplicationLogPreview> {
    if (!isApplicationLogFilter(filter)) {
      throw new Error("The application log preview filter is invalid.");
    }
    const value = await this.#request(APPLICATION_LOG_RPC_METHODS.preview, { filter });
    if (!isApplicationLogPreview(value)) {
      throw new Error("The backend returned an invalid application log preview.");
    }
    return value;
  }

  async prepareApplicationLogExport(
    filter: ApplicationLogFilter,
  ): Promise<InternalApplicationLogExportPayload> {
    if (!isApplicationLogFilter(filter)) {
      throw new Error("The application log export filter is invalid.");
    }
    const value = await this.#request(APPLICATION_LOG_RPC_METHODS.prepareExport, { filter });
    if (!isInternalApplicationLogExportPayload(value)) {
      throw new Error("The backend returned an invalid application log export payload.");
    }
    return value;
  }

  async getIntegrityPresets(): Promise<IntegrityPresetCatalog> {
    const value = await this.#request(INTEGRITY_RPC_METHODS.presets, {});
    if (!isIntegrityPresetCatalog(value)) {
      throw new Error("The backend returned an invalid file-integrity preset catalog.");
    }
    return value;
  }

  async listIntegrityBaselines(bindingHandle: string): Promise<IntegrityBaselineList> {
    if (!isIntegrityOpaqueHandle(bindingHandle)) {
      throw new Error("The file-integrity binding is invalid.");
    }
    const value = await this.#request(INTEGRITY_RPC_METHODS.listBaselines, { bindingHandle });
    if (!isIntegrityBaselineList(value) ||
      value.items.some((baseline) => baseline.baselineHandle === bindingHandle)) {
      throw new Error("The backend returned an invalid file-integrity baseline list.");
    }
    return value;
  }

  async startIntegrityComparison(
    bindingHandle: string,
    baselineHandle: string,
  ): Promise<IntegrityComparisonStarted> {
    if (!isIntegrityOpaqueHandle(bindingHandle) ||
      !isIntegrityOpaqueHandle(baselineHandle) || baselineHandle === bindingHandle) {
      throw new Error("The file-integrity comparison request is invalid.");
    }
    const value = await this.#request(INTEGRITY_RPC_METHODS.startComparison, {
      bindingHandle,
      baselineHandle,
    });
    if (!isIntegrityComparisonStarted(value) || value.baselineHandle !== baselineHandle ||
      value.operationHandle === bindingHandle || value.operationHandle === baselineHandle) {
      throw new Error("The backend returned an invalid file-integrity comparison start.");
    }
    return value;
  }

  async pollIntegrityComparison(
    bindingHandle: string,
    operationHandle: string,
    afterEvent: number,
    limit: number,
  ): Promise<IntegrityComparisonPoll> {
    if (!isIntegrityOpaqueHandle(bindingHandle) ||
      !isIntegrityOpaqueHandle(operationHandle) || operationHandle === bindingHandle ||
      !isIntegrityPollRequest(afterEvent, limit)) {
      throw new Error("The file-integrity poll request is invalid.");
    }
    const value = await this.#request(INTEGRITY_RPC_METHODS.pollComparison, {
      bindingHandle,
      operationHandle,
      afterEvent,
      limit,
    });
    if (!isIntegrityComparisonPoll(value) || value.operationHandle !== operationHandle ||
      value.baselineHandle === bindingHandle || value.baselineHandle === operationHandle ||
      value.nextEventCursor < afterEvent ||
      value.events.some((event) => event.sequence <= afterEvent)) {
      throw new Error("The backend returned an invalid file-integrity comparison poll.");
    }
    return value;
  }

  async cancelIntegrityComparison(
    bindingHandle: string,
    operationHandle: string,
  ): Promise<IntegrityComparisonCancellation> {
    if (!isIntegrityOpaqueHandle(bindingHandle) ||
      !isIntegrityOpaqueHandle(operationHandle) || operationHandle === bindingHandle) {
      throw new Error("The file-integrity cancellation request is invalid.");
    }
    const value = await this.#request(INTEGRITY_RPC_METHODS.cancelComparison, {
      bindingHandle,
      operationHandle,
    });
    if (!isIntegrityComparisonCancellation(value)) {
      throw new Error("The backend returned an invalid file-integrity cancellation.");
    }
    return value;
  }

  async loadSettings(): Promise<SettingsSnapshot> {
    const value = await this.#request(SETTINGS_RPC_METHODS.get, {});
    if (!isSettingsSnapshot(value)) {
      throw new Error("The backend returned an invalid settings snapshot.");
    }
    return value;
  }

  async saveSettings(input: SettingsSaveInput): Promise<SettingsSnapshot> {
    if (!isSettingsSaveInput(input)) {
      throw new Error("The settings input is invalid.");
    }
    const value = await this.#request(SETTINGS_RPC_METHODS.save, input);
    if (!isSettingsSnapshot(value)) {
      throw new Error("The backend returned an invalid settings snapshot.");
    }
    return value;
  }

  async replaceSettingsAiApiKey(
    input: SettingsAiApiKeyReplacementInput,
  ): Promise<SettingsAiApiKeyReplacementResult> {
    if (!isSettingsAiApiKeyReplacementInput(input)) {
      throw new Error("The Settings API-key replacement input is invalid.");
    }
    const value = await this.#request(SETTINGS_RPC_METHODS.replaceAiApiKey, input);
    if (!isSettingsAiApiKeyReplacementResult(value) || value.providerId !== input.providerId) {
      throw new Error("The backend returned an invalid Settings API-key replacement result.");
    }
    return value;
  }

  async planSettingsAiApiKeyClear(providerId: string): Promise<SettingsMutationProposal> {
    if (!isSettingsProviderId(providerId)) throw new Error("The Settings provider is invalid.");
    const value = await this.#request(SETTINGS_RPC_METHODS.planAiApiKeyClear, { providerId });
    if (!isSettingsMutationProposal(value) || value.kind !== "clear-ai-api-key") {
      throw new Error("The backend returned an invalid Settings API-key clear plan.");
    }
    return value;
  }

  async planSettingsAiProviderRemoval(providerId: string): Promise<SettingsMutationProposal> {
    if (!isSettingsProviderId(providerId)) throw new Error("The Settings provider is invalid.");
    const value = await this.#request(SETTINGS_RPC_METHODS.planAiProviderRemoval, { providerId });
    if (!isSettingsMutationProposal(value) || value.kind !== "remove-ai-provider") {
      throw new Error("The backend returned an invalid Settings provider removal plan.");
    }
    return value;
  }

  async confirmSettingsMutation(mutationHandle: string): Promise<SettingsMutationResult> {
    if (!isSettingsMutationHandle(mutationHandle)) {
      throw new Error("The Settings mutation handle is invalid.");
    }
    const value = await this.#request(SETTINGS_RPC_METHODS.confirmMutation, { mutationHandle });
    if (!isSettingsMutationResult(value)) {
      throw new Error("The backend returned an invalid Settings mutation result.");
    }
    return value;
  }

  async cancelSettingsMutation(mutationHandle: string): Promise<SettingsMutationCancellation> {
    if (!isSettingsMutationHandle(mutationHandle)) {
      throw new Error("The Settings mutation handle is invalid.");
    }
    const value = await this.#request(SETTINGS_RPC_METHODS.cancelMutation, { mutationHandle });
    if (!isSettingsMutationCancellation(value)) {
      throw new Error("The backend returned an invalid Settings mutation cancellation.");
    }
    return value;
  }

  async listAiHistory(query: string, offset: number, limit: number): Promise<AiHistoryListPage> {
    if (!isAiHistoryQuery(query) || !isAiHistoryPageRequest(offset, limit)) {
      throw new Error("The AI history page request is invalid.");
    }
    const value = await this.#request(AI_HISTORY_RPC_METHODS.list, { query, offset, limit });
    if (!isAiHistoryListPage(value)) {
      throw new Error("The backend returned an invalid AI history page.");
    }
    return value;
  }

  async getAiHistoryRecord(id: string): Promise<AiHistoryRecord> {
    if (!isAiHistoryId(id)) throw new Error("The AI history identifier is invalid.");
    const value = await this.#request(AI_HISTORY_RPC_METHODS.get, { id });
    if (!isAiHistoryRecord(value)) {
      throw new Error("The backend returned an invalid AI history record.");
    }
    return value;
  }

  async planAiHistoryRemove(id: string): Promise<AiHistoryMutationProposal> {
    if (!isAiHistoryId(id)) throw new Error("The AI history identifier is invalid.");
    const value = await this.#request(AI_HISTORY_RPC_METHODS.planRemove, { id });
    if (!isAiHistoryMutationProposal(value) || value.kind !== "remove") {
      throw new Error("The backend returned an invalid AI history removal plan.");
    }
    return value;
  }

  async planAiHistoryClear(): Promise<AiHistoryMutationProposal> {
    const value = await this.#request(AI_HISTORY_RPC_METHODS.planClear, {});
    if (!isAiHistoryMutationProposal(value) || value.kind !== "clear") {
      throw new Error("The backend returned an invalid AI history clear plan.");
    }
    return value;
  }

  async confirmAiHistoryMutation(handle: string): Promise<AiHistoryMutationResult> {
    if (!isAiHistoryOpaqueHandle(handle)) throw new Error("The AI history plan is invalid.");
    const value = await this.#request(AI_HISTORY_RPC_METHODS.confirm, { handle });
    if (!isAiHistoryMutationResult(value)) {
      throw new Error("The backend returned an invalid AI history mutation result.");
    }
    return value;
  }

  async cancelAiHistoryMutation(handle: string): Promise<AiHistoryMutationCancellation> {
    if (!isAiHistoryOpaqueHandle(handle)) throw new Error("The AI history plan is invalid.");
    const value = await this.#request(AI_HISTORY_RPC_METHODS.cancel, { handle });
    if (!isAiHistoryMutationCancellation(value)) {
      throw new Error("The backend returned an invalid AI history cancellation.");
    }
    return value;
  }

  async prepareAiHistoryExport(format: AiHistoryExportFormat): Promise<InternalAiHistoryExportPayload> {
    if (!isAiHistoryExportFormat(format)) throw new Error("The AI history export format is invalid.");
    const value = await this.#request(AI_HISTORY_RPC_METHODS.export, { format });
    if (!isInternalAiHistoryExportPayload(value)) {
      throw new Error("The backend returned an invalid AI history export payload.");
    }
    return value;
  }

  async listCommandHistory(
    bindingHandle: string,
    query: string,
    offset: number,
    limit: number,
  ): Promise<CommandHistoryListPage> {
    if (!isCommandHistoryOpaqueHandle(bindingHandle) ||
      !isCommandHistoryQuery(query) || !isCommandHistoryPageRequest(offset, limit)) {
      throw new Error("The command history page request is invalid.");
    }
    const value = await this.#request(COMMAND_HISTORY_RPC_METHODS.list, {
      bindingHandle, query, offset, limit,
    });
    if (!isCommandHistoryListPage(value) || value.offset !== offset) {
      throw new Error("The backend returned an invalid command history page.");
    }
    return value;
  }

  async getCommandHistory(bindingHandle: string, recordId: string): Promise<CommandHistoryRecord> {
    if (!isCommandHistoryOpaqueHandle(bindingHandle) || !isCommandHistoryId(recordId)) {
      throw new Error("The command history record request is invalid.");
    }
    const value = await this.#request(COMMAND_HISTORY_RPC_METHODS.get, { bindingHandle, recordId });
    if (!isCommandHistoryRecord(value) || value.id !== recordId) {
      throw new Error("The backend returned an invalid command history record.");
    }
    return value;
  }

  async planCommandReplay(bindingHandle: string, recordId: string): Promise<CommandReplayIntent> {
    if (!isCommandHistoryOpaqueHandle(bindingHandle) || !isCommandHistoryId(recordId)) {
      throw new Error("The command history replay request is invalid.");
    }
    const value = await this.#request(COMMAND_HISTORY_RPC_METHODS.planReplay, { bindingHandle, recordId });
    if (!isCommandReplayIntent(value)) {
      throw new Error("The backend returned an invalid command history replay intent.");
    }
    return value;
  }

  async planCommandHistoryRemove(
    bindingHandle: string,
    recordId: string,
  ): Promise<CommandHistoryMutationProposal> {
    if (!isCommandHistoryOpaqueHandle(bindingHandle) || !isCommandHistoryId(recordId)) {
      throw new Error("The command history removal plan request is invalid.");
    }
    const value = await this.#request(COMMAND_HISTORY_RPC_METHODS.planRemove, {
      bindingHandle, recordId,
    });
    if (!isCommandHistoryMutationProposal(value) || value.kind !== "remove") {
      throw new Error("The backend returned an invalid command history removal plan.");
    }
    return value;
  }

  async planCommandHistoryClear(bindingHandle: string): Promise<CommandHistoryMutationProposal> {
    if (!isCommandHistoryOpaqueHandle(bindingHandle)) {
      throw new Error("The command history binding is invalid.");
    }
    const value = await this.#request(COMMAND_HISTORY_RPC_METHODS.planClear, { bindingHandle });
    if (!isCommandHistoryMutationProposal(value) || value.kind !== "clear") {
      throw new Error("The backend returned an invalid command history clear plan.");
    }
    return value;
  }

  async confirmCommandHistoryMutation(
    bindingHandle: string,
    mutationHandle: string,
  ): Promise<CommandHistoryMutationResult> {
    if (!isCommandHistoryOpaqueHandle(bindingHandle) ||
      !isCommandHistoryOpaqueHandle(mutationHandle)) {
      throw new Error("The command history mutation plan is invalid.");
    }
    const value = await this.#request(COMMAND_HISTORY_RPC_METHODS.confirm, {
      bindingHandle, mutationHandle,
    });
    if (!isCommandHistoryMutationResult(value)) {
      throw new Error("The backend returned an invalid command history mutation result.");
    }
    return value;
  }

  async cancelCommandHistoryMutation(
    bindingHandle: string,
    mutationHandle: string,
  ): Promise<CommandHistoryMutationCancellation> {
    if (!isCommandHistoryOpaqueHandle(bindingHandle) ||
      !isCommandHistoryOpaqueHandle(mutationHandle)) {
      throw new Error("The command history mutation plan is invalid.");
    }
    const value = await this.#request(COMMAND_HISTORY_RPC_METHODS.cancel, {
      bindingHandle, mutationHandle,
    });
    if (!isCommandHistoryMutationCancellation(value)) {
      throw new Error("The backend returned an invalid command history cancellation.");
    }
    return value;
  }

  async generateDisposalReport(bindingHandle: string): Promise<DisposalReportSnapshot> {
    if (!isDisposalReportOpaqueHandle(bindingHandle)) {
      throw new Error("The disposal report binding is invalid.");
    }
    const value = await this.#request(DISPOSAL_REPORT_RPC_METHODS.generate, { bindingHandle });
    if (!isDisposalReportSnapshot(value)) {
      throw new Error("The backend returned an invalid disposal report snapshot.");
    }
    return value;
  }

  async getDisposalReportContent(
    bindingHandle: string,
    reportHandle: string,
    format: DisposalReportPreviewFormat,
  ): Promise<DisposalReportContent> {
    if (!isDisposalReportOpaqueHandle(bindingHandle) ||
      !isDisposalReportOpaqueHandle(reportHandle) || !isDisposalReportPreviewFormat(format)) {
      throw new Error("The disposal report content request is invalid.");
    }
    const value = await this.#request(DISPOSAL_REPORT_RPC_METHODS.content, {
      bindingHandle, reportHandle, format,
    });
    if (!isDisposalReportContent(value) || value.format !== format) {
      throw new Error("The backend returned invalid disposal report content.");
    }
    return value;
  }

  async prepareDisposalReportExport(
    bindingHandle: string,
    reportHandle: string,
    format: DisposalReportExportFormat,
  ): Promise<InternalDisposalReportExportPayload> {
    if (!isDisposalReportOpaqueHandle(bindingHandle) ||
      !isDisposalReportOpaqueHandle(reportHandle) || !isDisposalReportExportFormat(format)) {
      throw new Error("The disposal report export request is invalid.");
    }
    const value = await this.#request(DISPOSAL_REPORT_RPC_METHODS.export, {
      bindingHandle, reportHandle, format,
    });
    if (!isInternalDisposalReportExportPayload(value) || value.format !== format) {
      throw new Error("The backend returned an invalid disposal report export payload.");
    }
    return value;
  }

  async getConfigCatalog(): Promise<ConfigCatalog> {
    const value = await this.#request("config.catalog.get", {});
    if (!isConfigCatalog(value)) {
      throw new Error("The backend returned an invalid configuration catalog.");
    }
    return value;
  }

  async generateConfig(input: ConfigGenerateInput): Promise<ConfigDraft> {
    const value = await this.#request("config.quick.generate", input);
    if (!isConfigDraft(value)) {
      throw new Error("The backend returned an invalid configuration draft.");
    }
    return value;
  }

  async reviseConfig(
    handle: string,
    revision: number,
    input: ConfigGenerateInput,
  ): Promise<ConfigDraft> {
    const value = await this.#request("config.quick.revise", { handle, revision, input });
    if (!isConfigDraft(value)) {
      throw new Error("The backend returned an invalid revised configuration draft.");
    }
    return value;
  }

  async copyConfigDraft(handle: string, revision: number): Promise<InternalConfigCopy> {
    const value = await this.#request("config.quick.copy", { handle, revision });
    if (!isInternalConfigCopy(value)) {
      throw new Error("The backend returned an invalid configuration copy payload.");
    }
    return value;
  }

  async closeConfigDraft(handle: string, revision: number): Promise<ConfigClosedResult> {
    const value = await this.#request("config.quick.close", { handle, revision });
    if (!isConfigClosedResult(value)) {
      throw new Error("The backend returned an invalid configuration close outcome.");
    }
    return value;
  }

  async getConfigArtifact(
    handle: string,
    revision: number,
    artifactKey: string,
  ): Promise<InternalConfigArtifact> {
    const value = await this.#request("config.quick.artifact", {
      handle,
      revision,
      artifactKey,
    });
    if (!isInternalConfigArtifact(value)) {
      throw new Error("The backend returned an invalid configuration artifact.");
    }
    return value;
  }

  async setSecurityReferenceFavorites(
    favoriteIds: string[],
  ): Promise<SecurityReferenceFavoritesResult> {
    const value = await this.#request("security-reference.set-favorites", { favoriteIds });
    if (!isSecurityReferenceFavoritesResult(value)) {
      throw new Error("The backend returned an invalid favorites payload.");
    }
    return value;
  }

  async listNotes(query: string, offset: number, limit: number): Promise<NoteListPage> {
    const value = await this.#request("notes.list", { query, offset, limit });
    if (!isNoteListPage(value)) throw new Error("The backend returned an invalid notes page.");
    return value;
  }

  async getNote(id: string): Promise<NoteResult> {
    const value = await this.#request("notes.get", { id });
    if (!isNoteResult(value)) throw new Error("The backend returned an invalid note.");
    return value;
  }

  async createNote(input: NoteCreateInput): Promise<NoteResult> {
    const value = await this.#request("notes.create", input);
    if (!isNoteResult(value)) throw new Error("The backend returned an invalid note.");
    return value;
  }

  async updateNote(input: NoteUpdateInput): Promise<NoteResult> {
    const value = await this.#request("notes.update", input);
    if (!isNoteResult(value)) throw new Error("The backend returned an invalid note.");
    return value;
  }

  async setNotePinned(id: string, pinned: boolean, expectedRevision: string, mutationId: string): Promise<NoteResult> {
    const value = await this.#request("notes.set-pinned", { id, pinned, expectedRevision, mutationId });
    if (!isNoteResult(value)) throw new Error("The backend returned an invalid note.");
    return value;
  }

  async addNoteTag(id: string, tag: string, expectedRevision: string, mutationId: string): Promise<NoteResult> {
    const value = await this.#request("notes.add-tag", { id, tag, expectedRevision, mutationId });
    if (!isNoteResult(value)) throw new Error("The backend returned an invalid note.");
    return value;
  }

  async removeNoteTag(id: string, tag: string, expectedRevision: string, mutationId: string): Promise<NoteResult> {
    const value = await this.#request("notes.remove-tag", { id, tag, expectedRevision, mutationId });
    if (!isNoteResult(value)) throw new Error("The backend returned an invalid note.");
    return value;
  }

  async planNoteDelete(id: string, expectedRevision: string, mutationId: string): Promise<NoteDeleteProposal> {
    const value = await this.#request("notes.delete.plan", { id, expectedRevision, mutationId });
    if (!isNoteDeleteProposal(value)) {
      throw new Error("The backend returned an invalid note delete plan.");
    }
    return value;
  }

  async confirmNoteDelete(handle: string, mutationId: string): Promise<NoteDeleteResult> {
    const value = await this.#request("notes.delete.confirm", { handle, mutationId });
    if (!isNoteDeleteResult(value)) {
      throw new Error("The backend returned an invalid note delete outcome.");
    }
    return value;
  }

  async cancelNoteDelete(handle: string, mutationId: string): Promise<NoteDeleteCancellation> {
    const value = await this.#request("notes.delete.cancel", { handle, mutationId });
    if (!isNoteDeleteCancellation(value)) {
      throw new Error("The backend returned an invalid note delete cancellation.");
    }
    return value;
  }

  async exportNotes(id: string | null): Promise<NotesTextExport> {
    const value = await this.#request("notes.export", { id });
    if (!isNotesTextExport(value)) {
      throw new Error("The backend returned an invalid notes export.");
    }
    return value;
  }

  async openSftpBrowser(bindingHandle: string): Promise<SftpDirectorySnapshot> {
    if (!isSftpBrowserOpaqueHandle(bindingHandle)) {
      throw new Error("The SFTP browser request is invalid.");
    }
    const value = await this.#request(SFTP_BROWSER_RPC_METHODS.open, {
      bindingHandle,
    }, SFTP_BROWSER_TIMEOUT_MS);
    if (!isSftpDirectorySnapshot(value)) {
      throw new Error("The backend returned an invalid SFTP directory.");
    }
    return value;
  }

  async listSftpDirectory(
    bindingHandle: string,
    browserHandle: string,
    directoryHandle: string,
  ): Promise<SftpDirectorySnapshot> {
    if (![bindingHandle, browserHandle, directoryHandle].every(isSftpBrowserOpaqueHandle)) {
      throw new Error("The SFTP directory request is invalid.");
    }
    const value = await this.#request(SFTP_BROWSER_RPC_METHODS.listDirectory, {
      bindingHandle,
      browserHandle,
      directoryHandle,
    }, SFTP_BROWSER_TIMEOUT_MS);
    if (
      !isSftpDirectorySnapshot(value) ||
      value.browserHandle !== browserHandle ||
      value.directoryHandle !== directoryHandle
    ) {
      throw new Error("The backend returned an invalid SFTP directory.");
    }
    return value;
  }

  async readSftpText(
    bindingHandle: string,
    browserHandle: string,
    fileHandle: string,
  ): Promise<SftpTextPreview> {
    if (![bindingHandle, browserHandle, fileHandle].every(isSftpBrowserOpaqueHandle)) {
      throw new Error("The SFTP preview request is invalid.");
    }
    const value = await this.#request(SFTP_BROWSER_RPC_METHODS.readText, {
      bindingHandle,
      browserHandle,
      fileHandle,
    }, SFTP_BROWSER_TIMEOUT_MS);
    if (
      !isSftpTextPreview(value) ||
      value.browserHandle !== browserHandle ||
      value.fileHandle !== fileHandle
    ) {
      throw new Error("The backend returned an invalid SFTP preview.");
    }
    return value;
  }

  async downloadSftpEntry(
    bindingHandle: string,
    browserHandle: string,
    fileHandle: string,
    localPath: string,
  ): Promise<{ bytes: string }> {
    if (![bindingHandle, browserHandle, fileHandle].every(isSftpBrowserOpaqueHandle)) {
      throw new Error("The SFTP download request is invalid.");
    }
    const value = await this.#request(SFTP_BROWSER_RPC_METHODS.download, {
      bindingHandle,
      browserHandle,
      fileHandle,
      localPath,
    }, SFTP_TRANSFER_TIMEOUT_MS);
    if (
      typeof value !== "object" || value === null ||
      !isSftpBrowserOpaqueHandle((value as Record<string, unknown>).browserHandle) ||
      (value as Record<string, unknown>).browserHandle !== browserHandle ||
      (value as Record<string, unknown>).fileHandle !== fileHandle ||
      typeof (value as Record<string, unknown>).bytes !== "string"
    ) {
      throw new Error("The backend returned an invalid SFTP transfer result.");
    }
    return { bytes: (value as { bytes: string }).bytes };
  }

  async planSftpOperation(
    bindingHandle: string,
    browserHandle: string,
    input: SftpOperationInput,
  ): Promise<SftpOperationPlan> {
    if (![bindingHandle, browserHandle, ...input.entryHandles].every(isSftpBrowserOpaqueHandle)) {
      throw new Error("The SFTP operation request is invalid.");
    }
    const value = await this.#request(SFTP_BROWSER_RPC_METHODS.planOperation, {
      bindingHandle,
      browserHandle,
      kind: input.kind,
      entryHandles: input.entryHandles,
      name: input.name ?? null,
      mode: input.mode ?? null,
      format: input.format ?? null,
      stagedHandle: input.stagedHandle ?? null,
    }, SFTP_BROWSER_TIMEOUT_MS);
    if (!isSftpOperationPlan(value) || value.browserHandle !== browserHandle ||
      value.kind !== input.kind) {
      throw new Error("The backend returned an invalid SFTP operation plan.");
    }
    return value;
  }

  async confirmSftpOperation(bindingHandle: string, planHandle: string): Promise<SftpOperationPlan> {
    if (![bindingHandle, planHandle].every(isSftpBrowserOpaqueHandle)) {
      throw new Error("The SFTP confirmation request is invalid.");
    }
    const value = await this.#request(SFTP_BROWSER_RPC_METHODS.confirmOperation, {
      bindingHandle,
      planHandle,
    }, SFTP_BROWSER_TIMEOUT_MS);
    if (!isSftpOperationPlan(value) || value.planHandle !== planHandle ||
      value.state !== "confirmed") {
      throw new Error("The backend returned an invalid SFTP operation plan.");
    }
    return value;
  }

  async executeSftpOperation(
    bindingHandle: string,
    planHandle: string,
  ): Promise<SftpOperationReceipt> {
    if (![bindingHandle, planHandle].every(isSftpBrowserOpaqueHandle)) {
      throw new Error("The SFTP execution request is invalid.");
    }
    const value = await this.#request(SFTP_BROWSER_RPC_METHODS.executeOperation, {
      bindingHandle,
      planHandle,
    }, SFTP_OPERATION_TIMEOUT_MS);
    if (!isSftpOperationReceipt(value) || value.planHandle !== planHandle) {
      throw new Error("The backend returned an invalid SFTP operation receipt.");
    }
    return value;
  }

  async cancelSftpOperation(bindingHandle: string, planHandle: string): Promise<void> {
    if (![bindingHandle, planHandle].every(isSftpBrowserOpaqueHandle)) {
      throw new Error("The SFTP cancellation request is invalid.");
    }
    await this.#request(SFTP_BROWSER_RPC_METHODS.cancelOperation, {
      bindingHandle,
      planHandle,
    }, SFTP_BROWSER_TIMEOUT_MS);
  }

  async stageSftpUpload(
    bindingHandle: string,
    localPath: string,
    name: string,
  ): Promise<SftpStagedUpload> {
    if (!isSftpBrowserOpaqueHandle(bindingHandle)) {
      throw new Error("The SFTP staging request is invalid.");
    }
    const value = await this.#request(SFTP_BROWSER_RPC_METHODS.stageUpload, {
      bindingHandle,
      localPath,
      name,
    }, SFTP_TRANSFER_TIMEOUT_MS);
    if (!isSftpStagedUpload(value)) {
      throw new Error("The backend returned an invalid staged upload.");
    }
    return value;
  }

  #request(
    method: string,
    params: object,
    timeoutMs = defaultTimeoutFor(method),
  ): Promise<unknown> {
    const child = this.#process;
    if (child === null || child.stdin.destroyed) {
      return Promise.reject(new Error("LovelyRes backend is not running."));
    }
    const requestId = randomUUID();
    const encoded = JSON.stringify({
      protocol: BACKEND_PROTOCOL,
      requestId,
      method,
      params,
    });
    if (Buffer.byteLength(encoded, "utf8") > MAX_REQUEST_BYTES) {
      return Promise.reject(new Error("The backend request is too large."));
    }
    return new Promise<unknown>((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.#pending.delete(requestId);
        reject(new Error("The backend request timed out."));
      }, timeoutMs);
      this.#pending.set(requestId, { resolve, reject, timeout });
      child.stdin.write(`${encoded}\n`, "utf8", (error) => {
        if (error === null || error === undefined) return;
        const pending = this.#pending.get(requestId);
        if (pending === undefined) return;
        clearTimeout(pending.timeout);
        this.#pending.delete(requestId);
        pending.reject(error);
      });
    });
  }

  #consumeStdout(chunk: string): void {
    this.#stdoutBuffer += chunk;
    if (Buffer.byteLength(this.#stdoutBuffer, "utf8") > MAX_RESPONSE_BYTES) {
      const error = new Error("The backend response exceeded the allowed size.");
      this.#process?.kill();
      this.#failAll(error);
      this.#stdoutBuffer = "";
      return;
    }
    for (;;) {
      const newline = this.#stdoutBuffer.indexOf("\n");
      if (newline < 0) return;
      const line = this.#stdoutBuffer.slice(0, newline).replace(/\r$/, "");
      this.#stdoutBuffer = this.#stdoutBuffer.slice(newline + 1);
      this.#consumeResponse(line);
    }
  }

  #consumeResponse(line: string): void {
    let response: RpcResponse;
    try {
      response = JSON.parse(line) as RpcResponse;
    } catch {
      this.#failAll(new Error("The backend emitted invalid JSON."));
      return;
    }
    if (
      response.protocol !== BACKEND_PROTOCOL ||
      typeof response.requestId !== "string" ||
      typeof response.ok !== "boolean"
    ) {
      this.#failAll(new Error("The backend emitted an invalid response envelope."));
      return;
    }
    const pending = this.#pending.get(response.requestId);
    if (pending === undefined) return;
    clearTimeout(pending.timeout);
    this.#pending.delete(response.requestId);
    if (response.ok) {
      pending.resolve(response.result);
      return;
    }
    const code = response.error?.code ?? "backend-error";
    const message = response.error?.message ?? "The backend operation failed.";
    pending.reject(new Error(`${message} (${code})`));
  }

  #failAll(error: Error): void {
    for (const pending of this.#pending.values()) {
      clearTimeout(pending.timeout);
      pending.reject(error);
    }
    this.#pending.clear();
  }
}
