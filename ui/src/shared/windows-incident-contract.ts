import type { WindowsRdpRequest, WindowsRdpStatus } from "./windows-rdp-contract.js";
/**
 * Shared contract for Windows Incident Response over RDP Dynamic Virtual Channel (DVC).
 */

export type WindowsRiskLevel = "high" | "medium" | "low" | "normal";

export type WindowsRemoteIntent =
  | { action: "send-chat"; text: string }
  | { action: "run-command"; command: string }
  | { action: "pull-file"; remotePath: string }
  | {
      action:
        | "collect-overview"
        | "collect-baseline"
        | "collect-processes"
        | "collect-network"
        | "collect-startup"
        | "collect-accounts";
    }
  | { action: "collect-logs"; category: string }
  | { action: "inspect-process"; pid: number; startTime: string }
  | { action: "collect-files"; path: string }
  | { action: "preview-file"; path: string }
  | { action: "collect-registry"; keyPath: string }
  | { action: "remediate-baseline"; ruleId: string }
  | { action: "kill-process"; pid: number; startTime: string }
  | { action: "remove-startup"; sourceType: string; name: string; location: string }
  | { action: "disable-account"; name: string; sid: string }
  | { action: "delete-file"; path: string; dirPath: string }
  | { action: "delete-registry-value"; keyPath: string; valueName: string };

export type WindowsIncidentRequest =
  | { action: "status" | "register-plugin" | "unregister-plugin" | "start-listener" | "open-remote-desktop" | "reveal-agent" }
  | (WindowsRemoteIntent & { sessionId: string });

export interface DvcRegistrationStatus {
  registered: boolean;
  clsid: string;
  addinName: string;
  localServerCommand: string | null;
}

export interface DvcLogEntry {
  timestamp: string;
  direction: string;
  kind: string;
  summary: string;
}

export interface DvcReceivedFile {
  fileId: string;
  name: string;
  sizeBytes: number;
  sha256: string;
  verified: boolean;
  receivedAt: string;
}

export interface DvcRuntimeStatus {
  registration: DvcRegistrationStatus;
  listenerRunning: boolean;
  rdpPluginInitialized: boolean;
  channelConnected: boolean;
  activeChannelName: string | null;
  connectedSince: string | null;
  sessionId: string | null;
  messagesSent: number;
  messagesReceived: number;
  recentLogs: DvcLogEntry[];
  receivedFiles: DvcReceivedFile[];
}

export interface WindowsOverviewSnapshot {
  hostname: string;
  osCaption: string;
  osVersion: string;
  architecture: string;
  domainOrWorkgroup: string;
  partOfDomain: boolean;
  currentUser: string;
  isElevated: boolean;
  sessionName: string;
  bootTime: string;
  uptimeHours: number;
  cpuName: string;
  cpuCores: number;
  cpuLoadPercent: number;
  memoryTotalMb: number;
  memoryUsedMb: number;
  memoryUsagePercent: number;
  systemDriveFreeGb: number;
  systemDriveTotalGb: number;
  defenderEnabled: boolean | null;
  realtimeProtection: boolean | null;
  firewallDomainEnabled: boolean | null;
  firewallPrivateEnabled: boolean | null;
  firewallPublicEnabled: boolean | null;
  highRiskCount: number;
  mediumRiskCount: number;
  highlights: string[];
  facts: Array<{ group: string; label: string; value: string }>;
  warnings: string[];
}

export interface WindowsBaselineItem {
  id: string;
  category: string;
  title: string;
  currentValue: string;
  expectedValue: string;
  status: "pass" | "warn" | "fail" | "unknown";
  severity: WindowsRiskLevel;
  description: string;
  recommendation: string;
}

export interface WindowsBaselineSnapshot {
  totalChecks: number;
  passedCount: number;
  failedCount: number;
  warningCount: number;
  unknownCount: number;
  items: WindowsBaselineItem[];
}

export interface WindowsProcessEntry {
  pid: number;
  ppid: number;
  name: string;
  executablePath: string;
  commandLine: string;
  user: string;
  sessionId: number;
  workingSetMb: number;
  startTime: string;
  riskLevel: WindowsRiskLevel;
  riskReasons: string[];
}

export interface WindowsProcessesSnapshot {
  totalCount: number;
  suspiciousCount: number;
  processes: WindowsProcessEntry[];
}

export interface WindowsProcessInspection {
  pid: number; startTime: string; observedAt: string; user: string;
  services: Array<{ name: string; displayName: string; state: string; startMode: string; path: string; account: string }>;
  modules: Array<{ name: string; path: string; sizeBytes: number }>;
  network: WindowsNetworkEntry[]; warnings: string[];
}

export interface WindowsNetworkEntry {
  protocol: string;
  localAddress: string;
  localPort: number;
  remoteAddress: string;
  remotePort: number;
  state: string;
  pid: number;
  processName: string;
  processPath: string;
  riskLevel: WindowsRiskLevel;
  riskReason: string;
}

export interface WindowsNetworkSnapshot {
  totalCount: number;
  suspiciousCount: number;
  connections: WindowsNetworkEntry[];
}

export interface WindowsStartupEntry {
  sourceType: string;
  name: string;
  location: string;
  command: string;
  runAs: string;
  state: string;
  riskLevel: WindowsRiskLevel;
  riskReason: string;
}

export interface WindowsStartupSnapshot {
  totalCount: number;
  suspiciousCount: number;
  entries: WindowsStartupEntry[];
}

export interface WindowsAccountEntry {
  name: string;
  fullName: string;
  enabled: boolean;
  isAdmin: boolean;
  sid: string;
  rid: number;
  lastLogon: string;
  passwordRequired: boolean;
  passwordExpires: boolean;
  riskLevel: WindowsRiskLevel;
  riskReasons: string[];
}

export interface WindowsAccountsSnapshot {
  totalCount: number;
  adminCount: number;
  suspiciousCount: number;
  accounts: WindowsAccountEntry[];
}

export interface WindowsEventLogEntry {
  recordId: number;
  timeCreated: string;
  channel: string;
  eventId: number;
  level: string;
  category: string;
  summary: string;
  detail: string;
  detailTruncated: boolean;
  riskLevel: WindowsRiskLevel;
}

export interface WindowsLogsSnapshot {
  categoryFilter: string;
  totalCount: number;
  highRiskCount: number;
  warnings: string[];
  entries: WindowsEventLogEntry[];
}

export interface WindowsFileEntry {
  name: string;
  fullPath: string;
  entryType: string;
  sizeBytes: number;
  lastWriteTime: string;
  sha256: string;
  hidden: boolean;
  system: boolean;
  riskLevel: WindowsRiskLevel;
  riskReason: string;
}

export interface WindowsFilesSnapshot {
  currentPath: string;
  /** Entries in the folder; entries holds at most the listing cap. */
  totalEntries: number;
  truncated: boolean;
  entries: WindowsFileEntry[];
}

/** The first bytes of one remote file, base64-encoded, for the preview pane. */
export interface WindowsFilePreview {
  fullPath: string;
  sizeBytes: number;
  lastWriteTime: string;
  previewB64: string;
  previewBytes: number;
  truncated: boolean;
}

export interface WindowsRegistryValue {
  name: string;
  kind: string;
  data: string;
  truncated: boolean;
  riskLevel: WindowsRiskLevel;
  riskReason: string;
}

export interface WindowsRegistrySnapshot {
  keyPath: string;
  subkeys: string[];
  values: WindowsRegistryValue[];
  warnings: string[];
}

export type WindowsIncidentResponse =
  | { kind: "status"; status: DvcRuntimeStatus; filelessScript: string }
  | { kind: "command-output"; output: string; status: DvcRuntimeStatus }
  | { kind: "overview"; snapshot: WindowsOverviewSnapshot }
  | { kind: "baseline"; snapshot: WindowsBaselineSnapshot }
  | { kind: "processes"; snapshot: WindowsProcessesSnapshot }
  | { kind: "process-inspection"; inspection: WindowsProcessInspection }
  | { kind: "network"; snapshot: WindowsNetworkSnapshot }
  | { kind: "startup"; snapshot: WindowsStartupSnapshot }
  | { kind: "accounts"; snapshot: WindowsAccountsSnapshot }
  | { kind: "logs"; snapshot: WindowsLogsSnapshot }
  | { kind: "files"; snapshot: WindowsFilesSnapshot }
  | { kind: "file-preview"; preview: WindowsFilePreview }
  | { kind: "registry"; snapshot: WindowsRegistrySnapshot };

export interface WindowsIncidentApi {
  windowsRdp?: (request: WindowsRdpRequest) => Promise<WindowsRdpStatus>;
  windowsIncident(request: WindowsIncidentRequest): Promise<WindowsIncidentResponse>;
  saveWindowsFile?(fileId: string): Promise<WindowsFileSaveResult>;
}

export interface WindowsFileSaveResult {
  saved: boolean;
  fileName: string | null;
  sha256: string | null;
}

export function isWindowsFileId(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu.test(value);
}

export function isWindowsFileSaveResult(value: unknown): value is WindowsFileSaveResult {
  if (!isRecord(value) || !exactKeys(value, ["saved", "fileName", "sha256"])) return false;
  return value.saved === false ? value.fileName === null && value.sha256 === null :
    value.saved === true && isBoundedText(value.fileName, 512) && !/[\\/\r\n]/u.test(value.fileName) &&
    typeof value.sha256 === "string" && /^[a-f0-9]{64}$/iu.test(value.sha256);
}

type JsonRecord = Record<string, unknown>;
const encoder = new TextEncoder();

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactKeys(value: JsonRecord, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && keys.every((k) => Object.hasOwn(value, k));
}

function isBoundedText(value: unknown, maxBytes: number, allowEmpty = false): value is string {
  return (
    typeof value === "string" &&
    (allowEmpty || value.trim().length > 0) &&
    encoder.encode(value).byteLength <= maxBytes &&
    !value.includes("\0")
  );
}

export function isWindowsIncidentRequest(value: unknown): value is WindowsIncidentRequest {
  if (!isRecord(value) || typeof value.action !== "string") return false;
  const local = ["status", "register-plugin", "unregister-plugin", "start-listener", "open-remote-desktop", "reveal-agent"].includes(value.action);
  if (!local && !isWindowsFileId(value.sessionId)) return false;
  const keys = (...fields: string[]) => exactKeys(value, local ? ["action", ...fields] : ["action", "sessionId", ...fields]);
  switch (value.action) {
    case "status":
    case "register-plugin":
    case "unregister-plugin":
    case "start-listener":
    case "open-remote-desktop":
    case "reveal-agent":
    case "collect-overview":
    case "collect-baseline":
    case "collect-processes":
    case "collect-network":
    case "collect-startup":
    case "collect-accounts":
      return keys();
    case "inspect-process":
      return keys("pid", "startTime") && Number.isInteger(value.pid) && (value.pid as number) > 0 && (value.pid as number) <= 4294967295 &&
        typeof value.startTime === "string" && value.startTime.length <= 64 && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)$/u.test(value.startTime) && Number.isFinite(Date.parse(value.startTime));
    case "send-chat":
      return keys("text") && isBoundedText(value.text, 8192);
    case "run-command":
      return keys("command") && isBoundedText(value.command, 16384);
    case "pull-file":
      return (
        keys("remotePath") &&
        isBoundedText(value.remotePath, 1024) &&
        !value.remotePath.includes("\n") &&
        !value.remotePath.includes("\r")
      );
    case "collect-logs":
      return keys("category") && typeof value.category === "string" &&
        ["all", "logon", "account", "service", "powershell", "failed-logon", "rdp", "defender", "tasks", "sysmon", "clear-log", "process", "security", "system", "application", "wmi"].includes(value.category);
    case "collect-files":
      return (
        keys("path") &&
        isBoundedText(value.path, 1024) &&
        !value.path.includes("\n") &&
        !value.path.includes("\r")
      );
    case "preview-file":
      return (
        keys("path") &&
        isBoundedText(value.path, 1024) &&
        !value.path.includes("\n") &&
        !value.path.includes("\r")
      );
    case "collect-registry":
      return (
        keys("keyPath") &&
        isBoundedText(value.keyPath, 1024) &&
        !value.keyPath.includes("\n") &&
        !value.keyPath.includes("\r")
      );
    case "remediate-baseline":
      return (
        keys("ruleId") &&
        isBoundedText(value.ruleId, 128) &&
        /^[a-z0-9-]+$/u.test(value.ruleId) &&
        value.ruleId !== "defender-tamper"
      );
    case "kill-process":
      return (
        keys("pid", "startTime") &&
        Number.isInteger(value.pid) &&
        (value.pid as number) > 4 &&
        (value.pid as number) <= 4294967295 &&
        typeof value.startTime === "string" &&
        value.startTime.length <= 64 &&
        /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)$/u.test(value.startTime) &&
        Number.isFinite(Date.parse(value.startTime))
      );
    case "remove-startup":
      return (
        keys("sourceType", "name", "location") &&
        isBoundedText(value.sourceType, 64) &&
        isBoundedText(value.name, 512) &&
        isBoundedText(value.location, 1024) &&
        ![value.sourceType, value.name, value.location].some((part) => part.includes("\n") || part.includes("\r"))
      );
    case "disable-account":
      return (
        keys("name", "sid") &&
        isBoundedText(value.name, 256) &&
        isBoundedText(value.sid, 128) &&
        !value.name.includes("\n") &&
        !value.name.includes("\r") &&
        /^S-1-[0-9-]+$/u.test(value.sid)
      );
    case "delete-file":
      return (
        keys("path", "dirPath") &&
        isBoundedText(value.path, 1024) &&
        isBoundedText(value.dirPath, 1024) &&
        ![value.path, value.dirPath].some((part) => part.includes("\n") || part.includes("\r"))
      );
    case "delete-registry-value":
      return (
        keys("keyPath", "valueName") &&
        isBoundedText(value.keyPath, 1024) &&
        isBoundedText(value.valueName, 512) &&
        ![value.keyPath, value.valueName].some((part) => part.includes("\n") || part.includes("\r"))
      );
    default:
      return false;
  }
}

type Check = (value: unknown) => boolean;
const text: Check = (value) => isBoundedText(value, 32 * 1024, true);
const shortText: Check = (value) => isBoundedText(value, 4096, true);
const boolean: Check = (value) => typeof value === "boolean";
const uint: Check = (value) => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
const percentage: Check = (value) => uint(value) && (value as number) <= 100;
const risk: Check = (value) => typeof value === "string" && ["high", "medium", "low", "normal"].includes(value);
const hash: Check = (value) => typeof value === "string" && (value === "" || /^[a-f0-9]{64}$/iu.test(value));
const nullable = (check: Check): Check => (value) => value === null || check(value);
const list = (check: Check, max: number): Check => (value) =>
  Array.isArray(value) && value.length <= max && value.every(check);
const object = (fields: Readonly<Record<string, Check>>): Check => (value) =>
  isRecord(value) && exactKeys(value, Object.keys(fields)) && Object.entries(fields).every(([key, check]) => check(value[key]));
const reasonList = list(shortText, 64);
const port: Check = (value) => uint(value) && (value as number) <= 65535;
const logCategory: Check = (value) => typeof value === "string" && ["all", "logon", "account", "service", "powershell", "failed-logon", "rdp", "defender", "tasks", "sysmon", "clear-log", "process", "security", "system", "application", "wmi"].includes(value);

const checkStatusShape = object({
  registration: object({ registered: boolean, clsid: shortText, addinName: shortText, localServerCommand: nullable(text) }),
  listenerRunning: boolean, rdpPluginInitialized: boolean, channelConnected: boolean,
  activeChannelName: nullable(shortText), connectedSince: nullable(shortText), sessionId: nullable(isWindowsFileId), messagesSent: uint, messagesReceived: uint,
  recentLogs: list(object({ timestamp: shortText, direction: shortText, kind: shortText, summary: text }), 200),
  receivedFiles: list(object({ fileId: shortText, name: shortText, sizeBytes: uint, sha256: hash, verified: boolean, receivedAt: shortText }), 32),
});
const checkStatus: Check = (value) => checkStatusShape(value) && isRecord(value) &&
  (!value.channelConnected || (typeof value.connectedSince === "string" && value.connectedSince.length > 0 && typeof value.activeChannelName === "string" && isWindowsFileId(value.sessionId)));

const checkOverview = object({
  hostname: shortText, osCaption: shortText, osVersion: shortText, architecture: shortText, domainOrWorkgroup: shortText,
  partOfDomain: boolean, currentUser: shortText, isElevated: boolean, sessionName: shortText, bootTime: shortText,
  uptimeHours: uint, cpuName: shortText, cpuCores: uint, cpuLoadPercent: percentage,
  memoryTotalMb: uint, memoryUsedMb: uint, memoryUsagePercent: percentage, systemDriveFreeGb: uint, systemDriveTotalGb: uint,
  defenderEnabled: nullable(boolean), realtimeProtection: nullable(boolean), firewallDomainEnabled: nullable(boolean), firewallPrivateEnabled: nullable(boolean),
  firewallPublicEnabled: nullable(boolean), highRiskCount: uint, mediumRiskCount: uint, highlights: reasonList, facts: list(object({ group: shortText, label: shortText, value: text }), 256), warnings: reasonList,
});
const checkBaseline = object({
  totalChecks: uint, passedCount: uint, failedCount: uint, warningCount: uint, unknownCount: uint,
  items: list(object({
    id: shortText, category: shortText, title: shortText, currentValue: text, expectedValue: text,
    status: (value) => typeof value === "string" && ["pass", "warn", "fail", "unknown"].includes(value),
    severity: risk, description: text, recommendation: text,
  }), 1024),
});
const checkProcesses = object({
  totalCount: uint, suspiciousCount: uint,
  processes: list(object({
    pid: uint, ppid: uint, name: shortText, executablePath: text, commandLine: text, user: shortText,
    sessionId: uint, workingSetMb: uint, startTime: shortText, riskLevel: risk, riskReasons: reasonList,
  }), 32768),
});
const checkNetwork = object({
  totalCount: uint, suspiciousCount: uint,
  connections: list(object({
    protocol: shortText, localAddress: shortText, localPort: port, remoteAddress: shortText, remotePort: port,
    state: shortText, pid: uint, processName: shortText, processPath: text, riskLevel: risk, riskReason: shortText,
  }), 32768),
});
const checkInspection = object({
  pid: uint, startTime: shortText, observedAt: shortText, user: shortText,
  services: list(object({ name: shortText, displayName: shortText, state: shortText, startMode: shortText, path: text, account: shortText }), 256),
  modules: list(object({ name: shortText, path: text, sizeBytes: uint }), 512),
  network: list(object({ protocol: shortText, localAddress: shortText, localPort: port, remoteAddress: shortText, remotePort: port, state: shortText, pid: uint, processName: shortText, processPath: text, riskLevel: risk, riskReason: shortText }), 2048),
  warnings: reasonList,
});
const checkStartup = object({
  totalCount: uint, suspiciousCount: uint,
  entries: list(object({
    sourceType: shortText, name: shortText, location: text, command: text, runAs: shortText, state: shortText,
    riskLevel: risk, riskReason: shortText,
  }), 8192),
});
const checkAccounts = object({
  totalCount: uint, adminCount: uint, suspiciousCount: uint,
  accounts: list(object({
    name: shortText, fullName: shortText, enabled: boolean, isAdmin: boolean, sid: shortText, rid: uint, lastLogon: shortText,
    passwordRequired: boolean, passwordExpires: boolean, riskLevel: risk, riskReasons: reasonList,
  }), 4096),
});
const checkLogs = object({
  categoryFilter: logCategory, totalCount: uint, highRiskCount: uint, warnings: reasonList,
  entries: list(object({
    recordId: uint, timeCreated: shortText, channel: shortText, eventId: uint, level: shortText, category: shortText,
    summary: text, detail: text, detailTruncated: boolean, riskLevel: risk,
  }), 4096),
});
const checkFilesShape = object({
  currentPath: text, totalEntries: uint, truncated: boolean,
  entries: list(object({
    name: shortText, fullPath: text, entryType: (value) => value === "dir" || value === "file", sizeBytes: uint,
    lastWriteTime: shortText, sha256: hash, hidden: boolean, system: boolean, riskLevel: risk, riskReason: shortText,
  }), 1000),
});
const checkFiles: Check = (value) => checkFilesShape(value) && isRecord(value) && Array.isArray(value.entries) &&
  (value.totalEntries as number) >= value.entries.length &&
  (value.truncated === true || value.totalEntries === value.entries.length);
const checkRegistry = object({
  keyPath: text, subkeys: list(shortText, 4096),
  values: list(object({ name: shortText, kind: shortText, data: text, truncated: boolean, riskLevel: risk, riskReason: shortText }), 4096),
  warnings: reasonList,
});
const checkPreviewShape = object({
  fullPath: (value) => isBoundedText(value, 32 * 1024),
  sizeBytes: uint, lastWriteTime: shortText, previewB64: text, previewBytes: uint, truncated: boolean,
});
const checkPreview: Check = (value) => {
  // The content cap is 16 KiB, before Base64 expansion.
  if (!isRecord(value) || !checkPreviewShape(value)) return false;
  const b64 = value.previewB64 as string;
  const bytes = value.previewBytes as number;
  if (bytes > 16384 || bytes > (value.sizeBytes as number) || b64.length > 21848 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(b64)) return false;
  const decodedLength = b64.length / 4 * 3 - (b64.endsWith("==") ? 2 : b64.endsWith("=") ? 1 : 0);
  return bytes === decodedLength && value.truncated === ((value.sizeBytes as number) > bytes);
};

function snapshotResponse(value: JsonRecord, kind: string, check: Check): boolean {
  return value.kind === kind && exactKeys(value, ["kind", "snapshot"]) && check(value.snapshot);
}

export function matchesWindowsIncidentResponse(
  request: WindowsIncidentRequest,
  value: unknown,
): value is WindowsIncidentResponse {
  if (!isRecord(value) || typeof value.kind !== "string") return false;
  switch (request.action) {
    case "status":
    case "register-plugin":
    case "unregister-plugin":
    case "start-listener":
    case "open-remote-desktop":
    case "reveal-agent":
    case "send-chat":
    case "pull-file":
      return (
        value.kind === "status" &&
        exactKeys(value, ["kind", "status", "filelessScript"]) &&
        checkStatus(value.status) &&
        isBoundedText(value.filelessScript, 128 * 1024, true)
      );
    case "run-command":
      return (
        value.kind === "command-output" &&
        exactKeys(value, ["kind", "output", "status"]) &&
        isBoundedText(value.output, 2 * 1024 * 1024, true) &&
        checkStatus(value.status)
      );
    case "collect-overview":
      return snapshotResponse(value, "overview", checkOverview);
    case "collect-baseline":
    case "remediate-baseline":
      return snapshotResponse(value, "baseline", checkBaseline);
    case "collect-processes":
    case "kill-process":
      return snapshotResponse(value, "processes", checkProcesses);
    case "inspect-process":
      return value.kind === "process-inspection" && exactKeys(value, ["kind", "inspection"]) && checkInspection(value.inspection) &&
        isRecord(value.inspection) && value.inspection.pid === request.pid && value.inspection.startTime === request.startTime &&
        (value.inspection.network as WindowsNetworkEntry[]).every((entry) => entry.pid === request.pid);
    case "collect-network":
      return snapshotResponse(value, "network", checkNetwork);
    case "collect-startup":
    case "remove-startup":
      return snapshotResponse(value, "startup", checkStartup);
    case "collect-accounts":
    case "disable-account":
      return snapshotResponse(value, "accounts", checkAccounts);
    case "collect-logs":
      return snapshotResponse(value, "logs", checkLogs);
    case "collect-files":
    case "delete-file":
      return snapshotResponse(value, "files", checkFiles);
    case "preview-file":
      return (
        value.kind === "file-preview" &&
        exactKeys(value, ["kind", "preview"]) &&
        checkPreview(value.preview)
      );
    case "collect-registry":
    case "delete-registry-value":
      return snapshotResponse(value, "registry", checkRegistry);
  }
}
