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
  | { action: "inspect-file-access"; path: string }
  | { action: "collect-registry"; keyPath: string }
  | { action: "plan-baseline"; ruleIds: string[] }
  | { action: "apply-baseline-plan" | "discard-baseline-plan" | "cancel-baseline-plan" | "baseline-plan-progress"; planId: string }
  | { action: "baseline-history" }
  | { action: "plan-baseline-restore"; recordId: string }
  | { action: "collect-inventory"; kind: WindowsInventoryKind }
  | { action: "plan-control"; objectId: string; operation: WindowsControlOperation }
  | { action: "inspect-inventory"; objectId: string }
  | { action: "apply-control" | "discard-control-plan"; planId: string }
  | { action: "control-history" }
  | { action: "plan-control-restore"; recordId: string }
  | { action: "plan-process-change"; pid: number; startTime: string; tree: boolean }
  | { action: "apply-process-plan" | "discard-process-plan"; planId: string }
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
  status: "pass" | "warn" | "fail" | "unknown" | "not-applicable";
  severity: WindowsRiskLevel;
  description: string;
  recommendation: string;
  remediationAvailable: boolean;
}

export interface WindowsBaselineSnapshot {
  totalChecks: number;
  passedCount: number;
  failedCount: number;
  warningCount: number;
  unknownCount: number;
  notApplicableCount: number;
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

export const WINDOWS_STARTUP_CATEGORIES = ["logon","explorer","internet-explorer","services","drivers","codecs","winsock","print","lsa","network","boot-execute","image-hijacks","app-init","known-dlls","winlogon","ime","tasks","gadgets","folder-extensions"] as const;
export type WindowsStartupCategory = typeof WINDOWS_STARTUP_CATEGORIES[number];
export interface WindowsStartupCategoryResult { category: WindowsStartupCategory; count: number; status: "complete" | "partial" | "unavailable"; message: string }
export interface WindowsStartupEntry {
  category: WindowsStartupCategory;
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
  categories: WindowsStartupCategoryResult[];
  warnings: string[];
  observedAt: string;
  truncated: boolean;
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
export interface WindowsFileAccess { path: string; observedAt: string; attributes: string; owner: string; accessRules: { identity: string; rights: string; access: "Allow" | "Deny"; inherited: boolean }[]; processes: { pid: number; name: string }[]; services: { name: string; displayName: string; state: string; startMode: string; path: string; kind: "driver" | "service" }[]; warnings: string[] }
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

export const WINDOWS_BASELINE_CHANGE_IDS = ["rdp-nla", "rdp-encryption", "rdp-security-layer", "wdigest", "uac", "uac-prompt", "uac-secure-desktop", "uac-filter-admin", "blank-password", "anonymous", "anonymous-sam", "ntlm", "lm-hash", "winrm-basic", "winrm-cleartext", "installer-machine", "installer-user", "autorun", "ps-scriptblock-logging"] as const;
export interface WindowsBaselinePlanItem { id: string; title: string; location: string; currentValue: string; expectedValue: string; impact: string }
export interface WindowsBaselineChangePlan { id: string; target: string; expiresAt: number; restoring: boolean; items: WindowsBaselinePlanItem[]; notes: string[] }
export type WindowsBaselineChangeState = "pending" | "applying" | "verified" | "restored" | "refused" | "uncertain" | "skipped";
export interface WindowsBaselineChangeReport { id: string; target: string; createdAt: number; restoring: boolean; finished: boolean; recoveryAvailable: boolean; items: { id: string; title: string; state: WindowsBaselineChangeState }[]; message: string }

export type WindowsInventoryKind = "services" | "drivers" | "tasks";
export interface WindowsInventoryEntry { objectId: string | null; name: string; displayName: string; location: string; command: string; account: string; state: string; startMode: string; pid: number; details: string[]; riskLevel: WindowsRiskLevel; riskReason: string }
export interface WindowsInventorySnapshot { kind: WindowsInventoryKind; observedAt: string; totalCount: number; truncated: boolean; warnings: string[]; entries: WindowsInventoryEntry[] }
export interface WindowsProcessPlan { id: string; target: string; expiresAt: number; tree: boolean; items: { pid: number; ppid: number; name: string; startTime: string }[] }
export interface WindowsProcessChangeReport { id: string; items: { pid: number; state: "verified" | "refused" | "failed" | "skipped" | "uncertain" }[]; message: string }
export const WINDOWS_CONTROL_OPERATIONS = ["start","stop","restart","automatic","manual","enable","disable","run","delete"] as const;
export interface WindowsInventoryDetails { objectId: string; target: string; kind: WindowsInventoryKind; name: string; observedAt: string; fields: {label:string;value:string}[]; warnings: string[] }
export type WindowsControlOperation = typeof WINDOWS_CONTROL_OPERATIONS[number];
export interface WindowsControlPlan { id: string; target: string; kind: WindowsInventoryKind; name: string; operation: WindowsControlOperation; command: string; currentState: string; beforeSetting: string; afterSetting: string; impact: string[]; restoring: boolean; expiresAt: number }
export interface WindowsControlReport { id: string; target: string; kind: WindowsInventoryKind; name: string; operation: WindowsControlOperation; state: "verified" | "submitted" | "refused" | "uncertain"; message: string; canRestore: boolean; createdAt: number }

export type WindowsIncidentResponse =
  | { kind: "control-plan"; plan: WindowsControlPlan }
  | { kind: "inventory-details"; details: WindowsInventoryDetails }
  | { kind: "control-report"; report: WindowsControlReport }
  | { kind: "control-history"; records: WindowsControlReport[] }
  | { kind: "inventory"; snapshot: WindowsInventorySnapshot }
  | { kind: "process-plan"; plan: WindowsProcessPlan }
  | { kind: "process-change"; report: WindowsProcessChangeReport }
  | { kind: "baseline-plan"; plan: WindowsBaselineChangePlan }
  | { kind: "baseline-change"; report: WindowsBaselineChangeReport }
  | { kind: "baseline-progress"; report: WindowsBaselineChangeReport | null }
  | { kind: "baseline-history"; records: WindowsBaselineChangeReport[] }
  | { kind: "baseline-acknowledged"; accepted: boolean }
  | { kind: "baseline-change-error"; message: string }
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
  | { kind: "file-access"; inspection: WindowsFileAccess }
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
    case "plan-baseline":
      return keys("ruleIds") && Array.isArray(value.ruleIds) && value.ruleIds.length>0 && value.ruleIds.length<=19 && new Set(value.ruleIds).size===value.ruleIds.length && value.ruleIds.every(isBaselineChangeId);
    case "apply-baseline-plan": case "discard-baseline-plan": case "cancel-baseline-plan": case "baseline-plan-progress":
      return keys("planId") && isWindowsFileId(value.planId);
    case "plan-baseline-restore": return keys("recordId") && isWindowsFileId(value.recordId);
    case "baseline-history": return keys();
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
    case "inspect-file-access":
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
    case "collect-inventory": return keys("kind") && ["services","drivers","tasks"].includes(value.kind as string);
    case "plan-control": return keys("objectId","operation") && isWindowsFileId(value.objectId) && controlOperation(value.operation);
    case "inspect-inventory": return keys("objectId") && isWindowsFileId(value.objectId);
    case "apply-control": case "discard-control-plan": return keys("planId") && isWindowsFileId(value.planId);
    case "control-history": return keys();
    case "plan-control-restore": return keys("recordId") && isWindowsFileId(value.recordId);
    case "apply-process-plan": case "discard-process-plan": return keys("planId") && isWindowsFileId(value.planId);
    case "plan-process-change":
      return keys("pid","startTime","tree") && typeof value.tree === "boolean" && isWindowsIncidentRequest({action:"kill-process",pid:value.pid,startTime:value.startTime,sessionId:value.sessionId});
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
const checkBaselineShape = object({
  totalChecks: uint, passedCount: uint, failedCount: uint, warningCount: uint, unknownCount: uint, notApplicableCount: uint,
  items: list(object({
    id: shortText, category: shortText, title: shortText, currentValue: text, expectedValue: text,
    status: (value) => typeof value === "string" && ["pass", "warn", "fail", "unknown", "not-applicable"].includes(value),
    severity: risk, description: text, recommendation: text, remediationAvailable: boolean,
  }), 1024),
});
const checkBaseline: Check = (value) => {
  if (!checkBaselineShape(value)) return false;
  const snapshot = value as WindowsBaselineSnapshot;
  const ids = new Set(snapshot.items.map((item) => item.id));
  const counts = { pass: snapshot.passedCount, fail: snapshot.failedCount, warn: snapshot.warningCount, unknown: snapshot.unknownCount, "not-applicable": snapshot.notApplicableCount };
  return ids.size === snapshot.items.length && snapshot.totalChecks === snapshot.items.length &&
    Object.entries(counts).every(([status, count]) => snapshot.items.filter((item) => item.status === status).length === count) &&
    snapshot.items.every((item) => !item.remediationAvailable || (isBaselineChangeId(item.id) && (item.status === "fail" || item.status === "warn")));
};
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
const startupCategory: Check = (v) => typeof v === "string" && (WINDOWS_STARTUP_CATEGORIES as readonly string[]).includes(v);
const checkStartupShape = object({
  totalCount: uint, suspiciousCount: uint,
  entries: list(object({
    category: startupCategory,
    sourceType: shortText, name: shortText, location: text, command: text, runAs: shortText, state: shortText,
    riskLevel: risk, riskReason: shortText,
  }), 4000),
  observedAt: shortText, truncated: boolean, warnings: reasonList,
  categories: list(object({category:startupCategory,count:uint,status:(v)=>["complete","partial","unavailable"].includes(v as string),message:shortText}),19),
});
const checkStartup: Check = (value) => {
  if (!checkStartupShape(value)) return false;
  const s=value as WindowsStartupSnapshot;
  return Number.isFinite(Date.parse(s.observedAt)) && s.totalCount===s.entries.length && s.categories.length===19 && new Set(s.categories.map(c=>c.category)).size===19 && s.categories.every(c=>c.count===s.entries.filter(e=>e.category===c.category).length);
};
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
  if (["inspect-inventory","plan-control","apply-control","discard-control-plan","control-history","plan-control-restore","plan-process-change", "apply-process-plan", "discard-process-plan", "plan-baseline", "apply-baseline-plan", "discard-baseline-plan", "cancel-baseline-plan", "baseline-plan-progress", "baseline-history", "plan-baseline-restore"].includes(request.action) && value.kind === "baseline-change-error") return exactKeys(value,["kind","message"]) && isBoundedText(value.message,2048);
  switch (request.action) {
    case "plan-control": return value.kind==="control-plan" && exactKeys(value,["kind","plan"]) && isWindowsControlPlan(value.plan) && !value.plan.restoring && value.plan.operation===request.operation;
    case "inspect-inventory": return value.kind==="inventory-details" && exactKeys(value,["kind","details"]) && isWindowsInventoryDetails(value.details) && value.details.objectId===request.objectId;
    case "plan-control-restore": return value.kind==="control-plan" && exactKeys(value,["kind","plan"]) && isWindowsControlPlan(value.plan) && value.plan.restoring;
    case "apply-control": return value.kind==="control-report" && exactKeys(value,["kind","report"]) && isWindowsControlReport(value.report) && value.report.id===request.planId;
    case "discard-control-plan": return value.kind==="baseline-acknowledged" && exactKeys(value,["kind","accepted"]) && value.accepted===true;
    case "control-history": return value.kind==="control-history" && exactKeys(value,["kind","records"]) && list(isWindowsControlReport,100)(value.records);
    case "collect-inventory": return value.kind === "inventory" && exactKeys(value,["kind","snapshot"]) && isWindowsInventorySnapshot(value.snapshot) && value.snapshot.kind === request.kind;
    case "plan-process-change": return value.kind === "process-plan" && exactKeys(value,["kind","plan"]) && isWindowsProcessPlan(value.plan) && value.plan.tree === request.tree && value.plan.items[0]?.pid === request.pid && value.plan.items[0]?.startTime === request.startTime;
    case "apply-process-plan": return value.kind === "process-change" && exactKeys(value,["kind","report"]) && isWindowsProcessChangeReport(value.report) && value.report.id === request.planId;
    case "discard-process-plan": return value.kind === "baseline-acknowledged" && exactKeys(value,["kind","accepted"]) && typeof value.accepted === "boolean";
    case "inspect-file-access": return value.kind === "file-access" && exactKeys(value,["kind","inspection"]) && object({ path: shortText, observedAt: shortText, attributes: shortText, owner: shortText, accessRules: list(object({identity:shortText,rights:shortText,access:(v)=>v==="Allow"||v==="Deny",inherited:boolean}),64), processes:list(object({pid:uint,name:shortText}),256), services:list(object({name:shortText,displayName:shortText,state:shortText,startMode:shortText,path:text,kind:(v)=>v==="driver"||v==="service"}),256),warnings:list(shortText,16)})(value.inspection);
    case "plan-baseline": case "plan-baseline-restore":
      return value.kind === "baseline-plan" && exactKeys(value,["kind","plan"]) && isBaselineChangePlan(value.plan) && value.plan.restoring === (request.action === "plan-baseline-restore") && (request.action !== "plan-baseline" || value.plan.items.every((item) => request.ruleIds.includes(item.id)));
    case "apply-baseline-plan": return value.kind === "baseline-change" && exactKeys(value,["kind","report"]) && isBaselineChangeReport(value.report) && value.report.id === request.planId && value.report.finished;
    case "baseline-plan-progress": return value.kind === "baseline-progress" && exactKeys(value,["kind","report"]) && (value.report === null || (isBaselineChangeReport(value.report) && value.report.id === request.planId));
    case "baseline-history": return value.kind === "baseline-history" && exactKeys(value,["kind","records"]) && Array.isArray(value.records) && value.records.length<=100 && value.records.every(isBaselineChangeReport) && new Set(value.records.map((r) => r.id)).size === value.records.length;
    case "discard-baseline-plan": case "cancel-baseline-plan": return value.kind === "baseline-acknowledged" && exactKeys(value,["kind","accepted"]) && typeof value.accepted === "boolean";
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

function isBaselineChangeId(value: unknown): value is string { return typeof value === "string" && (WINDOWS_BASELINE_CHANGE_IDS as readonly string[]).includes(value); }
function isEpoch(value: unknown): value is number { return typeof value === "number" && Number.isSafeInteger(value) && value>0; }
function isBaselineChangePlan(value: unknown): value is WindowsBaselineChangePlan {
  return isRecord(value) && exactKeys(value,["id","target","expiresAt","restoring","items","notes"]) && isWindowsFileId(value.id) && isBoundedText(value.target,255) && isEpoch(value.expiresAt) && typeof value.restoring === "boolean" && Array.isArray(value.notes) && value.notes.length<=10 && value.notes.every((v) => isBoundedText(v,2048)) && Array.isArray(value.items) && value.items.length<=19 && value.items.every((item) => isRecord(item) && exactKeys(item,["id","title","location","currentValue","expectedValue","impact"]) && isBaselineChangeId(item.id) && isBoundedText(item.title,256) && isBoundedText(item.location,1024) && isBoundedText(item.currentValue,256) && isBoundedText(item.expectedValue,256) && isBoundedText(item.impact,2048)) && new Set(value.items.map((v) => v.id)).size===value.items.length;
}
function isBaselineChangeReport(value: unknown): value is WindowsBaselineChangeReport {
  if (!isRecord(value) || !exactKeys(value,["id","target","createdAt","restoring","finished","recoveryAvailable","items","message"]) || !isWindowsFileId(value.id) || !isBoundedText(value.target,255) || !isEpoch(value.createdAt) || typeof value.restoring!=="boolean" || typeof value.finished!=="boolean" || typeof value.recoveryAvailable!=="boolean" || !isBoundedText(value.message,2048) || !Array.isArray(value.items) || value.items.length<1 || value.items.length>19) return false;
  return value.items.every((item) => isRecord(item) && exactKeys(item,["id","title","state"]) && isBaselineChangeId(item.id) && isBoundedText(item.title,256) && typeof item.state==="string" && ["pending","applying","verified","restored","refused","uncertain","skipped"].includes(item.state) && (!value.finished || !["pending","applying"].includes(item.state))) && new Set(value.items.map((v) => v.id)).size===value.items.length && value.recoveryAvailable===(!value.restoring && value.items.some((v) => v.state==="verified"));
}

export function isWindowsProcessPlan(value: unknown): value is WindowsProcessPlan {
  if (!isRecord(value) || !exactKeys(value,["id","target","expiresAt","tree","items"]) || !isWindowsFileId(value.id) || !isBoundedText(value.target,255) || !isEpoch(value.expiresAt) || typeof value.tree !== "boolean" || !Array.isArray(value.items) || value.items.length < 1 || value.items.length > 64 || (!value.tree && value.items.length !== 1)) return false;
  const seen = new Map<number, number>();
  return value.items.every((item, index) => {
    if (!isRecord(item) || !exactKeys(item,["pid","ppid","name","startTime"]) || !isBoundedText(item.name,260) || !uint(item.ppid) || !isWindowsIncidentRequest({action:"kill-process",pid:item.pid,startTime:item.startTime,sessionId:"00000000-0000-0000-0000-000000000000"})) return false;
    const pid = item.pid as number, time = Date.parse(item.startTime as string) * 1000 + Number(((item.startTime as string).match(/\.(\d+)/u)?.[1] ?? "").padEnd(6,"0").slice(3,6));
    if (seen.has(pid) || (index > 0 && (!seen.has(item.ppid as number) || seen.get(item.ppid as number)! >= time))) return false;
    seen.set(pid,time); return true;
  });
}
export function isWindowsProcessChangeReport(value: unknown): value is WindowsProcessChangeReport {
  return isRecord(value) && exactKeys(value,["id","items","message"]) && isWindowsFileId(value.id) && isBoundedText(value.message,2048) && Array.isArray(value.items) && value.items.length > 0 && value.items.length <= 64 && value.items.every((item) => isRecord(item) && exactKeys(item,["pid","state"]) && uint(item.pid) && (item.pid as number)>4 && typeof item.state === "string" && ["verified","refused","failed","skipped","uncertain"].includes(item.state)) && new Set(value.items.map((item) => item.pid)).size===value.items.length;
}

export function isWindowsInventorySnapshot(value: unknown): value is WindowsInventorySnapshot {
  if (!isRecord(value) || !exactKeys(value,["kind","observedAt","totalCount","truncated","warnings","entries"]) || !["services","drivers","tasks"].includes(value.kind as string) || !isBoundedText(value.observedAt,64) || !Number.isFinite(Date.parse(value.observedAt)) || !uint(value.totalCount) || typeof value.truncated !== "boolean" || !list((v) => isBoundedText(v,1024),32)(value.warnings) || !Array.isArray(value.entries) || value.entries.length > 2000 || (value.totalCount as number) < value.entries.length) return false;
  if ((value.totalCount as number) !== value.entries.length && !value.truncated && (value.warnings as string[]).length === 0) return false;
  return value.entries.every(object({objectId:nullable(isWindowsFileId),name:(v)=>isBoundedText(v,1024),displayName:(v)=>isBoundedText(v,1024,true),location:(v)=>isBoundedText(v,2048,true),command:(v)=>isBoundedText(v,8192,true),account:(v)=>isBoundedText(v,1024,true),state:(v)=>isBoundedText(v,256,true),startMode:(v)=>isBoundedText(v,256,true),pid:uint,details:list((v)=>isBoundedText(v,4096,true),32),riskLevel:risk,riskReason:(v)=>isBoundedText(v,1024,true)}));
}
function controlOperation(value:unknown): value is WindowsControlOperation {return typeof value==="string" && (WINDOWS_CONTROL_OPERATIONS as readonly string[]).includes(value);}
function controlKind(value:unknown): value is WindowsInventoryKind {return typeof value==="string" && ["services","drivers","tasks"].includes(value);}
function validControlOperation(kind: WindowsInventoryKind, operation: WindowsControlOperation): boolean { return (kind==="tasks"?["run","stop","enable","disable","delete"]:["start","stop","restart","automatic","manual","disable","delete"]).includes(operation); }
export function isWindowsInventoryDetails(value: unknown): value is WindowsInventoryDetails {
  return isRecord(value) && exactKeys(value,["objectId","target","kind","name","observedAt","fields","warnings"]) && isWindowsFileId(value.objectId) && isBoundedText(value.target,255) && controlKind(value.kind) && isBoundedText(value.name,1024) && isBoundedText(value.observedAt,64) && Number.isFinite(Date.parse(value.observedAt)) && Array.isArray(value.fields) && value.fields.length>0 && list(object({label:v=>isBoundedText(v,128),value:v=>isBoundedText(v,8192,true)}),96)(value.fields) && list(v=>isBoundedText(v,1024),16)(value.warnings);
}
export function isWindowsControlPlan(value:unknown):value is WindowsControlPlan {
  return isRecord(value)&&exactKeys(value,["id","target","kind","name","operation","command","currentState","beforeSetting","afterSetting","impact","restoring","expiresAt"])&&isWindowsFileId(value.id)&&isBoundedText(value.target,255)&&controlKind(value.kind)&&isBoundedText(value.name,1024)&&controlOperation(value.operation)&&validControlOperation(value.kind,value.operation)&&isBoundedText(value.command,8192,true)&&isBoundedText(value.currentState,64,true)&&isBoundedText(value.beforeSetting,256)&&isBoundedText(value.afterSetting,256)&&list((v)=>isBoundedText(v,2048),12)(value.impact)&&typeof value.restoring==="boolean"&&(!value.restoring||["automatic","manual","enable","disable"].includes(value.operation))&&isEpoch(value.expiresAt);
}
export function isWindowsControlReport(value:unknown):value is WindowsControlReport {
  return isRecord(value)&&exactKeys(value,["id","target","kind","name","operation","state","message","canRestore","createdAt"])&&isWindowsFileId(value.id)&&isBoundedText(value.target,255)&&controlKind(value.kind)&&isBoundedText(value.name,1024)&&controlOperation(value.operation)&&validControlOperation(value.kind,value.operation)&&["verified","submitted","refused","uncertain"].includes(value.state as string)&&(value.state!=="submitted"||value.kind==="tasks"&&value.operation==="run")&&!(value.operation==="run"&&value.state==="verified")&&isBoundedText(value.message,2048)&&typeof value.canRestore==="boolean"&&(!value.canRestore||value.state==="verified"&&["automatic","manual","enable","disable"].includes(value.operation))&&isEpoch(value.createdAt);
}
