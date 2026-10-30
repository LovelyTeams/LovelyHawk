/**
 * 应急处置（扫描 → 逐项修复 → 复验）的页面侧契约。
 *
 * 页面只提交经验证的操作意图：修复对象永远用后端在扫描时签发的不透明句柄
 * 指代，请求里不出现路径、命令、账户名或口令。后端响应按 kind 判别标签
 * 逐字段校验，校验不过的响应不进入页面。
 */

export const RESPONSE_ENGINE_ACTIONS = [
  "scan",
  "poll-scan",
  "plan-fix",
  "confirm-fix",
  "cancel-fix",
  "execute-fix",
  "poll-fix",
] as const;

export type ResponseEngineAction = (typeof RESPONSE_ENGINE_ACTIONS)[number];

export type ResponseIssueKind =
  | "hijacked-command"
  | "uid-zero-account"
  | "empty-password"
  | "suspicious-account"
  | "malicious-sudoers"
  | "cron-persistence"
  | "backdoor-process"
  | "ld-preload-hijack"
  | "path-injection"
  | "ssh-key-backdoor"
  | "pam-backdoor"
  | "bind-listener"
  | "stash-dir"
  | "web-sensitive-file"
  | "webshell"
  | "command-recorder"
  | "history-credential-leak"
  | "session-env-hook"
  | "preload-residue";

export type ResponseSeverity = "critical" | "high" | "medium" | "low";

/** 账户类修复的方式：锁定（默认、可逆）或删除（不可逆，仅空口令类接受）。 */
export type ResponseFixMode = "lock" | "remove";

export type ResponseFixStage = "running" | "verify-pending" | "completed" | "failed";

export interface ResponseIssue {
  issueHandle: string;
  kind: ResponseIssueKind;
  severity: ResponseSeverity;
  summary: string;
  evidence: string[];
  fixable: boolean;
  fixSummary: string | null;
}

export interface ResponseEngineScan {
  kind: "scan";
  scanHandle: string;
  scannedAt: string;
  truncated: boolean;
  gaps: string[];
  issues: ResponseIssue[];
}

/** scan 已在后台开始；用 poll-scan 跟随阶段直到拿到完整结果。 */
export interface ResponseEngineScanStarted {
  kind: "scan-started";
  scanHandle: string;
}

export type ResponseScanStage = "running" | "completed" | "failed";

/** 扫描进度：running 时 percent 是后端真实到达的阶段刻度（不是连续动画）。 */
export interface ResponseEngineScanStatus {
  kind: "scan-status";
  scanHandle: string;
  stage: ResponseScanStage;
  stageLabel: string;
  percent: number;
  scan: ResponseEngineScan | null;
  error: string | null;
}

export interface ResponseEnginePlan {
  kind: "plan";
  planHandle: string;
  summary: string;
  steps: string[];
  impact: string;
  rollbackNote: string | null;
  expiresInSeconds: number;
}

export interface ResponseEngineConfirmed {
  kind: "confirmed";
  planHandle: string;
  confirmed: boolean;
  expiresInSeconds: number;
}

export interface ResponseEngineCancelled {
  kind: "cancelled";
  cancelled: boolean;
}

export interface ResponseEngineExecution {
  kind: "execution";
  operationHandle: string;
}

export interface ResponseEngineStatus {
  kind: "status";
  operationHandle: string;
  stage: ResponseFixStage;
  summary: string;
  verifyPassed: boolean | null;
}

export type ResponseEngineResponse =
  | ResponseEngineScan
  | ResponseEngineScanStarted
  | ResponseEngineScanStatus
  | ResponseEnginePlan
  | ResponseEngineConfirmed
  | ResponseEngineCancelled
  | ResponseEngineExecution
  | ResponseEngineStatus;

type Binding = { bindingHandle: string };
export type ResponseEngineRequest = Binding & (
  | { action: "scan"; kinds?: ResponseIssueKind[] }
  | { action: "poll-scan"; scanHandle: string }
  | { action: "plan-fix"; issueHandle: string; mode?: ResponseFixMode }
  | { action: "confirm-fix" | "cancel-fix" | "execute-fix"; planHandle: string }
  | { action: "poll-fix"; operationHandle: string }
);

export interface ResponseEngineApi {
  responseEngine(request: ResponseEngineRequest): Promise<unknown>;
}

export const RESPONSE_ENGINE_API_METHODS = [
  "responseEngine",
] as const satisfies readonly (keyof ResponseEngineApi)[];

type AssertNever<T extends never> = T;
export type ResponseEngineApiMethodCoverage = AssertNever<
  Exclude<keyof ResponseEngineApi, (typeof RESPONSE_ENGINE_API_METHODS)[number]>
>;

const ISSUE_KINDS: readonly ResponseIssueKind[] = [
  "hijacked-command",
  "uid-zero-account",
  "empty-password",
  "suspicious-account",
  "malicious-sudoers",
  "cron-persistence",
  "backdoor-process",
  "ld-preload-hijack",
  "path-injection",
  "ssh-key-backdoor",
  "pam-backdoor",
  "bind-listener",
  "stash-dir",
  "web-sensitive-file",
  "webshell",
  "command-recorder",
  "history-credential-leak",
  "session-env-hook",
  "preload-residue",
];
const SEVERITIES: readonly ResponseSeverity[] = ["critical", "high", "medium", "low"];
const FIX_STAGES: readonly ResponseFixStage[] = [
  "running",
  "verify-pending",
  "completed",
  "failed",
];

/** Mirrors the backend's MAX_HANDLE_BYTES. */
const MAX_HANDLE_BYTES = 128;
const MAX_ISSUES = 64;
const MAX_EVIDENCE_PER_ISSUE = 32;
const MAX_EVIDENCE_TEXT_BYTES = 1_024;
const MAX_GAPS = 32;
const MAX_PLAN_STEPS = 32;
const MAX_TEXT_BYTES = 2_048;
/** Mirrors the backend's MAX_RESPONSE_BYTES. */
const MAX_RESPONSE_BYTES = 512 * 1_024;

const encoder = new TextEncoder();

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function keys(value: Record<string, unknown>, names: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === names.length && names.every((name) => actual.includes(name));
}

function text(value: unknown, maximumBytes: number, allowEmpty = false): value is string {
  return typeof value === "string" && (allowEmpty || value.length > 0) &&
    encoder.encode(value).byteLength <= maximumBytes &&
    !/[\u0000-\u001f\u007f]/u.test(value);
}

/** A bounded label shown as-is; remote text must not carry control bytes. */
function displayText(value: unknown, maximumBytes: number): value is string {
  return text(value, maximumBytes) && !/[\u0080-\u009f]/u.test(value);
}

export function isResponseEngineHandle(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 &&
    encoder.encode(value).byteLength <= MAX_HANDLE_BYTES &&
    /^[A-Za-z0-9-]+$/u.test(value);
}

function isIssueKind(value: unknown): value is ResponseIssueKind {
  return typeof value === "string" && ISSUE_KINDS.includes(value as ResponseIssueKind);
}

function isSeverity(value: unknown): value is ResponseSeverity {
  return typeof value === "string" && SEVERITIES.includes(value as ResponseSeverity);
}

function isFixMode(value: unknown): value is ResponseFixMode {
  return value === "lock" || value === "remove";
}

export function isResponseEngineRequest(value: unknown): value is ResponseEngineRequest {
  if (!record(value) || typeof value.action !== "string" ||
    !isResponseEngineHandle(value.bindingHandle)) return false;
  switch (value.action) {
    case "scan":
      return (keys(value, ["action", "bindingHandle"]) ||
        keys(value, ["action", "bindingHandle", "kinds"])) &&
        (value.kinds === undefined || isKindSelection(value.kinds));
    case "poll-scan":
      return keys(value, ["action", "bindingHandle", "scanHandle"]) &&
        isResponseEngineHandle(value.scanHandle) &&
        value.scanHandle !== value.bindingHandle;
    case "plan-fix":
      return (keys(value, ["action", "bindingHandle", "issueHandle"]) ||
        keys(value, ["action", "bindingHandle", "issueHandle", "mode"])) &&
        isResponseEngineHandle(value.issueHandle) &&
        value.issueHandle !== value.bindingHandle &&
        (value.mode === undefined || isFixMode(value.mode));
    case "confirm-fix":
    case "cancel-fix":
    case "execute-fix":
      return keys(value, ["action", "bindingHandle", "planHandle"]) &&
        isResponseEngineHandle(value.planHandle) && value.planHandle !== value.bindingHandle;
    case "poll-fix":
      return keys(value, ["action", "bindingHandle", "operationHandle"]) &&
        isResponseEngineHandle(value.operationHandle) && value.operationHandle !== value.bindingHandle;
    default:
      return false;
  }
}

function boundedTextList(value: unknown, maximumItems: number, maximumBytes: number): value is string[] {
  return Array.isArray(value) && value.length <= maximumItems &&
    value.every((item) => displayText(item, maximumBytes)) &&
    value.reduce((total, item) => total + encoder.encode(item).byteLength, 0) <= 64 * 1_024;
}

function issue(value: unknown): value is ResponseIssue {
  return record(value) && keys(value, [
    "issueHandle", "kind", "severity", "summary", "evidence", "fixable", "fixSummary",
  ]) && isResponseEngineHandle(value.issueHandle) && isIssueKind(value.kind) &&
    isSeverity(value.severity) && displayText(value.summary, MAX_TEXT_BYTES) &&
    boundedTextList(value.evidence, MAX_EVIDENCE_PER_ISSUE, MAX_EVIDENCE_TEXT_BYTES) &&
    typeof value.fixable === "boolean" &&
    (value.fixSummary === null || displayText(value.fixSummary, MAX_TEXT_BYTES));
}

function scan(value: unknown): value is ResponseEngineScan {
  if (!record(value) || !keys(value, ["kind", "scanHandle", "scannedAt", "truncated", "gaps", "issues"]) ||
    !isResponseEngineHandle(value.scanHandle) ||
    !text(value.scannedAt, 64) || Number.isNaN(Date.parse(value.scannedAt as string)) ||
    typeof value.truncated !== "boolean" ||
    !boundedTextList(value.gaps, MAX_GAPS, MAX_TEXT_BYTES) ||
    !Array.isArray(value.issues) || value.issues.length > MAX_ISSUES ||
    !value.issues.every(issue)) return false;
  const handles = value.issues.map((item) => (item as ResponseIssue).issueHandle);
  return new Set(handles).size === handles.length && !handles.includes(value.scanHandle as string);
}

/** 扫描项选择：闭合类别、去重、有上限；空列表没有意义，由调用方避免。 */
function isKindSelection(value: unknown): value is ResponseIssueKind[] {
  return Array.isArray(value) && value.length > 0 && value.length <= ISSUE_KINDS.length &&
    value.every(isIssueKind) &&
    new Set(value as ResponseIssueKind[]).size === (value as ResponseIssueKind[]).length;
}

function scanStatus(value: unknown): value is ResponseEngineScanStatus {
  if (!record(value) || !keys(value, [
    "kind", "scanHandle", "stage", "stageLabel", "percent", "scan", "error",
  ]) || !isResponseEngineHandle(value.scanHandle) ||
    typeof value.stage !== "string" ||
    !SCAN_STAGES.includes(value.stage as ResponseScanStage) ||
    !displayText(value.stageLabel, MAX_TEXT_BYTES) ||
    typeof value.percent !== "number" ||
    !Number.isSafeInteger(value.percent) || value.percent < 0 || value.percent > 100) {
    return false;
  }
  if (value.stage === "running") {
    return value.scan === null && value.error === null;
  }
  if (value.stage === "completed") {
    return value.error === null && scan(value.scan);
  }
  return value.scan === null && displayText(value.error ?? "", MAX_TEXT_BYTES);
}

const SCAN_STAGES: readonly ResponseScanStage[] = ["running", "completed", "failed"];

function plan(value: unknown): value is ResponseEnginePlan {
  return record(value) && keys(value, [
    "kind", "planHandle", "summary", "steps", "impact", "rollbackNote", "expiresInSeconds",
  ]) && isResponseEngineHandle(value.planHandle) &&
    displayText(value.summary, MAX_TEXT_BYTES) &&
    boundedTextList(value.steps, MAX_PLAN_STEPS, MAX_TEXT_BYTES) &&
    (value.steps as string[]).length > 0 &&
    displayText(value.impact, MAX_TEXT_BYTES) &&
    (value.rollbackNote === null || displayText(value.rollbackNote, MAX_TEXT_BYTES)) &&
    typeof value.expiresInSeconds === "number" &&
    Number.isSafeInteger(value.expiresInSeconds) &&
    value.expiresInSeconds >= 1 && value.expiresInSeconds <= 300;
}

function status(value: unknown): value is ResponseEngineStatus {
  if (!record(value) || !keys(value, ["kind", "operationHandle", "stage", "summary", "verifyPassed"]) ||
    !isResponseEngineHandle(value.operationHandle) ||
    typeof value.stage !== "string" || !FIX_STAGES.includes(value.stage as ResponseFixStage) ||
    !displayText(value.summary, MAX_TEXT_BYTES)) return false;
  // 复验结论只在完成时有值；进行中和失败都不允许冒充复验结果。
  return value.stage === "completed"
    ? typeof value.verifyPassed === "boolean"
    : value.verifyPassed === null;
}

export function isResponseEngineResponse(value: unknown): value is ResponseEngineResponse {
  if (!record(value) || encoder.encode(JSON.stringify(value)).byteLength > MAX_RESPONSE_BYTES) {
    return false;
  }
  switch (value.kind) {
    case "scan":
      return scan(value);
    case "scan-started":
      return keys(value, ["kind", "scanHandle"]) && isResponseEngineHandle(value.scanHandle);
    case "scan-status":
      return scanStatus(value);
    case "plan":
      return plan(value);
    case "confirmed":
      return keys(value, ["kind", "planHandle", "confirmed", "expiresInSeconds"]) &&
        isResponseEngineHandle(value.planHandle) && value.confirmed === true &&
        typeof value.expiresInSeconds === "number" &&
        Number.isSafeInteger(value.expiresInSeconds) &&
        value.expiresInSeconds >= 1 && value.expiresInSeconds <= 300;
    case "cancelled":
      return keys(value, ["kind", "cancelled"]) && typeof value.cancelled === "boolean";
    case "execution":
      return keys(value, ["kind", "operationHandle"]) &&
        isResponseEngineHandle(value.operationHandle);
    case "status":
      return status(value);
    default:
      return false;
  }
}

/** 响应不仅要自身合法，还得是这次请求所问的那一种。 */
export function matchesResponseEngineResponse(
  request: ResponseEngineRequest,
  value: unknown,
): value is ResponseEngineResponse {
  if (!isResponseEngineResponse(value)) return false;
  switch (request.action) {
    case "scan":
      return value.kind === "scan-started";
    case "poll-scan":
      return value.kind === "scan-status" && value.scanHandle === request.scanHandle;
    case "plan-fix":
      return value.kind === "plan";
    case "confirm-fix":
      return value.kind === "confirmed" && value.planHandle === request.planHandle;
    case "cancel-fix":
      return value.kind === "cancelled";
    case "execute-fix":
      return value.kind === "execution";
    case "poll-fix":
      return value.kind === "status" && value.operationHandle === request.operationHandle;
  }
}
