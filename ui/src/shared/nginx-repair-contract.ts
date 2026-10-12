/** A closed workflow, not an arbitrary command/configuration dispatch API. */
type Binding = { bindingHandle: string };
export type NginxRepairRequest = Binding & (
  | { action: "discover" | "history" }
  | { action: "load" | "listeners"; instanceHandle: string }
  | { action: "probe"; endpointHandle: string; serverName: string; path: string }
  | { action: "retain" | "discard-observation"; observationHandle: string }
  | { action: "plan"; configurationHandle: string; candidateHandle: string }
  | { action: "confirm" | "execute" | "cancel"; planHandle: string }
  | { action: "execution"; executionHandle: string }
  | { action: "restore"; recordHandle: string }
);
export interface NginxInstance { instanceHandle: string; title: string; version: string; mainPid: number }
export interface NginxEndpoint { endpointHandle: string; address: string; port: number; connectAddress: string }
export interface NginxRetention { state: "saved" | "unsaved"; caseId: string | null; caseTitle: string | null;
  evidenceId: string | null; sha256: string | null; detail: string; canRetry: boolean }
export interface NginxTlsObservation { version: "TLSv1" | "TLSv1_1" | "TLSv1_2" | "TLSv1_3";
  outcome: "accepted" | "protocol-rejected" | "certificate-rejected" | "local-unavailable" | "inconclusive";
  detail: string; certificateSha256: string | null; httpOutcome: "not-sent" | "status" | "unavailable"; httpStatus: number | null }
export interface NginxCandidate { candidateHandle: string; setting: "autoindex" | "server-tokens" | "ssl-protocols";
  title: string; path: string; line: number; before: string; after: string }
export interface NginxRepairPlan { planHandle: string; targetLabel: string; candidateHandle: string | null; title: string;
  path: string; line: number | null; diff: string; impact: string; restoreDescription: string;
  confirmed: boolean; expiresInSeconds: number }
export interface NginxRepairReceipt { planHandle: string; state: "verified" | "restored" | "unverified";
  detail: string; recordHandle: string | null }
export interface NginxRepairRecord { recordHandle: string; path: string; state: "applied" | "restored" | "pending" | "restore-failed";
  createdAt: string; canPrepareRestore: boolean }
export type NginxRepairResponse =
  | { kind: "inventory"; instances: NginxInstance[] }
  | { kind: "listeners"; instanceHandle: string; endpoints: NginxEndpoint[] }
  | { kind: "connectivity"; observationHandle: string; recordText: string | null; endpointHandle: string; serverName: string; path: string; checkedAt: string;
      report: { clientVersion: string; rows: NginxTlsObservation[] }; retention: NginxRetention }
  | { kind: "retention"; observationHandle: string; retention: NginxRetention }
  | { kind: "observation-discarded"; observationHandle: string }
  | { kind: "configuration"; configurationHandle: string; instanceHandle: string; fileCount: number; unresolvedIncludes: number; candidates: NginxCandidate[] }
  | { kind: "plan"; plan: NginxRepairPlan }
  | { kind: "execution"; executionHandle: string; receipt: NginxRepairReceipt | null }
  | { kind: "cancelled"; cancelled: boolean }
  | { kind: "history"; records: NginxRepairRecord[]; totalRecords: number; truncated: boolean };
export interface NginxRepairApi { nginxRepair(request: NginxRepairRequest): Promise<unknown> }

const FIELDS = {
  discover: [], history: [], load: ["instanceHandle"], listeners: ["instanceHandle"], probe: ["endpointHandle", "serverName", "path"],
  retain: ["observationHandle"], "discard-observation": ["observationHandle"],
  plan: ["configurationHandle", "candidateHandle"], confirm: ["planHandle"], execute: ["planHandle"],
  cancel: ["planHandle"], execution: ["executionHandle"], restore: ["recordHandle"],
} as const;
const TITLES = { autoindex: "关闭目录列表", "server-tokens": "隐藏 Nginx 版本", "ssl-protocols": "移除旧版 TLS/SSL 协议" } as const;
function record(value: unknown): value is Record<string, unknown> { return value !== null && typeof value === "object" && !Array.isArray(value); }
function keys(value: Record<string, unknown>, names: readonly string[]): boolean {
  return Object.keys(value).length === names.length && names.every((name) => Object.hasOwn(value, name));
}
function text(value: unknown, limit: number): value is string { return typeof value === "string" && value.length <= limit; }
function handle(value: unknown): value is string {
  return text(value, 128) && value.length > 0 && new TextEncoder().encode(value).length <= 128 && !controls(value);
}
function controls(value: string): boolean { return [...value].some((char) => { const code = char.codePointAt(0)!; return code < 0x20 || code >= 0x7f && code <= 0x9f; }); }
function integer(value: unknown, minimum: number, maximum: number): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= minimum && value <= maximum;
}
function path(value: unknown): value is string { return text(value, 4096) && value.startsWith("/") && !controls(value); }
function unique<T>(items: T[], getHandle: (item: T) => string): boolean { return new Set(items.map(getHandle)).size === items.length; }

function ipAddress(value: unknown): boolean {
  if (!text(value, 45) || !value) return false;
  const ipv4 = (ip: string) => ip.split(".").length === 4 && ip.split(".").every((part) => /^(0|[1-9][0-9]{0,2})$/u.test(part) && Number(part) <= 255);
  if (!value.includes(":")) return ipv4(value);
  if (!/^[a-fA-F0-9:.]+$/u.test(value)) return false;
  let normalized = value;
  if (value.includes(".")) {
    const boundary = value.lastIndexOf(":");
    if (!ipv4(value.slice(boundary + 1))) return false;
    normalized = value.slice(0, boundary + 1) + "0:0";
  }
  const halves = normalized.split("::");
  const groups = halves.flatMap((half) => half ? half.split(":") : []);
  return halves.length <= 2 && groups.every((group) => /^[a-fA-F0-9]{1,4}$/u.test(group)) &&
    (halves.length === 2 ? groups.length < 8 : groups.length === 8);
}
export function isNginxServerName(value: unknown): value is string {
  return text(value, 253) && value.length > 0 && (ipAddress(value) || !/^[0-9.]+$/u.test(value) &&
    value.split(".").every((label) => /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/u.test(label)));
}
export function isNginxProbePath(value: unknown): value is string {
  return text(value, 1024) && value.startsWith("/") && !value.startsWith("//") && /^[\x21-\x7e]+$/u.test(value) && !/[?#\\]/u.test(value);
}

export function isNginxRepairRequest(value: unknown): value is NginxRepairRequest {
  if (!record(value) || typeof value.action !== "string" || !Object.hasOwn(FIELDS, value.action)) return false;
  const extra = FIELDS[value.action as keyof typeof FIELDS];
  return keys(value, ["action", "bindingHandle", ...extra]) && handle(value.bindingHandle) && extra.every((name) =>
    name === "serverName" ? isNginxServerName(value[name]) : name === "path" ? isNginxProbePath(value[name]) : handle(value[name]));
}

function endpoint(value: unknown): value is NginxEndpoint {
  return record(value) && keys(value, ["endpointHandle", "address", "port", "connectAddress"]) && handle(value.endpointHandle) &&
    ipAddress(value.address) && integer(value.port, 1, 65535) && ipAddress(value.connectAddress) &&
    value.connectAddress === (value.address === "0.0.0.0" ? "127.0.0.1" : value.address === "::" ? "::1" : value.address);
}
function retention(value: unknown): value is NginxRetention {
  if (!record(value) || !keys(value, ["state", "caseId", "caseTitle", "evidenceId", "sha256", "detail", "canRetry"]) ||
    !text(value.detail, 1024) || typeof value.canRetry !== "boolean") return false;
  const destination = handle(value.caseId) && text(value.caseTitle, 512) && value.caseTitle.trim().length > 0;
  return value.state === "saved" ? destination && handle(value.evidenceId) && typeof value.sha256 === "string" && /^[a-fA-F0-9]{64}$/u.test(value.sha256) && !value.canRetry
    : value.state === "unsaved" && (destination || value.caseId === null && value.caseTitle === null) && value.evidenceId === null && value.sha256 === null;
}
function observation(value: unknown, index: number): value is NginxTlsObservation {
  if (!record(value) || !keys(value, ["version", "outcome", "detail", "certificateSha256", "httpOutcome", "httpStatus"]) ||
    value.version !== ["TLSv1", "TLSv1_1", "TLSv1_2", "TLSv1_3"][index]) return false;
  const modernAccepted = value.outcome === "accepted" && index >= 2;
  const details: Record<string, readonly string[]> = {
    accepted: [index < 2 ? "legacy-accepted" : "identity-verified"], "protocol-rejected": ["server-protocol-alert"],
    "certificate-rejected": index >= 2 ? ["certificate-verification-failed"] : [],
    "local-unavailable": ["local-tls-unavailable", "local-protocol-unavailable"], inconclusive: ["timeout", "handshake-failed", "connection-failed"],
  };
  return typeof value.outcome === "string" && Object.hasOwn(details, value.outcome) && typeof value.detail === "string" && details[value.outcome]!.includes(value.detail) &&
    (modernAccepted ? typeof value.certificateSha256 === "string" && /^[a-fA-F0-9]{64}$/u.test(value.certificateSha256) &&
      (value.httpOutcome === "status" ? integer(value.httpStatus, 100, 599) : value.httpOutcome === "unavailable" && value.httpStatus === null)
      : value.certificateSha256 === null && value.httpStatus === null && value.httpOutcome === "not-sent");
}
export function isNginxRepairPlan(value: unknown): value is NginxRepairPlan {
  return record(value) && keys(value, ["planHandle", "targetLabel", "candidateHandle", "title", "path", "line", "diff", "impact", "restoreDescription", "confirmed", "expiresInSeconds"]) &&
    handle(value.planHandle) && text(value.targetLabel, 1024) && value.targetLabel.trim().length > 0 && !controls(value.targetLabel) &&
    path(value.path) && text(value.diff, 256 * 1024) && text(value.impact, 1024) && text(value.restoreDescription, 1024) &&
    typeof value.confirmed === "boolean" && integer(value.expiresInSeconds, 1, 300) &&
    (value.candidateHandle === null
      ? value.line === null && value.title === "恢复先前配置"
      : handle(value.candidateHandle) && integer(value.line, 1, 4 * 1024 * 1024) && (value.title === TITLES.autoindex || value.title === TITLES["server-tokens"] || value.title === TITLES["ssl-protocols"]));
}
function instance(value: unknown): value is NginxInstance {
  return record(value) && keys(value, ["instanceHandle", "title", "version", "mainPid"]) && handle(value.instanceHandle) &&
    text(value.title, 256) && text(value.version, 256) && integer(value.mainPid, 1, 4_294_967_295);
}
function candidate(value: unknown): value is NginxCandidate {
  return record(value) && keys(value, ["candidateHandle", "setting", "title", "path", "line", "before", "after"]) &&
    handle(value.candidateHandle) && (value.setting === "autoindex" || value.setting === "server-tokens" || value.setting === "ssl-protocols") &&
    value.title === TITLES[value.setting] && path(value.path) && integer(value.line, 1, 4 * 1024 * 1024) &&
    text(value.before, 1024) && text(value.after, 1024);
}
function receipt(value: unknown): value is NginxRepairReceipt {
  return record(value) && keys(value, ["planHandle", "state", "detail", "recordHandle"]) && handle(value.planHandle) &&
    (value.state === "verified" || value.state === "restored" || value.state === "unverified") && text(value.detail, 1024) &&
    (value.recordHandle === null || handle(value.recordHandle));
}
function historyRecord(value: unknown): value is NginxRepairRecord {
  return record(value) && keys(value, ["recordHandle", "path", "state", "createdAt", "canPrepareRestore"]) && handle(value.recordHandle) && path(value.path) &&
    typeof value.state === "string" && ["applied", "restored", "pending", "restore-failed"].includes(value.state) &&
    text(value.createdAt, 48) && Number.isFinite(Date.parse(value.createdAt)) && typeof value.canPrepareRestore === "boolean" &&
    value.canPrepareRestore === (value.state !== "restored");
}
export function isNginxRepairResponse(value: unknown): value is NginxRepairResponse {
  if (!record(value)) return false;
  switch (value.kind) {
    case "listeners": return keys(value, ["kind", "instanceHandle", "endpoints"]) && handle(value.instanceHandle) && Array.isArray(value.endpoints) &&
      value.endpoints.length <= 64 && value.endpoints.every(endpoint) && unique(value.endpoints, (item) => item.endpointHandle);
    case "retention": return keys(value, ["kind", "observationHandle", "retention"]) && handle(value.observationHandle) && retention(value.retention);
    case "observation-discarded": return keys(value, ["kind", "observationHandle"]) && handle(value.observationHandle);
    case "connectivity": return keys(value, ["kind", "observationHandle", "recordText", "endpointHandle", "serverName", "path", "checkedAt", "report", "retention"]) &&
      handle(value.observationHandle) && retention(value.retention) &&
      (value.recordText === null ? value.retention.state === "unsaved" && !value.retention.canRetry : text(value.recordText, 8192) && [...value.recordText].length <= 4096 && value.recordText.length > 0) &&
      handle(value.endpointHandle) && isNginxServerName(value.serverName) && isNginxProbePath(value.path) && text(value.checkedAt, 48) && Number.isFinite(Date.parse(value.checkedAt)) &&
      record(value.report) && keys(value.report, ["clientVersion", "rows"]) && text(value.report.clientVersion, 128) && value.report.clientVersion.length > 0 && !controls(value.report.clientVersion) &&
      Array.isArray(value.report.rows) && value.report.rows.length === 4 && value.report.rows.every(observation);
    case "inventory": return keys(value, ["kind", "instances"]) && Array.isArray(value.instances) && value.instances.length <= 32 && value.instances.every(instance) && unique(value.instances, (item) => item.instanceHandle);
    case "configuration": return keys(value, ["kind", "configurationHandle", "instanceHandle", "fileCount", "unresolvedIncludes", "candidates"]) &&
      handle(value.configurationHandle) && handle(value.instanceHandle) && integer(value.fileCount, 1, 256) && integer(value.unresolvedIncludes, 0, 4096) &&
      Array.isArray(value.candidates) && value.candidates.length <= 256 && value.candidates.every(candidate) && unique(value.candidates, (item) => item.candidateHandle);
    case "plan": return keys(value, ["kind", "plan"]) && isNginxRepairPlan(value.plan);
    case "execution": return keys(value, ["kind", "executionHandle", "receipt"]) && handle(value.executionHandle) && (value.receipt === null || receipt(value.receipt));
    case "cancelled": return keys(value, ["kind", "cancelled"]) && typeof value.cancelled === "boolean";
    case "history": return keys(value, ["kind", "records", "totalRecords", "truncated"]) && Array.isArray(value.records) && value.records.length <= 64 &&
      value.records.every(historyRecord) && unique(value.records, (item) => item.recordHandle) && integer(value.totalRecords, value.records.length, 512) &&
      value.records.length === Math.min(value.totalRecords, 64) && value.truncated === (value.totalRecords > 64);
    default: return false;
  }
}
export function matchesNginxRepairResponse(request: NginxRepairRequest, value: unknown): value is NginxRepairResponse {
  if (!isNginxRepairResponse(value)) return false;
  switch (request.action) {
    case "discover": return value.kind === "inventory";
    case "history": return value.kind === "history";
    case "load": return value.kind === "configuration" && value.instanceHandle === request.instanceHandle;
    case "listeners": return value.kind === "listeners" && value.instanceHandle === request.instanceHandle;
    case "probe": return value.kind === "connectivity" && value.endpointHandle === request.endpointHandle && value.serverName === request.serverName && value.path === request.path;
    case "retain": return value.kind === "retention" && value.observationHandle === request.observationHandle;
    case "discard-observation": return value.kind === "observation-discarded" && value.observationHandle === request.observationHandle;
    case "plan": return value.kind === "plan" && !value.plan.confirmed && value.plan.candidateHandle === request.candidateHandle;
    case "restore": return value.kind === "plan" && !value.plan.confirmed && value.plan.candidateHandle === null;
    case "confirm": return value.kind === "plan" && value.plan.confirmed && value.plan.planHandle === request.planHandle;
    case "execute": return value.kind === "execution" && value.receipt === null;
    case "execution": return value.kind === "execution" && value.executionHandle === request.executionHandle;
    case "cancel": return value.kind === "cancelled";
  }
}
