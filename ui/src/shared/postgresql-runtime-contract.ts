import { isPostgresqlObjectPage, isPostgresqlObjectDetail, type PostgresqlObjectPage, type PostgresqlObjectDetail, type ObjectSection, type ObjectFilter } from "./postgresql-object-contract.js";
import { isPostgresqlRolePage, type PostgresqlRolePage, type RoleAccessMode } from "./postgresql-role-contract.js";
import { isPostgresqlAccessPage, isPostgresqlAccessSummary, type AccessSection, type PostgresqlAccessSummary, type PostgresqlAccessPage } from "./postgresql-access-contract.js";
export type PostgresqlTlsMode = "verify-full" | "ssh-loopback";
export interface PostgresqlProfileInput {
  name: string; host: string; port: number; username: string; database: string;
  tlsMode: PostgresqlTlsMode; caPem: string | null;
}
export type PostgresqlPasswordChange = { action: "keep" | "remove" } | { action: "replace"; value: string };
export type PostgresqlRuntimeRequest =
  | { action: "list"; bindingHandle: string }
  | { action: "edit" | "plan-delete"; bindingHandle: string; profileHandle: string }
  | { action: "begin"; bindingHandle: string; profileHandle: string; retainEvidence: boolean }
  | { action: "save"; bindingHandle: string; profileHandle: string | null; profile: PostgresqlProfileInput; password: PostgresqlPasswordChange }
  | { action: "delete"; bindingHandle: string; planHandle: string }
  | { action: "poll" | "cancel" | "retain" | "discard-evidence"; bindingHandle: string; jobHandle: string }
  | { action: "object-rows"; bindingHandle: string; jobHandle: string; section: ObjectSection; query: string; filter: ObjectFilter; offset: number }
  | { action: "object-detail"; bindingHandle: string; jobHandle: string; section: ObjectSection; oid: number; subId: number; roleOid: number | null }
  | { action: "role-access"; bindingHandle: string; jobHandle: string; roleOid: number; mode: RoleAccessMode; query: string; offset: number }
  | { action: "access-rows"; bindingHandle: string; jobHandle: string; section: AccessSection; query: string; offset: number }
  | { action: "rows"; bindingHandle: string; jobHandle: string; query: string; offset: number };
export interface PostgresqlProfileSummary {
  profileHandle: string; name: string; host: string; port: number; username: string; database: string;
  tlsMode: PostgresqlTlsMode; hasPassword: boolean; hasCa: boolean; unassigned: boolean;
}
export interface PostgresqlRuntimeRow {
  name: string; value: string | null; sensitivity: "public" | "redacted" | "private-key";
  presence: "null" | "empty" | "present";
  context: "internal" | "postmaster" | "sighup" | "superuser-backend" | "backend" | "superuser" | "user";
  source: string | null; pendingRestart: boolean; minimum: string | null; maximum: string | null;
  enumValues: string[]; metadataTruncated: boolean;
}
export interface PostgresqlRuntimeSummary {
  version: string; tlsMode: PostgresqlTlsMode; parameterCount: number; noticeCount: number;
  observations: PostgresqlRuntimeRow[];
  session: PostgresqlSessionObservation;
  hostProcess: PostgresqlHostInspection;
  access: PostgresqlAccessSummary;
}
export const postgresqlReviewNames = ["ssl", "logging_collector", "log_connections", "log_disconnections", "password_encryption", "log_statement", "listen_addresses", "ssl_min_protocol_version", "ssl_max_protocol_version", "default_transaction_read_only"] as const;
export const postgresqlPathNames = ["config_file", "data_directory", "hba_file", "ident_file"] as const;
export interface PostgresqlSessionObservation {
  observedAt: string; databaseName: string; databaseOid: number; sessionUser: string; effectiveUser: string;
  backendPid: number; serverAddress: string | null; serverPort: number | null; clientAddress: string | null; clientPort: number | null;
  serverStartedAt: string; configurationLoadedAt: string; inRecovery: boolean;
  clusterIdentifierReadable: boolean; clusterIdentifier: string | null; settingsReadable: boolean;
  paths: { name: typeof postgresqlPathNames[number]; path: string | null }[];
  origins: { name: typeof postgresqlReviewNames[number]; source: string | null; sourceFile: string | null; sourceLine: number | null; pendingRestart: boolean | null }[];
}
export const postgresqlProcessReasons = ["unsupported", "transport-unavailable", "no-tcp-observation", "permission-denied", "process-unavailable", "process-changed", "namespace-unmatched", "socket-unmatched", "executable-unmatched", "executable-unavailable", "path-unavailable", "limit-exceeded", "invalid-input", "invalid-procfs", "invalid-output", "timeout"] as const;
export type PostgresqlProcessReason = typeof postgresqlProcessReasons[number];
export interface PostgresqlHostProcess {
  observedAt: string; bootId: string; backendPid: number; backendStartTicks: string; postmasterPid: number; postmasterStartTicks: string;
  socketInode: string; pidNamespace: string; networkNamespace: string; mountNamespace: string;
  executablePath: string; executableDevice: string; executableInode: string; executableSha256: string; dataDirectory: string; reportedDirectoryMatches: boolean | null;
}
export type PostgresqlHostInspection = { state: "matched"; reason: null; process: PostgresqlHostProcess } | { state: "unavailable"; reason: PostgresqlProcessReason; process: null };
export interface PostgresqlRetention {
  state: "pending" | "saved" | "unsaved"; caseId: string | null; caseTitle: string | null;
  evidenceId: string | null; sha256: string | null; canRetry: boolean; detail: string; recordText: string | null;
}
export interface PostgresqlRuntimeJob {
  jobHandle: string; profile: PostgresqlProfileSummary; targetLabel: string;
  state: "reading" | "completed" | "failed" | "cancelled" | "expired";
  startedAt: string; finishedAt: string | null; detail: string; result: PostgresqlRuntimeSummary | null;
  retention: PostgresqlRetention | null;
}
export type PostgresqlRuntimeResponse =
  | PostgresqlObjectPage
  | PostgresqlObjectDetail
  | PostgresqlRolePage
  | PostgresqlAccessPage
  | { kind: "rejected"; action: PostgresqlRuntimeRequest["action"]; code: "invalid-params" | "stale" | "busy" | "capacity" | "store"; detail: string }
  | { kind: "profiles"; profiles: PostgresqlProfileSummary[] }
  | { kind: "editor"; profile: PostgresqlProfileSummary; caPem: string | null }
  | { kind: "saved"; profile: PostgresqlProfileSummary }
  | { kind: "delete-plan"; planHandle: string; profile: PostgresqlProfileSummary; expiresInMs: number }
  | { kind: "deleted"; planHandle: string; profileHandle: string; verified: boolean; detail: string }
  | { kind: "job"; job: PostgresqlRuntimeJob }
  | { kind: "rows"; jobHandle: string; query: string; offset: number; matched: number; total: number; rows: PostgresqlRuntimeRow[] };
export interface PostgresqlRuntimeApi {
  postgresqlRuntime(request: PostgresqlRuntimeRequest): Promise<PostgresqlRuntimeResponse>;
}

const encoder = new TextEncoder();
function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function keys(value: Record<string, unknown>, expected: string[]): boolean {
  return Object.keys(value).length === expected.length && expected.every(key => Object.hasOwn(value, key));
}
function string(value: unknown, maximum: number, empty = false, multiline = false): value is string {
  return typeof value === "string" && (empty || value.trim().length > 0) && encoder.encode(value).length <= maximum &&
    !/[\uD800-\uDFFF]/u.test(value) && ![...value].some(char => {
      const code = char.codePointAt(0)!;
      return code < 0x20 && !(multiline && [9, 10, 13].includes(code)) || code >= 0x7f && code <= 0x9f;
    });
}
function integer(value: unknown, max: number, min = 0): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= min && value <= max;
}
function mode(value: unknown): value is PostgresqlTlsMode { return value === "verify-full" || value === "ssh-loopback"; }
function nullable(value: unknown, maximum: number): boolean { return value === null || string(value, maximum, true); }
function certificate(value: unknown): boolean { return value === null || string(value, 65536, false, true); }
function host(value: unknown): value is string { return string(value, 253) && /^[A-Za-z0-9._:[\]-]+$/u.test(value); }
function profileInput(value: unknown): value is PostgresqlProfileInput {
  return record(value) && keys(value, ["name", "host", "port", "username", "database", "tlsMode", "caPem"]) &&
    string(value.name, 256) && host(value.host) && integer(value.port, 65535, 1) && string(value.username, 128) &&
    string(value.database, 128) && mode(value.tlsMode) && certificate(value.caPem) && (value.tlsMode !== "ssh-loopback" || value.caPem === null);
}
function passwordChange(value: unknown): value is PostgresqlPasswordChange {
  if (!record(value)) return false;
  if (value.action === "keep" || value.action === "remove") return keys(value, ["action"]);
  return value.action === "replace" && keys(value, ["action", "value"]) && typeof value.value === "string" &&
    value.value.length > 0 && encoder.encode(value.value).length <= 16384 && !value.value.includes("\0") && !/[\uD800-\uDFFF]/u.test(value.value);
}
export function isPostgresqlRuntimeRequest(value: unknown): value is PostgresqlRuntimeRequest {
  if (!record(value) || !string(value.bindingHandle, 128)) return false;
  const basic = ["action", "bindingHandle"];
  switch (value.action) {
    case "list": return keys(value, basic);
    case "edit": case "plan-delete": return keys(value, [...basic, "profileHandle"]) && string(value.profileHandle, 128);
    case "begin": return keys(value, [...basic, "profileHandle", "retainEvidence"]) && string(value.profileHandle, 128) && typeof value.retainEvidence === "boolean";
    case "save": return keys(value, [...basic, "profileHandle", "profile", "password"]) &&
      (value.profileHandle === null || string(value.profileHandle, 128)) && profileInput(value.profile) && passwordChange(value.password);
    case "delete": return keys(value, [...basic, "planHandle"]) && string(value.planHandle, 128);
    case "poll": case "cancel": case "retain": case "discard-evidence": return keys(value, [...basic, "jobHandle"]) && string(value.jobHandle, 128);
    case "object-rows": return keys(value, [...basic, "jobHandle", "section", "query", "filter", "offset"]) && string(value.jobHandle, 128) &&
      typeof value.section === "string" && ["database", "schemas", "relations", "columns", "routines", "types", "languages", "tablespaces", "foreign-wrappers", "foreign-servers", "large-objects", "parameters", "defaults"].includes(value.section) && typeof value.filter === "string" && ["all", "public", "delegated", "security-definer", "unfixed-definer"].includes(value.filter) && string(value.query, 128, true) && integer(value.offset, 2048);
    case "object-detail": return keys(value, [...basic, "jobHandle", "section", "oid", "subId", "roleOid"]) && string(value.jobHandle, 128) &&
      typeof value.section === "string" && ["database", "schemas", "relations", "columns", "routines", "types", "languages", "tablespaces", "foreign-wrappers", "foreign-servers", "large-objects", "parameters", "defaults"].includes(value.section) && integer(value.oid, 4294967295, 1) && integer(value.subId, value.section === "columns" ? 32767 : 0, value.section === "columns" ? 1 : 0) &&
      (value.roleOid === null || value.section !== "defaults" && integer(value.roleOid, 4294967295, 1));
    case "role-access": return keys(value, [...basic, "jobHandle", "roleOid", "mode", "query", "offset"]) && string(value.jobHandle, 128) &&
      integer(value.roleOid, 4294967295, 1) && typeof value.mode === "string" && ["member", "inherit", "set", "after-set"].includes(value.mode) && string(value.query, 128, true) && integer(value.offset, 1024);
    case "access-rows": return keys(value, [...basic, "jobHandle", "section", "query", "offset"]) && string(value.jobHandle, 128) &&
      typeof value.section === "string" && ["hba", "ident", "roles", "memberships"].includes(value.section) && string(value.query, 128, true) && integer(value.offset, value.section === "memberships" ? 2048 : 1024);
    case "rows": return keys(value, [...basic, "jobHandle", "query", "offset"]) && string(value.jobHandle, 128) &&
      string(value.query, 128, true) && integer(value.offset, 16384);
    default: return false;
  }
}
function profileSummary(value: unknown): value is PostgresqlProfileSummary {
  return record(value) && keys(value, ["profileHandle", "name", "host", "port", "username", "database", "tlsMode", "hasPassword", "hasCa", "unassigned"]) &&
    string(value.profileHandle, 128) && string(value.name, 256) && host(value.host) && integer(value.port, 65535, 1) &&
    string(value.username, 128) && string(value.database, 128) && mode(value.tlsMode) && typeof value.hasPassword === "boolean" &&
    typeof value.hasCa === "boolean" && typeof value.unassigned === "boolean" && (value.tlsMode !== "ssh-loopback" || value.hasCa === false);
}
function oneOf(value: unknown, values: readonly string[]): boolean { return typeof value === "string" && values.includes(value); }
function row(value: unknown): value is PostgresqlRuntimeRow {
  if (!record(value) || !keys(value, ["name", "value", "sensitivity", "presence", "context", "source", "pendingRestart", "minimum", "maximum", "enumValues", "metadataTruncated"]) ||
    !string(value.name, 512) || !oneOf(value.sensitivity, ["public", "redacted", "private-key"]) ||
    !oneOf(value.presence, ["null", "empty", "present"]) ||
    !oneOf(value.context, ["internal", "postmaster", "sighup", "superuser-backend", "backend", "superuser", "user"]) ||
    !nullable(value.source, 256) || typeof value.pendingRestart !== "boolean" || !nullable(value.minimum, 128) || !nullable(value.maximum, 128) ||
    !Array.isArray(value.enumValues) || value.enumValues.length > 32 || !value.enumValues.every(item => string(item, 256, true)) ||
    typeof value.metadataTruncated !== "boolean") return false;
  if (value.sensitivity !== "public") return value.value === null;
  if (!string(value.value, 32, true)) return false;
  return value.presence === (value.value === "" ? "empty" : "present");
}
function timestamp(value: unknown): value is string {
  return typeof value === "string" && value.length <= 40 && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|\+00:00)$/u.test(value) && Number.isFinite(Date.parse(value));
}
function address(value: unknown): boolean { return value === null || string(value, 45) && /^[0-9a-f:.]+$/u.test(value); }
function sessionObservation(value: unknown): value is PostgresqlSessionObservation {
  if (!record(value) || !keys(value, ["observedAt", "databaseName", "databaseOid", "sessionUser", "effectiveUser", "backendPid", "serverAddress", "serverPort", "clientAddress", "clientPort", "serverStartedAt", "configurationLoadedAt", "inRecovery", "clusterIdentifierReadable", "clusterIdentifier", "settingsReadable", "paths", "origins"])) return false;
  return timestamp(value.observedAt) && timestamp(value.serverStartedAt) && timestamp(value.configurationLoadedAt) &&
    string(value.databaseName, 256) && string(value.sessionUser, 256) && string(value.effectiveUser, 256) && integer(value.databaseOid, 4294967295, 1) && integer(value.backendPid, 2147483647, 1) &&
    address(value.serverAddress) && address(value.clientAddress) && (value.serverAddress === null ? value.serverPort === null : integer(value.serverPort, 65535, 1)) &&
    (value.clientAddress === null ? value.clientPort === null : integer(value.clientPort, 65535, 1)) && typeof value.inRecovery === "boolean" && typeof value.settingsReadable === "boolean" &&
    typeof value.clusterIdentifierReadable === "boolean" && (value.clusterIdentifierReadable ? typeof value.clusterIdentifier === "string" && /^[1-9]\d{0,19}$/u.test(value.clusterIdentifier) && BigInt(value.clusterIdentifier) <= 18446744073709551615n : value.clusterIdentifier === null) &&
    Array.isArray(value.paths) && value.paths.length === 4 && value.paths.every((p, i) => record(p) && keys(p, ["name", "path"]) && p.name === postgresqlPathNames[i] && (p.path === null || string(p.path, 2048))) &&
    Array.isArray(value.origins) && value.origins.length === 10 && value.origins.every((p, i) => record(p) && keys(p, ["name", "source", "sourceFile", "sourceLine", "pendingRestart"]) && p.name === postgresqlReviewNames[i] &&
      (p.source === null || string(p.source, 128)) && (p.sourceFile === null || string(p.sourceFile, 2048)) &&
      (p.sourceLine === null || p.sourceFile !== null && integer(p.sourceLine, 2147483647, 1)) &&
      (p.source === null ? p.pendingRestart === null && p.sourceFile === null : typeof p.pendingRestart === "boolean"));
}
function retention(value: unknown): value is PostgresqlRetention {
  if (!record(value) || !keys(value, ["state", "caseId", "caseTitle", "evidenceId", "sha256", "canRetry", "detail", "recordText"]) ||
    !oneOf(value.state, ["pending", "saved", "unsaved"]) || !string(value.detail, 2048) || typeof value.canRetry !== "boolean" ||
    !(value.caseId === null ? value.caseTitle === null : string(value.caseId, 128) && string(value.caseTitle, 1024)) ||
    !(value.recordText === null || string(value.recordText, 16384, false, true) && [...value.recordText].length <= 4096)) return false;
  if (value.state === "saved") return value.caseId !== null && string(value.evidenceId, 128) && typeof value.sha256 === "string" && /^[0-9a-f]{64}$/u.test(value.sha256) && value.canRetry === false && value.recordText !== null;
  if (value.evidenceId !== null || value.sha256 !== null) return false;
  return value.state === "pending" ? value.canRetry === false && value.recordText === null : value.canRetry === (value.recordText !== null);
}
function uintText(value: unknown, zero = false): value is string {
  return typeof value === "string" && /^(?:0|[1-9]\d{0,19})$/u.test(value) && BigInt(value) <= 18446744073709551615n && (zero || value !== "0");
}
function hostInspection(value: unknown, session: PostgresqlSessionObservation): value is PostgresqlHostInspection {
  if (!record(value) || !keys(value, ["state", "reason", "process"])) return false;
  if (value.state === "unavailable") return oneOf(value.reason, postgresqlProcessReasons) && value.process === null;
  const p = value.process;
  if (value.state !== "matched" || value.reason !== null || !record(p) || !keys(p, ["observedAt", "bootId", "backendPid", "backendStartTicks", "postmasterPid", "postmasterStartTicks", "socketInode", "pidNamespace", "networkNamespace", "mountNamespace", "executablePath", "executableDevice", "executableInode", "executableSha256", "dataDirectory", "reportedDirectoryMatches"])) return false;
  const reported = session.paths.find(path => path.name === "data_directory")!.path;
  return session.serverAddress !== null && session.clientAddress !== null && timestamp(p.observedAt) && p.observedAt.endsWith("Z") && typeof p.bootId === "string" && /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/iu.test(p.bootId) && p.backendPid === session.backendPid && integer(p.postmasterPid, 2147483647, 1) && p.postmasterPid !== p.backendPid &&
    uintText(p.backendStartTicks) && uintText(p.postmasterStartTicks) && BigInt(p.postmasterStartTicks) <= BigInt(p.backendStartTicks) &&
    [p.socketInode, p.pidNamespace, p.networkNamespace, p.mountNamespace, p.executableInode].every(value => uintText(value)) && uintText(p.executableDevice, true) &&
    string(p.executablePath, 2048) && p.executablePath.startsWith("/") && !p.executablePath.endsWith(" (deleted)") && string(p.dataDirectory, 2048) && p.dataDirectory.startsWith("/") &&
    typeof p.executableSha256 === "string" && /^[0-9a-f]{64}$/u.test(p.executableSha256) &&
    p.reportedDirectoryMatches === (reported === null ? null : reported.replace(/\/+$/u, "") === p.dataDirectory.replace(/\/+$/u, ""));
}
function runtimeSummary(value: unknown): value is PostgresqlRuntimeSummary {
  return record(value) && keys(value, ["version", "tlsMode", "parameterCount", "noticeCount", "observations", "session", "hostProcess", "access"]) && isPostgresqlAccessSummary(value.access) && sessionObservation(value.session) && hostInspection(value.hostProcess, value.session) &&
    (value.access.roleGraph.state !== "available" || value.access.roleGraph.database.oid === value.session.databaseOid && value.access.roleGraph.database.name === value.session.databaseName) &&
    typeof value.version === "string" && /^(?:16|17|18)\.(?:0|[1-9]\d{0,3})$/u.test(value.version) && mode(value.tlsMode) &&
    integer(value.parameterCount, 16384) && integer(value.noticeCount, 64) && Array.isArray(value.observations) &&
    value.observations.length <= 12 && value.observations.length <= value.parameterCount && value.observations.every(row) && new Set(value.observations.map(item => item.name)).size === value.observations.length;
}
function job(value: unknown): value is PostgresqlRuntimeJob {
  if (!record(value) || !keys(value, ["jobHandle", "profile", "targetLabel", "state", "startedAt", "finishedAt", "detail", "result", "retention"]) ||
    !string(value.jobHandle, 128) || !profileSummary(value.profile) || value.profile.unassigned || !string(value.targetLabel, 1024) || !timestamp(value.startedAt) ||
    !string(value.detail, 2048) || !oneOf(value.state, ["reading", "completed", "failed", "cancelled", "expired"]) || !(value.retention === null || retention(value.retention))) return false;
  if (value.state === "reading") return value.finishedAt === null && value.result === null && (value.retention === null || value.retention.state === "pending");
  if (value.retention?.state === "pending") return false;
  if (!timestamp(value.finishedAt)) return false;
  return value.state === "completed" ? runtimeSummary(value.result) && value.result.tlsMode === value.profile.tlsMode : value.result === null;
}
export function isPostgresqlRuntimeResponse(value: unknown): value is PostgresqlRuntimeResponse {
  if (!record(value)) return false;
  switch (value.kind) {
    case "rejected": return keys(value, ["kind", "action", "code", "detail"]) && oneOf(value.action, ["list", "edit", "save", "plan-delete", "delete", "begin", "poll", "cancel", "rows", "access-rows", "role-access", "object-rows", "object-detail", "retain", "discard-evidence"]) && oneOf(value.code, ["invalid-params", "stale", "busy", "capacity", "store"]) && string(value.detail, 2048);
    case "profiles": return keys(value, ["kind", "profiles"]) && Array.isArray(value.profiles) && value.profiles.length <= 256 &&
      value.profiles.every(profileSummary) && new Set(value.profiles.map(item => item.profileHandle)).size === value.profiles.length;
    case "editor": return keys(value, ["kind", "profile", "caPem"]) && profileSummary(value.profile) && certificate(value.caPem) && value.profile.hasCa === (value.caPem !== null);
    case "saved": return keys(value, ["kind", "profile"]) && profileSummary(value.profile) && !value.profile.unassigned;
    case "delete-plan": return keys(value, ["kind", "planHandle", "profile", "expiresInMs"]) && string(value.planHandle, 128) && profileSummary(value.profile) && integer(value.expiresInMs, 120000, 1);
    case "deleted": return keys(value, ["kind", "planHandle", "profileHandle", "verified", "detail"]) && string(value.planHandle, 128) && string(value.profileHandle, 128) && typeof value.verified === "boolean" && string(value.detail, 2048);
    case "job": return keys(value, ["kind", "job"]) && job(value.job);
    case "object-rows": return isPostgresqlObjectPage(value);
    case "object-detail": return isPostgresqlObjectDetail(value);
    case "role-access": return isPostgresqlRolePage(value);
    case "access-rows": return isPostgresqlAccessPage(value);
    case "rows": return keys(value, ["kind", "jobHandle", "query", "offset", "matched", "total", "rows"]) && string(value.jobHandle, 128) && string(value.query, 128, true) &&
      integer(value.total, 16384) && integer(value.matched, value.total) && integer(value.offset, 16384) && Array.isArray(value.rows) && value.rows.length <= 50 &&
      value.rows.length === Math.min(50, Math.max(0, value.matched - value.offset)) && value.rows.every(row);
    default: return false;
  }
}
export function matchesPostgresqlRuntimeResponse(request: PostgresqlRuntimeRequest, response: unknown): response is PostgresqlRuntimeResponse {
  if (!isPostgresqlRuntimeResponse(response)) return false;
  if (response.kind === "rejected") return response.action === request.action;
  switch (request.action) {
    case "list": return response.kind === "profiles";
    case "edit": return response.kind === "editor" && response.profile.profileHandle === request.profileHandle;
    case "save": return response.kind === "saved" && ["name", "host", "port", "username", "database", "tlsMode"].every(key =>
      response.profile[key as keyof PostgresqlProfileSummary] === request.profile[key as keyof PostgresqlProfileInput]) &&
      response.profile.hasCa === (request.profile.caPem !== null) &&
      (request.password.action === "keep" || response.profile.hasPassword === (request.password.action === "replace"));
    case "plan-delete": return response.kind === "delete-plan" && response.profile.profileHandle === request.profileHandle;
    case "delete": return response.kind === "deleted" && response.planHandle === request.planHandle;
    case "begin": return response.kind === "job" && response.job.profile.profileHandle === request.profileHandle && (response.job.retention !== null) === request.retainEvidence;
    case "poll": case "cancel": case "retain": return response.kind === "job" && response.job.jobHandle === request.jobHandle;
    case "discard-evidence": return response.kind === "job" && response.job.jobHandle === request.jobHandle && response.job.retention === null;
    case "object-rows": return response.kind === "object-rows" && response.jobHandle === request.jobHandle && response.section === request.section && response.query === request.query && response.filter === request.filter && response.offset === request.offset;
    case "object-detail": return response.kind === "object-detail" && response.jobHandle === request.jobHandle && response.section === request.section && response.oid === request.oid && response.subId === request.subId && response.roleOid === request.roleOid;
    case "role-access": return response.kind === "role-access" && response.jobHandle === request.jobHandle && response.roleOid === request.roleOid && response.mode === request.mode && response.query === request.query && response.offset === request.offset;
    case "access-rows": return response.kind === "access-rows" && response.jobHandle === request.jobHandle && response.section === request.section && response.query === request.query && response.offset === request.offset;
    case "rows": return response.kind === "rows" && response.jobHandle === request.jobHandle && response.query === request.query && response.offset === request.offset;
  }
}
