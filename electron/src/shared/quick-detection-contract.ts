export type QuickDetectionModuleId =
  | "port-scan"
  | "user-audit"
  | "backdoor-scan"
  | "process-analysis"
  | "file-permission"
  | "ssh-audit"
  | "firewall-check"
  | "log-analysis"
  | "webshell-scan"
  | "cpu-test"
  | "memory-test"
  | "disk-test"
  | "network-test";

export type QuickDetectionCategory = "security" | "competition" | "performance";
export type QuickDetectionProfileId = "selected" | "competition-triage";
export type QuickDetectionOutcome =
  | "passed"
  | "failed"
  | "not-applicable"
  | "error"
  | "cancelled";
export type QuickDetectionSeverity = "info" | "low" | "medium" | "high" | "critical";
export type QuickDetectionReportStatus = "completed" | "partial" | "cancelled";
export type QuickDetectionScanStage = "running" | "cancelling" | "completed" | "cancelled" | "failed";
export const QUICK_DETECTION_REDACTED_TEXT = "[SENSITIVE QUICK DETECTION TEXT REDACTED]" as const;

export interface QuickDetectionModuleCatalogEntry {
  id: QuickDetectionModuleId;
  label: string;
  description: string;
  category: QuickDetectionCategory;
  categoryLabel: string;
}

export interface QuickDetectionProfile {
  id: QuickDetectionProfileId;
  label: string;
  moduleIds: QuickDetectionModuleId[];
}

export interface QuickDetectionCatalog {
  modules: QuickDetectionModuleCatalogEntry[];
  profiles: QuickDetectionProfile[];
  maximumFindingsPerModule: number;
}

export interface QuickDetectionPlanInput {
  profile: QuickDetectionProfileId;
  moduleIds: QuickDetectionModuleId[];
  maximumFindingsPerModule: number;
}

export interface QuickDetectionPlan {
  planHandle: string;
  profile: QuickDetectionProfileId;
  moduleIds: QuickDetectionModuleId[];
  moduleCount: number;
  maximumFindingsPerModule: number;
  expiresInSeconds: number;
  summary: string;
}

export interface QuickDetectionScanStarted {
  scanHandle: string;
  stage: "running";
  total: number;
  expiresInSeconds: number;
}

export interface QuickDetectionCancellation {
  cancelRequested: true;
}

export interface QuickDetectionEvent {
  sequence: number;
  kind: "module-started" | "module-finished" | "scan-finished";
  module: QuickDetectionModuleId | null;
  outcome: QuickDetectionOutcome | null;
  completed: number;
  total: number;
}

export interface QuickDetectionPoll {
  scanHandle: string;
  stage: QuickDetectionScanStage;
  completed: number;
  total: number;
  currentModule: QuickDetectionModuleId | null;
  cancelRequested: boolean;
  events: QuickDetectionEvent[];
  nextEventCursor: number;
  eventsTruncated: boolean;
  reportHandle: string | null;
  errorCode: "binding-stale" | "scan-failed" | "report-rejected" | null;
}

export interface QuickDetectionSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  failedModules: number;
  notApplicableModules: number;
  errorModules: number;
  cancelledModules: number;
}

export interface QuickDetectionHistoryItem {
  reportHandle: string;
  profile: QuickDetectionProfileId;
  startedAt: string;
  durationMs: number;
  status: QuickDetectionReportStatus;
  overallScore: number;
  moduleCount: number;
  summary: QuickDetectionSummary;
}

export interface QuickDetectionHistoryPage {
  total: number;
  offset: number;
  hasMore: boolean;
  items: QuickDetectionHistoryItem[];
}

export interface QuickDetectionFinding {
  title: string;
  description: string;
  severity: QuickDetectionSeverity;
  recommendation: string | null;
  redacted: boolean;
  textTruncated: boolean;
  textProjected: boolean;
}

export interface QuickDetectionModuleReport {
  id: QuickDetectionModuleId;
  label: string;
  category: QuickDetectionCategory;
  outcome: QuickDetectionOutcome;
  score: number;
  durationMs: number;
  findings: QuickDetectionFinding[];
  findingsTruncated: boolean;
  rawText: string;
  rawTextRedacted: boolean;
  rawTextTruncated: boolean;
  rawTextProjected: boolean;
}

export interface QuickDetectionReport {
  reportHandle: string;
  profile: QuickDetectionProfileId;
  startedAt: string;
  durationMs: number;
  status: QuickDetectionReportStatus;
  overallScore: number;
  summary: QuickDetectionSummary;
  droppedProgressEvents: number;
  redactedFieldCount: number;
  textProjected: boolean;
  truncated: boolean;
  modules: QuickDetectionModuleReport[];
}

export interface QuickDetectionApi {
  getQuickDetectionCatalog(): Promise<unknown>;
  planQuickDetection(bindingHandle: string, input: QuickDetectionPlanInput): Promise<unknown>;
  startQuickDetection(bindingHandle: string, planHandle: string): Promise<unknown>;
  pollQuickDetection(
    bindingHandle: string,
    scanHandle: string,
    afterEvent: number,
    limit: number,
  ): Promise<unknown>;
  cancelQuickDetection(bindingHandle: string, scanHandle: string): Promise<unknown>;
  listQuickDetectionHistory(bindingHandle: string, offset: number, limit: number): Promise<unknown>;
  getQuickDetectionReport(bindingHandle: string, reportHandle: string): Promise<unknown>;
}

export const QUICK_DETECTION_API_METHODS = [
  "getQuickDetectionCatalog",
  "planQuickDetection",
  "startQuickDetection",
  "pollQuickDetection",
  "cancelQuickDetection",
  "listQuickDetectionHistory",
  "getQuickDetectionReport",
] as const satisfies readonly (keyof QuickDetectionApi)[];
type AssertNever<T extends never> = T;
export type QuickDetectionApiMethodCoverage = AssertNever<
  Exclude<keyof QuickDetectionApi, (typeof QUICK_DETECTION_API_METHODS)[number]>
>;

type JsonRecord = Record<string, unknown>;
const encoder = new TextEncoder();
const moduleIds = new Set<QuickDetectionModuleId>([
  "port-scan", "user-audit", "backdoor-scan", "process-analysis", "file-permission",
  "ssh-audit", "firewall-check", "log-analysis", "webshell-scan", "cpu-test",
  "memory-test", "disk-test", "network-test",
]);
const triageIds = new Set<QuickDetectionModuleId>([
  "backdoor-scan", "process-analysis", "user-audit", "webshell-scan", "port-scan", "ssh-audit",
]);
const outcomes = new Set<QuickDetectionOutcome>([
  "passed", "failed", "not-applicable", "error", "cancelled",
]);
const severities = new Set<QuickDetectionSeverity>(["info", "low", "medium", "high", "critical"]);
const reportStatuses = new Set<QuickDetectionReportStatus>(["completed", "partial", "cancelled"]);
const scanStages = new Set<QuickDetectionScanStage>([
  "running", "cancelling", "completed", "cancelled", "failed",
]);

function record(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exact(value: JsonRecord, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && actual.every((key) => keys.includes(key));
}

function text(value: unknown, maximumBytes: number, allowEmpty = false): value is string {
  return typeof value === "string" &&
    (allowEmpty || value.length > 0) &&
    encoder.encode(value).byteLength <= maximumBytes &&
    !/[\u0000-\u001f\u007f]/u.test(value);
}

function publicText(value: unknown, maximumBytes: number, allowEmpty = false): value is string {
  return typeof value === "string" && (allowEmpty || value.length > 0) &&
    encoder.encode(value).byteLength <= maximumBytes && !/[\u0000-\u001f\u007f]/u.test(value) &&
    (value === QUICK_DETECTION_REDACTED_TEXT ||
      !value.includes(QUICK_DETECTION_REDACTED_TEXT) && !containsSensitiveMaterial(value));
}

function publicMultilineText(value: unknown, maximumBytes: number): value is string {
  return typeof value === "string" && encoder.encode(value).byteLength <= maximumBytes &&
    !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value) &&
    (value === QUICK_DETECTION_REDACTED_TEXT ||
      !value.includes(QUICK_DETECTION_REDACTED_TEXT) && !containsSensitiveMaterial(value));
}

function containsSensitiveMaterial(value: string): boolean {
  const lower = value.toLowerCase();
  return [
    "password=", "password:", "password\"", "password'", "password_", "_password",
    "--password", "passwd=", "passphrase=", "passphrase:", "passphrase\"", "passphrase'",
    "secret=", "secret:", "secret\"", "secret'", "secret_", "_secret", "--secret",
    "token=", "token:", "token\"", "token'", "token_", "_token", "--token",
    "authorization=", "authorization:", "authorization\"", "authorization'", "api_key=",
    "api_key:", "api-key:", "apikey=", "apikey:", "apikey\"", "apikey'",
    "private_key=", "private-key", "access_key", "access-key", "client_secret",
    "client-secret", "private key-----", "credential=", "credential:", "credential\"",
    "credential'", "cookie:", "set-cookie:", "session_id=", "session_id:",
    "session-id:", "sessionid\"", "sessionid'", "fingerprint=", "bearer ",
  ].some((marker) => lower.includes(marker)) ||
    /[a-z][a-z0-9+.-]*:\/\/[^\s/@]+(?::[^\s/@]*)?@/iu.test(value);
}

function unsigned(value: unknown, maximum = Number.MAX_SAFE_INTEGER): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= maximum;
}

export function isQuickDetectionOpaqueHandle(value: unknown): value is string {
  return text(value, 128) && /^[A-Za-z0-9-]+$/u.test(value);
}

export function isQuickDetectionModuleId(value: unknown): value is QuickDetectionModuleId {
  return typeof value === "string" && moduleIds.has(value as QuickDetectionModuleId);
}

function profile(value: unknown): value is QuickDetectionProfileId {
  return value === "selected" || value === "competition-triage";
}

function category(value: unknown): value is QuickDetectionCategory {
  return value === "security" || value === "competition" || value === "performance";
}

function uniqueModules(value: unknown, maximum = 13): value is QuickDetectionModuleId[] {
  return Array.isArray(value) && value.length <= maximum &&
    value.every(isQuickDetectionModuleId) && new Set(value).size === value.length;
}

function summary(value: unknown): value is QuickDetectionSummary {
  if (!record(value) || !exact(value, [
    "critical", "high", "medium", "low", "info", "failedModules",
    "notApplicableModules", "errorModules", "cancelledModules",
  ])) return false;
  return Object.values(value).every((item) => unsigned(item, 2_600));
}

function timestamp(value: unknown): value is string {
  return text(value, 64) && !Number.isNaN(Date.parse(value));
}

export function isQuickDetectionCatalog(value: unknown): value is QuickDetectionCatalog {
  if (!record(value) || !exact(value, ["modules", "profiles", "maximumFindingsPerModule"]) ||
    !Array.isArray(value.modules) || value.modules.length !== 13 ||
    !Array.isArray(value.profiles) || value.profiles.length !== 2 ||
    !unsigned(value.maximumFindingsPerModule, 200) || value.maximumFindingsPerModule === 0) return false;
  const modulesValid = value.modules.every((item) => record(item) && exact(item, [
    "id", "label", "description", "category", "categoryLabel",
  ]) && isQuickDetectionModuleId(item.id) && text(item.label, 256) &&
    text(item.description, 1_024) && category(item.category) && text(item.categoryLabel, 128));
  if (!modulesValid || new Set(value.modules.map((item) => (item as JsonRecord).id)).size !== 13) return false;
  const profilesValid = value.profiles.every((item) => record(item) && exact(item, [
    "id", "label", "moduleIds",
  ]) && profile(item.id) && text(item.label, 256) && uniqueModules(item.moduleIds));
  if (!profilesValid) return false;
  const selected = value.profiles.find((item) => record(item) && item.id === "selected") as JsonRecord | undefined;
  const triage = value.profiles.find((item) => record(item) && item.id === "competition-triage") as JsonRecord | undefined;
  return selected !== undefined && Array.isArray(selected.moduleIds) && selected.moduleIds.length === 0 &&
    triage !== undefined && Array.isArray(triage.moduleIds) && triage.moduleIds.length === triageIds.size &&
    triage.moduleIds.every((id) => isQuickDetectionModuleId(id) && triageIds.has(id));
}

export function isQuickDetectionPlanInput(value: unknown): value is QuickDetectionPlanInput {
  if (!record(value) || !exact(value, ["profile", "moduleIds", "maximumFindingsPerModule"]) ||
    !profile(value.profile) || !uniqueModules(value.moduleIds) ||
    !unsigned(value.maximumFindingsPerModule, 200) || value.maximumFindingsPerModule === 0) return false;
  return value.profile === "selected" ? value.moduleIds.length > 0 : value.moduleIds.length === 0;
}

export function isQuickDetectionPlan(value: unknown): value is QuickDetectionPlan {
  if (!record(value) || !exact(value, [
    "planHandle", "profile", "moduleIds", "moduleCount", "maximumFindingsPerModule",
    "expiresInSeconds", "summary",
  ])) return false;
  if (!uniqueModules(value.moduleIds) || !unsigned(value.moduleCount, 13) || value.moduleCount === 0 ||
    !isQuickDetectionOpaqueHandle(value.planHandle) || !profile(value.profile) ||
    value.moduleCount !== value.moduleIds.length || !unsigned(value.maximumFindingsPerModule, 200) ||
    value.maximumFindingsPerModule === 0 || !unsigned(value.expiresInSeconds, 600) ||
    value.expiresInSeconds === 0 || !publicText(value.summary, 2_048) ||
    value.summary === QUICK_DETECTION_REDACTED_TEXT) return false;
  return value.profile === "selected"
    ? value.moduleIds.length > 0
    : value.moduleIds.length === triageIds.size && value.moduleIds.every((id) => triageIds.has(id));
}

export function isQuickDetectionScanStarted(value: unknown): value is QuickDetectionScanStarted {
  return record(value) && exact(value, ["scanHandle", "stage", "total", "expiresInSeconds"]) &&
    isQuickDetectionOpaqueHandle(value.scanHandle) && value.stage === "running" &&
    unsigned(value.total, 13) && value.total > 0 && unsigned(value.expiresInSeconds, 3_600) &&
    value.expiresInSeconds > 0;
}

export function isQuickDetectionCancellation(value: unknown): value is QuickDetectionCancellation {
  return record(value) && exact(value, ["cancelRequested"]) && value.cancelRequested === true;
}

function event(value: unknown): value is QuickDetectionEvent {
  if (!record(value) || !exact(value, [
    "sequence", "kind", "module", "outcome", "completed", "total",
  ]) || !unsigned(value.sequence) || value.sequence === 0 || !unsigned(value.completed, 13) ||
    !unsigned(value.total, 13) || value.total === 0 || value.completed > value.total) return false;
  if (value.kind === "module-started") {
    return isQuickDetectionModuleId(value.module) && value.outcome === null;
  }
  if (value.kind === "module-finished") {
    return isQuickDetectionModuleId(value.module) &&
      typeof value.outcome === "string" && outcomes.has(value.outcome as QuickDetectionOutcome);
  }
  return value.kind === "scan-finished" && value.module === null && value.outcome === null &&
    value.completed === value.total;
}

export function isQuickDetectionPoll(value: unknown): value is QuickDetectionPoll {
  if (!record(value) || !exact(value, [
    "scanHandle", "stage", "completed", "total", "currentModule", "cancelRequested",
    "events", "nextEventCursor", "eventsTruncated", "reportHandle", "errorCode",
  ]) || !isQuickDetectionOpaqueHandle(value.scanHandle) || typeof value.stage !== "string" ||
    !scanStages.has(value.stage as QuickDetectionScanStage) || !unsigned(value.completed, 13) ||
    !unsigned(value.total, 13) || value.total === 0 || value.completed > value.total ||
    !(value.currentModule === null || isQuickDetectionModuleId(value.currentModule)) ||
    typeof value.cancelRequested !== "boolean" || !Array.isArray(value.events) ||
    value.events.length > 32 || !value.events.every(event) || !unsigned(value.nextEventCursor) ||
    typeof value.eventsTruncated !== "boolean" ||
    !(value.reportHandle === null || isQuickDetectionOpaqueHandle(value.reportHandle)) ||
    !(value.errorCode === null || value.errorCode === "binding-stale" ||
      value.errorCode === "scan-failed" || value.errorCode === "report-rejected")) return false;
  const sequences = value.events.map((item) => item.sequence);
  if (sequences.some((sequence, index) => index > 0 && sequence <= (sequences[index - 1] ?? 0)) ||
    (sequences.at(-1) ?? 0) > value.nextEventCursor) return false;
  const terminalWithReport = value.stage === "completed" || value.stage === "cancelled";
  return terminalWithReport === (value.reportHandle !== null) &&
    (value.stage === "failed") === (value.errorCode !== null) &&
    (value.stage === "cancelling" || value.stage === "cancelled") === value.cancelRequested;
}

function historyItem(value: unknown): value is QuickDetectionHistoryItem {
  return record(value) && exact(value, [
    "reportHandle", "profile", "startedAt", "durationMs", "status", "overallScore",
    "moduleCount", "summary",
  ]) && isQuickDetectionOpaqueHandle(value.reportHandle) && profile(value.profile) &&
    timestamp(value.startedAt) && unsigned(value.durationMs) && typeof value.status === "string" &&
    reportStatuses.has(value.status as QuickDetectionReportStatus) && unsigned(value.overallScore, 100) &&
    unsigned(value.moduleCount, 13) && value.moduleCount > 0 && summary(value.summary);
}

export function isQuickDetectionHistoryPage(value: unknown): value is QuickDetectionHistoryPage {
  if (!record(value) || !exact(value, ["total", "offset", "hasMore", "items"]) ||
    !unsigned(value.total, 64) || !unsigned(value.offset, 56) || typeof value.hasMore !== "boolean" ||
    !Array.isArray(value.items) || value.items.length > 8 || !value.items.every(historyItem) ||
    value.offset + value.items.length > value.total) return false;
  return new Set(value.items.map((item) => item.reportHandle)).size === value.items.length &&
    value.hasMore === (value.offset + value.items.length < value.total);
}

function finding(value: unknown): value is QuickDetectionFinding {
  if (!record(value) || !exact(value, [
    "title", "description", "severity", "recommendation", "redacted", "textTruncated",
    "textProjected",
  ]) || !publicText(value.title, 512, true) || !publicText(value.description, 2_048, true) ||
    typeof value.severity !== "string" || !severities.has(value.severity as QuickDetectionSeverity) ||
    !(value.recommendation === null || publicText(value.recommendation, 2_048, true)) ||
    typeof value.redacted !== "boolean" || typeof value.textTruncated !== "boolean" ||
    typeof value.textProjected !== "boolean") return false;
  const redactedFieldCount = [value.title, value.description, value.recommendation]
    .filter((item) => item === QUICK_DETECTION_REDACTED_TEXT).length;
  return value.redacted === (redactedFieldCount > 0) &&
    (value.textProjected || !value.redacted && !value.textTruncated);
}

function moduleReport(value: unknown): value is QuickDetectionModuleReport {
  if (!record(value) || !exact(value, [
    "id", "label", "category", "outcome", "score", "durationMs", "findings",
    "findingsTruncated", "rawText", "rawTextRedacted", "rawTextTruncated", "rawTextProjected",
  ]) || !isQuickDetectionModuleId(value.id) || !text(value.label, 256) || !category(value.category) ||
    typeof value.outcome !== "string" || !outcomes.has(value.outcome as QuickDetectionOutcome) ||
    !unsigned(value.score, 100) || !unsigned(value.durationMs) || !Array.isArray(value.findings) ||
    value.findings.length > 100 || !value.findings.every(finding) ||
    typeof value.findingsTruncated !== "boolean" || !publicMultilineText(value.rawText, 64 * 1_024) ||
    typeof value.rawTextRedacted !== "boolean" || typeof value.rawTextTruncated !== "boolean" ||
    typeof value.rawTextProjected !== "boolean") return false;
  return value.rawTextRedacted === (value.rawText === QUICK_DETECTION_REDACTED_TEXT) &&
    (value.rawTextProjected || !value.rawTextRedacted && !value.rawTextTruncated);
}

export function isQuickDetectionReport(value: unknown): value is QuickDetectionReport {
  if (!record(value) || !exact(value, [
    "reportHandle", "profile", "startedAt", "durationMs", "status", "overallScore", "summary",
    "droppedProgressEvents", "redactedFieldCount", "textProjected", "truncated", "modules",
  ]) || !isQuickDetectionOpaqueHandle(value.reportHandle) || !profile(value.profile) ||
    !timestamp(value.startedAt) || !unsigned(value.durationMs) || typeof value.status !== "string" ||
    !reportStatuses.has(value.status as QuickDetectionReportStatus) || !unsigned(value.overallScore, 100) ||
    !summary(value.summary) || !unsigned(value.droppedProgressEvents) ||
    !unsigned(value.redactedFieldCount, 1_213) || typeof value.textProjected !== "boolean" ||
    typeof value.truncated !== "boolean" || !Array.isArray(value.modules) ||
    value.modules.length === 0 || value.modules.length > 13 || !value.modules.every(moduleReport)) return false;
  const redactedFieldCount = value.modules.reduce((total, module) => total +
    Number(module.rawTextRedacted) + module.findings.reduce((findingTotal, item) => findingTotal +
      [item.title, item.description, item.recommendation]
        .filter((field) => field === QUICK_DETECTION_REDACTED_TEXT).length, 0), 0);
  const textProjected = value.modules.some((module) => module.rawTextProjected ||
    module.findings.some((item) => item.textProjected));
  const truncated = value.modules.some((module) => module.findingsTruncated ||
    module.rawTextTruncated || module.findings.some((item) => item.textTruncated));
  const textBytes = value.modules.reduce((total, module) => total + encoder.encode(module.rawText).byteLength +
    module.findings.reduce((findingTotal, item) => findingTotal + encoder.encode(item.title).byteLength +
      encoder.encode(item.description).byteLength +
      (item.recommendation === null ? 0 : encoder.encode(item.recommendation).byteLength), 0), 0);
  return new Set(value.modules.map((item) => item.id)).size === value.modules.length &&
    value.modules.reduce((total, item) => total + item.findings.length, 0) <= 400 &&
    redactedFieldCount === value.redactedFieldCount && textProjected === value.textProjected &&
    truncated === value.truncated && textBytes <= 512 * 1_024;
}

export function isQuickDetectionHistoryRequest(offset: unknown, limit: unknown): boolean {
  return unsigned(offset, 56) && unsigned(limit, 8) && limit !== 0;
}

export function isQuickDetectionPollRequest(afterEvent: unknown, limit: unknown): boolean {
  return unsigned(afterEvent) && unsigned(limit, 32) && limit !== 0;
}
