export const INTEGRITY_PRESET_DEFINITIONS = [
  { id: "web-root", label: "/var/www（Web 根目录）", path: "/var/www", defaultSelected: true },
  { id: "usr-bin", label: "/usr/bin", path: "/usr/bin", defaultSelected: true },
  { id: "usr-sbin", label: "/usr/sbin", path: "/usr/sbin", defaultSelected: true },
  { id: "bin", label: "/bin", path: "/bin", defaultSelected: true },
  { id: "etc", label: "/etc", path: "/etc", defaultSelected: false },
  { id: "usr-local-bin", label: "/usr/local/bin", path: "/usr/local/bin", defaultSelected: false },
] as const;

export const INTEGRITY_REDACTED_PATH = "[SENSITIVE INTEGRITY PATH REDACTED]" as const;

export type IntegrityPresetId = (typeof INTEGRITY_PRESET_DEFINITIONS)[number]["id"];
export type IntegrityDiffKind = "added" | "removed" | "modified";
export type IntegritySeverity = "high" | "medium";
export type IntegrityOperationStage = "running" | "completed" | "cancelled" | "failed";

export interface IntegrityPreset {
  id: IntegrityPresetId;
  label: string;
  path: string;
  defaultSelected: boolean;
}

export interface IntegrityPresetCatalog {
  presets: IntegrityPreset[];
  maximumSelected: 6;
}

export interface IntegrityBaseline {
  baselineHandle: string;
  createdAt: string;
  paths: string[];
  pathsTruncated: boolean;
  redactedPathCount: number;
  textProjected: boolean;
  fileCount: number;
}

export interface IntegrityBaselineList {
  items: IntegrityBaseline[];
  truncated: boolean;
}

export interface IntegrityFinding {
  path: string;
  pathRedacted: boolean;
  pathTruncated: boolean;
  pathProjected: boolean;
  kind: IntegrityDiffKind;
  severity: IntegritySeverity;
}

export interface IntegrityComparison {
  baselineHandle: string;
  added: number;
  removed: number;
  modified: number;
  displayed: number;
  redactedPathCount: number;
  textProjected: boolean;
  truncated: boolean;
  entries: IntegrityFinding[];
}

export interface IntegrityComparisonStarted {
  operationHandle: string;
  baselineHandle: string;
  stage: "running";
  expiresInSeconds: number;
}

export interface IntegrityOperationEvent {
  sequence: number;
  kind: "started" | "completed" | "cancelled" | "failed";
}

export interface IntegrityComparisonPoll {
  operationHandle: string;
  baselineHandle: string;
  stage: IntegrityOperationStage;
  events: IntegrityOperationEvent[];
  nextEventCursor: number;
  eventsTruncated: boolean;
  comparison: IntegrityComparison | null;
  errorCode: "comparison-failed" | "comparison-rejected" | null;
}

export interface IntegrityComparisonCancellation {
  cancelled: true;
}

export interface IntegrityApi {
  getIntegrityPresets(): Promise<unknown>;
  listIntegrityBaselines(bindingHandle: string): Promise<unknown>;
  startIntegrityComparison(bindingHandle: string, baselineHandle: string): Promise<unknown>;
  pollIntegrityComparison(
    bindingHandle: string,
    operationHandle: string,
    afterEvent: number,
    limit: number,
  ): Promise<unknown>;
  cancelIntegrityComparison(bindingHandle: string, operationHandle: string): Promise<unknown>;
}

export const INTEGRITY_API_METHODS = [
  "getIntegrityPresets",
  "listIntegrityBaselines",
  "startIntegrityComparison",
  "pollIntegrityComparison",
  "cancelIntegrityComparison",
] as const satisfies readonly (keyof IntegrityApi)[];
type AssertNever<T extends never> = T;
export type IntegrityApiMethodCoverage = AssertNever<
  Exclude<keyof IntegrityApi, (typeof INTEGRITY_API_METHODS)[number]>
>;

type JsonRecord = Record<string, unknown>;
const encoder = new TextEncoder();
const presetIds = new Set<IntegrityPresetId>(
  INTEGRITY_PRESET_DEFINITIONS.map((preset) => preset.id),
);
const eventKinds = new Set(["started", "completed", "cancelled", "failed"]);

function record(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exact(value: JsonRecord, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && actual.every((key) => keys.includes(key));
}

function text(value: unknown, maximumBytes: number, allowEmpty = false): value is string {
  return typeof value === "string" && (allowEmpty || value.length > 0) &&
    encoder.encode(value).byteLength <= maximumBytes &&
    !/[\u0000-\u001f\u007f]/u.test(value);
}

function unsigned(value: unknown, maximum = Number.MAX_SAFE_INTEGER): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= maximum;
}

function timestamp(value: unknown): value is string {
  return text(value, 64) && !Number.isNaN(Date.parse(value));
}

export function isIntegrityOpaqueHandle(value: unknown): value is string {
  return text(value, 128) && /^[A-Za-z0-9-]+$/u.test(value);
}

export function isIntegrityPresetId(value: unknown): value is IntegrityPresetId {
  return typeof value === "string" && presetIds.has(value as IntegrityPresetId);
}

function containsSensitiveMaterial(value: string): boolean {
  const lower = value.toLowerCase();
  return [
    "password=", "password:", "passwd=", "passphrase=", "passphrase:", "secret=",
    "secret:", "token=", "token:", "authorization=", "authorization:", "api_key=",
    "api-key:", "apikey=", "private_key=", "private-key", "access_key", "access-key",
    "client_secret", "client-secret", "credential=", "credential:", "cookie:",
    "set-cookie:", "session_id=", "session-id:", "fingerprint=", "bearer ",
  ].some((marker) => lower.includes(marker)) ||
    /[a-z][a-z0-9+.-]*:\/\/[^\s/@]+(?::[^\s/@]*)?@/iu.test(value);
}

function safeDisplayPath(value: unknown): value is string {
  return text(value, 4_096) && value !== INTEGRITY_REDACTED_PATH &&
    value.startsWith("/") && !value.split("/").some((component) => component === "..") &&
    !containsSensitiveMaterial(value);
}

function projectedPath(
  value: unknown,
  redacted: unknown,
  truncated: unknown,
  projected: unknown,
): value is string {
  if (typeof redacted !== "boolean" || typeof truncated !== "boolean" ||
    typeof projected !== "boolean") return false;
  if (redacted) {
    return value === INTEGRITY_REDACTED_PATH && projected && !truncated;
  }
  return safeDisplayPath(value) && (projected || !truncated);
}

export function isIntegrityPresetCatalog(value: unknown): value is IntegrityPresetCatalog {
  if (!record(value) || !exact(value, ["presets", "maximumSelected"]) ||
    value.maximumSelected !== 6 || !Array.isArray(value.presets) ||
    value.presets.length !== INTEGRITY_PRESET_DEFINITIONS.length) return false;
  return value.presets.every((preset, index) => {
    const expected = INTEGRITY_PRESET_DEFINITIONS[index];
    return expected !== undefined && record(preset) &&
      exact(preset, ["id", "label", "path", "defaultSelected"]) &&
      preset.id === expected.id && preset.label === expected.label &&
      preset.path === expected.path && preset.defaultSelected === expected.defaultSelected;
  });
}

export function isIntegrityBaseline(value: unknown): value is IntegrityBaseline {
  if (!record(value) || !exact(value, [
    "baselineHandle", "createdAt", "paths", "pathsTruncated", "redactedPathCount",
    "textProjected", "fileCount",
  ]) || !isIntegrityOpaqueHandle(value.baselineHandle) || !timestamp(value.createdAt) ||
    !Array.isArray(value.paths) || value.paths.length > 16 ||
    typeof value.pathsTruncated !== "boolean" || !unsigned(value.redactedPathCount, 16) ||
    typeof value.textProjected !== "boolean" || !unsigned(value.fileCount)) return false;
  const redactedPathCount = value.paths.filter((path) => path === INTEGRITY_REDACTED_PATH).length;
  if (!value.paths.every((path) => path === INTEGRITY_REDACTED_PATH || safeDisplayPath(path)) ||
    redactedPathCount !== value.redactedPathCount ||
    (redactedPathCount > 0 && !value.textProjected)) return false;
  return value.paths.reduce((total, path) => total + encoder.encode(path).byteLength, 0) <=
    64 * 1_024;
}

export function isIntegrityBaselineList(value: unknown): value is IntegrityBaselineList {
  if (!record(value) || !exact(value, ["items", "truncated"]) ||
    !Array.isArray(value.items) || value.items.length > 64 ||
    !value.items.every(isIntegrityBaseline) || typeof value.truncated !== "boolean") return false;
  const handles = value.items.map((item) => item.baselineHandle);
  return new Set(handles).size === handles.length &&
    encoder.encode(JSON.stringify(value)).byteLength <= 256 * 1_024;
}

function diffKind(value: unknown): value is IntegrityDiffKind {
  return value === "added" || value === "removed" || value === "modified";
}

function severity(value: unknown): value is IntegritySeverity {
  return value === "high" || value === "medium";
}

export function isIntegrityFinding(value: unknown): value is IntegrityFinding {
  return record(value) && exact(value, [
    "path", "pathRedacted", "pathTruncated", "pathProjected", "kind", "severity",
  ]) && projectedPath(
    value.path,
    value.pathRedacted,
    value.pathTruncated,
    value.pathProjected,
  ) && diffKind(value.kind) && severity(value.severity);
}

export function isIntegrityComparison(value: unknown): value is IntegrityComparison {
  if (!record(value) || !exact(value, [
    "baselineHandle", "added", "removed", "modified", "displayed", "redactedPathCount",
    "textProjected", "truncated", "entries",
  ]) || !isIntegrityOpaqueHandle(value.baselineHandle) || !unsigned(value.added, 5_000) ||
    !unsigned(value.removed, 5_000) || !unsigned(value.modified, 5_000) ||
    !unsigned(value.displayed, 500) || !unsigned(value.redactedPathCount, 500) ||
    typeof value.textProjected !== "boolean" || typeof value.truncated !== "boolean" ||
    !Array.isArray(value.entries) || value.entries.length !== value.displayed ||
    !value.entries.every(isIntegrityFinding)) return false;
  const counts = { added: 0, removed: 0, modified: 0 };
  let pathBytes = 0;
  let redactedPathCount = 0;
  for (const entry of value.entries) {
    counts[entry.kind] += 1;
    pathBytes += encoder.encode(entry.path).byteLength;
    redactedPathCount += Number(entry.pathRedacted);
  }
  return counts.added <= value.added && counts.removed <= value.removed &&
    counts.modified <= value.modified && pathBytes <= 256 * 1_024 &&
    redactedPathCount === value.redactedPathCount &&
    (redactedPathCount === 0 || value.textProjected) &&
    value.textProjected === value.entries.some((entry) => entry.pathProjected) &&
    encoder.encode(JSON.stringify(value)).byteLength <= 768 * 1_024;
}

export function isIntegrityComparisonStarted(
  value: unknown,
): value is IntegrityComparisonStarted {
  return record(value) && exact(value, [
    "operationHandle", "baselineHandle", "stage", "expiresInSeconds",
  ]) && isIntegrityOpaqueHandle(value.operationHandle) &&
    isIntegrityOpaqueHandle(value.baselineHandle) && value.stage === "running" &&
    unsigned(value.expiresInSeconds, 300) && value.expiresInSeconds > 0;
}

function operationEvent(value: unknown): value is IntegrityOperationEvent {
  return record(value) && exact(value, ["sequence", "kind"]) &&
    unsigned(value.sequence) && value.sequence > 0 &&
    typeof value.kind === "string" && eventKinds.has(value.kind);
}

export function isIntegrityComparisonPoll(value: unknown): value is IntegrityComparisonPoll {
  if (!record(value) || !exact(value, [
    "operationHandle", "baselineHandle", "stage", "events", "nextEventCursor",
    "eventsTruncated", "comparison", "errorCode",
  ]) || !isIntegrityOpaqueHandle(value.operationHandle) ||
    !isIntegrityOpaqueHandle(value.baselineHandle) ||
    !(value.stage === "running" || value.stage === "completed" ||
      value.stage === "cancelled" || value.stage === "failed") ||
    !Array.isArray(value.events) || value.events.length > 8 ||
    !value.events.every(operationEvent) || !unsigned(value.nextEventCursor) ||
    typeof value.eventsTruncated !== "boolean" ||
    !(value.errorCode === null || value.errorCode === "comparison-failed" ||
      value.errorCode === "comparison-rejected")) return false;
  const sequences = value.events.map((event) => event.sequence);
  if (sequences.some((sequence, index) => index > 0 &&
    sequence <= (sequences[index - 1] ?? 0)) ||
    (sequences.at(-1) ?? 0) > value.nextEventCursor) return false;
  if (value.events.some((event) => event.kind !== "started" && event.kind !== value.stage)) {
    return false;
  }
  if (value.stage === "completed") {
    return isIntegrityComparison(value.comparison) &&
      value.comparison.baselineHandle === value.baselineHandle && value.errorCode === null;
  }
  if (value.stage === "failed") {
    return value.comparison === null && value.errorCode !== null;
  }
  return value.comparison === null && value.errorCode === null;
}

export function isIntegrityComparisonCancellation(
  value: unknown,
): value is IntegrityComparisonCancellation {
  return record(value) && exact(value, ["cancelled"]) && value.cancelled === true;
}

export function isIntegrityPollRequest(afterEvent: unknown, limit: unknown): boolean {
  return unsigned(afterEvent) && unsigned(limit, 8) && limit !== 0;
}
