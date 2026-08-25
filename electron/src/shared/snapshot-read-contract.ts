export const snapshotKinds = ["directory", "forensic"] as const;
export const snapshotPresets = [
  "etc", "current-crontab", "passwd", "shadow", "authorized-keys", "web-root", "cron-spool", "root-home",
] as const;
export const snapshotItemKinds = ["file", "directory", "crontab"] as const;
export const forensicCollectors = [
  "processes", "networkConnections", "listeningPorts", "loginHistory", "cronJobs", "startupServices",
  "authorizedKeys", "sudoers", "runningUsers", "loadedModules", "recentModifiedFiles", "envVariables",
] as const;
export const fullyRedactedForensicCollectors = [
  "processes", "loginHistory", "cronJobs", "authorizedKeys", "sudoers", "recentModifiedFiles", "envVariables",
] as const;

export type SnapshotKind = typeof snapshotKinds[number];
export type SnapshotPreset = typeof snapshotPresets[number];
export type SnapshotItemKind = typeof snapshotItemKinds[number];
export type ForensicCollector = typeof forensicCollectors[number];

export interface SnapshotListItem {
  snapshotHandle: string;
  kind: SnapshotKind;
  capturedAt: string;
  itemCount: number;
  completedCollectors: number | null;
  failedCollectors: number | null;
}

export interface SnapshotListResult {
  expiresInSeconds: number;
  snapshots: SnapshotListItem[];
  directoryCount: number;
  forensicCount: number;
  truncated: boolean;
}

export interface DirectorySnapshotItem {
  preset: SnapshotPreset;
  kind: SnapshotItemKind;
  bytes: string;
  present: boolean;
  archiveAvailability: "not-checked";
}

export interface DirectorySnapshotDetail {
  snapshotHandle: string;
  kind: "directory";
  capturedAt: string;
  items: DirectorySnapshotItem[];
  truncated: boolean;
}

export interface ForensicField {
  collector: ForensicCollector;
  text: string;
  redactedLineCount: number;
  truncated: boolean;
}

export interface ForensicSnapshotDetail {
  snapshotHandle: string;
  kind: "forensic";
  capturedAt: string;
  totalCollectors: number;
  completedCollectors: number;
  failedCollectors: number;
  fields: ForensicField[];
  redactedLineCount: number;
  truncated: boolean;
}

export type SnapshotDetail = DirectorySnapshotDetail | ForensicSnapshotDetail;

export interface SnapshotDiffInput {
  olderSnapshotHandle: string;
  newerSnapshotHandle: string;
}

export interface ForensicDiffField {
  collector: ForensicCollector;
  added: string[];
  removed: string[];
  redactedLineCount: number;
  truncated: boolean;
}

export interface SnapshotDiffResult {
  olderSnapshotHandle: string;
  newerSnapshotHandle: string;
  fields: ForensicDiffField[];
  addedLineCount: number;
  removedLineCount: number;
  redactedLineCount: number;
  truncated: boolean;
}

export interface SnapshotReadApi {
  listSnapshots(bindingHandle: string): Promise<SnapshotListResult>;
  getSnapshotDetail(bindingHandle: string, snapshotHandle: string): Promise<SnapshotDetail>;
  diffForensicSnapshots(bindingHandle: string, input: SnapshotDiffInput): Promise<SnapshotDiffResult>;
}

type JsonRecord = Record<string, unknown>;
const encoder = new TextEncoder();
const redactedLine = "[SENSITIVE SNAPSHOT TEXT REDACTED]";
const failedCollectorLine = "[FORENSIC COLLECTOR FAILED]";
const kindSet = new Set<string>(snapshotKinds);
const presetSet = new Set<string>(snapshotPresets);
const itemKindSet = new Set<string>(snapshotItemKinds);
const collectorSet = new Set<string>(forensicCollectors);
const fullyRedactedCollectorSet = new Set<string>(fullyRedactedForensicCollectors);

function record(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exact(value: JsonRecord, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && actual.every((key) => keys.includes(key));
}

function text(value: unknown, maximumBytes: number, allowEmpty = true): value is string {
  return typeof value === "string" && (allowEmpty || value.length > 0) &&
    encoder.encode(value).byteLength <= maximumBytes;
}

function unsigned(value: unknown, maximum: number): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= maximum;
}

function publicText(value: unknown, maximumBytes: number): value is string {
  return text(value, maximumBytes) && !containsSensitiveMaterial(value);
}

function containsSensitiveMaterial(value: string): boolean {
  const lower = value.toLowerCase();
  const compact = lower.replace(/\s/gu, "");
  return [
    "password=", "password:", "password_", "_password", "--password", "passwd=", "passphrase=",
    "passphrase:", "secret=", "secret:", "secret_", "_secret", "--secret", "token=", "token:",
    "token_", "_token", "--token", "authorization=", "authorization:", "api_key=", "apikey=",
    "private_key=", "private_key", "private-key", "access_key", "access-key", "client_secret", "client-secret",
    "private key-----", "credential=", "cookie:", "set-cookie:", "session_id=", "fingerprint=", "bearer ",
  ].some((marker) => lower.includes(marker)) || [
    "password=", "password:", "passwd=", "passphrase=", "passphrase:", "secret=", "secret:",
    "token=", "token:", "authorization=", "authorization:", "api_key=", "apikey=", "private_key=",
    "access_key=", "client_secret=", "credential=",
  ].some((marker) => compact.includes(marker)) || /(?:^|\s)-p\S*/iu.test(lower) ||
    lower.includes("-----begin ") && lower.includes(" private key-----") ||
    lower.includes("://") && lower.includes("@");
}

function serializedWithin(value: unknown, maximumBytes: number): boolean {
  try {
    const encoded = JSON.stringify(value);
    return typeof encoded === "string" && encoder.encode(encoded).byteLength <= maximumBytes;
  } catch {
    return false;
  }
}

function lineCount(value: string): number {
  return value.length === 0 ? 0 : value.split("\n").length;
}

function redactedLines(value: string): number {
  return value.length === 0 ? 0 : value.split("\n")
    .filter((line) => line === redactedLine || line === failedCollectorLine).length;
}

function isCollectorPolicyMarker(value: unknown): value is string {
  return value === redactedLine || value === failedCollectorLine;
}

export function isSnapshotOpaqueHandle(value: unknown): value is string {
  return text(value, 128, false) && /^[A-Za-z0-9-]+$/u.test(value);
}

function capturedAt(value: unknown): value is string {
  return text(value, 64, false) &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|\+00:00)$/u.test(value) &&
    Number.isFinite(Date.parse(value));
}

function listItem(value: unknown): value is SnapshotListItem {
  if (!record(value) || !exact(value, [
    "snapshotHandle", "kind", "capturedAt", "itemCount", "completedCollectors", "failedCollectors",
  ]) || !isSnapshotOpaqueHandle(value.snapshotHandle) || typeof value.kind !== "string" ||
    !kindSet.has(value.kind) || !capturedAt(value.capturedAt)) return false;
  if (value.kind === "directory") {
    return unsigned(value.itemCount, 8) && value.itemCount > 0 &&
      value.completedCollectors === null && value.failedCollectors === null;
  }
  return value.itemCount === 12 && value.completedCollectors === 12 &&
    unsigned(value.failedCollectors, 12);
}

export function isSnapshotListResult(value: unknown): value is SnapshotListResult {
  if (!record(value) || !exact(value, [
    "expiresInSeconds", "snapshots", "directoryCount", "forensicCount", "truncated",
  ]) || !unsigned(value.expiresInSeconds, 300) || value.expiresInSeconds === 0 ||
    !Array.isArray(value.snapshots) || value.snapshots.length > 74 || !value.snapshots.every(listItem) ||
    !unsigned(value.directoryCount, 64) || !unsigned(value.forensicCount, 10) ||
    value.directoryCount + value.forensicCount !== value.snapshots.length ||
    typeof value.truncated !== "boolean" || !serializedWithin(value, 128 * 1_024)) return false;
  const snapshots = value.snapshots as SnapshotListItem[];
  return new Set(snapshots.map((snapshot) => snapshot.snapshotHandle)).size === snapshots.length &&
    snapshots.filter((snapshot) => snapshot.kind === "directory").length === value.directoryCount &&
    snapshots.filter((snapshot) => snapshot.kind === "forensic").length === value.forensicCount &&
    snapshots.every((snapshot, index) => index === 0 ||
      Date.parse(snapshots[index - 1]!.capturedAt) >= Date.parse(snapshot.capturedAt));
}

function directoryItem(value: unknown): value is DirectorySnapshotItem {
  if (!record(value) || !exact(value, [
    "preset", "kind", "bytes", "present", "archiveAvailability",
  ]) || typeof value.preset !== "string" || !presetSet.has(value.preset) ||
    typeof value.kind !== "string" || !itemKindSet.has(value.kind) ||
    typeof value.bytes !== "string" || !/^(?:0|[1-9][0-9]{0,19})$/u.test(value.bytes) ||
    typeof value.present !== "boolean" || value.archiveAvailability !== "not-checked") return false;
  try {
    return BigInt(value.bytes) <= 18_446_744_073_709_551_615n;
  } catch {
    return false;
  }
}

function isDirectoryDetail(value: JsonRecord): value is JsonRecord & DirectorySnapshotDetail {
  if (!exact(value, ["snapshotHandle", "kind", "capturedAt", "items", "truncated"]) ||
    !isSnapshotOpaqueHandle(value.snapshotHandle) || value.kind !== "directory" || !capturedAt(value.capturedAt) ||
    !Array.isArray(value.items) || value.items.length === 0 || value.items.length > 8 ||
    !value.items.every(directoryItem) || typeof value.truncated !== "boolean") return false;
  const items = value.items as DirectorySnapshotItem[];
  return new Set(items.map((item) => item.preset)).size === items.length &&
    serializedWithin(value, 768 * 1_024);
}

function forensicField(value: unknown, collector: ForensicCollector): value is ForensicField {
  if (!record(value) || !exact(value, ["collector", "text", "redactedLineCount", "truncated"]) ||
    value.collector !== collector || typeof value.truncated !== "boolean") return false;
  if (fullyRedactedCollectorSet.has(collector)) {
    return isCollectorPolicyMarker(value.text) && value.redactedLineCount === 1;
  }
  return publicText(value.text, 512 * 1_024) && lineCount(value.text) <= 512 &&
    unsigned(value.redactedLineCount, 512) && value.redactedLineCount === redactedLines(value.text);
}

function isForensicDetail(value: JsonRecord): value is JsonRecord & ForensicSnapshotDetail {
  if (!exact(value, [
    "snapshotHandle", "kind", "capturedAt", "totalCollectors", "completedCollectors", "failedCollectors",
    "fields", "redactedLineCount", "truncated",
  ]) || !isSnapshotOpaqueHandle(value.snapshotHandle) || value.kind !== "forensic" ||
    !capturedAt(value.capturedAt) || value.totalCollectors !== 12 || value.completedCollectors !== 12 ||
    !unsigned(value.failedCollectors, 12) || !Array.isArray(value.fields) || value.fields.length !== 12 ||
    !value.fields.every((field, index) => forensicField(field, forensicCollectors[index]!)) ||
    !unsigned(value.redactedLineCount, 2_048) || typeof value.truncated !== "boolean") return false;
  const fields = value.fields as ForensicField[];
  const totalTextBytes = fields.reduce((total, field) => total + encoder.encode(field.text).byteLength, 0);
  const totalLines = fields.reduce((total, field) => total + lineCount(field.text), 0);
  return totalTextBytes <= 512 * 1_024 && totalLines <= 2_048 &&
    value.redactedLineCount === fields.reduce((total, field) => total + field.redactedLineCount, 0) &&
    value.truncated === fields.some((field) => field.truncated) && serializedWithin(value, 768 * 1_024);
}

export function isSnapshotDetail(value: unknown): value is SnapshotDetail {
  return record(value) && (value.kind === "directory" ? isDirectoryDetail(value) :
    value.kind === "forensic" && isForensicDetail(value));
}

export function isSnapshotDiffInput(value: unknown): value is SnapshotDiffInput {
  return record(value) && exact(value, ["olderSnapshotHandle", "newerSnapshotHandle"]) &&
    isSnapshotOpaqueHandle(value.olderSnapshotHandle) && isSnapshotOpaqueHandle(value.newerSnapshotHandle) &&
    value.olderSnapshotHandle !== value.newerSnapshotHandle;
}

function diffLine(value: unknown): value is string {
  return publicText(value, 4 * 1_024) && !/[\r\n]/u.test(value);
}

function diffField(value: unknown, collector: ForensicCollector): value is ForensicDiffField {
  if (!record(value) || !exact(value, [
    "collector", "added", "removed", "redactedLineCount", "truncated",
  ]) || value.collector !== collector || !Array.isArray(value.added) || !Array.isArray(value.removed) ||
    typeof value.truncated !== "boolean") return false;
  if (fullyRedactedCollectorSet.has(collector)) {
    const lines = [...value.added, ...value.removed];
    return value.added.length <= 1 && value.removed.length <= 1 && lines.every(isCollectorPolicyMarker) &&
      value.redactedLineCount === lines.length;
  }
  if (value.added.length > 200 || !value.added.every(diffLine) || value.removed.length > 200 ||
    !value.removed.every(diffLine) || !unsigned(value.redactedLineCount, 400)) return false;
  const lines = [...value.added, ...value.removed] as string[];
  return value.redactedLineCount === lines.filter((line) =>
    line === redactedLine || line === failedCollectorLine).length;
}

export function isSnapshotDiffResult(value: unknown): value is SnapshotDiffResult {
  if (!record(value) || !exact(value, [
    "olderSnapshotHandle", "newerSnapshotHandle", "fields", "addedLineCount", "removedLineCount",
    "redactedLineCount", "truncated",
  ]) || !isSnapshotOpaqueHandle(value.olderSnapshotHandle) ||
    !isSnapshotOpaqueHandle(value.newerSnapshotHandle) ||
    value.olderSnapshotHandle === value.newerSnapshotHandle || !Array.isArray(value.fields) ||
    value.fields.length !== 12 || !value.fields.every((field, index) =>
      diffField(field, forensicCollectors[index]!)) || !unsigned(value.addedLineCount, 1_000) ||
    !unsigned(value.removedLineCount, 1_000) || !unsigned(value.redactedLineCount, 1_000) ||
    typeof value.truncated !== "boolean") return false;
  const fields = value.fields as ForensicDiffField[];
  const added = fields.reduce((total, field) => total + field.added.length, 0);
  const removed = fields.reduce((total, field) => total + field.removed.length, 0);
  const redacted = fields.reduce((total, field) => total + field.redactedLineCount, 0);
  const textBytes = fields.reduce((total, field) => total + [...field.added, ...field.removed]
    .reduce((fieldTotal, line) => fieldTotal + encoder.encode(line).byteLength, 0), 0);
  return added + removed <= 1_000 && added === value.addedLineCount && removed === value.removedLineCount &&
    redacted === value.redactedLineCount && textBytes <= 512 * 1_024 &&
    value.truncated === fields.some((field) => field.truncated) && serializedWithin(value, 768 * 1_024);
}
