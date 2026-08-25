export type MiddlewareProduct = "nginx" | "apache-httpd" | "redis" | "tomcat";
export type MiddlewareInstanceStatus =
  | "active"
  | "inactive"
  | "failed"
  | "activating"
  | "deactivating"
  | "reloading"
  | "unknown";
export type MiddlewareConfigRole =
  | "primary"
  | "included"
  | "tomcat-web"
  | "tomcat-context"
  | "properties"
  | "logging"
  | "users"
  | "other";
export type MiddlewareNodeKind =
  | "preamble"
  | "whitespace"
  | "comment"
  | "directive"
  | "block-start"
  | "block-end"
  | "element-start"
  | "element-end"
  | "attribute"
  | "text"
  | "cdata"
  | "processing-instruction"
  | "declaration"
  | "opaque";
export type MiddlewareHistoryState =
  | "recovery-pending"
  | "applied"
  | "automatically-restored"
  | "restore-failed";
export type MiddlewareRawTextReason = "available" | "not-safe-text" | "sensitive" | "size-limit";

export interface MiddlewareInstanceSummary {
  instanceHandle: string;
  title: string;
  product: MiddlewareProduct;
  version: string;
  status: MiddlewareInstanceStatus;
  statusText: string;
  active: boolean;
  redacted: boolean;
  textTruncated: boolean;
}

export interface MiddlewareDiscovery {
  discoveryHandle: string;
  expiresInSeconds: number;
  instances: MiddlewareInstanceSummary[];
  discoveredCount: number;
  displayed: number;
  redactedFieldCount: number;
  truncated: boolean;
}

export interface MiddlewareNodeSummary {
  kind: MiddlewareNodeKind;
  name: string | null;
  depth: number;
  editable: boolean;
  sensitive: boolean;
  redacted: boolean;
  textTruncated: boolean;
}

export interface MiddlewareConfigurationFile {
  fileHandle: string;
  ordinal: number;
  role: MiddlewareConfigRole;
  byteLength: string;
  contentMode: "raw-text" | "structured-only";
  rawText: string | null;
  rawTextUnavailableReason: MiddlewareRawTextReason;
  nodeCount: number;
  displayedNodes: number;
  nodes: MiddlewareNodeSummary[];
  containsSensitiveValues: boolean;
  redactedFieldCount: number;
  truncated: boolean;
}

export interface MiddlewareConfiguration {
  discoveryHandle: string;
  instanceHandle: string;
  product: MiddlewareProduct;
  loadedAt: string;
  totalBytes: string;
  fileCount: number;
  unresolvedIncludeCount: number;
  directoryManifestCount: number;
  files: MiddlewareConfigurationFile[];
  displayed: number;
  displayedNodes: number;
  redactedFieldCount: number;
  truncated: boolean;
}

export interface MiddlewareHistoryEntry {
  historyItemHandle: string;
  product: MiddlewareProduct;
  state: MiddlewareHistoryState;
  summary: string;
  oldBytes: string;
  newBytes: string;
  createdAt: string;
  updatedAt: string;
}

export interface MiddlewareHistory {
  historyHandle: string;
  expiresInSeconds: number;
  entries: MiddlewareHistoryEntry[];
  recordCount: number;
  displayed: number;
  truncated: boolean;
}

export interface MiddlewareReadApi {
  discoverMiddleware(bindingHandle: string): Promise<unknown>;
  loadMiddlewareConfiguration(
    bindingHandle: string,
    discoveryHandle: string,
    instanceHandle: string,
  ): Promise<unknown>;
  listMiddlewareHistory(bindingHandle: string): Promise<unknown>;
}

type JsonRecord = Record<string, unknown>;
const encoder = new TextEncoder();
const redactedText = "[SENSITIVE MIDDLEWARE TEXT REDACTED]";
const products = new Set<MiddlewareProduct>(["nginx", "apache-httpd", "redis", "tomcat"]);
const statuses = new Set<MiddlewareInstanceStatus>([
  "active", "inactive", "failed", "activating", "deactivating", "reloading", "unknown",
]);
const roles = new Set<MiddlewareConfigRole>([
  "primary", "included", "tomcat-web", "tomcat-context", "properties", "logging", "users", "other",
]);
const nodeKinds = new Set<MiddlewareNodeKind>([
  "preamble", "whitespace", "comment", "directive", "block-start", "block-end", "element-start",
  "element-end", "attribute", "text", "cdata", "processing-instruction", "declaration", "opaque",
]);
const historyStates = new Set<MiddlewareHistoryState>([
  "recovery-pending", "applied", "automatically-restored", "restore-failed",
]);
const rawReasons = new Set<MiddlewareRawTextReason>([
  "available", "not-safe-text", "sensitive", "size-limit",
]);

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

/**
 * Bounded, control-character-free text. It does not judge the content: a
 * collected line that mentions a credential is the evidence, and refusing it
 * here would reject the whole response rather than one line.
 */
function publicText(value: unknown, maximumBytes: number, allowEmpty = true): value is string {
  return text(value, maximumBytes, allowEmpty) &&
    !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value);
}

function remoteText(value: unknown, maximumBytes: number): value is string {
  return value === redactedText || publicText(value, maximumBytes);
}

function timestamp(value: unknown): value is string {
  return publicText(value, 64, false) && /^\d{4}-\d{2}-\d{2}T/u.test(value) &&
    Number.isFinite(Date.parse(value));
}

function decimalBytes(value: unknown, maximum: bigint): value is string {
  if (typeof value !== "string" || !/^(?:0|[1-9]\d{0,19})$/u.test(value)) return false;
  try {
    return BigInt(value) <= maximum;
  } catch {
    return false;
  }
}

function serializedWithin(value: unknown, maximumBytes: number): boolean {
  try {
    const encoded = JSON.stringify(value);
    return typeof encoded === "string" && encoder.encode(encoded).byteLength <= maximumBytes;
  } catch {
    return false;
  }
}

function textWithin(values: Iterable<string>, maximumBytes: number): boolean {
  let total = 0;
  for (const value of values) {
    total += encoder.encode(value).byteLength;
    if (total > maximumBytes) return false;
  }
  return true;
}

export function isMiddlewareOpaqueHandle(value: unknown): value is string {
  return text(value, 128, false) && /^[A-Za-z0-9_-]+$/u.test(value);
}

function instanceSummary(value: unknown): value is MiddlewareInstanceSummary {
  if (!record(value) || !exact(value, [
    "instanceHandle", "title", "product", "version", "status", "statusText", "active", "redacted",
    "textTruncated",
  ]) || !isMiddlewareOpaqueHandle(value.instanceHandle) || !publicText(value.title, 128, false) ||
    typeof value.product !== "string" || !products.has(value.product as MiddlewareProduct) ||
    !remoteText(value.version, 256) || typeof value.status !== "string" ||
    !statuses.has(value.status as MiddlewareInstanceStatus) || !remoteText(value.statusText, 256) ||
    typeof value.active !== "boolean" || typeof value.redacted !== "boolean" ||
    typeof value.textTruncated !== "boolean") return false;
  const redactedFields = Number(value.version === redactedText) + Number(value.statusText === redactedText);
  return value.redacted === (redactedFields > 0) && (value.status === "active") === value.active;
}

export function isMiddlewareDiscovery(value: unknown): value is MiddlewareDiscovery {
  if (!record(value) || !exact(value, [
    "discoveryHandle", "expiresInSeconds", "instances", "discoveredCount", "displayed",
    "redactedFieldCount", "truncated",
  ]) || !isMiddlewareOpaqueHandle(value.discoveryHandle) || !unsigned(value.expiresInSeconds, 300) ||
    value.expiresInSeconds < 1 || !Array.isArray(value.instances) || value.instances.length > 32 ||
    !value.instances.every(instanceSummary) || !unsigned(value.discoveredCount, 32) ||
    !unsigned(value.displayed, 32) || value.displayed !== value.instances.length ||
    value.discoveredCount < value.displayed || !unsigned(value.redactedFieldCount, value.displayed * 2) ||
    typeof value.truncated !== "boolean") return false;
  const instances = value.instances as MiddlewareInstanceSummary[];
  return new Set(instances.map((item) => item.instanceHandle)).size === instances.length &&
    value.redactedFieldCount === instances.reduce((count, item) => count +
      Number(item.version === redactedText) + Number(item.statusText === redactedText), 0) &&
    (value.discoveredCount === value.displayed || value.truncated) &&
    (!instances.some((item) => item.textTruncated) || value.truncated) &&
    textWithin(instances.flatMap((item) => [item.title, item.version, item.statusText]), 32 * 1_024) &&
    serializedWithin(value, 256 * 1_024);
}

function nodeSummary(value: unknown): value is MiddlewareNodeSummary {
  if (!record(value) || !exact(value, [
    "kind", "name", "depth", "editable", "sensitive", "redacted", "textTruncated",
  ]) || typeof value.kind !== "string" || !nodeKinds.has(value.kind as MiddlewareNodeKind) ||
    !(value.name === null || remoteText(value.name, 128)) || !unsigned(value.depth, 65_536) ||
    typeof value.editable !== "boolean" || typeof value.sensitive !== "boolean" ||
    typeof value.redacted !== "boolean" || typeof value.textTruncated !== "boolean") return false;
  return value.redacted === (value.name === redactedText) && (!value.sensitive || value.editable);
}

function configurationFile(value: unknown): value is MiddlewareConfigurationFile {
  if (!record(value) || !exact(value, [
    "fileHandle", "ordinal", "role", "byteLength", "contentMode", "rawText",
    "rawTextUnavailableReason", "nodeCount", "displayedNodes", "nodes", "containsSensitiveValues",
    "redactedFieldCount", "truncated",
  ]) || !isMiddlewareOpaqueHandle(value.fileHandle) || !unsigned(value.ordinal, 64) || value.ordinal < 1 ||
    typeof value.role !== "string" || !roles.has(value.role as MiddlewareConfigRole) ||
    !decimalBytes(value.byteLength, 4_194_304n) ||
    !(value.contentMode === "raw-text" || value.contentMode === "structured-only") ||
    !(value.rawText === null || publicText(value.rawText, 128 * 1_024)) ||
    typeof value.rawTextUnavailableReason !== "string" ||
    !rawReasons.has(value.rawTextUnavailableReason as MiddlewareRawTextReason) ||
    !unsigned(value.nodeCount, 65_536) || !unsigned(value.displayedNodes, 256) ||
    !Array.isArray(value.nodes) || value.nodes.length !== value.displayedNodes ||
    !value.nodes.every(nodeSummary) || value.nodeCount < value.displayedNodes ||
    typeof value.containsSensitiveValues !== "boolean" ||
    !unsigned(value.redactedFieldCount, value.displayedNodes + 1) || typeof value.truncated !== "boolean") return false;
  const nodes = value.nodes as MiddlewareNodeSummary[];
  const rawAvailable = value.rawTextUnavailableReason === "available";
  const rawSensitive = value.rawTextUnavailableReason === "sensitive";
  return rawAvailable === (value.contentMode === "raw-text" && value.rawText !== null) &&
    (!rawAvailable || !value.containsSensitiveValues) &&
    (!rawSensitive || value.rawText === null) &&
    value.redactedFieldCount === nodes.filter((node) => node.redacted).length + Number(rawSensitive) &&
    (!nodes.some((node) => node.textTruncated) || value.truncated) &&
    (value.nodeCount === value.displayedNodes || value.truncated) &&
    (value.rawTextUnavailableReason !== "size-limit" || value.truncated);
}

export function isMiddlewareConfiguration(value: unknown): value is MiddlewareConfiguration {
  if (!record(value) || !exact(value, [
    "discoveryHandle", "instanceHandle", "product", "loadedAt", "totalBytes", "fileCount",
    "unresolvedIncludeCount", "directoryManifestCount", "files", "displayed", "displayedNodes",
    "redactedFieldCount", "truncated",
  ]) || !isMiddlewareOpaqueHandle(value.discoveryHandle) || !isMiddlewareOpaqueHandle(value.instanceHandle) ||
    typeof value.product !== "string" || !products.has(value.product as MiddlewareProduct) ||
    !timestamp(value.loadedAt) || !decimalBytes(value.totalBytes, 16_777_216n) ||
    !unsigned(value.fileCount, 256) || !unsigned(value.unresolvedIncludeCount, 65_536) ||
    !unsigned(value.directoryManifestCount, 256) || !Array.isArray(value.files) ||
    value.files.length > 64 || !value.files.every(configurationFile) || !unsigned(value.displayed, 64) ||
    value.displayed !== value.files.length || value.fileCount < value.displayed ||
    !unsigned(value.displayedNodes, 1_024) || !unsigned(value.redactedFieldCount, 1_088) ||
    typeof value.truncated !== "boolean") return false;
  const files = value.files as MiddlewareConfigurationFile[];
  return new Set(files.map((file) => file.fileHandle)).size === files.length &&
    files.every((file, index) => file.ordinal === index + 1) &&
    value.displayedNodes === files.reduce((total, file) => total + file.displayedNodes, 0) &&
    value.redactedFieldCount === files.reduce((total, file) => total + file.redactedFieldCount, 0) &&
    (value.fileCount === value.displayed || value.truncated) &&
    (!files.some((file) => file.truncated) || value.truncated) &&
    textWithin(files.flatMap((file) => [
      ...(file.rawText === null ? [] : [file.rawText]),
      ...file.nodes.flatMap((node) => node.name === null ? [] : [node.name]),
    ]), 640 * 1_024) && serializedWithin(value, 1_024 * 1_024);
}

function historyEntry(value: unknown): value is MiddlewareHistoryEntry {
  return record(value) && exact(value, [
    "historyItemHandle", "product", "state", "summary", "oldBytes", "newBytes", "createdAt", "updatedAt",
  ]) && isMiddlewareOpaqueHandle(value.historyItemHandle) && typeof value.product === "string" &&
    products.has(value.product as MiddlewareProduct) && typeof value.state === "string" &&
    historyStates.has(value.state as MiddlewareHistoryState) && publicText(value.summary, 256, false) &&
    decimalBytes(value.oldBytes, 4_194_304n) && decimalBytes(value.newBytes, 4_194_304n) &&
    timestamp(value.createdAt) && timestamp(value.updatedAt) &&
    Date.parse(value.updatedAt) >= Date.parse(value.createdAt);
}

export function isMiddlewareHistory(value: unknown): value is MiddlewareHistory {
  if (!record(value) || !exact(value, [
    "historyHandle", "expiresInSeconds", "entries", "recordCount", "displayed", "truncated",
  ]) || !isMiddlewareOpaqueHandle(value.historyHandle) || !unsigned(value.expiresInSeconds, 300) ||
    value.expiresInSeconds < 1 || !Array.isArray(value.entries) || value.entries.length > 128 ||
    !value.entries.every(historyEntry) || !unsigned(value.recordCount, 512) || !unsigned(value.displayed, 128) ||
    value.displayed !== value.entries.length || value.recordCount < value.displayed ||
    typeof value.truncated !== "boolean") return false;
  const entries = value.entries as MiddlewareHistoryEntry[];
  return new Set(entries.map((entry) => entry.historyItemHandle)).size === entries.length &&
    entries.every((entry, index) => index === 0 ||
      Date.parse(entries[index - 1]!.updatedAt) >= Date.parse(entry.updatedAt)) &&
    (value.recordCount === value.displayed || value.truncated) &&
    textWithin(entries.map((entry) => entry.summary), 32 * 1_024) &&
    serializedWithin(value, 256 * 1_024);
}
