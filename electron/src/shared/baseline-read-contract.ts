export type BaselineCategory =
  | "ssh"
  | "password"
  | "kernel"
  | "network"
  | "authentication"
  | "logging"
  | "file-permissions";

export type BaselineRisk = "critical" | "high" | "medium" | "low";
export type BaselineObservedKind = "missing" | "unsupported" | "value";
export type BaselineHistoryState = "applied" | "restored";

export type BaselineValueKind =
  | { kind: "choice"; options: string[] }
  | { kind: "integer"; minimum: number; maximum: number };

export interface BaselineCatalogItem {
  itemHandle: string;
  category: BaselineCategory;
  risk: BaselineRisk;
  valueKind: BaselineValueKind;
  title: string;
  description: string;
  recommendation: string;
}

export interface BaselineCatalog {
  items: BaselineCatalogItem[];
  displayed: number;
  truncated: boolean;
}

export interface BaselineStatus {
  itemHandle: string;
  observedKind: BaselineObservedKind;
  observed: string;
  compliant: boolean;
  redacted: boolean;
  textTruncated: boolean;
}

export interface BaselineScan {
  scanHandle: string;
  capturedAt: string;
  expiresInSeconds: number;
  statuses: BaselineStatus[];
  displayed: number;
  compliantCount: number;
  nonCompliantCount: number;
  redactedFieldCount: number;
  truncated: boolean;
}

export interface BaselineHistoryEntry {
  historyItemHandle: string;
  state: BaselineHistoryState;
  summary: string;
  changeCount: number;
  createdAt: string;
  updatedAt: string;
  redacted: boolean;
  textTruncated: boolean;
}

export interface BaselineHistory {
  historyHandle: string;
  expiresInSeconds: number;
  entries: BaselineHistoryEntry[];
  displayed: number;
  redactedFieldCount: number;
  truncated: boolean;
}

/**
 * A line of a configuration file that names the setting being checked.
 *
 * `effective` marks the one line the program on the target actually obeys.
 * A commented line never is, and when the same setting is written more than
 * once only one of them counts — which one depends on the program.
 */
export interface BaselineFileMention {
  line: number;
  commented: boolean;
  effective: boolean;
}

/** The configuration file behind one check, as it stands on the target. */
export interface BaselineFile {
  itemHandle: string;
  /** The file this check reads. A label; the window cannot act on it. */
  path: string;
  key: string;
  exists: boolean;
  text: string;
  lineCount: number;
  mentions: BaselineFileMention[];
  truncated: boolean;
}

export interface BaselineReadApi {
  getBaselineCatalog(): Promise<unknown>;
  scanBaseline(bindingHandle: string): Promise<unknown>;
  listBaselineHistory(bindingHandle: string): Promise<unknown>;
  readBaselineFile(bindingHandle: string, itemHandle: string): Promise<unknown>;
}

type JsonRecord = Record<string, unknown>;
const encoder = new TextEncoder();
const redactedText = "[SENSITIVE BASELINE TEXT REDACTED]";
const missingText = "未设置";
const unsupportedText = "不支持（符号链接或特殊文件）";
const categories = new Set<BaselineCategory>([
  "ssh", "password", "kernel", "network", "authentication", "logging", "file-permissions",
]);
const risks = new Set<BaselineRisk>(["critical", "high", "medium", "low"]);
const observedKinds = new Set<BaselineObservedKind>(["missing", "unsupported", "value"]);
const historyStates = new Set<BaselineHistoryState>(["applied", "restored"]);

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

function safeInteger(value: unknown, minimum: number, maximum: number): value is number {
  return unsigned(value, maximum) && value >= minimum;
}

/**
 * Bounded, control-character-free text. It does not judge the content: a
 * collected line that mentions a credential is the evidence, and refusing it
 * here would reject the whole response rather than one line.
 */
function publicText(value: unknown, maximumBytes: number, allowEmpty = true): value is string {
  return text(value, maximumBytes, allowEmpty) &&
    !/[\u0000-\u001f\u007f]/u.test(value);
}

function timestamp(value: unknown): value is string {
  return publicText(value, 64, false) && /^\d{4}-\d{2}-\d{2}T/u.test(value) &&
    Number.isFinite(Date.parse(value));
}

function withinTextBudget(values: Iterable<string>, maximumBytes: number): boolean {
  let total = 0;
  for (const value of values) {
    total += encoder.encode(value).byteLength;
    if (total > maximumBytes) return false;
  }
  return true;
}

function withinSerializedBudget(value: unknown, maximumBytes: number): boolean {
  try {
    const encoded = JSON.stringify(value);
    return typeof encoded === "string" && encoder.encode(encoded).byteLength <= maximumBytes;
  } catch {
    return false;
  }
}

export function isBaselineOpaqueHandle(value: unknown): value is string {
  return text(value, 128, false) && /^[A-Za-z0-9_-]+$/u.test(value);
}

function valueKind(value: unknown, recommendation: string): value is BaselineValueKind {
  if (!record(value) || typeof value.kind !== "string") return false;
  if (value.kind === "choice") {
    if (!exact(value, ["kind", "options"]) || !Array.isArray(value.options) ||
      value.options.length === 0 || value.options.length > 16 ||
      !value.options.every((option) => publicText(option, 128, false))) return false;
    const options = value.options as string[];
    return new Set(options).size === options.length && options.includes(recommendation);
  }
  if (value.kind === "integer") {
    if (!exact(value, ["kind", "minimum", "maximum"]) ||
      !unsigned(value.minimum, 0xffff_ffff) || !unsigned(value.maximum, 0xffff_ffff) ||
      value.minimum > value.maximum || !/^\d+$/u.test(recommendation)) return false;
    const numeric = Number(recommendation);
    return Number.isSafeInteger(numeric) && numeric >= value.minimum && numeric <= value.maximum;
  }
  return false;
}

function catalogItem(value: unknown): value is BaselineCatalogItem {
  if (!record(value) || !exact(value, [
    "itemHandle", "category", "risk", "valueKind", "title", "description", "recommendation",
  ]) || !isBaselineOpaqueHandle(value.itemHandle) || typeof value.category !== "string" ||
    !categories.has(value.category as BaselineCategory) || typeof value.risk !== "string" ||
    !risks.has(value.risk as BaselineRisk) || !publicText(value.title, 256, false) ||
    !publicText(value.description, 2 * 1_024, false) ||
    !publicText(value.recommendation, 128, false)) return false;
  return valueKind(value.valueKind, value.recommendation);
}

export function isBaselineCatalog(value: unknown): value is BaselineCatalog {
  if (!record(value) || !exact(value, ["items", "displayed", "truncated"]) ||
    !Array.isArray(value.items) || value.items.length > 64 || !value.items.every(catalogItem) ||
    !unsigned(value.displayed, 64) || value.displayed !== value.items.length ||
    typeof value.truncated !== "boolean") return false;
  const items = value.items as BaselineCatalogItem[];
  return new Set(items.map((item) => item.itemHandle)).size === items.length &&
    withinTextBudget(items.flatMap((item) => [
      item.title,
      item.description,
      item.recommendation,
      ...(item.valueKind.kind === "choice" ? item.valueKind.options : []),
    ]), 128 * 1_024) && withinSerializedBudget(value, 256 * 1_024);
}

function status(value: unknown): value is BaselineStatus {
  if (!record(value) || !exact(value, [
    "itemHandle", "observedKind", "observed", "compliant", "redacted", "textTruncated",
  ]) || !isBaselineOpaqueHandle(value.itemHandle) || typeof value.observedKind !== "string" ||
    !observedKinds.has(value.observedKind as BaselineObservedKind) ||
    typeof value.compliant !== "boolean" || typeof value.redacted !== "boolean" ||
    typeof value.textTruncated !== "boolean" || !text(value.observed, 512, false)) return false;
  if (value.redacted) return value.observedKind === "value" && value.observed === redactedText;
  if (/[\u0000-\u001f\u007f]/u.test(value.observed)) return false;
  if (value.observedKind === "missing") return value.observed === missingText;
  if (value.observedKind === "unsupported") return value.observed === unsupportedText;
  return true;
}

export function isBaselineScan(value: unknown): value is BaselineScan {
  if (!record(value) || !exact(value, [
    "scanHandle", "capturedAt", "expiresInSeconds", "statuses", "displayed", "compliantCount",
    "nonCompliantCount", "redactedFieldCount", "truncated",
  ]) || !isBaselineOpaqueHandle(value.scanHandle) || !timestamp(value.capturedAt) ||
    !safeInteger(value.expiresInSeconds, 1, 300) || !Array.isArray(value.statuses) ||
    value.statuses.length > 64 || !value.statuses.every(status) || !unsigned(value.displayed, 64) ||
    value.displayed !== value.statuses.length || !unsigned(value.compliantCount, value.displayed) ||
    !unsigned(value.nonCompliantCount, value.displayed) ||
    value.compliantCount + value.nonCompliantCount !== value.displayed ||
    !unsigned(value.redactedFieldCount, value.displayed) || typeof value.truncated !== "boolean") return false;
  const statuses = value.statuses as BaselineStatus[];
  return new Set(statuses.map((item) => item.itemHandle)).size === statuses.length &&
    value.compliantCount === statuses.filter((item) => item.compliant).length &&
    value.redactedFieldCount === statuses.filter((item) => item.redacted).length &&
    (!statuses.some((item) => item.textTruncated) || value.truncated) &&
    withinTextBudget(statuses.map((item) => item.observed), 64 * 1_024) &&
    withinSerializedBudget(value, 256 * 1_024);
}

function historyEntry(value: unknown): value is BaselineHistoryEntry {
  if (!record(value) || !exact(value, [
    "historyItemHandle", "state", "summary", "changeCount", "createdAt", "updatedAt", "redacted",
    "textTruncated",
  ]) || !isBaselineOpaqueHandle(value.historyItemHandle) || typeof value.state !== "string" ||
    !historyStates.has(value.state as BaselineHistoryState) || !text(value.summary, 1_024, false) ||
    !safeInteger(value.changeCount, 1, 64) || !timestamp(value.createdAt) || !timestamp(value.updatedAt) ||
    Date.parse(value.updatedAt) < Date.parse(value.createdAt) || typeof value.redacted !== "boolean" ||
    typeof value.textTruncated !== "boolean") return false;
  return value.redacted
    ? value.summary === redactedText
    : !/[\u0000-\u001f\u007f]/u.test(value.summary);
}

export function isBaselineHistory(value: unknown): value is BaselineHistory {
  if (!record(value) || !exact(value, [
    "historyHandle", "expiresInSeconds", "entries", "displayed", "redactedFieldCount", "truncated",
  ]) || !isBaselineOpaqueHandle(value.historyHandle) || !safeInteger(value.expiresInSeconds, 1, 300) ||
    !Array.isArray(value.entries) || value.entries.length > 256 || !value.entries.every(historyEntry) ||
    !unsigned(value.displayed, 256) || value.displayed !== value.entries.length ||
    !unsigned(value.redactedFieldCount, value.displayed) || typeof value.truncated !== "boolean") return false;
  const entries = value.entries as BaselineHistoryEntry[];
  return new Set(entries.map((entry) => entry.historyItemHandle)).size === entries.length &&
    entries.every((entry, index) => index === 0 ||
      Date.parse(entries[index - 1]!.createdAt) >= Date.parse(entry.createdAt)) &&
    value.redactedFieldCount === entries.filter((entry) => entry.redacted).length &&
    (!entries.some((entry) => entry.textTruncated) || value.truncated) &&
    withinTextBudget(entries.map((entry) => entry.summary), 128 * 1_024) &&
    withinSerializedBudget(value, 512 * 1_024);
}

function fileMention(value: unknown, lineCount: number): value is BaselineFileMention {
  return record(value) && exact(value, ["line", "commented", "effective"]) &&
    unsigned(value.line, 3_999) && value.line < lineCount &&
    typeof value.commented === "boolean" && typeof value.effective === "boolean" &&
    // A commented line sets nothing, so it can never be the one in force.
    !(value.effective && value.commented);
}

/**
 * A configuration file the operator reads on screen.
 *
 * The text crosses as the target wrote it. Only newlines and tabs are allowed
 * among the control characters, because the rest break the rendering; nothing
 * is filtered on how the content looks.
 */
export function isBaselineFile(value: unknown): value is BaselineFile {
  if (!record(value) || !exact(value, [
    "itemHandle", "path", "key", "exists", "text", "lineCount", "mentions", "truncated",
  ]) || !isBaselineOpaqueHandle(value.itemHandle) ||
    typeof value.path !== "string" || !value.path.startsWith("/") || value.path.length > 256 ||
    typeof value.key !== "string" || value.key.length === 0 || value.key.length > 128 ||
    typeof value.exists !== "boolean" || typeof value.text !== "string" ||
    encoder.encode(value.text).byteLength > 256 * 1_024 ||
    /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value.text) ||
    /[\u0000-\u001f\u007f]/u.test(value.path) || /[\u0000-\u001f\u007f]/u.test(value.key) ||
    !unsigned(value.lineCount, 4_000) || !Array.isArray(value.mentions) ||
    value.mentions.length > 256 || typeof value.truncated !== "boolean") return false;
  const lines = value.text.length === 0 ? 0 : value.text.split("\n").length;
  if (lines !== value.lineCount) return false;
  // A file that is not there has nothing to show and nothing to mark.
  if (!value.exists && (value.text.length > 0 || value.mentions.length > 0)) return false;
  const lineCount = value.lineCount;
  const mentions = value.mentions as unknown[];
  if (!mentions.every((mention) => fileMention(mention, lineCount))) return false;
  const typed = mentions as BaselineFileMention[];
  return typed.every((mention, index) => index === 0 || mention.line > typed[index - 1]!.line) &&
    typed.filter((mention) => mention.effective).length <= 1 &&
    withinSerializedBudget(value, 384 * 1_024);
}
