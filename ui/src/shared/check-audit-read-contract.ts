export const defaultCheckAuditCommands = [
  "cat", "head", "tail", "more", "less", "grep", "awk", "sed", "bash", "sh", "curl", "wget",
  "mysql", "redis-cli", "psql", "mongo", "find",
] as const;

export type CheckAuditCommandState =
  | "original" | "instrumented" | "missing" | "foreign-script" | "coreutils-shim" | "multi-call";
export type CheckAuditCycleCategory = "file-read" | "service-check" | "network" | "database" | "process";
export type CheckAuditSuggestionSeverity = "critical" | "warning" | "info";

export interface CheckAuditCatalogInput {
  customCommandNames: string[];
}

export interface CheckAuditCatalogCommand {
  commandHandle: string;
  name: string;
  isDefault: boolean;
  critical: boolean;
}

export interface CheckAuditCatalog {
  snapshotHandle: string;
  expiresInSeconds: number;
  commands: CheckAuditCatalogCommand[];
  customCount: number;
}

export interface CheckAuditCommandStatus {
  commandHandle: string;
  name: string;
  state: CheckAuditCommandState;
  critical: boolean;
  displayLocation: string | null;
  locationRedacted: boolean;
  textTruncated: boolean;
}

export interface CheckAuditStatus {
  snapshotHandle: string;
  isRoot: boolean;
  commands: CheckAuditCommandStatus[];
  redactedFieldCount: number;
  truncated: boolean;
}

export interface CheckAuditLogInput {
  limit: number;
  search: string | null;
}

export interface CheckAuditLogEntry {
  timestamp: string;
  command: string;
  args: string;
  user: string;
  pid: number;
  ppid: number;
  caller: string;
  suspicious: boolean;
  /** Not an audit record: `args` is the line as written, the other text fields are empty. */
  malformed: boolean;
  redacted: boolean;
  textTruncated: boolean;
}

/**
 * What was found where the command audit log belongs. Only "read" means the
 * counts describe a log; the others say why nothing was read.
 */
export type CheckAuditLogState = "read" | "absent" | "not-regular-file" | "unreadable";

export interface CheckAuditCommandCount {
  command: string;
  count: number;
  redacted: boolean;
  textTruncated: boolean;
}

export interface CheckAuditCycle {
  command: string;
  args: string;
  intervalSeconds: number | null;
  count: number;
  lastSeen: string;
  category: CheckAuditCycleCategory;
  redacted: boolean;
  textTruncated: boolean;
}

export interface CheckAuditSuggestion {
  severity: CheckAuditSuggestionSeverity;
  title: string;
  description: string;
  redacted: boolean;
  textTruncated: boolean;
}

export interface CheckAuditLogResult {
  snapshotHandle: string;
  limit: number;
  logState: CheckAuditLogState;
  fetchedCount: number;
  /** Lines in the read window that were not audit records. */
  malformedCount: number;
  matchedCount: number;
  displayedCount: number;
  suspiciousCount: number;
  matchedSuspiciousCount: number;
  entries: CheckAuditLogEntry[];
  commandCounts: CheckAuditCommandCount[];
  cycles: CheckAuditCycle[];
  suggestions: CheckAuditSuggestion[];
  redactedFieldCount: number;
  truncated: boolean;
}

export interface CheckAuditReadApi {
  getCheckAuditCatalog(bindingHandle: string, input: CheckAuditCatalogInput): Promise<unknown>;
  collectCheckAuditStatus(bindingHandle: string, snapshotHandle: string): Promise<unknown>;
  readCheckAuditLog(
    bindingHandle: string,
    snapshotHandle: string,
    input: CheckAuditLogInput,
  ): Promise<unknown>;
}

type JsonRecord = Record<string, unknown>;
const encoder = new TextEncoder();
const redactedText = "[SENSITIVE AUDIT TEXT REDACTED]";
const defaults = new Set<string>(defaultCheckAuditCommands);
const commandStates = new Set<CheckAuditCommandState>([
  "original", "instrumented", "missing", "foreign-script", "coreutils-shim", "multi-call",
]);
const cycleCategories = new Set<CheckAuditCycleCategory>([
  "file-read", "service-check", "network", "database", "process",
]);
const suggestionSeverities = new Set<CheckAuditSuggestionSeverity>(["critical", "warning", "info"]);

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
  return text(value, maximumBytes, allowEmpty);
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

function criticalName(name: string): boolean {
  return name === "cat" || name === "bash" || name === "sh";
}

export function isCheckAuditOpaqueHandle(value: unknown): value is string {
  return text(value, 128, false) && /^[A-Za-z0-9-]+$/u.test(value);
}

export function isCheckAuditCommandName(value: unknown): value is string {
  return text(value, 128, false) && /^[A-Za-z0-9][A-Za-z0-9._+-]*$/u.test(value);
}

export function isCheckAuditCatalogInput(value: unknown): value is CheckAuditCatalogInput {
  if (!record(value) || !exact(value, ["customCommandNames"]) ||
    !Array.isArray(value.customCommandNames) || value.customCommandNames.length > 15 ||
    !value.customCommandNames.every(isCheckAuditCommandName)) return false;
  const names = value.customCommandNames as string[];
  return new Set(names).size === names.length && names.every((name) => !defaults.has(name));
}

function catalogCommand(value: unknown): value is CheckAuditCatalogCommand {
  return record(value) && exact(value, ["commandHandle", "name", "isDefault", "critical"]) &&
    isCheckAuditOpaqueHandle(value.commandHandle) && isCheckAuditCommandName(value.name) &&
    typeof value.isDefault === "boolean" && typeof value.critical === "boolean" &&
    value.critical === criticalName(value.name);
}

export function isCheckAuditCatalog(value: unknown): value is CheckAuditCatalog {
  if (!record(value) || !exact(value, [
    "snapshotHandle", "expiresInSeconds", "commands", "customCount",
  ]) || !isCheckAuditOpaqueHandle(value.snapshotHandle) || !unsigned(value.expiresInSeconds, 300) ||
    value.expiresInSeconds === 0 || !Array.isArray(value.commands) ||
    value.commands.length < defaultCheckAuditCommands.length || value.commands.length > 32 ||
    !value.commands.every(catalogCommand) || !unsigned(value.customCount, 15) ||
    value.customCount !== value.commands.length - defaultCheckAuditCommands.length) return false;
  const commands = value.commands as CheckAuditCatalogCommand[];
  const handles = commands.map((command) => command.commandHandle);
  const names = commands.map((command) => command.name);
  const defaultsMatch = defaultCheckAuditCommands.every((name, index) =>
    commands[index]?.name === name && commands[index]?.isDefault === true);
  const custom = commands.slice(defaultCheckAuditCommands.length);
  return defaultsMatch && custom.every((command) => !command.isDefault && !defaults.has(command.name)) &&
    custom.every((command, index) => index === 0 || custom[index - 1]!.name < command.name) &&
    new Set(handles).size === handles.length && new Set(names).size === names.length &&
    withinSerializedBudget(value, 64 * 1_024);
}

function commandStatus(value: unknown): value is CheckAuditCommandStatus {
  if (!record(value) || !exact(value, [
    "commandHandle", "name", "state", "critical", "displayLocation", "locationRedacted", "textTruncated",
  ]) || !isCheckAuditOpaqueHandle(value.commandHandle) || !isCheckAuditCommandName(value.name) ||
    typeof value.state !== "string" || !commandStates.has(value.state as CheckAuditCommandState) ||
    typeof value.critical !== "boolean" || value.critical !== criticalName(value.name) ||
    !(value.displayLocation === null || publicText(value.displayLocation, 4 * 1_024)) ||
    typeof value.locationRedacted !== "boolean" || typeof value.textTruncated !== "boolean") return false;
  return !value.locationRedacted || value.displayLocation === redactedText;
}

export function isCheckAuditStatus(value: unknown): value is CheckAuditStatus {
  if (!record(value) || !exact(value, [
    "snapshotHandle", "isRoot", "commands", "redactedFieldCount", "truncated",
  ]) || !isCheckAuditOpaqueHandle(value.snapshotHandle) || typeof value.isRoot !== "boolean" ||
    !Array.isArray(value.commands) || value.commands.length === 0 || value.commands.length > 32 ||
    !value.commands.every(commandStatus) || !unsigned(value.redactedFieldCount, 32) ||
    typeof value.truncated !== "boolean") return false;
  const commands = value.commands as CheckAuditCommandStatus[];
  return new Set(commands.map((command) => command.commandHandle)).size === commands.length &&
    new Set(commands.map((command) => command.name)).size === commands.length &&
    value.redactedFieldCount === commands.filter((command) => command.locationRedacted).length &&
    (!commands.some((command) => command.textTruncated) || value.truncated) &&
    withinTextBudget(commands.flatMap((command) => [command.name, command.displayLocation ?? ""]), 256 * 1_024) &&
    withinSerializedBudget(value, 512 * 1_024);
}

export function isCheckAuditLogInput(value: unknown): value is CheckAuditLogInput {
  return record(value) && exact(value, ["limit", "search"]) && unsigned(value.limit, 200) && value.limit > 0 &&
    (value.search === null || publicText(value.search, 256, false) && value.search === value.search.trim() &&
      !/[\u0000-\u001f\u007f]/u.test(value.search));
}

function logEntry(value: unknown): value is CheckAuditLogEntry {
  return record(value) && exact(value, [
    "timestamp", "command", "args", "user", "pid", "ppid", "caller", "suspicious", "malformed", "redacted",
    "textTruncated",
  ]) && publicText(value.timestamp, 64) && publicText(value.command, 128) &&
    publicText(value.args, 2 * 1_024) && publicText(value.user, 128) && unsigned(value.pid, 0xffff_ffff) &&
    unsigned(value.ppid, 0xffff_ffff) && publicText(value.caller, 256) &&
    typeof value.suspicious === "boolean" && typeof value.malformed === "boolean" &&
    typeof value.redacted === "boolean" && typeof value.textTruncated === "boolean" &&
    // A line that is no record carries only itself.
    (!value.malformed || (value.command === "" && value.user === "" && value.caller === "" &&
      value.timestamp === "" && value.pid === 0 && value.ppid === 0));
}

const logStates: ReadonlySet<string> = new Set<CheckAuditLogState>(["read", "absent", "not-regular-file", "unreadable"]);

function commandCount(value: unknown, maximum: number): value is CheckAuditCommandCount {
  return record(value) && exact(value, ["command", "count", "redacted", "textTruncated"]) &&
    publicText(value.command, 128) && unsigned(value.count, maximum) && value.count > 0 &&
    typeof value.redacted === "boolean" && typeof value.textTruncated === "boolean";
}

function cycle(value: unknown, maximum: number): value is CheckAuditCycle {
  return record(value) && exact(value, [
    "command", "args", "intervalSeconds", "count", "lastSeen", "category", "redacted", "textTruncated",
  ]) && publicText(value.command, 128) && publicText(value.args, 2 * 1_024) &&
    (value.intervalSeconds === null || unsigned(value.intervalSeconds, Number.MAX_SAFE_INTEGER)) &&
    unsigned(value.count, maximum) && value.count >= 2 && publicText(value.lastSeen, 64) &&
    typeof value.category === "string" && cycleCategories.has(value.category as CheckAuditCycleCategory) &&
    typeof value.redacted === "boolean" && typeof value.textTruncated === "boolean";
}

function suggestion(value: unknown): value is CheckAuditSuggestion {
  return record(value) && exact(value, ["severity", "title", "description", "redacted", "textTruncated"]) &&
    typeof value.severity === "string" &&
    suggestionSeverities.has(value.severity as CheckAuditSuggestionSeverity) &&
    publicText(value.title, 256) && publicText(value.description, 512) &&
    typeof value.redacted === "boolean" && typeof value.textTruncated === "boolean";
}

export function isCheckAuditLogResult(value: unknown): value is CheckAuditLogResult {
  if (!record(value) || !exact(value, [
    "snapshotHandle", "limit", "logState", "fetchedCount", "malformedCount", "matchedCount", "displayedCount",
    "suspiciousCount", "matchedSuspiciousCount", "entries", "commandCounts", "cycles", "suggestions",
    "redactedFieldCount", "truncated",
  ]) || !isCheckAuditOpaqueHandle(value.snapshotHandle) || !unsigned(value.limit, 200) || value.limit === 0 ||
    typeof value.logState !== "string" || !logStates.has(value.logState) ||
    !unsigned(value.fetchedCount, value.limit) || !unsigned(value.malformedCount, value.fetchedCount) ||
    // Nothing read means nothing counted.
    (value.logState !== "read" && value.fetchedCount !== 0) ||
    !unsigned(value.matchedCount, value.fetchedCount) ||
    !unsigned(value.displayedCount, value.matchedCount) || !unsigned(value.suspiciousCount, value.fetchedCount) ||
    !unsigned(value.matchedSuspiciousCount, value.matchedCount) || !Array.isArray(value.entries) ||
    value.entries.length > 200 || !value.entries.every(logEntry) || value.entries.length !== value.displayedCount ||
    !Array.isArray(value.commandCounts) || value.commandCounts.length > 8 ||
    !value.commandCounts.every((item) => commandCount(item, value.fetchedCount as number)) ||
    !Array.isArray(value.cycles) || value.cycles.length > 100 ||
    !value.cycles.every((item) => cycle(item, value.fetchedCount as number)) ||
    !Array.isArray(value.suggestions) || value.suggestions.length > 64 ||
    !value.suggestions.every(suggestion) || value.suggestions.length > value.cycles.length ||
    !unsigned(value.redactedFieldCount, 2_000) || typeof value.truncated !== "boolean") return false;
  const entries = value.entries as CheckAuditLogEntry[];
  const counts = value.commandCounts as CheckAuditCommandCount[];
  const cycles = value.cycles as CheckAuditCycle[];
  const suggestions = value.suggestions as CheckAuditSuggestion[];
  let remainingCycleCount = value.fetchedCount;
  for (const item of cycles) {
    if (item.count > remainingCycleCount) return false;
    remainingCycleCount -= item.count;
  }
  const visibleRedacted = entries.filter((entry) => entry.redacted).length +
    counts.filter((count) => count.redacted).length + cycles.filter((item) => item.redacted).length +
    suggestions.filter((item) => item.redacted).length;
  const anyTextTruncated = [...entries, ...counts, ...cycles, ...suggestions]
    .some((item) => item.textTruncated);
  const visibleSuspicious = entries.filter((entry) => entry.suspicious).length;
  const visibleMalformed = entries.filter((entry) => entry.malformed).length;
  return new Set(counts.map((count) => count.command)).size === counts.length &&
    visibleMalformed <= value.malformedCount &&
    // Lines that are no record are never counted as commands.
    counts.reduce((total, count) => total + count.count, 0) + value.malformedCount <= value.fetchedCount &&
    counts.reduce((total, count) => total + count.count, 0) <= value.fetchedCount &&
    value.matchedSuspiciousCount <= value.suspiciousCount &&
    visibleSuspicious <= value.matchedSuspiciousCount &&
    (value.displayedCount !== value.matchedCount || value.truncated ||
      visibleSuspicious === value.matchedSuspiciousCount) &&
    value.redactedFieldCount >= visibleRedacted &&
    (!(value.displayedCount < value.matchedCount || anyTextTruncated) || value.truncated) &&
    withinTextBudget(entries.flatMap((entry) => [
      entry.timestamp, entry.command, entry.args, entry.user, entry.caller,
    ]).concat(counts.map((count) => count.command)), 512 * 1_024) &&
    withinTextBudget(cycles.flatMap((item) => [item.command, item.args, item.lastSeen])
      .concat(suggestions.flatMap((item) => [item.title, item.description])), 256 * 1_024) &&
    withinSerializedBudget(value, 1_024 * 1_024);
}
