export type CommandRisk = "read-only" | "mutating";
export type CommandStatus = "succeeded" | "failed" | "unknown";
/** Where a record came from: a catalog run keeps no command, only a result summary. */
export type CommandHistoryOrigin = "emergency-catalog" | "recorded-command";

export interface CommandHistorySummary {
  id: string;
  title: string;
  commandPreview: string;
  commandTruncated: boolean;
  outputPreview: string;
  outputTruncated: boolean;
  timestamp: number;
  exitCode: number | null;
  status: CommandStatus;
  risk: CommandRisk;
  origin: CommandHistoryOrigin;
  source: string;
}

export interface CommandHistoryListPage {
  total: number;
  offset: number;
  hasMore: boolean;
  items: CommandHistorySummary[];
}

export interface CommandHistoryRecord {
  id: string;
  title: string;
  command: string;
  output: string;
  timestamp: number;
  exitCode: number | null;
  status: CommandStatus;
  risk: CommandRisk;
  origin: CommandHistoryOrigin;
  source: string;
  /** A catalog check that kept which check it was, so the workbench can find it again. */
  rerunnable: boolean;
}

export type CommandReplayBlockReason =
  | "not-found"
  | "target-mismatch"
  | "digest-mismatch"
  | "risk-changed"
  | "mutating-command";

export type CommandReplayIntent =
  | { status: "blocked"; reason: CommandReplayBlockReason }
  | {
      status: "ready";
      historyId: string;
      risk: "read-only";
      executionAvailable: false;
    };

export type CommandHistoryMutationKind = "remove" | "clear";

export interface CommandHistoryMutationProposal {
  handle: string;
  kind: CommandHistoryMutationKind;
  affectedRecords: number;
  summary: string;
  expiresInSeconds: number;
}

export interface CommandHistoryMutationResult {
  kind: CommandHistoryMutationKind;
  affectedRecords: number;
  verified: true;
}

export interface CommandHistoryMutationCancellation {
  cancelled: true;
}

export interface CommandHistoryApi {
  listCommandHistory(
    bindingHandle: string,
    query: string,
    offset: number,
    limit: number,
  ): Promise<CommandHistoryListPage>;
  getCommandHistory(bindingHandle: string, recordId: string): Promise<CommandHistoryRecord>;
  planCommandReplay(bindingHandle: string, recordId: string): Promise<CommandReplayIntent>;
  planCommandHistoryRemove(bindingHandle: string, recordId: string): Promise<CommandHistoryMutationProposal>;
  planCommandHistoryClear(bindingHandle: string): Promise<CommandHistoryMutationProposal>;
  confirmCommandHistoryMutation(bindingHandle: string, mutationHandle: string): Promise<CommandHistoryMutationResult>;
  cancelCommandHistoryMutation(bindingHandle: string, mutationHandle: string): Promise<CommandHistoryMutationCancellation>;
}

type JsonRecord = Record<string, unknown>;
const encoder = new TextEncoder();

function record(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exact(value: JsonRecord, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && actual.every((key) => keys.includes(key));
}

function utf8(value: unknown, maximumBytes: number, allowEmpty = false): value is string {
  return typeof value === "string" &&
    (allowEmpty || value.length > 0) &&
    encoder.encode(value).byteLength <= maximumBytes;
}

function unsigned(value: unknown, maximum = Number.MAX_SAFE_INTEGER): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= maximum;
}

function exitCode(value: unknown): value is number | null {
  return value === null ||
    (typeof value === "number" && Number.isInteger(value) && value >= -2_147_483_648 && value <= 2_147_483_647);
}

function risk(value: unknown): value is CommandRisk {
  return value === "read-only" || value === "mutating";
}

function origin(value: unknown): value is CommandHistoryOrigin {
  return value === "emergency-catalog" || value === "recorded-command";
}

function status(value: unknown): value is CommandStatus {
  return value === "succeeded" || value === "failed" || value === "unknown";
}

function statusMatchesExitCode(value: CommandStatus, code: number | null): boolean {
  return code === null ? value === "unknown" : code === 0 ? value === "succeeded" : value === "failed";
}

export function isCommandHistoryOpaqueHandle(value: unknown): value is string {
  return utf8(value, 128) && /^[A-Za-z0-9-]+$/u.test(value);
}

export function isCommandHistoryId(value: unknown): value is string {
  return utf8(value, 128) && !/[\u0000-\u001f\u007f-\u009f]/u.test(value);
}

export function isCommandHistoryQuery(value: unknown): value is string {
  return utf8(value, 1_024, true) && [...value].length <= 256;
}

export function isCommandHistoryPageRequest(offset: unknown, limit: unknown): boolean {
  return unsigned(offset, 100) && unsigned(limit, 50) && limit !== 0;
}

function isSummary(value: unknown): value is CommandHistorySummary {
  if (!record(value) || !exact(value, [
    "id", "title", "commandPreview", "commandTruncated", "outputPreview", "outputTruncated",
    "timestamp", "exitCode", "status", "risk", "origin", "source",
  ])) return false;
  return isCommandHistoryId(value.id) &&
    utf8(value.title, 1_024) &&
    utf8(value.commandPreview, 2_048) &&
    typeof value.commandTruncated === "boolean" &&
    utf8(value.outputPreview, 2_048, true) &&
    typeof value.outputTruncated === "boolean" &&
    unsigned(value.timestamp) &&
    exitCode(value.exitCode) &&
    status(value.status) &&
    statusMatchesExitCode(value.status, value.exitCode) &&
    risk(value.risk) &&
    origin(value.origin) &&
    utf8(value.source, 1_024);
}

export function isCommandHistoryListPage(value: unknown): value is CommandHistoryListPage {
  if (!record(value) || !exact(value, ["total", "offset", "hasMore", "items"]) ||
    !unsigned(value.total, 100) || !unsigned(value.offset, 100) ||
    typeof value.hasMore !== "boolean" || !Array.isArray(value.items) ||
    value.items.length > 50 || !value.items.every(isSummary)) return false;
  const ids = value.items.map((item) => item.id);
  return new Set(ids).size === ids.length && value.offset + value.items.length <= value.total;
}

export function isCommandHistoryRecord(value: unknown): value is CommandHistoryRecord {
  if (!record(value) || !exact(value, [
    "id", "title", "command", "output", "timestamp", "exitCode", "status", "risk", "origin", "source", "rerunnable",
  ])) return false;
  return isCommandHistoryId(value.id) &&
    utf8(value.title, 1_024) &&
    utf8(value.command, 256 * 1_024) &&
    utf8(value.output, 256 * 1_024, true) &&
    unsigned(value.timestamp) &&
    exitCode(value.exitCode) &&
    status(value.status) &&
    statusMatchesExitCode(value.status, value.exitCode) &&
    risk(value.risk) &&
    origin(value.origin) &&
    utf8(value.source, 1_024) &&
    typeof value.rerunnable === "boolean" &&
    // Only a catalog check can be found again in the catalog.
    (!value.rerunnable || value.origin === "emergency-catalog");
}

const replayReasons = new Set<CommandReplayBlockReason>([
  "not-found", "target-mismatch", "digest-mismatch", "risk-changed", "mutating-command",
]);

export function isCommandReplayIntent(value: unknown): value is CommandReplayIntent {
  if (!record(value) || typeof value.status !== "string") return false;
  if (value.status === "blocked") {
    return exact(value, ["status", "reason"]) && replayReasons.has(value.reason as CommandReplayBlockReason);
  }
  return value.status === "ready" &&
    exact(value, ["status", "historyId", "risk", "executionAvailable"]) &&
    isCommandHistoryId(value.historyId) &&
    value.risk === "read-only" &&
    value.executionAvailable === false;
}

function mutationKind(value: unknown): value is CommandHistoryMutationKind {
  return value === "remove" || value === "clear";
}

export function commandHistoryMutationSummary(
  kind: CommandHistoryMutationKind,
  affectedRecords: number,
): string {
  return kind === "remove"
    ? "这条记录会被永久删除，无法恢复。"
    : `这台主机上的 ${affectedRecords} 条命令历史会被永久删除，无法恢复；确认之后新产生的记录会保留。`;
}

export function isCommandHistoryMutationProposal(
  value: unknown,
): value is CommandHistoryMutationProposal {
  if (!record(value) ||
    !exact(value, ["handle", "kind", "affectedRecords", "summary", "expiresInSeconds"]) ||
    !isCommandHistoryOpaqueHandle(value.handle) ||
    !mutationKind(value.kind) ||
    !unsigned(value.affectedRecords, 100) || value.affectedRecords === 0 ||
    !utf8(value.summary, 2_048) ||
    !unsigned(value.expiresInSeconds, 600) || value.expiresInSeconds === 0) return false;
  return (value.kind !== "remove" || value.affectedRecords === 1) &&
    value.summary === commandHistoryMutationSummary(value.kind, value.affectedRecords);
}

export function isCommandHistoryMutationResult(
  value: unknown,
): value is CommandHistoryMutationResult {
  return record(value) &&
    exact(value, ["kind", "affectedRecords", "verified"]) &&
    mutationKind(value.kind) &&
    unsigned(value.affectedRecords, 100) &&
    value.verified === true;
}

export function isCommandHistoryMutationCancellation(
  value: unknown,
): value is CommandHistoryMutationCancellation {
  return record(value) && exact(value, ["cancelled"]) && value.cancelled === true;
}
