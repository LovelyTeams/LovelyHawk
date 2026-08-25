export interface AiHistorySummary {
  id: string;
  timestamp: number;
  provider: string;
  model: string;
  source: string;
  promptPreview: string;
  promptTruncated: boolean;
  resultPreview: string;
  resultTruncated: boolean;
}

export interface AiHistoryListPage {
  total: number;
  offset: number;
  hasMore: boolean;
  items: AiHistorySummary[];
}

export interface AiHistoryRecord {
  id: string;
  timestamp: number;
  provider: string;
  model: string;
  prompt: string;
  result: string;
  source: string;
}

export type AiHistoryMutationKind = "remove" | "clear";

export interface AiHistoryMutationProposal {
  handle: string;
  kind: AiHistoryMutationKind;
  affectedRecords: number;
  summary: string;
  expiresInSeconds: number;
}

export interface AiHistoryMutationResult {
  kind: AiHistoryMutationKind;
  affectedRecords: number;
  verified: true;
}

export interface AiHistoryMutationCancellation {
  cancelled: true;
}

export type AiHistoryExportFormat = "text" | "json";

export interface AiHistoryExportResult {
  saved: boolean;
  fileName: string | null;
  recordCount: number;
}

export interface AiHistoryApi {
  listAiHistory(query: string, offset: number, limit: number): Promise<unknown>;
  getAiHistoryRecord(id: string): Promise<unknown>;
  planAiHistoryRemove(id: string): Promise<unknown>;
  planAiHistoryClear(): Promise<unknown>;
  confirmAiHistoryMutation(handle: string): Promise<unknown>;
  cancelAiHistoryMutation(handle: string): Promise<unknown>;
  exportAiHistory(format: AiHistoryExportFormat): Promise<unknown>;
}

type JsonRecord = Record<string, unknown>;
const encoder = new TextEncoder();

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exact(value: JsonRecord, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && actual.every((key) => keys.includes(key));
}

function utf8(value: unknown, maximumBytes: number, allowEmpty = false): value is string {
  return (
    typeof value === "string" &&
    (allowEmpty || value.length > 0) &&
    encoder.encode(value).byteLength <= maximumBytes
  );
}

function safeUnsigned(value: unknown, maximum = Number.MAX_SAFE_INTEGER): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= maximum;
}

export function isAiHistoryId(value: unknown): value is string {
  return utf8(value, 128) && !/[\u0000-\u001f\u007f-\u009f]/u.test(value);
}

export function isAiHistoryQuery(value: unknown): value is string {
  return utf8(value, 256, true);
}

export function isAiHistoryPageRequest(offset: unknown, limit: unknown): boolean {
  return safeUnsigned(offset, 500) && safeUnsigned(limit, 100) && limit !== 0;
}

export function isAiHistoryOpaqueHandle(value: unknown): value is string {
  return utf8(value, 128) && /^[A-Za-z0-9-]+$/u.test(value);
}

export function isAiHistoryExportFormat(value: unknown): value is AiHistoryExportFormat {
  return value === "text" || value === "json";
}

export function aiHistoryMutationSummary(
  kind: AiHistoryMutationKind,
  affectedRecords: number,
): string {
  return kind === "remove"
    ? "永久删除这条 AI 历史？此操作不可恢复。"
    : `永久清空计划中的 ${affectedRecords} 条 AI 历史？此操作不可恢复；确认后新增记录会保留。`;
}

function isSummary(value: unknown): value is AiHistorySummary {
  return (
    isRecord(value) &&
    exact(value, [
      "id", "timestamp", "provider", "model", "source", "promptPreview", "promptTruncated",
      "resultPreview", "resultTruncated",
    ]) &&
    isAiHistoryId(value.id) &&
    safeUnsigned(value.timestamp) &&
    utf8(value.provider, 512) &&
    utf8(value.model, 1_024) &&
    utf8(value.source, 1_024) &&
    utf8(value.promptPreview, 2_048, true) &&
    typeof value.promptTruncated === "boolean" &&
    utf8(value.resultPreview, 2_048, true) &&
    typeof value.resultTruncated === "boolean"
  );
}

export function isAiHistoryListPage(value: unknown): value is AiHistoryListPage {
  if (
    !isRecord(value) ||
    !exact(value, ["total", "offset", "hasMore", "items"]) ||
    !safeUnsigned(value.total, 500) ||
    !safeUnsigned(value.offset, 500) ||
    typeof value.hasMore !== "boolean" ||
    !Array.isArray(value.items) ||
    value.items.length > 100 ||
    !value.items.every(isSummary)
  ) return false;
  const ids = value.items.map((item) => item.id);
  return new Set(ids).size === ids.length && value.offset + value.items.length <= value.total;
}

export function isAiHistoryRecord(value: unknown): value is AiHistoryRecord {
  return (
    isRecord(value) &&
    exact(value, ["id", "timestamp", "provider", "model", "prompt", "result", "source"]) &&
    isAiHistoryId(value.id) &&
    safeUnsigned(value.timestamp) &&
    utf8(value.provider, 512) &&
    utf8(value.model, 1_024) &&
    utf8(value.prompt, 512 * 1_024) &&
    utf8(value.result, 4 * 1_024 * 1_024, true) &&
    utf8(value.source, 1_024)
  );
}

function isKind(value: unknown): value is AiHistoryMutationKind {
  return value === "remove" || value === "clear";
}

export function isAiHistoryMutationProposal(value: unknown): value is AiHistoryMutationProposal {
  if (
    isRecord(value) &&
    exact(value, ["handle", "kind", "affectedRecords", "summary", "expiresInSeconds"]) &&
    isAiHistoryOpaqueHandle(value.handle) &&
    isKind(value.kind) &&
    safeUnsigned(value.affectedRecords, 500) &&
    value.affectedRecords > 0 &&
    utf8(value.summary, 2_048) &&
    safeUnsigned(value.expiresInSeconds, 600) &&
    value.expiresInSeconds > 0
  ) {
    return (
      (value.kind !== "remove" || value.affectedRecords === 1) &&
      value.summary === aiHistoryMutationSummary(value.kind, value.affectedRecords)
    );
  }
  return false;
}

export function isAiHistoryMutationResult(value: unknown): value is AiHistoryMutationResult {
  return (
    isRecord(value) &&
    exact(value, ["kind", "affectedRecords", "verified"]) &&
    isKind(value.kind) &&
    safeUnsigned(value.affectedRecords, 500) &&
    value.verified === true
  );
}

export function isAiHistoryMutationCancellation(
  value: unknown,
): value is AiHistoryMutationCancellation {
  return isRecord(value) && exact(value, ["cancelled"]) && value.cancelled === true;
}

function safeFileName(value: unknown): value is string {
  return (
    utf8(value, 240) &&
    value !== "." &&
    value !== ".." &&
    !/[\u0000-\u001f<>:"/\\|?*]/u.test(value) &&
    !/[. ]$/u.test(value)
  );
}

export function isAiHistoryExportResult(value: unknown): value is AiHistoryExportResult {
  if (
    !isRecord(value) ||
    !exact(value, ["saved", "fileName", "recordCount"]) ||
    typeof value.saved !== "boolean" ||
    !safeUnsigned(value.recordCount, 500)
  ) return false;
  return value.saved ? safeFileName(value.fileName) : value.fileName === null;
}
