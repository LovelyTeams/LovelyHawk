export type DisposalReportPreviewFormat = "summary" | "markdown" | "html";
export type DisposalReportExportFormat = "markdown" | "html";

export interface DisposalReportSourceCount {
  source: string;
  count: number;
}

export interface DisposalReportSummary {
  total: number;
  succeeded: number;
  failed: number;
  restored: number;
  uncertain: number;
  recoverable: number;
  bySource: DisposalReportSourceCount[];
}

export interface DisposalReportSnapshot {
  handle: string;
  generatedAt: string;
  snapshotSha256: string;
  detectionIncluded: false;
  incidentIncluded: boolean;
  evidenceCount: number;
  empty: boolean;
  summary: DisposalReportSummary;
}

export interface DisposalReportContent {
  format: DisposalReportPreviewFormat;
  content: string;
}

export interface DisposalReportExportResult {
  saved: boolean;
  fileName: string | null;
  operationCount: number;
}

export interface DisposalReportApi {
  generateDisposalReport(bindingHandle: string): Promise<DisposalReportSnapshot>;
  getDisposalReportContent(
    bindingHandle: string,
    reportHandle: string,
    format: DisposalReportPreviewFormat,
  ): Promise<DisposalReportContent>;
  exportDisposalReport(
    bindingHandle: string,
    reportHandle: string,
    format: DisposalReportExportFormat,
  ): Promise<DisposalReportExportResult>;
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

function unsigned(value: unknown, maximum: number): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= maximum;
}

export function isDisposalReportOpaqueHandle(value: unknown): value is string {
  return utf8(value, 128) && /^[A-Za-z0-9-]+$/u.test(value);
}

export function isDisposalReportPreviewFormat(value: unknown): value is DisposalReportPreviewFormat {
  return value === "summary" || value === "markdown" || value === "html";
}

export function isDisposalReportExportFormat(value: unknown): value is DisposalReportExportFormat {
  return value === "markdown" || value === "html";
}

function isSourceCount(value: unknown): value is DisposalReportSourceCount {
  return record(value) && exact(value, ["source", "count"]) &&
    utf8(value.source, 64) && /^[A-Za-z0-9_-]+$/u.test(value.source) &&
    unsigned(value.count, 2_000) && value.count > 0;
}

export function isDisposalReportSummary(value: unknown): value is DisposalReportSummary {
  if (!record(value) || !exact(value, [
    "total", "succeeded", "failed", "restored", "uncertain", "recoverable", "bySource",
  ]) ||
    !unsigned(value.total, 2_000) || !unsigned(value.succeeded, 2_000) ||
    !unsigned(value.failed, 2_000) || !unsigned(value.restored, 2_000) ||
    !unsigned(value.uncertain, 2_000) || !unsigned(value.recoverable, 2_000) ||
    !Array.isArray(value.bySource) || value.bySource.length > 2_000 ||
    !value.bySource.every(isSourceCount)) return false;
  const sources = value.bySource.map((item) => item.source);
  const statusTotal = value.succeeded + value.failed + value.restored + value.uncertain;
  const sourceTotal = value.bySource.reduce((total, item) => total + item.count, 0);
  return new Set(sources).size === sources.length && statusTotal === value.total &&
    sourceTotal === value.total && value.recoverable <= value.total;
}

export function isDisposalReportSnapshot(value: unknown): value is DisposalReportSnapshot {
  return record(value) && exact(value, [
    "handle", "generatedAt", "snapshotSha256", "detectionIncluded", "incidentIncluded", "evidenceCount", "empty", "summary",
  ]) &&
    isDisposalReportOpaqueHandle(value.handle) &&
    utf8(value.generatedAt, 64) && Number.isFinite(Date.parse(value.generatedAt)) &&
    typeof value.snapshotSha256 === "string" && /^[a-f0-9]{64}$/u.test(value.snapshotSha256) &&
    value.detectionIncluded === false && typeof value.empty === "boolean" &&
    typeof value.incidentIncluded === "boolean" && unsigned(value.evidenceCount, 500) &&
    (value.incidentIncluded || value.evidenceCount === 0) &&
    isDisposalReportSummary(value.summary) && value.empty === (value.summary.total === 0 && !value.incidentIncluded);
}

export function isDisposalReportContent(value: unknown): value is DisposalReportContent {
  if (!record(value) || !exact(value, ["format", "content"]) ||
    !isDisposalReportPreviewFormat(value.format)) return false;
  const maximum = value.format === "summary" ? 16 * 1_024 : 512 * 1_024;
  return utf8(value.content, maximum, true);
}

function safeFileName(value: unknown): value is string {
  return utf8(value, 240) && value !== "." && value !== ".." &&
    !/[\u0000-\u001f<>:"/\\|?*]/u.test(value) && !/[. ]$/u.test(value);
}

export function isDisposalReportExportResult(value: unknown): value is DisposalReportExportResult {
  if (!record(value) || !exact(value, ["saved", "fileName", "operationCount"]) ||
    typeof value.saved !== "boolean" || !unsigned(value.operationCount, 2_000)) return false;
  return value.saved ? safeFileName(value.fileName) : value.fileName === null;
}
