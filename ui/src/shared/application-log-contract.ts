export type ApplicationLogLevel = "debug" | "info" | "warn" | "error";

export interface ApplicationLogFilter {
  minimumLevel: ApplicationLogLevel | null;
  search: string;
}

export interface ApplicationLogDetail {
  name: string;
  value: string;
}

export interface ApplicationLogEntry {
  sequence: number;
  timestampUnixMs: number;
  level: ApplicationLogLevel;
  module: string;
  message: string;
  details: ApplicationLogDetail[];
}

export interface ApplicationLogSnapshot {
  capacity: 500;
  totalBuffered: number;
  totalMatched: number;
  displayed: number;
  currentLevel: ApplicationLogLevel;
  generation: number;
  entries: ApplicationLogEntry[];
  /**
   * Whether entries also go to `data/logs/lovelyhawk.log`: being written, memory only
   * (no file was opened), or failed (writing stopped after an error).
   */
  logFile: ApplicationLogFileState;
}

export const applicationLogFileStates = ["writing", "memory-only", "failed"] as const;
export type ApplicationLogFileState = typeof applicationLogFileStates[number];

export interface ApplicationLogLevelResult {
  level: ApplicationLogLevel;
  persisted: false;
}

export interface ApplicationLogClearResult {
  clearedEntries: number;
  volatileOnly: true;
  persistedFilesAffected: false;
  generation: number;
}

export interface ApplicationLogPreview {
  content: string;
  entryCount: number;
  truncated: boolean;
}

export interface ApplicationLogExportResult {
  saved: boolean;
  fileName: string | null;
  entryCount: number;
  truncated: boolean;
}

export interface ApplicationLogApi {
  listApplicationLogs(filter: ApplicationLogFilter): Promise<unknown>;
  setApplicationLogLevel(level: ApplicationLogLevel): Promise<unknown>;
  clearApplicationLogBuffer(): Promise<unknown>;
  getApplicationLogPreview(filter: ApplicationLogFilter): Promise<unknown>;
  exportApplicationLogs(filter: ApplicationLogFilter): Promise<unknown>;
}

type JsonRecord = Record<string, unknown>;
const encoder = new TextEncoder();
const REDACTED = "[REDACTED]";
const SINGLE_LINE_CONTROL = /[\u0000-\u001f\u007f-\u009f]/u;
const MULTILINE_CONTROL = /[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/u;
const CREDENTIAL_MARKERS = [
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
] as const;
const SENSITIVE_FIELD_MARKERS = [
  "password", "passwd", "passphrase", "secret", "token", "authorization", "api_key",
  "apikey", "private_key", "credential", "cookie", "session_id", "archive_root", "data_root",
  "local_path",
] as const;

function record(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exact(value: JsonRecord, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && actual.every((key) => keys.includes(key));
}

function utf8(value: unknown, maximumBytes: number, allowEmpty = false): value is string {
  return typeof value === "string" && (allowEmpty || value.length > 0) &&
    encoder.encode(value).byteLength <= maximumBytes;
}

function singleLine(value: unknown, maximumBytes: number, allowEmpty = false): value is string {
  return utf8(value, maximumBytes, allowEmpty) && !SINGLE_LINE_CONTROL.test(value);
}

function containsUriUserinfo(value: string): boolean {
  let remaining = value;
  while (true) {
    const marker = remaining.indexOf("://");
    if (marker < 0) return false;
    remaining = remaining.slice(marker + 3);
    const authority = remaining.split(/[/?#\s]/u, 1)[0] ?? "";
    if (authority.includes("@")) return true;
  }
}

function publicSingleLine(
  value: unknown,
  maximumBytes: number,
  allowEmpty = false,
): value is string {
  return singleLine(value, maximumBytes, allowEmpty);
}

export function isApplicationLogPublicMultiline(
  value: unknown,
  maximumBytes: number,
  allowEmpty = false,
): value is string {
  return utf8(value, maximumBytes, allowEmpty) && !MULTILINE_CONTROL.test(value);
}

function isSensitiveFieldName(value: string): boolean {
  const normalized = value.toLowerCase();
  return SENSITIVE_FIELD_MARKERS.some((marker) => normalized.includes(marker));
}

function unsigned(value: unknown, maximum: number): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= maximum;
}

export function isApplicationLogLevel(value: unknown): value is ApplicationLogLevel {
  return value === "debug" || value === "info" || value === "warn" || value === "error";
}

export function isApplicationLogFilter(value: unknown): value is ApplicationLogFilter {
  return record(value) && exact(value, ["minimumLevel", "search"]) &&
    (value.minimumLevel === null || isApplicationLogLevel(value.minimumLevel)) &&
    singleLine(value.search, 256, true);
}

export function isApplicationLogDetail(value: unknown): value is ApplicationLogDetail {
  if (!record(value) || !exact(value, ["name", "value"]) ||
    !singleLine(value.name, 64) || !publicSingleLine(value.value, 4 * 1_024, true)) {
    return false;
  }
  return !isSensitiveFieldName(value.name) || value.value === REDACTED;
}

export function isApplicationLogEntry(value: unknown): value is ApplicationLogEntry {
  if (!record(value) || !exact(value, [
    "sequence", "timestampUnixMs", "level", "module", "message", "details",
  ]) || !unsigned(value.sequence, Number.MAX_SAFE_INTEGER) || value.sequence === 0 ||
    !unsigned(value.timestampUnixMs, Number.MAX_SAFE_INTEGER) ||
    !isApplicationLogLevel(value.level) || !publicSingleLine(value.module, 256) ||
    !publicSingleLine(value.message, 4 * 1_024) || !Array.isArray(value.details) ||
    value.details.length > 32 || !value.details.every(isApplicationLogDetail)) {
    return false;
  }
  const detailBytes = value.details.reduce(
    (total, detail) => total + encoder.encode(detail.name).byteLength + encoder.encode(detail.value).byteLength,
    0,
  );
  return detailBytes <= 16 * 1_024;
}

export function isApplicationLogSnapshot(value: unknown): value is ApplicationLogSnapshot {
  if (!record(value) || !exact(value, [
    "capacity", "totalBuffered", "totalMatched", "displayed", "currentLevel", "generation", "entries", "logFile",
  ]) || !(applicationLogFileStates as readonly unknown[]).includes(value.logFile) ||
    value.capacity !== 500 || !unsigned(value.totalBuffered, 500) ||
    !unsigned(value.totalMatched, 500) || !unsigned(value.displayed, 100) ||
    !isApplicationLogLevel(value.currentLevel) ||
    !unsigned(value.generation, Number.MAX_SAFE_INTEGER) || !Array.isArray(value.entries) ||
    value.entries.length > 100 || !value.entries.every(isApplicationLogEntry)) {
    return false;
  }
  return value.totalMatched <= value.totalBuffered && value.displayed === value.entries.length &&
    value.displayed <= value.totalMatched && value.entries.every((entry, index, entries) =>
      index === 0 || entry.sequence < entries[index - 1]!.sequence);
}

export function isApplicationLogLevelResult(value: unknown): value is ApplicationLogLevelResult {
  return record(value) && exact(value, ["level", "persisted"]) &&
    isApplicationLogLevel(value.level) && value.persisted === false;
}

export function isApplicationLogClearResult(value: unknown): value is ApplicationLogClearResult {
  return record(value) && exact(value, [
    "clearedEntries", "volatileOnly", "persistedFilesAffected", "generation",
  ]) && unsigned(value.clearedEntries, 500) && value.volatileOnly === true &&
    value.persistedFilesAffected === false && unsigned(value.generation, Number.MAX_SAFE_INTEGER);
}

export function isApplicationLogPreview(value: unknown): value is ApplicationLogPreview {
  return record(value) && exact(value, ["content", "entryCount", "truncated"]) &&
    isApplicationLogPublicMultiline(value.content, 128 * 1_024, true) &&
    unsigned(value.entryCount, 500) &&
    typeof value.truncated === "boolean";
}

export function isApplicationLogExportResult(value: unknown): value is ApplicationLogExportResult {
  if (!record(value) || !exact(value, ["saved", "fileName", "entryCount", "truncated"]) ||
    typeof value.saved !== "boolean" || !unsigned(value.entryCount, 500) ||
    typeof value.truncated !== "boolean") {
    return false;
  }
  if (!value.saved) return value.fileName === null && value.entryCount === 0;
  return utf8(value.fileName, 240) && !/[\u0000-\u001f\u007f-\u009f<>:"/\\|?*]/u.test(value.fileName) &&
    value.fileName.endsWith(".log") && value.fileName !== ".log";
}
