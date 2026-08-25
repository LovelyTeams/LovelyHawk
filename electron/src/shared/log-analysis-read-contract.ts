export type LogSourceKind = "file" | "journal";
export type LogThreatLevel = "none" | "low" | "medium" | "high" | "critical";

export interface LogSource {
  sourceHandle: string;
  kind: LogSourceKind;
  displayName: string;
  displayLocation: string;
  sizeBytes: number | null;
  modified: string;
}

export interface LogSourceSnapshot {
  snapshotHandle: string;
  expiresInSeconds: number;
  sources: LogSource[];
  partial: boolean;
  truncated: boolean;
}

export interface LogSourceReadInput {
  page: number;
  pageSize: number;
  keyword: string | null;
  date: string | null;
  journalUnit: string | null;
}

export interface LogCorrelationInput {
  sourceHandles: string[];
  lineLimit: number;
}

export interface LogIocSearchInput {
  sourceHandles: string[];
  indicators: string[];
}

export interface PublicLogEntry {
  timestamp: string;
  level: string;
  service: string;
  message: string;
  rawText: string;
  highlighted: boolean;
  sourceHandle: string | null;
  sourceName: string | null;
  redacted: boolean;
  textTruncated: boolean;
}

export interface ThreatIp {
  ip: string;
  count: number;
  lastSeen: string;
  actionType: string;
}

export interface ThreatUser {
  username: string;
  count: number;
  successCount: number;
  failCount: number;
}

export interface LogThreatSummary {
  bruteForceCount: number;
  successfulLoginCount: number;
  privilegeEscalationCount: number;
  suspiciousActivityCount: number;
  topSourceIps: ThreatIp[];
  topTargetUsers: ThreatUser[];
  hourlyDistribution: number[];
  threatLevel: LogThreatLevel;
}

export interface LogSourceReadResult {
  snapshotHandle: string;
  sourceHandle: string;
  sourceKind: LogSourceKind;
  page: number;
  pageSize: number;
  entryCount: number;
  highlightedCount: number;
  hasMore: boolean;
  entries: PublicLogEntry[];
  threatSummary: LogThreatSummary;
  redactedCount: number;
  truncated: boolean;
}

export interface LogCorrelationResult {
  snapshotHandle: string;
  sourceHandles: string[];
  coverage: "bounded-best-effort";
  totalObserved: number;
  entries: PublicLogEntry[];
  threatSummary: LogThreatSummary;
  redactedCount: number;
  truncated: boolean;
}

export interface LogIocMatch {
  indicator: string;
  sourceHandle: string;
  sourceName: string;
  count: number;
  sampleLines: string[];
  samplesRedacted: boolean;
  textTruncated: boolean;
}

export interface LogIocSearchResult {
  snapshotHandle: string;
  results: LogIocMatch[];
  totalMatches: number;
  redactedSampleCount: number;
  truncated: boolean;
}

export interface LogAnalysisReadApi {
  discoverLogSources(bindingHandle: string): Promise<unknown>;
  readLogSource(
    bindingHandle: string,
    snapshotHandle: string,
    sourceHandle: string,
    input: LogSourceReadInput,
  ): Promise<unknown>;
  correlateLogSources(
    bindingHandle: string,
    snapshotHandle: string,
    input: LogCorrelationInput,
  ): Promise<unknown>;
  searchLogIocs(
    bindingHandle: string,
    snapshotHandle: string,
    input: LogIocSearchInput,
  ): Promise<unknown>;
}

type JsonRecord = Record<string, unknown>;
const encoder = new TextEncoder();
const redactedLine = "[SENSITIVE LOG LINE REDACTED]";
const sourceKinds = new Set<LogSourceKind>(["file", "journal"]);
const threatLevels = new Set<LogThreatLevel>(["none", "low", "medium", "high", "critical"]);

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

function withinTextBudget(values: Iterable<string>, maximumBytes: number): boolean {
  let total = 0;
  for (const value of values) {
    total += encoder.encode(value).byteLength;
    if (total > maximumBytes) return false;
  }
  return true;
}

function noControls(value: string): boolean {
  return !/[\u0000-\u001f\u007f]/u.test(value);
}

function containsSensitiveMaterial(value: string): boolean {
  const lower = value.toLocaleLowerCase();
  return [
    "password=", "password:", "passwd=", "passphrase=", "passphrase:", "secret=", "secret:",
    "token=", "token:", "authorization=", "authorization:", "api_key=", "apikey=", "private_key=",
    "credential=", "cookie:", "set-cookie:", "session_id=", "bearer ",
  ].some((marker) => lower.includes(marker)) || lower.includes("://") && lower.includes("@");
}

function publicText(value: unknown, maximumBytes: number, allowEmpty = true): value is string {
  return text(value, maximumBytes, allowEmpty) && !containsSensitiveMaterial(value);
}

export function isLogAnalysisOpaqueHandle(value: unknown): value is string {
  return text(value, 128, false) && /^[A-Za-z0-9-]+$/u.test(value);
}

export function isLogSourceKind(value: unknown): value is LogSourceKind {
  return typeof value === "string" && sourceKinds.has(value as LogSourceKind);
}

export function isLogCalendarDay(value: unknown): value is string {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/u.test(value)) return false;
  const timestamp = Date.parse(`${value}T00:00:00Z`);
  return !Number.isNaN(timestamp) && new Date(timestamp).toISOString().slice(0, 10) === value;
}

function optionalQueryText(value: unknown, maximumBytes: number): value is string | null {
  return value === null || (text(value, maximumBytes, false) && value === value.trim() && noControls(value));
}

function journalUnit(value: unknown): value is string | null {
  return value === null || (optionalQueryText(value, 128) &&
    typeof value === "string" && /^[A-Za-z0-9_.@:-]+$/u.test(value));
}

function uniqueHandles(value: unknown, minimum: number, maximum: number): value is string[] {
  return Array.isArray(value) && value.length >= minimum && value.length <= maximum &&
    value.every(isLogAnalysisOpaqueHandle) && new Set(value).size === value.length;
}

export function isLogSourceReadInput(value: unknown): value is LogSourceReadInput {
  return record(value) && exact(value, ["page", "pageSize", "keyword", "date", "journalUnit"]) &&
    unsigned(value.page, 10_000) && value.page > 0 &&
    unsigned(value.pageSize, 200) && value.pageSize > 0 &&
    optionalQueryText(value.keyword, 256) &&
    (value.date === null || isLogCalendarDay(value.date)) && journalUnit(value.journalUnit);
}

export function isLogCorrelationInput(value: unknown): value is LogCorrelationInput {
  return record(value) && exact(value, ["sourceHandles", "lineLimit"]) &&
    uniqueHandles(value.sourceHandles, 2, 8) && unsigned(value.lineLimit, 200) && value.lineLimit > 0;
}

export function isLogIocSearchInput(value: unknown): value is LogIocSearchInput {
  if (!record(value) || !exact(value, ["sourceHandles", "indicators"]) ||
    !uniqueHandles(value.sourceHandles, 1, 8) || !Array.isArray(value.indicators) ||
    value.indicators.length === 0 || value.indicators.length > 16 ||
    value.indicators.length * value.sourceHandles.length > 64) return false;
  return value.indicators.every((indicator) => optionalQueryText(indicator, 256) && indicator !== null &&
    !containsSensitiveMaterial(indicator)) &&
    new Set(value.indicators).size === value.indicators.length;
}

function source(value: unknown): value is LogSource {
  if (!record(value) || !exact(value, [
    "sourceHandle", "kind", "displayName", "displayLocation", "sizeBytes", "modified",
  ]) || !isLogAnalysisOpaqueHandle(value.sourceHandle) || !isLogSourceKind(value.kind) ||
    !publicText(value.displayName, 256) || !publicText(value.displayLocation, 4_096) ||
    !publicText(value.modified, 64)) return false;
  return value.kind === "file"
    ? unsigned(value.sizeBytes, Number.MAX_SAFE_INTEGER)
    : value.sizeBytes === null && value.modified === "";
}

export function isLogSourceSnapshot(value: unknown): value is LogSourceSnapshot {
  if (!record(value) || !exact(value, [
    "snapshotHandle", "expiresInSeconds", "sources", "partial", "truncated",
  ]) || !isLogAnalysisOpaqueHandle(value.snapshotHandle) || !unsigned(value.expiresInSeconds, 300) ||
    value.expiresInSeconds === 0 || !Array.isArray(value.sources) || value.sources.length > 101 ||
    !value.sources.every(source) || typeof value.partial !== "boolean" || typeof value.truncated !== "boolean") return false;
  const sources = value.sources as LogSource[];
  return new Set(sources.map((item) => item.sourceHandle)).size === sources.length &&
    sources.filter((item) => item.kind === "file").length <= 100 &&
    sources.filter((item) => item.kind === "journal").length <= 1 &&
    withinTextBudget(sources.flatMap((item) => [item.displayName, item.displayLocation, item.modified]), 512 * 1_024);
}

function logEntry(value: unknown): value is PublicLogEntry {
  if (!record(value) || !exact(value, [
    "timestamp", "level", "service", "message", "rawText", "highlighted", "sourceHandle",
    "sourceName", "redacted", "textTruncated",
  ]) || !publicText(value.timestamp, 128) || !publicText(value.level, 32) ||
    !publicText(value.service, 256) || !publicText(value.message, 8 * 1_024) ||
    !publicText(value.rawText, 16 * 1_024) ||
    typeof value.highlighted !== "boolean" || typeof value.redacted !== "boolean" ||
    typeof value.textTruncated !== "boolean") return false;
  const sourceValid = value.sourceHandle === null && value.sourceName === null ||
    isLogAnalysisOpaqueHandle(value.sourceHandle) && publicText(value.sourceName, 256);
  return sourceValid && (!value.redacted || value.message === redactedLine && value.rawText === redactedLine);
}

function threatIp(value: unknown, maximum: number): value is ThreatIp {
  return record(value) && exact(value, ["ip", "count", "lastSeen", "actionType"]) &&
    publicText(value.ip, 64) && unsigned(value.count, maximum) && publicText(value.lastSeen, 128) &&
    publicText(value.actionType, 64);
}

function threatUser(value: unknown, maximum: number): value is ThreatUser {
  if (!record(value) || !exact(value, ["username", "count", "successCount", "failCount"]) ||
    !publicText(value.username, 64) || !unsigned(value.count, maximum) ||
    !unsigned(value.successCount, maximum) || !unsigned(value.failCount, maximum)) return false;
  return value.successCount + value.failCount === value.count;
}

function threatSummary(value: unknown, maximum: number): value is LogThreatSummary {
  return record(value) && exact(value, [
    "bruteForceCount", "successfulLoginCount", "privilegeEscalationCount", "suspiciousActivityCount",
    "topSourceIps", "topTargetUsers", "hourlyDistribution", "threatLevel",
  ]) && unsigned(value.bruteForceCount, maximum) && unsigned(value.successfulLoginCount, maximum) &&
    unsigned(value.privilegeEscalationCount, maximum) && unsigned(value.suspiciousActivityCount, maximum) &&
    Array.isArray(value.topSourceIps) && value.topSourceIps.length <= 20 &&
    value.topSourceIps.every((item) => threatIp(item, maximum)) &&
    Array.isArray(value.topTargetUsers) && value.topTargetUsers.length <= 20 &&
    value.topTargetUsers.every((item) => threatUser(item, maximum)) &&
    Array.isArray(value.hourlyDistribution) && value.hourlyDistribution.length === 24 &&
    value.hourlyDistribution.every((item) => unsigned(item, maximum)) &&
    typeof value.threatLevel === "string" && threatLevels.has(value.threatLevel as LogThreatLevel);
}

function entryTextBudget(entries: PublicLogEntry[], maximumBytes: number): boolean {
  return withinTextBudget(entries.flatMap((entry) => [
    entry.timestamp,
    entry.level,
    entry.service,
    entry.message,
    entry.rawText,
    entry.sourceName ?? "",
  ]), maximumBytes);
}

export function isLogSourceReadResult(value: unknown): value is LogSourceReadResult {
  if (!record(value) || !exact(value, [
    "snapshotHandle", "sourceHandle", "sourceKind", "page", "pageSize", "entryCount",
    "highlightedCount", "hasMore", "entries", "threatSummary", "redactedCount", "truncated",
  ]) || !isLogAnalysisOpaqueHandle(value.snapshotHandle) || !isLogAnalysisOpaqueHandle(value.sourceHandle) ||
    !isLogSourceKind(value.sourceKind) || !unsigned(value.page, 10_000) || value.page === 0 ||
    !unsigned(value.pageSize, 200) || value.pageSize === 0 || !Array.isArray(value.entries) ||
    value.entries.length > 200 || !value.entries.every(logEntry) ||
    !unsigned(value.entryCount, 200) || value.entryCount !== value.entries.length ||
    !unsigned(value.highlightedCount, 200) || typeof value.hasMore !== "boolean" ||
    !threatSummary(value.threatSummary, 200) || !unsigned(value.redactedCount, 200) ||
    typeof value.truncated !== "boolean") return false;
  const entries = value.entries as PublicLogEntry[];
  return entries.every((entry) => entry.sourceHandle === null && entry.sourceName === null) &&
    value.highlightedCount === entries.filter((entry) => entry.highlighted).length &&
    value.redactedCount === entries.filter((entry) => entry.redacted).length &&
    entryTextBudget(entries, 512 * 1_024);
}

export function isLogCorrelationResult(value: unknown): value is LogCorrelationResult {
  if (!record(value) || !exact(value, [
    "snapshotHandle", "sourceHandles", "coverage", "totalObserved", "entries", "threatSummary",
    "redactedCount", "truncated",
  ]) || !isLogAnalysisOpaqueHandle(value.snapshotHandle) || !uniqueHandles(value.sourceHandles, 2, 8) ||
    value.coverage !== "bounded-best-effort" || !unsigned(value.totalObserved, 1_600) ||
    !Array.isArray(value.entries) || value.entries.length > 1_000 || !value.entries.every(logEntry) ||
    value.entries.length > value.totalObserved || !threatSummary(value.threatSummary, 1_600) ||
    !unsigned(value.redactedCount, 1_000) || typeof value.truncated !== "boolean") return false;
  const handles = new Set(value.sourceHandles as string[]);
  const entries = value.entries as PublicLogEntry[];
  return entries.every((entry) => entry.sourceHandle !== null && handles.has(entry.sourceHandle) &&
    entry.sourceName !== null) && value.redactedCount === entries.filter((entry) => entry.redacted).length &&
    entryTextBudget(entries, 1_024 * 1_024);
}

function iocMatch(value: unknown): value is LogIocMatch {
  if (!record(value) || !exact(value, [
    "indicator", "sourceHandle", "sourceName", "count", "sampleLines", "samplesRedacted", "textTruncated",
  ]) || !optionalQueryText(value.indicator, 256) || value.indicator === null ||
    containsSensitiveMaterial(value.indicator) ||
    !isLogAnalysisOpaqueHandle(value.sourceHandle) || !publicText(value.sourceName, 256) ||
    !unsigned(value.count, 1_000_000) || !Array.isArray(value.sampleLines) || value.sampleLines.length > 3 ||
    !value.sampleLines.every((line) => publicText(line, 4 * 1_024)) || typeof value.samplesRedacted !== "boolean" ||
    typeof value.textTruncated !== "boolean") return false;
  const redacted = value.sampleLines.filter((line) => line === redactedLine).length;
  return value.samplesRedacted ? redacted > 0 : redacted === 0;
}

export function isLogIocSearchResult(value: unknown): value is LogIocSearchResult {
  if (!record(value) || !exact(value, [
    "snapshotHandle", "results", "totalMatches", "redactedSampleCount", "truncated",
  ]) || !isLogAnalysisOpaqueHandle(value.snapshotHandle) || !Array.isArray(value.results) ||
    value.results.length > 64 || !value.results.every(iocMatch) || !unsigned(value.totalMatches, 64_000_000) ||
    !unsigned(value.redactedSampleCount, 192) || typeof value.truncated !== "boolean") return false;
  const results = value.results as LogIocMatch[];
  const pairs = results.map((item) => `${item.indicator}\0${item.sourceHandle}`);
  const displayedMatches = results.reduce((total, item) => total + item.count, 0);
  const redactedSamples = results.flatMap((item) => item.sampleLines)
    .filter((line) => line === redactedLine).length;
  return new Set(pairs).size === pairs.length && displayedMatches <= value.totalMatches &&
    (!value.truncated ? displayedMatches === value.totalMatches : true) &&
    redactedSamples === value.redactedSampleCount &&
    withinTextBudget(results.flatMap((item) => [item.indicator, item.sourceName, ...item.sampleLines]), 512 * 1_024);
}
