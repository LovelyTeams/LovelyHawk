import {
  isLogCalendarDay,
  isLogSourceReadInput,
  type LogSource,
  type LogSourceKind,
  type LogSourceReadInput,
  type LogThreatLevel,
} from "../shared/log-analysis-read-contract";
import type { EmergencyCommandPathOffer } from "../shared/emergency-command-contract";
import type { LogAnalysisTab, LogReadFilter } from "./log-analysis-read-state";

const encoder = new TextEncoder();

export function logAnalysisScope(bindingHandle: string): string {
  return bindingHandle;
}

export function logAnalysisTabLabel(tab: LogAnalysisTab): string {
  switch (tab) {
    case "browse": return "日志浏览";
    case "correlation": return "多源关联";
    case "ioc": return "IOC 搜索";
  }
}

export function logThreatLevelLabel(level: LogThreatLevel): string {
  switch (level) {
    case "none": return "未发现";
    case "low": return "低";
    case "medium": return "中";
    case "high": return "高";
    case "critical": return "严重";
  }
}

export function logSourceKindLabel(kind: LogSourceKind): string {
  return kind === "journal" ? "systemd journal" : "文件日志";
}

/** One branch per kind, files first, so the tree reads the same way every time. */
export interface LogSourceGroup {
  kind: LogSourceKind;
  sources: LogSource[];
}

export function groupLogSources(sources: readonly LogSource[]): LogSourceGroup[] {
  const order: LogSourceKind[] = ["file", "journal"];
  return order
    .map((kind) => ({ kind, sources: sources.filter((source) => source.kind === kind) }))
    .filter((group) => group.sources.length > 0);
}

/**
 * Whether this source is a rotated archive rather than a live log.
 *
 * Read from the location that is already on screen, not asked for over the
 * boundary: it decides two words of labelling, and the reader on the other side
 * makes the same call from the same name.
 */
/**
 * What file evidence needs to keep a listed log file: the handle the backend
 * offered, and the location as shown, which the evidence dialog checks against
 * the path the backend resolves. Nothing for the journal or for a file the
 * backend offered no handle for (its location is shown cut short).
 */
export function logEvidenceOffer(source: LogSource): EmergencyCommandPathOffer | null {
  if (source.kind !== "file" || source.pathHandle === null) return null;
  return { pathHandle: source.pathHandle, line: 0, path: source.displayLocation };
}

export function isArchivedLog(source: Pick<LogSource, "displayLocation">): boolean {
  return source.displayLocation.endsWith(".gz");
}

export function formatLogSourceSize(sizeBytes: number | null): string {
  if (sizeBytes === null) return "动态日志流";
  if (sizeBytes < 1_024) return `${sizeBytes} B`;
  if (sizeBytes < 1_024 * 1_024) return `${(sizeBytes / 1_024).toFixed(1)} KiB`;
  if (sizeBytes < 1_024 * 1_024 * 1_024) return `${(sizeBytes / (1_024 * 1_024)).toFixed(1)} MiB`;
  return `${(sizeBytes / (1_024 * 1_024 * 1_024)).toFixed(1)} GiB`;
}

export function filterLogSources(sources: readonly LogSource[], query: string): LogSource[] {
  const needle = query.trim().toLocaleLowerCase();
  if (needle.length === 0) return [...sources];
  return sources.filter((source) => [source.displayName, source.displayLocation, source.kind]
    .some((value) => value.toLocaleLowerCase().includes(needle)));
}

export function buildLogReadInput(
  source: LogSource,
  page: number,
  filter: LogReadFilter,
): { input: LogSourceReadInput | null; error: string | null } {
  const keyword = normalizeOptional(filter.keyword);
  if (keyword.error !== null || byteLength(keyword.value) > 256) {
    return { input: null, error: "关键词必须是不超过 256 字节的单行文本。" };
  }
  const date = filter.date.trim();
  if (date.length > 0 && !isLogCalendarDay(date)) {
    return { input: null, error: "日期必须是有效的 YYYY-MM-DD。" };
  }
  const unit = source.kind === "journal" ? normalizeOptional(filter.journalUnit) : { value: null, error: null };
  if (unit.error !== null || byteLength(unit.value) > 128 ||
    unit.value !== null && !/^[A-Za-z0-9_.@:-]+$/u.test(unit.value)) {
    return { input: null, error: "Journal 单元只能使用字母、数字和 . _ @ : -，且不超过 128 字节。" };
  }
  const input: LogSourceReadInput = {
    page,
    pageSize: 100,
    keyword: keyword.value,
    date: date.length === 0 ? null : date,
    journalUnit: unit.value,
  };
  return isLogSourceReadInput(input)
    ? { input, error: null }
    : { input: null, error: "日志查询超出只读安全边界。" };
}

/** What a marked run of text inside one log line is. */
export type LogHighlightKind = "network" | "secret" | "payload";

export interface LogTextSegment {
  text: string;
  kind: LogHighlightKind | null;
}

/**
 * The most matches marked in one line.
 *
 * A line that is nothing but addresses is not made more readable by painting
 * all of it; past this the rest is left plain rather than turning the row into
 * a wall of colour.
 */
const MAX_HIGHLIGHTS_PER_LINE = 24;

/** Beyond this a line is left alone: scanning it costs more than it is worth. */
const MAX_HIGHLIGHT_SCAN_CHARS = 4_096;

/**
 * The three things worth finding again once a line is already on screen.
 *
 * Whole rows the reader judged abnormal are already marked by the reader
 * itself; this is the layer under that — where in the line to look. Every
 * alternative is anchored and free of nested quantifiers, so a hostile line
 * cannot make the scan expensive.
 */
const HIGHLIGHT_PATTERN = new RegExp(
  [
    // An address or a URL: the first thing anyone looks for in an auth log.
    "(?<network>\\bhttps?:\\/\\/[^\\s\"'<>]{1,200}|\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b|\\b(?:[0-9a-f]{1,4}:){4,7}[0-9a-f]{1,4}\\b)",
    // A credential word, with the value when it is attached to it. The value
    // is marked, never masked: a log is evidence, and hiding part of it is
    // how a finding gets lost.
    "(?<secret>\\b(?:password|passwd|pwd|token|secret|credential|api[_-]?key|access[_-]?key|private[_-]?key|authorization)s?\\b(?:\\s*[:=]\\s*\\S{1,120})?)",
    // Fetching something and running it, or working out of a world-writable
    // directory.
    "(?<payload>\\b(?:curl|wget|ncat|socat|base64|openssl\\s+enc|chattr)\\b|\\bnc\\b(?=\\s)|\\/dev\\/tcp\\/[^\\s\"']{0,80}|(?:\\/tmp\\/|\\/var\\/tmp\\/|\\/dev\\/shm\\/)[^\\s\"';|]{0,120})",
  ].join("|"),
  "giu",
);

/**
 * Splits one log line into plain and marked runs, in order.
 *
 * Returns the line as a single plain segment when there is nothing to mark, so
 * the common case costs one array entry and the caller needs no special case.
 */
export function splitSensitiveSegments(text: string): LogTextSegment[] {
  if (text.length === 0) return [];
  if (text.length > MAX_HIGHLIGHT_SCAN_CHARS) return [{ text, kind: null }];
  const segments: LogTextSegment[] = [];
  let cursor = 0;
  let marked = 0;
  HIGHLIGHT_PATTERN.lastIndex = 0;
  for (
    let match = HIGHLIGHT_PATTERN.exec(text);
    match !== null && marked < MAX_HIGHLIGHTS_PER_LINE;
    match = HIGHLIGHT_PATTERN.exec(text)
  ) {
    const groups = match.groups ?? {};
    const kind: LogHighlightKind | null = groups["network"] !== undefined
      ? "network"
      : groups["secret"] !== undefined
        ? "secret"
        : groups["payload"] !== undefined
          ? "payload"
          : null;
    if (kind === null || match[0].length === 0) {
      // Never let a zero-width match stall the scan.
      HIGHLIGHT_PATTERN.lastIndex = match.index + 1;
      continue;
    }
    if (match.index > cursor) segments.push({ text: text.slice(cursor, match.index), kind: null });
    segments.push({ text: match[0], kind });
    cursor = match.index + match[0].length;
    marked += 1;
  }
  if (cursor < text.length) segments.push({ text: text.slice(cursor), kind: null });
  return segments;
}

export function parseIocIndicators(
  raw: string,
  sourceCount: number,
): { indicators: string[]; error: string | null } {
  const values = raw.split(/\r?\n/u).map((value) => value.trim()).filter((value) => value.length > 0);
  if (values.length === 0) return { indicators: [], error: "请至少输入一个 IOC，每行一个。" };
  if (values.length > 16) return { indicators: [], error: "一次最多提交 16 个 IOC。" };
  if (new Set(values).size !== values.length) return { indicators: [], error: "IOC 不能重复。" };
  if (values.some((value) => byteLength(value) > 256 || /[\u0000-\u001f\u007f]/u.test(value))) {
    return { indicators: [], error: "每个 IOC 必须是不超过 256 字节的单行文本。" };
  }
  if (sourceCount < 1 || sourceCount > 8 || values.length * sourceCount > 64) {
    return { indicators: [], error: "IOC 与日志源的组合数不能超过 64。" };
  }
  return { indicators: values, error: null };
}

function normalizeOptional(value: string): { value: string | null; error: string | null } {
  const trimmed = value.trim();
  if (trimmed.length === 0) return { value: null, error: null };
  if (/[\u0000-\u001f\u007f]/u.test(trimmed)) return { value: null, error: "control" };
  return { value: trimmed, error: null };
}

function byteLength(value: string | null): number {
  return value === null ? 0 : encoder.encode(value).byteLength;
}
