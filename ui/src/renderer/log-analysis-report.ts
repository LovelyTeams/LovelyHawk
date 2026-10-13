import type {
  LogCorrelationResult,
  LogIocSearchResult,
  LogSource,
  LogSourceReadResult,
  LogThreatSummary,
  PublicLogEntry,
} from "../shared/log-analysis-read-contract";
import { logSourceKindLabel, logThreatLevelLabel } from "./log-analysis-read-helpers";
import type { LogReadFilter } from "./log-analysis-read-state";

/**
 * The host takes at most this much on the clipboard (MAX_CLIPBOARD_BYTES in
 * ui/src/host/main-api.ts). A report keeps its header, summary and closing
 * note whole and drops log lines from the end, saying how many.
 */
export const LOG_REPORT_MAXIMUM_BYTES = 128 * 1_024;

/** A report and how many log lines did not fit in it. */
export interface LogReport {
  text: string;
  omitted: number;
}

const encoder = new TextEncoder();
const bytes = (value: string): number => encoder.encode(value).byteLength;

/**
 * Remote text as one line of plain text. Line breaks become spaces, and other
 * control characters — including the invisible ones that reorder text — are
 * replaced so a pasted report reads the way the page showed it. Nothing else
 * is removed or masked: the line is evidence.
 */
export function plainReportText(value: string): string {
  return value
    .replace(/\r\n|[\r\n\u2028\u2029]/gu, " ")
    .replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/gu, "\ufffd");
}

/** Local time with its offset, so a pasted report says when, and in which zone. */
export function formatReportTime(date: Date): string {
  const pad = (value: number) => String(value).padStart(2, "0");
  const offset = -date.getTimezoneOffset();
  const sign = offset >= 0 ? "+" : "-";
  const absolute = Math.abs(offset);
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ` +
    `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}` +
    `（本机时间，UTC${sign}${pad(Math.floor(absolute / 60))}:${pad(absolute % 60)}）`;
}

function sourceLine(source: LogSource | undefined, handle: string): string {
  if (source === undefined) return `（日志源列表已刷新，名称不可用：${handle.slice(0, 8)}…）`;
  const name = plainReportText(source.displayName) || "日志源";
  const location = plainReportText(source.displayLocation);
  return location === "" || location === name ? name : `${name}（${location}）`;
}

function threatLines(summary: LogThreatSummary): string[] {
  const ips = summary.topSourceIps.map((item) =>
    `${plainReportText(item.ip) || "—"}（${item.count} 次，${plainReportText(item.actionType) || "—"}，` +
    `最后 ${plainReportText(item.lastSeen) || "—"}）`);
  const users = summary.topTargetUsers.map((item) =>
    `${plainReportText(item.username) || "—"}（${item.count} 次：成功 ${item.successCount} / 失败 ${item.failCount}）`);
  const hours = summary.hourlyDistribution
    .map((count, hour) => ({ count, hour }))
    .filter((item) => item.count > 0)
    .map((item) => `${String(item.hour).padStart(2, "0")}:00 ${item.count}`);
  return [
    "## 威胁摘要",
    "",
    `- 威胁等级：${logThreatLevelLabel(summary.threatLevel)}（只按这里读到的行估计，不是对整台主机的结论）`,
    `- 暴力尝试 ${summary.bruteForceCount}，成功登录 ${summary.successfulLoginCount}，` +
      `提权活动 ${summary.privilegeEscalationCount}，可疑活动 ${summary.suspiciousActivityCount}`,
    `- 来源 IP：${ips.length === 0 ? "无" : ips.join("；")}`,
    `- 目标用户：${users.length === 0 ? "无" : users.join("；")}`,
    `- 有记录的小时：${hours.length === 0 ? "无" : hours.join(" · ")}`,
  ];
}

function entryLine(entry: PublicLogEntry, index: number): string {
  const text = entry.rawText !== ""
    ? entry.rawText
    : [entry.timestamp, entry.level, entry.service, entry.message].filter((part) => part !== "").join(" ");
  const parts = [`${index + 1}.`];
  if (entry.highlighted) parts.push("[可疑]");
  if (entry.sourceName !== null && entry.sourceName !== "") parts.push(`[${plainReportText(entry.sourceName)}]`);
  parts.push(plainReportText(text) || "—");
  if (entry.textTruncated) parts.push("（这一行已截断）");
  return parts.join(" ");
}

/**
 * Joins a report: the head and the closing note always whole, as many of the
 * body lines as the clipboard takes, and a line saying how many it did not.
 */
function assemble(head: string[], bodyTitle: string, body: string[], tail: string[]): LogReport {
  const headText = `${head.join("\n")}\n\n${bodyTitle}\n\n`;
  const tailText = `\n\n${tail.join("\n")}\n`;
  // Room for the line that says what was left out.
  const reserve = bytes(headText) + bytes(tailText) + 160;
  let used = reserve;
  const kept: string[] = [];
  for (const line of body) {
    const size = bytes(line) + 1;
    if (used + size > LOG_REPORT_MAXIMUM_BYTES) break;
    kept.push(line);
    used += size;
  }
  const omitted = body.length - kept.length;
  const note = omitted > 0
    ? [`（还有 ${omitted} 条没有复制：超出剪贴板上限。缩小范围或分页后再复制。）`]
    : [];
  const bodyText = [...(kept.length === 0 && omitted === 0 ? ["（没有日志行）"] : kept), ...note].join("\n");
  return { text: `${headText}${bodyText}${tailText}`, omitted };
}

const READ_ONLY_NOTE = "只读读取，没有改动目标机。";

/** The browse view: one page of one source, with the conditions it was read under. */
export function buildLogReadReport(input: {
  source: LogSource;
  filter: LogReadFilter;
  result: LogSourceReadResult;
  copiedAt: Date;
}): LogReport {
  const { source, filter, result } = input;
  const conditions = [
    `关键词 ${filter.keyword.trim() === "" ? "无" : `“${plainReportText(filter.keyword.trim())}”`}`,
    `日期 ${filter.date === "" ? "不限" : plainReportText(filter.date)}`,
    ...(source.kind === "journal"
      ? [`Journal 单元 ${filter.journalUnit.trim() === "" ? "不限" : plainReportText(filter.journalUnit.trim())}`]
      : []),
  ];
  const head = [
    "# LovelyHawk 日志分析 · 日志浏览",
    "",
    `复制时间：${formatReportTime(input.copiedAt)}`,
    `日志源：${sourceLine(source, result.sourceHandle)}，${logSourceKindLabel(source.kind)}`,
    `读取条件：${conditions.join("；")}`,
    `范围：第 ${result.page} 页，每页最多 ${result.pageSize} 条；本页 ${result.entryCount} 条，` +
      `其中 ${result.highlightedCount} 条标为可疑；${result.hasMore ? "后面还有更多" : "这是最后一页"}`,
    ...(result.truncated ? ["注意：本页文本已按大小上限截断。"] : []),
    "",
    ...threatLines(result.threatSummary),
  ];
  return assemble(head, "## 日志（本页）", result.entries.map(entryLine), [
    `${READ_ONLY_NOTE}这里只有本页读到的行，不代表这个日志的全部；没有读到的部分没有发现，不等于没有事件。`,
  ]);
}

/** The correlation view: several sources read side by side, each to its bound. */
export function buildLogCorrelationReport(input: {
  sources: readonly LogSource[];
  result: LogCorrelationResult;
  copiedAt: Date;
}): LogReport {
  const { result } = input;
  const byHandle = new Map(input.sources.map((source) => [source.sourceHandle, source]));
  const head = [
    "# LovelyHawk 日志分析 · 多源关联",
    "",
    `复制时间：${formatReportTime(input.copiedAt)}`,
    `日志源（${result.sourceHandles.length} 个）：` +
      result.sourceHandles.map((handle) => sourceLine(byHandle.get(handle), handle)).join("、"),
    `范围：每源最多观察 200 行，共观察 ${result.totalObserved} 条，列出 ${result.entries.length} 条`,
    ...(result.truncated ? ["注意：结果已截断。"] : []),
    "",
    ...threatLines(result.threatSummary),
  ];
  return assemble(head, "## 关联日志", result.entries.map(entryLine), [
    `${READ_ONLY_NOTE}关联只覆盖每个日志源读到的那一段，不代表未读取的范围。`,
  ]);
}

/** The IOC view: which indicators were found where, and which were not found at all. */
export function buildLogIocReport(input: {
  sources: readonly LogSource[];
  indicators: readonly string[];
  result: LogIocSearchResult;
  sourceHandles: readonly string[];
  copiedAt: Date;
}): LogReport {
  const { result } = input;
  const byHandle = new Map(input.sources.map((source) => [source.sourceHandle, source]));
  const found = new Set(result.results.map((item) => item.indicator));
  const missing = input.indicators.filter((indicator) => !found.has(indicator));
  const head = [
    "# LovelyHawk 日志分析 · IOC 搜索",
    "",
    `复制时间：${formatReportTime(input.copiedAt)}`,
    `日志源（${input.sourceHandles.length} 个）：` +
      input.sourceHandles.map((handle) => sourceLine(byHandle.get(handle), handle)).join("、"),
    `IOC（${input.indicators.length} 个）：${input.indicators.map(plainReportText).join("、")}`,
    `结果：共命中 ${result.totalMatches} 次，涉及 ${found.size} 个 IOC`,
    `没有命中：${missing.length === 0 ? "无" : missing.map(plainReportText).join("、")}`,
    ...(result.truncated ? ["注意：结果已截断。"] : []),
  ];
  const body: string[] = [];
  for (const match of result.results) {
    const name = match.sourceName !== "" ? plainReportText(match.sourceName) : sourceLine(byHandle.get(match.sourceHandle), match.sourceHandle);
    body.push(`- ${plainReportText(match.indicator)} @ ${name}：${match.count} 次${match.textTruncated ? "（样例已截断）" : ""}`);
    for (const sample of match.sampleLines) body.push(`    ${plainReportText(sample)}`);
  }
  return assemble(head, "## 命中", body, [
    `${READ_ONLY_NOTE}没有命中只说明在所选日志源里没找到，不代表其他地方没有。`,
  ]);
}
