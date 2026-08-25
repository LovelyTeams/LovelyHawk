import {
  isLogCalendarDay,
  isLogSourceReadInput,
  type LogSource,
  type LogSourceReadInput,
  type LogThreatLevel,
} from "../shared/log-analysis-read-contract";
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
