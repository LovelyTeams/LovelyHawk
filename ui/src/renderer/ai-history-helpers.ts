import type { AiHistoryRecord } from "../shared/ai-history-contract";

const encoder = new TextEncoder();
const MAX_COPY_BYTES = 4 * 1_024 * 1_024;

export function formatAiHistoryTimestamp(timestamp: number): string {
  const value = new Date(timestamp);
  return Number.isNaN(value.getTime()) ? String(timestamp) : value.toLocaleString();
}

/** Where an answer was asked from, as the backend records it (AiAssistTask::source). */
const SOURCE_LABELS: Readonly<Record<string, string>> = Object.freeze({
  "log-analysis": "日志分析",
  "log-analysis-ioc": "日志分析 · IOC 搜索",
  terminal: "终端选中内容",
});

/** The page that asked, in words; a source this version does not know is shown as stored. */
export function aiHistorySourceLabel(source: string): string {
  return Object.hasOwn(SOURCE_LABELS, source) ? SOURCE_LABELS[source]! : source;
}

export function aiHistoryCopyText(record: AiHistoryRecord, field: "prompt" | "result"): string {
  const text = record[field];
  if (encoder.encode(text).byteLength > MAX_COPY_BYTES) {
    throw new Error("AI 历史正文超过复制预算。");
  }
  return text;
}

export function nextAiHistoryModalFocus(
  currentIndex: number,
  focusableCount: number,
  backwards: boolean,
): number {
  if (focusableCount <= 0) return -1;
  if (currentIndex < 0 || currentIndex >= focusableCount) {
    return backwards ? focusableCount - 1 : 0;
  }
  if (backwards) return currentIndex === 0 ? focusableCount - 1 : currentIndex - 1;
  return currentIndex === focusableCount - 1 ? 0 : currentIndex + 1;
}
