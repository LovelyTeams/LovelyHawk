import type { AiHistoryRecord } from "../shared/ai-history-contract";

const encoder = new TextEncoder();
const MAX_COPY_BYTES = 4 * 1_024 * 1_024;

export function formatAiHistoryTimestamp(timestamp: number): string {
  const value = new Date(timestamp);
  return Number.isNaN(value.getTime()) ? String(timestamp) : value.toLocaleString();
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
