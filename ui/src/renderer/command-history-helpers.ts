import type { CommandHistoryRecord, CommandRisk, CommandStatus } from "../shared/command-history-contract";

export function commandHistoryInitialFocus(
  searchInput: HTMLElement | null,
  panel: HTMLElement | null,
): HTMLElement | null {
  return searchInput ?? panel;
}

const MAX_COPY_BYTES = 256 * 1_024;
const encoder = new TextEncoder();

export function formatCommandHistoryTimestamp(timestamp: number): string {
  const date = new Date(timestamp);
  return Number.isNaN(date.getTime()) ? "未知时间" : date.toLocaleString();
}

export function commandStatusLabel(status: CommandStatus, exitCode: number | null): string {
  switch (status) {
    case "succeeded": return "成功（退出码 0）";
    case "failed": return `失败（退出码 ${exitCode ?? "未知"}）`;
    case "unknown": return "状态未知（无退出码）";
  }
}

export function commandHistoryCopyText(
  record: CommandHistoryRecord,
  field: "command" | "output",
): string {
  const value = record[field];
  if (encoder.encode(value).byteLength > MAX_COPY_BYTES) {
    throw new Error("command history copy exceeds the local budget");
  }
  return value;
}

export function nextCommandHistoryFocus(
  currentIndex: number,
  count: number,
  backwards: boolean,
): number {
  if (count <= 0) return -1;
  if (currentIndex < 0) return backwards ? count - 1 : 0;
  return backwards ? (currentIndex - 1 + count) % count : (currentIndex + 1) % count;
}

export function commandRiskLabel(risk: CommandRisk): string {
  return risk === "read-only" ? "只读命令" : "可能修改系统的命令，或无法判断是否只读";
}
