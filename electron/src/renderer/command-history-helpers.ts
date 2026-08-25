import type { CommandHistoryRecord, CommandStatus } from "../shared/command-history-contract";

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

export function replayBlockMessage(reason: string): string {
  switch (reason) {
    case "not-found": return "重放意图已阻止：记录不存在。";
    case "target-mismatch": return "重放意图已阻止：记录不属于当前连接目标。";
    case "digest-mismatch": return "重放意图已阻止：命令摘要不匹配。";
    case "risk-changed": return "重放意图已阻止：命令风险分类已变化。";
    case "mutating-command": return "可写或未知命令没有领域化 plan/verify/restore，禁止重放。";
    default: return "重放意图未通过本地安全边界。";
  }
}
