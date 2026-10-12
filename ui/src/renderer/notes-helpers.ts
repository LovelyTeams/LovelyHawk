import type { NoteSummary } from "../shared/contract";

export function reconcileNoteSelection(
  items: readonly Pick<NoteSummary, "id">[],
  selectedId: string | null,
): string | null {
  if (selectedId !== null && items.some((item) => item.id === selectedId)) {
    return selectedId;
  }
  return items[0]?.id ?? null;
}

export function formatNoteTimestamp(timestamp: number): string {
  if (!Number.isFinite(timestamp) || timestamp < 0) return "未知时间";
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return "未知时间";
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  }).format(date);
}

export async function retryTimedOut<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (reason: unknown) {
    if (!(reason instanceof Error) || reason.message !== "The backend request timed out.") {
      throw reason;
    }
    return operation();
  }
}
