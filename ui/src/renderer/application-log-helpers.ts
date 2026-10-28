import type {
  ApplicationLogEntry,
  ApplicationLogLevel,
  ApplicationLogPreview,
} from "../shared/application-log-contract";

const encoder = new TextEncoder();

export function applicationLogLevelLabel(level: ApplicationLogLevel): string {
  switch (level) {
    case "debug": return "DEBUG";
    case "info": return "INFO";
    case "warn": return "WARN";
    case "error": return "ERROR";
  }
}

export function formatApplicationLogTimestamp(timestampUnixMs: number): string {
  const date = new Date(timestampUnixMs);
  return Number.isNaN(date.valueOf()) ? "时间不可用" : date.toISOString();
}

export function applicationLogEntryText(entry: ApplicationLogEntry): string {
  const details = entry.details.length === 0 ? "" : ` | ${JSON.stringify(entry.details)}`;
  return `[${entry.timestampUnixMs}] [${applicationLogLevelLabel(entry.level)}] [${entry.module}] ${entry.message}${details}`;
}

export function applicationLogCopyText(preview: ApplicationLogPreview): string {
  if (encoder.encode(preview.content).byteLength > 128 * 1_024) {
    throw new Error("application log preview exceeds the renderer copy budget");
  }
  return preview.content;
}

export function nextApplicationLogFocus(
  currentIndex: number,
  count: number,
  backwards: boolean,
): number {
  if (count <= 0) return -1;
  if (currentIndex < 0) return backwards ? count - 1 : 0;
  return backwards ? (currentIndex - 1 + count) % count : (currentIndex + 1) % count;
}

export function applicationLogEscapeIntent(key: string): boolean {
  return key === "Escape";
}

interface ApplicationLogMutableSlot<T> {
  current: T;
}

export function deactivateApplicationLogOverlay(
  alive: ApplicationLogMutableSlot<boolean>,
  request: ApplicationLogMutableSlot<number>,
  operation: ApplicationLogMutableSlot<number>,
): void {
  alive.current = false;
  request.current += 1;
  operation.current += 1;
}

interface ApplicationLogInertTarget {
  inert: boolean;
  getAttribute(name: string): string | null;
  setAttribute(name: string, value: string): void;
  removeAttribute(name: string): void;
}

export function isolateApplicationLogBackground(
  targets: ApplicationLogInertTarget[],
): () => void {
  const previous = targets.map((target) => ({
    target,
    inert: target.inert,
    ariaHidden: target.getAttribute("aria-hidden"),
  }));
  for (const { target } of previous) {
    target.inert = true;
    target.setAttribute("aria-hidden", "true");
  }
  return () => {
    for (const { target, inert, ariaHidden } of previous) {
      target.inert = inert;
      if (ariaHidden === null) target.removeAttribute("aria-hidden");
      else target.setAttribute("aria-hidden", ariaHidden);
    }
  };
}

interface ApplicationLogFocusTarget {
  isConnected: boolean;
  focus(options?: FocusOptions): void;
}

export function restoreApplicationLogFocus(target: ApplicationLogFocusTarget | null): void {
  if (target?.isConnected) target.focus({ preventScroll: true });
}
