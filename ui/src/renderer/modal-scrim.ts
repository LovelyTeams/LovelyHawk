import { useEffect } from "react";

/**
 * Tracks whether any modal backdrop currently dims the page.
 *
 * The OS paints the window controls above the web contents, so CSS cannot dim
 * them; main has to repaint the native overlay instead. App-level overlays are
 * visible to App, but page-level dialogs (row details, inspections) are not —
 * every backdrop registers here so the signal stays complete.
 */
type ScrimListener = (active: boolean) => void;

let depth = 0;
const listeners = new Set<ScrimListener>();

function publish(): void {
  const active = depth > 0;
  for (const listener of [...listeners]) listener(active);
}

export function isModalScrimActive(): boolean {
  return depth > 0;
}

export function subscribeModalScrim(listener: ScrimListener): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** Test seam: drops any depth a failed render left behind. */
export function resetModalScrim(): void {
  depth = 0;
  listeners.clear();
}

/**
 * Counts this component's backdrop while `active` holds. Nested modals stack,
 * so the scrim only lifts once the last one unmounts.
 */
export function useModalScrim(active = true): void {
  useEffect(() => {
    if (!active) return;
    depth += 1;
    publish();
    return () => {
      depth = Math.max(0, depth - 1);
      publish();
    };
  }, [active]);
}
