import type { BrowserWindow, Input } from "electron";

/**
 * Debug mode gates Chromium DevTools for every LovelyRes window. It is on for
 * unpackaged development builds and can be forced for a packaged portable
 * build with LOVELYRES_DEBUG=1; packaged competition builds keep DevTools
 * compiled out of webPreferences otherwise.
 */
export function isDebugModeEnabled(
  isPackaged: boolean,
  environment: Readonly<Record<string, string | undefined>>,
): boolean {
  if (environment.LOVELYRES_DEBUG === "1") return true;
  return !isPackaged;
}

/** Matches the F12 and Ctrl/Cmd+Shift+I DevTools chords on key down only. */
export function isDevToolsChord(input: Pick<Input, "type" | "key" | "control" | "meta" | "shift" | "alt">): boolean {
  if (input.type !== "keyDown") return false;
  if (input.key === "F12" && !input.control && !input.meta && !input.alt) return true;
  return (
    (input.control || input.meta) &&
    input.shift &&
    !input.alt &&
    (input.key === "I" || input.key === "i")
  );
}

/**
 * Wires the DevTools toggle chords onto a window. A no-op unless debug mode is
 * enabled, so packaged builds never register the listener. DevTools opens
 * detached to keep the 1080px minimum layout intact.
 */
export function installDevToolsToggle(window: BrowserWindow, debugEnabled: boolean): void {
  if (!debugEnabled) return;
  window.webContents.on("before-input-event", (event, input) => {
    if (!isDevToolsChord(input)) return;
    event.preventDefault();
    const contents = window.webContents;
    if (contents.isDevToolsOpened()) {
      contents.closeDevTools();
    } else {
      contents.openDevTools({ mode: "detach" });
    }
  });
}
