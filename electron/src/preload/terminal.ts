import { contextBridge, ipcRenderer } from "electron";

import type { TerminalApi } from "../shared/terminal-contract.js";

/**
 * Preload runs in the terminal renderer; the main-process tsconfig deliberately
 * omits the DOM lib, so declare only the members used here.
 */
declare const document: {
  readonly documentElement: { readonly dataset: Record<string, string> } | null;
  readonly readyState: string;
  addEventListener(type: string, listener: () => void, options?: { once?: boolean }): void;
};

/**
 * This preload is sandboxed, so it cannot require sibling modules; the theme
 * ids are repeated here instead of imported from shared/theme-contract.ts.
 * terminal-preload-theme.test.ts fails if the two lists ever diverge.
 */
const THEME_ARGUMENT_PREFIX = "--lovelyres-theme=";
const THEME_IDS = ["light", "dark", "sakura", "incident-canvas"];
const DEFAULT_THEME = "light";

/**
 * The terminal window stays strictly invoke-only, so main hands it the active
 * theme as a launch switch instead of a push channel. Stamping the resolved id
 * applies the palette before first paint; an unknown or missing value falls
 * back to the default theme. Theming must never keep the API from loading, so
 * every step here is best-effort.
 */
function applyLaunchTheme(): void {
  try {
    const argument = process.argv.find((value) => value.startsWith(THEME_ARGUMENT_PREFIX));
    const requested = argument?.slice(THEME_ARGUMENT_PREFIX.length) ?? "";
    const theme = THEME_IDS.includes(requested) ? requested : DEFAULT_THEME;
    const apply = () => {
      if (document.documentElement !== null) document.documentElement.dataset["theme"] = theme;
    };
    if (document.documentElement === null && document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", apply, { once: true });
    } else {
      apply();
    }
  } catch {
    // Keep the default theme rather than failing the terminal window.
  }
}

applyLaunchTheme();

const terminalApi: TerminalApi = Object.freeze({
  open: (columns: number, rows: number) =>
    ipcRenderer.invoke("lovelyres:terminal:open", { columns, rows }),
  poll: (maximumEvents: number, maximumBytes: number) =>
    ipcRenderer.invoke("lovelyres:terminal:poll", { maximumEvents, maximumBytes }),
  input: (bytesBase64: string) =>
    ipcRenderer.invoke("lovelyres:terminal:input", bytesBase64),
  resize: (columns: number, rows: number) =>
    ipcRenderer.invoke("lovelyres:terminal:resize", { columns, rows }),
  search: (
    query: string,
    caseSensitive: boolean,
    regex: boolean,
    maximumResults: number,
  ) => ipcRenderer.invoke("lovelyres:terminal:search", {
    query,
    caseSensitive,
    regex,
    maximumResults,
  }),
  copySelection: (text: string) =>
    ipcRenderer.invoke("lovelyres:terminal:copy-selection", text),
  close: () => ipcRenderer.invoke("lovelyres:terminal:close"),
});

contextBridge.exposeInMainWorld("lovelyresTerminal", terminalApi);
