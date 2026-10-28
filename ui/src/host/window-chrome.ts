import { getCurrentWindow } from "@tauri-apps/api/window";

/**
 * The window controls a page draws in its own title bar.
 *
 * Windows have no system frame, so minimize, maximize and close are buttons
 * on the page. Closing still goes through the host: the main window asks the
 * page first, so unsaved work can say no.
 */
export interface WindowChromeApi {
  minimize(): Promise<void>;
  toggleMaximize(): Promise<void>;
  close(): Promise<void>;
  isMaximized(): Promise<boolean>;
  /** Calls `listener` whenever the window is maximized or restored. */
  onMaximizedChange(listener: (maximized: boolean) => void): () => void;
}

export function createWindowChrome(): WindowChromeApi {
  const current = getCurrentWindow();
  return Object.freeze({
    minimize: () => current.minimize(),
    toggleMaximize: () => current.toggleMaximize(),
    close: () => current.close(),
    isMaximized: () => current.isMaximized(),
    onMaximizedChange: (listener: (maximized: boolean) => void) => {
      let disposed = false;
      let stop: (() => void) | null = null;
      let last: boolean | null = null;
      const report = () => {
        void current.isMaximized().then((maximized) => {
          if (disposed || maximized === last) return;
          last = maximized;
          listener(maximized);
        }, () => undefined);
      };
      report();
      void current.onResized(report).then((unlisten) => {
        if (disposed) unlisten();
        else stop = unlisten;
      }, () => undefined);
      return () => {
        disposed = true;
        stop?.();
      };
    },
  });
}

function isEditable(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  if (target.isContentEditable) return true;
  if (target instanceof HTMLTextAreaElement) return !target.readOnly && !target.disabled;
  if (target instanceof HTMLInputElement) {
    return !target.readOnly && !target.disabled &&
      !["button", "checkbox", "color", "file", "hidden", "image", "radio", "range", "reset", "submit"].includes(target.type);
  }
  return false;
}

/** Keys the embedded browser would act on: reload, print, history, view source. */
export function isBrowserAccelerator(event: Pick<KeyboardEvent, "key" | "ctrlKey" | "metaKey" | "altKey" | "shiftKey">): boolean {
  const key = event.key.length === 1 ? event.key.toLowerCase() : event.key;
  const command = event.ctrlKey || event.metaKey;
  if (key === "F5" || key === "BrowserRefresh" || key === "BrowserBack" || key === "BrowserForward") return true;
  if (event.altKey && (key === "ArrowLeft" || key === "ArrowRight")) return true;
  return command && ["r", "p", "u", "s", "o", "n", "t", "w", "j", "h", "+", "=", "-", "0"].includes(key);
}

/** Find-in-page keys: pages may take them; otherwise the browser's bar is suppressed. */
function isFindAccelerator(event: KeyboardEvent): boolean {
  const key = event.key.length === 1 ? event.key.toLowerCase() : event.key;
  return key === "F3" || ((event.ctrlKey || event.metaKey) && (key === "f" || key === "g"));
}

/**
 * Keeps the embedded browser out of the operator's way. A page is an
 * application, not a web page: no reload that drops unsaved state, no browser
 * menu, no navigating to a file dropped by accident.
 *
 * Keys are only taken after the page had its turn. A terminal owns Ctrl+R,
 * Ctrl+U, Ctrl+W and the rest — xterm ignores a key someone already marked
 * handled — so suppressing them before it saw them would break the shell.
 */
export function hardenPage(target: Window = window): void {
  target.addEventListener("keydown", (event) => {
    if (!event.defaultPrevented && (isBrowserAccelerator(event) || isFindAccelerator(event))) {
      event.preventDefault();
    }
  });
  target.addEventListener("contextmenu", (event) => {
    if (!event.defaultPrevented && !isEditable(event.target)) event.preventDefault();
  });
  target.addEventListener("auxclick", (event) => {
    if (event.button === 3 || event.button === 4) event.preventDefault();
  }, { capture: true });
  target.addEventListener("mouseup", (event) => {
    if (event.button === 3 || event.button === 4) event.preventDefault();
  }, { capture: true });
  target.addEventListener("dragover", (event) => {
    if (!event.defaultPrevented) event.preventDefault();
  });
  target.addEventListener("drop", (event) => {
    if (!event.defaultPrevented) event.preventDefault();
  });
}
