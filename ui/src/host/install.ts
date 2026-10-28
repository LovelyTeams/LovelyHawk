import { createMainApi } from "./main-api.js";
import { createTerminalApi } from "./terminal-api.js";
import { createWindowChrome, hardenPage } from "./window-chrome.js";
import { createWindowsChannelApi } from "./windows-channel-api";

/** Fixed, read-only globals: a page cannot swap in an API of its own. */
function expose(name: "lovelyhawk" | "lovelyhawkTerminal" | "lovelyhawkWindow" | "lovelyhawkChannel", value: object): void {
  Object.defineProperty(window, name, {
    value,
    writable: false,
    configurable: false,
    enumerable: true,
  });
}

export function installChannelHost(): void {
  hardenPage();
  expose("lovelyhawkWindow", createWindowChrome());
  expose("lovelyhawkChannel", createWindowsChannelApi());
}

/** Run once in the main window, before the page renders. */
export function installMainHost(): void {
  hardenPage();
  expose("lovelyhawkWindow", createWindowChrome());
  expose("lovelyhawk", createMainApi());
}

/** Run once in a terminal or file-editor window, before the page renders. */
export function installChildHost(): void {
  hardenPage();
  expose("lovelyhawkWindow", createWindowChrome());
  expose("lovelyhawkTerminal", createTerminalApi());
}
