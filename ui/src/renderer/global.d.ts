import type { WindowChromeApi } from "../host/window-chrome";
import type { LovelyHawkApi } from "../shared/contract";
import type { TerminalApi } from "../shared/terminal-contract";

declare global {
  interface Window {
    lovelyhawkChannel: import("../shared/windows-channel-contract").WindowsChannelApi;
    /** Main window only: the validated backend and host API. */
    lovelyhawk: LovelyHawkApi;
    /** Terminal and file-editor windows only. */
    lovelyhawkTerminal: TerminalApi;
    /** Every window: its own minimize, maximize and close buttons. */
    lovelyhawkWindow: WindowChromeApi;
  }
}

export {};
