import type { LovelyResApi } from "../shared/contract";
import type { TerminalApi } from "../shared/terminal-contract";

declare global {
  interface Window {
    lovelyres: LovelyResApi;
    lovelyresTerminal: TerminalApi;
  }
}

export {};
