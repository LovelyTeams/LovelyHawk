import { TerminalSurface } from "./TerminalSurface";

export function TerminalWindow() {
  return (
    <main className="terminal-window-root" data-testid="terminal-window">
      <TerminalSurface
        api={window.lovelyresTerminal}
        writeClipboard={window.lovelyresTerminal.copySelection}
      />
    </main>
  );
}
