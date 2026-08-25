import { useState } from "react";

import { SftpBrowserPage } from "./SftpBrowserPage";
import { TerminalSurface } from "./TerminalSurface";

/**
 * The SSH window carries both halves of one connection: the shell and the
 * read-only file browser for the same target. Main resolves which target this
 * window belongs to, so neither half holds target identity.
 */
export function TerminalWindow() {
  const [filesOpen, setFilesOpen] = useState(false);
  return (
    <main className="terminal-window-root" data-testid="terminal-window">
      <div className={filesOpen ? "terminal-window-split is-open" : "terminal-window-split"}>
        <div className="terminal-window-shell">
          <TerminalSurface
            api={window.lovelyresTerminal}
            writeClipboard={window.lovelyresTerminal.copySelection}
          />
        </div>
        {filesOpen ? (
          <aside className="terminal-window-files" aria-label="远程文件">
            <SftpBrowserPage
              connection={{ scopeKey: "ssh-window" }}
              api={window.lovelyresTerminal}
              active={filesOpen}
            />
          </aside>
        ) : null}
      </div>
      <button
        type="button"
        className="terminal-window-files-toggle"
        data-testid="toggle-remote-files"
        aria-expanded={filesOpen}
        onClick={() => setFilesOpen((open) => !open)}
      >
        {filesOpen ? "隐藏远程文件" : "远程文件"}
      </button>
    </main>
  );
}
