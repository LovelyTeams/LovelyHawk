import { useEffect, useState } from "react";

import { CommandAssistant } from "./CommandAssistant";
import { SftpBrowserPage } from "./SftpBrowserPage";
import { TerminalSurface } from "./TerminalSurface";
import "./ssh-window.css";

/**
 * The SSH window carries both halves of one connection: the shell and the
 * read-only file browser for the same target. Main resolves which target this
 * window belongs to, so neither half holds target identity — the label below is
 * presentation text the preload stamps, not something the window can act on.
 */
export function TerminalWindow() {
  const [filesOpen, setFilesOpen] = useState(true);
  const [viewport, setViewport] = useState<{ columns: number; rows: number } | null>(null);
  const [insert, setInsert] = useState<{ token: number; text: string } | null>(null);
  const elapsed = useElapsedTime();
  const label = readTargetLabel();
  return (
    <div className="ssh-window" data-testid="terminal-window">
      <header className="ssh-window-titlebar" data-testid="ssh-window-titlebar">
        <div className="ssh-window-tabs" role="tablist" aria-label="会话">
          <span className="ssh-window-tab is-active" role="tab" aria-selected="true">
            <span className="ssh-window-tab-dot" aria-hidden="true" />
            {label === "" ? "SSH 会话" : label}
          </span>
          <span className="ssh-window-tab-hint">在主窗口的连接管理中切换目标</span>
        </div>
      </header>

      <div className="ssh-window-body">
        <section className="ssh-window-shell" aria-label="终端">
          <div className="ssh-window-shell-bar">
            <span className="ssh-window-chip">{label === "" ? "未知目标" : label}</span>
            <span className="ssh-window-chip is-quiet">SSH</span>
            <button
              type="button"
              className="ssh-window-files-toggle"
              data-testid="toggle-remote-files"
              aria-expanded={filesOpen}
              onClick={() => setFilesOpen((open) => !open)}
            >
              {filesOpen ? "隐藏文件管理" : "文件管理"}
            </button>
          </div>
          <div className="ssh-window-terminal">
            <TerminalSurface
              api={window.lovelyresTerminal}
              writeClipboard={window.lovelyresTerminal.copySelection}
              onViewport={(columns, rows) => setViewport({ columns, rows })}
              insert={insert}
            />
          </div>
          <CommandAssistant
            onInsert={(text) => setInsert((current) => ({ token: (current?.token ?? 0) + 1, text }))}
          />
          <footer className="ssh-window-status" data-testid="ssh-window-status">
            <span>会话时间 {elapsed}</span>
            <span>{viewport === null ? "网格 —" : `${viewport.rows} 行 × ${viewport.columns} 列`}</span>
            <span>UTF-8</span>
            <span>LF</span>
            <span className="ssh-window-status-end">
              <span className="ssh-window-tab-dot" aria-hidden="true" />已连接
            </span>
          </footer>
        </section>

        {filesOpen ? (
          <aside className="ssh-window-files" aria-label="文件管理">
            <SftpBrowserPage
              connection={{ scopeKey: "ssh-window" }}
              api={window.lovelyresTerminal}
              active={filesOpen}
            />
          </aside>
        ) : null}
      </div>
    </div>
  );
}

/** The preload stamps the label before first paint; absence is not an error. */
function readTargetLabel(): string {
  try {
    return document.documentElement.dataset["targetLabel"] ?? "";
  } catch {
    return "";
  }
}

function useElapsedTime(): string {
  const [seconds, setSeconds] = useState(0);
  useEffect(() => {
    const timer = window.setInterval(() => setSeconds((value) => value + 1), 1_000);
    return () => window.clearInterval(timer);
  }, []);
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${pad(Math.floor(seconds / 3_600))}:${pad(Math.floor(seconds / 60) % 60)}:${pad(seconds % 60)}`;
}
