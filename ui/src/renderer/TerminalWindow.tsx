import { useEffect, useState } from "react";

import { CommandAssistant } from "./CommandAssistant";
import { SftpBrowserPage } from "./SftpBrowserPage";
import { TerminalSurface, type TerminalSessionState } from "./TerminalSurface";
import { WindowControls } from "./WindowControls";
import "./ssh-window.css";

/** Which terminal this window is: the host's SSH shell, a container's, a pod's, or one started in a folder. */
export type TerminalWindowKind = "terminal" | "container" | "pod" | "directory";

export function terminalWindowKind(query: string | null): TerminalWindowKind {
  return query === "container" || query === "pod" || query === "directory" ? query : "terminal";
}

/**
 * The SSH window carries both halves of one connection: the shell and the
 * file browser for the same target. Main resolves which target this window
 * belongs to, so neither half holds target identity — the label below is
 * presentation text the host stamps before first paint, not something the window can act on.
 *
 * Only that window has the file browser. A container's shell beside the
 * host's files would read as the container's files, and the connection has
 * one browser, which the SSH window's editors and folder terminals rely on.
 */
export function TerminalWindow({ kind = "terminal" }: { kind?: TerminalWindowKind }) {
  const hasFiles = kind === "terminal";
  const [filesOpen, setFilesOpen] = useState(hasFiles);
  const [viewport, setViewport] = useState<{ columns: number; rows: number } | null>(null);
  const [insert, setInsert] = useState<{ token: number; text: string } | null>(null);
  const [session, setSession] = useState<TerminalSessionState>("opening");
  const elapsed = useElapsedTime(session === "connected");
  const label = readTargetLabel();
  return (
    <div className="ssh-window" data-testid="terminal-window">
      <header className="ssh-window-titlebar" data-testid="ssh-window-titlebar" data-tauri-drag-region="deep">
        <div className="ssh-window-tabs" role="tablist" aria-label="会话">
          <span className="ssh-window-tab is-active" role="tab" aria-selected="true">
            <span className={`ssh-window-tab-dot${SESSION_DOT[session]}`} aria-hidden="true" />
            {label === "" ? "SSH 会话" : label}
          </span>
          <span className="ssh-window-tab-hint">在主窗口的连接管理中切换目标</span>
        </div>
        <WindowControls />
      </header>

      <div className="ssh-window-body">
        <section className="ssh-window-shell" aria-label="终端">
          <div className="ssh-window-shell-bar">
            <span className="ssh-window-chip">{label === "" ? "未知目标" : label}</span>
            <span className="ssh-window-chip is-quiet">{KIND_CHIP[kind]}</span>
            {hasFiles ? (
              <button
                type="button"
                className="ssh-window-files-toggle"
                data-testid="toggle-remote-files"
                aria-expanded={filesOpen}
                onClick={() => setFilesOpen((open) => !open)}
              >
                {filesOpen ? "隐藏文件管理" : "文件管理"}
              </button>
            ) : (
              <span className="ssh-window-files-note" data-testid="terminal-files-note">主机文件在 SSH 终端窗口的文件管理中</span>
            )}
          </div>
          <div className="ssh-window-terminal">
            <TerminalSurface
              api={window.lovelyhawkTerminal}
              writeClipboard={window.lovelyhawkTerminal.copySelection}
              onViewport={(columns, rows) => setViewport({ columns, rows })}
              onSession={setSession}
              insert={insert}
            />
          </div>
          <CommandAssistant
            onInsert={(text) => setInsert((current) => ({ token: (current?.token ?? 0) + 1, text }))}
          />
          <footer className="ssh-window-status" data-testid="ssh-window-status">
            <span>会话时间 {elapsed ?? "—"}</span>
            <span>{viewport === null ? "网格 —" : `${viewport.rows} 行 × ${viewport.columns} 列`}</span>
            <span>UTF-8</span>
            <span>LF</span>
            <span className="ssh-window-status-end" data-testid="ssh-window-session">
              <span className={`ssh-window-tab-dot${SESSION_DOT[session]}`} aria-hidden="true" />{SESSION_TEXT[session]}
            </span>
          </footer>
        </section>

        {hasFiles && filesOpen ? (
          <aside className="ssh-window-files" aria-label="文件管理">
            <SftpBrowserPage
              connection={{ scopeKey: "ssh-window" }}
              api={window.lovelyhawkTerminal}
              active={filesOpen}
            />
          </aside>
        ) : null}
      </div>
    </div>
  );
}

const SESSION_TEXT: Record<TerminalSessionState, string> = {
  opening: "正在连接",
  connected: "已连接",
  ended: "会话已结束",
  failed: "未连接",
};

const SESSION_DOT: Record<TerminalSessionState, string> = {
  opening: " is-off",
  connected: "",
  ended: " is-off",
  failed: " is-failed",
};

const KIND_CHIP: Record<TerminalWindowKind, string> = {
  terminal: "SSH",
  container: "容器",
  pod: "Pod",
  directory: "SSH · 文件夹",
};

/** The host stamps the label before first paint; absence is not an error. */
function readTargetLabel(): string {
  try {
    return document.documentElement.dataset["targetLabel"] ?? "";
  } catch {
    return "";
  }
}

/**
 * Time the session has been live: nothing before it connects, counting while
 * it is, and held at its last value once it ends.
 */
function useElapsedTime(running: boolean): string | null {
  const [seconds, setSeconds] = useState<number | null>(null);
  useEffect(() => {
    if (!running) return undefined;
    setSeconds((value) => value ?? 0);
    const timer = window.setInterval(() => setSeconds((value) => (value ?? 0) + 1), 1_000);
    return () => window.clearInterval(timer);
  }, [running]);
  if (seconds === null) return null;
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${pad(Math.floor(seconds / 3_600))}:${pad(Math.floor(seconds / 60) % 60)}:${pad(seconds % 60)}`;
}
