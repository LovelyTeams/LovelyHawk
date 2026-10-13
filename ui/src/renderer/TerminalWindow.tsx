import { useEffect, useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent } from "react";

import { TERMINAL_LIMITS, type TerminalApi } from "../shared/terminal-contract";
import { CommandAssistant } from "./CommandAssistant";
import { SftpBrowserPage } from "./SftpBrowserPage";
import { TERMINAL_ERROR_MESSAGES } from "./terminal-controller";
import { terminalTabSession, type TerminalTabSession } from "./terminal-tabs";
import { TerminalSurface, type TerminalSessionState } from "./TerminalSurface";
import { WindowControls } from "./WindowControls";
import "./ssh-window.css";

/** Which terminal this window is: the host's SSH shell, a container's, a pod's, or one started in a folder. */
export type TerminalWindowKind = "terminal" | "container" | "pod" | "directory";

export function terminalWindowKind(query: string | null): TerminalWindowKind {
  return query === "container" || query === "pod" || query === "directory" ? query : "terminal";
}

/** One shell in the window, as the page tracks it. */
interface ShellTab {
  /** The page's own key; the host's tab number arrives with the session. */
  key: number;
  session: TerminalTabSession;
  state: TerminalSessionState;
  viewport: { columns: number; rows: number } | null;
  insert: { token: number; text: string } | null;
  connectedAt: number | null;
  endedAt: number | null;
}

function newTab(api: TerminalApi, key: number): ShellTab {
  return {
    key,
    session: terminalTabSession(api, key === 1),
    state: "opening",
    viewport: null,
    insert: null,
    connectedAt: null,
    endedAt: null,
  };
}

/**
 * The SSH window carries both halves of one connection: the shell and the
 * file browser for the same target. Main resolves which target this window
 * belongs to, so neither half holds target identity — the label below is
 * presentation text the host stamps before first paint, not something the window can act on.
 *
 * Only that window has the file browser, and only it has tabs: more shells on
 * the same host, each its own session. A container's, a pod's or a folder's
 * window is one shell for one thing. A container's shell beside the host's
 * files would read as the container's files, and the connection has one
 * browser, which the SSH window's editors and folder terminals rely on.
 */
export function TerminalWindow({ kind = "terminal" }: { kind?: TerminalWindowKind }) {
  const api = window.lovelyhawkTerminal;
  const hasFiles = kind === "terminal";
  const hasTabs = kind === "terminal";
  const [filesOpen, setFilesOpen] = useState(hasFiles);
  const [tabs, setTabs] = useState<ShellTab[]>(() => [newTab(api, 1)]);
  const [activeKey, setActiveKey] = useState(1);
  const nextKey = useRef(2);
  const closingWindow = useRef(false);
  const tabsRef = useRef(tabs);
  tabsRef.current = tabs;
  const label = readTargetLabel();
  const active = tabs.find((tab) => tab.key === activeKey) ?? tabs[0];
  const elapsed = useElapsedTime(active?.connectedAt ?? null, active?.endedAt ?? null);
  const full = tabs.length >= TERMINAL_LIMITS.maximumTabs;

  function update(key: number, change: (tab: ShellTab) => ShellTab): void {
    setTabs((current) => current.map((tab) => (tab.key === key ? change(tab) : tab)));
  }

  function addTab(): void {
    if (!hasTabs || tabsRef.current.length >= TERMINAL_LIMITS.maximumTabs) return;
    const key = nextKey.current;
    nextKey.current += 1;
    setTabs((current) => [...current, newTab(api, key)]);
    setActiveKey(key);
  }

  /**
   * Closes one tab's shell. The last tab closes the window, as closing the
   * only shell always did; the others keep running.
   */
  function closeTab(key: number): void {
    const current = tabsRef.current;
    const index = current.findIndex((tab) => tab.key === key);
    if (index === -1) return;
    if (current.length === 1) {
      if (closingWindow.current) return;
      closingWindow.current = true;
      void api.close().catch(() => {
        closingWindow.current = false;
      });
      return;
    }
    const remaining = current.filter((tab) => tab.key !== key);
    setTabs(remaining);
    if (key === activeKey) {
      setActiveKey((remaining[index] ?? remaining[index - 1] ?? remaining[0]!).key);
    }
  }

  function onSession(key: number, state: TerminalSessionState): void {
    const now = Date.now();
    update(key, (tab) => ({
      ...tab,
      state,
      connectedAt: state === "connected" ? tab.connectedAt ?? now : tab.connectedAt,
      endedAt: state === "ended" && tab.connectedAt !== null ? tab.endedAt ?? now : tab.endedAt,
    }));
  }

  function selectByOffset(offset: number): void {
    const current = tabsRef.current;
    if (current.length < 2) return;
    const index = current.findIndex((tab) => tab.key === activeKey);
    const next = current[(index + offset + current.length) % current.length];
    if (next !== undefined) setActiveKey(next.key);
  }

  // Ctrl+Shift+T opens a tab and Ctrl+Tab / Ctrl+Shift+Tab move between them:
  // none of them reaches a shell anyway. Closing has no shortcut — it ends a
  // session, and that stays a deliberate click.
  useEffect(() => {
    if (!hasTabs) return undefined;
    function onKeyDown(event: KeyboardEvent): void {
      if (!event.ctrlKey || event.altKey || event.metaKey) return;
      if (event.key === "Tab") {
        event.preventDefault();
        selectByOffset(event.shiftKey ? -1 : 1);
      } else if (event.shiftKey && event.key.toLowerCase() === "t") {
        event.preventDefault();
        addTab();
      }
    }
    window.addEventListener("keydown", onKeyDown, true);
    return () => window.removeEventListener("keydown", onKeyDown, true);
  });

  function onTabKeyDown(event: ReactKeyboardEvent<HTMLButtonElement>): void {
    if (event.key !== "ArrowRight" && event.key !== "ArrowLeft") return;
    event.preventDefault();
    selectByOffset(event.key === "ArrowRight" ? 1 : -1);
  }

  const tabStripRef = useRef<HTMLDivElement>(null);
  // Arrow keys move the selection; the focus follows it, as in any tab list.
  useEffect(() => {
    const strip = tabStripRef.current;
    if (strip === null || !strip.contains(document.activeElement)) return;
    strip.querySelector<HTMLButtonElement>(`[data-tab-key="${activeKey}"]`)?.focus();
  }, [activeKey]);

  const viewport = active?.viewport ?? null;
  const session = active?.state ?? "opening";
  const tabTitles = useMemo(() => tabs.map((tab, index) => (index === 0 && label !== "" ? label : `终端 ${index + 1}`)), [tabs, label]);

  return (
    <div className="ssh-window" data-testid="terminal-window">
      <header className="ssh-window-titlebar" data-testid="ssh-window-titlebar" data-tauri-drag-region="deep">
        <div className="ssh-window-tabs" role="tablist" aria-label="会话" ref={tabStripRef}>
          {tabs.map((tab, index) => {
            const selected = tab.key === active?.key;
            return (
              <span key={tab.key} className={`ssh-window-tab${selected ? " is-active" : ""}`}>
                <button
                  type="button"
                  role="tab"
                  id={`ssh-window-tab-${tab.key}`}
                  className="ssh-window-tab-select"
                  data-tab-key={tab.key}
                  data-testid="ssh-window-tab"
                  aria-selected={selected}
                  aria-controls={`ssh-window-panel-${tab.key}`}
                  tabIndex={selected ? 0 : -1}
                  title={tabTitles[index]}
                  onClick={() => setActiveKey(tab.key)}
                  onKeyDown={onTabKeyDown}
                >
                  <span className={`ssh-window-tab-dot${SESSION_DOT[tab.state]}`} aria-hidden="true" />
                  <span className="ssh-window-tab-name">{tabTitles[index]}</span>
                </button>
                {tabs.length > 1 ? (
                  <button
                    type="button"
                    className="ssh-window-tab-close"
                    data-testid="ssh-window-tab-close"
                    aria-label={`关闭${tabTitles[index]}`}
                    title="关闭这个标签页（结束它的会话）"
                    onClick={() => closeTab(tab.key)}
                  >
                    <CloseGlyph />
                  </button>
                ) : null}
              </span>
            );
          })}
          {hasTabs ? (
            <button
              type="button"
              className="ssh-window-tab-add"
              data-testid="ssh-window-tab-add"
              aria-label="新建终端标签页"
              title={full ? `一个窗口最多 ${TERMINAL_LIMITS.maximumTabs} 个终端标签页` : "新建终端标签页（Ctrl+Shift+T）"}
              disabled={full}
              onClick={addTab}
            >
              <PlusGlyph />
            </button>
          ) : null}
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
            {tabs.map((tab) => {
              const selected = tab.key === active?.key;
              return (
                <div
                  key={tab.key}
                  id={`ssh-window-panel-${tab.key}`}
                  className={`ssh-window-terminal-panel${selected ? "" : " is-behind"}`}
                  role="tabpanel"
                  aria-labelledby={`ssh-window-tab-${tab.key}`}
                  aria-hidden={selected ? undefined : true}
                  inert={selected ? undefined : true}
                >
                  <TerminalSurface
                    api={tab.session}
                    writeClipboard={api.copySelection}
                    active={selected}
                    onViewport={(columns, rows) => update(tab.key, (current) => ({ ...current, viewport: { columns, rows } }))}
                    onSession={(state) => onSession(tab.key, state)}
                    onExit={() => closeTab(tab.key)}
                    insert={tab.insert}
                    {...(kind === "directory" ? { openFailure: TERMINAL_ERROR_MESSAGES.openFolder } : {})}
                  />
                </div>
              );
            })}
          </div>
          <CommandAssistant
            onInsert={(text) => {
              if (active === undefined) return;
              update(active.key, (tab) => ({ ...tab, insert: { token: (tab.insert?.token ?? 0) + 1, text } }));
            }}
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
              api={api}
              active={filesOpen}
            />
          </aside>
        ) : null}
      </div>
    </div>
  );
}

function PlusGlyph() {
  return (
    <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true" focusable="false">
      <path d="M6 1.5v9M1.5 6h9" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  );
}

function CloseGlyph() {
  return (
    <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true" focusable="false">
      <path d="m2 2 6 6M8 2 2 8" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
    </svg>
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
 * Time the shown tab's session has been live: nothing before it connects,
 * counting while it is, and held at its last value once it ends.
 */
function useElapsedTime(connectedAt: number | null, endedAt: number | null): string | null {
  const [now, setNow] = useState(() => Date.now());
  const running = connectedAt !== null && endedAt === null;
  useEffect(() => {
    if (!running) return undefined;
    setNow(Date.now());
    const timer = window.setInterval(() => setNow(Date.now()), 1_000);
    return () => window.clearInterval(timer);
  }, [running]);
  if (connectedAt === null) return null;
  const seconds = Math.max(0, Math.floor(((endedAt ?? now) - connectedAt) / 1_000));
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${pad(Math.floor(seconds / 3_600))}:${pad(Math.floor(seconds / 60) % 60)}:${pad(seconds % 60)}`;
}
