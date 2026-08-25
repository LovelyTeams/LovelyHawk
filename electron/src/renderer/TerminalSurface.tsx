import { FitAddon } from "@xterm/addon-fit";
import { SearchAddon } from "@xterm/addon-search";
import { Terminal } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";
import { useEffect, useRef, useState, type FormEvent } from "react";

import {
  clampTerminalSize,
  isTerminalSearchRequest,
  TERMINAL_LIMITS,
  type TerminalApi,
} from "../shared/terminal-contract";
import { TerminalController } from "./terminal-controller";
import { terminalXtermTheme } from "./terminal-theme";
import "./terminal-surface.css";

interface TerminalSurfaceProps {
  api: TerminalApi;
  initialColumns?: number;
  initialRows?: number;
  writeClipboard?: (text: string) => Promise<void>;
}

interface TerminalSelectionSource {
  hasSelection(): boolean;
  getSelection(): string;
}

export type TerminalSelectionCopyOutcome =
  | "copied"
  | "unavailable"
  | "too-large"
  | "failed";

export async function copyBoundedTerminalSelection(
  terminal: TerminalSelectionSource,
  writeClipboard: ((text: string) => Promise<void>) | undefined,
): Promise<TerminalSelectionCopyOutcome> {
  if (writeClipboard === undefined || !terminal.hasSelection()) return "unavailable";
  const selected = terminal.getSelection();
  if (selected.length === 0) return "unavailable";
  if (new TextEncoder().encode(selected).byteLength > TERMINAL_LIMITS.maximumSelectionCopyBytes) {
    return "too-large";
  }
  try {
    await writeClipboard(selected);
    return "copied";
  } catch {
    return "failed";
  }
}

export function interceptTerminalCopyEvent(
  event: Pick<ClipboardEvent, "preventDefault" | "stopImmediatePropagation">,
  terminal: Pick<TerminalSelectionSource, "hasSelection">,
  copySelection: () => void,
): boolean {
  if (!terminal.hasSelection()) return false;
  event.preventDefault();
  event.stopImmediatePropagation();
  copySelection();
  return true;
}

const RESIZE_DEBOUNCE_MS = 80;

export function disposeTerminalRuntime(
  controller: Pick<TerminalController, "dispose">,
  terminal: Pick<Terminal, "dispose">,
): Promise<void> {
  const closing = controller.dispose();
  terminal.dispose();
  return closing;
}

export function TerminalSurface({
  api,
  initialColumns = 80,
  initialRows = 24,
  writeClipboard,
}: TerminalSurfaceProps) {
  const hostRef = useRef<HTMLDivElement>(null);
  const terminalRef = useRef<Terminal | null>(null);
  const controllerRef = useRef<TerminalController | null>(null);
  const searchAddonRef = useRef<SearchAddon | null>(null);
  const searchGenerationRef = useRef(0);
  const [status, setStatus] = useState("正在打开绑定终端…");
  const [error, setError] = useState<string | null>(null);
  const [title, setTitle] = useState("远程终端");
  const [query, setQuery] = useState("");
  const [caseSensitive, setCaseSensitive] = useState(false);
  const [regex, setRegex] = useState(false);
  const [hasSelection, setHasSelection] = useState(false);

  useEffect(() => {
    const host = hostRef.current;
    if (host === null) return;
    let active = true;
    let resizeTimer: number | null = null;
    let resizeFrame: number | null = null;
    let inputDisposable: { dispose(): void } | null = null;

    const terminal = new Terminal({
      allowProposedApi: false,
      allowTransparency: false,
      convertEol: false,
      cursorBlink: true,
      cursorStyle: "block",
      fontFamily: '"Cascadia Mono", monospace',
      fontSize: 13,
      letterSpacing: 0,
      lineHeight: 1.15,
      linkHandler: {
        activate: () => undefined,
        allowNonHttpProtocols: false,
      },
      logLevel: "off",
      rightClickSelectsWord: true,
      screenReaderMode: true,
      scrollback: TERMINAL_LIMITS.maximumScrollbackLines,
      theme: terminalXtermTheme((name) =>
        window.getComputedStyle(document.documentElement).getPropertyValue(name)),
    });
    const fitAddon = new FitAddon();
    const searchAddon = new SearchAddon({
      highlightLimit: TERMINAL_LIMITS.maximumSearchResults,
    });
    terminal.loadAddon(fitAddon);
    terminal.loadAddon(searchAddon);
    terminal.open(host);
    terminalRef.current = terminal;
    searchAddonRef.current = searchAddon;

    const selectionDisposable = terminal.onSelectionChange(() => {
      if (active) setHasSelection(terminal.hasSelection());
    });
    const copyListener = (event: ClipboardEvent) => {
      interceptTerminalCopyEvent(event, terminal, () => {
        void copySelectionFrom(terminal);
      });
    };
    host.addEventListener("copy", copyListener, true);
    const controller = new TerminalController(api, {
      write: (bytes) => new Promise<void>((resolve) => terminal.write(bytes, resolve)),
      titleChanged: (nextTitle) => {
        if (active) setTitle(nextTitle);
      },
      bell: () => {
        if (active) setStatus("终端请求注意。");
      },
      exited: (exitCode) => {
        if (active) setStatus(exitCode === null ? "终端进程已退出。" : `终端进程已退出（${exitCode}）。`);
      },
      closed: () => {
        if (active) setStatus("终端会话已关闭。");
      },
    }, {
      isScopeCurrent: () => active,
      onError: (message) => {
        if (active) setError(message);
      },
    });
    controllerRef.current = controller;

    function fitAndResize() {
      if (!active) return;
      const proposed = fitAddon.proposeDimensions();
      const size = clampTerminalSize(
        proposed?.cols ?? terminal.cols,
        proposed?.rows ?? terminal.rows,
      );
      if (terminal.cols !== size.columns || terminal.rows !== size.rows) {
        terminal.resize(size.columns, size.rows);
      }
      controller.resize(size.columns, size.rows);
    }

    function scheduleResize() {
      if (resizeTimer !== null) window.clearTimeout(resizeTimer);
      resizeTimer = window.setTimeout(() => {
        resizeTimer = null;
        fitAndResize();
      }, RESIZE_DEBOUNCE_MS);
    }

    const resizeObserver = typeof ResizeObserver === "undefined"
      ? null
      : new ResizeObserver(scheduleResize);
    resizeObserver?.observe(host);
    if (resizeObserver === null) window.addEventListener("resize", scheduleResize);

    const initialSize = clampTerminalSize(initialColumns, initialRows);
    terminal.resize(initialSize.columns, initialSize.rows);
    void controller.open(initialSize.columns, initialSize.rows).then((opened) => {
      if (!active || !opened) return;
      setStatus("终端已连接。");
      inputDisposable = terminal.onData((data) => {
        controller.enqueueText(data);
      });
      terminal.focus();
      resizeFrame = window.requestAnimationFrame(scheduleResize);
    });

    return () => {
      active = false;
      searchGenerationRef.current += 1;
      if (resizeTimer !== null) window.clearTimeout(resizeTimer);
      if (resizeFrame !== null) window.cancelAnimationFrame(resizeFrame);
      resizeObserver?.disconnect();
      if (resizeObserver === null) window.removeEventListener("resize", scheduleResize);
      inputDisposable?.dispose();
      selectionDisposable.dispose();
      host.removeEventListener("copy", copyListener, true);
      controllerRef.current = null;
      searchAddonRef.current = null;
      void disposeTerminalRuntime(controller, terminal);
      terminalRef.current = null;
    };
  }, [api, initialColumns, initialRows, writeClipboard]);

  async function search(direction: "next" | "previous") {
    const controller = controllerRef.current;
    const searchAddon = searchAddonRef.current;
    if (
      controller === null ||
      searchAddon === null ||
      !isTerminalSearchRequest(query, TERMINAL_LIMITS.maximumSearchResults)
    ) {
      setStatus("请输入不含控制字符的搜索内容。");
      return;
    }
    const generation = searchGenerationRef.current + 1;
    searchGenerationRef.current = generation;
    const options = { caseSensitive, regex };
    if (direction === "next") searchAddon.findNext(query, options);
    else searchAddon.findPrevious(query, options);
    const result = await controller.search(
      query,
      caseSensitive,
      regex,
      TERMINAL_LIMITS.maximumSearchResults,
    );
    if (searchGenerationRef.current !== generation || result === null) return;
    setStatus(`找到 ${result.matches.length} 个匹配。`);
  }

  function submitSearch(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void search("next");
  }

  async function copySelectionFrom(terminal: TerminalSelectionSource) {
    const outcome = await copyBoundedTerminalSelection(terminal, writeClipboard);
    if (outcome === "copied") setStatus("已复制选中的纯文本。");
    else if (outcome === "too-large") setStatus("选区超过纯文本复制上限。");
    else if (outcome === "failed") setStatus("复制终端选区失败。");
  }

  async function copySelection() {
    const terminal = terminalRef.current;
    if (terminal !== null) await copySelectionFrom(terminal);
  }

  return (
    <section className="terminal-surface" aria-labelledby="terminal-surface-title">
      <header className="terminal-surface-header">
        <div>
          <p>SSH 终端</p>
          <h2 id="terminal-surface-title">{title}</h2>
        </div>
        <button
          type="button"
          disabled={!hasSelection || writeClipboard === undefined}
          onClick={() => void copySelection()}
        >
          复制选区
        </button>
      </header>

      <form className="terminal-search" role="search" onSubmit={submitSearch}>
        <label>
          <span className="terminal-sr-only">搜索终端输出</span>
          <input
            type="search"
            value={query}
            maxLength={TERMINAL_LIMITS.maximumSearchQueryBytes}
            placeholder="搜索终端输出"
            onChange={(event) => setQuery(event.target.value)}
          />
        </label>
        <label><input type="checkbox" checked={caseSensitive} onChange={(event) => setCaseSensitive(event.target.checked)} />区分大小写</label>
        <label><input type="checkbox" checked={regex} onChange={(event) => setRegex(event.target.checked)} />正则</label>
        <button type="button" onClick={() => void search("previous")}>上一个</button>
        <button type="submit">下一个</button>
      </form>

      <div
        ref={hostRef}
        className="terminal-xterm-host"
        role="region"
        aria-label="SSH 终端输出与输入"
        onMouseDown={() => terminalRef.current?.focus()}
      />
      <p className="terminal-ime-note">支持输入法组合输入、键盘操作、文本选择与搜索。</p>
      <p className="terminal-status" role="status" aria-live="polite">{status}</p>
      {error === null ? null : <p className="terminal-error" role="alert">{error}</p>}
    </section>
  );
}
