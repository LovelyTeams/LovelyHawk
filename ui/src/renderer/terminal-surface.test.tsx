import { readFileSync } from "node:fs";

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type { TerminalSessionApi } from "../shared/terminal-contract";
import {
  copyBoundedTerminalSelection,
  disposeTerminalRuntime,
  interceptTerminalCopyEvent,
  TerminalSurface,
} from "./TerminalSurface";

/** One tab's shell, and the window's selection copy beside it. */
const api: TerminalSessionApi & { copySelection(text: string): Promise<void> } = {
  open: vi.fn(async (columns, rows) => ({ columns, rows })),
  poll: vi.fn(async () => ({ events: [], rawBytes: 0, hasMore: false })),
  input: vi.fn(async () => ({ acceptedBytes: 1 })),
  resize: vi.fn(async (columns, rows) => ({ columns, rows })),
  search: vi.fn(async () => ({ matches: [], limited: false })),
  copySelection: vi.fn(async () => undefined),
  close: vi.fn(async () => ({ closed: true as const })),
};

describe("standalone xterm surface", () => {
  it("renders an accessible inert shell without exposing binding or scope capabilities", () => {
    const markup = renderToStaticMarkup(
      <TerminalSurface api={api} writeClipboard={api.copySelection} />,
    );

    expect(markup).toContain("SSH 终端");
    // Nothing floats over the output: search opens on Ctrl+F, and copying is
    // the terminal's own copy event.
    expect(markup).not.toContain("terminal-surface-tools");
    expect(markup).not.toContain("terminal-tool");
    expect(markup).not.toContain("复制选区");
    expect(markup).toContain('role="region"');
    expect(markup).toContain('aria-label="SSH 终端输出与输入"');
    expect(markup).toContain("支持输入法组合输入、键盘操作、文本选择与搜索");
    expect(markup).not.toContain("navigator.clipboard");
    expect(markup).not.toContain("bindingHandle");
    expect(markup).not.toContain("scopeKey");
    expect(markup).not.toContain("sessionId");
    expect(markup).not.toContain("TargetGuard");
  });

  /**
   * Removing the toggle would have taken search with it, so the shortcut has to
   * be the thing that opens it, and Escape has to give the keys back.
   */
  it("fits the grid to a box that holds nothing but the grid, once the font is in", () => {
    const source = readFileSync(new URL("./TerminalSurface.tsx", import.meta.url), "utf8");
    const css = readFileSync(new URL("./terminal-surface.css", import.meta.url), "utf8");
    const entry = readFileSync(new URL("./terminal-main.tsx", import.meta.url), "utf8");
    // Opened in the padded host, the fit counted padding as room for text.
    expect(source).toContain("terminal.open(mount);");
    expect(source).not.toContain("terminal.open(host)");
    expect(source).toContain("resizeObserver?.observe(mount);");
    expect(source).toContain('<div ref={mountRef} className="terminal-xterm-mount" />');
    expect(css).toMatch(/\.terminal-xterm-mount \{[^}]*min-width: 0;[^}]*min-height: 0;/u);
    expect(css).not.toMatch(/\.terminal-xterm-mount \{[^}]*padding/u);
    // A hidden box still scrolls to keep focus in view; an IME near the right edge shifted it.
    expect(css).toMatch(/\.terminal-xterm-host \{[^}]*overflow: clip;/u);
    // xterm's black viewport showed as a bar under the last row.
    expect(css).toMatch(/\.terminal-xterm-host \.xterm \.xterm-viewport \{\s*background-color: var\(--term-bg\);/u);
    // xterm measures its cells once: the font is loaded before the window renders.
    expect(entry).toContain("document.fonts.load('13px \"Cascadia Mono\"')");
    expect(entry.indexOf("fontReady")).toBeLessThan(entry.indexOf("createRoot(root).render("));
    expect(source).toContain("fontFamily: '\"Cascadia Mono\", monospace'");
  });

  it("keeps search reachable from the keyboard", () => {
    const source = readFileSync(new URL("./TerminalSurface.tsx", import.meta.url), "utf8");
    expect(source).toContain('event.key.toLowerCase() === "f"');
    expect(source).toContain("setSearchOpen(true);");
    expect(source).toContain('if (event.key === "Escape" && searchOpen)');
    expect(source).toContain("terminalRef.current?.focus();");
    // Opening it puts the caret in the field rather than leaving it in the shell.
    expect(source).toContain("if (searchOpen) searchInputRef.current?.focus();");
    // The bar itself is gone from the DOM while it is closed.
    expect(source).toMatch(/\{searchOpen \? \(\s+<div className="terminal-surface-tools">/u);
  });

  it("does not start a terminal or renderer bridge during SSR", () => {
    renderToStaticMarkup(
      <TerminalSurface api={api} />,
    );
    expect(api.open).not.toHaveBeenCalled();
    expect(api.poll).not.toHaveBeenCalled();
    expect(api.close).not.toHaveBeenCalled();
  });

  it("always starts backend close and disposes xterm during unmount cleanup", async () => {
    const controller = { dispose: vi.fn(async () => undefined) };
    const terminal = { dispose: vi.fn() };
    await disposeTerminalRuntime(controller, terminal);
    expect(controller.dispose).toHaveBeenCalledTimes(1);
    expect(terminal.dispose).toHaveBeenCalledTimes(1);
  });

  it("routes hostile bounded selections through the trusted writer and rejects oversized text", async () => {
    const hostile = "</textarea><script>copy-must-stay-plain()</script>";
    const writeClipboard = vi.fn(async (_text: string) => undefined);
    expect(await copyBoundedTerminalSelection({
      hasSelection: () => true,
      getSelection: () => hostile,
    }, writeClipboard)).toBe("copied");
    expect(writeClipboard).toHaveBeenCalledWith(hostile);

    writeClipboard.mockClear();
    expect(await copyBoundedTerminalSelection({
      hasSelection: () => true,
      getSelection: () => "界".repeat(43_691),
    }, writeClipboard)).toBe("too-large");
    expect(writeClipboard).not.toHaveBeenCalled();
  });

  it("intercepts browser copy only when xterm has a selection", () => {
    const event = {
      preventDefault: vi.fn(),
      stopImmediatePropagation: vi.fn(),
    };
    const copy = vi.fn();
    expect(interceptTerminalCopyEvent(event, { hasSelection: () => false }, copy)).toBe(false);
    expect(event.preventDefault).not.toHaveBeenCalled();
    expect(event.stopImmediatePropagation).not.toHaveBeenCalled();
    expect(copy).not.toHaveBeenCalled();

    expect(interceptTerminalCopyEvent(event, { hasSelection: () => true }, copy)).toBe(true);
    expect(event.preventDefault).toHaveBeenCalledTimes(1);
    expect(event.stopImmediatePropagation).toHaveBeenCalledTimes(1);
    expect(copy).toHaveBeenCalledTimes(1);
  });
});
