import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type { TerminalApi } from "../shared/terminal-contract";
import {
  copyBoundedTerminalSelection,
  disposeTerminalRuntime,
  interceptTerminalCopyEvent,
  TerminalSurface,
} from "./TerminalSurface";

const api: TerminalApi = {
  open: vi.fn(async (columns, rows) => ({ columns, rows })),
  poll: vi.fn(async () => ({ events: [], rawBytes: 0, hasMore: false })),
  input: vi.fn(async () => ({ acceptedBytes: 1 })),
  resize: vi.fn(async (columns, rows) => ({ columns, rows })),
  search: vi.fn(async () => ({ matches: [], limited: false })),
  copySelection: vi.fn(async () => undefined),
  close: vi.fn(async () => ({ closed: true as const })),
  openSftpBrowser: vi.fn(async () => ({})),
  listSftpDirectory: vi.fn(async () => ({})),
  readSftpText: vi.fn(async () => ({})),
};

describe("standalone xterm surface", () => {
  it("renders an accessible inert shell without exposing binding or scope capabilities", () => {
    const markup = renderToStaticMarkup(
      <TerminalSurface api={api} writeClipboard={api.copySelection} />,
    );

    expect(markup).toContain("SSH 终端");
    // Search lives behind a toggle so the output keeps the window.
    expect(markup).toContain('title="搜索终端输出"');
    expect(markup).toContain('aria-expanded="false"');
    expect(markup).toContain('role="region"');
    expect(markup).toContain('aria-label="SSH 终端输出与输入"');
    expect(markup).toContain("支持输入法组合输入、键盘操作、文本选择与搜索");
    expect(markup).not.toContain("navigator.clipboard");
    expect(markup).toContain("复制选区");
    expect(markup).not.toContain("bindingHandle");
    expect(markup).not.toContain("scopeKey");
    expect(markup).not.toContain("sessionId");
    expect(markup).not.toContain("TargetGuard");
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
