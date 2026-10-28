import { describe, expect, it, vi } from "vitest";

import type { TerminalApi } from "../shared/terminal-contract";
import { terminalTabSession } from "./terminal-tabs";

function windowApi(tab: string) {
  return {
    open: vi.fn(async (columns: number, rows: number) => ({ tab, columns, rows })),
    openTab: vi.fn(async (columns: number, rows: number) => ({ tab, columns, rows })),
    poll: vi.fn(async () => ({ events: [], rawBytes: 0, hasMore: false })),
    input: vi.fn(async () => ({ acceptedBytes: 1 })),
    resize: vi.fn(async (_tab: string, columns: number, rows: number) => ({ columns, rows })),
    search: vi.fn(async () => ({ matches: [], limited: false })),
    closeTab: vi.fn(async () => ({ closed: true as const })),
    close: vi.fn(async () => ({ closed: true as const })),
  };
}

describe("a terminal tab over the window's API", () => {
  it("opens the window's shell for the first tab and a new tab for the rest", async () => {
    const first = windowApi("1");
    // The view's controller checks the answer has exactly these two keys.
    await expect(terminalTabSession(first as unknown as TerminalApi, true).open(80, 24))
      .resolves.toEqual({ columns: 80, rows: 24 });
    expect(first.open).toHaveBeenCalledWith(80, 24);
    expect(first.openTab).not.toHaveBeenCalled();

    const later = windowApi("3");
    await terminalTabSession(later as unknown as TerminalApi, false).open(100, 30);
    expect(later.openTab).toHaveBeenCalledWith(100, 30);
    expect(later.open).not.toHaveBeenCalled();
  });

  it("names its own tab on every call and closes only that tab", async () => {
    const api = windowApi("3");
    const session = terminalTabSession(api as unknown as TerminalApi, false);
    await session.open(80, 24);
    expect(session.tab).toBe("3");
    await session.poll(4, 1024);
    await session.input("YQ==");
    await session.resize(90, 30);
    await session.search("root", true, false, 8);
    await session.close();
    expect(api.poll).toHaveBeenCalledWith("3", 4, 1024);
    expect(api.input).toHaveBeenCalledWith("3", "YQ==");
    expect(api.resize).toHaveBeenCalledWith("3", 90, 30);
    expect(api.search).toHaveBeenCalledWith("3", "root", true, false, 8);
    expect(api.closeTab).toHaveBeenCalledWith("3");
    // Closing a tab is never closing the window.
    expect(api.close).not.toHaveBeenCalled();
  });

  it("asks nothing of the host before it opened, and opens once", async () => {
    const api = windowApi("1");
    const session = terminalTabSession(api as unknown as TerminalApi, true);
    expect(() => session.poll(1, 1)).toThrow("还没有打开");
    expect(() => session.input("YQ==")).toThrow("还没有打开");
    await expect(session.close()).resolves.toEqual({ closed: true });
    expect(api.closeTab).not.toHaveBeenCalled();
    expect(api.close).not.toHaveBeenCalled();

    await session.open(80, 24);
    await expect(session.open(80, 24)).rejects.toThrow("Invalid terminal open request.");
    expect(api.open).toHaveBeenCalledTimes(1);
  });
});
