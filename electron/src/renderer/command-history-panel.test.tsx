import { readFileSync } from "node:fs";

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import {
  commandHistoryMutationSummary,
  type CommandHistoryApi,
} from "../shared/command-history-contract";
import { CommandHistoryPanel } from "./CommandHistoryPanel";
import {
  commandHistoryCopyText,
  commandHistoryInitialFocus,
  nextCommandHistoryFocus,
  replayBlockMessage,
} from "./command-history-helpers";

const api: CommandHistoryApi = {
  listCommandHistory: async () => ({ total: 0, offset: 0, hasMore: false, items: [] }),
  getCommandHistory: async () => ({
    id: "command-1", title: "test", command: "uname -a", output: "Linux",
    timestamp: 1, exitCode: 0, status: "succeeded", risk: "read-only", source: "test",
  }),
  planCommandReplay: async () => ({ status: "blocked", reason: "not-found" }),
  planCommandHistoryRemove: async () => ({
    handle: "mutation-1", kind: "remove", affectedRecords: 1,
    summary: commandHistoryMutationSummary("remove", 1), expiresInSeconds: 300,
  }),
  planCommandHistoryClear: async () => ({
    handle: "mutation-1", kind: "clear", affectedRecords: 1,
    summary: commandHistoryMutationSummary("clear", 1), expiresInSeconds: 300,
  }),
  confirmCommandHistoryMutation: async () => ({ kind: "remove", affectedRecords: 1, verified: true }),
  cancelCommandHistoryMutation: async () => ({ cancelled: true }),
};

describe("standalone command history panel", () => {
  it("uses global theme tokens with no color literals", () => {
    const css = readFileSync(new URL("./command-history.css", import.meta.url), "utf8");
    expect((css.match(/var\(--[a-z0-9-]+\)/gu) ?? []).length).toBeGreaterThan(10);
    expect(css).not.toMatch(/#[0-9a-f]{3,8}|rgba?\(|hsla?\(/iu);
  });

  it("SSR renders a connection prompt without fake execution controls or internal handles", () => {
    const html = renderToStaticMarkup(<CommandHistoryPanel activeTarget={null} api={api} />);
    expect(html).toContain("请先在连接管理器中建立 SSH 连接");
    expect(html).not.toContain("shell.execute");
    expect(html).not.toContain("sessionId");
    expect(html).not.toContain("TargetGuard");
    expect(html).not.toContain("bindingHandle");
  });

  it("SSR exposes only safe target summary and labels replay as intent generation", () => {
    const html = renderToStaticMarkup(<CommandHistoryPanel activeTarget={{
      bindingHandle: "opaque-binding",
      target: {
        connectionId: "server-1",
        host: "server.example",
        port: 22,
        username: "ops",
        timestamp: "now",
      },
    }} api={api} />);
    expect(html).toContain("ops@server.example:22");
    expect(html).not.toContain("opaque-binding");
    expect(html).not.toContain("执行命令");
  });

  it("copy preserves hostile plain text and modal focus wraps", () => {
    const hostile = "</pre><script>steal()</script>";
    expect(commandHistoryCopyText({
      id: "command-1", title: "test", command: hostile, output: hostile,
      timestamp: 1, exitCode: 7, status: "failed", risk: "mutating", source: "test",
    }, "output")).toBe(hostile);
    expect(nextCommandHistoryFocus(0, 2, true)).toBe(1);
    expect(nextCommandHistoryFocus(1, 2, false)).toBe(0);
    expect(replayBlockMessage("mutating-command")).toContain("禁止重放");
  });

  it("falls back to the dialog itself for disconnected initial focus", () => {
    const panel = {} as HTMLElement;
    const search = {} as HTMLElement;
    expect(commandHistoryInitialFocus(null, panel)).toBe(panel);
    expect(commandHistoryInitialFocus(search, panel)).toBe(search);
  });
});
