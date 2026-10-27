import { describe, expect, it } from "vitest";
import { isChannelAction, isChannelRead, isChannelView, type WindowsChannelView } from "./windows-channel-contract";
import { isWindowsFileId } from "./windows-incident-contract";

const view: WindowsChannelView = { hostname: "target", connected: false, busy: null, batch: null, history: [], registered: false, messagesSent: 0, messagesReceived: 0, logs: [], files: [], savedFiles: [], canSave: true, output: null, suggestion: null };
describe("the channel window boundary", () => {
  it("accepts a bounded view without exposing paths or a remote target selector", () => {
    expect(isChannelView(view)).toBe(true);
    expect(isChannelView({ ...view, sessionId: "injected" })).toBe(false);
    expect(isChannelView({ ...view, registration: { localServerCommand: "C:\\private" } })).toBe(false);
    expect(isChannelView({ ...view, batch: { done: 3, total: 2, stopping: false } })).toBe(false);
  });
  it("rejects extra target identity, arbitrary modules, invalid text and receipt IDs", () => {
    expect(isChannelAction({ kind: "run", command: "whoami" })).toBe(true);
    expect(isChannelAction({ kind: "run", command: "whoami", sessionId: "other" })).toBe(false);
    expect(isChannelAction({ kind: "run", command: "a\0b" })).toBe(false);
    expect(isChannelAction({ kind: "run", command: "测".repeat(6000) })).toBe(false);
    expect(isChannelAction({ kind: "collect", key: "delete-file" })).toBe(false);
    expect(isChannelAction({ kind: "save", fileId: "../../other" })).toBe(false);
    expect(isWindowsFileId("00000000-0000-4000-8000-000000000001")).toBe(true);
  });
  it("keeps large command output intact within its byte limit and refuses oversized lists", () => {
    const output = { command: "query", output: "汉".repeat(400_000), time: "2026-10-27" };
    expect(isChannelView({ ...view, output })).toBe(true);
    expect(isChannelView({ ...view, output: { ...output, output: "a".repeat(16 * 1024 * 1024 + 1) } })).toBe(false);
    expect(isChannelView({ ...view, logs: Array(257).fill({ timestamp: "now", direction: "in", kind: "log", summary: "line" }) })).toBe(false);
  });
  it("validates the response and permits unchanged view polls", () => {
    const read = { revision: 3, binding: 2, theme: "light", tab: "files", openRequest: 1, view: null, completion: { id: 1, ok: false } };
    // Use an existing theme from the shipped contract, not a display string.
    expect(isChannelRead({ ...read, theme: "unknown" })).toBe(false);
    expect(isChannelRead({ ...read, theme: "light", view })).toBe(true);
    expect(isChannelRead({ ...read, binding: -1 })).toBe(false);
  });
});
