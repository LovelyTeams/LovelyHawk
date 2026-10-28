import { afterEach, describe, expect, it, vi } from "vitest";
import { createWindowsChannelApi, createWindowsChannelOwnerApi } from "./windows-channel-api";
import { setHostInvokerForTests } from "./transport";

afterEach(() => setHostInvokerForTests(async () => { throw new Error("unconfigured"); }));
describe("channel host APIs", () => {
  it("uses distinct frozen APIs and never grants the child a general backend call", async () => {
    const call = vi.fn(async () => 1); setHostInvokerForTests(call);
    const child = createWindowsChannelApi();
    expect(Object.isFrozen(child)).toBe(true);
    expect(Object.keys(child).sort()).toEqual(["act", "copy", "dirty", "notify", "read"]);
    await child.act(3, { kind: "send", text: "hello" });
    expect(call).toHaveBeenCalledWith("windows_channel_child", { request: { kind: "act", binding: 3, action: { kind: "send", text: "hello" } } });
  });
  it("rejects extra parameters and wrong returned data before exposing it", async () => {
    const call = vi.fn(async () => ({ arbitrary: "not a view" })); setHostInvokerForTests(call);
    const child = createWindowsChannelApi();
    await expect((child.read as (...v: unknown[]) => Promise<unknown>)(0, "other-window")).rejects.toThrow();
    expect(call).not.toHaveBeenCalled();
    await expect(child.read(0)).rejects.toThrow();
    await expect(child.copy("汉".repeat(50000))).rejects.toThrow();
    expect(call).toHaveBeenCalledTimes(1);
  });
  it("only accepts a real owner token for opening and releasing", async () => {
    const call = vi.fn(async () => null); setHostInvokerForTests(call);
    const owner = createWindowsChannelOwnerApi();
    await expect(owner.open("main", "tasks")).rejects.toThrow();
    expect(call).not.toHaveBeenCalled();
    await owner.release("00000000-0000-4000-8000-000000000001");
    expect(call).toHaveBeenCalledWith("windows_channel_owner", { request: { kind: "release", owner: "00000000-0000-4000-8000-000000000001", expectedDraft: null } });
  });
});
