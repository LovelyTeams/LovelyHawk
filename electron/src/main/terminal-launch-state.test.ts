import { describe, expect, it } from "vitest";

import { TerminalBindingLaunchState } from "./terminal-launch-state";

const target = {
  connectionId: "connection",
  host: "host.invalid",
  port: 22,
  username: "operator",
  timestamp: "2026-08-24T00:00:00Z",
};

describe("terminal main-owned binding launch state", () => {
  it("accepts only the latest connect success and never revives a disconnected binding", () => {
    const state = new TerminalBindingLaunchState();
    state.startConnect("attempt-old");
    expect(state.observe("attempt-old", {
      stage: "connected",
      bindingHandle: "binding-old",
      target,
    })).toEqual({
      kind: "accepted",
      bindingHandle: "binding-old",
      previousBindingHandle: null,
    });
    expect(state.currentBindingHandle()).toBe("binding-old");

    state.startConnect("attempt-new");
    expect(state.observe("attempt-new", {
      stage: "connected",
      bindingHandle: "binding-new",
      target,
    })).toEqual({
      kind: "accepted",
      bindingHandle: "binding-new",
      previousBindingHandle: "binding-old",
    });
    expect(state.currentBindingHandle()).toBe("binding-new");
    expect(state.observe("attempt-old", {
      stage: "connected",
      bindingHandle: "binding-old",
      target,
    })).toEqual({ kind: "stale" });
    expect(state.currentBindingHandle()).toBe("binding-new");

    expect(state.disconnect("binding-new")).toBe(true);
    expect(state.currentBindingHandle()).toBeNull();
    expect(state.observe("attempt-new", {
      stage: "connected",
      bindingHandle: "binding-new",
      target,
    })).toEqual({ kind: "stale" });
    expect(state.currentBindingHandle()).toBeNull();
  });

  it("does not clear an active binding for an unrelated disconnect or failed replacement", () => {
    const state = new TerminalBindingLaunchState();
    state.startConnect("attempt-a");
    state.observe("attempt-a", { stage: "connected", bindingHandle: "binding-a", target });
    state.startConnect("attempt-b");
    state.observe("attempt-b", {
      stage: "failed",
      error: { code: "ssh-attempt-failed", message: "fixed" },
    });
    expect(state.disconnect("binding-b")).toBe(false);
    expect(state.currentBindingHandle()).toBe("binding-a");
  });
});
