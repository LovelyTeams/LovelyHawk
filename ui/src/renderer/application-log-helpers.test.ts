import { describe, expect, it } from "vitest";

import {
  applicationLogEscapeIntent,
  applicationLogCopyText,
  applicationLogEntryText,
  deactivateApplicationLogOverlay,
  formatApplicationLogTimestamp,
  isolateApplicationLogBackground,
  nextApplicationLogFocus,
  restoreApplicationLogFocus,
} from "./application-log-helpers";

describe("application log renderer helpers", () => {
  it("keeps hostile values as copyable plain text", () => {
    const hostile = "</pre><img src=x onerror=steal()>";
    expect(applicationLogCopyText({ content: hostile, entryCount: 1, truncated: false })).toBe(hostile);
    expect(applicationLogEntryText({
      sequence: 1,
      timestampUnixMs: 1_777_000_000_000,
      level: "error",
      module: "lovelyres_test",
      message: hostile,
      details: [{ name: "payload", value: hostile }],
    })).toContain(hostile);
  });

  it("formats deterministic timestamps and wraps modal focus", () => {
    expect(formatApplicationLogTimestamp(0)).toBe("1970-01-01T00:00:00.000Z");
    expect(nextApplicationLogFocus(0, 3, true)).toBe(2);
    expect(nextApplicationLogFocus(2, 3, false)).toBe(0);
    expect(nextApplicationLogFocus(-1, 0, false)).toBe(-1);
  });

  it("rejects copy content above the renderer budget", () => {
    expect(() => applicationLogCopyText({
      content: "x".repeat(128 * 1_024 + 1),
      entryCount: 1,
      truncated: true,
    })).toThrow(/budget/u);
  });

  it("invalidates both async lanes when the overlay deactivates", () => {
    const alive = { current: true };
    const request = { current: 7 };
    const operation = { current: 11 };
    deactivateApplicationLogOverlay(alive, request, operation);
    expect(alive.current).toBe(false);
    expect(request.current).toBe(8);
    expect(operation.current).toBe(12);
  });

  it("restores inert/aria state, handles Escape, and restores connected focus", () => {
    const attributes = new Map<string, string>();
    const preservedAttributes = new Map<string, string>([["aria-hidden", "mixed"]]);
    const background = {
      inert: false,
      getAttribute: (name: string) => attributes.get(name) ?? null,
      setAttribute: (name: string, value: string) => attributes.set(name, value),
      removeAttribute: (name: string) => { attributes.delete(name); },
    };
    const preservedBackground = {
      inert: true,
      getAttribute: (name: string) => preservedAttributes.get(name) ?? null,
      setAttribute: (name: string, value: string) => preservedAttributes.set(name, value),
      removeAttribute: (name: string) => { preservedAttributes.delete(name); },
    };
    const restore = isolateApplicationLogBackground([background, preservedBackground]);
    expect(background.inert).toBe(true);
    expect(attributes.get("aria-hidden")).toBe("true");
    restore();
    expect(background.inert).toBe(false);
    expect(attributes.has("aria-hidden")).toBe(false);
    expect(preservedBackground.inert).toBe(true);
    expect(preservedAttributes.get("aria-hidden")).toBe("mixed");
    expect(applicationLogEscapeIntent("Escape")).toBe(true);
    expect(applicationLogEscapeIntent("Enter")).toBe(false);

    let focusOptions: FocusOptions | undefined;
    restoreApplicationLogFocus({
      isConnected: true,
      focus: (options) => { focusOptions = options; },
    });
    expect(focusOptions).toEqual({ preventScroll: true });

    let disconnectedFocused = false;
    restoreApplicationLogFocus({
      isConnected: false,
      focus: () => { disconnectedFocused = true; },
    });
    expect(disconnectedFocused).toBe(false);
  });
});
