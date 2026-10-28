import { describe, expect, it } from "vitest";

import { vi } from "vitest";

import { formatNoteTimestamp, reconcileNoteSelection, retryTimedOut } from "./notes-helpers";

describe("reconcileNoteSelection", () => {
  const items = [{ id: "first" }, { id: "second" }];

  it("keeps a selection that is still visible", () => {
    expect(reconcileNoteSelection(items, "second")).toBe("second");
  });

  it("moves a missing selection to the first result", () => {
    expect(reconcileNoteSelection(items, "missing")).toBe("first");
  });

  it("clears the selection when a search has no results", () => {
    expect(reconcileNoteSelection([], "missing")).toBeNull();
  });
});

describe("retryTimedOut", () => {
  it("replays one timed-out mutation with the caller-owned idempotency key", async () => {
    const operation = vi
      .fn<() => Promise<string>>()
      .mockRejectedValueOnce(new Error("The backend request timed out."))
      .mockResolvedValueOnce("persisted-once");
    await expect(retryTimedOut(operation)).resolves.toBe("persisted-once");
    expect(operation).toHaveBeenCalledTimes(2);
  });

  it("does not retry a deterministic validation failure", async () => {
    const operation = vi.fn<() => Promise<string>>().mockRejectedValue(new Error("conflict"));
    await expect(retryTimedOut(operation)).rejects.toThrow("conflict");
    expect(operation).toHaveBeenCalledOnce();
  });
});

describe("formatNoteTimestamp", () => {
  it("rejects invalid timestamps without throwing", () => {
    expect(formatNoteTimestamp(Number.NaN)).toBe("未知时间");
    expect(formatNoteTimestamp(-1)).toBe("未知时间");
    expect(formatNoteTimestamp(Number.MAX_SAFE_INTEGER)).toBe("未知时间");
  });

  it("formats a valid timestamp with date and time", () => {
    const formatted = formatNoteTimestamp(new Date(2026, 7, 24, 8, 30).getTime());
    expect(formatted).toMatch(/2026/);
    expect(formatted).toMatch(/08/);
    expect(formatted).toMatch(/24/);
    expect(formatted).toMatch(/:/);
  });
});
