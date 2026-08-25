import { describe, expect, it, vi } from "vitest";

import {
  isTerminalSelectionCopyRequest,
  openTerminalWithFailureCleanup,
} from "./terminal-open-boundary";

describe("terminal main open failure boundary", () => {
  it("removes the failed keyed context so the next launch is fresh", async () => {
    const first = { key: "ssh-terminal:binding", generation: 1 };
    let keyedContext: typeof first | null = first;
    const cleanup = vi.fn(async () => {
      keyedContext = null;
    });

    await expect(openTerminalWithFailureCleanup(
      async () => {
        throw new Error("hostile-backend-detail-must-not-return");
      },
      cleanup,
    )).rejects.toThrow("Unable to open the bound SSH terminal.");

    expect(cleanup).toHaveBeenCalledTimes(1);
    expect(keyedContext).toBeNull();
    const second = keyedContext ?? { key: first.key, generation: 2 };
    expect(second).not.toBe(first);
    expect(second.generation).toBe(2);
  });

  it("permits bounded hostile plain text only after the terminal session opened", () => {
    const hostile = "</textarea><script>must-stay-plain()</script>";
    expect(isTerminalSelectionCopyRequest(false, [hostile])).toBe(false);
    expect(isTerminalSelectionCopyRequest(true, [hostile])).toBe(true);
    expect(isTerminalSelectionCopyRequest(true, [])).toBe(false);
    expect(isTerminalSelectionCopyRequest(true, [hostile, "extra"])).toBe(false);
    expect(isTerminalSelectionCopyRequest(true, ["界".repeat(43_691)])).toBe(false);
  });
});
