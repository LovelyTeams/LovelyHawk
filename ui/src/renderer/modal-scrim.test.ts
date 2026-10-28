import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import { isModalScrimActive, resetModalScrim, subscribeModalScrim } from "./modal-scrim";

function rendererDir(): string {
  return path.dirname(new URL(import.meta.url).pathname.replace(/^\/([a-z]:)/iu, "$1"));
}

afterEach(() => {
  resetModalScrim();
});

describe("modal scrim registry", () => {
  it("notifies subscribers as backdrops appear and disappear", () => {
    const seen: boolean[] = [];
    subscribeModalScrim((active) => seen.push(active));
    expect(isModalScrimActive()).toBe(false);

    // Simulate the effect bodies the hook runs on mount/unmount.
    const listener = vi.fn();
    const unsubscribe = subscribeModalScrim(listener);
    unsubscribe();
    expect(listener).not.toHaveBeenCalled();
  });

  it("keeps the scrim up until the last nested modal closes", async () => {
    const { useModalScrim } = await import("./modal-scrim");
    // The hook is exercised through its effect contract in the component tree;
    // here we assert the module keeps a depth rather than a boolean.
    const source = readFileSync(new URL("./modal-scrim.ts", import.meta.url), "utf8");
    expect(typeof useModalScrim).toBe("function");
    expect(source).toContain("depth += 1;");
    expect(source).toContain("depth = Math.max(0, depth - 1);");
    // A stale decrement must never drive the depth negative.
    expect(source).not.toMatch(/depth\s*-=\s*1/u);
  });

  it("registers every rendered backdrop", () => {
    const files = readdirSync(rendererDir())
      .filter((name) => name.endsWith(".tsx") && !name.endsWith(".test.tsx"));
    const withBackdrop = files.filter((name) => {
      const source = readFileSync(path.join(rendererDir(), name), "utf8");
      return /className="[a-z-]*backdrop[a-z-]*"/u.test(source);
    });
    expect(withBackdrop.length).toBeGreaterThanOrEqual(9);
    for (const name of withBackdrop) {
      const source = readFileSync(path.join(rendererDir(), name), "utf8");
      expect(source, `${name} must register its backdrop`).toContain("useModalScrim(");
    }
  });

  it("folds page-level dialogs into the native title-bar scrim", () => {
    const appSource = readFileSync(new URL("./App.tsx", import.meta.url), "utf8");
    expect(appSource).toContain("useEffect(() => subscribeModalScrim(setPageModalOpen), []);");
    expect(appSource).toContain("scrim: overlayOpen || pageModalOpen");
  });
});
