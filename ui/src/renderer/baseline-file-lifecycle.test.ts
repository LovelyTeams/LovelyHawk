import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { BaselineFile, BaselineReadApi } from "../shared/baseline-read-contract";

type Effect = () => void | (() => void);
type Slot = { value?: unknown; deps?: readonly unknown[] | undefined; cleanup?: void | (() => void) };
const hooks = vi.hoisted(() => ({ slots: [] as Slot[], cursor: 0, pending: [] as (() => void)[] }));
// Control the React scheduler while exercising the actual async hook and DTO
// checks. Out-of-order completion is intentional in each regression below.
vi.mock("react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react")>();
  function slot() { return hooks.slots[hooks.cursor++] ??= {}; }
  function same(a: readonly unknown[] | undefined, b: readonly unknown[] | undefined) {
    return a !== undefined && b !== undefined && a.length === b.length && a.every((value, i) => Object.is(value, b[i]));
  }
  return {
    ...actual,
    useState: <T,>(initial: T) => {
      const current = slot();
      if (!("value" in current)) current.value = initial;
      return [current.value, (next: T) => { current.value = next; }];
    },
    useRef: <T,>(initial: T) => { const current = slot(); return current.value ??= { current: initial }; },
    useCallback: (callback: unknown, deps: readonly unknown[]) => {
      const current = slot();
      if (!same(current.deps, deps)) { current.value = callback; current.deps = deps; }
      return current.value;
    },
    useEffect: (setup: Effect, deps?: readonly unknown[]) => {
      const current = slot();
      if (!same(current.deps, deps)) {
        hooks.pending.push(() => {
          if (typeof current.cleanup === "function") current.cleanup();
          current.cleanup = setup();
        });
        current.deps = deps;
      }
    },
  };
});
import { useBaselineFile } from "./BaselineFilePane";

function mockApi() {
  return { getBaselineCatalog: vi.fn(), scanBaseline: vi.fn(), listBaselineHistory: vi.fn(),
    readBaselineFile: vi.fn<(binding: string, item: string) => Promise<unknown>>() } satisfies BaselineReadApi;
}
let api = mockApi();
function render(binding: string | null = "target-a") {
  hooks.cursor = 0;
  const result = useBaselineFile(api, binding);
  for (const effect of hooks.pending.splice(0)) effect();
  return result;
}
function unmount() {
  for (const slot of hooks.slots) if (typeof slot.cleanup === "function") slot.cleanup();
}
function deferred() {
  let resolve!: (value: unknown) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<unknown>((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}
function file(text: string): BaselineFile {
  return { itemHandle: "item-a", path: "/etc/nginx/conf.d/site.conf", key: "autoindex",
    exists: true, text, lineCount: 1, mentions: [], truncated: false };
}
beforeEach(() => { hooks.slots = []; hooks.cursor = 0; hooks.pending = []; api = mockApi(); });
afterEach(unmount);

describe("baseline file read ownership", () => {
  it.each(["resolve", "reject"] as const)("keeps a newer read when an older identical item read %ss", async (completion) => {
    const old = deferred(), fresh = deferred();
    api.readBaselineFile.mockReturnValueOnce(old.promise).mockReturnValueOnce(fresh.promise);
    const before = render().open("item-a");
    await render().open(null);
    const after = render().open("item-a");
    fresh.resolve(file("new evidence")); await after;
    if (completion === "resolve") old.resolve(file("old evidence")); else old.reject(new Error("old error"));
    await before;
    expect(render().file?.text).toBe("new evidence");
    expect(render().status).toBe("ready");
  });

  it.each(["binding", "api", "disconnect", "unmount"] as const)("drops a late file after %s changes", async (change) => {
    const old = deferred(); api.readBaselineFile.mockReturnValueOnce(old.promise);
    const pending = render().open("item-a");
    let binding: string | null = "target-a";
    if (change === "binding") binding = "target-b";
    if (change === "disconnect") binding = null;
    if (change === "api") api = mockApi();
    if (change === "unmount") unmount(); else render(binding);
    old.resolve(file("old target evidence")); await pending;
    expect(render(binding).file).toBeNull();
  });

  it("ignores a callback retained from a previous target", async () => {
    const oldOpen = render().open;
    render("target-b");
    await oldOpen("item-a");
    expect(api.readBaselineFile).not.toHaveBeenCalled();
  });

  it("clears previous bytes during reload and rejects a mismatched item response", async () => {
    api.readBaselineFile.mockResolvedValueOnce(file("old"));
    await render().open("item-a");
    const next = deferred(); api.readBaselineFile.mockReturnValueOnce(next.promise);
    const pending = render().open("item-a");
    expect(render().file).toBeNull();
    next.resolve({ ...file("wrong item"), itemHandle: "item-b" }); await pending;
    expect(render().file).toBeNull();
    expect(render().status).toBe("error");
  });
});
