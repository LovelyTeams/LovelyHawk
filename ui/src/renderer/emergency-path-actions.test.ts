import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type {
  EmergencyCommandApi,
  EmergencyCommandPathOffer,
  EmergencyPathDetail,
  EmergencyPathPlan,
  EmergencyPathReceipt,
} from "../shared/emergency-command-contract";

type Effect = () => void | (() => void);
type Slot = { value?: unknown; deps?: readonly unknown[] | undefined; cleanup?: void | (() => void) };
const hooks = vi.hoisted(() => ({
  slots: [] as Slot[], cursor: 0, count: null as number | null, pending: [] as (() => void)[],
}));

// Exercise the real async hook with deferred API responses. Only the React
// scheduler is controlled; requests, validation and state transitions are real.
vi.mock("react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react")>();
  function slot(): Slot {
    const index = hooks.cursor++;
    return hooks.slots[index] ??= {};
  }
  function same(a: readonly unknown[] | undefined, b: readonly unknown[] | undefined): boolean {
    return a !== undefined && b !== undefined && a.length === b.length && a.every((v, i) => Object.is(v, b[i]));
  }
  return {
    ...actual,
    useState: <T,>(initial: T | (() => T)) => {
      const current = slot();
      if (!("value" in current)) current.value = typeof initial === "function" ? (initial as () => T)() : initial;
      return [current.value, (next: T | ((value: T) => T)) => {
        current.value = typeof next === "function" ? (next as (value: T) => T)(current.value as T) : next;
      }];
    },
    useRef: <T,>(initial: T) => {
      const current = slot();
      return current.value ??= { current: initial };
    },
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
    useReducer: (reducer: (state: unknown, action: unknown) => unknown, initial: unknown, init?: (value: unknown) => unknown) => {
      const current = slot();
      if (!("value" in current)) current.value = init === undefined ? initial : init(initial);
      return [current.value, (action: unknown) => { current.value = reducer(current.value, action); }];
    },
  };
});

import { reason, undoFailure, useEmergencyPathActions } from "./emergency-path-actions";
import { EmergencyCommandsPage } from "./EmergencyCommandsPage";

const offer: EmergencyCommandPathOffer = { pathHandle: "path-one", path: "/tmp/evidence-one", line: 0 };
const detail: EmergencyPathDetail = {
  pathHandle: offer.pathHandle, path: offer.path, kind: "file", size: "20", mode: "4700", ownerId: 0, groupId: 0,
  modifiedAt: null, executable: true,
};
const plan: EmergencyPathPlan = {
  planHandle: "plan-one", pathHandle: offer.pathHandle, path: offer.path, action: "disarm",
  summary: "移除文件的执行权限", dangerous: true, restoreDescription: "恢复原权限",
  state: "planned", expiresInSeconds: 300,
};
const confirmed: EmergencyPathPlan = { ...plan, state: "confirmed", expiresInSeconds: 290 };
const receipt: EmergencyPathReceipt = {
  planHandle: plan.planHandle, path: plan.path, action: plan.action,
  passed: true, detail: "已复核权限", restored: false, untouched: false, undoable: true,
};
const undone = { planHandle: plan.planHandle, path: plan.path, undone: true, detail: "权限已经恢复为 4755" };

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

function mockApi() {
  return {
    fileEvidence: vi.fn(async () => null),
    loadEmergencyCommandCatalog: vi.fn(async () => ({
      snapshotHandle: "snapshot-one", expiresInSeconds: 300, commandSet: "portable", commands: [], containers: [],
    })),
    runEmergencyCommand: vi.fn(async () => null),
    inspectEmergencyPath: vi.fn(async (): Promise<unknown> => detail),
    planEmergencyPathAction: vi.fn(async (): Promise<unknown> => plan),
    confirmEmergencyPathAction: vi.fn(async (): Promise<unknown> => confirmed),
    executeEmergencyPathAction: vi.fn(async (): Promise<unknown> => receipt),
    cancelEmergencyPathAction: vi.fn(async () => undefined),
    undoEmergencyPathAction: vi.fn(async (): Promise<unknown> => undone),
    locateEmergencyHistoryCommand: vi.fn(async (): Promise<unknown> => ({ status: "missing", commandHandle: null })),
  } satisfies EmergencyCommandApi & import("../shared/file-evidence-contract").FileEvidenceApi;
}

let api = mockApi();
function render<T>(component: () => T): T {
  hooks.cursor = 0;
  const value = component();
  if (hooks.count !== null) expect(hooks.cursor, "hook count changed between renders").toBe(hooks.count);
  hooks.count = hooks.cursor;
  for (const effect of hooks.pending.splice(0)) effect();
  return value;
}
const view = (binding: string | null = "target-one") => render(() => useEmergencyPathActions(api, binding));
function unmount() {
  for (const current of hooks.slots) {
    if (typeof current.cleanup === "function") current.cleanup();
    current.cleanup = undefined;
  }
}

beforeEach(() => {
  hooks.slots = []; hooks.cursor = 0; hooks.count = null; hooks.pending = []; api = mockApi();
});
afterEach(unmount);

describe("emergency file action lifecycle", () => {
  it("keeps the page's hooks in the same order across connect and disconnect", () => {
    render(() => EmergencyCommandsPage({ bindingHandle: null, api }));
    render(() => EmergencyCommandsPage({ bindingHandle: "target-one", api }));
    render(() => EmergencyCommandsPage({ bindingHandle: null, api }));
  });

  it("requires an explicit confirmation and executes an unchanged plan only once", async () => {
    await view().start("disarm", offer);
    expect(view().state?.plan).toEqual(plan);
    expect(api.confirmEmergencyPathAction).not.toHaveBeenCalled();
    expect(api.executeEmergencyPathAction).not.toHaveBeenCalled();
    await Promise.all([view().confirm(), view().confirm()]);
    await view().confirm();
    expect(api.confirmEmergencyPathAction).toHaveBeenCalledExactlyOnceWith("target-one", plan.planHandle);
    expect(api.executeEmergencyPathAction).toHaveBeenCalledExactlyOnceWith("target-one", plan.planHandle);
    expect(view().state?.receipt).toEqual(receipt);
  });

  it("does not let a dismissed inspection fill or unlock its replacement dialog", async () => {
    const oldDetail = deferred<unknown>();
    const newDetail = deferred<unknown>();
    api.inspectEmergencyPath.mockReturnValueOnce(oldDetail.promise).mockReturnValueOnce(newDetail.promise);
    const oldRequest = view().start("properties", offer);
    view().close();
    const nextOffer = { ...offer, pathHandle: "path-two", path: "/tmp/evidence-two" };
    const newRequest = view().start("properties", nextOffer);
    oldDetail.resolve(detail);
    await oldRequest;
    expect(view().state?.offer).toEqual(nextOffer);
    expect(view().state?.busy).toBe(true);
    await view().start("disarm", offer);
    expect(api.inspectEmergencyPath).toHaveBeenCalledTimes(2);
    newDetail.resolve({ ...detail, pathHandle: nextOffer.pathHandle, path: nextOffer.path });
    await newRequest;
    expect(view().state?.detail?.path).toBe(nextOffer.path);
    expect(api.planEmergencyPathAction).not.toHaveBeenCalled();
  });

  it("cancels a plan arriving after its dialog was closed against its original target", async () => {
    const pending = deferred<unknown>();
    api.planEmergencyPathAction.mockReturnValueOnce(pending.promise);
    const request = view().start("disarm", offer);
    await Promise.resolve();
    expect(api.planEmergencyPathAction).toHaveBeenCalledOnce();
    view().close();
    view("target-two");
    pending.resolve(plan);
    await request;
    expect(view("target-two").state).toBeNull();
    expect(api.cancelEmergencyPathAction).toHaveBeenCalledExactlyOnceWith("target-one", plan.planHandle);
  });

  it.each(["close", "disconnect", "switch", "unmount"])(
    "does not execute a confirmation arriving after %s", async (transition) => {
      await view().start("disarm", offer);
      const pending = deferred<unknown>();
      api.confirmEmergencyPathAction.mockReturnValueOnce(pending.promise);
      const request = view().confirm();
      if (transition === "close") view().close();
      else if (transition === "disconnect") view(null);
      else if (transition === "switch") view("target-two");
      else unmount();
      pending.resolve(confirmed);
      await request;
      expect(api.executeEmergencyPathAction).not.toHaveBeenCalled();
      expect(api.cancelEmergencyPathAction).toHaveBeenCalledExactlyOnceWith("target-one", plan.planHandle);
    },
  );

  it("undoes a verified action once, and only after it was verified", async () => {
    await view().start("disarm", offer);
    // Nothing to undo before the action ran.
    await view().undo();
    expect(api.undoEmergencyPathAction).not.toHaveBeenCalled();
    await view().confirm();
    expect(view().state?.receipt).toEqual(receipt);
    const first = view().undo();
    // A second click while the first is in flight is the same attempt.
    const second = view().undo();
    await Promise.all([first, second]);
    expect(api.undoEmergencyPathAction).toHaveBeenCalledExactlyOnceWith("target-one", plan.planHandle);
    expect(view().state?.undo).toEqual(undone);
    expect(view().state?.undoSpent).toBe(true);
    await view().undo();
    expect(api.undoEmergencyPathAction).toHaveBeenCalledOnce();
  });

  it("does not offer an undo the receipt did not", async () => {
    api.executeEmergencyPathAction.mockResolvedValueOnce({ ...receipt, undoable: false });
    await view().start("disarm", offer);
    await view().confirm();
    await view().undo();
    expect(api.undoEmergencyPathAction).not.toHaveBeenCalled();
  });

  it.each([{ planHandle: "other-plan" }, { path: "/tmp/other" }, { undone: "yes" }])(
    "does not report an undo result it cannot match: %j", async (mismatch) => {
      api.undoEmergencyPathAction.mockResolvedValueOnce({ ...undone, ...mismatch });
      await view().start("disarm", offer);
      await view().confirm();
      await view().undo();
      expect(view().state?.undo).toBeNull();
      expect(view().state?.error).toContain("无法核对撤销的结果");
      // Spent: the attempt reached the target, so it is not offered again.
      expect(view().state?.undoSpent).toBe(true);
    },
  );

  it("says an expired undo changed nothing, instead of pointing back at the output", async () => {
    api.undoEmergencyPathAction.mockRejectedValueOnce(
      new Error("这个文件操作入口已过期或已使用，请从输出行重新打开。 (emergency-path-unavailable)"));
    await view().start("disarm", offer);
    await view().confirm();
    await view().undo();
    expect(view().state?.error).toContain("撤销的时限已过");
    expect(view().state?.error).toContain("没有被改动");
    // Any other failure keeps its own words.
    expect(undoFailure("命令超出时限，请在目标主机上核对是否仍在运行。 (emergency-command-timeout)")).toContain("不确定文件是否已经放回");
    expect(undoFailure("无法连接目标 (emergency-command-binding-unavailable)")).toBe("无法连接目标 (emergency-command-binding-unavailable)");
  });

  it("drops an undo result arriving after its dialog closed", async () => {
    await view().start("disarm", offer);
    await view().confirm();
    const pending = deferred<unknown>();
    api.undoEmergencyPathAction.mockReturnValueOnce(pending.promise);
    const request = view().undo();
    view().close();
    pending.resolve(undone);
    await request;
    expect(view().state).toBeNull();
  });

  it("does not replace a newer inspection with a late execution receipt", async () => {
    await view().start("disarm", offer);
    const pending = deferred<unknown>();
    api.executeEmergencyPathAction.mockReturnValueOnce(pending.promise);
    const request = view().confirm();
    await Promise.resolve();
    expect(api.executeEmergencyPathAction).toHaveBeenCalledOnce();
    view().close();
    await view().start("properties", offer);
    pending.resolve(receipt);
    await request;
    expect(view().state?.action).toBeNull();
    expect(view().state?.receipt).toBeNull();
    expect(view().state?.detail).toEqual(detail);
  });

  it.each([{ pathHandle: "other-path" }, { path: "/tmp/other" }])(
    "rejects file information for another selection: %j", async (mismatch) => {
      api.inspectEmergencyPath.mockResolvedValue({ ...detail, ...mismatch });
      await view().start("disarm", offer);
      expect(view().state?.error).toContain("本次选择不一致");
      expect(api.planEmergencyPathAction).not.toHaveBeenCalled();
    },
  );

  it.each([{ pathHandle: "other-path" }, { action: "quarantine" }, { state: "confirmed" }])(
    "cancels a plan that does not match the requested action: %j", async (mismatch) => {
      api.planEmergencyPathAction.mockResolvedValue({ ...plan, ...mismatch });
      await view().start("disarm", offer);
      expect(view().state?.plan).toBeNull();
      expect(view().state?.error).toContain("本次选择不一致");
      expect(api.cancelEmergencyPathAction).toHaveBeenCalledExactlyOnceWith("target-one", plan.planHandle);
    },
  );

  it.each([
    { planHandle: "other-plan" }, { pathHandle: "other-path" }, { path: "/tmp/other" },
    { action: "quarantine" }, { summary: "另一项操作" }, { dangerous: false },
    { restoreDescription: null }, { state: "planned" },
  ])("rejects a changed or unconfirmed plan: %j", async (mismatch) => {
    api.confirmEmergencyPathAction.mockResolvedValue({ ...confirmed, ...mismatch });
    await view().start("disarm", offer);
    await view().confirm();
    expect(view().state?.error).toContain("所查看的计划不一致");
    expect(view().state?.plan).toBeNull();
    expect(api.executeEmergencyPathAction).not.toHaveBeenCalled();
  });

  it("does not report a foreign receipt as success or allow the plan to be replayed", async () => {
    api.executeEmergencyPathAction.mockResolvedValue({ ...receipt, planHandle: "other-plan" });
    await view().start("disarm", offer);
    await view().confirm();
    expect(view().state?.receipt).toBeNull();
    expect(view().state?.error).toContain("勿重复执行");
    await view().confirm();
    expect(api.executeEmergencyPathAction).toHaveBeenCalledOnce();
  });

  it("does not issue file requests without a connected target", async () => {
    await view(null).start("disarm", offer);
    await view(null).confirm();
    expect(api.inspectEmergencyPath).not.toHaveBeenCalled();
    expect(api.executeEmergencyPathAction).not.toHaveBeenCalled();
  });

  it("does not let an old dialog's confirmation approve its replacement", async () => {
    await view().start("disarm", offer);
    const oldConfirm = view().confirm;
    view().close();
    const nextPlan = { ...plan, planHandle: "plan-two" };
    api.planEmergencyPathAction.mockResolvedValue(nextPlan);
    api.confirmEmergencyPathAction.mockResolvedValue({ ...nextPlan, state: "confirmed" });
    api.executeEmergencyPathAction.mockResolvedValue({ ...receipt, planHandle: "plan-two" });
    await view().start("disarm", offer);
    await oldConfirm();
    expect(api.confirmEmergencyPathAction).not.toHaveBeenCalled();
    await view().confirm();
    expect(api.executeEmergencyPathAction).toHaveBeenCalledExactlyOnceWith("target-one", "plan-two");
  });

  it("does not interpret a generic refusal as proof the file is already disarmed", () => {
    const refusal = reason("could not act on that path", "disarm");
    expect(refusal).toContain("重新查看文件属性");
    expect(refusal).not.toContain("已经没有执行位");
  });
});
