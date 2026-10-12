import { describe, expect, it, vi } from "vitest";
import { CaseLibraryController } from "./case-library-controller";
import type { CaseLibraryRequest, CaseLibraryResult } from "../shared/case-library-contract";
const incident = { id: "case", title: "case", status: "open" as const, createdAt: 1, updatedAt: 1, evidenceCount: 0, iocCount: 0, timelineCount: 1 };
const item = { itemHandle: "i", incident, targetId: "saved-target", connectionName: null, location: "working" as const, archivedAt: null };
const plan = { kind: "plan" as const, snapshotHandle: "s", planHandle: "p", operation: "archive" as const, summary: "保留全部证据", expiresInSeconds: 300 };
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>((done) => { resolve = done; }); return { resolve, promise }; }
function fixture() {
  const override: Partial<Record<CaseLibraryRequest["action"], (request: CaseLibraryRequest) => Promise<CaseLibraryResult | null>>> = {};
  const call = vi.fn(async (request: CaseLibraryRequest): Promise<CaseLibraryResult | null> => {
    if (override[request.action]) return override[request.action]!(request);
    switch (request.action) {
      case "list": return { kind: "list", items: [item], workingCount: 1, archiveCount: 0 };
      case "view": return { kind: "view", snapshotHandle: "s", item };
      case "items": return { kind: "items", snapshotHandle: "s", section: request.section, query: request.query, offset: request.offset, total: 0, hasMore: false, items: [] };
      case "plan": return plan;
      case "status-plan": return { ...plan, operation: request.operation, summary: `${request.conclusion}\n${request.followup}` };
      case "confirm": return { kind: "changed", planHandle: "p", operation: "archive", caseId: "case", verified: true, message: "归档已通过核对" };
      case "cancel": return { kind: "cancelled", planHandle: request.planHandle };
      case "export": return null;
    }
  });
  return { override, call, controller: new CaseLibraryController({ caseLibrary: call }) };
}
describe("offline case library lifecycle", () => {
  it("opens the requested working case and confirms its complete status record once", async () => {
    const f = fixture(); await f.controller.refresh("case");
    expect(f.controller.getSnapshot().view?.item.incident.id).toBe("case");
    const result = await f.controller.planStatus("close", "调查结论", "尚待复核");
    expect(result?.summary).toBe("调查结论\n尚待复核");
    expect(f.call).toHaveBeenLastCalledWith({ action: "status-plan", snapshotHandle: "s", operation: "close", conclusion: "调查结论", followup: "尚待复核" });
    f.override.confirm = async () => ({ kind: "changed", planHandle: "p", operation: "close", caseId: "case", verified: true, message: "结案已核对" });
    expect(await f.controller.confirm(result!)).toBe(true); expect(await f.controller.confirm(result!)).toBe(false);
  });
  it("does not substitute another or archived case for an online status request", async () => {
    const f = fixture(); await f.controller.refresh("missing");
    expect(f.controller.getSnapshot().view).toBeNull(); expect(f.controller.getSnapshot().error).toContain("不在活动列表");
    expect(f.call.mock.calls.some(([r]) => r.action === "view")).toBe(false);
    f.override.view = async () => ({ kind: "view", snapshotHandle: "s", item: { ...item, location: "archived", archivedAt: 3 } });
    await f.controller.view("i"); expect(await f.controller.planStatus("close", "reason", "todo")).toBeNull();
    expect(f.call.mock.calls.some(([r]) => r.action === "status-plan")).toBe(false);
  });
  it("does not select a live case and exports only the viewed snapshot", async () => {
    const f = fixture(); await f.controller.refresh(); await f.controller.view("i"); await f.controller.export();
    expect(f.call.mock.calls.map(([request]) => request.action)).toEqual(["list", "view", "items", "export"]);
    expect(f.call).toHaveBeenLastCalledWith({ action: "export", snapshotHandle: "s" }); expect(f.controller.getSnapshot().notice).toBe("已取消导出。");
  });
  it("cancels a late plan after leaving and ignores an earlier read after remount", async () => {
    const f = fixture(); await f.controller.view("i"); const pending = deferred<CaseLibraryResult>(); f.override.plan = () => pending.promise;
    const planning = f.controller.plan("archive"); f.controller.dispose(); await f.controller.refresh(); pending.resolve(plan); expect(await planning).toBeNull();
    expect(f.call).toHaveBeenLastCalledWith({ action: "cancel", planHandle: "p" }); expect(f.controller.getSnapshot().plan).toBeNull(); expect(f.controller.getSnapshot().view).toBeNull();
    const reading = deferred<CaseLibraryResult>(); f.override.list = () => reading.promise; const old = f.controller.refresh(); f.controller.dispose(); delete f.override.list;
    await f.controller.refresh(); reading.resolve({ kind: "list", items: [], workingCount: 0, archiveCount: 0 }); await old;
    expect(f.controller.getSnapshot().list?.workingCount).toBe(1);
  });
  it("confirms once, blocks competing work and retains success when refresh fails", async () => {
    const f = fixture(); await f.controller.view("i"); const planned = (await f.controller.plan("archive"))!;
    const pending = deferred<CaseLibraryResult>(); f.override.confirm = () => pending.promise; f.override.list = async () => { throw new Error("refresh failed"); };
    const confirming = f.controller.confirm(planned); await f.controller.confirm(planned); await f.controller.export(); await f.controller.view("i");
    expect(f.call.mock.calls.filter(([request]) => request.action === "confirm")).toHaveLength(1);
    pending.resolve({ kind: "changed", planHandle: "p", operation: "archive", caseId: "case", verified: true, message: "已核对归档" }); await confirming;
    expect(f.controller.getSnapshot().notice).toBe("已核对归档"); expect(f.controller.getSnapshot().error).toBe("refresh failed"); expect(f.controller.getSnapshot().view).toBeNull();
  });
  it("expires or cancels an exact plan without executing it", async () => {
    const f = fixture(); await f.controller.view("i"); const planned = (await f.controller.plan("archive"))!;
    planned.expiresAt = Date.now() - 1; await f.controller.confirm(planned);
    expect(f.call.mock.calls.some(([request]) => request.action === "confirm")).toBe(false); expect(f.controller.getSnapshot().error).toContain("过期");
    const other = (await f.controller.plan("archive"))!; await f.controller.cancel(); await f.controller.confirm(other);
    expect(f.call.mock.calls.some(([request]) => request.action === "confirm")).toBe(false);
  });
  it("does not claim success for another case and never retries an uncertain write", async () => {
    const f = fixture(); await f.controller.view("i"); const planned = (await f.controller.plan("archive"))!;
    f.override.confirm = async () => ({ kind: "changed", planHandle: "p", operation: "archive", caseId: "another-case", verified: true, message: "wrong success" });
    await f.controller.confirm(planned); await f.controller.confirm(planned);
    expect(f.controller.getSnapshot().notice).toBeNull(); expect(f.controller.getSnapshot().error).toContain("不一致"); expect(f.call.mock.calls.filter(([request]) => request.action === "confirm")).toHaveLength(1);
  });
});
