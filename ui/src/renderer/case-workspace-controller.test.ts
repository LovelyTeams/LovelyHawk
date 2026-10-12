import { describe, expect, it, vi } from "vitest";
import { CaseWorkspaceController, caseWorkspaceStateForBinding } from "./case-workspace-controller";
import type { CaseSummary, CaseWorkspaceRequest, CaseWorkspaceResult } from "../shared/case-workspace-contract";
const summary = (id: string): CaseSummary => ({ id, title: id, status: "open", createdAt: 1, updatedAt: 2, evidenceCount: 0, iocCount: 0, timelineCount: 0 });
const list = { kind: "list" as const, cases: [summary("a"), summary("b")], activeCaseId: "a", totalCases: 2 };
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>((done) => { resolve = done; }); return { promise, resolve }; }
function fixture() {
  const override: Partial<Record<CaseWorkspaceRequest["action"], (request: CaseWorkspaceRequest) => Promise<CaseWorkspaceResult>>> = {};
  const call = vi.fn(async (request: CaseWorkspaceRequest): Promise<CaseWorkspaceResult> => {
    if (override[request.action]) return override[request.action]!(request);
    if (request.action === "list") return list;
    if (request.action === "view") return { kind: "view", snapshotHandle: `snapshot-${request.caseId}`, incident: summary(request.caseId) };
    if (request.action === "items") return { kind: "items", snapshotHandle: request.snapshotHandle, section: request.section, query: request.query, offset: request.offset, total: 0, hasMore: false, items: [] };
    return { kind: "changed", caseId: "caseId" in request ? request.caseId : "a", message: "保存成功" };
  });
  return { call, override, controller: new CaseWorkspaceController({ caseWorkspace: call }) };
}
async function ready(controller: CaseWorkspaceController) { await vi.waitFor(() => expect(controller.getSnapshot().busy).toBe(false)); }
describe("case workspace lifecycle", () => {
  it("hides old-target evidence in the render before the effect can invalidate it", async () => {
    const f = fixture(); f.controller.setBinding("old"); await ready(f.controller);
    const old = f.controller.getSnapshot();
    expect(old.view?.incident.id).toBe("a");
    for (const binding of ["new", null]) {
      const visible = caseWorkspaceStateForBinding(old, binding);
      expect(visible.view).toBeNull(); expect(visible.list).toBeNull(); expect(visible.page).toBeNull();
      expect(visible.binding).toBe(binding);
    }
    expect(caseWorkspaceStateForBinding(old, "old")).toBe(old);
  });
  it("browsing another case never changes the collection selection", async () => {
    const f = fixture(); f.controller.setBinding("binding"); await ready(f.controller); await f.controller.view("b");
    expect(f.controller.getSnapshot().view?.incident.id).toBe("b"); expect(f.controller.getSnapshot().list?.activeCaseId).toBe("a");
    expect(f.call.mock.calls.map(([request]) => request.action)).toEqual(["list", "view", "items", "view", "items"]);
  });
  it("rejects late results after a target change and survives strict effect replay", async () => {
    const f = fixture(), pending = deferred<CaseWorkspaceResult>(); f.override.list = () => pending.promise;
    f.controller.setBinding("old"); f.controller.dispose(); delete f.override.list; f.controller.setBinding("new"); await ready(f.controller);
    pending.resolve({ ...list, cases: [summary("wrong")], activeCaseId: "wrong", totalCases: 1 }); await Promise.resolve(); await Promise.resolve();
    expect(f.controller.getSnapshot().binding).toBe("new"); expect(f.controller.getSnapshot().view?.incident.id).toBe("a");
  });
  it("ignores an older search after opening another immutable case view", async () => {
    const f = fixture(); f.controller.setBinding("binding"); await ready(f.controller);
    const pending = deferred<CaseWorkspaceResult>(); f.override.items = () => pending.promise;
    const search = f.controller.items("evidence", "old"); delete f.override.items; await f.controller.view("b");
    pending.resolve({ kind: "items", snapshotHandle: "snapshot-a", section: "evidence", query: "old", offset: 0, total: 0, hasMore: false, items: [] }); await search;
    expect(f.controller.getSnapshot().page?.snapshotHandle).toBe("snapshot-b"); expect(f.controller.getSnapshot().query).toBe("");
  });
  it("allows only one write and never retargets or accepts a late write outcome", async () => {
    const f = fixture(); f.controller.setBinding("binding"); await ready(f.controller);
    const pending = deferred<CaseWorkspaceResult>(); f.override.note = () => pending.promise;
    const request = { action: "note" as const, bindingHandle: "binding", caseId: "b", title: "note", content: "evidence" };
    const first = f.controller.mutate(request); expect(await f.controller.mutate(request)).toBe(false);
    f.controller.setBinding(null); pending.resolve({ kind: "changed", caseId: "b", message: "saved" }); expect(await first).toBe(false);
    expect(f.call.mock.calls.filter(([r]) => r.action === "note")).toEqual([[request]]); expect(f.controller.getSnapshot().view).toBeNull();
  });
  it("keeps a successful receipt distinct from a failed refresh", async () => {
    const f = fixture(); f.controller.setBinding("binding"); await ready(f.controller);
    f.override.list = async () => { throw new Error("refresh failed"); };
    expect(await f.controller.mutate({ action: "note", bindingHandle: "binding", caseId: "a", title: "note", content: "evidence" })).toBe(true);
    expect(f.controller.getSnapshot().notice).toBe("保存成功"); expect(f.controller.getSnapshot().error).toBe("refresh failed");
  });
  it("refuses a reply for another case before showing its contents", async () => {
    const f = fixture(); f.controller.setBinding("binding"); await ready(f.controller);
    f.override.view = async () => ({ kind: "view", snapshotHandle: "s", incident: summary("wrong") }); await f.controller.view("b");
    expect(f.controller.getSnapshot().view).toBeNull(); expect(f.controller.getSnapshot().error).toContain("校验");
  });
});
