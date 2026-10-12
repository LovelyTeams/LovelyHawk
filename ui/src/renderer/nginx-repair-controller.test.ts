import { afterEach, describe, expect, it, vi } from "vitest";
import { NginxRepairController } from "./nginx-repair-controller";
import type { NginxRepairRequest, NginxRepairPlan } from "../shared/nginx-repair-contract";

const plan: NginxRepairPlan = { planHandle: "plan-1", targetLabel: "root@lab:22 · Nginx 主进程 1", candidateHandle: "candidate-1", title: "关闭目录列表",
  path: "/etc/nginx/conf.d/site.conf", line: 7, diff: "- autoindex on;\n+ autoindex off;",
  impact: "重载实例", restoreDescription: "保留备份", confirmed: false, expiresInSeconds: 300 };
const configuration = { kind: "configuration", configurationHandle: "config-1", instanceHandle: "instance-1", fileCount: 3, unresolvedIncludes: 0,
  candidates: [{ candidateHandle: "candidate-1", setting: "autoindex", title: "关闭目录列表", path: plan.path, line: 7, before: "autoindex on;", after: "autoindex off;" }] };
function deferred() { let resolve!: (value: unknown) => void; const promise = new Promise<unknown>((yes) => { resolve = yes; }); return { resolve, promise }; }
async function settle() { for (let i = 0; i < 18; i++) await Promise.resolve(); }
function fixture() {
  const custom = new Map<string, (request: NginxRepairRequest) => unknown>();
  const nginxRepair = vi.fn(async (request: NginxRepairRequest): Promise<unknown> => {
    if (custom.has(request.action)) return await custom.get(request.action)!(request);
    switch (request.action) {
      case "discover": return { kind: "inventory", instances: [{ instanceHandle: "instance-1", title: "Nginx 主进程 1", version: "1.27.5", mainPid: 1 }] };
      case "load": return structuredClone(configuration);
      case "listeners": return { kind: "listeners", instanceHandle: request.instanceHandle, endpoints: [{ endpointHandle: "e", address: "127.0.0.1", port: 8443, connectAddress: "127.0.0.1" }] };
      case "probe": return { kind: "connectivity", observationHandle: "observation-1", recordText: "完整观察", retention: { state: "saved", caseId: "case-1", caseTitle: "应急案件", evidenceId: "evidence-1", sha256: "a".repeat(64), detail: "已保存", canRetry: false }, endpointHandle: request.endpointHandle, serverName: request.serverName, path: request.path, checkedAt: "2026-09-08T12:00:00Z",
        report: { clientVersion: "OpenSSL test", rows: ["TLSv1", "TLSv1_1", "TLSv1_2", "TLSv1_3"].map((version) => ({ version, outcome: "inconclusive", detail: "handshake-failed", certificateSha256: null, httpOutcome: "not-sent", httpStatus: null })) } };
      case "retain": return { kind: "retention", observationHandle: request.observationHandle, retention: { state: "saved", caseId: "case-1", caseTitle: "应急案件", evidenceId: "evidence-1", sha256: "a".repeat(64), detail: "已保存", canRetry: false } };
      case "discard-observation": return { kind: "observation-discarded", observationHandle: request.observationHandle };
      case "plan": return { kind: "plan", plan: { ...plan } };
      case "confirm": return { kind: "plan", plan: { ...plan, planHandle: request.planHandle, confirmed: true, expiresInSeconds: 290 } };
      case "execute": return { kind: "execution", executionHandle: "job-1", receipt: null };
      case "execution": return { kind: "execution", executionHandle: "job-1", receipt: { planHandle: "plan-1", state: "verified", detail: "已核实进程切换", recordHandle: "record-1" } };
      case "history": return { kind: "history", totalRecords: 1, truncated: false, records: [{ recordHandle: "record-1", path: plan.path, state: "applied", createdAt: "2026-09-08T10:00:00Z", canPrepareRestore: true }] };
      case "restore": return { kind: "plan", plan: { ...plan, candidateHandle: null, title: "恢复先前配置", line: null } };
      case "cancel": return { kind: "cancelled", cancelled: true };
    }
  });
  const controller = new NginxRepairController({ nginxRepair }, "binding-1");
  return { controller, nginxRepair, custom, actions: () => nginxRepair.mock.calls.map(([request]) => request.action),
    async ready() { await controller.read("discover"); await controller.read("load", "instance-1"); await controller.prepare("candidate-1"); } };
}
afterEach(() => { vi.useRealTimers(); });
describe("Nginx repair ownership and one-time execution", () => {
  it.each(["saved", "unsaved"] as const)("waits for an in-flight observation before leaving when retention becomes %s", async (state) => {
    const f = fixture(); await f.controller.read("load", "instance-1"); await f.controller.read("listeners", "instance-1");
    const result = await f.nginxRepair({ action: "probe", bindingHandle: "binding-1", endpointHandle: "e", serverName: "a.test", path: "/" }) as Record<string, unknown>;
    f.nginxRepair.mockClear();
    const later = deferred(); f.custom.set("probe", () => later.promise);
    const work = f.controller.probe("e", "a.test", "/");
    let completed = false; const leave = f.controller.beforeDeactivate().then((value) => { completed = true; return value; });
    await settle(); expect(completed).toBe(false); expect(f.actions()).toEqual(["probe"]);
    later.resolve({ ...result, ...(state === "unsaved" ? { retention: { state, caseId: "case-1", caseTitle: "原案件", evidenceId: null, sha256: null, detail: "存储失败", canRetry: true } } : {}) });
    await work; expect(await leave).toBe(state === "saved");
    expect(f.controller.getSnapshot().connectivity?.retention.state).toBe(state);
    if (state === "unsaved") {
      await f.controller.retainObservation(); expect(await f.controller.beforeDeactivate()).toBe(true);
      expect(f.actions()).toEqual(["probe", "retain"]);
    }
  });
  it("keeps an unsaved observation and retries storage without probing or changing its contents", async () => {
    const f = fixture();
    const result = await f.nginxRepair({ action: "probe", bindingHandle: "binding-1", endpointHandle: "e", serverName: "a.test", path: "/" }) as Record<string, unknown>;
    f.nginxRepair.mockClear(); f.custom.set("probe", () => ({ ...result, retention: { state: "unsaved", caseId: "case-1", caseTitle: "应急案件", evidenceId: null, sha256: null, detail: "存储失败", canRetry: true } }));
    await f.controller.read("load", "instance-1"); await f.controller.read("listeners", "instance-1"); await f.controller.probe("e", "a.test", "/");
    const original = f.controller.getSnapshot().connectivity;
    f.controller.clearConnectivity(); await f.controller.read("discover"); await f.controller.probe("e", "other.test", "/");
    expect(f.controller.getSnapshot().connectivity).toEqual(original);
    await f.controller.retainObservation(); await f.controller.retainObservation();
    expect(f.actions()).toEqual(["load", "listeners", "probe", "retain"]);
    expect(f.controller.getSnapshot().connectivity).toMatchObject({ report: original!.report, recordText: original!.recordText, checkedAt: original!.checkedAt, retention: { state: "saved", caseId: "case-1" } });
  });
  it("rejects a different observation's storage receipt and requires an explicit discard", async () => {
    const f = fixture(); const result = await f.nginxRepair({ action: "probe", bindingHandle: "binding-1", endpointHandle: "e", serverName: "a.test", path: "/" }) as Record<string, unknown>;
    f.nginxRepair.mockClear(); f.custom.set("probe", () => ({ ...result, retention: { state: "unsaved", caseId: null, caseTitle: null, evidenceId: null, sha256: null, detail: "未保存", canRetry: true } }));
    await f.controller.read("load", "instance-1"); await f.controller.read("listeners", "instance-1"); await f.controller.probe("e", "a.test", "/");
    f.custom.set("retain", () => ({ kind: "retention", observationHandle: "other", retention: (result as { retention: unknown }).retention }));
    await f.controller.retainObservation(); expect(f.controller.getSnapshot().connectivity?.retention.state).toBe("unsaved");
    expect(f.controller.getSnapshot().error).toContain("不匹配");
    expect(await f.controller.discardObservation()).toBe(true); expect(f.controller.getSnapshot().connectivity).toBeNull();
    expect(f.actions().filter((action) => action === "probe")).toHaveLength(1);
  });
  it("only probes discovered endpoints and clears observations on refresh or a write", async () => {
    const f = fixture(); await f.controller.read("load", "instance-1");
    await f.controller.read("listeners", "instance-1");
    await f.controller.probe("forged", "a.test", "/"); await f.controller.probe("e", "a.test:443", "/");
    expect(f.actions()).toEqual(["load", "listeners"]);
    await f.controller.probe("e", "a.test", "/"); expect(f.controller.getSnapshot().connectivity?.serverName).toBe("a.test");
    await f.controller.prepare("candidate-1"); await f.controller.confirm();
    expect(f.controller.getSnapshot().connectivity).toBeNull(); expect(f.controller.getSnapshot().endpoints).toBeNull();
  });
  it("drops a late TLS observation after leaving and refuses concurrent requests", async () => {
    const f = fixture(); await f.controller.read("load", "instance-1"); await f.controller.read("listeners", "instance-1");
    const later = deferred(); f.custom.set("probe", () => later.promise);
    const work = f.controller.probe("e", "a.test", "/");
    await f.controller.probe("e", "a.test", "/"); await f.controller.read("listeners", "instance-1");
    expect(f.actions()).toEqual(["load", "listeners", "probe"]);
    f.controller.dispose(); f.controller.activate(); later.resolve({ kind: "inventory", instances: [] }); await work;
    expect(f.controller.getSnapshot().connectivity).toBeNull(); expect(f.controller.getSnapshot().error).toBeNull();
  });
  it("displays a complete result and invalidates the pre-write configuration", async () => {
    const f = fixture(); await f.ready();
    await Promise.all([f.controller.confirm(), f.controller.confirm()]);
    expect(f.actions()).toEqual(["discover", "load", "plan", "confirm", "execute", "execution"]);
    expect(f.controller.getSnapshot().dialog?.receipt?.state).toBe("verified");
    expect(f.controller.getSnapshot().configuration).toBeNull();
    await f.controller.confirm(); expect(f.actions().filter((a) => a === "execute")).toHaveLength(1);
  });
  it("cancels a plan arriving after the preparation dialog was closed", async () => {
    const f = fixture(), later = deferred(); await f.controller.read("load", "instance-1");
    f.custom.set("plan", () => later.promise);
    const work = f.controller.prepare("candidate-1"); f.controller.closeDialog();
    later.resolve({ kind: "plan", plan }); await work;
    expect(f.controller.getSnapshot().dialog).toBeNull(); expect(f.actions()).toEqual(["load", "plan", "cancel"]);
  });
  it("cancels late confirmation on navigation without issuing a write", async () => {
    const f = fixture(), later = deferred(); await f.ready(); f.custom.set("confirm", () => later.promise);
    const work = f.controller.confirm(); expect(await f.controller.beforeDeactivate()).toBe(true);
    later.resolve({ kind: "plan", plan: { ...plan, confirmed: true } }); await work;
    expect(f.actions()).not.toContain("execute"); expect(f.controller.getSnapshot().dialog).toBeNull();
  });
  it.each(["targetLabel", "path", "diff", "impact", "restoreDescription", "line", "candidateHandle"] as const)("rejects changed confirmation field %s", async (field) => {
    const f = fixture(); await f.ready();
    f.custom.set("confirm", () => ({ kind: "plan", plan: { ...plan, confirmed: true, [field]: field === "line" ? 8 : field === "path" ? "/etc/nginx/other.conf" : "changed" } }));
    await f.controller.confirm(); expect(f.actions()).not.toContain("execute");
    expect(f.controller.getSnapshot().dialog?.phase).toBe("failed");
  });
  it("rejects unresolved configuration graphs and invented candidate/restore handles before dispatch", async () => {
    const f = fixture(); f.custom.set("load", () => ({ ...configuration, unresolvedIncludes: 1 }));
    await f.controller.read("load", "instance-1"); await f.controller.prepare("candidate-1"); await f.controller.prepare("invented"); await f.controller.restore("invented");
    expect(f.actions()).toEqual(["load"]);
  });
  it("waits for execution during navigation and cannot cancel a dispatched write", async () => {
    const f = fixture(), later = deferred(); await f.ready(); f.custom.set("execution", () => later.promise);
    const work = f.controller.confirm(); await settle();
    f.controller.closeDialog(); expect(f.controller.getSnapshot().dialog?.phase).toBe("executing");
    let left = false; const navigation = f.controller.beforeDeactivate().then(() => { left = true; });
    await settle(); expect(left).toBe(false);
    later.resolve({ kind: "execution", executionHandle: "job-1", receipt: { planHandle: "plan-1", state: "restored", detail: "已还原", recordHandle: "record-1" } });
    await work; await navigation; expect(left).toBe(true); expect(f.actions()).not.toContain("cancel");
  });
  it("does not mix replies into a replacement target or resume a disposed execution", async () => {
    const f = fixture(), later = deferred(); await f.ready(); f.custom.set("confirm", () => later.promise);
    const work = f.controller.confirm(); f.controller.dispose();
    const replacement = new NginxRepairController({ nginxRepair: f.nginxRepair }, "binding-2");
    later.resolve({ kind: "plan", plan: { ...plan, confirmed: true } }); await work;
    expect(f.actions()).not.toContain("execute"); expect(replacement.getSnapshot().dialog).toBeNull();
    expect(f.nginxRepair.mock.calls.every(([request]) => request.bindingHandle === "binding-1")).toBe(true);
  });
  it("drops a stale discovery reply even if React remounts the same controller", async () => {
    const f = fixture(), later = deferred(); f.custom.set("discover", () => later.promise);
    const work = f.controller.read("discover"); f.controller.dispose(); f.controller.activate();
    later.resolve({ kind: "inventory", instances: [] }); await work;
    expect(f.controller.getSnapshot().inventory).toBeNull(); expect(f.controller.getSnapshot().reading).toBeNull();
  });
  it("reports a lost execution acknowledgement as unknown and never replays it", async () => {
    vi.useFakeTimers(); const f = fixture(); await f.ready(); f.custom.set("execute", () => new Promise(() => {}));
    const work = f.controller.confirm(); await settle(); await vi.advanceTimersByTimeAsync(30_001); await work;
    expect(f.controller.getSnapshot().dialog?.error).toContain("不要重复提交");
    await f.controller.confirm(); expect(f.actions().filter((a) => a === "execute")).toHaveLength(1);
  });
  it("rejects a receipt about another plan", async () => {
    const f = fixture(); await f.ready(); f.custom.set("execution", () => ({ kind: "execution", executionHandle: "job-1", receipt: { planHandle: "other", state: "verified", detail: "", recordHandle: null } }));
    await f.controller.confirm(); expect(f.controller.getSnapshot().dialog?.receipt).toBeNull();
    expect(f.controller.getSnapshot().dialog?.phase).toBe("failed");
  });
  it("expires waiting for a running job and retains the unknown-result guidance", async () => {
    vi.useFakeTimers(); const f = fixture(); await f.ready(); f.custom.set("execution", () => ({ kind: "execution", executionHandle: "job-1", receipt: null }));
    const work = f.controller.confirm(); await settle(); await vi.advanceTimersByTimeAsync(300_001); await work;
    expect(f.controller.getSnapshot().dialog?.phase).toBe("failed");
    expect(f.actions().filter((a) => a === "execute")).toHaveLength(1);
  });
  it("cancels a plan arriving after a preparation timeout", async () => {
    vi.useFakeTimers(); const f = fixture(), later = deferred(); await f.controller.read("load", "instance-1"); f.custom.set("plan", () => later.promise);
    const work = f.controller.prepare("candidate-1"); await vi.advanceTimersByTimeAsync(185_001); await work;
    later.resolve({ kind: "plan", plan }); await settle(); expect(f.actions()).toContain("cancel");
    expect(f.controller.getSnapshot().dialog?.phase).toBe("failed");
  });
  it("prepares restoration only from the current target history, still requiring confirmation", async () => {
    const f = fixture(); await f.controller.read("history"); await f.controller.restore("record-1");
    expect(f.controller.getSnapshot().dialog?.plan?.candidateHandle).toBeNull(); expect(f.actions()).toEqual(["history", "restore"]);
  });
});
