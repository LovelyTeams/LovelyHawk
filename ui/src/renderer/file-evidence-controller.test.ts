import { afterEach, describe, expect, it, vi } from "vitest";
import { FileEvidenceController } from "./file-evidence-controller";
import type { FileEvidenceRequest, FileEvidenceResult } from "../shared/file-evidence-contract";
const offer = { pathHandle: "path-one", path: "/tmp/sample", line: 0 };
const running: FileEvidenceResult = {
  jobHandle: "job-one", pathHandle: offer.pathHandle, path: offer.path, targetLabel: "root@127.0.0.1:22",
  folderName: "LovelyHawk-evidence-12345678-1234-4234-8234-123456789012", caseTitle: "测试案件", state: "collecting",
  copiedBytes: 0, verifiedBytes: 0, totalBytes: 3, sha256: null, detail: "正在采集",
};
const complete: FileEvidenceResult = { ...running, state: "completed", copiedBytes: 3, verifiedBytes: 3, sha256: "a".repeat(64) };
function deferred<T>() { let resolve!: (v: T) => void; const promise = new Promise<T>((done) => { resolve = done; }); return { promise, resolve }; }
const controllers: FileEvidenceController[] = [];
function fixture() {
  const override: Partial<Record<FileEvidenceRequest["action"], () => Promise<FileEvidenceResult | null>>> = {};
  const fileEvidence = vi.fn(async (request: FileEvidenceRequest): Promise<FileEvidenceResult | null> =>
    override[request.action] ? override[request.action]!() : request.action === "cancel" ? { ...running, state: "cancelled" } : running);
  const controller = new FileEvidenceController({ fileEvidence }, "binding-one", offer); controllers.push(controller);
  return { controller, fileEvidence, override };
}
afterEach(() => { controllers.forEach((controller) => controller.dispose()); controllers.length = 0; vi.useRealTimers(); });
describe("file evidence lifecycle", () => {
  it("does not start twice and treats a native picker cancellation as no collection", async () => {
    const f = fixture(), pending = deferred<FileEvidenceResult | null>(); f.override.begin = () => pending.promise;
    const start = f.controller.begin(); await f.controller.begin(); expect(f.fileEvidence).toHaveBeenCalledTimes(1);
    pending.resolve(null); await start; expect(f.controller.getSnapshot().phase).toBe("ready");
  });
  it("cancels a late begin after closing without populating a replacement dialog", async () => {
    const f = fixture(), pending = deferred<FileEvidenceResult | null>(); f.override.begin = () => pending.promise;
    const begin = f.controller.begin(); f.controller.dispose(); pending.resolve(running); await begin;
    expect(f.fileEvidence.mock.calls.map(([v]) => v.action)).toEqual(["begin", "cancel"]);
    expect(f.controller.getSnapshot().result).toBeNull();
  });
  it("survives React strict effect cleanup and still rejects an earlier generation result", async () => {
    const f = fixture(), pending = deferred<FileEvidenceResult | null>(); f.override.begin = () => pending.promise;
    const begin = f.controller.begin(); f.controller.dispose(); f.controller.attach(); pending.resolve(running); await begin;
    expect(f.controller.getSnapshot().phase).toBe("ready");
    expect(f.fileEvidence.mock.calls.at(-1)?.[0].action).toBe("cancel");
    f.override.begin = async () => complete; await f.controller.begin(); expect(f.controller.getSnapshot().phase).toBe("done");
  });
  it("keeps cancellation final when an older progress reply arrives later", async () => {
    const f = fixture(); await f.controller.begin(); const pending = deferred<FileEvidenceResult | null>(); f.override.poll = () => pending.promise;
    const poll = f.controller.poll(); await f.controller.cancel(); pending.resolve(running); await poll;
    expect(f.controller.getSnapshot().result?.state).toBe("cancelled");
  });
  it("rejects changed provenance and never repeats begin to recover progress", async () => {
    const f = fixture(); await f.controller.begin(); f.override.poll = async () => ({ ...running, folderName: running.folderName.replace("12345678", "87654321") });
    await f.controller.poll(); expect(f.controller.getSnapshot().phase).toBe("interrupted");
    expect(f.controller.getSnapshot().result?.folderName).toBe(running.folderName);
    expect(f.fileEvidence.mock.calls.filter(([v]) => v.action === "begin")).toHaveLength(1);
  });
  it("polls to a verified receipt and releases its timer", async () => {
    vi.useFakeTimers(); const f = fixture(); await f.controller.begin(); f.override.poll = async () => complete;
    await vi.advanceTimersByTimeAsync(701); expect(f.controller.getSnapshot().result?.sha256).toBe(complete.sha256);
    await vi.advanceTimersByTimeAsync(60_000); expect(f.fileEvidence).toHaveBeenCalledTimes(2);
  });
});
