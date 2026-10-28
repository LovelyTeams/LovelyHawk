import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  isPodFileEvidenceRequest,
  isPodFileEvidenceResult,
  matchesPodFileEvidenceResult,
  type PodFileEvidenceRequest,
  type PodFileEvidenceResult,
} from "../shared/pod-file-evidence-contract";
import { PodFileDialog } from "./PodFileDialog";
import { PodFileEvidenceController, type PodFileEvidenceTarget } from "./pod-file-evidence-controller";
import { PodFileEvidencePanel } from "./PodFileEvidencePanel";

const BINDING = "00000000-0000-4000-8000-000000000001";
const target: PodFileEvidenceTarget = {
  snapshotHandle: "00000000-0000-4000-8000-000000000002",
  rowHandle: "00000000-0000-4000-8000-000000000003",
  container: "app",
  path: "/var/log/app.log",
};
const copying: PodFileEvidenceResult = {
  jobHandle: "job-one", pod: "payments/ledger-0", container: "app", path: "/var/log/app.log",
  targetLabel: "root@192.0.2.10:22", folderName: "LovelyHawk-evidence-12345678-1234-4234-8234-123456789012",
  caseTitle: "测试案件", state: "copying", copiedBytes: 0, verifiedBytes: 0, totalBytes: 0, sha256: null,
  detail: "正在复制", temporaryFile: "pending",
};
const complete: PodFileEvidenceResult = {
  ...copying, state: "completed", copiedBytes: 900, verifiedBytes: 900, totalBytes: 900,
  sha256: "a".repeat(64), detail: "已保存", temporaryFile: "removed",
};
const cancelled: PodFileEvidenceResult = { ...copying, state: "cancelled", detail: "已取消" };

const controllers: PodFileEvidenceController[] = [];
function fixture() {
  const override: Partial<Record<PodFileEvidenceRequest["action"], () => Promise<PodFileEvidenceResult | null>>> = {};
  const podFileEvidence = vi.fn(async (request: PodFileEvidenceRequest) =>
    override[request.action] ? override[request.action]!() : request.action === "cancel" ? cancelled : copying);
  const controller = new PodFileEvidenceController({ podFileEvidence }, BINDING);
  controllers.push(controller);
  return { controller, podFileEvidence, override };
}

afterEach(() => {
  controllers.forEach((controller) => controller.dispose());
  controllers.length = 0;
  vi.useRealTimers();
});

describe("pod file evidence contract", () => {
  const begin = { action: "begin", bindingHandle: BINDING, ...target } as const;

  it("names the pod by handles, the container by name and the file by an absolute path", () => {
    expect(isPodFileEvidenceRequest(begin)).toBe(true);
    expect(isPodFileEvidenceRequest({ ...begin, container: null })).toBe(true);
    expect(isPodFileEvidenceRequest({ action: "cancel", bindingHandle: BINDING, jobHandle: "job-one" })).toBe(true);
    for (const forged of [
      { ...begin, selectedDirectory: "C:\\evidence" },
      { ...begin, path: "relative/file" },
      { ...begin, path: "/var/../etc/shadow" },
      { ...begin, path: "/" },
      { ...begin, container: "App; id" },
      { ...begin, namespace: "kube-system" },
      { ...begin, hostPath: "/tmp/x" },
      { action: "begin", bindingHandle: BINDING, snapshotHandle: target.snapshotHandle, rowHandle: target.rowHandle, path: target.path },
      { action: "export", bindingHandle: BINDING, jobHandle: "job-one" },
    ]) {
      expect(isPodFileEvidenceRequest(forged), JSON.stringify(forged)).toBe(false);
    }
  });

  it("accepts a saved result only with its digest and every byte read back", () => {
    expect(isPodFileEvidenceResult(copying)).toBe(true);
    expect(isPodFileEvidenceResult(complete)).toBe(true);
    // An empty file is still a file.
    expect(isPodFileEvidenceResult({ ...complete, copiedBytes: 0, verifiedBytes: 0, totalBytes: 0 })).toBe(true);
    for (const forged of [
      { ...complete, sha256: null },
      { ...complete, verifiedBytes: 899 },
      { ...copying, sha256: "a".repeat(64) },
      { ...copying, verifiedBytes: 1, copiedBytes: 0 },
      { ...copying, folderName: "../elsewhere" },
      { ...copying, pod: "payments" },
      { ...copying, state: "uploading" },
      { ...copying, temporaryFile: "kept" },
      { ...copying, hostPath: "/tmp/lovelyhawk-podfile-x.bin" },
      { ...copying, totalBytes: 512 * 1024 * 1024 + 1 },
    ]) {
      expect(isPodFileEvidenceResult(forged), JSON.stringify(forged)).toBe(false);
    }
  });

  it("matches an answer to the request it answers", () => {
    expect(matchesPodFileEvidenceResult(begin, copying)).toBe(true);
    expect(matchesPodFileEvidenceResult(begin, null)).toBe(true);
    expect(matchesPodFileEvidenceResult(begin, { ...copying, path: "/etc/passwd" })).toBe(false);
    expect(matchesPodFileEvidenceResult(begin, { ...copying, container: null })).toBe(false);
    expect(matchesPodFileEvidenceResult(begin, complete)).toBe(false);
    const poll = { action: "poll", bindingHandle: BINDING, jobHandle: "job-one" } as const;
    expect(matchesPodFileEvidenceResult(poll, complete)).toBe(true);
    expect(matchesPodFileEvidenceResult(poll, null)).toBe(false);
    expect(matchesPodFileEvidenceResult(poll, { ...complete, jobHandle: "job-two" })).toBe(false);
  });
});

describe("pod file kept as evidence", () => {
  it("follows the copy to a verified file, and a closed folder dialog starts nothing", async () => {
    vi.useFakeTimers();
    const dismissed = fixture();
    dismissed.override.begin = async () => null;
    await dismissed.controller.begin(target);
    expect(dismissed.controller.getSnapshot()).toMatchObject({ phase: "ready", result: null });

    const f = fixture();
    await f.controller.begin(target);
    expect(f.podFileEvidence.mock.calls[0]![0]).toEqual({ action: "begin", bindingHandle: BINDING, ...target });
    expect(f.controller.getSnapshot()).toMatchObject({ phase: "running", result: { state: "copying" } });
    f.override.poll = async () => complete;
    await vi.advanceTimersByTimeAsync(1_001);
    expect(f.controller.getSnapshot()).toMatchObject({ phase: "done", result: { sha256: complete.sha256 } });
    await vi.advanceTimersByTimeAsync(60_000);
    expect(f.podFileEvidence.mock.calls.map(([request]) => request.action)).toEqual(["begin", "poll"]);
  });

  it("refuses an answer about another file", async () => {
    const f = fixture();
    f.override.begin = async () => ({ ...copying, path: "/etc/shadow" });
    await f.controller.begin(target);
    expect(f.controller.getSnapshot()).toMatchObject({ phase: "interrupted", result: null });
    expect(f.controller.getSnapshot().error).toContain("对不上");
  });

  it("cancels a running copy when the dialog goes away", async () => {
    const f = fixture();
    await f.controller.begin(target);
    f.controller.dispose();
    expect(f.podFileEvidence.mock.calls.map(([request]) => request.action)).toEqual(["begin", "cancel"]);
  });

  it("says where it is, what was kept and what became of the host's copy", () => {
    const running = renderToStaticMarkup(
      <PodFileEvidencePanel view={{ phase: "running", result: copying, error: null, startedAt: 0 }}
        onCancel={() => undefined} onReset={() => undefined} />,
    );
    expect(running).toContain("正在从 Pod 复制到 SSH 主机");
    expect(running).toContain("取消留证");
    expect(running).toContain("payments/ledger-0 · 容器 app");
    expect(running).toContain("在 SSH 主机的 /tmp，读回后删除");
    const done = renderToStaticMarkup(
      <PodFileEvidencePanel view={{ phase: "done", result: complete, error: null, startedAt: 0 }}
        onCancel={() => undefined} onReset={() => undefined} />,
    );
    expect(done).toContain("已保存为证据");
    expect(done).toContain("a".repeat(64));
    expect(done).toContain("pod-file.bin");
    expect(done).toContain("已删除");
    expect(done).toContain("知道了");
    const left = renderToStaticMarkup(
      <PodFileEvidencePanel view={{ phase: "done", result: { ...cancelled, temporaryFile: "left" }, error: null, startedAt: 0 }}
        onCancel={() => undefined} onReset={() => undefined} />,
    );
    expect(left).toContain("lovelyhawk-podfile-");
    // Nothing is shown before anything is asked.
    expect(renderToStaticMarkup(
      <PodFileEvidencePanel view={{ phase: "ready", result: null, error: null, startedAt: null }}
        onCancel={() => undefined} onReset={() => undefined} />,
    )).toBe("");
  });

  it("offers keeping any listed file as evidence from the pod file dialog", () => {
    const html = renderToStaticMarkup(
      <PodFileDialog api={{
        listKubernetesPodDirectory: vi.fn(async () => ({})),
        readKubernetesPodFile: vi.fn(async () => ({})),
        podFileEvidence: vi.fn(async () => null),
      }} bindingHandle={BINDING} snapshotHandle="s" rowHandle="r" podName="payments/ledger-0" container="app"
        onClose={() => undefined} />,
    );
    expect(html).toContain("“留证”把原始字节经 SSH 主机的 /tmp 复制回本机你选的文件夹");
    expect(html).not.toContain(BINDING);
  });
});
