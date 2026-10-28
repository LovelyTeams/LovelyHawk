import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { PacketCaptureEvidenceRequest, PacketCaptureEvidenceResult } from "../shared/packet-capture-evidence-contract";
import { PacketCaptureEvidenceController } from "./packet-capture-evidence-controller";
import { PacketCaptureEvidencePanel } from "./PacketCaptureEvidencePanel";

const INTERFACE = "00000000-0000-4000-8000-000000000002";
const input = { filter: "icmp", packetLimit: 6, durationSeconds: 20 };
const capturing: PacketCaptureEvidenceResult = {
  jobHandle: "job-one", interface: "eth0", durationSeconds: 20, packetLimit: 6, filtered: true,
  targetLabel: "root@192.0.2.10:22", folderName: "LovelyHawk-evidence-12345678-1234-4234-8234-123456789012",
  caseTitle: "测试案件", state: "capturing", copiedBytes: 0, verifiedBytes: 0, totalBytes: 0, sha256: null,
  detail: "正在目标上抓包", tcpdumpLine: null, temporaryFile: "pending",
};
const complete: PacketCaptureEvidenceResult = {
  ...capturing, state: "completed", copiedBytes: 900, verifiedBytes: 900, totalBytes: 900,
  sha256: "a".repeat(64), detail: "已保存", temporaryFile: "removed",
};
const cancelled: PacketCaptureEvidenceResult = { ...capturing, state: "cancelled", detail: "已取消" };

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

const controllers: PacketCaptureEvidenceController[] = [];
function fixture() {
  const override: Partial<Record<PacketCaptureEvidenceRequest["action"], () => Promise<PacketCaptureEvidenceResult | null>>> = {};
  const packetCaptureEvidence = vi.fn(async (request: PacketCaptureEvidenceRequest) =>
    override[request.action] ? override[request.action]!() : request.action === "cancel" ? cancelled : capturing);
  const controller = new PacketCaptureEvidenceController({ packetCaptureEvidence }, "binding-one");
  controllers.push(controller);
  return { controller, packetCaptureEvidence, override };
}

afterEach(() => {
  controllers.forEach((controller) => controller.dispose());
  controllers.length = 0;
  vi.useRealTimers();
});

describe("packet capture kept as evidence", () => {
  it("starts once, and a closed folder dialog starts nothing", async () => {
    const f = fixture();
    const pending = deferred<PacketCaptureEvidenceResult | null>();
    f.override.begin = () => pending.promise;
    const start = f.controller.begin(INTERFACE, input);
    await f.controller.begin(INTERFACE, input);
    expect(f.packetCaptureEvidence).toHaveBeenCalledTimes(1);
    expect(f.controller.getSnapshot().phase).toBe("choosing");
    pending.resolve(null);
    await start;
    expect(f.controller.getSnapshot()).toMatchObject({ phase: "ready", result: null, error: null });
  });

  it("follows the capture to a verified file and stops asking", async () => {
    vi.useFakeTimers();
    const f = fixture();
    await f.controller.begin(INTERFACE, input);
    expect(f.controller.getSnapshot()).toMatchObject({ phase: "running", result: { state: "capturing" } });
    f.override.poll = async () => complete;
    await vi.advanceTimersByTimeAsync(1_001);
    expect(f.controller.getSnapshot()).toMatchObject({ phase: "done", result: { sha256: complete.sha256 } });
    await vi.advanceTimersByTimeAsync(60_000);
    expect(f.packetCaptureEvidence.mock.calls.map(([request]) => request.action)).toEqual(["begin", "poll"]);
  });

  it("cancels, then looks once more to say whether the target's file went", async () => {
    vi.useFakeTimers();
    const f = fixture();
    await f.controller.begin(INTERFACE, input);
    await f.controller.cancel();
    expect(f.controller.getSnapshot()).toMatchObject({ phase: "done", result: { state: "cancelled", temporaryFile: "pending" } });
    f.override.poll = async () => ({ ...cancelled, temporaryFile: "removed" });
    await vi.advanceTimersByTimeAsync(1_001);
    expect(f.controller.getSnapshot().result?.temporaryFile).toBe("removed");
    await vi.advanceTimersByTimeAsync(60_000);
    expect(f.packetCaptureEvidence.mock.calls.map(([request]) => request.action)).toEqual(["begin", "cancel", "poll"]);
  });

  it("keeps a cancel final when an older progress answer arrives after it", async () => {
    const f = fixture();
    await f.controller.begin(INTERFACE, input);
    const pending = deferred<PacketCaptureEvidenceResult | null>();
    f.override.poll = () => pending.promise;
    const poll = f.controller.poll();
    await f.controller.cancel();
    pending.resolve(capturing);
    await poll;
    expect(f.controller.getSnapshot().result?.state).toBe("cancelled");
  });

  it("refuses an answer about another job or folder and never starts again to recover", async () => {
    const f = fixture();
    await f.controller.begin(INTERFACE, input);
    f.override.poll = async () => ({ ...capturing, folderName: capturing.folderName.replace("12345678", "87654321") });
    await f.controller.poll();
    expect(f.controller.getSnapshot().phase).toBe("interrupted");
    expect(f.controller.getSnapshot().result?.folderName).toBe(capturing.folderName);
    expect(f.packetCaptureEvidence.mock.calls.filter(([request]) => request.action === "begin")).toHaveLength(1);
  });

  it("cancels a capture still running when the page or connection goes away", async () => {
    const f = fixture();
    await f.controller.begin(INTERFACE, input);
    f.controller.dispose();
    expect(f.packetCaptureEvidence.mock.calls.at(-1)?.[0]).toEqual({ action: "cancel", bindingHandle: "binding-one", jobHandle: "job-one" });
    const late = fixture();
    const pending = deferred<PacketCaptureEvidenceResult | null>();
    late.override.begin = () => pending.promise;
    const begin = late.controller.begin(INTERFACE, input);
    late.controller.dispose();
    pending.resolve(capturing);
    await begin;
    expect(late.packetCaptureEvidence.mock.calls.map(([request]) => request.action)).toEqual(["begin", "cancel"]);
    expect(late.controller.getSnapshot().result).toBeNull();
  });

  it("gives up and cancels a capture that outlives its own time and the collection deadline", async () => {
    vi.useFakeTimers();
    const f = fixture();
    await f.controller.begin(INTERFACE, input);
    let cancelledOnce = false;
    f.override.cancel = async () => { cancelledOnce = true; return cancelled; };
    f.override.poll = async () => (cancelledOnce ? { ...cancelled, temporaryFile: "removed" } : capturing);
    await vi.advanceTimersByTimeAsync(20_000 + 16 * 60_000 + 2_000);
    expect(f.packetCaptureEvidence.mock.calls.some(([request]) => request.action === "cancel")).toBe(true);
    expect(f.controller.getSnapshot().result?.state).toBe("cancelled");
  });
});

describe("packet capture evidence panel", () => {
  const ready = { phase: "ready" as const, result: null, error: null, startedAt: null };
  const noop = () => undefined;

  it("says what keeping a capture does before anything starts, and why it cannot yet", () => {
    const html = renderToStaticMarkup(<PacketCaptureEvidencePanel view={ready} blockedReason="先在上面选一块网卡。"
      onBegin={noop} onCancel={noop} onReset={noop} />);
    expect(html).toContain("抓包并保存…");
    expect(html).toContain("capture.pcap");
    expect(html).toContain("root 或能免密码 sudo");
    expect(html).toContain("/tmp");
    expect(html).toContain("先在上面选一块网卡。");
    const begin = html.match(/<button[^>]*data-testid="packet-capture-evidence-begin"[^>]*>/u)?.[0] ?? "";
    expect(begin).toContain("disabled=\"\"");
  });

  it("shows the kept file's digest, case and the target's file going away", () => {
    const html = renderToStaticMarkup(<PacketCaptureEvidencePanel view={{ phase: "done", result: complete, error: null, startedAt: 1 }}
      blockedReason={null} onBegin={noop} onCancel={noop} onReset={noop} />);
    expect(html).toContain("已保存为证据");
    expect(html).toContain(complete.sha256!);
    expect(html).toContain("测试案件");
    expect(html).toContain(complete.folderName);
    expect(html).toContain("已删除");
    expect(html).toContain("知道了");
  });

  it("quotes tcpdump's refusal as text, never as markup", () => {
    const refused: PacketCaptureEvidenceResult = {
      ...capturing, state: "failed", detail: "tcpdump 没有完成这次抓包", temporaryFile: "none",
      tcpdumpLine: "tcpdump: <img src=x onerror=alert(1)> syntax error",
    };
    const html = renderToStaticMarkup(<PacketCaptureEvidencePanel view={{ phase: "done", result: refused, error: null, startedAt: 1 }}
      blockedReason={null} onBegin={noop} onCancel={noop} onReset={noop} />);
    expect(html).toContain("tcpdump 的原话");
    expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
    expect(html).not.toContain("<img");
    expect(html).toContain("没有留下");
  });

  it("offers cancel while capturing and says how long it may take", () => {
    const html = renderToStaticMarkup(<PacketCaptureEvidencePanel view={{ phase: "running", result: capturing, error: null, startedAt: Date.now() }}
      blockedReason={null} onBegin={noop} onCancel={noop} onReset={noop} />);
    expect(html).toContain("正在抓包");
    expect(html).toContain("最长 20 秒");
    expect(html).toContain("抓满 6 个包");
    expect(html).toContain("data-testid=\"packet-capture-evidence-cancel\"");
    expect(html).not.toContain("抓包并保存…");
  });
});
