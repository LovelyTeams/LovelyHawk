import type { PacketCaptureStartInput } from "../shared/packet-capture-live-contract";
import {
  matchesPacketCaptureEvidenceResult,
  type PacketCaptureEvidenceApi,
  type PacketCaptureEvidenceRequest,
  type PacketCaptureEvidenceResult,
} from "../shared/packet-capture-evidence-contract";
import { EvidenceJobController, type EvidenceJobViewState } from "./evidence-job-controller";

export type PacketCaptureEvidenceViewState = EvidenceJobViewState<PacketCaptureEvidenceResult>;

/** Capture time plus the file evidence deadline, with room for the round trips. */
const COLLECTION_MS = 16 * 60_000;

function running(result: PacketCaptureEvidenceResult): boolean {
  return result.state === "capturing" || result.state === "collecting";
}

/**
 * One packet capture kept as evidence, for one connection.
 *
 * It owns its job: leaving the page or the connection disposes it, and a job
 * still running is cancelled so nothing goes on capturing that no page shows.
 */
export class PacketCaptureEvidenceController extends EvidenceJobController<
  PacketCaptureEvidenceResult,
  { interfaceHandle: string; input: PacketCaptureStartInput }
> {
  constructor(api: PacketCaptureEvidenceApi, binding: string, now: () => number = Date.now) {
    const request = async (request: PacketCaptureEvidenceRequest): Promise<PacketCaptureEvidenceResult | null> => {
      const result = await api.packetCaptureEvidence(request);
      if (!matchesPacketCaptureEvidenceResult(request, result)) {
        throw new Error("抓包留证的结果与这次请求对不上，请重新读取网卡后再试。");
      }
      return result;
    };
    super({
      begin: (bindingHandle, { interfaceHandle, input }) =>
        request({ action: "begin", bindingHandle, interfaceHandle, input }),
      poll: (bindingHandle, jobHandle) => request({ action: "poll", bindingHandle, jobHandle }),
      cancel: (bindingHandle, jobHandle) => request({ action: "cancel", bindingHandle, jobHandle }),
      running,
      sameJob: (previous, next) => next.folderName === previous.folderName &&
        next.targetLabel === previous.targetLabel && next.caseTitle === previous.caseTitle &&
        next.interface === previous.interface,
      changedMessage: "连接或留证位置已变化，已停止展示这次抓包留证。",
      unreachableMessage: "读不到抓包留证的进度，请检查连接。",
    }, binding, now);
  }

  begin = (interfaceHandle: string, input: PacketCaptureStartInput): Promise<void> =>
    this.start({ interfaceHandle, input }, input.durationSeconds * 1_000 + COLLECTION_MS);
}
