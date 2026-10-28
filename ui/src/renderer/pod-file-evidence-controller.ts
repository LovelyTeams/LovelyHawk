import {
  matchesPodFileEvidenceResult,
  type PodFileEvidenceApi,
  type PodFileEvidenceRequest,
  type PodFileEvidenceResult,
} from "../shared/pod-file-evidence-contract";
import { EvidenceJobController, type EvidenceJobViewState } from "./evidence-job-controller";

export type PodFileEvidenceViewState = EvidenceJobViewState<PodFileEvidenceResult>;

/**
 * The copy out of the pod plus the file evidence deadline, with room for the
 * round trips.
 */
const COLLECTION_MS = 32 * 60_000;

function running(result: PodFileEvidenceResult): boolean {
  return result.state === "copying" || result.state === "collecting";
}

/** Which pod file, named only the way the list and the dialog name it. */
export interface PodFileEvidenceTarget {
  snapshotHandle: string;
  rowHandle: string;
  container: string | null;
  path: string;
}

/**
 * One pod file kept as evidence, for one connection. The dialog that shows it
 * disposes it on close, which cancels a job still running.
 */
export class PodFileEvidenceController extends EvidenceJobController<PodFileEvidenceResult, PodFileEvidenceTarget> {
  constructor(api: PodFileEvidenceApi, binding: string, now: () => number = Date.now) {
    const request = async (request: PodFileEvidenceRequest): Promise<PodFileEvidenceResult | null> => {
      const result = await api.podFileEvidence(request);
      if (!matchesPodFileEvidenceResult(request, result)) {
        throw new Error("Pod 文件留证的结果与这次请求对不上，请刷新 Pod 列表后再试。");
      }
      return result;
    };
    super({
      begin: (bindingHandle, target) => request({ action: "begin", bindingHandle, ...target }),
      poll: (bindingHandle, jobHandle) => request({ action: "poll", bindingHandle, jobHandle }),
      cancel: (bindingHandle, jobHandle) => request({ action: "cancel", bindingHandle, jobHandle }),
      running,
      sameJob: (previous, next) => next.folderName === previous.folderName &&
        next.targetLabel === previous.targetLabel && next.caseTitle === previous.caseTitle &&
        next.pod === previous.pod && next.container === previous.container && next.path === previous.path,
      changedMessage: "连接或留证位置已变化，已停止展示这次 Pod 文件留证。",
      unreachableMessage: "读不到 Pod 文件留证的进度，请检查连接。",
    }, binding, now);
  }

  begin = (target: PodFileEvidenceTarget): Promise<void> => this.start(target, COLLECTION_MS);
}
