import { isExecFilePath } from "./exec-files-contract.js";
import { isKubernetesContainerName, isKubernetesOpaqueHandle } from "./kubernetes-read-contract.js";

/**
 * A file inside a pod kept as case evidence. The pod is named only by the
 * list's handles and the container by one of that pod's names; the folder is
 * chosen in the host's own dialog and never passes through the page.
 */
export type PodFileEvidenceRequest =
  | {
    action: "begin";
    bindingHandle: string;
    snapshotHandle: string;
    rowHandle: string;
    /** One of the pod's containers; null for its default one. */
    container: string | null;
    path: string;
  }
  | { action: "poll" | "cancel"; bindingHandle: string; jobHandle: string };

export type PodFileEvidenceState = "copying" | "collecting" | "completed" | "saved-unlinked" | "failed" | "cancelled";
export type PodFileTemporaryFile = "pending" | "removed" | "left" | "none";

export interface PodFileEvidenceResult {
  jobHandle: string;
  /** `namespace/name`, as listed. */
  pod: string;
  container: string | null;
  path: string;
  targetLabel: string;
  folderName: string;
  caseTitle: string;
  state: PodFileEvidenceState;
  copiedBytes: number;
  verifiedBytes: number;
  totalBytes: number;
  sha256: string | null;
  detail: string;
  temporaryFile: PodFileTemporaryFile;
}

export interface PodFileEvidenceApi {
  podFileEvidence(request: PodFileEvidenceRequest): Promise<PodFileEvidenceResult | null>;
}

const encoder = new TextEncoder();
const STATES: readonly string[] = ["copying", "collecting", "completed", "saved-unlinked", "failed", "cancelled"];
const TEMPORARY: readonly string[] = ["pending", "removed", "left", "none"];
const MAX_EVIDENCE_BYTES = 512 * 1024 * 1024;
const POD = /^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?\/[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?$/u;

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function exact(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}
function text(value: unknown, maximum: number): value is string {
  return typeof value === "string" && value.trim().length > 0 && encoder.encode(value).length <= maximum &&
    ![...value].some((char) => { const code = char.codePointAt(0)!; return code < 0x20 || code >= 0x7f && code <= 0x9f; });
}
function bytes(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= MAX_EVIDENCE_BYTES;
}

export function isPodFileEvidenceRequest(value: unknown): value is PodFileEvidenceRequest {
  if (!record(value) || typeof value.action !== "string") return false;
  if (value.action === "begin") {
    return exact(value, ["action", "bindingHandle", "snapshotHandle", "rowHandle", "container", "path"]) &&
      isKubernetesOpaqueHandle(value.bindingHandle) && isKubernetesOpaqueHandle(value.snapshotHandle) &&
      isKubernetesOpaqueHandle(value.rowHandle) &&
      (value.container === null || isKubernetesContainerName(value.container)) &&
      isExecFilePath(value.path);
  }
  return (value.action === "poll" || value.action === "cancel") &&
    exact(value, ["action", "bindingHandle", "jobHandle"]) &&
    isKubernetesOpaqueHandle(value.bindingHandle) && text(value.jobHandle, 128);
}

export function isPodFileEvidenceResult(value: unknown): value is PodFileEvidenceResult {
  if (!record(value) || !exact(value, [
    "jobHandle", "pod", "container", "path", "targetLabel", "folderName", "caseTitle",
    "state", "copiedBytes", "verifiedBytes", "totalBytes", "sha256", "detail", "temporaryFile",
  ])) return false;
  if (!text(value.jobHandle, 128) ||
    typeof value.pod !== "string" || !POD.test(value.pod) ||
    !(value.container === null || isKubernetesContainerName(value.container)) ||
    !isExecFilePath(value.path) ||
    !text(value.targetLabel, 1024) || !text(value.caseTitle, 1024) || !text(value.detail, 2048) ||
    typeof value.folderName !== "string" || !/^LovelyHawk-evidence-[a-f0-9-]{36}$/u.test(value.folderName) ||
    !STATES.includes(String(value.state)) || !TEMPORARY.includes(String(value.temporaryFile)) ||
    !bytes(value.copiedBytes) || !bytes(value.verifiedBytes) || !bytes(value.totalBytes) ||
    value.copiedBytes > value.totalBytes || value.verifiedBytes > value.copiedBytes) return false;
  const saved = value.state === "completed" || value.state === "saved-unlinked";
  return saved
    ? typeof value.sha256 === "string" && /^[a-f0-9]{64}$/u.test(value.sha256) &&
      value.copiedBytes === value.totalBytes && value.verifiedBytes === value.totalBytes
    : value.sha256 === null;
}

export function matchesPodFileEvidenceResult(
  request: PodFileEvidenceRequest,
  result: unknown,
): result is PodFileEvidenceResult | null {
  if (result === null) return request.action === "begin";
  if (!isPodFileEvidenceResult(result)) return false;
  if (request.action !== "begin") return result.jobHandle === request.jobHandle;
  return result.state === "copying" && result.path === request.path && result.container === request.container;
}
