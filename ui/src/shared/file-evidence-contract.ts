export type FileEvidenceRequest =
  | { action: "begin"; bindingHandle: string; pathHandle: string }
  | { action: "poll" | "cancel"; bindingHandle: string; jobHandle: string };

export interface FileEvidenceResult {
  jobHandle: string;
  pathHandle: string;
  path: string;
  targetLabel: string;
  folderName: string;
  caseTitle: string;
  state: "collecting" | "completed" | "saved-unlinked" | "failed" | "cancelled";
  copiedBytes: number;
  verifiedBytes: number;
  totalBytes: number;
  sha256: string | null;
  detail: string;
}
export interface FileEvidenceApi {
  fileEvidence(request: FileEvidenceRequest): Promise<FileEvidenceResult | null>;
}
const encoder = new TextEncoder();
function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function text(value: unknown, maximum: number): value is string {
  return typeof value === "string" && value.trim().length > 0 && encoder.encode(value).length <= maximum &&
    ![...value].some((char) => { const code = char.codePointAt(0)!; return code < 0x20 || code >= 0x7f && code <= 0x9f; });
}
export function isFileEvidenceRequest(value: unknown): value is FileEvidenceRequest {
  if (!record(value) || typeof value.action !== "string" || !["begin", "poll", "cancel"].includes(value.action)) return false;
  const key = value.action === "begin" ? "pathHandle" : "jobHandle";
  return Object.keys(value).length === 3 && Object.hasOwn(value, key) &&
    Object.hasOwn(value, "action") && Object.hasOwn(value, "bindingHandle") && text(value.bindingHandle, 128) && text(value[key], 128);
}
function bytes(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= 512 * 1024 * 1024;
}
export function isFileEvidenceResult(value: unknown): value is FileEvidenceResult {
  if (!record(value)) return false;
  const keys = ["jobHandle", "pathHandle", "path", "targetLabel", "folderName", "caseTitle", "state", "copiedBytes", "verifiedBytes", "totalBytes", "sha256", "detail"];
  if (Object.keys(value).length !== keys.length || !keys.every((key) => Object.hasOwn(value, key)) ||
    !text(value.jobHandle, 128) || !text(value.pathHandle, 128) || !text(value.path, 4096) || !value.path.startsWith("/") ||
    !text(value.targetLabel, 1024) || !text(value.caseTitle, 1024) || !text(value.detail, 2048) ||
    typeof value.folderName !== "string" || !/^LovelyHawk-evidence-[a-f0-9-]{36}$/u.test(value.folderName) ||
    !["collecting", "completed", "saved-unlinked", "failed", "cancelled"].includes(String(value.state)) ||
    !bytes(value.copiedBytes) || !bytes(value.verifiedBytes) || !bytes(value.totalBytes) ||
    value.copiedBytes > value.totalBytes || value.verifiedBytes > value.copiedBytes) return false;
  const saved = value.state === "completed" || value.state === "saved-unlinked";
  return saved ? typeof value.sha256 === "string" && /^[a-f0-9]{64}$/u.test(value.sha256) &&
    value.copiedBytes === value.totalBytes && value.verifiedBytes === value.totalBytes : value.sha256 === null;
}
export function matchesFileEvidenceResult(request: FileEvidenceRequest, result: unknown): result is FileEvidenceResult | null {
  if (result === null) return request.action === "begin";
  return isFileEvidenceResult(result) && (request.action === "begin" ? result.pathHandle === request.pathHandle : result.jobHandle === request.jobHandle);
}
