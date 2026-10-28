import { isPacketCaptureOpaqueHandle, isPacketCaptureStartInput, type PacketCaptureStartInput } from "./packet-capture-live-contract.js";

/**
 * A packet capture kept as evidence. The page names the interface only by the
 * handle the live capture surface gave it; the folder is chosen in the host's
 * own dialog and never passes through the page.
 */
export type PacketCaptureEvidenceRequest =
  | { action: "begin"; bindingHandle: string; interfaceHandle: string; input: PacketCaptureStartInput }
  | { action: "poll" | "cancel"; bindingHandle: string; jobHandle: string };

export type PacketCaptureEvidenceState = "capturing" | "collecting" | "completed" | "saved-unlinked" | "failed" | "cancelled";
export type PacketCaptureTemporaryFile = "pending" | "removed" | "left" | "none";

export interface PacketCaptureEvidenceResult {
  jobHandle: string;
  interface: string;
  durationSeconds: number;
  packetLimit: number | null;
  filtered: boolean;
  targetLabel: string;
  folderName: string;
  caseTitle: string;
  state: PacketCaptureEvidenceState;
  copiedBytes: number;
  verifiedBytes: number;
  totalBytes: number;
  sha256: string | null;
  detail: string;
  /** tcpdump's own last line when it refused: the target's text, shown as text. */
  tcpdumpLine: string | null;
  temporaryFile: PacketCaptureTemporaryFile;
}

export interface PacketCaptureEvidenceApi {
  packetCaptureEvidence(request: PacketCaptureEvidenceRequest): Promise<PacketCaptureEvidenceResult | null>;
}

const encoder = new TextEncoder();
const STATES = ["capturing", "collecting", "completed", "saved-unlinked", "failed", "cancelled"];
const TEMPORARY = ["pending", "removed", "left", "none"];
const MAX_EVIDENCE_BYTES = 512 * 1024 * 1024;

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

export function isPacketCaptureEvidenceRequest(value: unknown): value is PacketCaptureEvidenceRequest {
  if (!record(value) || typeof value.action !== "string") return false;
  if (value.action === "begin") {
    return exact(value, ["action", "bindingHandle", "interfaceHandle", "input"]) &&
      isPacketCaptureOpaqueHandle(value.bindingHandle) && isPacketCaptureOpaqueHandle(value.interfaceHandle) &&
      isPacketCaptureStartInput(value.input);
  }
  return (value.action === "poll" || value.action === "cancel") &&
    exact(value, ["action", "bindingHandle", "jobHandle"]) &&
    isPacketCaptureOpaqueHandle(value.bindingHandle) && text(value.jobHandle, 128);
}

export function isPacketCaptureEvidenceResult(value: unknown): value is PacketCaptureEvidenceResult {
  if (!record(value) || !exact(value, [
    "jobHandle", "interface", "durationSeconds", "packetLimit", "filtered", "targetLabel", "folderName", "caseTitle",
    "state", "copiedBytes", "verifiedBytes", "totalBytes", "sha256", "detail", "tcpdumpLine", "temporaryFile",
  ])) return false;
  if (!text(value.jobHandle, 128) ||
    typeof value.interface !== "string" || !/^[A-Za-z0-9_.:@-]{1,64}$/u.test(value.interface) ||
    typeof value.durationSeconds !== "number" || !Number.isSafeInteger(value.durationSeconds) ||
    value.durationSeconds < 1 || value.durationSeconds > 300 ||
    !(value.packetLimit === null || typeof value.packetLimit === "number" && Number.isSafeInteger(value.packetLimit) &&
      value.packetLimit >= 1 && value.packetLimit <= 100_000) ||
    typeof value.filtered !== "boolean" ||
    !text(value.targetLabel, 1024) || !text(value.caseTitle, 1024) || !text(value.detail, 2048) ||
    typeof value.folderName !== "string" || !/^LovelyHawk-evidence-[a-f0-9-]{36}$/u.test(value.folderName) ||
    !STATES.includes(String(value.state)) || !TEMPORARY.includes(String(value.temporaryFile)) ||
    !(value.tcpdumpLine === null || text(value.tcpdumpLine, 512)) ||
    !bytes(value.copiedBytes) || !bytes(value.verifiedBytes) || !bytes(value.totalBytes) ||
    value.copiedBytes > value.totalBytes || value.verifiedBytes > value.copiedBytes) return false;
  // Only a refusal carries tcpdump's words, and only while nothing is kept.
  if (value.tcpdumpLine !== null && value.state !== "failed") return false;
  const saved = value.state === "completed" || value.state === "saved-unlinked";
  return saved
    ? typeof value.sha256 === "string" && /^[a-f0-9]{64}$/u.test(value.sha256) && value.totalBytes > 0 &&
      value.copiedBytes === value.totalBytes && value.verifiedBytes === value.totalBytes
    : value.sha256 === null;
}

export function matchesPacketCaptureEvidenceResult(
  request: PacketCaptureEvidenceRequest,
  result: unknown,
): result is PacketCaptureEvidenceResult | null {
  if (result === null) return request.action === "begin";
  if (!isPacketCaptureEvidenceResult(result)) return false;
  if (request.action !== "begin") return result.jobHandle === request.jobHandle;
  return result.state === "capturing" && result.durationSeconds === request.input.durationSeconds &&
    result.packetLimit === request.input.packetLimit && result.filtered === (request.input.filter !== null);
}
