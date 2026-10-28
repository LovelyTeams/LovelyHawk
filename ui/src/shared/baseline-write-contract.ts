import { isBaselineOpaqueHandle } from "./baseline-read-contract.js";

/**
 * Changing baseline settings, and putting a change back from its history.
 *
 * The page names settings only by catalogue item handles and history entries
 * only by the handles a history snapshot minted, plus the value it wants for
 * each setting. It never names a file, a command or a reload of its own.
 */
export type BaselineReloadChoice = "defer" | "apply-now";

export interface BaselineChangeInput {
  itemHandle: string;
  value: string;
}

export type BaselineAction =
  | { kind: "change"; changes: BaselineChangeInput[]; reload: BaselineReloadChoice }
  | { kind: "restore"; historyHandle: string; historyItemHandle: string };

export interface BaselinePlannedChange {
  itemHandle: string;
  /** What the scan found, in words ("未设置") or as the value it read. */
  before: string;
  after: string;
  file: string;
}

export interface BaselinePlan {
  planHandle: string;
  action: BaselineAction["kind"];
  summary: string;
  /** The settings a change plan writes; empty for a restore. */
  changes: BaselinePlannedChange[];
  /** The complete files the plan writes, backs up or puts back. */
  files: string[];
  /** What happens to the running program afterwards; null for a restore. */
  reload: string | null;
  dangerous: boolean;
  restoreDescription: string | null;
  confirmed: boolean;
  expiresInSeconds: number;
}

export interface BaselineReceipt {
  planHandle: string;
  action: BaselineAction["kind"];
  files: string[];
  /** Whether an independent read-back found the files as planned. */
  verified: boolean;
  detail: string;
  /** The plan's own backups were put back after a failed check. */
  restored: boolean;
}

export interface BaselineActionCancellation {
  cancelled: boolean;
}

export interface BaselineWriteApi {
  planBaselineAction(bindingHandle: string, action: BaselineAction): Promise<unknown>;
  confirmBaselineAction(bindingHandle: string, planHandle: string): Promise<unknown>;
  executeBaselineAction(bindingHandle: string, planHandle: string): Promise<unknown>;
  cancelBaselineAction(bindingHandle: string, planHandle: string): Promise<unknown>;
}

export const MAX_BASELINE_ACTION_CHANGES = 16;
const encoder = new TextEncoder();
const KINDS: readonly string[] = ["change", "restore"];
/** The backend's bound on plan text, plus the ellipsis it adds when it cuts. */
const MAX_TEXT_BYTES = 2_048 + 3;

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function exact(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}
function text(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0 && encoder.encode(value).length <= MAX_TEXT_BYTES;
}
function value(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0 && encoder.encode(value).length <= 256 &&
    !/[\u0000-\u001f\u007f]/u.test(value);
}

export function isBaselineAction(input: unknown): input is BaselineAction {
  if (!record(input)) return false;
  if (input.kind === "restore") {
    return exact(input, ["kind", "historyHandle", "historyItemHandle"]) &&
      isBaselineOpaqueHandle(input.historyHandle) && isBaselineOpaqueHandle(input.historyItemHandle);
  }
  if (input.kind !== "change" || !exact(input, ["kind", "changes", "reload"]) ||
    (input.reload !== "defer" && input.reload !== "apply-now") || !Array.isArray(input.changes) ||
    input.changes.length < 1 || input.changes.length > MAX_BASELINE_ACTION_CHANGES) return false;
  const handles = new Set<string>();
  for (const change of input.changes) {
    if (!record(change) || !exact(change, ["itemHandle", "value"]) || !isBaselineOpaqueHandle(change.itemHandle) ||
      !value(change.value) || handles.has(change.itemHandle)) return false;
    handles.add(change.itemHandle);
  }
  return true;
}

function plannedChange(input: unknown): input is BaselinePlannedChange {
  return record(input) && exact(input, ["itemHandle", "before", "after", "file"]) &&
    isBaselineOpaqueHandle(input.itemHandle) && text(input.before) && text(input.after) && text(input.file);
}

function files(input: unknown, minimum: number): input is string[] {
  return Array.isArray(input) && input.length >= minimum && input.length <= 64 && input.every(text);
}

export function isBaselinePlan(input: unknown): input is BaselinePlan {
  if (!record(input) || !exact(input, [
    "planHandle", "action", "summary", "changes", "files", "reload", "dangerous", "restoreDescription", "confirmed",
    "expiresInSeconds",
  ]) || !isBaselineOpaqueHandle(input.planHandle) || !KINDS.includes(String(input.action)) ||
    !text(input.summary) || !Array.isArray(input.changes) || input.changes.length > MAX_BASELINE_ACTION_CHANGES ||
    !input.changes.every(plannedChange) || !files(input.files, 1) ||
    typeof input.dangerous !== "boolean" ||
    !(input.restoreDescription === null || text(input.restoreDescription)) ||
    typeof input.confirmed !== "boolean" ||
    typeof input.expiresInSeconds !== "number" || !Number.isSafeInteger(input.expiresInSeconds) ||
    input.expiresInSeconds < 1 || input.expiresInSeconds > 300) return false;
  // A change names what it writes and how the program picks it up; a restore
  // names only the files it puts back.
  return input.action === "change"
    ? input.changes.length >= 1 && text(input.reload)
    : input.changes.length === 0 && input.reload === null;
}

export function isBaselineReceipt(input: unknown): input is BaselineReceipt {
  return record(input) && exact(input, ["planHandle", "action", "files", "verified", "detail", "restored"]) &&
    isBaselineOpaqueHandle(input.planHandle) && KINDS.includes(String(input.action)) && files(input.files, 0) &&
    typeof input.verified === "boolean" && text(input.detail) && typeof input.restored === "boolean" &&
    !(input.verified && input.restored);
}

export function isBaselineActionCancellation(input: unknown): input is BaselineActionCancellation {
  return record(input) && exact(input, ["cancelled"]) && input.cancelled === true;
}
