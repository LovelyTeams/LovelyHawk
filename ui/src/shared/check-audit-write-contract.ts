import { isCheckAuditCommandName, isCheckAuditOpaqueHandle } from "./check-audit-read-contract.js";

/**
 * Adding command collection, taking it off, and clearing the collected log.
 *
 * The page names commands only by the handles its own catalog snapshot
 * minted, and a plan only by the handle the backend minted. It never names a
 * path or a program, so the worst it can ask for is a change to a command the
 * operator is already looking at — and only after approving that exact plan.
 */
export type CheckAuditAction =
  | { kind: "collect"; commandHandles: string[] }
  | { kind: "uncollect"; commandHandles: string[] }
  | { kind: "clear-log" };

export const MAX_CHECK_AUDIT_ACTION_COMMANDS = 32;

export interface CheckAuditPlan {
  planHandle: string;
  action: CheckAuditAction["kind"];
  summary: string;
  /** The commands the plan changes; display only. */
  commands: string[];
  dangerous: boolean;
  restoreDescription: string | null;
  confirmed: boolean;
  expiresInSeconds: number;
}

export interface CheckAuditReceipt {
  planHandle: string;
  action: CheckAuditAction["kind"];
  commands: string[];
  /** Whether the target, read back afterwards, is in the planned state. */
  verified: boolean;
  detail: string;
  restored: boolean;
}

export interface CheckAuditActionCancellation {
  cancelled: boolean;
}

export interface CheckAuditWriteApi {
  planCheckAuditAction(bindingHandle: string, snapshotHandle: string, action: CheckAuditAction): Promise<unknown>;
  confirmCheckAuditAction(bindingHandle: string, planHandle: string): Promise<unknown>;
  executeCheckAuditAction(bindingHandle: string, planHandle: string): Promise<unknown>;
  cancelCheckAuditAction(bindingHandle: string, planHandle: string): Promise<unknown>;
}

const encoder = new TextEncoder();
const KINDS: readonly string[] = ["collect", "uncollect", "clear-log"];
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
function commands(value: unknown, minimum: number): value is string[] {
  return Array.isArray(value) && value.length >= minimum && value.length <= MAX_CHECK_AUDIT_ACTION_COMMANDS &&
    value.every(isCheckAuditCommandName) && new Set(value).size === value.length;
}

export function isCheckAuditAction(value: unknown): value is CheckAuditAction {
  if (!record(value)) return false;
  if (value.kind === "clear-log") return exact(value, ["kind"]);
  return (value.kind === "collect" || value.kind === "uncollect") && exact(value, ["kind", "commandHandles"]) &&
    Array.isArray(value.commandHandles) && value.commandHandles.length >= 1 &&
    value.commandHandles.length <= MAX_CHECK_AUDIT_ACTION_COMMANDS &&
    value.commandHandles.every(isCheckAuditOpaqueHandle) &&
    new Set(value.commandHandles).size === value.commandHandles.length;
}

export function isCheckAuditPlan(value: unknown): value is CheckAuditPlan {
  return record(value) && exact(value, [
    "planHandle", "action", "summary", "commands", "dangerous", "restoreDescription", "confirmed", "expiresInSeconds",
  ]) && isCheckAuditOpaqueHandle(value.planHandle) && KINDS.includes(String(value.action)) &&
    text(value.summary) && commands(value.commands, value.action === "clear-log" ? 0 : 1) &&
    typeof value.dangerous === "boolean" &&
    (value.restoreDescription === null || text(value.restoreDescription)) &&
    typeof value.confirmed === "boolean" &&
    typeof value.expiresInSeconds === "number" && Number.isSafeInteger(value.expiresInSeconds) &&
    value.expiresInSeconds >= 1 && value.expiresInSeconds <= 300;
}

export function isCheckAuditReceipt(value: unknown): value is CheckAuditReceipt {
  return record(value) && exact(value, ["planHandle", "action", "commands", "verified", "detail", "restored"]) &&
    isCheckAuditOpaqueHandle(value.planHandle) && KINDS.includes(String(value.action)) &&
    commands(value.commands, 0) && typeof value.verified === "boolean" && text(value.detail) &&
    typeof value.restored === "boolean" && !(value.verified && value.restored);
}

export function isCheckAuditActionCancellation(value: unknown): value is CheckAuditActionCancellation {
  return record(value) && exact(value, ["cancelled"]) && value.cancelled === true;
}
