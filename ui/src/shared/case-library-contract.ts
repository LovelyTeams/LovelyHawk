import { isCaseSummary, matchesCaseWorkspaceResult, type CaseSection, type CaseSummary, type CaseWorkspaceResult } from "./case-workspace-contract.js";

export type CaseTransfer = "archive" | "restore";
export type CaseStatusAction = "close" | "reopen";
export type CaseLibraryOperation = CaseTransfer | CaseStatusAction;
export type CaseLibraryRequest =
  | { action: "list" }
  | { action: "view"; itemHandle: string }
  | { action: "items"; snapshotHandle: string; section: CaseSection; query: string; offset: number }
  | { action: "plan"; snapshotHandle: string; operation: CaseTransfer }
  | { action: "status-plan"; snapshotHandle: string; operation: CaseStatusAction; conclusion: string; followup: string }
  | { action: "confirm" | "cancel"; planHandle: string }
  | { action: "export"; snapshotHandle: string };
export interface CaseLibraryItem {
  itemHandle: string; incident: CaseSummary; targetId: string; connectionName: string | null; location: "working" | "archived"; archivedAt: number | null;
}
export type CaseLibraryResult =
  | { kind: "list"; items: CaseLibraryItem[]; workingCount: number; archiveCount: number }
  | { kind: "view"; snapshotHandle: string; item: CaseLibraryItem }
  | Extract<CaseWorkspaceResult, { kind: "items" }>
  | { kind: "plan"; snapshotHandle: string; planHandle: string; operation: CaseLibraryOperation; summary: string; expiresInSeconds: number }
  | { kind: "changed"; planHandle: string; operation: CaseLibraryOperation; caseId: string; verified: boolean; message: string }
  | { kind: "cancelled"; planHandle: string }
  | { kind: "exported"; snapshotHandle: string; filename: string; bytes: number; sha256: string };
export interface CaseLibraryApi { caseLibrary(request: CaseLibraryRequest): Promise<CaseLibraryResult | null> }

export function isCaseLibraryRequest(value: unknown): value is CaseLibraryRequest {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const input = value as Record<string, unknown>;
  const fields = { list: [], view: ["itemHandle"], items: ["snapshotHandle", "section", "query", "offset"],
    plan: ["snapshotHandle", "operation"], "status-plan": ["snapshotHandle", "operation", "conclusion", "followup"], confirm: ["planHandle"], cancel: ["planHandle"], export: ["snapshotHandle"] } as const;
  if (typeof input.action !== "string" || !Object.hasOwn(fields, input.action)) return false;
  const keys = ["action", ...fields[input.action as keyof typeof fields]];
  if (Object.keys(input).length !== keys.length || !keys.every((key) => Object.hasOwn(input, key))) return false;
  const text = (candidate: unknown, max: number, empty = false): candidate is string => typeof candidate === "string" &&
    (empty || candidate.trim().length > 0) && [...candidate].length <= max && !/[\uD800-\uDFFF]/u.test(candidate);
  const handle = (candidate: unknown) => text(candidate, 128) && !/[\u0000-\u001F\u007F-\u009F]/u.test(candidate) && new TextEncoder().encode(candidate).length <= 128;
  switch (input.action) {
    case "list": return true;
    case "view": return handle(input.itemHandle);
    case "items": return handle(input.snapshotHandle) && ["evidence", "iocs", "timeline"].includes(String(input.section)) && text(input.query, 256, true) &&
      typeof input.offset === "number" && Number.isSafeInteger(input.offset) && input.offset >= 0 && input.offset <= 1000;
    case "plan": return handle(input.snapshotHandle) && (input.operation === "archive" || input.operation === "restore");
    case "status-plan": return handle(input.snapshotHandle) && (input.operation === "close" || input.operation === "reopen") && text(input.conclusion, 1024) && text(input.followup, 512);
    case "confirm": case "cancel": return handle(input.planHandle);
    case "export": return handle(input.snapshotHandle);
    default: return false;
  }
}
function record(value: unknown): value is Record<string, unknown> { return value !== null && typeof value === "object" && !Array.isArray(value); }
function keys(value: Record<string, unknown>, expected: string[]): boolean { return Object.keys(value).length === expected.length && expected.every((key) => Object.hasOwn(value, key)); }
function text(value: unknown, maximum: number): value is string { return typeof value === "string" && value.trim().length > 0 && [...value].length <= maximum && !/[\uD800-\uDFFF]/u.test(value); }
function id(value: unknown, maximum = 128): value is string { return text(value, maximum) && !/[\u0000-\u001F\u007F-\u009F]/u.test(value); }
function handle(value: unknown): value is string { return id(value) && new TextEncoder().encode(value).length <= 128; }
function number(value: unknown, max: number): value is number { return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= max; }
function item(value: unknown): value is CaseLibraryItem {
  return record(value) && keys(value, ["itemHandle", "incident", "targetId", "connectionName", "location", "archivedAt"]) && handle(value.itemHandle) && isCaseSummary(value.incident) &&
    id(value.targetId, 256) && new TextEncoder().encode(value.targetId).length <= 256 &&
    (value.connectionName === null || text(value.connectionName, 256)) &&
    (value.location === "working" && value.archivedAt === null || value.location === "archived" && number(value.archivedAt, 8_640_000_000_000_000));
}
export function matchesCaseLibraryResult(request: CaseLibraryRequest, value: unknown): value is CaseLibraryResult | null {
  if (value === null) return request.action === "export";
  if (!record(value)) return false;
  switch (request.action) {
    case "list": return value.kind === "list" && keys(value, ["kind", "items", "workingCount", "archiveCount"]) && Array.isArray(value.items) && value.items.length <= 230 &&
      value.items.every(item) && new Set(value.items.map((item) => item.itemHandle)).size === value.items.length && number(value.workingCount, 30) && number(value.archiveCount, 200) &&
      value.items.filter((item) => item.location === "working").length === value.workingCount && value.items.length === value.workingCount + value.archiveCount;
    case "view": return value.kind === "view" && keys(value, ["kind", "snapshotHandle", "item"]) && handle(value.snapshotHandle) && item(value.item) && value.item.itemHandle === request.itemHandle;
    case "items": return matchesCaseWorkspaceResult({ ...request, bindingHandle: "local-library" }, value);
    case "plan": case "status-plan": return value.kind === "plan" && keys(value, ["kind", "snapshotHandle", "planHandle", "operation", "summary", "expiresInSeconds"]) &&
      value.snapshotHandle === request.snapshotHandle && handle(value.planHandle) && value.operation === request.operation && text(value.summary, 4096) && new TextEncoder().encode(value.summary).length <= 7 * 1024 &&
      typeof value.expiresInSeconds === "number" && value.expiresInSeconds > 0 && number(value.expiresInSeconds, 300);
    case "confirm": return value.kind === "changed" && keys(value, ["kind", "planHandle", "operation", "caseId", "verified", "message"]) && value.planHandle === request.planHandle &&
      ["archive", "restore", "close", "reopen"].includes(String(value.operation)) && id(value.caseId) && typeof value.verified === "boolean" && text(value.message, 1024);
    case "cancel": return value.kind === "cancelled" && keys(value, ["kind", "planHandle"]) && value.planHandle === request.planHandle;
    case "export": return value.kind === "exported" && keys(value, ["kind", "snapshotHandle", "filename", "bytes", "sha256"]) && value.snapshotHandle === request.snapshotHandle &&
      id(value.filename, 1024) && !/[\\/:]/u.test(value.filename) && value.filename.endsWith(".json") && number(value.bytes, 32 * 1024 * 1024) && value.bytes > 0 &&
      typeof value.sha256 === "string" && /^[a-f0-9]{64}$/u.test(value.sha256);
  }
}
