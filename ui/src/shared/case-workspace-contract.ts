import { isDisposalReportSnapshot, type DisposalReportSnapshot } from "./disposal-report-contract.js";

export type CaseSection = "evidence" | "iocs" | "timeline";
export type CaseIocType = "ip" | "domain" | "hash" | "path" | "process" | "user" | "other";
export type CaseWorkspaceRequest =
  | { action: "list"; bindingHandle: string }
  | { action: "create"; bindingHandle: string; title: string; mutationId: string }
  | { action: "select" | "view"; bindingHandle: string; caseId: string }
  | { action: "items"; bindingHandle: string; snapshotHandle: string; section: CaseSection; query: string; offset: number }
  | { action: "note"; bindingHandle: string; caseId: string; title: string; content: string }
  | { action: "ioc"; bindingHandle: string; caseId: string; iocType: CaseIocType; value: string }
  | { action: "attach-note"; bindingHandle: string; caseId: string; noteId: string; revision: string }
  | { action: "report"; bindingHandle: string; snapshotHandle: string };

export interface CaseSummary {
  id: string; title: string; status: "open" | "closed"; createdAt: number; updatedAt: number;
  evidenceCount: number; iocCount: number; timelineCount: number;
}
export interface CaseEntry {
  id: string; category: string; title: string; text: string; source: string;
  locator: string | null; sha256: string | null; hashScope: "stored-preview" | "external-artifact" | null;
  timestamp: number; evidenceId: string | null; iocId: string | null; operationId: string | null;
}
export type CaseWorkspaceResult =
  | { kind: "list"; cases: CaseSummary[]; activeCaseId: string | null; totalCases: number }
  | { kind: "view"; snapshotHandle: string; incident: CaseSummary }
  | { kind: "items"; snapshotHandle: string; section: CaseSection; query: string; offset: number; total: number; hasMore: boolean; items: CaseEntry[] }
  | { kind: "changed"; caseId: string; message: string }
  | { kind: "report"; report: DisposalReportSnapshot };
export interface CaseWorkspaceApi { caseWorkspace(request: CaseWorkspaceRequest): Promise<CaseWorkspaceResult> }

// Self-contained because the sandbox preload mirrors this request guard.
export function isCaseWorkspaceRequest(value: unknown): value is CaseWorkspaceRequest {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const input = value as Record<string, unknown>;
  const fields = { list: [], create: ["title", "mutationId"], select: ["caseId"], view: ["caseId"],
    items: ["snapshotHandle", "section", "query", "offset"], note: ["caseId", "title", "content"],
    ioc: ["caseId", "iocType", "value"], "attach-note": ["caseId", "noteId", "revision"], report: ["snapshotHandle"] } as const;
  if (typeof input.action !== "string" || !Object.hasOwn(fields, input.action)) return false;
  const keys = ["action", "bindingHandle", ...fields[input.action as keyof typeof fields]];
  if (Object.keys(input).length !== keys.length || !keys.every((key) => Object.hasOwn(input, key))) return false;
  const text = (candidate: unknown, max: number, empty = false): candidate is string => typeof candidate === "string" &&
    (empty || candidate.trim().length > 0) && [...candidate].length <= max && !/[\uD800-\uDFFF]/u.test(candidate);
  const id = (candidate: unknown) => text(candidate, 128) && !/[\u0000-\u001F\u007F-\u009F]/u.test(candidate);
  const handle = (candidate: unknown) => id(candidate) && new TextEncoder().encode(candidate as string).length <= 128;
  if (!handle(input.bindingHandle)) return false;
  switch (input.action) {
    case "list": return true;
    case "create": return text(input.title, 160) && typeof input.mutationId === "string" && /^[A-Za-z0-9_-]{16,64}$/u.test(input.mutationId);
    case "select": case "view": return id(input.caseId);
    case "items": return handle(input.snapshotHandle) && ["evidence", "iocs", "timeline"].includes(String(input.section)) && text(input.query, 256, true) &&
      typeof input.offset === "number" && Number.isSafeInteger(input.offset) && input.offset >= 0 && input.offset <= 1000;
    case "note": return id(input.caseId) && text(input.title, 256) && text(input.content, 4096);
    case "ioc": return id(input.caseId) && ["ip", "domain", "hash", "path", "process", "user", "other"].includes(String(input.iocType)) && text(input.value, 2048);
    case "attach-note": return id(input.caseId) && id(input.noteId) && typeof input.revision === "string" && /^[a-f0-9]{64}$/u.test(input.revision);
    case "report": return handle(input.snapshotHandle);
    default: return false;
  }
}

function record(value: unknown): value is Record<string, unknown> { return value !== null && typeof value === "object" && !Array.isArray(value); }
function keys(value: Record<string, unknown>, names: string[]): boolean { return Object.keys(value).length === names.length && names.every((name) => Object.hasOwn(value, name)); }
function text(value: unknown, max: number, empty = false): value is string { return typeof value === "string" && (empty || value.trim().length > 0) && [...value].length <= max && !/[\uD800-\uDFFF]/u.test(value); }
function id(value: unknown): value is string { return text(value, 128) && !/[\u0000-\u001F\u007F-\u009F]/u.test(value); }
function handle(value: unknown): value is string { return id(value) && new TextEncoder().encode(value).length <= 128; }
function number(value: unknown, max = 8_640_000_000_000_000): value is number { return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= max; }
function nullableId(value: unknown): boolean { return value === null || id(value); }
export function isCaseSummary(value: unknown): value is CaseSummary {
  return record(value) && keys(value, ["id", "title", "status", "createdAt", "updatedAt", "evidenceCount", "iocCount", "timelineCount"]) &&
    id(value.id) && text(value.title, 160) && (value.status === "open" || value.status === "closed") && number(value.createdAt) && number(value.updatedAt) &&
    number(value.evidenceCount, 500) && number(value.iocCount, 500) && number(value.timelineCount, 1000);
}
function entry(value: unknown, section: CaseSection): value is CaseEntry {
  if (!record(value) || !keys(value, ["id", "category", "title", "text", "source", "locator", "sha256", "hashScope", "timestamp", "evidenceId", "iocId", "operationId"]) ||
    !id(value.id) || !text(value.title, section === "iocs" ? 2048 : 256) || !text(value.text, 4096, true) || !text(value.source, 160) ||
    !number(value.timestamp) || !nullableId(value.evidenceId) || !nullableId(value.iocId) || !nullableId(value.operationId)) return false;
  if (section === "evidence") return ["finding", "path", "command-output", "snapshot", "pcap", "log", "note", "other"].includes(String(value.category)) &&
    (value.locator === null || text(value.locator, 2048)) && typeof value.sha256 === "string" && /^[a-f0-9]{64}$/u.test(value.sha256) &&
    (value.hashScope === "stored-preview" || value.hashScope === "external-artifact") && value.evidenceId === null && value.iocId === null && value.operationId === null;
  if (value.locator !== null || value.sha256 !== null || value.hashScope !== null) return false;
  return section === "iocs" ? ["ip", "domain", "hash", "path", "process", "user", "other"].includes(String(value.category)) && value.text === "" && value.evidenceId === null && value.iocId === null && value.operationId === null :
    ["case-created", "finding", "evidence", "ioc", "action", "verification", "note"].includes(String(value.category));
}
export function matchesCaseWorkspaceResult(request: CaseWorkspaceRequest, value: unknown): value is CaseWorkspaceResult {
  if (!record(value)) return false;
  if (request.action === "list") return value.kind === "list" && keys(value, ["kind", "cases", "activeCaseId", "totalCases"]) && Array.isArray(value.cases) &&
    value.cases.length <= 30 && value.cases.every(isCaseSummary) && new Set(value.cases.map((item) => item.id)).size === value.cases.length &&
    number(value.totalCases, 30) && value.totalCases >= value.cases.length &&
    (value.activeCaseId === null || value.cases.some((item) => item.id === value.activeCaseId && item.status === "open"));
  if (request.action === "view") return value.kind === "view" && keys(value, ["kind", "snapshotHandle", "incident"]) && handle(value.snapshotHandle) &&
    isCaseSummary(value.incident) && value.incident.id === request.caseId;
  if (request.action === "items") return value.kind === "items" && keys(value, ["kind", "snapshotHandle", "section", "query", "offset", "total", "hasMore", "items"]) &&
    value.snapshotHandle === request.snapshotHandle && value.section === request.section && value.query === request.query && value.offset === request.offset &&
    number(value.total, request.section === "timeline" ? 1000 : 500) && Array.isArray(value.items) && value.items.length <= 25 &&
    value.items.every((item) => entry(item, request.section)) && new Set(value.items.map((item) => item.id)).size === value.items.length &&
    value.items.length === Math.min(25, Math.max(0, value.total - request.offset)) && value.hasMore === (request.offset + value.items.length < value.total);
  if (request.action === "report") return value.kind === "report" && keys(value, ["kind", "report"]) && isDisposalReportSnapshot(value.report) && value.report.incidentIncluded;
  return value.kind === "changed" && keys(value, ["kind", "caseId", "message"]) && id(value.caseId) && text(value.message, 512) &&
    (request.action === "create" || value.caseId === request.caseId);
}
