import type { DvcLogEntry, DvcReceivedFile } from "./windows-incident-contract";
import { isWindowsFileId } from "./windows-incident-contract";
import { isThemeId } from "./theme-contract";

export const CHANNEL_TABS = ["tasks", "files", "command", "logs"] as const;
export type WindowsChannelTab = typeof CHANNEL_TABS[number];
export const CHANNEL_COLLECTIONS = ["overview", "baseline", "processes", "network", "startup", "accounts", "logs"] as const;
export type ChannelCollection = typeof CHANNEL_COLLECTIONS[number];
export interface WindowsChannelView {
  hostname: string;
  connected: boolean;
  busy: string | null;
  batch: { done: number; total: number; stopping: boolean } | null;
  history: { key: ChannelCollection; time: string | null; error: string | null }[];
  registered: boolean;
  messagesSent: number;
  messagesReceived: number;
  logs: DvcLogEntry[];
  files: DvcReceivedFile[];
  savedFiles: string[];
  canSave: boolean;
  output: { command: string; output: string; time: string } | null;
  suggestion: { id: string; request: number } | null;
}
export type WindowsChannelAction =
  | { kind: "run"; command: string }
  | { kind: "send"; text: string }
  | { kind: "save"; fileId: string }
  | { kind: "collect"; key: ChannelCollection }
  | { kind: "cancel-batch" | "unregister" };
export interface ChannelWork { id: number; sessionId: string | null; action: WindowsChannelAction }
export interface ChannelNotification { message: string; severity: "info" | "error" }
export interface ChannelOwnerStatus { dirty: boolean; draftRevision: number; pending: boolean; work: ChannelWork | null; notifications: ChannelNotification[] }
export interface ChannelRead {
  revision: number; binding: number; theme: string; tab: WindowsChannelTab; openRequest: number;
  view: WindowsChannelView | null;
  completion: { id: number; ok: boolean } | null;
}
export interface WindowsChannelOwnerApi {
  attach(): Promise<string>;
  sync(owner: string, sessionId: string | null, view: WindowsChannelView): Promise<void>;
  open(owner: string, tab: WindowsChannelTab): Promise<void>;
  poll(owner: string, take: boolean): Promise<ChannelOwnerStatus>;
  finish(owner: string, id: number, ok: boolean): Promise<void>;
  release(owner: string, expectedDraft?: number): Promise<void>;
}
export interface WindowsChannelApi {
  read(after: number): Promise<ChannelRead>;
  act(binding: number, action: WindowsChannelAction): Promise<number>;
  dirty(dirty: boolean): Promise<void>;
  copy(text: string): Promise<void>;
  notify(notification: ChannelNotification): Promise<void>;
}

const enc = new TextEncoder();
const obj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const exact = (v: Record<string, unknown>, keys: string[]) => Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const str = (v: unknown, n: number): v is string => typeof v === "string" && enc.encode(v).length <= n;
const nullable = (v: unknown, n: number) => v === null || str(v, n);
const num = (v: unknown, max = Number.MAX_SAFE_INTEGER): v is number => Number.isSafeInteger(v) && Number(v) >= 0 && Number(v) <= max;
const list = (v: unknown, n: number, check: (x: unknown) => boolean) => Array.isArray(v) && v.length <= n && v.every(check);
export const isChannelTab = (v: unknown): v is WindowsChannelTab => CHANNEL_TABS.includes(v as WindowsChannelTab);
export const isChannelOwner = (v: unknown): v is string => isWindowsFileId(v);
export function isChannelAction(v: unknown): v is WindowsChannelAction {
  if (!obj(v)) return false;
  switch (v.kind) {
    case "run": return exact(v, ["kind", "command"]) && str(v.command, 16384) && v.command.trim().length > 0 && !v.command.includes("\0");
    case "send": return exact(v, ["kind", "text"]) && str(v.text, 8192) && v.text.trim().length > 0 && !v.text.includes("\0");
    case "save": return exact(v, ["kind", "fileId"]) && isWindowsFileId(v.fileId);
    case "collect": return exact(v, ["kind", "key"]) && CHANNEL_COLLECTIONS.includes(v.key as ChannelCollection);
    case "cancel-batch": case "unregister": return exact(v, ["kind"]);
    default: return false;
  }
}
export function isChannelView(v: unknown): v is WindowsChannelView {
  return obj(v) && exact(v, ["hostname", "connected", "busy", "batch", "history", "registered", "messagesSent", "messagesReceived", "logs", "files", "savedFiles", "canSave", "output", "suggestion"])
    && str(v.hostname, 1024) && typeof v.connected === "boolean" && nullable(v.busy, 4096) && typeof v.registered === "boolean"
    && (v.batch === null || (obj(v.batch) && exact(v.batch, ["done", "total", "stopping"]) && num(v.batch.done, 32) && num(v.batch.total, 32) && v.batch.done <= v.batch.total && typeof v.batch.stopping === "boolean"))
    && list(v.history, 7, x => obj(x) && exact(x, ["key", "time", "error"]) && CHANNEL_COLLECTIONS.includes(x.key as ChannelCollection) && nullable(x.time, 128) && nullable(x.error, 16384))
    && num(v.messagesSent) && num(v.messagesReceived)
    && list(v.logs, 256, x => obj(x) && exact(x, ["timestamp", "direction", "kind", "summary"]) && str(x.timestamp, 128) && str(x.direction, 128) && str(x.kind, 128) && str(x.summary, 16384))
    && list(v.files, 32, x => obj(x) && exact(x, ["fileId", "name", "sizeBytes", "sha256", "verified", "receivedAt"]) && isWindowsFileId(x.fileId) && str(x.name, 4096) && num(x.sizeBytes) && typeof x.sha256 === "string" && /^[a-fA-F0-9]{64}$/.test(x.sha256) && typeof x.verified === "boolean" && str(x.receivedAt, 128))
    && list(v.savedFiles, 32, isWindowsFileId) && typeof v.canSave === "boolean"
    && (v.output === null || (obj(v.output) && exact(v.output, ["command", "output", "time"]) && str(v.output.command, 16384) && str(v.output.output, 16 * 1024 * 1024) && str(v.output.time, 128)))
    && (v.suggestion === null || (obj(v.suggestion) && exact(v.suggestion, ["id", "request"]) && str(v.suggestion.id, 128) && num(v.suggestion.request)));
}
export function isChannelOwnerStatus(v: unknown): v is ChannelOwnerStatus {
  return obj(v) && exact(v, ["dirty", "draftRevision", "pending", "work", "notifications"]) && typeof v.dirty === "boolean" && num(v.draftRevision) && typeof v.pending === "boolean"
    && list(v.notifications, 16, isChannelNotification)
    && (v.work === null || (obj(v.work) && exact(v.work, ["id", "sessionId", "action"]) && num(v.work.id) && (v.work.sessionId === null || isChannelOwner(v.work.sessionId)) && isChannelAction(v.work.action)));
}
export function isChannelNotification(v: unknown): v is ChannelNotification {
  return obj(v) && exact(v, ["message", "severity"]) && str(v.message, 4096) && (v.severity === "info" || v.severity === "error");
}
export function isChannelRead(v: unknown): v is ChannelRead {
  return obj(v) && exact(v, ["revision", "binding", "theme", "tab", "openRequest", "view", "completion"])
    && num(v.revision) && num(v.binding) && num(v.openRequest) && isThemeId(v.theme) && isChannelTab(v.tab)
    && (v.view === null || isChannelView(v.view))
    && (v.completion === null || (obj(v.completion) && exact(v.completion, ["id", "ok"]) && num(v.completion.id) && typeof v.completion.ok === "boolean"));
}
