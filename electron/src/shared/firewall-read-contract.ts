export type FirewallBackend = "iptables" | "nftables" | "ufw" | "firewalld" | "unknown";
export type FirewallEngine = "iptables" | "nftables" | "unavailable";
export type FirewallChangeKind =
  | "block-ipv4"
  | "temporary-block-ipv4"
  | "allow-tcp-port"
  | "isolate-inbound";
export type FirewallChangeState = "awaiting-keep" | "kept" | "restored" | "auto-restored";

export interface FirewallInspection {
  snapshotHandle: string;
  backend: FirewallBackend;
  engine: FirewallEngine;
  active: boolean;
  rules: string;
  rulesTruncated: boolean;
  capturedAt: string;
  expiresInSeconds: number;
}

export interface FirewallHistoryEntry {
  changeHandle: string;
  backend: FirewallBackend;
  engine: FirewallEngine;
  changeKind: FirewallChangeKind;
  label: string;
  state: FirewallChangeState;
  sshPort: number;
  createdAt: string;
  deadmanDeadline: string;
  updatedAt: string;
  textTruncated: boolean;
}

export interface FirewallHistory {
  historyHandle: string;
  entries: FirewallHistoryEntry[];
  displayed: number;
  truncated: boolean;
  expiresInSeconds: number;
}

export interface FirewallReadApi {
  inspectFirewall(bindingHandle: string): Promise<FirewallInspection>;
  listFirewallChangeHistory(bindingHandle: string): Promise<FirewallHistory>;
}

type JsonRecord = Record<string, unknown>;
const encoder = new TextEncoder();
const HANDLE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const BACKENDS = new Set<FirewallBackend>([
  "iptables", "nftables", "ufw", "firewalld", "unknown",
]);
const ENGINES = new Set<FirewallEngine>(["iptables", "nftables", "unavailable"]);
const CHANGE_KINDS = new Set<FirewallChangeKind>([
  "block-ipv4", "temporary-block-ipv4", "allow-tcp-port", "isolate-inbound",
]);
const CHANGE_STATES = new Set<FirewallChangeState>([
  "awaiting-keep", "kept", "restored", "auto-restored",
]);

function record(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exact(value: JsonRecord, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && actual.every((key) => keys.includes(key));
}

function singleLineText(value: unknown, maximumBytes: number, allowEmpty = true): value is string {
  return typeof value === "string" && (allowEmpty || value.length > 0) &&
    encoder.encode(value).byteLength <= maximumBytes && !/[\u0000-\u001f\u007f]/u.test(value);
}

function multilineText(value: unknown, maximumBytes: number): value is string {
  return typeof value === "string" && encoder.encode(value).byteLength <= maximumBytes &&
    !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value) && !value.includes("\r");
}

function timestamp(value: unknown): value is string {
  return singleLineText(value, 64, false) && !Number.isNaN(Date.parse(value));
}

function unsigned(value: unknown, maximum: number): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= maximum;
}

function jsonBytesAtMost(value: unknown, maximum: number): boolean {
  try {
    return encoder.encode(JSON.stringify(value)).byteLength <= maximum;
  } catch {
    return false;
  }
}

export function isFirewallOpaqueHandle(value: unknown): value is string {
  return typeof value === "string" && HANDLE.test(value);
}

export function isFirewallInspection(value: unknown): value is FirewallInspection {
  return record(value) && exact(value, [
    "snapshotHandle", "backend", "engine", "active", "rules", "rulesTruncated",
    "capturedAt", "expiresInSeconds",
  ]) && isFirewallOpaqueHandle(value.snapshotHandle) &&
    typeof value.backend === "string" && BACKENDS.has(value.backend as FirewallBackend) &&
    typeof value.engine === "string" && ENGINES.has(value.engine as FirewallEngine) &&
    typeof value.active === "boolean" && multilineText(value.rules, 256 * 1_024) &&
    typeof value.rulesTruncated === "boolean" && timestamp(value.capturedAt) &&
    unsigned(value.expiresInSeconds, 300) && value.expiresInSeconds > 0 &&
    jsonBytesAtMost(value, 320 * 1_024);
}

export function isFirewallHistoryEntry(value: unknown): value is FirewallHistoryEntry {
  return record(value) && exact(value, [
    "changeHandle", "backend", "engine", "changeKind", "label", "state", "sshPort",
    "createdAt", "deadmanDeadline", "updatedAt", "textTruncated",
  ]) && isFirewallOpaqueHandle(value.changeHandle) &&
    typeof value.backend === "string" && BACKENDS.has(value.backend as FirewallBackend) &&
    typeof value.engine === "string" && ENGINES.has(value.engine as FirewallEngine) &&
    typeof value.changeKind === "string" &&
    CHANGE_KINDS.has(value.changeKind as FirewallChangeKind) &&
    singleLineText(value.label, 512, false) && typeof value.state === "string" &&
    CHANGE_STATES.has(value.state as FirewallChangeState) && unsigned(value.sshPort, 65_535) &&
    value.sshPort > 0 && timestamp(value.createdAt) && timestamp(value.deadmanDeadline) &&
    timestamp(value.updatedAt) && typeof value.textTruncated === "boolean" &&
    jsonBytesAtMost(value, 2 * 1_024);
}

export function isFirewallHistory(value: unknown): value is FirewallHistory {
  if (!record(value) || !exact(value, [
    "historyHandle", "entries", "displayed", "truncated", "expiresInSeconds",
  ]) || !isFirewallOpaqueHandle(value.historyHandle) || !Array.isArray(value.entries) ||
    value.entries.length > 256 || !value.entries.every(isFirewallHistoryEntry) ||
    !unsigned(value.displayed, 256) || value.displayed !== value.entries.length ||
    typeof value.truncated !== "boolean" || !unsigned(value.expiresInSeconds, 300) ||
    value.expiresInSeconds === 0) return false;
  const handles = value.entries.map((entry) => entry.changeHandle);
  return new Set(handles).size === handles.length && jsonBytesAtMost(value, 512 * 1_024);
}
