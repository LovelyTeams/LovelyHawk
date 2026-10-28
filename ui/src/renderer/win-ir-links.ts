import type { WindowsRiskLevel } from "../shared/windows-incident-contract";
import { commandExecutable } from "./win-ir-helpers";
import { networkKey, startupKey, type CollectionTab, type FocusTarget, type WinIrSnapshots } from "./win-ir-model";

export type RelatedMatch = "path" | "name" | "account" | "address" | "mention" | "pid";

export const MATCH_LABEL: Record<RelatedMatch, string> = {
  path: "完整路径相同",
  name: "仅文件名相同",
  account: "账户名相同",
  address: "远端地址相同",
  mention: "事件文本提及",
  pid: "PID 相同",
};

export interface RelatedHit {
  id: string;
  tab: CollectionTab;
  target: FocusTarget;
  title: string;
  detail: string;
  risk: WindowsRiskLevel;
  match: RelatedMatch;
}

/** What to look for; the record itself is left out by its id. */
export interface RelatedQuery {
  paths?: readonly string[];
  accounts?: readonly string[];
  addresses?: readonly string[];
  pid?: number;
  exclude?: string;
}

/** Lower case, backslashes, no quotes, no trailing separator or `\\?\` prefix; environment variables stay unexpanded. */
export function normalizeWinPath(path: string): string {
  let value = path.trim().replace(/^"(.*)"$/u, "$1").replace(/\//gu, "\\");
  value = value.replace(/^\\\\\?\\/u, "");
  const unc = value.startsWith("\\\\");
  value = value.replace(/\\{2,}/gu, "\\").replace(/\\+$/u, "");
  return (unc ? `\\${value}` : value).toLowerCase();
}

function fileName(normalized: string): string {
  const index = normalized.lastIndexOf("\\");
  return index >= 0 ? normalized.slice(index + 1) : normalized;
}

/** The account name without its domain, lower case. */
export function accountName(value: string): string {
  const trimmed = value.trim();
  const name = trimmed.includes("\\") ? trimmed.slice(trimmed.lastIndexOf("\\") + 1) : trimmed.split("@")[0] ?? "";
  return name.toLowerCase();
}

const SERVICE_ACCOUNTS = new Set(["system", "localsystem", "local service", "network service", "trustedinstaller"]);

/** Built-in service identities shared by many processes; matching on them says nothing about a record. */
export function isServiceAccount(value: string): boolean {
  const name = accountName(value);
  return SERVICE_ACCOUNTS.has(name) || /^(dwm|umfd)-\d+$/u.test(name);
}

/** The program a command starts: a full path when readable, otherwise its first token (which may hold unexpanded variables). */
export function commandPath(command: string): string | null {
  const executable = commandExecutable(command);
  if (executable !== null) return executable;
  const trimmed = command.trim();
  const token = trimmed.startsWith('"') ? trimmed.slice(1, trimmed.indexOf('"', 1) > 0 ? trimmed.indexOf('"', 1) : undefined) : trimmed.split(/\s+/u)[0] ?? "";
  return /[\\/]/u.test(token) || /\.[a-z0-9]{2,4}$/iu.test(token) ? token : null;
}

const UNSPECIFIED = new Set(["", "*", "0.0.0.0", "::", "127.0.0.1", "::1"]);

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

export const RELATED_ID = {
  process: (entry: { pid: number; startTime: string }) => `process:${entry.pid}:${entry.startTime}`,
  startup: (entry: { sourceType: string; location: string; name: string }) => `startup:${startupKey(entry)}`,
  network: (entry: Parameters<typeof networkKey>[0]) => `network:${networkKey(entry)}`,
  account: (entry: { sid: string; name: string }) => `account:${entry.sid || entry.name}`,
  log: (entry: { channel: string; recordId: number }) => `log:${entry.channel}:${entry.recordId}`,
  file: (path: string) => `file:${normalizeWinPath(path)}`,
  registry: (keyPath: string, name: string) => `registry:${keyPath.toLowerCase()}:${name}`,
};

/**
 * Records in the collected snapshots that share a path, account, remote
 * address or PID with the query. Snapshots are not taken at the same moment,
 * and a shared name does not make two records the same object.
 */
export function findRelated(query: RelatedQuery, snapshots: Partial<WinIrSnapshots>): RelatedHit[] {
  const paths = (query.paths ?? []).map(normalizeWinPath).filter((path) => path !== "");
  const names = new Set(paths.map(fileName).filter((name) => name !== ""));
  const accounts = new Set((query.accounts ?? []).filter((value) => !isServiceAccount(value)).map(accountName).filter((name) => name !== ""));
  const addresses = new Set((query.addresses ?? []).map((address) => address.trim().toLowerCase()).filter((address) => !UNSPECIFIED.has(address)));
  const hits: RelatedHit[] = [];
  const add = (hit: RelatedHit) => { if (hit.id !== query.exclude && !hits.some((other) => other.id === hit.id)) hits.push(hit); };
  const pathMatch = (raw: string | null | undefined): RelatedMatch | null => {
    if (!raw) return null;
    const candidate = normalizeWinPath(raw);
    if (candidate === "") return null;
    if (paths.includes(candidate)) return "path";
    return names.has(fileName(candidate)) ? "name" : null;
  };

  for (const process of snapshots.processes?.processes ?? []) {
    const byPath = pathMatch(process.executablePath);
    const match = byPath ?? (accounts.has(accountName(process.user)) && process.user ? "account" : null) ?? (query.pid !== undefined && process.pid === query.pid ? "pid" : null);
    if (match) add({ id: RELATED_ID.process(process), tab: "processes", target: { tab: "processes", pid: process.pid, startTime: process.startTime }, title: `${process.name} · PID ${process.pid}`, detail: match === "account" ? process.user : process.executablePath || "执行路径未取得", risk: process.riskLevel, match });
  }
  for (const entry of snapshots.startup?.entries ?? []) {
    const match = pathMatch(commandPath(entry.command)) ?? (accounts.has(accountName(entry.runAs)) && entry.runAs ? "account" : null);
    if (match) add({ id: RELATED_ID.startup(entry), tab: "startup", target: { tab: "startup", key: startupKey(entry) }, title: entry.name, detail: entry.command || entry.location, risk: entry.riskLevel, match });
  }
  for (const entry of snapshots.network?.connections ?? []) {
    const remote = entry.remoteAddress.trim().toLowerCase();
    const match = (addresses.has(remote) ? "address" : null) ?? (query.pid !== undefined && entry.pid === query.pid ? "pid" : null) ?? pathMatch(entry.processPath);
    if (match) add({ id: RELATED_ID.network(entry), tab: "network", target: { tab: "network", key: networkKey(entry) }, title: `${entry.protocol} ${entry.remoteAddress}:${entry.remotePort}`, detail: `${entry.processName || "未取得进程名"} · PID ${entry.pid} · ${entry.state || "无连接状态"}`, risk: entry.riskLevel, match });
  }
  for (const entry of snapshots.accounts?.accounts ?? []) {
    if (accounts.has(accountName(entry.name))) add({ id: RELATED_ID.account(entry), tab: "accounts", target: { tab: "accounts", sid: entry.sid, name: entry.name }, title: entry.name, detail: `${entry.isAdmin ? "管理员组" : "普通账户"} · ${entry.enabled ? "启用" : "禁用"}`, risk: entry.riskLevel, match: "account" });
  }
  const mentions = [
    ...[...accounts].map((name) => new RegExp(`(^|[^\\p{L}\\p{N}_$])${escapeRegExp(name)}($|[^\\p{L}\\p{N}_$])`, "iu")),
    ...[...addresses].map((address) => new RegExp(`(^|[^\\p{N}.:])${escapeRegExp(address)}($|[^\\p{N}.:])`, "iu")),
  ];
  for (const entry of snapshots.logs?.entries ?? []) {
    const text = `${entry.summary}\n${entry.detail}`;
    const lowered = text.toLowerCase().replace(/\//gu, "\\");
    if (paths.some((path) => lowered.includes(path)) || mentions.some((pattern) => pattern.test(text))) {
      add({ id: RELATED_ID.log(entry), tab: "logs", target: { tab: "logs", channel: entry.channel, recordId: entry.recordId }, title: `${entry.eventId} · ${entry.summary || entry.category}`, detail: `${entry.channel} · ${entry.timeCreated}`, risk: entry.riskLevel, match: "mention" });
    }
  }
  for (const entry of snapshots.files?.entries ?? []) {
    if (entry.entryType === "dir") continue;
    const match = pathMatch(entry.fullPath);
    if (match) add({ id: RELATED_ID.file(entry.fullPath), tab: "files", target: { tab: "files", path: entry.fullPath }, title: entry.name, detail: entry.fullPath, risk: entry.riskLevel, match });
  }
  const registry = snapshots.registry;
  for (const value of registry?.values ?? []) {
    const match = pathMatch(commandPath(value.data));
    if (match && registry) add({ id: RELATED_ID.registry(registry.keyPath, value.name), tab: "registry", target: { tab: "registry", keyPath: registry.keyPath, valueName: value.name }, title: value.name || "(默认)", detail: `${registry.keyPath} · ${value.data}`, risk: value.riskLevel, match });
  }
  return hits;
}
