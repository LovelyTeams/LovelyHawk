import type { WindowsProcessEntry, WindowsRiskLevel } from "../shared/windows-incident-contract";

export type RiskFilter = "all" | WindowsRiskLevel;

export const RISK_ORDER: Record<WindowsRiskLevel, number> = { high: 3, medium: 2, low: 1, normal: 0 };

export const RISK_LABEL: Record<WindowsRiskLevel, string> = {
  high: "高危",
  medium: "中危",
  low: "关注",
  normal: "未标记",
};

export function riskCounts<T>(rows: readonly T[], risk: (row: T) => WindowsRiskLevel): Record<RiskFilter, number> {
  const counts: Record<RiskFilter, number> = { all: rows.length, high: 0, medium: 0, low: 0, normal: 0 };
  for (const row of rows) counts[risk(row)] += 1;
  return counts;
}

/** Case-insensitive match of a query against any of the given texts. */
export function matchesQuery(query: string, ...texts: ReadonlyArray<string | number>): boolean {
  const needle = query.trim().toLowerCase();
  if (needle === "") return true;
  return texts.some((text) => String(text).toLowerCase().includes(needle));
}

/** True for addresses that leave the host and its private networks. */
export function isPublicAddress(address: string): boolean {
  const value = address.trim().toLowerCase().replace(/^\[|\]$/gu, "");
  if (value === "" || value === "*" || value === "0.0.0.0" || value === "::" || value === "::1") return false;
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/u.exec(value.replace(/^::ffff:/u, ""));
  if (v4 !== null) {
    const octets = v4.slice(1).map(Number);
    if (octets.some((part) => part > 255)) return false;
    const [a = 0, b = 0, c = 0] = octets;
    if (a === 10 || a === 127 || a === 0 || a >= 224) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a === 192 && b === 0 && (c === 0 || c === 2)) return false;
    if (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) return false;
    if (a === 203 && b === 0 && c === 113) return false;
    return true;
  }
  if (value.includes(":")) {
    try {
      // URL's parser validates the IPv6 syntax without making a network request.
      const host = new URL(`http://[${value}]/`).hostname;
      return /^\[[23][0-9a-f]{3}:/u.test(host) && !host.startsWith("[2001:db8:") && !host.startsWith("[2001:2:");
    } catch { return false; }
  }
  return false;
}

export function endpoint(address: string, port: number): string {
  return `${address.includes(":") ? `[${address}]` : address}:${port}`;
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const exponent = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  const value = bytes / 1024 ** exponent;
  return `${value >= 100 || exponent === 0 ? Math.round(value) : value.toFixed(1)} ${units[exponent]}`;
}

/** Escapes one value for a CSV cell. */
function csvCell(value: string): string {
  const safe = /^[\s]*[=+\-@]/u.test(value) || /^[\t\r\n]/u.test(value) ? `'${value}` : value;
  return /[",\n\r]/u.test(safe) ? `"${safe.replace(/"/gu, '""')}"` : safe;
}

export function toCsv(header: readonly string[], rows: ReadonlyArray<readonly string[]>): string {
  return [header, ...rows].map((row) => row.map(csvCell).join(",")).join("\r\n");
}

/** Why a process with a parent PID is shown without a parent. */
export type ParentGap = "exited" | "reused";

export type ParentLink =
  | { parent: WindowsProcessEntry; verified: boolean; gap: null }
  | { parent: null; verified: false; gap: ParentGap | null };

export interface ProcessTreeRow {
  process: WindowsProcessEntry;
  depth: number;
  hasChildren: boolean;
  childCount: number;
  link: ParentLink;
  /** High and medium risk processes below this one, at any depth. */
  descendantRisk: { high: number; medium: number };
}

function startMs(process: WindowsProcessEntry): number | null {
  if (process.startTime === "") return null;
  const value = Date.parse(process.startTime);
  return Number.isNaN(value) ? null : value;
}

/** Earlier start first; processes without a readable start time first, then by PID. */
export function byStartTime(a: WindowsProcessEntry, b: WindowsProcessEntry): number {
  return ((startMs(a) ?? -Infinity) - (startMs(b) ?? -Infinity)) || a.pid - b.pid;
}

/**
 * Windows keeps the parent PID after the parent exits, and the PID can then be
 * reused. A process in the snapshot only counts as the parent when it did not
 * start after the child; without both start times the link stays unverified.
 */
export function resolveParent(process: WindowsProcessEntry, byPid: ReadonlyMap<number, WindowsProcessEntry>): ParentLink {
  if (process.ppid === process.pid || process.ppid === 0) return { parent: null, verified: false, gap: null };
  const parent = byPid.get(process.ppid);
  if (parent === undefined) return { parent: null, verified: false, gap: "exited" };
  const child = startMs(process);
  const born = startMs(parent);
  if (child !== null && born !== null && born > child) return { parent: null, verified: false, gap: "reused" };
  return { parent, verified: child !== null && born !== null, gap: null };
}

export function processKey(process: WindowsProcessEntry): string {
  return `${process.pid}:${process.startTime}`;
}

/**
 * Orders processes as a tree, parents before their children and siblings by
 * start time. A process whose parent is not in the list, started later than
 * it, or is itself starts its own root.
 */
export function buildProcessTree(processes: readonly WindowsProcessEntry[]): ProcessTreeRow[] {
  const byPid = new Map(processes.map((process) => [process.pid, process]));
  const links = new Map<number, ParentLink>();
  const children = new Map<number, WindowsProcessEntry[]>();
  const roots: WindowsProcessEntry[] = [];
  for (const process of processes) {
    const link = resolveParent(process, byPid);
    links.set(process.pid, link);
    if (link.parent === null) {
      roots.push(process);
    } else {
      const list = children.get(link.parent.pid) ?? [];
      list.push(process);
      children.set(link.parent.pid, list);
    }
  }
  roots.sort(byStartTime);
  for (const list of children.values()) list.sort(byStartTime);
  const rows: ProcessTreeRow[] = [];
  const treeParent = new Map<number, number>();
  const seen = new Set<number>();
  const visit = (root: WindowsProcessEntry) => {
    const stack = [{ process: root, depth: 0 }];
    while (stack.length) {
      const { process, depth } = stack.pop()!;
      if (seen.has(process.pid)) continue;
      seen.add(process.pid);
      const kids = (children.get(process.pid) ?? []).filter((kid) => !seen.has(kid.pid));
      rows.push({ process, depth, hasChildren: kids.length > 0, childCount: kids.length, link: links.get(process.pid)!, descendantRisk: { high: 0, medium: 0 } });
      for (let index = kids.length - 1; index >= 0; index -= 1) {
        treeParent.set(kids[index]!.pid, process.pid);
        stack.push({ process: kids[index]!, depth: depth + 1 });
      }
    }
  };
  for (const root of roots) visit(root);
  // A parent cycle has no root; it still has to be listed.
  for (const process of processes) visit(process);
  const rowByPid = new Map(rows.map((row) => [row.process.pid, row]));
  // Preorder lists every child after its parent, so walking backwards totals each subtree first.
  for (let index = rows.length - 1; index >= 0; index -= 1) {
    const row = rows[index]!;
    const parentPid = treeParent.get(row.process.pid);
    const parent = parentPid === undefined ? undefined : rowByPid.get(parentPid);
    if (parent === undefined || parent.depth >= row.depth) continue;
    parent.descendantRisk.high += row.descendantRisk.high + (row.process.riskLevel === "high" ? 1 : 0);
    parent.descendantRisk.medium += row.descendantRisk.medium + (row.process.riskLevel === "medium" ? 1 : 0);
  }
  return rows;
}

/** The chain of ancestors of a process, nearest first, without loops. */
export function processAncestors(pid: number, processes: readonly WindowsProcessEntry[]): WindowsProcessEntry[] {
  const byPid = new Map(processes.map((process) => [process.pid, process]));
  const chain: WindowsProcessEntry[] = [];
  const seen = new Set<number>([pid]);
  let current = byPid.get(pid);
  while (current !== undefined) {
    const parent = resolveParent(current, byPid).parent;
    if (parent === null || seen.has(parent.pid)) break;
    chain.push(parent);
    seen.add(parent.pid);
    current = parent;
  }
  return chain;
}

/** The direct children of a process under the same parent rule as the tree, by start time. */
export function processChildren(pid: number, processes: readonly WindowsProcessEntry[]): WindowsProcessEntry[] {
  const byPid = new Map(processes.map((process) => [process.pid, process]));
  return processes.filter((process) => process.pid !== pid && resolveParent(process, byPid).parent?.pid === pid).sort(byStartTime);
}

/** The executable path at the start of a command line, when one can be read. */
export function commandExecutable(command: string): string | null {
  const trimmed = command.trim();
  if (trimmed === "") return null;
  if (trimmed.startsWith('"')) {
    const end = trimmed.indexOf('"', 1);
    return end > 1 ? trimmed.slice(1, end) : null;
  }
  const match = /^([a-z]:\\[^"]*?\.(?:exe|dll|bat|cmd|ps1|vbs|js|hta|scr|com))(?:\s|$)/iu.exec(trimmed);
  return match?.[1] ?? (/^[a-z]:\\\S+$/iu.test(trimmed) ? trimmed : null);
}

/** The folder holding a Windows path, or null at a drive root. */
export function parentPath(path: string): string | null {
  const normalized = path.replace(/\//gu, "\\");
  const trimmed = normalized.replace(/\\+$/u, "");
  if (/^\\\\[^\\]+\\[^\\]+$/u.test(trimmed)) return null;
  if (/^[a-z]:$/iu.test(trimmed) || trimmed === "") return null;
  const index = trimmed.lastIndexOf("\\");
  if (index < 0) return null;
  const parent = trimmed.slice(0, index);
  return /^[a-z]:$/iu.test(parent) ? `${parent}\\` : parent;
}

export interface PathSegment {
  label: string;
  path: string;
}

export function pathSegments(path: string): PathSegment[] {
  const parts = path.split(/[\\/]+/u).filter((part) => part !== "");
  const segments: PathSegment[] = [];
  let built = "";
  if (/^[\\/]{2}/u.test(path) && parts.length >= 2) {
    built = `\\\\${parts.shift()}\\${parts.shift()}\\`;
    segments.push({ label: built.slice(0, -1), path: built });
  }
  for (const part of parts) {
    built = built === "" ? (/^[a-z]:$/iu.test(part) ? `${part}\\` : part) : built.endsWith("\\") ? `${built}${part}` : `${built}\\${part}`;
    segments.push({ label: part, path: built });
  }
  return segments;
}

export type FileKind = "folder" | "executable" | "script" | "document" | "archive" | "image" | "config" | "log" | "web" | "other";

const KIND_BY_EXTENSION: Record<string, FileKind> = {
  exe: "executable", dll: "executable", sys: "executable", scr: "executable", com: "executable", msi: "executable", ocx: "executable", cpl: "executable",
  ps1: "script", psm1: "script", bat: "script", cmd: "script", vbs: "script", vbe: "script", js: "script", jse: "script", wsf: "script", hta: "script", py: "script", sh: "script",
  doc: "document", docx: "document", xls: "document", xlsx: "document", ppt: "document", pptx: "document", pdf: "document", txt: "document", rtf: "document", md: "document", csv: "document",
  zip: "archive", rar: "archive", "7z": "archive", gz: "archive", tar: "archive", cab: "archive", iso: "archive",
  png: "image", jpg: "image", jpeg: "image", gif: "image", bmp: "image", ico: "image", svg: "image", webp: "image",
  ini: "config", xml: "config", json: "config", config: "config", conf: "config", yml: "config", yaml: "config", reg: "config", inf: "config", lnk: "config",
  log: "log", evtx: "log", etl: "log",
  php: "web", jsp: "web", jspx: "web", asp: "web", aspx: "web", ashx: "web", asmx: "web", html: "web", htm: "web",
};

export const FILE_KIND_LABEL: Record<FileKind, string> = {
  folder: "文件夹", executable: "可执行程序", script: "脚本", document: "文档", archive: "压缩包",
  image: "图片", config: "配置", log: "日志", web: "网页脚本", other: "文件",
};

export function fileExtension(name: string): string {
  const index = name.lastIndexOf(".");
  return index > 0 ? name.slice(index + 1).toLowerCase() : "";
}

export function fileKind(name: string, isFolder: boolean): FileKind {
  return isFolder ? "folder" : KIND_BY_EXTENSION[fileExtension(name)] ?? "other";
}

export function decodeBase64(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

export interface TextPreview {
  text: string;
  encoding: string;
}

/** Reads the bytes as text when they look like text; null for binary content. */
export function decodeTextPreview(bytes: Uint8Array): TextPreview | null {
  if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe) {
    return { text: new TextDecoder("utf-16le").decode(bytes.subarray(2)), encoding: "UTF-16 LE" };
  }
  const sample = bytes.subarray(0, 4096);
  let control = 0;
  for (const byte of sample) {
    if (byte === 0) return null;
    if (byte < 9 || (byte > 13 && byte < 32)) control += 1;
  }
  if (sample.length > 0 && control / sample.length > 0.1) return null;
  try {
    return { text: new TextDecoder("utf-8", { fatal: true }).decode(bytes), encoding: "UTF-8" };
  } catch {
    // A cut multi-byte character at the end, or a legacy code page.
    try {
      return { text: new TextDecoder("gbk").decode(bytes), encoding: "GBK" };
    } catch {
      return { text: new TextDecoder("utf-8").decode(bytes), encoding: "UTF-8（含无法识别的字节）" };
    }
  }
}

export function hexDump(bytes: Uint8Array, maxLines = 1024): string {
  const lines: string[] = [];
  for (let offset = 0; offset < bytes.length && lines.length < maxLines; offset += 16) {
    const chunk = bytes.subarray(offset, offset + 16);
    const hex = [...chunk].map((byte) => byte.toString(16).padStart(2, "0")).join(" ").padEnd(47, " ");
    const ascii = [...chunk].map((byte) => (byte >= 32 && byte < 127 ? String.fromCharCode(byte) : ".")).join("");
    lines.push(`${offset.toString(16).padStart(8, "0")}  ${hex}  ${ascii}`);
  }
  return lines.join("\n");
}

export interface PeSummary {
  machine: string;
  kind: string;
  compiledAt: string | null;
  subsystem: string;
  sections: string[];
}

const MACHINES: Record<number, string> = { 0x14c: "x86", 0x8664: "x64", 0xaa64: "ARM64", 0x1c4: "ARM" };
const SUBSYSTEMS: Record<number, string> = { 1: "驱动程序", 2: "图形界面程序", 3: "控制台程序", 9: "Windows CE", 10: "EFI 程序" };

/** Reads the PE headers in the preview bytes, when they are a PE file. */
export function parsePeHeader(bytes: Uint8Array): PeSummary | null {
  if (bytes.length < 64 || bytes[0] !== 0x4d || bytes[1] !== 0x5a) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const peOffset = view.getUint32(0x3c, true);
  if (peOffset + 24 > bytes.length || view.getUint32(peOffset, true) !== 0x00004550) return null;
  const machine = view.getUint16(peOffset + 4, true);
  const sectionCount = view.getUint16(peOffset + 6, true);
  const timestamp = view.getUint32(peOffset + 8, true);
  const optionalSize = view.getUint16(peOffset + 20, true);
  const characteristics = view.getUint16(peOffset + 22, true);
  const optional = peOffset + 24;
  const subsystem = optional + 70 <= bytes.length ? view.getUint16(optional + 68, true) : 0;
  const sections: string[] = [];
  const table = optional + optionalSize;
  for (let index = 0; index < Math.min(sectionCount, 24); index += 1) {
    const start = table + index * 40;
    if (start + 8 > bytes.length) break;
    const name = [...bytes.subarray(start, start + 8)].filter((byte) => byte !== 0).map((byte) => String.fromCharCode(byte)).join("");
    sections.push(name || "(无名)");
  }
  return {
    machine: MACHINES[machine] ?? `0x${machine.toString(16)}`,
    kind: characteristics & 0x2000 ? "动态链接库 (DLL)" : "可执行程序 (EXE)",
    compiledAt: timestamp > 0 ? new Date(timestamp * 1000).toISOString().replace("T", " ").slice(0, 19) : null,
    subsystem: SUBSYSTEMS[subsystem] ?? (subsystem === 0 ? "未知" : `子系统 ${subsystem}`),
    sections,
  };
}
