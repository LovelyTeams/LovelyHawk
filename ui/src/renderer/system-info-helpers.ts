import type {
  SystemInfoRisk,
  SystemInfoRow,
  SystemInfoSummary,
  SystemInfoTabCatalogEntry,
  SystemInfoTable,
} from "../shared/system-info-contract";

const encoder = new TextEncoder();
const MAX_CLIPBOARD_BYTES = 768 * 1_024;

export const SUMMARY_FIELDS: readonly {
  key: keyof SystemInfoSummary;
  label: string;
  format?: "bytes" | "seconds" | "list";
}[] = [
  { key: "hostname", label: "主机名" },
  { key: "operatingSystem", label: "操作系统" },
  { key: "kernel", label: "内核" },
  { key: "architecture", label: "架构" },
  { key: "virtualization", label: "虚拟化" },
  { key: "bootTime", label: "启动时间" },
  { key: "timezone", label: "时区" },
  { key: "locale", label: "区域设置" },
  { key: "initSystem", label: "Init 系统" },
  { key: "packageManager", label: "包管理器" },
  { key: "selinux", label: "SELinux" },
  { key: "apparmor", label: "AppArmor" },
  { key: "uptimeSeconds", label: "运行时长", format: "seconds" },
  { key: "loadAverage", label: "负载", format: "list" },
  { key: "cpuModel", label: "CPU" },
  { key: "cpuCores", label: "CPU 核心" },
  { key: "memoryTotalBytes", label: "总内存", format: "bytes" },
  { key: "memoryAvailableBytes", label: "可用内存", format: "bytes" },
  { key: "swapTotalBytes", label: "Swap 总量", format: "bytes" },
  { key: "swapFreeBytes", label: "Swap 可用", format: "bytes" },
  { key: "rootDevice", label: "根设备" },
  { key: "rootFilesystem", label: "根文件系统" },
  { key: "rootTotalBytes", label: "根分区总量", format: "bytes" },
  { key: "rootAvailableBytes", label: "根分区可用", format: "bytes" },
  { key: "primaryIp", label: "主要 IP" },
  { key: "defaultGateway", label: "默认网关" },
  { key: "dnsServers", label: "DNS" },
  { key: "processCount", label: "进程数" },
  { key: "loggedInUsers", label: "登录用户" },
  { key: "networkConnections", label: "网络连接" },
  { key: "receivedBytes", label: "接收字节", format: "bytes" },
  { key: "transmittedBytes", label: "发送字节", format: "bytes" },
];

export function groupSystemInfoCatalog(
  catalog: readonly SystemInfoTabCatalogEntry[],
): Array<{ key: SystemInfoTabCatalogEntry["group"]; label: string; tabs: SystemInfoTabCatalogEntry[] }> {
  const groups: Array<{
    key: SystemInfoTabCatalogEntry["group"];
    label: string;
    tabs: SystemInfoTabCatalogEntry[];
  }> = [];
  for (const entry of catalog) {
    let group = groups.find((candidate) => candidate.key === entry.group);
    if (group === undefined) {
      group = { key: entry.group, label: entry.groupLabel, tabs: [] };
      groups.push(group);
    }
    group.tabs.push(entry);
  }
  return groups;
}

export function formatSystemInfoValue(
  value: SystemInfoSummary[keyof SystemInfoSummary],
  format?: "bytes" | "seconds" | "list",
): string {
  if (format === "bytes" && typeof value === "number") return formatBytes(value);
  if (format === "seconds" && typeof value === "number") return formatDuration(value);
  if (format === "list" && Array.isArray(value)) return value.join(" / ");
  return String(value);
}

/**
 * A summary value as the page shows it: the collector's own placeholder words
 * ("unavailable", "physical-or-unknown") said in Chinese, with the word itself
 * kept in brackets for whoever searches for it. Values the host reported are
 * shown as they are; the copied summary keeps the raw value.
 */
export function describeSystemInfoValue(key: keyof SystemInfoSummary, shown: string): string {
  const known: Partial<Record<keyof SystemInfoSummary, Record<string, string>>> = {
    virtualization: { "physical-or-unknown": "未检测到虚拟化（物理机，或无法判断）", none: "未检测到虚拟化" },
    locale: { unknown: "未设置（LANG 为空）" },
    selinux: {
      unavailable: "没有 SELinux 工具（getenforce 不存在）",
      Enforcing: "强制模式",
      Permissive: "宽容模式（只记录不拦截）",
      Disabled: "已关闭",
    },
    apparmor: {
      unavailable: "没有 AppArmor",
      enabled: "已启用",
      disabled: "未启用",
      present: "内核里有 AppArmor，但读不到状态",
    },
  };
  const said = known[key]?.[shown];
  if (said !== undefined) return shown === said ? said : `${said}（${shown}）`;
  // PID 1 is not an init system at all: usually a container's own command.
  if (key === "initSystem" && shown !== "" &&
    !["systemd", "init", "upstart", "openrc-init", "runit", "s6-svscan", "busybox", "tini", "dumb-init", "docker-init"].includes(shown)) {
    return `${shown}（PID 1 不是常见的 init，多半是容器里的程序）`;
  }
  return shown;
}

export interface SystemInfoGauge {
  id: "memory" | "disk" | "load" | "swap";
  label: string;
  value: string;
  detail: string;
  /** How full, 0–1, for the bar; null when there is nothing to measure. */
  ratio: number | null;
  tone: "ok" | "warning" | "high" | "none";
}

/**
 * The figures an operator looks for first, worked out from the summary: how
 * full memory and the root partition are, how loaded the CPUs are, and swap.
 * Thresholds are rules of thumb, said as such on the page, not alarms.
 */
export function systemInfoGauges(summary: SystemInfoSummary): SystemInfoGauge[] {
  const filled = (used: number, total: number, warning: number, high: number) => {
    const ratio = total > 0 ? Math.min(Math.max(used / total, 0), 1) : null;
    const tone: SystemInfoGauge["tone"] = ratio === null ? "none" : ratio >= high ? "high" : ratio >= warning ? "warning" : "ok";
    return { ratio, tone };
  };
  const percent = (ratio: number | null) => ratio === null ? "—" : `${Math.round(ratio * 100)}%`;
  const memoryUsed = summary.memoryTotalBytes - summary.memoryAvailableBytes;
  const memory = filled(memoryUsed, summary.memoryTotalBytes, 0.8, 0.9);
  const diskUsed = summary.rootTotalBytes - summary.rootAvailableBytes;
  const disk = filled(diskUsed, summary.rootTotalBytes, 0.8, 0.9);
  const load1 = Number.parseFloat(summary.loadAverage[0]);
  const perCore = Number.isFinite(load1) && summary.cpuCores > 0 ? load1 / summary.cpuCores : null;
  const loadTone: SystemInfoGauge["tone"] = perCore === null ? "none" : perCore >= 1 ? "high" : perCore >= 0.7 ? "warning" : "ok";
  const swapUsed = summary.swapTotalBytes - summary.swapFreeBytes;
  const swap = filled(swapUsed, summary.swapTotalBytes, 0.5, 0.8);
  return [
    { id: "memory", label: "内存", value: percent(memory.ratio), ratio: memory.ratio, tone: memory.tone,
      detail: summary.memoryTotalBytes > 0 ? `已用 ${formatBytes(Math.max(memoryUsed, 0))} / ${formatBytes(summary.memoryTotalBytes)}` : "没有读到内存总量" },
    { id: "disk", label: "根分区", value: percent(disk.ratio), ratio: disk.ratio, tone: disk.tone,
      detail: summary.rootTotalBytes > 0 ? `已用 ${formatBytes(Math.max(diskUsed, 0))} / ${formatBytes(summary.rootTotalBytes)}` : "没有读到根分区大小" },
    { id: "load", label: "CPU 负载", value: Number.isFinite(load1) ? summary.loadAverage[0] : "—", ratio: perCore === null ? null : Math.min(perCore, 1), tone: loadTone,
      detail: perCore === null ? "没有读到负载或核数" : `1 分钟平均，${summary.cpuCores} 核，每核约 ${perCore.toFixed(2)}` },
    summary.swapTotalBytes > 0
      ? { id: "swap", label: "Swap", value: percent(swap.ratio), ratio: swap.ratio, tone: swap.tone,
        detail: `已用 ${formatBytes(Math.max(swapUsed, 0))} / ${formatBytes(summary.swapTotalBytes)}` }
      : { id: "swap", label: "Swap", value: "未启用", ratio: null, tone: "none", detail: "这台主机没有配置 Swap" },
  ];
}

/** A file's modification time as the host reports it: seconds since the epoch. */
export function formatEpochSeconds(value: string): string {
  const seconds = Number(value);
  if (!Number.isFinite(seconds) || seconds <= 0) return value;
  const when = new Date(seconds * 1_000);
  if (Number.isNaN(when.getTime())) return value;
  const pad = (part: number) => String(part).padStart(2, "0");
  return `${when.getFullYear()}-${pad(when.getMonth() + 1)}-${pad(when.getDate())} ` +
    `${pad(when.getHours())}:${pad(when.getMinutes())}`;
}

export interface ShellConfigLine {
  /** The table row this line came from, so it can be right-clicked like one. */
  rowId: string;
  number: string;
  text: string;
  risk: SystemInfoRisk;
}

export interface ShellConfigFile {
  path: string;
  owner: string;
  modified: string;
  lines: ShellConfigLine[];
}

/**
 * Shell configuration arrives as one table row per line of the file, repeating
 * the path, the owner and the timestamp on every one of them.
 *
 * Read as a table that is four columns of the same value next to one column of
 * shell, three hundred rows deep, and a login script is unreadable that way —
 * the thing an operator is looking for is a line that does not belong, which
 * only shows against the lines around it. Grouped back into the files it came
 * from, it is the files.
 */
export function groupShellConfigRows(table: SystemInfoTable): ShellConfigFile[] {
  const files: ShellConfigFile[] = [];
  const byPath = new Map<string, ShellConfigFile>();
  for (const row of table.rows) {
    const [path = "", owner = "", modified = "", number = "", text = ""] = row.cells;
    let file = byPath.get(path);
    if (file === undefined) {
      file = { path, owner, modified: formatEpochSeconds(modified), lines: [] };
      byPath.set(path, file);
      files.push(file);
    }
    file.lines.push({ rowId: row.id, number, text, risk: row.risk });
  }
  return files;
}

/** One row as tab-separated plain text, the same shape the table copy uses. */
export function buildSystemInfoRowCopy(row: SystemInfoRow): string {
  return boundedClipboardText(row.cells.map(plainCell).join("\t"));
}

export function buildSystemInfoSummaryCopy(summary: SystemInfoSummary): string {
  return boundedClipboardText(
    SUMMARY_FIELDS.map((field) =>
      `${plainCell(field.label)}\t${plainCell(formatSystemInfoValue(summary[field.key], field.format))}`,
    ).join("\n"),
  );
}

export function buildSystemInfoTableCopy(table: SystemInfoTable): string {
  const lines = [
    table.columns.map(plainCell).join("\t"),
    ...table.rows.map((row) => row.cells.map(plainCell).join("\t")),
  ];
  return boundedClipboardText(lines.join("\n"));
}

export function nextModalFocusIndex(
  currentIndex: number,
  focusableCount: number,
  backwards: boolean,
): number {
  if (focusableCount <= 0) return -1;
  if (currentIndex < 0 || currentIndex >= focusableCount) {
    return backwards ? focusableCount - 1 : 0;
  }
  if (backwards) return currentIndex === 0 ? focusableCount - 1 : currentIndex - 1;
  return currentIndex === focusableCount - 1 ? 0 : currentIndex + 1;
}

function plainCell(value: string): string {
  return value.replace(/[\t\r\n]+/gu, " ");
}

function boundedClipboardText(value: string): string {
  if (encoder.encode(value).byteLength > MAX_CLIPBOARD_BYTES) {
    throw new Error("复制内容超过本地剪贴板预算。");
  }
  return value;
}

function formatBytes(value: number): string {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let amount = value;
  let unit = 0;
  while (amount >= 1_024 && unit < units.length - 1) {
    amount /= 1_024;
    unit += 1;
  }
  return `${amount.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function formatDuration(seconds: number): string {
  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3_600);
  const minutes = Math.floor((seconds % 3_600) / 60);
  return [days > 0 ? `${days} 天` : "", hours > 0 ? `${hours} 小时` : "", `${minutes} 分钟`]
    .filter((part) => part.length > 0)
    .join(" ");
}
