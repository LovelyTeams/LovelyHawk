import type {
  SftpBrowserEntry,
  SftpBrowserEntryKind,
} from "../shared/sftp-browser-contract";

export interface SftpBrowserConnectionScope {
  /** Identifies the window the browser belongs to. */
  scopeKey: string;
}

export type SftpBrowserKindFilter = SftpBrowserEntryKind | "all";

export function sftpBrowserScope(connection: SftpBrowserConnectionScope): string {
  return connection.scopeKey;
}

export function filterSftpBrowserEntries(
  entries: readonly SftpBrowserEntry[],
  kind: SftpBrowserKindFilter,
  search: string,
): SftpBrowserEntry[] {
  const needle = search.trim().toLocaleLowerCase();
  return entries.filter((entry) => (kind === "all" || entry.kind === kind) &&
    (needle.length === 0 || entry.name.toLocaleLowerCase().includes(needle)));
}

export function sftpBrowserKindLabel(kind: SftpBrowserEntryKind): string {
  switch (kind) {
    case "directory": return "目录";
    case "file": return "文件";
    case "symlink": return "符号链接";
    case "other": return "其他";
  }
}

export function sftpBrowserActionLabel(entry: SftpBrowserEntry): string {
  switch (entry.action) {
    case "browse": return "可浏览";
    case "preview": return "可预览文本";
    case "none": return entry.kind === "symlink" ? "不跟随" : "不可打开";
  }
}

export function displaySftpBytes(value: string): string {
  return `${value} 字节`;
}

const BYTE_UNITS = ["KB", "MB", "GB", "TB", "PB", "EB"] as const;

/**
 * A size that fits a table column: `6.0 GB`, not ten digits cut off by the
 * column. Under a kilobyte the exact count reads fine as it is. The exact
 * figure stays available where the number matters (a tooltip, properties).
 */
export function compactSftpBytes(value: string): string {
  const bytes = Number(value);
  if (!/^\d+$/u.test(value) || !Number.isFinite(bytes) || bytes < 1024) return displaySftpBytes(value);
  let scaled = bytes / 1024;
  let unit = 0;
  while (scaled >= 1024 && unit < BYTE_UNITS.length - 1) {
    scaled /= 1024;
    unit += 1;
  }
  return `${scaled.toFixed(1)} ${BYTE_UNITS[unit]}`;
}

/** Both at once, for a place with room: `6.0 GB（6442450944 字节）`. */
export function describeSftpBytes(value: string): string {
  const compact = compactSftpBytes(value);
  return compact === displaySftpBytes(value) ? compact : `${compact}（${displaySftpBytes(value)}）`;
}

/** `2026-05-28T08:12:00Z` reads better as `2026-05-28 08:12` in a table. */
export function displaySftpModifiedAt(value: string | null): string {
  if (value === null) return "时间未知";
  const match = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})/u.exec(value);
  return match === null ? value : `${match[1]} ${match[2]}`;
}

export function boundSftpSearch(value: string): string {
  return [...value].slice(0, 256).join("");
}
