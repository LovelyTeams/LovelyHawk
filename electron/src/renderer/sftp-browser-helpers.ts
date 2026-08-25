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
  return `${value} bytes`;
}

export function displaySftpModifiedAt(value: string | null): string {
  return value ?? "时间未知";
}

export function boundSftpSearch(value: string): string {
  return [...value].slice(0, 256).join("");
}
