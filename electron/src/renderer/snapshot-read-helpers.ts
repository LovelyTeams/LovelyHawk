import type {
  ForensicCollector,
  ForensicDiffField,
  SnapshotDetail,
  SnapshotListItem,
  SnapshotPreset,
} from "../shared/snapshot-read-contract";

export function snapshotScope(bindingHandle: string): string {
  return bindingHandle;
}

export function snapshotKindLabel(kind: SnapshotListItem["kind"]): string {
  return kind === "directory" ? "目录归档" : "主机取证";
}

export function snapshotPresetLabel(preset: SnapshotPreset): string {
  switch (preset) {
    case "etc": return "/etc 配置";
    case "current-crontab": return "当前用户 Crontab";
    case "passwd": return "账户清单";
    case "shadow": return "账户凭据元数据";
    case "authorized-keys": return "授权密钥";
    case "web-root": return "Web 根目录";
    case "cron-spool": return "Cron 队列";
    case "root-home": return "Root 主目录";
  }
}

export function forensicCollectorLabel(collector: ForensicCollector): string {
  switch (collector) {
    case "processes": return "进程树";
    case "networkConnections": return "网络连接";
    case "listeningPorts": return "监听端口";
    case "loginHistory": return "登录历史";
    case "cronJobs": return "计划任务";
    case "startupServices": return "自启动服务";
    case "authorizedKeys": return "授权密钥";
    case "sudoers": return "Sudoers";
    case "runningUsers": return "在线用户";
    case "loadedModules": return "内核模块";
    case "recentModifiedFiles": return "近期修改文件";
    case "envVariables": return "环境变量";
  }
}

export function filterSnapshotList(
  snapshots: readonly SnapshotListItem[],
  kind: SnapshotListItem["kind"],
  search: string,
): SnapshotListItem[] {
  const needle = search.trim().toLocaleLowerCase();
  return snapshots.filter((snapshot) => snapshot.kind === kind && (needle.length === 0 ||
    `${snapshotKindLabel(snapshot.kind)} ${snapshot.capturedAt}`.toLocaleLowerCase().includes(needle)));
}

export function filterPlainText(value: string, search: string): string {
  const needle = search.trim().toLocaleLowerCase();
  if (needle.length === 0) return value;
  return value.split("\n").filter((line) => line.toLocaleLowerCase().includes(needle)).join("\n");
}

export function filterDirectoryItems(
  detail: SnapshotDetail,
  search: string,
) {
  if (detail.kind !== "directory") return [];
  const needle = search.trim().toLocaleLowerCase();
  return detail.items.filter((item) => needle.length === 0 ||
    `${snapshotPresetLabel(item.preset)} ${item.kind} ${item.bytes}`.toLocaleLowerCase().includes(needle));
}

export function filterDiffField(field: ForensicDiffField, search: string): ForensicDiffField {
  const needle = search.trim().toLocaleLowerCase();
  if (needle.length === 0) return field;
  return {
    ...field,
    added: field.added.filter((line) => line.toLocaleLowerCase().includes(needle)),
    removed: field.removed.filter((line) => line.toLocaleLowerCase().includes(needle)),
  };
}

export function chronologicalForensicHandles(
  snapshots: readonly SnapshotListItem[],
): { older: string | null; newer: string | null } {
  const forensic = snapshots.filter((snapshot) => snapshot.kind === "forensic")
    .sort((left, right) => Date.parse(left.capturedAt) - Date.parse(right.capturedAt));
  return {
    older: forensic.length >= 2 ? forensic[0]!.snapshotHandle : null,
    newer: forensic.length >= 2 ? forensic[forensic.length - 1]!.snapshotHandle : null,
  };
}

export function isChronologicalDiff(
  snapshots: readonly SnapshotListItem[],
  older: string | null,
  newer: string | null,
): boolean {
  if (older === null || newer === null || older === newer) return false;
  const olderItem = snapshots.find((snapshot) => snapshot.kind === "forensic" && snapshot.snapshotHandle === older);
  const newerItem = snapshots.find((snapshot) => snapshot.kind === "forensic" && snapshot.snapshotHandle === newer);
  return olderItem !== undefined && newerItem !== undefined &&
    Date.parse(olderItem.capturedAt) < Date.parse(newerItem.capturedAt);
}

export function displaySnapshotBytes(bytes: string): string {
  return `${bytes} bytes`;
}
