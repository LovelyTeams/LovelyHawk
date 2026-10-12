import {
  emergencyCommandCategories,
  type EmergencyCommandCatalogItem,
  type EmergencyCommandCategory,
  type EmergencyCommandResultKind,
} from "../shared/emergency-command-contract";

export function emergencyCommandScope(bindingHandle: string): string {
  return bindingHandle;
}

export function emergencyCommandCategoryLabel(category: EmergencyCommandCategory): string {
  switch (category) {
    case "permissions": return "权限安全";
    case "accounts": return "账户与认证";
    case "network": return "网络排查";
    case "processes": return "进程与内存";
    case "persistence": return "持久化检查";
    case "logs": return "日志线索";
    case "files": return "文件线索";
    case "containers": return "容器环境";
    case "system": return "系统状态";
  }
}

export function emergencyCommandResultLabel(kind: EmergencyCommandResultKind): string {
  switch (kind) {
    case "success": return "执行成功";
    case "empty": return "成功 · 无输出";
    case "non-zero": return "非零退出";
    case "timeout": return "执行超时";
    case "missing-command": return "命令缺失";
    case "permission-denied": return "权限不足";
    case "unknown-exit": return "退出状态未知";
  }
}

export function filterEmergencyCommands(
  commands: readonly EmergencyCommandCatalogItem[],
  search: string,
): EmergencyCommandCatalogItem[] {
  const needle = search.trim().toLocaleLowerCase();
  return commands.filter((command) => needle === "" ||
    `${command.title}\n${command.description}\n${emergencyCommandCategoryLabel(command.category)}`
      .toLocaleLowerCase().includes(needle));
}

export interface EmergencyCommandGroup {
  category: EmergencyCommandCategory;
  commands: EmergencyCommandCatalogItem[];
}

/** Groups the visible commands into catalog-ordered category branches. */
export function groupEmergencyCommands(
  commands: readonly EmergencyCommandCatalogItem[],
): EmergencyCommandGroup[] {
  return emergencyCommandCategories
    .map((category) => ({ category, commands: commands.filter((command) => command.category === category) }))
    .filter((group) => group.commands.length > 0);
}

export function emergencyExitCodeLabel(exitCode: number | null): string {
  return exitCode === null ? "未返回" : String(exitCode);
}
