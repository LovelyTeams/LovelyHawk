import type {
  WindowsAccountsSnapshot,
  WindowsBaselineSnapshot,
  WindowsFilesSnapshot,
  WindowsLogsSnapshot,
  WindowsNetworkSnapshot,
  WindowsOverviewSnapshot,
  WindowsProcessesSnapshot,
  WindowsRegistrySnapshot,
  WindowsStartupSnapshot,
} from "../shared/windows-incident-contract";

export interface WinIrSnapshots {
  overview: WindowsOverviewSnapshot;
  baseline: WindowsBaselineSnapshot;
  processes: WindowsProcessesSnapshot;
  network: WindowsNetworkSnapshot;
  startup: WindowsStartupSnapshot;
  accounts: WindowsAccountsSnapshot;
  logs: WindowsLogsSnapshot;
  files: WindowsFilesSnapshot;
  registry: WindowsRegistrySnapshot;
}

export type CollectionTab = keyof WinIrSnapshots;
export type WindowsIncidentTab = CollectionTab | "timeline" | "console" | "desktop";
export type CollectedAt = Partial<Record<CollectionTab, string>>;

export const WIN_IR_MODULES: ReadonlyArray<{
  key: WindowsIncidentTab;
  label: string;
  description: string;
  group: string;
  action: string;
}> = [
  { key: "overview", label: "主机总览", group: "调查", description: "先了解目标与防护状态，再沿着风险线索深入排查。", action: "刷新主机概况" },
  { key: "baseline", label: "基线配置", group: "配置", description: "对照当前值和建议值核查配置，查看每项检查的依据与建议。", action: "核查安全基线" },
  { key: "timeline", label: "调查时间线", group: "取证", description: "按时间对照已采集的事件、进程启动和文件修改记录。", action: "采集核心模块" },
  { key: "processes", label: "进程分析", group: "调查", description: "从父子关系、执行路径和命令行定位可疑活动。", action: "刷新进程" },
  { key: "network", label: "网络连接", group: "调查", description: "区分监听、活动连接和公网地址，关联到所属进程。", action: "刷新连接" },
  { key: "startup", label: "启动项", group: "调查", description: "按持久化来源检查启动位置、执行命令与运行账户。", action: "采集启动项" },
  { key: "accounts", label: "本地账户", group: "调查", description: "核对管理员、账户状态、口令属性与最近登录。", action: "采集账户" },
  { key: "logs", label: "事件日志", group: "取证", description: "围绕登录、账户变更、服务安装和脚本执行筛选事件。", action: "读取事件日志" },
  { key: "files", label: "文件排查", group: "取证", description: "像文件管理器一样浏览远程目录，查看属性、预览内容并拉取取证文件。", action: "刷新目录" },
  { key: "registry", label: "注册表", group: "取证", description: "浏览常见持久化、凭据策略与用户活动位置，查看原始键值。", action: "刷新键值" },
  { key: "desktop", label: "远程桌面", group: "连接", description: "在软件内查看并操作远程 Windows 桌面。", action: "刷新客户端状态" },
  { key: "console", label: "通道与传输", group: "连接", description: "检查会话通信、已接收文件和命令执行记录。", action: "刷新通道状态" },
];

export const CORE_COLLECTION: readonly CollectionTab[] = [
  "overview", "baseline", "processes", "network", "startup", "accounts", "logs",
];

export const DEFAULT_FILE_PATH = "C:\\Users\\Public";
export const DEFAULT_REGISTRY_PATH = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";

/** One record a cross-link points at; each module resolves its own kind. */
export type FocusTarget =
  | { tab: "processes"; pid: number; startTime?: string }
  | { tab: "network"; pid?: number; key?: string }
  | { tab: "startup"; key: string }
  | { tab: "accounts"; sid: string; name: string }
  | { tab: "logs"; channel?: string; recordId?: number; query?: string }
  | { tab: "baseline"; id: string }
  | { tab: "files"; path: string }
  | { tab: "registry"; keyPath: string; valueName?: string };

export interface InvestigationFocus<T extends FocusTarget = FocusTarget> {
  target: T;
  request: number;
}

/** The focus meant for one module, or null. */
export function focusFor<K extends FocusTarget["tab"]>(focus: InvestigationFocus | null, tab: K): InvestigationFocus<Extract<FocusTarget, { tab: K }>> | null {
  return focus !== null && focus.target.tab === tab ? focus as InvestigationFocus<Extract<FocusTarget, { tab: K }>> : null;
}

export function startupKey(entry: { sourceType: string; location: string; name: string }): string {
  return `${entry.sourceType}\u0000${entry.location}\u0000${entry.name}`;
}

export function networkKey(entry: { protocol: string; localAddress: string; localPort: number; remoteAddress: string; remotePort: number; pid: number }): string {
  return `${entry.protocol}|${entry.localAddress}|${entry.localPort}|${entry.remoteAddress}|${entry.remotePort}|${entry.pid}`;
}

export function moduleLabel(tab: WindowsIncidentTab): string {
  return WIN_IR_MODULES.find((module) => module.key === tab)?.label ?? tab;
}

/** Keep the source timestamp intact in copied evidence; only format its label. */
export function collectedTime(value?: string): string | null {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleTimeString("zh-CN", { hour12: false });
}

export const STARTUP_SOURCE_LABELS: Readonly<Record<string, string>> = {
  registry: "注册表自启动",
  "startup-folder": "启动文件夹",
  "scheduled-task": "计划任务",
  service: "服务",
  services: "服务",
};

export function startupSourceLabel(source: string): string {
  return STARTUP_SOURCE_LABELS[source] ?? source;
}
