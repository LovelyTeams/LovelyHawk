import {
  defaultCheckAuditCommands,
  isCheckAuditCommandName,
  isCheckAuditLogInput,
  type CheckAuditCatalogCommand,
  type CheckAuditCommandState,
  type CheckAuditCycleCategory,
  type CheckAuditLogEntry,
  type CheckAuditLogInput,
  type CheckAuditLogState,
  type CheckAuditSuggestionSeverity,
} from "../shared/check-audit-read-contract";
import type { CheckAuditTab } from "./check-audit-read-state";

const defaultNames = new Set<string>(defaultCheckAuditCommands);

export function checkAuditScope(bindingHandle: string): string {
  return `binding:${bindingHandle}`;
}

export function normalizeCustomAuditCommand(
  draft: string,
  existing: readonly string[],
): { name: string | null; error: string | null } {
  const name = draft.trim();
  if (!isCheckAuditCommandName(name)) {
    return { name: null, error: "命令名必须以字母或数字开头，只能包含字母、数字、. _ + -，且不超过 128 字节。" };
  }
  if (defaultNames.has(name)) return { name: null, error: "该命令已在固定默认目录中。" };
  if (existing.includes(name)) return { name: null, error: "该自定义命令已存在。" };
  if (existing.length >= 15) return { name: null, error: "最多添加 15 个自定义命令。" };
  return { name, error: null };
}

export function buildCheckAuditLogInput(
  limit: number,
  draftSearch: string,
): { input: CheckAuditLogInput | null; error: string | null } {
  if (![50, 100, 200].includes(limit)) {
    return { input: null, error: "读取上限只能为 50、100 或 200。" };
  }
  const search = draftSearch.trim();
  const input: CheckAuditLogInput = { limit, search: search.length === 0 ? null : search };
  return isCheckAuditLogInput(input)
    ? { input, error: null }
    : { input: null, error: "日志搜索必须是 256 字节以内的单行文本，读取上限只能为 50、100 或 200。" };
}

export function filterCheckAuditCommands(
  commands: readonly CheckAuditCatalogCommand[],
  query: string,
): CheckAuditCatalogCommand[] {
  const needle = query.trim().toLocaleLowerCase();
  if (needle.length === 0) return [...commands];
  return commands.filter((command) => command.name.toLocaleLowerCase().includes(needle));
}

export function checkAuditTabLabel(tab: CheckAuditTab): string {
  switch (tab) {
    case "commands": return "命令";
    case "logs": return "日志";
    case "analysis": return "周期分析";
    case "suggestions": return "建议";
  }
}

/**
 * What the collector can tell about a command: whether this tool's collection
 * wrapper is on it, and whether it is a program or a script. "未加采集" says
 * nothing about whether the program itself is genuine.
 */
export function checkAuditStateLabel(state: CheckAuditCommandState): string {
  switch (state) {
    case "original": return "未加采集";
    case "instrumented": return "已加采集";
    case "missing": return "未安装";
    case "foreign-script": return "是脚本（非本工具）";
    case "coreutils-shim": return "转到 coreutils（发行版写法）";
    case "multi-call": return "BusyBox 等多合一程序";
  }
}

/** Why the log tabs have nothing to show, when nothing was read. */
export function checkAuditLogStateText(state: Exclude<CheckAuditLogState, "read">): { title: string; detail: string } {
  switch (state) {
    case "absent": return {
      title: "这台主机上没有命令审计日志",
      detail: `只有为命令加上采集之后才会产生日志（${CHECK_AUDIT_LOG_PATH}）。没有日志不代表这些命令没有被执行过。`,
    };
    case "not-regular-file": return {
      title: "日志的位置上不是普通文件，没有读取",
      detail: `${CHECK_AUDIT_LOG_PATH} 或它所在的目录是符号链接、目录或其他特殊文件。为避免读到别处的内容，这里不跟随它。日志被换成这样本身值得核查。`,
    };
    case "unreadable": return {
      title: "日志存在，但当前账号读不了",
      detail: `${CHECK_AUDIT_LOG_PATH} 或它所在的目录不允许当前账号读取。请用有权限的账号（通常是 root）连接后再读；没有读到不代表没有记录。`,
    };
  }
}

/** The clipboard limit the host enforces for one copy. */
export const CHECK_AUDIT_COPY_MAX_BYTES = 128 * 1_024;

/**
 * The shown log records as tab-separated text, one row each under a header.
 * Tabs, line breaks and backslashes inside a field are written as \t, \n, \r
 * and \\ so every row stays one line and nothing in it is lost.
 */
export function checkAuditLogTsv(entries: readonly CheckAuditLogEntry[]): string {
  const field = (value: string) => value.replace(/\\/gu, "\\\\").replace(/\t/gu, "\\t").replace(/\n/gu, "\\n").replace(/\r/gu, "\\r");
  const rows = entries.map((entry) => entry.malformed
    ? ["", "", field(entry.args), "", "", "", "", "是", "不是审计记录"]
    : [field(entry.timestamp), field(entry.command), field(entry.args), field(entry.user), String(entry.pid), String(entry.ppid),
      field(entry.caller), entry.suspicious ? "是" : "否", ""]);
  return [["时间", "命令", "参数", "用户", "PID", "PPID", "调用者", "可疑", "格式"], ...rows]
    .map((row) => row.join("\t")).join("\n") + "\n";
}

/** Where the collection wrappers write; fixed by the core, shown for reference only. */
export const CHECK_AUDIT_LOG_PATH = "/var/log/lovelyres/command-audit.log";

export function checkAuditCategoryLabel(category: CheckAuditCycleCategory): string {
  switch (category) {
    case "file-read": return "文件读取";
    case "service-check": return "服务探测";
    case "network": return "网络访问";
    case "database": return "数据库";
    case "process": return "进程行为";
  }
}

export function checkAuditSeverityLabel(severity: CheckAuditSuggestionSeverity): string {
  switch (severity) {
    case "critical": return "高风险";
    case "warning": return "需关注";
    case "info": return "信息";
  }
}

export function checkAuditIntervalLabel(intervalSeconds: number | null): string {
  return intervalSeconds === null ? "未识别周期" : `约每 ${intervalSeconds} 秒`;
}
