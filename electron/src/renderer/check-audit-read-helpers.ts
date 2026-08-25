import {
  defaultCheckAuditCommands,
  isCheckAuditCommandName,
  isCheckAuditLogInput,
  type CheckAuditCatalogCommand,
  type CheckAuditCommandState,
  type CheckAuditCycleCategory,
  type CheckAuditLogInput,
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

export function checkAuditStateLabel(state: CheckAuditCommandState): string {
  switch (state) {
    case "original": return "原始二进制";
    case "instrumented": return "已采集";
    case "missing": return "未安装";
    case "foreign-script": return "未知脚本";
  }
}

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
