import type {
  BaselineCatalogItem,
  BaselineCategory,
  BaselineHistoryState,
  BaselineRisk,
  BaselineScan,
  BaselineStatus,
  BaselineValueKind,
} from "../shared/baseline-read-contract";
import type {
  BaselineCategoryFilter,
  BaselineComplianceFilter,
  BaselineTab,
} from "./baseline-read-state";

export interface BaselineVisibleItem {
  item: BaselineCatalogItem;
  status: BaselineStatus | null;
}

export function baselineScope(bindingHandle: string): string {
  return bindingHandle;
}

export function filterBaselineItems(
  items: readonly BaselineCatalogItem[],
  scan: BaselineScan | null,
  query: string,
  category: BaselineCategoryFilter,
  compliance: BaselineComplianceFilter,
): BaselineVisibleItem[] {
  const byHandle = new Map(scan?.statuses.map((status) => [status.itemHandle, status]) ?? []);
  const needle = query.trim().toLocaleLowerCase();
  const visible: BaselineVisibleItem[] = [];
  for (const item of items) {
    const status = byHandle.get(item.itemHandle) ?? null;
    if (category !== "all" && item.category !== category) continue;
    if (compliance === "compliant" && status?.compliant !== true) continue;
    if (compliance === "non-compliant" && (status === null || status.compliant)) continue;
    if (compliance === "unscanned" && status !== null) continue;
    if (needle.length > 0) {
      const valueKind = item.valueKind.kind === "choice"
        ? item.valueKind.options.join(" ")
        : `${item.valueKind.minimum} ${item.valueKind.maximum}`;
      const searchable = [
        item.title,
        item.description,
        item.recommendation,
        baselineCategoryLabel(item.category),
        baselineRiskLabel(item.risk),
        valueKind,
        status?.observed ?? "",
      ].join("\n").toLocaleLowerCase();
      if (!searchable.includes(needle)) continue;
    }
    visible.push({ item, status });
  }
  return visible;
}

export function baselineTabLabel(tab: BaselineTab): string {
  return tab === "checks" ? "基线检查" : "变更历史";
}

export function baselineCategoryLabel(category: BaselineCategory): string {
  switch (category) {
    case "ssh": return "SSH 安全";
    case "password": return "密码策略";
    case "kernel": return "内核加固";
    case "network": return "网络参数";
    case "authentication": return "认证防护";
    case "logging": return "审计日志";
    case "file-permissions": return "文件权限";
  }
}

export function baselineRiskLabel(risk: BaselineRisk): string {
  switch (risk) {
    case "critical": return "严重";
    case "high": return "高";
    case "medium": return "中";
    case "low": return "低";
  }
}

export function baselineValueKindLabel(valueKind: BaselineValueKind): string {
  return valueKind.kind === "choice"
    ? `选项：${valueKind.options.join(" / ")}`
    : `整数范围：${valueKind.minimum}–${valueKind.maximum}`;
}

export function baselineHistoryStateLabel(state: BaselineHistoryState): string {
  return state === "applied" ? "已应用" : "已恢复";
}

export function baselineComplianceLabel(status: BaselineStatus | null): string {
  if (status === null) return "尚未扫描";
  return status.compliant ? "符合" : "不符合";
}
