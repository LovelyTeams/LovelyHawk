import type {
  BaselineCatalogItem,
  BaselineCategory,
  BaselineComponent,
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

/** One product's worth of checks, with how many of them failed. */
export interface BaselineCheckGroup {
  component: BaselineComponent;
  items: BaselineVisibleItem[];
  failing: number;
  /** True when this software is not on the target at all. */
  absent: boolean;
}

/** The order the products are read in: the machine itself, then what it runs. */
const COMPONENT_ORDER: readonly BaselineComponent[] = [
  "system", "ssh", "mysql", "postgresql", "redis", "mongodb", "nginx", "apache", "tomcat",
  "opengauss", "tidb", "haproxy",
];

/** A check on software the target does not run is neither passed nor failed. */
export function baselineApplies(status: BaselineStatus | null): boolean {
  return status === null || status.observedKind !== "not-installed";
}

/**
 * Groups what is on screen by the software each check is about.
 *
 * Ninety-odd checks in one flat list is a scroll, not a picture, and the
 * grouping that helps is the one that matches the question: an operator sent
 * to harden the database wants the database's checks together. Which kind of
 * hardening each is stays available as a filter.
 */
export function groupBaselineChecks(visible: readonly BaselineVisibleItem[]): BaselineCheckGroup[] {
  const groups = new Map<BaselineComponent, BaselineVisibleItem[]>();
  for (const entry of visible) {
    const bucket = groups.get(entry.item.component);
    if (bucket === undefined) groups.set(entry.item.component, [entry]);
    else bucket.push(entry);
  }
  return COMPONENT_ORDER.flatMap((component) => {
    const items = groups.get(component);
    if (items === undefined || items.length === 0) return [];
    const scanned = items.filter((entry) => entry.status !== null);
    return [{
      component,
      items,
      failing: items.filter((entry) =>
        entry.status !== null && !entry.status.compliant && baselineApplies(entry.status)).length,
      absent: scanned.length > 0 && scanned.every((entry) => !baselineApplies(entry.status)),
    }];
  });
}

/** The one line a compact card can spare for what the target actually has. */
export function baselineValueSummary(
  item: BaselineCatalogItem,
  status: BaselineStatus | null,
): string {
  const wanted = item.valueKind.kind === "choice" && item.valueKind.options.length === 1
    ? item.valueKind.options[0] ?? item.recommendation
    : item.recommendation;
  if (status === null) return `建议 ${wanted}`;
  if (!baselineApplies(status)) return "这台机器上没有这个软件";
  if (status.compliant) return `${wanted}，符合`;
  return `建议 ${wanted}，实际 ${status.observed}`;
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
    case "access-control": return "访问控制";
    case "transport": return "传输加密";
    case "service-hardening": return "服务加固";
  }
}

export function baselineComponentLabel(component: BaselineComponent): string {
  switch (component) {
    case "system": return "操作系统";
    case "ssh": return "SSH 服务";
    case "mysql": return "MySQL / MariaDB";
    case "postgresql": return "PostgreSQL";
    case "redis": return "Redis";
    case "mongodb": return "MongoDB";
    case "nginx": return "Nginx";
    case "apache": return "Apache";
    case "tomcat": return "Apache Tomcat";
    case "opengauss": return "openGauss";
    case "tidb": return "TiDB";
    case "haproxy": return "HAProxy";
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
  if (!baselineApplies(status)) return "不适用";
  return status.compliant ? "符合" : "不符合";
}
