import type {
  MiddlewareConfigRole,
  MiddlewareHistoryState,
  MiddlewareInstanceStatus,
  MiddlewareInstanceSummary,
  MiddlewareNodeKind,
  MiddlewareProduct,
  MiddlewareRawTextReason,
} from "../shared/middleware-read-contract";
import type {
  MiddlewareProductFilter,
  MiddlewareStatusFilter,
  MiddlewareTab,
} from "./middleware-read-state";

export function middlewareScope(bindingHandle: string): string {
  return bindingHandle;
}

export function filterMiddlewareInstances(
  instances: readonly MiddlewareInstanceSummary[],
  query: string,
  product: MiddlewareProductFilter,
  status: MiddlewareStatusFilter,
): MiddlewareInstanceSummary[] {
  const needle = query.trim().toLocaleLowerCase();
  return instances.filter((instance) => {
    if (product !== "all" && instance.product !== product) return false;
    if (status !== "all" && instance.status !== status) return false;
    if (needle.length === 0) return true;
    return [
      instance.title,
      instance.version,
      instance.statusText,
      middlewareProductLabel(instance.product),
      middlewareStatusLabel(instance.status),
    ].join("\n").toLocaleLowerCase().includes(needle);
  });
}

export function middlewareTabLabel(tab: MiddlewareTab): string {
  return tab === "instances" ? "实例与配置" : "变更历史";
}

export function middlewareProductLabel(product: MiddlewareProduct): string {
  switch (product) {
    case "nginx": return "Nginx";
    case "apache-httpd": return "Apache HTTPD";
    case "redis": return "Redis";
    case "tomcat": return "Tomcat";
  }
}

export function middlewareStatusLabel(status: MiddlewareInstanceStatus): string {
  switch (status) {
    case "active": return "运行中";
    case "inactive": return "未运行";
    case "failed": return "失败";
    case "activating": return "启动中";
    case "deactivating": return "停止中";
    case "reloading": return "重载中";
    case "unknown": return "未知";
  }
}

export function middlewareRoleLabel(role: MiddlewareConfigRole): string {
  switch (role) {
    case "primary": return "主配置";
    case "included": return "包含配置";
    case "tomcat-web": return "Web 默认配置";
    case "tomcat-context": return "Context 配置";
    case "properties": return "属性配置";
    case "logging": return "日志配置";
    case "users": return "用户配置";
    case "other": return "其他配置";
  }
}

export function middlewareNodeKindLabel(kind: MiddlewareNodeKind): string {
  switch (kind) {
    case "preamble": return "前导";
    case "whitespace": return "空白";
    case "comment": return "注释";
    case "directive": return "指令";
    case "block-start": return "块开始";
    case "block-end": return "块结束";
    case "element-start": return "元素开始";
    case "element-end": return "元素结束";
    case "attribute": return "属性";
    case "text": return "文本";
    case "cdata": return "CDATA";
    case "processing-instruction": return "处理指令";
    case "declaration": return "声明";
    case "opaque": return "不透明区域";
  }
}

export function middlewareRawReasonLabel(reason: MiddlewareRawTextReason): string {
  switch (reason) {
    case "available": return "core 与 sidecar 均允许安全原文";
    case "not-safe-text": return "core 未授权安全原文";
    case "sensitive": return "sidecar 检测到 credential-like 文本";
    case "size-limit": return "原文超过独立读取预算";
  }
}

export function middlewareHistoryStateLabel(state: MiddlewareHistoryState): string {
  switch (state) {
    case "recovery-pending": return "恢复待处理";
    case "applied": return "已应用";
    case "automatically-restored": return "已自动恢复";
    case "restore-failed": return "恢复失败";
  }
}

export function formatMiddlewareBytes(value: string): string {
  const bytes = BigInt(value);
  if (bytes < 1024n) return `${bytes} B`;
  if (bytes < 1024n * 1024n) return `${Number(bytes / 1024n).toLocaleString()} KiB`;
  return `${Number(bytes / (1024n * 1024n)).toLocaleString()} MiB`;
}
