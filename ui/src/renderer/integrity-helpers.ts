import type {
  IntegrityApi,
  IntegrityDiffKind,
  IntegrityOperationStage,
  IntegritySeverity,
} from "../shared/integrity-contract";

export type IntegrityViewStage =
  | "idle"
  | "starting"
  | "cancelling"
  | IntegrityOperationStage;

export function formatIntegrityTime(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "时间不可用" : date.toLocaleString("zh-CN");
}

export function integrityKindLabel(kind: IntegrityDiffKind): string {
  switch (kind) {
    case "added": return "新增";
    case "removed": return "已移除";
    case "modified": return "已修改";
  }
}

export function integritySeverityLabel(severity: IntegritySeverity): string {
  return severity === "high" ? "高危" : "中危";
}

export function integrityOperationIsActive(stage: IntegrityViewStage): boolean {
  return stage === "starting" || stage === "running" || stage === "cancelling";
}

export async function cancelIntegrityLifecycle(
  api: IntegrityApi,
  bindingHandle: string | null,
  operationHandle: string | null,
  stage: IntegrityViewStage,
): Promise<void> {
  if (bindingHandle === null || operationHandle === null || stage !== "running") return;
  await api.cancelIntegrityComparison(bindingHandle, operationHandle);
}
