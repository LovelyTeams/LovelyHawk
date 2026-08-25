import type {
  QuickDetectionApi,
  QuickDetectionModuleReport,
  QuickDetectionOutcome,
  QuickDetectionPlanInput,
  QuickDetectionProfileId,
  QuickDetectionReportStatus,
  QuickDetectionScanStage,
  QuickDetectionSeverity,
} from "../shared/quick-detection-contract";

export type QuickDetectionResultFilter = "all" | QuickDetectionOutcome;

export function createQuickDetectionPlanInput(
  profile: QuickDetectionProfileId,
  selectedModules: QuickDetectionPlanInput["moduleIds"],
  maximumFindingsPerModule: number,
): QuickDetectionPlanInput {
  return {
    profile,
    moduleIds: profile === "selected" ? selectedModules : [],
    maximumFindingsPerModule,
  };
}

export function filterQuickDetectionModules(
  modules: readonly QuickDetectionModuleReport[],
  query: string,
  filter: QuickDetectionResultFilter,
): QuickDetectionModuleReport[] {
  const needle = query.trim().toLocaleLowerCase();
  return modules.filter((module) => {
    if (filter !== "all" && module.outcome !== filter) return false;
    if (needle.length === 0) return true;
    return module.id.includes(needle) ||
      module.label.toLocaleLowerCase().includes(needle) ||
      module.rawText.toLocaleLowerCase().includes(needle) ||
      module.findings.some((finding) =>
        finding.title.toLocaleLowerCase().includes(needle) ||
        finding.description.toLocaleLowerCase().includes(needle) ||
        finding.recommendation?.toLocaleLowerCase().includes(needle),
      );
  });
}

export function quickDetectionProgress(completed: number, total: number): number {
  if (total <= 0) return 0;
  return Math.max(0, Math.min(100, Math.round((completed / total) * 100)));
}

export function quickDetectionOutcomeLabel(outcome: QuickDetectionOutcome): string {
  switch (outcome) {
    case "passed": return "通过";
    case "failed": return "发现风险";
    case "not-applicable": return "不适用";
    case "error": return "检测错误";
    case "cancelled": return "已取消";
  }
}

export function quickDetectionSeverityLabel(severity: QuickDetectionSeverity): string {
  switch (severity) {
    case "info": return "信息";
    case "low": return "低";
    case "medium": return "中";
    case "high": return "高";
    case "critical": return "严重";
  }
}

export function quickDetectionStatusLabel(status: QuickDetectionReportStatus): string {
  switch (status) {
    case "completed": return "完成";
    case "partial": return "部分完成";
    case "cancelled": return "已取消";
  }
}

export function formatQuickDetectionTime(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "—" : date.toLocaleString("zh-CN", { hour12: false });
}

export function quickDetectionStageIsActive(stage: QuickDetectionScanStage | "idle"): boolean {
  return stage === "running" || stage === "cancelling";
}

export async function cancelQuickDetectionLifecycle(
  api: QuickDetectionApi,
  bindingHandle: string,
  scanHandle: string,
  stage: QuickDetectionScanStage | "idle",
): Promise<void> {
  if (!quickDetectionStageIsActive(stage)) return;
  try {
    await api.cancelQuickDetection(bindingHandle, scanHandle);
  } catch {
    // Binding revocation can win the race with React cleanup. The backend has
    // already invalidated the scan registry, so there is nothing else to send.
  }
}
