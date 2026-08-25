import type {
  QuickDetectionCatalog,
  QuickDetectionHistoryPage,
  QuickDetectionModuleId,
  QuickDetectionOutcome,
  QuickDetectionPlan,
  QuickDetectionPoll,
  QuickDetectionProfileId,
  QuickDetectionReport,
  QuickDetectionScanStage,
  QuickDetectionScanStarted,
} from "../shared/quick-detection-contract";

export type QuickDetectionLoadStatus = "idle" | "loading" | "ready" | "error";

export interface QuickDetectionModuleProgress {
  stage: "running" | "finished";
  outcome: QuickDetectionOutcome | null;
}

export interface QuickDetectionState {
  scope: string | null;
  catalogStatus: QuickDetectionLoadStatus;
  catalog: QuickDetectionCatalog | null;
  profile: QuickDetectionProfileId;
  selectedModules: QuickDetectionModuleId[];
  planStatus: QuickDetectionLoadStatus;
  planRequest: number | null;
  plan: QuickDetectionPlan | null;
  scanRequest: number | null;
  scanHandle: string | null;
  scanStage: QuickDetectionScanStage | "idle";
  completed: number;
  total: number;
  currentModule: QuickDetectionModuleId | null;
  eventCursor: number;
  pollRequest: number | null;
  eventsTruncated: boolean;
  moduleProgress: Partial<Record<QuickDetectionModuleId, QuickDetectionModuleProgress>>;
  historyStatus: QuickDetectionLoadStatus;
  historyRequest: number | null;
  history: QuickDetectionHistoryPage | null;
  selectedReportHandle: string | null;
  reportStatus: QuickDetectionLoadStatus;
  reportRequest: number | null;
  report: QuickDetectionReport | null;
  selectedReportModule: QuickDetectionModuleId | null;
  error: string | null;
}

export function createQuickDetectionState(): QuickDetectionState {
  return {
    scope: null,
    catalogStatus: "idle",
    catalog: null,
    profile: "competition-triage",
    selectedModules: [],
    planStatus: "idle",
    planRequest: null,
    plan: null,
    scanRequest: null,
    scanHandle: null,
    scanStage: "idle",
    completed: 0,
    total: 0,
    currentModule: null,
    eventCursor: 0,
    pollRequest: null,
    eventsTruncated: false,
    moduleProgress: {},
    historyStatus: "idle",
    historyRequest: null,
    history: null,
    selectedReportHandle: null,
    reportStatus: "idle",
    reportRequest: null,
    report: null,
    selectedReportModule: null,
    error: null,
  };
}

export type QuickDetectionAction =
  | { type: "scope-changed"; scope: string | null }
  | { type: "catalog-started"; scope: string }
  | { type: "catalog-loaded"; scope: string; catalog: QuickDetectionCatalog }
  | { type: "catalog-failed"; scope: string; error: string }
  | { type: "profile-selected"; profile: QuickDetectionProfileId }
  | { type: "module-toggled"; module: QuickDetectionModuleId }
  | { type: "select-all-modules" }
  | { type: "plan-started"; scope: string; request: number }
  | { type: "plan-loaded"; scope: string; request: number; plan: QuickDetectionPlan }
  | { type: "plan-failed"; scope: string; request: number; error: string }
  | { type: "scan-starting"; scope: string; request: number; planHandle: string }
  | { type: "scan-started"; scope: string; request: number; planHandle: string; started: QuickDetectionScanStarted }
  | { type: "scan-start-failed"; scope: string; request: number; planHandle: string; error: string }
  | { type: "poll-started"; scope: string; scanHandle: string; request: number; afterEvent: number }
  | { type: "poll-loaded"; scope: string; scanHandle: string; request: number; afterEvent: number; poll: QuickDetectionPoll }
  | { type: "poll-failed"; scope: string; scanHandle: string; request: number; afterEvent: number; error: string }
  | { type: "cancel-marked"; scope: string; scanHandle: string }
  | { type: "scan-cancel-failed"; scope: string; scanHandle: string; error: string }
  | { type: "history-started"; scope: string; request: number }
  | { type: "history-loaded"; scope: string; request: number; history: QuickDetectionHistoryPage }
  | { type: "history-failed"; scope: string; request: number; error: string }
  | { type: "report-selected"; handle: string }
  | { type: "report-started"; scope: string; request: number; handle: string }
  | { type: "report-loaded"; scope: string; request: number; handle: string; report: QuickDetectionReport }
  | { type: "report-failed"; scope: string; request: number; handle: string; error: string }
  | { type: "report-module-selected"; module: QuickDetectionModuleId };

export function quickDetectionReducer(
  state: QuickDetectionState,
  action: QuickDetectionAction,
): QuickDetectionState {
  switch (action.type) {
    case "scope-changed":
      return action.scope === state.scope ? state : { ...createQuickDetectionState(), scope: action.scope };
    case "catalog-started":
      if (action.scope !== state.scope) return state;
      return { ...state, catalogStatus: "loading", error: null };
    case "catalog-loaded": {
      if (action.scope !== state.scope) return state;
      const triage = action.catalog.profiles.find((profile) => profile.id === "competition-triage");
      return {
        ...state,
        catalogStatus: "ready",
        catalog: action.catalog,
        selectedModules: triage?.moduleIds ?? [],
        error: null,
      };
    }
    case "catalog-failed":
      if (action.scope !== state.scope) return state;
      return { ...state, catalogStatus: "error", error: action.error };
    case "profile-selected": {
      if (scanActive(state.scanStage) || state.scanRequest !== null || state.catalog === null) return state;
      const selectedModules = action.profile === "competition-triage"
        ? state.catalog.profiles.find((profile) => profile.id === action.profile)?.moduleIds ?? []
        : state.selectedModules;
      return invalidatePlan({ ...state, profile: action.profile, selectedModules });
    }
    case "module-toggled": {
      if (state.profile !== "selected" || scanActive(state.scanStage) || state.scanRequest !== null || state.catalog === null ||
        !state.catalog.modules.some((module) => module.id === action.module)) return state;
      const selectedModules = state.selectedModules.includes(action.module)
        ? state.selectedModules.filter((module) => module !== action.module)
        : [...state.selectedModules, action.module];
      return invalidatePlan({ ...state, selectedModules });
    }
    case "select-all-modules":
      if (state.profile !== "selected" || scanActive(state.scanStage) || state.scanRequest !== null || state.catalog === null) return state;
      return invalidatePlan({ ...state, selectedModules: state.catalog.modules.map((module) => module.id) });
    case "plan-started":
      if (action.scope !== state.scope || scanActive(state.scanStage) || state.scanRequest !== null) return state;
      return { ...state, planStatus: "loading", planRequest: action.request, plan: null, error: null };
    case "plan-loaded":
      if (action.scope !== state.scope || action.request !== state.planRequest) return state;
      return { ...state, planStatus: "ready", planRequest: null, plan: action.plan, error: null };
    case "plan-failed":
      if (action.scope !== state.scope || action.request !== state.planRequest) return state;
      return { ...state, planStatus: "error", planRequest: null, plan: null, error: action.error };
    case "scan-starting":
      if (action.scope !== state.scope || action.request <= 0 || state.scanRequest !== null ||
        state.scanHandle !== null || state.planStatus !== "ready" ||
        state.plan?.planHandle !== action.planHandle) return state;
      return { ...state, scanRequest: action.request, error: null };
    case "scan-started":
      if (action.scope !== state.scope || action.request !== state.scanRequest ||
        state.plan?.planHandle !== action.planHandle) return state;
      return {
        ...state,
        scanRequest: null,
        scanHandle: action.started.scanHandle,
        scanStage: action.started.stage,
        completed: 0,
        total: action.started.total,
        currentModule: null,
        eventCursor: 0,
        pollRequest: null,
        eventsTruncated: false,
        moduleProgress: {},
        planStatus: "idle",
        plan: null,
        selectedReportHandle: null,
        reportStatus: "idle",
        report: null,
        selectedReportModule: null,
        error: null,
      };
    case "scan-start-failed":
      if (action.scope !== state.scope || action.request !== state.scanRequest ||
        state.plan?.planHandle !== action.planHandle) return state;
      return { ...state, scanRequest: null, planStatus: "error", plan: null, error: action.error };
    case "poll-started":
      if (action.scope !== state.scope || action.scanHandle !== state.scanHandle ||
        action.afterEvent !== state.eventCursor || action.request <= 0 || state.pollRequest !== null ||
        !scanActive(state.scanStage)) return state;
      return { ...state, pollRequest: action.request };
    case "poll-loaded": {
      if (action.scope !== state.scope || action.scanHandle !== state.scanHandle ||
        action.request !== state.pollRequest || action.afterEvent !== state.eventCursor ||
        action.poll.scanHandle !== action.scanHandle ||
        action.poll.nextEventCursor < action.afterEvent) return state;
      const moduleProgress = { ...state.moduleProgress };
      for (const event of action.poll.events) {
        if (event.module === null) continue;
        moduleProgress[event.module] = event.kind === "module-started"
          ? { stage: "running", outcome: null }
          : { stage: "finished", outcome: event.outcome };
      }
      const reportChanged = action.poll.reportHandle !== null &&
        action.poll.reportHandle !== state.selectedReportHandle;
      return {
        ...state,
        scanStage: action.poll.stage,
        completed: action.poll.completed,
        total: action.poll.total,
        currentModule: action.poll.currentModule,
        eventCursor: action.poll.nextEventCursor,
        pollRequest: null,
        eventsTruncated: state.eventsTruncated || action.poll.eventsTruncated,
        moduleProgress,
        selectedReportHandle: action.poll.reportHandle ?? state.selectedReportHandle,
        reportStatus: reportChanged ? "idle" : state.reportStatus,
        report: reportChanged ? null : state.report,
        selectedReportModule: reportChanged ? null : state.selectedReportModule,
        error: action.poll.errorCode === null ? state.error : scanErrorMessage(action.poll.errorCode),
      };
    }
    case "poll-failed":
      if (action.scope !== state.scope || action.scanHandle !== state.scanHandle ||
        action.request !== state.pollRequest || action.afterEvent !== state.eventCursor) return state;
      return { ...state, pollRequest: null, scanStage: "failed", currentModule: null, error: action.error };
    case "cancel-marked":
      if (action.scope !== state.scope || action.scanHandle !== state.scanHandle ||
        !scanActive(state.scanStage)) return state;
      return { ...state, scanStage: "cancelling" };
    case "scan-cancel-failed":
      if (action.scope !== state.scope || action.scanHandle !== state.scanHandle ||
        !scanActive(state.scanStage)) return state;
      return { ...state, error: action.error };
    case "history-started":
      if (action.scope !== state.scope) return state;
      return { ...state, historyStatus: "loading", historyRequest: action.request };
    case "history-loaded": {
      if (action.scope !== state.scope || action.request !== state.historyRequest) return state;
      const selectedReportHandle = state.selectedReportHandle !== null &&
        action.history.items.some((item) => item.reportHandle === state.selectedReportHandle)
        ? state.selectedReportHandle
        : state.selectedReportHandle ?? action.history.items[0]?.reportHandle ?? null;
      return {
        ...state,
        historyStatus: "ready",
        historyRequest: null,
        history: action.history,
        selectedReportHandle,
      };
    }
    case "history-failed":
      if (action.scope !== state.scope || action.request !== state.historyRequest) return state;
      return { ...state, historyStatus: "error", historyRequest: null, error: action.error };
    case "report-selected":
      if (action.handle === state.selectedReportHandle && state.reportStatus !== "error") return state;
      return {
        ...state,
        selectedReportHandle: action.handle,
        reportStatus: "idle",
        reportRequest: null,
        report: null,
        selectedReportModule: null,
      };
    case "report-started":
      if (action.scope !== state.scope || action.handle !== state.selectedReportHandle) return state;
      return { ...state, reportStatus: "loading", reportRequest: action.request, report: null };
    case "report-loaded":
      if (action.scope !== state.scope || action.request !== state.reportRequest ||
        action.handle !== state.selectedReportHandle || action.report.reportHandle !== action.handle) return state;
      return {
        ...state,
        reportStatus: "ready",
        reportRequest: null,
        report: action.report,
        selectedReportModule: action.report.modules[0]?.id ?? null,
        error: null,
      };
    case "report-failed":
      if (action.scope !== state.scope || action.request !== state.reportRequest ||
        action.handle !== state.selectedReportHandle) return state;
      return { ...state, reportStatus: "error", reportRequest: null, report: null, error: action.error };
    case "report-module-selected":
      if (!state.report?.modules.some((module) => module.id === action.module)) return state;
      return { ...state, selectedReportModule: action.module };
  }
}

export function quickDetectionScanIsActive(stage: QuickDetectionState["scanStage"]): boolean {
  return scanActive(stage);
}

function scanActive(stage: QuickDetectionState["scanStage"]): boolean {
  return stage === "running" || stage === "cancelling";
}

function invalidatePlan(state: QuickDetectionState): QuickDetectionState {
  return { ...state, planStatus: "idle", planRequest: null, plan: null, error: null };
}

function scanErrorMessage(code: NonNullable<QuickDetectionPoll["errorCode"]>): string {
  switch (code) {
    case "binding-stale": return "SSH 绑定已变化，晚到的扫描结果已被拒绝。";
    case "scan-failed": return "快速检测任务失败。";
    case "report-rejected": return "检测报告未通过目标绑定或容量校验。";
  }
}
