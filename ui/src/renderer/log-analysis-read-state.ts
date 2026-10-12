import type {
  LogCorrelationResult,
  LogIocSearchResult,
  LogSourceReadResult,
  LogSourceSnapshot,
} from "../shared/log-analysis-read-contract";

export type LogAnalysisStatus = "idle" | "loading" | "ready" | "error";

/**
 * The furthest page the reader will go to.
 *
 * Shared with the view so the jump box refuses the same page the reducer
 * would have dropped on the floor, rather than looking like it worked.
 */
export const MAX_LOG_PAGE = 10_000;
export type LogAnalysisTab = "browse" | "correlation" | "ioc";

export interface LogReadFilter {
  keyword: string;
  date: string;
  journalUnit: string;
}

interface ReadRequest {
  id: number;
  snapshotHandle: string;
  sourceHandle: string;
  page: number;
}

interface CorrelationRequest {
  id: number;
  snapshotHandle: string;
  sourceHandles: string[];
}

interface IocRequest extends CorrelationRequest {
  indicators: string[];
}

export interface LogAnalysisReadState {
  scope: string | null;
  tab: LogAnalysisTab;
  sourceFilter: string;
  snapshotStatus: LogAnalysisStatus;
  snapshotRequest: number | null;
  snapshot: LogSourceSnapshot | null;
  snapshotError: string | null;
  selectedSourceHandle: string | null;
  appliedFilter: LogReadFilter;
  page: number;
  readStatus: LogAnalysisStatus;
  readRequest: ReadRequest | null;
  read: LogSourceReadResult | null;
  readError: string | null;
  analysisSourceHandles: string[];
  correlationStatus: LogAnalysisStatus;
  correlationRequest: CorrelationRequest | null;
  correlation: LogCorrelationResult | null;
  correlationError: string | null;
  iocStatus: LogAnalysisStatus;
  iocRequest: IocRequest | null;
  ioc: LogIocSearchResult | null;
  iocError: string | null;
}

const emptyFilter: LogReadFilter = { keyword: "", date: "", journalUnit: "" };

export function createLogAnalysisReadState(): LogAnalysisReadState {
  return {
    scope: null,
    tab: "browse",
    sourceFilter: "",
    snapshotStatus: "idle",
    snapshotRequest: null,
    snapshot: null,
    snapshotError: null,
    selectedSourceHandle: null,
    appliedFilter: emptyFilter,
    page: 1,
    readStatus: "idle",
    readRequest: null,
    read: null,
    readError: null,
    analysisSourceHandles: [],
    correlationStatus: "idle",
    correlationRequest: null,
    correlation: null,
    correlationError: null,
    iocStatus: "idle",
    iocRequest: null,
    ioc: null,
    iocError: null,
  };
}

export type LogAnalysisReadAction =
  | { type: "scope-changed"; scope: string | null }
  | { type: "tab-selected"; tab: LogAnalysisTab }
  | { type: "source-filter-changed"; value: string }
  | { type: "snapshot-started"; scope: string; request: number }
  | { type: "snapshot-loaded"; scope: string; request: number; snapshot: LogSourceSnapshot }
  | { type: "snapshot-failed"; scope: string; request: number; error: string }
  | { type: "source-selected"; handle: string }
  | { type: "filter-applied"; filter: LogReadFilter }
  | { type: "page-selected"; page: number }
  | { type: "read-started"; scope: string; request: ReadRequest }
  | { type: "read-loaded"; scope: string; request: ReadRequest; result: LogSourceReadResult }
  | { type: "read-failed"; scope: string; request: ReadRequest; error: string }
  | { type: "analysis-source-toggled"; handle: string }
  | { type: "correlation-started"; scope: string; request: CorrelationRequest }
  | { type: "correlation-loaded"; scope: string; request: CorrelationRequest; result: LogCorrelationResult }
  | { type: "correlation-failed"; scope: string; request: CorrelationRequest; error: string }
  | { type: "ioc-started"; scope: string; request: IocRequest }
  | { type: "ioc-loaded"; scope: string; request: IocRequest; result: LogIocSearchResult }
  | { type: "ioc-failed"; scope: string; request: IocRequest; error: string };

export function logAnalysisReadReducer(
  state: LogAnalysisReadState,
  action: LogAnalysisReadAction,
): LogAnalysisReadState {
  switch (action.type) {
    case "scope-changed":
      return action.scope === state.scope ? state : { ...createLogAnalysisReadState(), scope: action.scope };
    case "tab-selected": {
      if (action.tab === state.tab) return state;
      return {
        ...state,
        tab: action.tab,
        readStatus: state.readStatus === "loading" ? "idle" : state.readStatus,
        readRequest: null,
        correlationStatus: state.correlationStatus === "loading" ? "idle" : state.correlationStatus,
        correlationRequest: null,
        iocStatus: state.iocStatus === "loading" ? "idle" : state.iocStatus,
        iocRequest: null,
      };
    }
    case "source-filter-changed":
      return { ...state, sourceFilter: action.value };
    case "snapshot-started":
      if (action.scope !== state.scope) return state;
      return {
        ...createLogAnalysisReadState(),
        scope: state.scope,
        tab: state.tab,
        sourceFilter: state.sourceFilter,
        snapshotStatus: "loading",
        snapshotRequest: action.request,
      };
    case "snapshot-loaded": {
      if (action.scope !== state.scope || action.request !== state.snapshotRequest) return state;
      const files = action.snapshot.sources.filter((source) => source.kind === "file");
      return {
        ...state,
        snapshotStatus: "ready",
        snapshotRequest: null,
        snapshot: action.snapshot,
        snapshotError: null,
        selectedSourceHandle: action.snapshot.sources[0]?.sourceHandle ?? null,
        analysisSourceHandles: files.slice(0, 2).map((source) => source.sourceHandle),
      };
    }
    case "snapshot-failed":
      if (action.scope !== state.scope || action.request !== state.snapshotRequest) return state;
      return { ...state, snapshotStatus: "error", snapshotRequest: null, snapshotError: action.error };
    case "source-selected":
      if (!state.snapshot?.sources.some((source) => source.sourceHandle === action.handle)) return state;
      return resetRead({ ...state, selectedSourceHandle: action.handle });
    case "filter-applied":
      return resetRead({ ...state, appliedFilter: { ...action.filter } });
    case "page-selected":
      if (!Number.isSafeInteger(action.page) || action.page < 1 || action.page > MAX_LOG_PAGE) {
        return state;
      }
      return resetRead({ ...state, page: action.page }, false);
    case "read-started":
      if (!sameReadTarget(state, action.scope, action.request)) return state;
      return { ...state, readStatus: "loading", readRequest: action.request, read: null, readError: null };
    case "read-loaded": {
      if (!sameReadRequest(state, action.scope, action.request)) return state;
      const selected = state.snapshot?.sources.find((source) => source.sourceHandle === action.request.sourceHandle);
      if (selected === undefined || action.result.snapshotHandle !== action.request.snapshotHandle ||
        action.result.sourceHandle !== action.request.sourceHandle || action.result.page !== action.request.page ||
        action.result.sourceKind !== selected.kind) return state;
      return { ...state, readStatus: "ready", readRequest: null, read: action.result, readError: null };
    }
    case "read-failed":
      if (!sameReadRequest(state, action.scope, action.request)) return state;
      return { ...state, readStatus: "error", readRequest: null, read: null, readError: action.error };
    case "analysis-source-toggled": {
      const source = state.snapshot?.sources.find((item) => item.sourceHandle === action.handle);
      if (source?.kind !== "file") return state;
      const selected = state.analysisSourceHandles.includes(action.handle)
        ? state.analysisSourceHandles.filter((handle) => handle !== action.handle)
        : state.analysisSourceHandles.length < 8 ? [...state.analysisSourceHandles, action.handle] : state.analysisSourceHandles;
      if (selected === state.analysisSourceHandles) return state;
      return resetAnalysisResults({ ...state, analysisSourceHandles: selected });
    }
    case "correlation-started":
      if (!sameAnalysisTarget(state, action.scope, action.request) || action.request.sourceHandles.length < 2) return state;
      return { ...state, correlationStatus: "loading", correlationRequest: action.request, correlation: null, correlationError: null };
    case "correlation-loaded":
      if (!sameCorrelationRequest(state, action.scope, action.request) ||
        action.result.snapshotHandle !== action.request.snapshotHandle ||
        !sameStrings(action.result.sourceHandles, action.request.sourceHandles)) return state;
      return { ...state, correlationStatus: "ready", correlationRequest: null, correlation: action.result, correlationError: null };
    case "correlation-failed":
      if (!sameCorrelationRequest(state, action.scope, action.request)) return state;
      return { ...state, correlationStatus: "error", correlationRequest: null, correlation: null, correlationError: action.error };
    case "ioc-started":
      if (!sameAnalysisTarget(state, action.scope, action.request) || action.request.sourceHandles.length < 1 ||
        action.request.indicators.length < 1) return state;
      return { ...state, iocStatus: "loading", iocRequest: action.request, ioc: null, iocError: null };
    case "ioc-loaded":
      if (!sameIocRequest(state, action.scope, action.request) ||
        action.result.snapshotHandle !== action.request.snapshotHandle ||
        action.result.results.some((item) => !action.request.sourceHandles.includes(item.sourceHandle) ||
          !action.request.indicators.includes(item.indicator))) return state;
      return { ...state, iocStatus: "ready", iocRequest: null, ioc: action.result, iocError: null };
    case "ioc-failed":
      if (!sameIocRequest(state, action.scope, action.request)) return state;
      return { ...state, iocStatus: "error", iocRequest: null, ioc: null, iocError: action.error };
  }
}

function resetRead(state: LogAnalysisReadState, resetPage = true): LogAnalysisReadState {
  return {
    ...state,
    page: resetPage ? 1 : state.page,
    readStatus: "idle",
    readRequest: null,
    read: null,
    readError: null,
  };
}

function resetAnalysisResults(state: LogAnalysisReadState): LogAnalysisReadState {
  return {
    ...state,
    correlationStatus: "idle",
    correlationRequest: null,
    correlation: null,
    correlationError: null,
    iocStatus: "idle",
    iocRequest: null,
    ioc: null,
    iocError: null,
  };
}

function sameReadTarget(state: LogAnalysisReadState, scope: string, request: ReadRequest): boolean {
  return state.scope === scope && state.snapshot?.snapshotHandle === request.snapshotHandle &&
    state.selectedSourceHandle === request.sourceHandle && state.page === request.page;
}

function sameReadRequest(state: LogAnalysisReadState, scope: string, request: ReadRequest): boolean {
  return sameReadTarget(state, scope, request) && state.readRequest?.id === request.id &&
    state.readRequest.snapshotHandle === request.snapshotHandle &&
    state.readRequest.sourceHandle === request.sourceHandle && state.readRequest.page === request.page;
}

function sameAnalysisTarget(
  state: LogAnalysisReadState,
  scope: string,
  request: CorrelationRequest,
): boolean {
  return state.scope === scope && state.snapshot?.snapshotHandle === request.snapshotHandle &&
    sameStrings(state.analysisSourceHandles, request.sourceHandles);
}

function sameCorrelationRequest(
  state: LogAnalysisReadState,
  scope: string,
  request: CorrelationRequest,
): boolean {
  return sameAnalysisTarget(state, scope, request) && state.correlationRequest?.id === request.id &&
    sameStrings(state.correlationRequest.sourceHandles, request.sourceHandles);
}

function sameIocRequest(state: LogAnalysisReadState, scope: string, request: IocRequest): boolean {
  return sameAnalysisTarget(state, scope, request) && state.iocRequest?.id === request.id &&
    sameStrings(state.iocRequest.sourceHandles, request.sourceHandles) &&
    sameStrings(state.iocRequest.indicators, request.indicators);
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}
