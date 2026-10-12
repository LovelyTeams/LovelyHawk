import type {
  BaselineCatalog,
  BaselineCategory,
  BaselineHistory,
  BaselineScan,
} from "../shared/baseline-read-contract";

export type BaselineReadStatus = "idle" | "loading" | "ready" | "error";
export type BaselineTab = "checks" | "history";
export type BaselineComplianceFilter = "all" | "compliant" | "non-compliant" | "unverified" | "unscanned";
export type BaselineCategoryFilter = BaselineCategory | "all";

interface ScopedRequest {
  id: number;
}

export interface BaselineReadState {
  scope: string | null;
  tab: BaselineTab;
  search: string;
  category: BaselineCategoryFilter;
  compliance: BaselineComplianceFilter;
  catalogStatus: BaselineReadStatus;
  catalogRequest: number | null;
  catalog: BaselineCatalog | null;
  catalogError: string | null;
  scanStatus: BaselineReadStatus;
  scanRequest: ScopedRequest | null;
  scan: BaselineScan | null;
  scanError: string | null;
  historyStatus: BaselineReadStatus;
  historyRequest: ScopedRequest | null;
  history: BaselineHistory | null;
  historyError: string | null;
}

export function createBaselineReadState(): BaselineReadState {
  return {
    scope: null,
    tab: "checks",
    search: "",
    category: "all",
    compliance: "all",
    catalogStatus: "idle",
    catalogRequest: null,
    catalog: null,
    catalogError: null,
    scanStatus: "idle",
    scanRequest: null,
    scan: null,
    scanError: null,
    historyStatus: "idle",
    historyRequest: null,
    history: null,
    historyError: null,
  };
}

export type BaselineReadAction =
  | { type: "scope-changed"; scope: string | null }
  | { type: "deactivated"; scope: string | null }
  | { type: "tab-selected"; tab: BaselineTab }
  | { type: "search-changed"; value: string }
  | { type: "category-changed"; value: BaselineCategoryFilter }
  | { type: "compliance-changed"; value: BaselineComplianceFilter }
  | { type: "catalog-started"; request: number }
  | { type: "catalog-loaded"; request: number; catalog: BaselineCatalog }
  | { type: "catalog-failed"; request: number; error: string }
  | { type: "scan-started"; scope: string; request: ScopedRequest }
  | { type: "scan-loaded"; scope: string; request: ScopedRequest; scan: BaselineScan }
  | { type: "scan-failed"; scope: string; request: ScopedRequest; error: string }
  | { type: "history-started"; scope: string; request: ScopedRequest }
  | { type: "history-loaded"; scope: string; request: ScopedRequest; history: BaselineHistory }
  | { type: "history-failed"; scope: string; request: ScopedRequest; error: string };

export function baselineReadReducer(
  state: BaselineReadState,
  action: BaselineReadAction,
): BaselineReadState {
  switch (action.type) {
    case "scope-changed":
      if (action.scope === state.scope) return state;
      return {
        ...state,
        scope: action.scope,
        scanStatus: "idle",
        scanRequest: null,
        scan: null,
        scanError: null,
        historyStatus: "idle",
        historyRequest: null,
        history: null,
        historyError: null,
      };
    case "deactivated":
      if (action.scope !== state.scope) return state;
      return {
        ...state,
        scanStatus: "idle",
        scanRequest: null,
        scan: null,
        scanError: null,
        historyStatus: "idle",
        historyRequest: null,
        history: null,
        historyError: null,
      };
    case "tab-selected":
      if (action.tab === state.tab) return state;
      return {
        ...state,
        tab: action.tab,
        scanStatus: action.tab === "history" && state.scanStatus === "loading"
          ? "idle"
          : state.scanStatus,
        scanRequest: action.tab === "checks" ? state.scanRequest : null,
        historyStatus: action.tab === "checks" && state.historyStatus === "loading"
          ? "idle"
          : state.historyStatus,
        historyRequest: action.tab === "history" ? state.historyRequest : null,
      };
    case "search-changed":
      return { ...state, search: action.value };
    case "category-changed":
      return { ...state, category: action.value };
    case "compliance-changed":
      return { ...state, compliance: action.value };
    case "catalog-started":
      return {
        ...state,
        catalogStatus: "loading",
        catalogRequest: action.request,
        catalog: null,
        catalogError: null,
        scanStatus: "idle",
        scanRequest: null,
        scan: null,
        scanError: null,
      };
    case "catalog-loaded":
      if (state.catalogRequest !== action.request) return state;
      return {
        ...state,
        catalogStatus: "ready",
        catalogRequest: null,
        catalog: action.catalog,
        catalogError: null,
      };
    case "catalog-failed":
      if (state.catalogRequest !== action.request) return state;
      return {
        ...state,
        catalogStatus: "error",
        catalogRequest: null,
        catalog: null,
        catalogError: action.error,
      };
    case "scan-started":
      if (state.scope !== action.scope || state.tab !== "checks" || state.catalog === null) return state;
      return {
        ...state,
        scanStatus: "loading",
        scanRequest: action.request,
        scan: null,
        scanError: null,
      };
    case "scan-loaded":
      if (!sameRequest(state.scope, state.scanRequest, action.scope, action.request) ||
        state.tab !== "checks" || !scanMatchesCatalog(action.scan, state.catalog)) return state;
      return {
        ...state,
        scanStatus: "ready",
        scanRequest: null,
        scan: action.scan,
        scanError: null,
      };
    case "scan-failed":
      if (!sameRequest(state.scope, state.scanRequest, action.scope, action.request) ||
        state.tab !== "checks") return state;
      return {
        ...state,
        scanStatus: "error",
        scanRequest: null,
        scan: null,
        scanError: action.error,
      };
    case "history-started":
      if (state.scope !== action.scope || state.tab !== "history") return state;
      return {
        ...state,
        historyStatus: "loading",
        historyRequest: action.request,
        history: null,
        historyError: null,
      };
    case "history-loaded":
      if (!sameRequest(state.scope, state.historyRequest, action.scope, action.request) ||
        state.tab !== "history") return state;
      return {
        ...state,
        historyStatus: "ready",
        historyRequest: null,
        history: action.history,
        historyError: null,
      };
    case "history-failed":
      if (!sameRequest(state.scope, state.historyRequest, action.scope, action.request) ||
        state.tab !== "history") return state;
      return {
        ...state,
        historyStatus: "error",
        historyRequest: null,
        history: null,
        historyError: action.error,
      };
  }
}

function sameRequest(
  currentScope: string | null,
  current: ScopedRequest | null,
  scope: string,
  request: ScopedRequest,
): boolean {
  return currentScope === scope && current?.id === request.id;
}

function scanMatchesCatalog(scan: BaselineScan, catalog: BaselineCatalog | null): boolean {
  if (catalog === null) return false;
  const handles = new Set(catalog.items.map((item) => item.itemHandle));
  return scan.statuses.every((status) => handles.has(status.itemHandle));
}
