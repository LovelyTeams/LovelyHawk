import type {
  MiddlewareConfiguration,
  MiddlewareDiscovery,
  MiddlewareHistory,
  MiddlewareInstanceStatus,
  MiddlewareProduct,
} from "../shared/middleware-read-contract";

export type MiddlewareReadStatus = "idle" | "loading" | "ready" | "error";
export type MiddlewareTab = "instances" | "history";
export type MiddlewareProductFilter = MiddlewareProduct | "all";
export type MiddlewareStatusFilter = MiddlewareInstanceStatus | "all";

interface ScopedRequest {
  id: number;
}

export interface MiddlewareReadState {
  scope: string | null;
  tab: MiddlewareTab;
  search: string;
  product: MiddlewareProductFilter;
  status: MiddlewareStatusFilter;
  discoveryStatus: MiddlewareReadStatus;
  discoveryRequest: ScopedRequest | null;
  discovery: MiddlewareDiscovery | null;
  discoveryError: string | null;
  selectedInstanceHandle: string | null;
  configurationStatus: MiddlewareReadStatus;
  configurationRequest: ScopedRequest | null;
  configuration: MiddlewareConfiguration | null;
  configurationError: string | null;
  historyStatus: MiddlewareReadStatus;
  historyRequest: ScopedRequest | null;
  history: MiddlewareHistory | null;
  historyError: string | null;
}

export function createMiddlewareReadState(): MiddlewareReadState {
  return {
    scope: null,
    tab: "instances",
    search: "",
    product: "all",
    status: "all",
    discoveryStatus: "idle",
    discoveryRequest: null,
    discovery: null,
    discoveryError: null,
    selectedInstanceHandle: null,
    configurationStatus: "idle",
    configurationRequest: null,
    configuration: null,
    configurationError: null,
    historyStatus: "idle",
    historyRequest: null,
    history: null,
    historyError: null,
  };
}

export type MiddlewareReadAction =
  | { type: "scope-changed"; scope: string | null }
  | { type: "tab-selected"; tab: MiddlewareTab }
  | { type: "search-changed"; value: string }
  | { type: "product-changed"; value: MiddlewareProductFilter }
  | { type: "status-changed"; value: MiddlewareStatusFilter }
  | { type: "discovery-started"; scope: string; request: ScopedRequest }
  | { type: "discovery-loaded"; scope: string; request: ScopedRequest; discovery: MiddlewareDiscovery }
  | { type: "discovery-failed"; scope: string; request: ScopedRequest; error: string }
  | { type: "instance-selected"; instanceHandle: string }
  | { type: "configuration-started"; scope: string; request: ScopedRequest }
  | {
    type: "configuration-loaded";
    scope: string;
    request: ScopedRequest;
    configuration: MiddlewareConfiguration;
  }
  | { type: "configuration-failed"; scope: string; request: ScopedRequest; error: string }
  | { type: "history-started"; scope: string; request: ScopedRequest }
  | { type: "history-loaded"; scope: string; request: ScopedRequest; history: MiddlewareHistory }
  | { type: "history-failed"; scope: string; request: ScopedRequest; error: string };

export function middlewareReadReducer(
  state: MiddlewareReadState,
  action: MiddlewareReadAction,
): MiddlewareReadState {
  switch (action.type) {
    case "scope-changed":
      if (action.scope === state.scope) return state;
      return {
        ...createMiddlewareReadState(),
        tab: state.tab,
        search: state.search,
        product: state.product,
        status: state.status,
        scope: action.scope,
      };
    case "tab-selected":
      if (action.tab === state.tab) return state;
      return {
        ...state,
        tab: action.tab,
        discoveryStatus: action.tab === "history" && state.discoveryStatus === "loading"
          ? "idle"
          : state.discoveryStatus,
        discoveryRequest: action.tab === "instances" ? state.discoveryRequest : null,
        configurationStatus: action.tab === "history" && state.configurationStatus === "loading"
          ? "idle"
          : state.configurationStatus,
        configurationRequest: action.tab === "instances" ? state.configurationRequest : null,
        historyStatus: action.tab === "instances" && state.historyStatus === "loading"
          ? "idle"
          : state.historyStatus,
        historyRequest: action.tab === "history" ? state.historyRequest : null,
      };
    case "search-changed":
      return { ...state, search: action.value };
    case "product-changed":
      return { ...state, product: action.value };
    case "status-changed":
      return { ...state, status: action.value };
    case "discovery-started":
      if (state.scope !== action.scope || state.tab !== "instances") return state;
      return {
        ...state,
        discoveryStatus: "loading",
        discoveryRequest: action.request,
        discovery: null,
        discoveryError: null,
        selectedInstanceHandle: null,
        configurationStatus: "idle",
        configurationRequest: null,
        configuration: null,
        configurationError: null,
      };
    case "discovery-loaded":
      if (!sameRequest(state.scope, state.discoveryRequest, action.scope, action.request) ||
        state.tab !== "instances") return state;
      return {
        ...state,
        discoveryStatus: "ready",
        discoveryRequest: null,
        discovery: action.discovery,
        discoveryError: null,
        selectedInstanceHandle: action.discovery.instances[0]?.instanceHandle ?? null,
      };
    case "discovery-failed":
      if (!sameRequest(state.scope, state.discoveryRequest, action.scope, action.request) ||
        state.tab !== "instances") return state;
      return {
        ...state,
        discoveryStatus: "error",
        discoveryRequest: null,
        discovery: null,
        discoveryError: action.error,
        selectedInstanceHandle: null,
      };
    case "instance-selected":
      if (state.discovery === null ||
        !state.discovery.instances.some((instance) => instance.instanceHandle === action.instanceHandle)) return state;
      if (state.selectedInstanceHandle === action.instanceHandle) return state;
      return {
        ...state,
        selectedInstanceHandle: action.instanceHandle,
        configurationStatus: "idle",
        configurationRequest: null,
        configuration: null,
        configurationError: null,
      };
    case "configuration-started":
      if (state.scope !== action.scope || state.tab !== "instances" ||
        state.discovery === null || state.selectedInstanceHandle === null) return state;
      return {
        ...state,
        configurationStatus: "loading",
        configurationRequest: action.request,
        configuration: null,
        configurationError: null,
      };
    case "configuration-loaded":
      if (!sameRequest(state.scope, state.configurationRequest, action.scope, action.request) ||
        state.tab !== "instances" || !configurationMatchesSelection(state, action.configuration)) return state;
      return {
        ...state,
        configurationStatus: "ready",
        configurationRequest: null,
        configuration: action.configuration,
        configurationError: null,
      };
    case "configuration-failed":
      if (!sameRequest(state.scope, state.configurationRequest, action.scope, action.request) ||
        state.tab !== "instances") return state;
      return {
        ...state,
        configurationStatus: "error",
        configurationRequest: null,
        configuration: null,
        configurationError: action.error,
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

function configurationMatchesSelection(
  state: MiddlewareReadState,
  configuration: MiddlewareConfiguration,
): boolean {
  if (state.discovery === null || state.selectedInstanceHandle === null ||
    configuration.discoveryHandle !== state.discovery.discoveryHandle ||
    configuration.instanceHandle !== state.selectedInstanceHandle) return false;
  const selected = state.discovery.instances.find((instance) =>
    instance.instanceHandle === state.selectedInstanceHandle);
  return selected?.product === configuration.product;
}
