import type {
  IntegrityBaselineList,
  IntegrityComparison,
  IntegrityComparisonPoll,
  IntegrityComparisonStarted,
  IntegrityPresetCatalog,
} from "../shared/integrity-contract";
import type { IntegrityViewStage } from "./integrity-helpers";

export type IntegrityLoadStatus = "idle" | "loading" | "ready" | "error";

export interface IntegrityState {
  scope: string | null;
  catalogStatus: IntegrityLoadStatus;
  catalog: IntegrityPresetCatalog | null;
  listStatus: IntegrityLoadStatus;
  listRequest: number;
  baselineList: IntegrityBaselineList | null;
  selectedBaselineHandle: string | null;
  startRequest: number;
  operationHandle: string | null;
  operationBaselineHandle: string | null;
  operationStage: IntegrityViewStage;
  pollRequest: number;
  pollAfterEvent: number;
  eventCursor: number;
  eventsTruncated: boolean;
  comparison: IntegrityComparison | null;
  error: string | null;
}

export type IntegrityAction =
  | { type: "scope-changed"; scope: string | null }
  | { type: "catalog-started"; scope: string }
  | { type: "catalog-loaded"; scope: string; catalog: IntegrityPresetCatalog }
  | { type: "catalog-failed"; scope: string; error: string }
  | { type: "list-started"; scope: string; request: number }
  | { type: "list-loaded"; scope: string; request: number; list: IntegrityBaselineList }
  | { type: "list-failed"; scope: string; request: number; error: string }
  | { type: "baseline-selected"; scope: string; handle: string }
  | {
      type: "comparison-start-requested";
      scope: string;
      request: number;
      baselineHandle: string;
    }
  | {
      type: "comparison-started";
      scope: string;
      request: number;
      baselineHandle: string;
      started: IntegrityComparisonStarted;
    }
  | {
      type: "comparison-start-failed";
      scope: string;
      request: number;
      baselineHandle: string;
      error: string;
    }
  | {
      type: "poll-started";
      scope: string;
      operationHandle: string;
      request: number;
      afterEvent: number;
    }
  | {
      type: "poll-loaded";
      scope: string;
      operationHandle: string;
      request: number;
      afterEvent: number;
      poll: IntegrityComparisonPoll;
    }
  | {
      type: "poll-failed";
      scope: string;
      operationHandle: string;
      request: number;
      afterEvent: number;
      error: string;
    }
  | { type: "cancel-started"; scope: string; operationHandle: string }
  | { type: "cancelled"; scope: string; operationHandle: string }
  | { type: "cancel-failed"; scope: string; operationHandle: string; error: string };

export function createIntegrityState(scope: string | null = null): IntegrityState {
  return {
    scope,
    catalogStatus: "idle",
    catalog: null,
    listStatus: "idle",
    listRequest: 0,
    baselineList: null,
    selectedBaselineHandle: null,
    startRequest: 0,
    operationHandle: null,
    operationBaselineHandle: null,
    operationStage: "idle",
    pollRequest: 0,
    pollAfterEvent: 0,
    eventCursor: 0,
    eventsTruncated: false,
    comparison: null,
    error: null,
  };
}

export function integrityReducer(
  state: IntegrityState,
  action: IntegrityAction,
): IntegrityState {
  switch (action.type) {
    case "scope-changed":
      return action.scope === state.scope ? state : createIntegrityState(action.scope);
    case "catalog-started":
      if (action.scope !== state.scope) return state;
      return { ...state, catalogStatus: "loading", error: null };
    case "catalog-loaded":
      if (action.scope !== state.scope) return state;
      return { ...state, catalogStatus: "ready", catalog: action.catalog, error: null };
    case "catalog-failed":
      if (action.scope !== state.scope) return state;
      return { ...state, catalogStatus: "error", catalog: null, error: action.error };
    case "list-started":
      if (action.scope !== state.scope) return state;
      return { ...state, listStatus: "loading", listRequest: action.request, error: null };
    case "list-loaded": {
      if (action.scope !== state.scope || action.request !== state.listRequest) return state;
      const retained = state.selectedBaselineHandle !== null &&
        action.list.items.some((item) => item.baselineHandle === state.selectedBaselineHandle)
        ? state.selectedBaselineHandle
        : null;
      const selected = retained ?? action.list.items[0]?.baselineHandle ?? null;
      return {
        ...state,
        listStatus: "ready",
        baselineList: action.list,
        selectedBaselineHandle: selected,
        error: null,
      };
    }
    case "list-failed":
      if (action.scope !== state.scope || action.request !== state.listRequest) return state;
      return { ...state, listStatus: "error", baselineList: null, error: action.error };
    case "baseline-selected":
      if (action.scope !== state.scope || integrityOperationActive(state) ||
        !state.baselineList?.items.some((item) => item.baselineHandle === action.handle)) {
        return state;
      }
      if (state.selectedBaselineHandle === action.handle) return state;
      return {
        ...state,
        selectedBaselineHandle: action.handle,
        operationHandle: null,
        operationBaselineHandle: null,
        operationStage: "idle",
        eventCursor: 0,
        eventsTruncated: false,
        comparison: null,
        error: null,
      };
    case "comparison-start-requested":
      if (action.scope !== state.scope || integrityOperationActive(state) ||
        state.selectedBaselineHandle !== action.baselineHandle) return state;
      return {
        ...state,
        startRequest: action.request,
        operationHandle: null,
        operationBaselineHandle: action.baselineHandle,
        operationStage: "starting",
        eventCursor: 0,
        eventsTruncated: false,
        comparison: null,
        error: null,
      };
    case "comparison-started":
      if (!matchesStart(state, action) || action.started.stage !== "running" ||
        action.started.baselineHandle !== action.baselineHandle) return state;
      return {
        ...state,
        operationHandle: action.started.operationHandle,
        operationStage: "running",
        error: null,
      };
    case "comparison-start-failed":
      if (!matchesStart(state, action)) return state;
      return {
        ...state,
        operationHandle: null,
        operationBaselineHandle: null,
        operationStage: "failed",
        error: action.error,
      };
    case "poll-started":
      if (!matchesRunningOperation(state, action.scope, action.operationHandle) ||
        action.afterEvent !== state.eventCursor) return state;
      return {
        ...state,
        pollRequest: action.request,
        pollAfterEvent: action.afterEvent,
      };
    case "poll-loaded": {
      if (!matchesPoll(state, action) || action.poll.operationHandle !== action.operationHandle ||
        action.poll.baselineHandle !== state.operationBaselineHandle ||
        action.poll.nextEventCursor < state.eventCursor ||
        action.poll.events.some((event) => event.sequence <= action.afterEvent)) return state;
      return {
        ...state,
        operationStage: action.poll.stage,
        eventCursor: action.poll.nextEventCursor,
        eventsTruncated: state.eventsTruncated || action.poll.eventsTruncated,
        comparison: action.poll.stage === "completed" ? action.poll.comparison : null,
        error: action.poll.stage === "failed" ? "完整性比较未能完成。" : null,
      };
    }
    case "poll-failed":
      if (!matchesPoll(state, action)) return state;
      return { ...state, operationStage: "failed", comparison: null, error: action.error };
    case "cancel-started":
      if (!matchesRunningOperation(state, action.scope, action.operationHandle)) return state;
      return { ...state, operationStage: "cancelling", error: null };
    case "cancelled":
      if (action.scope !== state.scope || action.operationHandle !== state.operationHandle ||
        state.operationStage !== "cancelling") return state;
      return { ...state, operationStage: "cancelled", comparison: null, error: null };
    case "cancel-failed":
      if (action.scope !== state.scope || action.operationHandle !== state.operationHandle ||
        state.operationStage !== "cancelling") return state;
      return { ...state, operationStage: "running", error: action.error };
  }
}

function integrityOperationActive(state: IntegrityState): boolean {
  return state.operationStage === "starting" || state.operationStage === "running" ||
    state.operationStage === "cancelling";
}

function matchesStart(
  state: IntegrityState,
  action: { scope: string; request: number; baselineHandle: string },
): boolean {
  return action.scope === state.scope && action.request === state.startRequest &&
    action.baselineHandle === state.selectedBaselineHandle &&
    action.baselineHandle === state.operationBaselineHandle && state.operationStage === "starting";
}

function matchesRunningOperation(
  state: IntegrityState,
  scope: string,
  operationHandle: string,
): boolean {
  return scope === state.scope && operationHandle === state.operationHandle &&
    state.operationStage === "running";
}

function matchesPoll(
  state: IntegrityState,
  action: {
    scope: string;
    operationHandle: string;
    request: number;
    afterEvent: number;
  },
): boolean {
  return matchesRunningOperation(state, action.scope, action.operationHandle) &&
    action.request === state.pollRequest && action.afterEvent === state.pollAfterEvent &&
    action.afterEvent === state.eventCursor;
}
