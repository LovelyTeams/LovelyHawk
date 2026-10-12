import type {
  EmergencyCommandCatalog,
  EmergencyCommandCategory,
  EmergencyCommandResult,
} from "../shared/emergency-command-contract";
import { filterEmergencyCommands } from "./emergency-command-helpers";

export type EmergencyCommandLoadStatus = "idle" | "loading" | "ready" | "error";

interface EmergencyCommandRunRequest {
  id: number;
  snapshotHandle: string;
  commandHandle: string;
}

/** One finished step of a group run; either a result or a fixed public error. */
export interface EmergencyCommandGroupEntry {
  commandHandle: string;
  result: EmergencyCommandResult | null;
  error: string | null;
  elapsedMs: number;
}

export interface EmergencyCommandGroupRun {
  id: number;
  snapshotHandle: string;
  category: EmergencyCommandCategory;
  commandHandles: readonly string[];
  entries: readonly EmergencyCommandGroupEntry[];
  status: "loading" | "ready";
}

export interface EmergencyCommandState {
  scope: string | null;
  collapsedCategories: readonly EmergencyCommandCategory[];
  search: string;
  catalogStatus: EmergencyCommandLoadStatus;
  catalogRequest: number | null;
  catalog: EmergencyCommandCatalog | null;
  catalogError: string | null;
  selectedCommandHandle: string | null;
  runStatus: EmergencyCommandLoadStatus;
  runRequest: EmergencyCommandRunRequest | null;
  result: EmergencyCommandResult | null;
  runError: string | null;
  groupRun: EmergencyCommandGroupRun | null;
}

export function createEmergencyCommandState(): EmergencyCommandState {
  return {
    scope: null,
    collapsedCategories: [],
    search: "",
    catalogStatus: "idle",
    catalogRequest: null,
    catalog: null,
    catalogError: null,
    selectedCommandHandle: null,
    runStatus: "idle",
    runRequest: null,
    result: null,
    runError: null,
    groupRun: null,
  };
}

export type EmergencyCommandAction =
  | { type: "scope-changed"; scope: string | null }
  | { type: "category-toggled"; category: EmergencyCommandCategory }
  | { type: "search-changed"; search: string }
  | { type: "catalog-started"; scope: string; request: number }
  | { type: "catalog-loaded"; scope: string; request: number; catalog: EmergencyCommandCatalog }
  | { type: "catalog-failed"; scope: string; request: number; error: string }
  | { type: "command-selected"; commandHandle: string }
  /** Puts one check in view and selected, e.g. one reopened from command history. */
  | { type: "command-revealed"; scope: string; snapshotHandle: string; commandHandle: string }
  | { type: "run-started"; scope: string; request: EmergencyCommandRunRequest }
  | { type: "run-loaded"; scope: string; request: EmergencyCommandRunRequest; result: EmergencyCommandResult }
  | { type: "run-failed"; scope: string; request: EmergencyCommandRunRequest; error: string }
  | {
    type: "group-run-started";
    scope: string;
    run: { id: number; snapshotHandle: string; category: EmergencyCommandCategory; commandHandles: readonly string[] };
  }
  | { type: "group-run-progress"; scope: string; runId: number; entry: EmergencyCommandGroupEntry }
  | { type: "group-run-finished"; scope: string; runId: number };

export function emergencyCommandReducer(
  state: EmergencyCommandState,
  action: EmergencyCommandAction,
): EmergencyCommandState {
  switch (action.type) {
    case "scope-changed":
      return action.scope === state.scope ? state : { ...createEmergencyCommandState(), scope: action.scope };
    case "category-toggled": {
      // Collapsing is presentation only: it never drops a selection or a result.
      const collapsed = state.collapsedCategories.includes(action.category)
        ? state.collapsedCategories.filter((category) => category !== action.category)
        : [...state.collapsedCategories, action.category];
      return { ...state, collapsedCategories: collapsed };
    }
    case "search-changed":
      return withVisibleSelection({ ...state, search: action.search });
    case "catalog-started":
      if (state.scope !== action.scope) return state;
      return {
        ...state,
        catalogStatus: "loading",
        catalogRequest: action.request,
        catalog: null,
        catalogError: null,
        runStatus: "idle",
        runRequest: null,
        result: null,
        runError: null,
        groupRun: null,
      };
    case "catalog-loaded": {
      if (state.scope !== action.scope || state.catalogRequest !== action.request) return state;
      const visible = filterEmergencyCommands(action.catalog.commands, state.search);
      const selectedCommandHandle = visible.some((command) => command.commandHandle === state.selectedCommandHandle)
        ? state.selectedCommandHandle : visible[0]?.commandHandle ?? null;
      return {
        ...state,
        catalogStatus: "ready",
        catalogRequest: null,
        catalog: action.catalog,
        catalogError: null,
        selectedCommandHandle,
      };
    }
    case "catalog-failed":
      if (state.scope !== action.scope || state.catalogRequest !== action.request) return state;
      return {
        ...state,
        catalogStatus: "error",
        catalogRequest: null,
        catalog: null,
        catalogError: action.error,
        selectedCommandHandle: null,
      };
    case "command-selected":
      if (!state.catalog?.commands.some((command) => command.commandHandle === action.commandHandle)) return state;
      return {
        ...state,
        selectedCommandHandle: action.commandHandle,
        runStatus: "idle",
        runRequest: null,
        result: null,
        runError: null,
        groupRun: null,
      };
    case "command-revealed": {
      // Never in the middle of a run: the operator would lose what is running.
      if (state.scope !== action.scope || state.catalog?.snapshotHandle !== action.snapshotHandle ||
        state.runStatus === "loading" || state.groupRun?.status === "loading") return state;
      const command = state.catalog.commands.find((entry) => entry.commandHandle === action.commandHandle);
      if (command === undefined) return state;
      return {
        ...state,
        // A search or a collapsed group that would hide it is set aside.
        search: "",
        collapsedCategories: state.collapsedCategories.filter((category) => category !== command.category),
        selectedCommandHandle: command.commandHandle,
        runStatus: "idle",
        runRequest: null,
        result: null,
        runError: null,
        groupRun: null,
      };
    }
    case "run-started":
      if (state.scope !== action.scope || state.catalogStatus !== "ready" || state.groupRun?.status === "loading" ||
        state.catalog?.snapshotHandle !== action.request.snapshotHandle ||
        state.selectedCommandHandle !== action.request.commandHandle ||
        !state.catalog.commands.some((command) => command.commandHandle === action.request.commandHandle)) return state;
      return {
        ...state,
        runStatus: "loading",
        runRequest: action.request,
        result: null,
        runError: null,
        groupRun: null,
      };
    case "run-loaded":
      if (!sameRun(state, action.scope, action.request) ||
        action.result.snapshotHandle !== action.request.snapshotHandle ||
        action.result.commandHandle !== action.request.commandHandle) return state;
      return { ...state, runStatus: "ready", runRequest: null, result: action.result, runError: null };
    case "run-failed":
      if (!sameRun(state, action.scope, action.request)) return state;
      return { ...state, runStatus: "error", runRequest: null, result: null, runError: action.error };
    case "group-run-started": {
      const catalog = state.catalog;
      if (state.scope !== action.scope || state.catalogStatus !== "ready" || catalog === null ||
        catalog.snapshotHandle !== action.run.snapshotHandle || action.run.commandHandles.length === 0 ||
        state.runStatus === "loading" || state.groupRun?.status === "loading" ||
        !action.run.commandHandles.every((handle) => catalog.commands.some((command) =>
          command.commandHandle === handle && command.category === action.run.category))) return state;
      return {
        ...state,
        runStatus: "idle",
        runRequest: null,
        result: null,
        runError: null,
        groupRun: { ...action.run, entries: [], status: "loading" },
      };
    }
    case "group-run-progress": {
      const run = state.groupRun;
      if (run === null || !sameGroupRun(state, run, action.scope, action.runId) ||
        run.entries.length >= run.commandHandles.length ||
        run.commandHandles[run.entries.length] !== action.entry.commandHandle) return state;
      return { ...state, groupRun: { ...run, entries: [...run.entries, action.entry] } };
    }
    case "group-run-finished": {
      const run = state.groupRun;
      if (run === null || !sameGroupRun(state, run, action.scope, action.runId)) return state;
      return { ...state, groupRun: { ...run, status: "ready" } };
    }
  }
}

function withVisibleSelection(state: EmergencyCommandState): EmergencyCommandState {
  const visible = filterEmergencyCommands(state.catalog?.commands ?? [], state.search);
  const selectedCommandHandle = visible.some((command) => command.commandHandle === state.selectedCommandHandle)
    ? state.selectedCommandHandle : visible[0]?.commandHandle ?? null;
  if (selectedCommandHandle === state.selectedCommandHandle) return state;
  return {
    ...state,
    selectedCommandHandle,
    runStatus: "idle",
    runRequest: null,
    result: null,
    runError: null,
  };
}

function sameRun(
  state: EmergencyCommandState,
  scope: string,
  request: EmergencyCommandRunRequest,
): boolean {
  return state.scope === scope && state.runRequest?.id === request.id &&
    state.runRequest.snapshotHandle === request.snapshotHandle &&
    state.runRequest.commandHandle === request.commandHandle &&
    state.catalog?.snapshotHandle === request.snapshotHandle &&
    state.selectedCommandHandle === request.commandHandle;
}

function sameGroupRun(
  state: EmergencyCommandState,
  run: EmergencyCommandGroupRun,
  scope: string,
  runId: number,
): boolean {
  return state.scope === scope && run.id === runId && run.status === "loading" &&
    state.catalog?.snapshotHandle === run.snapshotHandle;
}
