import type {
  CheckAuditCatalog,
  CheckAuditLogInput,
  CheckAuditLogResult,
  CheckAuditStatus,
} from "../shared/check-audit-read-contract";

export type CheckAuditStatusKind = "idle" | "loading" | "ready" | "error";
export type CheckAuditTab = "commands" | "logs" | "analysis" | "suggestions";

interface SnapshotRequest {
  id: number;
  snapshotHandle: string;
}

interface LogRequest extends SnapshotRequest {
  input: CheckAuditLogInput;
}

export interface CheckAuditReadState {
  scope: string | null;
  tab: CheckAuditTab;
  commandSearch: string;
  catalogStatus: CheckAuditStatusKind;
  catalogRequest: number | null;
  catalog: CheckAuditCatalog | null;
  catalogError: string | null;
  selectedCommandName: string | null;
  statusStatus: CheckAuditStatusKind;
  statusRequest: SnapshotRequest | null;
  status: CheckAuditStatus | null;
  statusError: string | null;
  logInput: CheckAuditLogInput;
  logStatus: CheckAuditStatusKind;
  logRequest: LogRequest | null;
  log: CheckAuditLogResult | null;
  logError: string | null;
}

export function createCheckAuditReadState(): CheckAuditReadState {
  return {
    scope: null,
    tab: "commands",
    commandSearch: "",
    catalogStatus: "idle",
    catalogRequest: null,
    catalog: null,
    catalogError: null,
    selectedCommandName: null,
    statusStatus: "idle",
    statusRequest: null,
    status: null,
    statusError: null,
    logInput: { limit: 200, search: null },
    logStatus: "idle",
    logRequest: null,
    log: null,
    logError: null,
  };
}

export type CheckAuditReadAction =
  | { type: "scope-changed"; scope: string | null }
  | { type: "tab-selected"; tab: CheckAuditTab }
  | { type: "command-search-changed"; value: string }
  | { type: "catalog-started"; scope: string; request: number }
  | { type: "catalog-loaded"; scope: string; request: number; catalog: CheckAuditCatalog }
  | { type: "catalog-failed"; scope: string; request: number; error: string }
  | { type: "command-selected"; name: string }
  | { type: "status-started"; scope: string; request: SnapshotRequest }
  | { type: "status-loaded"; scope: string; request: SnapshotRequest; status: CheckAuditStatus }
  | { type: "status-failed"; scope: string; request: SnapshotRequest; error: string }
  | { type: "log-input-applied"; input: CheckAuditLogInput }
  | { type: "log-started"; scope: string; request: LogRequest }
  | { type: "log-loaded"; scope: string; request: LogRequest; result: CheckAuditLogResult }
  | { type: "log-failed"; scope: string; request: LogRequest; error: string };

export function checkAuditReadReducer(
  state: CheckAuditReadState,
  action: CheckAuditReadAction,
): CheckAuditReadState {
  switch (action.type) {
    case "scope-changed":
      return action.scope === state.scope ? state : { ...createCheckAuditReadState(), scope: action.scope };
    case "tab-selected": {
      if (action.tab === state.tab) return state;
      const enteringCommands = action.tab === "commands";
      return {
        ...state,
        tab: action.tab,
        statusStatus: !enteringCommands && state.statusStatus === "loading" ? "idle" : state.statusStatus,
        statusRequest: enteringCommands ? state.statusRequest : null,
        logStatus: enteringCommands && state.logStatus === "loading" ? "idle" : state.logStatus,
        logRequest: enteringCommands ? null : state.logRequest,
      };
    }
    case "command-search-changed":
      return { ...state, commandSearch: action.value };
    case "catalog-started":
      if (state.scope !== action.scope) return state;
      return {
        ...state,
        catalogStatus: "loading",
        catalogRequest: action.request,
        catalog: null,
        catalogError: null,
        statusStatus: "idle",
        statusRequest: null,
        status: null,
        statusError: null,
        logStatus: "idle",
        logRequest: null,
        log: null,
        logError: null,
      };
    case "catalog-loaded": {
      if (state.scope !== action.scope || state.catalogRequest !== action.request) return state;
      const selected = action.catalog.commands.some((command) => command.name === state.selectedCommandName)
        ? state.selectedCommandName
        : action.catalog.commands[0]?.name ?? null;
      return {
        ...state,
        catalogStatus: "ready",
        catalogRequest: null,
        catalog: action.catalog,
        catalogError: null,
        selectedCommandName: selected,
      };
    }
    case "catalog-failed":
      if (state.scope !== action.scope || state.catalogRequest !== action.request) return state;
      return { ...state, catalogStatus: "error", catalogRequest: null, catalogError: action.error };
    case "command-selected":
      if (!state.catalog?.commands.some((command) => command.name === action.name)) return state;
      return { ...state, selectedCommandName: action.name };
    case "status-started":
      if (!sameSnapshot(state, action.scope, action.request.snapshotHandle) || state.tab !== "commands") return state;
      return { ...state, statusStatus: "loading", statusRequest: action.request, status: null, statusError: null };
    case "status-loaded":
      if (!sameStatusRequest(state, action.scope, action.request) ||
        action.status.snapshotHandle !== action.request.snapshotHandle ||
        !statusMatchesCatalog(action.status, state.catalog)) return state;
      return { ...state, statusStatus: "ready", statusRequest: null, status: action.status, statusError: null };
    case "status-failed":
      if (!sameStatusRequest(state, action.scope, action.request)) return state;
      return { ...state, statusStatus: "error", statusRequest: null, status: null, statusError: action.error };
    case "log-input-applied":
      return {
        ...state,
        logInput: { ...action.input },
        logStatus: "idle",
        logRequest: null,
        log: null,
        logError: null,
      };
    case "log-started":
      if (!sameSnapshot(state, action.scope, action.request.snapshotHandle) || state.tab === "commands" ||
        !sameLogInput(state.logInput, action.request.input)) return state;
      return { ...state, logStatus: "loading", logRequest: action.request, log: null, logError: null };
    case "log-loaded":
      if (!sameLogRequest(state, action.scope, action.request) ||
        action.result.snapshotHandle !== action.request.snapshotHandle ||
        action.result.limit !== action.request.input.limit) return state;
      return { ...state, logStatus: "ready", logRequest: null, log: action.result, logError: null };
    case "log-failed":
      if (!sameLogRequest(state, action.scope, action.request)) return state;
      return { ...state, logStatus: "error", logRequest: null, log: null, logError: action.error };
  }
}

function sameSnapshot(state: CheckAuditReadState, scope: string, snapshotHandle: string): boolean {
  return state.scope === scope && state.catalog?.snapshotHandle === snapshotHandle;
}

function sameStatusRequest(
  state: CheckAuditReadState,
  scope: string,
  request: SnapshotRequest,
): boolean {
  return sameSnapshot(state, scope, request.snapshotHandle) && state.statusRequest?.id === request.id &&
    state.statusRequest.snapshotHandle === request.snapshotHandle && state.tab === "commands";
}

function sameLogRequest(state: CheckAuditReadState, scope: string, request: LogRequest): boolean {
  return sameSnapshot(state, scope, request.snapshotHandle) && state.tab !== "commands" &&
    state.logRequest?.id === request.id && state.logRequest.snapshotHandle === request.snapshotHandle &&
    sameLogInput(state.logRequest.input, request.input) && sameLogInput(state.logInput, request.input);
}

function sameLogInput(left: CheckAuditLogInput, right: CheckAuditLogInput): boolean {
  return left.limit === right.limit && left.search === right.search;
}

function statusMatchesCatalog(status: CheckAuditStatus, catalog: CheckAuditCatalog | null): boolean {
  if (catalog === null || status.commands.length !== catalog.commands.length) return false;
  const byHandle = new Map(status.commands.map((command) => [command.commandHandle, command]));
  return catalog.commands.every((command) => {
    const current = byHandle.get(command.commandHandle);
    return current?.name === command.name && current.critical === command.critical;
  });
}
