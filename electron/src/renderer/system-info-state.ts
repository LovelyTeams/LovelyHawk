import type {
  SystemInfoDetail,
  SystemInfoSummary,
  SystemInfoTabCatalogEntry,
  SystemInfoTabKey,
  SystemInfoTable,
} from "../shared/system-info-contract";
import type { SshTargetSummary } from "../shared/ssh-contract";

export interface SystemInfoConnection {
  bindingHandle: string;
  target: SshTargetSummary;
}

export type LoadStatus = "idle" | "loading" | "ready" | "error";

export interface SystemInfoDetailState {
  snapshotHandle: string;
  rowId: string;
  status: "loading" | "ready" | "error";
  detail: SystemInfoDetail | null;
  error: string | null;
}

export interface SystemInfoState {
  scope: string | null;
  status: LoadStatus;
  catalog: SystemInfoTabCatalogEntry[];
  summary: SystemInfoSummary | null;
  selectedTab: SystemInfoTabKey | null;
  tableStatus: LoadStatus;
  table: SystemInfoTable | null;
  error: string | null;
  detail: SystemInfoDetailState | null;
}

export type SystemInfoAction =
  | { type: "scope-cleared" }
  | { type: "bootstrap-started"; scope: string }
  | {
      type: "bootstrap-loaded";
      scope: string;
      catalog: SystemInfoTabCatalogEntry[];
      summary: SystemInfoSummary;
    }
  | { type: "bootstrap-failed"; scope: string; error: string }
  | { type: "tab-selected"; scope: string; tab: SystemInfoTabKey }
  | { type: "table-started"; scope: string; tab: SystemInfoTabKey }
  | { type: "table-loaded"; scope: string; tab: SystemInfoTabKey; table: SystemInfoTable }
  | { type: "table-failed"; scope: string; tab: SystemInfoTabKey; error: string }
  | {
      type: "detail-started";
      scope: string;
      tab: SystemInfoTabKey;
      snapshotHandle: string;
      rowId: string;
    }
  | {
      type: "detail-loaded";
      scope: string;
      tab: SystemInfoTabKey;
      snapshotHandle: string;
      rowId: string;
      detail: SystemInfoDetail;
    }
  | {
      type: "detail-failed";
      scope: string;
      tab: SystemInfoTabKey;
      snapshotHandle: string;
      rowId: string;
      error: string;
    }
  | { type: "detail-closed" };

export function createSystemInfoState(): SystemInfoState {
  return {
    scope: null,
    status: "idle",
    catalog: [],
    summary: null,
    selectedTab: null,
    tableStatus: "idle",
    table: null,
    error: null,
    detail: null,
  };
}

export function systemInfoScope(connection: SystemInfoConnection): string {
  return JSON.stringify([
    connection.bindingHandle,
    connection.target.connectionId,
    connection.target.timestamp,
  ]);
}

export function systemInfoReducer(
  state: SystemInfoState,
  action: SystemInfoAction,
): SystemInfoState {
  switch (action.type) {
    case "scope-cleared":
      return createSystemInfoState();
    case "bootstrap-started":
      return { ...createSystemInfoState(), scope: action.scope, status: "loading" };
    case "bootstrap-loaded":
      if (state.scope !== action.scope) return state;
      return {
        ...state,
        status: "ready",
        catalog: action.catalog,
        summary: action.summary,
        selectedTab: action.catalog[0]?.key ?? null,
        tableStatus: "idle",
        table: null,
        error: null,
        detail: null,
      };
    case "bootstrap-failed":
      if (state.scope !== action.scope) return state;
      return { ...state, status: "error", error: action.error };
    case "tab-selected":
      if (state.scope !== action.scope || !state.catalog.some((entry) => entry.key === action.tab)) {
        return state;
      }
      return {
        ...state,
        selectedTab: action.tab,
        tableStatus: "idle",
        table: null,
        error: null,
        detail: null,
      };
    case "table-started":
      if (state.scope !== action.scope || state.selectedTab !== action.tab) return state;
      return { ...state, tableStatus: "loading", table: null, error: null, detail: null };
    case "table-loaded":
      if (
        state.scope !== action.scope ||
        state.selectedTab !== action.tab ||
        action.table.tab !== action.tab
      ) return state;
      return { ...state, tableStatus: "ready", table: action.table, error: null };
    case "table-failed":
      if (state.scope !== action.scope || state.selectedTab !== action.tab) return state;
      return { ...state, tableStatus: "error", table: null, error: action.error, detail: null };
    case "detail-started":
      if (!matchesCurrentTable(state, action.scope, action.tab, action.snapshotHandle)) return state;
      if (!state.table?.rows.some((row) => row.id === action.rowId)) return state;
      return {
        ...state,
        detail: {
          snapshotHandle: action.snapshotHandle,
          rowId: action.rowId,
          status: "loading",
          detail: null,
          error: null,
        },
      };
    case "detail-loaded":
      if (
        !matchesDetailRequest(state, action) ||
        action.detail.tab !== action.tab ||
        action.detail.rowId !== action.rowId
      ) return state;
      return {
        ...state,
        detail: {
          snapshotHandle: action.snapshotHandle,
          rowId: action.rowId,
          status: "ready",
          detail: action.detail,
          error: null,
        },
      };
    case "detail-failed":
      if (!matchesDetailRequest(state, action)) return state;
      return {
        ...state,
        detail: {
          snapshotHandle: action.snapshotHandle,
          rowId: action.rowId,
          status: "error",
          detail: null,
          error: action.error,
        },
      };
    case "detail-closed":
      return state.detail === null ? state : { ...state, detail: null };
  }
}

function matchesCurrentTable(
  state: SystemInfoState,
  scope: string,
  tab: SystemInfoTabKey,
  snapshotHandle: string,
): boolean {
  return (
    state.scope === scope &&
    state.selectedTab === tab &&
    state.table?.tab === tab &&
    state.table.snapshotHandle === snapshotHandle
  );
}

function matchesDetailRequest(
  state: SystemInfoState,
  action: {
    scope: string;
    tab: SystemInfoTabKey;
    snapshotHandle: string;
    rowId: string;
  },
): boolean {
  return (
    matchesCurrentTable(state, action.scope, action.tab, action.snapshotHandle) &&
    state.detail?.snapshotHandle === action.snapshotHandle &&
    state.detail.rowId === action.rowId
  );
}
