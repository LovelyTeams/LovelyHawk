import type {
  FirewallHistory,
  FirewallInspection,
} from "../shared/firewall-read-contract";
import { boundFirewallText } from "./firewall-read-helpers";

export type FirewallTab = "rules" | "history";
export type FirewallLoadStatus = "idle" | "loading" | "ready" | "error";

export interface FirewallReadState {
  scope: string | null;
  activeTab: FirewallTab;
  inspectionStatus: FirewallLoadStatus;
  inspectionRequest: number;
  inspection: FirewallInspection | null;
  inspectionError: string | null;
  historyStatus: FirewallLoadStatus;
  historyRequest: number;
  history: FirewallHistory | null;
  historyError: string | null;
  selectedChangeHandle: string | null;
  ruleQuery: string;
  copyRequest: number;
  copySnapshotHandle: string | null;
  notice: string | null;
}

export type FirewallReadAction =
  | { type: "scope-changed"; scope: string | null }
  | { type: "deactivated"; scope: string | null }
  | { type: "tab-selected"; scope: string; tab: FirewallTab }
  | { type: "inspection-started"; scope: string; request: number }
  | {
      type: "inspection-loaded";
      scope: string;
      request: number;
      inspection: FirewallInspection;
    }
  | { type: "inspection-failed"; scope: string; request: number; error: string }
  | { type: "history-started"; scope: string; request: number }
  | { type: "history-loaded"; scope: string; request: number; history: FirewallHistory }
  | { type: "history-failed"; scope: string; request: number; error: string }
  | { type: "history-selected"; scope: string; changeHandle: string }
  | { type: "rule-query-changed"; query: string }
  | { type: "copy-started"; scope: string; request: number; snapshotHandle: string }
  | {
      type: "copy-finished";
      scope: string;
      request: number;
      snapshotHandle: string;
      truncated: boolean;
    }
  | {
      type: "copy-failed";
      scope: string;
      request: number;
      snapshotHandle: string;
      error: string;
    }
  | { type: "notice-cleared" };

export function createFirewallReadState(scope: string | null = null): FirewallReadState {
  return {
    scope,
    activeTab: "rules",
    inspectionStatus: "idle",
    inspectionRequest: 0,
    inspection: null,
    inspectionError: null,
    historyStatus: "idle",
    historyRequest: 0,
    history: null,
    historyError: null,
    selectedChangeHandle: null,
    ruleQuery: "",
    copyRequest: 0,
    copySnapshotHandle: null,
    notice: null,
  };
}

export function firewallReadReducer(
  state: FirewallReadState,
  action: FirewallReadAction,
): FirewallReadState {
  switch (action.type) {
    case "scope-changed":
      return action.scope === state.scope ? state : createFirewallReadState(action.scope);
    case "deactivated":
      return action.scope === state.scope ? createFirewallReadState(action.scope) : state;
    case "tab-selected":
      return action.scope === state.scope && action.tab !== state.activeTab
        ? { ...state, activeTab: action.tab, notice: null }
        : state;
    case "inspection-started":
      if (action.scope !== state.scope) return state;
      return {
        ...state,
        inspectionStatus: "loading",
        inspectionRequest: action.request,
        inspectionError: null,
        notice: null,
      };
    case "inspection-loaded":
      if (action.scope !== state.scope || action.request !== state.inspectionRequest ||
        state.inspectionStatus !== "loading") return state;
      return {
        ...state,
        inspectionStatus: "ready",
        inspection: action.inspection,
        inspectionError: null,
        copySnapshotHandle: null,
      };
    case "inspection-failed":
      if (action.scope !== state.scope || action.request !== state.inspectionRequest) return state;
      return {
        ...state,
        inspectionStatus: "error",
        inspection: null,
        inspectionError: action.error,
        copySnapshotHandle: null,
      };
    case "history-started":
      if (action.scope !== state.scope) return state;
      return {
        ...state,
        historyStatus: "loading",
        historyRequest: action.request,
        historyError: null,
      };
    case "history-loaded": {
      if (action.scope !== state.scope || action.request !== state.historyRequest ||
        state.historyStatus !== "loading") return state;
      const selectedChangeHandle = state.selectedChangeHandle !== null &&
        action.history.entries.some((entry) => entry.changeHandle === state.selectedChangeHandle)
        ? state.selectedChangeHandle
        : action.history.entries[0]?.changeHandle ?? null;
      return {
        ...state,
        historyStatus: "ready",
        history: action.history,
        historyError: null,
        selectedChangeHandle,
      };
    }
    case "history-failed":
      if (action.scope !== state.scope || action.request !== state.historyRequest) return state;
      return {
        ...state,
        historyStatus: "error",
        history: null,
        historyError: action.error,
        selectedChangeHandle: null,
      };
    case "history-selected":
      if (action.scope !== state.scope ||
        !state.history?.entries.some((entry) => entry.changeHandle === action.changeHandle)) {
        return state;
      }
      return { ...state, selectedChangeHandle: action.changeHandle };
    case "rule-query-changed":
      return { ...state, ruleQuery: boundFirewallText(action.query, 256) };
    case "copy-started":
      if (action.scope !== state.scope || action.snapshotHandle !== state.inspection?.snapshotHandle) {
        return state;
      }
      return {
        ...state,
        copyRequest: action.request,
        copySnapshotHandle: action.snapshotHandle,
        notice: "正在写入系统剪贴板…",
      };
    case "copy-finished":
      if (!matchesCopy(state, action)) return state;
      return {
        ...state,
        copySnapshotHandle: null,
        notice: action.truncated
          ? "规则纯文本已按系统剪贴板 128 KiB 限制安全截断并复制。"
          : "有界规则纯文本已复制。",
      };
    case "copy-failed":
      if (!matchesCopy(state, action)) return state;
      return { ...state, copySnapshotHandle: null, notice: action.error };
    case "notice-cleared":
      return state.notice === null ? state : { ...state, notice: null };
  }
}

function matchesCopy(
  state: FirewallReadState,
  action: { scope: string; request: number; snapshotHandle: string },
): boolean {
  return action.scope === state.scope && action.request === state.copyRequest &&
    action.snapshotHandle === state.copySnapshotHandle &&
    action.snapshotHandle === state.inspection?.snapshotHandle;
}
