import type {
  KubernetesAvailability,
  KubernetesNamespaceScope,
  KubernetesReadTab,
  KubernetesSnapshot,
  KubernetesTextResult,
} from "../shared/kubernetes-read-contract";
import {
  boundKubernetesQuery,
  kubernetesListContext,
  kubernetesNamespaceCapability,
  kubernetesNamespaceKey,
} from "./kubernetes-read-helpers";

export type KubernetesLoadStatus = "idle" | "loading" | "ready" | "error";

export interface KubernetesReadState {
  scope: string | null;
  availabilityStatus: KubernetesLoadStatus;
  availabilityRequest: number;
  availability: KubernetesAvailability | null;
  namespacesStatus: KubernetesLoadStatus;
  namespacesRequest: number;
  namespaces: KubernetesSnapshot | null;
  /**
   * The cluster refused this account the namespace list, and the kubeconfig
   * names a namespace of its own: that one is offered instead.
   */
  namespacesRestricted: boolean;
  selectedNamespace: KubernetesNamespaceScope | null;
  activeTab: KubernetesReadTab;
  listStatus: KubernetesLoadStatus;
  listRequest: number;
  listContext: string;
  snapshot: KubernetesSnapshot | null;
  selectedRowHandle: string | null;
  detailStatus: KubernetesLoadStatus;
  detailRequest: number;
  detail: KubernetesTextResult | null;
  query: string;
  page: number;
  error: string | null;
  notice: string | null;
}

export type KubernetesReadAction =
  | { type: "scope-changed"; scope: string | null }
  | { type: "availability-started"; scope: string; request: number }
  | {
      type: "availability-loaded";
      scope: string;
      request: number;
      availability: KubernetesAvailability;
    }
  | { type: "availability-failed"; scope: string; request: number; error: string }
  | { type: "namespaces-started"; scope: string; request: number }
  | {
      type: "namespaces-loaded";
      scope: string;
      request: number;
      snapshot: KubernetesSnapshot;
    }
  | {
      type: "namespaces-failed";
      scope: string;
      request: number;
      error: string;
      /** The refusal was the cluster's permission check, not a failure. */
      forbidden: boolean;
    }
  | { type: "tab-selected"; scope: string; tab: KubernetesReadTab }
  | {
      type: "namespace-selected";
      scope: string;
      capability: KubernetesNamespaceScope | null;
    }
  | {
      type: "list-started";
      scope: string;
      request: number;
      tab: KubernetesReadTab;
      context: string;
    }
  | {
      type: "list-loaded";
      scope: string;
      request: number;
      tab: KubernetesReadTab;
      context: string;
      snapshot: KubernetesSnapshot;
    }
  | {
      type: "list-failed";
      scope: string;
      request: number;
      tab: KubernetesReadTab;
      context: string;
      error: string;
    }
  | { type: "row-cleared"; scope: string }
  | { type: "row-selected"; scope: string; snapshotHandle: string; rowHandle: string }
  | {
      type: "detail-started";
      scope: string;
      request: number;
      snapshotHandle: string;
      rowHandle: string;
    }
  | {
      type: "detail-loaded";
      scope: string;
      request: number;
      snapshotHandle: string;
      rowHandle: string;
      detail: KubernetesTextResult;
    }
  | {
      type: "detail-failed";
      scope: string;
      request: number;
      snapshotHandle: string;
      rowHandle: string;
      error: string;
    }
  | { type: "query-changed"; query: string }
  | { type: "page-selected"; page: number }
  | { type: "notice-cleared" };

export function createKubernetesReadState(
  scope: string | null = null,
): KubernetesReadState {
  return {
    scope,
    availabilityStatus: "idle",
    availabilityRequest: 0,
    availability: null,
    namespacesStatus: "idle",
    namespacesRequest: 0,
    namespaces: null,
    namespacesRestricted: false,
    selectedNamespace: null,
    activeTab: "pods",
    listStatus: "idle",
    listRequest: 0,
    listContext: "",
    snapshot: null,
    selectedRowHandle: null,
    detailStatus: "idle",
    detailRequest: 0,
    detail: null,
    query: "",
    page: 0,
    error: null,
    notice: null,
  };
}

export function kubernetesReadReducer(
  state: KubernetesReadState,
  action: KubernetesReadAction,
): KubernetesReadState {
  switch (action.type) {
    case "scope-changed":
      return action.scope === state.scope ? state : createKubernetesReadState(action.scope);
    case "availability-started":
      if (action.scope !== state.scope) return state;
      return {
        ...state,
        availabilityStatus: "loading",
        availabilityRequest: action.request,
        error: null,
      };
    case "availability-loaded":
      if (action.scope !== state.scope || action.request !== state.availabilityRequest) return state;
      return {
        ...state,
        availabilityStatus: "ready",
        availability: action.availability,
        namespacesStatus: action.availability.apiReachable ? state.namespacesStatus : "idle",
        namespaces: action.availability.apiReachable ? state.namespaces : null,
        selectedNamespace: action.availability.apiReachable ? state.selectedNamespace : null,
        listStatus: action.availability.apiReachable ? state.listStatus : "idle",
        snapshot: action.availability.apiReachable ? state.snapshot : null,
        selectedRowHandle: action.availability.apiReachable ? state.selectedRowHandle : null,
        detailStatus: action.availability.apiReachable ? state.detailStatus : "idle",
        detail: action.availability.apiReachable ? state.detail : null,
        notice: action.availability.apiReachable
          ? null
          : action.availability.kubectlInstalled
            ? "kubectl 已安装，但当前 context 的 API 不可达。"
            : "目标上未检测到 kubectl。",
        error: null,
      };
    case "availability-failed":
      if (action.scope !== state.scope || action.request !== state.availabilityRequest) return state;
      return {
        ...state,
        availabilityStatus: "error",
        availability: null,
        namespacesStatus: "idle",
        namespaces: null,
        selectedNamespace: null,
        listStatus: "idle",
        snapshot: null,
        selectedRowHandle: null,
        detailStatus: "idle",
        detail: null,
        error: action.error,
      };
    case "namespaces-started":
      if (action.scope !== state.scope) return state;
      return {
        ...state,
        namespacesStatus: "loading",
        namespacesRequest: action.request,
        error: null,
      };
    case "namespaces-loaded": {
      if (action.scope !== state.scope || action.request !== state.namespacesRequest ||
        action.snapshot.tab !== "namespaces") return state;
      // The full list is readable after all: the context stand-in goes.
      const selected = state.selectedNamespace;
      const selectedRow = selected === null || "context" in selected ? null : selected.rowHandle;
      const selectedNamespace = selectedRow === null
        ? null
        : kubernetesNamespaceCapability(action.snapshot, selectedRow);
      const scopeChanged = selected !== null && (
        selectedNamespace === null ||
        "context" in selected ||
        selectedNamespace.snapshotHandle !== selected.snapshotHandle
      );
      const invalidateScopedList = scopeChanged && isNamespaceTab(state.activeTab);
      const namespaceTabRefreshed = state.activeTab === "namespaces";
      const retainedNamespaceRow = namespaceTabRefreshed && state.selectedRowHandle !== null &&
        action.snapshot.rows.some((row) => row.rowHandle === state.selectedRowHandle)
        ? state.selectedRowHandle
        : null;
      const invalidateDetail = invalidateScopedList || namespaceTabRefreshed;
      return {
        ...state,
        namespacesStatus: "ready",
        namespaces: action.snapshot,
        namespacesRestricted: false,
        selectedNamespace,
        listStatus: invalidateScopedList ? "idle" : state.listStatus,
        snapshot: invalidateScopedList ? null : state.snapshot,
        selectedRowHandle: namespaceTabRefreshed
          ? retainedNamespaceRow
          : invalidateScopedList
            ? null
            : state.selectedRowHandle,
        detailStatus: invalidateDetail ? "idle" : state.detailStatus,
        detail: invalidateDetail ? null : state.detail,
        error: null,
      };
    }
    case "namespaces-failed": {
      if (action.scope !== state.scope || action.request !== state.namespacesRequest) return state;
      const contextNamespace = state.availability?.contextNamespace ?? null;
      if (action.forbidden && contextNamespace !== null) {
        // Not a failure to report but a limit to work within: the account
        // was given one namespace, and that is what is shown.
        const alreadyContext = state.selectedNamespace !== null && "context" in state.selectedNamespace;
        const relist = !alreadyContext && isNamespaceTab(state.activeTab);
        return {
          ...state,
          namespacesStatus: "error",
          namespaces: null,
          namespacesRestricted: true,
          selectedNamespace: { context: true },
          listStatus: relist ? "idle" : state.listStatus,
          snapshot: relist ? null : state.snapshot,
          selectedRowHandle: relist ? null : state.selectedRowHandle,
          detailStatus: relist ? "idle" : state.detailStatus,
          detail: relist ? null : state.detail,
          page: relist ? 0 : state.page,
          error: null,
          notice: `当前账号不能列出命名空间（集群拒绝，权限不足），改为查看 kubeconfig 当前上下文的命名空间「${contextNamespace}」。`,
        };
      }
      return {
        ...state,
        namespacesStatus: "error",
        namespaces: null,
        namespacesRestricted: false,
        selectedNamespace: null,
        listStatus: isNamespaceTab(state.activeTab) ? "idle" : state.listStatus,
        snapshot: isNamespaceTab(state.activeTab) ? null : state.snapshot,
        selectedRowHandle: isNamespaceTab(state.activeTab) ? null : state.selectedRowHandle,
        detailStatus: "idle",
        detail: null,
        error: action.error,
      };
    }
    case "tab-selected":
      if (action.scope !== state.scope || action.tab === state.activeTab) return state;
      return {
        ...state,
        activeTab: action.tab,
        listStatus: action.tab === "namespaces" && state.namespaces !== null ? "ready" : "idle",
        snapshot: null,
        selectedRowHandle: null,
        detailStatus: "idle",
        detail: null,
        query: "",
        page: 0,
        error: null,
      };
    case "namespace-selected":
      if (action.scope !== state.scope || !validNamespaceCapability(state, action.capability)) {
        return state;
      }
      if (kubernetesNamespaceKey(action.capability) ===
        kubernetesNamespaceKey(state.selectedNamespace)) return state;
      return {
        ...state,
        selectedNamespace: action.capability,
        listStatus: isNamespaceTab(state.activeTab) ? "idle" : state.listStatus,
        snapshot: isNamespaceTab(state.activeTab) ? null : state.snapshot,
        selectedRowHandle: null,
        detailStatus: "idle",
        detail: null,
        page: 0,
        error: null,
      };
    case "list-started":
      if (!matchesListContext(state, action)) return state;
      return {
        ...state,
        listStatus: "loading",
        listRequest: action.request,
        listContext: action.context,
        error: null,
      };
    case "list-loaded": {
      if (!matchesListResult(state, action) || action.snapshot.tab !== action.tab) return state;
      const retained = state.selectedRowHandle !== null &&
        action.snapshot.rows.some((row) => row.rowHandle === state.selectedRowHandle)
        ? state.selectedRowHandle
        : null;
      return {
        ...state,
        listStatus: "ready",
        snapshot: action.snapshot,
        selectedRowHandle: retained,
        detailStatus: "idle",
        detail: null,
        error: null,
      };
    }
    case "list-failed":
      if (!matchesListResult(state, action)) return state;
      return {
        ...state,
        listStatus: "error",
        snapshot: null,
        selectedRowHandle: null,
        detailStatus: "idle",
        detail: null,
        error: action.error,
      };
    case "row-cleared":
      if (action.scope !== state.scope) return state;
      // The in-flight read goes with it, so a late reply cannot repopulate a
      // dialog the operator has just closed.
      return {
        ...state,
        selectedRowHandle: null,
        detailStatus: "idle",
        detailRequest: 0,
        detail: null,
      };
    case "row-selected": {
      if (action.scope !== state.scope) return state;
      const snapshot = currentSnapshot(state);
      if (snapshot?.snapshotHandle !== action.snapshotHandle ||
        !snapshot.rows.some((row) => row.rowHandle === action.rowHandle)) return state;
      return {
        ...state,
        selectedRowHandle: action.rowHandle,
        detailStatus: "idle",
        detail: null,
        error: null,
      };
    }
    case "detail-started":
      if (!matchesSelectedRow(state, action)) return state;
      return {
        ...state,
        detailStatus: "loading",
        detailRequest: action.request,
        detail: null,
        error: null,
      };
    case "detail-loaded":
      if (!matchesDetailResult(state, action) ||
        action.detail.snapshotHandle !== action.snapshotHandle ||
        action.detail.rowHandle !== action.rowHandle) return state;
      return { ...state, detailStatus: "ready", detail: action.detail, error: null };
    case "detail-failed":
      if (!matchesDetailResult(state, action)) return state;
      return { ...state, detailStatus: "error", detail: null, error: action.error };
    case "query-changed":
      return { ...state, query: boundKubernetesQuery(action.query), page: 0 };
    case "page-selected":
      return { ...state, page: Math.max(0, Math.floor(action.page)) };
    case "notice-cleared":
      return state.notice === null ? state : { ...state, notice: null };
  }
}

export function currentSnapshot(state: KubernetesReadState): KubernetesSnapshot | null {
  return state.activeTab === "namespaces" ? state.namespaces : state.snapshot;
}

function isNamespaceTab(tab: KubernetesReadTab): boolean {
  return tab === "pods" || tab === "deployments";
}

function validNamespaceCapability(
  state: KubernetesReadState,
  capability: KubernetesNamespaceScope | null,
): boolean {
  if (capability === null) return true;
  // Only offered while the kubeconfig names a namespace of its own.
  if ("context" in capability) return (state.availability?.contextNamespace ?? null) !== null;
  return state.namespaces?.snapshotHandle === capability.snapshotHandle &&
    state.namespaces.rows.some((row) =>
      row.kind === "namespace" && row.rowHandle === capability.rowHandle);
}

function expectedListContext(state: KubernetesReadState): string {
  return kubernetesListContext(state.activeTab, state.selectedNamespace);
}

function matchesListContext(
  state: KubernetesReadState,
  action: { scope: string; tab: KubernetesReadTab; context: string },
): boolean {
  return state.scope === action.scope && state.activeTab === action.tab &&
    action.tab !== "namespaces" && action.context === expectedListContext(state);
}

function matchesListResult(
  state: KubernetesReadState,
  action: { scope: string; request: number; tab: KubernetesReadTab; context: string },
): boolean {
  return matchesListContext(state, action) && state.listRequest === action.request &&
    state.listContext === action.context;
}

function matchesSelectedRow(
  state: KubernetesReadState,
  action: { scope: string; snapshotHandle: string; rowHandle: string },
): boolean {
  const snapshot = currentSnapshot(state);
  return state.scope === action.scope && snapshot?.snapshotHandle === action.snapshotHandle &&
    state.selectedRowHandle === action.rowHandle &&
    snapshot.rows.some((row) => row.rowHandle === action.rowHandle);
}

function matchesDetailResult(
  state: KubernetesReadState,
  action: {
    scope: string;
    request: number;
    snapshotHandle: string;
    rowHandle: string;
  },
): boolean {
  return matchesSelectedRow(state, action) && state.detailRequest === action.request;
}
