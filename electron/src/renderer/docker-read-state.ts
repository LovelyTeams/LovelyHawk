import type {
  DockerCollectionKind,
  DockerContainerSnapshot,
  DockerLogs,
  DockerReadCollection,
  DockerReadInspection,
  DockerResourceKind,
  DockerSecurityAudit,
} from "../shared/docker-read-contract";

export type DockerReadStatus = "idle" | "loading" | "ready" | "error";
export type DockerTab = "containers" | "images" | "networks" | "volumes" | "compose-projects" | "security";

export interface DockerReadState {
  scope: string | null;
  tab: DockerTab;
  filter: string;
  snapshotStatus: DockerReadStatus;
  snapshotRequest: number | null;
  snapshot: DockerContainerSnapshot | null;
  collections: Partial<Record<DockerCollectionKind, DockerReadCollection>>;
  collectionStatus: Partial<Record<DockerCollectionKind, DockerReadStatus>>;
  collectionRequests: Partial<Record<DockerCollectionKind, number>>;
  selectedContainerHandle: string | null;
  selectedNetworkHandle: string | null;
  selectedVolumeHandle: string | null;
  inspectionStatus: DockerReadStatus;
  inspectionRequest: number | null;
  inspectionKind: DockerResourceKind | null;
  inspectionHandle: string | null;
  inspection: DockerReadInspection | null;
  auditStatus: DockerReadStatus;
  auditRequest: number | null;
  audit: DockerSecurityAudit | null;
  logsStatus: DockerReadStatus;
  logsRequest: number | null;
  logsContainerHandle: string | null;
  logs: DockerLogs | null;
  error: string | null;
}

export function createDockerReadState(): DockerReadState {
  return {
    scope: null,
    tab: "containers",
    filter: "",
    snapshotStatus: "idle",
    snapshotRequest: null,
    snapshot: null,
    collections: {},
    collectionStatus: {},
    collectionRequests: {},
    selectedContainerHandle: null,
    selectedNetworkHandle: null,
    selectedVolumeHandle: null,
    inspectionStatus: "idle",
    inspectionRequest: null,
    inspectionKind: null,
    inspectionHandle: null,
    inspection: null,
    auditStatus: "idle",
    auditRequest: null,
    audit: null,
    logsStatus: "idle",
    logsRequest: null,
    logsContainerHandle: null,
    logs: null,
    error: null,
  };
}

export type DockerReadAction =
  | { type: "scope-changed"; scope: string | null }
  | { type: "tab-selected"; tab: DockerTab }
  | { type: "filter-changed"; filter: string }
  | { type: "snapshot-started"; scope: string; request: number }
  | { type: "snapshot-loaded"; scope: string; request: number; snapshot: DockerContainerSnapshot }
  | { type: "snapshot-failed"; scope: string; request: number; error: string }
  | { type: "collection-started"; scope: string; snapshotHandle: string; kind: DockerCollectionKind; request: number }
  | { type: "collection-loaded"; scope: string; snapshotHandle: string; kind: DockerCollectionKind; request: number; collection: DockerReadCollection }
  | { type: "collection-failed"; scope: string; snapshotHandle: string; kind: DockerCollectionKind; request: number; error: string }
  | { type: "container-selected"; handle: string }
  | { type: "network-selected"; handle: string }
  | { type: "volume-selected"; handle: string }
  | { type: "inspection-started"; scope: string; snapshotHandle: string; kind: DockerResourceKind; handle: string; request: number }
  | { type: "inspection-loaded"; scope: string; snapshotHandle: string; kind: DockerResourceKind; handle: string; request: number; inspection: DockerReadInspection }
  | { type: "inspection-failed"; scope: string; snapshotHandle: string; kind: DockerResourceKind; handle: string; request: number; error: string }
  | { type: "audit-started"; scope: string; snapshotHandle: string; request: number }
  | { type: "audit-loaded"; scope: string; snapshotHandle: string; request: number; audit: DockerSecurityAudit }
  | { type: "audit-failed"; scope: string; snapshotHandle: string; request: number; error: string }
  | { type: "logs-started"; scope: string; snapshotHandle: string; handle: string; request: number }
  | { type: "logs-loaded"; scope: string; snapshotHandle: string; handle: string; request: number; logs: DockerLogs }
  | { type: "logs-failed"; scope: string; snapshotHandle: string; handle: string; request: number; error: string };

export function dockerReadReducer(state: DockerReadState, action: DockerReadAction): DockerReadState {
  switch (action.type) {
    case "scope-changed":
      return action.scope === state.scope ? state : { ...createDockerReadState(), scope: action.scope };
    case "tab-selected":
      return { ...state, tab: action.tab, error: null };
    case "filter-changed":
      return { ...state, filter: action.filter };
    case "snapshot-started":
      if (action.scope !== state.scope) return state;
      return {
        ...state,
        snapshotStatus: "loading",
        snapshotRequest: action.request,
        snapshot: null,
        collections: {},
        collectionStatus: {},
        collectionRequests: {},
        selectedContainerHandle: null,
        selectedNetworkHandle: null,
        selectedVolumeHandle: null,
        inspectionStatus: "idle",
        inspectionRequest: null,
        inspectionKind: null,
        inspectionHandle: null,
        inspection: null,
        auditStatus: "idle",
        auditRequest: null,
        audit: null,
        logsStatus: "idle",
        logsRequest: null,
        logsContainerHandle: null,
        logs: null,
        error: null,
      };
    case "snapshot-loaded":
      if (action.scope !== state.scope || action.request !== state.snapshotRequest) return state;
      return {
        ...state,
        snapshotStatus: "ready",
        snapshotRequest: null,
        snapshot: action.snapshot,
        selectedContainerHandle: action.snapshot.containers[0]?.containerHandle ?? null,
        error: null,
      };
    case "snapshot-failed":
      if (action.scope !== state.scope || action.request !== state.snapshotRequest) return state;
      return { ...state, snapshotStatus: "error", snapshotRequest: null, error: action.error };
    case "collection-started":
      if (!sameSnapshot(state, action.scope, action.snapshotHandle)) return state;
      return {
        ...state,
        collectionStatus: { ...state.collectionStatus, [action.kind]: "loading" },
        collectionRequests: { ...state.collectionRequests, [action.kind]: action.request },
        error: null,
      };
    case "collection-loaded": {
      if (!sameCollectionRequest(state, action.scope, action.snapshotHandle, action.kind, action.request) ||
        action.collection.kind !== action.kind || action.collection.snapshotHandle !== action.snapshotHandle) return state;
      const next: DockerReadState = {
        ...state,
        collections: { ...state.collections, [action.kind]: action.collection },
        collectionStatus: { ...state.collectionStatus, [action.kind]: "ready" },
        collectionRequests: { ...state.collectionRequests, [action.kind]: undefined },
        error: null,
      };
      if (action.collection.kind === "networks") {
        next.selectedNetworkHandle = action.collection.items[0]?.networkHandle ?? null;
        next.inspectionStatus = "idle";
        next.inspectionRequest = null;
        next.inspectionKind = null;
        next.inspectionHandle = null;
        next.inspection = null;
      } else if (action.collection.kind === "volumes") {
        next.selectedVolumeHandle = action.collection.items[0]?.volumeHandle ?? null;
        next.inspectionStatus = "idle";
        next.inspectionRequest = null;
        next.inspectionKind = null;
        next.inspectionHandle = null;
        next.inspection = null;
      }
      return next;
    }
    case "collection-failed":
      if (!sameCollectionRequest(state, action.scope, action.snapshotHandle, action.kind, action.request)) return state;
      return {
        ...state,
        collectionStatus: { ...state.collectionStatus, [action.kind]: "error" },
        collectionRequests: { ...state.collectionRequests, [action.kind]: undefined },
        error: action.error,
      };
    case "container-selected":
      if (!state.snapshot?.containers.some((item) => item.containerHandle === action.handle)) return state;
      return selectionChanged(state, "container", action.handle);
    case "network-selected": {
      const collection = state.collections.networks;
      if (collection?.kind !== "networks" || !collection.items.some((item) => item.networkHandle === action.handle)) return state;
      return selectionChanged(state, "network", action.handle);
    }
    case "volume-selected": {
      const collection = state.collections.volumes;
      if (collection?.kind !== "volumes" || !collection.items.some((item) => item.volumeHandle === action.handle)) return state;
      return selectionChanged(state, "volume", action.handle);
    }
    case "inspection-started":
      if (!sameSnapshot(state, action.scope, action.snapshotHandle) ||
        selectedHandle(state, action.kind) !== action.handle) return state;
      return {
        ...state,
        inspectionStatus: "loading",
        inspectionRequest: action.request,
        inspectionKind: action.kind,
        inspectionHandle: action.handle,
        inspection: null,
        error: null,
      };
    case "inspection-loaded":
      if (!sameInspectionRequest(state, action) || action.inspection.kind !== action.kind ||
        action.inspection.snapshotHandle !== action.snapshotHandle ||
        action.inspection.resourceHandle !== action.handle) return state;
      return { ...state, inspectionStatus: "ready", inspectionRequest: null, inspection: action.inspection, error: null };
    case "inspection-failed":
      if (!sameInspectionRequest(state, action)) return state;
      return { ...state, inspectionStatus: "error", inspectionRequest: null, inspection: null, error: action.error };
    case "audit-started":
      if (!sameSnapshot(state, action.scope, action.snapshotHandle)) return state;
      return { ...state, auditStatus: "loading", auditRequest: action.request, audit: null, error: null };
    case "audit-loaded":
      if (!sameSnapshot(state, action.scope, action.snapshotHandle) || action.request !== state.auditRequest ||
        action.audit.snapshotHandle !== action.snapshotHandle) return state;
      return { ...state, auditStatus: "ready", auditRequest: null, audit: action.audit, error: null };
    case "audit-failed":
      if (!sameSnapshot(state, action.scope, action.snapshotHandle) || action.request !== state.auditRequest) return state;
      return { ...state, auditStatus: "error", auditRequest: null, audit: null, error: action.error };
    case "logs-started":
      if (!sameSnapshot(state, action.scope, action.snapshotHandle) ||
        state.selectedContainerHandle !== action.handle) return state;
      return {
        ...state,
        logsStatus: "loading",
        logsRequest: action.request,
        logsContainerHandle: action.handle,
        logs: null,
        error: null,
      };
    case "logs-loaded":
      if (!sameLogsRequest(state, action) || action.logs.snapshotHandle !== action.snapshotHandle ||
        action.logs.containerHandle !== action.handle) return state;
      return { ...state, logsStatus: "ready", logsRequest: null, logs: action.logs, error: null };
    case "logs-failed":
      if (!sameLogsRequest(state, action)) return state;
      return { ...state, logsStatus: "error", logsRequest: null, logs: null, error: action.error };
  }
}

function sameSnapshot(state: DockerReadState, scope: string, snapshotHandle: string): boolean {
  return state.scope === scope && state.snapshot?.snapshotHandle === snapshotHandle;
}

function sameCollectionRequest(
  state: DockerReadState,
  scope: string,
  snapshotHandle: string,
  kind: DockerCollectionKind,
  request: number,
): boolean {
  return sameSnapshot(state, scope, snapshotHandle) && state.collectionRequests[kind] === request;
}

function sameInspectionRequest(
  state: DockerReadState,
  action: { scope: string; snapshotHandle: string; kind: DockerResourceKind; handle: string; request: number },
): boolean {
  return sameSnapshot(state, action.scope, action.snapshotHandle) &&
    state.inspectionRequest === action.request && state.inspectionKind === action.kind &&
    state.inspectionHandle === action.handle && selectedHandle(state, action.kind) === action.handle;
}

function sameLogsRequest(
  state: DockerReadState,
  action: { scope: string; snapshotHandle: string; handle: string; request: number },
): boolean {
  return sameSnapshot(state, action.scope, action.snapshotHandle) && state.logsRequest === action.request &&
    state.logsContainerHandle === action.handle && state.selectedContainerHandle === action.handle;
}

function selectedHandle(state: DockerReadState, kind: DockerResourceKind): string | null {
  if (kind === "container") return state.selectedContainerHandle;
  if (kind === "network") return state.selectedNetworkHandle;
  return state.selectedVolumeHandle;
}

function selectionChanged(state: DockerReadState, kind: DockerResourceKind, handle: string): DockerReadState {
  return {
    ...state,
    selectedContainerHandle: kind === "container" ? handle : state.selectedContainerHandle,
    selectedNetworkHandle: kind === "network" ? handle : state.selectedNetworkHandle,
    selectedVolumeHandle: kind === "volume" ? handle : state.selectedVolumeHandle,
    inspectionStatus: "idle",
    inspectionRequest: null,
    inspectionKind: null,
    inspectionHandle: null,
    inspection: null,
    logsStatus: kind === "container" ? "idle" : state.logsStatus,
    logsRequest: kind === "container" ? null : state.logsRequest,
    logsContainerHandle: kind === "container" ? null : state.logsContainerHandle,
    logs: kind === "container" ? null : state.logs,
    error: null,
  };
}
