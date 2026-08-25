import type {
  ForensicCollector,
  SnapshotDetail,
  SnapshotDiffResult,
  SnapshotListResult,
} from "../shared/snapshot-read-contract";
import { chronologicalForensicHandles, isChronologicalDiff } from "./snapshot-read-helpers";

export type SnapshotTab = "directory" | "forensic" | "diff";
export type SnapshotLoadStatus = "idle" | "loading" | "ready" | "error";

interface DetailRequest {
  id: number;
  snapshotHandle: string;
}

interface DiffRequest {
  id: number;
  olderSnapshotHandle: string;
  newerSnapshotHandle: string;
}

export interface SnapshotReadState {
  scope: string | null;
  tab: SnapshotTab;
  search: string;
  collector: ForensicCollector;
  listStatus: SnapshotLoadStatus;
  listRequest: number | null;
  list: SnapshotListResult | null;
  listError: string | null;
  selectedDirectoryHandle: string | null;
  selectedForensicHandle: string | null;
  detailStatus: SnapshotLoadStatus;
  detailRequest: DetailRequest | null;
  detail: SnapshotDetail | null;
  detailError: string | null;
  olderSnapshotHandle: string | null;
  newerSnapshotHandle: string | null;
  diffStatus: SnapshotLoadStatus;
  diffRequest: DiffRequest | null;
  diff: SnapshotDiffResult | null;
  diffError: string | null;
}

export function createSnapshotReadState(): SnapshotReadState {
  return {
    scope: null,
    tab: "directory",
    search: "",
    collector: "processes",
    listStatus: "idle",
    listRequest: null,
    list: null,
    listError: null,
    selectedDirectoryHandle: null,
    selectedForensicHandle: null,
    detailStatus: "idle",
    detailRequest: null,
    detail: null,
    detailError: null,
    olderSnapshotHandle: null,
    newerSnapshotHandle: null,
    diffStatus: "idle",
    diffRequest: null,
    diff: null,
    diffError: null,
  };
}

export type SnapshotReadAction =
  | { type: "scope-changed"; scope: string | null }
  | { type: "tab-selected"; tab: SnapshotTab }
  | { type: "search-changed"; value: string }
  | { type: "collector-selected"; collector: ForensicCollector }
  | { type: "list-started"; scope: string; request: number }
  | { type: "list-loaded"; scope: string; request: number; list: SnapshotListResult }
  | { type: "list-failed"; scope: string; request: number; error: string }
  | { type: "snapshot-selected"; kind: "directory" | "forensic"; snapshotHandle: string }
  | { type: "detail-started"; scope: string; request: DetailRequest }
  | { type: "detail-loaded"; scope: string; request: DetailRequest; detail: SnapshotDetail }
  | { type: "detail-failed"; scope: string; request: DetailRequest; error: string }
  | { type: "diff-selection"; side: "older" | "newer"; snapshotHandle: string }
  | { type: "diff-started"; scope: string; request: DiffRequest }
  | { type: "diff-loaded"; scope: string; request: DiffRequest; diff: SnapshotDiffResult }
  | { type: "diff-failed"; scope: string; request: DiffRequest; error: string };

export function snapshotReadReducer(state: SnapshotReadState, action: SnapshotReadAction): SnapshotReadState {
  switch (action.type) {
    case "scope-changed":
      return action.scope === state.scope ? state : { ...createSnapshotReadState(), scope: action.scope };
    case "tab-selected":
      if (action.tab === state.tab) return state;
      return {
        ...state,
        tab: action.tab,
        detailStatus: "idle",
        detailRequest: null,
        detail: null,
        detailError: null,
        diffStatus: "idle",
        diffRequest: null,
        diff: null,
        diffError: null,
      };
    case "search-changed":
      return { ...state, search: action.value };
    case "collector-selected":
      return { ...state, collector: action.collector };
    case "list-started":
      if (state.scope !== action.scope) return state;
      return {
        ...state,
        listStatus: "loading",
        listRequest: action.request,
        list: null,
        listError: null,
        detailStatus: "idle",
        detailRequest: null,
        detail: null,
        detailError: null,
        diffStatus: "idle",
        diffRequest: null,
        diff: null,
        diffError: null,
      };
    case "list-loaded": {
      if (state.scope !== action.scope || state.listRequest !== action.request) return state;
      const selectedDirectoryHandle = retainOrFirst(
        action.list,
        "directory",
        state.selectedDirectoryHandle,
      );
      const selectedForensicHandle = retainOrFirst(
        action.list,
        "forensic",
        state.selectedForensicHandle,
      );
      const defaults = chronologicalForensicHandles(action.list.snapshots);
      const olderSnapshotHandle = hasForensic(action.list, state.olderSnapshotHandle)
        ? state.olderSnapshotHandle : defaults.older;
      const newerSnapshotHandle = hasForensic(action.list, state.newerSnapshotHandle)
        ? state.newerSnapshotHandle : defaults.newer;
      return {
        ...state,
        listStatus: "ready",
        listRequest: null,
        list: action.list,
        listError: null,
        selectedDirectoryHandle,
        selectedForensicHandle,
        olderSnapshotHandle,
        newerSnapshotHandle,
      };
    }
    case "list-failed":
      if (state.scope !== action.scope || state.listRequest !== action.request) return state;
      return { ...state, listStatus: "error", listRequest: null, listError: action.error };
    case "snapshot-selected": {
      if (!state.list?.snapshots.some((snapshot) =>
        snapshot.kind === action.kind && snapshot.snapshotHandle === action.snapshotHandle)) return state;
      return {
        ...state,
        selectedDirectoryHandle: action.kind === "directory" ? action.snapshotHandle : state.selectedDirectoryHandle,
        selectedForensicHandle: action.kind === "forensic" ? action.snapshotHandle : state.selectedForensicHandle,
        detailStatus: "idle",
        detailRequest: null,
        detail: null,
        detailError: null,
      };
    }
    case "detail-started": {
      const kind = state.tab === "directory" ? "directory" : state.tab === "forensic" ? "forensic" : null;
      if (state.scope !== action.scope || kind === null || !state.list?.snapshots.some((snapshot) =>
        snapshot.kind === kind && snapshot.snapshotHandle === action.request.snapshotHandle)) return state;
      return {
        ...state,
        detailStatus: "loading",
        detailRequest: action.request,
        detail: null,
        detailError: null,
      };
    }
    case "detail-loaded":
      if (!sameDetailRequest(state, action.scope, action.request) ||
        action.detail.snapshotHandle !== action.request.snapshotHandle || action.detail.kind !== state.tab) return state;
      return { ...state, detailStatus: "ready", detailRequest: null, detail: action.detail, detailError: null };
    case "detail-failed":
      if (!sameDetailRequest(state, action.scope, action.request)) return state;
      return { ...state, detailStatus: "error", detailRequest: null, detail: null, detailError: action.error };
    case "diff-selection":
      if (!hasForensic(state.list, action.snapshotHandle)) return state;
      return {
        ...state,
        olderSnapshotHandle: action.side === "older" ? action.snapshotHandle : state.olderSnapshotHandle,
        newerSnapshotHandle: action.side === "newer" ? action.snapshotHandle : state.newerSnapshotHandle,
        diffStatus: "idle",
        diffRequest: null,
        diff: null,
        diffError: null,
      };
    case "diff-started":
      if (state.scope !== action.scope || state.tab !== "diff" || state.list === null ||
        !isChronologicalDiff(
          state.list.snapshots,
          action.request.olderSnapshotHandle,
          action.request.newerSnapshotHandle,
        )) return state;
      return { ...state, diffStatus: "loading", diffRequest: action.request, diff: null, diffError: null };
    case "diff-loaded":
      if (!sameDiffRequest(state, action.scope, action.request) ||
        action.diff.olderSnapshotHandle !== action.request.olderSnapshotHandle ||
        action.diff.newerSnapshotHandle !== action.request.newerSnapshotHandle) return state;
      return { ...state, diffStatus: "ready", diffRequest: null, diff: action.diff, diffError: null };
    case "diff-failed":
      if (!sameDiffRequest(state, action.scope, action.request)) return state;
      return { ...state, diffStatus: "error", diffRequest: null, diff: null, diffError: action.error };
  }
}

function retainOrFirst(
  list: SnapshotListResult,
  kind: "directory" | "forensic",
  selected: string | null,
): string | null {
  return list.snapshots.some((snapshot) => snapshot.kind === kind && snapshot.snapshotHandle === selected)
    ? selected : list.snapshots.find((snapshot) => snapshot.kind === kind)?.snapshotHandle ?? null;
}

function hasForensic(list: SnapshotListResult | null, handle: string | null): boolean {
  return handle !== null && list?.snapshots.some((snapshot) =>
    snapshot.kind === "forensic" && snapshot.snapshotHandle === handle) === true;
}

function sameDetailRequest(state: SnapshotReadState, scope: string, request: DetailRequest): boolean {
  return state.scope === scope && state.detailRequest?.id === request.id &&
    state.detailRequest.snapshotHandle === request.snapshotHandle && state.tab !== "diff";
}

function sameDiffRequest(state: SnapshotReadState, scope: string, request: DiffRequest): boolean {
  return state.scope === scope && state.tab === "diff" && state.diffRequest?.id === request.id &&
    state.diffRequest.olderSnapshotHandle === request.olderSnapshotHandle &&
    state.diffRequest.newerSnapshotHandle === request.newerSnapshotHandle &&
    state.olderSnapshotHandle === request.olderSnapshotHandle &&
    state.newerSnapshotHandle === request.newerSnapshotHandle;
}
