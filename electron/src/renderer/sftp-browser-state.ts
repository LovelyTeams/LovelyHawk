import type {
  SftpBrowserEntry,
  SftpDirectorySnapshot,
  SftpTextPreview,
} from "../shared/sftp-browser-contract";
import {
  boundSftpSearch,
  filterSftpBrowserEntries,
  type SftpBrowserKindFilter,
} from "./sftp-browser-helpers";

export type SftpBrowserLoadStatus = "idle" | "loading" | "ready" | "error";

export interface SftpDirectoryRequest {
  id: number;
  mode: "open" | "list";
  browserHandle: string | null;
  directoryHandle: string | null;
}

export interface SftpPreviewRequest {
  id: number;
  browserHandle: string;
  fileHandle: string;
}

export interface SftpBrowserState {
  scope: string | null;
  search: string;
  kind: SftpBrowserKindFilter;
  directoryStatus: SftpBrowserLoadStatus;
  directoryRequest: SftpDirectoryRequest | null;
  directory: SftpDirectorySnapshot | null;
  directoryError: string | null;
  rootDirectoryHandle: string | null;
  selectedEntryHandle: string | null;
  previewStatus: SftpBrowserLoadStatus;
  previewRequest: SftpPreviewRequest | null;
  preview: SftpTextPreview | null;
  previewError: string | null;
}

export function createSftpBrowserState(scope: string | null = null): SftpBrowserState {
  return {
    scope,
    search: "",
    kind: "all",
    directoryStatus: "idle",
    directoryRequest: null,
    directory: null,
    directoryError: null,
    rootDirectoryHandle: null,
    selectedEntryHandle: null,
    previewStatus: "idle",
    previewRequest: null,
    preview: null,
    previewError: null,
  };
}

export type SftpBrowserAction =
  | { type: "scope-changed"; scope: string | null }
  | { type: "deactivated"; scope: string | null }
  | { type: "search-changed"; value: string }
  | { type: "kind-selected"; kind: SftpBrowserKindFilter }
  | { type: "directory-started"; scope: string; request: SftpDirectoryRequest }
  | { type: "directory-loaded"; scope: string; request: SftpDirectoryRequest; directory: SftpDirectorySnapshot }
  | { type: "directory-failed"; scope: string; request: SftpDirectoryRequest; error: string }
  | { type: "entry-selected"; entryHandle: string }
  | { type: "preview-started"; scope: string; request: SftpPreviewRequest }
  | { type: "preview-loaded"; scope: string; request: SftpPreviewRequest; preview: SftpTextPreview }
  | { type: "preview-failed"; scope: string; request: SftpPreviewRequest; error: string };

export function sftpBrowserReducer(
  state: SftpBrowserState,
  action: SftpBrowserAction,
): SftpBrowserState {
  switch (action.type) {
    case "scope-changed":
      return action.scope === state.scope ? state : createSftpBrowserState(action.scope);
    case "deactivated":
      return action.scope === state.scope ? createSftpBrowserState(action.scope) : state;
    case "search-changed":
      return withVisibleSelection({ ...state, search: boundSftpSearch(action.value) });
    case "kind-selected":
      return withVisibleSelection({ ...state, kind: action.kind });
    case "directory-started":
      if (state.scope !== action.scope || !validDirectoryRequest(state, action.request)) return state;
      return {
        ...state,
        directoryStatus: "loading",
        directoryRequest: action.request,
        directory: action.request.mode === "open" ? null : state.directory,
        directoryError: null,
        rootDirectoryHandle: action.request.mode === "open" ? null : state.rootDirectoryHandle,
        selectedEntryHandle: action.request.mode === "open" ? null : state.selectedEntryHandle,
        ...emptyPreview(),
      };
    case "directory-loaded": {
      if (!sameDirectoryRequest(state, action.scope, action.request) ||
        !matchesDirectoryResponse(action.request, action.directory)) return state;
      const visible = filterSftpBrowserEntries(action.directory.entries, state.kind, state.search);
      const selectedEntryHandle = visible.some((entry) => entry.entryHandle === state.selectedEntryHandle)
        ? state.selectedEntryHandle : visible[0]?.entryHandle ?? null;
      return {
        ...state,
        directoryStatus: "ready",
        directoryRequest: null,
        directory: action.directory,
        directoryError: null,
        rootDirectoryHandle: action.request.mode === "open"
          ? action.directory.directoryHandle : state.rootDirectoryHandle,
        selectedEntryHandle,
        ...emptyPreview(),
      };
    }
    case "directory-failed":
      if (!sameDirectoryRequest(state, action.scope, action.request)) return state;
      return {
        ...state,
        directoryStatus: "error",
        directoryRequest: null,
        directory: action.request.mode === "open" ? null : state.directory,
        directoryError: action.error,
        rootDirectoryHandle: action.request.mode === "open" ? null : state.rootDirectoryHandle,
        selectedEntryHandle: action.request.mode === "open" ? null : state.selectedEntryHandle,
        ...emptyPreview(),
      };
    case "entry-selected":
      if (!state.directory?.entries.some((entry) => entry.entryHandle === action.entryHandle)) return state;
      return action.entryHandle === state.selectedEntryHandle ? state : {
        ...state,
        selectedEntryHandle: action.entryHandle,
        ...emptyPreview(),
      };
    case "preview-started":
      if (state.scope !== action.scope || state.directoryStatus !== "ready" ||
        state.directory?.browserHandle !== action.request.browserHandle ||
        state.selectedEntryHandle !== action.request.fileHandle ||
        selectedEntry(state)?.action !== "preview") return state;
      return {
        ...state,
        previewStatus: "loading",
        previewRequest: action.request,
        preview: null,
        previewError: null,
      };
    case "preview-loaded":
      if (!samePreviewRequest(state, action.scope, action.request) ||
        action.preview.browserHandle !== action.request.browserHandle ||
        action.preview.fileHandle !== action.request.fileHandle) return state;
      return {
        ...state,
        previewStatus: "ready",
        previewRequest: null,
        preview: action.preview,
        previewError: null,
      };
    case "preview-failed":
      if (!samePreviewRequest(state, action.scope, action.request)) return state;
      return {
        ...state,
        previewStatus: "error",
        previewRequest: null,
        preview: null,
        previewError: action.error,
      };
  }
}

function validDirectoryRequest(state: SftpBrowserState, request: SftpDirectoryRequest): boolean {
  if (request.mode === "open") return request.browserHandle === null && request.directoryHandle === null;
  return request.browserHandle !== null && request.directoryHandle !== null &&
    state.directory?.browserHandle === request.browserHandle &&
    (state.directory.directoryHandle === request.directoryHandle ||
      state.directory.parentDirectoryHandle === request.directoryHandle ||
      state.rootDirectoryHandle === request.directoryHandle ||
      state.directory.entries.some((entry) =>
        entry.entryHandle === request.directoryHandle && entry.action === "browse"));
}

function matchesDirectoryResponse(
  request: SftpDirectoryRequest,
  directory: SftpDirectorySnapshot,
): boolean {
  return request.mode === "open" ||
    directory.browserHandle === request.browserHandle && directory.directoryHandle === request.directoryHandle;
}

function sameDirectoryRequest(
  state: SftpBrowserState,
  scope: string,
  request: SftpDirectoryRequest,
): boolean {
  return state.scope === scope && state.directoryRequest?.id === request.id &&
    state.directoryRequest.mode === request.mode &&
    state.directoryRequest.browserHandle === request.browserHandle &&
    state.directoryRequest.directoryHandle === request.directoryHandle;
}

function samePreviewRequest(
  state: SftpBrowserState,
  scope: string,
  request: SftpPreviewRequest,
): boolean {
  return state.scope === scope && state.previewRequest?.id === request.id &&
    state.previewRequest.browserHandle === request.browserHandle &&
    state.previewRequest.fileHandle === request.fileHandle &&
    state.directory?.browserHandle === request.browserHandle &&
    state.selectedEntryHandle === request.fileHandle && selectedEntry(state)?.action === "preview";
}

function selectedEntry(state: SftpBrowserState): SftpBrowserEntry | null {
  return state.directory?.entries.find((entry) => entry.entryHandle === state.selectedEntryHandle) ?? null;
}

function withVisibleSelection(state: SftpBrowserState): SftpBrowserState {
  const visible = filterSftpBrowserEntries(state.directory?.entries ?? [], state.kind, state.search);
  const selectedEntryHandle = visible.some((entry) => entry.entryHandle === state.selectedEntryHandle)
    ? state.selectedEntryHandle : visible[0]?.entryHandle ?? null;
  return selectedEntryHandle === state.selectedEntryHandle ? state : {
    ...state,
    selectedEntryHandle,
    ...emptyPreview(),
  };
}

function emptyPreview(): Pick<SftpBrowserState, "previewStatus" | "previewRequest" | "preview" | "previewError"> {
  return { previewStatus: "idle", previewRequest: null, preview: null, previewError: null };
}
