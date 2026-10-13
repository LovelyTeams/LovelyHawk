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
  /**
   * The names of the folders from the start directory down to the one shown,
   * as the listings named them; null when one of them was cut short, so the
   * way back cannot be told.
   */
  trail: string[] | null;
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
    trail: null,
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
        trail: action.request.mode === "open" ? null : state.trail,
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
        trail: nextTrail(state, action.request),
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
        trail: action.request.mode === "open" ? null : state.trail,
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

/**
 * Where a listing that just arrived sits, from where the one on screen was:
 * the same folder again, its parent, the start directory, or one of its
 * folders.
 */
function nextTrail(state: SftpBrowserState, request: SftpDirectoryRequest): string[] | null {
  if (request.mode === "open") return [];
  const current = state.directory;
  const trail = state.trail;
  if (current === null || request.directoryHandle === null) return null;
  if (request.directoryHandle === current.directoryHandle) return trail;
  if (request.directoryHandle === state.rootDirectoryHandle) return [];
  if (request.directoryHandle === current.parentDirectoryHandle) {
    return trail === null || trail.length === 0 ? null : trail.slice(0, -1);
  }
  const entry = current.entries.find((candidate) => candidate.entryHandle === request.directoryHandle);
  if (trail === null || entry === undefined || entry.nameTruncated) return null;
  return trail.length >= SFTP_TRAIL_MAXIMUM_DEPTH ? null : [...trail, entry.name];
}

/** Deeper than this, the way back is not kept: each step is one more listing. */
export const SFTP_TRAIL_MAXIMUM_DEPTH = 32;

/** A trail as a path, for saying where something is. */
export function sftpTrailPath(trail: readonly string[]): string {
  return `/${trail.join("/")}`;
}

export type SftpReturnStep =
  | { kind: "enter"; entryHandle: string }
  | { kind: "missing" }
  | { kind: "ambiguous" };

/**
 * The next step back down to a folder after reopening: the one folder in this
 * listing with that exact name. Two with the same shown name (or one whose
 * name was cut short) cannot be told apart, so the walk stops there rather
 * than guess.
 */
export function sftpReturnStep(directory: SftpDirectorySnapshot, name: string): SftpReturnStep {
  const matches = directory.entries.filter((entry) => entry.name === name && entry.action === "browse");
  if (matches.length === 0) return { kind: "missing" };
  if (matches.length > 1 || matches[0]!.nameTruncated) return { kind: "ambiguous" };
  return { kind: "enter", entryHandle: matches[0]!.entryHandle };
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
