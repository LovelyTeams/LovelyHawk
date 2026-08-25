import { describe, expect, it } from "vitest";

import type {
  SftpBrowserEntry,
  SftpDirectorySnapshot,
  SftpTextPreview,
} from "../shared/sftp-browser-contract";
import {
  displaySftpBytes,
  filterSftpBrowserEntries,
  sftpBrowserActionLabel,
  sftpBrowserKindLabel,
  sftpBrowserScope,
} from "./sftp-browser-helpers";
import {
  createSftpBrowserState,
  sftpBrowserReducer,
  type SftpDirectoryRequest,
  type SftpPreviewRequest,
} from "./sftp-browser-state";

const entries: SftpBrowserEntry[] = [
  { entryHandle: "dir-handle", name: "配置目录", nameTruncated: false,
    kind: "directory", action: "browse", sizeBytes: "4096", modifiedAt: null, mode: "0755", ownerId: 0, groupId: 0 },
  { entryHandle: "file-handle", name: "Evidence.LOG", nameTruncated: false,
    kind: "file", action: "preview", sizeBytes: "42", modifiedAt: "2026-08-24T10:00:00Z", mode: "0644", ownerId: 1000, groupId: 1000 },
  { entryHandle: "link-handle", name: "latest", nameTruncated: false,
    kind: "symlink", action: "none", sizeBytes: "7", modifiedAt: null, mode: "0777", ownerId: 0, groupId: 0 },
];

const root: SftpDirectorySnapshot = {
  browserHandle: "browser-one",
  directoryHandle: "root-handle",
  parentDirectoryHandle: null,
  directoryLabel: "根目录",
  directoryLabelTruncated: false,
  expiresInSeconds: 300,
  observedEntryCount: entries.length,
  displayedEntryCount: entries.length,
  truncated: false,
  entries,
};

const child: SftpDirectorySnapshot = {
  ...root,
  directoryHandle: "dir-handle",
  parentDirectoryHandle: "root-handle",
  directoryLabel: "配置目录",
  entries: [entries[1]!],
  observedEntryCount: 1,
  displayedEntryCount: 1,
};

const scope = "scope-one";
const openRequest: SftpDirectoryRequest = {
  id: 1,
  mode: "open",
  browserHandle: null,
  directoryHandle: null,
};

function loadedRoot() {
  let state = createSftpBrowserState(scope);
  state = sftpBrowserReducer(state, { type: "directory-started", scope, request: openRequest });
  return sftpBrowserReducer(state, { type: "directory-loaded", scope, request: openRequest, directory: root });
}

describe("sftp browser helpers and state", () => {
  it("filters locally by kind and case-insensitive hostile-safe name text", () => {
    expect(filterSftpBrowserEntries(entries, "all", "evidence").map((entry) => entry.entryHandle))
      .toEqual(["file-handle"]);
    expect(filterSftpBrowserEntries(entries, "directory", "")).toEqual([entries[0]]);
    expect(sftpBrowserKindLabel("symlink")).toBe("符号链接");
    expect(sftpBrowserActionLabel(entries[2]!)).toBe("不跟随");
    expect(displaySftpBytes("18446744073709551615")).toBe("18446744073709551615 bytes");
  });

  it("uses only the opaque binding handle as the renderer lifecycle scope", () => {
    expect(sftpBrowserScope({ scopeKey: "binding-one" })).toBe("binding-one");
  });

  it("opens a root snapshot and keeps a stable valid selection", () => {
    const state = loadedRoot();
    expect(state.directoryStatus).toBe("ready");
    expect(state.rootDirectoryHandle).toBe("root-handle");
    expect(state.selectedEntryHandle).toBe("dir-handle");
    const refreshed = { ...root, entries: [entries[2]!, entries[0]!, entries[1]!] };
    const request: SftpDirectoryRequest = { id: 2, mode: "list", browserHandle: "browser-one",
      directoryHandle: "root-handle" };
    const loading = sftpBrowserReducer(state, { type: "directory-started", scope, request });
    const ready = sftpBrowserReducer(loading, { type: "directory-loaded", scope, request, directory: refreshed });
    expect(ready.selectedEntryHandle).toBe("dir-handle");
  });

  it("navigates only through a returned browse capability and retains the root capability", () => {
    const state = loadedRoot();
    const request: SftpDirectoryRequest = { id: 2, mode: "list", browserHandle: "browser-one",
      directoryHandle: "dir-handle" };
    const loading = sftpBrowserReducer(state, { type: "directory-started", scope, request });
    const ready = sftpBrowserReducer(loading, { type: "directory-loaded", scope, request, directory: child });
    expect(ready.directory?.parentDirectoryHandle).toBe("root-handle");
    expect(ready.rootDirectoryHandle).toBe("root-handle");
    const symlinkRequest: SftpDirectoryRequest = { id: 3, mode: "list", browserHandle: "browser-one",
      directoryHandle: "link-handle" };
    expect(sftpBrowserReducer(state, { type: "directory-started", scope, request: symlinkRequest })).toBe(state);
  });

  it("loads preview only for the exact selected file capability", () => {
    let state = loadedRoot();
    state = sftpBrowserReducer(state, { type: "entry-selected", entryHandle: "file-handle" });
    const request: SftpPreviewRequest = { id: 2, browserHandle: "browser-one", fileHandle: "file-handle" };
    state = sftpBrowserReducer(state, { type: "preview-started", scope, request });
    const preview: SftpTextPreview = { browserHandle: "browser-one", fileHandle: "file-handle", text: "plain",
      observedLineCount: 1, displayedLineCount: 1, truncated: false };
    state = sftpBrowserReducer(state, { type: "preview-loaded", scope, request, preview });
    expect(state.preview).toEqual(preview);
    expect(state.previewStatus).toBe("ready");
  });

  it("rejects late directory and preview results after scope or selection changes", () => {
    let state = loadedRoot();
    const directoryRequest: SftpDirectoryRequest = { id: 2, mode: "list", browserHandle: "browser-one",
      directoryHandle: "dir-handle" };
    const loading = sftpBrowserReducer(state, { type: "directory-started", scope, request: directoryRequest });
    const switched = sftpBrowserReducer(loading, { type: "scope-changed", scope: "scope-two" });
    expect(sftpBrowserReducer(switched, { type: "directory-loaded", scope, request: directoryRequest,
      directory: child }).directory).toBeNull();

    state = sftpBrowserReducer(state, { type: "entry-selected", entryHandle: "file-handle" });
    const previewRequest: SftpPreviewRequest = { id: 3, browserHandle: "browser-one", fileHandle: "file-handle" };
    state = sftpBrowserReducer(state, { type: "preview-started", scope, request: previewRequest });
    state = sftpBrowserReducer(state, { type: "entry-selected", entryHandle: "dir-handle" });
    const preview: SftpTextPreview = { browserHandle: "browser-one", fileHandle: "file-handle", text: "late",
      observedLineCount: 1, displayedLineCount: 1, truncated: false };
    expect(sftpBrowserReducer(state, { type: "preview-loaded", scope, request: previewRequest, preview }).preview)
      .toBeNull();
  });

  it("clears target data on deactivation and bounds local search", () => {
    let state = loadedRoot();
    state = sftpBrowserReducer(state, { type: "search-changed", value: "界".repeat(300) });
    expect([...state.search]).toHaveLength(256);
    state = sftpBrowserReducer(state, { type: "deactivated", scope });
    expect(state.directory).toBeNull();
    expect(state.preview).toBeNull();
    expect(state.scope).toBe(scope);
  });

  it("preserves the current snapshot on a list error but fails a new open closed", () => {
    const state = loadedRoot();
    const listRequest: SftpDirectoryRequest = { id: 2, mode: "list", browserHandle: "browser-one",
      directoryHandle: "root-handle" };
    const listing = sftpBrowserReducer(state, { type: "directory-started", scope, request: listRequest });
    const listError = sftpBrowserReducer(listing, { type: "directory-failed", scope, request: listRequest,
      error: "fixed" });
    expect(listError.directory).toEqual(root);
    expect(listError.directoryStatus).toBe("error");

    const opening = sftpBrowserReducer(state, { type: "directory-started", scope,
      request: { ...openRequest, id: 3 } });
    const openError = sftpBrowserReducer(opening, { type: "directory-failed", scope,
      request: { ...openRequest, id: 3 }, error: "fixed" });
    expect(openError.directory).toBeNull();
    expect(openError.rootDirectoryHandle).toBeNull();
  });
});
