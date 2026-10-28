import { describe, expect, it } from "vitest";

import type {
  SftpBrowserEntry,
  SftpDirectorySnapshot,
  SftpTextPreview,
} from "../shared/sftp-browser-contract";
import {
  compactSftpBytes,
  describeSftpBytes,
  displaySftpBytes,
  filterSftpBrowserEntries,
  sftpBrowserActionLabel,
  sftpBrowserKindLabel,
  sftpBrowserScope,
} from "./sftp-browser-helpers";
import {
  createSftpBrowserState,
  SFTP_TRAIL_MAXIMUM_DEPTH,
  sftpBrowserReducer,
  sftpReturnStep,
  sftpTrailPath,
  type SftpBrowserState,
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
    expect(displaySftpBytes("18446744073709551615")).toBe("18446744073709551615 字节");
  });

  it("fits a size in a column without losing the exact count", () => {
    expect(compactSftpBytes("0")).toBe("0 字节");
    expect(compactSftpBytes("1023")).toBe("1023 字节");
    expect(compactSftpBytes("1024")).toBe("1.0 KB");
    expect(compactSftpBytes("5483520")).toBe("5.2 MB");
    expect(compactSftpBytes("6442450944")).toBe("6.0 GB");
    expect(compactSftpBytes("18446744073709551615")).toBe("16.0 EB");
    // Anything that is not a plain count is shown as it came.
    expect(compactSftpBytes("12x")).toBe("12x 字节");
    expect(describeSftpBytes("128")).toBe("128 字节");
    expect(describeSftpBytes("6442450944")).toBe("6.0 GB（6442450944 字节）");
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
      observedLineCount: 1, displayedLineCount: 1, truncated: false, sha256: "a".repeat(64), exact: true };
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
      observedLineCount: 1, displayedLineCount: 1, truncated: false, sha256: "a".repeat(64), exact: true };
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

  it("keeps the folder names from the start directory to the one shown", () => {
    let id = 10;
    const list = (state: SftpBrowserState, directory: SftpDirectorySnapshot) => {
      const request: SftpDirectoryRequest = {
        id: ++id, mode: "list", browserHandle: directory.browserHandle, directoryHandle: directory.directoryHandle,
      };
      const started = sftpBrowserReducer(state, { type: "directory-started", scope, request });
      return sftpBrowserReducer(started, { type: "directory-loaded", scope, request, directory });
    };
    const deeper: SftpDirectorySnapshot = {
      ...child,
      entries: [{ ...entries[0]!, entryHandle: "deep-handle", name: "nginx" }],
    };
    const deep: SftpDirectorySnapshot = {
      ...root, directoryHandle: "deep-handle", parentDirectoryHandle: "dir-handle", directoryLabel: "nginx", entries: [],
    };
    let state = loadedRoot();
    expect(state.trail).toEqual([]);
    state = list(state, deeper);
    expect(state.trail).toEqual(["配置目录"]);
    state = list(state, deep);
    expect(state.trail).toEqual(["配置目录", "nginx"]);
    expect(sftpTrailPath(state.trail!)).toBe("/配置目录/nginx");
    // Listing the same folder again keeps it; up one drops a name; home empties it.
    expect(list(state, deep).trail).toEqual(["配置目录", "nginx"]);
    expect(list(state, deeper).trail).toEqual(["配置目录"]);
    expect(list(state, root).trail).toEqual([]);

    // A name cut short cannot be walked back to, nor can anything below it.
    const cut = list(loadedRoot(), deeper);
    const truncatedParent = { ...cut, directory: { ...deeper, entries: [{ ...deeper.entries[0]!, nameTruncated: true }] } };
    const lost = list(truncatedParent, deep);
    expect(lost.trail).toBeNull();
    expect(list(lost, { ...deep, directoryHandle: "deep-handle" }).trail).toBeNull();
    // A new browser starts the trail over; a failed open forgets it.
    expect(sftpBrowserReducer(state, { type: "directory-started", scope, request: { ...openRequest, id: 99 } }).trail).toBeNull();
    expect(SFTP_TRAIL_MAXIMUM_DEPTH).toBeGreaterThan(8);
  });

  it("walks back only into the one folder with exactly that name", () => {
    const listing = (named: SftpBrowserEntry[]): SftpDirectorySnapshot => ({ ...root, entries: named });
    const folder = (handle: string, name: string, extra: Partial<SftpBrowserEntry> = {}): SftpBrowserEntry =>
      ({ ...entries[0]!, entryHandle: handle, name, ...extra });
    expect(sftpReturnStep(listing([folder("a", "log"), folder("b", "lib")]), "log"))
      .toEqual({ kind: "enter", entryHandle: "a" });
    // Gone, or only a file or an unfollowed link of that name.
    expect(sftpReturnStep(listing([folder("b", "lib")]), "log")).toEqual({ kind: "missing" });
    expect(sftpReturnStep(listing([{ ...entries[1]!, name: "log" }, { ...entries[2]!, name: "log" }]), "log"))
      .toEqual({ kind: "missing" });
    // Names are compared exactly: no case folding, no trimming.
    expect(sftpReturnStep(listing([folder("a", "Log"), folder("c", "log ")]), "log")).toEqual({ kind: "missing" });
    // Two shown the same way, or one cut short, cannot be told apart.
    expect(sftpReturnStep(listing([folder("a", "log"), folder("d", "log")]), "log")).toEqual({ kind: "ambiguous" });
    expect(sftpReturnStep(listing([folder("a", "log", { nameTruncated: true })]), "log")).toEqual({ kind: "ambiguous" });
  });
});
