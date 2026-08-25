import { describe, expect, it } from "vitest";

import type {
  SnapshotDetail,
  SnapshotDiffResult,
  SnapshotListResult,
} from "../shared/snapshot-read-contract";
import {
  filterDiffField,
  filterPlainText,
  filterSnapshotList,
  snapshotScope,
} from "./snapshot-read-helpers";
import { createSnapshotReadState, snapshotReadReducer } from "./snapshot-read-state";

const list: SnapshotListResult = {
  expiresInSeconds: 300,
  snapshots: [{
    snapshotHandle: "newer", kind: "forensic", capturedAt: "2026-08-24T00:00:00Z", itemCount: 12,
    completedCollectors: 12, failedCollectors: 0,
  }, {
    snapshotHandle: "directory", kind: "directory", capturedAt: "2026-08-23T12:00:00Z", itemCount: 1,
    completedCollectors: null, failedCollectors: null,
  }, {
    snapshotHandle: "older", kind: "forensic", capturedAt: "2026-08-23T00:00:00Z", itemCount: 12,
    completedCollectors: 12, failedCollectors: 1,
  }],
  directoryCount: 1,
  forensicCount: 2,
  truncated: false,
};

const detail: SnapshotDetail = {
  snapshotHandle: "directory",
  kind: "directory",
  capturedAt: "2026-08-23T12:00:00Z",
  items: [{ preset: "etc", kind: "directory", bytes: "42", present: true, archiveAvailability: "not-checked" }],
  truncated: false,
};

const diff: SnapshotDiffResult = {
  olderSnapshotHandle: "older",
  newerSnapshotHandle: "newer",
  fields: [],
  addedLineCount: 0,
  removedLineCount: 0,
  redactedLineCount: 0,
  truncated: false,
};

function loadedState() {
  let state = snapshotReadReducer(createSnapshotReadState(), { type: "scope-changed", scope: "scope-a" });
  state = snapshotReadReducer(state, { type: "list-started", scope: "scope-a", request: 1 });
  return snapshotReadReducer(state, { type: "list-loaded", scope: "scope-a", request: 1, list });
}

describe("snapshot read reducer", () => {
  it("rejects late list results after exact target scope changes", () => {
    let state = snapshotReadReducer(createSnapshotReadState(), { type: "scope-changed", scope: "scope-a" });
    state = snapshotReadReducer(state, { type: "list-started", scope: "scope-a", request: 1 });
    state = snapshotReadReducer(state, { type: "scope-changed", scope: "scope-b" });
    state = snapshotReadReducer(state, { type: "list-loaded", scope: "scope-a", request: 1, list });
    expect(state.scope).toBe("scope-b");
    expect(state.list).toBeNull();
  });

  it("retains opaque selection across refresh and derives chronological diff defaults", () => {
    let state = loadedState();
    expect(state.selectedDirectoryHandle).toBe("directory");
    expect(state.olderSnapshotHandle).toBe("older");
    expect(state.newerSnapshotHandle).toBe("newer");
    state = snapshotReadReducer(state, { type: "list-started", scope: "scope-a", request: 2 });
    state = snapshotReadReducer(state, { type: "list-loaded", scope: "scope-a", request: 2, list });
    expect(state.selectedDirectoryHandle).toBe("directory");
  });

  it("rejects late detail after selection or tab changes", () => {
    let state = loadedState();
    const request = { id: 2, snapshotHandle: "directory" };
    state = snapshotReadReducer(state, { type: "detail-started", scope: "scope-a", request });
    state = snapshotReadReducer(state, { type: "tab-selected", tab: "forensic" });
    state = snapshotReadReducer(state, { type: "detail-loaded", scope: "scope-a", request, detail });
    expect(state.detail).toBeNull();
  });

  it("accepts diff only for the active ordered pair and rejects late replacement", () => {
    let state = snapshotReadReducer(loadedState(), { type: "tab-selected", tab: "diff" });
    const request = { id: 3, olderSnapshotHandle: "older", newerSnapshotHandle: "newer" };
    state = snapshotReadReducer(state, { type: "diff-started", scope: "scope-a", request });
    state = snapshotReadReducer(state, { type: "diff-selection", side: "older", snapshotHandle: "newer" });
    state = snapshotReadReducer(state, { type: "diff-loaded", scope: "scope-a", request, diff });
    expect(state.diff).toBeNull();
  });
});

describe("snapshot read helpers", () => {
  it("filters hostile plain text and diff lines without interpreting them", () => {
    const hostile = "</pre><script>x()</script>";
    expect(filterPlainText(`${hostile}\nsafe`, "script")).toBe(hostile);
    expect(filterDiffField({
      collector: "networkConnections", added: [hostile, "safe"], removed: [], redactedLineCount: 0,
      truncated: false,
    }, "script").added).toEqual([hostile]);
    expect(filterSnapshotList(list.snapshots, "forensic", "2026-08-24").map((item) => item.snapshotHandle))
      .toEqual(["newer"]);
  });

  it("changes lifecycle scope only with the opaque binding capability", () => {
    expect(snapshotScope("binding-a")).toBe("binding-a");
    expect(snapshotScope("binding-a")).not.toBe(snapshotScope("binding-b"));
  });
});
