import { describe, expect, it } from "vitest";

import type { EmergencyCommandCatalog, EmergencyCommandResult } from "../shared/emergency-command-contract";
import {
  emergencyCommandScope,
  filterEmergencyCommands,
  groupEmergencyCommands,
} from "./emergency-command-helpers";
import { createEmergencyCommandState, emergencyCommandReducer } from "./emergency-command-state";

const catalog: EmergencyCommandCatalog = {
  snapshotHandle: "snapshot-one",
  containers: [],
  expiresInSeconds: 300,
  commandSet: "detected",
  commands: [
    { commandHandle: "command-network", category: "network", title: "监听端口", description: "网络状态", timeoutSeconds: 30 },
    { commandHandle: "command-system", category: "system", title: "系统状态", description: "内核资源", timeoutSeconds: 30 },
  ],
};

const result: EmergencyCommandResult = {
  snapshotHandle: "snapshot-one",
  commandHandle: "command-network",
  resultKind: "success",
  exitCode: 0,
  output: "plain",
  observedLineCount: 1,
  displayedLineCount: 1,
  findingLines: [],
  findingReason: null,
  truncated: false,
  paths: [],
};

function loaded() {
  let state = emergencyCommandReducer(createEmergencyCommandState(), { type: "scope-changed", scope: "scope-one" });
  state = emergencyCommandReducer(state, { type: "catalog-started", scope: "scope-one", request: 1 });
  return emergencyCommandReducer(state, { type: "catalog-loaded", scope: "scope-one", request: 1, catalog });
}

describe("emergency command state", () => {
  it("scopes lifecycle only to the opaque binding handle", () => {
    expect(emergencyCommandScope("binding-one")).toBe("binding-one");
    expect(emergencyCommandScope("binding-one")).not.toBe(emergencyCommandScope("binding-two"));
  });

  it("rejects late catalog results after target lifecycle changes", () => {
    let state = emergencyCommandReducer(createEmergencyCommandState(), { type: "scope-changed", scope: "scope-one" });
    state = emergencyCommandReducer(state, { type: "catalog-started", scope: "scope-one", request: 1 });
    state = emergencyCommandReducer(state, { type: "scope-changed", scope: "scope-two" });
    state = emergencyCommandReducer(state, { type: "catalog-loaded", scope: "scope-one", request: 1, catalog });
    expect(state.catalog).toBeNull();
    expect(state.scope).toBe("scope-two");
  });

  it("reveals a check from history even when a search or a collapsed group hid it", () => {
    let state = loaded();
    state = emergencyCommandReducer(state, { type: "search-changed", search: "监听" });
    state = emergencyCommandReducer(state, { type: "category-toggled", category: "system" });
    const reveal = { type: "command-revealed", scope: "scope-one", snapshotHandle: "snapshot-one", commandHandle: "command-system" } as const;
    state = emergencyCommandReducer(state, reveal);
    expect(state.selectedCommandHandle).toBe("command-system");
    expect(state.search).toBe("");
    expect(state.collapsedCategories).not.toContain("system");
    // Another target's catalogue, an older snapshot, or a handle it never gave: nothing moves.
    const before = state;
    expect(emergencyCommandReducer(before, { ...reveal, scope: "scope-two", commandHandle: "command-network" })).toBe(before);
    expect(emergencyCommandReducer(before, { ...reveal, snapshotHandle: "snapshot-old", commandHandle: "command-network" })).toBe(before);
    expect(emergencyCommandReducer(before, { ...reveal, commandHandle: "command-forged" })).toBe(before);
    // Not in the middle of a run.
    const running = emergencyCommandReducer(before, { type: "run-started", scope: "scope-one",
      request: { id: 2, snapshotHandle: "snapshot-one", commandHandle: "command-system" } });
    expect(emergencyCommandReducer(running, { ...reveal, commandHandle: "command-network" })).toBe(running);
  });

  it("keeps selection stable while visible and selects the first filtered command otherwise", () => {
    let state = loaded();
    expect(state.selectedCommandHandle).toBe("command-network");
    state = emergencyCommandReducer(state, { type: "command-selected", commandHandle: "command-system" });
    state = emergencyCommandReducer(state, { type: "search-changed", search: "系统" });
    expect(state.selectedCommandHandle).toBe("command-system");
    state = emergencyCommandReducer(state, { type: "search-changed", search: "没有匹配" });
    expect(state.selectedCommandHandle).toBeNull();
    state = emergencyCommandReducer(state, { type: "search-changed", search: "" });
    expect(state.selectedCommandHandle).toBe("command-network");
  });

  /** Collapsing a tree branch is presentation only. */
  it("toggles branches without disturbing the selection or the last result", () => {
    const request = { id: 2, snapshotHandle: "snapshot-one", commandHandle: "command-network" };
    let state = emergencyCommandReducer(loaded(), { type: "run-started", scope: "scope-one", request });
    state = emergencyCommandReducer(state, { type: "run-loaded", scope: "scope-one", request, result });
    state = emergencyCommandReducer(state, { type: "category-toggled", category: "network" });
    expect(state.collapsedCategories).toEqual(["network"]);
    expect(state.selectedCommandHandle).toBe("command-network");
    expect(state.result).toEqual(result);
    state = emergencyCommandReducer(state, { type: "category-toggled", category: "network" });
    expect(state.collapsedCategories).toEqual([]);
  });

  it("runs only the selected command from the current opaque snapshot", () => {
    let state = loaded();
    const request = { id: 2, snapshotHandle: "snapshot-one", commandHandle: "command-network" };
    state = emergencyCommandReducer(state, { type: "run-started", scope: "scope-one", request });
    expect(state.runStatus).toBe("loading");
    state = emergencyCommandReducer(state, { type: "run-loaded", scope: "scope-one", request, result });
    expect(state.result).toEqual(result);
    const invalid = { id: 3, snapshotHandle: "snapshot-one", commandHandle: "not-selected" };
    expect(emergencyCommandReducer(state, { type: "run-started", scope: "scope-one", request: invalid })).toBe(state);
  });

  it("keeps a running result attached to its selection and rejects late data after a target switch", () => {
    const request = { id: 2, snapshotHandle: "snapshot-one", commandHandle: "command-network" };
    let state = emergencyCommandReducer(loaded(), { type: "run-started", scope: "scope-one", request });
    expect(emergencyCommandReducer(state, { type: "command-selected", commandHandle: "command-system" })).toBe(state);
    expect(emergencyCommandReducer(state, { type: "search-changed", search: "系统" })).toBe(state);
    expect(emergencyCommandReducer(state, { type: "catalog-started", scope: "scope-one", request: 3 })).toBe(state);
    state = emergencyCommandReducer(state, { type: "run-loaded", scope: "scope-one", request, result });
    expect(state.result).toEqual(result);

    state = emergencyCommandReducer(loaded(), { type: "run-started", scope: "scope-one", request });
    state = emergencyCommandReducer(state, { type: "scope-changed", scope: "scope-two" });
    state = emergencyCommandReducer(state, { type: "run-loaded", scope: "scope-one", request, result });
    expect(state.result).toBeNull();

    state = emergencyCommandReducer(loaded(), { type: "run-started", scope: "scope-one", request });
    state = emergencyCommandReducer(state, { type: "scope-changed", scope: null });
    state = emergencyCommandReducer(state, { type: "run-loaded", scope: "scope-one", request, result });
    expect(state.result).toBeNull();
  });

  it("filters only safe display metadata and exposes empty matches", () => {
    expect(filterEmergencyCommands(catalog.commands, "内核").map((item) => item.commandHandle))
      .toEqual(["command-system"]);
    expect(filterEmergencyCommands(catalog.commands, "missing")).toEqual([]);
  });

  it("clears observations when the execution location changes after completion", () => {
    const request = { id: 2, snapshotHandle: "snapshot-one", commandHandle: "command-network" };
    let state = emergencyCommandReducer(loaded(), { type: "run-started", scope: "scope-one", request });
    expect(emergencyCommandReducer(state, { type: "run-place-changed" })).toBe(state);
    state = emergencyCommandReducer(state, { type: "run-loaded", scope: "scope-one", request, result });
    state = emergencyCommandReducer(state, { type: "run-place-changed" });
    expect(state.result).toBeNull();
    expect(state.runStatus).toBe("idle");
    expect(state.selectedCommandHandle).toBe("command-network");
  });

  it("groups visible commands into catalog-ordered branches", () => {
    expect(groupEmergencyCommands(catalog.commands).map((group) => group.category)).toEqual(["network", "system"]);
    expect(groupEmergencyCommands(filterEmergencyCommands(catalog.commands, "内核")))
      .toEqual([{ category: "system", commands: [catalog.commands[1]] }]);
    expect(groupEmergencyCommands([])).toEqual([]);
  });

  it("walks a group run in order and refuses steps from a stale or foreign run", () => {
    const run = { id: 5, snapshotHandle: "snapshot-one", category: "network" as const,
      commandHandles: ["command-network"] };
    let state = emergencyCommandReducer(loaded(), { type: "group-run-started", scope: "scope-one", run });
    expect(state.groupRun?.status).toBe("loading");

    // A category the handles do not belong to is refused outright.
    expect(emergencyCommandReducer(loaded(), { type: "group-run-started", scope: "scope-one",
      run: { ...run, category: "system" } }).groupRun).toBeNull();

    const entry = { commandHandle: "command-network", result, error: null, elapsedMs: 12 };
    expect(emergencyCommandReducer(state, { type: "group-run-progress", scope: "scope-one", runId: 99, entry }))
      .toBe(state);
    expect(emergencyCommandReducer(state, { type: "group-run-progress", scope: "scope-one", runId: 5,
      entry: { ...entry, commandHandle: "command-system" } })).toBe(state);
    state = emergencyCommandReducer(state, { type: "group-run-progress", scope: "scope-one", runId: 5, entry });
    expect(state.groupRun?.entries).toEqual([entry]);
    // The walk never runs past its planned length.
    expect(emergencyCommandReducer(state, { type: "group-run-progress", scope: "scope-one", runId: 5, entry }))
      .toBe(state);
    state = emergencyCommandReducer(state, { type: "group-run-finished", scope: "scope-one", runId: 5 });
    expect(state.groupRun?.status).toBe("ready");
  });

  it("holds selection and refresh during a group run, and drops results on target changes", () => {
    const run = { id: 5, snapshotHandle: "snapshot-one", category: "network" as const,
      commandHandles: ["command-network"] };
    const started = emergencyCommandReducer(loaded(), { type: "group-run-started", scope: "scope-one", run });
    expect(emergencyCommandReducer(started, { type: "command-selected", commandHandle: "command-system" })
      .groupRun).toEqual(started.groupRun);
    expect(emergencyCommandReducer(started, { type: "catalog-started", scope: "scope-one", request: 9 })
      .groupRun).toEqual(started.groupRun);
    expect(emergencyCommandReducer(started, { type: "scope-changed", scope: "scope-two" }).groupRun).toBeNull();

    // A single run and a group run can never overlap.
    const request = { id: 6, snapshotHandle: "snapshot-one", commandHandle: "command-network" };
    expect(emergencyCommandReducer(started, { type: "run-started", scope: "scope-one", request })).toBe(started);
    const single = emergencyCommandReducer(loaded(), { type: "run-started", scope: "scope-one", request });
    expect(emergencyCommandReducer(single, { type: "group-run-started", scope: "scope-one", run })).toBe(single);
  });

  it("stops scheduling after the active item while retaining its result and unfinished count", () => {
    const expanded = { ...catalog, commands: [...catalog.commands,
      { ...catalog.commands[0]!, commandHandle: "command-network-2" }] };
    let state = emergencyCommandReducer(loaded(), { type: "catalog-started", scope: "scope-one", request: 8 });
    state = emergencyCommandReducer(state, { type: "catalog-loaded", scope: "scope-one", request: 8, catalog: expanded });
    const run = { id: 9, snapshotHandle: "snapshot-one", category: "network" as const,
      commandHandles: ["command-network", "command-network-2"] };
    state = emergencyCommandReducer(state, { type: "group-run-started", scope: "scope-one", run });
    expect(emergencyCommandReducer(state, { type: "group-run-stop-requested", scope: "scope-two", runId: 9 })).toBe(state);
    state = emergencyCommandReducer(state, { type: "group-run-stop-requested", scope: "scope-one", runId: 9 });
    expect(state.groupRun?.status).toBe("stopping");
    expect(emergencyCommandReducer(state, { type: "command-selected", commandHandle: "command-system" })).toBe(state);
    const entry = { commandHandle: "command-network", result, error: null, elapsedMs: 12 };
    state = emergencyCommandReducer(state, { type: "group-run-progress", scope: "scope-one", runId: 9, entry });
    expect(emergencyCommandReducer(state, { type: "group-run-finished", scope: "scope-one", runId: 9 })).toBe(state);
    state = emergencyCommandReducer(state, { type: "group-run-finished", scope: "scope-one", runId: 9, stopped: true });
    expect(state.groupRun?.status).toBe("stopped");
    expect(state.groupRun?.entries).toEqual([entry]);
    expect(state.groupRun?.commandHandles).toHaveLength(2);
    expect(emergencyCommandReducer(state, { type: "group-run-progress", scope: "scope-one", runId: 9,
      entry: { ...entry, commandHandle: "command-network-2" } })).toBe(state);
  });
});
