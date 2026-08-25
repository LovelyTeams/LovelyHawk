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
  expiresInSeconds: 300,
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

  it("rejects late execution after selection, refresh or target switch", () => {
    const request = { id: 2, snapshotHandle: "snapshot-one", commandHandle: "command-network" };
    let state = emergencyCommandReducer(loaded(), { type: "run-started", scope: "scope-one", request });
    state = emergencyCommandReducer(state, { type: "command-selected", commandHandle: "command-system" });
    state = emergencyCommandReducer(state, { type: "run-loaded", scope: "scope-one", request, result });
    expect(state.result).toBeNull();

    state = emergencyCommandReducer(loaded(), { type: "run-started", scope: "scope-one", request });
    state = emergencyCommandReducer(state, { type: "catalog-started", scope: "scope-one", request: 3 });
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

  it("drops a group run when the target, catalog or selection changes", () => {
    const run = { id: 5, snapshotHandle: "snapshot-one", category: "network" as const,
      commandHandles: ["command-network"] };
    const started = emergencyCommandReducer(loaded(), { type: "group-run-started", scope: "scope-one", run });
    expect(emergencyCommandReducer(started, { type: "command-selected", commandHandle: "command-system" })
      .groupRun).toBeNull();
    expect(emergencyCommandReducer(started, { type: "catalog-started", scope: "scope-one", request: 9 })
      .groupRun).toBeNull();
    expect(emergencyCommandReducer(started, { type: "scope-changed", scope: "scope-two" }).groupRun).toBeNull();

    // A single run and a group run can never overlap.
    const request = { id: 6, snapshotHandle: "snapshot-one", commandHandle: "command-network" };
    expect(emergencyCommandReducer(started, { type: "run-started", scope: "scope-one", request })).toBe(started);
    const single = emergencyCommandReducer(loaded(), { type: "run-started", scope: "scope-one", request });
    expect(emergencyCommandReducer(single, { type: "group-run-started", scope: "scope-one", run })).toBe(single);
  });
});
