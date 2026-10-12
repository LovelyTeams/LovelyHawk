import { describe, expect, it } from "vitest";

import type {
  CheckAuditCatalog,
  CheckAuditLogResult,
  CheckAuditStatus,
} from "../shared/check-audit-read-contract";
import {
  buildCheckAuditLogInput,
  checkAuditScope,
  filterCheckAuditCommands,
  normalizeCustomAuditCommand,
} from "./check-audit-read-helpers";
import { checkAuditReadReducer, createCheckAuditReadState } from "./check-audit-read-state";

const catalog: CheckAuditCatalog = {
  snapshotHandle: "snapshot-a",
  expiresInSeconds: 300,
  commands: [{ commandHandle: "command-cat", name: "cat", isDefault: true, critical: true }, {
    commandHandle: "command-grep", name: "grep", isDefault: true, critical: false,
  }, {
    commandHandle: "command-openssl", name: "openssl", isDefault: false, critical: false,
  }],
  customCount: 1,
};

const status: CheckAuditStatus = {
  snapshotHandle: "snapshot-a",
  isRoot: false,
  commands: catalog.commands.map((command) => ({
    commandHandle: command.commandHandle,
    name: command.name,
    state: "original",
    critical: command.critical,
    displayLocation: `/usr/bin/${command.name}`,
    locationRedacted: false,
    textTruncated: false,
  })),
  redactedFieldCount: 0,
  truncated: false,
};

const log: CheckAuditLogResult = {
  snapshotHandle: "snapshot-a",
  limit: 200,
  logState: "read",
  malformedCount: 0,
  fetchedCount: 0,
  matchedCount: 0,
  displayedCount: 0,
  suspiciousCount: 0,
  matchedSuspiciousCount: 0,
  entries: [],
  commandCounts: [],
  cycles: [],
  suggestions: [],
  redactedFieldCount: 0,
  truncated: false,
};

function loadedState() {
  let state = checkAuditReadReducer(createCheckAuditReadState(), { type: "scope-changed", scope: "scope-a" });
  state = checkAuditReadReducer(state, { type: "catalog-started", scope: "scope-a", request: 1 });
  return checkAuditReadReducer(state, { type: "catalog-loaded", scope: "scope-a", request: 1, catalog });
}

describe("check audit read reducer", () => {
  it("rejects a late catalog after exact target scope changes", () => {
    let state = checkAuditReadReducer(createCheckAuditReadState(), { type: "scope-changed", scope: "scope-a" });
    state = checkAuditReadReducer(state, { type: "catalog-started", scope: "scope-a", request: 1 });
    state = checkAuditReadReducer(state, { type: "scope-changed", scope: "scope-b" });
    state = checkAuditReadReducer(state, { type: "catalog-loaded", scope: "scope-a", request: 1, catalog });
    expect(state.scope).toBe("scope-b");
    expect(state.catalog).toBeNull();
  });

  it("preserves command selection by safe name across catalog handle refresh", () => {
    let state = loadedState();
    state = checkAuditReadReducer(state, { type: "command-selected", name: "openssl" });
    state = checkAuditReadReducer(state, { type: "catalog-started", scope: "scope-a", request: 2 });
    const refreshed = {
      ...catalog,
      snapshotHandle: "snapshot-b",
      commands: catalog.commands.map((command) => ({ ...command, commandHandle: `${command.commandHandle}-new` })),
    };
    state = checkAuditReadReducer(state, {
      type: "catalog-loaded", scope: "scope-a", request: 2, catalog: refreshed,
    });
    expect(state.selectedCommandName).toBe("openssl");
    expect(state.catalog?.snapshotHandle).toBe("snapshot-b");
  });

  it("accepts status only when every handle and name matches the active catalog", () => {
    let state = loadedState();
    const request = { id: 2, snapshotHandle: "snapshot-a" };
    state = checkAuditReadReducer(state, { type: "status-started", scope: "scope-a", request });
    state = checkAuditReadReducer(state, {
      type: "status-loaded",
      scope: "scope-a",
      request,
      status: { ...status, commands: status.commands.map((command, index) => index === 0 ? {
        ...command, commandHandle: "wrong-handle",
      } : command) },
    });
    expect(state.status).toBeNull();
    state = checkAuditReadReducer(state, { type: "status-loaded", scope: "scope-a", request, status });
    expect(state.status).toBe(status);
  });

  it("cancels command-lane work when switching to a log-derived tab", () => {
    let state = loadedState();
    const request = { id: 2, snapshotHandle: "snapshot-a" };
    state = checkAuditReadReducer(state, { type: "status-started", scope: "scope-a", request });
    state = checkAuditReadReducer(state, { type: "tab-selected", tab: "analysis" });
    expect(state.statusStatus).toBe("idle");
    expect(state.statusRequest).toBeNull();
    state = checkAuditReadReducer(state, { type: "status-loaded", scope: "scope-a", request, status });
    expect(state.status).toBeNull();
  });

  it("binds logs to snapshot, applied query and request across all three derived tabs", () => {
    let state = loadedState();
    state = checkAuditReadReducer(state, { type: "tab-selected", tab: "logs" });
    const request = { id: 2, snapshotHandle: "snapshot-a", input: { limit: 200, search: null } };
    state = checkAuditReadReducer(state, { type: "log-started", scope: "scope-a", request });
    state = checkAuditReadReducer(state, { type: "tab-selected", tab: "suggestions" });
    state = checkAuditReadReducer(state, { type: "log-loaded", scope: "scope-a", request, result: log });
    expect(state.log).toBe(log);
    state = checkAuditReadReducer(state, {
      type: "log-input-applied", input: { limit: 100, search: "cat" },
    });
    state = checkAuditReadReducer(state, { type: "log-loaded", scope: "scope-a", request, result: log });
    expect(state.log).toBeNull();
  });

  it("catalog refresh invalidates every pending status and log result", () => {
    const statusRequest = { id: 2, snapshotHandle: "snapshot-a" };
    let statusState = checkAuditReadReducer(loadedState(), {
      type: "status-started", scope: "scope-a", request: statusRequest,
    });
    statusState = checkAuditReadReducer(statusState, {
      type: "catalog-started", scope: "scope-a", request: 3,
    });
    expect(statusState.catalog).toBeNull();
    expect(statusState.statusRequest).toBeNull();
    statusState = checkAuditReadReducer(statusState, {
      type: "status-loaded", scope: "scope-a", request: statusRequest, status,
    });
    expect(statusState.status).toBeNull();

    let logState = checkAuditReadReducer(loadedState(), { type: "tab-selected", tab: "logs" });
    const logRequest = { id: 2, snapshotHandle: "snapshot-a", input: { limit: 200, search: null } };
    logState = checkAuditReadReducer(logState, {
      type: "log-started", scope: "scope-a", request: logRequest,
    });
    logState = checkAuditReadReducer(logState, {
      type: "catalog-started", scope: "scope-a", request: 3,
    });
    expect(logState.catalog).toBeNull();
    expect(logState.logRequest).toBeNull();
    logState = checkAuditReadReducer(logState, {
      type: "log-loaded", scope: "scope-a", request: logRequest, result: log,
    });
    expect(logState.log).toBeNull();
  });

  it("ignores superseded requests and late failures after lifecycle invalidation", () => {
    let catalogState = checkAuditReadReducer(createCheckAuditReadState(), {
      type: "scope-changed", scope: "scope-a",
    });
    catalogState = checkAuditReadReducer(catalogState, {
      type: "catalog-started", scope: "scope-a", request: 1,
    });
    catalogState = checkAuditReadReducer(catalogState, {
      type: "catalog-started", scope: "scope-a", request: 2,
    });
    catalogState = checkAuditReadReducer(catalogState, {
      type: "catalog-failed", scope: "scope-a", request: 1, error: "late catalog error",
    });
    expect(catalogState.catalogRequest).toBe(2);
    expect(catalogState.catalogError).toBeNull();

    const statusRequest = { id: 3, snapshotHandle: "snapshot-a" };
    let statusState = checkAuditReadReducer(loadedState(), {
      type: "status-started", scope: "scope-a", request: statusRequest,
    });
    statusState = checkAuditReadReducer(statusState, { type: "scope-changed", scope: "scope-b" });
    statusState = checkAuditReadReducer(statusState, {
      type: "status-failed", scope: "scope-a", request: statusRequest, error: "late status error",
    });
    expect(statusState.scope).toBe("scope-b");
    expect(statusState.statusError).toBeNull();

    const logRequest = { id: 4, snapshotHandle: "snapshot-a", input: { limit: 200, search: null } };
    let logState = checkAuditReadReducer(loadedState(), { type: "tab-selected", tab: "analysis" });
    logState = checkAuditReadReducer(logState, {
      type: "log-started", scope: "scope-a", request: logRequest,
    });
    logState = checkAuditReadReducer(logState, { type: "tab-selected", tab: "commands" });
    logState = checkAuditReadReducer(logState, {
      type: "log-failed", scope: "scope-a", request: logRequest, error: "late log error",
    });
    expect(logState.logStatus).toBe("idle");
    expect(logState.logError).toBeNull();
  });
});

describe("check audit helpers", () => {
  it("normalizes only custom command names accepted by the closed core grammar", () => {
    expect(normalizeCustomAuditCommand(" openssl ", [])).toEqual({ name: "openssl", error: null });
    expect(normalizeCustomAuditCommand("cat", []).name).toBeNull();
    expect(normalizeCustomAuditCommand("cat;id", []).name).toBeNull();
    expect(normalizeCustomAuditCommand("openssl", ["openssl"]).name).toBeNull();
  });

  it("builds closed log queries and filters hostile names only as text", () => {
    expect(buildCheckAuditLogInput(100, " hostile ")).toEqual({
      input: { limit: 100, search: "hostile" }, error: null,
    });
    expect(buildCheckAuditLogInput(10, "").input).toBeNull();
    expect(filterCheckAuditCommands([
      ...catalog.commands,
      { commandHandle: "hostile", name: "script-tool", isDefault: false, critical: false },
    ], "script").map((command) => command.name)).toEqual(["script-tool"]);
  });

  it("keys lifecycle scope only by the opaque SSH binding handle", () => {
    expect(checkAuditScope("binding-a")).toBe("binding:binding-a");
    expect(checkAuditScope("binding-a")).not.toBe(checkAuditScope("binding-b"));
  });
});
