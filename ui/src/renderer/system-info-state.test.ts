import { describe, expect, it } from "vitest";

import type {
  SystemInfoSummary,
  SystemInfoTabCatalogEntry,
  SystemInfoTable,
} from "../shared/system-info-contract";
import { SYSTEM_INFO_CATALOG } from "../shared/system-info-contract";
import {
  createSystemInfoState,
  systemInfoReducer,
} from "./system-info-state";

const catalog: SystemInfoTabCatalogEntry[] = SYSTEM_INFO_CATALOG.map((entry) => ({
  ...entry,
  columns: [...entry.columns],
}));

const summary = {
  hostname: "server",
  loadAverage: ["0", "0", "0"],
} as unknown as SystemInfoSummary;

function table(tab: "processes" | "network", snapshotHandle: string): SystemInfoTable {
  const definition = catalog.find((entry) => entry.key === tab);
  if (definition === undefined) throw new Error("fixture tab missing");
  return {
    snapshotHandle,
    tab,
    columns: definition.columns,
    rows: [{
      id: `${tab}:1`,
      cells: definition.columns.map(() => "plain"),
      risk: "normal",
      detail: false,
    }],
    truncated: false,
    missingTool: null,
    failedTool: null,
  };
}

describe("system-info reducer", () => {
  it("drops bootstrap results from an older target scope", () => {
    let state = systemInfoReducer(createSystemInfoState(), {
      type: "bootstrap-started",
      scope: "new-target",
    });
    const next = systemInfoReducer(state, {
      type: "bootstrap-loaded",
      scope: "old-target",
      catalog,
      summary,
    });

    expect(next).toBe(state);
    expect(next.summary).toBeNull();
  });

  it("drops late table results after the selected tab changes", () => {
    let state = systemInfoReducer(createSystemInfoState(), {
      type: "bootstrap-started",
      scope: "scope-1",
    });
    state = systemInfoReducer(state, {
      type: "bootstrap-loaded",
      scope: "scope-1",
      catalog,
      summary,
    });
    expect(state.selectedTab).toBe("processes");
    state = systemInfoReducer(state, { type: "tab-selected", scope: "scope-1", tab: "network" });
    const late = systemInfoReducer(state, {
      type: "table-loaded",
      scope: "scope-1",
      tab: "processes",
      request: 1,
      table: table("processes", "old-snapshot"),
    });

    expect(late).toBe(state);
    expect(late.selectedTab).toBe("network");
    expect(late.table).toBeNull();
  });

  it("drops a slow collect that a newer collect of the same tab has replaced", () => {
    let state = systemInfoReducer(createSystemInfoState(), {
      type: "bootstrap-started",
      scope: "scope-1",
    });
    state = systemInfoReducer(state, {
      type: "bootstrap-loaded",
      scope: "scope-1",
      catalog,
      summary,
    });
    // Two collects of the same tab overlap: a refresh, or a tab left and come
    // back to. Matching the scope and the tab cannot tell them apart.
    state = systemInfoReducer(state, {
      type: "table-started", scope: "scope-1", tab: "processes", request: 1,
    });
    state = systemInfoReducer(state, {
      type: "table-started", scope: "scope-1", tab: "processes", request: 2,
    });
    const fresh = systemInfoReducer(state, {
      type: "table-loaded",
      scope: "scope-1",
      tab: "processes",
      request: 2,
      table: table("processes", "snapshot-new"),
    });
    expect(fresh.table?.snapshotHandle).toBe("snapshot-new");

    // The earlier request lands last. It must not put its older snapshot back:
    // every row id an open menu is addressing belongs to the newer one.
    const overtaken = systemInfoReducer(fresh, {
      type: "table-loaded",
      scope: "scope-1",
      tab: "processes",
      request: 1,
      table: table("processes", "snapshot-old"),
    });
    expect(overtaken).toBe(fresh);
    expect(overtaken.table?.snapshotHandle).toBe("snapshot-new");

    // A failure from the superseded request must not blank the fresh table.
    const staleFailure = systemInfoReducer(fresh, {
      type: "table-failed",
      scope: "scope-1",
      tab: "processes",
      request: 1,
      error: "无法读取当前系统信息标签。",
    });
    expect(staleFailure).toBe(fresh);
    expect(staleFailure.tableStatus).toBe("ready");
  });

  it("binds detail results to the current table snapshot and row", () => {
    let state = systemInfoReducer(createSystemInfoState(), {
      type: "bootstrap-started",
      scope: "scope-1",
    });
    state = systemInfoReducer(state, {
      type: "bootstrap-loaded",
      scope: "scope-1",
      catalog,
      summary,
    });
    const currentTable = table("processes", "snapshot-new");
    state = systemInfoReducer(state, {
      type: "table-started", scope: "scope-1", tab: "processes", request: 1,
    });
    state = systemInfoReducer(state, {
      type: "table-loaded",
      scope: "scope-1",
      tab: "processes",
      request: 1,
      table: currentTable,
    });
    state = systemInfoReducer(state, {
      type: "detail-started",
      scope: "scope-1",
      tab: "processes",
      snapshotHandle: "snapshot-new",
      rowId: "processes:1",
    });
    const late = systemInfoReducer(state, {
      type: "detail-loaded",
      scope: "scope-1",
      tab: "processes",
      snapshotHandle: "snapshot-old",
      rowId: "processes:1",
      detail: { tab: "processes", rowId: "processes:1", fields: [] },
    });

    expect(late).toBe(state);
    expect(late.detail?.status).toBe("loading");
  });
});
