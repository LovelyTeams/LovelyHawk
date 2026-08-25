import { describe, expect, it } from "vitest";

import type {
  BaselineCatalog,
  BaselineHistory,
  BaselineScan,
} from "../shared/baseline-read-contract";
import { baselineReadReducer, createBaselineReadState } from "./baseline-read-state";

const catalog: BaselineCatalog = {
  items: [{
    itemHandle: "item-a",
    category: "ssh",
    risk: "critical",
    valueKind: { kind: "choice", options: ["yes", "no"] },
    title: "关闭密码认证",
    description: "只读目录项",
    recommendation: "no",
  }],
  displayed: 1,
  truncated: false,
};

const scan: BaselineScan = {
  scanHandle: "scan-a",
  capturedAt: "2026-08-24T01:02:03Z",
  expiresInSeconds: 300,
  statuses: [{
    itemHandle: "item-a",
    observedKind: "value",
    observed: "yes",
    compliant: false,
    redacted: false,
    textTruncated: false,
  }],
  displayed: 1,
  compliantCount: 0,
  nonCompliantCount: 1,
  redactedFieldCount: 0,
  truncated: false,
};

const history: BaselineHistory = {
  historyHandle: "history-a",
  expiresInSeconds: 300,
  entries: [],
  displayed: 0,
  redactedFieldCount: 0,
  truncated: false,
};

function catalogLoaded() {
  let state = baselineReadReducer(createBaselineReadState(), { type: "catalog-started", request: 1 });
  state = baselineReadReducer(state, { type: "catalog-loaded", request: 1, catalog });
  return state;
}

describe("baseline read reducer", () => {
  it("rejects late catalog responses by exact request identity", () => {
    let state = baselineReadReducer(createBaselineReadState(), { type: "catalog-started", request: 1 });
    state = baselineReadReducer(state, { type: "catalog-started", request: 2 });
    state = baselineReadReducer(state, { type: "catalog-loaded", request: 1, catalog });
    expect(state.catalog).toBeNull();
    state = baselineReadReducer(state, { type: "catalog-loaded", request: 2, catalog });
    expect(state.catalog).toBe(catalog);
  });

  it("clears target data and rejects late scan when binding scope changes or disconnects", () => {
    let state = baselineReadReducer(catalogLoaded(), { type: "scope-changed", scope: "scope-a" });
    const request = { id: 2 };
    state = baselineReadReducer(state, { type: "scan-started", scope: "scope-a", request });
    state = baselineReadReducer(state, { type: "scope-changed", scope: "scope-b" });
    state = baselineReadReducer(state, { type: "scan-loaded", scope: "scope-a", request, scan });
    expect(state.scope).toBe("scope-b");
    expect(state.scan).toBeNull();
    state = baselineReadReducer(state, { type: "scope-changed", scope: null });
    expect(state.scanStatus).toBe("idle");
    expect(state.history).toBeNull();
  });

  it("clears target lanes on deactivation and rejects both late result types", () => {
    let state = baselineReadReducer(catalogLoaded(), { type: "scope-changed", scope: "binding-a" });
    const scanRequest = { id: 2 };
    state = baselineReadReducer(state, {
      type: "scan-started", scope: "binding-a", request: scanRequest,
    });
    state = baselineReadReducer(state, { type: "deactivated", scope: "binding-a" });
    state = baselineReadReducer(state, {
      type: "scan-loaded", scope: "binding-a", request: scanRequest, scan,
    });
    expect(state.scan).toBeNull();

    state = baselineReadReducer(state, { type: "tab-selected", tab: "history" });
    const historyRequest = { id: 3 };
    state = baselineReadReducer(state, {
      type: "history-started", scope: "binding-a", request: historyRequest,
    });
    state = baselineReadReducer(state, { type: "deactivated", scope: "binding-a" });
    state = baselineReadReducer(state, {
      type: "history-loaded", scope: "binding-a", request: historyRequest, history,
    });
    expect(state.history).toBeNull();
  });

  it("rejects a status whose opaque item is absent from the current catalog", () => {
    let state = baselineReadReducer(catalogLoaded(), { type: "scope-changed", scope: "scope-a" });
    const request = { id: 2 };
    state = baselineReadReducer(state, { type: "scan-started", scope: "scope-a", request });
    state = baselineReadReducer(state, {
      type: "scan-loaded",
      scope: "scope-a",
      request,
      scan: { ...scan, statuses: [{ ...scan.statuses[0]!, itemHandle: "unknown" }] },
    });
    expect(state.scan).toBeNull();
    state = baselineReadReducer(state, { type: "scan-loaded", scope: "scope-a", request, scan });
    expect(state.scan).toBe(scan);
  });

  it("cancels the inactive tab lane and rejects its late result", () => {
    let state = baselineReadReducer(catalogLoaded(), { type: "scope-changed", scope: "scope-a" });
    const scanRequest = { id: 2 };
    state = baselineReadReducer(state, { type: "scan-started", scope: "scope-a", request: scanRequest });
    state = baselineReadReducer(state, { type: "tab-selected", tab: "history" });
    state = baselineReadReducer(state, { type: "scan-loaded", scope: "scope-a", request: scanRequest, scan });
    expect(state.scan).toBeNull();

    const historyRequest = { id: 3 };
    state = baselineReadReducer(state, { type: "history-started", scope: "scope-a", request: historyRequest });
    state = baselineReadReducer(state, { type: "tab-selected", tab: "checks" });
    state = baselineReadReducer(state, {
      type: "history-loaded", scope: "scope-a", request: historyRequest, history,
    });
    expect(state.history).toBeNull();
  });

  it("catalog refresh invalidates scans but preserves local filters", () => {
    let state = baselineReadReducer(catalogLoaded(), { type: "scope-changed", scope: "scope-a" });
    state = baselineReadReducer(state, { type: "search-changed", value: "SSH" });
    state = baselineReadReducer(state, { type: "category-changed", value: "ssh" });
    state = baselineReadReducer(state, { type: "compliance-changed", value: "non-compliant" });
    state = baselineReadReducer(state, { type: "catalog-started", request: 3 });
    expect(state.scan).toBeNull();
    expect(state.search).toBe("SSH");
    expect(state.category).toBe("ssh");
    expect(state.compliance).toBe("non-compliant");
  });
});
