import { describe, expect, it } from "vitest";

import type {
  MiddlewareConfiguration,
  MiddlewareDiscovery,
  MiddlewareHistory,
} from "../shared/middleware-read-contract";
import { createMiddlewareReadState, middlewareReadReducer } from "./middleware-read-state";

const discovery: MiddlewareDiscovery = {
  discoveryHandle: "discovery-a",
  expiresInSeconds: 300,
  instances: [{
    instanceHandle: "instance-a",
    title: "Nginx 实例 1",
    product: "nginx",
    version: "1.28",
    status: "active",
    statusText: "active / running",
    active: true,
    redacted: false,
    textTruncated: false,
  }],
  discoveredCount: 1,
  displayed: 1,
  redactedFieldCount: 0,
  truncated: false,
};

const configuration: MiddlewareConfiguration = {
  discoveryHandle: "discovery-a",
  instanceHandle: "instance-a",
  product: "nginx",
  loadedAt: "2026-08-24T01:02:03Z",
  totalBytes: "0",
  fileCount: 0,
  unresolvedIncludeCount: 0,
  directoryManifestCount: 0,
  files: [],
  displayed: 0,
  displayedNodes: 0,
  redactedFieldCount: 0,
  truncated: false,
};

const history: MiddlewareHistory = {
  historyHandle: "history-a",
  expiresInSeconds: 300,
  entries: [],
  recordCount: 0,
  displayed: 0,
  truncated: false,
};

function scoped() {
  return middlewareReadReducer(createMiddlewareReadState(), { type: "scope-changed", scope: "scope-a" });
}

function discovered() {
  let state = scoped();
  state = middlewareReadReducer(state, { type: "discovery-started", scope: "scope-a", request: { id: 1 } });
  return middlewareReadReducer(state, {
    type: "discovery-loaded", scope: "scope-a", request: { id: 1 }, discovery,
  });
}

describe("middleware read reducer", () => {
  it("accepts only the current discovery request and selects its first opaque instance", () => {
    let state = scoped();
    state = middlewareReadReducer(state, { type: "discovery-started", scope: "scope-a", request: { id: 1 } });
    state = middlewareReadReducer(state, { type: "discovery-started", scope: "scope-a", request: { id: 2 } });
    state = middlewareReadReducer(state, {
      type: "discovery-loaded", scope: "scope-a", request: { id: 1 }, discovery,
    });
    expect(state.discovery).toBeNull();
    state = middlewareReadReducer(state, {
      type: "discovery-loaded", scope: "scope-a", request: { id: 2 }, discovery,
    });
    expect(state.selectedInstanceHandle).toBe("instance-a");
  });

  it("clears target data and rejects late configuration after target change or disconnect", () => {
    let state = discovered();
    const request = { id: 2 };
    state = middlewareReadReducer(state, { type: "configuration-started", scope: "scope-a", request });
    state = middlewareReadReducer(state, { type: "scope-changed", scope: "scope-b" });
    state = middlewareReadReducer(state, {
      type: "configuration-loaded", scope: "scope-a", request, configuration,
    });
    expect(state.configuration).toBeNull();
    expect(state.discovery).toBeNull();
    state = middlewareReadReducer(state, { type: "scope-changed", scope: null });
    expect(state.history).toBeNull();
  });

  it("rejects configuration that does not match the active discovery and instance handles", () => {
    let state = discovered();
    const request = { id: 2 };
    state = middlewareReadReducer(state, { type: "configuration-started", scope: "scope-a", request });
    state = middlewareReadReducer(state, {
      type: "configuration-loaded",
      scope: "scope-a",
      request,
      configuration: { ...configuration, instanceHandle: "instance-other" },
    });
    expect(state.configuration).toBeNull();
    state = middlewareReadReducer(state, {
      type: "configuration-loaded", scope: "scope-a", request, configuration,
    });
    expect(state.configuration).toBe(configuration);
  });

  it("discovery refresh invalidates configuration while preserving local filters", () => {
    let state = discovered();
    state = middlewareReadReducer(state, { type: "search-changed", value: "Nginx" });
    state = middlewareReadReducer(state, { type: "product-changed", value: "nginx" });
    state = middlewareReadReducer(state, { type: "status-changed", value: "active" });
    state = middlewareReadReducer(state, { type: "discovery-started", scope: "scope-a", request: { id: 3 } });
    expect(state.discovery).toBeNull();
    expect(state.configuration).toBeNull();
    expect(state.selectedInstanceHandle).toBeNull();
    expect(state.search).toBe("Nginx");
    expect(state.product).toBe("nginx");
    expect(state.status).toBe("active");
  });

  it("cancels inactive tab lanes and rejects their late results", () => {
    let state = discovered();
    const configRequest = { id: 2 };
    state = middlewareReadReducer(state, {
      type: "configuration-started", scope: "scope-a", request: configRequest,
    });
    state = middlewareReadReducer(state, { type: "tab-selected", tab: "history" });
    state = middlewareReadReducer(state, {
      type: "configuration-loaded", scope: "scope-a", request: configRequest, configuration,
    });
    expect(state.configuration).toBeNull();
    const historyRequest = { id: 3 };
    state = middlewareReadReducer(state, { type: "history-started", scope: "scope-a", request: historyRequest });
    state = middlewareReadReducer(state, { type: "tab-selected", tab: "instances" });
    state = middlewareReadReducer(state, {
      type: "history-loaded", scope: "scope-a", request: historyRequest, history,
    });
    expect(state.history).toBeNull();
  });
});
