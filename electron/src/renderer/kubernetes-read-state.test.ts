import { describe, expect, it } from "vitest";

import type {
  KubernetesSnapshot,
  KubernetesTextResult,
} from "../shared/kubernetes-read-contract";
import { kubernetesNamespaceKey } from "./kubernetes-read-helpers";
import {
  createKubernetesReadState,
  kubernetesReadReducer,
} from "./kubernetes-read-state";

const availability = {
  kubectlInstalled: true,
  apiReachable: true,
  currentContext: "production",
  contextTruncated: false,
};

function namespaceSnapshot(handle = "snapshot-namespaces"): KubernetesSnapshot {
  return {
    snapshotHandle: handle,
    tab: "namespaces",
    namespaceScoped: false,
    displayed: 1,
    truncated: false,
    expiresInSeconds: 300,
    rows: [{
      kind: "namespace",
      rowHandle: "namespace-production",
      name: "production",
      phase: "Active",
      createdAt: "now",
      textTruncated: false,
    }],
  };
}

function podSnapshot(handle = "snapshot-pods", includeSecond = true): KubernetesSnapshot {
  const rows: KubernetesSnapshot["rows"] = [{
    kind: "pod",
    rowHandle: "pod-a",
    namespace: "production",
    name: "api",
    phase: "Running",
    readyContainers: 1,
    totalContainers: 1,
    restarts: 0,
    node: "node-a",
    podIp: "10.0.0.1",
    images: ["api:1"],
    createdAt: "now",
    supportsLogs: true,
    textTruncated: false,
  }];
  if (includeSecond) rows.push({
    kind: "pod",
    rowHandle: "pod-b",
    namespace: "production",
    name: "worker",
    phase: "Pending",
    readyContainers: 0,
    totalContainers: 1,
    restarts: 1,
    node: "node-b",
    podIp: "",
    images: ["worker:1"],
    createdAt: "now",
    supportsLogs: true,
    textTruncated: false,
  });
  return {
    snapshotHandle: handle,
    tab: "pods",
    namespaceScoped: false,
    displayed: rows.length,
    truncated: false,
    expiresInSeconds: 300,
    rows,
  };
}

function availableState(scope = "scope-new") {
  let state = createKubernetesReadState(scope);
  state = kubernetesReadReducer(state, {
    type: "availability-started",
    scope,
    request: 1,
  });
  return kubernetesReadReducer(state, {
    type: "availability-loaded",
    scope,
    request: 1,
    availability,
  });
}

function loadedPods(scope = "scope-new") {
  let state = availableState(scope);
  state = kubernetesReadReducer(state, {
    type: "list-started",
    scope,
    request: 2,
    tab: "pods",
    context: "all",
  });
  return kubernetesReadReducer(state, {
    type: "list-loaded",
    scope,
    request: 2,
    tab: "pods",
    context: "all",
    snapshot: podSnapshot(),
  });
}

describe("Kubernetes read reducer", () => {
  it("defaults to Pods and rejects a list arriving from an old target", () => {
    let state = availableState();
    expect(state.activeTab).toBe("pods");
    state = kubernetesReadReducer(state, {
      type: "list-started",
      scope: "scope-new",
      request: 2,
      tab: "pods",
      context: "all",
    });
    state = kubernetesReadReducer(state, { type: "scope-changed", scope: "scope-next" });
    const late = kubernetesReadReducer(state, {
      type: "list-loaded",
      scope: "scope-new",
      request: 2,
      tab: "pods",
      context: "all",
      snapshot: podSnapshot(),
    });
    expect(late).toBe(state);
    expect(late.snapshot).toBeNull();
  });

  it("retains a stable row handle across refresh and rejects old detail after selection changes", () => {
    let state = loadedPods();
    state = kubernetesReadReducer(state, {
      type: "row-selected",
      scope: "scope-new",
      snapshotHandle: "snapshot-pods",
      rowHandle: "pod-a",
    });
    state = kubernetesReadReducer(state, {
      type: "list-started",
      scope: "scope-new",
      request: 3,
      tab: "pods",
      context: "all",
    });
    state = kubernetesReadReducer(state, {
      type: "list-loaded",
      scope: "scope-new",
      request: 3,
      tab: "pods",
      context: "all",
      snapshot: podSnapshot("snapshot-pods-next"),
    });
    expect(state.selectedRowHandle).toBe("pod-a");

    state = kubernetesReadReducer(state, {
      type: "detail-started",
      scope: "scope-new",
      request: 4,
      snapshotHandle: "snapshot-pods-next",
      rowHandle: "pod-a",
    });
    state = kubernetesReadReducer(state, {
      type: "row-selected",
      scope: "scope-new",
      snapshotHandle: "snapshot-pods-next",
      rowHandle: "pod-b",
    });
    const lateDetail: KubernetesTextResult = {
      snapshotHandle: "snapshot-pods-next",
      rowHandle: "pod-a",
      contentKind: "detail",
      text: "late",
      truncated: false,
    };
    const late = kubernetesReadReducer(state, {
      type: "detail-loaded",
      scope: "scope-new",
      request: 4,
      snapshotHandle: "snapshot-pods-next",
      rowHandle: "pod-a",
      detail: lateDetail,
    });
    expect(late).toBe(state);
    expect(late.detail).toBeNull();
  });

  it("derives namespace scope only from its snapshot and invalidates it on refresh", () => {
    let state = availableState();
    state = kubernetesReadReducer(state, {
      type: "namespaces-started",
      scope: "scope-new",
      request: 2,
    });
    state = kubernetesReadReducer(state, {
      type: "namespaces-loaded",
      scope: "scope-new",
      request: 2,
      snapshot: namespaceSnapshot(),
    });
    state = kubernetesReadReducer(state, {
      type: "namespace-selected",
      scope: "scope-new",
      capability: {
        snapshotHandle: "snapshot-namespaces",
        rowHandle: "namespace-production",
      },
    });
    const context = kubernetesNamespaceKey(state.selectedNamespace);
    state = kubernetesReadReducer(state, {
      type: "list-started",
      scope: "scope-new",
      request: 3,
      tab: "pods",
      context,
    });
    state = kubernetesReadReducer(state, {
      type: "list-loaded",
      scope: "scope-new",
      request: 3,
      tab: "pods",
      context,
      snapshot: { ...podSnapshot(), namespaceScoped: true },
    });

    state = kubernetesReadReducer(state, {
      type: "namespaces-started",
      scope: "scope-new",
      request: 4,
    });
    state = kubernetesReadReducer(state, {
      type: "namespaces-loaded",
      scope: "scope-new",
      request: 4,
      snapshot: namespaceSnapshot("snapshot-namespaces-next"),
    });
    expect(state.selectedNamespace).toEqual({
      snapshotHandle: "snapshot-namespaces-next",
      rowHandle: "namespace-production",
    });
    expect(state.listStatus).toBe("idle");
    expect(state.snapshot).toBeNull();
  });

  it("rejects a namespace capability not issued by the current namespace snapshot", () => {
    let state = availableState();
    state = kubernetesReadReducer(state, {
      type: "namespaces-started",
      scope: "scope-new",
      request: 2,
    });
    state = kubernetesReadReducer(state, {
      type: "namespaces-loaded",
      scope: "scope-new",
      request: 2,
      snapshot: namespaceSnapshot(),
    });
    const rejected = kubernetesReadReducer(state, {
      type: "namespace-selected",
      scope: "scope-new",
      capability: { snapshotHandle: "attacker", rowHandle: "namespace-production" },
    });
    expect(rejected).toBe(state);
    expect(rejected.selectedNamespace).toBeNull();
  });

  it("clears stale namespace detail while retaining only a row present after refresh", () => {
    let state = availableState();
    state = kubernetesReadReducer(state, {
      type: "namespaces-started",
      scope: "scope-new",
      request: 2,
    });
    state = kubernetesReadReducer(state, {
      type: "namespaces-loaded",
      scope: "scope-new",
      request: 2,
      snapshot: namespaceSnapshot(),
    });
    state = kubernetesReadReducer(state, {
      type: "tab-selected",
      scope: "scope-new",
      tab: "namespaces",
    });
    state = kubernetesReadReducer(state, {
      type: "row-selected",
      scope: "scope-new",
      snapshotHandle: "snapshot-namespaces",
      rowHandle: "namespace-production",
    });
    state = {
      ...state,
      detailStatus: "ready",
      detail: {
        snapshotHandle: "snapshot-namespaces",
        rowHandle: "namespace-production",
        contentKind: "detail",
        text: "old detail",
        truncated: false,
      },
    };
    state = kubernetesReadReducer(state, {
      type: "namespaces-started",
      scope: "scope-new",
      request: 3,
    });
    state = kubernetesReadReducer(state, {
      type: "namespaces-loaded",
      scope: "scope-new",
      request: 3,
      snapshot: namespaceSnapshot("snapshot-namespaces-next"),
    });
    expect(state.selectedRowHandle).toBe("namespace-production");
    expect(state.detailStatus).toBe("idle");
    expect(state.detail).toBeNull();
  });

  it("clears stale snapshots if API availability is lost and byte-bounds search", () => {
    let state = loadedPods();
    state = kubernetesReadReducer(state, { type: "query-changed", query: "界".repeat(100) });
    expect(new TextEncoder().encode(state.query).byteLength).toBeLessThanOrEqual(256);
    state = kubernetesReadReducer(state, {
      type: "availability-started",
      scope: "scope-new",
      request: 9,
    });
    state = kubernetesReadReducer(state, {
      type: "availability-loaded",
      scope: "scope-new",
      request: 9,
      availability: {
        kubectlInstalled: true,
        apiReachable: false,
        currentContext: "production",
        contextTruncated: false,
      },
    });
    expect(state.snapshot).toBeNull();
    expect(state.selectedRowHandle).toBeNull();
    expect(state.notice).toContain("API 不可达");
  });
});
