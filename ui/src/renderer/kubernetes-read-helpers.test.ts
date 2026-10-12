import { describe, expect, it } from "vitest";

import type { KubernetesDeploymentRow, KubernetesPodRow, KubernetesSnapshot } from "../shared/kubernetes-read-contract";
import {
  KUBERNETES_ROW_WINDOW,
  boundKubernetesQuery,
  filteredKubernetesRows,
  kubernetesListContext,
  kubernetesNamespaceCapability,
  kubernetesColumns,
  kubernetesReadScope,
  kubernetesRowAge,
  kubernetesRowNeedsAttention,
  kubernetesRowRestarted,
  kubernetesRowState,
  kubernetesStatCards,
  windowedKubernetesRows,
} from "./kubernetes-read-helpers";

const snapshot: KubernetesSnapshot = {
  snapshotHandle: "snapshot-1",
  tab: "pods",
  namespaceScoped: false,
  displayed: 2,
  truncated: false,
  expiresInSeconds: 300,
  rows: [
    {
      kind: "pod",
      rowHandle: "row-b",
      namespace: "zeta",
      name: "</button><script>bad()</script>",
      phase: "Pending",
      readyContainers: 0,
      totalContainers: 1,
      restarts: 0,
      node: "node-b",
      podIp: "",
      images: ["app:b"],
      createdAt: "now",
      supportsLogs: true,
      containers: [{ name: "app", image: "registry.example/app:1", ready: true, running: true, restarts: 0 }],
      defaultContainer: "app",
      textTruncated: false,
    },
    {
      kind: "pod",
      rowHandle: "row-a",
      namespace: "alpha",
      name: "api",
      phase: "Running",
      readyContainers: 1,
      totalContainers: 1,
      restarts: 0,
      node: "node-a",
      podIp: "10.0.0.1",
      images: ["app:a"],
      createdAt: "now",
      supportsLogs: true,
      containers: [{ name: "app", image: "registry.example/app:1", ready: true, running: true, restarts: 0 }],
      defaultContainer: "app",
      textTruncated: false,
    },
  ],
};

describe("Kubernetes read helpers", () => {
  it("scopes renderer lifecycle only by the opaque binding handle", () => {
    expect(kubernetesReadScope("binding-1")).toBe("binding-1");
    expect(kubernetesReadScope("binding-1")).not.toBe(kubernetesReadScope("binding-2"));
  });

  it("bounds search by UTF-8 bytes without splitting a scalar", () => {
    expect(boundKubernetesQuery("界".repeat(100))).toBe("界".repeat(85));
    expect(new TextEncoder().encode(boundKubernetesQuery("a".repeat(400))).byteLength).toBe(256);
  });

  it("filters hostile plain text and sorts a copy without mutating the snapshot", () => {
    const original = snapshot.rows.map((row) => row.rowHandle);
    expect(filteredKubernetesRows(snapshot, "SCRIPT")).toHaveLength(1);
    expect(filteredKubernetesRows(snapshot, "node-a")[0]?.name).toBe("api");
    expect(filteredKubernetesRows(snapshot, "").map((row) => row.rowHandle))
      .toEqual(["row-a", "row-b"]);
    expect(snapshot.rows.map((row) => row.rowHandle)).toEqual(original);
  });

  it("creates namespace scope only from a namespace snapshot row", () => {
    expect(kubernetesNamespaceCapability(snapshot, "row-a")).toBeNull();
    const namespaces: KubernetesSnapshot = {
      ...snapshot,
      tab: "namespaces",
      displayed: 1,
      rows: [{
        kind: "namespace",
        rowHandle: "namespace-row",
        name: "production",
        phase: "Active",
        createdAt: "now",
        textTruncated: false,
      }],
    };
    expect(kubernetesNamespaceCapability(namespaces, "namespace-row")).toEqual({
      snapshotHandle: "snapshot-1",
      rowHandle: "namespace-row",
    });
    expect(kubernetesNamespaceCapability(namespaces, "missing")).toBeNull();
    const capability = { snapshotHandle: "snapshot-1", rowHandle: "namespace-row" };
    expect(kubernetesListContext("pods", capability)).toContain("namespace-row");
    expect(kubernetesListContext("nodes", capability)).toBe("all");
    expect(kubernetesListContext("namespaces", capability)).toBe("all");
  });

  it("windows results to sixty rows", () => {
    const rows = Array.from({ length: KUBERNETES_ROW_WINDOW + 5 }, (_, index) => ({
      ...snapshot.rows[1]!,
      rowHandle: `row-${index}`,
    }));
    expect(windowedKubernetesRows(rows, 0)).toHaveLength(60);
    expect(windowedKubernetesRows(rows, 1)).toHaveLength(5);
    expect(windowedKubernetesRows(rows, -10)[0]?.rowHandle).toBe("row-0");
  });
});

/**
 * The page's first question is "what is broken", not "what is running".
 *
 * A cluster with two hundred pods puts the three that matter somewhere in the
 * middle of the list, and scrolling for them is how they get missed.
 */
describe("what needs attention", () => {
  const deployment: KubernetesDeploymentRow = {
    kind: "deployment", rowHandle: "deployment", namespace: "default", name: "service",
    desiredReplicas: 3, readyReplicas: 3, availableReplicas: 3, updatedReplicas: 3,
    images: ["app:1"], createdAt: "now", textTruncated: false,
  };

  it("keeps incomplete updates and availability visible even when readiness matches", () => {
    expect(kubernetesRowNeedsAttention(deployment)).toBe(false);
    expect(kubernetesRowState(deployment).tone).toBe("up");
    for (const row of [{ ...deployment, availableReplicas: 2 }, { ...deployment, updatedReplicas: 2 },
      { ...deployment, readyReplicas: 4 }]) {
      expect(kubernetesRowNeedsAttention(row)).toBe(true);
      expect(kubernetesRowState(row).tone).not.toBe("up");
    }
  });

  it("describes zero desired replicas without claiming either a failure or application health", () => {
    const stopped = { ...deployment, desiredReplicas: 0, readyReplicas: 0, availableReplicas: 0, updatedReplicas: 0 };
    expect(kubernetesRowState(stopped)).toEqual({ label: "已设为 0 副本", tone: "other" });
    expect(kubernetesRowNeedsAttention(stopped)).toBe(true);
  });

  it("does not describe a cordoned node as isolated", () => {
    expect(kubernetesRowState({
      kind: "node", rowHandle: "node", name: "node-one", ready: true, unschedulable: true,
      roles: [], kubeletVersion: "1.31.4", internalIp: "", cpuCapacity: "2", memoryCapacity: "2Gi",
      podCapacity: "100", createdAt: "now", textTruncated: false,
    })).toEqual({ label: "已暂停调度", tone: "other" });
  });

  const pod = (over: Partial<KubernetesPodRow>): KubernetesPodRow => ({
    kind: "pod",
    rowHandle: "r",
    namespace: "default",
    name: "app",
    phase: "Running",
    readyContainers: 1,
    totalContainers: 1,
    restarts: 0,
    node: "node-a",
    podIp: "10.0.0.1",
    images: ["app:1"],
    createdAt: "2026-08-28T00:00:00Z",
    supportsLogs: true,
    containers: [{ name: "app", image: "registry.example/app:1", ready: true, running: true, restarts: 0 }],
    defaultContainer: "app",
    textTruncated: false,
    ...over,
  });

  it("counts a pod that is up but not whole", () => {
    expect(kubernetesRowNeedsAttention(pod({}))).toBe(false);
    // Running, but one of its containers is not ready. The phase alone says
    // this pod is fine; it is not.
    expect(kubernetesRowNeedsAttention(pod({ readyContainers: 1, totalContainers: 2 }))).toBe(true);
    // Running and ready but restarted: marked apart, not counted as broken —
    // one node reboot restarts every pod, and a list of nothing but red rows
    // tells the operator nothing.
    expect(kubernetesRowNeedsAttention(pod({ restarts: 4 }))).toBe(false);
    expect(kubernetesRowRestarted(pod({ restarts: 4 }))).toBe(true);
    expect(kubernetesRowRestarted(pod({}))).toBe(false);
    // A broken pod is "要看的" whatever its restarts, never merely "restarted".
    expect(kubernetesRowRestarted(pod({ phase: "CrashLoopBackOff", restarts: 72 }))).toBe(false);
    // And the obvious ones.
    expect(kubernetesRowNeedsAttention(pod({ phase: "CrashLoopBackOff" }))).toBe(true);
    expect(kubernetesRowNeedsAttention(pod({ phase: "ImagePullBackOff" }))).toBe(true);
  });

  it("never invents a count for a tab nobody opened", () => {
    // A tab with nothing loaded behind it has no number. Showing `0` there
    // would say "there are no nodes" when the truth is "nobody looked".
    const cards = kubernetesStatCards({ pods: [pod({}), pod({ restarts: 2 }), pod({ phase: "CrashLoopBackOff" })] });
    const byId = new Map(cards.map((card) => [card.id, card]));
    expect(byId.get("pods")?.value).toBe("3");
    expect(byId.get("healthy")?.value).toBe("2");
    expect(byId.get("healthy")?.detail).toBe("就绪运行，其中 1 个重启过");
    expect(byId.get("attention")?.value).toBe("1");
    expect(byId.get("attention")?.tone).toBe("bad");
    expect(byId.get("nodes")?.value).toBeNull();
    expect(byId.get("deployments")?.value).toBeNull();
    // With nothing wrong the card stops shouting.
    const calm = kubernetesStatCards({ pods: [pod({})] });
    expect(calm.find((card) => card.id === "attention")?.tone).toBe("plain");
  });

  it("gives every tab its own columns, with counts right-aligned", () => {
    const pods = kubernetesColumns("pods").map((column) => column.key);
    expect(pods).toEqual(["name", "namespace", "ready", "restarts", "node", "ip", "age"]);
    // Restarts is the column an operator runs their eye down, so it lines up.
    expect(kubernetesColumns("pods").find((c) => c.key === "restarts")?.numeric).toBe(true);
    expect(kubernetesColumns("nodes").map((c) => c.key)).toContain("roles");
    // Every column reads something from a real row rather than throwing on a
    // row of another kind.
    for (const tab of ["namespaces", "pods", "deployments", "nodes"] as const) {
      for (const column of kubernetesColumns(tab)) {
        expect(typeof column.read(pod({}))).toBe("string");
      }
    }
  });

  it("reads an age a person can act on, and says so when it cannot", () => {
    const now = Date.parse("2026-08-28T12:00:00Z");
    expect(kubernetesRowAge("2026-08-28T11:59:30Z", now)).toBe("30 秒");
    expect(kubernetesRowAge("2026-08-28T11:30:00Z", now)).toBe("30 分钟");
    expect(kubernetesRowAge("2026-08-28T00:00:00Z", now)).toBe("12 小时");
    expect(kubernetesRowAge("2026-08-20T12:00:00Z", now)).toBe("8 天");
    // The cluster does not always give a parseable time, and a wrong age is
    // worse than none.
    expect(kubernetesRowAge("now", now)).toBe("—");
    expect(kubernetesRowAge("", now)).toBe("—");
  });
});
