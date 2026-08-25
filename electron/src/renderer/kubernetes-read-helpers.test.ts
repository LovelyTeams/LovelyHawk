import { describe, expect, it } from "vitest";

import type { KubernetesSnapshot } from "../shared/kubernetes-read-contract";
import {
  KUBERNETES_ROW_WINDOW,
  boundKubernetesQuery,
  filteredKubernetesRows,
  kubernetesListContext,
  kubernetesNamespaceCapability,
  kubernetesReadScope,
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
