import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  KUBERNETES_REDACTED_TEXT,
  isKubernetesAvailability,
  isKubernetesListInput,
  isKubernetesReadRow,
  isKubernetesSnapshot,
  isKubernetesTextResult,
} from "./kubernetes-read-contract";

const hostile = "</pre><script>steal()</script><img src=x onerror=steal()>";
const namespaceRow = {
  kind: "namespace",
  rowHandle: "row-namespace",
  name: hostile,
  phase: "Active",
  createdAt: "2026-08-24T00:00:00Z",
  textTruncated: false,
} as const;
const podRow = {
  kind: "pod",
  rowHandle: "row-pod",
  namespace: "production",
  name: hostile,
  phase: "Running",
  readyContainers: 1,
  totalContainers: 2,
  restarts: 3,
  node: "node-a",
  podIp: "10.0.0.8",
  images: ["registry.invalid/app:1"],
  createdAt: "2026-08-24T00:00:00Z",
  supportsLogs: true,
  textTruncated: false,
} as const;

describe("Kubernetes read strict boundary", () => {
  it("accepts only closed tabs and opaque namespace capabilities", () => {
    expect(isKubernetesListInput({ tab: "pods", namespaceScope: null })).toBe(true);
    expect(isKubernetesListInput({
      tab: "deployments",
      namespaceScope: { snapshotHandle: "snapshot-1", rowHandle: "row-1" },
    })).toBe(true);
    expect(isKubernetesListInput({
      tab: "nodes",
      namespaceScope: { snapshotHandle: "snapshot-1", rowHandle: "row-1" },
    })).toBe(false);
    expect(isKubernetesListInput({ tab: "pods", namespaceScope: null, namespace: "prod" }))
      .toBe(false);
    expect(isKubernetesListInput({ tab: "secrets", namespaceScope: null })).toBe(false);
  });

  it("keeps availability exact, bounded, and coherent", () => {
    const value = {
      kubectlInstalled: true,
      apiReachable: true,
      currentContext: hostile,
      contextTruncated: false,
    };
    expect(isKubernetesAvailability(value)).toBe(true);
    expect(isKubernetesAvailability({ ...value, targetGuard: { generation: 9 } })).toBe(false);
    expect(isKubernetesAvailability({ ...value, kubectlInstalled: false })).toBe(false);
    expect(isKubernetesAvailability({ ...value, currentContext: "x".repeat(1_025) })).toBe(false);
    expect(isKubernetesAvailability({ ...value, currentContext: "token=context-secret" }))
      .toBe(false);
    expect(isKubernetesAvailability({
      ...value,
      currentContext: KUBERNETES_REDACTED_TEXT,
      contextTruncated: true,
    })).toBe(true);
    expect(isKubernetesAvailability({
      ...value,
      currentContext: KUBERNETES_REDACTED_TEXT,
      contextTruncated: false,
    })).toBe(false);
  });

  it("accepts hostile display text without accepting hidden identity or unsafe numbers", () => {
    expect(isKubernetesReadRow(namespaceRow)).toBe(true);
    expect(isKubernetesReadRow(podRow)).toBe(true);
    expect(isKubernetesReadRow({ ...podRow, uid: "real-kubernetes-uid" })).toBe(false);
    expect(isKubernetesReadRow({ ...podRow, readyContainers: 3 })).toBe(false);
    expect(isKubernetesReadRow({ ...podRow, restarts: Number.MAX_SAFE_INTEGER + 1 })).toBe(false);
    expect(isKubernetesReadRow({ ...podRow, supportsLogs: false })).toBe(false);
    expect(isKubernetesReadRow({ ...podRow, images: Array.from({ length: 17 }, () => "x") }))
      .toBe(false);
    expect(isKubernetesReadRow({ ...podRow, images: ["password=image-secret"] })).toBe(false);
    expect(isKubernetesReadRow({
      ...podRow,
      images: [KUBERNETES_REDACTED_TEXT],
      textTruncated: false,
    })).toBe(false);
    expect(isKubernetesReadRow({
      ...podRow,
      images: [KUBERNETES_REDACTED_TEXT],
      textTruncated: true,
    })).toBe(true);
  });

  it("requires exact bounded snapshots with one fixed row kind", () => {
    const snapshot = {
      snapshotHandle: "snapshot-1",
      tab: "pods",
      namespaceScoped: true,
      displayed: 1,
      truncated: false,
      expiresInSeconds: 300,
      rows: [podRow],
    };
    expect(isKubernetesSnapshot(snapshot)).toBe(true);
    expect(isKubernetesSnapshot({ ...snapshot, displayed: 2 })).toBe(false);
    expect(isKubernetesSnapshot({ ...snapshot, rows: [podRow, podRow], displayed: 2 })).toBe(false);
    expect(isKubernetesSnapshot({ ...snapshot, rows: [namespaceRow] })).toBe(false);
    expect(isKubernetesSnapshot({ ...snapshot, remoteNamespace: "production" })).toBe(false);

    const cyclic: Record<string, unknown> = { ...snapshot };
    cyclic.self = cyclic;
    expect(() => isKubernetesSnapshot(cyclic)).not.toThrow();
    expect(isKubernetesSnapshot(cyclic)).toBe(false);
  });

  it("bounds detail and logs as multiline plain text with exact handles", () => {
    const result = {
      snapshotHandle: "snapshot-1",
      rowHandle: "row-pod",
      contentKind: "pod-logs",
      text: `first line\n${hostile}`,
      truncated: false,
    };
    expect(isKubernetesTextResult(result)).toBe(true);
    expect(isKubernetesTextResult({ ...result, path: "/var/log/pods" })).toBe(false);
    expect(isKubernetesTextResult({ ...result, text: "\u0000secret" })).toBe(false);
    expect(isKubernetesTextResult({ ...result, text: "x".repeat(512 * 1_024 + 1) })).toBe(false);
    expect(isKubernetesTextResult({ ...result, text: "safe\ntoken=pod-secret" })).toBe(false);
    expect(isKubernetesTextResult({
      ...result,
      text: 'safe\n{"clientSecret":"pod-secret"}',
    })).toBe(false);
    expect(isKubernetesTextResult({
      ...result,
      text: `safe\n${KUBERNETES_REDACTED_TEXT}`,
      truncated: true,
    })).toBe(true);
    expect(isKubernetesTextResult({
      ...result,
      text: `${KUBERNETES_REDACTED_TEXT} injected suffix`,
    })).toBe(false);
    expect(isKubernetesTextResult({
      ...result,
      text: KUBERNETES_REDACTED_TEXT,
      truncated: false,
    })).toBe(false);
  });

  it("has exactly four read methods and no renderer-supplied remote identity or command", () => {
    const source = readFileSync(new URL("./kubernetes-read-contract.ts", import.meta.url), "utf8");
    const api = source.slice(
      source.indexOf("export interface KubernetesReadApi"),
      source.indexOf("type JsonRecord"),
    );
    const methods = [
      "getKubernetesAvailability", "listKubernetesResources",
      "getKubernetesResourceDetail", "getKubernetesPodLogs",
    ];
    expect([...api.matchAll(/^\s{2}([A-Za-z_$][A-Za-z0-9_$]*)\(/gmu)]
      .map((match) => match[1])).toEqual(methods);
    expect((api.match(/Promise<unknown>/gu) ?? [])).toHaveLength(4);
    for (const forbidden of [
      "sessionId", "targetGuard", "generation", "identity", "resourceUid",
      "namespace: string", "name: string", "command", "remotePath", "scale", "restart",
      "delete", "cordon", "drain", "exec", "file", "terminal", "exportKubernetes",
      "generic", "invoke",
    ]) expect(api).not.toContain(forbidden);
  });
});
