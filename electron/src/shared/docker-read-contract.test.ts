import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  DOCKER_REDACTED_TEXT,
  isDockerCollectionKind,
  isDockerContainerSnapshot,
  isDockerLogs,
  isDockerReadCollection,
  isDockerReadInspection,
  isDockerResourceKind,
  isDockerSecurityAudit,
} from "./docker-read-contract";

const hostile = "</pre><script>steal()</script><img src=x onerror=steal()>";

const snapshot = {
  snapshotHandle: "snapshot-1",
  expiresInSeconds: 300,
  containers: [{
    containerHandle: "container-1",
    name: hostile,
    image: "registry.local/app:1",
    state: "running",
    status: hostile,
    ports: "127.0.0.1:8080->80/tcp",
    createdAt: "2026-08-24 01:00:00",
  }],
  truncated: false,
};

describe("Docker read strict boundary", () => {
  // The hostile-text sweep below is CPU-heavy; give it headroom under a loaded full-suite run.
  it("accepts bounded hostile container text while rejecting identity, command and capability fields", { timeout: 30_000 }, () => {
    expect(isDockerContainerSnapshot(snapshot)).toBe(true);
    expect(isDockerContainerSnapshot({ ...snapshot, sessionId: "secret" })).toBe(false);
    expect(isDockerContainerSnapshot({
      ...snapshot,
      containers: [{ ...snapshot.containers[0], id: "raw-id" }],
    })).toBe(false);
    expect(isDockerContainerSnapshot({
      ...snapshot,
      containers: [{ ...snapshot.containers[0], command: "docker rm -f app" }],
    })).toBe(false);
    expect(isDockerContainerSnapshot({
      ...snapshot,
      containers: [snapshot.containers[0], snapshot.containers[0]],
    })).toBe(false);
    expect(isDockerContainerSnapshot({
      ...snapshot,
      containers: Array.from({ length: 500 }, (_, index) => ({
        ...snapshot.containers[0],
        containerHandle: `container-${index}`,
        ports: "x".repeat(4_096),
      })),
    })).toBe(false);
    expect(isDockerContainerSnapshot({
      ...snapshot,
      containers: [{ ...snapshot.containers[0], status: "token=container-secret" }],
    })).toBe(true);
    expect(isDockerContainerSnapshot({
      ...snapshot,
      containers: [{ ...snapshot.containers[0], status: DOCKER_REDACTED_TEXT }],
    })).toBe(false);
    expect(isDockerContainerSnapshot({
      ...snapshot,
      containers: [{ ...snapshot.containers[0], status: DOCKER_REDACTED_TEXT }],
      truncated: true,
    })).toBe(true);
  });

  it("keeps collection and resource selectors closed", () => {
    expect(isDockerCollectionKind("stats")).toBe(true);
    expect(isDockerCollectionKind("containers/remove")).toBe(false);
    expect(isDockerResourceKind("network")).toBe(true);
    expect(isDockerResourceKind("file")).toBe(false);
  });

  it("validates exact tagged collections and opaque follow-up handles", () => {
    const networks = {
      kind: "networks",
      snapshotHandle: "snapshot-1",
      items: [{
        networkHandle: "network-1",
        name: hostile,
        driver: "bridge",
        scope: "local",
        internal: false,
        ipv6: false,
      }],
      truncated: false,
    };
    expect(isDockerReadCollection(networks)).toBe(true);
    expect(isDockerReadCollection({ ...networks, kind: "network-prune" })).toBe(false);
    expect(isDockerReadCollection({
      ...networks,
      items: [{ ...networks.items[0], networkId: "raw-id" }],
    })).toBe(false);
    expect(isDockerReadCollection({
      ...networks,
      items: [networks.items[0], networks.items[0]],
    })).toBe(false);
  });

  it("validates bounded inspection details without accepting hidden commands or identities", () => {
    const inspection = {
      kind: "container",
      snapshotHandle: "snapshot-1",
      resourceHandle: "container-1",
      name: hostile,
      fields: [{ label: "状态", value: hostile }],
      mounts: [{ kind: "bind", source: hostile, destination: "/data", mode: "ro", readWrite: false }],
      networks: [{ name: "bridge", macAddress: "", ipv4Address: "172.18.0.2/16", ipv6Address: "" }],
      truncated: false,
    };
    expect(isDockerReadInspection(inspection)).toBe(true);
    expect(isDockerReadInspection({ ...inspection, command: "inspect --format" })).toBe(false);
    expect(isDockerReadInspection({ ...inspection, containerId: "raw-id" })).toBe(false);
    expect(isDockerReadInspection({ ...inspection, fields: Array.from({ length: 65 }, () => inspection.fields[0]) })).toBe(false);
    expect(isDockerReadInspection({
      ...inspection,
      fields: [{ label: "Env", value: '{"clientSecret":"inspect-secret"}' }],
    })).toBe(true);
    expect(isDockerReadInspection({
      ...inspection,
      mounts: [{ ...inspection.mounts[0], source: "https://user:password@example.invalid/data" }],
    })).toBe(true);
    expect(isDockerReadInspection({
      ...inspection,
      mounts: [{
        ...inspection.mounts[0],
        source: "https://example.invalid/public https://user:password@example.invalid/private",
      }],
    })).toBe(true);
    expect(isDockerReadInspection({
      ...inspection,
      fields: [{ label: "Env", value: DOCKER_REDACTED_TEXT }],
    })).toBe(false);
    expect(isDockerReadInspection({
      ...inspection,
      fields: [{ label: "Env", value: DOCKER_REDACTED_TEXT }],
      truncated: true,
    })).toBe(true);

    const networkInspection = {
      kind: "network",
      snapshotHandle: "snapshot-1",
      resourceHandle: "network-1",
      name: "bridge",
      driver: "bridge",
      scope: "local",
      internal: false,
      ipv6: false,
      attachable: false,
      ingress: false,
      ipamDriver: "default",
      ipam: [],
      attachments: [],
      options: [{ key: "authorization", value: "Bearer network-secret" }],
      labels: [],
      truncated: false,
    };
    expect(isDockerReadInspection(networkInspection)).toBe(true);
    expect(isDockerReadInspection({
      ...networkInspection,
      options: [{ key: "authorization", value: DOCKER_REDACTED_TEXT }],
      truncated: true,
    })).toBe(true);
  });

  it("bounds security findings and omits finding identity/action material", () => {
    const audit = {
      snapshotHandle: "snapshot-1",
      containersScanned: 1,
      findings: [{
        severity: "high",
        severityLabel: "高",
        category: "privileged",
        categoryLabel: "特权",
        containerName: hostile,
        description: hostile,
        recommendation: hostile,
        textTruncated: false,
      }],
      summary: { critical: 0, high: 1, medium: 0, low: 0, info: 0, total: 1, score: 70 },
      truncated: false,
    };
    expect(isDockerSecurityAudit(audit)).toBe(true);
    expect(isDockerSecurityAudit({
      ...audit,
      findings: [{ ...audit.findings[0], containerId: "raw-id" }],
    })).toBe(false);
    expect(isDockerSecurityAudit({
      ...audit,
      findings: [{ ...audit.findings[0], remediationHandle: "action-1" }],
    })).toBe(false);
    expect(isDockerSecurityAudit({
      ...audit,
      summary: { ...audit.summary, total: 2 },
    })).toBe(false);
  });

  it("bounds logs by UTF-8 bytes and exact snapshot/container handles", () => {
    const logs = {
      snapshotHandle: "snapshot-1",
      containerHandle: "container-1",
      tail: 200,
      text: hostile,
      truncated: false,
    };
    expect(isDockerLogs(logs)).toBe(true);
    expect(isDockerLogs({ ...logs, tail: 0 })).toBe(false);
    expect(isDockerLogs({ ...logs, text: "界".repeat(90_000) })).toBe(false);
    expect(isDockerLogs({ ...logs, path: "/var/lib/docker" })).toBe(false);
    expect(isDockerLogs({ ...logs, text: "safe\nAuthorization: Bearer log-secret" })).toBe(true);
    expect(isDockerLogs({ ...logs, text: `safe\n${DOCKER_REDACTED_TEXT}` })).toBe(false);
    expect(isDockerLogs({
      ...logs,
      text: `safe\n${DOCKER_REDACTED_TEXT}`,
      truncated: true,
    })).toBe(true);
    expect(isDockerLogs({ ...logs, text: `${DOCKER_REDACTED_TEXT} injected` })).toBe(false);
    expect(isDockerLogs({ ...logs, text: "safe\u0000secret" })).toBe(false);
  });

  it("exposes exactly five opaque read methods without mutation or generic primitives", () => {
    const source = readFileSync(new URL("./docker-read-contract.ts", import.meta.url), "utf8");
    const api = source.slice(
      source.indexOf("export interface DockerReadApi"),
      source.indexOf("type JsonRecord"),
    );
    expect([...api.matchAll(/^\s{2}([A-Za-z_$][A-Za-z0-9_$]*)\(/gmu)]
      .map((match) => match[1])).toEqual([
      "refreshDockerContainers",
      "getDockerCollection",
      "inspectDockerResource",
      "getDockerSecurityAudit",
      "getDockerLogs",
    ]);
    expect((api.match(/Promise<unknown>/gu) ?? [])).toHaveLength(5);
    for (const forbidden of [
      "sessionId", "targetGuard", "generation", "identity", "containerId", "networkId",
      "volumeId", "command", "remotePath", "scale", "restart", "delete", "prune",
      "exec", "terminal", "exportDocker", "generic", "invoke",
    ]) expect(api).not.toContain(forbidden);
  });
});
