import { describe, expect, it } from "vitest";

import {
  isMiddlewareConfiguration,
  isMiddlewareDiscovery,
  isMiddlewareHistory,
  isMiddlewareOpaqueHandle,
  type MiddlewareConfiguration,
  type MiddlewareDiscovery,
  type MiddlewareHistory,
  type MiddlewareReadApi,
} from "./middleware-read-contract";

const hostile = "</pre><script>plain()</script>";

const discovery: MiddlewareDiscovery = {
  discoveryHandle: "middleware-discovery-a",
  expiresInSeconds: 300,
  instances: [{
    instanceHandle: "middleware-instance-a",
    title: "Nginx 实例 1",
    product: "nginx",
    version: hostile,
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
  discoveryHandle: "middleware-discovery-a",
  instanceHandle: "middleware-instance-a",
  product: "nginx",
  loadedAt: "2026-08-24T01:02:03Z",
  totalBytes: "42",
  fileCount: 1,
  unresolvedIncludeCount: 0,
  directoryManifestCount: 0,
  files: [{
    fileHandle: "middleware-file-a",
    ordinal: 1,
    role: "primary",
    byteLength: "42",
    contentMode: "raw-text",
    rawText: `events {}\n# ${hostile}`,
    rawTextUnavailableReason: "available",
    nodeCount: 1,
    displayedNodes: 1,
    nodes: [{
      kind: "directive",
      name: "worker_processes",
      depth: 0,
      editable: true,
      sensitive: false,
      redacted: false,
      textTruncated: false,
    }],
    containsSensitiveValues: false,
    redactedFieldCount: 0,
    truncated: false,
  }],
  displayed: 1,
  displayedNodes: 1,
  redactedFieldCount: 0,
  truncated: false,
};

const history: MiddlewareHistory = {
  historyHandle: "middleware-history-a",
  expiresInSeconds: 300,
  entries: [{
    historyItemHandle: "middleware-record-a",
    product: "nginx",
    state: "applied",
    summary: "Nginx 配置记录：100 B → 120 B",
    oldBytes: "100",
    newBytes: "120",
    createdAt: "2026-08-24T01:02:03Z",
    updatedAt: "2026-08-24T01:03:04Z",
  }],
  recordCount: 1,
  displayed: 1,
  truncated: false,
};

describe("middleware read contract", () => {
  it("accepts the exact bounded discovery, configuration and history shapes", () => {
    expect(isMiddlewareDiscovery(discovery)).toBe(true);
    expect(isMiddlewareConfiguration(configuration)).toBe(true);
    expect(isMiddlewareHistory(history)).toBe(true);
  });

  it("rejects extra raw identity, path, digest and command fields", () => {
    for (const field of ["sessionId", "targetGeneration", "configPath", "includePath", "sha256", "shell"]) {
      expect(isMiddlewareConfiguration({ ...configuration, [field]: hostile })).toBe(false);
    }
    expect(isMiddlewareDiscovery({ ...discovery, instances: [{ ...discovery.instances[0]!, unit: "nginx.service" }] }))
      .toBe(false);
    expect(isMiddlewareHistory({ ...history, entries: [{ ...history.entries[0]!, operationId: "raw" }] }))
      .toBe(false);
  });

  it("requires core-denied or sidecar-denied raw text to remain structured-only", () => {
    const file = configuration.files[0]!;
    expect(isMiddlewareConfiguration({
      ...configuration,
      files: [{
        ...file,
        contentMode: "structured-only",
        rawText: null,
        rawTextUnavailableReason: "not-safe-text",
        containsSensitiveValues: true,
      }],
    })).toBe(true);
    expect(isMiddlewareConfiguration({
      ...configuration,
      files: [{ ...file, rawText: "password=secret" }],
    })).toBe(false);
    expect(isMiddlewareConfiguration({
      ...configuration,
      files: [{ ...file, rawText: null }],
    })).toBe(false);
  });

  it("rejects inconsistent counts, overlong text, stale ordering and malformed handles", () => {
    expect(isMiddlewareDiscovery({ ...discovery, displayed: 2 })).toBe(false);
    expect(isMiddlewareConfiguration({ ...configuration, displayedNodes: 2 })).toBe(false);
    expect(isMiddlewareHistory({
      ...history,
      entries: [history.entries[0]!, { ...history.entries[0]!, historyItemHandle: "record-b",
        updatedAt: "2026-08-24T00:00:00Z" }],
      displayed: 2,
      recordCount: 2,
    })).toBe(false);
    expect(isMiddlewareOpaqueHandle("../raw/path")).toBe(false);
    expect(isMiddlewareOpaqueHandle("x".repeat(129))).toBe(false);
  });

  it("fixes the future public surface to exactly three read methods", () => {
    const api: MiddlewareReadApi = {
      discoverMiddleware: async () => discovery,
      loadMiddlewareConfiguration: async () => configuration,
      listMiddlewareHistory: async () => history,
    };
    expect(Object.keys(api).sort()).toEqual([
      "discoverMiddleware", "listMiddlewareHistory", "loadMiddlewareConfiguration",
    ]);
  });
});
