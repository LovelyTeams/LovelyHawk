import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  INTEGRITY_API_METHODS,
  INTEGRITY_PRESET_DEFINITIONS,
  INTEGRITY_REDACTED_PATH,
  isIntegrityBaseline,
  isIntegrityBaselineList,
  isIntegrityComparison,
  isIntegrityComparisonCancellation,
  isIntegrityComparisonPoll,
  isIntegrityComparisonStarted,
  isIntegrityPollRequest,
  isIntegrityPresetCatalog,
  type IntegrityBaseline,
  type IntegrityComparison,
} from "./integrity-contract";

const baseline: IntegrityBaseline = {
  baselineHandle: "baseline-opaque",
  createdAt: "2026-08-25T00:00:00Z",
  paths: ["/var/www", INTEGRITY_REDACTED_PATH],
  pathsTruncated: false,
  redactedPathCount: 1,
  textProjected: true,
  fileCount: 12,
};

const comparison: IntegrityComparison = {
  baselineHandle: baseline.baselineHandle,
  added: 1,
  removed: 1,
  modified: 0,
  displayed: 2,
  redactedPathCount: 1,
  textProjected: true,
  truncated: false,
  entries: [
    {
      path: "/var/www/</code><script>hostile()</script>",
      pathRedacted: false,
      pathTruncated: false,
      pathProjected: false,
      kind: "added",
      severity: "high",
    },
    {
      path: INTEGRITY_REDACTED_PATH,
      pathRedacted: true,
      pathTruncated: false,
      pathProjected: true,
      kind: "removed",
      severity: "medium",
    },
  ],
};

describe("integrity read-only contract", () => {
  it("freezes an exhaustive exact-five preload surface", () => {
    expect(INTEGRITY_API_METHODS).toEqual([
      "getIntegrityPresets",
      "listIntegrityBaselines",
      "startIntegrityComparison",
      "pollIntegrityComparison",
      "cancelIntegrityComparison",
    ]);
    expect(new Set(INTEGRITY_API_METHODS).size).toBe(5);
  });

  it("accepts only the fixed preset catalog", () => {
    const catalog = {
      presets: INTEGRITY_PRESET_DEFINITIONS.map((preset) => ({ ...preset })),
      maximumSelected: 6,
    };
    expect(isIntegrityPresetCatalog(catalog)).toBe(true);
    expect(isIntegrityPresetCatalog({ ...catalog, customPath: "/tmp" })).toBe(false);
    expect(isIntegrityPresetCatalog({ ...catalog, maximumSelected: 7 })).toBe(false);
  });

  it("keeps baseline handles opaque and projection flags coherent", () => {
    expect(isIntegrityBaseline(baseline)).toBe(true);
    expect(isIntegrityBaseline({ ...baseline, sessionId: "secret" })).toBe(false);
    expect(isIntegrityBaseline({ ...baseline, redactedPathCount: 0 })).toBe(false);
    expect(isIntegrityBaseline({ ...baseline, textProjected: false })).toBe(false);
    expect(isIntegrityBaseline({ ...baseline, paths: ["relative/path"] })).toBe(false);
    expect(isIntegrityBaselineList({ items: [baseline], truncated: false })).toBe(true);
    expect(isIntegrityBaselineList({ items: [baseline, baseline], truncated: false })).toBe(false);
  });

  it("treats hostile display text as bounded data and rejects secrets", () => {
    expect(isIntegrityComparison(comparison)).toBe(true);
    expect(isIntegrityComparison({
      ...comparison,
      entries: [{
        ...comparison.entries[0],
        path: "/var/www/token=super-secret",
      }, comparison.entries[1]],
    })).toBe(true);
    expect(isIntegrityComparison({ ...comparison, command: "cat /etc/shadow" })).toBe(false);
    expect(isIntegrityComparison({ ...comparison, redactedPathCount: 0 })).toBe(false);
  });

  it("validates start, cursor polling, terminal coherence, and cancellation exactly", () => {
    expect(isIntegrityComparisonStarted({
      operationHandle: "operation-opaque",
      baselineHandle: baseline.baselineHandle,
      stage: "running",
      expiresInSeconds: 300,
    })).toBe(true);
    expect(isIntegrityPollRequest(0, 8)).toBe(true);
    expect(isIntegrityPollRequest(-1, 8)).toBe(false);
    expect(isIntegrityPollRequest(0, 9)).toBe(false);
    expect(isIntegrityComparisonPoll({
      operationHandle: "operation-opaque",
      baselineHandle: baseline.baselineHandle,
      stage: "running",
      events: [{ sequence: 1, kind: "started" }],
      nextEventCursor: 1,
      eventsTruncated: false,
      comparison: null,
      errorCode: null,
    })).toBe(true);
    expect(isIntegrityComparisonPoll({
      operationHandle: "operation-opaque",
      baselineHandle: baseline.baselineHandle,
      stage: "running",
      events: [{ sequence: 1, kind: "completed" }],
      nextEventCursor: 1,
      eventsTruncated: false,
      comparison: null,
      errorCode: null,
    })).toBe(false);
    expect(isIntegrityComparisonPoll({
      operationHandle: "operation-opaque",
      baselineHandle: baseline.baselineHandle,
      stage: "completed",
      events: [{ sequence: 2, kind: "completed" }],
      nextEventCursor: 2,
      eventsTruncated: false,
      comparison,
      errorCode: null,
    })).toBe(true);
    expect(isIntegrityComparisonPoll({
      operationHandle: "operation-opaque",
      baselineHandle: baseline.baselineHandle,
      stage: "failed",
      events: [],
      nextEventCursor: 2,
      eventsTruncated: false,
      comparison,
      errorCode: "comparison-failed",
    })).toBe(false);
    expect(isIntegrityComparisonCancellation({ cancelled: true })).toBe(true);
    expect(isIntegrityComparisonCancellation({ cancelled: true, operationHandle: "leak" })).toBe(false);
  });

  it("contains no creation, quarantine, shell, path, target, or session surface", () => {
    const source = readFileSync(new URL("./integrity-contract.ts", import.meta.url), "utf8");
    const api = source.slice(
      source.indexOf("export interface IntegrityApi"),
      source.indexOf("export const INTEGRITY_API_METHODS"),
    );
    for (const forbidden of [
      "createIntegrityBaseline", "Quarantine", "command", "shell", "remotePath",
      "sessionId", "connectionId", "target", "host", "username",
    ]) {
      expect(api).not.toContain(forbidden);
    }
  });
});
