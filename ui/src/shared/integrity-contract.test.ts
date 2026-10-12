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
  isIntegrityCreationCancellation,
  isIntegrityCreationPoll,
  isIntegrityCreationRequest,
  isIntegrityCreationStarted,
  isIntegrityFinding,
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
      pathHandle: "path-handle-one",
    },
    {
      path: INTEGRITY_REDACTED_PATH,
      pathRedacted: true,
      pathTruncated: false,
      pathProjected: true,
      kind: "removed",
      severity: "medium",
      pathHandle: null,
    },
  ],
};

describe("integrity read-only contract", () => {
  it("freezes an exhaustive exact-eight surface", () => {
    expect(INTEGRITY_API_METHODS).toEqual([
      "getIntegrityPresets",
      "listIntegrityBaselines",
      "startIntegrityComparison",
      "pollIntegrityComparison",
      "cancelIntegrityComparison",
      "startIntegrityBaselineCreation",
      "pollIntegrityBaselineCreation",
      "cancelIntegrityBaselineCreation",
    ]);
    expect(new Set(INTEGRITY_API_METHODS).size).toBe(8);
  });

  it("offers a finding's file actions only for a whole path that is there", () => {
    const finding = comparison.entries[0]!;
    expect(isIntegrityFinding(finding)).toBe(true);
    expect(isIntegrityFinding({ ...finding, pathHandle: null })).toBe(true);
    // Gone, redacted, shortened or rewritten: nothing to act on.
    expect(isIntegrityFinding({ ...finding, kind: "removed" })).toBe(false);
    expect(isIntegrityFinding({ ...finding, pathTruncated: true })).toBe(false);
    expect(isIntegrityFinding({ ...finding, pathProjected: true })).toBe(false);
    expect(isIntegrityFinding({ ...finding, pathHandle: "has spaces" })).toBe(false);
    const { pathHandle: _pathHandle, ...older } = finding;
    expect(isIntegrityFinding(older)).toBe(false);
  });

  it("takes a creation request of preset ids only", () => {
    expect(isIntegrityCreationRequest(["etc"])).toBe(true);
    expect(isIntegrityCreationRequest(["etc", "web-root"])).toBe(true);
    expect(isIntegrityCreationRequest([])).toBe(false);
    expect(isIntegrityCreationRequest(["etc", "etc"])).toBe(false);
    // A path, even one that names a preset location, is not a preset id.
    expect(isIntegrityCreationRequest(["/etc"])).toBe(false);
    expect(isIntegrityCreationRequest(["/www/wwwroot"])).toBe(false);
    expect(isIntegrityCreationRequest("etc")).toBe(false);
  });

  it("reports a baseline being recorded, with counts only once it is done", () => {
    expect(isIntegrityCreationStarted({ operationHandle: "operation-one", expiresInSeconds: 660 })).toBe(true);
    expect(isIntegrityCreationStarted({ operationHandle: "operation-one", expiresInSeconds: 0 })).toBe(false);
    const running = { operationHandle: "operation-one", stage: "running", fileCount: null, pathCount: null };
    expect(isIntegrityCreationPoll(running)).toBe(true);
    expect(isIntegrityCreationPoll({ ...running, fileCount: 3 })).toBe(false);
    expect(isIntegrityCreationPoll({ ...running, stage: "completed", fileCount: 812, pathCount: 4 })).toBe(true);
    expect(isIntegrityCreationPoll({ ...running, stage: "completed" })).toBe(false);
    expect(isIntegrityCreationPoll({ ...running, stage: "completed", fileCount: 812, pathCount: 7 })).toBe(false);
    expect(isIntegrityCreationPoll({ ...running, stage: "failed" })).toBe(true);
    expect(isIntegrityCreationPoll({ ...running, stage: "paused" })).toBe(false);
    expect(isIntegrityCreationPoll({ ...running, path: "/etc" })).toBe(false);
    expect(isIntegrityCreationCancellation({ cancelled: false })).toBe(true);
    expect(isIntegrityCreationCancellation({ cancelled: "yes" })).toBe(false);
  });

  it("accepts only the fixed preset catalog", () => {
    const catalog = {
      presets: INTEGRITY_PRESET_DEFINITIONS.map((preset) => ({ ...preset })),
      maximumSelected: 6,
    };
    expect(isIntegrityPresetCatalog(catalog)).toBe(true);
    // The page shows only the label, so each label has to name its path.
    expect(INTEGRITY_PRESET_DEFINITIONS.every((preset) => preset.label.startsWith(preset.path))).toBe(true);
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
