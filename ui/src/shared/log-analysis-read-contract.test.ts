import { describe, expect, it } from "vitest";

import {
  isLogCorrelationInput,
  isLogCorrelationResult,
  isLogIocSearchInput,
  isLogIocSearchResult,
  isLogSourceReadInput,
  isLogSourceReadResult,
  isLogSourceSnapshot,
} from "./log-analysis-read-contract";

const hostile = "</pre><script>steal()</script><img src=x onerror=steal()>";
const threatSummary = {
  bruteForceCount: 0,
  successfulLoginCount: 0,
  privilegeEscalationCount: 0,
  suspiciousActivityCount: 0,
  topSourceIps: [],
  topTargetUsers: [],
  hourlyDistribution: Array.from({ length: 24 }, () => 0),
  threatLevel: "none",
};

const snapshot = {
  snapshotHandle: "snapshot-1",
  expiresInSeconds: 300,
  sources: [{
    sourceHandle: "source-file-1",
    kind: "file",
    displayName: hostile,
    displayLocation: `/var/log/${hostile}`,
    sizeBytes: 512,
    modified: "2026-08-24T01:00:00Z",
    pathHandle: "path-file-1",
  }, {
    sourceHandle: "source-journal-1",
    kind: "journal",
    displayName: "systemd journal",
    displayLocation: hostile,
    sizeBytes: null,
    modified: "",
    pathHandle: null,
  }],
  partial: false,
  truncated: false,
};

const fileEntry = {
  timestamp: "2026-08-24T01:02:03Z",
  level: "warning",
  service: hostile,
  message: hostile,
  rawText: hostile,
  highlighted: true,
  sourceHandle: null,
  sourceName: null,
  textTruncated: false,
};

describe("log analysis read strict boundary", () => {
  it("accepts bounded hostile source labels but rejects paths and target capabilities", () => {
    expect(isLogSourceSnapshot(snapshot)).toBe(true);
    expect(isLogSourceSnapshot({ ...snapshot, sessionId: "secret" })).toBe(false);
    expect(isLogSourceSnapshot({ ...snapshot, targetGeneration: 7 })).toBe(false);
    expect(isLogSourceSnapshot({
      ...snapshot,
      sources: [{ ...snapshot.sources[0], path: "/etc/shadow" }],
    })).toBe(false);
    // A path that happens to read like a credential is still just a path.
    expect(isLogSourceSnapshot({
      ...snapshot,
      sources: [{ ...snapshot.sources[0], displayLocation: "/var/log/token=secret-value" }],
    })).toBe(true);
    expect(isLogSourceSnapshot({
      ...snapshot,
      sources: [snapshot.sources[0], snapshot.sources[0]],
    })).toBe(false);
    // A file may carry a handle file evidence can keep it by; never a path, and
    // the journal is not a file to keep.
    expect(isLogSourceSnapshot({
      ...snapshot,
      sources: [{ ...snapshot.sources[0], pathHandle: null }, snapshot.sources[1]],
    })).toBe(true);
    for (const pathHandle of ["/var/log/auth.log", "", "a b", 7]) {
      expect(isLogSourceSnapshot({ ...snapshot, sources: [{ ...snapshot.sources[0], pathHandle }] })).toBe(false);
    }
    expect(isLogSourceSnapshot({ ...snapshot, sources: [{ ...snapshot.sources[0], pathHandle: undefined }] })).toBe(false);
    expect(isLogSourceSnapshot({
      ...snapshot,
      sources: [snapshot.sources[0], { ...snapshot.sources[1], pathHandle: "path-journal" }],
    })).toBe(false);
    expect(isLogSourceSnapshot({
      ...snapshot,
      sources: [snapshot.sources[0], { ...snapshot.sources[0], sourceHandle: "source-file-2" }],
    })).toBe(false);
    expect(isLogSourceSnapshot({
      ...snapshot,
      sources: Array.from({ length: 101 }, (_, index) => ({
        ...snapshot.sources[0], sourceHandle: `source-${index}`,
      })),
    })).toBe(false);
  });

  it("keeps read queries typed, exact and bounded", () => {
    const query = { page: 1, pageSize: 100, keyword: "failed login", date: "2026-08-24", journalUnit: null };
    expect(isLogSourceReadInput(query)).toBe(true);
    expect(isLogSourceReadInput({ ...query, path: "/etc/shadow" })).toBe(false);
    expect(isLogSourceReadInput({ ...query, command: "cat /etc/shadow" })).toBe(false);
    expect(isLogSourceReadInput({ ...query, date: "2026-02-30" })).toBe(false);
    expect(isLogSourceReadInput({ ...query, journalUnit: "ssh.service; id" })).toBe(false);
    expect(isLogSourceReadInput({ ...query, keyword: "x".repeat(257) })).toBe(false);
  });

  it("closes correlation and IOC selectors over bounded opaque handles", () => {
    expect(isLogCorrelationInput({ sourceHandles: ["source-1", "source-2"], lineLimit: 200 })).toBe(true);
    expect(isLogCorrelationInput({ sourceHandles: ["source-1"], lineLimit: 200 })).toBe(false);
    expect(isLogCorrelationInput({ sourceHandles: ["source-1", "source-2"], lineLimit: 201 })).toBe(false);
    expect(isLogIocSearchInput({
      sourceHandles: ["source-1", "source-2"], indicators: ["203.0.113.7", "evil.test"],
    })).toBe(true);
    expect(isLogIocSearchInput({
      sourceHandles: Array.from({ length: 8 }, (_, index) => `source-${index}`),
      indicators: Array.from({ length: 9 }, (_, index) => `ioc-${index}`),
    })).toBe(false);
    expect(isLogIocSearchInput({ sourceHandles: ["source-1"], indicators: ["token\nleak"] })).toBe(false);
    // Hunting for a token string is a legitimate search, so it is accepted.
    expect(isLogIocSearchInput({ sourceHandles: ["source-1"], indicators: ["token=secret-value"] })).toBe(true);
    expect(isLogIocSearchInput({ sourceHandles: ["source-1"], indicators: ["same", "same"] })).toBe(false);
  });

  it("validates paged entries and threat counts without judging their content", () => {
    const result = {
      snapshotHandle: "snapshot-1",
      sourceHandle: "source-file-1",
      sourceKind: "file",
      page: 1,
      pageSize: 100,
      entryCount: 2,
      highlightedCount: 1,
      hasMore: false,
      entries: [fileEntry, {
        ...fileEntry,
        message: "authorization: Bearer abc",
        rawText: "authorization: Bearer abc",
        highlighted: false,
      }],
      threatSummary,
      truncated: false,
    };
    expect(isLogSourceReadResult(result)).toBe(true);
    expect(isLogSourceReadResult({ ...result, command: "journalctl" })).toBe(false);
    expect(isLogSourceReadResult({ ...result, entryCount: 1 })).toBe(false);
    // A username or a line that mentions a password is the finding, not a leak.
    expect(isLogSourceReadResult({
      ...result,
      threatSummary: {
        ...threatSummary,
        topTargetUsers: [{ username: "password:user-secret", count: 1, successCount: 0, failCount: 1 }],
      },
    })).toBe(true);
    expect(isLogSourceReadResult({
      ...result,
      entries: [fileEntry, { ...result.entries[1], rawText: "password=visible" }],
    })).toBe(true);
  });

  it("maps correlated entries only to the selected opaque source set", () => {
    const result = {
      snapshotHandle: "snapshot-1",
      sourceHandles: ["source-1", "source-2"],
      coverage: "bounded-best-effort",
      totalObserved: 1,
      entries: [{ ...fileEntry, sourceHandle: "source-1", sourceName: hostile }],
      threatSummary,
      truncated: false,
    };
    expect(isLogCorrelationResult(result)).toBe(true);
    expect(isLogCorrelationResult({
      ...result,
      entries: [{ ...result.entries[0], sourceHandle: "source-3" }],
    })).toBe(false);
    expect(isLogCorrelationResult({ ...result, coverage: "complete" })).toBe(false);
  });

  it("bounds IOC result pairs, samples and totals", () => {
    const result = {
      snapshotHandle: "snapshot-1",
      results: [{
        indicator: "203.0.113.7",
        sourceHandle: "source-1",
        sourceName: hostile,
        count: 2,
        sampleLines: [hostile, "password=visible"],
        textTruncated: false,
      }],
      totalMatches: 2,
      truncated: false,
    };
    expect(isLogIocSearchResult(result)).toBe(true);
    expect(isLogIocSearchResult({ ...result, path: "/var/log/auth.log" })).toBe(false);
    expect(isLogIocSearchResult({ ...result, totalMatches: 3 })).toBe(false);
    expect(isLogIocSearchResult({
      ...result,
      results: [result.results[0], result.results[0]],
      totalMatches: 4,
    })).toBe(false);
  });
});
