import { describe, expect, it } from "vitest";

import type {
  LogCorrelationResult,
  LogIocSearchResult,
  LogSourceReadResult,
  LogSourceSnapshot,
} from "../shared/log-analysis-read-contract";
import {
  buildLogReadInput,
  filterLogSources,
  formatLogSourceSize,
  logAnalysisScope,
  parseIocIndicators,
} from "./log-analysis-read-helpers";
import { createLogAnalysisReadState, logAnalysisReadReducer } from "./log-analysis-read-state";

const snapshot: LogSourceSnapshot = {
  snapshotHandle: "snapshot-a",
  expiresInSeconds: 300,
  sources: [{
    sourceHandle: "journal-a",
    kind: "journal",
    displayName: "systemd journal",
    displayLocation: "journal",
    sizeBytes: null,
    modified: "",
  }, {
    sourceHandle: "file-a",
    kind: "file",
    displayName: "auth.log",
    displayLocation: "/var/log/auth.log",
    sizeBytes: 2_048,
    modified: "today",
  }, {
    sourceHandle: "file-b",
    kind: "file",
    displayName: "syslog",
    displayLocation: "</button><script>x()</script>",
    sizeBytes: 4_096,
    modified: "today",
  }],
  partial: false,
  truncated: false,
};

const threatSummary = {
  bruteForceCount: 0,
  successfulLoginCount: 0,
  privilegeEscalationCount: 0,
  suspiciousActivityCount: 0,
  topSourceIps: [],
  topTargetUsers: [],
  hourlyDistribution: Array.from({ length: 24 }, () => 0),
  threatLevel: "none" as const,
};

function loadedState() {
  let state = logAnalysisReadReducer(createLogAnalysisReadState(), { type: "scope-changed", scope: "scope-a" });
  state = logAnalysisReadReducer(state, { type: "snapshot-started", scope: "scope-a", request: 1 });
  return logAnalysisReadReducer(state, { type: "snapshot-loaded", scope: "scope-a", request: 1, snapshot });
}

function readResult(sourceHandle = "journal-a", page = 1): LogSourceReadResult {
  return {
    snapshotHandle: "snapshot-a",
    sourceHandle,
    sourceKind: sourceHandle === "journal-a" ? "journal" : "file",
    page,
    pageSize: 100,
    entryCount: 0,
    highlightedCount: 0,
    hasMore: false,
    entries: [],
    threatSummary,
    redactedCount: 0,
    truncated: false,
  };
}

describe("log analysis read reducer", () => {
  it("rejects late discovery after the exact target scope changes", () => {
    let state = logAnalysisReadReducer(createLogAnalysisReadState(), { type: "scope-changed", scope: "scope-a" });
    state = logAnalysisReadReducer(state, { type: "snapshot-started", scope: "scope-a", request: 1 });
    state = logAnalysisReadReducer(state, { type: "scope-changed", scope: "scope-b" });
    state = logAnalysisReadReducer(state, { type: "snapshot-loaded", scope: "scope-a", request: 1, snapshot });
    expect(state.scope).toBe("scope-b");
    expect(state.snapshot).toBeNull();
  });

  it("selects a stable browse source and only file sources for multi-source analysis", () => {
    const state = loadedState();
    expect(state.selectedSourceHandle).toBe("journal-a");
    expect(state.analysisSourceHandles).toEqual(["file-a", "file-b"]);
    expect(logAnalysisReadReducer(state, {
      type: "analysis-source-toggled", handle: "journal-a",
    })).toBe(state);
  });

  it("binds reads to scope, snapshot, source, page and request", () => {
    let state = loadedState();
    const request = { id: 2, snapshotHandle: "snapshot-a", sourceHandle: "journal-a", page: 1 };
    state = logAnalysisReadReducer(state, { type: "read-started", scope: "scope-a", request });
    state = logAnalysisReadReducer(state, { type: "source-selected", handle: "file-a" });
    state = logAnalysisReadReducer(state, {
      type: "read-loaded", scope: "scope-a", request, result: readResult(),
    });
    expect(state.selectedSourceHandle).toBe("file-a");
    expect(state.read).toBeNull();

    const current = { id: 3, snapshotHandle: "snapshot-a", sourceHandle: "file-a", page: 1 };
    state = logAnalysisReadReducer(state, { type: "read-started", scope: "scope-a", request: current });
    state = logAnalysisReadReducer(state, {
      type: "read-loaded", scope: "scope-a", request: current, result: readResult("file-a"),
    });
    expect(state.read?.sourceHandle).toBe("file-a");
  });

  it("refresh invalidates pending read, correlation and IOC capabilities", () => {
    let state = loadedState();
    const correlationRequest = { id: 2, snapshotHandle: "snapshot-a", sourceHandles: ["file-a", "file-b"] };
    const iocRequest = { ...correlationRequest, id: 3, indicators: ["203.0.113.7"] };
    state = logAnalysisReadReducer(state, { type: "correlation-started", scope: "scope-a", request: correlationRequest });
    state = logAnalysisReadReducer(state, { type: "ioc-started", scope: "scope-a", request: iocRequest });
    state = logAnalysisReadReducer(state, { type: "snapshot-started", scope: "scope-a", request: 4 });
    expect(state.snapshot).toBeNull();
    expect(state.correlationRequest).toBeNull();
    expect(state.iocRequest).toBeNull();
  });

  it("cancels pending tab work while preserving already validated results", () => {
    let state = loadedState();
    const request = { id: 2, snapshotHandle: "snapshot-a", sourceHandles: ["file-a", "file-b"] };
    state = logAnalysisReadReducer(state, { type: "tab-selected", tab: "correlation" });
    state = logAnalysisReadReducer(state, { type: "correlation-started", scope: "scope-a", request });
    expect(state.correlationStatus).toBe("loading");
    state = logAnalysisReadReducer(state, { type: "tab-selected", tab: "ioc" });
    expect(state.correlationStatus).toBe("idle");
    expect(state.correlationRequest).toBeNull();
  });

  it("accepts correlation only when echoed handles preserve the active selection", () => {
    let state = loadedState();
    const request = { id: 2, snapshotHandle: "snapshot-a", sourceHandles: ["file-a", "file-b"] };
    const result: LogCorrelationResult = {
      snapshotHandle: "snapshot-a",
      sourceHandles: ["file-a", "file-b"],
      coverage: "bounded-best-effort",
      totalObserved: 0,
      entries: [],
      threatSummary,
      redactedCount: 0,
      truncated: false,
    };
    state = logAnalysisReadReducer(state, { type: "correlation-started", scope: "scope-a", request });
    state = logAnalysisReadReducer(state, {
      type: "correlation-loaded", scope: "scope-a", request, result: { ...result, sourceHandles: ["file-b", "file-a"] },
    });
    expect(state.correlation).toBeNull();
    state = logAnalysisReadReducer(state, { type: "correlation-loaded", scope: "scope-a", request, result });
    expect(state.correlation).toBe(result);
  });

  it("rejects IOC results outside the request's source and indicator closure", () => {
    let state = loadedState();
    const request = {
      id: 2,
      snapshotHandle: "snapshot-a",
      sourceHandles: ["file-a", "file-b"],
      indicators: ["203.0.113.7"],
    };
    const result: LogIocSearchResult = {
      snapshotHandle: "snapshot-a",
      results: [{
        indicator: "unrequested.example",
        sourceHandle: "file-a",
        sourceName: "auth.log",
        count: 1,
        sampleLines: [],
        samplesRedacted: false,
        textTruncated: false,
      }],
      totalMatches: 1,
      redactedSampleCount: 0,
      truncated: false,
    };
    state = logAnalysisReadReducer(state, { type: "ioc-started", scope: "scope-a", request });
    state = logAnalysisReadReducer(state, { type: "ioc-loaded", scope: "scope-a", request, result });
    expect(state.ioc).toBeNull();
  });
});

describe("log analysis read helpers", () => {
  it("uses only the current opaque binding handle in its renderer lifecycle scope", () => {
    expect(logAnalysisScope("binding-a")).toBe("binding-a");
    expect(logAnalysisScope("binding-a")).not.toBe(logAnalysisScope("binding-b"));
  });

  it("builds closed file and journal queries without accepting arbitrary path data", () => {
    const filter = { keyword: " failed ", date: "2026-08-24", journalUnit: " ssh.service " };
    expect(buildLogReadInput(snapshot.sources[0]!, 1, filter)).toEqual({
      input: { page: 1, pageSize: 100, keyword: "failed", date: "2026-08-24", journalUnit: "ssh.service" },
      error: null,
    });
    expect(buildLogReadInput(snapshot.sources[1]!, 1, filter).input?.journalUnit).toBeNull();
    expect(buildLogReadInput(snapshot.sources[0]!, 1, { ...filter, journalUnit: "ssh;id" }).input).toBeNull();
  });

  it("keeps source filtering and IOC parsing bounded and hostile-text agnostic", () => {
    expect(filterLogSources(snapshot.sources, "script").map((source) => source.sourceHandle)).toEqual(["file-b"]);
    expect(formatLogSourceSize(2_048)).toBe("2.0 KiB");
    expect(parseIocIndicators("203.0.113.7\nevil.test", 2).indicators).toEqual(["203.0.113.7", "evil.test"]);
    expect(parseIocIndicators("same\nsame", 2).error).toContain("不能重复");
    expect(parseIocIndicators(Array.from({ length: 9 }, (_, index) => `ioc-${index}`).join("\n"), 8).error)
      .toContain("不能超过 64");
  });
});
