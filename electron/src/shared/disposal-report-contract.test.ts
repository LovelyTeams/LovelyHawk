import { describe, expect, it } from "vitest";

import {
  isDisposalReportContent,
  isDisposalReportExportResult,
  isDisposalReportSnapshot,
} from "./disposal-report-contract";

const summary = {
  total: 2,
  succeeded: 1,
  failed: 0,
  restored: 0,
  uncertain: 1,
  recoverable: 1,
  bySource: [{ source: "notes", count: 2 }],
};

describe("disposal report standalone contract", () => {
  it("accepts exact snapshots and rejects renderer-supplied report ingredients", () => {
    const value = {
      handle: "42d3bd8c-38d2-4335-857e-c36a065cb74e",
      generatedAt: "2026-08-24T01:02:03Z",
      snapshotSha256: "a".repeat(64),
      detectionIncluded: false,
      empty: false,
      summary,
    };
    expect(isDisposalReportSnapshot(value)).toBe(true);
    expect(isDisposalReportSnapshot({ ...value, targetLabel: "renderer target" })).toBe(false);
    expect(isDisposalReportSnapshot({ ...value, targetGuard: { identity: "x", generation: 1 } })).toBe(false);
    expect(isDisposalReportSnapshot({ ...value, operations: [] })).toBe(false);
    expect(isDisposalReportSnapshot({ ...value, detectionIncluded: true, detection: {} })).toBe(false);
  });

  it("validates internally consistent summary totals", () => {
    const base = {
      handle: "42d3bd8c-38d2-4335-857e-c36a065cb74e",
      generatedAt: "2026-08-24T01:02:03Z",
      snapshotSha256: "b".repeat(64),
      detectionIncluded: false,
      empty: false,
      summary,
    };
    expect(isDisposalReportSnapshot({ ...base, summary: { ...summary, succeeded: 2 } })).toBe(false);
    expect(isDisposalReportSnapshot({ ...base, summary: { ...summary, bySource: [{ source: "x", count: 1 }] } })).toBe(false);
  });

  it("keeps Markdown and HTML as bounded plain strings with exact keys", () => {
    const hostile = "<script>steal()</script>";
    expect(isDisposalReportContent({ format: "html", content: hostile })).toBe(true);
    expect(isDisposalReportContent({ format: "markdown", content: hostile, trustedHtml: true })).toBe(false);
    expect(isDisposalReportContent({ format: "summary", content: "界".repeat(6_000) })).toBe(false);
  });

  it("export results expose only a basename and count", () => {
    expect(isDisposalReportExportResult({ saved: true, fileName: "report.html", operationCount: 2 })).toBe(true);
    expect(isDisposalReportExportResult({ saved: true, fileName: "C:\\secret\\report.html", operationCount: 2 })).toBe(false);
    expect(isDisposalReportExportResult({
      saved: true, fileName: "report.html", operationCount: 2, contents: "private", path: "C:\\secret",
    })).toBe(false);
  });
});
