import { describe, expect, it } from "vitest";

import type { DisposalReportSnapshot } from "../shared/disposal-report-contract";
import {
  type DisposalReportState,
  disposalReportReducer,
  initialDisposalReportState,
} from "./disposal-report-state";

const report: DisposalReportSnapshot = {
  handle: "report-handle",
  generatedAt: "2026-08-24T01:02:03Z",
  snapshotSha256: "a".repeat(64),
  detectionIncluded: false,
  empty: true,
  summary: {
    total: 0, succeeded: 0, failed: 0, restored: 0, uncertain: 0, recoverable: 0,
    bySource: [],
  },
};

describe("disposal report reducer", () => {
  it("drops late generation after target scope changes", () => {
    let state = disposalReportReducer(initialDisposalReportState, { type: "scope-changed", scope: "binding-a" });
    state = disposalReportReducer(state, { type: "report-started", scope: "binding-a", request: 1 });
    state = disposalReportReducer(state, { type: "scope-changed", scope: "binding-b" });
    expect(disposalReportReducer(state, { type: "report-loaded", scope: "binding-a", request: 1, report })).toBe(state);
  });

  it("drops content for stale report handles and preview modes", () => {
    let state: DisposalReportState = { ...initialDisposalReportState, scope: "binding-a", report, preview: "html" };
    state = disposalReportReducer(state, {
      type: "content-started", scope: "binding-a", request: 2, handle: report.handle, format: "html",
    });
    state = disposalReportReducer(state, { type: "preview-selected", preview: "markdown" });
    expect(disposalReportReducer(state, {
      type: "content-loaded", scope: "binding-a", request: 2, handle: report.handle,
      content: { format: "html", content: "<script>hostile()</script>" },
    })).toBe(state);
  });

  it("represents a valid empty report without treating it as an error", () => {
    let state: DisposalReportState = { ...initialDisposalReportState, scope: "binding-a", reportRequest: 3 };
    state = disposalReportReducer(state, { type: "report-loaded", scope: "binding-a", request: 3, report });
    expect(state.reportStatus).toBe("ready");
    expect(state.report?.empty).toBe(true);
    expect(state.error).toBeNull();
  });
});
