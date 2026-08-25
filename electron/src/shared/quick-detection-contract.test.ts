import { describe, expect, it } from "vitest";

import {
  QUICK_DETECTION_API_METHODS,
  QUICK_DETECTION_REDACTED_TEXT,
  isQuickDetectionCatalog,
  isQuickDetectionHistoryPage,
  isQuickDetectionPlan,
  isQuickDetectionPlanInput,
  isQuickDetectionPoll,
  isQuickDetectionReport,
  type QuickDetectionModuleId,
} from "./quick-detection-contract";

const ids: QuickDetectionModuleId[] = [
  "port-scan", "user-audit", "backdoor-scan", "process-analysis", "file-permission",
  "ssh-audit", "firewall-check", "log-analysis", "webshell-scan", "cpu-test",
  "memory-test", "disk-test", "network-test",
];

const summary = {
  critical: 1, high: 2, medium: 3, low: 4, info: 5,
  failedModules: 1, notApplicableModules: 0, errorModules: 0, cancelledModules: 0,
};

describe("quick-detection strict boundary", () => {
  it("accepts only the complete closed catalog and exact triage profile", () => {
    const catalog = {
      modules: ids.map((id) => ({
        id, label: id, description: `description ${id}`, category: "security", categoryLabel: "安全",
      })),
      profiles: [
        { id: "selected", label: "自选", moduleIds: [] },
        {
          id: "competition-triage", label: "排查",
          moduleIds: ["backdoor-scan", "process-analysis", "user-audit", "webshell-scan", "port-scan", "ssh-audit"],
        },
      ],
      maximumFindingsPerModule: 200,
    };
    expect(isQuickDetectionCatalog(catalog)).toBe(true);
    expect(isQuickDetectionCatalog({ ...catalog, targetGuard: { generation: 1 } })).toBe(false);
    expect(isQuickDetectionCatalog({
      ...catalog,
      profiles: [catalog.profiles[0], { ...catalog.profiles[1], moduleIds: ["cpu-test"] }],
    })).toBe(false);
  });

  it("requires selected modules while triage accepts no renderer-selected modules", () => {
    expect(isQuickDetectionPlanInput({
      profile: "selected", moduleIds: ["ssh-audit"], maximumFindingsPerModule: 200,
    })).toBe(true);
    expect(isQuickDetectionPlanInput({
      profile: "selected", moduleIds: [], maximumFindingsPerModule: 200,
    })).toBe(false);
    expect(isQuickDetectionPlanInput({
      profile: "competition-triage", moduleIds: [], maximumFindingsPerModule: 200,
    })).toBe(true);
    expect(isQuickDetectionPlanInput({
      profile: "competition-triage", moduleIds: ["ssh-audit"], maximumFindingsPerModule: 200,
    })).toBe(false);
  });

  it("binds plan responses to the selected or exact triage module set", () => {
    const plan = {
      planHandle: "plan-1", profile: "selected", moduleIds: ["ssh-audit"], moduleCount: 1,
      maximumFindingsPerModule: 200, expiresInSeconds: 300, summary: "one closed module",
    };
    expect(isQuickDetectionPlan(plan)).toBe(true);
    expect(isQuickDetectionPlan({ ...plan, profile: "competition-triage" })).toBe(false);
    expect(isQuickDetectionPlan({
      ...plan,
      profile: "competition-triage",
      moduleIds: ["backdoor-scan", "process-analysis", "user-audit", "webshell-scan", "port-scan", "ssh-audit"],
      moduleCount: 6,
    })).toBe(true);
  });

  it("validates monotonic bounded polling and terminal report relationships", () => {
    const running = {
      scanHandle: "scan-1", stage: "running", completed: 1, total: 2,
      currentModule: "ssh-audit", cancelRequested: false,
      events: [{
        sequence: 1, kind: "module-finished", module: "port-scan", outcome: "passed",
        completed: 1, total: 2,
      }],
      nextEventCursor: 1, eventsTruncated: false, reportHandle: null, errorCode: null,
    };
    expect(isQuickDetectionPoll(running)).toBe(true);
    expect(isQuickDetectionPoll({ ...running, reportHandle: "report-1" })).toBe(false);
    expect(isQuickDetectionPoll({
      ...running,
      events: [{ ...running.events[0], message: "token=leak" }],
    })).toBe(false);
    expect(isQuickDetectionPoll({ ...running, events: [
      { ...running.events[0], sequence: 2 },
      { ...running.events[0], sequence: 1 },
    ], nextEventCursor: 2 })).toBe(false);
    expect(isQuickDetectionPoll({
      ...running, stage: "completed", completed: 2, currentModule: null,
      events: [], reportHandle: "report-1",
    })).toBe(true);
  });

  it("accepts bounded hostile report text as data and rejects hidden capability fields", () => {
    const hostile = "</pre><script>steal()</script>";
    const report = {
      reportHandle: "report-1", profile: "selected", startedAt: "2026-08-24T00:00:00Z",
      durationMs: 10, status: "completed", overallScore: 42, summary,
      droppedProgressEvents: 0,
      redactedFieldCount: 0, textProjected: false, truncated: false,
      modules: [{
        id: "webshell-scan", label: "WebShell", category: "competition", outcome: "failed",
        score: 42, durationMs: 5,
        findings: [{
          title: hostile, description: hostile, severity: "critical", recommendation: hostile,
          redacted: false, textTruncated: false, textProjected: false,
        }],
        findingsTruncated: false, rawText: hostile, rawTextRedacted: false,
        rawTextTruncated: false, rawTextProjected: false,
      }],
    };
    expect(isQuickDetectionReport(report)).toBe(true);
    expect(isQuickDetectionReport({ ...report, sessionId: "secret" })).toBe(false);
    expect(isQuickDetectionReport({
      ...report,
      modules: [{ ...report.modules[0], findings: Array.from({ length: 101 }, () => report.modules[0]?.findings[0]) }],
    })).toBe(false);
  });

  it("freezes an exact seven-method API and requires fixed-marker projection flags", () => {
    expect(QUICK_DETECTION_API_METHODS).toEqual([
      "getQuickDetectionCatalog", "planQuickDetection", "startQuickDetection",
      "pollQuickDetection", "cancelQuickDetection", "listQuickDetectionHistory",
      "getQuickDetectionReport",
    ]);
    const finding = {
      title: QUICK_DETECTION_REDACTED_TEXT, description: "plain", severity: "high",
      recommendation: null, redacted: true, textTruncated: false, textProjected: true,
    };
    const redactedReport = {
      reportHandle: "report-1", profile: "selected", startedAt: "2026-08-24T00:00:00Z",
      durationMs: 10, status: "completed", overallScore: 42, summary,
      droppedProgressEvents: 0, redactedFieldCount: 1, textProjected: true, truncated: false,
      modules: [{
        id: "ssh-audit", label: "SSH", category: "security", outcome: "failed", score: 42,
        durationMs: 5, findings: [finding], findingsTruncated: false, rawText: "plain",
        rawTextRedacted: false, rawTextTruncated: false, rawTextProjected: false,
      }],
    };
    expect(isQuickDetectionReport(redactedReport)).toBe(true);
    expect(isQuickDetectionReport({ ...redactedReport, redactedFieldCount: 0 })).toBe(false);
    expect(isQuickDetectionReport({
      ...redactedReport,
      modules: [{ ...redactedReport.modules[0], findings: [{ ...finding, textProjected: false }] }],
    })).toBe(false);
    expect(isQuickDetectionReport({
      ...redactedReport,
      modules: [{ ...redactedReport.modules[0], rawText: "token=leak", rawTextProjected: true }],
    })).toBe(false);
    expect(isQuickDetectionReport({
      ...redactedReport,
      modules: [{ ...redactedReport.modules[0], rawText: "plain\u0000text", rawTextProjected: true }],
    })).toBe(false);
  });

  it("keeps history pages finite and handle-unique", () => {
    const item = {
      reportHandle: "report-1", profile: "selected", startedAt: "2026-08-24T00:00:00Z",
      durationMs: 10, status: "completed", overallScore: 42, moduleCount: 1, summary,
    };
    expect(isQuickDetectionHistoryPage({ total: 1, offset: 0, hasMore: false, items: [item] })).toBe(true);
    expect(isQuickDetectionHistoryPage({ total: 2, offset: 0, hasMore: false, items: [item] })).toBe(false);
    expect(isQuickDetectionHistoryPage({ total: 2, offset: 0, hasMore: false, items: [item, item] })).toBe(false);
    expect(isQuickDetectionHistoryPage({
      total: 1, offset: 0, hasMore: false, items: [{ ...item, target: "server-a" }],
    })).toBe(false);
  });
});
