import { readFileSync } from "node:fs";

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type {
  QuickDetectionApi,
  QuickDetectionReport,
} from "../shared/quick-detection-contract";
import {
  cancelQuickDetectionLifecycle,
  filterQuickDetectionModules,
  quickDetectionProgress,
} from "./quick-detection-helpers";
import { QuickDetectionPage, QuickDetectionReportView } from "./QuickDetectionPage";

const api: QuickDetectionApi = {
  getQuickDetectionCatalog: vi.fn(async () => ({})),
  planQuickDetection: vi.fn(async () => ({})),
  startQuickDetection: vi.fn(async () => ({})),
  pollQuickDetection: vi.fn(async () => ({})),
  cancelQuickDetection: vi.fn(async () => ({ cancelRequested: true })),
  listQuickDetectionHistory: vi.fn(async () => ({ total: 0, offset: 0, hasMore: false, items: [] })),
  getQuickDetectionReport: vi.fn(async () => ({})),
};

const hostile = "</pre><script>steal()</script><img src=x onerror=steal()>";
const report: QuickDetectionReport = {
  reportHandle: "report-1",
  profile: "selected",
  startedAt: "2026-08-24T00:00:00Z",
  durationMs: 10,
  status: "completed",
  overallScore: 42,
  summary: {
    critical: 1, high: 0, medium: 0, low: 0, info: 0,
    failedModules: 1, notApplicableModules: 0, errorModules: 0, cancelledModules: 0,
  },
  droppedProgressEvents: 0,
  redactedFieldCount: 0,
  textProjected: false,
  truncated: false,
  modules: [{
    id: "webshell-scan",
    label: "WebShell",
    category: "competition",
    outcome: "failed",
    score: 42,
    durationMs: 5,
    findings: [{
      title: hostile,
      description: hostile,
      severity: "critical",
      recommendation: hostile,
      redacted: false,
      textTruncated: false,
      textProjected: false,
    }],
    findingsTruncated: false,
    rawText: hostile,
    rawTextRedacted: false,
    rawTextTruncated: false,
    rawTextProjected: false,
  }],
};

describe("standalone quick detection page", () => {
  it("renders a disconnected boundary without internal capabilities", () => {
    const markup = renderToStaticMarkup(<QuickDetectionPage bindingHandle={null} api={api} />);
    expect(markup).toContain("连接目标后运行快速检测");
    expect(markup).toContain("只能运行内置的检测模块");
    expect(markup).not.toContain("sessionId");
    expect(markup).not.toContain("TargetGuard");
    expect(markup).not.toContain("bindingHandle");
  });

  it("accepts only an 请先建立 SSH 连接 and contains no renderer target or session metadata access", () => {
    const source = readFileSync(new URL("./QuickDetectionPage.tsx", import.meta.url), "utf8");
    expect(source).toContain("bindingHandle: string | null");
    for (const forbidden of [
      "SshTargetSummary", "QuickDetectionConnection", "connection.target", ".connectionId",
      ".sessionId", ".username", ".host", ".port", "remotePath", "shellCommand",
    ]) {
      expect(source).not.toContain(forbidden);
    }
  });

  it("renders hostile report strings as escaped plain text and exposes no remediation button", () => {
    const markup = renderToStaticMarkup(
      <QuickDetectionReportView report={report} selectedModuleId="webshell-scan" onSelectModule={() => undefined} />,
    );
    expect(markup).toContain("&lt;/pre&gt;&lt;script&gt;steal()&lt;/script&gt;");
    expect(markup).not.toContain("<script>steal()</script>");
    expect(markup).toContain("本页不提供修复操作");
    expect(markup).not.toContain("执行修复");
    expect(markup).not.toContain("DangerousConfirmation");
  });

  it("filters hostile plain text without interpreting it and clamps progress", () => {
    expect(filterQuickDetectionModules(report.modules, "onerror", "all")).toHaveLength(1);
    expect(filterQuickDetectionModules(report.modules, "missing", "all")).toHaveLength(0);
    expect(quickDetectionProgress(5, 2)).toBe(100);
    expect(quickDetectionProgress(0, 0)).toBe(0);
  });

  it("requests backend cancellation on active lifecycle cleanup only", async () => {
    const cancel = vi.fn(async () => ({ cancelRequested: true }));
    const lifecycleApi = { ...api, cancelQuickDetection: cancel };
    await cancelQuickDetectionLifecycle(lifecycleApi, "binding-1", "scan-1", "running");
    await cancelQuickDetectionLifecycle(lifecycleApi, "binding-1", "scan-2", "completed");
    expect(cancel).toHaveBeenCalledTimes(1);
    expect(cancel).toHaveBeenCalledWith("binding-1", "scan-1");
  });
});
