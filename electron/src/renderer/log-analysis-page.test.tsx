import { readFileSync } from "node:fs";

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { LogAnalysisReadApi, LogIocSearchResult, PublicLogEntry } from "../shared/log-analysis-read-contract";
import {
  EmptyPanel,
  ErrorPanel,
  LogAnalysisPage,
  LogEntriesView,
  LogIocResultsView,
  LogThreatCards,
  StatusPanel,
} from "./LogAnalysisPage";

const hostile = "</pre><script>steal()</script><img src=x onerror=steal()>";
const api: LogAnalysisReadApi = {
  discoverLogSources: async () => { throw new Error(); },
  readLogSource: async () => { throw new Error(); },
  correlateLogSources: async () => { throw new Error(); },
  searchLogIocs: async () => { throw new Error(); },
};

const entry: PublicLogEntry = {
  timestamp: "2026-08-24T01:02:03Z",
  level: hostile,
  service: hostile,
  message: hostile,
  rawText: hostile,
  highlighted: true,
  sourceHandle: "source-1",
  sourceName: hostile,
  textTruncated: true,
};

const threatSummary = {
  bruteForceCount: 2,
  successfulLoginCount: 1,
  privilegeEscalationCount: 1,
  suspiciousActivityCount: 3,
  topSourceIps: [{ ip: hostile, count: 2, lastSeen: hostile, actionType: hostile }],
  topTargetUsers: [{ username: hostile, count: 2, successCount: 1, failCount: 1 }],
  hourlyDistribution: Array.from({ length: 24 }, (_, index) => index),
  threatLevel: "high" as const,
};

describe("LogAnalysisPage", () => {
  it("renders a disconnected empty state without issuing fake data", () => {
    const html = renderToStaticMarkup(<LogAnalysisPage bindingHandle={null} api={api} />);
    expect(html).toContain("连接 SSH 目标后");
    expect(html).toContain("文件日志与 systemd journal");
    expect(html).not.toContain("snapshot-");
  });

  it("renders hostile log content only as escaped plain text", () => {
    const html = renderToStaticMarkup(<LogEntriesView entries={[entry]} empty="empty" />);
    expect(html).toContain("&lt;/pre&gt;&lt;script&gt;steal()&lt;/script&gt;");
    expect(html).not.toContain("<script>");
    expect(html).not.toContain("<img src=x");
    expect(html).toContain("文本已截断");
  });

  it("renders the complete bounded threat summary without interpreting hostile labels", () => {
    const html = renderToStaticMarkup(<LogThreatCards summary={threatSummary} />);
    expect(html).toContain("威胁等级");
    expect(html).toContain("暴力尝试");
    expect(html).toContain("来源 IP");
    expect(html).toContain("23:00 23");
    expect(html).not.toContain("<script>");
  });

  it("renders IOC samples and truncation as bounded evidence", () => {
    const result: LogIocSearchResult = {
      snapshotHandle: "snapshot-1",
      results: [{
        indicator: hostile,
        sourceHandle: "source-1",
        sourceName: hostile,
        count: 2,
        sampleLines: [hostile, "password=visible"],
        textTruncated: true,
      }],
      totalMatches: 2,
      truncated: true,
    };
    const html = renderToStaticMarkup(<LogIocResultsView result={result} />);
    expect(html).toContain("匹配总数 2");
    // A sample that mentions a password is the match, shown as it was logged.
    expect(html).toContain("password=visible");
    expect(html).toContain("样本文本已截断");
    expect(html).toContain("IOC 结果已按大小上限截断");
    expect(html).not.toContain("<script>");
  });

  it("exposes explicit loading, empty and error states", () => {
    const html = [
      renderToStaticMarkup(<StatusPanel label="正在读取日志…" />),
      renderToStaticMarkup(<EmptyPanel title="没有匹配" detail="有界空结果" compact />),
      renderToStaticMarkup(<ErrorPanel message="固定公开错误" compact />),
    ].join("");
    expect(html).toContain("aria-live=\"polite\"");
    expect(html).toContain("有界空结果");
    expect(html).toContain("role=\"alert\"");
  });

  /**
   * The page reads like the command workbench: one compact toolbar, a source
   * tree on the left, and everything about the selected source on the right.
   */
  it("is laid out as a workbench rather than a header, a banner and tabs", () => {
    const source = readFileSync(new URL("./LogAnalysisPage.tsx", import.meta.url), "utf8");
    expect(source).toContain('className="log-analysis-toolbar"');
    expect(source).toContain('className="log-analysis-workbench"');
    expect(source).toContain('className="log-analysis-list"');
    expect(source).toContain('className="log-analysis-detail"');
    // The view switcher sits in the toolbar, not on a row of its own.
    const toolbar = source.slice(
      source.indexOf('className="log-analysis-toolbar"'),
      source.indexOf('className="log-analysis-workbench"'),
    );
    expect(toolbar).toContain('className="log-analysis-views"');
    expect(toolbar).toContain('className="log-analysis-search"');
    expect(toolbar).toContain('className="log-analysis-reload"');
    // The old chrome is gone.
    expect(source).not.toContain("log-analysis-header");
    expect(source).not.toContain("log-analysis-readonly-banner");
    expect(source).not.toContain("log-analysis-tabs");
    expect(source).not.toContain("log-analysis-sources");
    expect(source).not.toContain("log-analysis-selector");
    // One source list serves all three views: analysis modes select in it.
    expect(source).toContain('{ type: "analysis-source-toggled", handle }');
    expect(source).toContain('{ type: "source-selected", handle }');
  });

  /** Log lines are numbered like command output, and nothing is blanked. */
  it("shows every log line as the target wrote it", () => {
    const html = renderToStaticMarkup(
      <LogEntriesView entries={[entry, { ...entry, highlighted: false, rawText: "password=visible" }]}
        empty="没有日志" />,
    );
    expect(html).toContain('class="log-analysis-output"');
    expect(html).toContain('class="log-analysis-gutter"');
    // The highlighted line is marked in both the gutter and the text.
    expect((html.match(/is-abnormal/gu) ?? [])).toHaveLength(2);
    // A credential-shaped line is evidence, not something to hide.
    expect(html).toContain("password=visible");

    const source = readFileSync(new URL("./LogAnalysisPage.tsx", import.meta.url), "utf8");
    for (const gone of ["redacted", "遮蔽", "SENSITIVE"]) expect(source).not.toContain(gone);
  });

  it("keeps phase one free of AI, rule mutation, exports, file entrypoints, terminals and generic execution", () => {
    const source = readFileSync(new URL("./LogAnalysisPage.tsx", import.meta.url), "utf8");
    for (const forbidden of [
      ["analyzeLog", "WithAi"].join(""),
      ["addLog", "Rule"].join(""),
      ["removeLog", "Rule"].join(""),
      ["mutateLog", "Rule"].join(""),
      ["exportLog", "Analysis"].join(""),
      ["openLog", "File"].join(""),
      ["launchLog", "Terminal"].join(""),
      ["executeLog", "Command"].join(""),
      "dangerouslySetInnerHTML",
    ]) expect(source).not.toContain(forbidden);
    expect(source).not.toMatch(/\b(?:sessionId|targetGeneration|guard|command|path)\s*:/u);
    expect(source).not.toMatch(/\b(?:connection|target|session|guard)\s*:/u);
  });

  it("uses global theme tokens with no color literals", () => {
    const css = readFileSync(new URL("./log-analysis-page.css", import.meta.url), "utf8");
    expect((css.match(/var\(--[a-z0-9-]+\)/gu) ?? []).length).toBeGreaterThan(30);
    expect(css).not.toMatch(/#[0-9a-f]{3,8}|rgba?\(|hsla?\(/iu);
  });
});


