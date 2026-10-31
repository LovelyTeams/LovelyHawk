import { readFileSync } from "node:fs";

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type {
  LogAnalysisReadApi,
  LogIocSearchResult,
  LogSource,
  LogSourceReadResult,
  PublicLogEntry,
} from "../shared/log-analysis-read-contract";
import type { FileEvidenceApi } from "../shared/file-evidence-contract";
import { logEvidenceOffer } from "./log-analysis-read-helpers";
import type { LogRulesApi } from "./log-rule-hits";
import type { AiAssistApi } from "./AiAssistPanel";
import {
  EmptyPanel,
  ErrorPanel,
  LogAnalysisPage,
  LogEntriesView,
  LogIocResultsView,
  LogPagination,
  LogResultCopy,
  LogRuleSummary,
  LogSourceBranch,
  logAnalysisFailureMessage,
  logDiscoveryGap,
  logLineMeta,
  LogThreatCards,
  StatusPanel,
} from "./LogAnalysisPage";

const hostile = "</pre><script>steal()</script><img src=x onerror=steal()>";
const api: LogAnalysisReadApi & FileEvidenceApi & LogRulesApi & AiAssistApi = {
  discoverLogSources: async () => { throw new Error(); },
  readLogSource: async () => { throw new Error(); },
  correlateLogSources: async () => { throw new Error(); },
  searchLogIocs: async () => { throw new Error(); },
  fileEvidence: async () => { throw new Error(); },
  logRules: async () => { throw new Error(); },
  aiAssist: async () => { throw new Error(); },
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

const readResult: LogSourceReadResult = {
  snapshotHandle: "snapshot-1",
  sourceHandle: "source-1",
  sourceKind: "file",
  page: 1,
  pageSize: 100,
  entryCount: 100,
  highlightedCount: 0,
  hasMore: true,
  entries: [],
  threatSummary,
  truncated: false,
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
    expect(toolbar).toContain('className="log-analysis-views view-tabs"');
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
    // The one file action is keeping a listed log as evidence: through the
    // audited file-evidence dialog, by the handle discovery offered.
    expect(source.match(/<FileEvidenceDialog/gu)).toHaveLength(1);
    expect(source).toContain("logEvidenceOffer(selectedSource)");
    expect(source).not.toMatch(/fileEvidence\(/u);
  });

  it("offers to keep a listed log file only by the handle discovery gave it", () => {
    const listed: LogSource = {
      sourceHandle: "source-a",
      kind: "file",
      displayName: "auth.log",
      displayLocation: "/var/log/auth.log",
      sizeBytes: 10,
      modified: "today",
      pathHandle: "path-a",
    };
    expect(logEvidenceOffer(listed)).toEqual({ pathHandle: "path-a", line: 0, path: "/var/log/auth.log" });
    expect(logEvidenceOffer({ ...listed, pathHandle: null })).toBeNull();
    expect(logEvidenceOffer({
      ...listed, kind: "journal", sizeBytes: null, modified: "", pathHandle: "path-j",
    })).toBeNull();
  });

  it("lets the operator change source while a read is still running", () => {
    // The tree used to go dead for the length of a read. On an RPM host that
    // is eleven seconds per command with nothing on screen explaining why the
    // clicks do nothing, so an operator who picked the wrong log had to wait
    // out their own mistake.
    const file = (sourceHandle: string, displayName: string): LogSource => ({
      sourceHandle,
      kind: "file",
      displayName,
      displayLocation: `/var/log/${displayName}`,
      sizeBytes: 1_024,
      modified: "2026-09-03T00:00:00Z",
      pathHandle: null,
    });
    const group = { kind: "file" as const, sources: [file("file-a", "auth.log"), file("file-b", "access_log")] };
    const html = renderToStaticMarkup(
      <LogSourceBranch group={group} collapsed={false} selecting={false} selectedHandle="file-a"
        checked={[]} onToggle={() => undefined} onSelect={() => undefined} />,
    );
    // Neither source button is disabled, whatever the read is doing.
    expect(html).not.toContain("disabled");
    expect(html).toContain('aria-pressed="true"');
    expect(html).toContain('aria-pressed="false"');

    // In analysis mode a journal still cannot join a correlation, which is a
    // property of the source and not of how busy the page is.
    const mixed = {
      kind: "journal" as const,
      sources: [{
        sourceHandle: "journal-a",
        kind: "journal" as const,
        displayName: "systemd Journal",
        displayLocation: "systemd journal",
        sizeBytes: null,
        modified: "2026-09-03T00:00:00Z",
        pathHandle: null,
      }],
    };
    const analysing = renderToStaticMarkup(
      <LogSourceBranch group={mixed} collapsed={false} selecting selectedHandle={null}
        checked={[]} onToggle={() => undefined} onSelect={() => undefined} />,
    );
    expect(analysing).toContain("disabled");
  });

  it("says what to do rather than listing what might have gone wrong", () => {
    // All three views used to answer with their own list of causes joined by
    // "or" — cancelled, or expired, or invalid — which is the page handing its
    // own uncertainty to the operator. Each of these has exactly one action.
    const gone = logAnalysisFailureMessage(new Error("log-analysis-binding-unavailable"), "fb");
    const stale = logAnalysisFailureMessage(new Error("log-analysis-snapshot-unavailable"), "fb");
    const busy = logAnalysisFailureMessage(new Error("log-analysis-capacity"), "fb");
    expect(new Set([gone, stale, busy]).size).toBe(3);
    expect(gone).toContain("重新连上");
    expect(stale).toContain("刷新日志源");
    expect(busy).toContain("等前面的读完");
    for (const text of [gone, stale, busy]) {
      // "or else close one" offers an alternative action, which is fine. What
      // is gone is the alternative *cause*: the page no longer says "cancelled,
      // or expired, or invalid" and leaves the reader to pick.
      expect(text).not.toContain("已取消");
      expect(text).not.toContain("返回内容无效");
      expect(text).not.toMatch(/log-analysis-/u);
    }
    const source = readFileSync(new URL("./LogAnalysisPage.tsx", import.meta.url), "utf8");
    expect(source).not.toContain("多源关联已取消、快照已过期或返回内容无效");
    expect(source).not.toContain("IOC 搜索已取消、快照已过期或返回内容无效");
    // Anything else keeps the caller's own sentence, which names that view.
    expect(logAnalysisFailureMessage(new Error("something-else"), "这句是兜底")).toContain("这句是兜底");
    expect(logAnalysisFailureMessage(undefined, "这句是兜底")).toContain("这句是兜底");
  });

  it("says where the paging is and whether the count is the whole of it", () => {
    // The count is derived from the paging, so while there is more to fetch it
    // can only be a floor. It says which of the two it is rather than printing
    // a number the reader would have to guess about.
    const middle = renderToStaticMarkup(
      <LogPagination page={3} result={{ ...readResult, hasMore: true }} busy={false}
        onPage={() => undefined} />,
    );
    expect(middle).toContain("第 3 页");
    expect(middle).toContain("本页 100 条");
    expect(middle).toContain("已翻出 300 条，后面还有");
    expect(middle).not.toContain("共 ");

    // On the last page the same number is exact, and it now says so.
    const last = renderToStaticMarkup(
      <LogPagination page={3} result={{ ...readResult, entryCount: 20, hasMore: false }}
        busy={false} onPage={() => undefined} />,
    );
    expect(last).toContain("共 220 条");
    expect(last).not.toContain("后面还有");

    // First page: nothing behind it, so going back is not offered.
    const first = renderToStaticMarkup(
      <LogPagination page={1} result={{ ...readResult, hasMore: true }} busy={false}
        onPage={() => undefined} />,
    );
    expect(first.match(/disabled=""/gu)?.length).toBe(3);
    // A box to type a page into, which is what a hundred pages of log needs.
    expect(first).toContain('aria-label="跳转到页码"');
    // While a read is in flight nothing in the pager is clickable.
    const busy = renderToStaticMarkup(
      <LogPagination page={2} result={{ ...readResult, hasMore: true }} busy
        onPage={() => undefined} />,
    );
    expect(busy.match(/disabled=""/gu)?.length).toBe(5);
  });

  it("uses global theme tokens with no color literals", () => {
    const css = readFileSync(new URL("./log-analysis-page.css", import.meta.url), "utf8");
    expect((css.match(/var\(--[a-z0-9-]+\)/gu) ?? []).length).toBeGreaterThan(30);
    expect(css).not.toMatch(/#[0-9a-f]{3,8}\b|rgba?\(|hsla?\(/iu);
  });
});



describe("what a log line is prefixed with", () => {
  const base = { highlighted: false, sourceHandle: null, sourceName: null, textTruncated: false, message: "" };
  it("adds only what the line does not already say, and never the parser's guesses", () => {
    // As read on lab-ubuntu: the parser took the program name into the time
    // and "with" for the service; the line already says all of it.
    const raw = "update-alternatives 2026-08-10 14:50:17: run with --install /usr/bin/awk awk /usr/bin/mawk 5";
    expect(logLineMeta({ ...base, rawText: raw, timestamp: "update-alternatives 2026-08-10 14:50:17:", level: "INFO", service: "with" })).toEqual([]);
    // A journal line whose text lacks the time and unit keeps both.
    expect(logLineMeta({ ...base, rawText: "Accepted password for root", timestamp: "2026-10-11 06:00:01", level: "warning", service: "sshd" }))
      .toEqual([{ kind: "time", text: "2026-10-11 06:00:01" }, { kind: "level", text: "warning" }, { kind: "service", text: "sshd" }]);
    // Mixed sources keep the name of the log each line came from.
    expect(logLineMeta({ ...base, rawText: "x", timestamp: "", level: "", service: "", sourceName: "auth.log" }))
      .toEqual([{ kind: "source", text: "auth.log" }]);
    // The line itself is always shown whole.
    const html = renderToStaticMarkup(<LogEntriesView entries={[{ ...base, rawText: raw, timestamp: "update-alternatives 2026-08-10 14:50:17:", level: "INFO", service: "with" }]} empty="x" />);
    expect(html).toContain("run with --install");
    expect(html).not.toContain("log-analysis-line-meta");
  });
});

describe("a discovery that came back partly", () => {
  it("says which half is missing", () => {
    expect(logDiscoveryGap([{ kind: "file" }, { kind: "file" }])).toContain("没有读到 journal");
    expect(logDiscoveryGap([{ kind: "journal" }])).toContain("没能列出日志文件");
    expect(logDiscoveryGap([])).toContain("下面不是全部");
  });
});

describe("copying a log result", () => {
  it("offers a named button and says what the copy did, failures as alerts", () => {
    const idle = renderToStaticMarkup(<LogResultCopy copy={{ notice: null, onCopy: () => undefined }} />);
    expect(idle).toContain('data-testid="log-analysis-copy"');
    expect(idle).toContain("复制分析结果");
    expect(idle).not.toContain('role="status"');
    const done = renderToStaticMarkup(<LogResultCopy copy={{
      notice: { tab: "browse", text: "已复制本页 2 条日志和威胁摘要（纯文本）。", failed: false },
      onCopy: () => undefined,
    }} />);
    expect(done).toMatch(/role="status">已复制本页 2 条日志和威胁摘要（纯文本）。</u);
    const failed = renderToStaticMarkup(<LogResultCopy copy={{
      notice: { tab: "ioc", text: "复制失败，请再试一次。", failed: true },
      onCopy: () => undefined,
    }} />);
    expect(failed).toMatch(/class="is-failed" role="alert">复制失败/u);
  });
});

describe("the operator's match rules on a page", () => {
  const hit = { id: "log-rule-0f8fad5b-d9cb-469f-a165-70867728950e", name: "webshell", severity: "high" as const };

  it("marks a matched line at its start, with the rule's name and level", () => {
    const html = renderToStaticMarkup(<LogEntriesView entries={[entry, { ...entry, rawText: "plain" }]} empty="none"
      hits={{ hits: [hit, null], ruleCount: 1, failed: false }} />);
    // The fixture line is also flagged suspicious; the two marks sit side by side.
    expect(html).toMatch(/<p class="is-abnormal has-rule"><span class="log-analysis-rule-hit is-high" data-testid="log-analysis-rule-hit" title="命中你的规则「webshell」，级别高">webshell<\/span>/u);
    expect(html.match(/data-testid="log-analysis-rule-hit"/gu)).toHaveLength(1);
  });

  it("says how many lines the rules marked, or that none did, or that it could not tell", () => {
    expect(renderToStaticMarkup(<LogRuleSummary hits={null} />)).toBe("");
    expect(renderToStaticMarkup(<LogRuleSummary hits={{ hits: [null], ruleCount: 0, failed: false }} />)).toBe("");
    expect(renderToStaticMarkup(<LogRuleSummary hits={{ hits: [hit, null, hit], ruleCount: 3, failed: false }} />))
      .toContain("2 行命中你的匹配规则，已在行首标出。");
    expect(renderToStaticMarkup(<LogRuleSummary hits={{ hits: [null], ruleCount: 3, failed: false }} />))
      .toContain("这些行没有命中你的 3 条匹配规则。");
    expect(renderToStaticMarkup(<LogRuleSummary hits={{ hits: [null], ruleCount: 0, failed: true }} />))
      .toContain("没能用匹配规则比对这些行");
  });
});
