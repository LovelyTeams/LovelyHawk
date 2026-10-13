import { describe, expect, it } from "vitest";

import type {
  LogCorrelationResult,
  LogIocSearchResult,
  LogSource,
  LogSourceReadResult,
  LogThreatSummary,
  PublicLogEntry,
} from "../shared/log-analysis-read-contract";
import {
  buildLogCorrelationReport,
  buildLogIocReport,
  buildLogReadReport,
  formatReportTime,
  LOG_REPORT_MAXIMUM_BYTES,
  plainReportText,
} from "./log-analysis-report";

const copiedAt = new Date(2026, 9, 13, 15, 4, 5);

function source(handle: string, name: string, location: string): LogSource {
  return {
    sourceHandle: handle, kind: "file", displayName: name, displayLocation: location,
    sizeBytes: 1_024, modified: "", pathHandle: null,
  };
}

function entry(text: string, highlighted = false, sourceName: string | null = null): PublicLogEntry {
  return {
    timestamp: "", level: "", service: "", message: "", rawText: text, highlighted,
    sourceHandle: null, sourceName, textTruncated: false,
  };
}

const quiet: LogThreatSummary = {
  bruteForceCount: 3, successfulLoginCount: 1, privilegeEscalationCount: 0, suspiciousActivityCount: 2,
  topSourceIps: [{ ip: "198.51.100.7", count: 3, lastSeen: "Oct 13 15:00:01", actionType: "failed-password" }],
  topTargetUsers: [{ username: "root", count: 4, successCount: 1, failCount: 3 }],
  hourlyDistribution: Array.from({ length: 24 }, (_, hour) => (hour === 15 ? 4 : 0)),
  threatLevel: "medium",
};

function read(entries: PublicLogEntry[], extra: Partial<LogSourceReadResult> = {}): LogSourceReadResult {
  return {
    snapshotHandle: "s", sourceHandle: "auth", sourceKind: "file", page: 2, pageSize: 100,
    entryCount: entries.length, highlightedCount: entries.filter((item) => item.highlighted).length,
    hasMore: true, entries, threatSummary: quiet, truncated: false, ...extra,
  };
}

const bytes = (value: string) => new TextEncoder().encode(value).byteLength;

describe("log analysis reports", () => {
  it("says what was read, from where, under which conditions and when", () => {
    const report = buildLogReadReport({
      source: source("auth", "auth.log", "/var/log/auth.log"),
      filter: { keyword: "Failed", date: "2026-10-13", journalUnit: "ignored for files" },
      result: read([entry("Oct 13 15:00:01 sshd[1]: Failed password for root", true), entry("ordinary line")]),
      copiedAt,
    });
    expect(report.omitted).toBe(0);
    const text = report.text;
    expect(text).toContain("# LovelyHawk 日志分析 · 日志浏览");
    expect(text).toContain("复制时间：2026-10-13 15:04:05（本机时间，UTC");
    expect(text).toContain("日志源：auth.log（/var/log/auth.log），文件日志");
    expect(text).toContain("读取条件：关键词 “Failed”；日期 2026-10-13");
    // A file has no journal unit; the condition is not invented for it.
    expect(text).not.toContain("Journal 单元");
    expect(text).toContain("范围：第 2 页，每页最多 100 条；本页 2 条，其中 1 条标为可疑；后面还有更多");
    expect(text).toContain("- 威胁等级：中（只按这里读到的行估计，不是对整台主机的结论）");
    expect(text).toContain("- 来源 IP：198.51.100.7（3 次，failed-password，最后 Oct 13 15:00:01）");
    expect(text).toContain("- 目标用户：root（4 次：成功 1 / 失败 3）");
    expect(text).toContain("- 有记录的小时：15:00 4");
    expect(text).toContain("1. [可疑] Oct 13 15:00:01 sshd[1]: Failed password for root");
    expect(text).toContain("2. ordinary line");
    expect(text).toContain("只读读取，没有改动目标机。");
    expect(text).toContain("不等于没有事件");
  });

  it("keeps hostile text as text, one line per entry", () => {
    const hostile = "a\nforged line\r\n\u001b[31mred\u001b[0m <script>alert(1)</script> \u202eevil\u2066";
    expect(plainReportText(hostile)).toBe("a forged line \ufffd[31mred\ufffd[0m <script>alert(1)</script> \ufffdevil\ufffd");
    const report = buildLogReadReport({
      source: source("auth", "a\nb", "/var/log/x"),
      filter: { keyword: "", date: "", journalUnit: "" },
      result: read([entry(hostile)]),
      copiedAt,
    });
    const lines = report.text.split("\n");
    expect(lines.filter((line) => line.startsWith("1. "))).toHaveLength(1);
    expect(report.text).not.toMatch(/[\u0000-\u0008\u000b-\u001f\u007f\u202e\u2066]/u);
    // Shown, not masked: the line is evidence.
    expect(report.text).toContain("<script>alert(1)</script>");
    expect(report.text).toContain("日志源：a b（/var/log/x）");
  });

  it("stays inside the clipboard limit and says how many lines did not fit", () => {
    const entries = Array.from({ length: 400 }, (_, index) => entry(`${index} ${"x".repeat(1_000)}`));
    const report = buildLogReadReport({
      source: source("auth", "auth.log", "/var/log/auth.log"),
      filter: { keyword: "", date: "", journalUnit: "" },
      result: read(entries, { truncated: true }),
      copiedAt,
    });
    expect(bytes(report.text)).toBeLessThanOrEqual(LOG_REPORT_MAXIMUM_BYTES);
    expect(report.omitted).toBeGreaterThan(0);
    expect(report.text).toContain(`（还有 ${report.omitted} 条没有复制：超出剪贴板上限。`);
    expect(report.text).toContain("注意：本页文本已按大小上限截断。");
    // The head and the closing note survive whatever is dropped.
    expect(report.text).toContain("## 威胁摘要");
    expect(report.text).toContain("只读读取，没有改动目标机。");
  });

  it("names every correlated source, even one the list no longer has", () => {
    const result: LogCorrelationResult = {
      snapshotHandle: "s", sourceHandles: ["a", "gone-handle-123"], coverage: "bounded-best-effort",
      totalObserved: 400, entries: [entry("one", false, "auth.log")], threatSummary: quiet, truncated: true,
    };
    const report = buildLogCorrelationReport({ sources: [source("a", "auth.log", "/var/log/auth.log")], result, copiedAt });
    expect(report.text).toContain("日志源（2 个）：auth.log（/var/log/auth.log）、（日志源列表已刷新，名称不可用：gone-han…）");
    expect(report.text).toContain("范围：每源最多观察 200 行，共观察 400 条，列出 1 条");
    expect(report.text).toContain("注意：结果已截断。");
    expect(report.text).toContain("1. [auth.log] one");
    expect(report.text).toContain("不代表未读取的范围");
  });

  it("lists what each indicator matched, and the ones that matched nothing", () => {
    const result: LogIocSearchResult = {
      snapshotHandle: "s",
      results: [{
        indicator: "198.51.100.7", sourceHandle: "a", sourceName: "auth.log", count: 3,
        sampleLines: ["Failed password from 198.51.100.7", "line\nbreak"], textTruncated: true,
      }],
      totalMatches: 3,
      truncated: false,
    };
    const report = buildLogIocReport({
      sources: [source("a", "auth.log", "/var/log/auth.log")],
      indicators: ["198.51.100.7", "evil.example"],
      sourceHandles: ["a"],
      result,
      copiedAt,
    });
    expect(report.text).toContain("IOC（2 个）：198.51.100.7、evil.example");
    expect(report.text).toContain("结果：共命中 3 次，涉及 1 个 IOC");
    expect(report.text).toContain("没有命中：evil.example");
    expect(report.text).toContain("- 198.51.100.7 @ auth.log：3 次（样例已截断）");
    expect(report.text).toContain("    Failed password from 198.51.100.7");
    expect(report.text).toContain("    line break");
    expect(report.text).toContain("没有命中只说明在所选日志源里没找到");
  });

  it("writes the time with its zone", () => {
    expect(formatReportTime(copiedAt)).toMatch(/^2026-10-13 15:04:05（本机时间，UTC[+-]\d{2}:\d{2}）$/u);
  });
});
