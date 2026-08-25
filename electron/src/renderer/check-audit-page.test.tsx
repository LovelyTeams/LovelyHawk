import { readFileSync } from "node:fs";

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type {
  CheckAuditCatalog,
  CheckAuditLogResult,
  CheckAuditReadApi,
  CheckAuditStatus,
} from "../shared/check-audit-read-contract";
import {
  AnalysisView,
  AuditLogEntries,
  CheckAuditPage,
  CommandsView,
  EmptyPanel,
  ErrorPanel,
  StatusPanel,
  SuggestionsView,
} from "./CheckAuditPage";

const hostile = "</pre><script>steal()</script><img src=x onerror=steal()>";
const api: CheckAuditReadApi = {
  getCheckAuditCatalog: async () => { throw new Error(); },
  collectCheckAuditStatus: async () => { throw new Error(); },
  readCheckAuditLog: async () => { throw new Error(); },
};

const catalog: CheckAuditCatalog = {
  snapshotHandle: "snapshot-1",
  expiresInSeconds: 300,
  commands: [{ commandHandle: "command-1", name: "cat", isDefault: true, critical: true }],
  customCount: 0,
};

const status: CheckAuditStatus = {
  snapshotHandle: "snapshot-1",
  isRoot: false,
  commands: [{
    commandHandle: "command-1",
    name: "cat",
    state: "original",
    critical: true,
    displayLocation: hostile,
    locationRedacted: false,
    textTruncated: false,
  }],
  redactedFieldCount: 0,
  truncated: false,
};

const result: CheckAuditLogResult = {
  snapshotHandle: "snapshot-1",
  limit: 200,
  fetchedCount: 3,
  matchedCount: 1,
  displayedCount: 1,
  suspiciousCount: 1,
  matchedSuspiciousCount: 1,
  entries: [{
    timestamp: "2026-08-24 01:02:03",
    command: "cat",
    args: hostile,
    user: hostile,
    pid: 10,
    ppid: 1,
    caller: hostile,
    suspicious: true,
    redacted: false,
    textTruncated: true,
  }],
  commandCounts: [{ command: "cat", count: 3, redacted: false, textTruncated: false }],
  cycles: [{
    command: "cat",
    args: hostile,
    intervalSeconds: 10,
    count: 3,
    lastSeen: hostile,
    category: "file-read",
    redacted: false,
    textTruncated: false,
  }],
  suggestions: [{
    severity: "critical",
    title: hostile,
    description: hostile,
    redacted: false,
    textTruncated: true,
  }],
  redactedFieldCount: 0,
  truncated: true,
};

describe("CheckAuditPage", () => {
  it("renders the disconnected phase-one empty state without invented evidence", () => {
    const html = renderToStaticMarkup(<CheckAuditPage bindingHandle={null} api={api} />);
    expect(html).toContain("连接 SSH 目标后");
    expect(html).toContain("周期行为与建议");
    expect(html).not.toContain("snapshot-");
  });

  it("renders hostile command locations only as escaped plain text", () => {
    const html = renderToStaticMarkup(<CommandsView
      catalog={catalog} statusKind="ready" status={status} error={null} search="" selectedName="cat"
      customCommands={[]} customDraft="" customError={null} onSearch={() => undefined}
      onSelect={() => undefined} onCustomDraft={() => undefined} onAddCustom={() => undefined}
      onRemoveCustom={() => undefined} onRefresh={() => undefined} />);
    expect(html).toContain("&lt;/pre&gt;&lt;script&gt;steal()&lt;/script&gt;");
    expect(html).not.toContain("<script>");
    expect(html).toContain("原始二进制");
  });

  it("renders hostile log arguments as escaped text with truncation state", () => {
    const html = renderToStaticMarkup(<AuditLogEntries entries={result.entries} />);
    expect(html).toContain("&lt;/pre&gt;&lt;script&gt;steal()&lt;/script&gt;");
    expect(html).not.toContain("<img src=x");
    expect(html).toContain("文本已截断");
    expect(html).toContain("PID 10 / PPID 1");
  });

  it("renders core-derived cycles and command-free recommendation text", () => {
    const analysis = renderToStaticMarkup(<AnalysisView status="ready" result={result} error={null}
      onRefresh={() => undefined} />);
    const suggestions = renderToStaticMarkup(<SuggestionsView status="ready" result={result} error={null}
      onRefresh={() => undefined} />);
    expect(analysis).toContain("约每 10 秒");
    expect(analysis).toContain("文件读取");
    expect(suggestions).toContain("高风险");
    expect(suggestions).toContain("建议文本已遮蔽或截断");
    expect(`${analysis}${suggestions}`).not.toContain("<script>");
  });

  it("exposes explicit loading, empty and fixed public error states", () => {
    const html = [
      renderToStaticMarkup(<StatusPanel label="正在读取审计日志…" />),
      renderToStaticMarkup(<EmptyPanel title="没有匹配日志" detail="有界空结果" compact />),
      renderToStaticMarkup(<ErrorPanel message="固定公开错误" compact />),
    ].join("");
    expect(html).toContain("aria-live=\"polite\"");
    expect(html).toContain("有界空结果");
    expect(html).toContain("role=\"alert\"");
  });

  it("keeps phase one free of mutation, execution, terminal, file and export surfaces", () => {
    const source = readFileSync(new URL("./CheckAuditPage.tsx", import.meta.url), "utf8");
    expect(source).toContain("bindingHandle: string | null;");
    expect(source).not.toContain("SshTargetSummary");
    expect(source).not.toContain("CheckAuditConnection");
    expect(source).not.toContain("connection.target");
    for (const forbidden of [
      ["deployCheck", "Audit"].join(""),
      ["restoreCheck", "Audit"].join(""),
      ["clearCheck", "AuditLog"].join(""),
      ["planCheck", "Audit"].join(""),
      ["confirmCheck", "Audit"].join(""),
      ["executeCheck", "Audit"].join(""),
      ["openAudit", "Terminal"].join(""),
      ["openAudit", "File"].join(""),
      ["exportAudit", "Log"].join(""),
      ".checkCommand",
      ".fixCommand",
      "dangerouslySetInnerHTML",
    ]) expect(source).not.toContain(forbidden);
    expect(source).not.toMatch(/\b(?:sessionId|targetGeneration|guard|shell|remotePath|path)\s*:/u);
  });

  it("uses global theme tokens with no color literals", () => {
    const css = readFileSync(new URL("./check-audit-page.css", import.meta.url), "utf8");
    expect((css.match(/var\(--[a-z0-9-]+\)/gu) ?? []).length).toBeGreaterThan(30);
    expect(css).not.toMatch(/#[0-9a-f]{3,8}|rgba?\(|hsla?\(/iu);
    expect(css).toMatch(/\.check-audit-log-list pre,[\s\S]*?color:\s*var\(--console-text\);[\s\S]*?background:\s*var\(--console-bg\);/u);
  });
});


