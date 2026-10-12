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
  LogStatePanel,
  LogsView,
  StatusPanel,
  SuggestionsView,
} from "./CheckAuditPage";
import { CHECK_AUDIT_COPY_MAX_BYTES, CHECK_AUDIT_LOG_PATH, checkAuditLogTsv } from "./check-audit-read-helpers";

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
  logState: "read",
  malformedCount: 0,
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
    malformed: false,
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
  it("stops reading once the command list has expired, without cancelling a read on its way", () => {
    const source = readFileSync(new URL("./CheckAuditPage.tsx", import.meta.url), "utf8");
    // Both reads check expiry when they would start…
    expect(source.match(/\|\| expiredRef\.current\) return;/gu)).toHaveLength(2);
    // …through a ref, so expiry itself never re-runs (and cancels) a read.
    for (const deps of source.matchAll(/\}, \[([^\]]*)\]\);/gu)) {
      expect(deps[1]).not.toContain("catalogExpired");
    }
    // A refusal for a stale list settles it at once.
    expect(source).toContain('includes("check-audit-catalog-unavailable")');
    // The views' read buttons go off together, and say why.
    expect(source).toContain("disabled={loading || expired}");
    expect(source).toContain("disabled={status === \"loading\" || expired}");
    expect(source).toContain("命令列表已过期，先点右上角的“刷新命令列表”");
  });

  /**
   * A page must not claim to have hidden something it cannot hide.
   *
   * Filtering by credential shape was removed everywhere — it swallowed the
   * shadow and auth-log lines an audit exists to surface — but the notices it
   * had left behind stayed, wired to flags nothing sets. So the page carried a
   * counter permanently reading zero and a line promising that credential-like
   * fields had been hidden. In a tool for reading evidence, telling an operator
   * that something was kept from them is the direction that makes them stop
   * looking, and this one was not even true.
   */
  it("never tells the operator that something was hidden", () => {
    for (const file of ["CheckAuditPage.tsx", "BaselinePage.tsx"]) {
      const source = readFileSync(new URL(`./${file}`, import.meta.url), "utf8");
      expect(source, file).not.toContain("遮蔽");
      expect(source, file).not.toContain("credential-like");
      // The flags themselves are frozen into the response shape, but no page
      // may read one to decide what to say.
      expect(source, file).not.toMatch(/\.redacted\b|redactedFieldCount|locationRedacted/u);
    }
  });

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
    // A program without the collection wrapper is not claimed to be genuine.
    expect(html).toContain("未加采集");
    expect(html).not.toContain("原始二进制");
    expect(html).toContain("不代表它没被篡改");
    expect(html).not.toContain("check-audit-scripts");
  });

  it("calls out commands that run a script, by name", () => {
    const scripted = { ...status, commands: [{ ...status.commands[0]!, state: "foreign-script" as const, displayLocation: "/usr/local/bin/cat" }] };
    const html = renderToStaticMarkup(<CommandsView
      catalog={catalog} statusKind="ready" status={scripted} error={null} search="" selectedName={null}
      customCommands={[]} customDraft="" customError={null} onSearch={() => undefined}
      onSelect={() => undefined} onCustomDraft={() => undefined} onAddCustom={() => undefined}
      onRemoveCustom={() => undefined} onRefresh={() => undefined} />);
    expect(html).toContain('data-testid="check-audit-scripts"');
    expect(html).toContain("1 个命令执行的是脚本而不是程序文件：cat");
    expect(html).toContain("是脚本（非本工具）");
    expect(html).toContain("/usr/local/bin/cat");
  });

  it("explains a single-binary coreutils shim instead of raising it as a script", () => {
    const shimmed = { ...status, commands: [{ ...status.commands[0]!, state: "coreutils-shim" as const, displayLocation: "/usr/bin/cat" }] };
    const html = renderToStaticMarkup(<CommandsView
      catalog={catalog} statusKind="ready" status={shimmed} error={null} search="" selectedName={null}
      customCommands={[]} customDraft="" customError={null} onSearch={() => undefined}
      onSelect={() => undefined} onCustomDraft={() => undefined} onAddCustom={() => undefined}
      onRemoveCustom={() => undefined} onRefresh={() => undefined} />);
    expect(html).not.toContain('data-testid="check-audit-scripts"');
    expect(html).toContain('data-testid="check-audit-shims"');
    expect(html).toContain("转到 coreutils（发行版写法）");
    expect(html).toContain("/usr/bin/coreutils 本身是否被改过需要另行核对");
  });

  it("renders hostile log arguments as escaped text with truncation state", () => {
    const html = renderToStaticMarkup(<AuditLogEntries entries={result.entries} empty="x" />);
    expect(html).toContain("&lt;/pre&gt;&lt;script&gt;steal()&lt;/script&gt;");
    expect(html).not.toContain("<img src=x");
    expect(html).toContain("文本已截断");
    expect(html).toContain("PID 10 / PPID 1");
  });

  it("shows a line that is no record as written, never as a command", () => {
    const odd = { ...result.entries[0]!, timestamp: "", command: "", user: "", caller: "", pid: 0, ppid: 0,
      args: "rm -rf /tmp/x </pre>", malformed: true, textTruncated: false };
    const html = renderToStaticMarkup(<AuditLogEntries entries={[odd]} empty="x" />);
    expect(html).toContain("不是审计记录");
    expect(html).toContain("rm -rf /tmp/x &lt;/pre&gt;");
    expect(html).not.toContain("PID 0");
    expect(html).not.toContain("invalid-record");
  });

  it("says why there is no log, in every tab, and never shows it as an empty or clean log", () => {
    for (const logState of ["absent", "not-regular-file", "unreadable"] as const) {
      const unread = { ...result, logState, fetchedCount: 0, malformedCount: 0, matchedCount: 0, displayedCount: 0,
        suspiciousCount: 0, matchedSuspiciousCount: 0, entries: [], commandCounts: [], cycles: [], suggestions: [] };
      const views = [
        renderToStaticMarkup(<AnalysisView status="ready" result={unread} error={null} onRefresh={() => undefined} />),
        renderToStaticMarkup(<SuggestionsView status="ready" result={unread} error={null} onRefresh={() => undefined} />),
        renderToStaticMarkup(<LogStatePanel state={logState} />),
      ];
      for (const html of views) {
        expect(html, logState).toContain(`data-state="${logState}"`);
        expect(html, logState).not.toContain("没有识别到周期行为");
        expect(html, logState).not.toContain("没有生成建议");
      }
    }
    expect(renderToStaticMarkup(<LogStatePanel state="absent" />)).toContain("没有日志不代表这些命令没有被执行过");
    expect(renderToStaticMarkup(<LogStatePanel state="not-regular-file" />)).toContain("不跟随它");
    expect(renderToStaticMarkup(<LogStatePanel state="unreadable" />)).toContain("没有读到不代表没有记录");
    // The log location shown is the one the core reads.
    const core = readFileSync(new URL("../../../crates/lovelyhawk-core/src/audit.rs", import.meta.url), "utf8");
    expect(core).toContain(`const LOG_PATH: &str = "${CHECK_AUDIT_LOG_PATH}";`);
  });

  it("renders core-derived cycles and command-free recommendation text", () => {
    const analysis = renderToStaticMarkup(<AnalysisView status="ready" result={result} error={null}
      onRefresh={() => undefined} />);
    const suggestions = renderToStaticMarkup(<SuggestionsView status="ready" result={result} error={null}
      onRefresh={() => undefined} />);
    expect(analysis).toContain("约每 10 秒");
    expect(analysis).toContain("文件读取");
    expect(suggestions).toContain("高风险");
    // Truncation is the only thing that happens here. The page used to also
    // offer "hidden", for a flag nothing sets — an audit page claiming to have
    // hidden fields is the one lie that makes an operator stop looking.
    expect(suggestions).toContain("建议文本已截断");
    expect(`${analysis}${suggestions}`).not.toContain("遮蔽");
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

  it("copies the shown records as one line each, losing nothing inside a field", () => {
    const odd = { ...result.entries[0]!, timestamp: "", command: "", user: "", caller: "", pid: 0, ppid: 0,
      args: "free\ttext", malformed: true };
    const tsv = checkAuditLogTsv([
      { ...result.entries[0]!, args: "a\tb\nc\\d\r", caller: "cron" },
      odd,
    ]);
    const lines = tsv.split("\n");
    const cells = (index: number) => (lines[index] ?? "").split("\t");
    expect(lines).toHaveLength(4);
    expect(lines[3]).toBe("");
    expect(lines[0]).toBe("时间\t命令\t参数\t用户\tPID\tPPID\t调用者\t可疑\t格式");
    expect(cells(1)).toHaveLength(9);
    expect(lines[1]).toContain("a\\tb\\nc\\\\d\\r");
    expect(cells(1).slice(4, 8)).toEqual(["10", "1", "cron", "是"]);
    expect(cells(2)).toEqual(["", "", "free\\ttext", "", "", "", "", "是", "不是审计记录"]);
    expect(CHECK_AUDIT_COPY_MAX_BYTES).toBe(128 * 1_024);
    // The page checks the size the host will accept before it asks the host.
    const source = readFileSync(new URL("./CheckAuditPage.tsx", import.meta.url), "utf8");
    expect(source).toContain("byteLength > CHECK_AUDIT_COPY_MAX_BYTES");
    expect(source).toContain("if (writeClipboard === undefined || copying.current) return;");
    const host = readFileSync(new URL("../host/main-api.ts", import.meta.url), "utf8");
    expect(host).toContain(`const MAX_CLIPBOARD_BYTES = 128 * 1_024;`);
  });

  it("offers the copy only with a clipboard and records to copy", () => {
    const props = {
      status: "ready" as const, result, error: null, searchDraft: "", limitDraft: 200, inputError: null,
      onSearchDraft: () => undefined, onLimitDraft: () => undefined, onApply: () => undefined, onRefresh: () => undefined,
    };
    expect(renderToStaticMarkup(<LogsView {...props} />)).not.toContain("check-audit-copy");
    const offered = renderToStaticMarkup(<LogsView {...props} onCopy={() => undefined}
      copyNotice={{ ok: true, text: "已复制显示的 1 条（制表符分隔）。" }} />);
    expect(offered).toContain("复制显示的记录（TSV）");
    expect(offered).toContain('role="status"');
    const refused = renderToStaticMarkup(<LogsView {...props} onCopy={() => undefined} copyNotice={{ ok: false, text: "没有复制" }} />);
    expect(refused).toContain('role="alert"');
    const none = renderToStaticMarkup(<LogsView {...props} result={{ ...result, entries: [], displayedCount: 0, matchedCount: 0, matchedSuspiciousCount: 0 }}
      onCopy={() => undefined} />);
    expect(none).not.toContain("复制显示的记录");
  });

  it("changes the target only through planned, approved actions, and offers no terminal, file or export", () => {
    const source = readFileSync(new URL("./CheckAuditPage.tsx", import.meta.url), "utf8");
    const actions = readFileSync(new URL("./CheckAuditActions.tsx", import.meta.url), "utf8");
    expect(source).toContain("bindingHandle: string | null;");
    expect(source).not.toContain("SshTargetSummary");
    expect(source).not.toContain("CheckAuditConnection");
    expect(source).not.toContain("connection.target");
    for (const forbidden of [
      ["deployCheck", "Audit"].join(""),
      ["restoreCheck", "Audit"].join(""),
      ["clearCheck", "AuditLog"].join(""),
      ["openAudit", "Terminal"].join(""),
      ["openAudit", "File"].join(""),
      ["exportAudit", "Log"].join(""),
      ".checkCommand",
      ".fixCommand",
      "dangerouslySetInnerHTML",
    ]) {
      expect(source).not.toContain(forbidden);
      expect(actions).not.toContain(forbidden);
    }
    // The page never runs a change itself: only the actions component does,
    // and only after the plan was shown and approved.
    for (const call of ["planCheckAuditAction(", "confirmCheckAuditAction(", "executeCheckAuditAction("]) {
      expect(source).not.toContain(`api.${call}`);
    }
    expect(actions).toMatch(/await ask\([\s\S]*?confirmCheckAuditAction\([\s\S]*?executeCheckAuditAction\(/u);
    for (const text of [source, actions]) {
      expect(text).not.toMatch(/\b(?:sessionId|targetGeneration|guard|shell|remotePath|path)\s*:/u);
    }
  });

  it("uses global theme tokens with no color literals", () => {
    const css = readFileSync(new URL("./check-audit-page.css", import.meta.url), "utf8");
    expect((css.match(/var\(--[a-z0-9-]+\)/gu) ?? []).length).toBeGreaterThan(30);
    expect(css).not.toMatch(/#[0-9a-f]{3,8}\b|rgba?\(|hsla?\(/iu);
    expect(css).toMatch(/\.check-audit-log-list pre,[\s\S]*?color:\s*var\(--console-text\);[\s\S]*?background:\s*var\(--console-bg\);/u);
  });
});


