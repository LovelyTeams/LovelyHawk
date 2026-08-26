import { readFileSync } from "node:fs";

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type {
  BaselineCatalog,
  BaselineHistory,
  BaselineReadApi,
  BaselineScan,
} from "../shared/baseline-read-contract";
import {
  BaselineChecksView,
  BaselineEmptyPanel,
  BaselineErrorPanel,
  BaselineHistoryView,
  BaselinePage,
  BaselineStatusPanel,
} from "./BaselinePage";

const hostile = "</code><script>plain()</script><img src=x onerror=plain()>";
const api: BaselineReadApi = {
  getBaselineCatalog: async () => { throw new Error(); },
  scanBaseline: async () => { throw new Error(); },
  listBaselineHistory: async () => { throw new Error(); },
  readBaselineFile: async () => { throw new Error(); },
};

const catalog: BaselineCatalog = {
  items: [{
    itemHandle: "item-a",
    category: "ssh",
    risk: "critical",
    valueKind: { kind: "choice", options: ["yes", "no"] },
    title: "关闭 SSH 密码认证",
    description: hostile,
    recommendation: "no",
  }],
  displayed: 1,
  truncated: false,
};

const scan: BaselineScan = {
  scanHandle: "scan-a",
  capturedAt: "2026-08-24T01:02:03Z",
  expiresInSeconds: 300,
  statuses: [{
    itemHandle: "item-a",
    observedKind: "value",
    observed: hostile,
    compliant: false,
    redacted: false,
    textTruncated: true,
  }],
  displayed: 1,
  compliantCount: 0,
  nonCompliantCount: 1,
  redactedFieldCount: 0,
  truncated: true,
};

const history: BaselineHistory = {
  historyHandle: "history-a",
  expiresInSeconds: 300,
  entries: [{
    historyItemHandle: "record-a",
    state: "applied",
    summary: hostile,
    changeCount: 1,
    createdAt: "2026-08-24T01:02:03Z",
    updatedAt: "2026-08-24T01:03:04Z",
    redacted: false,
    textTruncated: true,
  }],
  displayed: 1,
  redactedFieldCount: 0,
  truncated: true,
};

describe("central Baseline page", () => {
  it("renders an honest disconnected phase-one state without invented scan or history evidence", () => {
    const html = renderToStaticMarkup(<BaselinePage bindingHandle={null} api={api} />);
    expect(html).toContain("尚未连接 SSH 目标");
    expect(html).toContain("只读取固定目录");
    expect(html).toContain("正在读取随包分发的基线目录");
    expect(html).not.toContain("scan-a");
    expect(html).not.toContain("record-a");
  });

  it("renders explicit deactivation without retaining a target result surface", () => {
    const html = renderToStaticMarkup(
      <BaselinePage bindingHandle="binding-a" api={api} active={false} />,
    );
    expect(html).toContain("安全基线页面已停用");
    expect(html).toContain("切换页面会清空当前的扫描结果与历史");
    expect(html).not.toContain("scan-a");
    expect(html).not.toContain("record-a");
  });

  it("renders categories, compliance filters and hostile observations only as escaped plain text", () => {
    const html = renderToStaticMarkup(<BaselineChecksView
      catalog={catalog} status="ready" scan={scan} error={null} connected search="" category="all"
      compliance="all" onSearch={() => undefined} onCategory={() => undefined}
      onCompliance={() => undefined} onRefresh={() => undefined} />);
    expect(html).toContain("全部分类");
    expect(html).toContain("仅不符合");
    expect(html).toContain("SSH 安全");
    expect(html).toContain("不符合");
    expect(html).toContain("&lt;/code&gt;&lt;script&gt;plain()&lt;/script&gt;");
    expect(html).not.toContain("<script>");
    // Nothing is hidden any more, so there is no "已遮蔽" notice to show. What
    // is left is the honest one: a value that ran past the byte ceiling.
    expect(html).not.toContain("credential-like");
    expect(html).not.toContain("遮蔽");
    expect(html).toContain("手动扫描");
    // Without a selection the pane says what it is for rather than sitting blank.
    expect(html).toContain("右边会显示这项检查读的那个配置文件");
  });

  it("renders hostile history summaries as text with empty and truncated states", () => {
    const html = renderToStaticMarkup(<BaselineHistoryView status="ready" history={history}
      error={null} connected onRefresh={() => undefined} />);
    expect(html).toContain("&lt;/code&gt;&lt;script&gt;plain()&lt;/script&gt;");
    expect(html).not.toContain("<img src=x");
    expect(html).toContain("摘要已遮蔽或截断");
    expect(html).toContain("原始记录与备份证据不在此展示");

    const empty = renderToStaticMarkup(<BaselineHistoryView status="ready" history={{
      ...history, entries: [], displayed: 0, truncated: false,
    }} error={null} connected onRefresh={() => undefined} />);
    expect(empty).toContain("没有基线变更历史");
  });

  it("exposes explicit loading, error and filtered-empty surfaces", () => {
    const html = [
      renderToStaticMarkup(<BaselineStatusPanel label="正在读取有界状态…" />),
      renderToStaticMarkup(<BaselineErrorPanel message="固定公开错误" compact />),
      renderToStaticMarkup(<BaselineEmptyPanel title="没有匹配项" detail="调整筛选" compact />),
    ].join("");
    expect(html).toContain("aria-live=\"polite\"");
    expect(html).toContain("role=\"alert\"");
    expect(html).toContain("调整筛选");
  });

  it("keeps the page on the exact four read APIs with lifecycle cancellation and no action surfaces", () => {
    const source = readFileSync(new URL("./BaselinePage.tsx", import.meta.url), "utf8");
    const pane = readFileSync(new URL("./BaselineFilePane.tsx", import.meta.url), "utf8");
    for (const required of ["getBaselineCatalog()", "scanBaseline(bindingHandle)", "listBaselineHistory(bindingHandle)"])
      expect(source).toContain(required);
    // The file is opened by naming the check, never the file.
    expect(pane).toContain("api.readBaselineFile(bindingHandle, itemHandle)");
    expect(pane).not.toMatch(/readBaselineFile\([^)]*["'`]\//u);
    // A reply for a check the operator has moved on from is dropped.
    expect(pane).toContain("wanted.current !== itemHandle");
    expect(source.match(/let cancelled = false;/gu)?.length).toBe(3);
    expect(source.match(/cancelled = true;/gu)?.length).toBe(3);
    expect(source).toContain("bindingHandle: string | null");
    expect(source).not.toContain("SshTargetSummary");
    expect(source).not.toContain("connection.target");
    for (const forbidden of [
      ["plan", "Baseline"].join(""),
      ["confirm", "Baseline"].join(""),
      ["execute", "Baseline"].join(""),
      ["restore", "Baseline"].join(""),
      ["reload", "Baseline"].join(""),
      ["open", "Terminal"].join(""),
      ["open", "File"].join(""),
      ["export", "Baseline"].join(""),
      ["analyze", "BaselineWithAi"].join(""),
      "dangerouslySetInnerHTML",
      "TODO",
    ]) expect(source).not.toContain(forbidden);
    expect(source).not.toMatch(/\b(?:sessionId|targetGeneration|guard|shell|remotePath|recordId|operationId|digest|backup)\s*:/u);
  });

  it("is mounted by the configuration page with only the current binding and frozen API", () => {
    const app = readFileSync(new URL("./App.tsx", import.meta.url), "utf8");
    const host = readFileSync(new URL("./ConfigurationPage.tsx", import.meta.url), "utf8");
    // The shell hands the configuration page the binding and the frozen API,
    // and the configuration page hands the same two on to the checking half.
    expect(app).toMatch(
      /activePage\.id === "config-generator"[\s\S]*?<ConfigurationPage[\s\S]*?bindingHandle=\{activeTarget\?\.bindingHandle \?\? null\}[\s\S]*?api=\{window\.lovelyres\}/u,
    );
    expect(host).toContain("<BaselinePage bindingHandle={bindingHandle} api={api} embedded />");
    for (const mount of [
      app.match(/<ConfigurationPage[\s\S]*?\/>/u)?.[0] ?? "",
      host.match(/<BaselinePage[\s\S]*?\/>/u)?.[0] ?? "",
    ]) expect(mount).not.toMatch(/\b(?:target|connection|summary|session|guard)=/u);
    // Generating needs no target, and checking still lists what it would check
    // when there is none, so neither half is gated behind a connection.
    expect(host).not.toContain("bindingHandle === null");
  });

  it("uses global theme tokens with no color literals", () => {
    const css = readFileSync(new URL("./baseline-page.css", import.meta.url), "utf8");
    expect((css.match(/var\(--[a-z0-9-]+\)/gu) ?? []).length).toBeGreaterThan(30);
    expect(css).not.toMatch(/#[0-9a-f]{3,8}|rgba?\(|hsla?\(/iu);
    expect(css).toMatch(/\.baseline-card-bubble code \{[^}]*color: var\(--console-text\);[^}]*background: var\(--console-bg\);/u);
    // The bubble only exists on hover, so it must not be reachable by a stray
    // pointer event while it is invisible.
    expect(css).toMatch(/\.baseline-card-bubble \{[^}]*opacity: 0;[^}]*pointer-events: none;/u);
  });
});


