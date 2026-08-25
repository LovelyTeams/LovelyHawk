import { readFileSync } from "node:fs";

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type {
  MiddlewareConfiguration,
  MiddlewareDiscovery,
  MiddlewareHistory,
  MiddlewareReadApi,
} from "../shared/middleware-read-contract";
import {
  MiddlewareConfigurationView,
  MiddlewareEmptyPanel,
  MiddlewareErrorPanel,
  MiddlewareHistoryView,
  MiddlewareInventoryView,
  MiddlewarePage,
  MiddlewareStatusPanel,
} from "./MiddlewarePage";

const hostile = "</pre><script>plain()</script><img src=x onerror=plain()>";
const api: MiddlewareReadApi = {
  discoverMiddleware: async () => { throw new Error(); },
  loadMiddlewareConfiguration: async () => { throw new Error(); },
  listMiddlewareHistory: async () => { throw new Error(); },
};

const discovery: MiddlewareDiscovery = {
  discoveryHandle: "discovery-a",
  expiresInSeconds: 300,
  instances: [{
    instanceHandle: "instance-a",
    title: "Nginx 实例 1",
    product: "nginx",
    version: hostile,
    status: "active",
    statusText: hostile,
    active: true,
    redacted: false,
    textTruncated: true,
  }],
  discoveredCount: 1,
  displayed: 1,
  redactedFieldCount: 0,
  truncated: true,
};

const configuration: MiddlewareConfiguration = {
  discoveryHandle: "discovery-a",
  instanceHandle: "instance-a",
  product: "nginx",
  loadedAt: "2026-08-24T01:02:03Z",
  totalBytes: "128",
  fileCount: 2,
  unresolvedIncludeCount: 1,
  directoryManifestCount: 1,
  files: [{
    fileHandle: "file-a",
    ordinal: 1,
    role: "primary",
    byteLength: "64",
    contentMode: "raw-text",
    rawText: hostile,
    rawTextUnavailableReason: "available",
    nodeCount: 1,
    displayedNodes: 1,
    nodes: [{ kind: "directive", name: "events", depth: 0, editable: false, sensitive: false,
      redacted: false, textTruncated: false }],
    containsSensitiveValues: false,
    redactedFieldCount: 0,
    truncated: false,
  }, {
    fileHandle: "file-b",
    ordinal: 2,
    role: "included",
    byteLength: "64",
    contentMode: "structured-only",
    rawText: null,
    rawTextUnavailableReason: "not-safe-text",
    nodeCount: 2,
    displayedNodes: 1,
    nodes: [{ kind: "attribute", name: hostile, depth: 1, editable: true, sensitive: true,
      redacted: false, textTruncated: true }],
    containsSensitiveValues: true,
    redactedFieldCount: 0,
    truncated: true,
  }],
  displayed: 2,
  displayedNodes: 2,
  redactedFieldCount: 0,
  truncated: true,
};

const history: MiddlewareHistory = {
  historyHandle: "history-a",
  expiresInSeconds: 300,
  entries: [{
    historyItemHandle: "record-a",
    product: "nginx",
    state: "applied",
    summary: "Nginx 配置记录：100 B → 120 B",
    oldBytes: "100",
    newBytes: "120",
    createdAt: "2026-08-24T01:02:03Z",
    updatedAt: "2026-08-24T01:03:04Z",
  }],
  recordCount: 2,
  displayed: 1,
  truncated: true,
};

describe("standalone Middleware page", () => {
  it("renders an honest disconnected read-only phase-one shell", () => {
    const html = renderToStaticMarkup(<MiddlewarePage bindingHandle={null} api={api} />);
    expect(html).toContain("尚未连接 SSH 目标");
    expect(html).toContain("只读");
    expect(html).toContain("只做只读查看");
    expect(html).toContain("连接 SSH 目标后才能发现实例");
    expect(html).not.toContain("discovery-a");
  });

  it("renders filters and hostile discovery text only as escaped plain text", () => {
    const html = renderToStaticMarkup(<MiddlewareInventoryView connected status="ready"
      discovery={discovery} error={null} selectedInstanceHandle="instance-a" search="" product="all"
      instanceStatus="all" onSearch={() => undefined} onProduct={() => undefined}
      onStatus={() => undefined} onSelect={() => undefined} onRefresh={() => undefined} />);
    expect(html).toContain("全部产品");
    expect(html).toContain("全部状态");
    expect(html).toContain("&lt;/pre&gt;&lt;script&gt;plain()&lt;/script&gt;");
    expect(html).not.toContain("<script>");
    expect(html).toContain("远端文本已遮蔽或截断");
    expect(html).toContain("结果已按文本、响应或 registry 预算截断");
  });

  it("renders core-safe raw text and structured-only summaries without path evidence", () => {
    const html = renderToStaticMarkup(<MiddlewareConfigurationView connected selected status="ready"
      configuration={configuration} error={null} onRefresh={() => undefined} />);
    expect(html).toContain("安全原文");
    expect(html).toContain("&lt;/pre&gt;&lt;script&gt;plain()&lt;/script&gt;");
    expect(html).toContain("仅结构摘要");
    expect(html).toContain("core 未授权安全原文");
    expect(html).toContain("属性");
    expect(html).toContain("配置结果已截断");
    for (const forbidden of ["/etc/nginx", "sha256", "nginx -t", "backup"]) expect(html).not.toContain(forbidden);
  });

  it("renders bounded history plus loading, error and empty surfaces", () => {
    const rendered = [
      renderToStaticMarkup(<MiddlewareHistoryView connected status="ready" history={history}
        error={null} onRefresh={() => undefined} />),
      renderToStaticMarkup(<MiddlewareStatusPanel label="正在读取有界视图…" />),
      renderToStaticMarkup(<MiddlewareErrorPanel message="固定公开错误" compact />),
      renderToStaticMarkup(<MiddlewareEmptyPanel title="空结果" detail="没有公开记录" compact />),
    ].join("");
    expect(rendered).toContain("Nginx 配置记录");
    expect(rendered).toContain("原始证据不在此展示");
    expect(rendered).toContain("aria-live=\"polite\"");
    expect(rendered).toContain("role=\"alert\"");
    expect(rendered).toContain("没有公开记录");
  });

  it("uses exactly three future APIs with lifecycle cancellation and no action surfaces", () => {
    const source = readFileSync(new URL("./MiddlewarePage.tsx", import.meta.url), "utf8");
    for (const required of [
      "discoverMiddleware(bindingHandle)",
      "loadMiddlewareConfiguration(",
      "listMiddlewareHistory(bindingHandle)",
    ]) expect(source).toContain(required);
    expect(source.match(/let cancelled = false;/gu)?.length).toBe(3);
    expect(source.match(/cancelled = true;/gu)?.length).toBe(3);
    expect(source).toContain("bindingHandle: string | null;");
    expect(source).not.toContain("SshTargetSummary");
    for (const forbidden of [
      ["plan", "Middleware"].join(""),
      ["confirm", "Middleware"].join(""),
      ["execute", "Middleware"].join(""),
      ["verify", "Middleware"].join(""),
      ["restore", "Middleware"].join(""),
      ["save", "Draft"].join(""),
      ["open", "Terminal"].join(""),
      ["open", "File"].join(""),
      ["export", "Middleware"].join(""),
      ["analyze", "MiddlewareWithAi"].join(""),
      "dangerouslySetInnerHTML",
      "TODO",
    ]) expect(source).not.toContain(forbidden);
    expect(source).not.toMatch(/\b(?:sessionId|targetGeneration|guard|binaryPath|configPath|includePath|backupPath|sha256|digest|shell|command)\s*:/u);

    const appSource = readFileSync(new URL("./App.tsx", import.meta.url), "utf8");
    expect(appSource).toMatch(
      /activePage\.id === "middleware"[\s\S]*?<MiddlewarePage[\s\S]*?bindingHandle=\{activeTarget\?\.bindingHandle \?\? null\}[\s\S]*?api=\{window\.lovelyres\}/u,
    );
    const mount = appSource.match(/<MiddlewarePage[\s\S]*?\/>/u)?.[0] ?? "";
    expect(mount).not.toContain("connection=");
    expect(mount).not.toContain("activeTarget.target");
  });

  it("uses global theme tokens with no color literals", () => {
    const css = readFileSync(new URL("./middleware-page.css", import.meta.url), "utf8");
    expect((css.match(/var\(--[a-z0-9-]+\)/gu) ?? []).length).toBeGreaterThan(35);
    expect(css).not.toMatch(/#[0-9a-f]{3,8}|rgba?\(|hsla?\(/iu);
  });
});


