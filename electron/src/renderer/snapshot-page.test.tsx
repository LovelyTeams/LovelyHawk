import { readFileSync } from "node:fs";

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type {
  ForensicSnapshotDetail,
  SnapshotDiffResult,
  SnapshotListResult,
  SnapshotReadApi,
} from "../shared/snapshot-read-contract";
import {
  forensicCollectors,
} from "../shared/snapshot-read-contract";
import {
  ForensicDetailContent,
  SnapshotDiffContent,
  SnapshotDirectoryView,
  SnapshotEmptyPanel,
  SnapshotErrorPanel,
  SnapshotPage,
  SnapshotStatusPanel,
} from "./SnapshotPage";

const hostile = "</pre><script>steal()</script><img src=x onerror=steal()>";
const redacted = "[SENSITIVE SNAPSHOT TEXT REDACTED]";
const api: SnapshotReadApi = {
  listSnapshots: async () => { throw new Error(); },
  getSnapshotDetail: async () => { throw new Error(); },
  diffForensicSnapshots: async () => { throw new Error(); },
};

const list: SnapshotListResult = {
  expiresInSeconds: 300,
  snapshots: [{
    snapshotHandle: "directory-opaque", kind: "directory", capturedAt: "2026-08-24T00:00:00Z",
    itemCount: 1, completedCollectors: null, failedCollectors: null,
  }],
  directoryCount: 1,
  forensicCount: 0,
  truncated: false,
};

const forensic: ForensicSnapshotDetail = {
  snapshotHandle: "forensic-opaque",
  kind: "forensic",
  capturedAt: "2026-08-24T00:00:00Z",
  totalCollectors: 12,
  completedCollectors: 12,
  failedCollectors: 1,
  fields: forensicCollectors.map((collector, index) => ({
    collector,
    text: index === 1 ? `${hostile}\n${redacted}` : "",
    redactedLineCount: index === 1 ? 1 : 0,
    truncated: index === 1,
  })),
  redactedLineCount: 1,
  truncated: true,
};

const diff: SnapshotDiffResult = {
  olderSnapshotHandle: "older-opaque",
  newerSnapshotHandle: "newer-opaque",
  fields: forensicCollectors.map((collector, index) => ({
    collector, added: index === 1 ? [hostile] : [], removed: index === 1 ? ["old plain text"] : [],
    redactedLineCount: 0, truncated: false,
  })),
  addedLineCount: 1,
  removedLineCount: 1,
  redactedLineCount: 0,
  truncated: false,
};

describe("SnapshotPage", () => {
  it("renders a disconnected honest read-only empty state", () => {
    const html = renderToStaticMarkup(<SnapshotPage bindingHandle={null} api={api} />);
    expect(html).toContain("连接 SSH 目标后");
    expect(html).toContain("只读查看");
    expect(html).not.toContain("directory-opaque");
  });

  it("renders directory metadata while explicitly marking remote availability not checked", () => {
    const html = renderToStaticMarkup(<SnapshotDirectoryView
      list={list} selectedHandle="directory-opaque" detailStatus="ready" search=""
      detail={{
        snapshotHandle: "directory-opaque", kind: "directory", capturedAt: "2026-08-24T00:00:00Z",
        items: [{
          preset: "etc", kind: "directory", bytes: "42", present: true, archiveAvailability: "not-checked",
        }],
        truncated: false,
      }} detailError={null} onSelect={() => undefined} />);
    expect(html).toContain("远端归档：未检查");
    expect(html).toContain("不代表远端归档当前存在、不可变或已重新验证");
    expect(html).toContain("42 bytes");
    expect(html).not.toContain("/tmp/.lovelyres_snap");
    expect(html).not.toContain("SHA-256");
  });

  it("renders hostile forensic text only as escaped text with redaction and truncation states", () => {
    const field = forensic.fields[1]!;
    const html = renderToStaticMarkup(<ForensicDetailContent detail={forensic} field={field}
      fieldText={field.text} collector="networkConnections" onCollector={() => undefined} search="" />);
    expect(html).toContain("&lt;/pre&gt;&lt;script&gt;steal()&lt;/script&gt;");
    expect(html).not.toContain("<script>");
    expect(html).toContain("已遮蔽 1 行");
    expect(html).toContain("文本已按行数或字节上限截断");
  });

  it("renders hostile added and removed diff lines only as escaped text", () => {
    const html = renderToStaticMarkup(<SnapshotDiffContent result={diff} field={diff.fields[1]!}
      collector="networkConnections" search="" />);
    expect(html).toContain("&lt;/pre&gt;&lt;script&gt;steal()&lt;/script&gt;");
    expect(html).not.toContain("<img src=x");
    expect(html).toContain("+ ");
    expect(html).toContain("- old plain text");
  });

  it("exposes explicit loading, error and empty states", () => {
    const html = [
      renderToStaticMarkup(<SnapshotStatusPanel label="正在读取…" />),
      renderToStaticMarkup(<SnapshotErrorPanel message="固定公开错误" />),
      renderToStaticMarkup(<SnapshotEmptyPanel title="空结果" detail="没有记录" compact />),
    ].join("");
    expect(html).toContain("aria-live=\"polite\"");
    expect(html).toContain("role=\"alert\"");
    expect(html).toContain("没有记录");
  });

  it("keeps phase one free of mutation, generic execution, file, terminal and export surfaces", () => {
    const source = readFileSync(new URL("./SnapshotPage.tsx", import.meta.url), "utf8");
    for (const forbidden of [
      ["createDirectory", "Snapshot"].join(""),
      ["captureForensic", "Snapshot"].join(""),
      ["restoreDirectory", "Snapshot"].join(""),
      ["deleteDirectory", "Snapshot"].join(""),
      ["confirmSnapshot", "Mutation"].join(""),
      ["exportForensic", "Snapshot"].join(""),
      ["open", "Terminal"].join(""),
      ["open", "File"].join(""),
      ["execute", "Command"].join(""),
      "dangerouslySetInnerHTML",
      "setInterval",
      "window.open",
    ]) expect(source).not.toContain(forbidden);
    expect(source).not.toMatch(/\b(?:sessionId|targetGeneration|guard|shell|remotePath|snapshotId|sha256)\s*:/u);
  });

  it("is centrally mounted with only the 请先建立 SSH 连接 capability", () => {
    const source = readFileSync(new URL("./App.tsx", import.meta.url), "utf8");
    expect(source).toContain('activePage.id === "snapshot"');
    expect(source).toContain("bindingHandle={activeTarget?.bindingHandle ?? null}");
    expect(source).not.toContain("<SnapshotPage connection={activeTarget}");
    expect(source).not.toMatch(/<SnapshotPage[\s\S]{0,200}target=\{/u);
  });

  it("uses global theme tokens with no color literals", () => {
    const css = readFileSync(new URL("./snapshot-page.css", import.meta.url), "utf8");
    expect((css.match(/var\(--[a-z0-9-]+\)/gu) ?? []).length).toBeGreaterThan(30);
    expect(css).not.toMatch(/#[0-9a-f]{3,8}|rgba?\(|hsla?\(/iu);
  });
});


