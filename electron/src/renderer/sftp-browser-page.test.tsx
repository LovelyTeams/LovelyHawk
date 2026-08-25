import { readFileSync } from "node:fs";

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type {
  SftpBrowserApi,
  SftpBrowserEntry,
  SftpTextPreview,
} from "../shared/sftp-browser-contract";
import {
  SftpBrowserEmpty,
  SftpBrowserError,
  SftpBrowserPage,
  SftpBrowserStatus,
  SftpBrowserWorkbench,
  SftpTextPreviewView,
} from "./SftpBrowserPage";

const api: SftpBrowserApi = {
  openSftpBrowser: async () => { throw new Error(); },
  listSftpDirectory: async () => { throw new Error(); },
  readSftpText: async () => { throw new Error(); },
};

const hostileName = "<script>steal()<img src=x onerror=steal()>";
const entries: SftpBrowserEntry[] = [
  { entryHandle: "opaque-directory", name: "配置目录", nameRedacted: false, nameTruncated: false,
    kind: "directory", action: "browse", sizeBytes: "4096", modifiedAt: null },
  { entryHandle: "opaque-file", name: hostileName, nameRedacted: false, nameTruncated: true,
    kind: "file", action: "preview", sizeBytes: "42", modifiedAt: "2026-08-24T10:00:00Z" },
  { entryHandle: "opaque-link", name: "latest", nameRedacted: false, nameTruncated: false,
    kind: "symlink", action: "none", sizeBytes: "7", modifiedAt: null },
];

const hostileText = "</pre><script>steal()</script><img src=x onerror=steal()>";
const preview: SftpTextPreview = {
  browserHandle: "opaque-browser",
  fileHandle: "opaque-file",
  text: `${hostileText}\n[SENSITIVE SFTP TEXT REDACTED]`,
  observedLineCount: 4,
  displayedLineCount: 2,
  redactedLineCount: 1,
  truncated: true,
};

describe("SftpBrowserPage", () => {
  it("renders honest disconnected and deactivated lifecycle states", () => {
    const disconnected = renderToStaticMarkup(<SftpBrowserPage connection={null} api={api} />);
    expect(disconnected).toContain("连接 SSH 目标后");
    expect(disconnected).toContain("可浏览服务器目录");
    const deactivated = renderToStaticMarkup(<SftpBrowserPage connection={{ bindingHandle: "binding-one" }}
      api={api} active={false} />);
    expect(deactivated).toContain("页面失活会清空目录与预览状态");
  });

  it("renders hostile entry names only as escaped text and exposes only capability-derived actions", () => {
    const fileHtml = renderToStaticMarkup(<SftpBrowserWorkbench entries={entries} selected={entries[1]!}
      selectedHandle="opaque-file" previewStatus="idle" preview={null} previewError={null} search="" busy={false}
      onSelect={() => undefined} onBrowse={() => undefined} onPreview={() => undefined} />);
    expect(fileHtml).toContain("&lt;script&gt;steal()&lt;img src=x onerror=steal()&gt;");
    expect(fileHtml).not.toContain("<script>");
    expect(fileHtml).not.toContain("<img src=x");
    expect(fileHtml).toContain("预览文本");
    expect(fileHtml).not.toContain("打开目录</button>");

    const symlinkHtml = renderToStaticMarkup(<SftpBrowserWorkbench entries={entries} selected={entries[2]!}
      selectedHandle="opaque-link" previewStatus="idle" preview={null} previewError={null} search="" busy={false}
      onSelect={() => undefined} onBrowse={() => undefined} onPreview={() => undefined} />);
    expect(symlinkHtml).toContain("符号链接不会跟随");
    expect(symlinkHtml).not.toContain("预览文本</button>");
    expect(symlinkHtml).not.toContain("打开目录</button>");
  });

  it("renders hostile preview content only in escaped pre text with truncation and redaction", () => {
    const html = renderToStaticMarkup(<SftpTextPreviewView preview={preview} />);
    expect(html).toContain("&lt;/pre&gt;&lt;script&gt;steal()&lt;/script&gt;");
    expect(html).not.toContain("<script>");
    expect(html).not.toContain("<img src=x");
    expect(html).toContain("已遮蔽 1 行");
    expect(html).toContain("文本已按 Electron");
  });

  it("exposes loading, error, empty and empty-preview states", () => {
    const emptyPreview = { ...preview, text: "", observedLineCount: 0, displayedLineCount: 0,
      redactedLineCount: 0, truncated: false };
    const html = [
      renderToStaticMarkup(<SftpBrowserStatus label="读取中…" />),
      renderToStaticMarkup(<SftpBrowserError message="固定公开错误" />),
      renderToStaticMarkup(<SftpBrowserEmpty title="空目录" detail="没有条目" />),
      renderToStaticMarkup(<SftpTextPreviewView preview={emptyPreview} />),
    ].join("");
    expect(html).toContain("aria-live=\"polite\"");
    expect(html).toContain("role=\"alert\"");
    expect(html).toContain("文件没有可显示文本");
  });

  it("calls exactly the three finite methods with opaque handles and cancels late lifecycle work", () => {
    const source = readFileSync(new URL("./SftpBrowserPage.tsx", import.meta.url), "utf8");
    expect(source).toContain("api.openSftpBrowser(bindingHandle)");
    expect(source).toContain("api.listSftpDirectory(");
    expect(source).toContain("api.readSftpText(bindingHandle, request.browserHandle, request.fileHandle)");
    expect(source).toContain("cancelled = true");
    expect(source).toContain('type: "deactivated"');
    for (const forbidden of [
      "dangerouslySetInnerHTML", "contentEditable", "<textarea", "setInterval", "window.open",
      "remotePath", "localPath", "sessionId:", "guard:", "generation:", "fingerprint:", "shellCommand",
      ["download", "Sftp"].join(""), ["upload", "Sftp"].join(""), ["rename", "Sftp"].join(""),
      ["delete", "Sftp"].join(""), ["open", "Terminal"].join(""), ["export", "Sftp"].join(""),
      ["plan", "Mutation"].join(""), ["run", "Command"].join(""),
    ]) expect(source).not.toContain(forbidden);
    const listArguments = source.match(/api\.listSftpDirectory\(([\s\S]*?)\)\.then/u)?.[1];
    const readArguments = source.match(/api\.readSftpText\(([\s\S]*?)\)\.then/u)?.[1];
    expect(listArguments?.split(",").map((value) => value.trim()).filter(Boolean)).toHaveLength(3);
    expect(readArguments?.split(",").map((value) => value.trim()).filter(Boolean)).toHaveLength(3);
  });

  it("uses global theme tokens with no color literals", () => {
    const css = readFileSync(new URL("./sftp-browser.css", import.meta.url), "utf8");
    expect((css.match(/var\(--[a-z0-9-]+\)/gu) ?? []).length).toBeGreaterThan(40);
    expect(css).not.toMatch(/#[0-9a-f]{3,8}|rgba?\(|hsla?\(/iu);
  });
});


