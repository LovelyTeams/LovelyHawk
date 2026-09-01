import { readFileSync } from "node:fs";

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { LocalBrowserApi } from "../shared/local-browser-contract";
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
  SftpBrowserTable,
  SftpTextPreviewView,
} from "./SftpBrowserPage";

const api: SftpBrowserApi & LocalBrowserApi = {
  openLocalBrowser: async () => { throw new Error(); },
  listLocalDirectory: async () => { throw new Error(); },
  openSftpBrowser: async () => { throw new Error(); },
  listSftpDirectory: async () => { throw new Error(); },
  readSftpText: async () => { throw new Error(); },
  downloadSftpEntry: async () => { throw new Error(); },
  planSftpOperation: async () => { throw new Error(); },
  confirmSftpOperation: async () => { throw new Error(); },
  executeSftpOperation: async () => { throw new Error(); },
  cancelSftpOperation: async () => { throw new Error(); },
  stageSftpUpload: async () => { throw new Error(); },
  openFileEditor: async () => ({ opened: true, reused: false }),
};

const hostileName = "<script>steal()<img src=x onerror=steal()>";
const entries: SftpBrowserEntry[] = [
  { entryHandle: "opaque-directory", name: "配置目录", nameTruncated: false,
    kind: "directory", action: "browse", sizeBytes: "4096", modifiedAt: null, mode: "0755", ownerId: 0, groupId: 0 },
  { entryHandle: "opaque-file", name: hostileName, nameTruncated: true,
    kind: "file", action: "preview", sizeBytes: "42", modifiedAt: "2026-08-24T10:00:00Z", mode: "0644", ownerId: 1000, groupId: 1000 },
  { entryHandle: "opaque-link", name: "latest", nameTruncated: false,
    kind: "symlink", action: "none", sizeBytes: "7", modifiedAt: null, mode: "0777", ownerId: 0, groupId: 0 },
];

const hostileText = "</pre><script>steal()</script><img src=x onerror=steal()>";
const preview: SftpTextPreview = {
  browserHandle: "opaque-browser",
  fileHandle: "opaque-file",
  text: `${hostileText}\n[SENSITIVE SFTP TEXT REDACTED]`,
  observedLineCount: 4,
  displayedLineCount: 2,
  truncated: true,
  sha256: "a".repeat(64),
  exact: false,
};

describe("SftpBrowserPage", () => {
  it("renders honest disconnected and deactivated lifecycle states", () => {
    const disconnected = renderToStaticMarkup(<SftpBrowserPage connection={null} api={api} />);
    expect(disconnected).toContain("连接 SSH 目标后");
    expect(disconnected).toContain("可浏览服务器目录");
    const deactivated = renderToStaticMarkup(<SftpBrowserPage connection={{ scopeKey: "binding-one" }}
      api={api} active={false} />);
    expect(deactivated).toContain("页面失活会清空目录与预览状态");
  });

  it("renders hostile entry names only as escaped text and exposes only capability-derived actions", () => {
    const rows = renderToStaticMarkup(<SftpBrowserTable entries={entries} selectedHandle="opaque-file"
      search="" busy={false} onSelect={() => undefined} onBrowse={() => undefined} />);
    expect(rows).toContain("&lt;script&gt;steal()&lt;img src=x onerror=steal()&gt;");
    expect(rows).not.toContain("<script>");
    expect(rows).not.toContain("<img src=x");
    // The row is a name/size/time record, not an action surface.
    expect(rows).not.toContain("预览文本");
    expect(rows).not.toContain("打开目录");

  });

  /** The design asks for a table; every column has to come from the contract. */
  it("lists entries as name, size and modified time", () => {
    const rows = renderToStaticMarkup(<SftpBrowserTable entries={entries} selectedHandle={null}
      search="" busy={false} onSelect={() => undefined} onBrowse={() => undefined} />);
    expect(rows).toContain("sftp-browser-row-name");
    expect(rows).toContain("sftp-browser-row-size");
    expect(rows).toContain("sftp-browser-row-time");
    // A directory has no meaningful byte count, so it shows none.
    expect(rows).toContain("—");

    const empty = renderToStaticMarkup(<SftpBrowserTable entries={[]} selectedHandle={null}
      search="" busy={false} onSelect={() => undefined} onBrowse={() => undefined} />);
    expect(empty).toContain("目录为空");
  });

  it("renders hostile preview content as escaped pre text without hiding anything", () => {
    const html = renderToStaticMarkup(<SftpTextPreviewView preview={preview} />);
    expect(html).toContain("&lt;/pre&gt;&lt;script&gt;steal()&lt;/script&gt;");
    expect(html).not.toContain("<script>");
    expect(html).not.toContain("<img src=x");
    // What the file holds reaches the operator; only rendering is made safe.
    expect(html).toContain("文本已按行数或大小上限截断");
  });

  it("exposes loading, error, empty and empty-preview states", () => {
    const emptyPreview = { ...preview, text: "", observedLineCount: 0, displayedLineCount: 0, truncated: false };
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
    expect(source).toContain("api.openSftpBrowser()");
    expect(source).toContain("api.listSftpDirectory(");
    expect(source).toContain("api.readSftpText(request.browserHandle, request.fileHandle)");
    // The window owns exactly one target, so the renderer never holds its handle.
    expect(source).not.toContain("bindingHandle");
    expect(source).toContain("cancelled = true");
    expect(source).toContain('type: "deactivated"');
    for (const forbidden of [
      "dangerouslySetInnerHTML", "contentEditable", "<textarea", "setInterval", "window.open",
      "remotePath", "localPath", "sessionId:", "guard:", "generation:", "fingerprint:", "shellCommand",
      ["upload", "Sftp"].join(""), ["rename", "Sftp"].join(""),
      ["delete", "Sftp"].join(""), ["open", "Terminal"].join(""), ["export", "Sftp"].join(""),
      ["plan", "Mutation"].join(""), ["run", "Command"].join(""),
    ]) expect(source).not.toContain(forbidden);
    const listArguments = source.match(/api\.listSftpDirectory\(([\s\S]*?)\)\.then/u)?.[1];
    const readArguments = source.match(/api\.readSftpText\(([\s\S]*?)\)\.then/u)?.[1];
    expect(listArguments?.split(",").map((value) => value.trim()).filter(Boolean)).toHaveLength(2);
    expect(readArguments?.split(",").map((value) => value.trim()).filter(Boolean)).toHaveLength(2);
  });

  it("uses global theme tokens with no color literals", () => {
    const css = readFileSync(new URL("./sftp-browser.css", import.meta.url), "utf8");
    expect((css.match(/var\(--[a-z0-9-]+\)/gu) ?? []).length).toBeGreaterThan(40);
    expect(css).not.toMatch(/#[0-9a-f]{3,8}|rgba?\(|hsla?\(/iu);
  });
});


