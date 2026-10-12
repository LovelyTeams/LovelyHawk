import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import fs from "node:fs";

import type {
  ApplicationLogApi,
  ApplicationLogSnapshot,
} from "../shared/application-log-contract";
import { ApplicationLogOverlay, applicationLogFileNote } from "./ApplicationLogOverlay";

const api: ApplicationLogApi = {
  listApplicationLogs: async () => ({}),
  setApplicationLogLevel: async () => ({}),
  clearApplicationLogBuffer: async () => ({}),
  getApplicationLogPreview: async () => ({}),
  exportApplicationLogs: async () => ({}),
};

const hostile = "</pre><img src=x onerror=steal()><script>bad()</script>";
const snapshot: ApplicationLogSnapshot = {
  capacity: 500,
  totalBuffered: 1,
  totalMatched: 1,
  displayed: 1,
  currentLevel: "warn",
  generation: 3,
  logFile: "writing",
  entries: [{
    sequence: 9,
    timestampUnixMs: 1_777_000_000_000,
    level: "error",
    module: "lovelyres_hostile",
    message: hostile,
    details: [{ name: "payload", value: hostile }],
  }],
};

describe("standalone application log overlay", () => {
  it("renders hostile fields only as escaped text nodes", () => {
    const html = renderToStaticMarkup(
      <ApplicationLogOverlay api={api} initialSnapshot={snapshot} />,
    );
    expect(html).toContain("&lt;img src=x onerror=steal()&gt;");
    expect(html).not.toContain("<img src=x");
    expect(html).not.toContain("<script>bad()");
    expect(html).not.toContain("dangerouslySetInnerHTML");
  });

  it("states the volatile clear and non-stderr security boundaries", () => {
    const html = renderToStaticMarkup(
      <ApplicationLogOverlay api={api} initialSnapshot={snapshot} />,
    );
    expect(html).toContain("当前进程内存缓冲 1/500");
    expect(html).toContain("日志同时写入程序旁的 data/logs/lovelyhawk.log");
    expect(html).toContain("“清空内存缓冲”只清这里，不动日志文件和之前导出的文件");
    expect(html).toContain('role="dialog"');
    expect(html).toContain('aria-modal="true"');
  });

  it("says where the log is kept for each file state, and raises a failed file", () => {
    expect(applicationLogFileNote("memory-only")).toContain("日志只保存在本次运行的内存中");
    expect(applicationLogFileNote(null)).toContain("日志只保存在本次运行的内存中");
    expect(applicationLogFileNote("writing")).toContain("程序重启后仍可查看");
    const failed = renderToStaticMarkup(
      <ApplicationLogOverlay api={api} initialSnapshot={{ ...snapshot, logFile: "failed" }} />,
    );
    expect(failed).toContain("日志文件写入失败");
    expect(failed).toMatch(/<footer class="application-log-footnote error" role="alert">/u);
  });

  it("does not expose paths, generic channels, or persistence claims", () => {
    const html = renderToStaticMarkup(<ApplicationLogOverlay api={api} />);
    expect(html).not.toContain("archiveRoot");
    expect(html).not.toContain("dataRoot");
    expect(html).not.toContain("ipcRenderer");
    expect(html).not.toContain("invoke(");
    expect(html).not.toContain("日志文件已删除");
  });

  it("invalidates late loads and operations before every close intent", () => {
    const source = fs.readFileSync(new URL("./ApplicationLogOverlay.tsx", import.meta.url), "utf8");
    const closeBody = source.split("const requestClose = useCallback(() => {")[1]
      ?.split("}, [beforeClose, onClose]);")[0] ?? "";
    expect(closeBody.indexOf("beforeClose()"))
      .toBeLessThan(closeBody.indexOf("onClose();"));
    expect(source).toContain("useImperativeHandle(ref, () => ({ beforeClose }), [beforeClose])");
    expect(source).toContain("deactivateApplicationLogOverlay(alive, request, operation)");
    expect(source).not.toContain("onClose?.()");
    expect(source).not.toContain("onClick={onClose}");
    expect(source).toContain("if (event.target === event.currentTarget) requestClose()");
    expect(source).toContain("if (!alive.current || request.current !== requestId) return");
    expect(source).toContain("if (!alive.current || operation.current !== operationId) return");
    expect(source).toContain("const previousFocus = returnFocusElement ??");
    expect(source).toContain("restoreApplicationLogFocus(previousFocus)");
    expect(source).not.toContain("isolateApplicationLogBackground");
  });

  it("places volatile clear on both sides of an in-flight list boundary", () => {
    const source = fs.readFileSync(new URL("./ApplicationLogOverlay.tsx", import.meta.url), "utf8");
    const clearBody = source.split("async function clearBuffer() {")[1]
      ?.split("async function copyPreview() {")[0] ?? "";
    expect(clearBody.match(/request\.current \+= 1/gmu)).toHaveLength(2);
    expect(clearBody).toContain('dispatch({ type: "buffer-cleared", generation: result.generation })');
    expect(clearBody).toContain("setRefreshVersion((version) => version + 1)");
  });
});
