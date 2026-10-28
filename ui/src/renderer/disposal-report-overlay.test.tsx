import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type {
  DisposalReportApi,
  DisposalReportContent,
  DisposalReportExportResult,
  DisposalReportSnapshot,
} from "../shared/disposal-report-contract";
import { DisposalReportOverlay } from "./DisposalReportOverlay";
import { disposalReportCopyText, disposalReportExportFailure, nextDisposalReportFocus } from "./disposal-report-helpers";

const api: DisposalReportApi = {
  generateDisposalReport: async () => ({}) as DisposalReportSnapshot,
  getDisposalReportContent: async () => ({}) as DisposalReportContent,
  exportDisposalReport: async () => ({}) as DisposalReportExportResult,
};

describe("standalone disposal report overlay", () => {
  it("SSR renders connection guidance without renderer report ingredients", () => {
    const html = renderToStaticMarkup(<DisposalReportOverlay activeTarget={null} api={api} />);
    expect(html).toContain("请先建立 SSH 连接");
    expect(html).not.toContain("TargetGuard");
    expect(html).not.toContain("operationEntries");
    expect(html).not.toContain("detectionReport");
    expect(html).not.toContain("dangerouslySetInnerHTML");
  });

  it("SSR shows only the safe active target summary, never binding capability", () => {
    const html = renderToStaticMarkup(<DisposalReportOverlay activeTarget={{
      bindingHandle: "opaque-report-binding",
      target: {
        connectionId: "server-1", host: "server.example", port: 22,
        username: "ops", timestamp: "now",
      },
    }} api={api} />);
    expect(html).toContain("ops@server.example:22");
    expect(html).not.toContain("opaque-report-binding");
    expect(html).toContain("尚无可预览报告。");
  });

  it("copy preserves hostile HTML as plain text and focus wraps", () => {
    const hostile = "<img src=x onerror=steal()>";
    expect(disposalReportCopyText({ format: "html", content: hostile })).toBe(hostile);
    expect(nextDisposalReportFocus(0, 3, true)).toBe(2);
    expect(nextDisposalReportFocus(2, 3, false)).toBe(0);
  });

  /** The host's reason reaches the operator; a page validation message does not. */
  it("says why an export was refused only when the host said it in words", () => {
    expect(disposalReportExportFailure(new Error("所选文件已存在。导出只创建新文件，请换一个文件名。")))
      .toBe("处置报告没有导出：所选文件已存在。导出只创建新文件，请换一个文件名。");
    expect(disposalReportExportFailure(new Error("The disposal report export response is invalid.")))
      .toBe("处置报告没有导出，请重试。");
    expect(disposalReportExportFailure("所选文件已存在。")).toBe("处置报告没有导出，请重试。");
  });
});
