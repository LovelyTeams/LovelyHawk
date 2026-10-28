import type {
  DisposalReportContent,
  DisposalReportPreviewFormat,
  DisposalReportSummary,
} from "../shared/disposal-report-contract";

const encoder = new TextEncoder();

export function disposalReportPreviewLabel(format: DisposalReportPreviewFormat): string {
  switch (format) {
    case "summary": return "摘要纯文本";
    case "markdown": return "Markdown 纯文本";
    case "html": return "HTML 源码纯文本";
  }
}

/**
 * The host refuses an export in a sentence the operator can act on (the file
 * already exists, the extension does not match); those are passed on. A page
 * validation failure is an English programming message and is not.
 */
export function disposalReportExportFailure(reason: unknown): string {
  const message = reason instanceof Error ? reason.message.trim() : "";
  return /[一-鿿]/u.test(message) && !/[A-Za-z]{4,}/u.test(message)
    ? `处置报告没有导出：${message}`
    : "处置报告没有导出，请重试。";
}

export function disposalReportCopyText(content: DisposalReportContent): string {
  const maximum = content.format === "summary" ? 16 * 1_024 : 512 * 1_024;
  if (encoder.encode(content.content).byteLength > maximum) {
    throw new Error("disposal report copy exceeds the renderer budget");
  }
  return content.content;
}

export function disposalReportSummaryCards(summary: DisposalReportSummary): Array<[string, number]> {
  return [
    ["处置操作", summary.total],
    ["成功", summary.succeeded],
    ["失败", summary.failed],
    ["已恢复", summary.restored],
    ["待核验", summary.uncertain],
    ["可恢复", summary.recoverable],
  ];
}

export function nextDisposalReportFocus(
  currentIndex: number,
  count: number,
  backwards: boolean,
): number {
  if (count <= 0) return -1;
  if (currentIndex < 0) return backwards ? count - 1 : 0;
  return backwards ? (currentIndex - 1 + count) % count : (currentIndex + 1) % count;
}
