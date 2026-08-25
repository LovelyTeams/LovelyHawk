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

export function disposalReportCopyText(content: DisposalReportContent): string {
  const maximum = content.format === "summary" ? 16 * 1_024 : 512 * 1_024;
  if (encoder.encode(content.content).byteLength > maximum) {
    throw new Error("disposal report copy exceeds the renderer budget");
  }
  return content.content;
}

export function disposalReportSummaryCards(summary: DisposalReportSummary): Array<[string, number]> {
  return [
    ["审计操作", summary.total],
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
