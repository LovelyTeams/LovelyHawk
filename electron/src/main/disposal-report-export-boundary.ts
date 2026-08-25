import fs from "node:fs";
import path from "node:path";

import type { DisposalReportExportResult } from "../shared/disposal-report-contract.js";

const MAX_EXPORT_BYTES = 512 * 1_024;

export interface InternalDisposalReportExportPayload {
  format: "markdown" | "html";
  suggestedName: string;
  mediaType: "text/markdown; charset=utf-8" | "text/html; charset=utf-8";
  operationCount: number;
  contents: string;
}

export function isInternalDisposalReportExportPayload(
  value: unknown,
): value is InternalDisposalReportExportPayload {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length !== 5 || !keys.every((key) => [
    "format", "suggestedName", "mediaType", "operationCount", "contents",
  ].includes(key)) || !safeName(record.suggestedName) ||
    typeof record.operationCount !== "number" || !Number.isSafeInteger(record.operationCount) ||
    record.operationCount < 0 || record.operationCount > 2_000 ||
    typeof record.contents !== "string" || Buffer.byteLength(record.contents, "utf8") > MAX_EXPORT_BYTES) {
    return false;
  }
  if (record.format === "markdown") {
    return record.mediaType === "text/markdown; charset=utf-8" &&
      path.extname(record.suggestedName as string).toLowerCase() === ".md";
  }
  return record.format === "html" && record.mediaType === "text/html; charset=utf-8" &&
    path.extname(record.suggestedName as string).toLowerCase() === ".html";
}

export function cancelledDisposalReportExport(): DisposalReportExportResult {
  return { saved: false, fileName: null, operationCount: 0 };
}

export async function saveDisposalReportExport(
  selectedPath: string,
  payload: InternalDisposalReportExportPayload,
): Promise<DisposalReportExportResult> {
  if (!path.isAbsolute(selectedPath) || !isInternalDisposalReportExportPayload(payload)) {
    throw new Error("Invalid disposal report export boundary input.");
  }
  const requiredExtension = payload.format === "markdown" ? ".md" : ".html";
  if (path.extname(selectedPath).toLowerCase() !== requiredExtension) {
    throw new Error("The selected disposal report extension does not match its format.");
  }
  const file = await fs.promises.open(selectedPath, "wx", 0o600);
  try {
    await file.writeFile(payload.contents, { encoding: "utf8" });
    await file.sync();
  } finally {
    await file.close();
  }
  return {
    saved: true,
    fileName: path.basename(selectedPath),
    operationCount: payload.operationCount,
  };
}

function safeName(value: unknown): value is string {
  return typeof value === "string" && value !== "" && value !== "." && value !== ".." &&
    Buffer.byteLength(value, "utf8") <= 240 && path.basename(value) === value &&
    !/[\u0000-\u001f<>:"/\\|?*]/u.test(value) && !/[. ]$/u.test(value);
}
