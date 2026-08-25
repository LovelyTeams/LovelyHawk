import fs from "node:fs";
import path from "node:path";

import type { AiHistoryExportResult } from "../shared/ai-history-contract.js";

const MAX_EXPORT_BYTES = 8 * 1_024 * 1_024;

export interface InternalAiHistoryExportPayload {
  suggestedName: string;
  mediaType: "text/plain; charset=utf-8" | "application/json";
  recordCount: number;
  contents: string;
}

export function isInternalAiHistoryExportPayload(
  value: unknown,
): value is InternalAiHistoryExportPayload {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  return (
    keys.length === 4 &&
    keys.every((key) => ["suggestedName", "mediaType", "recordCount", "contents"].includes(key)) &&
    safeName(record.suggestedName) &&
    (record.mediaType === "text/plain; charset=utf-8" || record.mediaType === "application/json") &&
    typeof record.recordCount === "number" &&
    Number.isSafeInteger(record.recordCount) &&
    record.recordCount >= 0 &&
    record.recordCount <= 500 &&
    typeof record.contents === "string" &&
    Buffer.byteLength(record.contents, "utf8") <= MAX_EXPORT_BYTES
  );
}

export function cancelledAiHistoryExport(): AiHistoryExportResult {
  return { saved: false, fileName: null, recordCount: 0 };
}

export async function saveAiHistoryExport(
  selectedPath: string,
  payload: InternalAiHistoryExportPayload,
): Promise<AiHistoryExportResult> {
  if (
    !path.isAbsolute(selectedPath) ||
    !safeName(path.basename(selectedPath)) ||
    !isInternalAiHistoryExportPayload(payload)
  ) {
    throw new Error("Invalid AI history export boundary input.");
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
    recordCount: payload.recordCount,
  };
}

function safeName(value: unknown): value is string {
  return (
    typeof value === "string" &&
    Buffer.byteLength(value, "utf8") <= 240 &&
    value !== "" &&
    value !== "." &&
    value !== ".." &&
    path.basename(value) === value &&
    !/[\u0000-\u001f<>:"/\\|?*]/u.test(value) &&
    !/[. ]$/u.test(value)
  );
}
