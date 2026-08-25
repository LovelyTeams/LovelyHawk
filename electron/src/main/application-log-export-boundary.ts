import fs from "node:fs";
import path from "node:path";

import {
  isApplicationLogPublicMultiline,
  type ApplicationLogExportResult,
} from "../shared/application-log-contract.js";

const MAX_EXPORT_BYTES = 256 * 1_024;

/** This payload is sidecar-to-main only and must never cross the renderer IPC boundary. */
export interface InternalApplicationLogExportPayload {
  format: "text";
  suggestedName: string;
  mediaType: "text/plain; charset=utf-8";
  entryCount: number;
  truncated: boolean;
  contents: string;
}

export function isInternalApplicationLogExportPayload(
  value: unknown,
): value is InternalApplicationLogExportPayload {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  return keys.length === 6 && keys.every((key) => [
    "format", "suggestedName", "mediaType", "entryCount", "truncated", "contents",
  ].includes(key)) && record.format === "text" && safeLogName(record.suggestedName) &&
    record.mediaType === "text/plain; charset=utf-8" &&
    typeof record.entryCount === "number" && Number.isSafeInteger(record.entryCount) &&
    record.entryCount >= 0 && record.entryCount <= 500 &&
    typeof record.truncated === "boolean" &&
    isApplicationLogPublicMultiline(record.contents, MAX_EXPORT_BYTES, true);
}

export function cancelledApplicationLogExport(): ApplicationLogExportResult {
  return { saved: false, fileName: null, entryCount: 0, truncated: false };
}

export async function saveApplicationLogExport(
  selectedPath: string,
  payload: InternalApplicationLogExportPayload,
): Promise<ApplicationLogExportResult> {
  if (!path.isAbsolute(selectedPath) || !isInternalApplicationLogExportPayload(payload)) {
    throw new Error("Invalid application log export boundary input.");
  }
  if (path.extname(selectedPath).toLowerCase() !== ".log") {
    throw new Error("The selected diagnostic log must use the .log extension.");
  }
  if (!safeLogName(path.basename(selectedPath))) {
    throw new Error("The selected diagnostic log name is not allowed.");
  }
  let file: fs.promises.FileHandle;
  try {
    file = await fs.promises.open(selectedPath, "wx", 0o600);
  } catch {
    throw new Error("Application log export could not create a new file.");
  }
  let failed = false;
  try {
    await file.writeFile(payload.contents, { encoding: "utf8" });
    await file.sync();
  } catch {
    failed = true;
  }
  try {
    await file.close();
  } catch {
    failed = true;
  }
  if (failed) throw new Error("Application log export could not be completed.");
  return {
    saved: true,
    fileName: path.basename(selectedPath),
    entryCount: payload.entryCount,
    truncated: payload.truncated,
  };
}

function safeLogName(value: unknown): value is string {
  return typeof value === "string" && value !== "" && value !== "." && value !== ".." &&
    Buffer.byteLength(value, "utf8") <= 240 && path.basename(value) === value &&
    path.extname(value).toLowerCase() === ".log" && value.toLowerCase() !== ".log" &&
    !/[\u0000-\u001f\u007f-\u009f<>:"/\\|?*]/u.test(value) && !/[. ]$/u.test(value);
}
