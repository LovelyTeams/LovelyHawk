import path from "node:path";

import type {
  ConnectionExportResult,
  ConnectionImportResult,
  InternalConnectionExportResult,
  InternalConnectionImportResult,
} from "../shared/contract.js";

const MAX_SELECTED_PATH_BYTES = 32 * 1_024;

export function isSelectedConnectionJsonPath(value: unknown): value is string {
  return (
    typeof value === "string" &&
    Buffer.byteLength(value, "utf8") <= MAX_SELECTED_PATH_BYTES &&
    !value.includes("\0") &&
    path.isAbsolute(value) &&
    path.extname(value).toLocaleLowerCase() === ".json"
  );
}

export function cancelledConnectionImport(): ConnectionImportResult {
  return {
    cancelled: true,
    imported: 0,
    skippedExisting: 0,
    skippedDuplicate: 0,
  };
}

export function completedConnectionImport(
  result: InternalConnectionImportResult,
): ConnectionImportResult {
  return { cancelled: false, ...result };
}

export function cancelledConnectionExport(): ConnectionExportResult {
  return { cancelled: true, count: 0, fileName: null };
}

export function completedConnectionExport(
  result: InternalConnectionExportResult,
  selectedPath: string,
): ConnectionExportResult {
  const basename = path.basename(selectedPath);
  const fileName =
    basename.length > 0 &&
    Buffer.byteLength(basename, "utf8") <= 512 &&
    !/[\u0000-\u001f\u007f-\u009f/\\]/u.test(basename)
      ? basename
      : "lovelyres-connections.json";
  return {
    cancelled: false,
    count: result.count,
    fileName,
  };
}
