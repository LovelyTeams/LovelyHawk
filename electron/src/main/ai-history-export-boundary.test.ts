import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  cancelledAiHistoryExport,
  isInternalAiHistoryExportPayload,
  saveAiHistoryExport,
} from "./ai-history-export-boundary";

const payload = {
  suggestedName: "lovelyres-ai-history-42.txt",
  mediaType: "text/plain; charset=utf-8" as const,
  recordCount: 1,
  contents: "hostile </script> remains text",
};

describe("AI history native export boundary", () => {
  it("accepts only the exact bounded internal body shape", () => {
    expect(isInternalAiHistoryExportPayload(payload)).toBe(true);
    expect(isInternalAiHistoryExportPayload({ ...payload, path: "C:\\secret" })).toBe(false);
    expect(isInternalAiHistoryExportPayload({ ...payload, suggestedName: "../escape.txt" })).toBe(false);
    expect(isInternalAiHistoryExportPayload({ ...payload, contents: "x".repeat(8 * 1_024 * 1_024 + 1) })).toBe(false);
  });

  it("writes create-only and returns only basename and counts", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyres-ai-history-export-"));
    const destination = path.join(root, payload.suggestedName);
    try {
      const result = await saveAiHistoryExport(destination, payload);
      expect(result).toEqual({ saved: true, fileName: payload.suggestedName, recordCount: 1 });
      expect(fs.readFileSync(destination, "utf8")).toBe(payload.contents);
      await expect(saveAiHistoryExport(destination, payload)).rejects.toMatchObject({ code: "EEXIST" });
      expect(JSON.stringify(result)).not.toContain(root);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it("keeps cancellation path-free", () => {
    expect(cancelledAiHistoryExport()).toEqual({ saved: false, fileName: null, recordCount: 0 });
  });
});
