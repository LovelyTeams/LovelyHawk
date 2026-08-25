import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  cancelledDisposalReportExport,
  isInternalDisposalReportExportPayload,
  saveDisposalReportExport,
} from "./disposal-report-export-boundary";

const payload = {
  format: "html" as const,
  suggestedName: "LovelyRes-disposal-20260824-010203.html",
  mediaType: "text/html; charset=utf-8" as const,
  operationCount: 2,
  contents: "<!DOCTYPE html><script>hostile text stays file content</script>",
};

describe("disposal report native export boundary", () => {
  it("accepts only exact bounded format-consistent internal payloads", () => {
    expect(isInternalDisposalReportExportPayload(payload)).toBe(true);
    expect(isInternalDisposalReportExportPayload({ ...payload, path: "C:\\secret" })).toBe(false);
    expect(isInternalDisposalReportExportPayload({ ...payload, suggestedName: "../escape.html" })).toBe(false);
    expect(isInternalDisposalReportExportPayload({ ...payload, format: "markdown" })).toBe(false);
    expect(isInternalDisposalReportExportPayload({
      ...payload, contents: "x".repeat(512 * 1_024 + 1),
    })).toBe(false);
  });

  it("writes create-only with fsync and returns no absolute path or body", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyres-disposal-export-"));
    const destination = path.join(root, payload.suggestedName);
    try {
      const result = await saveDisposalReportExport(destination, payload);
      expect(result).toEqual({ saved: true, fileName: payload.suggestedName, operationCount: 2 });
      expect(fs.readFileSync(destination, "utf8")).toBe(payload.contents);
      await expect(saveDisposalReportExport(destination, payload)).rejects.toMatchObject({ code: "EEXIST" });
      expect(JSON.stringify(result)).not.toContain(root);
      expect(JSON.stringify(result)).not.toContain(payload.contents);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it("keeps cancellation path-free and rejects extension confusion", async () => {
    expect(cancelledDisposalReportExport()).toEqual({
      saved: false, fileName: null, operationCount: 0,
    });
    await expect(saveDisposalReportExport("C:\\report.md", payload)).rejects.toThrow(/extension/u);
  });
});
