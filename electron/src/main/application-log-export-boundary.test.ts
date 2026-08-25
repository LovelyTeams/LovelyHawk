import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  cancelledApplicationLogExport,
  isInternalApplicationLogExportPayload,
  saveApplicationLogExport,
} from "./application-log-export-boundary";

const payload = {
  format: "text" as const,
  suggestedName: "LovelyRes-diagnostics-1777000000.log",
  mediaType: "text/plain; charset=utf-8" as const,
  entryCount: 2,
  truncated: false,
  contents: "[1777000000000] [WARN] [lovelyres_test] <script>plain text</script>",
};

describe("application log native export boundary", () => {
  it("accepts only exact bounded sidecar payloads", () => {
    expect(isInternalApplicationLogExportPayload(payload)).toBe(true);
    expect(isInternalApplicationLogExportPayload({ ...payload, path: "C:\\private" })).toBe(false);
    expect(isInternalApplicationLogExportPayload({ ...payload, suggestedName: "../escape.log" })).toBe(false);
    expect(isInternalApplicationLogExportPayload({ ...payload, suggestedName: "report.txt" })).toBe(false);
    expect(isInternalApplicationLogExportPayload({
      ...payload,
      contents: "界".repeat(256 * 1_024),
    })).toBe(false);
    expect(isInternalApplicationLogExportPayload({ ...payload, contents: "password=hunter2" })).toBe(true);
    expect(isInternalApplicationLogExportPayload({
      ...payload,
      contents: "https://user:pass@example.invalid/private",
    })).toBe(true);
    expect(isInternalApplicationLogExportPayload({ ...payload, contents: "safe\0text" })).toBe(false);
    expect(isInternalApplicationLogExportPayload({ ...payload, contents: "line one\nline two" })).toBe(true);
    expect(isInternalApplicationLogExportPayload({
      ...payload,
      contents: '[1] [WARN] [lovelyres] event | [{"name":"[SENSITIVE FIELD]","value":"[REDACTED]"}]',
    })).toBe(true);
  });

  it("writes create-only with fsync and returns no absolute path or content", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyres-application-log-export-"));
    const destination = path.join(root, payload.suggestedName);
    try {
      const result = await saveApplicationLogExport(destination, payload);
      expect(result).toEqual({
        saved: true,
        fileName: payload.suggestedName,
        entryCount: 2,
        truncated: false,
      });
      expect(fs.readFileSync(destination, "utf8")).toBe(payload.contents);
      const duplicateError = await saveApplicationLogExport(destination, payload)
        .then(() => null, (error: unknown) => error);
      expect(duplicateError).toBeInstanceOf(Error);
      expect(String(duplicateError)).toContain("could not create a new file");
      expect(String(duplicateError)).not.toContain(root);
      expect(String(duplicateError)).not.toContain(destination);
      expect(JSON.stringify(result)).not.toContain(root);
      expect(JSON.stringify(result)).not.toContain(payload.contents);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it("keeps cancellation path-free and rejects extension confusion", async () => {
    expect(cancelledApplicationLogExport()).toEqual({
      saved: false,
      fileName: null,
      entryCount: 0,
      truncated: false,
    });
    await expect(saveApplicationLogExport("C:\\report.txt", payload)).rejects.toThrow(/extension/u);
    await expect(saveApplicationLogExport(path.resolve("bad<name.log"), payload)).rejects.toThrow(/not allowed/u);
  });

  it("keeps payload bytes main-only behind create-only durable file handling", () => {
    const source = fs.readFileSync(
      new URL("./application-log-export-boundary.ts", import.meta.url),
      "utf8",
    );
    expect(source).toContain('fs.promises.open(selectedPath, "wx", 0o600)');
    expect(source).toContain("await file.sync()");
    expect(source).toContain("fileName: path.basename(selectedPath)");
    const rendererResult = source.split("await file.close();")[1]?.split("};")[0] ?? "";
    expect(rendererResult).not.toMatch(/\bpath\s*:/u);
    expect(rendererResult).not.toMatch(/\bcontents\s*:/u);
  });
});
