import { describe, expect, it } from "vitest";
import fs from "node:fs";

import {
  isApplicationLogClearResult,
  isApplicationLogEntry,
  isApplicationLogExportResult,
  isApplicationLogFilter,
  isApplicationLogLevelResult,
  isApplicationLogPreview,
  isApplicationLogPublicMultiline,
  isApplicationLogSnapshot,
} from "./application-log-contract";

const entry = {
  sequence: 7,
  timestampUnixMs: 1_777_000_000_000,
  level: "warn",
  module: "lovelyres_backend",
  message: "hostile <script>alert(1)</script>",
  details: [{ name: "api_token", value: "[REDACTED]" }],
} as const;

describe("application log contract", () => {
  it("accepts only exact bounded filters and redacted structured entries", () => {
    expect(isApplicationLogFilter({ minimumLevel: null, search: "连接" })).toBe(true);
    expect(isApplicationLogFilter({ minimumLevel: "trace", search: "" })).toBe(false);
    expect(isApplicationLogFilter({ minimumLevel: null, search: "界".repeat(100) })).toBe(false);
    expect(isApplicationLogFilter({ minimumLevel: null, search: "", path: "C:\\data" })).toBe(false);
    expect(isApplicationLogFilter({ minimumLevel: null, search: "token=" })).toBe(true);
    expect(isApplicationLogFilter({ minimumLevel: null, search: "line\0break" })).toBe(false);
    expect(isApplicationLogEntry(entry)).toBe(true);
    expect(isApplicationLogEntry({ ...entry, stack: "C:\\private" })).toBe(false);
    expect(isApplicationLogEntry({ ...entry, details: Array.from({ length: 33 }, () => ({ name: "x", value: "y" })) })).toBe(false);
    expect(isApplicationLogEntry({ ...entry, message: "界".repeat(1_500) })).toBe(false);
    expect(isApplicationLogEntry({ ...entry, message: "password=hunter2" })).toBe(true);
    expect(isApplicationLogEntry({ ...entry, module: "https://user:pass@example.invalid/log" })).toBe(true);
    expect(isApplicationLogEntry({ ...entry, message: "safe\u0007text" })).toBe(false);
    expect(isApplicationLogEntry({ ...entry, message: "safe\u0085text" })).toBe(false);
    expect(isApplicationLogEntry({
      ...entry,
      details: [{ name: "api_token", value: "secret-without-marker" }],
    })).toBe(false);
  });

  it("validates a coherent 500-ring / 100-display snapshot", () => {
    expect(isApplicationLogSnapshot({
      capacity: 500,
      totalBuffered: 1,
      totalMatched: 1,
      displayed: 1,
      currentLevel: "info",
      generation: 9,
      entries: [entry],
    })).toBe(true);
    expect(isApplicationLogSnapshot({
      capacity: 500,
      totalBuffered: 0,
      totalMatched: 1,
      displayed: 1,
      currentLevel: "info",
      generation: 9,
      entries: [entry],
    })).toBe(false);
    expect(isApplicationLogSnapshot({
      capacity: 500,
      totalBuffered: 2,
      totalMatched: 2,
      displayed: 2,
      currentLevel: "info",
      generation: 9,
      entries: [entry, entry],
    })).toBe(false);
    expect(isApplicationLogSnapshot({
      capacity: 500,
      totalBuffered: 2,
      totalMatched: 2,
      displayed: 2,
      currentLevel: "info",
      generation: 9,
      entries: [{ ...entry, sequence: 6 }, { ...entry, sequence: 7 }],
    })).toBe(false);
  });

  it("requires honest volatile-clear and non-persisted level outcomes", () => {
    expect(isApplicationLogLevelResult({ level: "debug", persisted: false })).toBe(true);
    expect(isApplicationLogLevelResult({ level: "debug", persisted: true })).toBe(false);
    expect(isApplicationLogClearResult({
      clearedEntries: 2,
      volatileOnly: true,
      persistedFilesAffected: false,
      generation: 10,
    })).toBe(true);
    expect(isApplicationLogClearResult({
      clearedEntries: 2,
      volatileOnly: false,
      persistedFilesAffected: true,
      generation: 10,
    })).toBe(false);
  });

  it("bounds previews and keeps export results path/body free", () => {
    expect(isApplicationLogPreview({ content: "safe\n<script>plain text</script>", entryCount: 1, truncated: false })).toBe(true);
    expect(isApplicationLogPreview({ content: "x".repeat(128 * 1_024 + 1), entryCount: 1, truncated: false })).toBe(false);
    expect(isApplicationLogPreview({ content: "safe\0text", entryCount: 1, truncated: false })).toBe(false);
    expect(isApplicationLogPreview({ content: "password=hunter2", entryCount: 1, truncated: false })).toBe(true);
    expect(isApplicationLogPreview({
      content: "https://user:pass@example.invalid/log", entryCount: 1, truncated: false,
    })).toBe(true);
    expect(isApplicationLogPublicMultiline("line one\nline two", 64, true)).toBe(true);
    expect(isApplicationLogPublicMultiline("line one\rline two", 64, true)).toBe(false);
    expect(isApplicationLogExportResult({
      saved: true,
      fileName: "LovelyRes-diagnostics-123.log",
      entryCount: 2,
      truncated: false,
    })).toBe(true);
    expect(isApplicationLogExportResult({
      saved: true,
      fileName: "C:\\private\\logs.log",
      entryCount: 2,
      truncated: false,
    })).toBe(false);
    expect(isApplicationLogExportResult({
      saved: true,
      fileName: "LovelyRes-diagnostics-123.log",
      entryCount: 2,
      truncated: false,
      path: "C:\\private\\LovelyRes-diagnostics-123.log",
    })).toBe(false);
    expect(isApplicationLogExportResult({
      saved: true,
      fileName: "LovelyRes-diagnostics-123.log",
      entryCount: 2,
      truncated: false,
      contents: "must remain main-only",
    })).toBe(false);
    expect(isApplicationLogExportResult({
      saved: true,
      fileName: "LovelyRes\u0085diagnostics.log",
      entryCount: 2,
      truncated: false,
    })).toBe(false);
    expect(isApplicationLogExportResult({
      saved: false,
      fileName: null,
      entryCount: 2,
      truncated: false,
    })).toBe(false);
  });

  it("freezes the standalone future surface at exact five methods", () => {
    const source = fs.readFileSync(new URL("./application-log-contract.ts", import.meta.url), "utf8");
    const apiSource = source.split("export interface ApplicationLogApi {")[1]?.split("}\n\n")[0] ?? "";
    const methods = Array.from(apiSource.matchAll(/^\s{2}([A-Za-z][A-Za-z0-9]*)\(/gmu), (match) => match[1]);
    expect(methods).toEqual([
      "listApplicationLogs",
      "setApplicationLogLevel",
      "clearApplicationLogBuffer",
      "getApplicationLogPreview",
      "exportApplicationLogs",
    ]);
    expect(apiSource.match(/Promise<unknown>/gmu)).toHaveLength(5);
    expect(apiSource).not.toMatch(/invoke|shell|terminal|filePath|target|session|connection/iu);
  });
});
