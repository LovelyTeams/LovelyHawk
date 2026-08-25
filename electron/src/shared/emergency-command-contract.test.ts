import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  isEmergencyCommandCatalog,
  isEmergencyCommandOpaqueHandle,
  isEmergencyCommandResult,
  type EmergencyCommandCatalog,
  type EmergencyCommandResult,
} from "./emergency-command-contract";

const catalog: EmergencyCommandCatalog = {
  snapshotHandle: "snapshot-opaque",
  expiresInSeconds: 300,
  commands: [{
    commandHandle: "command-opaque",
    category: "network",
    title: "监听端口",
    description: "只读收集监听状态。",
    timeoutSeconds: 30,
  }],
};

const result: EmergencyCommandResult = {
  snapshotHandle: "snapshot-opaque",
  commandHandle: "command-opaque",
  resultKind: "success",
  exitCode: 0,
  output: "</pre><script>steal()</script>\nplain evidence",
  observedLineCount: 2,
  displayedLineCount: 2,
  findingLines: [],
  findingReason: null,
  truncated: false,
};

describe("emergency command contract", () => {
  it("accepts exact bounded catalog and hostile plain-text output", () => {
    expect(isEmergencyCommandCatalog(catalog)).toBe(true);
    expect(isEmergencyCommandResult(result)).toBe(true);
  });

  /** The shipped catalog now carries well over a hundred entries. */
  it("admits the full catalog but still bounds its size", () => {
    const many = (count: number) => ({
      ...catalog,
      commands: Array.from({ length: count }, (_item, index) => ({
        ...catalog.commands[0], commandHandle: `opaque-handle-${index}`,
      })),
    });
    expect(isEmergencyCommandCatalog(many(200))).toBe(true);
    expect(isEmergencyCommandCatalog(many(257))).toBe(false);
  });

  it("rejects unknown keys, duplicate handles and internal metadata", () => {
    expect(isEmergencyCommandCatalog({ ...catalog, family: "debian" })).toBe(false);
    expect(isEmergencyCommandCatalog({
      ...catalog,
      commands: [...catalog.commands, { ...catalog.commands[0] }],
    })).toBe(false);
    expect(isEmergencyCommandCatalog({ ...catalog, expiresInSeconds: 301 })).toBe(false);
    expect(isEmergencyCommandCatalog({
      ...catalog,
      commands: [{ ...catalog.commands[0], command: "ss -tulpen" }],
    })).toBe(false);
  });

  it("rejects malformed handles, categories, timeouts and text controls", () => {
    expect(isEmergencyCommandOpaqueHandle("opaque-good-123")).toBe(true);
    for (const invalid of ["", "space value", "slash/value", "control\n", "x".repeat(129)]) {
      expect(isEmergencyCommandOpaqueHandle(invalid)).toBe(false);
    }
    expect(isEmergencyCommandCatalog({
      ...catalog,
      commands: [{ ...catalog.commands[0], category: "unknown" }],
    })).toBe(false);
    expect(isEmergencyCommandCatalog({
      ...catalog,
      commands: [{ ...catalog.commands[0], timeoutSeconds: 0 }],
    })).toBe(false);
    expect(isEmergencyCommandCatalog({
      ...catalog,
      commands: [{ ...catalog.commands[0], description: "line\nbreak" }],
    })).toBe(false);
  });

  /**
   * The tool runs against targets the operator owns, so output is shown as the
   * target printed it. Only what breaks rendering is refused.
   */
  it("passes credential-shaped output through and still refuses control characters", () => {
    for (const verbatim of [
      "root:$6$salt$hash:19000:0:99999:7:::",
      "Failed password for invalid user admin from 10.0.0.9",
      "ctf ALL=(ALL) NOPASSWD: ALL",
      "https://user:secret@example.internal/repo.git",
    ]) {
      expect(isEmergencyCommandResult({
        ...result, output: verbatim, observedLineCount: 1, displayedLineCount: 1,
      }), verbatim).toBe(true);
    }
    expect(isEmergencyCommandResult({
      ...result,
      output: "control\u0007character",
      observedLineCount: 1,
      displayedLineCount: 1,
    })).toBe(false);
    expect(isEmergencyCommandResult({
      ...result,
      observedLineCount: 3,
      truncated: false,
    })).toBe(false);
  });

  /** A highlight must point at a line that is still here and still readable. */
  it("bounds abnormal-line marks to readable displayed lines", () => {
    expect(isEmergencyCommandResult({ ...result, findingLines: [0, 1] })).toBe(true);
    expect(isEmergencyCommandResult({ ...result, findingLines: [2] })).toBe(false);
    expect(isEmergencyCommandResult({ ...result, findingLines: [1, 0] })).toBe(false);
    expect(isEmergencyCommandResult({ ...result, findingLines: [0, 0] })).toBe(false);
    expect(isEmergencyCommandResult({ ...result, findingLines: [-1] })).toBe(false);
    expect(isEmergencyCommandResult({ ...result, findingLines: ["0"] })).toBe(false);
    expect(isEmergencyCommandResult({ ...result, findingLines: 0 })).toBe(false);
  });

  it("requires the reason to be plain bounded text or nothing at all", () => {
    expect(isEmergencyCommandResult({ ...result, findingReason: "标红的行不在标准名单内。" })).toBe(true);
    expect(isEmergencyCommandResult({ ...result, findingReason: "line\nbreak" })).toBe(false);
    expect(isEmergencyCommandResult({ ...result, findingReason: "x".repeat(513) })).toBe(false);
    expect(isEmergencyCommandResult({ ...result, findingReason: 0 })).toBe(false);
    expect(isEmergencyCommandResult({ ...result, findingReason: undefined })).toBe(false);
  });

  it("enforces line, aggregate, serialized and result-kind semantics", () => {
    expect(isEmergencyCommandResult({ ...result, output: "x".repeat(4 * 1_024 + 1), observedLineCount: 1, displayedLineCount: 1 })).toBe(false);
    expect(isEmergencyCommandResult({ ...result, resultKind: "empty", output: "", observedLineCount: 0, displayedLineCount: 0 })).toBe(true);
    expect(isEmergencyCommandResult({ ...result, resultKind: "non-zero", exitCode: 7 })).toBe(true);
    expect(isEmergencyCommandResult({ ...result, resultKind: "unknown-exit", exitCode: 0 })).toBe(false);
    const escaped = "\\\"".repeat(90_000);
    expect(isEmergencyCommandResult({
      ...result,
      output: escaped,
      observedLineCount: 1,
      displayedLineCount: 1,
    })).toBe(false);
  });

  it("declares exactly two finite methods and no raw execution arguments", () => {
    const source = readFileSync(new URL("./emergency-command-contract.ts", import.meta.url), "utf8");
    const api = source.slice(source.indexOf("export interface EmergencyCommandApi"), source.indexOf("type JsonRecord"));
    expect(api.match(/^\s{2}[a-zA-Z].*Promise<unknown>;/gmu)).toHaveLength(2);
    expect(api).toContain("loadEmergencyCommandCatalog(bindingHandle: string)");
    expect(api).toContain("runEmergencyCommand(bindingHandle: string, snapshotHandle: string, commandHandle: string)");
    expect(api).not.toMatch(/\b(?:commandId|family|sessionId|generation|guard|host|path|shell|commandText)\b/u);
  });
});
