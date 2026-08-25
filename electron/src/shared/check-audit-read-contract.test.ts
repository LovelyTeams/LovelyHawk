import { describe, expect, it } from "vitest";

import {
  defaultCheckAuditCommands,
  isCheckAuditCatalog,
  isCheckAuditCatalogInput,
  isCheckAuditLogInput,
  isCheckAuditLogResult,
  isCheckAuditStatus,
} from "./check-audit-read-contract";

const hostile = "</td><script>steal()</script><img src=x onerror=steal()>";
const hostileUtf8 = "审计💥</td><script>steal()</script>Данные";
const redacted = "[SENSITIVE AUDIT TEXT REDACTED]";

const catalog = {
  snapshotHandle: "snapshot-1",
  expiresInSeconds: 300,
  commands: [...defaultCheckAuditCommands, "openssl"].map((name, index) => ({
    commandHandle: `command-${index}`,
    name,
    isDefault: index < defaultCheckAuditCommands.length,
    critical: name === "cat" || name === "bash" || name === "sh",
  })),
  customCount: 1,
};

const entry = {
  timestamp: "2026-08-24 01:02:03",
  command: "cat",
  args: hostile,
  user: hostile,
  pid: 10,
  ppid: 1,
  caller: hostile,
  suspicious: true,
  redacted: false,
  textTruncated: false,
};

describe("check audit read strict boundary", () => {
  it("accepts only the core-safe custom command-name grammar and exact inputs", () => {
    expect(isCheckAuditCatalogInput({ customCommandNames: ["openssl", "tool+v1"] })).toBe(true);
    for (const name of ["cat", "-rf", "cat;id", "../cat", "a b", "a\nwhoami", "x".repeat(129)]) {
      expect(isCheckAuditCatalogInput({ customCommandNames: [name] })).toBe(false);
    }
    expect(isCheckAuditCatalogInput({ customCommandNames: ["openssl", "openssl"] })).toBe(false);
    expect(isCheckAuditCatalogInput({ customCommandNames: [], command: "id" })).toBe(false);
    expect(isCheckAuditLogInput({ limit: 200, search: hostile })).toBe(true);
    expect(isCheckAuditLogInput({ limit: 201, search: null })).toBe(false);
    expect(isCheckAuditLogInput({ limit: 10, search: null, path: "/var/log/audit.log" })).toBe(false);
  });

  it("requires the fixed default catalog order and opaque unique handles", () => {
    expect(isCheckAuditCatalog(catalog)).toBe(true);
    expect(isCheckAuditCatalog({ ...catalog, sessionId: "secret" })).toBe(false);
    expect(isCheckAuditCatalog({
      ...catalog,
      commands: [catalog.commands[1], catalog.commands[0], ...catalog.commands.slice(2)],
    })).toBe(false);
    expect(isCheckAuditCatalog({
      ...catalog,
      commands: catalog.commands.map((command) => ({ ...command, commandHandle: "same" })),
    })).toBe(false);
  });

  it("validates status text without accepting backup, digest, path or action identity fields", () => {
    const status = {
      snapshotHandle: "snapshot-1",
      isRoot: false,
      commands: catalog.commands.map((command) => ({
        commandHandle: command.commandHandle,
        name: command.name,
        state: "original",
        critical: command.critical,
        displayLocation: command.name === "cat" ? redacted : `/usr/bin/${command.name}`,
        locationRedacted: command.name === "cat",
        textTruncated: false,
      })),
      redactedFieldCount: 1,
      truncated: false,
    };
    expect(isCheckAuditStatus(status)).toBe(true);
    expect(isCheckAuditStatus({ ...status, targetGeneration: 1 })).toBe(false);
    expect(isCheckAuditStatus({
      ...status,
      commands: [{ ...status.commands[0], path: "/usr/bin/cat" }],
    })).toBe(false);
    expect(isCheckAuditStatus({
      ...status,
      commands: [{ ...status.commands[0], originalSha256: "a".repeat(64) }],
    })).toBe(false);
    expect(isCheckAuditStatus({
      ...status,
      commands: [{ ...status.commands[0], displayLocation: "/usr/bin/token=secret-value" }],
    })).toBe(false);
  });

  it("accepts hostile log text as data while enforcing counts and aggregate bounds", () => {
    const result = {
      snapshotHandle: "snapshot-1",
      limit: 200,
      fetchedCount: 2,
      matchedCount: 1,
      displayedCount: 1,
      suspiciousCount: 2,
      matchedSuspiciousCount: 1,
      entries: [entry],
      commandCounts: [{ command: "cat", count: 2, redacted: false, textTruncated: false }],
      cycles: [{
        command: "cat",
        args: hostile,
        intervalSeconds: 10,
        count: 2,
        lastSeen: "2026-08-24 01:02:03",
        category: "file-read",
        redacted: false,
        textTruncated: false,
      }],
      suggestions: [{
        severity: "critical",
        title: hostile,
        description: hostile,
        redacted: false,
        textTruncated: false,
      }],
      redactedFieldCount: 0,
      truncated: false,
    };
    expect(isCheckAuditLogResult(result)).toBe(true);
    expect(isCheckAuditLogResult({ ...result, suspiciousCount: 1 })).toBe(true);
    expect(isCheckAuditLogResult({ ...result, suspiciousCount: 0 })).toBe(false);

    const boundaryCycles = [
      result.cycles[0],
      { ...result.cycles[0], command: hostileUtf8, args: hostileUtf8 },
    ];
    expect(isCheckAuditLogResult({
      ...result,
      fetchedCount: 4,
      cycles: boundaryCycles,
    })).toBe(true);
    expect(isCheckAuditLogResult({
      ...result,
      fetchedCount: 3,
      cycles: boundaryCycles,
    })).toBe(false);
    expect(isCheckAuditLogResult({ ...result, fetchedCount: 1 })).toBe(false);
    expect(isCheckAuditLogResult({ ...result, displayedCount: 2 })).toBe(false);
    expect(isCheckAuditLogResult({ ...result, command: "cat /etc/shadow" })).toBe(false);
  });

  it("rejects credential-like public text and suggestion command surfaces", () => {
    const base = {
      snapshotHandle: "snapshot-1",
      limit: 10,
      fetchedCount: 1,
      matchedCount: 1,
      displayedCount: 1,
      suspiciousCount: 1,
      matchedSuspiciousCount: 1,
      entries: [{ ...entry, args: redacted, redacted: true }],
      commandCounts: [{ command: "cat", count: 1, redacted: false, textTruncated: false }],
      cycles: [],
      suggestions: [],
      redactedFieldCount: 1,
      truncated: false,
    };
    expect(isCheckAuditLogResult(base)).toBe(true);
    expect(isCheckAuditLogResult({
      ...base,
      entries: [{ ...base.entries[0], args: "authorization: Bearer secret-value" }],
    })).toBe(true);
    const withSuggestion = {
      ...base,
      fetchedCount: 2,
      cycles: [{
        command: "cat", args: "", intervalSeconds: null, count: 2, lastSeen: "",
        category: "file-read", redacted: false, textTruncated: false,
      }],
      suggestions: [{
        severity: "critical", title: "review", description: "review", redacted: false,
        textTruncated: false,
      }],
    };
    expect(isCheckAuditLogResult(withSuggestion)).toBe(true);
    expect(isCheckAuditLogResult({
      ...withSuggestion,
      suggestions: [{ ...withSuggestion.suggestions[0], checkCommand: "cat /etc/shadow" }],
    })).toBe(false);
  });

  it("enforces the serialized response cap after JSON escaping", () => {
    const escapedEntry = {
      ...entry,
      timestamp: "",
      command: "",
      args: "\u0000".repeat(2 * 1_024),
      user: "",
      caller: "",
      suspicious: false,
    };
    expect(isCheckAuditLogResult({
      snapshotHandle: "snapshot-1",
      limit: 200,
      fetchedCount: 200,
      matchedCount: 200,
      displayedCount: 200,
      suspiciousCount: 0,
      matchedSuspiciousCount: 0,
      entries: Array.from({ length: 200 }, () => escapedEntry),
      commandCounts: [],
      cycles: [],
      suggestions: [],
      redactedFieldCount: 0,
      truncated: false,
    })).toBe(false);
  });
});
