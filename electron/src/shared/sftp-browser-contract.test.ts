import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  isSftpBrowserOpaqueHandle,
  isSftpDirectorySnapshot,
  isSftpTextPreview,
  type SftpDirectorySnapshot,
  type SftpTextPreview,
} from "./sftp-browser-contract";

const directory: SftpDirectorySnapshot = {
  browserHandle: "opaque-browser",
  directoryHandle: "opaque-directory",
  parentDirectoryHandle: null,
  directoryLabel: "根目录",
  directoryLabelTruncated: false,
  expiresInSeconds: 300,
  observedEntryCount: 4,
  displayedEntryCount: 4,
  truncated: false,
  entries: [
    { entryHandle: "opaque-dir", name: "etc", nameTruncated: false,
      kind: "directory", action: "browse", sizeBytes: "4096", modifiedAt: "2026-08-24T10:00:00+00:00" },
    { entryHandle: "opaque-file", name: "<script>evidence()", nameTruncated: false,
      kind: "file", action: "preview", sizeBytes: "42", modifiedAt: null },
    { entryHandle: "opaque-link", name: "latest", nameTruncated: false,
      kind: "symlink", action: "none", sizeBytes: "12", modifiedAt: null },
    { entryHandle: "opaque-secret-name", name: "[SENSITIVE NAME REDACTED]",
      nameTruncated: false, kind: "other", action: "none", sizeBytes: "0", modifiedAt: null },
  ],
};

const preview: SftpTextPreview = {
  browserHandle: "opaque-browser",
  fileHandle: "opaque-file",
  text: "<script>evidence()</script>\n[SENSITIVE SFTP TEXT REDACTED]",
  observedLineCount: 4,
  displayedLineCount: 2,
  truncated: true,
};

describe("sftp browser standalone contract", () => {
  it("accepts an exact bounded directory capability response", () => {
    expect(isSftpDirectorySnapshot(directory)).toBe(true);
  });

  /**
   * Remote names are the operator's evidence, so they cross as written. Only
   * what breaks rendering is refused.
   */
  it("accepts hostile names as data and refuses only control characters", () => {
    expect(isSftpDirectorySnapshot(directory)).toBe(true);
    for (const verbatim of ["password=keep-this", "id_rsa", "secret_key.pem", "</pre><script>"]) {
      const named = structuredClone(directory);
      named.entries[1]!.name = verbatim;
      expect(isSftpDirectorySnapshot(named), verbatim).toBe(true);
    }
    const control = structuredClone(directory);
    control.entries[1]!.name = "tab\u0009name";
    expect(isSftpDirectorySnapshot(control)).toBe(false);
  });

  it("rejects symlink/file actions and handle aliasing", () => {
    for (const mutation of [
      (value: SftpDirectorySnapshot) => { value.entries[2]!.action = "browse"; },
      (value: SftpDirectorySnapshot) => { value.entries[1]!.action = "browse"; },
      (value: SftpDirectorySnapshot) => { value.entries[0]!.entryHandle = value.directoryHandle; },
      (value: SftpDirectorySnapshot) => { value.parentDirectoryHandle = value.directoryHandle; },
    ]) {
      const changed = structuredClone(directory);
      mutation(changed);
      expect(isSftpDirectorySnapshot(changed)).toBe(false);
    }
  });

  it("rejects extra keys, inconsistent counts, invalid timestamps and oversized lists", () => {
    expect(isSftpDirectorySnapshot({ ...directory, remotePath: "/etc" })).toBe(false);
    expect(isSftpDirectorySnapshot({ ...directory, displayedEntryCount: 3 })).toBe(false);
    expect(isSftpDirectorySnapshot({ ...directory, truncated: true })).toBe(false);
    const invalidDate = structuredClone(directory);
    invalidDate.entries[0]!.modifiedAt = "not-a-date";
    expect(isSftpDirectorySnapshot(invalidDate)).toBe(false);
    expect(isSftpDirectorySnapshot({ ...directory, entries: Array.from({ length: 129 }, (_, index) => ({
      ...directory.entries[1]!, entryHandle: `opaque-${index}`,
    })), displayedEntryCount: 129, observedEntryCount: 129 })).toBe(false);
  });

  it("accepts bounded hostile preview text and enforces redaction semantics", () => {
    expect(isSftpTextPreview(preview)).toBe(true);
    expect(isSftpTextPreview({ ...preview, text: "token=do-not-render\nplain", redactedLineCount: 0 })).toBe(false);
    expect(isSftpTextPreview({ ...preview, text: "[SENSITIVE SFTP TEXT REDACTED] spoof",
      displayedLineCount: 1, redactedLineCount: 0 })).toBe(false);
    expect(isSftpTextPreview({ ...preview, text: "x".repeat(4 * 1_024 + 1),
      observedLineCount: 1, displayedLineCount: 1, truncated: true })).toBe(false);
  });

  it("handles empty text without inventing content", () => {
    expect(isSftpTextPreview({ ...preview, text: "", observedLineCount: 0, displayedLineCount: 0, truncated: false })).toBe(true);
    expect(isSftpTextPreview({ ...preview, text: "", observedLineCount: 1, displayedLineCount: 1, truncated: false })).toBe(true);
  });

  it("restricts opaque handles to bounded inert tokens", () => {
    expect(isSftpBrowserOpaqueHandle("opaque-ABC-123")).toBe(true);
    for (const invalid of ["", "has space", "../escape", "slash/value", "x".repeat(129)]) {
      expect(isSftpBrowserOpaqueHandle(invalid)).toBe(false);
    }
  });

  it("keeps the future public surface at exactly three finite methods", () => {
    const source = readFileSync(new URL("./sftp-browser-contract.ts", import.meta.url), "utf8");
    const api = source.split("export interface SftpBrowserApi")[1]!.split("}")[0]!;
    expect([...api.matchAll(/^\s{2}([A-Za-z0-9]+)\(/gmu)].map((match) => match[1])).toEqual([
      "openSftpBrowser", "listSftpDirectory", "readSftpText",
    ]);
    for (const forbidden of [
      "sessionId:", "guard:", "generation:", "remotePath:", "localPath:", "command:",
      ["download", "Sftp"].join(""), ["upload", "Sftp"].join(""), ["delete", "Sftp"].join(""),
      ["open", "Terminal"].join(""), ["export", "Sftp"].join(""),
    ]) expect(api).not.toContain(forbidden);
  });
});
