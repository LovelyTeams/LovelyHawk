import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  isSftpBrowserOpaqueHandle,
  isSftpDirectorySnapshot,
  isSftpOperationReceipt,
  isSftpOperationUndoResult,
  isSftpTransferCancelResult,
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
      kind: "directory", action: "browse", sizeBytes: "4096", modifiedAt: "2026-08-24T10:00:00+00:00", mode: "0755", ownerId: 0, groupId: 0 },
    { entryHandle: "opaque-file", name: "<script>evidence()", nameTruncated: false,
      kind: "file", action: "preview", sizeBytes: "42", modifiedAt: null, mode: "0644", ownerId: 1000, groupId: 1000 },
    { entryHandle: "opaque-link", name: "latest", nameTruncated: false,
      kind: "symlink", action: "none", sizeBytes: "12", modifiedAt: null, mode: "0777", ownerId: 0, groupId: 0 },
    { entryHandle: "opaque-secret-name", name: "[SENSITIVE NAME REDACTED]",
      nameTruncated: false, kind: "other", action: "none", sizeBytes: "0", modifiedAt: null, mode: null, ownerId: null, groupId: null },
  ],
};

const preview: SftpTextPreview = {
  browserHandle: "opaque-browser",
  fileHandle: "opaque-file",
  text: "<script>evidence()</script>\n[SENSITIVE SFTP TEXT REDACTED]",
  observedLineCount: 4,
  displayedLineCount: 2,
  truncated: true,
  sha256: "a".repeat(64),
  exact: false,
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
    // A file that is a single empty line is "\n", not "": the projection keeps
    // the newline, so the text and the count describe the same thing.
    expect(isSftpTextPreview({ ...preview, text: "\n", observedLineCount: 1, displayedLineCount: 1, truncated: false })).toBe(true);
    expect(isSftpTextPreview({ ...preview, text: "", observedLineCount: 1, displayedLineCount: 1, truncated: false })).toBe(false);
  });

  /**
   * The shape almost every real file has.
   *
   * Every fixture above stops without a final newline, and text files do not:
   * the projection keeps the trailing newline so that opening a file and
   * saving it back does not silently remove one. Splitting the raw text on
   * "\n" counts a line that is not there, which rejected every ordinary file
   * the moment the projection started being faithful — and no fixture noticed,
   * because none of them ended the way files end.
   */
  it("accepts text that ends the way text files end", () => {
    const cases: readonly (readonly [string, number])[] = [
      ["one\ntwo\nthree\n", 3],
      ["one\ntwo\nthree", 3],
      ["only\n", 1],
      ["only", 1],
      ["\n", 1],
      ["a\n\n", 2],
    ];
    for (const [text, displayedLineCount] of cases) {
      expect(
        isSftpTextPreview({ ...preview, text, displayedLineCount, observedLineCount: displayedLineCount, truncated: false }),
        text,
      ).toBe(true);
    }
    // The count still has to be the truth: one line too many or too few is
    // rejected exactly as before.
    for (const [text, displayedLineCount] of [["one\ntwo\n", 3], ["one\ntwo\n", 1]] as const) {
      expect(
        isSftpTextPreview({ ...preview, text, displayedLineCount, observedLineCount: displayedLineCount, truncated: false }),
        text,
      ).toBe(false);
    }
  });

  it("restricts opaque handles to bounded inert tokens", () => {
    expect(isSftpBrowserOpaqueHandle("opaque-ABC-123")).toBe(true);
    for (const invalid of ["", "has space", "../escape", "slash/value", "x".repeat(129)]) {
      expect(isSftpBrowserOpaqueHandle(invalid)).toBe(false);
    }
  });

  /**
   * Reading, plus the one transfer that needs no plan. Everything that changes
   * the target has to arrive through the plan/confirm pipeline instead, so
   * those names stay forbidden here until that pipeline exists.
   */
  /**
   * Reading, one transfer, and the plan pipeline. There is deliberately no
   * method that changes a target directly: every change is planned, confirmed
   * and executed as three separate steps.
   */
  it("offers an undo only on verified work, and bounds what the undo reports", () => {
    const receipt = {
      planHandle: "opaque-plan", kind: "remove", passed: true, detail: "原路径已不存在，可以恢复的备份还在。",
      restored: false, undoable: true, cancelled: false,
    };
    expect(isSftpOperationReceipt(receipt)).toBe(true);
    // A cancelled upload neither passed, nor was restored, nor can be undone.
    const cancelled = { ...receipt, kind: "upload", passed: false, undoable: false, cancelled: true };
    expect(isSftpOperationReceipt(cancelled)).toBe(true);
    expect(isSftpOperationReceipt({ ...cancelled, passed: true })).toBe(false);
    expect(isSftpOperationReceipt({ ...cancelled, restored: true })).toBe(false);
    expect(isSftpOperationReceipt({ ...cancelled, passed: true, undoable: true })).toBe(false);
    expect(isSftpTransferCancelResult({ cancelled: 0 })).toBe(true);
    expect(isSftpTransferCancelResult({ cancelled: 2 })).toBe(true);
    expect(isSftpTransferCancelResult({ cancelled: -1 })).toBe(false);
    expect(isSftpTransferCancelResult({ cancelled: 1, path: "C:\\x" })).toBe(false);
    expect(isSftpOperationReceipt({ ...receipt, undoable: false })).toBe(true);
    expect(isSftpOperationReceipt({ ...receipt, passed: false, undoable: false })).toBe(true);
    // A failed operation has nothing of its own to put back.
    expect(isSftpOperationReceipt({ ...receipt, passed: false, undoable: true })).toBe(false);
    const { undoable: _undoable, ...older } = receipt;
    expect(isSftpOperationReceipt(older)).toBe(false);

    const undone = { planHandle: "opaque-plan", kind: "remove", undone: true, detail: "文件已从备份移回原来的位置，并在目标机上核对过。" };
    expect(isSftpOperationUndoResult(undone)).toBe(true);
    expect(isSftpOperationUndoResult({ ...undone, undone: false })).toBe(true);
    expect(isSftpOperationUndoResult({ ...undone, kind: "shred" })).toBe(false);
    expect(isSftpOperationUndoResult({ ...undone, detail: "line\nbreak" })).toBe(false);
    expect(isSftpOperationUndoResult({ ...undone, path: "/etc/passwd" })).toBe(false);
  });

  it("keeps the public surface at exactly thirteen finite methods", () => {
    const source = readFileSync(new URL("./sftp-browser-contract.ts", import.meta.url), "utf8");
    const api = source.split("export interface SftpBrowserApi")[1]!.split("\n}")[0]!;
    expect([...api.matchAll(/^\s{2}([A-Za-z0-9]+)\(/gmu)].map((match) => match[1])).toEqual([
      "openSftpBrowser", "listSftpDirectory", "readSftpText", "downloadSftpEntry",
      "planSftpOperation", "confirmSftpOperation", "executeSftpOperation",
      "cancelSftpOperation", "undoSftpOperation", "cancelSftpTransfer", "stageSftpUpload", "openFileEditor",
      "openDirectoryTerminal",
    ]);
    // Transfers and operations name capabilities, never paths: main owns both
    // dialogs and the sidecar owns the staging area.
    expect(api).toContain("downloadSftpEntry(browserHandle: string, fileHandle: string)");
    // Staging takes at most a capability from the local pane, never a path.
    expect(api).toContain("stageSftpUpload(localFileHandle?: string): Promise<unknown>");
    // A terminal opens only in a folder the pane listed, named by its handles.
    expect(api).toContain(
      "openDirectoryTerminal(browserHandle: string, directoryHandle: string, name: string): Promise<unknown>",
    );
    for (const forbidden of [
      "sessionId:", "guard:", "generation:", "remotePath:", "localPath:", "command:", "shell:", "path:",
      ["delete", "Sftp"].join(""), ["rename", "Sftp"].join(""), ["chmod", "Sftp"].join(""),
      ["write", "Sftp"].join(""), ["open", "Terminal("].join(""), ["export", "Sftp"].join(""),
    ]) expect(api).not.toContain(forbidden);
  });
});
