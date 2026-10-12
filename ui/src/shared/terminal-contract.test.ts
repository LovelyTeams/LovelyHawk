import { describe, expect, it } from "vitest";

import {
  clampTerminalSize,
  isTerminalClosed,
  isTerminalInputAcknowledgement,
  isTerminalOpened,
  isTerminalPoll,
  isTerminalPollBounds,
  isTerminalRenderSnapshot,
  isTerminalResized,
  isTerminalSearch,
  isTerminalSearchRequest,
  isTerminalSelectionCopyText,
  isTerminalSize,
  isTerminalWindowLaunchResult,
  isTerminalWindowOpened,
  terminalBase64DecodedLength,
  TERMINAL_LIMITS,
} from "./terminal-contract";

const handle = "11111111-2222-4333-8444-555555555555";

describe("standalone terminal contract", () => {
  it("accepts only exact open, acknowledgement, resize and close DTOs", () => {
    expect(isTerminalOpened({ handle, columns: 80, rows: 24 })).toBe(true);
    expect(isTerminalOpened({ handle, columns: 80, rows: 24, sessionId: "leak" })).toBe(false);
    expect(isTerminalOpened({ handle: "not-a-uuid", columns: 80, rows: 24 })).toBe(false);
    expect(isTerminalWindowLaunchResult({ opened: true, reused: false })).toBe(true);
    expect(isTerminalWindowLaunchResult({ opened: true, reused: false, bindingHandle: handle })).toBe(false);
    expect(isTerminalWindowOpened({ columns: 80, rows: 24 })).toBe(true);
    expect(isTerminalWindowOpened({ columns: 80, rows: 24, handle })).toBe(false);

    expect(isTerminalInputAcknowledgement({ acceptedBytes: 3 })).toBe(true);
    expect(isTerminalInputAcknowledgement({ acceptedBytes: 0 })).toBe(false);
    expect(isTerminalInputAcknowledgement({ acceptedBytes: 3, command: "whoami" })).toBe(false);
    expect(isTerminalResized({ columns: 160, rows: 60 })).toBe(true);
    expect(isTerminalResized({ columns: 161, rows: 60 })).toBe(false);
    expect(isTerminalClosed({ closed: true })).toBe(true);
    expect(isTerminalClosed({ closed: true, path: "/tmp/session" })).toBe(false);
  });

  it("pins dimension, poll and search bounds to the Rust boundary", () => {
    expect(isTerminalSize(1, 1)).toBe(true);
    expect(isTerminalSize(TERMINAL_LIMITS.maximumColumns, TERMINAL_LIMITS.maximumRows)).toBe(true);
    expect(isTerminalSize(0, 24)).toBe(false);
    expect(isTerminalSize(80, 61)).toBe(false);
    expect(clampTerminalSize(999.9, Number.NaN)).toEqual({ columns: 160, rows: 1 });

    expect(isTerminalPollBounds(64, 256 * 1_024)).toBe(true);
    expect(isTerminalPollBounds(65, 256 * 1_024)).toBe(false);
    expect(isTerminalPollBounds(1, 0)).toBe(false);
    expect(isTerminalSearchRequest("错误", 256)).toBe(true);
    expect(isTerminalSearchRequest("line\nbreak", 10)).toBe(false);
    expect(isTerminalSearchRequest("界".repeat(342), 10)).toBe(false);
    expect(isTerminalSelectionCopyText("hostile <script> stays plain")).toBe(true);
    expect(isTerminalSelectionCopyText("")).toBe(false);
    expect(isTerminalSelectionCopyText("界".repeat(43_691))).toBe(false);
  });

  it("requires canonical bounded base64 and exact Rust enum field names", () => {
    expect(terminalBase64DecodedLength("YWJj", 3, false)).toBe(3);
    expect(terminalBase64DecodedLength("TQ==", 1, false)).toBe(1);
    expect(terminalBase64DecodedLength("AB==", 1, false)).toBeNull();
    expect(terminalBase64DecodedLength("YWJj=", 8, false)).toBeNull();

    const poll = {
      events: [
        { kind: "output", sequence: 1, bytes_base64: "YWJj" },
        { kind: "title-changed", sequence: 2, title: "</title><script>x</script>", truncated: false },
        { kind: "exited", sequence: 3, exit_code: 0 },
      ],
      rawBytes: 3 + new TextEncoder().encode("</title><script>x</script>").byteLength,
      hasMore: false,
    };
    expect(isTerminalPoll(poll)).toBe(true);
    expect(isTerminalPoll({
      ...poll,
      events: [{ kind: "output", sequence: 1, bytesBase64: "YWJj" }],
      rawBytes: 3,
    })).toBe(false);
    expect(isTerminalPoll({ ...poll, rawBytes: poll.rawBytes + 1 })).toBe(false);
    expect(isTerminalPoll({ ...poll, targetGuard: { generation: 1 } })).toBe(false);
  });

  it("validates the complete bounded render snapshot without accepting leaked fields", () => {
    const color = { kind: "named", name: "Foreground" };
    const snapshot = {
      columns: 1,
      rows: 1,
      cells: [[{
        row: 0,
        column: 0,
        text: "界",
        width: 2,
        foreground: color,
        background: { kind: "rgb", red: 1, green: 2, blue: 3 },
        bold: false,
        dim: false,
        italic: false,
        underline: false,
        strikeout: false,
        inverse: false,
        hidden: false,
        selected: true,
      }]],
      cursor: { row: 0, column: 0, shape: "block" },
      displayOffset: 0,
      alternateScreen: false,
      totalOutputBytes: 3,
    };
    expect(isTerminalRenderSnapshot(snapshot)).toBe(true);
    expect(isTerminalRenderSnapshot({ ...snapshot, command: "cat /etc/passwd" })).toBe(false);
    expect(isTerminalRenderSnapshot({
      ...snapshot,
      cells: [[{ ...snapshot.cells[0]?.[0], text: "x".repeat(257) }]],
    })).toBe(false);
    expect(isTerminalRenderSnapshot({ ...snapshot, cells: [] })).toBe(false);
  });

  it("keeps search matches exact and bounded plain text", () => {
    const search = {
      matches: [{ line: -1, startColumn: 2, endColumn: 5, text: "<b>hit</b>" }],
      limited: false,
    };
    expect(isTerminalSearch(search)).toBe(true);
    expect(isTerminalSearch({
      ...search,
      matches: [{ ...search.matches[0], url: "https://remote.invalid" }],
    })).toBe(false);
    expect(isTerminalSearch({
      ...search,
      matches: [{ ...search.matches[0], endColumn: 161 }],
    })).toBe(false);
    expect(isTerminalSearch({ matches: [], limited: false, sessionId: "leak" })).toBe(false);
  });
});
