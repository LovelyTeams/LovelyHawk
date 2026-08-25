import { describe, expect, it } from "vitest";

import {
  commandHistoryMutationSummary,
  isCommandHistoryListPage,
  isCommandHistoryMutationProposal,
  isCommandHistoryQuery,
  isCommandHistoryRecord,
  isCommandReplayIntent,
} from "./command-history-contract";

const summary = {
  id: "command-1",
  title: "Inspect host",
  commandPreview: "uname -a",
  commandTruncated: false,
  outputPreview: "Linux",
  outputTruncated: false,
  timestamp: 1_700_000_000_000,
  exitCode: 0,
  status: "succeeded",
  risk: "read-only",
  source: "workbench",
};

describe("command history standalone contract", () => {
  it("accepts exact bounded pages and rejects body, target, digest, and extra keys", () => {
    expect(isCommandHistoryListPage({ total: 1, offset: 0, hasMore: false, items: [summary] })).toBe(true);
    expect(isCommandHistoryListPage({
      total: 1, offset: 0, hasMore: false,
      items: [{ ...summary, command: "uname -a" }],
    })).toBe(false);
    expect(isCommandHistoryListPage({
      total: 1, offset: 0, hasMore: false,
      items: [{ ...summary, target: "server-1", commandSha256: "secret" }],
    })).toBe(false);
  });

  it("keeps hostile full command and output as bounded plain strings", () => {
    const hostile = "</pre><img src=x onerror=steal()>";
    expect(isCommandHistoryRecord({
      id: "command-1",
      title: hostile,
      command: hostile,
      output: hostile,
      timestamp: 1,
      exitCode: 7,
      status: "failed",
      risk: "mutating",
      source: "test",
    })).toBe(true);
    expect(isCommandHistoryRecord({ ...summary, command: "x", output: "", status: "failed" })).toBe(false);
    expect(isCommandHistoryRecord({
      id: "command-1", title: "large", command: "x", output: "界".repeat(100_000),
      timestamp: 1, exitCode: null, status: "unknown", risk: "read-only", source: "test",
    })).toBe(false);
  });

  it("allows only closed non-executable replay summaries", () => {
    expect(isCommandReplayIntent({
      status: "ready",
      historyId: "command-1",
      risk: "read-only",
      executionAvailable: false,
    })).toBe(true);
    expect(isCommandReplayIntent({
      status: "ready",
      historyId: "command-1",
      risk: "read-only",
      executionAvailable: true,
      command: "uname -a",
    })).toBe(false);
    expect(isCommandReplayIntent({ status: "blocked", reason: "mutating-command" })).toBe(true);
  });

  it("accepts only opaque exact mutation proposals", () => {
    expect(isCommandHistoryMutationProposal({
      handle: "c74253ec-7421-4abc-a818-56db940986bd",
      kind: "clear",
      affectedRecords: 3,
      summary: commandHistoryMutationSummary("clear", 3),
      expiresInSeconds: 300,
    })).toBe(true);
    expect(isCommandHistoryMutationProposal({
      handle: "plan/server-1",
      kind: "clear",
      affectedRecords: 3,
      summary: "unsafe",
      expiresInSeconds: 300,
      operationId: "internal",
    })).toBe(false);
    expect(isCommandHistoryMutationProposal({
      handle: "c74253ec-7421-4abc-a818-56db940986bd",
      kind: "remove",
      affectedRecords: 2,
      summary: commandHistoryMutationSummary("remove", 2),
      expiresInSeconds: 300,
    })).toBe(false);
    expect(isCommandHistoryMutationProposal({
      handle: "c74253ec-7421-4abc-a818-56db940986bd",
      kind: "clear",
      affectedRecords: 3,
      summary: "伪造摘要",
      expiresInSeconds: 300,
    })).toBe(false);
  });

  it("bounds search by both UTF-8 bytes and characters", () => {
    expect(isCommandHistoryQuery("x".repeat(256))).toBe(true);
    expect(isCommandHistoryQuery("x".repeat(257))).toBe(false);
    expect(isCommandHistoryQuery("界".repeat(256))).toBe(true);
  });
});
