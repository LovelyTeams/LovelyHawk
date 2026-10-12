import { describe, expect, it } from "vitest";

import {
  aiHistoryMutationSummary,
  isAiHistoryExportResult,
  isAiHistoryListPage,
  isAiHistoryMutationCancellation,
  isAiHistoryMutationProposal,
  isAiHistoryMutationResult,
  isAiHistoryRecord,
} from "./ai-history-contract";

const summary = {
  id: "ai-1",
  timestamp: 42,
  provider: "local",
  model: "qwen",
  source: "triage",
  promptPreview: "prompt",
  promptTruncated: false,
  resultPreview: "result",
  resultTruncated: false,
};

describe("AI history process-boundary validators", () => {
  it("accepts bounded exact pages and rejects body or internal field leaks", () => {
    expect(isAiHistoryListPage({ total: 1, offset: 0, hasMore: false, items: [summary] })).toBe(true);
    expect(isAiHistoryListPage({ total: 1, offset: 0, hasMore: false, items: [{ ...summary, result: "full body" }] })).toBe(false);
    expect(isAiHistoryListPage({ total: 1, offset: 0, hasMore: false, items: [{ ...summary, sessionId: "secret" }] })).toBe(false);
    expect(isAiHistoryListPage({ total: 0, offset: 100, hasMore: false, items: [] })).toBe(false);
  });

  it("preserves hostile full text while enforcing exact UTF-8 bounds", () => {
    const hostile = "</script><img src=x onerror=steal()>";
    const record = { id: "ai-1", timestamp: 42, provider: "local", model: "qwen", prompt: hostile, result: hostile, source: "test" };
    expect(isAiHistoryRecord(record)).toBe(true);
    expect(record.prompt).toBe(hostile);
    expect(isAiHistoryRecord({ ...record, targetGuard: {} })).toBe(false);
    expect(isAiHistoryRecord({ ...record, prompt: "界".repeat(174_763) })).toBe(false);
  });

  it("keeps plans opaque, exact, single-kind and renderer-safe", () => {
    const proposal = { handle: "plan-123", kind: "remove", affectedRecords: 1, summary: aiHistoryMutationSummary("remove", 1), expiresInSeconds: 300 };
    expect(isAiHistoryMutationProposal(proposal)).toBe(true);
    expect(isAiHistoryMutationProposal({ ...proposal, summary: "伪造摘要" })).toBe(false);
    expect(isAiHistoryMutationProposal({ ...proposal, affectedRecords: 2 })).toBe(false);
    expect(isAiHistoryMutationProposal({ ...proposal, operationId: "leak" })).toBe(false);
    expect(isAiHistoryMutationProposal({ ...proposal, handle: "/tmp/plan" })).toBe(false);
    expect(isAiHistoryMutationResult({ kind: "clear", affectedRecords: 2, verified: true })).toBe(true);
    expect(isAiHistoryMutationResult({ kind: "clear", affectedRecords: 2, verified: false })).toBe(false);
    expect(isAiHistoryMutationCancellation({ cancelled: true })).toBe(true);
    expect(isAiHistoryMutationCancellation({ cancelled: true, handle: "leak" })).toBe(false);
  });

  it("returns export basename and counts without body or path", () => {
    expect(isAiHistoryExportResult({ saved: true, fileName: "history.json", recordCount: 2 })).toBe(true);
    expect(isAiHistoryExportResult({ saved: false, fileName: null, recordCount: 0 })).toBe(true);
    expect(isAiHistoryExportResult({ saved: true, fileName: "C:\\private\\history.json", recordCount: 2 })).toBe(false);
    expect(isAiHistoryExportResult({ saved: true, fileName: "history.json", recordCount: 2, contents: "leak" })).toBe(false);
  });
});
