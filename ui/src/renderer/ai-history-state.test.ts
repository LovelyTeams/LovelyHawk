import { describe, expect, it } from "vitest";

import type { AiHistoryListPage, AiHistoryRecord } from "../shared/ai-history-contract";
import { aiHistoryReducer, createAiHistoryState } from "./ai-history-state";

const page: AiHistoryListPage = {
  total: 1,
  offset: 0,
  hasMore: false,
  items: [{
    id: "ai-new",
    timestamp: 2,
    provider: "local",
    model: "qwen",
    source: "test",
    promptPreview: "prompt",
    promptTruncated: false,
    resultPreview: "result",
    resultTruncated: false,
  }],
};

const record: AiHistoryRecord = {
  id: "ai-new",
  timestamp: 2,
  provider: "local",
  model: "qwen",
  source: "test",
  prompt: "prompt",
  result: "result",
};

describe("AI history reducer", () => {
  it("drops late list responses after a newer query scope starts", () => {
    let state = aiHistoryReducer(createAiHistoryState(), { type: "list-started", request: 1 });
    state = aiHistoryReducer(state, { type: "query-changed", query: "new" });
    state = aiHistoryReducer(state, { type: "list-started", request: 2 });
    const late = aiHistoryReducer(state, { type: "list-loaded", request: 1, page });
    expect(late).toBe(state);
    expect(late.page).toBeNull();
  });

  it("drops late detail responses after selection changes", () => {
    let state = aiHistoryReducer(createAiHistoryState(), { type: "list-started", request: 1 });
    state = aiHistoryReducer(state, { type: "list-loaded", request: 1, page });
    state = aiHistoryReducer(state, { type: "detail-started", request: 2, id: "ai-new" });
    state = aiHistoryReducer(state, { type: "record-selected", id: "ai-other" });
    const late = aiHistoryReducer(state, { type: "detail-loaded", request: 2, id: "ai-new", record });
    expect(late).toBe(state);
    expect(late.record).toBeNull();
  });

  it("accepts only the newest opaque mutation proposal", () => {
    let state = aiHistoryReducer(createAiHistoryState(), { type: "proposal-started", request: 7 });
    state = aiHistoryReducer(state, { type: "proposal-started", request: 8 });
    const late = aiHistoryReducer(state, {
      type: "proposal-loaded",
      request: 7,
      proposal: { handle: "old", kind: "clear", affectedRecords: 1, summary: "old", expiresInSeconds: 300 },
    });
    expect(late).toBe(state);
    expect(late.proposal).toBeNull();
  });
});
