import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type { AiHistoryApi, AiHistoryRecord } from "../shared/ai-history-contract";
import {
  aiHistoryCopyText,
  aiHistorySourceLabel,
  nextAiHistoryModalFocus,
} from "./ai-history-helpers";
import { AiHistoryPage } from "./AiHistoryPage";

const api: AiHistoryApi = {
  listAiHistory: vi.fn(async () => ({ total: 0, offset: 0, hasMore: false, items: [] })),
  getAiHistoryRecord: vi.fn(async () => ({})),
  planAiHistoryRemove: vi.fn(async () => ({})),
  planAiHistoryClear: vi.fn(async () => ({})),
  confirmAiHistoryMutation: vi.fn(async () => ({})),
  cancelAiHistoryMutation: vi.fn(async () => ({ cancelled: true })),
  exportAiHistory: vi.fn(async () => ({ saved: false, fileName: null, recordCount: 0 })),
};

describe("standalone AI history page", () => {
  it("renders the local plain-text workflow without inventing AI generation", () => {
    const markup = renderToStaticMarkup(<AiHistoryPage api={api} />);
    expect(markup).toContain("AI 历史");
    expect(markup).toContain("搜索 AI 历史");
    expect(markup).toContain("导出文本");
    expect(markup).not.toContain("生成回答");
    expect(markup).not.toContain("sessionId");
    expect(markup).not.toContain("TargetGuard");
  });

  it("keeps hostile copy text unchanged and wraps modal focus", () => {
    const hostile = "</script><img src=x onerror=steal()>";
    const record: AiHistoryRecord = {
      id: "ai-1",
      timestamp: 1,
      provider: "local",
      model: "qwen",
      source: "test",
      prompt: hostile,
      result: hostile,
    };
    expect(aiHistoryCopyText(record, "prompt")).toBe(hostile);
    expect(nextAiHistoryModalFocus(0, 2, true)).toBe(1);
    expect(nextAiHistoryModalFocus(1, 2, false)).toBe(0);
    expect(nextAiHistoryModalFocus(-1, 2, false)).toBe(0);
  });

  it("names where each answer was asked from in words", () => {
    expect(aiHistorySourceLabel("log-analysis")).toBe("日志分析");
    expect(aiHistorySourceLabel("log-analysis-ioc")).toBe("日志分析 · IOC 搜索");
    expect(aiHistorySourceLabel("terminal")).toBe("终端选中内容");
    // Not a key of the object's prototype, and an unknown source stays as stored.
    expect(aiHistorySourceLabel("toString")).toBe("toString");
    expect(aiHistorySourceLabel("imported")).toBe("imported");
  });
});
