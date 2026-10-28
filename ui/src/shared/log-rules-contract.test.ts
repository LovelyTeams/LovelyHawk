import { describe, expect, it } from "vitest";

import {
  isLogRuleName,
  isLogRulePattern,
  isLogRulesRequest,
  LOG_RULE_LIMITS,
  matchesLogRulesResponse,
  type LogRulesRequest,
} from "./log-rules-contract";

const ID = "log-rule-0f8fad5b-d9cb-469f-a165-70867728950e";
const HANDLE = "6fa459ea-ee8a-4ca4-894e-db77e160355e";

describe("log match rule contract", () => {
  it("takes exactly the requests the backend serves", () => {
    for (const request of [
      { action: "list" },
      { action: "add", name: "webshell", pattern: "eval\\(", severity: "high" },
      { action: "match", lines: ["a", ""] },
      { action: "match", lines: [] },
      { action: "plan-remove", id: ID },
      { action: "confirm-remove", handle: HANDLE },
      { action: "cancel-remove", handle: HANDLE },
    ]) {
      expect(isLogRulesRequest(request), JSON.stringify(request)).toBe(true);
    }
    for (const request of [
      null,
      { action: "export" },
      { action: "list", path: "/etc/passwd" },
      { action: "add", name: "x", pattern: "x", severity: "extreme" },
      { action: "add", name: "  ", pattern: "x", severity: "low" },
      { action: "add", name: "x\n", pattern: "x", severity: "low" },
      { action: "add", name: "x", pattern: "", severity: "low" },
      { action: "add", name: "x", pattern: "a\u0000b", severity: "low" },
      { action: "add", name: "x".repeat(LOG_RULE_LIMITS.maximumNameBytes + 1), pattern: "x", severity: "low" },
      { action: "add", name: "x", pattern: "x".repeat(LOG_RULE_LIMITS.maximumPatternBytes + 1), severity: "low" },
      { action: "match", lines: Array.from({ length: LOG_RULE_LIMITS.maximumMatchLines + 1 }, () => "x") },
      { action: "match", lines: ["x".repeat(LOG_RULE_LIMITS.maximumMatchLineBytes + 1)] },
      { action: "match", lines: [1] },
      { action: "plan-remove", id: "/etc/passwd" },
      { action: "plan-remove", id: "log-rule-not-a-uuid" },
      { action: "confirm-remove", handle: ID },
    ]) {
      expect(isLogRulesRequest(request), JSON.stringify(request)).toBe(false);
    }
  });

  it("names and patterns follow core's bounds, counted in bytes", () => {
    // 43 three-byte characters are 129 bytes: one over.
    expect(isLogRuleName("规".repeat(42))).toBe(true);
    expect(isLogRuleName("规".repeat(43))).toBe(false);
    expect(isLogRuleName("  padded  ")).toBe(true);
    expect(isLogRulePattern("(unclosed")).toBe(true); // compiling is core's to judge
  });

  it("checks each answer against what was asked", () => {
    const rule = { id: ID, name: "webshell", pattern: "eval\\(", severity: "high" };
    const add: LogRulesRequest = { action: "add", name: " webshell ", pattern: "eval\\(", severity: "high" };
    expect(matchesLogRulesResponse(add, rule)).toBe(true);
    expect(matchesLogRulesResponse(add, { ...rule, severity: "low" })).toBe(false);
    expect(matchesLogRulesResponse(add, { ...rule, extra: true })).toBe(false);

    expect(matchesLogRulesResponse({ action: "list" }, { rules: [rule], maximum: 128 })).toBe(true);
    expect(matchesLogRulesResponse({ action: "list" }, { rules: [{ ...rule, id: "x" }], maximum: 128 })).toBe(false);

    const match: LogRulesRequest = { action: "match", lines: ["a", "b"] };
    const hit = { id: ID, name: "webshell", severity: "high" };
    expect(matchesLogRulesResponse(match, { matches: [hit, null], ruleCount: 1 })).toBe(true);
    // One answer per line, no more and no fewer.
    expect(matchesLogRulesResponse(match, { matches: [hit], ruleCount: 1 })).toBe(false);
    expect(matchesLogRulesResponse(match, { matches: [hit, null, null], ruleCount: 1 })).toBe(false);

    const plan = { handle: HANDLE, summary: "永久删除日志匹配规则「webshell」；此操作不可恢复。", expiresInSeconds: 300 };
    expect(matchesLogRulesResponse({ action: "plan-remove", id: ID }, plan)).toBe(true);
    expect(matchesLogRulesResponse({ action: "plan-remove", id: ID }, { ...plan, handle: ID })).toBe(false);
    expect(matchesLogRulesResponse({ action: "confirm-remove", handle: HANDLE }, { ruleId: ID, verified: true })).toBe(true);
    expect(matchesLogRulesResponse({ action: "cancel-remove", handle: HANDLE }, { cancelled: true })).toBe(true);
    expect(matchesLogRulesResponse({ action: "cancel-remove", handle: HANDLE }, { cancelled: false })).toBe(false);
  });
});
