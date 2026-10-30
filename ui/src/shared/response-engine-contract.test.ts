import { describe, expect, it } from "vitest";

import {
  isResponseEngineHandle,
  isResponseEngineRequest,
  isResponseEngineResponse,
  matchesResponseEngineResponse,
  RESPONSE_ENGINE_ACTIONS,
  type ResponseEngineRequest,
  type ResponseIssue,
} from "./response-engine-contract";

const BINDING = "b1nd1ng-0000-4000-8000-000000000001";
const ISSUE = "1550e-0000-4000-8000-000000000002";
const PLAN = "p1an-0000-4000-8000-000000000003";
const OPERATION = "0perat10n-0000-4000-8000-000000000004";
const SCAN = "scan-0000-4000-8000-000000000009";

function issue(overrides: Partial<ResponseIssue> = {}): ResponseIssue {
  return {
    issueHandle: ISSUE,
    kind: "empty-password",
    severity: "high",
    summary: "账户 watcher 的口令为空",
    evidence: ["watcher::1000:1000::/home/watcher:/bin/bash"],
    fixable: true,
    fixSummary: "锁定账户口令",
    ...overrides,
  };
}

const scanResponse = {
  kind: "scan",
  scanHandle: "scan-0000-4000-8000-000000000005",
  scannedAt: "2026-10-29T08:00:00+08:00",
  truncated: false,
  gaps: ["缺少 sudo 权限，sudoers 检查未执行"],
  issues: [issue()],
};

const planResponse = {
  kind: "plan",
  planHandle: PLAN,
  summary: "锁定空口令账户 watcher",
  steps: ["归档 /etc/shadow 相关行", "passwd -l watcher", "回读 /etc/shadow 复验"],
  impact: "将执行 3 个修复步骤；删除前证据归档到远端 /var/case/bak/20261029-empty-password",
  rollbackNote: "passwd -u 可解除锁定",
  expiresInSeconds: 300,
};

describe("response-engine request validation", () => {
  it("accepts every action with its exact closed shape", () => {
    const valid: ResponseEngineRequest[] = [
      { action: "scan", bindingHandle: BINDING },
      { action: "scan", bindingHandle: BINDING, kinds: ["pam-backdoor", "webshell"] },
      { action: "poll-scan", bindingHandle: BINDING, scanHandle: SCAN },
      { action: "plan-fix", bindingHandle: BINDING, issueHandle: ISSUE },
      { action: "plan-fix", bindingHandle: BINDING, issueHandle: ISSUE, mode: "lock" },
      { action: "plan-fix", bindingHandle: BINDING, issueHandle: ISSUE, mode: "remove" },
      { action: "confirm-fix", bindingHandle: BINDING, planHandle: PLAN },
      { action: "cancel-fix", bindingHandle: BINDING, planHandle: PLAN },
      { action: "execute-fix", bindingHandle: BINDING, planHandle: PLAN },
      { action: "poll-fix", bindingHandle: BINDING, operationHandle: OPERATION },
    ];
    for (const request of valid) {
      expect(isResponseEngineRequest(request), JSON.stringify(request)).toBe(true);
    }
    expect(RESPONSE_ENGINE_ACTIONS).toHaveLength(7);
  });

  it("rejects paths, commands, accounts, secrets and any extra field", () => {
    const base: [string, Record<string, unknown>][] = [
      ["scan", { action: "scan", bindingHandle: BINDING }],
      ["scan+kinds", { action: "scan", bindingHandle: BINDING, kinds: ["webshell"] }],
      ["poll-scan", { action: "poll-scan", bindingHandle: BINDING, scanHandle: SCAN }],
      ["plan-fix", { action: "plan-fix", bindingHandle: BINDING, issueHandle: ISSUE }],
      ["confirm-fix", { action: "confirm-fix", bindingHandle: BINDING, planHandle: PLAN }],
      ["cancel-fix", { action: "cancel-fix", bindingHandle: BINDING, planHandle: PLAN }],
      ["execute-fix", { action: "execute-fix", bindingHandle: BINDING, planHandle: PLAN }],
      ["poll-fix", { action: "poll-fix", bindingHandle: BINDING, operationHandle: OPERATION }],
    ];
    for (const [action, request] of base) {
      for (const extra of ["path", "command", "username", "password", "target", "confirmed", "__proto__"]) {
        expect(isResponseEngineRequest({ ...request, [extra]: "forged" }), `${action}: ${extra}`).toBe(false);
      }
      const missing = { ...request };
      delete missing.bindingHandle;
      expect(isResponseEngineRequest(missing), `${action}: missing bindingHandle`).toBe(false);
    }
  });

  it("rejects unknown actions, bad modes, bad kinds and malformed handles", () => {
    for (const action of ["fix", "shell", "Scan", "planFix", "", "hardening-scan"]) {
      expect(isResponseEngineRequest({ action, bindingHandle: BINDING })).toBe(false);
    }
    expect(isResponseEngineRequest({
      action: "plan-fix", bindingHandle: BINDING, issueHandle: ISSUE, mode: "delete",
    })).toBe(false);
    expect(isResponseEngineRequest({
      action: "scan", bindingHandle: BINDING, kinds: ["not-a-kind" as never],
    })).toBe(false);
    // 空列表与重复项都没有意义。
    expect(isResponseEngineRequest({
      action: "scan", bindingHandle: BINDING, kinds: [],
    })).toBe(false);
    expect(isResponseEngineRequest({
      action: "scan", bindingHandle: BINDING, kinds: ["webshell", "webshell"],
    })).toBe(false);
    for (const bad of ["", "x".repeat(129), "a b", "a;rm -rf /", "a\nb", "汉".repeat(43), null, 42]) {
      expect(isResponseEngineRequest({ action: "scan", bindingHandle: bad })).toBe(false);
    }
    // A handle must not be reused as its own second handle.
    expect(isResponseEngineRequest({ action: "plan-fix", bindingHandle: BINDING, issueHandle: BINDING })).toBe(false);
    expect(isResponseEngineRequest({ action: "poll-fix", bindingHandle: BINDING, operationHandle: BINDING })).toBe(false);
    expect(isResponseEngineRequest({ action: "poll-scan", bindingHandle: BINDING, scanHandle: BINDING })).toBe(false);
  });
});

describe("response-engine handle shape", () => {
  it("accepts only short ASCII alphanumeric-plus-dash handles", () => {
    expect(isResponseEngineHandle("a-1_Z".replace("_", "-"))).toBe(true);
    expect(isResponseEngineHandle("550e8400-e29b-41d4-a716-446655440000")).toBe(true);
    for (const bad of ["", " ", "a b", "a/b", "../x", "a;b", "a_b", "汉", "x".repeat(129)]) {
      expect(isResponseEngineHandle(bad), JSON.stringify(bad)).toBe(false);
    }
  });
});

describe("response-engine response validation", () => {
  it("accepts a well-formed scan and enforces issue bounds", () => {
    expect(isResponseEngineResponse(scanResponse)).toBe(true);
    // Duplicate issue handles would let one row's fix target another row.
    expect(isResponseEngineResponse({
      ...scanResponse, issues: [issue(), issue()],
    })).toBe(false);
    // The scan handle must not double as an issue handle.
    expect(isResponseEngineResponse({
      ...scanResponse, issues: [issue({ issueHandle: scanResponse.scanHandle })],
    })).toBe(false);
    expect(isResponseEngineResponse({ ...scanResponse, issues: new Array(65).fill(0).map((_, index) => issue({ issueHandle: `i-${index}` })) })).toBe(false);
    expect(isResponseEngineResponse({ ...scanResponse, scannedAt: "not-a-time" })).toBe(false);
    expect(isResponseEngineResponse({ ...scanResponse, gaps: new Array(33).fill("gap") })).toBe(false);
  });

  it("accepts every closed issue kind, including the deep-compromise kinds", () => {
    for (const kind of [
      "hijacked-command",
      "uid-zero-account",
      "empty-password",
      "suspicious-account",
      "malicious-sudoers",
      "cron-persistence",
      "backdoor-process",
      "ld-preload-hijack",
      "path-injection",
      "ssh-key-backdoor",
      "pam-backdoor",
      "bind-listener",
      "stash-dir",
      "web-sensitive-file",
      "webshell",
      "command-recorder",
      "history-credential-leak",
      "session-env-hook",
      "preload-residue",
    ] as const) {
      expect(
        isResponseEngineResponse({ ...scanResponse, issues: [issue({ kind })] }),
        kind,
      ).toBe(true);
    }
  });

  it("checks every issue field against the closed enums and text bounds", () => {
    const scanWith = (overrides: Partial<ResponseIssue>) => ({
      ...scanResponse, issues: [issue(overrides)],
    });
    expect(isResponseEngineResponse(scanWith({ kind: "kernel-exploit" as never }))).toBe(false);
    expect(isResponseEngineResponse(scanWith({ severity: "fatal" as never }))).toBe(false);
    // critical is a first-class severity for the deep-compromise kinds.
    expect(isResponseEngineResponse(scanWith({ severity: "critical" }))).toBe(true);
    expect(isResponseEngineResponse(scanWith({ summary: "x".repeat(3_000) }))).toBe(false);
    expect(isResponseEngineResponse(scanWith({ summary: "坏\n摘要" }))).toBe(false);
    expect(isResponseEngineResponse(scanWith({ evidence: new Array(33).fill("e") }))).toBe(false);
    expect(isResponseEngineResponse(scanWith({ fixSummary: "x".repeat(3_000) }))).toBe(false);
    expect(isResponseEngineResponse(scanWith({ fixable: false, fixSummary: null }))).toBe(true);
    // Untrusted remote text never reaches the DOM raw; control bytes are refused anyway.
    const hostile = issue({ summary: "<script>alert(1)</script>", evidence: ["<img src=x onerror=1>"] });
    expect(isResponseEngineResponse({ ...scanResponse, issues: [hostile] })).toBe(true);
  });

  it("validates the async scan start and stage statuses", () => {
    expect(isResponseEngineResponse({ kind: "scan-started", scanHandle: SCAN })).toBe(true);
    expect(isResponseEngineResponse({ kind: "scan-started", scanHandle: "a b" })).toBe(false);
    const base = {
      kind: "scan-status", scanHandle: SCAN, stageLabel: "正在采集进程与文件", percent: 45,
    };
    expect(isResponseEngineResponse({ ...base, stage: "running", scan: null, error: null })).toBe(true);
    // running 不允许携带结果或错误。
    expect(isResponseEngineResponse({ ...base, stage: "running", scan: scanResponse, error: null })).toBe(false);
    expect(isResponseEngineResponse({ ...base, stage: "running", percent: 101, scan: null, error: null })).toBe(false);
    // completed 必须带完整扫描且不得带错误。
    expect(isResponseEngineResponse({
      ...base, stage: "completed", percent: 100, scan: scanResponse, error: null,
    })).toBe(true);
    expect(isResponseEngineResponse({ ...base, stage: "completed", percent: 100, scan: null, error: null })).toBe(false);
    // failed 带错误说明，不带扫描结果。
    expect(isResponseEngineResponse({
      ...base, stage: "failed", percent: 60, scan: null, error: "目标连接中断",
    })).toBe(true);
    expect(isResponseEngineResponse({ ...base, stage: "failed", percent: 60, scan: null, error: null })).toBe(false);
    expect(isResponseEngineResponse({ ...base, stage: "done", scan: null, error: null })).toBe(false);
  });

  it("accepts a plan only with steps, a bounded TTL and exact keys", () => {
    expect(isResponseEngineResponse(planResponse)).toBe(true);
    expect(isResponseEngineResponse({ ...planResponse, rollbackNote: null })).toBe(true);
    expect(isResponseEngineResponse({ ...planResponse, steps: [] })).toBe(false);
    expect(isResponseEngineResponse({ ...planResponse, steps: new Array(33).fill("s") })).toBe(false);
    expect(isResponseEngineResponse({ ...planResponse, expiresInSeconds: 0 })).toBe(false);
    expect(isResponseEngineResponse({ ...planResponse, expiresInSeconds: 301 })).toBe(false);
    expect(isResponseEngineResponse({ ...planResponse, command: "rm -rf /" })).toBe(false);
  });

  it("keeps the confirm/cancel/execute answers minimal and exact", () => {
    expect(isResponseEngineResponse({
      kind: "confirmed", planHandle: PLAN, confirmed: true, expiresInSeconds: 240,
    })).toBe(true);
    expect(isResponseEngineResponse({
      kind: "confirmed", planHandle: PLAN, confirmed: false, expiresInSeconds: 240,
    })).toBe(false);
    expect(isResponseEngineResponse({ kind: "cancelled", cancelled: false })).toBe(true);
    expect(isResponseEngineResponse({ kind: "execution", operationHandle: OPERATION })).toBe(true);
    expect(isResponseEngineResponse({ kind: "execution", operationHandle: "a b" })).toBe(false);
  });

  it("ties the verify verdict to the completed stage only", () => {
    const statusWith = (stage: string, verifyPassed: boolean | null) => ({
      kind: "status", operationHandle: OPERATION, stage, summary: "s", verifyPassed,
    });
    expect(isResponseEngineResponse(statusWith("running", null))).toBe(true);
    expect(isResponseEngineResponse(statusWith("verify-pending", null))).toBe(true);
    expect(isResponseEngineResponse(statusWith("completed", true))).toBe(true);
    expect(isResponseEngineResponse(statusWith("completed", false))).toBe(true);
    expect(isResponseEngineResponse(statusWith("failed", null))).toBe(true);
    // A running or failed operation must not claim a verification result.
    expect(isResponseEngineResponse(statusWith("running", true))).toBe(false);
    expect(isResponseEngineResponse(statusWith("failed", false))).toBe(false);
    expect(isResponseEngineResponse(statusWith("completed", null))).toBe(false);
    expect(isResponseEngineResponse(statusWith("done", null))).toBe(false);
  });

  it("refuses responses over the backend byte bound", () => {
    const huge = {
      ...scanResponse,
      issues: [issue({ summary: "x".repeat(400 * 1_024) })],
    };
    expect(isResponseEngineResponse(huge)).toBe(false);
  });
});

describe("response-engine request/response pairing", () => {
  const scanStatusRunning = {
    kind: "scan-status", scanHandle: SCAN, stage: "running",
    stageLabel: "正在采集进程与文件", percent: 45, scan: null, error: null,
  };
  const requests: [ResponseEngineRequest, unknown, string][] = [
    [{ action: "scan", bindingHandle: BINDING }, { kind: "scan-started", scanHandle: SCAN }, "scan-started"],
    [{ action: "poll-scan", bindingHandle: BINDING, scanHandle: SCAN }, scanStatusRunning, "scan-status"],
    [{ action: "plan-fix", bindingHandle: BINDING, issueHandle: ISSUE }, planResponse, "plan"],
    [{ action: "confirm-fix", bindingHandle: BINDING, planHandle: PLAN },
      { kind: "confirmed", planHandle: PLAN, confirmed: true, expiresInSeconds: 240 }, "confirmed"],
    [{ action: "cancel-fix", bindingHandle: BINDING, planHandle: PLAN },
      { kind: "cancelled", cancelled: true }, "cancelled"],
    [{ action: "execute-fix", bindingHandle: BINDING, planHandle: PLAN },
      { kind: "execution", operationHandle: OPERATION }, "execution"],
    [{ action: "poll-fix", bindingHandle: BINDING, operationHandle: OPERATION },
      { kind: "status", operationHandle: OPERATION, stage: "verify-pending", summary: "等待复验", verifyPassed: null }, "status"],
  ];

  it("accepts the matching response kind for every action", () => {
    for (const [request, response] of requests) {
      expect(matchesResponseEngineResponse(request, response), JSON.stringify(request)).toBe(true);
    }
  });

  it("rejects every other kind for every action", () => {
    const all = requests.map(([, response]) => response);
    for (const [request, response] of requests) {
      for (const other of all) {
        if (other === response) continue;
        expect(
          matchesResponseEngineResponse(request, other),
          `${request.action} vs ${JSON.stringify(other).slice(0, 40)}`,
        ).toBe(false);
      }
    }
  });

  it("rejects a confirmed, status or scan answer that names another handle", () => {
    const confirm: ResponseEngineRequest = { action: "confirm-fix", bindingHandle: BINDING, planHandle: PLAN };
    expect(matchesResponseEngineResponse(confirm, {
      kind: "confirmed", planHandle: "p1an-other", confirmed: true, expiresInSeconds: 240,
    })).toBe(false);
    const poll: ResponseEngineRequest = { action: "poll-fix", bindingHandle: BINDING, operationHandle: OPERATION };
    expect(matchesResponseEngineResponse(poll, {
      kind: "status", operationHandle: "0perat10n-other", stage: "completed", summary: "s", verifyPassed: true,
    })).toBe(false);
    const scanPoll: ResponseEngineRequest = { action: "poll-scan", bindingHandle: BINDING, scanHandle: SCAN };
    expect(matchesResponseEngineResponse(scanPoll, {
      kind: "scan-status", scanHandle: "scan-other", stage: "running", stageLabel: "s", percent: 30, scan: null, error: null,
    })).toBe(false);
  });
});
