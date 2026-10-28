import { describe, expect, it } from "vitest";
import { isNginxRepairRequest, isNginxRepairResponse, matchesNginxRepairResponse, type NginxRepairPlan } from "./nginx-repair-contract";
const plan: NginxRepairPlan = { planHandle: "p", targetLabel: "root@lab:22 · Nginx 主进程 1", candidateHandle: "c", title: "关闭目录列表", path: "/etc/nginx/nginx.conf", line: 1,
  diff: "- autoindex on;\n+ autoindex off;", impact: "重载", restoreDescription: "备份", confirmed: false, expiresInSeconds: 300 };
describe("closed Nginx repair protocol", () => {
  it("retains only a captured observation and rejects invented evidence or contradictory saved receipts", () => {
    for (const action of ["retain", "discard-observation"] as const) {
      const request = { action, bindingHandle: "b", observationHandle: "observation-1" };
      expect(isNginxRepairRequest(request)).toBe(true);
      for (const key of ["caseId", "sha256", "recordText", "target", "evidenceId"]) expect(isNginxRepairRequest({ ...request, [key]: "forged" })).toBe(false);
    }
    const retention = { state: "saved", caseId: "case-1", caseTitle: "原案件", evidenceId: "evidence-1", sha256: "a".repeat(64), detail: "已保存", canRetry: false };
    const response = { kind: "retention", observationHandle: "observation-1", retention };
    expect(matchesNginxRepairResponse({ action: "retain", bindingHandle: "b", observationHandle: "observation-1" }, response)).toBe(true);
    expect(matchesNginxRepairResponse({ action: "retain", bindingHandle: "b", observationHandle: "other" }, response)).toBe(false);
    for (const patch of [{ caseId: null }, { caseTitle: null }, { evidenceId: null }, { sha256: null }, { canRetry: true }, { state: "unsaved" }]) expect(isNginxRepairResponse({ ...response, retention: { ...retention, ...patch } })).toBe(false);
    expect(isNginxRepairResponse({ ...response, retention: { state: "unsaved", caseId: "case-1", caseTitle: "原案件", evidenceId: null, sha256: null, detail: "未保存", canRetry: true } })).toBe(true);
  });
  it("only accepts a bound listener plus a site identity and origin path for connectivity", () => {
    const request = { action: "probe", bindingHandle: "b", endpointHandle: "e", serverName: "a.test", path: "/health" };
    expect(isNginxRepairRequest(request)).toBe(true);
    expect(isNginxRepairRequest({ action: "listeners", bindingHandle: "b", instanceHandle: "i" })).toBe(true);
    for (const serverName of ["::1", "127.0.0.1", "2001:db8::1", "xn--fiqs8s.test"]) expect(isNginxRepairRequest({ ...request, serverName })).toBe(true);
    for (const serverName of ["", "https://a.test", "a.test:443", "a\r\nHost:x", "*.test", "a..test", "a.", "256.1.1.1", "::invalid", "例子.test"]) expect(isNginxRepairRequest({ ...request, serverName })).toBe(false);
    for (const path of ["", "//other", "/a?token=secret", "/a#x", "/a b", "/x\r\nCookie:x"]) expect(isNginxRepairRequest({ ...request, path })).toBe(false);
    for (const extra of ["address", "port", "caFile", "skipVerify", "command"]) expect(isNginxRepairRequest({ ...request, [extra]: "forged" })).toBe(false);
  });
  it("requires all four consistent TLS observations and the exact requested endpoint, name and path", () => {
    const request = { action: "probe", bindingHandle: "b", endpointHandle: "e", serverName: "a.test", path: "/" } as const;
    const rows = ["TLSv1", "TLSv1_1", "TLSv1_2", "TLSv1_3"].map((version) => ({ version, outcome: "inconclusive", detail: "handshake-failed", certificateSha256: null, httpOutcome: "not-sent", httpStatus: null }));
    const result = { kind: "connectivity", observationHandle: "observation-1", recordText: "完整观察", retention: { state: "saved", caseId: "case-1", caseTitle: "应急案件", evidenceId: "evidence-1", sha256: "a".repeat(64), detail: "已保存", canRetry: false }, endpointHandle: "e", serverName: "a.test", path: "/", checkedAt: "2026-09-08T12:00:00Z", report: { clientVersion: "OpenSSL test", rows } };
    expect(matchesNginxRepairResponse(request, result)).toBe(true);
    for (const field of ["endpointHandle", "serverName", "path"]) expect(matchesNginxRepairResponse(request, { ...result, [field]: "other" })).toBe(false);
    for (const badRows of [rows.slice(1), [rows[0], rows[0], rows[2], rows[3]], rows.map((row, i) => i ? row : { ...row, httpStatus: 200 }),
      rows.map((row, i) => i ? row : { ...row, outcome: "protocol-rejected" }), rows.map((row, i) => i !== 2 ? row : { ...row, outcome: "accepted", detail: "identity-verified", httpOutcome: "status", httpStatus: 200 })])
      expect(isNginxRepairResponse({ ...result, report: { ...result.report, rows: badRows } })).toBe(false);
    const endpoint = { endpointHandle: "e", address: "0.0.0.0", port: 8443, connectAddress: "127.0.0.1" };
    expect(isNginxRepairResponse({ kind: "listeners", instanceHandle: "i", endpoints: [endpoint] })).toBe(true);
    expect(isNginxRepairResponse({ kind: "listeners", instanceHandle: "i", endpoints: [{ ...endpoint, connectAddress: "203.0.113.1" }] })).toBe(false);
  });
  it.each([
    { action: "discover" }, { action: "history" }, { action: "load", instanceHandle: "i" },
    { action: "plan", configurationHandle: "g", candidateHandle: "c" }, { action: "confirm", planHandle: "p" },
    { action: "execute", planHandle: "p" }, { action: "cancel", planHandle: "p" },
    { action: "execution", executionHandle: "e" }, { action: "restore", recordHandle: "r" },
  ])("accepts only required fields for $action", (intent) => {
    const valid = { ...intent, bindingHandle: "b" }; expect(isNginxRepairRequest(valid)).toBe(true);
    for (const extra of ["command", "path", "replacement", "confirmation", "nodeIndex", "__proto__"])
      expect(isNginxRepairRequest({ ...valid, [extra]: "untrusted" })).toBe(false);
    for (const bindingHandle of ["", "x".repeat(129), "汉".repeat(60), "a\n", "a\u007f", "a\u0085", 1, null])
      expect(isNginxRepairRequest({ ...valid, bindingHandle })).toBe(false);
  });
  it("rejects invented actions, prototypes and missing capabilities", () => {
    for (const value of [null, [], {}, { action: "__proto__", bindingHandle: "b" }, { action: "constructor", bindingHandle: "b" },
      { action: "shell", bindingHandle: "b" }, { action: "plan", bindingHandle: "b", candidateHandle: "c" }]) expect(isNginxRepairRequest(value)).toBe(false);
  });
  it("checks immutable plan shape and bounded plain text", () => {
    expect(isNginxRepairResponse({ kind: "plan", plan })).toBe(true);
    for (const patch of [{ targetLabel: "" }, { targetLabel: "x".repeat(1025) }, { targetLabel: "root@lab\n" }, { line: 0 }, { line: null }, { candidateHandle: null }, { path: "../etc/a" }, { path: "/etc/a\n" },
      { diff: "x".repeat(256 * 1024 + 1) }, { expiresInSeconds: 0 }, { expiresInSeconds: 301 }, { title: "任意执行" }, { confirmed: 1 }, { secret: "never" }])
      expect(isNginxRepairResponse({ kind: "plan", plan: { ...plan, ...patch } })).toBe(false);
    expect(isNginxRepairResponse({ kind: "plan", plan: { ...plan, title: "恢复先前配置", candidateHandle: null, line: null } })).toBe(true);
  });
  it("rejects duplicated inventory, contradictory counts and forged candidate labels", () => {
    const instance = { instanceHandle: "i", title: "Nginx", version: "1.27.5", mainPid: 1 };
    expect(isNginxRepairResponse({ kind: "inventory", instances: [instance, instance] })).toBe(false);
    const candidate = { candidateHandle: "c", setting: "autoindex", title: "关闭目录列表", path: plan.path, line: 1, before: "on", after: "off" };
    const configuration = { kind: "configuration", configurationHandle: "g", instanceHandle: "i", fileCount: 1, unresolvedIncludes: 0, candidates: [candidate] };
    expect(isNginxRepairResponse(configuration)).toBe(true);
    for (const patch of [{ fileCount: 0 }, { fileCount: 257 }, { unresolvedIncludes: -1 }, { candidates: [candidate, candidate] }, { candidates: [{ ...candidate, title: "隐藏 Nginx 版本" }] }])
      expect(isNginxRepairResponse({ ...configuration, ...patch })).toBe(false);
    expect(isNginxRepairResponse({ kind: "history", totalRecords: 1, truncated: false, records: [] })).toBe(false);
    expect(isNginxRepairResponse({ kind: "history", totalRecords: 0, truncated: true, records: [] })).toBe(false);
  });
  it("correlates prepared, confirmed and polled responses to their requests", () => {
    expect(matchesNginxRepairResponse({ action: "plan", bindingHandle: "b", configurationHandle: "g", candidateHandle: "other" }, { kind: "plan", plan })).toBe(false);
    expect(matchesNginxRepairResponse({ action: "confirm", bindingHandle: "b", planHandle: "p" }, { kind: "plan", plan })).toBe(false);
    expect(matchesNginxRepairResponse({ action: "confirm", bindingHandle: "b", planHandle: "other" }, { kind: "plan", plan: { ...plan, confirmed: true } })).toBe(false);
    expect(matchesNginxRepairResponse({ action: "execution", bindingHandle: "b", executionHandle: "job" }, { kind: "execution", executionHandle: "other", receipt: null })).toBe(false);
    expect(matchesNginxRepairResponse({ action: "execute", bindingHandle: "b", planHandle: "p" }, { kind: "execution", executionHandle: "job", receipt: { planHandle: "p", state: "verified", detail: "", recordHandle: null } })).toBe(false);
  });
  it("accepts the bounded TLS recipe without accepting client-provided protocol changes", () => {
    const candidate = { candidateHandle: "tls", setting: "ssl-protocols", title: "移除旧版 TLS/SSL 协议", path: plan.path,
      line: 2, before: "ssl_protocols TLSv1 TLSv1.2;", after: "ssl_protocols TLSv1.2;" };
    const response = { kind: "configuration", configurationHandle: "g", instanceHandle: "i", fileCount: 1, unresolvedIncludes: 0, candidates: [candidate] };
    expect(isNginxRepairResponse(response)).toBe(true);
    expect(isNginxRepairResponse({ ...response, candidates: [{ ...candidate, setting: "ssl-ciphers" }] })).toBe(false);
    expect(isNginxRepairResponse({ ...response, candidates: [{ ...candidate, title: "关闭目录列表" }] })).toBe(false);
    expect(isNginxRepairResponse({ kind: "plan", plan: { ...plan, candidateHandle: "tls", title: candidate.title } })).toBe(true);
    expect(isNginxRepairRequest({ action: "plan", bindingHandle: "b", configurationHandle: "g", candidateHandle: "tls", protocols: ["TLSv1.3"] })).toBe(false);
  });
});
