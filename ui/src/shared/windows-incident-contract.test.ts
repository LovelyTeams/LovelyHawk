import { describe, expect, it } from "vitest";

import {
  isWindowsIncidentRequest,
  matchesWindowsIncidentResponse,
  WINDOWS_STARTUP_CATEGORIES,
} from "./windows-incident-contract";
const sessionId = "00000000-0000-4000-8000-000000000001";

it("requires all startup categories and distinguishes incomplete coverage from empty data", () => {
  const request={action:"collect-startup",sessionId} as const;
  const snapshot={observedAt:"2026-10-27T00:00:00Z",truncated:false,warnings:[],totalCount:0,suspiciousCount:0,entries:[],categories:WINDOWS_STARTUP_CATEGORIES.map(category=>({category,count:0,status:"unavailable",message:"权限不足"}))};
  expect(matchesWindowsIncidentResponse(request,{kind:"startup",snapshot})).toBe(true);
  for(const changed of [{...snapshot,categories:[]},{...snapshot,categories:snapshot.categories.map((c,i)=>i===0?{...c,count:1}:c)},{...snapshot,categories:snapshot.categories.map(()=>snapshot.categories[0])},{...snapshot,observedAt:"unknown"}]) expect(matchesWindowsIncidentResponse(request,{kind:"startup",snapshot:changed})).toBe(false);
});
it("binds controls to captured ids and refuses invented scope or false task success", () => {
  const request={action:"plan-control",sessionId,objectId:sessionId,operation:"stop"} as const;
  expect(isWindowsIncidentRequest(request)).toBe(true);
  for(const bad of [{...request,name:"RpcSs"},{...request,force:true},{...request,operation:"delete"},{...request,objectId:"service-name"},{action:"apply-control",sessionId,planId:sessionId,operation:"stop"}]) expect(isWindowsIncidentRequest(bad)).toBe(false);
  const apply={action:"apply-control",sessionId,planId:sessionId} as const;
  const report={id:sessionId,target:"lab",kind:"tasks",name:"owned",operation:"run",state:"submitted",message:"已接受请求",canRestore:false,createdAt:1790000000};
  expect(matchesWindowsIncidentResponse(apply,{kind:"control-report",report})).toBe(true);
  for(const bad of [{...report,state:"verified"},{...report,kind:"drivers"},{...report,canRestore:true},{...report,operation:"restart"},{...report,configHash:"private"}]) expect(matchesWindowsIncidentResponse(apply,{kind:"control-report",report:bad})).toBe(false);
});

describe("windows-incident contract", () => {
  it("keeps unknown and inapplicable baseline results out of pass counts and repair actions", () => {
    const request = { action: "collect-baseline", sessionId } as const;
    const base = { category: "测试", title: "检查项", currentValue: "未取得", expectedValue: "启用", severity: "low", description: "读取范围", recommendation: "核对权限", remediationAvailable: false };
    const snapshot = { totalChecks: 4, passedCount: 1, failedCount: 1, warningCount: 0, unknownCount: 1, notApplicableCount: 1, items: [
      { ...base, id: "pass", status: "pass" },
      { ...base, id: "wdigest", status: "fail", remediationAvailable: true },
      { ...base, id: "unknown", status: "unknown" },
      { ...base, id: "na", status: "not-applicable" },
    ] };
    const valid = (value: unknown) => matchesWindowsIncidentResponse(request, { kind: "baseline", snapshot: value });
    expect(valid(snapshot)).toBe(true);
    for (const changed of [
      { ...snapshot, passedCount: 2 }, { ...snapshot, unknownCount: 0 }, { ...snapshot, notApplicableCount: 0 },
      { ...snapshot, totalChecks: 5 },
      { ...snapshot, items: snapshot.items.map((item) => ({ ...item, id: "duplicate" })) },
      { ...snapshot, items: snapshot.items.map((item) => ({ ...item, remediationAvailable: true })) },
      { ...snapshot, items: snapshot.items.map(({ remediationAvailable: _missing, ...item }) => item) },
    ]) expect(valid(changed)).toBe(false);
  });
  it("binds process details to both the selected PID and creation timestamp", () => {
    const request = { action: "inspect-process", pid: 12, startTime: "2026-10-24T10:00:00.0000000Z", sessionId } as const;
    const inspection = { pid: 12, startTime: request.startTime, observedAt: "2026-10-24T10:10:00Z", user: "lab", services: [], modules: [], network: [], warnings: [] };
    expect(isWindowsIncidentRequest(request)).toBe(true);
    expect(isWindowsIncidentRequest({ ...request, pid: 0 })).toBe(false);
    expect(isWindowsIncidentRequest({ ...request, startTime: "yesterday'; calc" })).toBe(false);
    expect(isWindowsIncidentRequest({ ...request, path: "C:\\a" })).toBe(false);
    expect(matchesWindowsIncidentResponse(request, { kind: "process-inspection", inspection })).toBe(true);
    expect(matchesWindowsIncidentResponse(request, { kind: "process-inspection", inspection: { ...inspection, startTime: "2026-10-24T09:00:00Z" } })).toBe(false);
    expect(matchesWindowsIncidentResponse(request, { kind: "process-inspection", inspection: { ...inspection, pid: 13 } })).toBe(false);
  });
  it("accepts valid requests and rejects extra or oversized fields", () => {
    expect(isWindowsIncidentRequest({ action: "status" })).toBe(true);
    expect(isWindowsIncidentRequest({ action: "register-plugin" })).toBe(true);
    expect(isWindowsIncidentRequest({ action: "send-chat", text: "hello", sessionId })).toBe(true);
    expect(isWindowsIncidentRequest({ action: "collect-files", path: "C:\\Users\\Public", sessionId })).toBe(
      true,
    );
    expect(
      isWindowsIncidentRequest({
        action: "collect-registry",
        keyPath: "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        sessionId,
      }),
    ).toBe(true);

    expect(isWindowsIncidentRequest({ action: "status", extra: 1 })).toBe(false);
    expect(isWindowsIncidentRequest({ action: "send-chat", text: "" })).toBe(false);
    expect(isWindowsIncidentRequest({ action: "pull-file", remotePath: "C:\\a\nb" })).toBe(false);
  });

  it("matches responses against the requested action", () => {
    expect(
      matchesWindowsIncidentResponse(
        { action: "status" },
        {
          kind: "status",
          status: { listenerRunning: true },
          filelessScript: "Add-Type ...",
        },
      ),
    ).toBe(false);
    expect(
      matchesWindowsIncidentResponse(
        { action: "collect-overview", sessionId },
        { kind: "overview", snapshot: { hostname: "WIN-IR" } },
      ),
    ).toBe(false);
    expect(
      matchesWindowsIncidentResponse(
        { action: "collect-overview", sessionId },
        { kind: "processes", snapshot: {} },
      ),
    ).toBe(false);
  });

  it("validates preview bytes, base64, metadata and the exact response fields", () => {
    const request = { action: "preview-file", path: "C:\\evidence.txt", sessionId } as const;
    const preview = { fullPath: request.path, sizeBytes: 4, lastWriteTime: "", previewB64: "YWJjZA==", previewBytes: 4, truncated: false };
    expect(matchesWindowsIncidentResponse(request, { kind: "file-preview", preview })).toBe(true);
    for (const invalid of [
      { ...preview, previewB64: "%%%%" },
      { ...preview, previewBytes: 3 },
      { ...preview, previewBytes: -1 },
      { ...preview, sizeBytes: 2 },
      { ...preview, truncated: true },
      { ...preview, previewB64: "YQ==".repeat(5500) },
      { ...preview, fullPath: "C:\\a\0b" },
      { ...preview, extra: true },
    ]) expect(matchesWindowsIncidentResponse(request, { kind: "file-preview", preview: invalid })).toBe(false);
    expect(matchesWindowsIncidentResponse(request, { kind: "file-preview", preview: { ...preview, sizeBytes: 100, truncated: true } })).toBe(true);
    expect(matchesWindowsIncidentResponse(request, { kind: "file-preview", preview: { ...preview, sizeBytes: 0, previewBytes: 0, previewB64: "" } })).toBe(true);
  });

  it("rejects malformed nested records and mismatched directory coverage", () => {
    const request = { action: "collect-files", path: "C:\\", sessionId } as const;
    const entry = { name: "example.txt", fullPath: "C:\\example.txt", entryType: "file", sizeBytes: 10, lastWriteTime: "", sha256: "", hidden: false, system: false, riskLevel: "normal", riskReason: "" };
    const snapshot = { currentPath: "C:\\", totalEntries: 1, truncated: false, entries: [entry] };
    expect(matchesWindowsIncidentResponse(request, { kind: "files", snapshot })).toBe(true);
    expect(matchesWindowsIncidentResponse(request, { kind: "files", snapshot: { ...snapshot, totalEntries: 0 } })).toBe(false);
    expect(matchesWindowsIncidentResponse(request, { kind: "files", snapshot: { ...snapshot, totalEntries: 20 } })).toBe(false);
    expect(matchesWindowsIncidentResponse(request, { kind: "files", snapshot: { ...snapshot, totalEntries: 20, truncated: true } })).toBe(true);
    for (const invalid of [{ ...entry, riskLevel: "critical" }, { ...entry, sizeBytes: NaN }, { ...entry, sha256: "not-a-hash" }, { ...entry, hidden: "false" }]) {
      expect(matchesWindowsIncidentResponse(request, { kind: "files", snapshot: { ...snapshot, entries: [invalid] } })).toBe(false);
    }
  });

  it("rejects empty, oversized, control-character paths and unsupported log categories", () => {
    for (const path of ["", " ", "C:\\a\0b", "C:\\a\rb", "C:\\a\nb", `C:\\${"文".repeat(1024)}`]) {
      expect(isWindowsIncidentRequest({ action: "preview-file", path, sessionId })).toBe(false);
      expect(isWindowsIncidentRequest({ action: "collect-files", path, sessionId })).toBe(false);
      expect(isWindowsIncidentRequest({ action: "collect-registry", keyPath: path, sessionId })).toBe(false);
    }
    for (const category of ["", "all; whoami", "ALL", "System"]) expect(isWindowsIncidentRequest({ action: "collect-logs", category, sessionId })).toBe(false);
    expect(isWindowsIncidentRequest({ action: "collect-logs", category: "powershell", sessionId })).toBe(true);
    expect(isWindowsIncidentRequest({ action: "run-command", command: "whoami" })).toBe(false);
    expect(isWindowsIncidentRequest({ action: "run-command", command: "whoami", sessionId: "changed" })).toBe(false);
    expect(isWindowsIncidentRequest({ action: "plan-baseline", ruleIds: ["wdigest"], sessionId })).toBe(true);
    expect(isWindowsIncidentRequest({ action: "plan-baseline", ruleIds: ["defender-tamper"], sessionId })).toBe(false);
    expect(isWindowsIncidentRequest({ action: "kill-process", pid: 900, startTime: "2026-10-24T10:00:00Z", sessionId })).toBe(true);
    expect(isWindowsIncidentRequest({ action: "kill-process", pid: 4, startTime: "2026-10-24T10:00:00Z", sessionId })).toBe(false);
    expect(isWindowsIncidentRequest({ action: "remove-startup", sourceType: "registry", name: "Updater", location: "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", sessionId })).toBe(true);
    expect(isWindowsIncidentRequest({ action: "disable-account", name: "support$", sid: "S-1-5-21-1001", sessionId })).toBe(true);
    expect(isWindowsIncidentRequest({ action: "disable-account", name: "support$", sid: "not-a-sid", sessionId })).toBe(false);
    expect(isWindowsIncidentRequest({ action: "delete-file", path: "C:\\Users\\Public\\dropper.exe", dirPath: "C:\\Users\\Public", sessionId })).toBe(true);
    expect(isWindowsIncidentRequest({ action: "delete-registry-value", keyPath: "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", valueName: "Updater", sessionId })).toBe(true);
    expect(isWindowsIncidentRequest({ action: "delete-registry-value", keyPath: "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", valueName: "", sessionId })).toBe(false);
  });
});


describe("Windows baseline immutable plan contract", () => {
  const planId = "00000000-0000-4000-8000-000000000011";
  const request = { action: "plan-baseline", sessionId, ruleIds: ["wdigest"] } as const;
  const plan = { id: planId, target: "LAB", expiresAt: 1790000300, restoring: false, items: [{ id: "wdigest", title: "WDigest", location: "HKLM\\fixed", currentValue: "DWORD 1", expectedValue: "DWORD 0", impact: "需要重启复核" }], notes: ["原值将持久保存"] };
  it("rejects arbitrary paths, duplicate rules and the former direct write", () => {
    expect(isWindowsIncidentRequest(request)).toBe(true);
    for (const value of [{ ...request, ruleIds: [] }, { ...request, ruleIds: ["wdigest", "wdigest"] }, { ...request, ruleIds: ["unknown"] }, { ...request, path: "HKLM\\Other" }, { ...request, value: 0 }, { action: "remediate-baseline", sessionId, ruleId: "wdigest" }, { action: "apply-baseline-plan", sessionId, planId, ruleIds: ["uac"] }]) expect(isWindowsIncidentRequest(value)).toBe(false);
  });
  it("accepts only the planned subset without identities or backup contents", () => {
    const req = { ...request, ruleIds: [...request.ruleIds] };
    expect(matchesWindowsIncidentResponse(req, { kind: "baseline-plan", plan })).toBe(true);
    for (const value of [{ ...plan, items: [...plan.items, ...plan.items] }, { ...plan, machine: "private" }, { ...plan, restoring: true }, { ...plan, items: [{ ...plan.items[0], id: "uac" }] }, { ...plan, items: [{ ...plan.items[0], backupPath: "D:/data" }] }]) expect(matchesWindowsIncidentResponse(req, { kind: "baseline-plan", plan: value })).toBe(false);
  });
  it("requires a finished, matching report and honest recovery capability", () => {
    const req = { action: "apply-baseline-plan", sessionId, planId } as const;
    const report = { id: planId, target: "LAB", createdAt: 1790000000, restoring: false, finished: true, recoveryAvailable: true, items: [{ id: "wdigest", title: "WDigest", state: "verified" }], message: "仅配置回读通过" };
    expect(matchesWindowsIncidentResponse(req, { kind: "baseline-change", report })).toBe(true);
    for (const value of [{ ...report, id: sessionId }, { ...report, finished: false }, { ...report, recoveryAvailable: false }, { ...report, items: [{ ...report.items[0], state: "applying" }] }]) expect(matchesWindowsIncidentResponse(req, { kind: "baseline-change", report: value })).toBe(false);
    expect(matchesWindowsIncidentResponse(req, { kind: "baseline-change", report: { ...report, recoveryAvailable: false, items: [{ ...report.items[0], state: "uncertain" }] } })).toBe(true);
  });
});


it("bounds file diagnosis and rejects injected effect parameters", () => {
  const request = { action: "inspect-file-access", sessionId, path: "C:\\sample.txt" } as const;
  expect(isWindowsIncidentRequest(request)).toBe(true);
  expect(isWindowsIncidentRequest({ ...request, elevate: true })).toBe(false);
  expect(isWindowsIncidentRequest({ ...request, path: "C:\\x\nwhoami" })).toBe(false);
  const inspection = { path: request.path, observedAt: "2026-10-26T01:00:00Z", attributes: "ReadOnly", owner: "SYSTEM", accessRules: [{ identity: "Users", rights: "ReadAndExecute", access: "Allow", inherited: true }], processes: [], services: [{ name: "driver", displayName: "Driver", state: "Running", startMode: "Boot", path: request.path, kind: "driver" }], warnings: ["权限观察不代表有效删除权限"] };
  expect(matchesWindowsIncidentResponse(request, { kind: "file-access", inspection })).toBe(true);
  for (const changed of [{ ...inspection, services: Array(257).fill(inspection.services[0]) }, { ...inspection, accessRules: Array(65).fill(inspection.accessRules[0]) }, { ...inspection, deleted: true }, { ...inspection, services: [{ ...inspection.services[0], kind: "kernel-exploit" }] }]) expect(matchesWindowsIncidentResponse(request, { kind: "file-access", inspection: changed })).toBe(false);
});
