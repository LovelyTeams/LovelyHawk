import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const mainSource = readFileSync(new URL("./index.ts", import.meta.url), "utf8");
const preloadSource = readFileSync(new URL("../preload/index.ts", import.meta.url), "utf8");
const contractSource = readFileSync(new URL("../shared/contract.ts", import.meta.url), "utf8");
const appSource = readFileSync(new URL("../renderer/App.tsx", import.meta.url), "utf8");

function frozenApiBody(): string {
  const match = preloadSource.match(
    /const api: LovelyResApi = Object\.freeze\(\{(?<body>[\s\S]*?)^\}\);/mu,
  );
  expect(match?.groups?.body).toBeDefined();
  return match?.groups?.body ?? "";
}

describe("central Check Audit Electron boundary", () => {
  it("keeps the exact three read methods in the frozen exact 118 preload", () => {
    const body = frozenApiBody();
    const names = [...body.matchAll(/^  (?<name>[A-Za-z_$][A-Za-z0-9_$]*):/gmu)]
      .map((match) => match.groups?.name);
    expect(names).toHaveLength(118);
    for (const name of [
      "getCheckAuditCatalog",
      "collectCheckAuditStatus",
      "readCheckAuditLog",
    ]) expect(names.filter((candidate) => candidate === name)).toEqual([name]);
    expect(body).toMatch(
      /getCheckAuditCatalog: \(bindingHandle: string, input: CheckAuditCatalogInput\) =>\s*ipcRenderer\.invoke\("lovelyres:check-audit:catalog:get", \{ bindingHandle, input \}\)/u,
    );
    expect(body).toMatch(
      /collectCheckAuditStatus: \(bindingHandle: string, snapshotHandle: string\) =>\s*ipcRenderer\.invoke\("lovelyres:check-audit:status:collect", \{\s*bindingHandle,\s*snapshotHandle,\s*\}\)/u,
    );
    expect(body).toMatch(
      /readCheckAuditLog: \(\s*bindingHandle: string,\s*snapshotHandle: string,\s*input: CheckAuditLogInput,\s*\) => ipcRenderer\.invoke\("lovelyres:check-audit:log:read", \{\s*bindingHandle,\s*snapshotHandle,\s*input,\s*\}\)/u,
    );
  });

  it("registers three exact object-shaped IPC routes with bounded validators", () => {
    for (const channel of [
      "lovelyres:check-audit:catalog:get",
      "lovelyres:check-audit:status:collect",
      "lovelyres:check-audit:log:read",
    ]) expect((mainSource.match(new RegExp(channel, "gu")) ?? [])).toHaveLength(1);
    const boundary = mainSource.slice(
      mainSource.indexOf('ipcMain.handle("lovelyres:check-audit:catalog:get"'),
      mainSource.indexOf('ipcMain.handle("lovelyres:log-analysis:sources:discover"'),
    );
    expect((boundary.match(/values\.length !== 1/gu) ?? [])).toHaveLength(3);
    expect(boundary).toContain('hasOnlyKeys(value, ["bindingHandle", "input"])');
    expect(boundary).toContain(
      'hasOnlyKeys(value, ["bindingHandle", "snapshotHandle"])',
    );
    expect(boundary).toContain(
      'hasOnlyKeys(value, ["bindingHandle", "snapshotHandle", "input"])',
    );
    expect((boundary.match(/isCheckAuditOpaqueHandle/gu) ?? [])).toHaveLength(5);
    expect((boundary.match(/isCheckAuditCatalogInput/gu) ?? [])).toHaveLength(1);
    expect((boundary.match(/isCheckAuditLogInput/gu) ?? [])).toHaveLength(1);
    expect(boundary).not.toMatch(
      /\b(?:sessionId|targetIdentity|targetGeneration|guard|remotePath|shell|terminal|export|plan|confirm|execute|mutat)/u,
    );
  });

  it("keeps the aggregate API typed, target-opaque and read-only", () => {
    const api = contractSource.slice(
      contractSource.indexOf("export interface LovelyResApi"),
      contractSource.indexOf("type JsonRecord"),
    );
    expect(api).toMatch(
      /getCheckAuditCatalog\(\s*bindingHandle: string,\s*input: CheckAuditCatalogInput,\s*\): Promise<CheckAuditCatalog>;/u,
    );
    expect(api).toMatch(
      /collectCheckAuditStatus\(\s*bindingHandle: string,\s*snapshotHandle: string,\s*\): Promise<CheckAuditStatus>;/u,
    );
    expect(api).toMatch(
      /readCheckAuditLog\(\s*bindingHandle: string,\s*snapshotHandle: string,\s*input: CheckAuditLogInput,\s*\): Promise<CheckAuditLogResult>;/u,
    );
    for (const forbidden of [
      "planCheckAudit",
      "confirmCheckAudit",
      "executeCheckAudit",
      "restoreCheckAudit",
      "exportCheckAudit",
      "openCheckAuditTerminal",
      "readCheckAuditFile",
      "invoke(",
    ]) expect(api).not.toContain(forbidden);
  });

  it("mounts the page with only the current opaque binding handle", () => {
    const branch = appSource.slice(
      appSource.indexOf('activePage.id === "check-audit"'),
      appSource.indexOf("<MigrationPlaceholder", appSource.indexOf('activePage.id === "check-audit"')),
    );
    expect(branch).toContain("<CheckAuditPage");
    expect(branch).toContain("bindingHandle={activeTarget?.bindingHandle ?? null}");
    expect(branch).toContain("api={window.lovelyres}");
    expect(branch).not.toContain("connection={activeTarget}");
    expect(branch).not.toMatch(/target=|session|guard/u);
  });
});
