import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const mainSource = readFileSync(new URL("./index.ts", import.meta.url), "utf8");
const preloadSource = readFileSync(new URL("../preload/index.ts", import.meta.url), "utf8");
const contractSource = readFileSync(new URL("../shared/contract.ts", import.meta.url), "utf8");
const appSource = readFileSync(new URL("../renderer/App.tsx", import.meta.url), "utf8");
const pageSource = readFileSync(new URL("../renderer/LogAnalysisPage.tsx", import.meta.url), "utf8");
const backendSource = readFileSync(
  new URL("../../../crates/lovelyres-electron-backend/src/lib.rs", import.meta.url),
  "utf8",
);

function frozenApiBody(): string {
  const match = preloadSource.match(
    /const api: LovelyResApi = Object\.freeze\(\{(?<body>[\s\S]*?)^\}\);/mu,
  );
  expect(match?.groups?.body).toBeDefined();
  return match?.groups?.body ?? "";
}

describe("central Log Analysis Electron boundary", () => {
  it("keeps the exact four read methods in the frozen exact 124 preload", () => {
    const body = frozenApiBody();
    const names = [...body.matchAll(/^  (?<name>[A-Za-z_$][A-Za-z0-9_$]*):/gmu)]
      .map((match) => match.groups?.name);
    expect(names).toHaveLength(124);
    for (const name of [
      "discoverLogSources",
      "readLogSource",
      "correlateLogSources",
      "searchLogIocs",
    ]) expect(names.filter((candidate) => candidate === name)).toEqual([name]);
    expect(body).toMatch(
      /discoverLogSources: \(bindingHandle: string\) =>\s*ipcRenderer\.invoke\("lovelyres:log-analysis:sources:discover", bindingHandle\)/u,
    );
    expect(body).toContain('ipcRenderer.invoke("lovelyres:log-analysis:source:read", {');
    expect(body).toContain('ipcRenderer.invoke("lovelyres:log-analysis:sources:correlate", {');
    expect(body).toContain('ipcRenderer.invoke("lovelyres:log-analysis:iocs:search", {');
  });

  it("registers four exact arity-one IPC routes with closed input validators", () => {
    for (const channel of [
      "lovelyres:log-analysis:sources:discover",
      "lovelyres:log-analysis:source:read",
      "lovelyres:log-analysis:sources:correlate",
      "lovelyres:log-analysis:iocs:search",
    ]) expect((mainSource.match(new RegExp(channel, "gu")) ?? [])).toHaveLength(1);
    const boundary = mainSource.slice(
      mainSource.indexOf('ipcMain.handle("lovelyres:log-analysis:sources:discover"'),
      mainSource.indexOf('ipcMain.handle("lovelyres:kubernetes:availability:get"'),
    );
    expect((boundary.match(/values\.length !== 1/gu) ?? [])).toHaveLength(4);
    expect(boundary).toContain(
      'hasOnlyKeys(value, ["bindingHandle", "snapshotHandle", "sourceHandle", "input"])',
    );
    expect((boundary.match(
      /hasOnlyKeys\(value, \["bindingHandle", "snapshotHandle", "input"\]\)/gu,
    ) ?? [])).toHaveLength(2);
    expect((boundary.match(/isLogAnalysisOpaqueHandle/gu) ?? [])).toHaveLength(8);
    expect((boundary.match(/isLogSourceReadInput/gu) ?? [])).toHaveLength(1);
    expect((boundary.match(/isLogCorrelationInput/gu) ?? [])).toHaveLength(1);
    expect((boundary.match(/isLogIocSearchInput/gu) ?? [])).toHaveLength(1);
    expect(boundary).not.toMatch(
      /\b(?:sessionId|targetIdentity|targetGeneration|guard|remotePath|shell|terminal|export|plan|confirm|execute|mutat)/u,
    );
  });

  it("keeps the aggregate API typed, target-opaque and strictly read-only", () => {
    const api = contractSource.slice(
      contractSource.indexOf("export interface LovelyResApi"),
      contractSource.indexOf("type JsonRecord"),
    );
    expect(api).toContain(
      "discoverLogSources(bindingHandle: string): Promise<LogSourceSnapshot>;",
    );
    expect(api).toMatch(
      /readLogSource\(\s*bindingHandle: string,\s*snapshotHandle: string,\s*sourceHandle: string,\s*input: LogSourceReadInput,\s*\): Promise<LogSourceReadResult>;/u,
    );
    expect(api).toMatch(
      /correlateLogSources\(\s*bindingHandle: string,\s*snapshotHandle: string,\s*input: LogCorrelationInput,\s*\): Promise<LogCorrelationResult>;/u,
    );
    expect(api).toMatch(
      /searchLogIocs\(\s*bindingHandle: string,\s*snapshotHandle: string,\s*input: LogIocSearchInput,\s*\): Promise<LogIocSearchResult>;/u,
    );
    for (const forbidden of [
      "analyzeLogWithAi",
      "addLogRule",
      "removeLogRule",
      "exportLogAnalysis",
      "openLogFile",
      "launchLogTerminal",
      "executeLogCommand",
      "invoke(",
    ]) expect(api).not.toContain(forbidden);
  });

  it("mounts the page with only the current opaque binding handle", () => {
    const branch = appSource.slice(
      appSource.indexOf('activePage.id === "log-analysis"'),
      appSource.indexOf("<MigrationPlaceholder", appSource.indexOf('activePage.id === "log-analysis"')),
    );
    expect(branch).toContain("<LogAnalysisPage");
    expect(branch).toContain("bindingHandle={activeTarget?.bindingHandle ?? null}");
    expect(branch).toContain("api={window.lovelyres}");
    expect(branch).not.toContain("connection={activeTarget}");
    expect(branch).not.toMatch(/target=|session|guard/u);
    expect(pageSource).toContain("bindingHandle: string | null;");
    expect(pageSource).not.toContain("SshTargetSummary");
    expect(pageSource).not.toContain("LogAnalysisConnection");
  });

  it("closes sidecar log capabilities before real SSH disconnect", () => {
    const branch = backendSource.split("RpcMethod::SshBindingDisconnect =>")[1]
      ?.split("RpcMethod::TerminalOpen")[0] ?? "";
    const close = branch.indexOf("self.log_analysis_read.close_binding(&params.binding_handle);");
    const disconnect = branch.indexOf(".disconnect_binding(&params.binding_handle)");
    expect(close).toBeGreaterThanOrEqual(0);
    expect(disconnect).toBeGreaterThan(close);
  });
});
