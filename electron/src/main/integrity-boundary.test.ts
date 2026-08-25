import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const mainSource = readFileSync(new URL("./index.ts", import.meta.url), "utf8");
const preloadSource = readFileSync(new URL("../preload/index.ts", import.meta.url), "utf8");
const contractSource = readFileSync(new URL("../shared/contract.ts", import.meta.url), "utf8");
const integrityContractSource = readFileSync(
  new URL("../shared/integrity-contract.ts", import.meta.url),
  "utf8",
);
const backendClientSource = readFileSync(new URL("./backend-client.ts", import.meta.url), "utf8");
const appSource = readFileSync(new URL("../renderer/App.tsx", import.meta.url), "utf8");
const pageSource = readFileSync(new URL("../renderer/IntegrityPage.tsx", import.meta.url), "utf8");
const helperSource = readFileSync(
  new URL("../renderer/integrity-helpers.ts", import.meta.url),
  "utf8",
);
const cssSource = readFileSync(new URL("../renderer/integrity.css", import.meta.url), "utf8");
const backendSource = readFileSync(
  new URL("../../../crates/lovelyres-electron-backend/src/lib.rs", import.meta.url),
  "utf8",
);
const integrityBackendSource = readFileSync(
  new URL("../../../crates/lovelyres-electron-backend/src/integrity_api.rs", import.meta.url),
  "utf8",
);

const methodNames = [
  "getIntegrityPresets",
  "listIntegrityBaselines",
  "startIntegrityComparison",
  "pollIntegrityComparison",
  "cancelIntegrityComparison",
] as const;

const channels = [
  "lovelyres:integrity:presets:get",
  "lovelyres:integrity:baselines:list",
  "lovelyres:integrity:comparison:start",
  "lovelyres:integrity:comparison:poll",
  "lovelyres:integrity:comparison:cancel",
] as const;

const rpcNames = [
  "integrity.presets.get",
  "integrity.baselines.list",
  "integrity.comparison.start",
  "integrity.comparison.poll",
  "integrity.comparison.cancel",
] as const;

function frozenApiBody(): string {
  const match = preloadSource.match(
    /const api: LovelyResApi = Object\.freeze\(\{(?<body>[\s\S]*?)^\}\);/mu,
  );
  expect(match?.groups?.body).toBeDefined();
  return match?.groups?.body ?? "";
}

function expectLiteralErrorsOnly(source: string, expectedCount: number): void {
  const expressions = [...source.matchAll(/throw new Error\((?<expression>[^\r\n]+)\);/gu)]
    .map((match) => match.groups?.expression ?? "");
  expect(expressions).toHaveLength(expectedCount);
  for (const expression of expressions) expect(expression).toMatch(/^"[^"]+"$/u);
}

describe("central File Integrity Electron boundary", () => {
  it("adds exact five fixed-arity methods to the frozen exact111 preload", () => {
    const body = frozenApiBody();
    const names = [...body.matchAll(/^  (?<name>[A-Za-z_$][A-Za-z0-9_$]*):/gmu)]
      .map((match) => match.groups?.name);
    expect(names).toHaveLength(111);
    for (const name of methodNames) {
      expect(names.filter((candidate) => candidate === name)).toEqual([name]);
    }
    const boundary = body.slice(
      body.indexOf("getIntegrityPresets:"),
      body.indexOf("loadSettings:"),
    );
    expect(boundary).toContain(
      'getIntegrityPresets: () =>\n    ipcRenderer.invoke("lovelyres:integrity:presets:get")',
    );
    expect(boundary).toContain("listIntegrityBaselines: (bindingHandle: string)");
    expect(boundary).toContain(
      "startIntegrityComparison: (bindingHandle: string, baselineHandle: string)",
    );
    expect(boundary).toContain("afterEvent: number");
    expect(boundary).toContain("limit: number");
    expect(boundary).toContain(
      "cancelIntegrityComparison: (bindingHandle: string, operationHandle: string)",
    );
    expect(boundary).not.toMatch(
      /\b(?:create|quarantine|customPath|remotePath|shell|file|export|genericInvoke|ipcRenderer\.send)\b/iu,
    );
  });

  it("registers exact strict IPC routes with exact-own-key input validation", () => {
    for (const channel of channels) {
      expect((mainSource.match(new RegExp(channel, "gu")) ?? [])).toHaveLength(1);
    }
    const boundary = mainSource.slice(
      mainSource.indexOf('ipcMain.handle("lovelyres:integrity:presets:get"'),
      mainSource.indexOf('ipcMain.handle("lovelyres:settings:get"'),
    );
    expect((boundary.match(/validateSender\(event\)/gu) ?? [])).toHaveLength(5);
    expect((boundary.match(/values\.length !== 0/gu) ?? [])).toHaveLength(1);
    expect((boundary.match(/values\.length !== 1/gu) ?? [])).toHaveLength(4);
    expect((boundary.match(/hasExactKeys\(value,/gu) ?? [])).toHaveLength(4);
    expect((boundary.match(/isIntegrityOpaqueHandle\(/gu) ?? [])).toHaveLength(7);
    expect((boundary.match(/isIntegrityPollRequest\(/gu) ?? [])).toHaveLength(1);
    expect((boundary.match(/value\.bindingHandle === value\.(?:baseline|operation)Handle/gu) ?? []))
      .toHaveLength(3);
    expectLiteralErrorsOnly(boundary, 5);
    expect(boundary).not.toMatch(/hasOnlyKeys|ipcRenderer|remotePath|shellCommand|exportIntegrity/iu);
  });

  it("pins exact five RPCs and rejects uncorrelated backend DTOs", () => {
    const constants = backendClientSource.slice(
      backendClientSource.indexOf("export const INTEGRITY_RPC_METHODS"),
      backendClientSource.indexOf("export const SETTINGS_RPC_METHODS"),
    );
    for (const method of rpcNames) {
      expect((constants.match(new RegExp(method.replaceAll(".", "\\."), "gu")) ?? []))
        .toHaveLength(1);
    }
    const boundary = backendClientSource.slice(
      backendClientSource.indexOf("async getIntegrityPresets"),
      backendClientSource.indexOf("async loadSettings"),
    );
    for (const validator of [
      "isIntegrityPresetCatalog",
      "isIntegrityBaselineList",
      "isIntegrityComparisonStarted",
      "isIntegrityComparisonPoll",
      "isIntegrityComparisonCancellation",
      "isIntegrityOpaqueHandle",
      "isIntegrityPollRequest",
    ]) expect(boundary).toContain(validator);
    expect(boundary).toContain("baseline.baselineHandle === bindingHandle");
    expect(boundary).toContain("value.baselineHandle !== baselineHandle");
    expect(boundary).toContain("value.operationHandle === bindingHandle");
    expect(boundary).toContain("value.operationHandle === baselineHandle");
    expect(boundary).toContain("value.operationHandle !== operationHandle");
    expect(boundary).toContain("value.baselineHandle === operationHandle");
    expect(boundary).toContain("value.nextEventCursor < afterEvent");
    expect(boundary).toContain("event.sequence <= afterEvent");
    expectLiteralErrorsOnly(boundary, 9);
    expect(boundary).not.toMatch(/remotePath|shellCommand|readFile|exportIntegrity|genericInvoke/iu);
  });

  it("keeps the aggregate contract concrete while the standalone page boundary stays unknown", () => {
    const aggregate = contractSource.slice(
      contractSource.indexOf("getIntegrityPresets():"),
      contractSource.indexOf("loadSettings():"),
    );
    for (const name of methodNames) expect(aggregate).toContain(name);
    for (const result of [
      "IntegrityPresetCatalog",
      "IntegrityBaselineList",
      "IntegrityComparisonStarted",
      "IntegrityComparisonPoll",
      "IntegrityComparisonCancellation",
    ]) expect(aggregate).toContain(`Promise<${result}>`);
    const standalone = integrityContractSource.slice(
      integrityContractSource.indexOf("export interface IntegrityApi"),
      integrityContractSource.indexOf("export const INTEGRITY_API_METHODS"),
    );
    expect((standalone.match(/Promise<unknown>/gu) ?? [])).toHaveLength(5);
    expect(standalone).not.toMatch(
      /createIntegrity|quarantineIntegrity|pathInput|shellCommand|readFile|exportIntegrity|genericInvoke/iu,
    );
  });

  it("mounts only the binding capability and closes active work through page lifecycle", () => {
    const branch = appSource.slice(
      appSource.indexOf('activePage.id === "integrity"'),
      appSource.indexOf('activePage.id === "log-analysis"'),
    );
    expect(branch).toContain("<IntegrityPage");
    expect(branch).toContain("bindingHandle={activeTarget?.bindingHandle ?? null}");
    expect(branch).toContain("api={window.lovelyres}");
    expect(branch).not.toMatch(/connection=|target=|session=|host=|username=/u);
    expect(pageSource).toContain("cancelIntegrityLifecycle(");
    expect(pageSource).toContain("api.cancelIntegrityComparison(bindingHandle, result.operationHandle)");
    expect(helperSource).toContain('stage !== "running"');
    expect(cssSource).toContain("background: var(--console-bg)");
    expect(cssSource).toContain("min-height: 100%");
    expect(cssSource).not.toMatch(/integrity-dialog|integrity-sftp|\.integrity-page \.danger/u);
  });

  it("composes one TargetGuard-bound backend and closes it before packet and SSH teardown", () => {
    expect(backendSource).toContain("mod integrity_api;");
    const state = backendSource.slice(
      backendSource.indexOf("pub struct BackendState"),
      backendSource.indexOf("struct NoteReplayEntry"),
    );
    const open = backendSource.slice(
      backendSource.indexOf("impl BackendState"),
      backendSource.indexOf("async fn replay_note_mutation"),
    );
    expect((state.match(/integrity: Arc<IntegrityApi>/gu) ?? [])).toHaveLength(1);
    expect((open.match(/Arc::new\(IntegrityApi::new/gu) ?? [])).toHaveLength(1);
    for (const method of rpcNames) expect(backendSource).toContain(`serde(rename = "${method}")`);
    for (const params of [
      "IntegrityBindingParams",
      "IntegrityBaselineParams",
      "IntegrityPollParams",
      "IntegrityOperationParams",
    ]) {
      const declaration = backendSource.indexOf(`struct ${params}`);
      const attribute = backendSource.lastIndexOf("deny_unknown_fields", declaration);
      expect(attribute).toBeGreaterThan(backendSource.lastIndexOf("#[derive(Deserialize)]", declaration));
    }
    const disconnect = backendSource.split("RpcMethod::SshBindingDisconnect =>")[1]
      ?.split("RpcMethod::TerminalOpen")[0] ?? "";
    const integrityClose = disconnect.indexOf("self.integrity.close_binding");
    expect(integrityClose).toBeGreaterThan(-1);
    expect(integrityClose).toBeLessThan(disconnect.indexOf("self.packet_capture_live"));
    expect(integrityClose).toBeLessThan(disconnect.indexOf("disconnect_binding"));
    expect(integrityBackendSource).toContain("target::TargetGuard");
    expect(integrityBackendSource).toMatch(/self\.services\s*\.target\(\)\s*\.validate/u);
    const publicSurface = `${preloadSource}\n${contractSource}\n${mainSource}`;
    expect(publicSurface).not.toMatch(
      /integrity[^\r\n]*(?:create|quarantine|custom-path|remote-path|shell|file|export|generic)/iu,
    );
  });
});
