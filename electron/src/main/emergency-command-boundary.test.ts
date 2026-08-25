import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const mainSource = readFileSync(new URL("./index.ts", import.meta.url), "utf8");
const preloadSource = readFileSync(new URL("../preload/index.ts", import.meta.url), "utf8");
const contractSource = readFileSync(new URL("../shared/contract.ts", import.meta.url), "utf8");
const backendClientSource = readFileSync(new URL("./backend-client.ts", import.meta.url), "utf8");
const appSource = readFileSync(new URL("../renderer/App.tsx", import.meta.url), "utf8");
const pageSource = readFileSync(
  new URL("../renderer/EmergencyCommandsPage.tsx", import.meta.url),
  "utf8",
);
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

function expectLiteralErrorsOnly(source: string, expectedCount: number): void {
  const expressions = [...source.matchAll(/throw new Error\((?<expression>[^\r\n]+)\);/gu)]
    .map((match) => match.groups?.expression ?? "");
  expect(expressions).toHaveLength(expectedCount);
  for (const expression of expressions) expect(expression).toMatch(/^"[^"]+"$/u);
}

describe("central Emergency Commands Electron boundary", () => {
  it("keeps the exact two closed methods in the frozen exact 118 preload", () => {
    const body = frozenApiBody();
    const names = [...body.matchAll(/^  (?<name>[A-Za-z_$][A-Za-z0-9_$]*):/gmu)]
      .map((match) => match.groups?.name);
    expect(names).toHaveLength(118);
    for (const name of ["loadEmergencyCommandCatalog", "runEmergencyCommand"]) {
      expect(names.filter((candidate) => candidate === name)).toEqual([name]);
    }
    expect(body).toMatch(
      /loadEmergencyCommandCatalog: \(bindingHandle: string\) =>\s*ipcRenderer\.invoke\("lovelyres:emergency-command:catalog:load", bindingHandle\)/u,
    );
    expect(body).toContain('ipcRenderer.invoke("lovelyres:emergency-command:run", {');
  });

  it("registers two exact arity-one IPC routes with strict opaque-only validators", () => {
    for (const channel of [
      "lovelyres:emergency-command:catalog:load",
      "lovelyres:emergency-command:run",
    ]) expect((mainSource.match(new RegExp(channel, "gu")) ?? [])).toHaveLength(1);

    const boundary = mainSource.slice(
      mainSource.indexOf('ipcMain.handle("lovelyres:emergency-command:catalog:load"'),
      mainSource.indexOf('ipcMain.handle("lovelyres:packet-capture:interfaces:list"'),
    );
    expect((boundary.match(/validateSender\(event\)/gu) ?? [])).toHaveLength(2);
    expect((boundary.match(/values\.length !== 1/gu) ?? [])).toHaveLength(2);
    expect((boundary.match(/isEmergencyCommandOpaqueHandle/gu) ?? [])).toHaveLength(4);
    expect(boundary).toContain(
      'hasOnlyKeys(value, ["bindingHandle", "snapshotHandle", "commandHandle"])',
    );
    expectLiteralErrorsOnly(boundary, 2);
    for (const forbidden of [
      "commandText",
      "remotePath",
      "targetIdentity",
      "targetGeneration",
      "connectionId",
      "sessionId",
      "mutationHandle",
      "exportPath",
      "terminalHandle",
      "shellText",
      "genericInvoke",
    ]) expect(boundary).not.toContain(forbidden);
  });

  it("pins the exact two sidecar RPCs and validates correlated bounded DTOs", () => {
    const methods = backendClientSource.slice(
      backendClientSource.indexOf("export const EMERGENCY_COMMAND_RPC_METHODS"),
      backendClientSource.indexOf("export const SETTINGS_RPC_METHODS"),
    );
    expect(methods).toContain('loadCatalog: "emergency-command.catalog.load"');
    expect(methods).toContain('run: "emergency-command.run"');
    expect((methods.match(/emergency-command\./gu) ?? [])).toHaveLength(2);

    const boundary = backendClientSource.slice(
      backendClientSource.indexOf("async loadEmergencyCommandCatalog"),
      backendClientSource.indexOf("async listPacketCaptureInterfaces"),
    );
    expect((boundary.match(/isEmergencyCommandOpaqueHandle/gu) ?? [])).toHaveLength(2);
    expect((boundary.match(/isEmergencyCommandCatalog/gu) ?? [])).toHaveLength(1);
    expect((boundary.match(/isEmergencyCommandResult/gu) ?? [])).toHaveLength(1);
    expect(boundary).toContain("value.snapshotHandle !== snapshotHandle");
    expect(boundary).toContain("value.commandHandle !== commandHandle");
    expect(boundary).toContain("EMERGENCY_COMMAND_CATALOG_TIMEOUT_MS");
    expect(boundary).toContain("EMERGENCY_COMMAND_RUN_TIMEOUT_MS");
    expectLiteralErrorsOnly(boundary, 4);
  });

  it("keeps the aggregate API closed, typed and capability-only", () => {
    const api = contractSource.slice(
      contractSource.indexOf("loadEmergencyCommandCatalog(bindingHandle: string)"),
      contractSource.indexOf("listPacketCaptureInterfaces(bindingHandle: string)"),
    );
    expect(api).toContain(
      "loadEmergencyCommandCatalog(bindingHandle: string): Promise<EmergencyCommandCatalog>;",
    );
    expect(api).toMatch(
      /runEmergencyCommand\(\s*bindingHandle: string,\s*snapshotHandle: string,\s*commandHandle: string,\s*\): Promise<EmergencyCommandResult>;/u,
    );
    expect(api).not.toMatch(
      /\b(?:targetIdentity|targetGeneration|connectionId|sessionId|commandText|remotePath|shellText|mutationHandle|exportPath|terminalHandle|genericInvoke)\b/u,
    );
  });

  it("mounts the page with only the opaque binding and clears late target state", () => {
    const branch = appSource.slice(
      appSource.indexOf('activePage.id === "emergency-commands"'),
      appSource.indexOf("<MigrationPlaceholder", appSource.indexOf('activePage.id === "emergency-commands"')),
    );
    expect(branch).toContain("<EmergencyCommandsPage");
    expect(branch).toContain("bindingHandle={activeTarget?.bindingHandle ?? null}");
    expect(branch).toContain("api={window.lovelyres}");
    expect(branch).not.toContain("connection={activeTarget}");
    expect(branch).not.toMatch(/target=|session=|connection=/u);
    expect(pageSource).toContain("bindingHandle: string | null;");
    expect(pageSource).toContain('dispatch({ type: "scope-changed", scope });');
    expect(pageSource).toContain("cancelled = true;");
    expect(pageSource).not.toContain("SshTargetSummary");
    expect(pageSource).not.toContain("EmergencyCommandsConnection");
    for (const forbidden of [
      "commandText",
      "remotePath",
      "targetIdentity",
      "targetGeneration",
      "connectionId",
      "sessionId",
      "runCustomCommand",
      "openTerminal",
      "openFile",
      "exportCommand",
      "planMutation",
      "genericInvoke",
    ]) expect(pageSource).not.toContain(forbidden);
  });

  it("closes emergency capabilities before the real SSH disconnect", () => {
    const branch = backendSource.split("RpcMethod::SshBindingDisconnect =>")[1]
      ?.split("RpcMethod::TerminalOpen")[0] ?? "";
    const close = branch.indexOf("self.emergency_command.close_binding(&params.binding_handle);");
    const disconnect = branch.indexOf(".disconnect_binding(&params.binding_handle)");
    expect(close).toBeGreaterThanOrEqual(0);
    expect(disconnect).toBeGreaterThan(close);
    expect(backendSource).toContain('serde(rename = "emergency-command.catalog.load")');
    expect(backendSource).toContain('serde(rename = "emergency-command.run")');
    expect((backendSource.match(/struct EmergencyCommand(?:Binding|Run)Params/gu) ?? []))
      .toHaveLength(2);
  });
});
