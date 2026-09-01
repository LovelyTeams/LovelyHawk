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
const pathActionsSource = readFileSync(
  new URL("../renderer/emergency-path-actions.ts", import.meta.url),
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
  it("keeps the exact seven closed methods in the frozen exact 124 preload", () => {
    const body = frozenApiBody();
    const names = [...body.matchAll(/^  (?<name>[A-Za-z_$][A-Za-z0-9_$]*):/gmu)]
      .map((match) => match.groups?.name);
    expect(names).toHaveLength(124);
    for (const name of [
      "loadEmergencyCommandCatalog",
      "runEmergencyCommand",
      "inspectEmergencyPath",
      "planEmergencyPathAction",
      "confirmEmergencyPathAction",
      "executeEmergencyPathAction",
      "cancelEmergencyPathAction",
    ]) {
      expect(names.filter((candidate) => candidate === name)).toEqual([name]);
    }
    // Acting on a file goes through the handle the run handed out. A path is
    // never a parameter, so a compromised window cannot name its own target.
    const actions = body.slice(
      body.indexOf("  inspectEmergencyPath:"),
      body.indexOf("  listPacketCaptureInterfaces:"),
    );
    expect((actions.match(/pathHandle: string/gu) ?? [])).toHaveLength(2);
    expect((actions.match(/planHandle: string/gu) ?? [])).toHaveLength(3);
    expect(actions).not.toMatch(/path: string|remotePath|mode|content/u);
    expect(body).toMatch(
      /loadEmergencyCommandCatalog: \(bindingHandle: string\) =>\s*ipcRenderer\.invoke\("lovelyres:emergency-command:catalog:load", bindingHandle\)/u,
    );
    expect(body).toContain('ipcRenderer.invoke("lovelyres:emergency-command:run", {');
  });

  it("registers seven exact arity-one IPC routes with strict opaque-only validators", () => {
    for (const channel of [
      "lovelyres:emergency-command:catalog:load",
      "lovelyres:emergency-command:run",
      "lovelyres:emergency-command:path:inspect",
      "lovelyres:emergency-command:path:plan",
      "lovelyres:emergency-command:path:confirm",
      "lovelyres:emergency-command:path:execute",
      "lovelyres:emergency-command:path:cancel",
    ]) expect((mainSource.match(new RegExp(channel, "gu")) ?? [])).toHaveLength(1);

    const boundary = mainSource.slice(
      mainSource.indexOf('ipcMain.handle("lovelyres:emergency-command:catalog:load"'),
      mainSource.indexOf('ipcMain.handle("lovelyres:packet-capture:interfaces:list"'),
    );
    expect((boundary.match(/validateSender\(event\)/gu) ?? [])).toHaveLength(7);
    expect((boundary.match(/values\.length !== 1/gu) ?? [])).toHaveLength(7);
    // Fifteen, not fourteen: running a check can now name a container, and
    // that handle is checked exactly like every other one.
    expect((boundary.match(/isEmergencyCommandOpaqueHandle/gu) ?? [])).toHaveLength(15);
    expect(boundary).toContain(
      'hasOnlyKeys(value, ["bindingHandle", "snapshotHandle", "commandHandle", "containerHandle"])',
    );
    // Absent means the target itself, and absent is the only other thing it
    // may be — not an empty string, not a name.
    expect(boundary).toContain("!(value.containerHandle === undefined ||");
    // The only thing an action carries beyond two handles is which action it
    // is, and that is checked against the closed set.
    expect((boundary.match(/isEmergencyPathAction\(value\.action\)/gu) ?? [])).toHaveLength(1);
    expect(boundary).toContain('hasExactKeys(value, ["bindingHandle", "pathHandle", "action"])');
    expectLiteralErrorsOnly(boundary, 7);
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

  it("pins the exact seven sidecar RPCs and validates correlated bounded DTOs", () => {
    const methods = backendClientSource.slice(
      backendClientSource.indexOf("export const EMERGENCY_COMMAND_RPC_METHODS"),
      backendClientSource.indexOf("export const SETTINGS_RPC_METHODS"),
    );
    expect(methods).toContain('loadCatalog: "emergency-command.catalog.load"');
    expect(methods).toContain('run: "emergency-command.run"');
    expect(methods).toContain('inspectPath: "emergency-command.path.inspect"');
    expect(methods).toContain('planPath: "emergency-command.path.plan"');
    expect(methods).toContain('confirmPath: "emergency-command.path.confirm"');
    expect(methods).toContain('executePath: "emergency-command.path.execute"');
    expect(methods).toContain('cancelPath: "emergency-command.path.cancel"');
    expect((methods.match(/emergency-command\./gu) ?? [])).toHaveLength(7);

    const boundary = backendClientSource.slice(
      backendClientSource.indexOf("async loadEmergencyCommandCatalog"),
      backendClientSource.indexOf("async listPacketCaptureInterfaces"),
    );
    // Eight: the run method now also checks an optional container handle.
    expect((boundary.match(/isEmergencyCommandOpaqueHandle/gu) ?? [])).toHaveLength(8);
    expect((boundary.match(/isEmergencyCommandCatalog/gu) ?? [])).toHaveLength(1);
    expect((boundary.match(/isEmergencyCommandResult/gu) ?? [])).toHaveLength(1);
    expect(boundary).toContain("value.snapshotHandle !== snapshotHandle");
    expect(boundary).toContain("value.commandHandle !== commandHandle");
    expect(boundary).toContain("EMERGENCY_COMMAND_CATALOG_TIMEOUT_MS");
    expect(boundary).toContain("EMERGENCY_COMMAND_RUN_TIMEOUT_MS");
    // Each path reply is tied back to the handle that was asked about, so a
    // reply about a different file is rejected rather than acted on.
    expect(boundary).toContain("value.pathHandle !== pathHandle");
    expect(boundary).toContain("value.planHandle !== planHandle");
    expect(boundary).toContain("value.action !== action");
    expect((boundary.match(/isEmergencyPathDetail/gu) ?? [])).toHaveLength(1);
    expect((boundary.match(/isEmergencyPathPlan/gu) ?? [])).toHaveLength(2);
    expect((boundary.match(/isEmergencyPathReceipt/gu) ?? [])).toHaveLength(1);
    expectLiteralErrorsOnly(boundary, 13);
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
      /runEmergencyCommand\(\s*bindingHandle: string,\s*snapshotHandle: string,\s*commandHandle: string,[\s\S]*?containerHandle\?: string,\s*\): Promise<EmergencyCommandResult>;/u,
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

  it("acts on a file only through the handle the run handed out", () => {
    // The window displays offer.path so the menu can say what it will touch,
    // and passes offer.pathHandle when it asks for anything to happen.
    expect(pageSource).toContain("onPathMenu={pathActions.openMenu}");
    expect(pageSource).toContain("paths={result.paths}");
    for (const call of [
      "api.inspectEmergencyPath(bindingHandle, offer.pathHandle)",
      "api.planEmergencyPathAction(bindingHandle, offer.pathHandle, action)",
      "api.confirmEmergencyPathAction(bindingHandle, planHandle)",
      "api.executeEmergencyPathAction(bindingHandle, planHandle)",
      "api.cancelEmergencyPathAction(bindingHandle, abandoned)",
    ]) expect(pathActionsSource).toContain(call);
    // Nothing read out of the displayed text ever reaches the boundary.
    expect(pathActionsSource).not.toMatch(/api\.\w+\([^)]*offer\.path[^H]/u);
    // Every reply is re-checked here too, because a shape that crossed two
    // processes is not the shape this code was written against.
    for (const guard of [
      "isEmergencyPathDetail(detail)",
      "isEmergencyPathPlan(plan)",
      "isEmergencyPathPlan(confirmed)",
      "isEmergencyPathReceipt(receipt)",
    ]) expect(pathActionsSource).toContain(guard);
    // A second click during a round trip would plan or execute twice.
    expect(pathActionsSource).toContain("inFlight.current");
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
    for (const method of ["inspect", "plan", "confirm", "execute", "cancel"]) {
      expect(backendSource).toContain('serde(rename = "emergency-command.path.' + method + '")');
    }
    expect((backendSource.match(/struct EmergencyCommand(?:Binding|Run)Params/gu) ?? []))
      .toHaveLength(2);
    // Every path parameter is a handle. Nothing on this boundary takes a path.
    const pathParams = backendSource.slice(
      backendSource.indexOf("struct EmergencyCommandPathParams"),
      backendSource.indexOf("struct SftpBrowserBindingParams"),
    );
    expect(pathParams).not.toMatch(/path: String/u);
    // Path capabilities die with the binding, like the catalogue does.
    expect(backendSource).toContain("self.emergency_command.close_binding(&params.binding_handle);");
  });
});
