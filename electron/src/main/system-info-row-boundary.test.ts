import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const mainSource = readFileSync(new URL("./index.ts", import.meta.url), "utf8");
const preloadSource = readFileSync(new URL("../preload/index.ts", import.meta.url), "utf8");
const contractSource = readFileSync(new URL("../shared/contract.ts", import.meta.url), "utf8");
const backendClientSource = readFileSync(new URL("./backend-client.ts", import.meta.url), "utf8");
const pageSource = readFileSync(new URL("../renderer/SystemInfoPage.tsx", import.meta.url), "utf8");
const hookSource = readFileSync(
  new URL("../renderer/system-info-row-actions.ts", import.meta.url),
  "utf8",
);
const backendSource = readFileSync(
  new URL("../../../crates/lovelyres-electron-backend/src/lib.rs", import.meta.url),
  "utf8",
);
const actionApiSource = readFileSync(
  new URL("../../../crates/lovelyres-electron-backend/src/system_info_action_api.rs", import.meta.url),
  "utf8",
);

const CHANNELS = [
  "lovelyres:system-info:row:actions:list",
  "lovelyres:system-info:row:inspect",
  "lovelyres:system-info:row:action:plan",
  "lovelyres:system-info:row:action:confirm",
  "lovelyres:system-info:row:action:execute",
  "lovelyres:system-info:row:action:cancel",
];

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

describe("system-information row action Electron boundary", () => {
  it("adds exactly six row methods to the frozen exact 124 preload", () => {
    const body = frozenApiBody();
    const names = [...body.matchAll(/^  (?<name>[A-Za-z_$][A-Za-z0-9_$]*):/gmu)]
      .map((match) => match.groups?.name);
    expect(names).toHaveLength(124);
    for (const name of [
      "listSystemInfoRowActions",
      "inspectSystemInfoRow",
      "planSystemInfoRowAction",
      "confirmSystemInfoRowAction",
      "executeSystemInfoRowAction",
      "cancelSystemInfoRowAction",
    ]) {
      expect(names.filter((candidate) => candidate === name)).toEqual([name]);
    }
    const methods = body.slice(
      body.indexOf("  listSystemInfoRowActions:"),
      body.indexOf("  getBaselineCatalog:"),
    );
    // A row is only ever named by the sidecar's own snapshot handle and row
    // id, and an action only by its fixed key. No command, path, PID or unit
    // name crosses this boundary in either direction.
    expect((methods.match(/snapshotHandle: string/gu) ?? [])).toHaveLength(3);
    expect((methods.match(/rowId: string/gu) ?? [])).toHaveLength(3);
    expect((methods.match(/action: string/gu) ?? [])).toHaveLength(2);
    expect((methods.match(/planHandle: string/gu) ?? [])).toHaveLength(3);
    expect(methods).not.toMatch(/command|pid|unit|path|signal|username/iu);
    for (const channel of CHANNELS) expect(methods).toContain(`"${channel}"`);
  });

  it("registers six exact arity-one IPC routes with strict validators", () => {
    for (const channel of CHANNELS) {
      expect((mainSource.match(new RegExp(channel, "gu")) ?? [])).toHaveLength(1);
    }
    const boundary = mainSource.slice(
      mainSource.indexOf('ipcMain.handle("lovelyres:system-info:row:actions:list"'),
      mainSource.indexOf('ipcMain.handle("lovelyres:baseline:catalog:get"'),
    );
    expect((boundary.match(/validateSender\(event\)/gu) ?? [])).toHaveLength(6);
    expect((boundary.match(/values\.length !== 1/gu) ?? [])).toHaveLength(6);
    expect((boundary.match(/hasExactKeys\(/gu) ?? [])).toHaveLength(6);
    expect((boundary.match(/isSshOpaqueHandle\(value\.bindingHandle\)/gu) ?? [])).toHaveLength(6);
    expect((boundary.match(/isSystemInfoOpaqueHandle\(value\.snapshotHandle\)/gu) ?? [])).toHaveLength(3);
    expect((boundary.match(/isSystemInfoOpaqueHandle\(value\.planHandle\)/gu) ?? [])).toHaveLength(3);
    expect((boundary.match(/isBoundedString\(value\.rowId, 256, false\)/gu) ?? [])).toHaveLength(3);
    // The action is checked against the closed key shape before the sidecar
    // sees it, and the sidecar checks it against the closed set itself.
    expect((boundary.match(/isSystemInfoRowActionKey\(value\.action\)/gu) ?? [])).toHaveLength(2);
    expectLiteralErrorsOnly(boundary, 6);
    for (const forbidden of [
      "commandText",
      "remotePath",
      "targetIdentity",
      "connectionId",
      "sessionId",
      "shellText",
      "genericInvoke",
    ]) expect(boundary).not.toContain(forbidden);
  });

  it("pins the six sidecar RPCs, their typed API and the sidecar's closed action set", () => {
    for (const method of [
      'rowActions: "system-info.row.actions.list"',
      'rowInspect: "system-info.row.inspect"',
      'rowPlan: "system-info.row.action.plan"',
      'rowConfirm: "system-info.row.action.confirm"',
      'rowExecute: "system-info.row.action.execute"',
      'rowCancel: "system-info.row.action.cancel"',
    ]) expect((backendClientSource.match(new RegExp(method.replace(/[.()]/gu, "\\$&"), "gu")) ?? [])).toHaveLength(1);
    for (const method of [
      "system-info.row.actions.list",
      "system-info.row.inspect",
      "system-info.row.action.plan",
      "system-info.row.action.confirm",
      "system-info.row.action.execute",
      "system-info.row.action.cancel",
    ]) expect(backendSource).toContain(`#[serde(rename = "${method}")]`);
    expect(backendSource).toContain("self.system_info.close_binding(&params.binding_handle);");
    for (const signature of [
      /listSystemInfoRowActions\(\s*bindingHandle: string,\s*snapshotHandle: string,\s*rowId: string,\s*\): Promise<SystemInfoRowActions>/u,
      /inspectSystemInfoRow\(\s*bindingHandle: string,\s*snapshotHandle: string,\s*rowId: string,\s*action: string,\s*\): Promise<SystemInfoRowInspection>/u,
      /planSystemInfoRowAction\(\s*bindingHandle: string,\s*snapshotHandle: string,\s*rowId: string,\s*action: string,\s*\): Promise<SystemInfoRowPlan>/u,
      /confirmSystemInfoRowAction\(bindingHandle: string, planHandle: string\): Promise<SystemInfoRowPlan>/u,
      /executeSystemInfoRowAction\(\s*bindingHandle: string,\s*planHandle: string,\s*\): Promise<SystemInfoRowReceipt>/u,
      /cancelSystemInfoRowAction\(bindingHandle: string, planHandle: string\): Promise<void>/u,
    ]) expect(contractSource).toMatch(signature);
    // The action vocabulary is the core's own enums, keyed by the sidecar.
    // Nothing is parsed into a command; a key that is not one of these is
    // `None`, and a change is planned through the core before it can run.
    expect(actionApiSource).toContain("pub(crate) fn parse(key: &str) -> Option<Self>");
    expect(actionApiSource).toContain("DangerousConfirmation::approve(stored.plan.definition())");
    expect(actionApiSource).toContain("registry.take_confirmed(&scope, plan_handle, now)?");
    expect(actionApiSource).not.toMatch(/execute_bound\(|format!\("kill|Command::new/u);
  });

  it("keeps the page to opaque row ids and plan handles, and cancels what it abandons", () => {
    expect(pageSource).toContain("useSystemInfoRowActions(api, bindingHandle, table?.snapshotHandle ?? null)");
    expect(pageSource).toContain("onContextMenu={(event) => rowActions.openMenu(event, row, cell)}");
    expect(pageSource).not.toMatch(/api\.(?:inspectSystemInfoRow|planSystemInfoRowAction|executeSystemInfoRowAction)/u);
    expect(hookSource).toContain("api.cancelSystemInfoRowAction(bindingHandle, abandoned)");
    expect(hookSource).toContain("const inFlight = useRef(false);");
    expect(hookSource).toContain("if (menuSequence.current !== sequence) return;");
    // A refreshed table invalidates every row id; the menu and dialog go with it.
    expect(hookSource).toMatch(/useEffect\(\(\) => \{\s*dismissMenu\(\);\s*close\(\);\s*\}, \[close, dismissMenu, snapshotHandle\]\)/u);
    for (const validator of [
      "isSystemInfoRowActions(result)",
      "isSystemInfoRowInspection(inspection)",
      "isSystemInfoRowPlan(plan)",
      "isSystemInfoRowPlan(confirmed)",
      "isSystemInfoRowReceipt(receipt)",
    ]) expect(hookSource).toContain(validator);
  });
});
