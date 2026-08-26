import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const mainSource = readFileSync(new URL("./index.ts", import.meta.url), "utf8");
const preloadSource = readFileSync(new URL("../preload/index.ts", import.meta.url), "utf8");
const contractSource = readFileSync(new URL("../shared/contract.ts", import.meta.url), "utf8");
const backendClientSource = readFileSync(new URL("./backend-client.ts", import.meta.url), "utf8");
const exportSource = readFileSync(
  new URL("./application-log-export-boundary.ts", import.meta.url),
  "utf8",
);
const appSource = readFileSync(new URL("../renderer/App.tsx", import.meta.url), "utf8");
const overlaySource = readFileSync(
  new URL("../renderer/ApplicationLogOverlay.tsx", import.meta.url),
  "utf8",
);
const backendSource = readFileSync(
  new URL("../../../crates/lovelyres-electron-backend/src/lib.rs", import.meta.url),
  "utf8",
);
const backendMainSource = readFileSync(
  new URL("../../../crates/lovelyres-electron-backend/src/main.rs", import.meta.url),
  "utf8",
);

const methodNames = [
  "listApplicationLogs",
  "setApplicationLogLevel",
  "clearApplicationLogBuffer",
  "getApplicationLogPreview",
  "exportApplicationLogs",
] as const;

const rpcNames = [
  "application-log.list",
  "application-log.level.set",
  "application-log.buffer.clear",
  "application-log.preview.get",
  "application-log.export.prepare",
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

describe("central Application Log Electron boundary", () => {
  it("keeps exact five fixed-arity methods in the frozen exact117 preload", () => {
    const body = frozenApiBody();
    const names = [...body.matchAll(/^  (?<name>[A-Za-z_$][A-Za-z0-9_$]*):/gmu)]
      .map((match) => match.groups?.name);
    expect(names).toHaveLength(117);
    for (const name of methodNames) {
      expect(names.filter((candidate) => candidate === name)).toEqual([name]);
    }
    expect(body).toContain(
      'ipcRenderer.invoke("lovelyres:application-log:list", filter)',
    );
    expect(body).toContain(
      'ipcRenderer.invoke("lovelyres:application-log:level:set", level)',
    );
    expect(body).toContain(
      'ipcRenderer.invoke("lovelyres:application-log:buffer:clear")',
    );
    expect(body).toContain(
      'ipcRenderer.invoke("lovelyres:application-log:preview:get", filter)',
    );
    expect(body).toContain(
      'ipcRenderer.invoke("lovelyres:application-log:export", filter)',
    );
    const boundary = body.slice(
      body.indexOf("listApplicationLogs:"),
      body.indexOf("getIntegrityPresets:"),
    );
    expect(boundary).not.toMatch(
      /\b(?:bindingHandle|target|session|connection|stderr|path|contents|shell|terminal|genericInvoke)\b/u,
    );
  });

  it("registers exact strict IPC routes with fixed no-echo failures", () => {
    for (const channel of [
      "lovelyres:application-log:list",
      "lovelyres:application-log:level:set",
      "lovelyres:application-log:buffer:clear",
      "lovelyres:application-log:preview:get",
      "lovelyres:application-log:export",
    ]) expect((mainSource.match(new RegExp(channel, "gu")) ?? [])).toHaveLength(1);
    const boundary = mainSource.slice(
      mainSource.indexOf('ipcMain.handle("lovelyres:application-log:list"'),
      mainSource.indexOf('ipcMain.handle("lovelyres:integrity:presets:get"'),
    );
    expect((boundary.match(/validateSender\(event\)/gu) ?? [])).toHaveLength(5);
    expect((boundary.match(/values\.length !== 1/gu) ?? [])).toHaveLength(4);
    expect((boundary.match(/values\.length !== 0/gu) ?? [])).toHaveLength(1);
    expect((boundary.match(/isApplicationLogFilter\(values\[0\]\)/gu) ?? []))
      .toHaveLength(3);
    expect((boundary.match(/isApplicationLogLevel\(values\[0\]\)/gu) ?? []))
      .toHaveLength(1);
    expectLiteralErrorsOnly(boundary, 6);
    expect(boundary).not.toMatch(
      /\b(?:bindingHandle|targetIdentity|targetGeneration|connectionId|sessionId|stderr|command|shell|remotePath|terminal|genericInvoke)\b/u,
    );
  });

  it("pins five RPCs and validates all public and internal responses", () => {
    const methods = backendClientSource.slice(
      backendClientSource.indexOf("export const APPLICATION_LOG_RPC_METHODS"),
      backendClientSource.indexOf("export const INTEGRITY_RPC_METHODS"),
    );
    for (const method of rpcNames) {
      expect((methods.match(new RegExp(method.replaceAll(".", "\\."), "gu")) ?? []))
        .toHaveLength(1);
    }
    const boundary = backendClientSource.slice(
      backendClientSource.indexOf("async listApplicationLogs"),
      backendClientSource.indexOf("async getIntegrityPresets"),
    );
    for (const validator of [
      "isApplicationLogFilter",
      "isApplicationLogSnapshot",
      "isApplicationLogLevel",
      "isApplicationLogLevelResult",
      "isApplicationLogClearResult",
      "isApplicationLogPreview",
      "isInternalApplicationLogExportPayload",
    ]) expect(boundary).toContain(validator);
    expect(boundary).toContain("value.level !== level");
    expectLiteralErrorsOnly(boundary, 9);
    expect(boundary).not.toMatch(
      /\b(?:bindingHandle|targetIdentity|targetGeneration|connectionId|sessionId|stderr|command|shell|remotePath|terminal|genericInvoke)\b/u,
    );
  });

  it("keeps the aggregate contract concrete, local, and authority-free", () => {
    const api = contractSource.slice(
      contractSource.indexOf("listApplicationLogs(filter:"),
      contractSource.indexOf("getIntegrityPresets():"),
    );
    for (const name of methodNames) expect(api).toContain(name);
    for (const result of [
      "ApplicationLogSnapshot",
      "ApplicationLogLevelResult",
      "ApplicationLogClearResult",
      "ApplicationLogPreview",
      "ApplicationLogExportResult",
    ]) expect(api).toContain(`Promise<${result}>`);
    expect(api).not.toMatch(
      /\b(?:bindingHandle|target|session|connection|stderr|command|shell|path|contents|terminal|genericInvoke)\b/u,
    );
  });

  it("keeps export bytes main-only behind native create-only durable output", () => {
    const ipc = mainSource.slice(
      mainSource.indexOf('ipcMain.handle("lovelyres:application-log:export"'),
      mainSource.indexOf('ipcMain.handle("lovelyres:integrity:presets:get"'),
    );
    expect(ipc).toContain("backend.prepareApplicationLogExport");
    expect(ipc).toContain("dialog.showSaveDialog(mainWindow");
    expect(ipc).toContain("cancelledApplicationLogExport()");
    expect(ipc).toContain("saveApplicationLogExport(selection.filePath, payload)");
    expect(exportSource).toContain('fs.promises.open(selectedPath, "wx", 0o600)');
    expect(exportSource).toContain("await file.sync()");
    expect(exportSource).toContain("fileName: path.basename(selectedPath)");
    const publicApi = `${contractSource}\n${preloadSource}\n${overlaySource}`;
    expect(publicApi).not.toContain("InternalApplicationLogExportPayload");
    expect(publicApi).not.toContain("prepareApplicationLogExport");
  });

  it("mounts a global overlay and cancels late work before transitions", () => {
    const branch = appSource.slice(
      appSource.indexOf(") : applicationLogOpen ? ("),
      appSource.indexOf(") : null}", appSource.indexOf(") : applicationLogOpen ? (")),
    );
    expect(branch).toContain("<ApplicationLogOverlay");
    expect(branch).toContain("api={window.lovelyres}");
    expect(branch).not.toMatch(/activeTarget|bindingHandle|target=|session=|connection=/u);
    const disconnect = appSource.slice(
      appSource.indexOf("async function disconnectTarget()"),
      appSource.indexOf("async function openSshTerminal()"),
    );
    expect(disconnect.indexOf("closeApplicationLog()"))
      .toBeLessThan(disconnect.indexOf("disconnectSshBinding(bindingHandle)"));
    expect(appSource).toContain(
      "if (applicationLogOpen) applicationLogOverlayRef.current?.beforeClose();",
    );
    expect(overlaySource).toContain(
      "useImperativeHandle(ref, () => ({ beforeClose }), [beforeClose])",
    );
    expect(overlaySource).toContain("deactivateApplicationLogOverlay(alive, request, operation)");
  });

  it("uses one local store on the unique subscriber and never loops stderr into renderer", () => {
    const state = backendSource.slice(
      backendSource.indexOf("pub struct BackendState"),
      backendSource.indexOf("struct NoteReplayEntry"),
    );
    expect((state.match(/diagnostic_log: DiagnosticLogApi/gu) ?? [])).toHaveLength(1);
    const open = backendSource.slice(
      backendSource.indexOf("impl BackendState"),
      backendSource.indexOf("async fn replay_note_mutation"),
    );
    expect((open.match(/DiagnosticLogApi::new/gu) ?? [])).toHaveLength(1);
    expect((backendMainSource.match(/\.try_init\(\)/gu) ?? [])).toHaveLength(1);
    expect(backendMainSource).toContain("with_filter(stderr_filter)");
    expect(backendMainSource).toContain("with(diagnostic_capture.layer())");
    const disconnect = backendSource.split("RpcMethod::SshBindingDisconnect =>")[1]
      ?.split("RpcMethod::TerminalOpen")[0] ?? "";
    expect(disconnect).not.toContain("diagnostic_log.clear_buffer");
    const publicBoundary = `${preloadSource}\n${contractSource}\n${mainSource}`;
    expect(publicBoundary).not.toMatch(/application-log[^\r\n]*(?:stderr|stderr\.read)/iu);
    for (const method of rpcNames) expect(backendSource).toContain(`serde(rename = "${method}")`);
  });
});
