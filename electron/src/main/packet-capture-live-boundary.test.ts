import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const mainSource = readFileSync(new URL("./index.ts", import.meta.url), "utf8");
const preloadSource = readFileSync(new URL("../preload/index.ts", import.meta.url), "utf8");
const contractSource = readFileSync(new URL("../shared/contract.ts", import.meta.url), "utf8");
const backendClientSource = readFileSync(new URL("./backend-client.ts", import.meta.url), "utf8");
const appSource = readFileSync(new URL("../renderer/App.tsx", import.meta.url), "utf8");
const pageSource = readFileSync(new URL("../renderer/PacketCapturePage.tsx", import.meta.url), "utf8");
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

describe("central Packet Capture Live Electron boundary", () => {
  it("keeps the exact four live methods in the frozen exact 116 preload", () => {
    const body = frozenApiBody();
    const names = [...body.matchAll(/^  (?<name>[A-Za-z_$][A-Za-z0-9_$]*):/gmu)]
      .map((match) => match.groups?.name);
    expect(names).toHaveLength(116);
    for (const name of [
      "listPacketCaptureInterfaces",
      "startPacketCapture",
      "pollPacketCapture",
      "stopPacketCapture",
    ]) expect(names.filter((candidate) => candidate === name)).toEqual([name]);
    expect(body).toContain(
      'ipcRenderer.invoke("lovelyres:packet-capture:interfaces:list", { bindingHandle })',
    );
    expect(body).toContain('ipcRenderer.invoke("lovelyres:packet-capture:start", {');
    expect(body).toContain('ipcRenderer.invoke("lovelyres:packet-capture:poll", {');
    expect(body).toContain('ipcRenderer.invoke("lovelyres:packet-capture:stop", {');
  });

  it("registers four exact arity-one IPC routes with exact-own-key validators", () => {
    for (const channel of [
      "lovelyres:packet-capture:interfaces:list",
      "lovelyres:packet-capture:start",
      "lovelyres:packet-capture:poll",
      "lovelyres:packet-capture:stop",
    ]) expect((mainSource.match(new RegExp(channel, "gu")) ?? [])).toHaveLength(1);

    const boundary = mainSource.slice(
      mainSource.indexOf('ipcMain.handle("lovelyres:packet-capture:interfaces:list"'),
      mainSource.indexOf('ipcMain.handle("lovelyres:application-log:list"'),
    );
    expect((boundary.match(/validateSender\(event\)/gu) ?? [])).toHaveLength(4);
    expect((boundary.match(/values\.length !== 1/gu) ?? [])).toHaveLength(4);
    expect((boundary.match(/hasExactKeys\(value,/gu) ?? [])).toHaveLength(4);
    expect((boundary.match(/isPacketCaptureOpaqueHandle/gu) ?? [])).toHaveLength(7);
    expect((boundary.match(/isPacketCaptureStartInput/gu) ?? [])).toHaveLength(1);
    expect((boundary.match(/isPacketCaptureCursor/gu) ?? [])).toHaveLength(1);
    expect(boundary).toContain('hasExactKeys(value, ["bindingHandle"])');
    expect(boundary).toContain(
      'hasExactKeys(value, ["bindingHandle", "interfaceHandle", "input"])',
    );
    expect(boundary).toContain(
      'hasExactKeys(value, ["bindingHandle", "captureHandle", "afterSequence"])',
    );
    expectLiteralErrorsOnly(boundary, 4);
    expect(boundary).not.toMatch(
      /\b(?:targetIdentity|targetGeneration|connectionId|sessionId|interfaceName|command|shell|path|mutation|file|terminal|export|genericInvoke)\b/u,
    );
  });

  it("pins four sidecar RPCs and validates bounded correlated responses", () => {
    const methods = backendClientSource.slice(
      backendClientSource.indexOf("export const PACKET_CAPTURE_LIVE_RPC_METHODS"),
      backendClientSource.indexOf("export const QUICK_DETECTION_RPC_METHODS"),
    );
    for (const method of [
      "packet-capture.interfaces.list",
      "packet-capture.start",
      "packet-capture.poll",
      "packet-capture.stop",
    ]) expect((methods.match(new RegExp(method.replaceAll(".", "\\."), "gu")) ?? []))
      .toHaveLength(1);

    const boundary = backendClientSource.slice(
      backendClientSource.indexOf("async listPacketCaptureInterfaces"),
      backendClientSource.indexOf("async listApplicationLogs"),
    );
    for (const validator of [
      "isPacketCaptureInterfaceList",
      "isPacketCaptureStarted",
      "isPacketCapturePoll",
      "isPacketCaptureStopped",
      "isPacketCaptureStartInput",
      "isPacketCaptureCursor",
    ]) expect(boundary).toContain(validator);
    expect(boundary).toContain("item.interfaceHandle === bindingHandle");
    expect(boundary).toContain("value.captureHandle === interfaceHandle");
    expect(boundary).toContain("value.captureHandle !== captureHandle");
    expect(boundary).toContain("event.sequence <= afterSequence");
    for (const timeout of [
      "PACKET_CAPTURE_LIST_TIMEOUT_MS",
      "PACKET_CAPTURE_START_TIMEOUT_MS",
      "PACKET_CAPTURE_POLL_TIMEOUT_MS",
      "PACKET_CAPTURE_STOP_TIMEOUT_MS",
    ]) expect(boundary).toContain(timeout);
    expectLiteralErrorsOnly(boundary, 8);
  });

  it("keeps the aggregate API concrete, binding-only, and free of generic primitives", () => {
    const api = contractSource.slice(
      contractSource.indexOf("listPacketCaptureInterfaces(bindingHandle: string)"),
      contractSource.indexOf("listApplicationLogs(filter:"),
    );
    expect(api).toContain(
      "listPacketCaptureInterfaces(bindingHandle: string): Promise<PacketCaptureInterfaceList>;",
    );
    expect(api).toMatch(
      /startPacketCapture\(\s*bindingHandle: string,\s*interfaceHandle: string,\s*input: PacketCaptureStartInput,\s*\): Promise<PacketCaptureStarted>;/u,
    );
    expect(api).toMatch(
      /pollPacketCapture\(\s*bindingHandle: string,\s*captureHandle: string,\s*afterSequence: number,\s*\): Promise<PacketCapturePoll>;/u,
    );
    expect(api).toMatch(
      /stopPacketCapture\(\s*bindingHandle: string,\s*captureHandle: string,\s*\): Promise<PacketCaptureStopped>;/u,
    );
    expect(api).not.toMatch(
      /\b(?:targetIdentity|targetGeneration|connectionId|sessionId|interfaceName|command|shell|path|mutation|file|terminal|export|genericInvoke)\b/u,
    );
  });

  it("mounts the page with only the current opaque binding handle", () => {
    const branch = appSource.slice(
      appSource.indexOf('activePage.id === "packet-capture"'),
      appSource.indexOf('activePage.id === "kubernetes"'),
    );
    expect(branch).toContain("<PacketCapturePage");
    expect(branch).toContain("bindingHandle={activeTarget?.bindingHandle ?? null}");
    expect(branch).toContain("api={window.lovelyres}");
    expect(branch).not.toContain("connection={activeTarget}");
    expect(branch).not.toMatch(/target=|session=|connection=/u);
    expect(pageSource).toContain("bindingHandle: string | null;");
    expect(pageSource).not.toContain("SshTargetSummary");
    expect(pageSource).not.toContain("PacketCaptureConnection");
    expect(pageSource).not.toMatch(
      /\b(?:targetIdentity|targetGeneration|connectionId|sessionId|interfaceName|commandText|remotePath|runCustomCommand|openTerminal|openFile|exportCapture|planMutation|genericInvoke)\b/u,
    );
  });

  it("uses one BackendState instance and closes captures before the real SSH disconnect", () => {
    expect(backendSource).toContain("packet_capture_live: PacketCaptureLiveApi");
    expect(backendSource).toContain(
      "PacketCaptureLiveApi::new(services.clone(), Arc::clone(&ssh))",
    );
    const branch = backendSource.split("RpcMethod::SshBindingDisconnect =>")[1]
      ?.split("RpcMethod::TerminalOpen")[0] ?? "";
    const close = branch.indexOf("self.packet_capture_live");
    const disconnect = branch.indexOf(".disconnect_binding(&params.binding_handle)");
    expect(close).toBeGreaterThanOrEqual(0);
    expect(disconnect).toBeGreaterThan(close);
    for (const method of [
      "packet-capture.interfaces.list",
      "packet-capture.start",
      "packet-capture.poll",
      "packet-capture.stop",
    ]) expect(backendSource).toContain(`serde(rename = "${method}")`);
    const productionBackend = backendSource.split("#[cfg(test)]")[0] ?? "";
    expect((productionBackend.match(/struct PacketCapture(?:Binding|Start|Poll|Handle)Params/gu) ?? []))
      .toHaveLength(4);
  });
});
