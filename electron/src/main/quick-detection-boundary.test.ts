import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const mainSource = readFileSync(new URL("./index.ts", import.meta.url), "utf8");
const preloadSource = readFileSync(new URL("../preload/index.ts", import.meta.url), "utf8");
const contractSource = readFileSync(new URL("../shared/contract.ts", import.meta.url), "utf8");
const backendClientSource = readFileSync(new URL("./backend-client.ts", import.meta.url), "utf8");
const appSource = readFileSync(new URL("../renderer/App.tsx", import.meta.url), "utf8");
const pageSource = readFileSync(new URL("../renderer/QuickDetectionPage.tsx", import.meta.url), "utf8");
const backendSource = readFileSync(
  new URL("../../../crates/lovelyres-electron-backend/src/lib.rs", import.meta.url),
  "utf8",
);

const methodNames = [
  "getQuickDetectionCatalog",
  "planQuickDetection",
  "startQuickDetection",
  "pollQuickDetection",
  "cancelQuickDetection",
  "listQuickDetectionHistory",
  "getQuickDetectionReport",
] as const;

const rpcNames = [
  "quick-detection.catalog.get",
  "quick-detection.plan",
  "quick-detection.start",
  "quick-detection.poll",
  "quick-detection.cancel",
  "quick-detection.history.list",
  "quick-detection.report.get",
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

describe("central Quick Detection Electron boundary", () => {
  it("keeps exact7 in the frozen exact118 preload with fixed arities", () => {
    const body = frozenApiBody();
    const names = [...body.matchAll(/^  (?<name>[A-Za-z_$][A-Za-z0-9_$]*):/gmu)]
      .map((match) => match.groups?.name);
    expect(names).toHaveLength(118);
    for (const name of methodNames) expect(names.filter((candidate) => candidate === name))
      .toEqual([name]);
    expect(body).toContain('ipcRenderer.invoke("lovelyres:quick-detection:catalog:get")');
    expect(body).toContain('ipcRenderer.invoke("lovelyres:quick-detection:plan", { bindingHandle, input })');
    for (const channel of ["start", "poll", "cancel", "history:list", "report:get"]) {
      expect(body).toContain(`ipcRenderer.invoke("lovelyres:quick-detection:${channel}", {`);
    }
  });

  it("registers seven exact IPC routes with exact-own-key validation and literal errors", () => {
    for (const channel of rpcNames.map((name) => `lovelyres:${name.replaceAll(".", ":")}`)) {
      expect((mainSource.match(new RegExp(channel, "gu")) ?? [])).toHaveLength(1);
    }
    const boundary = mainSource.slice(
      mainSource.indexOf('ipcMain.handle("lovelyres:quick-detection:catalog:get"'),
      mainSource.indexOf('ipcMain.handle("lovelyres:application-log:list"'),
    );
    expect((boundary.match(/validateSender\(event\)/gu) ?? [])).toHaveLength(7);
    expect((boundary.match(/values\.length !==/gu) ?? [])).toHaveLength(7);
    expect((boundary.match(/hasExactKeys\(value,/gu) ?? [])).toHaveLength(6);
    expect((boundary.match(/isQuickDetectionOpaqueHandle/gu) ?? [])).toHaveLength(10);
    expect(boundary).toContain('hasExactKeys(value, ["bindingHandle", "input"])');
    expect(boundary).toContain(
      'hasExactKeys(value, ["bindingHandle", "scanHandle", "afterEvent", "limit"])',
    );
    expect(boundary).toContain('hasExactKeys(value, ["bindingHandle", "offset", "limit"])');
    expect(boundary).toContain("isQuickDetectionPlanInput");
    expect(boundary).toContain("isQuickDetectionPollRequest");
    expect(boundary).toContain("isQuickDetectionHistoryRequest");
    expectLiteralErrorsOnly(boundary, 7);
    expect(boundary).not.toMatch(
      /\b(?:targetIdentity|targetGeneration|connectionId|sessionId|command|remotePath|shell|mutation|filePath|terminal|export|genericInvoke)\b/u,
    );
  });

  it("pins exact7 sidecar methods and validates every correlated response", () => {
    const methods = backendClientSource.slice(
      backendClientSource.indexOf("export const QUICK_DETECTION_RPC_METHODS"),
      backendClientSource.indexOf("export const APPLICATION_LOG_RPC_METHODS"),
    );
    for (const method of rpcNames) {
      expect((methods.match(new RegExp(method.replaceAll(".", "\\."), "gu")) ?? []))
        .toHaveLength(1);
    }
    const boundary = backendClientSource.slice(
      backendClientSource.indexOf("async getQuickDetectionCatalog"),
      backendClientSource.indexOf("async listApplicationLogs"),
    );
    for (const validator of [
      "isQuickDetectionCatalog",
      "isQuickDetectionPlanInput",
      "isQuickDetectionPlan",
      "isQuickDetectionScanStarted",
      "isQuickDetectionPollRequest",
      "isQuickDetectionPoll",
      "isQuickDetectionCancellation",
      "isQuickDetectionHistoryRequest",
      "isQuickDetectionHistoryPage",
      "isQuickDetectionReport",
    ]) expect(boundary).toContain(validator);
    expect(boundary).toContain("value.profile !== input.profile");
    expect(boundary).toContain("value.scanHandle !== scanHandle");
    expect(boundary).toContain("event.sequence <= afterEvent");
    expect(boundary).toContain("event.total !== value.total");
    expect(boundary).toContain("value.offset !== offset");
    expect(boundary).toContain("value.items.length > limit");
    expect(boundary).toContain("value.reportHandle !== reportHandle");
    expectLiteralErrorsOnly(boundary, 13);
  });

  it("keeps the aggregate API concrete and free of renderer authority primitives", () => {
    const api = contractSource.slice(
      contractSource.indexOf("getQuickDetectionCatalog():"),
      contractSource.indexOf("listApplicationLogs(filter:"),
    );
    for (const name of methodNames) expect(api).toContain(name);
    for (const result of [
      "QuickDetectionCatalog", "QuickDetectionPlan", "QuickDetectionScanStarted",
      "QuickDetectionPoll", "QuickDetectionCancellation", "QuickDetectionHistoryPage",
      "QuickDetectionReport",
    ]) expect(api).toContain(`Promise<${result}>`);
    expect(api).not.toMatch(
      /\b(?:targetIdentity|targetGeneration|connectionId|sessionId|command|remotePath|shell|mutation|filePath|terminal|export|genericInvoke|remediation)\b/u,
    );
  });

  it("mounts Quick Detection using only the current opaque binding handle", () => {
    const branch = appSource.slice(
      appSource.indexOf('activePage.id === "quick-detection"'),
      appSource.indexOf('activePage.id === "packet-capture"'),
    );
    expect(branch).toContain("<QuickDetectionPage");
    expect(branch).toContain("bindingHandle={activeTarget?.bindingHandle ?? null}");
    expect(branch).toContain("api={window.lovelyres}");
    expect(branch).not.toContain("connection={activeTarget}");
    expect(branch).not.toMatch(/target=|session=|connection=/u);
    const props = pageSource.slice(
      pageSource.indexOf("interface QuickDetectionPageProps"),
      pageSource.indexOf("const POLL_PAGE_SIZE"),
    );
    expect(props).toContain("bindingHandle: string | null;");
    expect(props).not.toContain("SshTargetSummary");
  });

  it("owns one backend API and eagerly closes it before SSH disconnect", () => {
    const state = backendSource.slice(
      backendSource.indexOf("pub struct BackendState"),
      backendSource.indexOf("struct NoteReplayEntry"),
    );
    expect((state.match(/quick_detection: Arc<QuickDetectionApi>/gu) ?? [])).toHaveLength(1);
    const open = backendSource.slice(
      backendSource.indexOf("impl BackendState"),
      backendSource.indexOf("async fn replay_note_mutation"),
    );
    expect((open.match(/QuickDetectionApi::new/gu) ?? [])).toHaveLength(1);
    const disconnect = backendSource.split("RpcMethod::SshBindingDisconnect =>")[1]
      ?.split("RpcMethod::TerminalOpen")[0] ?? "";
    const closeIndex = disconnect.indexOf("self.quick_detection.close_binding");
    const disconnectIndex = disconnect.indexOf(".disconnect_binding(&params.binding_handle)");
    expect(closeIndex).toBeGreaterThanOrEqual(0);
    expect(disconnectIndex).toBeGreaterThan(closeIndex);
    for (const method of rpcNames) expect(backendSource).toContain(`serde(rename = "${method}")`);
    const params = backendSource.slice(
      backendSource.indexOf("struct QuickDetectionPlanParams"),
      backendSource.indexOf("struct ApplicationLogFilterParams"),
    );
    expect((params.match(/struct QuickDetection\w+Params/gu) ?? [])).toHaveLength(6);
    expect(params).not.toMatch(
      /\b(?:target|session|connection|command|shell|path|mutation|file|terminal|export|generic|remediation)\b/u,
    );
  });
});
