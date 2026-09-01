import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const mainSource = readFileSync(new URL("./index.ts", import.meta.url), "utf8");
const preloadSource = readFileSync(new URL("../preload/index.ts", import.meta.url), "utf8");
const contractSource = readFileSync(new URL("../shared/contract.ts", import.meta.url), "utf8");
const backendClientSource = readFileSync(new URL("./backend-client.ts", import.meta.url), "utf8");
const backendSource = readFileSync(
  new URL("../../../crates/lovelyres-electron-backend/src/lib.rs", import.meta.url),
  "utf8",
);
const writeApiSource = readFileSync(
  new URL("../../../crates/lovelyres-electron-backend/src/docker_write_api.rs", import.meta.url),
  "utf8",
);

function frozenApiBody(): string {
  const match = preloadSource.match(
    /const api: LovelyResApi = Object\.freeze\(\{(?<body>[\s\S]*?)^\}\);/mu,
  );
  expect(match?.groups?.body).toBeDefined();
  return match?.groups?.body ?? "";
}

describe("central Docker Electron action boundary", () => {
  it("adds exactly four action methods to the frozen exact 124 preload", () => {
    const body = frozenApiBody();
    const names = [...body.matchAll(/^  (?<name>[A-Za-z_$][A-Za-z0-9_$]*):/gmu)]
      .map((match) => match.groups?.name);
    expect(names).toHaveLength(124);
    for (const name of [
      "planDockerContainerAction",
      "confirmDockerContainerAction",
      "executeDockerContainerAction",
      "cancelDockerContainerAction",
    ]) expect(names.filter((candidate) => candidate === name)).toEqual([name]);
    // Nothing that acts without going through a plan first.
    for (const forbidden of [
      "startDockerContainer", "stopDockerContainer", "removeDockerContainer",
      "runDockerCommand", "execDockerContainer",
    ]) expect(body).not.toContain(forbidden);
  });

  it("registers four exact object-validated IPC routes and nothing else", () => {
    for (const channel of [
      "lovelyres:docker:container:action:plan",
      "lovelyres:docker:container:action:confirm",
      "lovelyres:docker:container:action:execute",
      "lovelyres:docker:container:action:cancel",
    ]) {
      expect((mainSource.match(new RegExp(channel, "gu")) ?? [])).toHaveLength(1);
      expect((preloadSource.match(new RegExp(channel, "gu")) ?? [])).toHaveLength(1);
    }

    const boundary = mainSource.slice(
      mainSource.indexOf('ipcMain.handle("lovelyres:docker:container:action:plan"'),
      mainSource.indexOf('ipcMain.handle("lovelyres:emergency-command:catalog:load"'),
    );
    expect(boundary).toContain(
      'hasExactKeys(value, [\n        "bindingHandle",\n        "snapshotHandle",\n        "containerHandle",\n        "containerName",\n        "action",\n      ])',
    );
    expect(boundary).toContain('hasExactKeys(value, ["bindingHandle", "planHandle"])');
    expect((boundary.match(/isDockerOpaqueHandle/gu) ?? [])).toHaveLength(5);
    expect((boundary.match(/isDockerWriteAction/gu) ?? [])).toHaveLength(1);
    expect((boundary.match(/isDockerContainerName/gu) ?? [])).toHaveLength(1);
    // The renderer names a container by handle and an action by a closed word.
    // A path, a command, or a runtime verb reaching main would mean the plan
    // is not the only thing deciding what runs.
    expect(boundary).not.toMatch(
      /\b(?:path|command|shell|exec|terminal|runtime|docker start|docker stop)\b/iu,
    );
  });

  it("pins exact RPC methods and correlates every plan and receipt", () => {
    const methods = backendClientSource.slice(
      backendClientSource.indexOf("export const DOCKER_WRITE_RPC_METHODS"),
      backendClientSource.indexOf("export const EMERGENCY_COMMAND_RPC_METHODS"),
    );
    for (const method of [
      "docker.container.action.plan",
      "docker.container.action.confirm",
      "docker.container.action.execute",
      "docker.container.action.cancel",
    ]) expect((methods.match(new RegExp(method.replaceAll(".", "\\."), "gu")) ?? []))
      .toHaveLength(1);

    const boundary = backendClientSource.slice(
      backendClientSource.indexOf("async planDockerContainerAction"),
      backendClientSource.indexOf("async loadEmergencyCommandCatalog"),
    );
    for (const validator of [
      "isDockerActionPlan(value)",
      "isDockerActionReceipt(value)",
      "isDockerActionCancellation(value)",
    ]) expect(boundary).toContain(validator);
    // A plan that came back describing a different container or action is one
    // the operator would approve without having chosen it.
    expect(boundary).toContain("value.containerHandle !== containerHandle");
    expect(boundary).toContain("value.action !== action");
    expect(boundary).toContain("value.planHandle !== planHandle");
    // Planning must not come back already approved.
    expect(boundary).toContain("value.confirmed");
  });

  it("keeps approval and execution separate all the way down", () => {
    // Four RPC routes in the sidecar, and the state machine that makes the
    // separation real: approval is recorded, and the plan leaves the registry
    // as it is taken so it can never run twice.
    for (const marker of [
      "mod docker_write_api;",
      "DockerWriteApi::new(",
      "self.docker_write.close_binding(&params.binding_handle);",
      "DockerActionPlanParams",
      "DockerPlanParams",
      "fn docker_write_failure(error: DockerWriteApiError)",
      "docker.container.action.plan",
      "docker.container.action.confirm",
      "docker.container.action.execute",
      "docker.container.action.cancel",
    ]) expect(backendSource).toContain(marker);

    for (const marker of [
      "PLAN_TTL: Duration = Duration::from_secs(5 * 60)",
      "fn take_confirmed(",
      "DockerWriteApiError::PlanNotConfirmed",
      "DangerousConfirmation::approve(",
      "resolve_container_for_mutation(",
    ]) expect(writeApiSource).toContain(marker);
    // The renderer's handle is the only way to name a container here.
    expect(writeApiSource).not.toMatch(/fn\s+\w*container_id\w*\s*\(/u);
  });

  it("keeps the aggregate API to plans and receipts, never to commands", () => {
    const api = contractSource.slice(
      contractSource.indexOf("export interface LovelyResApi"),
      contractSource.indexOf("type JsonRecord"),
    );
    expect(api).toContain("): Promise<DockerActionPlan>;");
    expect(api).toContain("): Promise<DockerActionReceipt>;");
    expect(api).toContain("): Promise<DockerActionCancellation>;");
    for (const forbidden of [
      "runDockerCommand", "execDocker", "dockerShell", "containerId", "remotePath",
    ]) expect(api).not.toContain(forbidden);
  });
});
