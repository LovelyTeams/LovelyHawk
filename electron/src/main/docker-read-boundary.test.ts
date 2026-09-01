import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const mainSource = readFileSync(new URL("./index.ts", import.meta.url), "utf8");
const preloadSource = readFileSync(new URL("../preload/index.ts", import.meta.url), "utf8");
const contractSource = readFileSync(new URL("../shared/contract.ts", import.meta.url), "utf8");
const backendClientSource = readFileSync(new URL("./backend-client.ts", import.meta.url), "utf8");
const appSource = readFileSync(new URL("../renderer/App.tsx", import.meta.url), "utf8");
const pageSource = readFileSync(new URL("../renderer/DockerPage.tsx", import.meta.url), "utf8");
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

describe("central Docker Electron read boundary", () => {
  it("keeps the exact five read methods in the frozen exact 124 preload", () => {
    const body = frozenApiBody();
    const names = [...body.matchAll(/^  (?<name>[A-Za-z_$][A-Za-z0-9_$]*):/gmu)]
      .map((match) => match.groups?.name);
    expect(names).toHaveLength(124);
    for (const name of [
      "refreshDockerContainers",
      "getDockerCollection",
      "inspectDockerResource",
      "getDockerSecurityAudit",
      "getDockerLogs",
    ]) expect(names.filter((candidate) => candidate === name)).toEqual([name]);
    expect(body).toContain('ipcRenderer.invoke("lovelyres:docker:containers:refresh", { bindingHandle })');
    expect(body).toContain('ipcRenderer.invoke("lovelyres:docker:collection:get", {');
    expect(body).toContain('ipcRenderer.invoke("lovelyres:docker:resource:inspect", {');
    expect(body).toContain('ipcRenderer.invoke("lovelyres:docker:security:audit:get", {');
    expect(body).toContain('ipcRenderer.invoke("lovelyres:docker:container:logs:get", {');
  });

  it("registers five exact arity-one IPC routes with closed object validators", () => {
    for (const channel of [
      "lovelyres:docker:containers:refresh",
      "lovelyres:docker:collection:get",
      "lovelyres:docker:resource:inspect",
      "lovelyres:docker:security:audit:get",
      "lovelyres:docker:container:logs:get",
    ]) expect((mainSource.match(new RegExp(channel, "gu")) ?? [])).toHaveLength(1);

    // Ends where reading ends. The action routes live immediately after and
    // have their own boundary test; letting them into this slice would make
    // the read counts drift every time an action is added.
    const boundary = mainSource.slice(
      mainSource.indexOf('ipcMain.handle("lovelyres:docker:containers:refresh"'),
      mainSource.indexOf('ipcMain.handle("lovelyres:docker:container:action:plan"'),
    );
    const exactKeyValidator = mainSource.slice(
      mainSource.indexOf("function hasExactKeys("),
      mainSource.indexOf("function isBoundedString("),
    );
    expect(exactKeyValidator).toContain("keys.length === expected.length");
    expect((boundary.match(/validateSender\(event\)/gu) ?? [])).toHaveLength(5);
    expect((boundary.match(/values\.length !== 1/gu) ?? [])).toHaveLength(5);
    expect((boundary.match(/isDockerOpaqueHandle/gu) ?? [])).toHaveLength(11);
    expect((boundary.match(/isDockerCollectionKind/gu) ?? [])).toHaveLength(1);
    expect((boundary.match(/isDockerResourceKind/gu) ?? [])).toHaveLength(1);
    expect((boundary.match(/isDockerLogTail/gu) ?? [])).toHaveLength(1);
    expect((boundary.match(/hasExactKeys\(value,/gu) ?? [])).toHaveLength(5);
    expect(boundary).toContain('hasExactKeys(value, ["bindingHandle"])');
    expect(boundary).toContain(
      'hasExactKeys(value, ["bindingHandle", "snapshotHandle", "kind"])',
    );
    expect(boundary).toContain(
      'hasExactKeys(value, ["bindingHandle", "snapshotHandle", "kind", "resourceHandle"])',
    );
    expect(boundary).toContain(
      'hasExactKeys(value, ["bindingHandle", "snapshotHandle", "containerHandle", "tail"])',
    );
    expectLiteralErrorsOnly(boundary, 5);
    expect(boundary).not.toMatch(
      /\b(?:scale|restart|delete|prune|exec|file|terminal|export|generic|shell|process|invoke)\b/iu,
    );
  });

  it("pins exact RPC methods and correlates every returned capability", () => {
    const methods = backendClientSource.slice(
      backendClientSource.indexOf("export const DOCKER_READ_RPC_METHODS"),
      backendClientSource.indexOf("export const EMERGENCY_COMMAND_RPC_METHODS"),
    );
    for (const method of [
      "docker.containers.refresh",
      "docker.collection.get",
      "docker.resource.inspect",
      "docker.security.audit.get",
      "docker.container.logs.get",
    ]) expect((methods.match(new RegExp(method.replaceAll(".", "\\."), "gu")) ?? []))
      .toHaveLength(1);

    const boundary = backendClientSource.slice(
      backendClientSource.indexOf("async refreshDockerContainers"),
      backendClientSource.indexOf("async planDockerContainerAction"),
    );
    for (const validator of [
      "isDockerContainerSnapshot",
      "isDockerReadCollection",
      "isDockerReadInspection",
      "isDockerSecurityAudit",
      "isDockerLogs",
      "isDockerCollectionKind",
      "isDockerResourceKind",
      "isDockerLogTail",
    ]) expect(boundary).toContain(validator);
    expect((boundary.match(/value\.snapshotHandle !== snapshotHandle/gu) ?? [])).toHaveLength(4);
    expect((boundary.match(/value\.kind !== kind/gu) ?? [])).toHaveLength(2);
    expect(boundary).toContain("value.resourceHandle !== resourceHandle");
    expect(boundary).toContain("value.containerHandle !== containerHandle");
    expect(boundary).toContain("value.tail !== tail");
    expectLiteralErrorsOnly(boundary, 10);
  });

  it("keeps the aggregate API concrete, target-opaque and strictly read-only", () => {
    const api = contractSource.slice(
      contractSource.indexOf("refreshDockerContainers(bindingHandle: string)"),
      contractSource.indexOf("loadEmergencyCommandCatalog(bindingHandle: string)"),
    );
    expect(api).toContain(
      "refreshDockerContainers(bindingHandle: string): Promise<DockerContainerSnapshot>;",
    );
    expect(api).toMatch(
      /getDockerCollection\(\s*bindingHandle: string,\s*snapshotHandle: string,\s*kind: DockerCollectionKind,\s*\): Promise<DockerReadCollection>;/u,
    );
    expect(api).toMatch(
      /inspectDockerResource\(\s*bindingHandle: string,\s*snapshotHandle: string,\s*kind: DockerResourceKind,\s*resourceHandle: string,\s*\): Promise<DockerReadInspection>;/u,
    );
    expect(api).toMatch(
      /getDockerLogs\(\s*bindingHandle: string,\s*snapshotHandle: string,\s*containerHandle: string,\s*tail: number,\s*\): Promise<DockerLogs>;/u,
    );
    // The surface is closed by enumeration rather than by banning verbs. A
    // word blacklist could only catch a name someone happened to choose
    // badly, and it fired on this file's own documentation the moment a
    // method was called what it is; this fails for anything added at all.
    // The slice starts mid-line, at the first method's name, so the leading
    // indentation the pattern anchors on is put back before scanning.
    const methods = [...`  ${api}`.matchAll(/^ {2}(?<name>[A-Za-z_$][A-Za-z0-9_$]*)\(/gmu)]
      .map((match) => match.groups?.name);
    expect(methods).toEqual([
      "refreshDockerContainers",
      "getDockerCollection",
      "inspectDockerResource",
      "getDockerSecurityAudit",
      "getDockerLogs",
      "planDockerContainerAction",
      "confirmDockerContainerAction",
      "executeDockerContainerAction",
      "cancelDockerContainerAction",
      "openDockerContainerTerminal",
    ]);

    // What actually has to stay opaque is what crosses, so check the
    // parameters. Comments are stripped first: prose is not a parameter, and
    // treating it as one is what made the previous rule unusable.
    const declarations = api.replace(/\/\*[\s\S]*?\*\//gu, "").replace(/\/\/[^\r\n]*/gu, "");
    const parameters = [...declarations.matchAll(/(?<name>\w+): (?<type>[A-Za-z][\w.<>]*)/gu)]
      .map((match) => ({ name: match.groups?.name ?? "", type: match.groups?.type ?? "" }));
    expect(parameters.length).toBeGreaterThan(20);
    for (const { name, type } of parameters) {
      // Closed enums and bounded numbers pass on their type alone. Everything
      // else must be an opaque handle, or the one display-only name the
      // action dialog and the terminal window title need.
      if (["DockerCollectionKind", "DockerResourceKind", "DockerWriteAction", "number"].includes(type)) continue;
      expect({ name, type }).toEqual({ name: expect.stringMatching(/Handle$|^containerName$/u), type: "string" });
    }
  });

  it("mounts the page with only the current opaque binding handle", () => {
    const branch = appSource.slice(
      appSource.indexOf('activePage.id === "docker"'),
      appSource.indexOf('activePage.id === "emergency-commands"'),
    );
    expect(branch).toContain("<DockerPage");
    expect(branch).toContain("bindingHandle={activeTarget?.bindingHandle ?? null}");
    expect(branch).toContain("api={window.lovelyres}");
    expect(branch).not.toContain("connection={activeTarget}");
    expect(branch).not.toMatch(/target=|session|guard/u);
    expect(pageSource).toContain("bindingHandle: string | null;");
    expect(pageSource).not.toContain("SshTargetSummary");
    expect(pageSource).not.toContain("DockerConnection");
  });

  it("closes Docker capabilities before the real SSH disconnect", () => {
    const branch = backendSource.split("RpcMethod::SshBindingDisconnect =>")[1]
      ?.split("RpcMethod::TerminalOpen")[0] ?? "";
    const close = branch.indexOf("self.docker_read.close_binding(&params.binding_handle);");
    const disconnect = branch.indexOf(".disconnect_binding(&params.binding_handle)");
    expect(close).toBeGreaterThanOrEqual(0);
    expect(disconnect).toBeGreaterThan(close);
  });
});
