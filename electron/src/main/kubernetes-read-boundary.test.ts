import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const mainSource = readFileSync(new URL("./index.ts", import.meta.url), "utf8");
const preloadSource = readFileSync(new URL("../preload/index.ts", import.meta.url), "utf8");
const contractSource = readFileSync(new URL("../shared/contract.ts", import.meta.url), "utf8");
const backendClientSource = readFileSync(new URL("./backend-client.ts", import.meta.url), "utf8");

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

describe("central Kubernetes Electron read boundary", () => {
  it("keeps the exact four read methods in the frozen exact 118 preload", () => {
    const body = frozenApiBody();
    const names = [...body.matchAll(/^  (?<name>[A-Za-z_$][A-Za-z0-9_$]*):/gmu)]
      .map((match) => match.groups?.name);
    expect(names).toHaveLength(118);
    for (const name of [
      "getKubernetesAvailability",
      "listKubernetesResources",
      "getKubernetesResourceDetail",
      "getKubernetesPodLogs",
    ]) expect(names.filter((candidate) => candidate === name)).toEqual([name]);

    expect(body).toMatch(
      /getKubernetesAvailability: \(bindingHandle: string\) =>\s*ipcRenderer\.invoke\("lovelyres:kubernetes:availability:get", bindingHandle\)/u,
    );
    expect(body).toMatch(
      /listKubernetesResources: \(bindingHandle: string, input: KubernetesListInput\) =>\s*ipcRenderer\.invoke\("lovelyres:kubernetes:resources:list", \{ bindingHandle, input \}\)/u,
    );
    expect(body).toContain('ipcRenderer.invoke("lovelyres:kubernetes:resource:detail:get", {');
    expect(body).toContain('ipcRenderer.invoke("lovelyres:kubernetes:pod:logs:get", {');
  });

  it("registers four exact arity-one IPC routes with closed input validators", () => {
    for (const channel of [
      "lovelyres:kubernetes:availability:get",
      "lovelyres:kubernetes:resources:list",
      "lovelyres:kubernetes:resource:detail:get",
      "lovelyres:kubernetes:pod:logs:get",
    ]) expect((mainSource.match(new RegExp(channel, "gu")) ?? [])).toHaveLength(1);

    const boundary = mainSource.slice(
      mainSource.indexOf('ipcMain.handle("lovelyres:kubernetes:availability:get"'),
      mainSource.indexOf('ipcMain.handle("lovelyres:docker:containers:refresh"'),
    );
    expect((boundary.match(/validateSender\(event\)/gu) ?? [])).toHaveLength(4);
    expect((boundary.match(/values\.length !== 1/gu) ?? [])).toHaveLength(4);
    expect((boundary.match(/isKubernetesOpaqueHandle/gu) ?? [])).toHaveLength(8);
    expect((boundary.match(/isKubernetesListInput/gu) ?? [])).toHaveLength(1);
    expect(boundary).toContain('hasOnlyKeys(value, ["bindingHandle", "input"])');
    expect((boundary.match(
      /hasOnlyKeys\(value, \["bindingHandle", "snapshotHandle", "rowHandle"\]\)/gu,
    ) ?? [])).toHaveLength(2);
    expectLiteralErrorsOnly(boundary, 4);
    expect(boundary).not.toMatch(
      /\b(?:scale|restart|delete|cordon|drain|exec|file|terminal|export|generic|shell|process|invoke)\b/iu,
    );
  });

  it("pins the exact four RPC methods and correlates every response capability", () => {
    const methods = backendClientSource.slice(
      backendClientSource.indexOf("export const KUBERNETES_READ_RPC_METHODS"),
      backendClientSource.indexOf("export const DOCKER_READ_RPC_METHODS"),
    );
    for (const method of [
      "kubernetes.availability.get",
      "kubernetes.resources.list",
      "kubernetes.resource.detail.get",
      "kubernetes.pod.logs.get",
    ]) expect((methods.match(new RegExp(method.replaceAll(".", "\\."), "gu")) ?? []))
      .toHaveLength(1);

    const boundary = backendClientSource.slice(
      backendClientSource.indexOf("async getKubernetesAvailability"),
      backendClientSource.indexOf("async refreshDockerContainers"),
    );
    expect((boundary.match(/isKubernetesAvailability/gu) ?? [])).toHaveLength(1);
    expect((boundary.match(/isKubernetesSnapshot/gu) ?? [])).toHaveLength(1);
    expect((boundary.match(/isKubernetesTextResult/gu) ?? [])).toHaveLength(2);
    expect(boundary).toContain("value.tab !== input.tab");
    expect(boundary).toContain("value.namespaceScoped !== (input.namespaceScope !== null)");
    expect((boundary.match(/value\.snapshotHandle !== snapshotHandle/gu) ?? [])).toHaveLength(2);
    expect((boundary.match(/value\.rowHandle !== rowHandle/gu) ?? [])).toHaveLength(2);
    expect(boundary).toContain('value.contentKind !== "detail"');
    expect(boundary).toContain('value.contentKind !== "pod-logs"');
    expectLiteralErrorsOnly(boundary, 8);
  });

  it("keeps the aggregate API concrete, target-opaque and strictly read-only", () => {
    const api = contractSource.slice(
      contractSource.indexOf("getKubernetesAvailability(bindingHandle: string)"),
      contractSource.indexOf("refreshDockerContainers(bindingHandle: string)"),
    );
    expect(api).toContain(
      "getKubernetesAvailability(bindingHandle: string): Promise<KubernetesAvailability>;",
    );
    expect(api).toMatch(
      /listKubernetesResources\(\s*bindingHandle: string,\s*input: KubernetesListInput,\s*\): Promise<KubernetesSnapshot>;/u,
    );
    expect(api).toMatch(
      /getKubernetesResourceDetail\(\s*bindingHandle: string,\s*snapshotHandle: string,\s*rowHandle: string,\s*\): Promise<KubernetesTextResult>;/u,
    );
    expect(api).toMatch(
      /getKubernetesPodLogs\(\s*bindingHandle: string,\s*snapshotHandle: string,\s*rowHandle: string,\s*\): Promise<KubernetesTextResult>;/u,
    );
    expect(api).not.toMatch(
      /\b(?:scale|restart|delete|cordon|drain|exec|file|terminal|export|generic|shell|process|invoke)\b/iu,
    );
  });
});
