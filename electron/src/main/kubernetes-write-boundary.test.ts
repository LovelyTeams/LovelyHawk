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
  new URL(
    "../../../crates/lovelyres-electron-backend/src/kubernetes_write_api.rs",
    import.meta.url,
  ),
  "utf8",
);

function frozenApiBody(): string {
  const match = preloadSource.match(
    /const api: LovelyResApi = Object\.freeze\(\{(?<body>[\s\S]*?)^\}\);/mu,
  );
  expect(match?.groups?.body).toBeDefined();
  return match?.groups?.body ?? "";
}

describe("central Kubernetes Electron action boundary", () => {
  it("adds exactly four action methods to the frozen exact 124 preload", () => {
    const body = frozenApiBody();
    const names = [...body.matchAll(/^  (?<name>[A-Za-z_$][A-Za-z0-9_$]*):/gmu)]
      .map((match) => match.groups?.name);
    expect(names).toHaveLength(124);
    for (const name of [
      "planKubernetesWorkloadAction",
      "confirmKubernetesWorkloadAction",
      "executeKubernetesWorkloadAction",
      "cancelKubernetesWorkloadAction",
    ]) expect(names.filter((candidate) => candidate === name)).toEqual([name]);
    // Nothing that acts without going through a plan first, and nothing the
    // core has no closed workflow for.
    for (const forbidden of [
      "scaleKubernetesDeployment", "deleteKubernetesResource", "drainKubernetesNode",
      "execKubernetesPod", "applyKubernetesManifest",
    ]) expect(body).not.toContain(forbidden);
  });

  it("registers four exact object-validated IPC routes and nothing else", () => {
    for (const channel of [
      "lovelyres:kubernetes:workload:action:plan",
      "lovelyres:kubernetes:workload:action:confirm",
      "lovelyres:kubernetes:workload:action:execute",
      "lovelyres:kubernetes:workload:action:cancel",
    ]) {
      expect((mainSource.match(new RegExp(channel, "gu")) ?? [])).toHaveLength(1);
      expect((preloadSource.match(new RegExp(channel, "gu")) ?? [])).toHaveLength(1);
    }

    const boundary = mainSource.slice(
      mainSource.indexOf('ipcMain.handle("lovelyres:kubernetes:workload:action:plan"'),
      mainSource.indexOf('ipcMain.handle("lovelyres:docker:containers:refresh"'),
    );
    expect(boundary).toContain('hasExactKeys(value, ["bindingHandle", "planHandle"])');
    expect((boundary.match(/isKubernetesOpaqueHandle/gu) ?? [])).toHaveLength(5);
    expect((boundary.match(/isKubernetesWriteAction/gu) ?? [])).toHaveLength(1);
    expect((boundary.match(/isKubernetesResourceName/gu) ?? [])).toHaveLength(1);
    // The renderer names a workload by handle and an action by a closed shape.
    // A namespace, a name or a UID reaching main would mean something other
    // than the approved plan decides what is patched.
    expect(boundary).not.toMatch(
      /\b(?:namespace|resourceName:\s*string|uid|manifest|kubectl|command|shell|exec)\b/u,
    );
  });

  it("keeps the action set closed and the replica count bounded", () => {
    const contract = readFileSync(
      new URL("../shared/kubernetes-write-contract.ts", import.meta.url),
      "utf8",
    );
    // Three shapes and no more. A fourth would have to be added here, in the
    // sidecar enum, and in the core — none of which can be done by accident.
    expect(contract).toContain('{ kind: "scale-deployment"; replicas: number }');
    expect(contract).toContain('{ kind: "cordon" }');
    expect(contract).toContain('{ kind: "uncordon" }');
    expect(contract).toContain("MAX_KUBERNETES_REPLICAS = 1_000");
    expect(contract).toContain("value.replicas <= MAX_KUBERNETES_REPLICAS");
    for (const forbidden of ["delete", "drain", "evict", "apply", "exec"]) {
      expect(contract).not.toContain(`"${forbidden}"`);
    }
  });

  it("pins exact RPC methods and correlates every plan and receipt", () => {
    const methods = backendClientSource.slice(
      backendClientSource.indexOf("export const KUBERNETES_WRITE_RPC_METHODS"),
      backendClientSource.indexOf("export const DOCKER_READ_RPC_METHODS"),
    );
    for (const method of [
      "kubernetes.workload.action.plan",
      "kubernetes.workload.action.confirm",
      "kubernetes.workload.action.execute",
      "kubernetes.workload.action.cancel",
    ]) expect((methods.match(new RegExp(method.replaceAll(".", "\\."), "gu")) ?? []))
      .toHaveLength(1);

    const boundary = backendClientSource.slice(
      backendClientSource.indexOf("async planKubernetesWorkloadAction"),
      backendClientSource.indexOf("async refreshDockerContainers"),
    );
    for (const validator of [
      "isKubernetesActionPlan(value)",
      "isKubernetesActionReceipt(value)",
      "isKubernetesActionCancellation(value)",
    ]) expect(boundary).toContain(validator);
    // A plan that came back describing a different workload or action is one
    // the operator would approve without having chosen it.
    expect(boundary).toContain("value.rowHandle !== rowHandle");
    expect(boundary).toContain("value.action !== action.kind");
    expect(boundary).toContain("value.planHandle !== planHandle");
    expect(boundary).toContain("value.confirmed");
  });

  it("keeps approval and execution separate all the way down", () => {
    for (const marker of [
      "mod kubernetes_write_api;",
      "KubernetesWriteApi::new(",
      "self.kubernetes_write.close_binding(&params.binding_handle);",
      "KubernetesActionPlanParams",
      "KubernetesPlanParams",
      "fn kubernetes_write_failure(error: KubernetesWriteApiError)",
      "kubernetes.workload.action.plan",
      "kubernetes.workload.action.confirm",
      "kubernetes.workload.action.execute",
      "kubernetes.workload.action.cancel",
    ]) expect(backendSource).toContain(marker);

    for (const marker of [
      "PLAN_TTL: Duration = Duration::from_secs(5 * 60)",
      "fn take_confirmed(",
      "KubernetesWriteApiError::PlanNotConfirmed",
      "DangerousConfirmation::approve(",
      "resolve_workload_for_mutation(",
      // A scale asked of a node, or a cordon asked of a deployment, is named
      // rather than left to fail somewhere deeper as a generic error.
      "KubernetesWriteApiError::ActionKindMismatch",
    ]) expect(writeApiSource).toContain(marker);
    // The renderer's handle is the only way to name a workload here.
    expect(writeApiSource).not.toMatch(/fn\s+\w*(?:namespace|resource_uid)\w*\s*\(/u);
  });

  it("keeps the aggregate API to plans and receipts, never to manifests", () => {
    const api = contractSource.slice(
      contractSource.indexOf("export interface LovelyResApi"),
      contractSource.indexOf("type JsonRecord"),
    );
    expect(api).toContain("): Promise<KubernetesActionPlan>;");
    expect(api).toContain("): Promise<KubernetesActionReceipt>;");
    expect(api).toContain("): Promise<KubernetesActionCancellation>;");
    for (const forbidden of [
      "applyKubernetes", "execKubernetes", "kubectl", "manifest", "resourceUid",
    ]) expect(api).not.toContain(forbidden);
  });
});
