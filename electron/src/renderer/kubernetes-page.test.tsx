import { readFileSync } from "node:fs";

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type {
  KubernetesReadApi,
  KubernetesSnapshot,
} from "../shared/kubernetes-read-contract";
import { KubernetesPage } from "./KubernetesPage";
import { kubernetesReadScope } from "./kubernetes-read-helpers";
import { createKubernetesReadState, type KubernetesReadState } from "./kubernetes-read-state";

const api: KubernetesReadApi = {
  getKubernetesAvailability: vi.fn(async () => ({})),
  listKubernetesResources: vi.fn(async () => ({})),
  getKubernetesResourceDetail: vi.fn(async () => ({})),
  getKubernetesPodLogs: vi.fn(async () => ({})),
};
const bindingHandle = "binding-secret-capability";
const hostile = "</pre><script>steal()</script><img src=x onerror=steal()>";

function namespaces(): KubernetesSnapshot {
  return {
    snapshotHandle: "snapshot-namespace-secret",
    tab: "namespaces",
    namespaceScoped: false,
    displayed: 1,
    truncated: false,
    expiresInSeconds: 300,
    rows: [{
      kind: "namespace",
      rowHandle: "namespace-row-secret",
      name: "production",
      phase: "Active",
      createdAt: "now",
      textTruncated: false,
    }],
  };
}

function pods(truncated = false): KubernetesSnapshot {
  return {
    snapshotHandle: "snapshot-pod-secret",
    tab: "pods",
    namespaceScoped: true,
    displayed: 1,
    truncated,
    expiresInSeconds: 300,
    rows: [{
      kind: "pod",
      rowHandle: "pod-row-secret",
      namespace: "production",
      name: hostile,
      phase: "Running",
      readyContainers: 1,
      totalContainers: 1,
      restarts: 0,
      node: "node-a",
      podIp: "10.0.0.8",
      images: ["app:1"],
      createdAt: "now",
      supportsLogs: true,
      textTruncated: false,
    }],
  };
}

function readyState(truncated = false): KubernetesReadState {
  return {
    ...createKubernetesReadState(kubernetesReadScope(bindingHandle)),
    availabilityStatus: "ready",
    availability: {
      kubectlInstalled: true,
      apiReachable: true,
      currentContext: hostile,
      contextTruncated: false,
    },
    namespacesStatus: "ready",
    namespaces: namespaces(),
    selectedNamespace: {
      snapshotHandle: "snapshot-namespace-secret",
      rowHandle: "namespace-row-secret",
    },
    listStatus: "ready",
    listContext: "snapshot-namespace-secret:namespace-row-secret",
    snapshot: pods(truncated),
    selectedRowHandle: "pod-row-secret",
    detailStatus: "ready",
    detail: {
      snapshotHandle: "snapshot-pod-secret",
      rowHandle: "pod-row-secret",
      contentKind: "pod-logs",
      text: `line one\n${hostile}`,
      truncated,
    },
  };
}

describe("standalone Kubernetes read page", () => {
  it("renders hostile remote text literally without exposing opaque handles", () => {
    const html = renderToStaticMarkup(
      <KubernetesPage bindingHandle={bindingHandle} api={api} initialState={readyState()} />,
    );
    expect(html).toContain("&lt;/pre&gt;&lt;script&gt;steal()&lt;/script&gt;");
    expect(html).not.toContain("<script>steal()</script>");
    expect(html).not.toContain("binding-secret-capability");
    expect(html).not.toContain("snapshot-pod-secret");
    expect(html).not.toContain("pod-row-secret");
    expect(html).not.toContain("dangerouslySetInnerHTML");
    expect(html).toContain("最近 Pod 日志");
  });

  it("starts on Pods and renders exactly the four fixed read tabs", () => {
    const state = readyState();
    state.selectedNamespace = null;
    state.listContext = "all";
    state.snapshot = { ...pods(), namespaceScoped: false };
    state.selectedRowHandle = null;
    state.detailStatus = "idle";
    state.detail = null;
    const html = renderToStaticMarkup(
      <KubernetesPage bindingHandle={bindingHandle} api={api} initialState={state} />,
    );
    for (const label of ["Namespaces", "Pods", "Deployments", "Nodes"]) {
      expect(html).toContain(`>${label}</button>`);
    }
    expect(html).toContain('aria-current="page">Pods</button>');
    expect(html).toContain("全部 namespaces");
  });

  it("renders disconnected, empty, error, and truncation states without invented rows", () => {
    let html = renderToStaticMarkup(<KubernetesPage bindingHandle={null} api={api} />);
    expect(html).toContain("连接目标后调查 Kubernetes");
    expect(html).toContain("不会修改集群");

    const empty = readyState();
    empty.snapshot = { ...pods(), displayed: 0, rows: [], namespaceScoped: true };
    empty.selectedRowHandle = null;
    empty.detailStatus = "idle";
    empty.detail = null;
    html = renderToStaticMarkup(
      <KubernetesPage bindingHandle={bindingHandle} api={api} initialState={empty} />,
    );
    expect(html).toContain("当前范围没有 Pods");
    expect(html).not.toContain("示例 Pod");

    const failed = readyState();
    failed.listStatus = "error";
    failed.snapshot = null;
    failed.selectedRowHandle = null;
    failed.detail = null;
    failed.detailStatus = "idle";
    failed.error = "目标已断开。";
    html = renderToStaticMarkup(
      <KubernetesPage bindingHandle={bindingHandle} api={api} initialState={failed} />,
    );
    expect(html).toContain('role="alert"');
    expect(html).toContain("目标已断开");
    expect(html).toContain("资源快照不可用");

    html = renderToStaticMarkup(
      <KubernetesPage bindingHandle={bindingHandle} api={api} initialState={readyState(true)} />,
    );
    expect(html).toContain("结果已截断");
    expect(html).toContain("文本已按敏感信息与 UTF-8 字节安全边界处理");
  });

  it("offers recent logs only for a selected Pod", () => {
    let html = renderToStaticMarkup(
      <KubernetesPage bindingHandle={bindingHandle} api={api} initialState={readyState()} />,
    );
    expect(html).toContain("读取最近 Pod 日志");

    const state = readyState();
    state.activeTab = "deployments";
    state.snapshot = {
      snapshotHandle: "snapshot-deployment-secret",
      tab: "deployments",
      namespaceScoped: true,
      displayed: 1,
      truncated: false,
      expiresInSeconds: 300,
      rows: [{
        kind: "deployment",
        rowHandle: "deployment-row-secret",
        namespace: "production",
        name: "api",
        desiredReplicas: 2,
        readyReplicas: 2,
        availableReplicas: 2,
        updatedReplicas: 2,
        images: ["api:1"],
        createdAt: "now",
        textTruncated: false,
      }],
    };
    state.selectedRowHandle = "deployment-row-secret";
    state.detailStatus = "idle";
    state.detail = null;
    html = renderToStaticMarkup(
      <KubernetesPage bindingHandle={bindingHandle} api={api} initialState={state} />,
    );
    expect(html).toContain("读取详情");
    expect(html).not.toContain("读取最近 Pod 日志");
  });

  it("contains no phase-one mutation, generic execution, or placeholder surface", () => {
    const source = readFileSync(new URL("./KubernetesPage.tsx", import.meta.url), "utf8");
    for (const forbidden of [
      ["scale", "Kubernetes"].join(""),
      ["restart", "Kubernetes"].join(""),
      ["delete", "Kubernetes"].join(""),
      ["cord", "on"].join(""),
      ["dr", "ain"].join(""),
      ["execute", "Command"].join(""),
      ["open", "KubernetesFile"].join(""),
      ["open", "KubernetesTerminal"].join(""),
      ["export", "Kubernetes"].join(""),
      ["generic", "Invoke"].join(""),
      "dangerouslySetInnerHTML",
      ["TO", "DO"].join(""),
    ]) expect(source).not.toContain(forbidden);
    for (const forbidden of [
      "SshTargetSummary", "KubernetesReadConnection", "connectionId", "sessionId",
      "targetGuard", "generation", "username", "timestamp",
    ]) expect(source).not.toContain(forbidden);
    expect(source).toContain("bindingHandle: string | null");
    expect(source).toContain("kubernetesReadScope(bindingHandle)");
  });

  it("is centrally mounted with only the current 请先建立 SSH 连接 handle and fixed API", () => {
    const source = readFileSync(new URL("./App.tsx", import.meta.url), "utf8");
    // The page is its own chunk now, so the import is the lazy one.
    expect(source).toContain(
      'const KubernetesPage = lazy(async () => ({ default: (await import("./KubernetesPage")).KubernetesPage }));',
    );
    expect(source).toContain('activePage.id === "kubernetes"');
    const mount = source.match(/<KubernetesPage[\s\S]*?\/>/u)?.[0];
    expect(mount).toBeDefined();
    expect(mount).toContain("bindingHandle={activeTarget?.bindingHandle ?? null}");
    expect(mount).toContain("api={window.lovelyres}");
    expect(mount).not.toMatch(/\b(?:connection|target|session|guard|generation|host|port)=/iu);
  });

  it("uses global theme tokens with no color literals", () => {
    const css = readFileSync(new URL("./kubernetes-page.css", import.meta.url), "utf8");
    expect((css.match(/var\(--[a-z0-9-]+\)/gu) ?? []).length).toBeGreaterThan(30);
    expect(css).not.toMatch(/#[0-9a-f]{3,8}|rgba?\(|hsla?\(/iu);
  });
});
