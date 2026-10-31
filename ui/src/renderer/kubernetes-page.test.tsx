import { readFileSync } from "node:fs";

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type {
  KubernetesManifestExportApi,
  KubernetesReadApi,
  KubernetesSnapshot,
} from "../shared/kubernetes-read-contract";
import type { KubernetesWriteApi } from "../shared/kubernetes-write-contract";
import type { PodFilesApi } from "../shared/exec-files-contract";
import type { PodFileEvidenceApi } from "../shared/pod-file-evidence-contract";
import { KubernetesPage, KubernetesUnavailable } from "./KubernetesPage";
import { kubernetesReadScope } from "./kubernetes-read-helpers";
import { createKubernetesReadState, type KubernetesReadState } from "./kubernetes-read-state";

const api: KubernetesReadApi & KubernetesWriteApi & PodFilesApi & PodFileEvidenceApi & KubernetesManifestExportApi = {
  getKubernetesAvailability: vi.fn(async () => ({})),
  listKubernetesResources: vi.fn(async () => ({})),
  getKubernetesResourceDetail: vi.fn(async () => ({})),
  getKubernetesPodLogs: vi.fn(async () => ({})),
  planKubernetesWorkloadAction: vi.fn(async () => ({})),
  confirmKubernetesWorkloadAction: vi.fn(async () => ({})),
  executeKubernetesWorkloadAction: vi.fn(async () => ({})),
  cancelKubernetesWorkloadAction: vi.fn(async () => ({})),
  openKubernetesPodTerminal: vi.fn(async () => ({ opened: true, reused: false })),
  exportKubernetesManifest: vi.fn(async () => ({ saved: false, fileName: null })),
  listKubernetesPodDirectory: vi.fn(async () => ({})),
  readKubernetesPodFile: vi.fn(async () => ({})),
  podFileEvidence: vi.fn(async () => null),
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
      containers: [{ name: "app", image: "registry.example/app:1", ready: true, running: true, restarts: 0 }],
      defaultContainer: "app",
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
      contextNamespace: "default",
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
  it("shows the kubeconfig's own namespace, labelled, when the account may not list namespaces", () => {
    const state: KubernetesReadState = {
      ...readyState(),
      availability: { ...readyState().availability!, contextNamespace: "payments" },
      namespacesStatus: "error",
      namespaces: null,
      namespacesRestricted: true,
      selectedNamespace: { context: true },
      listContext: "context",
      snapshot: pods(),
      selectedRowHandle: null,
      detailStatus: "idle",
      detail: null,
      notice: "当前账号不能列出命名空间（集群拒绝，权限不足），改为查看 kubeconfig 当前上下文的命名空间「payments」。",
    };
    const html = renderToStaticMarkup(
      <KubernetesPage bindingHandle={bindingHandle} api={api} initialState={state} />,
    );
    expect(html).toMatch(/data-testid="kubernetes-context-namespace"[^>]*aria-pressed="true"[^>]*>当前上下文 · payments</u);
    expect(html).toContain("payments（当前上下文）");
    expect(html).toContain("不能列出命名空间");
    expect(html).not.toContain("kubernetes-forbidden");
    // Without the restriction, no such entry is offered.
    const ordinary = renderToStaticMarkup(
      <KubernetesPage bindingHandle={bindingHandle} api={api} initialState={readyState()} />,
    );
    expect(ordinary).not.toContain("kubernetes-context-namespace");
  });

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
    expect(html).toContain("全部命名空间");
  });

  it("renders disconnected, empty, error, and truncation states without invented rows", () => {
    let html = renderToStaticMarkup(<KubernetesPage bindingHandle={null} api={api} />);
    expect(html).toContain("连接目标后调查 Kubernetes");
    expect(html).toContain("要先确认再执行");

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
    // The table points at the reason above instead of a vaguer one of its own.
    expect(html).toContain("这一页没有读到，原因见上方提示");
    expect(html).not.toContain("当前范围没有");

    html = renderToStaticMarkup(
      <KubernetesPage bindingHandle={bindingHandle} api={api} initialState={readyState(true)} />,
    );
    expect(html).toContain("结果已截断");
    expect(html).toContain("文本中有内容过长，已截短显示。");
    expect(html).not.toContain("看起来像口令");
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

  it("offers the logs from before a restart only for a Pod that has restarted", () => {
    let html = renderToStaticMarkup(
      <KubernetesPage bindingHandle={bindingHandle} api={api} initialState={readyState()} />,
    );
    expect(html).not.toContain("上次日志");
    expect(html).not.toContain("读取重启前日志");

    const restarted = readyState();
    const [row] = restarted.snapshot!.rows;
    restarted.snapshot = { ...restarted.snapshot!, rows: [{ ...row!, restarts: 3 } as typeof row & object] };
    restarted.detail = { ...restarted.detail!, contentKind: "pod-previous-logs" };
    html = renderToStaticMarkup(
      <KubernetesPage bindingHandle={bindingHandle} api={api} initialState={restarted} />,
    );
    expect(html).toContain('data-testid="kubernetes-row-previous-logs"');
    expect(html).toContain("读取重启前日志");
    expect(html).toContain("重启前那次运行的日志");
    expect(html).not.toContain("最近 Pod 日志</p>");
  });

  it("offers a terminal for a running Pod, and names it only by the list's handles", () => {
    let html = renderToStaticMarkup(
      <KubernetesPage bindingHandle={bindingHandle} api={api} initialState={readyState()} />,
    );
    const button = html.match(/<button[^>]*data-testid="kubernetes-row-terminal"[^>]*>/u)?.[0] ?? "";
    expect(button).not.toBe("");
    expect(button).not.toContain("disabled");

    const stopped = readyState();
    const [row] = stopped.snapshot!.rows;
    stopped.snapshot = { ...stopped.snapshot!, rows: [{ ...row!, phase: "Pending" } as typeof row & object] };
    html = renderToStaticMarkup(
      <KubernetesPage bindingHandle={bindingHandle} api={api} initialState={stopped} />,
    );
    expect(html.match(/<button[^>]*data-testid="kubernetes-row-terminal"[^>]*>/u)?.[0]).toContain("disabled");

    // The window is asked for by the snapshot's and row's handles; namespace
    // and name travel only as the title, never as what is resolved.
    const source = readFileSync(new URL("./KubernetesPage.tsx", import.meta.url), "utf8");
    expect(source).toContain(
      "api.openKubernetesPodTerminal(activeSnapshot.snapshotHandle, row.rowHandle, podName, containerFor(row))",
    );
    expect(source).toContain("if (terminalRef.current ||");
  });

  it("lets a pod of several containers be read, entered and browsed one container at a time", () => {
    const several = readyState();
    const [row] = several.snapshot!.rows;
    several.snapshot = {
      ...several.snapshot!,
      rows: [{
        ...row!,
        containers: [
          { name: "proxy", image: "envoy:1", ready: false, running: false, restarts: 4 },
          { name: "app", image: "app:2", ready: true, running: true, restarts: 0 },
        ],
        defaultContainer: "proxy",
      } as typeof row & object],
    };
    const html = renderToStaticMarkup(
      <KubernetesPage bindingHandle={bindingHandle} api={api} initialState={several} />,
    );
    const select = html.match(/<select[^>]*data-testid="kubernetes-row-container"[^>]*>[\s\S]*?<\/select>/u)?.[0] ?? "";
    expect(select).toContain("proxy（默认）（未运行）");
    expect(select).toContain(">app<");
    // The default container is chosen at first; it is not running, so there
    // is no shell or file browsing in it, and the buttons say why.
    const terminal = html.match(/<button[^>]*data-testid="kubernetes-row-terminal"[^>]*>/u)?.[0] ?? "";
    expect(terminal).toContain("disabled");
    expect(terminal).toContain("容器 proxy 现在没有在运行");
    const files = html.match(/<button[^>]*data-testid="kubernetes-row-files"[^>]*>/u)?.[0] ?? "";
    expect(files).toContain("disabled");
    // Logs of a stopped container stay readable.
    expect(html.match(/<button[^>]*data-testid="kubernetes-row-logs"[^>]*>/u)?.[0]).not.toContain("disabled");
    // A pod of one container shows no choice: kubectl picks it.
    const single = renderToStaticMarkup(
      <KubernetesPage bindingHandle={bindingHandle} api={api} initialState={readyState()} />,
    );
    expect(single).not.toContain('data-testid="kubernetes-row-container"');
    // Every pod read, shell and file request carries the row's container.
    const source = readFileSync(new URL("./KubernetesPage.tsx", import.meta.url), "utf8");
    expect(source).toContain("void loadText(content, activeSnapshot.snapshotHandle, row.rowHandle, containerFor(row));");
    expect(source).toContain("kind === \"pod-previous-logs\", container)");
    expect(source.match(/containerFor\(selectedRow\)/gu)?.length).toBe(2);
  });

  it("says in the detail dialog why a read failed, not only that it did", () => {
    const failed = readyState();
    failed.detailStatus = "error";
    failed.detail = null;
    failed.error = "读不到上一次运行的日志：容器可能没有重启过、旧日志已被清理，或目标已切换。";
    const html = renderToStaticMarkup(
      <KubernetesPage bindingHandle={bindingHandle} api={api} initialState={failed} />,
    );
    const dialog = html.slice(html.indexOf('class="kubernetes-detail"'));
    expect(dialog).toContain("旧日志已被清理");
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
      ["generic", "Invoke"].join(""),
      "dangerouslySetInnerHTML",
      ["TO", "DO"].join(""),
    ]) expect(source).not.toContain(forbidden);
    // The one export is a read: the listed object's manifest, named by the
    // list's handles alone — no kind, namespace or name from the page.
    expect(source.match(/export[A-Z]\w*/gu)?.filter((name) => name.startsWith("exportKubernetes")))
      .toEqual(["exportKubernetesManifest"]);
    expect(source).toContain(
      "api.exportKubernetesManifest(bindingHandle, activeSnapshot.snapshotHandle, row.rowHandle)",
    );
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
    expect(mount).toContain("api={window.lovelyhawk}");
    expect(mount).not.toMatch(/\b(?:connection|target|session|guard|generation|host|port)=/iu);
  });

  it("uses global theme tokens with no color literals", () => {
    const css = readFileSync(new URL("./kubernetes-page.css", import.meta.url), "utf8");
    expect((css.match(/var\(--[a-z0-9-]+\)/gu) ?? []).length).toBeGreaterThan(30);
    expect(css).not.toMatch(/#[0-9a-f]{3,8}\b|rgba?\(|hsla?\(/iu);
  });
});

describe("a host with no reachable cluster", () => {
  it("says why nothing was read, and that it proves nothing about a cluster", () => {
    const missing = renderToStaticMarkup(<KubernetesUnavailable kubectlInstalled={false} context="" />);
    expect(missing).toContain("这台主机上没有 kubectl");
    expect(missing).toContain("没能读取任何集群资源");
    expect(missing).toContain("这不代表这台主机与集群无关");
    const unreachable = renderToStaticMarkup(<KubernetesUnavailable kubectlInstalled context="prod-east" />);
    expect(unreachable).toContain("kubectl 已安装，但连不上集群");
    expect(unreachable).toContain("当前 context（prod-east）的 API 不可达");
    // The empty cluster interface is hidden behind it, not shown under it.
    const source = readFileSync(new URL("./KubernetesPage.tsx", import.meta.url), "utf8");
    for (const marker of ['className="kubernetes-scope" aria-label="Namespace 范围" hidden={unavailable}',
      'className="kubernetes-tabs view-tabs" aria-label="Kubernetes 资源类型" hidden={unavailable}',
      'className="kubernetes-workbench" hidden={unavailable}']) expect(source).toContain(marker);
  });
});
