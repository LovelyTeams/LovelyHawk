import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { isValidElement, type ReactNode } from "react";
type Effect = () => void | (() => void);
type Slot = { value?: unknown; deps?: readonly unknown[] | undefined; cleanup?: void | (() => void) };
const hooks = vi.hoisted(() => ({
  slots: [] as Slot[], cursor: 0, count: null as number | null, pending: [] as (() => void)[],
}));

// Exercise the real async hook with deferred API responses. Only the React
// scheduler is controlled; requests, validation and state transitions are real.
vi.mock("react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react")>();
  function slot(): Slot {
    const index = hooks.cursor++;
    return hooks.slots[index] ??= {};
  }
  function same(a: readonly unknown[] | undefined, b: readonly unknown[] | undefined): boolean {
    return a !== undefined && b !== undefined && a.length === b.length && a.every((v, i) => Object.is(v, b[i]));
  }
  return {
    ...actual,
    useState: <T,>(initial: T | (() => T)) => {
      const current = slot();
      if (!("value" in current)) current.value = typeof initial === "function" ? (initial as () => T)() : initial;
      return [current.value, (next: T | ((value: T) => T)) => {
        current.value = typeof next === "function" ? (next as (value: T) => T)(current.value as T) : next;
      }];
    },
    useRef: <T,>(initial: T) => {
      const current = slot();
      return current.value ??= { current: initial };
    },
    useCallback: (callback: unknown, deps: readonly unknown[]) => {
      const current = slot();
      if (!same(current.deps, deps)) { current.value = callback; current.deps = deps; }
      return current.value;
    },
    useEffect: (setup: Effect, deps?: readonly unknown[]) => {
      const current = slot();
      if (!same(current.deps, deps)) {
        hooks.pending.push(() => {
          if (typeof current.cleanup === "function") current.cleanup();
          current.cleanup = setup();
        });
        current.deps = deps;
      }
    },
    useReducer: (reducer: (state: unknown, action: unknown) => unknown, initial: unknown, init?: (value: unknown) => unknown) => {
      const current = slot();
      if (!("value" in current)) current.value = init === undefined ? initial : init(initial);
      return [current.value, (action: unknown) => { current.value = reducer(current.value, action); }];
    },
  };
});

import { DockerPage } from "./DockerPage";
import { KubernetesPage } from "./KubernetesPage";
import { DockerActionDialog, type DockerActionDialogProps } from "./DockerActionDialog";
import { KubernetesActionDialog, type KubernetesActionDialogProps } from "./KubernetesActionDialog";
import { createDockerReadState } from "./docker-read-state";
import { createKubernetesReadState } from "./kubernetes-read-state";
import { dockerReadScope } from "./docker-read-helpers";
import { kubernetesListContext, kubernetesReadScope } from "./kubernetes-read-helpers";
import type { DockerContainerSnapshot, DockerReadApi } from "../shared/docker-read-contract";
import type { DockerActionPlan, DockerActionReceipt, DockerWriteApi } from "../shared/docker-write-contract";
import type { KubernetesManifestExportApi, KubernetesReadApi, KubernetesSnapshot } from "../shared/kubernetes-read-contract";
import type { KubernetesActionPlan, KubernetesActionReceipt, KubernetesWriteApi } from "../shared/kubernetes-write-contract";
import type { ContainerFilesApi, PodFilesApi } from "../shared/exec-files-contract";
import type { PodFileEvidenceApi } from "../shared/pod-file-evidence-contract";
import type { DockerForensicsApi } from "../shared/docker-forensics-contract";

function render(component: () => ReactNode): ReactNode {
  hooks.cursor = 0;
  const tree = component();
  if (hooks.count !== null) expect(hooks.cursor, "hook count changed").toBe(hooks.count);
  hooks.count = hooks.cursor;
  for (const effect of hooks.pending.splice(0)) effect();
  return tree;
}
function unmount() {
  for (const slot of hooks.slots) {
    if (typeof slot.cleanup === "function") slot.cleanup();
    slot.cleanup = undefined;
  }
}
beforeEach(() => {
  hooks.slots = []; hooks.cursor = 0; hooks.count = null; hooks.pending = [];
  vi.stubGlobal("window", { addEventListener: vi.fn(), removeEventListener: vi.fn() });
});
afterEach(() => { unmount(); vi.unstubAllGlobals(); });

function elements(tree: ReactNode): React.ReactElement<Record<string, unknown>>[] {
  if (Array.isArray(tree)) return tree.flatMap(elements);
  if (!isValidElement<Record<string, unknown>>(tree)) return [];
  return [tree, ...elements(tree.props.children as ReactNode)];
}
function deferred() {
  let resolve!: (value: unknown) => void;
  let reject!: (reason: Error) => void;
  const promise = new Promise<unknown>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
async function settle() { for (let i = 0; i < 12; i++) await Promise.resolve(); }

function fixture(kind: "docker" | "kubernetes") {
  const dockerPlan: DockerActionPlan = {
    planHandle: "plan-one", containerHandle: "row-one", containerName: "cache-node", action: "stop",
    actionLabel: "停止", beforeState: "running", summary: "停止容器 cache-node。", dangerous: true,
    restoreDescription: "恢复运行", confirmed: false, expiresInSeconds: 300,
  };
  const kubePlan: KubernetesActionPlan = {
    planHandle: "plan-one", rowHandle: "row-one", resourceName: "node-one", action: "cordon",
    actionLabel: "标记为不可调度", summary: "将 node-one 标记为不可调度。", dangerous: true,
    restoreDescription: "恢复可调度", confirmed: false, expiresInSeconds: 300,
  };
  const plan = kind === "docker" ? dockerPlan : kubePlan;
  const confirmed = { ...plan, confirmed: true, expiresInSeconds: 290 };
  const receipt: DockerActionReceipt | KubernetesActionReceipt = kind === "docker"
    ? { planHandle: plan.planHandle, containerName: dockerPlan.containerName, actionLabel: plan.actionLabel,
      verified: true, detail: "已回读核对", restored: false }
    : { planHandle: plan.planHandle, resourceName: kubePlan.resourceName, actionLabel: plan.actionLabel,
      verified: true, detail: "已回读核对", restored: false };
  const calls = {
    plan: vi.fn(async (..._args: unknown[]): Promise<unknown> => plan),
    confirm: vi.fn(async (..._args: unknown[]): Promise<unknown> => confirmed),
    execute: vi.fn(async (..._args: unknown[]): Promise<unknown> => receipt),
    cancel: vi.fn(async (..._args: unknown[]): Promise<unknown> => ({ cancelled: true })),
  };
  const dockerSnapshot: DockerContainerSnapshot = {
    snapshotHandle: "snapshot-one", runtime: "docker", installedRuntimes: ["docker"],
    expiresInSeconds: 300, truncated: false,
    containers: [{ containerHandle: "row-one", name: "cache-node", shortId: "012345678abc",
      image: "alpine:3.20", state: "running", status: "Up", ports: "", createdAt: "now" }],
  };
  const dockerApi = {
    refreshDockerContainers: vi.fn(async () => dockerSnapshot),
    getDockerCollection: vi.fn(async () => ({})),
    inspectDockerResource: vi.fn(async () => ({})), getDockerSecurityAudit: vi.fn(async () => ({})),
    getDockerLogs: vi.fn(async () => ({})), openDockerContainerTerminal: vi.fn(async () => ({})),
    planDockerContainerAction: calls.plan, confirmDockerContainerAction: calls.confirm,
    executeDockerContainerAction: calls.execute, cancelDockerContainerAction: calls.cancel,
    readDockerContainerFile: vi.fn(async () => ({})), planDockerFileWrite: vi.fn(async () => ({})),
    planDockerFileCopy: vi.fn(async () => ({})),
    listDockerContainerDirectory: vi.fn(async () => ({})),
    getDockerContainerChanges: vi.fn(async () => ({})), getDockerContainerProcesses: vi.fn(async () => ({})),
  } satisfies DockerReadApi & DockerWriteApi & ContainerFilesApi & DockerForensicsApi;
  const dockerState = {
    ...createDockerReadState(), scope: dockerReadScope("target-one"),
    snapshotStatus: "ready" as const, snapshot: dockerSnapshot,
  };
  const kubeSnapshot: KubernetesSnapshot = {
    snapshotHandle: "snapshot-one", tab: "nodes", namespaceScoped: false, displayed: 1,
    truncated: false, expiresInSeconds: 300,
    rows: [{ kind: "node", rowHandle: "row-one", name: "node-one", ready: true, unschedulable: false,
      roles: ["control-plane"], kubeletVersion: "v1.31.4", internalIp: "10.0.0.1", cpuCapacity: "2",
      memoryCapacity: "1Gi", podCapacity: "110", createdAt: "now", textTruncated: false }],
  };
  const availability = { kubectlInstalled: true, apiReachable: true, currentContext: "lab", contextTruncated: false, contextNamespace: "default" };
  const kubeApi = {
    getKubernetesAvailability: vi.fn(async () => availability),
    listKubernetesResources: vi.fn(async (_binding: string, input: { tab: string }) => input.tab === "nodes"
      ? kubeSnapshot : { ...kubeSnapshot, tab: "namespaces", rows: [], displayed: 0 }),
    getKubernetesResourceDetail: vi.fn(async () => ({})), getKubernetesPodLogs: vi.fn(async () => ({})),
    planKubernetesWorkloadAction: calls.plan, confirmKubernetesWorkloadAction: calls.confirm,
    executeKubernetesWorkloadAction: calls.execute, cancelKubernetesWorkloadAction: calls.cancel,
    openKubernetesPodTerminal: vi.fn(async () => ({})),
    exportKubernetesManifest: vi.fn(async () => ({ saved: false, fileName: null })),
    listKubernetesPodDirectory: vi.fn(async () => ({})), readKubernetesPodFile: vi.fn(async () => ({})),
    podFileEvidence: vi.fn(async () => null),
  } satisfies KubernetesReadApi & KubernetesWriteApi & PodFilesApi & PodFileEvidenceApi & KubernetesManifestExportApi;
  const kubeState = {
    ...createKubernetesReadState(kubernetesReadScope("target-one")),
    availabilityStatus: "ready" as const, availability, activeTab: "nodes" as const,
    listStatus: "ready" as const, listContext: kubernetesListContext("nodes", null),
    snapshot: kubeSnapshot, selectedRowHandle: "row-one",
  };
  let dockerOwner = dockerApi;
  let kubeOwner = kubeApi;
  const view = (binding: string | null = "target-one") => render(() => kind === "docker"
    ? DockerPage({ bindingHandle: binding, api: dockerOwner, initialState: dockerState })
    : KubernetesPage({ bindingHandle: binding, api: kubeOwner, initialState: kubeState }));
  function entry() {
    const tree = elements(view());
    if (kind === "docker") {
      const props = tree.find((node) => typeof node.props.onAction === "function")?.props;
      expect(props).toBeDefined();
      return () => (props?.onAction as (handle: string, name: string, action: string) => void)("row-one", "cache-node", "stop");
    }
    const props = tree.find((node) => node.props["data-testid"] === "kubernetes-action-cordon")?.props;
    expect(props).toBeDefined();
    return props?.onClick as () => void;
  }
  function dialog(binding: string | null = "target-one") {
    return elements(view(binding)).find((node) => node.type === DockerActionDialog || node.type === KubernetesActionDialog)
      ?.props as unknown as DockerActionDialogProps | KubernetesActionDialogProps | undefined;
  }
  return {
    plan, confirmed, receipt, calls, view, entry, dialog,
    objectField: kind === "docker" ? "containerHandle" : "rowHandle",
    nameField: kind === "docker" ? "containerName" : "resourceName",
    refresh: kind === "docker" ? dockerApi.refreshDockerContainers : kubeApi.getKubernetesAvailability,
    replaceApi: () => { dockerOwner = { ...dockerApi }; kubeOwner = { ...kubeApi }; },
    ready: async () => { view(); await settle(); view(); await settle(); },
    open: async () => { entry()(); await settle(); return dialog()!; },
  };
}

describe.each(["docker", "kubernetes"] as const)("%s action ownership", (kind) => {
  it("executes only after explicit approval, blocks double clicks and consumed-plan replay", async () => {
    const f = fixture(kind); await f.ready();
    const dialog = await f.open();
    expect(dialog.plan).toEqual(f.plan); expect(f.calls.execute).not.toHaveBeenCalled();
    dialog.onConfirm(); dialog.onConfirm(); await settle();
    expect(f.calls.confirm).toHaveBeenCalledTimes(1);
    expect(f.calls.execute).toHaveBeenCalledExactlyOnceWith("target-one", "plan-one");
    expect(f.dialog()?.receipt).toEqual(f.receipt);
    dialog.onConfirm(); await settle(); expect(f.calls.execute).toHaveBeenCalledTimes(1);
  });

  it("cancels a late plan after closing and reopening in the same render", async () => {
    const f = fixture(kind); await f.ready(); const late = deferred();
    f.calls.plan.mockReturnValueOnce(late.promise);
    const start = f.entry(); start();
    const waiting = f.dialog()!; expect(waiting.busy).toBe(true);
    waiting.onClose(); start(); await settle();
    expect(f.dialog()?.plan).toEqual(f.plan);
    late.resolve({ ...f.plan, planHandle: "abandoned-plan" }); await settle();
    expect(f.calls.cancel).toHaveBeenCalledWith("target-one", "abandoned-plan");
    expect(f.dialog()?.plan?.planHandle).toBe("plan-one");
    expect(f.calls.execute).not.toHaveBeenCalled();
  });

  it("does not let old dialog callbacks confirm or close a replacement", async () => {
    const f = fixture(kind); await f.ready(); const old = await f.open();
    old.onClose(); const current = await f.open();
    old.onConfirm(); old.onClose(); await settle();
    expect(f.calls.confirm).not.toHaveBeenCalled();
    expect(f.dialog()?.plan).toEqual(current.plan);
  });

  it.each(["disconnect", "switch", "api", "unmount"])("abandons a pending confirmation on %s", async (change) => {
    const f = fixture(kind); await f.ready(); const pending = deferred();
    f.calls.confirm.mockReturnValueOnce(pending.promise);
    (await f.open()).onConfirm();
    if (change === "unmount") unmount();
    else if (change === "api") { f.replaceApi(); expect(f.dialog()).toBeUndefined(); }
    else expect(f.dialog(change === "disconnect" ? null : "target-two")).toBeUndefined();
    pending.resolve(f.confirmed); await settle();
    expect(f.calls.execute).not.toHaveBeenCalled();
    expect(f.calls.cancel).toHaveBeenCalledWith("target-one", "plan-one");
  });

  it("cleans a plan arriving after unmount using its original owner", async () => {
    const f = fixture(kind); await f.ready(); const pending = deferred();
    f.calls.plan.mockReturnValueOnce(pending.promise); f.entry()(); unmount();
    pending.resolve(f.plan); await settle();
    expect(f.calls.cancel).toHaveBeenCalledExactlyOnceWith("target-one", "plan-one");
  });

  it.each(["planHandle", "object", "name", "action", "actionLabel", "summary", "dangerous", "restoreDescription", "confirmed", "expiresInSeconds"])(
    "refuses changed confirmation %s and invalidates retry", async (field) => {
      const f = fixture(kind); await f.ready();
      const key = field === "object" ? f.objectField : field === "name" ? f.nameField : field;
      const changed = { ...f.confirmed, [key]: field === "dangerous" || field === "confirmed" ? false
        : field === "expiresInSeconds" ? 301 : field === "action" ? (kind === "docker" ? "start" : "uncordon") : "changed" };
      f.calls.confirm.mockResolvedValueOnce(changed);
      const dialog = await f.open(); dialog.onConfirm(); await settle();
      expect(f.calls.execute).not.toHaveBeenCalled();
      expect(f.dialog()?.plan).toBeNull(); expect(f.dialog()?.error).toBeTruthy();
      dialog.onConfirm(); await settle(); expect(f.calls.confirm).toHaveBeenCalledTimes(1);
    },
  );

  it.each(["object", "name", "action", "confirmed"])("refuses an initial plan with another %s", async (field) => {
    const f = fixture(kind); await f.ready();
    const key = field === "object" ? f.objectField : field === "name" ? f.nameField : field;
    f.calls.plan.mockResolvedValueOnce({ ...f.plan, [key]: field === "confirmed" ? true
      : field === "action" ? (kind === "docker" ? "start" : "uncordon") : "other" });
    const dialog = await f.open(); expect(dialog.plan).toBeNull(); expect(dialog.error).toBeTruthy();
    dialog.onConfirm(); await settle(); expect(f.calls.confirm).not.toHaveBeenCalled();
  });

  it.each(["planHandle", "name", "actionLabel"])("does not present a foreign receipt %s as success", async (field) => {
    const f = fixture(kind); await f.ready();
    f.calls.execute.mockResolvedValueOnce({ ...f.receipt, [field === "name" ? f.nameField : field]: "other" });
    const dialog = await f.open(); dialog.onConfirm(); await settle();
    expect(f.dialog()?.receipt).toBeNull(); expect(f.dialog()?.error).toBeTruthy();
    dialog.onConfirm(); await settle(); expect(f.calls.execute).toHaveBeenCalledTimes(1);
  });

  it.each(["confirm", "execute"] as const)("does not replay after a %s transport failure", async (stage) => {
    const f = fixture(kind); await f.ready(); f.calls[stage].mockRejectedValueOnce(new Error("connection lost"));
    const dialog = await f.open(); dialog.onConfirm(); await settle();
    expect(f.dialog()?.plan).toBeNull(); expect(f.dialog()?.error).toBeTruthy();
    dialog.onConfirm(); await settle(); expect(f.calls[stage]).toHaveBeenCalledTimes(1);
  });

  it("does not refresh or show a late receipt on another target", async () => {
    const f = fixture(kind); await f.ready(); const pending = deferred();
    f.calls.execute.mockReturnValueOnce(pending.promise);
    (await f.open()).onConfirm(); await settle();
    f.view("target-two"); await settle(); f.view("target-two"); await settle();
    const reads = f.refresh.mock.calls.length;
    pending.resolve(f.receipt); await settle();
    expect(f.dialog("target-two")).toBeUndefined(); expect(f.refresh).toHaveBeenCalledTimes(reads);
  });
});

