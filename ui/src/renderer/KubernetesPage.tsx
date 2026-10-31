import { TransientNotice } from "./NotificationCenter";
import { useEffect, useReducer, useRef, useState } from "react";

import { targetFailureMessage } from "./target-lost";
import { errorText } from "./error-text";

import {
  KUBERNETES_READ_TABS,
  isKubernetesAvailability,
  isKubernetesListInput,
  isKubernetesManifestExportResult,
  isKubernetesSnapshot,
  isKubernetesTextResult,
  type KubernetesContentKind,
  type KubernetesListInput,
  type KubernetesManifestExportApi,
  type KubernetesReadApi,
  type KubernetesReadRow,
  type KubernetesReadTab,
} from "../shared/kubernetes-read-contract";
import {
  KUBERNETES_ROW_WINDOW,
  filteredKubernetesRows,
  kubernetesListContext,
  kubernetesNamespaceCapability,
  kubernetesReadScope,
  kubernetesRowName,
  kubernetesColumns,
  kubernetesRowNeedsAttention,
  kubernetesRowRestarted,
  kubernetesRowState,
  kubernetesStatCards,
  kubernetesRowSubtitle,
  kubernetesTabLabel,
  windowedKubernetesRows,
} from "./kubernetes-read-helpers";
import {
  createKubernetesReadState,
  currentSnapshot,
  kubernetesReadReducer,
  type KubernetesReadState,
} from "./kubernetes-read-state";
import {
  isKubernetesActionPlan,
  isKubernetesActionReceipt,
  type KubernetesActionPlan,
  MAX_KUBERNETES_REPLICAS,
  type KubernetesWriteAction,
  type KubernetesWriteApi,
} from "../shared/kubernetes-write-contract";
import {
  createKubernetesActionState,
  kubernetesActionReducer,
} from "./kubernetes-action-state";
import { KubernetesActionDialog } from "./KubernetesActionDialog";
import { PodFileDialog } from "./PodFileDialog";
import type { PodFilesApi } from "../shared/exec-files-contract";
import type { PodFileEvidenceApi } from "../shared/pod-file-evidence-contract";
import { useModalScrim } from "./modal-scrim";
import {
  availableKubernetesActions,
  kubernetesActionLabel,
} from "./kubernetes-action-helpers";
import "./kubernetes-page.css";

interface KubernetesPageProps {
  bindingHandle: string | null;
  api: KubernetesReadApi & KubernetesWriteApi & PodFilesApi & PodFileEvidenceApi & KubernetesManifestExportApi;
  /** Deterministic standalone/SSR fixture; production leaves this unset. */
  initialState?: KubernetesReadState;
  /**
   * Takes a running pod to the command workbench with it already chosen as
   * where the checks run (`namespace/pod`, as the workbench lists pods).
   */
  onInvestigate?: ((kind: "pod", name: string) => void) | undefined;
}

interface KubernetesActionOperation {
  api: KubernetesWriteApi;
  bindingHandle: string;
  requestId: number;
  plan: KubernetesActionPlan | null;
  busy: boolean;
}

/** The cluster's permission check refused the request (RBAC). */
function isForbidden(error: unknown): boolean {
  return error instanceof Error && error.message.includes("kubernetes-forbidden");
}

function isNamespaceScopedTab(tab: KubernetesReadTab): boolean {
  return tab === "pods" || tab === "deployments";
}

function discardKubernetesAction(operation: KubernetesActionOperation) {
  const plan = operation.plan;
  operation.plan = null;
  if (plan !== null) {
    void operation.api.cancelKubernetesWorkloadAction(operation.bindingHandle, plan.planHandle).catch(() => {});
  }
}

/**
 * Why no cluster could be read, and what that does and does not mean. It
 * replaces the namespace picker, the tabs and an empty table, which looked
 * like a cluster with nothing in it.
 */
export function KubernetesUnavailable({ kubectlInstalled, context }: { kubectlInstalled: boolean; context: string }) {
  return (
    <div className="kubernetes-unavailable" role="status" data-testid="kubernetes-unavailable">
      <strong>{kubectlInstalled ? "kubectl 已安装，但连不上集群" : "这台主机上没有 kubectl"}</strong>
      <p>{kubectlInstalled
        ? `当前 context${context === "" ? "" : `（${context}）`}的 API 不可达，所以没能读取任何集群资源。可能是集群地址不可达、凭据过期，或这个账号没有可用的 kubeconfig。`
        : "当前登录账号找不到 kubectl，所以没能读取任何集群资源。这不代表这台主机与集群无关：kubectl 可能不在这个账号的 PATH 里，或集群由别的机器管理。"}</p>
      <p>处理后点右上角“刷新”再读一次。</p>
    </div>
  );
}

export function KubernetesPage({ bindingHandle, api, initialState, onInvestigate }: KubernetesPageProps) {
  const [state, dispatch] = useReducer(
    kubernetesReadReducer,
    initialState ?? createKubernetesReadState(),
  );
  const [actionState, actionDispatch] = useReducer(
    kubernetesActionReducer,
    undefined,
    createKubernetesActionState,
  );
  const [refreshVersion, setRefreshVersion] = useState(0);
  // Which row the replica input is open for, and what it holds. Kept as a
  // string so a half-typed value is not silently coerced to a number.
  const [scaleRow, setScaleRow] = useState<string | null>(null);
  const [scaleReplicas, setScaleReplicas] = useState("1");
  // Narrowing to what is broken is the operator's view of the list, not part
  // of it, so a refresh does not throw it away.
  const [attentionOnly, setAttentionOnly] = useState(false);
  // The details dim what is behind them, like every other modal in the app.
  useModalScrim(state.selectedRowHandle !== null);
  const requestRef = useRef(0);
  // Opening a window is a remote call a double click would make twice; the
  // window already open for the same pod is raised instead, but only once
  // the first call has registered it.
  const terminalRef = useRef(false);
  const [terminalError, setTerminalError] = useState<{ scope: string; message: string } | null>(null);
  // Saving a manifest asks where through the system save dialog; a second
  // click while it is open would ask twice. The outcome belongs to the row
  // and the target it was for.
  const exportRef = useRef(false);
  const [exporting, setExporting] = useState(false);
  const [exportNotice, setExportNotice] = useState<
    { scope: string; rowHandle: string; saved: boolean; message: string } | null
  >(null);
  // The pod whose files are open, by the list's own handles. Tied to the
  // scope it was opened in, so a target switch closes it rather than
  // pointing it at whatever the new target lists.
  const [podFiles, setPodFiles] = useState<{
    scope: string;
    snapshotHandle: string;
    rowHandle: string;
    podName: string;
    container: string | null;
  } | null>(null);
  // The container chosen per multi-container pod row, for its logs, shell and
  // files; a row without a choice uses the pod's default container.
  const [podContainers, setPodContainers] = useState<{ scope: string | null; chosen: Record<string, string> }>(
    { scope: null, chosen: {} },
  );
  // Which container the logs on screen came from, said above them.
  const [logsContainer, setLogsContainer] = useState<string | null>(null);
  const scope = bindingHandle === null ? null : kubernetesReadScope(bindingHandle);
  const visibleState = state.scope === scope ? state : createKubernetesReadState(scope);
  const listContext = kubernetesListContext(
    visibleState.activeTab,
    visibleState.selectedNamespace,
  );
  const activeSnapshot = currentSnapshot(visibleState);
  const activeStatus = visibleState.activeTab === "namespaces"
    ? visibleState.namespacesStatus
    : visibleState.listStatus;
  const searched = filteredKubernetesRows(activeSnapshot, visibleState.query);
  // Counted before the toggle is applied, so the badge says how many there are
  // rather than how many are showing.
  const attentionCount = searched.filter(kubernetesRowNeedsAttention).length;
  const filteredRows = attentionOnly
    ? searched.filter(kubernetesRowNeedsAttention)
    : searched;
  const columns = kubernetesColumns(visibleState.activeTab);
  const pageCount = Math.max(1, Math.ceil(filteredRows.length / KUBERNETES_ROW_WINDOW));
  const safePage = Math.min(visibleState.page, pageCount - 1);
  const shownRows = windowedKubernetesRows(filteredRows, safePage);
  const selectedRow = activeSnapshot?.rows.find(
    (row) => row.rowHandle === visibleState.selectedRowHandle,
  ) ?? null;
  const selectedScope = visibleState.selectedNamespace;
  const contextNamespace = visibleState.availability?.contextNamespace ?? null;
  const contextScopeSelected = selectedScope !== null && "context" in selectedScope;
  const selectedNamespaceRow = selectedScope !== null && !("context" in selectedScope)
    ? selectedScope.rowHandle
    : null;
  const selectedNamespaceName = contextScopeSelected
    ? contextNamespace === null ? null : `${contextNamespace}（当前上下文）`
    : visibleState.namespaces?.rows.find(
      (row) => row.kind === "namespace" && row.rowHandle === selectedNamespaceRow,
    )?.name ?? null;

  useEffect(() => {
    dispatch({ type: "scope-changed", scope });
  }, [scope]);

  // The details are a dialog now, so they owe the operator a way out that is
  // not hunting for a close button.
  const detailOpen = visibleState.selectedRowHandle !== null;
  useEffect(() => {
    if (!detailOpen) return;
    function dismissOnEscape(event: KeyboardEvent): void {
      if (event.key === "Escape") closeDetail();
    }
    window.addEventListener("keydown", dismissOnEscape, true);
    return () => window.removeEventListener("keydown", dismissOnEscape, true);
  }, [detailOpen, scope]);

  useEffect(() => {
    if (scope === null || bindingHandle === null) return;
    const request = ++requestRef.current;
    dispatch({ type: "availability-started", scope, request });
    void api.getKubernetesAvailability(bindingHandle).then((result) => {
      if (!isKubernetesAvailability(result)) throw new Error();
      dispatch({ type: "availability-loaded", scope, request, availability: result });
    }).catch(() => {
      dispatch({
        type: "availability-failed",
        scope,
        request,
        error: "Kubernetes 可用性结果格式异常，或 SSH 目标已切换。",
      });
    });
  }, [api, bindingHandle, refreshVersion, scope]);

  useEffect(() => {
    if (scope === null || bindingHandle === null ||
      visibleState.availability?.apiReachable !== true) return;
    const request = ++requestRef.current;
    const input: KubernetesListInput = { tab: "namespaces", namespaceScope: null };
    dispatch({ type: "namespaces-started", scope, request });
    void api.listKubernetesResources(bindingHandle, input).then((result) => {
      if (!isKubernetesSnapshot(result) || result.tab !== "namespaces") throw new Error();
      dispatch({ type: "namespaces-loaded", scope, request, snapshot: result });
    }).catch((error: unknown) => {
      dispatch({
        type: "namespaces-failed",
        scope,
        request,
        forbidden: isForbidden(error),
        error: isForbidden(error)
          ? "当前账号没有权限列出命名空间（集群拒绝），kubeconfig 也没有指定命名空间。请换有权限的 kubeconfig 或账号。"
          : "无法读取当前目标的命名空间列表。",
      });
    });
  }, [
    api,
    bindingHandle,
    refreshVersion,
    scope,
    visibleState.availability?.apiReachable,
  ]);

  useEffect(() => {
    if (scope === null || bindingHandle === null ||
      visibleState.availability?.apiReachable !== true ||
      visibleState.activeTab === "namespaces") return;
    const input: KubernetesListInput = {
      tab: visibleState.activeTab,
      namespaceScope: visibleState.activeTab === "pods" ||
        visibleState.activeTab === "deployments"
        ? visibleState.selectedNamespace
        : null,
    };
    if (!isKubernetesListInput(input)) return;
    const request = ++requestRef.current;
    dispatch({
      type: "list-started",
      scope,
      request,
      tab: input.tab,
      context: listContext,
    });
    void api.listKubernetesResources(bindingHandle, input).then((result) => {
      if (!isKubernetesSnapshot(result) || result.tab !== input.tab ||
        result.namespaceScoped !== (input.namespaceScope !== null)) throw new Error();
      dispatch({
        type: "list-loaded",
        scope,
        request,
        tab: input.tab,
        context: listContext,
        snapshot: result,
      });
    }).catch((error: unknown) => {
      // A refusal is a limit of this account, said as one, with the way
      // around it when there is one — never an empty list.
      const contextOffered = input.namespaceScope === null && isNamespaceScopedTab(input.tab) &&
        visibleState.availability?.contextNamespace != null;
      dispatch({
        type: "list-failed",
        scope,
        request,
        tab: input.tab,
        context: listContext,
        error: isForbidden(error)
          ? `当前账号没有权限读取 ${kubernetesTabLabel(input.tab)}（集群拒绝）。${contextOffered
            ? `可以在上方改选当前上下文的命名空间「${visibleState.availability?.contextNamespace ?? ""}」。`
            : "请改选这个账号能访问的命名空间，或换有权限的 kubeconfig、账号。"}`
          : "资源快照不可用，或目标已发生变化。",
      });
    });
  }, [
    api,
    bindingHandle,
    listContext,
    refreshVersion,
    scope,
    visibleState.activeTab,
    visibleState.availability?.apiReachable,
  ]);

  useEffect(() => {
    if (scope === null || bindingHandle === null || activeSnapshot === null ||
      visibleState.selectedRowHandle === null || visibleState.detailStatus !== "idle") return;
    void loadText("detail", activeSnapshot.snapshotHandle, visibleState.selectedRowHandle);
  }, [
    activeSnapshot?.snapshotHandle,
    api,
    bindingHandle,
    scope,
    visibleState.detailStatus,
    visibleState.selectedRowHandle,
  ]);

  const connectedScope = scope ?? "";

  /**
   * The container a pod row's logs, shell and files use: the one chosen in
   * its row, else the pod's default. Null for a pod with one container, which
   * kubectl picks by itself.
   */
  function containerFor(row: KubernetesReadRow): string | null {
    if (row.kind !== "pod" || row.containers.length < 2) return null;
    const chosen = podContainers.scope === scope ? podContainers.chosen[row.rowHandle] : undefined;
    if (chosen !== undefined && row.containers.some((container) => container.name === chosen)) return chosen;
    return row.defaultContainer ?? row.containers[0]?.name ?? null;
  }

  function chooseContainer(row: KubernetesReadRow, container: string) {
    setPodContainers((current) => ({
      scope,
      chosen: { ...(current.scope === scope ? current.chosen : {}), [row.rowHandle]: container },
    }));
  }

  async function loadText(
    kind: KubernetesContentKind,
    snapshotHandle: string,
    rowHandle: string,
    container: string | null = null,
  ) {
    if (scope === null || bindingHandle === null) return;
    const request = ++requestRef.current;
    dispatch({ type: "detail-started", scope, request, snapshotHandle, rowHandle });
    setLogsContainer(kind === "detail" ? null : container);
    try {
      const result = kind === "detail"
        ? await api.getKubernetesResourceDetail(bindingHandle, snapshotHandle, rowHandle)
        : await api.getKubernetesPodLogs(bindingHandle, snapshotHandle, rowHandle, kind === "pod-previous-logs", container);
      if (!isKubernetesTextResult(result) || result.contentKind !== kind ||
        result.snapshotHandle !== snapshotHandle || result.rowHandle !== rowHandle) throw new Error();
      dispatch({
        type: "detail-loaded",
        scope,
        request,
        snapshotHandle,
        rowHandle,
        detail: result,
      });
    } catch (reason) {
      // The kubelet's own "cannot hand it over right now" is passing, not a
      // missing log; saying so is what tells the operator to try again.
      const notReady = String(reason instanceof Error ? reason.message : reason)
        .includes("kubernetes-logs-not-ready");
      dispatch({
        type: "detail-failed",
        scope,
        request,
        snapshotHandle,
        rowHandle,
        error: notReady
          ? "kubelet 这会儿交不出这段容器日志（容器刚被替换，或旧日志已被回收）。稍等几秒再读一次。"
          : kind === "pod-previous-logs"
            ? "读不到上一次运行的日志：容器可能没有重启过、旧日志已被清理，或目标已切换。"
            : kind === "pod-logs"
              ? "Pod 日志不可用，或目标已切换。"
              : "资源详情不可用，或目标已切换。",
      });
    }
  }

  function closeDetail() {
    if (scope === null) return;
    dispatch({ type: "row-cleared", scope });
  }

  function selectRow(row: KubernetesReadRow) {
    if (scope === null || activeSnapshot === null) return;
    dispatch({
      type: "row-selected",
      scope,
      snapshotHandle: activeSnapshot.snapshotHandle,
      rowHandle: row.rowHandle,
    });
  }

  /**
   * Opens a row with what was asked for already on its way: its detail, or a
   * pod's recent logs. Opening and then pressing "读取" was two steps for the
   * one thing anyone opens a row to see.
   */
  function openRow(row: KubernetesReadRow, content: KubernetesContentKind = "detail") {
    if (activeSnapshot === null) return;
    selectRow(row);
    void loadText(content, activeSnapshot.snapshotHandle, row.rowHandle, containerFor(row));
  }

  /**
   * Opens a terminal window with a shell in a running pod. The window opens
   * its shell by the list's own handles; whether kubectl may exec there, and
   * which shell the image has, the window itself reports.
   */
  async function openPodTerminal(row: KubernetesReadRow) {
    if (terminalRef.current || scope === null || activeSnapshot === null || row.kind !== "pod") return;
    terminalRef.current = true;
    setTerminalError(null);
    const podName = `${row.namespace}/${row.name}`;
    try {
      await api.openKubernetesPodTerminal(activeSnapshot.snapshotHandle, row.rowHandle, podName, containerFor(row));
    } catch (reason: unknown) {
      setTerminalError({
        scope,
        message: targetFailureMessage(reason, `打不开 ${podName} 的终端窗口，请刷新列表后再试。`),
      });
    } finally {
      terminalRef.current = false;
    }
  }

  /**
   * Saves the selected Pod, Deployment or Node's live manifest (YAML) to a
   * file the operator picks. The object goes by the list's handles; the
   * contents go from the cluster to the file and never through this page.
   */
  async function exportManifest(row: KubernetesReadRow) {
    if (exportRef.current || scope === null || bindingHandle === null || activeSnapshot === null ||
      row.kind === "namespace") return;
    exportRef.current = true;
    setExporting(true);
    setExportNotice(null);
    try {
      const result = await api.exportKubernetesManifest(bindingHandle, activeSnapshot.snapshotHandle, row.rowHandle);
      if (!isKubernetesManifestExportResult(result)) throw new Error();
      if (result.saved) {
        setExportNotice({
          scope,
          rowHandle: row.rowHandle,
          saved: true,
          message: `已保存为 ${result.fileName ?? ""}。文件里是集群返回的原文，可能含有环境变量里的明文口令或令牌，请按证据保管。`,
        });
      }
    } catch (reason: unknown) {
      setExportNotice({
        scope,
        rowHandle: row.rowHandle,
        saved: false,
        message: targetFailureMessage(reason, errorText(reason, "清单没有导出，请刷新列表后再试。")),
      });
    } finally {
      exportRef.current = false;
      setExporting(false);
    }
  }

  // Ownership outlives a render, but never the target or dialog that requested it.
  const actionRef = useRef<KubernetesActionOperation | null>(null);
  const actionSequence = useRef(0);
  const actionContext = useRef({ api, bindingHandle });
  actionContext.current = { api, bindingHandle };
  const renderedAction = actionRef.current;
  function isCurrentAction(operation: KubernetesActionOperation | null): operation is KubernetesActionOperation {
    return operation !== null && actionRef.current === operation &&
      actionContext.current.api === operation.api &&
      actionContext.current.bindingHandle === operation.bindingHandle;
  }
  useEffect(() => {
    actionDispatch({ type: "closed" });
    return () => {
      const operation = actionRef.current;
      if (operation?.api === api && operation.bindingHandle === bindingHandle) {
        actionRef.current = null;
        discardKubernetesAction(operation);
      }
    };
  }, [api, bindingHandle]);

  async function openAction(row: KubernetesReadRow, action: KubernetesWriteAction) {
    if (actionRef.current !== null || bindingHandle === null || activeSnapshot === null ||
      actionContext.current.api !== api || actionContext.current.bindingHandle !== bindingHandle) return;
    const operation: KubernetesActionOperation = {
      api, bindingHandle, requestId: ++actionSequence.current, plan: null, busy: true,
    };
    actionRef.current = operation;
    const request = operation.requestId;
    actionDispatch({
      type: "opened",
      requestId: request,
      rowHandle: row.rowHandle,
      resourceName: row.name,
      action,
      actionLabel: kubernetesActionLabel(action.kind),
    });
    try {
      const plan = await api.planKubernetesWorkloadAction(
        bindingHandle, activeSnapshot.snapshotHandle, row.rowHandle, row.name, action,
      );
      if (!isKubernetesActionPlan(plan)) throw new Error();
      operation.plan = plan;
      if (!isCurrentAction(operation)) { discardKubernetesAction(operation); return; }
      if (plan.rowHandle !== row.rowHandle || plan.resourceName !== row.name ||
        plan.action !== action.kind || plan.actionLabel !== kubernetesActionLabel(action.kind) || plan.confirmed) throw new Error();
      actionDispatch({ type: "planned", requestId: request, plan });
    } catch (reason: unknown) {
      if (!isCurrentAction(operation)) return;
      discardKubernetesAction(operation);
      actionDispatch({
        type: "failed",
        requestId: request,
        message: kubernetesActionFailure(reason),
      });
    } finally {
      operation.busy = false;
    }
  }

  async function runAction() {
    const operation = renderedAction;
    const plan = actionState.plan;
    if (!isCurrentAction(operation) || operation.busy || plan === null || operation.plan !== plan) return;
    operation.busy = true;
    const request = operation.requestId;
    actionDispatch({ type: "executing", requestId: request });
    try {
      // Approval and execution stay two calls. Nothing runs until the sidecar
      // has recorded that the operator pressed this button.
      const confirmed = await operation.api.confirmKubernetesWorkloadAction(operation.bindingHandle, plan.planHandle);
      if (!isCurrentAction(operation)) return;
      if (!isKubernetesActionPlan(confirmed) || !confirmed.confirmed ||
        confirmed.expiresInSeconds <= 0 || confirmed.expiresInSeconds > plan.expiresInSeconds ||
        confirmed.planHandle !== plan.planHandle || confirmed.rowHandle !== plan.rowHandle ||
        confirmed.resourceName !== plan.resourceName || confirmed.action !== plan.action ||
        confirmed.actionLabel !== plan.actionLabel || confirmed.summary !== plan.summary ||
        confirmed.dangerous !== plan.dangerous || confirmed.restoreDescription !== plan.restoreDescription) throw new Error();
      const receipt = await operation.api.executeKubernetesWorkloadAction(operation.bindingHandle, plan.planHandle);
      if (!isCurrentAction(operation)) return;
      if (!isKubernetesActionReceipt(receipt) || receipt.planHandle !== plan.planHandle ||
        receipt.resourceName !== plan.resourceName || receipt.actionLabel !== plan.actionLabel) throw new Error();
      operation.plan = null;
      actionDispatch({ type: "executed", requestId: request, receipt });
      // Whatever the read-back said, the list is now out of date.
      setRefreshVersion((version) => version + 1);
    } catch (reason: unknown) {
      if (!isCurrentAction(operation)) return;
      discardKubernetesAction(operation);
      actionDispatch({
        type: "failed",
        requestId: request,
        message: kubernetesActionFailure(reason),
      });
    } finally {
      operation.busy = false;
    }
  }

  function closeAction() {
    if (!isCurrentAction(renderedAction)) return;
    actionRef.current = null;
    discardKubernetesAction(renderedAction);
    actionDispatch({ type: "closed" });
  }

  /**
   * The two refusals worth telling apart from a generic failure: an action
   * that does not apply to the kind of thing clicked, and a row that is no
   * longer in a live snapshot. Both are things the operator can act on.
   */
  function kubernetesActionFailure(reason: unknown): string {
    const message = reason instanceof Error ? reason.message : String(reason ?? "");
    if (message.includes("kubernetes-action-kind-mismatch")) {
      return "这个动作不适用于所选资源。";
    }
    if (message.includes("kubernetes-resource-unavailable")) {
      return "这个资源已经不在当前列表里，刷新后再试。";
    }
    return targetFailureMessage(reason, "操作没有完成，集群里的状态请再确认一次。");
  }

  if (bindingHandle === null) {
    return (
      <section className="page kubernetes-page">
        <div className="kubernetes-connect-state">
          <span aria-hidden="true">⎈</span>
          <h1>连接目标后调查 Kubernetes</h1>
          <p>连上之后可以看命名空间、Pod、Deployment 与节点；调整副本数、暂停节点调度这类操作要先确认再执行。</p>
        </div>
      </section>
    );
  }
  const available = visibleState.availability?.apiReachable === true;
  // Known and not reachable: one explanation, not an empty cluster interface.
  const unavailable = visibleState.availabilityStatus === "ready" && visibleState.availability !== null && !available;
  return (
    <section className="page kubernetes-page">
      {/* Pinned, the same way the Docker pane pins its own: identity, cluster
          scope and the resource tabs are what tell you where you are, and a
          long pod list scrolled all of it away. */}
      <div className="kubernetes-page-top">
      {/* Name, cluster, reachability on one baseline. The old header stacked
          an eyebrow reading "只读" — which had stopped being true — over a
          title, over a subtitle, with the availability pill floated opposite;
          four things saying what two can. */}
      <header className="page-heading kubernetes-heading">
        <div className="kubernetes-identity">
          <h1>Kubernetes</h1>
          <span className={`kubernetes-availability ${available ? "ready" : "pending"}`}>
            {available ? "API 可达" : "API 未就绪"}
          </span>
          {visibleState.availability?.currentContext ? (
            <span className="kubernetes-context">
              context {visibleState.availability.currentContext}
            </span>
          ) : null}
        </div>
        <button
          type="button"
          disabled={visibleState.availabilityStatus === "loading"}
          onClick={() => setRefreshVersion((version) => version + 1)}
        >
          {visibleState.availabilityStatus === "loading" ? "刷新中…" : "刷新"}
        </button>
      </header>

      {unavailable && visibleState.availability !== null ? (
        <KubernetesUnavailable kubectlInstalled={visibleState.availability.kubectlInstalled}
          context={visibleState.availability.currentContext} />
      ) : visibleState.notice !== null ? (
        <TransientNotice source="Kubernetes" message={visibleState.notice ?? ""} severity="info"><div className="kubernetes-notice" role="status">{visibleState.notice}</div></TransientNotice>
      ) : null}
      {visibleState.error !== null ? (
        <TransientNotice source="Kubernetes" message={visibleState.error ?? ""} severity="error"><div className="kubernetes-notice error" role="alert">{visibleState.error}</div></TransientNotice>
      ) : null}
      {terminalError !== null && terminalError.scope === scope ? (
        <TransientNotice source="Kubernetes" message={terminalError.message ?? ""} severity="error"><div className="kubernetes-notice error" role="alert" data-testid="kubernetes-terminal-error">
          {terminalError.message}
        </div></TransientNotice>
      ) : null}

      <section className="kubernetes-scope" aria-label="Namespace 范围" hidden={unavailable}>
        <div>
          <p>命名空间范围</p>
          <strong>{selectedNamespaceName ?? "全部命名空间"}</strong>
        </div>
        <div className="kubernetes-namespace-list">
          <button
            type="button"
            className={visibleState.selectedNamespace === null ? "active" : undefined}
            aria-pressed={visibleState.selectedNamespace === null}
            onClick={() => dispatch({
              type: "namespace-selected",
              scope: connectedScope,
              capability: null,
            })}
          >
            全部
          </button>
          {/* The account may not list namespaces: the one its kubeconfig
              names is offered by itself, labelled as such. */}
          {visibleState.namespacesRestricted && contextNamespace !== null ? (
            <button
              type="button"
              data-testid="kubernetes-context-namespace"
              className={contextScopeSelected ? "active" : undefined}
              aria-pressed={contextScopeSelected}
              title="kubeconfig 当前上下文指定的命名空间"
              onClick={() => dispatch({
                type: "namespace-selected",
                scope: connectedScope,
                capability: { context: true },
              })}
            >
              当前上下文 · {contextNamespace}
            </button>
          ) : null}
          {visibleState.namespaces?.rows.map((row) => row.kind === "namespace" ? (
            <button
              type="button"
              key={row.rowHandle}
              className={row.rowHandle === selectedNamespaceRow ? "active" : undefined}
              aria-pressed={row.rowHandle === selectedNamespaceRow}
              onClick={() => dispatch({
                type: "namespace-selected",
                scope: connectedScope,
                capability: kubernetesNamespaceCapability(
                  visibleState.namespaces as NonNullable<typeof visibleState.namespaces>,
                  row.rowHandle,
                ),
              })}
            >
              {row.name}
            </button>
          ) : null)}
        </div>
        {visibleState.namespacesStatus === "loading" ||
        visibleState.namespacesStatus === "idle" && available ? (
          <span className="kubernetes-inline-state" role="status">正在读取 namespaces…</span>
        ) : null}
      </section>

      <nav className="kubernetes-tabs view-tabs" aria-label="Kubernetes 资源类型" hidden={unavailable}>
        {KUBERNETES_READ_TABS.map((tab) => (
          <button
            type="button"
            key={tab}
            className={tab === visibleState.activeTab ? "active" : undefined}
            aria-current={tab === visibleState.activeTab ? "page" : undefined}
            onClick={() => dispatch({ type: "tab-selected", scope: connectedScope, tab })}
          >
            {kubernetesTabLabel(tab)}
          </button>
        ))}
      </nav>

      {/* What is broken, before any scrolling. On this page that is the first
          question, and it used to require reading every row to answer. Only
          tabs that have been read contribute a number — a tab nobody opened
          shows no count rather than a zero that would read as "none". */}
      {available && (
        <div className="kubernetes-stat-row">
          {kubernetesStatCards({
            ...(visibleState.namespaces === null ? {} : { namespaces: visibleState.namespaces.rows }),
            ...(visibleState.activeTab === "pods" && activeSnapshot !== null ? { pods: activeSnapshot.rows } : {}),
            ...(visibleState.activeTab === "deployments" && activeSnapshot !== null ? { deployments: activeSnapshot.rows } : {}),
            ...(visibleState.activeTab === "nodes" && activeSnapshot !== null ? { nodes: activeSnapshot.rows } : {}),
          }).map((card) => (
            <article key={card.id} className={`kubernetes-stat-card is-${card.tone}`}>
              <p className="kubernetes-stat-label">{card.label}</p>
              <p className="kubernetes-stat-value">{card.value ?? "—"}</p>
              <p className="kubernetes-stat-detail">{card.detail}</p>
            </article>
          ))}
        </div>
      )}
      </div>

      <div className="kubernetes-workbench" hidden={unavailable}>
        <section className="kubernetes-resources" aria-labelledby="kubernetes-resources-title">
          <header>
            <div>
              <p>资源快照</p>
              <h2 id="kubernetes-resources-title">{kubernetesTabLabel(visibleState.activeTab)}</h2>
            </div>
            <div className="kubernetes-filters">
              <label className="kubernetes-search">
                <span>搜索当前快照</span>
                <input
                  type="search"
                  value={visibleState.query}
                  maxLength={256}
                  onChange={(event) => dispatch({
                    type: "query-changed",
                    query: event.currentTarget.value,
                  })}
                  placeholder="名称、状态、节点或镜像"
                />
              </label>
              {/* The one filter this page actually needs. A cluster with two
                  hundred pods puts the three that matter somewhere in the
                  middle, and scrolling for them is how they get missed. */}
              <label className="kubernetes-attention-toggle">
                <input
                  type="checkbox"
                  checked={attentionOnly}
                  onChange={(event) => {
                    setAttentionOnly(event.currentTarget.checked);
                    dispatch({ type: "page-selected", page: 0 });
                  }}
                />
                只看要处理的
                {attentionCount > 0 && <em>{attentionCount}</em>}
              </label>
            </div>
          </header>

          {!available && visibleState.availabilityStatus !== "loading" ? (
            <div className="kubernetes-state">当前目标没有可用的 Kubernetes API，未生成资源结果。</div>
          ) : null}
          {available && (activeStatus === "idle" || activeStatus === "loading") ? (
            <div className="kubernetes-state" role="status">正在读取资源快照…</div>
          ) : null}
          {activeStatus === "error" ? (
            <div className="kubernetes-state error">
              {visibleState.activeTab === "namespaces" && visibleState.namespacesRestricted
                ? "当前账号不能列出命名空间（集群拒绝，权限不足）；其他页按 kubeconfig 当前上下文的命名空间读取。"
                : visibleState.error !== null
                  ? "这一页没有读到，原因见上方提示。"
                  : "资源快照不可用。"}
            </div>
          ) : null}
          {activeStatus === "ready" && activeSnapshot?.rows.length === 0 ? (
            <div className="kubernetes-state">当前范围没有 {kubernetesTabLabel(visibleState.activeTab)}。</div>
          ) : null}
          {activeStatus === "ready" && activeSnapshot !== null &&
          activeSnapshot.rows.length > 0 && filteredRows.length === 0 ? (
            <div className="kubernetes-state">当前快照没有匹配搜索条件的资源。</div>
          ) : null}

          {/* A table, not a list of run-on lines. Restart counts and ready
              ratios are exactly the things you want to run your eye down a
              column of, and they used to be buried mid-sentence in each row. */}
          <div className="kubernetes-table-wrap">
            <table className="kubernetes-table">
              <thead>
                <tr>
                  {columns.map((column) => (
                    <th key={column.key} className={column.numeric === true ? "is-numeric" : undefined}>
                      {column.label}
                    </th>
                  ))}
                  <th>状态</th>
                  <th className="kubernetes-actions-head">操作</th>
                </tr>
              </thead>
              <tbody>
                {shownRows.map((row) => {
                  const state = kubernetesRowState(row);
                  const attention = kubernetesRowNeedsAttention(row);
                  const restarted = kubernetesRowRestarted(row);
                  const selected = row.rowHandle === visibleState.selectedRowHandle;
                  return (
                    <tr
                      key={row.rowHandle}
                      className={[
                        selected ? "is-selected" : "",
                        attention ? "needs-attention" : "",
                        restarted ? "has-restarts" : "",
                      ].filter(Boolean).join(" ") || undefined}
                    >
                      {columns.map((column, index) => (
                        <td
                          key={column.key}
                          className={[
                            column.numeric === true ? "is-numeric" : "",
                            column.key === "restarts" && restarted ? "is-restarted" : "",
                          ].filter(Boolean).join(" ") || undefined}
                        >
                          {index === 0 ? (
                            <button
                              type="button"
                              className="kubernetes-row-button"
                              aria-pressed={selected}
                              onClick={() => openRow(row)}
                            >
                              {column.read(row)}
                            </button>
                          ) : column.read(row)}
                        </td>
                      ))}
                      <td>
                        <span className={`kubernetes-state is-${state.tone}`}>{state.label}</span>
                        {row.textTruncated ? <em>字段已截断</em> : null}
                      </td>
                      <td className="kubernetes-row-actions">
                        {/* A pod of several containers: which one the logs,
                            shell and files below are for. */}
                        {row.kind === "pod" && row.containers.length > 1 ? (
                          <label className="kubernetes-row-container">
                            <span>容器</span>
                            <select value={containerFor(row) ?? ""} data-testid="kubernetes-row-container"
                              aria-label={`${row.name} 的日志、终端和文件用哪个容器`}
                              onChange={(event) => chooseContainer(row, event.target.value)}>
                              {row.containers.map((container) => (
                                <option key={container.name} value={container.name}>
                                  {`${container.name}${container.name === row.defaultContainer ? "（默认）" : ""}${container.running ? "" : "（未运行）"}`}
                                </option>
                              ))}
                            </select>
                          </label>
                        ) : null}
                        {row.kind === "pod" ? (
                          <button type="button" aria-label={`查看 ${row.name} 的最近日志`}
                            data-testid="kubernetes-row-logs" onClick={() => openRow(row, "pod-logs")}>日志</button>
                        ) : null}
                        <button type="button" aria-label={`查看 ${row.name} 的详情`}
                          onClick={() => openRow(row)}>详情</button>
                        {row.kind === "pod" ? (() => {
                          const container = containerFor(row);
                          const stopped = container !== null &&
                            row.containers.find((entry) => entry.name === container)?.running !== true;
                          return (
                            <>
                              <button type="button" aria-label={`打开 ${row.name} 的终端`}
                                data-testid="kubernetes-row-terminal"
                                title={row.phase !== "Running" ? "只有运行中的 Pod 能打开终端"
                                  : stopped ? `容器 ${container} 现在没有在运行，打不开终端`
                                    : `在新窗口里打开这个 Pod${container === null ? "" : ` 的容器 ${container}`} 的 shell（kubectl exec）`}
                                disabled={row.phase !== "Running" || stopped}
                                onClick={() => void openPodTerminal(row)}>终端</button>
                              <button type="button" aria-label={`浏览 ${row.name} 里的文件`}
                                data-testid="kubernetes-row-files"
                                title={row.phase !== "Running" ? "只有运行中的 Pod 能浏览文件"
                                  : stopped ? `容器 ${container} 现在没有在运行，不能浏览文件`
                                    : `浏览 ${container === null ? "Pod 默认容器" : `容器 ${container}`}里的文件（只读）`}
                                disabled={row.phase !== "Running" || stopped || scope === null || activeSnapshot === null}
                                onClick={() => {
                                  if (scope === null || activeSnapshot === null) return;
                                  setPodFiles({
                                    scope,
                                    snapshotHandle: activeSnapshot.snapshotHandle,
                                    rowHandle: row.rowHandle,
                                    podName: `${row.namespace}/${row.name}`,
                                    container,
                                  });
                                }}>文件</button>
                            </>
                          );
                        })() : null}
                        {row.kind === "pod" && onInvestigate !== undefined ? (
                          <button type="button" aria-label={`在命令工作台里排查 ${row.name}`}
                            data-testid="kubernetes-row-investigate"
                            title={row.phase === "Running" ? "在命令工作台里对这个 Pod 运行只读检查" : "只有运行中的 Pod 能在里面运行检查"}
                            disabled={row.phase !== "Running"}
                            onClick={() => onInvestigate("pod", `${row.namespace}/${row.name}`)}>排查</button>
                        ) : null}
                        {/* A crash loop's cause is in the run that ended, not in
                            the one that just started; current logs of a pod
                            restarted a second ago are nearly empty. Last, so the
                            buttons every pod has line up from row to row. */}
                        {row.kind === "pod" && row.restarts > 0 ? (
                          <button type="button" aria-label={`查看 ${row.name} 重启前那次运行的日志`}
                            data-testid="kubernetes-row-previous-logs"
                            title="容器重启前那一次运行留下的日志，常用来找崩溃原因"
                            onClick={() => openRow(row, "pod-previous-logs")}>上次日志</button>
                        ) : null}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {activeSnapshot?.truncated ? (
            <p className="kubernetes-truncated" role="status">
              结果已截断；当前显示 {activeSnapshot.displayed} 条。
            </p>
          ) : null}
          {pageCount > 1 ? (
            <footer className="kubernetes-pagination">
              <button
                type="button"
                disabled={safePage === 0}
                onClick={() => dispatch({ type: "page-selected", page: safePage - 1 })}
              >上一页</button>
              <span>第 {safePage + 1} / {pageCount} 页</span>
              <button
                type="button"
                disabled={safePage + 1 >= pageCount}
                onClick={() => dispatch({ type: "page-selected", page: safePage + 1 })}
              >下一页</button>
            </footer>
          ) : null}
        </section>

        {/* A dialog over the table rather than a column beside it. Details are
            read in bursts — pick a row, look, close — and a permanent column
            was charging the table 40% of its width for the whole session, on a
            page whose rows have eight columns to show. */}
        {selectedRow !== null && (
        <div
          className="kubernetes-detail-backdrop"
          role="presentation"
          onClick={(event) => {
            if (event.target === event.currentTarget) closeDetail();
          }}
        >
        <aside className="kubernetes-detail" role="dialog" aria-modal="true" aria-label="资源详情与 Pod 日志">
          <header>
            {/* It used to say 详情 twice, one under the other. The second line
                now names what is selected, which is the thing worth knowing. */}
            <div>
              <h2>详情</h2>
              {selectedRow === null ? null : <p>{selectedRow.name}</p>}
            </div>
            <button
              type="button"
              className="kubernetes-detail-close"
              aria-label="关闭详情"
              onClick={closeDetail}
            >
              ✕
            </button>
            {selectedRow !== null && activeSnapshot !== null ? (
              <div className="kubernetes-detail-actions">
                <button
                  type="button"
                  disabled={visibleState.detailStatus === "loading"}
                  onClick={() => void loadText(
                    "detail",
                    activeSnapshot.snapshotHandle,
                    selectedRow.rowHandle,
                  )}
                >读取详情</button>
                {selectedRow.kind === "pod" && selectedRow.supportsLogs ? (
                  <button
                    type="button"
                    disabled={visibleState.detailStatus === "loading"}
                    onClick={() => void loadText(
                      "pod-logs",
                      activeSnapshot.snapshotHandle,
                      selectedRow.rowHandle,
                      containerFor(selectedRow),
                    )}
                  >读取最近 Pod 日志</button>
                ) : null}
                {selectedRow.kind === "pod" && selectedRow.supportsLogs && selectedRow.restarts > 0 ? (
                  <button
                    type="button"
                    disabled={visibleState.detailStatus === "loading"}
                    data-testid="kubernetes-detail-previous-logs"
                    onClick={() => void loadText(
                      "pod-previous-logs",
                      activeSnapshot.snapshotHandle,
                      selectedRow.rowHandle,
                      containerFor(selectedRow),
                    )}
                  >读取重启前日志</button>
                ) : null}
                {selectedRow.kind !== "namespace" ? (
                  <button
                    type="button"
                    disabled={exporting}
                    data-testid="kubernetes-export-manifest"
                    title="把这个对象当前的完整清单（YAML）保存到本机文件，只读，不改动集群"
                    onClick={() => void exportManifest(selectedRow)}
                  >{exporting ? "正在导出…" : "导出 YAML…"}</button>
                ) : null}
                {/* Only what this kind of resource can do, and for a node only
                    the direction it is not already in. Anything offered here
                    is still re-checked against the cluster before a plan
                    exists. */}
                {availableKubernetesActions(selectedRow).map((kind) => (
                  <button
                    key={kind}
                    type="button"
                    className="kubernetes-action-button"
                    data-testid={`kubernetes-action-${kind}`}
                    onClick={() => {
                      if (kind === "scale-deployment") {
                        setScaleRow(selectedRow.rowHandle);
                        return;
                      }
                      void openAction(selectedRow, { kind });
                    }}
                  >
                    {kubernetesActionLabel(kind)}
                  </button>
                ))}
              </div>
            ) : null}
          </header>
          {scaleRow !== null && selectedRow !== null && scaleRow === selectedRow.rowHandle ? (
            <form
              className="kubernetes-scale-form"
              onSubmit={(event) => {
                event.preventDefault();
                const replicas = Number(scaleReplicas);
                if (!Number.isInteger(replicas) || replicas < 0 ||
                  replicas > MAX_KUBERNETES_REPLICAS) return;
                setScaleRow(null);
                void openAction(selectedRow, { kind: "scale-deployment", replicas });
              }}
            >
              <label>
                <span>目标副本数</span>
                <input
                  type="number"
                  min={0}
                  max={MAX_KUBERNETES_REPLICAS}
                  step={1}
                  value={scaleReplicas}
                  data-testid="kubernetes-scale-replicas"
                  onChange={(event) => setScaleReplicas(event.currentTarget.value)}
                />
              </label>
              <button type="submit" data-testid="kubernetes-scale-submit">下一步</button>
              <button type="button" onClick={() => setScaleRow(null)}>取消</button>
            </form>
          ) : null}
          {selectedRow === null ? (
            <div className="kubernetes-state">选择资源后查看纯文本详情。</div>
          ) : null}
          {selectedRow !== null ? (
            <div className="kubernetes-selected-summary">
              <strong>{selectedRow.name}</strong>
              <span>{kubernetesRowSubtitle(selectedRow)}</span>
            </div>
          ) : null}
          {selectedRow !== null && exportNotice !== null && exportNotice.scope === scope &&
            exportNotice.rowHandle === selectedRow.rowHandle ? (
              <TransientNotice source="Kubernetes" message={exportNotice.message ?? ""} severity={(exportNotice.saved ? "status" : "alert") === "alert" ? "error" : "info"}><p
                className={exportNotice.saved ? "kubernetes-export-notice" : "kubernetes-export-notice is-error"}
                role={exportNotice.saved ? "status" : "alert"}
                data-testid="kubernetes-export-notice"
              >{exportNotice.message}</p></TransientNotice>
            ) : null}
          {visibleState.detailStatus === "loading" ? (
            <div className="kubernetes-state" role="status">正在读取并验证结果…</div>
          ) : null}
          {visibleState.detailStatus === "error" ? (
            <div className="kubernetes-state error" role="alert">{visibleState.error ?? "详情或日志不可用。"}</div>
          ) : null}
          {visibleState.detailStatus === "ready" && visibleState.detail !== null ? (
            <div className="kubernetes-text-result">
              <p data-testid="kubernetes-text-title">{visibleState.detail.contentKind === "pod-logs"
                ? "最近 Pod 日志"
                : visibleState.detail.contentKind === "pod-previous-logs"
                  ? "重启前那次运行的日志"
                  : "资源详情"}{visibleState.detail.contentKind !== "detail" && logsContainer !== null
                  ? ` · 容器 ${logsContainer}` : ""}</p>
              <pre>{visibleState.detail.text}</pre>
              {visibleState.detail.truncated ? (
                <span>文本中有内容过长，已截短显示。</span>
              ) : null}
            </div>
          ) : null}
        </aside>
        </div>
        )}
      </div>

      <footer className="kubernetes-boundary-note">
        只认固定的几类资源；集群返回的文本一律按纯文本展示，不会被当作链接、路径或操作执行。
        改动集群的操作先出计划、再确认、执行后回读核对。
      </footer>
      {podFiles !== null && podFiles.scope === scope && bindingHandle !== null ? (
        <PodFileDialog
          api={api}
          bindingHandle={bindingHandle}
          snapshotHandle={podFiles.snapshotHandle}
          rowHandle={podFiles.rowHandle}
          podName={podFiles.podName}
          container={podFiles.container}
          onClose={() => setPodFiles(null)}
        />
      ) : null}
      {isCurrentAction(renderedAction) && actionState.request !== null && (
        <KubernetesActionDialog
          resourceName={actionState.request.resourceName}
          actionLabel={actionState.request.actionLabel}
          plan={actionState.plan}
          receipt={actionState.receipt}
          busy={actionState.busy}
          error={actionState.error}
          onConfirm={() => void runAction()}
          onClose={closeAction}
        />
      )}
    </section>
  );
}
