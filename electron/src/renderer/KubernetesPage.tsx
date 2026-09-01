import { useEffect, useReducer, useRef, useState } from "react";

import { targetFailureMessage } from "./target-lost";

import {
  KUBERNETES_READ_TABS,
  isKubernetesAvailability,
  isKubernetesListInput,
  isKubernetesSnapshot,
  isKubernetesTextResult,
  type KubernetesContentKind,
  type KubernetesListInput,
  type KubernetesReadApi,
  type KubernetesReadRow,
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
  MAX_KUBERNETES_REPLICAS,
  type KubernetesWriteAction,
  type KubernetesWriteApi,
} from "../shared/kubernetes-write-contract";
import {
  createKubernetesActionState,
  kubernetesActionReducer,
} from "./kubernetes-action-state";
import { KubernetesActionDialog } from "./KubernetesActionDialog";
import { useModalScrim } from "./modal-scrim";
import {
  availableKubernetesActions,
  kubernetesActionLabel,
} from "./kubernetes-action-helpers";
import "./kubernetes-page.css";

interface KubernetesPageProps {
  bindingHandle: string | null;
  api: KubernetesReadApi & KubernetesWriteApi;
  /** Deterministic standalone/SSR fixture; production leaves this unset. */
  initialState?: KubernetesReadState;
}

export function KubernetesPage({ bindingHandle, api, initialState }: KubernetesPageProps) {
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
  const selectedNamespaceName = visibleState.namespaces?.rows.find(
    (row) => row.kind === "namespace" &&
      row.rowHandle === visibleState.selectedNamespace?.rowHandle,
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
        error: "Kubernetes 可用性结果未通过本地边界校验，或 SSH 目标已切换。",
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
    }).catch(() => {
      dispatch({
        type: "namespaces-failed",
        scope,
        request,
        error: "无法读取当前目标的 namespace 快照。",
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
    }).catch(() => {
      dispatch({
        type: "list-failed",
        scope,
        request,
        tab: input.tab,
        context: listContext,
        error: "资源快照不可用，或目标已发生变化。",
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

  if (bindingHandle === null) {
    return (
      <section className="page kubernetes-page">
        <div className="kubernetes-connect-state">
          <span aria-hidden="true">⎈</span>
          <h1>连接目标后调查 Kubernetes</h1>
          <p>连上之后可以看命名空间、Pod、Deployment 与节点；调整副本数、隔离节点这类操作要先确认再执行。</p>
        </div>
      </section>
    );
  }
  const connectedScope = scope ?? "";

  async function loadText(
    kind: KubernetesContentKind,
    snapshotHandle: string,
    rowHandle: string,
  ) {
    if (scope === null || bindingHandle === null) return;
    const request = ++requestRef.current;
    dispatch({ type: "detail-started", scope, request, snapshotHandle, rowHandle });
    try {
      const result = kind === "detail"
        ? await api.getKubernetesResourceDetail(bindingHandle, snapshotHandle, rowHandle)
        : await api.getKubernetesPodLogs(bindingHandle, snapshotHandle, rowHandle);
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
    } catch {
      dispatch({
        type: "detail-failed",
        scope,
        request,
        snapshotHandle,
        rowHandle,
        error: kind === "pod-logs"
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

  // A destructive action must not fire twice from a fast double click, and a
  // `busy` flag in state is set a render too late to stop the second one.
  const actionRef = useRef(false);
  async function openAction(row: KubernetesReadRow, action: KubernetesWriteAction) {
    if (actionRef.current || bindingHandle === null || activeSnapshot === null) return;
    actionRef.current = true;
    const request = actionState.requestId + 1;
    actionDispatch({
      type: "opened",
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
      actionDispatch({ type: "planned", requestId: request, plan });
    } catch (reason: unknown) {
      actionDispatch({
        type: "failed",
        requestId: request,
        message: kubernetesActionFailure(reason),
      });
    } finally {
      actionRef.current = false;
    }
  }

  async function runAction() {
    const plan = actionState.plan;
    if (actionRef.current || bindingHandle === null || plan === null) return;
    actionRef.current = true;
    const request = actionState.requestId;
    actionDispatch({ type: "executing", requestId: request });
    try {
      // Approval and execution stay two calls. Nothing runs until the sidecar
      // has recorded that the operator pressed this button.
      await api.confirmKubernetesWorkloadAction(bindingHandle, plan.planHandle);
      const receipt = await api.executeKubernetesWorkloadAction(bindingHandle, plan.planHandle);
      if (!isKubernetesActionReceipt(receipt)) throw new Error();
      actionDispatch({ type: "executed", requestId: request, receipt });
      // Whatever the read-back said, the list is now out of date.
      setRefreshVersion((version) => version + 1);
    } catch (reason: unknown) {
      actionDispatch({
        type: "failed",
        requestId: request,
        message: kubernetesActionFailure(reason),
      });
    } finally {
      actionRef.current = false;
    }
  }

  function closeAction() {
    const plan = actionState.plan;
    // A plan that was never executed is dropped on the sidecar too, rather
    // than left to expire holding the binding's one dialog slot.
    if (plan !== null && actionState.receipt === null && bindingHandle !== null) {
      void api.cancelKubernetesWorkloadAction(bindingHandle, plan.planHandle).catch(() => {});
    }
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

  const available = visibleState.availability?.apiReachable === true;
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

      {visibleState.notice !== null ? (
        <div className="kubernetes-notice" role="status">{visibleState.notice}</div>
      ) : null}
      {visibleState.error !== null ? (
        <div className="kubernetes-notice error" role="alert">{visibleState.error}</div>
      ) : null}

      <section className="kubernetes-scope" aria-label="Namespace 范围">
        <div>
          <p>命名空间范围</p>
          <strong>{selectedNamespaceName ?? "全部 namespaces"}</strong>
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
          {visibleState.namespaces?.rows.map((row) => row.kind === "namespace" ? (
            <button
              type="button"
              key={row.rowHandle}
              className={row.rowHandle === visibleState.selectedNamespace?.rowHandle
                ? "active"
                : undefined}
              aria-pressed={row.rowHandle === visibleState.selectedNamespace?.rowHandle}
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

      <nav className="kubernetes-tabs" aria-label="Kubernetes 资源类型">
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

      <div className="kubernetes-workbench">
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
            <div className="kubernetes-state error">资源快照不可用。</div>
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
                </tr>
              </thead>
              <tbody>
                {shownRows.map((row) => {
                  const state = kubernetesRowState(row);
                  const attention = kubernetesRowNeedsAttention(row);
                  const selected = row.rowHandle === visibleState.selectedRowHandle;
                  return (
                    <tr
                      key={row.rowHandle}
                      className={[
                        selected ? "is-selected" : "",
                        attention ? "needs-attention" : "",
                      ].filter(Boolean).join(" ") || undefined}
                    >
                      {columns.map((column, index) => (
                        <td
                          key={column.key}
                          className={column.numeric === true ? "is-numeric" : undefined}
                        >
                          {index === 0 ? (
                            <button
                              type="button"
                              className="kubernetes-row-button"
                              aria-pressed={selected}
                              onClick={() => selectRow(row)}
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
                    )}
                  >读取最近 Pod 日志</button>
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
          {visibleState.detailStatus === "loading" ? (
            <div className="kubernetes-state" role="status">正在读取并验证结果…</div>
          ) : null}
          {visibleState.detailStatus === "error" ? (
            <div className="kubernetes-state error">详情或日志不可用。</div>
          ) : null}
          {visibleState.detailStatus === "ready" && visibleState.detail !== null ? (
            <div className="kubernetes-text-result">
              <p>{visibleState.detail.contentKind === "pod-logs" ? "最近 Pod 日志" : "资源详情"}</p>
              <pre>{visibleState.detail.text}</pre>
              {visibleState.detail.truncated ? (
                <span>文本已按敏感信息与 UTF-8 字节安全边界处理。</span>
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
      {actionState.request !== null && (
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
