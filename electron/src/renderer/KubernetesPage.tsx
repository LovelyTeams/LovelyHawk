import { useEffect, useReducer, useRef, useState } from "react";

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
import "./kubernetes-page.css";

interface KubernetesPageProps {
  bindingHandle: string | null;
  api: KubernetesReadApi;
  /** Deterministic standalone/SSR fixture; production leaves this unset. */
  initialState?: KubernetesReadState;
}

export function KubernetesPage({ bindingHandle, api, initialState }: KubernetesPageProps) {
  const [state, dispatch] = useReducer(
    kubernetesReadReducer,
    initialState ?? createKubernetesReadState(),
  );
  const [refreshVersion, setRefreshVersion] = useState(0);
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
  const filteredRows = filteredKubernetesRows(activeSnapshot, visibleState.query);
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
          <p>只读取资源快照、详情与 Pod 日志，不会修改集群。</p>
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

  function selectRow(row: KubernetesReadRow) {
    if (scope === null || activeSnapshot === null) return;
    dispatch({
      type: "row-selected",
      scope,
      snapshotHandle: activeSnapshot.snapshotHandle,
      rowHandle: row.rowHandle,
    });
  }

  const available = visibleState.availability?.apiReachable === true;
  return (
    <section className="page kubernetes-page">
      <header className="page-heading kubernetes-heading">
        <div>
          <p className="eyebrow">只读</p>
          <h1>Kubernetes 调查</h1>
          <p>
            当前目标
            {visibleState.availability?.currentContext
              ? ` · Context ${visibleState.availability.currentContext}`
              : " · 正在确认 context"}
          </p>
        </div>
        <div className="kubernetes-heading-actions">
          <span className={`kubernetes-availability ${available ? "ready" : "pending"}`}>
            {available ? "API 可达" : "API 未就绪"}
          </span>
          <button
            type="button"
            disabled={visibleState.availabilityStatus === "loading"}
            onClick={() => setRefreshVersion((version) => version + 1)}
          >
            {visibleState.availabilityStatus === "loading" ? "刷新中…" : "刷新调查"}
          </button>
        </div>
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

      <div className="kubernetes-workbench">
        <section className="kubernetes-resources" aria-labelledby="kubernetes-resources-title">
          <header>
            <div>
              <p>资源快照</p>
              <h2 id="kubernetes-resources-title">{kubernetesTabLabel(visibleState.activeTab)}</h2>
            </div>
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

          <div className="kubernetes-resource-list" role="list">
            {shownRows.map((row) => (
              <button
                type="button"
                role="listitem"
                key={row.rowHandle}
                className={row.rowHandle === visibleState.selectedRowHandle ? "active" : undefined}
                aria-pressed={row.rowHandle === visibleState.selectedRowHandle}
                onClick={() => selectRow(row)}
              >
                <span>
                  <strong>{kubernetesRowName(row)}</strong>
                  <small>{kubernetesRowSubtitle(row)}</small>
                </span>
                <span className={`kubernetes-kind ${row.kind}`}>{row.kind}</span>
                {row.textTruncated ? <em>字段已截断</em> : null}
              </button>
            ))}
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

        <aside className="kubernetes-detail" aria-label="资源详情与 Pod 日志">
          <header>
            <div><p>详情</p><h2>详情</h2></div>
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
              </div>
            ) : null}
          </header>
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

      <footer className="kubernetes-boundary-note">
        只读取固定的资源类型；远端文本一律按纯文本展示，不会被当作链接、路径或操作执行。
      </footer>
    </section>
  );
}
