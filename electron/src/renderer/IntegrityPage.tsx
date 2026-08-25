import { useEffect, useReducer, useRef, useState } from "react";

import {
  isIntegrityBaselineList,
  isIntegrityComparisonCancellation,
  isIntegrityComparisonPoll,
  isIntegrityComparisonStarted,
  isIntegrityPresetCatalog,
  type IntegrityApi,
} from "../shared/integrity-contract";
import {
  cancelIntegrityLifecycle,
  formatIntegrityTime,
  integrityKindLabel,
  integrityOperationIsActive,
  integritySeverityLabel,
  type IntegrityViewStage,
} from "./integrity-helpers";
import {
  createIntegrityState,
  integrityReducer,
  type IntegrityState,
} from "./integrity-state";
import "./integrity.css";

interface IntegrityPageProps {
  bindingHandle: string | null;
  api: IntegrityApi;
  /** Deterministic standalone/SSR fixture; production leaves this unset. */
  initialState?: IntegrityState;
}

interface IntegrityLifecycle {
  bindingHandle: string;
  operationHandle: string;
  stage: IntegrityViewStage;
}

interface IntegrityStartRequest {
  bindingHandle: string;
  baselineHandle: string;
  request: number;
}

const POLL_LIMIT = 8;
const POLL_DELAY_MS = 200;

export function IntegrityPage({ bindingHandle, api, initialState }: IntegrityPageProps) {
  const [state, dispatch] = useReducer(
    integrityReducer,
    initialState ?? createIntegrityState(),
  );
  const [refreshVersion, setRefreshVersion] = useState(0);
  const [pollVersion, setPollVersion] = useState(0);
  const requestRef = useRef(0);
  const mountedRef = useRef(true);
  const currentBindingRef = useRef(bindingHandle);
  const lifecycleRef = useRef<IntegrityLifecycle | null>(null);
  const activeStartRef = useRef<IntegrityStartRequest | null>(null);
  const scope = bindingHandle;
  const visibleState = state.scope === scope ? state : createIntegrityState(scope);
  currentBindingRef.current = bindingHandle;

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  useEffect(() => {
    dispatch({ type: "scope-changed", scope });
  }, [scope]);

  useEffect(() => {
    return () => {
      const lifecycle = lifecycleRef.current;
      if (lifecycle?.bindingHandle !== bindingHandle) return;
      void cancelIntegrityLifecycle(
        api,
        lifecycle.bindingHandle,
        lifecycle.operationHandle,
        lifecycle.stage,
      ).catch(() => {
        // Rust close_binding and operation TTL remain the authoritative cleanup boundary.
      });
      lifecycleRef.current = null;
    };
  }, [api, bindingHandle]);

  useEffect(() => {
    if (scope === null) return;
    dispatch({ type: "catalog-started", scope });
    void api.getIntegrityPresets().then((result) => {
      if (!isIntegrityPresetCatalog(result)) throw new Error();
      if (!mountedRef.current || currentBindingRef.current !== scope) return;
      dispatch({ type: "catalog-loaded", scope, catalog: result });
    }).catch(() => {
      if (!mountedRef.current || currentBindingRef.current !== scope) return;
      dispatch({
        type: "catalog-failed",
        scope,
        error: "完整性目录未通过本地边界校验。",
      });
    });
  }, [api, scope]);

  useEffect(() => {
    if (scope === null || bindingHandle === null) return;
    const request = ++requestRef.current;
    dispatch({ type: "list-started", scope, request });
    void api.listIntegrityBaselines(bindingHandle).then((result) => {
      if (!isIntegrityBaselineList(result)) throw new Error();
      if (!mountedRef.current || currentBindingRef.current !== bindingHandle) return;
      dispatch({ type: "list-loaded", scope, request, list: result });
    }).catch(() => {
      if (!mountedRef.current || currentBindingRef.current !== bindingHandle) return;
      dispatch({
        type: "list-failed",
        scope,
        request,
        error: "无法读取当前绑定的完整性基线。",
      });
    });
  }, [api, bindingHandle, refreshVersion, scope]);

  useEffect(() => {
    const operationHandle = visibleState.operationHandle;
    const operationBaselineHandle = visibleState.operationBaselineHandle;
    if (scope === null || bindingHandle === null || operationHandle === null ||
      operationBaselineHandle === null || visibleState.operationStage !== "running") return;
    const afterEvent = visibleState.eventCursor;
    const request = ++requestRef.current;
    const timer = window.setTimeout(() => {
      dispatch({ type: "poll-started", scope, operationHandle, request, afterEvent });
      void api.pollIntegrityComparison(
        bindingHandle,
        operationHandle,
        afterEvent,
        POLL_LIMIT,
      ).then((result) => {
        if (!isIntegrityComparisonPoll(result)) throw new Error();
        if (!mountedRef.current || currentBindingRef.current !== bindingHandle) return;
        if (result.operationHandle !== operationHandle ||
          result.baselineHandle !== operationBaselineHandle ||
          result.nextEventCursor < afterEvent ||
          result.events.some((event) => event.sequence <= afterEvent)) throw new Error();
        if (result.stage !== "running") lifecycleRef.current = null;
        dispatch({
          type: "poll-loaded",
          scope,
          operationHandle,
          request,
          afterEvent,
          poll: result,
        });
        if (result.stage === "running") setPollVersion((version) => version + 1);
      }).catch(() => {
        if (!mountedRef.current || currentBindingRef.current !== bindingHandle) return;
        void api.cancelIntegrityComparison(bindingHandle, operationHandle).catch(() => {});
        lifecycleRef.current = null;
        dispatch({
          type: "poll-failed",
          scope,
          operationHandle,
          request,
          afterEvent,
          error: "完整性比较轮询未通过本地边界校验。",
        });
      });
    }, POLL_DELAY_MS);
    return () => window.clearTimeout(timer);
  }, [
    api,
    bindingHandle,
    pollVersion,
    scope,
    visibleState.eventCursor,
    visibleState.operationHandle,
    visibleState.operationStage,
  ]);

  function startComparison() {
    if (scope === null || bindingHandle === null ||
      visibleState.selectedBaselineHandle === null ||
      integrityOperationIsActive(visibleState.operationStage)) return;
    const baselineHandle = visibleState.selectedBaselineHandle;
    const request = ++requestRef.current;
    activeStartRef.current = { bindingHandle, baselineHandle, request };
    dispatch({ type: "comparison-start-requested", scope, request, baselineHandle });
    void api.startIntegrityComparison(bindingHandle, baselineHandle).then((result) => {
      if (!isIntegrityComparisonStarted(result)) throw new Error();
      const activeStart = activeStartRef.current;
      if (!mountedRef.current || currentBindingRef.current !== bindingHandle || activeStart === null ||
        activeStart.bindingHandle !== bindingHandle || activeStart.baselineHandle !== baselineHandle ||
        activeStart.request !== request) {
        void api.cancelIntegrityComparison(bindingHandle, result.operationHandle).catch(() => {});
        return;
      }
      if (result.baselineHandle !== baselineHandle) {
        void api.cancelIntegrityComparison(bindingHandle, result.operationHandle).catch(() => {});
        throw new Error();
      }
      activeStartRef.current = null;
      lifecycleRef.current = {
        bindingHandle,
        operationHandle: result.operationHandle,
        stage: "running",
      };
      dispatch({ type: "comparison-started", scope, request, baselineHandle, started: result });
    }).catch(() => {
      const activeStart = activeStartRef.current;
      if (!mountedRef.current || currentBindingRef.current !== bindingHandle || activeStart === null ||
        activeStart.bindingHandle !== bindingHandle || activeStart.baselineHandle !== baselineHandle ||
        activeStart.request !== request) return;
      activeStartRef.current = null;
      dispatch({
        type: "comparison-start-failed",
        scope,
        request,
        baselineHandle,
        error: "无法启动完整性比较。",
      });
    });
  }

  function cancelComparison() {
    const operationHandle = visibleState.operationHandle;
    if (scope === null || bindingHandle === null || operationHandle === null ||
      visibleState.operationStage !== "running") return;
    dispatch({ type: "cancel-started", scope, operationHandle });
    if (lifecycleRef.current?.operationHandle === operationHandle) {
      lifecycleRef.current.stage = "cancelling";
    }
    void api.cancelIntegrityComparison(bindingHandle, operationHandle).then((result) => {
      if (!isIntegrityComparisonCancellation(result)) throw new Error();
      if (!mountedRef.current || currentBindingRef.current !== bindingHandle) return;
      lifecycleRef.current = null;
      dispatch({ type: "cancelled", scope, operationHandle });
    }).catch(() => {
      if (!mountedRef.current || currentBindingRef.current !== bindingHandle) return;
      if (lifecycleRef.current?.operationHandle === operationHandle) {
        lifecycleRef.current.stage = "running";
      }
      dispatch({
        type: "cancel-failed",
        scope,
        operationHandle,
        error: "取消完整性比较失败。",
      });
    });
  }

  if (bindingHandle === null) {
    return (
      <main className="integrity-page integrity-connect-state">
        <span aria-hidden="true">◇</span>
        <h1>连接目标后检查文件完整性</h1>
        <p>连接目标后可比对文件完整性基线。</p>
      </main>
    );
  }

  const active = integrityOperationIsActive(visibleState.operationStage);
  const comparison = visibleState.comparison;

  return (
    <main className="integrity-page">
      <div className="integrity-background">
        <header className="integrity-heading">
          <div>
            <p>只读</p>
            <h1>文件完整性</h1>
          </div>
          <div className="integrity-heading-actions">
            <button type="button" disabled={active} onClick={() => setRefreshVersion((v) => v + 1)}>
              刷新基线
            </button>
            <button
              type="button"
              className="primary"
              disabled={active || visibleState.selectedBaselineHandle === null}
              onClick={startComparison}
            >
              开始只读比较
            </button>
            {visibleState.operationStage === "running" && (
              <button type="button" onClick={cancelComparison}>取消比较</button>
            )}
          </div>
        </header>

        <p className="integrity-boundary-note">
          Phase 0 仅列出并比较已有基线；不创建基线、不隔离文件，也不接受自定义路径或命令。
        </p>

        {visibleState.error !== null && (
          <p className="integrity-notice error" role="alert">{visibleState.error}</p>
        )}

        <section className="integrity-presets" aria-labelledby="integrity-catalog-title">
          <header>
            <div>
              <p>内置目录</p>
              <h2 id="integrity-catalog-title">受控检查目录</h2>
            </div>
          </header>
          {visibleState.catalogStatus === "loading" && (
            <p className="integrity-state">正在读取固定目录…</p>
          )}
          {visibleState.catalogStatus === "ready" && visibleState.catalog !== null && (
            <div className="integrity-preset-grid">
              {visibleState.catalog.presets.map((preset) => (
                <div key={preset.id}>
                  <span>{preset.label}</span>
                  <code>{preset.path}</code>
                </div>
              ))}
            </div>
          )}
        </section>

        <div className="integrity-workbench">
          <section className="integrity-baselines" aria-labelledby="integrity-baselines-title">
            <header>
              <div>
                <p>基线快照</p>
                <h2 id="integrity-baselines-title">已有基线</h2>
              </div>
            </header>
            {visibleState.listStatus === "loading" && (
              <p className="integrity-state">正在读取基线…</p>
            )}
            {visibleState.listStatus === "error" && (
              <p className="integrity-state error">基线列表不可用</p>
            )}
            {visibleState.listStatus === "ready" && visibleState.baselineList?.items.length === 0 && (
              <p className="integrity-state">当前绑定尚无可比较的已有基线。</p>
            )}
            <div className="integrity-baseline-list">
              {visibleState.baselineList?.items.map((baseline) => (
                <button
                  type="button"
                  key={baseline.baselineHandle}
                  className={baseline.baselineHandle === visibleState.selectedBaselineHandle ? "active" : undefined}
                  disabled={active}
                  onClick={() => dispatch({
                    type: "baseline-selected",
                    scope: bindingHandle,
                    handle: baseline.baselineHandle,
                  })}
                >
                  <span>
                    <time>{formatIntegrityTime(baseline.createdAt)}</time>
                    <strong>{baseline.fileCount} 文件</strong>
                  </span>
                  <small>{baseline.paths.join(" · ")}</small>
                  {(baseline.pathsTruncated || baseline.textProjected) && (
                    <small>路径已截断或部分遮蔽。</small>
                  )}
                </button>
              ))}
            </div>
            {visibleState.baselineList?.truncated && (
              <p className="integrity-truncated">基线列表已按安全上限截断。</p>
            )}
          </section>

          <section className="integrity-comparison" aria-labelledby="integrity-comparison-title">
            <header>
              <div>
                <p>比对结果</p>
                <h2 id="integrity-comparison-title">比较结果</h2>
              </div>
            </header>
            {(visibleState.operationStage === "starting" || visibleState.operationStage === "running") && (
              <p className="integrity-state">比较进行中，可安全取消…</p>
            )}
            {visibleState.operationStage === "cancelling" && (
              <p className="integrity-state">正在取消并回收操作能力…</p>
            )}
            {visibleState.operationStage === "cancelled" && (
              <p className="integrity-state">比较已取消。</p>
            )}
            {comparison === null && visibleState.operationStage === "idle" && (
              <p className="integrity-state">选择已有基线后开始只读比较。</p>
            )}
            {comparison !== null && (
              <>
                <div className="integrity-stats">
                  <div className="added"><span>新增</span><strong>{comparison.added}</strong></div>
                  <div className="modified"><span>修改</span><strong>{comparison.modified}</strong></div>
                  <div className="removed"><span>移除</span><strong>{comparison.removed}</strong></div>
                  <div><span>展示</span><strong>{comparison.displayed}</strong></div>
                </div>
                {(comparison.truncated || comparison.textProjected || visibleState.eventsTruncated) && (
                  <p className="integrity-truncated">
                    远端结果已按上限截断，敏感内容已遮蔽。
                  </p>
                )}
                <div className="integrity-findings">
                  {comparison.entries.map((finding, index) => (
                    <article
                      className={`integrity-finding ${finding.kind}`}
                      key={`${finding.kind}-${index}`}
                    >
                      <div>
                        <span className={`integrity-severity ${finding.severity}`}>
                          {integritySeverityLabel(finding.severity)}
                        </span>
                        <span>{integrityKindLabel(finding.kind)}</span>
                        <code>{finding.path}</code>
                      </div>
                      {(finding.pathProjected || finding.pathRedacted || finding.pathTruncated) && (
                        <small className="integrity-no-action">已遮蔽</small>
                      )}
                    </article>
                  ))}
                </div>
              </>
            )}
          </section>
        </div>
      </div>
    </main>
  );
}
