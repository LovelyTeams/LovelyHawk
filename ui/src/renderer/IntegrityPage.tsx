import { TransientNotice } from "./NotificationCenter";
import { useEffect, useReducer, useRef, useState } from "react";

import type { EmergencyCommandApi, EmergencyCommandPathOffer } from "../shared/emergency-command-contract";
import type { FileEvidenceApi } from "../shared/file-evidence-contract";
import {
  isIntegrityBaselineList,
  isIntegrityComparisonCancellation,
  isIntegrityComparisonPoll,
  isIntegrityComparisonStarted,
  isIntegrityCreationCancellation,
  isIntegrityCreationPoll,
  isIntegrityCreationStarted,
  isIntegrityCreationRequest,
  isIntegrityPresetCatalog,
  type IntegrityApi,
  type IntegrityPresetId,
} from "../shared/integrity-contract";
import { DialogHost } from "./DialogHost";
import { EmergencyPathDialog, EmergencyPathProperties } from "./EmergencyPathDialog";
import { EmergencyPathMenu } from "./EmergencyPathMenu";
import { useEmergencyPathActions } from "./emergency-path-actions";
import { errorText } from "./error-text";
import { FileEvidenceDialog } from "./FileEvidenceDialog";
import { useConfirmDialog } from "./use-confirm-dialog";
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
  /** Findings use the command workbench's file actions, so its API comes too. */
  api: IntegrityApi & EmergencyCommandApi & FileEvidenceApi;
  /** Deterministic standalone/SSR fixture; production leaves this unset. */
  initialState?: IntegrityState;
}

/** A baseline being recorded on one target. */
interface IntegrityCreation {
  bindingHandle: string;
  operationHandle: string;
  startedAt: number;
  cancelling: boolean;
}

const CREATION_POLL_MS = 500;

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
  const confirm = useConfirmDialog();
  const pathActions = useEmergencyPathActions(api, bindingHandle);
  const [evidence, setEvidence] = useState<{
    offer: EmergencyCommandPathOffer;
    binding: string;
    returnFocus: HTMLElement | null;
  } | null>(null);
  // Which preset locations a new baseline records; null until the operator
  // changes the catalogue's own defaults.
  const [chosenPresets, setChosenPresets] = useState<readonly IntegrityPresetId[] | null>(null);
  const [creation, setCreation] = useState<IntegrityCreation | null>(null);
  const [creationTick, setCreationTick] = useState(0);
  const [creationNotice, setCreationNotice] = useState<{ bindingHandle: string; ok: boolean; text: string } | null>(null);
  const creationStartingRef = useRef(false);
  const creationRef = useRef<IntegrityCreation | null>(null);
  creationRef.current = creation;

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  // A creation belongs to the target it runs on: switching or leaving the page stops it.
  useEffect(() => {
    setEvidence(null);
    return () => {
      const running = creationRef.current;
      if (running?.bindingHandle === bindingHandle) {
        void api.cancelIntegrityBaselineCreation(running.bindingHandle, running.operationHandle).catch(() => {});
      }
      setCreation(null);
      setCreationNotice(null);
    };
  }, [api, bindingHandle]);

  useEffect(() => {
    if (creation === null || creation.bindingHandle !== bindingHandle) return;
    const { bindingHandle: binding, operationHandle } = creation;
    const timer = window.setTimeout(() => {
      void api.pollIntegrityBaselineCreation(binding, operationHandle).then((result) => {
        if (!isIntegrityCreationPoll(result) || result.operationHandle !== operationHandle) throw new Error();
        if (!mountedRef.current || currentBindingRef.current !== binding) return;
        if (result.stage === "running") {
          setCreationTick((tick) => tick + 1);
          return;
        }
        setCreation(null);
        if (result.stage === "completed") {
          setCreationNotice({
            bindingHandle: binding,
            ok: true,
            text: `基线已建立：记录了 ${result.fileCount ?? 0} 个文件（${result.pathCount ?? 0} 个位置）。它在下面列表的最上面。`,
          });
          setRefreshVersion((version) => version + 1);
        } else {
          setCreationNotice({
            bindingHandle: binding,
            ok: result.stage === "cancelled",
            text: result.stage === "cancelled"
              ? "已取消新建基线，列表里没有增加。"
              : "新建基线没有完成：可能没有权限读取所选目录，或目标机缺少 sha256sum。原有基线不受影响。",
          });
        }
      }).catch(() => {
        if (!mountedRef.current || currentBindingRef.current !== binding) return;
        setCreation(null);
        setCreationNotice({
          bindingHandle: binding,
          ok: false,
          text: "读不到新建基线的进度；请刷新基线列表，看看是否已经建好。",
        });
      });
    }, CREATION_POLL_MS);
    return () => window.clearTimeout(timer);
  }, [api, bindingHandle, creation, creationTick]);

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
        error: "完整性目录格式异常，没有采用。",
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
        error: "无法读取当前目标的完整性基线。",
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
          error: "完整性比较轮询格式异常，没有采用。",
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

  async function startCreation(presetIds: readonly IntegrityPresetId[]) {
    if (bindingHandle === null || creation !== null || creationStartingRef.current ||
      !isIntegrityCreationRequest(presetIds)) return;
    const binding = bindingHandle;
    const locations = (visibleState.catalog?.presets ?? [])
      .filter((preset) => presetIds.includes(preset.id))
      .map((preset) => preset.path)
      .join("、");
    creationStartingRef.current = true;
    try {
      const confirmed = await confirm.ask(
        "新建完整性基线？",
        `会读取 ${locations} 里的每个文件并记下它的哈希，清单写在目标机的 /tmp/.lovelyres_fim 下；被记录的文件不会被改动。` +
          "目录很大时可能要几分钟，期间可以取消。之后拿这份基线比较，就能看出哪些文件新增、改动或消失了。",
        "新建基线",
      );
      if (!confirmed || !mountedRef.current || currentBindingRef.current !== binding) return;
      const started = await api.startIntegrityBaselineCreation(binding, presetIds);
      if (!isIntegrityCreationStarted(started)) throw new Error();
      if (!mountedRef.current || currentBindingRef.current !== binding) {
        void api.cancelIntegrityBaselineCreation(binding, started.operationHandle).catch(() => {});
        return;
      }
      setCreationNotice(null);
      setCreation({ bindingHandle: binding, operationHandle: started.operationHandle, startedAt: Date.now(), cancelling: false });
    } catch (reason) {
      if (!mountedRef.current || currentBindingRef.current !== binding) return;
      setCreationNotice({
        bindingHandle: binding,
        ok: false,
        text: errorText(reason, "无法开始新建基线；这个目标上可能已经有一个正在建立。"),
      });
    } finally {
      creationStartingRef.current = false;
    }
  }

  function cancelCreation() {
    if (creation === null || creation.cancelling) return;
    const current = creation;
    setCreation({ ...current, cancelling: true });
    void api.cancelIntegrityBaselineCreation(current.bindingHandle, current.operationHandle).then((result) => {
      if (!isIntegrityCreationCancellation(result)) throw new Error();
      // The next poll reports what happened: cancelled, or finished first.
    }).catch(() => {
      setCreation((now) => now?.operationHandle === current.operationHandle ? { ...now, cancelling: false } : now);
    });
  }

  function openFindingMenu(
    event: { clientX: number; clientY: number; preventDefault: () => void },
    offer: EmergencyCommandPathOffer,
  ) {
    pathActions.openMenu(event, offer);
  }

  if (bindingHandle === null) {
    return (
      <main className="integrity-page integrity-connect-state">
        <span aria-hidden="true">◇</span>
        <h1>连接目标后检查文件完整性</h1>
        <p>连接目标后可以新建基线，并拿它比较文件有没有被新增、改动或删除。</p>
      </main>
    );
  }

  const active = integrityOperationIsActive(visibleState.operationStage);
  const comparison = visibleState.comparison;
  const presets = visibleState.catalog?.presets ?? [];
  const chosen = chosenPresets ?? presets.filter((preset) => preset.defaultSelected).map((preset) => preset.id);
  const canCreate = chosen.length > 0;
  const creating = creation !== null && creation.bindingHandle === bindingHandle;
  const notice = creationNotice !== null && creationNotice.bindingHandle === bindingHandle ? creationNotice : null;
  const elapsed = creating ? Math.max(0, Math.floor((Date.now() - creation.startedAt) / 1000)) : 0;
  const acting = pathActions.state;

  return (
    <main className="integrity-page">
      <div className="integrity-background">
        <header className="integrity-heading">
          <div>
            <p>发现篡改</p>
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
              开始比较
            </button>
            {visibleState.operationStage === "running" && (
              <button type="button" onClick={cancelComparison}>取消比较</button>
            )}
          </div>
        </header>

        <p className="integrity-boundary-note">
          比较只读取文件，不改动它们。对比较中新增或改动的文件，可以查看属性、下载留证、去掉执行权限或隔离：
          每一步都先给出计划，确认后才执行，完成后可以撤销。
        </p>

        {visibleState.error !== null && (
          <TransientNotice source="文件完整性" message={visibleState.error ?? ""} severity="error"><p className="integrity-notice error" role="alert">{visibleState.error}</p></TransientNotice>
        )}

        <section className="integrity-presets" aria-labelledby="integrity-catalog-title">
          <header>
            <div>
              <p>新建基线</p>
              <h2 id="integrity-catalog-title">记录哪些位置</h2>
            </div>
            <div className="integrity-heading-actions">
              {creating ? (
                <button type="button" disabled={creation.cancelling} onClick={cancelCreation}
                  data-testid="integrity-create-cancel">
                  {creation.cancelling ? "正在取消…" : "取消新建"}
                </button>
              ) : (
                <button type="button" className="primary" data-testid="integrity-create"
                  disabled={!canCreate || visibleState.catalogStatus !== "ready"}
                  onClick={() => void startCreation(chosen)}>
                  新建基线
                </button>
              )}
            </div>
          </header>
          {visibleState.catalogStatus === "loading" && (
            <p className="integrity-state">正在读取可选位置…</p>
          )}
          {visibleState.catalogStatus === "ready" && (
            <fieldset className="integrity-preset-grid" disabled={creating}>
              <legend>先建一份基线，之后才能比较。勾选要记录的位置：</legend>
              {presets.map((preset) => (
                <label key={preset.id} data-preset-path={preset.path}>
                  <input
                    type="checkbox"
                    checked={chosen.includes(preset.id)}
                    onChange={(event) => {
                      const on = event.currentTarget.checked;
                      setChosenPresets(on ? [...chosen, preset.id] : chosen.filter((id) => id !== preset.id));
                    }}
                  />
                  {/* Every label already starts with its path; showing both repeated it. */}
                  <span>{preset.label}</span>
                </label>
              ))}
            </fieldset>
          )}
          {creating && (
            <p className="integrity-state" role="status" data-testid="integrity-create-running">
              正在记录所选位置里的文件…（已用 {elapsed} 秒）
            </p>
          )}
          {notice !== null && (
            <TransientNotice source="文件完整性" message={notice.text ?? ""} severity={(notice.ok ? "status" : "alert") === "alert" ? "error" : "info"}><p className={notice.ok ? "integrity-notice" : "integrity-notice error"} role={notice.ok ? "status" : "alert"}
              data-testid="integrity-create-notice">
              {notice.text}
            </p></TransientNotice>
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
              <p className="integrity-state">当前目标还没有基线。先在上面勾选位置，新建一份。</p>
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
                    <small>
                      {baseline.pathsTruncated ? "路径过多已截断。" : "路径里的控制字符已替换成可见符号。"}
                    </small>
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
              <p className="integrity-state">选一份基线，再点“开始比较”。</p>
            )}
            {comparison !== null && (
              <>
                <div className="integrity-stats">
                  <div className="added"><span>新增</span><strong>{comparison.added}</strong></div>
                  <div className="modified"><span>修改</span><strong>{comparison.modified}</strong></div>
                  <div className="removed"><span>移除</span><strong>{comparison.removed}</strong></div>
                  <div><span>展示</span><strong>{comparison.displayed}</strong></div>
                </div>
                {/* Truncating a list, cleaning control characters out of a
                    path, and replacing a path that contained this tool's own
                    connection secret are three different things. Saying
                    "sensitive content was hidden" for all of them told an
                    operator something had been kept from them when usually
                    nothing had — and in a tool for reading evidence, that is
                    the direction that makes people stop looking. */}
                {(comparison.truncated || visibleState.eventsTruncated) && (
                  <p className="integrity-truncated">
                    结果已按上限截断，看到的不是全部。
                  </p>
                )}
                {comparison.textProjected && (
                  <p className="integrity-truncated">
                    路径里的控制字符已替换成可见符号，文字本身没有删改。
                  </p>
                )}
                <div className="integrity-findings">
                  {comparison.entries.map((finding, index) => {
                    const offer = finding.pathHandle === null ? null
                      : { pathHandle: finding.pathHandle, line: index, path: finding.path };
                    return (
                    <article
                      className={`integrity-finding ${finding.kind}`}
                      key={`${finding.kind}-${index}`}
                      data-path-handle={finding.pathHandle ?? undefined}
                      onContextMenu={offer === null ? undefined : (event) => openFindingMenu(event, offer)}
                    >
                      <div>
                        <span className={`integrity-severity ${finding.severity}`}>
                          {integritySeverityLabel(finding.severity)}
                        </span>
                        <span>{integrityKindLabel(finding.kind)}</span>
                        <code>{finding.path}</code>
                        {offer !== null && (
                          <button type="button" className="integrity-finding-action"
                            aria-label={`文件操作：${finding.path}`} disabled={acting !== null}
                            onClick={(event) => {
                              const box = event.currentTarget.getBoundingClientRect();
                              openFindingMenu({ clientX: box.left, clientY: box.bottom, preventDefault: () => undefined }, offer);
                            }}>
                            文件操作
                          </button>
                        )}
                      </div>
                      {finding.pathRedacted ? (
                        <small className="integrity-no-action">这条路径含本机连接口令，已整条替换</small>
                      ) : (finding.pathProjected || finding.pathTruncated) && (
                        <small className="integrity-no-action">
                          {finding.pathTruncated ? "路径过长已截断" : "控制字符已替换成可见符号"}
                        </small>
                      )}
                    </article>
                    );
                  })}
                </div>
              </>
            )}
          </section>
        </div>
      </div>
      {pathActions.menu !== null && <EmergencyPathMenu
        position={pathActions.menu.position}
        offer={pathActions.menu.offer}
        busy={acting !== null}
        onAction={(action) => {
          const { offer } = pathActions.menu ?? { offer: null };
          if (offer !== null && action === "evidence") {
            const returnFocus = document.querySelector<HTMLElement>(`[data-path-handle="${CSS.escape(offer.pathHandle)}"] button`) ??
              (document.activeElement instanceof HTMLElement ? document.activeElement : null);
            pathActions.dismissMenu();
            setEvidence({ offer, binding: bindingHandle, returnFocus });
          } else if (offer !== null && action !== "evidence") void pathActions.start(action, offer);
        }}
        onDismiss={pathActions.dismissMenu} />}
      {evidence !== null && evidence.binding === bindingHandle ? <FileEvidenceDialog
        key={`${evidence.binding}:${evidence.offer.pathHandle}`} api={api} binding={evidence.binding}
        offer={evidence.offer} returnFocus={evidence.returnFocus} onClose={() => setEvidence(null)} /> : null}
      {acting !== null && (acting.action === null ? <EmergencyPathProperties
        path={acting.offer.path}
        detail={acting.detail}
        error={acting.error}
        onClose={pathActions.close} /> : <EmergencyPathDialog
        path={acting.offer.path}
        action={acting.action}
        detail={acting.detail}
        plan={acting.plan}
        receipt={acting.receipt}
        undo={acting.undo}
        undoSpent={acting.undoSpent}
        busy={acting.busy}
        error={acting.error}
        onConfirm={() => void pathActions.confirm()}
        onUndo={() => void pathActions.undo()}
        onClose={pathActions.close} />)}
      {confirm.dialog !== null ? <DialogHost dialog={confirm.dialog} onResolve={confirm.resolve} /> : null}
    </main>
  );
}
