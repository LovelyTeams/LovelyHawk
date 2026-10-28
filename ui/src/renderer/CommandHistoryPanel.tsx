import { TransientNotice } from "./NotificationCenter";
import {
  forwardRef,
  useCallback,
  useEffect,
  useImperativeHandle,
  useMemo,
  useReducer,
  useRef,
  useState,
} from "react";

import type { SshTargetSummary } from "../shared/ssh-contract";
import {
  type CommandHistoryApi,
  type CommandHistoryMutationKind,
  isCommandHistoryListPage,
  isCommandHistoryMutationCancellation,
  isCommandHistoryMutationProposal,
  isCommandHistoryMutationResult,
  isCommandHistoryRecord,
} from "../shared/command-history-contract";
import {
  commandHistoryCopyText,
  commandHistoryInitialFocus,
  commandRiskLabel,
  commandStatusLabel,
  formatCommandHistoryTimestamp,
  nextCommandHistoryFocus,
} from "./command-history-helpers";
import { commandHistoryReducer, initialCommandHistoryState } from "./command-history-state";
import "./command-history.css";
import { useModalScrim } from "./modal-scrim";
import { planExpiryLabel } from "./plan-expiry";

const PAGE_SIZE = 25;

export interface CommandHistoryTarget {
  bindingHandle: string;
  target: SshTargetSummary;
}

export interface CommandHistoryPanelProps {
  activeTarget: CommandHistoryTarget | null;
  api: CommandHistoryApi;
  onClose?: () => void | Promise<void>;
  returnFocusElement?: HTMLElement | null;
  writeClipboard?: (text: string) => Promise<void>;
  /** Opens the command workbench on the check this record ran. Nothing runs by itself. */
  onRerunCheck?: (recordId: string) => void | Promise<void>;
}

export interface CommandHistoryPanelHandle {
  beforeClose(): Promise<void>;
}

export const CommandHistoryPanel = forwardRef<CommandHistoryPanelHandle, CommandHistoryPanelProps>(function CommandHistoryPanel({
  activeTarget,
  api,
  onClose,
  returnFocusElement,
  writeClipboard,
  onRerunCheck,
}: CommandHistoryPanelProps, ref) {
  useModalScrim();
  const [state, dispatch] = useReducer(commandHistoryReducer, initialCommandHistoryState);
  const [refreshVersion, setRefreshVersion] = useState(0);
  const [busy, setBusy] = useState<"plan" | "confirm" | "cancel" | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const scope = activeTarget?.bindingHandle ?? null;
  const request = useRef(0);
  const panelRef = useRef<HTMLElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const dialogRef = useRef<HTMLElement>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);
  const proposalRef = useRef(state.proposal);
  const proposalBindingRef = useRef<string | null>(null);
  const busyRef = useRef(busy);
  const scopeRef = useRef(scope);
  const lifecycleRef = useRef(0);
  proposalRef.current = state.proposal;
  busyRef.current = busy;
  const targetLabel = useMemo(() => activeTarget === null
    ? null
    : `${activeTarget.target.username}@${activeTarget.target.host}:${activeTarget.target.port}`,
  [activeTarget]);

  const cancelHandleBestEffort = useCallback(async (bindingHandle: string, mutationHandle: string) => {
    try {
      const result = await api.cancelCommandHistoryMutation(bindingHandle, mutationHandle);
      if (!isCommandHistoryMutationCancellation(result)) return;
    } catch {
      // Closing and target changes fail closed: an unconfirmed plan is never executed here.
    }
  }, [api]);

  const beforeClose = useCallback(async () => {
    lifecycleRef.current += 1;
    request.current += 1;
    const proposal = proposalRef.current;
    const bindingHandle = proposalBindingRef.current;
    proposalRef.current = null;
    proposalBindingRef.current = null;
    dispatch({ type: "proposal-closed" });
    if (proposal !== null && bindingHandle !== null && busyRef.current !== "confirm") {
      await cancelHandleBestEffort(bindingHandle, proposal.handle);
    }
  }, [cancelHandleBestEffort]);

  useImperativeHandle(ref, () => ({ beforeClose }), [beforeClose]);

  useEffect(() => {
    const previousScope = scopeRef.current;
    if (previousScope !== scope) {
      lifecycleRef.current += 1;
      request.current += 1;
      const proposal = proposalRef.current;
      const bindingHandle = proposalBindingRef.current ?? previousScope;
      proposalRef.current = null;
      proposalBindingRef.current = null;
      if (proposal !== null && bindingHandle !== null && busyRef.current !== "confirm") {
        void cancelHandleBestEffort(bindingHandle, proposal.handle);
      }
    }
    scopeRef.current = scope;
    dispatch({ type: "scope-changed", scope });
    setBusy(null);
    setNotice(null);
  }, [cancelHandleBestEffort, scope]);

  useEffect(() => () => {
    lifecycleRef.current += 1;
    const proposal = proposalRef.current;
    const bindingHandle = proposalBindingRef.current;
    proposalRef.current = null;
    proposalBindingRef.current = null;
    if (proposal !== null && bindingHandle !== null && busyRef.current !== "confirm") {
      void cancelHandleBestEffort(bindingHandle, proposal.handle);
    }
  }, [cancelHandleBestEffort]);

  useEffect(() => {
    const previousFocus = returnFocusElement ??
      (document.activeElement instanceof HTMLElement ? document.activeElement : null);
    commandHistoryInitialFocus(searchRef.current, panelRef.current)?.focus({ preventScroll: true });
    function keydown(event: KeyboardEvent) {
      if (proposalRef.current !== null) return;
      if (event.key === "Escape") {
        event.preventDefault();
        void onClose?.();
        return;
      }
      if (event.key !== "Tab") return;
      const panel = panelRef.current;
      if (panel === null) return;
      const focusable = Array.from(panel.querySelectorAll<HTMLElement>(
        'button:not([disabled]), input:not([disabled]), [href], [tabindex]:not([tabindex="-1"])',
      ));
      const index = focusable.findIndex((element) => element === document.activeElement);
      const next = nextCommandHistoryFocus(index, focusable.length, event.shiftKey);
      const boundary = index < 0 || (event.shiftKey ? index === 0 : index === focusable.length - 1);
      if (!boundary) return;
      event.preventDefault();
      (next < 0 ? panel : focusable[next])?.focus();
    }
    document.addEventListener("keydown", keydown);
    return () => {
      document.removeEventListener("keydown", keydown);
      if (previousFocus?.isConnected) previousFocus.focus({ preventScroll: true });
    };
  }, [onClose, returnFocusElement]);

  useEffect(() => {
    if (activeTarget === null || state.scope !== activeTarget.bindingHandle) return;
    const currentScope = activeTarget.bindingHandle;
    const generation = lifecycleRef.current;
    const requestId = ++request.current;
    dispatch({ type: "list-started", scope: currentScope, request: requestId });
    const timer = window.setTimeout(() => {
      void api.listCommandHistory(currentScope, state.query, state.offset, PAGE_SIZE).then((result) => {
        if (generation !== lifecycleRef.current || scopeRef.current !== currentScope) return;
        if (!isCommandHistoryListPage(result) || result.offset !== state.offset) {
          dispatch({ type: "list-failed", scope: currentScope, request: requestId, error: "命令历史列表格式异常，没有采用。" });
          return;
        }
        dispatch({ type: "list-loaded", scope: currentScope, request: requestId, page: result });
      }).catch(() => {
        if (generation !== lifecycleRef.current || scopeRef.current !== currentScope) return;
        dispatch({ type: "list-failed", scope: currentScope, request: requestId, error: "无法读取当前目标的命令历史。" });
      });
    }, 120);
    return () => window.clearTimeout(timer);
  }, [activeTarget, api, refreshVersion, state.offset, state.query, state.scope]);

  useEffect(() => {
    if (activeTarget === null || state.scope !== activeTarget.bindingHandle || state.selectedId === null) return;
    const currentScope = activeTarget.bindingHandle;
    const generation = lifecycleRef.current;
    const recordId = state.selectedId;
    const requestId = ++request.current;
    dispatch({ type: "detail-started", scope: currentScope, request: requestId, id: recordId });
    void api.getCommandHistory(currentScope, recordId).then((result) => {
      if (generation !== lifecycleRef.current || scopeRef.current !== currentScope) return;
      if (!isCommandHistoryRecord(result) || result.id !== recordId) {
        dispatch({ type: "detail-failed", scope: currentScope, request: requestId, id: recordId, error: "命令历史正文格式异常，没有采用。" });
        return;
      }
      dispatch({ type: "detail-loaded", scope: currentScope, request: requestId, id: recordId, record: result });
    }).catch(() => {
      if (generation !== lifecycleRef.current || scopeRef.current !== currentScope) return;
      dispatch({ type: "detail-failed", scope: currentScope, request: requestId, id: recordId, error: "无法读取所选命令历史正文。" });
    });
  }, [activeTarget, api, state.scope, state.selectedId]);

  useEffect(() => {
    if (state.proposal === null) return;
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    cancelRef.current?.focus({ preventScroll: true });
    function keydown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        event.preventDefault();
        if (busyRef.current === null) void cancelProposal();
        return;
      }
      if (event.key !== "Tab") return;
      const dialog = dialogRef.current;
      if (dialog === null) return;
      const focusable = Array.from(dialog.querySelectorAll<HTMLElement>('button:not([disabled]), [tabindex]:not([tabindex="-1"])'));
      const index = focusable.findIndex((element) => element === document.activeElement);
      const boundary = index < 0 || (event.shiftKey ? index === 0 : index === focusable.length - 1);
      if (!boundary) return;
      event.preventDefault();
      const next = nextCommandHistoryFocus(index, focusable.length, event.shiftKey);
      (next < 0 ? dialog : focusable[next])?.focus();
    }
    document.addEventListener("keydown", keydown);
    return () => {
      document.removeEventListener("keydown", keydown);
      if (previousFocus?.isConnected) previousFocus.focus({ preventScroll: true });
    };
  }, [state.proposal?.handle]);

  async function copy(field: "command" | "output") {
    if (state.record === null) return;
    try {
      const value = commandHistoryCopyText(state.record, field);
      await (writeClipboard ?? ((text) => window.lovelyhawk.writeClipboard(text)))(value);
      setNotice(field === "command"
        ? "已复制命令纯文本。"
        : state.record.origin === "emergency-catalog" ? "已复制结果摘要。" : "已复制输出纯文本。");
    } catch {
      setNotice("复制失败，或文本太大无法复制。");
    }
  }

  async function requestMutation(kind: CommandHistoryMutationKind) {
    if (activeTarget === null || busy !== null) return;
    const currentScope = activeTarget.bindingHandle;
    const generation = lifecycleRef.current;
    const requestId = ++request.current;
    setBusy("plan");
    dispatch({ type: "proposal-started", scope: currentScope, request: requestId });
    try {
      const result = kind === "remove" && state.selectedId !== null
        ? await api.planCommandHistoryRemove(currentScope, state.selectedId)
        : await api.planCommandHistoryClear(currentScope);
      if (!isCommandHistoryMutationProposal(result) || result.kind !== kind) throw new Error();
      if (generation !== lifecycleRef.current || scopeRef.current !== currentScope) {
        await cancelHandleBestEffort(currentScope, result.handle);
        return;
      }
      proposalRef.current = result;
      proposalBindingRef.current = currentScope;
      dispatch({ type: "proposal-loaded", scope: currentScope, request: requestId, proposal: result });
    } catch {
      if (generation !== lifecycleRef.current || scopeRef.current !== currentScope) return;
      dispatch({ type: "proposal-failed", scope: currentScope, request: requestId, error: "没能准备删除，请稍后再试。" });
    } finally {
      if (generation === lifecycleRef.current) setBusy(null);
    }
  }

  async function confirmProposal() {
    if (activeTarget === null || state.proposal === null || busy !== null) return;
    const proposal = state.proposal;
    const currentScope = activeTarget.bindingHandle;
    const generation = lifecycleRef.current;
    proposalRef.current = null;
    proposalBindingRef.current = null;
    setBusy("confirm");
    try {
      const result = await api.confirmCommandHistoryMutation(currentScope, proposal.handle);
      if (generation !== lifecycleRef.current || scopeRef.current !== currentScope) return;
      if (!isCommandHistoryMutationResult(result) || result.kind !== proposal.kind ||
        result.affectedRecords !== proposal.affectedRecords) throw new Error();
      setNotice(`已永久删除 ${result.affectedRecords} 条命令历史，并核对了保存结果。`);
    } catch {
      if (generation !== lifecycleRef.current || scopeRef.current !== currentScope) return;
      setNotice("没能确认删除结果，已重新读取这台主机的命令历史。");
    } finally {
      if (generation === lifecycleRef.current && scopeRef.current === currentScope) {
        dispatch({ type: "proposal-closed" });
        setBusy(null);
        dispatch({ type: "page-selected", offset: 0 });
        setRefreshVersion((version) => version + 1);
      }
    }
  }

  async function cancelProposal() {
    if (activeTarget === null || state.proposal === null || busy !== null) return;
    const proposal = state.proposal;
    const currentScope = activeTarget.bindingHandle;
    const generation = lifecycleRef.current;
    proposalRef.current = null;
    proposalBindingRef.current = null;
    setBusy("cancel");
    try {
      const result = await api.cancelCommandHistoryMutation(currentScope, proposal.handle);
      if (generation !== lifecycleRef.current || scopeRef.current !== currentScope) return;
      if (!isCommandHistoryMutationCancellation(result)) throw new Error();
      setNotice("已取消，命令历史没有改动。");
    } catch {
      if (generation !== lifecycleRef.current || scopeRef.current !== currentScope) return;
      setNotice("这次确认已失效，没有删除任何记录。");
    } finally {
      if (generation === lifecycleRef.current && scopeRef.current === currentScope) {
        dispatch({ type: "proposal-closed" });
        setBusy(null);
      }
    }
  }

  const proposalOpen = state.proposal !== null;
  return (
    <div className="command-history-backdrop">
      <section ref={panelRef} className="command-history-panel" role="dialog" aria-modal="true" aria-labelledby="command-history-title" tabIndex={-1}>
        <div className="command-history-shell" aria-hidden={proposalOpen ? true : undefined} inert={proposalOpen ? true : undefined}>
          <header className="command-history-heading">
            <div>
              <h1 id="command-history-title">命令历史</h1>
              <span>{targetLabel === null ? "未连接 SSH 目标" : `当前目标 ${targetLabel}`}</span>
            </div>
            <div className="command-history-header-actions">
              <button type="button" disabled={activeTarget === null} onClick={() => setRefreshVersion((version) => version + 1)}>刷新</button>
              <button type="button" disabled={activeTarget === null || (state.page?.total ?? 0) === 0 || busy !== null} className="danger" onClick={() => void requestMutation("clear")}>清空目标历史</button>
              <button type="button" onClick={() => void onClose?.()}>关闭</button>
            </div>
          </header>

          {notice !== null ? <TransientNotice source="命令历史" message={notice ?? ""} severity="info"><div className="command-history-notice" role="status">{notice}</div></TransientNotice> : null}
          {state.error !== null ? <TransientNotice source="命令历史" message={state.error ?? ""} severity="error"><div className="command-history-notice error" role="alert">{state.error}</div></TransientNotice> : null}

          {activeTarget === null ? (
            <div className="command-history-disconnected">请先在连接管理中连接 SSH 目标，再查看这台主机的命令历史。</div>
          ) : (
            <div className="command-history-workbench">
              <aside className="command-history-list-panel">
                <label>
                  <span>搜索</span>
                  <input ref={searchRef} aria-label="搜索命令历史" value={state.query} maxLength={256} placeholder="标题、命令、输出或来源" onChange={(event) => dispatch({ type: "query-changed", query: event.currentTarget.value })} />
                </label>
                <div className="command-history-list" aria-busy={state.listStatus === "loading"}>
                  {state.listStatus === "loading" && state.page === null ? <p>正在读取命令历史…</p> : null}
                  {state.listStatus === "ready" && state.page?.items.length === 0 ? <p>{state.query.trim() === "" ? "当前目标暂无命令历史" : "没有匹配的命令历史"}</p> : null}
                  {state.page?.items.map((item) => (
                    <button type="button" key={item.id} className={item.id === state.selectedId ? "command-history-row active" : "command-history-row"} onClick={() => dispatch({ type: "record-selected", id: item.id })}>
                      <span><strong>{item.title}</strong><time>{formatCommandHistoryTimestamp(item.timestamp)}</time></span>
                      {item.origin === "emergency-catalog" ? (
                        <small className={item.status}>{commandStatusLabel(item.status, item.exitCode)} · {item.source}</small>
                      ) : (
                        <>
                          <small className={`${item.status} ${item.risk}`}>{commandStatusLabel(item.status, item.exitCode)} · {commandRiskLabel(item.risk)}</small>
                          <code>{item.commandPreview}{item.commandTruncated ? "…" : ""}</code>
                        </>
                      )}
                      <p>{item.outputPreview}{item.outputTruncated ? "…" : ""}</p>
                    </button>
                  ))}
                </div>
                <footer>
                  <span>{state.page?.total ?? 0} 条</span>
                  <div>
                    <button type="button" disabled={state.offset === 0 || state.listStatus === "loading"} onClick={() => dispatch({ type: "page-selected", offset: Math.max(0, state.offset - PAGE_SIZE) })}>上一页</button>
                    <button type="button" disabled={state.page?.hasMore !== true || state.listStatus === "loading"} onClick={() => dispatch({ type: "page-selected", offset: state.offset + PAGE_SIZE })}>下一页</button>
                  </div>
                </footer>
              </aside>

              <section className="command-history-detail">
                {state.selectedId === null ? <div className="command-history-detail-state">选择一条记录查看详情。</div> : null}
                {state.detailStatus === "loading" ? <div className="command-history-detail-state" role="status">正在读取完整记录…</div> : null}
                {state.detailStatus === "error" ? <div className="command-history-detail-state error" role="alert">无法读取所选记录。</div> : null}
                {state.detailStatus === "ready" && state.record !== null ? (
                  <>
                    <header>
                      <div>
                        <h2>{state.record.title}</h2>
                        <p>{commandStatusLabel(state.record.status, state.record.exitCode)} · {state.record.source} · {formatCommandHistoryTimestamp(state.record.timestamp)}</p>
                      </div>
                      <div>
                        {state.record.origin === "emergency-catalog" ? (
                          <>
                            {state.record.rerunnable && onRerunCheck !== undefined ? (
                              <button type="button" className="primary" disabled={busy !== null}
                                data-testid="command-history-rerun"
                                onClick={() => { if (state.record !== null) void onRerunCheck(state.record.id); }}>
                                到命令工作台再次运行
                              </button>
                            ) : null}
                            <button type="button" onClick={() => void copy("output")}>复制结果摘要</button>
                          </>
                        ) : (
                          <>
                            <button type="button" onClick={() => void copy("command")}>复制命令</button>
                            <button type="button" onClick={() => void copy("output")}>复制输出</button>
                          </>
                        )}
                        <button type="button" className="danger" disabled={busy !== null} onClick={() => void requestMutation("remove")}>永久删除</button>
                      </div>
                    </header>
                    {state.record.origin === "emergency-catalog" ? (
                      <>
                        <div className={`command-history-status ${state.record.status}`}>
                          {state.record.rerunnable
                            ? "这是命令工作台清单里的一项检查。历史只记下检查名称、时间和结果，不保存命令全文和原始输出；要再看完整结果，点“到命令工作台再次运行”，会选中同一项检查，由你确认后运行。"
                            : "这是命令工作台清单里的一项检查。历史只记下检查名称、时间和结果，不保存命令全文和原始输出。这条是较早的记录，没有记下是哪一项检查；要再看完整结果，请到命令工作台按名称找到它重新运行。"}
                        </div>
                        <article><h3>结果摘要</h3><pre>{state.record.output}</pre></article>
                      </>
                    ) : (
                      <>
                        <div className={`command-history-status ${state.record.status}`}>{commandRiskLabel(state.record.risk)}</div>
                        <article><h3>命令（纯文本）</h3><pre>{state.record.command}</pre></article>
                        <article><h3>{state.record.status === "failed" ? "输出 / 错误文本（纯文本）" : "输出（纯文本）"}</h3><pre>{state.record.output}</pre></article>
                      </>
                    )}
                  </>
                ) : null}
              </section>
            </div>
          )}
        </div>

        {state.proposal !== null ? (
          <div className="command-history-confirm-backdrop">
            <section ref={dialogRef} className="command-history-confirm" role="alertdialog" aria-modal="true" aria-labelledby="command-history-confirm-title" tabIndex={-1}>
              <p>危险操作</p>
              <h2 id="command-history-confirm-title">{state.proposal.kind === "clear" ? "永久清空目标命令历史？" : "永久删除这条命令历史？"}</h2>
              <div>{state.proposal.summary}</div>
              <small>这次确认在 {planExpiryLabel(state.proposal.expiresInSeconds)}后失效，只能使用一次。</small>
              <footer>
                <button ref={cancelRef} type="button" disabled={busy !== null} onClick={() => void cancelProposal()}>取消</button>
                <button type="button" className="danger" disabled={busy !== null} onClick={() => void confirmProposal()}>{busy === "confirm" ? "正在删除并核对…" : "确认永久删除"}</button>
              </footer>
            </section>
          </div>
        ) : null}
      </section>
    </div>
  );
});
