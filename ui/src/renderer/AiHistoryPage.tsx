import { useEffect, useReducer, useRef, useState } from "react";

import {
  isAiHistoryExportResult,
  isAiHistoryListPage,
  isAiHistoryMutationCancellation,
  isAiHistoryMutationProposal,
  isAiHistoryMutationResult,
  isAiHistoryRecord,
  type AiHistoryApi,
  type AiHistoryExportFormat,
} from "../shared/ai-history-contract";
import {
  aiHistoryCopyText,
  formatAiHistoryTimestamp,
  nextAiHistoryModalFocus,
} from "./ai-history-helpers";
import {
  aiHistoryReducer,
  createAiHistoryState,
} from "./ai-history-state";
import "./ai-history.css";
import { useModalScrim } from "./modal-scrim";
import { planExpiryLabel } from "./plan-expiry";

export interface AiHistoryPageProps {
  api: AiHistoryApi;
  writeClipboard?: (text: string) => Promise<void>;
}

const PAGE_SIZE = 100;

export function AiHistoryPage({ api, writeClipboard }: AiHistoryPageProps) {
  const [state, dispatch] = useReducer(aiHistoryReducer, undefined, createAiHistoryState);
  const [refreshVersion, setRefreshVersion] = useState(0);
  const [busy, setBusy] = useState<"plan" | "confirm" | "cancel" | "export" | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const request = useRef(0);
  const busyRef = useRef(busy);
  const dialogRef = useRef<HTMLElement>(null);
  const cancelButtonRef = useRef<HTMLButtonElement>(null);
  const proposalReturnFocusRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    busyRef.current = busy;
  }, [busy]);

  useEffect(() => {
    const requestId = ++request.current;
    dispatch({ type: "list-started", request: requestId });
    const timer = window.setTimeout(() => {
      void api.listAiHistory(state.query, state.offset, PAGE_SIZE).then((result) => {
        if (!isAiHistoryListPage(result) || result.offset !== state.offset) {
          dispatch({ type: "list-failed", request: requestId, error: "AI 历史列表格式异常，没有采用。" });
          return;
        }
        dispatch({ type: "list-loaded", request: requestId, page: result });
      }).catch(() => {
        dispatch({ type: "list-failed", request: requestId, error: "无法读取本地 AI 历史。" });
      });
    }, 120);
    return () => window.clearTimeout(timer);
  }, [api, refreshVersion, state.offset, state.query]);

  useEffect(() => {
    if (state.selectedId === null) return;
    const selectedId = state.selectedId;
    const requestId = ++request.current;
    dispatch({ type: "detail-started", request: requestId, id: selectedId });
    void api.getAiHistoryRecord(selectedId).then((result) => {
      if (!isAiHistoryRecord(result) || result.id !== selectedId) {
        dispatch({ type: "detail-failed", request: requestId, id: selectedId, error: "AI 历史正文格式异常，没有采用。" });
        return;
      }
      dispatch({ type: "detail-loaded", request: requestId, id: selectedId, record: result });
    }).catch(() => {
      dispatch({ type: "detail-failed", request: requestId, id: selectedId, error: "无法读取这条 AI 历史正文。" });
    });
  }, [api, state.selectedId]);

  useEffect(() => {
    if (state.proposal === null) return;
    const previousFocus = document.activeElement instanceof HTMLElement
      ? document.activeElement
      : null;
    const returnFocus = proposalReturnFocusRef.current ?? previousFocus;
    cancelButtonRef.current?.focus({ preventScroll: true });

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        event.preventDefault();
        if (busyRef.current === null) void cancelProposal();
        return;
      }
      if (event.key !== "Tab") return;
      const dialog = dialogRef.current;
      if (dialog === null) return;
      const focusable = Array.from(dialog.querySelectorAll<HTMLElement>(
        'button:not([disabled]), [href], [tabindex]:not([tabindex="-1"])',
      ));
      const currentIndex = focusable.findIndex((element) => element === document.activeElement);
      const atBoundary = currentIndex === -1 ||
        (event.shiftKey ? currentIndex === 0 : currentIndex === focusable.length - 1);
      if (!atBoundary) return;
      event.preventDefault();
      const next = nextAiHistoryModalFocus(currentIndex, focusable.length, event.shiftKey);
      (next < 0 ? dialog : focusable[next])?.focus();
    }

    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      if (returnFocus?.isConnected) returnFocus.focus({ preventScroll: true });
    };
  }, [state.proposal?.handle]);

  async function requestRemove() {
    if (state.selectedId === null || busy !== null) return;
    proposalReturnFocusRef.current = document.activeElement instanceof HTMLElement
      ? document.activeElement
      : null;
    const requestId = ++request.current;
    setBusy("plan");
    dispatch({ type: "proposal-started", request: requestId });
    try {
      const result = await api.planAiHistoryRemove(state.selectedId);
      if (!isAiHistoryMutationProposal(result) || result.kind !== "remove") throw new Error();
      dispatch({ type: "proposal-loaded", request: requestId, proposal: result });
    } catch {
      dispatch({ type: "proposal-failed", request: requestId, error: "没能准备删除，请稍后再试。" });
    } finally {
      setBusy(null);
    }
  }

  async function requestClear() {
    if (busy !== null || (state.page?.total ?? 0) === 0) return;
    proposalReturnFocusRef.current = document.activeElement instanceof HTMLElement
      ? document.activeElement
      : null;
    const requestId = ++request.current;
    setBusy("plan");
    dispatch({ type: "proposal-started", request: requestId });
    try {
      const result = await api.planAiHistoryClear();
      if (!isAiHistoryMutationProposal(result) || result.kind !== "clear") throw new Error();
      dispatch({ type: "proposal-loaded", request: requestId, proposal: result });
    } catch {
      dispatch({ type: "proposal-failed", request: requestId, error: "没能准备清空，请稍后再试。" });
    } finally {
      setBusy(null);
    }
  }

  async function confirmProposal() {
    const proposal = state.proposal;
    if (proposal === null || busy !== null) return;
    setBusy("confirm");
    try {
      const result = await api.confirmAiHistoryMutation(proposal.handle);
      if (
        !isAiHistoryMutationResult(result) ||
        result.kind !== proposal.kind ||
        result.affectedRecords !== proposal.affectedRecords
      ) throw new Error();
      dispatch({ type: "proposal-closed" });
      setNotice(`已永久删除 ${result.affectedRecords} 条 AI 历史，并核对了保存结果。`);
    } catch {
      dispatch({ type: "proposal-closed" });
      setNotice("没能确认删除结果，已重新读取 AI 历史。");
    } finally {
      setBusy(null);
      dispatch({ type: "page-selected", offset: 0 });
      setRefreshVersion((version) => version + 1);
    }
  }

  async function cancelProposal() {
    const proposal = state.proposal;
    if (proposal === null || busy !== null) return;
    setBusy("cancel");
    try {
      const result = await api.cancelAiHistoryMutation(proposal.handle);
      if (!isAiHistoryMutationCancellation(result)) throw new Error();
      setNotice("已取消，AI 历史没有改动。");
    } catch {
      setNotice("这次确认已失效，没有删除任何记录。");
    } finally {
      dispatch({ type: "proposal-closed" });
      setBusy(null);
    }
  }

  async function copy(field: "prompt" | "result") {
    if (state.record === null) return;
    try {
      const text = aiHistoryCopyText(state.record, field);
      await (writeClipboard ?? ((value) => window.lovelyhawk.writeClipboard(value)))(text);
      setNotice(field === "prompt" ? "已复制提示词纯文本。" : "已复制 AI 回答纯文本。");
    } catch {
      setNotice("复制失败，或正文太大无法复制。");
    }
  }

  async function exportHistory(format: AiHistoryExportFormat) {
    if (busy !== null) return;
    setBusy("export");
    try {
      const result = await api.exportAiHistory(format);
      if (!isAiHistoryExportResult(result)) throw new Error();
      setNotice(result.saved
        ? `已导出 ${result.recordCount} 条记录到 ${result.fileName}。`
        : "已取消 AI 历史导出。");
    } catch {
      setNotice("AI 历史导出失败。");
    } finally {
      setBusy(null);
    }
  }

  const proposalOpen = state.proposal !== null;
  const historyEmpty = state.listStatus === "ready" && state.query.trim() === "" && (state.page?.total ?? 0) === 0;
  useModalScrim(proposalOpen);
  return (
    <section className="page ai-history-page">
      <div className="ai-history-background" aria-hidden={proposalOpen ? true : undefined} inert={proposalOpen ? true : undefined}>
        <header className="page-heading ai-history-heading">
          <div><h1>AI 历史</h1><p>本地 AI 调用记录；服务商、模型、来源、提示词和回答始终按纯文本显示。</p></div>
          <div className="ai-history-actions">
            <button type="button" disabled={busy !== null} onClick={() => setRefreshVersion((value) => value + 1)}>刷新</button>
            {/* An unfiltered list that came back empty has nothing to export;
                a filtered one may still hide records, so it does not decide. */}
            <button type="button" disabled={busy !== null || historyEmpty} onClick={() => void exportHistory("text")}>导出文本</button>
            <button type="button" disabled={busy !== null || historyEmpty} onClick={() => void exportHistory("json")}>导出 JSON</button>
            <button type="button" className="danger" disabled={busy !== null || (state.page?.total ?? 0) === 0} onClick={() => void requestClear()}>清空全部</button>
          </div>
        </header>

        {notice !== null ? <div className="ai-history-notice" role="status">{notice}</div> : null}
        {state.error !== null ? <div className="ai-history-notice error" role="alert">{state.error}</div> : null}

        <div className="ai-history-workbench">
          <aside className="ai-history-list-panel">
            <label className="ai-history-search"><span aria-hidden="true">⌕</span><input aria-label="搜索 AI 历史" value={state.query} maxLength={256} placeholder="搜索服务商、模型、来源或正文" onChange={(event) => dispatch({ type: "query-changed", query: event.currentTarget.value })} /></label>
            <div className="ai-history-list" aria-busy={state.listStatus === "loading"}>
              {state.listStatus === "loading" && state.page === null ? <p className="ai-history-empty">正在读取 AI 历史…</p> : null}
              {state.listStatus === "ready" && state.page?.items.length === 0 ? <p className="ai-history-empty">{state.query.trim() === "" ? "还没有 AI 记录。本机保存的 AI 分析记录会列在这里，可以搜索、复制和导出。" : "没有匹配的 AI 记录，换个服务商、模型或正文里的词试试。"}</p> : null}
              {state.page?.items.map((item) => (
                <button type="button" key={item.id} className={item.id === state.selectedId ? "ai-history-row active" : "ai-history-row"} onClick={() => dispatch({ type: "record-selected", id: item.id })}>
                  <span><strong>{item.provider} / {item.model}</strong><time>{formatAiHistoryTimestamp(item.timestamp)}</time></span>
                  <small>{item.source}</small>
                  <p>问：{item.promptPreview}{item.promptTruncated ? "…" : ""}</p>
                  <p>答：{item.resultPreview}{item.resultTruncated ? "…" : ""}</p>
                </button>
              ))}
            </div>
            <footer>
              <span>{state.page?.total ?? 0} 条</span>
              <div><button type="button" disabled={state.offset === 0 || state.listStatus === "loading"} onClick={() => dispatch({ type: "page-selected", offset: Math.max(0, state.offset - PAGE_SIZE) })}>上一页</button><button type="button" disabled={state.page?.hasMore !== true || state.listStatus === "loading"} onClick={() => dispatch({ type: "page-selected", offset: state.offset + PAGE_SIZE })}>下一页</button></div>
            </footer>
          </aside>

          <section className="ai-history-detail">
            {state.selectedId === null ? <div className="ai-history-detail-state">选择一条记录查看提示词和回答。</div> : null}
            {state.detailStatus === "loading" ? <div className="ai-history-detail-state" role="status">正在读取正文…</div> : null}
            {state.detailStatus === "error" ? <div className="ai-history-detail-state error" role="alert">无法读取所选记录。</div> : null}
            {state.detailStatus === "ready" && state.record !== null ? (
              <>
                <header><div><h2>{state.record.provider} / {state.record.model}</h2><p>{state.record.source} · {formatAiHistoryTimestamp(state.record.timestamp)}</p></div><div><button type="button" onClick={() => void copy("prompt")}>复制提示词</button><button type="button" onClick={() => void copy("result")}>复制回答</button><button type="button" className="danger" disabled={busy !== null} onClick={() => void requestRemove()}>永久删除</button></div></header>
                <div className="ai-history-text"><article><h3>提示词</h3><pre>{state.record.prompt}</pre></article><article><h3>AI 回答（纯文本）</h3><pre>{state.record.result}</pre></article></div>
              </>
            ) : null}
          </section>
        </div>
      </div>

      {state.proposal !== null ? (
        <div className="ai-history-modal-backdrop">
          <section ref={dialogRef} className="ai-history-modal" role="dialog" aria-modal="true" aria-labelledby="ai-history-modal-title" tabIndex={-1}>
            <p>危险操作</p><h2 id="ai-history-modal-title">{state.proposal.kind === "clear" ? "永久清空 AI 历史？" : "永久删除这条记录？"}</h2><div>{state.proposal.summary}</div><small>这次确认在 {planExpiryLabel(state.proposal.expiresInSeconds)}后失效，只能使用一次。</small>
            <footer><button ref={cancelButtonRef} type="button" disabled={busy !== null} onClick={() => void cancelProposal()}>取消</button><button type="button" className="danger" disabled={busy !== null} onClick={() => void confirmProposal()}>{busy === "confirm" ? "验证中…" : "确认永久删除"}</button></footer>
          </section>
        </div>
      ) : null}
    </section>
  );
}
