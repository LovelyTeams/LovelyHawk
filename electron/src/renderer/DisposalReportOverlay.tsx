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
  type DisposalReportApi,
  type DisposalReportExportFormat,
  type DisposalReportPreviewFormat,
  isDisposalReportContent,
  isDisposalReportExportResult,
  isDisposalReportSnapshot,
} from "../shared/disposal-report-contract";
import {
  disposalReportCopyText,
  disposalReportPreviewLabel,
  disposalReportSummaryCards,
  nextDisposalReportFocus,
} from "./disposal-report-helpers";
import { disposalReportReducer, initialDisposalReportState } from "./disposal-report-state";
import "./disposal-report.css";
import { useModalScrim } from "./modal-scrim";

export interface DisposalReportTarget {
  bindingHandle: string;
  target: SshTargetSummary;
}

export interface DisposalReportOverlayProps {
  activeTarget: DisposalReportTarget | null;
  api: DisposalReportApi;
  onClose?: () => void | Promise<void>;
  returnFocusElement?: HTMLElement | null;
  writeClipboard?: (text: string) => Promise<void>;
}

export interface DisposalReportOverlayHandle {
  beforeClose(): Promise<void>;
}

export const DisposalReportOverlay = forwardRef<
  DisposalReportOverlayHandle,
  DisposalReportOverlayProps
>(function DisposalReportOverlay({
  activeTarget,
  api,
  onClose,
  returnFocusElement,
  writeClipboard,
}: DisposalReportOverlayProps, ref) {
  useModalScrim();
  const [state, dispatch] = useReducer(disposalReportReducer, initialDisposalReportState);
  const [refreshVersion, setRefreshVersion] = useState(0);
  const [notice, setNotice] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const request = useRef(0);
  const lifecycleRef = useRef(0);
  const latestReportRequest = useRef(0);
  const latestContentRequest = useRef(0);
  const overlayRef = useRef<HTMLElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);
  const bindingHandle = activeTarget?.bindingHandle ?? null;
  const scopeRef = useRef(bindingHandle);
  const reportHandleRef = useRef(state.report?.handle ?? null);
  scopeRef.current = bindingHandle;
  reportHandleRef.current = state.report?.handle ?? null;
  const targetLabel = useMemo(() => activeTarget === null
    ? "未连接 SSH 目标"
    : `${activeTarget.target.username}@${activeTarget.target.host}:${activeTarget.target.port}`,
  [activeTarget]);

  const beforeClose = useCallback(async () => {
    lifecycleRef.current += 1;
    request.current += 1;
  }, []);

  useImperativeHandle(ref, () => ({ beforeClose }), [beforeClose]);

  useEffect(() => {
    dispatch({ type: "scope-changed", scope: bindingHandle });
    setNotice(null);
    setExporting(false);
  }, [bindingHandle]);

  useEffect(() => {
    const previousFocus = returnFocusElement ??
      (document.activeElement instanceof HTMLElement ? document.activeElement : null);
    closeRef.current?.focus({ preventScroll: true });
    function keydown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        event.preventDefault();
        void onClose?.();
        return;
      }
      if (event.key !== "Tab") return;
      const overlay = overlayRef.current;
      if (overlay === null) return;
      const focusable = Array.from(overlay.querySelectorAll<HTMLElement>(
        'button:not([disabled]), [href], [tabindex]:not([tabindex="-1"])',
      ));
      const index = focusable.findIndex((element) => element === document.activeElement);
      const boundary = index < 0 || (event.shiftKey ? index === 0 : index === focusable.length - 1);
      if (!boundary) return;
      event.preventDefault();
      const next = nextDisposalReportFocus(index, focusable.length, event.shiftKey);
      (next < 0 ? overlay : focusable[next])?.focus();
    }
    document.addEventListener("keydown", keydown);
    return () => {
      document.removeEventListener("keydown", keydown);
      if (previousFocus?.isConnected) previousFocus.focus({ preventScroll: true });
    };
  }, [onClose, returnFocusElement]);

  useEffect(() => () => {
    lifecycleRef.current += 1;
    request.current += 1;
    scopeRef.current = null;
    reportHandleRef.current = null;
  }, []);

  useEffect(() => {
    if (bindingHandle === null || state.scope !== bindingHandle) return;
    const currentScope = bindingHandle;
    const generation = lifecycleRef.current;
    const requestId = ++request.current;
    latestReportRequest.current = requestId;
    dispatch({ type: "report-started", scope: currentScope, request: requestId });
    void api.generateDisposalReport(currentScope).then((result) => {
      if (generation !== lifecycleRef.current || scopeRef.current !== currentScope ||
        latestReportRequest.current !== requestId) return;
      if (!isDisposalReportSnapshot(result)) {
        dispatch({ type: "report-failed", scope: currentScope, request: requestId, error: "报告快照未通过本地边界校验。" });
        return;
      }
      dispatch({ type: "report-loaded", scope: currentScope, request: requestId, report: result });
      setNotice("报告快照已从当前目标的审计日志生成；第一阶段未附带 detection 快照。");
    }).catch(() => {
      if (generation !== lifecycleRef.current || scopeRef.current !== currentScope ||
        latestReportRequest.current !== requestId) return;
      dispatch({ type: "report-failed", scope: currentScope, request: requestId, error: "无法生成当前目标的处置报告。" });
    });
  }, [api, bindingHandle, refreshVersion, state.scope]);

  useEffect(() => {
    if (bindingHandle === null || state.scope !== bindingHandle || state.report === null) return;
    const currentScope = bindingHandle;
    const generation = lifecycleRef.current;
    const reportHandle = state.report.handle;
    const format = state.preview;
    const requestId = ++request.current;
    latestContentRequest.current = requestId;
    dispatch({ type: "content-started", scope: currentScope, request: requestId, handle: reportHandle, format });
    void api.getDisposalReportContent(currentScope, reportHandle, format).then((result) => {
      if (generation !== lifecycleRef.current || scopeRef.current !== currentScope ||
        reportHandleRef.current !== reportHandle ||
        latestContentRequest.current !== requestId) return;
      if (!isDisposalReportContent(result) || result.format !== format) {
        dispatch({ type: "content-failed", scope: currentScope, request: requestId, handle: reportHandle, error: "报告内容未通过本地边界校验。" });
        return;
      }
      dispatch({ type: "content-loaded", scope: currentScope, request: requestId, handle: reportHandle, content: result });
    }).catch(() => {
      if (generation !== lifecycleRef.current || scopeRef.current !== currentScope ||
        reportHandleRef.current !== reportHandle ||
        latestContentRequest.current !== requestId) return;
      dispatch({ type: "content-failed", scope: currentScope, request: requestId, handle: reportHandle, error: "无法读取报告纯文本。" });
    });
  }, [api, bindingHandle, state.preview, state.report, state.scope]);

  async function copy() {
    if (state.content === null) return;
    const generation = lifecycleRef.current;
    try {
      const text = disposalReportCopyText(state.content);
      await (writeClipboard ?? ((value) => window.lovelyres.writeClipboard(value)))(text);
      if (generation !== lifecycleRef.current) return;
      setNotice(`${disposalReportPreviewLabel(state.content.format)}已复制。`);
    } catch {
      if (generation !== lifecycleRef.current) return;
      setNotice("报告复制失败或内容超过本地预算。");
    }
  }

  async function exportReport(format: DisposalReportExportFormat) {
    if (bindingHandle === null || state.report === null || exporting) return;
    const currentScope = bindingHandle;
    const reportHandle = state.report.handle;
    const generation = lifecycleRef.current;
    setExporting(true);
    try {
      const result = await api.exportDisposalReport(currentScope, reportHandle, format);
      if (generation !== lifecycleRef.current || scopeRef.current !== currentScope ||
        reportHandleRef.current !== reportHandle) return;
      if (!isDisposalReportExportResult(result)) throw new Error();
      setNotice(result.saved
        ? `已导出 ${result.operationCount} 项审计操作到 ${result.fileName}。`
        : "已取消处置报告导出。"
      );
    } catch {
      if (generation !== lifecycleRef.current || scopeRef.current !== currentScope ||
        reportHandleRef.current !== reportHandle) return;
      setNotice("处置报告导出失败。");
    } finally {
      if (generation === lifecycleRef.current && scopeRef.current === currentScope &&
        reportHandleRef.current === reportHandle) setExporting(false);
    }
  }

  return (
    <div className="disposal-report-backdrop">
      <section ref={overlayRef} className="disposal-report-overlay" role="dialog" aria-modal="true" aria-labelledby="disposal-report-title" tabIndex={-1}>
        <header className="disposal-report-heading">
          <div>
            <h1 id="disposal-report-title">处置交付报告</h1>
            <span>{targetLabel}</span>
          </div>
          <div>
            <button type="button" disabled={bindingHandle === null || state.reportStatus === "loading" || exporting} onClick={() => setRefreshVersion((version) => version + 1)}>{state.reportStatus === "loading" ? "生成中…" : "刷新快照"}</button>
            <button type="button" disabled={state.content === null} onClick={() => void copy()}>复制当前纯文本</button>
            <button type="button" disabled={state.report === null || exporting} onClick={() => void exportReport("markdown")}>保存 MD</button>
            <button type="button" disabled={state.report === null || exporting} onClick={() => void exportReport("html")}>保存 HTML</button>
            <button ref={closeRef} type="button" data-testid="close-disposal-report" onClick={onClose}>关闭</button>
          </div>
        </header>

        {notice !== null ? <div className="disposal-report-notice" role="status">{notice}</div> : null}
        {state.error !== null ? <div className="disposal-report-notice error" role="alert">{state.error}</div> : null}

        {bindingHandle === null ? (
          <div className="disposal-report-empty">请先建立 SSH 连接，再生成处置报告。</div>
        ) : state.reportStatus === "loading" && state.report === null ? (
          <div className="disposal-report-empty" role="status">正在汇总当前目标的审计日志并生成不可变报告快照…</div>
        ) : state.reportStatus === "error" ? (
          <div className="disposal-report-empty error" role="alert">报告生成失败。可在连接仍有效时重试。</div>
        ) : state.report !== null ? (
          <div className="disposal-report-body">
            <div className="disposal-report-summary-grid">
              {disposalReportSummaryCards(state.report.summary).map(([label, value]) => (
                <article key={label}><span>{label}</span><strong>{value}</strong></article>
              ))}
            </div>
            <div className="disposal-report-meta">
              <span>生成时间 {state.report.generatedAt}</span>
              <span>快照 SHA-256 {state.report.snapshotSha256}</span>
              <span>检测项：暂未包含</span>
            </div>
            {state.report.empty ? <div className="disposal-report-empty-report">当前目标没有已审计处置操作；仍已生成可验证的空报告快照。</div> : null}
            <nav aria-label="报告预览格式">
              {(["summary", "markdown", "html"] as const).map((format) => (
                <button type="button" key={format} aria-pressed={state.preview === format} className={state.preview === format ? "active" : ""} onClick={() => dispatch({ type: "preview-selected", preview: format })}>{disposalReportPreviewLabel(format)}</button>
              ))}
              <span>所有格式均按纯文本显示，不会渲染 HTML。</span>
            </nav>
            <section className="disposal-report-preview" aria-busy={state.contentStatus === "loading"}>
              {state.contentStatus === "loading" ? <p>正在读取报告…</p> : null}
              {state.contentStatus === "error" ? <p className="error">报告文本读取失败。</p> : null}
              {state.contentStatus === "ready" && state.content !== null ? <pre>{state.content.content}</pre> : null}
            </section>
          </div>
        ) : (
          <div className="disposal-report-empty">尚无可预览报告。</div>
        )}
      </section>
    </div>
  );
});
