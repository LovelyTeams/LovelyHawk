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
  type DisposalReportSnapshot,
  type DisposalReportExportFormat,
  type DisposalReportPreviewFormat,
  isDisposalReportContent,
  isDisposalReportExportResult,
  isDisposalReportSnapshot,
} from "../shared/disposal-report-contract";
import {
  disposalReportCopyText,
  disposalReportExportFailure,
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
  fixedReport?: DisposalReportSnapshot | null;
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
  fixedReport = null,
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
    void (fixedReport === null ? api.generateDisposalReport(currentScope) : Promise.resolve(fixedReport)).then((result) => {
      if (generation !== lifecycleRef.current || scopeRef.current !== currentScope ||
        latestReportRequest.current !== requestId) return;
      if (!isDisposalReportSnapshot(result)) {
        dispatch({ type: "report-failed", scope: currentScope, request: requestId, error: "报告快照格式异常，没有采用。" });
        return;
      }
      dispatch({ type: "report-loaded", scope: currentScope, request: requestId, report: result });
      setNotice(fixedReport !== null ? "已汇总所查看的案件快照和此主机的处置记录。此报告使用固定快照，后续记录不会自动加入。" : result.incidentIncluded ? "已汇总当前主机的处置记录和当前案件。" : "已汇总当前主机的处置记录。");
    }).catch(() => {
      if (generation !== lifecycleRef.current || scopeRef.current !== currentScope ||
        latestReportRequest.current !== requestId) return;
      dispatch({ type: "report-failed", scope: currentScope, request: requestId, error: "无法生成当前目标的处置报告。" });
    });
  }, [api, bindingHandle, fixedReport, refreshVersion, state.scope]);

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
        dispatch({ type: "content-failed", scope: currentScope, request: requestId, handle: reportHandle, error: "报告内容格式异常，没有采用。" });
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
      await (writeClipboard ?? ((value) => window.lovelyhawk.writeClipboard(value)))(text);
      if (generation !== lifecycleRef.current) return;
      setNotice(`${disposalReportPreviewLabel(state.content.format)}已复制。`);
    } catch {
      if (generation !== lifecycleRef.current) return;
      setNotice("报告复制失败，或内容太大无法复制。");
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
        ? `已导出 ${result.operationCount} 项处置操作到 ${result.fileName}。`
        : "已取消导出，没有写入文件。"
      );
    } catch (reason: unknown) {
      if (generation !== lifecycleRef.current || scopeRef.current !== currentScope ||
        reportHandleRef.current !== reportHandle) return;
      setNotice(disposalReportExportFailure(reason));
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
            {fixedReport === null ? <button type="button" disabled={bindingHandle === null || state.reportStatus === "loading" || exporting} onClick={() => setRefreshVersion((version) => version + 1)}>{state.reportStatus === "loading" ? "生成中…" : "重新生成"}</button> : null}
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
          <div className="disposal-report-empty" role="status">正在汇总这台主机的处置记录并生成报告…</div>
        ) : state.reportStatus === "error" ? (
          <div className="disposal-report-empty error" role="alert">报告生成失败。连接还在时，可以点“重新生成”再试。</div>
        ) : state.report !== null ? (
          <div className="disposal-report-body">
            <div className="disposal-report-summary-grid">
              {disposalReportSummaryCards(state.report.summary).map(([label, value]) => (
                <article key={label}><span>{label}</span><strong>{value}</strong></article>
              ))}
            </div>
            <div className="disposal-report-meta">
              <span>生成时间 {state.report.generatedAt}</span>
              <span>报告数据 SHA-256 {state.report.snapshotSha256}</span>
              <span>报告暂不包含检测结果</span>
            </div>
            {state.report.incidentIncluded ? <div className="disposal-report-evidence">报告包含所选案件的 {state.report.evidenceCount} 条证据。来源、采集时间与完整性摘要可在 Markdown / HTML 中查看。</div> : null}
            {state.report.empty ? <div className="disposal-report-empty-report">这台主机还没有记录在案的处置操作；仍然生成了一份空报告，可以照常保存。</div> : null}
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
