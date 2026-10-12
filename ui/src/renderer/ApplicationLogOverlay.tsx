import {
  forwardRef,
  useCallback,
  useEffect,
  useImperativeHandle,
  useReducer,
  useRef,
  useState,
} from "react";

import {
  type ApplicationLogApi,
  type ApplicationLogFilter,
  type ApplicationLogLevel,
  type ApplicationLogFileState,
  type ApplicationLogSnapshot,
  isApplicationLogClearResult,
  isApplicationLogExportResult,
  isApplicationLogFilter,
  isApplicationLogLevelResult,
  isApplicationLogPreview,
  isApplicationLogSnapshot,
} from "../shared/application-log-contract";
import {
  applicationLogEscapeIntent,
  applicationLogCopyText,
  applicationLogLevelLabel,
  deactivateApplicationLogOverlay,
  formatApplicationLogTimestamp,
  nextApplicationLogFocus,
  restoreApplicationLogFocus,
} from "./application-log-helpers";
import { applicationLogReducer, initialApplicationLogState } from "./application-log-state";
import "./application-log.css";
import { useModalScrim } from "./modal-scrim";

const FOCUSABLE_SELECTOR = [
  "button:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  '[tabindex]:not([tabindex="-1"])',
].join(",");

export interface ApplicationLogOverlayProps {
  api: ApplicationLogApi;
  onClose?: () => void;
  onCopied?: () => void;
  returnFocusElement?: HTMLElement | null;
  writeClipboard?: (text: string) => Promise<void>;
  initialSnapshot?: ApplicationLogSnapshot;
}

export interface ApplicationLogOverlayHandle {
  beforeClose(): void;
}

type BusyOperation = "level" | "clear" | "copy" | "export" | null;

/** Where the log is kept, as the operator needs to know it: what survives a restart. */
export function applicationLogFileNote(state: ApplicationLogFileState | null): string {
  if (state === "writing") {
    return "日志同时写入程序旁的 data/logs/lovelyhawk.log（每个约 2 MB，连同较早的一共保留 3 个），程序重启后仍可查看。" +
      "这里只显示本次运行最近的 500 条；“清空内存缓冲”只清这里，不动日志文件和之前导出的文件。";
  }
  if (state === "failed") {
    return "日志文件写入失败，之后的日志只保存在本次运行的内存中（最多 500 条）。请检查程序旁的 data/logs 目录是否可写；" +
      "需要留存时请用“导出 .log”。";
  }
  return "日志只保存在本次运行的内存中（最多 500 条）；需要留存时请用“导出 .log”。“清空内存缓冲”不会影响之前导出的文件。";
}

export const ApplicationLogOverlay = forwardRef<
  ApplicationLogOverlayHandle,
  ApplicationLogOverlayProps
>(function ApplicationLogOverlay({
  api,
  onClose,
  onCopied,
  returnFocusElement,
  writeClipboard,
  initialSnapshot,
}: ApplicationLogOverlayProps, ref) {
  useModalScrim();
  const [state, dispatch] = useReducer(applicationLogReducer, {
    ...initialApplicationLogState,
    status: initialSnapshot === undefined ? "idle" : "ready",
    snapshot: initialSnapshot ?? null,
  });
  const [refreshVersion, setRefreshVersion] = useState(0);
  const [busy, setBusy] = useState<BusyOperation>(null);
  const [notice, setNotice] = useState<{ text: string; error: boolean } | null>(null);
  const request = useRef(0);
  const operation = useRef(0);
  const alive = useRef(true);
  const backdropRef = useRef<HTMLDivElement>(null);
  const overlayRef = useRef<HTMLElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const filterRef = useRef(state.filter);
  filterRef.current = state.filter;

  const beforeClose = useCallback(() => {
    deactivateApplicationLogOverlay(alive, request, operation);
  }, []);

  useImperativeHandle(ref, () => ({ beforeClose }), [beforeClose]);

  const requestClose = useCallback(() => {
    if (onClose === undefined) return;
    beforeClose();
    onClose();
  }, [beforeClose, onClose]);

  useEffect(() => {
    alive.current = true;
    return () => {
      beforeClose();
    };
  }, [beforeClose]);

  useEffect(() => {
    const previousFocus = returnFocusElement ??
      (document.activeElement instanceof HTMLElement ? document.activeElement : null);
    searchRef.current?.focus({ preventScroll: true });
    function keydown(event: KeyboardEvent) {
      if (applicationLogEscapeIntent(event.key)) {
        event.preventDefault();
        requestClose();
        return;
      }
      if (event.key !== "Tab") return;
      const overlay = overlayRef.current;
      if (overlay === null) return;
      const focusable = Array.from(overlay.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR));
      const index = focusable.findIndex((element) => element === document.activeElement);
      const boundary = index < 0 || (event.shiftKey ? index === 0 : index === focusable.length - 1);
      if (!boundary) return;
      event.preventDefault();
      const next = nextApplicationLogFocus(index, focusable.length, event.shiftKey);
      (next < 0 ? overlay : focusable[next])?.focus({ preventScroll: true });
    }
    document.addEventListener("keydown", keydown);
    return () => {
      document.removeEventListener("keydown", keydown);
      restoreApplicationLogFocus(previousFocus);
    };
  }, [requestClose, returnFocusElement]);

  useEffect(() => {
    const requestId = ++request.current;
    const filter = state.filter;
    dispatch({ type: "load-started", request: requestId });
    const timer = window.setTimeout(() => {
      void api.listApplicationLogs(filter).then((result) => {
        if (!alive.current || request.current !== requestId) return;
        if (!isApplicationLogSnapshot(result)) {
          dispatch({
            type: "load-failed",
            request: requestId,
            error: "日志快照格式异常，没有采用。",
          });
          return;
        }
        dispatch({ type: "load-completed", request: requestId, snapshot: result });
      }).catch(() => {
        if (!alive.current || request.current !== requestId) return;
        dispatch({ type: "load-failed", request: requestId, error: "无法读取应用日志缓冲。" });
      });
    }, 120);
    return () => window.clearTimeout(timer);
  }, [api, refreshVersion, state.filter]);

  function updateFilter(patch: Partial<ApplicationLogFilter>) {
    const filter = { ...state.filter, ...patch };
    if (isApplicationLogFilter(filter)) dispatch({ type: "filter-changed", filter });
  }

  function updateSearch(search: string) {
    updateFilter({ search });
  }

  async function updateCaptureLevel(level: ApplicationLogLevel) {
    const operationId = ++operation.current;
    setBusy("level");
    setNotice(null);
    try {
      const result = await api.setApplicationLogLevel(level);
      if (!alive.current || operation.current !== operationId) return;
      if (!isApplicationLogLevelResult(result) || result.level !== level) throw new Error();
      setNotice({
        text: `采集级别已切换为 ${applicationLogLevelLabel(level)}，只对本次运行有效，不会写入设置。`,
        error: false,
      });
      setRefreshVersion((version) => version + 1);
    } catch {
      if (alive.current && operation.current === operationId) {
        setNotice({ text: "无法更新当前进程的日志采集级别。", error: true });
      }
    } finally {
      if (alive.current && operation.current === operationId) setBusy(null);
    }
  }

  async function clearBuffer() {
    const operationId = ++operation.current;
    request.current += 1;
    setBusy("clear");
    setNotice(null);
    try {
      const result = await api.clearApplicationLogBuffer();
      if (!alive.current || operation.current !== operationId) return;
      if (!isApplicationLogClearResult(result)) throw new Error();
      request.current += 1;
      dispatch({ type: "buffer-cleared", generation: result.generation });
      setNotice({
        text: `已清除 ${result.clearedEntries} 条内存中的日志；日志文件和之前导出的 .log 文件不受影响。`,
        error: false,
      });
      setRefreshVersion((version) => version + 1);
    } catch {
      if (alive.current && operation.current === operationId) {
        setNotice({ text: "无法清空当前进程内存日志缓冲。", error: true });
        setRefreshVersion((version) => version + 1);
      }
    } finally {
      if (alive.current && operation.current === operationId) setBusy(null);
    }
  }

  async function copyPreview() {
    const operationId = ++operation.current;
    const filter = filterRef.current;
    setBusy("copy");
    setNotice(null);
    try {
      const result = await api.getApplicationLogPreview(filter);
      if (!alive.current || operation.current !== operationId) return;
      if (!isApplicationLogPreview(result) || writeClipboard === undefined) throw new Error();
      await writeClipboard(applicationLogCopyText(result));
      if (!alive.current || operation.current !== operationId) return;
      setNotice({
        text: `已复制 ${result.entryCount} 条日志${result.truncated ? "（已截断）" : ""}。`,
        error: false,
      });
      onCopied?.();
    } catch {
      if (alive.current && operation.current === operationId) {
        setNotice({ text: "日志复制失败，或预览内容格式异常。", error: true });
      }
    } finally {
      if (alive.current && operation.current === operationId) setBusy(null);
    }
  }

  async function exportLogs() {
    const operationId = ++operation.current;
    const filter = filterRef.current;
    setBusy("export");
    setNotice(null);
    try {
      const result = await api.exportApplicationLogs(filter);
      if (!alive.current || operation.current !== operationId) return;
      if (!isApplicationLogExportResult(result)) throw new Error();
      setNotice({
        text: result.saved
          ? `已导出 ${result.entryCount} 条日志到 ${result.fileName}${result.truncated ? "（已截断）" : ""}。`
          : "已取消日志导出。",
        error: false,
      });
    } catch {
      if (alive.current && operation.current === operationId) {
        setNotice({ text: "日志导出失败。已有同名文件不会被覆盖。", error: true });
      }
    } finally {
      if (alive.current && operation.current === operationId) setBusy(null);
    }
  }

  const snapshot = state.snapshot;
  return (
    <div
      ref={backdropRef}
      className="application-log-backdrop"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) requestClose();
      }}
    >
      <section
        ref={overlayRef}
        className="application-log-overlay"
        role="dialog"
        aria-modal="true"
        aria-labelledby="application-log-title"
        tabIndex={-1}
      >
        <header className="application-log-heading">
          <div>
            <h1 id="application-log-title">应用诊断日志</h1>
            <span>
              当前进程内存缓冲 {snapshot?.totalBuffered ?? 0}/500 · 最多显示最近 100 条
            </span>
          </div>
          <div className="application-log-actions">
            <button type="button" disabled={busy !== null} onClick={() => setRefreshVersion((version) => version + 1)}>刷新</button>
            <button type="button" disabled={busy !== null} onClick={() => void copyPreview()}>{busy === "copy" ? "复制中…" : "复制筛选结果"}</button>
            <button type="button" disabled={busy !== null} onClick={() => void exportLogs()}>{busy === "export" ? "导出中…" : "导出 .log"}</button>
            <button type="button" className="danger" disabled={busy !== null} onClick={() => void clearBuffer()}>{busy === "clear" ? "清空中…" : "清空内存缓冲"}</button>
            <button type="button" onClick={requestClose}>关闭</button>
          </div>
        </header>

        {notice !== null ? (
          <div className={`application-log-notice${notice.error ? " error" : ""}`} role={notice.error ? "alert" : "status"}>
            {notice.text}
          </div>
        ) : null}

        <div className="application-log-toolbar">
          <label>
            筛选
            <input
              ref={searchRef}
              type="search"
              value={state.filter.search}
              placeholder="模块、消息或字段"
              onChange={(event) => updateSearch(event.currentTarget.value)}
            />
          </label>
          <label>
            显示级别
            <select
              value={state.filter.minimumLevel ?? ""}
              onChange={(event) => updateFilter({
                minimumLevel: event.currentTarget.value === ""
                  ? null
                  : event.currentTarget.value as ApplicationLogLevel,
              })}
            >
              <option value="">全部已捕获</option>
              <option value="debug">DEBUG+</option>
              <option value="info">INFO+</option>
              <option value="warn">WARN+</option>
              <option value="error">ERROR</option>
            </select>
          </label>
          <label>
            当前采集级别
            <select
              aria-label="当前采集级别"
              value={snapshot?.currentLevel ?? "info"}
              disabled={busy !== null}
              onChange={(event) => void updateCaptureLevel(event.currentTarget.value as ApplicationLogLevel)}
            >
              <option value="debug">DEBUG</option>
              <option value="info">INFO</option>
              <option value="warn">WARN</option>
              <option value="error">ERROR</option>
            </select>
          </label>
          <span>
            匹配 {snapshot?.totalMatched ?? 0} · 显示 {snapshot?.displayed ?? 0}
          </span>
        </div>

        <section className="application-log-list" aria-busy={state.status === "loading"} aria-label="应用日志">
          {state.error !== null ? <p className="application-log-state error" role="alert">{state.error}</p> : null}
          {state.status === "loading" && snapshot === null ? <p className="application-log-state" role="status">正在读取日志…</p> : null}
          {snapshot !== null && snapshot.entries.length === 0 ? <p className="application-log-state">当前缓冲中没有符合筛选条件的日志。</p> : null}
          {snapshot?.entries.map((entry) => (
            <article className={`application-log-entry ${entry.level}`} key={entry.sequence}>
              <div>
                <time dateTime={formatApplicationLogTimestamp(entry.timestampUnixMs)}>{formatApplicationLogTimestamp(entry.timestampUnixMs)}</time>
                <strong>{applicationLogLevelLabel(entry.level)}</strong>
                <code>{entry.module}</code>
              </div>
              <pre>{entry.message}</pre>
              {entry.details.length > 0 ? (
                <dl>
                  {entry.details.map((detail, index) => (
                    <div key={`${entry.sequence}-${index}`}>
                      <dt>{detail.name}</dt>
                      <dd>{detail.value}</dd>
                    </div>
                  ))}
                </dl>
              ) : null}
            </article>
          ))}
        </section>

        <footer className={snapshot?.logFile === "failed" ? "application-log-footnote error" : "application-log-footnote"}
          role={snapshot?.logFile === "failed" ? "alert" : undefined}>
          {applicationLogFileNote(snapshot?.logFile ?? null)}
        </footer>
      </section>
    </div>
  );
});
