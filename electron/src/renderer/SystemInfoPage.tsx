import { useEffect, useMemo, useReducer, useRef, useState } from "react";

import {
  isSystemInfoCatalog,
  isSystemInfoDetail,
  isSystemInfoSummary,
  isSystemInfoTable,
  type SystemInfoApi,
  type SystemInfoTable,
  type SystemInfoTabKey,
} from "../shared/system-info-contract";
import {
  buildSystemInfoSummaryCopy,
  buildSystemInfoTableCopy,
  formatSystemInfoValue,
  groupShellConfigRows,
  groupSystemInfoCatalog,
  nextModalFocusIndex,
  SUMMARY_FIELDS,
} from "./system-info-helpers";
import {
  createSystemInfoState,
  systemInfoReducer,
  systemInfoScope,
  type SystemInfoConnection,
} from "./system-info-state";
import "./system-info.css";
import { useModalScrim } from "./modal-scrim";

interface SystemInfoPageProps {
  connection: SystemInfoConnection | null;
  api: SystemInfoApi;
  writeClipboard?: (text: string) => Promise<void>;
}

const MAXIMUM_ROWS = 500;

export function SystemInfoPage({ connection, api, writeClipboard }: SystemInfoPageProps) {
  const [state, dispatch] = useReducer(systemInfoReducer, undefined, createSystemInfoState);
  const [summaryVersion, setSummaryVersion] = useState(0);
  const [notice, setNotice] = useState<string | null>(null);
  const backgroundRef = useRef<HTMLDivElement>(null);
  const dialogRef = useRef<HTMLElement>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);

  const scope = connection === null ? null : systemInfoScope(connection);
  const bindingHandle = connection?.bindingHandle ?? null;
  const stateIsCurrent = state.scope === scope;
  const catalog = stateIsCurrent ? state.catalog : [];
  const selectedTab = stateIsCurrent ? state.selectedTab : null;
  const table = stateIsCurrent ? state.table : null;
  const detailState = stateIsCurrent ? state.detail : null;
  useModalScrim(detailState !== null);
  const groups = useMemo(() => groupSystemInfoCatalog(catalog), [catalog]);
  // Most tabs have no detail behind any of their rows; the column is only worth
  // its width where at least one row can answer.
  const anyDetail = table?.rows.some((row) => row.detail) ?? false;
  // The summary is a renderer-only tab: it reuses the snapshot the page already
  // loaded, so it never sends a collect request or crosses the tab contract.
  const [summaryTabActive, setSummaryTabActive] = useState(true);

  useEffect(() => {
    if (scope === null || bindingHandle === null) {
      dispatch({ type: "scope-cleared" });
      return;
    }
    const requestScope = scope;
    const requestBinding = bindingHandle;
    dispatch({ type: "bootstrap-started", scope: requestScope });
    setNotice(null);
    void Promise.all([
      api.getSystemInfoCatalog(),
      api.getSystemInfoSummary(requestBinding),
    ]).then(([catalogResult, summaryResult]) => {
      if (!isSystemInfoCatalog(catalogResult) || !isSystemInfoSummary(summaryResult)) {
        dispatch({
          type: "bootstrap-failed",
          scope: requestScope,
          error: "系统信息响应未通过本地边界校验。",
        });
        return;
      }
      dispatch({
        type: "bootstrap-loaded",
        scope: requestScope,
        catalog: catalogResult,
        summary: summaryResult,
      });
    }).catch(() => {
      dispatch({
        type: "bootstrap-failed",
        scope: requestScope,
        error: "无法读取当前目标的系统摘要。",
      });
    });
  }, [api, bindingHandle, scope, summaryVersion]);

  useEffect(() => {
    if (
      scope === null ||
      bindingHandle === null ||
      state.scope !== scope ||
      state.status !== "ready" ||
      state.selectedTab === null ||
      state.tableStatus !== "idle"
    ) return;
    const requestScope = scope;
    const requestBinding = bindingHandle;
    const requestTab = state.selectedTab;
    dispatch({ type: "table-started", scope: requestScope, tab: requestTab });
    void api.collectSystemInfo(requestBinding, requestTab, MAXIMUM_ROWS).then((result) => {
      if (!isSystemInfoTable(result) || result.tab !== requestTab) {
        dispatch({
          type: "table-failed",
          scope: requestScope,
          tab: requestTab,
          error: "系统信息表格未通过本地边界校验。",
        });
        return;
      }
      dispatch({ type: "table-loaded", scope: requestScope, tab: requestTab, table: result });
    }).catch(() => {
      dispatch({
        type: "table-failed",
        scope: requestScope,
        tab: requestTab,
        error: "无法读取当前系统信息标签。",
      });
    });
  }, [api, bindingHandle, scope, state.scope, state.selectedTab, state.status, state.tableStatus]);

  useEffect(() => {
    if (detailState === null) return;
    const previousFocus = document.activeElement instanceof HTMLElement
      ? document.activeElement
      : null;
    closeButtonRef.current?.focus({ preventScroll: true });

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        event.preventDefault();
        dispatch({ type: "detail-closed" });
        return;
      }
      if (event.key !== "Tab") return;
      const dialog = dialogRef.current;
      if (dialog === null) return;
      const focusable = Array.from(dialog.querySelectorAll<HTMLElement>(
        'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
      ));
      const currentIndex = focusable.findIndex((element) => element === document.activeElement);
      const nextIndex = nextModalFocusIndex(currentIndex, focusable.length, event.shiftKey);
      const atBoundary = currentIndex === -1 ||
        (event.shiftKey ? currentIndex === 0 : currentIndex === focusable.length - 1);
      if (atBoundary) {
        event.preventDefault();
        (nextIndex === -1 ? dialog : focusable[nextIndex])?.focus();
      }
    }

    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      if (previousFocus?.isConnected) previousFocus.focus({ preventScroll: true });
    };
  }, [detailState?.snapshotHandle, detailState?.rowId]);

  function selectTab(tab: SystemInfoTabKey) {
    if (scope === null) return;
    setNotice(null);
    setSummaryTabActive(false);
    dispatch({ type: "tab-selected", scope, tab });
  }

  function refreshSummary() {
    setNotice(null);
    setSummaryVersion((version) => version + 1);
  }

  function refreshTable() {
    if (scope === null || selectedTab === null) return;
    setNotice(null);
    // Resetting the tab to idle is what schedules the collect.
    dispatch({ type: "tab-selected", scope, tab: selectedTab });
  }

  function openDetail(rowId: string) {
    if (
      scope === null ||
      bindingHandle === null ||
      selectedTab === null ||
      table === null
    ) return;
    const requestScope = scope;
    const requestTab = selectedTab;
    const snapshotHandle = table.snapshotHandle;
    dispatch({
      type: "detail-started",
      scope: requestScope,
      tab: requestTab,
      snapshotHandle,
      rowId,
    });
    void api.getSystemInfoDetail(bindingHandle, snapshotHandle, rowId).then((result) => {
      if (!isSystemInfoDetail(result) || result.tab !== requestTab || result.rowId !== rowId) {
        dispatch({
          type: "detail-failed",
          scope: requestScope,
          tab: requestTab,
          snapshotHandle,
          rowId,
          error: "详情响应未通过本地边界校验。",
        });
        return;
      }
      dispatch({
        type: "detail-loaded",
        scope: requestScope,
        tab: requestTab,
        snapshotHandle,
        rowId,
        detail: result,
      });
    }).catch(() => {
      dispatch({
        type: "detail-failed",
        scope: requestScope,
        tab: requestTab,
        snapshotHandle,
        rowId,
        error: "当前行没有可用详情，或快照已失效。",
      });
    });
  }

  async function copySummary() {
    if (!stateIsCurrent || state.summary === null) return;
    try {
      const text = buildSystemInfoSummaryCopy(state.summary);
      await (writeClipboard ?? ((value) => window.lovelyres.writeClipboard(value)))(text);
      setNotice("系统摘要已复制为纯文本。");
    } catch {
      setNotice("复制系统摘要失败。");
    }
  }

  async function copyTable() {
    if (table === null) return;
    try {
      const text = buildSystemInfoTableCopy(table);
      await (writeClipboard ?? ((value) => window.lovelyres.writeClipboard(value)))(text);
      setNotice(`已复制 ${table.rows.length} 行纯文本表格。`);
    } catch {
      setNotice("复制表格失败或内容超过本地预算。");
    }
  }

  if (connection === null) {
    return (
      <section className="page system-info-page">
        <div className="system-info-connect-prompt">
          <span aria-hidden="true">⌁</span>
          <h1>连接目标后查看系统信息</h1>
          <p>请先在连接管理中建立 SSH 连接。本页只做只读采集。</p>
        </div>
      </section>
    );
  }

  const visibleStatus = stateIsCurrent ? state.status : "loading";
  return (
    <section className="page system-info-page">
      <div
        ref={backgroundRef}
        className="system-info-background"
        aria-hidden={detailState !== null ? true : undefined}
        inert={detailState !== null ? true : undefined}
      >

        {notice !== null ? <div className="system-info-notice" role="status">{notice}</div> : null}
        {visibleStatus === "error" ? <div className="system-info-notice error" role="alert">{state.error}</div> : null}

        {visibleStatus === "loading" || visibleStatus === "idle" ? (
          <div className="system-info-loading" role="status">正在读取系统摘要…</div>
        ) : null}

        {visibleStatus === "ready" && state.summary !== null ? (
          <>
            <div className="system-info-workbench">
              <nav className="system-info-tabs" aria-label="系统信息标签">
                {groups.map((group) => (
                  <section key={group.key}>
                    <h2>{group.label}</h2>
                    {group.key === "realtime" ? (
                      <button
                        type="button"
                        className={summaryTabActive ? "active" : undefined}
                        aria-pressed={summaryTabActive}
                        onClick={() => { setNotice(null); setSummaryTabActive(true); }}
                      >
                        系统信息
                      </button>
                    ) : null}
                    {group.tabs.map((tab) => (
                      <button
                        type="button"
                        key={tab.key}
                        className={!summaryTabActive && selectedTab === tab.key ? "active" : undefined}
                        aria-pressed={!summaryTabActive && selectedTab === tab.key}
                        onClick={() => selectTab(tab.key)}
                      >
                        {tab.label}
                      </button>
                    ))}
                  </section>
                ))}
              </nav>

              <section className="system-info-table-panel">
                <header>
                  <div>
                    <h2>
                      {summaryTabActive
                        ? "系统信息"
                        : catalog.find((entry) => entry.key === selectedTab)?.label ?? "系统信息"}
                    </h2>
                    <p>
                      {summaryTabActive
                        ? "本次绑定快照采集到的主机概况。"
                        : "最多 500 行；刷新会创建新的绑定快照。"}
                    </p>
                  </div>
                  <div className="system-info-panel-actions">
                    {summaryTabActive ? (
                      <button type="button" disabled={state.summary === null} onClick={() => void copySummary()}>复制摘要</button>
                    ) : (
                      <button type="button" disabled={table === null} onClick={() => void copyTable()}>复制表格</button>
                    )}
                    <button
                      type="button"
                      className="system-info-refresh"
                      disabled={summaryTabActive ? state.status === "loading" : state.tableStatus === "loading"}
                      onClick={summaryTabActive ? refreshSummary : refreshTable}
                    >
                      刷新
                    </button>
                  </div>
                </header>

                {summaryTabActive ? (
                  <section className="system-info-summary" aria-label="系统摘要">
                    {SUMMARY_FIELDS.map((field) => (
                      <article key={field.key}>
                        <span>{field.label}</span>
                        <strong>{formatSystemInfoValue(state.summary?.[field.key] ?? "", field.format) || "—"}</strong>
                      </article>
                    ))}
                  </section>
                ) : (
                  <>

                {state.tableStatus === "loading" || state.tableStatus === "idle" ? (
                  <div className="system-info-table-state" role="status">正在采集当前标签…</div>
                ) : null}
                {state.tableStatus === "error" ? (
                  <div className="system-info-table-state error" role="alert">{state.error}</div>
                ) : null}
                {state.tableStatus === "ready" && table?.rows.length === 0 ? (
                  <div className="system-info-table-state">当前目标没有返回条目。</div>
                ) : null}
                {state.tableStatus === "ready" && table !== null && table.rows.length > 0
                  && table.tab === "shell-configs" ? (
                  <ShellConfigText table={table} />
                ) : null}
                {state.tableStatus === "ready" && table !== null && table.rows.length > 0
                  && table.tab !== "shell-configs" ? (
                  <div className="system-info-table-scroll">
                    <table>
                      <thead><tr>{table.columns.map((column) => <th key={column}>{column}</th>)}<th>级别</th>{anyDetail ? <th>详情</th> : null}</tr></thead>
                      <tbody>
                        {table.rows.map((row) => (
                          <tr key={row.id}>
                            {row.cells.map((cell, index) => <td key={`${row.id}:${index}`}>{cell}</td>)}
                            <td><span className={`system-info-risk ${row.risk}`}>{riskLabel(row.risk)}</span></td>
                            {anyDetail ? (
                              <td>
                                {row.detail
                                  ? <button type="button" onClick={() => openDetail(row.id)}>查看</button>
                                  : null}
                              </td>
                            ) : null}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {table.truncated ? <p className="system-info-truncated">结果已在 500 行边界截断。</p> : null}
                  </div>
                ) : null}
                  </>
                )}
              </section>
            </div>
          </>
        ) : null}
      </div>

      {detailState !== null ? (
        <div className="system-info-detail-backdrop">
          <section
            ref={dialogRef}
            className="system-info-detail-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="system-info-detail-title"
            tabIndex={-1}
          >
            <header>
              <div><p>快照详情</p><h2 id="system-info-detail-title">行详情</h2></div>
              <button ref={closeButtonRef} type="button" onClick={() => dispatch({ type: "detail-closed" })}>关闭</button>
            </header>
            {detailState.status === "loading" ? <div className="system-info-detail-state" role="status">正在读取详情…</div> : null}
            {detailState.status === "error" ? <div className="system-info-detail-state error" role="alert">{detailState.error}</div> : null}
            {detailState.status === "ready" && detailState.detail !== null ? (
              <dl>
                {detailState.detail.fields.map((field, index) => (
                  <div key={`${field.label}:${index}`}><dt>{field.label}</dt><dd>{field.value}</dd></div>
                ))}
              </dl>
            ) : null}
          </section>
        </div>
      ) : null}
    </section>
  );
}

/**
 * Shell configuration, shown as the files it is.
 *
 * The risky lines keep their marking — a `curl … | sh` in a login script is the
 * whole reason to open this tab — but they are marked in place, where the lines
 * around them give them their meaning.
 */
function ShellConfigText({ table }: { table: SystemInfoTable }) {
  const files = useMemo(() => groupShellConfigRows(table), [table]);
  return (
    <div className="system-info-file-scroll">
      {files.map((file) => (
        <article className="system-info-file" key={file.path}>
          <header>
            <strong>{file.path}</strong>
            <span>{file.owner}</span>
            <span>{file.modified}</span>
            <span>{file.lines.length} 行</span>
          </header>
          <pre>
            {file.lines.map((line) => (
              <div className={`system-info-file-line ${line.risk}`} key={`${file.path}:${line.number}`}>
                <span className="system-info-file-number">{line.number}</span>
                <span className="system-info-file-text">{line.text}</span>
              </div>
            ))}
          </pre>
        </article>
      ))}
      {table.truncated ? <p className="system-info-truncated">结果已在 500 行边界截断。</p> : null}
    </div>
  );
}

function riskLabel(risk: "normal" | "warning" | "high"): string {
  switch (risk) {
    case "normal": return "正常";
    case "warning": return "注意";
    case "high": return "高风险";
  }
}
