import { TransientNotice } from "./NotificationCenter";
import { useEffect, useMemo, useReducer, useRef, useState } from "react";

import {
  isSystemInfoCatalog,
  isSystemInfoDetail,
  isSystemInfoSummary,
  isSystemInfoTable,
  type SystemInfoApi,
  type SystemInfoRow,
  type SystemInfoTable,
  type SystemInfoTabKey,
} from "../shared/system-info-contract";
import {
  buildSystemInfoRowCopy,
  buildSystemInfoSummaryCopy,
  buildSystemInfoTableCopy,
  describeSystemInfoValue,
  EMPTY_SYSTEM_INFO_FILTER,
  filterSystemInfoRows,
  systemInfoGauges,
  formatSystemInfoValue,
  groupShellConfigRows,
  groupSystemInfoCatalog,
  isSystemInfoFilterActive,
  nextModalFocusIndex,
  SUMMARY_FIELDS,
  systemInfoRiskCounts,
  type SystemInfoRiskFilter,
  type SystemInfoRowFilter,
} from "./system-info-helpers";
import { SearchIcon } from "./file-icons";
import { rowActionFailureText, useSystemInfoRowActions } from "./system-info-row-actions";
import { SystemInfoRowActionDialog } from "./SystemInfoRowActionDialog";
import { SystemInfoRowMenu, type SystemInfoRowLocalAction } from "./SystemInfoRowMenu";
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
  const tableRequestRef = useRef(0);
  const dialogRef = useRef<HTMLElement>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);

  const scope = connection === null ? null : systemInfoScope(connection);
  const bindingHandle = connection?.bindingHandle ?? null;
  const stateIsCurrent = state.scope === scope;
  const catalog = stateIsCurrent ? state.catalog : [];
  const selectedTab = stateIsCurrent ? state.selectedTab : null;
  const table = stateIsCurrent ? state.table : null;
  const detailState = stateIsCurrent ? state.detail : null;
  // The right-click menu and the dialog it opens. Every request they make
  // names a row of the table currently showing and nothing else.
  const rowActions = useSystemInfoRowActions(api, bindingHandle, table?.snapshotHandle ?? null);
  const overlayOpen = detailState !== null || rowActions.state !== null;
  useModalScrim(detailState !== null);
  const groups = useMemo(() => groupSystemInfoCatalog(catalog), [catalog]);
  // Most tabs have no detail behind any of their rows; the column is only worth
  // its width where at least one row can answer.
  const anyDetail = table?.rows.some((row) => row.detail) ?? false;
  // Each tab keeps what it was narrowed to, so moving between 进程 and 网络
  // does not throw either search away; a different target starts clean, since
  // its rows are a different machine's.
  const [filters, setFilters] = useState<{
    scope: string | null;
    byTab: Partial<Record<SystemInfoTabKey, SystemInfoRowFilter>>;
  }>({ scope: null, byTab: {} });
  const filter = (selectedTab === null || filters.scope !== scope
    ? undefined
    : filters.byTab[selectedTab]) ?? EMPTY_SYSTEM_INFO_FILTER;
  const filterActive = isSystemInfoFilterActive(filter);
  const visibleRows = useMemo(
    () => table === null
      ? []
      : filterSystemInfoRows(table.rows, filter, (index) => shownColumn(table.columns, index)),
    [table, filter],
  );
  const riskCounts = useMemo(() => systemInfoRiskCounts(table?.rows ?? []), [table]);
  const visibleTable = useMemo(
    () => table === null ? null : { ...table, rows: visibleRows },
    [table, visibleRows],
  );
  const searchRef = useRef<HTMLInputElement>(null);

  function updateFilter(patch: Partial<SystemInfoRowFilter>) {
    if (selectedTab === null) return;
    const tab = selectedTab;
    setFilters((current) => {
      const byTab = current.scope === scope ? current.byTab : {};
      return { scope, byTab: { ...byTab, [tab]: { ...(byTab[tab] ?? EMPTY_SYSTEM_INFO_FILTER), ...patch } } };
    });
  }

  function clearFilter() {
    updateFilter(EMPTY_SYSTEM_INFO_FILTER);
    searchRef.current?.focus();
  }
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
          error: "系统信息响应格式异常，没有采用。",
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
      state.tableStatus !== "idle" ||
      // The page opens on the summary, which is already loaded. Collecting the
      // first tab underneath it sent a five-hundred-row process sweep to the
      // target nobody had asked for, and then a second one the moment the
      // operator actually opened that tab — two collects racing, the later
      // snapshot replacing the earlier one under whatever was already on
      // screen.
      summaryTabActive
    ) return;
    const requestScope = scope;
    const requestBinding = bindingHandle;
    const requestTab = state.selectedTab;
    // Monotonic across the page's whole life, so a response can always be told
    // apart from the one that superseded it.
    tableRequestRef.current += 1;
    const request = tableRequestRef.current;
    dispatch({ type: "table-started", scope: requestScope, tab: requestTab, request });
    void api.collectSystemInfo(requestBinding, requestTab, MAXIMUM_ROWS).then((result) => {
      if (!isSystemInfoTable(result) || result.tab !== requestTab) {
        dispatch({
          type: "table-failed",
          scope: requestScope,
          tab: requestTab,
          request,
          error: "系统信息表格格式异常，没有采用。",
        });
        return;
      }
      dispatch({ type: "table-loaded", scope: requestScope, tab: requestTab, request, table: result });
    }).catch(() => {
      dispatch({
        type: "table-failed",
        scope: requestScope,
        tab: requestTab,
        request,
        error: "无法读取当前系统信息标签。",
      });
    });
  }, [
    api, bindingHandle, scope, state.scope, state.selectedTab, state.status, state.tableStatus,
    summaryTabActive,
  ]);

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
          error: "详情响应格式异常，没有采用。",
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
    }).catch((reason: unknown) => {
      dispatch({
        type: "detail-failed",
        scope: requestScope,
        tab: requestTab,
        snapshotHandle,
        rowId,
        // Not "no detail, or a stale snapshot" any more: that `or` handed the
        // guess to the operator, and one of the two is worth retrying while
        // the other never will be.
        error: rowActionFailureText(reason),
      });
    });
  }

  async function copySummary() {
    if (!stateIsCurrent || state.summary === null) return;
    try {
      const text = buildSystemInfoSummaryCopy(state.summary);
      await (writeClipboard ?? ((value) => window.lovelyhawk.writeClipboard(value)))(text);
      setNotice("系统摘要已复制为纯文本。");
    } catch {
      setNotice("复制系统摘要失败。");
    }
  }

  async function copyTable() {
    if (visibleTable === null) return;
    try {
      // What is on screen: a filtered table copies the rows it shows.
      const text = buildSystemInfoTableCopy(visibleTable);
      await (writeClipboard ?? ((value) => window.lovelyhawk.writeClipboard(value)))(text);
      setNotice(filterActive
        ? `已复制筛选后的 ${visibleTable.rows.length} 行（共 ${table?.rows.length ?? 0} 行）纯文本表格。`
        : `已复制 ${visibleTable.rows.length} 行纯文本表格。`);
    } catch {
      setNotice("复制表格失败，或表格太大无法复制。");
    }
  }

  async function copyText(text: string, done: string) {
    try {
      await (writeClipboard ?? ((value) => window.lovelyhawk.writeClipboard(value)))(text);
      setNotice(done);
    } catch {
      setNotice("复制失败，或内容太大无法复制。");
    }
  }

  /** The menu items the window answers by itself, without asking the target. */
  function handleLocalRowAction(action: SystemInfoRowLocalAction) {
    const menu = rowActions.menu;
    rowActions.dismissMenu();
    if (menu === null) return;
    switch (action) {
      case "copy-cell":
        if (menu.cell !== null) void copyText(menu.cell, "已复制这一格。");
        return;
      case "copy-row":
        try {
          void copyText(buildSystemInfoRowCopy(menu.row), "已复制这一行。");
        } catch {
          setNotice("复制失败，或内容太大无法复制。");
        }
        return;
      case "detail":
        openDetail(menu.row.id);
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
        aria-hidden={overlayOpen ? true : undefined}
        inert={overlayOpen ? true : undefined}
      >

        {notice !== null ? <TransientNotice source="系统信息" message={notice ?? ""} severity="info"><div className="system-info-notice" role="status">{notice}</div></TransientNotice> : null}
        {visibleStatus === "error" ? <TransientNotice source="系统信息" message={state.error ?? ""} severity="error"><div className="system-info-notice error" role="alert">{state.error}</div></TransientNotice> : null}

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
                        ? "这次连接时读取到的主机概况。"
                        : "最多 500 行；刷新会重新读取主机上的最新数据。"}
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
                  <>
                  {state.summary === null ? null : (
                    <section className="system-info-gauges" aria-label="资源占用">
                      {systemInfoGauges(state.summary).map((gauge) => (
                        <article key={gauge.id} className={`is-${gauge.tone}`} data-gauge={gauge.id}>
                          <span>{gauge.label}</span>
                          <strong>{gauge.value}</strong>
                          <div className="system-info-gauge-bar" aria-hidden="true">
                            <i style={{ width: gauge.ratio === null ? "0%" : `${Math.round(gauge.ratio * 100)}%` }} />
                          </div>
                          <small>{gauge.detail}</small>
                        </article>
                      ))}
                      <p>颜色只是经验阈值的提示（八成、九成满；每核负载 0.7、1.0），不等于出了问题。</p>
                    </section>
                  )}
                  <section className="system-info-summary" aria-label="系统摘要">
                    {SUMMARY_FIELDS.map((field) => (
                      <article key={field.key}>
                        <span>{field.label}</span>
                        <strong>{describeSystemInfoValue(field.key, formatSystemInfoValue(state.summary?.[field.key] ?? "", field.format)) || "—"}</strong>
                      </article>
                    ))}
                  </section>
                  </>
                ) : (
                  <>

                {state.tableStatus === "loading" || state.tableStatus === "idle" ? (
                  <div className="system-info-table-state" role="status">正在采集当前标签…</div>
                ) : null}
                {state.tableStatus === "error" ? (
                  <TransientNotice source="系统信息" message={state.error ?? ""} severity="error"><div className="system-info-table-state error" role="alert">{state.error}</div></TransientNotice>
                ) : null}
                {/* "Nothing here" and "nobody could look" are opposite
                    findings. An empty firewall means act now; a machine with no
                    iptables means find another way to look. They read as the
                    same sentence until you say which one it is. */}
                {state.tableStatus === "ready" && table?.rows.length === 0 ? (
                  <div className="system-info-table-state">
                    {table.missingTool !== null
                      ? `这台机器上没有 ${table.missingTool}，所以这项查不了——空白不代表没有。`
                      : table.failedTool !== null
                        ? `${table.failedTool} 装着，但这次没答上来（服务可能没起）。空白不代表没有，`
                          + `先把它弄通再看这一页。`
                        : "这台机器上没有这类条目。"}
                  </div>
                ) : null}
                {state.tableStatus === "ready" && table !== null && table.rows.length > 0 ? (
                  <div className="system-info-filter" role="search" aria-label="搜索和筛选这一页">
                    <label className="system-info-filter-search">
                      <SearchIcon />
                      <input
                        ref={searchRef}
                        type="search"
                        value={filter.query}
                        placeholder="搜索这一页，空格分隔多个词"
                        aria-label="搜索这一页"
                        maxLength={200}
                        onChange={(event) => updateFilter({ query: event.target.value })}
                        onKeyDown={(event) => {
                          if (event.key === "Escape" && filter.query !== "") {
                            event.preventDefault();
                            event.stopPropagation();
                            updateFilter({ query: "" });
                          }
                        }}
                      />
                    </label>
                    <label className="system-info-filter-column">
                      <span>在</span>
                      <select
                        value={filter.column === null ? "all" : String(filter.column)}
                        aria-label="搜索哪一列"
                        onChange={(event) => updateFilter({
                          column: event.target.value === "all" ? null : Number(event.target.value),
                        })}
                      >
                        <option value="all">所有列</option>
                        {table.columns.map((column, index) => shownColumn(table.columns, index)
                          ? <option key={column} value={String(index)}>{column}</option>
                          : null)}
                      </select>
                    </label>
                    <div className="system-info-filter-risk" role="group" aria-label="按级别筛选">
                      {RISK_FILTERS.map(({ key, label }) => (
                        <button
                          type="button"
                          key={key}
                          aria-pressed={filter.risk === key}
                          className={filter.risk === key ? "active" : undefined}
                          onClick={() => updateFilter({ risk: key })}
                        >
                          {label}<span>{riskCounts[key]}</span>
                        </button>
                      ))}
                    </div>
                    <span className="system-info-filter-count" aria-live="polite">
                      {filterActive ? `显示 ${visibleRows.length} / 共 ${table.rows.length} 行` : `共 ${table.rows.length} 行`}
                    </span>
                    {filterActive ? (
                      <button type="button" className="system-info-filter-clear" onClick={clearFilter}>清除筛选</button>
                    ) : null}
                  </div>
                ) : null}
                {state.tableStatus === "ready" && table !== null && table.rows.length > 0
                  && visibleRows.length === 0 ? (
                  <div className="system-info-table-state">
                    <p>
                      没有符合条件的行。筛选只在已经读到的 {table.rows.length} 行里找
                      {table.truncated ? `；主机上还有更多没读到的，那些不在其中` : ""}。
                    </p>
                    <button type="button" onClick={clearFilter}>清除筛选</button>
                  </div>
                ) : null}
                {state.tableStatus === "ready" && visibleTable !== null && visibleRows.length > 0
                  && visibleTable.tab === "shell-configs" ? (
                  <ShellConfigText
                    table={visibleTable}
                    selectedRowId={rowActions.menu?.row.id ?? null}
                    onRowContextMenu={rowActions.openMenu}
                  />
                ) : null}
                {state.tableStatus === "ready" && table !== null && visibleRows.length > 0
                  && table.tab !== "shell-configs" ? (
                  <div className="system-info-table-scroll">
                    <table>
                      <thead><tr>{table.columns.map((column, index) => shownColumn(table.columns, index) ? <th key={column}>{column}</th> : null)}<th>级别</th>{anyDetail ? <th>详情</th> : null}</tr></thead>
                      <tbody>
                        {visibleRows.map((row) => (
                          <tr
                            key={row.id}
                            className={rowActions.menu?.row.id === row.id ? "is-selected" : undefined}
                            onContextMenu={(event) => rowActions.openMenu(event, row, null)}
                          >
                            {row.cells.map((cell, index) => !shownColumn(table.columns, index) ? null : (
                              <td
                                key={`${row.id}:${index}`}
                                onContextMenu={(event) => rowActions.openMenu(event, row, cell)}
                              >
                                {cell}
                              </td>
                            ))}
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
                    {table.truncated ? <p className="system-info-truncated">这台机器上不止这些，只显示了前 {MAXIMUM_ROWS} 行；需要完整列表时请在终端中查看。</p> : null}
                  </div>
                ) : null}
                  </>
                )}
              </section>
            </div>
          </>
        ) : null}
      </div>

      {rowActions.menu !== null ? (
        <SystemInfoRowMenu
          position={rowActions.menu.position}
          row={rowActions.menu.row}
          cell={rowActions.menu.cell}
          actions={rowActions.menu.actions}
          error={rowActions.menu.error}
          onLocal={handleLocalRowAction}
          onAction={(action) => void rowActions.choose(action)}
          onDismiss={rowActions.dismissMenu}
        />
      ) : null}

      {rowActions.state !== null ? (
        <SystemInfoRowActionDialog
          state={rowActions.state}
          onConfirm={() => void rowActions.confirm()}
          onCopyOutput={(text) => void copyText(text, "已复制输出。")}
          onClose={rowActions.close}
        />
      ) : null}

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
            {detailState.status === "error" ? <TransientNotice source="系统信息" message={detailState.error ?? ""} severity="error"><div className="system-info-detail-state error" role="alert">{detailState.error}</div></TransientNotice> : null}
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
function ShellConfigText({
  table,
  selectedRowId,
  onRowContextMenu,
}: {
  table: SystemInfoTable;
  selectedRowId: string | null;
  onRowContextMenu: (
    event: { clientX: number; clientY: number; preventDefault: () => void },
    row: SystemInfoRow,
    cell: string | null,
  ) => void;
}) {
  const files = useMemo(() => groupShellConfigRows(table), [table]);
  const rowsById = useMemo(() => new Map(table.rows.map((row) => [row.id, row])), [table]);
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
              <div
                className={`system-info-file-line ${line.risk}${selectedRowId === line.rowId ? " is-selected" : ""}`}
                key={`${file.path}:${line.number}`}
                onContextMenu={(event) => {
                  const row = rowsById.get(line.rowId);
                  if (row !== undefined) onRowContextMenu(event, row, line.text);
                }}
              >
                <span className="system-info-file-number">{line.number}</span>
                <span className="system-info-file-text">{line.text}</span>
              </div>
            ))}
          </pre>
        </article>
      ))}
      {table.truncated ? <p className="system-info-truncated">这台机器上不止这些，只显示了前 {MAXIMUM_ROWS} 行；需要完整列表时请在终端中查看。</p> : null}
    </div>
  );
}

/**
 * The collector's own 风险 column holds the raw normal / warning / high that
 * the 级别 column already says in Chinese; on screen it is left out. Copying
 * the table keeps every column.
 */
export function shownColumn(columns: readonly string[], index: number): boolean {
  return columns[index] !== "风险";
}

const RISK_FILTERS: readonly { key: SystemInfoRiskFilter; label: string }[] = [
  { key: "all", label: "全部" },
  { key: "attention", label: "注意及以上" },
  { key: "high", label: "只看高风险" },
];

function riskLabel(risk: "normal" | "warning" | "high"): string {
  switch (risk) {
    case "normal": return "正常";
    case "warning": return "注意";
    case "high": return "高风险";
  }
}
