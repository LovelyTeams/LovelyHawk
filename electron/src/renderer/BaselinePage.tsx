import { useEffect, useReducer, useRef, useState } from "react";
import type { ReactNode } from "react";

import { targetFailureMessage } from "./target-lost";

import {
  isBaselineCatalog,
  isBaselineHistory,
  isBaselineScan,
  type BaselineCatalog,
  type BaselineCatalogItem,
  type BaselineFile,
  type BaselineHistory,
  type BaselineReadApi,
  type BaselineScan,
  type BaselineStatus,
} from "../shared/baseline-read-contract";
import {
  BaselineFilePane,
  useBaselineFile,
  type BaselineFileStatus,
} from "./BaselineFilePane";
import {
  baselineCategoryLabel,
  baselineComplianceLabel,
  baselineHistoryStateLabel,
  baselineRiskLabel,
  baselineScope,
  baselineValueSummary,
  groupBaselineChecks,
  baselineTabLabel,
  baselineValueKindLabel,
  filterBaselineItems,
} from "./baseline-read-helpers";
import {
  baselineReadReducer,
  createBaselineReadState,
  type BaselineCategoryFilter,
  type BaselineComplianceFilter,
  type BaselineReadStatus,
  type BaselineTab,
} from "./baseline-read-state";
import "./baseline-page.css";

export interface BaselinePageProps {
  bindingHandle: string | null;
  api: BaselineReadApi;
  active?: boolean;
  /**
   * Set when the page sits inside the configuration workbench, which already
   * carries the title and says what the view does. Two headers stacked on top
   * of each other read as two pages.
   */
  embedded?: boolean;
  /**
   * The switch between the two halves of the configuration page. It is
   * rendered into the view tabs rather than above them, because a row that
   * exists already costs nothing.
   */
  modeSwitch?: ReactNode;
}

const tabs: readonly BaselineTab[] = ["checks", "history"];
const categories: readonly BaselineCategoryFilter[] = [
  "all", "ssh", "authentication", "password", "kernel", "network", "logging", "file-permissions",
];
const complianceFilters: readonly BaselineComplianceFilter[] = [
  "all", "compliant", "non-compliant", "unscanned",
];

export function BaselinePage({
  bindingHandle,
  api,
  active = true,
  embedded = false,
  modeSwitch,
}: BaselinePageProps) {
  const [state, dispatch] = useReducer(baselineReadReducer, undefined, createBaselineReadState);
  const [catalogVersion, setCatalogVersion] = useState(0);
  const [scanVersion, setScanVersion] = useState(0);
  const [historyVersion, setHistoryVersion] = useState(0);
  const requestRef = useRef(0);
  const scope = bindingHandle === null ? null : baselineScope(bindingHandle);
  const enabled = active && bindingHandle !== null;

  useEffect(() => {
    dispatch({ type: "scope-changed", scope });
  }, [scope]);

  useEffect(() => {
    if (enabled) return;
    dispatch({ type: "deactivated", scope });
  }, [enabled, scope]);

  useEffect(() => {
    const request = ++requestRef.current;
    let cancelled = false;
    dispatch({ type: "catalog-started", request });
    void api.getBaselineCatalog().then((result) => {
      if (cancelled) return;
      if (!isBaselineCatalog(result)) throw new Error();
      dispatch({ type: "catalog-loaded", request, catalog: result });
    }).catch((reason: unknown) => {
      if (!cancelled) dispatch({
        type: "catalog-failed",
        request,
        error: "基线目录未通过本地完整性与边界校验。",
      });
    });
    return () => {
      cancelled = true;
    };
  }, [api, catalogVersion]);

  useEffect(() => {
    if (!enabled || scope === null || bindingHandle === null || state.scope !== scope ||
      state.tab !== "checks" || state.catalog === null) return;
    const request = { id: ++requestRef.current };
    let cancelled = false;
    dispatch({ type: "scan-started", scope, request });
    void api.scanBaseline(bindingHandle).then((result) => {
      if (cancelled) return;
      if (!isBaselineScan(result)) throw new Error();
      dispatch({ type: "scan-loaded", scope, request, scan: result });
    }).catch((reason: unknown) => {
      if (!cancelled) dispatch({
        type: "scan-failed",
        scope,
        request,
        error: targetFailureMessage(reason, "无法读取当前目标的基线状态；绑定可能已变化、断开或权限不足。"),
      });
    });
    return () => {
      cancelled = true;
    };
  }, [api, bindingHandle, enabled, scanVersion, scope, state.catalog, state.scope, state.tab]);

  useEffect(() => {
    if (!enabled || scope === null || bindingHandle === null || state.scope !== scope ||
      state.tab !== "history") return;
    const request = { id: ++requestRef.current };
    let cancelled = false;
    dispatch({ type: "history-started", scope, request });
    void api.listBaselineHistory(bindingHandle).then((result) => {
      if (cancelled) return;
      if (!isBaselineHistory(result)) throw new Error();
      dispatch({ type: "history-loaded", scope, request, history: result });
    }).catch((reason: unknown) => {
      if (!cancelled) dispatch({
        type: "history-failed",
        scope,
        request,
        error: targetFailureMessage(reason, "无法读取当前目标的基线历史；绑定可能已变化、断开或本地记录不可用。"),
      });
    });
    return () => {
      cancelled = true;
    };
  }, [api, bindingHandle, enabled, historyVersion, scope, state.scope, state.tab]);

  const current = state.scope === scope;
  // Which check the file pane is showing. View state, so it lives here rather
  // than in the reducer that guards the scoped reads.
  const [selectedItemHandle, setSelectedItemHandle] = useState<string | null>(null);
  const configFile = useBaselineFile(api, bindingHandle);
  const loadConfigFile = configFile.open;

  useEffect(() => {
    setSelectedItemHandle(null);
  }, [scope]);

  useEffect(() => {
    void loadConfigFile(selectedItemHandle);
  }, [loadConfigFile, selectedItemHandle]);

  if (!active) {
    return (
      <main className="baseline-page">
        <BaselineEmptyPanel
          title="安全基线页面已停用"
          detail="切换页面会清空当前的扫描结果与历史。"
        />
      </main>
    );
  }
  return (
    <main className={embedded ? "baseline-page is-embedded" : "baseline-page"}>
      {!embedded && (
        <>
          <header className="baseline-header">
            <div>
              <p className="baseline-kicker">只读</p>
              <h1>Linux 安全基线</h1>
              <p className="baseline-target">
                {bindingHandle === null ? "尚未连接 SSH 目标" : "已连接目标"}
              </p>
            </div>
            <button type="button" disabled={state.catalogStatus === "loading"}
              onClick={() => setCatalogVersion((value) => value + 1)}>
              {state.catalogStatus === "loading" ? "目录刷新中…" : "刷新目录"}
            </button>
          </header>

          <p className="baseline-readonly-banner">
            本页只读取固定目录、当前合规状态与当前目标的安全历史摘要；不提供计划、确认、执行、恢复或重载入口。
          </p>
        </>
      )}

      {(state.catalogStatus === "idle" || state.catalogStatus === "loading") && state.catalog === null ? (
        <BaselineStatusPanel label="正在读取随包分发的基线目录…" />
      ) : state.catalogStatus === "error" ? (
        <BaselineErrorPanel message={state.catalogError ?? "基线目录不可用。"} />
      ) : state.catalog === null ? (
        <BaselineEmptyPanel title="基线目录为空" detail="手动刷新本地目录后重试。" />
      ) : (
        <>
          <nav className="baseline-tabs" aria-label="安全基线视图">
            {tabs.map((tab) => (
              <button key={tab} type="button" className={state.tab === tab ? "is-active" : ""}
                aria-current={state.tab === tab ? "page" : undefined}
                onClick={() => dispatch({ type: "tab-selected", tab })}>
                {baselineTabLabel(tab)}
              </button>
            ))}
            {modeSwitch}
          </nav>
          <section className="baseline-content">
            {state.tab === "checks" ? (
              <BaselineChecksView
                catalog={state.catalog}
                status={state.scanStatus}
                scan={state.scan}
                error={state.scanError}
                connected={enabled && current}
                search={state.search}
                category={state.category}
                compliance={state.compliance}
                onSearch={(value) => dispatch({ type: "search-changed", value })}
                onCategory={(value) => dispatch({ type: "category-changed", value })}
                onCompliance={(value) => dispatch({ type: "compliance-changed", value })}
                onRefresh={() => setScanVersion((value) => value + 1)}
                selectedItemHandle={selectedItemHandle}
                onSelect={setSelectedItemHandle}
                file={configFile.file}
                fileStatus={configFile.status}
                fileError={configFile.error}
                onReloadFile={() => void loadConfigFile(selectedItemHandle)}
              />
            ) : (
              <BaselineHistoryView
                status={state.historyStatus}
                history={state.history}
                error={state.historyError}
                connected={enabled && current}
                onRefresh={() => setHistoryVersion((value) => value + 1)}
              />
            )}
          </section>
        </>
      )}
    </main>
  );
}

export function BaselineChecksView({ catalog, status, scan, error, connected, search, category,
  compliance, onSearch, onCategory, onCompliance, onRefresh, selectedItemHandle = null,
  onSelect, file = null, fileStatus = "idle", fileError = null, onReloadFile }: {
  catalog: BaselineCatalog;
  status: BaselineReadStatus;
  scan: BaselineScan | null;
  error: string | null;
  connected: boolean;
  search: string;
  category: BaselineCategoryFilter;
  compliance: BaselineComplianceFilter;
  onSearch(value: string): void;
  onCategory(value: BaselineCategoryFilter): void;
  onCompliance(value: BaselineComplianceFilter): void;
  onRefresh(): void;
  selectedItemHandle?: string | null;
  onSelect?: ((itemHandle: string | null) => void) | undefined;
  file?: BaselineFile | null;
  fileStatus?: BaselineFileStatus;
  fileError?: string | null;
  onReloadFile?: (() => void) | undefined;
}) {
  const visible = filterBaselineItems(catalog.items, scan, search, category, compliance);
  const selected = visible.find(({ item }) => item.itemHandle === selectedItemHandle) ?? null;
  return (
    <>
      <div className="baseline-view-header">
        <div><h2>基线检查</h2><p>分类浏览固定目录，并手动读取当前目标的合规状态。</p></div>
        <button type="button" disabled={!connected || status === "loading"} onClick={onRefresh}>
          {status === "loading" ? "扫描中…" : "手动扫描"}
        </button>
      </div>
      {!connected && (
        <p className="baseline-connection-note" role="status">
          连接 SSH 目标后才能扫描；本地目录仍可浏览，不代表任何目标已检查。
        </p>
      )}
      <div className="baseline-filters">
        <label>搜索
          <input type="search" value={search} maxLength={256} placeholder="标题、说明、建议或观察值"
            onChange={(event) => onSearch(event.target.value)} />
        </label>
        <label>分类
          <select value={category} onChange={(event) => onCategory(event.target.value as BaselineCategoryFilter)}>
            {categories.map((value) => <option key={value} value={value}>
              {value === "all" ? "全部分类" : baselineCategoryLabel(value)}
            </option>)}
          </select>
        </label>
        <label>合规状态
          <select value={compliance}
            onChange={(event) => onCompliance(event.target.value as BaselineComplianceFilter)}>
            {complianceFilters.map((value) => <option key={value} value={value}>{complianceFilterLabel(value)}</option>)}
          </select>
        </label>
      </div>
      <div className="baseline-summary" aria-label="基线汇总">
        <article><strong>{catalog.displayed}</strong><span>目录项</span></article>
        <article><strong>{scan?.compliantCount ?? 0}</strong><span>符合</span></article>
        <article><strong>{scan?.nonCompliantCount ?? 0}</strong><span>不符合</span></article>
        <article><strong>{scan === null ? catalog.displayed : Math.max(0, catalog.displayed - scan.displayed)}</strong>
          <span>尚未扫描</span></article>
      </div>
      {status === "loading" && scan === null ? (
        <BaselineStatusPanel label="正在通过当前目标绑定读取基线状态…" />
      ) : status === "error" ? (
        <BaselineErrorPanel message={error ?? "基线扫描失败。"} compact />
      ) : visible.length === 0 ? (
        <BaselineEmptyPanel title="没有匹配的基线项" detail="调整分类、合规状态或搜索文本。" compact />
      ) : (
        <div className="baseline-workbench">
          <div className="baseline-card-grid">
            {groupBaselineChecks(visible).map((group) => (
              <section className="baseline-check-group" key={group.category}>
                <header>
                  <strong>{baselineCategoryLabel(group.category)}</strong>
                  <span className="baseline-group-count">
                    {group.failing === 0
                      ? `${group.items.length} 项`
                      : `${group.items.length} 项，`}
                    {group.failing > 0 && (
                      <em className="baseline-group-failing">{group.failing} 项不符合</em>
                    )}
                  </span>
                </header>
                <div role="list">
                  {group.items.map(({ item, status: itemStatus }) => (
                    <BaselineCheckCard
                      key={item.itemHandle}
                      item={item}
                      status={itemStatus}
                      selected={item.itemHandle === selectedItemHandle}
                      onSelect={onSelect}
                    />
                  ))}
                </div>
              </section>
            ))}
          </div>
          <BaselineFilePane
            item={selected?.item ?? null}
            status={selected?.status ?? null}
            file={file}
            fileStatus={fileStatus}
            error={fileError}
            connected={connected}
            onReload={() => onReloadFile?.()}
          />
        </div>
      )}
      {(catalog.truncated || scan?.truncated) && (
        <BaselineTruncatedNotice>
          目录或扫描结果已按数量、文本或响应预算截断；未显示不表示符合。
        </BaselineTruncatedNotice>
      )}
    </>
  );
}

/**
 * One check. Selecting it opens the file it reads in the pane beside the list,
 * because a verdict without the line it came from is only an assertion.
 */
/**
 * One check, in the space one check is worth.
 *
 * A verdict, a title and what the target has against what it should have —
 * that is what an operator scans a list of thirty-eight for. The wording of
 * the check and the values it accepts only matter once they have stopped on
 * one, so those wait in the bubble that opens on hover.
 */
export function BaselineCheckCard({ item, status, selected = false, onSelect }: {
  item: BaselineCatalogItem;
  status: BaselineStatus | null;
  selected?: boolean;
  onSelect?: ((itemHandle: string | null) => void) | undefined;
}) {
  const verdict = status?.compliant === true
    ? "is-compliant"
    : status === null ? "is-unscanned" : "is-noncompliant";
  return (
    <div className="baseline-card-slot" role="listitem">
      <button
        type="button"
        className={`baseline-card risk-${item.risk}${selected ? " is-selected" : ""}`}
        aria-pressed={selected}
        disabled={onSelect === undefined}
        onClick={() => onSelect?.(selected ? null : item.itemHandle)}
      >
        <span className="baseline-card-risk" aria-hidden="true" />
        <span className="baseline-card-body">
          <strong>{item.title}</strong>
          <span className="baseline-card-values">{baselineValueSummary(item, status)}</span>
        </span>
        <span className={`baseline-card-verdict ${verdict}`}>{baselineComplianceLabel(status)}</span>
      </button>
      <span className="baseline-card-bubble" role="tooltip">
        <strong>{item.title}</strong>
        <span className="baseline-card-bubble-risk">{baselineRiskLabel(item.risk)}风险</span>
        <p>{item.description}</p>
        <dl>
          <div><dt>建议值</dt><dd><code>{item.recommendation}</code></dd></div>
          <div><dt>取值</dt><dd>{baselineValueKindLabel(item.valueKind)}</dd></div>
          <div><dt>目标机上的值</dt><dd><code>{status?.observed ?? "尚未扫描"}</code></dd></div>
        </dl>
        {status?.textTruncated === true && <em>观察值已按字节边界截断。</em>}
      </span>
    </div>
  );
}

export function BaselineHistoryView({ status, history, error, connected, onRefresh }: {
  status: BaselineReadStatus;
  history: BaselineHistory | null;
  error: string | null;
  connected: boolean;
  onRefresh(): void;
}) {
  return (
    <>
      <div className="baseline-view-header">
        <div><h2>变更历史</h2><p>只展示当前目标的安全摘要。</p></div>
        <button type="button" disabled={!connected || status === "loading"} onClick={onRefresh}>
          {status === "loading" ? "读取中…" : "手动刷新"}
        </button>
      </div>
      {!connected ? (
        <BaselineEmptyPanel title="尚未连接目标" detail="连接后才能读取该目标的便携历史。" compact />
      ) : status === "loading" && history === null ? (
        <BaselineStatusPanel label="正在读取基线历史…" />
      ) : status === "error" ? (
        <BaselineErrorPanel message={error ?? "基线历史不可用。"} compact />
      ) : history === null || history.entries.length === 0 ? (
        <BaselineEmptyPanel title="没有基线变更历史"
          detail="空结果只表示当前目标没有可展示的受管记录。" compact />
      ) : (
        <div className="baseline-history-list">
          {history.entries.map((entry) => (
            <article key={entry.historyItemHandle}>
              <header>
                <strong>{baselineHistoryStateLabel(entry.state)}</strong>
                <span>{entry.changeCount} 项</span>
                <time>{entry.updatedAt}</time>
              </header>
              <p>{entry.summary}</p>
              <small>创建于 {entry.createdAt}</small>
              {(entry.redacted || entry.textTruncated) && <small>摘要已遮蔽或截断。</small>}
            </article>
          ))}
        </div>
      )}
      {history !== null && (history.truncated || history.redactedFieldCount > 0) && (
        <BaselineTruncatedNotice>
          历史摘要已截断；原始记录与备份证据不在此展示。
        </BaselineTruncatedNotice>
      )}
    </>
  );
}

export function BaselineStatusPanel({ label }: { label: string }) {
  return <div className="baseline-status-panel" aria-live="polite"><span aria-hidden="true" />{label}</div>;
}

export function BaselineErrorPanel({ message, compact = false }: { message: string; compact?: boolean }) {
  return <div className={compact ? "baseline-error is-compact" : "baseline-error"} role="alert">{message}</div>;
}

export function BaselineEmptyPanel({ title, detail, compact = false }: {
  title: string;
  detail: string;
  compact?: boolean;
}) {
  return <div className={compact ? "baseline-empty is-compact" : "baseline-empty"}>
    <strong>{title}</strong><p>{detail}</p>
  </div>;
}

function BaselineTruncatedNotice({ children }: { children: string }) {
  return <p className="baseline-warning" role="status">{children}</p>;
}

function complianceFilterLabel(filter: BaselineComplianceFilter): string {
  switch (filter) {
    case "all": return "全部状态";
    case "compliant": return "仅符合";
    case "non-compliant": return "仅不符合";
    case "unscanned": return "仅尚未扫描";
  }
}
