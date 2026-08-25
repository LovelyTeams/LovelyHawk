import { useEffect, useReducer, useRef, useState } from "react";

import {
  isLogCorrelationInput,
  isLogCorrelationResult,
  isLogIocSearchInput,
  isLogIocSearchResult,
  isLogSourceReadResult,
  isLogSourceSnapshot,
  type LogAnalysisReadApi,
  type LogCorrelationResult,
  type LogIocSearchResult,
  type LogSourceKind,
  type LogSource,
  type LogSourceReadResult,
  type LogThreatSummary,
  type PublicLogEntry,
} from "../shared/log-analysis-read-contract";
import {
  buildLogReadInput,
  filterLogSources,
  formatLogSourceSize,
  groupLogSources,
  logAnalysisScope,
  logAnalysisTabLabel,
  logSourceKindLabel,
  logThreatLevelLabel,
  parseIocIndicators,
  type LogSourceGroup,
} from "./log-analysis-read-helpers";
import {
  CheckIcon,
  ChevronIcon,
  ClockIcon,
  LockIcon,
  PlayIcon,
  RefreshIcon,
  SearchIcon,
  TagIcon,
} from "./emergency-command-icons";
import { LogSourceIcon } from "./log-source-icon";
import {
  createLogAnalysisReadState,
  logAnalysisReadReducer,
  type LogAnalysisStatus,
  type LogAnalysisTab,
  type LogReadFilter,
} from "./log-analysis-read-state";
import "./log-analysis-page.css";

export interface LogAnalysisPageProps {
  bindingHandle: string | null;
  api: LogAnalysisReadApi;
}

const tabs: readonly LogAnalysisTab[] = ["browse", "correlation", "ioc"];
const initialFilter: LogReadFilter = { keyword: "", date: "", journalUnit: "" };

export function LogAnalysisPage({ bindingHandle, api }: LogAnalysisPageProps) {
  const [state, dispatch] = useReducer(logAnalysisReadReducer, undefined, createLogAnalysisReadState);
  const [snapshotVersion, setSnapshotVersion] = useState(0);
  const [readVersion, setReadVersion] = useState(0);
  const [draftFilter, setDraftFilter] = useState<LogReadFilter>(initialFilter);
  const [queryError, setQueryError] = useState<string | null>(null);
  const [iocDraft, setIocDraft] = useState("");
  const [iocInputError, setIocInputError] = useState<string | null>(null);
  // Collapsing a branch is view state, so it lives with the view.
  const [collapsedKinds, setCollapsedKinds] = useState<readonly LogSourceKind[]>([]);
  const requestRef = useRef(0);
  const scope = bindingHandle === null ? null : logAnalysisScope(bindingHandle);
  const activeScopeRef = useRef<string | null>(scope);
  activeScopeRef.current = scope;

  useEffect(() => {
    dispatch({ type: "scope-changed", scope });
    setDraftFilter(initialFilter);
    setQueryError(null);
    setIocDraft("");
    setIocInputError(null);
  }, [scope]);

  useEffect(() => () => {
    activeScopeRef.current = null;
  }, []);

  useEffect(() => {
    if (scope === null || bindingHandle === null || state.scope !== scope) return;
    const request = ++requestRef.current;
    let cancelled = false;
    dispatch({ type: "snapshot-started", scope, request });
    void api.discoverLogSources(bindingHandle).then((result) => {
      if (cancelled) return;
      if (!isLogSourceSnapshot(result)) throw new Error();
      dispatch({ type: "snapshot-loaded", scope, request, snapshot: result });
    }).catch(() => {
      if (!cancelled) dispatch({
        type: "snapshot-failed",
        scope,
        request,
        error: "无法发现当前 SSH 绑定上的可读日志源。",
      });
    });
    return () => {
      cancelled = true;
    };
  }, [api, bindingHandle, scope, snapshotVersion, state.scope]);

  const snapshotHandle = state.snapshot?.snapshotHandle ?? null;
  const selectedSource = state.snapshot?.sources.find(
    (source) => source.sourceHandle === state.selectedSourceHandle,
  ) ?? null;

  useEffect(() => {
    if (scope === null || bindingHandle === null || snapshotHandle === null || selectedSource === null ||
      state.scope !== scope || state.tab !== "browse") return;
    const built = buildLogReadInput(selectedSource, state.page, state.appliedFilter);
    const request = {
      id: ++requestRef.current,
      snapshotHandle,
      sourceHandle: selectedSource.sourceHandle,
      page: state.page,
    };
    if (built.input === null) {
      dispatch({ type: "read-started", scope, request });
      dispatch({ type: "read-failed", scope, request, error: built.error ?? "日志查询无效。" });
      return;
    }
    let cancelled = false;
    dispatch({ type: "read-started", scope, request });
    void api.readLogSource(
      bindingHandle,
      snapshotHandle,
      selectedSource.sourceHandle,
      built.input,
    ).then((result) => {
      if (cancelled) return;
      if (!isLogSourceReadResult(result) || result.snapshotHandle !== snapshotHandle ||
        result.sourceHandle !== selectedSource.sourceHandle || result.page !== state.page) throw new Error();
      dispatch({ type: "read-loaded", scope, request, result });
    }).catch(() => {
      if (!cancelled) dispatch({
        type: "read-failed",
        scope,
        request,
        error: "日志源快照已过期、目标已变化或返回内容无效。",
      });
    });
    return () => {
      cancelled = true;
    };
  }, [
    api,
    bindingHandle,
    readVersion,
    scope,
    selectedSource,
    snapshotHandle,
    state.appliedFilter.date,
    state.appliedFilter.journalUnit,
    state.appliedFilter.keyword,
    state.page,
    state.scope,
    state.tab,
  ]);

  if (bindingHandle === null) {
    return (
      <main className="log-analysis-page log-analysis-disconnected">
        <h1>日志分析</h1>
        <p>连接 SSH 目标后，可在短期只读快照中调查文件日志与 systemd journal。</p>
      </main>
    );
  }

  const stateIsCurrent = state.scope === scope;
  const runCorrelation = () => {
    if (!stateIsCurrent || scope === null || bindingHandle === null || snapshotHandle === null) return;
    const input = { sourceHandles: [...state.analysisSourceHandles], lineLimit: 200 };
    if (!isLogCorrelationInput(input)) return;
    const request = { id: ++requestRef.current, snapshotHandle, sourceHandles: input.sourceHandles };
    dispatch({ type: "correlation-started", scope, request });
    void api.correlateLogSources(bindingHandle, snapshotHandle, input).then((result) => {
      if (activeScopeRef.current !== scope) return;
      if (!isLogCorrelationResult(result) || result.snapshotHandle !== snapshotHandle) throw new Error();
      dispatch({ type: "correlation-loaded", scope, request, result });
    }).catch(() => {
      if (activeScopeRef.current === scope) dispatch({
        type: "correlation-failed",
        scope,
        request,
        error: "多源关联已取消、快照已过期或返回内容无效。",
      });
    });
  };

  const runIocSearch = () => {
    if (!stateIsCurrent || scope === null || bindingHandle === null || snapshotHandle === null) return;
    const parsed = parseIocIndicators(iocDraft, state.analysisSourceHandles.length);
    setIocInputError(parsed.error);
    if (parsed.error !== null) return;
    const input = { sourceHandles: [...state.analysisSourceHandles], indicators: parsed.indicators };
    if (!isLogIocSearchInput(input)) {
      setIocInputError("IOC 查询超出只读安全边界。");
      return;
    }
    const request = {
      id: ++requestRef.current,
      snapshotHandle,
      sourceHandles: input.sourceHandles,
      indicators: input.indicators,
    };
    dispatch({ type: "ioc-started", scope, request });
    void api.searchLogIocs(bindingHandle, snapshotHandle, input).then((result) => {
      if (activeScopeRef.current !== scope) return;
      if (!isLogIocSearchResult(result) || result.snapshotHandle !== snapshotHandle) throw new Error();
      dispatch({ type: "ioc-loaded", scope, request, result });
    }).catch(() => {
      if (activeScopeRef.current === scope) dispatch({
        type: "ioc-failed",
        scope,
        request,
        error: "IOC 搜索已取消、快照已过期或返回内容无效。",
      });
    });
  };

  const sources = state.snapshot?.sources ?? [];
  const visible = filterLogSources(sources, state.sourceFilter);
  const groups = groupLogSources(visible);
  const analysing = state.tab !== "browse";
  const busy = state.readStatus === "loading" || state.correlationStatus === "loading" ||
    state.iocStatus === "loading";

  return (
    <main className="log-analysis-page">
      <div className="log-analysis-toolbar">
        <h1>日志分析</h1>
        <nav className="log-analysis-views" aria-label="日志分析视图">
          {tabs.map((tab) => (
            <button key={tab} type="button" className={state.tab === tab ? "is-active" : ""}
              aria-current={state.tab === tab ? "page" : undefined}
              onClick={() => dispatch({ type: "tab-selected", tab })}>
              {logAnalysisTabLabel(tab)}
            </button>
          ))}
        </nav>
        <label className="log-analysis-search">
          <SearchIcon />
          <span className="log-analysis-sr-only">筛选日志源</span>
          <input value={state.sourceFilter} maxLength={256} placeholder="筛选日志源"
            onChange={(event) => dispatch({ type: "source-filter-changed", value: event.target.value })} />
        </label>
        <div className="log-analysis-toolbar-meta">
          {state.snapshot !== null && <span>{visible.length === sources.length ?
            `共 ${sources.length} 个日志源` : `${visible.length}/${sources.length} 个日志源`}</span>}
          {state.snapshot !== null && <span className="log-analysis-expiry"><ClockIcon />快照约 {
            Math.max(1, Math.ceil(state.snapshot.expiresInSeconds / 60))} 分钟有效</span>}
          <button type="button" className="log-analysis-reload"
            disabled={!stateIsCurrent || state.snapshotStatus === "loading" || busy}
            onClick={() => setSnapshotVersion((value) => value + 1)}>
            <RefreshIcon />{state.snapshotStatus === "loading" ? "刷新中…" : "刷新日志源"}
          </button>
        </div>
      </div>
      {!stateIsCurrent || state.snapshotStatus === "loading" && state.snapshot === null ? (
        <StatusPanel label="正在发现可读日志源…" />
      ) : state.snapshotStatus === "error" ? (
        <ErrorPanel message={state.snapshotError ?? "日志源发现失败。"} />
      ) : state.snapshot === null || sources.length === 0 ? (
        <EmptyPanel title="没有可读日志源" detail="当前目标没有返回文件日志或 journal 探测结果。" />
      ) : (
        <div className="log-analysis-workbench">
          <aside className="log-analysis-list" aria-label="可读日志源">
            {(state.snapshot.partial || state.snapshot.truncated) && (
              <p className="log-analysis-warning" role="status">
                {state.snapshot.partial ? "部分日志源探测失败。" : ""}
                {state.snapshot.truncated ? "日志源清单已按安全边界截断。" : ""}
              </p>
            )}
            {groups.length === 0 ? <EmptyPanel title="没有匹配的日志源"
              detail="调整上方的筛选条件。" compact /> : groups.map((group) => (
              <LogSourceBranch
                key={group.kind}
                group={group}
                collapsed={collapsedKinds.includes(group.kind)}
                selecting={analysing}
                selectedHandle={state.selectedSourceHandle}
                checked={state.analysisSourceHandles}
                busy={busy}
                onToggle={() => setCollapsedKinds((current) => current.includes(group.kind)
                  ? current.filter((kind) => kind !== group.kind)
                  : [...current, group.kind])}
                onSelect={(handle) => dispatch(analysing
                  ? { type: "analysis-source-toggled", handle }
                  : { type: "source-selected", handle })}
              />
            ))}
          </aside>
          <section className="log-analysis-detail">
            {state.tab === "browse" ? (
              selectedSource === null ? <EmptyPanel title="未选择日志源"
                detail="从左侧选择一个文件日志或 journal 单元。" /> : (
                <BrowseView
                  source={selectedSource}
                  draftFilter={draftFilter}
                  onDraftFilter={setDraftFilter}
                  queryError={queryError}
                  onApply={() => {
                    const built = buildLogReadInput(selectedSource, 1, draftFilter);
                    setQueryError(built.error);
                    if (built.input !== null) {
                      dispatch({ type: "filter-applied", filter: { ...draftFilter } });
                      setReadVersion((value) => value + 1);
                    }
                  }}
                  status={state.readStatus}
                  error={state.readError}
                  result={state.read}
                  page={state.page}
                  onPage={(page) => dispatch({ type: "page-selected", page })}
                />
              )
            ) : state.tab === "correlation" ? (
              <CorrelationView
                selected={state.analysisSourceHandles}
                status={state.correlationStatus}
                error={state.correlationError}
                result={state.correlation}
                onRun={runCorrelation}
              />
            ) : (
              <IocView
                selected={state.analysisSourceHandles}
                draft={iocDraft}
                onDraft={setIocDraft}
                inputError={iocInputError}
                status={state.iocStatus}
                error={state.iocError}
                result={state.ioc}
                onRun={runIocSearch}
              />
            )}
          </section>
        </div>
      )}
    </main>
  );
}

/**
 * One kind of log source: a collapsible branch with its own count. In the two
 * analysis views the same rows become a multi-selection, so the operator never
 * has to find the source list twice.
 */
function LogSourceBranch({ group, collapsed, selecting, selectedHandle, checked, busy, onToggle, onSelect }: {
  group: LogSourceGroup;
  collapsed: boolean;
  selecting: boolean;
  selectedHandle: string | null;
  checked: readonly string[];
  busy: boolean;
  onToggle(): void;
  onSelect(handle: string): void;
}) {
  const label = logSourceKindLabel(group.kind);
  return (
    <div className="log-analysis-group">
      <div className="log-analysis-group-header">
        <button type="button" className="log-analysis-group-toggle" aria-expanded={!collapsed} onClick={onToggle}>
          <ChevronIcon open={!collapsed} />
          <LogSourceIcon kind={group.kind} />
          <strong>{label}</strong>
          <span className="log-analysis-group-count">{group.sources.length}</span>
        </button>
        {selecting && group.kind === "journal" && <span className="log-analysis-group-note">不参与关联</span>}
      </div>
      {!collapsed && <div className="log-analysis-group-items">
        {group.sources.map((source) => {
          const excluded = selecting && source.kind === "journal";
          const active = selecting
            ? checked.includes(source.sourceHandle)
            : selectedHandle === source.sourceHandle;
          return (
            <button type="button" key={source.sourceHandle} className={active ? "is-selected" : ""}
              aria-pressed={active} disabled={busy || excluded}
              onClick={() => onSelect(source.sourceHandle)}>
              {selecting && <span className="log-analysis-check" aria-hidden="true">
                {active ? <CheckIcon /> : null}
              </span>}
              <span className="log-analysis-source-body">
                <strong>{source.displayName || "（未命名日志源）"}</strong>
                <span>{formatLogSourceSize(source.sizeBytes)}</span>
                <span className="log-analysis-source-location">{source.displayLocation || "—"}</span>
              </span>
            </button>
          );
        })}
      </div>}
    </div>
  );
}

function BrowseView({ source, draftFilter, onDraftFilter, queryError, onApply, status, error, result, page, onPage }: {
  source: LogSource;
  draftFilter: LogReadFilter;
  onDraftFilter(value: LogReadFilter): void;
  queryError: string | null;
  onApply(): void;
  status: LogAnalysisStatus;
  error: string | null;
  result: LogSourceReadResult | null;
  page: number;
  onPage(page: number): void;
}) {
  return (
    <>
      <header>
        <LogSourceIcon kind={source.kind} />
        <div>
          <h2>{source.displayName || "日志源"}</h2>
          <p>{source.displayLocation || "—"}</p>
        </div>
      </header>
      <dl className="log-analysis-facts">
        <div>
          <dt><TagIcon />类型</dt>
          <dd>{logSourceKindLabel(source.kind)}</dd>
        </div>
        <div>
          <dt><ClockIcon />大小</dt>
          <dd>{formatLogSourceSize(source.sizeBytes)}</dd>
        </div>
        <div>
          <dt><LockIcon />读取方式</dt>
          <dd>只读，按页读取</dd>
        </div>
      </dl>
      <form className="log-analysis-query" onSubmit={(event) => { event.preventDefault(); onApply(); }}>
        <label>关键词<input value={draftFilter.keyword} maxLength={256} placeholder="可选，单行文本"
          onChange={(event) => onDraftFilter({ ...draftFilter, keyword: event.target.value })} /></label>
        <label>日期<input type="date" value={draftFilter.date}
          onChange={(event) => onDraftFilter({ ...draftFilter, date: event.target.value })} /></label>
        {source.kind === "journal" && <label>Journal 单元<input value={draftFilter.journalUnit} maxLength={128}
          placeholder="例如 ssh.service"
          onChange={(event) => onDraftFilter({ ...draftFilter, journalUnit: event.target.value })} /></label>}
        <button className="log-analysis-run" type="submit" disabled={status === "loading"}>
          <PlayIcon />{status === "loading" ? "读取中…" : "读取日志"}
        </button>
      </form>
      {queryError !== null && <p className="log-analysis-inline-error" role="alert">{queryError}</p>}
      {status === "loading" && result === null ? <StatusPanel label="正在读取日志…" /> :
        status === "error" ? <ErrorPanel message={error ?? "日志读取失败。"} compact /> : result === null ?
          <EmptyPanel title="尚未读取" detail="结果将在这里以纯文本逐行显示。" compact /> : (
            <>
              <LogThreatCards summary={result.threatSummary} />
              <LogEntriesView entries={result.entries} empty="当前页没有匹配日志。" />
              <div className="log-analysis-pagination">
                <button type="button" disabled={page <= 1 || status === "loading"}
                  onClick={() => onPage(page - 1)}>上一页</button>
                <span>第 {page} 页 · {result.entryCount} 条</span>
                <button type="button" disabled={!result.hasMore || status === "loading" || page >= 10_000}
                  onClick={() => onPage(page + 1)}>下一页</button>
              </div>
              {result.truncated && <p className="log-analysis-warning" role="status">
                本页文本已按大小上限截断。
              </p>}
            </>
          )}
    </>
  );
}

function CorrelationView({ selected, status, error, result, onRun }: {
  selected: readonly string[];
  status: LogAnalysisStatus;
  error: string | null;
  result: LogCorrelationResult | null;
  onRun(): void;
}) {
  return (
    <>
      <header>
        <LogSourceIcon kind="file" />
        <div>
          <h2>多源关联</h2>
          <p>在左侧勾选 2–8 个文件日志源；每源最多观察 200 行。</p>
        </div>
      </header>
      <dl className="log-analysis-facts">
        <div>
          <dt><TagIcon />已选日志源</dt>
          <dd>{selected.length} / 8</dd>
        </div>
        <div>
          <dt><ClockIcon />每源观察上限</dt>
          <dd>200 行</dd>
        </div>
        <div>
          <dt><LockIcon />读取方式</dt>
          <dd>只读，一次性关联</dd>
        </div>
      </dl>
      <button className="log-analysis-run" type="button" disabled={selected.length < 2 || status === "loading"}
        onClick={onRun}>
        <PlayIcon />{status === "loading" ? "关联中…" : "运行关联"}
      </button>
      {status === "loading" ? <StatusPanel label="正在关联所选日志源…" /> : status === "error" ?
        <ErrorPanel message={error ?? "多源关联失败。"} compact /> : result === null ?
          <EmptyPanel title="尚未运行关联" detail="在左侧勾选至少两个文件日志源后运行。" compact /> : (
            <>
              <p className="log-analysis-coverage">已观察 {result.totalObserved} 条</p>
              <LogThreatCards summary={result.threatSummary} />
              <LogEntriesView entries={result.entries} empty="没有可展示的关联日志。" />
              {result.truncated && <p className="log-analysis-warning" role="status">
                关联结果不代表未读取范围。
              </p>}
            </>
          )}
    </>
  );
}

function IocView({ selected, draft, onDraft, inputError, status, error, result, onRun }: {
  selected: readonly string[];
  draft: string;
  onDraft(value: string): void;
  inputError: string | null;
  status: LogAnalysisStatus;
  error: string | null;
  result: LogIocSearchResult | null;
  onRun(): void;
}) {
  return (
    <>
      <header>
        <LogSourceIcon kind="file" />
        <div>
          <h2>IOC 搜索</h2>
          <p>在左侧勾选 1–8 个文件日志源，最多 16 个 IOC，组合上限 64。</p>
        </div>
      </header>
      <dl className="log-analysis-facts">
        <div>
          <dt><TagIcon />已选日志源</dt>
          <dd>{selected.length} / 8</dd>
        </div>
        <div>
          <dt><ClockIcon />IOC 上限</dt>
          <dd>16 个</dd>
        </div>
        <div>
          <dt><LockIcon />读取方式</dt>
          <dd>只读，逐源匹配</dd>
        </div>
      </dl>
      <label className="log-analysis-ioc-input">IOC（每行一个）
        <textarea value={draft} rows={5} maxLength={4_111} onChange={(event) => onDraft(event.target.value)} />
      </label>
      {inputError !== null && <p className="log-analysis-inline-error" role="alert">{inputError}</p>}
      <button className="log-analysis-run" type="button" disabled={selected.length < 1 || status === "loading"}
        onClick={onRun}>
        <PlayIcon />{status === "loading" ? "搜索中…" : "搜索 IOC"}
      </button>
      {status === "loading" ? <StatusPanel label="正在搜索 IOC…" /> : status === "error" ?
        <ErrorPanel message={error ?? "IOC 搜索失败。"} compact /> : result === null ?
          <EmptyPanel title="尚未搜索 IOC" detail="输入 IOC 并在左侧勾选至少一个文件日志源。" compact /> :
          <LogIocResultsView result={result} />}
    </>
  );
}

export function LogThreatCards({ summary }: { summary: LogThreatSummary }) {
  return (
    <section className={`log-analysis-threat level-${summary.threatLevel}`} aria-label="威胁摘要">
      <div className="log-analysis-threat-metrics">
        <article className="log-analysis-threat-level">
          <strong>{logThreatLevelLabel(summary.threatLevel)}</strong><span>威胁等级</span>
        </article>
        <article><strong>{summary.bruteForceCount}</strong><span>暴力尝试</span></article>
        <article><strong>{summary.successfulLoginCount}</strong><span>成功登录</span></article>
        <article><strong>{summary.privilegeEscalationCount}</strong><span>提权活动</span></article>
        <article><strong>{summary.suspiciousActivityCount}</strong><span>可疑活动</span></article>
      </div>
      <details>
        <summary>来源、用户与小时分布</summary>
        <div className="log-analysis-threat-detail">
          <section>
            <h3>来源 IP</h3>
            {summary.topSourceIps.length === 0 ? <p>无</p> : summary.topSourceIps.map((item, index) => (
              <p key={`${item.ip}\0${index}`}>{item.ip || "—"} · {item.count} · {item.actionType || "—"} · {
                item.lastSeen || "—"}</p>
            ))}
          </section>
          <section>
            <h3>目标用户</h3>
            {summary.topTargetUsers.length === 0 ? <p>无</p> : summary.topTargetUsers.map((item, index) => (
              <p key={`${item.username}\0${index}`}>{item.username || "—"} · {item.count}（成功 {
                item.successCount} / 失败 {item.failCount}）</p>
            ))}
          </section>
          <section>
            <h3>小时分布</h3>
            <p>{summary.hourlyDistribution.map((count, hour) =>
              `${String(hour).padStart(2, "0")}:00 ${count}`).join(" · ")}</p>
          </section>
        </div>
      </details>
    </section>
  );
}

/**
 * Numbered lines with a pinned gutter, the same shape the command workbench
 * uses for command output. Highlighted entries are marked rather than hidden,
 * and the raw line is shown as the target wrote it.
 */
export function LogEntriesView({ entries, empty }: { entries: readonly PublicLogEntry[]; empty: string }) {
  if (entries.length === 0) {
    return <EmptyPanel title={empty} detail="空结果不代表未调查范围没有事件。" compact />;
  }
  return (
    <div className="log-analysis-output">
      <span className="log-analysis-gutter" aria-hidden="true">
        {entries.map((entry, index) => <span key={`${entry.timestamp}\0${index}`}
          className={entry.highlighted ? "is-abnormal" : undefined}>{index + 1}</span>)}
      </span>
      <div className="log-analysis-lines">
        {entries.map((entry, index) => (
          <p key={`${entry.timestamp}\0${index}`} className={entry.highlighted ? "is-abnormal" : undefined}>
            <span className="log-analysis-line-meta">
              <time>{entry.timestamp || "—"}</time>
              <em>{entry.level || "—"}</em>
              <span>{entry.service || "—"}</span>
              {entry.sourceName !== null && <span>{entry.sourceName}</span>}
            </span>
            <span className="log-analysis-line-text">{entry.rawText || entry.message || "—"}</span>
            {entry.textTruncated && <small>文本已截断。</small>}
          </p>
        ))}
      </div>
    </div>
  );
}

export function LogIocResultsView({ result }: { result: LogIocSearchResult }) {
  return (
    <section className="log-analysis-ioc-results">
      <p className="log-analysis-coverage">匹配总数 {result.totalMatches}</p>
      {result.results.length === 0 ? <EmptyPanel title="没有 IOC 匹配"
        detail="本次搜索没有返回匹配。" compact /> : result.results.map((item, index) => (
        <article key={`${item.indicator}\0${item.sourceHandle}\0${index}`}>
          <header>
            <strong>{item.indicator}</strong>
            <span>{item.sourceName || "—"}</span>
            <span className="log-analysis-ioc-count">{item.count} 次</span>
          </header>
          {item.sampleLines.length === 0 ? <p className="log-analysis-muted">没有返回样本行。</p> : (
            <div className="log-analysis-output">
              <span className="log-analysis-gutter" aria-hidden="true">
                {item.sampleLines.map((_line, lineIndex) => <span key={lineIndex}>{lineIndex + 1}</span>)}
              </span>
              <pre>{item.sampleLines.join("\n")}</pre>
            </div>
          )}
          {item.textTruncated && <small>样本文本已截断。</small>}
        </article>
      ))}
      {result.truncated && <p className="log-analysis-warning" role="status">IOC 结果已按大小上限截断。</p>}
    </section>
  );
}

export function StatusPanel({ label }: { label: string }) {
  return <div className="log-analysis-status" aria-live="polite"><span aria-hidden="true" />{label}</div>;
}

export function ErrorPanel({ message, compact = false }: { message: string; compact?: boolean }) {
  return <div className={compact ? "log-analysis-error is-compact" : "log-analysis-error"}
    role="alert"><strong>操作失败</strong><p>{message}</p></div>;
}

export function EmptyPanel({ title, detail, compact = false }: {
  title: string;
  detail: string;
  compact?: boolean;
}) {
  return <div className={compact ? "log-analysis-empty is-compact" : "log-analysis-empty"}>
    <strong>{title}</strong><p>{detail}</p>
  </div>;
}
