import { useEffect, useReducer, useRef, useState } from "react";

import {
  isLogCorrelationInput,
  isLogCorrelationResult,
  isLogIocSearchInput,
  isLogIocSearchResult,
  isLogSourceReadResult,
  isLogSourceSnapshot,
  type LogAnalysisReadApi,
  type LogIocSearchResult,
  type LogSource,
  type LogSourceReadResult,
  type LogThreatSummary,
  type PublicLogEntry,
} from "../shared/log-analysis-read-contract";
import {
  buildLogReadInput,
  filterLogSources,
  formatLogSourceSize,
  logAnalysisScope,
  logAnalysisTabLabel,
  logThreatLevelLabel,
  parseIocIndicators,
} from "./log-analysis-read-helpers";
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

  return (
    <main className="log-analysis-page">
      <header className="log-analysis-header">
        <div>
          <p className="log-analysis-kicker">只读</p>
          <h1>日志分析</h1>
          <p className="log-analysis-target">当前 SSH 绑定的只读短期快照</p>
        </div>
        <div className="log-analysis-header-actions">
          {state.snapshot !== null && <span>快照约 {Math.max(1, Math.ceil(state.snapshot.expiresInSeconds / 60))} 分钟有效</span>}
          <button type="button" disabled={!stateIsCurrent || state.snapshotStatus === "loading"} onClick={() => setSnapshotVersion((value) => value + 1)}>
            {state.snapshotStatus === "loading" ? "刷新中…" : "刷新日志源"}
          </button>
        </div>
      </header>
      <p className="log-analysis-readonly-banner">
        本页只读取已发现并绑定到短期快照的日志源；不会将展示位置作为后续读取参数。
      </p>
      {!stateIsCurrent || state.snapshotStatus === "loading" && state.snapshot === null ? (
        <StatusPanel label="正在发现可读日志源…" />
      ) : state.snapshotStatus === "error" ? (
        <ErrorPanel message={state.snapshotError ?? "日志源发现失败。"} />
      ) : state.snapshot === null || state.snapshot.sources.length === 0 ? (
        <EmptyPanel title="没有可读日志源" detail="当前目标没有返回文件日志或 journal 探测结果。" />
      ) : (
        <>
          {(state.snapshot.partial || state.snapshot.truncated) && (
            <p className="log-analysis-warning" role="status">
              {state.snapshot.partial ? "部分日志源探测失败。" : ""} {state.snapshot.truncated ? "日志源清单已按安全边界截断。" : ""}
            </p>
          )}
          <nav className="log-analysis-tabs" aria-label="日志分析视图">
            {tabs.map((tab) => (
              <button key={tab} type="button" className={state.tab === tab ? "is-active" : ""}
                aria-current={state.tab === tab ? "page" : undefined}
                onClick={() => dispatch({ type: "tab-selected", tab })}>
                {logAnalysisTabLabel(tab)}
              </button>
            ))}
          </nav>
          <div className="log-analysis-layout">
            <SourceSidebar
              sources={state.snapshot.sources}
              selectedHandle={state.selectedSourceHandle}
              filter={state.sourceFilter}
              onFilter={(value) => dispatch({ type: "source-filter-changed", value })}
              onSelect={(handle) => dispatch({ type: "source-selected", handle })}
            />
            <section className="log-analysis-workspace">
              {state.tab === "browse" && selectedSource !== null && (
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
              )}
              {state.tab === "correlation" && (
                <CorrelationView
                  sources={state.snapshot.sources}
                  selected={state.analysisSourceHandles}
                  onToggle={(handle) => dispatch({ type: "analysis-source-toggled", handle })}
                  status={state.correlationStatus}
                  error={state.correlationError}
                  result={state.correlation}
                  onRun={runCorrelation}
                />
              )}
              {state.tab === "ioc" && (
                <IocView
                  sources={state.snapshot.sources}
                  selected={state.analysisSourceHandles}
                  onToggle={(handle) => dispatch({ type: "analysis-source-toggled", handle })}
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
        </>
      )}
    </main>
  );
}

function SourceSidebar({ sources, selectedHandle, filter, onFilter, onSelect }: {
  sources: readonly LogSource[];
  selectedHandle: string | null;
  filter: string;
  onFilter(value: string): void;
  onSelect(handle: string): void;
}) {
  const visible = filterLogSources(sources, filter);
  return (
    <aside className="log-analysis-sources">
      <label>筛选日志源<input value={filter} maxLength={256} onChange={(event) => onFilter(event.target.value)} /></label>
      <div className="log-analysis-source-list">
        {visible.length === 0 ? <p className="log-analysis-muted">没有匹配的日志源。</p> : visible.map((source) => (
          <button key={source.sourceHandle} type="button" className={selectedHandle === source.sourceHandle ? "is-selected" : ""}
            aria-pressed={selectedHandle === source.sourceHandle} onClick={() => onSelect(source.sourceHandle)}>
            <strong>{source.displayName || "（未命名日志源）"}</strong>
            <span>{source.kind === "journal" ? "Journal" : "文件"} · {formatLogSourceSize(source.sizeBytes)}</span>
            <small>{source.displayLocation || "—"}</small>
          </button>
        ))}
      </div>
    </aside>
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
      <div className="log-analysis-view-header"><div><h2>{source.displayName || "日志源"}</h2><p>{source.displayLocation || "—"}</p></div></div>
      <form className="log-analysis-query" onSubmit={(event) => { event.preventDefault(); onApply(); }}>
        <label>关键词<input value={draftFilter.keyword} maxLength={256} placeholder="可选，单行文本"
          onChange={(event) => onDraftFilter({ ...draftFilter, keyword: event.target.value })} /></label>
        <label>日期<input type="date" value={draftFilter.date}
          onChange={(event) => onDraftFilter({ ...draftFilter, date: event.target.value })} /></label>
        {source.kind === "journal" && <label>Journal 单元<input value={draftFilter.journalUnit} maxLength={128} placeholder="例如 ssh.service"
          onChange={(event) => onDraftFilter({ ...draftFilter, journalUnit: event.target.value })} /></label>}
        <button className="log-analysis-primary" type="submit" disabled={status === "loading"}>{status === "loading" ? "读取中…" : "应用并读取"}</button>
      </form>
      {queryError !== null && <p className="log-analysis-inline-error" role="alert">{queryError}</p>}
      {status === "loading" && result === null ? <StatusPanel label="正在读取日志…" /> :
        status === "error" ? <ErrorPanel message={error ?? "日志读取失败。"} compact /> : result === null ?
          <EmptyPanel title="等待日志结果" detail="应用查询后读取当前源。" compact /> : (
            <>
              <LogThreatCards summary={result.threatSummary} />
              <LogEntriesView entries={result.entries} empty="当前页没有匹配日志。" />
              <div className="log-analysis-pagination">
                <button type="button" disabled={page <= 1 || status === "loading"} onClick={() => onPage(page - 1)}>上一页</button>
                <span>第 {page} 页 · {result.entryCount} 条</span>
                <button type="button" disabled={!result.hasMore || status === "loading" || page >= 10_000} onClick={() => onPage(page + 1)}>下一页</button>
              </div>
              {(result.truncated || result.redactedCount > 0) && <p className="log-analysis-warning" role="status">
                {result.truncated ? "本页文本已按安全边界截断。" : ""} {result.redactedCount > 0 ? `${result.redactedCount} 条疑似敏感日志已整行遮蔽。` : ""}
              </p>}
            </>
          )}
    </>
  );
}

function CorrelationView({ sources, selected, onToggle, status, error, result, onRun }: {
  sources: readonly LogSource[];
  selected: readonly string[];
  onToggle(handle: string): void;
  status: LogAnalysisStatus;
  error: string | null;
  result: import("../shared/log-analysis-read-contract").LogCorrelationResult | null;
  onRun(): void;
}) {
  return (
    <>
      <div className="log-analysis-view-header"><div><h2>多源关联</h2><p>选择 2–8 个文件日志源；每源最多观察 200 行。</p></div>
        <button className="log-analysis-primary" type="button" disabled={selected.length < 2 || status === "loading"} onClick={onRun}>{status === "loading" ? "关联中…" : "运行关联"}</button></div>
      <AnalysisSourceSelector sources={sources} selected={selected} onToggle={onToggle} />
      {status === "loading" ? <StatusPanel label="正在关联所选日志源…" /> : status === "error" ?
        <ErrorPanel message={error ?? "多源关联失败。"} compact /> : result === null ?
          <EmptyPanel title="尚未运行关联" detail="选择至少两个文件日志源后运行。" compact /> : (
            <>
              <p className="log-analysis-coverage">已观察 {result.totalObserved} 条</p>
              <LogThreatCards summary={result.threatSummary} />
              <LogEntriesView entries={result.entries} empty="没有可展示的关联日志。" />
              {(result.truncated || result.redactedCount > 0) && <p className="log-analysis-warning" role="status">
                关联结果不代表未读取范围。{result.redactedCount > 0 ? ` ${result.redactedCount} 条已整行遮蔽。` : ""}
              </p>}
            </>
          )}
    </>
  );
}

function IocView({ sources, selected, onToggle, draft, onDraft, inputError, status, error, result, onRun }: {
  sources: readonly LogSource[];
  selected: readonly string[];
  onToggle(handle: string): void;
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
      <div className="log-analysis-view-header"><div><h2>IOC 搜索</h2><p>1–8 个文件日志源，最多 16 个 IOC，组合上限 64。</p></div>
        <button className="log-analysis-primary" type="button" disabled={selected.length < 1 || status === "loading"} onClick={onRun}>{status === "loading" ? "搜索中…" : "搜索 IOC"}</button></div>
      <AnalysisSourceSelector sources={sources} selected={selected} onToggle={onToggle} />
      <label className="log-analysis-ioc-input">IOC（每行一个）<textarea value={draft} rows={6} maxLength={4_111}
        onChange={(event) => onDraft(event.target.value)} /></label>
      {inputError !== null && <p className="log-analysis-inline-error" role="alert">{inputError}</p>}
      {status === "loading" ? <StatusPanel label="正在搜索 IOC…" /> : status === "error" ?
        <ErrorPanel message={error ?? "IOC 搜索失败。"} compact /> : result === null ?
          <EmptyPanel title="尚未搜索 IOC" detail="输入 IOC 并选择至少一个文件日志源。" compact /> :
          <LogIocResultsView result={result} />}
    </>
  );
}

function AnalysisSourceSelector({ sources, selected, onToggle }: {
  sources: readonly LogSource[];
  selected: readonly string[];
  onToggle(handle: string): void;
}) {
  const files = sources.filter((source) => source.kind === "file");
  return <fieldset className="log-analysis-selector"><legend>文件日志源（已选 {selected.length}/8）</legend>
    {files.length === 0 ? <p className="log-analysis-muted">没有可用于此调查的文件日志源。</p> : files.map((source) => (
      <label key={source.sourceHandle}><input type="checkbox" checked={selected.includes(source.sourceHandle)}
        disabled={!selected.includes(source.sourceHandle) && selected.length >= 8}
        onChange={() => onToggle(source.sourceHandle)} /><span>{source.displayName || "（未命名）"}</span><small>{source.displayLocation}</small></label>
    ))}
  </fieldset>;
}

export function LogThreatCards({ summary }: { summary: LogThreatSummary }) {
  return (
    <section className={`log-analysis-threat level-${summary.threatLevel}`} aria-label="威胁摘要">
      <div className="log-analysis-threat-metrics">
        <article><strong>{logThreatLevelLabel(summary.threatLevel)}</strong><span>威胁等级</span></article>
        <article><strong>{summary.bruteForceCount}</strong><span>暴力尝试</span></article>
        <article><strong>{summary.successfulLoginCount}</strong><span>成功登录</span></article>
        <article><strong>{summary.privilegeEscalationCount}</strong><span>提权活动</span></article>
        <article><strong>{summary.suspiciousActivityCount}</strong><span>可疑活动</span></article>
      </div>
      <details><summary>来源、用户与小时分布</summary>
        <div className="log-analysis-threat-detail">
          <section><h3>来源 IP</h3>{summary.topSourceIps.length === 0 ? <p>无</p> : summary.topSourceIps.map((item, index) => <p key={`${item.ip}\0${index}`}>{item.ip || "—"} · {item.count} · {item.actionType || "—"} · {item.lastSeen || "—"}</p>)}</section>
          <section><h3>目标用户</h3>{summary.topTargetUsers.length === 0 ? <p>无</p> : summary.topTargetUsers.map((item, index) => <p key={`${item.username}\0${index}`}>{item.username || "—"} · {item.count}（成功 {item.successCount} / 失败 {item.failCount}）</p>)}</section>
          <section><h3>小时分布</h3><p>{summary.hourlyDistribution.map((count, hour) => `${String(hour).padStart(2, "0")}:00 ${count}`).join(" · ")}</p></section>
        </div>
      </details>
    </section>
  );
}

export function LogEntriesView({ entries, empty }: { entries: readonly PublicLogEntry[]; empty: string }) {
  if (entries.length === 0) return <EmptyPanel title={empty} detail="空结果不代表未调查范围没有事件。" compact />;
  return <div className="log-analysis-entry-list">{entries.map((entry, index) => (
    <article className={entry.highlighted ? "is-highlighted" : ""} key={`${entry.timestamp}\0${index}`}>
      <header><time>{entry.timestamp || "—"}</time><span>{entry.level || "—"}</span><span>{entry.service || "—"}</span>{entry.sourceName !== null && <span>{entry.sourceName}</span>}</header>
      <p>{entry.message || "—"}</p>
      <pre>{entry.rawText}</pre>
      {(entry.redacted || entry.textTruncated) && <small>{entry.redacted ? "疑似敏感整行已遮蔽。" : ""} {entry.textTruncated ? "文本已截断。" : ""}</small>}
    </article>
  ))}</div>;
}

export function LogIocResultsView({ result }: { result: LogIocSearchResult }) {
  return (
    <section className="log-analysis-ioc-results">
      <p>匹配总数：{result.totalMatches}</p>
      {result.results.length === 0 ? <EmptyPanel title="没有 IOC 匹配" detail="本次搜索没有返回匹配。" compact /> : result.results.map((item, index) => (
        <article key={`${item.indicator}\0${item.sourceHandle}\0${index}`}>
          <header><strong>{item.indicator}</strong><span>{item.sourceName || "—"}</span><span>{item.count} 次</span></header>
          {item.sampleLines.length === 0 ? <p className="log-analysis-muted">没有返回样本行。</p> : item.sampleLines.map((line, lineIndex) => <pre key={lineIndex}>{line}</pre>)}
          {(item.samplesRedacted || item.textTruncated) && <small>{item.samplesRedacted ? "样本包含整行遮蔽。" : ""} {item.textTruncated ? "样本文本已截断。" : ""}</small>}
        </article>
      ))}
      {result.truncated && <p className="log-analysis-warning" role="status">IOC 结果已按安全边界截断。</p>}
    </section>
  );
}

export function StatusPanel({ label }: { label: string }) {
  return <div className="log-analysis-status" aria-live="polite"><span aria-hidden="true" />{label}</div>;
}

export function ErrorPanel({ message, compact = false }: { message: string; compact?: boolean }) {
  return <div className={compact ? "log-analysis-error is-compact" : "log-analysis-error"} role="alert">{message}</div>;
}

export function EmptyPanel({ title, detail, compact = false }: { title: string; detail: string; compact?: boolean }) {
  return <div className={compact ? "log-analysis-empty is-compact" : "log-analysis-empty"}><strong>{title}</strong><p>{detail}</p></div>;
}
