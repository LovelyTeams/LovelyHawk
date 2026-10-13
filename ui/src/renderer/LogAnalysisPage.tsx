import { useEffect, useMemo, useReducer, useRef, useState, type ReactNode } from "react";

import { targetFailureMessage } from "./target-lost";

import type { EmergencyCommandPathOffer } from "../shared/emergency-command-contract";
import type { FileEvidenceApi } from "../shared/file-evidence-contract";
import { FileEvidenceDialog } from "./FileEvidenceDialog";
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
  isArchivedLog,
  groupLogSources,
  logAnalysisScope,
  logAnalysisTabLabel,
  logEvidenceOffer,
  logSourceKindLabel,
  logThreatLevelLabel,
  parseIocIndicators,
  splitSensitiveSegments,
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
  SparkIcon,
  TagIcon,
} from "./emergency-command-icons";
import { CopyIcon } from "./file-icons";
import { AiAssistPanel, type AiAssistApi } from "./AiAssistPanel";
import type { AiAssistTask } from "../shared/ai-assist-contract";
import { LogRulesDialog } from "./LogRulesDialog";
import {
  logRuleHitCount,
  logRuleSeverityLabel,
  useLogRuleHits,
  type LogRuleHits,
  type LogRulesApi,
} from "./log-rule-hits";
import { LogSourceIcon } from "./log-source-icon";
import {
  buildLogCorrelationReport,
  buildLogIocReport,
  buildLogReadReport,
  type LogReport,
} from "./log-analysis-report";
import {
  createLogAnalysisReadState,
  logAnalysisReadReducer,
  MAX_LOG_PAGE,
  type LogAnalysisStatus,
  type LogAnalysisTab,
  type LogReadFilter,
} from "./log-analysis-read-state";
import "./log-analysis-page.css";

/**
 * What to tell the operator when a page of a log will not come back.
 *
 * Everything but one case is the same sentence, because everything but one
 * case is the same problem. The exception is an archive on a machine with
 * nothing to open it with: that file is readable, it just needs a tool, and
 * saying so is the difference between installing gzip and giving up on the
 * one log holding yesterday's evidence.
 */
export function logReadFailureMessage(reason: unknown): string {
  const text = reason instanceof Error ? reason.message : "";
  if (text.includes("log-analysis-archive-tool-missing")) {
    return "这台目标机上没有 gzip，打不开压缩的归档日志。装上 gzip 再读，"
      + "或者在命令工作台里把它解压到别处。这个文件本身是好的。";
  }
  return logAnalysisFailureMessage(reason, "这一页日志没能读出来。刷新日志源再试一次。");
}

/**
 * What went wrong, in terms of what to do next.
 *
 * The three views used to each list their own causes joined by "or" — "cancelled,
 * or the snapshot expired, or the content was invalid" — which is the page
 * handing its own uncertainty to the operator. Each of these has one action, so
 * each says that action and nothing else.
 */
export function logAnalysisFailureMessage(reason: unknown, fallback: string): string {
  const text = reason instanceof Error ? reason.message : "";
  if (text.includes("log-analysis-binding-unavailable")) {
    return "和这台目标机的连接断了。重新连上再来。";
  }
  if (text.includes("log-analysis-snapshot-unavailable")) {
    return "这份日志源清单比目标机的现状旧了。点「刷新日志源」再试。";
  }
  if (text.includes("log-analysis-capacity")) {
    return "同时在读的日志太多了。等前面的读完，或者关掉一个再来。";
  }
  return targetFailureMessage(reason, fallback);
}

export interface LogAnalysisPageProps {
  bindingHandle: string | null;
  /** A listed log file can be kept as evidence, so the file evidence API comes too. */
  api: LogAnalysisReadApi & FileEvidenceApi & LogRulesApi & AiAssistApi;
  /** Where a copied report goes: the app clipboard, or a test's own. */
  writeClipboard?: (text: string) => Promise<void>;
}

/** What the last copy of a result did, shown beside the button that made it. */
interface CopyNotice {
  tab: LogAnalysisTab;
  text: string;
  failed: boolean;
}

/** The log file being kept, bound to the connection it was listed on. */
interface KeptLog {
  offer: EmergencyCommandPathOffer;
  binding: string;
  returnFocus: HTMLElement | null;
}

const tabs: readonly LogAnalysisTab[] = ["browse", "correlation", "ioc"];
const initialFilter: LogReadFilter = { keyword: "", date: "", journalUnit: "" };

export function LogAnalysisPage({ bindingHandle, api, writeClipboard }: LogAnalysisPageProps) {
  const [state, dispatch] = useReducer(logAnalysisReadReducer, undefined, createLogAnalysisReadState);
  const [copyNotice, setCopyNotice] = useState<CopyNotice | null>(null);
  // Which view's result the AI panel is open for; it closes when that result changes.
  const [aiTab, setAiTab] = useState<LogAnalysisTab | null>(null);
  // The saved match rules: their dialog, and a version that changes with them.
  const [rulesDialog, setRulesDialog] = useState<{ returnFocus: HTMLElement | null } | null>(null);
  const [rulesVersion, setRulesVersion] = useState(0);
  const readHits = useLogRuleHits(api, state.read?.entries ?? null, rulesVersion);
  const correlationHits = useLogRuleHits(api, state.correlation?.entries ?? null, rulesVersion);
  const [snapshotVersion, setSnapshotVersion] = useState(0);
  const [readVersion, setReadVersion] = useState(0);
  const [draftFilter, setDraftFilter] = useState<LogReadFilter>(initialFilter);
  const [queryError, setQueryError] = useState<string | null>(null);
  const [iocDraft, setIocDraft] = useState("");
  const [iocInputError, setIocInputError] = useState<string | null>(null);
  // Collapsing a branch is view state, so it lives with the view.
  const [collapsedKinds, setCollapsedKinds] = useState<readonly LogSourceKind[]>([]);
  const [kept, setKept] = useState<KeptLog | null>(null);
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
    setKept(null);
  }, [scope]);

  // A notice about a copy belongs to the result it copied.
  useEffect(() => {
    setCopyNotice(null);
    setAiTab(null);
  }, [scope, state.read, state.correlation, state.ioc]);

  /**
   * The AI reading of one view's result: the same report the copy makes,
   * within the provider's bound, built only when the panel is opened.
   */
  function aiFor(
    tab: LogAnalysisTab, task: AiAssistTask, what: string, build: (maximumBytes: number) => LogReport,
  ): NonNullable<ResultCopy["ai"]> {
    return {
      open: aiTab === tab,
      onToggle: () => setAiTab((current) => (current === tab ? null : tab)),
      panel: <AiAssistPanel api={api} task={task} what={what} build={build} onClose={() => setAiTab(null)} />,
    };
  }

  /**
   * Copies one result as a plain-text report. The report is built from what
   * the page holds, so it says exactly what was read and under which
   * conditions, and when it does not all fit it says how much was left out.
   */
  async function copyReport(tab: LogAnalysisTab, build: () => LogReport, what: string): Promise<void> {
    try {
      const report = build();
      await (writeClipboard ?? ((value) => window.lovelyhawk.writeClipboard(value)))(report.text);
      setCopyNotice({
        tab,
        failed: false,
        text: report.omitted > 0
          ? `已复制${what}；还有 ${report.omitted} 条超出剪贴板上限，没有复制。`
          : `已复制${what}（纯文本）。`,
      });
    } catch {
      setCopyNotice({ tab, failed: true, text: "复制失败，请再试一次。" });
    }
  }

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
    }).catch((reason: unknown) => {
      if (!cancelled) dispatch({
        type: "snapshot-failed",
        scope,
        request,
        error: "无法列出这台主机上可以读取的日志源。",
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
    }).catch((reason: unknown) => {
      if (!cancelled) dispatch({
        type: "read-failed",
        scope,
        request,
        error: logReadFailureMessage(reason),
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
    }).catch((reason: unknown) => {
      if (activeScopeRef.current === scope) dispatch({
        type: "correlation-failed",
        scope,
        request,
        error: logAnalysisFailureMessage(reason, "多源关联没能跑完。刷新日志源后重新选一次。"),
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
    }).catch((reason: unknown) => {
      if (activeScopeRef.current === scope) dispatch({
        type: "ioc-failed",
        scope,
        request,
        error: logAnalysisFailureMessage(reason, "IOC 搜索没能跑完。刷新日志源后重新选一次。"),
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
          {state.snapshot !== null && <span className="log-analysis-expiry"><ClockIcon />日志源列表约 {
            Math.max(1, Math.ceil(state.snapshot.expiresInSeconds / 60))} 分钟有效</span>}
          <button type="button" className="log-analysis-rules-open" data-testid="log-analysis-rules-open"
            title="管理你自己的匹配规则：读到的日志行命中时会就地标出"
            onClick={(event) => setRulesDialog({ returnFocus: event.currentTarget })}>
            <TagIcon />匹配规则
          </button>
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
        <EmptyPanel title="没有可读日志源" detail="这台主机上没有找到可以读取的日志文件或 journal；可能是没有权限，也可能确实没有。" />
      ) : (
        <div className="log-analysis-workbench">
          <aside className="log-analysis-list" aria-label="可读日志源">
            {(state.snapshot.partial || state.snapshot.truncated) && (
              <p className="log-analysis-warning" role="status">
                {state.snapshot.partial ? logDiscoveryGap(sources) : ""}
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
                  onKeep={bindingHandle === null || logEvidenceOffer(selectedSource) === null ? null : (returnFocus) => {
                    const offer = logEvidenceOffer(selectedSource);
                    if (offer !== null) setKept({ offer, binding: bindingHandle, returnFocus });
                  }}
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
                  hits={readHits}
                  copy={state.read === null || state.read.sourceHandle !== selectedSource.sourceHandle ? null : {
                    notice: copyNotice?.tab === "browse" ? copyNotice : null,
                    onCopy: () => {
                      const result = state.read;
                      if (result === null) return;
                      void copyReport("browse", () => buildLogReadReport({
                        source: selectedSource, filter: state.appliedFilter, result, copiedAt: new Date(), hits: readHits?.hits,
                      }), `本页 ${result.entries.length} 条日志和威胁摘要`);
                    },
                    ai: aiFor("browse", "explain-log", `本页 ${state.read.entries.length} 条日志和威胁摘要`, (maximumBytes) =>
                      buildLogReadReport({
                        source: selectedSource, filter: state.appliedFilter, result: state.read!, copiedAt: new Date(),
                        hits: readHits?.hits, maximumBytes,
                      })),
                  }}
                />
              )
            ) : state.tab === "correlation" ? (
              <CorrelationView
                selected={state.analysisSourceHandles}
                status={state.correlationStatus}
                error={state.correlationError}
                result={state.correlation}
                onRun={runCorrelation}
                hits={correlationHits}
                copy={state.correlation === null ? null : {
                  notice: copyNotice?.tab === "correlation" ? copyNotice : null,
                  onCopy: () => {
                    const result = state.correlation;
                    if (result === null) return;
                    void copyReport("correlation", () => buildLogCorrelationReport({
                      sources: state.snapshot?.sources ?? [], result, copiedAt: new Date(), hits: correlationHits?.hits,
                    }), `关联出的 ${result.entries.length} 条日志和威胁摘要`);
                  },
                  ai: aiFor("correlation", "explain-log", `关联出的 ${state.correlation.entries.length} 条日志和威胁摘要`,
                    (maximumBytes) => buildLogCorrelationReport({
                      sources: state.snapshot?.sources ?? [], result: state.correlation!, copiedAt: new Date(),
                      hits: correlationHits?.hits, maximumBytes,
                    })),
                }}
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
                copy={state.ioc === null ? null : {
                  notice: copyNotice?.tab === "ioc" ? copyNotice : null,
                  onCopy: () => {
                    const result = state.ioc;
                    if (result === null) return;
                    // Changing the selection clears the result, so the
                    // sources selected now are the ones it searched.
                    void copyReport("ioc", () => buildLogIocReport({
                      sources: state.snapshot?.sources ?? [], indicators: state.iocIndicators,
                      sourceHandles: state.analysisSourceHandles, result, copiedAt: new Date(),
                    }), `这次 ${state.iocIndicators.length} 个 IOC 的搜索结果`);
                  },
                  ai: aiFor("ioc", "explain-ioc", `这次 ${state.iocIndicators.length} 个 IOC 的搜索结果`,
                    (maximumBytes) => buildLogIocReport({
                      sources: state.snapshot?.sources ?? [], indicators: state.iocIndicators,
                      sourceHandles: state.analysisSourceHandles, result: state.ioc!, copiedAt: new Date(), maximumBytes,
                    })),
                }}
              />
            )}
          </section>
        </div>
      )}
      {rulesDialog !== null ? <LogRulesDialog api={api} returnFocus={rulesDialog.returnFocus}
        onChanged={() => setRulesVersion((value) => value + 1)} onClose={() => setRulesDialog(null)} /> : null}
      {kept !== null && kept.binding === bindingHandle ? <FileEvidenceDialog
        key={`${kept.binding}:${kept.offer.pathHandle}`} api={api} binding={kept.binding}
        offer={kept.offer} returnFocus={kept.returnFocus} onClose={() => setKept(null)} /> : null}
    </main>
  );
}

/**
 * One kind of log source: a collapsible branch with its own count. In the two
 * analysis views the same rows become a multi-selection, so the operator never
 * has to find the source list twice.
 */
export function LogSourceBranch({ group, collapsed, selecting, selectedHandle, checked, onToggle, onSelect }: {
  group: LogSourceGroup;
  collapsed: boolean;
  selecting: boolean;
  selectedHandle: string | null;
  checked: readonly string[];
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
            // Still clickable while a read is in flight. Locking the whole tree
            // meant that on a slow machine — an RPM target spends eleven seconds
            // on every command — the operator could not change their mind for
            // as long as the read took, and nothing on screen said why. The
            // reducer already discards a result whose request no longer
            // matches, so switching mid-read costs nothing but the wait.
            <button type="button" key={source.sourceHandle} className={active ? "is-selected" : ""}
              aria-pressed={active} disabled={excluded}
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

/** Copying a shown result: null while there is nothing to copy. */
interface ResultCopy {
  notice: CopyNotice | null;
  onCopy(): void;
  /** Asking an AI provider about the same result; absent where it is not offered. */
  ai?: {
    open: boolean;
    onToggle(): void;
    panel: ReactNode;
  };
}

/** The copy button above a result, what its last copy did, and the AI reading of it. */
export function LogResultCopy({ copy }: { copy: ResultCopy }) {
  return (
    <>
      <div className="log-analysis-result-actions">
        <button type="button" className="log-analysis-copy" data-testid="log-analysis-copy"
          title="把这次的结果连同来源、条件和时间复制成纯文本，可以贴进笔记或报告"
          onClick={copy.onCopy}>
          <CopyIcon />复制分析结果
        </button>
        {copy.ai !== undefined ? (
          <button type="button" className="log-analysis-ai" data-testid="log-analysis-ai"
            aria-expanded={copy.ai.open}
            title="把这次的结果发给你在设置里配置的 AI 服务商解读；发送前会说明发什么、发到哪"
            onClick={copy.ai.onToggle}>
            <SparkIcon />AI 解读
          </button>
        ) : null}
        {copy.notice !== null ? (
          <p className={copy.notice.failed ? "is-failed" : undefined} role={copy.notice.failed ? "alert" : "status"}>
            {copy.notice.text}
          </p>
        ) : null}
      </div>
      {copy.ai?.open ? copy.ai.panel : null}
    </>
  );
}

function BrowseView({ source, onKeep, draftFilter, onDraftFilter, queryError, onApply, status, error, result, page, onPage, hits, copy }: {
  source: LogSource;
  /** Null when this source cannot be kept as a file: the journal, or a location shown cut short. */
  onKeep: ((returnFocus: HTMLElement | null) => void) | null;
  draftFilter: LogReadFilter;
  onDraftFilter(value: LogReadFilter): void;
  queryError: string | null;
  onApply(): void;
  status: LogAnalysisStatus;
  error: string | null;
  result: LogSourceReadResult | null;
  page: number;
  onPage(page: number): void;
  hits: LogRuleHits | null;
  copy: ResultCopy | null;
}) {
  return (
    <>
      <header>
        <LogSourceIcon kind={source.kind} />
        <div>
          <h2>{source.displayName || "日志源"}</h2>
          <p>{source.displayLocation || "—"}</p>
        </div>
        {onKeep !== null ? (
          <button type="button" className="log-analysis-keep" data-testid="log-analysis-keep"
            title="把整个日志文件原样下载到案件里，记下来源、时间和校验值"
            onClick={(event) => onKeep(event.currentTarget)}>
            <LockIcon />留存这个日志文件
          </button>
        ) : source.kind === "file" ? (
          <small className="log-analysis-keep-note">位置显示不全，不能从这里留存</small>
        ) : null}
      </header>
      <dl className="log-analysis-facts">
        <div>
          <dt><TagIcon />类型</dt>
          <dd>{logSourceKindLabel(source.kind)}</dd>
        </div>
        <div>
          <dt><ClockIcon />{isArchivedLog(source) ? "压缩后大小" : "大小"}</dt>
          <dd>{formatLogSourceSize(source.sizeBytes)}</dd>
        </div>
        <div>
          <dt><LockIcon />读取方式</dt>
          <dd>{isArchivedLog(source) ? "只读，解压后按页读取" : "只读，按页读取"}</dd>
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
              {copy !== null ? <LogResultCopy copy={copy} /> : null}
              <LogThreatCards summary={result.threatSummary} />
              <LogRuleSummary hits={hits} />
              <LogEntriesView entries={result.entries} hits={hits} empty="当前页没有匹配日志。" />
              <LogPagination page={page} result={result} busy={status === "loading"} onPage={onPage} />
              {result.truncated && <p className="log-analysis-warning" role="status">
                本页文本已按大小上限截断。
              </p>}
            </>
          )}
    </>
  );
}

function CorrelationView({ selected, status, error, result, onRun, hits, copy }: {
  selected: readonly string[];
  status: LogAnalysisStatus;
  error: string | null;
  result: LogCorrelationResult | null;
  onRun(): void;
  hits: LogRuleHits | null;
  copy: ResultCopy | null;
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
              {copy !== null ? <LogResultCopy copy={copy} /> : null}
              <p className="log-analysis-coverage">已观察 {result.totalObserved} 条</p>
              <LogThreatCards summary={result.threatSummary} />
              <LogRuleSummary hits={hits} />
              <LogEntriesView entries={result.entries} hits={hits} empty="没有可展示的关联日志。" />
              {result.truncated && <p className="log-analysis-warning" role="status">
                关联结果不代表未读取范围。
              </p>}
            </>
          )}
    </>
  );
}

function IocView({ selected, draft, onDraft, inputError, status, error, result, onRun, copy }: {
  selected: readonly string[];
  draft: string;
  onDraft(value: string): void;
  inputError: string | null;
  status: LogAnalysisStatus;
  error: string | null;
  result: LogIocSearchResult | null;
  onRun(): void;
  copy: ResultCopy | null;
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
          <EmptyPanel title="尚未搜索 IOC" detail="输入 IOC 并在左侧勾选至少一个文件日志源。" compact /> : (
            <>
              {copy !== null ? <LogResultCopy copy={copy} /> : null}
              <LogIocResultsView result={result} />
            </>
          )}
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
/**
 * Which half of the discovery came back empty-handed, said plainly. Files and
 * the journal are probed separately and one may fail alone; "some sources
 * failed" alarmed on every machine without journald and said nothing of what was
 * missing.
 */
export function logDiscoveryGap(sources: readonly { kind: "file" | "journal" }[]): string {
  const files = sources.some((source) => source.kind === "file");
  const journal = sources.some((source) => source.kind === "journal");
  if (files && !journal) return "没有读到 journal（这台主机可能没有 systemd-journald，或当前账号无权读取），下面只列出日志文件。";
  if (journal && !files) return "没能列出日志文件，下面只有 journal；可以稍后刷新重试。";
  return "有一部分日志源没能列出，下面不是全部；可以稍后刷新重试。";
}

/**
 * What to show in front of a log line: only what the line itself does not
 * already say. The parsed time, level and service used to be printed before
 * every line that already started with them, and for formats the parser does
 * not know they were wrong as well (a "service" of `with`). The line itself is
 * the evidence and is always shown whole; the source name stays when lines
 * from several logs are mixed.
 */
export function logLineMeta(entry: PublicLogEntry): { kind: "time" | "level" | "service" | "source"; text: string }[] {
  const line = entry.rawText || entry.message || "";
  const adds = (value: string) => value !== "" && !line.includes(value);
  const meta: { kind: "time" | "level" | "service" | "source"; text: string }[] = [];
  if (adds(entry.timestamp)) meta.push({ kind: "time", text: entry.timestamp });
  // INFO is also what the parser says when a line names no level at all.
  if (adds(entry.level) && entry.level.toUpperCase() !== "INFO") meta.push({ kind: "level", text: entry.level });
  if (adds(entry.service)) meta.push({ kind: "service", text: entry.service });
  if (entry.sourceName !== null && entry.sourceName !== "") meta.push({ kind: "source", text: entry.sourceName });
  return meta;
}

/** How many of the shown lines the operator's own rules marked, said once above them. */
export function LogRuleSummary({ hits }: { hits: LogRuleHits | null }) {
  if (hits === null || (!hits.failed && hits.ruleCount === 0)) return null;
  if (hits.failed) {
    return <p className="log-analysis-rule-summary is-failed" role="status">没能用匹配规则比对这些行，下面的行没有规则标记。</p>;
  }
  const count = logRuleHitCount(hits);
  return (
    <p className="log-analysis-rule-summary" role="status" data-testid="log-analysis-rule-summary">
      {count === 0
        ? `这些行没有命中你的 ${hits.ruleCount} 条匹配规则。`
        : `${count} 行命中你的匹配规则，已在行首标出。`}
    </p>
  );
}

export function LogEntriesView({ entries, empty, hits = null }: {
  entries: readonly PublicLogEntry[];
  empty: string;
  /** The operator's rules, matched against these same lines, one answer per line. */
  hits?: LogRuleHits | null;
}) {
  if (entries.length === 0) {
    return <EmptyPanel title={empty} detail="空结果不代表未调查范围没有事件。" compact />;
  }
  const lineClass = (entry: PublicLogEntry, index: number): string | undefined => {
    const names = [entry.highlighted ? "is-abnormal" : "", hits?.hits[index] ? "has-rule" : ""].filter(Boolean);
    return names.length === 0 ? undefined : names.join(" ");
  };
  return (
    <div className="log-analysis-output">
      <span className="log-analysis-gutter" aria-hidden="true">
        {entries.map((entry, index) => <span key={`${entry.timestamp}\0${index}`}
          className={lineClass(entry, index)}>{index + 1}</span>)}
      </span>
      <div className="log-analysis-lines">
        {entries.map((entry, index) => {
          const meta = logLineMeta(entry);
          const hit = hits?.hits[index] ?? null;
          return (
            <p key={`${entry.timestamp}\0${index}`} className={lineClass(entry, index)}>
              {hit === null ? null : (
                <span className={`log-analysis-rule-hit is-${hit.severity}`} data-testid="log-analysis-rule-hit"
                  title={`命中你的规则「${hit.name}」，级别${logRuleSeverityLabel(hit.severity)}`}>
                  {hit.name}
                </span>
              )}
              {meta.length === 0 ? null : (
                <span className="log-analysis-line-meta">
                  {meta.map((item) => item.kind === "time"
                    ? <time key={item.kind}>{item.text}</time>
                    : item.kind === "level" ? <em key={item.kind}>{item.text}</em> : <span key={item.kind}>{item.text}</span>)}
                </span>
              )}
              <span className="log-analysis-line-text">
                <LogLineText text={entry.rawText || entry.message || "—"} />
              </span>
              {entry.textTruncated && <small>文本已截断。</small>}
            </p>
          );
        })}
      </div>
    </div>
  );
}

/**
 * Paging that says where you are and lets you go somewhere else.
 *
 * The count is derived from the paging rather than asked for: an exact total
 * up front would mean scanning the whole log a second time on every page, and
 * on a busy machine that is the expensive half of the request. So it is stated as
 * a floor until the last page is reached, where it becomes exact — and it says
 * which of the two it is instead of printing a number that might be either.
 */
export function LogPagination({ page, result, busy, onPage }: {
  page: number;
  result: LogSourceReadResult;
  busy: boolean;
  onPage(page: number): void;
}) {
  const [draft, setDraft] = useState("");
  const seen = (page - 1) * result.pageSize + result.entryCount;
  const jump = () => {
    const wanted = Number.parseInt(draft.trim(), 10);
    if (!Number.isSafeInteger(wanted) || wanted < 1 || wanted > MAX_LOG_PAGE) return;
    setDraft("");
    onPage(wanted);
  };
  return (
    <div className="log-analysis-pagination">
      <button type="button" disabled={page <= 1 || busy} onClick={() => onPage(1)}>首页</button>
      <button type="button" disabled={page <= 1 || busy}
        onClick={() => onPage(page - 1)}>上一页</button>
      <span data-testid="log-pagination-summary">
        第 {page} 页 · 本页 {result.entryCount} 条 ·{" "}
        {result.hasMore ? `已翻出 ${seen} 条，后面还有` : `共 ${seen} 条`}
      </span>
      <button type="button" disabled={!result.hasMore || busy || page >= MAX_LOG_PAGE}
        onClick={() => onPage(page + 1)}>下一页</button>
      <label className="log-analysis-jump">
        跳至
        <input
          value={draft}
          inputMode="numeric"
          maxLength={5}
          placeholder={String(page)}
          aria-label="跳转到页码"
          disabled={busy}
          onChange={(event) => setDraft(event.target.value.replace(/[^0-9]/gu, ""))}
          onKeyDown={(event) => {
            if (event.key === "Enter") {
              event.preventDefault();
              jump();
            }
          }}
        />
        页
      </label>
      <button type="button" disabled={busy || draft.trim() === ""} onClick={jump}>跳转</button>
    </div>
  );
}

/**
 * One log line, with the parts worth finding again marked in place.
 *
 * Nothing is removed or masked — a log is evidence, and the marks only say
 * where to look first. The text is still exactly what the target sent.
 */
function LogLineText({ text }: { text: string }) {
  const segments = useMemo(() => splitSensitiveSegments(text), [text]);
  return (
    <>
      {segments.map((segment, index) => segment.kind === null
        ? <span key={index}>{segment.text}</span>
        : <mark key={index} className={`log-analysis-mark is-${segment.kind}`}>{segment.text}</mark>)}
    </>
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
