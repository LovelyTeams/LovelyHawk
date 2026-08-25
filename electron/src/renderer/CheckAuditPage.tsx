import { useEffect, useReducer, useRef, useState } from "react";

import {
  isCheckAuditCatalog,
  isCheckAuditLogResult,
  isCheckAuditStatus,
  type CheckAuditCatalog,
  type CheckAuditLogEntry,
  type CheckAuditLogResult,
  type CheckAuditReadApi,
  type CheckAuditStatus,
} from "../shared/check-audit-read-contract";
import {
  buildCheckAuditLogInput,
  checkAuditCategoryLabel,
  checkAuditIntervalLabel,
  checkAuditScope,
  checkAuditSeverityLabel,
  checkAuditStateLabel,
  checkAuditTabLabel,
  filterCheckAuditCommands,
  normalizeCustomAuditCommand,
} from "./check-audit-read-helpers";
import {
  checkAuditReadReducer,
  createCheckAuditReadState,
  type CheckAuditStatusKind,
  type CheckAuditTab,
} from "./check-audit-read-state";
import "./check-audit-page.css";

export interface CheckAuditPageProps {
  bindingHandle: string | null;
  api: CheckAuditReadApi;
}

const tabs: readonly CheckAuditTab[] = ["commands", "logs", "analysis", "suggestions"];

export function CheckAuditPage({ bindingHandle, api }: CheckAuditPageProps) {
  const [state, dispatch] = useReducer(checkAuditReadReducer, undefined, createCheckAuditReadState);
  const [customCommands, setCustomCommands] = useState<string[]>([]);
  const [customDraft, setCustomDraft] = useState("");
  const [customError, setCustomError] = useState<string | null>(null);
  const [logSearchDraft, setLogSearchDraft] = useState("");
  const [logLimitDraft, setLogLimitDraft] = useState(200);
  const [logInputError, setLogInputError] = useState<string | null>(null);
  const [catalogVersion, setCatalogVersion] = useState(0);
  const [statusVersion, setStatusVersion] = useState(0);
  const [logVersion, setLogVersion] = useState(0);
  const requestRef = useRef(0);
  const scope = bindingHandle === null ? null : checkAuditScope(bindingHandle);
  const customKey = customCommands.join("\0");

  useEffect(() => {
    dispatch({ type: "scope-changed", scope });
    setCustomError(null);
    setLogInputError(null);
  }, [scope]);

  useEffect(() => {
    if (scope === null || bindingHandle === null || state.scope !== scope) return;
    const request = ++requestRef.current;
    let cancelled = false;
    dispatch({ type: "catalog-started", scope, request });
    void api.getCheckAuditCatalog(bindingHandle, { customCommandNames: [...customCommands] }).then((result) => {
      if (cancelled) return;
      if (!isCheckAuditCatalog(result)) throw new Error();
      dispatch({ type: "catalog-loaded", scope, request, catalog: result });
    }).catch(() => {
      if (!cancelled) dispatch({
        type: "catalog-failed",
        scope,
        request,
        error: "命令审计目录无效、目标已变化或当前绑定不可用。",
      });
    });
    return () => {
      cancelled = true;
    };
  }, [api, bindingHandle, catalogVersion, customKey, scope, state.scope]);

  const snapshotHandle = state.catalog?.snapshotHandle ?? null;

  useEffect(() => {
    if (scope === null || bindingHandle === null || snapshotHandle === null ||
      state.scope !== scope || state.tab !== "commands") return;
    const request = { id: ++requestRef.current, snapshotHandle };
    let cancelled = false;
    dispatch({ type: "status-started", scope, request });
    void api.collectCheckAuditStatus(bindingHandle, snapshotHandle).then((result) => {
      if (cancelled) return;
      if (!isCheckAuditStatus(result) || result.snapshotHandle !== snapshotHandle) throw new Error();
      dispatch({ type: "status-loaded", scope, request, status: result });
    }).catch(() => {
      if (!cancelled) dispatch({
        type: "status-failed",
        scope,
        request,
        error: "无法采集当前目录的命令状态；快照可能已过期或权限不足。",
      });
    });
    return () => {
      cancelled = true;
    };
  }, [api, bindingHandle, scope, snapshotHandle, state.scope, state.tab, statusVersion]);

  useEffect(() => {
    if (scope === null || bindingHandle === null || snapshotHandle === null ||
      state.scope !== scope || state.tab === "commands") return;
    const request = { id: ++requestRef.current, snapshotHandle, input: { ...state.logInput } };
    let cancelled = false;
    dispatch({ type: "log-started", scope, request });
    void api.readCheckAuditLog(bindingHandle, snapshotHandle, request.input).then((result) => {
      if (cancelled) return;
      if (!isCheckAuditLogResult(result) || result.snapshotHandle !== snapshotHandle ||
        result.limit !== request.input.limit) throw new Error();
      dispatch({ type: "log-loaded", scope, request, result });
    }).catch(() => {
      if (!cancelled) dispatch({
        type: "log-failed",
        scope,
        request,
        error: "无法读取审计日志：快照可能已过期，或权限不足。",
      });
    });
    return () => {
      cancelled = true;
    };
  }, [
    api,
    bindingHandle,
    logVersion,
    scope,
    snapshotHandle,
    state.logInput.limit,
    state.logInput.search,
    state.scope,
    state.tab,
  ]);

  if (bindingHandle === null) {
    return (
      <main className="check-audit-page check-audit-disconnected">
        <h1>命令审计</h1>
        <p>连接 SSH 目标后，可只读调查固定命令目录、审计日志、周期行为与建议。</p>
      </main>
    );
  }

  const current = state.scope === scope;
  const addCustom = () => {
    const result = normalizeCustomAuditCommand(customDraft, customCommands);
    setCustomError(result.error);
    if (result.name === null) return;
    setCustomCommands((names) => [...names, result.name!].sort());
    setCustomDraft("");
  };

  const applyLogInput = () => {
    const result = buildCheckAuditLogInput(logLimitDraft, logSearchDraft);
    setLogInputError(result.error);
    if (result.input === null) return;
    dispatch({ type: "log-input-applied", input: result.input });
    setLogVersion((value) => value + 1);
  };

  return (
    <main className="check-audit-page">
      <header className="check-audit-header">
        <div>
          <p className="check-audit-kicker">只读</p>
          <h1>命令审计</h1>
          <p className="check-audit-target">当前 target-bound SSH 绑定</p>
        </div>
        <div className="check-audit-header-actions">
          {state.catalog !== null && <span>目录约 {Math.max(1, Math.ceil(state.catalog.expiresInSeconds / 60))} 分钟有效</span>}
          <button type="button" disabled={!current || state.catalogStatus === "loading"}
            onClick={() => setCatalogVersion((value) => value + 1)}>
            {state.catalogStatus === "loading" ? "刷新中…" : "刷新目录"}
          </button>
        </div>
      </header>
      <p className="check-audit-readonly-banner">
        本页只采集状态并分析既有日志。建议仅展示说明，不包含可执行命令或后台动作。
      </p>
      {!current || state.catalogStatus === "loading" && state.catalog === null ? (
        <StatusPanel label="正在建立目标绑定的命令目录…" />
      ) : state.catalogStatus === "error" ? (
        <ErrorPanel message={state.catalogError ?? "命令目录不可用。"} />
      ) : state.catalog === null ? (
        <EmptyPanel title="命令目录不可用" detail="刷新目录后重试。" />
      ) : (
        <>
          <nav className="check-audit-tabs" aria-label="命令审计视图">
            {tabs.map((tab) => <button key={tab} type="button" className={state.tab === tab ? "is-active" : ""}
              aria-current={state.tab === tab ? "page" : undefined}
              onClick={() => dispatch({ type: "tab-selected", tab })}>{checkAuditTabLabel(tab)}</button>)}
          </nav>
          <section className="check-audit-content">
            {state.tab === "commands" && (
              <CommandsView
                catalog={state.catalog}
                statusKind={state.statusStatus}
                status={state.status}
                error={state.statusError}
                search={state.commandSearch}
                selectedName={state.selectedCommandName}
                customCommands={customCommands}
                customDraft={customDraft}
                customError={customError}
                onSearch={(value) => dispatch({ type: "command-search-changed", value })}
                onSelect={(name) => dispatch({ type: "command-selected", name })}
                onCustomDraft={setCustomDraft}
                onAddCustom={addCustom}
                onRemoveCustom={(name) => setCustomCommands((names) => names.filter((value) => value !== name))}
                onRefresh={() => setStatusVersion((value) => value + 1)}
              />
            )}
            {state.tab === "logs" && (
              <LogsView
                status={state.logStatus}
                result={state.log}
                error={state.logError}
                searchDraft={logSearchDraft}
                limitDraft={logLimitDraft}
                inputError={logInputError}
                onSearchDraft={setLogSearchDraft}
                onLimitDraft={setLogLimitDraft}
                onApply={applyLogInput}
                onRefresh={() => setLogVersion((value) => value + 1)}
              />
            )}
            {state.tab === "analysis" && (
              <AnalysisView status={state.logStatus} result={state.log} error={state.logError}
                onRefresh={() => setLogVersion((value) => value + 1)} />
            )}
            {state.tab === "suggestions" && (
              <SuggestionsView status={state.logStatus} result={state.log} error={state.logError}
                onRefresh={() => setLogVersion((value) => value + 1)} />
            )}
          </section>
        </>
      )}
    </main>
  );
}

export function CommandsView({ catalog, statusKind, status, error, search, selectedName, customCommands,
  customDraft, customError, onSearch, onSelect, onCustomDraft, onAddCustom, onRemoveCustom, onRefresh }: {
  catalog: CheckAuditCatalog;
  statusKind: CheckAuditStatusKind;
  status: CheckAuditStatus | null;
  error: string | null;
  search: string;
  selectedName: string | null;
  customCommands: readonly string[];
  customDraft: string;
  customError: string | null;
  onSearch(value: string): void;
  onSelect(name: string): void;
  onCustomDraft(value: string): void;
  onAddCustom(): void;
  onRemoveCustom(name: string): void;
  onRefresh(): void;
}) {
  const visible = filterCheckAuditCommands(catalog.commands, search);
  const byHandle = new Map(status?.commands.map((command) => [command.commandHandle, command]) ?? []);
  return (
    <>
      <ViewHeader title="命令状态" detail={`${catalog.commands.length} 个目录项 · ${status?.isRoot ? "root 会话" : "普通会话或尚未确认"}`}
        loading={statusKind === "loading"} onRefresh={onRefresh} />
      <div className="check-audit-command-tools">
        <label>搜索目录<input value={search} maxLength={128} onChange={(event) => onSearch(event.target.value)} /></label>
        <form onSubmit={(event) => { event.preventDefault(); onAddCustom(); }}>
          <label>自定义命令名<input value={customDraft} maxLength={128} placeholder="例如 openssl"
            onChange={(event) => onCustomDraft(event.target.value)} /></label>
          <button type="submit">添加到本地目录</button>
        </form>
      </div>
      {customError !== null && <p className="check-audit-inline-error" role="alert">{customError}</p>}
      {customCommands.length > 0 && <div className="check-audit-custom-list" aria-label="自定义命令">
        {customCommands.map((name) => <span key={name}>{name}<button type="button" aria-label={`移除 ${name}`}
          onClick={() => onRemoveCustom(name)}>×</button></span>)}
      </div>}
      {statusKind === "loading" && status === null ? <StatusPanel label="正在采集目标命令状态…" /> :
        statusKind === "error" ? <ErrorPanel message={error ?? "命令状态采集失败。"} compact /> :
          visible.length === 0 ? <EmptyPanel title="没有匹配目录项" detail="调整命令搜索文本。" compact /> : (
            <div className="check-audit-command-list">{visible.map((item) => {
              const current = byHandle.get(item.commandHandle);
              return <button type="button" key={item.commandHandle} className={selectedName === item.name ? "is-selected" : ""}
                aria-pressed={selectedName === item.name} onClick={() => onSelect(item.name)}>
                <span><strong>{item.name}</strong>{item.isDefault ? <small>默认</small> : <small>自定义</small>}</span>
                <span>{current === undefined ? "等待采集" : checkAuditStateLabel(current.state)}</span>
                <span>{item.critical ? "关键命令" : "普通命令"}</span>
                <span>{current?.displayLocation ?? "—"}</span>
                {(current?.locationRedacted || current?.textTruncated) && <small>位置已遮蔽或截断。</small>}
              </button>;
            })}</div>
          )}
      {(status?.truncated || status !== null && status.redactedFieldCount > 0) && <TruncatedNotice>
        状态文本已按安全边界截断或遮蔽。
      </TruncatedNotice>}
    </>
  );
}

function LogsView({ status, result, error, searchDraft, limitDraft, inputError, onSearchDraft, onLimitDraft,
  onApply, onRefresh }: {
  status: CheckAuditStatusKind;
  result: CheckAuditLogResult | null;
  error: string | null;
  searchDraft: string;
  limitDraft: number;
  inputError: string | null;
  onSearchDraft(value: string): void;
  onLimitDraft(value: number): void;
  onApply(): void;
  onRefresh(): void;
}) {
  return <>
    <ViewHeader title="审计日志" detail="手动读取最新的日志片段。" loading={status === "loading"} onRefresh={onRefresh} />
    <form className="check-audit-log-query" onSubmit={(event) => { event.preventDefault(); onApply(); }}>
      <label>搜索<input value={searchDraft} maxLength={256} placeholder="命令、参数、用户或调用者"
        onChange={(event) => onSearchDraft(event.target.value)} /></label>
      <label>读取上限<select value={limitDraft} onChange={(event) => onLimitDraft(Number(event.target.value))}>
        <option value={50}>50</option><option value={100}>100</option><option value={200}>200</option>
      </select></label>
      <button className="check-audit-primary" type="submit" disabled={status === "loading"}>应用并读取</button>
    </form>
    {inputError !== null && <p className="check-audit-inline-error" role="alert">{inputError}</p>}
    {status === "loading" && result === null ? <StatusPanel label="正在读取审计日志…" /> :
      status === "error" ? <ErrorPanel message={error ?? "审计日志读取失败。"} compact /> : result === null ?
        <EmptyPanel title="尚未读取日志" detail="手动刷新或应用搜索条件。" compact /> : <>
          <div className="check-audit-log-summary">
            <article><strong>{result.fetchedCount}</strong><span>读取窗口</span></article>
            <article><strong>{result.matchedCount}</strong><span>搜索匹配</span></article>
            <article><strong>{result.matchedSuspiciousCount}</strong><span>匹配中的可疑项</span></article>
            <article><strong>{result.redactedFieldCount}</strong><span>遮蔽字段</span></article>
          </div>
          {result.commandCounts.length > 0 && <div className="check-audit-counts">{result.commandCounts.map((item, index) =>
            <span key={`${item.command}\0${index}`}>{item.command || "—"} · {item.count}</span>)}</div>}
          <AuditLogEntries entries={result.entries} />
          {(result.truncated || result.redactedFieldCount > 0) && <TruncatedNotice>
            结果可能已截断；credential-like 字段已遮蔽，隐藏范围不表示安全。
          </TruncatedNotice>}
        </>}
  </>;
}

export function AuditLogEntries({ entries }: { entries: readonly CheckAuditLogEntry[] }) {
  if (entries.length === 0) return <EmptyPanel title="没有匹配日志" detail="本次读取未返回匹配项。" compact />;
  return <div className="check-audit-log-list">{entries.map((entry, index) => <article
    className={entry.suspicious ? "is-suspicious" : ""} key={`${entry.timestamp}\0${index}`}>
    <header><time>{entry.timestamp || "—"}</time><strong>{entry.command || "—"}</strong><span>{entry.user || "—"}</span>
      <span>PID {entry.pid} / PPID {entry.ppid}</span><span>{entry.caller || "—"}</span></header>
    <pre>{entry.args}</pre>
    {(entry.redacted || entry.textTruncated) && <small>{entry.redacted ? "字段已遮蔽。" : ""} {entry.textTruncated ? "文本已截断。" : ""}</small>}
  </article>)}</div>;
}

export function AnalysisView({ status, result, error, onRefresh }: {
  status: CheckAuditStatusKind;
  result: CheckAuditLogResult | null;
  error: string | null;
  onRefresh(): void;
}) {
  return <>
    <ViewHeader title="周期分析" detail="对最新日志片段做分组与周期推导。" loading={status === "loading"} onRefresh={onRefresh} />
    {status === "loading" && result === null ? <StatusPanel label="正在读取并分析日志…" /> :
      status === "error" ? <ErrorPanel message={error ?? "周期分析不可用。"} compact /> :
        result === null || result.cycles.length === 0 ? <EmptyPanel title="没有识别到周期行为"
          detail="至少需要同一命令与参数的多次记录；空结果不代表没有未采集行为。" compact /> :
          <div className="check-audit-cycle-list">{result.cycles.map((cycle, index) => <article key={`${cycle.command}\0${cycle.args}\0${index}`}>
            <header><strong>{cycle.command || "—"}</strong><span>{checkAuditCategoryLabel(cycle.category)}</span><span>{cycle.count} 次</span></header>
            <pre>{cycle.args}</pre>
            <p>{checkAuditIntervalLabel(cycle.intervalSeconds)} · 最后出现 {cycle.lastSeen || "—"}</p>
            {(cycle.redacted || cycle.textTruncated) && <small>分析文本已遮蔽或截断。</small>}
          </article>)}</div>}
  </>;
}

export function SuggestionsView({ status, result, error, onRefresh }: {
  status: CheckAuditStatusKind;
  result: CheckAuditLogResult | null;
  error: string | null;
  onRefresh(): void;
}) {
  return <>
    <ViewHeader title="调查建议" detail="只展示说明文本，不会下发或复制任何命令。" loading={status === "loading"} onRefresh={onRefresh} />
    {status === "loading" && result === null ? <StatusPanel label="正在生成只读建议…" /> :
      status === "error" ? <ErrorPanel message={error ?? "调查建议不可用。"} compact /> :
        result === null || result.suggestions.length === 0 ? <EmptyPanel title="没有生成建议"
          detail="当前日志片段没有足够的周期证据。" compact /> :
          <div className="check-audit-suggestion-list">{result.suggestions.map((suggestion, index) => <article
            className={`severity-${suggestion.severity}`} key={`${suggestion.title}\0${index}`}>
            <header><strong>{suggestion.title || "—"}</strong><span>{checkAuditSeverityLabel(suggestion.severity)}</span></header>
            <p>{suggestion.description || "—"}</p>
            {(suggestion.redacted || suggestion.textTruncated) && <small>建议文本已遮蔽或截断。</small>}
          </article>)}</div>}
  </>;
}

function ViewHeader({ title, detail, loading, onRefresh }: {
  title: string;
  detail: string;
  loading: boolean;
  onRefresh(): void;
}) {
  return <div className="check-audit-view-header"><div><h2>{title}</h2><p>{detail}</p></div>
    <button type="button" disabled={loading} onClick={onRefresh}>{loading ? "刷新中…" : "手动刷新"}</button></div>;
}

export function StatusPanel({ label }: { label: string }) {
  return <div className="check-audit-status-panel" aria-live="polite"><span aria-hidden="true" />{label}</div>;
}

export function ErrorPanel({ message, compact = false }: { message: string; compact?: boolean }) {
  return <div className={compact ? "check-audit-error is-compact" : "check-audit-error"} role="alert">{message}</div>;
}

export function EmptyPanel({ title, detail, compact = false }: { title: string; detail: string; compact?: boolean }) {
  return <div className={compact ? "check-audit-empty is-compact" : "check-audit-empty"}><strong>{title}</strong><p>{detail}</p></div>;
}

function TruncatedNotice({ children }: { children: string }) {
  return <p className="check-audit-warning" role="status">{children}</p>;
}
