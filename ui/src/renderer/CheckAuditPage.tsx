import { TransientNotice } from "./NotificationCenter";
import { createContext, useContext, useEffect, useReducer, useRef, useState } from "react";

import { targetFailureMessage } from "./target-lost";

import {
  isCheckAuditCatalog,
  isCheckAuditLogResult,
  isCheckAuditStatus,
  type CheckAuditCatalog,
  type CheckAuditLogEntry,
  type CheckAuditLogResult,
  type CheckAuditLogState,
  type CheckAuditReadApi,
  type CheckAuditStatus,
} from "../shared/check-audit-read-contract";
import {
  buildCheckAuditLogInput,
  checkAuditCategoryLabel,
  CHECK_AUDIT_COPY_MAX_BYTES,
  checkAuditIntervalLabel,
  checkAuditLogStateText,
  checkAuditLogTsv,
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
import { useListExpiry } from "./use-list-expiry";
import type { CheckAuditWriteApi } from "../shared/check-audit-write-contract";
import { CheckAuditActions } from "./CheckAuditActions";
import { DialogHost } from "./DialogHost";
import { useConfirmDialog } from "./use-confirm-dialog";
import "./check-audit-page.css";

export interface CheckAuditPageProps {
  bindingHandle: string | null;
  /** Reads, and — when given — the plan/confirm/run of collection changes. */
  api: CheckAuditReadApi & Partial<CheckAuditWriteApi>;
  /** Writes to the system clipboard; copying is offered only when it is given. */
  writeClipboard?: (text: string) => Promise<void>;
}

type CopyNotice = { ok: boolean; text: string } | null;

const tabs: readonly CheckAuditTab[] = ["commands", "logs", "analysis", "suggestions"];

export function CheckAuditPage({ bindingHandle, api, writeClipboard }: CheckAuditPageProps) {
  const [state, dispatch] = useReducer(checkAuditReadReducer, undefined, createCheckAuditReadState);
  const { dialog, ask, resolve } = useConfirmDialog();
  const writeApi = isWriteApi(api) ? api : null;
  const [copyNotice, setCopyNotice] = useState<CopyNotice>(null);
  // A second click while the clipboard write is out would copy twice.
  const copying = useRef(false);
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
  // The snapshot is good for a fixed time from when it was read; reads do not
  // extend it. Once it is past, reads are refused, so none are sent: the
  // views say so and the way forward is reading a new list.
  const [refusedSnapshot, setRefusedSnapshot] = useState<string | null>(null);
  const expiry = useListExpiry(state.catalog, state.catalog?.expiresInSeconds ?? null);
  const catalogExpired = state.catalog !== null &&
    (expiry.expired || refusedSnapshot === state.catalog.snapshotHandle);
  // Read inside the read effects, not listed as their dependency: the moment
  // of expiry must not cancel a read already on its way.
  const expiredRef = useRef(catalogExpired);
  expiredRef.current = catalogExpired;
  const noteRefusal = (reason: unknown, snapshot: string) => {
    if (String(reason instanceof Error ? reason.message : reason).includes("check-audit-catalog-unavailable")) {
      setRefusedSnapshot(snapshot);
    }
  };

  useEffect(() => {
    dispatch({ type: "scope-changed", scope });
    setCustomError(null);
    setLogInputError(null);
    setCopyNotice(null);
  }, [scope]);

  // What a copy notice speaks of is the log on screen; a new read replaces it.
  useEffect(() => {
    setCopyNotice(null);
  }, [state.log]);

  useEffect(() => {
    if (scope === null || bindingHandle === null || state.scope !== scope) return;
    const request = ++requestRef.current;
    let cancelled = false;
    dispatch({ type: "catalog-started", scope, request });
    void api.getCheckAuditCatalog(bindingHandle, { customCommandNames: [...customCommands] }).then((result) => {
      if (cancelled) return;
      if (!isCheckAuditCatalog(result)) throw new Error();
      dispatch({ type: "catalog-loaded", scope, request, catalog: result });
    }).catch((reason: unknown) => {
      if (!cancelled) dispatch({
        type: "catalog-failed",
        scope,
        request,
        error: targetFailureMessage(reason, "命令审计目录无效、目标已切换或当前连接不可用。"),
      });
    });
    return () => {
      cancelled = true;
    };
  }, [api, bindingHandle, catalogVersion, customKey, scope, state.scope]);

  const snapshotHandle = state.catalog?.snapshotHandle ?? null;

  useEffect(() => {
    if (scope === null || bindingHandle === null || snapshotHandle === null ||
      state.scope !== scope || state.tab !== "commands" || expiredRef.current) return;
    const request = { id: ++requestRef.current, snapshotHandle };
    let cancelled = false;
    dispatch({ type: "status-started", scope, request });
    void api.collectCheckAuditStatus(bindingHandle, snapshotHandle).then((result) => {
      if (cancelled) return;
      if (!isCheckAuditStatus(result) || result.snapshotHandle !== snapshotHandle) throw new Error();
      dispatch({ type: "status-loaded", scope, request, status: result });
    }).catch((reason: unknown) => {
      if (!cancelled) noteRefusal(reason, snapshotHandle);
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
      state.scope !== scope || state.tab === "commands" || expiredRef.current) return;
    const request = { id: ++requestRef.current, snapshotHandle, input: { ...state.logInput } };
    let cancelled = false;
    dispatch({ type: "log-started", scope, request });
    void api.readCheckAuditLog(bindingHandle, snapshotHandle, request.input).then((result) => {
      if (cancelled) return;
      if (!isCheckAuditLogResult(result) || result.snapshotHandle !== snapshotHandle ||
        result.limit !== request.input.limit) throw new Error();
      dispatch({ type: "log-loaded", scope, request, result });
    }).catch((reason: unknown) => {
      if (!cancelled) noteRefusal(reason, snapshotHandle);
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

  const copyLog = async (result: CheckAuditLogResult) => {
    if (writeClipboard === undefined || copying.current) return;
    const text = checkAuditLogTsv(result.entries);
    if (new TextEncoder().encode(text).byteLength > CHECK_AUDIT_COPY_MAX_BYTES) {
      setCopyNotice({ ok: false, text: "显示的记录超过剪贴板一次能放的 128 KB，没有复制。请用搜索或读取上限缩小范围后再复制。" });
      return;
    }
    copying.current = true;
    try {
      await writeClipboard(text);
      setCopyNotice({ ok: true, text: `已复制显示的 ${result.entries.length} 条（制表符分隔）${result.displayedCount < result.matchedCount ? `；匹配的共 ${result.matchedCount} 条，其余没有显示也没有复制` : ""}。` });
    } catch {
      setCopyNotice({ ok: false, text: "没能写入剪贴板，没有复制。" });
    } finally {
      copying.current = false;
    }
  };

  return (
    <main className="check-audit-page">
      <header className="check-audit-header">
        <div>
          <p className="check-audit-kicker">{writeApi === null ? "只读" : "排查与采集"}</p>
          <h1>命令审计</h1>
          <p className="check-audit-target">看常用命令实际执行的是哪个文件，以及本工具留下的命令记录。</p>
        </div>
        <div className="check-audit-header-actions">
          {state.catalog !== null && (catalogExpired
            ? <span className="check-audit-expiry is-expired" data-testid="check-audit-expired">命令列表已过期</span>
            : <span className="check-audit-expiry" title="从读取命令列表时算起；到时再读取会被拒绝，点“刷新命令列表”即可继续。">
              命令列表约 {expiry.minutesLeft ?? Math.max(1, Math.ceil(state.catalog.expiresInSeconds / 60))} 分钟内有效
            </span>)}
          <button type="button" className={catalogExpired ? "is-attention" : undefined}
            disabled={!current || state.catalogStatus === "loading"}
            onClick={() => setCatalogVersion((value) => value + 1)}>
            {state.catalogStatus === "loading" ? "刷新中…" : "刷新命令列表"}
          </button>
        </div>
      </header>
      <p className="check-audit-readonly-banner">
        {writeApi === null
          ? "本页只读：查看命令状态和已有的命令记录，不会运行这些命令，也不会改动目标。"
          : "查看命令状态和已有的命令记录不会运行这些命令，也不会改动目标；加采集、移除采集和清空日志会改动目标，每次都先列出计划，确认后才执行并读回核对。"}
      </p>
      {catalogExpired && state.catalog !== null ? (
        <p className="check-audit-expired-notice" role="status">
          命令列表读取已超过 {Math.max(1, Math.round(state.catalog.expiresInSeconds / 60))} 分钟，已经过期，现在读取状态或日志会被拒绝。
          点右上角的“刷新命令列表”重新读取；已显示的内容仍可查看。
        </p>
      ) : null}
      {!current || state.catalogStatus === "loading" && state.catalog === null ? (
        <StatusPanel label="正在读取当前目标的命令目录…" />
      ) : state.catalogStatus === "error" ? (
        <ErrorPanel message={state.catalogError ?? "命令目录不可用。"} />
      ) : state.catalog === null ? (
        <EmptyPanel title="命令列表不可用" detail="点“刷新命令列表”重试。" />
      ) : (
        <CatalogExpired.Provider value={catalogExpired}>
          <nav className="check-audit-tabs" aria-label="命令审计视图">
            {tabs.map((tab) => <button key={tab} type="button" className={state.tab === tab ? "is-active" : ""}
              aria-current={state.tab === tab ? "page" : undefined}
              onClick={() => dispatch({ type: "tab-selected", tab })}>{checkAuditTabLabel(tab)}</button>)}
          </nav>
          {writeApi !== null && current && bindingHandle !== null &&
            (state.tab === "commands" || state.tab === "logs") ? (
              <CheckAuditActions
                bindingHandle={bindingHandle}
                snapshotHandle={state.catalog.snapshotHandle}
                expired={catalogExpired}
                mode={state.tab === "commands" ? "commands" : "log"}
                selected={state.status?.commands.find((command) => command.name === state.selectedCommandName) ?? null}
                api={writeApi}
                ask={ask}
                onChanged={() => {
                  setStatusVersion((value) => value + 1);
                  setLogVersion((value) => value + 1);
                }}
              />
            ) : null}
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
                onCopy={writeClipboard === undefined ? undefined : (result) => void copyLog(result)}
                copyNotice={copyNotice}
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
        </CatalogExpired.Provider>
      )}
      {dialog !== null ? <DialogHost dialog={dialog} scrollMessage onResolve={resolve} /> : null}
    </main>
  );
}

function isWriteApi(api: CheckAuditReadApi & Partial<CheckAuditWriteApi>): api is CheckAuditReadApi & CheckAuditWriteApi {
  return typeof api.planCheckAuditAction === "function" && typeof api.confirmCheckAuditAction === "function" &&
    typeof api.executeCheckAuditAction === "function" && typeof api.cancelCheckAuditAction === "function";
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
  const scripts = status?.commands.filter((command) => command.state === "foreign-script") ?? [];
  const shims = status?.commands.filter((command) => command.state === "coreutils-shim") ?? [];
  const multiCall = status?.commands.filter((command) => command.state === "multi-call") ?? [];
  return (
    <>
      <ViewHeader title="命令状态" detail={`${catalog.commands.length} 个命令 · ${status?.isRoot ? "root 会话" : "普通会话或尚未确认"}`}
        loading={statusKind === "loading"} onRefresh={onRefresh} />
      <p className="check-audit-note">按当前登录环境的 PATH 找到每个命令实际执行的文件。“未加采集”只说明它是程序文件、没有本工具的采集包装，不代表它没被篡改；核对文件来源请用文件完整性或软件包校验。</p>
      {scripts.length === 0 ? null : (
        <p className="check-audit-warning" role="status" data-testid="check-audit-scripts">
          {scripts.length} 个命令执行的是脚本而不是程序文件：{scripts.map((command) => command.name).join("、")}。
          可能是发行版自带的包装脚本，也可能被人替换过（例如放在 PATH 更靠前的目录里），请核对下面列出的位置和文件来源。
        </p>
      )}
      {shims.length === 0 ? null : (
        <p className="check-audit-note" data-testid="check-audit-shims">
          {shims.map((command) => command.name).join("、")} 是单文件 coreutils 的转接（EL9 及其衍生发行版的写法）：命令文件只有发行版写的那一行，实际运行 /usr/bin/coreutils。
          这里只核对了那一行的内容，/usr/bin/coreutils 本身是否被改过需要另行核对。
        </p>
      )}
      {multiCall.length === 0 ? null : (
        <p className="check-audit-note" data-testid="check-audit-multi-call">
          {multiCall.map((command) => command.name).join("、")} 都是同一个多合一程序（BusyBox 一类，按运行时的名字决定做什么）。
          给其中一个加采集会同时换掉它的所有命令（包括 sh），所以这里不提供；它本身是否被改过请用文件完整性核对。
        </p>
      )}
      <div className="check-audit-command-tools">
        <label>搜索命令<input value={search} maxLength={128} onChange={(event) => onSearch(event.target.value)} /></label>
        <form onSubmit={(event) => { event.preventDefault(); onAddCustom(); }}>
          <label>自定义命令名<input value={customDraft} maxLength={128} placeholder="例如 openssl"
            onChange={(event) => onCustomDraft(event.target.value)} /></label>
          <button type="submit">加入检查列表</button>
        </form>
      </div>
      {customError !== null && <TransientNotice source="安全检查" message={customError ?? ""} severity="error" inline><p className="check-audit-inline-error" role="alert">{customError}</p></TransientNotice>}
      {customCommands.length > 0 && <div className="check-audit-custom-list" aria-label="自定义命令">
        {customCommands.map((name) => <span key={name}>{name}<button type="button" aria-label={`移除 ${name}`}
          onClick={() => onRemoveCustom(name)}>×</button></span>)}
      </div>}
      {statusKind === "loading" && status === null ? <StatusPanel label="正在采集目标命令状态…" /> :
        statusKind === "error" ? <ErrorPanel message={error ?? "命令状态采集失败。"} compact /> :
          visible.length === 0 ? <EmptyPanel title="没有匹配的命令" detail="换个命令名试试，或把它加入检查列表。" compact /> : (
            <div className="check-audit-command-list">{visible.map((item) => {
              const current = byHandle.get(item.commandHandle);
              return <button type="button" key={item.commandHandle} className={selectedName === item.name ? "is-selected" : ""}
                aria-pressed={selectedName === item.name} onClick={() => onSelect(item.name)}>
                <span><strong>{item.name}</strong>{item.isDefault ? <small>默认</small> : <small>自定义</small>}</span>
                <span>{current === undefined ? "等待采集" : checkAuditStateLabel(current.state)}</span>
                <span>{item.critical ? "关键命令" : "普通命令"}</span>
                <span>{current?.displayLocation ?? "—"}</span>
                {current?.textTruncated === true && <small>位置已截断。</small>}
              </button>;
            })}</div>
          )}
      {status?.truncated === true && <TruncatedNotice>
        状态文本已按大小上限截断，看到的不是全部。内容本身没有做过删改。
      </TruncatedNotice>}
    </>
  );
}

export function LogsView({ status, result, error, searchDraft, limitDraft, inputError, onSearchDraft, onLimitDraft,
  onApply, onRefresh, onCopy, copyNotice = null }: {
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
  onCopy?: ((result: CheckAuditLogResult) => void) | undefined;
  copyNotice?: CopyNotice;
}) {
  const expired = useContext(CatalogExpired);
  return <>
    <ViewHeader title="审计日志" detail="手动读取最新的日志片段。" loading={status === "loading"} onRefresh={onRefresh} />
    <form className="check-audit-log-query" onSubmit={(event) => { event.preventDefault(); onApply(); }}>
      <label>搜索<input value={searchDraft} maxLength={256} placeholder="命令、参数、用户或调用者"
        onChange={(event) => onSearchDraft(event.target.value)} /></label>
      <label>读取上限<select value={limitDraft} onChange={(event) => onLimitDraft(Number(event.target.value))}>
        <option value={50}>50</option><option value={100}>100</option><option value={200}>200</option>
      </select></label>
      <button className="check-audit-primary" type="submit" disabled={status === "loading" || expired}
        title={expired ? EXPIRED_TITLE : undefined}>应用并读取</button>
    </form>
    {inputError !== null && <TransientNotice source="安全检查" message={inputError ?? ""} severity="error" inline><p className="check-audit-inline-error" role="alert">{inputError}</p></TransientNotice>}
    {status === "loading" && result === null ? <StatusPanel label="正在读取审计日志…" /> :
      status === "error" ? <ErrorPanel message={error ?? "审计日志读取失败。"} compact /> : result === null ?
        <EmptyPanel title="尚未读取日志" detail="点“刷新”读取，或调整搜索条件。" compact /> :
        result.logState !== "read" ? <LogStatePanel state={result.logState} /> : <>
          <div className="check-audit-log-summary">
            <article><strong>{result.fetchedCount}</strong><span>读取窗口</span></article>
            <article><strong>{result.matchedCount}</strong><span>搜索匹配</span></article>
            <article><strong>{result.matchedSuspiciousCount}</strong><span>匹配中的可疑项</span></article>
            {result.malformedCount > 0 ? <article><strong>{result.malformedCount}</strong><span>不是审计记录的行</span></article> : null}
          </div>
          {result.malformedCount > 0 ? <p className="check-audit-warning" role="status">
            日志里有 {result.malformedCount} 行不是本工具写的审计记录格式，按原样列出、标为可疑：可能是日志被截断，也可能有人往里写过内容。
          </p> : null}
          {result.commandCounts.length > 0 && <div className="check-audit-counts">{result.commandCounts.map((item, index) =>
            <span key={`${item.command}\0${index}`}>{item.command || "—"} · {item.count}</span>)}</div>}
          {onCopy === undefined || result.entries.length === 0 ? null : (
            <div className="check-audit-copy">
              <button type="button" data-testid="check-audit-copy" onClick={() => onCopy(result)}>复制显示的记录（TSV）</button>
              {copyNotice === null ? null : (
                <TransientNotice source="安全检查" message={copyNotice.text ?? ""} severity={(copyNotice.ok ? "status" : "alert") === "alert" ? "error" : "info"}><span className={copyNotice.ok ? "is-ok" : "is-error"} role={copyNotice.ok ? "status" : "alert"}
                  data-testid="check-audit-copy-notice">{copyNotice.text}</span></TransientNotice>
              )}
            </div>
          )}
          <AuditLogEntries entries={result.entries}
            empty={result.fetchedCount === 0 ? "日志文件存在，但是空的：还没有记录到任何命令。" : "读取到的记录里没有匹配搜索条件的。"} />
          {result.truncated && <TruncatedNotice>
            结果已按大小上限截断，看到的不是全部。内容本身没有做过删改。
          </TruncatedNotice>}
        </>}
  </>;
}

export function AuditLogEntries({ entries, empty }: { entries: readonly CheckAuditLogEntry[]; empty: string }) {
  if (entries.length === 0) return <EmptyPanel title="没有可显示的记录" detail={empty} compact />;
  return <div className="check-audit-log-list">{entries.map((entry, index) => entry.malformed ? (
    <article className="is-suspicious is-malformed" key={`malformed\0${index}`}>
      <header><strong>不是审计记录</strong><span>按日志里的原样显示</span></header>
      <pre>{entry.args}</pre>
      {entry.textTruncated && <small>文本已截断。</small>}
    </article>
  ) : <article
    className={entry.suspicious ? "is-suspicious" : ""} key={`${entry.timestamp}\0${index}`}>
    <header><time>{entry.timestamp || "—"}</time><strong>{entry.command || "—"}</strong><span>{entry.user || "—"}</span>
      <span>PID {entry.pid} / PPID {entry.ppid}</span><span>{entry.caller || "—"}</span></header>
    <pre>{entry.args}</pre>
    {entry.textTruncated && <small>文本已截断。</small>}
  </article>)}</div>;
}

/** Why there is no log to show; never presented as an empty or clean log. */
export function LogStatePanel({ state }: { state: Exclude<CheckAuditLogState, "read"> }) {
  const text = checkAuditLogStateText(state);
  return <div className={state === "absent" ? "check-audit-empty is-compact" : "check-audit-warning-panel"}
    role={state === "absent" ? undefined : "status"} data-testid="check-audit-log-state" data-state={state}>
    <strong>{text.title}</strong><p>{text.detail}</p>
  </div>;
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
        result !== null && result.logState !== "read" ? <LogStatePanel state={result.logState} /> :
        result === null || result.cycles.length === 0 ? <EmptyPanel title="没有识别到周期行为"
          detail="至少需要同一命令与参数的多次记录；空结果不代表没有未采集行为。" compact /> :
          <div className="check-audit-cycle-list">{result.cycles.map((cycle, index) => <article key={`${cycle.command}\0${cycle.args}\0${index}`}>
            <header><strong>{cycle.command || "—"}</strong><span>{checkAuditCategoryLabel(cycle.category)}</span><span>{cycle.count} 次</span></header>
            <pre>{cycle.args}</pre>
            <p>{checkAuditIntervalLabel(cycle.intervalSeconds)} · 最后出现 {cycle.lastSeen || "—"}</p>
            {cycle.textTruncated && <small>分析文本已截断。</small>}
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
        result !== null && result.logState !== "read" ? <LogStatePanel state={result.logState} /> :
        result === null || result.suggestions.length === 0 ? <EmptyPanel title="没有生成建议"
          detail="当前日志片段没有足够的周期证据。" compact /> :
          <div className="check-audit-suggestion-list">{result.suggestions.map((suggestion, index) => <article
            className={`severity-${suggestion.severity}`} key={`${suggestion.title}\0${index}`}>
            <header><strong>{suggestion.title || "—"}</strong><span>{checkAuditSeverityLabel(suggestion.severity)}</span></header>
            <p>{suggestion.description || "—"}</p>
            {suggestion.textTruncated && <small>建议文本已截断。</small>}
          </article>)}</div>}
  </>;
}

/** Whether the command list on screen has expired: reads from it would be refused. */
const CatalogExpired = createContext(false);
const EXPIRED_TITLE = "命令列表已过期，先点右上角的“刷新命令列表”";

function ViewHeader({ title, detail, loading, onRefresh }: {
  title: string;
  detail: string;
  loading: boolean;
  onRefresh(): void;
}) {
  const expired = useContext(CatalogExpired);
  return <div className="check-audit-view-header"><div><h2>{title}</h2><p>{detail}</p></div>
    <button type="button" disabled={loading || expired} title={expired ? EXPIRED_TITLE : undefined}
      onClick={onRefresh}>{loading ? "刷新中…" : "刷新"}</button></div>;
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
