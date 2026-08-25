import { useEffect, useReducer, useRef, useState } from "react";

import {
  isEmergencyCommandCatalog,
  isEmergencyCommandResult,
  type EmergencyCommandApi,
  type EmergencyCommandCatalog,
  type EmergencyCommandCatalogItem,
  type EmergencyCommandCategory,
  type EmergencyCommandResult,
} from "../shared/emergency-command-contract";
import {
  emergencyCommandCategoryLabel,
  emergencyCommandResultLabel,
  emergencyCommandScope,
  emergencyExitCodeLabel,
  filterEmergencyCommands,
  groupEmergencyCommands,
  type EmergencyCommandGroup,
} from "./emergency-command-helpers";
import {
  CheckIcon,
  ChevronIcon,
  ClockIcon,
  EmergencyCommandIcon,
  LockIcon,
  PlayIcon,
  RefreshIcon,
  SearchIcon,
  TagIcon,
} from "./emergency-command-icons";
import {
  createEmergencyCommandState,
  emergencyCommandReducer,
  type EmergencyCommandGroupRun,
  type EmergencyCommandLoadStatus,
} from "./emergency-command-state";
import "./emergency-commands.css";

export interface EmergencyCommandsPageProps {
  bindingHandle: string | null;
  api: EmergencyCommandApi;
}

export function EmergencyCommandsPage({ bindingHandle, api }: EmergencyCommandsPageProps) {
  const [state, dispatch] = useReducer(emergencyCommandReducer, undefined, createEmergencyCommandState);
  const [refreshVersion, setRefreshVersion] = useState(0);
  const [runVersion, setRunVersion] = useState(0);
  // The backend result carries no duration, so time the round trip the operator
  // actually waited for.
  const [runElapsedMs, setRunElapsedMs] = useState<number | null>(null);
  const runStartedAtRef = useRef<number | null>(null);
  const [groupRun, setGroupRun] = useState<{ version: number; category: EmergencyCommandCategory } | null>(null);
  const requestRef = useRef(0);
  const consumedRunVersion = useRef(0);
  const consumedGroupRunVersion = useRef(0);
  const scope = bindingHandle === null ? null : emergencyCommandScope(bindingHandle);

  useEffect(() => {
    dispatch({ type: "scope-changed", scope });
  }, [scope]);

  useEffect(() => {
    if (scope === null || bindingHandle === null || state.scope !== scope) return;
    const request = ++requestRef.current;
    let cancelled = false;
    dispatch({ type: "catalog-started", scope, request });
    void api.loadEmergencyCommandCatalog(bindingHandle).then((value) => {
      if (cancelled) return;
      if (!isEmergencyCommandCatalog(value)) throw new Error();
      dispatch({ type: "catalog-loaded", scope, request, catalog: value });
    }).catch(() => {
      if (!cancelled) dispatch({
        type: "catalog-failed",
        scope,
        request,
        error: "无法加载当前目标的内置应急命令目录；绑定可能已失效或系统识别失败。",
      });
    });
    return () => {
      cancelled = true;
    };
  }, [api, bindingHandle, refreshVersion, scope, state.scope]);

  useEffect(() => {
    if (runVersion === 0 || consumedRunVersion.current === runVersion || scope === null || bindingHandle === null ||
      state.scope !== scope || state.catalog === null || state.selectedCommandHandle === null) return;
    consumedRunVersion.current = runVersion;
    const request = {
      id: ++requestRef.current,
      snapshotHandle: state.catalog.snapshotHandle,
      commandHandle: state.selectedCommandHandle,
    };
    let cancelled = false;
    runStartedAtRef.current = Date.now();
    setRunElapsedMs(null);
    dispatch({ type: "run-started", scope, request });
    void api.runEmergencyCommand(bindingHandle, request.snapshotHandle, request.commandHandle).then((value) => {
      if (cancelled) return;
      const startedAt = runStartedAtRef.current;
      if (startedAt !== null) setRunElapsedMs(Date.now() - startedAt);
      if (!isEmergencyCommandResult(value) || value.snapshotHandle !== request.snapshotHandle ||
        value.commandHandle !== request.commandHandle) throw new Error();
      dispatch({ type: "run-loaded", scope, request, result: value });
    }).catch(() => {
      if (!cancelled) dispatch({
        type: "run-failed",
        scope,
        request,
        error: "内置命令未能完成；能力可能过期、目标已变化或远端执行失败。",
      });
    });
    return () => {
      cancelled = true;
    };
  }, [api, bindingHandle, runVersion, scope, state.catalog, state.scope, state.selectedCommandHandle]);

  useEffect(() => {
    if (groupRun === null || consumedGroupRunVersion.current === groupRun.version || scope === null ||
      bindingHandle === null || state.scope !== scope || state.catalog === null) return;
    consumedGroupRunVersion.current = groupRun.version;
    const commandHandles = state.catalog.commands
      .filter((command) => command.category === groupRun.category)
      .map((command) => command.commandHandle);
    if (commandHandles.length === 0) return;
    const run = {
      id: ++requestRef.current,
      snapshotHandle: state.catalog.snapshotHandle,
      category: groupRun.category,
      commandHandles,
    };
    let cancelled = false;
    dispatch({ type: "group-run-started", scope, run });
    void (async () => {
      // The catalog runs one fixed command at a time, so a group is a strictly
      // sequential walk; a target switch or reload cancels the rest.
      for (const commandHandle of commandHandles) {
        if (cancelled) return;
        const startedAt = Date.now();
        let entry;
        try {
          const value = await api.runEmergencyCommand(bindingHandle, run.snapshotHandle, commandHandle);
          if (!isEmergencyCommandResult(value) || value.snapshotHandle !== run.snapshotHandle ||
            value.commandHandle !== commandHandle) throw new Error();
          entry = { commandHandle, result: value, error: null, elapsedMs: Date.now() - startedAt };
        } catch {
          entry = {
            commandHandle,
            result: null,
            error: "内置命令未能完成；能力可能过期、目标已变化或远端执行失败。",
            elapsedMs: Date.now() - startedAt,
          };
        }
        if (cancelled) return;
        dispatch({ type: "group-run-progress", scope, runId: run.id, entry });
      }
      if (!cancelled) dispatch({ type: "group-run-finished", scope, runId: run.id });
    })();
    return () => {
      cancelled = true;
    };
  }, [api, bindingHandle, groupRun, scope, state.catalog, state.scope]);

  if (bindingHandle === null) {
    return (
      <main className="emergency-commands-page emergency-commands-disconnected">
        <h1>应急命令工作台</h1>
        <p>连接 SSH 目标后，可运行内置的只读调查命令。</p>
      </main>
    );
  }

  const current = state.scope === scope;
  const filtered = filterEmergencyCommands(state.catalog?.commands ?? [], state.search);
  const groups = groupEmergencyCommands(filtered);
  const selected = state.catalog?.commands.find((command) =>
    command.commandHandle === state.selectedCommandHandle) ?? null;
  const busy = state.runStatus === "loading" || state.groupRun?.status === "loading";
  return (
    <main className="emergency-commands-page">
      <div className="emergency-commands-toolbar">
        <div className="emergency-commands-search">
          <SearchIcon />
          <input aria-label="搜索命令" value={state.search} maxLength={256} placeholder="搜索命令标题、用途或分类"
            disabled={state.catalog === null}
            onChange={(event) => dispatch({ type: "search-changed", search: event.currentTarget.value })} />
        </div>
        <div className="emergency-commands-meta">
          <span className="emergency-commands-readonly"><LockIcon />只读</span>
          {state.catalog !== null && <span>{filtered.length === state.catalog.commands.length ?
            `共 ${filtered.length} 项` : `${filtered.length}/${state.catalog.commands.length} 项`}</span>}
          {state.catalog !== null && <span className="emergency-commands-expiry"><ClockIcon />能力约 {
            Math.max(1, Math.ceil(state.catalog.expiresInSeconds / 60))} 分钟有效</span>}
          <button type="button" className="emergency-commands-reload"
            disabled={!current || state.catalogStatus === "loading" || state.runStatus === "loading"}
            onClick={() => setRefreshVersion((value) => value + 1)}>
            <RefreshIcon />{state.catalogStatus === "loading" ? "加载中…" : "重新加载"}
          </button>
        </div>
      </div>
      {!current || state.catalogStatus === "loading" && state.catalog === null ? (
        <EmergencyCommandStatus label="正在识别目标系统并加载命令目录…" />
      ) : state.catalogStatus === "error" ? (
        <EmergencyCommandError message={state.catalogError ?? "命令目录不可用。"} />
      ) : state.catalog === null ? (
        <EmergencyCommandEmpty title="命令目录不可用" detail="点击右上角的重新加载后重试。" />
      ) : state.catalog.commands.length === 0 ? (
        <EmergencyCommandEmpty title="内置目录为空" detail="当前没有可运行的调查项。" />
      ) : (
        <EmergencyCommandWorkbench
          groups={groups}
          commands={state.catalog.commands}
          collapsed={state.collapsedCategories}
          selected={selected}
          selectedHandle={state.selectedCommandHandle}
          runStatus={state.runStatus}
          result={state.result}
          elapsedMs={runElapsedMs}
          runError={state.runError}
          groupRun={state.groupRun}
          busy={busy}
          search={state.search}
          onToggleCategory={(category) => dispatch({ type: "category-toggled", category })}
          onSelect={(commandHandle) => dispatch({ type: "command-selected", commandHandle })}
          onRun={() => setRunVersion((value) => value + 1)}
          onRunGroup={(category) => setGroupRun((value) => ({ version: (value?.version ?? 0) + 1, category }))}
        />
      )}
    </main>
  );
}

export function EmergencyCommandWorkbench({ groups, commands = [], collapsed = [], selected, selectedHandle,
  runStatus, result, runError, search, elapsedMs = null, groupRun = null, busy = false,
  onToggleCategory = () => undefined, onSelect, onRun, onRunGroup = () => undefined }: {
  groups: EmergencyCommandGroup[];
  commands?: readonly EmergencyCommandCatalogItem[];
  collapsed?: readonly EmergencyCommandCategory[];
  selected: EmergencyCommandCatalogItem | null;
  selectedHandle: string | null;
  runStatus: EmergencyCommandLoadStatus;
  result: EmergencyCommandResult | null;
  runError: string | null;
  search: string;
  elapsedMs?: number | null;
  groupRun?: EmergencyCommandGroupRun | null;
  busy?: boolean;
  onToggleCategory?: (category: EmergencyCommandCategory) => void;
  onSelect: (commandHandle: string) => void;
  onRun: () => void;
  onRunGroup?: (category: EmergencyCommandCategory) => void;
}) {
  return (
    <div className="emergency-commands-workbench">
      <aside className="emergency-commands-list" aria-label="内置应急命令">
        {groups.length === 0 ? <EmergencyCommandEmpty
          title={search.trim() === "" ? "内置目录为空" : "没有匹配命令"}
          detail={search.trim() === "" ? "当前没有可运行的调查项。" : "调整本地搜索条件。"} compact /> :
          groups.map((group) => <EmergencyCommandBranch key={group.category} group={group}
            collapsed={collapsed.includes(group.category)} selectedHandle={selectedHandle} busy={busy}
            running={groupRun?.status === "loading" && groupRun.category === group.category}
            onToggle={() => onToggleCategory(group.category)} onSelect={onSelect}
            onRunGroup={() => onRunGroup(group.category)} />)}
      </aside>
      <section className="emergency-command-detail">
        {groupRun !== null ? <EmergencyCommandGroupView run={groupRun} commands={commands} /> :
          selected === null ? <EmergencyCommandEmpty title="未选择调查项" detail="从左侧选择一项内置命令。" /> : (
          <>
            <header>
              <EmergencyCommandIcon category={selected.category} />
              <div>
                <h2>{selected.title}</h2>
                <p>{selected.description}</p>
              </div>
            </header>
            <dl className="emergency-command-facts">
              <div>
                <dt><TagIcon />分类</dt>
                <dd>{emergencyCommandCategoryLabel(selected.category)}</dd>
              </div>
              <div>
                <dt><ClockIcon />执行上限</dt>
                <dd>{selected.timeoutSeconds} 秒</dd>
              </div>
              <div>
                <dt><LockIcon />执行方式</dt>
                <dd>只读，不接受自定义输入</dd>
              </div>
            </dl>
            <button type="button" className="emergency-command-run" disabled={runStatus === "loading"} onClick={onRun}>
              <PlayIcon />{runStatus === "loading" ? "执行中…" : "运行只读调查"}
            </button>
            {runStatus === "loading" ? <EmergencyCommandStatus label="正在等待远端结果…" compact /> :
              runStatus === "error" ? <EmergencyCommandError message={runError ?? "命令执行失败。"} compact /> :
                result === null ? <EmergencyCommandEmpty title="尚未执行" detail="结果将在这里以纯文本显示。" compact /> :
                  <EmergencyCommandResultView result={result} elapsedMs={elapsedMs} />}
          </>) }
      </section>
    </div>
  );
}

/** One category branch: a collapsible header with its own quick run. */
function EmergencyCommandBranch({ group, collapsed, selectedHandle, busy, running, onToggle, onSelect, onRunGroup }: {
  group: EmergencyCommandGroup;
  collapsed: boolean;
  selectedHandle: string | null;
  busy: boolean;
  running: boolean;
  onToggle: () => void;
  onSelect: (commandHandle: string) => void;
  onRunGroup: () => void;
}) {
  const label = emergencyCommandCategoryLabel(group.category);
  return (
    <div className="emergency-command-group">
      <div className="emergency-command-group-header">
        <button type="button" className="emergency-command-group-toggle" aria-expanded={!collapsed}
          onClick={onToggle}>
          <ChevronIcon open={!collapsed} />
          <EmergencyCommandIcon category={group.category} />
          <strong>{label}</strong>
          <span className="emergency-command-group-count">{group.commands.length}</span>
        </button>
        <button type="button" className="emergency-command-group-run" disabled={busy} onClick={onRunGroup}
          aria-label={`快速执行 ${label} 的 ${group.commands.length} 项调查`}>
          <PlayIcon />{running ? "执行中…" : "快速执行"}
        </button>
      </div>
      {!collapsed && <div className="emergency-command-group-items">
        {group.commands.map((command) => <button type="button" key={command.commandHandle}
          className={selectedHandle === command.commandHandle ? "is-selected" : ""}
          aria-pressed={selectedHandle === command.commandHandle}
          onClick={() => onSelect(command.commandHandle)}>
          <span className="emergency-command-card-body">
            <strong>{command.title}</strong>
            <span>{command.timeoutSeconds} 秒上限</span>
            <span className="emergency-command-card-detail">{command.description}</span>
          </span>
          {selectedHandle === command.commandHandle &&
            <span className="emergency-command-card-check"><CheckIcon /></span>}
        </button>)}
      </div>}
    </div>
  );
}

/** Sequential group run: one result block per finished step. */
export function EmergencyCommandGroupView({ run, commands }: {
  run: EmergencyCommandGroupRun;
  commands: readonly EmergencyCommandCatalogItem[];
}) {
  const total = run.commandHandles.length;
  const done = run.entries.length;
  const failed = run.entries.filter((entry) => entry.result === null ||
    (entry.result.resultKind !== "success" && entry.result.resultKind !== "empty")).length;
  const title = (commandHandle: string) =>
    commands.find((command) => command.commandHandle === commandHandle)?.title ?? "内置调查项";
  const pending = run.status === "loading" && done < total ? run.commandHandles[done] ?? null : null;
  return (
    <>
      <header>
        <EmergencyCommandIcon category={run.category} />
        <div>
          <h2>{emergencyCommandCategoryLabel(run.category)} · 快速执行</h2>
          <p>按目录顺序运行该分组的 {total} 项只读调查，结果依次显示在下方。</p>
        </div>
      </header>
      <div className="emergency-command-progress">
        <div className="emergency-command-progress-track" aria-label="分组执行进度">
          <span style={{ width: `${total === 0 ? 0 : Math.round((done / total) * 100)}%` }} />
        </div>
        <p aria-live="polite">
          {run.status === "loading" ? `正在执行第 ${Math.min(done + 1, total)} 项，共 ${total} 项` :
            `已完成 ${total} 项`}{failed > 0 ? ` · ${failed} 项未成功` : ""}
        </p>
      </div>
      <ol className="emergency-command-steps">
        {run.entries.map((entry, index) => <li key={entry.commandHandle}>
          <p className="emergency-command-step"><span>{index + 1}</span>{title(entry.commandHandle)}</p>
          {entry.error !== null ? <EmergencyCommandError message={entry.error} compact /> :
            entry.result === null ? null :
              <EmergencyCommandResultView result={entry.result} elapsedMs={entry.elapsedMs} />}
        </li>)}
        {pending !== null && <li>
          <p className="emergency-command-step"><span>{done + 1}</span>{title(pending)}</p>
          <EmergencyCommandStatus label="正在等待远端结果…" compact />
        </li>}
      </ol>
    </>
  );
}

export function EmergencyCommandResultView({ result, elapsedMs = null }: {
  result: EmergencyCommandResult;
  elapsedMs?: number | null;
}) {
  const successful = result.resultKind === "success" || result.resultKind === "empty";
  return (
    <div className={successful ? "emergency-command-result is-success" : "emergency-command-result is-failure"}>
      <header>
        <strong>
          {successful ? <CheckIcon /> : null}
          {emergencyCommandResultLabel(result.resultKind)}
        </strong>
        {elapsedMs !== null && <span className="emergency-command-elapsed">完成耗时 {
          (elapsedMs / 1000).toFixed(2)} 秒</span>}
        {result.findingLines.length > 0 && <span className="emergency-command-abnormal">
          {result.findingLines.length} 处需要关注
        </span>}
        <span className="emergency-command-counts">exit {emergencyExitCodeLabel(result.exitCode)}</span>
        <span className="emergency-command-counts">{result.displayedLineCount}/{result.observedLineCount} 行</span>
      </header>
      {result.findingLines.length > 0 && result.findingReason !== null &&
        <p className="emergency-command-reason">{result.findingReason}</p>}
      {result.truncated && <p className="emergency-command-warning" role="status">输出已按行数或大小上限截断。</p>}
      {result.output.length === 0 ? <EmergencyCommandEmpty title="命令没有输出"
        detail="固定调查项已完成，但没有可显示的匹配内容。" compact /> :
        <EmergencyCommandOutput output={result.output} findingLines={result.findingLines} />}
    </div>
  );
}

/**
 * Numbered output with the abnormal lines marked. The gutter is pinned so it
 * survives horizontal scrolling.
 */
export function EmergencyCommandOutput({ output, findingLines = [] }: {
  output: string;
  findingLines?: readonly number[];
}) {
  const lines = output.split("\n");
  const abnormal = new Set(findingLines);
  return (
    <div className="emergency-command-output">
      <span className="emergency-command-gutter" aria-hidden="true">
        {lines.map((_line, index) => <span key={index}
          className={abnormal.has(index) ? "is-abnormal" : undefined}>{index + 1}</span>)}
      </span>
      <pre>{lines.map((line, index) => <span key={index}
        className={abnormal.has(index) ? "is-abnormal" : undefined}>{line}{"\n"}</span>)}</pre>
    </div>
  );
}

export function EmergencyCommandStatus({ label, compact = false }: { label: string; compact?: boolean }) {
  return <div className={compact ? "emergency-command-status is-compact" : "emergency-command-status"}
    aria-live="polite"><span aria-hidden="true" />{label}</div>;
}

export function EmergencyCommandError({ message, compact = false }: { message: string; compact?: boolean }) {
  return <div className={compact ? "emergency-command-error is-compact" : "emergency-command-error"}
    role="alert"><strong>操作失败</strong><p>{message}</p></div>;
}

export function EmergencyCommandEmpty({ title, detail, compact = false }: {
  title: string;
  detail: string;
  compact?: boolean;
}) {
  return <div className={compact ? "emergency-command-empty is-compact" : "emergency-command-empty"}>
    <strong>{title}</strong><p>{detail}</p>
  </div>;
}
