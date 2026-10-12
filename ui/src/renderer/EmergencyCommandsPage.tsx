import { useEffect, useReducer, useRef, useState } from "react";

import { targetFailureMessage } from "./target-lost";

import {
  isEmergencyCommandCatalog,
  isEmergencyCommandResult,
  isEmergencyHistoryLocation,
  type EmergencyCommandApi,
  type EmergencyHistoryLocationStatus,
  type EmergencyCommandCatalog,
  type EmergencyCommandCatalogItem,
  type EmergencyCommandCategory,
  type EmergencyCommandPathOffer,
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
import { EmergencyPathDialog, EmergencyPathProperties } from "./EmergencyPathDialog";
import { EmergencyPathMenu } from "./EmergencyPathMenu";
import { useEmergencyPathActions } from "./emergency-path-actions";
import { FileEvidenceDialog } from "./FileEvidenceDialog";
import type { FileEvidenceApi } from "../shared/file-evidence-contract";
import { useListExpiry } from "./use-list-expiry";
import "./emergency-commands.css";

export interface EmergencyCommandsPageProps {
  bindingHandle: string | null;
  api: EmergencyCommandApi & FileEvidenceApi;
  /**
   * A command-history record whose check should be put in front of the
   * operator again. A new key is a new request; nothing runs by itself.
   */
  rerun?: { historyId: string; key: number } | null;
  /**
   * A container or pod another page asked to investigate: it becomes where
   * the checks run, once the list has it. A new key is a new request; nothing
   * runs by itself.
   */
  runIn?: { kind: "container" | "pod"; name: string; key: number } | null;
}

/** Where the checks run, as the operator chose it: by kind and name, not by a handle of one list. */
type RunChoice = { kind: "container" | "pod"; name: string };

const RERUN_MISSING: Record<Exclude<EmergencyHistoryLocationStatus, "found">, string> = {
  missing: "命令历史里已经没有这条记录了，可能刚被删除。",
  "not-recorded": "这是较早的记录，没有记下是哪一项检查，没法直接找回；请在左侧清单里按名称找到它。",
  "not-in-catalog": "当前目标的命令清单里没有这一项检查（这台机器给的可能是另一套命令）。可以重新加载清单后再从命令历史打开。",
};

export function EmergencyCommandsPage({ bindingHandle, api, rerun = null, runIn = null }: EmergencyCommandsPageProps) {
  const [evidence, setEvidence] = useState<{ offer: EmergencyCommandPathOffer; binding: string; api: FileEvidenceApi; returnFocus: HTMLElement | null } | null>(null);
  useEffect(() => { setEvidence(null); }, [api, bindingHandle]);
  const [state, dispatch] = useReducer(emergencyCommandReducer, undefined, createEmergencyCommandState);
  const [refreshVersion, setRefreshVersion] = useState(0);
  const [runVersion, setRunVersion] = useState(0);
  // Where the checks run: the target itself, one of its containers, or a pod
  // of the cluster it can reach. Null is the target, and stays the default —
  // a check aimed at one container answers a narrower question than most
  // operators are asking when they open this page.
  //
  // Kept as kind and name and looked up in the list on screen: each reload
  // hands out new handles, and a handle kept from the last list made every
  // run after a reload fail as "expired". A choice the new list no longer
  // has blocks running instead of quietly running on the target itself.
  const [runChoice, setRunChoice] = useState<RunChoice | null>(null);
  // The backend result carries no duration, so time the round trip the operator
  // actually waited for.
  const [runElapsedMs, setRunElapsedMs] = useState<number | null>(null);
  const runStartedAtRef = useRef<number | null>(null);
  const [groupRun, setGroupRun] = useState<{ version: number; category: EmergencyCommandCategory } | null>(null);
  const requestRef = useRef(0);
  const consumedRunVersion = useRef(0);
  const consumedGroupRunVersion = useRef(0);
  const scope = bindingHandle === null ? null : emergencyCommandScope(bindingHandle);
  const pathActions = useEmergencyPathActions(api, bindingHandle);
  // What came of the last request from command history, for this target only.
  const [rerunNotice, setRerunNotice] = useState<{ scope: string; found: boolean; text: string } | null>(null);
  const consumedRerun = useRef(0);
  // Running a check renews the list's window on the backend, from when the
  // run was accepted; only a run that came back counts, so a refused one
  // never makes the page think the list is fresher than it is.
  const [catalogUsedAt, setCatalogUsedAt] = useState<number | null>(null);
  // A run refused because the list went stale settles it at once.
  const [refusedSnapshot, setRefusedSnapshot] = useState<string | null>(null);
  const noteRefusal = (reason: unknown, snapshotHandle: string) => {
    if (String(reason instanceof Error ? reason.message : reason).includes("emergency-command-catalog-unavailable")) {
      setRefusedSnapshot(snapshotHandle);
    }
  };
  const expiry = useListExpiry(state.catalog, state.catalog?.expiresInSeconds ?? null, catalogUsedAt);
  const catalogExpired = state.catalog !== null &&
    (expiry.expired || refusedSnapshot === state.catalog.snapshotHandle);
  const chosenPlace = runChoice === null ? null
    : state.catalog?.containers.find((container) =>
      container.kind === runChoice.kind && container.name === runChoice.name) ?? null;
  // Chosen, but not in the list now on screen: the container stopped or the
  // pod went away. Running is held until the operator chooses again.
  const runPlaceMissing = runChoice !== null && state.catalog !== null && chosenPlace === null;
  const containerHandle = chosenPlace?.containerHandle ?? null;
  const runBlockedReason = catalogExpired ? "命令列表已过期，先点“重新加载”"
    : runPlaceMissing ? "之前选的运行位置已不在列表里，请重新选择"
    : null;
  const consumedRunIn = useRef(0);

  useEffect(() => {
    dispatch({ type: "scope-changed", scope });
    // A choice of container belongs to the target it was made on.
    setRunChoice(null);
  }, [scope]);

  // Another page asked to investigate in a container or pod: choose it once
  // the list is here, and say plainly when the list does not have it.
  useEffect(() => {
    if (runIn === null || consumedRunIn.current === runIn.key || scope === null ||
      state.scope !== scope || state.catalog === null) return;
    consumedRunIn.current = runIn.key;
    const found = state.catalog.containers.find((container) =>
      container.kind === runIn.kind && container.name === runIn.name);
    const label = `${runIn.kind === "pod" ? "Pod" : "容器"} ${runIn.name}`;
    if (found === undefined) {
      setRerunNotice({
        scope,
        found: false,
        text: runIn.kind === "pod"
          ? `命令列表里没有 ${label}：只有正在运行的 Pod 能在里面运行检查。Pod 刚启动的话，点“重新加载”再试。`
          : `命令列表里没有 ${label}：只有正在运行的容器能在里面运行检查。容器刚启动的话，点“重新加载”再试。`,
      });
      return;
    }
    setRunChoice({ kind: found.kind, name: found.name });
    setRerunNotice({
      scope,
      found: true,
      text: `运行位置已切到 ${label}。在左边选一项检查后点“运行只读调查”，或点分类旁的“快速执行”。`,
    });
  }, [runIn, scope, state.catalog, state.scope]);

  useEffect(() => {
    if (rerun === null || consumedRerun.current === rerun.key || scope === null || bindingHandle === null ||
      state.scope !== scope || state.catalog === null) return;
    const { key } = rerun;
    const snapshotHandle = state.catalog.snapshotHandle;
    const busyNow = state.runStatus === "loading" || state.groupRun?.status === "loading";
    let cancelled = false;
    if (busyNow) {
      consumedRerun.current = key;
      setRerunNotice({ scope, found: false, text: "工作台正在运行别的检查，等它结束后再从命令历史打开这一项。" });
      return;
    }
    void api.locateEmergencyHistoryCommand(bindingHandle, snapshotHandle, rerun.historyId).then((value) => {
      if (cancelled) return;
      if (!isEmergencyHistoryLocation(value)) throw new Error();
      consumedRerun.current = key;
      if (value.status === "found" && value.commandHandle !== null) {
        dispatch({ type: "command-revealed", scope, snapshotHandle, commandHandle: value.commandHandle });
        setRerunNotice({ scope, found: true, text: "已从命令历史找到这项检查。确认运行位置后，点“运行只读调查”再运行一次。" });
        requestAnimationFrame(() => {
          const run = document.querySelector<HTMLElement>(".emergency-command-run");
          run?.scrollIntoView({ block: "nearest" });
          run?.focus();
        });
      } else {
        setRerunNotice({ scope, found: false, text: RERUN_MISSING[value.status === "found" ? "missing" : value.status] });
      }
    }).catch((reason: unknown) => {
      if (cancelled) return;
      consumedRerun.current = key;
      setRerunNotice({
        scope,
        found: false,
        text: targetFailureMessage(reason, "没能在当前命令清单里找到这项检查；清单可能已过期，请重新加载后再从命令历史打开。"),
      });
    });
    return () => {
      cancelled = true;
    };
  }, [api, bindingHandle, rerun, scope, state.catalog, state.groupRun?.status, state.runStatus, state.scope]);

  useEffect(() => {
    if (scope === null || bindingHandle === null || state.scope !== scope) return;
    const request = ++requestRef.current;
    let cancelled = false;
    dispatch({ type: "catalog-started", scope, request });
    void api.loadEmergencyCommandCatalog(bindingHandle).then((value) => {
      if (cancelled) return;
      if (!isEmergencyCommandCatalog(value)) throw new Error();
      dispatch({ type: "catalog-loaded", scope, request, catalog: value });
    }).catch((reason: unknown) => {
      if (!cancelled) dispatch({
        type: "catalog-failed",
        scope,
        request,
        error: targetFailureMessage(reason, "无法加载当前目标的内置应急命令目录；连接可能已断开，或系统识别失败。"),
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
    void api.runEmergencyCommand(
      bindingHandle,
      request.snapshotHandle,
      request.commandHandle,
      containerHandle ?? undefined,
    ).then((value) => {
      if (cancelled) return;
      const startedAt = runStartedAtRef.current;
      if (startedAt !== null) setRunElapsedMs(Date.now() - startedAt);
      if (!isEmergencyCommandResult(value) || value.snapshotHandle !== request.snapshotHandle ||
        value.commandHandle !== request.commandHandle) throw new Error();
      if (startedAt !== null) setCatalogUsedAt(startedAt);
      dispatch({ type: "run-loaded", scope, request, result: value });
    }).catch((reason: unknown) => {
      if (cancelled) return;
      noteRefusal(reason, request.snapshotHandle);
      dispatch({
        type: "run-failed",
        scope,
        request,
        error: targetFailureMessage(reason, "内置命令未能完成；操作入口可能已过期、目标已切换，或远端执行失败。"),
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
          const value = await api.runEmergencyCommand(
            bindingHandle,
            run.snapshotHandle,
            commandHandle,
            containerHandle ?? undefined,
          );
          if (!isEmergencyCommandResult(value) || value.snapshotHandle !== run.snapshotHandle ||
            value.commandHandle !== commandHandle) throw new Error();
          entry = { commandHandle, result: value, error: null, elapsedMs: Date.now() - startedAt };
          if (!cancelled) setCatalogUsedAt(startedAt);
        } catch (reason: unknown) {
          if (!cancelled) noteRefusal(reason, run.snapshotHandle);
          entry = {
            commandHandle,
            result: null,
            error: targetFailureMessage(reason, "内置命令未能完成；操作入口可能已过期、目标已切换，或远端执行失败。"),
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
  const acting = pathActions.state;
  return (
    <main className="emergency-commands-page">
      {/* The page's name for a screen reader: the compact toolbar shows none,
          and the only headings below appear once a command is chosen. */}
      <h1 className="emergency-commands-sr-only">应急命令工作台</h1>
      <div className="emergency-commands-toolbar">
        <div className="emergency-commands-search">
          <SearchIcon />
          <input aria-label="搜索命令" value={state.search} maxLength={256} placeholder="搜索命令标题、用途或分类"
            disabled={state.catalog === null}
            onChange={(event) => dispatch({ type: "search-changed", search: event.currentTarget.value })} />
        </div>
        {/* Where the checks run. Only offered when the target actually has
            containers, so a machine without a runtime keeps a toolbar with
            nothing dead on it. */}
        {((state.catalog?.containers.length ?? 0) > 0 || runPlaceMissing) && (
          <label className="emergency-commands-scope">
            <span>运行位置</span>
            <select
              value={runPlaceMissing ? "missing" : containerHandle ?? ""}
              disabled={state.runStatus === "loading"}
              data-testid="emergency-commands-run-place"
              onChange={(event) => {
                const picked = state.catalog?.containers.find((container) =>
                  container.containerHandle === event.currentTarget.value);
                setRunChoice(picked === undefined ? null : { kind: picked.kind, name: picked.name });
              }}
            >
              {runPlaceMissing && runChoice !== null ? (
                <option value="missing" disabled>
                  {runChoice.kind === "pod" ? "Pod" : "容器"} {runChoice.name}（已不在列表里）
                </option>
              ) : null}
              <option value="">这台主机</option>
              {state.catalog?.containers.map((container) => (
                <option key={container.containerHandle} value={container.containerHandle}>
                  {container.kind === "pod" ? "Pod" : "容器"} {container.name}（{container.image}）
                </option>
              ))}
            </select>
          </label>
        )}
        <div className="emergency-commands-meta">
          <span className="emergency-commands-readonly"><LockIcon />只读</span>
          {state.catalog !== null && <span>{filtered.length === state.catalog.commands.length ?
            `共 ${filtered.length} 项` : `${filtered.length}/${state.catalog.commands.length} 项`}</span>}
          {state.catalog !== null && (catalogExpired ? (
            <span className="emergency-commands-expiry is-expired" data-testid="emergency-commands-expired">
              <ClockIcon />命令列表已过期
            </span>
          ) : (
            <span className="emergency-commands-expiry"
              title="每次运行检查都会把有效期往后延；一直不用，到时再运行会被拒绝，点“重新加载”取回新的命令列表即可。">
              <ClockIcon />命令列表约 {expiry.minutesLeft ?? Math.max(1, Math.ceil(state.catalog.expiresInSeconds / 60))} 分钟内有效
            </span>
          ))}
          {/* Only said when it is not the good news: a machine that answered
              needs no announcement, and a machine that did not is about to
              give shallower answers than it could have. */}
          {state.catalog?.commandSet === "portable" && (
            <span className="emergency-commands-portable" role="status">
              这台机器没能及时报出自己是什么系统，下面给的是通用命令，比按发行版挑的要粗一些。可以重新加载再试。
            </span>
          )}
          <button type="button" className={catalogExpired ? "emergency-commands-reload is-attention" : "emergency-commands-reload"}
            disabled={!current || state.catalogStatus === "loading" || state.runStatus === "loading"}
            onClick={() => setRefreshVersion((value) => value + 1)}>
            <RefreshIcon />{state.catalogStatus === "loading" ? "加载中…" : "重新加载"}
          </button>
        </div>
      </div>
      {catalogExpired && state.catalog !== null && (
        <p className="emergency-commands-expired-notice" role="status">
          命令列表超过 {Math.max(1, Math.round(state.catalog.expiresInSeconds / 60))} 分钟没有运行检查，已经过期，现在运行会被拒绝。
          点右上角的“重新加载”取回新的命令列表；已显示的结果仍可查看。
        </p>
      )}
      {rerunNotice !== null && rerunNotice.scope === scope && (
        <p className={rerunNotice.found ? "emergency-commands-rerun" : "emergency-commands-rerun is-missing"}
          role="status" data-testid="emergency-commands-rerun">
          {rerunNotice.text}
        </p>
      )}
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
          blockedReason={runBlockedReason}
          search={state.search}
          onToggleCategory={(category) => dispatch({ type: "category-toggled", category })}
          onSelect={(commandHandle) => {
            setRerunNotice(null);
            dispatch({ type: "command-selected", commandHandle });
          }}
          onRun={() => {
            setRerunNotice(null);
            setRunVersion((value) => value + 1);
          }}
          onRunGroup={(category) => setGroupRun((value) => ({ version: (value?.version ?? 0) + 1, category }))}
          onPathMenu={pathActions.openMenu}
        />
      )}
      {pathActions.menu !== null && <EmergencyPathMenu
        position={pathActions.menu.position}
        offer={pathActions.menu.offer}
        busy={acting !== null}
        onAction={(action) => {
          const { offer } = pathActions.menu ?? { offer: null };
          if (offer !== null && action === "evidence" && bindingHandle !== null) {
            const returnFocus = document.querySelector<HTMLElement>(`[data-path-handle="${CSS.escape(offer.pathHandle)}"]`) ??
              (document.activeElement instanceof HTMLElement ? document.activeElement : null);
            pathActions.dismissMenu();
            setEvidence({ offer, binding: bindingHandle, api, returnFocus });
          } else if (offer !== null && action !== "evidence") void pathActions.start(action, offer);
        }}
        onDismiss={pathActions.dismissMenu} />}
      {evidence !== null && evidence.binding === bindingHandle && evidence.api === api ? <FileEvidenceDialog
        key={`${evidence.binding}:${evidence.offer.pathHandle}`} api={api} binding={evidence.binding}
        offer={evidence.offer} returnFocus={evidence.returnFocus} onClose={() => setEvidence(null)} /> : null}
      {acting !== null && (acting.action === null ? <EmergencyPathProperties
        path={acting.offer.path}
        detail={acting.detail}
        error={acting.error}
        onClose={pathActions.close} /> : <EmergencyPathDialog
        path={acting.offer.path}
        action={acting.action}
        detail={acting.detail}
        plan={acting.plan}
        receipt={acting.receipt}
        undo={acting.undo}
        undoSpent={acting.undoSpent}
        busy={acting.busy}
        error={acting.error}
        onConfirm={() => void pathActions.confirm()}
        onUndo={() => void pathActions.undo()}
        onClose={pathActions.close} />)}
    </main>
  );
}

export function EmergencyCommandWorkbench({ groups, commands = [], collapsed = [], selected, selectedHandle,
  runStatus, result, runError, search, elapsedMs = null, groupRun = null, busy = false, blockedReason = null,
  onToggleCategory = () => undefined, onSelect, onRun, onRunGroup = () => undefined, onPathMenu }: {
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
  /** Why running is off right now (the list expired, the chosen place is gone); null when it may run. */
  blockedReason?: string | null;
  onToggleCategory?: (category: EmergencyCommandCategory) => void;
  onSelect: (commandHandle: string) => void;
  onRun: () => void;
  onRunGroup?: (category: EmergencyCommandCategory) => void;
  onPathMenu?: ((event: MouseEvent, offer: EmergencyCommandPathOffer) => void) | undefined;
}) {
  return (
    <div className="emergency-commands-workbench">
      <aside className="emergency-commands-list" aria-label="内置应急命令">
        {groups.length === 0 ? <EmergencyCommandEmpty
          title={search.trim() === "" ? "内置目录为空" : "没有匹配命令"}
          detail={search.trim() === "" ? "当前没有可运行的调查项。" : "调整本地搜索条件。"} compact /> :
          groups.map((group) => <EmergencyCommandBranch key={group.category} group={group}
            collapsed={collapsed.includes(group.category)} selectedHandle={selectedHandle} busy={busy} blockedReason={blockedReason}
            running={groupRun?.status === "loading" && groupRun.category === group.category}
            onToggle={() => onToggleCategory(group.category)} onSelect={onSelect}
            onRunGroup={() => onRunGroup(group.category)} />)}
      </aside>
      <section className="emergency-command-detail">
        {groupRun !== null ? <EmergencyCommandGroupView run={groupRun} commands={commands}
          onPathMenu={onPathMenu} /> :
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
            <button type="button" className="emergency-command-run" disabled={runStatus === "loading" || blockedReason !== null}
              title={blockedReason ?? undefined} onClick={onRun}>
              <PlayIcon />{runStatus === "loading" ? "执行中…" : "运行只读调查"}
            </button>
            {runStatus === "loading" ? <EmergencyCommandStatus label="正在等待远端结果…" compact /> :
              runStatus === "error" ? <EmergencyCommandError message={runError ?? "命令执行失败。"} compact /> :
                result === null ? <EmergencyCommandEmpty title="尚未执行" detail="结果将在这里以纯文本显示。" compact /> :
                  <EmergencyCommandResultView result={result} elapsedMs={elapsedMs}
                    onPathMenu={onPathMenu} />}
          </>) }
      </section>
    </div>
  );
}

/** One category branch: a collapsible header with its own quick run. */
function EmergencyCommandBranch({ group, collapsed, selectedHandle, busy, blockedReason, running, onToggle, onSelect, onRunGroup }: {
  group: EmergencyCommandGroup;
  collapsed: boolean;
  selectedHandle: string | null;
  busy: boolean;
  blockedReason: string | null;
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
        <button type="button" className="emergency-command-group-run" disabled={busy || blockedReason !== null} onClick={onRunGroup}
          title={blockedReason ?? undefined}
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
export function EmergencyCommandGroupView({ run, commands, onPathMenu }: {
  run: EmergencyCommandGroupRun;
  commands: readonly EmergencyCommandCatalogItem[];
  onPathMenu?: ((event: MouseEvent, offer: EmergencyCommandPathOffer) => void) | undefined;
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
              <EmergencyCommandResultView result={entry.result} elapsedMs={entry.elapsedMs}
                onPathMenu={onPathMenu} />}
        </li>)}
        {pending !== null && <li>
          <p className="emergency-command-step"><span>{done + 1}</span>{title(pending)}</p>
          <EmergencyCommandStatus label="正在等待远端结果…" compact />
        </li>}
      </ol>
    </>
  );
}

export function EmergencyCommandResultView({ result, elapsedMs = null, onPathMenu }: {
  result: EmergencyCommandResult;
  elapsedMs?: number | null;
  onPathMenu?: ((event: MouseEvent, offer: EmergencyCommandPathOffer) => void) | undefined;
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
        {onPathMenu !== undefined && result.paths.length > 0 && <span className="emergency-command-counts">
          {result.paths.length} 行可右键处置
        </span>}
        <span className="emergency-command-counts">exit {emergencyExitCodeLabel(result.exitCode)}</span>
        <span className="emergency-command-counts">{result.displayedLineCount}/{result.observedLineCount} 行</span>
      </header>
      {result.findingLines.length > 0 && result.findingReason !== null &&
        <p className="emergency-command-reason">{result.findingReason}</p>}
      {result.truncated && <p className="emergency-command-warning" role="status">输出已按行数或大小上限截断。</p>}
      {result.output.length === 0 ? <EmergencyCommandEmpty title="命令没有输出"
        detail="固定调查项已完成，但没有可显示的匹配内容。" compact /> :
        <EmergencyCommandOutput output={result.output} findingLines={result.findingLines}
          paths={result.paths} onPathMenu={onPathMenu} />}
    </div>
  );
}

/**
 * Numbered output with the abnormal lines marked. The gutter is pinned so it
 * survives horizontal scrolling.
 *
 * A line the run read a file path out of is right-clickable. The menu acts
 * through the handle that came back with the result, so the window never names
 * a path of its own.
 */
export function EmergencyCommandOutput({ output, findingLines = [], paths = [], onPathMenu }: {
  output: string;
  findingLines?: readonly number[];
  paths?: readonly EmergencyCommandPathOffer[];
  onPathMenu?: ((event: MouseEvent, offer: EmergencyCommandPathOffer) => void) | undefined;
}) {
  const lines = output.split("\n");
  const abnormal = new Set(findingLines);
  const offers = new Map(paths.map((offer) => [offer.line, offer]));
  const actionable = onPathMenu !== undefined;
  return (
    <div className="emergency-command-output">
      <span className="emergency-command-gutter" aria-hidden="true">
        {lines.map((_line, index) => <span key={index}
          className={abnormal.has(index) ? "is-abnormal" : undefined}>{index + 1}</span>)}
      </span>
      <pre>{lines.map((line, index) => {
        const offer = actionable ? offers.get(index) : undefined;
        const marks = [
          abnormal.has(index) ? "is-abnormal" : null,
          offer === undefined ? null : "has-path",
        ].filter((mark) => mark !== null);
        return <span key={index} className={marks.length === 0 ? undefined : marks.join(" ")}
          title={offer === undefined ? undefined : `右键可对 ${offer.path} 处置`}
          onContextMenu={offer === undefined || onPathMenu === undefined ? undefined
            : (event) => onPathMenu(event.nativeEvent, offer)}>{line}{offer !== undefined && onPathMenu !== undefined ? <button
              type="button" className="emergency-path-open" data-path-handle={offer.pathHandle}
              aria-label={`文件操作：${offer.path}`} onClick={(event) => onPathMenu(event.nativeEvent, offer)}>文件操作</button> : null}{"\n"}</span>;
      })}</pre>
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
