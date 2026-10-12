import { forwardRef, useCallback, useEffect, useImperativeHandle, useMemo, useRef, useState, useSyncExternalStore } from "react";
import { isCaseLibraryRequest, type CaseLibraryApi, type CaseTransfer, type CaseStatusAction } from "../shared/case-library-contract";
import type { CaseSection } from "../shared/case-workspace-contract";
import { CaseLibraryController } from "./case-library-controller";
import { Entry, type CaseWorkspaceHandle } from "./CaseWorkspacePage";
import { DialogHost } from "./DialogHost";
import { useConfirmDialog } from "./use-confirm-dialog";
import "./case-workspace.css";

const stamp = (value: number) => new Date(value).toLocaleString("zh-CN", { hour12: false, timeZoneName: "short" });
const sections: Record<CaseSection, string> = { evidence: "证据", iocs: "调查线索", timeline: "时间线" };
interface Props { api: CaseLibraryApi; initialCaseId?: string | undefined; initialStatusAction?: CaseStatusAction | undefined }
interface StatusDraft { caseId: string; caseTitle: string; snapshotHandle: string; operation: CaseStatusAction; conclusion: string; followup: string }
export const CaseLibraryPanel = forwardRef<CaseWorkspaceHandle, Props>(function CaseLibraryPanel({ api, initialCaseId, initialStatusAction }, ref) {
  const controller = useMemo(() => new CaseLibraryController(api), [api]);
  const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot);
  const [query, setQuery] = useState("");
  const [location, setLocation] = useState("all");
  const [listOffset, setListOffset] = useState(0);
  const [search, setSearch] = useState("");
  const [navigationError, setNavigationError] = useState<string | null>(null);
  const [draft, setDraft] = useState<StatusDraft | null>(null);
  const draftRef = useRef(draft); draftRef.current = draft;
  const statusForm = useRef<HTMLFormElement>(null);
  const automaticStatus = useRef(initialStatusAction);
  const statusReturnFocus = useRef<HTMLElement | null>(null);
  const { dialog, ask, resolve } = useConfirmDialog();
  const refreshRef = useRef<HTMLButtonElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const mounted = useRef(false);
  useEffect(() => {
    mounted.current = true; void controller.refresh(initialCaseId);
    return () => { mounted.current = false; controller.dispose(); resolve({ kind: "cancelled", dialogId: "case-library-unmounted" }); };
  }, [controller, resolve, initialCaseId]);
  useEffect(() => { if (draft !== null) statusForm.current?.querySelector<HTMLTextAreaElement>("textarea")?.focus(); }, [draft?.caseId, draft?.operation]);
  useEffect(() => {
    const requested = automaticStatus.current, view = state.view;
    if (requested === undefined || view === null || state.busy || view.item.incident.id !== initialCaseId) return;
    automaticStatus.current = undefined;
    if (view.item.location !== "working" || view.item.incident.status !== (requested === "close" ? "open" : "closed")) {
      setNavigationError("案件状态已变化，请核对当前内容后重新选择操作。"); return;
    }
    setDraft({ caseId: view.item.incident.id, caseTitle: view.item.incident.title, snapshotHandle: view.snapshotHandle, operation: requested, conclusion: "", followup: "" });
  }, [state.view, state.busy, initialCaseId]);
  useEffect(() => {
    const plan = state.plan;
    if (plan === null) return;
    const timer = setTimeout(() => { resolve({ kind: "cancelled", dialogId: "case-library-expired" }); void controller.cancel(); }, Math.max(0, plan.expiresAt - Date.now()));
    return () => clearTimeout(timer);
  }, [state.plan, controller, resolve]);
  useEffect(() => { if (!state.busy) setNavigationError((message) => message === "正在处理本机案件，请等待完成后再切换。" ? null : message); }, [state.busy]);
  const beforeDeactivate = useCallback(async () => {
    if (controller.getSnapshot().busy) { setNavigationError("正在处理本机案件，请等待完成后再切换。"); return false; }
    resolve({ kind: "cancelled", dialogId: "case-library-leaving" });
    await controller.cancel();
    const current = draftRef.current;
    if (current !== null && (current.conclusion.trim() !== "" || current.followup.trim() !== "") &&
      !(await ask("保留未保存的案件结论？", "选择取消可继续编辑；放弃后，这段尚未保存的结论和后续事项不会进入案件。", "放弃未保存内容"))) return false;
    setDraft(null); draftRef.current = null; setNavigationError(null); return true;
  }, [controller, resolve, ask]);
  useImperativeHandle(ref, () => ({ beforeDeactivate }), [beforeDeactivate]);
  async function transfer(operation: CaseTransfer, button: HTMLElement) {
    const plan = await controller.plan(operation);
    if (plan === null || !mounted.current) return;
    const approved = await ask(operation === "archive" ? "归档这个案件？" : "恢复这个归档版本？", `${plan.summary}\n\n仅整理本机案件记录；原始留证文件需随交接另行保存。本次确认有效期为 5 分钟。`, operation === "archive" ? "确认归档" : "确认恢复");
    if (!mounted.current) return;
    if (approved) await controller.confirm(plan); else await controller.cancel();
    if (mounted.current) requestAnimationFrame(() => (button.isConnected ? button : refreshRef.current)?.focus());
  }
  async function section(value: CaseSection, query = "", focus = false) {
    setSearch(query); await controller.items(value, query);
    if (focus && mounted.current) searchRef.current?.focus({ preventScroll: true });
  }
  async function startStatus(operation: CaseStatusAction, button: HTMLElement) {
    if (!(await beforeDeactivate())) return;
    const view = controller.getSnapshot().view;
    if (view === null || view.item.location !== "working") return;
    statusReturnFocus.current = button;
    setDraft({ caseId: view.item.incident.id, caseTitle: view.item.incident.title, snapshotHandle: view.snapshotHandle, operation, conclusion: "", followup: "" });
  }
  async function reviewStatus() {
    const current = draftRef.current;
    if (current === null || current.snapshotHandle !== controller.getSnapshot().view?.snapshotHandle) { setNavigationError("案件视图已变化，请保留需要的输入并重新查看案件。"); return; }
    const request = { action: "status-plan" as const, snapshotHandle: current.snapshotHandle, operation: current.operation, conclusion: current.conclusion, followup: current.followup };
    if (!isCaseLibraryRequest(request)) { setNavigationError("请填写结论和后续事项：结论最多 1024 字，后续事项最多 512 字。没有待办时请明确填写“无”。"); return; }
    const plan = await controller.planStatus(current.operation, current.conclusion, current.followup);
    if (plan === null || !mounted.current || draftRef.current !== current) return;
    const approved = await ask(current.operation === "close" ? "确认结案记录？" : "确认重新调查？", `${plan.summary}\n\n本次确认有效期为 5 分钟。`, current.operation === "close" ? "确认结案" : "确认重新调查");
    if (!mounted.current) return;
    if (approved && draftRef.current === current) {
      if (await controller.confirm(plan) && mounted.current && draftRef.current === current) { setDraft(null); draftRef.current = null; }
    } else await controller.cancel();
    if (mounted.current) requestAnimationFrame(() => {
      if (mounted.current && document.querySelector('[role="dialog"]') === null) (draftRef.current === null ? refreshRef.current : statusForm.current?.querySelector<HTMLTextAreaElement>("textarea"))?.focus();
    });
  }
  async function cancelStatus() {
    if (!(await beforeDeactivate())) return;
    (statusReturnFocus.current?.isConnected ? statusReturnFocus.current : refreshRef.current)?.focus();
  }
  const filtered = state.list?.items.filter((item) => (location === "all" || item.location === location) &&
    [item.incident.title, item.incident.id, item.targetId, item.connectionName ?? ""].some((text) => text.toLowerCase().includes(query.trim().toLowerCase()))) ?? [];
  const offset = Math.min(listOffset, Math.max(0, Math.floor((filtered.length - 1) / 25) * 25));
  const viewed = state.view?.item;
  const disabled = state.busy || state.plan !== null;
  return <section className="case-workspace" data-testid="case-library">
    <header className="case-heading"><div><h1>本机案件库</h1><p>断开主机后仍可查看、交接和整理证据。归档释放活动案件名额，恢复保留原归档版本。</p></div>
      <button ref={refreshRef} disabled={disabled} onClick={() => { void beforeDeactivate().then((leave) => { if (leave) void controller.refresh(); }); }}>刷新案件库</button></header>
    <p className="case-capacity">活动案件 {state.list?.workingCount ?? "—"} / 30 · 归档版本 {state.list?.archiveCount ?? "—"} / 200 · 案件 JSON 最多 32 MiB</p>
    {state.error !== null || navigationError !== null ? <p className="case-error" role="alert">{navigationError ?? state.error}</p> : null}
    {state.notice !== null ? <p className="case-notice" role="status">{state.notice}</p> : null}
    {draft !== null ? <form ref={statusForm} className="case-draft case-status-draft" aria-label="案件状态记录" onSubmit={(event) => { event.preventDefault(); void reviewStatus(); }}>
      <h2>{draft.operation === "close" ? "结案记录" : "重新调查"} · {draft.caseTitle}</h2>
      <p>{draft.operation === "close" ? "写清已核实的事实和未解决的问题。结案后停止向此案新增内容，原证据保留；结案不代表主机已恢复安全。结案保留在活动列表，可随后归档。" : "记录重新调查的原因和下一步。原结案记录会保留，重新调查不会自动改变当前采集归属。"}</p>
      <fieldset disabled={disabled}><label>{draft.operation === "close" ? "调查结论" : "重新调查原因"}<textarea required rows={4} maxLength={2048} value={draft.conclusion} onChange={(event) => setDraft({ ...draft, conclusion: event.target.value })} placeholder="概括已核实的事实、判断依据与限制；详细材料保留在证据或笔记中。" /><span>{[...draft.conclusion].length} / 1024 字</span></label>
        <label>{draft.operation === "close" ? "尚待处理事项" : "后续调查计划"}<textarea required rows={3} maxLength={1024} value={draft.followup} onChange={(event) => setDraft({ ...draft, followup: event.target.value })} placeholder="写明待解决的问题与下一步；没有待办时请明确填写“无”。" /><span>{[...draft.followup].length} / 512 字</span></label></fieldset>
      <div className="case-actions"><button className="case-primary" type="submit" disabled={disabled}>{state.busy ? "正在核对…" : "核对完整记录"}</button><button type="button" disabled={disabled} onClick={() => void cancelStatus()}>取消编辑</button></div>
    </form> : null}
    <div className="case-columns"><aside className="case-list" aria-label="本机案件列表">
      <label>搜索案件或主机名称<input value={query} maxLength={256} onChange={(event) => { setQuery(event.target.value); setListOffset(0); }} /></label>
      <label className="case-search">存放位置<select value={location} onChange={(event) => { setLocation(event.target.value); setListOffset(0); }}><option value="all">全部案件</option><option value="working">活动列表</option><option value="archived">已归档版本</option></select></label>
      {filtered.slice(offset, offset + 25).map((item) => <button key={item.itemHandle} className="case-list-item" disabled={disabled} aria-pressed={viewed?.itemHandle === item.itemHandle} onClick={() => { void beforeDeactivate().then((leave) => { if (leave) { setSearch(""); void controller.view(item.itemHandle); } }); }}>
        <strong>{item.incident.title}</strong><span>{item.location === "working" ? "活动列表" : "已归档"} · {item.incident.status === "closed" ? "已结案" : "调查中"} · {item.incident.evidenceCount} 条证据</span>
        <small>{item.connectionName ?? "连接名称不可用"}</small>
        <small>{item.archivedAt === null ? `更新于 ${stamp(item.incident.updatedAt)}` : `归档于 ${stamp(item.archivedAt)}`}</small></button>)}
      {state.list !== null && filtered.length === 0 ? <p className="case-empty">{query !== "" || location !== "all" ? "没有匹配案件，可调整搜索或存放位置。" : "还没有案件。连接主机后，在“当前主机”中新建案件，或采集首条证据。"}</p> : null}
      {/* Paging only when there is more than one page to page through. */}
      {filtered.length > 25 ? (
        <div className="case-pagination"><button disabled={offset === 0} onClick={() => setListOffset(Math.max(0, offset - 25))}>上一页案件</button><span>{filtered.length} 项</span><button disabled={offset + 25 >= filtered.length} onClick={() => setListOffset(offset + 25)}>下一页案件</button></div>
      ) : filtered.length > 0 ? <p className="case-pagination">{filtered.length} 项</p> : null}
    </aside><div className="case-detail">
      {viewed !== undefined ? <><header><h2>{viewed.incident.title}</h2><p>{viewed.location === "working" ? "活动案件" : "归档版本"} · {viewed.incident.status === "open" ? "调查中" : "已结案"}</p>
        <p className="case-help">连接库名称（现值）：{viewed.connectionName ?? "不可用"}。原始主机与采集来源以各条证据中的记录为准。</p>
        <details className="case-help"><summary>案件与连接编号</summary><p>案件：{viewed.incident.id}<br />保存的连接标识：{viewed.targetId}</p></details>
        {viewed.archivedAt !== null ? <p className="case-help">归档时间：{stamp(viewed.archivedAt)}</p> : null}
        <div className="case-actions"><button disabled={disabled || draft !== null} onClick={() => void controller.export()}>导出完整案件 JSON</button>
          <button disabled={disabled || draft !== null} onClick={(event) => void transfer(viewed.location === "working" ? "archive" : "restore", event.currentTarget)}>{viewed.location === "working" ? "归档此案" : "恢复到活动列表"}</button>
          {viewed.location === "working" ? <button disabled={disabled || draft !== null} onClick={(event) => void startStatus(viewed.incident.status === "open" ? "close" : "reopen", event.currentTarget)}>{viewed.incident.status === "open" ? "结案并记录结论" : "重新调查"}</button> : <span className="case-help">修改状态前，请先恢复到活动列表。</span>}</div>
        <p className="case-help">此处展示打开时的固定版本；导出包含全部记录及来源清单，外部原始文件需另行交接。查看案件不改变当前采集归属。</p></header>
        <div className="case-tabs" aria-label="案件记录分类">{(Object.keys(sections) as CaseSection[]).map((value) => <button key={value} disabled={disabled} aria-pressed={state.section === value} onClick={() => void section(value)}>{sections[value]} <span>{value === "evidence" ? viewed.incident.evidenceCount : value === "iocs" ? viewed.incident.iocCount : viewed.incident.timelineCount}</span></button>)}</div>
        <form className="case-search" onSubmit={(event) => { event.preventDefault(); void controller.items(state.section, search); }}><label>搜索记录内容、来源或编号<input ref={searchRef} disabled={disabled} value={search} maxLength={256} onChange={(event) => setSearch(event.target.value)} /></label><button disabled={disabled} type="submit">查找记录</button></form>
        {state.page !== null ? <><div className="case-entries">{state.page.items.map((item) => <Entry key={item.id} item={item} section={state.section} onRelated={(value, query) => void section(value, query, true)} />)}</div>
          {state.page.total === 0 ? <p className="case-empty">{state.query !== "" ? "没有匹配记录，可清空搜索后重试。" : "此分类还没有记录。"}</p> : null}
          <div className="case-pagination"><button disabled={disabled || state.offset === 0} onClick={() => void controller.items(state.section, state.query, Math.max(0, state.offset - 25))}>上一页</button><span>{state.page.total === 0 ? 0 : `${state.offset + 1}–${state.offset + state.page.items.length}`} / {state.page.total} 条</span><button disabled={disabled || !state.page.hasMore} onClick={() => void controller.items(state.section, state.query, state.offset + 25)}>下一页</button></div></> : null}
      </> : <p className="case-empty">从左侧选择案件，即可查看证据、导出或整理归档。</p>}
      {state.busy ? <p role="status">正在核对本机案件…</p> : null}
    </div></div>
    {dialog !== null ? <DialogHost dialog={dialog} scrollMessage onResolve={resolve} /> : null}
  </section>;
});
