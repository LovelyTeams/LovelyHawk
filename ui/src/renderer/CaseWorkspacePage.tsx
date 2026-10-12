import { forwardRef, useCallback, useEffect, useImperativeHandle, useMemo, useRef, useState, useSyncExternalStore } from "react";
import type { LovelyHawkApi, NoteListPage, NoteResult } from "../shared/contract";
import { isCaseWorkspaceRequest, type CaseWorkspaceApi, type CaseIocType, type CaseSection, type CaseEntry } from "../shared/case-workspace-contract";
import type { DisposalReportSnapshot } from "../shared/disposal-report-contract";
import type { CaseStatusAction } from "../shared/case-library-contract";
import { CaseWorkspaceController, caseWorkspaceStateForBinding } from "./case-workspace-controller";
import { useConfirmDialog } from "./use-confirm-dialog";
import { DialogHost } from "./DialogHost";
import "./case-workspace.css";

export interface CaseWorkspaceHandle { beforeDeactivate(): Promise<boolean> }
interface Props {
  bindingHandle: string | null;
  targetLabel: string;
  api: CaseWorkspaceApi & Pick<LovelyHawkApi, "listNotes" | "getNote">;
  onReport(report: DisposalReportSnapshot, returnFocus: HTMLElement, bindingHandle: string): void;
  onStatusCase?(caseId: string, action: CaseStatusAction): Promise<void>;
}
interface Draft {
  mode: "create" | "note" | "ioc" | "attach"; binding: string; caseId: string; caseTitle: string;
  title: string; content: string; iocType: CaseIocType; mutationId: string; note: NoteResult | null;
}
const sectionLabels: Record<CaseSection, string> = { evidence: "证据", iocs: "调查线索", timeline: "时间线" };
const labels: Record<string, string> = { finding: "发现", path: "文件 / 路径", "command-output": "命令输出", snapshot: "系统快照", pcap: "抓包", log: "日志", note: "调查记录", other: "其他",
  ip: "IP 地址", domain: "域名", hash: "文件摘要", process: "进程", user: "账号", "case-created": "创建案件", evidence: "收集证据", ioc: "加入线索", action: "处置记录", verification: "复核记录" };
const stamp = (value: number) => new Date(value).toLocaleString("zh-CN", { hour12: false, timeZoneName: "short" });
const dirty = (draft: Draft | null) => draft !== null && (draft.title.trim() !== "" || draft.content.trim() !== "" || draft.note !== null);

export const CaseWorkspacePage = forwardRef<CaseWorkspaceHandle, Props>(function CaseWorkspacePage({ bindingHandle, targetLabel, api, onReport, onStatusCase }, ref) {
  const controller = useMemo(() => new CaseWorkspaceController(api), [api]);
  const received = useSyncExternalStore(controller.subscribe, controller.getSnapshot);
  const state = caseWorkspaceStateForBinding(received, bindingHandle);
  const scopeRef = useRef(bindingHandle); scopeRef.current = bindingHandle;
  const [draft, setDraft] = useState<Draft | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [caseQuery, setCaseQuery] = useState("");
  const [search, setSearch] = useState("");
  const [notes, setNotes] = useState<NoteListPage | null>(null);
  const [noteQuery, setNoteQuery] = useState("");
  const [noteBusy, setNoteBusy] = useState(false);
  const draftRef = useRef(draft); draftRef.current = draft;
  const noteGeneration = useRef(0);
  const searchTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const formRef = useRef<HTMLFormElement>(null);
  const createRef = useRef<HTMLButtonElement>(null);
  const returnFocus = useRef<HTMLElement | null>(null);
  const { dialog, ask, resolve } = useConfirmDialog();

  useEffect(() => {
    controller.setBinding(bindingHandle);
    setSearch(""); setCaseQuery(""); noteGeneration.current += 1; setNoteBusy(false);
    return () => { controller.dispose(); noteGeneration.current += 1; if (searchTimer.current !== null) clearTimeout(searchTimer.current); };
  }, [bindingHandle, controller]);
  useEffect(() => { if (draft !== null) formRef.current?.querySelector<HTMLElement>("input,textarea,select")?.focus(); }, [draft?.mode]);
  useEffect(() => () => { resolve({ kind: "cancelled", dialogId: "case-workspace-unmounted" }); }, [resolve]);

  const beforeDeactivate = useCallback(async () => {
    if (controller.getSnapshot().busy || noteBusy) { setFormError("正在处理案件，请等待完成后再切换。"); return false; }
    if (dirty(draftRef.current) && !(await ask("保留尚未保存的内容？", "选择取消可继续编辑；放弃后，这段尚未保存的内容不会进入案件。", "放弃未保存内容"))) return false;
    setDraft(null); draftRef.current = null; setFormError(null); noteGeneration.current += 1;
    return true;
  }, [ask, controller, noteBusy]);
  useImperativeHandle(ref, () => ({ beforeDeactivate }), [beforeDeactivate]);

  async function start(mode: Draft["mode"], button: HTMLElement) {
    if (bindingHandle === null || state.busy || !(await beforeDeactivate())) return;
    const current = controller.getSnapshot().view?.incident;
    if (mode !== "create" && (current === undefined || current.status !== "open")) return;
    returnFocus.current = button;
    setDraft({ mode, binding: bindingHandle, caseId: current?.id ?? "", caseTitle: current?.title ?? "", title: "", content: "", iocType: "ip", mutationId: crypto.randomUUID(), note: null });
    setNotes(null); setNoteQuery("");
    if (mode === "attach") void loadNotes("", 0);
  }
  async function cancelDraft() {
    if (!(await beforeDeactivate())) return;
    (returnFocus.current?.isConnected ? returnFocus.current : createRef.current)?.focus();
  }
  async function loadNotes(query: string, offset: number) {
    const generation = ++noteGeneration.current;
    setNoteBusy(true); setFormError(null);
    try { const value = await api.listNotes(query, offset, 25); if (generation === noteGeneration.current) setNotes(value); }
    catch { if (generation === noteGeneration.current) setFormError("无法读取笔记，请重试。"); }
    finally { if (generation === noteGeneration.current) setNoteBusy(false); }
  }
  async function chooseNote(id: string) {
    const generation = ++noteGeneration.current;
    const captured = draftRef.current;
    setNoteBusy(true); setFormError(null);
    try {
      const note = await api.getNote(id);
      if (generation !== noteGeneration.current || draftRef.current !== captured) return;
      if ([...note.content].length > 4096) { setFormError("这篇笔记超过 4096 字，请先在笔记中拆分需要归档的内容。没有截断或保存。 "); return; }
      setDraft((current) => current === null ? null : { ...current, note });
    } catch { if (generation === noteGeneration.current) setFormError("无法读取这篇笔记，请刷新列表后重试。"); }
    finally { if (generation === noteGeneration.current) setNoteBusy(false); }
  }
  async function save() {
    const captured = draftRef.current;
    if (captured === null || captured.binding !== bindingHandle || state.busy || noteBusy) return;
    const common = { bindingHandle: captured.binding, caseId: captured.caseId };
    const request = captured.mode === "create" ? { action: "create" as const, bindingHandle: captured.binding, title: captured.title, mutationId: captured.mutationId } :
      captured.mode === "note" ? { action: "note" as const, ...common, title: captured.title, content: captured.content } :
      captured.mode === "ioc" ? { action: "ioc" as const, ...common, iocType: captured.iocType, value: captured.content } :
      captured.note === null ? null : { action: "attach-note" as const, ...common, noteId: captured.note.id, revision: captured.note.revision };
    if (!isCaseWorkspaceRequest(request)) { setFormError("请填写完整内容：案件名最多 160 字，记录标题 256 字，正文 4096 字，线索 2048 字。"); return; }
    setFormError(null);
    if (await controller.mutate(request) && draftRef.current === captured) {
      setDraft(null); draftRef.current = null;
      requestAnimationFrame(() => (returnFocus.current?.isConnected ? returnFocus.current : createRef.current)?.focus());
    }
  }
  async function showCase(caseId: string) {
    if (!(await beforeDeactivate())) return;
    if (searchTimer.current !== null) clearTimeout(searchTimer.current);
    setSearch(""); await controller.view(caseId);
  }
  function changeSearch(value: string) {
    setSearch(value);
    if (searchTimer.current !== null) clearTimeout(searchTimer.current);
    searchTimer.current = setTimeout(() => { void controller.items(controller.getSnapshot().section, value); }, 220);
  }
  function section(section: CaseSection, query = "", focusSearch = false) {
    if (searchTimer.current !== null) clearTimeout(searchTimer.current);
    const binding = controller.getSnapshot().binding;
    setSearch(query); void controller.items(section, query).then(() => {
      if (focusSearch && controller.getSnapshot().binding === binding) searchRef.current?.focus({ preventScroll: true });
    });
  }
  const incident = state.view?.incident;
  const current = incident !== undefined && state.list?.activeCaseId === incident.id;
  const canWrite = incident?.status === "open" && !state.busy && bindingHandle !== null;
  const visibleCases = state.list?.cases.filter((item) => item.title.toLowerCase().includes(caseQuery.trim().toLowerCase())) ?? [];

  return <section className="case-workspace" data-testid="case-workspace">
    <header className="case-heading"><div><h1>案件工作台</h1><p>把证据、线索和调查经过放在一起，便于复核和交接。</p><p className="case-target">当前目标：<strong>{targetLabel}</strong></p></div>
      <div className="case-actions"><button disabled={bindingHandle === null || state.busy} onClick={() => void controller.refresh()}>刷新案件</button>
        <button ref={createRef} className="case-primary" disabled={bindingHandle === null || state.busy || state.list === null || state.list.totalCases >= 30} onClick={(event) => void start("create", event.currentTarget)}>新建案件</button></div>
    </header>
    {state.error !== null ? <p className="case-error" role="alert">{state.error}</p> : null}
    {state.notice !== null ? <p className="case-notice" role="status">{state.notice}</p> : null}
    {formError !== null ? <p className="case-error" role="alert">{formError}</p> : null}
    {draft !== null ? <form ref={formRef} className="case-draft" onSubmit={(event) => { event.preventDefault(); void save(); }} aria-label="案件记录编辑">
      <h2>{draft.mode === "create" ? "新建案件" : draft.mode === "note" ? "添加调查记录" : draft.mode === "ioc" ? "添加调查线索" : "关联已有笔记"}</h2>
      {draft.mode !== "create" ? <p>归入：<strong>{draft.caseTitle}</strong></p> : <p>新案件将成为此主机后续采集的归档位置。正在采集的文件保持原归属。</p>}
      {draft.binding !== bindingHandle ? <p role="alert">主机已切换，草稿仍保留。请复制需要的内容后取消编辑，再为当前主机记录。</p> : null}
      <fieldset disabled={state.busy || noteBusy}>
        {draft.mode === "create" || draft.mode === "note" ? <label>{draft.mode === "create" ? "案件名称" : "记录标题"}<input value={draft.title} maxLength={draft.mode === "create" ? 320 : 512} placeholder={draft.mode === "create" ? "例如：Web 主机异常登录调查" : "例如：已核对异常登录来源"} onChange={(event) => setDraft({ ...draft, title: event.target.value, mutationId: crypto.randomUUID() })} /></label> : null}
        {draft.mode === "ioc" ? <label>线索类型<select value={draft.iocType} onChange={(event) => setDraft({ ...draft, iocType: event.target.value as CaseIocType })}>{(["ip", "domain", "hash", "path", "process", "user", "other"] as const).map((kind) => <option value={kind} key={kind}>{labels[kind]}</option>)}</select></label> : null}
        {draft.mode === "note" || draft.mode === "ioc" ? <label>{draft.mode === "note" ? "调查经过与依据" : "线索内容"}<textarea rows={draft.mode === "note" ? 5 : 2} maxLength={draft.mode === "note" ? 8192 : 4096} value={draft.content} onChange={(event) => setDraft({ ...draft, content: event.target.value })} /><span>{[...draft.content].length} / {draft.mode === "note" ? 4096 : 2048} 字 · 保存后作为独立记录保留</span></label> : null}
        {draft.mode === "ioc" ? <p>IOC 是用于调查的可疑特征；手工加入线索不会自动扫描，也不代表已证实入侵。</p> : null}
        {draft.mode === "attach" ? <div className="case-note-picker"><p>保存所选笔记的完整正文快照（最多 4096 字），不会随笔记中的后续编辑变化。</p>
          <label>搜索笔记<input value={noteQuery} maxLength={256} onChange={(event) => setNoteQuery(event.target.value)} /></label><button type="button" onClick={() => void loadNotes(noteQuery, 0)}>查找笔记</button>
          <div className="case-note-choices">{notes?.items.map((note) => <button type="button" key={note.id} aria-pressed={draft.note?.id === note.id} onClick={() => void chooseNote(note.id)}>{note.title}<small>{note.contentPreview || "空白笔记"}</small></button>)}</div>
          {notes?.items.length === 0 ? <p>{noteQuery.trim() === "" && notes.offset === 0 ? "还没有笔记。" : "没有匹配的笔记。"}可先在笔记中记录，或直接添加调查记录。</p> : null}
          {notes !== null ? <div className="case-actions"><button type="button" disabled={notes.offset === 0} onClick={() => void loadNotes(noteQuery, Math.max(0, notes.offset - 25))}>上一页笔记</button><span>共 {notes.total} 篇</span><button type="button" disabled={!notes.hasMore} onClick={() => void loadNotes(noteQuery, notes.offset + 25)}>下一页笔记</button></div> : null}
          {draft.note !== null ? <div><h3>即将关联：{draft.note.title}</h3><pre>{draft.note.content || "（正文为空）"}</pre><small>笔记更新时间：{stamp(draft.note.updatedAt)}</small></div> : null}
        </div> : null}
      </fieldset>
      <div className="case-actions"><button type="submit" className="case-primary" disabled={state.busy || noteBusy || draft.binding !== bindingHandle || draft.mode === "attach" && draft.note === null}>{state.busy ? "正在保存…" : draft.mode === "create" ? "创建并设为当前" : "保存到此案"}</button><button type="button" disabled={state.busy || noteBusy} onClick={() => void cancelDraft()}>取消编辑</button>{noteBusy ? <span role="status">正在读取笔记…</span> : null}</div>
    </form> : null}
    {bindingHandle === null ? <p className="case-empty">连接主机后即可查看属于该主机的案件。案件记录保存在本机便携数据中。</p> : <div className="case-columns">
      <aside className="case-list"><label>筛选案件<input value={caseQuery} maxLength={256} onChange={(event) => setCaseQuery(event.target.value)} placeholder="按案件名称查找" /></label>
        <p className="case-capacity">此主机 {state.list?.cases.length ?? "—"} 个 · 本机共 {state.list?.totalCases ?? "—"} / 30 个</p>
        {state.list !== null && state.list.totalCases >= 30 ? <p className="case-help">活动案件已达上限。可在“本机案件库”归档旧案，保留完整记录并释放名额。</p> : null}
        {visibleCases.map((item) => <button className="case-list-item" key={item.id} disabled={state.busy} aria-pressed={incident?.id === item.id} onClick={() => void showCase(item.id)}><strong>{item.title}</strong><span>{item.id === state.list?.activeCaseId ? "当前归档案件" : item.status === "closed" ? "已关闭" : "调查中"} · {item.evidenceCount} 条证据</span><small>{stamp(item.updatedAt)}</small></button>)}
        {state.list !== null && visibleCases.length === 0 ? <p>{state.list.cases.length === 0 ? "这台主机还没有案件。新建案件，或从命令工作台下载留证后自动建案。" : "没有匹配的案件，试试其他名称。"}</p> : null}
        <p className="case-help">浏览案件只切换视图。“设为当前案件”才会改变后续采集的归属。</p>
      </aside>
      <div className="case-detail">
        {incident !== undefined ? <><header><h2>{incident.title}</h2><p>{current ? "当前归档案件" : incident.status === "closed" ? "已关闭 · 仅供查看和报告" : "正在查看 · 后续采集仍归入当前案件"} · 更新于 {stamp(incident.updatedAt)}</p>
          <div className="case-actions">{!current && incident.status === "open" ? <button disabled={!canWrite || draft !== null} onClick={() => void controller.mutate({ action: "select", bindingHandle: bindingHandle!, caseId: incident.id })}>设为当前案件</button> : null}
            <button disabled={!canWrite} onClick={(event) => void start("note", event.currentTarget)}>添加调查记录</button><button disabled={!canWrite} onClick={(event) => void start("ioc", event.currentTarget)}>添加线索</button><button disabled={!canWrite} onClick={(event) => void start("attach", event.currentTarget)}>关联笔记</button>
            <button disabled={state.busy} onClick={(event) => { const button = event.currentTarget, binding = bindingHandle; void controller.report().then((result) => { if (result !== null && binding !== null && scopeRef.current === binding) onReport(result.report, button, binding); }); }}>生成此案报告</button>
            {onStatusCase !== undefined ? <button disabled={state.busy} onClick={() => void onStatusCase(incident.id, incident.status === "open" ? "close" : "reopen")}>{incident.status === "open" ? "结案并记录结论" : "重新调查"}</button> : null}</div>
          <p className="case-help">报告包含当前查看的案件快照和此主机的处置记录。原始文件仍保存在下载留证时选择的目录中。</p></header>
          <nav className="case-tabs" aria-label="案件内容">{(["evidence", "iocs", "timeline"] as const).map((key) => <button key={key} aria-pressed={state.section === key} onClick={() => section(key)} disabled={state.busy}>{sectionLabels[key]} <span>{key === "evidence" ? incident.evidenceCount : key === "iocs" ? incident.iocCount : incident.timelineCount}</span></button>)}</nav>
          <label className="case-search">搜索{sectionLabels[state.section]}<input ref={searchRef} value={search} maxLength={256} onChange={(event) => changeSearch(event.target.value)} placeholder="支持内容、来源、路径、摘要或记录编号" /></label>
          {state.page !== null ? <><div className="case-entries">{state.page.items.map((item) => <Entry key={item.id} item={item} section={state.section} onRelated={(key, query) => section(key, query, true)} />)}</div>
            {state.page.total === 0 ? <p className="case-empty">{search.trim() ? "没有匹配记录，可换个关键词或清空搜索。" : state.section === "evidence" ? "此案还没有证据。可以添加调查记录、关联笔记，或设为当前案件后从命令工作台下载留证。" : state.section === "iocs" ? "尚未添加调查线索。" : "尚无时间线记录。"}</p> : null}
            <div className="case-pagination"><button disabled={state.busy || state.offset === 0} onClick={() => void controller.items(state.section, state.query, Math.max(0, state.offset - 25))}>上一页</button><span>{state.page.total === 0 ? "0" : `${state.offset + 1}–${state.offset + state.page.items.length}`} / {state.page.total} 条</span><button disabled={state.busy || !state.page.hasMore} onClick={() => void controller.items(state.section, state.query, state.offset + 25)}>下一页</button></div></> : null}
        </> : !state.busy ? <p className="case-empty">选择左侧案件，查看证据和调查经过。</p> : null}
        {state.busy ? <p role="status">正在处理案件…</p> : null}
      </div>
    </div>}
    {dialog !== null ? <DialogHost dialog={dialog} onResolve={resolve} /> : null}
  </section>;
});

export function Entry({ item, section, onRelated }: { item: CaseEntry; section: CaseSection; onRelated(section: CaseSection, query: string): void }) {
  return <article className="case-entry"><header><strong>{item.title}</strong><span>{labels[item.category] ?? item.category} · {stamp(item.timestamp)}</span></header>
    {item.text !== "" ? <pre>{item.text}</pre> : null}
    <details><summary>来源与完整性详情</summary><dl><dt>记录编号</dt><dd>{item.id}</dd><dt>来源</dt><dd>{item.source}</dd>
      {item.locator !== null ? <><dt>原件 / 笔记位置</dt><dd>{item.locator}</dd></> : null}
      {item.sha256 !== null ? <><dt>SHA-256</dt><dd className="case-hash">{item.sha256}</dd><dt>摘要范围</dt><dd>{item.hashScope === "external-artifact" ? "外部原始文件；报告不包含文件本体" : "本机存储的记录内容及其元数据；不是远端原始文件摘要"}</dd></> : null}
      {item.operationId !== null ? <><dt>处置记录编号</dt><dd>{item.operationId}</dd></> : null}</dl></details>
    {section === "timeline" && item.evidenceId !== null ? <button onClick={() => onRelated("evidence", item.evidenceId!)}>查看关联证据</button> : null}
    {section === "timeline" && item.iocId !== null ? <button onClick={() => onRelated("iocs", item.iocId!)}>查看关联线索</button> : null}
  </article>;
}
