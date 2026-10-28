import { TransientNotice } from "./NotificationCenter";
import { forwardRef, useEffect, useImperativeHandle, useMemo, useRef, useState, useSyncExternalStore } from "react";
import type { PostgresqlPasswordChange, PostgresqlProfileInput, PostgresqlRuntimeApi, PostgresqlRuntimeRow, PostgresqlSessionObservation } from "../shared/postgresql-runtime-contract";
import { PostgresqlRuntimeController } from "./postgresql-runtime-controller";
import { DialogHost } from "./DialogHost";
import { useConfirmDialog } from "./use-confirm-dialog";
import { PostgresqlHostProcessPanel } from "./PostgresqlHostProcessPanel";
import { PostgresqlAccessPanel } from "./PostgresqlAccessPanel";
import "./database-page.css";

export interface DatabasePageHandle { beforeDeactivate(): Promise<boolean> }
export interface DatabasePageProps { api: PostgresqlRuntimeApi; bindingHandle: string | null; targetLabel: string }
interface Editor { handle: string | null; input: PostgresqlProfileInput; initial: string; password: string; passwordAction: "keep" | "replace" | "remove"; unassigned: boolean }
const initial: PostgresqlProfileInput = { name: "", host: "127.0.0.1", port: 5432, username: "postgres", database: "postgres", tlsMode: "verify-full", caPem: null };
const explanations: Record<string, string> = {
  ssl: "允许数据库 TLS 连接；仍需结合访问规则确认所有业务连接是否强制加密。",
  logging_collector: "收集标准错误日志；关闭时也可能由其他日志系统接收。",
  log_connections: "记录连接尝试及认证信息，帮助追溯访问。", log_disconnections: "记录会话结束信息。",
  password_encryption: "控制以后设置的口令格式；已有口令不会随此设置自动升级。",
  log_statement: "语句日志可能包含敏感业务数据，应结合审计与存储策略判断。",
  listen_addresses: "监听范围还需结合防火墙、访问规则及实际端口判断。",
  ssl_min_protocol_version: "允许的最低 TLS 协议版本。", ssl_max_protocol_version: "空值表示未设置最高版本限制。",
  default_transaction_read_only: "本次检查会话主动使用只读事务；不能据此判断业务账号权限。",
};
export function runtimeValue(row: PostgresqlRuntimeRow): string {
  if (row.sensitivity !== "public") return row.presence === "null" ? "未提供" : row.presence === "empty" ? "空值（已保护）" : "已隐藏敏感值";
  return row.value === "" ? "空值" : row.value ?? "未提供";
}
const pathLabels: Record<string, string> = { config_file: "主配置", data_directory: "数据目录", hba_file: "访问规则", ident_file: "身份映射" };
function endpoint(address: string | null, port: number | null): string {
  return address === null ? "服务端未提供" : `${address.includes(":") ? `[${address}]` : address}:${port}`;
}
export function PostgresqlObservationPanel({ session, expert }: { session: PostgresqlSessionObservation; expert: boolean }) {
  const missing = session.origins.filter(item => item.source === null);
  return <section className="database-session" aria-label="数据库会话与来源"><h4>本次连接的数据库</h4>
    <dl><dt>数据库 / 登录身份</dt><dd>{session.databaseName} / {session.sessionUser}</dd>
      <dt>服务端连接地址</dt><dd>{endpoint(session.serverAddress, session.serverPort)}</dd>
      <dt>集群标识</dt><dd>{session.clusterIdentifier ?? "无读取权限，未取得"}</dd>
      <dt>恢复模式</dt><dd>{session.inRecovery ? "正在恢复或作为备库运行" : "本次未处于恢复模式"}</dd></dl>
    <p>这些信息由数据库报告，请结合下方主机实例核对结果理解；集群副本也可能共用标识。</p>
    {missing.length ? <p role="status">{missing.length} 项重点参数未取得：{missing.map(item => item.name).join("、")}。当前账号权限或数据库版本可能限制其可见性，这些项目仍需核实。</p> : null}
    {expert ? <details className="database-source-details"><summary>会话与配置来源详情（10 项重点参数）</summary>
      <dl><dt>数据库 OID / 会话 PID</dt><dd>{session.databaseOid} / {session.backendPid}</dd>
        <dt>执行身份 / 客户端地址</dt><dd>{session.effectiveUser} / {endpoint(session.clientAddress, session.clientPort)}</dd>
        <dt>服务端观察时间（UTC）</dt><dd>{session.observedAt}</dd><dt>服务启动时间（UTC）</dt><dd>{session.serverStartedAt}</dd>
        <dt>会话报告的配置加载时间（UTC）</dt><dd>{session.configurationLoadedAt}</dd></dl>
      <h4>服务端报告的配置位置</h4><dl>{session.paths.map(item => <div key={item.name}><dt>{pathLabels[item.name]}</dt><dd>{item.path ?? "未取得路径"}</dd></div>)}</dl>
      {!session.settingsReadable ? <p>当前账号没有完整参数来源读取权限，部分路径、来源或行号可能不可见。</p> : null}
      <div className="database-table" tabIndex={0} role="region" aria-label="重点参数来源，可横向滚动"><table><thead><tr><th>参数</th><th>来源</th><th>来源文件 / 行号</th><th>等待重启</th></tr></thead>
        <tbody>{session.origins.map(item => <tr key={item.name}><th scope="row">{item.name}</th><td>{item.source ?? "未取得"}</td><td>{item.sourceFile ?? "未提供文件来源"}{item.sourceLine !== null ? ` · 第 ${item.sourceLine} 行` : ""}</td><td>{item.pendingRestart === null ? "未取得" : item.pendingRestart ? "是" : "否"}</td></tr>)}</tbody></table></div>
      <p>文件来源为空可能因为权限不足或该值来自会话、默认值等其他来源。这里只记录十项重点参数的来源，未读取配置内容、完整 include 关系或访问规则。查询前后会核对会话与配置加载信息；这不构成磁盘原子快照。路径和已结束会话的 PID 不能直接用于修补、重启或结束进程。</p>
    </details> : null}
  </section>;
}
export const DatabasePage = forwardRef<DatabasePageHandle, DatabasePageProps>(function DatabasePage({ api, bindingHandle, targetLabel }, ref) {
  const controller = useMemo(() => new PostgresqlRuntimeController(api, bindingHandle ?? ""), [api, bindingHandle]);
  const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
  const [editor, setEditor] = useState<Editor | null>(null);
  const activeController = useRef(controller); activeController.current = controller;
  const editorRef = useRef(editor); editorRef.current = editor;
  const savingTask = useRef<Promise<void> | null>(null);
  const [expert, setExpert] = useState(false);
  const [query, setQuery] = useState("");
  const [saving, setSaving] = useState(false);
  const [dialogBusy, setDialogBusy] = useState(false);
  const dialog = useConfirmDialog();
  const nameInput = useRef<HTMLInputElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const selected = state.profiles.find(profile => profile.profileHandle === state.selected);
  const reading = state.job?.state === "reading";
  const unsaved = state.job?.retention?.state === "unsaved";
  const blocked = state.busy || reading || saving || dialogBusy || unsaved;
  useEffect(() => {
    setEditor(null); editorRef.current = null; setSaving(false); setDialogBusy(false); setQuery("");
    if (dialog.dialog) dialog.resolve({ kind: "cancelled", dialogId: dialog.dialog.id });
    if (bindingHandle) void controller.list();
    return controller.dispose;
  }, [bindingHandle, controller]);
  useEffect(() => { if (editor) nameInput.current?.focus(); }, [editor?.handle, editor !== null]);
  const leaveEditor = async (): Promise<boolean> => {
    const current = editorRef.current;
    const dirty = current !== null && (JSON.stringify(current.input) !== current.initial || current.passwordAction !== "keep" || current.password !== "");
    if (dirty && !(await dialog.ask("保留连接编辑？", "当前数据库连接尚未保存。离开会丢弃本次编辑和未保存的口令。", "丢弃并离开"))) return false;
    if (activeController.current !== controller) return false;
    editorRef.current = null; setEditor(null); return true;
  };
  const discardEvidence = async (): Promise<boolean> => {
    if (!controller.hasUnsaved()) return true;
    if (!(await dialog.ask("放弃未保存的检查摘要？", "本次摘要尚未进入案件。可以取消后重试留证，或先展开记录并复制。放弃后，再次读取会产生新的观察，不能替代本次记录。", "放弃本次未保存摘要"))) return false;
    if (activeController.current !== controller) return false;
    await controller.discard();
    return activeController.current === controller && !controller.hasUnsaved();
  };
  useImperativeHandle(ref, () => ({ beforeDeactivate: async () => {
    if (dialogBusy) return false;
    await savingTask.current;
    if (activeController.current !== controller) return false;
    if (!(await leaveEditor())) return false;
    const leave = await controller.prepareToLeave(reason => reason === "uncertain"
      ? dialog.ask("读取状态尚未核实", "未能确认当前读取是否结束。可以取消离开并再次尝试停止；继续离开后，如选择了留证，请保留本次反馈并核对本机留证记录，避免把状态未知当作成功或未执行。", "继续离开")
      : dialog.ask("放弃未保存的检查摘要？", "本次摘要尚未进入案件。可以取消后重试留证，或先展开记录并复制。放弃后，再次读取会产生新的观察，不能替代本次记录。", "放弃本次未保存摘要"));
    return activeController.current === controller && leave;
  } }));
  const startEditor = async (create: boolean): Promise<void> => {
    if (!(await leaveEditor())) return;
    if (create) { setEditor({ handle: null, input: { ...initial }, initial: JSON.stringify(initial), password: "", passwordAction: "keep", unassigned: false }); return; }
    if (!selected) return;
    const result = await controller.request({ action: "edit", bindingHandle: controller.binding, profileHandle: selected.profileHandle });
    if (activeController.current !== controller || result?.kind !== "editor") return;
    const { name, host, port, username, database, tlsMode } = result.profile;
    const input = { name, host, port, username, database, tlsMode, caPem: result.caPem };
    setEditor({ handle: result.profile.profileHandle, input, initial: JSON.stringify(input), password: "", passwordAction: "keep", unassigned: result.profile.unassigned });
  };
  const save = (): void => {
    if (!editor || savingTask.current) return;
    setSaving(true);
    const password: PostgresqlPasswordChange = editor.passwordAction === "replace" ? { action: "replace", value: editor.password } : { action: editor.passwordAction };
    const task = (async () => {
      try {
        const result = await controller.request({ action: "save", bindingHandle: controller.binding, profileHandle: editor.handle, profile: editor.input, password });
        if (activeController.current !== controller) return;
        if (result?.kind === "saved") { editorRef.current = null; setEditor(null); heading.current?.focus(); }
        else setEditor(current => current ? { ...current, password: "" } : null);
      } finally { if (activeController.current === controller) setSaving(false); }
    })();
    savingTask.current = task;
    void task.finally(() => { if (savingTask.current === task) savingTask.current = null; });
  };
  const remove = async (): Promise<void> => {
    if (!selected || blocked) return;
    setDialogBusy(true);
    try {
      const result = await controller.request({ action: "plan-delete", bindingHandle: controller.binding, profileHandle: selected.profileHandle });
      if (result?.kind !== "delete-plan") return;
      if (!(await dialog.ask("删除保存的数据库连接？", `SSH 主机：${targetLabel}\n连接：${result.profile.name}\n数据库：${result.profile.username}@${result.profile.host}:${result.profile.port}/${result.profile.database}\n\n将删除本机保存的连接和加密口令。数据库内容不受影响；以后需重新填写连接。确认在两分钟内有效，配置发生变化时会拒绝删除。`, "删除本机连接"))) return;
      await controller.request({ action: "delete", bindingHandle: controller.binding, planHandle: result.planHandle });
    } finally { if (activeController.current === controller) { setDialogBusy(false); heading.current?.focus(); } }
  };
  const field = (key: keyof PostgresqlProfileInput, value: string | number | null): void => setEditor(current => current ? { ...current, input: { ...current.input, [key]: value } } : null);
  return <section className="database-page" aria-label="数据库检查">
    <div inert={dialog.dialog !== null}>
      <header><div><h2 ref={heading} tabIndex={-1}>PostgreSQL 数据库检查</h2><p>通过 SSH 加密通道连接数据库，核实版本、读取参数和访问规则，检查角色直接权限。当前支持 PostgreSQL 16–18 的社区版本身份识别。</p></div>
        <label className="database-mode"><input type="checkbox" checked={expert} onChange={event => setExpert(event.target.checked)} />专家详情</label></header>
      <p className="database-target">SSH 主机：<strong>{targetLabel}</strong></p>
      {!bindingHandle ? <p className="database-empty">请先连接 SSH 主机，再添加数据库连接。</p> : <>
        <div className="database-toolbar">
          <label>数据库连接<select aria-label="数据库连接" disabled={blocked || editor !== null} value={state.selected ?? ""} onChange={event => { controller.select(event.target.value); setQuery(""); }}>
            <option value="" disabled>选择连接</option>{state.profiles.map(profile => <option key={profile.profileHandle} value={profile.profileHandle}>{profile.name}{profile.unassigned ? " · 待关联" : ""}</option>)}
          </select></label>
          <button disabled={blocked || editor !== null} onClick={() => void controller.list()}>刷新连接</button>
          <button disabled={blocked} onClick={() => void startEditor(true)}>添加连接</button>
          <button disabled={blocked || !selected} onClick={() => void startEditor(false)}>编辑连接</button>
          <button disabled={blocked || !selected || editor !== null} onClick={() => void remove()}>删除连接</button>
        </div>
        {!state.profiles.length && !state.busy && !editor ? <div className="database-empty">
          <p>这台 SSH 主机还没有数据库连接。添加地址、账号和证书后，即可开始只读检查。</p>
          <button type="button" className="database-primary" disabled={blocked} onClick={() => void startEditor(true)}>添加数据库连接</button>
        </div> : null}
        {editor ? <form className="database-editor" onSubmit={event => { event.preventDefault(); void save(); }}>
          <h3>{editor.handle ? "编辑数据库连接" : "添加数据库连接"}</h3>
          {editor.unassigned ? <p>此旧连接尚未关联 SSH 主机。请核对以下地址；保存后将关联到上方主机。</p> : null}
          <p>数据库地址从 SSH 主机访问；127.0.0.1 指 SSH 主机自身。口令只用于数据库认证，加密保存在本机。</p>
          <fieldset disabled={saving || state.busy}><div className="database-fields">
            <label>连接名称<input ref={nameInput} required maxLength={256} value={editor.input.name} onChange={event => field("name", event.target.value)} /></label>
            <label>数据库地址<input required maxLength={253} value={editor.input.host} onChange={event => field("host", event.target.value)} /></label>
            <label>端口<input type="number" required min={1} max={65535} value={editor.input.port || ""} onChange={event => field("port", Number(event.target.value))} /></label>
            <label>数据库用户名<input required maxLength={128} autoComplete="off" value={editor.input.username} onChange={event => field("username", event.target.value)} /></label>
            <label>数据库名称<input required maxLength={128} value={editor.input.database} onChange={event => field("database", event.target.value)} /></label>
            <label>数据库加密<select value={editor.input.tlsMode} onChange={event => setEditor(current => current ? { ...current, input: { ...current.input, tlsMode: event.target.value as PostgresqlProfileInput["tlsMode"], caPem: null } } : null)}>
              <option value="verify-full">TLS · 校验证书和地址</option><option value="ssh-loopback">仅 SSH 加密 · 数据库必须在回环地址</option></select></label>
          </div>
          {editor.input.tlsMode === "verify-full" ? <label>CA 证书（PEM，可选）<textarea rows={4} maxLength={65536} autoComplete="off" spellCheck={false} placeholder="留空使用系统信任的证书机构；私有证书可粘贴一张 CA 公钥证书。" value={editor.input.caPem ?? ""} onChange={event => field("caPem", event.target.value || null)} /></label>
            : <p>SSH 通道保持加密；SSH 主机到本机数据库这一段不使用 TLS，仅允许 127.0.0.0/8 或 ::1 回环地址。</p>}
          <div className="database-fields"><label>口令处理<select value={editor.passwordAction} onChange={event => setEditor(current => current ? { ...current, passwordAction: event.target.value as Editor["passwordAction"], password: "" } : null)}>
            <option value="keep">{editor.handle ? "保留已保存口令" : "暂不保存口令"}</option><option value="replace">设置新口令</option><option value="remove">移除已保存口令</option></select></label>
            {editor.passwordAction === "replace" ? <label>新口令<input type="password" required maxLength={16384} autoComplete="new-password" value={editor.password} onChange={event => setEditor(current => current ? { ...current, password: event.target.value } : null)} /></label> : null}</div>
          <div className="database-toolbar"><button type="submit">{saving ? "正在保存…" : editor.unassigned ? "保存并关联此主机" : "保存连接"}</button><button type="button" onClick={() => { void leaveEditor().then(left => { if (left) heading.current?.focus(); }); }}>取消编辑</button></div>
          </fieldset>
        </form> : !state.profiles.length ? null : <div className="database-toolbar">
          <button disabled={blocked || !selected || selected.unassigned} onClick={() => { setQuery(""); void controller.begin(); }}>读取数据库状态</button>
          <button disabled={blocked || !selected || selected.unassigned} onClick={() => { setQuery(""); void controller.begin(true); }}>读取并留证</button>
          {reading ? <button onClick={() => void controller.cancel()}>取消读取</button> : null}
          {selected?.unassigned ? <p>此旧连接需要先编辑并保存，明确关联当前 SSH 主机。</p> : selected ? <p>{selected.username}@{selected.host}:{selected.port}/{selected.database} · {selected.tlsMode === "verify-full" ? "TLS 校验证书与地址" : "SSH 加密 / 数据库回环连接"} · {selected.hasPassword ? "已保存口令" : "未保存口令"}</p> : null}
        </div>}
        {!editor && state.profiles.length ? <p className="database-hint">“读取并留证”会把会话与进程对应状态、十项重点参数、访问诊断数量及检查结果保存到开始时的采集案件，未选择时创建案件。失败和取消也记录结果；普通读取仅在内存展示。</p> : null}
      </>}
      {state.error ? <TransientNotice source="数据库" message={state.error ?? ""} severity="error"><p role="alert" className="database-error">{state.error}</p></TransientNotice> : null}
      {state.notice ? <TransientNotice source="数据库" message={state.notice ?? ""} severity="info"><p role="status">{state.notice}</p></TransientNotice> : null}
      {state.job ? <section className="database-result"><h3>{{ reading: "正在读取", completed: "读取完成", failed: "读取未完成", cancelled: "读取已取消", expired: "检查结果已过期" }[state.job.state]}</h3>
        <p role="status">{state.job.detail}</p><p>{state.job.profile.name} · 开始于 {new Date(state.job.startedAt).toLocaleString()}{state.job.finishedAt ? ` · 结束于 ${new Date(state.job.finishedAt).toLocaleString()}` : ""}</p>
        {state.job.retention ? <section className="database-retention" aria-label="案件留证"><h4>{{ pending: "正在准备留证", saved: "检查摘要已留证", unsaved: "检查摘要尚未保存" }[state.job.retention.state]}</h4>
          <p role={unsaved ? "alert" : "status"}>{state.job.retention.detail}</p>
          {state.job.retention.caseId ? <p>归属案件：{state.job.retention.caseTitle} · {state.job.retention.caseId}</p> : <p>归属案件尚未取得；重试时会选择那时的采集案件。</p>}
          {state.job.retention.sha256 ? <p>保存记录 SHA-256：<code>{state.job.retention.sha256}</code></p> : null}
          {state.job.retention.recordText ? <details><summary>查看并复制本次保存记录</summary><label>检查摘要（可全选复制）<textarea readOnly rows={12} value={state.job.retention.recordText} onFocus={event => event.currentTarget.select()} /></label></details> : null}
          {unsaved ? <div className="database-toolbar"><button disabled={state.busy || !state.job.retention.canRetry} onClick={() => void controller.retain()}>重试留证</button><button disabled={state.busy} onClick={() => void discardEvidence()}>放弃本次未保存摘要</button><p>请先处理本次摘要，再开始另一项数据库检查。</p></div> : null}
        </section> : null}
        {state.job.result ? <>
          <p>PostgreSQL {state.job.result.version} · 共 {state.job.result.parameterCount} 个参数 · 本次读取会话使用只读事务。结果保存于内存，十分钟后需重新读取。</p>
          {state.job.result.noticeCount ? <p>数据库返回 {state.job.result.noticeCount} 条通知，其正文未保留。</p> : null}
          <p>以下是观察值，不等同于完整基线合规或业务恢复结论。可能包含秘密的值已隐藏。</p>
          <PostgresqlObservationPanel session={state.job.result.session} expert={expert} />
          <PostgresqlHostProcessPanel inspection={state.job.result.hostProcess} expert={expert} />
          <PostgresqlAccessPanel key={state.job.jobHandle} summary={state.job.result.access} page={state.accessRows} busy={state.busy} expert={expert} onRead={controller.accessRows} rolePage={state.rolePage} onRoleRead={controller.roleAccess} objectPage={state.objectPage} objectDetail={state.objectDetail} onObjectRead={controller.objectRows} onObjectDetail={controller.objectDetail} />
          <div className="database-observations">{state.job.result.observations.map(row => <article key={row.name}><h4>{row.name}</h4><strong>{runtimeValue(row)}</strong><p>{explanations[row.name]}</p><small>来源：{row.source ?? "未提供"}{row.pendingRestart ? " · 等待重启生效" : ""}</small></article>)}</div>
          {expert ? <section aria-label="全部参数"><form className="database-toolbar" onSubmit={event => { event.preventDefault(); void controller.rows(query, 0); }}><label>搜索参数名<input type="search" maxLength={128} value={query} onChange={event => setQuery(event.target.value)} placeholder="例如 ssl、log、password" /></label><button disabled={state.busy}>搜索</button></form>
            {state.rows ? <><p>匹配 {state.rows.matched} / {state.rows.total} 项 · 当前筛选：{state.rows.query || "全部"} · 第 {Math.min(state.rows.offset + 1, state.rows.matched)}–{Math.min(state.rows.offset + 50, state.rows.matched)} 项</p>
              {state.rows.rows.length ? <div className="database-table" tabIndex={0} role="region" aria-label="参数详情，可横向滚动"><table><thead><tr><th>参数</th><th>观察值</th><th>来源 / 生效范围</th><th>取值信息</th></tr></thead><tbody>{state.rows.rows.map(row => <tr key={row.name}><th scope="row">{row.name}</th><td>{runtimeValue(row)}</td><td>{row.source ?? "未提供"}<br />{row.context}{row.pendingRestart ? " · 等待重启" : ""}</td><td>{row.enumValues.length ? row.enumValues.map(value => value === "" ? "（空值）" : value).join(" / ") : `${row.minimum ?? "未提供"} – ${row.maximum ?? "未提供"}`}{row.metadataTruncated ? " · 取值信息过长，仅展示部分" : ""}</td></tr>)}</tbody></table></div> : <p>没有匹配的参数，请调整搜索条件。</p>}
              <div className="database-toolbar"><button disabled={state.busy || state.rows.offset === 0} onClick={() => void controller.rows(state.rows!.query, Math.max(0, state.rows!.offset - 50))}>上一页</button><button disabled={state.busy || state.rows.offset + 50 >= state.rows.matched} onClick={() => void controller.rows(state.rows!.query, state.rows!.offset + 50)}>下一页</button></div>
            </> : <p>正在读取参数详情…</p>}
            <details><summary>如何理解生效范围</summary><p>internal：内部只读；postmaster：通常需重启；sighup：通常需重新加载配置；backend / superuser-backend：影响新连接；user / superuser：可由相应权限的会话调整。此页显示检查会话的观察值，业务会话可能不同。缺少权限、版本不符或结果过期时应重新核实。</p></details>
          </section> : null}
        </> : null}
      </section> : null}
    </div>
    {dialog.dialog ? <DialogHost dialog={dialog.dialog} onResolve={dialog.resolve} /> : null}
  </section>;
});
