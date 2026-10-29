import { useEffect, useRef, useState } from "react";
import { roleAccessModes, type PostgresqlRolePage, type RoleAccessMode, type RoleAttributes, type RoleGraphReason, type RoleGraphSummary } from "../shared/postgresql-role-contract";

export const roleModeText: Record<RoleAccessMode, string> = { member: "全部成员路径", inherit: "自动继承的普通权限来源", set: "允许切换到的角色", "after-set": "切换后新增的普通权限来源" };
const gaps: Record<RoleGraphReason, string> = { "roles-unavailable": "角色数据未完整取得", "memberships-unavailable": "成员授权未完整取得", "database-unavailable": "当前数据库及所有者未能稳定核对", "invalid-graph": "角色引用或关系无法完整核对" };
export function roleManagement(role: RoleAttributes): string {
  return [[role.superuser,"超级用户"],[role.createRole,"创建角色"],[role.createDatabase,"创建数据库"],[role.replication,"复制"],[role.bypassRls,"绕过行级安全"]].filter(([yes]) => yes).map(([,name]) => name).join("、") || "未设置这些管理属性";
}
export function PostgresqlRolePanel({ summary, source, page, busy, onRead }: {
  summary: RoleGraphSummary; source: RoleAttributes | null; page: PostgresqlRolePage | null; busy: boolean;
  onRead?: ((oid: number, mode: RoleAccessMode, query: string, offset: number) => unknown) | undefined;
}): React.JSX.Element {
  const [mode,setMode] = useState<RoleAccessMode>("inherit");
  const [query,setQuery] = useState("");
  const lastFocused = useRef<PostgresqlRolePage | null>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const current = page?.roleOid === source?.oid && page?.mode === mode ? page : null;
  useEffect(() => {
    if (!busy && current && current !== lastFocused.current && heading.current) { lastFocused.current = current; heading.current.focus({ preventScroll: true }); heading.current.scrollIntoView({ block: "start" }); }
  },[current,busy]);
  const load = (mode: RoleAccessMode, query: string, offset: number): void => { if (source) void onRead?.(source.oid,mode,query,offset); };
  return <section aria-label="角色权限来源"><h5 ref={heading} tabIndex={-1}>角色权限来源{source ? ` · ${source.name}` : ""}</h5>
    {summary.state === "unavailable" ? <p>本次无法分析：{gaps[summary.reason]}。请先复核对应读取状态；这不表示没有权限关联。</p> : <>
      <p>可经角色切换获得额外管理属性的登录角色：{summary.additionalManagementLogins} 个。</p>
      <p>当前数据库：{summary.database.name}（OID：{summary.database.oid}），所有者 OID：{summary.database.ownerOid}。数据库所有者隐式属于 pg_database_owner，此关系随数据库变化。</p>
      {source ? <><p>以此角色作为会话身份分析。{source.canLogin ? "该角色设置了 LOGIN，实际登录仍取决于认证、网络和其他限制。" : "该角色未设置 LOGIN，不能据此认定可直接登录。"}自身管理属性：{roleManagement(source)}。</p>
        <form className="database-toolbar" onSubmit={e => { e.preventDefault(); load(mode,query,0); }}>
          <label>权限路径类型<select disabled={busy} value={mode} onChange={e => { const next = e.target.value as RoleAccessMode; setMode(next); setQuery(""); load(next,"",0); }}>{roleAccessModes.map(m => <option value={m} key={m}>{roleModeText[m]}</option>)}</select></label>
          <label>搜索权限来源<input type="search" value={query} maxLength={128} onChange={e => setQuery(e.target.value)} placeholder="目标角色名称" /></label><button disabled={busy || !onRead}>搜索角色路径</button>
        </form>
        <p>{mode === "member" ? "成员关系只表示存在授权链；必须再看每条授权的 INHERIT 和 SET 选项。" : mode === "inherit" ? "这里只计算普通对象权限的自动继承。SUPERUSER、CREATEDB、CREATEROLE、REPLICATION、BYPASSRLS 不随普通权限继承。" : mode === "set" ? "列出允许成为的角色。SET ROLE 权限以原始会话身份为准；目标的管理属性不能当作当前已经拥有的属性。" : "展示先切换角色再继承普通权限时新增的来源。切换可能同时失去当前部分权限，列表不表示可以同时使用所有来源。"}</p>
        {current ? <><div className="database-table"><table><caption>{roleModeText[mode]} · 共 {current.total} 项，匹配 {current.matched} 项 · 每页 20 项</caption>
          <thead><tr><th>目标角色 / 管理属性</th><th>一条可行来源路径</th></tr></thead><tbody>{current.rows.map(row => <tr key={row.target.oid}><td>{row.target.name}<p>OID：{row.target.oid}</p><p>{roleManagement(row.target)}（是否适用取决于路径类型）</p></td><td>
            <ol>{row.steps.map((step,i) => <li key={step.role.oid}>{step.role.name}（OID：{step.role.oid}）{i ? ` · ${step.via === "database-owner" ? "当前数据库所有者的隐式关系" : step.via === "superuser" ? "超级用户的普通权限或角色切换规则" : `授权 OID ${step.grantOid}`} · ${step.operation === "set" ? "允许切换" : step.operation === "inherit" ? "普通权限继承" : "成员关系"}` : " · 起点"}</li>)}</ol>
            <p>{row.hops} 步{row.truncated ? "；路径过长，仅显示前 32 个角色，目标见左列。" : "；存在其他路径时仅展示其中一条。"}</p>
          </td></tr>)}</tbody></table>{current.rows.length === 0 ? <p>当前类型和搜索没有匹配路径；未检查具体对象授权，也不构成安全结论。</p> : null}</div>
          <div className="database-toolbar"><button disabled={busy || current.offset === 0} onClick={() => load(mode,current.query,Math.max(0,current.offset-20))}>角色路径上一页</button><button disabled={busy || current.offset+20 >= current.matched} onClick={() => load(mode,current.query,current.offset+20)}>角色路径下一页</button></div>
        </> : <p>{busy ? "正在读取角色路径…" : "选择路径类型以查看结果。"}</p>}
      </> : <p>点击“查看角色属性”，再选择角色旁的“查看权限来源”。</p>}
      <details><summary>理解继承、切换与分析范围</summary><p>本功能只读分析，不会执行 SET ROLE。每条成员授权的 INHERIT、SET、ADMIN 分别控制继承、切换与成员管理；角色自身 INHERIT 属性在 PostgreSQL 16 及以后用于新授权的默认值，不会改变已有授权选项。</p><p>切换角色不会自动应用该角色的 ALTER ROLE 会话设置；复制连接等能力还有协议与会话前提。ADMIN 标志不能代替对应版本的实际授权检查。表、函数、数据库等对象授权和 PUBLIC 权限可在对象诊断中另行查看；通过函数执行代码等间接途径尚未分析。</p></details>
    </>}
  </section>;
}
