import { useEffect, useRef, useState } from "react";
import { objectSections, objectFilters, type ObjectSection, type ObjectFilter, type ObjectGrant, type ObjectGrantVia, type ObjectAnalysis, type ObjectProperties, type PostgresqlObjectsSummary, type PostgresqlObjectRow, type PostgresqlObjectPage, type PostgresqlObjectDetail } from "../shared/postgresql-object-contract";
import type { RoleAttributes } from "../shared/postgresql-role-contract";

export const objectNames: Record<ObjectSection,string> = { database: "当前数据库", schemas: "模式", relations: "表、视图与序列", columns: "单独授权的列", routines: "函数与过程", types: "数据类型", languages: "过程语言", tablespaces: "表空间", "foreign-wrappers": "外部数据包装器", "foreign-servers": "外部服务器", "large-objects": "大对象", parameters: "配置参数授权", defaults: "以后创建对象的默认授权" };
const filterNames: Record<ObjectFilter,string> = { all: "全部对象", public: "授予 PUBLIC", delegated: "允许非所有者转授权", "security-definer": "以定义者权限运行", "unfixed-definer": "定义者函数未固定搜索路径" };
const gaps = { "permission-denied": "没有足够权限读取目录", "query-failed": "目录查询未能完成", "invalid-output": "目录结果无法完整核实", "limit-exceeded": "目录超出本次容量，未展示部分结果", changed: "两次读取期间目录发生变化，请重新读取" };
const viaNames: Record<ObjectGrantVia | "superuser" | "superuser-after-set",string> = { public: "所有角色共有", self: "直接授予此角色", inherit: "可自动继承", "after-set": "切换角色后可能取得", unreachable: "当前已知角色路径不可到达", "unknown-role": "角色引用未能核实", "not-selected": "尚未选择分析角色", "future-default": "以后创建对象时应用", superuser: "自身超级用户属性", "superuser-after-set": "可切换到超级用户" };
const analysisGaps: Record<Extract<ObjectAnalysis,{ state: "unavailable" }>["reason"],string> = { "table-unavailable": "所属表授权未完整取得，不能合并列权限", "unknown-role": "所有者或授权涉及未能核实的角色", "temporary-namespace": "临时对象的权限依赖具体会话，本次未作角色模拟", "database-context": "对象目录与当前数据库身份未能对应" };
const aclSourceNames = { explicit: "目录保存的明确授权", "builtin-default": "目录未单独记录授权（NULL），按此版本内建默认展开", "future-global": "此所有者的全局创建默认值", "future-schema": "此所有者在指定模式的创建附加授权" };
function rights(values: readonly string[]): string { return values.join("、") || "本次未取得这些权限"; }
function identity(name: string | null, oid: number): string { return `${name ?? "名称未取得"}（OID：${oid}）`; }
function objectTitle(row: PostgresqlObjectRow): string { return `${row.namespaceName ? `${row.namespaceName}.` : ""}${row.parentName ? `${row.parentName}.` : ""}${row.name ?? `OID ${row.oid}`}`; }
function Properties({ detail }: { detail: ObjectProperties }): React.JSX.Element | null {
  switch (detail.kind) {
    case "database": return <p>接受连接：{detail.allowConnections ? "允许，仍需满足认证和其他限制" : "未允许"} · 模板库：{detail.isTemplate ? "是" : "否"}</p>;
    case "schema": return detail.sessionTemporary || detail.otherTemporary ? <p>临时模式：{detail.sessionTemporary ? "属于本次读取会话" : "属于其他会话"}。</p> : null;
    case "relation": case "column": return <p>对象类型：{({ r: "普通表", p: "分区表", v: "视图", m: "物化视图", f: "外部表", S: "序列" })[detail.relationKind as "r"]} · 行级安全标志：{detail.rowSecurity ? "启用" : "未启用"} · 强制所有者受行级策略约束标志：{detail.forceRowSecurity ? "启用" : "未启用"}。尚未解析策略或验证可读写的具体行。</p>;
    case "routine": return <><p>以{detail.securityDefiner ? "定义者" : "调用者"}权限运行；函数级 search_path：{detail.fixedSearchPath ? "已设置，路径是否可信仍需核对" : "未设置"}。设置存在不能证明安全。</p><p>过程种类：{detail.routineKind} · 语言 OID：{detail.languageOid} · 参数类型 OID：{detail.argumentTypeOids.join("、") || "无输入参数"}。</p></>;
    case "type": return <p>类型对象所有者 OID：{detail.objectOwnerOid}。授权取自 {identity(detail.aclTypeName,detail.aclTypeOid)}；数组使用元素类型的授权与所有者。</p>;
    case "language": return <p>{detail.trusted ? "标记为受信任语言；仍需相应数据库和对象权限。" : "未标记为受信任语言；创建函数还需要超级用户条件，USAGE 不能代替此要求。"}</p>;
    case "default": return <p>创建对象种类：{({ r: "表", S: "序列", f: "函数与过程", T: "类型", n: "模式" })[detail.objectType as "r"]}。仅影响此所有者以后创建的对象，不改变已存在对象。</p>;
    case "parameter": return <p>仅列出有授权记录的参数；未列出不表示可任意修改。SET 与 ALTER SYSTEM 各有适用范围，未读取参数值。</p>;
    case "large-object": return <p>仅读取大对象的所有者与授权元数据，未读取其内容。</p>;
    default: return null;
  }
}
function Grants({ rows, caption }: { rows: ObjectGrant[]; caption: string }): React.JSX.Element {
  return rows.length ? <div className="database-table"><table><caption>{caption}</caption><thead><tr><th>授予对象 / 来源路径</th><th>普通权限</th><th>允许转授权</th><th>授权者</th></tr></thead><tbody>{rows.map(g => <tr key={`${g.grantorOid}:${g.granteeOid}`}>
    <td>{identity(g.granteeName,g.granteeOid)}<p>{viaNames[g.via]}</p></td><td>{rights(g.privileges)}</td><td>{g.grantOptions.join("、") || "此条未授予"}</td><td>{identity(g.grantorName,g.grantorOid)}</td>
  </tr>)}</tbody></table></div> : <p>{caption}：没有明确条目。所有者的转授权能力与超级用户规则需另看下方分析。</p>;
}
function Analysis({ detail }: { detail: PostgresqlObjectDetail }): React.JSX.Element {
  const analysis = detail.analysis;
  if (!analysis || !detail.role) return <p>{detail.section === "defaults" ? "创建默认值不作现有对象的角色权限分析。全局默认值替换内建默认；模式级授权在全局默认之上增加。" : "可先在角色属性中点击“查看权限来源”，再查看此对象授权，分析指定角色。"}</p>;
  if (analysis.state === "unavailable") return <p>角色授权分析未完成：{analysisGaps[analysis.reason]}。上方目录条目仍可供人工核对。</p>;
  return <section aria-label="此角色的对象权限"><h6>以 {detail.role.name} 作为会话角色</h6>
    <p>当前普通权限：{rights(analysis.currentPrivileges)}。</p><p>当前可再次授予他人的权限：{rights(analysis.currentGrantOptions)}。所有者即使撤销了自身普通权限，仍可再次授予；两者须分别核对。</p>
    <p>切换角色后可能新增的普通权限：{rights(analysis.additionalAfterSet)}。</p><p>切换后可能新增的转授权能力：{rights(analysis.additionalGrantOptionsAfterSet)}。这些来自不同可能身份，切换也可能失去当前权限，不能视为可同时使用。</p>
    <p>所有者权限来源：{viaNames[analysis.ownerVia]}。{detail.object.namespaceOid === null ? "" : `当前角色对所属模式的 USAGE：${analysis.schemaUsage === null ? "未能核实" : analysis.schemaUsage ? "已找到授权来源" : "未找到授权来源"}。`}</p>
    {analysis.implicit.length ? <ul>{analysis.implicit.map(g => <li key={`${g.sourceOid}:${g.via}`}>{identity(g.sourceName,g.sourceOid)} · {viaNames[g.via]} · {rights(g.privileges)}</li>)}</ul> : null}
  </section>;
}
export function PostgresqlObjectPanel({ summary, source, page, detail, busy, onRead, onDetail }: {
  summary: PostgresqlObjectsSummary; source: RoleAttributes | null; page: PostgresqlObjectPage | null; detail: PostgresqlObjectDetail | null; busy: boolean;
  onRead?: ((section: ObjectSection, query: string, filter: ObjectFilter, offset: number) => unknown) | undefined;
  onDetail?: ((section: ObjectSection, oid: number, subId: number, roleOid: number | null) => unknown) | undefined;
}): React.JSX.Element {
  const [section,setSection] = useState<ObjectSection>("relations"), [query,setQuery] = useState(""), [filter,setFilter] = useState<ObjectFilter>("all");
  const heading = useRef<HTMLHeadingElement>(null), detailHeading = useRef<HTMLHeadingElement>(null);
  const focusedPage = useRef<PostgresqlObjectPage | null>(null), focusedDetail = useRef<PostgresqlObjectDetail | null>(null);
  const current = page?.section === section && page.filter === filter ? page : null;
  const roleOid = section === "defaults" ? null : source?.oid ?? null;
  const selected = detail?.section === section && detail.roleOid === roleOid && current?.rows.some(r => r.oid === detail.oid && r.subId === detail.subId) ? detail : null;
  useEffect(() => {
    if (busy) return;
    if (selected && selected !== focusedDetail.current && detailHeading.current) { focusedDetail.current = selected; detailHeading.current.focus({ preventScroll: true }); detailHeading.current.scrollIntoView({ block: "start" }); }
    else if (current && current !== focusedPage.current && heading.current) { focusedPage.current = current; heading.current.focus({ preventScroll: true }); heading.current.scrollIntoView({ block: "start" }); }
  },[busy,current,selected]);
  const s = summary[section];
  const load = (section: ObjectSection, query: string, filter: ObjectFilter, offset = 0): void => { if (summary[section].state === "available") void onRead?.(section,query,filter,offset); };
  return <section aria-label="对象授权诊断" className="database-objects"><h5>对象授权诊断</h5>
    <p>查看谁能够访问数据库中的对象、权限从哪里来，以及谁还能转授权。当前已取得 {objectSections.filter(s => summary[s].state === "available").length} / {objectSections.length} 类目录；各目录的缺口单独保留。</p>
    <p>{source ? `已选角色：${identity(source.name,source.oid)}。点击对象的“查看授权”可同时分析此角色。` : "尚未选择角色，可先查看 PUBLIC 和各项授权；若需分析指定角色，先查看角色属性并选择权限来源。"}</p>
    <form className="database-toolbar" onSubmit={e => { e.preventDefault(); load(section,query,filter); }}>
      <label>对象类别<select value={section} disabled={busy} onChange={e => { const next = e.target.value as ObjectSection; setSection(next); setQuery(""); setFilter("all"); load(next,"","all"); }}>{objectSections.map(k => <option key={k} value={k}>{objectNames[k]}{summary[k].state === "unavailable" ? "（未取得）" : ""}</option>)}</select></label>
      <label>授权筛选<select value={filter} disabled={busy} onChange={e => { const next = e.target.value as ObjectFilter; setFilter(next); load(section,query,next); }}>{objectFilters.filter(f => section === "routines" || !["security-definer","unfixed-definer"].includes(f)).map(k => <option value={k} key={k}>{filterNames[k]}</option>)}</select></label>
      <label>搜索对象<input type="search" value={query} maxLength={128} onChange={e => setQuery(e.target.value)} placeholder="对象、所有者、模式或完整 OID" /></label><button disabled={busy || !onRead || s.state !== "available"}>查看对象列表</button>
    </form>
    {s.state === "available" ? <p>已读取 {s.total} 项 · 授予 PUBLIC {s.publicObjects} 项 · 允许非所有者转授权 {s.delegatedObjects} 项{section === "routines" ? ` · 以定义者权限运行 ${s.securityDefiners} 项，其中未固定函数搜索路径 ${s.unfixedDefiners} 项` : ""}。这些数量用于定位复核对象，不是风险定论。</p> : <p>本类目录未取得：{gaps[s.reason]}。请复核权限或重新读取数据库状态。</p>}
    {s.state === "available" && ["routines","types","columns"].includes(section) ? <p>{section === "columns" ? `只单列有明确列授权的 ${s.total} 列；另有 ${s.omittedDefaults} 列没有单独条目，其权限需结合所属表。` : `另有 ${s.omittedDefaults} 个没有特定授权或设置的内建对象未逐项列出。名称搜索仅覆盖本次已采集范围。`}</p> : null}
    <h6 ref={heading} tabIndex={-1}>{objectNames[section]}授权列表</h6>
    {current ? <><div className="database-table"><table><caption>{objectNames[section]} · 共 {current.total} 项，匹配 {current.matched} 项 · 每页 50 项</caption><thead><tr><th>对象 / 所有者</th><th>授权依据</th><th>PUBLIC / 转授权</th><th>查看</th></tr></thead><tbody>{current.rows.map(r => <tr key={`${r.oid}:${r.subId}`}>
      <td>{objectTitle(r)}<p>OID：{r.oid}{r.subId ? ` · 列号：${r.subId}` : ""}</p><p>授权所有者：{identity(r.ownerName,r.ownerOid)}</p></td><td>{aclSourceNames[r.aclSource]}<p>{r.grantCount} 组授权</p></td><td>{r.publicPrivileges.length ? `PUBLIC：${rights(r.publicPrivileges)}` : "此对象未向 PUBLIC 授予普通权限"}<p>{r.delegated ? "有非所有者可转授权，需核对用途" : "此目录未发现非所有者转授权条目"}</p></td><td><button disabled={busy || !onDetail} onClick={() => void onDetail?.(section,r.oid,r.subId,roleOid)}>查看授权</button></td>
    </tr>)}</tbody></table>{current.rows.length === 0 ? <p>本次采集范围内没有匹配对象；不表示该对象不存在或权限安全。</p> : null}</div>
      <div className="database-toolbar"><button disabled={busy || current.offset === 0} onClick={() => load(section,current.query,current.filter,Math.max(0,current.offset-50))}>对象上一页</button><button disabled={busy || current.offset+50 >= current.matched} onClick={() => load(section,current.query,current.filter,current.offset+50)}>对象下一页</button></div>
    </> : <p>{busy ? "正在读取对象授权…" : "选择类别并查看对象列表。"}</p>}
    {selected ? <section aria-label="所选对象授权"><h6 ref={detailHeading} tabIndex={-1}>对象授权详情 · {objectTitle(selected.object)}</h6><p>{aclSourceNames[selected.object.aclSource]}。</p><Properties detail={selected.object.detail} />
      {selected.object.catalogWriteRestricted ? <p>此对象受到系统目录的普通写权限限制；目录中的表授权不能直接证明非超级用户可写。单独列授权与转授权位另行计算。</p> : null}
      <Grants rows={selected.grants} caption="此对象的授权条目" />{section === "columns" ? <Grants rows={selected.tableGrants} caption="所属表的授权条目（计算列权限时仅取适用权限）" /> : null}<Analysis detail={selected} />
    </section> : null}
    <details><summary>理解权限名称与采集范围</summary><p>PUBLIC 代表所有角色。SELECT 为读取，INSERT / UPDATE / DELETE 为写入，USAGE 为使用对象，EXECUTE 为执行函数或过程，CREATE 为在相应范围创建对象。具体权限含义由对象种类决定，序列、语言和参数还有各自的前提。</p><p>目录未单独记录授权（NULL）时使用 PostgreSQL 内建默认值，不使用当前 ALTER DEFAULT PRIVILEGES 设置。对象所有者的普通权限可被撤销，所有权仍保留再次授权等能力。函数以定义者权限运行时应核对可信搜索路径与可调用范围；本页未分析函数正文、视图内部访问和行级策略。</p><p>仅读取本次连接数据库及相关共享目录的授权元数据，不读取业务行、函数正文、外部连接选项值或大对象内容。两次采集一致不能当作事务快照，页面结果也不能直接授权后续修改。</p></details>
  </section>;
}
