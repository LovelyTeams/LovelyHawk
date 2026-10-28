import { PostgresqlObjectPanel } from "./PostgresqlObjectPanel";
import type { ObjectSection, ObjectFilter, PostgresqlObjectPage, PostgresqlObjectDetail } from "../shared/postgresql-object-contract";
import { PostgresqlRolePanel } from "./PostgresqlRolePanel";
import type { PostgresqlRolePage, RoleAccessMode } from "../shared/postgresql-role-contract";
import { useEffect, useRef, useState } from "react";
import { accessSections, type AccessFinding, type AccessReason, type AccessSection, type PostgresqlAccessPage, type PostgresqlAccessSummary, type PostgresqlRoleRow } from "../shared/postgresql-access-contract";

const names = { hba: "HBA 连接规则", ident: "ident 用户映射", roles: "角色直接属性", memberships: "成员授权" };
const buttons = { hba: "查看 HBA 规则", ident: "查看 ident 映射", roles: "查看角色属性", memberships: "查看成员授权" };
const reasons: Record<AccessReason, string> = {
  "permission-denied": "当前账号没有读取权限。可请管理员用已有授权账号复核。",
  "query-failed": "查询未完成。参数结果仍可查看，请检查连接或该视图的读取权限后重试。",
  "invalid-output": "返回数据无法完整核对。请核对产品版本后重新读取。",
  "limit-exceeded": "超过读取上限，本项未展示部分数据。HBA／ident 各限 512 项，角色限 1024 项，成员授权限 2048 项，每类公开结果限 384 KiB。请由管理员分范围复核。",
  changed: "读取前后内容或权限发生变化，未采用这项结果。请等待变更结束后重新读取。",
};
export const accessFindingText: Record<AccessFinding, { title: string; detail: string }> = {
  "membership-admin": { title: "成员授权允许管理成员关系", detail: "此条授权启用了 ADMIN；实际授予或撤销还受执行角色、继承、授权者、角色属性和版本规则限制，不能据此认定可任意管理账号。" },
  "server-issue": { title: "服务器报告规则问题", detail: "请复核来源文件和行号。原始报错可能带有秘密配置，因此只保留问题状态。" },
  trust: { title: "规则允许无口令认证", detail: "连接若匹配 trust 规则，无需提供口令证明。请确认适用的连接类型、账号和来源是否符合用途。" },
  "password-transport": { title: "口令传输可能未加密", detail: "这条 password 规则可匹配没有 TLS 或 GSS 加密的网络连接。请核实实际连接保护和业务需求。" },
  "md5-rule": { title: "规则使用旧版 md5 方式", detail: "请评估客户端兼容性；若角色已存储 SCRAM 校验值，md5 规则也可能协商 SCRAM，不能据此认定实际使用 MD5 口令。" },
  "broad-source": { title: "数值地址范围覆盖所有来源", detail: "地址的掩码为零；请结合规则顺序、数据库、用户和网络边界复核，不能据此认定任意账号可访问。" },
  "unknown-method": { title: "认证方式尚未适配", detail: "当前产品版本没有可用的已审阅语义，需结合对应版本说明复核。" },
  "unknown-option": { title: "认证选项尚未适配", detail: "有选项缺少当前版本的已审阅语义。页面只保留选项名称，全部选项值均未采集。" },
  "login-superuser": { title: "可登录角色具有超级用户权限", detail: "请确认是否确需直接使用此角色登录业务，并检查账号用途和访问范围。" },
  "login-bypassrls": { title: "可登录角色可绕过行级安全策略", detail: "请核对业务是否依赖行级数据限制；请结合下方角色路径与对象授权复核；行级策略仍需单独验证。" },
  "login-createrole": { title: "可登录角色能够创建角色", detail: "请核实账号管理职责及对应版本的权限范围。" },
  "login-replication": { title: "可登录角色具有复制权限", detail: "请核实复制用途、连接规则和复制槽管理范围。" },
  "md5-verifier": { title: "角色存储了 MD5 口令校验值", detail: "调整 password_encryption 不会转换已有口令。请先评估客户端兼容性，再制定逐账号更新计划。" },
  "password-expired": { title: "可登录角色的口令已过期", detail: "按数据库服务器当前时间判断；只影响口令认证，不能据此认定账号完全停用。" },
  "unrecognized-verifier": { title: "口令存储标识无法识别", detail: "请由管理员复核角色的口令状态；页面未采集校验值。" },
};
function Findings({ codes }: { codes: AccessFinding[] }): React.JSX.Element {
  return codes.length ? <ul>{codes.map(code => <li key={code}>{accessFindingText[code].title}</li>)}</ul> : <span>未触发本次提示；仍需核对用途与生效情况</span>;
}
function source(file: string | null, line: number | null): string { return `${file ?? "来源未提供"}${line === null ? "" : ` · 第 ${line} 行`}`; }
function roleAttributes(row: PostgresqlRoleRow): string {
  return [[row.superuser, "超级用户"], [row.inherit, "新成员授权默认继承"], [row.createRole, "创建角色"], [row.createDatabase, "创建数据库"], [row.replication, "复制"], [row.bypassRls, "绕过行级安全"]].filter(([enabled]) => enabled).map(([, label]) => label).join("、") || "以上直接属性均未启用";
}
export function PostgresqlAccessTable({ page, onInspectRole, busy = false }: { page: PostgresqlAccessPage; onInspectRole?: ((role: PostgresqlRoleRow) => void) | undefined; busy?: boolean }): React.JSX.Element {
  return <div className="database-table"><table><caption>{names[page.section]} · 共 {page.total} 项，匹配 {page.matched} 项{page.query ? ` · 搜索：${page.query}` : ""}</caption>
    {page.section === "hba" ? <><thead><tr><th>顺序 / 来源</th><th>连接与选择项</th><th>地址 / 掩码</th><th>认证方式 / 诊断选项名称</th><th>需要复核</th></tr></thead><tbody>{page.rows.map((row, i) => <tr key={i}>
      <td>{row.ruleNumber ?? "未编号"}<p>{source(row.fileName, row.lineNumber)}</p></td><td>{row.connectionType ?? "未取得"}<p>数据库：{row.databases?.join("、") ?? "未取得"}</p><p>用户：{row.users?.join("、") ?? "未取得"}</p></td>
      <td>{row.address ?? "不适用或未取得"}<p>{row.netmask ?? "无独立掩码"}</p></td><td>{row.method ?? "未取得"}<p>{row.optionNames.join("、") || "无选项名称"}</p></td><td><Findings codes={row.findings} /></td>
    </tr>)}</tbody></> : page.section === "ident" ? <><thead><tr><th>顺序 / 来源</th><th>映射名称</th><th>系统用户</th><th>数据库用户</th><th>需要复核</th></tr></thead><tbody>{page.rows.map((row, i) => <tr key={i}>
      <td>{row.mapNumber ?? "未编号"}<p>{source(row.fileName, row.lineNumber)}</p></td><td>{row.mapName ?? "未取得"}</td><td>{row.systemUser ?? "未取得"}</td><td>{row.databaseUser ?? "未取得"}</td><td><Findings codes={row.findings} /></td>
    </tr>)}</tbody></> : page.section === "memberships" ? <><thead><tr><th>成员</th><th>获授角色</th><th>授权者 / 记录</th><th>授权选项</th><th>需要复核</th></tr></thead><tbody>{page.rows.map(row => <tr key={row.oid}>
      <td>{row.memberName ?? "角色名称未取得"}<p>OID：{row.memberOid}</p></td><td>{row.roleName ?? "角色名称未取得"}<p>OID：{row.roleOid}</p></td><td>{row.grantorName ?? "授权者名称未取得"}<p>授权者 OID：{row.grantorOid} · 授权 OID：{row.oid}</p></td>
      <td>自动继承：{row.inheritOption ? "允许" : "不允许"}<p>切换角色：{row.setOption ? "允许" : "不允许"}</p><p>管理成员（ADMIN）：{row.adminOption ? "允许，需复核条件" : "未授予"}</p></td><td><Findings codes={row.findings} /></td>
    </tr>)}</tbody></> : <><thead><tr><th>角色 / 登录</th><th>直接属性</th><th>口令状态</th><th>需要复核 / 查看</th></tr></thead><tbody>{page.rows.map(row => <tr key={row.oid}>
      <td>{row.name}<p>OID：{row.oid} · {row.canLogin ? "允许作为登录角色" : "未设置 LOGIN"}</p><p>连接限制：{row.connectionLimit === -1 ? "未设置数量上限" : row.connectionLimit}（不等同于所有连接均受此限制）</p></td>
      <td>{roleAttributes(row)}</td><td>{{ none: "未存储口令", md5: "MD5 存储标识", "scram-sha-256": "SCRAM 存储标识", unrecognized: "无法识别", unavailable: "无权读取存储标识" }[row.passwordKind]}<p>到期时间（数据库显示格式）：{row.passwordExpiresAt ?? "未设置"}</p>{row.passwordExpired ? <p>按服务器时间已过期；仅影响口令认证</p> : null}</td><td><Findings codes={row.findings} /><button disabled={busy || !onInspectRole} onClick={() => onInspectRole?.(row)}>查看权限来源</button></td>
    </tr>)}</tbody></>}
  </table>{page.rows.length === 0 ? <p>当前搜索没有匹配记录。此状态不构成安全结论。</p> : null}</div>;
}
export function PostgresqlAccessPanel({ summary, page, busy, expert, onRead, rolePage = null, onRoleRead, objectPage = null, objectDetail = null, onObjectRead, onObjectDetail }: {
  summary: PostgresqlAccessSummary; page: PostgresqlAccessPage | null; busy: boolean; expert: boolean;
  onRead(section: AccessSection, query: string, offset: number): unknown;
  objectPage?: PostgresqlObjectPage | null; objectDetail?: PostgresqlObjectDetail | null;
  onObjectRead?(section: ObjectSection, query: string, filter: ObjectFilter, offset: number): unknown;
  onObjectDetail?(section: ObjectSection, oid: number, subId: number, roleOid: number | null): unknown;
  rolePage?: PostgresqlRolePage | null; onRoleRead?(roleOid: number, mode: RoleAccessMode, query: string, offset: number): unknown;
}): React.JSX.Element {
  const [selectedRole, setSelectedRole] = useState<PostgresqlRoleRow | null>(null);
  const [section, setSection] = useState<AccessSection>("hba");
  const [query, setQuery] = useState("");
  const [expanded, setExpanded] = useState(false);
  const current = page?.section === section ? page : null;
  const detailHeading = useRef<HTMLHeadingElement>(null);
  const focusRequested = useRef(false);
  const load = (section: AccessSection, query: string, offset: number): void => { focusRequested.current = true; void onRead(section, query, offset); };
  useEffect(() => {
    if (!focusRequested.current || busy || !current || !detailHeading.current) return;
    focusRequested.current = false;
    detailHeading.current.focus({ preventScroll: true });
    detailHeading.current.scrollIntoView({ block: "start" });
  }, [busy, current]);
  const codes = [...new Set(accessSections.flatMap(section => summary[section].findings.map(f => f.code)))];
  return <section className="database-session database-access" aria-label="访问规则与角色诊断"><h4>访问规则与角色诊断</h4>
    <p>HBA 决定连接认证方式，ident 映射系统用户与数据库用户。以下规则来自当前磁盘文件，尚未证明已加载生效；角色信息反映本次读取时的属性与成员关系。</p>
    <div className="database-observations">{accessSections.map(section => { const s = summary[section]; return <article key={section}><h4>{names[section]}</h4>
      {s.state === "available" ? <><strong>已读取 {s.total} 项 · 需复核 {s.flagged} 项</strong><p>{s.flagged ? s.findings.map(f => `${accessFindingText[f.code].title}：${f.count}`).join("；") : "本次未触发提示；尚未验证完整访问策略。"}</p></> : <><strong>本项未取得</strong><p>{reasons[s.reason]}</p></>}
      <button disabled={busy || s.state !== "available"} onClick={() => { setSection(section); setQuery(""); setExpanded(true); load(section, "", 0); }}>{buttons[section]}</button>
    </article>; })}</div>
    <p>{summary.passwordClassification ? "已在数据库端分类口令存储标识，未采集口令校验值。" : "口令存储标识未取得，不能判断现存口令使用何种算法。"}对象授权可在下方按类别查看，实际登录可达性仍需另行验证。</p>
    <PostgresqlRolePanel key={selectedRole?.oid ?? "none"} summary={summary.roleGraph} source={selectedRole} page={rolePage} busy={busy} onRead={onRoleRead} />
    <PostgresqlObjectPanel summary={summary.objects} source={selectedRole} page={objectPage} detail={objectDetail} busy={busy} onRead={onObjectRead} onDetail={onObjectDetail} />
    {codes.length ? <details><summary>理解提示与下一步</summary><dl>{codes.map(code => <div key={code}><dt>{accessFindingText[code].title}</dt><dd>{accessFindingText[code].detail}</dd></div>)}</dl></details> : null}
    {expert || expanded ? <div aria-label="访问诊断详情"><p>诊断视图会丢失部分原始引号信息；all、正则和角色选择项仅展示其文本，不能用于重建配置。未解析规则优先级遮蔽、名称与成员关系，也未验证服务器是否具备所需认证支持。诊断选项仅展示名称，可能含服务端派生字段（例如 LDAP 的 ldapscope），不能当作可写入配置的选项清单；原始错误和全部选项值均未采集。</p>
      <p>未存储口令仍可能通过其他认证方式登录；SCRAM 存储标识不代表已验证校验值或登录成功。口令到期不等于账号停用。</p>
      <h5 ref={detailHeading} tabIndex={-1}>{names[section]}详情</h5>
      <form className="database-toolbar" onSubmit={event => { event.preventDefault(); load(section, query, 0); }}><label>搜索{names[section]}<input type="search" maxLength={128} value={query} onChange={event => setQuery(event.target.value)} placeholder={section === "memberships" ? "角色、授权者名称或 OID" : section === "roles" ? "角色名称" : "来源文件、用户或规则名称"} /></label><button disabled={busy || summary[section].state !== "available"}>搜索访问诊断</button></form>
      {current ? <><PostgresqlAccessTable page={current} busy={busy} onInspectRole={summary.roleGraph.state === "available" && onRoleRead ? role => { setSelectedRole(role); void onRoleRead(role.oid, "inherit", "", 0); } : undefined} /><div className="database-toolbar"><button disabled={busy || current.offset === 0} onClick={() => load(section, current.query, Math.max(0, current.offset - 50))}>访问诊断上一页</button><button disabled={busy || current.offset + 50 >= current.matched} onClick={() => load(section, current.query, current.offset + 50)}>访问诊断下一页</button></div></> : <p>{busy ? "正在读取所选详情…" : "选择上方查看按钮，展开对应的规则或角色。"}</p>}
    </div> : null}
  </section>;
}
