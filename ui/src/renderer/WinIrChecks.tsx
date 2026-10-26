import { useMemo, useState } from "react";

import type {
  WindowsAccountEntry, WindowsAccountsSnapshot, WindowsBaselineItem, WindowsBaselineSnapshot,
  WindowsStartupEntry, WindowsStartupSnapshot,
} from "../shared/windows-incident-contract";
import { DataTable, DetailPane, FilterChips, RiskBadge, RiskCell, SearchBox, StatStrip, riskChipOptions, riskSort, useFocusRequest, type Column } from "./WinIrKit";
import { WinIrRelated, type RelatedContext } from "./WinIrRelated";
import { commandExecutable, matchesQuery, riskCounts, toCsv, type RiskFilter } from "./win-ir-helpers";
import { RELATED_ID, commandPath } from "./win-ir-links";
import { startupKey, startupSourceLabel, type FocusTarget, type InvestigationFocus } from "./win-ir-model";

const BASELINE_STATUS = { pass: "通过", fail: "不通过", warn: "需复核", unknown: "无法判断", "not-applicable": "不适用" } as const;

type Target<K extends FocusTarget["tab"]> = InvestigationFocus<Extract<FocusTarget, { tab: K }>> | null;

function MissingFocus({ show, what }: { show: boolean; what: string }) {
  return show ? <p className="wir-footnote" role="status">当前快照中没有要定位的{what}，记录可能已变化或快照较旧，请刷新后再查找。</p> : null;
}

export function WinIrBaseline({ snapshot, focus, busy = false, connected = false, onCopy, onRemediate, onConfigure }:  {
  snapshot: WindowsBaselineSnapshot | null; focus?: Target<"baseline">; busy?: boolean; connected?: boolean;
  onCopy: (text: string) => void; onRemediate?: (item: WindowsBaselineItem) => void; onConfigure?: () => void;
}) {
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState("all");
  const [status, setStatus] = useState("all");
  const [selected, setSelected] = useState<string | null>(null);
  const [missing, setMissing] = useState(false);
  const items = snapshot?.items ?? [];
  useFocusRequest(focus, snapshot !== null, (target) => {
    const found = items.some((item) => item.id === target.id);
    setQuery(""); setCategory("all"); setStatus("all");
    setSelected(found ? target.id : null); setMissing(!found);
  });
  const categories = [...new Set(items.map((item) => item.category))];
  const visible = items.filter((item) =>
    (status === "all" || item.status === status) && (category === "all" || item.category === category) &&
    matchesQuery(query, item.id, item.category, item.title, item.currentValue, item.expectedValue, item.description, item.recommendation));
  const current = items.find((item) => item.id === selected);
  const columns: Column<WindowsBaselineItem>[] = [
    { key: "title", label: "检查项", width: "32%", sort: (item) => item.title, render: (item) => <div className="wir-cell-stack"><strong>{item.title}</strong><small>{item.category}</small></div> },
    { key: "current", label: "当前值", width: "26%", mono: true, render: (item) => <span className="wir-clip" title={item.currentValue}>{item.currentValue || "未取得"}</span> },
    { key: "expected", label: "建议值", mono: true, render: (item) => <span className="wir-clip" title={item.expectedValue}>{item.expectedValue}</span> },
    { key: "risk", label: "结果", width: "110px", sort: riskSort((item) => item.severity), render: (item) => item.status === "not-applicable" ? <span className="wir-tag">不适用</span> : <RiskBadge level={item.status === "pass" ? "normal" : item.severity} label={BASELINE_STATUS[item.status]} /> },
  ];
  return (
    <div className="wir-module">
      <StatStrip cards={[
        { label: "检查目录", value: snapshot?.totalChecks ?? "—", hint: "含无法判断和不适用项" },
        { label: "通过", value: snapshot?.passedCount ?? "—", tone: "normal", onClick: () => setStatus("pass") },
        { label: "不通过", value: snapshot?.failedCount ?? "—", tone: "high", onClick: () => setStatus("fail") },
        { label: "无法判断", value: snapshot?.unknownCount ?? "—", tone: "low", onClick: () => setStatus("unknown") },
        { label: "需要复核", value: snapshot?.warningCount ?? "—", tone: "medium", onClick: () => setStatus("warn") },
        { label: "不适用", value: snapshot?.notApplicableCount ?? "—", onClick: () => setStatus("not-applicable") },
      ]} />
      <p className="wir-query-scope">{snapshot ? `当前返回 ${categories.length} 类检查。` : "核查后可按类别与结果筛选。"}口令策略限定本地账户，审计与防护按本次采集权限读取；“无法判断”和“不适用”均不计入通过。</p>
      <details className="wir-collection-warnings"><summary>检查范围与采集影响</summary><p>检查读取系统策略、日志通道和防护状态，不修改这些配置，也不自动提权。查询可能产生 PowerShell/.NET 临时编译文件及系统审计记录。口令策略不读取口令，日志检查只读取通道配置；容量建议不等于实际留存天数。缺少组件、权限或适用条件时保留缺口。</p></details>
      <div className="wir-toolbar">
        {onConfigure ? <button type="button" className="win-ir-btn is-primary" disabled={busy || !connected || !snapshot} onClick={onConfigure}>一键配置…</button> : null}
        <SearchBox value={query} onChange={setQuery} placeholder="搜索检查项、配置值或加固建议" />
        <select className="win-ir-input wir-select" aria-label="基线类别" value={category} onChange={(event) => setCategory(event.target.value)}>
          <option value="all">全部类别</option>{categories.map((value) => <option key={value}>{value}</option>)}
        </select>
        <button type="button" className="win-ir-btn" disabled={!visible.length} onClick={() => onCopy(toCsv(
          ["检查项", "类别", "结果", "当前值", "建议值", "说明", "建议"],
          visible.map((item) => [item.title, item.category, BASELINE_STATUS[item.status], item.currentValue, item.expectedValue, item.description, item.recommendation]),
        ))}>复制筛选结果 CSV</button>
      </div>
      <FilterChips label="基线检查结果" value={status} onChange={setStatus} options={[
        { value: "all", label: "全部", count: items.length },
        { value: "fail", label: "不通过", tone: "high", count: snapshot?.failedCount },
        { value: "warn", label: "需复核", tone: "medium", count: snapshot?.warningCount },
        { value: "pass", label: "通过", tone: "normal", count: snapshot?.passedCount },
        { value: "unknown", label: "无法判断", count: snapshot?.unknownCount },
        { value: "not-applicable", label: "不适用", count: snapshot?.notApplicableCount },
      ]} />
      <MissingFocus show={missing} what="检查项" />
      <div className={`wir-master${current ? " is-split" : ""}`}>
        <DataTable label="基线检查" columns={columns} rows={visible} rowKey={(item) => item.id} selectedKey={selected} onSelect={(item) => setSelected(item?.id ?? null)} rowRisk={(item) => item.severity} defaultSort={{ key: "risk", descending: true }} empty={snapshot ? "没有符合当前筛选的检查项。" : "点击「核查安全基线」，读取当前配置与防护状态。"} />
        {current ? <DetailPane title={current.title} subtitle={current.category} {...(current.status === "not-applicable" ? {} : { risk: current.severity })} onClose={() => setSelected(null)} onCopy={onCopy} fields={[
          { label: "检查结果", value: BASELINE_STATUS[current.status] },
          { label: "采集到的配置 / 运行值", value: current.currentValue, mono: true },
          { label: "建议值", value: current.expectedValue, mono: true },
          { label: "说明与依据", value: current.description },
          { label: "加固建议", value: current.recommendation },
        ]} actions={onRemediate && current.remediationAvailable && (current.status === "fail" || current.status === "warn") ? (
          <button
            type="button"
            className="win-ir-btn is-primary"
            disabled={busy || !connected}
            onClick={() => onRemediate(current)}
          >
            预览配置差异
          </button>
        ) : undefined}>
          {!current.remediationAvailable && current.status !== "pass" ? <p className="wir-footnote">{current.status === "unknown" ? "先补齐采集与适用条件，再制定变更计划。" : current.status === "not-applicable" ? "当前条件下不执行此项修复。" : "此项提供检查与建议，尚未提供自动修复；请按适用范围人工复核。"}</p> : null}
        </DetailPane> : null}
      </div>
      <p className="wir-footnote">结果仅对应已列出的检查项；“通过”不代表主机无入侵，也不代表完整符合某项合规标准。配置变更应另行确认影响并复核。</p>
    </div>
  );
}

export function WinIrStartup({ snapshot, focus, related, busy = false, connected = false, onCopy, onFile, onRegistry, onRemove }: {
  snapshot: WindowsStartupSnapshot | null; focus?: Target<"startup">; related?: RelatedContext; busy?: boolean; connected?: boolean;
  onCopy: (text: string) => void; onFile: (path: string) => void; onRegistry: (path: string, valueName?: string) => void;
  onRemove?: (entry: WindowsStartupEntry) => void;
}) {
  const [query, setQuery] = useState("");
  const [source, setSource] = useState("all");
  const [risk, setRisk] = useState<RiskFilter>("all");
  const [selected, setSelected] = useState<string | null>(null);
  const [missing, setMissing] = useState(false);
  const entries = useMemo(() => (snapshot?.entries ?? []).map((entry, index) => ({ ...entry, rowId: `${startupKey(entry)}#${index}` })), [snapshot]);
  useFocusRequest(focus, snapshot !== null, (target) => {
    const found = entries.find((entry) => startupKey(entry) === target.key);
    setQuery(""); setSource("all"); setRisk("all");
    setSelected(found?.rowId ?? null); setMissing(found === undefined);
  });
  const visible = entries.filter((entry) => (source === "all" || source === entry.sourceType) && (risk === "all" || risk === entry.riskLevel) &&
    matchesQuery(query, entry.name, entry.location, entry.command, entry.runAs, entry.riskReason));
  const current = entries.find((entry) => entry.rowId === selected);
  const sources = [...new Set(entries.map((entry) => entry.sourceType))];
  const executable = current ? commandExecutable(current.command) : null;
  const registryPath = current?.sourceType === "registry" ? current.location.replace(/^HKEY_LOCAL_MACHINE\\|^HKLM\\|^HKLM:\\/iu, "HKLM:\\").replace(/^HKEY_CURRENT_USER\\|^HKCU\\|^HKCU:\\/iu, "HKCU:\\") : null;
  const columns: Column<WindowsStartupEntry & { rowId: string }>[] = [
    { key: "name", label: "名称 / 来源", width: "26%", sort: (entry) => entry.name, render: (entry) => <div className="wir-cell-stack"><strong>{entry.name}</strong><small>{startupSourceLabel(entry.sourceType)}</small></div> },
    { key: "command", label: "执行命令", mono: true, render: (entry) => <span className="wir-clip" title={entry.command}>{entry.command || "未取得"}</span> },
    { key: "account", label: "运行账户", width: "16%", sort: (entry) => entry.runAs, render: (entry) => entry.runAs || "未取得" },
    { key: "risk", label: "风险", width: "95px", sort: riskSort((entry) => entry.riskLevel), render: (entry) => <RiskCell level={entry.riskLevel} /> },
  ];
  return (
    <div className="wir-module">
      <StatStrip cards={[
        { label: "已取得启动项", value: snapshot?.totalCount ?? "—" },
        { label: "风险线索", value: snapshot?.suspiciousCount ?? "—", tone: "high" },
        { label: "来源类型", value: snapshot ? sources.length : "—", hint: "以实际返回的来源为准" },
      ]} />
      <div className="wir-toolbar">
        <SearchBox value={query} onChange={setQuery} placeholder="搜索名称、路径、运行账户或命令" />
        <select aria-label="持久化来源" className="win-ir-input wir-select" value={source} onChange={(event) => setSource(event.target.value)}>
          <option value="all">全部来源</option>{sources.map((value) => <option value={value} key={value}>{startupSourceLabel(value)}</option>)}
        </select>
      </div>
      <FilterChips label="启动项风险" value={risk} onChange={setRisk} options={riskChipOptions(riskCounts(entries, (entry) => entry.riskLevel))} />
      <MissingFocus show={missing} what="启动项" />
      <div className={`wir-master${current ? " is-split" : ""}`}>
        <DataTable label="启动项与持久化" rows={visible} columns={columns} selectedKey={selected} rowKey={(entry) => entry.rowId} onSelect={(entry) => setSelected(entry?.rowId ?? null)} rowRisk={(entry) => entry.riskLevel} defaultSort={{ key: "risk", descending: true }} empty={snapshot ? "没有符合筛选条件的启动项。" : "采集注册表自启动、启动文件夹和计划任务记录。"} />
        {current ? <DetailPane title={current.name} subtitle={startupSourceLabel(current.sourceType)} risk={current.riskLevel} reasons={current.riskReason ? [current.riskReason] : []} onClose={() => setSelected(null)} onCopy={onCopy} fields={[
          { label: "位置", value: current.location, mono: true },
          { label: "完整命令", value: current.command, mono: true },
          { label: "运行账户", value: current.runAs },
          { label: "状态", value: current.state },
        ]} actions={<>
          <button type="button" className="win-ir-btn" onClick={() => onCopy(current.command)}>复制命令</button>
          {executable ? <button type="button" className="win-ir-btn" onClick={() => onFile(executable)}>在文件排查中打开 ↗</button> : null}
          {registryPath && /^HK(LM|CU):\\/iu.test(registryPath) ? <button type="button" className="win-ir-btn" onClick={() => onRegistry(registryPath, current.name)}>在注册表中打开 ↗</button> : null}
          {onRemove ? (
            <button
              type="button"
              className="win-ir-btn is-danger"
              disabled={busy || !connected || (/\\winlogon$/iu.test(current.location) && /^(winlogon\\)?(shell|userinit)$/iu.test(current.name))}
              title={/\\winlogon$/iu.test(current.location) ? "Winlogon 核心登录键不支持直接删除，请在注册表模块核实后恢复默认值" : undefined}
              onClick={() => onRemove(current)}
            >
              {current.sourceType.toLowerCase() === "service" ? "停止并禁用服务" : "清理启动项"}
            </button>
          ) : null}
        </>}>
          {related ? <WinIrRelated key={current.rowId} context={related} query={{ paths: [commandPath(current.command) ?? ""], exclude: RELATED_ID.startup(current) }} /> : null}
        </DetailPane> : null}
      </div>
      <p className="wir-footnote">列表是本次采集到的启动记录，权限和采集端支持的来源会影响覆盖范围。正常名称与签名也不能单独证明可信。</p>
    </div>
  );
}

export function WinIrAccounts({ snapshot, focus, related, busy = false, connected = false, onCopy, onLogs, onDisable }: {
  snapshot: WindowsAccountsSnapshot | null; focus?: Target<"accounts">; related?: RelatedContext; busy?: boolean; connected?: boolean;
  onCopy: (text: string) => void; onLogs: (account: string) => void; onDisable?: (entry: WindowsAccountEntry) => void;
}) {
  const [query, setQuery] = useState("");
  const [scope, setScope] = useState("all");
  const [risk, setRisk] = useState<RiskFilter>("all");
  const [selected, setSelected] = useState<string | null>(null);
  const [missing, setMissing] = useState(false);
  const entries = snapshot?.accounts ?? [];
  const key = (entry: WindowsAccountEntry) => entry.sid || entry.name;
  useFocusRequest(focus, snapshot !== null, (target) => {
    const found = entries.find((entry) => (target.sid !== "" && entry.sid === target.sid) || (target.sid === "" && entry.name === target.name));
    setQuery(""); setScope("all"); setRisk("all");
    setSelected(found ? key(found) : null); setMissing(found === undefined);
  });
  const visible = entries.filter((entry) =>
    (scope === "all" || (scope === "admins" && entry.isAdmin) || (scope === "enabled" && entry.enabled) || (scope === "disabled" && !entry.enabled)) &&
    (risk === "all" || risk === entry.riskLevel) && matchesQuery(query, entry.name, entry.fullName, entry.sid, entry.rid));
  const current = entries.find((entry) => key(entry) === selected);
  const columns: Column<WindowsAccountEntry>[] = [
    { key: "name", label: "账户", width: "28%", sort: (entry) => entry.name, render: (entry) => <div className="wir-cell-stack"><strong>{entry.name}</strong><small>{entry.fullName || `RID ${entry.rid}`}</small></div> },
    { key: "privilege", label: "权限", width: "16%", sort: (entry) => Number(entry.isAdmin), render: (entry) => <span className={`wir-tag${entry.isAdmin ? " is-accent" : ""}`}>{entry.isAdmin ? "管理员组" : "普通账户"}</span> },
    { key: "state", label: "状态", width: "12%", sort: (entry) => Number(entry.enabled), render: (entry) => entry.enabled ? "启用" : "禁用" },
    { key: "logon", label: "最后登录", mono: true, sort: (entry) => entry.lastLogon, render: (entry) => entry.lastLogon || "未取得" },
    { key: "risk", label: "风险", width: "95px", sort: riskSort((entry) => entry.riskLevel), render: (entry) => <RiskCell level={entry.riskLevel} /> },
  ];
  return (
    <div className="wir-module">
      <StatStrip cards={[
        { label: "本地账户", value: snapshot?.totalCount ?? "—" },
        { label: "管理员", value: snapshot?.adminCount ?? "—", onClick: () => setScope("admins") },
        { label: "启用中", value: snapshot ? entries.filter((entry) => entry.enabled).length : "—", onClick: () => setScope("enabled") },
        { label: "风险线索", value: snapshot?.suspiciousCount ?? "—", tone: "high" },
      ]} />
      <div className="wir-toolbar">
        <SearchBox value={query} onChange={setQuery} placeholder="搜索账户名称、SID 或 RID" />
        <select className="win-ir-input wir-select" aria-label="账户范围" value={scope} onChange={(event) => setScope(event.target.value)}>
          <option value="all">全部账户</option><option value="admins">管理员</option><option value="enabled">已启用</option><option value="disabled">已禁用</option>
        </select>
      </div>
      <FilterChips label="账户风险" value={risk} onChange={setRisk} options={riskChipOptions(riskCounts(entries, (entry) => entry.riskLevel))} />
      <MissingFocus show={missing} what="账户" />
      <div className={`wir-master${current ? " is-split" : ""}`}>
        <DataTable label="本地账户" columns={columns} rows={visible} rowKey={key} selectedKey={selected} onSelect={(entry) => setSelected(entry ? key(entry) : null)} rowRisk={(entry) => entry.riskLevel} defaultSort={{ key: "risk", descending: true }} empty={snapshot ? "没有符合筛选条件的账户。" : "点击「采集账户」，核对本地账户和管理员组。"} />
        {current ? <DetailPane title={current.name} subtitle={current.fullName} risk={current.riskLevel} reasons={current.riskReasons} onClose={() => setSelected(null)} onCopy={onCopy} fields={[
          { label: "安全标识符 SID", value: current.sid, mono: true },
          { label: "RID", value: String(current.rid), mono: true },
          { label: "状态", value: current.enabled ? "启用" : "禁用" },
          { label: "管理员组", value: current.isAdmin ? "是" : "否" },
          { label: "要求口令", value: current.passwordRequired ? "是" : "否" },
          { label: "口令过期", value: current.passwordExpires ? "受过期策略约束" : "不要求过期" },
          { label: "最后登录", value: current.lastLogon || "未取得" },
        ]} actions={<>
          <button type="button" className="win-ir-btn" onClick={() => onLogs(current.name)}>在事件日志中查找 ↗</button>
          {onDisable && current.enabled ? (
            <button
              type="button"
              className="win-ir-btn is-danger"
              disabled={busy || !connected || !current.sid.startsWith("S-1-")}
              onClick={() => onDisable(current)}
            >
              禁用账户
            </button>
          ) : null}
        </>}>
          {related ? <WinIrRelated key={key(current)} context={related} query={{ accounts: [current.name], exclude: RELATED_ID.account(current) }} /> : null}
        </DetailPane> : null}
      </div>
      <p className="wir-footnote">账户属性不是完整登录历史；相关事件只在已采集日志中检索，需结合审计开启情况与日志保留范围判断。</p>
    </div>
  );
}
