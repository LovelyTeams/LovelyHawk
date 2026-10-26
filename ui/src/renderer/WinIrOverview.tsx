import { WinIrIcon } from "./WinIrIcon";
import { CollectionWarnings, RiskBadge, StatStrip } from "./WinIrKit";
import { RISK_ORDER } from "./win-ir-helpers";
import { CORE_COLLECTION, WIN_IR_MODULES, collectedTime, moduleLabel, networkKey, startupKey, type CollectedAt, type CollectionTab, type FocusTarget, type WinIrSnapshots, type WindowsIncidentTab } from "./win-ir-model";
import type { WindowsRiskLevel } from "../shared/windows-incident-contract";

function Meter({ label, value, detail }: { label: string; value: number; detail: string }) {
  const bounded = Math.max(0, Math.min(100, value));
  return (
    <div className="wir-meter">
      <div><span>{label}</span><strong>{bounded.toFixed(0)}<small>%</small></strong></div>
      <div className="wir-meter-track" role="meter" aria-label={label} aria-valuenow={bounded} aria-valuemin={0} aria-valuemax={100}><i style={{ width: `${bounded}%` }} /></div>
      <small>{detail}</small>
    </div>
  );
}

interface Finding { id: string; title: string; detail: string; tab: CollectionTab; risk: WindowsRiskLevel; target?: FocusTarget }

export function WinIrOverview({ snapshots, collectedAt, busy, onNavigate, onGo, onCollectAll }: {
  snapshots: Partial<WinIrSnapshots>; collectedAt: CollectedAt; busy: boolean;
  onNavigate: (tab: WindowsIncidentTab) => void; onGo: (target: FocusTarget) => void; onCollectAll: () => void;
}) {
  const host = snapshots.overview;
  const findings: Finding[] = [
    ...(host && (host.highRiskCount > 0 || host.mediumRiskCount > 0) ? [{
      id: "overview:protection", title: "主机防护状态需要核实",
      detail: `概况报告 ${host.highRiskCount} 项高危、${host.mediumRiskCount} 项需关注；请继续核查基线配置。`,
      tab: "baseline" as const, risk: (host.highRiskCount > 0 ? "high" : "medium") as WindowsRiskLevel,
    }] : []),
    ...(snapshots.baseline?.items.filter((item) => item.status !== "pass").map((item): Finding => ({ id: `baseline:${item.id}`, title: item.title, detail: item.description, tab: "baseline", risk: item.severity, target: { tab: "baseline", id: item.id } })) ?? []),
    ...(snapshots.processes?.processes.filter((item) => item.riskLevel !== "normal").map((item): Finding => ({ id: `process:${item.pid}:${item.startTime}`, title: item.name, detail: item.riskReasons.join("；"), tab: "processes", risk: item.riskLevel, target: { tab: "processes", pid: item.pid, startTime: item.startTime } })) ?? []),
    ...(snapshots.startup?.entries.filter((item) => item.riskLevel !== "normal").map((item, index): Finding => ({ id: `startup:${index}`, title: item.name, detail: item.riskReason, tab: "startup", risk: item.riskLevel, target: { tab: "startup", key: startupKey(item) } })) ?? []),
    ...(snapshots.accounts?.accounts.filter((item) => item.riskLevel !== "normal").map((item): Finding => ({ id: `account:${item.sid || item.name}`, title: item.name, detail: item.riskReasons.join("；"), tab: "accounts", risk: item.riskLevel, target: { tab: "accounts", sid: item.sid, name: item.name } })) ?? []),
    ...(snapshots.network?.connections.filter((item) => item.riskLevel !== "normal").map((item, index): Finding => ({ id: `network:${index}`, title: `${item.processName || item.pid} → ${item.remoteAddress}`, detail: item.riskReason, tab: "network", risk: item.riskLevel, target: { tab: "network", key: networkKey(item) } })) ?? []),
    ...(snapshots.logs?.entries.filter((item) => item.riskLevel === "high").map((item, index): Finding => ({ id: `event:${index}`, title: `${item.eventId} · ${item.summary}`, detail: item.timeCreated, tab: "logs", risk: item.riskLevel, target: { tab: "logs", channel: item.channel, recordId: item.recordId } })) ?? []),
  ].sort((a, b) => RISK_ORDER[b.risk] - RISK_ORDER[a.risk]);
  const complete = CORE_COLLECTION.filter((tab) => collectedAt[tab]).length;
  const baseline = snapshots.baseline;
  return (
    <div className="wir-module">
      <section className="wir-overview-hero">
        <div className="wir-host-emblem"><WinIrIcon name="overview" /></div>
        <div className="wir-host-description">
          <span className="win-ir-eyebrow">当前被检主机</span>
          <h2>{host?.hostname || "正在识别主机"}</h2>
          <p>{host ? `${host.osCaption} · ${host.architecture} · ${host.osVersion}` : "连接成功后自动读取主机概况。"}</p>
          {host ? <div className="wir-host-tags"><span>{host.currentUser}</span><span>{host.isElevated ? "管理员权限" : "普通用户权限"}</span><span>{host.partOfDomain ? "域" : "工作组"}：{host.domainOrWorkgroup}</span></div> : null}
        </div>
        <div className="wir-hero-action">
          <button type="button" className="win-ir-btn is-primary" disabled={busy} onClick={onCollectAll}>采集核心模块 <span aria-hidden="true">→</span></button>
          <small>概况 · 基线 · 进程 · 网络 · 启动项 · 账户 · 日志</small>
        </div>
      </section>
      <StatStrip cards={[
        { label: "核心模块已采集", value: `${complete} / ${CORE_COLLECTION.length}`, hint: "各模块采集时间单独记录" },
        { label: "高危线索条目", value: complete <= 1 && findings.length === 0 ? "待排查" : findings.filter((item) => item.risk === "high").length, tone: "high", hint: "仅含已采集记录，各模块可能重叠" },
        { label: baseline ? "基线通过项" : "基线状态", value: baseline ? `${baseline.passedCount} / ${baseline.totalChecks}` : "未核查", tone: !baseline ? "info" : baseline.failedCount ? "high" : baseline.warningCount ? "medium" : "normal", onClick: () => onNavigate("baseline") },
        { label: "主机已运行", value: host ? `${Math.floor(host.uptimeHours / 24)} 天 ${host.uptimeHours % 24} 时` : "—", hint: host?.bootTime || "启动时间待采集" },
      ]} />
      <div className="wir-overview-grid">
        <section className="wir-panel wir-findings-panel">
          <header><div><h2>优先关注</h2><p>从已采集记录中提取的调查线索</p></div><span className="wir-tag">{findings.length} 项</span></header>
          {findings.length ? <div className="wir-findings">{findings.slice(0, 12).map((item) => <button key={item.id} type="button" aria-label={`在${moduleLabel(item.tab)}中定位 ${item.title}`} onClick={() => (item.target ? onGo(item.target) : onNavigate(item.tab))}>
            <RiskBadge level={item.risk} /><div><strong>{item.title}</strong><span>{item.detail}</span></div><span className="wir-finding-source">{moduleLabel(item.tab)} ↗</span>
          </button>)}</div> : <div className="wir-empty"><WinIrIcon name="baseline" /><strong>{complete > 1 ? "已取得的记录暂未产生风险线索" : "开始一次有重点的排查"}</strong><p>{complete > 1 ? "继续核对采集范围与权限，不能据此证明没有入侵。" : "点击「采集核心模块」，逐项查看进度与结果。也可以从左侧直接进入任一模块。"}</p></div>}
          {findings.length > 12 ? <p className="wir-footnote">显示优先级最高的 12 项，其余记录可在各模块中筛选。</p> : null}
        </section>
        <section className="wir-panel">
          <header><div><h2>资源与防护</h2><p>本次读取时的状态</p></div></header>
          {host ? <>
            <div className="wir-resource-grid">
              <Meter label="处理器" value={host.cpuLoadPercent} detail={`${host.cpuCores} 逻辑核心`} />
              <Meter label="内存" value={host.memoryUsagePercent} detail={`${(host.memoryUsedMb / 1024).toFixed(1)} / ${(host.memoryTotalMb / 1024).toFixed(1)} GB`} />
              <Meter label="系统盘使用率" value={host.systemDriveTotalGb > 0 ? (1 - host.systemDriveFreeGb / host.systemDriveTotalGb) * 100 : 0} detail={`可用 ${host.systemDriveFreeGb} / ${host.systemDriveTotalGb} GB`} />
            </div>
            <dl className="wir-protection">
              <div><dt>Defender 实时保护</dt><dd><RiskBadge level={host.realtimeProtection ? "normal" : "medium"} label={host.realtimeProtection === null ? "未取得" : host.realtimeProtection ? "报告为开启" : "已关闭"} /></dd></div>
              <div><dt>防火墙 · 域 / 专用 / 公用</dt><dd>{[host.firewallDomainEnabled, host.firewallPrivateEnabled, host.firewallPublicEnabled].map((enabled, index) => <span className={`wir-tag${enabled ? " is-good" : " is-caution"}`} key={index}>{enabled === null ? "未知" : enabled ? "开启" : "关闭"}</span>)}</dd></div>
              <div><dt>会话</dt><dd>{host.sessionName || "未取得"}</dd></div>
            </dl>
            {host.highlights.length ? <ul className="wir-overview-highlights">{host.highlights.map((text, index) => <li key={index}>{text}</li>)}</ul> : null}
          </> : <div className="wir-empty">主机信息尚未取得。</div>}
        </section>
      </div>
      {host ? <>
        <CollectionWarnings warnings={host.warnings} />
        <section className="wir-panel"><header><h2>主机详细信息</h2><span className="wir-tag">{host.facts.length} 项观察</span></header>
          <div className="wir-host-facts">{[...new Set(host.facts.map((fact) => fact.group))].map((group) => <details key={group} open={group !== "更新记录"}><summary>{group} · {host.facts.filter((fact) => fact.group === group).length}</summary><dl>{host.facts.filter((fact) => fact.group === group).map((fact, i) => <div key={i}><dt>{fact.label}</dt><dd>{fact.value || "未取得"}</dd></div>)}</dl></details>)}</div>
        </section>
      </> : null}
      <section className="wir-panel">
        <header><div><h2>调查入口</h2><p>按问题深入，保留每个模块的筛选与已采集结果</p></div></header>
        <div className="wir-module-cards">{WIN_IR_MODULES.filter((module) => module.key !== "overview" && module.key !== "console" && module.key !== "timeline" && module.key !== "desktop").map((module) =>
          <button key={module.key} type="button" onClick={() => onNavigate(module.key)}><span className="wir-module-card-icon"><WinIrIcon name={module.key} /></span><strong>{module.label}</strong><small>{collectedAt[module.key as CollectionTab] ? `采集于 ${collectedTime(collectedAt[module.key as CollectionTab])}` : "尚未采集"}</small><span aria-hidden="true">↗</span></button>,
        )}</div>
      </section>
    </div>
  );
}
