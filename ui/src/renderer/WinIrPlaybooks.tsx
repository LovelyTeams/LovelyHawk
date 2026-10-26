import { useEffect, useRef, useState } from "react";
import { SearchBox } from "./WinIrKit";
import { findPlaybooks, playbookActionLabel, playbookText, PLAYBOOK_PHASES, PLAYBOOK_REVIEW_DATE, PLAYBOOK_SOURCES, WINDOWS_PLAYBOOKS, type PlaybookAction } from "./win-ir-playbooks";
import "./win-ir-playbooks.css";

export function WinIrPlaybooks({ connected, busy, onAction, onCopy }: {
  connected: boolean; busy: boolean;
  onAction: (action: PlaybookAction) => void; onCopy: (text: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [selectedId, setSelectedId] = useState("triage");
  const root = useRef<HTMLElement>(null);
  const lastSelection = useRef(selectedId);
  useEffect(() => { root.current?.querySelector<HTMLButtonElement>('nav button[aria-current="true"]')?.focus({ preventScroll: true }); }, []);
  useEffect(() => {
    if (lastSelection.current !== selectedId) root.current?.querySelector(".wir-playbook-detail")?.scrollTo({ top: 0 });
    lastSelection.current = selectedId;
  }, [selectedId]);
  const plans = findPlaybooks(query);
  const selected = WINDOWS_PLAYBOOKS.find((plan) => plan.id === selectedId)!;
  const groups = [...new Set(plans.map((plan) => plan.group))];
  return <section ref={root} className="wir-playbooks" aria-label="Windows 响应方案">
    <header className="wir-playbooks-heading">
      <div><span className="wir-eyebrow">WINDOWS · 响应方案</span><h1>从事件出发，沿证据推进</h1><p>{WINDOWS_PLAYBOOKS.length} 类常见场景 · 发现与留证 → 关联定界 → 遏制修复 → 独立复核</p></div>
      <span className="wir-tag">可离线查阅</span>
    </header>
    <div className="wir-playbooks-body">
      <aside className="wir-playbooks-rail" aria-label="选择响应场景">
        <SearchBox value={query} onChange={setQuery} placeholder="搜索响应方案，如 WMI、勒索、IIS" />
        <span className="wir-footnote" role="status">{plans.length} / {WINDOWS_PLAYBOOKS.length} 个场景</span>
        <nav aria-label="响应场景">
          {groups.map((group) => <section key={group}><h2>{group}</h2>{plans.filter((plan) => plan.group === group).map((plan) => <button type="button" key={plan.id} aria-current={selectedId === plan.id ? "true" : undefined} onClick={() => setSelectedId(plan.id)}>
            <strong>{plan.title}</strong><span>{plan.summary}</span>
          </button>)}</section>)}
        </nav>
        {plans.length === 0 ? <div className="wir-playbooks-empty"><p>没有匹配场景。可试试症状、工具名或攻击类型。</p><button type="button" className="win-ir-btn" onClick={() => setQuery("")}>清空搜索</button></div> : null}
      </aside>
      <article className="wir-playbook-detail" aria-label={selected.title}>
        <header><div><span className="wir-eyebrow">{selected.group}</span><h2>{selected.title}</h2><p>{selected.scope}</p></div><button type="button" className="win-ir-btn" onClick={() => onCopy(playbookText(selected))}>复制当前方案</button></header>
        {!plans.some((plan) => plan.id === selectedId) ? <p className="wir-playbook-filter-note">当前方案不在搜索结果中；选择左侧场景切换，或清空搜索。</p> : null}
        <div className="wir-playbook-first"><strong>优先行动</strong><p>{selected.first}</p></div>
        <div className="wir-playbook-evidence"><h3>需要保留的证据</h3><ul>{selected.evidence.map((item) => <li key={item}>{item}</li>)}</ul></div>
        <p className="wir-playbook-availability" role="status">{!connected ? "当前未连接：可浏览、复制方案和准备查询；连接后可读取目标。" : busy ? "当前任务进行中：结束后可打开其他排查入口。" : "打开排查页可查看已有结果；未采集时按页面规则读取。目录、注册表和日志按钮会发起只读查询。"} 查询预设先保留现有草稿，核对后填入，再确认执行。</p>
        <ol className="wir-playbook-steps">
          {selected.steps.map((step, index) => <li key={`${selected.id}:${index}`}>
            <div className="wir-playbook-phase"><span aria-hidden="true">{index + 1}</span><strong>{PLAYBOOK_PHASES[index]}</strong>{index === 2 ? <small>处置前逐项确认</small> : null}</div>
            <h3>{step.title}</h3><p>{step.text}</p>
            {step.actions.length ? <div className="wir-playbook-actions">{step.actions.map((action, actionIndex) => <button type="button" className="win-ir-btn" key={actionIndex} disabled={action.kind !== "command" && (!connected || busy)} onClick={() => onAction(action)}>{playbookActionLabel(action)}</button>)}</div> : <p className="wir-footnote">此步骤需由相应系统负责人执行专项流程。</p>}
          </li>)}
        </ol>
        <section className="wir-playbook-gaps" aria-label="能力与证据边界"><h3>还需要补齐</h3><ul>{selected.gaps.map((gap) => <li key={gap}>{gap}</li>)}</ul><p>日志页默认最近 7 天、每通道最多 200 条；用户目录变量指当前采集账户。缺少权限、工具或记录均须保留为缺口。打开页面、命令返回或基线通过都不会把本方案标为已完成。</p></section>
        <details className="wir-playbook-sources"><summary>依据与参考资料 · {selected.sources.length} 项 · 整理于 {PLAYBOOK_REVIEW_DATE}</summary><p>以下是产品调查流程的参考依据，步骤经过综合整理。ATT&CK 用于线索分类，不能单独作为恶意判定。</p><ul>{selected.sources.map((key) => <li key={key}><strong>{PLAYBOOK_SOURCES[key].title}</strong><span>{PLAYBOOK_SOURCES[key].url}</span><button type="button" className="wir-link" aria-label={`复制资料链接：${PLAYBOOK_SOURCES[key].title}`} onClick={() => onCopy(PLAYBOOK_SOURCES[key].url)}>复制资料链接</button></li>)}</ul></details>
      </article>
    </div>
  </section>;
}
