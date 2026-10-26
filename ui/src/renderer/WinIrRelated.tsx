import { useMemo, useState } from "react";

import { RiskBadge } from "./WinIrKit";
import { MATCH_LABEL, findRelated, isServiceAccount, type RelatedHit, type RelatedQuery } from "./win-ir-links";
import { collectedTime, moduleLabel, type CollectedAt, type CollectionTab, type FocusTarget, type WinIrSnapshots } from "./win-ir-model";

const ORDER: readonly CollectionTab[] = ["processes", "startup", "network", "accounts", "logs", "files", "registry"];
const SEARCHED: readonly CollectionTab[] = ["processes", "startup", "network", "accounts", "logs"];
const SHOWN = 8;

/** The collected snapshots and the cross-link a module needs to show related records. */
export interface RelatedContext {
  snapshots: Partial<WinIrSnapshots>;
  collectedAt: CollectedAt;
  onGo: (target: FocusTarget) => void;
}

/** Records in other modules that share a path, account, address or PID with the selected one. */
export function WinIrRelated({ query, context: { snapshots, collectedAt, onGo } }: { query: RelatedQuery; context: RelatedContext }) {
  const [expanded, setExpanded] = useState<ReadonlySet<CollectionTab>>(new Set());
  const queryKey = JSON.stringify(query);
  // The query is rebuilt on every render; its content decides when to search again.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const hits = useMemo(() => findRelated(query, snapshots), [queryKey, snapshots]);
  const groups = ORDER.map((tab) => ({ tab, hits: hits.filter((hit) => hit.tab === tab) })).filter((group) => group.hits.length > 0);
  const missing = SEARCHED.filter((tab) => !snapshots[tab]).map(moduleLabel);
  const serviceAccounts = (query.accounts ?? []).filter(isServiceAccount);
  return (
    <section className="wir-related" aria-label="关联线索">
      <h4>关联线索 · {hits.length}</h4>
      {groups.map(({ tab, hits: items }) => {
        const all = expanded.has(tab);
        const time = collectedTime(collectedAt[tab]);
        return <div className="wir-related-group" key={tab}>
          <p><strong>{moduleLabel(tab)} · {items.length}</strong>{time ? <small>采集于 {time}</small> : null}</p>
          <ul>{(all ? items : items.slice(0, SHOWN)).map((hit: RelatedHit) => <li key={hit.id}>
            <button type="button" className="wir-related-item" aria-label={`在${moduleLabel(tab)}中定位 ${hit.title}`} onClick={() => onGo(hit.target)}>
              <span className="wir-related-title">{hit.risk !== "normal" ? <RiskBadge level={hit.risk} /> : null}<strong>{hit.title}</strong><span className="wir-tag">{MATCH_LABEL[hit.match]}</span></span>
              <small className="is-mono" title={hit.detail}>{hit.detail}</small>
              <i aria-hidden="true">↗</i>
            </button>
          </li>)}</ul>
          {items.length > SHOWN ? <button type="button" className="wir-link" onClick={() => setExpanded((before) => { const after = new Set(before); if (all) after.delete(tab); else after.add(tab); return after; })}>{all ? "收起" : `显示全部 ${items.length} 条`}</button> : null}
        </div>;
      })}
      {hits.length === 0 ? <p className="wir-footnote">已采集的模块中没有相同路径、账户或地址的记录。</p> : null}
      {serviceAccounts.length ? <p className="wir-footnote">{serviceAccounts.join("、")} 是系统内置服务账户，不参与账户匹配。</p> : null}
      {missing.length ? <p className="wir-footnote">尚未采集：{missing.join("、")}，关联结果可能不完整。</p> : null}
      <p className="wir-footnote">按已采集快照匹配，各模块不是同一时刻采集；名称相同不代表同一文件或同一进程，文本提及也不代表直接关联。</p>
    </section>
  );
}
