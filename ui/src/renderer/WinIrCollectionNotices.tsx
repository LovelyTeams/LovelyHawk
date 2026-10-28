import { NoticeSummary } from "./NoticeSummary";
import { STARTUP_CATEGORY_LABELS, WIN_IR_MODULES, type CollectedAt, type CollectionTab, type WinIrSnapshots } from "./win-ir-model";

/** Report the whole batch, including modules that are not currently visible. */
export function WinIrCollectionNotices({ snapshots, collectedAt, errors }: { snapshots: Partial<WinIrSnapshots>; collectedAt: CollectedAt; errors: Partial<Record<CollectionTab,string>> }) {
  return <>{(Object.keys(snapshots) as CollectionTab[]).map(tab => {
    const snapshot = snapshots[tab];
    if (!snapshot) return null;
    const messages = "warnings" in snapshot ? [...snapshot.warnings] : [];
    if ("categories" in snapshot) messages.push(...snapshot.categories.filter(c => c.status !== "complete").map(c => `${STARTUP_CATEGORY_LABELS[c.category]} · ${c.status === "partial" ? "部分读取" : "未能读取"}：${c.message}`));
    if ("truncated" in snapshot && snapshot.truncated) messages.push("清单或字段已截断，不能视为完整清单；具体范围见本次查询说明。");
    const partial = ("truncated" in snapshot && snapshot.truncated) || ("categories" in snapshot && snapshot.categories.some(c => c.status !== "complete"));
    return <NoticeSummary key={tab} reportOnly source={`${WIN_IR_MODULES.find(m => m.key === tab)?.label ?? tab}采集`} summary="" stamp={"observedAt" in snapshot ? snapshot.observedAt : collectedAt[tab] ?? ""} severity={partial || tab !== "startup" ? "warning" : "info"} messages={messages} />;
  })}{(Object.keys(errors) as CollectionTab[]).map(tab => <NoticeSummary key={`error:${tab}`} reportOnly source={`${WIN_IR_MODULES.find(m => m.key === tab)?.label ?? tab}采集`} summary="" severity="error" messages={[`上次采集未完成：${errors[tab]}${snapshots[tab] ? " 当前保留上一次成功采集的结果。" : ""}`]} />)}</>;
}
