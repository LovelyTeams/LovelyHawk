import { useEffect, useReducer, useRef, useState } from "react";

import {
  isFirewallHistory,
  isFirewallInspection,
  type FirewallReadApi,
} from "../shared/firewall-read-contract";
import {
  firewallBackendLabel,
  firewallChangeKindLabel,
  firewallChangeStateLabel,
  firewallCopyText,
  firewallEngineLabel,
  firewallReadScope,
  firewallRuleView,
} from "./firewall-read-helpers";
import {
  createFirewallReadState,
  firewallReadReducer,
  type FirewallReadState,
} from "./firewall-read-state";
import "./firewall-page.css";

interface FirewallPageProps {
  bindingHandle: string | null;
  api: FirewallReadApi;
  active?: boolean;
  writeClipboard?: (text: string) => Promise<void>;
  /** Deterministic standalone/SSR fixture; production leaves this unset. */
  initialState?: FirewallReadState;
}

export function FirewallPage({
  bindingHandle,
  api,
  active = true,
  writeClipboard,
  initialState,
}: FirewallPageProps) {
  const [state, dispatch] = useReducer(
    firewallReadReducer,
    initialState ?? createFirewallReadState(),
  );
  const [refreshVersion, setRefreshVersion] = useState(0);
  const requestRef = useRef(0);
  const scope = bindingHandle === null ? null : firewallReadScope(bindingHandle);
  const enabled = active && bindingHandle !== null;
  const visibleState = state.scope === scope ? state : createFirewallReadState(scope);

  useEffect(() => {
    dispatch({ type: "scope-changed", scope });
  }, [scope]);

  useEffect(() => {
    if (enabled) return;
    dispatch({ type: "deactivated", scope });
  }, [enabled, scope]);

  useEffect(() => {
    if (!enabled || scope === null || bindingHandle === null) return;
    const inspectionRequest = ++requestRef.current;
    dispatch({ type: "inspection-started", scope, request: inspectionRequest });
    void api.inspectFirewall(bindingHandle).then((result) => {
      if (!isFirewallInspection(result)) throw new Error();
      dispatch({
        type: "inspection-loaded",
        scope,
        request: inspectionRequest,
        inspection: result,
      });
    }).catch(() => {
      dispatch({
        type: "inspection-failed",
        scope,
        request: inspectionRequest,
        error: "防火墙快照不可用，或目标已发生变化。",
      });
    });

    const historyRequest = ++requestRef.current;
    dispatch({ type: "history-started", scope, request: historyRequest });
    void api.listFirewallChangeHistory(bindingHandle).then((result) => {
      if (!isFirewallHistory(result)) throw new Error();
      dispatch({ type: "history-loaded", scope, request: historyRequest, history: result });
    }).catch(() => {
      dispatch({
        type: "history-failed",
        scope,
        request: historyRequest,
        error: "当前目标的防火墙变更历史不可用。",
      });
    });
  }, [api, bindingHandle, enabled, refreshVersion, scope]);

  if (bindingHandle === null) {
    return (
      <section className="page firewall-page">
        <div className="firewall-connect-state">
          <span aria-hidden="true">⌁</span>
          <h1>连接目标后调查防火墙</h1>
          <p>只读取规则快照与本地变更历史，不会修改防火墙。</p>
        </div>
      </section>
    );
  }

  if (!active) {
    return (
      <section className="page firewall-page">
        <div className="firewall-connect-state">
          <span aria-hidden="true">Ⅱ</span>
          <h1>防火墙调查页面已停用</h1>
          <p>页面失活会清空目标快照，并拒绝仍在途的旧目标结果。</p>
        </div>
      </section>
    );
  }

  const connectedScope = scope ?? "";
  const loading = visibleState.inspectionStatus === "loading" ||
    visibleState.historyStatus === "loading";
  const rules = visibleState.inspection === null
    ? null
    : firewallRuleView(visibleState.inspection.rules, visibleState.ruleQuery);
  const selectedChange = visibleState.history?.entries.find(
    (entry) => entry.changeHandle === visibleState.selectedChangeHandle,
  ) ?? null;

  async function copyRules() {
    const inspection = visibleState.inspection;
    if (inspection === null || writeClipboard === undefined) return;
    const request = ++requestRef.current;
    dispatch({
      type: "copy-started",
      scope: connectedScope,
      request,
      snapshotHandle: inspection.snapshotHandle,
    });
    try {
      const copy = firewallCopyText(inspection);
      await writeClipboard(copy.text);
      dispatch({
        type: "copy-finished",
        scope: connectedScope,
        request,
        snapshotHandle: inspection.snapshotHandle,
        truncated: copy.truncated,
      });
    } catch {
      dispatch({
        type: "copy-failed",
        scope: connectedScope,
        request,
        snapshotHandle: inspection.snapshotHandle,
        error: "系统剪贴板拒绝了这次纯文本复制。",
      });
    }
  }

  return (
    <section className="page firewall-page">
      <header className="page-heading firewall-heading">
        <div>
          <p className="eyebrow">只读</p>
          <h1>Firewall 调查</h1>
          <p>
            当前目标 · 规则与历史均按纯文本展示。
          </p>
        </div>
        <span className="firewall-read-badge">只读</span>
      </header>

      <div className="firewall-toolbar">
        <div className="firewall-tabs" role="tablist" aria-label="Firewall 只读视图">
          <button
            type="button"
            role="tab"
            aria-selected={visibleState.activeTab === "rules"}
            aria-current={visibleState.activeTab === "rules" ? "page" : undefined}
            className={visibleState.activeTab === "rules" ? "active" : undefined}
            onClick={() => dispatch({
              type: "tab-selected", scope: connectedScope, tab: "rules",
            })}
          >当前规则</button>
          <button
            type="button"
            role="tab"
            aria-selected={visibleState.activeTab === "history"}
            aria-current={visibleState.activeTab === "history" ? "page" : undefined}
            className={visibleState.activeTab === "history" ? "active" : undefined}
            onClick={() => dispatch({
              type: "tab-selected", scope: connectedScope, tab: "history",
            })}
          >变更历史</button>
        </div>
        <button
          type="button"
          disabled={loading}
          onClick={() => setRefreshVersion((version) => version + 1)}
        >{loading ? "刷新中…" : "手动刷新"}</button>
      </div>

      {visibleState.notice !== null ? (
        <div className="firewall-notice" role="status">
          <span>{visibleState.notice}</span>
          <button type="button" onClick={() => dispatch({ type: "notice-cleared" })}>关闭</button>
        </div>
      ) : null}

      {visibleState.activeTab === "rules" ? (
        <section className="firewall-rules-view" role="tabpanel">
          {visibleState.inspectionError !== null ? (
            <div className="firewall-error" role="alert">{visibleState.inspectionError}</div>
          ) : null}
          {visibleState.inspectionStatus === "loading" && visibleState.inspection === null ? (
            <div className="firewall-inline-state" role="status">正在读取防火墙规则快照…</div>
          ) : null}
          {visibleState.inspection !== null && rules !== null ? (
            <>
              <section className="firewall-metrics" aria-label="防火墙快照摘要">
                <div><span>当前 backend</span><strong>{firewallBackendLabel(visibleState.inspection.backend)}</strong></div>
                <div><span>安全 engine</span><strong>{firewallEngineLabel(visibleState.inspection.engine)}</strong></div>
                <div><span>当前状态</span><strong className={visibleState.inspection.active ? "positive" : "warning"}>
                  {visibleState.inspection.active ? "已启用" : "未启用 / 空规则"}
                </strong></div>
                <div><span>捕获时间</span><strong>{visibleState.inspection.capturedAt}</strong></div>
              </section>

              <section className="firewall-rule-panel" aria-labelledby="firewall-rules-title">
                <header>
                  <div>
                    <p>规则快照</p>
                    <h2 id="firewall-rules-title">当前规则</h2>
                  </div>
                  <div className="firewall-rule-actions">
                    <label>
                      <span>搜索规则</span>
                      <input
                        type="search"
                        value={visibleState.ruleQuery}
                        maxLength={256}
                        placeholder="搜索当前快照"
                        onChange={(event) => dispatch({
                          type: "rule-query-changed", query: event.currentTarget.value,
                        })}
                      />
                    </label>
                    <button
                      type="button"
                      className="primary"
                      disabled={writeClipboard === undefined || visibleState.inspection.rules === "" ||
                        visibleState.copySnapshotHandle !== null}
                      onClick={() => void copyRules()}
                    >{visibleState.copySnapshotHandle === null ? "复制规则纯文本" : "复制中…"}</button>
                  </div>
                </header>
                <div className="firewall-rule-summary">
                  <span>总计 {rules.totalLines} 行</span>
                  <span>匹配 {rules.matchedLines} 行</span>
                  <span>显示 {rules.displayedLines} 行</span>
                </div>
                {visibleState.inspection.rulesTruncated ? (
                  <div className="firewall-warning" role="status">
                    规则快照已截断。
                  </div>
                ) : null}
                {rules.truncated ? (
                  <div className="firewall-warning" role="status">
                    最多显示 2,000 行 / 128 KiB，复制内容同样限于该范围。
                  </div>
                ) : null}
                {rules.text === "" ? (
                  <div className="firewall-empty">
                    {visibleState.inspection.rules === ""
                      ? "目标未返回规则，或当前账户没有可读规则。"
                      : "当前快照没有匹配搜索条件的规则。"}
                  </div>
                ) : <pre>{rules.text}</pre>}
              </section>
            </>
          ) : null}
        </section>
      ) : (
        <section className="firewall-history-view" role="tabpanel">
          {visibleState.historyError !== null ? (
            <div className="firewall-error" role="alert">{visibleState.historyError}</div>
          ) : null}
          {visibleState.historyStatus === "loading" && visibleState.history === null ? (
            <div className="firewall-inline-state" role="status">正在读取变更历史…</div>
          ) : null}
          {visibleState.history?.truncated ? (
            <div className="firewall-warning" role="status">历史记录已达到显示上限。</div>
          ) : null}
          {visibleState.historyStatus === "ready" && visibleState.history?.entries.length === 0 ? (
            <div className="firewall-empty">当前目标没有 LovelyRes 防火墙变更记录。</div>
          ) : null}
          {visibleState.history !== null && visibleState.history.entries.length > 0 ? (
            <div className="firewall-history-workbench">
              <section className="firewall-history-list" aria-label="防火墙变更历史">
                {visibleState.history.entries.map((entry) => (
                  <button
                    type="button"
                    key={entry.changeHandle}
                    className={entry.changeHandle === visibleState.selectedChangeHandle
                      ? "active"
                      : undefined}
                    aria-pressed={entry.changeHandle === visibleState.selectedChangeHandle}
                    onClick={() => dispatch({
                      type: "history-selected",
                      scope: connectedScope,
                      changeHandle: entry.changeHandle,
                    })}
                  >
                    <strong>{entry.label}</strong>
                    <span>{firewallChangeKindLabel(entry.changeKind)}</span>
                    <span className={`state ${entry.state}`}>
                      {firewallChangeStateLabel(entry.state)}
                    </span>
                    <time>{entry.createdAt}</time>
                  </button>
                ))}
              </section>
              <aside className="firewall-history-detail" aria-label="历史记录纯文本详情">
                <header><p>变更详情</p><h2>记录详情</h2></header>
                {selectedChange === null ? (
                  <div className="firewall-empty">选择一条历史记录查看详情。</div>
                ) : (
                  <div className="firewall-history-detail-content">
                    <h3>{selectedChange.label}</h3>
                    <dl>
                      <div><dt>历史类型</dt><dd>{firewallChangeKindLabel(selectedChange.changeKind)}</dd></div>
                      <div><dt>记录状态</dt><dd>{firewallChangeStateLabel(selectedChange.state)}</dd></div>
                      <div><dt>Backend</dt><dd>{firewallBackendLabel(selectedChange.backend)}</dd></div>
                      <div><dt>Engine</dt><dd>{firewallEngineLabel(selectedChange.engine)}</dd></div>
                      <div><dt>当时 SSH 端口</dt><dd>{selectedChange.sshPort}</dd></div>
                      <div><dt>创建时间</dt><dd>{selectedChange.createdAt}</dd></div>
                      <div><dt>Dead-man deadline</dt><dd>{selectedChange.deadmanDeadline}</dd></div>
                      <div><dt>最后更新时间</dt><dd>{selectedChange.updatedAt}</dd></div>
                    </dl>
                    {selectedChange.textTruncated ? <p className="firewall-warning">标签已截断。</p> : null}
                    {selectedChange.state === "awaiting-keep" ? (
                      <p className="firewall-history-caveat">
                        这是持久化只读记录。本阶段不执行 reconcile，不能据此推断远端最终状态。
                      </p>
                    ) : null}
                  </div>
                )}
              </aside>
            </div>
          ) : null}
        </section>
      )}

      <footer className="firewall-boundary-note">
        本页不提供任何防火墙变更、终端、文件或导出入口。
      </footer>
    </section>
  );
}
