import { useEffect, useReducer, useRef, useState } from "react";

import { isTargetLost, TARGET_LOST_MESSAGE, targetFailureMessage } from "./target-lost";
import {
  isMiddlewareConfiguration,
  isMiddlewareDiscovery,
  isMiddlewareHistory,
  type MiddlewareConfiguration,
  type MiddlewareDiscovery,
  type MiddlewareHistory,
  type MiddlewareReadApi,
} from "../shared/middleware-read-contract";
import {
  filterMiddlewareInstances,
  formatMiddlewareBytes,
  middlewareHistoryStateLabel,
  middlewareNodeKindLabel,
  middlewareProductLabel,
  middlewareRawReasonLabel,
  middlewareRoleLabel,
  middlewareScope,
  middlewareStatusLabel,
  middlewareTabLabel,
} from "./middleware-read-helpers";
import {
  createMiddlewareReadState,
  middlewareReadReducer,
  type MiddlewareProductFilter,
  type MiddlewareReadStatus,
  type MiddlewareStatusFilter,
  type MiddlewareTab,
} from "./middleware-read-state";
import "./middleware-page.css";

export interface MiddlewarePageProps {
  bindingHandle: string | null;
  api: MiddlewareReadApi;
}

/**
 * Why discovery could not answer.
 *
 * Finding middleware means enumerating service units, so a target without
 * systemd — a container, a minimal install — cannot be asked at all. Saying
 * "none found" there would read as "nothing is running", which on a machine
 * with four services would be a lie, so it says what happened and where to
 * look instead.
 */
export function middlewareFailureMessage(reason: unknown): string {
  const message = reason instanceof Error ? reason.message : String(reason ?? "");
  if (message.includes("middleware-unsupported-target")) {
    return "这台主机没有 systemd，中间件是按服务单元找的，所以这里问不出来。改到命令工作台里按进程和监听端口查。";
  }
  if (isTargetLost(reason)) return TARGET_LOST_MESSAGE;
  return "无法发现当前目标的中间件实例：连接可能已断开或变化，也可能权限不足。";
}

const tabs: readonly MiddlewareTab[] = ["instances", "history"];
const products: readonly MiddlewareProductFilter[] = ["all", "nginx", "apache-httpd", "redis", "tomcat"];
const statuses: readonly MiddlewareStatusFilter[] = [
  "all", "active", "inactive", "failed", "activating", "deactivating", "reloading", "unknown",
];

export function MiddlewarePage({ bindingHandle, api }: MiddlewarePageProps) {
  const [state, dispatch] = useReducer(middlewareReadReducer, undefined, createMiddlewareReadState);
  const [discoveryVersion, setDiscoveryVersion] = useState(0);
  const [configurationVersion, setConfigurationVersion] = useState(0);
  const [historyVersion, setHistoryVersion] = useState(0);
  const requestRef = useRef(0);
  const scope = bindingHandle === null ? null : middlewareScope(bindingHandle);

  useEffect(() => {
    dispatch({ type: "scope-changed", scope });
  }, [scope]);

  useEffect(() => {
    if (scope === null || bindingHandle === null || state.scope !== scope || state.tab !== "instances") return;
    const request = { id: ++requestRef.current };
    let cancelled = false;
    dispatch({ type: "discovery-started", scope, request });
    void api.discoverMiddleware(bindingHandle).then((result) => {
      if (cancelled) return;
      if (!isMiddlewareDiscovery(result)) throw new Error();
      dispatch({ type: "discovery-loaded", scope, request, discovery: result });
    }).catch((reason: unknown) => {
      if (!cancelled) dispatch({
        type: "discovery-failed",
        scope,
        request,
        // A target with no systemd cannot answer this at all, which is worth
        // saying outright — and worth pointing somewhere that can.
        error: middlewareFailureMessage(reason),
      });
    });
    return () => {
      cancelled = true;
    };
  }, [api, bindingHandle, discoveryVersion, scope, state.scope, state.tab]);

  useEffect(() => {
    if (scope === null || bindingHandle === null || state.scope !== scope || state.tab !== "instances" ||
      state.discovery === null || state.selectedInstanceHandle === null) return;
    const request = { id: ++requestRef.current };
    let cancelled = false;
    dispatch({ type: "configuration-started", scope, request });
    void api.loadMiddlewareConfiguration(
      bindingHandle,
      state.discovery.discoveryHandle,
      state.selectedInstanceHandle,
    ).then((result) => {
      if (cancelled) return;
      if (!isMiddlewareConfiguration(result)) throw new Error();
      dispatch({ type: "configuration-loaded", scope, request, configuration: result });
    }).catch((reason: unknown) => {
      if (!cancelled) dispatch({
        type: "configuration-failed",
        scope,
        request,
        error: targetFailureMessage(reason, "无法安全读取所选实例配置；discovery 可能过期、目标已变化或配置图不满足边界。"),
      });
    });
    return () => {
      cancelled = true;
    };
  }, [
    api,
    bindingHandle,
    configurationVersion,
    scope,
    state.discovery,
    state.scope,
    state.selectedInstanceHandle,
    state.tab,
  ]);

  useEffect(() => {
    if (scope === null || bindingHandle === null || state.scope !== scope || state.tab !== "history") return;
    const request = { id: ++requestRef.current };
    let cancelled = false;
    dispatch({ type: "history-started", scope, request });
    void api.listMiddlewareHistory(bindingHandle).then((result) => {
      if (cancelled) return;
      if (!isMiddlewareHistory(result)) throw new Error();
      dispatch({ type: "history-loaded", scope, request, history: result });
    }).catch((reason: unknown) => {
      if (!cancelled) dispatch({
        type: "history-failed",
        scope,
        request,
        error: "无法读取当前目标的中间件历史：连接可能已断开或变化，也可能本地记录不可用。",
      });
    });
    return () => {
      cancelled = true;
    };
  }, [api, bindingHandle, historyVersion, scope, state.scope, state.tab]);

  const connected = bindingHandle !== null && state.scope === scope;
  return (
    <main className="middleware-page">
      <header className="middleware-header">
        <div>
          <p className="middleware-kicker">只读</p>
          <h1>中间件配置调查</h1>
          <p className="middleware-target">
            {bindingHandle === null ? "尚未连接 SSH 目标" : "已连接当前 SSH 目标"}
          </p>
        </div>
        <span>只读</span>
      </header>

      <p className="middleware-readonly-banner">
        本页只做只读查看：发现实例、审阅配置与历史摘要，不提供修改、部署或恢复操作。
      </p>

      <nav className="middleware-tabs" aria-label="中间件只读视图">
        {tabs.map((tab) => (
          <button key={tab} type="button" className={state.tab === tab ? "is-active" : ""}
            aria-current={state.tab === tab ? "page" : undefined}
            onClick={() => dispatch({ type: "tab-selected", tab })}>
            {middlewareTabLabel(tab)}
          </button>
        ))}
      </nav>

      <section className="middleware-content">
        {state.tab === "instances" ? (
          <MiddlewareInventoryView
            connected={connected}
            status={state.discoveryStatus}
            discovery={state.discovery}
            error={state.discoveryError}
            selectedInstanceHandle={state.selectedInstanceHandle}
            search={state.search}
            product={state.product}
            instanceStatus={state.status}
            onSearch={(value) => dispatch({ type: "search-changed", value })}
            onProduct={(value) => dispatch({ type: "product-changed", value })}
            onStatus={(value) => dispatch({ type: "status-changed", value })}
            onSelect={(instanceHandle) => dispatch({ type: "instance-selected", instanceHandle })}
            onRefresh={() => setDiscoveryVersion((value) => value + 1)}
          >
            <MiddlewareConfigurationView
              connected={connected}
              selected={state.selectedInstanceHandle !== null}
              status={state.configurationStatus}
              configuration={state.configuration}
              error={state.configurationError}
              onRefresh={() => setConfigurationVersion((value) => value + 1)}
            />
          </MiddlewareInventoryView>
        ) : (
          <MiddlewareHistoryView
            connected={connected}
            status={state.historyStatus}
            history={state.history}
            error={state.historyError}
            onRefresh={() => setHistoryVersion((value) => value + 1)}
          />
        )}
      </section>
    </main>
  );
}

export function MiddlewareInventoryView({ connected, status, discovery, error, selectedInstanceHandle,
  search, product, instanceStatus, onSearch, onProduct, onStatus, onSelect, onRefresh, children }: {
  connected: boolean;
  status: MiddlewareReadStatus;
  discovery: MiddlewareDiscovery | null;
  error: string | null;
  selectedInstanceHandle: string | null;
  search: string;
  product: MiddlewareProductFilter;
  instanceStatus: MiddlewareStatusFilter;
  onSearch(value: string): void;
  onProduct(value: MiddlewareProductFilter): void;
  onStatus(value: MiddlewareStatusFilter): void;
  onSelect(instanceHandle: string): void;
  onRefresh(): void;
  children?: React.ReactNode;
}) {
  const visible = filterMiddlewareInstances(discovery?.instances ?? [], search, product, instanceStatus);
  return (
    <>
      <div className="middleware-view-header">
        <div><h2>实例发现</h2><p>只做只读探测，不会修改中间件配置。</p></div>
        <button type="button" disabled={!connected || status === "loading"} onClick={onRefresh}>
          {status === "loading" ? "发现中…" : "手动刷新发现"}
        </button>
      </div>
      {!connected && <p className="middleware-connection-note" role="status">
        连接 SSH 目标后才能发现实例；当前页面没有目标数据，也没有运行任何检查。
      </p>}
      <div className="middleware-filters">
        <label>搜索
          <input type="search" value={search} maxLength={256} placeholder="产品、版本或状态"
            onChange={(event) => onSearch(event.target.value)} />
        </label>
        <label>产品
          <select value={product} onChange={(event) => onProduct(event.target.value as MiddlewareProductFilter)}>
            {products.map((value) => <option key={value} value={value}>
              {value === "all" ? "全部产品" : middlewareProductLabel(value)}
            </option>)}
          </select>
        </label>
        <label>状态
          <select value={instanceStatus}
            onChange={(event) => onStatus(event.target.value as MiddlewareStatusFilter)}>
            {statuses.map((value) => <option key={value} value={value}>
              {value === "all" ? "全部状态" : middlewareStatusLabel(value)}
            </option>)}
          </select>
        </label>
      </div>
      {status === "loading" && discovery === null ? (
        <MiddlewareStatusPanel label="正在发现中间件实例…" />
      ) : status === "error" ? (
        <MiddlewareErrorPanel message={error ?? "中间件发现失败。"} compact />
      ) : !connected ? null : discovery === null || discovery.instances.length === 0 ? (
        <MiddlewareEmptyPanel title="未发现受管实例" detail="当前目标没有识别到中间件实例。" compact />
      ) : visible.length === 0 ? (
        <MiddlewareEmptyPanel title="没有匹配的实例" detail="调整产品、状态或搜索文本。" compact />
      ) : (
        <div className="middleware-instance-grid">
          {visible.map((instance) => (
            <button key={instance.instanceHandle} type="button"
              className={selectedInstanceHandle === instance.instanceHandle ? "is-selected" : ""}
              aria-pressed={selectedInstanceHandle === instance.instanceHandle}
              onClick={() => onSelect(instance.instanceHandle)}>
              <span>{middlewareProductLabel(instance.product)}</span>
              <strong>{instance.title}</strong>
              <small>{instance.version || "版本未报告"}</small>
              <em className={`status-${instance.status}`}>{middlewareStatusLabel(instance.status)}</em>
              <code>{instance.statusText || "状态详情未报告"}</code>
              {(instance.redacted || instance.textTruncated) && <i>远端文本已遮蔽或截断</i>}
            </button>
          ))}
        </div>
      )}
      {discovery?.truncated && <MiddlewareTruncatedNotice>
        实例结果已按文本、响应或 registry 预算截断；未显示不代表目标不存在其他实例。
      </MiddlewareTruncatedNotice>}
      {children}
    </>
  );
}

export function MiddlewareConfigurationView({ connected, selected, status, configuration, error,
  onRefresh }: {
  connected: boolean;
  selected: boolean;
  status: MiddlewareReadStatus;
  configuration: MiddlewareConfiguration | null;
  error: string | null;
  onRefresh(): void;
}) {
  return (
    <section className="middleware-configuration">
      <div className="middleware-view-header">
        <div><h2>安全配置视图</h2><p>不显示路径、摘要、命令或 include 解析目标。</p></div>
        <button type="button" disabled={!connected || !selected || status === "loading"} onClick={onRefresh}>
          {status === "loading" ? "读取中…" : "手动刷新配置"}
        </button>
      </div>
      {!selected ? (
        <MiddlewareEmptyPanel title="请选择一个实例" detail="选择实例后查看它的配置。" compact />
      ) : status === "loading" && configuration === null ? (
        <MiddlewareStatusPanel label="正在读取配置…" />
      ) : status === "error" ? (
        <MiddlewareErrorPanel message={error ?? "配置读取失败。"} compact />
      ) : configuration === null ? (
        <MiddlewareEmptyPanel title="尚无配置结果" detail="手动刷新所选实例的安全配置视图。" compact />
      ) : configuration.files.length === 0 ? (
        <MiddlewareEmptyPanel title="配置图为空" detail="没有可展示的配置文件摘要。" compact />
      ) : (
        <>
          <div className="middleware-summary" aria-label="配置汇总">
            <article><strong>{middlewareProductLabel(configuration.product)}</strong><span>产品</span></article>
            <article><strong>{configuration.displayed}/{configuration.fileCount}</strong><span>文件摘要</span></article>
            <article><strong>{configuration.displayedNodes}</strong><span>结构节点</span></article>
            <article><strong>{formatMiddlewareBytes(configuration.totalBytes)}</strong><span>采集总量</span></article>
          </div>
          <p className="middleware-graph-note">
            未解析 include：{configuration.unresolvedIncludeCount} · 目录清单：{configuration.directoryManifestCount}
          </p>
          <div className="middleware-file-list">
            {configuration.files.map((file) => (
              <article key={file.fileHandle}>
                <header>
                  <strong>配置 #{file.ordinal}</strong>
                  <span>{middlewareRoleLabel(file.role)}</span>
                  <span>{formatMiddlewareBytes(file.byteLength)}</span>
                  <em>{file.contentMode === "raw-text" ? "安全原文" : "仅结构摘要"}</em>
                </header>
                {file.rawText !== null ? (
                  <pre>{file.rawText}</pre>
                ) : (
                  <div className="middleware-structure">
                    <p>{middlewareRawReasonLabel(file.rawTextUnavailableReason)}</p>
                    {file.nodes.length === 0 ? <span>没有可显示的结构节点。</span> : (
                      <ul>
                        {file.nodes.map((node, index) => (
                          <li key={`${index}-${node.kind}-${node.depth}`}>
                            <b>{middlewareNodeKindLabel(node.kind)}</b>
                            <code>{node.name ?? "未命名"}</code>
                            <span>深度 {node.depth}</span>
                            {node.editable && <span>{node.sensitive ? "敏感值" : "有值区域"}</span>}
                            {(node.redacted || node.textTruncated) && <i>名称已遮蔽或截断</i>}
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                )}
                {(file.containsSensitiveValues || file.truncated) && <small>
                  该文件包含敏感值，或内容已截断。
                </small>}
              </article>
            ))}
          </div>
        </>
      )}
      {configuration?.truncated && <MiddlewareTruncatedNotice>
        配置结果已截断；缺失内容不表示配置不存在、有效或合规。
      </MiddlewareTruncatedNotice>}
    </section>
  );
}

export function MiddlewareHistoryView({ connected, status, history, error, onRefresh }: {
  connected: boolean;
  status: MiddlewareReadStatus;
  history: MiddlewareHistory | null;
  error: string | null;
  onRefresh(): void;
}) {
  return (
    <>
      <div className="middleware-view-header">
        <div><h2>变更历史摘要</h2><p>只展示变更摘要，原始记录不在此显示。</p></div>
        <button type="button" disabled={!connected || status === "loading"} onClick={onRefresh}>
          {status === "loading" ? "读取中…" : "手动刷新历史"}
        </button>
      </div>
      {!connected ? (
        <MiddlewareEmptyPanel title="尚未连接目标" detail="连接目标后才能读取中间件历史。" compact />
      ) : status === "loading" && history === null ? (
        <MiddlewareStatusPanel label="正在读取历史摘要…" />
      ) : status === "error" ? (
        <MiddlewareErrorPanel message={error ?? "中间件历史不可用。"} compact />
      ) : history === null || history.entries.length === 0 ? (
        <MiddlewareEmptyPanel title="没有中间件历史" detail="当前目标没有可展示的记录。" compact />
      ) : (
        <div className="middleware-history-list">
          {history.entries.map((entry) => (
            <article key={entry.historyItemHandle}>
              <header>
                <strong>{middlewareProductLabel(entry.product)}</strong>
                <span>{middlewareHistoryStateLabel(entry.state)}</span>
                <time>{entry.updatedAt}</time>
              </header>
              <p>{entry.summary}</p>
              <small>{formatMiddlewareBytes(entry.oldBytes)} → {formatMiddlewareBytes(entry.newBytes)} · 创建于 {entry.createdAt}</small>
            </article>
          ))}
        </div>
      )}
      {history?.truncated && <MiddlewareTruncatedNotice>
        历史已截断；原始证据不在此展示。
      </MiddlewareTruncatedNotice>}
    </>
  );
}

export function MiddlewareStatusPanel({ label }: { label: string }) {
  return <div className="middleware-status-panel" aria-live="polite"><span aria-hidden="true" />{label}</div>;
}

export function MiddlewareErrorPanel({ message, compact = false }: { message: string; compact?: boolean }) {
  return <div className={compact ? "middleware-error is-compact" : "middleware-error"} role="alert">{message}</div>;
}

export function MiddlewareEmptyPanel({ title, detail, compact = false }: {
  title: string;
  detail: string;
  compact?: boolean;
}) {
  return <div className={compact ? "middleware-empty is-compact" : "middleware-empty"}>
    <strong>{title}</strong><p>{detail}</p>
  </div>;
}

function MiddlewareTruncatedNotice({ children }: { children: string }) {
  return <p className="middleware-warning" role="status">{children}</p>;
}
