import { useEffect, useReducer, useRef, useState } from "react";

import { targetFailureMessage } from "./target-lost";

import {
  isDockerContainerSnapshot,
  isDockerLogs,
  isDockerReadCollection,
  isDockerReadInspection,
  isDockerSecurityAudit,
  type DockerCollectionKind,
  type DockerContainerInspection,
  type DockerLogs,
  type DockerNetworkInspection,
  type DockerReadApi,
  type DockerReadCollection,
  type DockerReadInspection,
  type DockerResourceKind,
  type DockerSecurityAudit,
  type DockerVolumeInspection,
} from "../shared/docker-read-contract";
import {
  dockerBooleanLabel,
  dockerCollectionForTab,
  dockerReadScope,
  dockerSecuritySeverityLabel,
  dockerSnapshotMinutes,
  dockerTabLabel,
  filterDockerContainers,
} from "./docker-read-helpers";
import {
  createDockerReadState,
  dockerReadReducer,
  type DockerReadStatus,
  type DockerTab,
} from "./docker-read-state";
import "./docker-page.css";

export interface DockerPageProps {
  bindingHandle: string | null;
  api: DockerReadApi;
}

const tabs: readonly DockerTab[] = [
  "containers", "images", "networks", "volumes", "compose-projects", "security",
];
const LOG_TAIL = 200;

export function DockerPage({ bindingHandle, api }: DockerPageProps) {
  const [state, dispatch] = useReducer(dockerReadReducer, undefined, createDockerReadState);
  const [snapshotVersion, setSnapshotVersion] = useState(0);
  const [collectionVersion, setCollectionVersion] = useState(0);
  const [auditVersion, setAuditVersion] = useState(0);
  const requestRef = useRef(0);
  const scope = bindingHandle === null ? null : dockerReadScope(bindingHandle);
  const stateIsCurrent = state.scope === scope;

  useEffect(() => {
    dispatch({ type: "scope-changed", scope });
  }, [scope]);

  useEffect(() => {
    if (scope === null || bindingHandle === null || state.scope !== scope) return;
    const request = ++requestRef.current;
    let cancelled = false;
    dispatch({ type: "snapshot-started", scope, request });
    void api.refreshDockerContainers(bindingHandle).then((result) => {
      if (cancelled) return;
      if (!isDockerContainerSnapshot(result)) throw new Error();
      dispatch({ type: "snapshot-loaded", scope, request, snapshot: result });
    }).catch((reason: unknown) => {
      if (!cancelled) {
        dispatch({
          type: "snapshot-failed",
          scope,
          request,
          error: "无法读取当前 SSH 绑定的 Docker 容器清单。",
        });
      }
    });
    return () => {
      cancelled = true;
    };
  }, [api, bindingHandle, scope, snapshotVersion, state.scope]);

  const snapshotHandle = state.snapshot?.snapshotHandle ?? null;
  const collectionKind = dockerCollectionForTab(state.tab);

  useEffect(() => {
    if (scope === null || bindingHandle === null || snapshotHandle === null ||
      state.scope !== scope || collectionKind === null) return;
    const request = ++requestRef.current;
    let cancelled = false;
    dispatch({
      type: "collection-started",
      scope,
      snapshotHandle,
      kind: collectionKind,
      request,
    });
    void api.getDockerCollection(bindingHandle, snapshotHandle, collectionKind).then((result) => {
      if (cancelled) return;
      if (!isDockerReadCollection(result) || result.kind !== collectionKind ||
        result.snapshotHandle !== snapshotHandle) throw new Error();
      dispatch({
        type: "collection-loaded",
        scope,
        snapshotHandle,
        kind: collectionKind,
        request,
        collection: result,
      });
    }).catch((reason: unknown) => {
      if (!cancelled) {
        dispatch({
          type: "collection-failed",
          scope,
          snapshotHandle,
          kind: collectionKind,
          request,
          error: targetFailureMessage(reason, "资源快照已过期、目标已变化或 Docker 响应无效。"),
        });
      }
    });
    return () => {
      cancelled = true;
    };
  }, [api, bindingHandle, collectionKind, collectionVersion, scope, snapshotHandle, state.scope]);

  useEffect(() => {
    if (scope === null || bindingHandle === null || snapshotHandle === null ||
      state.scope !== scope || state.tab !== "security") return;
    const request = ++requestRef.current;
    let cancelled = false;
    dispatch({ type: "audit-started", scope, snapshotHandle, request });
    void api.getDockerSecurityAudit(bindingHandle, snapshotHandle).then((result) => {
      if (cancelled) return;
      if (!isDockerSecurityAudit(result) || result.snapshotHandle !== snapshotHandle) throw new Error();
      dispatch({ type: "audit-loaded", scope, snapshotHandle, request, audit: result });
    }).catch((reason: unknown) => {
      if (!cancelled) {
        dispatch({
          type: "audit-failed",
          scope,
          snapshotHandle,
          request,
          error: "无法完成当前快照的只读安全审计。",
        });
      }
    });
    return () => {
      cancelled = true;
    };
  }, [api, auditVersion, bindingHandle, scope, snapshotHandle, state.scope, state.tab]);

  const selectedResource = selectedInspectionResource(state);
  useEffect(() => {
    if (scope === null || bindingHandle === null || snapshotHandle === null ||
      state.scope !== scope || selectedResource === null) return;
    const { kind, handle } = selectedResource;
    const request = ++requestRef.current;
    let cancelled = false;
    dispatch({ type: "inspection-started", scope, snapshotHandle, kind, handle, request });
    void api.inspectDockerResource(bindingHandle, snapshotHandle, kind, handle).then((result) => {
      if (cancelled) return;
      if (!isDockerReadInspection(result) || result.kind !== kind ||
        result.snapshotHandle !== snapshotHandle || result.resourceHandle !== handle) throw new Error();
      dispatch({ type: "inspection-loaded", scope, snapshotHandle, kind, handle, request, inspection: result });
    }).catch((reason: unknown) => {
      if (!cancelled) {
        dispatch({
          type: "inspection-failed",
          scope,
          snapshotHandle,
          kind,
          handle,
          request,
          error: targetFailureMessage(reason, "所选资源已失效、目标已变化或调查结果无效。"),
        });
      }
    });
    return () => {
      cancelled = true;
    };
  }, [api, bindingHandle, scope, selectedResource?.handle, selectedResource?.kind, snapshotHandle, state.scope]);

  if (bindingHandle === null) {
    return (
      <section className="page docker-page">
        <div className="docker-connect-prompt">
          <span aria-hidden="true">◇</span>
          <h1>连接目标后调查 Docker</h1>
          <p>该页面只读取资源快照，不会修改容器。</p>
        </div>
      </section>
    );
  }

  const visibleState = stateIsCurrent ? state : createDockerReadState();
  const visibleCollectionKind = dockerCollectionForTab(visibleState.tab);
  const visibleCollection = visibleCollectionKind === null
    ? null
    : visibleState.collections[visibleCollectionKind] ?? null;

  async function loadLogs() {
    const snapshot = visibleState.snapshot;
    const handle = visibleState.selectedContainerHandle;
    if (scope === null || bindingHandle === null || snapshot === null || handle === null) return;
    const request = ++requestRef.current;
    dispatch({ type: "logs-started", scope, snapshotHandle: snapshot.snapshotHandle, handle, request });
    try {
      const result = await api.getDockerLogs(bindingHandle, snapshot.snapshotHandle, handle, LOG_TAIL);
      if (!isDockerLogs(result) || result.snapshotHandle !== snapshot.snapshotHandle ||
        result.containerHandle !== handle || result.tail !== LOG_TAIL) throw new Error();
      dispatch({
        type: "logs-loaded",
        scope,
        snapshotHandle: snapshot.snapshotHandle,
        handle,
        request,
        logs: result,
      });
    } catch {
      dispatch({
        type: "logs-failed",
        scope,
        snapshotHandle: snapshot.snapshotHandle,
        handle,
        request,
        error: "无法读取所选容器的日志。",
      });
    }
  }

  return (
    <section className="page docker-page" aria-label="Docker 只读调查">
      <header className="docker-page-header">
        <div>
          <p className="docker-page-kicker">只读调查 · Docker</p>
          <h1>资源盘点</h1>
          <p className="docker-page-target">当前目标的只读 Docker 快照</p>
        </div>
        <div className="docker-header-actions">
          {visibleState.snapshot !== null && (
            <span className="docker-snapshot-note">
              快照约 {dockerSnapshotMinutes(visibleState.snapshot.expiresInSeconds)} 后失效
            </span>
          )}
          <button
            className="docker-primary-button"
            type="button"
            disabled={visibleState.snapshotStatus === "loading"}
            onClick={() => setSnapshotVersion((version) => version + 1)}
          >
            {visibleState.snapshotStatus === "loading" ? "读取中…" : "刷新全部快照"}
          </button>
        </div>
      </header>

      <p className="docker-readonly-banner">
        当前阶段仅提供调查与资源盘点；容器操作、资源变更、文件访问和终端入口均未开放。
      </p>

      <nav className="docker-tabs" aria-label="Docker 资源视图">
        {tabs.map((tab) => (
          <button
            key={tab}
            type="button"
            aria-current={visibleState.tab === tab ? "page" : undefined}
            className={visibleState.tab === tab ? "docker-tab is-active" : "docker-tab"}
            onClick={() => dispatch({ type: "tab-selected", tab })}
          >
            {dockerTabLabel(tab)}
          </button>
        ))}
      </nav>

      {visibleState.error !== null && <p className="docker-error" role="alert">{visibleState.error}</p>}
      {visibleState.snapshotStatus === "loading" && visibleState.snapshot === null && (
        <StatusPanel label="正在建立当前目标的 Docker 容器快照…" />
      )}
      {visibleState.snapshotStatus === "error" && visibleState.snapshot === null && (
        <EmptyPanel title="容器快照不可用" detail="可刷新重试；旧目标的晚到结果不会被接收。" />
      )}
      {visibleState.snapshotStatus === "ready" && visibleState.snapshot !== null && (
        <main className="docker-page-content">
          {visibleState.tab === "containers" && (
            <ContainersView
              state={visibleState}
              collection={visibleCollection?.kind === "stats" ? visibleCollection : null}
              onFilter={(filter) => dispatch({ type: "filter-changed", filter })}
              onSelect={(handle) => dispatch({ type: "container-selected", handle })}
              onRefresh={() => setCollectionVersion((version) => version + 1)}
              onLoadLogs={() => void loadLogs()}
            />
          )}
          {visibleState.tab === "images" && (
            <ImagesView
              status={visibleState.collectionStatus.images ?? "idle"}
              collection={visibleCollection?.kind === "images" ? visibleCollection : null}
              onRefresh={() => setCollectionVersion((version) => version + 1)}
            />
          )}
          {visibleState.tab === "networks" && (
            <NetworksView
              state={visibleState}
              collection={visibleCollection?.kind === "networks" ? visibleCollection : null}
              onSelect={(handle) => dispatch({ type: "network-selected", handle })}
              onRefresh={() => setCollectionVersion((version) => version + 1)}
            />
          )}
          {visibleState.tab === "volumes" && (
            <VolumesView
              state={visibleState}
              collection={visibleCollection?.kind === "volumes" ? visibleCollection : null}
              onSelect={(handle) => dispatch({ type: "volume-selected", handle })}
              onRefresh={() => setCollectionVersion((version) => version + 1)}
            />
          )}
          {visibleState.tab === "compose-projects" && (
            <ComposeView
              status={visibleState.collectionStatus["compose-projects"] ?? "idle"}
              collection={visibleCollection?.kind === "compose-projects" ? visibleCollection : null}
              onRefresh={() => setCollectionVersion((version) => version + 1)}
            />
          )}
          {visibleState.tab === "security" && (
            <DockerSecurityView
              status={visibleState.auditStatus}
              audit={visibleState.audit}
              onRefresh={() => setAuditVersion((version) => version + 1)}
            />
          )}
        </main>
      )}
    </section>
  );
}

function selectedInspectionResource(state: ReturnType<typeof createDockerReadState>): {
  kind: DockerResourceKind;
  handle: string;
} | null {
  if (state.tab === "containers" && state.selectedContainerHandle !== null) {
    return { kind: "container", handle: state.selectedContainerHandle };
  }
  if (state.tab === "networks" && state.selectedNetworkHandle !== null) {
    return { kind: "network", handle: state.selectedNetworkHandle };
  }
  if (state.tab === "volumes" && state.selectedVolumeHandle !== null) {
    return { kind: "volume", handle: state.selectedVolumeHandle };
  }
  return null;
}

interface ContainersViewProps {
  state: ReturnType<typeof createDockerReadState>;
  collection: Extract<DockerReadCollection, { kind: "stats" }> | null;
  onFilter(filter: string): void;
  onSelect(handle: string): void;
  onRefresh(): void;
  onLoadLogs(): void;
}

function ContainersView({ state, collection, onFilter, onSelect, onRefresh, onLoadLogs }: ContainersViewProps) {
  const containers = filterDockerContainers(state.snapshot?.containers ?? [], state.filter);
  const statsByHandle = new Map(collection?.items.map((item) => [item.containerHandle, item]) ?? []);
  return (
    <>
      <ViewHeader
        title="容器与实时统计"
        status={state.collectionStatus.stats ?? "idle"}
        onRefresh={onRefresh}
      />
      <label className="docker-filter">
        <span>筛选容器</span>
        <input
          type="search"
          value={state.filter}
          placeholder="名称、镜像、状态或端口"
          onChange={(event) => onFilter(event.currentTarget.value)}
        />
      </label>
      {containers.length === 0 ? (
        <EmptyPanel
          title={(state.snapshot?.containers.length ?? 0) === 0 ? "当前目标没有 Docker 容器" : "没有匹配的容器"}
          detail="调整筛选条件或刷新快照。"
        />
      ) : (
        <div className="docker-table-wrap">
          <table className="docker-table">
            <thead><tr><th>容器</th><th>镜像</th><th>状态</th><th>CPU</th><th>内存</th><th>网络 I/O</th></tr></thead>
            <tbody>
              {containers.map((container) => {
                const stats = statsByHandle.get(container.containerHandle);
                return (
                  <tr key={container.containerHandle} className={state.selectedContainerHandle === container.containerHandle ? "is-selected" : undefined}>
                    <td>
                      <button className="docker-row-button" type="button" onClick={() => onSelect(container.containerHandle)}>
                        {container.name || "（未命名）"}
                      </button>
                      <small>{container.ports || "无端口信息"}</small>
                    </td>
                    <td>{container.image || "—"}</td><td>{container.status || container.state || "—"}</td>
                    <td>{stats?.cpuPercent || "—"}</td><td>{stats?.memoryUsage || "—"}</td><td>{stats?.networkIo || "—"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <TruncatedNotice value={(state.snapshot?.truncated ?? false) || (collection?.truncated ?? false)} />
      <InspectionPanel status={state.inspectionStatus} inspection={state.inspection} />
      {state.selectedContainerHandle !== null && (
        <section className="docker-card docker-logs-card">
          <div className="docker-section-heading">
            <div><h3>最近日志</h3><p>固定读取最后 {LOG_TAIL} 行，输出最多 256 KiB。</p></div>
            <button type="button" onClick={onLoadLogs} disabled={state.logsStatus === "loading"}>
              {state.logsStatus === "loading" ? "读取中…" : "读取最近日志"}
            </button>
          </div>
          {state.logsStatus === "idle" && <p className="docker-muted">按需读取，不持续跟踪远端输出。</p>}
          {state.logsStatus === "error" && <p className="docker-inline-error">日志不可用。</p>}
          {state.logsStatus === "ready" && state.logs !== null && <DockerLogsText logs={state.logs} />}
        </section>
      )}
    </>
  );
}

function ImagesView({ status, collection, onRefresh }: {
  status: DockerReadStatus;
  collection: Extract<DockerReadCollection, { kind: "images" }> | null;
  onRefresh(): void;
}) {
  return (
    <>
      <ViewHeader title="镜像盘点" status={status} onRefresh={onRefresh} />
      {status === "loading" && collection === null ? <StatusPanel label="正在读取镜像…" /> :
        collection === null || collection.items.length === 0 ? <EmptyPanel title="没有镜像记录" detail="刷新当前资源以再次调查。" /> : (
          <div className="docker-card-grid">
            {collection.items.map((item, index) => (
              <article className="docker-card" key={`${item.repository}\0${item.tag}\0${index}`}>
                <h3>{item.repository || "（无仓库名）"}:{item.tag || "（无标签）"}</h3>
                <dl><dt>摘要</dt><dd>{item.digest || "—"}</dd><dt>大小</dt><dd>{item.size || "—"}</dd><dt>创建时间</dt><dd>{item.createdAt || "—"}</dd></dl>
              </article>
            ))}
          </div>
        )}
      <TruncatedNotice value={collection?.truncated ?? false} />
    </>
  );
}

function NetworksView({ state, collection, onSelect, onRefresh }: {
  state: ReturnType<typeof createDockerReadState>;
  collection: Extract<DockerReadCollection, { kind: "networks" }> | null;
  onSelect(handle: string): void;
  onRefresh(): void;
}) {
  return (
    <>
      <ViewHeader title="网络盘点" status={state.collectionStatus.networks ?? "idle"} onRefresh={onRefresh} />
      {collection === null || collection.items.length === 0 ? <EmptyPanel title="没有网络记录" detail="当前只展示 Docker 返回的清单。" /> : (
        <div className="docker-resource-list" role="list">
          {collection.items.map((item) => (
            <button key={item.networkHandle} role="listitem" type="button" className={state.selectedNetworkHandle === item.networkHandle ? "is-selected" : undefined} onClick={() => onSelect(item.networkHandle)}>
              <strong>{item.name || "（未命名）"}</strong><span>{item.driver || "—"} · {item.scope || "—"}</span>
              <small>内部：{dockerBooleanLabel(item.internal)} · IPv6：{dockerBooleanLabel(item.ipv6)}</small>
            </button>
          ))}
        </div>
      )}
      <TruncatedNotice value={collection?.truncated ?? false} />
      <InspectionPanel status={state.inspectionStatus} inspection={state.inspection} />
    </>
  );
}

function VolumesView({ state, collection, onSelect, onRefresh }: {
  state: ReturnType<typeof createDockerReadState>;
  collection: Extract<DockerReadCollection, { kind: "volumes" }> | null;
  onSelect(handle: string): void;
  onRefresh(): void;
}) {
  return (
    <>
      <ViewHeader title="存储卷盘点" status={state.collectionStatus.volumes ?? "idle"} onRefresh={onRefresh} />
      {collection === null || collection.items.length === 0 ? <EmptyPanel title="没有存储卷记录" detail="当前只展示 Docker 返回的清单。" /> : (
        <div className="docker-resource-list" role="list">
          {collection.items.map((item) => (
            <button key={item.volumeHandle} role="listitem" type="button" className={state.selectedVolumeHandle === item.volumeHandle ? "is-selected" : undefined} onClick={() => onSelect(item.volumeHandle)}>
              <strong>{item.name || "（未命名）"}</strong><span>{item.driver || "—"} · {item.scope || "—"}</span>
              <small>{item.mountpoint || "无挂载点信息"}</small>
            </button>
          ))}
        </div>
      )}
      <TruncatedNotice value={collection?.truncated ?? false} />
      <InspectionPanel status={state.inspectionStatus} inspection={state.inspection} />
    </>
  );
}

function ComposeView({ status, collection, onRefresh }: {
  status: DockerReadStatus;
  collection: Extract<DockerReadCollection, { kind: "compose-projects" }> | null;
  onRefresh(): void;
}) {
  return (
    <>
      <ViewHeader title="Compose 项目盘点" status={status} onRefresh={onRefresh} />
      {status === "loading" && collection === null ? <StatusPanel label="正在读取 Compose 项目…" /> :
        collection === null || collection.items.length === 0 ? <EmptyPanel title="没有 Compose 项目" detail="没有返回可展示的项目记录。" /> : (
          <div className="docker-card-grid">
            {collection.items.map((item, index) => (
              <article className="docker-card" key={`${item.name}\0${index}`}>
                <h3>{item.name || "（未命名）"}</h3><p>{item.status || "—"}</p>
                <dl><dt>服务</dt><dd>{item.services}</dd><dt>运行中</dt><dd>{item.running}</dd><dt>已停止</dt><dd>{item.stopped}</dd><dt>配置来源</dt><dd>{item.configFiles || "—"}</dd></dl>
              </article>
            ))}
          </div>
        )}
      <TruncatedNotice value={collection?.truncated ?? false} />
    </>
  );
}

export function DockerSecurityView({ status, audit, onRefresh }: {
  status: DockerReadStatus;
  audit: DockerSecurityAudit | null;
  onRefresh(): void;
}) {
  return (
    <>
      <ViewHeader title="只读安全审计" status={status} onRefresh={onRefresh} />
      {status === "loading" && audit === null ? <StatusPanel label="正在运行 Docker 安全调查…" /> :
        audit === null ? <EmptyPanel title="安全审计尚不可用" detail="刷新当前资源以重新调查。" /> : (
          <>
            <div className="docker-security-summary">
              <article><strong>{audit.summary.score}</strong><span>安全得分</span></article>
              <article><strong>{audit.containersScanned}</strong><span>扫描容器</span></article>
              <article><strong>{audit.summary.critical}</strong><span>严重</span></article>
              <article><strong>{audit.summary.high}</strong><span>高风险</span></article>
              <article><strong>{audit.summary.total}</strong><span>全部发现</span></article>
            </div>
            {audit.findings.length === 0 ? <EmptyPanel title="没有返回安全发现" detail="这不代表未执行的检查已通过。" /> : (
              <div className="docker-findings">
                {audit.findings.map((finding, index) => (
                  <article className={`docker-finding severity-${finding.severity}`} key={`${finding.containerName}\0${finding.category}\0${index}`}>
                    <header><span>{dockerSecuritySeverityLabel(finding.severity)}</span><strong>{finding.categoryLabel}</strong><small>{finding.containerName || "（未命名容器）"}</small></header>
                    <p>{finding.description}</p><p className="docker-recommendation">建议：{finding.recommendation || "未提供"}</p>
                    {finding.textTruncated && <small>该发现文本已按敏感信息与 UTF-8 字节安全边界处理。</small>}
                  </article>
                ))}
              </div>
            )}
            <TruncatedNotice value={audit.truncated} />
          </>
        )}
    </>
  );
}

function ViewHeader({ title, status, onRefresh }: { title: string; status: DockerReadStatus; onRefresh(): void }) {
  return (
    <div className="docker-view-header">
      <div><h2>{title}</h2><p>{status === "loading" ? "正在刷新当前资源…" : "数据严格绑定到当前短期快照。"}</p></div>
      <button type="button" disabled={status === "loading"} onClick={onRefresh}>{status === "loading" ? "刷新中…" : "刷新当前资源"}</button>
    </div>
  );
}

function InspectionPanel({ status, inspection }: { status: DockerReadStatus; inspection: DockerReadInspection | null }) {
  if (status === "idle") return null;
  if (status === "loading") return <StatusPanel label="正在读取所选资源详情…" />;
  if (status === "error" || inspection === null) return <EmptyPanel title="资源详情不可用" detail="选择其他资源或刷新清单。" />;
  if (inspection.kind === "container") return <ContainerInspectionView inspection={inspection} />;
  if (inspection.kind === "network") return <NetworkInspectionView inspection={inspection} />;
  return <VolumeInspectionView inspection={inspection} />;
}

function ContainerInspectionView({ inspection }: { inspection: DockerContainerInspection }) {
  return (
    <section className="docker-card docker-inspection">
      <h3>容器详情 · {inspection.name || "（未命名）"}</h3>
      <MetadataList items={inspection.fields.map((item) => ({ key: item.label, value: item.value }))} empty="没有详情字段。" />
      <h4>挂载</h4>
      {inspection.mounts.length === 0 ? <p className="docker-muted">没有挂载记录。</p> : inspection.mounts.map((mount, index) => (
        <p className="docker-plain-row" key={index}>{mount.kind || "—"} · {mount.source || "—"} → {mount.destination || "—"} · {mount.readWrite ? "可写" : "只读"} · {mount.mode || "—"}</p>
      ))}
      <h4>网络连接</h4>
      {inspection.networks.length === 0 ? <p className="docker-muted">没有网络连接记录。</p> : inspection.networks.map((network, index) => (
        <p className="docker-plain-row" key={index}>{network.name || "—"} · {network.ipv4Address || network.ipv6Address || "无地址"} · {network.macAddress || "无 MAC"}</p>
      ))}
      <TruncatedNotice value={inspection.truncated} />
    </section>
  );
}

function NetworkInspectionView({ inspection }: { inspection: DockerNetworkInspection }) {
  return (
    <section className="docker-card docker-inspection">
      <h3>网络详情 · {inspection.name || "（未命名）"}</h3>
      <dl className="docker-detail-grid"><dt>驱动</dt><dd>{inspection.driver || "—"}</dd><dt>范围</dt><dd>{inspection.scope || "—"}</dd><dt>内部网络</dt><dd>{dockerBooleanLabel(inspection.internal)}</dd><dt>IPv6</dt><dd>{dockerBooleanLabel(inspection.ipv6)}</dd><dt>可附加</dt><dd>{dockerBooleanLabel(inspection.attachable)}</dd><dt>Ingress</dt><dd>{dockerBooleanLabel(inspection.ingress)}</dd><dt>IPAM 驱动</dt><dd>{inspection.ipamDriver || "—"}</dd></dl>
      <h4>IPAM</h4>{inspection.ipam.length === 0 ? <p className="docker-muted">没有 IPAM 记录。</p> : inspection.ipam.map((item, index) => <p className="docker-plain-row" key={index}>{item.subnet || "—"} · 网关 {item.gateway || "—"} · 范围 {item.ipRange || "—"}</p>)}
      <h4>连接容器</h4>{inspection.attachments.length === 0 ? <p className="docker-muted">没有连接记录。</p> : inspection.attachments.map((item, index) => <p className="docker-plain-row" key={index}>{item.name || "—"} · {item.ipv4Address || item.ipv6Address || "无地址"}</p>)}
      <h4>选项</h4><MetadataList items={inspection.options} empty="没有选项。" />
      <h4>标签</h4><MetadataList items={inspection.labels} empty="没有标签。" />
      <TruncatedNotice value={inspection.truncated} />
    </section>
  );
}

function VolumeInspectionView({ inspection }: { inspection: DockerVolumeInspection }) {
  return (
    <section className="docker-card docker-inspection">
      <h3>存储卷详情 · {inspection.name || "（未命名）"}</h3>
      <dl className="docker-detail-grid"><dt>驱动</dt><dd>{inspection.driver || "—"}</dd><dt>范围</dt><dd>{inspection.scope || "—"}</dd><dt>挂载点</dt><dd>{inspection.mountpoint || "—"}</dd><dt>创建时间</dt><dd>{inspection.createdAt || "—"}</dd></dl>
      <h4>选项</h4><MetadataList items={inspection.options} empty="没有选项。" />
      <h4>标签</h4><MetadataList items={inspection.labels} empty="没有标签。" />
      <TruncatedNotice value={inspection.truncated} />
    </section>
  );
}

function MetadataList({ items, empty }: { items: ReadonlyArray<{ key: string; value: string }>; empty: string }) {
  if (items.length === 0) return <p className="docker-muted">{empty}</p>;
  return <dl className="docker-metadata">{items.map((item, index) => <div key={`${item.key}\0${index}`}><dt>{item.key || "—"}</dt><dd>{item.value || "—"}</dd></div>)}</dl>;
}

export function DockerLogsText({ logs }: { logs: DockerLogs }) {
  return (
    <>
      {logs.text.length === 0 ? <p className="docker-muted">日志为空。</p> : <pre className="docker-log-text">{logs.text}</pre>}
      <TruncatedNotice value={logs.truncated} />
    </>
  );
}

function StatusPanel({ label }: { label: string }) {
  return <div className="docker-status-panel" aria-live="polite"><span aria-hidden="true" />{label}</div>;
}

function EmptyPanel({ title, detail }: { title: string; detail: string }) {
  return <div className="docker-empty"><strong>{title}</strong><p>{detail}</p></div>;
}

function TruncatedNotice({ value }: { value: boolean }) {
  return value
    ? <p className="docker-truncated" role="status">结果已按敏感信息与 UTF-8 字节安全边界处理。</p>
    : null;
}
