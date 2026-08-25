import { useEffect, useReducer, useRef, useState } from "react";

import {
  isPacketCaptureInterfaceList,
  isPacketCapturePoll,
  isPacketCaptureStartInput,
  isPacketCaptureStarted,
  isPacketCaptureStopped,
  type PacketCaptureLiveApi,
} from "../shared/packet-capture-live-contract";
import {
  filterPacketCapturePackets,
  formatPacketCaptureBytes,
  packetCaptureInterfaceLabel,
  packetCaptureProtocolSummary,
  packetCaptureScope,
  packetCaptureStartInput,
} from "./packet-capture-live-helpers";
import {
  createPacketCaptureLiveState,
  packetCaptureLiveReducer,
  type PacketCaptureLiveState,
} from "./packet-capture-live-state";
import "./packet-capture-page.css";

interface PacketCapturePageProps {
  bindingHandle: string | null;
  api: PacketCaptureLiveApi;
  active?: boolean;
  /** Deterministic standalone/SSR fixture; production leaves this unset. */
  initialState?: PacketCaptureLiveState;
}

interface CaptureOwner {
  scope: string;
  bindingHandle: string;
  captureHandle: string;
}

export function PacketCapturePage({
  bindingHandle,
  api,
  active = true,
  initialState,
}: PacketCapturePageProps) {
  const [state, dispatch] = useReducer(
    packetCaptureLiveReducer,
    initialState ?? createPacketCaptureLiveState(),
  );
  const [refreshVersion, setRefreshVersion] = useState(0);
  const requestRef = useRef(0);
  const ownerRef = useRef<CaptureOwner | null>(null);
  const startPendingRef = useRef(false);
  const mountedRef = useRef(true);
  const apiRef = useRef(api);
  const scope = bindingHandle === null ? null : packetCaptureScope(bindingHandle);
  const enabled = active && bindingHandle !== null;
  const visibleState = state.scope === scope ? state : createPacketCaptureLiveState(scope);
  const activeRef = useRef(enabled);
  const scopeRef = useRef(scope);
  activeRef.current = enabled;
  scopeRef.current = scope;
  apiRef.current = api;

  useEffect(() => {
    const owner = ownerRef.current;
    if (owner !== null && owner.scope !== scope) {
      ownerRef.current = null;
      void stopOwner(api, owner);
    }
    dispatch({ type: "scope-changed", scope });
  }, [api, scope]);

  useEffect(() => {
    if (enabled) return;
    const owner = ownerRef.current;
    if (owner !== null) {
      ownerRef.current = null;
      void stopOwner(api, owner);
    }
    dispatch({ type: "deactivated", scope });
  }, [api, enabled, scope]);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      activeRef.current = false;
      const owner = ownerRef.current;
      ownerRef.current = null;
      if (owner !== null) void stopOwner(apiRef.current, owner);
    };
  }, []);

  useEffect(() => {
    if (!enabled || scope === null || bindingHandle === null ||
      visibleState.captureHandle !== null || visibleState.captureStatus === "starting") return;
    const request = ++requestRef.current;
    let cancelled = false;
    dispatch({ type: "interfaces-started", scope, request });
    void api.listPacketCaptureInterfaces(bindingHandle).then((result) => {
      if (!isPacketCaptureInterfaceList(result)) throw new Error();
      if (cancelled || scopeRef.current !== scope || !activeRef.current) return;
      dispatch({ type: "interfaces-loaded", scope, request, interfaces: result });
    }).catch(() => {
      if (cancelled || scopeRef.current !== scope || !activeRef.current) return;
      dispatch({
        type: "interfaces-failed",
        scope,
        request,
        error: "无法读取网卡列表：SSH 目标可能已断开或切换。",
      });
    });
    return () => {
      cancelled = true;
    };
  }, [
    api,
    bindingHandle,
    enabled,
    refreshVersion,
    scope,
    visibleState.captureHandle,
    visibleState.captureStatus,
  ]);

  useEffect(() => {
    if (!enabled || scope === null || bindingHandle === null ||
      visibleState.captureStatus !== "running" || visibleState.captureHandle === null) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const captureHandle = visibleState.captureHandle;
    const afterSequence = visibleState.afterSequence;
    const pollScope = scope;
    const pollBindingHandle = bindingHandle;

    async function poll() {
      if (cancelled) return;
      const request = ++requestRef.current;
      dispatch({
        type: "poll-started",
        scope: pollScope,
        request,
        captureHandle,
        afterSequence,
      });
      try {
        const result = await api.pollPacketCapture(
          pollBindingHandle,
          captureHandle,
          afterSequence,
        );
        if (!isPacketCapturePoll(result) || result.captureHandle !== captureHandle) throw new Error();
        if (cancelled || scopeRef.current !== pollScope || !activeRef.current) return;
        dispatch({
          type: "poll-loaded",
          scope: pollScope,
          request,
          captureHandle,
          afterSequence,
          result,
        });
        if (result.status !== "running") {
          const owner = ownerRef.current;
          if (owner !== null && owner.captureHandle === captureHandle) {
            ownerRef.current = null;
            const stopped = await stopOwner(api, owner);
            if (!cancelled) dispatch({
              type: "capture-released",
              scope: pollScope,
              captureHandle,
              failed: result.status === "failed" || !stopped,
            });
          }
          return;
        }
        const lastSequence = result.events.at(-1)?.sequence ?? afterSequence;
        if (lastSequence === afterSequence) {
          timer = setTimeout(() => void poll(), result.hasMore ? 0 : 250);
        }
      } catch {
        if (cancelled) return;
        dispatch({
          type: "poll-failed",
          scope: pollScope,
          request,
          captureHandle,
          error: "抓包事件不可用，或目标已切换。",
        });
        const owner = ownerRef.current;
        if (owner !== null && owner.captureHandle === captureHandle) {
          ownerRef.current = null;
          await stopOwner(api, owner);
          if (!cancelled) dispatch({
            type: "capture-released",
            scope: pollScope,
            captureHandle,
            failed: true,
          });
        }
      }
    }

    void poll();
    return () => {
      cancelled = true;
      if (timer !== null) clearTimeout(timer);
    };
  }, [
    api,
    bindingHandle,
    enabled,
    scope,
    visibleState.afterSequence,
    visibleState.captureHandle,
    visibleState.captureStatus,
  ]);

  if (bindingHandle === null) {
    return (
      <section className="page packet-capture-page">
        <div className="packet-capture-connect-state">
          <span aria-hidden="true">⌁</span>
          <h1>连接目标后开始受控网络抓包</h1>
          <p>实时抓包只在当前 SSH 目标上进行，不提供任意命令或文件操作。</p>
        </div>
      </section>
    );
  }

  if (!active) {
    return (
      <section className="page packet-capture-page">
        <div className="packet-capture-connect-state">
          <span aria-hidden="true">Ⅱ</span>
          <h1>网络抓包页面已停用</h1>
          <p>页面失活会请求停止并释放 live capture；重新激活后需重新选择目标绑定的网卡。</p>
        </div>
      </section>
    );
  }

  const connectedScope = scope ?? "";
  const input = packetCaptureStartInput(visibleState.form);
  const parametersValid = input !== null && isPacketCaptureStartInput(input);
  const selectedInterface = visibleState.interfaces?.interfaces.find(
    (item) => item.interfaceHandle === visibleState.selectedInterfaceHandle,
  ) ?? null;
  const busy = visibleState.captureStatus === "starting" ||
    visibleState.captureStatus === "running" || visibleState.captureStatus === "stopping" ||
    visibleState.captureHandle !== null;
  const shownPackets = filterPacketCapturePackets(visibleState.packets, visibleState.search);
  const selectedPacket = visibleState.packets.find(
    (packet) => packet.sequence === visibleState.selectedPacketSequence,
  ) ?? null;
  const protocols = packetCaptureProtocolSummary(visibleState.packets);

  async function startCapture() {
    if (!enabled || scope === null || bindingHandle === null || selectedInterface === null ||
      input === null || !isPacketCaptureStartInput(input) || busy || startPendingRef.current) return;
    startPendingRef.current = true;
    const request = ++requestRef.current;
    dispatch({
      type: "start-started",
      scope,
      request,
      interfaceHandle: selectedInterface.interfaceHandle,
    });
    try {
      const result = await api.startPacketCapture(
        bindingHandle,
        selectedInterface.interfaceHandle,
        input,
      );
      if (!isPacketCaptureStarted(result)) throw new Error();
      if (!mountedRef.current || !activeRef.current || scopeRef.current !== scope ||
        requestRef.current !== request) {
        await stopOwner(api, { scope, bindingHandle, captureHandle: result.captureHandle });
        return;
      }
      if (ownerRef.current !== null) {
        await stopOwner(api, { scope, bindingHandle, captureHandle: result.captureHandle });
        throw new Error();
      }
      ownerRef.current = { scope, bindingHandle, captureHandle: result.captureHandle };
      dispatch({
        type: "start-loaded",
        scope,
        request,
        interfaceHandle: selectedInterface.interfaceHandle,
        capture: result,
      });
    } catch {
      dispatch({
        type: "start-failed",
        scope,
        request,
        error: "无法启动抓包：目标可能缺少 tcpdump，或没有 root/sudo 权限。",
      });
    } finally {
      startPendingRef.current = false;
    }
  }

  async function stopCapture() {
    const owner = ownerRef.current;
    if (owner === null || owner.scope !== scope) return;
    const request = ++requestRef.current;
    dispatch({
      type: "stop-started",
      scope: connectedScope,
      request,
      captureHandle: owner.captureHandle,
    });
    ownerRef.current = null;
    const stopped = await stopOwner(api, owner);
    dispatch({
      type: "capture-released",
      scope: connectedScope,
      captureHandle: owner.captureHandle,
      failed: !stopped,
    });
  }

  return (
    <section className="page packet-capture-page">
      <header className="page-heading packet-capture-heading">
        <div>
          <p className="eyebrow">只读</p>
          <h1>网络抓包</h1>
          <p>远端 tcpdump live stream，离开页面或切换绑定立即停止。</p>
        </div>
        <span className={`packet-capture-status ${visibleState.captureStatus}`}>
          {captureStatusLabel(visibleState.captureStatus)}
        </span>
      </header>

      {visibleState.notice !== null ? (
        <div className="packet-capture-notice" role="status">
          <span>{visibleState.notice}</span>
          <button type="button" onClick={() => dispatch({ type: "notice-cleared" })}>关闭</button>
        </div>
      ) : null}
      {visibleState.error !== null ? (
        <div className="packet-capture-notice error" role="alert">{visibleState.error}</div>
      ) : null}

      <section className="packet-capture-controls" aria-labelledby="packet-capture-controls-title">
        <header>
          <div>
            <p>网卡</p>
            <h2 id="packet-capture-controls-title">抓包参数</h2>
          </div>
          <button
            type="button"
            disabled={busy || visibleState.interfacesStatus === "loading"}
            onClick={() => setRefreshVersion((version) => version + 1)}
          >
            {visibleState.interfacesStatus === "loading" ? "刷新中…" : "刷新网卡"}
          </button>
        </header>

        {visibleState.interfacesStatus === "loading" ||
        visibleState.interfacesStatus === "idle" ? (
          <div className="packet-capture-inline-state" role="status">正在读取目标网卡…</div>
        ) : null}
        {visibleState.interfacesStatus === "ready" &&
        visibleState.interfaces?.interfaces.length === 0 ? (
          <div className="packet-capture-inline-state">当前目标没有可用网卡。</div>
        ) : null}
        <div className="packet-capture-interface-list" aria-label="目标网卡">
          {visibleState.interfaces?.interfaces.map((item) => (
            <button
              type="button"
              key={item.interfaceHandle}
              className={item.interfaceHandle === visibleState.selectedInterfaceHandle
                ? "active"
                : undefined}
              aria-pressed={item.interfaceHandle === visibleState.selectedInterfaceHandle}
              disabled={busy}
              onClick={() => dispatch({
                type: "interface-selected",
                scope: connectedScope,
                handle: item.interfaceHandle,
              })}
            >
              {packetCaptureInterfaceLabel(item)}
              {item.textTruncated ? <em>字段已截断</em> : null}
            </button>
          ))}
        </div>

        <div className="packet-capture-form">
          <label>
            <span>BPF filter（可选）</span>
            <input
              type="text"
              value={visibleState.form.filter}
              disabled={busy}
              maxLength={2_048}
              placeholder="例如 tcp port 443"
              onChange={(event) => dispatch({
                type: "filter-changed",
                value: event.currentTarget.value,
              })}
            />
          </label>
          <label>
            <span>数据包上限</span>
            <input
              type="number"
              min="1"
              max="100000"
              inputMode="numeric"
              value={visibleState.form.packetLimit}
              disabled={busy}
              onChange={(event) => dispatch({
                type: "packet-limit-changed",
                value: event.currentTarget.value,
              })}
            />
          </label>
          <label>
            <span>持续秒数</span>
            <input
              type="number"
              min="1"
              max="300"
              inputMode="numeric"
              value={visibleState.form.durationSeconds}
              disabled={busy}
              onChange={(event) => dispatch({
                type: "duration-changed",
                value: event.currentTarget.value,
              })}
            />
          </label>
          <div className="packet-capture-actions">
            <button
              type="button"
              className="primary"
              disabled={busy || selectedInterface === null || !parametersValid}
              onClick={() => void startCapture()}
            >
              {visibleState.captureStatus === "starting" ? "启动中…" : "开始抓包"}
            </button>
            <button
              type="button"
              className="danger"
              disabled={visibleState.captureHandle === null ||
                visibleState.captureStatus === "stopping"}
              onClick={() => void stopCapture()}
            >
              {visibleState.captureStatus === "stopping" ? "停止中…" : "停止抓包"}
            </button>
          </div>
        </div>
        {!parametersValid ? (
          <p className="packet-capture-validation">
            请输入 1–100000 个包、1–300 秒；filter 最多 2048 UTF-8 字节且不能含换行或 NUL。
          </p>
        ) : null}
      </section>

      <section className="packet-capture-metrics" aria-label="实时抓包摘要">
        <div><span>累计数据包</span><strong>{visibleState.totalPackets}</strong></div>
        <div><span>估算流量</span><strong>{formatPacketCaptureBytes(visibleState.totalBytes)}</strong></div>
        <div><span>缓冲</span><strong>{visibleState.packets.length} / 400</strong></div>
        <div><span>丢弃事件</span><strong>{visibleState.droppedEvents}</strong></div>
      </section>

      <section className="packet-capture-protocols" aria-label="当前缓冲协议汇总">
        <span>协议汇总</span>
        {protocols.length === 0 ? <em>等待数据</em> : protocols.map((item) => (
          <span key={item.protocol}><strong>{item.protocol}</strong>{item.count}</span>
        ))}
      </section>

      {visibleState.info !== null ? (
        <div className="packet-capture-info" role="status">{visibleState.info}</div>
      ) : null}
      {visibleState.truncated ? (
        <div className="packet-capture-truncated" role="status">
          缓冲已达上限，较早的事件可能已丢弃。
        </div>
      ) : null}

      <div className="packet-capture-workbench">
        <section className="packet-capture-table-panel" aria-labelledby="packet-capture-table-title">
          <header>
            <div><p>实时缓冲</p><h2 id="packet-capture-table-title">实时数据包</h2></div>
            <label className="packet-capture-search">
              <span>搜索当前缓冲</span>
              <input
                type="search"
                value={visibleState.search}
                maxLength={256}
                placeholder="协议、源、目标或摘要"
                onChange={(event) => dispatch({
                  type: "search-changed",
                  value: event.currentTarget.value,
                })}
              />
            </label>
          </header>
          {shownPackets.length === 0 ? (
            <div className="packet-capture-empty">
              {visibleState.packets.length === 0
                ? visibleState.captureStatus === "running"
                  ? "等待远端数据…"
                  : "开始抓包后，数据将在这里实时显示。"
                : "当前缓冲没有匹配搜索条件的数据包。"}
            </div>
          ) : (
            <div className="packet-capture-table" role="table" aria-label="实时网络数据包">
              <div className="packet-capture-table-head" role="row">
                <span role="columnheader">Seq</span>
                <span role="columnheader">时间</span>
                <span role="columnheader">协议</span>
                <span role="columnheader">源</span>
                <span role="columnheader">目标</span>
                <span role="columnheader">长度</span>
                <span role="columnheader">摘要</span>
              </div>
              {shownPackets.map((packet) => (
                <button
                  type="button"
                  role="row"
                  key={packet.sequence}
                  className={packet.sequence === visibleState.selectedPacketSequence
                    ? "active"
                    : undefined}
                  aria-pressed={packet.sequence === visibleState.selectedPacketSequence}
                  onClick={() => dispatch({ type: "packet-selected", sequence: packet.sequence })}
                >
                  <span role="cell">{packet.sequence}</span>
                  <span role="cell">{packet.timestamp || packet.observedAt}</span>
                  <span role="cell" className="protocol">{packet.protocol}</span>
                  <span role="cell">{packet.source || "—"}</span>
                  <span role="cell">{packet.destination || "—"}</span>
                  <span role="cell">{packet.length || "—"}</span>
                  <span role="cell">{packet.info}</span>
                </button>
              ))}
            </div>
          )}
        </section>

        <aside className="packet-capture-detail" aria-label="数据包纯文本详情">
          <header><p>数据包详情</p><h2>数据包详情</h2></header>
          {selectedPacket === null ? (
            <div className="packet-capture-empty">选择缓冲中的数据包查看详情。</div>
          ) : (
            <div className="packet-capture-detail-content">
              <dl>
                <div><dt>Sequence</dt><dd>{selectedPacket.sequence}</dd></div>
                <div><dt>时间</dt><dd>{selectedPacket.timestamp || selectedPacket.observedAt}</dd></div>
                <div><dt>协议</dt><dd>{selectedPacket.protocol}</dd></div>
                <div><dt>源</dt><dd>{selectedPacket.source || "—"}</dd></div>
                <div><dt>目标</dt><dd>{selectedPacket.destination || "—"}</dd></div>
                <div><dt>长度</dt><dd>{selectedPacket.length || "—"}</dd></div>
              </dl>
              <p>摘要</p>
              <pre>{selectedPacket.info}</pre>
              <p>原始行</p>
              <pre>{selectedPacket.raw}</pre>
              {selectedPacket.textTruncated ? <span>字段已截断。</span> : null}
            </div>
          )}
        </aside>
      </div>

      <footer className="packet-capture-boundary-note">
        本页不创建或读取 PCAP 文件，也不提供下载、导出或终端入口。
      </footer>
    </section>
  );
}

async function stopOwner(api: PacketCaptureLiveApi, owner: CaptureOwner): Promise<boolean> {
  try {
    const result = await api.stopPacketCapture(owner.bindingHandle, owner.captureHandle);
    return isPacketCaptureStopped(result);
  } catch {
    return false;
  }
}

function captureStatusLabel(status: PacketCaptureLiveState["captureStatus"]): string {
  switch (status) {
    case "idle": return "○ 尚未开始";
    case "starting": return "◌ 正在启动";
    case "running": return "● 正在采集";
    case "stopping": return "◌ 正在停止";
    case "stopped": return "○ 已停止";
    case "failed": return "× 已失败";
  }
}
