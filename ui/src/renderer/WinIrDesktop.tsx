import { useEffect, useRef, useState } from "react";
import { RDP_RESOLUTION_LIMITS, isWindowsRdpResolution, type WindowsRdpBounds, type WindowsRdpRequest, type WindowsRdpResolution, type WindowsRdpStatus } from "../shared/windows-rdp-contract";

const PRESETS: ReadonlyArray<WindowsRdpResolution> = [
  { width: 1280, height: 720 }, { width: 1366, height: 768 }, { width: 1600, height: 900 },
  { width: 1920, height: 1080 }, { width: 2560, height: 1440 },
];

/** The chosen size: "fit" follows the viewport, a preset or a custom width × height stays fixed. */
function chosenResolution(mode: string, width: string, height: string): WindowsRdpResolution | null | "invalid" {
  if (mode === "fit") return null;
  const [w, h] = mode === "custom" ? [Number(width), Number(height)] : mode.split("x").map(Number);
  const size = { width: w ?? NaN, height: h ?? NaN };
  return isWindowsRdpResolution(size) ? size : "invalid";
}

export function WinIrDesktop({ api, covered }: { api: ((request: WindowsRdpRequest) => Promise<WindowsRdpStatus>) | undefined; covered: boolean }) {
  const [server, setServer] = useState("");
  const [clipboard, setClipboard] = useState(false);
  const [mode, setMode] = useState("fit");
  const [customWidth, setCustomWidth] = useState("1920");
  const [customHeight, setCustomHeight] = useState("1080");
  const resolution = chosenResolution(mode, customWidth, customHeight);
  const [status, setStatus] = useState<WindowsRdpStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const viewport = useRef<HTMLDivElement>(null);
  const current = useRef<WindowsRdpStatus | null>(null);
  const mounted = useRef(false);
  const operation = useRef(0);
  const placementFailed = useRef(false);
  const obscured = useRef(covered); obscured.current = covered;
  function bounds(): WindowsRdpBounds | null {
    const rect = viewport.current?.getBoundingClientRect();
    if (!rect || rect.width < 160 || rect.height < 120 || rect.top < 40 || rect.bottom > window.innerHeight || rect.left < 0 || rect.right > window.innerWidth) return null;
    return { x: rect.left, y: rect.top, width: rect.width, height: rect.height };
  }
  useEffect(() => {
    if (!api) return;
    mounted.current = true;
    let disposed = false;
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      try {
        const version = operation.current;
        const next = await api!({ action: "status" });
        if (version !== operation.current) { if (!disposed) timer = setTimeout(() => void poll(), 750); return; }
        current.current = next;
        if (next.clientId && !disposed) await placeNow(next.clientId);
        if (!disposed) { setStatus(next); if (next.clientId) setServer(next.server); }
      } catch (reason) { if (!disposed) setError(reason instanceof Error ? reason.message : "远程桌面状态读取失败。"); }
      if (!disposed) timer = setTimeout(() => void poll(), 750);
    }
    // A resized window or panel moves the session at once instead of on the next poll.
    let frame = 0;
    const follow = () => { cancelAnimationFrame(frame); frame = requestAnimationFrame(() => { const id = current.current?.clientId; if (id && !disposed) void placeNow(id); }); };
    const observer = new ResizeObserver(follow);
    if (viewport.current) observer.observe(viewport.current);
    window.addEventListener("resize", follow);
    void poll();
    return () => {
      disposed = true; mounted.current = false; clearTimeout(timer); cancelAnimationFrame(frame); observer.disconnect(); window.removeEventListener("resize", follow);
      const id = current.current?.clientId; if (id) void api({ action: "hide", clientId: id }).catch(() => undefined);
    };
    // placeNow reads only refs and the api.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [api]);
  /** Places or hides the session; a placement error clears itself once placing works again. */
  async function placeNow(clientId: string) {
    if (!api) return;
    const area = bounds();
    try {
      if (!obscured.current && area) await api({ action: "place", clientId, bounds: area });
      else await api({ action: "hide", clientId });
      if (placementFailed.current && mounted.current) { placementFailed.current = false; setError(""); }
    } catch (reason) {
      placementFailed.current = true;
      if (mounted.current) setError(reason instanceof Error ? reason.message : "远程桌面画面布局失败。");
    }
  }
  useEffect(() => { const id = current.current?.clientId; if (covered && id && api) void api({ action: "hide", clientId: id }).catch(() => undefined); }, [covered, api]);
  async function connect() {
    if (!api || busy) return;
    if (resolution === "invalid") { setError(`分辨率无效：宽度需为 ${RDP_RESOLUTION_LIMITS.minWidth}–${RDP_RESOLUTION_LIMITS.max} 之间的偶数，高度为 ${RDP_RESOLUTION_LIMITS.minHeight}–${RDP_RESOLUTION_LIMITS.max}。`); return; }
    const area = bounds();
    if (!area) { setError("当前显示区域不足，请放大窗口或收起上方提示后重试。"); return; }
    operation.current++; setBusy(true); setError("");
    try {
      const next = await api({ action: "start", server: server.trim(), clipboard, bounds: area, resolution }); current.current = next;
      if (mounted.current) setStatus(next);
      if ((!mounted.current || obscured.current) && next.clientId) await api({ action: "hide", clientId: next.clientId });
    } catch (reason) { if (mounted.current) setError(reason instanceof Error ? reason.message : "远程桌面启动失败。"); }
    finally { if (mounted.current) setBusy(false); }
  }
  async function disconnect() {
    const id = current.current?.clientId; if (!id || !api || busy) return;
    operation.current++; setBusy(true); setError("");
    try { const next = await api({ action: "disconnect", clientId: id }); current.current = next; if (mounted.current) setStatus(next); }
    catch (reason) { if (mounted.current) setError(reason instanceof Error ? reason.message : "断开请求未完成。"); }
    finally { if (mounted.current) setBusy(false); }
  }
  return <section className="wir-desktop" aria-label="内嵌远程桌面">
    <header><h1>远程桌面</h1><span>在工作台内查看与操作 Windows 会话</span></header>
    <form className="wir-toolbar" onSubmit={(event) => { event.preventDefault(); void connect(); }}>
      <input className="win-ir-input" aria-label="远程桌面地址" value={server} onChange={(event) => setServer(event.target.value)} placeholder="主机名或 IP，可附 :端口" maxLength={253} disabled={Boolean(status?.clientId) || busy} />
      <select className="win-ir-input wir-select" aria-label="远程桌面分辨率" value={mode} disabled={Boolean(status?.clientId) || busy} onChange={(event) => setMode(event.target.value)}>
        <option value="fit">适应显示区域</option>
        {PRESETS.map((size) => <option key={`${size.width}x${size.height}`} value={`${size.width}x${size.height}`}>{size.width} × {size.height}</option>)}
        <option value="custom">自定义…</option>
      </select>
      {mode === "custom" ? <span className="wir-rdp-size">
        <input className="win-ir-input" type="number" inputMode="numeric" aria-label="自定义宽度" min={RDP_RESOLUTION_LIMITS.minWidth} max={RDP_RESOLUTION_LIMITS.max} step={2} value={customWidth} disabled={Boolean(status?.clientId) || busy} onChange={(event) => setCustomWidth(event.target.value)} />
        <span aria-hidden="true">×</span>
        <input className="win-ir-input" type="number" inputMode="numeric" aria-label="自定义高度" min={RDP_RESOLUTION_LIMITS.minHeight} max={RDP_RESOLUTION_LIMITS.max} value={customHeight} disabled={Boolean(status?.clientId) || busy} onChange={(event) => setCustomHeight(event.target.value)} />
      </span> : null}
      <label><input type="checkbox" checked={clipboard} onChange={(event) => setClipboard(event.target.checked)} disabled={Boolean(status?.clientId) || busy} />允许剪贴板</label>
      <button type="submit" className="win-ir-btn is-primary" disabled={!api || busy || !server.trim() || Boolean(status?.clientId)}>{busy ? "正在处理…" : "连接"}</button>
      <button type="button" className="win-ir-btn" disabled={!status?.clientId || busy} onClick={() => void disconnect()}>断开远程桌面</button>
    </form>
    {error ? <p className="wir-preview-error" role="alert">{error}</p> : null}
    {mode === "custom" && resolution === "invalid" ? <p className="wir-preview-error" role="status">宽度需为 {RDP_RESOLUTION_LIMITS.minWidth}–{RDP_RESOLUTION_LIMITS.max} 之间的偶数，高度为 {RDP_RESOLUTION_LIMITS.minHeight}–{RDP_RESOLUTION_LIMITS.max}。</p> : null}
    {!status?.clientId ? <p className="wir-footnote">{mode === "fit" ? "按当前显示区域的实际像素启动会话；目标支持动态分辨率时，窗口大小变化后远程分辨率随之调整。" : "固定远程分辨率：比显示区域大时按比例缩小显示，比显示区域小时居中显示。连接后如需更改，请断开后重新连接。"}</p> : null}
    <p className="wir-footnote">{status?.clientId ? `${status.server} · ${status.message}` : "密码与证书确认由系统客户端处理。目标使用自签名证书时会弹出证书警告，请先点「查看证书」核对名称与指纹，确认是要排查的主机再继续。连接后鼠标、键盘直接操作远程桌面；Ctrl+Alt+End 打开远程安全选项。"}</p>
    <div className="wir-rdp-viewport" ref={viewport}><div className="wir-empty">{!api ? "当前宿主不支持内嵌远程桌面。" : status?.clientId ? "等待系统远程桌面画面…" : "输入目标地址后连接；不自动开放目标端口或修改目标配置。"}</div></div>
    <p className="wir-footnote">切换模块保留会话；断开或关闭软件会关闭本次客户端，不注销远端登录。采集端仍需在远程会话中启动。</p>
  </section>;
}
