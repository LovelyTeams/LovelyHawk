import { useEffect, useRef, useState } from "react";
import type { WindowsFileAccess } from "../shared/windows-incident-contract";
import { errorText } from "./error-text";

export function WinIrFileAccessPanel({ path, busy, connected, onInspect, onCopy, onCommands }: {
  path: string; busy: boolean; connected: boolean; onInspect: (path: string) => Promise<WindowsFileAccess>; onCopy: (text: string) => void; onCommands: () => void;
}) {
  const [result, setResult] = useState<WindowsFileAccess | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const live = useRef(true);
  useEffect(() => { live.current = true; return () => { live.current = false; }; }, []);
  async function inspect() {
    if (busy || loading || !connected) return;
    setLoading(true); setError(null);
    try { const value = await onInspect(path); if (live.current) setResult(value); }
    catch (reason) { if (live.current) setError(errorText(reason, "诊断未完成；请核对权限和连接后重试。")); }
    finally { if (live.current) setLoading(false); }
  }
  return <div className="wir-access-guide"><div className="wir-toolbar"><button type="button" className="win-ir-btn is-primary" disabled={busy || loading || !connected} onClick={() => void inspect()}>{loading ? "正在读取权限与服务关联…" : "诊断文件访问与驱动关联"}</button><button type="button" className="win-ir-btn" onClick={onCommands}>打开服务 / 驱动命令预设</button></div>
    <p>只读查询文件属性、访问规则及相同路径的进程、服务、驱动。不会提权、夺取所有权或强制卸载。</p>
    {error ? <p role="alert" className="wir-reader-warning">{error}</p> : null}
    {result ? <><p>观察时间：{result.observedAt} · 属主：{result.owner || "未取得"} · 属性：{result.attributes || "未取得"}</p>
      {result.warnings.map((warning) => <p key={warning} className="wir-reader-warning">{warning}</p>)}
      <p>相同程序路径的进程：{result.processes.length ? result.processes.map((process) => `${process.name} (PID ${process.pid})`).join("、") : "本次未取得；不代表无人占用"}</p>
      {result.services.length ? result.services.map((service) => <article key={`${service.kind}:${service.name}`}><strong>{service.kind === "driver" ? "驱动" : "服务"}：{service.displayName || service.name}</strong><p>{service.name} · {service.state} · 启动方式 {service.startMode}</p><code>{service.path}</code><button type="button" className="win-ir-btn" onClick={() => onCopy(`${service.name}\n${service.path}\n${service.state}\n${service.startMode}`)}>复制关联记录</button></article>) : <p>未取得相同路径的服务或驱动；模块加载、过滤驱动和间接路径仍需核查。</p>}
      <details><summary>查看 {result.accessRules.length} 条访问规则</summary>{result.accessRules.map((rule, index) => <p key={index}>{rule.identity} · {rule.access === "Deny" ? "拒绝" : "允许"} · {rule.rights} · {rule.inherited ? "继承" : "显式"}</p>)}</details>
    </> : null}
    <details><summary>删除受阻与提权程序的处置建议</summary><ol><li>先保留样本、摘要与来源。权限不足时核对采集账户、文件 ACL 和所有者；管理员也可能受受保护进程或安全产品限制。</li><li>在进程、启动项与服务查询中核实关联；路径关联不能证明文件正在占用，也不能覆盖所有加载模块。</li><li>删除 .sys 文件不会卸载已加载驱动。停止驱动、修改启动方式或安排重启可能影响存储、网络与系统启动，需单独制定可恢复的计划。</li><li>无法在线处置时，使用可信恢复环境并准备恢复介质；当前功能不自动关闭防护、卸载驱动、取得所有权或安排重启删除。</li></ol></details>
  </div>;
}
