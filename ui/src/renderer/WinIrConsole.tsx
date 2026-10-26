import { useState } from "react";

import type { DvcRuntimeStatus } from "../shared/windows-incident-contract";
import { DialogHost } from "./DialogHost";
import { useConfirmDialog } from "./use-confirm-dialog";
import { StatStrip } from "./WinIrKit";
import { formatBytes } from "./win-ir-helpers";

export function WinIrConsole({ status, busy, sessionKey, hostname, output, savedFiles, canSave, onCopy, onSend, onRun, onSave, onUnregister }: {
  status: DvcRuntimeStatus | null; busy: boolean; sessionKey: string | null; hostname: string;
  output: { command: string; output: string; time: string } | null;
  savedFiles: ReadonlySet<string>; canSave: boolean; onSave: (fileId: string) => void;
  onCopy: (text: string) => void; onSend: (text: string) => Promise<boolean>;
  onRun: (command: string, expectedSession: string) => Promise<void>; onUnregister: () => void;
}) {
  const [message, setMessage] = useState("");
  const [command, setCommand] = useState("whoami /all");
  const confirm = useConfirmDialog();
  const available = !busy && sessionKey !== null;
  async function execute() {
    const submitted = command.trim();
    const capturedSession = sessionKey;
    if (!available || !submitted || !capturedSession) return;
    if (await confirm.ask("确认远程执行", `目标：${hostname}\n命令：\n${submitted}\n\n命令将以远程采集端的账户权限执行。自定义命令可能修改目标，执行结果不代表已完成安全复核。`, "执行该命令")) {
      await onRun(submitted, capturedSession);
    }
  }
  return (
    <div className="wir-module">
      <StatStrip cards={[
        { label: "会话通道", value: sessionKey ? "已连接" : "未连接", tone: sessionKey ? "normal" : "medium" },
        { label: "已发送消息", value: status?.messagesSent ?? "—" },
        { label: "已接收消息", value: status?.messagesReceived ?? "—" },
        { label: "接收缓存中的文件", value: status?.receivedFiles.length ?? "—" },
      ]} />
      <div className="wir-console-grid">
        <section className="wir-panel">
          <header><div><h2>命令检查台</h2><p>选择常用查询，或输入需要执行的完整命令</p></div></header>
          <div className="wir-console-content">
            <div className="wir-chips" role="group" aria-label="填入常用查询">{["whoami /all", "systeminfo", "netstat -ano", "tasklist /v"].map((value) => <button type="button" className="wir-chip" key={value} onClick={() => setCommand(value)}>{value}</button>)}</div>
            <label className="wir-command-label">远程命令<textarea value={command} onChange={(event) => setCommand(event.target.value)} spellCheck={false} maxLength={16384} rows={3} /></label>
            <div className="wir-toolbar"><span className="wir-muted">提交前确认目标与完整命令</span><button type="button" className="win-ir-btn is-primary" disabled={!available || !command.trim()} onClick={() => void execute()}>确认并执行</button></div>
            {output ? <div className="wir-command-result"><header><span>返回于 {output.time}</span><button type="button" className="wir-link" onClick={() => onCopy(`${output.command}\n${output.output}`)}>复制输出</button></header><pre>{`> ${output.command}\n\n${output.output}`}</pre></div> : <div className="wir-empty">命令返回的原始输出将显示在这里。</div>}
          </div>
        </section>
        <section className="wir-panel">
          <header><div><h2>会话消息</h2><p>向远程采集端发送文本</p></div></header>
          <div className="wir-console-content">
            <form className="wir-toolbar" onSubmit={(event) => { event.preventDefault(); const text = message.trim(); if (available && text) void onSend(text).then((sent) => { if (sent) setMessage((current) => current.trim() === text ? "" : current); }); }}>
              <input className="win-ir-input" value={message} aria-label="会话消息" placeholder="输入要发送的消息" maxLength={8192} onChange={(event) => setMessage(event.target.value)} />
              <button type="submit" className="win-ir-btn" disabled={!available || !message.trim()}>发送</button>
            </form>
            <div className="wir-channel-log" role="log" aria-label="最近通道日志">{status?.recentLogs.length ? status.recentLogs.slice().reverse().map((entry, index) => <div key={`${entry.timestamp}:${index}`}><time>{entry.timestamp}</time><span className="wir-tag">{entry.direction} · {entry.kind}</span><p>{entry.summary}</p></div>) : <p className="wir-empty">暂无通信记录。</p>}</div>
          </div>
        </section>
      </div>
      <section className="wir-panel">
          <header><div><h2>取证文件接收记录</h2><p>这里保留本次程序运行期间接收的文件。请及时另存；未保存的缓存会在退出或超过 32 个文件时移除。</p></div></header>
        {status?.receivedFiles.length ? <div className="wir-transfer-list">{status.receivedFiles.map((file) => <article key={file.fileId}>
          <span className="wir-transfer-icon" aria-hidden="true">↓</span><div><strong>{file.name}</strong><p>{formatBytes(file.sizeBytes)} · {file.receivedAt}</p><code>{file.sha256}</code></div><span className={`wir-tag ${file.verified ? "is-good" : "is-caution"}`}>{savedFiles.has(file.fileId) ? "已另存" : file.verified ? "SHA256 已校验" : "校验不一致"}</span><button type="button" className="win-ir-btn" onClick={() => onCopy(`${file.name}\n${file.sizeBytes} bytes\nSHA256 ${file.sha256}\n${file.receivedAt}`)}>复制记录</button><button type="button" className="win-ir-btn is-primary" disabled={busy || !canSave || !file.verified || file.sizeBytes > 8 * 1024 * 1024} onClick={() => onSave(file.fileId)}>{savedFiles.has(file.fileId) ? "再次另存" : "另存为…"}</button>
        </article>)}</div> : <div className="wir-empty">从「文件排查」选择文件并取证拉取后，这里会列出接收时间和完整摘要。</div>}
      </section>
      <div className="wir-toolbar wir-connection-maintenance"><span>本机插件注册：{status?.registration.registered ? "已注册" : "未注册"}</span><button type="button" className="win-ir-btn is-quiet" disabled={busy || !status?.registration.registered} onClick={() => void confirm.ask("移除本机插件注册", "移除当前用户的远程桌面插件配置，之后新开的远程桌面客户端将不再加载它。当前连接不会因此完成断开；需要再次使用时可重新注册。", "移除注册").then((approved) => { if (approved) onUnregister(); })}>移除插件注册</button></div>
      {confirm.dialog ? <DialogHost dialog={confirm.dialog} scrollMessage onResolve={confirm.resolve} /> : null}
    </div>
  );
}
