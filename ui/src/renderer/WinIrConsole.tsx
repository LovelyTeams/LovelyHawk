import { Activity, useEffect, useState } from "react";

import type { DvcRuntimeStatus } from "../shared/windows-incident-contract";
import { DialogHost } from "./DialogHost";
import { useConfirmDialog } from "./use-confirm-dialog";
import { formatBytes } from "./win-ir-helpers";
import { WINDOWS_COMMAND_PRESETS } from "./win-ir-command-presets";

export type WindowsDockTab = "tasks" | "files" | "command" | "logs";

export function WinIrConsole({ panel, status, busy, sessionKey, hostname, output, savedFiles, canSave, onCopy, onSend, onRun, onSave, onUnregister, suggestion, onDirtyChange }: {
  panel: WindowsDockTab;
  status: (Pick<DvcRuntimeStatus, "messagesSent" | "messagesReceived" | "recentLogs" | "receivedFiles"> & { registration: { registered: boolean } }) | null; busy: boolean; sessionKey: string | null; hostname: string;
  output: { command: string; output: string; time: string } | null;
  savedFiles: ReadonlySet<string>; canSave: boolean; onSave: (fileId: string) => void;
  onCopy: (text: string) => void; onSend: (text: string) => Promise<boolean>;
  onRun: (command: string, expectedSession: string) => Promise<unknown>; onUnregister: () => void;
  onDirtyChange?: (dirty: boolean) => void;
  suggestion?: { id: string; request: number } | null;
}) {
  const [message, setMessage] = useState("");
  const [command, setCommand] = useState("whoami /all");
  const [submittedCommand, setSubmittedCommand] = useState("whoami /all");
  useEffect(() => { onDirtyChange?.(command !== submittedCommand || message.trim().length > 0); }, [command, submittedCommand, message, onDirtyChange]);
  const [presetGroup, setPresetGroup] = useState("服务与驱动");
  const [presetId, setPresetId] = useState<string | null>(null);
  const selectedPreset = WINDOWS_COMMAND_PRESETS.find((preset) => preset.id === presetId);
  const [handledSuggestion, setHandledSuggestion] = useState<number | null>(null);
  const proposed = suggestion && suggestion.request !== handledSuggestion ? WINDOWS_COMMAND_PRESETS.find((preset) => preset.id === suggestion.id) : undefined;
  const confirm = useConfirmDialog();
  const available = !busy && sessionKey !== null;
  async function execute() {
    const submitted = command.trim();
    const capturedSession = sessionKey;
    if (!available || !submitted || !capturedSession) return;
    if (await confirm.ask("确认远程执行", `目标：${hostname}\n命令：\n${submitted}\n\n命令将以远程采集端的账户权限执行。自定义命令可能修改目标，执行结果不代表已完成安全复核。`, "执行该命令")) {
      if (await onRun(submitted, capturedSession) !== false) setSubmittedCommand(submitted);
    }
  }
  return (
    <div className="wir-console-panels">
      <Activity mode={panel === "command" ? "visible" : "hidden"}>
        <section className="wir-panel">
          <header><div><h2>命令检查台</h2><p>选择常用查询，或输入需要执行的完整命令</p></div></header>
          <div className="wir-console-content">
            {proposed && suggestion ? <section className="wir-command-suggestion" aria-label="响应方案推荐查询">
              <strong>方案推荐：{proposed.label}</strong><p>{proposed.hint}。现有命令草稿仍保留；填入后需再次核对目标并确认执行。</p><pre>{proposed.command}</pre>
              <div className="wir-toolbar"><button type="button" className="win-ir-btn" onClick={() => { setCommand(proposed.command); setPresetId(proposed.id); setPresetGroup(proposed.group); setHandledSuggestion(suggestion.request); }}>替换草稿为此查询</button><button type="button" className="win-ir-btn" onClick={() => setHandledSuggestion(suggestion.request)}>保留草稿</button></div>
            </section> : null}
            <div className="wir-command-presets">
              <label>排查预设（{WINDOWS_COMMAND_PRESETS.length} 项）<select className="win-ir-input" aria-label="命令预设类别" value={presetGroup} onChange={(event) => setPresetGroup(event.target.value)}>{[...new Set(WINDOWS_COMMAND_PRESETS.map((preset) => preset.group))].map((group) => <option key={group}>{group}</option>)}</select></label>
              <div className="wir-chips" role="group" aria-label="填入常用查询">{WINDOWS_COMMAND_PRESETS.filter((preset) => preset.group === presetGroup).map((preset) => <button type="button" className="wir-chip" key={preset.id} aria-pressed={preset.id === presetId} title={preset.hint} onClick={() => { setCommand(preset.command); setPresetId(preset.id); }}>{preset.label}</button>)}</div>
              <p className="wir-footnote">{selectedPreset?.hint ?? "点击预设只填入命令，核对目标后再执行。"} 优先使用 CIM；新版系统可能没有 WMIC。预设只读，不自动安装工具、提权或卸载驱动。</p>
            </div>
            <label className="wir-command-label">远程命令<textarea value={command} onChange={(event) => setCommand(event.target.value)} spellCheck={false} maxLength={16384} rows={3} /></label>
            <div className="wir-toolbar"><span className="wir-muted">提交前确认目标与完整命令</span><button type="button" className="win-ir-btn is-primary" disabled={!available || !command.trim()} onClick={() => void execute()}>确认并执行</button></div>
            {output ? <div className="wir-command-result"><header><span>返回于 {output.time}</span><button type="button" className="wir-link" onClick={() => onCopy(`${output.command}\n${output.output}`)}>复制输出</button></header><pre>{`> ${output.command}\n\n${output.output}`}</pre></div> : <div className="wir-empty">命令返回的原始输出将显示在这里。</div>}
          </div>
        </section>
      </Activity>
      <Activity mode={panel === "logs" ? "visible" : "hidden"}>
        <section className="wir-panel">
          <header><div><h2>通信日志与会话消息</h2><p>已发送 {status?.messagesSent ?? 0} 条 · 已接收 {status?.messagesReceived ?? 0} 条</p></div></header>
          <div className="wir-console-content">
            <form className="wir-toolbar" onSubmit={(event) => { event.preventDefault(); const text = message.trim(); if (available && text) void onSend(text).then((sent) => { if (sent) setMessage((current) => current.trim() === text ? "" : current); }); }}>
              <input className="win-ir-input" value={message} aria-label="会话消息" placeholder="输入要发送的消息" maxLength={8192} onChange={(event) => setMessage(event.target.value)} />
              <button type="submit" className="win-ir-btn" disabled={!available || !message.trim()}>发送</button>
            </form>
            <div className="wir-channel-log" role="log" aria-label="最近通道日志">{status?.recentLogs.length ? status.recentLogs.slice().reverse().map((entry, index) => <div key={`${entry.timestamp}:${index}`}><time>{entry.timestamp}</time><span className="wir-tag">{entry.direction} · {entry.kind}</span><p>{entry.summary}</p></div>) : <p className="wir-empty">暂无通信记录。</p>}</div>
          </div>
        </section>
        <div className="wir-toolbar wir-connection-maintenance"><span>本机插件注册：{status?.registration.registered ? "已注册" : "未注册"}</span><button type="button" className="win-ir-btn is-quiet" disabled={busy || !status?.registration.registered} onClick={() => void confirm.ask("移除本机插件注册", "移除当前用户的远程桌面插件配置，之后新开的远程桌面客户端将不再加载它。当前连接不会因此完成断开；需要再次使用时可重新注册。", "移除注册").then((approved) => { if (approved) onUnregister(); })}>移除插件注册</button></div>
      </Activity>
      <Activity mode={panel === "files" ? "visible" : "hidden"}>
      <section className="wir-panel">
          <header><div><h2>接收文件</h2><p>校验通过后仍需另存到本机。缓存仅在本次运行期间保留，超过 32 个文件可能移除旧记录。</p></div></header>
        {status?.receivedFiles.length ? <div className="wir-transfer-list">{status.receivedFiles.map((file) => <article key={file.fileId}>
          <span className="wir-transfer-icon" aria-hidden="true">↓</span><div><strong>{file.name}</strong><p>{formatBytes(file.sizeBytes)} · {file.receivedAt} · {file.verified ? "SHA256 已校验" : "校验不一致，不能保存"}</p><details><summary>查看完整摘要</summary><code>{file.sha256}</code><button type="button" className="wir-link" onClick={() => onCopy(`${file.name}\n${file.sizeBytes} bytes\nSHA256 ${file.sha256}\n${file.receivedAt}`)}>复制记录</button></details></div><span className={`wir-tag ${savedFiles.has(file.fileId) ? "is-good" : "is-caution"}`}>{savedFiles.has(file.fileId) ? "已另存" : file.verified ? "待保存" : "校验失败"}</span><button type="button" className="win-ir-btn is-primary" disabled={busy || !canSave || !file.verified || file.sizeBytes > 8 * 1024 * 1024} onClick={() => onSave(file.fileId)}>{savedFiles.has(file.fileId) ? "再次另存" : "另存为…"}</button>
        </article>)}</div> : <div className="wir-empty">从「文件排查」选择文件并取证拉取后，这里会列出接收时间和完整摘要。</div>}
      </section>
      </Activity>
      {confirm.dialog ? <DialogHost dialog={confirm.dialog} scrollMessage onResolve={confirm.resolve} /> : null}
    </div>
  );
}
