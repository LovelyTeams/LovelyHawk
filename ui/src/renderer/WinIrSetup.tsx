import { useState } from "react";

import type { DvcRuntimeStatus } from "../shared/windows-incident-contract";
import { WinIrIcon } from "./WinIrIcon";

interface WinIrSetupProps {
  status: DvcRuntimeStatus | null;
  script: string;
  busy: boolean;
  canCopy: boolean;
  onRegister: () => void;
  onListen: () => void;
  onOpenDesktop: () => void;
  onCopyScript: () => void;
  onRevealAgent: () => void;
}

export function WinIrSetup({ status, script, busy, canCopy, onRegister, onListen, onOpenDesktop, onCopyScript, onRevealAgent }: WinIrSetupProps) {
  const [preview, setPreview] = useState(false);
  const prepared = status?.registration.registered === true && status.listenerRunning;
  const loaded = prepared && (status?.rdpPluginInitialized === true || status?.channelConnected === true);
  const connected = loaded && status?.channelConnected === true;
  const current = !prepared ? 0 : !loaded ? 1 : 2;
  const done = [prepared, loaded, connected];
  return (
    <section className="win-ir-setup" aria-labelledby="win-ir-setup-title">
      <header className="win-ir-setup-head">
        <span className="wir-setup-emblem"><WinIrIcon name="network" /></span>
        <p className="win-ir-eyebrow">Windows 应急响应工作台 · 接入向导</p>
        <h1 id="win-ir-setup-title">三步连接被检 Windows 主机</h1>
        <p>复用远程桌面会话进行排查与文件取证。按顺序完成接入，连接后自动读取主机概况。</p>
        <ol className="wir-setup-progress" aria-label="接入步骤">
          {["注册插件", "连接远程桌面", "启动采集端"].map((label, index) => <li key={label} className={done[index] ? "is-done" : index === current ? "is-current" : ""} aria-current={index === current && !connected ? "step" : undefined}><span>{done[index] ? "✓" : index + 1}</span>{label}</li>)}
        </ol>
      </header>
      <ol className="win-ir-steps">
        <li className={`win-ir-step is-${prepared ? "done" : "current"}`}>
          <span className="win-ir-step-index" aria-hidden="true">{prepared ? "✓" : "1"}</span>
          <div className="win-ir-step-body">
            <h2>注册插件并启动监听</h2>
            <p>点击下方按钮，在本机当前用户注册表登记插件并准备接收通道。无需管理员权限。</p>
            <div className="win-ir-step-actions">
              <button type="button" className={`win-ir-btn${prepared ? "" : " is-primary"}`} data-testid="windows-register-plugin" disabled={busy || status === null} onClick={onRegister}>{prepared ? "重新注册" : "注册插件并启动监听"}</button>
              {status?.registration.registered && !status.listenerRunning ? <button type="button" className="win-ir-btn" disabled={busy} onClick={onListen}>只启动通道监听</button> : null}
              <span className="wir-muted">{status === null ? "接入状态待核实" : prepared ? "本机已准备就绪" : status.registration.registered ? "插件已注册，等待启动监听" : "等待注册"}</span>
            </div>
          </div>
        </li>
        <li className={`win-ir-step is-${loaded ? "done" : prepared ? "current" : "pending"}`}>
          <span className="win-ir-step-index" aria-hidden="true">{loaded ? "✓" : "2"}</span>
          <div className="win-ir-step-body">
            <h2>打开远程桌面，连接服务器</h2>
            <p>在远程桌面客户端中输入服务器地址并登录。注册前已打开的客户端需要关闭后重新打开，才能加载插件。</p>
            <div className="win-ir-step-actions">
              <button type="button" className={`win-ir-btn${prepared && !loaded ? " is-primary" : ""}`} data-testid="windows-open-mstsc" disabled={busy || !prepared} onClick={onOpenDesktop}>打开远程桌面（mstsc）</button>
              <span className="wir-muted">{loaded ? "客户端已加载插件" : "等待客户端加载插件"}</span>
            </div>
          </div>
        </li>
        <li className={`win-ir-step is-${connected ? "done" : loaded ? "current" : "pending"}`}>
          <span className="win-ir-step-index" aria-hidden="true">{connected ? "✓" : "3"}</span>
          <div className="win-ir-step-body">
            <h2>复制命令或 Agent，在服务器中运行</h2>
            <p>以下两种方式任选其一，操作位置是远程桌面里的服务器。</p>
            <div className="win-ir-options">
              <div className="win-ir-option"><strong>PowerShell 脚本</strong><span>复制后粘贴到远程 PowerShell 窗口执行，保持窗口运行以维持采集连接。</span>
                <div className="win-ir-step-actions">
                  <button type="button" className={`win-ir-btn${loaded && !connected ? " is-primary" : ""}`} data-testid="windows-copy-script" disabled={busy || !script || !canCopy} onClick={onCopyScript}>复制免落地 PowerShell 脚本</button>
                  <button type="button" className="win-ir-btn is-quiet" aria-expanded={preview} onClick={() => setPreview(!preview)}>{preview ? "收起内容" : "查看脚本"}</button>
                </div>
              </div>
              <div className="win-ir-option"><strong>Agent 采集程序</strong><span>复制 lovelyhawk-win-agent.exe 到服务器并运行。通过远程桌面粘贴文件需要开启剪贴板重定向。</span>
                <div className="win-ir-step-actions"><button type="button" className="win-ir-btn" data-testid="windows-reveal-agent" disabled={busy} onClick={onRevealAgent}>打开 Agent 所在位置</button></div>
              </div>
            </div>
            {preview ? <pre className="win-ir-pre">{script || "正在准备脚本…"}</pre> : null}
            <p className="wir-footnote">{connected ? "采集端已接通，可以开始调查。" : "采集端接通后，这里会自动切换到主机总览。"}</p>
          </div>
        </li>
      </ol>
    </section>
  );
}
