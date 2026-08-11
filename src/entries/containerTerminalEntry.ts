/**
 * 容器终端窗口入口（替代原 container-terminal.html）
 *
 * 单入口架构下，容器终端窗口加载 index.html?window=container-terminal，
 * 由 main.ts 分流到此模块：注入专用样式与 DOM 标记，再启动容器终端逻辑。
 * 容器信息由 Rust 侧 create_container_terminal_window 通过 window.eval 注入 window.containerInfo。
 */

import '../css/container-terminal.css';
import { initContainerTerminal } from '../container-terminal';
import { createIconHTML } from '../modules/ui/iconMapping';

import { logger } from '../modules/core/logger';
/** 正式包 drop 掉 console，诊断信息只有进 logger 才留得下来（状态栏「日志」按钮可导出） */
const log = logger.module('ContainerTerminalEntry');


const MARKUP = `
  <div class="loading-screen" id="loading-screen">
    <div class="loading-spinner-container">
      <div class="loading-spinner-ring"></div>
      <div class="loading-spinner-dot"></div>
    </div>
    <div class="loading-text">初始化容器终端...</div>
    <div class="loading-sub-text">正在连接到容器</div>
  </div>

  <div class="container-terminal" id="container-terminal" style="display: none;">
    <div class="terminal-header">
      <div class="terminal-title-group">
        <div class="terminal-title-icon">${createIconHTML('🐳', { size: 16 })}</div>
        <span class="terminal-title" id="terminal-title">容器终端</span>
        <span class="terminal-title-badge">LIVE</span>
      </div>
      <div class="terminal-controls">
        <select class="shell-selector" id="shell-selector">
          <option value="bash">bash</option>
          <option value="sh">sh</option>
          <option value="zsh">zsh</option>
        </select>
        <button class="terminal-btn" id="clear-btn">清空</button>
        <button class="terminal-btn danger" id="close-btn">关闭</button>
      </div>
    </div>

    <div class="terminal-input-section">
      <span class="input-prompt">$</span>
      <input type="text" class="terminal-input" id="command-input" placeholder="输入要在容器内执行的命令..." autocomplete="off" spellcheck="false">
      <button class="terminal-btn primary" id="execute-btn">执行</button>
    </div>

    <div class="terminal-output" id="terminal-output">
      <div class="system-message">容器终端已就绪。选择 shell 类型并输入命令。</div>
    </div>

    <div class="terminal-status-bar">
      <span class="status-dot" id="status-dot"></span>
      <span id="status-text">已连接</span>
      <span style="margin-left:auto;" id="status-shell">bash</span>
    </div>
  </div>
`;

export function bootContainerTerminalWindow(): void {
  document.body.classList.add('container-terminal-window');
  // 主题由 container-terminal.ts 的 setupTheme 按保存值设置（跟随应用主题），此处不强制深色
  document.body.innerHTML = MARKUP;
  initContainerTerminal();
  log.debug('容器终端窗口已初始化（单入口）');
}
