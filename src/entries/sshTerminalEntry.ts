/**
 * SSH 终端窗口入口（替代原 ssh-terminal.html 的内联脚本）
 *
 * 单入口架构下，SSH 终端窗口加载 index.html?window=ssh-terminal，
 * 由 main.ts 分流到此模块：注入标题栏与容器 DOM，初始化主题/字体，
 * 挂载 SSHTerminal.vue 组件。
 */

import { createApp } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import { getCurrentWebviewWindow } from '@tauri-apps/api/webviewWindow';
import { listen } from '@tauri-apps/api/event';
import { install } from '@icon-park/vue-next/es/all';
import '@icon-park/vue-next/styles/index.css';
import 'xterm/css/xterm.css';
import '../css/ssh-terminal.css';
import SSHTerminal from '../components/SSHTerminal.vue';

import { logger } from '../modules/core/logger';
/** 正式包 drop 掉 console，诊断信息只有进 logger 才留得下来（设置→工具→诊断日志 可导出） */
const log = logger.module('SSHTerminalEntry');


const APP_MARKUP = `
  <div class="modern-title-bar" data-tauri-drag-region id="custom-title-bar">
    <div class="title-bar-left">
      <div class="app-logo">
        <div class="logo-icon" style="width: 24px; height: 24px; display: flex; align-items: center; justify-content: center;">
          <svg width="22" height="22" viewBox="0 0 128 128" xmlns="http://www.w3.org/2000/svg">
            <defs>
              <linearGradient id="ssh-s" x1=".1" y1="0" x2=".9" y2="1"><stop offset="0" stop-color="#f9a8d4"/><stop offset="1" stop-color="#c4b5fd"/></linearGradient>
              <linearGradient id="ssh-h" x1=".36" y1="0" x2=".5" y2=".5"><stop offset="0" stop-color="#fff" stop-opacity=".5"/><stop offset="1" stop-color="#fff" stop-opacity="0"/></linearGradient>
            </defs>
            <g transform="rotate(-15 64 62)">
              <path d="M64,16 L75.8,47.8 L109.2,48.8 L83.2,68.8 L93,101.2 L64,83.2 L35,101.2 L44.8,68.8 L18.8,48.8 L52.2,47.8 Z" fill="url(#ssh-s)" stroke="url(#ssh-s)" stroke-width="12" stroke-linejoin="round" paint-order="stroke fill"/>
              <path d="M64,16 L75.8,47.8 L109.2,48.8 L83.2,68.8 L93,101.2 L64,83.2 L35,101.2 L44.8,68.8 L18.8,48.8 L52.2,47.8 Z" fill="url(#ssh-h)" stroke="url(#ssh-h)" stroke-width="12" stroke-linejoin="round" paint-order="stroke fill"/>
            </g>
          </svg>
        </div>
        <div class="app-info">
          <div class="app-name" style="font-size: 14px;">SSH Terminal</div>
          <div style="font-size: 9px; color: #94a3b8;">LovelyRes</div>
        </div>
      </div>
    </div>
    <div class="title-bar-right" id="window-controls-container"></div>
  </div>
  <div id="ssh-terminal-content"></div>
`;

function setupWindowControls(): void {
  const isMacOS = navigator.platform.toUpperCase().indexOf('MAC') >= 0;
  const customTitleBar = document.getElementById('custom-title-bar');
  const terminalContent = document.getElementById('ssh-terminal-content');

  if (isMacOS) {
    if (customTitleBar) customTitleBar.style.display = 'none';
    if (terminalContent) terminalContent.style.height = '100vh';
  } else {
    if (terminalContent) terminalContent.style.height = 'calc(100vh - 45px)';
    const container = document.getElementById('window-controls-container');
    if (container) {
      container.innerHTML = `
        <button class="control-button minimize-btn" onclick="minimizeWindow()" title="最小化">
          <svg width="12" height="12" viewBox="0 0 12 12" fill="currentColor"><rect x="2" y="5.5" width="8" height="1"/></svg>
        </button>
        <button class="control-button maximize-btn" onclick="toggleMaximize()" title="最大化">
          <svg width="12" height="12" viewBox="0 0 12 12" fill="currentColor"><rect x="2" y="2" width="8" height="8" stroke="currentColor" stroke-width="1" fill="none"/></svg>
        </button>
        <button class="control-button close-btn close" onclick="closeWindow()" title="关闭">
          <svg width="12" height="12" viewBox="0 0 12 12" fill="currentColor"><path d="M2.5 2.5L9.5 9.5M9.5 2.5L2.5 9.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
        </button>
      `;
    }
  }

  (window as any).minimizeWindow = async () => {
    try { await getCurrentWebviewWindow().minimize(); } catch (e) { log.error('最小化窗口失败:', e); }
  };
  (window as any).toggleMaximize = async () => {
    try { await getCurrentWebviewWindow().toggleMaximize(); } catch (e) { log.error('切换最大化状态失败:', e); }
  };
  (window as any).closeWindow = async () => {
    try { await cleanupSSHSessions(); await getCurrentWebviewWindow().destroy(); }
    catch (e) { log.error('关闭窗口失败:', e); }
  };
}

async function cleanupSSHSessions(): Promise<void> {
  try {
    const count = await invoke('ssh_close_all_terminal_sessions');
    log.debug(`已清理所有SSH会话，共 ${count} 个`);
  } catch (error) {
    log.error('清理SSH会话时出错:', error);
    try {
      const terminals = document.querySelectorAll('[data-terminal-id]');
      for (const terminal of terminals) {
        const terminalId = terminal.getAttribute('data-terminal-id');
        if (terminalId) {
          try { await invoke('ssh_close_terminal_session', { terminalId }); }
          catch (e) { log.warn('清理SSH会话失败', { terminalId, error: e }); }
        }
      }
    } catch (fallbackError) {
      log.error('后备清理方案也失败:', fallbackError);
    }
  }
}

function applyTheme(theme: string): void {
  document.body.setAttribute('data-theme', theme);
  document.documentElement.setAttribute('data-theme', theme);
  document.body.classList.remove('light-theme', 'dark-theme', 'sakura-theme');
  document.body.classList.add(`${theme}-theme`);

  const existingThemeLink = document.querySelector('link[data-theme-css]');
  if (existingThemeLink) existingThemeLink.remove();
  const link = document.createElement('link');
  link.rel = 'stylesheet';
  link.href = `/src/css/themes/${theme}.css`;
  link.setAttribute('data-theme-css', 'true');
  document.head.appendChild(link);
}

async function initializeTheme(): Promise<void> {
  try {
    const themeSettings = await invoke<any>('get_theme_settings');
    const currentTheme = themeSettings?.current_theme || 'sakura';
    applyTheme(currentTheme);
    await listen('theme-changed', (event) => applyTheme(event.payload as string));
    log.debug('主题初始化完成:', currentTheme);
  } catch (error) {
    log.error('主题初始化失败:', error);
    applyTheme('sakura');
  }
}

async function initializeFontSettings(): Promise<void> {
  try {
    const settingsContent = await invoke<string>('read_settings_file');
    if (!settingsContent) return;
    const settings = JSON.parse(settingsContent);
    if (settings.ui && settings.ui.globalFont && settings.ui.globalFont !== 'system') {
      let fontFamily = settings.ui.globalFont;
      if (!fontFamily.includes("'") && !fontFamily.includes('"')) {
        fontFamily = `'${fontFamily}', sans-serif`;
      }
      document.documentElement.style.setProperty('--font-family', fontFamily);
      log.debug('SSH终端已应用全局字体:', fontFamily);
    }
  } catch (error) {
    log.error('SSH终端字体设置初始化失败:', error);
  }
}

export function bootSSHTerminalWindow(): void {
  document.body.classList.add('ssh-terminal-window');
  // 移除主应用的初始加载屏（SSH 终端窗口不需要）
  document.getElementById('loading-screen')?.remove();
  const appEl = document.getElementById('app') || document.body;
  appEl.innerHTML = APP_MARKUP;

  setupWindowControls();

  const app = createApp(SSHTerminal);
  install(app, 'icon');
  app.mount('#ssh-terminal-content');

  window.addEventListener('beforeunload', () => { void cleanupSSHSessions(); });

  void initializeTheme();
  void initializeFontSettings();

  log.debug('SSH终端窗口已初始化（单入口）');
}
