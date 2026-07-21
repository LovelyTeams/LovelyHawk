/**
 * LovelyRes 主入口文件
 * Linux Emergency Response Tool
 */

// 本地化第三方资源(字体 + highlight.js),替代 index.html 中的 CDN 引入,保证离线可用
import './modules/core/vendorAssets';

import './css/main.css';
import 'xterm/css/xterm.css';

import type { LovelyResApp } from './modules/core/app';

import { initNotificationManager } from './modules/ui/notificationManager';
import { logger, applySavedLogLevel } from './modules/core/logger';
import { escapeHtml } from './modules/core/htmlEscape';

/**
 * 启动路径上的日志尤其重要：冷启动卡死时用户什么也看不到，而正式包 drop 掉了
 * console，logger 的环形缓冲是唯一线索（设置→工具→诊断日志 可导出）。
 *
 * 级别在这里就恢复，而不是等设置页打开——否则用户调到 debug 重启复现问题时，
 * 启动路径上那段最关键的 debug 日志仍然会被丢掉。
 */
applySavedLogLevel();
const log = logger.module('Boot');

let app: LovelyResApp | null = null;
let bootPromise: Promise<void> | null = null;
let postBootDomListenersBound = false;

function removeLoadingScreen(): void {
  const loadingScreen = document.getElementById('loading-screen');
  if (!loadingScreen) return;

  loadingScreen.classList.add('hidden');
  setTimeout(() => loadingScreen.remove(), 600);
}

/**
 * 启动看门狗:若初始化长时间未完成(例如某个 Tauri invoke 一直不返回),
 * 加载屏会永久停在"正在初始化系统...",用户无从判断也无法恢复。
 * 这里在超时后就地提示并给出"重新加载"入口,避免冷启动被卡死。
 */
function showSlowBootWarning(): void {
  const loadingScreen = document.getElementById('loading-screen');
  if (!loadingScreen || loadingScreen.classList.contains('hidden')) return;

  const textEl = loadingScreen.querySelector('.loading-text');
  if (textEl) textEl.textContent = '初始化耗时较长,后端可能无响应…';

  const content = loadingScreen.querySelector('.loading-content');
  if (!content || content.querySelector('.ls-recover-btn')) return;

  const btn = document.createElement('button');
  btn.className = 'ls-recover-btn';
  btn.textContent = '重新加载';
  btn.style.cssText =
    'margin-top:8px;padding:8px 22px;background:linear-gradient(90deg,#f9a8d4,#c4b5fd);' +
    'color:#1e293b;border:none;border-radius:8px;cursor:pointer;font-size:13px;font-weight:600;';
  btn.addEventListener('click', () => location.reload());
  content.appendChild(btn);
}

function removeLegacyAccessArtifacts(): void {
  document.body.classList.remove('auth-locked');

  try {
    [
      'lovelyres-access-token',
      'lovelyres-refresh-token',
      'lovelyres-user-info'
    ].forEach((key) => localStorage.removeItem(key));
  } catch (error) {
    log.warn('清理旧访问状态失败:', error);
  }

  document
    .querySelectorAll(
      '#login-modal, #bind-device-modal, #account-settings-modal, .auth-required-toast, .license-card, .license-modal'
    )
    .forEach((element) => element.remove());
}

function showStartupFailure(error: unknown): void {
  removeLoadingScreen();

  const appEl = document.getElementById('app');
  if (!appEl) return;

  appEl.innerHTML = `
    <div style="
      display: flex; flex-direction: column; align-items: center; justify-content: center;
      height: 100vh; background: #f8fafc; color: #1e293b;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    ">
      <div style="font-size: 42px; margin-bottom: 24px;">启动失败</div>
      <h2 style="margin-bottom: 16px;">应用启动失败</h2>
      <p style="color: #64748b; text-align: center; max-width: 420px; line-height: 1.7;">
        LovelyRes 在启动过程中遇到了问题。请检查控制台获取详细错误信息。
      </p>
      <pre style="
        margin-top: 16px; max-width: 520px; white-space: pre-wrap; word-break: break-word;
        color: #dc2626; background: #fee2e2; padding: 12px; border-radius: 8px; font-size: 12px;
      ">${escapeHtml(String(error))}</pre>
      <button onclick="location.reload()" style="
        margin-top: 24px; padding: 12px 24px;
        background: #4299e1; color: white; border: none;
        border-radius: 8px; cursor: pointer; font-size: 14px;
      ">重新加载</button>
    </div>
  `;
}

/**
 * 在新窗口中打开 SSH 终端
 */
async function openSSHTerminalWindow(): Promise<void> {
  try {
    const { WebviewWindow } = await import('@tauri-apps/api/webviewWindow');
    const existingWindow = await WebviewWindow.getByLabel('ssh-terminal');
    if (existingWindow) {
      await existingWindow.setFocus();
      await existingWindow.unminimize();
      return;
    }

    const isMacOS = navigator.platform.toUpperCase().indexOf('MAC') >= 0;
    const sshWindow = new WebviewWindow('ssh-terminal', {
      url: 'index.html?window=ssh-terminal',
      title: 'SSH Terminal - LovelyRes',
      width: 1000,
      height: 700,
      minWidth: 600,
      minHeight: 400,
      resizable: true,
      maximizable: true,
      minimizable: true,
      closable: true,
      center: true,
      decorations: isMacOS,
      alwaysOnTop: false,
      skipTaskbar: false
    });

    sshWindow.once('tauri://error', (error) => log.error('SSH 终端窗口创建错误:', error));
  } catch (error) {
    log.error('创建 SSH 终端窗口失败:', error);

    try {
      const { WebviewWindow } = await import('@tauri-apps/api/webviewWindow');
      const existingWindow = await WebviewWindow.getByLabel('ssh-terminal');
      if (existingWindow) {
        await existingWindow.setFocus();
        await existingWindow.unminimize();
        return;
      }
    } catch (focusError) {
      log.error('聚焦 SSH 终端窗口失败:', focusError);
    }

    const fallbackWindow = window.open(
      '/?window=ssh-terminal',
      'ssh-terminal',
      'width=1000,height=700,resizable=yes,scrollbars=yes,status=yes'
    );
    if (!fallbackWindow) {
      window.showNotification?.('无法打开 SSH 终端窗口', 'error');
    }
  }
}

function bindPostBootDomListeners(logContextMenu: { showContextMenu(x: number, y: number, content: string): void }): void {
  if (postBootDomListenersBound) return;
  postBootDomListenersBound = true;

  document.addEventListener('contextmenu', (e) => {
    const target = e.target as HTMLElement;
    const logEntry = target.closest('.log-entry');
    if (!logEntry) return;

    e.preventDefault();
    const content = logEntry.textContent?.trim().replace(/\s+/g, ' ') || '';
    if (content) {
      logContextMenu.showContextMenu(e.clientX, e.clientY, content);
    }
  });

  document.body.addEventListener('click', (event) => {
    const target = event.target as HTMLElement;
    const terminalBtn = target.closest('#ssh-terminal-title-btn');
    if (terminalBtn) {
      event.preventDefault();
      event.stopPropagation();
      void openSSHTerminalWindow();
    }
  });

  document.addEventListener('click', (event) => {
    const target = event.target as HTMLElement;
    if (!target.closest('tr') && !target.closest('[id$="-context-menu"]')) {
      document.querySelectorAll('.system-table tr.selected').forEach(row => {
        row.classList.remove('selected');
      });
    }
  });
}

async function bootstrapApp(): Promise<void> {
  if (bootPromise) {
    return bootPromise;
  }

  // 启动看门狗:15s 内若仍未完成初始化,就地给出可恢复提示(见 showSlowBootWarning)
  const bootWatchdog = window.setTimeout(showSlowBootWarning, 15000);

  bootPromise = (async () => {
    removeLegacyAccessArtifacts();
    log.debug('LovelyRes 启动中...');

    const [
      { LovelyResApp },
      { remoteOperationsManager },
      { sshTerminalManager },
      { SettingsManager },
      { SettingsPageManager },
      { FileViewerModal },
      { UploadModal },
      { CreateFolderModal },
      { CompressModal },
      { ExtractModal },
      { PermissionsModal },
      { EmergencyResultModal },
      { CommandHistoryModal },
      { FileContextMenu },
      { LogContextMenu },
      { initSftpContextMenuHandler },
      { initServerModalManager },
      { initTableFilterManager },
      { initSystemInfoTabManager },
      { initTableUpdateManager },
      { initLogAnalysisManager },
      { initCommandPalette },
      { initKeyboardShortcuts },
      { initGlobalFunctions },
      { i18n },
      { forensicManager }
    ] = await Promise.all([
      import('./modules/core/app'),
      import('./modules/remote/remoteOperationsManager'),
      import('./modules/ssh/sshTerminalManager'),
      import('./modules/settings/settingsManager'),
      import('./modules/settings/settingsPageManager'),
      import('./modules/ui/fileViewerModal'),
      import('./modules/ui/uploadModal'),
      import('./modules/ui/createFolderModal'),
      import('./modules/ui/compressModal'),
      import('./modules/ui/extractModal'),
      import('./modules/ui/permissionsModal'),
      import('./modules/ui/emergencyModal'),
      import('./modules/ui/commandHistoryModal'),
      import('./modules/ui/fileContextMenu'),
      import('./modules/ui/logContextMenu'),
      import('./modules/ui/sftpContextMenuHandler'),
      import('./modules/ui/serverModalManager'),
      import('./modules/ui/tableFilterManager'),
      import('./modules/ui/systemInfoTabManager'),
      import('./modules/ui/tableUpdateManager'),
      import('./modules/ui/logAnalysisManager'),
      import('./modules/ui/commandPalette'),
      import('./modules/ui/keyboardShortcuts'),
      import('./modules/ui/globalFunctions'),
      import('./modules/i18n'),
      import('./modules/emergency/forensicManager')
    ]);

    initTableFilterManager();
    initTableUpdateManager();
    initSystemInfoTabManager();
    initServerModalManager();
    initSftpContextMenuHandler();
    initLogAnalysisManager();

    log.info(`LovelyRes 启动中... (语言: ${i18n.lang})`);
    forensicManager.loadFromStorage();

    const settingsManager = new SettingsManager();
    const settingsPageManager = new SettingsPageManager(settingsManager);

    app = new LovelyResApp();

    const fileViewerModal = new FileViewerModal();
    const uploadModal = new UploadModal();
    const createFolderModal = new CreateFolderModal();
    const compressModal = new CompressModal();
    const extractModal = new ExtractModal();
    const permissionsModal = new PermissionsModal();
    const emergencyResultModal = new EmergencyResultModal();
    const commandHistoryModal = new CommandHistoryModal();
    const fileContextMenu = new FileContextMenu();
    const logContextMenu = new LogContextMenu();

    (window as any).fileViewerModal = fileViewerModal;
    (window as any).uploadModal = uploadModal;
    (window as any).createFolderModal = createFolderModal;
    (window as any).compressModal = compressModal;
    (window as any).extractModal = extractModal;
    (window as any).permissionsModal = permissionsModal;
    (window as any).emergencyResultModal = emergencyResultModal;
    (window as any).commandHistoryModal = commandHistoryModal;
    (window as any).fileContextMenu = fileContextMenu;
    (window as any).logContextMenu = logContextMenu;

    bindPostBootDomListeners(logContextMenu);

    await app.initialize();
    window.clearTimeout(bootWatchdog);
    removeLoadingScreen();

    (window as any).app = app;
    (window as any).lovelyResApp = app;
    (window as any).openSSHTerminalWindow = openSSHTerminalWindow;

    setTimeout(() => {
      if (document.getElementById('ssh-terminal-container')) {
        sshTerminalManager.mountTerminal();
      }
    }, 1000);

    initGlobalFunctions({ app, settingsPageManager, openSSHTerminalWindow });

    // 可选模块:此时应用已展示,任一初始化失败都不应中止启动
    // (否则会命中外层 catch → showStartupFailure,把已经可用的界面整个抹掉)。
    const optionalInits: Array<{ name: string; promise: Promise<unknown> }> = [
      { name: '远程操作', promise: remoteOperationsManager.initialize() },
      { name: 'SSH 终端', promise: sshTerminalManager.initialize() },
      { name: '设置', promise: settingsManager.initialize() },
    ];
    const initResults = await Promise.allSettled(optionalInits.map((m) => m.promise));
    initResults.forEach((r, i) => {
      if (r.status === 'rejected') {
        log.error(`${optionalInits[i].name}模块初始化失败(不影响主功能):`, r.reason);
      }
    });

    initCommandPalette();
    initKeyboardShortcuts(app);

    log.debug('LovelyRes 启动完成');
  })().catch((error) => {
    window.clearTimeout(bootWatchdog);
    bootPromise = null;
    log.error('LovelyRes 启动失败:', error);
    showStartupFailure(error);
  });

  return bootPromise;
}

/**
 * 单入口分流：SSH 终端 / 容器终端窗口都加载 index.html?window=xxx，
 * 在此按参数分流到各自的入口模块，不再需要独立的 .html 文件。
 * 返回 true 表示已分流处理，主应用不再启动。
 */
async function routeSecondaryWindow(): Promise<boolean> {
  const which = new URLSearchParams(location.search).get('window');
  if (which === 'ssh-terminal') {
    const { bootSSHTerminalWindow } = await import('./entries/sshTerminalEntry');
    bootSSHTerminalWindow();
    return true;
  }
  if (which === 'container-terminal') {
    const { bootContainerTerminalWindow } = await import('./entries/containerTerminalEntry');
    bootContainerTerminalWindow();
    return true;
  }
  return false;
}

async function initializeApp(): Promise<void> {
  // 终端等辅助窗口走独立入口，跳过主应用引导
  if (await routeSecondaryWindow()) return;

  initNotificationManager();
  removeLegacyAccessArtifacts();
  await bootstrapApp();
}

window.addEventListener('error', (event) => {
  const msg = (event as any).message as string | undefined;
  if (msg && typeof msg === 'string' && msg.includes('ResizeObserver loop')) return;
  if ((event as any).error) {
    log.error('全局错误:', (event as any).error);
  } else {
    log.error('全局错误', {
      message: event.message,
      file: event.filename,
      line: event.lineno,
      col: event.colno,
    });
  }
});

window.addEventListener('unhandledrejection', (event) => {
  log.error('未处理的 Promise 拒绝:', event.reason);
});

window.addEventListener('beforeunload', () => {
  if (app) {
    log.debug('LovelyRes 正在清理资源...');
  }
});

document.addEventListener('DOMContentLoaded', () => {
  void initializeApp();
});
