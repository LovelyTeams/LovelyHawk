/**
 * SFTP 文件管理独立窗口入口
 *
 * 单入口架构：SFTP 窗口加载 index.html?window=sftp，由 main.ts 分流到此模块。
 * 注入标题栏与页面 DOM，初始化主题/字体，并把 SFTP 交互所需的 window 函数
 * 与弹窗全部备好——页面 HTML 与主窗口共用 ModernUIRenderer.renderRemoteOperationsPage()，
 * SSH 会话由后端持有，主窗口连接后本窗口直接可用（刷新即可）。
 */

import { invoke } from '@tauri-apps/api/core';
import { getCurrentWebviewWindow } from '@tauri-apps/api/webviewWindow';
import { listen } from '@tauri-apps/api/event';

import { logger } from '../modules/core/logger';
import { initNotificationManager } from '../modules/ui/notificationManager';
import { StateManager } from '../modules/core/stateManager';
import { ModernUIRenderer } from '../modules/ui/modernUIRenderer';
import { sftpManager } from '../modules/remote/sftpManager';
import { sshConnectionManager } from '../modules/remote/sshConnectionManager';
import { remoteOperationsManager } from '../modules/remote/remoteOperationsManager';
import { sshTerminalManager } from '../modules/ssh/sshTerminalManager';
import { UploadModal } from '../modules/ui/uploadModal';
import { CreateFolderModal } from '../modules/ui/createFolderModal';
import { CompressModal } from '../modules/ui/compressModal';
import { ExtractModal } from '../modules/ui/extractModal';
import { PermissionsModal } from '../modules/ui/permissionsModal';
import { FileViewerModal } from '../modules/ui/fileViewerModal';
import { FileContextMenu } from '../modules/ui/fileContextMenu';
import { initSftpContextMenuHandler } from '../modules/ui/sftpContextMenuHandler';
import '../modules/ui/sftpDetailPanel'; // 导入即注册 openSftpDetail 等 window 函数
import { initSftpSharedFunctions } from '../modules/ui/sftpGlobalFunctions';

/** 正式包 drop 掉 console，诊断信息只有进 logger 才留得下来（状态栏「日志」按钮可导出） */
const log = logger.module('SFTPEntry');

const APP_MARKUP = `
  <div class="modern-title-bar" data-tauri-drag-region id="custom-title-bar">
    <div class="title-bar-left">
      <div class="app-logo">
        <div class="logo-icon" style="width: 24px; height: 24px; display: flex; align-items: center; justify-content: center;">
          <svg width="22" height="22" viewBox="0 0 128 128" xmlns="http://www.w3.org/2000/svg">
            <defs>
              <linearGradient id="sftp-s" x1=".1" y1="0" x2=".9" y2="1"><stop offset="0" style="stop-color: var(--brand-logo-a, #f9a8d4)"/><stop offset="1" style="stop-color: var(--brand-logo-b, #c4b5fd)"/></linearGradient>
              <linearGradient id="sftp-h" x1=".36" y1="0" x2=".5" y2=".5"><stop offset="0" stop-color="#fff" stop-opacity=".5"/><stop offset="1" stop-color="#fff" stop-opacity="0"/></linearGradient>
            </defs>
            <g transform="rotate(-15 64 62)">
              <path d="M64,16 L75.8,47.8 L109.2,48.8 L83.2,68.8 L93,101.2 L64,83.2 L35,101.2 L44.8,68.8 L18.8,48.8 L52.2,47.8 Z" fill="url(#sftp-s)" stroke="url(#sftp-s)" stroke-width="12" stroke-linejoin="round" paint-order="stroke fill"/>
              <path d="M64,16 L75.8,47.8 L109.2,48.8 L83.2,68.8 L93,101.2 L64,83.2 L35,101.2 L44.8,68.8 L18.8,48.8 L52.2,47.8 Z" fill="url(#sftp-h)" stroke="url(#sftp-h)" stroke-width="12" stroke-linejoin="round" paint-order="stroke fill"/>
            </g>
          </svg>
        </div>
        <div class="app-info">
          <div class="app-name" style="font-size: 14px;">SFTP 文件管理</div>
          <div style="font-size: 9px; color: var(--text-tertiary);">LovelyRes</div>
        </div>
      </div>
    </div>
    <div class="title-bar-right" id="window-controls-container"></div>
  </div>
  <div id="sftp-window-content" class="sftp-window-content"></div>
`;

function setupWindowControls(): void {
  const isMacOS = navigator.platform.toUpperCase().indexOf('MAC') >= 0;
  const customTitleBar = document.getElementById('custom-title-bar');
  const content = document.getElementById('sftp-window-content');

  if (isMacOS) {
    if (customTitleBar) customTitleBar.style.display = 'none';
    if (content) content.style.height = '100vh';
  } else {
    if (content) content.style.height = 'calc(100vh - 45px)';
    const container = document.getElementById('window-controls-container');
    if (container) {
      container.innerHTML = `
        <button class="control-button minimize-btn" title="最小化">
          <svg width="12" height="12" viewBox="0 0 12 12" fill="currentColor"><rect x="2" y="5.5" width="8" height="1"/></svg>
        </button>
        <button class="control-button maximize-btn" title="最大化">
          <svg width="12" height="12" viewBox="0 0 12 12" fill="currentColor"><rect x="2" y="2" width="8" height="8" stroke="currentColor" stroke-width="1" fill="none"/></svg>
        </button>
        <button class="control-button close-btn close" title="关闭">
          <svg width="12" height="12" viewBox="0 0 12 12" fill="currentColor"><path d="M2.5 2.5L9.5 9.5M9.5 2.5L2.5 9.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
        </button>
      `;
      container.querySelector('.minimize-btn')?.addEventListener('click', () => {
        getCurrentWebviewWindow().minimize().catch((e) => log.error('最小化窗口失败:', e));
      });
      container.querySelector('.maximize-btn')?.addEventListener('click', () => {
        getCurrentWebviewWindow().toggleMaximize().catch((e) => log.error('切换最大化状态失败:', e));
      });
      container.querySelector('.close-btn')?.addEventListener('click', () => {
        getCurrentWebviewWindow().destroy().catch((e) => log.error('关闭窗口失败:', e));
      });
    }
  }
}

function applyTheme(theme: string): void {
  document.body.setAttribute('data-theme', theme);
  document.documentElement.setAttribute('data-theme', theme);
  document.body.classList.remove('light-theme', 'dark-theme', 'sakura-theme');
  document.body.classList.add(`${theme}-theme`);
}

async function initializeTheme(): Promise<void> {
  try {
    const themeSettings = await invoke<any>('get_theme_settings');
    // 后端值可能是已移除的历史主题，落到三套有效主题上
    const raw = themeSettings?.current_theme;
    applyTheme(['light', 'dark', 'sakura'].includes(raw) ? raw : 'dark');
  } catch (error) {
    log.error('主题初始化失败:', error);
    applyTheme('dark');
    return;
  }
  // 监听注册失败（如 event 权限缺失）只影响后续主题联动，
  // 绝不能覆盖上面已应用的主题
  try {
    await listen('theme-changed', (event) => {
      const t = event.payload as string;
      if (['light', 'dark', 'sakura'].includes(t)) applyTheme(t);
    });
    log.debug('主题初始化完成');
  } catch (error) {
    log.warn('主题变更监听注册失败:', error);
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
    }
  } catch (error) {
    log.error('SFTP 窗口字体设置初始化失败:', error);
  }
}

/** 用现有数据/空态渲染列表区域（未连接时给出明确指引） */
function renderExistingFiles(connected: boolean): void {
  const sftpFileList = document.getElementById('sftp-file-list');
  if (sftpFileList) {
    sftpFileList.innerHTML = connected
      ? sftpManager.renderFileListHTML()
      : `<tr><td colspan="8" class="sftp-placeholder-cell"><div class="sftp-placeholder"><span>未连接服务器。请在主窗口建立 SSH 连接后，点击右上角「刷新」。</span></div></td></tr>`;
  }
  const breadcrumb = document.getElementById('sftp-breadcrumb');
  if (breadcrumb) breadcrumb.innerHTML = sftpManager.renderBreadcrumbHTML();
  const pathInput = document.getElementById('sftp-path-input') as HTMLInputElement;
  if (pathInput) pathInput.value = sftpManager.getCurrentPath();
  sftpManager.updateSortIndicators();
}

/** 更新头部连接状态 chip */
function updateConnChip(connected: boolean): void {
  const chip = document.querySelector('.sftp-chip-conn');
  if (!chip) return;
  chip.classList.toggle('is-on', connected);
  chip.classList.toggle('is-off', !connected);
  chip.textContent = connected ? '已连接' : '未连接';
}

function registerWindowFunctions(): void {
  // 弹窗与右键菜单（与主窗口 bootstrap 时挂在 window 上的名称保持一致）
  (window as any).uploadModal = new UploadModal();
  (window as any).createFolderModal = new CreateFolderModal();
  (window as any).compressModal = new CompressModal();
  (window as any).extractModal = new ExtractModal();
  (window as any).permissionsModal = new PermissionsModal();
  (window as any).fileViewerModal = new FileViewerModal();
  (window as any).fileContextMenu = new FileContextMenu();

  // 管理器（上下文菜单/共享函数按名读取）
  (window as any).sftpManager = sftpManager;
  (window as any).sshConnectionManager = sshConnectionManager;
  (window as any).remoteOperationsManager = remoteOperationsManager;
  (window as any).sshTerminalManager = sshTerminalManager;

  initSftpSharedFunctions();
  initSftpContextMenuHandler();

  // 页面初始化（renderRemoteOperationsPage 的 100ms 延迟回调会调用它）
  let inited = false;
  (window as any).initRemoteOperationsPage = async () => {
    if (inited) return;
    inited = true;

    await remoteOperationsManager.initialize();
    await sshConnectionManager.checkConnectionStatus();
    const status = sshConnectionManager.getConnectionStatus();
    updateConnChip(!!status?.connected);

    if (status?.connected && sftpManager.getCurrentFiles().length === 0) {
      await sftpManager.refreshFileList();
    } else {
      renderExistingFiles(!!status?.connected);
    }

    sftpManager.addListener((_files, path) => {
      const pathInput = document.getElementById('sftp-path-input') as HTMLInputElement;
      if (pathInput) pathInput.value = path;

      const breadcrumb = document.getElementById('sftp-breadcrumb');
      if (breadcrumb) breadcrumb.innerHTML = sftpManager.renderBreadcrumbHTML();

      const sftpFileList = document.getElementById('sftp-file-list');
      if (sftpFileList) sftpFileList.innerHTML = sftpManager.renderFileListHTML();

      sftpManager.updateSortIndicators();
    });
  };
}

/** 主窗口的连接动作发生在另一个 JS 上下文，本窗口不会收到事件；
 *  在窗口重新获得焦点时校准一次连接状态即可。 */
function bindFocusSync(): void {
  window.addEventListener('focus', () => {
    sshConnectionManager.checkConnectionStatus()
      .then(async () => {
        const connected = !!sshConnectionManager.getConnectionStatus()?.connected;
        updateConnChip(connected);
        const targetChanged = sftpManager.synchronizeTarget();
        if (!connected) {
          renderExistingFiles(false);
        } else if (targetChanged) {
          await sftpManager.refreshFileList();
        }
      })
      .catch((e) => log.warn('焦点同步连接状态失败:', e));
  });
}

/** 跨窗口"定位到目录"承接：启动时消费 pending-path，之后监听即时导航事件 */
async function initNavigateBridge(): Promise<void> {
  const { SFTP_PENDING_PATH_KEY, SFTP_NAVIGATE_EVENT } = await import('../modules/remote/sftpWindowBridge');

  try {
    const pending = localStorage.getItem(SFTP_PENDING_PATH_KEY);
    if (pending) {
      localStorage.removeItem(SFTP_PENDING_PATH_KEY);
      // 等首屏初始化（连接检查）完成后再导航，避免未连接时误报
      setTimeout(() => { void sftpManager.navigateToPath(pending); }, 600);
    }
  } catch { /* intentional: localStorage 不可用时仅依赖事件通道 */ }

  try {
    await listen(SFTP_NAVIGATE_EVENT, (event) => {
      const p = (event.payload as { path?: string })?.path;
      if (typeof p === 'string' && p) {
        try { localStorage.removeItem(SFTP_PENDING_PATH_KEY); } catch { /* intentional: 清理失败不影响导航 */ }
        void sftpManager.navigateToPath(p);
      }
    });
  } catch (error) {
    // event 权限缺失时仅失去即时导航，pending-path 通道仍可用
    log.warn('导航事件监听注册失败:', error);
  }
}

export function bootSftpWindow(): void {
  document.body.classList.add('sftp-window');
  // 移除主应用的初始加载屏（SFTP 窗口不需要）
  document.getElementById('loading-screen')?.remove();
  const appEl = document.getElementById('app') || document.body;
  appEl.innerHTML = APP_MARKUP;

  setupWindowControls();
  initNotificationManager();
  registerWindowFunctions();
  bindFocusSync();
  void initNavigateBridge();

  // 渲染 SFTP 页面（与主窗口同一渲染函数；state 快照需先就位）
  const stateManager = new StateManager();
  const status = sshConnectionManager.getConnectionStatus();
  stateManager.setConnected(!!status?.connected, status?.host);
  const renderer = new ModernUIRenderer(stateManager);
  const content = document.getElementById('sftp-window-content');
  if (content) {
    content.innerHTML = renderer.renderRemoteOperationsPage();
  }

  void initializeTheme();
  void initializeFontSettings();

  log.debug('SFTP 文件管理窗口已初始化（单入口）');
}
