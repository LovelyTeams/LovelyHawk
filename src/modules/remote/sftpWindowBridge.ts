/**
 * SFTP 独立窗口桥（主窗口侧）
 *
 * 打开/聚焦 SFTP 窗口，以及"定位到指定目录"的跨窗口导航：
 * 新开窗口经 localStorage 的 pending-path 承接（启动后消费），
 * 已开窗口经 Tauri 事件 'sftp:navigate' 即时导航，两条通道互为备份。
 */

import { logger } from '../core/logger';
/** 正式包 drop 掉 console，诊断信息只有进 logger 才留得下来（状态栏「日志」按钮可导出） */
const log = logger.module('SFTPBridge');

export const SFTP_PENDING_PATH_KEY = 'sftp-pending-path';
export const SFTP_NAVIGATE_EVENT = 'sftp:navigate';

/**
 * 在新窗口中打开 SFTP 文件管理（已开则聚焦）
 */
export async function openSftpWindow(): Promise<void> {
  try {
    const { WebviewWindow } = await import('@tauri-apps/api/webviewWindow');
    const existingWindow = await WebviewWindow.getByLabel('sftp');
    if (existingWindow) {
      await existingWindow.setFocus();
      await existingWindow.unminimize();
      return;
    }

    const isMacOS = navigator.platform.toUpperCase().indexOf('MAC') >= 0;
    const sftpWindow = new WebviewWindow('sftp', {
      url: 'index.html?window=sftp',
      title: 'SFTP 文件管理 - LovelyRes',
      width: 1100,
      height: 720,
      minWidth: 720,
      minHeight: 480,
      resizable: true,
      maximizable: true,
      minimizable: true,
      closable: true,
      center: true,
      decorations: isMacOS,
      alwaysOnTop: false,
      skipTaskbar: false
    });

    sftpWindow.once('tauri://error', (error) => log.error('SFTP 窗口创建错误:', error));
  } catch (error) {
    log.error('创建 SFTP 窗口失败:', error);

    try {
      const { WebviewWindow } = await import('@tauri-apps/api/webviewWindow');
      const existingWindow = await WebviewWindow.getByLabel('sftp');
      if (existingWindow) {
        await existingWindow.setFocus();
        await existingWindow.unminimize();
        return;
      }
    } catch (focusError) {
      log.error('聚焦 SFTP 窗口失败:', focusError);
    }

    const fallbackWindow = window.open(
      '/?window=sftp',
      'sftp',
      'width=1100,height=720,resizable=yes,scrollbars=yes,status=yes'
    );
    if (!fallbackWindow) {
      window.showNotification?.('无法打开 SFTP 窗口', 'error');
    }
  }
}

/**
 * 打开 SFTP 窗口并定位到指定目录（窗口已开则聚焦后立即导航）
 */
export async function openSftpAt(dir: string): Promise<void> {
  try { localStorage.setItem(SFTP_PENDING_PATH_KEY, dir); } catch { /* intentional: localStorage 不可用时仅依赖事件通道 */ }
  await openSftpWindow();
  // 已开窗口：事件通道即时导航；新开窗口由 pending-path 在启动后消费（双保险）
  setTimeout(() => {
    import('@tauri-apps/api/event')
      .then(({ emit }) => emit(SFTP_NAVIGATE_EVENT, { path: dir }))
      .catch((e) => log.warn('SFTP 导航事件发送失败:', e));
  }, 700);
}
