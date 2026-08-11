/**
 * SFTP 共享 window 函数
 *
 * 主窗口（globalFunctions）与 SFTP 独立窗口（entries/sftpEntry）共用同一份
 * 注册逻辑：上传/新建/刷新/历史/排序/新建文件/完整性快照。
 * 弹窗类依赖（uploadModal/createFolderModal/fileContextMenu）由调用方在
 * window 上备好，这里只做读取，不做实例化。
 */

import { sftpManager } from '../remote/sftpManager';
import { showConfirm, showPrompt } from './confirmDialog';
import { createIconHTML } from './iconMapping';
import { shq } from '../core/shellEscape';
import { invokeTargetBoundSSH } from '../core/targetBoundSSH';

import { logger } from '../core/logger';
/** 正式包 drop 掉 console，诊断信息只有进 logger 才留得下来（状态栏「日志」按钮可导出） */
const log = logger.module('SFTPFns');

export function initSftpSharedFunctions(): void {
  // SFTP 当前目录内的客户端过滤（按文件名）
  (window as any).sftpFilterFiles = (query: string) => {
    const q = (query || '').trim().toLowerCase();
    document.querySelectorAll('#sftp-file-list .sftp-file-row').forEach(row => {
      const el = row as HTMLElement;
      const name = (el.querySelector('.file-name')?.textContent || '').toLowerCase();
      const isParent = el.classList.contains('parent-dir-item');
      el.style.display = (!q || isParent || name.includes(q)) ? '' : 'none';
    });
  };

  (window as any).sftpRefresh = () => {
    try {
      if (sftpManager && (sftpManager as any).refreshCurrentDirectory) {
        (sftpManager as any).refreshCurrentDirectory();
        window.showNotification && window.showNotification('文件列表已刷新', 'success');
      }
    } catch (e) {
      log.error('刷新失败:', e);
      window.showNotification && window.showNotification(`刷新失败: ${e}`, 'error');
    }
  };

  (window as any).sftpOpenUpload = () => {
    try {
      if (sftpManager && (sftpManager as any).getCurrentPath && (window as any).uploadModal) {
        (window as any).uploadModal.show((sftpManager as any).getCurrentPath());
      } else {
        window.showNotification && window.showNotification('上传窗口未初始化', 'error');
      }
    } catch (e) {
      log.error('打开上传对话框失败:', e);
      window.showNotification && window.showNotification(`打开上传对话框失败: ${e}`, 'error');
    }
  };

  (window as any).sftpOpenCreateFolder = () => {
    try {
      if (sftpManager && (sftpManager as any).getCurrentPath && (window as any).createFolderModal) {
        (window as any).createFolderModal.show((sftpManager as any).getCurrentPath());
      } else {
        window.showNotification && window.showNotification('新建文件夹窗口未初始化', 'error');
      }
    } catch (e) {
      log.error('打开新建文件夹对话框失败:', e);
      window.showNotification && window.showNotification(`打开新建文件夹失败: ${e}`, 'error');
    }
  };

  (window as any).toggleSftpHistory = () => {
    try {
      if ((window as any).fileContextMenu && (window as any).fileContextMenu.showHistoryModal) {
        (window as any).fileContextMenu.showHistoryModal();
      } else {
        window.showNotification && window.showNotification('文件分析历史窗口未初始化', 'error');
      }
    } catch (e) {
      log.error('显示历史记录失败:', e);
      window.showNotification && window.showNotification(`显示历史记录失败: ${e}`, 'error');
    }
  };

  (window as any).setSftpSortMode = (mode: 'name-asc' | 'name-desc' | 'size-asc' | 'size-desc' | 'modified-asc' | 'modified-desc') => {
    try {
      sftpManager.setSortMode(mode);
    } catch (e) {
      log.error('设置排序方式失败:', e);
      window.showNotification && window.showNotification(`设置排序方式失败: ${e}`, 'error');
    }
  };

  // ──── SFTP 新建文件 ────
  (window as any).sftpCreateFile = async () => {
    try {
      const currentPath = sftpManager.getCurrentPath();
      const fileName = await showPrompt({ title: '新建文件', message: '请输入文件名:', defaultValue: 'new_file.txt' });
      if (!fileName || !fileName.trim()) return;

      const fullPath = currentPath === '/'
        ? `/${fileName.trim()}`
        : `${currentPath}/${fileName.trim()}`;

      // Write empty file via existing sftp_write_file command
      invokeTargetBoundSSH('sftp_write_file', {
        path: fullPath,
        content: ''
      }).then(() => {
        window.showNotification && window.showNotification(`文件已创建: ${fileName}`, 'success');
        sftpManager.refreshCurrentDirectory();
      }).catch((e: any) => {
        window.showNotification && window.showNotification(`创建文件失败: ${e}`, 'error');
      });
    } catch (e) {
      log.error('创建文件失败:', e);
      window.showNotification && window.showNotification(`创建文件失败: ${e}`, 'error');
    }
  };

  // ──── SFTP 完整性快照 ────
  (window as any).sftpIntegritySnapshot = async () => {
    try {
      const currentPath = sftpManager.getCurrentPath();
      if (!(await showConfirm({ title: '完整性快照', message: `将为 ${currentPath} 目录生成文件哈希清单（md5sum），是否继续？` }))) return;

      window.showNotification && window.showNotification('正在生成完整性快照...', 'info');

      const cmd = `find ${shq(currentPath)} -maxdepth 1 -type f -exec md5sum {} \\; 2>/dev/null | sort -k2`;
      invokeTargetBoundSSH<{ output?: string; exit_code?: number }>('ssh_execute_command_direct', { command: cmd })
        .then((result) => {
          const output = result?.output || '(空目录或无文件)';
          if (typeof result?.exit_code === 'number' && result.exit_code !== 0) {
            window.showNotification && window.showNotification(`生成快照命令返回退出码 ${result.exit_code}`, 'warning');
          }
          // Show in modal（按钮走 addEventListener，不写内联 onclick）
          const modal = document.createElement('div');
          modal.className = 'modal-overlay';
          modal.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.5);z-index:10000;display:flex;align-items:center;justify-content:center;';
          modal.innerHTML = `
            <div style="background:var(--bg-primary);border-radius:12px;padding:24px;max-width:700px;width:90%;max-height:80vh;display:flex;flex-direction:column;border:1px solid var(--border-color);">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
                <h3 style="margin:0;font-size:16px;color:var(--text-primary);">${createIconHTML('🛡️', { size: 16 })} 文件完整性快照 — ${currentPath}</h3>
                <button class="snap-close-btn" style="background:none;border:none;color:var(--text-secondary);cursor:pointer;font-size:20px;">✕</button>
              </div>
              <div style="font-size:11px;color:var(--text-secondary);margin-bottom:12px;">
                生成时间: ${new Date().toLocaleString()} | 可复制保存，用于前后对比
              </div>
              <textarea readonly style="flex:1;min-height:300px;background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:8px;padding:12px;font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--text-primary);resize:vertical;">${output.replace(/</g, '&lt;')}</textarea>
              <div style="display:flex;gap:8px;margin-top:12px;justify-content:flex-end;">
                <button class="modern-btn secondary snap-copy-btn">${createIconHTML('📋', { size: 16 })} 复制</button>
                <button class="modern-btn primary snap-close-btn">关闭</button>
              </div>
            </div>
          `;
          document.body.appendChild(modal);
          modal.addEventListener('click', (e) => { if (e.target === modal) modal.remove(); });
          modal.querySelectorAll('.snap-close-btn').forEach(btn =>
            btn.addEventListener('click', () => modal.remove()));
          modal.querySelector('.snap-copy-btn')?.addEventListener('click', () => {
            const ta = modal.querySelector('textarea');
            if (!ta) return;
            navigator.clipboard.writeText(ta.value)
              .then(() => window.showNotification?.('已复制到剪贴板', 'success'))
              .catch(() => window.showNotification?.('复制失败', 'error'));
          });
          window.showNotification && window.showNotification('完整性快照已生成', 'success');
        })
        .catch((e: any) => {
          window.showNotification && window.showNotification(`生成快照失败: ${e}`, 'error');
        });
    } catch (e) {
      log.error('完整性快照失败:', e);
      window.showNotification && window.showNotification(`完整性快照失败: ${e}`, 'error');
    }
  };
}
