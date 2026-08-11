/**
 * 全局函数注册模块
 * 将 (window as any).xxx = ... 集中管理
 *
 * 从 main.ts 提取，原位置: 第 204–510 行
 * 这些函数是 HTML 模板中 onclick 等属性所需要的全局入口点，
 * 暂时保留 (window as any) 方式，后续可逐步迁移到 eventBus。
 */

import type { LovelyResApp } from '../core/app';
import { showPrompt } from './confirmDialog';
import './sftpDetailPanel'; // 注册 SFTP 文件详情侧栏的 window 函数
import { initSftpSharedFunctions } from './sftpGlobalFunctions';
import { sftpManager } from '../remote/sftpManager';
import { sshConnectionManager } from '../remote/sshConnectionManager';
import { sshConnectionDialog } from '../ui/sshConnectionDialog';
import { remoteOperationsManager } from '../remote/remoteOperationsManager';
import { dockerPageManager } from '../docker/dockerPageManager';
import { emergencyPageManager } from '../emergency/emergencyPageManager';
import { KubernetesPageManager } from '../kubernetes/kubernetesPageManager';
import { quickDetectionManager } from '../detection/quickDetectionManager';
import { quickDetectionPageController } from '../detection/quickDetectionPageController';
import { sshTerminalManager } from '../ssh/sshTerminalManager';
import type { SettingsPageManager } from '../settings/settingsPageManager';
import {
  targetCapabilityStore,
  type CapabilityAwareFeature,
} from '../core/targetCapabilities';

import { logger } from '../core/logger';
/** 正式包 drop 掉 console，诊断信息只有进 logger 才留得下来（状态栏「日志」按钮可导出） */
const log = logger.module('GlobalFn');


interface GlobalFunctionsDeps {
  app: LovelyResApp;
  settingsPageManager: SettingsPageManager;
  openSSHTerminalWindow: () => Promise<void>;
  openSftpWindow: () => Promise<void>;
}

let globalEventsBound = false;
let sftpListenerBound = false;
let settingsEscapeHandler: ((event: KeyboardEvent) => void) | null = null;

const PAGE_CAPABILITY_FEATURES: Partial<Record<string, CapabilityAwareFeature>> = {
  'system-info': 'system-info',
  'log-analysis': 'log-analysis',
  'packet-capture': 'packet-capture',
  firewall: 'firewall',
  docker: 'docker',
  kubernetes: 'kubernetes',
  'baseline-quick-edit': 'baseline-mutation',
};

function renderTargetCapabilityNotice(pageId: string): void {
  document.querySelector('[data-target-capability-notice]')?.remove();
  const feature = PAGE_CAPABILITY_FEATURES[pageId];
  const result = feature ? targetCapabilityStore.evaluate(feature) : null;
  if (!result || result.available) return;

  const workspace = document.querySelector<HTMLElement>('.main-workspace');
  if (!workspace) return;
  const notice = document.createElement('div');
  notice.dataset.targetCapabilityNotice = feature;
  notice.setAttribute('role', 'status');
  notice.style.cssText = 'margin:12px 16px;padding:10px 12px;border:1px solid var(--color-warning,#d99a24);border-radius:8px;background:color-mix(in srgb,var(--color-warning,#d99a24) 12%,transparent);font-size:13px;';
  notice.textContent = `当前目标能力不足：${result.reason}。替代方案：${result.alternative}`;
  workspace.prepend(notice);
}

/**
 * 注册所有全局函数到 window 对象
 */
export function initGlobalFunctions(deps: GlobalFunctionsDeps): void {
  const { app, settingsPageManager, openSSHTerminalWindow, openSftpWindow } = deps;

  // 账号 / 口令处置面板（供检测报告的用户类 Finding 按钮调起）
  import('../detection/userDisposal').then(({ userDisposal }) => {
    (window as any).userDisposal = userDisposal;
  }).catch(() => { /* ignore */ });

  // ──── 侧边栏：折叠/展开（52px 轨道模式）────
  (window as any).toggleSidebar = () => {
    const nav = document.querySelector('.sidebar-nav');
    if (!nav) return;
    nav.classList.toggle('collapsed');
    localStorage.setItem('sidebar-collapsed', nav.classList.contains('collapsed') ? '1' : '0');
  };

  // ──── 侧边栏：分组折叠/展开（智能折叠）────
  // 规则：展开 ⟺ 用户显式展开 ∥（含当前页 ∧ 未被用户显式收起）。
  // 显式展开记 sidebar-groups-open；显式收起的"当前组"记
  // sidebar-groups-active-closed（切页时清除，新页的组自动展开）。
  const OPEN_GROUPS_KEY = 'sidebar-groups-open';
  const ACTIVE_CLOSED_KEY = 'sidebar-groups-active-closed';

  function readOpenGroups(): string[] {
    try {
      const v = JSON.parse(localStorage.getItem(OPEN_GROUPS_KEY) || '[]');
      return Array.isArray(v) ? v : [];
    } catch { return []; }
  }

  // 从 DOM 现状回写两份持久化状态（手动开合分组后调用）
  function persistOpenGroups(): void {
    const open: string[] = [];
    let activeClosed: string | null = null;
    document.querySelectorAll('.sidebar-group').forEach(g => {
      const el = g as HTMLElement;
      const id = el.getAttribute('data-group-id');
      if (!id) return;
      const hasActive = !!el.querySelector('.sidebar-item.active');
      const isOpen = el.classList.contains('open');
      if (isOpen && !hasActive) open.push(id);
      if (!isOpen && hasActive) activeClosed = id;
    });
    localStorage.setItem(OPEN_GROUPS_KEY, JSON.stringify(open));
    if (activeClosed) localStorage.setItem(ACTIVE_CLOSED_KEY, activeClosed);
    else localStorage.removeItem(ACTIVE_CLOSED_KEY);
  }

  // 统一施加开合规则 + 组行高亮；切页/重渲/搜索清空后都走这里
  function syncSidebarGroups(): void {
    const opened = readOpenGroups();
    const activeClosed = localStorage.getItem(ACTIVE_CLOSED_KEY);
    document.querySelectorAll('.sidebar-group').forEach(g => {
      const el = g as HTMLElement;
      const id = el.getAttribute('data-group-id');
      const hasActive = !!el.querySelector('.sidebar-item.active');
      el.classList.toggle('open', (!!id && opened.includes(id)) || (hasActive && id !== activeClosed));
      el.querySelector('.sidebar-group-row')?.classList.toggle('active', hasActive);
    });
  }
  // 兼容旧名（app.ts / systemInfoTabManager.ts 通过 window 调用）
  (window as any).syncSidebarActiveGroup = syncSidebarGroups;

  (window as any).toggleSidebarGroup = (groupId: string) => {
    const nav = document.querySelector('.sidebar-nav');
    // 轨道（折叠）模式下点击分组：先展开整条侧边栏，再确保该组打开
    if (nav && nav.classList.contains('collapsed')) {
      nav.classList.remove('collapsed');
      localStorage.setItem('sidebar-collapsed', '0');
      document.querySelector(`.sidebar-group[data-group-id="${groupId}"]`)?.classList.add('open');
      persistOpenGroups();
      return;
    }
    const grp = document.querySelector(`.sidebar-group[data-group-id="${groupId}"]`);
    if (!grp) return;
    // 任何分组都可开可合；含当前页的组被显式收起后，切页前保持收起
    grp.classList.toggle('open');
    persistOpenGroups();
  };

  // ──── 侧边栏：搜索过滤 ────
  (window as any).filterSidebar = (query: string) => {
    const q = (query || '').trim().toLowerCase();
    document.querySelectorAll('.sidebar-group').forEach(group => {
      const g = group as HTMLElement;
      let anyVisible = false;
      g.querySelectorAll('.sidebar-item').forEach(item => {
        const el = item as HTMLElement;
        const text = (el.querySelector('.sidebar-item-label')?.textContent || '').toLowerCase();
        const match = q === '' || text.includes(q);
        el.hidden = !match;
        if (match) anyVisible = true;
      });
      // 子段标签：段内没有可见项时一并隐藏，避免残留孤标题
      g.querySelectorAll('.sidebar-itemsec').forEach(sec => {
        let sib = sec.nextElementSibling;
        let any = false;
        while (sib && !sib.classList.contains('sidebar-itemsec')) {
          if (sib.classList.contains('sidebar-item') && !(sib as HTMLElement).hidden) any = true;
          sib = sib.nextElementSibling;
        }
        (sec as HTMLElement).hidden = q !== '' && !any;
      });
      g.hidden = q !== '' && !anyVisible;
      if (q !== '') g.classList.toggle('open', anyVisible);
    });
    if (q === '') applySidebarState();
  };

  // 施加持久化的侧边栏状态（折叠轨道 + 智能折叠分组）；每次侧边栏渲染后调用
  function applySidebarState(): void {
    const nav = document.querySelector('.sidebar-nav');
    if (!nav) return;
    nav.classList.toggle('collapsed', localStorage.getItem('sidebar-collapsed') === '1');
    // 旧键迁移：「默认全展开」时代的显式收起列表在智能折叠下无意义，直接废弃
    localStorage.removeItem('sidebar-groups-closed');
    syncSidebarGroups();
  }
  (window as any).applySidebarState = applySidebarState;

  // 首次渲染后恢复侧边栏状态
  requestAnimationFrame(() => applySidebarState());

  // ──── SFTP 面板全局函数 ────
  // 注册逻辑与 SFTP 独立窗口共用（src/modules/ui/sftpGlobalFunctions.ts）
  initSftpSharedFunctions();

  // ──── 暴露管理器到全局 ────
  (window as any).remoteOperationsManager = remoteOperationsManager;
  (window as any).sshConnectionManager = sshConnectionManager;
  (window as any).sftpManager = sftpManager;
  (window as any).sshTerminalManager = sshTerminalManager;
  // 快速检测页与检测报告弹窗的 onclick 全部走 window.quickDetection.*,这一行是它们唯一的入口
  (window as any).quickDetection = quickDetectionManager;
  (window as any).sshConnectionDialog = sshConnectionDialog;

  if (!globalEventsBound) {
    // 预留给其他全局事件
  }

  // ──── 工作区/侧边栏刷新 ────
  (window as any).refreshDashboard = () => {
    try {
      if (app) {
        const mainWorkspace = document.querySelector('.main-workspace');
        if (mainWorkspace) {
          mainWorkspace.innerHTML = app.getStateManager().getUIRenderer().renderMainWorkspace();
        }
      }
    } catch (error) {
      log.error('刷新工作区失败:', error);
    }
  };

  (window as any).refreshSidebar = () => {
    try {
      if (!app) return;
      const sidebar = document.querySelector('.sidebar-nav');
      if (!sidebar) return;
      const sidebarHTML = app.getStateManager().getUIRenderer().renderSidebar();
      const tempDiv = document.createElement('div');
      tempDiv.innerHTML = sidebarHTML;
      const fresh = tempDiv.querySelector('.sidebar-nav');
      if (fresh) sidebar.replaceWith(fresh);
      applySidebarState();
    } catch (error) {
      log.error('刷新侧边栏失败:', error);
    }
  };

  // ──── 开发者工具 ────
  (window as any).toggleDevTools = async () => {
    try {
      await (window as any).__TAURI__.core.invoke('open_devtools');
      window.showNotification && window.showNotification('开发者工具已打开', 'success');
    } catch (error) {
      window.showNotification && window.showNotification(`打开开发者工具失败: ${error}`, 'error');
    }
  };

  // ──── 页面切换 ────
  let remoteOperationsPageInitialized = false;
  (window as any).switchPage = (pageId: string) => {
    log.debug('切换页面:', pageId);

    // 取消前一个页面的异步操作:离开快速检测页时中止正在跑的扫描,
    // 否则并发的 SSH 请求会继续占用连接并向已销毁的 DOM 写结果。
    if (pageId !== 'quick-detection') {
      quickDetectionManager.cancelScan();
    }

    // SFTP 已迁移至独立窗口：直接打开窗口，主窗口页面保持不变
    if (pageId === 'remote-operations') {
      const result = targetCapabilityStore.evaluate('sftp');
      if (result && !result.available) {
        window.showNotification?.(`${result.reason}；${result.alternative}`, 'warning');
        return;
      }
      void openSftpWindow();
      return;
    }

    // SFTP: 切走时标记需要重新绑定DOM事件，但不丢弃数据
    if (pageId !== 'remote-operations') {
      remoteOperationsPageInitialized = false;
    }

    // 切页后新当前组自动展开：清除上一页"显式收起当前组"的标记
    if (app?.getStateManager()?.getState()?.currentPage !== pageId) {
      localStorage.removeItem(ACTIVE_CLOSED_KEY);
    }

    document.querySelectorAll('.sidebar-item[data-nav-id], .activity-bar-item[data-nav-id], .nav-item[data-nav-id]').forEach(item => {
      const htmlItem = item as HTMLElement;
      const navId = htmlItem.getAttribute('data-nav-id');
      htmlItem.classList.toggle('active', navId === pageId);
    });
    syncSidebarGroups();

    const sm = app.getStateManager();
    if (app && sm) {
      const prevPage = sm.getState()?.currentPage;
      sm.setCurrentPage(pageId as any);
      app.render();
      setTimeout(() => renderTargetCapabilityNotice(pageId), 0);
      // 进出带「上下文分组」的页面时重渲主侧边栏，以并入/移除其上下文分组
      const CTX_PAGES = ['system-info', 'remote-operations'];
      if (prevPage !== pageId && (CTX_PAGES.includes(prevPage as string) || CTX_PAGES.includes(pageId))) {
        (window as any).refreshSidebar && (window as any).refreshSidebar();
      }

      if (pageId === 'docker') {
        // initialize is already called inside renderDockerPage()
        // Use setTimeout to ensure DOM is mounted before refresh
        setTimeout(() => dockerPageManager.refresh(true), 50);
      } else if (pageId === 'emergency-commands') {
        emergencyPageManager.initialize();
      } else if (pageId === 'log-analysis') {
        setTimeout(() => { (window as any).refreshLogAnalysis(); }, 200);
      } else if (pageId === 'settings') {
        setTimeout(() => { settingsPageManager.initialize(); }, 100);
      } else if (pageId === 'web-terminal') {
        (window as any).openWebTerminal?.();
        return;
      } else if (pageId === 'ssh-terminal') {
        const result = targetCapabilityStore.evaluate('terminal');
        if (result && !result.available) {
          window.showNotification?.(`${result.reason}；${result.alternative}`, 'warning');
          setTimeout(() => {
            const sm2 = app?.getStateManager();
            if (app && sm2) {
              sm2.setCurrentPage('system-info');
              app.render();
              renderTargetCapabilityNotice('system-info');
            }
          }, 0);
          return;
        }
        openSSHTerminalWindow();
        setTimeout(() => {
          const sm2 = app?.getStateManager();
          if (app && sm2) {
            sm2.setCurrentPage('system-info');
            app.render();
          }
        }, 100);
      } else if (pageId === 'kubernetes') {
        // Lazy init K8s page manager
        if (!(window as any).kubernetesPageManager) {
          const appObj = (window as any).app;
          if (appObj?.kubernetesManager && appObj?.kubernetesEmergencyManager && appObj?.kubernetesSecurityAuditor) {
            const renderer = appObj.modernUIRenderer?.kubernetesRenderer;
            if (renderer) {
              const kpm = new KubernetesPageManager(
                appObj.kubernetesManager,
                appObj.kubernetesEmergencyManager,
                appObj.kubernetesSecurityAuditor,
                renderer
              );
              (window as any).kubernetesPageManager = kpm;
            }
          }
        }
        const kpm = (window as any).kubernetesPageManager;
        if (kpm) {
          kpm.initialize();
          kpm.refresh(true);
        }
      } else if (pageId === 'baseline-quick-edit') {
        // Lazy init baseline quick edit manager
        if (!(window as any).baselineQuickEditManager) {
          import('../baseline/baselineQuickEditManager').then(({ BaselineQuickEditManager }) => {
            (window as any).baselineQuickEditManager = new BaselineQuickEditManager();
            (window as any).baselineQuickEditManager.initialize();
          }).catch((e) => {
            log.error('加载基线模块失败:', e);
            window.showNotification?.('加载基线模块失败', 'error');
          });
        } else {
          (window as any).baselineQuickEditManager.initialize();
        }
      } else if (pageId === 'database') {
        // Lazy init database manager
        import('./databaseManager').then(({ databaseManager }) => {
          databaseManager.initialize();
        }).catch((e) => {
          log.error('加载数据库模块失败:', e);
          window.showNotification?.('加载数据库模块失败', 'error');
        });
      } else if (pageId === 'java-hot-update') {
        import('../javaHotUpdate/javaHotUpdateManager').then(({ javaHotUpdateManager }) => {
          javaHotUpdateManager.initialize();
        }).catch((e) => {
          log.error('加载Java热更新模块失败:', e);
          window.showNotification?.('加载Java热更新模块失败', 'error');
        });
      } else if (pageId === 'notes') {
        import('../notes/notesManager').then(({ notesManager }) => {
          notesManager.initialize();
        }).catch((e) => {
          log.error('加载笔记模块失败:', e);
          window.showNotification?.('加载笔记模块失败', 'error');
        });
      } else if (pageId === 'secfix') {
        import('../secfix/secfixManager').then(({ secfixManager }) => {
          secfixManager.initialize();
        }).catch((e) => {
          log.error('加载安全速查模块失败:', e);
          window.showNotification?.('加载安全速查模块失败', 'error');
          });
      } else if (pageId === 'quick-detection') {
        quickDetectionPageController.initialize();
      } else if (pageId === 'check-audit') {
        import('../checkAudit/checkAuditManager').then(({ checkAuditManager }) => {
          checkAuditManager.initialize();
        }).catch((e) => {
          log.error('加载Check审计模块失败:', e);
          window.showNotification?.('加载Check审计模块失败', 'error');
        });
      } else if (pageId === 'ai-history') {
        import('../ai/aiHistoryManager').then(({ aiHistoryManager }) => {
          aiHistoryManager.initialize();
        }).catch((e) => {
          log.error('加载AI历史模块失败:', e);
          window.showNotification?.('加载AI历史模块失败', 'error');
        });
      } else if (pageId === 'snapshot') {
        import('../snapshot/snapshotManager').then(({ snapshotManager }) => {
          snapshotManager.initialize();
        }).catch((e) => {
          log.error('加载快照回滚模块失败:', e);
          window.showNotification?.('加载快照回滚模块失败', 'error');
        });
      } else if (pageId === 'firewall') {
        import('../firewall/firewallManager').then(({ firewallManager }) => {
          firewallManager.initialize();
        }).catch((e) => {
          log.error('加载防火墙模块失败:', e);
          window.showNotification?.('加载防火墙模块失败', 'error');
        });
      } else if (pageId === 'integrity') {
        import('../integrity/integrityManager').then(({ integrityManager }) => {
          integrityManager.initialize();
        }).catch((e) => {
          log.error('加载文件完整性模块失败:', e);
          window.showNotification?.('加载文件完整性模块失败', 'error');
        });
      } else if (pageId === 'batch-servers') {
        import('../server/batchServerPageManager').then(({ batchServerPageManager }) => {
          batchServerPageManager.initialize();
        }).catch((e) => {
          log.error('加载多机批量模块失败:', e);
          window.showNotification?.('加载多机批量模块失败', 'error');
        });
      }

      // 离开 Docker/K8s/PacketCapture 页面时停止后台操作
      if (pageId !== 'docker') dockerPageManager.deactivate();
      if (pageId !== 'kubernetes') {
        const kpm = (window as any).kubernetesPageManager;
        if (kpm) kpm.deactivate();
      }
      if (pageId !== 'packet-capture') {
        const renderer = (window as any).app?.modernUIRenderer?.packetCaptureRenderer;
        if (renderer) renderer.destroy();
      }
      if (pageId !== 'java-hot-update') {
        (window as any).__jhuManager?.deactivate?.();
      }

      // 系统概览：仅在无缓存时才重新加载
      if (pageId === 'system-info' && sshConnectionManager.isConnected()) {
        const cache = (window as any).systemInfoCache;
        if (cache && cache.detailedInfo) {
          // 有缓存，直接用缓存渲染，不重新请求
          (window as any).loadSystemDetailedInfo(false);
        }
      }
    }
  };

  // ──── SSH 连接对话框和设置覆盖层 ────
  (window as any).showSSHConnectionDialog = () => sshConnectionDialog.show();
  // 断线重连:先核对后端会话,否则打开连接对话框(见 sshConnectionManager.reconnect)
  (window as any).reconnectSSH = () => sshConnectionManager.reconnect();

  const closeSettingsOverlay = () => {
    const el = document.getElementById('settings-overlay-container');
    if (el) el.remove();
    if (settingsEscapeHandler) {
      document.removeEventListener('keydown', settingsEscapeHandler, true);
      settingsEscapeHandler = null;
    }
    settingsPageManager.resetEventBindings();
  };

  (window as any).showSettingsOverlay = () => {
    const renderer = (window as any).app?.modernUIRenderer;
    if (!app || !renderer) return;

    // Reopening settings must not leave duplicate IDs or listeners behind.
    closeSettingsOverlay();
    const settingsHTML = renderer.renderSettingsPage();
    const settingsOverlay = document.createElement('div');
    settingsOverlay.innerHTML = settingsHTML;
    settingsOverlay.id = 'settings-overlay-container';
    document.body.appendChild(settingsOverlay);

    const backdrop = settingsOverlay.querySelector('.settings-overlay');
    const closeButton = settingsOverlay.querySelector('.settings-close-btn');
    closeButton?.addEventListener('click', closeSettingsOverlay);
    backdrop?.addEventListener('click', (event) => {
      if (event.target === backdrop) closeSettingsOverlay();
    });

    settingsEscapeHandler = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;

      const providerModal = settingsOverlay.querySelector<HTMLElement>('#add-provider-modal');
      if (providerModal && getComputedStyle(providerModal).display !== 'none') {
        providerModal.style.display = 'none';
      } else {
        closeSettingsOverlay();
      }
      event.preventDefault();
      event.stopPropagation();
    };
    document.addEventListener('keydown', settingsEscapeHandler, true);

    requestAnimationFrame(() => {
      if (settingsOverlay.isConnected) void settingsPageManager.initialize();
    });
  };

  (window as any).hideSettingsOverlay = closeSettingsOverlay;

  // ──── 远程操作页面初始化 ────
  (window as any).initRemoteOperationsPage = async function () {
    if (remoteOperationsPageInitialized) return;
    remoteOperationsPageInitialized = true;
    await remoteOperationsManager.initialize();

    await sshConnectionManager.checkConnectionStatus();
    const connectionStatus = sshConnectionManager.getConnectionStatus();

    const hasExistingData = sftpManager.getCurrentFiles().length > 0;

    if (connectionStatus?.connected && !hasExistingData) {
      // 首次加载：请求文件列表
      await sftpManager.refreshFileList();
    } else {
      // 已有数据或未连接：直接用现有数据渲染
      const sftpFileList = document.getElementById('sftp-file-list');
      if (sftpFileList) sftpFileList.innerHTML = sftpManager.renderFileListHTML();
      const breadcrumb = document.getElementById('sftp-breadcrumb');
      if (breadcrumb) breadcrumb.innerHTML = sftpManager.renderBreadcrumbHTML();
      const pathInput = document.getElementById('sftp-path-input') as HTMLInputElement;
      if (pathInput) pathInput.value = sftpManager.getCurrentPath();
      sftpManager.updateSortIndicators();
    }

    // 修正排序下拉潜在的编码异常
    setTimeout(() => {
      try {
        const label = document.querySelector('label[for="sftp-sort-mode"]');
        if (label) label.textContent = '排序';
        const nameAsc = document.querySelector('#sftp-sort-mode option[value="name-asc"]') as HTMLOptionElement | null;
        if (nameAsc) nameAsc.textContent = '名称 A→Z';
        const nameDesc = document.querySelector('#sftp-sort-mode option[value="name-desc"]') as HTMLOptionElement | null;
        if (nameDesc) nameDesc.textContent = '名称 Z→A';
        const sizeAsc = document.querySelector('#sftp-sort-mode option[value="size-asc"]') as HTMLOptionElement | null;
        if (sizeAsc) sizeAsc.textContent = '大小 ↑';
        const sizeDesc = document.querySelector('#sftp-sort-mode option[value="size-desc"]') as HTMLOptionElement | null;
        if (sizeDesc) sizeDesc.textContent = '大小 ↓';
        const modifiedAsc = document.querySelector('#sftp-sort-mode option[value="modified-asc"]') as HTMLOptionElement | null;
        if (modifiedAsc) modifiedAsc.textContent = '修改时间 ↑';
        const modifiedDesc = document.querySelector('#sftp-sort-mode option[value="modified-desc"]') as HTMLOptionElement | null;
        if (modifiedDesc) modifiedDesc.textContent = '修改时间 ↓';
      } catch { }
    }, 0);

    if (!sftpListenerBound) {
    sftpListenerBound = true;
    sftpManager.addListener((_files, path) => {
      const pathInput = document.getElementById('sftp-path-input') as HTMLInputElement;
      if (pathInput) pathInput.value = path;

      // Update breadcrumb
      const breadcrumb = document.getElementById('sftp-breadcrumb');
      if (breadcrumb) breadcrumb.innerHTML = sftpManager.renderBreadcrumbHTML();

      // Render file list
      const sftpFileList = document.getElementById('sftp-file-list');
      if (sftpFileList) sftpFileList.innerHTML = sftpManager.renderFileListHTML();

      // Update sort indicators
      sftpManager.updateSortIndicators();

      const sortModeSelect = document.getElementById('sftp-sort-mode') as HTMLSelectElement;
      if (sortModeSelect) sortModeSelect.value = sftpManager.getSortMode();
    });
    } // end of !sftpListenerBound
  };

  // ──── 数据库管理 ────
  // databaseManager 通过事件委托 (data-db-action) 处理所有交互，无需额外全局函数

  // ──── 连接下拉菜单 ────
  (window as any).showConnectionDropdown = () => {
    const dropdown = document.getElementById('connection-dropdown');
    if (dropdown) {
      const card = document.querySelector('.connection-card');
      if (card) {
        const rect = card.getBoundingClientRect();
        dropdown.style.top = `${rect.bottom + 5}px`;
        dropdown.style.left = `${rect.left}px`;
        dropdown.style.minWidth = `${rect.width}px`;
      }
      dropdown.style.display = 'block';
      setTimeout(() => { dropdown.style.opacity = '1'; }, 10);
    }
  };

  (window as any).hideConnectionDropdown = () => {
    const dropdown = document.getElementById('connection-dropdown');
    if (dropdown) {
      dropdown.style.opacity = '0';
      setTimeout(() => { dropdown.style.display = 'none'; }, 200);
    }
  };

  // ──── Web 终端（新窗口打开） ────
  (window as any).openWebTerminal = async (url?: string) => {
    const { webTerminalManager } = await import('../remote/webTerminalManager');

    if (url) {
      await webTerminalManager.openUrl(url);
      return;
    }

    const input = await showPrompt({
      title: 'Web 终端',
      message: '输入 Web 终端 URL（在新窗口中打开）:',
      defaultValue: 'http://',
    });
    if (!input || input === 'http://') return;

    await webTerminalManager.openUrl(input);
  };

}
