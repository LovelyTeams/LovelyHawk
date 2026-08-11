/**
 * 现代化UI渲染器
 * 负责渲染应用的各个UI组件
 */

import type { StateManager } from '../core/stateManager';
import type { AppState } from '../core/app';
import { version as APP_VERSION } from '../../../package.json';
import { KubernetesRenderer } from './kubernetesRenderer';
import { dockerPageManager } from '../docker/dockerPageManager';
import { SftpContextMenuRenderer } from './sftpContextMenu';
import { sftpManager } from '../remote/sftpManager';
import { LogAnalysisRenderer } from './logAnalysisRenderer';
import { DatabaseRenderer } from './databaseRenderer';
import { PacketCaptureRenderer } from './packetCaptureRenderer';
import { activeTargetContext } from '../core/targetContext';
import { escapeHtml } from '../core/htmlEscape';
import { incidentCaseManager } from '../case/incidentCaseManager';

import { SystemInfoRenderer } from './renderers/systemInfoRenderer';
import { ServerModalRenderer } from './renderers/serverModalRenderer';
import { EmergencyRenderer } from './renderers/emergencyRenderer';
import { BaselineRenderer } from './renderers/baselineRenderer';
import {
  SettingTwo,
  Whale,
  CheckOne,
  Plus,
  LinkInterrupt,
  Connection,
  Up,
  Home,
  Refresh,
  Upload,
  FolderPlus,
  History,
  // 快速检测图标
  Shield,
  FileText,
  System,
  SettingConfig,
  Left,
  Right,
  // 设置菜单图标
  Bug,
  Fire,
  // 笔记
  DocDetail,
  Terminal,
  ApplicationTwo,
  Robot,
  AutoFocus,
  Compass,
  DatabaseSearch,
  FileFocus,
  FileSearch,
  FolderProtection,
  Monitor,
  Radar,
  ShieldAdd,
  TargetTwo,
  Timeline,
  Trace,
  // SFTP 工具栏溢出菜单
  MoreOne
} from '@icon-park/svg';
import { createIconHTML, statusIcon } from './iconMapping';

// 添加系统信息页面的样式
const systemInfoStyles = `
  <style>
    /* 基础样式已移至 system-info.css */
  </style>
`;

export class ModernUIRenderer {
  private stateManager: StateManager;
  private state: AppState;
  public kubernetesRenderer: KubernetesRenderer;
  private logAnalysisRenderer: LogAnalysisRenderer;

  public sftpContextMenuRenderer: SftpContextMenuRenderer;
  public databaseRenderer: DatabaseRenderer;
  public packetCaptureRenderer: PacketCaptureRenderer;
  private systemInfoRenderer: SystemInfoRenderer;
  private serverModalRenderer: ServerModalRenderer;
  private emergencyRenderer: EmergencyRenderer;
  public baselineRenderer: BaselineRenderer;

  constructor(stateManager: StateManager) {
    this.stateManager = stateManager;
    this.state = stateManager.getState();
    this.kubernetesRenderer = new KubernetesRenderer();
    this.logAnalysisRenderer = new LogAnalysisRenderer();
    this.sftpContextMenuRenderer = new SftpContextMenuRenderer();
    this.databaseRenderer = new DatabaseRenderer();
    this.packetCaptureRenderer = new PacketCaptureRenderer();
    this.systemInfoRenderer = new SystemInfoRenderer();
    this.serverModalRenderer = new ServerModalRenderer();
    this.emergencyRenderer = new EmergencyRenderer(this.state);
    this.baselineRenderer = new BaselineRenderer(this.state);

    // 注入系统信息页面样式
    if (!document.querySelector('#system-info-styles')) {
      const styleElement = document.createElement('div');
      styleElement.id = 'system-info-styles';
      styleElement.innerHTML = systemInfoStyles;
      document.head.appendChild(styleElement.firstElementChild!);
    }

    // 注册 System Info Header 切换函数
    (window as any).toggleSystemInfoHeader = () => {
      const header = document.querySelector('.system-info-header');
      const content = document.querySelector('.system-info-content');
      const toggleBtn = document.querySelector('.header-toggle-icon');
      
      if (header && content) {
        header.classList.toggle('collapsed');
        content.classList.toggle('expanded');
        
        // 保存状态到 localStorage
        const isCollapsed = header.classList.contains('collapsed');
        localStorage.setItem('system-info-header-collapsed', String(isCollapsed));
        
        // 更新按钮图标
        if (toggleBtn) {
          toggleBtn.innerHTML = isCollapsed 
            ? Right({ theme: 'outline', size: '16', fill: 'currentColor' })
            : Left({ theme: 'outline', size: '16', fill: 'currentColor' });
        }
      }
    };

    // 注册Kubernetes Tab切换函数
    (window as any).switchKubernetesTab = (tabId: string) => {
      this.kubernetesRenderer.setTab(tabId as any);
    };
    (window as any).switchKubernetesSubTab = (subTabId: string) => {
      this.kubernetesRenderer.setSubTab(subTabId);
    };

    // 监听状态变化
    this.stateManager.addListener((newState) => {
      const oldTheme = this.state.theme;
      const oldConnected = this.state.isConnected;

      this.state = newState;

      // 如果主题或连接状态发生变化，重新渲染连接面板
      if (oldTheme !== newState.theme || oldConnected !== newState.isConnected) {
        console.log('状态监听器检测到变化，重新渲染连接面板', {
          oldTheme,
          newTheme: newState.theme,
          oldConnected,
          newConnected: newState.isConnected
        });
        this.rerenderConnectionPanel();
        this.rerenderStatusBar();

        // 如果是从未连接变为已连接，触发状态变化动画
        if (!oldConnected && newState.isConnected) {
          console.log('连接成功，触发状态变化动画');
          setTimeout(() => {
            const connectionCard = document.querySelector('.connection-card');
            if (connectionCard) {
              connectionCard.classList.add('status-change');
              setTimeout(() => {
                connectionCard.classList.remove('status-change');
              }, 800);
            }
          }, 50); // 等待DOM更新
        }
      }
    });

  }


  /**
   * 更新状态
   */
  updateState(newState: AppState): void {
    const oldTheme = this.state.theme;
    this.state = newState;
    this.emergencyRenderer.setState(this.state);
    this.baselineRenderer.setState(this.state);

    console.log('ModernUIRenderer.updateState - 主题变化:', { oldTheme, newTheme: newState.theme });

    // 如果主题发生变化，重新渲染连接面板
    if (oldTheme !== newState.theme) {
      console.log('主题已变化，重新渲染连接面板');
      this.rerenderConnectionPanel();
    }
  }

  /**
   * 重新渲染连接面板
   */
  private rerenderConnectionPanel(): void {
    // 更新连接面板 (左下角)
    const sidebar = document.querySelector('.modern-sidebar');
    if (sidebar) {
      const wrapper = sidebar.querySelector('.connection-card-wrapper');
      if (wrapper) {
        wrapper.innerHTML = this.renderConnectionPanel();
      }
    }

    // 同时更新设置下拉菜单中的连接状态
    const settingsMenu = document.getElementById('settings-dropdown-menu');
    if (settingsMenu) {
      settingsMenu.outerHTML = this.renderSettingsMenu();
    }
  }

  /**
   * 重新渲染状态栏（连接状态变化时调用）
   */
  private rerenderStatusBar(): void {
    const bar = document.querySelector('.status-bar');
    if (!bar) return;
    const tmp = document.createElement('div');
    tmp.innerHTML = this.renderStatusBar();
    const newBar = tmp.firstElementChild;
    if (newBar) bar.replaceWith(newBar);
  }

  /**
   * 检测是否为 macOS
   */
  private isMacOS(): boolean {
    return navigator.platform.toUpperCase().indexOf('MAC') >= 0;
  }

  /**
   * 更新系统信息标签页的计数
   */
  public updateSystemInfoTabs(detailedInfo: any): void {
    if (!detailedInfo) return;

    const counts = {
      processes: detailedInfo.processes?.length || 0,
      network: detailedInfo.networkDetails?.length || 0,
      services: detailedInfo.services?.length || 0,
      users: detailedInfo.users?.length || 0,
      autostart: detailedInfo.autostart?.length || 0,
      cron: detailedInfo.cronJobs?.length || 0,
      firewall: detailedInfo.firewallRules?.length || 0,
      sshkeys: detailedInfo.sshKeys?.length || 0,
      loginhistory: detailedInfo.loginHistory?.length || 0,
      suidfiles: detailedInfo.suidFiles?.length || 0,
      envvars: detailedInfo.envVariables?.length || 0,
      shellconfigs: detailedInfo.shellConfigs?.length || 0,
      packages: detailedInfo.installedPackages?.length || 0,
      sudoers: detailedInfo.sudoersConfig?.length || 0,
      timers: detailedInfo.systemdTimers?.length || 0,
      kernelmodules: detailedInfo.kernelModules?.length || 0,
      recentfiles: detailedInfo.recentFiles?.length || 0,
      established: detailedInfo.established?.length || 0,
      openports: detailedInfo.openPorts?.length || 0,
      autoruns: detailedInfo.autoruns?.length || 0,
      rootcheck: detailedInfo.rootcheck?.length || 0,
      sensitive: detailedInfo.sensitiveFiles?.length || 0,
      docker: detailedInfo.dockerContainers?.length || 0,
      kubernetes: detailedInfo.kubernetesPods?.length || 0,
      webapps: detailedInfo.webApps?.length || 0,
    };

    Object.entries(counts).forEach(([key, count]) => {
      document.querySelectorAll<HTMLElement>(`[data-system-tab="${key}"] .si-lens-count`).forEach(badge => {
        badge.textContent = count > 0 ? String(count) : '';
        badge.classList.toggle('empty', count === 0);
      });
    });
  }

  /**
   * 渲染标题栏
   */
  renderTitleBar(): string {
    const isMac = this.isMacOS();

    return `
      <div class="modern-title-bar incident-title-bar" data-tauri-drag-region>
        <div class="title-bar-left">
          <div class="app-logo">
            <div class="logo-icon" aria-hidden="true">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M3.5 7.25A2.25 2.25 0 0 1 5.75 5h3l1.6 1.75h7.9A2.25 2.25 0 0 1 20.5 9v8.25a2.25 2.25 0 0 1-2.25 2.25H5.75a2.25 2.25 0 0 1-2.25-2.25v-10Z" fill="currentColor" opacity=".18"/>
                <path d="M3.5 8.25h17M5.75 5h3l1.6 1.75h7.9A2.25 2.25 0 0 1 20.5 9v8.25a2.25 2.25 0 0 1-2.25 2.25H5.75a2.25 2.25 0 0 1-2.25-2.25V7.25A2.25 2.25 0 0 1 5.75 5Z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/>
                <circle cx="12" cy="13.75" r="3.25" stroke="currentColor" stroke-width="1.5"/>
                <path d="M12 9.5v2M12 16v2M7.75 13.75h2M14.25 13.75h2" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
              </svg>
            </div>
            <span class="app-name">LovelyRes</span>
            <span class="app-edition">Incident Canvas</span>
          </div>

        </div>

        ${this.renderIncidentContextBar()}

        <div class="title-bar-right">
          <button id="sftp-title-btn" class="title-bar-btn" type="button" title="打开 SFTP 文件管理窗口">
            ${FolderProtection({ theme: 'outline', size: '14', fill: 'currentColor' })}
            SFTP
          </button>
          <button id="ssh-terminal-title-btn" class="title-bar-btn" type="button" title="打开 SSH 终端窗口">
            ${Terminal({ theme: 'outline', size: '14', fill: 'currentColor' })}
            终端
          </button>
          ${!isMac ? `
          <div class="window-controls">
            <button class="control-button minimize-btn" title="最小化">
              <svg width="12" height="12" viewBox="0 0 12 12" fill="currentColor">
                <rect x="2" y="5.5" width="8" height="1"/>
              </svg>
            </button>
            <button class="control-button maximize-btn" title="最大化">
              <svg width="12" height="12" viewBox="0 0 12 12" fill="currentColor">
                <rect x="2" y="2" width="8" height="8" stroke="currentColor" stroke-width="1" fill="none"/>
              </svg>
            </button>
            <button class="control-button close-btn close" title="关闭">
              <svg width="12" height="12" viewBox="0 0 12 12" fill="currentColor">
                <path d="M2.5 2.5L9.5 9.5M9.5 2.5L2.5 9.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
              </svg>
            </button>
          </div>
          ` : ''}
        </div>
      </div>
    `;
  }

  /**
   * 渲染侧边栏
   */
  renderSidebar(): string {
    return `
      <nav class="sidebar-nav">
        <!-- 分组导航树 -->
        <div class="sidebar-tree">
          ${this.renderNavigationMenu()}
        </div>

        <!-- 底部：连接面板 + 操作按钮（单排，按钮靠右） -->
        <div class="sidebar-foot">
          <div class="sidebar-search sidebar-bottom-search">
            <span class="sidebar-search-icon">
              ${FileSearch({ theme: 'outline', size: '14', fill: 'currentColor' })}
            </span>
            <input id="sidebar-filter" type="text" placeholder="搜索页面或动作…" spellcheck="false" autocomplete="off"
                   oninput="window.filterSidebar && window.filterSidebar(this.value)" />
          </div>
          <div class="sidebar-foot-row">
            <div class="connection-card-wrapper">
              ${this.renderConnectionPanel()}
            </div>
            <div class="sidebar-foot-actions">
              <div class="sidebar-settings-container">
                ${this.renderSettingsMenu()}
                <button class="sidebar-foot-btn" type="button" title="设置" data-ui-action="toggle-settings-dropdown"
                  onclick="event.stopPropagation(); document.getElementById('settings-dropdown-menu')?.classList.toggle('show')">
                  ${SettingTwo({ theme: 'outline', size: '18', fill: 'currentColor' })}
                </button>
              </div>
              <button class="sidebar-foot-btn sidebar-collapse-btn" type="button" title="折叠侧边栏" onclick="window.toggleSidebar && window.toggleSidebar()">
                ${Left({ theme: 'outline', size: '18', fill: 'currentColor' })}
              </button>
            </div>
          </div>
        </div>
      </nav>
    `;
  }

  /**
   * 渲染设置菜单
   */
  private renderSettingsMenu(): string {
    const currentTheme = this.state.theme;
    const themes: Array<{ value: string; label: string; dot: string; ring: string }> = [
      { value: 'light', label: '浅色', dot: 'linear-gradient(135deg, #f8fafc, #e2e8f0)', ring: '#cbd5e1' },
      { value: 'dark', label: '深色', dot: 'linear-gradient(135deg, #10182b, #0a0e1a)', ring: '#3aa0ff' },
      { value: 'sakura', label: '粉色', dot: 'linear-gradient(135deg, #ffb3c1, #ff9bb3)', ring: '#ff9bb3' },
    ];

    return `
      <div id="settings-dropdown-menu" class="settings-dropdown-menu">
        <div class="settings-group">
            <div class="settings-group-title">开发工具</div>
            <button class="settings-item" onclick="window.toggleDevTools(); window.hideSettingsDropdown();">
                <div class="settings-item-icon">
                    ${Bug({ theme: 'outline', size: '16', fill: 'currentColor' })}
                </div>
                <span>Debug 工具</span>
            </button>
        </div>

        <div class="dropdown-divider"></div>

        <div class="settings-group">
            <div class="settings-group-title">主题设置</div>
            <div class="theme-grid">
                ${themes.map((t) => `
                <button class="theme-swatch ${currentTheme === t.value ? 'active' : ''}" data-theme-value="${t.value}" title="${t.label}">
                    <span class="theme-swatch-dot" style="background: ${t.dot}; border-color: ${t.ring};"></span>
                    <span class="theme-swatch-label">${t.label}</span>
                </button>`).join('')}
            </div>
        </div>

        <div class="dropdown-divider"></div>

        <div class="settings-group">
            <div class="settings-group-title">连接</div>
            ${this.state.isConnected ? `
            <button class="settings-item danger" onclick="window.confirmDisconnect()">
                <div class="settings-item-icon" style="color:var(--error-color)">
                    ${LinkInterrupt({ theme: 'outline', size: '16', fill: 'currentColor' })}
                </div>
                <span>断开服务器</span>
            </button>` : `
            <button class="settings-item"
                onclick="window.switchPage?.('system-info'); window.hideSettingsDropdown?.();">
                <div class="settings-item-icon">
                    ${Connection({ theme: 'outline', size: '16', fill: 'currentColor' })}
                </div>
                <span>连接服务器</span>
            </button>`}
        </div>

        <div class="dropdown-divider"></div>

        <div class="settings-group">
            <div class="settings-group-title">通用</div>
            <button class="settings-item" data-ui-action="open-settings-overlay"
              onclick="event.stopPropagation(); window.showSettingsOverlay?.(); document.getElementById('settings-dropdown-menu')?.classList.remove('show')">
                 <div class="settings-item-icon">
                    ${SettingConfig({ theme: 'outline', size: '16', fill: 'currentColor' })}
                 </div>
                 <span>基础设置</span>
            </button>
        </div>
      </div>
    `;
  }

  /**
   * 公开版本：供 app.ts 在主题切换后重新渲染设置菜单
   */
  renderSettingsMenuPublic(): string {
    return this.renderSettingsMenu();
  }

  /**
   * 渲染连接面板（纯状态展示；连接/断开操作在设置菜单的「连接」分组里）
   */
  private renderConnectionPanel(): string {
    const isConnected = this.state.isConnected;
    const target = activeTargetContext.get();
    const serverName = isConnected && target
      ? `${target.username}@${target.host}:${target.port}`
      : isConnected && this.state.serverInfo
        ? (this.state.serverInfo.name || this.state.serverInfo.host)
        : '';
    const targetTitle = target
      ? `${serverName}\n主机指纹：${target.hostKeyFingerprint}\n会话 epoch：${target.epoch}`
      : serverName;

    return `
      <div class="user-panel">
        <span class="user-panel-avatar-mark" aria-hidden="true">
          ${TargetTwo({ theme: 'outline', size: '15', fill: 'currentColor' })}
        </span>
        <div class="user-panel-info">
          <span class="user-panel-name">${isConnected ? 'Trusted target' : 'LovelyRes'}</span>
          <span class="user-panel-status" title="${escapeHtml(targetTitle)}">${isConnected ? escapeHtml(serverName) : '未连接'}</span>
        </div>
        ${isConnected ? '<span class="user-panel-dot connected"></span>' : '<span class="user-panel-dot"></span>'}
      </div>
    `;
  }

  /**
   * 渲染导航菜单
   */
  private renderNavigationMenu(): string {
    const currentPage = this.state.currentPage;
    const ico = { theme: 'outline' as const, size: '18', fill: 'currentColor' };

    type NavItem = { id: string; icon: string; title: string };
    type NavGroup = {
      id: string; label: string; accent: string; icon: string;
      items?: NavItem[];
      sections?: Array<{ label: string; items: NavItem[] }>;
    };

    // Incident Canvas：18 个页面按目标、摸底、调查、处置、运维、分析六段组织。
    // 智能折叠：渲染时只展开含当前页的组，用户显式展开的组由 applySidebarState() 恢复。
    const navGroups: NavGroup[] = [
      {
        id: 'target', label: '目标与环境', accent: '#b85c4b', icon: TargetTwo(ico),
        items: [
          { id: 'system-info', icon: TargetTwo(ico), title: '主机全景' },
          { id: 'docker', icon: Whale(ico), title: 'Docker容器' },
          { id: 'kubernetes', icon: Trace(ico), title: 'Kubernetes' },
        ],
      },
      {
        id: 'triage', label: '快速摸底', accent: '#c86f51', icon: Radar(ico),
        items: [
          { id: 'quick-detection', icon: Radar(ico), title: '快速检测' },
          { id: 'secfix', icon: AutoFocus(ico), title: '安全速查' },
          { id: 'emergency-commands', icon: Terminal(ico), title: '命令工作台' },
        ],
      },
      {
        id: 'investigation', label: '调查与证据', accent: '#a66b5b', icon: FolderProtection(ico),
        items: [
          { id: 'log-analysis', icon: Timeline(ico), title: '日志时间线' },
          { id: 'packet-capture', icon: Trace(ico), title: '网络证据' },
          { id: 'check-audit', icon: FileSearch(ico), title: '核查审计' },
          { id: 'integrity', icon: FileFocus(ico), title: '文件完整性' },
          { id: 'notes', icon: DocDetail(ico), title: '调查笔记' },
        ],
      },
      {
        id: 'response', label: '处置与恢复', accent: '#bc5d4c', icon: ShieldAdd(ico),
        items: [
          { id: 'firewall', icon: ShieldAdd(ico), title: '边界隔离' },
          { id: 'snapshot', icon: History(ico), title: '快照回滚' },
          { id: 'baseline-quick-edit', icon: SettingConfig(ico), title: '基线修复' },
        ],
      },
      {
        id: 'operations', label: '日常运维', accent: '#72867b', icon: Monitor(ico),
        items: [
          { id: 'database', icon: DatabaseSearch(ico), title: '数据库' },
          { id: 'java-hot-update', icon: Fire(ico), title: 'Java热更新' },
          { id: 'batch-servers', icon: ApplicationTwo(ico), title: '多机批量' },
        ],
      },
      {
        id: 'intelligence', label: '分析助手', accent: '#8a746d', icon: Compass(ico),
        items: [
          { id: 'ai-history', icon: Robot(ico), title: 'AI分析记录' },
        ],
      },
    ];

    const renderItem = (it: NavItem): string => {
      const active = it.id === currentPage;
      return `
          <button class="sidebar-item ${active ? 'active' : ''}" type="button" data-nav-id="${it.id}" title="${it.title}">
            <span class="sidebar-item-icon">${it.icon}</span>
            <span class="sidebar-item-label">${it.title}</span>
          </button>`;
    };

    return navGroups.map(group => {
      const allItems = group.sections ? group.sections.flatMap(s => s.items) : (group.items || []);
      const hasActive = allItems.some(it => it.id === currentPage);
      const itemsHtml = group.sections
        ? group.sections.map(sec =>
            `<div class="sidebar-itemsec">${sec.label}</div>${sec.items.map(renderItem).join('')}`
          ).join('')
        : allItems.map(renderItem).join('');

      return `
        <div class="sidebar-group ${hasActive ? 'open has-active' : ''}" data-group-id="${group.id}" style="--accent:${group.accent}">
          <button class="sidebar-group-row ${hasActive ? 'active' : ''}" type="button" title="${group.label}"
                  onclick="window.toggleSidebarGroup && window.toggleSidebarGroup('${group.id}')">
            <span class="sidebar-gicon">${group.icon}</span>
            <span class="sidebar-glabel">${group.label}</span>
            <span class="sidebar-gchev">${Right({ theme: 'outline', size: '14', fill: 'currentColor' })}</span>
            <span class="sidebar-gdot"></span>
          </button>
          <div class="sidebar-items"><div class="sidebar-items-inner">
            ${itemsHtml}
          </div></div>
        </div>`;
    }).join('');
  }

  /**
   * 渲染主工作区
   */
  public renderIncidentContextBar(): string {
    const target = activeTargetContext.get();
    const incident = target ? incidentCaseManager.getActiveCase() : null;
    const targetLabel = target
      ? `${target.username}@${target.host}:${target.port}`
      : '未连接目标';
    const targetDetail = target
      ? `指纹 ${target.hostKeyFingerprint}`
      : '建立 SSH 会话后锁定目标身份与证据范围';
    const caseTitle = incident?.title || '尚未建立案件';
    const caseMeta = incident
      ? `${incident.evidence.length} 证据 · ${incident.iocs.length} IOC`
      : '目标连接后自动创建隔离案件';

    const stages = ['识别', '取证', '分析', '处置', '复核'];
    const stageByPage: Record<string, number> = {
      'system-info': 0,
      docker: 0,
      kubernetes: 0,
      'quick-detection': 1,
      secfix: 1,
      'log-analysis': 1,
      'packet-capture': 1,
      'check-audit': 2,
      integrity: 2,
      notes: 2,
      'ai-history': 2,
      'emergency-commands': 3,
      firewall: 3,
      'baseline-quick-edit': 3,
      snapshot: 4,
      database: 0,
      'java-hot-update': 3,
      'batch-servers': 0,
    };
    const activeStage = stageByPage[this.state.currentPage] ?? 0;
    const stageHtml = stages.map((stage, index) => `
      <span class="incident-stage ${index === activeStage ? 'active' : ''} ${index < activeStage ? 'complete' : ''}">
        <span class="incident-stage-index">${index + 1}</span>
        <span>${stage}</span>
      </span>`).join('');

    return `
      <section class="incident-context-bar" aria-label="当前目标与响应阶段">
        <div class="incident-target-block">
          <span class="incident-context-icon ${target ? 'connected' : ''}" aria-hidden="true">
            ${TargetTwo({ theme: 'outline', size: '18', fill: 'currentColor' })}
          </span>
          <div class="incident-context-copy">
            <span class="incident-eyebrow">${target ? 'ACTIVE TARGET' : 'TARGET CONTEXT'}</span>
            <strong title="${escapeHtml(targetLabel)}">${escapeHtml(targetLabel)}</strong>
            <small title="${escapeHtml(targetDetail)}">${escapeHtml(targetDetail)}</small>
          </div>
          <span class="incident-trust-state ${target ? 'trusted' : ''}">${target ? '指纹已锁定' : '等待连接'}</span>
        </div>

        <div class="incident-stage-track" aria-label="响应阶段">
          ${stageHtml}
        </div>

        <button type="button" class="incident-case-summary" data-ui-action="open-case-workspace" title="打开案件工作区">
          <span class="incident-case-icon" aria-hidden="true">
            ${FolderProtection({ theme: 'outline', size: '18', fill: 'currentColor' })}
          </span>
          <span class="incident-context-copy">
            <span class="incident-eyebrow">CASE WORKSPACE</span>
            <strong>${escapeHtml(caseTitle)}</strong>
            <small>${escapeHtml(caseMeta)}</small>
          </span>
          ${Right({ theme: 'outline', size: '14', fill: 'currentColor' })}
        </button>
      </section>`;
  }

  renderMainWorkspace(): string {
    return `
      <div class="main-workspace">
        <!-- 工作区内容 -->
        <div class="workspace-content page-enter">
          ${this.renderWorkspaceContent()}
        </div>
      </div>
    `;
  }



  /**
   * 渲染连接下拉菜单内容
   */
  renderConnectionDropdownContent(): string {
    const sshManager = (window as any).app?.sshManager;
    const connections = sshManager ? sshManager.getConnections() : [];
    // 优先使用 getActiveConnection，如果不行则遍历 connections 找一个已连接的
    const activeConnection = (sshManager ? sshManager.getActiveConnection() : null) 
        || connections.find((c: any) => c.isConnected);

    let menuItems = '';

    // 如果已连接，显示断开连接选项
    if (activeConnection) {
      const disconnectIcon = LinkInterrupt({ theme: 'outline', size: '16', fill: 'currentColor' });
      menuItems += `
        <div class="dropdown-item danger" onclick="window.disconnectServer('${activeConnection.id}'); window.hideConnectionDropdown();">
          <div class="dropdown-item-icon danger">
              ${disconnectIcon}
          </div>
          <div class="dropdown-item-content">
            <span class="dropdown-item-title">断开当前连接</span>
            <span class="dropdown-item-subtitle">${activeConnection.name}</span>
          </div>
        </div>
        <div class="dropdown-divider"></div>
      `;
    }

    // 添加新连接选项 - 放在顶部作为主要操作
    menuItems += `
      <div class="dropdown-item primary" onclick="window.showServerModal(); window.hideConnectionDropdown();">
        <div class="dropdown-item-icon primary">
            ${Plus({ theme: 'outline', size: '16', fill: 'currentColor' })}
        </div>
        <div class="dropdown-item-content">
            <span class="dropdown-item-title">添加新服务器</span>
            <span class="dropdown-item-subtitle">配置 SSH 连接</span>
        </div>
      </div>
      <div class="dropdown-divider"></div>
    `;

    if (connections.length > 0) {
      menuItems += `
        <div class="dropdown-section-title">
          <span>快速连接</span>
          <span class="count-badge">${connections.length}</span>
        </div>
        <div class="dropdown-scroll-area">
      `;

      connections.forEach((conn: any) => {
        const isConnected = conn.isConnected;
        
        menuItems += `
          <div class="dropdown-item ${isConnected ? 'active' : ''}" onclick="window.connectServer('${conn.id}'); window.hideConnectionDropdown();">
            
            <div class="dropdown-item-icon ${isConnected ? 'success' : 'default'}">
                ${isConnected 
                    ? CheckOne({ theme: 'filled', size: '16', fill: 'currentColor' }) 
                    : System({ theme: 'outline', size: '16', fill: 'currentColor' })
                }
                ${isConnected ? `<div class="status-dot"></div>` : ''}
            </div>

            <div class="dropdown-item-content">
              <span class="dropdown-item-title">${conn.name}</span>
              <span class="dropdown-item-subtitle">${conn.username}@${conn.host}</span>
            </div>
            
            ${isConnected ? `
                <div class="status-badge">运行中</div>
            ` : ''}
          </div>
        `;
      });
      
      menuItems += `</div>`; // Close scroll container
    } else {
      menuItems += `
        <div class="dropdown-empty-state">
          <div class="empty-icon">
            ${Connection({ theme: 'outline', size: '24', fill: 'currentColor' })}
          </div>
          <div class="empty-text">暂无已保存的服务器</div>
        </div>
      `;
    }

    return menuItems;
  }



  /**
   * 渲染工作区内容
   */
  private renderWorkspaceContent(): string {
    if (this.state.loading) {
      return this.renderLoadingState();
    }

    if (!this.state.isConnected) {
      return this.renderConnectionPrompt();
    }

    // 根据当前页面渲染不同内容
    switch (this.state.currentPage) {
      case 'system-info':
        return this.renderSystemInfo();
      case 'ssh-terminal':
        // SSH终端在独立窗口中打开，这里显示提示信息
        return this.renderSSHTerminalRedirect();
      case 'remote-operations':
        return this.renderRemoteOperationsPage();
      case 'docker':
        return this.renderDockerPage();
      case 'emergency-commands':
        return this.renderEmergencyCommandsPage();
      case 'kubernetes':
        return this.renderKubernetesPage();
      case 'database':
        return this.databaseRenderer.render();
      case 'java-hot-update':
        return this.renderJavaHotUpdatePage();
      case 'notes':
        return this.renderNotesPage();
      case 'secfix':
        return this.renderSecfixPage();
      case 'quick-detection':
        return this.renderQuickDetectionPage();
      case 'batch-servers':
        return this.renderBatchServersPage();
      case 'check-audit':
        return this.renderCheckAuditPage();
      case 'ai-history':
        return this.renderAIHistoryPage();
      case 'snapshot':
        return this.renderSnapshotPage();
      case 'firewall':
        return this.renderFirewallPage();
      case 'integrity':
        return this.renderIntegrityPage();
      case 'packet-capture':
        // Initialize lifecycle (event delegation, Tauri listeners, rate timer)
        this.packetCaptureRenderer.initialize();
        // Async render: load interfaces then populate container
        setTimeout(async () => {
            const container = document.getElementById('packet-capture-wrapper');
            if (container) {
                try {
                    container.innerHTML = await this.packetCaptureRenderer.render();
                } catch (e) {
                    console.error('Failed to render packet capture:', e);
                    container.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text-secondary);">网络抓包模块加载失败</div>';
                }
            }
        }, 0);
        return '<div id="packet-capture-wrapper" style="height:100%"><div style="display:flex;align-items:center;justify-content:center;height:200px;color:var(--text-secondary)">正在加载网络抓包工具...</div></div>';
      case 'baseline-quick-edit':
        return this.baselineRenderer.renderBaselineQuickEditPage();
      case 'log-analysis':
        return this.renderLogAnalysisPage();
      case 'settings':
        return this.renderSettingsPage();
      default:
        return this.renderSystemInfo();
    }
  }

  /**
   * 渲染系统信息页面
   */
  private renderSystemInfo(): string {
    return this.systemInfoRenderer.renderSystemInfo(this.state);
  }

  /**
   * 渲染系统信息标签页内容（供 systemInfoTabManager 调用）
   */
  renderSystemInfoTab(tab: string): string {
    return this.systemInfoRenderer.renderSystemInfoTab(this.state, tab);
  }



  /**
   * 渲染加载状态 — 居中显示连接进度
   */
  private renderLoadingState(): string {
    const step = this.state.loadingStep || '正在连接...';

    return `
      <div class="workspace-connecting-center">
        <div class="connecting-card">
          <svg width="36" height="36" viewBox="0 0 36 36" style="display:block;">
            <circle cx="18" cy="18" r="15" fill="none" stroke="var(--border-color, #334155)" stroke-width="3"/>
            <circle cx="18" cy="18" r="15" fill="none" stroke="var(--primary-color, #4299e1)" stroke-width="3"
              stroke-dasharray="28 66" stroke-linecap="round">
              <animateTransform attributeName="transform" type="rotate"
                from="0 18 18" to="360 18 18" dur="0.9s" repeatCount="indefinite"/>
            </circle>
          </svg>
          <span class="connecting-step">${step}</span>
          <div class="connecting-progress-track">
            <div class="connecting-progress-fill"></div>
          </div>
        </div>
      </div>
    `;
  }

  /**
   * 渲染服务器管理模态框
   */
  renderServerModal(): string {
    return this.serverModalRenderer.renderServerModal();
  }

  /**
   * 仅渲染服务器列表内容（用于局部刷新，不替换整个模态框）
   */
  renderServerList(): string {
    return this.serverModalRenderer.renderServerList();
  }

  renderStepForm(editData?: any): string {
    return this.serverModalRenderer.renderStepForm(editData);
  }

  /**
   * 渲染 Java 热更新页面骨架
   */
  private renderJavaHotUpdatePage(): string {
    return `
      <div class="jhu-page">
        <div class="jhu-header">
          <div class="jhu-header-left">
            <h2>${createIconHTML('🔥', { size: 20 })} Java 热更新</h2>
            <span class="jhu-badge">Hot Update</span>
          </div>
          <div class="jhu-header-actions">
            <button class="jhu-btn secondary" data-jhu-action="env-info">Java 环境</button>
            <button class="jhu-btn primary" data-jhu-action="refresh">刷新</button>
          </div>
        </div>
        <div class="jhu-tabs">
          <button class="jhu-tab-btn active" data-jhu-action="switch-tab" data-jhu-param="processes">进程管理</button>
          <button class="jhu-tab-btn" data-jhu-action="switch-tab" data-jhu-param="hotupdate">热更新</button>
          <button class="jhu-tab-btn" data-jhu-action="switch-tab" data-jhu-param="diagnostics">JVM 诊断</button>
          <button class="jhu-tab-btn" data-jhu-action="switch-tab" data-jhu-param="services">服务管理</button>
          <button class="jhu-tab-btn" data-jhu-action="switch-tab" data-jhu-param="deploy">部署管理</button>
          <button class="jhu-tab-btn" data-jhu-action="switch-tab" data-jhu-param="docker">Docker容器</button>
        </div>
        <div id="jhu-content" class="jhu-content"></div>
      </div>
    `;
  }


    /**
     * 渲染连接提示
     */
  private renderConnectionPrompt(): string {
    return this.serverModalRenderer.renderConnectionPrompt();
  }

  /**
   * 渲染笔记页面
   */
  private renderNotesPage(): string {
    return `
      <div class="notes-page">
        <div class="notes-header">
          <h2>笔记</h2>
        </div>
        <div id="notes-content" style="flex:1;overflow:hidden;"></div>
      </div>
    `;
  }

  /**
   * 渲染安全速查页面
   */
  private renderSecfixPage(): string {
    return `
      <div class="sf-page">
        <div class="sf-header">
          <div class="sf-header-left">
            <h2>安全速查</h2>
            <span class="sf-badge">CTF / 应急</span>
          </div>
        </div>
        <div id="secfix-content" class="sf-content"></div>
      </div>
    `;
  }

  private renderCheckAuditPage(): string {
    return `
      <div class="ca-page">
        <div class="ca-header">
          <div class="ca-header-left">
            <h2>Check 审计</h2>
            <span class="ca-badge">Check专武</span>
          </div>
          <div class="ca-header-actions">
            <button class="ca-btn primary" data-ca-action="refresh">刷新状态</button>
          </div>
        </div>
        <div class="ca-tabs">
          <button class="ca-tab-btn active" data-ca-action="switch-tab" data-ca-param="hijack">命令劫持</button>
          <button class="ca-tab-btn" data-ca-action="switch-tab" data-ca-param="audit-log">审计日志</button>
          <button class="ca-tab-btn" data-ca-action="switch-tab" data-ca-param="analysis">Check分析</button>
          <button class="ca-tab-btn" data-ca-action="switch-tab" data-ca-param="quick-fix">快速修复</button>
        </div>
        <div id="ca-content" class="ca-content"></div>
      </div>
    `;
  }

  private renderAIHistoryPage(): string {
    return `
      <div class="aih-page">
        <div class="aih-header"><h2>AI 历史</h2></div>
        <div id="ai-history-content" class="aih-content"></div>
      </div>
    `;
  }

  private renderSnapshotPage(): string {
    return `
      <div class="snap-page" style="padding:20px;height:100%;overflow:auto;">
        <div class="snap-page-header" style="margin-bottom:16px;">
          <h2 style="margin:0;">快照与回滚中心</h2>
          <div style="color:var(--text-secondary);font-size:12px;margin-top:4px;">集中管理本工具做过的所有变更，一键回滚；开赛前可对关键目录拍快照兜底。</div>
        </div>
        <div id="snapshot-content"></div>
      </div>
    `;
  }

  private renderFirewallPage(): string {
    return `
      <div class="fw-page" style="padding:20px;height:100%;overflow:auto;">
        <div class="fw-page-header" style="margin-bottom:16px;">
          <h2 style="margin:0;">防火墙规则管理</h2>
          <div style="color:var(--text-secondary);font-size:12px;margin-top:4px;">查看/增删 iptables·nftables·ufw 规则、封禁 IP。危险规则自动豁免当前 SSH 并支持超时自动还原，防止把自己关在门外。</div>
        </div>
        <div id="firewall-content"></div>
      </div>
    `;
  }

  private renderIntegrityPage(): string {
    return `
      <div class="fim-page" style="padding:20px;height:100%;overflow:auto;">
        <div class="fim-page-header" style="margin-bottom:16px;">
          <h2 style="margin:0;">文件完整性快照</h2>
          <div style="color:var(--text-secondary);font-size:12px;margin-top:4px;">对 Web 根目录、系统 bin 等建立哈希基线，随时比对出新增/修改/删除的文件，快速定位被篡改文件与新落地 webshell。</div>
        </div>
        <div id="integrity-content"></div>
      </div>
    `;
  }

  /**
   * 渲染远程操作页面（SFTP + SSH终端分屏）
   */
  private static remoteOperationsInitTimer: number | null = null;

  /**
   * 渲染 SFTP 远程文件页面（主窗口工作区与 SFTP 独立窗口共用）
   */
  public renderRemoteOperationsPage(): string {
    // 防止重复设置定时器
    if (ModernUIRenderer.remoteOperationsInitTimer) {
      clearTimeout(ModernUIRenderer.remoteOperationsInitTimer);
    }

    // 延迟初始化远程操作页面
    ModernUIRenderer.remoteOperationsInitTimer = window.setTimeout(() => {
      // 事件委托必须每次渲染都重绑：工作区是 outerHTML 整体替换的，
      // 切走再回来时这些节点全是新的。而 initRemoteOperationsPage 有个
      // 模块级 initialized 标志会提前 return，绑定不能依赖它。
      sftpManager.bindUIEvents();
      (window as any).initRemoteOperationsPage?.();
      ModernUIRenderer.remoteOperationsInitTimer = null;
    }, 100);

    const sideCollapsed = (() => { try { return localStorage.getItem('sftp-side-collapsed') === 'true'; } catch { return false; } })();

    // 所有交互一律 data-sftp-action + 事件委托（sftpManager.bindPageEvents）：
    // 不再写内联 onclick，既去掉属性内 JS 注入面，也是 CSP 收紧的前提。
    const icon = (fn: (o: any) => string, size = '15') =>
      fn({ theme: 'outline', size, fill: 'currentColor' });

    return `
      <div class="sftp-page-container" id="sftp-page">
        <!-- 头部：标题 + 计数 chips + 主操作（其余收进"更多"） -->
        <div class="sftp-header">
          <div class="sftp-head-row">
            <div class="sftp-title-wrap">
              <h2 class="sftp-title">远程文件</h2>
              <span class="sftp-chip" id="sftp-chip-count">0 项</span>
              <span class="sftp-chip sftp-chip-risk" id="sftp-chip-risk" hidden>
                ${statusIcon('warning', { size: 13 })} <span id="sftp-risk-count">0</span> 个可疑
              </span>
              <span class="sftp-chip sftp-chip-conn ${this.state.isConnected ? 'is-on' : 'is-off'}">
                ${this.state.isConnected ? '已连接' : '未连接'}
              </span>
            </div>
            <div class="sftp-head-actions">
              <button id="sftp-upload-btn" class="sftp-act-btn primary" data-sftp-action="upload">${icon(Upload)}<span>上传</span></button>
              <button class="sftp-act-btn" data-sftp-action="refresh">${icon(Refresh)}<span>刷新</span></button>
              <div class="sftp-more-wrap">
                <button class="sftp-act-btn sftp-more-btn" data-sftp-action="toggle-more" title="更多操作" aria-haspopup="true" aria-expanded="false">${icon(MoreOne, '16')}</button>
                <div class="sftp-more-menu" id="sftp-more-menu">
                  <button class="dropdown-item" data-sftp-action="new-folder">${icon(FolderPlus, '14')}<span>新建文件夹</span></button>
                  <button class="dropdown-item" data-sftp-action="new-file">${icon(FileText, '14')}<span>新建文件</span></button>
                  <button class="dropdown-item" data-sftp-action="snapshot">${icon(Shield, '14')}<span>完整性快照</span></button>
                  <button class="dropdown-item" data-sftp-action="history">${icon(History, '14')}<span>历史记录</span></button>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- 路径栏：导航 + 路径面包屑 + 搜索 -->
        <div class="sftp-pathbar">
          <div class="sftp-nav-controls">
            <button class="sftp-nav-btn" data-sftp-action="up" title="返回上一级">${icon(Up, '16')}</button>
            <button class="sftp-nav-btn" data-sftp-action="home" title="根目录">${icon(Home, '16')}</button>
          </div>
          <div class="sftp-breadcrumb-bar">
            <div id="sftp-breadcrumb" class="sftp-breadcrumb">
              <span class="breadcrumb-segment breadcrumb-root" data-path="/" title="根目录">/</span>
            </div>
            <input type="text" id="sftp-path-input" class="sftp-path-input" placeholder="输入路径..." />
          </div>
          <div class="sftp-search">
            <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"></circle><path d="M21 21l-4.3-4.3"></path></svg>
            <input type="text" id="sftp-search-input" placeholder="搜索当前目录..." />
          </div>
        </div>

        <!-- 敏感目录审计横幅 -->
        <div class="sftp-audit-banner" id="sftp-audit-banner" style="display:none;">
          <span class="sftp-audit-icon">${icon(Shield)}</span>
          <span class="sftp-audit-text"><strong>敏感目录</strong> · 操作将记录到审计日志</span>
          <button class="sftp-audit-link" data-sftp-action="history">查看日志</button>
        </div>

        <!-- Body: 文件表格 + 文件详情侧栏 -->
        <div class="sftp-body">
          <div class="sftp-file-list-container">
            <table class="sftp-table">
              <thead>
                <tr>
                  <th class="sftp-col-check"><input type="checkbox" id="sftp-check-all"></th>
                  <th class="sftp-th-sortable sftp-col-name" data-sftp-sort="name" id="sftp-th-name">名称 <span class="sort-indicator" id="sort-ind-name">▲</span></th>
                  <th class="sftp-col-type">类型</th>
                  <th class="sftp-th-sortable sftp-col-size" data-sftp-sort="size" id="sftp-th-size">大小 <span class="sort-indicator" id="sort-ind-size"></span></th>
                  <th class="sftp-col-perms">权限</th>
                  <th class="sftp-col-owner">所有者</th>
                  <th class="sftp-th-sortable sftp-col-time" data-sftp-sort="modified" id="sftp-th-modified">修改时间 <span class="sort-indicator" id="sort-ind-modified"></span></th>
                  <th class="sftp-col-risk">风险</th>
                </tr>
              </thead>
              <tbody id="sftp-file-list">
                <tr>
                  <td colspan="8" class="sftp-placeholder-cell">
                    <div class="sftp-placeholder">
                      <div class="loading-spinner"></div>
                      <span>正在加载文件列表...</span>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          <aside class="sftp-side${sideCollapsed ? ' collapsed' : ''}" id="sftp-side">
            <div class="sftp-side-head">
              <span class="sftp-side-title">文件详情</span>
              <button class="sftp-side-toggle" data-sftp-action="toggle-side" title="收起 / 展开">
                <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 6l6 6-6 6"/></svg>
              </button>
            </div>
            <div class="sftp-side-body" id="sftp-side-body">
              <div class="sftp-side-empty">
                <span class="sftp-side-empty-icon"><svg viewBox="0 0 24 24" width="30" height="30" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"><path d="M14 3v5h5"/><path d="M6 3h8l5 5v11a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z"/></svg></span>
                <p>选择文件查看详情</p>
              </div>
            </div>
          </aside>
        </div>
      </div>
      ${this.sftpContextMenuRenderer.renderContextMenu()}
    `;
  }





  /**
   * 渲染Docker页面
   */
  private renderDockerPage(): string {
    // dockerPageManager is a singleton import, always available
    dockerPageManager.initialize();
    return dockerPageManager.renderPage();
  }

  /**
   * 渲染Kubernetes页面
   */
  private renderKubernetesPage(): string {
    return this.kubernetesRenderer.render();
  }

  /**
   * 渲染日志审计页面
   */
  private renderLogAnalysisPage(): string {
    return this.logAnalysisRenderer.render();
  }

  /**
   * 渲染应急命令页面
   */
  private renderEmergencyCommandsPage(): string {
    return this.emergencyRenderer.renderEmergencyCommandsPage();
  }

  /**
   * 渲染快速检测页面
   */
  private renderQuickDetectionPage(): string {
    return this.emergencyRenderer.renderQuickDetectionPage();
  }

  /**
   * 渲染多机批量执行页面
   */
  private renderBatchServersPage(): string {
    return `
      <div class="bs-page">
        <div class="bs-header">
          <div>
            <h2 class="bs-title">多机批量执行</h2>
            <p class="bs-subtitle">在多台已保存的服务器上跑同一条命令，逐台收集结果</p>
          </div>
        </div>

        <div class="bs-warn">
          ${statusIcon('warning', { size: 14 })}
          <span>批量执行使用独立 SSH 会话，不替换当前工作目标。为防止中间人攻击，目标必须先交互连接一次并保存主机指纹。</span>
        </div>

        <div class="bs-body">
          <section class="bs-panel bs-targets">
            <div class="bs-panel-head">
              <span class="bs-panel-title">目标服务器</span>
              <span id="bs-selection-summary" class="bs-panel-meta"></span>
              <button class="modern-btn secondary bs-mini" data-bs-action="select-all">全选</button>
              <button class="modern-btn secondary bs-mini" data-bs-action="select-none">清空</button>
            </div>
            <div class="bs-filter-row">
              <input id="bs-target-filter" class="bs-input" placeholder="按名称、主机、角色、分组或标签筛选" />
              <select id="bs-environment-filter" class="bs-input">
                <option value="">全部环境</option>
                <option value="production">production</option><option value="staging">staging</option>
                <option value="development">development</option><option value="ctf">ctf</option>
              </select>
            </div>
            <div id="bs-server-list" class="bs-server-list"></div>
          </section>

          <section class="bs-panel bs-compose">
            <div class="bs-panel-head">
              <span class="bs-panel-title">命令与发布策略</span>
              <select id="bs-template" class="bs-input bs-template-select"><option value="">选择任务模板…</option></select>
              <button class="modern-btn secondary bs-mini" data-bs-action="load-template">载入</button>
              <button class="modern-btn secondary bs-mini" data-bs-action="save-template">保存模板</button>
              <button class="modern-btn secondary bs-mini" data-bs-action="delete-template">删除</button>
            </div>
            <label class="bs-field">
              <span class="bs-label">任务名称（可选）</span>
              <input id="bs-task-name" type="text" class="bs-input" placeholder="例如：统一关闭 SSH root 登录" />
            </label>
            <label class="bs-field">
              <span class="bs-label">执行命令</span>
              <textarea id="bs-command" class="bs-textarea" rows="4" spellcheck="false"
                placeholder="例如：sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config &amp;&amp; systemctl reload sshd"></textarea>
            </label>
            <label class="bs-field">
              <span class="bs-label">回滚命令（可选，强烈建议填写）</span>
              <input id="bs-restore" type="text" class="bs-input" spellcheck="false"
                placeholder="填写后会随每台记录写入操作日志，可在「快照回滚」里一键撤销" />
            </label>
            <label class="bs-field">
              <span class="bs-label">独立验证命令（退出码必须为 0）</span>
              <input id="bs-verify" type="text" class="bs-input" spellcheck="false"
                placeholder="例如：systemctl is-active sshd &amp;&amp; sshd -t" />
            </label>
            <div class="bs-strategy-row">
              <label class="bs-field"><span class="bs-label">发布策略</span><select id="bs-strategy" class="bs-input"><option value="rolling">Rolling 逐台</option><option value="canary">Canary 先试点</option></select></label>
              <label class="bs-field"><span class="bs-label">Canary 台数</span><input id="bs-canary-count" type="number" class="bs-input" value="1" min="1" max="100"></label>
              <label class="bs-check"><input id="bs-stop-on-failure" type="checkbox" checked><span>Rolling 遇错即停</span></label>
            </div>
            <div class="bs-actions">
              <button id="bs-run" class="modern-btn primary" data-bs-action="run" disabled>开始执行</button>
              <button id="bs-cancel" class="modern-btn secondary" data-bs-action="cancel" hidden>取消</button>
            </div>
            <div id="bs-progress" class="bs-progress" style="display:none;">
              <div class="bs-progress-track"><div id="bs-progress-bar" class="bs-progress-bar"></div></div>
              <span id="bs-progress-label" class="bs-progress-label"></span>
            </div>
          </section>
        </div>

        <section class="bs-panel bs-results-panel">
          <div class="bs-panel-head"><span class="bs-panel-title">执行结果</span></div>
          <div id="bs-results" class="bs-results"></div>
        </section>

        <section class="bs-panel bs-history-panel">
          <div class="bs-panel-head"><span class="bs-panel-title">历史任务</span></div>
          <div id="bs-history" class="bs-history"></div>
        </section>
      </div>
    `;
  }

  /**
   * @deprecated 不要接入渲染链路。检测报告弹窗的真实注入路径是
   * detectionReportRenderer.ensureReportModalExists(),它按需把弹窗 append 到 body。
   * 本方法与 emergencyRenderer.renderDetectionReportModal() 会产出**同名 id**
   * (#detection-report-modal) 的另一套结构,一旦渲染就会让 ensureReportModalExists()
   * 的存在性检查提前返回,fillReportData 随后填到错误的 DOM 上。待删除。
   */
  renderDetectionReportModal(): string {
    return this.emergencyRenderer.renderDetectionReportModal();
  }

  /**
   * 渲染状态栏
   */
  renderStatusBar(): string {
    const isConn = this.state.isConnected;
    const target = activeTargetContext.get();
    const server = isConn && target
      ? `${target.username}@${target.host}:${target.port}`
      : isConn ? (this.state.serverInfo?.name || this.state.currentServer || '') : '';
    const targetTitle = target
      ? `主机指纹：${target.hostKeyFingerprint} · 会话 epoch：${target.epoch}`
      : '';

    return `
      <div class="status-bar">
        <div class="status-left">
          <span class="status-item" title="${escapeHtml(targetTitle)}">
            <span class="status-dot ${isConn ? 'connected' : 'disconnected'}"></span>
            ${isConn ? escapeHtml(server) : '未连接'}
          </span>
        </div>
        <div class="status-right">
          <button type="button" class="status-item clickable" id="status-case-btn" title="打开当前目标的案件工作区">案件</button>
          <button type="button" class="status-item clickable" id="status-log-btn" title="查看前后端运行日志">${createIconHTML('Log', { size: 13 })}</button>
          <span class="status-item">v${APP_VERSION}</span>
        </div>
      </div>
    `;
  }

  /**
   * 渲染 SSH 终端重定向页面
   */
  private renderSSHTerminalRedirect(): string {
    return `
      <div class="ssh-terminal-redirect" style="
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        height: 100%;
        text-align: center;
        padding: 2rem;
      ">
        <div style="
          background: var(--bg-secondary);
          border: 1px solid var(--border-color);
          border-radius: 8px;
          padding: 2rem;
          max-width: 500px;
          width: 100%;
        ">
          <div style="
            font-size: 48px;
            margin-bottom: 1rem;
            color: var(--text-secondary);
          ">${createIconHTML('🖥️', { size: 48 })}</div>

          <h2 style="
            color: var(--text-primary);
            margin-bottom: 1rem;
            font-size: 1.5rem;
          ">SSH 终端已在新窗口中打开</h2>

          <p style="
            color: var(--text-secondary);
            margin-bottom: 1.5rem;
            line-height: 1.6;
          ">
            SSH 终端现在在独立窗口中运行，这样可以：<br>
            • 保持会话持久性<br>
            • 不影响主界面操作<br>
            • 提供更好的终端体验
          </p>

          <button
            onclick="openSSHTerminalWindow()"
            style="
              background: var(--primary-color);
              color: white;
              border: none;
              padding: 0.75rem 1.5rem;
              border-radius: 6px;
              cursor: pointer;
              font-size: 1rem;
              transition: all 0.2s;
            "
            onmouseover="this.style.opacity='0.9'"
            onmouseout="this.style.opacity='1'"
          >
            重新打开 SSH 终端
          </button>
        </div>
      </div>
    `;
  }



  /**
   * 渲染设置页面（覆盖层模式）
   */
  renderSettingsPage(): string {
    return `
      <div class="settings-overlay" style="
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(0, 0, 0, 0.5);
        z-index: 10000;
        display: flex;
        align-items: center;
        justify-content: center;
        backdrop-filter: blur(4px);
      ">
        <div class="settings-page" style="
          width: 90%;
          max-width: 800px;
          max-height: 90%;
          padding: var(--spacing-lg);
          background: var(--bg-primary);
          border-radius: var(--border-radius-lg);
          box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
          overflow-y: auto;
          position: relative;
        ">
          <!-- 关闭按钮 -->
          <button class="settings-close-btn" style="
            position: absolute;
            top: var(--spacing-md);
            right: var(--spacing-md);
            background: none;
            border: none;
            color: var(--text-secondary);
            font-size: 20px;
            cursor: pointer;
            padding: 4px;
            border-radius: 4px;
            transition: all 0.2s;
          " title="关闭设置">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
              <path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/>
            </svg>
          </button>

          <div class="settings-container" style="
            margin: 0;
          ">
          <div class="settings-header" style="
            margin-bottom: var(--spacing-xl);
            padding-bottom: var(--spacing-lg);
            border-bottom: 1px solid var(--border-color);
          ">
            <h1 style="
              font-size: 24px;
              font-weight: 600;
              color: var(--text-primary);
              margin: 0 0 var(--spacing-sm) 0;
            ">设置</h1>
            <p style="
              color: var(--text-secondary);
              margin: 0;
              font-size: 14px;
            ">配置应用程序的基础设置和AI功能</p>
          </div>

          <div class="settings-tabs" style="
            display: flex;
            gap: var(--spacing-sm);
            margin-bottom: var(--spacing-xl);
            border-bottom: 1px solid var(--border-color);
          ">
            <button class="settings-tab active" data-tab="basic" style="
              padding: var(--spacing-md) var(--spacing-lg);
              background: none;
              border: none;
              color: var(--text-primary);
              font-size: 14px;
              font-weight: 500;
              cursor: pointer;
              border-bottom: 2px solid var(--accent-color);
              transition: all 0.2s;
            ">基础设置</button>
            <button class="settings-tab" data-tab="ai" style="
              padding: var(--spacing-md) var(--spacing-lg);
              background: none;
              border: none;
              color: var(--text-secondary);
              font-size: 14px;
              font-weight: 500;
              cursor: pointer;
              border-bottom: 2px solid transparent;
              transition: all 0.2s;
            ">AI设置</button>
            <button class="settings-tab" data-tab="tools" style="
              padding: var(--spacing-md) var(--spacing-lg);
              background: none;
              border: none;
              color: var(--text-secondary);
              font-size: 14px;
              font-weight: 500;
              cursor: pointer;
              border-bottom: 2px solid transparent;
              transition: all 0.2s;
            ">工具</button>
          </div>

          <div class="settings-content">
            <!-- 基础设置 -->
            <div class="settings-panel" id="basic-settings" style="display: block;">
              <div class="settings-section" style="
                background: var(--bg-secondary);
                border-radius: var(--border-radius-lg);
                padding: var(--spacing-lg);
                margin-bottom: var(--spacing-lg);
              ">
                <h3 style="
                  font-size: 16px;
                  font-weight: 600;
                  color: var(--text-primary);
                  margin: 0 0 var(--spacing-md) 0;
                ">界面设置</h3>

                <div class="setting-item" style="
                  display: flex;
                  justify-content: space-between;
                  align-items: center;
                  margin-bottom: var(--spacing-md);
                ">
                  <div>
                    <label style="
                      font-size: 14px;
                      font-weight: 500;
                      color: var(--text-primary);
                      display: block;
                      margin-bottom: 4px;
                    ">全局字体</label>
                    <p style="
                      font-size: 12px;
                      color: var(--text-secondary);
                      margin: 0;
                    ">设置应用程序的全局字体</p>
                  </div>
                  <select id="global-font" style="
                    padding: 8px 12px;
                    border: 1px solid var(--border-color);
                    border-radius: var(--border-radius);
                    background: var(--bg-primary);
                    color: var(--text-primary);
                    font-size: 14px;
                    min-width: 200px;
                  ">
                    <option value="system">正在加载字体...</option>
                  </select>
                </div>

                <div class="setting-item" style="
                  display: flex;
                  justify-content: space-between;
                  align-items: center;
                  margin-bottom: var(--spacing-md);
                ">
                  <div>
                    <label style="
                      font-size: 14px;
                      font-weight: 500;
                      color: var(--text-primary);
                      display: block;
                      margin-bottom: 4px;
                    ">字体大小</label>
                    <p style="
                      font-size: 12px;
                      color: var(--text-secondary);
                      margin: 0;
                    ">设置应用程序的全局字体大小（10-24px）</p>
                  </div>
                  <div style="display: flex; align-items: center; gap: var(--spacing-sm);">
                    <input type="range" id="global-font-size" min="10" max="24" step="1" value="14" style="
                      width: 120px;
                      accent-color: var(--accent-color);
                    " />
                    <span id="font-size-value" style="
                      font-size: 14px;
                      color: var(--text-primary);
                      min-width: 40px;
                      text-align: right;
                    ">14px</span>
                  </div>
                </div>
              </div>
            </div>

            <!-- AI设置 -->
            <div class="settings-panel" id="ai-settings" style="display: none;">
              <div class="settings-section" style="
                background: var(--bg-secondary);
                border-radius: var(--border-radius-lg);
                padding: var(--spacing-lg);
                margin-bottom: var(--spacing-lg);
              ">
                <h3 style="
                  font-size: 16px;
                  font-weight: 600;
                  color: var(--text-primary);
                  margin: 0 0 var(--spacing-md) 0;
                ">AI配置</h3>

                <!-- AI提供商选择 -->
                <div class="setting-item" style="margin-bottom: var(--spacing-lg);">
                  <label style="
                    font-size: 14px;
                    font-weight: 500;
                    color: var(--text-primary);
                    display: block;
                    margin-bottom: 8px;
                  ">AI提供商</label>
                  <div style="display: flex; gap: var(--spacing-sm); align-items: flex-end;">
                    <div style="flex: 1; position: relative;">
                      <select id="ai-provider" style="
                        width: 100%;
                        padding: 10px 12px;
                        border: 1px solid var(--border-color);
                        border-radius: var(--border-radius);
                        background: var(--bg-primary);
                        color: var(--text-primary);
                        font-size: 14px;
                        box-sizing: border-box;
                      ">
                        <option value="openai">OpenAI (GPT-4o/GPT-3.5)</option>
                        <option value="deepseek">DeepSeek (国产大模型)</option>
                        <option value="claude">Claude (Anthropic)</option>
                        <option value="ollama">Ollama (本地模型)</option>
                        <option value="custom">自定义 API</option>
                      </select>
                    </div>
                    <button id="delete-ai-provider" class="modern-btn danger" style="
                      padding: 10px 12px;
                      font-size: 13px;
                      white-space: nowrap;
                      display: none;
                      align-items: center;
                      gap: 6px;
                    ">
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
                        <path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/>
                      </svg>
                      删除
                    </button>
                    <button id="add-ai-provider" class="modern-btn secondary" style="
                      padding: 10px 16px;
                      font-size: 13px;
                      white-space: nowrap;
                      display: flex;
                      align-items: center;
                      gap: 6px;
                    ">
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
                        <path d="M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z"/>
                      </svg>
                      新增
                    </button>
                  </div>
                </div>

                <!-- 当前提供商配置 -->
                <div id="ai-provider-config">
                  <div class="setting-item" style="margin-bottom: var(--spacing-md);">
                    <label style="
                      font-size: 14px;
                      font-weight: 500;
                      color: var(--text-primary);
                      display: block;
                      margin-bottom: 8px;
                    ">API Key</label>
                    <input type="password" id="ai-api-key" placeholder="输入您的AI API Key" style="
                      width: 100%;
                      padding: 10px 12px;
                      border: 1px solid var(--border-color);
                      border-radius: var(--border-radius);
                      background: var(--bg-primary);
                      color: var(--text-primary);
                      font-size: 14px;
                      box-sizing: border-box;
                    ">
                  </div>

                  <div class="setting-item" style="margin-bottom: var(--spacing-md);">
                    <label style="
                      font-size: 14px;
                      font-weight: 500;
                      color: var(--text-primary);
                      display: block;
                      margin-bottom: 8px;
                    ">模型</label>
                    <div style="display: flex; gap: 8px; align-items: center;">
                      <input type="text" id="ai-model" list="ai-model-list" placeholder="例如: gpt-4o-mini" style="
                        flex: 1;
                        padding: 10px 12px;
                        border: 1px solid var(--border-color);
                        border-radius: var(--border-radius);
                        background: var(--bg-primary);
                        color: var(--text-primary);
                        font-size: 14px;
                        box-sizing: border-box;
                      ">
                      <button type="button" id="ai-fetch-models" class="modern-btn secondary" style="
                        padding: 10px 14px;
                        font-size: 13px;
                        white-space: nowrap;
                        flex-shrink: 0;
                      ">拉取模型</button>
                    </div>
                    <datalist id="ai-model-list">
                      <option value="gpt-4o" label="OpenAI GPT-4o">
                      <option value="gpt-4o-mini" label="OpenAI GPT-4o Mini">
                      <option value="gpt-4-turbo" label="OpenAI GPT-4 Turbo">
                      <option value="claude-sonnet-4-20250514" label="Claude Sonnet 4">
                      <option value="claude-3-5-sonnet-20241022" label="Claude 3.5 Sonnet">
                      <option value="claude-3-haiku-20240307" label="Claude 3 Haiku">
                      <option value="deepseek-chat" label="DeepSeek Chat">
                      <option value="deepseek-reasoner" label="DeepSeek Reasoner">
                      <option value="qwen-turbo" label="通义千问 Turbo">
                      <option value="qwen-plus" label="通义千问 Plus">
                    </datalist>
                    <div id="ai-models-status" style="
                      font-size: 12px;
                      color: var(--text-secondary);
                      margin-top: 4px;
                      display: none;
                    "></div>
                  </div>

                  <div class="setting-item" style="margin-bottom: var(--spacing-lg);">
                    <label style="
                      font-size: 14px;
                      font-weight: 500;
                      color: var(--text-primary);
                      display: block;
                      margin-bottom: 8px;
                    ">Base URL</label>
                    <input type="url" id="ai-base-url" placeholder="例如: https://api.openai.com/v1" style="
                      width: 100%;
                      padding: 10px 12px;
                      border: 1px solid var(--border-color);
                      border-radius: var(--border-radius);
                      background: var(--bg-primary);
                      color: var(--text-primary);
                      font-size: 14px;
                      box-sizing: border-box;
                    ">
                  </div>

                  <!-- 代理设置 -->
                  <div class="setting-item" style="margin-bottom: var(--spacing-lg);">
                    <label style="
                      display: flex;
                      align-items: center;
                      gap: 8px;
                      font-size: 14px;
                      font-weight: 500;
                      color: var(--text-primary);
                      margin-bottom: 12px;
                      cursor: pointer;
                    ">
                      <input type="checkbox" id="ai-use-proxy" style="
                        width: 18px;
                        height: 18px;
                        cursor: pointer;
                      ">
                      使用代理
                    </label>
                    <div style="
                      font-size: 12px;
                      color: var(--text-secondary);
                      margin: -6px 0 12px 26px;
                    ">代理仅对 AI 请求生效</div>

                    <div id="ai-proxy-settings" style="
                      display: none;
                      padding: 12px;
                      border: 1px solid var(--border-color);
                      border-radius: var(--border-radius);
                      background: var(--bg-secondary);
                    ">
                      <div style="margin-bottom: 12px;">
                        <label style="
                          font-size: 13px;
                          color: var(--text-secondary);
                          display: block;
                          margin-bottom: 6px;
                        ">代理类型</label>
                        <select id="ai-proxy-type" style="
                          width: 100%;
                          padding: 8px 10px;
                          border: 1px solid var(--border-color);
                          border-radius: var(--border-radius);
                          background: var(--bg-primary);
                          color: var(--text-primary);
                          font-size: 14px;
                          cursor: pointer;
                        ">
                          <option value="http">HTTP</option>
                          <option value="https">HTTPS</option>
                          <option value="socks5">SOCKS5</option>
                        </select>
                      </div>

                      <div>
                        <label style="
                          font-size: 13px;
                          color: var(--text-secondary);
                          display: block;
                          margin-bottom: 6px;
                        ">代理地址</label>
                        <input type="text" id="ai-proxy-url" placeholder="例如: 127.0.0.1:7890" style="
                          width: 100%;
                          padding: 8px 10px;
                          border: 1px solid var(--border-color);
                          border-radius: var(--border-radius);
                          background: var(--bg-primary);
                          color: var(--text-primary);
                          font-size: 14px;
                          box-sizing: border-box;
                        ">
                        <div style="
                          font-size: 12px;
                          color: var(--text-secondary);
                          margin-top: 4px;
                        ">格式: 主机:端口 或 协议://主机:端口</div>
                      </div>
                    </div>
                  </div>

                  <!-- AI测试功能 -->
                  <div class="setting-item" style="margin-bottom: var(--spacing-md);">
                    <div style="
                      display: flex;
                      align-items: center;
                      gap: var(--spacing-md);
                      margin-bottom: var(--spacing-sm);
                    ">
                      <button id="test-ai-connection" class="modern-btn secondary" style="
                        padding: 8px 16px;
                        font-size: 13px;
                        display: flex;
                        align-items: center;
                        gap: 6px;
                      ">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
                          <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>
                        </svg>
                        测试连接
                      </button>
                      <span id="ai-test-status" style="
                        font-size: 13px;
                        color: var(--text-secondary);
                      ">点击测试AI连接状态</span>
                    </div>
                    <div id="ai-test-result" style="
                      padding: 10px;
                      border-radius: var(--border-radius);
                      background: var(--bg-primary);
                      border: 1px solid var(--border-color);
                      font-size: 13px;
                      color: var(--text-secondary);
                      display: none;
                      max-height: 100px;
                      overflow-y: auto;
                    "></div>
                  </div>
                </div>
              </div>
            </div>

            <!-- 工具设置 -->
            <div class="settings-panel" id="tools-settings" style="display: none;">
              <div class="settings-section" style="
                background: var(--bg-secondary);
                border-radius: var(--border-radius-lg);
                padding: var(--spacing-lg);
                margin-bottom: var(--spacing-lg);
              ">
                <h3 style="
                  font-size: 16px;
                  font-weight: 600;
                  color: var(--text-primary);
                  margin: 0 0 var(--spacing-md) 0;
                ">Busybox 可信命令执行</h3>
                <p style="font-size:12px;color:var(--text-secondary);margin:0 0 12px;">
                  busybox 是静态编译的工具集合，不受系统命令篡改和 LD_PRELOAD 劫持影响。启用后所有 SSH 命令将通过 busybox sh 执行。
                </p>
                <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;">
                  <span id="settings-bb-status" style="font-size:12px;color:var(--text-secondary);">状态: 检测中...</span>
                  <span id="settings-bb-path" style="font-size:11px;color:var(--text-secondary);font-family:monospace;"></span>
                </div>
                <div style="display:flex;gap:8px;flex-wrap:wrap;">
                  <button class="modern-btn primary" id="settings-bb-upload" style="padding:8px 16px;font-size:13px;"
                    onclick="window.__settingsBusyboxUpload?.()">
                    上传本地 busybox
                  </button>
                  <button class="modern-btn secondary" id="settings-bb-enable" style="padding:8px 16px;font-size:13px;"
                    onclick="window.__settingsBusyboxEnable?.()">
                    启用
                  </button>
                  <button class="modern-btn secondary" id="settings-bb-disable" style="padding:8px 16px;font-size:13px;"
                    onclick="window.__settingsBusyboxDisable?.()">
                    禁用
                  </button>
                  <a href="https://busybox.net/downloads/binaries/" target="_blank" rel="noopener"
                    style="padding:8px 16px;font-size:13px;color:var(--accent-color);text-decoration:none;border:1px solid var(--border-color);border-radius:var(--border-radius);display:inline-flex;align-items:center;">
                    busybox 下载地址
                  </a>
                </div>
                <div id="settings-bb-log" style="
                  margin-top:12px;font-size:11px;font-family:monospace;
                  color:var(--text-secondary);white-space:pre-wrap;
                  max-height:120px;overflow-y:auto;display:none;
                  background:var(--bg-tertiary);padding:8px;border-radius:6px;
                "></div>
              </div>

              <!-- 连接诊断:后端 test_ssh_performance / diagnose_shell_performance
                   早就实现并注册了,一直没有入口。赛场上靶机卡顿时,判断是网络问题
                   还是靶机 shell 启动慢(.bashrc 里被塞了东西),这两条最直接 -->
              <div class="settings-section" style="
                background: var(--bg-secondary);
                border-radius: var(--border-radius-lg);
                padding: var(--spacing-lg);
                margin-bottom: var(--spacing-lg);
              ">
                <h3 style="
                  font-size: 16px;
                  font-weight: 600;
                  color: var(--text-primary);
                  margin: 0 0 var(--spacing-md) 0;
                ">连接诊断</h3>
                <p style="font-size:12px;color:var(--text-secondary);margin:0 0 12px;">
                  靶机响应慢时用来定位瓶颈：命令往返耗时反映网络与 SSH 通道，Shell 诊断反映登录脚本是否被拖慢或篡改。
                </p>
                <div style="display:flex;gap:8px;flex-wrap:wrap;">
                  <button class="modern-btn primary" style="padding:8px 16px;font-size:13px;"
                    onclick="window.__diagSshPerf?.()">测试命令往返耗时</button>
                  <button class="modern-btn secondary" style="padding:8px 16px;font-size:13px;"
                    onclick="window.__diagShellPerf?.()">诊断 Shell 启动</button>
                </div>
                <div id="conn-diag-output" style="
                  margin-top:12px;font-size:11px;font-family:var(--font-mono, monospace);
                  color:var(--text-secondary);white-space:pre-wrap;word-break:break-all;
                  max-height:220px;overflow-y:auto;display:none;
                  background:var(--bg-tertiary);padding:8px;border-radius:6px;
                "></div>
              </div>
            </div>

            <!-- 保存按钮 -->
            <div class="settings-actions" style="
              display: flex;
              justify-content: flex-end;
              gap: var(--spacing-md);
              padding-top: var(--spacing-lg);
              border-top: 1px solid var(--border-color);
            ">
              <button class="modern-btn secondary" id="reset-settings" style="
                padding: 10px 20px;
                font-size: 14px;
              ">重置默认</button>
              <button class="modern-btn primary" id="save-settings" style="
                padding: 10px 20px;
                font-size: 14px;
              ">保存设置</button>
            </div>
          </div>
        </div>

        <!-- 新增AI提供商弹窗 -->
        <div id="add-provider-modal" style="
          display: none;
          position: fixed;
          top: 0;
          left: 0;
          width: 100%;
          height: 100%;
          background: rgba(0, 0, 0, 0.5);
          backdrop-filter: blur(4px);
          z-index: 10001;
          align-items: center;
          justify-content: center;
        ">
          <div style="
            background: var(--bg-primary);
            border-radius: var(--border-radius-lg);
            padding: var(--spacing-xl);
            width: 90%;
            max-width: 500px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
            border: 1px solid var(--border-color);
          ">
            <div style="
              display: flex;
              justify-content: space-between;
              align-items: center;
              margin-bottom: var(--spacing-lg);
            ">
              <h3 style="
                font-size: 18px;
                font-weight: 600;
                color: var(--text-primary);
                margin: 0;
              ">新增AI提供商</h3>
              <button id="close-add-provider-modal" style="
                background: none;
                border: none;
                color: var(--text-secondary);
                cursor: pointer;
                padding: 4px;
                border-radius: var(--border-radius);
                transition: all 0.2s;
              ">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/>
                </svg>
              </button>
            </div>

            <form id="add-provider-form">
              <div class="setting-item" style="margin-bottom: var(--spacing-md);">
                <label style="
                  font-size: 14px;
                  font-weight: 500;
                  color: var(--text-primary);
                  display: block;
                  margin-bottom: 8px;
                ">提供商名称 *</label>
                <input type="text" id="new-provider-name" placeholder="例如: 我的Claude、公司AI等" required style="
                  width: 100%;
                  padding: 10px 12px;
                  border: 1px solid var(--border-color);
                  border-radius: var(--border-radius);
                  background: var(--bg-primary);
                  color: var(--text-primary);
                  font-size: 14px;
                  box-sizing: border-box;
                ">
              </div>

              <div class="setting-item" style="margin-bottom: var(--spacing-md);">
                <label style="
                  font-size: 14px;
                  font-weight: 500;
                  color: var(--text-primary);
                  display: block;
                  margin-bottom: 8px;
                ">API Key</label>
                <input type="password" id="new-provider-api-key" placeholder="输入API Key" style="
                  width: 100%;
                  padding: 10px 12px;
                  border: 1px solid var(--border-color);
                  border-radius: var(--border-radius);
                  background: var(--bg-primary);
                  color: var(--text-primary);
                  font-size: 14px;
                  box-sizing: border-box;
                ">
              </div>

              <div class="setting-item" style="margin-bottom: var(--spacing-md);">
                <label style="font-size:14px;font-weight:500;color:var(--text-primary);display:block;margin-bottom:8px;">模型</label>
                <input type="text" id="new-provider-model" list="ai-model-hints" placeholder="选择或输入模型名称" style="
                  width:100%;padding:10px 12px;border:1px solid var(--border-color);border-radius:var(--border-radius);
                  background:var(--bg-primary);color:var(--text-primary);font-size:14px;box-sizing:border-box;">
                <datalist id="ai-model-hints">
                  <option value="gpt-4o" label="OpenAI GPT-4o（推荐，速度快）">
                  <option value="gpt-4o-mini" label="OpenAI GPT-4o Mini（最便宜）">
                  <option value="gpt-4-turbo" label="OpenAI GPT-4 Turbo">
                  <option value="gpt-3.5-turbo" label="OpenAI GPT-3.5（经济）">
                  <option value="claude-sonnet-4-20250514" label="Claude Sonnet 4（推荐）">
                  <option value="claude-3-5-sonnet-20241022" label="Claude 3.5 Sonnet">
                  <option value="claude-3-haiku-20240307" label="Claude 3 Haiku（最快）">
                  <option value="deepseek-chat" label="DeepSeek Chat（性价比高）">
                  <option value="deepseek-reasoner" label="DeepSeek Reasoner（推理）">
                  <option value="qwen-turbo" label="通义千问 Turbo">
                  <option value="qwen-plus" label="通义千问 Plus">
                  <option value="glm-4" label="智谱 GLM-4">
                </datalist>
                <div style="font-size:11px;color:var(--text-secondary);margin-top:4px;">
                  ${createIconHTML('💡', { size: 14 })} 可从列表选择常见模型，也可手动输入自定义模型名称
                </div>
              </div>

              <div class="setting-item" style="margin-bottom: var(--spacing-md);">
                <label style="font-size:14px;font-weight:500;color:var(--text-primary);display:block;margin-bottom:8px;">
                  API 格式
                </label>
                <div style="display:flex;gap:8px;">
                  <label style="display:flex;align-items:center;gap:4px;font-size:12px;color:var(--text-secondary);cursor:pointer;">
                    <input type="radio" name="new-provider-format" value="openai" checked style="accent-color:var(--primary-color);">
                    OpenAI 兼容（大多数国产模型）
                  </label>
                  <label style="display:flex;align-items:center;gap:4px;font-size:12px;color:var(--text-secondary);cursor:pointer;">
                    <input type="radio" name="new-provider-format" value="claude" style="accent-color:var(--primary-color);">
                    Claude 格式
                  </label>
                </div>
                <div style="font-size:11px;color:var(--text-secondary);margin-top:4px;">
                  ${createIconHTML('💡', { size: 14 })} DeepSeek/通义千问/智谱/Ollama 等均兼容 OpenAI 格式
                </div>
              </div>

              <div class="setting-item" style="margin-bottom: var(--spacing-lg);">
                <label style="font-size:14px;font-weight:500;color:var(--text-primary);display:block;margin-bottom:8px;">Base URL</label>
                <input type="url" id="new-provider-base-url" list="ai-baseurl-hints" placeholder="API 端点地址" style="
                  width:100%;padding:10px 12px;border:1px solid var(--border-color);border-radius:var(--border-radius);
                  background:var(--bg-primary);color:var(--text-primary);font-size:14px;box-sizing:border-box;">
                <datalist id="ai-baseurl-hints">
                  <option value="https://api.openai.com/v1/chat/completions" label="OpenAI 官方">
                  <option value="https://api.anthropic.com/v1/messages" label="Claude 官方">
                  <option value="https://api.deepseek.com/v1/chat/completions" label="DeepSeek 官方">
                  <option value="https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions" label="通义千问">
                  <option value="https://open.bigmodel.cn/api/paas/v4/chat/completions" label="智谱 GLM">
                  <option value="http://localhost:11434/v1/chat/completions" label="Ollama 本地">
                </datalist>
                <div style="font-size:11px;color:var(--text-secondary);margin-top:4px;">
                  ${createIconHTML('💡', { size: 14 })} 填入完整 API 地址。不填则使用提供商默认地址
                </div>
              </div>

              <div style="
                display: flex;
                gap: var(--spacing-md);
                justify-content: flex-end;
              ">
                <button type="button" id="cancel-add-provider" class="modern-btn secondary" style="
                  padding: 10px 20px;
                  font-size: 14px;
                ">取消</button>
                <button type="submit" id="save-new-provider" class="modern-btn primary" style="
                  padding: 10px 20px;
                  font-size: 14px;
                ">保存</button>
              </div>
            </form>
          </div>
        </div>
      </div>
    `;
  }

  renderSSHTerminalTitleButton(): string {
    return `
      <button id="ssh-terminal-title-btn" class="modern-btn secondary" style="padding: 6px 12px; font-size: 11px; margin-right: var(--spacing-sm); display: flex; align-items: center; gap: 6px;" title="打开SSH终端">
        <svg width="14" height="14" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
          <rect x="4" y="8" width="40" height="32" rx="2" fill="none" stroke="currentColor" stroke-width="4" stroke-linejoin="bevel"/>
          <path d="M12 18L19 24L12 30" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="bevel"/>
          <path d="M23 32H36" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="bevel"/>
        </svg>
        终端
      </button>
      <button class="modern-btn secondary" style="padding: 6px 12px; font-size: 11px; margin-right: var(--spacing-sm); display: flex; align-items: center; gap: 6px;" title="连接 Web 终端 (ttyd/wetty)" onclick="window.openWebTerminal?.()">
        <svg width="14" height="14" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
          <circle cx="24" cy="24" r="20" fill="none" stroke="currentColor" stroke-width="4"/>
          <path d="M14 20L22 28L14 36" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>
          <path d="M26 34H38" stroke="currentColor" stroke-width="4" stroke-linecap="round"/>
        </svg>
        Web终端
      </button>
    `;
  }
}
