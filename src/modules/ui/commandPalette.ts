/**
 * 全局命令面板：导航所有主页面，并把应急命令库作为可搜索入口。
 * 命令结果只负责定位，绝不会从面板直接执行。
 */

import { escapeHtml } from '../core/htmlEscape';
import { logger } from '../core/logger';

const log = logger.module('CommandPalette');

export interface CommandPalettePage {
  id: string;
  title: string;
  desc: string;
  shortcut: string;
}

/** 前 8 项同时决定 Ctrl+1…8 的比赛快捷键。 */
export const commandPalettePages: CommandPalettePage[] = [
  { id: 'secfix', title: '安全速查', desc: '漏洞修复与比赛处置片段库', shortcut: 'Ctrl+1' },
  { id: 'system-info', title: '系统信息', desc: '进程、网络、服务与用户', shortcut: 'Ctrl+2' },
  { id: 'remote-operations', title: 'SFTP 文件', desc: '打开远程文件管理窗口', shortcut: 'Ctrl+3' },
  { id: 'docker', title: 'Docker 容器', desc: '容器巡检、处置与取证', shortcut: 'Ctrl+4' },
  { id: 'emergency-commands', title: '应急命令', desc: '离线调查命令库', shortcut: 'Ctrl+5' },
  { id: 'packet-capture', title: '网络抓包', desc: '流量分析与 PCAP 证据', shortcut: 'Ctrl+6' },
  { id: 'quick-detection', title: '快速检测', desc: '10–20 秒比赛快速摸底', shortcut: 'Ctrl+7' },
  { id: 'log-analysis', title: '日志审计', desc: '日志检索、IOC 与威胁分析', shortcut: 'Ctrl+8' },
  { id: 'kubernetes', title: 'Kubernetes', desc: '集群巡检与安全处置', shortcut: '' },
  { id: 'firewall', title: '防火墙', desc: '规则检查、变更与回滚', shortcut: '' },
  { id: 'integrity', title: '文件完整性', desc: '基线、差异与证据', shortcut: '' },
  { id: 'snapshot', title: '快照回滚', desc: '处置快照与恢复', shortcut: '' },
  { id: 'check-audit', title: 'Check 审计', desc: '核查脚本与审计结果', shortcut: '' },
  { id: 'database', title: '数据库', desc: '数据库运维与应急操作', shortcut: '' },
  { id: 'java-hot-update', title: 'Java 热更新', desc: 'JVM 诊断与热更新', shortcut: '' },
  { id: 'baseline-quick-edit', title: '快速编辑', desc: '配置基线与原子文件编辑', shortcut: '' },
  { id: 'batch-servers', title: '多机批量', desc: 'Canary、滚动与批量验证', shortcut: '' },
  { id: 'notes', title: '笔记', desc: '比赛笔记与调查记录', shortcut: '' },
  { id: 'ai-history', title: 'AI 历史', desc: '案件分析与解释记录', shortcut: '' },
  { id: 'web-terminal', title: 'Web 终端', desc: '连接 ttyd、Wetty 等终端', shortcut: '' },
];

interface PaletteEmergencyCommand {
  id: string;
  title: string;
  category: string;
  desc: string;
  command: string;
}

let renderGeneration = 0;

function pageIcon(): string {
  return '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 3v18M3 9h6"/></svg>';
}

function commandIcon(): string {
  return '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 17l6-6-6-6"/><path d="M12 19h8"/></svg>';
}

async function searchEmergencyCommands(query: string): Promise<PaletteEmergencyCommand[]> {
  if (query.trim().length < 2) return [];
  const normalized = query.trim().toLowerCase();
  const { emergencyCategories } = await import('../emergency/commands');
  const matches: PaletteEmergencyCommand[] = [];
  for (const category of emergencyCategories) {
    for (const item of category.items) {
      const command = item.cmd || item.commands?.default || '';
      const haystack = `${category.title} ${item.name} ${item.desc || ''} ${command}`.toLowerCase();
      if (!haystack.includes(normalized)) continue;
      matches.push({
        id: item.id,
        title: item.name,
        category: category.title,
        desc: item.desc || '应急命令',
        command,
      });
      if (matches.length >= 16) return matches;
    }
  }
  return matches;
}

function renderPageGroup(pages: CommandPalettePage[], activeOffset: number): string {
  if (pages.length === 0) return '';
  return `
    <div class="command-palette-group">
      <div class="command-palette-group-title">页面与工具</div>
      ${pages.map((page, index) => `
        <div class="command-palette-item ${index + activeOffset === 0 ? 'active' : ''}" data-palette-page="${escapeHtml(page.id)}">
          <div class="command-palette-item-icon">${pageIcon()}</div>
          <div class="command-palette-item-text">
            <div class="command-palette-item-title">${escapeHtml(page.title)}</div>
            <div class="command-palette-item-desc">${escapeHtml(page.desc)}</div>
          </div>
          ${page.shortcut ? `<span class="command-palette-item-shortcut">${escapeHtml(page.shortcut)}</span>` : ''}
        </div>
      `).join('')}
    </div>`;
}

function renderCommandGroup(commands: PaletteEmergencyCommand[], activeOffset: number): string {
  if (commands.length === 0) return '';
  return `
    <div class="command-palette-group">
      <div class="command-palette-group-title">应急命令 · 仅定位，不自动执行</div>
      ${commands.map((item, index) => `
        <div class="command-palette-item ${index + activeOffset === 0 ? 'active' : ''}" data-palette-command="${escapeHtml(item.id)}">
          <div class="command-palette-item-icon">${commandIcon()}</div>
          <div class="command-palette-item-text">
            <div class="command-palette-item-title">${escapeHtml(item.title)} <small>· ${escapeHtml(item.category)}</small></div>
            <div class="command-palette-item-desc" title="${escapeHtml(item.command)}">${escapeHtml(item.desc)} · ${escapeHtml(item.command)}</div>
          </div>
          <span class="command-palette-item-shortcut">定位</span>
        </div>
      `).join('')}
    </div>`;
}

async function renderPaletteResults(query: string): Promise<void> {
  const results = document.getElementById('command-palette-results');
  if (!results) return;
  const generation = ++renderGeneration;
  const normalized = query.trim().toLowerCase();
  const pages = normalized
    ? commandPalettePages.filter(page => `${page.title} ${page.desc}`.toLowerCase().includes(normalized))
    : commandPalettePages;

  let commands: PaletteEmergencyCommand[] = [];
  try {
    commands = await searchEmergencyCommands(query);
  } catch (error) {
    log.warn('加载应急命令索引失败', error);
  }
  if (generation !== renderGeneration || !document.getElementById('command-palette-results')) return;

  if (pages.length === 0 && commands.length === 0) {
    results.innerHTML = '<div class="command-palette-empty">没有找到匹配结果</div>';
    return;
  }
  results.innerHTML = renderPageGroup(pages, 0) + renderCommandGroup(commands, pages.length);
}

export function openPalette(): void {
  const overlay = document.getElementById('command-palette-overlay');
  const input = document.getElementById('command-palette-input') as HTMLInputElement | null;
  if (!overlay) return;
  overlay.classList.add('active');
  if (input) {
    input.value = '';
    input.focus();
  }
  void renderPaletteResults('');
}

export function closePalette(): void {
  document.getElementById('command-palette-overlay')?.classList.remove('active');
}

function selectPaletteItem(item: HTMLElement): void {
  const switchPage = (window as unknown as { switchPage?: (pageId: string) => void }).switchPage;
  const pageId = item.dataset.palettePage;
  if (pageId) {
    switchPage?.(pageId);
    closePalette();
    return;
  }

  const commandId = item.dataset.paletteCommand;
  if (!commandId) return;
  switchPage?.('emergency-commands');
  closePalette();
  window.setTimeout(() => {
    const manager = (window as unknown as {
      emergencyPageManager?: { selectCommand: (id: string) => void };
    }).emergencyPageManager;
    if (manager) manager.selectCommand(commandId);
    else window.showNotification?.('应急命令页面尚未初始化', 'warning');
  }, 0);
}

/** 注入一次 DOM，并使用委托事件保持结果重渲染后仍可操作。 */
export function initCommandPalette(): void {
  if (document.getElementById('command-palette-overlay')) return;
  document.body.insertAdjacentHTML('beforeend', `
    <div id="command-palette-overlay" class="command-palette-overlay">
      <div class="command-palette">
        <div class="command-palette-header">
          <div class="command-palette-icon">${commandIcon()}</div>
          <input id="command-palette-input" class="command-palette-input" type="text" placeholder="搜索全部页面或应急命令…" autocomplete="off" />
          <span class="command-palette-shortcut">ESC</span>
        </div>
        <div id="command-palette-results" class="command-palette-results"></div>
        <div class="command-palette-footer">
          <div class="command-palette-footer-hint">
            <span><kbd>↑↓</kbd> 导航</span><span><kbd>↵</kbd> 选择</span><span><kbd>Esc</kbd> 关闭</span>
          </div>
          <span>LovelyRes · 不自动执行命令</span>
        </div>
      </div>
    </div>`);

  (window as unknown as { openCommandPalette?: () => void }).openCommandPalette = openPalette;
  (window as unknown as { closeCommandPalette?: () => void }).closeCommandPalette = closePalette;

  const input = document.getElementById('command-palette-input') as HTMLInputElement | null;
  input?.addEventListener('input', () => { void renderPaletteResults(input.value); });
  input?.addEventListener('keydown', event => {
    if (event.key === 'Escape') {
      closePalette();
      return;
    }
    if (event.key === 'Enter') {
      const active = document.querySelector('.command-palette-item.active') as HTMLElement | null;
      if (active) selectPaletteItem(active);
      return;
    }
    if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return;
    event.preventDefault();
    const items = Array.from(document.querySelectorAll<HTMLElement>('.command-palette-item'));
    if (items.length === 0) return;
    const activeIndex = items.findIndex(item => item.classList.contains('active'));
    items.forEach(item => item.classList.remove('active'));
    const nextIndex = event.key === 'ArrowDown'
      ? (activeIndex + 1) % items.length
      : (activeIndex <= 0 ? items.length - 1 : activeIndex - 1);
    items[nextIndex].classList.add('active');
    items[nextIndex].scrollIntoView({ block: 'nearest' });
  });

  const overlay = document.getElementById('command-palette-overlay');
  overlay?.addEventListener('click', event => {
    const target = event.target as HTMLElement;
    if (target === overlay) closePalette();
    const item = target.closest<HTMLElement>('.command-palette-item');
    if (item) selectPaletteItem(item);
  });
}
