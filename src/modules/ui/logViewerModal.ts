/**
 * 日志查看弹窗
 *
 * 由状态栏「日志」按钮触发，展示前端 logger 环形缓冲与后端 app_log 环形缓冲，
 * 可在两个标签页间切换。正式包 drop 掉了所有 console 输出（vite.config.ts
 * 的 esbuild.drop），这两个缓冲区是运行时错误唯一的落点，必须给它们一个出口。
 *
 * 弹窗懒加载挂到 document.body，不走 main-workspace 的 outerHTML 替换，
 * 因此页面切换不会影响它（见 AGENTS.md 对 renderMainWorkspace 的说明）。
 */

import { invoke } from '@tauri-apps/api/core';
import {
  logger,
  readSavedLogLevel,
  LOG_LEVEL_STORAGE_KEY,
  type LogLevelName,
} from '../core/logger';
import { reportError } from '../utils/errorHandler';

const log = logger.module('LogViewer');

interface BackendLogEntry {
  timestamp: string;
  level: string;
  message: string;
}

type LogTab = 'frontend' | 'backend';

let overlay: HTMLElement | null = null;
let viewEl: HTMLElement | null = null;
let countEl: HTMLElement | null = null;
let levelSel: HTMLSelectElement | null = null;
let currentTab: LogTab = 'frontend';
let refreshTimer: number | null = null;
let keyHandler: ((e: KeyboardEvent) => void) | null = null;

const VALID_LEVELS: LogLevelName[] = ['debug', 'info', 'warn', 'error'];

function formatBackendEntries(entries: BackendLogEntry[]): string {
  return entries
    .map((e) => `[${e.timestamp}] [${e.level}] ${e.message}`)
    .join('\n');
}

async function getCurrentText(): Promise<{ text: string; count: number }> {
  if (currentTab === 'frontend') {
    const buf = logger.getBuffer();
    return { text: logger.exportAsText(), count: buf.length };
  }
  const entries = await invoke<BackendLogEntry[]>('get_backend_logs');
  return { text: formatBackendEntries(entries), count: entries.length };
}

async function refresh(): Promise<void> {
  if (!viewEl) return;
  try {
    const { text, count } = await getCurrentText();
    viewEl.textContent = text || '(暂无日志)';
    if (countEl) countEl.textContent = `${count} 条`;
    viewEl.scrollTop = viewEl.scrollHeight;
  } catch (e) {
    viewEl.textContent = `读取日志失败：${e}`;
    reportError(e, { module: 'LogViewer', action: '读取日志', silent: true });
  }
}

function switchTab(tab: LogTab): void {
  currentTab = tab;
  overlay?.querySelectorAll('.log-modal-tab').forEach((el) => {
    el.classList.toggle('active', (el as HTMLElement).dataset.tab === tab);
  });
  // 记录级别只对前端 logger 有意义
  if (levelSel) levelSel.style.display = tab === 'frontend' ? '' : 'none';
  void refresh();
}

function buildOverlay(): HTMLElement {
  const root = document.createElement('div');
  root.className = 'log-modal-overlay';
  root.innerHTML = `
    <div class="log-modal" role="dialog" aria-label="运行日志">
      <div class="log-modal-header">
        <h3 class="log-modal-title">运行日志</h3>
        <button type="button" class="log-modal-close" title="关闭">×</button>
      </div>
      <div class="log-modal-tabs">
        <button type="button" class="log-modal-tab active" data-tab="frontend">前端</button>
        <button type="button" class="log-modal-tab" data-tab="backend">后端</button>
      </div>
      <div class="log-modal-toolbar">
        <select class="log-modal-level" title="前端日志记录级别">
          <option value="debug">调试（最详细）</option>
          <option value="info">信息（默认）</option>
          <option value="warn">警告</option>
          <option value="error">仅错误</option>
        </select>
        <button type="button" class="modern-btn secondary log-modal-btn" data-action="refresh">刷新</button>
        <button type="button" class="modern-btn secondary log-modal-btn" data-action="copy">复制</button>
        <button type="button" class="modern-btn secondary log-modal-btn" data-action="export">导出为文件</button>
        <button type="button" class="modern-btn secondary log-modal-btn" data-action="clear">清空</button>
        <span class="log-modal-count"></span>
      </div>
      <div class="log-modal-view">加载中…</div>
    </div>
  `;

  viewEl = root.querySelector('.log-modal-view');
  countEl = root.querySelector('.log-modal-count');
  levelSel = root.querySelector('.log-modal-level');

  root.querySelector('.log-modal-close')?.addEventListener('click', closeLogViewer);
  root.addEventListener('click', (e) => {
    if (e.target === root) closeLogViewer();
  });
  root.querySelectorAll('.log-modal-tab').forEach((el) => {
    el.addEventListener('click', () => switchTab((el as HTMLElement).dataset.tab as LogTab));
  });
  root.querySelector('[data-action="refresh"]')?.addEventListener('click', () => void refresh());
  root.querySelector('[data-action="copy"]')?.addEventListener('click', () => void copyLogs());
  root.querySelector('[data-action="export"]')?.addEventListener('click', () => void exportLogs());
  root.querySelector('[data-action="clear"]')?.addEventListener('click', () => void clearLogs());

  if (levelSel) {
    levelSel.value = readSavedLogLevel();
    levelSel.addEventListener('change', () => {
      const level = levelSel?.value as LogLevelName;
      if (!VALID_LEVELS.includes(level)) return;
      logger.setLevel(level);
      try {
        localStorage.setItem(LOG_LEVEL_STORAGE_KEY, level);
      } catch {
        /* intentional: 隐私模式下 localStorage 不可用，级别仅在本次会话生效 */
      }
      log.info(`日志记录级别已切换为 ${level}`);
      void refresh();
    });
  }

  return root;
}

async function copyLogs(): Promise<void> {
  try {
    const { text } = await getCurrentText();
    if (!text) {
      window.showNotification?.('暂无日志可复制', 'info');
      return;
    }
    await navigator.clipboard.writeText(text);
    window.showNotification?.('日志已复制到剪贴板', 'success');
  } catch (e) {
    reportError(e, { module: 'LogViewer', action: '复制日志' });
  }
}

async function exportLogs(): Promise<void> {
  try {
    const { text } = await getCurrentText();
    if (!text) {
      window.showNotification?.('暂无日志可导出', 'info');
      return;
    }
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const stamp = new Date().toISOString().slice(0, 19).replace(/[T:]/g, '-');
    const a = document.createElement('a');
    a.href = url;
    a.download = `LovelyRes-${currentTab === 'frontend' ? '前端' : '后端'}日志-${stamp}.log`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    window.showNotification?.('日志已导出', 'success');
  } catch (e) {
    reportError(e, { module: 'LogViewer', action: '导出日志' });
  }
}

async function clearLogs(): Promise<void> {
  try {
    if (currentTab === 'frontend') {
      logger.clear();
    } else {
      await invoke('clear_backend_logs');
    }
    await refresh();
    window.showNotification?.('日志已清空', 'info');
  } catch (e) {
    reportError(e, { module: 'LogViewer', action: '清空日志' });
  }
}

/** 打开日志弹窗（幂等：已打开时只刷新内容） */
export function openLogViewer(): void {
  if (!overlay) {
    overlay = buildOverlay();
    document.body.appendChild(overlay);
  }
  overlay.classList.add('visible');
  switchTab(currentTab);

  if (refreshTimer === null) {
    refreshTimer = window.setInterval(() => void refresh(), 2000);
  }
  if (!keyHandler) {
    keyHandler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') closeLogViewer();
    };
    document.addEventListener('keydown', keyHandler);
  }
}

export function closeLogViewer(): void {
  overlay?.classList.remove('visible');
  if (refreshTimer !== null) {
    window.clearInterval(refreshTimer);
    refreshTimer = null;
  }
  if (keyHandler) {
    document.removeEventListener('keydown', keyHandler);
    keyHandler = null;
  }
}
