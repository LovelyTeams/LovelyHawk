/**
 * 多机批量执行页
 *
 * 线下防御赛常常一人守多台靶机，同一条加固/排查命令要在每台上跑一遍。
 * BatchServerManager（本目录）早就写好了任务模型、逐台执行与 CSV 导出，
 * 只是一直没有入口，这里补上 UI。
 *
 * 批量任务使用独立、已校验主机指纹的 SSH 会话，不替换当前工作目标。
 * 任意命令无法自动推导回滚，因此提供可选的「回滚命令」输入框：填了就随每台
 *    机器的执行记录一起写进 operationJournal，快照回滚中心即可一键撤销
 *    （见 core/operationJournal.ts）。不填则只记录不可回滚。
 */

import { operationJournal } from '../core/operationJournal';
import { showConfirm, showPrompt } from '../ui/confirmDialog';
import { escapeHtml } from '../core/htmlEscape';
import { logger } from '../core/logger';
import { reportError } from '../utils/errorHandler';
import { statusIcon } from '../ui/iconMapping';
import { BatchServerManager, type BatchTask, type BatchResult } from './batchServerManager';
import type { SSHConfigManager, SSHConnection } from '../ssh/connectionManager';

const log = logger.module('BatchServers');
const TEMPLATE_STORAGE_KEY = 'lovelyres-batch-templates';

interface BatchTemplate {
  id: string;
  name: string;
  command: string;
  restoreCommand: string;
  verifyCommand: string;
  strategy: 'rolling' | 'canary';
  canaryCount: number;
  stopOnFailure: boolean;
}

class BatchServerPageManager {
  private manager: BatchServerManager | null = null;
  private eventsBound = false;
  private selected = new Set<string>();
  private running = false;
  private lastTask: BatchTask | null = null;

  /** 复用 app 的 SSHConfigManager 实例——「当前活动连接」是内存状态，另起一份会各说各话 */
  private getManager(): BatchServerManager | null {
    if (this.manager) return this.manager;
    const cfg = (window as any).app?.sshManager?.getConfigManager?.() as SSHConfigManager | undefined;
    if (!cfg) return null;
    this.manager = new BatchServerManager(cfg);
    return this.manager;
  }

  initialize(): void {
    if (!this.eventsBound) { this.bindEvents(); this.eventsBound = true; }
    this.renderServerList();
    this.renderResults(this.lastTask);
    this.renderHistory();
    this.renderTemplates();
  }

  // ──────── 渲染 ────────

  private servers(): SSHConnection[] {
    return this.getManager()?.getAvailableServers() ?? [];
  }

  private visibleServers(): SSHConnection[] {
    const query = (document.getElementById('bs-target-filter') as HTMLInputElement | null)?.value.trim().toLowerCase() || '';
    const environment = (document.getElementById('bs-environment-filter') as HTMLSelectElement | null)?.value || '';
    return this.servers().filter(server => {
      const haystack = [server.name, server.host, server.username, server.role, server.group, ...(server.tags || [])]
        .filter(Boolean).join(' ').toLowerCase();
      return (!query || haystack.includes(query)) && (!environment || server.environment === environment);
    });
  }

  private renderServerList(): void {
    const el = document.getElementById('bs-server-list');
    if (!el) return;

    const list = this.visibleServers();
    if (!list.length) {
      el.innerHTML = `<div class="bs-empty">
        还没有保存的服务器连接。先在「连接服务器」里添加并勾选「记住此连接」，这里才会出现可选目标。
      </div>`;
      this.updateSelectionSummary();
      return;
    }

    el.innerHTML = list.map(c => {
      const checked = this.selected.has(c.id) ? 'checked' : '';
      return `
        <label class="bs-server-item">
          <input type="checkbox" data-bs-target="${escapeHtml(c.id)}" ${checked} />
          <span class="bs-server-name">${escapeHtml(c.name)}</span>
          <span class="bs-server-addr">${escapeHtml(c.username)}@${escapeHtml(c.host)}:${escapeHtml(c.port)}</span>
          <span class="bs-server-tags">${escapeHtml([c.environment, c.role, c.group, ...(c.tags || [])].filter(Boolean).join(' · ') || '未分类')}</span>
          <span class="bs-server-auth">${c.authType === 'password' ? '密码' : '密钥'}</span>
        </label>`;
    }).join('');

    this.updateSelectionSummary();
  }

  private updateSelectionSummary(): void {
    const el = document.getElementById('bs-selection-summary');
    if (el) el.textContent = `已选 ${this.selected.size} 台 · 当前范围 ${this.visibleServers().length} / ${this.servers().length} 台`;
    const runBtn = document.getElementById('bs-run') as HTMLButtonElement | null;
    if (runBtn) runBtn.disabled = this.running || this.selected.size === 0;
  }

  private renderResults(task: BatchTask | null): void {
    const el = document.getElementById('bs-results');
    if (!el) return;
    if (!task || !task.results.length) {
      el.innerHTML = '<div class="bs-empty">执行后在此显示每台机器的结果</div>';
      return;
    }

    const rows = task.results.map((r, i) => this.renderResultRow(r, i)).join('');
    const ok = task.results.filter(r => r.status === 'success').length;
    const fail = task.results.filter(r => r.status !== 'success').length;

    el.innerHTML = `
      <div class="bs-result-head">
        <span class="bs-result-title">${escapeHtml(task.name)}</span>
        <span class="bs-result-stat ok">成功 ${ok}</span>
        <span class="bs-result-stat ${fail ? 'fail' : ''}">失败 ${fail}</span>
        <button class="modern-btn secondary bs-mini" data-bs-action="export-csv">导出 CSV</button>
      </div>
      <div class="bs-result-rows">${rows}</div>`;
  }

  private renderResultRow(r: BatchResult, index: number): string {
    const icon = statusIcon(r.status === 'success' ? 'success' : 'error', { size: 14 });
    const body = r.status === 'success' ? (r.output || '(无输出)') : (r.error || '执行失败');
    return `
      <div class="bs-result-row ${r.status}">
        <div class="bs-result-row-head" data-bs-action="toggle-result" data-bs-index="${index}">
          ${icon}
          <span class="bs-rr-name">${escapeHtml(r.serverName)}</span>
          <span class="bs-rr-host">${escapeHtml(r.host)}</span>
          <span class="bs-rr-dur">${(r.duration / 1000).toFixed(1)}s</span>
        </div>
        <pre class="bs-result-output">${escapeHtml(body)}</pre>
      </div>`;
  }

  private renderHistory(): void {
    const el = document.getElementById('bs-history');
    if (!el) return;
    const history = (this.getManager()?.getHistory() ?? []).slice().reverse();
    if (!history.length) {
      el.innerHTML = '<div class="bs-empty">暂无历史任务</div>';
      return;
    }
    el.innerHTML = history.slice(0, 20).map(t => {
      const ok = t.results.filter(r => r.status === 'success').length;
      return `
        <div class="bs-history-item" data-bs-action="load-history" data-bs-task="${escapeHtml(t.id)}">
          <span class="bs-hi-name">${escapeHtml(t.name)}</span>
          <code class="bs-hi-cmd">${escapeHtml(t.command)}</code>
          <span class="bs-hi-stat">${ok}/${t.results.length} 成功</span>
        </div>`;
    }).join('');
  }

  private loadTemplates(): BatchTemplate[] {
    try {
      const raw = localStorage.getItem(TEMPLATE_STORAGE_KEY);
      const parsed = raw ? JSON.parse(raw) : [];
      return Array.isArray(parsed) ? parsed : [];
    } catch { return []; }
  }

  private saveTemplates(templates: BatchTemplate[]): void {
    try { localStorage.setItem(TEMPLATE_STORAGE_KEY, JSON.stringify(templates.slice(-50))); }
    catch (error) { reportError(error, { module: 'BatchServers', action: '保存任务模板' }); }
  }

  private renderTemplates(): void {
    const select = document.getElementById('bs-template') as HTMLSelectElement | null;
    if (!select) return;
    const current = select.value;
    select.innerHTML = '<option value="">选择任务模板…</option>' + this.loadTemplates()
      .map(template => `<option value="${escapeHtml(template.id)}">${escapeHtml(template.name)}</option>`).join('');
    if ([...select.options].some(option => option.value === current)) select.value = current;
  }

  private async saveTemplate(): Promise<void> {
    const command = (document.getElementById('bs-command') as HTMLTextAreaElement | null)?.value.trim() || '';
    if (!command) { window.showNotification?.('请先填写执行命令', 'warning'); return; }
    const suggested = (document.getElementById('bs-task-name') as HTMLInputElement | null)?.value.trim() || command.slice(0, 32);
    const name = await showPrompt({ title: '保存任务模板', message: '模板名称', defaultValue: suggested });
    if (!name?.trim()) return;
    const template: BatchTemplate = {
      id: `batch-template-${Date.now()}`,
      name: name.trim().slice(0, 80),
      command,
      restoreCommand: (document.getElementById('bs-restore') as HTMLInputElement | null)?.value.trim() || '',
      verifyCommand: (document.getElementById('bs-verify') as HTMLInputElement | null)?.value.trim() || '',
      strategy: (document.getElementById('bs-strategy') as HTMLSelectElement | null)?.value === 'canary' ? 'canary' : 'rolling',
      canaryCount: Math.max(1, Number((document.getElementById('bs-canary-count') as HTMLInputElement | null)?.value || 1)),
      stopOnFailure: (document.getElementById('bs-stop-on-failure') as HTMLInputElement | null)?.checked === true,
    };
    const templates = this.loadTemplates().filter(item => item.name !== template.name);
    templates.push(template);
    this.saveTemplates(templates);
    this.renderTemplates();
    const select = document.getElementById('bs-template') as HTMLSelectElement | null;
    if (select) select.value = template.id;
    window.showNotification?.('批量任务模板已保存', 'success');
  }

  private loadSelectedTemplate(): void {
    const id = (document.getElementById('bs-template') as HTMLSelectElement | null)?.value;
    const template = this.loadTemplates().find(item => item.id === id);
    if (!template) return;
    const setValue = (elementId: string, value: string) => {
      const element = document.getElementById(elementId) as HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement | null;
      if (element) element.value = value;
    };
    setValue('bs-task-name', template.name);
    setValue('bs-command', template.command);
    setValue('bs-restore', template.restoreCommand);
    setValue('bs-verify', template.verifyCommand);
    setValue('bs-strategy', template.strategy);
    setValue('bs-canary-count', String(template.canaryCount));
    const stop = document.getElementById('bs-stop-on-failure') as HTMLInputElement | null;
    if (stop) stop.checked = template.stopOnFailure;
  }

  private async deleteSelectedTemplate(): Promise<void> {
    const select = document.getElementById('bs-template') as HTMLSelectElement | null;
    const id = select?.value;
    if (!id) return;
    const template = this.loadTemplates().find(item => item.id === id);
    if (!template) return;
    const confirmed = await showConfirm({
      title: '删除任务模板', message: `确定删除“${template.name}”？`,
      dangerous: true, defaultFocus: 'cancel',
    });
    if (!confirmed) return;
    this.saveTemplates(this.loadTemplates().filter(item => item.id !== id));
    this.renderTemplates();
  }

  private setProgress(percent: number, text: string): void {
    const bar = document.getElementById('bs-progress-bar');
    const label = document.getElementById('bs-progress-label');
    const wrap = document.getElementById('bs-progress');
    if (wrap) wrap.style.display = percent >= 0 ? 'block' : 'none';
    if (bar) bar.style.width = `${Math.max(0, percent)}%`;
    if (label) label.textContent = text;
  }

  // ──────── 事件 ────────

  private bindEvents(): void {
    document.addEventListener('change', (e) => {
      const t = e.target as HTMLElement;
      if (t.id === 'bs-environment-filter') {
        this.renderServerList();
        return;
      }
      const id = t?.getAttribute?.('data-bs-target');
      if (!id) return;
      if ((t as HTMLInputElement).checked) this.selected.add(id);
      else this.selected.delete(id);
      this.updateSelectionSummary();
    });

    document.addEventListener('input', (e) => {
      if ((e.target as HTMLElement)?.id === 'bs-target-filter') this.renderServerList();
    });

    document.addEventListener('click', (e) => {
      const t = (e.target as HTMLElement)?.closest?.('[data-bs-action]') as HTMLElement | null;
      if (!t) return;
      const action = t.getAttribute('data-bs-action');

      switch (action) {
        case 'select-all':
          this.visibleServers().forEach(c => this.selected.add(c.id));
          this.renderServerList();
          break;
        case 'select-none':
          this.selected.clear();
          this.renderServerList();
          break;
        case 'run':
          void this.run();
          break;
        case 'save-template':
          void this.saveTemplate();
          break;
        case 'load-template':
          this.loadSelectedTemplate();
          break;
        case 'delete-template':
          void this.deleteSelectedTemplate();
          break;
        case 'cancel':
          this.getManager()?.cancelBatch();
          this.setProgress(-1, '');
          break;
        case 'export-csv':
          if (this.lastTask) this.getManager()?.exportTaskAsCSV(this.lastTask);
          break;
        case 'toggle-result':
          t.parentElement?.classList.toggle('expanded');
          break;
        case 'load-history': {
          const id = t.getAttribute('data-bs-task');
          const task = this.getManager()?.getHistory().find(x => x.id === id) || null;
          this.lastTask = task;
          this.renderResults(task);
          break;
        }
      }
    });
  }

  // ──────── 执行 ────────

  private async run(): Promise<void> {
    const mgr = this.getManager();
    if (!mgr) { window.showNotification?.('应用尚未初始化完成', 'error'); return; }
    if (this.running) return;

    const cmdEl = document.getElementById('bs-command') as HTMLTextAreaElement | null;
    const restoreEl = document.getElementById('bs-restore') as HTMLInputElement | null;
    const verifyEl = document.getElementById('bs-verify') as HTMLInputElement | null;
    const nameEl = document.getElementById('bs-task-name') as HTMLInputElement | null;

    const command = cmdEl?.value?.trim() || '';
    const restoreCommand = restoreEl?.value?.trim() || '';
    const verifyCommand = verifyEl?.value?.trim() || '';
    const name = nameEl?.value?.trim() || command.slice(0, 40) || '批量任务';

    if (!command) {
      window.showNotification?.('请输入要执行的命令', 'warning');
      cmdEl?.focus();
      return;
    }
    const targets = this.servers().filter(server => this.selected.has(server.id)).map(server => server.id);
    if (!targets.length) {
      window.showNotification?.('请至少选择一台目标服务器', 'warning');
      return;
    }

    const names = this.servers().filter(c => targets.includes(c.id)).map(c => c.name);
    const strategy = (document.getElementById('bs-strategy') as HTMLSelectElement | null)?.value === 'canary' ? 'canary' : 'rolling';
    const canaryCount = Math.max(1, Math.min(targets.length, Number((document.getElementById('bs-canary-count') as HTMLInputElement | null)?.value || 1)));
    const stopOnFailure = (document.getElementById('bs-stop-on-failure') as HTMLInputElement | null)?.checked === true;
    const ok = await showConfirm({
      title: '确认批量执行',
      message:
        `将在 ${targets.length} 台机器上以当前用户执行：\n\n${command}\n\n` +
        `目标：${names.join('、')}\n\n` +
        `策略：${strategy === 'canary' ? `先执行 ${canaryCount} 台 Canary，全部成功才继续` : `逐台滚动执行${stopOnFailure ? '，遇错即停' : ''}`}。` +
        `每台必须已经过一次交互连接并保存主机指纹；批量任务使用独立会话，不替换当前工作目标。` +
        (verifyCommand ? `\n\n验证命令：${verifyCommand}` : `\n\n未填写验证命令，只能确认执行退出码，无法确认业务状态。`) +
        (restoreCommand ? `\n\n回滚命令已填写，将随每台记录写入操作日志。` : `\n\n未填写回滚命令，本次操作将无法一键撤销。`),
      confirmText: '开始执行',
      cancelText: '取消',
      dangerous: true,
    });
    if (!ok) return;

    this.running = true;
    this.updateSelectionSummary();
    document.getElementById('bs-cancel')?.removeAttribute('hidden');
    this.setProgress(0, '准备中…');

    try {
      const task = await mgr.executeBatch(name, command, targets, (p) => {
        this.setProgress(p.percent, `${p.completedServers}/${p.totalServers} · ${p.currentServer}`);
      }, { strategy, canaryCount, stopOnFailure, verifyCommand });

      this.lastTask = task;
      this.renderResults(task);
      this.renderHistory();

      // 每台真正发起过执行的机器都写回执；失败也可能已产生部分变更，不能丢失证据。
      for (const r of task.results) {
        if (r.status === 'skipped' || !r.target) continue;
        operationJournal.record({
          source: 'manual',
          server: r.host,
          target: r.target,
          allowStableTargetReconnect: true,
          title: `批量执行：${name}${r.status === 'success' ? '' : '（失败或验证未通过）'}`,
          command,
          restoreCommand: restoreCommand || undefined,
          output: r.output,
          exitCode: r.exitCode,
          timedOut: r.timedOut,
          verifyCommand: r.verifyCommand,
          verifyOutput: r.verifyOutput,
          verified: r.verified,
          success: r.status === 'success',
        });
      }

      const failed = task.results.filter(r => r.status !== 'success');
      if (failed.length) {
        window.showNotification?.(
          `批量任务完成，${failed.length} 台失败：${failed.map(f => f.serverName).join('、')}`,
          'warning',
        );
      }
      log.info('批量任务完成', { name, total: task.results.length, failed: failed.length });
    } catch (e) {
      reportError(e, { module: 'BatchServers', action: '批量执行' });
    } finally {
      this.running = false;
      this.setProgress(-1, '');
      document.getElementById('bs-cancel')?.setAttribute('hidden', '');
      this.updateSelectionSummary();
    }
  }
}

export const batchServerPageManager = new BatchServerPageManager();
