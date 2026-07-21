/**
 * 快照与回滚中心
 *
 * 两个子标签：
 *  A. 操作历史 & 回滚 —— 展示 operationJournal 里本机的所有可回滚操作，支持单条 / 一键全回滚
 *  B. 关键目录快照   —— 开赛时一键打包 /etc、web 根目录、crontab、口令文件等到靶机本地，
 *                       随时按路径恢复。快照本身与恢复动作都会记入 operationJournal。
 *
 * 页面注册见 modernUIRenderer(renderSnapshotPage) / globalFunctions(switchPage) / app.ts(AppState)。
 */

import { invoke } from '@tauri-apps/api/core';
import { operationJournal, opSourceLabel } from '../core/operationJournal';
import { sshConnectionManager } from '../remote/sshConnectionManager';
import { showConfirm } from '../ui/confirmDialog';
import { shq } from '../core/shellEscape';
import { logger } from '../core/logger';
import { reportError } from '../utils/errorHandler';

const log = logger.module('Snapshot');

interface SnapshotPathDef {
  label: string;
  path: string;               // 靶机上的源路径 / 或 'CRONTAB' 特殊标记
  kind: 'dir' | 'file' | 'crontab';
  defaultOn: boolean;
}

interface SnapshotItem {
  label: string;
  path: string;
  kind: 'dir' | 'file' | 'crontab';
  archive: string;            // 靶机上的备份文件绝对路径
  restoreCommand: string;     // 恢复该项的命令
}

interface DirSnapshot {
  id: string;
  server: string;
  timestamp: number;
  remoteDir: string;          // /tmp/.lovelyres_snap/<ts>
  items: SnapshotItem[];
}

const SNAP_STORAGE_KEY = 'lovelyres-dir-snapshots';
const SNAP_ROOT = '/tmp/.lovelyres_snap';

const PRESET_PATHS: SnapshotPathDef[] = [
  { label: '/etc（系统配置）', path: '/etc', kind: 'dir', defaultOn: true },
  { label: 'crontab（当前用户计划任务）', path: 'CRONTAB', kind: 'crontab', defaultOn: true },
  { label: '/etc/passwd', path: '/etc/passwd', kind: 'file', defaultOn: true },
  { label: '/etc/shadow', path: '/etc/shadow', kind: 'file', defaultOn: true },
  { label: '/root/.ssh/authorized_keys', path: '/root/.ssh/authorized_keys', kind: 'file', defaultOn: true },
  { label: '/var/www（Web 根目录）', path: '/var/www', kind: 'dir', defaultOn: true },
  { label: '/var/spool/cron（全量计划任务）', path: '/var/spool/cron', kind: 'dir', defaultOn: false },
  { label: '/root（root 家目录，可能较大）', path: '/root', kind: 'dir', defaultOn: false },
];

class SnapshotManager {
  private currentTab: 'history' | 'snapshot' = 'history';
  private eventsBound = false;
  private snapshots: DirSnapshot[] = [];
  private snapLoaded = false;

  // ──────── 生命周期 ────────

  initialize(): void {
    this.loadSnapshots();
    if (!this.eventsBound) {
      this.bindEvents();
      this.eventsBound = true;
    }
    this.render();
  }

  private server(): string {
    return sshConnectionManager.getConnectionStatus()?.host || '';
  }

  private async exec(cmd: string, timeoutSec = 120): Promise<string> {
    const r = await invoke('ssh_execute_emergency_command_direct', {
      command: cmd,
      username: null,
      timeoutSec,
      cwd: null,
    }) as any;
    return r?.output || '';
  }

  // ──────── 快照元数据持久化 ────────

  private loadSnapshots(): void {
    if (this.snapLoaded) return;
    this.snapLoaded = true;
    try {
      const raw = localStorage.getItem(SNAP_STORAGE_KEY);
      if (raw) this.snapshots = JSON.parse(raw);
    } catch { this.snapshots = []; }
  }

  private saveSnapshots(): void {
    try { localStorage.setItem(SNAP_STORAGE_KEY, JSON.stringify(this.snapshots)); } catch { /* ignore */ }
  }

  // ──────── 事件委托 ────────

  private bindEvents(): void {
    document.addEventListener('click', (e) => {
      const t = (e.target as HTMLElement).closest('[data-snap-action]') as HTMLElement;
      if (!t) return;
      const action = t.getAttribute('data-snap-action') || '';
      const param = t.getAttribute('data-snap-param') || '';

      switch (action) {
        case 'tab': this.currentTab = param as any; this.render(); break;
        case 'rollback': this.onRollbackOne(param); break;
        case 'rollback-all': this.onRollbackAll(); break;
        case 'clear-journal': this.onClearJournal(); break;
        case 'export-journal':
          navigator.clipboard.writeText(operationJournal.exportAll(this.server())).catch(() => {});
          window.showNotification?.('已复制操作日志', 'success');
          break;
        case 'export-report':
          void this.onExportDisposalReport(param === 'html' ? 'html' : 'markdown');
          break;
        case 'create-snapshot': this.onCreateSnapshot(); break;
        case 'restore-item': this.onRestoreItem(param); break;
        case 'delete-snapshot': this.onDeleteSnapshot(param); break;
        case 'toggle-snap':
          { const d = document.getElementById(`snap-detail-${param}`); if (d) d.style.display = d.style.display === 'none' ? '' : 'none'; }
          break;
      }
    });
  }

  // ──────── 子标签 A：操作历史 & 回滚 ────────

  /**
   * 导出处置交付报告。
   *
   * 数据来自两处：本机的 operationJournal（必有）+ 最近一次快速检测报告（可选）。
   * 检测模块是懒加载的，用动态 import 取，拿不到就只出处置记录部分，
   * 不因为「没跑过检测」就拒绝导出——赛场上先处置后补检测是常态。
   */
  private async onExportDisposalReport(format: 'markdown' | 'html'): Promise<void> {
    const server = this.server();
    const entries = operationJournal.list({ server });

    if (!entries.length) {
      window.showNotification?.('本机暂无处置记录，无法生成报告', 'warning');
      return;
    }

    let detection: import('../report/disposalReport').DisposalReportInput['detection'];
    try {
      const { quickDetectionManager } = await import('../detection/quickDetectionManager');
      const report = quickDetectionManager.getCurrentReport();
      if (report) {
        const findings = report.items
          .filter(i => i.status === 'completed' && i.result?.findings?.length)
          .flatMap(i => (i.result!.findings).map(f => ({
            title: f.title,
            description: f.description,
            severity: f.severity,
            recommendation: f.recommendation,
            source: i.name,
          })));
        detection = {
          timestamp: new Date(report.timestamp),
          overallScore: report.overallScore,
          findings,
        };
      }
    } catch (e) {
      // 检测模块不可用不影响交付报告的主体
      log.warn('读取检测报告失败，报告将只含处置记录', e);
    }

    try {
      const { downloadDisposalReport } = await import('../report/disposalReport');
      downloadDisposalReport(
        { server, generatedAt: new Date(), entries, detection },
        format,
      );
      window.showNotification?.(
        `已导出${format === 'markdown' ? ' Markdown' : ' HTML'}交付报告（${entries.length} 条处置${detection ? ' + 检测结果' : ''}）`,
        'success',
      );
    } catch (e) {
      reportError(e, { module: 'Snapshot', action: '导出交付报告' });
    }
  }

  private async onRollbackOne(id: string): Promise<void> {
    const entry = operationJournal.get(id);
    if (!entry) return;
    const ok = await showConfirm({
      title: '确认回滚',
      message: `将撤销操作：${entry.title}\n\n回滚命令：\n${entry.restoreCommand || '(无)'}`,
      confirmText: '回滚', cancelText: '取消', dangerous: true,
    });
    if (!ok) return;
    const r = await operationJournal.rollback(id);
    window.showNotification?.(r.success ? '回滚成功' : `回滚失败: ${r.output}`, r.success ? 'success' : 'error');
    this.render();
  }

  private async onRollbackAll(): Promise<void> {
    const server = this.server();
    const pending = operationJournal.list({ server }).filter(e => !e.rolledBack && e.restoreCommand);
    if (pending.length === 0) { window.showNotification?.('没有可回滚的操作', 'info'); return; }
    const ok = await showConfirm({
      title: '一键全回滚',
      message: `将按时间倒序撤销本机 ${pending.length} 项操作。\n\n此动作会连续执行多条回滚命令，请确认已了解影响。`,
      confirmText: `回滚 ${pending.length} 项`, cancelText: '取消', dangerous: true,
    });
    if (!ok) return;
    const results = await operationJournal.rollbackAll(server);
    window.showNotification?.(`回滚完成：成功 ${results.filter(r => r.success).length}/${results.length}`, 'success');
    this.render();
  }

  private async onClearJournal(): Promise<void> {
    const ok = await showConfirm({
      title: '清空操作日志',
      message: '仅清除本机的操作历史记录（不会撤销已做的变更，也不删除靶机上的备份）。确定继续？',
      confirmText: '清空', cancelText: '取消', dangerous: true,
    });
    if (!ok) return;
    operationJournal.clear(this.server());
    window.showNotification?.('操作日志已清空', 'success');
    this.render();
  }

  // ──────── 子标签 B：关键目录快照 ────────

  private async onCreateSnapshot(): Promise<void> {
    if (!sshConnectionManager.isConnected()) { window.showNotification?.('请先连接服务器', 'error'); return; }

    // 收集勾选的路径
    const checks = Array.from(document.querySelectorAll('.snap-path-check')) as HTMLInputElement[];
    const selected = PRESET_PATHS.filter((_, i) => checks[i]?.checked);
    if (selected.length === 0) { window.showNotification?.('请至少选择一个路径', 'info'); return; }

    const ok = await showConfirm({
      title: '创建开赛快照',
      message: `将打包 ${selected.length} 个位置到靶机 ${SNAP_ROOT}/ 下。\n\n打包大目录（如 /etc、/var/www）可能耗时数十秒，请耐心等待。`,
      confirmText: '开始快照', cancelText: '取消',
    });
    if (!ok) return;

    const ts = this.stamp();
    const remoteDir = `${SNAP_ROOT}/${ts}`;
    const items: SnapshotItem[] = [];
    const cmds: string[] = [`mkdir -p ${shq(remoteDir)}`];

    for (const p of selected) {
      if (p.kind === 'crontab') {
        const archive = `${remoteDir}/crontab.txt`;
        cmds.push(`crontab -l > ${shq(archive)} 2>/dev/null || true`);
        items.push({ label: p.label, path: p.path, kind: p.kind, archive,
          restoreCommand: `crontab ${shq(archive)}` });
      } else if (p.kind === 'file') {
        const archive = `${remoteDir}/${this.safeName(p.path)}`;
        cmds.push(`cp -a ${shq(p.path)} ${shq(archive)} 2>/dev/null || true`);
        items.push({ label: p.label, path: p.path, kind: p.kind, archive,
          restoreCommand: `cp -a ${shq(archive)} ${shq(p.path)}` });
      } else {
        // 目录 -> tar.gz
        const archive = `${remoteDir}/${this.safeName(p.path)}.tgz`;
        cmds.push(`tar czf ${shq(archive)} ${shq(p.path)} 2>/dev/null || true`);
        // 恢复：解包到根（tar 内含绝对路径的父目录）
        items.push({ label: p.label, path: p.path, kind: p.kind, archive,
          restoreCommand: `tar xzf ${shq(archive)} -C / 2>/dev/null` });
      }
    }
    // 记录清单大小便于校验
    cmds.push(`du -sh ${shq(remoteDir)} 2>/dev/null`);

    window.showNotification?.('正在创建快照...', 'info');
    let output = '';
    try {
      output = await this.exec(cmds.join(' && '), 300);
    } catch (e) {
      window.showNotification?.(`快照失败: ${e}`, 'error');
      return;
    }

    const snap: DirSnapshot = { id: `snap_${ts}`, server: this.server(), timestamp: Date.now(), remoteDir, items };
    this.snapshots.push(snap);
    this.saveSnapshots();

    // 记入操作日志（快照创建本身可回滚 = 删除快照目录）
    operationJournal.record({
      source: 'snapshot', server: this.server(),
      title: `创建开赛快照（${items.length} 项）`,
      command: `tar/cp -> ${remoteDir}`,
      backupInfo: remoteDir,
      restoreCommand: `rm -rf ${shq(remoteDir)}`,
      output, success: true,
    });

    window.showNotification?.('快照创建完成', 'success');
    this.render();
  }

  private async onRestoreItem(param: string): Promise<void> {
    // param = "<snapId>|<itemIndex>"
    const [snapId, idxStr] = param.split('|');
    const snap = this.snapshots.find(s => s.id === snapId);
    if (!snap) return;
    const item = snap.items[Number(idxStr)];
    if (!item) return;

    const ok = await showConfirm({
      title: '恢复快照项',
      message: `将用快照恢复：${item.label}\n\n命令：${item.restoreCommand}\n\n当前该位置的内容会被覆盖。建议恢复前对现状再拍一次快照。`,
      confirmText: '恢复', cancelText: '取消', dangerous: true,
    });
    if (!ok) return;

    let output = '';
    let success = true;
    try {
      output = await this.exec(item.restoreCommand, 300);
    } catch (e) { success = false; output = String(e); }

    operationJournal.record({
      source: 'snapshot', server: this.server(),
      title: `恢复快照项：${item.label}`,
      command: item.restoreCommand,
      backupInfo: item.archive,
      output, success,
    });

    window.showNotification?.(success ? '恢复完成' : `恢复失败: ${output}`, success ? 'success' : 'error');
    this.render();
  }

  private async onDeleteSnapshot(snapId: string): Promise<void> {
    const snap = this.snapshots.find(s => s.id === snapId);
    if (!snap) return;
    const ok = await showConfirm({
      title: '删除快照',
      message: `将删除靶机上的备份目录 ${snap.remoteDir} 并移除本地记录。确定？`,
      confirmText: '删除', cancelText: '取消', dangerous: true,
    });
    if (!ok) return;
    try { await this.exec(`rm -rf ${shq(snap.remoteDir)}`); } catch { /* ignore */ }
    this.snapshots = this.snapshots.filter(s => s.id !== snapId);
    this.saveSnapshots();
    window.showNotification?.('快照已删除', 'success');
    this.render();
  }

  // ──────── 渲染 ────────

  render(): void {
    const container = document.getElementById('snapshot-content');
    if (!container) return;

    const tabBar = `
      <div class="snap-tabs">
        <button class="snap-tab ${this.currentTab === 'history' ? 'active' : ''}" data-snap-action="tab" data-snap-param="history">操作历史 & 回滚</button>
        <button class="snap-tab ${this.currentTab === 'snapshot' ? 'active' : ''}" data-snap-action="tab" data-snap-param="snapshot">关键目录快照</button>
      </div>`;

    container.innerHTML = tabBar + (this.currentTab === 'history' ? this.renderHistory() : this.renderSnapshots()) + this.styles();
  }

  private renderHistory(): string {
    const server = this.server();
    const list = operationJournal.list({ server });
    const pending = list.filter(e => !e.rolledBack && e.restoreCommand).length;

    const rows = list.map(e => {
      const canRollback = !e.rolledBack && !!e.restoreCommand;
      const statusBadge = e.rolledBack
        ? '<span class="snap-badge rolled">已回滚</span>'
        : (e.success ? '<span class="snap-badge ok">已执行</span>' : '<span class="snap-badge fail">失败</span>');
      const diff = (e.beforeValue || e.afterValue)
        ? `<div class="snap-diff">${this.esc((e.beforeValue || '').slice(0, 60))} → ${this.esc((e.afterValue || '').slice(0, 60))}</div>` : '';
      return `
        <tr>
          <td class="snap-time">${this.relativeTime(e.timestamp)}</td>
          <td><span class="snap-src">${opSourceLabel(e.source)}</span></td>
          <td>
            <div class="snap-title">${this.esc(e.title)}</div>
            <div class="snap-cmd" title="${this.esc(e.command)}">${this.esc(e.command.slice(0, 90))}</div>
            ${diff}
          </td>
          <td>${statusBadge}</td>
          <td>${canRollback
            ? `<button class="snap-btn danger" data-snap-action="rollback" data-snap-param="${e.id}">回滚</button>`
            : '<span class="snap-muted">—</span>'}</td>
        </tr>`;
    }).join('');

    return `
      <div class="snap-toolbar">
        <span class="snap-count">共 ${list.length} 项操作，${pending} 项可回滚</span>
        <span class="snap-spacer"></span>
        <button class="snap-btn" data-snap-action="export-journal">复制日志</button>
        <button class="snap-btn" data-snap-action="export-report" data-snap-param="markdown">交付报告 MD</button>
        <button class="snap-btn" data-snap-action="export-report" data-snap-param="html">交付报告 HTML</button>
        <button class="snap-btn danger" data-snap-action="rollback-all" ${pending === 0 ? 'disabled' : ''}>一键全回滚</button>
        <button class="snap-btn" data-snap-action="clear-journal">清空记录</button>
      </div>
      ${list.length === 0
        ? '<div class="snap-empty">暂无操作记录。通过检测修复、用户处置、防火墙、快照等功能做的变更会自动记录在此，可随时回滚。</div>'
        : `<table class="snap-table"><thead><tr><th>时间</th><th>来源</th><th>操作</th><th>状态</th><th>回滚</th></tr></thead><tbody>${rows}</tbody></table>`}
    `;
  }

  private renderSnapshots(): string {
    const server = this.server();
    const mine = this.snapshots.filter(s => s.server === server).sort((a, b) => b.timestamp - a.timestamp);

    const pathChecks = PRESET_PATHS.map(p =>
      `<label class="snap-check"><input type="checkbox" class="snap-path-check" ${p.defaultOn ? 'checked' : ''}/> ${this.esc(p.label)}</label>`
    ).join('');

    const snapCards = mine.map(s => {
      const itemRows = s.items.map((it, i) => `
        <tr>
          <td>${this.esc(it.label)}</td>
          <td class="snap-cmd">${this.esc(it.archive)}</td>
          <td><button class="snap-btn danger" data-snap-action="restore-item" data-snap-param="${s.id}|${i}">恢复</button></td>
        </tr>`).join('');
      return `
        <div class="snap-card">
          <div class="snap-card-head" data-snap-action="toggle-snap" data-snap-param="${s.id}">
            <div>
              <span class="snap-title">${new Date(s.timestamp).toLocaleString()}</span>
              <span class="snap-muted">（${s.items.length} 项 · ${this.esc(s.remoteDir)}）</span>
            </div>
            <button class="snap-btn" data-snap-action="delete-snapshot" data-snap-param="${s.id}">删除</button>
          </div>
          <div class="snap-card-detail" id="snap-detail-${s.id}" style="display:none;">
            <table class="snap-table"><thead><tr><th>位置</th><th>备份文件</th><th>恢复</th></tr></thead><tbody>${itemRows}</tbody></table>
          </div>
        </div>`;
    }).join('');

    return `
      <div class="snap-panel">
        <div class="snap-section-title">选择要快照的位置</div>
        <div class="snap-checks">${pathChecks}</div>
        <button class="snap-btn primary" data-snap-action="create-snapshot">创建开赛快照</button>
        <div class="snap-hint">快照打包到靶机 ${SNAP_ROOT}/&lt;时间戳&gt;/ 下，恢复时按位置逐项还原。删除快照会移除靶机备份。</div>
      </div>
      <div class="snap-section-title" style="margin-top:16px;">已有快照（本机 ${mine.length} 个）</div>
      ${mine.length === 0 ? '<div class="snap-empty">尚无快照。建议进场后立刻创建一次开赛快照作为兜底。</div>' : snapCards}
    `;
  }

  // ──────── 工具 ────────

  private stamp(): string {
    const d = new Date();
    const p = (n: number) => String(n).padStart(2, '0');
    return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
  }

  private safeName(path: string): string {
    return path.replace(/^\//, '').replace(/[^a-zA-Z0-9._-]/g, '_') || 'root';
  }

  private esc(s: string): string {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  private relativeTime(ts: number): string {
    const d = Date.now() - ts;
    if (d < 60000) return '刚刚';
    if (d < 3600000) return `${Math.floor(d / 60000)}分钟前`;
    if (d < 86400000) return `${Math.floor(d / 3600000)}小时前`;
    return `${Math.floor(d / 86400000)}天前`;
  }

  private styles(): string {
    if (document.getElementById('snap-styles')) return '';
    return `<style id="snap-styles">
      .snap-tabs{display:flex;gap:8px;margin-bottom:14px;border-bottom:1px solid var(--border-color);padding-bottom:8px;}
      .snap-tab{background:transparent;border:none;color:var(--text-secondary);padding:8px 14px;border-radius:6px;cursor:pointer;font-size:13px;}
      .snap-tab.active{background:var(--primary-color);color:#fff;}
      .snap-toolbar{display:flex;align-items:center;gap:8px;margin-bottom:12px;}
      .snap-spacer{flex:1;}
      .snap-count{color:var(--text-secondary);font-size:12px;}
      .snap-btn{background:var(--bg-secondary);border:1px solid var(--border-color);color:var(--text-primary);padding:6px 12px;border-radius:6px;cursor:pointer;font-size:12px;}
      .snap-btn:hover{border-color:var(--primary-color);}
      .snap-btn.primary{background:var(--primary-color);color:#fff;border-color:var(--primary-color);}
      .snap-btn.danger{color:#ef4444;border-color:rgba(239,68,68,.4);}
      .snap-btn.danger:hover{background:rgba(239,68,68,.1);}
      .snap-btn:disabled{opacity:.4;cursor:not-allowed;}
      .snap-table{width:100%;border-collapse:collapse;font-size:12px;}
      .snap-table th{text-align:left;color:var(--text-secondary);font-weight:500;padding:8px;border-bottom:1px solid var(--border-color);}
      .snap-table td{padding:8px;border-bottom:1px solid var(--border-color);vertical-align:top;}
      .snap-time{color:var(--text-secondary);white-space:nowrap;}
      .snap-src{background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:4px;padding:2px 8px;font-size:11px;white-space:nowrap;}
      .snap-title{color:var(--text-primary);font-weight:500;}
      .snap-cmd{color:var(--text-secondary);font-family:monospace;font-size:11px;margin-top:2px;word-break:break-all;}
      .snap-diff{color:#f59e0b;font-size:11px;margin-top:2px;}
      .snap-badge{padding:2px 8px;border-radius:4px;font-size:11px;white-space:nowrap;}
      .snap-badge.ok{background:rgba(34,197,94,.12);color:#22c55e;}
      .snap-badge.fail{background:rgba(239,68,68,.12);color:#ef4444;}
      .snap-badge.rolled{background:rgba(148,163,184,.15);color:var(--text-secondary);}
      .snap-muted{color:var(--text-secondary);}
      .snap-empty{color:var(--text-secondary);text-align:center;padding:40px 20px;font-size:13px;line-height:1.6;}
      .snap-panel{background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:8px;padding:16px;}
      .snap-section-title{color:var(--text-primary);font-weight:600;font-size:13px;margin-bottom:10px;}
      .snap-checks{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:14px;}
      .snap-check{display:flex;align-items:center;gap:8px;color:var(--text-primary);font-size:12px;cursor:pointer;}
      .snap-hint{color:var(--text-secondary);font-size:11px;margin-top:10px;line-height:1.5;}
      .snap-card{border:1px solid var(--border-color);border-radius:8px;margin-bottom:10px;overflow:hidden;}
      .snap-card-head{display:flex;align-items:center;justify-content:space-between;padding:12px;cursor:pointer;background:var(--bg-secondary);}
      .snap-card-detail{padding:8px 12px;}
    </style>`;
  }
}

export const snapshotManager = new SnapshotManager();
