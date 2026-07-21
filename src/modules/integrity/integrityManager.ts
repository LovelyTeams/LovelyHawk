/**
 * 文件完整性快照对比（File Integrity Monitoring）
 *
 * 建立基线：对预设/自定义路径（Web 根目录、系统 bin、/etc）计算 sha256，落盘到靶机
 *          /tmp/.lovelyres_fim/<id>.sha256（排序后）。基线元数据存 localStorage。
 * 对比 diff：重新扫描 → 在靶机上用 comm 比对，只回传差异行，前端归类为
 *          新增 / 删除 / 修改，Web 目录变化标高危（最可能是新落地 webshell）。
 * 联动处置：可疑文件可"查看内容"（跳 SFTP）或"隔离"（移入隔离目录，写 operationJournal 可回滚）。
 *
 * 说明（相对计划的实现取舍）：基线存靶机文件 + comm 在靶机算差异，避免大列表回传与
 * Rust/SQLite 改动，更轻量且符合离线约束。
 */

import { invoke } from '@tauri-apps/api/core';
import { operationJournal } from '../core/operationJournal';
import { sshConnectionManager } from '../remote/sshConnectionManager';
import { showConfirm } from '../ui/confirmDialog';
import { shq } from '../core/shellEscape';

interface Baseline {
  id: string;
  server: string;
  timestamp: number;
  paths: string[];
  remoteFile: string;
  fileCount: number;
}

interface DiffEntry {
  path: string;
  kind: 'added' | 'removed' | 'modified';
  severity: 'high' | 'medium';
}

const FIM_STORAGE_KEY = 'lovelyres-fim-baselines';
const FIM_DIR = '/tmp/.lovelyres_fim';

const PRESET_PATHS: Array<{ label: string; path: string; defaultOn: boolean }> = [
  { label: '/var/www（Web 根目录）', path: '/var/www', defaultOn: true },
  { label: '/usr/bin', path: '/usr/bin', defaultOn: true },
  { label: '/usr/sbin', path: '/usr/sbin', defaultOn: true },
  { label: '/bin', path: '/bin', defaultOn: true },
  { label: '/etc', path: '/etc', defaultOn: false },
  { label: '/usr/local/bin', path: '/usr/local/bin', defaultOn: false },
];

class IntegrityManager {
  private baselines: Baseline[] = [];
  private loaded = false;
  private eventsBound = false;
  private busy = false;
  private lastDiff: { baselineId: string; entries: DiffEntry[] } | null = null;

  initialize(): void {
    this.load();
    if (!this.eventsBound) { this.bindEvents(); this.eventsBound = true; }
    this.render();
  }

  private server(): string {
    return sshConnectionManager.getConnectionStatus()?.host || '';
  }

  private async exec(cmd: string, timeoutSec = 300): Promise<string> {
    const r = await invoke('ssh_execute_emergency_command_direct', {
      command: cmd, username: null, timeoutSec, cwd: null,
    }) as any;
    return r?.output || '';
  }

  private load(): void {
    if (this.loaded) return;
    this.loaded = true;
    try {
      const raw = localStorage.getItem(FIM_STORAGE_KEY);
      if (raw) this.baselines = JSON.parse(raw);
    } catch { this.baselines = []; }
  }

  private save(): void {
    try { localStorage.setItem(FIM_STORAGE_KEY, JSON.stringify(this.baselines)); } catch { /* ignore */ }
  }

  // ──────── 事件 ────────

  private bindEvents(): void {
    document.addEventListener('click', (e) => {
      const t = (e.target as HTMLElement).closest('[data-fim-action]') as HTMLElement;
      if (!t) return;
      const action = t.getAttribute('data-fim-action') || '';
      const param = t.getAttribute('data-fim-param') || '';
      switch (action) {
        case 'build': this.onBuildBaseline(); break;
        case 'diff': this.onDiff(param); break;
        case 'delete': this.onDeleteBaseline(param); break;
        case 'view': this.onViewFile(param); break;
        case 'quarantine': this.onQuarantine(param); break;
      }
    });
  }

  private selectedPaths(): string[] {
    const checks = Array.from(document.querySelectorAll('.fim-path-check')) as HTMLInputElement[];
    const preset = PRESET_PATHS.filter((_, i) => checks[i]?.checked).map(p => p.path);
    const custom = (document.getElementById('fim-custom') as HTMLTextAreaElement)?.value || '';
    const extra = custom.split(/[\n,]+/).map(s => s.trim()).filter(Boolean);
    return [...preset, ...extra];
  }

  // ──────── 建立基线 ────────

  private async onBuildBaseline(): Promise<void> {
    if (!sshConnectionManager.isConnected()) { window.showNotification?.('请先连接服务器', 'error'); return; }
    const paths = this.selectedPaths();
    if (paths.length === 0) { window.showNotification?.('请至少选择一个路径', 'info'); return; }

    const ok = await showConfirm({
      title: '建立完整性基线',
      message: `将对 ${paths.length} 个位置计算 sha256 并落盘到靶机 ${FIM_DIR}/。\n\n路径：${paths.join('  ')}\n\n目录大时可能耗时较久。`,
      confirmText: '开始', cancelText: '取消',
    });
    if (!ok) return;

    this.busy = true; this.render();
    const id = `fim_${this.stamp()}`;
    const remoteFile = `${FIM_DIR}/${id}.sha256`;
    const pathArgs = paths.map(shq).join(' ');
    const cmd = `mkdir -p ${shq(FIM_DIR)} && find ${pathArgs} -type f -exec sha256sum {} + 2>/dev/null | sort > ${shq(remoteFile)}; wc -l < ${shq(remoteFile)}`;

    let count = 0;
    try {
      const out = await this.exec(cmd, 600);
      count = parseInt(out.trim().split(/\s+/).pop() || '0', 10) || 0;
    } catch (e) {
      window.showNotification?.(`建立基线失败: ${e}`, 'error');
      this.busy = false; this.render(); return;
    }

    this.baselines.push({ id, server: this.server(), timestamp: Date.now(), paths, remoteFile, fileCount: count });
    this.save();
    this.busy = false;
    window.showNotification?.(`基线建立完成，共 ${count} 个文件`, 'success');
    this.render();
  }

  // ──────── 对比 diff ────────

  private async onDiff(baselineId: string): Promise<void> {
    const bl = this.baselines.find(b => b.id === baselineId);
    if (!bl) return;
    this.busy = true; this.render();

    const pathArgs = bl.paths.map(shq).join(' ');
    // 在靶机上重新扫描并用 comm 只输出差异行
    const cmd = [
      `CUR=$(mktemp)`,
      `find ${pathArgs} -type f -exec sha256sum {} + 2>/dev/null | sort > "$CUR"`,
      `echo "===ADDED==="`,
      `comm -13 ${shq(bl.remoteFile)} "$CUR"`,
      `echo "===REMOVED==="`,
      `comm -23 ${shq(bl.remoteFile)} "$CUR"`,
      `rm -f "$CUR"`,
    ].join('; ');

    let out = '';
    try {
      out = await this.exec(cmd, 600);
    } catch (e) {
      window.showNotification?.(`对比失败: ${e}`, 'error');
      this.busy = false; this.render(); return;
    }

    this.lastDiff = { baselineId, entries: this.parseDiff(out) };
    this.busy = false;
    this.render();
  }

  /** 解析 comm 输出：ADDED 块 = 当前独有（新增或改后新哈希），REMOVED 块 = 基线独有（删除或改前旧哈希） */
  private parseDiff(out: string): DiffEntry[] {
    const addedBlock: Array<{ hash: string; path: string }> = [];
    const removedBlock: Array<{ hash: string; path: string }> = [];
    let mode: 'added' | 'removed' | '' = '';
    for (const line of out.split('\n')) {
      if (line.startsWith('===ADDED===')) { mode = 'added'; continue; }
      if (line.startsWith('===REMOVED===')) { mode = 'removed'; continue; }
      const m = /^([0-9a-f]{64})\s+(.+)$/.exec(line.trim());
      if (!m || !mode) continue;
      (mode === 'added' ? addedBlock : removedBlock).push({ hash: m[1], path: m[2] });
    }
    const addedPaths = new Set(addedBlock.map(e => e.path));
    const removedPaths = new Set(removedBlock.map(e => e.path));

    const entries: DiffEntry[] = [];
    for (const p of addedPaths) {
      const kind: DiffEntry['kind'] = removedPaths.has(p) ? 'modified' : 'added';
      entries.push({ path: p, kind, severity: this.sev(p, kind) });
    }
    for (const p of removedPaths) {
      if (addedPaths.has(p)) continue; // 已作为 modified 计入
      entries.push({ path: p, kind: 'removed', severity: this.sev(p, 'removed') });
    }
    // 高危在前
    return entries.sort((a, b) => (a.severity === b.severity ? 0 : a.severity === 'high' ? -1 : 1));
  }

  private sev(path: string, kind: DiffEntry['kind']): 'high' | 'medium' {
    const web = /\/(www|html|webapps|htdocs|public_html)\//i.test(path);
    if (web && (kind === 'added' || kind === 'modified')) return 'high';
    if (/\/(bin|sbin)\//.test(path) && kind !== 'removed') return 'high';
    return 'medium';
  }

  private async onDeleteBaseline(id: string): Promise<void> {
    const bl = this.baselines.find(b => b.id === id);
    if (!bl) return;
    const ok = await showConfirm({
      title: '删除基线', message: `删除靶机上的 ${bl.remoteFile} 并移除本地记录？`,
      confirmText: '删除', cancelText: '取消', dangerous: true,
    });
    if (!ok) return;
    try { await this.exec(`rm -f ${shq(bl.remoteFile)}`, 30); } catch { /* ignore */ }
    this.baselines = this.baselines.filter(b => b.id !== id);
    if (this.lastDiff?.baselineId === id) this.lastDiff = null;
    this.save();
    this.render();
  }

  // ──────── 联动处置 ────────

  private onViewFile(path: string): void {
    const dir = path.replace(/\/[^/]*$/, '') || '/';
    const sftp = (window as any).sftpManager;
    if (sftp?.navigateToPath) {
      (window as any).switchPage?.('remote-operations');
      setTimeout(() => sftp.navigateToPath(dir), 150);
    } else {
      navigator.clipboard.writeText(path).catch(() => {});
      window.showNotification?.('已复制文件路径', 'info');
    }
  }

  private async onQuarantine(path: string): Promise<void> {
    const ok = await showConfirm({
      title: '隔离文件',
      message: `将把可疑文件移入隔离目录 ${FIM_DIR}/quarantine/：\n${path}\n\n原位置文件会被移走（业务可能受影响），可在快照回滚中心一键还原。`,
      confirmText: '隔离', cancelText: '取消', dangerous: true,
    });
    if (!ok) return;

    const qDir = `${FIM_DIR}/quarantine`;
    const qFile = `${qDir}/${this.safeName(path)}.${this.stamp()}`;
    const cmd = `mkdir -p ${shq(qDir)} && mv ${shq(path)} ${shq(qFile)}`;
    const restore = `mv ${shq(qFile)} ${shq(path)}`;

    let output = ''; let success = true;
    try { output = await this.exec(cmd, 60); } catch (e) { success = false; output = String(e); }

    operationJournal.record({
      source: 'integrity', server: this.server(),
      title: `隔离文件 ${path}`, command: cmd,
      backupInfo: qFile, restoreCommand: restore,
      output, success,
    });
    window.showNotification?.(success ? '已隔离，可在快照回滚中心还原' : `隔离失败: ${output}`, success ? 'success' : 'error');
    // 从当前 diff 视图移除该项
    if (this.lastDiff) this.lastDiff.entries = this.lastDiff.entries.filter(e => e.path !== path);
    this.render();
  }

  // ──────── 渲染 ────────

  private render(): void {
    const container = document.getElementById('integrity-content');
    if (!container) return;

    if (!sshConnectionManager.isConnected()) {
      container.innerHTML = `<div class="fim-empty">请先连接服务器后使用文件完整性快照。</div>${this.styles()}`;
      return;
    }

    const mine = this.baselines.filter(b => b.server === this.server()).sort((a, b) => b.timestamp - a.timestamp);
    const checks = PRESET_PATHS.map(p =>
      `<label class="fim-check"><input type="checkbox" class="fim-path-check" ${p.defaultOn ? 'checked' : ''}/> ${this.esc(p.label)}</label>`
    ).join('');

    const baselineList = mine.map(b => `
      <div class="fim-bl">
        <div>
          <span class="fim-title">${new Date(b.timestamp).toLocaleString()}</span>
          <span class="fim-muted">（${b.fileCount} 文件 · ${this.esc(b.paths.join(' '))}）</span>
        </div>
        <div class="fim-bl-actions">
          <button class="fim-btn primary" data-fim-action="diff" data-fim-param="${b.id}">对比</button>
          <button class="fim-btn" data-fim-action="delete" data-fim-param="${b.id}">删除</button>
        </div>
      </div>`).join('');

    container.innerHTML = `
      <div class="fim-panel">
        <div class="fim-section-title">选择要监控的位置</div>
        <div class="fim-checks">${checks}</div>
        <textarea id="fim-custom" class="fim-custom" placeholder="自定义路径，逗号或换行分隔（可选）"></textarea>
        <button class="fim-btn primary" data-fim-action="build" ${this.busy ? 'disabled' : ''}>${this.busy ? '处理中...' : '建立基线'}</button>
      </div>

      <div class="fim-section-title" style="margin-top:16px;">已有基线（本机 ${mine.length} 个）</div>
      ${mine.length === 0 ? '<div class="fim-empty">尚无基线。建议进场后尽早对 Web 目录和系统 bin 建立基线。</div>' : baselineList}

      ${this.renderDiff()}
      ${this.styles()}
    `;
  }

  private renderDiff(): string {
    if (!this.lastDiff) return '';
    const { entries } = this.lastDiff;
    const counts = {
      added: entries.filter(e => e.kind === 'added').length,
      modified: entries.filter(e => e.kind === 'modified').length,
      removed: entries.filter(e => e.kind === 'removed').length,
    };
    const kindLabel = { added: '新增', modified: '修改', removed: '删除' };
    const rows = entries.map(e => `
      <tr>
        <td><span class="fim-kind ${e.kind}">${kindLabel[e.kind]}</span></td>
        <td><span class="fim-sev ${e.severity}"></span></td>
        <td class="fim-path">${this.esc(e.path)}</td>
        <td>
          ${e.kind !== 'removed' ? `<button class="fim-btn" data-fim-action="view" data-fim-param="${this.esc(e.path)}">查看</button>` : ''}
          ${e.kind !== 'removed' ? `<button class="fim-btn danger" data-fim-action="quarantine" data-fim-param="${this.esc(e.path)}">隔离</button>` : ''}
        </td>
      </tr>`).join('');

    return `
      <div class="fim-section-title" style="margin-top:16px;">对比结果</div>
      <div class="fim-diff-summary">新增 ${counts.added} · 修改 ${counts.modified} · 删除 ${counts.removed}</div>
      ${entries.length === 0
        ? '<div class="fim-empty">未发现变化，与基线一致。</div>'
        : `<table class="fim-table"><thead><tr><th>类型</th><th></th><th>文件</th><th>操作</th></tr></thead><tbody>${rows}</tbody></table>`}
    `;
  }

  private stamp(): string {
    const d = new Date();
    const p = (n: number) => String(n).padStart(2, '0');
    return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
  }

  private safeName(path: string): string {
    return path.replace(/^\//, '').replace(/[^a-zA-Z0-9._-]/g, '_') || 'file';
  }

  private esc(s: string): string {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  private styles(): string {
    if (document.getElementById('fim-styles')) return '';
    return `<style id="fim-styles">
      .fim-empty{color:var(--text-secondary);text-align:center;padding:30px;font-size:13px;line-height:1.6;}
      .fim-panel{background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:8px;padding:16px;}
      .fim-section-title{color:var(--text-primary);font-weight:600;font-size:13px;margin-bottom:10px;}
      .fim-checks{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:10px;}
      .fim-check{display:flex;align-items:center;gap:8px;color:var(--text-primary);font-size:12px;cursor:pointer;}
      .fim-custom{width:100%;box-sizing:border-box;background:var(--bg-primary);border:1px solid var(--border-color);color:var(--text-primary);border-radius:6px;padding:8px;font-size:12px;min-height:44px;margin-bottom:10px;resize:vertical;}
      .fim-btn{background:var(--bg-secondary);border:1px solid var(--border-color);color:var(--text-primary);padding:6px 12px;border-radius:6px;cursor:pointer;font-size:12px;}
      .fim-btn:hover{border-color:var(--primary-color);}
      .fim-btn.primary{background:var(--primary-color);color:#fff;border-color:var(--primary-color);}
      .fim-btn.danger{color:#ef4444;border-color:rgba(239,68,68,.4);}
      .fim-btn.danger:hover{background:rgba(239,68,68,.1);}
      .fim-btn:disabled{opacity:.4;cursor:not-allowed;}
      .fim-bl{display:flex;align-items:center;justify-content:space-between;gap:10px;border:1px solid var(--border-color);border-radius:8px;padding:10px 12px;margin-bottom:8px;}
      .fim-bl-actions{display:flex;gap:6px;flex-shrink:0;}
      .fim-title{color:var(--text-primary);font-weight:500;}
      .fim-muted{color:var(--text-secondary);font-size:11px;}
      .fim-diff-summary{color:var(--text-secondary);font-size:12px;margin-bottom:8px;}
      .fim-table{width:100%;border-collapse:collapse;font-size:12px;}
      .fim-table th{text-align:left;color:var(--text-secondary);font-weight:500;padding:8px;border-bottom:1px solid var(--border-color);}
      .fim-table td{padding:8px;border-bottom:1px solid var(--border-color);vertical-align:middle;}
      .fim-path{font-family:monospace;font-size:11px;word-break:break-all;color:var(--text-primary);}
      .fim-kind{padding:2px 8px;border-radius:4px;font-size:11px;white-space:nowrap;}
      .fim-kind.added{background:rgba(59,130,246,.12);color:#3b82f6;}
      .fim-kind.modified{background:rgba(245,158,11,.14);color:#f59e0b;}
      .fim-kind.removed{background:rgba(148,163,184,.15);color:var(--text-secondary);}
      .fim-sev{display:inline-block;width:8px;height:8px;border-radius:50%;}
      .fim-sev.high{background:#ef4444;}
      .fim-sev.medium{background:#f59e0b;}
    </style>`;
  }
}

export const integrityManager = new IntegrityManager();
