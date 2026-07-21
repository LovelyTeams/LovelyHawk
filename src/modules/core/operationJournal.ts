/**
 * 统一操作日志（Operation Journal）
 *
 * 汇总本工具对靶机做过的所有可回滚变更（基线修复、检测处置、用户/口令处置、
 * 防火墙规则、文件隔离/恢复等），并提供单条 / 批量回滚能力，是"快照与回滚中心"的数据源。
 *
 * 存储：localStorage（键 lovelyres-op-journal），按机器（server）字段区分，
 * 上限 MAX_ENTRIES 条，超限截断（与 aiHistoryManager / fixHistoryManager 一致的轻量模式）。
 *
 * 注意（离线约束）：restoreCommand 由各功能生成，务必对用户名/路径/IP 等做 shell 转义。
 */

import { invoke } from '@tauri-apps/api/core';

export type OpSource = 'baseline' | 'detection-fix' | 'user' | 'firewall' | 'integrity' | 'snapshot' | 'manual';

export interface OperationEntry {
  id: string;
  timestamp: number;
  source: OpSource;          // 哪个功能产生
  server: string;            // 目标机 host，用于按机隔离
  title: string;             // 人读描述，如 "锁定账号 test"
  command: string;           // 实际执行的命令
  beforeValue?: string;      // 变更前状态（展示 diff 用）
  afterValue?: string;       // 变更后状态
  backupInfo?: string;       // 备份文件路径 / 备份说明
  restoreCommand?: string;   // 一键回滚命令（核心）
  output: string;            // 执行输出
  success: boolean;
  rolledBack: boolean;
}

const STORAGE_KEY = 'lovelyres-op-journal';
const MAX_ENTRIES = 500;

const SOURCE_LABELS: Record<OpSource, string> = {
  'baseline': '基线',
  'detection-fix': '检测修复',
  'user': '用户/口令',
  'firewall': '防火墙',
  'integrity': '文件完整性',
  'snapshot': '快照',
  'manual': '手动',
};

export function opSourceLabel(s: OpSource): string {
  return SOURCE_LABELS[s] || s;
}

class OperationJournal {
  private entries: OperationEntry[] = [];
  private loaded = false;

  private load(): void {
    if (this.loaded) return;
    this.loaded = true;
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) this.entries = JSON.parse(raw);
    } catch { this.entries = []; }
  }

  private save(): void {
    if (this.entries.length > MAX_ENTRIES) this.entries = this.entries.slice(-MAX_ENTRIES);
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(this.entries)); } catch { /* 隐私模式忽略 */ }
  }

  /** 记录一条操作，返回补全后的条目 */
  record(entry: Omit<OperationEntry, 'id' | 'timestamp' | 'rolledBack'>): OperationEntry {
    this.load();
    const full: OperationEntry = {
      ...entry,
      id: `op_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`,
      timestamp: Date.now(),
      rolledBack: false,
    };
    this.entries.push(full);
    this.save();
    return full;
  }

  /** 列出操作（最新在前），可按 server / source 过滤 */
  list(filter?: { server?: string; source?: OpSource }): OperationEntry[] {
    this.load();
    let out = [...this.entries];
    if (filter?.server) out = out.filter(e => e.server === filter.server);
    if (filter?.source) out = out.filter(e => e.source === filter.source);
    return out.reverse();
  }

  get(id: string): OperationEntry | undefined {
    this.load();
    return this.entries.find(e => e.id === id);
  }

  /** 回滚单条：执行其 restoreCommand */
  async rollback(id: string): Promise<{ success: boolean; output: string }> {
    this.load();
    const entry = this.entries.find(e => e.id === id);
    if (!entry) return { success: false, output: '记录不存在' };
    if (entry.rolledBack) return { success: false, output: '已回滚过' };
    if (!entry.restoreCommand) return { success: false, output: '该操作无回滚命令' };

    try {
      const result = await invoke('ssh_execute_command_direct', { command: entry.restoreCommand }) as any;
      const output = result?.output || '';
      entry.rolledBack = true;
      this.save();
      return { success: true, output };
    } catch (e) {
      return { success: false, output: `回滚失败: ${e}` };
    }
  }

  /**
   * 批量回滚指定机器上尚未回滚的操作，按时间倒序（后做的先撤）。
   * 返回每条的结果，便于 UI 增量更新。
   */
  async rollbackAll(
    server: string,
    onEach?: (id: string, ok: boolean) => void,
  ): Promise<Array<{ id: string; success: boolean; output: string }>> {
    this.load();
    const targets = this.entries
      .filter(e => e.server === server && !e.rolledBack && e.restoreCommand)
      .sort((a, b) => b.timestamp - a.timestamp);

    const results: Array<{ id: string; success: boolean; output: string }> = [];
    for (const e of targets) {
      const r = await this.rollback(e.id);
      results.push({ id: e.id, ...r });
      onEach?.(e.id, r.success);
    }
    return results;
  }

  remove(id: string): void {
    this.load();
    this.entries = this.entries.filter(e => e.id !== id);
    this.save();
  }

  clear(server?: string): void {
    this.load();
    this.entries = server ? this.entries.filter(e => e.server !== server) : [];
    this.save();
  }

  getCount(server?: string): number {
    this.load();
    return server ? this.entries.filter(e => e.server === server).length : this.entries.length;
  }

  exportAll(server?: string): string {
    const list = this.list(server ? { server } : undefined);
    return list.map(e =>
      `[${new Date(e.timestamp).toLocaleString()}] ${e.success ? 'OK' : 'FAIL'}${e.rolledBack ? ' (已回滚)' : ''} [${opSourceLabel(e.source)}] ${e.title}\n`
      + `  cmd: ${e.command}\n`
      + (e.beforeValue || e.afterValue ? `  ${e.beforeValue || ''} -> ${e.afterValue || ''}\n` : '')
      + (e.restoreCommand ? `  restore: ${e.restoreCommand}\n` : '')
      + `  ${(e.output || '').substring(0, 200)}`
    ).join('\n\n');
  }
}

export const operationJournal = new OperationJournal();
