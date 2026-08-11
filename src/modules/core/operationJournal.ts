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
import { activeTargetContext, isSameStableTarget, type TargetIdentity } from './targetContext';

export type OpSource = 'baseline' | 'detection-fix' | 'detection-hardening' | 'user' | 'firewall' | 'integrity' | 'snapshot' | 'check-audit' | 'database' | 'docker' | 'kubernetes' | 'java' | 'manual';

export interface OperationEntry {
  id: string;
  timestamp: number;
  source: OpSource;          // 哪个功能产生
  server: string;            // 目标机 host，用于按机隔离
  target?: TargetIdentity;   // 精确会话身份；旧记录可能缺失，禁止自动回滚
  allowStableTargetReconnect?: boolean; // 独立批量会话结束后，仅允许同指纹目标的新会话回滚
  title: string;             // 人读描述，如 "锁定账号 test"
  command: string;           // 实际执行的命令
  beforeValue?: string;      // 变更前状态（展示 diff 用）
  afterValue?: string;       // 变更后状态
  backupInfo?: string;       // 备份文件路径 / 备份说明
  restoreCommand?: string;   // 一键回滚命令（核心）
  output: string;            // 执行输出
  exitCode?: number | null;  // 精确执行退出码；旧记录可能缺失
  timedOut?: boolean;
  verifyCommand?: string;    // 应用后的独立读回命令
  verifyOutput?: string;
  verified?: boolean;
  restoreVerifyCommand?: string;
  restoreVerifyExpected?: string;
  success: boolean;
  rolledBack: boolean;
}

const STORAGE_KEY = 'lovelyres-op-journal';
const MAX_ENTRIES = 500;

const SOURCE_LABELS: Record<OpSource, string> = {
  'baseline': '基线',
  'detection-fix': '检测修复',
  'detection-hardening': '快速加固',
  'user': '用户/口令',
  'firewall': '防火墙',
  'integrity': '文件完整性',
  'snapshot': '快照',
  'check-audit': '核查审计',
  'database': '数据库',
  'docker': 'Docker',
  'kubernetes': 'Kubernetes',
  'java': 'Java',
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
    const activeTarget = activeTargetContext.get();
    const target = entry.target ?? (
      activeTarget?.host === entry.server
        ? {
            sessionId: activeTarget.sessionId,
            hostKeyFingerprint: activeTarget.hostKeyFingerprint,
            host: activeTarget.host,
            port: activeTarget.port,
            username: activeTarget.username,
          }
        : undefined
    );
    const full: OperationEntry = {
      ...entry,
      target,
      id: `op_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`,
      timestamp: Date.now(),
      rolledBack: false,
    };
    this.entries.push(full);
    this.save();
    return full;
  }

  /** 列出操作（最新在前）；target 使用稳定身份匹配并排除未绑定目标的旧记录。 */
  list(filter?: { server?: string; source?: OpSource; target?: TargetIdentity }): OperationEntry[] {
    this.load();
    let out = [...this.entries];
    if (filter?.server) out = out.filter(e => e.server === filter.server);
    if (filter?.source) out = out.filter(e => e.source === filter.source);
    if (filter?.target) {
      out = out.filter(e => e.target && isSameStableTarget(e.target, filter.target!));
    }
    return out.reverse();
  }

  get(id: string): OperationEntry | undefined {
    this.load();
    return this.entries.find(e => e.id === id);
  }

  /** 外部入口已用同一回滚命令完成恢复时，同步回执状态。 */
  markRolledBack(id: string): boolean {
    this.load();
    const entry = this.entries.find(item => item.id === id);
    const activeTarget = activeTargetContext.get();
    if (!entry?.target || !activeTarget || (
      !activeTargetContext.matches(entry.target)
      && !(entry.allowStableTargetReconnect && isSameStableTarget(activeTarget, entry.target))
    )) return false;
    entry.rolledBack = true;
    this.save();
    return true;
  }

  /** 回滚单条：执行其 restoreCommand */
  async rollback(id: string): Promise<{ success: boolean; output: string }> {
    this.load();
    const entry = this.entries.find(e => e.id === id);
    if (!entry) return { success: false, output: '记录不存在' };
    if (entry.rolledBack) return { success: false, output: '已回滚过' };
    if (!entry.restoreCommand) return { success: false, output: '该操作无回滚命令' };
    if (!entry.target) {
      return { success: false, output: '旧操作记录缺少精确目标身份，已阻止自动回滚' };
    }
    const activeTarget = activeTargetContext.get();
    const exactMatch = activeTargetContext.matches(entry.target);
    const stableReconnectMatch = !!activeTarget
      && entry.allowStableTargetReconnect === true
      && isSameStableTarget(activeTarget, entry.target);
    if (!exactMatch && !stableReconnectMatch) {
      return {
        success: false,
        output: `当前目标与操作记录不一致，已阻止回滚；记录目标为 ${entry.target.username}@${entry.target.host}:${entry.target.port} ${entry.target.hostKeyFingerprint}`,
      };
    }

    try {
      const result = await invoke('ssh_execute_command_direct', {
        command: entry.restoreCommand,
        sessionId: activeTarget!.sessionId,
      }) as any;
      const output = result?.output || '';
      const success = result?.timed_out !== true && result?.exit_code === 0;
      if (!success) {
        const reason = result?.timed_out
          ? '回滚命令执行超时'
          : `回滚命令退出状态未知或非 0: ${String(result?.exit_code ?? 'unknown')}`;
        return { success: false, output: `${reason}${output ? `\n${output}` : ''}` };
      }
      if (entry.restoreVerifyCommand) {
        const verify = await invoke('ssh_execute_command_direct', {
          command: entry.restoreVerifyCommand,
          sessionId: activeTarget!.sessionId,
        }) as any;
        const verifyOutput = verify?.output || '';
        const verifySuccess = verify?.timed_out !== true
          && verify?.exit_code === 0
          && (!entry.restoreVerifyExpected || verifyOutput.includes(entry.restoreVerifyExpected));
        if (!verifySuccess) {
          return {
            success: false,
            output: `回滚命令已执行，但读回验证失败，记录保持待处理状态${verifyOutput ? `\n${verifyOutput}` : ''}`,
          };
        }
      }
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

  /** 仅回滚同一可信目标的记录；旧的 host-only 记录不会进入候选集。 */
  async rollbackAllTarget(
    target: TargetIdentity,
    onEach?: (id: string, ok: boolean) => void,
  ): Promise<Array<{ id: string; success: boolean; output: string }>> {
    const entries = this.list({ target })
      .filter(e => !e.rolledBack && e.restoreCommand && e.target && (
        activeTargetContext.matches(e.target)
        || (e.allowStableTargetReconnect === true && isSameStableTarget(e.target, target))
      ))
      .sort((a, b) => b.timestamp - a.timestamp);
    const results: Array<{ id: string; success: boolean; output: string }> = [];
    for (const entry of entries) {
      const result = await this.rollback(entry.id);
      results.push({ id: entry.id, ...result });
      onEach?.(entry.id, result.success);
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

  /** 只清除稳定目标一致的可信记录，不误删同 host 的其他端口、账号或指纹。 */
  clearTarget(target: TargetIdentity): void {
    this.load();
    this.entries = this.entries.filter(e => !e.target || !isSameStableTarget(e.target, target));
    this.save();
  }

  getCount(server?: string): number {
    this.load();
    return server ? this.entries.filter(e => e.server === server).length : this.entries.length;
  }

  exportAll(server?: string): string {
    const list = this.list(server ? { server } : undefined);
    return this.formatExport(list);
  }

  exportTarget(target: TargetIdentity): string {
    return this.formatExport(this.list({ target }));
  }

  private formatExport(list: OperationEntry[]): string {
    return list.map(e =>
      `[${new Date(e.timestamp).toLocaleString()}] ${e.success ? 'OK' : 'FAIL'}${e.rolledBack ? ' (已回滚)' : ''} [${opSourceLabel(e.source)}] ${e.title}\n`
      + `  cmd: ${e.command}\n`
      + (e.target ? `  target: ${e.target.username}@${e.target.host}:${e.target.port} ${e.target.hostKeyFingerprint} (${e.target.sessionId})\n` : '')
      + (e.beforeValue || e.afterValue ? `  ${e.beforeValue || ''} -> ${e.afterValue || ''}\n` : '')
      + (e.restoreCommand ? `  restore: ${e.restoreCommand}\n` : '')
      + `  ${(e.output || '').substring(0, 200)}`
    ).join('\n\n');
  }
}

export const operationJournal = new OperationJournal();
