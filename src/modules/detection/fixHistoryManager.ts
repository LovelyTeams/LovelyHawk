/**
 * 修复历史管理器 — 记录所有检测修复操作，支持回滚
 */

import { invoke } from '@tauri-apps/api/core';
import { activeTargetContext, type TargetIdentity } from '../core/targetContext';
import { classifyCommandResult } from '../emergency/commandExecution';

export interface FixHistoryEntry {
  id: string;
  timestamp: number;
  detectionItemId: string;
  findingTitle: string;
  fixTitle: string;
  type: 'baseline' | 'command' | 'snippet';
  baselineItemId?: string;
  beforeValue?: string;
  afterValue?: string;
  backupInfo?: string;      // 备份文件路径或命令
  restoreCommand?: string;  // 回滚命令
  restoreVerifyCommand?: string;
  restoreVerifyPattern?: string;
  restoreExpectedValue?: string;
  command?: string;
  output: string;
  success: boolean;
  rolledBack: boolean;
  server: string;
  target?: TargetIdentity;
}

const STORAGE_KEY = 'detection-fix-history';
const MAX_ENTRIES = 200;

class FixHistoryManager {
  private history: FixHistoryEntry[] = [];
  private loaded = false;

  private load(): void {
    if (this.loaded) return;
    this.loaded = true;
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) this.history = JSON.parse(raw);
    } catch { this.history = []; }
  }

  private save(): void {
    if (this.history.length > MAX_ENTRIES) this.history = this.history.slice(-MAX_ENTRIES);
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(this.history)); } catch { /* ignore */ }
  }

  addEntry(entry: Omit<FixHistoryEntry, 'id' | 'timestamp' | 'rolledBack'>): FixHistoryEntry {
    this.load();
    const activeTarget = activeTargetContext.get();
    const full: FixHistoryEntry = {
      ...entry,
      target: entry.target ?? (
        activeTarget?.host === entry.server
          ? {
              sessionId: activeTarget.sessionId,
              hostKeyFingerprint: activeTarget.hostKeyFingerprint,
              host: activeTarget.host,
              port: activeTarget.port,
              username: activeTarget.username,
            }
          : undefined
      ),
      id: `fix_${Date.now()}_${Math.random().toString(36).substr(2, 4)}`,
      timestamp: Date.now(),
      rolledBack: false,
    };
    this.history.push(full);
    this.save();
    return full;
  }

  getHistory(): FixHistoryEntry[] {
    this.load();
    return [...this.history].reverse();
  }

  getForDetection(detectionItemId: string): FixHistoryEntry[] {
    this.load();
    return this.history.filter(e => e.detectionItemId === detectionItemId).reverse();
  }

  async rollback(entryId: string): Promise<{ success: boolean; output: string }> {
    this.load();
    const entry = this.history.find(e => e.id === entryId);
    if (!entry) return { success: false, output: '记录不存在' };
    if (entry.rolledBack) return { success: false, output: '已回滚过' };
    if (!entry.restoreCommand) return { success: false, output: '无回滚命令' };
    if (!entry.restoreVerifyCommand || !entry.restoreVerifyPattern || entry.restoreExpectedValue === undefined) {
      return { success: false, output: '旧修复记录缺少回滚验证契约，已阻止自动回滚' };
    }
    if (!entry.target) return { success: false, output: '旧修复记录缺少精确目标身份，已阻止自动回滚' };
    if (!activeTargetContext.matches(entry.target)) {
      return { success: false, output: '当前目标与修复记录不一致，已阻止回滚' };
    }

    try {
      const result = await invoke('ssh_execute_command_direct', {
        command: entry.restoreCommand,
        sessionId: entry.target.sessionId,
      }) as any;
      const execution = classifyCommandResult(result, entry.restoreCommand);
      if (!execution.success) {
        return { success: false, output: `${execution.message}${execution.output ? `\n${execution.output}` : ''}` };
      }
      const verifyResult = await invoke('ssh_execute_command_direct', {
        command: entry.restoreVerifyCommand,
        sessionId: entry.target.sessionId,
      }) as any;
      const verification = classifyCommandResult(verifyResult, entry.restoreVerifyCommand);
      if (!verification.success) {
        return { success: false, output: `恢复命令已执行，但验证失败: ${verification.message}\n${verification.output}` };
      }
      const match = new RegExp(entry.restoreVerifyPattern).exec(verification.output);
      const actual = match?.[1]?.trim();
      if (actual === undefined || actual.replace(/\s+/g, ' ').toLowerCase() !== entry.restoreExpectedValue.replace(/\s+/g, ' ').toLowerCase()) {
        return { success: false, output: `恢复命令已执行，但读回值不一致：期望 ${entry.restoreExpectedValue}，实际 ${actual ?? '无法解析'}` };
      }
      entry.rolledBack = true;
      this.save();
      return { success: true, output: `${execution.output}\n验证通过: ${actual}`.trim() };
    } catch (e) {
      return { success: false, output: `回滚失败: ${e}` };
    }
  }

  markRolledBack(entryId: string): void {
    this.load();
    const e = this.history.find(x => x.id === entryId);
    if (e) { e.rolledBack = true; this.save(); }
  }

  clear(): void {
    this.history = [];
    this.save();
  }

  getCount(): number {
    this.load();
    return this.history.length;
  }

  exportAll(): string {
    this.load();
    return this.history.map(e =>
      `[${new Date(e.timestamp).toLocaleString()}] ${e.success ? 'OK' : 'FAIL'} ${e.fixTitle}\n  ${e.detectionItemId}: ${e.beforeValue || ''} -> ${e.afterValue || ''}\n  ${e.output.substring(0, 200)}`
    ).join('\n\n');
  }
}

export const fixHistoryManager = new FixHistoryManager();
