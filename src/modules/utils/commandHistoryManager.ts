/**
 * 命令历史记录管理器。
 *
 * v2 记录绑定已确认的 SSH 目标与命令摘要。旧记录仍可查看，但绝不允许重放。
 */

import { logger } from '../core/logger';
import {
  activeTargetContext,
  isSameStableTarget,
  type TargetIdentity,
} from '../core/targetContext';
import { deriveMeta } from '../emergency/emergencyView';
import { reportError } from './errorHandler';

const log = logger.module('CommandHistory');

export type CommandRisk = 'read-only' | 'mutating';

export interface CommandHistoryItem {
  id: string;
  command: string;
  title: string;
  output: string;
  timestamp: number;
  exitCode?: number;
  schemaVersion?: 2;
  target?: TargetIdentity;
  risk?: CommandRisk;
  source?: string;
  commandSha256?: string;
}

export type VerifiedCommandHistoryItem = CommandHistoryItem & {
  schemaVersion: 2;
  target: TargetIdentity;
  risk: CommandRisk;
  source: string;
  commandSha256: string;
};

export interface CommandReplayAssessment {
  allowed: boolean;
  requiresDangerousConfirmation: boolean;
  reason: string;
}

function isTargetIdentity(value: unknown): value is TargetIdentity {
  if (!value || typeof value !== 'object') return false;
  const target = value as Partial<TargetIdentity>;
  return typeof target.sessionId === 'string'
    && target.sessionId.length > 0
    && typeof target.hostKeyFingerprint === 'string'
    && target.hostKeyFingerprint.length > 0
    && typeof target.host === 'string'
    && target.host.length > 0
    && typeof target.port === 'number'
    && Number.isInteger(target.port)
    && target.port >= 1
    && target.port <= 65535
    && typeof target.username === 'string'
    && target.username.length > 0;
}

export function isVerifiedCommandHistoryItem(item: CommandHistoryItem): item is VerifiedCommandHistoryItem {
  return item.schemaVersion === 2
    && isTargetIdentity(item.target)
    && (item.risk === 'read-only' || item.risk === 'mutating')
    && typeof item.source === 'string'
    && item.source.length > 0
    && typeof item.commandSha256 === 'string'
    && /^[a-f0-9]{64}$/i.test(item.commandSha256);
}

export async function commandSha256(command: string): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error('当前环境不支持 WebCrypto，无法创建可验证命令历史');
  const digest = await subtle.digest('SHA-256', new TextEncoder().encode(command));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
}

function normalizeStoredItem(value: unknown): CommandHistoryItem | null {
  if (!value || typeof value !== 'object') return null;
  const item = value as Partial<CommandHistoryItem>;
  if (
    typeof item.id !== 'string'
    || typeof item.command !== 'string'
    || typeof item.title !== 'string'
    || typeof item.output !== 'string'
    || typeof item.timestamp !== 'number'
    || !Number.isFinite(item.timestamp)
  ) return null;

  return {
    id: item.id,
    command: item.command,
    title: item.title,
    output: item.output,
    timestamp: item.timestamp,
    ...(typeof item.exitCode === 'number' ? { exitCode: item.exitCode } : {}),
    ...(item.schemaVersion === 2 ? { schemaVersion: 2 as const } : {}),
    ...(isTargetIdentity(item.target) ? { target: { ...item.target } } : {}),
    ...(item.risk === 'read-only' || item.risk === 'mutating' ? { risk: item.risk } : {}),
    ...(typeof item.source === 'string' ? { source: item.source } : {}),
    ...(typeof item.commandSha256 === 'string' ? { commandSha256: item.commandSha256 } : {}),
  };
}

export class CommandHistoryManager {
  private static readonly STORAGE_KEY = 'lovelyres_command_history';
  private static readonly MAX_HISTORY_SIZE = 100;
  private static readonly MAX_OUTPUT_LENGTH = 64 * 1024;

  /** 保存可验证、目标绑定的 v2 历史；没有活动可信目标时拒绝保存。 */
  static async saveCommand(
    command: string,
    title: string,
    output: string,
    exitCode: number | null | undefined,
    source: string,
  ): Promise<boolean> {
    try {
      if (typeof localStorage === 'undefined') throw new Error('localStorage 不可用');
      const target = activeTargetContext.get();
      if (!target) throw new Error('没有已确认的活动 SSH 目标');

      const normalizedCommand = command.trim();
      if (!normalizedCommand) throw new Error('命令不能为空');
      const risk: CommandRisk = deriveMeta(normalizedCommand).readonly ? 'read-only' : 'mutating';
      const digest = await commandSha256(normalizedCommand);
      if (!activeTargetContext.matches(target)) {
        throw new Error('创建命令摘要期间活动目标已变化，未保存历史');
      }
      const history = this.getHistory();
      const newItem: VerifiedCommandHistoryItem = {
        id: this.generateId(),
        schemaVersion: 2,
        command: normalizedCommand,
        commandSha256: digest,
        title,
        output: output.slice(0, this.MAX_OUTPUT_LENGTH),
        timestamp: Date.now(),
        ...(typeof exitCode === 'number' ? { exitCode } : {}),
        target: {
          sessionId: target.sessionId,
          hostKeyFingerprint: target.hostKeyFingerprint,
          host: target.host,
          port: target.port,
          username: target.username,
        },
        risk,
        source: source.trim() || 'unknown',
      };

      history.unshift(newItem);
      localStorage.setItem(this.STORAGE_KEY, JSON.stringify(history.slice(0, this.MAX_HISTORY_SIZE)));
      log.info('已保存目标绑定的命令历史', {
        id: newItem.id,
        target: `${target.username}@${target.host}:${target.port}`,
        risk,
      });
      return true;
    } catch (error) {
      reportError(error, { module: 'CommandHistory', action: '保存命令历史', silent: true });
      return false;
    }
  }

  static getHistory(): CommandHistoryItem[] {
    try {
      if (typeof localStorage === 'undefined') return [];
      const data = localStorage.getItem(this.STORAGE_KEY);
      if (!data) return [];
      const parsed: unknown = JSON.parse(data);
      if (!Array.isArray(parsed)) return [];
      return parsed.map(normalizeStoredItem).filter((item): item is CommandHistoryItem => item !== null);
    } catch (error) {
      reportError(error, { module: 'CommandHistory', action: '读取命令历史', silent: true });
      return [];
    }
  }

  static getById(id: string): CommandHistoryItem | null {
    return this.getHistory().find(item => item.id === id) || null;
  }

  static clearHistory(): void {
    try {
      if (typeof localStorage === 'undefined') return;
      localStorage.removeItem(this.STORAGE_KEY);
      log.info('命令历史已清空');
    } catch (error) {
      reportError(error, { module: 'CommandHistory', action: '清空命令历史', silent: true });
    }
  }

  static deleteById(id: string): void {
    try {
      if (typeof localStorage === 'undefined') return;
      const filtered = this.getHistory().filter(item => item.id !== id);
      localStorage.setItem(this.STORAGE_KEY, JSON.stringify(filtered));
      log.info('已删除命令历史', { id });
    } catch (error) {
      reportError(error, { module: 'CommandHistory', action: '删除命令历史', silent: true });
    }
  }

  static search(keyword: string): CommandHistoryItem[] {
    const lowerKeyword = keyword.toLowerCase();
    return this.getHistory().filter(item =>
      item.command.toLowerCase().includes(lowerKeyword)
      || item.title.toLowerCase().includes(lowerKeyword)
      || item.output.toLowerCase().includes(lowerKeyword)
      || item.target?.host.toLowerCase().includes(lowerKeyword)
      || item.target?.username.toLowerCase().includes(lowerKeyword)
    );
  }

  static async assessReplay(
    item: CommandHistoryItem,
    activeTarget: TargetIdentity | null = activeTargetContext.get(),
  ): Promise<CommandReplayAssessment> {
    if (!isVerifiedCommandHistoryItem(item)) {
      return { allowed: false, requiresDangerousConfirmation: false, reason: '旧版或不完整记录仅可查看，不能重新执行' };
    }
    if (!activeTarget) {
      return { allowed: false, requiresDangerousConfirmation: false, reason: '没有已确认的活动 SSH 目标' };
    }
    if (!isSameStableTarget(item.target, activeTarget)) {
      return {
        allowed: false,
        requiresDangerousConfirmation: false,
        reason: `目标不一致：历史属于 ${item.target.username}@${item.target.host}:${item.target.port}`,
      };
    }

    const actualHash = await commandSha256(item.command);
    if (actualHash !== item.commandSha256.toLowerCase()) {
      return { allowed: false, requiresDangerousConfirmation: false, reason: '命令内容与保存摘要不一致，已阻止执行' };
    }

    const currentRisk: CommandRisk = deriveMeta(item.command).readonly ? 'read-only' : 'mutating';
    if (currentRisk !== item.risk) {
      return { allowed: false, requiresDangerousConfirmation: false, reason: '命令风险元数据已变化，已阻止执行' };
    }

    return {
      allowed: true,
      requiresDangerousConfirmation: currentRisk === 'mutating',
      reason: currentRisk === 'mutating' ? '同一可信目标；执行前必须危险确认' : '同一可信目标的只读命令',
    };
  }

  private static generateId(): string {
    return `cmd_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
  }

  static getRecent(count = 10): CommandHistoryItem[] {
    return this.getHistory().slice(0, count);
  }

  static getStats(): { total: number; oldestTimestamp: number | null; newestTimestamp: number | null } {
    const history = this.getHistory();
    if (history.length === 0) return { total: 0, oldestTimestamp: null, newestTimestamp: null };
    return {
      total: history.length,
      oldestTimestamp: history[history.length - 1].timestamp,
      newestTimestamp: history[0].timestamp,
    };
  }
}
