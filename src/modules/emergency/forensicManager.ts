/**
 * 取证快照管理器
 * 一键采集系统状态快照，支持快照对比
 */

import { executeEmergencyCommand, formatCommandResult } from './commandExecution';
import { activeTargetContext, type TargetIdentity } from '../core/targetContext';
import { incidentCaseManager } from '../case/incidentCaseManager';
import { logger } from '../core/logger';

// ========== 数据类型 ==========

export interface ForensicSnapshot {
  id: string;
  timestamp: Date;
  server: string;
  target: TargetIdentity;
  sha256: string;
  collection: { total: number; completed: number; failed: number };
  data: SnapshotData;
}

export interface SnapshotData {
  processes: string;
  networkConnections: string;
  listeningPorts: string;
  loginHistory: string;
  cronJobs: string;
  startupServices: string;
  authorizedKeys: string;
  sudoers: string;
  runningUsers: string;
  loadedModules: string;
  recentModifiedFiles: string;
  envVariables: string;
}

// 快照采集命令
const SNAPSHOT_COMMANDS: Record<keyof SnapshotData, string> = {
  processes:            'ps auxf 2>/dev/null | head -200',
  networkConnections:   '(ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null || echo "ss/netstat not available") | head -100',
  listeningPorts:       'ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || echo "ss/netstat not available"',
  loginHistory:         'last -20 2>/dev/null; echo "---"; w 2>/dev/null',
  cronJobs:             '(crontab -l 2>/dev/null; echo "===root==="; sudo -n crontab -l 2>/dev/null || true; echo "===/etc/crontab==="; cat /etc/crontab 2>/dev/null) | head -100',
  startupServices:      '(systemctl list-unit-files --type=service --state=enabled 2>/dev/null || chkconfig --list 2>/dev/null || rc-status -a 2>/dev/null || echo "service manager not available") | head -50',
  authorizedKeys:       'find /home /root -name authorized_keys -exec echo "=== {} ===" \\; -exec cat {} \\; 2>/dev/null | head -50',
  sudoers:              '(sudo -n cat /etc/sudoers 2>/dev/null || cat /etc/sudoers 2>/dev/null || echo "sudoers not readable") | grep -v "^#" | grep -v "^$" | head -30',
  runningUsers:         'who 2>/dev/null; echo "---"; id 2>/dev/null',
  loadedModules:        'lsmod 2>/dev/null | head -50',
  recentModifiedFiles:  'find /etc /usr/bin /usr/sbin -mtime -3 -type f 2>/dev/null | head -50',
  envVariables:         'env 2>/dev/null | sort | head -60',
};

const log = logger.module('Forensic');

export function buildForensicArtifact(snapshot: Omit<ForensicSnapshot, 'sha256'> | ForensicSnapshot): string {
  return JSON.stringify({
    schema: 'lovelyres-forensic-snapshot/v1',
    id: snapshot.id,
    timestamp: new Date(snapshot.timestamp).toISOString(),
    server: snapshot.server,
    target: snapshot.target,
    collection: snapshot.collection,
    data: snapshot.data,
  }, null, 2);
}

async function sha256(content: string): Promise<string> {
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new Error('当前运行环境不支持 WebCrypto，无法生成取证快照哈希');
  }
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(content));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
}

// ========== 管理器 ==========

export class ForensicManager {
  private snapshots: ForensicSnapshot[] = [];

  /** 采集一次完整快照 */
  async captureSnapshot(server: string, onProgress?: (pct: number, label: string) => void): Promise<ForensicSnapshot> {
    const target = activeTargetContext.get();
    if (!target) throw new Error('请先连接并确认目标主机');
    if (server && server !== target.host) throw new Error('请求的快照主机与当前可信目标不一致');
    const keys = Object.keys(SNAPSHOT_COMMANDS) as (keyof SnapshotData)[];
    const data: Partial<SnapshotData> = {};
    let completed = 0;
    let failed = 0;
    let cursor = 0;

    onProgress?.(5, '准备采集');

    const worker = async (): Promise<void> => {
      while (cursor < keys.length) {
        if (!activeTargetContext.matches(target)) {
          throw new Error('取证采集期间活动目标已变化，已丢弃整份快照');
        }
        const key = keys[cursor++];
        onProgress?.(Math.round((completed / keys.length) * 90) + 5, key);
        try {
          const result = await executeEmergencyCommand({
            command: SNAPSHOT_COMMANDS[key],
            timeoutSec: 30,
          });
          data[key] = result.success
            ? (result.output.trim() || '(empty)')
            : formatCommandResult(result);
          if (!result.success) failed += 1;
        } catch (error) {
          if (!activeTargetContext.matches(target)) {
            throw new Error('取证采集期间活动目标已变化，已丢弃整份快照');
          }
          failed += 1;
          data[key] = `(failed to collect: ${error})`;
        } finally {
          completed += 1;
        }
      }
    };
    await Promise.all(Array.from({ length: Math.min(4, keys.length) }, () => worker()));
    if (!activeTargetContext.matches(target)) {
      throw new Error('取证采集期间活动目标已变化，已丢弃整份快照');
    }
    onProgress?.(100, '完成');

    const baseSnapshot: Omit<ForensicSnapshot, 'sha256'> = {
      id: `snap-${Date.now()}`,
      timestamp: new Date(),
      server: target.host,
      target: {
        sessionId: target.sessionId, hostKeyFingerprint: target.hostKeyFingerprint,
        host: target.host, port: target.port, username: target.username,
      },
      collection: { total: keys.length, completed, failed },
      data: data as SnapshotData,
    };
    const snapshot: ForensicSnapshot = {
      ...baseSnapshot,
      sha256: await sha256(buildForensicArtifact(baseSnapshot)),
    };

    this.snapshots.push(snapshot);
    this.saveToStorage();
    await incidentCaseManager.addEvidence({
      kind: 'snapshot',
      label: `主机取证快照 ${snapshot.id}`,
      source: 'forensic-snapshot',
      locator: `forensic-snapshot:${snapshot.id}`,
      preview: `采集 ${snapshot.collection.completed}/${snapshot.collection.total} 项，失败 ${snapshot.collection.failed} 项`,
      externalSha256: snapshot.sha256,
    });
    return snapshot;
  }

  /** 获取所有快照 */
  getSnapshots(): ForensicSnapshot[] {
    return [...this.snapshots];
  }

  /** 比对两个快照并返回差异 */
  diffSnapshots(a: ForensicSnapshot, b: ForensicSnapshot): Record<keyof SnapshotData, { added: string[]; removed: string[] }> {
    const result = {} as Record<keyof SnapshotData, { added: string[]; removed: string[] }>;
    const keys = Object.keys(a.data) as (keyof SnapshotData)[];

    for (const key of keys) {
      const linesA = new Set(a.data[key].split('\n').map(l => l.trim()).filter(Boolean));
      const linesB = new Set(b.data[key].split('\n').map(l => l.trim()).filter(Boolean));
      const added = [...linesB].filter(l => !linesA.has(l));
      const removed = [...linesA].filter(l => !linesB.has(l));
      result[key] = { added, removed };
    }

    return result;
  }

  /** 导出快照为 JSON */
  exportSnapshot(snapshot: ForensicSnapshot): void {
    const json = buildForensicArtifact(snapshot);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `forensic-snapshot-${snapshot.id}-${snapshot.sha256.slice(0, 12)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // ========== 存储 ==========

  private saveToStorage(): void {
    if (typeof localStorage === 'undefined') return;
    try {
      const recent = this.snapshots.slice(-10);
      localStorage.setItem('lovelyres-forensic-snapshots', JSON.stringify(recent));
    } catch (error) {
      log.error('取证快照持久化失败', error);
      throw new Error('取证快照无法持久化，请释放本地存储空间后重试');
    }
  }

  loadFromStorage(): void {
    if (typeof localStorage === 'undefined') return;
    try {
      const raw = localStorage.getItem('lovelyres-forensic-snapshots');
      if (raw) {
        const parsed = JSON.parse(raw) as Array<ForensicSnapshot & { timestamp: string | Date }>;
        this.snapshots = parsed
          .filter(item => item?.target && item?.sha256 && item?.data)
          .map(item => ({ ...item, timestamp: new Date(item.timestamp) }));
      }
    } catch (error) {
      log.warn('取证快照存储读取失败', error);
      this.snapshots = [];
    }
  }
}

export const forensicManager = new ForensicManager();
