/**
 * 多服务器批量管理器
 * 在多台服务器上批量执行命令、收集结果
 */

import { invoke } from '@tauri-apps/api/core';
import { SSHConfigManager, type SSHConnection } from '../ssh/connectionManager';
import { eventBus } from '../core/eventBus';
import { activeTargetContext, targetIdentityFromBackend, type BackendSSHConnectionStatus, type TargetIdentity } from '../core/targetContext';
import { classifyCommandResult } from '../emergency/commandExecution';

// ========== 类型 ==========

export interface BatchTask {
  id: string;
  name: string;
  command: string;
  targets: string[];        // 连接 ID 列表
  status: 'pending' | 'running' | 'completed' | 'cancelled' | 'failed';
  results: BatchResult[];
  options: BatchExecutionOptions;
  error?: string;
  createdAt: Date;
  completedAt?: Date;
}

export interface BatchResult {
  connectionId: string;
  serverName: string;
  host: string;
  status: 'success' | 'failed' | 'skipped';
  output: string;
  error?: string;
  duration: number;         // ms
  target?: TargetIdentity;
  exitCode?: number | null;
  timedOut?: boolean;
  verifyCommand?: string;
  verifyOutput?: string;
  verified?: boolean;
}

export interface BatchExecutionOptions {
  strategy?: 'rolling' | 'canary';
  canaryCount?: number;
  stopOnFailure?: boolean;
  verifyCommand?: string;
}

export interface BatchProgress {
  taskId: string;
  totalServers: number;
  completedServers: number;
  currentServer: string;
  percent: number;
}

// ========== 批量管理器 ==========

export class BatchServerManager {
  private connectionManager: SSHConfigManager;
  private taskHistory: BatchTask[] = [];
  private activeTask: BatchTask | null = null;
  private cancelled = false;

  constructor(connectionManager: SSHConfigManager) {
    this.connectionManager = connectionManager;
    this.loadHistory();
  }

  /** 获取所有可用的服务器 */
  getAvailableServers(): SSHConnection[] {
    return this.connectionManager.getConnections();
  }

  /** 获取任务历史 */
  getHistory(): BatchTask[] {
    return [...this.taskHistory];
  }

  /** 获取当前活动任务 */
  getActiveTask(): BatchTask | null {
    return this.activeTask;
  }

  /**
   * 在多台服务器上批量执行命令
   */
  async executeBatch(
    name: string,
    command: string,
    targetIds: string[],
    onProgress?: (p: BatchProgress) => void,
    options: BatchExecutionOptions = {},
  ): Promise<BatchTask> {
    if (this.activeTask?.status === 'running') {
      throw new Error('已有批量任务正在运行');
    }

    this.cancelled = false;

    const normalizedOptions: BatchExecutionOptions = {
      strategy: options.strategy === 'canary' ? 'canary' : 'rolling',
      canaryCount: Math.max(1, Math.min(targetIds.length || 1, Math.floor(options.canaryCount || 1))),
      stopOnFailure: options.stopOnFailure === true,
      verifyCommand: options.verifyCommand?.trim() || undefined,
    };
    const task: BatchTask = {
      id: `batch-${Date.now()}`,
      name,
      command,
      targets: targetIds,
      status: 'running',
      results: [],
      options: normalizedOptions,
      createdAt: new Date(),
    };

    this.activeTask = task;

    // 保存当前连接状态，任务结束后恢复
    const activeConn = this.connectionManager.getActiveConnection();
    const activeConnId = activeConn?.id;
    const previousSessionId = activeTargetContext.get()?.sessionId;

    try {
      let haltReason = '';
      for (let i = 0; i < targetIds.length; i++) {
        if (this.cancelled) {
          task.status = 'cancelled';
          break;
        }

        const connId = targetIds[i];
        const conn = this.connectionManager.getConnection(connId);
        if (haltReason) {
          task.results.push({
            connectionId: connId,
            serverName: conn?.name || '未知',
            host: conn?.host || '未知',
            status: 'skipped', output: '', error: haltReason, duration: 0,
          });
          continue;
        }
        if (!conn) {
          task.results.push({
            connectionId: connId,
            serverName: '未知',
            host: '未知',
            status: 'skipped',
            output: '',
            error: '连接配置不存在',
            duration: 0,
          });
        } else {
          onProgress?.({
            taskId: task.id,
            totalServers: targetIds.length,
            completedServers: i,
            currentServer: conn.name,
            percent: Math.round((i / targetIds.length) * 100),
          });

          const result = await this.executeOnServer(conn, command, normalizedOptions.verifyCommand);
          task.results.push(result);
        }

        const canaryBoundary = normalizedOptions.strategy === 'canary' && i + 1 === normalizedOptions.canaryCount;
        if (canaryBoundary && task.results.slice(0, normalizedOptions.canaryCount).some(result => result.status !== 'success')) {
          haltReason = 'Canary 阶段存在失败，已阻止向剩余服务器发布';
        } else if (normalizedOptions.strategy === 'rolling' && normalizedOptions.stopOnFailure && task.results[task.results.length - 1]?.status !== 'success') {
          haltReason = '滚动执行遇到失败，已按策略停止剩余服务器';
        }
      }

      if (task.status !== 'cancelled') {
        task.status = 'completed';
      }
      task.completedAt = new Date();

      onProgress?.({
        taskId: task.id,
        totalServers: targetIds.length,
        completedServers: targetIds.length,
        currentServer: '完成',
        percent: 100,
      });
    } catch (e: any) {
      task.status = 'failed';
      task.error = String(e);
      task.completedAt = new Date();
    }

    // 恢复原始连接
    if (previousSessionId) {
      try {
        await invoke('ssh_set_current_session', { sessionId: previousSessionId });
      } catch {
        if (activeConnId) {
          try { await this.connectionManager.connect(activeConnId); } catch { /* best effort */ }
        }
      }
    }

    // 保存到历史
    this.taskHistory.push(task);
    if (this.taskHistory.length > 50) this.taskHistory.shift();
    this.saveHistory();
    this.activeTask = null;

    const failedCount = task.results.filter(result => result.status === 'failed').length;
    eventBus.emit('notification', {
      type: task.status === 'completed' && failedCount === 0 ? 'success' : 'warning',
      message: task.status === 'cancelled'
        ? `批量任务「${name}」已取消`
        : `批量任务「${name}」完成，失败 ${failedCount} 台`,
      title: '批量执行',
    });

    return task;
  }

  /** 取消当前任务 */
  cancelBatch(): void {
    this.cancelled = true;
  }

  // ========== 内部方法 ==========

  /**
   * 在单台服务器上执行命令
   * 使用 ssh_connect_direct / ssh_execute_command_direct / ssh_disconnect_session_direct
   * 独立于主连接，不影响当前活动连接
   */
  private async executeOnServer(conn: SSHConnection, command: string, verifyCommand?: string): Promise<BatchResult> {
    const start = Date.now();
    let sessionId: string | undefined;
    let target: TargetIdentity | undefined;
    try {
      if (!conn.hostKeyFingerprint) {
        return {
          connectionId: conn.id, serverName: conn.name, host: conn.host,
          status: 'failed', output: '', duration: Date.now() - start,
          error: '缺少已确认的主机指纹；请先在服务器页交互连接一次，再执行批量任务',
        };
      }
      if (conn.jumpHost && !conn.jumpHost.hostKeyFingerprint) {
        return {
          connectionId: conn.id, serverName: conn.name, host: conn.host,
          status: 'failed', output: '', duration: Date.now() - start,
          error: '堡垒机缺少已确认的主机指纹；请先交互连接并核对堡垒机身份，再执行批量任务',
        };
      }
      if (conn.authType === 'keyboard-interactive'
        || conn.jumpHost?.authType === 'keyboard-interactive') {
        return {
          connectionId: conn.id, serverName: conn.name, host: conn.host,
          status: 'failed', output: '', duration: Date.now() - start,
          error: '批量任务不能弹出 MFA 提示；请改用 Agent/证书，或先完成独立的交互认证流程',
        };
      }
      // 解密密码
      let password: string | undefined;
      if (conn.authType === 'password' && conn.encryptedPassword) {
        password = await invoke('decrypt_password', {
          encryptedPassword: conn.encryptedPassword,
        }) as string;
      }
      let jumpPassword: string | undefined;
      if (conn.jumpHost?.authType === 'password' && conn.jumpHost.encryptedPassword) {
        jumpPassword = await invoke('decrypt_password', {
          encryptedPassword: conn.jumpHost.encryptedPassword,
        }) as string;
      }

      const useAdvancedConnect = Boolean(conn.jumpHost)
        || !['password', 'key'].includes(conn.authType);
      const connected = useAdvancedConnect
        ? await invoke<BackendSSHConnectionStatus>('ssh_connect_advanced', {
          request: {
            host: conn.host,
            port: conn.port,
            username: conn.username,
            expectedHostKeyFingerprint: conn.hostKeyFingerprint,
            authentication: {
              authType: conn.authType,
              password,
              keyPath: conn.keyPath || null,
              keyPassphrase: conn.keyPassphrase || null,
              certificatePath: conn.certificatePath || null,
              agentIdentityFingerprint: conn.agentIdentityFingerprint || null,
            },
            jumpHost: conn.jumpHost ? {
              host: conn.jumpHost.host,
              port: conn.jumpHost.port,
              username: conn.jumpHost.username,
              expectedHostKeyFingerprint: conn.jumpHost.hostKeyFingerprint || null,
              authentication: {
                authType: conn.jumpHost.authType,
                password: jumpPassword,
                keyPath: conn.jumpHost.keyPath || null,
                keyPassphrase: conn.jumpHost.keyPassphrase || null,
                certificatePath: conn.jumpHost.certificatePath || null,
                agentIdentityFingerprint: conn.jumpHost.agentIdentityFingerprint || null,
              },
            } : null,
          },
        })
        : await invoke<BackendSSHConnectionStatus>('ssh_connect_direct', {
          host: conn.host,
          port: conn.port,
          username: conn.username,
          password,
          authType: conn.authType,
          keyPath: conn.keyPath || null,
          keyPassphrase: conn.keyPassphrase || null,
          expectedHostKeyFingerprint: conn.hostKeyFingerprint,
        });
      sessionId = connected.session_id;
      target = targetIdentityFromBackend(connected);

      // 执行命令
      const result: any = await invoke('ssh_execute_command_direct', { command, sessionId });
      const execution = classifyCommandResult(result, command);

      if (!execution.success) {
        return {
          connectionId: conn.id,
          serverName: conn.name,
          host: conn.host,
          status: 'failed',
          output: execution.output,
          error: execution.message,
          duration: Date.now() - start,
          target,
          exitCode: result?.exit_code,
          timedOut: result?.timed_out,
        };
      }

      let verifyResult: any;
      if (verifyCommand) {
        verifyResult = await invoke('ssh_execute_command_direct', { command: verifyCommand, sessionId });
        const verification = classifyCommandResult(verifyResult, verifyCommand);
        if (!verification.success) {
          return {
            connectionId: conn.id, serverName: conn.name, host: conn.host,
            status: 'failed', output: result?.output || '',
            error: `执行成功，但独立验证失败：${verification.message}`,
            duration: Date.now() - start, target,
            exitCode: result?.exit_code, timedOut: result?.timed_out,
            verifyCommand, verifyOutput: verification.output, verified: false,
          };
        }
      }

      return {
        connectionId: conn.id,
        serverName: conn.name,
        host: conn.host,
        status: 'success',
        output: result?.output || '',
        duration: Date.now() - start,
        target,
        exitCode: result?.exit_code,
        timedOut: result?.timed_out,
        verifyCommand,
        verifyOutput: verifyResult?.output,
        verified: verifyCommand ? true : undefined,
      };
    } catch (e: any) {
      return {
        connectionId: conn.id,
        serverName: conn.name,
        host: conn.host,
        status: 'failed',
        output: '',
        error: String(e),
        duration: Date.now() - start,
        target,
      };
    } finally {
      if (sessionId) {
        try { await invoke('ssh_disconnect_session_direct', { sessionId }); } catch { /* best effort */ }
      }
    }
  }

  // ========== 持久化 ==========

  private saveHistory(): void {
    try {
      const data = this.taskHistory.slice(-20);
      localStorage.setItem('lovelyres-batch-history', JSON.stringify(data));
    } catch { /* ignore */ }
  }

  private loadHistory(): void {
    try {
      const raw = localStorage.getItem('lovelyres-batch-history');
      if (raw) this.taskHistory = JSON.parse(raw);
    } catch { /* ignore */ }
  }

  /**
   * 导出批量任务结果为 CSV
   */
  exportTaskAsCSV(task: BatchTask): void {
    const header = '服务器,主机,状态,耗时(s),输出,错误\n';
    const rows = task.results.map(r =>
      `"${r.serverName}","${r.host}","${r.status}","${(r.duration / 1000).toFixed(1)}","${(r.output || '').replace(/"/g, '""').slice(0, 500)}","${(r.error || '').replace(/"/g, '""')}"`
    ).join('\n');

    const csv = '\uFEFF' + header + rows; // BOM for Excel
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `batch-${task.id}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }
}
