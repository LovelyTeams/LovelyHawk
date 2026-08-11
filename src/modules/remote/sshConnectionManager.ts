/**
 * SSH连接管理器
 * 处理实际的SSH连接操作和状态管理
 * 与ssh/connectionManager.ts协同工作
 */

import {
  connectSSHAdvancedWithHostKeyConfirmation,
  type SSHAuthType,
  type SSHJumpHostArgs,
} from '../ssh/hostKeyConfirmation';
import { activeTargetContext, targetIdentityFromBackend, type BackendSSHConnectionStatus } from '../core/targetContext';
import { logger } from '../core/logger';
import { targetCapabilityStore, type TargetCapabilities } from '../core/targetCapabilities';
/** 正式包 drop 掉 console，诊断信息只有进 logger 才留得下来（状态栏「日志」按钮可导出） */
const log = logger.module('SSHConn');


export interface SSHConnectionInfo {
  id?: string; // 连接配置ID
  sessionId?: string; // 后端会话ID，每次重连都会变化
  hostKeyFingerprint?: string;
  host: string;
  port: number;
  username: string;
  connected: boolean;
  lastActivity?: Date;
  capabilities?: TargetCapabilities;
}

export interface SSHConnectAdvancedOptions {
  certificatePath?: string;
  keyboardInteractiveResponses?: string[];
  agentIdentityFingerprint?: string;
  jumpHost?: SSHJumpHostArgs | null;
}

export class SSHSessionManager {
  private connectionStatus: SSHConnectionInfo | null = null;
  private listeners: Array<(status: SSHConnectionInfo | null) => void> = [];

  /**
   * 获取当前连接状态
   */
  getConnectionStatus(): SSHConnectionInfo | null {
    return this.connectionStatus;
  }

  /**
   * 检查是否已连接
   */
  isConnected(): boolean {
    return this.connectionStatus?.connected || false;
  }

  /**
   * 获取当前连接的ID
   */
  getCurrentConnectionId(): string | undefined {
    return this.connectionStatus?.id;
  }

  /**
   * 手动设置连接状态（用于同步主界面连接状态）
   */
  setConnectionStatus(status: SSHConnectionInfo | null): void {
    this.connectionStatus = status;
    if (status?.connected && status.sessionId) {
      activeTargetContext.activate({
        sessionId: status.sessionId,
        hostKeyFingerprint: status.hostKeyFingerprint || '',
        host: status.host,
        port: status.port,
        username: status.username,
      });
    } else if (!status) {
      activeTargetContext.clear();
    }
    this.notifyListeners();
  }

  /**
   * 建立SSH连接
   */
  async connect(
    host: string,
    port: number,
    username: string,
    password: string,
    authType: string = 'password',
    keyPath?: string,
    keyPassphrase?: string,
    advanced: SSHConnectAdvancedOptions = {},
  ): Promise<void> {
    try {
      log.debug('[sshConnectionManager] connect 方法被调用');
      log.debug('  参数详情:', { host, port, username, authType, hasPassword: !!password, hasKeyPath: !!keyPath });

      const portNumber = typeof port === 'string' ? parseInt(port, 10) : port;
      if (isNaN(portNumber) || portNumber <= 0 || portNumber > 65535) {
        throw new Error(`无效的端口号: ${port} (类型: ${typeof port})`);
      }

      log.debug('调用 Tauri invoke: ssh_connect_direct, authType:', authType);
      const supportedAuthTypes: SSHAuthType[] = [
        'password', 'key', 'certificate', 'keyboard-interactive', 'agent',
      ];
      if (!supportedAuthTypes.includes(authType as SSHAuthType)) {
        throw new Error(`不支持的 SSH 认证方式: ${authType}`);
      }
      const typedAuthType = authType as SSHAuthType;
      const connected = await connectSSHAdvancedWithHostKeyConfirmation({
        host,
        port: portNumber,
        username,
        authentication: {
          authType: typedAuthType,
          password: typedAuthType === 'password' ? password : undefined,
          keyPath: typedAuthType === 'key' || typedAuthType === 'certificate' ? keyPath : undefined,
          keyPassphrase: typedAuthType === 'key' || typedAuthType === 'certificate'
            ? keyPassphrase
            : undefined,
          certificatePath: typedAuthType === 'certificate' ? advanced.certificatePath : undefined,
          keyboardInteractiveResponses: typedAuthType === 'keyboard-interactive'
            ? advanced.keyboardInteractiveResponses
            : undefined,
          agentIdentityFingerprint: typedAuthType === 'agent'
            ? advanced.agentIdentityFingerprint
            : undefined,
        },
        jumpHost: advanced.jumpHost,
      });

      log.debug('[sshConnectionManager] Tauri invoke 返回成功');

      // 更新连接状态
      this.connectionStatus = {
        sessionId: connected.session_id,
        hostKeyFingerprint: connected.host_key_fingerprint,
        host,
        port: portNumber,
        username,
        connected: true,
        lastActivity: new Date()
      };
      activeTargetContext.activate(targetIdentityFromBackend(connected));

      try {
        this.connectionStatus.capabilities = await targetCapabilityStore.probeActiveTarget();
      } catch (error) {
        log.warn('SSH 已连接，但目标能力预检失败', error);
      }

      // 通知监听器
      this.notifyListeners();

      // 初始化终端工作目录
      if ((window as any).terminalManager && (window as any).terminalManager.initializeWorkingDirectory) {
        setTimeout(() => {
          (window as any).terminalManager.initializeWorkingDirectory();
        }, 500);
      }

    } catch (error) {
      log.error('SSH连接失败:', error);
      throw error;
    }
  }

  /**
   * 重新连接。
   * 出于安全,凭据不落盘,因此无法完全静默重连:
   *  1) 先向后端核对会话是否仍存活(仅前端状态丢失的情况可直接恢复);
   *  2) 否则打开连接对话框,让用户在赛场快速重新连接。
   * 返回 true 表示已恢复为已连接状态。
   */
  async reconnect(): Promise<boolean> {
    const status = await this.checkConnectionStatus();
    if (status?.connected) {
      (window as any).showNotification?.('SSH 连接仍然有效，已恢复', 'success');
      return true;
    }
    (window as any).showNotification?.('SSH 已断开，请重新连接', 'warning');
    (window as any).showSSHConnectionDialog?.();
    return false;
  }

  /**
   * 断开SSH连接
   */
  async disconnect(): Promise<void> {
    try {
      if (this.connectionStatus?.connected) {
        const sessionId = this.connectionStatus.sessionId;
        await (window as any).__TAURI__.core.invoke('ssh_disconnect_direct');

        this.connectionStatus = null;
        activeTargetContext.clear(sessionId);
        this.notifyListeners();
      }
    } catch (error) {
      log.error('断开SSH连接失败:', error);
    }
  }

  /**
   * 更新最后活动时间（仅本地更新，不触发全局监听，以避免循环刷新）
   */
  updateLastActivity(): void {
    if (this.connectionStatus) {
      this.connectionStatus.lastActivity = new Date();
      // 不再调用 notifyListeners()，防止触发 UI 刷新循环
    }
  }

  /**
   * 添加状态监听器
   */
  addListener(listener: (status: SSHConnectionInfo | null) => void): void {
    this.listeners.push(listener);
  }

  /**
   * 移除状态监听器
   */
  removeListener(listener: (status: SSHConnectionInfo | null) => void): void {
    const index = this.listeners.indexOf(listener);
    if (index > -1) {
      this.listeners.splice(index, 1);
    }
  }

  /**
   * 通知所有监听器
   */
  private notifyListeners(): void {
    this.listeners.forEach(listener => {
      try {
        listener(this.connectionStatus);
      } catch (error) {
        log.error('SSH连接状态监听器执行失败:', error);
      }
    });
  }

  /**
   * 检查连接状态（从后端获取最新状态）
   */
  async checkConnectionStatus(): Promise<SSHConnectionInfo | null> {
    try {
      const status = await (window as any).__TAURI__.core.invoke('ssh_get_connection_status') as BackendSSHConnectionStatus | null;
      if (status) {
        this.connectionStatus = {
          sessionId: status.session_id,
          hostKeyFingerprint: status.host_key_fingerprint,
          host: status.host,
          port: status.port,
          username: status.username,
          connected: status.connected,
          lastActivity: new Date(status.last_activity)
        };
        if (status.session_id) {
          activeTargetContext.activate(targetIdentityFromBackend(status));
        }
        this.notifyListeners();
      } else {
        this.connectionStatus = null;
        activeTargetContext.clear();
        this.notifyListeners();
      }
      return this.connectionStatus;
    } catch (error) {
      log.error('检查SSH连接状态失败:', error);
      return null;
    }
  }
}

// 全局SSH连接管理器实例
export const sshConnectionManager = new SSHSessionManager();
