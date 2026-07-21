/**
 * SSH连接管理器
 * 处理实际的SSH连接操作和状态管理
 * 与ssh/connectionManager.ts协同工作
 */

import { SSHConfigManager as ConfigManager } from '../ssh/connectionManager';

import { logger } from '../core/logger';
/** 正式包 drop 掉 console，诊断信息只有进 logger 才留得下来（设置→工具→诊断日志 可导出） */
const log = logger.module('SSHConn');


export interface SSHConnectionInfo {
  id?: string; // 连接配置ID
  host: string;
  port: number;
  username: string;
  connected: boolean;
  lastActivity?: Date;
}

export class SSHSessionManager {
  private connectionStatus: SSHConnectionInfo | null = null;
  private listeners: Array<(status: SSHConnectionInfo | null) => void> = [];
  private configManager: ConfigManager;

  constructor() {
    this.configManager = new ConfigManager();
  }

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
    keyPassphrase?: string
  ): Promise<void> {
    try {
      log.debug('[sshConnectionManager] connect 方法被调用');
      log.debug('  参数详情:', { host, port, username, authType, hasPassword: !!password, hasKeyPath: !!keyPath });

      const portNumber = typeof port === 'string' ? parseInt(port, 10) : port;
      if (isNaN(portNumber) || portNumber <= 0 || portNumber > 65535) {
        throw new Error(`无效的端口号: ${port} (类型: ${typeof port})`);
      }

      log.debug('调用 Tauri invoke: ssh_connect_direct, authType:', authType);
      await (window as any).__TAURI__.core.invoke('ssh_connect_direct', {
        host,
        port: portNumber,
        username,
        password: authType === 'password' ? password : undefined,
        authType,
        keyPath: authType === 'key' ? keyPath : undefined,
        keyPassphrase: authType === 'key' ? keyPassphrase : undefined,
      });
      
      log.debug('[sshConnectionManager] Tauri invoke 返回成功');

      // 更新连接状态
      this.connectionStatus = {
        host,
        port,
        username,
        connected: true,
        lastActivity: new Date()
      };

      // 保存连接配置（如果不存在的话）
      await this.saveConnectionConfig(host, port, username);

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
        await (window as any).__TAURI__.core.invoke('ssh_disconnect_direct');

        this.connectionStatus = null;
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
   * 保存连接配置
   */
  private async saveConnectionConfig(host: string, port: number, username: string): Promise<void> {
    try {
      // 检查是否已存在相同的连接配置
      const existingConnections = this.configManager.getConnections();
      const exists = existingConnections.some(conn =>
        conn.host === host && conn.port === port && conn.username === username
      );

      if (!exists) {
        // 创建新的连接配置
        const connectionName = `${username}@${host}:${port}`;
        await this.configManager.addConnection({
          name: connectionName,
          host,
          port,
          username,
          authType: 'password' as const,
          tags: ['auto-saved'],
          accounts: [{
            username,
            authType: 'password' as const,
            isDefault: true
          }]
        });
        log.debug('连接配置已自动保存:', connectionName);
      }
    } catch (error) {
      log.error('保存连接配置失败:', error);
      // 不抛出错误，因为这不应该影响连接本身
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
      const status = await (window as any).__TAURI__.core.invoke('ssh_get_connection_status');
      if (status) {
        this.connectionStatus = {
          host: status.host,
          port: status.port,
          username: status.username,
          connected: status.connected,
          lastActivity: new Date(status.last_activity)
        };
        this.notifyListeners();
      } else {
        this.connectionStatus = null;
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
