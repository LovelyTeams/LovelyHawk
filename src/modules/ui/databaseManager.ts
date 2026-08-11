/**
 * 数据库管理器
 * 管理数据库连接、SQL 执行、数据浏览等功能
 */

import { invokeTargetBoundSSH } from '../core/targetBoundSSH';
import { activeTargetContext, type TargetIdentity } from '../core/targetContext';
import { isArtifactForTarget } from '../core/targetBoundArtifact';
import { operationJournal } from '../core/operationJournal';
import { shq } from '../core/shellEscape';
import { reportError } from '../utils/errorHandler';
import { showConfirm } from './confirmDialog';

// ==================== Types ====================

export interface DatabaseInfo {
  db_type: string;
  name: string;
  version: string;
  status: string;
  port: number;
  data_dir: string;
}

export interface DbConnection {
  id: string;
  db_type: string;
  host: string;
  port: number;
  username: string;
  password: string;
  database?: string;
  name: string;          // 显示名称
  isConnected: boolean;
}

export interface SqlResult {
  columns: string[];
  rows: string[][];
  row_count: number;
  affected_rows?: number;
  execution_time_ms: number;
  error?: string;
  exit_code?: number | null;
  timed_out?: boolean;
}

interface DbServiceControlResult {
  success: boolean;
  command: string;
  output: string;
  exit_code: number | null;
  timed_out: boolean;
  verify_output: string;
  verify_command: string;
  verified: boolean;
}

const DB_SERVICE_UNITS: Record<string, string[]> = {
  mysql: ['mysql', 'mysqld', 'mariadb'],
  postgresql: ['postgresql'],
  redis: ['redis', 'redis-server'],
  mongodb: ['mongod', 'mongodb'],
  dm: ['DmServiceDMSERVER'],
  kingbase: ['kingbase'],
};

function targetLabel(target: TargetIdentity): string {
  return `${target.username}@${target.host}:${target.port}\n指纹：${target.hostKeyFingerprint}`;
}

function dbServiceRollback(dbType: string, action: string): {
  command: string;
  verifyCommand: string;
  verifyExpected: string;
} | undefined {
  const restoreAction = action === 'start' ? 'stop' : action === 'stop' ? 'start' : undefined;
  const units = DB_SERVICE_UNITS[dbType];
  if (!restoreAction || !units?.length) return undefined;

  const command = units.map(unit => `systemctl ${shq(restoreAction)} ${shq(unit)} 2>/dev/null`).join(' || ');
  const activeTest = units.map(unit => `systemctl is-active --quiet ${shq(unit)}`).join(' || ');
  const verifyCommand = `if ${activeTest}; then echo active; else echo inactive; fi`;
  return {
    command,
    verifyCommand,
    verifyExpected: restoreAction === 'start' ? 'active' : 'inactive',
  };
}

export interface TableInfo {
  name: string;
  row_count?: number;
  size?: string;
  engine?: string;
}

export interface ColumnInfo {
  name: string;
  data_type: string;
  is_nullable: boolean;
  is_primary_key: boolean;
  default_value?: string;
}

export interface DbUser {
  username: string;
  host: string;
  privileges: string[];
}

export interface SqlHistoryEntry {
  sql: string;
  db_type: string;
  database: string;
  timestamp: number;
  success: boolean;
  row_count?: number;
  target?: TargetIdentity;
}

export type DbTab = 'connections' | 'sql' | 'browser' | 'users' | 'ops';

export function isPotentiallyMutatingSql(sql: string, dbType: string): boolean {
  const withoutLeadingComments = sql
    .replace(/^\s*(?:--[^\n]*(?:\n|$)|#[^\n]*(?:\n|$)|\/\*[\s\S]*?\*\/\s*)*/g, '')
    .trim();
  const firstWord = withoutLeadingComments.match(/^([a-z]+)/i)?.[1]?.toLowerCase() || '';
  if (dbType === 'redis') {
    return !['ping', 'get', 'mget', 'scan', 'keys', 'ttl', 'pttl', 'type', 'info', 'dbsize', 'exists'].includes(firstWord);
  }
  if (dbType === 'mongodb') {
    return !/\.(?:find|findOne|aggregate|count|countDocuments)\s*\(|runCommand\s*\(\s*\{\s*ping\s*:/i.test(withoutLeadingComments);
  }
  return !['select', 'show', 'describe', 'desc', 'explain'].includes(firstWord);
}

// ==================== Manager ====================

export class DatabaseManager {
  private detectedDatabases: DatabaseInfo[] = [];
  private connections: DbConnection[] = [];
  private activeConnection: DbConnection | null = null;
  private currentTab: DbTab = 'connections';
  private sqlHistory: SqlHistoryEntry[] = [];
  private lastSqlResult: SqlResult | null = null;

  // 数据浏览状态
  private databases: string[] = [];
  private currentDatabase: string = '';
  private tables: TableInfo[] = [];
  private currentTable: string = '';
  private tableData: SqlResult | null = null;
  private columns: ColumnInfo[] = [];

  // 用户管理状态
  private users: DbUser[] = [];

  // UI 状态
  private initialized = false;
  private loading = false;
  private targetSessionId = '';

  constructor() {
    this.loadConnectionsFromStorage();
    this.loadSqlHistory();
  }

  // ==================== Lifecycle ====================

  async initialize(): Promise<void> {
    this.synchronizeTargetState();
    if (!this.initialized) {
      this.bindEvents();
      this.initialized = true;
      (window as any).databaseManager = this;
    }
  }

  private synchronizeTargetState(): boolean {
    const nextSessionId = activeTargetContext.get()?.sessionId || '';
    if (nextSessionId === this.targetSessionId) return false;
    this.targetSessionId = nextSessionId;
    this.detectedDatabases = [];
    this.activeConnection = null;
    this.connections.forEach(connection => { connection.isConnected = false; });
    this.lastSqlResult = null;
    this.databases = [];
    this.currentDatabase = '';
    this.tables = [];
    this.currentTable = '';
    this.tableData = null;
    this.columns = [];
    this.users = [];
    this.loading = false;
    return true;
  }

  private bindEvents(): void {
    document.addEventListener('click', (e) => {
      const target = (e.target as HTMLElement).closest('[data-db-action]') as HTMLElement;
      if (!target) return;
      const action = target.getAttribute('data-db-action') || '';
      this.handleAction(action, target);
    });

    // SQL 执行快捷键
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        const modal = document.getElementById('db-add-modal');
        if (modal && getComputedStyle(modal).display !== 'none') {
          this.hideAddConnectionModal();
          e.preventDefault();
          return;
        }
      }

      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        const sqlEditor = document.getElementById('db-sql-editor') as HTMLTextAreaElement;
        if (sqlEditor && document.activeElement === sqlEditor) {
          e.preventDefault();
          this.executeSql();
        }
      }
    });

    document.addEventListener('click', (e) => {
      const modal = document.getElementById('db-add-modal');
      if (modal && e.target === modal) this.hideAddConnectionModal();
    });
  }

  // ==================== Action Router ====================

  private async handleAction(action: string, el: HTMLElement): Promise<void> {
    if (this.synchronizeTargetState()) this.updateUI();
    switch (action) {
      case 'switch-tab': this.switchTab(el.getAttribute('data-tab') as DbTab); break;
      case 'detect': await this.detectDatabases(); break;
      case 'add-connection': this.showAddConnectionModal(); break;
      case 'connect': await this.connectToDatabase(el.getAttribute('data-conn-id') || ''); break;
      case 'disconnect': this.disconnectDatabase(); break;
      case 'service-start': await this.serviceControl(el.getAttribute('data-db-type') || '', 'start'); break;
      case 'service-stop': await this.serviceControl(el.getAttribute('data-db-type') || '', 'stop'); break;
      case 'service-restart': await this.serviceControl(el.getAttribute('data-db-type') || '', 'restart'); break;
      case 'execute-sql': await this.executeSql(); break;
      case 'clear-sql': this.clearSqlEditor(); break;
      case 'select-database': await this.selectDatabase(el.getAttribute('data-name') || ''); break;
      case 'select-table': await this.selectTable(el.getAttribute('data-name') || ''); break;
      case 'refresh-tables': await this.refreshTables(); break;
      case 'list-users': await this.listUsers(); break;
      case 'backup': await this.backupDatabase(); break;
      case 'delete-connection': this.deleteConnection(el.getAttribute('data-conn-id') || ''); break;
      case 'save-connection': await this.saveNewConnection(); break;
      case 'close-modal': this.hideAddConnectionModal(); break;
      case 'history-item': this.loadHistoryItem(parseInt(el.getAttribute('data-index') || '0')); break;
    }
  }

  // ==================== Database Detection ====================

  async detectDatabases(): Promise<void> {
    this.synchronizeTargetState();
    const target = activeTargetContext.get();
    if (!target) { window.showNotification?.('当前 SSH 目标尚未完成可信身份确认', 'error'); return; }
    this.loading = true;
    this.updateUI();
    try {
      const detected = await invokeTargetBoundSSH<DatabaseInfo[]>('db_detect');

      // 对每个检测到的数据库尝试本地连接测试
      for (const db of detected) {
        if (!activeTargetContext.matches(target)) throw new Error('数据库检测期间活动目标已变化');
        if (db.status !== 'running') continue;
        try {
          const testSql = db.db_type === 'redis' ? 'PING'
            : db.db_type === 'mongodb' ? 'db.runCommand({ping:1})'
            : 'SELECT 1';
          await invokeTargetBoundSSH('db_execute_sql', {
            dbType: db.db_type, host: '127.0.0.1', port: db.port || 0,
            username: db.db_type === 'redis' ? '' : 'root',
            password: '', database: '', sql: testSql,
          });
          (db as any).connectable = true;
        } catch (error) {
          if (!activeTargetContext.matches(target)) throw error;
          (db as any).connectable = false;
        }
      }
      if (!activeTargetContext.matches(target)) throw new Error('数据库检测期间活动目标已变化');
      this.detectedDatabases = detected;
      window.showNotification?.(`发现 ${this.detectedDatabases.length} 个数据库实例`, 'success');
    } catch (e) {
      this.synchronizeTargetState();
      reportError(e, { module: 'DatabaseManager', action: '检测数据库', silent: true });
      window.showNotification?.(`检测失败: ${e}`, 'error');
    }
    this.loading = false;
    this.updateUI();
  }

  // ==================== Connection Management ====================

  async connectToDatabase(connId: string): Promise<void> {
    this.synchronizeTargetState();
    const conn = this.connections.find(c => c.id === connId);
    if (!conn) return;
    const target = activeTargetContext.get();
    if (!target) { window.showNotification?.('当前 SSH 目标尚未完成可信身份确认', 'error'); return; }

    try {
      // 验证连接（执行一个简单查询）
      const testSql = conn.db_type === 'redis' ? 'PING'
        : conn.db_type === 'mongodb' ? 'db.runCommand({ping:1})'
        : 'SELECT 1';

      await invokeTargetBoundSSH('db_execute_sql', {
        dbType: conn.db_type, host: conn.host, port: conn.port,
        username: conn.username, password: conn.password,
        database: conn.database || '', sql: testSql,
      });
      if (!activeTargetContext.matches(target)) throw new Error('数据库连接期间活动目标已变化');

      conn.isConnected = true;
      this.activeConnection = conn;
      this.saveConnectionsToStorage();

      // 加载数据库列表
      await this.loadDatabases();
      if (!activeTargetContext.matches(target)) throw new Error('数据库连接期间活动目标已变化');

      window.showNotification?.(`已连接 ${conn.name}`, 'success');
    } catch (e) {
      this.synchronizeTargetState();
      window.showNotification?.(`连接失败: ${e}`, 'error');
    }
    this.updateUI();
  }

  disconnectDatabase(): void {
    if (this.activeConnection) {
      this.activeConnection.isConnected = false;
      this.activeConnection = null;
      this.databases = [];
      this.tables = [];
      this.currentDatabase = '';
      this.currentTable = '';
      this.tableData = null;
      this.updateUI();
    }
  }

  // ==================== SQL Execution ====================

  async executeSql(): Promise<void> {
    this.synchronizeTargetState();
    if (!this.activeConnection) {
      window.showNotification?.('请先连接数据库', 'warning');
      return;
    }

    const editor = document.getElementById('db-sql-editor') as HTMLTextAreaElement;
    if (!editor) return;

    // 支持选中执行
    const sql = editor.selectionStart !== editor.selectionEnd
      ? editor.value.substring(editor.selectionStart, editor.selectionEnd).trim()
      : editor.value.trim();

    if (!sql) return;

    const conn = this.activeConnection;
    const isMutation = isPotentiallyMutatingSql(sql, conn.db_type);
    const capturedTarget = isMutation ? activeTargetContext.get() : null;
    const database = this.currentDatabase || conn.database || '';
    if (isMutation) {
      if (!capturedTarget) {
        window.showNotification?.('没有已确认的活动 SSH 目标，已阻止数据库变更', 'error');
        return;
      }
      const confirmed = await showConfirm({
        title: '执行可能修改数据库的语句',
        message: `目标：${targetLabel(capturedTarget)}\n数据库：${database || '(默认)'}\n\n${sql.slice(0, 500)}`,
        confirmText: '确认执行',
        dangerous: true,
        defaultFocus: 'cancel',
      });
      if (!confirmed) return;
      if (!activeTargetContext.matches(capturedTarget)) {
        window.showNotification?.('确认后活动目标已变化，已阻止数据库变更', 'error');
        return;
      }
    }
    this.loading = true;
    this.updateResultsArea('<div class="db-loading">执行中...</div>');

    try {
      const result = await invokeTargetBoundSSH<SqlResult>('db_execute_sql', {
        dbType: conn.db_type, host: conn.host, port: conn.port,
        username: conn.username, password: conn.password,
        database, sql,
      }) as SqlResult;

      this.lastSqlResult = result;
      this.addToHistory(sql, conn.db_type, this.currentDatabase, !result.error, result.row_count);

      if (isMutation && capturedTarget) {
        operationJournal.record({
          source: 'database',
          server: capturedTarget.host,
          target: capturedTarget,
          title: `${conn.db_type} 变更语句（${database || '默认库'}）`,
          command: sql,
          afterValue: `影响行数：${String(result.affected_rows ?? result.row_count)}`,
          output: result.error || `数据库客户端执行完成，耗时 ${result.execution_time_ms}ms`,
          exitCode: result.exit_code,
          timedOut: result.timed_out,
          success: !result.error && result.exit_code === 0 && result.timed_out !== true,
        });
      }

      if (result.error) {
        this.updateResultsArea(`<div class="db-error">${this.escapeHtml(result.error)}</div>`);
      } else {
        this.renderSqlResults(result);
      }
    } catch (e) {
      this.addToHistory(sql, conn.db_type, this.currentDatabase, false);
      this.updateResultsArea(`<div class="db-error">执行失败: ${this.escapeHtml(String(e))}</div>`);
      if (isMutation && capturedTarget) {
        operationJournal.record({
          source: 'database',
          server: capturedTarget.host,
          target: capturedTarget,
          title: `${conn.db_type} 变更语句失败（${database || '默认库'}）`,
          command: sql,
          output: String(e),
          success: false,
        });
      }
      reportError(e, { module: 'DatabaseManager', action: '执行 SQL', silent: true });
    }
    this.loading = false;
  }

  // ==================== Data Browser ====================

  async loadDatabases(): Promise<void> {
    this.synchronizeTargetState();
    if (!this.activeConnection) return;
    const conn = this.activeConnection;
    try {
      this.databases = await invokeTargetBoundSSH<string[]>('db_list_databases', {
        dbType: conn.db_type, host: conn.host, port: conn.port,
        username: conn.username, password: conn.password,
      }) as string[];
      if (this.databases.length > 0 && !this.currentDatabase) {
        this.currentDatabase = this.databases[0];
      }
    } catch (e) {
      this.synchronizeTargetState();
      reportError(e, { module: 'DatabaseManager', action: '加载数据库列表', silent: true });
    }
    this.updateUI();
  }

  async selectDatabase(name: string): Promise<void> {
    this.currentDatabase = name;
    this.currentTable = '';
    this.tableData = null;
    await this.refreshTables();
  }

  async refreshTables(): Promise<void> {
    this.synchronizeTargetState();
    if (!this.activeConnection || !this.currentDatabase) return;
    const conn = this.activeConnection;
    try {
      this.tables = await invokeTargetBoundSSH<TableInfo[]>('db_list_tables', {
        dbType: conn.db_type, host: conn.host, port: conn.port,
        username: conn.username, password: conn.password,
        database: this.currentDatabase,
      }) as TableInfo[];
    } catch (e) {
      this.synchronizeTargetState();
      reportError(e, { module: 'DatabaseManager', action: '加载表列表', silent: true });
    }
    this.updateUI();
  }

  async selectTable(name: string): Promise<void> {
    this.synchronizeTargetState();
    if (!this.activeConnection || !this.currentDatabase) return;
    const target = activeTargetContext.get();
    if (!target) return;
    this.currentTable = name;
    const conn = this.activeConnection;

    try {
      // 加载列信息
      this.columns = await invokeTargetBoundSSH<ColumnInfo[]>('db_list_columns', {
        dbType: conn.db_type, host: conn.host, port: conn.port,
        username: conn.username, password: conn.password,
        database: this.currentDatabase, table: name,
      }) as ColumnInfo[];
      if (!activeTargetContext.matches(target)) throw new Error('读取数据库表期间活动目标已变化');

      // 加载前 100 行数据
      const sql = conn.db_type === 'mongodb'
        ? `db.${name}.find().limit(100).toArray()`
        : `SELECT * FROM ${name} LIMIT 100`;

      this.tableData = await invokeTargetBoundSSH<SqlResult>('db_execute_sql', {
        dbType: conn.db_type, host: conn.host, port: conn.port,
        username: conn.username, password: conn.password,
        database: this.currentDatabase, sql,
      }) as SqlResult;
    } catch (e) {
      this.synchronizeTargetState();
      reportError(e, { module: 'DatabaseManager', action: '加载表数据', silent: true });
    }
    this.updateUI();
  }

  // ==================== User Management ====================

  async listUsers(): Promise<void> {
    if (!this.activeConnection) return;
    const conn = this.activeConnection;
    try {
      this.users = await invokeTargetBoundSSH<DbUser[]>('db_list_users', {
        dbType: conn.db_type, host: conn.host, port: conn.port,
        username: conn.username, password: conn.password,
      }) as DbUser[];
    } catch (e) {
      console.error('加载用户列表失败:', e);
      window.showNotification?.(`加载用户失败: ${e}`, 'error');
    }
    this.updateUI();
  }

  // ==================== Operations ====================

  async serviceControl(dbType: string, action: string): Promise<void> {
    const labels: Record<string, string> = { start: '启动', stop: '停止', restart: '重启' };
    const label = labels[action];
    const capturedTarget = activeTargetContext.get();
    if (!label || !capturedTarget) {
      window.showNotification?.(!label ? '不支持的数据库服务操作' : '没有已确认的活动 SSH 目标', 'error');
      return;
    }

    const confirmed = await showConfirm({
      title: `${label}数据库服务`,
      message: `目标：${targetLabel(capturedTarget)}\n服务：${dbType}\n动作：${label}\n\n服务状态变更可能影响业务连接。`,
      confirmText: `确认${label}`,
      dangerous: true,
      defaultFocus: 'cancel',
    });
    if (!confirmed) return;
    if (!activeTargetContext.matches(capturedTarget)) {
      window.showNotification?.('确认后活动目标已变化，已阻止服务操作', 'error');
      return;
    }

    try {
      const result = await invokeTargetBoundSSH<DbServiceControlResult>('db_service_control', { dbType, action });
      const rollback = dbServiceRollback(dbType, action);
      operationJournal.record({
        source: 'database',
        server: capturedTarget.host,
        target: capturedTarget,
        title: `${label} ${dbType} 数据库服务`,
        command: result.command,
        output: result.output,
        exitCode: result.exit_code,
        timedOut: result.timed_out,
        verifyCommand: result.verify_command,
        verifyOutput: result.verify_output,
        verified: result.verified,
        restoreCommand: result.success ? rollback?.command : undefined,
        restoreVerifyCommand: result.success ? rollback?.verifyCommand : undefined,
        restoreVerifyExpected: result.success ? rollback?.verifyExpected : undefined,
        success: result.success,
      });
      window.showNotification?.(
        result.success
          ? `${dbType} ${label}成功，状态读回：${result.verify_output || '未知'}`
          : `${dbType} ${label}未通过状态验证：${result.verify_output || result.output}`,
        result.success ? 'success' : 'error',
      );
      // 刷新检测
      setTimeout(() => this.detectDatabases(), 1000);
    } catch (e) {
      operationJournal.record({
        source: 'database',
        server: capturedTarget.host,
        target: capturedTarget,
        title: `${label} ${dbType} 数据库服务失败`,
        command: `db_service_control(${dbType}, ${action})`,
        output: String(e),
        success: false,
      });
      reportError(e, { module: 'DatabaseManager', action: `${label}数据库服务` });
    }
  }

  async backupDatabase(): Promise<void> {
    if (!this.activeConnection || !this.currentDatabase) {
      window.showNotification?.('请先选择数据库', 'warning');
      return;
    }
    const conn = this.activeConnection;
    try {
      window.showNotification?.(`正在备份 ${this.currentDatabase}...`, 'info');
      const result = await invokeTargetBoundSSH<string>('db_backup', {
        dbType: conn.db_type, host: conn.host, port: conn.port,
        username: conn.username, password: conn.password,
        database: this.currentDatabase,
      }) as string;
      window.showNotification?.(`备份完成: ${result}`, 'success');
    } catch (e) {
      window.showNotification?.(`备份失败: ${e}`, 'error');
    }
  }

  // ==================== Tab Management ====================

  switchTab(tab: DbTab): void {
    this.currentTab = tab;
    // Update tab buttons
    document.querySelectorAll('.db-tab-btn').forEach(btn => {
      btn.classList.toggle('active', btn.getAttribute('data-tab') === tab);
    });
    // Show/hide panels
    document.querySelectorAll('.db-tab-panel').forEach(panel => {
      (panel as HTMLElement).style.display = panel.id === `db-tab-${tab}` ? '' : 'none';
    });

    // 延迟加载
    if (tab === 'users' && this.users.length === 0 && this.activeConnection) {
      this.listUsers();
    }
    if (tab === 'browser' && this.databases.length === 0 && this.activeConnection) {
      this.loadDatabases();
    }
  }

  // ==================== Connection Storage ====================

  private loadConnectionsFromStorage(): void {
    try {
      const data = localStorage.getItem('lovelyres-db-connections');
      if (data) this.connections = JSON.parse(data);
    } catch { /* ignore */ }
  }

  private saveConnectionsToStorage(): void {
    try {
      // 不存储密码到 localStorage
      const safe = this.connections.map(c => ({ ...c, password: '' }));
      localStorage.setItem('lovelyres-db-connections', JSON.stringify(safe));
    } catch { /* ignore */ }
  }

  // ==================== SQL History ====================

  private loadSqlHistory(): void {
    try {
      const data = localStorage.getItem('lovelyres-sql-history');
      if (data) this.sqlHistory = JSON.parse(data);
    } catch { /* ignore */ }
  }

  private addToHistory(sql: string, dbType: string, database: string, success: boolean, rowCount?: number): void {
    const target = activeTargetContext.get();
    this.sqlHistory.unshift({
      sql, db_type: dbType, database, timestamp: Date.now(), success, row_count: rowCount, target: target || undefined,
    });
    if (this.sqlHistory.length > 50) this.sqlHistory.length = 50;
    try {
      localStorage.setItem('lovelyres-sql-history', JSON.stringify(this.sqlHistory));
    } catch { /* ignore */ }
  }

  private loadHistoryItem(index: number): void {
    const entry = this.currentTargetSqlHistory()[index];
    if (!entry) return;
    const editor = document.getElementById('db-sql-editor') as HTMLTextAreaElement;
    if (editor) editor.value = entry.sql;
  }

  private currentTargetSqlHistory(): SqlHistoryEntry[] {
    const target = activeTargetContext.get();
    return this.sqlHistory.filter(entry => isArtifactForTarget(entry, target));
  }

  // ==================== Modal ====================

  showAddConnectionModal(): void {
    const modal = document.getElementById('db-add-modal');
    if (modal) modal.style.display = 'flex';
  }

  hideAddConnectionModal(): void {
    const modal = document.getElementById('db-add-modal');
    if (modal) modal.style.display = 'none';
  }

  async saveNewConnection(): Promise<void> {
    const name = (document.getElementById('db-add-name') as HTMLInputElement)?.value?.trim();
    const dbType = (document.getElementById('db-add-type') as HTMLSelectElement)?.value;
    const host = (document.getElementById('db-add-host') as HTMLInputElement)?.value?.trim() || '127.0.0.1';
    const port = parseInt((document.getElementById('db-add-port') as HTMLInputElement)?.value) || 3306;
    const username = (document.getElementById('db-add-username') as HTMLInputElement)?.value?.trim() || 'root';
    const password = (document.getElementById('db-add-password') as HTMLInputElement)?.value || '';
    const database = (document.getElementById('db-add-database') as HTMLInputElement)?.value?.trim() || '';

    if (!name) {
      window.showNotification?.('请输入连接名称', 'warning');
      return;
    }

    const conn: DbConnection = {
      id: `db-${Date.now()}`, db_type: dbType, host, port,
      username, password, database, name, isConnected: false,
    };

    this.connections.push(conn);
    this.saveConnectionsToStorage();
    this.hideAddConnectionModal();
    this.updateUI();
    window.showNotification?.(`已添加连接: ${name}`, 'success');
  }

  deleteConnection(connId: string): void {
    this.connections = this.connections.filter(c => c.id !== connId);
    if (this.activeConnection?.id === connId) {
      this.disconnectDatabase();
    }
    this.saveConnectionsToStorage();
    this.updateUI();
  }

  // ==================== UI Helpers ====================

  private updateUI(): void {
    // 由 renderer 负责（通过 getters 获取状态）
    const content = document.getElementById(`db-tab-${this.currentTab}`);
    if (content) {
      // Trigger re-render based on current tab
      const renderer = (window as any).app?.modernUIRenderer?.databaseRenderer;
      if (renderer?.renderTabContent) {
        content.innerHTML = renderer.renderTabContent(this.currentTab, this);
      }
    }
  }

  private updateResultsArea(html: string): void {
    const area = document.getElementById('db-results-area');
    if (area) area.innerHTML = html;
  }

  private renderSqlResults(result: SqlResult): void {
    if (!result.columns.length) {
      this.updateResultsArea(`<div class="db-results-info">执行成功，影响 ${result.affected_rows || 0} 行 (${result.execution_time_ms}ms)</div>`);
      return;
    }

    const html = `
      <table class="db-results-table">
        <thead><tr>${result.columns.map(c => `<th>${this.escapeHtml(c)}</th>`).join('')}</tr></thead>
        <tbody>${result.rows.map(row =>
          `<tr>${row.map(cell => `<td>${this.escapeHtml(cell ?? 'NULL')}</td>`).join('')}</tr>`
        ).join('')}</tbody>
      </table>
      <div class="db-results-info">${result.row_count} 行 · ${result.execution_time_ms}ms</div>
    `;
    this.updateResultsArea(html);
  }

  private clearSqlEditor(): void {
    const editor = document.getElementById('db-sql-editor') as HTMLTextAreaElement;
    if (editor) editor.value = '';
  }

  private escapeHtml(s: string): string {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  // ==================== Getters (for renderer) ====================

  getDetectedDatabases(): DatabaseInfo[] { return this.detectedDatabases; }
  getConnections(): DbConnection[] { return this.connections; }
  getActiveConnection(): DbConnection | null { return this.activeConnection; }
  getCurrentTab(): DbTab { return this.currentTab; }
  getSqlHistory(): SqlHistoryEntry[] { return this.currentTargetSqlHistory(); }
  getLastSqlResult(): SqlResult | null { return this.lastSqlResult; }
  getDatabases(): string[] { return this.databases; }
  getCurrentDatabase(): string { return this.currentDatabase; }
  getTables(): TableInfo[] { return this.tables; }
  getCurrentTable(): string { return this.currentTable; }
  getTableData(): SqlResult | null { return this.tableData; }
  getColumns(): ColumnInfo[] { return this.columns; }
  getUsers(): DbUser[] { return this.users; }
  isLoading(): boolean { return this.loading; }
}

export const databaseManager = new DatabaseManager();
