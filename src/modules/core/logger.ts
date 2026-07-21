/**
 * 结构化日志记录器
 * 替代散落在各处的 console.log / console.error
 */

type LogLevel = 'debug' | 'info' | 'warn' | 'error';

interface LogEntry {
  timestamp: string;
  level: LogLevel;
  module: string;
  message: string;
  details?: any;
}

const LOG_LEVEL_PRIORITY: Record<LogLevel, number> = {
  debug: 0, info: 1, warn: 2, error: 3,
};

const LOG_STYLES: Record<LogLevel, string> = {
  debug: 'color: #6b7280',
  info:  'color: #3b82f6',
  warn:  'color: #f59e0b; font-weight: 600',
  error: 'color: #ef4444; font-weight: 600',
};

/**
 * 把 details 渲染成可读文本。
 *
 * 直接 JSON.stringify 会把 Error 序列化成 "{}"（message/stack 都是不可枚举属性），
 * 而 details 里最常见的恰恰就是 catch 到的 Error——导出的日志会变成一串
 * "加载失败: | {}"，等于什么都没记。这里对 Error 特殊处理，并对嵌套的 Error 也生效。
 */
function formatDetails(details: unknown): string {
  if (details === undefined || details === null) return '';

  const describeError = (e: Error) => {
    const first = (e.stack || '').split('\n').slice(0, 3).join(' | ');
    return `${e.name}: ${e.message}${first ? ` @ ${first}` : ''}`;
  };

  if (details instanceof Error) return ' | ' + describeError(details);

  try {
    const json = JSON.stringify(details, (_k, v) =>
      v instanceof Error ? describeError(v) : v
    );
    // 对象里全是不可枚举属性时 stringify 出 "{}"，退回 String() 至少还有类型信息
    if (json === '{}' && Object.keys(details as object).length === 0) {
      const s = String(details);
      return s === '[object Object]' ? '' : ' | ' + s;
    }
    return json === undefined ? '' : ' | ' + json;
  } catch {
    return ' | [无法序列化的 details]';
  }
}

class Logger {
  private minLevel: LogLevel = 'info';
  private buffer: LogEntry[] = [];
  private readonly MAX_BUFFER = 500;

  /** 设置最低日志级别 */
  setLevel(level: LogLevel): void {
    this.minLevel = level;
  }

  /** 创建模块级别的子 Logger */
  module(name: string): ModuleLogger {
    return new ModuleLogger(name, this);
  }

  /** 通用日志方法 */
  log(level: LogLevel, module: string, message: string, details?: any): void {
    if (LOG_LEVEL_PRIORITY[level] < LOG_LEVEL_PRIORITY[this.minLevel]) return;

    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level, module, message, details,
    };

    this.buffer.push(entry);
    if (this.buffer.length > this.MAX_BUFFER) {
      this.buffer.shift();
    }

    // 输出到控制台
    const style = LOG_STYLES[level];
    const tag = `[${module}]`;
    if (details !== undefined) {
      console.log(`%c${tag} ${message}`, style, details);
    } else {
      console.log(`%c${tag} ${message}`, style);
    }
  }

  /** 获取日志缓冲区（用于导出或 UI 展示） */
  getBuffer(): LogEntry[] {
    return [...this.buffer];
  }

  /** 导出日志为文本 */
  exportAsText(): string {
    return this.buffer.map(e =>
      `[${e.timestamp}] [${e.level.toUpperCase()}] [${e.module}] ${e.message}${formatDetails(e.details)}`
    ).join('\n');
  }

  /** 清空缓冲区 */
  clear(): void {
    this.buffer = [];
  }
}

class ModuleLogger {
  constructor(
    private name: string,
    private parent: Logger,
  ) {}

  debug(msg: string, details?: any): void { this.parent.log('debug', this.name, msg, details); }
  info(msg: string, details?: any): void  { this.parent.log('info',  this.name, msg, details); }
  warn(msg: string, details?: any): void  { this.parent.log('warn',  this.name, msg, details); }
  error(msg: string, details?: any): void { this.parent.log('error', this.name, msg, details); }
}

export const logger = new Logger();

export type LogLevelName = LogLevel;

/**
 * 记录级别的持久化。
 *
 * 默认 minLevel 是 info，意味着所有 log.debug 会被直接丢弃。排查问题时需要
 * 临时调到 debug，而且这个选择必须跨重启保留——赛场上重现一个问题往往要重启一次，
 * 若每次启动都退回 info，启动路径上最关键的那段 debug 日志就永远抓不到。
 */
export const LOG_LEVEL_STORAGE_KEY = 'lovelyres-log-level';

const VALID_LEVELS: LogLevel[] = ['debug', 'info', 'warn', 'error'];

export function readSavedLogLevel(): LogLevel {
  try {
    const v = localStorage.getItem(LOG_LEVEL_STORAGE_KEY) as LogLevel | null;
    return v && VALID_LEVELS.includes(v) ? v : 'info';
  } catch {
    return 'info';
  }
}

/** 在应用启动最早期调用，确保启动路径上的日志按用户选定的级别记录 */
export function applySavedLogLevel(): void {
  logger.setLevel(readSavedLogLevel());
}

// 便捷导出：按模块使用
// 示例: import { logger } from '../core/logger';
//       const log = logger.module('SSHManager');
//       log.info('连接成功', { host, port });
//       log.error('连接失败', error);
