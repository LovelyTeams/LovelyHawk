import { beforeEach, describe, expect, it } from 'vitest';

import { logger, readSavedLogLevel, LOG_LEVEL_STORAGE_KEY } from './logger';

/**
 * logger 的环形缓冲是正式包里唯一留得下诊断信息的地方
 * （vite.config.ts 对 release 配了 esbuild.drop:['console']），
 * 因此它的记录/过滤/导出行为都值得钉死。
 */
describe('logger 缓冲与级别', () => {
  beforeEach(() => {
    logger.clear();
    logger.setLevel('info');
  });

  it('按 minLevel 过滤：低于阈值的根本不进缓冲', () => {
    const log = logger.module('T');
    log.debug('应被丢弃');
    log.info('应保留');
    log.warn('应保留');
    log.error('应保留');

    const levels = logger.getBuffer().map(e => e.level);
    expect(levels).toEqual(['info', 'warn', 'error']);
  });

  it('调到 debug 后能拿到最详细的记录', () => {
    logger.setLevel('debug');
    logger.module('T').debug('细节');
    expect(logger.getBuffer().map(e => e.level)).toEqual(['debug']);
  });

  it('记录模块名与消息', () => {
    logger.module('SSHConnection').error('连接失败');
    const [entry] = logger.getBuffer();
    expect(entry.module).toBe('SSHConnection');
    expect(entry.message).toBe('连接失败');
    expect(entry.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });
});

describe('exportAsText 的 details 渲染', () => {
  beforeEach(() => {
    logger.clear();
    logger.setLevel('debug');
  });

  it('Error 不再被 JSON.stringify 吞成 {}', () => {
    // 这是改动前的实际症状：导出的日志全是 "xxx失败: | {}"，等于什么都没记
    logger.module('T').error('加载失败', new Error('boom'));
    const text = logger.exportAsText();
    expect(text).toContain('Error: boom');
    expect(text).not.toContain('| {}');
  });

  it('嵌套在对象里的 Error 同样能展开', () => {
    logger.module('T').warn('解析失败', { error: new TypeError('bad json'), data: 'x' });
    const text = logger.exportAsText();
    expect(text).toContain('TypeError: bad json');
    expect(text).toContain('"data":"x"');
  });

  it('普通对象照常序列化', () => {
    logger.module('T').info('连接', { host: '10.0.0.1', port: 22 });
    expect(logger.exportAsText()).toContain('{"host":"10.0.0.1","port":22}');
  });

  it('没有 details 时不留空的分隔符', () => {
    logger.module('T').info('无附加信息');
    expect(logger.exportAsText()).toBe(
      logger.exportAsText().replace(' | ', ''),
    );
  });

  it('循环引用不会抛错', () => {
    const a: any = { name: 'a' };
    a.self = a;
    logger.module('T').error('循环', a);
    expect(() => logger.exportAsText()).not.toThrow();
    expect(logger.exportAsText()).toContain('无法序列化');
  });
});

describe('记录级别持久化', () => {
  // 项目未装 jsdom（测试跑在 node 环境），这里给个最小 localStorage 替身，
  // 免得为一个纯函数引入整套 DOM 环境。
  const store = new Map<string, string>();
  beforeEach(() => {
    store.clear();
    (globalThis as any).localStorage = {
      getItem: (k: string) => (store.has(k) ? store.get(k)! : null),
      setItem: (k: string, v: string) => void store.set(k, v),
      removeItem: (k: string) => void store.delete(k),
    };
  });

  it('读不到或非法值时回落到 info', () => {
    expect(readSavedLogLevel()).toBe('info');

    localStorage.setItem(LOG_LEVEL_STORAGE_KEY, 'not-a-level');
    expect(readSavedLogLevel()).toBe('info');
  });

  it('读回合法值', () => {
    for (const lv of ['debug', 'info', 'warn', 'error'] as const) {
      localStorage.setItem(LOG_LEVEL_STORAGE_KEY, lv);
      expect(readSavedLogLevel()).toBe(lv);
    }
  });

  it('localStorage 不可用时不抛错（Tauri webview 隐私模式 / node 环境）', () => {
    delete (globalThis as any).localStorage;
    expect(() => readSavedLogLevel()).not.toThrow();
    expect(readSavedLogLevel()).toBe('info');
  });
});
