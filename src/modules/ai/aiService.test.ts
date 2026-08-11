/**
 * aiService 流式层单测（node 环境）
 *
 * 覆盖 stream_id 隔离的关键行为：外来 stream_id 的事件被忽略、
 * 本流事件驱动完成、cancel 通知后端并拒绝 pending Promise、
 * 前端不再把 Key 放进 headers（改传 apiKey/apiKeyHeader）。
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';

const h = vi.hoisted(() => {
  const listeners = new Map<string, Set<(event: { payload: any }) => void>>();
  const invokeMock = vi.fn();
  return { listeners, invokeMock };
});

vi.mock('@tauri-apps/api/core', () => ({ invoke: h.invokeMock }));
vi.mock('@tauri-apps/api/event', () => ({
  listen: async (name: string, handler: (event: { payload: any }) => void) => {
    if (!h.listeners.has(name)) h.listeners.set(name, new Set());
    h.listeners.get(name)!.add(handler);
    return () => { h.listeners.get(name)!.delete(handler); };
  },
}));

import { aiService } from './aiService';

function emit(name: string, payload: any): void {
  h.listeners.get(name)?.forEach((fn) => fn({ payload }));
}

const SETTINGS = JSON.stringify({
  ai: {
    currentProvider: 'openai',
    providers: {
      openai: { name: 'OpenAI', apiKey: 'enc:v1:secret', baseUrl: 'https://api.openai.com/v1', model: 'gpt-4o-mini' },
    },
  },
});

function stubLocalStorage() {
  const store = new Map<string, string>();
  vi.stubGlobal('localStorage', {
    getItem: (k: string) => (store.has(k) ? store.get(k)! : null),
    setItem: (k: string, v: string) => { store.set(k, String(v)); },
    removeItem: (k: string) => { store.delete(k); },
    clear: () => store.clear(),
  });
}

beforeEach(() => {
  h.invokeMock.mockReset();
  h.listeners.clear();
  vi.unstubAllGlobals();
  stubLocalStorage();
  h.invokeMock.mockImplementation(async (cmd: string) => {
    if (cmd === 'read_settings_file') return SETTINGS;
    return undefined;
  });
});

describe('streamOpenAICompatible', () => {
  it('按 stream_id 过滤事件：外来事件忽略，本流 chunk 聚合后 resolve', async () => {
    const chunks: string[] = [];
    const resultPromise = aiService.streamOpenAICompatible('分析这个', (t) => chunks.push(t));

    // 等监听注册 + ai_proxy_stream 调用发出
    await vi.waitFor(() => {
      expect(h.invokeMock.mock.calls.some(([cmd]) => cmd === 'ai_proxy_stream')).toBe(true);
    });
    const streamArgs = h.invokeMock.mock.calls.find(([cmd]) => cmd === 'ai_proxy_stream')![1] as any;
    const streamId: string = streamArgs.streamId;
    expect(typeof streamId).toBe('string');
    expect(streamId.length).toBeGreaterThan(0);

    // 前端不再携带认证头，Key 以 apiKey/apiKeyHeader 形式交给后端
    expect(streamArgs.headers).toEqual({ 'Content-Type': 'application/json' });
    expect(streamArgs.apiKey).toBe('enc:v1:secret');
    expect(streamArgs.apiKeyHeader).toBe('authorization-bearer');

    // 外来 stream_id 的事件必须被忽略
    emit('ai_stream_chunk', { stream_id: 'other-stream', chunk: 'data: {"choices":[{"delta":{"content":"外来"}}]}\n\n' });
    emit('ai_stream_done', { stream_id: 'other-stream' });
    emit('ai_stream_error', { stream_id: 'other-stream', error: '外来错误' });

    emit('ai_stream_chunk', { stream_id: streamId, chunk: 'data: {"choices":[{"delta":{"content":"你好"}}]}\n\n' });
    emit('ai_stream_chunk', { stream_id: streamId, chunk: 'data: [DONE]\n\n' });
    emit('ai_stream_done', { stream_id: streamId });

    const { text, cancel } = await resultPromise;
    expect(text).toBe('你好');
    expect(chunks.join('')).toBe('你好');
    expect(typeof cancel).toBe('function');

    // done 之后监听已注销
    expect(h.listeners.get('ai_stream_chunk')?.size ?? 0).toBe(0);
  });

  it('本流 error 事件使 Promise 拒绝', async () => {
    const resultPromise = aiService.streamOpenAICompatible('分析这个');
    await vi.waitFor(() => {
      expect(h.invokeMock.mock.calls.some(([cmd]) => cmd === 'ai_proxy_stream')).toBe(true);
    });
    const { streamId } = h.invokeMock.mock.calls.find(([cmd]) => cmd === 'ai_proxy_stream')![1] as any;

    emit('ai_stream_error', { stream_id: streamId, error: 'HTTP 500' });
    await expect(resultPromise).rejects.toThrow('HTTP 500');
  });

  it('cancel 通知后端取消并以 AbortError 结束 pending 流', async () => {
    let cancelFn: (() => void) | undefined;
    const resultPromise = aiService.streamOpenAICompatible('分析这个', undefined, {
      onStart: (cancel) => { cancelFn = cancel; },
    });

    await vi.waitFor(() => expect(cancelFn).toBeDefined());
    cancelFn!();

    await expect(resultPromise).rejects.toMatchObject({ name: 'AbortError' });
    expect(h.invokeMock.mock.calls.some(
      ([cmd, args]) => cmd === 'ai_proxy_stream_cancel' && typeof (args as any).streamId === 'string',
    )).toBe(true);
    expect(h.listeners.get('ai_stream_chunk')?.size ?? 0).toBe(0);
  });
});

describe('testConnection（无状态）', () => {
  it('用显式配置发最小请求，不读已保存配置', async () => {
    h.invokeMock.mockImplementation(async (cmd: string) => {
      if (cmd === 'ai_proxy_request') return { ok: true, status: 200, body: '{"choices":[{"message":{"content":"连接成功"}}]}' };
      throw new Error(`不应调用 ${cmd}：testConnection 必须无状态`);
    });

    const msg = await aiService.testConnection({
      providerType: 'deepseek',
      apiKey: 'enc:v1:k',
      baseUrl: 'https://api.deepseek.com/v1',
      model: 'deepseek-chat',
    });
    expect(msg).toContain('连接成功');

    const args = h.invokeMock.mock.calls.find(([cmd]) => cmd === 'ai_proxy_request')![1] as any;
    expect(args.url).toBe('https://api.deepseek.com/v1/chat/completions');
    expect(args.apiKey).toBe('enc:v1:k');
    expect(args.apiKeyHeader).toBe('authorization-bearer');
    expect(args.headers).toEqual({ 'Content-Type': 'application/json' });
  });

  it('claude 类型使用 /v1/messages 与 x-api-key', async () => {
    h.invokeMock.mockImplementation(async (cmd: string) => {
      if (cmd === 'ai_proxy_request') return { ok: true, status: 200, body: '{}' };
      throw new Error(`不应调用 ${cmd}`);
    });

    await aiService.testConnection({ providerType: 'claude', apiKey: 'k' });
    const args = h.invokeMock.mock.calls.find(([cmd]) => cmd === 'ai_proxy_request')![1] as any;
    expect(args.url).toBe('https://api.anthropic.com/v1/messages');
    expect(args.apiKeyHeader).toBe('x-api-key');
  });

  it('后端报错时抛出（非 ok 状态）', async () => {
    h.invokeMock.mockImplementation(async (cmd: string) => {
      if (cmd === 'ai_proxy_request') return { ok: false, status: 401, body: 'unauthorized' };
      throw new Error(`不应调用 ${cmd}`);
    });

    await expect(aiService.testConnection({ providerType: 'openai', apiKey: 'bad' }))
      .rejects.toThrow('401');
  });
});
