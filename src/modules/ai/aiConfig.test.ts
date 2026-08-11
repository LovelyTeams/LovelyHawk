/**
 * aiConfig 单测（node 环境）
 *
 * invoke 与 localStorage 全部 stub；每个用例通过 vi.resetModules + 动态 import
 * 拿到全新的模块实例，隔离模块级的 5 分钟缓存与一次性迁移 Promise。
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';

const invokeMock = vi.fn();
vi.mock('@tauri-apps/api/core', () => ({
  invoke: (...args: unknown[]) => invokeMock(...args),
}));

function stubLocalStorage(initial: Record<string, string> = {}) {
  const store = new Map<string, string>(Object.entries(initial));
  vi.stubGlobal('localStorage', {
    getItem: (k: string) => (store.has(k) ? store.get(k)! : null),
    setItem: (k: string, v: string) => { store.set(k, String(v)); },
    removeItem: (k: string) => { store.delete(k); },
    clear: () => store.clear(),
  });
  return store;
}

/** 以可变 settingsText 模拟 settings 文件持久化（write 会更新下一次 read 的内容） */
function stubSettingsFile(initial: any) {
  const state = { text: JSON.stringify(initial) };
  invokeMock.mockImplementation(async (cmd: string, args?: any) => {
    switch (cmd) {
      case 'read_settings_file':
        return state.text;
      case 'write_settings_file':
        state.text = args.content;
        return undefined;
      case 'encrypt_ai_key':
        return `enc:v1:${btoa(args.plaintext)}`;
      default:
        throw new Error(`未 mock 的命令: ${cmd}`);
    }
  });
  return state;
}

async function freshModule() {
  vi.resetModules();
  return await import('./aiConfig');
}

beforeEach(() => {
  invokeMock.mockReset();
  vi.unstubAllGlobals();
});

describe('ensureCompletionsPath', () => {
  it('已是完整端点时原样返回', async () => {
    const { ensureCompletionsPath } = await freshModule();
    expect(ensureCompletionsPath('https://api.openai.com/v1/chat/completions', false))
      .toBe('https://api.openai.com/v1/chat/completions');
    expect(ensureCompletionsPath('https://api.anthropic.com/v1/messages', true))
      .toBe('https://api.anthropic.com/v1/messages');
  });

  it('/v1 结尾补全对应端点', async () => {
    const { ensureCompletionsPath } = await freshModule();
    expect(ensureCompletionsPath('https://api.openai.com/v1', false))
      .toBe('https://api.openai.com/v1/chat/completions');
    expect(ensureCompletionsPath('https://api.anthropic.com/v1', true))
      .toBe('https://api.anthropic.com/v1/messages');
  });

  it('纯域名按提供商类型补全', async () => {
    const { ensureCompletionsPath } = await freshModule();
    expect(ensureCompletionsPath('https://api.openai.com', false))
      .toBe('https://api.openai.com/v1/chat/completions');
    expect(ensureCompletionsPath('https://api.anthropic.com', true))
      .toBe('https://api.anthropic.com/v1/messages');
  });

  it('已含 /v1/ 或 /api/ 路径时不做改动', async () => {
    const { ensureCompletionsPath } = await freshModule();
    expect(ensureCompletionsPath('https://proxy.internal/api/v2', false))
      .toBe('https://proxy.internal/api/v2');
    expect(ensureCompletionsPath('https://proxy.internal/v1beta', false))
      .toBe('https://proxy.internal/v1beta');
  });

  it('末尾多余斜杠先裁剪', async () => {
    const { ensureCompletionsPath } = await freshModule();
    expect(ensureCompletionsPath('https://api.openai.com/v1/', false))
      .toBe('https://api.openai.com/v1/chat/completions');
  });
});

describe('loadAIConfig 解析与默认值', () => {
  it('openai 缺省字段补默认值', async () => {
    stubLocalStorage();
    stubSettingsFile({ ai: { currentProvider: 'openai', providers: { openai: { name: 'OpenAI', apiKey: 'enc:v1:x' } } } });
    const { loadAIConfig } = await freshModule();

    const config = await loadAIConfig();
    expect(config.providerKey).toBe('openai');
    expect(config.providerType).toBe('openai');
    expect(config.model).toBe('gpt-4o-mini');
    expect(config.baseUrl).toBe('https://api.openai.com/v1/chat/completions');
    expect(config.apiKey).toBe('enc:v1:x');
    expect(config.isClaude).toBe(false);
    expect(config.apiKeyHeader).toBe('authorization-bearer');
  });

  it('claude 走 /v1/messages 与 x-api-key', async () => {
    stubLocalStorage();
    stubSettingsFile({ ai: { currentProvider: 'claude', providers: { claude: { name: 'Claude', apiKey: 'k' } } } });
    const { loadAIConfig } = await freshModule();

    const config = await loadAIConfig();
    expect(config.model).toBe('claude-3-5-sonnet-20241022');
    expect(config.baseUrl).toBe('https://api.anthropic.com/v1/messages');
    expect(config.isClaude).toBe(true);
    expect(config.apiKeyHeader).toBe('x-api-key');
  });

  it('deepseek 默认模型与端点', async () => {
    stubLocalStorage();
    stubSettingsFile({ ai: { currentProvider: 'deepseek', providers: { deepseek: { apiKey: 'k' } } } });
    const { loadAIConfig } = await freshModule();

    const config = await loadAIConfig();
    expect(config.model).toBe('deepseek-chat');
    expect(config.baseUrl).toBe('https://api.deepseek.com/v1/chat/completions');
  });

  it('currentProvider 指向的条目缺失时报错', async () => {
    stubLocalStorage();
    stubSettingsFile({ ai: { currentProvider: 'ghost', providers: {} } });
    const { loadAIConfig } = await freshModule();

    await expect(loadAIConfig()).rejects.toThrow('AI提供商配置不存在');
  });
});

describe('loadAIConfig 无 Key 规则', () => {
  it('openai 无 apiKey 抛出配置提示', async () => {
    stubLocalStorage();
    stubSettingsFile({ ai: { currentProvider: 'openai', providers: { openai: { apiKey: '' } } } });
    const { loadAIConfig } = await freshModule();

    await expect(loadAIConfig()).rejects.toThrow('请在设置中配置AI API Key');
  });

  it('ollama 系允许空 Key', async () => {
    stubLocalStorage();
    stubSettingsFile({ ai: { currentProvider: 'ollama', providers: { ollama: { name: 'Ollama', apiKey: '', baseUrl: 'http://localhost:11434/api', model: 'llama2' } } } });
    const { loadAIConfig } = await freshModule();

    const config = await loadAIConfig();
    expect(config.providerType).toBe('ollama');
    expect(config.apiKey).toBe('');
  });

  it('custom 提供商指向内网地址时允许空 Key', async () => {
    stubLocalStorage();
    stubSettingsFile({ ai: { currentProvider: 'mybox', providers: { mybox: { name: '内网网关', apiKey: '', baseUrl: 'http://192.168.1.10:8000/v1', model: 'qwen' } } } });
    const { loadAIConfig } = await freshModule();

    const config = await loadAIConfig();
    expect(config.providerType).toBe('custom');
    expect(config.baseUrl).toBe('http://192.168.1.10:8000/v1/chat/completions');
  });

  it('custom 提供商指向公网地址且无 Key 时报错', async () => {
    stubLocalStorage();
    stubSettingsFile({ ai: { currentProvider: 'mybox', providers: { mybox: { name: '网关', apiKey: '', baseUrl: 'https://api.example.com/v1' } } } });
    const { loadAIConfig } = await freshModule();

    await expect(loadAIConfig()).rejects.toThrow('请在设置中配置AI API Key');
  });
});

describe('localStorage 旧配置一次性迁移', () => {
  it('settings 中无同 Key provider 时加密写入并删除 localStorage', async () => {
    const store = stubLocalStorage({
      'lovelyres-ai-config': JSON.stringify({ provider: 'deepseek', apiKey: 'plain-key', model: 'deepseek-chat' }),
    });
    const state = stubSettingsFile({});
    const { loadAIConfig } = await freshModule();

    // 迁移后 settings 已有 deepseek provider，load 应成功
    const config = await loadAIConfig();

    const written = JSON.parse(state.text);
    expect(written.ai.currentProvider).toBe('deepseek');
    expect(written.ai.providers.deepseek.apiKey).toBe(`enc:v1:${btoa('plain-key')}`);
    expect(written.ai.providers.deepseek.model).toBe('deepseek-chat');
    expect(store.has('lovelyres-ai-config')).toBe(false);
    expect(config.providerKey).toBe('deepseek');
    expect(config.apiKey).toBe(`enc:v1:${btoa('plain-key')}`);
  });

  it('settings 已有相同 apiKey 的 provider 时跳过写入，仅删除 localStorage', async () => {
    const store = stubLocalStorage({
      'lovelyres-ai-config': JSON.stringify({ provider: 'deepseek', apiKey: 'plain-key' }),
    });
    const state = stubSettingsFile({
      ai: { currentProvider: 'deepseek', providers: { deepseek: { apiKey: 'plain-key', baseUrl: 'https://api.deepseek.com/v1' } } },
    });
    const { loadAIConfig } = await freshModule();

    const config = await loadAIConfig();
    expect(config.providerKey).toBe('deepseek');
    // 没有发生写回（内容保持原样）
    expect(JSON.parse(state.text).ai.providers.deepseek.apiKey).toBe('plain-key');
    expect(store.has('lovelyres-ai-config')).toBe(false);
  });

  it('迁移失败时保留 localStorage 以便下次重试，且不影响正常加载', async () => {
    const store = stubLocalStorage({
      'lovelyres-ai-config': JSON.stringify({ provider: 'openai', apiKey: 'plain-key' }),
    });
    stubSettingsFile({ ai: { currentProvider: 'openai', providers: { openai: { apiKey: 'k', baseUrl: 'https://api.openai.com/v1' } } } });
    // encrypt_ai_key 失败
    const baseImpl = invokeMock.getMockImplementation()!;
    invokeMock.mockImplementation(async (cmd: string, args?: any) => {
      if (cmd === 'encrypt_ai_key') throw new Error('加密服务不可用');
      return baseImpl(cmd, args);
    });
    const { loadAIConfig } = await freshModule();

    const config = await loadAIConfig();
    expect(config.apiKey).toBe('k');
    expect(store.has('lovelyres-ai-config')).toBe(true);
  });
});

describe('5 分钟缓存', () => {
  it('第二次加载命中缓存，不再读后端；invalidate 后重新读取', async () => {
    stubLocalStorage();
    stubSettingsFile({ ai: { currentProvider: 'openai', providers: { openai: { apiKey: 'k' } } } });
    const { loadAIConfig, invalidateAIConfigCache } = await freshModule();

    await loadAIConfig();
    await loadAIConfig();
    const readsAfterWarm = invokeMock.mock.calls.filter(([cmd]) => cmd === 'read_settings_file').length;
    expect(readsAfterWarm).toBe(1);

    invalidateAIConfigCache();
    await loadAIConfig();
    const readsAfterInvalidate = invokeMock.mock.calls.filter(([cmd]) => cmd === 'read_settings_file').length;
    expect(readsAfterInvalidate).toBe(2);
  });
});
