/**
 * AI 配置唯一来源
 *
 * 历史上 AI 配置有两个来源（aiService 的 localStorage 与后端 settings 文件），
 * URL 补全也有两份行为不一致的实现。本模块收口：
 *  - 配置一律读后端 settings 文件（settings.ai.currentProvider / providers）
 *  - URL 补全只有 ensureCompletionsPath 一份
 *  - localStorage 旧配置（lovelyres-ai-config）在首次加载时一次性迁移后删除
 *
 * apiKey 可能是 `enc:v1:` 密文（AES-256-GCM，密钥在后端 app_data_dir），
 * 前端绝不解密，原样传给 ai_proxy_* 命令由后端解密并注入认证头。
 */

import { invoke } from '@tauri-apps/api/core';

import { logger } from '../core/logger';
/** 正式包 drop 掉 console，诊断信息只有进 logger 才留得下来（状态栏「日志」按钮可导出） */
const log = logger.module('AIConfig');

/** 后端注入认证头的方式 */
export type AIKeyHeader = 'authorization-bearer' | 'x-api-key';

export interface ProviderPreset {
  name: string;
  defaultModel: string;
  defaultBaseUrl: string;
}

/**
 * 内置提供商预设（设置页与配置解析共用，避免两处默认值漂移）。
 * 注意默认 baseUrl 是不带 /chat/completions 的“基地址”，最终端点经 ensureCompletionsPath 补全。
 */
export const PROVIDER_PRESETS: Record<string, ProviderPreset> = {
  openai:   { name: 'OpenAI',  defaultModel: 'gpt-4o-mini',                defaultBaseUrl: 'https://api.openai.com/v1' },
  deepseek: { name: 'DeepSeek', defaultModel: 'deepseek-chat',              defaultBaseUrl: 'https://api.deepseek.com/v1' },
  claude:   { name: 'Claude',  defaultModel: 'claude-3-5-sonnet-20241022', defaultBaseUrl: 'https://api.anthropic.com' },
  ollama:   { name: 'Ollama',  defaultModel: 'llama2',                      defaultBaseUrl: 'http://localhost:11434/api' },
  custom:   { name: '自定义',  defaultModel: 'gpt-4o-mini',                defaultBaseUrl: '' },
};

/** 解析后的 AI 配置（可直接用于发请求） */
export interface ResolvedAIConfig {
  /** settings.ai.providers 里的键，如 openai / deepseek / 用户自定义键 */
  providerKey: string;
  /** 归一化类型：openai / deepseek / claude / ollama / custom */
  providerType: string;
  /** 经 ensureCompletionsPath 补全后的完整端点 URL */
  baseUrl: string;
  /** 原样透传的 apiKey（可能是 enc:v1: 密文，前端不解密） */
  apiKey: string;
  model: string;
  /** 是否 Claude/Anthropic 系（决定 /messages 端点与 x-api-key 头） */
  isClaude: boolean;
  apiKeyHeader: AIKeyHeader;
}

/** key/type/name 任一含 claude 或 anthropic 即视为 Claude 系 */
export function isClaudeProvider(key: string, type: string, name: string): boolean {
  return /claude|anthropic/i.test(`${key} ${type} ${name}`);
}

/** key/type/name 任一含 ollama 即视为 Ollama 系（本地无 Key 可用） */
export function isOllamaProvider(key: string, type: string, name: string): boolean {
  return /ollama/i.test(`${key} ${type} ${name}`);
}

/** 路径部分是否已含 /v1 或 /api 片段（只看 path，避免 api.openai.com 这种主机名误判） */
function hasVersionedOrApiPath(trimmedUrl: string): boolean {
  let path = '';
  try {
    path = new URL(trimmedUrl).pathname;
  } catch {
    // 非法 URL 时退化为去掉 scheme+host 后判断
    const m = trimmedUrl.match(/^[a-z][a-z0-9+.-]*:\/\/[^/]+(\/.*)?$/i);
    path = m?.[1] ?? (trimmedUrl.includes('://') ? '' : trimmedUrl);
  }
  return path.includes('/v1') || path.includes('/api');
}

/**
 * 唯一的 URL 补全实现（合并原 aiService 与 SSHTerminal 两份）：
 *  - 已是完整端点（/chat/completions 或 /messages 结尾）→ 原样返回
 *  - Claude 系 → 补 /v1/messages
 *  - 路径已含 /v1 或 /api 片段 → 原样返回（用户自己负责路径正确性）
 *  - 其余（纯域名、/v1 结尾）→ 补 /v1/chat/completions
 */
export function ensureCompletionsPath(baseUrl: string, isClaude: boolean): string {
  const trimmed = baseUrl.replace(/\/+$/, '');
  if (trimmed.endsWith('/chat/completions') || trimmed.endsWith('/messages')) {
    return trimmed;
  }
  if (isClaude) {
    if (trimmed.endsWith('/v1')) return `${trimmed}/messages`;
    if (!hasVersionedOrApiPath(trimmed)) {
      return `${trimmed}/v1/messages`;
    }
    return trimmed;
  }
  if (trimmed.endsWith('/v1')) {
    return `${trimmed}/chat/completions`;
  }
  if (!hasVersionedOrApiPath(trimmed)) {
    return `${trimmed}/v1/chat/completions`;
  }
  return trimmed;
}

/** baseUrl 主机是否为本机/内网（custom 提供商此时允许空 apiKey） */
function isLocalOrPrivateHost(baseUrl: string): boolean {
  let host = '';
  try {
    host = new URL(baseUrl).hostname.toLowerCase();
  } catch {
    // new URL 失败时退化为主机部分正则，尽力判断
    const m = baseUrl.match(/^[a-z][a-z0-9+.-]*:\/\/([^/:]+)/i);
    host = (m?.[1] ?? '').toLowerCase();
  }
  if (!host) return false;
  if (host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '[::1]') return true;
  // RFC1918
  if (/^10\./.test(host)) return true;
  if (/^192\.168\./.test(host)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(host)) return true;
  return false;
}

/** 归一化提供商类型：显式 type 字段优先，其次预设键，再次按名称嗅探，最后 custom */
function resolveProviderType(providerKey: string, provider: any): string {
  const explicit = String(provider?.type ?? '').toLowerCase();
  if (explicit) return explicit;
  const key = providerKey.toLowerCase();
  if (key in PROVIDER_PRESETS) return key;
  if (isClaudeProvider(providerKey, '', String(provider?.name ?? ''))) return 'claude';
  if (isOllamaProvider(providerKey, '', String(provider?.name ?? ''))) return 'ollama';
  return 'custom';
}

function defaultModelFor(providerKey: string, providerType: string): string {
  return PROVIDER_PRESETS[providerKey]?.defaultModel
    ?? PROVIDER_PRESETS[providerType]?.defaultModel
    ?? 'gpt-4o-mini';
}

function defaultBaseUrlFor(providerKey: string, providerType: string): string {
  return PROVIDER_PRESETS[providerKey]?.defaultBaseUrl
    ?? PROVIDER_PRESETS[providerType]?.defaultBaseUrl
    ?? '';
}

// ==================== 5 分钟内存缓存 ====================

const CACHE_TTL_MS = 5 * 60 * 1000;
/** 键为 providerKey；'__current__' 表示“跟随 currentProvider”的默认解析 */
const cache = new Map<string, { config: ResolvedAIConfig; at: number }>();

/** 设置保存后调用，强制下次 loadAIConfig 重新读后端 */
export function invalidateAIConfigCache(): void {
  cache.clear();
}

// ==================== localStorage 旧配置一次性迁移 ====================

const LEGACY_STORAGE_KEY = 'lovelyres-ai-config';
let migrationPromise: Promise<void> | null = null;

function migrateLegacyConfigOnce(): Promise<void> {
  if (!migrationPromise) {
    migrationPromise = doMigrateLegacyConfig();
  }
  return migrationPromise;
}

/**
 * 旧版 aiService 把 { provider, apiKey, baseUrl?, model? } 存在 localStorage。
 * 若 settings 里还没有任何 provider 持有同一个 apiKey，则加密后写入 settings，
 * 然后删除 localStorage 键。迁移失败时保留 localStorage 原值，下次启动重试。
 */
async function doMigrateLegacyConfig(): Promise<void> {
  if (typeof localStorage === 'undefined') return;

  let raw: string | null = null;
  try {
    raw = localStorage.getItem(LEGACY_STORAGE_KEY);
  } catch {
    return; // localStorage 不可读时放弃迁移（隐私模式等）
  }
  if (!raw) return;

  let legacy: { provider?: string; apiKey?: string; baseUrl?: string; model?: string };
  try {
    legacy = JSON.parse(raw);
  } catch (e) {
    log.warn('旧版 AI 配置 JSON 损坏，已清除', e);
    try { localStorage.removeItem(LEGACY_STORAGE_KEY); } catch { /* intentional: 清除失败无关紧要，下次启动还会读到同样的坏值 */ }
    return;
  }

  try {
    if (legacy && legacy.provider && legacy.apiKey) {
      const content = await invoke<string>('read_settings_file');
      const settings: any = content ? JSON.parse(content) : {};
      settings.ai ??= { currentProvider: '', providers: {} };
      settings.ai.providers ??= {};

      const alreadyExists = Object.values(settings.ai.providers as Record<string, any>)
        .some((p) => p && p.apiKey && p.apiKey === legacy.apiKey);

      if (!alreadyExists) {
        const encryptedKey = await invoke<string>('encrypt_ai_key', { plaintext: legacy.apiKey });
        const key = String(legacy.provider);
        const preset = PROVIDER_PRESETS[key];
        const existing = settings.ai.providers[key] ?? {};
        settings.ai.providers[key] = {
          ...existing,
          name: existing.name || preset?.name || key,
          apiKey: encryptedKey,
          baseUrl: legacy.baseUrl || existing.baseUrl || preset?.defaultBaseUrl || '',
          model: legacy.model || existing.model || preset?.defaultModel || 'gpt-4o-mini',
        };
        if (!settings.ai.currentProvider) {
          settings.ai.currentProvider = key;
        }
        await invoke('write_settings_file', { content: JSON.stringify(settings, null, 2) });
        log.info(`旧版 localStorage AI 配置已迁移到设置文件（provider: ${key}）`);
      }
    }
    try { localStorage.removeItem(LEGACY_STORAGE_KEY); } catch { /* intentional: 删除失败只是下次再迁移一次，幂等 */ }
  } catch (e) {
    // 保留 localStorage 原值，下次启动重试
    log.warn('旧版 AI 配置迁移失败，将在下次启动时重试', e);
  }
}

// ==================== 加载与解析 ====================

/**
 * 加载 AI 配置（5 分钟缓存）。
 *
 * @param providerKey 省略时解析 settings.ai.currentProvider 指向的 provider；
 *                    传入时解析指定 provider（测试连接、跨 provider 调用场景）
 *
 * @throws '请在设置中配置AI API Key' —— 非 ollama 系、且非本机/内网 custom 提供商却没有 apiKey
 * @throws 'AI提供商配置不存在，请在设置中配置AI' —— 目标 provider 条目缺失
 */
export async function loadAIConfig(providerKey?: string): Promise<ResolvedAIConfig> {
  const cacheKey = providerKey ?? '__current__';
  const hit = cache.get(cacheKey);
  if (hit && Date.now() - hit.at < CACHE_TTL_MS) {
    return hit.config;
  }

  await migrateLegacyConfigOnce();

  const content = await invoke<string>('read_settings_file');
  let settings: any = {};
  try {
    settings = content ? JSON.parse(content) : {};
  } catch (e) {
    log.warn('设置文件 JSON 解析失败，按空配置处理', e);
    settings = {};
  }

  const ai = settings.ai ?? {};
  const resolvedKey: string = providerKey || ai.currentProvider || 'openai';
  const provider = ai.providers?.[resolvedKey];
  if (!provider) {
    throw new Error('AI提供商配置不存在，请在设置中配置AI');
  }

  const name = String(provider.name ?? '');
  const providerType = resolveProviderType(resolvedKey, provider);
  const claude = isClaudeProvider(resolvedKey, providerType, name);
  const ollama = isOllamaProvider(resolvedKey, providerType, name);

  const apiKey = String(provider.apiKey ?? '');
  const rawBaseUrl = String(provider.baseUrl ?? '') || defaultBaseUrlFor(resolvedKey, providerType);
  if (!rawBaseUrl) {
    throw new Error('自定义提供商需要提供 API 端点（Base URL）');
  }
  const baseUrl = ensureCompletionsPath(rawBaseUrl, claude);

  // 无 Key 规则：ollama 系，或 baseUrl 指向本机/内网的 custom 提供商，允许空 Key
  if (!apiKey && !ollama && !(providerType === 'custom' && isLocalOrPrivateHost(rawBaseUrl))) {
    throw new Error('请在设置中配置AI API Key');
  }

  const model = String(provider.model ?? '') || defaultModelFor(resolvedKey, providerType);

  const config: ResolvedAIConfig = {
    providerKey: resolvedKey,
    providerType,
    baseUrl,
    apiKey,
    model,
    isClaude: claude,
    apiKeyHeader: claude ? 'x-api-key' : 'authorization-bearer',
  };

  cache.set(cacheKey, { config, at: Date.now() });
  log.debug(`AI 配置已解析: ${resolvedKey} (${providerType}) → ${baseUrl} (model: ${model})`);
  return config;
}
