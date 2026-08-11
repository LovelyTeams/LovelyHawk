/**
 * AI 服务
 * 用于生成安全问题的解决方案
 * 所有 HTTP 请求通过 Tauri 后端代理发送，绕过浏览器 CORS 限制
 *
 * 配置唯一来源是后端 settings 文件，经 ./aiConfig 解析（localStorage 旧配置
 * 由 aiConfig 在首次加载时一次性迁移）。apiKey 可能是 enc:v1: 密文，前端不解密、
 * 也不把 Key 放进 headers —— 由后端 ai_proxy_* 解密并注入认证头。
 * 流式请求带 stream_id，事件按 stream_id 过滤，因此不再有全局 isStreaming 锁，
 * 多窗口/多请求并发流互不干扰。
 */

import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';

import { logger } from '../core/logger';
import {
  ensureCompletionsPath,
  loadAIConfig,
  PROVIDER_PRESETS,
  type AIKeyHeader,
} from './aiConfig';
import {
  conciseSolutionPrompt,
  conciseSolutionUserPrompt,
  detailedSolutionPrompt,
  detailedSolutionUserPrompt,
  logExplainPrompt,
  logExplainUserPrompt,
} from './aiPrompts';
import { aiHistoryManager } from './aiHistoryManager';

/** 正式包 drop 掉 console，诊断信息只有进 logger 才留得下来（状态栏「日志」按钮可导出） */
const log = logger.module('AIService');


function createSseDataBuffer(onData: (data: string) => void): {
  push: (chunk: string) => void;
  flush: () => void;
} {
  let buffer = '';

  const consumeLine = (line: string) => {
    const normalized = line.endsWith('\r') ? line.slice(0, -1) : line;
    if (!normalized.trimStart().startsWith('data:')) return;
    onData(normalized.trimStart().replace(/^data:\s?/, '').trim());
  };

  return {
    push(chunk: string) {
      buffer += chunk;
      const lines = buffer.split('\n');
      buffer = lines.pop() ?? '';
      lines.forEach(consumeLine);
    },
    flush() {
      if (buffer) consumeLine(buffer);
      buffer = '';
    },
  };
}

// AI 响应接口
export interface AISolution {
  solution: string;
  steps: string[];
  risks: string[];
  timeEstimate?: string;
}

/** 一次流式请求的句柄：done 在流结束/失败/取消时 settle，cancel 主动中止 */
interface StreamHandle {
  done: Promise<void>;
  cancel: () => void;
}

function newStreamId(): string {
  try {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
      return crypto.randomUUID();
    }
  } catch { /* intentional: 非安全上下文下 randomUUID 可能抛错，走时间戳回退 */ }
  return `stream-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

/**
 * AI 服务类
 */
export class AIService {
  private static instance: AIService;

  private constructor() {}

  /**
   * 获取单例实例
   */
  public static getInstance(): AIService {
    if (!AIService.instance) {
      AIService.instance = new AIService();
    }
    return AIService.instance;
  }

  // ==================== Tauri 代理请求（绕过 CORS） ====================

  /**
   * 把底层网络/超时类错误富化为对用户友好、且带离线降级引导的消息。
   * 赛场断网时 AI 必然不可用,提示选手改用本地"安全速查"库,避免只看到晦涩堆栈或静默失败。
   */
  private toFriendlyError(e: unknown): Error {
    const raw = String((e as any)?.message ?? e);
    const isNetwork = /发送失败|超时|timed?\s*out|timeout|connect|dns|error sending request|os error|network|不可达|reqwest|创建 HTTP/i.test(raw);
    if (isNetwork) {
      return new Error(`AI 服务不可用(可能断网或超时)。赛场离线时请改用本地"安全速查"进行修复。\n原始错误: ${raw}`);
    }
    return e instanceof Error ? e : new Error(raw);
  }

  /** 组装发给 ai_proxy_* 的可选认证参数（apiKey 为空时省略，如 Ollama） */
  private authArgs(config: { apiKey: string; apiKeyHeader: AIKeyHeader }): Record<string, string> {
    return config.apiKey
      ? { apiKey: config.apiKey, apiKeyHeader: config.apiKeyHeader }
      : {};
  }

  /**
   * 通过 Tauri 后端发送非流式 AI 请求
   */
  private async tauriFetch(
    url: string,
    headers: Record<string, string>,
    body: string,
    auth?: { apiKey: string; apiKeyHeader: AIKeyHeader },
  ): Promise<{ ok: boolean; status: number; body: string }> {
    try {
      const result = await invoke('ai_proxy_request', {
        url, headers, body,
        ...(auth ? this.authArgs(auth) : {}),
      }) as { ok: boolean; status: number; body: string };
      return result;
    } catch (e) {
      throw this.toFriendlyError(e);
    }
  }

  /**
   * 通过 Tauri 后端发送流式 AI 请求，通过事件接收数据块。
   *
   * 每个请求生成独立 stream_id，事件（ai_stream_chunk/error/done）按
   * stream_id 过滤，外来事件直接忽略；cancel() 通知后端取消并清理监听。
   */
  private startAIStream(opts: {
    url: string;
    headers: Record<string, string>;
    body: string;
    apiKey: string;
    apiKeyHeader: AIKeyHeader;
    onChunk: (text: string) => void;
  }): StreamHandle {
    const streamId = newStreamId();

    let unlistenChunk: UnlistenFn | null = null;
    let unlistenError: UnlistenFn | null = null;
    let unlistenDone: UnlistenFn | null = null;
    let settled = false;
    let cancelRequested = false;

    let resolveDone!: () => void;
    let rejectDone!: (e: Error) => void;
    const done = new Promise<void>((resolve, reject) => {
      resolveDone = resolve;
      rejectDone = reject;
    });
    // cancel 先于调用方 await done 时不产生 unhandled rejection 噪音
    done.catch(() => { /* intentional: 拒绝理由会传给 await done 的调用方 */ });

    const cleanup = () => {
      unlistenChunk?.();
      unlistenError?.();
      unlistenDone?.();
      unlistenChunk = unlistenError = unlistenDone = null;
    };
    const finishResolve = () => {
      if (settled) return;
      settled = true;
      cleanup();
      resolveDone();
    };
    const finishReject = (e: Error) => {
      if (settled) return;
      settled = true;
      cleanup();
      rejectDone(e);
    };

    const cancel = () => {
      if (settled) return;
      cancelRequested = true;
      invoke('ai_proxy_stream_cancel', { streamId })
        .catch((e) => log.debug('流取消命令发送失败', e));
      const err = new Error('AI 流式请求已取消');
      err.name = 'AbortError';
      finishReject(err);
    };

    (async () => {
      try {
        unlistenChunk = await listen<{ stream_id: string; chunk?: string }>('ai_stream_chunk', (event) => {
          if (event.payload?.stream_id !== streamId) return;
          if (typeof event.payload.chunk === 'string') opts.onChunk(event.payload.chunk);
        });
        unlistenError = await listen<{ stream_id: string; error?: string }>('ai_stream_error', (event) => {
          if (event.payload?.stream_id !== streamId) return;
          finishReject(new Error(`AI 流式请求失败: ${event.payload.error ?? '未知错误'}`));
        });
        unlistenDone = await listen<{ stream_id: string }>('ai_stream_done', (event) => {
          if (event.payload?.stream_id !== streamId) return;
          finishResolve();
        });
      } catch (listenErr) {
        finishReject(new Error(`AI 事件监听注册失败: ${listenErr}`));
        return;
      }

      // 监听注册期间用户已取消：cancel() 已 settle 并清理，无需再发请求
      if (cancelRequested) return;

      try {
        await invoke('ai_proxy_stream', {
          url: opts.url,
          headers: opts.headers,
          body: opts.body,
          streamId,
          ...this.authArgs(opts),
        });
      } catch (e) {
        finishReject(this.toFriendlyError(e));
      }
    })();

    return { done, cancel };
  }

  /** 请求头：认证头由后端注入，前端只带 Content-Type（Claude 另带 anthropic-version） */
  private buildHeaders(isClaude: boolean): Record<string, string> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (isClaude) headers['anthropic-version'] = '2023-06-01';
    return headers;
  }

  /** 按提供商类型组装聊天请求体（Claude 无 system role，合并进单条 user 消息） */
  private buildChatBody(
    isClaude: boolean,
    model: string,
    systemPrompt: string,
    userPrompt: string | null,
    maxTokens: number,
    stream: boolean,
  ): string {
    if (isClaude) {
      return JSON.stringify({
        model, max_tokens: maxTokens, ...(stream ? { stream: true } : {}),
        messages: [{ role: 'user', content: userPrompt ? `${systemPrompt}\n\n${userPrompt}` : systemPrompt }],
      });
    }
    const messages = userPrompt
      ? [{ role: 'system', content: systemPrompt }, { role: 'user', content: userPrompt }]
      : [{ role: 'system', content: systemPrompt }];
    return JSON.stringify({
      model, temperature: 0.7, max_tokens: maxTokens, ...(stream ? { stream: true } : {}),
      messages,
    });
  }

  /** 从 SSE data 负载里提取增量文本（OpenAI delta / Claude delta 两种形状） */
  private extractDeltaText(data: string): string {
    if (data === '[DONE]') return '';
    try {
      const parsed = JSON.parse(data);
      return parsed.choices?.[0]?.delta?.content  // OpenAI
        || parsed.delta?.text                     // Claude
        || '';
    } catch (e) {
      // SSE 中途截断的半条 JSON，下一个 chunk 会补齐
      log.debug('SSE 数据块解析失败，已跳过', e);
      return '';
    }
  }

  /** 成功后写 AI 历史；尽力而为，绝不失败主流程 */
  private recordHistory(question: string, answer: string, source: string): void {
    if (!answer) return;
    try {
      aiHistoryManager.addRecord({ question, answer, source });
    } catch (e) {
      log.debug('AI 历史记录写入失败', e);
    }
  }

  /**
   * 生成解决方案
   */
  public async generateSolution(
    title: string,
    description: string,
    severity: string,
    serverInfo?: string
  ): Promise<AISolution> {
    const config = await loadAIConfig();
    const systemPrompt = detailedSolutionPrompt();
    const userPrompt = detailedSolutionUserPrompt(title, description, severity, serverInfo);

    try {
      const requestBody = this.buildChatBody(config.isClaude, config.model, systemPrompt, userPrompt, 2048, false);
      const response = await this.tauriFetch(config.baseUrl, this.buildHeaders(config.isClaude), requestBody, config);

      if (!response.ok) {
        // 截取前 200 字符，避免 HTML 页面堆栈
        const preview = response.body.substring(0, 200);
        throw new Error(`AI API 请求失败 (${response.status}): ${preview}`);
      }

      let responseData: any;
      try {
        responseData = JSON.parse(response.body);
      } catch {
        // API 返回了非 JSON 内容（可能是 HTML 错误页面）
        const preview = response.body.substring(0, 150);
        throw new Error(`AI API 返回了非 JSON 响应，请检查 Base URL 是否正确。\n响应内容: ${preview}`);
      }

      const content = config.isClaude
        ? responseData.content?.[0]?.text || ''
        : responseData.choices?.[0]?.message?.content || '';

      if (!content) {
        throw new Error('AI 返回了空响应，请检查模型名称是否正确');
      }

      const solution = this.parseSolution(content);
      this.recordHistory(`[${severity}] ${title}\n${description}`, solution.solution, 'solution');
      return solution;
    } catch (error) {
      log.error('AI 解决方案生成失败:', error);
      throw error;
    }
  }

  /**
   * 流式生成简洁解决方案
   */
  public async generateConciseSolutionStream(
    title: string,
    description: string,
    severity: string,
    serverInfo?: string,
    onChunk?: (text: string) => void,
    onComplete?: (fullText: string) => void
  ): Promise<void> {
    const config = await loadAIConfig();
    const systemPrompt = conciseSolutionPrompt();
    const userPrompt = conciseSolutionUserPrompt(title, description, severity, serverInfo);

    try {
      let fullText = '';
      const requestBody = this.buildChatBody(config.isClaude, config.model, systemPrompt, userPrompt, 500, true);

      const sse = createSseDataBuffer((data) => {
        const text = this.extractDeltaText(data);
        if (text) {
          fullText += text;
          onChunk?.(text);
        }
      });
      const stream = this.startAIStream({
        url: config.baseUrl,
        headers: this.buildHeaders(config.isClaude),
        body: requestBody,
        apiKey: config.apiKey,
        apiKeyHeader: config.apiKeyHeader,
        onChunk: sse.push,
      });
      await stream.done;
      sse.flush();

      this.recordHistory(`[${severity}] ${title}\n${description}`, fullText, 'solution');
      onComplete?.(fullText);
    } catch (error) {
      log.error('AI 流式生成失败:', error);
      throw error;
    }
  }

  /**
   * 流式解释系统日志
   */
  public async explainLogStream(
    logContent: string,
    context?: string,
    onChunk?: (text: string) => void,
    onComplete?: (fullText: string) => void
  ): Promise<void> {
    const config = await loadAIConfig();
    const systemPrompt = logExplainPrompt();
    const userPrompt = logExplainUserPrompt(logContent, context);

    try {
      let fullText = '';
      const requestBody = this.buildChatBody(config.isClaude, config.model, systemPrompt, userPrompt, 1000, true);

      const sse = createSseDataBuffer((data) => {
        const text = this.extractDeltaText(data);
        if (text) {
          fullText += text;
          onChunk?.(text);
        }
      });
      const stream = this.startAIStream({
        url: config.baseUrl,
        headers: this.buildHeaders(config.isClaude),
        body: requestBody,
        apiKey: config.apiKey,
        apiKeyHeader: config.apiKeyHeader,
        onChunk: sse.push,
      });
      await stream.done;
      sse.flush();

      this.recordHistory(context ? `[${context}]\n${logContent}` : logContent, fullText, 'log-explain');
      onComplete?.(fullText);
    } catch (error) {
      log.error('AI 日志解释失败:', error);
      throw error;
    }
  }

  /**
   * 以 OpenAI 兼容格式流式请求一个"纯 system prompt"补全。
   *
   * 配置经 aiConfig.loadAIConfig() 解析（默认当前 provider，可用
   * opts.providerKey 指定其他 provider）；前端不发送任何认证头，
   * apiKey（可能是 enc:v1: 密文）与 apiKeyHeader 交给后端注入。
   *
   * 返回的 Promise 在流完成时 resolve 出 { text, cancel }；若需要在流
   * 进行中拿到取消句柄（如「取消生成」按钮），传 opts.onStart —— 它在
   * 流注册完成后立刻以 cancel 回调。
   */
  public async streamOpenAICompatible(
    systemPrompt: string,
    onChunk?: (text: string) => void,
    opts?: { providerKey?: string; onStart?: (cancel: () => void) => void },
  ): Promise<{ text: string; cancel: () => void }> {
    const config = await loadAIConfig(opts?.providerKey);

    const body = this.buildChatBody(config.isClaude, config.model, systemPrompt, null, 1000, true);

    let fullContent = '';
    const sse = createSseDataBuffer((data) => {
      const text = this.extractDeltaText(data);
      if (text) {
        fullContent += text;
        onChunk?.(text);
      }
    });

    const stream = this.startAIStream({
      url: config.baseUrl,
      headers: this.buildHeaders(config.isClaude),
      body,
      apiKey: config.apiKey,
      apiKeyHeader: config.apiKeyHeader,
      onChunk: sse.push,
    });
    opts?.onStart?.(stream.cancel);

    await stream.done;
    sse.flush();

    const text = fullContent.trim();
    this.recordHistory(systemPrompt, text, 'explain');
    return { text, cancel: stream.cancel };
  }

  /**
   * 解析 AI 返回的解决方案
   */
  private parseSolution(content: string): AISolution {
    // 提取步骤
    const steps: string[] = [];
    const stepsMatch = content.match(/(?:解决步骤|步骤|操作步骤)[:：]([\s\S]*?)(?=##|风险|注意|预计|$)/i);
    if (stepsMatch) {
      const stepsText = stepsMatch[1];
      const stepMatches = stepsText.matchAll(/(?:^|\n)\s*(?:\d+[\.\、]|[-*])\s*(.+?)(?=\n\s*(?:\d+[\.\、]|[-*])|$)/gs);
      for (const match of stepMatches) {
        const step = match[1].trim();
        if (step) {
          steps.push(step);
        }
      }
    }

    // 提取风险
    const risks: string[] = [];
    const risksMatch = content.match(/(?:风险|注意事项|注意)[:：]([\s\S]*?)(?=##|预计|$)/i);
    if (risksMatch) {
      const risksText = risksMatch[1];
      const riskMatches = risksText.matchAll(/(?:^|\n)\s*(?:\d+[\.\、]|[-*])\s*(.+?)(?=\n\s*(?:\d+[\.\、]|[-*])|$)/gs);
      for (const match of riskMatches) {
        const risk = match[1].trim();
        if (risk) {
          risks.push(risk);
        }
      }
    }

    // 提取时间估算
    const timeMatch = content.match(/(?:预计|耗时|时间)[:：\s]*(.+?)(?:\n|$)/i);
    const timeEstimate = timeMatch ? timeMatch[1].trim() : undefined;

    return {
      solution: content,
      steps: steps.length > 0 ? steps : ['请参考完整解决方案'],
      risks: risks.length > 0 ? risks : ['请仔细阅读完整方案中的注意事项'],
      timeEstimate,
    };
  }

  /**
   * 测试 API 连接（无状态：不读写任何已保存配置，直接使用传入的配置）。
   *
   * 发一条最小的非流式聊天请求，成功返回简短的成功描述，失败抛出
   * toFriendlyError 富化后的错误。
   */
  public async testConnection(config: {
    providerType: string;
    apiKey: string;
    baseUrl?: string;
    model?: string;
  }): Promise<string> {
    const isClaude = /claude|anthropic/i.test(config.providerType);
    const preset = PROVIDER_PRESETS[config.providerType] ?? PROVIDER_PRESETS[isClaude ? 'claude' : 'custom'];

    const rawBaseUrl = config.baseUrl || preset?.defaultBaseUrl || '';
    if (!rawBaseUrl) {
      throw new Error('自定义提供商需要提供 API 端点（Base URL）');
    }
    const url = ensureCompletionsPath(rawBaseUrl, isClaude);
    const model = config.model || preset?.defaultModel || 'gpt-4o-mini';

    const body = this.buildChatBody(isClaude, model, '回复"连接成功"两个字即可。', null, 16, false);
    const response = await this.tauriFetch(url, this.buildHeaders(isClaude), body, {
      apiKey: config.apiKey,
      apiKeyHeader: isClaude ? 'x-api-key' : 'authorization-bearer',
    });

    if (!response.ok) {
      const preview = response.body.substring(0, 200);
      throw new Error(`AI API 请求失败 (${response.status}): ${preview}`);
    }
    return `连接成功（${model}）`;
  }

  /**
   * 拉取提供商的模型列表（设置页「拉取模型」按钮）。
   *
   * 与 testConnection 一样的无状态风格：传入表单值即可，不触碰已保存配置；
   * apiKey 可以是明文也可以是 enc:v1: 密文（后端自行解密）。
   * 端点推导在后端完成（OpenAI/Claude → /models，Ollama → /api/tags）。
   */
  public async listModels(config: {
    providerType: string;
    apiKey: string;
    baseUrl?: string;
  }): Promise<string[]> {
    try {
      const isClaude = /claude|anthropic/i.test(config.providerType);
      const preset = PROVIDER_PRESETS[config.providerType] ?? PROVIDER_PRESETS[isClaude ? 'claude' : 'custom'];
      const baseUrl = (config.baseUrl || preset?.defaultBaseUrl || '').trim();
      if (!baseUrl) {
        throw new Error('自定义提供商需要提供 API 端点（Base URL）');
      }

      return await invoke<string[]>('ai_list_models', {
        baseUrl,
        providerType: isClaude ? 'claude' : config.providerType,
        apiKey: config.apiKey || null,
        apiKeyHeader: isClaude ? 'x-api-key' : 'authorization-bearer',
      });
    } catch (error) {
      throw this.toFriendlyError(error);
    }
  }
}

// 导出单例实例
export const aiService = AIService.getInstance();
