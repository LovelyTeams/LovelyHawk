import { invoke } from '@tauri-apps/api/core';

import type { BackendSSHConnectionStatus } from '../core/targetContext';
import { showConfirm, showPrompt } from '../ui/confirmDialog';

const HOST_KEY_CONFIRMATION_PREFIX = 'LOVELYRES_SSH_HOST_KEY_CONFIRM:';
const KEYBOARD_INTERACTIVE_CHALLENGE_PREFIX = 'LOVELYRES_SSH_KBDINT_REQUIRED:';

export interface HostKeyConfirmationChallenge {
  code: 'HOST_KEY_CONFIRMATION_REQUIRED';
  host: string;
  port: number;
  username: string;
  fingerprint: string;
}

export interface SSHConnectArgs {
  host: string;
  port: number;
  username: string;
  password?: string;
  authType?: string;
  keyPath?: string | null;
  keyPassphrase?: string | null;
}

export type SSHAuthType = 'password' | 'key' | 'certificate' | 'keyboard-interactive' | 'agent';

export interface SSHAuthenticationArgs {
  authType: SSHAuthType;
  password?: string;
  keyPath?: string | null;
  keyPassphrase?: string | null;
  certificatePath?: string | null;
  keyboardInteractiveResponses?: string[];
  agentIdentityFingerprint?: string | null;
}

export interface SSHJumpHostArgs {
  host: string;
  port: number;
  username: string;
  authentication: SSHAuthenticationArgs;
  expectedHostKeyFingerprint?: string | null;
}

export interface SSHAdvancedConnectRequest {
  host: string;
  port: number;
  username: string;
  authentication: SSHAuthenticationArgs;
  expectedHostKeyFingerprint?: string | null;
  jumpHost?: SSHJumpHostArgs | null;
}

export interface KeyboardInteractiveChallenge {
  code: 'KEYBOARD_INTERACTIVE_REQUIRED';
  host: string;
  port: number;
  username: string;
  name: string;
  instructions: string;
  suppliedResponses: number;
  prompts: Array<{ prompt: string; echo: boolean }>;
}

type InvokeFn = <T>(command: string, args?: Record<string, unknown>) => Promise<T>;
type ConfirmFn = typeof showConfirm;
type PromptFn = typeof showPrompt;

const defaultInvoke: InvokeFn = (command, args) => invoke(command, args);

function errorText(error: unknown): string {
  if (typeof error === 'string') return error;
  if (error instanceof Error) return error.message;
  if (error && typeof error === 'object' && 'message' in error) {
    return String((error as { message: unknown }).message);
  }
  return String(error);
}

export function parseHostKeyConfirmationChallenge(
  error: unknown,
): HostKeyConfirmationChallenge | null {
  const text = errorText(error);
  const marker = text.indexOf(HOST_KEY_CONFIRMATION_PREFIX);
  if (marker < 0) return null;

  try {
    const value = JSON.parse(text.slice(marker + HOST_KEY_CONFIRMATION_PREFIX.length));
    if (
      value?.code !== 'HOST_KEY_CONFIRMATION_REQUIRED'
      || typeof value.host !== 'string'
      || typeof value.port !== 'number'
      || typeof value.username !== 'string'
      || typeof value.fingerprint !== 'string'
    ) {
      return null;
    }
    return value as HostKeyConfirmationChallenge;
  } catch {
    return null;
  }
}

export function parseKeyboardInteractiveChallenge(
  error: unknown,
): KeyboardInteractiveChallenge | null {
  const text = errorText(error);
  const marker = text.indexOf(KEYBOARD_INTERACTIVE_CHALLENGE_PREFIX);
  if (marker < 0) return null;
  try {
    const value = JSON.parse(text.slice(marker + KEYBOARD_INTERACTIVE_CHALLENGE_PREFIX.length));
    if (
      value?.code !== 'KEYBOARD_INTERACTIVE_REQUIRED'
      || typeof value.host !== 'string'
      || typeof value.port !== 'number'
      || typeof value.username !== 'string'
      || !Array.isArray(value.prompts)
      || value.prompts.some((prompt: unknown) => !prompt
        || typeof prompt !== 'object'
        || typeof (prompt as { prompt?: unknown }).prompt !== 'string'
        || typeof (prompt as { echo?: unknown }).echo !== 'boolean')
    ) return null;
    return value as KeyboardInteractiveChallenge;
  } catch {
    return null;
  }
}

function cloneAdvancedRequest(request: SSHAdvancedConnectRequest): SSHAdvancedConnectRequest {
  return {
    ...request,
    authentication: {
      ...request.authentication,
      keyboardInteractiveResponses: [...(request.authentication.keyboardInteractiveResponses || [])],
    },
    jumpHost: request.jumpHost ? {
      ...request.jumpHost,
      authentication: {
        ...request.jumpHost.authentication,
        keyboardInteractiveResponses: [
          ...(request.jumpHost.authentication.keyboardInteractiveResponses || []),
        ],
      },
    } : null,
  };
}

function endpointMatches(
  endpoint: { host: string; port: number; username: string },
  challenge: { host: string; port: number; username: string },
): boolean {
  return endpoint.host === challenge.host
    && endpoint.port === challenge.port
    && endpoint.username === challenge.username;
}

async function confirmHostKey(
  challenge: HostKeyConfirmationChallenge,
  confirmFn: ConfirmFn,
): Promise<void> {
  const confirmed = await confirmFn({
    title: '确认新的 SSH 主机指纹',
    description: '首次连接的主机尚未建立可信身份',
    message: [
      `目标：${challenge.username}@${challenge.host}:${challenge.port}`,
      `SHA256 指纹：${challenge.fingerprint}`,
      '',
      '请通过可信渠道核对该指纹。指纹不一致或无法核实时，请取消连接。',
    ].join('\n'),
    confirmText: '指纹一致，信任并连接',
    cancelText: '取消连接',
    dangerous: true,
    defaultFocus: 'cancel',
  });
  if (!confirmed) {
    throw new Error(`已取消信任未记录的 SSH 主机密钥：${challenge.username}@${challenge.host}:${challenge.port}`);
  }
}

export async function connectSSHAdvancedWithHostKeyConfirmation<T = BackendSSHConnectionStatus>(
  request: SSHAdvancedConnectRequest,
  invokeFn: InvokeFn = defaultInvoke,
  confirmFn: ConfirmFn = showConfirm,
  promptFn: PromptFn = showPrompt,
  command: 'ssh_connect_advanced' | 'ssh_test_connection_advanced' = 'ssh_connect_advanced',
): Promise<T> {
  const current = cloneAdvancedRequest(request);
  for (let attempt = 0; attempt < 12; attempt += 1) {
    try {
      return await invokeFn<T>(command, { request: current });
    } catch (error) {
      const hostKey = parseHostKeyConfirmationChallenge(error);
      if (hostKey) {
        await confirmHostKey(hostKey, confirmFn);
        if (endpointMatches(current, hostKey)) {
          current.expectedHostKeyFingerprint = hostKey.fingerprint;
          request.expectedHostKeyFingerprint = hostKey.fingerprint;
          continue;
        }
        if (current.jumpHost && endpointMatches(current.jumpHost, hostKey)) {
          current.jumpHost.expectedHostKeyFingerprint = hostKey.fingerprint;
          if (request.jumpHost) {
            request.jumpHost.expectedHostKeyFingerprint = hostKey.fingerprint;
          }
          continue;
        }
        throw new Error('SSH 主机指纹挑战与请求目标不一致，已阻止连接');
      }

      const keyboard = parseKeyboardInteractiveChallenge(error);
      if (keyboard) {
        const auth = endpointMatches(current, keyboard)
          ? current.authentication
          : current.jumpHost && endpointMatches(current.jumpHost, keyboard)
            ? current.jumpHost.authentication
            : null;
        if (!auth || auth.authType !== 'keyboard-interactive') {
          throw new Error('keyboard-interactive 挑战与请求目标不一致，已阻止连接');
        }
        for (const prompt of keyboard.prompts) {
          const response = await promptFn({
            title: keyboard.name || 'SSH 交互认证',
            message: [
              `${keyboard.username}@${keyboard.host}:${keyboard.port}`,
              keyboard.instructions,
              prompt.prompt,
            ].filter(Boolean).join('\n'),
            inputType: prompt.echo ? 'text' : 'password',
            confirmText: '继续认证',
            cancelText: '取消连接',
          });
          if (response === null) throw new Error('已取消 keyboard-interactive 认证');
          const responses = auth.keyboardInteractiveResponses || [];
          if (responses.length >= 16) throw new Error('keyboard-interactive 响应超过安全上限');
          responses.push(response);
          auth.keyboardInteractiveResponses = responses;
        }
        continue;
      }
      throw error;
    }
  }
  throw new Error('SSH 认证挑战次数超过安全上限');
}

export async function invokeWithHostKeyConfirmation<T>(
  command: 'ssh_connect_direct' | 'ssh_test_connection',
  args: Record<string, unknown>,
  invokeFn: InvokeFn = defaultInvoke,
  confirmFn: ConfirmFn = showConfirm,
): Promise<T> {
  try {
    return await invokeFn<T>(command, {
      ...args,
      expectedHostKeyFingerprint: null,
    });
  } catch (error) {
    const challenge = parseHostKeyConfirmationChallenge(error);
    if (!challenge) throw error;

    const confirmed = await confirmFn({
      title: '确认新的 SSH 主机指纹',
      description: '首次连接的主机尚未建立可信身份',
      message: [
        `目标：${challenge.username}@${challenge.host}:${challenge.port}`,
        `SHA256 指纹：${challenge.fingerprint}`,
        '',
        '请通过可信渠道核对该指纹。指纹不一致或无法核实时，请取消连接。',
      ].join('\n'),
      confirmText: '指纹一致，信任并连接',
      cancelText: '取消连接',
      dangerous: true,
      defaultFocus: 'cancel',
    });

    if (!confirmed) {
      throw new Error(
        `已取消信任未记录的 SSH 主机密钥：${challenge.username}@${challenge.host}:${challenge.port}`,
      );
    }

    return invokeFn<T>(command, {
      ...args,
      expectedHostKeyFingerprint: challenge.fingerprint,
    });
  }
}

export function connectSSHWithHostKeyConfirmation(
  args: SSHConnectArgs,
  invokeFn?: InvokeFn,
  confirmFn?: ConfirmFn,
): Promise<BackendSSHConnectionStatus> {
  return invokeWithHostKeyConfirmation<BackendSSHConnectionStatus>(
    'ssh_connect_direct',
    { ...args },
    invokeFn,
    confirmFn,
  );
}
