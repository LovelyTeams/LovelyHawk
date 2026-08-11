import { describe, expect, it, vi } from 'vitest';

import {
  connectSSHAdvancedWithHostKeyConfirmation,
  connectSSHWithHostKeyConfirmation,
  invokeWithHostKeyConfirmation,
  parseHostKeyConfirmationChallenge,
  parseKeyboardInteractiveChallenge,
  type SSHAdvancedConnectRequest,
} from './hostKeyConfirmation';

const challenge = {
  code: 'HOST_KEY_CONFIRMATION_REQUIRED',
  host: '10.0.0.8',
  port: 22,
  username: 'root',
  fingerprint: 'SHA256:confirmed-key',
} as const;

const challengeError = `LOVELYRES_SSH_HOST_KEY_CONFIRM:${JSON.stringify(challenge)}`;

describe('SSH host key confirmation', () => {
  it('parses only structured host-key challenges', () => {
    expect(parseHostKeyConfirmationChallenge(challengeError)).toEqual(challenge);
    expect(parseHostKeyConfirmationChallenge('普通连接失败')).toBeNull();
    expect(parseHostKeyConfirmationChallenge('LOVELYRES_SSH_HOST_KEY_CONFIRM:{}')).toBeNull();
  });

  it('retries with the exact fingerprint the user confirmed', async () => {
    const connected = {
      connected: true,
      session_id: 'root@10.0.0.8:22#1',
      host: challenge.host,
      port: challenge.port,
      username: challenge.username,
      host_key_fingerprint: challenge.fingerprint,
    };
    const invokeFn = vi.fn()
      .mockRejectedValueOnce(challengeError)
      .mockResolvedValueOnce(connected);
    const confirmFn = vi.fn().mockResolvedValue(true);

    await expect(connectSSHWithHostKeyConfirmation({
      host: challenge.host,
      port: challenge.port,
      username: challenge.username,
      password: 'secret',
    }, invokeFn, confirmFn)).resolves.toEqual(connected);

    expect(invokeFn).toHaveBeenNthCalledWith(1, 'ssh_connect_direct', expect.objectContaining({
      expectedHostKeyFingerprint: null,
    }));
    expect(invokeFn).toHaveBeenNthCalledWith(2, 'ssh_connect_direct', expect.objectContaining({
      expectedHostKeyFingerprint: challenge.fingerprint,
    }));
    expect(confirmFn).toHaveBeenCalledWith(expect.objectContaining({ defaultFocus: 'cancel' }));
  });

  it('does not retry when the user cancels', async () => {
    const invokeFn = vi.fn().mockRejectedValue(challengeError);
    const confirmFn = vi.fn().mockResolvedValue(false);

    await expect(invokeWithHostKeyConfirmation(
      'ssh_test_connection',
      { host: challenge.host },
      invokeFn,
      confirmFn,
    )).rejects.toThrow('已取消信任');
    expect(invokeFn).toHaveBeenCalledTimes(1);
  });

  it('propagates ordinary connection errors without prompting', async () => {
    const invokeFn = vi.fn().mockRejectedValue(new Error('connection refused'));
    const confirmFn = vi.fn();

    await expect(connectSSHWithHostKeyConfirmation({
      host: challenge.host,
      port: challenge.port,
      username: challenge.username,
    }, invokeFn, confirmFn)).rejects.toThrow('connection refused');
    expect(confirmFn).not.toHaveBeenCalled();
  });

  it('parses keyboard-interactive prompts without accepting malformed payloads', () => {
    const payload = {
      code: 'KEYBOARD_INTERACTIVE_REQUIRED',
      host: '10.0.0.8', port: 22, username: 'root', name: 'MFA', instructions: 'OTP',
      suppliedResponses: 0, prompts: [{ prompt: 'Verification code:', echo: false }],
    };
    expect(parseKeyboardInteractiveChallenge(
      `LOVELYRES_SSH_KBDINT_REQUIRED:${JSON.stringify(payload)}`,
    )).toEqual(payload);
    expect(parseKeyboardInteractiveChallenge(
      'LOVELYRES_SSH_KBDINT_REQUIRED:{"code":"KEYBOARD_INTERACTIVE_REQUIRED","prompts":"bad"}',
    )).toBeNull();
  });

  it('confirms jump and target keys separately, then answers MFA prompts', async () => {
    const jumpChallenge = {
      ...challenge,
      host: 'jump.example',
      username: 'jump-user',
      fingerprint: 'SHA256:jump',
    };
    const keyboard = {
      code: 'KEYBOARD_INTERACTIVE_REQUIRED',
      host: challenge.host, port: challenge.port, username: challenge.username,
      name: 'MFA', instructions: '', suppliedResponses: 0,
      prompts: [{ prompt: 'OTP:', echo: false }],
    };
    const connected = { connected: true, session_id: 's', host_key_fingerprint: challenge.fingerprint };
    const invokeFn = vi.fn()
      .mockRejectedValueOnce(`LOVELYRES_SSH_HOST_KEY_CONFIRM:${JSON.stringify(jumpChallenge)}`)
      .mockRejectedValueOnce(challengeError)
      .mockRejectedValueOnce(`LOVELYRES_SSH_KBDINT_REQUIRED:${JSON.stringify(keyboard)}`)
      .mockResolvedValueOnce(connected);
    const confirmFn = vi.fn().mockResolvedValue(true);
    const promptFn = vi.fn().mockResolvedValue('123456');

    const request: SSHAdvancedConnectRequest = {
      host: challenge.host,
      port: challenge.port,
      username: challenge.username,
      authentication: { authType: 'keyboard-interactive' },
      jumpHost: {
        host: jumpChallenge.host,
        port: jumpChallenge.port,
        username: jumpChallenge.username,
        authentication: { authType: 'agent' },
      },
    };
    await expect(connectSSHAdvancedWithHostKeyConfirmation(request, invokeFn, confirmFn, promptFn))
      .resolves.toEqual(connected);

    const lastRequest = invokeFn.mock.calls[3][1].request;
    expect(lastRequest.expectedHostKeyFingerprint).toBe(challenge.fingerprint);
    expect(lastRequest.jumpHost.expectedHostKeyFingerprint).toBe(jumpChallenge.fingerprint);
    expect(lastRequest.authentication.keyboardInteractiveResponses).toEqual(['123456']);
    expect(request.expectedHostKeyFingerprint).toBe(challenge.fingerprint);
    expect(request.jumpHost?.expectedHostKeyFingerprint).toBe(jumpChallenge.fingerprint);
    expect(promptFn).toHaveBeenCalledWith(expect.objectContaining({ inputType: 'password' }));
  });
});
