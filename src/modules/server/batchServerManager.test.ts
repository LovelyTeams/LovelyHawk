import { beforeEach, describe, expect, it, vi } from 'vitest';

import { BatchServerManager } from './batchServerManager';

const invokeMock = vi.hoisted(() => vi.fn());

vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));

const storage = new Map<string, string>();
Object.defineProperty(globalThis, 'localStorage', {
  configurable: true,
  value: {
    getItem: (key: string) => storage.get(key) ?? null,
    setItem: (key: string, value: string) => storage.set(key, value),
  },
});

describe('BatchServerManager execution truth', () => {
  beforeEach(() => {
    storage.clear();
    invokeMock.mockReset();
  });

  it('reports a resolved command with non-zero exit code as failed', async () => {
    const connection = {
      id: 'server-1', name: 'server', host: '10.0.0.1', port: 22, username: 'root',
      authType: 'password' as const, encryptedPassword: 'enc:v1:test', accounts: [], isConnected: false,
      hostKeyFingerprint: 'SHA256:test',
    };
    const connectionManager = {
      getConnections: () => [connection],
      getConnection: (id: string) => id === connection.id ? connection : undefined,
      getActiveConnection: () => undefined,
      connect: vi.fn(),
    };
    invokeMock.mockImplementation(async (command: string) => {
      if (command === 'decrypt_password') return 'secret';
      if (command === 'ssh_connect_direct') {
        return {
          connected: true,
          session_id: 'root@10.0.0.1:22#batch',
          host_key_fingerprint: 'SHA256:test',
          host: '10.0.0.1', port: 22, username: 'root', last_activity: '2026-08-09T00:00:00Z',
        };
      }
      if (command === 'ssh_execute_command_direct') {
        return { output: 'permission denied', exit_code: 1, timed_out: false };
      }
      return undefined;
    });

    const manager = new BatchServerManager(connectionManager as any);
    const task = await manager.executeBatch('test', 'false', [connection.id]);

    expect(task.results[0].status).toBe('failed');
    expect(task.results[0].error).toContain('权限不足');
    expect(invokeMock).toHaveBeenCalledWith('ssh_connect_direct', expect.objectContaining({
      expectedHostKeyFingerprint: 'SHA256:test',
    }));
    expect(invokeMock).toHaveBeenCalledWith('ssh_execute_command_direct', {
      command: 'false', sessionId: 'root@10.0.0.1:22#batch',
    });
    expect(invokeMock).toHaveBeenCalledWith('ssh_disconnect_session_direct', {
      sessionId: 'root@10.0.0.1:22#batch',
    });
  });

  it('stops after a failed canary and marks remaining targets skipped', async () => {
    const connections = ['one', 'two', 'three'].map((name, index) => ({
      id: name, name, host: `10.0.0.${index + 1}`, port: 22, username: 'root',
      authType: 'key' as const, accounts: [], isConnected: false,
      hostKeyFingerprint: `SHA256:${name}`,
    }));
    const connectionManager = {
      getConnections: () => connections,
      getConnection: (id: string) => connections.find(connection => connection.id === id),
      getActiveConnection: () => undefined,
      connect: vi.fn(),
    };
    invokeMock.mockImplementation(async (command: string, args: any) => {
      if (command === 'ssh_connect_direct') {
        return {
          connected: true, session_id: `${args.host}#batch`, host_key_fingerprint: args.expectedHostKeyFingerprint,
          host: args.host, port: 22, username: 'root', last_activity: '2026-08-09T00:00:00Z',
        };
      }
      if (command === 'ssh_execute_command_direct') {
        return { output: 'failed', exit_code: 1, timed_out: false };
      }
      return undefined;
    });

    const task = await new BatchServerManager(connectionManager as any)
      .executeBatch('canary', 'false', connections.map(connection => connection.id), undefined, {
        strategy: 'canary', canaryCount: 1,
      });

    expect(task.results.map(result => result.status)).toEqual(['failed', 'skipped', 'skipped']);
    expect(task.results[1].error).toContain('Canary');
    expect(invokeMock.mock.calls.filter(([command]) => command === 'ssh_connect_direct')).toHaveLength(1);
  });

  it('fails a host when the independent verification command fails', async () => {
    const connection = {
      id: 'server-1', name: 'server', host: '10.0.0.1', port: 22, username: 'root',
      authType: 'key' as const, accounts: [], isConnected: false, hostKeyFingerprint: 'SHA256:test',
    };
    const connectionManager = {
      getConnections: () => [connection], getConnection: () => connection,
      getActiveConnection: () => undefined, connect: vi.fn(),
    };
    invokeMock.mockImplementation(async (command: string, args: any) => {
      if (command === 'ssh_connect_direct') return {
        connected: true, session_id: 'batch-session', host_key_fingerprint: 'SHA256:test',
        host: connection.host, port: 22, username: 'root', last_activity: '2026-08-09T00:00:00Z',
      };
      if (command === 'ssh_execute_command_direct') {
        return args.command === 'verify' ? { output: 'bad', exit_code: 1, timed_out: false } : { output: 'ok', exit_code: 0, timed_out: false };
      }
      return undefined;
    });

    const task = await new BatchServerManager(connectionManager as any)
      .executeBatch('verify', 'apply', [connection.id], undefined, { verifyCommand: 'verify' });

    expect(task.results[0]).toMatchObject({ status: 'failed', verified: false, verifyCommand: 'verify' });
  });
});
