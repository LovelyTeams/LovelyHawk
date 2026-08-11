import { beforeEach, describe, expect, it, vi } from 'vitest';

import { activeTargetContext } from './targetContext';
import { operationJournal } from './operationJournal';

const invokeMock = vi.hoisted(() => vi.fn());

vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));

const storage = new Map<string, string>();
Object.defineProperty(globalThis, 'localStorage', {
  configurable: true,
  value: {
    getItem: (key: string) => storage.get(key) ?? null,
    setItem: (key: string, value: string) => storage.set(key, value),
    removeItem: (key: string) => storage.delete(key),
    clear: () => storage.clear(),
  },
});

const target = {
  sessionId: 'root@10.0.0.1:22#epoch-1',
  hostKeyFingerprint: 'SHA256:test',
  host: '10.0.0.1',
  port: 22,
  username: 'root',
};

describe('operationJournal target binding', () => {
  beforeEach(() => {
    invokeMock.mockReset();
    storage.clear();
    operationJournal.clear();
    activeTargetContext.clear();
  });

  it('captures the active target and blocks rollback after reconnect', async () => {
    activeTargetContext.activate(target);
    const entry = operationJournal.record({
      source: 'manual', server: target.host, title: 'change', command: 'apply',
      restoreCommand: 'restore', output: '', success: true,
    });

    activeTargetContext.activate({ ...target, sessionId: 'root@10.0.0.1:22#epoch-2' });
    const result = await operationJournal.rollback(entry.id);

    expect(entry.target).toEqual(target);
    expect(result.success).toBe(false);
    expect(result.output).toContain('当前目标与操作记录不一致');
    expect(invokeMock).not.toHaveBeenCalled();
  });

  it('marks rollback complete only after a zero exit status', async () => {
    activeTargetContext.activate(target);
    const entry = operationJournal.record({
      source: 'manual', server: target.host, title: 'change', command: 'apply',
      restoreCommand: 'restore', output: '', success: true,
    });
    invokeMock.mockResolvedValue({ output: 'restored', exit_code: 0, timed_out: false });

    const result = await operationJournal.rollback(entry.id);

    expect(result).toEqual({ success: true, output: 'restored' });
    expect(invokeMock).toHaveBeenCalledWith('ssh_execute_command_direct', {
      command: 'restore', sessionId: target.sessionId,
    });
    expect(operationJournal.get(entry.id)?.rolledBack).toBe(true);
  });

  it('allows an explicitly reconnectable batch receipt on the same trusted host', async () => {
    activeTargetContext.activate(target);
    const entry = operationJournal.record({
      source: 'manual', server: target.host, target, title: 'batch change', command: 'apply',
      restoreCommand: 'restore', allowStableTargetReconnect: true, output: '', success: true,
    });
    const reconnected = { ...target, sessionId: 'root@10.0.0.1:22#epoch-2' };
    activeTargetContext.activate(reconnected);
    invokeMock.mockResolvedValue({ output: 'restored', exit_code: 0, timed_out: false });

    const result = await operationJournal.rollback(entry.id);

    expect(result.success).toBe(true);
    expect(invokeMock).toHaveBeenCalledWith('ssh_execute_command_direct', {
      command: 'restore', sessionId: reconnected.sessionId,
    });
  });

  it('keeps a failed rollback pending', async () => {
    activeTargetContext.activate(target);
    const entry = operationJournal.record({
      source: 'manual', server: target.host, title: 'change', command: 'apply',
      restoreCommand: 'restore', output: '', success: true,
    });
    invokeMock.mockResolvedValue({ output: 'denied', exit_code: 1, timed_out: false });

    const result = await operationJournal.rollback(entry.id);

    expect(result.success).toBe(false);
    expect(operationJournal.get(entry.id)?.rolledBack).toBe(false);
  });

  it('marks rollback complete only after its independent read-back contract passes', async () => {
    activeTargetContext.activate(target);
    const entry = operationJournal.record({
      source: 'check-audit', server: target.host, title: 'replace binary', command: 'apply',
      restoreCommand: 'restore', restoreVerifyCommand: 'verify-restore', restoreVerifyExpected: 'ORIGINAL_OK',
      output: 'written', exitCode: 0, verifyCommand: 'verify-apply', verifyOutput: 'WRAPPER_OK',
      verified: true, success: true,
    });
    invokeMock
      .mockResolvedValueOnce({ output: 'restored', exit_code: 0, timed_out: false })
      .mockResolvedValueOnce({ output: 'still a script', exit_code: 0, timed_out: false });

    const result = await operationJournal.rollback(entry.id);

    expect(result.success).toBe(false);
    expect(result.output).toContain('读回验证失败');
    expect(operationJournal.get(entry.id)?.rolledBack).toBe(false);
    expect(invokeMock).toHaveBeenNthCalledWith(2, 'ssh_execute_command_direct', {
      command: 'verify-restore', sessionId: target.sessionId,
    });
  });

  it('allows a target-matched external restore flow to synchronize the receipt', () => {
    activeTargetContext.activate(target);
    const entry = operationJournal.record({
      source: 'check-audit', server: target.host, title: 'replace', command: 'apply',
      restoreCommand: 'restore', output: 'ok', success: true,
    });

    expect(operationJournal.markRolledBack(entry.id)).toBe(true);
    expect(operationJournal.get(entry.id)?.rolledBack).toBe(true);
  });

  it('filters, exports, and clears records by the full stable target identity', () => {
    activeTargetContext.activate(target);
    const mine = operationJournal.record({
      source: 'manual', server: target.host, title: 'mine', command: 'read', output: '', success: true,
    });
    operationJournal.record({
      source: 'manual', server: target.host,
      target: { ...target, sessionId: 'other-session', username: 'admin' },
      title: 'other account', command: 'read', output: '', success: true,
    });
    expect(operationJournal.list({ target }).map(entry => entry.id)).toEqual([mine.id]);
    expect(operationJournal.exportTarget(target)).toContain('mine');
    expect(operationJournal.exportTarget(target)).not.toContain('other account');

    operationJournal.clearTarget(target);
    expect(operationJournal.get(mine.id)).toBeUndefined();
    expect(operationJournal.list({ server: target.host })).toHaveLength(1);
  });
});
