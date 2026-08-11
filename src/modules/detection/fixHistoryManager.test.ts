import { beforeEach, describe, expect, it, vi } from 'vitest';

import { activeTargetContext } from '../core/targetContext';
import { fixHistoryManager } from './fixHistoryManager';

const mocks = vi.hoisted(() => {
  const storage = new Map<string, string>();
  Object.defineProperty(globalThis, 'localStorage', {
    configurable: true,
    value: {
      getItem: (key: string) => storage.get(key) ?? null,
      setItem: (key: string, value: string) => storage.set(key, value),
    },
  });
  return { invoke: vi.fn(), storage };
});

vi.mock('@tauri-apps/api/core', () => ({ invoke: mocks.invoke }));

const target = {
  sessionId: 'root@10.0.0.1:22#fix-history',
  hostKeyFingerprint: 'SHA256:key',
  host: '10.0.0.1',
  port: 22,
  username: 'root',
};

function addEntry() {
  return fixHistoryManager.addEntry({
    detectionItemId: 'ssh-audit', findingTitle: 'test', fixTitle: 'restore test',
    type: 'baseline', beforeValue: 'no', afterValue: 'yes', backupInfo: '/tmp/backup',
    restoreCommand: 'restore-command', restoreVerifyCommand: 'read-command',
    restoreVerifyPattern: 'VALUE=(\\w+)', restoreExpectedValue: 'no',
    output: 'fixed', success: true, server: target.host,
  });
}

describe('FixHistoryManager rollback verification', () => {
  beforeEach(() => {
    mocks.invoke.mockReset();
    mocks.storage.clear();
    activeTargetContext.clear();
    activeTargetContext.activate(target);
    fixHistoryManager.clear();
  });

  it('marks rollback only after the restored value is read back', async () => {
    const entry = addEntry();
    mocks.invoke
      .mockResolvedValueOnce({ output: 'restored', exit_code: 0, timed_out: false })
      .mockResolvedValueOnce({ output: 'VALUE=no', exit_code: 0, timed_out: false });

    await expect(fixHistoryManager.rollback(entry.id)).resolves.toMatchObject({ success: true });
    expect(mocks.invoke).toHaveBeenNthCalledWith(2, 'ssh_execute_command_direct', {
      command: 'read-command', sessionId: target.sessionId,
    });
    expect(fixHistoryManager.getHistory()[0].rolledBack).toBe(true);
  });

  it('keeps the receipt pending when read-back differs', async () => {
    const entry = addEntry();
    mocks.invoke
      .mockResolvedValueOnce({ output: 'restored', exit_code: 0, timed_out: false })
      .mockResolvedValueOnce({ output: 'VALUE=yes', exit_code: 0, timed_out: false });

    const result = await fixHistoryManager.rollback(entry.id);
    expect(result.success).toBe(false);
    expect(result.output).toContain('读回值不一致');
    expect(fixHistoryManager.getHistory()[0].rolledBack).toBe(false);
  });
});
