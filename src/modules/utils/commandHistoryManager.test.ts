import { beforeEach, describe, expect, it } from 'vitest';

import { activeTargetContext } from '../core/targetContext';
import {
  CommandHistoryManager,
  commandSha256,
  isVerifiedCommandHistoryItem,
  type CommandHistoryItem,
} from './commandHistoryManager';

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
  sessionId: 'root@192.0.2.10:22#one',
  hostKeyFingerprint: 'SHA256:trusted-target',
  host: '192.0.2.10',
  port: 22,
  username: 'root',
};

describe('CommandHistoryManager target-bound replay', () => {
  beforeEach(() => {
    storage.clear();
    activeTargetContext.clear();
  });

  it('stores a v2 target identity, risk, source and command digest', async () => {
    activeTargetContext.activate(target);

    expect(await CommandHistoryManager.saveCommand(' id ', 'identity', 'ok', 0, 'test')).toBe(true);

    const [item] = CommandHistoryManager.getHistory();
    expect(isVerifiedCommandHistoryItem(item)).toBe(true);
    expect(item.command).toBe('id');
    expect(item.target).toEqual(target);
    expect(item.risk).toBe('read-only');
    expect(item.source).toBe('test');
    expect(item.commandSha256).toBe(await commandSha256('id'));
  });

  it('keeps legacy records viewable but never replayable', async () => {
    const legacy: CommandHistoryItem = {
      id: 'legacy', command: 'id', title: 'old', output: 'uid=0', timestamp: Date.now(),
    };

    const assessment = await CommandHistoryManager.assessReplay(legacy, target);

    expect(assessment.allowed).toBe(false);
    expect(assessment.reason).toContain('旧版');
  });

  it('blocks replay on a different host even when the command digest is valid', async () => {
    activeTargetContext.activate(target);
    await CommandHistoryManager.saveCommand('id', 'identity', 'ok', 0, 'test');
    const item = CommandHistoryManager.getHistory()[0];

    const assessment = await CommandHistoryManager.assessReplay(item, {
      ...target,
      sessionId: 'root@192.0.2.11:22#two',
      host: '192.0.2.11',
    });

    expect(assessment.allowed).toBe(false);
    expect(assessment.reason).toContain('目标不一致');
  });

  it('blocks a command changed after it was recorded', async () => {
    activeTargetContext.activate(target);
    await CommandHistoryManager.saveCommand('id', 'identity', 'ok', 0, 'test');
    const item = { ...CommandHistoryManager.getHistory()[0], command: 'id; rm -f /tmp/x' };

    const assessment = await CommandHistoryManager.assessReplay(item, target);

    expect(assessment.allowed).toBe(false);
    expect(assessment.reason).toContain('摘要不一致');
  });

  it('allows a read-only replay after reconnecting to the same fingerprinted target', async () => {
    activeTargetContext.activate(target);
    await CommandHistoryManager.saveCommand('id', 'identity', 'ok', 0, 'test');
    const item = CommandHistoryManager.getHistory()[0];

    const assessment = await CommandHistoryManager.assessReplay(item, {
      ...target,
      sessionId: 'root@192.0.2.10:22#reconnected',
    });

    expect(assessment).toMatchObject({ allowed: true, requiresDangerousConfirmation: false });
  });

  it('requires dangerous confirmation for a verified mutating replay', async () => {
    activeTargetContext.activate(target);
    await CommandHistoryManager.saveCommand('rm -f /tmp/example', 'remove', '', 0, 'test');
    const item = CommandHistoryManager.getHistory()[0];

    const assessment = await CommandHistoryManager.assessReplay(item, target);

    expect(assessment).toMatchObject({ allowed: true, requiresDangerousConfirmation: true });
  });
});
