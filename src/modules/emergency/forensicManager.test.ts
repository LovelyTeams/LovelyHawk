import { beforeEach, describe, expect, it, vi } from 'vitest';

import { activeTargetContext } from '../core/targetContext';
import { incidentCaseManager } from '../case/incidentCaseManager';
import { buildForensicArtifact, ForensicManager } from './forensicManager';

const mocks = vi.hoisted(() => {
  const storage = new Map<string, string>();
  Object.defineProperty(globalThis, 'localStorage', {
    configurable: true,
    value: {
      getItem: (key: string) => storage.get(key) ?? null,
      setItem: (key: string, value: string) => storage.set(key, value),
    },
  });
  return { execute: vi.fn(), storage };
});

vi.mock('./commandExecution', () => ({
  executeEmergencyCommand: mocks.execute,
  formatCommandResult: (result: { output: string }) => result.output,
}));

const target = {
  sessionId: 'root@10.0.0.1:22#forensic', hostKeyFingerprint: 'SHA256:key',
  host: '10.0.0.1', port: 22, username: 'root',
};

describe('ForensicManager', () => {
  beforeEach(() => {
    mocks.storage.clear();
    mocks.execute.mockReset();
    mocks.execute.mockResolvedValue({ success: true, output: 'collected', exit_code: 0 });
    activeTargetContext.clear();
    activeTargetContext.activate(target);
    incidentCaseManager.clearAll();
  });

  it('collects a target-bound snapshot, hashes the exact export artifact and adds it to the case', async () => {
    const manager = new ForensicManager();
    const snapshot = await manager.captureSnapshot(target.host);
    const artifact = buildForensicArtifact(snapshot);
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(artifact));
    const expected = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');

    expect(mocks.execute).toHaveBeenCalledTimes(12);
    expect(snapshot.collection).toEqual({ total: 12, completed: 12, failed: 0 });
    expect(snapshot.target).toEqual(target);
    expect(snapshot.sha256).toBe(expected);
    expect(incidentCaseManager.getActiveCase()?.evidence).toEqual(expect.arrayContaining([
      expect.objectContaining({ kind: 'snapshot', sha256: expected, hashScope: 'external-artifact' }),
    ]));
  });

  it('discards the entire collection if the active target changes mid-flight', async () => {
    let switched = false;
    mocks.execute.mockImplementation(async () => {
      if (!switched) {
        switched = true;
        activeTargetContext.activate({
          sessionId: 'root@10.0.0.2:22#other', hostKeyFingerprint: 'SHA256:other',
          host: '10.0.0.2', port: 22, username: 'root',
        });
      }
      return { success: true, output: 'wrong target', exit_code: 0 };
    });
    const manager = new ForensicManager();

    await expect(manager.captureSnapshot(target.host)).rejects.toThrow('活动目标已变化');
    expect(manager.getSnapshots()).toHaveLength(0);
  });
});
