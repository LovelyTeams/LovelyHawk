import { beforeEach, describe, expect, it, vi } from 'vitest';

import { activeTargetContext, type TargetIdentity } from '../core/targetContext';
import { IncidentCaseManager, stableTargetKey } from './incidentCaseManager';

const mocks = vi.hoisted(() => {
  const storage = new Map<string, string>();
  Object.defineProperty(globalThis, 'localStorage', {
    configurable: true,
    value: {
      getItem: (key: string) => storage.get(key) ?? null,
      setItem: (key: string, value: string) => storage.set(key, value),
    },
  });
  return { storage };
});

const firstTarget: TargetIdentity = {
  sessionId: 'root@10.0.0.1:22#one',
  hostKeyFingerprint: 'SHA256:first',
  host: '10.0.0.1',
  port: 22,
  username: 'root',
};

describe('IncidentCaseManager', () => {
  let manager: IncidentCaseManager;

  beforeEach(() => {
    mocks.storage.clear();
    activeTargetContext.clear();
    activeTargetContext.activate(firstTarget);
    manager = new IncidentCaseManager();
  });

  it('keeps cases isolated by trusted target but continues across a reconnect', () => {
    const firstCase = manager.ensureActiveCase();
    manager.addIOC('ip', '192.0.2.10', 'test');

    activeTargetContext.activate({
      sessionId: 'root@10.0.0.2:22#one', hostKeyFingerprint: 'SHA256:second',
      host: '10.0.0.2', port: 22, username: 'root',
    });
    const secondCase = manager.ensureActiveCase();
    expect(secondCase.id).not.toBe(firstCase.id);
    expect(secondCase.iocs).toHaveLength(0);

    activeTargetContext.activate({ ...firstTarget, sessionId: 'root@10.0.0.1:22#two' });
    const reconnected = manager.ensureActiveCase();
    expect(reconnected.id).toBe(firstCase.id);
    expect(reconnected.iocs).toHaveLength(1);
    expect(stableTargetKey(reconnected.lastTarget)).toBe(stableTargetKey(firstTarget));
  });

  it('hashes the stored evidence preview and deduplicates the same artifact', async () => {
    const first = await manager.addEvidence({
      kind: 'finding', label: '可疑进程', source: 'quick-detection:process', preview: 'pid=42 cmd=/tmp/x',
    });
    const duplicate = await manager.addEvidence({
      kind: 'finding', label: '可疑进程', source: 'quick-detection:process', preview: 'pid=42 cmd=/tmp/x',
    });

    expect(first.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(first.hashScope).toBe('stored-preview');
    expect(duplicate.id).toBe(first.id);
    expect(manager.getActiveCase()?.evidence).toHaveLength(1);
  });

  it('deduplicates normalized IOC values without losing exact path casing', () => {
    const domain = manager.addIOC('domain', 'EVIL.EXAMPLE', 'one');
    const sameDomain = manager.addIOC('domain', 'evil.example', 'two');
    const upperPath = manager.addIOC('path', '/Tmp/X', 'one');
    const lowerPath = manager.addIOC('path', '/tmp/x', 'two');

    expect(sameDomain.id).toBe(domain.id);
    expect(lowerPath.id).not.toBe(upperPath.id);
    expect(manager.getActiveCase()?.iocs).toHaveLength(3);
  });

  it('exports a manifest with every evidence hash and exact collection session', async () => {
    await manager.addFinding({
      title: '异常账号', description: '发现 UID 0 别名', severity: 'critical', source: 'quick-detection:accounts',
    });
    const exported = JSON.parse(manager.exportActiveCase());

    expect(exported.schema).toBe('lovelyres-incident-case/v1');
    expect(exported.manifest.evidenceCount).toBe(1);
    expect(exported.manifest.evidenceHashes[0].sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(exported.case.evidence[0].target.sessionId).toBe(firstTarget.sessionId);
  });

  it('rejects invalid external artifact hashes instead of presenting them as verified', async () => {
    await expect(manager.addEvidence({
      kind: 'pcap', label: 'capture.pcap', source: 'packet-capture', externalSha256: 'not-a-hash',
    })).rejects.toThrow('64 位十六进制');
  });

  it('syncs only target-matched operation receipts into the case timeline', () => {
    manager.ensureActiveCase();
    const baseEntry = {
      id: 'op-1', timestamp: 10, source: 'baseline' as const, server: firstTarget.host,
      target: firstTarget, title: '关闭危险服务', command: 'systemctl disable x', output: 'ok',
      success: true, rolledBack: false,
    };
    const added = manager.syncOperationEntries([
      baseEntry,
      { ...baseEntry, id: 'op-other', target: { ...firstTarget, host: '10.0.0.9', hostKeyFingerprint: 'SHA256:other' } },
    ]);
    const duplicate = manager.syncOperationEntries([baseEntry]);

    expect(added).toBe(1);
    expect(duplicate).toBe(0);
    expect(manager.getActiveCase()?.timeline).toEqual(expect.arrayContaining([
      expect.objectContaining({ operationId: 'op-1', title: '处置成功：关闭危险服务', target: firstTarget }),
    ]));
    expect(manager.getActiveCase()?.timeline.some(event => event.operationId === 'op-other')).toBe(false);
  });
});
