import { describe, expect, it } from 'vitest';

import { evaluateTargetFeature, type TargetCapabilities } from './targetCapabilities';

function capabilities(overrides: Partial<TargetCapabilities> = {}): TargetCapabilities {
  return {
    schema: 'lovelyres-target-capabilities/v1',
    osId: 'alpine', osIdLike: '', osVersion: '3.20', prettyName: 'Alpine Linux',
    kernel: 'Linux', shell: '/bin/ash', uid: 1000, isRoot: false,
    sudoNonInteractive: false, doasNonInteractive: false, procfs: true,
    exec: true, sftp: false, pty: false, initSystem: 'openrc', tools: { ps: true, ss: true },
    probeError: null,
    probedAt: new Date(0).toISOString(),
    ...overrides,
  };
}

describe('target capability feature contract', () => {
  it('marks unsupported features N/A with an actionable alternative', () => {
    const result = evaluateTargetFeature(capabilities(), 'packet-capture');
    expect(result.available).toBe(false);
    expect(result.reason).toContain('tcpdump');
    expect(result.alternative).toContain('ss/netstat');
  });

  it('accepts equivalent tools and non-root privilege paths', () => {
    const target = capabilities({
      pty: true,
      sftp: true,
      sudoNonInteractive: true,
      tools: { ps: true, dumpcap: true, podman: true, crictl: true },
    });
    expect(evaluateTargetFeature(target, 'terminal').available).toBe(true);
    expect(evaluateTargetFeature(target, 'packet-capture').available).toBe(true);
    expect(evaluateTargetFeature(target, 'docker').available).toBe(true);
    expect(evaluateTargetFeature(target, 'kubernetes').available).toBe(true);
    expect(evaluateTargetFeature(target, 'baseline-mutation').available).toBe(true);
  });
});
