import { describe, expect, it } from 'vitest';

import { buildContainerRollback, isDockerActionVerified } from './dockerOperationContract';

describe('Docker mutation verification', () => {
  it('accepts only the state required by the requested action', () => {
    expect(isDockerActionVerified('start', 'running')).toBe(true);
    expect(isDockerActionVerified('restart', 'running')).toBe(true);
    expect(isDockerActionVerified('pause', 'paused')).toBe(true);
    expect(isDockerActionVerified('unpause', 'running')).toBe(true);
    expect(isDockerActionVerified('kill', 'dead')).toBe(true);
    expect(isDockerActionVerified('stop', 'exited')).toBe(true);
  });

  it('rejects missing, stale, and unexpected state readbacks', () => {
    expect(isDockerActionVerified('stop', 'running')).toBe(false);
    expect(isDockerActionVerified('start', 'exited')).toBe(false);
    expect(isDockerActionVerified('unknown', 'running')).toBe(false);
    expect(isDockerActionVerified('pause', null)).toBe(false);
  });

  it('only offers rollback when it restores the captured prior state', () => {
    expect(buildContainerRollback('stop', 'web; touch /tmp/pwn', 'running')).toEqual({
      command: "docker 'start' 'web; touch /tmp/pwn'",
      verifyCommand: "docker inspect --format '{{.State.Status}}' 'web; touch /tmp/pwn'",
      verifyExpected: 'running',
    });
    expect(buildContainerRollback('start', 'web', 'running')).toBeUndefined();
    expect(buildContainerRollback('kill', 'web', 'running')).toBeUndefined();
  });
});
