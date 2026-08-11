import { describe, expect, it } from 'vitest';

import { isArtifactForTarget } from './targetBoundArtifact';

const target = {
  sessionId: 'session-a',
  hostKeyFingerprint: 'SHA256:trusted',
  host: '10.0.0.7',
  port: 22,
  username: 'root',
};

describe('target-bound persisted artifacts', () => {
  it('allows the same fingerprint target after reconnect', () => {
    expect(isArtifactForTarget(
      { target },
      { ...target, sessionId: 'session-b' },
    )).toBe(true);
  });

  it('rejects legacy and lookalike targets', () => {
    expect(isArtifactForTarget({}, target)).toBe(false);
    expect(isArtifactForTarget({ target }, { ...target, username: 'admin' })).toBe(false);
    expect(isArtifactForTarget({ target }, { ...target, port: 2222 })).toBe(false);
    expect(isArtifactForTarget({ target }, { ...target, hostKeyFingerprint: 'SHA256:other' })).toBe(false);
  });
});
