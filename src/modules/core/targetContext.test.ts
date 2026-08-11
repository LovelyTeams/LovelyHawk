import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { activeTargetContext } from './targetContext';

describe('activeTargetContext', () => {
  beforeEach(() => {
    activeTargetContext.clear();
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-08-09T00:00:00Z'));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('increments the epoch only when the backend session changes', () => {
    const first = activeTargetContext.activate({
      sessionId: 'root@10.0.0.1:22#one', hostKeyFingerprint: 'SHA256:first', host: '10.0.0.1', port: 22, username: 'root',
    });
    const refreshed = activeTargetContext.activate({
      sessionId: 'root@10.0.0.1:22#one', hostKeyFingerprint: 'SHA256:first', host: '10.0.0.1', port: 22, username: 'root',
    });
    const reconnected = activeTargetContext.activate({
      sessionId: 'root@10.0.0.1:22#two', hostKeyFingerprint: 'SHA256:first', host: '10.0.0.1', port: 22, username: 'root',
    });

    expect(refreshed.epoch).toBe(first.epoch);
    expect(reconnected.epoch).toBe(first.epoch + 1);
  });

  it('does not clear a newer session when stale cleanup arrives', () => {
    activeTargetContext.activate({
      sessionId: 'new-session', hostKeyFingerprint: 'SHA256:key', host: 'host', port: 22, username: 'root',
    });

    activeTargetContext.clear('old-session');

    expect(activeTargetContext.get()?.sessionId).toBe('new-session');
  });
});
