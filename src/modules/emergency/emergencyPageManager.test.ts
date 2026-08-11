import { describe, expect, it } from 'vitest';

import { accountsForTarget, type SavedEmergencyConnection } from './emergencyPageManager';

const target = {
  sessionId: 'analyst@192.0.2.20:2222#one',
  hostKeyFingerprint: 'SHA256:current',
  host: '192.0.2.20',
  port: 2222,
  username: 'analyst',
};

describe('emergency account target selection', () => {
  const connections: SavedEmergencyConnection[] = [
    {
      host: '192.0.2.10', port: 22, username: 'root', host_key_fingerprint: 'SHA256:first',
      accounts: [{ username: 'wrong-first-account' }],
    },
    {
      host: target.host, port: target.port, username: target.username,
      host_key_fingerprint: target.hostKeyFingerprint,
      accounts: [{ username: 'analyst' }, { username: 'root', is_default: true }],
    },
  ];

  it('uses the current target rather than the first saved connection', () => {
    expect(accountsForTarget(connections, target).map(account => account.username)).toEqual(['analyst', 'root']);
  });

  it('rejects a saved connection whose host fingerprint no longer matches', () => {
    const changedKey = [{ ...connections[1], host_key_fingerprint: 'SHA256:changed' }];
    expect(accountsForTarget(changedKey, target)).toEqual([]);
  });

  it('accepts a secondary account as the active SSH identity', () => {
    const secondaryTarget = { ...target, username: 'root' };
    expect(accountsForTarget(connections, secondaryTarget)).toHaveLength(2);
  });
});
