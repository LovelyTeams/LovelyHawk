import { describe, expect, it } from 'vitest';

import { isPotentiallyMutatingSql } from './databaseManager';

describe('database mutation classification', () => {
  it('allows well-known read-only queries without a danger prompt', () => {
    expect(isPotentiallyMutatingSql('-- inspect\nSELECT * FROM users', 'mysql')).toBe(false);
    expect(isPotentiallyMutatingSql('SHOW DATABASES', 'mysql')).toBe(false);
    expect(isPotentiallyMutatingSql('GET incident:key', 'redis')).toBe(false);
    expect(isPotentiallyMutatingSql('db.events.find({})', 'mongodb')).toBe(false);
  });

  it('treats mutations and ambiguous statements as dangerous', () => {
    expect(isPotentiallyMutatingSql('DROP DATABASE production', 'mysql')).toBe(true);
    expect(isPotentiallyMutatingSql('WITH victim AS (SELECT 1) DELETE FROM users', 'postgresql')).toBe(true);
    expect(isPotentiallyMutatingSql('FLUSHALL', 'redis')).toBe(true);
    expect(isPotentiallyMutatingSql('db.users.deleteMany({})', 'mongodb')).toBe(true);
    expect(isPotentiallyMutatingSql('', 'mysql')).toBe(true);
  });
});
