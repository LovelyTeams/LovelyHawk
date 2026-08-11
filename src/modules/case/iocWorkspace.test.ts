import { describe, expect, it } from 'vitest';

import { inferIOCType, normalizeIOCValues } from './iocWorkspace';

describe('IOC workspace', () => {
  it('classifies common competition indicators', () => {
    expect(inferIOCType('192.0.2.10')).toBe('ip');
    expect(inferIOCType('2001:db8::1')).toBe('ip');
    expect(inferIOCType('evil.example.com')).toBe('domain');
    expect(inferIOCType('a'.repeat(64))).toBe('hash');
    expect(inferIOCType('/tmp/.x')).toBe('path');
    expect(inferIOCType('suspicious-process')).toBe('other');
  });

  it('deduplicates case-insensitive indicators while preserving path casing', () => {
    expect(normalizeIOCValues([
      ' EVIL.EXAMPLE.COM ',
      'evil.example.com',
      '/Tmp/X',
      '/tmp/x',
      '',
    ])).toEqual(['EVIL.EXAMPLE.COM', '/Tmp/X', '/tmp/x']);
  });

  it('does not classify malformed IPv4 values as IP addresses', () => {
    expect(inferIOCType('999.2.3.4')).toBe('other');
    expect(inferIOCType('1.2.3')).toBe('other');
  });
});
