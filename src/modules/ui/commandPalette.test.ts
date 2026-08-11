import { describe, expect, it } from 'vitest';

import { commandPalettePages } from './commandPalette';

const primaryNavigationPages = [
  'system-info',
  'docker',
  'kubernetes',
  'secfix',
  'quick-detection',
  'emergency-commands',
  'firewall',
  'integrity',
  'snapshot',
  'packet-capture',
  'log-analysis',
  'check-audit',
  'database',
  'java-hot-update',
  'baseline-quick-edit',
  'batch-servers',
  'notes',
  'ai-history',
];

describe('command palette catalog', () => {
  it('covers every primary navigation page', () => {
    const ids = new Set(commandPalettePages.map(page => page.id));
    expect(primaryNavigationPages.filter(id => !ids.has(id))).toEqual([]);
  });

  it('keeps the eight competition shortcuts unique and contiguous', () => {
    expect(commandPalettePages.slice(0, 8).map(page => page.shortcut)).toEqual([
      'Ctrl+1', 'Ctrl+2', 'Ctrl+3', 'Ctrl+4', 'Ctrl+5', 'Ctrl+6', 'Ctrl+7', 'Ctrl+8',
    ]);
    expect(new Set(commandPalettePages.map(page => page.id)).size).toBe(commandPalettePages.length);
  });
});
