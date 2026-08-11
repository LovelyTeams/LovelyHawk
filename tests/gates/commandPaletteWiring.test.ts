import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

const source = readFileSync('src/modules/ui/commandPalette.ts', 'utf8');

describe('command palette competition workflow gate', () => {
  it('keeps emergency-command search lazy and navigation-only', () => {
    expect(source).toContain("await import('../emergency/commands')");
    expect(source).toContain("switchPage?.('emergency-commands')");
    expect(source).toContain('manager.selectCommand(commandId)');
    expect(source).toContain('仅定位，不自动执行');
    expect(source).not.toContain('executeCommand(commandId)');
  });
});
