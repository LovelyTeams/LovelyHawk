import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

const read = (path: string) => readFileSync(path, 'utf8');

describe('command history replay safety wiring gate', () => {
  const manager = read('src/modules/utils/commandHistoryManager.ts');
  const historyModal = read('src/modules/ui/commandHistoryModal.ts');
  const emergencyModal = read('src/modules/ui/emergencyModal.ts');
  const emergencyPage = read('src/modules/emergency/emergencyPageManager.ts');

  it('keeps persisted history bound to target, digest, risk and source', () => {
    expect(manager).toContain('schemaVersion: 2');
    expect(manager).toContain('const digest = await commandSha256(normalizedCommand)');
    expect(manager).toContain('commandSha256: digest');
    expect(manager).toContain('isSameStableTarget(item.target, activeTarget)');
    expect(manager).toContain('currentRisk !== item.risk');
  });

  it('does not restore timer-driven auto execution or unbound SSH fallbacks', () => {
    expect(historyModal).not.toContain("executeBtn.click()");
    expect(historyModal).toContain('CommandHistoryManager.assessReplay(item)');
    expect(emergencyModal).toContain("this.executeCommand('command-history-replay')");
    expect(emergencyModal).toContain("title: '确认执行可写命令'");
    expect(emergencyPage).not.toContain('sshManager.executeCommand(command)');
    expect(emergencyPage).toContain("'emergency-page'");
  });
});
