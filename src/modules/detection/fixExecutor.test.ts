import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { FixAction } from './fixExecutor';
import { fixExecutor, type ResolvedBaselineItem } from './fixExecutor';

const mocks = vi.hoisted(() => ({
  execute: vi.fn(),
  journalRecord: vi.fn(),
  historyAdd: vi.fn(),
}));

vi.mock('../emergency/commandExecution', () => ({
  executeEmergencyCommand: mocks.execute,
}));
vi.mock('../core/operationJournal', () => ({
  operationJournal: { record: mocks.journalRecord },
}));
vi.mock('./fixHistoryManager', () => ({
  fixHistoryManager: { addEntry: mocks.historyAdd, rollback: vi.fn() },
}));

const action = (): FixAction => ({
  id: 'fix-action-1',
  detectionItemId: 'ssh-audit',
  findingTitle: '配置不安全',
  def: {
    type: 'baseline', title: '修复测试配置', description: '测试',
    baselineItemId: 'test-config', recommendedValue: 'yes', priority: 1,
  },
  status: 'pending',
});

const resolved: ResolvedBaselineItem = {
  id: 'test-config',
  filePath: '/etc/test.conf',
  readCommand: 'read-test-config',
  writeCommand: value => `write-test-config ${value}`,
  parseRegex: 'VALUE=(\\w+)',
  backupCommand: 'legacy-timestamp-backup',
  recommendedValue: 'yes',
};

function success(output: string) {
  return {
    command: 'test', output, exit_code: 0, duration_ms: 1, timed_out: false,
    kind: output ? 'success' : 'empty', success: true, message: '执行完成',
  };
}

describe('FixExecutor receipts', () => {
  beforeEach(() => {
    mocks.execute.mockReset();
    mocks.journalRecord.mockReset();
    mocks.historyAdd.mockReset();
    fixExecutor.setServer('10.0.0.1');
  });

  it('creates an exact backup/restore receipt and verifies the read-back value', async () => {
    mocks.execute
      .mockResolvedValueOnce(success('VALUE=no'))
      .mockResolvedValueOnce(success('present'))
      .mockResolvedValueOnce(success('written'))
      .mockResolvedValueOnce(success('VALUE=yes'));

    const result = await fixExecutor.executeFix(action(), resolved);

    expect(result.success).toBe(true);
    expect(mocks.execute.mock.calls[1][0].command).toContain("cp -p -- '/etc/test.conf'");
    expect(mocks.execute.mock.calls[1][0].command).toContain('.lovelyres.');
    expect(mocks.journalRecord).toHaveBeenCalledWith(expect.objectContaining({
      success: true,
      backupInfo: expect.stringContaining('/etc/test.conf.lovelyres.'),
      restoreCommand: expect.stringContaining("'/etc/test.conf'"),
      beforeValue: 'no',
      afterValue: 'yes',
    }));
  });

  it('records a failed receipt when read-back verification differs', async () => {
    mocks.execute
      .mockResolvedValueOnce(success('VALUE=no'))
      .mockResolvedValueOnce(success('present'))
      .mockResolvedValueOnce(success('written'))
      .mockResolvedValueOnce(success('VALUE=no'));

    const result = await fixExecutor.executeFix(action(), resolved);

    expect(result.success).toBe(false);
    expect(result.output).toContain('读回验证不一致');
    expect(mocks.journalRecord).toHaveBeenCalledWith(expect.objectContaining({
      success: false,
      restoreCommand: expect.stringContaining('cp -p --'),
    }));
  });
});
