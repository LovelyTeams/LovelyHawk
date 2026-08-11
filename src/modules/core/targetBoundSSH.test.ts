import { beforeEach, describe, expect, it, vi } from 'vitest';

import { activeTargetContext } from './targetContext';
import { invokeTargetBoundSSH } from './targetBoundSSH';

const firstTarget = {
  sessionId: 'root@10.0.0.1:22#first',
  hostKeyFingerprint: 'SHA256:first',
  host: '10.0.0.1',
  port: 22,
  username: 'root',
};

describe('invokeTargetBoundSSH', () => {
  beforeEach(() => activeTargetContext.clear());

  it('refuses to execute without an active target', async () => {
    const invokeFn = vi.fn();

    await expect(invokeTargetBoundSSH(
      'ssh_execute_command_direct',
      { command: 'id' },
      invokeFn,
    )).rejects.toThrow('没有已确认的活动 SSH 目标');
    expect(invokeFn).not.toHaveBeenCalled();
  });

  it('binds the captured session explicitly', async () => {
    activeTargetContext.activate(firstTarget);
    const invokeFn = vi.fn().mockResolvedValue({ output: 'ok', exit_code: 0 });

    await invokeTargetBoundSSH('ssh_execute_command_direct', { command: 'id' }, invokeFn);

    expect(invokeFn).toHaveBeenCalledWith('ssh_execute_command_direct', {
      command: 'id',
      sessionId: firstTarget.sessionId,
    });
  });

  it('discards a result when the active target changes in flight', async () => {
    activeTargetContext.activate(firstTarget);
    let resolveInvoke: ((value: unknown) => void) | undefined;
    const invokeFn: any = vi.fn(() => new Promise(resolve => { resolveInvoke = resolve; }));
    const pending = invokeTargetBoundSSH(
      'ssh_execute_command_direct',
      { command: 'sleep 1' },
      invokeFn,
    );

    activeTargetContext.activate({
      ...firstTarget,
      sessionId: 'root@10.0.0.2:22#second',
      host: '10.0.0.2',
      hostKeyFingerprint: 'SHA256:second',
    });
    resolveInvoke?.({ output: 'stale', exit_code: 0 });

    await expect(pending).rejects.toThrow('活动目标已变化');
  });
});
