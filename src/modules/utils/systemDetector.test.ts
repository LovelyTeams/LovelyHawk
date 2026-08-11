import { beforeEach, describe, expect, it, vi } from 'vitest';

import { activeTargetContext } from '../core/targetContext';
import { SystemDetector, type SystemInfo } from './systemDetector';

const invokeMock = vi.hoisted(() => vi.fn());
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));

const firstTarget = {
  sessionId: 'root@192.0.2.10:22#one',
  hostKeyFingerprint: 'SHA256:first',
  host: '192.0.2.10',
  port: 22,
  username: 'root',
};

const ubuntu: SystemInfo = {
  type: 'ubuntu', name: 'Ubuntu', version: '24.04', prettyName: 'Ubuntu 24.04',
  packageManager: 'apt', initSystem: 'systemd',
};

const alpine: SystemInfo = {
  type: 'alpine', name: 'Alpine', version: '3.21', prettyName: 'Alpine Linux 3.21',
  packageManager: 'apk', initSystem: 'openrc',
};

describe('SystemDetector target isolation', () => {
  beforeEach(() => {
    invokeMock.mockReset();
    activeTargetContext.clear();
    SystemDetector.clearCache();
  });

  it('does not reuse one host distribution for another target', async () => {
    invokeMock.mockResolvedValueOnce(ubuntu).mockResolvedValueOnce(alpine);
    activeTargetContext.activate(firstTarget);
    expect(await SystemDetector.detectSystem()).toEqual(ubuntu);

    const secondTarget = {
      ...firstTarget,
      sessionId: 'root@192.0.2.11:22#two',
      hostKeyFingerprint: 'SHA256:second',
      host: '192.0.2.11',
    };
    activeTargetContext.activate(secondTarget);
    expect(await SystemDetector.detectSystem()).toEqual(alpine);

    expect(invokeMock).toHaveBeenNthCalledWith(1, 'detect_system_type', { sessionId: firstTarget.sessionId });
    expect(invokeMock).toHaveBeenNthCalledWith(2, 'detect_system_type', { sessionId: secondTarget.sessionId });
  });

  it('may reuse detection after reconnecting to the same fingerprinted target', async () => {
    invokeMock.mockResolvedValue(ubuntu);
    activeTargetContext.activate(firstTarget);
    await SystemDetector.detectSystem();
    activeTargetContext.activate({ ...firstTarget, sessionId: 'root@192.0.2.10:22#reconnected' });

    expect(await SystemDetector.detectSystem()).toEqual(ubuntu);
    expect(invokeMock).toHaveBeenCalledTimes(1);
  });

  it('rejects a result when the active target changes in flight', async () => {
    activeTargetContext.activate(firstTarget);
    invokeMock.mockImplementationOnce(async () => {
      activeTargetContext.activate({
        ...firstTarget,
        sessionId: 'root@192.0.2.11:22#two',
        hostKeyFingerprint: 'SHA256:second',
        host: '192.0.2.11',
      });
      return ubuntu;
    });

    await expect(SystemDetector.detectSystem()).rejects.toThrow('系统检测期间活动目标已变化');
  });
});
