export interface TargetContext {
  sessionId: string;
  hostKeyFingerprint: string;
  host: string;
  port: number;
  username: string;
  epoch: number;
  connectedAt: number;
}

export type TargetIdentity = Pick<TargetContext, 'sessionId' | 'hostKeyFingerprint' | 'host' | 'port' | 'username'>;

/** 跨 SSH 重连识别同一可信目标；精确执行仍应使用 matches() 校验会话。 */
export function stableTargetKey(target: TargetIdentity): string {
  return [target.hostKeyFingerprint, target.host, target.port, target.username]
    .map(part => encodeURIComponent(String(part)))
    .join('|');
}

export function isSameStableTarget(left: TargetIdentity, right: TargetIdentity): boolean {
  return stableTargetKey(left) === stableTargetKey(right);
}

export interface BackendSSHConnectionStatus {
  connected: boolean;
  session_id: string;
  host_key_fingerprint: string;
  host: string;
  port: number;
  username: string;
  last_activity: string;
}

export function targetIdentityFromBackend(status: BackendSSHConnectionStatus): TargetIdentity {
  return {
    sessionId: status.session_id,
    hostKeyFingerprint: status.host_key_fingerprint,
    host: status.host,
    port: status.port,
    username: status.username,
  };
}

class ActiveTargetContext {
  private current: TargetContext | null = null;
  private epoch = 0;

  activate(identity: TargetIdentity): TargetContext {
    if (this.current?.sessionId === identity.sessionId) {
      this.current = { ...this.current, ...identity };
      return { ...this.current };
    }

    this.epoch += 1;
    this.current = {
      ...identity,
      epoch: this.epoch,
      connectedAt: Date.now(),
    };
    return { ...this.current };
  }

  get(): TargetContext | null {
    return this.current ? { ...this.current } : null;
  }

  matches(identity: TargetIdentity): boolean {
    return !!this.current
      && this.current.sessionId === identity.sessionId
      && this.current.hostKeyFingerprint === identity.hostKeyFingerprint
      && this.current.host === identity.host
      && this.current.port === identity.port
      && this.current.username === identity.username;
  }

  clear(sessionId?: string): void {
    if (!sessionId || this.current?.sessionId === sessionId) {
      this.current = null;
    }
  }
}

export const activeTargetContext = new ActiveTargetContext();
