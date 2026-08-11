import { isSameStableTarget, type TargetIdentity } from './targetContext';

export interface TargetBoundArtifact {
  target?: TargetIdentity;
}

/**
 * 本地元数据只有携带 SSH 指纹、主机、端口和账号，才允许在当前可信目标上使用。
 * 旧版 host-only 记录保留展示提示，但绝不自动归属到当前目标。
 */
export function isArtifactForTarget(
  artifact: TargetBoundArtifact,
  target: TargetIdentity | null,
): boolean {
  return !!artifact.target && !!target && isSameStableTarget(artifact.target, target);
}

export function targetDisplayName(target: TargetIdentity): string {
  return `${target.username}@${target.host}:${target.port} · ${target.hostKeyFingerprint}`;
}
