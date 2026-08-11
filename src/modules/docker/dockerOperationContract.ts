import { shq } from '../core/shellEscape';

const EXPECTED_STATES: Record<string, string[]> = {
  start: ['running'],
  stop: ['exited'],
  restart: ['running'],
  kill: ['exited', 'dead'],
  pause: ['paused'],
  unpause: ['running'],
};

export function isDockerActionVerified(action: string, state?: string | null): boolean {
  return !!state && (EXPECTED_STATES[action]?.includes(state.toLowerCase()) ?? false);
}

export function buildContainerRollback(action: string, ref: string, beforeState?: string): {
  command: string;
  verifyCommand: string;
  verifyExpected: string;
} | undefined {
  const restoreAction: Record<string, string> = {
    start: 'stop',
    stop: 'start',
    pause: 'unpause',
    unpause: 'pause',
  };
  const reversibleFrom: Record<string, string[]> = {
    start: ['created', 'exited', 'dead'],
    stop: ['running'],
    pause: ['running'],
    unpause: ['paused'],
  };
  const restore = restoreAction[action];
  if (!restore || !beforeState || !reversibleFrom[action]?.includes(beforeState.toLowerCase())) return undefined;
  return {
    command: `docker ${shq(restore)} ${shq(ref)}`,
    verifyCommand: `docker inspect --format '{{.State.Status}}' ${shq(ref)}`,
    verifyExpected: EXPECTED_STATES[restore]?.[0] || '',
  };
}
