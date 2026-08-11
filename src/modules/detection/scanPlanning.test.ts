import { describe, expect, it } from 'vitest';

import {
  COMPETITION_TRIAGE_IDS,
  calculateCompleteness,
  calculateTrustedScore,
  normalizeOutcome,
  notApplicableReason,
  type ScorableDetectionItem,
} from './scanPlanning';

const completed = (score: number, passed = score === 100): ScorableDetectionItem => ({
  status: 'completed',
  result: { passed, score, findings: [] },
});

describe('scan planning and scoring', () => {
  it('does not lower a normal host score for unavailable K8s checks', () => {
    const items: ScorableDetectionItem[] = [
      completed(100),
      { status: 'not-applicable', result: { passed: false, score: 0, outcome: 'not-applicable', findings: [] } },
      { status: 'failed' },
    ];

    expect(calculateTrustedScore(items)).toBe(100);
    expect(calculateCompleteness(3, items)).toEqual({
      planned: 3, completed: 1, failed: 1, notApplicable: 1, processedPercent: 100,
    });
  });

  it('classifies detector errors separately from security failures', () => {
    const detectorError: ScorableDetectionItem = {
      status: 'completed',
      result: { passed: false, score: 0, findings: [{ severity: 'info', title: '检测失败' }] },
    };
    expect(normalizeOutcome(detectorError)).toBe('error');
    expect(normalizeOutcome(completed(40, false))).toBe('failed');
  });

  it('plans environment-dependent checks as N/A', () => {
    const environment = { kubernetes: false, webRoot: false, containerRuntime: false, checkedAt: 1 };
    expect(notApplicableReason('k8s-rbac-audit', environment)).toContain('Kubernetes');
    expect(notApplicableReason('webshell-scan', environment)).toContain('Web');
    expect(notApplicableReason('ssh-audit', environment)).toBeNull();
  });

  it('keeps the first-minute preset small and free of stress or K8s checks', () => {
    expect(COMPETITION_TRIAGE_IDS).toHaveLength(8);
    expect(COMPETITION_TRIAGE_IDS.some(id => id.startsWith('k8s-'))).toBe(false);
    expect(COMPETITION_TRIAGE_IDS.some(id => id.endsWith('-test'))).toBe(false);
  });
});
