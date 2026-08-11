import { describe, expect, it } from 'vitest';

import { CIS_RULES, MLPS2_RULES, generateComplianceSummary } from './complianceRules';

const supportedDetectionIds = new Set([
  'password-policy', 'sudo-audit', 'pam-config', 'account-lockout',
  'selinux-status', 'kernel-params', 'unnecessary-services', 'audit-config',
  'ssh-audit', 'firewall-check', 'backdoor-scan', 'file-permission',
  'log-analysis', 'webshell-scan', 'rootkit-scan', 'persistence-scan', 'log-tamper',
]);

describe('compliance rule mapping', () => {
  it('maps every rule to a real quick-detection id', () => {
    for (const rule of [...CIS_RULES, ...MLPS2_RULES]) {
      expect(supportedDetectionIds.has(rule.detectionItemId), rule.id).toBe(true);
      expect(rule.detectionItemId).not.toContain('_');
    }
  });

  it('counts mapped results instead of leaving every rule pending', () => {
    const summary = generateComplianceSummary('cis', new Map([
      ['ssh-audit', true],
      ['firewall-check', false],
    ]));

    expect(summary.passed).toBe(1);
    expect(summary.failed).toBe(1);
    expect(summary.pending).toBe(CIS_RULES.length - 2);
  });
});
