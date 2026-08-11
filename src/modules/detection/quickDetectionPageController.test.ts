import { describe, expect, it } from 'vitest';

import { renderFindingCards } from './quickDetectionPageController';
import type { DetectionReport } from './quickDetectionManager';

function reportWithFinding(severity: 'critical' | 'high'): DetectionReport {
  return {
    id: 'report-1',
    timestamp: new Date('2026-08-09T00:00:00Z'),
    server: 'root@10.0.0.1:22',
    overallScore: 20,
    totalDuration: 100,
    summary: { critical: severity === 'critical' ? 1 : 0, high: severity === 'high' ? 1 : 0, medium: 0, low: 0, info: 0 },
    items: [{
      id: 'firewall-check',
      name: '防火墙检查',
      description: '检查防火墙',
      category: 'security',
      status: 'completed',
      result: {
        passed: false,
        score: 20,
        severity,
        findings: [{
          title: '<img src=x onerror=alert(1)>',
          description: '<script>remote-controlled</script>',
          severity,
        }],
        duration: 100,
        timestamp: new Date('2026-08-09T00:00:00Z'),
      },
    }],
  };
}

describe('quick detection result renderer', () => {
  it('escapes attacker-controlled finding content and wires fix actions', () => {
    const html = renderFindingCards(reportWithFinding('critical'), 'all');

    expect(html).not.toContain('<img src=x');
    expect(html).not.toContain('<script>');
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
    expect(html).toContain('data-qd-action="fix-one"');
    expect(html).toContain('data-qd-action="reverify"');
  });

  it('applies the selected severity filter', () => {
    expect(renderFindingCards(reportWithFinding('high'), 'critical')).toContain('该级别暂无风险项');
    expect(renderFindingCards(reportWithFinding('high'), 'high')).toContain('severity-high');
  });
});
