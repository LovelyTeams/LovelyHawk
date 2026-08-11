import { describe, expect, it } from 'vitest';

import { DetectionReportRenderer } from './detectionReportRenderer';
import type { DetectionItem } from './quickDetectionManager';

describe('DetectionReportRenderer', () => {
  it('keeps remote finding text out of inline executable handlers', () => {
    const renderer = new DetectionReportRenderer();
    const payload = `'); window.__pwned = true; // <img src=x onerror=alert(1)>`;
    const item: DetectionItem = {
      id: 'user-audit',
      name: '账号审计',
      description: 'test',
      category: 'security',
      status: 'completed',
      result: {
        passed: false,
        score: 0,
        severity: 'critical',
        duration: 1,
        timestamp: new Date(0),
        rawOutput: { payload },
        findings: [{
          title: payload,
          description: payload,
          severity: 'critical',
          recommendation: payload,
        }],
      },
    };

    const html = renderer.renderReportItem(item);

    expect(html).not.toContain('onclick=');
    expect(html).not.toContain('<img src=x');
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
    expect(html).toContain('data-report-action="user-disposal"');
    expect(html).toContain('data-report-action="ai-solution"');
  });
});
