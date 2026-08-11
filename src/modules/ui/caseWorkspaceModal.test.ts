import { describe, expect, it } from 'vitest';

import type { IncidentCase } from '../case/incidentCaseManager';
import { renderCaseWorkspaceContent } from './caseWorkspaceModal';

describe('case workspace renderer', () => {
  it('escapes attacker-controlled target and evidence fields', () => {
    const target = {
      sessionId: '<img src=x onerror=1>', hostKeyFingerprint: 'SHA256:<script>',
      host: '<svg onload=1>', port: 22, username: 'root" autofocus',
    };
    const incident: IncidentCase = {
      id: 'case-1', title: '<img src=x onerror=1>', status: 'open', targetKey: 'key',
      target, lastTarget: target, createdAt: 1, updatedAt: 1,
      iocs: [{ id: 'ioc-1', type: 'domain', value: '<script>alert(1)</script>', source: '<source>', addedAt: 1, target }],
      evidence: [{
        id: 'ev-1', kind: 'finding', label: '<img src=x>', source: '<source>', preview: '<payload>',
        sha256: 'a'.repeat(64), hashScope: 'stored-preview', collectedAt: 1, target,
      }],
      timeline: [{ id: 'event-1', type: 'finding', title: '<b>finding</b>', source: '<source>', timestamp: 1, target }],
    };

    const html = renderCaseWorkspaceContent(incident, [incident]);
    expect(html).not.toContain('<script>');
    expect(html).not.toContain('<img src=x');
    expect(html).not.toContain('<svg onload=1>');
    expect(html).toContain('&lt;script&gt;');
    expect(html).toContain('&lt;b&gt;finding&lt;/b&gt;');
  });
});
