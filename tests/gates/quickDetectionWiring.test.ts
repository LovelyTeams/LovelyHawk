import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const renderer = readFileSync('src/modules/ui/renderers/emergencyRenderer.ts', 'utf8');
const controller = readFileSync('src/modules/detection/quickDetectionPageController.ts', 'utf8');

function values(source: string, pattern: RegExp): Set<string> {
  return new Set([...source.matchAll(pattern)].map(match => match[1]));
}

describe('quick detection wiring gate', () => {
  it('requires every rendered action to have a controller case', () => {
    const renderedActions = values(`${renderer}\n${controller}`, /data-qd-action=\\?"([^"\\]+)\\?"/g);
    const handledActions = values(controller, /case '([^']+)'/g);
    const missing = [...renderedActions].filter(action => !handledActions.has(action));

    expect(missing, `未接线的 data-qd-action: ${missing.join(', ')}`).toEqual([]);
  });

  it('requires every rendered tab to have a matching panel', () => {
    const tabs = values(renderer, /data-qd-tab="([^"]+)"/g);
    const panels = values(renderer, /id="qd-tab-([^"]+)"/g);
    const missing = [...tabs].filter(tab => !panels.has(tab));

    expect(missing, `缺少面板的 data-qd-tab: ${missing.join(', ')}`).toEqual([]);
  });
});
