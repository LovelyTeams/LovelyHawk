import { describe, expect, it, vi } from 'vitest';
import type { AppState } from '../../core/app';

describe('SystemInfoRenderer investigation navigation', () => {
  it('keeps all investigation views without rendering the legacy sidebar subtree', async () => {
    vi.stubGlobal('window', {});
    const { SystemInfoRenderer } = await import('./systemInfoRenderer');
    const renderer = new SystemInfoRenderer();
    const html = renderer.renderSystemInfo({
      serverInfo: { detailedInfo: { processes: [{ pid: 1 }] } },
    } as AppState);

    const tabIds = Array.from(html.matchAll(/data-system-tab="([^"]+)"/g), match => match[1]);
    expect(new Set(tabIds).size).toBe(25);
    expect(html).toContain('class="si-lensbar"');
    expect(html).not.toContain('class="si-lens-current"');
    expect(html).not.toContain('sidebar-subitem');
    const navigatorHtml = html.split('<div class="system-info-content"')[0];
    expect(navigatorHtml).not.toContain('onclick=');
  });

  it('does not repeat the title total in the stat chips', async () => {
    vi.stubGlobal('window', {});
    const { SystemInfoRenderer } = await import('./systemInfoRenderer');
    const renderer = new SystemInfoRenderer();
    const html = renderer.renderSystemInfoTab({} as AppState, 'envvars');

    expect(html).toContain('id="envvars-title-count"');
    expect(html).not.toContain('id="envvars-chip-total-wrap"');
    expect(html).toContain('id="envvars-chip-high-wrap"');
    expect(html).toContain('id="envvars-chip-warn-wrap"');
  });
});
