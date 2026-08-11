import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

describe('门禁：离线包不得依赖运行时下载', () => {
  it('does not load scripts, styles or fonts from a CDN', () => {
    const html = readFileSync('index.html', 'utf8');
    const cssEntries = [
      'src/css/main.css',
      'src/css/pages/_index.css',
      'src/css/components/_index.css',
    ].map(path => readFileSync(path, 'utf8')).join('\n');

    expect(html).not.toMatch(/<(?:script|link)[^>]+(?:src|href)=["']https?:\/\//i);
    expect(cssEntries).not.toMatch(/(?:@import\s+url|url)\(["']?https?:\/\//i);
  });

  it('keeps Java diagnostics offline instead of auto-downloading tools', () => {
    const source = readFileSync('src/modules/javaHotUpdate/javaHotUpdateManager.ts', 'utf8');
    expect(source).not.toMatch(/(?:curl|wget)[^\n]*(?:arthas|cfr|procyon)[^\n]*https?:\/\//i);
    expect(source).not.toContain('arthas.aliyun.com');
  });
});
