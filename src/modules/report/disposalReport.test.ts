import { describe, expect, it } from 'vitest';

import {
  buildDisposalMarkdown,
  buildDisposalHtml,
  summarizeEntries,
  formatTimestamp,
  type DisposalReportInput,
} from './disposalReport';
import type { OperationEntry } from '../core/operationJournal';

function entry(over: Partial<OperationEntry> = {}): OperationEntry {
  return {
    id: 'op_1',
    timestamp: new Date('2026-07-20T10:00:00').getTime(),
    source: 'baseline',
    server: '10.0.0.1',
    title: '关闭 SSH root 登录',
    command: "sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
    restoreCommand: "sed -i 's/^PermitRootLogin no/PermitRootLogin yes/' /etc/ssh/sshd_config",
    output: 'ok',
    success: true,
    rolledBack: false,
    ...over,
  };
}

const base: DisposalReportInput = {
  server: '10.0.0.1',
  generatedAt: new Date('2026-07-20T12:30:45'),
  entries: [entry()],
};

describe('summarizeEntries', () => {
  it('区分成功/失败/已回滚/仍可回滚', () => {
    const s = summarizeEntries([
      entry({ id: '1', success: true, rolledBack: false }),
      entry({ id: '2', success: false, rolledBack: false }),
      entry({ id: '3', success: true, rolledBack: true }),
      entry({ id: '4', success: true, restoreCommand: undefined }), // 无回滚命令
    ]);
    expect(s.total).toBe(4);
    expect(s.succeeded).toBe(3);
    expect(s.failed).toBe(1);
    expect(s.rolledBack).toBe(1);
    // 仍可回滚 = 有 restoreCommand 且尚未回滚
    expect(s.revertible).toBe(2);
  });

  it('按来源归类计数', () => {
    const s = summarizeEntries([
      entry({ id: '1', source: 'baseline' }),
      entry({ id: '2', source: 'baseline' }),
      entry({ id: '3', source: 'firewall' }),
    ]);
    expect(s.bySource.get('baseline')).toBe(2);
    expect(s.bySource.get('firewall')).toBe(1);
  });
});

describe('buildDisposalMarkdown', () => {
  it('包含主机、统计与处置命令', () => {
    const md = buildDisposalMarkdown(base);
    expect(md).toContain('# 处置交付报告');
    expect(md).toContain('10.0.0.1');
    expect(md).toContain('2026-07-20 12:30:45');
    expect(md).toContain('关闭 SSH root 登录');
    expect(md).toContain('PermitRootLogin no');
    expect(md).toContain('回滚命令');
  });

  it('无回滚命令的条目明确标注不可撤销', () => {
    const md = buildDisposalMarkdown({ ...base, entries: [entry({ restoreCommand: undefined })] });
    expect(md).toContain('未登记回滚命令');
    expect(md).not.toContain('回滚命令：');
  });

  it('处置记录按时间正序排列，形成时间线', () => {
    const md = buildDisposalMarkdown({
      ...base,
      entries: [
        entry({ id: 'b', title: '后做的', timestamp: 2000 }),
        entry({ id: 'a', title: '先做的', timestamp: 1000 }),
      ],
    });
    expect(md.indexOf('先做的')).toBeLessThan(md.indexOf('后做的'));
  });

  it('表格单元格里的竖线与换行不会撑破 Markdown 表格', () => {
    const md = buildDisposalMarkdown({
      ...base,
      detection: {
        timestamp: new Date('2026-07-20T11:00:00'),
        overallScore: 72,
        findings: [{
          title: 'a | b',
          description: '第一行\n第二行',
          severity: 'high',
        }],
      },
    });
    const row = md.split('\n').find(l => l.includes('a \\| b'));
    expect(row, '竖线应被转义').toBeTruthy();
    // 该行必须仍是单行表格行（描述里的换行已被压平）
    expect(row).toContain('第一行 第二行');
  });

  it('没有检测数据时只输出处置记录，章节编号相应调整', () => {
    const md = buildDisposalMarkdown(base);
    expect(md).not.toContain('一、检测结果');
    expect(md).toContain('一、处置记录');

    const withDetection = buildDisposalMarkdown({
      ...base,
      detection: { timestamp: new Date(), overallScore: 90, findings: [] },
    });
    expect(withDetection).toContain('一、检测结果');
    expect(withDetection).toContain('二、处置记录');
  });
});

describe('buildDisposalHtml', () => {
  it('产出自包含文档，零外链（赛场断网约束）', () => {
    const html = buildDisposalHtml(base);
    expect(html).toContain('<!DOCTYPE html>');
    // 不得引用任何外部资源
    expect(html).not.toMatch(/<link[^>]+href=["']https?:/i);
    expect(html).not.toMatch(/<script[^>]+src=/i);
    expect(html).not.toMatch(/@import\s+url\(/i);
    expect(html).not.toMatch(/url\(\s*["']?https?:/i);
  });

  it('转义命令与标题里的 HTML，防止靶机数据破坏报告结构', () => {
    const html = buildDisposalHtml({
      ...base,
      entries: [entry({
        title: '<img src=x onerror=alert(1)>',
        command: 'echo "</pre><script>alert(1)</script>"',
      })],
    });
    expect(html).not.toContain('<img src=x');
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain('&lt;img src=x');
  });

  it('带打印样式，便于直接交卷', () => {
    expect(buildDisposalHtml(base)).toContain('@media print');
  });

  it('未回滚/已回滚/失败三种状态有区分样式', () => {
    const html = buildDisposalHtml({
      ...base,
      entries: [
        entry({ id: '1', success: true, rolledBack: false }),
        entry({ id: '2', success: false }),
        entry({ id: '3', rolledBack: true }),
      ],
    });
    expect(html).toContain('entry ok');
    expect(html).toContain('entry fail');
    expect(html).toContain('entry rolled');
  });

  it('空处置记录时给出明确文案而不是空白', () => {
    const html = buildDisposalHtml({ ...base, entries: [] });
    expect(html).toContain('本次未产生任何变更记录');
  });
});

describe('formatTimestamp', () => {
  it('补零到秒', () => {
    expect(formatTimestamp(new Date('2026-01-02T03:04:05'))).toBe('2026-01-02 03:04:05');
  });
});
