/**
 * 处置交付报告
 *
 * 线下防御赛通常要交一份书面加固说明：做了哪些检测、发现了什么、动了哪些地方、
 * 怎么撤回。这些数据本来就齐了，只是散在两处：
 *
 *  - core/operationJournal —— 所有可回滚变更的唯一汇总（基线 / 检测修复 / 账号 /
 *    防火墙 / 完整性 / 快照 / 手动 七类），每条带命令与 restoreCommand
 *  - detection/quickDetectionManager —— 最近一次检测报告（评分 + findings）
 *
 * 这里把两者合并成一份可交付文档。输出两种格式：
 *  - Markdown：贴题解 / 提交平台
 *  - HTML：直接打印或交卷，自包含、零外链（赛场断网，见 frontend_offline_assets 约定）
 *
 * 构建逻辑是纯函数（buildDisposalMarkdown / buildDisposalHtml），可单测；
 * 触发下载的部分才碰 DOM。
 */

import { escapeHtml } from '../core/htmlEscape';
import { opSourceLabel, type OperationEntry } from '../core/operationJournal';

/** 报告输入。刻意不直接依赖 operationJournal / quickDetectionManager 单例，方便测试与复用 */
export interface DisposalReportInput {
  server: string;
  generatedAt: Date;
  entries: OperationEntry[];
  detection?: {
    timestamp: Date;
    overallScore: number;
    findings: Array<{
      title: string;
      description: string;
      severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
      recommendation?: string;
      source?: string;
    }>;
  };
}

const SEVERITY_LABEL: Record<string, string> = {
  critical: '严重', high: '高危', medium: '中危', low: '低危', info: '提示',
};

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

export function formatTimestamp(d: Date): string {
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

/** 按来源归类统计，报告开头的概览用 */
export function summarizeEntries(entries: OperationEntry[]) {
  const total = entries.length;
  const succeeded = entries.filter(e => e.success).length;
  const rolledBack = entries.filter(e => e.rolledBack).length;
  const revertible = entries.filter(e => !!e.restoreCommand && !e.rolledBack).length;
  const bySource = new Map<string, number>();
  for (const e of entries) {
    bySource.set(e.source, (bySource.get(e.source) || 0) + 1);
  }
  return { total, succeeded, failed: total - succeeded, rolledBack, revertible, bySource };
}

// ──────────────── Markdown ────────────────

export function buildDisposalMarkdown(input: DisposalReportInput): string {
  const { server, generatedAt, entries, detection } = input;
  const s = summarizeEntries(entries);
  const L: string[] = [];

  L.push(`# 处置交付报告`);
  L.push('');
  L.push(`- 目标主机：${server || '(未记录)'}`);
  L.push(`- 生成时间：${formatTimestamp(generatedAt)}`);
  L.push(`- 处置条目：${s.total} 条（成功 ${s.succeeded}，失败 ${s.failed}，已回滚 ${s.rolledBack}）`);
  L.push(`- 仍可一键回滚：${s.revertible} 条`);
  L.push('');

  if (detection) {
    L.push(`## 一、检测结果`);
    L.push('');
    L.push(`检测时间：${formatTimestamp(detection.timestamp)}　总体评分：**${detection.overallScore}**`);
    L.push('');
    if (!detection.findings.length) {
      L.push('本次检测未发现问题。');
      L.push('');
    } else {
      const sorted = [...detection.findings].sort(
        (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
      );
      L.push('| 级别 | 问题 | 说明 | 建议 |');
      L.push('| --- | --- | --- | --- |');
      for (const f of sorted) {
        L.push(`| ${SEVERITY_LABEL[f.severity] || f.severity} | ${mdCell(f.title)} | ${mdCell(f.description)} | ${mdCell(f.recommendation || '-')} |`);
      }
      L.push('');
    }
  }

  L.push(`## ${detection ? '二' : '一'}、处置记录`);
  L.push('');

  if (!entries.length) {
    L.push('本次未产生任何变更记录。');
    L.push('');
  } else {
    // 时间正序，读起来就是一条处置时间线
    const ordered = [...entries].sort((a, b) => a.timestamp - b.timestamp);
    ordered.forEach((e, i) => {
      const status = e.rolledBack ? '已回滚' : e.success ? '成功' : '失败';
      L.push(`### ${i + 1}. ${e.title}`);
      L.push('');
      L.push(`- 时间：${formatTimestamp(new Date(e.timestamp))}`);
      L.push(`- 来源：${opSourceLabel(e.source)}　状态：${status}`);
      if (e.beforeValue || e.afterValue) {
        L.push(`- 变更：\`${e.beforeValue || '(空)'}\` → \`${e.afterValue || '(空)'}\``);
      }
      if (e.backupInfo) L.push(`- 备份：${e.backupInfo}`);
      L.push('');
      L.push('执行命令：');
      L.push('');
      L.push('```bash');
      L.push(e.command);
      L.push('```');
      L.push('');
      if (e.restoreCommand) {
        L.push('回滚命令：');
        L.push('');
        L.push('```bash');
        L.push(e.restoreCommand);
        L.push('```');
        L.push('');
      } else {
        L.push('> 该操作未登记回滚命令，无法一键撤销。');
        L.push('');
      }
    });
  }

  return L.join('\n');
}

/** Markdown 表格单元格：竖线会截断列，换行会截断整行 */
function mdCell(text: string): string {
  return String(text ?? '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ').trim() || '-';
}

// ──────────────── HTML ────────────────

const SEVERITY_COLOR: Record<string, string> = {
  critical: '#991b1b', high: '#9a3412', medium: '#854d0e', low: '#166534', info: '#1e40af',
};
const SEVERITY_BG: Record<string, string> = {
  critical: '#fef2f2', high: '#fff7ed', medium: '#fefce8', low: '#f0fdf4', info: '#eff6ff',
};

export function buildDisposalHtml(input: DisposalReportInput): string {
  const { server, generatedAt, entries, detection } = input;
  const s = summarizeEntries(entries);
  const ordered = [...entries].sort((a, b) => a.timestamp - b.timestamp);

  const findingsHtml = !detection
    ? ''
    : `
    <section class="card">
      <h2>检测结果</h2>
      <p class="meta">检测时间 ${escapeHtml(formatTimestamp(detection.timestamp))}　总体评分 <strong>${detection.overallScore}</strong></p>
      ${!detection.findings.length
        ? '<p class="empty">本次检测未发现问题。</p>'
        : `<table>
             <thead><tr><th>级别</th><th>问题</th><th>说明</th><th>建议</th></tr></thead>
             <tbody>${[...detection.findings]
               .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))
               .map(f => `<tr>
                 <td><span class="sev" style="color:${SEVERITY_COLOR[f.severity] || '#334155'};background:${SEVERITY_BG[f.severity] || '#f1f5f9'}">${escapeHtml(SEVERITY_LABEL[f.severity] || f.severity)}</span></td>
                 <td>${escapeHtml(f.title)}</td>
                 <td>${escapeHtml(f.description)}</td>
                 <td>${escapeHtml(f.recommendation || '-')}</td>
               </tr>`).join('')}</tbody>
           </table>`}
    </section>`;

  const entriesHtml = !ordered.length
    ? '<p class="empty">本次未产生任何变更记录。</p>'
    : ordered.map((e, i) => {
        const status = e.rolledBack ? '已回滚' : e.success ? '成功' : '失败';
        const cls = e.rolledBack ? 'rolled' : e.success ? 'ok' : 'fail';
        return `
        <article class="entry ${cls}">
          <h3><span class="idx">${i + 1}</span>${escapeHtml(e.title)}</h3>
          <p class="meta">
            ${escapeHtml(formatTimestamp(new Date(e.timestamp)))}
            · ${escapeHtml(opSourceLabel(e.source))}
            · <span class="status ${cls}">${escapeHtml(status)}</span>
          </p>
          ${e.beforeValue || e.afterValue
            ? `<p class="diff"><code>${escapeHtml(e.beforeValue || '(空)')}</code> → <code>${escapeHtml(e.afterValue || '(空)')}</code></p>`
            : ''}
          ${e.backupInfo ? `<p class="meta">备份：${escapeHtml(e.backupInfo)}</p>` : ''}
          <p class="label">执行命令</p>
          <pre>${escapeHtml(e.command)}</pre>
          ${e.restoreCommand
            ? `<p class="label">回滚命令</p><pre class="restore">${escapeHtml(e.restoreCommand)}</pre>`
            : '<p class="warn">该操作未登记回滚命令，无法一键撤销。</p>'}
        </article>`;
      }).join('');

  const sourceChips = [...s.bySource.entries()]
    .map(([src, n]) => `<span class="chip">${escapeHtml(opSourceLabel(src as OperationEntry['source']))} ${n}</span>`)
    .join('');

  // 自包含、零外链：赛场断网，任何外部资源都会加载失败
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>处置交付报告 — ${escapeHtml(server)} ${escapeHtml(formatTimestamp(generatedAt))}</title>
<style>
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Noto Sans SC',sans-serif;background:#f8fafc;color:#1e293b;line-height:1.65}
  .wrap{max-width:900px;margin:0 auto;padding:32px 24px}
  header{background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;border-radius:16px;padding:32px;margin-bottom:20px}
  header h1{font-size:26px;margin-bottom:6px}
  header .sub{opacity:.85;font-size:14px}
  .stats{display:flex;flex-wrap:wrap;gap:10px;margin-top:18px}
  .stat{background:rgba(255,255,255,.16);padding:6px 14px;border-radius:8px;font-size:13px}
  .card{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:20px;margin-bottom:20px}
  .card h2{font-size:17px;margin-bottom:10px}
  .chip{display:inline-block;background:#f1f5f9;border-radius:12px;padding:2px 10px;font-size:12px;margin:0 6px 6px 0}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{border:1px solid #e2e8f0;padding:8px 10px;text-align:left;vertical-align:top}
  th{background:#f8fafc;font-weight:600}
  .sev{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;font-weight:600;white-space:nowrap}
  .entry{background:#fff;border:1px solid #e2e8f0;border-left-width:4px;border-radius:12px;padding:18px;margin-bottom:14px}
  .entry.ok{border-left-color:#16a34a}
  .entry.fail{border-left-color:#dc2626}
  .entry.rolled{border-left-color:#94a3b8}
  .entry h3{font-size:15px;display:flex;align-items:center;gap:8px;margin-bottom:6px}
  .idx{display:inline-flex;align-items:center;justify-content:center;width:22px;height:22px;border-radius:50%;background:#eef2ff;color:#4338ca;font-size:12px;font-weight:700;flex:none}
  .meta{font-size:12px;color:#64748b;margin-bottom:6px}
  .status.ok{color:#16a34a}.status.fail{color:#dc2626}.status.rolled{color:#64748b}
  .diff code{background:#f1f5f9;padding:1px 6px;border-radius:4px;font-size:12px}
  .label{font-size:12px;color:#64748b;margin:10px 0 4px}
  pre{background:#0f172a;color:#e2e8f0;padding:10px 12px;border-radius:8px;font-size:12px;overflow-x:auto;white-space:pre-wrap;word-break:break-all}
  pre.restore{background:#052e16}
  .warn{font-size:12px;color:#b45309;background:#fffbeb;border-radius:6px;padding:6px 10px;margin-top:8px}
  .empty{font-size:13px;color:#64748b;padding:12px 0}
  @media print{
    body{background:#fff}
    .wrap{max-width:none;padding:0}
    header{background:#4338ca !important;-webkit-print-color-adjust:exact;print-color-adjust:exact}
    .entry,.card{break-inside:avoid}
  }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>处置交付报告</h1>
    <div class="sub">${escapeHtml(server || '(未记录目标主机)')}　·　生成于 ${escapeHtml(formatTimestamp(generatedAt))}</div>
    <div class="stats">
      <span class="stat">处置 ${s.total} 条</span>
      <span class="stat">成功 ${s.succeeded}</span>
      <span class="stat">失败 ${s.failed}</span>
      <span class="stat">已回滚 ${s.rolledBack}</span>
      <span class="stat">仍可回滚 ${s.revertible}</span>
    </div>
  </header>

  ${sourceChips ? `<section class="card"><h2>处置来源分布</h2>${sourceChips}</section>` : ''}
  ${findingsHtml}

  <section class="card">
    <h2>处置记录</h2>
    <p class="meta">按时间正序，即一条完整的处置时间线。</p>
  </section>
  ${entriesHtml}
</div>
</body>
</html>`;
}

// ──────────────── 下载 ────────────────

export function downloadDisposalReport(
  input: DisposalReportInput,
  format: 'markdown' | 'html',
): void {
  const content = format === 'markdown' ? buildDisposalMarkdown(input) : buildDisposalHtml(input);
  const ext = format === 'markdown' ? 'md' : 'html';
  const mime = format === 'markdown' ? 'text/markdown' : 'text/html';
  const stamp = formatTimestamp(input.generatedAt).replace(/[: ]/g, '-');
  const host = (input.server || 'unknown').replace(/[^\w.\-]/g, '_');

  const blob = new Blob([content], { type: `${mime};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `LovelyRes-处置交付报告-${host}-${stamp}.${ext}`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
