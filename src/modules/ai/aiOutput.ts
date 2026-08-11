/**
 * AI 输出渲染工具
 *
 * renderAIMarkdown 的渲染策略与 fileContextMenu.renderMarkdown 完全一致：
 * marked（breaks + gfm）→ 内联样式替换链。唯一的差别是失败兜底：
 * 原实现在 marked 抛错时把原始 markdown 作为 HTML 返回（会被赋给 innerHTML），
 * 这里退化为 textContent 纯文本，避免未转义内容进入 innerHTML。
 */

import { marked } from 'marked';

import { logger } from '../core/logger';
/** 正式包 drop 掉 console，诊断信息只有进 logger 才留得下来（状态栏「日志」按钮可导出） */
const log = logger.module('AIOutput');

/** marked 输出 → 带主题变量的内联样式 HTML（与 fileContextMenu 的替换链逐条一致） */
function styleMarkedHtml(rawHtml: string): string {
  return rawHtml
    .replace(/<h1>/g, '<h1 style="margin: 18px 0 14px 0; color: var(--primary-color); font-size: 18px; font-weight: 700; line-height: 1.4;">')
    .replace(/<h2>/g, '<h2 style="margin: 16px 0 12px 0; color: var(--primary-color); font-size: 16px; font-weight: 600; line-height: 1.4;">')
    .replace(/<h3>/g, '<h3 style="margin: 14px 0 10px 0; color: var(--text-primary); font-size: 15px; font-weight: 600; line-height: 1.4;">')
    .replace(/<h4>/g, '<h4 style="margin: 12px 0 8px 0; color: var(--text-primary); font-size: 14px; font-weight: 600; line-height: 1.4;">')
    .replace(/<h5>/g, '<h5 style="margin: 10px 0 6px 0; color: var(--text-primary); font-size: 13px; font-weight: 600; line-height: 1.4;">')
    .replace(/<h6>/g, '<h6 style="margin: 8px 0 4px 0; color: var(--text-primary); font-size: 12px; font-weight: 600; line-height: 1.4;">')
    .replace(/<p>/g, '<p style="margin: 8px 0; color: var(--text-primary); line-height: 1.6; font-size: 13px;">')
    .replace(/<ul>/g, '<ul style="margin: 8px 0; padding-left: 24px; list-style-type: disc;">')
    .replace(/<ol>/g, '<ol style="margin: 8px 0; padding-left: 24px;">')
    .replace(/<li>/g, '<li style="margin: 4px 0; color: var(--text-primary); line-height: 1.5;">')
    .replace(/<code>/g, '<code style="background: var(--bg-tertiary); padding: 2px 6px; border-radius: 3px; font-family: \'Consolas\', \'Monaco\', monospace; font-size: 12px; color: var(--primary-color);">')
    .replace(/<pre><code/g, '<pre style="background: var(--bg-tertiary); padding: 12px; border-radius: 6px; overflow-x: auto; margin: 12px 0;"><code style="font-family: \'Consolas\', \'Monaco\', monospace; font-size: 12px; color: var(--text-primary); background: transparent; padding: 0;"')
    .replace(/<a /g, '<a style="color: var(--primary-color); text-decoration: underline;" target="_blank" ')
    .replace(/<hr>/g, '<hr style="border: none; border-top: 1px solid var(--border-color); margin: 16px 0;">')
    .replace(/<hr \/>/g, '<hr style="border: none; border-top: 1px solid var(--border-color); margin: 16px 0;" />')
    .replace(/<blockquote>/g, '<blockquote style="margin: 12px 0; padding: 8px 16px; border-left: 4px solid var(--primary-color); background: var(--bg-secondary); color: var(--text-secondary); font-style: italic;">')
    .replace(/<table>/g, '<table style="border-collapse: collapse; width: 100%; margin: 12px 0; font-size: 13px;">')
    .replace(/<th>/g, '<th style="border: 1px solid var(--border-color); padding: 8px; background: var(--bg-secondary); color: var(--text-primary); font-weight: 600; text-align: left;">')
    .replace(/<td>/g, '<td style="border: 1px solid var(--border-color); padding: 8px; color: var(--text-primary);">')
    .replace(/<strong>/g, '<strong style="color: var(--text-primary); font-weight: 600;">')
    .replace(/<em>/g, '<em style="color: var(--text-secondary);">');
}

/**
 * 把 AI 返回的 markdown 渲染进目标元素。
 * 渲染失败时退化为纯文本（textContent），不抛出。
 */
export function renderAIMarkdown(el: HTMLElement, markdown: string): void {
  try {
    marked.setOptions({
      breaks: true,
      gfm: true,
    });

    const rawHtml = marked.parse(markdown) as string;
    el.innerHTML = styleMarkedHtml(rawHtml);
  } catch (error) {
    log.error('Markdown 渲染失败:', error);
    el.textContent = markdown;
  }
}

/**
 * 「取消生成」按钮：addEventListener 绑定（不用内联 onclick），
 * 样式复用现有 modern-btn 体系。
 */
export function createAICancelButton(onCancel: () => void): HTMLButtonElement {
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'modern-btn secondary';
  btn.textContent = '取消生成';
  btn.addEventListener('click', () => {
    btn.disabled = true;
    onCancel();
  });
  return btn;
}
