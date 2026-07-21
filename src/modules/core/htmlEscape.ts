/**
 * 统一 HTML 转义工具
 *
 * 合并原先散落在 emergencyView.ts(esc) / outputContextMenu.ts(escapeHtml) /
 * emergencyPageManager.ts(escapeHtml) 的重复实现，避免多份不一致。
 * 用于把命令输出等不可信文本安全地插入 innerHTML。
 */

/** 四转义 `& < > "`，null/undefined 归一为空串 */
export function escapeHtml(s: unknown): string {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/** 别名，兼容旧调用点命名 */
export const esc = escapeHtml;
