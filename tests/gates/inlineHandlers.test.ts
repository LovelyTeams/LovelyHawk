/**
 * 门禁：HTML 字符串里的内联事件属性（onclick= / onchange= / ...）
 *
 * 两个理由，都是硬的：
 *
 * 1. escapeHtml() 救不了它们。HTML 属性值在 JS 解析器看到之前就完成实体
 *    解码，所以 `onclick="fn('&#39;')"` 解码后是 `fn(''')`，攻击者仍然能
 *    逃出 JS 字符串字面量。改 data-action + 委托派发才是唯一正解 ——
 *    值经 dataset 读取，永不作为 JS 解析。
 *
 * 2. 只要还有一个内联 handler，CSP 就必须留着 script-src 'unsafe-inline'，
 *    整条 XSS→RCE 链路就还开着。这个计数归零之日，才能收紧 CSP。
 */

import { describe, it, expect } from 'vitest';
import { listSourceFiles } from './lib/scan';
import { checkRatchet, type Counts } from './lib/ratchet';

/**
 * 匹配 HTML 内联事件属性：on<name>= 后面跟引号。
 * 前置 [\s"'] 要求它出现在标签属性位置，避开 `element.onclick = fn`
 * 这类合法的 DOM 属性赋值（那不受 CSP 约束，也没有解析歧义）。
 */
const INLINE_HANDLER =
  /[\s"']on(click|change|input|submit|focus|blur|keydown|keyup|keypress|mouseover|mouseout|mouseenter|mouseleave|mousedown|mouseup|dblclick|contextmenu|wheel|scroll|load|error|drag|dragstart|dragover|drop|paste|copy|cut|toggle)\s*=\s*["']/gi;

function scan(): Counts {
  const counts: Counts = {};
  for (const { path, text } of listSourceFiles()) {
    const n = text.match(INLINE_HANDLER)?.length ?? 0;
    if (n > 0) counts[path] = n;
  }
  return counts;
}

describe('门禁：内联事件属性', () => {
  it('不得新增内联 onXxx= 事件属性', () => {
    const result = checkRatchet(
      'inlineHandlers',
      scan(),
      [
        '整改方式：改用 data-ns / data-action / data-* 属性，配合',
        'src/modules/ui/actionDispatcher.ts 的统一委托派发器。',
        '',
        '参数从 el.dataset 读取，此时对值做 escapeHtml() 才是真正充分的。',
      ].join('\n'),
    );
    expect(result.ok, result.message).toBe(true);
  });
});
