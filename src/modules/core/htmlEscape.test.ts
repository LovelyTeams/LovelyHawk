import { describe, expect, it } from 'vitest';

import { escapeHtml, esc } from './htmlEscape';

/**
 * 这个函数是把「靶机上的不可信文本」插进 innerHTML 的唯一安全出口。
 * 应急响应工具的威胁模型很直接：被查主机是攻击者可控的，进程名、文件名、
 * cron 命令、日志行都可以被精心构造；而本工具跑在 Tauri webview 里，
 * webview 能 invoke 122 个后端命令（含 SSH 执行）——一次 XSS 就是反打分析师。
 */
describe('escapeHtml', () => {
  it('转义全部四个字符 & < > "', () => {
    expect(escapeHtml('&')).toBe('&amp;');
    expect(escapeHtml('<')).toBe('&lt;');
    expect(escapeHtml('>')).toBe('&gt;');
    expect(escapeHtml('"')).toBe('&quot;');
  });

  it('& 先于其他字符转义，不会二次转义', () => {
    expect(escapeHtml('&lt;')).toBe('&amp;lt;');
    expect(escapeHtml('<script>')).toBe('&lt;script&gt;');
  });

  it('null / undefined 归一为空串而不是 "null"', () => {
    expect(escapeHtml(null)).toBe('');
    expect(escapeHtml(undefined)).toBe('');
    expect(escapeHtml(0)).toBe('0');
    expect(escapeHtml(false)).toBe('false');
  });

  it('esc 是同一个实现的别名', () => {
    expect(esc).toBe(escapeHtml);
  });
});

describe('属性上下文的注入防护（回归）', () => {
  /**
   * 属性能被撑破的充要条件，就是转义结果里还留着裸的 `"`。
   * 这里直接断言这个不变量——比在 node 环境里手搓 HTML 解析器可靠得多
   * （真实 DOM 下的效果已在浏览器里验证过：注入前 input 上会多出 onfocus 属性，
   * 换成本实现后属性列表只剩 class/value，且 value 完整保留原文）。
   */
  function hasBareDoubleQuote(raw: string): boolean {
    return escapeHtml(raw).includes('"');
  }

  it('靶机可控的文件名不再撑破 value 属性', () => {
    // sftpContextMenuHandler.ts 的重命名对话框把 file.name 直接作为 defaultValue，
    // 而改动前 confirmDialog 用的是 textContent->innerHTML 的三字符转义（不转 "），
    // 文件名 `a" onfocus="alert(1)` 会真的往 input 上挂一个 onfocus 属性。
    expect(hasBareDoubleQuote('a" onfocus="alert(1)')).toBe(false);
    // 原文不能丢：转义只是编码，语义要完整保留
    expect(escapeHtml('a" onfocus="alert(1)')).toBe('a&quot; onfocus=&quot;alert(1)');
  });

  it('含双引号的正常默认值不再被截断', () => {
    // kubernetesPageManager.ts 执行 Pod 命令时 defaultValue 就是 sh -c "ps aux"，
    // 三字符转义下 input 里只会显示 "sh -c "，后半截变成两个畸形属性。
    expect(hasBareDoubleQuote('sh -c "ps aux"')).toBe(false);
    expect(escapeHtml('sh -c "ps aux"')).toBe('sh -c &quot;ps aux&quot;');
  });

  it('闭合标签类注入同样无效', () => {
    const out = escapeHtml('"><script>alert(1)</script>');
    expect(out).not.toContain('"');
    expect(out).not.toContain('<script>');
    expect(out).toBe('&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;');
  });
});
