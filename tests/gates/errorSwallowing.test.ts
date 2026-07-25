/**
 * 门禁：静默吞掉的异常
 *
 * 为什么这在本项目是硬伤而不是风格问题：
 * vite.config.ts 的 `esbuild.drop: ['console','debugger']` 会在生产构建里
 * 删掉每一个 console.*。所以 `catch (e) { console.error(e) }` 在用户手上是
 * **彻底静默**的失败 —— UI 卡住、没有任何提示、logger 环形缓冲里也查不到。
 *
 * 两类计入：
 *   1. 完全空的 catch 块
 *   2. 整个 catch 体只有 console.* 调用
 *
 * 正确写法：core/logger.ts 记日志 + utils/errorHandler.ts 的 reportError()
 * 通知用户。确实要吞的（如隐私模式下的 localStorage），保留空 catch 但写明：
 *     catch { /* intentional: 隐私模式禁用 localStorage，降级为不持久化 *\/ }
 */

import { describe, it, expect } from 'vitest';
import { listSourceFiles } from './lib/scan';
import { checkRatchet, type Counts } from './lib/ratchet';

const OPT_OUT = /\/\*\s*intentional:/;

/** 找出所有 catch 块的块体原文 */
function catchBodies(src: string): string[] {
  const out: string[] = [];
  const re = /\bcatch\b\s*(\([^)]*\))?\s*\{/g;
  let m: RegExpExecArray | null;

  while ((m = re.exec(src)) !== null) {
    const open = m.index + m[0].length - 1;
    let depth = 0;
    let i = open;

    // 从 `{` 起做花括号配对，跳过字符串/模板/注释
    while (i < src.length) {
      const c = src[i];
      if (c === '/' && src[i + 1] === '/') { while (i < src.length && src[i] !== '\n') i++; continue; }
      if (c === '/' && src[i + 1] === '*') {
        i += 2;
        while (i < src.length && !(src[i] === '*' && src[i + 1] === '/')) i++;
        i += 2;
        continue;
      }
      if (c === '"' || c === "'" || c === '`') {
        const q = c;
        i++;
        while (i < src.length && src[i] !== q) { if (src[i] === '\\') i++; i++; }
        i++;
        continue;
      }
      if (c === '{') depth++;
      else if (c === '}') {
        depth--;
        if (depth === 0) { out.push(src.slice(open + 1, i)); break; }
      }
      i++;
    }
  }

  return out;
}

/** 去掉注释后是否为空 */
function isEffectivelyEmpty(body: string): boolean {
  return body
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/\/\/[^\n]*/g, '')
    .trim().length === 0;
}

/** 去掉注释与 console.* 语句后是否为空 */
function isConsoleOnly(body: string): boolean {
  const stripped = body
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/\/\/[^\n]*/g, '')
    .replace(/console\s*\.\s*\w+\s*\([\s\S]*?\)\s*;?/g, '')
    .trim();
  return stripped.length === 0;
}

function scan(): Counts {
  const counts: Counts = {};

  for (const { path, text } of listSourceFiles()) {
    let n = 0;
    for (const body of catchBodies(text)) {
      if (OPT_OUT.test(body)) continue;
      if (isEffectivelyEmpty(body) || isConsoleOnly(body)) n++;
    }
    if (n > 0) counts[path] = n;
  }

  return counts;
}

describe('门禁：静默吞异常', () => {
  it('不得新增空 catch 或只有 console 的 catch', () => {
    const result = checkRatchet(
      'errorSwallowing',
      scan(),
      [
        '整改方式：改用 utils/errorHandler.ts 的 reportError()：',
        "  catch (e) { reportError(e, { module: 'XxxManager', action: '加载列表' }); }",
        '',
        '生产构建会删掉所有 console.*，所以 catch 里只写 console 等于完全静默。',
        '确实要吞的，加注释豁免：  catch { /* intentional: 理由 */ }',
      ].join('\n'),
    );
    expect(result.ok, result.message).toBe(true);
  });
});
