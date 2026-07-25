/**
 * 门禁扫描器 —— 共享的源码遍历与模板字面量解析
 *
 * 这些门禁刻意用"扫源码 + 已提交基线计数"实现，而不是引入 ESLint：
 * 本仓库 151 个文件、零 lint 历史，一上来就接 ESLint 会产生数千条 day-one
 * 错误并被所有人忽略。棘轮只管三件事，零新依赖，且 `npm test` 本地和 CI 都跑。
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

/** 仓库根目录（本文件位于 <root>/tests/gates/lib/） */
export const REPO_ROOT = join(__dirname, '..', '..', '..');
const SRC_DIR = join(REPO_ROOT, 'src');

export interface SourceFile {
  /** 相对仓库根、正斜杠分隔的路径，用作基线的 key */
  path: string;
  text: string;
}

/** 遍历 src/ 下所有 .ts / .vue（跳过测试文件与压缩过的第三方资源） */
export function listSourceFiles(): SourceFile[] {
  const out: SourceFile[] = [];

  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) {
        walk(full);
        continue;
      }
      if (!/\.(ts|vue)$/.test(entry)) continue;
      if (/\.test\.ts$/.test(entry)) continue;
      if (/\.min\.(js|ts)$/.test(entry)) continue;
      out.push({
        path: relative(REPO_ROOT, full).split(sep).join('/'),
        text: readFileSync(full, 'utf8'),
      });
    }
  };

  walk(SRC_DIR);
  return out;
}

export interface TemplateLiteral {
  /** 模板内容，保留 `${...}` 原文 */
  body: string;
  /** 起始处所在行号（1-based），便于报错定位 */
  line: number;
}

/**
 * 提取源码中所有模板字面量。
 *
 * 手写扫描而非正则：需要正确跳过注释、单/双引号字符串，并处理
 * `${ }` 内的嵌套花括号（如 `${a ? {x:1} : y}`）与转义反引号。
 */
export function templateLiterals(src: string): TemplateLiteral[] {
  const out: TemplateLiteral[] = [];
  let i = 0;
  let line = 1;

  const bump = (s: string): void => {
    for (let k = 0; k < s.length; k++) if (s[k] === '\n') line++;
  };

  while (i < src.length) {
    const c = src[i];

    if (c === '\n') { line++; i++; continue; }

    // 行注释
    if (c === '/' && src[i + 1] === '/') {
      while (i < src.length && src[i] !== '\n') i++;
      continue;
    }
    // 块注释
    if (c === '/' && src[i + 1] === '*') {
      i += 2;
      while (i < src.length && !(src[i] === '*' && src[i + 1] === '/')) {
        if (src[i] === '\n') line++;
        i++;
      }
      i += 2;
      continue;
    }
    // 普通字符串
    if (c === '"' || c === "'") {
      const quote = c;
      i++;
      while (i < src.length && src[i] !== quote) {
        if (src[i] === '\\') i++;
        if (src[i] === '\n') line++;
        i++;
      }
      i++;
      continue;
    }
    // 模板字面量
    if (c === '`') {
      const startLine = line;
      i++;
      let depth = 0;
      let body = '';
      while (i < src.length) {
        if (src[i] === '\\') { body += src[i] + (src[i + 1] ?? ''); i += 2; continue; }
        if (src[i] === '$' && src[i + 1] === '{') { depth++; body += '${'; i += 2; continue; }
        if (depth > 0 && src[i] === '{') { depth++; body += '{'; i++; continue; }
        if (depth > 0 && src[i] === '}') { depth--; body += '}'; i++; continue; }
        if (depth === 0 && src[i] === '`') break;
        if (src[i] === '\n') line++;
        body += src[i];
        i++;
      }
      out.push({ body, line: startLine });
      bump('');
      i++;
      continue;
    }

    i++;
  }

  return out;
}

/** 取出模板字面量内的所有 `${...}` 表达式原文（不含花括号） */
export function interpolations(body: string): string[] {
  const out: string[] = [];
  let i = 0;
  while (i < body.length) {
    if (body[i] === '$' && body[i + 1] === '{') {
      let depth = 1;
      i += 2;
      let expr = '';
      while (i < body.length && depth > 0) {
        if (body[i] === '{') depth++;
        else if (body[i] === '}') { depth--; if (depth === 0) break; }
        expr += body[i];
        i++;
      }
      out.push(expr);
    }
    i++;
  }
  return out;
}
