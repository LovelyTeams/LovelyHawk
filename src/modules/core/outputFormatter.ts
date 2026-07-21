/**
 * 统一命令输出格式化器
 *
 * 把原始命令输出（可能含 ANSI 转义、JSON、可疑内容）渲染为安全的高亮 HTML。
 * 能力：ANSI SGR 着色（颜色跟随主题 --term-ansi-*）、JSON 美化、逐行可疑内容高亮
 * （复用 emergency/outputHighlightRules）、大输出折叠、可选行号。
 *
 * 安全：所有文本先 escapeHtml 再套色，杜绝 HTML 注入。
 */

import { escapeHtml } from './htmlEscape';
import { matchLine, LEVEL_CSS } from '../emergency/outputHighlightRules';

export interface FormatOptions {
  ansi?: boolean;          // 解析 ANSI 转义（默认 true）
  highlight?: boolean;     // 逐行可疑内容高亮（默认 false）
  lineNumbers?: boolean;   // 行号（默认 false）
  json?: boolean;          // 尝试 JSON 美化（默认 true）
  maxLines?: number;       // 超过则折叠（默认 2000，0=不折叠）
  className?: string;      // 附加到根节点的 class
  bare?: boolean;          // 只返回内部 HTML（不含外层 <pre>），用于插入已有 <pre> 容器
}

const ESC_RE = /\x1b\[([0-9;]*)m/;
const ANSI_NAMES = [
  '--term-ansi-black', '--term-ansi-red', '--term-ansi-green', '--term-ansi-yellow',
  '--term-ansi-blue', '--term-ansi-magenta', '--term-ansi-cyan', '--term-ansi-white',
  '--term-ansi-bright-black', '--term-ansi-bright-red', '--term-ansi-bright-green', '--term-ansi-bright-yellow',
  '--term-ansi-bright-blue', '--term-ansi-bright-magenta', '--term-ansi-bright-cyan', '--term-ansi-bright-white',
];
const CUBE = [0, 95, 135, 175, 215, 255];

let foldSeq = 0;

// ─────────── ANSI SGR → HTML ───────────

interface SgrState { fg?: string; bg?: string; bold?: boolean; dim?: boolean; italic?: boolean; underline?: boolean; }

function color256(n: number): string {
  if (n < 16) return `var(${ANSI_NAMES[n]})`;
  if (n < 232) {
    n -= 16;
    const r = CUBE[Math.floor(n / 36)];
    const g = CUBE[Math.floor((n % 36) / 6)];
    const b = CUBE[n % 6];
    return `rgb(${r},${g},${b})`;
  }
  const v = 8 + (n - 232) * 10;
  return `rgb(${v},${v},${v})`;
}

function applyCodes(state: SgrState, codes: number[]): void {
  for (let i = 0; i < codes.length; i++) {
    const c = codes[i];
    if (c === 0) { state.fg = state.bg = undefined; state.bold = state.dim = state.italic = state.underline = false; }
    else if (c === 1) state.bold = true;
    else if (c === 2) state.dim = true;
    else if (c === 3) state.italic = true;
    else if (c === 4) state.underline = true;
    else if (c === 22) { state.bold = false; state.dim = false; }
    else if (c === 23) state.italic = false;
    else if (c === 24) state.underline = false;
    else if (c >= 30 && c <= 37) state.fg = `var(${ANSI_NAMES[c - 30]})`;
    else if (c === 39) state.fg = undefined;
    else if (c >= 90 && c <= 97) state.fg = `var(${ANSI_NAMES[c - 90 + 8]})`;
    else if (c >= 40 && c <= 47) state.bg = `var(${ANSI_NAMES[c - 40]})`;
    else if (c === 49) state.bg = undefined;
    else if (c >= 100 && c <= 107) state.bg = `var(${ANSI_NAMES[c - 100 + 8]})`;
    else if (c === 38 || c === 48) {
      const target = c === 38 ? 'fg' : 'bg';
      if (codes[i + 1] === 5) { state[target] = color256(codes[i + 2] || 0); i += 2; }
      else if (codes[i + 1] === 2) { state[target] = `rgb(${codes[i + 2] || 0},${codes[i + 3] || 0},${codes[i + 4] || 0})`; i += 4; }
    }
  }
}

function styleOf(s: SgrState): string {
  const parts: string[] = [];
  if (s.fg) parts.push(`color:${s.fg}`);
  if (s.bg) parts.push(`background:${s.bg}`);
  if (s.bold) parts.push('font-weight:bold');
  if (s.dim) parts.push('opacity:.7');
  if (s.italic) parts.push('font-style:italic');
  if (s.underline) parts.push('text-decoration:underline');
  return parts.join(';');
}

/** 把含 ANSI 的一段文本转为高亮 HTML（已 escape） */
export function ansiToHtml(text: string): string {
  if (!text.includes('\x1b[')) return escapeHtml(text);
  const state: SgrState = {};
  let out = '';
  let rest = text;
  let m: RegExpMatchArray | null;
  while ((m = rest.match(ESC_RE))) {
    const idx = m.index || 0;
    if (idx > 0) {
      const chunk = escapeHtml(rest.slice(0, idx));
      const st = styleOf(state);
      out += st ? `<span style="${st}">${chunk}</span>` : chunk;
    }
    const codes = (m[1] || '0').split(';').map(x => parseInt(x || '0', 10));
    applyCodes(state, codes);
    rest = rest.slice(idx + m[0].length);
  }
  if (rest) {
    const chunk = escapeHtml(rest);
    const st = styleOf(state);
    out += st ? `<span style="${st}">${chunk}</span>` : chunk;
  }
  return out;
}

// ─────────── JSON 美化 ───────────

function looksLikeJson(s: string): boolean {
  const t = s.trim();
  return (t.startsWith('{') && t.endsWith('}')) || (t.startsWith('[') && t.endsWith(']'));
}

function highlightJson(pretty: string): string {
  // 先整体转义，再对 token 套色
  return escapeHtml(pretty).replace(
    /(&quot;(?:\\.|[^&]|&(?!quot;))*?&quot;)(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g,
    (match, str, colon, kw, num) => {
      if (str) return colon
        ? `<span class="ofmt-json-key">${str}</span>${colon}`
        : `<span class="ofmt-json-str">${str}</span>`;
      if (kw) return `<span class="ofmt-json-kw">${kw}</span>`;
      if (num) return `<span class="ofmt-json-num">${num}</span>`;
      return match;
    },
  );
}

// ─────────── 主入口 ───────────

export function formatOutput(raw: string, opts: FormatOptions = {}): string {
  ensureStyles();
  const {
    ansi = true, highlight = false, lineNumbers = false,
    json = true, maxLines = 2000, className = '', bare = false,
  } = opts;

  const text = raw ?? '';

  // JSON 美化（无 ANSI 时才尝试）
  if (json && !text.includes('\x1b[') && looksLikeJson(text)) {
    try {
      const pretty = JSON.stringify(JSON.parse(text), null, 2);
      const jhtml = highlightJson(pretty);
      return bare ? jhtml : `<pre class="ofmt ofmt-json ${className}">${jhtml}</pre>`;
    } catch { /* 非合法 JSON，回退普通渲染 */ }
  }

  const lines = text.split('\n');
  const total = lines.length;
  const fold = maxLines > 0 && total > maxLines;
  const shown = fold ? lines.slice(0, maxLines) : lines;
  const gutterW = String(total).length;

  const renderLine = (line: string, i: number): string => {
    let inner = ansi ? ansiToHtml(line) : escapeHtml(line);
    if (highlight) {
      const rule = matchLine(line);
      if (rule) {
        inner = `<span class="hl-line ${LEVEL_CSS[rule.level]}" title="${escapeHtml(rule.description)}">${inner}<span class="hl-badge">${escapeHtml(rule.label)}</span></span>`;
      }
    }
    if (lineNumbers) {
      const ln = String(i + 1).padStart(gutterW, ' ');
      return `<span class="ofmt-ln">${ln}</span>${inner}`;
    }
    return inner;
  };

  let body = shown.map(renderLine).join('\n');

  if (fold) {
    const id = `ofmt-more-${++foldSeq}`;
    const restHtml = lines.slice(maxLines).map((l, i) => renderLine(l, maxLines + i)).join('\n');
    body += `\n<span class="ofmt-fold" id="${id}-rest" style="display:none">${restHtml}</span>`
      + `\n<button class="ofmt-more-btn" onclick="var r=document.getElementById('${id}-rest');r.style.display='inline';this.remove();">展开剩余 ${total - maxLines} 行</button>`;
  }

  if (bare) return body;
  return `<pre class="ofmt ${lineNumbers ? 'ofmt-ln-on' : ''} ${className}">${body}</pre>`;
}

// ─────────── 样式（一次注入）───────────

function ensureStyles(): void {
  if (typeof document === 'undefined' || document.getElementById('ofmt-styles')) return;
  const style = document.createElement('style');
  style.id = 'ofmt-styles';
  style.textContent = `
    .ofmt{margin:0;padding:12px;font-family:var(--term-font,'Cascadia Code','JetBrains Mono',Consolas,monospace);
      font-size:12px;line-height:1.55;color:var(--term-fg,#e2e8f0);background:var(--term-bg,#0c1222);
      border-radius:8px;white-space:pre-wrap;word-break:break-all;overflow:auto;}
    .ofmt-ln{display:inline-block;min-width:3ch;margin-right:12px;text-align:right;color:var(--term-fg-dim,#64748b);
      user-select:none;opacity:.65;}
    .ofmt-json-key{color:var(--term-ansi-blue,#6db3ff);}
    .ofmt-json-str{color:var(--term-ansi-green,#4ade80);}
    .ofmt-json-num{color:var(--term-ansi-yellow,#facc15);}
    .ofmt-json-kw{color:var(--term-ansi-magenta,#c084fc);}
    .ofmt .hl-line{display:inline-block;width:100%;border-radius:3px;}
    .ofmt .hl-line.hl-critical{background:rgba(239,68,68,.14);}
    .ofmt .hl-line.hl-warning{background:rgba(245,158,11,.13);}
    .ofmt .hl-line.hl-info{background:rgba(99,102,241,.10);}
    .ofmt .hl-line.hl-safe{background:rgba(34,197,94,.10);}
    .ofmt .hl-badge{margin-left:8px;padding:0 6px;border-radius:3px;font-size:10px;
      background:rgba(255,255,255,.12);color:var(--term-fg,#e2e8f0);}
    .ofmt-more-btn{display:inline-block;margin-top:8px;padding:4px 12px;font-size:11px;cursor:pointer;
      background:var(--term-bg-elevated,#141c2b);color:var(--term-fg,#e2e8f0);
      border:1px solid var(--term-border,#283548);border-radius:6px;}
    .ofmt-more-btn:hover{border-color:var(--term-accent,#6db3ff);}
  `;
  document.head.appendChild(style);
}
