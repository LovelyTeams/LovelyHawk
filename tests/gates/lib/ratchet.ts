/**
 * 棘轮比对 —— 只许降，不许升
 *
 * 语义：
 *   - 某文件计数 > 基线      → FAIL（新增了违规）
 *   - 基线里没有的文件有违规 → FAIL（新文件带着违规进来）
 *   - 某文件计数 < 基线      → FAIL，并提示重新生成基线
 *
 * 降低也失败是刻意的：否则基线会一直停在旧的高位，别人可以把违规
 * 重新加回到旧上限而不被发现。整改 PR 多跑一条命令换来棘轮始终咬紧，
 * 而且减少量会体现在 diff 里，评审时看得见。
 *
 * 重新生成：  UPDATE_GATE_BASELINE=1 npm test
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

export type Counts = Record<string, number>;

const BASELINE_DIR = join(__dirname, '..', 'baselines');

// eslint 无关：vitest 跑在 node 下，process 一定存在
declare const process: { env: Record<string, string | undefined> };

function baselinePath(name: string): string {
  return join(BASELINE_DIR, `${name}.baseline.json`);
}

function readBaseline(name: string): Counts {
  try {
    return JSON.parse(readFileSync(baselinePath(name), 'utf8')) as Counts;
  } catch {
    return {};
  }
}

function writeBaseline(name: string, counts: Counts): void {
  const sorted: Counts = {};
  for (const key of Object.keys(counts).sort()) sorted[key] = counts[key];
  writeFileSync(baselinePath(name), `${JSON.stringify(sorted, null, 2)}\n`, 'utf8');
}

export interface RatchetResult {
  ok: boolean;
  message: string;
}

/**
 * 把本次扫描结果与基线比对。
 *
 * @param name     基线文件名（不含后缀）
 * @param counts   本次扫描：文件路径 -> 违规数（应已过滤掉 0）
 * @param howToFix 失败时给出的整改指引，会拼进报错信息
 */
export function checkRatchet(name: string, counts: Counts, howToFix: string): RatchetResult {
  if (process.env.UPDATE_GATE_BASELINE === '1') {
    writeBaseline(name, counts);
    const total = Object.values(counts).reduce((a, b) => a + b, 0);
    return { ok: true, message: `已重新生成基线 ${name}：${Object.keys(counts).length} 个文件 / ${total} 处` };
  }

  const baseline = readBaseline(name);
  const added: string[] = [];
  const introduced: string[] = [];
  const reduced: string[] = [];

  for (const [file, n] of Object.entries(counts)) {
    const base = baseline[file];
    if (base === undefined) introduced.push(`  ${file}: ${n} 处（基线中无此文件）`);
    else if (n > base) added.push(`  ${file}: ${base} → ${n}（+${n - base}）`);
    else if (n < base) reduced.push(`  ${file}: ${base} → ${n}（-${base - n}）`);
  }

  for (const [file, base] of Object.entries(baseline)) {
    if (counts[file] === undefined && base > 0) reduced.push(`  ${file}: ${base} → 0（已清零）`);
  }

  if (added.length || introduced.length) {
    const lines = ['棘轮门禁失败：违规数上升。', ''];
    if (introduced.length) lines.push('新文件带入违规：', ...introduced, '');
    if (added.length) lines.push('已有文件违规增加：', ...added, '');
    lines.push(howToFix);
    return { ok: false, message: lines.join('\n') };
  }

  if (reduced.length) {
    return {
      ok: false,
      message: [
        '违规数下降了 —— 这是好事，但需要把基线一起收紧后提交，',
        '否则别人可以把违规重新加回旧上限而不被发现。',
        '',
        ...reduced,
        '',
        '执行：  UPDATE_GATE_BASELINE=1 npm test    然后提交 tests/gates/baselines/ 下的改动。',
      ].join('\n'),
    };
  }

  return { ok: true, message: '与基线一致' };
}
