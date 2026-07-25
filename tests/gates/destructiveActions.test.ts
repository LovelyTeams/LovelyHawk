/**
 * 门禁：没有任何安全机制的破坏性命令
 *
 * 不可谈判项（AGENTS.md）：
 *   "Destructive actions go through showConfirm({ dangerous: true }) 且若可逆
 *    则记入 core/operationJournal.ts 并带 restoreCommand"
 *
 * 本门禁按**文件**粒度：统计构造了破坏性命令、却既没引入 showConfirm、
 * 也没引入 operationJournal / runGuardedCommand 的文件里，这类命令有多少条。
 * 也就是说它抓的是"这个文件在删东西/杀进程/改系统，但完全没有确认与回滚
 * 机制"—— 审计发现整个右键菜单层就是这个状态。
 *
 * 正确做法是让它们走 core/guardedCommand.ts 的 runGuardedCommand()，
 * 由它统一完成 确认 → 执行 → 记账。
 */

import { describe, it, expect } from 'vitest';
import { listSourceFiles, templateLiterals } from './lib/scan';
import { checkRatchet, type Counts } from './lib/ratchet';

/** 破坏性动作：删除 / 杀进程 / 改账号 / 改防火墙 / 覆写文件 / 停服务 */
const DESTRUCTIVE = [
  /(^|[\s;|&(`])rm\s+-[a-zA-Z]*[rf]/,
  /(^|[\s;|&(`])(kill|pkill|killall)\s+(-9|-KILL|-[a-zA-Z]*\s+)?/,
  /(^|[\s;|&(`])(userdel|usermod\s+-L|passwd\s+-l|chpasswd)/,
  /(^|[\s;|&(`])chattr\s+[+-][ia]/,
  /(^|[\s;|&(`])(systemctl|service)\s+(stop|disable|mask)/,
  /(^|[\s;|&(`])iptables\s+(-F|-X|-D|-A|-I)/,
  /(^|[\s;|&(`])(dd|mkfs|truncate)\s/,
  /(^|[\s;|&(`])docker\s+(rm|kill|stop)\s+-?f?/,
  /(^|[\s;|&(`])crontab\s+-r/,
  />\s*\/(etc|usr|bin|sbin|boot)\//,
];

/** 文件是否已引入任一安全机制 */
const HAS_GUARD = /\b(showConfirm|operationJournal|runGuardedCommand)\b/;

const OPT_OUT = /\/\*\s*destructive-ok:/;

function scan(): Counts {
  const counts: Counts = {};

  for (const { path, text } of listSourceFiles()) {
    if (HAS_GUARD.test(text)) continue;

    let n = 0;
    for (const { body } of templateLiterals(text)) {
      if (OPT_OUT.test(body)) continue;
      if (DESTRUCTIVE.some((re) => re.test(body))) n++;
    }
    if (n > 0) counts[path] = n;
  }

  return counts;
}

describe('门禁：破坏性操作的确认与记账', () => {
  it('不得新增无确认无记账的破坏性命令', () => {
    const result = checkRatchet(
      'destructiveActions',
      scan(),
      [
        '整改方式：改走 core/guardedCommand.ts 的 runGuardedCommand()，传',
        "risk: 'destructive' 并给出 restoreCommand（真不可回滚则 irreversible: true）。",
        '',
        '它会统一完成：确认对话框（展示真实命令串）→ 执行 → 写入 operationJournal。',
      ].join('\n'),
    );
    expect(result.ok, result.message).toBe(true);
  });
});
