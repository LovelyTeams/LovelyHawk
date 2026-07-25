/**
 * 门禁：进入 shell 的模板字面量里，未经 shq() 转义的 `${}` 插值
 *
 * 不可谈判项（AGENTS.md）：
 *   "Escape everything that reaches a shell. Use shq() from core/shellEscape.ts"
 *
 * 被检目标机由攻击者控制，其输出（文件名/进程名/crontab/iptables 规则/last
 * 输出）会被解析回前端再拼进命令串。一处漏转义 = 在应急人员已认证的机器上
 * 执行任意命令。
 *
 * 豁免：确实不该套 shq 的位置（整条命令串、纯数字常量等），在表达式内写
 * 块注释标记并说明理由：
 *     `${backup.restoreCommand /* shell-safe: 整条回滚命令，非操作数 *\/}`
 */

import { describe, it, expect } from 'vitest';
import { listSourceFiles, templateLiterals, interpolations } from './lib/scan';
import { checkRatchet, type Counts } from './lib/ratchet';

/**
 * 模板内容是否像一条 shell 命令。
 *
 * 两侧都要收紧，否则会把 HTML 渲染模板算进来（`<th class="${c.cls}">` 里的
 * `w`/`id`/`cat` 之类短词会误命中）：
 *   - 命令必须处于**命令位**：模板开头，或紧跟 ; | && || ( 换行 等分隔符之后
 *   - 命令后必须跟空格/参数/管道，排除出现在普通词句里的同名单词
 */
const SHELL_TOKENS =
  /(^|[;|&(\n]|\|\||&&)\s*(sudo\s+|nohup\s+|setsid\s+)?(rm|kill|pkill|killall|chattr|chmod|chown|userdel|usermod|useradd|passwd|chpasswd|systemctl|service|iptables|ip6tables|nft|crontab|docker|kubectl|dd|mkfs|truncate|tee|mount|umount|su|sh|bash|echo|cat|grep|egrep|find|ps|netstat|awk|sed|stat|md5sum|sha256sum|tar|curl|wget|base64|touch|mkdir|lsof|strings|readlink|getent|last|lastb|uname|sysctl|modprobe|lsmod|journalctl|dmesg)\s+[^\s<]/;

/** HTML 模板：含标签起始/闭合的一律不算 shell 命令 */
const LOOKS_LIKE_HTML = /<\/?[a-zA-Z][a-zA-Z0-9-]*[\s/>]/;

/** 已正确转义 / 校验的表达式 */
const ESCAPED = /^\s*(shq|escapeShellArg|shellQuote)\s*\(/;

/** 显式豁免标记 */
const OPT_OUT = /\/\*\s*shell-safe:/;

function scan(): Counts {
  const counts: Counts = {};

  for (const { path, text } of listSourceFiles()) {
    // shellEscape 自身与其调用示例不参与统计
    if (path.endsWith('src/modules/core/shellEscape.ts')) continue;

    let n = 0;
    for (const { body } of templateLiterals(text)) {
      if (LOOKS_LIKE_HTML.test(body)) continue;
      if (!SHELL_TOKENS.test(body)) continue;
      for (const expr of interpolations(body)) {
        if (ESCAPED.test(expr)) continue;
        if (OPT_OUT.test(expr)) continue;
        n++;
      }
    }
    if (n > 0) counts[path] = n;
  }

  return counts;
}

describe('门禁：shell 插值转义', () => {
  it('不得新增未转义的 shell 插值', () => {
    const result = checkRatchet(
      'shellInterpolation',
      scan(),
      [
        '整改方式：把动态操作数包进 core/shellEscape.ts 的 shq()，',
        '形状固定的值优先用白名单校验（isValidUsername / isValidIpOrCidr /',
        'isValidPort / isValidPid）。',
        '',
        '确实不该套 shq 的（整条命令串、数字常量），在表达式内加注释豁免：',
        '  `${x /* shell-safe: 理由 */}`',
      ].join('\n'),
    );
    expect(result.ok, result.message).toBe(true);
  });
});
