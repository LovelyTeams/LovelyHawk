import { describe, expect, it } from 'vitest';

import {
  buildQuickActionCommand,
  checkQuickActionParam,
  isValidDaysAndUser,
  PARAM_VALIDATORS,
  QUICK_ACTIONS_NEEDING_PARAM,
} from './quickActionCommands';

/**
 * 这些命令以 root 在靶机上执行。改造前 param 是裸拼的，只有一道不完整的字符黑名单
 * （漏 > < ' * ? 和前导 -），从扫描输出粘贴带特殊字符的值会静默执行非预期命令。
 *
 * 下面按「赛场上真会粘贴进来的脏输入」取样，断言：要么被校验拒绝，要么已被 shq() 中和。
 */

/** 会造成实际破坏的输入形态 */
const MALICIOUS_PARAMS = [
  '1 > /etc/passwd',      // 重定向截断（原黑名单不拦 >）
  'x < /etc/shadow',
  "test'x",               // 单引号逃逸
  'a|b',                  // 破坏 sed 的 s|...| 分隔符
  'a.b',                  // BRE 通配
  'a*',                   // glob
  '-h',                   // 参数注入
  '../../etc/passwd',
];

describe('checkQuickActionParam', () => {
  it('需要参数的操作在参数为空时拒绝', () => {
    for (const id of QUICK_ACTIONS_NEEDING_PARAM) {
      const r = checkQuickActionParam(id, '');
      expect(r.ok, `${id} 空参数应被拒绝`).toBe(false);
      if (!r.ok) expect(r.reason).toBe('missing');
    }
  });

  it('黑名单仍然拦住经典注入字符（纵深防御第一道）', () => {
    for (const bad of ['a;id', 'a&&id', 'a|id', 'a`id`', 'a$(id)', 'a{b}']) {
      const r = checkQuickActionParam('kill-name', bad);
      expect(r.ok, `应拒绝: ${bad}`).toBe(false);
    }
  });

  it('黑名单漏掉的字符由类型白名单兜住', () => {
    // 这几个字符黑名单不拦，正是改造前的事故来源
    for (const bad of ['1 > /etc/passwd', "root'x", 'root*', '-h']) {
      const r = checkQuickActionParam('kill-pid', bad);
      expect(r.ok, `kill-pid 应拒绝: ${bad}`).toBe(false);
      const r2 = checkQuickActionParam('delete-user', bad);
      expect(r2.ok, `delete-user 应拒绝: ${bad}`).toBe(false);
    }
  });

  it('放行合法参数', () => {
    expect(checkQuickActionParam('kill-pid', '1234').ok).toBe(true);
    expect(checkQuickActionParam('delete-user', 'www-data').ok).toBe(true);
    expect(checkQuickActionParam('block-ip', '10.0.0.1/32').ok).toBe(true);
    expect(checkQuickActionParam('block-port', '8080').ok).toBe(true);
    expect(checkQuickActionParam('set-user-maxdays', '90 root').ok).toBe(true);
    // 无参数操作
    expect(checkQuickActionParam('clean-tmp', '').ok).toBe(true);
  });
});

describe('isValidDaysAndUser', () => {
  it('要求「天数 用户名」两段且各自合法', () => {
    expect(isValidDaysAndUser('90 root')).toBe(true);
    expect(isValidDaysAndUser('0 www-data')).toBe(true);
    expect(isValidDaysAndUser('90')).toBe(false);          // 缺用户名
    expect(isValidDaysAndUser('root 90')).toBe(false);     // 顺序反了
    expect(isValidDaysAndUser('-1 root')).toBe(false);     // 负天数
    expect(isValidDaysAndUser("90 a'b")).toBe(false);      // 脏用户名
    expect(isValidDaysAndUser('90 root extra')).toBe(false);
  });
});

describe('buildQuickActionCommand — 危险输入不得逃出引号', () => {
  it('每个需要参数的操作，脏输入要么被校验拦下，要么在命令里被完整引起来', () => {
    for (const actionId of QUICK_ACTIONS_NEEDING_PARAM) {
      for (const evil of MALICIOUS_PARAMS) {
        const check = checkQuickActionParam(actionId, evil);
        if (!check.ok) continue; // 被校验拒绝，不会走到生成命令这一步

        const built = buildQuickActionCommand(actionId, evil, 'debian');
        expect(built, `${actionId} 应能生成命令`).not.toBeNull();
        const cmd = built!.cmd;

        // 关键断言：脏输入不得以「未加引号」的形态出现在命令里。
        // shq() 的产物是 '...'，所以命令中应当能找到被引起来的形态。
        expect(cmd, `${actionId} + ${JSON.stringify(evil)} 未被引用`).toContain(
          `'${evil.replace(/'/g, `'\\''`)}'`,
        );
      }
    }
  });

  it('没有类型白名单的自由文本操作也必须靠 shq() 中和', () => {
    // kill-name / remove-sshkey-line 是仅有的两个自由文本入口
    for (const actionId of ['kill-name', 'remove-sshkey-line']) {
      expect(PARAM_VALIDATORS[actionId]).toBeUndefined();
      const built = buildQuickActionCommand(actionId, "a'b > /tmp/x", 'debian')!;
      expect(built.cmd).toContain(`'a'\\''b > /tmp/x'`);
    }
  });
});

describe('buildQuickActionCommand — 已修掉的具体事故形态', () => {
  it('kill-pid 不再让重定向逃出（原: kill -9 1 > /etc/passwd 会截断密码文件）', () => {
    // 该输入现在会被 isValidPid 直接拒绝
    expect(checkQuickActionParam('kill-pid', '1 > /etc/passwd').ok).toBe(false);
    // 合法 PID 生成的命令带 -- 终止选项解析
    const built = buildQuickActionCommand('kill-pid', '1234', 'debian')!;
    expect(built.cmd).toBe(`kill -9 -- '1234'`);
  });

  it('clear-authkeys / clear-history 不再用 eval 展开用户输入', () => {
    for (const id of ['clear-authkeys', 'clear-history']) {
      const built = buildQuickActionCommand(id, 'www-data', 'debian')!;
      expect(built.cmd, `${id} 不应含 eval`).not.toContain('eval');
      // 改用 getent 查真实主目录
      expect(built.cmd).toContain(`getent passwd 'www-data'`);
      expect(built.cmd).not.toContain('~');
    }
  });

  it('remove-sshkey-line 不再经过正则引擎（公钥含 / 会破坏 sed 分隔符）', () => {
    const key = 'AAAAB3NzaC1yc2EAAAADAQABAAAB/gQC+abc/def';
    const built = buildQuickActionCommand('remove-sshkey-line', key, 'debian')!;
    expect(built.cmd).not.toContain('sed');
    expect(built.cmd).toContain('grep -qF --');
    expect(built.cmd).toContain('grep -vF --');
    expect(built.cmd).toContain(`k='${key}'`);
  });

  it('query-user-sudo-log 不再把用户名插进 grep 的单引号正则', () => {
    const built = buildQuickActionCommand('query-user-sudo-log', 'root', 'debian')!;
    expect(built.cmd).toContain(`u='root'`);
    expect(built.cmd).toContain('grep -iF --');
  });

  it('Alpine 的 sed 分支只在用户名通过白名单后才拼接', () => {
    // 白名单保证用户名不含 sed 元字符，这是该分支敢裸拼的唯一依据
    expect(checkQuickActionParam('lock-user', 'a|b').ok).toBe(false);
    expect(checkQuickActionParam('set-user-nologin', 'a.b').ok).toBe(false);

    const built = buildQuickActionCommand('lock-user', 'www-data', 'alpine')!;
    expect(built.cmd).toContain(`passwd -l 'www-data'`);
    expect(built.cmd).toContain('sed -i');
  });

  it('破坏性操作都标了 dangerous（会触发 showConfirm 二次确认）', () => {
    const mustBeDangerous = [
      ['block-ip', '1.1.1.1'], ['block-port', '8080'], ['kick-user', 'root'],
      ['kill-pid', '1234'], ['kill-name', 'nginx'], ['kill-port', '80'],
      ['lock-user', 'root'], ['clear-crontab', 'root'], ['clear-authkeys', 'root'],
      ['clean-tmp', ''], ['remove-sshkey-line', 'AAAA'], ['set-user-nologin', 'root'],
      ['delete-user', 'test'],
    ] as const;
    for (const [id, param] of mustBeDangerous) {
      const built = buildQuickActionCommand(id, param, 'debian')!;
      expect(built.dangerous, `${id} 应标记 dangerous`).toBe(true);
    }
  });

  it('未知 actionId 返回 null 而不是抛错', () => {
    expect(buildQuickActionCommand('no-such-action', 'x', 'debian')).toBeNull();
  });
});

describe('校验表与命令表保持同源', () => {
  it('PARAM_VALIDATORS 里的每个 actionId 都能生成命令', () => {
    for (const id of Object.keys(PARAM_VALIDATORS)) {
      // 用各自合法的样例参数
      const sample = id.includes('days') ? '7 root'
        : id.includes('ip') ? '1.1.1.1'
        : id.includes('port') ? '8080'
        : id === 'kill-pid' ? '1234'
        : 'root';
      expect(buildQuickActionCommand(id, sample, 'debian'), `${id} 无对应命令`).not.toBeNull();
    }
  });

  it('需要参数的操作都能生成命令', () => {
    for (const id of QUICK_ACTIONS_NEEDING_PARAM) {
      expect(buildQuickActionCommand(id, 'root', 'debian'), `${id} 无对应命令`).not.toBeNull();
    }
  });
});
