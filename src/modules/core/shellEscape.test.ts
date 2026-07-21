import { describe, expect, it } from 'vitest';

import {
  shq,
  isValidUsername,
  isValidIpOrCidr,
  isValidPort,
  isValidPid,
  isValidNonNegativeInt,
} from './shellEscape';

/**
 * shq() 是全项目命令拼接的最后一道防线（firewall / snapshot / userDisposal /
 * integrity / baseline 都依赖它），这里覆盖 POSIX sh 里所有有特殊含义的字符。
 */
describe('shq', () => {
  it('用单引号包裹普通值', () => {
    expect(shq('root')).toBe("'root'");
    expect(shq('a b')).toBe("'a b'");
    expect(shq(22)).toBe("'22'");
    expect(shq('')).toBe("''");
  });

  it('用 POSIX 标准写法转义单引号（闭合→转义→重开）', () => {
    expect(shq("O'Brien")).toBe("'O'\\''Brien'");
    // 连续单引号
    expect(shq("''")).toBe("''\\'''\\'''");
  });

  it('把 shell 元字符变成字面量', () => {
    // 这些字符一旦逃出引号就是命令注入 / 重定向
    for (const evil of [
      'a;rm -rf /',
      'a&&whoami',
      'a||whoami',
      'a|tee /etc/passwd',
      'a`id`',
      'a$(id)',
      'a$HOME',
      'a>/etc/passwd',      // 重定向：原黑名单漏掉的字符
      'a</etc/shadow',
      'a*',                 // glob
      'a?',
      'a\nwhoami',          // 换行
      '-rf',                // 前导横杠（参数注入）
      '~root',
    ]) {
      const quoted = shq(evil);
      // 结果整体必须是单引号包裹，且内部不含裸单引号
      expect(quoted.startsWith("'")).toBe(true);
      expect(quoted.endsWith("'")).toBe(true);
      // 去掉首尾引号后，剩下的内容里每个 ' 都必须是 '\'' 序列的一部分
      expect(quoted).toBe(`'${evil.replace(/'/g, `'\\''`)}'`);
    }
  });

  it('对不含单引号的输入，解引用后等于原值', () => {
    // 模拟 POSIX sh 的单引号解析：去掉首尾引号即为字面值
    const cases = ['a>b', 'a;b', 'a b', '*', '$X', '`id`'];
    for (const c of cases) {
      expect(shq(c).slice(1, -1)).toBe(c);
    }
  });
});

describe('isValidUsername', () => {
  it('接受合法 Linux 用户名', () => {
    for (const ok of ['root', 'www-data', 'user_1', 'a', '_svc', 'A'.repeat(32)]) {
      expect(isValidUsername(ok)).toBe(true);
    }
  });

  it('拒绝含 shell / sed 元字符的用户名', () => {
    // 这一条是 lockUserCmd / set-user-nologin 的 Alpine 分支敢把用户名裸拼进
    // sed 的 s|...| 表达式的唯一依据：白名单里不含任何 sed 元字符
    for (const bad of [
      "test'x",       // 单引号
      'a|b',          // sed 分隔符
      'a.b',          // BRE 通配
      'a*b', 'a[b', 'a]b', 'a^b', 'a$b', 'a\\b', 'a/b',
      '-h',           // 前导横杠
      '1user',        // 数字开头
      'a b',          // 空格
      'a>b',
      '',
      'A'.repeat(33), // 超长
    ]) {
      expect(isValidUsername(bad), `应拒绝: ${JSON.stringify(bad)}`).toBe(false);
    }
  });
});

describe('isValidIpOrCidr', () => {
  it('接受合法 IPv4 / CIDR / IPv6', () => {
    for (const ok of ['1.1.1.1', '192.168.0.0/16', '10.0.0.1/32', '255.255.255.255', 'fe80::1', '2001:db8::/32']) {
      expect(isValidIpOrCidr(ok), `应接受: ${ok}`).toBe(true);
    }
  });

  it('拒绝越界与注入形态', () => {
    for (const bad of [
      '256.1.1.1',
      '1.1.1.1 > /etc/passwd',   // 重定向：原黑名单漏掉
      "1.1.1.1' drop'",          // 逃出 rich-rule 的单引号
      '1.1.1.1;id',
      '1.1.1',
      'notanip',
      '',
    ]) {
      expect(isValidIpOrCidr(bad), `应拒绝: ${JSON.stringify(bad)}`).toBe(false);
    }
  });
});

describe('isValidPort', () => {
  it('接受 1-65535', () => {
    for (const ok of ['1', '22', '65535', 8080]) expect(isValidPort(ok)).toBe(true);
  });

  it('拒绝越界与非数字', () => {
    for (const bad of ['0', '65536', '-1', '22/tcp', '22;id', '22 > /tmp/x', 'abc', '']) {
      expect(isValidPort(bad), `应拒绝: ${JSON.stringify(bad)}`).toBe(false);
    }
  });
});

describe('isValidPid', () => {
  it('接受合法 PID', () => {
    for (const ok of ['1', '4194304', 1234]) expect(isValidPid(ok)).toBe(true);
  });

  it('拒绝 0 / 负数 / 越界 / 注入形态', () => {
    // '1 > /etc/passwd' 是原实现最典型的事故形态：kill -9 1 > /etc/passwd 会截断密码文件
    for (const bad of ['0', '-1', '4194305', '1 > /etc/passwd', '1;id', '1.5', '', ' ']) {
      expect(isValidPid(bad), `应拒绝: ${JSON.stringify(bad)}`).toBe(false);
    }
  });
});

describe('isValidNonNegativeInt', () => {
  it('接受非负整数', () => {
    for (const ok of ['0', '7', '90', '99999']) expect(isValidNonNegativeInt(ok)).toBe(true);
  });

  it('拒绝负数 / 小数 / 超大值 / 非数字', () => {
    for (const bad of ['-1', '1.5', '100000', 'abc', '', '7;id']) {
      expect(isValidNonNegativeInt(bad), `应拒绝: ${JSON.stringify(bad)}`).toBe(false);
    }
  });
});
