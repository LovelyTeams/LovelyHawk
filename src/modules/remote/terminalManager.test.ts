import { describe, expect, it } from 'vitest';

import { longestCommonPrefix } from './terminalManager';

/**
 * Tab 补全在多候选时补到最长公共前缀，这是 bash 的行为。
 * 补错会直接把用户正在敲的命令改坏，值得钉死。
 */
describe('longestCommonPrefix', () => {
  it('空输入返回空串', () => {
    expect(longestCommonPrefix([])).toBe('');
  });

  it('单个候选就是它自己', () => {
    expect(longestCommonPrefix(['systemctl'])).toBe('systemctl');
  });

  it('取公共前缀', () => {
    expect(longestCommonPrefix(['systemctl', 'systemd-analyze', 'systemd-run'])).toBe('system');
    expect(longestCommonPrefix(['/etc/ssh/sshd_config', '/etc/ssh/ssh_config'])).toBe('/etc/ssh/ssh');
  });

  it('没有公共前缀时返回空串，调用方据此不改动输入', () => {
    expect(longestCommonPrefix(['ls', 'cat', 'grep'])).toBe('');
  });

  it('一个候选是另一个的前缀时，取较短者', () => {
    expect(longestCommonPrefix(['ssh', 'sshd', 'ssh-keygen'])).toBe('ssh');
  });

  it('区分大小写', () => {
    expect(longestCommonPrefix(['Make', 'make'])).toBe('');
  });

  it('候选完全相同时原样返回', () => {
    expect(longestCommonPrefix(['pwd', 'pwd'])).toBe('pwd');
  });
});
