import { describe, expect, it } from 'vitest';

import { buildHijackCommandPlan, isValidAbsoluteCommandPath } from './checkAuditManager';

describe('check audit hijack command plan', () => {
  it('builds a reversible, independently verified receipt plan', () => {
    const plan = buildHijackCommandPlan('cat', '/usr/bin/cat', false);

    expect(plan.backupCommand).toBe("sudo cp -n -- '/usr/bin/cat' '/usr/bin/cat_orig'");
    expect(plan.writeCommand).toContain("sudo /bin/sh -c '");
    expect(plan.functionalVerifyCommand).toContain('WRAPPER_OK');
    expect(plan.restoreCommand).toBe("sudo mv -- '/usr/bin/cat_orig' '/usr/bin/cat'");
    expect(plan.restoreVerifyCommand).toContain('ORIGINAL_OK');
  });

  it('rejects attacker-controlled command names and paths before building shell', () => {
    expect(isValidAbsoluteCommandPath('/usr/local/bin/tool-1')).toBe(true);
    expect(isValidAbsoluteCommandPath('/usr/bin/../tmp/x')).toBe(false);
    expect(() => buildHijackCommandPlan('cat;touch', '/usr/bin/cat', true)).toThrow('命令名不合法');
    expect(() => buildHijackCommandPlan('cat', "/usr/bin/cat'; touch /tmp/pwn #", true)).toThrow('路径不合法');
  });
});
