import { describe, expect, it } from 'vitest';

import { buildEditorBackupPath, contentSha256, validateEditableRemotePath } from './baselineFileEditor';

describe('baseline file editor safety helpers', () => {
  it('accepts absolute config paths and rejects shell/path traversal payloads', () => {
    expect(validateEditableRemotePath('/etc/ssh/sshd_config')).toBe('/etc/ssh/sshd_config');
    expect(() => validateEditableRemotePath('../../etc/passwd')).toThrow('绝对路径');
    expect(() => validateEditableRemotePath('/etc/../tmp/x')).toThrow('上级目录');
    expect(() => validateEditableRemotePath('/etc/x\n/tmp/y')).toThrow('绝对路径');
    expect(() => validateEditableRemotePath('/')).toThrow('目录');
  });

  it('builds a deterministic non-overwriting backup path and hashes exact content', async () => {
    expect(buildEditorBackupPath('/etc/test.conf', 123)).toBe('/etc/test.conf.lovelyres.bak.123');
    expect(await contentSha256('hello')).toBe('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
  });
});
