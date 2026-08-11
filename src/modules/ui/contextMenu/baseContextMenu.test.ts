import { describe, expect, it } from 'vitest';

import { isPotentiallyMutatingContextCommand } from './baseContextMenu';

describe('context-menu mutation classification', () => {
  it('detects service, process, account, firewall, and file mutations', () => {
    expect(isPotentiallyMutatingContextCommand('kill -9 123')).toBe(true);
    expect(isPotentiallyMutatingContextCommand('sudo systemctl restart nginx')).toBe(true);
    expect(isPotentiallyMutatingContextCommand('echo x | sudo tee /etc/example')).toBe(true);
    expect(isPotentiallyMutatingContextCommand('iptables -D INPUT 1')).toBe(true);
    expect(isPotentiallyMutatingContextCommand('userdel compromised')).toBe(true);
  });

  it('does not add danger prompts to ordinary read-only inspection commands', () => {
    expect(isPotentiallyMutatingContextCommand('systemctl status nginx')).toBe(false);
    expect(isPotentiallyMutatingContextCommand('cat /proc/123/status')).toBe(false);
    expect(isPotentiallyMutatingContextCommand('journalctl -u nginx -n 100')).toBe(false);
    expect(isPotentiallyMutatingContextCommand('ss -antlp')).toBe(false);
  });
});
