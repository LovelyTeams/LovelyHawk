import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

interface CompatibilityMatrix {
  schema: string;
  openssh: Array<{ label: string; image: string; expectedVersion: string }>;
  dropbear: Array<{ label: string; image: string }>;
  distros: Array<{ label: string; image: string; expectedOs: string }>;
  auth: string[];
  faults: string[];
}

const root = process.cwd();
const matrix = JSON.parse(readFileSync(
  resolve(root, 'tests/ssh-compat/matrix.json'),
  'utf8',
)) as CompatibilityMatrix;
const workflow = readFileSync(resolve(root, '.github/workflows/ssh-compatibility.yml'), 'utf8');

describe('SSH compatibility matrix gate', () => {
  it('keeps OpenSSH 7 through 10 in the executable contract', () => {
    expect(matrix.schema).toBe('lovelyres-ssh-compatibility-matrix/v1');
    for (const major of [7, 8, 9, 10]) {
      expect(matrix.openssh.some(target => target.label.includes(`OpenSSH ${major}.`))).toBe(true);
      expect(workflow).toContain('openssh-versions:');
    }
  });

  it('keeps a non-OpenSSH server implementation in the executable contract', () => {
    expect(matrix.dropbear.some(target => target.label.includes('Dropbear'))).toBe(true);
    expect(workflow).toContain('dropbear:');
  });

  it('keeps mainstream, minimal and domestic Linux families in the matrix', () => {
    for (const family of ['Ubuntu', 'Debian', 'Rocky', 'Alpine', 'openEuler', 'Anolis', 'openSUSE']) {
      expect(matrix.distros.some(target => target.label.includes(family))).toBe(true);
    }
    expect(workflow).toContain('linux-distros:');
  });

  it('does not silently drop advanced authentication or fault contracts', () => {
    for (const auth of [
      'password', 'key', 'ecdsa-key', 'certificate', 'keyboard-interactive', 'agent',
      'rsa-agent', 'jump-host', 'rsa-private-key-rejected',
    ]) {
      expect(matrix.auth).toContain(auth);
    }
    for (const fault of [
      'ipv6', 'high-latency', 'disconnect', 'no-sftp', 'no-pty', 'host-key-change',
      'restricted-account',
    ]) {
      expect(matrix.faults).toContain(fault);
    }
    expect(workflow).toContain('authentication:');
    expect(workflow).toContain('subsystem-faults:');
  });
});
