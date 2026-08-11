import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

const read = (path: string) => readFileSync(path, 'utf8');

describe('raw PCAP evidence wiring gate', () => {
  const renderer = read('src/modules/ui/packetCaptureRenderer.ts');
  const targetBound = read('src/modules/core/targetBoundSSH.ts');
  const commands = read('src-tauri/src/commands/ssh_commands.rs');
  const registry = read('src-tauri/src/lib.rs');

  it('keeps the UI action connected to a target-bound backend command', () => {
    expect(renderer).toContain('data-pc-action="capture-evidence"');
    expect(renderer).toContain("case 'capture-evidence'");
    expect(renderer).toContain("invokeTargetBoundSSH<PcapEvidenceReceipt>('capture_pcap_evidence'");
    expect(targetBound).toContain("| 'capture_pcap_evidence'");
    expect(registry).toContain('commands::ssh_commands::capture_pcap_evidence');
  });

  it('keeps native path authorization, local hash verification and case registration', () => {
    expect(commands).toContain('blocking_save_file()');
    expect(commands).toContain('sha256_file(&staging)');
    expect(commands).toContain('commit_verified_download(&staging, &destination)');
    expect(renderer).toContain("kind: 'pcap'");
    expect(renderer).toContain('externalSha256: receipt.sha256');
  });
});
