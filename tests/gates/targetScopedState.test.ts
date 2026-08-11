import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

const read = (path: string) => readFileSync(path, 'utf8');

describe('target-scoped UI state wiring gate', () => {
  const detector = read('src/modules/utils/systemDetector.ts');
  const emergency = read('src/modules/emergency/emergencyPageManager.ts');
  const baseline = read('src/modules/baseline/baselineQuickEditManager.ts');
  const integrity = read('src/modules/integrity/integrityManager.ts');
  const snapshot = read('src/modules/snapshot/snapshotManager.ts');
  const journal = read('src/modules/core/operationJournal.ts');
  const sftp = read('src/modules/remote/sftpManager.ts');
  const docker = read('src/modules/docker/dockerPageManager.ts');
  const kubernetes = read('src/modules/kubernetes/kubernetesPageManager.ts');
  const database = read('src/modules/ui/databaseManager.ts');
  const java = read('src/modules/javaHotUpdate/javaHotUpdateManager.ts');
  const terminal = read('src/modules/remote/terminalManager.ts');

  it('keeps system detection and emergency accounts scoped to the trusted target', () => {
    expect(detector).toContain('new Map<string, SystemInfo>()');
    expect(detector).toContain('stableTargetKey(target)');
    expect(detector).toContain('this.assertTarget(target)');
    expect(emergency).toContain('accountsForTarget(connections, target)');
    expect(emergency).not.toContain('connections[0].accounts');
  });

  it('discards baseline edits on session changes and keeps toolbar events alive after rerender', () => {
    expect(baseline).toContain('this.targetSessionId !== target.sessionId');
    expect(baseline).toContain('this.resetTargetState()');
    expect(baseline).toContain('await this.detectSystem(target)');
    expect(baseline).toContain("target.closest('#bl-btn-refresh')");
    expect(baseline).toContain("target.id === 'bl-search-input'");
    expect(baseline).not.toContain("searchInput.addEventListener('input'");
  });

  it('binds persisted integrity, snapshot, and rollback artifacts to the trusted target', () => {
    expect(integrity).toContain('target?: TargetIdentity');
    expect(integrity).toContain('isArtifactForTarget(bl, target)');
    expect(integrity).toContain('activeTargetContext.matches(target)');
    expect(snapshot).toContain('target?: TargetIdentity');
    expect(snapshot).toContain('isArtifactForTarget(snap, target)');
    expect(snapshot).toContain('operationJournal.list({ target })');
    expect(snapshot).toContain('operationJournal.clearTarget(target)');
    expect(journal).toContain('rollbackAllTarget(');
    expect(journal).toContain('exportTarget(target: TargetIdentity)');
  });

  it('clears SFTP path, file, sort, and UID state when the SSH session changes', () => {
    expect(sftp).toContain('synchronizeTarget(): boolean');
    expect(sftp).toContain("this.currentPath = '/'");
    expect(sftp).toContain('this.fileList = []');
    expect(sftp).toContain('this.uidNameCache = {}');
    expect(sftp).toContain('this.targetSessionId !== navigationSessionId');
  });

  it('rebinds container page events and clears container/database state on target changes', () => {
    expect(docker).toContain('this.synchronizeTargetState();\n    this.bindEvents();');
    expect(docker).toContain("throw new Error('Docker 刷新期间活动目标已变化')");
    expect(kubernetes).toContain('this.synchronizeTargetState();\n        this.bindEvents();');
    expect(kubernetes).toContain('this.renderer.resetTargetState()');
    expect(database).toContain('private synchronizeTargetState(): boolean');
    expect(database).toContain('this.activeConnection = null');
    expect(database).toContain('this.currentTargetSqlHistory()[index]');
    expect(java).toContain('private synchronizeTargetState(): boolean');
    expect(java).toContain("throw new Error('Java 数据刷新期间活动目标已变化')");
    expect(terminal).toContain('private synchronizeTarget(): boolean');
    expect(terminal).toContain('this.commandHistory = []');
    expect(terminal).toContain('cd ${shq(cwd)}');
  });
});
