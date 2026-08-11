import { describe, expect, it } from 'vitest';

import { buildJarUpdatePlan, validateJarEntryPath } from './javaOperationContract';

describe('verified JAR update contract', () => {
  it('rejects traversal and non-class archive entries', () => {
    expect(() => validateJarEntryPath('../evil.class')).toThrow();
    expect(() => validateJarEntryPath('/absolute/Evil.class')).toThrow();
    expect(() => validateJarEntryPath('config/application.yml')).toThrow();
    expect(validateJarEntryPath('com/example/App.class')).toBe('com/example/App.class');
  });

  it('quotes every remote path and produces a deterministic restore plan', () => {
    const plan = buildJarUpdatePlan(
      "/opt/app's/app.jar",
      'com/example/App.class',
      "/tmp/new class's.class",
      42,
    );

    expect(plan.backupPath).toBe("/opt/app's/app.jar.lovelyres.bak.42");
    expect(plan.command).toContain("'/opt/app'\\''s/app.jar'");
    expect(plan.command).toContain("'/tmp/new class'\\''s.class'");
    expect(plan.restoreCommand).toContain("lovelyres.bak.42");
    expect(plan.archiveHashCommand).toContain("'com/example/App.class'");
  });
});
