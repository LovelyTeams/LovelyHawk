import { validateEditableRemotePath } from '../baseline/baselineFileEditor';
import { shq } from '../core/shellEscape';

export interface JarUpdatePlan {
  jarPath: string;
  sourcePath: string;
  entryPath: string;
  backupPath: string;
  command: string;
  sourceHashCommand: string;
  archiveHashCommand: string;
  backupHashCommand: string;
  restoreCommand: string;
}

export function validateJarEntryPath(path: string): string {
  const value = path.trim().replace(/\\/g, '/');
  if (!value || value.length > 4096 || value.startsWith('/') || /[\0\r\n]/.test(value)) {
    throw new Error('JAR 条目必须是合法的相对路径');
  }
  if (value.split('/').some(segment => !segment || segment === '.' || segment === '..')) {
    throw new Error('JAR 条目不能包含空段或父级跳转');
  }
  if (!value.endsWith('.class')) throw new Error('当前安全更新流程仅允许替换 .class 条目');
  return value;
}

export function buildJarUpdatePlan(
  jarPathInput: string,
  entryPathInput: string,
  sourcePathInput: string,
  timestamp = Date.now(),
): JarUpdatePlan {
  const jarPath = validateEditableRemotePath(jarPathInput);
  const sourcePath = validateEditableRemotePath(sourcePathInput);
  const entryPath = validateJarEntryPath(entryPathInput);
  const backupPath = `${jarPath}.lovelyres.bak.${timestamp}`;
  const workspace = `/tmp/lovelyres-jar-${timestamp}`;
  const entryParent = entryPath.includes('/') ? entryPath.slice(0, entryPath.lastIndexOf('/')) : '';
  const stagedPath = `${workspace}/${entryPath}`;
  const mkdirPath = entryParent ? `${workspace}/${entryParent}` : workspace;
  const update = [
    `mkdir -p ${shq(mkdirPath)}`,
    `cp -a ${shq(sourcePath)} ${shq(stagedPath)}`,
    `cd ${shq(workspace)}`,
    `jar uf ${shq(jarPath)} ${shq(entryPath)}`,
  ].join(' && ');
  const command = [
    'set -eu',
    `test -f ${shq(jarPath)}`,
    `test -f ${shq(sourcePath)}`,
    `cp -a ${shq(jarPath)} ${shq(backupPath)}`,
    `if ! ( ${update} ); then cp -a ${shq(backupPath)} ${shq(jarPath)}; exit 1; fi`,
  ].join('; ');

  return {
    jarPath,
    sourcePath,
    entryPath,
    backupPath,
    command,
    sourceHashCommand: `sha256sum ${shq(sourcePath)} | awk '{print $1}'`,
    archiveHashCommand: `unzip -p ${shq(jarPath)} ${shq(entryPath)} | sha256sum | awk '{print $1}'`,
    backupHashCommand: `sha256sum ${shq(backupPath)} | awk '{print $1}'`,
    restoreCommand: `cp -a ${shq(backupPath)} ${shq(jarPath)}`,
  };
}
