import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

function files(root, current = root) {
  return readdirSync(current).flatMap(name => {
    const path = join(current, name);
    return statSync(path).isDirectory() ? files(root, path) : [path];
  });
}

function manifest(root) {
  return files(root).sort().map(path => ({
    path: relative(root, path).replaceAll('\\', '/'),
    sha256: createHash('sha256').update(readFileSync(path)).digest('hex'),
  }));
}

const first = manifest('dist');
if (process.platform === 'win32') {
  execFileSync(process.env.ComSpec || 'cmd.exe', ['/d', '/s', '/c', 'npm run build'], { stdio: 'inherit' });
} else {
  execFileSync('npm', ['run', 'build'], { stdio: 'inherit' });
}
const second = manifest('dist');

if (JSON.stringify(first) !== JSON.stringify(second)) {
  const before = new Map(first.map(item => [item.path, item.sha256]));
  const changed = second.filter(item => before.get(item.path) !== item.sha256).map(item => item.path);
  throw new Error(`生产构建不可复现，变化文件: ${changed.join(', ') || '文件集合发生变化'}`);
}
console.log(`reproducible-build ${second.length} files`);
