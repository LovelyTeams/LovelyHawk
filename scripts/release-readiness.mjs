import { readFileSync } from 'node:fs';

const readJson = path => JSON.parse(readFileSync(path, 'utf8'));
const pkg = readJson('package.json');
const lock = readJson('package-lock.json');
const tauri = readJson('src-tauri/tauri.conf.json');
const cargo = readFileSync('src-tauri/Cargo.toml', 'utf8');
const releaseWorkflow = readFileSync('.github/workflows/release.yml', 'utf8');

const cargoVersion = cargo.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
const versions = {
  package: pkg.version,
  lock: lock.packages?.['']?.version,
  tauri: tauri.version,
  cargo: cargoVersion,
};
const distinct = new Set(Object.values(versions));
if (distinct.size !== 1 || distinct.has(undefined)) {
  throw new Error(`版本不一致: ${JSON.stringify(versions)}`);
}

const exactSemver = (value, label) => {
  if (!/^\d+\.\d+\.\d+$/.test(value ?? '')) {
    throw new Error(`${label} 必须锁定精确版本，当前为 ${value ?? 'missing'}`);
  }
  return value;
};
const cargoDependencyVersion = name => exactSemver(
  cargo.match(new RegExp(`^${name.replaceAll('-', '\\-')}\\s*=\\s*(?:\\{[^\\n]*version\\s*=\\s*)?"([^"]+)"`, 'm'))?.[1],
  `Cargo ${name}`,
);
const jsDependencyVersion = name => exactSemver(
  pkg.dependencies?.[name] ?? pkg.devDependencies?.[name],
  `npm ${name}`,
);
const sameMajorMinor = (left, right) => left.split('.').slice(0, 2).join('.') === right.split('.').slice(0, 2).join('.');

const rustTauri = cargoDependencyVersion('tauri');
const jsApi = jsDependencyVersion('@tauri-apps/api');
const jsCli = jsDependencyVersion('@tauri-apps/cli');
if (!sameMajorMinor(rustTauri, jsApi) || !sameMajorMinor(rustTauri, jsCli)) {
  throw new Error(`Tauri 核心次版本不一致: Rust=${rustTauri}, API=${jsApi}, CLI=${jsCli}`);
}
for (const plugin of ['dialog', 'fs', 'opener']) {
  const rustVersion = cargoDependencyVersion(`tauri-plugin-${plugin}`);
  const jsName = `@tauri-apps/plugin-${plugin}`;
  const jsVersion = jsDependencyVersion(jsName);
  if (rustVersion !== jsVersion) {
    throw new Error(`Tauri ${plugin} 插件版本不一致: Rust=${rustVersion}, JS=${jsVersion}`);
  }
  const installedVersion = lock.packages?.[`node_modules/${jsName}`]?.version;
  if (installedVersion !== jsVersion) {
    throw new Error(`package-lock 中 ${jsName}=${installedVersion ?? 'missing'}，预期 ${jsVersion}`);
  }
}

const tag = process.argv[2];
if (tag?.startsWith('v') && tag !== `v${pkg.version}`) {
  throw new Error(`发布标签 ${tag} 与应用版本 v${pkg.version} 不一致`);
}
if (tauri.bundle?.active !== true || tauri.bundle?.targets !== 'all') {
  throw new Error('Tauri 必须生成完整安装包，bundle.active=true 且 targets=all');
}
if (/npm install(?:\s|$)/m.test(releaseWorkflow)) {
  throw new Error('Release 禁止 npm install，必须使用锁文件严格的 npm ci');
}
if (/--no-bundle/.test(releaseWorkflow)) {
  throw new Error('Release 禁止只发布裸可执行文件，必须生成平台安装包');
}
for (const required of [
  'npm ci',
  'npm test',
  'cargo test --locked',
  'SHA256SUMS',
  'sbom-action',
  'attest-build-provenance',
  'Linux installer startup smoke',
  'Windows NSIS install and startup smoke',
  'windows-install-smoke.ps1',
  'LOVELYRES_SMOKE_READY_FILE',
  'macOS application startup smoke',
  'real_linux_ssh_contract',
  'tcpdump coreutils',
]) {
  if (!releaseWorkflow.includes(required)) throw new Error(`Release 缺少门禁: ${required}`);
}

console.log(`release-ready v${pkg.version}`);
