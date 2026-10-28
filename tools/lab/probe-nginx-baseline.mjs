// Real candidate-config scanning and desktop UI against an owned disposable
// Nginx container. Lab edits below are fixtures, not application repair evidence.
// node tools/lab/probe-nginx-baseline.mjs  (NGINX_UI=0 skips only the UI cases)
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { startDesktop } from "./desktop.mjs";
import { Sidecar, connect } from "./rpc-harness.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const backend = path.join(repository, "target/debug/lovelyhawk-backend.exe");
const runId = randomUUID(), name = `lr-nginx-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target/lab-nginx-baseline", runId);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-nginx-"));
fs.mkdirSync(evidence, { recursive: true });
const checks = [], consoleErrors = [];
let containerId, sidecar, app, session, imageId, version;
function check(label, actual, expected = true) {
  const passed = actual === expected;
  checks.push({ label, passed, ...(passed ? {} : { actual, expected }) });
  console.log(`${passed ? "PASS" : "FAIL"} ${label}`);
  if (!passed) throw new Error(label);
}
function wsl(...args) {
  return execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", ...args],
    { encoding: "utf8", windowsHide: true, timeout: 45_000 }).trim();
}
const docker = (...args) => wsl("docker", ...args);
function owned() {
  const found = JSON.parse(docker("inspect", containerId))[0];
  if (found.Id !== containerId || found.Name !== `/${name}` || found.Image !== imageId ||
    found.Config.Labels?.["lovelyres-test-run"] !== runId || found.HostConfig.Privileged ||
    found.Mounts.length !== 0 || found.HostConfig.NetworkMode !== "bridge") {
    throw new Error("Disposable Nginx target identity changed");
  }
  return found;
}
function onHost(...args) { owned(); return docker("exec", containerId, ...args); }
function writeFixture(file, content) {
  if (!["/etc/nginx/nginx.conf", "/etc/nginx/conf.d/00-risky.conf", "/etc/nginx/conf.d/99-safe.conf"].includes(file))
    throw new Error("Unknown fixture path");
  const encoded = Buffer.from(content).toString("base64");
  onHost("sh", "-c", `printf '%s' '${encoded}' | base64 -d > '${file}'`);
}
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function until(fn, label, attempts = 80) {
  for (let index = 0; index < attempts; index++) {
    if (await fn()) return;
    await sleep(300);
  }
  throw new Error(`Timed out: ${label}`);
}
const mainConfig = `worker_processes 1;
pid /tmp/lr-nginx.pid;
error_log /tmp/lr-nginx-error.log notice;
events { worker_connections 64; }
http {
  include /etc/nginx/mime.types;
  default_type application/octet-stream;
  include /etc/nginx/conf.d/00-risky.conf;
  include /etc/nginx/conf.d/99-safe.conf;
}
`;
const risky = `server {
  listen 127.0.0.1:8080;
  root /tmp/lr-nginx-www;
  server_tokens on;
  autoindex on;
  ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
  access_log off;
  error_log /dev/null;
}
`;
const safe = `server {
  listen 127.0.0.1:8081;
  root /tmp/lr-nginx-www;
  server_tokens off;
  autoindex off;
  ssl_protocols TLSv1.2 TLSv1.3;
  access_log /tmp/lr-nginx-access.log;
}
`;
function activate() {
  onHost("nginx", "-t");
  onHost("nginx", "-s", "reload");
}
function get(port, resource = "/", headers = false) {
  return onHost("curl", "--max-time", "3", "-sS", ...(headers ? ["-I"] : []), `http://127.0.0.1:${port}${resource}`);
}

try {
  imageId = JSON.parse(docker("image", "inspect", "lovelyres-svc:nginx"))[0].Id;
  const host = wsl("hostname", "-I").split(/\s+/)[0];
  if (!/^172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+$/.test(host)) throw new Error("Expected private WSL target address");
  containerId = docker("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`,
    "--network", "bridge", "--memory", "384m", "--cpus", "1", "--pids-limit", "128",
    "-p", `${host}::22`, imageId);
  const target = owned();
  const sshPort = Number(target.NetworkSettings.Ports["22/tcp"][0].HostPort);
  version = onHost("nginx", "-v");
  if (!version) version = onHost("sh", "-c", "nginx -v 2>&1");
  onHost("sh", "-c", "set -eu; rm -f /etc/nginx/conf.d/default.conf; mkdir -p /tmp/lr-nginx-www/risky /tmp/lr-nginx-www/safe; printf 'harmless lab evidence\n' > /tmp/lr-nginx-www/visible.txt; cp /tmp/lr-nginx-www/visible.txt /tmp/lr-nginx-www/risky/visible.txt");
  writeFixture("/etc/nginx/nginx.conf", mainConfig);
  writeFixture("/etc/nginx/conf.d/00-risky.conf", risky);
  writeFixture("/etc/nginx/conf.d/99-safe.conf", safe);
  onHost("nginx", "-t"); onHost("nginx");
  check("real first server exposes its version", /Server: nginx\//i.test(get(8080, "/", true)));
  check("real later server hides its version", /Server: nginx\r?\n/i.test(get(8081, "/", true)));
  check("real first server exposes a directory listing", get(8080).includes("visible.txt"));
  check("real later server refuses the directory listing", /403 Forbidden/.test(get(8081)));

  sidecar = new Sidecar(backend, dataRoot);
  const connected = await connect(sidecar, { host, port: sshPort, username: "root", password: "LabRoot#2026", name: "Nginx 隔离验证" });
  check("application connects to the disposable target", connected.stage, "connected");
  const bindingHandle = connected.bindingHandle;
  const catalog = await sidecar.call("baseline.catalog.get", {});
  const nginx = catalog.items.filter((item) => item.component === "nginx");
  check("all five Nginx checks use the scoped workflow boundary", nginx.length === 5 && nginx.every((item) => !item.writable));
  const item = (title) => {
    const found = nginx.find((candidate) => candidate.title.includes(title));
    if (!found) throw new Error(`Missing Nginx check: ${title}`);
    return found;
  };
  const scan = () => sidecar.call("baseline.scan", { bindingHandle }, 90_000);
  const row = (result, title) => result.statuses.find((entry) => entry.itemHandle === item(title).itemHandle);
  const first = await scan();
  check("later safe server cannot hide version exposure", row(first, "隐藏版本号").observed, "on");
  check("later safe server cannot hide directory listing", row(first, "关闭目录浏览").observed, "on");
  check("TLS presence is not a passing modern-protocol check", row(first, "TLS").compliant, false);
  check("legacy TLS configuration is preserved as a finding", row(first, "TLS").observed, "TLSv1");
  check("access_log off cannot be reported as logging configured", row(first, "访问日志").observed, "off");
  check("discarded error logs remain a finding", row(first, "错误日志").observed, "/dev/null");
  check("TLS recommendation requires instance capability, not mere presence", item("TLS").recommendation, "仅启用实例支持的 TLS 1.2/1.3");
  check("finding points to the risky candidate", row(first, "关闭目录浏览").fix.file, "/etc/nginx/conf.d/00-risky.conf");
  const file = await sidecar.call("baseline.file.read", { bindingHandle, itemHandle: item("关闭目录浏览").itemHandle }, 90_000);
  check("file view opens the finding source", file.path, "/etc/nginx/conf.d/00-risky.conf");
  check("file view never invents a unique effective Nginx line", file.mentions.every((mention) => !mention.effective));

  writeFixture("/etc/nginx/conf.d/00-risky.conf", `server { listen 127.0.0.1:8080; root /tmp/lr-nginx-www; server_tokens off;
    location /risky/ { server_tokens "on"; autoindex
      "on"; }
    location /safe/ { server_tokens off; autoindex off; }
  }`);
  activate();
  await until(() => /Server: nginx\//i.test(get(8080, "/risky/", true)), "new worker configuration");
  check("native nested location still exposes its listing", get(8080, "/risky/").includes("visible.txt"));
  const nested = await scan();
  check("inline nested directive is found", row(nested, "隐藏版本号").observed, "on");
  check("multiline quoted directive is found", row(nested, "关闭目录浏览").observed, "on");

  const safeFirst = safe.replace(":8081", ":8080").replace("  server_tokens off;", `  # server_tokens on; autoindex on;
  add_header X-Lab "server_tokens on; autoindex on; # not a directive";
  server_tokens off;
  error_log off;`);
  writeFixture("/etc/nginx/conf.d/00-risky.conf", safeFirst); activate();
  await until(() => /Server: nginx\r?\n/i.test(get(8080, "/", true)), "hidden version after fixture edit");
  const reviewed = await scan();
  check("comments and quoted strings do not become risky directives", nginx.every((entry) =>
    reviewed.statuses.find((status) => status.itemHandle === entry.itemHandle).observedKind === "unverified"));
  check("safe-looking candidate files are not claimed as effective compliance", nginx.every((entry) =>
    !reviewed.statuses.find((status) => status.itemHandle === entry.itemHandle).compliant));
  check("native fixture edit actually disables the directory listing", /403 Forbidden/.test(get(8080)));
  const build = onHost("sh", "-c", "nginx -V 2>&1");
  const prefix = /--prefix=([^\s]+)/.exec(build)?.[1];
  if (!prefix?.startsWith("/")) throw new Error("Nginx prefix was not reported");
  onHost("test", "-s", `${prefix}/off`);
  check("Nginx treats error_log off as a filename, not a disabled logger", true);

  onHost("sh", "-c", "test -e /usr/bin/awk && test ! -e /usr/bin/awk-lrprobe && mv /usr/bin/awk /usr/bin/awk-lrprobe");
  try {
    const unreadable = await scan();
    const ssh = catalog.items.find((entry) => entry.component === "ssh");
    check("missing parser is unresolved, not an implicit safe default", unreadable.statuses.find((entry) => entry.itemHandle === ssh.itemHandle).observedKind, "unverified");
  } finally { onHost("mv", "/usr/bin/awk-lrprobe", "/usr/bin/awk"); }
  writeFixture("/etc/nginx/conf.d/00-risky.conf", risky); activate();
  sidecar.close(); sidecar = undefined;

  if (process.env.NGINX_UI !== "0") {
    app = await startDesktop({ dataRoot, evidence, onConsoleError: (entry) => consoleErrors.push(JSON.stringify(entry.params).slice(0, 1500)) });
    session = app.session;
    await until(() => session.evaluate("document.querySelector('.connection-card button') !== null"), "saved connection");
    await session.evaluate("document.querySelector('.connection-card button').click()");
    await until(() => session.evaluate("document.querySelector('[data-testid=disconnect-target]:not([disabled])') !== null"), "connected UI", 160);
    await session.evaluate("[...document.querySelectorAll('.nav-item')].find(b => b.textContent.includes('配置')).click()");
    await until(() => session.evaluate("document.querySelector('.baseline-card-verdict.is-noncompliant') !== null"), "scanned UI", 180);
    await session.evaluate(`(() => { const input = document.querySelector('.baseline-filters input');
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, 'Nginx');
      input.dispatchEvent(new Event('input', {bubbles:true})); })()`);
    await until(() => session.evaluate("document.querySelectorAll('.baseline-card').length === 5"), "product search");
    check("UI product search finds all five Nginx checks", true);
    await session.evaluate("[...document.querySelectorAll('.baseline-card')].find(b => b.textContent.includes('关闭目录浏览')).click()");
    await until(() => session.evaluate("document.querySelector('.baseline-file-path')?.textContent === '/etc/nginx/conf.d/00-risky.conf'"), "finding file", 180);
    check("UI explains candidate scope instead of claiming effective configuration", await session.evaluate("document.querySelector('.baseline-file-verdict').textContent.includes('不能将某一行认定为唯一生效项')"));
    check("UI names the next safe repair step", await session.evaluate("document.querySelector('.baseline-fix-manual').textContent.includes('server/location')"));
    await session.shot("nginx-risk-candidates.png");
    writeFixture("/etc/nginx/conf.d/00-risky.conf", safeFirst); activate();
    await session.evaluate("[...document.querySelectorAll('.baseline-view-header button')].find(b => b.textContent.includes('扫描') && !b.disabled).click()");
    await until(() => session.evaluate("document.querySelectorAll('.baseline-card-verdict.is-review').length === 5"), "review state after fixture edit", 180);
    check("UI never turns unknown effective state green after an external fixture edit", await session.evaluate("document.querySelectorAll('.baseline-card-verdict.is-compliant').length === 0"));
    await until(() => session.evaluate("document.querySelector('.baseline-file-text')?.textContent.includes('autoindex off;') === true"), "fresh selected file after rescan", 180);
    check("UI refresh rereads the selected configuration", true);
    await session.shot("nginx-review-after-fixture-edit.png");
    // Match the actual window minimum (1080 × 700); a synthetic 850px viewport is
    // below the app's supported 1080px width and cannot be reached by resizing.
    await session.send("Emulation.setDeviceMetricsOverride", { width: 1080, height: 700, deviceScaleFactor: 1, mobile: false });
    await session.shot("nginx-narrow.png");
    const layout = await session.evaluate(`({ viewport: innerWidth, document: document.documentElement.scrollWidth,
      wide: [...document.querySelectorAll('body *')].map(e => ({ tag: e.tagName, class: e.className,
        left: e.getBoundingClientRect().left, right: e.getBoundingClientRect().right, width: e.getBoundingClientRect().width }))
        .filter(e => e.width > innerWidth || e.right > innerWidth + 1).slice(0, 30) })`);
    fs.writeFileSync(path.join(evidence, "narrow-layout.json"), JSON.stringify(layout, null, 2));
    check("minimum supported window has no horizontal document overflow", layout.document <= layout.viewport + 1);
    await session.evaluate("document.querySelector('[data-testid=disconnect-target]').click()");
    await until(() => session.evaluate("document.querySelector('.baseline-file-text') === null"), "cleared file on disconnect");
    check("UI clears target configuration on disconnect", true);
    check("desktop page has no exceptions or console errors", consoleErrors.length, 0);
  }
} catch (error) {
  checks.push({ label: "probe completed", passed: false, error: error.message });
  console.error(error.message); process.exitCode = 1;
} finally {
  sidecar?.close();
  if (app) await app.close();
  if (containerId) {
    try { owned(); docker("rm", "-f", containerId); check("only owned disposable target was removed", true); }
    catch (error) { checks.push({ label: "owned target cleanup", passed: false, error: error.message }); process.exitCode = 1; }
  }
  try {
    const temporaryRoot = fs.realpathSync(os.tmpdir());
    const resolvedRoot = fs.realpathSync(dataRoot);
    const relative = path.relative(temporaryRoot, resolvedRoot);
    if (!/^lovelyhawk-nginx-[A-Za-z0-9]{6}$/.test(relative)) throw new Error("Unexpected test data directory");
    fs.rmSync(resolvedRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 });
    check("isolated application data was removed", true);
  } catch (error) {
    checks.push({ label: "isolated data cleanup", passed: false, error: error.message }); process.exitCode = 1;
  }
  fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify({
    runId, date: new Date().toISOString(), mode: process.env.NGINX_UI === "0" ? "rpc" : "rpc-and-desktop",
    scope: "candidate configuration detection; fixture edits are not app repair evidence",
    containerId, imageId, version, dataRoot, checks, consoleErrors,
  }, null, 2));
  console.log(`Evidence: ${path.join(evidence, "report.json")}`);
}
