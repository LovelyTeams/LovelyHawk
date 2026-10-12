// Real finite RPC + native desktop CDP repair/restore, with independent HTTP
// and TLS checks. All mutations target this run's disposable, ownership-checked clone.
import { execFileSync, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";
import { inspectHtmlFile, startDesktop } from "./desktop.mjs";
import { Sidecar, connect } from "./rpc-harness.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID(), name = `lr-nginx-repair-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target/lab-nginx-repair", runId);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-nginx-repair-"));
fs.mkdirSync(evidence, { recursive: true });
const checks = [], consoleErrors = [], tlsObservations = {}, nativeTlsObservations = {}, nativeCaseObservations = {};
let containerId, imageId, sidecar, app, session, version, opensslVersion, platform, failure;
const startupErrors = [];
const keepalive = spawn("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", "cat"], { windowsHide: true, stdio: ["pipe", "ignore", "ignore"] });
keepalive.once("error", (error) => { failure ??= String(error); });
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
function check(label, actual) {
  checks.push({ label, passed: Boolean(actual) }); console.log(`${actual ? "PASS" : "FAIL"} ${label}`);
  if (!actual) throw new Error(label);
}
function wsl(...args) {
  return execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", ...args],
    { windowsHide: true, encoding: "utf8", timeout: 120_000, maxBuffer: 2 * 1024 * 1024 }).trim();
}
const docker = (...args) => wsl("docker", ...args);
function owned() {
  const target = JSON.parse(docker("inspect", containerId))[0];
  if (target.Id !== containerId || target.Name !== `/${name}` || target.Image !== imageId ||
    target.Config.Labels?.["lovelyres-test-run"] !== runId || target.Mounts.length !== 0 ||
    target.HostConfig.Privileged || target.HostConfig.NetworkMode !== "bridge") throw new Error("Test target identity changed");
  return target;
}
const onHost = (...args) => { owned(); return docker("exec", containerId, ...args); };
function fixture(file, content) {
  if (!["/etc/nginx/nginx.conf", "/etc/nginx/conf.d/lovelyres-process.conf", "/etc/nginx/lovelyres-tls.conf", "/etc/nginx/lovelyres-tls-policy.conf"].includes(file)) throw new Error("Unexpected fixture path");
  onHost("sh", "-c", `printf '%s' '${Buffer.from(content).toString("base64")}' | base64 -d > '${file}'`);
}
const site = `server {
  listen 127.0.0.1:8080;
  root /tmp/lr-nginx-www;
  server_tokens on;
  autoindex on;
  access_log /tmp/lr-nginx-access.log;
}
`;
const http = (headers = false) => onHost("curl", "--max-time", "3", "-sS", ...(headers ? ["-I"] : []), "http://127.0.0.1:8080/listing/");
function tls(version, serverName = "tls.lr.test") {
  if (!["tls1", "tls1_1", "tls1_2", "tls1_3"].includes(version) || !["tls.lr.test", "other.lr.test"].includes(serverName)) throw new Error("Invalid TLS fixture parameters");
  let output, exitCode = 0;
  try {
    output = onHost("sh", "-c", `printf 'GET / HTTP/1.0\\r\\nHost: ${serverName}\\r\\n\\r\\n' | timeout 6 openssl s_client -connect 127.0.0.1:8443 -servername ${serverName} -verify_hostname ${serverName} -verify_return_error -CAfile /tmp/lr-nginx-tls.crt -cipher DEFAULT:@SECLEVEL=0 -brief -ign_eof -${version} 2>&1`);
  } catch (error) { output = String(error.stdout ?? ""); exitCode = error.status; }
  return { exitCode, protocol: output.match(/Protocol version: (TLSv[^\s]+)/u)?.[1] ?? null,
    verified: exitCode === 0 && output.includes("Verification: OK") && output.includes("200 OK"),
    protocolRejected: /alert protocol version|unsupported protocol/u.test(output), output: output.slice(0, 8192) };
}
function tlsMatrix(label) {
  const result = Object.fromEntries(["tls1", "tls1_1", "tls1_2", "tls1_3"].map(version => [version, tls(version)]));
  tlsObservations[label] = result;
  return result;
}
async function until(fn, label, timeout = 60_000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) { if (await fn()) return; await sleep(300); }
  throw new Error(`Timed out: ${label}`);
}
async function refuses(work, code) {
  try { await work(); return false; } catch (error) { return error.message.startsWith(`${code}:`); }
}
const click = async (selector, text) => session.evaluate(`(() => {
  const item = [...document.querySelectorAll(${JSON.stringify(selector)})].find(e => e.textContent.includes(${JSON.stringify(text)}) && !e.disabled);
  if (!item) throw new Error('Enabled control not found'); item.click(); })()`);
const uiWait = (expression, label, timeout) => until(() => session.evaluate(expression), label, timeout);
const casesFile = path.join(dataRoot, "data", "cases.json");
const loadCases = () => JSON.parse(fs.readFileSync(casesFile, "utf8")).data;
const connectionEvidence = () => loadCases().cases.flatMap(incident => incident.evidence.filter(item => item.source === "nginx-tls-http/v1").map(item => ({ caseId: incident.id, caseTitle: incident.title, evidence: item })));
async function saveDialog(file) {
  if (path.dirname(path.resolve(file)) !== path.resolve(evidence)) throw new Error("Unexpected export path");
  // Answer only the next OS save dialog of this run's isolated debug app.
  app.setDialogAnswers([file]);
}
async function closeResult() {
  await click(".nginx-repair-dialog footer button", "关闭并查看历史");
  await uiWait("document.querySelector('.nginx-repair-history li') !== null", "history after write");
  check("result close keeps keyboard focus in the repair workbench", await session.evaluate("document.querySelector('.nginx-repair-workbench')?.contains(document.activeElement) === true"));
}
async function readUiEndpoints() {
  await click(".nginx-connectivity button", "读取监听端口");
  await uiWait("document.querySelectorAll('.nginx-connectivity select option').length > 1 || document.querySelector('.nginx-repair-error') !== null", "Nginx owned listeners");
  const error = await session.evaluate("document.querySelector('.nginx-repair-error')?.textContent ?? null");
  if (error) throw new Error(error);
}
async function probeUi(label, serverName = "tls.lr.test", httpPath = "/", listener = "127.0.0.1:8443", expectError = false, options = {}) {
  const expectUnsaved = options.expectUnsaved === true;
  const beforeIds = !expectError && !expectUnsaved && fs.existsSync(casesFile) ? connectionEvidence().map(item => item.evidence.id) : [];
  await session.evaluate(`(() => {
    const select = document.querySelector('.nginx-connectivity select');
    const option = [...select.options].find(e => e.textContent === ${JSON.stringify(listener)});
    if (!option) throw new Error('Expected owned listener missing');
    Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set.call(select, option.value);
    select.dispatchEvent(new Event('change', { bubbles: true }));
    for (const [label, value] of [["TLS 站点名称", ${JSON.stringify(serverName)}], ["TLS 复核 HTTP 路径", ${JSON.stringify(httpPath)}]]) {
      const input = document.querySelector('input[aria-label="' + label + '"]');
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, value);
      input.dispatchEvent(new Event('input', { bubbles: true }));
    }
  })()`);
  if (options.navigateDuringProbe) {
    // Both clicks occur before IPC can deliver a result, exercising real in-flight navigation.
    await session.evaluate("(() => { const submit = document.querySelector('.nginx-connectivity button[type=submit]'); if (submit.disabled) throw new Error('Probe disabled'); submit.click(); document.querySelector('.configuration-modes button[aria-pressed=false]').click(); })()");
  } else await click(".nginx-connectivity button", "开始连接复核");
  check("TLS probe disables duplicate submission and instance switching", await session.evaluate("document.querySelector('.nginx-connectivity button[type=submit]').disabled && document.querySelector('.nginx-repair-instances button').disabled"));
  await uiWait("document.querySelector('.nginx-connectivity-result') !== null || document.querySelector('.nginx-repair-error') !== null", "native connectivity result");
  const error = await session.evaluate("document.querySelector('.nginx-repair-error')?.textContent ?? null");
  if (expectError) { check(label, error?.includes("未能核实连接结果") && !await session.evaluate("document.querySelector('.nginx-connectivity-result') !== null")); return null; }
  if (error) {
    const helper = fs.readFileSync(path.join(repository, "crates/lovelyhawk-core/src/nginx_process.py"), "utf8").split('if __name__ == "__main__":')[0];
    const diagnostic = helper + "\ntry:\n e=discover()[0]\n endpoint=next(x for x in owned_listeners(e['pid'])[0] if x['port']==8443 and x['address']=='127.0.0.1')\n print(json.dumps(connectivity(e, {'endpoint':endpoint,'server_name':'tls.lr.test','path':'/'})))\nexcept Refusal as error:\n print(json.dumps({'refused':str(error)}))\nexcept Exception as error:\n print(json.dumps({'error_type':type(error).__name__}))\n";
    let result;
    try { result = onHost("python3", "-I", "-c", diagnostic); } catch (failure) { result = String(failure.stdout ?? "diagnostic unavailable"); }
    fs.writeFileSync(path.join(evidence, "connectivity-helper-diagnostic.json"), result);
    throw new Error(error);
  }
  const rows = await session.evaluate("[...document.querySelectorAll('.nginx-connectivity tbody tr')].map(row => [...row.cells].map(cell => cell.textContent))");
  nativeTlsObservations[label] = { listener, serverName, path: httpPath, rows };
  check(`${label}: four independently displayed versions`, rows.length === 4 && rows.map(row => row[0]).join(',') === 'TLS 1.0,TLS 1.1,TLS 1.2,TLS 1.3');
  check(`${label}: retention status matches actual local storage`, await session.evaluate(`document.querySelector('.nginx-retention-saved') !== null`) === !expectUnsaved);
  if (!expectUnsaved) {
    const added = connectionEvidence().filter(item => !beforeIds.includes(item.evidence.id));
    check(`${label}: one complete snapshot with record hash scope`, added.length === 1 && added[0].evidence.hash_scope === "stored-preview" && added[0].evidence.preview.includes(`站点名称：${serverName}\nHTTP 路径：${httpPath}\n`) && added[0].evidence.preview.endsWith("不是原始网络包摘要。\n"));
    nativeCaseObservations[label] = added[0];
  }
  return rows;
}
async function confirmUi() {
  await click(".nginx-repair-dialog footer button", "确认并执行");
  await uiWait("document.querySelector('.nginx-repair-dialog footer')?.textContent.includes('关闭并查看历史')", "repair result", 240_000);
  check("UI reports verified result", await session.evaluate("['修补已通过配置与进程验证', '已恢复先前配置'].includes(document.querySelector('.nginx-repair-dialog h2')?.textContent)"));
  check("UI has no mutation error", await session.evaluate("document.querySelector('.nginx-repair-dialog .nginx-repair-error') === null"));
}

try {
  imageId = JSON.parse(docker("image", "inspect", "lovelyres-svc:nginx"))[0].Id;
  const host = wsl("hostname", "-I").split(/\s+/)[0];
  if (!/^172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+$/.test(host)) throw new Error("Expected private WSL address");
  containerId = docker("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--network", "bridge", "--memory", "384m", "--cpus", "1", "--pids-limit", "128", "-p", `${host}::22`, imageId);
  check("owned nonprivileged fixture without mounts", Boolean(owned()));
  const port = Number(owned().NetworkSettings.Ports["22/tcp"][0].HostPort);
  onHost("sh", "-c", "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends python3 openssl ca-certificates > /tmp/lr-python-install.log 2>&1");
  platform = onHost("sh", "-c", "cat /etc/os-release; uname -m");
  opensslVersion = onHost("openssl", "version");
  fixture("/etc/nginx/nginx.conf", `worker_processes 1;
pid /tmp/lr-nginx.pid;
error_log /tmp/lr-nginx-error.log notice;
events { worker_connections 64; }
http { include /etc/nginx/mime.types; include conf.d/lovelyres-process.conf; }
`);
  fixture("/etc/nginx/conf.d/lovelyres-process.conf", site);
  onHost("sh", "-c", "mkdir -p /tmp/lr-nginx-www/listing; printf 'safe fixture' > /tmp/lr-nginx-www/listing/item.txt");
  onHost("nginx"); version = onHost("sh", "-c", "nginx -v 2>&1");
  check("HTTP fixture exposes directory listing and version", http().includes("Index of /listing/") && /Server: nginx\//i.test(http(true)));
  sidecar = new Sidecar(path.join(repository, "target/debug/lovelyhawk-backend.exe"), dataRoot);
  const connected = await connect(sidecar, { host, port, username: "root", password: "LabRoot#2026", id: runId, name });
  if (connected.stage !== "connected") throw new Error("Fixture SSH connection failed");
  const bindingHandle = connected.bindingHandle;
  const rpc = (request) => { owned(); return sidecar.call("nginx.repair", { bindingHandle, ...request }, 185_000); };
  check("RPC rejects injected file and arbitrary replacement", await refuses(() => rpc({ action: "discover", path: "/etc/passwd" }), "invalid-params"));
  const inventory = await rpc({ action: "discover" }); check("RPC discovers real Nginx process", inventory.instances.length === 1);
  const configuration = await rpc({ action: "load", instanceHandle: inventory.instances[0].instanceHandle });
  check("RPC exposes two exact candidates from the included file", configuration.candidates.length === 2 && configuration.candidates.every((c) => c.path === "/etc/nginx/conf.d/lovelyres-process.conf") && configuration.unresolvedIncludes === 0);
  const candidateHandle = configuration.candidates.find((c) => c.setting === "autoindex").candidateHandle;
  const prepared = await rpc({ action: "plan", configurationHandle: configuration.configurationHandle, candidateHandle });
  check("RPC plan identifies the bound SSH target and actual master", prepared.plan.targetLabel === `root@${host}:${port} · Nginx 主进程 ${inventory.instances[0].mainPid}`);
  check("RPC does not execute without confirmation", await refuses(() => rpc({ action: "execute", planHandle: prepared.plan.planHandle }), "invalid-params"));
  check("preparation and refused execution preserve exact fixture", onHost("cat", "/etc/nginx/conf.d/lovelyres-process.conf") === site.trim());
  await rpc({ action: "cancel", planHandle: prepared.plan.planHandle });
  check("cancelled RPC plan cannot be confirmed", await refuses(() => rpc({ action: "confirm", planHandle: prepared.plan.planHandle }), "nginx-repair-stale"));
  const second = await rpc({ action: "plan", configurationHandle: configuration.configurationHandle, candidateHandle });
  async function executeRpc(plan) {
    await rpc({ action: "confirm", planHandle: plan.planHandle });
    const job = await rpc({ action: "execute", planHandle: plan.planHandle }); let receipt;
    await until(async () => { receipt = (await rpc({ action: "execution", executionHandle: job.executionHandle })).receipt; return receipt !== null; }, "RPC verification", 240_000);
    check("RPC execution receipt is correlated and verified", receipt.planHandle === plan.planHandle && receipt.state === "verified");
    return receipt;
  }
  const receipt = await executeRpc(second.plan);
  check("HTTP independently confirms RPC directory repair", http(true).startsWith("HTTP/1.1 403"));
  check("RPC replay of consumed plan is refused", await refuses(() => rpc({ action: "execute", planHandle: second.plan.planHandle }), "nginx-repair-stale"));
  const history = await rpc({ action: "history" });
  check("RPC retains verified history and receipt restoration handle", history.records[0].state === "applied" && history.records[0].recordHandle === receipt.recordHandle);
  const restore = await rpc({ action: "restore", recordHandle: receipt.recordHandle });
  check("RPC restoration previews a concrete bounded diff", restore.plan.title === "恢复先前配置" && restore.plan.diff.includes("autoindex on"));
  await executeRpc(restore.plan);
  check("HTTP independently confirms RPC restoration", http().includes("Index of /listing/") && onHost("cat", "/etc/nginx/conf.d/lovelyres-process.conf") === site.trim());
  await sidecar.call("ssh.binding.disconnect", { bindingHandle });
  check("disconnected RPC binding cannot read previous history", await refuses(() => rpc({ action: "history" }), "nginx-repair-stale"));
  sidecar.close(); sidecar = undefined;

  // The probe attaches once the real main document has loaded. Errors the page
  // replays while Runtime/Log are enabled happened before that and are kept
  // apart as startup errors; later ones are this run's console errors. Save
  // dialogs answer from a script and copies go to a file, both debug-only hooks.
  app = await startDesktop({ dataRoot, evidence, dialogAnswers: [], clipboard: true, sessionTimeoutMs: 185_000,
    onConsoleError: (entry) => {
      if (entry.phase === "startup") { if (startupErrors.length < 128) startupErrors.push({ source: entry.source, url: entry.url, detail: JSON.stringify(entry.params).slice(0, 1500) }); }
      else consoleErrors.push(JSON.stringify(entry.params).slice(0, 1500));
    } });
  session = app.session;
  await uiWait("document.querySelector('.connection-card button') !== null", "saved connection");
  await session.evaluate("document.querySelector('.connection-card button').click()");
  await uiWait("document.querySelector('[data-testid=disconnect-target]:not([disabled])') !== null", "connected UI");
  await click(".nav-item", "配置");
  await uiWait("document.querySelector('.configuration-modes') !== null", "configuration page");
  await click(".configuration-modes button", "修补已有配置");
  await click(".nginx-repair-toolbar button", "识别 Nginx 实例");
  await uiWait("document.querySelector('.nginx-repair-instances button') !== null", "UI process discovery");
  await session.evaluate("document.querySelector('.nginx-repair-instances button').click()");
  await uiWait("document.querySelectorAll('.nginx-repair-candidates li').length === 2", "UI configuration candidates");
  await session.shot("nginx-repair-candidates.png");
  await session.evaluate("[...document.querySelectorAll('.nginx-repair-candidates li')].find(e => e.textContent.includes('关闭目录列表')).querySelector('button').click()");
  await uiWait("document.querySelector('.nginx-repair-confirm:not([disabled])') !== null", "UI plan");
  check("UI plan names exact file and line", await session.evaluate("document.querySelector('.nginx-repair-dialog .nginx-repair-location').textContent.includes('/etc/nginx/conf.d/lovelyres-process.conf · 第 5 行')"));
  check("UI confirmation names the bound host and process", await session.evaluate(`document.querySelector('.nginx-repair-target').textContent.includes(${JSON.stringify(`root@${host}:${port}`)}) && document.querySelector('.nginx-repair-target').textContent.includes('Nginx 主进程')`));
  check("UI initial focus chooses cancellation", await session.evaluate("document.activeElement?.textContent === '取消'"));
  check("UI confirmation has the theme danger text treatment", await session.evaluate("(() => { const probe = document.createElement('span'); probe.style.color = getComputedStyle(document.documentElement).getPropertyValue('--danger-text').trim(); return getComputedStyle(document.querySelector('.nginx-repair-confirm')).color === probe.style.color; })()"));
  await session.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
  await session.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
  await uiWait("document.querySelector('.nginx-repair-dialog') === null", "keyboard cancellation");
  check("UI cancellation returns focus to the selected repair control", await session.evaluate("document.activeElement?.getAttribute('aria-label')?.startsWith('准备修补：关闭目录列表') === true"));
  check("UI cancel preserves real file and HTTP behavior", http().includes("Index of /listing/") && onHost("cat", "/etc/nginx/conf.d/lovelyres-process.conf") === site.trim());
  await session.evaluate("[...document.querySelectorAll('.nginx-repair-candidates li')].find(e => e.textContent.includes('关闭目录列表')).querySelector('button').click()");
  await uiWait("document.querySelector('.nginx-repair-confirm:not([disabled])') !== null", "second UI plan");
  await session.send("Emulation.setDeviceMetricsOverride", { width: 1080, height: 700, deviceScaleFactor: 1, mobile: false });
  await session.shot("nginx-repair-confirm-minimum.png");
  check("minimum window contains the entire confirmation dialog", await session.evaluate("(() => { const box=document.querySelector('.nginx-repair-dialog').getBoundingClientRect(); return box.left>=0 && box.right<=innerWidth && box.top>=0 && box.bottom<=innerHeight; })()"));
  await confirmUi(); check("HTTP independently verifies UI directory repair", http(true).startsWith("HTTP/1.1 403"));
  await session.shot("nginx-repair-result.png"); await closeResult();
  await session.evaluate("document.querySelector('.nginx-repair-instances button').click()");
  await uiWait("document.querySelectorAll('.nginx-repair-candidates li').length === 1", "fresh graph after directory repair");
  await click(".nginx-repair-candidates li button", "准备修补");
  await uiWait("document.querySelector('.nginx-repair-confirm:not([disabled])') !== null", "version plan");
  check("UI version plan keeps a literal directive difference", await session.evaluate("document.querySelector('.nginx-repair-diff').textContent.includes('server_tokens off')"));
  await confirmUi(); check("HTTP independently verifies UI version suppression", /Server: nginx\r?\n/i.test(http(true)) && !/Server: nginx\//i.test(http(true)));
  await closeResult();
  await session.evaluate("document.querySelector('.nginx-repair-history li button').click()");
  await uiWait("document.querySelector('.nginx-repair-confirm:not([disabled])') !== null", "restore version plan");
  check("UI restoration has concrete before and after version values", await session.evaluate("document.querySelector('.nginx-repair-diff').textContent.includes('server_tokens on')"));
  await session.shot("nginx-repair-restore.png"); await confirmUi();
  check("HTTP independently verifies UI restoration", /Server: nginx\//i.test(http(true)) && http(true).startsWith("HTTP/1.1 403"));
  await closeResult();
  await session.evaluate("document.querySelector('.nginx-repair-instances button').click()");
  await uiWait("document.querySelectorAll('.nginx-repair-candidates li').length === 1", "candidate before concurrent change");
  await click(".nginx-repair-candidates li button", "准备修补");
  await uiWait("document.querySelector('.nginx-repair-confirm:not([disabled])') !== null", "plan before concurrent change");
  const concurrent = `${onHost("cat", "/etc/nginx/conf.d/lovelyres-process.conf")}\n# independent business edit after planning\n`;
  fixture("/etc/nginx/conf.d/lovelyres-process.conf", concurrent);
  await click(".nginx-repair-dialog footer button", "确认并执行");
  await uiWait("document.querySelector('.nginx-repair-dialog h2')?.textContent === '结果尚未核实'", "concurrent edit refused", 240_000);
  check("UI does not label a rejected concurrent write successful", await session.evaluate("document.querySelector('.nginx-repair-dialog [role=status]')?.textContent.includes('不要重放旧计划')"));
  check("concurrent business edit and previous HTTP behavior survive UI execution", onHost("cat", "/etc/nginx/conf.d/lovelyres-process.conf") === concurrent.trim() && /Server: nginx\//i.test(http(true)));
  await session.shot("nginx-repair-concurrent-change.png"); await closeResult();

  // A real weak TLS fixture: the reduced OpenSSL security level applies only
  // inside this disposable container. Product repair never changes ciphers or
  // security levels. Keep private-key paths outside the edited policy file.
  onHost("sh", "-c", "umask 077; openssl req -x509 -newkey rsa:2048 -sha256 -days 1 -nodes -subj /CN=tls.lr.test -addext 'subjectAltName=DNS:tls.lr.test,DNS:other.lr.test' -keyout /tmp/lr-nginx-tls.key -out /tmp/lr-nginx-tls.crt >/tmp/lr-tls-cert.log 2>&1");
  const tlsPolicy = "# policy shared by the default TLS server\nssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;\n";
  fixture("/etc/nginx/lovelyres-tls-policy.conf", tlsPolicy);
  fixture("/etc/nginx/lovelyres-tls.conf", `server {
  listen 127.0.0.1:8443 ssl default_server;
  listen [::1]:8443 ssl default_server;
  server_name tls.lr.test;
  access_log /tmp/lr-nginx-tls-access.log;
  ssl_certificate /tmp/lr-nginx-tls.crt;
  ssl_certificate_key /tmp/lr-nginx-tls.key;
  ssl_ciphers DEFAULT:@SECLEVEL=0;
  include /etc/nginx/lovelyres-tls-policy.conf;
  location / { return 200 'TLS fixture ready\\n'; }
  location = /missing { return 404; }
}
server {
  listen 127.0.0.1:8443 ssl;
  listen [::1]:8443 ssl;
  server_name other.lr.test;
  access_log /tmp/lr-nginx-tls-access.log;
  ssl_certificate /tmp/lr-nginx-tls.crt;
  ssl_certificate_key /tmp/lr-nginx-tls.key;
  ssl_ciphers DEFAULT:@SECLEVEL=0;
  ssl_protocols TLSv1.2;
  return 200 'Other TLS fixture ready\\n';
}
`);
  fixture("/etc/nginx/nginx.conf", "worker_processes 1;\npid /tmp/lr-nginx.pid;\nerror_log /tmp/lr-nginx-error.log notice;\nevents { worker_connections 64; }\nhttp { include /etc/nginx/mime.types; include conf.d/lovelyres-process.conf; include /etc/nginx/lovelyres-tls.conf; }\n");
  onHost("sh", "-c", "nginx -t && nginx -s reload");
  await until(() => tls("tls1_2").verified, "TLS fixture startup");
  const beforeTls = tlsMatrix("beforeRepair");
  check("TLS fixture actually accepts TLS 1.0 1.1 1.2 and 1.3 with a verified certificate", Object.values(beforeTls).every(result => result.verified) && beforeTls.tls1.protocol === "TLSv1" && beforeTls.tls1_1.protocol === "TLSv1.1" && beforeTls.tls1_2.protocol === "TLSv1.2" && beforeTls.tls1_3.protocol === "TLSv1.3");
  tlsObservations.otherServerBefore = tls("tls1", "other.lr.test");
  check("independent SNI observation exposes the default server protocol policy", tlsObservations.otherServerBefore.verified);
  await session.evaluate("document.querySelector('.nginx-repair-instances button').click()");
  await uiWait("[...document.querySelectorAll('.nginx-repair-candidates li')].some(e => e.textContent.includes('移除旧版 TLS/SSL 协议'))", "TLS candidate");
  await readUiEndpoints();
  const untrusted = await probeUi("untrustedCertificate");
  check("native TLS client refuses self-signed certificate and sends no HTTP", untrusted.slice(2).every(row => row[1] === "证书校验失败" && row[3] === "未发送"));
  check("native legacy observations never claim certificate or HTTP verification", untrusted.slice(0, 2).every(row => row[1] === "接受旧协议" && row[2] === "未校验" && row[3] === "未发送"));
  // Trust this run's generated certificate only inside its disposable target.
  onHost("sh", "-c", "cp /tmp/lr-nginx-tls.crt /usr/local/share/ca-certificates/lovelyres-fixture.crt && update-ca-certificates >/tmp/lr-ca-update.log 2>&1");
  const trusted = await probeUi("trustedBeforeRepair");
  check("native modern TLS verifies target trust store and HEAD response", trusted.slice(2).every(row => row[1] === "握手已完成" && row[2] === "已校验" && row[3] === "HTTP 200"));
  const wrongName = await probeUi("wrongCertificateName", "unknown.lr.test");
  check("native certificate hostname mismatch cannot send HTTP", wrongName.slice(2).every(row => row[1] === "证书校验失败" && row[3] === "未发送"));
  const missing = await probeUi("missingHttpPath", "tls.lr.test", "/missing");
  check("native HEAD preserves HTTP 404 without claiming business recovery", missing.slice(2).every(row => row[3] === "HTTP 404"));
  const ipv6 = await probeUi("ipv6Listener", "tls.lr.test", "/", "[::1]:8443");
  check("native IPv6 listener produces verified modern TLS and HTTP", ipv6.slice(2).every(row => row[2] === "已校验" && row[3] === "HTTP 200"));
  const plainHttp = await probeUi("plainHttpListener", "tls.lr.test", "/", "127.0.0.1:8080");
  check("plain HTTP handshake failure is never reported as disabled TLS", plainHttp.every(row => row[1] === "未能判断"));
  await probeUi("beforeRepair");
  await session.evaluate("document.querySelector('.nginx-connectivity-result').scrollIntoView({block:'center'})");
  await session.shot("nginx-connectivity-before.png");
  await session.evaluate("[...document.querySelectorAll('.nginx-repair-candidates li')].find(e => e.textContent.includes('移除旧版 TLS/SSL 协议')).querySelector('button').click()");
  await uiWait("document.querySelector('.nginx-repair-confirm:not([disabled])') !== null", "TLS plan");
  check("TLS confirmation previews the exact reduction and client compatibility impact", await session.evaluate("document.querySelector('.nginx-repair-diff').textContent.includes('+ ssl_protocols TLSv1.2 TLSv1.3;') && document.querySelector('.nginx-repair-plan-details').textContent.includes('客户端可能无法连接') && document.querySelector('.nginx-repair-plan-details').textContent.includes('默认服务器')"));
  check("TLS review keeps certificate and cipher configuration out of this change", await session.evaluate("!document.querySelector('.nginx-repair-diff').textContent.includes('ssl_certificate') && !document.querySelector('.nginx-repair-diff').textContent.includes('ssl_ciphers')"));
  await session.shot("nginx-tls-review-minimum.png");
  await click(".nginx-repair-dialog footer button", "取消");
  await uiWait("document.querySelector('.nginx-repair-dialog') === null", "TLS cancellation");
  check("cancelling TLS repair preserves the original policy and connection", onHost("cat", "/etc/nginx/lovelyres-tls-policy.conf") === tlsPolicy.trim() && tls("tls1").verified);
  await session.evaluate("[...document.querySelectorAll('.nginx-repair-candidates li')].find(e => e.textContent.includes('移除旧版 TLS/SSL 协议')).querySelector('button').click()");
  await uiWait("document.querySelector('.nginx-repair-confirm:not([disabled])') !== null", "confirmed TLS plan");
  await confirmUi();
  const afterTls = tlsMatrix("afterRepair");
  check("native repair disables TLS 1.0 and 1.1 while preserving verified TLS 1.2 and 1.3 HTTP", afterTls.tls1.protocolRejected && afterTls.tls1_1.protocolRejected && afterTls.tls1_2.verified && afterTls.tls1_3.verified);
  tlsObservations.otherServerAfter = tls("tls1", "other.lr.test");
  check("the default server policy is independently verified for the other SNI name", tlsObservations.otherServerAfter.protocolRejected);
  check("TLS result does not equate configuration validation with business verification", await session.evaluate("document.querySelector('.nginx-repair-dialog').textContent.includes('不能替代业务健康检查')"));
  check("TLS repair preserves unrelated HTTP behavior and cipher policy", http(true).startsWith("HTTP/1.1 403") && onHost("cat", "/etc/nginx/lovelyres-tls.conf").includes("ssl_ciphers DEFAULT:@SECLEVEL=0;"));
  await session.shot("nginx-tls-result.png"); await closeResult();
  await session.evaluate("document.querySelector('.nginx-repair-instances button').click()");
  await uiWait("document.querySelector('.nginx-repair-candidates') !== null && !document.querySelector('.nginx-repair-candidates').textContent.includes('移除旧版 TLS/SSL 协议')", "TLS repair is idempotent");
  check("a fresh graph offers no repeated TLS edit", !await session.evaluate("[...document.querySelectorAll('.nginx-repair-candidates li')].some(e => e.textContent.includes('移除旧版 TLS/SSL 协议'))"));
  await readUiEndpoints();
  const productAfter = await probeUi("afterRepair");
  check("native product confirms old TLS rejection and verified modern HEAD after repair", productAfter.slice(0, 2).every(row => row[1] === "明确拒绝此版本") && productAfter.slice(2).every(row => row[2] === "已校验" && row[3] === "HTTP 200"));
  await session.evaluate("document.querySelector('.nginx-connectivity-result').scrollIntoView({block:'center'})");
  await session.shot("nginx-connectivity-after.png");

  await click(".nginx-repair-toolbar button", "查看修补历史");
  await uiWait("[...document.querySelectorAll('.nginx-repair-history li')].some(e => e.textContent.includes('/etc/nginx/lovelyres-tls-policy.conf'))", "TLS history");
  await session.evaluate("[...document.querySelectorAll('.nginx-repair-history li')].find(e => e.textContent.includes('/etc/nginx/lovelyres-tls-policy.conf') && !e.querySelector('button').disabled).querySelector('button').click()");
  await uiWait("document.querySelector('.nginx-repair-confirm:not([disabled])') !== null", "TLS restore review");
  check("TLS restoration explicitly warns that old protocols can return", await session.evaluate("document.querySelector('.nginx-repair-diff').textContent.includes('TLSv1 TLSv1.1 TLSv1.2 TLSv1.3') && document.querySelector('.nginx-repair-plan-details').textContent.includes('可能重新启用旧版 TLS/SSL 协议')"));
  await session.shot("nginx-tls-restore-review.png"); await confirmUi();
  const restoredTls = tlsMatrix("afterRestore");
  check("native restoration recovers the complete policy and actual prior TLS behavior", onHost("cat", "/etc/nginx/lovelyres-tls-policy.conf") === tlsPolicy.trim() && Object.values(restoredTls).every(result => result.verified));
  await closeResult();
  await readUiEndpoints();
  const productRestored = await probeUi("afterRestore");
  check("native product detects restored legacy TLS acceptance", productRestored.slice(0, 2).every(row => row[1] === "接受旧协议") && productRestored.slice(2).every(row => row[3] === "HTTP 200"));
  await session.evaluate("document.querySelector('.nginx-connectivity-result').scrollIntoView({block:'center'})");
  await session.shot("nginx-connectivity-restored.png");
  const changedListenerConfig = onHost("cat", "/etc/nginx/lovelyres-tls.conf").replaceAll(":8443", ":8444");
  fixture("/etc/nginx/lovelyres-tls.conf", changedListenerConfig);
  onHost("sh", "-c", "nginx -t && nginx -s reload");
  await sleep(800);
  await probeUi("native stale listener is refused without retaining old results", "tls.lr.test", "/", "127.0.0.1:8443", true);
  await readUiEndpoints();
  const newListener = await probeUi("refreshedListener", "tls.lr.test", "/", "127.0.0.1:8444");
  check("refresh observes the replacement listener before reconnecting", newListener.slice(2).every(row => row[3] === "HTTP 200"));

  // Fail only the local case store, never the remote probe or RPC implementation.
  const resolvedRoot = fs.realpathSync(dataRoot), resolvedTemp = fs.realpathSync(os.tmpdir());
  if (path.dirname(resolvedRoot) !== resolvedTemp || !/^lovelyhawk-nginx-repair-[A-Za-z0-9]{6}$/u.test(path.basename(resolvedRoot)) ||
    fs.realpathSync(path.dirname(casesFile)) !== path.join(resolvedRoot, "data") || fs.lstatSync(casesFile).isSymbolicLink() || !fs.lstatSync(casesFile).isFile()) throw new Error("Unexpected owned case store");
  const backupFile = `${casesFile}.nginx-test-backup`, originalBytes = fs.readFileSync(casesFile);
  if (fs.existsSync(backupFile)) throw new Error("Unexpected case fixture backup");
  const priorRecords = connectionEvidence(), priorActive = loadCases().active_case_by_target[runId];
  let unsavedRecord, unsavedTime;
  fs.renameSync(casesFile, backupFile);
  try {
    fs.mkdirSync(casesFile);
    const unsaved = await probeUi("localStoreUnavailable", "tls.lr.test", "/", "127.0.0.1:8444", false, { expectUnsaved: true, navigateDuringProbe: true });
    check("local storage failure preserves independently verified TLS results", unsaved.slice(2).every(row => row[2] === "已校验" && row[3] === "HTTP 200"));
    unsavedRecord = await session.evaluate("document.querySelector('.nginx-connectivity-record').textContent");
    unsavedTime = await session.evaluate("document.querySelector('.nginx-connectivity-result time').dateTime");
    check("unsaved record contains original source, process identity, time and all four outcomes", unsavedRecord.includes(`来源主机：root@${host}:${port}`) && unsavedRecord.includes(`观察完成（UTC）：${unsavedTime}`) && /进程身份 SHA-256：[0-9a-f]{64}/u.test(unsavedRecord) && ["TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"].every(value => unsavedRecord.includes(value)));
    check("unsaved result prevents replacement reads and names a recovery action", await session.evaluate("document.querySelector('.nginx-connectivity button[type=submit]').disabled && document.querySelector('.nginx-repair-instances button').disabled && document.querySelector('.nginx-connectivity-result').textContent.includes('重试保存本次观察')"));
    check("unknown original case destination is explicit before retry", await session.evaluate("document.querySelector('.nginx-connectivity-result').textContent.includes('重试保存时使用届时的当前案件')"));
    await uiWait("document.querySelector('[role=dialog]')?.textContent.includes('放弃未保存的连接观察')", "wait for probe before reviewing unsaved navigation");
    check("in-flight navigation waits for retention and keeps the original workbench", await session.evaluate("document.querySelector('.configuration-modes [aria-pressed=true]').textContent.includes('修补已有配置') && document.querySelector('.nginx-connectivity-result') !== null"));
    check("unsaved navigation review initially focuses cancellation", await session.evaluate("document.activeElement?.textContent === '取消'"));
    await click("[role=dialog] button", "取消");
    await uiWait("document.querySelector('[role=dialog]') === null", "cancel discarding original observation");
    check("cancelled navigation keeps the full original observation", await session.evaluate("document.querySelector('.nginx-connectivity-record').textContent") === unsavedRecord);
    await click("[data-testid=disconnect-target]", "断开");
    await uiWait("document.querySelector('[role=dialog]')?.textContent.includes('放弃未保存的连接观察')", "protect unsaved record before disconnect");
    await click("[role=dialog] button", "取消");
    await uiWait("document.querySelector('[role=dialog]') === null && document.querySelector('[data-testid=disconnect-target]:not([disabled])') !== null", "cancel disconnect and keep target");
    check("cancelling disconnect preserves the live target and unsaved record", await session.evaluate("document.querySelector('.nginx-connectivity-record').textContent") === unsavedRecord);
    await session.evaluate("document.querySelector('.nginx-connectivity-result').scrollIntoView({block:'start'})");
    await session.shot("nginx-connectivity-unsaved.png");
  } finally {
    if (fs.existsSync(casesFile)) {
      if (fs.lstatSync(casesFile).isSymbolicLink() || !fs.lstatSync(casesFile).isDirectory() || fs.realpathSync(casesFile) !== path.join(resolvedRoot, "data", "cases.json")) throw new Error("Unexpected case failure fixture");
      fs.rmdirSync(casesFile); // Must be the exact empty directory created above.
    }
    fs.renameSync(backupFile, casesFile);
    check("original owned case store survives local fault injection unchanged", fs.readFileSync(casesFile).equals(originalBytes));
  }
  const requestsBeforeRetry = onHost("cat", "/tmp/lr-nginx-tls-access.log");
  await click(".nginx-retention-actions button", "重试保存本次观察");
  await uiWait("document.querySelector('.nginx-retention-saved') !== null", "save cached observation without another probe");
  const afterRetry = connectionEvidence(), retried = afterRetry.filter(item => !priorRecords.some(old => old.evidence.id === item.evidence.id));
  check("retry appends exactly one original record without changing previous evidence", retried.length === 1 && retried[0].evidence.preview === unsavedRecord && priorRecords.every(old => afterRetry.some(item => isDeepStrictEqual(item, old))));
  nativeCaseObservations.retried = retried[0];
  const savedCase = retried[0];
  check("retry preserves observation time and sends no additional TLS HEAD requests", await session.evaluate("document.querySelector('.nginx-connectivity-result time').dateTime") === unsavedTime && onHost("cat", "/tmp/lr-nginx-tls-access.log") === requestsBeforeRetry);
  check("saved receipt names the actual case and stored record digest", await session.evaluate(`document.querySelector('.nginx-connectivity-result').textContent.includes(${JSON.stringify(savedCase.caseTitle)}) && document.querySelector('.nginx-connectivity-result').textContent.includes(${JSON.stringify(savedCase.evidence.sha256)})`));

  // Clipboard writes are captured at the host boundary into this run's file (debug-build hook).
  app.clearClipboard();
  await click(".nginx-retention-actions button", "复制完整记录");
  await uiWait("document.querySelector('.nginx-connectivity-result').textContent.includes('已复制完整观察记录')", "explicit record copy");
  check("copy uses the complete original observation without touching the user clipboard", app.readClipboard() === unsavedRecord);
  await click(".nginx-retention-actions button", "查看留证案件");
  await uiWait(`document.querySelector('[data-testid=case-library] .case-detail h2')?.textContent === ${JSON.stringify(savedCase.caseTitle)} && document.querySelector('.case-detail').textContent.includes(${JSON.stringify(savedCase.caseId)})`, "open exact retained case");
  check("opening retained case preserves collection selection", loadCases().active_case_by_target[runId] === priorActive);
  await session.shot("nginx-connectivity-case.png");
  await click(".cases-mode button", "当前主机");
  await uiWait("document.querySelector('.case-list-item') !== null && document.querySelector('[data-testid=case-library]') === null", "live case report source");
  await click(".case-list-item", savedCase.caseTitle);
  await uiWait(`document.querySelector('.case-detail h2')?.textContent === ${JSON.stringify(savedCase.caseTitle)}`, "selected original case");
  await click(".case-detail button", "生成此案报告");
  await uiWait("document.querySelector('.disposal-report-evidence') !== null", "connectivity case report");
  await click(".disposal-report-body nav button", "Markdown");
  await uiWait("document.querySelector('.disposal-report-preview pre')?.textContent.includes('nginx-tls-http/v1')", "complete connection record in report");
  const markdown = await session.evaluate("document.querySelector('.disposal-report-preview pre').textContent");
  check("report keeps source and failure observations beside repair and restore checks", afterRetry.every(item => markdown.includes(item.evidence.sha256) && markdown.includes(item.evidence.locator)) && ["证书校验失败", "TLS 1.0：接受旧协议", "TLS 1.0：服务端明确拒绝此版本", "HTTP 404", "未能判断", `来源主机：root@${host}:${port}`].every(value => markdown.includes(value)));
  for (const [extension, label] of [["md", "保存 MD"], ["html", "保存 HTML"]]) {
    const output = path.join(evidence, `nginx-connectivity-case.${extension}`);
    await saveDialog(output); await click(".disposal-report-heading button", label);
    await until(() => fs.existsSync(output), `${extension} report export`);
    const text = fs.readFileSync(output, "utf8");
    check(`${extension} export retains every stored observation and its scope`, afterRetry.every(item => text.includes(item.evidence.sha256) && text.includes(item.evidence.locator)) && text.includes("不是原始网络包摘要") && text.includes("HTTP 404"));
    await uiWait("[...document.querySelectorAll('.disposal-report-heading button')].filter(e => e.textContent.includes('保存')).every(e => !e.disabled)", "report export complete");
  }
  // Changed in the Tauri port: there is no hidden window to render the export, so it is parsed inertly in the page; layout overflow and the rendered screenshot are no longer observed.
  const standalone = await inspectHtmlFile(session, path.join(evidence, "nginx-connectivity-case.html"),
    "(d) => { const item = d.querySelector('.evidence-detail'); return { record: item?.textContent, records: d.querySelectorAll('.evidence-detail').length, activeContent: d.querySelector('script,iframe,img') !== null }; }");
  check("standalone HTML holds complete source records without active content", standalone.records === afterRetry.length && standalone.record.includes(`来源主机：root@${host}:${port}`) && standalone.record.includes("不是原始网络包摘要") && !standalone.activeContent);
  await session.shot("nginx-connectivity-report.png");
  await click(".disposal-report-heading button", "关闭");
  await click(".nav-item", "配置"); await uiWait("document.querySelector('.configuration-modes') !== null", "return to configuration");
  await click(".configuration-modes button", "修补已有配置");
  await click(".nginx-repair-toolbar button", "识别 Nginx 实例");
  await uiWait("document.querySelector('.nginx-repair-instances button') !== null", "rediscover before disconnect");
  check("minimum window has no horizontal document overflow", await session.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"));
  await session.shot("nginx-repair-history-minimum.png");
  await session.evaluate("document.querySelector('[data-testid=disconnect-target]').click()");
  await uiWait("document.querySelector('.nginx-repair-empty')?.textContent.includes('请先连接')", "disconnect clears repair scope");
  check("UI removes target instances and history on disconnect", await session.evaluate("document.querySelectorAll('.nginx-repair-instances button, .nginx-repair-history li').length === 0"));
  await session.shot("nginx-repair-disconnected.png");
  await click(".nav-item", "案件");
  await uiWait("document.querySelector('[data-testid=case-library] .case-list-item') !== null", "offline case after disconnect");
  await click(".case-list-item", savedCase.caseTitle);
  await uiWait(`document.querySelector('.case-detail h2')?.textContent === ${JSON.stringify(savedCase.caseTitle)} && document.querySelectorAll('.case-entry').length > 0`, "offline connection evidence");
  const jsonFile = path.join(evidence, "nginx-connectivity-case.json");
  await saveDialog(jsonFile); await click(".case-detail button", "导出完整案件 JSON");
  await until(() => fs.existsSync(jsonFile), "offline complete case export");
  await uiWait("document.querySelector('.case-notice')?.textContent.includes('已导出')", "offline export verified");
  const exported = JSON.parse(fs.readFileSync(jsonFile, "utf8"));
  check("offline JSON preserves complete records, original timestamps and hash scopes", exported.schema === "lovelyres-incident-case/v1" && exported.incident_case.id === savedCase.caseId && afterRetry.every(item => exported.incident_case.evidence.some(record => isDeepStrictEqual(record, item.evidence))));
  check("offline evidence view fits the minimum window", await session.evaluate("document.documentElement.scrollWidth <= innerWidth + 1 && document.querySelector('.case-workspace').scrollWidth <= document.querySelector('.case-workspace').clientWidth + 1"));
  await session.shot("nginx-connectivity-offline.png");
  check("no page errors were replayed from startup when the probe attached", startupErrors.length === 0);
  check("desktop page has no exceptions or console errors", consoleErrors.length === 0);
} catch (error) {
  failure = String(error); console.error(failure); process.exitCode = 1;
  if (session) { try { await session.shot("failure.png"); fs.writeFileSync(path.join(evidence, "failure-text.txt"), await session.evaluate("document.body.innerText")); } catch {} }
} finally {
  sidecar?.close();
  if (app) await app.close();
  if (containerId) { try { owned(); docker("rm", "-f", containerId); check("owned container removed", true); } catch (error) { failure ??= String(error); process.exitCode = 1; } }
  try {
    const resolved = fs.realpathSync(dataRoot), temp = fs.realpathSync(os.tmpdir());
    if (path.dirname(resolved) !== temp || !/^lovelyhawk-nginx-repair-[A-Za-z0-9]{6}$/u.test(path.basename(resolved))) throw new Error("Unexpected test data directory");
    fs.rmSync(resolved, { recursive: true, maxRetries: 10, retryDelay: 300 }); check("isolated app data removed", true);
  } catch (error) { failure ??= String(error); process.exitCode = 1; }
  fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify({ runId, date: new Date().toISOString(), mode: "rpc-and-native-desktop", imageId, version, opensslVersion, platform,
    checks, consoleErrors, startupErrors, tlsObservations, nativeTlsObservations, nativeCaseObservations, error: failure ?? null, limits: ["Nginx conventional invocation with Python 3.9+ and Linux pidfd", "single Debian amd64 container; broader OS/runtime matrix pending", "Product TLS/HEAD observations cover target-local listeners and named sites only; external/client and business-data checks remain separate", "Low server cipher security and temporary CA trust are owned-fixture setup only; product legacy probes lower only their own client context and send no HTTP", "Local store failure, scripted save-dialog answers and the clipboard capture file are isolated test fixtures; pending records are not a durable queue", "Page console observation begins when CDP attaches to the loaded main document; earlier messages are those the page replays when Runtime/Log are enabled", "Exported HTML is parsed inertly in the app page; its rendered layout and screenshot are not captured (the Tauri host has no hidden window)"] }, null, 2));
  console.log(`Evidence: ${path.join(evidence, "report.json")}`); keepalive.stdin.end();
}
