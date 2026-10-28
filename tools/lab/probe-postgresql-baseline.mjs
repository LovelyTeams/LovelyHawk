// Real PostgreSQL parsing, runtime values, finite baseline RPC and native UI.
// Fixture edits/ALTER SYSTEM are test inputs, not product remediation evidence.
import { execFileSync, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { startDesktop } from "./desktop.mjs";
import { Sidecar, connect } from "./rpc-harness.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID(), name = `lr-postgresql-baseline-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target/lab-postgresql-baseline", runId);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-postgresql-baseline-"));
fs.mkdirSync(evidence, { recursive: true });
const pgdata = "/var/lib/postgresql/data", config = `${pgdata}/postgresql.conf`, auto = `${pgdata}/postgresql.auto.conf`;
const reader = fs.readFileSync(path.join(repository, "crates/lovelyhawk-core/src/baseline_postgresql.awk"), "utf8");
const checks = [], observations = {}, consoleErrors = [];
let containerId, imageId, version, platform, sidecar, app, session, failure;
const keepalive = spawn("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", "cat"], { windowsHide: true, stdio: ["pipe", "ignore", "ignore"] });
keepalive.once("error", error => { failure ??= String(error); });
function wsl(...args) { return execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", ...args], { encoding: "utf8", windowsHide: true, timeout: 60_000, maxBuffer: 2 * 1024 * 1024 }).trim(); }
const docker = (...args) => wsl("docker", ...args);
function owned() {
  const target = JSON.parse(docker("inspect", containerId))[0];
  if (target.Id !== containerId || target.Image !== imageId || target.Name !== `/${name}` || target.Config.Labels?.["lovelyres-test-run"] !== runId ||
    target.HostConfig.Privileged || target.HostConfig.NetworkMode !== "bridge" || target.Mounts.some(mount => mount.Type !== "tmpfs" || mount.Destination !== pgdata) ||
    target.HostConfig.Tmpfs?.[pgdata] !== "rw,noexec,nosuid,size=256m") throw new Error("PostgreSQL fixture identity or storage changed");
  return target;
}
function onHost(...args) { owned(); return docker("exec", containerId, ...args); }
function asPostgres(...args) { owned(); return docker("exec", "--user", "postgres", containerId, ...args); }
function writeFixture(file, content) {
  if (![config, "/etc/postgresql/postgresql.conf", "/tmp/lr-pg-reader.conf", "/tmp/lr-pg-other.conf", "/tmp/lr-pg-reader.awk"].includes(file)) throw new Error("Unexpected PostgreSQL fixture file");
  owned();
  // stdin preserves quotes/newlines and avoids the Windows command-line limit.
  execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", "docker", "exec", "-i", containerId, "sh", "-c", `cat > '${file}'`],
    { input: content, encoding: "utf8", windowsHide: true, timeout: 60_000, maxBuffer: 2 * 1024 * 1024 });
}
const sql = command => asPostgres("psql", "-X", "-w", "-At", "-v", "ON_ERROR_STOP=1", "-d", "postgres", "-c", command);
const runtime = () => JSON.parse(sql("SELECT json_object_agg(name, json_build_object('setting',setting,'source',source,'sourcefile',sourcefile,'pending_restart',pending_restart)) FROM pg_settings WHERE name IN ('listen_addresses','password_encryption','log_connections','log_disconnections','log_statement','logging_collector','ssl')"));
function check(label, value) { checks.push({ label, passed: Boolean(value) }); console.log(`${value ? "PASS" : "FAIL"} ${label}`); if (!value) throw new Error(label); }
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(fn, label) { const end = Date.now() + 60_000; while (Date.now() < end) { if (await fn()) return; await sleep(200); } throw new Error(`Timed out: ${label}`); }
const click=(selector,text)=>session.evaluate(`(()=>{const button=[...document.querySelectorAll(${JSON.stringify(selector)})].find(e=>e.textContent.includes(${JSON.stringify(text)})&&!e.disabled);if(!button)throw new Error('Control missing');button.click();})()`);
const uiWait=(expression,label)=>until(()=>session.evaluate(expression),label);

try {
  // Independent GNU awk byte-limit checks on WSL; no target packages installed.
  const wslReader = wsl("wslpath", "-u", path.join(repository, "crates/lovelyhawk-core/src/baseline_postgresql.awk").replaceAll("\\", "/"));
  observations.gnuAwk = { version: wsl("gawk", "--version").split("\n")[0], scope: "WSL Ubuntu, LC_ALL=C", samples: [] };
  for (const [label, input, expected] of [
    ["short UTF-8 comment preserves candidate", "ssl = off\n#中文注释\n", "off"],
    ["UTF-8 physical-line ceiling counts bytes", `ssl = off\n#${"汉".repeat(6000)}\n`, "__unverified__"],
    ["UTF-8 file ceiling counts bytes", `ssl = off\n${("#" + "汉".repeat(1000) + "\n").repeat(180)}`, "__unverified__"],
  ]) {
    const observed = execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", "env", "LC_ALL=C", "gawk", "-v", "k=ssl", "-f", wslReader],
      { input, encoding: "utf8", windowsHide: true, timeout: 60_000, maxBuffer: 2 * 1024 * 1024 }).trim();
    observations.gnuAwk.samples.push({ label, bytes: Buffer.byteLength(input), observed });
    check(label, observed === expected);
  }
  imageId = docker("image", "inspect", "lovelyres-svc:postgres", "--format", "{{.Id}}");
  const host = wsl("hostname", "-I").split(/\s+/u).find(ip => /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/u.test(ip));
  if (!host) throw new Error("Missing private WSL address");
  containerId = docker("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "512m", "--cpus", "1", "--pids-limit", "128", "--tmpfs", `${pgdata}:rw,noexec,nosuid,size=256m`, "-p", `${host}::22`,
    "-e", "POSTGRES_PASSWORD=LabDb#2026", "-e", "LAB_SERVICE_COMMAND=/usr/local/bin/docker-entrypoint.sh postgres", imageId);
  check("owned PostgreSQL fixture has no host mounts or privileged access", Boolean(owned()));
  await until(() => { try { return sql("SELECT 1") === "1"; } catch { return false; } }, "PostgreSQL initialized");
  version = onHost("postgres", "--version"); platform = onHost("sh", "-c", "cat /etc/os-release; uname -m");
  const original = onHost("cat", config);
  observations.originalRuntime = runtime();
  check("real fixture has wildcard listeners, MD5 defaults and disabled connection logging", observations.originalRuntime.listen_addresses.setting === "*" && observations.originalRuntime.password_encryption.setting === "md5" && observations.originalRuntime.log_connections.setting === "off");

  const samples = [
    ["commented safe value", "ssl", "ssl = off\n#ssl = on\n", "off", "off"],
    ["case-insensitive last scalar", "ssl", "ssl = off\nSSL 'ON' # current candidate\n", "__unverified__", "on"],
    ["last unsafe scalar", "ssl", "ssl on\nssl = false\n", "off", "off"],
    ["unambiguous false prefix", "log_connections", "log_connections = 'OF' # reason\n", "off", "off"],
    ["numeric false", "log_disconnections", "log_disconnections = 0\n", "off", "off"],
    ["ambiguous boolean", "ssl", "ssl = o\n", "__unverified__", null],
    ["quoted hash is data", "listen_addresses", "listen_addresses = 'localhost#*'\n", "__unverified__", "localhost#*"],
    ["wildcard inside address list", "listen_addresses", "listen_addresses = 'localhost, *'\n", "wildcard-listen", "localhost, *"],
    ["IPv6 wildcard", "listen_addresses", "listen_addresses = '::'\n", "wildcard-listen", "::"],
    ["empty TCP listener list", "listen_addresses", "listen_addresses = ''\n", "__unverified__", ""],
    ["MD5 password defaults", "password_encryption", "password_encryption = 'MD5'\n", "md5", "md5"],
    ["SCRAM setting is not account migration", "password_encryption", "password_encryption = 'scram-sha-256'\n", "__unverified__", "scram-sha-256"],
    ["invalid SCRAM spelling", "password_encryption", "password_encryption = 'scram_sha_256'\n", "__unverified__", null],
    ["mod includes DDL", "log_statement", "log_statement = 'mod'\n", "__unverified__", "mod"],
    ["all includes DDL", "log_statement", "log_statement = 'ALL'\n", "__unverified__", "all"],
    ["statement logging disabled", "log_statement", "log_statement = 'none'\n", "none", "none"],
    ["stderr collector disabled needs context", "logging_collector", "logging_collector = off\n", "__unverified__", "off"],
    ["collector enabled still needs retention verification", "logging_collector", "logging_collector = on\n", "__unverified__", "on"],
    ["native escape requires full parser", "ssl", "ssl = 'f\\141lse'\n", "__unverified__", "off"],
    ["broken quote after risk", "ssl", "ssl = off\ncluster_name = 'broken\n", "__unverified__", null],
    ["doubled single quote", "ssl", "cluster_name = 'a''b#secret'\nssl = off\n", "off", "off"],
    ["double quotes are not string quotes", "ssl", 'ssl = "off"\n', "__unverified__", null],
  ];
  writeFixture("/tmp/lr-pg-reader.awk", reader);
  observations.nativeParser = [];
  for (const [label, key, content, expected, nativeExpected] of samples) {
    writeFixture("/tmp/lr-pg-reader.conf", content);
    let actual, accepted = true;
    try { actual = asPostgres("postgres", "-D", pgdata, "-C", key, "-c", "config_file=/tmp/lr-pg-reader.conf"); } catch { accepted = false; }
    const observed = onHost("env", "LC_ALL=C", "awk", "-v", `k=${key}`, "-f", "/tmp/lr-pg-reader.awk", "/tmp/lr-pg-reader.conf");
    observations.nativeParser.push({ label, key, actual: accepted ? actual : null, observed });
    check(`${label}: independent PostgreSQL parser and bounded candidate finding`, (nativeExpected === null ? !accepted : accepted && actual === nativeExpected) && observed === expected);
  }
  writeFixture("/tmp/lr-pg-reader.conf", "ssl = off\n"); writeFixture("/tmp/lr-pg-other.conf", "ssl = on\n");
  check("another cluster candidate cannot erase an explicit risk", onHost("env", "LC_ALL=C", "awk", "-v", "k=ssl", "-f", "/tmp/lr-pg-reader.awk", "/tmp/lr-pg-reader.conf", "/tmp/lr-pg-other.conf") === "off");
  writeFixture("/tmp/lr-pg-reader.conf", `ssl = off\n#${"x".repeat(16385)}\n`);
  check("oversized physical lines remain unresolved", onHost("env", "LC_ALL=C", "awk", "-v", "k=ssl", "-f", "/tmp/lr-pg-reader.awk", "/tmp/lr-pg-reader.conf") === "__unverified__");
  writeFixture("/tmp/lr-pg-reader.conf", `ssl = off\n${"# bounded comment\n".repeat(32769)}`);
  check("oversized files cannot emit an earlier partial finding", onHost("env", "LC_ALL=C", "awk", "-v", "k=ssl", "-f", "/tmp/lr-pg-reader.awk", "/tmp/lr-pg-reader.conf") === "__unverified__");

  sidecar = new Sidecar(path.join(repository, "target/debug/lovelyhawk-backend.exe"), dataRoot);
  const connected = await connect(sidecar, { host, port: Number(owned().NetworkSettings.Ports["22/tcp"][0].HostPort), username: "root", password: "LabRoot#2026", id: runId, name });
  const bindingHandle = connected.bindingHandle, catalog = await sidecar.call("baseline.catalog.get", {});
  const items = catalog.items.filter(item => item.component === "postgresql");
  const item = title => { const found = items.find(entry => entry.title.includes(title)); if (!found) throw new Error(`Missing check: ${title}`); return found; };
  const scan = () => sidecar.call("baseline.scan", { bindingHandle }, 90_000);
  const row = (result, title) => result.statuses.find(status => status.itemHandle === item(title).itemHandle);
  const rows = result => result.statuses.filter(status => items.some(entry => entry.itemHandle === status.itemHandle));
  check("catalog excludes invalid SCRAM and guessed automatic writes", items.length === 7 && items.every(item => !item.writable) && !JSON.stringify(items).includes("scram_sha_256"));
  const initial = await scan(); observations.initial = rows(initial);
  check("real running defects have source findings while log persistence remains unresolved", rows(initial).filter(row => row.observedKind === "value").length === 6 && row(initial, "持久留存").observedKind === "unverified" && rows(initial).every(row => !row.compliant));
  check("listener finding uses product language and its actual candidate source", row(initial, "限制监听").observed === "候选地址包含通配监听" && row(initial, "限制监听").fix.file === config);
  writeFixture(config, `${original}\n#${"汉".repeat(6000)}\n`);
  check("SSH scan rejects partial findings from an oversized UTF-8 line", rows(await scan()).every(row => row.observedKind === "unverified" && !row.compliant));
  writeFixture(config, original);
  onHost("mkdir", "-p", "/etc/postgresql");
  const safeLooking = "listen_addresses = 'localhost'\npassword_encryption = 'scram-sha-256'\nlog_connections = on\nlog_disconnections = on\nlog_statement = mod\nlogging_collector = off\nssl = on\n# <img src=x onerror=pgInjected()>\n";
  writeFixture("/etc/postgresql/postgresql.conf", safeLooking);
  check("an unrelated safe-looking file cannot hide the running cluster candidate", row(await scan(), "记录连接建立").fix.file === config);
  writeFixture(config, safeLooking);
  const pending = await scan(); observations.changedWithoutReload = { scan: rows(pending), runtime: runtime() };
  check("editing files without reload never produces a verified runtime pass", rows(pending).every(row => row.observedKind === "unverified" && !row.compliant) && observations.changedWithoutReload.runtime.log_connections.setting === "off");
  writeFixture(config, `# <img src=x onerror=window.pgInjected()>\n${original}\nlog_connections = on\n`);
  sql("ALTER SYSTEM SET log_connections = 'off'"); sql("SELECT pg_reload_conf()");
  await until(() => runtime().log_connections.setting === "off" && runtime().log_connections.sourcefile === auto, "ALTER SYSTEM runtime source");
  const overridden = await scan(); observations.autoOverride = { scan: rows(overridden), runtime: runtime() };
  check("ALTER SYSTEM override is discovered and located without treating main file as effective", row(overridden, "记录连接建立").fix.file === auto && row(overridden, "记录连接建立").observed === "off");
  const loaded = await sidecar.call("baseline.file.read", { bindingHandle, itemHandle: item("记录连接建立").itemHandle }, 90_000);
  check("auto.conf file read preserves managed-source guidance without claiming a unique effective line", loaded.path === auto && loaded.mentions.every(mention => !mention.effective) && row(overridden, "记录连接建立").fix.manualReason.includes("不应直接覆写"));
  await sidecar.call("ssh.binding.disconnect", { bindingHandle }); sidecar.close(); sidecar = undefined;

  // Attached once the real main document has loaded; enabling Runtime/Log
  // replays what the page logged earlier (phase "startup").
  app = await startDesktop({ dataRoot, evidence,
    onConsoleError: (entry) => consoleErrors.push(JSON.stringify({ ...entry.params, phase: entry.phase, source: entry.source, afterCheck: checks.at(-1)?.label ?? "startup" })) });
  session = app.session;
  await uiWait("document.querySelector('.connection-card button') !== null", "saved fixture connection");
  await session.evaluate("document.querySelector('.connection-card button').click()");
  await uiWait("document.querySelector('[data-testid=disconnect-target]:not([disabled])') !== null", "connected UI");
  await click(".nav-item", "配置"); await uiWait("document.querySelector('.baseline-filters input') !== null", "baseline view");
  await session.evaluate("(() => { const input = document.querySelector('.baseline-filters input'); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, 'PostgreSQL'); input.dispatchEvent(new Event('input', { bubbles: true })); })()");
  await uiWait("document.querySelectorAll('.baseline-card').length === 7", "PostgreSQL checks");
  check("native view distinguishes candidate configuration from running instances", await session.evaluate("document.querySelector('.baseline-scope-note').textContent.includes('postgresql.auto.conf') && document.querySelectorAll('.baseline-card-verdict.is-compliant').length === 0"));
  await click(".baseline-card", "记录连接建立"); await uiWait(`document.querySelector('.baseline-file-path')?.textContent === ${JSON.stringify(auto)}`, "native actual risk source");
  check("native source is managed auto.conf and is not presented as uniquely effective", await session.evaluate("document.querySelector('.baseline-file-verdict').textContent.includes('不能将某一行认定为唯一生效项') && document.querySelector('.baseline-fix-manual').textContent.includes('不应直接覆写')"));
  await session.send("Emulation.setDeviceMetricsOverride", { width: 1080, height: 700, deviceScaleFactor: 1, mobile: false });
  await session.evaluate("document.querySelector('.baseline-file-pane').scrollIntoView({ block: 'start' })");
  check("long managed paths keep the reload action readable on one line", await session.evaluate("(() => { const button = document.querySelector('.baseline-file-pane > header button'); return button.textContent === '重新读取' && button.getBoundingClientRect().height <= 32 && button.scrollWidth <= button.clientWidth + 1; })()"));
  await session.shot("postgresql-auto-conf-source.png");
  await click(".baseline-card", "持久留存");
  await uiWait(`document.querySelector('.baseline-file-path')?.textContent === ${JSON.stringify(config)} && document.querySelector('.baseline-file-text') !== null && [...document.querySelectorAll('.baseline-file-pane button')].every(button => button.textContent !== '读取中…')`, "actual logging source loaded");
  await uiWait("document.querySelector('.baseline-fix pre')?.textContent.includes('不要仅因')", "contextual logging advice");
  check("collector guidance does not equate stderr with missing logs", await session.evaluate("document.querySelector('.baseline-file-facts').textContent.includes('核对实际日志去向与持久留存') && document.querySelector('.baseline-fix-reload').textContent.includes('需重启')"));
  check("long logging advice wraps completely in the minimum window", await session.evaluate("(() => { const pre = document.querySelector('.baseline-fix pre'); return pre.scrollWidth <= pre.clientWidth + 1 && getComputedStyle(pre).whiteSpace === 'pre-wrap'; })()"));
  check("configuration comments remain text without creating executable markup", await session.evaluate("document.querySelector('.baseline-file-text').textContent.includes('<img src=x onerror=window.pgInjected()>') && document.querySelector('.baseline-file-text img') === null && typeof window.pgInjected === 'undefined'"));
  await session.evaluate("document.querySelector('.baseline-file-pane').scrollIntoView({ block: 'start' })");
  await session.shot("postgresql-logging-context.png");
  await session.evaluate("document.querySelector('.baseline-file-text').scrollIntoView({ block: 'center' })");
  observations.fileViewport = await session.evaluate("(() => { const text = document.querySelector('.baseline-file-text'); const rect = text.getBoundingClientRect(); text.scrollTop = 70; return { height: rect.height, clientHeight: text.clientHeight, top: rect.top, bottom: rect.bottom, windowHeight: innerHeight, scrollTop: text.scrollTop, scrollHeight: text.scrollHeight }; })()");
  // The 160px border box includes borders and the Windows horizontal scrollbar.
  const viewport = observations.fileViewport;
  check("long guidance leaves configuration evidence readable and scrollable", viewport.height >= 160 && viewport.clientHeight >= 128 && viewport.top >= 0 && viewport.bottom <= viewport.windowHeight && viewport.scrollTop > 0);
  await session.evaluate("document.querySelector('.baseline-file-text').scrollTop = 0");
  await session.shot("postgresql-file-evidence.png");
  check("native workbench has no horizontal overflow", await session.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"));
  await click("[data-testid=disconnect-target]", "断开"); await uiWait("document.querySelector('.baseline-file-text') === null", "clear PostgreSQL file after disconnect");
  check("disconnect clears target evidence", true);
  check("observed startup and page have no errors", consoleErrors.length === 0);
} catch (error) {
  failure = String(error); console.error(failure); process.exitCode = 1;
  if (containerId) { try { fs.writeFileSync(path.join(evidence, "service-log.txt"), onHost("tail", "-n", "60", "/var/log/lab-service.log")); } catch {} }
  if (session) { try { await session.shot("failure.png"); fs.writeFileSync(path.join(evidence, "failure-text.txt"), await session.evaluate("document.body.innerText")); } catch {} }
} finally {
  sidecar?.close();
  if (app) await app.close();
  if (containerId) { try { owned(); docker("rm", "-f", containerId); check("owned PostgreSQL container removed", true); } catch (error) { failure ??= String(error); process.exitCode = 1; } }
  try {
    const resolved = fs.realpathSync(dataRoot), temp = fs.realpathSync(os.tmpdir());
    if (path.dirname(resolved) !== temp || !/^lovelyhawk-postgresql-baseline-[A-Za-z0-9]{6}$/u.test(path.basename(resolved))) throw new Error("Unexpected PostgreSQL test data root");
    fs.rmSync(resolved, { recursive: true, maxRetries: 10, retryDelay: 300 }); check("isolated application data removed", true);
  } catch (error) { failure ??= String(error); process.exitCode = 1; }
  fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify({ runId, date: new Date().toISOString(), imageId, version, platform, checks, observations, consoleErrors, error: failure ?? null,
    limits: ["one PostgreSQL version and container do not establish all products or architectures", "candidate files do not prove runtime, HBA policy, current account passwords or complete log retention", "fixture edits and ALTER SYSTEM are test inputs, not product remediation", "native console observation begins when CDP attaches to the loaded main document; earlier messages are those the page replays"] }, null, 2));
  console.log(`Evidence: ${path.join(evidence, "report.json")}`); keepalive.stdin.end();
}
