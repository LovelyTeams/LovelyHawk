// Real Redis / SSH / baseline RPC against an owned disposable container.
// Fixture changes are test inputs, not evidence of application remediation.
import { execFileSync, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { startDesktop } from "./desktop.mjs";
import { Sidecar, connect } from "./rpc-harness.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID(), name = `lr-redis-baseline-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target/lab-redis-baseline", runId);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-redis-baseline-"));
fs.mkdirSync(evidence, { recursive: true });
const checks = [], observations = {}, consoleErrors = [];
let containerId, imageId, version, platform, sidecar, failure, app, session;
const keepalive = spawn("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", "cat"], { windowsHide: true, stdio: ["pipe", "ignore", "ignore"] });
keepalive.once("error", (error) => { failure ??= String(error); });
function wsl(...args) { return execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", ...args], { encoding: "utf8", windowsHide: true, timeout: 45_000, maxBuffer: 2 * 1024 * 1024 }).trim(); }
const docker = (...args) => wsl("docker", ...args);
function owned() {
  const target = JSON.parse(docker("inspect", containerId))[0];
  if (target.Id !== containerId || target.Image !== imageId || target.Name !== `/${name}` || target.Config.Labels?.["lovelyres-test-run"] !== runId ||
    target.HostConfig.Privileged || target.HostConfig.NetworkMode !== "bridge" || target.Mounts.some(mount => mount.Type !== "tmpfs" || mount.Destination !== "/data") ||
    target.HostConfig.Tmpfs?.["/data"] !== "rw,noexec,nosuid,size=64m") throw new Error("Redis fixture identity or storage changed");
  return target;
}
function onHost(...args) { owned(); return docker("exec", containerId, ...args); }
function writeFixture(file, content) {
  if (!["/etc/redis/redis.conf", "/etc/redis.conf", "/usr/local/etc/redis/redis.conf", "/tmp/lr-redis-include.conf"].includes(file)) throw new Error("Unexpected Redis fixture file");
  onHost("sh", "-c", `printf '%s' '${Buffer.from(content).toString("base64")}' | base64 -d > '${file}'`);
}
function check(label, value) { checks.push({ label, passed: Boolean(value) }); console.log(`${value ? "PASS" : "FAIL"} ${label}`); if (!value) throw new Error(label); }
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(fn, label) { const end=Date.now()+60_000; while(Date.now()<end) { if(await fn()) return; await sleep(150); } throw new Error(`Timed out: ${label}`); }
const click=(selector,text)=>session.evaluate(`(()=>{const button=[...document.querySelectorAll(${JSON.stringify(selector)})].find(e=>e.textContent.includes(${JSON.stringify(text)})&&!e.disabled);if(!button)throw new Error('Control missing');button.click();})()`);
const uiWait=(expression,label)=>until(()=>session.evaluate(expression),label);
try {
  imageId = docker("image", "inspect", "lovelyres-svc:redis", "--format", "{{.Id}}");
  const host = wsl("hostname", "-I").split(/\s+/u).find(ip => /^172\.(1[6-9]|2\d|3[01])\./u.test(ip));
  if (!host) throw new Error("Missing private WSL address");
  containerId = docker("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "256m", "--cpus", "1", "--pids-limit", "128", "--tmpfs", "/data:rw,noexec,nosuid,size=64m", "-p", `${host}::22`, imageId);
  check("owned Redis fixture has no host mounts or privileged access", Boolean(owned()));
  version = onHost("redis-server", "--version");
  platform = onHost("sh", "-c", "cat /etc/os-release; uname -m");
  onHost("redis-server", "/etc/redis/redis.conf", "--daemonize", "yes");
  check("real Redis starts with the intentionally exposed configuration", onHost("redis-cli", "--raw", "CONFIG", "GET", "bind") === "bind\n0.0.0.0" && onHost("redis-cli", "--raw", "PING") === "PONG");
  sidecar = new Sidecar(path.join(repository, "target/debug/lovelyhawk-backend.exe"), dataRoot);
  const connected = await connect(sidecar, { host, port: Number(owned().NetworkSettings.Ports["22/tcp"][0].HostPort), username: "root", password: "LabRoot#2026", id: runId, name });
  const bindingHandle = connected.bindingHandle;
  const catalog = await sidecar.call("baseline.catalog.get", {});
  const redis = catalog.items.filter(item => item.component === "redis");
  const item = title => { const found = redis.find(entry => entry.title.includes(title)); if (!found) throw new Error(`Missing Redis check: ${title}`); return found; };
  const scan = () => sidecar.call("baseline.scan", { bindingHandle }, 90_000);
  const row = (result, title) => result.statuses.find(status => status.itemHandle === item(title).itemHandle);
  const initial = await scan();
  observations.initial = initial.statuses.filter(status => redis.some(entry => entry.itemHandle === status.itemHandle));
  fs.writeFileSync(path.join(evidence, "initial-scan.json"), JSON.stringify(observations.initial, null, 2));
  check("an explicit all-interface bind is never reported as compliant", row(initial, "限定监听地址").compliant === false);
  check("wildcard evidence keeps the observed address and exact source", row(initial, "限定监听地址").observed === "0.0.0.0" && row(initial, "限定监听地址").fix.file === "/etc/redis/redis.conf");
  check("all Redis candidate checks require an instance-specific remediation plan", redis.length === 7 && redis.every(entry => !entry.writable));
  check("Redis recommendations use native yes/no and do not guess a service restart", row(initial, "保持保护模式").fix.lines[0] === "protected-mode yes" && row(initial, "DEBUG").fix.lines[0] === "enable-debug-command no" && row(initial, "MODULE").fix.lines[0] === "enable-module-command no" && row(initial, "保持保护模式").fix.reload === null);
  let rejectedSyntax = false;
  try { onHost("redis-server", "--port", "0", "--protected-mode", "on"); }
  catch (error) { rejectedSyntax = /FATAL CONFIG FILE ERROR/u.test(String(error.stdout) + String(error.stderr)); }
  check("the real Redis parser rejects the former protected-mode on recommendation", rejectedSyntax);
  check("real Redis accepts the corrected boolean spelling", onHost("redis-cli", "--raw", "CONFIG", "SET", "protected-mode", "yes") === "OK" && onHost("redis-cli", "--raw", "CONFIG", "GET", "protected-mode") === "protected-mode\nyes");
  onHost("redis-cli", "--raw", "CONFIG", "SET", "protected-mode", "no");
  writeFixture("/etc/redis/redis.conf", 'bind 127.0.0.1 -::1\nprotected-mode yes\nrequirepass "lab-redis-secret-canary"\nenable-debug-command no\nenable-module-command no\nlogfile ""\n');
  const safeLooking = await scan();
  check("safe-looking file values cannot attest to the unchanged running Redis instance", redis.every(entry => safeLooking.statuses.find(status => status.itemHandle === entry.itemHandle).observedKind === "unverified") && onHost("redis-cli", "--raw", "CONFIG", "GET", "bind") === "bind\n0.0.0.0");
  check("scan responses never contain a configured password", !JSON.stringify(safeLooking).includes("lab-redis-secret-canary") && !sidecar.stderr.join("").includes("lab-redis-secret-canary"));
  writeFixture("/etc/redis/redis.conf", 'bind 127.0.0.1\nprotected-mode no\n# protected-mode yes\nrequirepass ""\n');
  const emptyPassword = await scan();
  check("empty quoted requirepass is not treated as authentication", row(emptyPassword, "访问口令").observed === "候选文件未声明口令或 ACL" && !row(emptyPassword, "访问口令").compliant);
  check("a commented safe directive does not hide disabled protection", row(emptyPassword, "保持保护模式").observed === "no");
  writeFixture("/etc/redis/redis.conf", 'protected-mode no\nprotected-mode yes\nuser default off\nuser investigator on >lab-acl-secret-canary ~* +@read\nlogfile ""\n');
  const acl = await scan();
  check("inline ACLs do not become a false missing-password failure or disclose their secrets", row(acl, "访问口令").observedKind === "unverified" && !JSON.stringify(acl).includes("lab-acl-secret-canary"));
  check("the last scalar directive within the same file supersedes an earlier value", row(acl, "保持保护模式").observedKind === "unverified");
  check("stdout logging and absent command renaming require context instead of an automatic failure", row(acl, "日志写到文件").observedKind === "unverified" && row(acl, "危险命令权限").observedKind === "unverified");
  writeFixture("/etc/redis/redis.conf", 'protected-mode yes\naclfile /tmp/lr-redis-users.acl\n');
  check("an external ACL file requires runtime verification", row(await scan(), "访问口令").observedKind === "unverified");
  writeFixture("/etc/redis/redis.conf", 'protected-mode yes\ninclude /tmp/lr-redis-include.conf\n');
  writeFixture("/tmp/lr-redis-include.conf", 'protected-mode no\n');
  const included = await scan();
  check("unresolved includes never establish safe authentication or protected mode", row(included, "访问口令").observedKind === "unverified" && row(included, "保持保护模式").observedKind === "unverified");
  writeFixture("/etc/redis/redis.conf", 'bind 127.0.0.1 -::*\nprotected-mode no # not a Redis inline comment\n');
  check("malformed Redis directive syntax is unresolved", row(await scan(), "保持保护模式").observedKind === "unverified");
  for (const address of ["-::*", "0:0:0:0:0:0:0:0", "::", "*"]) {
    writeFixture("/etc/redis/redis.conf", `bind 127.0.0.1 ${address}\n`);
    const binding = row(await scan(), "限定监听地址");
    check(`wildcard ${address} remains an exposure finding`, binding.observedKind === "value" && !binding.compliant && binding.observed === address.replace(/^-/, ""));
  }
  writeFixture("/etc/redis/redis.conf", 'bind ::::::::\n');
  check("malformed IPv6 is not invented as a valid wildcard finding", row(await scan(), "限定监听地址").observedKind === "unverified");
  writeFixture("/etc/redis/redis.conf", 'protected-mode "n\\x6f"\nrequirepass "escaped-lab-secret"\n');
  check("unresolved escapes are not simplified into a different configuration", row(await scan(), "保持保护模式").observedKind === "unverified");
  onHost("sh", "-c", "printf 'protected-mode no\\n' > /etc/redis/redis.conf; head -c 524288 /dev/zero | tr '\\000' '#' >> /etc/redis/redis.conf; printf '\\n' >> /etc/redis/redis.conf");
  check("oversized candidate contents stay unresolved", row(await scan(), "保持保护模式").observedKind === "unverified");
  onHost("mkdir", "-p", "/usr/local/etc/redis");
  writeFixture("/etc/redis/redis.conf", 'protected-mode no\nbind 0.0.0.0\n');
  writeFixture("/usr/local/etc/redis/redis.conf", 'protected-mode yes\nbind 127.0.0.1\nrequirepass "another-lab-secret"\n');
  const separate = await scan();
  check("a safe separate candidate cannot erase risk in another instance file", row(separate, "保持保护模式").observed === "no" && row(separate, "限定监听地址").fix.file === "/etc/redis/redis.conf");
  writeFixture("/etc/redis/redis.conf", 'protected-mode yes\nbind 127.0.0.1\n');
  writeFixture("/usr/local/etc/redis/redis.conf", 'protected-mode no\nbind 0.0.0.0\n# <img src=x onerror=window.redisInjected=1>\n');
  const alternative = await scan();
  check("the standard official-image configuration path is inspected independently", row(alternative, "限定监听地址").fix.file === "/usr/local/etc/redis/redis.conf");
  const view = await sidecar.call("baseline.file.read", { bindingHandle, itemHandle: item("限定监听地址").itemHandle }, 90_000);
  check("file view follows the risk source without claiming a uniquely effective line", view.path === "/usr/local/etc/redis/redis.conf" && view.text.includes("bind 0.0.0.0") && view.mentions.every(mention => !mention.effective));
  onHost("rm", "--", "/etc/redis/redis.conf", "/usr/local/etc/redis/redis.conf");
  const noFile = await scan();
  check("an installed running Redis with no candidate file is unresolved rather than default-compliant", redis.every(entry => noFile.statuses.find(status => status.itemHandle === entry.itemHandle).observedKind === "unverified") && onHost("redis-cli", "--raw", "PING") === "PONG");
  writeFixture("/etc/redis/redis.conf", 'protected-mode yes\nbind 127.0.0.1\n');
  writeFixture("/usr/local/etc/redis/redis.conf", 'protected-mode no\nbind 0.0.0.0\n# <img src=x onerror=window.redisInjected=1>\n');
  sidecar.close();sidecar=undefined;await sleep(300);
  if(process.env.REDIS_UI!=="0") {
    // Attached once the real main document has loaded; enabling Runtime/Log
    // replays what the page logged earlier (phase "startup").
    app=await startDesktop({dataRoot,evidence,
      onConsoleError:(entry)=>consoleErrors.push(JSON.stringify({...entry.params,phase:entry.phase,source:entry.source,afterCheck:checks.at(-1)?.label??"startup"}))});
    session=app.session;
    await uiWait("document.querySelector('.connection-card button')!==null","saved Redis test connection");
    await session.evaluate(`[...document.querySelectorAll('.connection-card')].find(e=>e.querySelector('strong').textContent===${JSON.stringify(name)}).querySelector('button').click()`);
    await uiWait("document.querySelector('[data-testid=disconnect-target]:not([disabled])')!==null","native SSH connection");
    await click(".nav-item","配置");await uiWait("document.querySelector('.baseline-card-verdict.is-noncompliant')!==null","native baseline scan");
    await session.evaluate("(()=>{const e=document.querySelector('.baseline-filters input');Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(e,'Redis');e.dispatchEvent(new Event('input',{bubbles:true}));})()");
    await uiWait("document.querySelectorAll('.baseline-card').length===7","Redis product filter");
    check("the UI distinguishes Redis candidate findings from runtime verification",await session.evaluate("document.querySelector('.baseline-scope-note').textContent.includes('ACL 和运行时设置')&&document.querySelectorAll('.baseline-card-verdict.is-compliant').length===0"));
    await click(".baseline-card","限定监听地址");await uiWait("document.querySelector('.baseline-file-path')?.textContent==='/usr/local/etc/redis/redis.conf'","native risk source");
    check("the native file view retains exact source and literal hostile comments",await session.evaluate("document.querySelector('.baseline-file-text').textContent.includes('<img')&&document.querySelector('.baseline-file-text img')===null&&window.redisInjected===undefined"));
    check("the UI does not claim a uniquely effective Redis line or offer a guessed restart",await session.evaluate("document.querySelector('.baseline-file-verdict').textContent.includes('不能将某一行认定为唯一生效项')&&document.querySelector('.baseline-fix-manual').textContent.includes('实际实例')&&document.querySelector('.baseline-fix-reload')===null"));
    await session.send("Emulation.setDeviceMetricsOverride",{width:1080,height:700,deviceScaleFactor:1,mobile:false});
    await session.shot("redis-risk-candidates.png");
    await click(".baseline-card","保持保护模式");await uiWait("document.querySelector('.baseline-fix pre')?.textContent.includes('protected-mode yes')","native corrected recommendation");
    check("the native recommendation and suggested value both use Redis syntax",await session.evaluate("document.querySelector('.baseline-fix pre').textContent==='protected-mode yes'&&document.querySelector('.baseline-file-facts div:nth-child(2) code').textContent==='yes'"));
    await uiWait("document.querySelector('.baseline-file-text')?.textContent.includes('protected-mode no')&&document.querySelector('.baseline-file-pane > header button')?.textContent==='重新读取'","loaded protection source");
    await session.shot("redis-corrected-recommendation.png");
    const reviewed='protected-mode yes\nbind 127.0.0.1\naclfile /tmp/lr-redis-users.acl\n';
    writeFixture("/etc/redis/redis.conf",reviewed);writeFixture("/usr/local/etc/redis/redis.conf",reviewed);
    await click(".baseline-view-header button","扫描");await uiWait("document.querySelectorAll('.baseline-card-verdict.is-review').length===7","review pending after fixture edit");
    check("safe-looking fixture edits do not turn unknown running state green",await session.evaluate("document.querySelectorAll('.baseline-card-verdict.is-compliant').length===0")&&onHost("redis-cli","--raw","CONFIG","GET","protected-mode")==="protected-mode\nno");
    await uiWait("document.querySelector('.baseline-file-text')?.textContent.includes('protected-mode yes')","selected Redis file refreshed");
    check("the minimum window has no horizontal overflow",await session.evaluate("document.documentElement.scrollWidth<=innerWidth+1"));
    await session.shot("redis-review-after-fixture-edit.png");
    await click("[data-testid=disconnect-target]","断开");await uiWait("document.querySelector('.baseline-file-text')===null","cleared Redis state after disconnect");
    check("disconnect clears target configuration",true);
    check("native desktop startup and page have no console errors",consoleErrors.length===0);
  }
} catch (error) {
  failure = String(error); console.error(failure); process.exitCode = 1;
  if(session){try{await session.shot("failure.png");fs.writeFileSync(path.join(evidence,"failure-text.txt"),await session.evaluate("document.body.innerText"));}catch{}}
} finally {
  sidecar?.close();
  if(app)await app.close();
  if (containerId) { try { owned(); docker("rm", "-f", containerId); check("owned Redis container removed", true); } catch (error) { failure ??= String(error); process.exitCode = 1; } }
  try {
    const resolved = fs.realpathSync(dataRoot), temp = fs.realpathSync(os.tmpdir());
    if (path.dirname(resolved) !== temp || !/^lovelyhawk-redis-baseline-[A-Za-z0-9]{6}$/u.test(path.basename(resolved))) throw new Error("Unexpected Redis test data root");
    fs.rmSync(resolved, { recursive: true, maxRetries: 10, retryDelay: 300 }); check("isolated application data removed", true);
  } catch (error) { failure ??= String(error); process.exitCode = 1; }
  fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify({ runId, date: new Date().toISOString(), imageId, version, platform, mode:process.env.REDIS_UI==="0"?"rpc":"rpc-and-desktop", checks, observations, consoleErrors, error: failure ?? null,
    limits:["candidate configuration findings do not establish the loaded runtime or complete ACL policy", "fixture edits and CONFIG SET calls are test inputs, not application remediation evidence", "one Redis version and container do not establish full Linux or database compatibility"] }, null, 2));
  console.log(`Evidence: ${path.join(evidence, "report.json")}`); keepalive.stdin.end();
}
