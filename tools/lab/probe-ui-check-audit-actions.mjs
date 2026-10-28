// 命令审计, second phase, in the Tauri window against a real host: adding
// command collection to a program, declining a plan, taking collection off,
// and clearing the log — each from the page's own buttons, through the full
// plan shown in the in-app confirmation, and checked on the host.
//
// The host is a container this probe creates from the local lovelyres-lab
// image of one distribution (LAB=ubuntu by default), labelled with this run's
// id, resource-limited, reachable only on the WSL address, and removed at the
// end after its identity is checked again. Only a planted copy of a
// standalone program (/usr/bin/lhprobe-bin, from ssh-keygen) is changed.
//
//   LAB=alpine node tools/lab/probe-ui-check-audit-actions.mjs
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { startDesktop } from "./desktop.mjs";
import { LAB_PORTS } from "./lab-target.mjs";
import { Sidecar, backendBinary, connect } from "./rpc-harness.mjs";

const lab = process.env.LAB ?? "ubuntu";
if (!Object.hasOwn(LAB_PORTS, lab)) throw new Error(`Unknown LAB ${lab}`);
const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID();
const name = `lr-ui-audit-actions-${lab}-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target", "lab-ui-check-audit-actions", lab, runId);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-ui-audit-actions-"));
const logPath = "/var/log/lovelyres/command-audit.log";
const checks = [];
let failures = 0;
let containerId = null;
let imageId = null;
let app = null;
fs.mkdirSync(evidence, { recursive: true });

/**
 * check(label, ok, detail) with a boolean, or check(label, actual, expected)
 * compared exactly. A value is never taken as a pass just for being truthy,
 * and a non-boolean with nothing to compare against fails rather than being
 * compared with a default (`check(label, null)` used to pass).
 */
function check(label, ok, ...rest) {
  const comparing = typeof ok !== "boolean";
  const detail = rest.length > 0 ? rest[0] : null;
  const passed = comparing ? rest.length > 0 && ok === detail : ok;
  const shown = comparing ? { actual: ok, expected: rest.length > 0 ? detail : "(nothing to compare with)" } : detail;
  checks.push({ label, passed, detail: shown });
  if (!passed) failures += 1;
  console.log(`${passed ? "PASS" : "FAIL"} ${label}${passed || shown === null ? "" : ` — ${JSON.stringify(shown).slice(0, 400)}`}`);
}
const wsl = (...args) => execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", ...args],
  { encoding: "utf8", windowsHide: true, timeout: 120_000, maxBuffer: 4 * 1024 * 1024 }).trim();
const docker = (...args) => wsl("docker", ...args);
function owned() {
  const target = JSON.parse(docker("inspect", containerId))[0];
  if (target.Id !== containerId || target.Image !== imageId || target.Name !== `/${name}` ||
    target.Config.Labels?.["lovelyres-test-run"] !== runId || target.HostConfig.Privileged ||
    target.HostConfig.Memory !== 256 * 1024 * 1024 || target.HostConfig.PidsLimit !== 256) {
    throw new Error("The audit fixture's identity or limits changed");
  }
  return target;
}
function script(input, user = "root") {
  owned();
  return execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", "docker", "exec", "-i", "-u", user, containerId, "sh", "-se"],
    { input, encoding: "utf8", windowsHide: true, timeout: 120_000 }).trim();
}
const digest = (file) => script(`sha256sum ${file} | awk '{print $1}'`);
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function until(predicate, label, timeoutMs = 60_000) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    try { if (await predicate()) return; } catch {}
    await sleep(300);
  }
  throw new Error(`Timed out: ${label}`);
}

try {
  imageId = docker("image", "inspect", `lovelyres-lab:${lab}`, "--format", "{{.Id}}");
  const host = wsl("hostname", "-I").split(/\s+/u).find((ip) => /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/u.test(ip));
  if (!host) throw new Error("Missing private WSL address");
  containerId = docker("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "256m",
    "--cpus", "1", "--pids-limit", "256", "-p", `${host}::22`, imageId);
  const sshPort = Number(owned().NetworkSettings.Ports["22/tcp"][0].HostPort);
  script(`cp "$(readlink -f "$(command -v ssh-keygen)")" /usr/bin/lhprobe-bin
[ "$(head -c 4 /usr/bin/lhprobe-bin)" = "$(printf '\\177ELF')" ]
chmod 755 /usr/bin/lhprobe-bin
rm -f /run/nologin /var/run/nologin
rm -rf /var/log/lovelyres`);
  const original = digest("/usr/bin/lhprobe-bin");

  const sidecar = new Sidecar(backendBinary(), dataRoot);
  try {
    const status = await connect(sidecar, { host, port: sshPort, username: "root", password: "LabRoot#2026",
      id: "22222222-2222-4222-8222-222222222221", name: `采集靶机 ${lab}` });
    if (status?.stage !== "connected") throw new Error(`fixture connect failed: ${JSON.stringify(status)}`);
  } finally { sidecar.close(); }

  const consoleErrors = [];
  app = await startDesktop({ dataRoot, evidence,
    onConsoleError: (event) => consoleErrors.push(JSON.stringify(event.params ?? event).slice(0, 600)) });
  const page = app.session;
  const evaluate = (expression) => page.evaluate(expression);
  const uiWait = (expression, label, timeoutMs = 90_000) => until(async () => (await evaluate(expression)) === true, label, timeoutMs);
  await uiWait(`[...document.querySelectorAll('.connection-card')].some((card) => card.textContent.includes(${JSON.stringify(`采集靶机 ${lab}`)}))`, "the connection card");
  await evaluate(`(() => { const card = [...document.querySelectorAll('.connection-card')].find((c) => c.textContent.includes(${JSON.stringify(`采集靶机 ${lab}`)})); (card.querySelector('button') ?? card).click(); return true; })()`);
  await uiWait("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]') !== null", "the connection");
  await evaluate("[...document.querySelectorAll('.nav-item')].find((item) => item.textContent.includes('命令审计'))?.click(), true");
  await uiWait("document.querySelector('.check-audit-page .check-audit-tabs') !== null", "the audit page");
  check("the page says what it may change, and that each change is planned and approved first",
    await evaluate("document.querySelector('.check-audit-readonly-banner')?.textContent.includes('每次都先列出计划') === true"));
  const setInput = (selector, value) => evaluate(`(() => {
    const input = document.querySelector(${JSON.stringify(selector)});
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, ${JSON.stringify(value)});
    input.dispatchEvent(new Event('input', { bubbles: true }));
    return true;
  })()`);
  await setInput(".check-audit-command-tools form input", "lhprobe-bin");
  await evaluate("document.querySelector('.check-audit-command-tools form').requestSubmit(), true");
  const rowState = () => evaluate(`(() => { const b = [...document.querySelectorAll('.check-audit-command-list button')].find((x) => x.querySelector('strong')?.textContent === 'lhprobe-bin'); return b ? b.querySelectorAll(':scope > span')[1]?.textContent ?? null : null; })()`);
  await until(async () => (await rowState()) === "未加采集", "lhprobe-bin read as not collected");
  await evaluate("[...document.querySelectorAll('.check-audit-command-list button')].find((x) => x.querySelector('strong')?.textContent === 'lhprobe-bin').click(), true");
  await uiWait("document.querySelector('[data-testid=\"check-audit-collect\"]')?.disabled === false", "the collect button");
  check("an original program offers 加采集 and not 移除采集",
    await evaluate("document.querySelector('[data-testid=\"check-audit-uncollect\"]').disabled === true"));

  // Collect: the whole plan in the confirmation, then approve.
  await evaluate("document.querySelector('[data-testid=\"check-audit-collect\"]').click(), true");
  await uiWait("document.querySelector('[role=dialog]') !== null", "the confirmation");
  const dialogText = await evaluate("document.querySelector('[role=dialog]').textContent");
  check("the confirmation shows the plan, the commands, what it does and how it is undone",
    ["给 lhprobe-bin 加上命令采集", "涉及的命令：lhprobe-bin", "/var/log/lovelyres/command-audit.log", "检查不通过时："]
      .every((part) => dialogText.includes(part)) && !/wrapper/iu.test(dialogText), dialogText.slice(0, 300));
  check("the host is untouched while the confirmation is open", digest("/usr/bin/lhprobe-bin"), original);
  await page.shot("check-audit-collect-confirm.png");
  await evaluate("[...document.querySelectorAll('[role=dialog] button')].find((b) => b.textContent.trim() === '确认加采集').click(), true");
  await uiWait("document.querySelector('[data-testid=\"check-audit-receipt\"]') !== null", "the receipt", 180_000);
  const receipt = await evaluate("({ verified: document.querySelector('[data-testid=\"check-audit-receipt\"]').dataset.verified, text: document.querySelector('[data-testid=\"check-audit-receipt\"]').textContent })");
  check("the receipt says, in words, that it was done and checked", receipt.verified === "true" &&
    receipt.text.includes("已完成并核对") && receipt.text.includes("已读回核对") &&
    !/\b(?:verified|audit|mutation|steps|wrapper)\b/iu.test(receipt.text), receipt);
  check("on the host the command is now the collection script, the original kept as a backup",
    script("grep -c LOVELYRES_AUDIT_WRAPPER_V1 /usr/bin/lhprobe-bin") !== "0" &&
    digest(`/usr/bin/${script("ls -a /usr/bin | grep -E '^\\.lhprobe-bin\\.lovelyres-orig-' | head -1")}`) === original);
  await until(async () => (await rowState()) === "已加采集", "the row read again as collected");
  check("the page reads the command again as collected", true);
  await page.shot("check-audit-collected.png");

  // Decline: nothing changes.
  await uiWait("document.querySelector('[data-testid=\"check-audit-uncollect\"]')?.disabled === false", "the uncollect button");
  const wrapped = digest("/usr/bin/lhprobe-bin");
  await evaluate("document.querySelector('[data-testid=\"check-audit-uncollect\"]').click(), true");
  await uiWait("document.querySelector('[role=dialog]') !== null", "the uncollect confirmation");
  await evaluate("[...document.querySelectorAll('[role=dialog] button')].find((b) => b.textContent.trim() === '取消').click(), true");
  await uiWait("document.querySelector('[role=dialog]') === null", "the declined confirmation");
  await sleep(1_000);
  check("declining changes nothing on the host", digest("/usr/bin/lhprobe-bin"), wrapped);

  // Uncollect, approved.
  await evaluate("document.querySelector('[data-testid=\"check-audit-uncollect\"]').click(), true");
  await uiWait("document.querySelector('[role=dialog]') !== null", "the uncollect confirmation again");
  await evaluate("[...document.querySelectorAll('[role=dialog] button')].find((b) => b.textContent.trim() === '确认移除').click(), true");
  await uiWait("document.querySelector('[data-testid=\"check-audit-receipt\"]')?.dataset.verified === 'true'", "the uncollect receipt", 180_000);
  check("taking collection off puts the original bytes back", digest("/usr/bin/lhprobe-bin"), original);
  await until(async () => (await rowState()) === "未加采集", "the row read again as original");
  check("the page reads the command again as not collected", true);

  // Clear the log from the log tab.
  script("echo kept-record >> /var/log/lovelyres/command-audit.log");
  await evaluate("[...document.querySelectorAll('.check-audit-tabs button')].find((b) => b.textContent.trim() === '日志').click(), true");
  await uiWait("document.querySelector('[data-testid=\"check-audit-clear-log\"]')?.disabled === false", "the clear button");
  await evaluate("document.querySelector('[data-testid=\"check-audit-clear-log\"]').click(), true");
  await uiWait("document.querySelector('[role=dialog]') !== null", "the clear confirmation");
  check("the clear confirmation says the old log is kept",
    await evaluate("document.querySelector('[role=dialog]').textContent.includes('之前的记录不会被删除')"));
  await evaluate("[...document.querySelectorAll('[role=dialog] button')].find((b) => b.textContent.trim() === '确认清空').click(), true");
  await uiWait("document.querySelector('[data-testid=\"check-audit-receipt\"]')?.dataset.verified === 'true'", "the clear receipt", 180_000);
  const kept = script("ls /var/log/lovelyres | grep -E '^command-audit\\.log\\.clear-' | head -1");
  check("on the host the log is empty and the old one kept",
    script(`wc -c < ${logPath} | tr -d ' '`) === "0" && kept !== "" && script(`cat /var/log/lovelyres/${kept}`).includes("kept-record"), kept);
  await page.shot("check-audit-cleared.png");
  check("no console errors", consoleErrors.length === 0, consoleErrors.slice(0, 2));
} catch (error) {
  failures += 1;
  console.log(`FAILED: ${error instanceof Error ? error.message : String(error)}`);
  try { await app?.session?.shot("failure.png"); } catch {}
} finally {
  try { await app?.close(); } catch {}
  if (containerId !== null) {
    try {
      owned();
      docker("rm", "-f", containerId);
      check("the run's own container was removed", !docker("ps", "-a", "--filter", `label=lovelyres-test-run=${runId}`, "--format", "{{.ID}}"));
    } catch (error) {
      failures += 1;
      console.log(`cleanup refused: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  fs.rmSync(dataRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 });
}
fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify({
  schema: "lovelyhawk-ui-check-audit-actions-probe/v1", lab,
  status: failures === 0 ? "PASS" : "FAIL", generatedAt: new Date().toISOString(), checks,
}, null, 2)}\n`);
console.log(`${failures === 0 ? "PASS" : "FAIL"}: ${checks.filter((item) => item.passed).length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failures === 0 ? 0 : 1;
