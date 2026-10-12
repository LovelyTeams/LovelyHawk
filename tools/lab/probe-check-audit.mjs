// 命令审计 in the Tauri window against a real host: what each command runs,
// and what is (or is not) where the command audit log belongs.
//
// The host is a container this probe creates from the local lovelyres-lab
// image of one distribution (LAB=ubuntu by default; any of the nine), labelled
// with this run's id, resource-limited, reachable only on the WSL address, and
// removed at the end after its identity is checked again. The image has root
// and an ordinary account (deploy). Everything planted lives only in it:
//
//   - three custom command names: a shell script, a real program, and one
//     that does not exist;
//   - the audit log missing; then a symlink to /etc/shadow in its place; then
//     a log with periodic records and a line that is no record; then empty;
//     then unreadable to deploy.
//
// Checked on the host side by construction: the page must report each state
// for what it is (never an empty or clean log), and nothing of /etc/shadow may
// reach the page through the symlink.
//
//   LAB=alpine node tools/lab/probe-check-audit.mjs

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
const name = `lr-audit-${lab}-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target", "lab-check-audit", lab, runId);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-audit-"));
const logDir = "/var/log/lovelyres";
const logPath = `${logDir}/command-audit.log`;
const checks = [];
let failures = 0;
let containerId = null;
let imageId = null;
let app = null;
fs.mkdirSync(evidence, { recursive: true });

/**
 * check(label, ok, detail) with a boolean, or check(label, actual, expected)
 * compared exactly. A value is never taken as a pass just for being truthy,
 * and a non-boolean with nothing to compare against fails.
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
/** The container must still be the one this run made, with the limits it was made with. */
function owned() {
  const target = JSON.parse(docker("inspect", containerId))[0];
  if (target.Id !== containerId || target.Image !== imageId || target.Name !== `/${name}` ||
    target.Config.Labels?.["lovelyres-test-run"] !== runId || target.HostConfig.Privileged ||
    target.HostConfig.Memory !== 256 * 1024 * 1024 || target.HostConfig.PidsLimit !== 256) {
    throw new Error("The audit fixture's identity or limits changed");
  }
  return target;
}
/** Runs a script in the fixture through stdin, so nothing is re-quoted on the way. */
function script(input) {
  owned();
  return execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", "docker", "exec", "-i", containerId, "sh", "-se"],
    { input, encoding: "utf8", windowsHide: true, timeout: 120_000 }).trim();
}
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function until(predicate, label, timeoutMs = 60_000) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    try { if (await predicate()) return; } catch {}
    await sleep(300);
  }
  throw new Error(`Timed out: ${label}`);
}
const b64 = (value) => Buffer.from(value, "utf8").toString("base64");
const record = (time, command, args, user, pid, caller) =>
  `LR_AUDIT_V2|${b64(time)}|${b64(command)}|${b64(args)}|${b64(user)}|${pid}|1|${b64(caller)}`;

/** Opens the app on one stored connection and the 命令审计 page. */
async function openAs(connectionName, consoleErrors) {
  const desktop = await startDesktop({ dataRoot, evidence, clipboard: true,
    onConsoleError: (event) => consoleErrors.push(JSON.stringify(event.params ?? event).slice(0, 600)) });
  const page = desktop.session;
  const evaluate = (expression) => page.evaluate(expression);
  await until(async () => (await evaluate(`[...document.querySelectorAll('.connection-card')].some((card) => card.textContent.includes(${JSON.stringify(connectionName)}))`)) === true, "the connection card");
  await evaluate(`(() => { const card = [...document.querySelectorAll('.connection-card')].find((c) => c.textContent.includes(${JSON.stringify(connectionName)})); (card.querySelector('button') ?? card).click(); return true; })()`);
  await until(async () => (await evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]') !== null")) === true, "the connection");
  await evaluate("[...document.querySelectorAll('.nav-item')].find((item) => item.textContent.includes('命令审计'))?.click(), true");
  await until(async () => (await evaluate("document.querySelector('.check-audit-page .check-audit-tabs') !== null")) === true, "the audit page", 90_000);
  return desktop;
}

try {
  // 1. The fixture.
  imageId = docker("image", "inspect", `lovelyres-lab:${lab}`, "--format", "{{.Id}}");
  const host = wsl("hostname", "-I").split(/\s+/u).find((ip) => /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/u.test(ip));
  if (!host) throw new Error("Missing private WSL address");
  containerId = docker("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "256m",
    "--cpus", "1", "--pids-limit", "256", "-p", `${host}::22`, imageId);
  const sshPort = Number(owned().NetworkSettings.Ports["22/tcp"][0].HostPort);
  // lhprobe-bin must be a real standalone ELF program: on EL9 images
  // /usr/bin/ls itself is a one-line coreutils shim, and on Alpine every
  // command is BusyBox (which the page rightly names as a multi-call program),
  // so ssh-keygen comes first and the first candidate that starts with the
  // ELF magic is copied. The Anolis image also ships a stale /run/nologin
  // ("System is booting up") that turns every non-root login away; a booted
  // host has none, so this container's copy is removed.
  script(`printf '#!/bin/sh\\nexec /bin/ls "$@"\\n' > /usr/bin/lhprobe-tool && chmod 755 /usr/bin/lhprobe-tool
for candidate in "$(readlink -f "$(command -v ssh-keygen)")" /usr/bin/coreutils "$(readlink -f /bin/ls)" "$(readlink -f /bin/sh)"; do
  if [ -f "$candidate" ] && [ "$(head -c 4 "$candidate")" = "$(printf '\\177ELF')" ]; then cp "$candidate" /usr/bin/lhprobe-bin; break; fi
done
chmod 755 /usr/bin/lhprobe-bin
rm -f /run/nologin /var/run/nologin
rm -rf ${logDir}`);
  check("the fixture starts with no audit log and the three planted names",
    script(`test ! -e ${logDir} && test -x /usr/bin/lhprobe-tool && [ "$(head -c 4 /usr/bin/lhprobe-bin)" = "$(printf '\\177ELF')" ] && ! command -v lhprobe-none >/dev/null && echo ok`) === "ok");
  const catBusybox = script('[ "$(readlink -f "$(command -v cat)")" = /bin/busybox ] && echo yes || echo no') === "yes";
  const catShim = script(`p=$(readlink -f "$(command -v cat)"); [ "$(head -c 512 "$p")" = "#!/usr/bin/coreutils --coreutils-prog-shebang=cat" ] && echo shim || echo program`) === "shim";

  const sidecar = new Sidecar(backendBinary(), dataRoot);
  try {
    for (const [id, username, password] of [
      ["22222222-2222-4222-8222-222222222201", "root", "LabRoot#2026"],
      ["22222222-2222-4222-8222-222222222202", "deploy", "LabDeploy#2026"],
    ]) {
      const status = await connect(sidecar, { host, port: sshPort, username, password, id, name: `审计靶机 ${lab} ${username}` });
      if (status?.stage !== "connected") throw new Error(`fixture connect as ${username} failed: ${JSON.stringify(status)}`);
    }
  } finally { sidecar.close(); }

  // 2. As root: the commands.
  const consoleErrors = [];
  app = await openAs(`审计靶机 ${lab} root`, consoleErrors);
  let page = app.session;
  let evaluate = (expression) => page.evaluate(expression);
  const uiWait = (expression, label, timeoutMs = 90_000) => until(async () => (await evaluate(expression)) === true, label, timeoutMs);
  const setInput = (selector, value) => evaluate(`(() => {
    const input = document.querySelector(${JSON.stringify(selector)});
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, ${JSON.stringify(value)});
    input.dispatchEvent(new Event('input', { bubbles: true }));
    return true;
  })()`);
  const tab = (label) => evaluate(`[...document.querySelectorAll('.check-audit-tabs button')].find((b) => b.textContent.trim() === ${JSON.stringify(label)}).click(), true`);
  const refresh = () => evaluate("[...document.querySelectorAll('.check-audit-view-header button')].find((b) => !b.disabled)?.click(), true");
  const row = (command) => evaluate(`(() => {
    const button = [...document.querySelectorAll('.check-audit-command-list button')].find((b) => b.querySelector('strong')?.textContent === ${JSON.stringify(command)});
    return button ? [...button.querySelectorAll(':scope > span')].map((span) => span.textContent) : null;
  })()`);
  for (const custom of ["lhprobe-tool", "lhprobe-bin", "lhprobe-none"]) {
    await setInput(".check-audit-command-tools form input", custom);
    await evaluate("document.querySelector('.check-audit-command-tools form').requestSubmit(), true");
    await uiWait(`[...document.querySelectorAll('.check-audit-custom-list span')].some((s) => s.textContent.startsWith(${JSON.stringify(custom)}))`, `the custom name ${custom}`);
  }
  await uiWait("(() => { const b = [...document.querySelectorAll('.check-audit-command-list button')].find((x) => x.querySelector('strong')?.textContent === 'lhprobe-none'); return b !== undefined && !b.textContent.includes('等待采集'); })()", "the custom commands' status");
  const tool = await row("lhprobe-tool");
  const bin = await row("lhprobe-bin");
  const none = await row("lhprobe-none");
  check("a planted shell script is reported as a script, at its real location",
    tool?.[1] === "是脚本（非本工具）" && tool?.[3] === "/usr/bin/lhprobe-tool", tool);
  check("a real program without the collection wrapper is 未加采集, not claimed genuine",
    bin?.[1] === "未加采集" && bin?.[3] === "/usr/bin/lhprobe-bin" &&
    await evaluate("document.querySelector('.check-audit-note')?.textContent.includes('不代表它没被篡改') === true"), bin);
  check("a name that is not installed is 未安装", none?.[1] === "未安装", none);
  const scripts = await evaluate("document.querySelector('[data-testid=\"check-audit-scripts\"]')?.textContent ?? null");
  check("the page names the commands that run a script", scripts !== null && scripts.includes("lhprobe-tool"), scripts);
  const cat = await row("cat");
  const shimNote = await evaluate("document.querySelector('[data-testid=\"check-audit-shims\"]')?.textContent ?? null");
  if (catShim) {
    check("on this host cat is the distribution's coreutils shim: explained, not raised as a script",
      cat?.[1] === "转到 coreutils（发行版写法）" && shimNote?.includes("cat") === true && !(scripts ?? "").includes("cat"), { cat, shimNote });
  } else if (catBusybox) {
    const multiNote = await evaluate("document.querySelector('[data-testid=\"check-audit-multi-call\"]')?.textContent ?? null");
    check("on this host cat is BusyBox: named as a multi-call program, never offered collection",
      cat?.[1] === "BusyBox 等多合一程序" && multiNote?.includes("cat") === true && shimNote === null, { cat, multiNote });
  } else {
    check("on this host cat is a program: 未加采集, and no shim is mentioned",
      cat?.[1] === "未加采集" && shimNote === null, { cat, shimNote });
  }
  const defaults = await evaluate(`[...document.querySelectorAll('.check-audit-command-list button')].map((b) => [b.querySelector('strong')?.textContent, b.querySelectorAll(':scope > span')[1]?.textContent])`);
  check("no command is labelled with the old 原始二进制 claim", !(await evaluate("document.body.textContent.includes('原始二进制')")), defaults.slice(0, 6));
  await page.shot("check-audit-commands.png");

  // 3. The log: missing.
  const logState = () => evaluate("(() => { const panel = document.querySelector('[data-testid=\"check-audit-log-state\"]'); return panel ? panel.dataset.state : null; })()");
  await tab("日志");
  await uiWait("document.querySelector('[data-testid=\"check-audit-log-state\"]') !== null || document.querySelector('.check-audit-log-summary') !== null", "the log read");
  check("with no log at all the page says so and that it proves nothing, not that the log is empty",
    await logState() === "absent" && await evaluate("document.querySelector('[data-testid=\"check-audit-log-state\"]').textContent.includes('没有日志不代表这些命令没有被执行过')"));
  await tab("周期分析");
  await uiWait("document.querySelector('[data-testid=\"check-audit-log-state\"]')?.dataset.state === 'absent'", "the analysis tab");
  check("the analysis tab gives the same reason instead of 没有识别到周期行为",
    !(await evaluate("document.querySelector('.check-audit-content').textContent.includes('没有识别到周期行为')")));
  await page.shot("check-audit-log-absent.png");

  // 4. A symlink to /etc/shadow where the log belongs.
  const shadowStart = script("head -n 1 /etc/shadow | cut -d: -f1-2");
  script(`mkdir -p ${logDir} && ln -s /etc/shadow ${logPath}`);
  await tab("日志");
  await refresh();
  await uiWait("document.querySelector('[data-testid=\"check-audit-log-state\"]')?.dataset.state === 'not-regular-file'", "the symlinked log");
  check("a symlink in the log's place is reported and not followed",
    await evaluate("document.querySelector('[data-testid=\"check-audit-log-state\"]').textContent.includes('不跟随它')"));
  check("nothing of /etc/shadow reaches the page through it",
    shadowStart.length > 5 && !(await evaluate(`document.body.textContent.includes(${JSON.stringify(shadowStart)})`)), shadowStart.slice(0, 5));

  // 5. A real log: periodic records and a line that is no record.
  const lines = [
    ...[0, 1, 2, 3].map((i) => record(`2026-10-11 10:0${i}:00`, "curl", "-s http://198.51.100.7/beacon", "www-data", 3100 + i, "cron")),
    ...[0, 1, 2].map((i) => record(`2026-10-11 10:10:${String(i * 10).padStart(2, "0")}`, "cat", "/etc/shadow", "deploy", 3200 + i, "bash")),
    "someone appended this </pre><script>x()</script>",
  ];
  script(`rm -f ${logPath}
cat > ${logPath} <<'EOF'
${lines.join("\n")}
EOF
chmod 0644 ${logPath}`);
  await refresh();
  await uiWait("document.querySelector('.check-audit-log-summary') !== null", "the planted log");
  const read = await evaluate(`(() => ({
    summary: [...document.querySelectorAll('.check-audit-log-summary article')].map((a) => a.textContent),
    counts: [...document.querySelectorAll('.check-audit-counts span')].map((s) => s.textContent),
    malformed: [...document.querySelectorAll('.check-audit-log-list article.is-malformed')].map((a) => a.textContent),
    warning: [...document.querySelectorAll('.check-audit-warning')].map((p) => p.textContent).join(' '),
    scripts: document.querySelectorAll('.check-audit-log-list script').length,
  }))()`);
  check("all eight lines are read, one of them counted as no record",
    read.summary[0] === "8读取窗口" && read.summary.includes("1不是审计记录的行"), read.summary);
  check("the counts list the commands only, never the line that is no record",
    read.counts.length === 2 && read.counts.includes("curl · 4") && read.counts.includes("cat · 3"), read.counts);
  check("the line that is no record is shown as written, as text, and called out",
    read.malformed.length === 1 && read.malformed[0].includes("someone appended this </pre><script>x()</script>") &&
    read.scripts === 0 && read.warning.includes("1 行不是本工具写的审计记录格式"), read);
  await page.shot("check-audit-log-read.png");
  // Copying: the shown records as TSV through the host clipboard.
  app.clearClipboard();
  await evaluate("document.querySelector('[data-testid=\"check-audit-copy\"]').click(), true");
  await uiWait("document.querySelector('[data-testid=\"check-audit-copy-notice\"]') !== null", "the copy");
  const copyNotice = await evaluate("document.querySelector('[data-testid=\"check-audit-copy-notice\"]').textContent");
  const copiedRows = (app.readClipboard() ?? "").split("\n").filter((line) => line !== "");
  check("copying gives the shown records as TSV, one line each, the odd line marked as no record",
    copyNotice.startsWith("已复制显示的 8 条") && copiedRows.length === 9 && copiedRows[0].startsWith("时间\t命令\t参数") &&
    copiedRows.every((line) => line.split("\t").length === 9) &&
    copiedRows.filter((line) => line.includes("curl\t-s http://198.51.100.7/beacon\twww-data")).length === 4 &&
    copiedRows.some((line) => line.endsWith("\t是\t不是审计记录") && line.includes("someone appended this </pre><script>x()</script>")),
  { copyNotice, rows: copiedRows.slice(0, 3) });
  await setInput(".check-audit-log-query input", "shadow");
  await evaluate("document.querySelector('.check-audit-log-query').requestSubmit(), true");
  await uiWait("document.querySelector('.check-audit-log-summary article:nth-child(2) strong')?.textContent === '3'", "the search");
  check("a search keeps to the records that match", (await evaluate("document.querySelectorAll('.check-audit-log-list article').length")) === 3);
  await tab("周期分析");
  await uiWait("document.querySelectorAll('.check-audit-cycle-list article').length > 0", "the cycles");
  const cycles = await evaluate("[...document.querySelectorAll('.check-audit-cycle-list article')].map((a) => a.textContent)");
  check("the periodic beacon and the repeated read are found with their periods",
    cycles.some((c) => c.includes("curl") && c.includes("约每 60 秒")) && cycles.some((c) => c.includes("cat") && c.includes("约每 10 秒")), cycles);
  await tab("建议");
  await uiWait("document.querySelectorAll('.check-audit-suggestion-list article').length > 0", "the suggestions");
  check("suggestions are text only, with nothing to run or copy",
    await evaluate("document.querySelectorAll('.check-audit-suggestion-list button, .check-audit-suggestion-list code').length === 0"));

  // 6. Empty.
  script(`: > ${logPath}`);
  await tab("日志");
  await setInput(".check-audit-log-query input", "");
  await evaluate("document.querySelector('.check-audit-log-query').requestSubmit(), true");
  await uiWait("document.querySelector('.check-audit-log-summary article strong')?.textContent === '0'", "the empty log");
  check("an empty log is said to be empty, not missing",
    await evaluate("document.querySelector('.check-audit-content').textContent.includes('日志文件存在，但是空的')"));
  await app.close();
  app = null;

  // 7. As deploy: the log root keeps to itself.
  script(`printf '%s\\n' '${record("2026-10-11 11:00:00", "cat", "/etc/hosts", "root", 4000, "bash")}' > ${logPath} && chown root:root ${logPath} && chmod 0600 ${logPath}`);
  app = await openAs(`审计靶机 ${lab} deploy`, consoleErrors);
  page = app.session;
  evaluate = (expression) => page.evaluate(expression);
  await tab("日志");
  await uiWait("document.querySelector('[data-testid=\"check-audit-log-state\"]') !== null || document.querySelector('.check-audit-log-summary') !== null", "the log read as deploy");
  check("a log this account may not read is reported as unreadable, not as empty",
    await logState() === "unreadable" && await evaluate("document.querySelector('[data-testid=\"check-audit-log-state\"]').textContent.includes('没有读到不代表没有记录')"));
  script(`chmod 0644 ${logPath} && chmod 0700 ${logDir}`);
  await refresh();
  await uiWait("document.querySelector('[data-testid=\"check-audit-log-state\"]')?.dataset.state === 'unreadable' && document.querySelector('.check-audit-view-header button')?.disabled === false", "the closed directory");
  check("a directory this account may not enter is also reported as unreadable, not as no log", await logState() === "unreadable");
  await page.shot("check-audit-log-unreadable.png");
  await tab("命令");
  await uiWait("document.querySelector('.check-audit-view-header p')?.textContent.includes('普通会话') === true", "the session kind");
  check("the commands tab says this is not a root session", true);
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
  schema: "lovelyhawk-check-audit-probe/v1",
  lab,
  status: failures === 0 ? "PASS" : "FAIL",
  generatedAt: new Date().toISOString(),
  checks,
}, null, 2)}\n`);
console.log(`${failures === 0 ? "PASS" : "FAIL"}: ${checks.filter((item) => item.passed).length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failures === 0 ? 0 : 1;
