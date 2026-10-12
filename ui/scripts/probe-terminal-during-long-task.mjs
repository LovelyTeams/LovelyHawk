// The terminal window keeps working while the main window waits on a long
// remote command.
//
// On lab-ubuntu, /etc/crontab is swapped for a named pipe for the length of
// the probe, so the built-in "系统计划任务内容" command blocks in `cat` until its
// 30-second limit — a long main-window call that does not depend on timing
// luck. While it is still running, a line typed into the terminal must come
// back within a few seconds, and the terminal window's file list must refresh.
// Before the host gave terminal and file calls their own lanes, both waited
// for the whole command. The original /etc/crontab is restored at the end
// (byte-identical, checked), and lab-ubuntu runs no cron daemon to trip on
// the pipe meanwhile.
//
//   node ui/scripts/probe-terminal-during-long-task.mjs

import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { labTarget } from "../../tools/lab/lab-target.mjs";
import { Sidecar, backendBinary, connect } from "../../tools/lab/rpc-harness.mjs";
import { attach, delay, launchDesktop, waitFor } from "./cdp.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const executable = path.join(repositoryRoot, "target", "debug", process.platform === "win32" ? "lovelyhawk.exe" : "lovelyhawk");
const id = randomUUID().slice(0, 8);
const backup = `/etc/crontab.lovelyhawk-probe-${id}`;
const runRoot = path.join(repositoryRoot, "target", "desktop-debug", `long-task-${randomUUID()}`);
const evidence = path.join(runRoot, "evidence");
const checks = [];
function check(name, ok, detail = null) {
  checks.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail === null ? "" : ` — ${JSON.stringify(detail).slice(0, 400)}`}`);
}
fs.mkdirSync(evidence, { recursive: true });
const onHost = (script) => execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "-e", "docker", "exec", "lab-ubuntu", "sh", "-c", script], { encoding: "utf8" });

if (onHost("pgrep -x cron >/dev/null && echo running || echo none").trim() !== "none") {
  throw new Error("lab-ubuntu runs cron; refusing to put a pipe where it reads.");
}
const originalHash = onHost("sha256sum /etc/crontab | cut -d' ' -f1").trim();

const sidecar = new Sidecar(backendBinary(), runRoot);
try {
  const status = await connect(sidecar, { ...labTarget("ubuntu"), name: "实验 ubuntu" });
  if (status?.stage !== "connected") throw new Error(`lab connect failed: ${JSON.stringify(status)}`);
  await sidecar.call("ssh.binding.disconnect", { bindingHandle: status.bindingHandle });
} finally {
  sidecar.close();
}
await delay(500);

const port = 11_900 + Math.floor(Math.random() * 80);
const { child, output } = launchDesktop({ executable, archiveRoot: runRoot, port });
let exitCode = null;
child.once("exit", (code) => { exitCode = code; });
const errors = [];
let piped = false;
try {
  const { session: main } = await attach(port, (url) => /^https?:\/\/tauri\.localhost\/(index\.html)?$/u.test(url));
  main.onEvent((method, params) => {
    if (method === "Runtime.exceptionThrown" || (method === "Runtime.consoleAPICalled" && params?.type === "error")) errors.push(JSON.stringify(params).slice(0, 1_500));
  });
  await main.send("Runtime.enable");
  await waitFor(() => main.evaluate("(() => { const button = document.querySelector('[data-testid=\"sidebar-connect-target\"]'); if (!button) return false; button.click(); return true; })()"), { label: "连接管理" });
  await waitFor(() => main.evaluate(`(() => { const row = document.querySelector('.connection-list .connection-list-row'); if (!row || row.disabled) return false; row.click(); return true; })()`), { timeoutMs: 15_000, label: "the saved connection" });
  await waitFor(() => main.evaluate(`(() => { const button = [...document.querySelectorAll('.connection-detail button')].find((candidate) => candidate.textContent.trim() === '连接目标' && !candidate.disabled); if (!button) return false; button.click(); return true; })()`), { timeoutMs: 15_000, label: "连接目标" });
  await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"sidebar-open-terminal\"]') !== null && document.querySelector('.connection-manager-backdrop') === null"), { timeoutMs: 90_000, label: "the connection" });

  await main.evaluate("document.querySelector('[data-testid=\"sidebar-open-terminal\"]').click(), true");
  const { session: terminal } = await attach(port, (url) => url.includes("/terminal.html?window=terminal"), 30_000);
  await terminal.send("Runtime.enable");
  await waitFor(() => terminal.evaluate("(document.querySelector('.xterm-rows')?.textContent ?? '').includes('#')"), { timeoutMs: 45_000, label: "the shell prompt" });
  await waitFor(() => terminal.evaluate("document.querySelectorAll('section[aria-label=\"远程文件\"] .sftp-browser-row').length > 0"), { timeoutMs: 30_000, label: "the file list" });
  async function typeLine(text) {
    await terminal.evaluate("document.querySelector('.xterm-helper-textarea')?.focus(), true");
    for (const character of text) {
      await terminal.send("Input.dispatchKeyEvent", { type: "keyDown", key: character, text: character, unmodifiedText: character });
      await terminal.send("Input.dispatchKeyEvent", { type: "keyUp", key: character });
    }
    await terminal.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13, text: "\r" });
    await terminal.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
  }

  // The long main-window call.
  await main.evaluate(`(() => { const button = [...document.querySelectorAll('.nav-item')].find((candidate) => candidate.textContent?.includes('命令工作台')); button?.click(); return true; })()`);
  await waitFor(() => main.evaluate(`(() => { const button = [...document.querySelectorAll('.emergency-commands-list button')].find((candidate) => candidate.textContent.includes('系统计划任务内容')); if (!button || button.disabled) return false; button.click(); return true; })()`), { timeoutMs: 120_000, label: "系统计划任务内容" });
  await waitFor(() => main.evaluate("document.querySelector('.emergency-command-detail h2')?.textContent === '系统计划任务内容'"), { label: "the command" });
  onHost(`mv /etc/crontab ${backup} && mkfifo -m 644 /etc/crontab`);
  piped = true;
  await main.evaluate("document.querySelector('.emergency-command-run').click(), true");
  await waitFor(() => main.evaluate("document.querySelector('.emergency-command-run')?.textContent.includes('执行中') === true"), { label: "the command running" });
  const started = Date.now();
  await delay(2_000);

  // While it runs: a typed line comes back, and the file list refreshes.
  const marker = `lanes-${id}`;
  const typedAt = Date.now();
  await typeLine(`echo ${marker}`);
  const echoed = await waitFor(() => terminal.evaluate(`(document.querySelector('.xterm-rows')?.textContent ?? "").split(${JSON.stringify(marker)}).length >= 3`), { timeoutMs: 40_000, label: "the echo" }).then(() => Date.now() - typedAt).catch(() => null);
  const stillRunning = await main.evaluate("document.querySelector('.emergency-command-run')?.textContent.includes('执行中') === true");
  check("a line typed during the long command comes back within 5 s, while the command is still running", echoed !== null && echoed < 5_000 && stillRunning, { echoMs: echoed, stillRunning, sinceStartMs: Date.now() - started });
  const refreshedAt = Date.now();
  await terminal.evaluate("[...document.querySelectorAll('.sftp-browser-actions button')].find((button) => button.textContent.includes('刷新'))?.click(), true");
  await delay(300);
  const listed = await waitFor(() => terminal.evaluate("(() => { const button = [...document.querySelectorAll('.sftp-browser-actions button')].find((candidate) => candidate.textContent.includes('刷新')); return button !== undefined && !button.disabled && document.querySelectorAll('section[aria-label=\"远程文件\"] .sftp-browser-row').length > 0; })()"), { timeoutMs: 40_000, label: "the refreshed list" }).then(() => Date.now() - refreshedAt).catch(() => null);
  const stillRunningAfterList = await main.evaluate("document.querySelector('.emergency-command-run')?.textContent.includes('执行中') === true");
  check("the terminal window's file list refreshes within 5 s, too", listed !== null && listed < 5_000 && stillRunningAfterList, { listMs: listed, stillRunning: stillRunningAfterList });
  await terminal.screenshot(path.join(evidence, "terminal-during-long-task.png"));

  // The long command ends on its own limit and says so.
  const finished = await waitFor(() => main.evaluate("document.querySelector('.emergency-command-run')?.textContent.includes('执行中') === false ? (document.querySelector('.emergency-command-detail')?.textContent ?? '') : null"), { timeoutMs: 60_000, label: "the command to end" }).catch(() => null);
  check("the blocked command ends at its limit and reports a timeout", finished !== null && /超时|时限|上限/u.test(finished), finished?.slice(0, 200));
  await main.screenshot(path.join(evidence, "command-timeout.png"));

  check("no console errors in the main window", errors.length === 0, errors.slice(0, 3));
  await main.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]').click(), true");
  await delay(1_000);
  await main.evaluate("document.querySelector('[data-testid=\"window-close\"]').click(), true");
  await waitFor(() => exitCode !== null, { timeoutMs: 15_000, label: "exit" }).catch(() => undefined);
  check("the app exits cleanly", exitCode === 0, exitCode);
} catch (error) {
  check("probe completed", false, error instanceof Error ? error.message : String(error));
  console.error(output.join("").slice(-3_000));
} finally {
  if (exitCode === null) child.kill();
  if (piped) onHost(`rm -f /etc/crontab && mv ${backup} /etc/crontab`);
  check("/etc/crontab is back, byte for byte", onHost("[ -f /etc/crontab ] && sha256sum /etc/crontab | cut -d' ' -f1").trim() === originalHash);
}

const failed = checks.filter((entry) => !entry.ok);
fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify({
  schema: "lovelyhawk-terminal-during-long-task-probe/v1",
  status: failed.length === 0 ? "PASS" : "FAIL",
  generatedAt: new Date().toISOString(),
  checks,
}, null, 2)}\n`);
console.log(`${failed.length === 0 ? "PASS" : "FAIL"}: ${checks.length - failed.length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failed.length === 0 ? 0 : 1;
