// 主机全景 against a real lab host in the real window: the summary (CPU,
// memory, disk, network), every tab with its table or its stated empty or
// missing-tool reason, refresh, copying a table through the host clipboard,
// a planted process whose command line is hostile markup shown as plain text,
// and disconnect leaving no stale table. The process is harmless (`sleep`
// under a crafted name) and is removed afterwards.
//
//   LAB=ubuntu node ui/scripts/probe-system-info.mjs
//
// Needs the debug desktop build and the backend harness build.

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
const lab = process.env.LAB ?? "ubuntu";
const runRoot = path.join(repositoryRoot, "target", "desktop-debug", `system-info-${randomUUID()}`);
const evidence = path.join(runRoot, "evidence");
const clipboardFile = path.join(runRoot, "clipboard.txt");
const marker = `lhprobe${randomUUID().slice(0, 8)}`;
const hostileName = `<img src=x onerror="document.title='owned'">${marker}`;
const checks = [];
function check(name, ok, detail = null) {
  checks.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail === null ? "" : ` — ${JSON.stringify(detail).slice(0, 500)}`}`);
}
fs.mkdirSync(evidence, { recursive: true });

const container = `lab-${lab}`;
function docker(...args) {
  // -e runs docker directly; "--" would hand the line to a shell that expands $ first.
  return execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "-e", "docker", ...args], { encoding: "utf8" });
}
/** PIDs of processes whose command line carries the marker, matched here rather than by pkill -f. */
function plantedPids() {
  return docker("exec", container, "ps", "-eo", "pid=,args=").split("\n")
    .filter((line) => line.includes(marker)).map((line) => line.trim().split(/\s+/u)[0]).filter(Boolean);
}

// A harmless process whose name is hostile markup. The name travels base64
// encoded so no shell or argument parser on the way can reinterpret it.
const encoded = Buffer.from(hostileName, "utf8").toString("base64");
docker("exec", "-d", "-e", `LH_NAME=${encoded}`, container, "bash", "-c", 'exec -a "$(printf %s "$LH_NAME" | base64 -d)" sleep 900');
await delay(800);
const planted = docker("exec", container, "ps", "-eo", "args=").split("\n").find((line) => line.includes(marker)) ?? "";
check("a process with a hostile name runs on the lab host", planted.includes(`${hostileName} 900`), planted);

const sidecar = new Sidecar(backendBinary(), runRoot);
try {
  const status = await connect(sidecar, { ...labTarget(lab), name: `实验室 ${lab}` });
  if (status?.stage !== "connected") throw new Error(`lab connect failed: ${JSON.stringify(status)}`);
  await sidecar.call("ssh.binding.disconnect", { bindingHandle: status.bindingHandle });
} finally {
  sidecar.close();
}
await delay(500);

const port = 11_400 + Math.floor(Math.random() * 80);
const { child, output } = launchDesktop({ executable, archiveRoot: runRoot, port, extraEnv: { LOVELYHAWK_TEST_CLIPBOARD_FILE: clipboardFile } });
let exitCode = null;
child.once("exit", (code) => { exitCode = code; });
const errors = [];
const tableState = `(() => {
  const panel = document.querySelector('.system-info-table-panel');
  const scroll = panel?.querySelector('.system-info-table-scroll, .system-info-file-scroll');
  return {
    active: document.querySelector('.system-info-tabs button[aria-selected="true"], .system-info-tabs .active')?.textContent.trim() ?? null,
    loading: panel?.querySelector('.system-info-table-state[role="status"]') !== null && panel?.querySelector('.system-info-table-state[role="status"]') !== undefined,
    error: panel?.querySelector('.system-info-table-state.error')?.textContent ?? null,
    state: panel?.querySelector('.system-info-table-state:not([role])')?.textContent.trim().slice(0, 160) ?? null,
    rows: scroll ? scroll.querySelectorAll('tbody tr, .system-info-file').length : 0,
  };
})()`;
try {
  const { session } = await attach(port, (url) => /^https?:\/\/tauri\.localhost\/(index\.html)?$/u.test(url));
  session.onEvent((method, params) => {
    if (method === "Runtime.exceptionThrown" || (method === "Runtime.consoleAPICalled" && params?.type === "error")) errors.push(JSON.stringify(params).slice(0, 1_500));
  });
  await session.send("Runtime.enable");
  await waitFor(() => session.evaluate("document.querySelector('[data-testid=\"sidebar-connect-target\"]') !== null"), { label: "the sidebar" });
  await session.evaluate("[...document.querySelectorAll('.nav-item')].find((item) => item.textContent.includes('主机全景')).click(), true");
  const prompt = await waitFor(() => session.evaluate("document.querySelector('.system-info-connect-prompt, .target-required-banner, .content-connect-action') !== null"), { timeoutMs: 10_000, label: "the connect prompt" }).catch(() => false);
  check("disconnected, the page asks for a target instead of showing an empty table", prompt && await session.evaluate("document.querySelector('.system-info-table-scroll') === null"));

  // Connect through the manager.
  await session.evaluate("document.querySelector('[data-testid=\"sidebar-connect-target\"]').click(), true");
  await waitFor(() => session.evaluate(`(() => { const row = document.querySelector('.connection-list-row'); if (!row || row.disabled) return false; row.click(); return true; })()`), { timeoutMs: 15_000, label: "the saved connection" });
  await waitFor(() => session.evaluate(`(() => { const button = [...document.querySelectorAll('.connection-detail button')].find((candidate) => candidate.textContent.trim() === '连接目标' && !candidate.disabled); if (!button) return false; button.click(); return true; })()`), { timeoutMs: 15_000, label: "连接目标" });
  await waitFor(() => session.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]') !== null && document.querySelector('.connection-manager-backdrop') === null"), { timeoutMs: 90_000, label: "the connection" });
  await session.evaluate("[...document.querySelectorAll('.nav-item')].find((item) => item.textContent.includes('主机全景')).click(), true");

  const summary = await waitFor(() => session.evaluate(`(() => {
    const section = document.querySelector('.system-info-summary');
    if (!section) return null;
    const facts = Object.fromEntries([...section.querySelectorAll('dt, span')].map((label) => [label.textContent.trim(), label.nextElementSibling?.textContent.trim() ?? '']));
    return facts['主机名'] ? facts : null;
  })()`), { timeoutMs: 60_000, label: "the summary" }).catch(() => null);
  const needed = ["主机名", "操作系统", "CPU", "总内存", "根分区总量", "主要 IP"];
  check("the summary shows host, CPU, memory, disk and network figures", summary !== null && needed.every((key) => (summary[key] ?? "").length > 0 && summary[key] !== "—"), summary && Object.fromEntries(needed.map((key) => [key, summary[key]])));
  await session.screenshot(path.join(evidence, "summary.png"));

  // Every tab: rows, or a reason.
  const tabs = await session.evaluate("[...document.querySelectorAll('.system-info-tabs button')].map((button) => button.textContent.trim())");
  const outcomes = [];
  for (const [index, label] of tabs.entries()) {
    await session.evaluate(`document.querySelectorAll('.system-info-tabs button')[${index}].click(), true`);
    const outcome = await waitFor(async () => {
      const state = await session.evaluate(tableState);
      // The first tab is the summary, not a table.
      const summary = await session.evaluate("document.querySelector('.system-info-summary') !== null");
      return state.rows > 0 || state.state !== null || state.error !== null || summary ? { ...state, summary } : null;
    }, { timeoutMs: 60_000, label: `the ${label} tab` }).catch(() => session.evaluate(tableState));
    outcomes.push({ label, rows: outcome.rows, state: outcome.state, error: outcome.error, summary: outcome.summary === true });
  }
  const silent = outcomes.filter((outcome) => !outcome.summary && outcome.rows === 0 && outcome.state === null && outcome.error === null);
  check(`every one of ${tabs.length} tabs shows rows or says why it has none`, silent.length === 0, { silent, sample: outcomes.slice(0, 6) });
  const empties = outcomes.filter((outcome) => outcome.rows === 0 && outcome.state !== null);
  check("an empty tab never claims the host is clean", empties.every((outcome) => !/没有风险|安全|无异常/u.test(outcome.state)), empties);

  // The planted process, as text.
  const processTab = tabs.findIndex((label) => label.includes("进程"));
  await session.evaluate(`document.querySelectorAll('.system-info-tabs button')[${processTab}].click(), true`);
  const found = await waitFor(() => session.evaluate(`(() => { const row = [...document.querySelectorAll('.system-info-table-scroll tbody tr')].find((candidate) => candidate.textContent.includes(${JSON.stringify(marker)})); return row ? row.textContent.slice(0, 200) : null; })()`), { timeoutMs: 30_000, label: "the planted process" }).catch(() => null);
  check("the hostile process name is shown literally and never runs", found?.includes(`<img src=x onerror=`) === true && await session.evaluate("document.title !== 'owned' && document.querySelectorAll('.system-info-table-scroll img').length === 0"), found);

  fs.rmSync(clipboardFile, { force: true });
  await session.evaluate("[...document.querySelectorAll('.system-info-panel-actions button')].find((button) => button.textContent.trim() === '复制表格').click(), true");
  const copied = await waitFor(() => fs.existsSync(clipboardFile) ? fs.readFileSync(clipboardFile, "utf8") : null, { timeoutMs: 10_000, label: "the copied table" }).catch(() => null);
  check("copying the table hands its text, header first, to the host clipboard", copied !== null && copied.startsWith("风险\tPID") && copied.includes(hostileName), copied?.slice(0, 160));

  await session.evaluate("document.querySelector('.system-info-refresh').click(), true");
  const refreshed = await waitFor(() => session.evaluate(`(() => { const rows = [...document.querySelectorAll('.system-info-table-scroll tbody tr')]; return rows.some((row) => row.textContent.includes(${JSON.stringify(marker)})) ? rows.length : null; })()`), { timeoutMs: 60_000, label: "the refreshed table" }).catch(() => null);
  check("刷新 reads the host again and the row is still there", refreshed !== null, refreshed);
  await session.screenshot(path.join(evidence, "processes.png"));

  await session.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]').click(), true");
  const after = await waitFor(() => session.evaluate("document.querySelector('[data-testid=\"sidebar-connect-target\"]') !== null ? { table: document.querySelector('.system-info-table-scroll') !== null, marker: document.body.textContent.includes(" + JSON.stringify(marker) + ") } : null"), { timeoutMs: 20_000, label: "the disconnect" }).catch(() => null);
  check("after disconnecting no table or row from the old target remains", after !== null && !after.table && !after.marker, after);

  check("no console errors", errors.length === 0, errors.slice(0, 3));
  await session.evaluate("document.querySelector('[data-testid=\"window-close\"]').click(), true");
  await waitFor(() => exitCode !== null, { timeoutMs: 15_000, label: "exit" }).catch(() => undefined);
  check("the app exits cleanly", exitCode === 0, exitCode);
} catch (error) {
  check("probe completed", false, error instanceof Error ? error.message : String(error));
  console.error(output.join("").slice(-3_000));
} finally {
  if (exitCode === null) child.kill();
  try { for (const pid of plantedPids()) docker("exec", container, "kill", pid); } catch { /* the host may be gone */ }
  await delay(300);
  const left = plantedPids();
  check("the planted process was removed", left.length === 0, left);
}

const failed = checks.filter((entry) => !entry.ok);
fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify({
  schema: "lovelyhawk-system-info-probe/v1",
  status: failed.length === 0 ? "PASS" : "FAIL",
  lab,
  generatedAt: new Date().toISOString(),
  checks,
}, null, 2)}\n`);
console.log(`${failed.length === 0 ? "PASS" : "FAIL"}: ${checks.length - failed.length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failed.length === 0 ? 0 : 1;
