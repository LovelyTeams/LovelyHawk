// The file manager's directory list going stale, in the real terminal window.
//
// The backend forgets a browser five minutes after its last listing. The page
// has to say so when it happens — not when the next click is refused — turn
// off what would be refused, and offer the one thing that helps: opening the
// browser again. This waits out the five minutes once, idle, and checks all
// three, then reopens: the new browser walks back down to the folder that was
// on screen. The probe makes three empty folders under /tmp on the lab host
// for that, and removes them afterwards.
//
//   LAB=super node ui/scripts/probe-sftp-expiry.mjs

import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { labTarget } from "../../tools/lab/lab-target.mjs";
import { Sidecar, backendBinary, connect } from "../../tools/lab/rpc-harness.mjs";
import { attach, delay, launchDesktop, waitFor } from "./cdp.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const executable = process.env.LOVELYHAWK_DESKTOP_BIN ??
  path.join(repositoryRoot, "target", "debug", process.platform === "win32" ? "lovelyhawk.exe" : "lovelyhawk");
const lab = process.env.LAB ?? "ubuntu";
const runRoot = path.join(repositoryRoot, "target", "desktop-debug", `sftp-expiry-${randomUUID()}`);
const evidence = path.join(runRoot, "evidence");
const checks = [];
function check(name, ok, detail = null) {
  checks.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail === null ? "" : ` — ${JSON.stringify(detail).slice(0, 400)}`}`);
}
fs.mkdirSync(evidence, { recursive: true });

/** A command in the lab container, as root; only for the probe's own folders under /tmp. */
function onHost(command) {
  return execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "-e", "docker", "exec", `lab-${lab}`, "sh", "-c", command],
    { encoding: "utf8", windowsHide: true, timeout: 60_000 }).trim();
}
const folder = `lh-return-${randomUUID().slice(0, 8)}`;
const deepPath = `/tmp/${folder}/inner/deep`;
onHost(`mkdir -p ${deepPath}`);

const sidecar = new Sidecar(backendBinary(), runRoot);
try {
  const status = await connect(sidecar, { ...labTarget(lab), name: `实验室 ${lab}` });
  if (status?.stage !== "connected") throw new Error(`lab connect failed: ${JSON.stringify(status)}`);
  await sidecar.call("ssh.binding.disconnect", { bindingHandle: status.bindingHandle });
} finally {
  sidecar.close();
}
await delay(500);

const port = 11_600 + Math.floor(Math.random() * 80);
const { child, output } = launchDesktop({ executable, archiveRoot: runRoot, port });
let exitCode = null;
child.once("exit", (code) => { exitCode = code; });
const errors = [];
// The local pane comes first and uses the same classes, so everything is
// looked up inside the remote pane.
const remote = 'section[aria-label="远程文件"]';
const remotePath = `document.querySelector('${remote} .sftp-browser-path-value')?.textContent`;
const row = (name) => `[...document.querySelectorAll('section[aria-label="远程文件"] .sftp-browser-row')].find((candidate) => candidate.querySelector('.sftp-browser-row-label')?.textContent === ${JSON.stringify(name)})`;
const toolbar = `(() => {
  const buttons = [...document.querySelectorAll('.sftp-browser-actions button')];
  const named = (text) => buttons.find((button) => button.textContent.trim() === text);
  return {
    footer: document.querySelector('section[aria-label="远程文件"] .sftp-browser-pane-foot')?.textContent ?? '',
    expired: document.querySelector('[data-testid="sftp-list-expired"]') !== null,
    reopen: document.querySelector('[data-testid="sftp-reopen"]')?.disabled === false,
    refresh: named('刷新') !== undefined,
    upload: named('上传')?.disabled ?? null,
    newFolder: named('新建文件夹')?.disabled ?? null,
    terminalHere: document.querySelector('[data-testid="sftp-terminal-here"]')?.disabled ?? null,
  };
})()`;
try {
  const { session: main } = await attach(port, (url) => /^https?:\/\/tauri\.localhost\/(index\.html)?$/u.test(url));
  await main.send("Runtime.enable");
  await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"sidebar-connect-target\"]') !== null"), { label: "the sidebar" });
  await main.evaluate("document.querySelector('[data-testid=\"sidebar-connect-target\"]').click(), true");
  await waitFor(() => main.evaluate("(() => { const candidate = document.querySelector('.connection-list-row'); if (!candidate || candidate.disabled) return false; candidate.click(); return true; })()"), { timeoutMs: 15_000, label: "the saved connection" });
  await waitFor(() => main.evaluate("(() => { const button = [...document.querySelectorAll('.connection-detail button')].find((candidate) => candidate.textContent.trim() === '连接目标' && !candidate.disabled); if (!button) return false; button.click(); return true; })()"), { timeoutMs: 15_000, label: "连接目标" });
  await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"sidebar-open-terminal\"]') !== null && document.querySelector('.connection-manager-backdrop') === null"), { timeoutMs: 90_000, label: "the connection" });
  await main.evaluate("document.querySelector('[data-testid=\"sidebar-open-terminal\"]').click(), true");
  const { session: terminal } = await attach(port, (url) => url.includes("/terminal.html?window=terminal"), 30_000);
  terminal.onEvent((method, params) => {
    if (method === "Runtime.exceptionThrown" || (method === "Runtime.consoleAPICalled" && params?.type === "error")) errors.push(JSON.stringify(params).slice(0, 1_500));
  });
  await terminal.send("Runtime.enable");
  await waitFor(() => terminal.evaluate("document.querySelector('[data-testid=\"toggle-remote-files\"]')?.getAttribute('aria-expanded') === 'true'"), { timeoutMs: 30_000, label: "the file panel" });
  await waitFor(() => terminal.evaluate(`(() => { const candidate = ${row("tmp")}; if (!candidate || candidate.disabled) return false; candidate.dispatchEvent(new MouseEvent('dblclick', { bubbles: true })); return true; })()`), { timeoutMs: 30_000, label: "the tmp directory" });
  await waitFor(() => terminal.evaluate(`${remotePath} === 'tmp'`), { timeoutMs: 30_000, label: "/tmp listed" })
    .catch(async (error) => {
      console.error(await terminal.evaluate(`JSON.stringify({ path: ${remotePath} ?? null, rows: [...document.querySelectorAll('${remote} .sftp-browser-row-label')].map((label) => label.textContent).slice(0, 20), error: document.querySelector('${remote} [role="alert"]')?.textContent ?? null })`));
      throw error;
    });

  // Down to the probe's folder, three levels below /tmp.
  for (const name of [folder, "inner", "deep"]) {
    await waitFor(() => terminal.evaluate(`(() => { const candidate = ${row(name)}; if (!candidate || candidate.disabled) return false; candidate.dispatchEvent(new MouseEvent('dblclick', { bubbles: true })); return true; })()`), { timeoutMs: 30_000, label: `the ${name} folder` });
    await waitFor(() => terminal.evaluate(`${remotePath} === ${JSON.stringify(name)}`), { timeoutMs: 30_000, label: `${name} listed` });
  }

  const fresh = await terminal.evaluate(toolbar);
  check("a fresh listing says how long it is good for, and every action is on", /约 5 分钟内有效/u.test(fresh.footer) && fresh.refresh && !fresh.expired && fresh.upload === false && fresh.newFolder === false, fresh);
  await terminal.screenshot(path.join(evidence, "sftp-fresh.png"));

  // Five minutes idle, as an operator reading something else would leave it.
  console.log("waiting out the five-minute window…");
  await delay(5 * 60_000 + 10_000);
  const stale = await terminal.evaluate(toolbar);
  check("past its deadline the list says it has expired, without a click being refused first", stale.expired && /目录列表已过期/u.test(stale.footer), stale);
  check("刷新 has become 重新打开, and what would be refused is off", stale.reopen && !stale.refresh && stale.upload === true && stale.newFolder === true && stale.terminalHere === true, stale);
  await terminal.screenshot(path.join(evidence, "sftp-expired.png"));

  await terminal.evaluate("document.querySelector('[data-testid=\"sftp-reopen\"]').click(), true");
  await waitFor(() => terminal.evaluate("document.querySelector('[data-testid=\"sftp-list-expired\"]') === null && (document.querySelector('section[aria-label=\"远程文件\"] .sftp-browser-pane-foot')?.textContent ?? '').includes('分钟内有效')"), { timeoutMs: 30_000, label: "the reopened browser" }).catch(() => undefined);
  const returned = await waitFor(() => terminal.evaluate(`(() => {
    const notice = document.querySelector('[data-testid="sftp-return"]')?.textContent ?? '';
    return notice.startsWith('已回到') ? { path: ${remotePath} ?? null, notice } : null;
  })()`), { timeoutMs: 30_000, label: "the walk back" }).catch(async () => terminal.evaluate(`({
    path: ${remotePath} ?? null, notice: document.querySelector('[data-testid="sftp-return"]')?.textContent ?? null,
  })`));
  check("and walks back down to the folder that was on screen, saying so",
    returned.path === "deep" && returned.notice === `已回到重新打开前所在的 ${deepPath}。`, returned);
  // Read once the walk has settled: each step's listing turns the actions off while it loads.
  const reopened = await terminal.evaluate(toolbar);
  check("重新打开 reads the directory list again and everything is back on", !reopened.expired && reopened.refresh && reopened.upload === false && /约 5 分钟内有效/u.test(reopened.footer), reopened);
  await terminal.screenshot(path.join(evidence, "sftp-returned.png"));
  // And the new browser really works from there: up one level lists inner.
  const up = await terminal.evaluate("(() => { const button = document.querySelector('section[aria-label=\"远程文件\"] button[aria-label=\"上一级\"]'); if (!button || button.disabled) return false; button.click(); return true; })()");
  const listedUp = up && await waitFor(() => terminal.evaluate(`${remotePath} === 'inner'`), { timeoutMs: 30_000, label: "inner after going up" })
    .then(() => true, () => false);
  check("the reopened browser lists directories again", listedUp);
  check("and moving on clears the notice", await terminal.evaluate("document.querySelector('[data-testid=\"sftp-return\"]') === null"));
  await terminal.screenshot(path.join(evidence, "sftp-reopened.png"));
  check("no console errors in the terminal window", errors.length === 0, errors.slice(0, 3));
  await main.evaluate("document.querySelector('[data-testid=\"window-close\"]').click(), true");
  await waitFor(() => exitCode !== null, { timeoutMs: 15_000, label: "exit" }).catch(() => undefined);
  check("the app exits cleanly", exitCode === 0, exitCode);
} catch (error) {
  check("probe completed", false, error instanceof Error ? error.message : String(error));
  console.error(output.join("").slice(-3_000));
} finally {
  if (exitCode === null) child.kill();
  try {
    onHost(`rm -rf /tmp/${folder}`);
  } catch (error) {
    console.error(`could not remove /tmp/${folder}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

const failed = checks.filter((entry) => !entry.ok);
fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify({
  schema: "lovelyhawk-sftp-expiry-probe/v1",
  status: failed.length === 0 ? "PASS" : "FAIL",
  generatedAt: new Date().toISOString(),
  checks,
}, null, 2)}\n`);
console.log(`${failed.length === 0 ? "PASS" : "FAIL"}: ${checks.length - failed.length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failed.length === 0 ? 0 : 1;
