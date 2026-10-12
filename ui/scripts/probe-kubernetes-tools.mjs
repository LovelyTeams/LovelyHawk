// The Kubernetes page's responder tools in the window the operator uses,
// against the k3s lab from tools/lab/orchestration (svc-kubernetes → lab-k3s).
//
// Checked: each pod row carries its actions (logs, the run before a restart,
// detail, terminal, files, the workbench) and a pod that is not running offers
// no shell; the crash-looping pod's previous run is readable and says why it
// died; a pod's files can be browsed and one read with its digest; a shell
// opens in its own window inside the pod itself, and what it was running ends
// when the connection goes. Nothing in the cluster is changed by this probe.
//
//   node ui/scripts/probe-kubernetes-tools.mjs
import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { labTarget } from "../../tools/lab/lab-target.mjs";
import { Sidecar, backendBinary, connect } from "../../tools/lab/rpc-harness.mjs";
import { attach, delay, launchDesktop, listTargets, waitFor } from "./cdp.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const executable = process.env.LOVELYHAWK_DESKTOP_BIN ??
  path.join(repositoryRoot, "target", "debug", process.platform === "win32" ? "lovelyhawk.exe" : "lovelyhawk");
const runRoot = path.join(repositoryRoot, "target", "desktop-debug", `kubernetes-tools-${randomUUID()}`);
const evidence = path.join(runRoot, "evidence");
const sleepSeconds = 50_000 + Math.floor(Math.random() * 9_000);
const checks = [];
function check(name, ok, detail = null) {
  checks.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail === null ? "" : ` — ${JSON.stringify(detail).slice(0, 400)}`}`);
}
fs.mkdirSync(evidence, { recursive: true });
/** kubectl on the lab host, read directly so a check is not the tool grading itself. */
const kubectl = (...args) => execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "-e", "docker", "exec", "svc-kubernetes", "kubectl", ...args], { encoding: "utf8", windowsHide: true }).trim();

const sidecar = new Sidecar(backendBinary(), runRoot);
try {
  const status = await connect(sidecar, { ...labTarget("kubernetes"), name: "实验 Kubernetes" });
  if (status?.stage !== "connected") throw new Error(`lab connect failed: ${JSON.stringify(status)}`);
  await sidecar.call("ssh.binding.disconnect", { bindingHandle: status.bindingHandle });
} finally {
  sidecar.close();
}
await delay(500);

const port = 12_200 + Math.floor(Math.random() * 80);
const { child, output } = launchDesktop({ executable, archiveRoot: runRoot, port });
let exitCode = null;
child.once("exit", (code) => { exitCode = code; });
const errors = [];
const visible = "candidate.closest('[hidden]') === null";
const rowOf = (prefix) => `[...document.querySelectorAll('.kubernetes-page tbody tr')].find((row) => (row.querySelector('.kubernetes-row-button')?.textContent ?? '').startsWith(${JSON.stringify(prefix)}))`;
const buttonIn = (prefix, testId) => `(${rowOf(prefix)})?.querySelector('[data-testid="${testId}"]')`;
let podName = null;
try {
  const { session: main } = await attach(port, (url) => /^https?:\/\/tauri\.localhost\/(index\.html)?$/u.test(url));
  main.onEvent((method, params) => {
    if (method === "Runtime.exceptionThrown" || (method === "Runtime.consoleAPICalled" && params?.type === "error")) errors.push(JSON.stringify(params).slice(0, 1_500));
  });
  await main.send("Runtime.enable");
  await waitFor(() => main.evaluate("(() => { const button = document.querySelector('[data-testid=\"sidebar-connect-target\"]'); if (!button) return false; button.click(); return true; })()"), { label: "连接管理" });
  await waitFor(() => main.evaluate("(() => { const row = document.querySelector('.connection-list .connection-list-row'); if (!row || row.disabled) return false; row.click(); return true; })()"), { timeoutMs: 15_000, label: "the saved connection" });
  await waitFor(() => main.evaluate("(() => { const button = [...document.querySelectorAll('.connection-detail button')].find((candidate) => candidate.textContent.trim() === '连接目标' && !candidate.disabled); if (!button) return false; button.click(); return true; })()"), { timeoutMs: 15_000, label: "连接目标" });
  await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]') !== null && document.querySelector('.connection-manager-backdrop') === null"), { timeoutMs: 90_000, label: "the connection" });
  await main.evaluate("(() => { const button = [...document.querySelectorAll('.nav-item')].find((candidate) => candidate.querySelector('strong')?.textContent === 'Kubernetes'); button?.click(); return true; })()");
  await waitFor(() => main.evaluate(`(${rowOf("ledger-")}) != null && (${rowOf("flapping-worker")}) != null`), { timeoutMs: 120_000, label: "the pods" });

  // --- Each row carries what a responder does with a pod.
  const actions = await main.evaluate(`(() => {
    const rows = [...document.querySelectorAll('.kubernetes-page tbody tr')];
    const read = (prefix) => {
      const row = rows.find((candidate) => (candidate.querySelector('.kubernetes-row-button')?.textContent ?? '').startsWith(prefix));
      return Object.fromEntries(['logs', 'previous-logs', 'terminal', 'files', 'investigate'].map((id) => {
        const button = row?.querySelector('[data-testid="kubernetes-row-' + id + '"]');
        return [id, button ? (button.disabled ? 'disabled' : 'enabled') : 'absent'];
      }));
    };
    return { ledger: read('ledger-'), flapping: read('flapping-worker'), pending: read('nightly-report-') };
  })()`);
  check("a running pod offers logs, terminal, files and the workbench on its row", actions.ledger.logs === "enabled" && actions.ledger.terminal === "enabled" && actions.ledger.files === "enabled" && actions.ledger.investigate === "enabled", actions.ledger);
  check("only a pod that restarted offers the run before the restart", actions.flapping["previous-logs"] === "enabled" && actions.ledger["previous-logs"] === "absent", { flapping: actions.flapping, ledger: actions.ledger });
  check("a pod that is not running offers no shell and no files", actions.pending.terminal === "disabled" && actions.pending.files === "disabled", actions.pending);
  await main.screenshot(path.join(evidence, "kubernetes-pod-actions.png"));

  // --- The crash loop's previous run, with the reason it gave before dying.
  await main.evaluate(`${buttonIn("flapping-worker", "kubernetes-row-previous-logs")}.click(), true`);
  let previous = null;
  for (let attempt = 0; attempt < 4 && previous?.text?.includes("lab-marker") !== true; attempt += 1) {
    if (attempt > 0) {
      // The kubelet briefly cannot hand over the old log while it swaps the
      // container; the page says so, and reading again is the operator's move.
      await delay(4_000);
      await main.evaluate("document.querySelector('[data-testid=\"kubernetes-detail-previous-logs\"]')?.click(), true");
    }
    previous = await waitFor(() => main.evaluate("(() => { const dialog = document.querySelector('.kubernetes-detail'); if (!dialog || dialog.textContent.includes('正在读取')) return null; const result = dialog.querySelector('.kubernetes-text-result'); const alert = dialog.querySelector('[role=\"alert\"]'); return result ? { title: result.querySelector('p')?.textContent, text: result.querySelector('pre')?.textContent } : alert ? { alert: alert.textContent } : null; })()"), { timeoutMs: 60_000, label: "the previous run's logs" }).catch(() => null);
  }
  check("the previous run's logs are titled as such and say why it exited", previous?.title === "重启前那次运行的日志" && previous?.text?.includes("lab-marker: cannot reach queue") === true, previous);
  await main.screenshot(path.join(evidence, "kubernetes-previous-logs.png"));
  await main.evaluate("document.querySelector('.kubernetes-detail-close')?.click(), true");
  await waitFor(() => main.evaluate("document.querySelector('.kubernetes-detail') === null"), { label: "the closed detail" });

  // --- A pod's files: browse to /etc and read /etc/hostname, checked by digest.
  podName = await main.evaluate(`(${rowOf("ledger-")}).querySelector('.kubernetes-row-button').textContent`);
  await main.evaluate(`${buttonIn("ledger-", "kubernetes-row-files")}.click(), true`);
  const rootNames = await waitFor(() => main.evaluate("(() => { const names = [...document.querySelectorAll('[data-testid=\"pod-file-dialog\"] [data-testid=\"exec-browser-enter\"]')].map((button) => button.textContent); return names.length > 0 ? names : null; })()"), { timeoutMs: 60_000, label: "the pod's root" }).catch(() => null);
  check("a pod's files open on its root, listed", rootNames?.includes("etc") === true && rootNames.includes("tmp"), rootNames);
  await main.evaluate(`(() => { const candidate = [...document.querySelectorAll('[data-testid="pod-file-dialog"] .exec-browser-places button')].find((candidate) => candidate.textContent === '/etc' && ${visible}); candidate?.click(); return true; })()`);
  const hostnameRow = "[...document.querySelectorAll('[data-testid=\"pod-file-dialog\"] .exec-browser-table tbody tr')].find((row) => row.querySelector('.exec-browser-name')?.textContent === 'hostname')";
  await waitFor(() => main.evaluate(`(${hostnameRow}) != null`), { timeoutMs: 60_000, label: "/etc/hostname in the listing" });
  await main.evaluate(`(${hostnameRow}).querySelector('[data-testid="pod-browser-read"]').click(), true`);
  const viewed = await waitFor(() => main.evaluate("(() => { const view = document.querySelector('[data-testid=\"pod-file-view\"]'); return view ? { text: view.querySelector('textarea').value, digest: view.querySelector('.exec-file-digest').textContent } : null; })()"), { timeoutMs: 60_000, label: "the file view" }).catch(() => null);
  check("reading /etc/hostname shows this pod's own name, with its SHA-256", viewed?.text?.trim() === podName && viewed?.digest === createHash("sha256").update(viewed?.text ?? "").digest("hex"), viewed);
  await main.screenshot(path.join(evidence, "kubernetes-pod-file.png"));
  await main.evaluate("[...document.querySelectorAll('[data-testid=\"pod-file-dialog\"] footer button')].find((button) => button.textContent === '关闭')?.click(), true");
  await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"pod-file-dialog\"]') === null"), { label: "the closed file dialog" });

  // --- A shell in the pod, in its own window.
  await main.evaluate(`${buttonIn("ledger-", "kubernetes-row-terminal")}.click(), true`);
  const { session: shell } = await attach(port, (url) => url.includes("/terminal.html?window=pod"), 30_000);
  await shell.send("Runtime.enable");
  await waitFor(() => shell.evaluate("(document.querySelector('.xterm-rows')?.textContent ?? '').trim().length > 0"), { timeoutMs: 60_000, label: "the pod shell" });
  const type = async (text) => {
    await shell.evaluate("document.querySelector('.xterm-helper-textarea')?.focus(), true");
    for (const character of text) {
      await shell.send("Input.dispatchKeyEvent", { type: "keyDown", key: character, text: character, unmodifiedText: character });
      await shell.send("Input.dispatchKeyEvent", { type: "keyUp", key: character });
    }
    await shell.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13, text: "\r" });
    await shell.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
  };
  const marker = `pod-${randomUUID().slice(0, 8)}`;
  await type(`echo ${marker} $(cat /etc/hostname)`);
  const echoed = await waitFor(() => shell.evaluate(`(document.querySelector('.xterm-rows')?.textContent ?? '').includes(${JSON.stringify(`${marker} ${podName}`)})`), { timeoutMs: 20_000, label: "the echo" }).catch(() => false);
  check("the shell runs inside the pod: its hostname is the pod's name", echoed === true);
  const windowState = await shell.evaluate("({ label: document.documentElement.dataset.targetLabel ?? '', chip: [...document.querySelectorAll('.ssh-window-chip')].map((chip) => chip.textContent), files: document.querySelector('[data-testid=\"toggle-remote-files\"]') !== null })");
  check("the window names the pod, is marked Pod, and shows no host files", windowState.label.includes(podName) && windowState.chip.includes("Pod") && !windowState.files, windowState);
  await shell.screenshot(path.join(evidence, "kubernetes-pod-terminal.png"));
  await type(`sleep ${sleepSeconds}`);
  await delay(1_500);
  const sleeping = () => {
    try { return kubectl("exec", podName, "-n", "payments", "--", "sh", "-c", `ps -o args | grep -c '^sleep ${sleepSeconds}$' || true`); } catch { return "?"; }
  };
  check("the command started in the pod shell is running", sleeping() === "1", sleeping());

  // --- Disconnecting closes the pod window and ends what it was running.
  const podWindows = async () => (await listTargets(port)).filter((entry) => entry.url.includes("/terminal.html?window=pod"));
  await main.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]').click(), true");
  await waitFor(async () => (await podWindows()).length === 0, { timeoutMs: 20_000, label: "the pod window to close" }).catch(() => undefined);
  check("disconnecting closes the pod terminal window", (await podWindows()).length === 0, (await podWindows()).length);
  await waitFor(() => sleeping() === "0", { timeoutMs: 20_000, label: "the sleep to end" }).catch(() => undefined);
  check("closing the window ended the command it was running in the pod", sleeping() === "0", sleeping());
  check("no console errors in the main window", errors.length === 0, errors.slice(0, 3));
  await main.evaluate("document.querySelector('[data-testid=\"window-close\"]').click(), true");
  await waitFor(() => exitCode !== null, { timeoutMs: 15_000, label: "exit" }).catch(() => undefined);
  check("the app exits cleanly", exitCode === 0, exitCode);
} catch (error) {
  check("probe completed", false, error instanceof Error ? error.message : String(error));
  console.error(output.join("").slice(-3_000));
} finally {
  if (exitCode === null) child.kill();
}

const failed = checks.filter((entry) => !entry.ok);
fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify({
  schema: "lovelyhawk-kubernetes-tools-probe/v1",
  status: failed.length === 0 ? "PASS" : "FAIL",
  generatedAt: new Date().toISOString(),
  checks,
}, null, 2)}\n`);
console.log(`${failed.length === 0 ? "PASS" : "FAIL"}: ${checks.length - failed.length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failed.length === 0 ? 0 : 1;
