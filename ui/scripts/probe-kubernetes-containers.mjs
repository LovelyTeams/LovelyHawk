// Choosing a container of a multi-container pod, in the window the operator
// uses, against the k3s lab (svc-kubernetes → lab-k3s).
//
// The run creates a namespace of its own, labelled with the run's id, holding
// one pod of three containers — app and sidecar each write their own marker
// and log line, crasher keeps exiting — with sidecar named as the default by
// the kubectl.kubernetes.io/default-container annotation. Checked: the row
// offers the containers, the default chosen and the stopped one marked; logs
// say which container they came from and are that container's; a stopped
// container offers no shell and no files, and says why; the file dialog and
// the shell window are in the container chosen. The namespace is deleted at
// the end after its label is checked.
//
//   node ui/scripts/probe-kubernetes-containers.mjs
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
const runId = randomUUID();
const runRoot = path.join(repositoryRoot, "target", "desktop-debug", `kubernetes-containers-${runId}`);
const evidence = path.join(runRoot, "evidence");
const namespace = `lh-ui-containers-${runId.slice(0, 8)}`;
const checks = [];
function check(name, ok, detail = null) {
  checks.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${ok || detail === null ? "" : ` — ${JSON.stringify(detail).slice(0, 400)}`}`);
}
fs.mkdirSync(evidence, { recursive: true });
const kubectl = (args, input) => execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "-e", "docker", "exec", "-i", "svc-kubernetes", "kubectl", ...args],
  { encoding: "utf8", windowsHide: true, timeout: 120_000, input }).trim();

const container = (name, script) => ({
  name, image: "alpine:3.20", imagePullPolicy: "IfNotPresent", command: ["sh", "-c", script],
  resources: { limits: { cpu: "100m", memory: "32Mi" } },
});
kubectl(["apply", "-f", "-"], JSON.stringify({
  apiVersion: "v1", kind: "List", items: [
    { apiVersion: "v1", kind: "Namespace", metadata: { name: namespace, labels: { "lovelyres-test-run": runId } } },
    {
      apiVersion: "v1", kind: "Pod",
      metadata: { name: "duo", namespace, annotations: { "kubectl.kubernetes.io/default-container": "sidecar" } },
      spec: {
        terminationGracePeriodSeconds: 1,
        containers: [
          container("app", "echo app > /tmp/which; while true; do echo app-tick; sleep 2; done"),
          container("sidecar", "echo sidecar > /tmp/which; while true; do echo sidecar-tick; sleep 2; done"),
          container("crasher", "echo crasher-says-bye; sleep 1; exit 1"),
        ],
      },
    },
  ],
}));
for (let attempt = 0; attempt < 60; attempt += 1) {
  const state = JSON.parse(kubectl(["get", "pod", "duo", "-n", namespace, "-o", "json"]));
  const statuses = Object.fromEntries((state.status.containerStatuses ?? []).map((s) => [s.name, s]));
  if (statuses.app?.state?.running && statuses.sidecar?.state?.running && (statuses.crasher?.restartCount ?? 0) >= 1 &&
    !statuses.crasher?.state?.running) break;
  await delay(2_000);
}

const sidecarProcess = new Sidecar(backendBinary(), runRoot);
try {
  const status = await connect(sidecarProcess, { ...labTarget("kubernetes"), name: "实验 Kubernetes" });
  if (status?.stage !== "connected") throw new Error(`lab connect failed: ${JSON.stringify(status)}`);
  await sidecarProcess.call("ssh.binding.disconnect", { bindingHandle: status.bindingHandle });
} finally {
  sidecarProcess.close();
}
await delay(500);

const port = 12_300 + Math.floor(Math.random() * 80);
const { child, output } = launchDesktop({ executable, archiveRoot: runRoot, port });
let exitCode = null;
child.once("exit", (code) => { exitCode = code; });
const errors = [];
const row = `[...document.querySelectorAll('.kubernetes-page tbody tr')].find((candidate) => (candidate.querySelector('.kubernetes-row-button')?.textContent ?? '') === 'duo' && candidate.textContent.includes(${JSON.stringify(namespace)}))`;
const inRow = (testId) => `(${row})?.querySelector('[data-testid="${testId}"]')`;
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
  await waitFor(() => main.evaluate(`(${row}) != null`), { timeoutMs: 120_000, label: "the duo pod" });

  // --- The row offers the containers, the default chosen, the stopped one marked.
  const choice = await main.evaluate(`(() => { const select = ${inRow("kubernetes-row-container")}; return select ? { value: select.value, options: [...select.options].map((o) => o.textContent) } : null; })()`);
  check("the row offers the pod's containers in order, the annotated default chosen and the stopped one marked",
    choice?.value === "sidecar" && JSON.stringify(choice.options) === JSON.stringify(["app", "sidecar（默认）", "crasher（未运行）"]), choice);
  await main.screenshot(path.join(evidence, "kubernetes-container-choice.png"));

  const pick = (value) => main.evaluate(`(() => { const select = ${inRow("kubernetes-row-container")}; Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set.call(select, ${JSON.stringify(value)}); select.dispatchEvent(new Event('change', { bubbles: true })); return true; })()`);
  const readLogs = async () => {
    await main.evaluate(`${inRow("kubernetes-row-logs")}.click(), true`);
    const logs = await waitFor(() => main.evaluate("(() => { const dialog = document.querySelector('.kubernetes-detail'); if (!dialog || dialog.textContent.includes('正在读取')) return null; const result = dialog.querySelector('.kubernetes-text-result'); const alert = dialog.querySelector('[role=\"alert\"]'); return result ? { title: result.querySelector('[data-testid=\"kubernetes-text-title\"]')?.textContent, text: result.querySelector('pre')?.textContent } : alert ? { alert: alert.textContent } : null; })()"), { timeoutMs: 60_000, label: "the logs" }).catch(() => null);
    await main.evaluate("document.querySelector('.kubernetes-detail-close')?.click(), true");
    await waitFor(() => main.evaluate("document.querySelector('.kubernetes-detail') === null"), { label: "the closed detail" });
    return logs;
  };
  // --- Logs say which container they came from, and are that container's.
  const defaultLogs = await readLogs();
  check("logs with the default chosen are sidecar's, and say so",
    defaultLogs?.title === "最近 Pod 日志 · 容器 sidecar" && defaultLogs.text?.includes("sidecar-tick") && !defaultLogs.text?.includes("app-tick"), defaultLogs);
  await pick("app");
  const appLogs = await readLogs();
  check("choosing app reads app's logs, and says so",
    appLogs?.title === "最近 Pod 日志 · 容器 app" && appLogs.text?.includes("app-tick") && !appLogs.text?.includes("sidecar-tick"), appLogs);

  // --- A stopped container offers no shell and no files, and says why.
  await pick("crasher");
  const stopped = await main.evaluate(`(() => ({
    terminal: { disabled: ${inRow("kubernetes-row-terminal")}.disabled, title: ${inRow("kubernetes-row-terminal")}.title },
    files: { disabled: ${inRow("kubernetes-row-files")}.disabled, title: ${inRow("kubernetes-row-files")}.title },
    logs: ${inRow("kubernetes-row-logs")}.disabled,
  }))()`);
  check("with the stopped container chosen there is no shell or files, and the buttons say why, but its logs stay readable",
    stopped.terminal.disabled && stopped.files.disabled && stopped.terminal.title.includes("容器 crasher 现在没有在运行") && !stopped.logs, stopped);
  await main.screenshot(path.join(evidence, "kubernetes-container-stopped.png"));

  // --- Files of the chosen container.
  await pick("app");
  await main.evaluate(`${inRow("kubernetes-row-files")}.click(), true`);
  const subtitle = await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"pod-file-dialog\"] header p')?.textContent ?? null"), { timeoutMs: 30_000, label: "the file dialog" });
  await waitFor(() => main.evaluate("[...document.querySelectorAll('[data-testid=\"pod-file-dialog\"] [data-testid=\"exec-browser-enter\"]')].some((button) => button.textContent === 'tmp')"), { timeoutMs: 60_000, label: "the root listing" });
  await main.evaluate("[...document.querySelectorAll('[data-testid=\"pod-file-dialog\"] [data-testid=\"exec-browser-enter\"]')].find((button) => button.textContent === 'tmp').click(), true");
  const whichRow = "[...document.querySelectorAll('[data-testid=\"pod-file-dialog\"] .exec-browser-table tbody tr')].find((row) => row.querySelector('.exec-browser-name')?.textContent === 'which')";
  await waitFor(() => main.evaluate(`(${whichRow}) != null`), { timeoutMs: 60_000, label: "/tmp/which" });
  await main.evaluate(`(${whichRow}).querySelector('[data-testid="pod-browser-read"]').click(), true`);
  const viewed = await waitFor(() => main.evaluate("(() => { const view = document.querySelector('[data-testid=\"pod-file-view\"]'); return view ? view.querySelector('textarea').value : null; })()"), { timeoutMs: 60_000, label: "the file view" }).catch(() => null);
  const note = await main.evaluate("document.querySelector('[data-testid=\"pod-file-dialog\"] .exec-file-note')?.textContent ?? ''");
  check("the file dialog names the container and reads app's own marker file",
    subtitle === `${namespace}/duo · 容器 app` && viewed === "app\n" && note.includes("容器 app"), { subtitle, viewed, note: note.slice(0, 60) });
  await main.screenshot(path.join(evidence, "kubernetes-container-file.png"));
  await main.evaluate("[...document.querySelectorAll('[data-testid=\"pod-file-dialog\"] footer button')].find((button) => button.textContent === '关闭')?.click(), true");
  await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"pod-file-dialog\"]') === null"), { label: "the closed file dialog" });

  // --- The shell window is in the chosen container.
  await main.evaluate(`${inRow("kubernetes-row-terminal")}.click(), true`);
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
  const marker = `which-${randomUUID().slice(0, 8)}`;
  await type(`echo ${marker}=$(cat /tmp/which)`);
  const inside = await waitFor(() => shell.evaluate(`(document.querySelector('.xterm-rows')?.textContent ?? '').includes(${JSON.stringify(`${marker}=app`)})`), { timeoutMs: 20_000, label: "the echo" }).catch(() => false);
  const label = await shell.evaluate("document.documentElement.dataset.targetLabel ?? ''");
  check("the shell window opens in the chosen container and its title says which", inside === true && label.includes(`${namespace}/duo · 容器 app`), { inside, label });
  await shell.screenshot(path.join(evidence, "kubernetes-container-terminal.png"));
  check("no console errors in the main window", errors.length === 0, errors.slice(0, 3));
  await main.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]').click(), true");
  await delay(1_500);
  await main.evaluate("document.querySelector('[data-testid=\"window-close\"]').click(), true");
  await waitFor(() => exitCode !== null, { timeoutMs: 15_000, label: "exit" }).catch(() => undefined);
  check("the app exits cleanly", exitCode === 0, exitCode);
} catch (error) {
  check("probe completed", false, error instanceof Error ? error.message : String(error));
  console.error(output.join("").slice(-3_000));
} finally {
  if (exitCode === null) child.kill();
  try {
    const label = kubectl(["get", "namespace", namespace, "-o", "jsonpath={.metadata.labels.lovelyres-test-run}"]);
    if (label === runId) {
      kubectl(["delete", "namespace", namespace, "--wait=true", "--timeout=120s"]);
      check("the run's own namespace was deleted", true);
    } else {
      check("the run's own namespace was deleted", false, `label ${label}`);
    }
  } catch (error) {
    check("the run's own namespace was deleted", false, error instanceof Error ? error.message : String(error));
  }
}

const failed = checks.filter((entry) => !entry.ok);
fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify({
  schema: "lovelyhawk-kubernetes-containers-probe/v1",
  status: failed.length === 0 ? "PASS" : "FAIL",
  generatedAt: new Date().toISOString(),
  checks,
}, null, 2)}\n`);
console.log(`${failed.length === 0 ? "PASS" : "FAIL"}: ${checks.length - failed.length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failed.length === 0 ? 0 : 1;
