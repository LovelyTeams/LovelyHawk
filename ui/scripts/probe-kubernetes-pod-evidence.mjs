// Keeping a pod file as case evidence, in the window the operator uses,
// against the k3s lab (svc-kubernetes → lab-k3s).
//
// The run creates a namespace of its own, labelled with the run's id, with
// one pod holding a 1 MiB random file and a text file. Checked: a file row in
// the pod file dialog offers 留证; the folder comes from the host's dialog
// (scripted in this debug build, as for the other evidence probes); the panel
// follows the copy to 已保存为证据 with a digest that matches the one kubectl
// computes inside the pod and the bytes saved locally; the host's copy is
// gone; a dismissed folder dialog starts nothing; the case lists the evidence
// with its file. The namespace is deleted at the end after its label is checked.
//
//   node ui/scripts/probe-kubernetes-pod-evidence.mjs
import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { labTarget } from "../../tools/lab/lab-target.mjs";
import { Sidecar, backendBinary, connect } from "../../tools/lab/rpc-harness.mjs";
import { assertKubernetesLab, labKubectl, onClient } from "../../tools/lab/kubernetes-rbac-fixture.mjs";
import { attach, delay, launchDesktop, waitFor } from "./cdp.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const executable = process.env.LOVELYHAWK_DESKTOP_BIN ??
  path.join(repositoryRoot, "target", "debug", process.platform === "win32" ? "lovelyhawk.exe" : "lovelyhawk");
const runId = randomUUID();
const runRoot = path.join(repositoryRoot, "target", "desktop-debug", `kubernetes-pod-evidence-${runId}`);
const evidence = path.join(runRoot, "evidence");
const kept = path.join(runRoot, "kept");
const namespace = `lh-ui-evidence-${runId.slice(0, 8)}`;
const checks = [];
function check(name, ok, detail = null) {
  checks.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${ok || detail === null ? "" : ` — ${JSON.stringify(detail).slice(0, 400)}`}`);
}
fs.mkdirSync(evidence, { recursive: true });
fs.mkdirSync(kept, { recursive: true });
// The host's folder dialog answers from this file, one answer per dialog.
const hooks = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-lab-hooks-"));
const answers = path.join(hooks, "dialog-answers.json");
const answer = (value) => fs.writeFileSync(answers, JSON.stringify([value]));
answer(null);

assertKubernetesLab();
labKubectl(["apply", "-f", "-"], JSON.stringify({
  apiVersion: "v1", kind: "List", items: [
    { apiVersion: "v1", kind: "Namespace", metadata: { name: namespace, labels: { "lovelyres-test-run": runId } } },
    {
      apiVersion: "v1", kind: "Pod", metadata: { name: "keeper", namespace },
      spec: {
        terminationGracePeriodSeconds: 1,
        containers: [{
          name: "app", image: "alpine:3.20", imagePullPolicy: "IfNotPresent",
          command: ["sh", "-c", "mkdir -p /data; head -c 1048576 /dev/urandom > /data/blob.bin; echo planted-report > /data/report.txt; touch /data/ready; while true; do sleep 5; done"],
          resources: { limits: { cpu: "500m", memory: "32Mi" } },
        }],
      },
    },
  ],
}));
for (let attempt = 0; attempt < 90; attempt += 1) {
  const ready = labKubectl(["get", "pod", "keeper", "-n", namespace, "-o", "jsonpath={.status.containerStatuses[*].ready}"]).trim();
  if (ready === "true" && labKubectl(["exec", "keeper", "-n", namespace, "--", "sh", "-c", "test -e /data/ready && echo yes || echo no"]).trim() === "yes") break;
  await delay(2_000);
}

let child = null;
let exitCode = null;
let output = [];
const errors = [];
try {
  const sidecarProcess = new Sidecar(backendBinary(), runRoot);
  try {
    const status = await connect(sidecarProcess, { ...labTarget("kubernetes"), name: "实验 Kubernetes" });
    if (status?.stage !== "connected") throw new Error(`lab connect failed: ${JSON.stringify(status)}`);
    await sidecarProcess.call("ssh.binding.disconnect", { bindingHandle: status.bindingHandle });
  } finally {
    sidecarProcess.close();
  }
  await delay(500);

  const port = 12_460 + Math.floor(Math.random() * 80);
  ({ child, output } = launchDesktop({
    executable, archiveRoot: runRoot, port, extraEnv: { LOVELYHAWK_TEST_DIALOG_ANSWERS: answers },
  }));
  child.once("exit", (code) => { exitCode = code; });
  const { session: main } = await attach(port, (url) => /^https?:\/\/tauri\.localhost\/(index\.html)?$/u.test(url));
  main.onEvent((method, params) => {
    if (method === "Runtime.exceptionThrown" || (method === "Runtime.consoleAPICalled" && params?.type === "error")) errors.push(JSON.stringify(params).slice(0, 1_500));
  });
  await main.send("Runtime.enable");
  await waitFor(() => main.evaluate("(() => { const button = document.querySelector('[data-testid=\"sidebar-connect-target\"]'); if (!button) return false; button.click(); return true; })()"), { label: "连接管理" });
  await waitFor(() => main.evaluate("(() => { const row = document.querySelector('.connection-list .connection-list-row'); if (!row || row.disabled) return false; row.click(); return true; })()"), { timeoutMs: 15_000, label: "the saved connection" });
  await waitFor(() => main.evaluate("(() => { const button = [...document.querySelectorAll('.connection-detail button')].find((candidate) => candidate.textContent.trim() === '连接目标' && !candidate.disabled); if (!button) return false; button.click(); return true; })()"), { timeoutMs: 15_000, label: "连接目标" });
  await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]') !== null && document.querySelector('.connection-manager-backdrop') === null"), { timeoutMs: 90_000, label: "the connection" });
  const navigate = (title) => main.evaluate(`[...document.querySelectorAll('.nav-item')].find((item) => item.querySelector('strong')?.textContent === ${JSON.stringify(title)})?.click(), true`);
  await navigate("Kubernetes");
  const row = `[...document.querySelectorAll('.kubernetes-page tbody tr')].find((candidate) => (candidate.querySelector('.kubernetes-row-button')?.textContent ?? '') === 'keeper' && candidate.textContent.includes(${JSON.stringify(namespace)}))`;
  await waitFor(() => main.evaluate(`(${row}) != null`), { timeoutMs: 120_000, label: "the keeper pod" });

  // --- Open the pod's files and go to /data.
  await main.evaluate(`(${row}).querySelector('[data-testid="kubernetes-row-files"]').click(), true`);
  await waitFor(() => main.evaluate("[...document.querySelectorAll('[data-testid=\"pod-file-dialog\"] [data-testid=\"exec-browser-enter\"]')].some((button) => button.textContent === 'data')"), { timeoutMs: 60_000, label: "the root listing" });
  await main.evaluate("[...document.querySelectorAll('[data-testid=\"pod-file-dialog\"] [data-testid=\"exec-browser-enter\"]')].find((button) => button.textContent === 'data').click(), true");
  const fileRow = (name) => `[...document.querySelectorAll('[data-testid="pod-file-dialog"] .exec-browser-table tbody tr')].find((candidate) => candidate.querySelector('.exec-browser-name')?.textContent === ${JSON.stringify(name)})`;
  await waitFor(() => main.evaluate(`(${fileRow("blob.bin")}) != null`), { timeoutMs: 60_000, label: "/data/blob.bin" });
  const offered = await main.evaluate(`(() => { const button = (${fileRow("blob.bin")}).querySelector('[data-testid="pod-browser-evidence"]'); return button ? { text: button.textContent, label: button.getAttribute('aria-label') ?? button.title } : null; })()`);
  check("a file row offers 留证 with a name that says what it does", offered?.text === "留证" && (offered.label ?? "").includes("blob.bin"), offered);

  // --- Keep it: the folder from the host's dialog, then the copy followed to the end.
  answer(kept);
  await main.evaluate(`(${fileRow("blob.bin")}).querySelector('[data-testid="pod-browser-evidence"]').click(), true`);
  const progress = await waitFor(() => main.evaluate("(() => { const panel = document.querySelector('[data-testid=\"pod-evidence\"]'); return panel ? panel.dataset.state : null; })()"), { timeoutMs: 30_000, label: "the evidence panel" }).catch(() => null);
  check("the panel appears and follows the copy", ["choosing", "copying", "collecting", "completed"].includes(progress), progress);
  const done = await waitFor(() => main.evaluate("(() => { const panel = document.querySelector('[data-testid=\"pod-evidence\"]'); if (!panel || !['completed', 'failed', 'saved-unlinked', 'cancelled'].includes(panel.dataset.state)) return null; return { state: panel.dataset.state, text: panel.textContent, sha: panel.querySelector('[data-testid=\"pod-evidence-sha256\"]')?.textContent ?? null, temporary: panel.querySelector('[data-testid=\"pod-evidence-temporary\"]')?.textContent ?? null, folder: [...panel.querySelectorAll('code')].map((node) => node.textContent).find((value) => value.startsWith('LovelyHawk-evidence-')) ?? null }; })()"), { timeoutMs: 180_000, label: "the kept file" }).catch(() => null);
  const podDigest = labKubectl(["exec", "keeper", "-n", namespace, "--", "sha256sum", "/data/blob.bin"]).split(/\s+/u)[0];
  check("the panel says it was kept, with the digest kubectl computes inside the pod",
    done?.state === "completed" && done.text.includes("已保存为证据") && done.sha === podDigest, { done, podDigest });
  const local = done?.folder ? path.join(kept, done.folder, "pod-file.bin") : null;
  const localDigest = local !== null && fs.existsSync(local) ? createHash("sha256").update(fs.readFileSync(local)).digest("hex") : null;
  check("the bytes saved in the chosen folder are the pod's", localDigest === podDigest, { local, localDigest });
  check("the host's copy is gone, and the panel says so",
    done?.temporary === "已删除" && onClient("ls /tmp/lovelyhawk-podfile-* 2>/dev/null | wc -l").trim() === "0", done?.temporary);
  await main.screenshot(path.join(evidence, "kubernetes-pod-evidence.png"));

  // --- From the file view, with the folder dialog dismissed: nothing starts.
  await main.evaluate("document.querySelector('[data-testid=\"pod-evidence-reset\"]')?.click(), true");
  await main.evaluate(`(${fileRow("report.txt")}).querySelector('[data-testid="pod-browser-read"]').click(), true`);
  await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"pod-file-view-evidence\"]') !== null"), { timeoutMs: 60_000, label: "the file view" });
  const foldersBefore = fs.readdirSync(kept).length;
  answer(null);
  await main.evaluate("document.querySelector('[data-testid=\"pod-file-view-evidence\"]').click(), true");
  await delay(1_500);
  const dismissed = await main.evaluate("document.querySelector('[data-testid=\"pod-evidence\"]')?.dataset.state ?? null");
  check("a dismissed folder dialog starts nothing and creates no folder",
    dismissed === null && fs.readdirSync(kept).length === foldersBefore, { dismissed, folders: fs.readdirSync(kept).length });
  await main.evaluate("[...document.querySelectorAll('[data-testid=\"pod-file-dialog\"] footer button')].find((button) => button.textContent === '关闭')?.click(), true");
  await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"pod-file-dialog\"]') === null"), { label: "the closed file dialog" });

  // --- The case lists it.
  await navigate("案件工作台");
  await waitFor(() => main.evaluate("document.querySelector('.case-list-item') !== null"), { timeoutMs: 30_000, label: "the case list" });
  await main.evaluate("document.querySelector('.case-list-item').click(), true");
  const listed = await waitFor(() => main.evaluate(`document.body.textContent.includes('Pod 文件留证') && document.body.textContent.includes(${JSON.stringify(`${done?.folder}/pod-file.bin`)})`), { timeoutMs: 30_000, label: "the case evidence" }).catch(() => false);
  check("the case lists the pod file as evidence with its file", listed === true);
  await main.screenshot(path.join(evidence, "kubernetes-pod-evidence-case.png"));

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
  if (child !== null && exitCode === null) child.kill();
  fs.rmSync(hooks, { recursive: true, force: true });
  try {
    const label = labKubectl(["get", "namespace", namespace, "-o", "jsonpath={.metadata.labels.lovelyres-test-run}"]).trim();
    if (label === runId) {
      labKubectl(["delete", "namespace", namespace, "--wait=true", "--timeout=120s"]);
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
  schema: "lovelyhawk-kubernetes-pod-evidence-probe/v1",
  status: failed.length === 0 ? "PASS" : "FAIL",
  generatedAt: new Date().toISOString(),
  namespace,
  checks,
}, null, 2)}\n`);
console.log(`${failed.length === 0 ? "PASS" : "FAIL"}: ${checks.length - failed.length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failed.length === 0 ? 0 : 1;
