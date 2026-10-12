// Exporting a pod's manifest from the window the operator uses, against the
// k3s lab (svc-kubernetes → lab-k3s).
//
// The run creates a namespace of its own, labelled with the run's id, with one
// pod carrying a clear-text environment value. Checked: the pod's detail
// offers 导出 YAML…; the file goes where the host's save dialog says (scripted
// in this debug build, as for the other export probes) and holds the pod's
// own manifest under the provenance header, its UID as kubectl reads it and
// the clear-text value kept; the page says where it went and warns about
// secrets; a dismissed dialog writes nothing and says nothing; an existing file
// is never replaced and the page says the export did not happen. The namespace
// is deleted at the end after its label is checked.
//
//   node ui/scripts/probe-kubernetes-manifest.mjs
import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { labTarget } from "../../tools/lab/lab-target.mjs";
import { Sidecar, backendBinary, connect } from "../../tools/lab/rpc-harness.mjs";
import { assertKubernetesLab, labKubectl } from "../../tools/lab/kubernetes-rbac-fixture.mjs";
import { attach, delay, launchDesktop, waitFor } from "./cdp.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const executable = process.env.LOVELYHAWK_DESKTOP_BIN ??
  path.join(repositoryRoot, "target", "debug", process.platform === "win32" ? "lovelyhawk.exe" : "lovelyhawk");
const runId = randomUUID();
const runRoot = path.join(repositoryRoot, "target", "desktop-debug", `kubernetes-manifest-${runId}`);
const evidence = path.join(runRoot, "evidence");
const namespace = `lh-ui-manifest-${runId.slice(0, 8)}`;
const saved = path.join(evidence, `keeper-${runId.slice(0, 8)}.yaml`);
const secretValue = `planted-${runId.slice(0, 8)}`;
const checks = [];
/**
 * check(label, ok, detail) with a boolean, or check(label, actual, expected)
 * compared exactly. A non-boolean with nothing to compare against fails.
 */
function check(name, ok, ...rest) {
  const comparing = typeof ok !== "boolean";
  const detail = rest.length > 0 ? rest[0] : null;
  const passed = comparing ? rest.length > 0 && ok === detail : ok;
  const shown = comparing ? { actual: ok, expected: rest.length > 0 ? detail : "(nothing to compare with)" } : detail;
  checks.push({ name, ok: passed, detail: shown });
  console.log(`${passed ? "PASS" : "FAIL"} ${name}${passed || shown === null ? "" : ` — ${JSON.stringify(shown).slice(0, 400)}`}`);
}
fs.mkdirSync(evidence, { recursive: true });
// The host's save dialog answers from this file, one answer per dialog.
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
          command: ["sh", "-c", "while true; do sleep 5; done"],
          env: [{ name: "PROBE_SECRET", value: secretValue }],
          resources: { limits: { cpu: "100m", memory: "32Mi" } },
        }],
      },
    },
  ],
}));
for (let attempt = 0; attempt < 90; attempt += 1) {
  if (labKubectl(["get", "pod", "keeper", "-n", namespace, "-o", "jsonpath={.status.phase}"]).trim() === "Running") break;
  await delay(2_000);
}

let child = null;
let exitCode = null;
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

  const port = 12_560 + Math.floor(Math.random() * 80);
  ({ child } = launchDesktop({ executable, archiveRoot: runRoot, port, extraEnv: { LOVELYHAWK_TEST_DIALOG_ANSWERS: answers } }));
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
  await main.evaluate("[...document.querySelectorAll('.nav-item')].find((item) => item.querySelector('strong')?.textContent === 'Kubernetes')?.click(), true");
  const row = `[...document.querySelectorAll('.kubernetes-page tbody tr')].find((candidate) => (candidate.querySelector('.kubernetes-row-button')?.textContent ?? '') === 'keeper' && candidate.textContent.includes(${JSON.stringify(namespace)}))`;
  await waitFor(() => main.evaluate(`(${row}) != null`), { timeoutMs: 120_000, label: "the keeper pod" });
  await main.evaluate(`[...(${row}).querySelectorAll('button')].find((button) => button.textContent.trim() === '详情').click(), true`);
  await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"kubernetes-export-manifest\"]') !== null"), { timeoutMs: 30_000, label: "the detail with its export" });
  const offered = await main.evaluate("(() => { const button = document.querySelector('[data-testid=\"kubernetes-export-manifest\"]'); return { text: button.textContent.trim(), title: button.title }; })()");
  check("the pod's detail offers 导出 YAML…, saying it is read-only", offered.text === "导出 YAML…" && offered.title.includes("只读"), offered);
  const exportAndSettle = async () => {
    await main.evaluate("document.querySelector('[data-testid=\"kubernetes-export-manifest\"]').click(), true");
    await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"kubernetes-export-manifest\"]')?.disabled === false"), { timeoutMs: 90_000, label: "the export to finish" });
    await delay(300);
    return main.evaluate("(() => { const notice = document.querySelector('[data-testid=\"kubernetes-export-notice\"]'); return notice ? { text: notice.textContent, role: notice.getAttribute('role'), error: notice.classList.contains('is-error') } : null; })()");
  };

  // --- Saved where the dialog said.
  answer(saved);
  const done = await exportAndSettle();
  check("the page says where it went, and warns that secrets may be inside",
    done !== null && done.role === "status" && !done.error && done.text.includes(path.basename(saved)) && done.text.includes("明文口令"), done);
  const contents = fs.existsSync(saved) ? fs.readFileSync(saved, "utf8") : "";
  const uid = labKubectl(["get", "pod", "keeper", "-n", namespace, "-o", "jsonpath={.metadata.uid}"]).trim();
  check("the file is the pod's manifest under its header, its UID as kubectl reads it",
    contents.startsWith("# LovelyHawk 导出的 Kubernetes 对象清单") && contents.includes(`# 对象：Pod ${namespace}/keeper`) &&
    contents.includes(`# UID：${uid}  `) && contents.includes(`\n  uid: ${uid}\n`) && /^kind: Pod$/mu.test(contents),
    contents.slice(0, 400));
  check("every field is kept as the cluster returned it, the clear-text value included", contents.includes(`value: ${secretValue}`));
  await main.screenshot(path.join(evidence, "kubernetes-manifest-saved.png"));
  const digest = createHash("sha256").update(contents).digest("hex");

  // --- The dialog dismissed: nothing written, nothing said.
  answer(null);
  const dismissed = await exportAndSettle();
  check("a dismissed save dialog writes nothing and says nothing",
    dismissed === null && fs.readdirSync(evidence).filter((name) => name.endsWith(".yaml")).length === 1, dismissed);

  // --- An existing file is never replaced.
  answer(saved);
  const existing = await exportAndSettle();
  check("an existing file is not replaced, and the page says the export did not happen",
    existing !== null && existing.error && existing.role === "alert" &&
    createHash("sha256").update(fs.readFileSync(saved, "utf8")).digest("hex") === digest, existing);
  await main.screenshot(path.join(evidence, "kubernetes-manifest-refused.png"));
  check("no console errors", errors.length === 0, errors.slice(0, 2));
  await main.evaluate("document.querySelector('[data-testid=\"window-close\"]').click(), true");
  await waitFor(() => exitCode !== null, { timeoutMs: 15_000, label: "the app to exit" }).catch(() => undefined);
} catch (error) {
  check("probe completed", false, error instanceof Error ? error.message : String(error));
} finally {
  if (exitCode === null) child?.kill();
  fs.rmSync(hooks, { recursive: true, force: true });
  try {
    const label = labKubectl(["get", "namespace", namespace, "-o", "jsonpath={.metadata.labels.lovelyres-test-run}"]).trim();
    if (label === runId) {
      labKubectl(["delete", "namespace", namespace, "--wait=true", "--timeout=120s"]);
      check("the run's own namespace was removed", true);
    } else {
      check("the run's own namespace was removed", false, "its label is not this run's; left in place");
    }
  } catch (error) {
    check("the run's own namespace was removed", false, error instanceof Error ? error.message : String(error));
  }
}
const failed = checks.filter((entry) => !entry.ok);
fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify({
  schema: "lovelyhawk-kubernetes-manifest-ui/v1", runId, status: failed.length === 0 ? "PASS" : "FAIL",
  generatedAt: new Date().toISOString(), checks, errors,
}, null, 2)}\n`);
console.log(`${failed.length === 0 ? "PASS" : "FAIL"}: ${checks.length - failed.length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failed.length === 0 ? 0 : 1;
