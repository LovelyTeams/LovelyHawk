// A kubeconfig that may read one namespace and nothing else, in the window
// the operator uses, against the k3s lab (svc-kubernetes → lab-k3s).
//
// The account comes from tools/lab/kubernetes-rbac-fixture.mjs: a login whose
// kubeconfig is a service account bound to a read-only Role in a namespace
// this run creates (no namespace list, no pods/exec, no writes). Checked: the
// page offers the kubeconfig's own namespace, labelled, and reads it; the
// all-namespaces list and the namespace tab say the cluster refused, never
// "nothing there"; the pod's files and shell say pods/exec is missing; no
// console errors. The account and namespace are removed at the end.
//
//   node ui/scripts/probe-kubernetes-rbac.mjs
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { labTarget } from "../../tools/lab/lab-target.mjs";
import { Sidecar, backendBinary, connect } from "../../tools/lab/rpc-harness.mjs";
import { createRestrictedAccount } from "../../tools/lab/kubernetes-rbac-fixture.mjs";
import { attach, delay, launchDesktop, waitFor } from "./cdp.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const executable = process.env.LOVELYHAWK_DESKTOP_BIN ??
  path.join(repositoryRoot, "target", "debug", process.platform === "win32" ? "lovelyhawk.exe" : "lovelyhawk");
const runId = randomUUID();
const runRoot = path.join(repositoryRoot, "target", "desktop-debug", `kubernetes-rbac-${runId}`);
const evidence = path.join(runRoot, "evidence");
const checks = [];
function check(name, ok, detail = null) {
  checks.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${ok || detail === null ? "" : ` — ${JSON.stringify(detail).slice(0, 400)}`}`);
}
fs.mkdirSync(evidence, { recursive: true });

const account = await createRestrictedAccount("lh-ui-rbac");
const { namespace, login, password } = account;
let child = null;
let exitCode = null;
let output = [];
try {
  const sidecarProcess = new Sidecar(backendBinary(), runRoot);
  try {
    const status = await connect(sidecarProcess, { ...labTarget("kubernetes"), username: login, password, name: "受限的 Kubernetes 账号" });
    if (status?.stage !== "connected") throw new Error(`lab connect failed: ${JSON.stringify(status)}`);
    await sidecarProcess.call("ssh.binding.disconnect", { bindingHandle: status.bindingHandle });
  } finally {
    sidecarProcess.close();
  }
  await delay(500);

  const port = 12_380 + Math.floor(Math.random() * 80);
  ({ child, output } = launchDesktop({ executable, archiveRoot: runRoot, port }));
  child.once("exit", (code) => { exitCode = code; });
  const errors = [];
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

  const webRow = "[...document.querySelectorAll('.kubernetes-page tbody tr')].find((candidate) => (candidate.querySelector('.kubernetes-row-button')?.textContent ?? '').startsWith('web-'))";
  const pageState = `(() => {
    const button = document.querySelector('[data-testid="kubernetes-context-namespace"]');
    return {
      context: button ? { text: button.textContent, pressed: button.getAttribute('aria-pressed') } : null,
      scope: document.querySelector('.kubernetes-scope strong')?.textContent ?? '',
      notice: [...document.querySelectorAll('.kubernetes-page .kubernetes-notice')].map((node) => node.textContent).join(' | '),
      table: document.querySelector('.kubernetes-page .kubernetes-state')?.textContent ?? '',
      rows: [...document.querySelectorAll('.kubernetes-page tbody tr')].map((row) => row.textContent),
    };
  })()`;

  // --- The kubeconfig's own namespace, offered and read.
  await waitFor(() => main.evaluate(`(${webRow}) != null`), { timeoutMs: 120_000, label: "the web pod" });
  const first = await main.evaluate(pageState);
  check("the page offers the kubeconfig's own namespace, chosen, and says why",
    first.context?.text === `当前上下文 · ${namespace}` && first.context.pressed === "true" &&
    first.scope === `${namespace}（当前上下文）` && first.notice.includes("不能列出命名空间"), first);
  check("the pods listed are that namespace's", first.rows.length > 0 && first.rows.every((row) => row.includes(namespace)), first.rows);
  await main.screenshot(path.join(evidence, "kubernetes-rbac-context.png"));

  // --- All namespaces: refused, and said so, never shown as empty.
  await main.evaluate("[...document.querySelectorAll('.kubernetes-namespace-list button')].find((button) => button.textContent === '全部')?.click(), true");
  const refused = await waitFor(async () => {
    const state = await main.evaluate(pageState);
    return state.notice.includes("当前账号没有权限读取") ? state : null;
  }, { timeoutMs: 60_000, label: "the refusal" }).catch(() => null);
  check("all namespaces is refused as a permission problem, pointing back to the context namespace",
    refused !== null && refused.notice.includes("当前账号没有权限读取 Pods（集群拒绝）") &&
    refused.notice.includes(`「${namespace}」`) && refused.rows.length === 0 &&
    !refused.table.includes("当前范围没有"), refused);
  await main.screenshot(path.join(evidence, "kubernetes-rbac-all-refused.png"));

  // --- The namespace tab says the list was refused.
  await main.evaluate("[...document.querySelectorAll('.kubernetes-tabs button')].find((button) => button.textContent === 'Namespaces')?.click(), true");
  const namespaceTab = await waitFor(async () => {
    const state = await main.evaluate(pageState);
    return state.table.includes("不能列出命名空间") ? state : null;
  }, { timeoutMs: 30_000, label: "the namespace tab" }).catch(() => null);
  check("the namespace tab says the account may not list namespaces", namespaceTab !== null, await main.evaluate(pageState));
  await main.evaluate("[...document.querySelectorAll('.kubernetes-tabs button')].find((button) => button.textContent === 'Pods')?.click(), true");
  await main.evaluate("document.querySelector('[data-testid=\"kubernetes-context-namespace\"]')?.click(), true");
  await waitFor(() => main.evaluate(`(${webRow}) != null`), { timeoutMs: 60_000, label: "the web pod again" });
  check("choosing the context namespace again lists its pods", true);

  // --- Files need pods/exec: the dialog says so.
  await main.evaluate(`(${webRow}).querySelector('[data-testid="kubernetes-row-files"]').click(), true`);
  const fileError = await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"pod-file-dialog\"] .exec-browser-error')?.textContent ?? null"), { timeoutMs: 60_000, label: "the file dialog's answer" }).catch(() => null);
  check("the file dialog says the account may not exec into the pod", fileError?.includes("pods/exec") === true, fileError);
  await main.screenshot(path.join(evidence, "kubernetes-rbac-files.png"));
  await main.evaluate("[...document.querySelectorAll('[data-testid=\"pod-file-dialog\"] footer button')].find((button) => button.textContent === '关闭')?.click(), true");
  await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"pod-file-dialog\"]') === null"), { label: "the closed file dialog" });

  // --- So does the shell window.
  await main.evaluate(`(${webRow}).querySelector('[data-testid="kubernetes-row-terminal"]').click(), true`);
  const { session: shell } = await attach(port, (url) => url.includes("/terminal.html?window=pod"), 30_000);
  await shell.send("Runtime.enable");
  const shellText = await waitFor(() => shell.evaluate("(() => { const text = document.body.innerText; return text.includes('pods/exec') ? text : null; })()"), { timeoutMs: 60_000, label: "the shell window's answer" }).catch(() => null);
  check("the shell window stays open and says pods/exec is missing", shellText !== null, shellText?.slice(0, 300) ?? null);
  await shell.screenshot(path.join(evidence, "kubernetes-rbac-terminal.png"));

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
  const problems = account.remove();
  check("the run's own namespace and login were removed", problems.length === 0, problems);
}

const failed = checks.filter((entry) => !entry.ok);
fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify({
  schema: "lovelyhawk-kubernetes-rbac-probe/v1",
  status: failed.length === 0 ? "PASS" : "FAIL",
  generatedAt: new Date().toISOString(),
  namespace,
  checks,
}, null, 2)}\n`);
console.log(`${failed.length === 0 ? "PASS" : "FAIL"}: ${checks.length - failed.length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failed.length === 0 ? 0 : 1;
