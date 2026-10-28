// Accessibility and resource audit of every page and overlay in the real
// window, using the browser's own accessibility tree (CDP Accessibility
// domain): every interactive element must have a name a screen reader can
// say, and a name made only of symbols ("×", "↻", "⌕") does not count. Icons
// must be inline SVG or local images, and nothing may load from outside the
// application. Runs disconnected against a throwaway data root.

import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { attach, delay, launchDesktop, waitFor } from "./cdp.mjs";

// With LAB=<name> the pages are audited a second time connected to that lab
// host, where tables, row actions and live panels exist.
const lab = process.env.LAB ?? null;

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const executable = path.join(repositoryRoot, "target", "debug", process.platform === "win32" ? "lovelyhawk.exe" : "lovelyhawk");
const runRoot = path.join(repositoryRoot, "target", "desktop-debug", `accessibility-${randomUUID()}`);
const evidence = path.join(runRoot, "evidence");
const checks = [];
function check(name, ok, detail = null) {
  checks.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail === null ? "" : ` — ${JSON.stringify(detail).slice(0, 600)}`}`);
}
fs.mkdirSync(evidence, { recursive: true });

const INTERACTIVE = new Set(["button", "link", "textbox", "searchbox", "combobox", "checkbox", "radio", "switch", "menuitem",
  "menuitemcheckbox", "menuitemradio", "tab", "slider", "spinbutton", "listbox", "option", "treeitem"]);
const meaningful = (name) => /[\p{L}\p{N}]/u.test(name);

async function audit(session, scope) {
  const { nodes } = await session.send("Accessibility.getFullAXTree", {}, 30_000);
  const problems = [];
  let interactive = 0;
  for (const node of nodes) {
    if (node.ignored) continue;
    const role = node.role?.value;
    if (!INTERACTIVE.has(role)) continue;
    const disabled = (node.properties ?? []).some((property) => property.name === "disabled" && property.value?.value === true);
    const hidden = (node.properties ?? []).some((property) => property.name === "hidden" && property.value?.value === true);
    if (hidden) continue;
    interactive += 1;
    const name = String(node.name?.value ?? "").trim();
    if (!meaningful(name)) problems.push({ role, name, disabled, backendDOMNodeId: node.backendDOMNodeId });
  }
  // Describe each problem by its DOM element so the fix is easy to find.
  for (const problem of problems.slice(0, 25)) {
    try {
      const { object } = await session.send("DOM.resolveNode", { backendNodeId: problem.backendDOMNodeId });
      const { result } = await session.send("Runtime.callFunctionOn", {
        objectId: object.objectId,
        functionDeclaration: "function () { const id = this.id ? '#' + this.id : ''; const cls = typeof this.className === 'string' && this.className ? '.' + this.className.trim().split(/\\s+/).join('.') : ''; return this.tagName.toLowerCase() + id + cls + ' «' + (this.outerHTML || '').slice(0, 160) + '»'; }",
        returnByValue: true,
      });
      problem.element = result.value;
    } catch { /* the node went away */ }
    delete problem.backendDOMNodeId;
  }
  const resources = await session.evaluate(`(() => {
    const external = [];
    for (const image of document.querySelectorAll('img')) if (!/^(https?:\\/\\/(tauri|ipc)\\.localhost\\/|data:|tauri:|blob:)/u.test(image.currentSrc || image.src)) external.push('img ' + (image.currentSrc || image.src));
    for (const use of document.querySelectorAll('svg use, svg image')) { const href = use.getAttribute('href') || use.getAttribute('xlink:href') || ''; if (/^(https?:)?\\/\\//u.test(href)) external.push('svg ' + href); }
    for (const entry of performance.getEntriesByType('resource')) if (!/^(https?:\\/\\/(tauri|ipc)\\.localhost\\/|ipc:|data:|tauri:)/u.test(entry.name)) external.push('load ' + entry.name);
    return external;
  })()`);
  return { scope, interactive, problems, resources };
}

if (lab !== null) {
  // Record the lab connection and accept its host key in this data root first.
  const { labTarget } = await import("../../tools/lab/lab-target.mjs");
  const { Sidecar, backendBinary, connect } = await import("../../tools/lab/rpc-harness.mjs");
  const sidecar = new Sidecar(backendBinary(), runRoot);
  try {
    const status = await connect(sidecar, { ...labTarget(lab), name: `实验室 ${lab}` });
    if (status?.stage !== "connected") throw new Error(`lab connect failed: ${JSON.stringify(status)}`);
    await sidecar.call("ssh.binding.disconnect", { bindingHandle: status.bindingHandle });
  } finally {
    sidecar.close();
  }
  await delay(500);
}

const port = 11_100 + Math.floor(Math.random() * 80);
const { child, output } = launchDesktop({ executable, archiveRoot: runRoot, port });
let exitCode = null;
child.once("exit", (code) => { exitCode = code; });
const errors = [];
const results = [];
try {
  const { session } = await attach(port, (url) => /^https?:\/\/tauri\.localhost\/(index\.html)?$/u.test(url));
  session.onEvent((method, params) => {
    if (method === "Runtime.exceptionThrown" || (method === "Runtime.consoleAPICalled" && params?.type === "error")) {
      errors.push(JSON.stringify(params).slice(0, 1_500));
    }
  });
  await session.send("Runtime.enable");
  await session.send("DOM.enable");
  await session.send("Accessibility.enable");
  await waitFor(() => session.evaluate("document.querySelectorAll('.nav-item').length >= 15"), { label: "the navigation" });
  results.push(await audit(session, "欢迎页"));

  const pages = await session.evaluate("[...document.querySelectorAll('.nav-item')].map((item) => item.textContent.trim())");
  for (const [index, title] of pages.entries()) {
    await session.evaluate(`document.querySelectorAll('.nav-item')[${index}].click(), true`);
    await delay(1_200);
    results.push(await audit(session, `页面 ${title}`));
  }

  for (const [label, opener] of [
    ["连接管理", "[data-testid=\"open-connections\"]"],
    ["设置", "[data-testid=\"open-settings\"]"],
    ["命令历史", "[data-testid=\"open-command-history\"]"],
    ["应用日志", "[data-testid=\"open-application-log\"], [data-testid=\"sidebar-open-application-log\"]"],
    ["处置报告", "[data-testid=\"open-disposal-report\"], [data-testid=\"sidebar-open-disposal-report\"]"],
  ]) {
    const opened = await session.evaluate(`(() => { const button = document.querySelector(${JSON.stringify(opener)}); if (!button) return false; button.click(); return true; })()`);
    if (!opened) { results.push({ scope: `浮层 ${label}`, interactive: 0, problems: [{ role: "opener", name: "not found" }], resources: [] }); continue; }
    await delay(1_200);
    results.push(await audit(session, `浮层 ${label}`));
    await session.screenshot(path.join(evidence, `overlay-${label}.png`));
    await session.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
    await session.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
    await delay(600);
  }

  if (lab !== null) {
    await session.evaluate("document.querySelector('[data-testid=\"sidebar-connect-target\"]')?.click(), true");
    await waitFor(() => session.evaluate("document.querySelector('.connection-list-row') !== null"), { timeoutMs: 15_000, label: "the saved connection" });
    await waitFor(() => session.evaluate(`(() => { const row = document.querySelector('.connection-list-row'); if (!row || row.disabled) return false; row.click(); return true; })()`), { timeoutMs: 10_000, label: "the row" });
    await waitFor(() => session.evaluate(`(() => { const button = [...document.querySelectorAll('.connection-detail button')].find((candidate) => candidate.textContent.trim() === '连接目标' && !candidate.disabled); if (!button) return false; button.click(); return true; })()`), { timeoutMs: 15_000, label: "连接目标" });
    await waitFor(() => session.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]') !== null && document.querySelector('.connection-manager-backdrop') === null"), { timeoutMs: 90_000, label: "the connected target" });
    for (const [index, title] of pages.entries()) {
      await session.evaluate(`document.querySelectorAll('.nav-item')[${index}].click(), true`);
      await delay(4_000);
      results.push(await audit(session, `已连接 ${lab}：${title}`));
    }
    await session.screenshot(path.join(evidence, "connected-last-page.png"));
    await session.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]')?.click(), true");
    await delay(1_000);
  }

  for (const result of results) {
    check(`${result.scope}: every one of ${result.interactive} controls has a meaningful name`, result.problems.length === 0, result.problems);
    check(`${result.scope}: nothing loads from outside the application`, result.resources.length === 0, result.resources);
  }
  check("no console errors", errors.length === 0, errors.slice(0, 3));
  await session.evaluate("document.querySelector('[data-testid=\"window-close\"]').click(), true");
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
  schema: "lovelyhawk-accessibility-probe/v1",
  status: failed.length === 0 ? "PASS" : "FAIL",
  generatedAt: new Date().toISOString(),
  checks,
}, null, 2)}\n`);
console.log(`${failed.length === 0 ? "PASS" : "FAIL"}: ${checks.length - failed.length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failed.length === 0 ? 0 : 1;
