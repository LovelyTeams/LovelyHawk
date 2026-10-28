// Accessibility and layout of the connected app, in the Tauri window against a
// lab host: every page once connected, every tab of 主机全景 (the tables with
// row actions), and the terminal window. The audit is the one the desktop
// smoke runs (ui/scripts/accessibility-audit.mjs, proved to fail by
// ui/scripts/check-accessibility-audit.mjs): visible controls named, images
// with text alternatives, unique ids, a heading; plus no sideways scrolling of
// the page and no console errors.
//
// Read-only: pages are opened and read, nothing on the host is changed.
//
//   LAB=ubuntu node tools/lab/probe-ui-accessibility.mjs
//   LAB=ubuntu VIEWPORT=1080x700 node tools/lab/probe-ui-accessibility.mjs   # the window minimum
//   LAB=docker node tools/lab/probe-ui-accessibility.mjs   # also opens a container's shell window
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";

import { ACCESSIBILITY_AUDIT } from "../../ui/scripts/accessibility-audit.mjs";
import { startDesktop } from "./desktop.mjs";
import { ORCHESTRATION_PORTS, isLinuxLab, labTarget } from "./lab-target.mjs";
import { Sidecar, backendBinary, connect } from "./rpc-harness.mjs";

const lab = process.env.LAB ?? "ubuntu";
// The nine distributions, or the Docker host, whose containers give the
// container window something to open.
if (!isLinuxLab(lab) && lab !== "docker") throw new Error(`Unknown LAB ${lab}`);
if (lab === "docker" && !Object.hasOwn(ORCHESTRATION_PORTS, "docker")) throw new Error("No Docker lab host");
const viewport = /^(\d{3,4})x(\d{3,4})$/u.exec(process.env.VIEWPORT ?? "1280x800");
if (viewport === null) throw new Error("VIEWPORT is <width>x<height>, e.g. 1080x700");
const [width, height] = [Number(viewport[1]), Number(viewport[2])];
if (width < 1080 || height < 700) throw new Error("The window cannot be smaller than 1080x700");
const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID();
const evidence = path.join(repository, "target", "lab-ui-accessibility", lab, `${width}x${height}`, runId);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-ui-a11y-"));
const connectionName = `无障碍巡检 ${lab}`;
const checks = [];
let failures = 0;
let app = null;
const consoleErrors = [];
fs.mkdirSync(evidence, { recursive: true });

/**
 * check(label, ok, detail) with a boolean, or check(label, actual, expected)
 * compared exactly. A non-boolean with nothing to compare against fails.
 */
function check(label, ok, ...rest) {
  const comparing = typeof ok !== "boolean";
  const detail = rest.length > 0 ? rest[0] : null;
  const passed = comparing ? rest.length > 0 && ok === detail : ok;
  const shown = comparing ? { actual: ok, expected: rest.length > 0 ? detail : "(nothing to compare with)" } : detail;
  checks.push({ label, passed, detail: shown });
  if (!passed) failures += 1;
  console.log(`${passed ? "PASS" : "FAIL"} ${label}${passed || shown === null ? "" : ` — ${JSON.stringify(shown).slice(0, 500)}`}`);
}
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function until(predicate, label, timeoutMs = 60_000) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    try { if (await predicate()) return true; } catch { /* page still changing */ }
    await sleep(300);
  }
  throw new Error(`Timed out: ${label}`);
}
const fileName = (text) => text.replace(/[^\p{L}\p{N}-]+/gu, "_");
/** The title bar's own minimise / maximise / close look the same in every window: flat, no box. */
const FLAT_WINDOW_CONTROLS = `(() => {
  const buttons = [...document.querySelectorAll('.window-controls button')];
  return buttons.length === 3 && buttons.every((button) => {
    const style = getComputedStyle(button);
    return style.borderTopWidth === "0px" && style.borderRadius === "0px";
  });
})()`;

/** Waits for the page to stop loading, then audits what is on it. */
async function auditPage(session, label, { heading = true } = {}) {
  await until(() => session.evaluate(`document.querySelector('.content-page-loading') === null &&
    ![...document.querySelectorAll('main.content [role="status"]')].some((n) => /正在|读取中|采集/u.test(n.textContent))`),
  `${label} to finish loading`, 45_000).catch(() => null);
  await sleep(600);
  const audit = await session.evaluate(ACCESSIBILITY_AUDIT);
  check(`${label}: every visible control has a name`, audit.unnamed.length === 0,
    audit.unnamed.length === 0 ? `${audit.controls} controls` : audit.unnamed);
  check(`${label}: every image has a text alternative`, audit.imagesWithoutAlt.length === 0, audit.imagesWithoutAlt);
  check(`${label}: ids are unique`, audit.duplicateIds.length === 0, audit.duplicateIds);
  if (heading) check(`${label}: has a heading`, audit.heading);
  const overflow = await session.evaluate(`(() => {
    const main = document.querySelector("main.content");
    return main === null ? null : { client: main.clientWidth, scroll: main.scrollWidth };
  })()`);
  if (overflow !== null) check(`${label}: does not scroll sideways`, overflow.scroll <= overflow.client, overflow);
  // Pages built to fill the window scroll inside their own lists and tables.
  // The page itself scrolling means one of them grew past the window again,
  // which is how the last rows ended up under the status bar.
  const filling = await session.evaluate(`(() => {
    const main = document.querySelector("main.content");
    if (main === null || main.querySelector(${JSON.stringify(FILLING_PAGES)}) === null) return null;
    return { client: main.clientHeight, scroll: main.scrollHeight };
  })()`);
  if (filling !== null) {
    check(`${label}: fills the window without scrolling the page`, filling.scroll <= filling.client + 1, filling);
  }
}

/** The pages laid out to fill the window rather than grow with their content. */
const FILLING_PAGES = ".system-info-page, .notes-page, .ai-history-page";

try {
  const sidecar = new Sidecar(backendBinary(), dataRoot);
  try {
    const status = await connect(sidecar, { ...labTarget(lab), name: connectionName });
    if (status?.stage !== "connected") throw new Error(`lab connect failed: ${JSON.stringify(status)}`);
    await sidecar.call("ssh.binding.disconnect", { bindingHandle: status.bindingHandle });
  } finally { sidecar.close(); }

  app = await startDesktop({ dataRoot, evidence,
    onConsoleError: (event) => consoleErrors.push(JSON.stringify(event.params ?? event).slice(0, 600)) });
  const page = app.session;
  await app.setViewport(width, height);
  await until(() => page.evaluate(`[...document.querySelectorAll('.connection-card')].some((card) => card.textContent.includes(${JSON.stringify(connectionName)}))`), "the connection card");
  await page.evaluate(`(() => { const card = [...document.querySelectorAll('.connection-card')].find((c) => c.textContent.includes(${JSON.stringify(connectionName)})); (card.querySelector('button') ?? card).click(); return true; })()`);
  await until(() => page.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]') !== null"), "the connection", 90_000);

  check("main window: title bar controls are flat", await page.evaluate(FLAT_WINDOW_CONTROLS));
  const pages = await page.evaluate("[...document.querySelectorAll('.nav-item')].map((n) => n.textContent.trim())");
  check("the connected app lists its pages", pages.length >= 15, pages);
  for (const [index, label] of pages.entries()) {
    await page.evaluate(`document.querySelectorAll('.nav-item')[${index}].click(), true`);
    await until(() => page.evaluate(`document.querySelectorAll('.nav-item')[${index}].classList.contains('active')`), `page ${label}`);
    await auditPage(page, label);
    await page.shot(`page-${String(index + 1).padStart(2, "0")}-${fileName(label)}.png`);

    // 主机全景: each tab is a table with its own row actions.
    if (index === 0) {
      const tabs = await page.evaluate("[...document.querySelectorAll('.system-info-tabs button')].map((b) => b.textContent.trim())");
      check("主机全景 lists its tabs", tabs.length >= 20, tabs.length);
      for (const [tabIndex, tab] of tabs.entries()) {
        await page.evaluate(`document.querySelectorAll('.system-info-tabs button')[${tabIndex}].click(), true`);
        await until(() => page.evaluate(`document.querySelectorAll('.system-info-tabs button')[${tabIndex}].getAttribute('aria-pressed') === 'true'`), `tab ${tab}`);
        await until(() => page.evaluate("!document.querySelector('.system-info-table-state')?.textContent.includes('正在采集')"), `tab ${tab} to load`, 60_000).catch(() => null);
        await auditPage(page, `主机全景 · ${tab}`, { heading: false });
      }
      await page.shot("system-info-last-tab.png");
    }
  }

  // The terminal window, opened from the sidebar.
  await page.evaluate("document.querySelector('[data-testid=\"sidebar-open-terminal\"]').click(), true");
  const terminal = await app.attachChild("terminal", { timeoutMs: 45_000 });
  await until(() => terminal.evaluate("document.querySelector('.xterm') !== null"), "the terminal", 45_000);
  await sleep(1_500);
  const terminalAudit = await terminal.evaluate(ACCESSIBILITY_AUDIT);
  check("terminal window: every visible control has a name", terminalAudit.unnamed.length === 0,
    terminalAudit.unnamed.length === 0 ? `${terminalAudit.controls} controls` : terminalAudit.unnamed);
  check("terminal window: ids are unique", terminalAudit.duplicateIds.length === 0, terminalAudit.duplicateIds);
  check("terminal window: title bar controls look like the main window's", await terminal.evaluate(FLAT_WINDOW_CONTROLS));
  await terminal.shot("terminal-window.png");

  // The file editor, opened on /etc/hostname from the terminal window's file
  // pane and closed again unchanged. Its context menu is audited on the way.
  const row = (name) => `[...document.querySelectorAll('section[aria-label="远程文件"] .sftp-browser-row')].find((candidate) => candidate.querySelector('.sftp-browser-row-label')?.textContent === ${JSON.stringify(name)})`;
  // A double click on a listing that is still settling can be lost, so it is
  // repeated until /etc is actually open (its hostname row is there).
  await until(async () => {
    if (await terminal.evaluate(`${row("hostname")} !== undefined`)) return true;
    await terminal.evaluate(`(() => { const candidate = ${row("etc")}; if (candidate && !candidate.disabled) candidate.dispatchEvent(new MouseEvent('dblclick', { bubbles: true })); return true; })()`);
    await sleep(1_500);
    return terminal.evaluate(`${row("hostname")} !== undefined`);
  }, "the etc directory", 60_000);
  await until(() => terminal.evaluate(`(() => {
    const candidate = ${row("hostname")};
    if (!candidate) return false;
    const box = candidate.getBoundingClientRect();
    candidate.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, cancelable: true, clientX: box.left + 20, clientY: box.top + 5 }));
    return document.querySelector('[role="menu"]') !== null;
  })()`), "the file's menu", 45_000);
  const menuAudit = await terminal.evaluate(ACCESSIBILITY_AUDIT);
  check("file menu: every item has a name", menuAudit.unnamed.length === 0,
    menuAudit.unnamed.length === 0 ? `${menuAudit.controls} controls` : menuAudit.unnamed);
  await terminal.evaluate("[...document.querySelectorAll('[role=\"menuitem\"]')].find((entry) => entry.textContent.includes('编辑文本')).click(), true");
  const editor = await app.attachChild("file-editor", { timeoutMs: 45_000 });
  await until(() => editor.evaluate("(document.querySelector('.file-editor-text')?.value ?? '').length > 0"), "the file text", 45_000);
  const editorAudit = await editor.evaluate(ACCESSIBILITY_AUDIT);
  check("file editor window: every visible control has a name", editorAudit.unnamed.length === 0,
    editorAudit.unnamed.length === 0 ? `${editorAudit.controls} controls` : editorAudit.unnamed);
  check("file editor window: ids are unique", editorAudit.duplicateIds.length === 0, editorAudit.duplicateIds);
  check("file editor window: title bar controls look like the main window's", await editor.evaluate(FLAT_WINDOW_CONTROLS));
  check("file editor window: the text area has a name",
    await editor.evaluate("(() => { const area = document.querySelector('.file-editor-text'); return (area.getAttribute('aria-label') ?? '').trim().length > 0 || (area.labels?.length ?? 0) > 0; })()"));
  await editor.shot("file-editor-window.png");
  // Unchanged, so it closes without asking; the CDP session goes with it.
  await editor.evaluate("window.lovelyhawkWindow.close().then(() => true, () => true)").catch(() => true);

  // A container's shell window, from the Docker page: opened, audited and
  // closed with nothing typed into it.
  if (lab === "docker") {
    await page.evaluate("[...document.querySelectorAll('.nav-item')].find((n) => n.textContent.trim() === 'Docker').click(), true");
    await until(() => page.evaluate("[...document.querySelectorAll('[data-testid=\"docker-open-terminal\"]')].some((b) => !b.disabled)"), "a container with a shell", 90_000);
    await page.evaluate("[...document.querySelectorAll('[data-testid=\"docker-open-terminal\"]')].find((b) => !b.disabled).click(), true");
    const container = await app.attachChild("container", { timeoutMs: 45_000 });
    await until(() => container.evaluate("(document.querySelector('.xterm-rows')?.textContent ?? '').trim().length > 0"), "the container shell", 60_000);
    const containerAudit = await container.evaluate(ACCESSIBILITY_AUDIT);
    check("container window: every visible control has a name", containerAudit.unnamed.length === 0,
      containerAudit.unnamed.length === 0 ? `${containerAudit.controls} controls` : containerAudit.unnamed);
    check("container window: ids are unique", containerAudit.duplicateIds.length === 0, containerAudit.duplicateIds);
    check("container window: title bar controls look like the main window's", await container.evaluate(FLAT_WINDOW_CONTROLS));
    await container.shot("container-window.png");
    await container.evaluate("window.lovelyhawkWindow.close().then(() => true, () => true)").catch(() => true);
  }

  check("no console errors", consoleErrors.length === 0, consoleErrors.slice(0, 3));
} catch (error) {
  failures += 1;
  console.log(`FAILED: ${error instanceof Error ? error.message : String(error)}`);
  try { await app?.session?.shot("failure.png"); } catch { /* keep going */ }
} finally {
  try { await app?.close(); } catch { /* keep going */ }
  fs.rmSync(dataRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 });
}
fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify({
  schema: "lovelyhawk-ui-accessibility-probe/v1", lab, runId, viewport: { width, height },
  status: failures === 0 ? "PASS" : "FAIL", generatedAt: new Date().toISOString(), checks, consoleErrors,
}, null, 2)}\n`);
console.log(`${failures === 0 ? "PASS" : "FAIL"}: ${checks.filter((item) => item.passed).length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failures === 0 ? 0 : 1;
