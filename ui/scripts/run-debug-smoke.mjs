// Desktop debug smoke: drives the real debug build over WebView2's CDP
// endpoint with an isolated data root, visits every page and overlay of the
// disconnected app, saves screenshots, and fails on console errors, a missing
// page, an unexpected API surface or an unclean exit.
//
//   node scripts/run-debug-smoke.mjs [--theme dark] [--width 1280 --height 800]

import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { ACCESSIBILITY_AUDIT } from "./accessibility-audit.mjs";
import { attach, delay, launchDesktop, waitFor } from "./cdp.mjs";

const uiRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = path.resolve(uiRoot, "..");
// Like the lab probes, another debug build may be named — for example one
// built into a separate target directory while the usual one is open and
// locked. It must still be a debug build: only those honour the test hooks.
const executable = process.env.LOVELYHAWK_DESKTOP_BIN ??
  path.join(repositoryRoot, "target", "debug", process.platform === "win32" ? "lovelyhawk.exe" : "lovelyhawk");
const runId = randomUUID();
const runRoot = path.join(repositoryRoot, "target", "desktop-debug", runId);
const evidence = path.join(runRoot, "evidence");
const argument = (name, fallback) => {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] ?? fallback : fallback;
};
const theme = argument("theme", null);
const viewport = { width: Number(argument("width", "0")), height: Number(argument("height", "0")) };
const port = 9300 + Math.floor(Math.random() * 500);
const smokeNonce = randomUUID().replaceAll("-", "");
const smokeRoot = path.join(os.tmpdir(), `lovelyhawk-smoke-${smokeNonce}`);

const EXPECTED_API_METHODS = 165;
const EXPECTED_PAGES = 15;
const checks = [];
function check(name, ok, detail = null) {
  checks.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail === null ? "" : ` — ${typeof detail === "string" ? detail : JSON.stringify(detail)}`}`);
}

fs.mkdirSync(evidence, { recursive: true });
fs.mkdirSync(smokeRoot, { recursive: false });
const { child, output } = launchDesktop({
  executable,
  archiveRoot: runRoot,
  port,
  extraEnv: { LOVELYHAWK_SMOKE_READY_ROOT: smokeRoot, LOVELYHAWK_SMOKE_READY_NONCE: smokeNonce },
});
let exitCode = null;
child.once("exit", (code) => { exitCode = code; });

const consoleErrors = [];
// A request the page made that failed or came back as an error. Everything is
// local, so any of these is a missing asset or a broken route, not the network.
const networkErrors = [];
let session;
try {
  ({ session } = await attach(port, (url) => /^https?:\/\/tauri\.localhost\/(index\.html)?$/u.test(url)));
  session.onEvent((method, params) => {
    if (method === "Runtime.exceptionThrown" ||
      (method === "Runtime.consoleAPICalled" && params?.type === "error") ||
      (method === "Log.entryAdded" && params?.entry?.level === "error")) {
      consoleErrors.push(JSON.stringify(params).slice(0, 2_000));
    }
    if (method === "Network.loadingFailed" && params?.canceled !== true) {
      networkErrors.push(`${params?.type ?? "request"} failed: ${params?.errorText ?? ""}`.slice(0, 400));
    }
    if (method === "Network.responseReceived" && (params?.response?.status ?? 0) >= 400) {
      networkErrors.push(`${params.response.status} ${params.response.url}`.slice(0, 400));
    }
  });
  await session.send("Runtime.enable");
  await session.send("Log.enable");
  await session.send("Page.enable");
  await session.send("Network.enable");
  if (viewport.width > 0 && viewport.height > 0) {
    await session.send("Emulation.setDeviceMetricsOverride", { ...viewport, deviceScaleFactor: 1, mobile: false });
  }
  await waitFor(() => session.evaluate("document.querySelector('[data-testid=\"welcome-view\"]') !== null"),
    { label: "the welcome view" });

  const shell = await session.evaluate(`(() => ({
    href: location.href,
    title: document.title,
    apiMethods: Object.keys(window.lovelyhawk).length,
    apiFrozen: Object.isFrozen(window.lovelyhawk),
    apiWritable: Object.getOwnPropertyDescriptor(window, "lovelyhawk")?.writable ?? null,
    terminalApi: typeof window.lovelyhawkTerminal,
    node: typeof window.process + "/" + typeof window.require,
    globalTauri: typeof window.__TAURI__,
    csp: document.querySelector('meta[http-equiv="Content-Security-Policy"]')?.content ?? "",
    inlineHandlers: document.querySelectorAll('[onclick],[onerror],[onload]').length,
    resources: performance.getEntriesByType("resource").map((entry) => entry.name),
    navItems: [...document.querySelectorAll(".nav-item")].map((item) => item.textContent.trim()),
    controls: [...document.querySelectorAll('[data-testid="window-controls"] button')].map((b) => b.dataset.testid),
    dragRegion: document.querySelector('[data-testid="window-titlebar"]')?.getAttribute("data-tauri-drag-region"),
  }))()`);
  check("main page is the embedded app origin", /^https:\/\/tauri\.localhost\/(index\.html)?$/u.test(shell.href), shell.href);
  check("window title", shell.title === "LovelyHawk", shell.title);
  check("host API is frozen, read-only and complete", shell.apiFrozen && shell.apiWritable === false && shell.apiMethods === EXPECTED_API_METHODS, shell.apiMethods);
  check("main window has no terminal API, Node or global Tauri", shell.terminalApi === "undefined" && shell.node === "undefined/undefined" && shell.globalTauri === "undefined");
  check("page CSP forbids inline script and remote content", shell.csp.includes("script-src 'self'") && !/unsafe-eval|https?:\/\/(?!ipc\.localhost)/u.test(shell.csp));
  check("no inline event handlers", shell.inlineHandlers === 0);
  check("every resource is local", shell.resources.every((url) => /^https:\/\/tauri\.localhost\/|^http:\/\/ipc\.localhost\/|^https:\/\/ipc\.localhost\/|^ipc:/u.test(url)), shell.resources.filter((url) => !url.includes("localhost")));
  check(`navigation lists ${EXPECTED_PAGES} pages`, shell.navItems.length === EXPECTED_PAGES, shell.navItems);
  check("frameless window draws its own controls", shell.controls.join(",") === "window-minimize,window-maximize,window-close" && shell.dragRegion === "deep");
  const marker = path.join(smokeRoot, `ready-${smokeNonce}.json`);
  await waitFor(() => fs.existsSync(marker), { timeoutMs: 10_000, label: "the readiness marker" }).catch(() => undefined);
  check("readiness marker written after first render", fs.existsSync(marker));

  if (theme !== null) {
    await session.evaluate(`document.documentElement.dataset.theme = ${JSON.stringify(theme)}, true`);
  }
  await session.screenshot(path.join(evidence, "00-welcome.png"));

  // The keyboard reaches the app: Tab lands on a named control that shows it
  // has the focus.
  await session.evaluate("document.activeElement?.blur?.(), true");
  await session.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Tab", code: "Tab", windowsVirtualKeyCode: 9 });
  await session.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Tab", code: "Tab", windowsVirtualKeyCode: 9 });
  const focused = await session.evaluate(`(() => {
    const element = document.activeElement;
    if (element === null || element === document.body) return null;
    const style = getComputedStyle(element);
    const ring = (style.outlineStyle !== "none" && parseFloat(style.outlineWidth) > 0) || style.boxShadow !== "none";
    return { tag: element.tagName, name: (element.getAttribute("aria-label") ?? element.textContent ?? "").trim().slice(0, 40), ring };
  })()`);
  check("Tab moves the focus into the app", focused !== null && focused.name.length > 0, focused);
  check("the focused control shows a focus ring", focused?.ring === true, focused);

  // Every page, in navigation order.
  for (let index = 0; index < shell.navItems.length; index += 1) {
    const label = shell.navItems[index];
    await session.evaluate(`document.querySelectorAll(".nav-item")[${index}].click(), true`);
    const rendered = await waitFor(() => session.evaluate(`(() => {
      const item = document.querySelectorAll(".nav-item")[${index}];
      const loading = document.querySelector(".content-page-loading");
      const content = document.querySelector("main.content");
      return item?.classList.contains("active") && loading === null && (content?.textContent?.trim().length ?? 0) > 0
        // No slack: a single pixel over is enough for the window to draw a
        // scroll bar under the whole page.
        ? { text: content.textContent.trim().slice(0, 80), overflowX: content.scrollWidth > content.clientWidth } : null;
    })()`), { timeoutMs: 15_000, label: `page ${label}` }).catch(() => null);
    check(`page "${label}" renders`, rendered !== null, rendered?.text ?? null);
    if (rendered?.overflowX) check(`page "${label}" fits the window width`, false);
    await delay(250);
    const audit = await session.evaluate(ACCESSIBILITY_AUDIT);
    check(`page "${label}" names every visible control`, audit.unnamed.length === 0,
      audit.unnamed.length === 0 ? `${audit.controls} controls` : audit.unnamed);
    if (audit.imagesWithoutAlt.length > 0) check(`page "${label}" gives every image a text alternative`, false, audit.imagesWithoutAlt);
    if (audit.duplicateIds.length > 0) check(`page "${label}" has unique ids`, false, audit.duplicateIds);
    check(`page "${label}" has a heading`, audit.heading);
    await session.screenshot(path.join(evidence, `${String(index + 1).padStart(2, "0")}-${label.replace(/[^\p{L}\p{N}-]+/gu, "_")}.png`));
  }

  // Overlays reachable from the title bar and status bar.
  for (const [testid, name] of [
    ["open-connections", "connections"],
    ["open-settings", "settings"],
    ["open-command-history", "command-history"],
    ["open-application-log", "application-log"],
    ["open-disposal-report", "disposal-report"],
  ]) {
    // With the status bar hidden, its entries live at the foot of the sidebar.
    const clicked = await session.evaluate(`(() => {
      const button = document.querySelector('[data-testid="${testid}"]') ?? document.querySelector('[data-testid="sidebar-${testid}"]');
      button?.focus();
      button?.click();
      window.__smokeOpener = button;
      return button !== null;
    })()`);
    check(`${name} entry is reachable`, clicked);
    const open = await waitFor(() => session.evaluate(`document.querySelector('[role="dialog"]') !== null`),
      { timeoutMs: 8_000, label: `${name} overlay` }).catch(() => false);
    check(`${name} overlay opens as a dialog`, open);
    await delay(300);
    const dialog = await session.evaluate(`(() => {
      const dialog = document.querySelector('[role="dialog"]');
      if (dialog === null) return null;
      const labelled = dialog.getAttribute("aria-labelledby");
      return {
        named: (dialog.getAttribute("aria-label") ?? "").trim().length > 0 ||
          (labelled !== null && (document.getElementById(labelled)?.textContent ?? "").trim().length > 0),
        focusInside: dialog.contains(document.activeElement),
      };
    })()`);
    check(`${name} overlay has a name`, dialog?.named === true, dialog);
    check(`${name} overlay takes the focus`, dialog?.focusInside === true, dialog);
    const overlayAudit = await session.evaluate(ACCESSIBILITY_AUDIT);
    check(`${name} overlay names every visible control`, overlayAudit.unnamed.length === 0,
      overlayAudit.unnamed.length === 0 ? `${overlayAudit.controls} controls` : overlayAudit.unnamed);
    await session.screenshot(path.join(evidence, `overlay-${name}.png`));
    await session.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
    await session.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
    const closed = await waitFor(() => session.evaluate(`document.querySelector('[role="dialog"]') === null`),
      { timeoutMs: 8_000, label: `${name} overlay to close` }).catch(() => false);
    check(`${name} overlay closes with Escape`, closed);
    // Focus goes back where it came from, so the keyboard user is not dropped
    // at the top of the window.
    const returned = await waitFor(() => session.evaluate("document.activeElement === window.__smokeOpener"),
      { timeoutMs: 3_000, label: `${name} focus return` }).catch(() => false);
    check(`${name} overlay returns the focus to its button`, returned);
  }

  check("no console errors", consoleErrors.length === 0, consoleErrors.slice(0, 5));
  check("no failed or error responses", networkErrors.length === 0, networkErrors.slice(0, 5));
  await session.evaluate("document.querySelector('[data-testid=\"window-close\"]').click(), true");
  session.close();
  await waitFor(() => exitCode !== null, { timeoutMs: 15_000, label: "the app to exit" }).catch(() => undefined);
  check("closing the window exits cleanly", exitCode === 0, exitCode);
} catch (error) {
  check("smoke completed", false, error instanceof Error ? error.message : String(error));
} finally {
  if (exitCode === null) child.kill();
  try { fs.rmSync(smokeRoot, { recursive: true, force: true }); } catch { /* keep going */ }
}

const failed = checks.filter((entry) => !entry.ok);
const report = {
  schema: "lovelyhawk-desktop-debug/v1",
  status: failed.length === 0 ? "PASS" : "FAIL",
  generatedAt: new Date().toISOString(),
  checks,
  consoleErrors,
  networkErrors,
  log: failed.length === 0 ? undefined : output.join("").slice(-6_000),
};
fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify(report, null, 2)}\n`);
console.log(`${report.status}: ${checks.length - failed.length}/${checks.length} checks; evidence in ${evidence}`);
process.exitCode = failed.length === 0 ? 0 : 1;
