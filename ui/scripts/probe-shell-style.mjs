// The restyled shell in the real window: welcome, the grouped sidebar with its
// filter, the palette chooser (a light and a dark palette applied and saved),
// and the icon rail. Isolated data root; no network, no target.
//   node scripts/probe-shell-style.mjs

import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { attach, delay, launchDesktop, waitFor } from "./cdp.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const executable = path.join(repositoryRoot, "target", "debug", process.platform === "win32" ? "lovelyhawk.exe" : "lovelyhawk");
const runRoot = path.join(repositoryRoot, "target", "desktop-debug", `shell-style-${randomUUID()}`);
const evidence = path.join(runRoot, "evidence");
const checks = [];
function check(name, ok, detail = null) {
  checks.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail === null ? "" : ` — ${JSON.stringify(detail)}`}`);
}
fs.mkdirSync(evidence, { recursive: true });
const port = 11_400 + Math.floor(Math.random() * 80);
const { child, output } = launchDesktop({ executable, archiveRoot: runRoot, port });
let exitCode = null;
child.once("exit", (code) => { exitCode = code; });
const errors = [];
try {
  const { session } = await attach(port, (url) => /^https?:\/\/tauri\.localhost\/(index\.html)?$/u.test(url));
  session.onEvent((method, params) => {
    if (method === "Runtime.exceptionThrown" || (method === "Runtime.consoleAPICalled" && params?.type === "error") ||
      (method === "Log.entryAdded" && params?.entry?.level === "error")) errors.push(JSON.stringify(params).slice(0, 1_500));
  });
  await session.send("Runtime.enable");
  await session.send("Log.enable");
  await waitFor(() => session.evaluate("document.querySelector('[data-testid=\"welcome-view\"]') !== null"), { label: "the welcome view" });
  await delay(500);
  await session.screenshot(path.join(evidence, "01-welcome.png"));

  await session.evaluate("[...document.querySelectorAll('.welcome-tool')][0]?.click(), true");
  await waitFor(() => session.evaluate("document.querySelector('.sidebar-search input') !== null"), { label: "the sidebar" });
  await delay(400);
  const nav = await session.evaluate("({ groups: document.querySelectorAll('.nav-group-row').length, items: document.querySelectorAll('nav .nav-item').length })");
  check("the sidebar shows grouped pages", nav.groups >= 4 && nav.items >= 15, nav);
  await session.screenshot(path.join(evidence, "02-sidebar.png"));

  await session.send("Input.dispatchKeyEvent", { type: "keyDown", key: "/", code: "Slash", text: "/" });
  await session.send("Input.dispatchKeyEvent", { type: "keyUp", key: "/", code: "Slash" });
  const focused = await session.evaluate("document.activeElement?.dataset.testid ?? null");
  check("/ focuses the page filter", focused === "sidebar-filter", focused);
  await session.send("Input.insertText", { text: "Docker" });
  await delay(250);
  const filtered = await session.evaluate("[...document.querySelectorAll('nav .nav-item')].map((item) => item.textContent.trim())");
  check("the filter narrows the list", filtered.length === 1 && filtered[0] === "Docker", filtered);
  await session.screenshot(path.join(evidence, "03-filter.png"));
  await session.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
  await session.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
  await delay(200);
  check("Escape clears the filter", (await session.evaluate("document.querySelectorAll('nav .nav-item').length")) === nav.items);

  await session.evaluate("document.querySelector('.nav-group-row')?.click(), true");
  await delay(400);
  const folded = await session.evaluate("document.querySelector('.nav-group-row')?.getAttribute('aria-expanded')");
  check("a group folds on its header", folded === "false", folded);
  await session.evaluate("document.querySelector('.nav-group-row')?.click(), true");

  for (const id of ["tingwu", "shenhai"]) {
    await session.evaluate("document.querySelector('[data-testid=\"open-theme-picker\"]').click(), true");
    await waitFor(() => session.evaluate("document.querySelector('.theme-picker-panel') !== null"), { label: "the palette chooser" });
    await delay(300);
    if (id === "tingwu") await session.screenshot(path.join(evidence, "04-theme-picker.png"));
    await session.evaluate(`document.querySelector('[data-testid="theme-card-${id}"]').click(), true`);
    await delay(700);
    const applied = await session.evaluate("document.documentElement.dataset.theme");
    const saved = (await session.evaluate("window.lovelyhawk.loadSettings().then((s) => s.theme)"));
    check(`palette ${id} is applied and saved`, applied === id && saved === id, { applied, saved });
    await session.screenshot(path.join(evidence, `05-theme-${id}.png`));
  }

  await session.evaluate("document.querySelector('[data-testid=\"sidebar-rail-toggle\"]').click(), true");
  await delay(400);
  const rail = await session.evaluate("({ width: document.querySelector('.sidebar').getBoundingClientRect().width, named: [...document.querySelectorAll('nav .nav-item')].every((item) => (item.getAttribute('aria-label') ?? '').length > 0) })");
  check("the rail is narrow and every icon is named", rail.width <= 64 && rail.named, rail);
  await session.screenshot(path.join(evidence, "06-rail.png"));

  check("no console errors", errors.length === 0, errors.slice(0, 3));
  await session.evaluate("document.querySelector('[data-testid=\"window-close\"]').click(), true");
  await waitFor(() => exitCode !== null, { timeoutMs: 15_000, label: "exit" }).catch(() => undefined);
  check("the app exits cleanly", exitCode === 0, exitCode);
} catch (error) {
  check("completed", false, error instanceof Error ? error.message : String(error));
  console.error(output.join("").slice(-3_000));
} finally {
  if (exitCode === null) child.kill();
}
const failed = checks.filter((entry) => !entry.ok);
console.log(`${failed.length === 0 ? "PASS" : "FAIL"}: ${checks.length - failed.length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failed.length === 0 ? 0 : 1;
