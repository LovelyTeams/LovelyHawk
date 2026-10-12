// Launches the debug desktop build with an isolated data root, checks the
// first screen through CDP and saves screenshots. Usage:
//   node scripts/probe-launch.mjs [--keep-open] [--theme dark]

import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { attach, delay, launchDesktop, waitFor } from "./cdp.mjs";

const uiRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = path.resolve(uiRoot, "..");
const executable = path.join(repositoryRoot, "target", "debug", process.platform === "win32" ? "lovelyhawk.exe" : "lovelyhawk");
const runRoot = path.join(repositoryRoot, "target", "desktop-debug", randomUUID());
const evidence = path.join(runRoot, "evidence");
const port = 9300 + Math.floor(Math.random() * 500);
const keepOpen = process.argv.includes("--keep-open");

fs.mkdirSync(evidence, { recursive: true });
const { child, output } = launchDesktop({ executable, archiveRoot: runRoot, port });
let exitCode = null;
child.once("exit", (code) => { exitCode = code; });

try {
  const { session } = await attach(port, (url) => /^https?:\/\/tauri\.localhost\/(index\.html)?$/u.test(url));
  const consoleErrors = [];
  session.onEvent((method, params) => {
    if (method === "Runtime.exceptionThrown" ||
      (method === "Runtime.consoleAPICalled" && params?.type === "error") ||
      (method === "Log.entryAdded" && params?.entry?.level === "error")) {
      consoleErrors.push(JSON.stringify(params).slice(0, 2_000));
    }
  });
  await session.send("Runtime.enable");
  await session.send("Log.enable");
  await session.send("Page.enable");
  await waitFor(() => session.evaluate("document.querySelector('[data-testid=\"welcome-view\"]') !== null"),
    { label: "the welcome view" });
  const state = await session.evaluate(`(() => ({
    href: location.href,
    title: document.title,
    apiMethods: Object.keys(window.lovelyhawk ?? {}).length,
    apiFrozen: Object.isFrozen(window.lovelyhawk),
    terminalApi: typeof window.lovelyhawkTerminal,
    nodeGlobals: typeof window.process + "/" + typeof window.require,
    navItems: document.querySelectorAll('.nav-item').length,
    statusbar: document.querySelector('.window-statusbar') !== null,
    controls: [...document.querySelectorAll('[data-testid="window-controls"] button')].map((b) => b.dataset.testid),
    dragRegion: document.querySelector('[data-testid="window-titlebar"]')?.getAttribute('data-tauri-drag-region'),
    theme: document.documentElement.dataset.theme ?? null,
  }))()`);
  console.log(JSON.stringify(state, null, 2));
  const shot = await session.screenshot(path.join(evidence, "welcome.png"));
  console.log(`screenshot: ${shot}`);
  if (consoleErrors.length > 0) console.log(`console errors:\n${consoleErrors.join("\n")}`);
  if (keepOpen) {
    console.log("keeping the app open; press Ctrl+C to stop");
    await new Promise(() => undefined);
  }
  // Close through the window's own button so the close handshake runs.
  await session.evaluate("document.querySelector('[data-testid=\"window-close\"]').click(), true");
  session.close();
  await waitFor(() => exitCode !== null, { timeoutMs: 15_000, label: "the app to exit" });
  console.log(`exit code: ${exitCode}`);
} catch (error) {
  console.error(error);
  console.error(output.join("").slice(-4_000));
  process.exitCode = 1;
} finally {
  if (exitCode === null) {
    await delay(200);
    child.kill();
  }
}
