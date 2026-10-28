// Tabs in the SSH terminal window, against a real lab host: each tab is its
// own shell (counted on the host as its own pseudo-terminal), output never
// crosses between tabs, a window holds at most four, closing or exiting one
// tab ends only that shell, and closing the window ends every one of them.
//
// Needs a running lab host (LAB=super by default; any lab-<name> container)
// and the debug builds of the desktop app and of the backend harness.
//   cargo build --locked -p lovelyhawk-backend --bin lovelyhawk-backend
//   pnpm --filter @lovelyhawk/ui desktop:build
//   LAB=super node scripts/probe-terminal-tabs.mjs
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { labTarget } from "../../tools/lab/lab-target.mjs";
import { Sidecar, backendBinary, connect } from "../../tools/lab/rpc-harness.mjs";
import { attach, delay, launchDesktop, listTargets, waitFor } from "./cdp.mjs";

const uiRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = path.resolve(uiRoot, "..");
const executable = process.env.LOVELYHAWK_DESKTOP_BIN ?? path.join(repositoryRoot, "target", "debug", "lovelyhawk.exe");
const runRoot = path.join(repositoryRoot, "target", "desktop-debug", `terminal-tabs-${randomUUID()}`);
const evidence = path.join(runRoot, "evidence");
const port = 9300 + Math.floor(Math.random() * 500);
const lab = process.env.LAB ?? "super";
const markerA = `TAB_A_${randomUUID().slice(0, 8)}`;
const markerB = `TAB_B_${randomUUID().slice(0, 8)}`;
const checks = [];
function check(name, ok, detail = null) {
  checks.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail === null ? "" : ` — ${JSON.stringify(detail)}`}`);
}

/**
 * Pseudo-terminals open on the host. Every shell a tab opens holds one; the
 * window's other reads run without a terminal, so the count is the shells.
 */
function hostTerminals() {
  const output = execFileSync(
    "wsl.exe",
    ["-d", "Ubuntu", "-u", "root", "-e", "sh", "-c", `docker exec lab-${lab} sh -c 'ls /dev/pts'`],
    { encoding: "utf8", windowsHide: true, timeout: 60_000 },
  );
  return output.split(/\s+/u).filter((name) => /^[0-9]+$/u.test(name)).length;
}

fs.mkdirSync(evidence, { recursive: true });
const target = labTarget(lab);
console.log(`recording ${target.username}@${target.host}:${target.port} in ${runRoot}`);
const sidecar = new Sidecar(backendBinary(), runRoot);
try {
  const status = await connect(sidecar, { ...target, name: `实验室 ${lab}` });
  if (status?.stage !== "connected") throw new Error(`lab connect failed: ${JSON.stringify(status)}`);
  await sidecar.call("ssh.binding.disconnect", { bindingHandle: status.bindingHandle });
} finally {
  sidecar.close();
}
await delay(1_000);
const before = hostTerminals();
console.log(`host terminals before: ${before}`);

const { child, output } = launchDesktop({ executable, archiveRoot: runRoot, port });
let exitCode = null;
child.once("exit", (code) => { exitCode = code; });
const errors = [];
const watchErrors = (session, name) => session.onEvent((method, params) => {
  if (method === "Runtime.exceptionThrown" || (method === "Runtime.consoleAPICalled" && params?.type === "error")) {
    errors.push(`${name}: ${JSON.stringify(params).slice(0, 1_500)}`);
  }
});
try {
  const { session: main } = await attach(port, (url) => /^https?:\/\/tauri\.localhost\/(index\.html)?$/u.test(url));
  watchErrors(main, "main");
  await main.send("Runtime.enable");
  await main.send("Page.enable");
  await waitFor(() => main.evaluate("document.querySelector('.connection-card') !== null"), { label: "the saved connection" });
  await main.evaluate("document.querySelector('.connection-card button.is-connect').click(), true");
  await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]') !== null"),
    { timeoutMs: 90_000, label: "the connected target" });
  await main.evaluate("document.querySelector('[role=\"dialog\"] button[aria-label=\"关闭\"]')?.click(), true");
  await delay(1_000);

  await main.evaluate("document.querySelector('[data-testid=\"sidebar-open-terminal\"]').click(), true");
  const { session: terminal } = await attach(port, (url) => url.includes("/terminal.html?window=terminal"), 30_000);
  watchErrors(terminal, "terminal");
  await terminal.send("Runtime.enable");
  await terminal.send("Page.enable");

  const shown = "document.querySelector('.ssh-window-terminal-panel:not(.is-behind)')";
  const tabState = `(() => ({
    tabs: document.querySelectorAll('[data-testid="ssh-window-tab"]').length,
    selected: [...document.querySelectorAll('[data-testid="ssh-window-tab"]')].findIndex((tab) => tab.getAttribute('aria-selected') === 'true'),
    names: [...document.querySelectorAll('[data-testid="ssh-window-tab"]')].map((tab) => tab.textContent.trim()),
    closers: document.querySelectorAll('[data-testid="ssh-window-tab-close"]').length,
    addDisabled: document.querySelector('[data-testid="ssh-window-tab-add"]')?.disabled ?? null,
    addTitle: document.querySelector('[data-testid="ssh-window-tab-add"]')?.title ?? null,
    panels: document.querySelectorAll('.ssh-window-terminal-panel').length,
    session: document.querySelector('[data-testid="ssh-window-session"]')?.textContent ?? null,
  }))()`;
  const panelText = (index) => `(document.querySelectorAll('.ssh-window-terminal-panel')[${index}]?.querySelector('.xterm-rows')?.textContent ?? "")`;
  const promptShown = () => waitFor(() => terminal.evaluate(`(${shown}?.querySelector('.xterm-rows')?.textContent ?? "").trim().length > 0`),
    { timeoutMs: 45_000, label: "the shell prompt" });

  async function typeLine(text) {
    await terminal.evaluate(`${shown}?.querySelector('.xterm-helper-textarea')?.focus(), true`);
    for (const character of text) {
      await terminal.send("Input.dispatchKeyEvent", { type: "keyDown", key: character, text: character, unmodifiedText: character });
      await terminal.send("Input.dispatchKeyEvent", { type: "keyUp", key: character });
    }
    await terminal.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13, text: "\r" });
    await terminal.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
  }
  const hostCount = (expected, label) => waitFor(() => hostTerminals() === expected, { timeoutMs: 20_000, intervalMs: 700, label })
    .then(() => true, () => false);

  // One tab to begin with, its shell live, nothing to close it by but the window.
  await promptShown();
  let state = await terminal.evaluate(tabState);
  check("the window opens with one selected tab and a way to add more", state.tabs === 1 && state.selected === 0 && state.closers === 0 && state.addDisabled === false, state);
  check("the host holds one terminal for it", await hostCount(before + 1, "one host terminal"), { before, now: hostTerminals() });
  await typeLine(`echo ${markerA}`);
  check("the first tab runs what is typed into it",
    await waitFor(() => terminal.evaluate(`${panelText(0)}.split(${JSON.stringify(markerA)}).length >= 3`), { timeoutMs: 20_000, label: "marker A" }).then(() => true, () => false));

  // A second tab: its own shell, selected, the first kept behind it.
  await terminal.evaluate("document.querySelector('[data-testid=\"ssh-window-tab-add\"]').click(), true");
  await waitFor(() => terminal.evaluate("document.querySelectorAll('.ssh-window-terminal-panel').length === 2"), { label: "the second panel" });
  await promptShown();
  state = await terminal.evaluate(tabState);
  check("a new tab opens beside the first and is selected", state.tabs === 2 && state.selected === 1 && state.closers === 2, state);
  check("the host holds a second terminal for it", await hostCount(before + 2, "two host terminals"), hostTerminals());
  await typeLine(`echo ${markerB}`);
  const separate = await waitFor(() => terminal.evaluate(`${panelText(1)}.split(${JSON.stringify(markerB)}).length >= 3`), { timeoutMs: 20_000, label: "marker B" })
    .then(() => terminal.evaluate(`({ first: ${panelText(0)}, second: ${panelText(1)} })`), () => null);
  check("each tab shows only its own shell's output",
    separate !== null && separate.second.includes(markerB) && !separate.second.includes(markerA) &&
      separate.first.includes(markerA) && !separate.first.includes(markerB),
    separate === null ? null : { firstHasB: separate.first.includes(markerB), secondHasA: separate.second.includes(markerA) });
  check("the tab behind is hidden from the screen and from assistive tech", await terminal.evaluate(`(() => {
    const behind = document.querySelectorAll('.ssh-window-terminal-panel')[0];
    return getComputedStyle(behind).visibility === 'hidden' && behind.getAttribute('aria-hidden') === 'true' && behind.inert === true;
  })()`));
  await terminal.screenshot(path.join(evidence, "two-tabs.png"));

  // Ctrl+Tab moves between tabs; the first one's output is still there.
  await terminal.send("Input.dispatchKeyEvent", { type: "rawKeyDown", key: "Tab", code: "Tab", windowsVirtualKeyCode: 9, modifiers: 2 });
  await terminal.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Tab", code: "Tab", windowsVirtualKeyCode: 9, modifiers: 2 });
  state = await waitFor(async () => { const value = await terminal.evaluate(tabState); return value.selected === 0 ? value : null; }, { timeoutMs: 5_000, label: "Ctrl+Tab" }).catch(() => null);
  check("Ctrl+Tab brings the other tab to the front", state !== null, state);
  check("its shell kept its output while it was behind", await terminal.evaluate(`${panelText(0)}.includes(${JSON.stringify(markerA)})`));

  // Up to four; then the add button says why it is off.
  for (let count = 3; count <= 4; count += 1) {
    await terminal.evaluate("document.querySelector('[data-testid=\"ssh-window-tab-add\"]').click(), true");
    await waitFor(() => terminal.evaluate(`document.querySelectorAll('.ssh-window-terminal-panel').length === ${count}`), { label: `tab ${count}` });
    await promptShown();
  }
  state = await terminal.evaluate(tabState);
  check("a window holds four tabs and then offers no more", state.tabs === 4 && state.addDisabled === true && state.addTitle.includes("最多 4 个"), state);
  check("the host holds four terminals", await hostCount(before + 4, "four host terminals"), hostTerminals());
  await terminal.screenshot(path.join(evidence, "four-tabs.png"));

  // Closing a tab ends its shell and only its shell.
  await terminal.evaluate("document.querySelectorAll('[data-testid=\"ssh-window-tab-close\"]')[3].click(), true");
  await waitFor(() => terminal.evaluate("document.querySelectorAll('.ssh-window-terminal-panel').length === 3"), { label: "three panels" });
  check("closing a tab ends its shell on the host", await hostCount(before + 3, "three host terminals"), hostTerminals());
  state = await terminal.evaluate(tabState);
  check("and a tab can be added again", state.addDisabled === false, state);

  // A shell that exits closes its own tab.
  await terminal.evaluate("[...document.querySelectorAll('[data-testid=\"ssh-window-tab\"]')][2].click(), true");
  await delay(400);
  await typeLine("exit");
  const exited = await waitFor(() => terminal.evaluate("document.querySelectorAll('.ssh-window-terminal-panel').length === 2"), { timeoutMs: 20_000, label: "the exited tab to close" })
    .then(() => true, () => false);
  check("exiting a shell closes its tab", exited, await terminal.evaluate(tabState));
  check("and its terminal is gone from the host", await hostCount(before + 2, "two host terminals again"), hostTerminals());
  check("the other tabs' shells still answer",
    await terminal.evaluate(`${panelText(0)}.includes(${JSON.stringify(markerA)}) && ${panelText(1)}.includes(${JSON.stringify(markerB)})`));

  check("no console errors in either window", errors.length === 0, errors.slice(0, 3));

  // Closing the window ends every shell it held.
  await terminal.evaluate("document.querySelector('[data-testid=\"window-close\"]').click(), true");
  const closed = await waitFor(async () => (await listTargets(port)).every((entry) => !entry.url.includes("window=terminal")),
    { timeoutMs: 20_000, label: "the terminal window to close" }).then(() => true, () => false);
  check("the window closes", closed);
  check("closing the window ends every shell it held", await hostCount(before, "no host terminals left"), { before, now: hostTerminals() });

  await main.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]').click(), true");
  await delay(1_000);
  await main.evaluate("document.querySelector('[data-testid=\"window-close\"]').click(), true");
  await waitFor(() => exitCode !== null, { timeoutMs: 15_000, label: "exit" }).catch(() => undefined);
  check("the app exits cleanly", exitCode === 0, exitCode);
} catch (error) {
  check("scenario completed", false, error instanceof Error ? error.message : String(error));
  console.error(output.join("").slice(-3_000));
} finally {
  if (exitCode === null) child.kill();
}
const failed = checks.filter((entry) => !entry.ok);
fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify({ status: failed.length === 0 ? "PASS" : "FAIL", lab, checks }, null, 2)}\n`);
console.log(`${failed.length === 0 ? "PASS" : "FAIL"}: ${checks.length - failed.length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failed.length === 0 ? 0 : 1;
