// The shared in-app confirmation dialog, driven with the keyboard in the real
// window: it opens over unsaved settings with focus on the safe choice, Tab
// and Shift+Tab stay inside it and reach every button, the page behind is
// inert, Escape and Enter-on-取消 both back out and return focus, and only
// the explicit button discards. No target is involved; throwaway data root.

import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { attach, delay, launchDesktop, waitFor } from "./cdp.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const executable = path.join(repositoryRoot, "target", "debug", process.platform === "win32" ? "lovelyhawk.exe" : "lovelyhawk");
const runRoot = path.join(repositoryRoot, "target", "desktop-debug", `dialogs-${randomUUID()}`);
const evidence = path.join(runRoot, "evidence");
const checks = [];
function check(name, ok, detail = null) {
  checks.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail === null ? "" : ` — ${JSON.stringify(detail)}`}`);
}
fs.mkdirSync(evidence, { recursive: true });

const port = 10_900 + Math.floor(Math.random() * 80);
const { child, output } = launchDesktop({ executable, archiveRoot: runRoot, port });
let exitCode = null;
child.once("exit", (code) => { exitCode = code; });
const errors = [];

const dialog = `(() => {
  const host = document.querySelector('.dialog-host');
  if (!host) return null;
  return {
    role: host.getAttribute('role'),
    title: host.querySelector('h2')?.textContent ?? null,
    eyebrow: host.querySelector('.dialog-host-eyebrow')?.textContent ?? null,
    focus: document.activeElement?.textContent?.trim() ?? null,
    focusInside: host.contains(document.activeElement),
    settingsInert: document.querySelector('.settings-panel')?.closest('[inert]') !== null,
  };
})()`;
async function key(session, name, { shift = false } = {}) {
  const codes = { Tab: 9, Escape: 27, Enter: 13 };
  const base = { key: name, code: name, windowsVirtualKeyCode: codes[name], modifiers: shift ? 8 : 0 };
  await session.send("Input.dispatchKeyEvent", { type: "keyDown", ...base, ...(name === "Enter" ? { text: "\r" } : {}) });
  await session.send("Input.dispatchKeyEvent", { type: "keyUp", ...base });
  await delay(150);
}
async function openDiscard(session) {
  await key(session, "Escape");
  return waitFor(() => session.evaluate(dialog), { timeoutMs: 8_000, label: "the discard question" }).catch(() => null);
}

try {
  const { session } = await attach(port, (url) => /^https?:\/\/tauri\.localhost\/(index\.html)?$/u.test(url));
  session.onEvent((method, params) => {
    if (method === "Runtime.exceptionThrown" || (method === "Runtime.consoleAPICalled" && params?.type === "error")) {
      errors.push(JSON.stringify(params).slice(0, 1_500));
    }
  });
  await session.send("Runtime.enable");
  await waitFor(() => session.evaluate("document.querySelector('[data-testid=\"open-settings\"]') !== null"), { label: "the title bar" });
  await session.evaluate("document.querySelector('[data-testid=\"open-settings\"]').click(), true");
  const toggled = await waitFor(() => session.evaluate(`(() => {
    const box = document.querySelector('.settings-panel .settings-toggle input[type="checkbox"]');
    if (!box) return false;
    box.click();
    box.focus();
    return true;
  })()`), { timeoutMs: 10_000, label: "a settings toggle" }).catch(() => false);
  check("settings has an unsaved change", toggled);

  let now = await openDiscard(session);
  check("Escape over unsaved settings asks first, with focus on 取消", now?.role === "dialog" && now.eyebrow === "请确认" && now.title === "放弃未保存的更改" && now.focus === "取消", now);
  check("the settings behind the question are inert", now?.settingsInert === true, now?.settingsInert);
  await session.screenshot(path.join(evidence, "discard-dialog.png"));

  await key(session, "Tab");
  now = await session.evaluate(dialog);
  check("Tab moves to the next button inside the dialog", now?.focus === "放弃更改" && now.focusInside, now?.focus);
  await key(session, "Tab");
  now = await session.evaluate(dialog);
  check("Tab from the last button wraps to the first", now?.focus === "取消" && now.focusInside, now?.focus);
  await key(session, "Tab", { shift: true });
  now = await session.evaluate(dialog);
  check("Shift+Tab from the first button wraps to the last", now?.focus === "放弃更改" && now.focusInside, now?.focus);
  await key(session, "Tab", { shift: true });
  now = await session.evaluate(dialog);
  check("Shift+Tab moves back to 取消", now?.focus === "取消" && now.focusInside, now?.focus);

  await key(session, "Escape");
  now = await session.evaluate(`({ dialog: ${dialog}, settings: document.querySelector('.settings-panel') !== null, focusInSettings: document.querySelector('.settings-panel')?.contains(document.activeElement) ?? false })`);
  check("Escape backs out, keeps settings open and returns focus there", now.dialog === null && now.settings && now.focusInSettings, now);

  now = await openDiscard(session);
  await key(session, "Enter");
  now = await session.evaluate(`({ dialog: ${dialog}, settings: document.querySelector('.settings-panel') !== null })`);
  check("Enter on the focused 取消 backs out instead of discarding", now.dialog === null && now.settings, now);

  now = await openDiscard(session);
  await session.evaluate(`[...document.querySelectorAll('.dialog-host button')].find((button) => button.textContent.trim() === '放弃更改').click(), true`);
  const closed = await waitFor(() => session.evaluate("document.querySelector('.settings-panel') === null && document.querySelector('.dialog-host') === null"), { timeoutMs: 8_000, label: "settings to close" }).catch(() => false);
  check("only the explicit 放弃更改 button discards and closes settings", closed);

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
  schema: "lovelyhawk-dialogs-probe/v1",
  status: failed.length === 0 ? "PASS" : "FAIL",
  generatedAt: new Date().toISOString(),
  checks,
}, null, 2)}\n`);
console.log(`${failed.length === 0 ? "PASS" : "FAIL"}: ${checks.length - failed.length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failed.length === 0 ? 0 : 1;
