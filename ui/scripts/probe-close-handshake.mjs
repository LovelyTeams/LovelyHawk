// Closing the main window over unsaved settings: the page asks, the operator
// takes longer than the host's 15-second close timeout to decide, and the
// answer must still close the window. Before the host numbered its close
// requests, a late "放弃更改" was dropped and the window stayed open.
//
// Runs the debug build against a throwaway data root; touches no target.

import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { attach, delay, launchDesktop, waitFor } from "./cdp.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const executable = path.join(repositoryRoot, "target", "debug", process.platform === "win32" ? "lovelyhawk.exe" : "lovelyhawk");
const runRoot = path.join(repositoryRoot, "target", "desktop-debug", `close-${randomUUID()}`);
const port = 9800 + Math.floor(Math.random() * 150);
const checks = [];
function check(name, ok, detail = null) {
  checks.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail === null ? "" : ` — ${JSON.stringify(detail)}`}`);
}

fs.mkdirSync(runRoot, { recursive: true });
const { child, output } = launchDesktop({ executable, archiveRoot: runRoot, port });
let exitCode = null;
child.once("exit", (code) => { exitCode = code; });

const click = (selector) => `(() => { const element = document.querySelector(${JSON.stringify(selector)}); if (!element) return false; element.click(); return true; })()`;
const clickButton = (label) => `(() => { const button = [...document.querySelectorAll('[role="dialog"] button, [role="alertdialog"] button')].find((candidate) => candidate.textContent.trim() === ${JSON.stringify(label)}); if (!button) return false; button.click(); return true; })()`;
const dialogText = `[...document.querySelectorAll('[role="dialog"], [role="alertdialog"]')].map((dialog) => dialog.textContent).join(' | ')`;

let session;
try {
  ({ session } = await attach(port, (url) => /^https?:\/\/tauri\.localhost\/(index\.html)?$/u.test(url)));
  await waitFor(() => session.evaluate(`document.querySelector('[data-testid="open-settings"]') !== null`), { label: "the title bar" });

  check("settings opens", await session.evaluate(click('[data-testid="open-settings"]')));
  const toggled = await waitFor(() => session.evaluate(`(() => {
    const box = document.querySelector('[role="dialog"] .settings-toggle input[type="checkbox"]');
    if (!box) return false;
    box.click();
    return true;
  })()`), { timeoutMs: 10_000, label: "a settings toggle" }).catch(() => false);
  check("an unsaved settings change is made", toggled);

  await session.evaluate(click('[data-testid="window-close"]'));
  const asked = await waitFor(() => session.evaluate(`${dialogText}.includes('放弃未保存的更改')`), { timeoutMs: 10_000, label: "the discard question" }).catch(() => false);
  check("closing asks about the unsaved change", asked);

  await delay(17_000);
  check("the window waits while the operator reads", exitCode === null && await session.evaluate(`${dialogText}.includes('放弃未保存的更改')`));

  check("the late answer is given", await session.evaluate(clickButton("放弃更改")));
  session.close();
  await waitFor(() => exitCode !== null, { timeoutMs: 15_000, label: "the app to exit" }).catch(() => undefined);
  check("a late 放弃更改 still closes the app", exitCode === 0, exitCode);
} catch (error) {
  check("probe completed", false, error instanceof Error ? error.message : String(error));
} finally {
  if (exitCode === null) child.kill();
}

const failed = checks.filter((entry) => !entry.ok);
fs.writeFileSync(path.join(runRoot, "report.json"), `${JSON.stringify({
  schema: "lovelyhawk-close-handshake/v1",
  status: failed.length === 0 ? "PASS" : "FAIL",
  generatedAt: new Date().toISOString(),
  checks,
  log: failed.length === 0 ? undefined : output.join("").slice(-4_000),
}, null, 2)}\n`);
console.log(`${failed.length === 0 ? "PASS" : "FAIL"}: ${checks.length - failed.length}/${checks.length} checks; report in ${runRoot}`);
process.exitCode = failed.length === 0 ? 0 : 1;
