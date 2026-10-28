// End-to-end check of the Tauri host's target binding: connect to a lab host
// from the main window, open the SSH terminal window, run a harmless echo,
// then disconnect and confirm the host closed the terminal window with it.
//
// Needs a running lab host (LAB=ubuntu by default) and the debug builds of the
// desktop app and of the backend harness (used only to record the connection
// and accept the lab's host key in the isolated data root beforehand).
//   cargo build --locked -p lovelyhawk-backend --bin lovelyhawk-backend
//   pnpm --filter @lovelyhawk/ui desktop:build
//   node scripts/probe-terminal-window.mjs

import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { labTarget } from "../../tools/lab/lab-target.mjs";
import { Sidecar, backendBinary, connect } from "../../tools/lab/rpc-harness.mjs";
import { attach, delay, launchDesktop, listTargets, waitFor } from "./cdp.mjs";

const uiRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = path.resolve(uiRoot, "..");
const executable = path.join(repositoryRoot, "target", "debug", "lovelyhawk.exe");
const runRoot = path.join(repositoryRoot, "target", "desktop-debug", `terminal-${randomUUID()}`);
const evidence = path.join(runRoot, "evidence");
const port = 9300 + Math.floor(Math.random() * 500);
const marker = `LOVELYHAWK_TAURI_${randomUUID().slice(0, 8)}`;
const checks = [];
function check(name, ok, detail = null) {
  checks.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail === null ? "" : ` — ${JSON.stringify(detail)}`}`);
}

fs.mkdirSync(evidence, { recursive: true });
const target = labTarget(process.env.LAB ?? "ubuntu");
console.log(`recording ${target.username}@${target.host}:${target.port} in ${runRoot}`);
const sidecar = new Sidecar(backendBinary(), runRoot);
try {
  const status = await connect(sidecar, { ...target, name: "实验室 ubuntu" });
  if (status?.stage !== "connected") throw new Error(`lab connect failed: ${JSON.stringify(status)}`);
  await sidecar.call("ssh.binding.disconnect", { bindingHandle: status.bindingHandle });
} finally {
  sidecar.close();
}
await delay(500);

const { child, output } = launchDesktop({ executable, archiveRoot: runRoot, port });
let exitCode = null;
child.once("exit", (code) => { exitCode = code; });
const errors = [];
try {
  const { session: main } = await attach(port, (url) => /^https?:\/\/tauri\.localhost\/(index\.html)?$/u.test(url));
  main.onEvent((method, params) => {
    if (method === "Runtime.exceptionThrown" || (method === "Runtime.consoleAPICalled" && params?.type === "error")) {
      errors.push(JSON.stringify(params).slice(0, 1_500));
    }
  });
  await main.send("Runtime.enable");
  await main.send("Page.enable");
  await waitFor(() => main.evaluate("document.querySelector('.connection-card') !== null"), { label: "the saved connection" });

  // Connect from the welcome page; the connection manager owns the attempt.
  await main.evaluate("document.querySelector('.connection-card button.is-connect').click(), true");
  const label = await waitFor(() => main.evaluate(`(() => {
    const card = document.querySelector('[data-testid="sidebar-target"] strong');
    return document.querySelector('[data-testid="sidebar-disconnect-target"]') !== null ? card?.textContent ?? "" : null;
  })()`), { timeoutMs: 90_000, label: "the connected target" });
  check("connecting from the welcome page binds the target", label.includes(`@`) && label.endsWith(`:${target.port}`), label);
  // Close the connection manager if it is still open.
  await main.evaluate("document.querySelector('[role=\"dialog\"] button[aria-label=\"关闭\"]')?.click(), true");
  await waitFor(() => main.evaluate("document.querySelector('[role=\"dialog\"]') === null"), { timeoutMs: 10_000, label: "the manager to close" }).catch(() => undefined);
  const page = await waitFor(() => main.evaluate(`(() => {
    const active = document.querySelector('.nav-item.active')?.textContent ?? "";
    const waiting = document.querySelectorAll('.nav-item.needs-target').length;
    return active.includes("主机全景") ? { active, waiting, banner: document.querySelector('.content-connect-action') !== null } : null;
  })()`), { timeoutMs: 20_000, label: "the host overview" });
  check("connected target opens the host overview and clears the waiting marks", page.waiting === 0 && !page.banner, page);
  await delay(1_500);
  await main.screenshot(path.join(evidence, "main-connected.png"));

  // Open the SSH terminal window from the sidebar.
  await main.evaluate("document.querySelector('[data-testid=\"sidebar-open-terminal\"]').click(), true");
  const { session: terminal } = await attach(port, (url) => url.includes("/terminal.html?window=terminal"), 30_000);
  await terminal.send("Runtime.enable");
  await terminal.send("Page.enable");
  const terminalState = await waitFor(() => terminal.evaluate(`(() => {
    const rows = document.querySelector('.xterm-rows');
    return rows !== null && rows.textContent.trim().length > 0
      ? { label: document.documentElement.dataset.targetLabel ?? "", theme: document.documentElement.dataset.theme ?? "",
          mainApi: typeof window.lovelyhawk, terminalApi: typeof window.lovelyhawkTerminal }
      : null;
  })()`), { timeoutMs: 45_000, label: "the shell prompt" });
  check("the terminal window shows its target and the theme before paint", terminalState.label.includes(String(target.port)) && terminalState.theme !== "", terminalState);
  check("the terminal window gets only the terminal API", terminalState.mainApi === "undefined" && terminalState.terminalApi === "object", terminalState);

  // Type a harmless command through the real input path.
  async function typeLine(text) {
    await terminal.evaluate("document.querySelector('.xterm-helper-textarea')?.focus(), true");
    // xterm reads printable keys from key events, not from inserted text.
    for (const character of text) {
      await terminal.send("Input.dispatchKeyEvent", { type: "keyDown", key: character, text: character, unmodifiedText: character });
      await terminal.send("Input.dispatchKeyEvent", { type: "keyUp", key: character });
    }
    await terminal.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13, text: "\r" });
    await terminal.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
  }
  await typeLine(`echo ${marker}`);
  const echoed = await waitFor(() => terminal.evaluate(`(document.querySelector('.xterm-rows')?.textContent ?? "").split(${JSON.stringify(marker)}).length >= 3`),
    { timeoutMs: 20_000, label: "the echoed marker" }).catch(() => false);
  check("input reaches the shell and its output comes back", echoed);
  await terminal.screenshot(path.join(evidence, "terminal-window.png"));

  // The file editor window: open a throwaway file, edit without saving, and
  // check that both close buttons ask before the edit is dropped. The file is
  // created and removed under the lab host's /tmp; nothing is saved.
  const scratchFile = `lovelyhawk-editor-${randomUUID().slice(0, 8)}.txt`;
  await typeLine(`echo probe > /tmp/${scratchFile}`);
  await delay(800);
  await terminal.evaluate("[...document.querySelectorAll('button')].find((button) => button.textContent.trim() === '文件管理')?.click(), true");
  // The remote pane starts at the root directory; open tmp.
  await waitFor(() => terminal.evaluate(`(() => {
    const row = [...document.querySelectorAll('section[aria-label="远程文件"] .sftp-browser-row')].find((candidate) => candidate.querySelector('.sftp-browser-row-label')?.textContent === 'tmp');
    if (!row || row.disabled) return false;
    row.dispatchEvent(new MouseEvent('dblclick', { bubbles: true, cancelable: true }));
    return true;
  })()`), { timeoutMs: 30_000, label: "the remote tmp directory" }).catch(() => false);
  async function openEditor() {
    const opened = await waitFor(() => terminal.evaluate(`(() => {
      const row = [...document.querySelectorAll('section[aria-label="远程文件"] .sftp-browser-row')].find((candidate) => candidate.querySelector('.sftp-browser-row-label')?.textContent === ${JSON.stringify(scratchFile)});
      if (!row) return false;
      const box = row.getBoundingClientRect();
      row.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, cancelable: true, clientX: box.left + 20, clientY: box.top + 5 }));
      const item = [...document.querySelectorAll('[role="menuitem"]')].find((candidate) => candidate.textContent.includes('编辑文本'));
      if (!item) return false;
      item.click();
      return true;
    })()`), { timeoutMs: 30_000, label: "the scratch file in the remote pane" }).catch(() => false);
    if (!opened) {
      console.log("remote pane state:", await terminal.evaluate(`JSON.stringify({
        path: document.querySelector('.sftp-browser-path-value')?.textContent ?? null,
        rows: [...document.querySelectorAll('section[aria-label="远程文件"] .sftp-browser-row-label')].map((label) => label.textContent).slice(0, 40),
        menu: [...document.querySelectorAll('[role="menuitem"]')].map((item) => item.textContent),
        files: document.querySelector('.ssh-window-files')?.textContent.slice(0, 400) ?? null,
      })`));
      await terminal.screenshot(path.join(evidence, "remote-pane.png"));
      return null;
    }
    const { session: editor } = await attach(port, (url) => url.includes("/terminal.html?window=file-editor"), 30_000);
    await waitFor(() => editor.evaluate("document.querySelector('.file-editor-text')?.value === 'probe\\n'"), { timeoutMs: 20_000, label: "the file text" });
    return editor;
  }
  const editorOpen = async () => (await listTargets(port)).some((entry) => entry.url.includes("window=file-editor"));
  const dialogText = "[...document.querySelectorAll('[role=\"dialog\"], [role=\"alertdialog\"]')].map((dialog) => dialog.textContent).join(' | ')";
  const clickDialogButton = (label) => `[...document.querySelectorAll('[role="dialog"] button, [role="alertdialog"] button')].find((button) => button.textContent.trim() === ${JSON.stringify(label)})?.click(), true`;

  let editor = await openEditor();
  check("the file editor window opens with the file's text", editor !== null);
  if (editor !== null) {
    check("the file editor gets only the terminal-family API", await editor.evaluate("typeof window.lovelyhawk === 'undefined' && typeof window.lovelyhawkTerminal === 'object'"));
    await editor.evaluate("document.querySelector('[data-testid=\"file-editor-close\"]').click(), true");
    const cleanClosed = await waitFor(async () => !(await editorOpen()), { timeoutMs: 10_000, label: "the clean editor to close" }).catch(() => false);
    check("an editor without changes closes without asking", cleanClosed);
  }

  editor = await openEditor();
  if (editor !== null) {
    await editor.evaluate(`(() => {
      const area = document.querySelector('.file-editor-text');
      Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(area, area.value + 'unsaved');
      area.dispatchEvent(new Event('input', { bubbles: true }));
      return true;
    })()`);
    await editor.evaluate("document.querySelector('[data-testid=\"file-editor-close\"]').click(), true");
    const askedFromButton = await waitFor(() => editor.evaluate(`${dialogText}.includes('放弃未保存的修改？')`), { timeoutMs: 10_000, label: "the discard question" }).catch(() => false);
    check("closing an edited file asks first", askedFromButton);
    await editor.screenshot(path.join(evidence, "file-editor-discard.png"));
    await editor.evaluate(clickDialogButton("取消"));
    await delay(1_000);
    check("cancelling keeps the window and the edit", await editorOpen() &&
      await editor.evaluate("document.querySelector('.file-editor-text').value.endsWith('unsaved')"));
    await editor.evaluate("document.querySelector('[data-testid=\"window-close\"]').click(), true");
    const askedFromTitleBar = await waitFor(() => editor.evaluate(`${dialogText}.includes('放弃未保存的修改？')`), { timeoutMs: 10_000, label: "the title-bar question" }).catch(() => false);
    check("the title-bar close asks the same question", askedFromTitleBar);
    await editor.evaluate(clickDialogButton("放弃修改并关闭"));
    const discarded = await waitFor(async () => !(await editorOpen()), { timeoutMs: 10_000, label: "the edited editor to close" }).catch(() => false);
    check("discarding closes the editor", discarded);
  } else {
    check("the file editor reopens", false);
  }
  await typeLine(`rm -f /tmp/${scratchFile}`);
  await delay(800);

  // A second request raises the same window instead of opening another.
  await main.evaluate("document.querySelector('[data-testid=\"sidebar-open-terminal\"]').click(), true");
  await delay(1_500);
  const terminals = (await listTargets(port)).filter((entry) => entry.url.includes("window=terminal"));
  check("reopening raises the existing terminal window", terminals.length === 1, terminals.length);

  // Disconnecting closes the terminal window with its binding.
  await main.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]').click(), true");
  const gone = await waitFor(async () => (await listTargets(port)).every((entry) => !entry.url.includes("window=terminal")),
    { timeoutMs: 20_000, label: "the terminal window to close" }).catch(() => false);
  check("disconnecting closes the terminal window", gone);
  const idle = await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"sidebar-connect-target\"]') !== null"),
    { timeoutMs: 10_000, label: "the idle target card" }).catch(() => false);
  check("the main window returns to the disconnected state", idle);

  check("no console errors in the main window", errors.length === 0, errors.slice(0, 3));
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
fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify({ status: failed.length === 0 ? "PASS" : "FAIL", lab: process.env.LAB ?? "ubuntu", checks }, null, 2)}\n`);
console.log(`${failed.length === 0 ? "PASS" : "FAIL"}: ${checks.length - failed.length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failed.length === 0 ? 0 : 1;
