// Unsaved text in a file editor window is asked about however the window is
// closed. A scratch file under /tmp on lab-ubuntu is opened and edited without
// saving, then:
//   * a close from outside the page (the same native close request Alt+F4 or
//     the taskbar sends) is held and the editor asks; 取消 keeps the text;
//   * closing the main window asks first, naming one editor; 取消 keeps both;
//   * connecting another target asks first; 取消 keeps the current target;
//   * disconnecting asks first; confirming closes the editor and disconnects;
//   * an editor without unsaved text closes from outside without asking;
// and the file on the host is never written. The scratch file is removed.
//
//   node ui/scripts/probe-editor-close.mjs

import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { labTarget } from "../../tools/lab/lab-target.mjs";
import { Sidecar, backendBinary, connect } from "../../tools/lab/rpc-harness.mjs";
import { attach, delay, launchDesktop, listTargets, waitFor } from "./cdp.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const executable = path.join(repositoryRoot, "target", "debug", process.platform === "win32" ? "lovelyhawk.exe" : "lovelyhawk");
const id = randomUUID().slice(0, 8);
const scratch = `lh-close-${id}.txt`;
const runRoot = path.join(repositoryRoot, "target", "desktop-debug", `editor-close-${randomUUID()}`);
const evidence = path.join(runRoot, "evidence");
const checks = [];
function check(name, ok, detail = null) {
  checks.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail === null ? "" : ` — ${JSON.stringify(detail).slice(0, 400)}`}`);
}
fs.mkdirSync(evidence, { recursive: true });
const onHost = (script) => execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "-e", "docker", "exec", "lab-ubuntu", "sh", "-c", script], { encoding: "utf8" });
onHost(`printf 'original ${id}\\n' > /tmp/${scratch}`);
const original = onHost(`cat /tmp/${scratch}`);

const hosts = [
  { lab: "ubuntu", name: "实验 ubuntu", id: "11111111-1111-4111-8111-111111111111" },
  { lab: "debian", name: "实验 debian", id: "22222222-2222-4222-8222-222222222222" },
];
const sidecar = new Sidecar(backendBinary(), runRoot);
try {
  for (const host of hosts) {
    const status = await connect(sidecar, { ...labTarget(host.lab), name: host.name, id: host.id });
    if (status?.stage !== "connected") throw new Error(`lab connect failed: ${JSON.stringify(status)}`);
    await sidecar.call("ssh.binding.disconnect", { bindingHandle: status.bindingHandle });
  }
} finally {
  sidecar.close();
}
await delay(500);

const port = 12_000 + Math.floor(Math.random() * 80);
const { child, output } = launchDesktop({ executable, archiveRoot: runRoot, port });
let exitCode = null;
child.once("exit", (code) => { exitCode = code; });
const errors = [];
const clickText = (selector, text) => `(() => { const element = [...document.querySelectorAll(${JSON.stringify(selector)})].find((candidate) => candidate.textContent.trim() === ${JSON.stringify(text)}); if (!element || element.disabled) return false; element.click(); return true; })()`;
const row = (name) => `[...document.querySelectorAll('section[aria-label="远程文件"] .sftp-browser-row')].find((candidate) => candidate.querySelector('.sftp-browser-row-label')?.textContent === ${JSON.stringify(name)})`;
const dialogText = "document.querySelector('.dialog-host')?.textContent ?? null";
const editorOpen = async () => (await listTargets(port)).some((entry) => entry.url.includes("window=file-editor"));
try {
  const { session: main } = await attach(port, (url) => /^https?:\/\/tauri\.localhost\/(index\.html)?$/u.test(url));
  main.onEvent((method, params) => {
    if (method === "Runtime.exceptionThrown" || (method === "Runtime.consoleAPICalled" && params?.type === "error")) errors.push(JSON.stringify(params).slice(0, 1_500));
  });
  await main.send("Runtime.enable");
  async function connectTo(name, expectQuestion = false) {
    await waitFor(() => main.evaluate("(() => { const button = document.querySelector('[data-testid=\"sidebar-connect-target\"]') ?? document.querySelector('[data-testid=\"open-connections\"]'); if (!button) return false; button.click(); return true; })()"), { label: "连接管理" });
    await waitFor(() => main.evaluate(`(() => { const candidate = [...document.querySelectorAll('.connection-list .connection-list-row')].find((entry) => entry.querySelector('strong')?.textContent === ${JSON.stringify(name)}); if (!candidate || candidate.disabled) return false; candidate.click(); return true; })()`), { timeoutMs: 15_000, label: `the ${name} row` });
    await waitFor(() => main.evaluate(`(() => { const button = [...document.querySelectorAll('.connection-detail button')].find((candidate) => candidate.textContent.trim() === '连接目标' && !candidate.disabled); if (!button) return false; button.click(); return true; })()`), { timeoutMs: 15_000, label: "连接目标" });
    if (expectQuestion) return;
    await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]') !== null && document.querySelector('.connection-manager-backdrop') === null"), { timeoutMs: 90_000, label: `the connection to ${name}` });
  }
  async function openEditor(terminal) {
    await waitFor(() => terminal.evaluate(`(() => {
      const candidate = ${row(scratch)};
      if (!candidate) return false;
      const box = candidate.getBoundingClientRect();
      candidate.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, cancelable: true, clientX: box.left + 20, clientY: box.top + 5 }));
      const item = [...document.querySelectorAll('[role="menuitem"]')].find((entry) => entry.textContent.includes('编辑文本'));
      if (!item) return false;
      item.click();
      return true;
    })()`), { timeoutMs: 20_000, label: "编辑文本" });
    const { session: editor } = await attach(port, (url) => url.includes("/terminal.html?window=file-editor"), 30_000);
    await editor.send("Runtime.enable");
    await waitFor(() => editor.evaluate("(document.querySelector('.file-editor-text')?.value ?? '').length > 0"), { timeoutMs: 20_000, label: "the file text" });
    return editor;
  }
  const edit = (editor, value) => editor.evaluate(`(() => { const area = document.querySelector('.file-editor-text'); Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(area, ${JSON.stringify(value)}); area.dispatchEvent(new Event('input', { bubbles: true })); return true; })()`);
  // The native close request a window gets from Alt+F4 or the taskbar.
  // A window that closes at once takes its CDP session with it; that is the expected outcome.
  const closeFromOutside = (editor) => editor.evaluate("window.lovelyhawkWindow.close().then(() => true, () => true)").catch(() => true);

  await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"sidebar-connect-target\"]') !== null"), { label: "the sidebar" });
  await connectTo("实验 ubuntu");
  await main.evaluate("document.querySelector('[data-testid=\"sidebar-open-terminal\"]').click(), true");
  const { session: terminal } = await attach(port, (url) => url.includes("/terminal.html?window=terminal"), 30_000);
  await terminal.send("Runtime.enable");
  await waitFor(() => terminal.evaluate(`(() => { const candidate = ${row("tmp")}; if (!candidate || candidate.disabled) return false; candidate.dispatchEvent(new MouseEvent('dblclick', { bubbles: true })); return true; })()`), { timeoutMs: 30_000, label: "tmp" });
  await waitFor(() => terminal.evaluate(`${row(scratch)} !== undefined`), { timeoutMs: 20_000, label: "the scratch file" });

  let editor = await openEditor(terminal);
  const edited = `${original}typed but never saved\n`;
  await edit(editor, edited);
  await waitFor(() => editor.evaluate("(document.querySelector('.file-editor-identity')?.textContent ?? '').includes('已修改')"), { label: "the unsaved mark" });
  await delay(500);

  // 1. From outside the page.
  await closeFromOutside(editor);
  let question = await waitFor(() => editor.evaluate(dialogText), { timeoutMs: 10_000, label: "the editor's question" }).catch(() => null);
  check("a close from outside the page is held and the editor asks", question?.includes("放弃未保存的修改？") === true && await editorOpen(), question);
  await editor.screenshot(path.join(evidence, "editor-asks.png"));
  await editor.evaluate(clickText(".dialog-host button", "取消"));
  await delay(800);
  check("取消 keeps the window and the typed text", await editorOpen() && await editor.evaluate("document.querySelector('.file-editor-text').value") === edited);

  // 2. Closing the main window.
  await main.evaluate("document.querySelector('[data-testid=\"window-close\"]').click(), true");
  question = await waitFor(() => main.evaluate(dialogText), { timeoutMs: 10_000, label: "the main window's question" }).catch(() => null);
  check("closing the main window asks first and names the editor", question?.includes("还有 1 个文件编辑窗口") === true && question.includes("放弃修改并关闭"), question);
  await main.screenshot(path.join(evidence, "main-asks.png"));
  await main.evaluate(clickText(".dialog-host button", "取消"));
  await delay(1_000);
  check("取消 keeps the app and the editor open", exitCode === null && await editorOpen());

  // 3. Connecting another target.
  await connectTo("实验 debian", true);
  question = await waitFor(() => main.evaluate(dialogText), { timeoutMs: 10_000, label: "the switch question" }).catch(() => null);
  check("connecting another target asks first", question?.includes("连接新目标会关闭它们") === true, question);
  await main.evaluate(clickText(".dialog-host button", "取消"));
  await delay(800);
  await main.evaluate("document.querySelector('[aria-label=\"关闭连接管理\"]')?.click(), true");
  await delay(500);
  const stillUbuntu = await main.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]') !== null");
  check("取消 keeps the current target and the editor", stillUbuntu && await editorOpen());

  // 4. Disconnecting.
  await main.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]').click(), true");
  question = await waitFor(() => main.evaluate(dialogText), { timeoutMs: 10_000, label: "the disconnect question" }).catch(() => null);
  check("disconnecting asks first", question?.includes("断开连接会关闭它们") === true, question);
  await waitFor(() => main.evaluate(clickText(".dialog-host button", "放弃修改并断开")), { label: "放弃修改并断开" });
  await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]') === null"), { timeoutMs: 20_000, label: "the disconnect" });
  await waitFor(async () => !(await editorOpen()), { timeoutMs: 10_000, label: "the editor to close" }).catch(() => undefined);
  check("confirming disconnects and closes the editor", !(await editorOpen()));
  check("the file on the host was never written", onHost(`cat /tmp/${scratch}`) === original);

  // 5. Without unsaved text, a close from outside just closes.
  await connectTo("实验 ubuntu");
  await main.evaluate("document.querySelector('[data-testid=\"sidebar-open-terminal\"]').click(), true");
  const { session: terminal2 } = await attach(port, (url) => url.includes("/terminal.html?window=terminal"), 30_000);
  await waitFor(() => terminal2.evaluate(`(() => { const candidate = ${row("tmp")}; if (!candidate || candidate.disabled) return false; candidate.dispatchEvent(new MouseEvent('dblclick', { bubbles: true })); return true; })()`), { timeoutMs: 30_000, label: "tmp again" });
  await waitFor(() => terminal2.evaluate(`${row(scratch)} !== undefined`), { timeoutMs: 20_000, label: "the scratch file again" });
  editor = await openEditor(terminal2);
  await delay(500);
  await closeFromOutside(editor);
  await waitFor(async () => !(await editorOpen()), { timeoutMs: 10_000, label: "the clean editor to close" }).catch(() => undefined);
  check("an editor without unsaved text closes from outside without asking", !(await editorOpen()));

  check("no console errors in the main window", errors.length === 0, errors.slice(0, 3));
  await main.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]').click(), true");
  await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]') === null"), { timeoutMs: 20_000, label: "the last disconnect" }).catch(() => undefined);
  await main.evaluate("document.querySelector('[data-testid=\"window-close\"]').click(), true");
  await waitFor(() => exitCode !== null, { timeoutMs: 15_000, label: "exit" }).catch(() => undefined);
  check("the app exits cleanly", exitCode === 0, exitCode);
} catch (error) {
  check("probe completed", false, error instanceof Error ? error.message : String(error));
  console.error(output.join("").slice(-3_000));
} finally {
  if (exitCode === null) child.kill();
  onHost(`rm -f /tmp/${scratch}`);
}

const failed = checks.filter((entry) => !entry.ok);
fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify({
  schema: "lovelyhawk-editor-close-probe/v1",
  status: failed.length === 0 ? "PASS" : "FAIL",
  generatedAt: new Date().toISOString(),
  checks,
}, null, 2)}\n`);
console.log(`${failed.length === 0 ? "PASS" : "FAIL"}: ${checks.length - failed.length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failed.length === 0 ? 0 : 1;
